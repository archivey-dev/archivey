"""The PE tail probe: a ZIP far behind a Windows executable, found from its end record.

The install4j shape: a ZIP 35 MB into an installer, past the 2 MiB SFX window. The
probe runs only when the PE's own layout says an overlay runs past the window, so an
ordinary program never pays for the tail read.
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import replace

import pytest

from archivey import detect_format, open_archive
from archivey.config import ArchiveyConfig
from archivey.detection_cost import (
    BALANCED_BUDGET,
    FAST_BUDGET,
    DetectionBudget,
    TierSkip,
    TierSkipReason,
)
from archivey.exceptions import FormatDetectionError
from archivey.internal.detection_workspace import PrefixWorkspace
from archivey.internal.sfx import SFX_MAX, VALIDATOR_PEEK_MAX
from archivey.types import ArchiveFormat
from tests.detection_cost_util import within_budget
from tests.pe_build import FILE_ALIGNMENT, pe_file, pe_headers
from tests.streams_util import NonSeekableBytesIO
from tests.test_detection_workspace import InstrumentedBytesIO

_IMAGE = 0x1000
_OVERLAY = FILE_ALIGNMENT + _IMAGE
# Overlay filler with no archive magic in it, longer than the SFX window: install4j's
# XORed block stands here.
_FILLER = b"\x88" * (3 * 1024 * 1024)
_MEMBERS = {"a.txt": b"alpha\n" * 100, "dir/b.bin": bytes(range(256)) * 4}
_TAIL_SKIP = TierSkip("sfx_tail", TierSkipReason.CAPABILITY_UNAVAILABLE)


def _zip(members: dict[str, bytes] = _MEMBERS) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _installer(
    payload: bytes,
    *,
    certificate_size: int | None = 0x2900,
    padding: bytes = b"\0" * 224,
) -> bytes:
    return pe_file(
        _IMAGE,
        payload=_FILLER + payload,
        after_payload=padding if certificate_size is not None else b"",
        certificate_size=certificate_size,
    )


def _in_place_installer(certificate_size: int) -> bytes:
    """A ZIP whose offsets count from byte 0 (``zip -A``), behind the same stub."""
    head = pe_file(_IMAGE) + _FILLER
    buffer = io.BytesIO(head)
    buffer.seek(0, io.SEEK_END)
    with zipfile.ZipFile(buffer, "a") as archive:
        for name, data in _MEMBERS.items():
            archive.writestr(name, data)
    body = buffer.getvalue()[len(pe_file(_IMAGE)) :]
    # The same layout, now naming the certificate in its header.
    return pe_file(_IMAGE, payload=body, certificate_size=certificate_size)


def _listed(data: bytes) -> dict[str, bytes]:
    with open_archive(io.BytesIO(data)) as reader:
        return {
            member.name: reader.read(member)
            for member in reader.members()
            if not member.is_dir
        }


@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
def test_appended_zip_past_the_window_is_found(signed: bool) -> None:
    payload = _zip()
    data = _installer(payload, certificate_size=0x2900 if signed else None)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.ZIP
    assert info.detected_by == "sfx_scan"
    assert info.prefixed
    assert info.payload_offset == _OVERLAY + len(_FILLER)
    expected_end = _OVERLAY + len(_FILLER) + len(payload) + 224
    assert info.payload_end == (expected_end if signed else None)
    assert _listed(data) == _MEMBERS


def test_a_short_prefix_budget_still_runs_the_probe() -> None:
    # A ``max_prefix_bytes`` below the PE headers' span: detection reads the headers
    # anyway, so it finds the ZIP and the end a forced ``format=ZIP`` finds.
    payload = _zip()
    data = _installer(payload)
    config = ArchiveyConfig(
        detection_budget=replace(BALANCED_BUDGET, max_prefix_bytes=64)
    )
    info = detect_format(io.BytesIO(data), config=config)
    assert info.format is ArchiveFormat.ZIP
    assert info.payload_offset == _OVERLAY + len(_FILLER)
    assert info.payload_end == _OVERLAY + len(_FILLER) + len(payload) + 224


@pytest.mark.parametrize("certificate", [0x2900, 70_000], ids=["small", "over-64k"])
def test_zip_written_in_place_reports_base_zero(certificate: int) -> None:
    data = _in_place_installer(certificate)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.ZIP
    assert info.prefixed
    assert info.payload_offset == 0
    assert _listed(data) == _MEMBERS


def test_certificate_over_64k_after_an_appended_zip() -> None:
    data = _installer(_zip(), certificate_size=70_000)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.ZIP
    assert info.payload_offset == _OVERLAY + len(_FILLER)
    assert _listed(data) == _MEMBERS


def _reordered_directory(payload: bytes) -> bytes:
    """``payload`` with its central entries in reverse order."""
    eocd = payload.rindex(b"PK\x05\x06")
    _sig, _d, _c, _n, count, cd_size, cd_offset, _len = struct.unpack_from(
        "<4s4H2LH", payload, eocd
    )
    directory = payload[cd_offset : cd_offset + cd_size]
    entries = [b"PK\x01\x02" + e for e in directory.split(b"PK\x01\x02")[1:]]
    assert len(entries) == count == 2
    return payload[:cd_offset] + b"".join(reversed(entries)) + payload[eocd:]


def test_directory_out_of_file_order_still_starts_at_the_first_member() -> None:
    data = _installer(_reordered_directory(_zip()))
    info = detect_format(io.BytesIO(data))
    assert info.payload_offset == _OVERLAY + len(_FILLER)
    assert _listed(data) == _MEMBERS


def test_ordinary_signed_program_larger_than_the_window_reads_no_tail() -> None:
    # Its overlay holds only the certificate: nothing appended, so no tail read. The
    # 512-byte trailer step still reads the last block, as for any source.
    data = pe_file(len(_FILLER), certificate_size=0x2900)
    source = InstrumentedBytesIO(data)
    with pytest.raises(FormatDetectionError):
        detect_format(source)
    assert source.unique_bytes <= SFX_MAX + VALIDATOR_PEEK_MAX + 1024


def _tail_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The tiers each ``read_tail`` call is made for, from now on."""
    tiers: list[str] = []
    real = PrefixWorkspace.read_tail

    def spy(
        self: PrefixWorkspace,
        length: int,
        *,
        end: int | None = None,
        tier: str = "trailer",
    ) -> bytes | None:
        tiers.append(tier)
        return real(self, length, end=end, tier=tier)

    monkeypatch.setattr(PrefixWorkspace, "read_tail", spy)
    return tiers


def test_program_no_larger_than_the_window_reads_no_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = pe_file(_IMAGE, payload=b"\x88" * 100_000 + b"PK\x05\x06" + b"\0" * 18)
    tiers = _tail_reads(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))
    assert "sfx_tail" not in tiers


def test_ordinary_signed_program_makes_no_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tiers = _tail_reads(monkeypatch)
    recorded = _recorded_skips(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(pe_file(len(_FILLER), certificate_size=0x2900)))
    assert "sfx_tail" not in tiers
    assert all(skip.tier != "sfx_tail" for skip in recorded)


def test_elf_stub_with_a_zip_past_the_window_is_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elf = b"\x7fELF\x02\x01\x01" + b"\0" * 57
    tiers = _tail_reads(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(elf + _FILLER + _zip()))
    assert "sfx_tail" not in tiers


@pytest.mark.parametrize(
    "record",
    [
        # A string constant: counts and offsets that point nowhere.
        b"PK\x05\x06" + struct.pack("<4H2LH", 0, 0, 19280, 19280, 9_999_999, 5, 0),
        # No entries, or a real empty ZIP.
        b"PK\x05\x06" + b"\0" * 18,
        # ZIP64 placeholders.
        b"PK\x05\x06" + struct.pack("<4H2LH", 0, 0, 0xFFFF, 0xFFFF, 46, 0, 0),
    ],
    ids=["string-constant", "empty", "zip64-placeholders"],
)
def test_record_that_is_not_corroborated_is_declined(record: bytes) -> None:
    data = _installer(record)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


def test_first_local_header_inside_the_sections_is_declined() -> None:
    # The ZIP's members sit inside the program's own section: not appended data.
    payload = _zip()
    cd_offset = struct.unpack_from("<L", payload, payload.rindex(b"PK\x05\x06") + 16)[0]
    inside = len(_FILLER) + cd_offset
    head = pe_headers([(FILE_ALIGNMENT, _IMAGE + inside)])
    data = head + b"\xcc" * _IMAGE + _FILLER + payload
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))
    # The control: the same bytes with the section ending before the ZIP.
    head = pe_headers([(FILE_ALIGNMENT, _IMAGE)])
    data = head + b"\xcc" * _IMAGE + _FILLER + payload
    assert detect_format(io.BytesIO(data)).format is ArchiveFormat.ZIP


@pytest.mark.parametrize(
    "budget", [BALANCED_BUDGET, FAST_BUDGET], ids=["balanced", "fast"]
)
def test_probe_stays_within_budget(budget: DetectionBudget) -> None:
    data = _installer(_zip())
    info = detect_format(
        io.BytesIO(data), config=ArchiveyConfig(detection_budget=budget)
    )
    assert info.format is ArchiveFormat.ZIP
    assert info.cost_receipt is not None
    assert within_budget(info.cost_receipt, budget)
    assert info.cost_receipt.scanned_bytes <= budget.max_scan_bytes


def _recorded_skips(monkeypatch: pytest.MonkeyPatch) -> list[TierSkip]:
    """Every skip the workspace records, from now on."""
    recorded: list[TierSkip] = []
    real = PrefixWorkspace.record_skip

    def spy(self: PrefixWorkspace, tier: str, reason: TierSkipReason) -> None:
        recorded.append(TierSkip(tier, reason))
        real(self, tier, reason)

    monkeypatch.setattr(PrefixWorkspace, "record_skip", spy)
    return recorded


def test_probe_is_off_with_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = replace(BALANCED_BUDGET, max_scan_bytes=0)
    data = _installer(_zip())
    recorded = _recorded_skips(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data), config=ArchiveyConfig(detection_budget=budget))
    assert TierSkip("sfx_tail", TierSkipReason.NOT_ENABLED_BY_POLICY) in recorded


def test_pipe_records_sfx_tail_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pipe states no length, so the payload end is not known: the probe cannot look,
    # and says so under its own tier.
    recorded = _recorded_skips(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(NonSeekableBytesIO(_installer(_zip())))
    assert _TAIL_SKIP in recorded


def test_short_pipe_records_no_sfx_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pipe that ends inside the window has a known length and no overlay past it.
    recorded = _recorded_skips(monkeypatch)
    with pytest.raises(FormatDetectionError):
        detect_format(NonSeekableBytesIO(pe_file(_IMAGE, payload=b"\x88" * 1000)))
    assert all(skip.tier != "sfx_tail" for skip in recorded)


def test_probe_constants_mirror_the_zip_parser() -> None:
    # Detection keeps literals so it imports no backend module off the probe's path.
    from archivey.internal import detection
    from archivey.internal.backends import zip_parser

    assert detection.TAIL_PROBE_SPAN == zip_parser.EOCD_SEARCH_WINDOW
    assert detection.TAIL_PROBE_ALLOWANCE == (
        detection.TAIL_PROBE_SPAN + zip_parser.TAIL_CONFIRM_READS
    )


def test_member_stream_records_sfx_tail_not_trailer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A seek to a member stream's end re-decodes it, so the tail is not read, and the
    # decline names the probe's own tier.
    data = _installer(_zip())
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("setup.exe", data)
    outer.seek(0)
    recorded = _recorded_skips(monkeypatch)
    with (
        open_archive(outer, seekable_members=True) as reader,
        reader.open("setup.exe") as member,
        pytest.raises(FormatDetectionError),
    ):
        detect_format(member)
    assert _TAIL_SKIP in recorded


def test_probe_access_shape_is_one_seek_toward_the_end() -> None:
    # The span holds the directory and the local header here: one seek toward the
    # end, one back to the end of the prefix, then the exit restore.
    source = InstrumentedBytesIO(_installer(_zip()))
    assert detect_format(source).format is ArchiveFormat.ZIP
    assert source.forward_seeks == 1
    assert source.backward_seeks == 2


def test_probe_reads_records_outside_the_span() -> None:
    # A member larger than the span: the local header lies before it. One more read,
    # with its own seek there and back to the end of the prefix, as every read the
    # workspace makes off the prefix restores the handle.
    big = {"big.bin": bytes(range(256)) * 400, **_MEMBERS}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in big.items():
            archive.writestr(name, data)
    source = InstrumentedBytesIO(_installer(buffer.getvalue()))
    assert detect_format(source).format is ArchiveFormat.ZIP
    assert source.forward_seeks == 2
    assert source.backward_seeks == 3
