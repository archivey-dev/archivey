"""Self-extracting archives: the shared forward scan and the 7z start offset.

A self-extracting archive is an executable stub with a real archive appended, so the
archive magic sits at some offset ``N > 0``. Three pieces have to agree about that
offset — the shared scanner in ``archivey.internal.sfx``, each parser's own scan, and
``detect_format`` — so they are exercised together here rather than once per backend.

The detection half is the one with teeth: before it, a low-entropy ``MZ`` stub in front
of a real RAR/7z/ZIP was reported as ``BROTLI`` and ``open_archive`` returned a
fabricated ``*.uncompressed`` member. A test that only asserted ``FormatDetectionError``
would have stayed green through that, so the cases below assert the *members*.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import zipapp
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import DEFAULT_ARCHIVEY_CONFIG, detect_format, open_archive
from archivey.config import ArchiveyConfig
from archivey.detection_cost import (
    BALANCED_BUDGET,
    FAST_BUDGET,
    DetectionBudget,
)
from archivey.exceptions import (
    CorruptionError,
    FormatDetectionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_detect import validate_rar_main_header
from archivey.internal.backends.rar_parser import RAR5_ID, RAR_ID
from archivey.internal.backends.rar_reader import RarReadBackend
from archivey.internal.backends.sevenzip_detect import (
    validate_sevenzip_signature_header,
)
from archivey.internal.backends.sevenzip_parser import MAGIC_7Z, find_signature_offset
from archivey.internal.backends.sevenzip_reader import SevenZipReadBackend
from archivey.internal.backends.zip_detect import validate_zip_local_header
from archivey.internal.backends.zip_reader import ZipReadBackend
from archivey.internal.password import _PasswordCandidates

# Chunk-boundary tests need the real trim size.
from archivey.internal.sfx import (
    _SCAN_CHUNK,
    MAX_VALIDATED_CANDIDATES,
    SFX_MAX,
    VALIDATOR_PEEK_MAX,
    ExecutableCue,
    HitOutcome,
    MagicHit,
    ScanMiss,
    ScanNeedle,
    executable_cue,
    scan_for_magic,
)
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.codecs.brotli_framing import (
    BrotliBlock,
    parse_metablock,
)
from archivey.internal.streams.streamtools.slice import SlicingStream
from archivey.types import ArchiveFormat
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.detection_cost_util import trailer_allowance, within_budget
from tests.streams_util import NonSeekableBytesIO, brotli_compressed_metablock_header
from tests.test_detection_workspace import InstrumentedBytesIO

# The stub shape from Topic 8 A-34: `MZ` plus low-entropy filler. Deliberately the
# *synthetic* one — real PE/ELF stubs are the easy case, this one is what the Brotli
# content probe claims (see dev-docs/investigations/brotli-content-probe-brief.md).
_STUB = b"MZ" + b"\x90" * 4094
_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_SEVENZIP_FIXTURES = Path(__file__).parent / "fixtures" / "sevenzip"
_SIGNATURE_HEADER_SIZE = 32
# A source not named ``.br`` runs the Brotli probe only with every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def _elf_stub(size: int) -> bytes:
    ident = b"\x7fELF\x02\x01\x01"
    return ident + b"\x00" * (size - len(ident))


_FILES = {
    "alpha.txt": b"alpha\n" * 2000,
    "nested/beta.bin": bytes(range(256)) * 40,
}


def _write_7z(path: Path, *, header_encryption: bool = False) -> None:
    py7zr = pytest.importorskip("py7zr")
    source = path.parent / f"{path.stem}-src"
    for name, data in _FILES.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    password = "hunter2" if header_encryption else None
    with py7zr.SevenZipFile(
        path, "w", password=password, header_encryption=header_encryption
    ) as archive:
        for name in sorted(_FILES):
            archive.write(source / name, arcname=name)


def _sfx(tmp_path: Path, name: str, *, header_encryption: bool = False) -> Path:
    inner = tmp_path / f"{name}-inner.7z"
    _write_7z(inner, header_encryption=header_encryption)
    path = tmp_path / f"{name}.exe"
    path.write_bytes(_STUB + inner.read_bytes())
    return path


# --- the shared scanner ----------------------------------------------------------------


def test_scan_finds_magic_at_offset() -> None:
    data = b"stub" * 100 + MAGIC_7Z + b"rest"
    assert scan_for_magic(io.BytesIO(data), (MAGIC_7Z,)).hit == MagicHit(
        400, MAGIC_7Z, 0
    )


def test_scan_returns_none_when_absent() -> None:
    result = scan_for_magic(io.BytesIO(b"\x00" * 10_000), (MAGIC_7Z,))
    assert result.hit is None
    assert result.miss is ScanMiss.NO_MATCH


def test_scan_finds_magic_straddling_a_chunk_boundary() -> None:
    # The overlap carried between reads is what makes this work; without it a magic
    # split across two 64 KiB reads is invisible.
    for split in range(1, len(MAGIC_7Z)):
        offset = 65536 - split
        data = b"\x00" * offset + MAGIC_7Z + b"\x00" * 128
        assert scan_for_magic(io.BytesIO(data), (MAGIC_7Z,)).hit == MagicHit(
            offset, MAGIC_7Z, 0
        )


def test_scan_returns_the_earliest_of_several_needles() -> None:
    data = b"\x00" * 50 + b"SECOND" + b"\x00" * 50 + b"FIRST"
    # Earliest position wins, not the order the needles were passed in.
    assert scan_for_magic(io.BytesIO(data), (b"FIRST", b"SECOND")).hit == MagicHit(
        50, b"SECOND", 0
    )


def test_scan_requires_the_whole_magic_inside_the_limit() -> None:
    data = b"\x00" * 10 + MAGIC_7Z
    assert scan_for_magic(
        io.BytesIO(data), (MAGIC_7Z,), limit=10 + len(MAGIC_7Z)
    ).hit == MagicHit(10, MAGIC_7Z, 0)
    # One byte short: the magic starts inside the window but does not fit in it.
    assert scan_for_magic(io.BytesIO(data), (MAGIC_7Z,), limit=15).hit is None


def test_scan_stops_at_the_limit() -> None:
    data = b"\x00" * 5000 + MAGIC_7Z
    assert scan_for_magic(io.BytesIO(data), (MAGIC_7Z,), limit=1000).hit is None


_NEEDLE = b"NEEDLE"


def _reject(_peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
    return HitOutcome.NOT_THIS_FORMAT


def _accept(_peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
    return HitOutcome.VALID


def test_scan_skips_a_rejected_decoy_for_a_later_valid_hit() -> None:
    data = b"xxxx" + _NEEDLE + b"yy" + _NEEDLE
    offered = 0

    def second_valid(
        _peek: Callable[[int], bytes], _remaining: int | None
    ) -> HitOutcome:
        nonlocal offered
        offered += 1
        return HitOutcome.VALID if offered == 2 else HitOutcome.NOT_THIS_FORMAT

    assert scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=second_valid).hit == (
        MagicHit(4 + len(_NEEDLE) + 2, _NEEDLE, 0)
    )
    assert offered == 2


def test_scan_falls_back_to_the_first_rejected_candidate() -> None:
    data = b"xxxx" + _NEEDLE + b"yy" + _NEEDLE
    result = scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=_reject)
    assert result.hit == MagicHit(4, _NEEDLE, 0)
    assert result.miss is None
    assert result.rejected_count == 2


def test_scan_falls_back_to_a_damaged_candidate_when_nothing_validates() -> None:
    def damaged(_peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
        return HitOutcome.DAMAGED

    result = scan_for_magic(
        io.BytesIO(b"xxxx" + _NEEDLE), (_NEEDLE,), validator=damaged
    )
    assert result.hit == MagicHit(4, _NEEDLE, 0)
    assert result.miss is None


def test_scan_stops_after_the_rejected_candidate_cap() -> None:
    n = MAX_VALIDATED_CANDIDATES
    data = _NEEDLE * (n + 1)
    offered = 0

    def last_would_pass(
        _peek: Callable[[int], bytes], _remaining: int | None
    ) -> HitOutcome:
        nonlocal offered
        offered += 1
        return HitOutcome.VALID if offered > n else HitOutcome.NOT_THIS_FORMAT

    result = scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=last_would_pass)
    assert result.hit is None
    assert result.miss is ScanMiss.CAPPED
    assert result.rejected_count == n
    assert offered == n


def test_scan_without_a_validator_does_not_apply_the_candidate_cap() -> None:
    data = _NEEDLE * (MAX_VALIDATED_CANDIDATES + 5)
    assert scan_for_magic(io.BytesIO(data), (_NEEDLE,)).hit == MagicHit(0, _NEEDLE, 0)


def test_scan_without_a_validator_matches_a_validator_that_accepts_the_first() -> None:
    data = b"xxxx" + _NEEDLE + b"yy" + _NEEDLE
    bare = scan_for_magic(io.BytesIO(data), (_NEEDLE,))
    accepted = scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=_accept)
    assert bare.hit == accepted.hit == MagicHit(4, _NEEDLE, 0)


def test_scan_without_a_validator_does_not_seek() -> None:
    data = b"xxxx" + _NEEDLE
    src = InstrumentedBytesIO(data)
    assert scan_for_magic(src, (_NEEDLE,)).hit == MagicHit(4, _NEEDLE, 0)
    assert src.forward_seeks == 0
    assert src.backward_seeks == 0


def test_scan_skips_damaged_the_same_as_not_this_format() -> None:
    data = b"xxxx" + _NEEDLE + b"yy" + _NEEDLE
    offered = 0

    def first_damaged(
        _peek: Callable[[int], bytes], _remaining: int | None
    ) -> HitOutcome:
        nonlocal offered
        offered += 1
        return HitOutcome.DAMAGED if offered == 1 else HitOutcome.VALID

    assert scan_for_magic(
        io.BytesIO(data), (_NEEDLE,), validator=first_damaged
    ).hit == (MagicHit(4 + len(_NEEDLE) + 2, _NEEDLE, 0))


def test_scan_validator_does_not_seek_the_source() -> None:
    data = b"xxxx" + _NEEDLE
    src = InstrumentedBytesIO(data)
    assert scan_for_magic(src, (_NEEDLE,), validator=_accept).hit == MagicHit(
        4, _NEEDLE, 0
    )
    assert src.forward_seeks == 0
    assert src.backward_seeks == 0


def test_scan_validator_works_on_a_non_seekable_source() -> None:
    data = b"xxxx" + _NEEDLE + b"yy" + _NEEDLE
    offered = 0

    def second_valid(
        _peek: Callable[[int], bytes], _remaining: int | None
    ) -> HitOutcome:
        nonlocal offered
        offered += 1
        return HitOutcome.VALID if offered == 2 else HitOutcome.NOT_THIS_FORMAT

    src = NonSeekableBytesIO(data)
    assert scan_for_magic(src, (_NEEDLE,), validator=second_valid).hit == MagicHit(
        4 + len(_NEEDLE) + 2, _NEEDLE, 0
    )


def test_scan_passes_remaining_from_origin_when_size_is_known() -> None:
    data = b"xxxx" + _NEEDLE + b"yyyy"
    seen: list[int | None] = []

    def record(_peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        seen.append(remaining)
        return HitOutcome.VALID

    assert scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=record).hit == (
        MagicHit(4, _NEEDLE, 0)
    )
    assert seen == [len(data) - 4]


def test_scan_validator_can_peek_past_the_current_chunk() -> None:
    offset = 65536 - 3
    header = _NEEDLE + b"X" * 100
    data = b"\x00" * offset + header
    seen: list[bytes] = []

    def need_header(peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
        got = peek(len(header))
        seen.append(got)
        return HitOutcome.VALID if got == header else HitOutcome.NOT_THIS_FORMAT

    assert scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=need_header).hit == (
        MagicHit(offset, _NEEDLE, 0)
    )
    assert seen == [header]


def test_scan_does_not_return_a_magic_pulled_past_the_limit() -> None:
    """A validator peek may read past ``limit``; those bytes are not candidates."""
    limit = 20
    data = b"\x00" * 14 + _NEEDLE + _NEEDLE

    def peek_far(peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
        peek(100)
        return HitOutcome.NOT_THIS_FORMAT

    result = scan_for_magic(
        io.BytesIO(data), (_NEEDLE,), limit=limit, validator=peek_far
    )
    # First needle ends at 20 (inside); second starts at 20 (past the bound).
    # Nothing VALID, so the in-window candidate is the fallback. The past-limit
    # needle was never offered.
    assert result.hit == MagicHit(14, _NEEDLE, 0)
    assert result.rejected_count == 1


def test_scan_does_not_drop_a_shorter_needle_that_still_fits() -> None:
    # The ``abs_pos + len(needle) > limit`` skip only fires when the window already
    # holds bytes past ``limit``. The main read loop never stores those; only a
    # validator peek does. LONG at 34 ends at 44 (past 40); the SHRT inside it at
    # 36 ends at 40 (fits). The first SHRT at 0 is rejected and peeks 100 bytes
    # so LONG is visible. Stopping on the straddling needle would return the
    # fallback at 0 instead of 36.
    long, short, limit = b"AASHRTAAAA", b"SHRT", 40
    data = bytearray(b"\x90" * 200)
    data[0:4] = short
    data[34:44] = long
    offered = 0

    def reject_first_then_accept(
        peek: Callable[[int], bytes], _remaining: int | None
    ) -> HitOutcome:
        nonlocal offered
        offered += 1
        if offered == 1:
            peek(100)
            return HitOutcome.NOT_THIS_FORMAT
        return HitOutcome.VALID

    result = scan_for_magic(
        io.BytesIO(bytes(data)),
        (long, short),
        limit=limit,
        validator=reject_first_then_accept,
    )
    assert result.hit == MagicHit(36, short, 0)
    assert result.rejected_count == 1


def test_scan_does_not_double_count_a_candidate_on_a_chunk_boundary() -> None:
    # overlap = max(len) - 1 = 7. A 7-byte needle at _SCAN_CHUNK - 7 sits wholly
    # in the retained overlap and would be validated twice if the next pass
    # searched the overlap from 0 again. Mid-chunk markers cannot catch this.
    long, short = b"A" * 8, b"B" * 7
    origin = _SCAN_CHUNK - len(short)
    data = bytearray(b"\x00" * (_SCAN_CHUNK + 64))
    data[origin : origin + len(short)] = short
    calls = 0

    def reject_all(_peek: Callable[[int], bytes], _remaining: int | None) -> HitOutcome:
        nonlocal calls
        calls += 1
        return HitOutcome.NOT_THIS_FORMAT

    result = scan_for_magic(
        io.BytesIO(bytes(data)), (long, short), validator=reject_all
    )
    assert result.hit == MagicHit(origin, short, 0)
    assert result.rejected_count == 1
    assert calls == 1


def test_scan_probes_source_size_once_per_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.streams.streamtools import source_byte_size as real_size

    calls = {"n": 0}

    def counting(source: object) -> int | None:
        calls["n"] += 1
        return real_size(source)

    monkeypatch.setattr("archivey.internal.sfx.source_byte_size", counting)
    data = _NEEDLE * 10
    scan_for_magic(io.BytesIO(data), (_NEEDLE,), validator=_reject)
    assert calls["n"] == 1


def test_scan_rejects_a_nonzero_needle_offset_with_a_validator() -> None:
    with pytest.raises(ValueError, match="offset-0 needles"):
        scan_for_magic(
            io.BytesIO(_NEEDLE),
            (ScanNeedle(_NEEDLE, 1),),
            validator=_accept,
        )


# --- 7z: signature at a nonzero origin -------------------------------------------------


def test_find_signature_offset_fast_path_and_restore() -> None:
    fp = io.BytesIO(MAGIC_7Z + b"tail")
    assert find_signature_offset(fp) == 0
    assert fp.tell() == 0, "the probe must leave the stream where it found it"


def test_find_signature_offset_scans_and_restores() -> None:
    # next_size=10 needs 10 bytes after the 32-byte signature or remaining-known
    # sources grade the hit DAMAGED (declared end past EOF).
    payload = _sevenzip_signature(next_size=10) + b"\x00" * 10
    fp = io.BytesIO(_STUB + payload)
    assert find_signature_offset(fp) == len(_STUB)
    assert fp.tell() == 0


def test_find_signature_offset_skips_a_decoy_magic() -> None:
    payload = _sevenzip_signature(next_size=10) + b"\x00" * 10
    fp = io.BytesIO(b"MZ" + MAGIC_7Z + b"\x90" * 40 + payload)
    assert find_signature_offset(fp) == 2 + len(MAGIC_7Z) + 40
    assert fp.tell() == 0


def test_find_signature_offset_falls_back_to_a_truncated_magic() -> None:
    # Six bytes of magic, no signature header: not VALID, and the only candidate.
    fp = io.BytesIO(_STUB + MAGIC_7Z)
    assert find_signature_offset(fp) == len(_STUB)
    assert fp.tell() == 0


def test_find_signature_offset_reports_the_scan_window_on_a_miss() -> None:
    with raises_corruption_not_truncation(match="no signature within the 1000-byte"):
        find_signature_offset(io.BytesIO(b"\x90" * 1000), limit=1000)


def test_find_signature_offset_names_the_candidate_cap() -> None:
    data = MAGIC_7Z * (MAX_VALIDATED_CANDIDATES + 1)
    with raises_corruption_not_truncation(
        match="stopped after 256 rejected candidates"
    ):
        find_signature_offset(io.BytesIO(b"MZ" + data), limit=2 + len(data))


def test_forced_format_truncated_7z_names_the_truncation() -> None:
    payload = _sevenzip_signature(next_size=100) + b"\x00" * 10
    with pytest.raises(
        TruncatedError, match="Truncated 7z next header: expected 100 bytes"
    ):
        open_archive(io.BytesIO(_STUB + payload), format=ArchiveFormat.SEVEN_Z)


def test_forced_format_crc_damaged_7z_names_the_crc() -> None:
    with raises_corruption_not_truncation(match="7z signature header CRC mismatch"):
        open_archive(
            io.BytesIO(_STUB + _crc_damaged_sevenzip_signature()),
            format=ArchiveFormat.SEVEN_Z,
        )


def test_forced_format_empty_7z_behind_a_stub_opens() -> None:
    with open_archive(
        io.BytesIO(_STUB + _sevenzip_signature()), format=ArchiveFormat.SEVEN_Z
    ) as archive:
        assert list(archive.members()) == []
        assert archive.info.member_count == 0


def test_forced_format_crc_damaged_rar4_names_the_crc() -> None:
    payload = bytearray((_RAR_FIXTURES / "basic_nonsolid__rar4.rar").read_bytes())
    payload[len(RAR_ID)] ^= 0xFF
    with raises_corruption_not_truncation(match="RAR3 MAIN header CRC mismatch"):
        open_archive(io.BytesIO(_STUB + bytes(payload)), format=ArchiveFormat.RAR)


def test_forced_format_crc_damaged_rar5_names_the_crc() -> None:
    payload = bytearray((_RAR_FIXTURES / "basic_nonsolid__.rar").read_bytes())
    payload[len(RAR5_ID)] ^= 0xFF
    with raises_corruption_not_truncation(match="RAR5 header CRC mismatch"):
        open_archive(io.BytesIO(_STUB + bytes(payload)), format=ArchiveFormat.RAR)


def test_forced_format_rar_miss_names_the_scan_window() -> None:
    with raises_corruption_not_truncation(match="no signature within the"):
        open_archive(io.BytesIO(b"MZ" + b"\x90" * 1000), format=ArchiveFormat.RAR)


@requires("py7zr")
def test_forced_format_opens_a_7z_behind_a_stub(tmp_path: Path) -> None:
    # Forced format=RAR has always worked on an SFX file; this is the 7z parity that
    # used to raise CorruptionError("bad magic bytes").
    path = _sfx(tmp_path, "plain")
    with open_archive(path, format=ArchiveFormat.SEVEN_Z) as archive:
        members = {m.name: m for m in archive.members() if m.is_file}
        assert set(members) == set(_FILES)
        for name, expected in _FILES.items():
            assert archive.read(members[name]) == expected


@requires("py7zr")
def test_forced_format_skips_a_decoy_7z_needle(tmp_path: Path) -> None:
    stub = b"MZ" + b"\x90" * 512 + MAGIC_7Z + b"\x90" * 3576
    path = tmp_path / "decoy-forced.exe"
    path.write_bytes(stub + _7z_bytes(tmp_path))
    with open_archive(path, format=ArchiveFormat.SEVEN_Z) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


def test_forced_format_skips_a_decoy_rar_needle(tmp_path: Path) -> None:
    payload = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    stub = b"MZ" + b"\x90" * 32 + RAR_ID + b"\x90" * 32
    path = tmp_path / "decoy-forced.rar.exe"
    path.write_bytes(stub + payload)
    with open_archive(_RAR_FIXTURES / "stored_m0.rar") as expected:
        want = {m.name for m in expected.members() if m.is_file}
    with open_archive(path, format=ArchiveFormat.RAR) as archive:
        got = {m.name for m in archive.members() if m.is_file}
    assert got == want


@requires("py7zr")
def test_forced_format_opens_packed_and_encoded_header_behind_a_stub(
    tmp_path: Path,
) -> None:
    # Pack-stream and encoded-header offsets are the ones that would silently read the
    # stub if only the signature seek had been rebased.
    path = _sfx(tmp_path, "encoded", header_encryption=True)
    with open_archive(
        path, format=ArchiveFormat.SEVEN_Z, password="hunter2"
    ) as archive:
        members = {m.name: m for m in archive.members() if m.is_file}
        assert set(members) == set(_FILES)
        for name, expected in _FILES.items():
            assert archive.read(members[name]) == expected


@requires("py7zr")
def test_no_7z_magic_within_the_window_raises_rather_than_listing_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "not-an-archive.exe"
    path.write_bytes(b"MZ" + b"\x90" * 200_000)
    with raises_corruption_not_truncation(match="Not a 7z archive"):
        open_archive(path, format=ArchiveFormat.SEVEN_Z)


def _open_with(source, *, password=None, start_offset=0):
    from archivey.internal.source import ArchiveSource

    return SevenZipReadBackend().open_read(
        ArchiveSource.for_path(source)
        if isinstance(source, Path)
        else ArchiveSource.for_stream(source),
        format=ArchiveFormat.SEVEN_Z,
        streaming=False,
        passwords=_PasswordCandidates.from_input(password),
        encoding=None,
        archive_name="equiv.exe",
        config=DEFAULT_ARCHIVEY_CONFIG,
        start_offset=start_offset,
    )


@requires("py7zr")
@pytest.mark.parametrize("header_encryption", [False, True])
def test_start_offset_on_a_path_equals_an_offset_view_on_a_stream(
    tmp_path: Path, header_encryption: bool
) -> None:
    """``start_offset`` means "as if you had sliced the source" — checked literally.

    The two opens differ only in how the payload origin is expressed. Any divergence
    means the offset leaked into something other than the view.
    """
    path = _sfx(tmp_path, "equiv", header_encryption=header_encryption)
    password = "hunter2" if header_encryption else None

    with _open_with(path, password=password, start_offset=len(_STUB)) as by_offset:
        by_offset_read = {
            m.name: by_offset.read(m) for m in by_offset.members() if m.is_file
        }

    with (
        path.open("rb") as handle,
        _open_with(
            SlicingStream(handle, start=len(_STUB)), password=password
        ) as by_view,
    ):
        by_view_read = {m.name: by_view.read(m) for m in by_view.members() if m.is_file}

    assert by_offset_read == by_view_read == _FILES


@requires("py7zr")
def test_start_offset_is_believed_rather_than_rescanned(tmp_path: Path) -> None:
    """A CRC-valid decoy in the stub separates "opened at the offset" from "scanned again".

    With the offset supplied the decoy sits behind the origin and is invisible; without
    it the forced-format scan accepts the first VALID signature — the decoy — and fails
    parsing its header. An invalid decoy (bare magic) is skipped, so it cannot make
    this distinction, and neither can one whose declared end stops short of EOF (the
    scan prefers the real payload over it): this decoy declares its end at EOF.
    """
    inner = tmp_path / "decoy-inner.7z"
    _write_7z(inner)
    decoy_origin = 2 + 512
    stub_len = decoy_origin + 32 + 3576
    remaining = stub_len + inner.stat().st_size - decoy_origin
    decoy = _sevenzip_signature(next_offset=remaining - 32 - 10, next_size=10)
    stub = b"MZ" + b"\x90" * 512 + decoy + b"\x90" * 3576
    assert len(stub) == stub_len
    path = tmp_path / "decoy.exe"
    path.write_bytes(stub + inner.read_bytes())

    with _open_with(path, start_offset=len(stub)) as archive:
        assert {m.name for m in archive.members() if m.is_file} == set(_FILES)

    with raises_corruption_not_truncation():
        _open_with(path)


def test_a_format_without_stubs_refuses_a_start_offset(tmp_path: Path) -> None:
    from archivey.internal.backends.tar_reader import TarReadBackend
    from archivey.internal.source import ArchiveSource

    path = tmp_path / "x.tar"
    path.write_bytes(b"\x00" * 1024)
    with pytest.raises(UnsupportedFeatureError, match="nonzero start offset"):
        TarReadBackend().open_read(
            ArchiveSource.for_path(path),
            format=ArchiveFormat.TAR,
            streaming=False,
            passwords=None,
            encoding=None,
            archive_name=path.name,
            config=DEFAULT_ARCHIVEY_CONFIG,
            start_offset=64,
        )


def test_sfx_max_is_one_shared_bound() -> None:
    """RAR, 7z, the forward ZIP walk and detection bind to the same constant, not
    drifting copies."""
    from archivey.internal.backends import rar_parser, zip_local_walk

    assert rar_parser.SFX_MAX is SFX_MAX
    assert zip_local_walk.SFX_MAX is SFX_MAX


# --- detection: executable cues ---------------------------------------------------------


def _pe_stub(size: int = 8192, filler: bytes = b"\x90") -> bytes:
    """A DOS header whose ``e_lfanew`` really points at a ``PE\\0\\0`` signature."""
    header = bytearray(b"\x00" * 0x40)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = struct.pack("<I", 0x80)
    body = bytearray(filler * (size - 0x40))
    body[0x80 - 0x40 : 0x80 - 0x40 + 4] = b"PE\x00\x00"
    return bytes(header) + bytes(body)


def test_executable_cue_grades_the_evidence() -> None:
    assert executable_cue(b"not an executable at all") is ExecutableCue.NONE
    # `MZ` alone is two bytes — enough to look for a payload, not enough to overrule a
    # content probe.
    assert executable_cue(_STUB) is ExecutableCue.WEAK
    assert executable_cue(_pe_stub()) is ExecutableCue.STRONG
    assert executable_cue(b"\x7fELF" + b"\x00" * 64) is ExecutableCue.WEAK
    assert executable_cue(b"\x7fELF\x02\x01\x01" + b"\x00" * 64) is ExecutableCue.STRONG
    # Shebang is always weak: two bytes, never a confirmed executable.
    assert executable_cue(b"#!/usr/bin/env python3\n") is ExecutableCue.WEAK
    assert executable_cue(b"#!/bin/sh\n") is ExecutableCue.WEAK


def test_pe_cue_does_not_require_alignment_and_does_not_reject_a_large_e_lfanew() -> (
    None
):
    """e_lfanew past the prefix is WEAK (cannot confirm cheaply), never NONE.

    An unaligned pointer that still lands on ``PE\\0\\0`` is STRONG — alignment is
    not a validity requirement.
    """
    unaligned = bytearray(b"\x00" * 0x40 + b"\x00" * 256)
    unaligned[0:2] = b"MZ"
    unaligned[0x3C:0x40] = struct.pack("<I", 0x81)
    unaligned[0x81:0x85] = b"PE\x00\x00"
    assert executable_cue(bytes(unaligned)) is ExecutableCue.STRONG

    far = bytearray(_STUB)
    far[0x3C:0x40] = struct.pack("<I", 0x2000)  # past the 4 KiB stub
    assert far[:2] == b"MZ"
    assert executable_cue(bytes(far)) is ExecutableCue.WEAK


def test_a_real_elf_binary_is_a_strong_cue() -> None:
    """The strong cue against a shipped binary, not a hand-built header.

    Sampling the platform's own binaries is the point — a synthetic ELF header only
    proves the parser reads what this file wrote. Skipped where those binaries are not
    ELF: macOS ships Mach-O and Windows PE.
    """
    for candidate in (Path("/usr/bin/env"), Path("/bin/ls"), Path("/usr/bin/python3")):
        if not candidate.is_file():
            continue
        prefix = candidate.read_bytes()[:4096]
        if prefix.startswith(b"\x7fELF"):
            assert executable_cue(prefix) is ExecutableCue.STRONG
            return
    pytest.skip("no ELF binary on this platform to sample")


def _thin_macho64_stub(size: int = 8192, filler: bytes = b"\x90") -> bytes:
    """A little-endian 64-bit Mach-O header whose ``cputype`` / ``filetype`` parse."""
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<iiIIIII",
        0x01000007,  # CPU_TYPE_X86_64
        3,  # CPU_SUBTYPE_X86_64_ALL
        2,  # MH_EXECUTE
        0,
        0,
        0,
        0,
    )
    pad = filler * ((size - len(header) + len(filler) - 1) // len(filler))
    return (header + pad)[:size]


def _fat_macho_stub(size: int = 8192, filler: bytes = b"\x00") -> bytes:
    """A big-endian fat header with one x86_64 arch — parses, unlike a ``.class`` file."""
    header = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">iiIII", 0x01000007, 3, 0x1000, 0x100, 12)
    pad = filler * (size - len(header) - len(arch))
    return (header + arch + pad)[:size]


def _minimal_class_file(*, padding: int = 0) -> bytes:
    """Java class-file magic ``ca fe ba be`` plus a Java 8 version header."""
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 1) + b"\x00" * padding


def test_mach_o_cue_requires_a_parsing_header() -> None:
    """Mach-O raises no cue until the header parses — ``ca fe ba be`` is also Java."""
    assert executable_cue(b"\xcf\xfa\xed\xfe" + b"\x00" * 4092) is ExecutableCue.NONE
    assert executable_cue(_thin_macho64_stub()) is ExecutableCue.STRONG
    assert executable_cue(_fat_macho_stub()) is ExecutableCue.STRONG
    assert executable_cue(_minimal_class_file(padding=4092)) is ExecutableCue.NONE
    # Fat magic whose nfat_arch is implausible (the class-file major-version shape).
    assert executable_cue(b"\xca\xfe\xba\xbe" + b"\x00" * 4092) is ExecutableCue.NONE


# --- detection: the SFX matrix ----------------------------------------------------------


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in _FILES.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _rar_bytes(tmp_path: Path) -> bytes:
    source = tmp_path / "rar-src"
    for name, data in _FILES.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    out = tmp_path / "payload.rar"
    subprocess.run(
        ["rar", "a", "-r", "-ep1", str(out), "."],
        cwd=source,
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


def _7z_bytes(tmp_path: Path) -> bytes:
    inner = tmp_path / "payload.7z"
    _write_7z(inner)
    return inner.read_bytes()


def _assert_sfx_opens(path: Path, expected: ArchiveFormat, offset: int) -> None:
    # Every probe on, so the scan is shown to win over the Brotli probe, not to run alone.
    detected = detect_format(path, config=_ALWAYS_PROBE)
    assert detected.format == expected
    assert detected.payload_offset == offset
    assert detected.detected_by == "sfx_scan"
    with open_archive(path, config=_ALWAYS_PROBE) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


@requires("py7zr")
def test_sfx_7z_behind_a_low_entropy_stub_is_not_brotli(tmp_path: Path) -> None:
    path = tmp_path / "installer.exe"
    path.write_bytes(_STUB + _7z_bytes(tmp_path))
    _assert_sfx_opens(path, ArchiveFormat.SEVEN_Z, len(_STUB))


def test_sfx_zip_behind_a_low_entropy_stub_is_not_brotli(tmp_path: Path) -> None:
    path = tmp_path / "installer.exe"
    path.write_bytes(_STUB + _zip_bytes())
    _assert_sfx_opens(path, ArchiveFormat.ZIP, len(_STUB))


# Live ``rar a`` — skips on CI (unrar only). See tests/fixtures/rar/README.md.
@requires_binary("rar")
def test_sfx_rar_behind_a_low_entropy_stub_is_not_brotli(tmp_path: Path) -> None:
    path = tmp_path / "installer.exe"
    path.write_bytes(_STUB + _rar_bytes(tmp_path))
    _assert_sfx_opens(path, ArchiveFormat.RAR, len(_STUB))


# Live ``rar a -sfx`` — skips on CI (unrar only). See tests/fixtures/rar/README.md.
@requires_binary("rar")
def test_a_real_sfx_archive_auto_opens(tmp_path: Path) -> None:
    """`rar a -sfx` output: a real ~250 KB stub, not a hand-rolled one.

    Before the scan this raised FormatDetectionError — the loud half of the same defect.
    """
    source = tmp_path / "sfx-src"
    source.mkdir()
    (source / "alpha.txt").write_bytes(_FILES["alpha.txt"])
    path = tmp_path / "real.exe"
    subprocess.run(
        ["rar", "a", "-ep", "-sfx", str(path), "alpha.txt"],
        cwd=source,
        check=True,
        capture_output=True,
    )
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.RAR
    assert detected.payload_offset > 0
    with open_archive(path) as archive:
        assert archive.read("alpha.txt") == _FILES["alpha.txt"]


def test_executable_prefix_with_a_pe_header_never_becomes_a_stream_codec(
    tmp_path: Path,
) -> None:
    """A confirmed PE with no archive in the window: an error, never a fake member."""
    path = tmp_path / "plain.exe"
    path.write_bytes(_pe_stub(200_000))
    with pytest.raises(FormatDetectionError, match="executable header"):
        detect_format(path)


def test_a_weak_cue_still_lets_a_content_probe_answer(tmp_path: Path) -> None:
    """`MZ` is two bytes: a probe-matched stream that starts with them stays detectable.

    The short A-34 stub (`MZ` + ``\\x90`` × 4094) is no longer a probe hit — the framing
    gate rejects its declared meta-block overrun. A longer stream with the same weak cue
    and a *fitting* first block still answers ``BROTLI``, which is what proves the weak
    cue does not suppress content probes.
    """
    brotli = pytest.importorskip("brotli")
    del brotli
    # Smallest MZ-leading uncompressed first-block the bit layout allows (~1 MiB body).
    header = bytes.fromhex("4d5a0088")
    framing = parse_metablock(header)
    assert framing.outcome is BrotliBlock.UNCOMPRESSED
    assert framing.consumed is not None and framing.declared_length is not None
    need = framing.consumed + framing.declared_length
    # Pad a compressed second link so the chain walk stops rather than rejecting
    # exact EOF-without-ISLAST (same residual shape as OLE/COFF fixtures).
    second = brotli_compressed_metablock_header(first=False)
    path = tmp_path / "weak.bin"
    path.write_bytes(header + b"\x90" * (need - len(header)) + second + b"\x00" * 8)
    assert executable_cue(path.read_bytes()[:8]) is ExecutableCue.WEAK
    detected = detect_format(path, config=_ALWAYS_PROBE)
    assert detected.format == ArchiveFormat.BROTLI
    assert detected.detected_by == "content_probe"


def test_a_real_brotli_stream_is_unaffected(tmp_path: Path) -> None:
    brotli = pytest.importorskip("brotli")
    path = tmp_path / "payload.bin"
    path.write_bytes(brotli.compress(b"hello world\n" * 500))
    detected = detect_format(path, config=_ALWAYS_PROBE)
    assert detected.format == ArchiveFormat.BROTLI
    assert detected.detected_by == "content_probe"
    assert detected.payload_offset == 0


def test_no_archive_needle_in_the_window_falls_through_to_the_extension(
    tmp_path: Path,
) -> None:
    path = tmp_path / "mislabelled.zip"
    path.write_bytes(_pe_stub(100_000))
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.detected_by == "extension"
    assert detected.payload_offset == 0


def test_the_scan_does_not_reach_past_the_shared_bound(tmp_path: Path) -> None:
    path = tmp_path / "far.exe"
    path.write_bytes(b"MZ" + b"\x00" * SFX_MAX + _zip_bytes())
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_detection_leaves_a_non_seekable_stream_replayable(tmp_path: Path) -> None:
    """The scan peeks; it must not eat the bytes the backend still needs.

    A pipe cannot be rewound, so this is what stops the SFX window from being a
    destructive read for the streaming ZIP reader this repo is heading towards.
    """
    payload = _STUB + _zip_bytes()
    source = ArchiveSource.for_stream(io.BytesIO(payload))
    detected = detect_format(source)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.payload_offset == len(_STUB)
    assert source.read() == payload


# --- the payload_offset hand-off --------------------------------------------------------


@pytest.mark.parametrize(
    "builder,expected",
    [
        pytest.param(lambda tmp: _zip_bytes(), ArchiveFormat.ZIP, id="zip"),
        pytest.param(
            _7z_bytes,
            ArchiveFormat.SEVEN_Z,
            id="7z",
            marks=requires("py7zr"),
        ),
        pytest.param(
            _rar_bytes,
            ArchiveFormat.RAR,
            id="rar",
            marks=requires_binary("rar"),  # live rar a; see fixtures/rar/README.md
        ),
    ],
)
def test_auto_open_matches_an_explicitly_sliced_stream(
    tmp_path: Path, builder, expected: ArchiveFormat
) -> None:
    """Auto-open of an SFX file equals opening a view whose byte 0 is the payload.

    The hand-off is an argument rather than a slice so a path source stays a path; this
    is the assertion that the two are nonetheless the same archive.
    """
    payload = builder(tmp_path)
    path = tmp_path / "installer.exe"
    path.write_bytes(_STUB + payload)

    with open_archive(path) as auto:
        assert auto.format == expected
        auto_read = {m.name: auto.read(m) for m in auto.members() if m.is_file}

    with (
        path.open("rb") as handle,
        open_archive(SlicingStream(handle, start=len(_STUB))) as sliced,
    ):
        sliced_read = {m.name: sliced.read(m) for m in sliced.members() if m.is_file}

    assert auto_read == sliced_read == _FILES


def test_a_stub_carrying_a_decoy_zip_header_does_not_move_the_answer(
    tmp_path: Path,
) -> None:
    """ZIP is sliced at the detected offset rather than left to self-adjust.

    zipfile would find the EOCD from the tail and correct for a stub on its own, so this
    only fails if the slice is dropped — the point being that ``start_offset`` decides
    where the archive starts, not the file's own tail arithmetic.
    """
    payload = _zip_bytes()
    path = tmp_path / "installer.exe"
    path.write_bytes(_STUB + payload)

    detected = detect_format(path)
    assert detected.payload_offset == len(_STUB)
    with open_archive(path) as archive:
        assert {
            m.name: archive.read(m) for m in archive.members() if m.is_file
        } == _FILES


@requires("py7zr")
def test_a_decoy_7z_needle_is_skipped_for_the_real_payload(tmp_path: Path) -> None:
    """Six ``7z`` magic bytes fail signature-header identity; the scan resumes.

    Before the validator this claimed offset 514 (the decoy) and ``open_archive``
    raised ``CorruptionError``. A decoy is ``NOT_THIS_FORMAT`` (major version is
    ``0x90``), and the real signature further on is the answer (task 4.4).
    """
    stub = b"MZ" + b"\x90" * 512 + MAGIC_7Z + b"\x90" * 3576
    path = tmp_path / "decoy-7z.exe"
    path.write_bytes(stub + _7z_bytes(tmp_path))
    _assert_sfx_opens(path, ArchiveFormat.SEVEN_Z, len(stub))


@pytest.mark.parametrize("filler", [b"\x90", b"\x00"], ids=["nop-fill", "zero-fill"])
def test_a_decoy_zip_needle_is_skipped_for_the_real_payload(
    tmp_path: Path, filler: bytes
) -> None:
    """Four ``PK\\x03\\x04`` bytes fail local-header sanity; the scan resumes.

    Before the validator this claimed offset 514 (the decoy) and still opened, because
    zipfile locates the EOCD from the tail. The cheap check must not widen that: a
    decoy is ``NOT_THIS_FORMAT``, and the real local header further on is the answer.
    Zero-fill is the usual ELF/PE stub padding; ``0x90`` is the synthetic A-34 stub.
    """
    stub = b"MZ" + filler * 512 + b"PK\x03\x04" + filler * 3576
    path = tmp_path / "decoy-zip.exe"
    payload = _zip_bytes()
    path.write_bytes(stub + payload)

    detected = detect_format(path)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.payload_offset == len(stub)
    with open_archive(path) as archive:
        assert {
            m.name: archive.read(m) for m in archive.members() if m.is_file
        } == _FILES


def _peek_view(data: bytes) -> Callable[[int], bytes]:
    def peek_more(n: int) -> bytes:
        return data[:n]

    return peek_more


def test_zip_local_header_validator_accepts_a_real_header_and_rejects_a_decoy() -> None:
    payload = _zip_bytes()
    assert payload[:4] == b"PK\x03\x04"
    assert validate_zip_local_header(_peek_view(payload), None) is HitOutcome.VALID
    assert (
        validate_zip_local_header(_peek_view(b"PK\x03\x04"), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    assert (
        validate_zip_local_header(_peek_view(b"PK\x03\x04" + b"\x90" * 40), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    assert (
        validate_zip_local_header(_peek_view(b"PK\x03\x04" + b"\x00" * 40), None)
        is HitOutcome.NOT_THIS_FORMAT
    )

    def _header(
        *,
        version: int = 20,
        flags: int = 0,
        method: int = 8,
        name_len: int = 1,
        extra_len: int = 0,
        rest: bytes = b"a",
    ) -> bytes:
        return (
            b"PK\x03\x04"
            + struct.pack(
                "<HHHHHIIIHH",
                version,
                flags,
                method,
                0,
                0,
                0,
                0,
                0,
                name_len,
                extra_len,
            )
            + rest
        )

    assert validate_zip_local_header(_peek_view(_header()), None) is HitOutcome.VALID
    assert (
        validate_zip_local_header(_peek_view(_header(method=20)), None)
        is HitOutcome.VALID
    )
    # 94 is MP3, which WinZip writes for .mp3 members.
    assert (
        validate_zip_local_header(_peek_view(_header(method=94)), None)
        is HitOutcome.VALID
    )
    assert (
        validate_zip_local_header(_peek_view(_header(version=0)), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    assert (
        validate_zip_local_header(_peek_view(_header(name_len=0, rest=b"")), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    # Reserved GP-flag bit 15.
    assert (
        validate_zip_local_header(_peek_view(_header(flags=0x8000)), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    assert (
        validate_zip_local_header(_peek_view(_header(method=11)), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    assert (
        validate_zip_local_header(_peek_view(_header(name_len=20, rest=b"short")), None)
        is HitOutcome.NOT_THIS_FORMAT
    )
    # Source remaining, not the peek helper: a view that could supply the name
    # still fails identity when those bytes sit past EOF (F7).
    full = _header(name_len=20, rest=b"abcdefghijklmnopqrst")
    assert validate_zip_local_header(_peek_view(full), None) is HitOutcome.VALID
    assert (
        validate_zip_local_header(_peek_view(full), remaining=30)
        is HitOutcome.NOT_THIS_FORMAT
    )


def test_zip_clamped_name_extra_peek_is_valid_when_remaining_is_known() -> None:
    """With ``remaining`` known, name/extra existence is a length compare, not a peek."""
    name = b"abcdefghijklmnop"
    extra = b"xy"
    header = (
        b"PK\x03\x04"
        + struct.pack("<HHHHHIIIHH", 20, 0, 8, 0, 0, 0, 0, 0, len(name), len(extra))
        + name
        + extra
    )
    needed = 30 + len(name) + len(extra)
    assert needed == 48

    def clamped(n: int) -> bytes:
        return header[: min(n, 40)]

    assert validate_zip_local_header(clamped, len(header)) is HitOutcome.VALID
    assert validate_zip_local_header(clamped, None) is HitOutcome.NOT_THIS_FORMAT
    assert validate_zip_local_header(_peek_view(header), None) is HitOutcome.VALID


def _sevenzip_signature(
    *,
    major: int = 0,
    next_offset: int = 0,
    next_size: int = 0,
    next_crc: int = 0,
    start_crc: int | None = None,
) -> bytes:
    start = struct.pack("<QQI", next_offset, next_size, next_crc)
    crc = zlib.crc32(start) & 0xFFFFFFFF if start_crc is None else start_crc
    return MAGIC_7Z + bytes((major, 0)) + crc.to_bytes(4, "little") + start


def _crc_damaged_sevenzip_signature() -> bytes:
    damaged = bytearray(_sevenzip_signature())
    damaged[8] ^= 0xFF
    return bytes(damaged)


@pytest.mark.parametrize(
    ("payload", "remaining", "expected"),
    [
        pytest.param(
            (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes(),
            None,
            HitOutcome.VALID,
            id="real-fixture",
        ),
        pytest.param(
            (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes(),
            len((_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()),
            HitOutcome.VALID,
            id="real-fixture-exact-eof",
        ),
        pytest.param(MAGIC_7Z, None, HitOutcome.NOT_THIS_FORMAT, id="truncated-magic"),
        pytest.param(
            _sevenzip_signature(),
            None,
            HitOutcome.NOT_THIS_FORMAT,
            id="empty-crc-valid-is-not-sfx",
        ),
        pytest.param(
            MAGIC_7Z + b"\x90" * 40,
            None,
            HitOutcome.NOT_THIS_FORMAT,
            id="wrong-major-filler",
        ),
        pytest.param(
            _crc_damaged_sevenzip_signature(),
            None,
            HitOutcome.DAMAGED,
            id="crc-mismatch",
        ),
        pytest.param(
            _sevenzip_signature(major=1),
            None,
            HitOutcome.NOT_THIS_FORMAT,
            id="major-version-1",
        ),
        pytest.param(
            _sevenzip_signature(next_offset=100, next_size=10),
            _SIGNATURE_HEADER_SIZE,
            HitOutcome.DAMAGED,
            id="declared-end-overruns-known-remaining",
        ),
        pytest.param(
            _sevenzip_signature(next_offset=100, next_size=10),
            None,
            HitOutcome.VALID,
            id="declared-end-unknown-remaining",
        ),
        pytest.param(
            _sevenzip_signature(next_offset=0, next_size=10),
            _SIGNATURE_HEADER_SIZE + 10,
            HitOutcome.VALID,
            id="declared-end-equals-remaining",
        ),
        pytest.param(
            _sevenzip_signature(next_size=(64 << 20) + 1),
            None,
            HitOutcome.DAMAGED,
            id="oversized-next-header",
        ),
        pytest.param(
            _sevenzip_signature(next_offset=0, next_size=10)
            + b"config after payload\n",
            None,
            HitOutcome.VALID,
            id="trailing-bytes",
        ),
        pytest.param(
            _sevenzip_signature(next_offset=0, next_size=10),
            _SIGNATURE_HEADER_SIZE + 10 + 5,
            HitOutcome.VALID_SHORT,
            id="declared-end-short-of-known-remaining",
        ),
    ],
)
def test_sevenzip_signature_validator(
    payload: bytes, remaining: int | None, expected: HitOutcome
) -> None:
    assert (
        validate_sevenzip_signature_header(_peek_view(payload), remaining) is expected
    )


def test_sevenzip_validator_peeks_only_the_signature_header() -> None:
    """Declared-end confirmation is a length compare, not a prefix grow (F2)."""
    next_offset = 1_900_000
    sig = _sevenzip_signature(next_offset=next_offset, next_size=64)
    peeked: list[int] = []

    def peek_more(n: int) -> bytes:
        peeked.append(n)
        return (sig + bytes(n))[:n]

    remaining = _SIGNATURE_HEADER_SIZE + next_offset + 64
    assert validate_sevenzip_signature_header(peek_more, remaining) is HitOutcome.VALID
    assert peeked == [_SIGNATURE_HEADER_SIZE]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param(
            (_RAR_FIXTURES / "stored_m0.rar").read_bytes(),
            HitOutcome.VALID,
            id="rar5",
        ),
        pytest.param(
            (_RAR_FIXTURES / "basic_nonsolid__rar4.rar").read_bytes(),
            HitOutcome.VALID,
            id="rar4",
        ),
        pytest.param(
            (_RAR_FIXTURES / "encrypted_header__.rar").read_bytes(),
            HitOutcome.VALID,
            id="rar5-encrypted-headers",
        ),
        pytest.param(RAR_ID, HitOutcome.NOT_THIS_FORMAT, id="truncated-rar4"),
        pytest.param(RAR5_ID, HitOutcome.NOT_THIS_FORMAT, id="truncated-rar5"),
    ],
)
def test_rar_main_header_validator(payload: bytes, expected: HitOutcome) -> None:
    assert validate_rar_main_header(_peek_view(payload), None) is expected


def test_rar_main_header_validator_crc_fail_is_damaged() -> None:
    rar5 = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    damaged = bytearray(rar5[:64])
    damaged[len(RAR5_ID)] ^= 0xFF
    assert (
        validate_rar_main_header(_peek_view(bytes(damaged)), None) is HitOutcome.DAMAGED
    )


@pytest.mark.parametrize(
    ("filename", "cut"),
    [
        ("stored_m0.rar", len(RAR5_ID)),
        ("stored_m0.rar", 13),
        ("stored_m0.rar", 18),
        ("basic_nonsolid__rar4.rar", len(RAR_ID)),
        ("basic_nonsolid__rar4.rar", 18),
    ],
    ids=["rar5-magic", "rar5-vint", "rar5-header", "rar4-magic", "rar4-header"],
)
def test_rar_short_peek_is_not_a_rar_even_when_remaining_is_known(
    filename: str, cut: int
) -> None:
    """A header the validator was not given is not checked, so it is not ``VALID``.

    Both scans give a validator every byte up to ``VALIDATOR_PEEK_MAX`` that the
    source holds, so a short peek means the bytes are not there. A ``remaining`` that
    claims they are cannot stand in for the header CRC.
    """
    payload = (_RAR_FIXTURES / filename).read_bytes()

    def short(n: int) -> bytes:
        return payload[: min(n, cut)]

    assert validate_rar_main_header(short, len(payload)) is HitOutcome.NOT_THIS_FORMAT
    assert validate_rar_main_header(short, None) is HitOutcome.NOT_THIS_FORMAT
    assert validate_rar_main_header(_peek_view(payload), None) is HitOutcome.VALID


def test_rar5_truncated_vint_with_every_byte_in_hand_is_not_a_rar() -> None:
    """An unterminated vint in a prefix holding all ``remaining`` bytes stays a reject."""
    payload = RAR5_ID + b"\xaa\xbb\xcc\xdd" + b"\x80" * 16
    assert (
        validate_rar_main_header(_peek_view(payload), len(payload))
        is HitOutcome.NOT_THIS_FORMAT
    )


def test_shebang_decoy_pk_bytes_are_not_a_zip(tmp_path: Path) -> None:
    """A ``#!`` stub whose text contains ``PK\\x03\\x04`` is not reported as ZIP."""
    path = tmp_path / "script.sh"
    path.write_bytes(b"#!/bin/sh\n# decoy PK\x03\x04 is not a zip\necho hi\n")
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_shebang_script_mentioning_7z_magic_is_not_seven_z() -> None:
    """Six ``7z`` magic bytes in script text are not a signature header (task 4.4)."""
    payload = b"#!/bin/sh\necho 'magic " + MAGIC_7Z + b" here'\n" + b"x" * 100
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(payload))


def test_shebang_script_mentioning_rar_magic_is_not_rar() -> None:
    """Seven ``Rar!`` magic bytes in script text are not a MAIN header (task 4.4)."""
    payload = b"#!/usr/bin/env python3\nMARKER = " + RAR_ID + b"\n"
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(payload))


@requires("py7zr")
def test_mz_crc_damaged_7z_header_skips_to_the_real_payload(tmp_path: Path) -> None:
    damaged = bytearray(_sevenzip_signature())
    damaged[8] ^= 0xFF
    stub = b"MZ" + b"\x90" * 64 + bytes(damaged) + b"\x90" * 64
    path = tmp_path / "crc-decoy-7z.exe"
    path.write_bytes(stub + _7z_bytes(tmp_path))
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.payload_offset == len(stub)


def test_mz_7z_declared_end_overrun_is_not_claimed(tmp_path: Path) -> None:
    """A CRC-valid signature whose next-header overruns the source is not a 7z."""
    stub = b"MZ" + b"\x00" * 16
    path = tmp_path / "overrun-7z.exe"
    path.write_bytes(stub + _sevenzip_signature(next_offset=100, next_size=10))
    with pytest.raises(FormatDetectionError):
        detect_format(path)


@pytest.mark.parametrize(
    ("stub_len", "next_offset", "budget"),
    [
        pytest.param(256 * 1024, 1_900_000, BALANCED_BUDGET, id="256k-stub-balanced"),
        pytest.param(4 * 1024, 1_900_000, BALANCED_BUDGET, id="4k-stub-balanced"),
        pytest.param(4 * 1024, 1_500_000, FAST_BUDGET, id="4k-stub-fast"),
    ],
)
def test_sevenzip_sfx_declared_end_uses_source_remaining_not_the_scan_window(
    stub_len: int, next_offset: int, budget: DetectionBudget
) -> None:
    """A large CRC-valid 7z behind a stub is still SEVEN_Z (F1 / F2).

    Comparing declared end against the peek window rejected every 7z SFX whose
    payload plus stub exceeded ``max_scan_bytes``. The budget is a cost gate:
    FAST still answers a hit inside its 256 KiB window. The validator peeks
    only the 32-byte signature, so unique bytes stay well below the archive.
    """
    stub = _elf_stub(stub_len)
    next_size = 64
    sig = _sevenzip_signature(next_offset=next_offset, next_size=next_size)
    declared = _SIGNATURE_HEADER_SIZE + next_offset + next_size
    blob = stub + sig + b"\x00" * (declared - len(sig))
    src = InstrumentedBytesIO(blob)
    detected = detect_format(src, config=ArchiveyConfig(detection_budget=budget))
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == stub_len
    assert src.unique_bytes < len(blob)
    assert src.unique_bytes <= budget.max_scan_bytes


def test_crc_valid_empty_7z_decoy_is_skipped_for_the_real_payload(
    tmp_path: Path,
) -> None:
    """``NextHeaderSize == 0`` behind a stub is not an SFX payload (D2 cheap complement)."""
    decoy = _sevenzip_signature()
    stub = b"MZ" + b"\x00" * 510 + decoy
    real = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    path = tmp_path / "empty-decoy-7z.exe"
    path.write_bytes(stub + b"\x00" * 64 + real)
    real_origin = len(stub) + 64
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == real_origin
    with open_archive(path) as archive:
        assert any(m.is_file for m in archive.members())


def test_inexact_7z_decoy_loses_to_a_later_exact_payload(tmp_path: Path) -> None:
    """A later 7z payload that ends at EOF beats an earlier CRC-valid decoy that does not.

    The decoy at 512 is a CRC-valid signature whose declared end is nonzero,
    self-consistent, and inside ``remaining`` — so the empty-header reject does
    not apply. It is ``VALID_SHORT``; the real payload at 3544 ends exactly at EOF.
    """
    decoy = _sevenzip_signature(next_offset=100, next_size=10)
    prefix = b"MZ" + b"\x00" * 510 + decoy
    real = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    real_origin = 3544
    path = tmp_path / "inexact-decoy-7z.exe"
    path.write_bytes(prefix + b"\x00" * (real_origin - len(prefix)) + real)
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == real_origin
    # The forced-format scan ranks the same way.
    with open_archive(path, format=ArchiveFormat.SEVEN_Z) as archive:
        assert any(m.is_file for m in archive.members())


def test_short_7z_hit_is_not_displaced_by_a_later_zip(tmp_path: Path) -> None:
    """The exact-end preference is a tie-break among 7z hits, not across formats.

    The 7z is short only because a ZIP follows it; the earliest validated candidate,
    the 7z the stub would extract, stays the answer.
    """
    real = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "hi there")
    stub = b"MZ" + b"\x00" * 510
    path = tmp_path / "7z-then-zip.exe"
    path.write_bytes(stub + real + buf.getvalue())
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.payload_offset == len(stub)


def test_short_7z_hit_scan_cost_is_bounded_by_the_window(tmp_path: Path) -> None:
    """Pins what a short hit costs: the whole scan window, never more.

    With the archive ending at EOF the scan stops at the hit. With data after it
    (an Authenticode signature, say) the scan keeps looking for a later 7z that
    ends at EOF, through the whole of the budget's scan window: a decoy in a stub
    ends before the real payload starts, so the short hit cannot bound where that
    payload is.
    """
    real = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    stub = b"MZ" + b"\x00" * 510
    exact = tmp_path / "exact.exe"
    exact.write_bytes(stub + real)
    exact_cost = detect_format(exact).cost_receipt
    assert exact_cost is not None
    assert exact_cost.scanned_bytes <= len(stub) + len(real)

    trailing = tmp_path / "trailing.exe"
    trailing.write_bytes(stub + real + b"\x00" * (3 << 20))
    detected = detect_format(trailing)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.payload_offset == len(stub)
    assert detected.cost_receipt is not None
    # The whole window, not a ceiling that every scan meets: if the bound changes,
    # this is the line to edit.
    assert detected.cost_receipt.scanned_bytes == BALANCED_BUDGET.max_scan_bytes


def test_short_7z_hit_is_kept_when_nothing_ends_at_eof(tmp_path: Path) -> None:
    """With no exact candidate, the first short one is still the answer."""
    real = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    stub = b"MZ" + b"\x00" * 510
    path = tmp_path / "trailing-sig.exe"
    path.write_bytes(stub + real + b"appended signature block" * 4)
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.payload_offset == len(stub)


@requires("py7zr")
def test_mz_7z_with_trailing_bytes_is_still_claimed(tmp_path: Path) -> None:
    stub = _STUB
    path = tmp_path / "trailing-7z.exe"
    path.write_bytes(stub + _7z_bytes(tmp_path) + b"sfx-config\n")
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(stub)


@requires("py7zr")
def test_shebang_plus_real_7z_detects_and_lists_members(tmp_path: Path) -> None:
    """Tasks 2.3 / F10: a shebang scan self-enables once 7z registers a validator."""
    shebang = b"#!/bin/sh\n# self-extracting 7z\n"
    path = tmp_path / "payload.7z.sh"
    path.write_bytes(shebang + _7z_bytes(tmp_path))
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(shebang)
    with open_archive(path) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


def test_shebang_plus_real_rar_detects(tmp_path: Path) -> None:
    """Tasks 2.4 / F10: a shebang scan self-enables once RAR registers a validator."""
    shebang = b"#!/bin/sh\n# self-extracting rar\n"
    payload = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    path = tmp_path / "payload.rar.sh"
    path.write_bytes(shebang + payload)
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.RAR
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(shebang)


def test_mz_rar5_crc_fail_skips_to_the_real_payload(tmp_path: Path) -> None:
    payload = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    damaged = bytearray(payload[:64])
    damaged[len(RAR5_ID)] ^= 0xFF
    stub = b"MZ" + b"\x90" * 32 + bytes(damaged) + b"\x90" * 32
    path = tmp_path / "crc-decoy-rar.exe"
    path.write_bytes(stub + payload)
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.RAR
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(stub)


def test_elf_decoy_pk_bytes_are_not_a_zip(tmp_path: Path) -> None:
    """The ELF-cued form of the same decoy: today this claimed a damaged ZIP."""
    stub = b"\x7fELF\x02\x01\x01" + b"\x00" * 200 + b"PK\x03\x04" + b"not a header"
    path = tmp_path / "a.bin"
    path.write_bytes(stub)
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_elf_zero_filled_zip_decoy_skips_to_the_real_payload(tmp_path: Path) -> None:
    """``PK\\x03\\x04`` plus zeros is the common stub filler, not a local header."""
    stub = b"\x7fELF\x02\x01\x01" + b"\x00" * 200 + b"PK\x03\x04" + b"\x00" * 300
    payload = _zip_bytes()
    path = tmp_path / "decoy-elf.bin"
    path.write_bytes(stub + payload)
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.payload_offset == len(stub)


def test_zipapp_detects_as_zip_and_lists_members(tmp_path: Path) -> None:
    src = tmp_path / "app"
    src.mkdir()
    # write_bytes: Path.write_text translates ``\n`` to ``\r\n`` on Windows, and
    # zipapp stores the on-disk bytes as the member payload.
    (src / "__main__.py").write_bytes(b"print('hi')\n")
    out = tmp_path / "app.pyz"
    zipapp.create_archive(src, out, interpreter="/usr/bin/env python3")

    detected = detect_format(out)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset > 0
    assert detected.unavailable_tiers == ()
    with open_archive(out) as archive:
        names = {m.name for m in archive.members() if m.is_file}
        assert "__main__.py" in names
        member = next(m for m in archive.members() if m.name == "__main__.py")
        assert archive.read(member) == b"print('hi')\n"


def test_shebang_plus_concatenated_zip_detects_and_lists_members(
    tmp_path: Path,
) -> None:
    """Spring Boot executable-JAR shape: ``#!/bin/sh`` then a ZIP."""
    shebang = b"#!/bin/sh\n# Spring Boot startup script\n"
    path = tmp_path / "app.jar"
    path.write_bytes(shebang + _zip_bytes())

    detected = detect_format(path)
    assert detected.format == ArchiveFormat.ZIP
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(shebang)
    with open_archive(path) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


def test_jpeg_plus_appended_zip_stays_undetected_under_balanced(tmp_path: Path) -> None:
    """No prefix cue and no tail under BALANCED — JPEG+ZIP is a later-block case."""
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100 + _zip_bytes())
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_shebang_non_archive_reads_at_most_min_size_sfx_max() -> None:
    script = b"#!/usr/bin/env python3\n" + b"print(1)\n" * 80
    src = InstrumentedBytesIO(script)
    with pytest.raises(FormatDetectionError):
        detect_format(src)
    assert src.unique_bytes <= min(len(script), SFX_MAX)


def test_hostile_zip_local_header_stays_inside_the_scan_budget(tmp_path: Path) -> None:
    """A candidate near the scan edge must not peek ``name_len`` past the cost gate.

    ``remaining`` can prove the declared name/extra exist (F7), so detection may
    answer from the 30-byte header without reading 128 KiB. The pin is unique
    bytes, not ``FormatDetectionError``.
    """
    hdr = b"PK\x03\x04" + struct.pack(
        "<HHHHHIIIHH", 20, 0, 8, 0, 0, 0, 0, 0, 0xFFFF, 0xFFFF
    )
    data = bytearray(b"#!/bin/sh\n" + b"\x90" * (SFX_MAX + 200_000))
    data[SFX_MAX - 40 : SFX_MAX - 40 + len(hdr)] = hdr
    path = tmp_path / "hostile.pyz"
    path.write_bytes(bytes(data))
    src = InstrumentedBytesIO(bytes(data))
    try:
        detect_format(src)
    except FormatDetectionError:
        pass
    assert src.unique_bytes <= SFX_MAX + 256
    info = detect_format(path)
    assert info.cost_receipt is not None
    assert within_budget(info.cost_receipt, BALANCED_BUDGET)
    assert info.cost_receipt.unique_bytes_read <= SFX_MAX + 256


def _zip_bytes_named(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(name, b"payload")
    return buffer.getvalue()


def test_budget_truncated_zip_header_still_detects_when_remaining_is_known(
    tmp_path: Path,
) -> None:
    """Name/extra past ``scan_limit`` is a clamp, not a reject, when remaining is known (F7)."""
    payload = _zip_bytes_named("n" * 40)
    name_len, extra_len = struct.unpack_from("<HH", payload, 26)
    needed = 30 + name_len + extra_len
    scan_limit = FAST_BUDGET.max_scan_bytes
    stub_hdr = b"\x7fELF\x02\x01\x01"

    def blob(header_at: int) -> bytes:
        stub = stub_hdr + b"\x00" * (header_at - len(stub_hdr))
        return stub + payload

    straddle_at = scan_limit - (needed - 2)
    detected = detect_format(
        io.BytesIO(blob(straddle_at)),
        config=ArchiveyConfig(detection_budget=FAST_BUDGET),
    )
    assert detected.format == ArchiveFormat.ZIP
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == straddle_at

    path = tmp_path / "edge-straddle.bin"
    path.write_bytes(blob(straddle_at))
    found = detect_format(path, config=ArchiveyConfig(detection_budget=FAST_BUDGET))
    assert found.format == ArchiveFormat.ZIP
    assert found.detected_by == "sfx_scan"
    assert found.payload_offset == straddle_at

    hit_at = scan_limit - needed
    hit_path = tmp_path / "edge-hit.bin"
    hit_path.write_bytes(blob(hit_at))
    inside = detect_format(
        hit_path, config=ArchiveyConfig(detection_budget=FAST_BUDGET)
    )
    assert inside.format == ArchiveFormat.ZIP
    assert inside.detected_by == "sfx_scan"
    assert inside.payload_offset == hit_at


@pytest.mark.parametrize(
    ("cls", "decoy"),
    [
        (ZipReadBackend, b"PK\x03\x04"),
        (SevenZipReadBackend, MAGIC_7Z),
        (RarReadBackend, RAR_ID),
    ],
    ids=["zip", "sevenzip", "rar"],
)
def test_sfx_hit_validator_is_not_bound_on_instance(cls: type, decoy: bytes) -> None:
    inst = object.__new__(cls)
    assert inst.SFX_HIT_VALIDATOR is cls.SFX_HIT_VALIDATOR
    validator = inst.SFX_HIT_VALIDATOR
    assert validator is not None
    assert validator(_peek_view(decoy), None) is HitOutcome.NOT_THIS_FORMAT


def test_class_file_does_not_enter_the_sfx_scan() -> None:
    """``ca fe ba be`` without a fat arch table must not pay ``SFX_MAX``."""
    payload = _minimal_class_file(padding=100_000)
    assert executable_cue(payload[:4096]) is ExecutableCue.NONE
    src = InstrumentedBytesIO(payload)
    try:
        info = detect_format(src)
    except FormatDetectionError:
        info = None
    # Far magic may peek ~32 KiB on a large source; the SFX scan would read ~100 KiB.
    assert src.unique_bytes < 50_000
    if info is not None:
        assert info.detected_by != "sfx_scan"


@requires("py7zr")
@pytest.mark.parametrize(
    "filler",
    [
        pytest.param(bytes(range(256)) * 32, id="realistic-entropy"),
        pytest.param(b"\x00", id="low-entropy"),
    ],
)
def test_thin_macho_stub_plus_7z_opens_real_members(
    tmp_path: Path, filler: bytes
) -> None:
    """A parsing thin Mach-O cue finds the 7z; probes no longer claim the stub."""
    stub = _thin_macho64_stub(size=8192, filler=filler)
    path = tmp_path / "macho-sfx.bin"
    path.write_bytes(stub + _7z_bytes(tmp_path))
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.detected_by == "sfx_scan"
    assert detected.payload_offset == len(stub)
    with open_archive(path) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


@requires("py7zr")
def test_fat_macho_stub_plus_7z_opens_real_members(tmp_path: Path) -> None:
    stub = _fat_macho_stub(size=8192)
    path = tmp_path / "fat-macho-sfx.bin"
    path.write_bytes(stub + _7z_bytes(tmp_path))
    detected = detect_format(path)
    assert detected.format == ArchiveFormat.SEVEN_Z
    assert detected.payload_offset == len(stub)
    with open_archive(path) as archive:
        members = {m.name: archive.read(m) for m in archive.members() if m.is_file}
    assert members == _FILES


# A RAR5 marker, a wrong header CRC, then ``hdrlen`` 60 000 (vint e0 d4 03): a decoy
# whose CRC can only be judged by reading 60 000 bytes past the marker.
_RAR5_LONG_DECOY = RAR5_ID + b"\xde\xad\xbe\xef" + bytes([0xE0, 0xD4, 0x03])


@pytest.mark.parametrize(
    "budget", [BALANCED_BUDGET, FAST_BUDGET], ids=["balanced", "fast"]
)
def test_rar_decoy_crossing_the_scan_window_end_is_rejected_like_one_inside(
    tmp_path: Path, budget: DetectionBudget
) -> None:
    """A decoy whose header crosses the window end still gets its CRC checked.

    The same bytes one window-half earlier are rejected, and a pipe rejects them at
    both places, so the window edge must not turn them into ``RAR``.
    """
    window = budget.max_scan_bytes
    config = ArchiveyConfig(detection_budget=budget)
    for at in (window // 2, window - 100):
        body = bytearray(b"MZ" + b"\x00" * (window + 200_000))
        body[at : at + len(_RAR5_LONG_DECOY)] = _RAR5_LONG_DECOY
        data = bytes(body)
        path = tmp_path / f"decoy-{at}.bin"
        path.write_bytes(data)
        for source in (path, io.BytesIO(data), NonSeekableBytesIO(data)):
            with pytest.raises(FormatDetectionError):
                detect_format(source, config=config)  # type: ignore[arg-type]  # NonSeekableBytesIO is a binary stream


@pytest.mark.parametrize(
    "budget", [BALANCED_BUDGET, FAST_BUDGET], ids=["balanced", "fast"]
)
def test_real_rar_crossing_the_scan_window_end_is_found_within_budget(
    tmp_path: Path, budget: DetectionBudget
) -> None:
    """A real RAR whose main header crosses the window end validates and is found."""
    payload = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    at = budget.max_scan_bytes - 10
    path = tmp_path / "edge.bin"
    path.write_bytes(b"MZ" + b"\x00" * (at - 2) + payload)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.format == ArchiveFormat.RAR
    assert info.detected_by == "sfx_scan"
    assert info.payload_offset == at
    assert info.cost_receipt is not None
    assert within_budget(info.cost_receipt, budget)


def test_every_validator_peek_fits_validator_peek_max() -> None:
    """The detector lets a validator read ``VALIDATOR_PEEK_MAX`` past the window.

    Each validator's largest peek, on a source of unknown length, must fit in it, or
    a candidate near the window end is judged on bytes it was not given.
    """
    zip_header = b"PK\x03\x04" + struct.pack(
        "<HHHHHIIIHH", 20, 0, 8, 0, 0, 0, 0, 0, 0xFFFF, 0xFFFF
    )
    # ``hdrlen`` 65 536, the RAR5 validator's cap (vint 80 80 04).
    rar5 = RAR5_ID + b"\x00\x00\x00\x00" + b"\x80\x80\x04"
    rar4 = RAR_ID + struct.pack("<HBHH", 0, 0x73, 0, 0xFFFF)
    cases = [
        (validate_zip_local_header, zip_header),
        (validate_rar_main_header, rar5),
        (validate_rar_main_header, rar4),
        (validate_sevenzip_signature_header, MAGIC_7Z + bytes(26)),
    ]
    for validator, head in cases:
        data = head + bytes(VALIDATOR_PEEK_MAX * 2)
        asked: list[int] = []

        def peek_more(n: int, data: bytes = data, asked: list[int] = asked) -> bytes:
            asked.append(n)
            return data[:n]

        validator(peek_more, None)
        assert max(asked) <= VALIDATOR_PEEK_MAX, (validator.__name__, max(asked))


# A RAR5 marker and a 10-byte header whose CRC is wrong: rejected after 23 bytes.
_RAR5_SHORT_DECOY = RAR5_ID + b"\x00\x00\x00\x00\x0a" + bytes(10)


@pytest.mark.parametrize(
    ("decoys", "found"),
    [(MAX_VALIDATED_CANDIDATES - 1, True), (MAX_VALIDATED_CANDIDATES, False)],
    ids=["under-cap", "at-cap"],
)
def test_detector_and_parser_stop_at_the_same_rejected_candidate_cap(
    tmp_path: Path, decoys: int, found: bool
) -> None:
    """Both SFX scans give up after ``MAX_VALIDATED_CANDIDATES`` rejected RAR candidates.

    A file of RAR decoys means the same thing to detection as to forced
    ``format=RAR``, and a capped detection records ``sfx_scan`` as cut short.
    """
    from archivey.detection_cost import TierSkip, TierSkipReason

    payload = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    stub = _STUB + _RAR5_SHORT_DECOY * decoys
    path = tmp_path / "carpet.rar"
    path.write_bytes(stub + payload)
    cut_short = TierSkip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED)

    info = detect_format(path)
    if found:
        assert info.detected_by == "sfx_scan"
        assert info.payload_offset == len(stub)
        assert cut_short not in info.unavailable_tiers
        with open_archive(path, format=ArchiveFormat.RAR) as archive:
            assert archive.members()
    else:
        assert info.detected_by == "extension"
        assert cut_short in info.unavailable_tiers
        with pytest.raises(CorruptionError, match="candidate"):
            open_archive(path, format=ArchiveFormat.RAR)


# A ZIP local header with ``version_needed`` 0: rejected after its 30 bytes.
_ZIP_DECOY = b"PK\x03\x04" + bytes(26)
# A 7z signature header with a wrong start-header CRC: rejected after its 32 bytes.
_7Z_DECOY = MAGIC_7Z + b"\xff" * 26


@pytest.mark.parametrize("payload", ["rar", "zip"])
@pytest.mark.parametrize(
    "decoys",
    [MAX_VALIDATED_CANDIDATES - 1, MAX_VALIDATED_CANDIDATES],
    ids=["under-cap", "at-cap"],
)
def test_zip_decoys_never_cap_the_scan(
    tmp_path: Path, payload: str, decoys: int
) -> None:
    """ZIP decoys spend no allowance: the ZIP reader runs no scan to agree with.

    The RAR and 7z parsers stop after ``MAX_VALIDATED_CANDIDATES`` rejections of their
    own format, so the detector caps those formats. The ZIP reader finds the end of
    central directory from the tail and opens the file whatever precedes the
    payload, so a cap on ZIP candidates would refuse a file forced ``format=ZIP``
    lists. Auto-detection opens what the forced format opens, and nothing is cut
    short.
    """
    from archivey.detection_cost import TierSkip, TierSkipReason

    if payload == "rar":
        data, forced, names = (
            (_RAR_FIXTURES / "stored_m0.rar").read_bytes(),
            ArchiveFormat.RAR,
            ["store.txt"],
        )
    else:
        data, forced, names = _zip_bytes(), ArchiveFormat.ZIP, sorted(_FILES)
    stub = _STUB + _ZIP_DECOY * decoys
    path = tmp_path / "carpet"
    path.write_bytes(stub + data)

    info = detect_format(path)
    assert info.format == forced
    assert info.detected_by == "sfx_scan"
    assert info.payload_offset == len(stub)
    assert TierSkip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED) not in (
        info.unavailable_tiers
    )
    with open_archive(path) as archive:
        assert sorted(m.name for m in archive.members()) == names
    with open_archive(path, format=forced) as archive:
        assert sorted(m.name for m in archive.members()) == names


@pytest.mark.parametrize("tail", ["7z", "zip"])
@pytest.mark.parametrize("decoy", [_ZIP_DECOY, _7Z_DECOY], ids=["zip", "7z"])
@pytest.mark.parametrize(
    "decoys",
    [MAX_VALIDATED_CANDIDATES - 1, MAX_VALIDATED_CANDIDATES],
    ids=["under-cap", "at-cap"],
)
def test_capped_scan_holding_a_short_hit_records_the_scan_as_cut_short(
    tmp_path: Path, decoy: bytes, decoys: int, tail: str
) -> None:
    """A whole 7z in the stub, decoys, then a real 7z or ZIP payload.

    The embedded 7z is ``VALID_SHORT``: only a fallback a later 7z displaces. A later
    ZIP does not displace it, because the end-of-source preference never reorders
    formats. ZIP decoys never cap the scan, so a real 7z after them is found. 7z
    decoys that reach the 7z cap leave the short hit as the answer, as forced
    ``format=SEVEN_Z`` gives, but the receipt says the scan was cut short.
    """
    from archivey.detection_cost import TierSkip, TierSkipReason

    embedded = (_SEVENZIP_FIXTURES / "lz4.7z").read_bytes()
    real = (
        (_SEVENZIP_FIXTURES / "links_mid_folder_nonsolid.7z").read_bytes()
        if tail == "7z"
        else _zip_bytes()
    )
    stub = _STUB + embedded + decoy * decoys
    path = tmp_path / "nested"
    path.write_bytes(stub + real)
    cut_short = TierSkip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED)
    capped = decoy == _7Z_DECOY and decoys == MAX_VALIDATED_CANDIDATES

    info = detect_format(path)
    assert info.format == ArchiveFormat.SEVEN_Z
    assert info.detected_by == "sfx_scan"
    assert (cut_short in info.unavailable_tiers) is capped
    short_answer = capped or tail == "zip"
    assert info.payload_offset == (len(_STUB) if short_answer else len(stub))
    with path.open("rb") as fp:
        assert find_signature_offset(fp) == info.payload_offset


@pytest.mark.parametrize("decoy", [_RAR5_SHORT_DECOY, _7Z_DECOY], ids=["rar", "7z"])
def test_a_capped_formats_needles_are_no_longer_searched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decoy: bytes
) -> None:
    """Once a format is capped, the scan stops finding its needles.

    Skipping each later hit one by one would still walk a window carpeted with one
    format's decoys hit by hit. Counting the hits the scan yields, not the clock,
    keeps the bound checkable.
    """
    from archivey.internal import detection

    yielded = 0
    real_iter = detection.iter_magic_in_prefix

    def counting_iter(*args: object, **kwargs: object) -> Iterator[MagicHit]:
        nonlocal yielded
        for hit in real_iter(*args, **kwargs):  # type: ignore[arg-type]
            yielded += 1
            yield hit

    monkeypatch.setattr(detection, "iter_magic_in_prefix", counting_iter)
    path = tmp_path / "carpet"
    path.write_bytes(_STUB + decoy * (4 * MAX_VALIDATED_CANDIDATES))

    with pytest.raises(FormatDetectionError):
        detect_format(path)
    assert yielded == MAX_VALIDATED_CANDIDATES


def test_tight_scan_budget_bounds_the_validator_read_past_the_window(
    tmp_path: Path,
) -> None:
    """A validator reads at most ``max_scan_bytes`` past a small window.

    A RAR5 decoy just inside an 8 KiB window declares a 60 000-byte header. Judging it
    would read seven times the scan budget, so the view stops at the allowance, the
    candidate is rejected, and ``sfx_scan`` is recorded as cut short.
    """
    from archivey.detection_cost import TierSkip, TierSkipReason
    from archivey.internal.detection import validator_allowance

    budget = DetectionBudget(
        max_prefix_bytes=4096,
        max_far_bytes=4096,
        max_scan_bytes=8192,
        max_decode_input=4096,
        max_decode_output=4096,
        completion_window_bytes=0,
    )
    assert validator_allowance(budget) == budget.max_scan_bytes
    body = bytearray(b"MZ" + b"\x00" * 200_000)
    at = budget.max_scan_bytes - 20
    body[at : at + len(_RAR5_LONG_DECOY)] = _RAR5_LONG_DECOY
    path = tmp_path / "edge.rar"
    path.write_bytes(bytes(body))

    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.detected_by == "extension"
    assert TierSkip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED) in (
        info.unavailable_tiers
    )
    receipt = info.cost_receipt
    assert receipt is not None
    # The window, the allowance past it, and the trailer block the cheap tier reads.
    assert receipt.unique_bytes_read <= 2 * budget.max_scan_bytes + trailer_allowance()
    assert within_budget(receipt, budget)


# --- A real self-extractor, from a file and through a pipe ---------------------------


def _unzipsfx_archive(tmp_path: Path, payload_at: int) -> bytes:
    """Info-ZIP's own self-extractor: the ``unzipsfx`` stub, zero bytes up to
    ``payload_at``, a ZIP, then ``zip -A`` to move the offsets past the stub.

    The stub's size depends on the platform's build (about 75 KiB on Linux, a universal
    Mach-O on macOS), so the test is skipped where it alone reaches ``payload_at``.
    """
    unzipsfx = shutil.which("unzipsfx")
    assert unzipsfx is not None  # requires_binary
    stub = Path(unzipsfx).read_bytes()
    if len(stub) >= payload_at:
        pytest.skip(f"this unzipsfx is {len(stub)} bytes, past offset {payload_at}")
    with zipfile.ZipFile(tmp_path / "base.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _FILES.items():
            zf.writestr(name, data)
    sfx = tmp_path / "sfx"
    padding = bytes(payload_at - len(stub))
    sfx.write_bytes(stub + padding + (tmp_path / "base.zip").read_bytes())
    subprocess.run(["zip", "-qA", str(sfx)], check=True)
    return sfx.read_bytes()


@requires_binary("unzipsfx", "zip")
@pytest.mark.parametrize("source", ["file", "pipe"])
@pytest.mark.parametrize(
    "budget", [FAST_BUDGET, BALANCED_BUDGET], ids=["fast", "default"]
)
def test_an_unzipsfx_self_extractor_streams_from_its_payload_offset(
    tmp_path: Path, budget: DetectionBudget, source: str
) -> None:
    # 128 KiB is inside both scan windows.
    data = _unzipsfx_archive(tmp_path, payload_at=128 << 10)
    src = NonSeekableBytesIO(data) if source == "pipe" else io.BytesIO(data)
    config = ArchiveyConfig(detection_budget=budget)
    with open_archive(src, streaming=True, config=config) as reader:
        assert reader.format_info is not None
        assert reader.format_info.payload_offset == 128 << 10
        read = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert read == _FILES


@requires_binary("unzipsfx", "zip")
@pytest.mark.parametrize("source", ["file", "pipe"])
def test_a_self_extractor_past_the_fast_window_needs_the_default_or_a_named_format(
    tmp_path: Path, source: str
) -> None:
    # 1 MiB is past FAST's 256 KiB scan and inside the default 2 MiB one.
    data = _unzipsfx_archive(tmp_path, payload_at=1 << 20)

    def src() -> io.RawIOBase | io.BytesIO:
        return NonSeekableBytesIO(data) if source == "pipe" else io.BytesIO(data)

    with pytest.raises(FormatDetectionError, match="executable header"):
        open_archive(
            src(), streaming=True, config=ArchiveyConfig(detection_budget=FAST_BUDGET)
        )
    with open_archive(src(), streaming=True) as reader:
        assert reader.format_info is not None
        assert reader.format_info.payload_offset == 1 << 20
        read = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert read == _FILES
    # Naming the format skips detection; the walk finds the first local header itself.
    with open_archive(src(), streaming=True, format=ArchiveFormat.ZIP) as reader:
        read = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert read == _FILES
