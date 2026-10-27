"""A symlink target read from member data is capped at ``MAX_LINK_TARGET_BYTES``.

ZIP, 7z and RAR4 store a symlink's target as the member's *data*, which ZIP and 7z can
compress. Listing reads it, so before the cap a 398 KiB ZIP whose one "target" was
400 MiB of zeros peaked at 2 400 MiB inside ``members()`` with every listing cap set as
tight as it goes, and the target it did produce was weighed as zero bytes because it
was read after its member had been registered.

The ruling these tests pin: a target over 4096 bytes is corrupt or malicious. It is
never truncated, since a shortened path points somewhere the archive did not say. It
is left unset with ``SYMLINK_TARGET_UNAVAILABLE`` (``reason="target_too_long"``), an
archive-integrity code, so a strict policy refuses the archive and the default one
lists everything and fails only that link at extraction.
"""

from __future__ import annotations

import io
import os
import stat
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import ExtractionStatus, open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import (
    DiagnosticRaisedError,
    LinkTargetNotFoundError,
    ResourceLimitError,
)
from archivey.internal.backends import rar_parser
from archivey.internal.backends.rar_parser import RarArchive
from archivey.internal.base_reader import MAX_LINK_TARGET_BYTES
from archivey.reader import ArchiveReader
from archivey.types import ArchiveMember, MemberType, OnError
from tests.conftest import complete_listing, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.memory_util import traced_peak

_MODES = [pytest.param(False, id="random-access"), pytest.param(True, id="streaming")]

# Zeros deflate about 1000:1, so this is a ~64 KiB archive member that decodes to
# 64 MiB: big enough that an uncapped read is unmistakable, small enough to build fast.
_BOMB_TARGET = b"\0" * (64 << 20)


def _symlink_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3  # Unix
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _zip_with_links(*targets: bytes) -> bytes:
    """A ZIP holding ``target.txt`` and one symlink per target, ``link0`` onwards."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("target.txt", b"payload")
        for index, target in enumerate(targets):
            zf.writestr(_symlink_info(f"link{index}"), target)
    return buf.getvalue()


def _sevenzip_with_link(
    tmp_path: Path,
    target: bytes,
    *,
    store: bool = False,
    sibling: bytes | None = None,
    method: str | None = None,
) -> bytes:
    """A 7z holding a symlink, ``link``, whose stored target is ``target``.

    A real symlink cannot be longer than ``PATH_MAX``, so ``7z -snl`` cannot write the
    over-long one this needs. The member is written as a regular file holding the
    target bytes, and its mode in the (uncompressed) header is then patched from
    a regular file to ``S_IFLNK``, which is the only thing that differs between the two
    in a 7z archive. Both header CRCs are recomputed so the archive stays valid.
    ``store`` writes the data uncompressed (``-mx0``), so a test can find and damage it.
    ``sibling`` adds a regular file, ``target.txt``, holding those bytes. ``method``
    is passed to 7-Zip as ``-m0=<method>``.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link").write_bytes(target)
    os.chmod(tree / "link", 0o644)
    names = ["link"]
    if sibling is not None:
        (tree / "target.txt").write_bytes(sibling)
        names.append("target.txt")
    archive = tmp_path / "link.7z"
    subprocess.run(
        [
            "7z",
            "a",
            "-mhc=off",
            *(["-mx0"] if store else []),
            *([f"-m0={method}"] if method else []),
            str(archive),
            *names,
        ],
        cwd=tree,
        check=True,
        capture_output=True,
    )
    data = bytearray(archive.read_bytes())
    # Start header: StartHeaderCRC at 8, then NextHeaderOffset, NextHeaderSize and
    # NextHeaderCRC over bytes 12..32; the next header follows at 32 + offset.
    offset, size, _crc = struct.unpack_from("<QQI", data, 12)
    start = 32 + offset
    header = bytearray(data[start : start + size])
    # kAttributes (0x15), property size, all-defined 1, external 0, then one UInt32 per
    # member, in the order the names are stored (UTF-16, NUL-terminated). The values
    # depend on the host 7-Zip ran on (a Windows writer records no Unix mode at all),
    # so the link's is overwritten rather than matched.
    # 7-Zip's Unix extension: 0x8000 flags a mode in the high word; 0x20 is ARCHIVE.
    attributes = bytes([0x15, 2 + 4 * len(names), 1, 0])
    assert header.count(attributes) == 1, "expected one kAttributes property"
    stored = sorted(names, key=lambda n: header.index(f"{n}\0".encode("utf-16-le")))
    at = header.index(attributes) + len(attributes) + 4 * stored.index("link")
    struct.pack_into("<I", header, at, (0o120777 << 16) | 0x8020)
    data[start : start + size] = header
    struct.pack_into("<I", data, 28, zlib.crc32(bytes(header)))
    struct.pack_into("<I", data, 8, zlib.crc32(bytes(data[12:32])))
    return bytes(data)


# Well under `_BOMB_TARGET`'s 64 MiB, and far over what listing a few small members
# allocates: a peak under this means the bomb was not decoded.
_DECODED_NOTHING = 8 << 20


def _list(reader: ArchiveReader, streaming: bool) -> list[ArchiveMember]:
    """Every member, with link targets resolved, by each mode's own full listing."""
    if not streaming:
        return reader.members()
    for _member, stream in reader.stream_members():
        if stream is not None:
            stream.read()
    return complete_listing(reader)


def _too_long(reader: ArchiveReader) -> list[str]:
    """Names of the members reported with ``reason="target_too_long"``."""
    return [
        d.context.member_name  # type: ignore[union-attr]
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        and d.context.reason == "target_too_long"  # type: ignore[union-attr]
    ]


# --------------------------------------------------------------------------------
# The cap itself
# --------------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", _MODES)
def test_zip_target_at_the_cap_is_kept_and_one_byte_over_is_refused(
    streaming: bool,
) -> None:
    at_cap = b"a" * MAX_LINK_TARGET_BYTES
    over = b"b" * (MAX_LINK_TARGET_BYTES + 1)
    data = _zip_with_links(at_cap, over)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        by_name = {m.name: m for m in _list(reader, streaming)}
        assert by_name["link0"].link_target == at_cap.decode()
        # Not truncated: unset, and still the link the archive said it was.
        assert by_name["link1"].link_target is None
        assert by_name["link1"].type is MemberType.SYMLINK
        assert _too_long(reader) == ["link1"]


@pytest.mark.parametrize("streaming", _MODES)
def test_a_compressed_zip_target_bomb_is_refused_without_decoding(
    streaming: bool,
) -> None:
    """The finding's own shape: listing must not decode the "target" at all."""
    data = _zip_with_links(_BOMB_TARGET)
    assert len(data) < 1 << 20
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        listed: list[ArchiveMember] = []
        # `bytes_decompressed` does not observe link-target reads, so the allocation
        # peak is what shows the 64 MiB was never decoded: the uncapped read peaked
        # at several times that.
        peak = traced_peak(lambda: listed.extend(_list(reader, streaming)))
        assert peak < _DECODED_NOTHING
        by_name = {m.name: m for m in listed}
        assert by_name["link0"].link_target is None
        assert _too_long(reader) == ["link0"]


@requires_binary("7z")
@pytest.mark.parametrize("streaming", _MODES)
@pytest.mark.parametrize(
    ("target", "kept"),
    [
        pytest.param(b"a" * MAX_LINK_TARGET_BYTES, True, id="at-cap"),
        pytest.param(b"b" * (MAX_LINK_TARGET_BYTES + 1), False, id="one-over"),
        pytest.param(_BOMB_TARGET, False, id="bomb"),
    ],
)
def test_sevenzip_target_is_capped(
    tmp_path: Path, streaming: bool, target: bytes, kept: bool
) -> None:
    data = _sevenzip_with_link(tmp_path, target)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        listed: list[ArchiveMember] = []
        peak = traced_peak(lambda: listed.extend(_list(reader, streaming)))
        (link,) = listed
        assert link.type is MemberType.SYMLINK
        if kept:
            assert link.link_target == target.decode()
            assert _too_long(reader) == []
        else:
            assert link.link_target is None
            assert _too_long(reader) == ["link"]
            assert peak < _DECODED_NOTHING


def test_a_rar4_stored_target_over_the_cap_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RAR4 stores the target uncompressed, so there is no amplification — but the
    same cap holds, so the three formats agree on what a too-long target is.

    The header is patched rather than written, as in `test_windows_reparse`: RAR 7
    cannot write RAR4 at all, and the sizes are the only fields the branch consults.
    Both are patched: a stored target whose two sizes disagree is damage, which is
    reported before the cap (`test_damaged_link_target.py`). They are patched after
    the header walk: the walk skips a FILE header's data by its parsed
    ``compress_size``, so a larger size set any earlier would move the walk too.
    """
    original_walk = rar_parser._parse_rar3

    def patched_walk(*args: Any, **kwargs: Any) -> RarArchive:
        archive = original_walk(*args, **kwargs)
        for member in archive.members:
            if member.is_symlink:
                member.file_size = member.compress_size = MAX_LINK_TARGET_BYTES + 1
        return archive

    monkeypatch.setattr(rar_parser, "_parse_rar3", patched_walk)

    fixture = Path(__file__).parent / "fixtures" / "rar" / "symlinks_solid__rar4.rar"
    with open_archive(fixture) as reader:
        links = [m for m in reader.members() if m.type is MemberType.SYMLINK]
        assert links
        assert all(m.link_target is None for m in links)
        assert sorted(_too_long(reader)) == sorted(m.name for m in links)


@pytest.mark.parametrize("streaming", _MODES)
def test_a_zip_target_longer_than_its_declared_size_is_corruption(
    streaming: bool,
) -> None:
    """A header that under-declares the target is a corrupt member, not a long target.

    ZIP verifies every member's data against its declared size, so the read stops at
    those 10 bytes and the data left over raises there, as it would for any other
    member. The cap is never what decides this case, and nothing past the declared
    size plus one byte is decoded. A damaged target costs only that link its target
    (`test_damaged_link_target.py`): the listing reports it, and opening it raises.
    """
    data = bytearray(_zip_with_links(b"x" * 500_000))
    for signature, size_at in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        # The second of each: the first is target.txt's header.
        header = data.find(signature, data.find(signature) + 1)
        struct.pack_into("<I", data, header + size_at, 10)
    with open_archive(io.BytesIO(bytes(data)), streaming=streaming) as reader:
        members = _list(reader, streaming)
        (link,) = [m for m in members if m.name == "link0"]
        assert link.link_target is None
        (diagnostic,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        assert diagnostic.context.reason == "target_data_damaged"  # type: ignore[union-attr]
        assert "declared size of 10 bytes" in diagnostic.message
        assert not _too_long(reader)
        if not streaming:
            with raises_corruption_not_truncation(match="declared size of 10 bytes"):
                reader.open(link)


def test_the_read_stops_one_byte_past_the_cap_when_the_size_is_unknown() -> None:
    """The byte bound for a backend that does not verify the declared size.

    Neither ZIP nor 7z reaches it with a real archive — both declare a size, which is
    checked first, and both verify it by default — so this drives the shared helper
    directly with an endless stream and no declared size.
    """

    class Endless(io.RawIOBase):
        def __init__(self) -> None:
            self.delivered = 0

        def readable(self) -> bool:
            return True

        def read(self, n: int = -1, /) -> bytes:
            assert n >= 0, "an unbounded read would never return"
            self.delivered += n
            return b"x" * n

    data = _zip_with_links(b"target.txt")
    with open_archive(io.BytesIO(data)) as reader:
        link = next(m for m in reader.members() if m.name == "link0")
        link.size = None
        endless = Endless()
        result = reader._read_link_target_data(  # type: ignore[attr-defined]
            link, lambda: endless, is_reparse_point=False
        )
        assert result is None
        assert endless.delivered == MAX_LINK_TARGET_BYTES + 1


# --------------------------------------------------------------------------------
# What a too-long target does downstream
# --------------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", _MODES)
def test_a_strict_policy_refuses_the_archive(streaming: bool) -> None:
    data = _zip_with_links(b"c" * (MAX_LINK_TARGET_BYTES + 1))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(io.BytesIO(data), streaming=streaming, config=config) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        _list(reader, streaming)


def test_extraction_fails_only_the_over_long_link(tmp_path: Path) -> None:
    """The archive carries a target, so this is a per-member failure, not the
    `LINK_TARGET_UNAVAILABLE` outcome reserved for a link the archive left empty."""
    archive = tmp_path / "links.zip"
    archive.write_bytes(
        _zip_with_links(b"target.txt", b"d" * (MAX_LINK_TARGET_BYTES + 1))
    )
    dest = tmp_path / "out"
    with open_archive(archive) as reader:
        report = reader.extract_all(dest, on_error=OnError.CONTINUE)
    by_name = {r.member.name: r for r in report.results}
    assert by_name["target.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["link0"].status is ExtractionStatus.EXTRACTED
    assert os.readlink(dest / "link0") == "target.txt"
    assert by_name["link1"].status is ExtractionStatus.FAILED
    assert isinstance(by_name["link1"].error, LinkTargetNotFoundError)
    assert not (dest / "link1").exists()

    with open_archive(archive) as reader, pytest.raises(LinkTargetNotFoundError):
        reader.extract_all(tmp_path / "stop")


# --------------------------------------------------------------------------------
# Listing limits weigh the targets they publish
# --------------------------------------------------------------------------------

# Ten 4000-byte targets: 40 000 bytes of link_target, every one under the cap.
_MANY_TARGETS = [bytes([ord("e") + i]) * 4000 for i in range(10)]


@pytest.mark.parametrize("streaming", _MODES)
def test_resolved_targets_count_against_max_metadata_bytes(streaming: bool) -> None:
    """Registration saw these targets as ``None``; the limit has to see them anyway.

    `archive-reading` §"Listing metadata-byte accounting" names ``link_target`` among
    the weighed fields, and before this the listing below passed a 20 000-byte cap
    while holding 40 000 bytes of targets.
    """
    data = _zip_with_links(*_MANY_TARGETS)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=20_000))
    with (
        open_archive(io.BytesIO(data), streaming=streaming, config=config) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        _list(reader, streaming)


def test_resolved_targets_fit_a_cap_that_holds_them() -> None:
    data = _zip_with_links(*_MANY_TARGETS)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=50_000))
    with open_archive(io.BytesIO(data), config=config) as reader:
        members = reader.members()
        assert sum(len(m.link_target or "") for m in members) == 40_000
