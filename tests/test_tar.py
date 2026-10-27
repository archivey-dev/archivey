"""TAR backend tests — random-access read, forward-only streaming on non-seekable
sources, PAX/GNU/ustar member mapping, cost, corrupt/truncated handling, and
end-of-archive verification."""

from __future__ import annotations

import errno
import gzip
import io
import logging
import os
import random
import tarfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO
from unittest import mock

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    CompressionAlgorithm,
    CompressionMethod,
    ExtractionLimits,
    ListingLimits,
    MemberType,
    open_archive,
)
from archivey.config import REWIND_REDECODE_WARN_BYTES
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DiagnosticPolicy,
)
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    ReadError,
    ResourceLimitError,
    StreamNotSeekableError,
    TruncatedError,
)
from archivey.internal.backends import tar_reader as tar_reader_module
from archivey.internal.backends.tar_parser import READ_STEP, TarWalker
from archivey.internal.backends.tar_reader import _WALK_BUFFER
from archivey.internal.streams.streamtools import DEFAULT_UNKNOWN_LENGTH_READ_STEP
from tests.conftest import CPYTHON, requires_zstd, zstd_backend
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)
from tests.extract_util import open_and_extract
from tests.streams_util import (
    FactSizedReadRecorder,
    NonSeekableBytesIO,
    ReadSizeRecorder,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _build_tar(mode: str = "w") -> bytes:
    """A small tar with a file, a nested file, a directory, and a symlink."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data, mtime in [
            ("hello.txt", b"hello world", 1_600_000_000),
            ("dir/nested.txt", b"nested content", 1_600_000_100),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = mtime
            info.uid, info.gid = 1000, 1000
            info.uname, info.gname = "alice", "staff"
            t.addfile(info, io.BytesIO(data))
        d = tarfile.TarInfo("dir")
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        t.addfile(d)
        link = tarfile.TarInfo("link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "hello.txt"
        t.addfile(link)
    return buf.getvalue()


def _tar_missing_eof_block() -> bytes:
    """Valid member data but only one of the two required EOF null blocks."""
    full = _build_tar()
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:") as t:
        members = t.getmembers()
        last = members[-1]
        blocks = (last.size + 511) & ~511
        eof_start = last.offset_data + blocks
    return full[: eof_start + 512]


def _tar_three() -> bytes:
    """A plain tar of three members (the middle one spanning several blocks)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        for name, data in [
            ("a.txt", b"aaa"),
            ("b.txt", b"b" * 4000),
            ("c.txt", b"ccc"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tar_corrupt_final_header() -> bytes:
    """Member data followed by a single non-null block where the end-of-archive marker
    (and the next header) should be, with nothing after it — the shape stdlib tarfile
    treats as a clean end. Only the block tarfile stopped on reveals the corruption; the
    trailing-block check reads past it into EOF."""
    full = _build_tar()
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:") as t:
        last = t.getmembers()[-1]
        eof_start = last.offset_data + ((last.size + 511) & ~511)
    return full[:eof_start] + b"\xff" * 512


def _tar_content_end(data: bytes) -> int:
    """Byte offset of the first end-of-archive null block (strip record padding)."""
    end = len(data)
    while end >= 512 and data[end - 512 : end] == b"\x00" * 512:
        end -= 512
    return end


def _tar_sparse_gnu(logical: int = 1024 * 1024) -> bytes:
    """A hand-built old-GNU-format sparse tar whose logical size ≫ packed size.

    Constructed in pure Python (no system ``tar``, so it runs identically on every OS —
    BSD/Windows ``tar`` reject ``--sparse``). One 3-byte sparse region carried by a
    ``logical``-byte file (1 MiB by default): the physical next-header offset
    (``offset_data + roundup(3)``) is far below ``offset_data + roundup(logical size)``,
    which is exactly the layout an offset-based end check gets wrong. Verified
    read back through stdlib ``tarfile``.
    """
    physical = b"xyz"

    def octal(value: int, width: int) -> bytes:
        return f"{value:0{width - 1}o}".encode() + b"\x00"

    h = bytearray(512)
    h[0:10] = b"sparse.bin"
    h[100:108] = octal(0o644, 8)
    h[108:116] = octal(0, 8)  # uid
    h[116:124] = octal(0, 8)  # gid
    h[124:136] = octal(len(physical), 12)  # PHYSICAL size (logical goes in realsize)
    h[136:148] = octal(0, 12)  # mtime
    h[156:157] = b"S"  # GNUTYPE_SPARSE
    h[257:265] = b"ustar  \x00"  # GNU magic + version
    h[386:398] = octal(0, 12)  # sparse region: logical offset
    h[398:410] = octal(len(physical), 12)  # sparse region: numbytes
    h[482] = 0  # isextended
    h[483:495] = octal(logical, 12)  # realsize (logical)
    h[148:156] = b" " * 8
    h[148:156] = f"{sum(h):06o}".encode() + b"\x00 "  # checksum
    full = bytes(h) + physical.ljust(512, b"\x00") + b"\x00" * 1024

    # Guard the fixture's premise: a real sparse member whose logical/physical ends diverge.
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:") as t:
        member = t.getmembers()[0]
        assert member.type == tarfile.GNUTYPE_SPARSE
        logical_end = member.offset_data + ((member.size + 511) & ~511)
        assert _tar_content_end(full) < logical_end
    return full


def _tar_corrupt_final_header_sparse() -> bytes:
    """Sparse member + rejected final header (nothing after)."""
    full = _tar_sparse_gnu()
    eof_start = _tar_content_end(full)
    return full[:eof_start] + b"\xff" * 512


def _tar_corrupt_mid_header() -> bytes:
    """Corrupt the second member's header so tarfile stops iterating after the first,
    with valid member data still following the bad block."""
    full = _tar_three()
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:") as t:
        second = t.getmembers()[1]
    start = second.offset  # header-block offset of the second member
    return full[:start] + b"\xff" * 512 + full[start + 512 :]


def _tar_minimal_eof() -> bytes:
    """A fully valid archive terminated by exactly the two required EOF null blocks.

    ``tarfile`` pads its own output to a 10240-byte record boundary, so a tar it wrote
    always has plenty of trailing zeros. This helper strips that padding down to the
    bare POSIX minimum (two 512-byte null blocks, no record padding) — what e.g.
    ``tar -b1`` or a streaming producer emits — to exercise the EOF check's boundary.
    """
    full = _build_tar()
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:") as t:
        members = t.getmembers()
        last = members[-1]
        blocks = (last.size + 511) & ~511
        eof_start = last.offset_data + blocks
    return full[: eof_start + 512 * 2]


@pytest.fixture
def plain_tar(tmp_path: Path) -> Path:
    path = tmp_path / "simple.tar"
    path.write_bytes(_build_tar())
    return path


# ---------------------------------------------------------------------------
# Cost / format properties (access-mode-and-cost for TAR)
# ---------------------------------------------------------------------------


def test_plain_tar_cost(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        assert ar.format == ArchiveFormat.TAR
        assert ar.cost.listing_cost == ListingCost.REQUIRES_SCANNING
        assert ar.cost.access_cost == AccessCost.DIRECT
        assert ar.cost.stream_capability == StreamCapability.SEEKABLE
        assert ar.info.is_solid is False
        assert ar.info.member_count is None  # no central directory: count needs a scan


@pytest.mark.parametrize(
    "mode,fmt",
    [
        ("w:gz", ArchiveFormat.TAR_GZ),
        ("w:bz2", ArchiveFormat.TAR_BZ2),
        ("w:xz", ArchiveFormat.TAR_XZ),
    ],
)
def test_compressed_tar_cost_and_read(
    mode: str, fmt: ArchiveFormat, tmp_path: Path
) -> None:
    path = tmp_path / f"a.{mode.split(':')[1]}"
    path.write_bytes(_build_tar(mode))
    with open_archive(path) as ar:
        assert ar.format == fmt
        assert ar.cost.listing_cost == ListingCost.REQUIRES_DECOMPRESSION
        assert ar.cost.access_cost == AccessCost.SOLID
        assert ar.info.is_solid is True
        assert ar.read("hello.txt") == b"hello world"
        assert ar.read("dir/nested.txt") == b"nested content"


# ---------------------------------------------------------------------------
# Random-access read + listing
# ---------------------------------------------------------------------------


def test_members_listed(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        names = {m.name for m in ar.members()}
        assert names == {"hello.txt", "dir/nested.txt", "dir/", "link.txt"}


def test_random_access_read_by_name(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        assert ar.read("dir/nested.txt") == b"nested content"
        assert ar.read("hello.txt") == b"hello world"  # out of order still works
        assert ar.read("hello.txt") == b"hello world"  # re-read


def test_member_list_not_available_without_scan(plain_tar: Path) -> None:
    # TAR has no upfront index: members_report_if_available is None until a scan materializes it.
    with open_archive(plain_tar) as ar:
        assert ar.members_report_if_available() is None
        ar.members()  # forces the scan
        assert ar.members_report_if_available() is not None


def test_stream_members(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        collected = {}
        for member, stream in ar.stream_members():
            collected[member.name] = stream.read() if stream is not None else None
        assert collected["hello.txt"] == b"hello world"
        assert collected["dir/"] is None  # directory has no data stream


# ---------------------------------------------------------------------------
# Member metadata mapping (ustar / GNU / PAX)
# ---------------------------------------------------------------------------


def test_member_metadata(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        by_name = {m.name: m for m in ar.members()}
        f = by_name["hello.txt"]
        assert f.type == MemberType.FILE
        assert f.size == len(b"hello world")
        assert f.mode == 0o644
        assert f.uid == 1000 and f.gid == 1000
        assert f.uname == "alice" and f.gname == "staff"
        assert f.modified == datetime.fromtimestamp(1_600_000_000, tz=UTC)
        assert f.modified.tzinfo is not None  # tz-aware UTC
        # tar stores members uncompressed; no encryption.
        assert f.compression == (CompressionMethod(algo=CompressionAlgorithm.STORED),)
        assert f.is_encrypted is False


def test_directory_and_symlink_types(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["dir/"].type == MemberType.DIRECTORY
        link = by_name["link.txt"]
        assert link.type == MemberType.SYMLINK
        assert link.link_target == "hello.txt"


def test_symlink_followed_on_read(plain_tar: Path) -> None:
    with open_archive(plain_tar) as ar:
        # Opening the symlink follows it to its target's data.
        assert ar.read("link.txt") == b"hello world"


def test_hardlink_type_mapping(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = b"original"
        info = tarfile.TarInfo("orig.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
        hl = tarfile.TarInfo("hard.txt")
        hl.type = tarfile.LNKTYPE
        hl.linkname = "orig.txt"
        t.addfile(hl)
    path = tmp_path / "hl.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as ar:
        hard = {m.name: m for m in ar.members()}["hard.txt"]
        assert hard.type == MemberType.HARDLINK
        assert hard.link_target == "orig.txt"
        assert ar.read("hard.txt") == b"original"  # follows to the linked data


def test_pax_mtime_override(tmp_path: Path) -> None:
    # A PAX header carries a sub-second mtime; tarfile folds it into TarInfo.mtime, which
    # the backend surfaces (overriding the whole-second ustar field).
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("p.txt")
        data = b"x"
        info.size = len(data)
        info.pax_headers["mtime"] = "1600000000.123456"
        t.addfile(info, io.BytesIO(data))
    path = tmp_path / "pax.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as ar:
        m = ar.get("p.txt")
        assert m.modified is not None
        assert abs(m.modified.timestamp() - 1_600_000_000.123456) < 1e-3


def test_raw_name_preserved(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("café.txt")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "u.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as ar:
        m = ar.get("café.txt")
        assert m.name == "café.txt"  # decoded name round-trips
        assert m.raw_name == b"caf\xc3\xa9.txt"  # verbatim stored bytes


def test_pax_atime_ctime(tmp_path: Path) -> None:
    # PAX access/inode-change times live only in pax_headers (tarfile does not fold them
    # into TarInfo like mtime). atime is `accessed`; ctime is st_ctime, never a birth
    # time, so it goes to `ctime` and `created` stays None.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("p.txt")
        info.size = 1
        info.pax_headers["atime"] = "1600000100.5"
        info.pax_headers["ctime"] = "1600000200.25"
        t.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "pax_times.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as ar:
        m = ar.get("p.txt")
        assert m.accessed is not None
        assert abs(m.accessed.timestamp() - 1_600_000_100.5) < 1e-3
        assert m.created is None
        assert abs(m.ctime.timestamp() - 1_600_000_200.25) < 1e-3


def test_pax_libarchive_creationtime_is_created(tmp_path: Path) -> None:
    # bsdtar stores the source's birth time as LIBARCHIVE.creationtime where the OS
    # has one; it sits beside the PAX ctime, so a member can carry both.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("p.txt")
        info.size = 1
        info.pax_headers["ctime"] = "1600000200.25"
        info.pax_headers["LIBARCHIVE.creationtime"] = "1500000000.5"
        t.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "pax_birth.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as ar:
        m = ar.get("p.txt")
        assert m.created is not None
        assert abs(m.created.timestamp() - 1_500_000_000.5) < 1e-3
        assert m.ctime is not None
        assert abs(m.ctime.timestamp() - 1_600_000_200.25) < 1e-3


# ---------------------------------------------------------------------------
# Compressed-tar combinations beyond gz/bz2/xz (codec-layer composition)
# ---------------------------------------------------------------------------


@requires_zstd()
def test_tar_zst_via_codec_layer() -> None:
    zstd = zstd_backend()
    plain = _build_tar()
    data = zstd.compress(plain)
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.format == ArchiveFormat.TAR_ZST
        assert ar.read("hello.txt") == b"hello world"


# ---------------------------------------------------------------------------
# Non-seekable source: random-access fails fast; streaming succeeds
# ---------------------------------------------------------------------------


def test_non_seekable_tar_fails_fast() -> None:
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(_build_tar()), format=ArchiveFormat.TAR)


def test_non_seekable_tar_fails_fast_via_detection() -> None:
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(_build_tar()))


def test_non_seekable_tar_streaming_opens_without_scanning() -> None:
    with open_archive(
        NonSeekableBytesIO(_build_tar()), format=ArchiveFormat.TAR, streaming=True
    ) as ar:
        assert ar.cost.stream_capability == StreamCapability.FORWARD_ONLY


def test_non_seekable_plain_tar_stream_members() -> None:
    with open_archive(
        NonSeekableBytesIO(_build_tar()), format=ArchiveFormat.TAR, streaming=True
    ) as ar:
        collected = {}
        for member, stream in ar.stream_members():
            collected[member.name] = stream.read() if stream is not None else None
        assert collected["hello.txt"] == b"hello world"
        assert collected["dir/nested.txt"] == b"nested content"
        assert collected["dir/"] is None


def test_non_seekable_plain_tar_iter() -> None:
    with open_archive(
        NonSeekableBytesIO(_build_tar()), format=ArchiveFormat.TAR, streaming=True
    ) as ar:
        names = [m.name for m in ar]
        assert "hello.txt" in names
        assert "dir/nested.txt" in names


def test_streaming_tar_disables_random_access(plain_tar: Path) -> None:
    with open_archive(plain_tar, streaming=True) as ar:
        with pytest.raises(ArchiveyUsageError):
            ar.members()
        with pytest.raises(ArchiveyUsageError):
            ar.read("hello.txt")


def test_streaming_tar_does_not_call_getmembers() -> None:
    data = _build_tar()
    with (
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
        mock.patch.object(
            tarfile.TarFile,
            "getmembers",
            side_effect=AssertionError("getmembers called"),
        ),
    ):
        list(ar.stream_members())


def test_non_seekable_tar_gz_streaming(tmp_path: Path) -> None:
    path = tmp_path / "a.tar.gz"
    path.write_bytes(_build_tar("w:gz"))
    data = path.read_bytes()
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        assert ar.format == ArchiveFormat.TAR_GZ
        assert ar.cost.stream_capability == StreamCapability.FORWARD_ONLY
        assert ar.cost.listing_cost == ListingCost.REQUIRES_DECOMPRESSION
        assert ar.cost.access_cost == AccessCost.SOLID
        collected: dict[str, bytes | None] = {}
        for member, stream in ar.stream_members():
            collected[member.name] = stream.read() if stream is not None else None
        assert set(collected) == {"hello.txt", "dir/nested.txt", "dir/", "link.txt"}
        assert collected["hello.txt"] == b"hello world"
        assert collected["dir/nested.txt"] == b"nested content"
        assert collected["dir/"] is None


def test_non_seekable_tar_bz2_streaming_smoke() -> None:
    data = _build_tar("w:bz2")
    with open_archive(
        NonSeekableBytesIO(data), format=ArchiveFormat.TAR_BZ2, streaming=True
    ) as ar:
        names = [m.name for m, _ in ar.stream_members()]
        assert "hello.txt" in names


def test_compressed_source_size_on_path(tmp_path: Path) -> None:
    path = tmp_path / "a.tar.gz"
    path.write_bytes(_build_tar("w:gz"))
    with open_archive(path) as ar:
        assert ar.compressed_source_size == path.stat().st_size


def test_compressed_source_size_generalized(plain_tar: Path) -> None:
    # Generalized (for the archive-wide extraction ratio guard): known for any path
    # source — a plain tar simply yields a harmless ~1:1 ratio — and for seekable
    # streams via a SEEK_END probe; only a non-seekable stream is unknowable.
    with open_archive(plain_tar) as ar:
        assert ar.compressed_source_size == plain_tar.stat().st_size
    data = _build_tar("w:gz")
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR_GZ) as ar:
        assert ar.compressed_source_size == len(data)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        assert ar.compressed_source_size is None


# ---------------------------------------------------------------------------
# end-of-archive truncation detection
# ---------------------------------------------------------------------------

# A missing trailer is an ordinary diagnostic; a caller who wants it fatal sets the code
# to RAISE and gets DiagnosticRaisedError.
_RAISE_ON_MISSING_EOF = ArchiveyConfig(
    diagnostic_policy=DiagnosticPolicy(
        raise_on={DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING}
    )
)


def _eof_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    """EOF-check warnings only — filtered to the backends logger so the unrelated
    ``archivey.normalization`` warning from the ``dir`` -> ``dir/`` fixture entry
    doesn't leak into the assertion."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "archivey.backends" and r.levelno == logging.WARNING
    ]


def test_valid_tar_eof_silent(
    plain_tar: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(plain_tar) as ar,
    ):
        ar.members()
    assert _eof_warnings(caplog) == []


def test_missing_eof_blocks_warns_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = _tar_missing_eof_block()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()
    warnings = _eof_warnings(caplog)
    assert len(warnings) == 1
    assert "truncated" in warnings[0].lower()


def test_missing_eof_blocks_raise_disposition_raises() -> None:
    data = _tar_missing_eof_block()
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.TAR,
            config=_RAISE_ON_MISSING_EOF,
        ) as ar,
    ):
        ar.members()


def test_members_report_recovers_prefix_on_corrupt_header() -> None:
    """Q7: members_report returns prefix + error; members() raises; iter yields then raises."""
    data = _tar_corrupt_mid_header()
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        report = ar.members_report()
        assert report.error is not None
        assert is_corruption_not_truncation(report.error)
        names = [m.name for m in report.members]
        assert names == ["a.txt"]
        assert ar.members_report_if_available() is report
        with raises_corruption_not_truncation():
            ar.members()
        yielded: list[str] = []
        with raises_corruption_not_truncation():
            for member in ar:
                yielded.append(member.name)
        assert yielded == names
        first = report.members[0]
        assert first in ar
        assert ar.open(first).read() == b"aaa"


def test_members_report_keeps_the_prefix_when_the_walk_raises() -> None:
    # A header whose data runs past the end of the file raises during the walk; the
    # members parsed before it must still reach the report.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, payload in (
            ("a.txt", b"aaa"),
            ("b.txt", b"bbb"),
            ("c.bin", bytes(4096)),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))
    # Keep a.txt and b.txt whole, c.bin's header, and 100 bytes of its data.
    data = buf.getvalue()[: 4 * tarfile.BLOCKSIZE + tarfile.BLOCKSIZE + 100]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        report = ar.members_report()
        assert isinstance(report.error, TruncatedError)
        assert [m.name for m in report.members][:2] == ["a.txt", "b.txt"]


def test_members_report_streaming_corrupt_header_yield_then_raise() -> None:
    data = _tar_corrupt_mid_header()
    with open_archive(
        NonSeekableBytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=True,
    ) as ar:
        yielded: list[str] = []
        with raises_corruption_not_truncation():
            for member, _stream in ar.stream_members():
                yielded.append(member.name)
        assert yielded == ["a.txt"]
        report = ar.members_report()
        assert is_corruption_not_truncation(report.error)
        assert [m.name for m in report.members] == yielded


def test_members_report_raises_a_raised_eof_diagnostic() -> None:
    # A missing trailer set to RAISE is the caller's policy firing, not listing damage,
    # so members_report() raises it rather than folding it into report.error. This was
    # TruncatedError-as-report under the removed ``strict_archive_eof`` flag.
    data = _tar_missing_eof_block()
    with (
        open_archive(
            io.BytesIO(data), format=ArchiveFormat.TAR, config=_RAISE_ON_MISSING_EOF
        ) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members_report()


def test_missing_eof_blocks_streaming_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = _tar_missing_eof_block()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
    ):
        list(ar.stream_members())
    assert len(_eof_warnings(caplog)) == 1


def test_missing_eof_blocks_streaming_raise_disposition_raises() -> None:
    data = _tar_missing_eof_block()
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(
            NonSeekableBytesIO(data),
            format=ArchiveFormat.TAR,
            streaming=True,
            config=_RAISE_ON_MISSING_EOF,
        ) as ar,
    ):
        list(ar.stream_members())


def test_minimal_eof_trailer_silent(caplog: pytest.LogCaptureFixture) -> None:
    # A valid archive whose trailer is exactly the two required null blocks (no record
    # padding) must not be flagged: tarfile consumes the first block detecting EOF, so the
    # check must only require the second block, not two more. Random-access path.
    data = _tar_minimal_eof()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()
    assert _eof_warnings(caplog) == []


def test_minimal_eof_trailer_streaming_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Same minimal-but-valid trailer over the forward-only streaming path.
    data = _tar_minimal_eof()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
    ):
        list(ar.stream_members())
    assert _eof_warnings(caplog) == []


def test_minimal_eof_trailer_strict_does_not_raise() -> None:
    # DiagnosticPolicy.STRICT must accept the minimal valid trailer on both access
    # modes: it raises on both EOF codes, and neither is emitted here.
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    data = _tar_minimal_eof()
    with open_archive(
        io.BytesIO(data),
        format=ArchiveFormat.TAR,
        config=strict,
    ) as ar:
        assert [m.name for m in ar.members()]
    with open_archive(
        NonSeekableBytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=True,
        config=strict,
    ) as ar:
        assert [m for m, _ in ar.stream_members()]


def test_corrupt_final_header_raises_corruption_by_default() -> None:
    # A rejected header in the archive's final block: tarfile treats it as a clean end,
    # and the trailing-block check reads past it. The error tarfile's last header parse
    # raised says the header was rejected, so it is CorruptionError — even under the
    # default (non-strict) config, because a complete tar never stops on one.
    data = _tar_corrupt_final_header()
    with (
        raises_corruption_not_truncation(),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


def test_corrupt_mid_header_raises_corruption_by_default() -> None:
    # A rejected non-first header with valid data still following: caught by default in
    # both access modes.
    data = _tar_corrupt_mid_header()
    with (
        raises_corruption_not_truncation(),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


def test_corrupt_mid_header_streaming_raises_corruption() -> None:
    # The same rejected mid-archive header over the forward-only path.
    data = _tar_corrupt_mid_header()
    with (
        raises_corruption_not_truncation(),
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
    ):
        list(ar.stream_members())


def test_corrupt_final_header_streaming_raises_corruption() -> None:
    # With nothing after the rejected final block, the block after tarfile's stop is
    # absent, so only the error tarfile's last header parse raised tells this from a
    # missing trailer. Streaming used to warn here; it now agrees with random access.
    data = _tar_corrupt_final_header()
    with (
        raises_corruption_not_truncation(),
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
    ):
        list(ar.stream_members())


def _tar_rejected_header_then_zero_block(tail: list[str]) -> bytes:
    """Members ``a`` and ``b``, then one 1-byte member per name in ``tail``; ``b``'s
    header checksum is wrong, so tarfile rejects it.

    ``b``'s data starts with a whole zero block, as a disk image or many binaries do.
    The block after the rejected header is therefore zero, which is what a good
    end-of-archive trailer looks like from there.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        payload = bytes(512) + b"B" * 100
        for name, data in [("a", b"abc"), ("b", payload)] + [
            (name, b"c") for name in tail
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    data = bytearray(buf.getvalue())
    data[1024 + 148 : 1024 + 156] = b"0000000\0"
    return bytes(data)


def _tar_negative_size(kind: str) -> bytes:
    """Members ``a`` and ``b``, where ``b``'s size is negative: through a PAX ``size``
    record, or through a GNU base-256 size field. tarfile rejects that header."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        a = tarfile.TarInfo("a")
        a.size = 3
        t.addfile(a, io.BytesIO(b"abc"))
        b = tarfile.TarInfo("b")
        if kind == "pax":
            b.pax_headers = {"size": "-2048"}
        t.addfile(b, io.BytesIO(b""))
    data = bytearray(buf.getvalue())
    if kind == "base256":
        offset = 1024  # a's header and its one data block come first
        assert data[offset : offset + 2] == b"b\0"
        data[offset + 124 : offset + 136] = b"\xff" * 8 + (-2048 % 2**32).to_bytes(
            4, "big"
        )
        data[offset + 148 : offset + 156] = b" " * 8
        checksum = sum(data[offset : offset + 512])
        data[offset + 148 : offset + 156] = b"%06o\0 " % checksum
    return bytes(data)


def _tar_malformed_pax_header_last() -> bytes:
    """One member, then a PAX ``x`` header whose records do not parse and whose data
    is longer than one block, and nothing after it: no member header, no trailer."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        a = tarfile.TarInfo("a")
        a.size = 3
        t.addfile(a, io.BytesIO(b"abc"))
    good = buf.getvalue()
    end = _tar_content_end(good)
    payload = b"not a pax record " * 40  # 680 bytes, two blocks
    xhdr = tarfile.TarInfo("./PaxHeaders/x")
    xhdr.type = tarfile.XHDTYPE
    xhdr.size = len(payload)
    return (
        good[:end]
        + xhdr.tobuf(format=tarfile.USTAR_FORMAT)
        + payload
        + bytes(-len(payload) % 512)
    )


_REJECTED_HEADER_CASES = {
    "zero_block_after_last_member": lambda: _tar_rejected_header_then_zero_block([]),
    "zero_block_then_members": lambda: _tar_rejected_header_then_zero_block(["c", "d"]),
    "negative_pax_size": lambda: _tar_negative_size("pax"),
    "negative_base256_size": lambda: _tar_negative_size("base256"),
    "malformed_pax_header_last": _tar_malformed_pax_header_last,
}


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize(
    "build", list(_REJECTED_HEADER_CASES.values()), ids=list(_REJECTED_HEADER_CASES)
)
def test_rejected_header_raises_corruption_in_both_modes(
    build: Any, streaming: bool
) -> None:
    # tarfile ends the walk on a rejected header after the first as if the archive had
    # ended. Whatever follows the rejected header (a zero block, a member, nothing),
    # both modes raise after the members before it, as GNU tar exits 2 on all of these.
    # Streaming used to read the next block and take a zero block for the trailer,
    # dropping every later member with at most a trailing-data warning.
    data = build()
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    names: list[str] = []
    with (
        raises_corruption_not_truncation(),
        open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar,
    ):
        for member, _stream in ar.stream_members():
            names.append(member.name)
    assert names == ["a"]


def test_corrupt_final_header_extract_raises(tmp_path: Path) -> None:
    # Extraction surfaces the corruption too. Random access extracts in one pass, as
    # streaming does, so the EOF check runs after the members before the damage are
    # written: those stay on disk, whole, and the call still raises.
    data = _tar_corrupt_final_header()
    dest = tmp_path / "out"
    with (
        raises_corruption_not_truncation(),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.extract_all(dest)
    assert (dest / "hello.txt").read_bytes() == b"hello world"


def test_corrupt_final_header_sparse_raises_corruption() -> None:
    # Regression: logical size ≫ packed size once made an
    # offset_data+roundup(size) check miss the stop block, so a rejected final header
    # after a GNU sparse member warned as absent instead of raising CorruptionError.
    data = _tar_corrupt_final_header_sparse()
    with (
        raises_corruption_not_truncation(),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


def test_sparse_tar_eof_no_false_positive(caplog: pytest.LogCaptureFixture) -> None:
    # A well-formed GNU sparse tar with a valid trailer must stay silent.
    data = _tar_sparse_gnu()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        members = ar.members()
    assert members
    assert members[0].is_sparse
    assert _eof_warnings(caplog) == []


def test_sparse_member_extracts_dense_and_counts_toward_ratio(tmp_path: Path) -> None:
    # docs/formats.md promises both halves: the holes are written as zeros, and those
    # zeros count as output for the archive-wide ratio limit. 10 MiB of logical data in
    # a 2 KiB tar is far past the default max_ratio of 1000, and past the 5 MiB
    # activation threshold, so the default limits must refuse it.
    logical = 10 * 1024 * 1024
    archive = tmp_path / "sparse.tar"
    archive.write_bytes(_tar_sparse_gnu(logical))

    with pytest.raises(ResourceLimitError):
        open_and_extract(archive, tmp_path / "default")

    out = tmp_path / "unlimited"
    open_and_extract(archive, out, limits=ExtractionLimits(max_ratio=None))
    written = out / "sparse.bin"
    assert written.stat().st_size == logical
    with written.open("rb") as f:
        assert f.read(3) == b"xyz"
        assert f.read(1024 * 1024).count(0) == 1024 * 1024


def _tar_sparse_pax_1_0() -> bytes:
    """A PAX 1.0 sparse member, the encoding GNU tar writes under ``--format=pax``.

    Unlike the old GNU form its typeflag is a plain ``0``: only the ``GNU.sparse.*``
    records and the map at the head of the data say it is sparse. One 5-byte region at
    offset 100 of a 1 000-byte file.
    """
    sparse_map = b"1\n100\n5\n".ljust(512, b"\0")
    stored = sparse_map + b"hello"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("GNUSparseFile.0/holes.bin")
        info.size = len(stored)
        info.pax_headers = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "holes.bin",
            "GNU.sparse.realsize": "1000",
        }
        t.addfile(info, io.BytesIO(stored))
    return buf.getvalue()


def _pax_record(key: str, value: str) -> bytes:
    """One PAX ``length key=value\n`` record, where the length counts itself."""
    body = f" {key}={value}\n".encode()
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length += 1
    return str(length).encode() + body


def _tar_sparse_pax_0_x(minor: int) -> bytes:
    """A PAX 0.0 or 0.1 sparse member: the same one region as the 1.0 fixture.

    Neither can be written through ``tarfile``'s ``pax_headers`` dict. 0.0 repeats the
    ``GNU.sparse.offset`` / ``GNU.sparse.numbytes`` keys once per region, which a dict
    cannot hold, and tarfile reads them by scanning the raw extended header; 0.1 puts
    the whole map in one ``GNU.sparse.map`` record. So the extended header is built by
    hand here. In both the stored data is the packed regions only, with no map in it.
    """
    records = [_pax_record("GNU.sparse.size", "1000")]
    if minor == 0:
        records += [
            _pax_record("GNU.sparse.numblocks", "1"),
            _pax_record("GNU.sparse.offset", "100"),
            _pax_record("GNU.sparse.numbytes", "5"),
        ]
    else:
        records += [
            _pax_record("GNU.sparse.numblocks", "1"),
            _pax_record("GNU.sparse.map", "100,5"),
        ]
    payload = b"".join(records)

    def block(data: bytes) -> bytes:
        return data + bytes(-len(data) % tarfile.BLOCKSIZE)

    xhdr = tarfile.TarInfo("./PaxHeaders/holes.bin")
    xhdr.type = tarfile.XHDTYPE
    xhdr.size = len(payload)
    member = tarfile.TarInfo("holes.bin")
    member.size = 5
    return b"".join(
        [
            xhdr.tobuf(format=tarfile.USTAR_FORMAT),
            block(payload),
            member.tobuf(format=tarfile.USTAR_FORMAT),
            block(b"hello"),
            bytes(2 * tarfile.BLOCKSIZE),
        ]
    )


@pytest.mark.parametrize(
    "build",
    [
        lambda: _tar_sparse_pax_0_x(0),
        lambda: _tar_sparse_pax_0_x(1),
        _tar_sparse_pax_1_0,
    ],
    ids=["pax-0.0", "pax-0.1", "pax-1.0"],
)
def test_pax_sparse_member_is_reported_sparse(build: Any) -> None:
    # tarfile dispatches the three PAX sparse encodings to three different parsers,
    # and none of them sets the old GNU ``S`` typeflag, so each gets its own fixture.
    with open_archive(io.BytesIO(build()), format=ArchiveFormat.TAR) as ar:
        (member,) = ar.members()
        assert member.name == "holes.bin"
        assert member.extra["tar.type"] == tarfile.REGTYPE
        assert member.is_sparse
        assert member.size == 1000
        assert ar.read(member) == bytes(100) + b"hello" + bytes(895)


def _cut_sparse_tar(encoding: str, into: int = 2) -> tuple[bytes, bytes]:
    """A one-member sparse tar cut ``into`` bytes into its stored data, and the
    logical bytes before the cut."""
    if encoding == "old-gnu":
        data, chunk, before = _tar_sparse_gnu(1000), b"xyz", b""
    else:
        build = {
            "pax-0.0": lambda: _tar_sparse_pax_0_x(0),
            "pax-0.1": lambda: _tar_sparse_pax_0_x(1),
            "pax-1.0": _tar_sparse_pax_1_0,
        }[encoding]
        data, chunk, before = build(), b"hello", bytes(100)
    at = data.index(chunk) + into
    return data[:at], before + chunk[:into]


_SPARSE_ENCODINGS = ["old-gnu", "pax-0.0", "pax-0.1", "pax-1.0"]


# How a test opens the cut archive: random access, or a streaming pass over a seekable
# source or a pipe.
_SPARSE_CUT_OPENS = {
    "random": (io.BytesIO, False),
    "stream-seekable": (io.BytesIO, True),
    "stream-pipe": (NonSeekableBytesIO, True),
}


@pytest.mark.parametrize("read_size", [7, 1000])
@pytest.mark.parametrize("into", [0, 2], ids=["at-chunk-start", "inside-chunk"])
@pytest.mark.parametrize("opening", sorted(_SPARSE_CUT_OPENS))
@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
def test_a_cut_sparse_member_delivers_its_prefix_then_raises(
    encoding: str, opening: str, into: int, read_size: int
) -> None:
    """A sparse member cut in its stored data is a truncation, as a plain member's
    cut is: sized reads deliver the logical bytes before the cut, holes included,
    and the next read raises ``TruncatedError``, never a builtin ``EOFError``. A cut
    at a chunk's first byte keeps the hole before it too."""
    cut, prefix = _cut_sparse_tar(encoding, into)
    source, streaming = _SPARSE_CUT_OPENS[opening]
    got = bytearray()
    with open_archive(source(cut), format=ArchiveFormat.TAR, streaming=streaming) as ar:
        streams = (
            (s for _, s in ar.stream_members())
            if streaming
            else iter([ar.open(next(iter(ar)))])
        )
        with pytest.raises(TruncatedError):
            for stream in streams:
                assert stream is not None
                while block := stream.read(read_size):
                    got += block
    assert bytes(got) == prefix


@pytest.mark.parametrize("streaming", [False, True])
def test_a_sparse_stream_eof_error_is_translated(streaming: bool) -> None:
    """The stream layer raises builtins only. When ``SparseStream`` raises its
    ``EOFError`` (the stream under it returned no bytes rather than raising), the
    TAR reader turns it into ``TruncatedError``."""
    from archivey.internal.streams.streamtools import SparseStream

    def ended(self: Any, at: int, count: int) -> bytes:
        raise EOFError("the stored sparse data ended")

    with (
        mock.patch.object(SparseStream, "_read_stored", ended),
        open_archive(
            io.BytesIO(_tar_sparse_pax_1_0()),
            format=ArchiveFormat.TAR,
            streaming=streaming,
        ) as ar,
        pytest.raises(TruncatedError, match="ended early"),
    ):
        for _, stream in ar.stream_members():
            assert stream is not None
            stream.read()


@pytest.mark.parametrize("opening", sorted(_SPARSE_CUT_OPENS))
@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
def test_a_cut_sparse_member_read_whole_raises_truncated(
    encoding: str, opening: str
) -> None:
    cut, _ = _cut_sparse_tar(encoding)
    source, streaming = _SPARSE_CUT_OPENS[opening]
    with (
        open_archive(source(cut), format=ArchiveFormat.TAR, streaming=streaming) as ar,
        pytest.raises(TruncatedError),
    ):
        if streaming:
            for _, stream in ar.stream_members():
                assert stream is not None
                stream.read()
        else:
            ar.read(next(iter(ar)))


@pytest.mark.parametrize("opening", sorted(_SPARSE_CUT_OPENS))
@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
def test_a_cut_sparse_member_fails_extract_all_with_truncated(
    encoding: str, opening: str, tmp_path: Path
) -> None:
    cut, _ = _cut_sparse_tar(encoding)
    source, streaming = _SPARSE_CUT_OPENS[opening]
    with (
        open_archive(source(cut), format=ArchiveFormat.TAR, streaming=streaming) as ar,
        pytest.raises(TruncatedError),
    ):
        ar.extract_all(tmp_path / "out")


def test_corrupt_final_header_gzip_raises_corruption(tmp_path: Path) -> None:
    # The compressed path classifies the end the same way, with no backward seek.
    import gzip

    path = tmp_path / "bad.tar.gz"
    path.write_bytes(gzip.compress(_tar_corrupt_final_header()))
    with raises_corruption_not_truncation(), open_archive(path) as ar:
        ar.members()


def test_corrupt_mid_header_raise_disposition_still_corruption() -> None:
    # A RAISE disposition does not change the type for a rejected header: the nonzero
    # case escalates as CorruptionError, which outranks DiagnosticRaisedError.
    data = _tar_corrupt_mid_header()
    with (
        raises_corruption_not_truncation(),
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.TAR,
            config=_RAISE_ON_MISSING_EOF,
        ) as ar,
    ):
        ar.members()


def test_corrupt_final_header_ignore_disposition_still_raises() -> None:
    # escalate_as=CorruptionError takes precedence over IGNORE (spec matrix).
    from archivey.diagnostics import (
        DiagnosticCode,
        DiagnosticPolicy,
    )

    data = _tar_corrupt_final_header()
    policy = DiagnosticPolicy(ignore={DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING})
    with (
        raises_corruption_not_truncation(),
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.TAR,
            config=ArchiveyConfig(diagnostic_policy=policy),
        ) as ar,
    ):
        ar.members()


def test_corrupt_mid_header_streaming_extract_writes_then_raises(
    tmp_path: Path,
) -> None:
    # Streaming extract writes salvageable members, then raises at end-of-pass.
    data = _tar_corrupt_mid_header()
    dest = tmp_path / "out"
    with (
        raises_corruption_not_truncation(),
        open_archive(
            NonSeekableBytesIO(data), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
    ):
        ar.extract_all(dest)
    assert (dest / "a.txt").exists()
    assert (dest / "a.txt").read_bytes() == b"aaa"
    assert not (dest / "b.txt").exists()


# A zero block, then a damaged second end-of-archive block: GNU tar ("A lone zero block")
# and 7-Zip list every member with a warning and exit 0. The second block is damaged by
# one stray byte, or holds a header-shaped run of junk.
_DAMAGED_SECOND_BLOCKS = {
    "stray_byte": b"\x00" * 100 + b"\x01" + b"\x00" * 411,
    "junk_header": b"A" * 100 + b"\x00" * 412,
}


def _tar_damaged_second_eof_block(damage: bytes) -> bytes:
    data = _tar_three()
    end = _tar_content_end(data)
    return data[:end] + b"\x00" * 512 + damage + b"\x00" * (512 * 8)


def _eof_marker_contexts(ar: Any) -> list[ArchiveEofContext]:
    contexts = [
        d.context
        for d in ar.diagnostics.retained
        if d.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING
    ]
    assert all(isinstance(c, ArchiveEofContext) for c in contexts)
    return contexts


_THREE = {"a.txt": b"aaa", "b.txt": b"b" * 4000, "c.txt": b"ccc"}


@pytest.mark.parametrize("damage", _DAMAGED_SECOND_BLOCKS, ids=str)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_damaged_second_eof_block_lists_every_member(
    streaming: bool, damage: str
) -> None:
    # The listing ends at the zero block, so it is whole: only the end-of-archive
    # marker is damaged. That is the ARCHIVE_EOF_MARKER_MISSING diagnostic, not the
    # CorruptionError a rejected header gets.
    data = _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS[damage])
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    with open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar:
        read = {m.name: stream.read() for m, stream in ar.stream_members() if stream}
        contexts = _eof_marker_contexts(ar)
        if not streaming:
            assert [m.name for m in ar.members()] == list(_THREE)
            assert {m.name: ar.read(m) for m in ar.members()} == _THREE
    assert read == _THREE
    assert len(contexts) == 1
    assert contexts[0].format == "tar"
    # Its own marker, so the context says the listing is whole: a rejected header
    # reports "two_zero_blocks" with the same observed_kind and raises.
    assert contexts[0].expected_marker == "second_zero_block"
    assert contexts[0].expected_bytes == 512
    assert contexts[0].observed_bytes == 512
    assert contexts[0].observed_kind == "nonzero"


def test_damaged_second_eof_block_gzip_lists_every_member(tmp_path: Path) -> None:
    import gzip

    path = tmp_path / "damaged-end.tar.gz"
    path.write_bytes(
        gzip.compress(
            _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS["stray_byte"])
        )
    )
    with open_archive(path) as ar:
        assert [m.name for m in ar.members()] == list(_THREE)
        assert len(_eof_marker_contexts(ar)) == 1


def _gzip_with_bad_crc(data: bytes) -> bytes:
    import gzip

    out = bytearray(gzip.compress(data))
    out[-8] ^= 0xFF  # the footer's CRC-32 over the whole decoded stream
    return bytes(out)


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize(
    "tail",
    ["healthy_trailer", "damaged_second_block"],
)
def test_bad_gzip_crc_is_reported_after_a_damaged_second_eof_block(
    tmp_path: Path, streaming: bool, tail: str
) -> None:
    # The gzip footer sits past the trailer, in the record padding, so the trailing
    # scan is where its CRC-32 over the members is checked. A damaged second block
    # must not skip that scan and hand the members back as whole. The 64 KiB of
    # padding is a ``tar -b128`` record; with less, the streaming codec can reach the
    # footer while the last header is still being read.
    if tail == "healthy_trailer":
        plain = _tar_three()
    else:
        plain = _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS["stray_byte"])
    path = tmp_path / "bad-crc.tar.gz"
    path.write_bytes(_gzip_with_bad_crc(plain + b"\x00" * (64 * 1024)))
    with (
        raises_corruption_not_truncation(),
        open_archive(path, streaming=streaming) as ar,
    ):
        list(ar.stream_members())


def test_damaged_second_eof_block_then_junk_reports_trailing_data() -> None:
    data = _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS["stray_byte"])
    end = _tar_content_end(data)  # the end of the damaged block
    data = data[:end] + b"\x00" * 100 + b"junk" + data[end + 104 :]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert [m.name for m in ar.members()] == list(_THREE)
        trailing = [
            d.context
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
        assert len(_eof_marker_contexts(ar)) == 1
    assert len(trailing) == 1
    assert isinstance(trailing[0], ArchiveEofContext)
    assert trailing[0].expected_marker == "zeros_to_eof"
    assert trailing[0].observed_bytes == 100


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_damaged_second_eof_block_refused_under_strict(streaming: bool) -> None:
    data = _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS["stray_byte"])
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(
            source, format=ArchiveFormat.TAR, streaming=streaming, config=strict
        ) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        list(ar.stream_members())


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_damaged_second_eof_block_extracts_every_member(
    tmp_path: Path, streaming: bool
) -> None:
    data = _tar_damaged_second_eof_block(_DAMAGED_SECOND_BLOCKS["junk_header"])
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    dest = tmp_path / "out"
    with open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar:
        ar.extract_all(dest)
        assert len(_eof_marker_contexts(ar)) == 1
    assert {p.name: p.read_bytes() for p in dest.iterdir()} == _THREE


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_zero_block_then_junk_with_no_member_stays_corruption(
    streaming: bool,
) -> None:
    # With no member before the zero block there is no listing to keep, and a file
    # that is a zero block and then junk is not shown to be a tar at all.
    data = b"\x00" * 512 + b"A" * 100 + b"\x00" * (512 * 9 - 100)
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    with (
        raises_corruption_not_truncation() as excinfo,
        open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar,
    ):
        list(ar.stream_members())
    # There is no member header and no listing to shorten, so the message says what
    # is actually wrong.
    assert "has no member" in str(excinfo.value)
    assert "shortened listing" not in str(excinfo.value)


def test_padded_tar_eof_no_false_positive(caplog: pytest.LogCaptureFixture) -> None:
    # tarfile writes 10240-byte record padding (many trailing null blocks past the two
    # required ones). The end check must not read that padding as a rejected block.
    data = _build_tar()  # full tarfile output, padded
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()
    assert _eof_warnings(caplog) == []


# ---------------------------------------------------------------------------
# Corrupt / truncated input (per-format slice of testing-contract).
# ---------------------------------------------------------------------------


def test_truncated_tar_raises() -> None:
    full = _build_tar()
    # Cut into the body so the header scan hits "unexpected end of data" (tarfile pads the
    # whole archive to a 10 KiB record, so cut well inside the real member region).
    truncated = full[:800]
    with (
        pytest.raises(TruncatedError),
        open_archive(io.BytesIO(truncated), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


def _cut_plain_tar() -> tuple[bytes, bytes]:
    """A plain tar holding ``a`` (300,000 bytes) then ``b``, cut inside ``a``'s data."""
    payload = random.Random(16).randbytes(300_000)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in (("a", payload), ("b", b"after")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()[:150_000], payload


class _SizelessSeekable(io.RawIOBase):
    """A seekable source with no cheap size: no ``size``, not a ``BytesIO`` or a file."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, n: int = -1, /) -> bytes:
        return self._inner.read(n)

    def readinto(self, b: Any, /) -> int:
        return self._inner.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._inner.seek(offset, whence)

    def tell(self) -> int:
        return self._inner.tell()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


_CUT_SOURCES = {"bytesio": io.BytesIO, "sizeless": _SizelessSeekable}


@pytest.mark.parametrize("source", sorted(_CUT_SOURCES))
@pytest.mark.parametrize("size", [-1, 1024])
def test_a_cut_plain_tar_member_raises_on_read_without_a_listing(
    source: str, size: int
) -> None:
    # The lookup stops at the first match, so the walk never reaches the cut: the
    # member read itself has to find it, whether or not the source size is known.
    cut, _payload = _cut_plain_tar()
    with open_archive(_CUT_SOURCES[source](cut), format=ArchiveFormat.TAR) as ar:
        with (
            ar.open("a") as stream,
            pytest.raises(TruncatedError, match="inside a member's data"),
        ):
            while stream.read(size):
                pass
        with pytest.raises(TruncatedError, match="inside a member's data"):
            ar.read("a")


@pytest.mark.parametrize("source", sorted(_CUT_SOURCES))
@pytest.mark.parametrize("chunk", [1024, 64 * 1024, 1024 * 1024])
def test_a_cut_plain_tar_member_delivers_its_prefix_then_raises(
    source: str, chunk: int
) -> None:
    cut, payload = _cut_plain_tar()
    got = bytearray()
    with open_archive(_CUT_SOURCES[source](cut), format=ArchiveFormat.TAR) as ar:
        member = ar.get("a")
        assert member.size == len(payload)
        with ar.open(member) as stream, pytest.raises(TruncatedError):
            while block := stream.read(chunk):
                got += block
    assert len(got) == len(cut) - 512  # every byte after the header
    assert payload.startswith(bytes(got))


def test_corrupt_tar_header_raises() -> None:
    raw = bytearray(_build_tar())
    # Corrupt the checksum field (offset 148, 8 bytes) of the first header.
    raw[148:156] = b"\xff\xff\xff\xff\xff\xff\xff\xff"
    with (
        raises_corruption_not_truncation(),
        open_archive(io.BytesIO(bytes(raw)), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


def _raw_tar_header(
    name: str, typeflag: bytes, size: int, *, size_field: bytes | None = None
) -> bytes:
    """A ustar header block for ``name`` with the given typeflag and size. ``size_field``
    replaces the 12-byte size field as stored (for a GNU base-256 size)."""
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o755
    header = bytearray(info.tobuf(format=tarfile.USTAR_FORMAT))
    header[156:157] = typeflag
    if size_field is not None:
        header[124:136] = size_field
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\0 " % sum(header)
    return bytes(header)


_OLD_STYLE_TYPEFLAGS = [
    pytest.param(tarfile.AREGTYPE, id="AREGTYPE"),
    pytest.param(tarfile.REGTYPE, id="REGTYPE"),
    pytest.param(tarfile.CONTTYPE, id="CONTTYPE"),
]
"""The three regular-file typeflags whose ``d/`` entry GNU tar reads as a directory.
7-Zip agrees for NUL and ``0``; it lists a contiguous ``d/`` as the file ``d``."""


def _tar_entry_with_data(
    typeflag: bytes,
    *,
    own_name: str = "d/",
    wrapper: str | None = None,
    final_name: str = "d/",
    size_field: bytes | None = None,
    data: bytes = b"hello directory",
    tail: bytes | None = None,
) -> bytes:
    """A ustar entry with the given typeflag and ``data`` (15 bytes by default), then a
    regular file ``after.txt`` and a good trailer, or ``tail`` in their place. The entry
    is named ``d/`` unless ``own_name`` says otherwise. GNU tar 1.35 lists ``d/`` as a
    directory and skips its data when the typeflag is NUL (old-style ``AREGTYPE``),
    ``0`` or ``7`` (``CONTTYPE``), as 7-Zip does for the first two; both report an
    error when it is ``5`` (``DIRTYPE``), which carries no data.

    ``wrapper`` puts a PAX ``path`` record (``"pax"``) or a GNU long name (``"gnu"``)
    holding ``final_name`` before the header, whose own name field is ``own_name``.
    """
    prefix = b""
    if wrapper == "pax":
        record = f"path={final_name}\n".encode()
        length = len(record) + 2
        length += len(str(length)) - 1
        record = b"%d " % length + record
        assert len(record) == length
        prefix = _raw_tar_header("PaxHeaders/d", tarfile.XHDTYPE, len(record))
        prefix += record.ljust(512, b"\0")
    elif wrapper == "gnu":
        long_name = final_name.encode() + b"\0"
        prefix = _raw_tar_header(
            "././@LongLink", tarfile.GNUTYPE_LONGNAME, len(long_name)
        )
        prefix += long_name.ljust(512, b"\0")
    if tail is None:
        after = tarfile.TarInfo("after.txt")
        after.size = 6
        tail = (
            after.tobuf(format=tarfile.USTAR_FORMAT)
            + b"after\n".ljust(512, b"\0")
            + b"\0" * 1024
        )
    return (
        prefix
        + _raw_tar_header(own_name, typeflag, len(data), size_field=size_field)
        + (data.ljust(512, b"\0") if data else b"")
        + tail
    )


_DAMAGED_TRAILER = b"\0" * 512 + b"j" * 512
"""A zero block, then a block that is neither a header nor zero: the end-of-archive
marker with its second block damaged, which GNU tar lists past with a warning."""


def _stream_all(data: bytes, streaming: bool) -> list[tuple[str, MemberType, Any]]:
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        return [
            (m.name, m.type, stream.read() if stream is not None else None)
            for m, stream in ar.stream_members()
        ]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_with_data_is_a_directory(
    typeflag: bytes, streaming: bool
) -> None:
    # stdlib tarfile turns an AREGTYPE header whose name ends in "/" into a directory
    # and then reads its data blocks as the next header, and lists a REGTYPE one as
    # the file "d/". GNU tar lists a directory for all three typeflags and skips the
    # data; 7-Zip does too for NUL and 0. The pass yields the directory's declared
    # bytes, as open() delivers them.
    data = _tar_entry_with_data(typeflag)
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, b"hello directory"),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_data_is_reported(typeflag: bytes, streaming: bool) -> None:
    # The directory keeps the size its header declares and
    # MEMBER_DIRECTORY_DATA_IGNORED names the bytes extraction drops, on both walks.
    data = _tar_entry_with_data(typeflag)
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        directory, stream = next(iter(ar.stream_members()))
        assert stream is not None
        assert directory.type is MemberType.DIRECTORY
        assert directory.size == 15
        assert directory.extra["tar.type"] == typeflag
        diags = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert [d.context.to_dict() if d.context else None for d in diags] == [
            {
                "kind": "directory_data",
                "archive_name": None,
                "member_name": "d/",
                "member_id": 0,
                "size": 15,
                "compressed_size": None,
            }
        ]
        assert "15 bytes" in diags[0].message


@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_data_is_readable(typeflag: bytes) -> None:
    # read() delivers the bytes, so the data an archive hides behind a directory name
    # is never out of reach. A streaming walk has no read(); its pass yields the same
    # bytes (test_old_style_directory_with_data_is_a_directory).
    data = _tar_entry_with_data(typeflag)
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        directory, after = ar.members()
        assert ar.read(directory) == b"hello directory"
        assert ar.read(after) == b"after\n"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_data_is_refused_by_strict_policy(
    typeflag: bytes, streaming: bool
) -> None:
    data = _tar_entry_with_data(typeflag)
    with (
        pytest.raises(DiagnosticRaisedError) as excinfo,
        open_archive(
            NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
            format=ArchiveFormat.TAR,
            streaming=streaming,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as ar,
    ):
        list(ar.stream_members())
    assert excinfo.value.diagnostic.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_slash_name_without_data_is_a_plain_directory(
    typeflag: bytes, streaming: bool
) -> None:
    # The common producer shape: an old-style "d/" header with size 0 (v7-era tars
    # wrote directories so). It is a directory with no size and nothing to report.
    data = _tar_entry_with_data(typeflag, data=b"")
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        directory = next(m for m, _ in ar.stream_members())
        assert directory.size is None
        assert directory.extra["tar.type"] == typeflag
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED not in ar.diagnostics.counts
    # Random access only: open() takes a member by name, which a streaming walk has
    # no index for.
    with (
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
        pytest.raises(ArchiveyUsageError, match="declares no data"),
    ):
        ar.open(ar.members()[0])


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("wrapper", ["pax", "gnu"])
@pytest.mark.parametrize("own_name", ["d", "d/"])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_name_from_extended_header(
    typeflag: bytes, wrapper: str, own_name: str, streaming: bool
) -> None:
    # GNU tar (and 7-Zip, for NUL and 0) decides on the final name, after a PAX path
    # or a GNU long name, whatever the header's own name field holds. stdlib tarfile
    # decides on the own name field, and only on Pythons without the 2025 fixes.
    data = _tar_entry_with_data(
        typeflag, own_name=own_name, wrapper=wrapper, final_name="d/"
    )
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, b"hello directory"),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("wrapper", ["pax", "gnu"])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_slash_name_overridden_without_slash_is_a_file(
    typeflag: bytes, wrapper: str, streaming: bool
) -> None:
    # The own name field says "d/", the final name says "d": GNU tar lists a file.
    data = _tar_entry_with_data(
        typeflag, own_name="d/", wrapper=wrapper, final_name="d"
    )
    assert _stream_all(data, streaming) == [
        ("d", MemberType.FILE, b"hello directory"),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]


@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_keeps_stored_typeflag(typeflag: bytes) -> None:
    # extra["tar.type"] is the typeflag byte as stored, which tells an old-style
    # directory apart from a DIRTYPE one.
    data = _tar_entry_with_data(typeflag)
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        member = ar.members()[0]
    assert member.type == MemberType.DIRECTORY
    assert member.extra["tar.type"] == typeflag


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_data_cut_off_is_truncation(
    typeflag: bytes, streaming: bool
) -> None:
    # The archive ends inside the data area the directory header declares.
    data = _tar_entry_with_data(typeflag)[:512]
    with pytest.raises(TruncatedError):
        _stream_all(data, streaming)


@pytest.mark.parametrize("from_file", [True, False], ids=["file", "bytesio"])
@pytest.mark.parametrize("typeflag", [tarfile.AREGTYPE, tarfile.REGTYPE])
def test_size_past_filesystem_limit_is_truncation(
    tmp_path: Path, typeflag: bytes, from_file: bool
) -> None:
    # A GNU base-256 size of 2**62 is under the largest seek offset. ext4 refuses a
    # seek that far with OSError(EINVAL); APFS and a BytesIO accept it, and the next
    # read finds the end of the data. The same archive must give the same error from
    # every source on every OS.
    size_field = b"\x80" + (2**62).to_bytes(11, "big")
    data = _tar_entry_with_data(typeflag, size_field=size_field)
    path = tmp_path / "big.tar"
    path.write_bytes(data)
    source = path if from_file else io.BytesIO(data)
    with (
        pytest.raises(TruncatedError),
        open_archive(source, format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


class _SeekRefusingBytesIO(io.BytesIO):
    """A ``BytesIO`` that refuses a seek past ``limit`` as ext4 does past its largest
    file size, so the refused-seek path runs on every filesystem and OS."""

    def __init__(self, data: bytes, *, err: int, limit: int = 2**40) -> None:
        super().__init__(data)
        self._err = err
        self._limit = limit

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if whence == io.SEEK_SET and offset > self._limit:
            raise OSError(self._err, os.strerror(self._err))
        return super().seek(offset, whence)


@pytest.mark.parametrize("err", [errno.EINVAL, errno.EOVERFLOW])
def test_refused_seek_is_truncation_naming_the_offset(err: int) -> None:
    inner = _SeekRefusingBytesIO(b"\0" * 1024, err=err)
    walker = TarWalker(inner, seekable=True)
    with pytest.raises(TruncatedError, match=r"offset 4611686018427388415\b"):
        walker._seek(2**62 + 511)


def test_refused_seek_with_other_errno_propagates() -> None:
    # Only the errnos lseek gives for an offset past the filesystem's limit read as
    # the end of the data; any other OSError is an I/O failure (DR-15a).
    inner = _SeekRefusingBytesIO(b"\0" * 1024, err=errno.EIO)
    walker = TarWalker(inner, seekable=True)
    with pytest.raises(OSError) as excinfo:
        walker._seek(2**62)
    assert excinfo.value.errno == errno.EIO
    assert not isinstance(excinfo.value, TruncatedError)


@pytest.mark.parametrize("typeflag", [tarfile.AREGTYPE, tarfile.REGTYPE])
def test_refused_seek_through_open_archive_is_truncation(typeflag: bytes) -> None:
    # The ext4 arm of test_size_past_filesystem_limit_is_truncation, on any OS.
    size_field = b"\x80" + (2**62).to_bytes(11, "big")
    data = _tar_entry_with_data(typeflag, size_field=size_field)
    source = _SeekRefusingBytesIO(data, err=errno.EINVAL)
    with (
        pytest.raises(TruncatedError, match="past the end of the archive"),
        open_archive(source, format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()


@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_with_data_extracts(
    tmp_path: Path, typeflag: bytes
) -> None:
    # The directory is created and its bytes are not written, as GNU tar does (and
    # 7-Zip, for NUL and 0).
    data = _tar_entry_with_data(typeflag)
    open_and_extract(io.BytesIO(data), tmp_path, format=ArchiveFormat.TAR)
    assert (tmp_path / "d").is_dir()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["after.txt", "d"]
    assert (tmp_path / "after.txt").read_bytes() == b"after\n"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_holds_the_members_under_it(
    tmp_path: Path, typeflag: bytes, streaming: bool
) -> None:
    # A "d/" header with no data and a member "d/f" behind it: d/ is a directory, so
    # extraction creates d/f inside it, as GNU tar 1.35 does for all three typeflags.
    # Listed as the file "d", d/f would fail to extract under it.
    inner = tarfile.TarInfo("d/f")
    inner.size = 3
    tail = (
        inner.tobuf(format=tarfile.USTAR_FORMAT)
        + b"bee".ljust(512, b"\0")
        + b"\0" * 1024
    )
    data = _tar_entry_with_data(typeflag, data=b"", tail=tail)
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, None),
        ("d/f", MemberType.FILE, b"bee"),
    ]
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    open_and_extract(source, tmp_path, format=ArchiveFormat.TAR, streaming=streaming)
    assert (tmp_path / "d" / "f").read_bytes() == b"bee"


@pytest.mark.parametrize("streaming", [False, True])
def test_old_gnu_sparse_slash_name_is_a_file(streaming: bool) -> None:
    # Old GNU sparse "S" carries a file's data but is not one of the regular-file
    # typeflags: GNU tar 1.35 extracts an "S" header named "d/" as the file "d".
    data = _tar_entry_with_data(tarfile.GNUTYPE_SPARSE, data=b"")
    assert _stream_all(data, streaming) == [
        ("d", MemberType.FILE, b""),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_bytes_payload_is_corruption(streaming: bool) -> None:
    # A DIRTYPE header has no data area, so the walker reads the declared blocks as the
    # next header; a non-zero payload does not parse. The error names the directory,
    # whose declared size is why a header sits where none parses. GNU tar 1.35 reports
    # "Skipping to next header", dropping after.txt; 7-Zip stops.
    data = _tar_entry_with_data(tarfile.DIRTYPE, data=b"hello directory")
    with raises_corruption_not_truncation(match="directory that declares"):
        _stream_all(data, streaming)


_ZERO_SPANS = [b"\0" * 512, b"\0" * 1024, b"\0" * 1536, b"\0" * 512 + b"x" * 512]
"""Declared DIRTYPE payloads that begin with a zero block: the walker reads them as the
end-of-archive marker (a lone block, a complete marker, or a marker with junk)."""


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "payload",
    _ZERO_SPANS,
    ids=["zero_block", "two_zero_blocks", "three_zero_blocks", "zero_then_bytes"],
)
def test_dirtype_zero_span_is_reported(payload: bytes, streaming: bool) -> None:
    # A DIRTYPE header has no data area, so the walker reads a zero payload as the
    # end-of-archive marker and after.txt behind it is not listed. Nothing in the file
    # tells that from a header whose blocks were never written before a trailer and
    # appended data, so the directory is listed with no size and reported with
    # MEMBER_DIRECTORY_DATA_IGNORED, the weight a directory's declared data has in
    # every format; the marker checks report the trailer as after a file. GNU tar 1.35
    # lists d/ with "A lone zero block" for one block and with no word for more.
    data = _tar_entry_with_data(tarfile.DIRTYPE, data=payload)
    assert _stream_all(data, streaming) == [("d/", MemberType.DIRECTORY, None)]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        member = ar.members()[0]
        assert member.size is None
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1
        # Attached to the member, as the old-style directory's report is.
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        diags = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert [d.context.to_dict() if d.context else None for d in diags] == [
            {
                "kind": "directory_data",
                "archive_name": None,
                "member_name": "d/",
                "member_id": 0,
                "size": len(payload),
                "compressed_size": None,
            }
        ]
        with pytest.raises(ArchiveyUsageError, match="declares no data"):
            ar.open("d/")


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_zero_span_is_refused_by_strict_policy(streaming: bool) -> None:
    data = _tar_entry_with_data(tarfile.DIRTYPE, data=b"\0" * 1024)
    with (
        pytest.raises(DiagnosticRaisedError) as excinfo,
        open_archive(
            NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
            format=ArchiveFormat.TAR,
            streaming=streaming,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as ar,
    ):
        list(ar.stream_members())
    assert excinfo.value.diagnostic.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_size_before_concatenated_archive_is_reported(
    streaming: bool,
) -> None:
    # A DIRTYPE header whose size field is set, no blocks, a good trailer, then a
    # second archive starting exactly where the declared span would end: the same
    # bytes as a two-block zero payload hiding second.txt. GNU tar lists d/ and exits
    # 0; archivey lists d/ with the directory-data report and the trailing-data
    # report, as it lists a file before a concatenated archive with the latter alone.
    second = tarfile.TarInfo("second.txt")
    second.size = 7
    tail = (
        b"\0" * 1024
        + second.tobuf(format=tarfile.USTAR_FORMAT)
        + b"second\n".ljust(512, b"\0")
        + b"\0" * 1024
    )
    data = _tar_entry_with_data(
        tarfile.DIRTYPE, data=b"", size_field=b"%011o\0" % 1024, tail=tail
    )
    assert _stream_all(data, streaming) == [("d/", MemberType.DIRECTORY, None)]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert [m.name for m in ar.members()] == ["d/"]
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1
        assert ar.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1
        assert DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING not in ar.diagnostics.counts


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_size_and_no_blocks_lists_whole(streaming: bool) -> None:
    # A DIRTYPE header whose size field is not zero but whose data blocks are not
    # there (a writer carried st_size into the header): the next header follows at
    # once, so GNU tar, bsdtar and 7-Zip list every member, and so does archivey, with
    # no size on the directory and nothing to report.
    data = _tar_entry_with_data(tarfile.DIRTYPE, data=b"", size_field=b"%011o\0" % 4096)
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[0].size is None
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED not in ar.diagnostics.counts
        assert DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING not in ar.diagnostics.counts


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_size_before_damaged_trailer_is_the_trailer_warning(
    streaming: bool,
) -> None:
    # A DIRTYPE header whose size field is set, with no blocks behind it, as the last
    # member before a damaged trailer: the bytes are the same as a zero payload with
    # junk after it, so the directory's declared size is reported and the trailer gets
    # the damaged-marker warning a file in its place gets; nothing raises. GNU tar
    # lists d/ and warns of a lone zero block; 7-Zip lists it with a warning.
    data = _tar_entry_with_data(
        tarfile.DIRTYPE, data=b"", size_field=b"%011o\0" % 4096, tail=_DAMAGED_TRAILER
    )
    assert _stream_all(data, streaming) == [("d/", MemberType.DIRECTORY, None)]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[0].size is None
        assert ar.diagnostics.counts[DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING] == 1
        # The walk ended on the zero block right after the directory, so its declared
        # size is reported too: these bytes are also a one-block zero span then junk.
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1


_LINK_TYPEFLAGS = [tarfile.SYMTYPE, tarfile.LNKTYPE]
"""The two link typeflags. Their size field announces no data area, as for a
directory, but a link with a size has its declared blocks skipped (maintainer ruling,
2026-10-17)."""

_LINK_PAYLOADS = [
    b"link data " * 60,
    b"\0" * 512,
    b"\0" * 1024,
    b"\0" * 1536,
    b"\0" * 512 + b"x" * 512,
]
_LINK_PAYLOAD_IDS = [
    "bytes",
    "zero_block",
    "two_zero_blocks",
    "three_zero_blocks",
    "zero_then_bytes",
]


def _tar_link_with_data(
    typeflag: bytes,
    data: bytes,
    *,
    size: int | None = None,
    tail: bytes | None = None,
) -> bytes:
    """``a.txt``, then a link ``l`` to it whose header declares ``size`` bytes
    (``len(data)`` by default) and is followed by ``data``, padded to a block, then
    ``after.txt`` and a good trailer, or ``tail`` in their place."""
    target = tarfile.TarInfo("a.txt")
    target.size = 5
    header = bytearray(
        _raw_tar_header("l", typeflag, len(data) if size is None else size)
    )
    header[157:162] = b"a.txt"
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\0 " % sum(header)
    if tail is None:
        after = tarfile.TarInfo("after.txt")
        after.size = 6
        tail = (
            after.tobuf(format=tarfile.USTAR_FORMAT)
            + b"after\n".ljust(512, b"\0")
            + b"\0" * 1024
        )
    return (
        target.tobuf(format=tarfile.USTAR_FORMAT)
        + b"hello".ljust(512, b"\0")
        + bytes(header)
        + (data + b"\0" * (-len(data) % 512))
        + tail
    )


def _link_type(typeflag: bytes) -> MemberType:
    return MemberType.SYMLINK if typeflag == tarfile.SYMTYPE else MemberType.HARDLINK


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("payload", _LINK_PAYLOADS, ids=_LINK_PAYLOAD_IDS)
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_data_is_skipped_and_reported(
    typeflag: bytes, payload: bytes, streaming: bool
) -> None:
    # A link header with a size and blocks behind it that are not a member header:
    # the blocks are skipped, so a zero block among them does not end the listing
    # and after.txt stays. GNU tar 1.35 and tarfile stop at a zero block (GNU tar
    # exits 0) and GNU tar reports "Skipping to next header" for bytes; 7-Zip skips
    # a symlink's blocks only. MEMBER_LINK_DATA_IGNORED names the link.
    data = _tar_link_with_data(typeflag, payload)
    assert _stream_all(data, streaming) == [
        ("a.txt", MemberType.FILE, b"hello"),
        ("l", _link_type(typeflag), None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        members = list(ar)
        assert [m.name for m in members] == ["a.txt", "l", "after.txt"]
        link = members[1]
        assert link.size is None
        assert link.link_target == "a.txt"
        assert ar.diagnostics.counts == {DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1}
        assert [d.code for d in link.diagnostics] == [
            DiagnosticCode.MEMBER_LINK_DATA_IGNORED
        ]
        (diag,) = ar.diagnostics.retained
        assert diag.context is not None
        assert diag.context.to_dict() == {
            "kind": "link_data",
            "archive_name": None,
            "member_name": "l",
            "member_id": 1,
            "size": len(payload),
        }
        assert "skipped" in diag.message


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "payload", [_LINK_PAYLOADS[0], _LINK_PAYLOADS[2]], ids=["bytes", "zero_blocks"]
)
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_data_extraction_makes_the_link_and_later_members(
    tmp_path: Path, typeflag: bytes, payload: bytes, streaming: bool
) -> None:
    # The link is extracted as a link, its declared bytes written nowhere, and the
    # member after them is extracted too.
    if typeflag == tarfile.SYMTYPE and not _can_symlink(tmp_path):
        pytest.skip("this process may not create symlinks")
    dest = tmp_path / "out"
    data = _tar_link_with_data(typeflag, payload)
    open_and_extract(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        dest,
        format=ArchiveFormat.TAR,
        streaming=streaming,
    )
    assert sorted(p.name for p in dest.iterdir()) == ["a.txt", "after.txt", "l"]
    assert (dest / "after.txt").read_bytes() == b"after\n"
    assert (dest / "l").read_bytes() == b"hello"
    if typeflag == tarfile.SYMTYPE:
        assert (dest / "l").is_symlink()
        assert os.readlink(dest / "l") == "a.txt"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_with_size_and_no_blocks_lists_whole(
    typeflag: bytes, streaming: bool
) -> None:
    # A link header whose size field is set but whose blocks are not there: the next
    # member header follows at once, so the size names no data. GNU tar, tarfile and
    # bsdtar list every member, and so does archivey, with nothing to report, as for
    # a DIRTYPE header with a size (PR 763). Skipping by the size would hide after.txt,
    # as 7-Zip hides it behind a symlink.
    data = _tar_link_with_data(typeflag, b"", size=600)
    assert [(n, t) for n, t, _ in _stream_all(data, streaming)] == [
        ("a.txt", MemberType.FILE),
        ("l", _link_type(typeflag)),
        ("after.txt", MemberType.FILE),
    ]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[1].size is None
        assert dict(ar.diagnostics.counts) == {}


@pytest.mark.parametrize("streaming", [False, True])
def test_link_with_size_and_no_blocks_before_a_pax_header_lists_whole(
    streaming: bool,
) -> None:
    # The header after the link is a PAX extended header, whose records the walk
    # reads from the blocks right after it: read ahead at the link, it is still read
    # from the right place.
    after = tarfile.TarInfo("after.txt")
    after.size = 6
    after.pax_headers = {"comment": "x" * 600}
    tail = (
        after.tobuf(format=tarfile.PAX_FORMAT)
        + b"after\n".ljust(512, b"\0")
        + b"\0" * 1024
    )
    data = _tar_link_with_data(tarfile.SYMTYPE, b"", size=600, tail=tail)
    assert _stream_all(data, streaming) == [
        ("a.txt", MemberType.FILE, b"hello"),
        ("l", MemberType.SYMLINK, None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[2].extra["tar.pax_headers"]["comment"] == "x" * 600
        assert dict(ar.diagnostics.counts) == {}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_with_size_before_the_trailer_is_reported_not_truncated(
    typeflag: bytes, streaming: bool
) -> None:
    # The last member is a link whose size declares more than the archive holds after
    # it, and what follows is the trailer: zeros to the end. Either the blocks were
    # never written or they are zeros cut short; nothing tells them apart, so the
    # zero block ends the walk, as in GNU tar and tarfile, and the declared size is
    # reported, as for a DIRTYPE header (PR 763). It is not truncation.
    data = _tar_link_with_data(typeflag, b"", size=64 * 1024, tail=b"\0" * 1024)
    assert [n for n, _, _ in _stream_all(data, streaming)] == ["a.txt", "l"]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        assert [m.name for m in ar] == ["a.txt", "l"]
        assert ar.diagnostics.counts == {DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1}
        (diag,) = ar.diagnostics.retained
        assert "end-of-archive marker" in diag.message


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("declared", "trailer"),
    [(10, 1024), (600, 1024), (1024, 1024), (1500, 1536)],
    ids=["10_before_1024", "600_before_1024", "1024_before_1024", "1500_before_1536"],
)
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_with_size_inside_the_trailer_keeps_the_trailer_whole(
    typeflag: bytes, declared: int, trailer: int, streaming: bool
) -> None:
    # The last member is a link whose declared span fits inside the trailer's zeros,
    # with no member header after it. The span is skipped as the link's data, but the
    # walk then ends right at its end, so the trailer checks read the span as the
    # trailer, as GNU tar and tarfile read these bytes (both list a.txt and l, exit
    # 0). Only the link's declared size is reported, not a missing marker.
    data = _tar_link_with_data(typeflag, b"", size=declared, tail=b"\0" * trailer)
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        assert [m.name for m in ar] == ["a.txt", "l"]
        assert ar.diagnostics.counts == {DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1}
        (diag,) = ar.diagnostics.retained
        # The report is made at the link, before the walk reads past the span, so
        # it names both readings.
        assert "skipped" in diag.message
        assert "end-of-archive marker" in diag.message


@pytest.mark.parametrize(
    "declared",
    [600, 64 * 1024],
    ids=["span_inside_the_trailer", "archive_ends_inside_the_span"],
)
def test_link_zero_span_in_a_large_tar_gz_does_not_rewind(declared: int) -> None:
    # A random-access walk over a .tar.gz larger than the rewind warning threshold,
    # whose last member is a link declaring `declared` bytes before a 1024-byte
    # trailer. The trailer checks run from the span's first block, which the walk
    # has read past: when the span lies inside the trailer and when the archive ends
    # inside the span. Either way the bytes are replayed from memory, not seeked
    # back to (a gzip stream with no resume point would decode again from its start
    # and report STREAM_REWIND_REDECOMPRESSES).
    chunk = 512 * 1024
    body = b""
    for i in range(4):
        info = tarfile.TarInfo(f"f{i}")
        info.size = chunk
        body += info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(chunk)
    raw = body + _tar_link_with_data(
        tarfile.SYMTYPE, b"", size=declared, tail=b"\0" * 1024
    )
    assert len(raw) > REWIND_REDECODE_WARN_BYTES
    with open_archive(
        io.BytesIO(gzip.compress(raw)), format=ArchiveFormat.TAR_GZ
    ) as ar:
        assert [m.name for m in ar.members()] == ["f0", "f1", "f2", "f3", "a.txt", "l"]
        assert ar.diagnostics.counts == {DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1}


@pytest.mark.parametrize("streaming", [False, True])
def test_link_with_size_inside_the_trailer_before_junk_is_trailing_data(
    streaming: bool,
) -> None:
    # As above with junk after the trailer: the junk is reported as after a file.
    data = _tar_link_with_data(
        tarfile.SYMTYPE, b"", size=600, tail=b"\0" * 1024 + b"junk".ljust(512, b"\0")
    )
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        assert [m.name for m in ar] == ["a.txt", "l"]
        assert ar.diagnostics.counts == {
            DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1,
            DiagnosticCode.ARCHIVE_TRAILING_DATA: 1,
        }


@pytest.mark.parametrize("streaming", [False, True])
def test_link_with_size_before_a_one_block_trailer_misses_the_marker(
    streaming: bool,
) -> None:
    # As above with a lone zero block: the marker checks then report its missing
    # second block, as after a file.
    data = _tar_link_with_data(tarfile.SYMTYPE, b"", size=4096, tail=b"\0" * 512)
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        assert [m.name for m in ar] == ["a.txt", "l"]
        assert ar.diagnostics.counts == {
            DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1,
            DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING: 1,
        }


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "payload", [b"x" * 600, b"\0" * 512 + b"x" * 88], ids=["bytes", "zero_then_bytes"]
)
def test_link_data_cut_short_is_truncation_after_the_link(
    payload: bytes, streaming: bool
) -> None:
    # The declared blocks start with data that is not all zeros and the archive ends
    # inside them: truncation, as for a file's data. The link is listed first (DR-2).
    data = _tar_link_with_data(tarfile.SYMTYPE, payload, size=8192, tail=b"")
    seen: list[str] = []
    with (
        open_archive(
            NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
            format=ArchiveFormat.TAR,
            streaming=streaming,
        ) as ar,
        pytest.raises(TruncatedError),
    ):
        for member in ar:
            seen.append(member.name)
    assert seen == ["a.txt", "l"]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("payload", "size", "tail", "names"),
    [
        (b"\0" * 1024, None, None, ["a.txt", "l", "after.txt"]),
        (b"", 64 * 1024, b"\0" * 1024, ["a.txt", "l"]),
    ],
    ids=["skipped", "ends_archive"],
)
def test_link_data_in_a_compressed_tar(
    payload: bytes,
    size: int | None,
    tail: bytes | None,
    names: list[str],
    streaming: bool,
) -> None:
    # A compressed tar has no known length, so a random-access walk finds the end of
    # the declared span by reading, not from the file size.
    data = gzip.compress(
        _tar_link_with_data(tarfile.SYMTYPE, payload, size=size, tail=tail)
    )
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR_GZ,
        streaming=streaming,
    ) as ar:
        assert [m.name for m in ar] == names
        assert ar.diagnostics.counts == {DiagnosticCode.MEMBER_LINK_DATA_IGNORED: 1}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _LINK_TYPEFLAGS)
def test_link_data_is_refused_by_strict_policy(
    typeflag: bytes, streaming: bool
) -> None:
    data = _tar_link_with_data(typeflag, b"\0" * 1024)
    with (
        pytest.raises(DiagnosticRaisedError) as excinfo,
        open_archive(
            NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
            format=ArchiveFormat.TAR,
            streaming=streaming,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as ar,
    ):
        list(ar.stream_members())
    assert excinfo.value.diagnostic.code is DiagnosticCode.MEMBER_LINK_DATA_IGNORED


def _can_symlink(tmp_path: Path) -> bool:
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to("x")
    except OSError:
        return False
    probe.unlink()
    return True


def _global_pax_chain() -> bytes:
    """A PAX global header (``g``) and its one record block: 1024 bytes that the walker
    reads as part of the next member's header chain, so a walk gets past them."""
    record = b"20 comment=archivey\n"
    assert len(record) == 20
    return _raw_tar_header("pax_global", tarfile.XGLTYPE, len(record)) + record.ljust(
        512, b"\0"
    )


def _gnu_long_name_chain() -> bytes:
    """A GNU long-name header (``L``) and its name block: 1024 bytes that must be
    followed by a member header."""
    long_name = b"after.txt\0"
    return _raw_tar_header(
        "././@LongLink", tarfile.GNUTYPE_LONGNAME, len(long_name)
    ) + long_name.ljust(512, b"\0")


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_size_spanned_by_global_header_lists_whole(
    streaming: bool,
) -> None:
    # A DIRTYPE header whose size field declares exactly the bytes a PAX global header
    # and its record occupy, then the trailer: the walk read past the whole declared
    # span before it stopped, so nothing can hide behind the directory and nothing is
    # reported. GNU tar 1.35 lists d/ and exits 0 with no warning.
    data = _tar_entry_with_data(
        tarfile.DIRTYPE,
        data=b"",
        size_field=b"%011o\0" % 1024,
        tail=_global_pax_chain() + b"\0" * 1024,
    )
    assert _stream_all(data, streaming) == [("d/", MemberType.DIRECTORY, None)]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[0].size is None
        assert dict(ar.diagnostics.counts) == {}


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_zero_block_inside_span_after_header_chain_is_reported(
    streaming: bool,
) -> None:
    # The same chain, but the directory declares more than it spans and a zero block
    # follows it inside the declared span: the blocks past the chain may still be
    # hiding members, so the directory is reported, on the member as well as on the
    # reader.
    data = _tar_entry_with_data(
        tarfile.DIRTYPE,
        data=b"",
        size_field=b"%011o\0" % 4096,
        tail=_gnu_long_name_chain() + b"\0" * 1024,
    )
    assert _stream_all(data, streaming) == [("d/", MemberType.DIRECTORY, None)]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        member = ar.members()[0]
        assert member.size is None
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]


@pytest.mark.parametrize("streaming", [False, True])
def test_dirtype_with_size_then_header_chain_then_junk_is_generic_corruption(
    streaming: bool,
) -> None:
    # A header did parse where the directory's data would begin (the long-name chain),
    # and the junk is past it, so the refusal is the ordinary rejected-header one and
    # does not claim the block where the data would begin failed to parse. GNU tar
    # exits 2 here too.
    data = _tar_entry_with_data(
        tarfile.DIRTYPE,
        data=b"",
        size_field=b"%011o\0" % 1024,
        tail=_gnu_long_name_chain() + b"j" * 512,
    )
    with raises_corruption_not_truncation(match="does not parse") as excinfo:
        _stream_all(data, streaming)
    assert "directory that declares" not in str(excinfo.value)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _OLD_STYLE_TYPEFLAGS)
def test_old_style_directory_with_data_before_lone_zero_block_lists(
    typeflag: bytes, streaming: bool
) -> None:
    # An old-style directory that declares data as the last member before a lone zero
    # block with a member behind it. Its header is a regular file's, so the walker skipped
    # its block and the listing reported it; the end check must not take the header
    # behind the zero block for one hidden by a DIRTYPE span, which would name the
    # directory. The listing stands, with the directory's data reported and the lone
    # zero block the damaged-marker warning and trailing-data report a file in its
    # place gets (GNU tar: "A lone zero block").
    after = tarfile.TarInfo("after.txt")
    after.size = 6
    tail = (
        b"\0" * 512
        + after.tobuf(format=tarfile.USTAR_FORMAT)
        + b"after\n".ljust(512, b"\0")
        + b"\0" * 1024
    )
    data = _tar_entry_with_data(typeflag, tail=tail)
    assert _stream_all(data, streaming) == [
        ("d/", MemberType.DIRECTORY, b"hello directory")
    ]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        assert ar.members()[0].size == 15
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1
        assert ar.diagnostics.counts[DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING] == 1
        assert ar.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


def test_filesystem_oserror_propagates_unwrapped(tmp_path: Path) -> None:
    # A genuine OSError (missing file) is not archive corruption: it must propagate
    # unchanged, not be reclassified as CorruptionError (error-handling spec).
    missing = tmp_path / "does-not-exist.tar"
    with pytest.raises(FileNotFoundError):
        open_archive(missing, format=ArchiveFormat.TAR)


def test_corrupt_path_open_releases_owned_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Path opens always use fileobj= with an owned fp. On open failure
    # the owned handle must be closed before re-raising — otherwise the exception
    # traceback pins the frame (and the fd) until the caller drops the exception.
    import builtins

    path = tmp_path / "bad.tar"
    path.write_bytes(b"\xff" * 1024)
    closed: list[bool] = []
    real_open = builtins.open

    def tracking_open(file: object, *args: object, **kwargs: object) -> object:
        f = real_open(file, *args, **kwargs)  # type: ignore[arg-type]
        if Path(file) == path:  # type: ignore[arg-type]
            inner_close = f.close

            def close() -> None:
                closed.append(True)
                inner_close()

            f.close = close  # type: ignore[method-assign]
        return f

    monkeypatch.setattr(builtins, "open", tracking_open)
    kept: list[Exception] = []
    with raises_corruption_not_truncation() as excinfo:
        open_archive(path, format=ArchiveFormat.TAR)
    kept.append(
        excinfo.value
    )  # keep the traceback alive, as a catch-and-continue loop would
    assert closed == [True], "owned path handle must close before open failure escapes"
    del kept


def test_corrupt_compressed_tar_surfaces_codec_corruption(tmp_path: Path) -> None:
    # A gzip-wrapped tar whose deflate body is mangled: the corruption surfaces through the
    # codec layer as a CorruptionError while scanning/reading (not a raw zlib.error).
    path = tmp_path / "bad.tar.gz"
    raw = bytearray(_build_tar("w:gz"))
    raw[len(raw) // 2] ^= 0xFF  # flip a byte inside the deflate stream
    path.write_bytes(bytes(raw))
    with raises_corruption_not_truncation(), open_archive(path) as ar:
        for _member, stream in ar.stream_members():
            if stream is not None:
                stream.read()


# ---------------------------------------------------------------------------
# Password rejection and hostile metadata robustness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("password", "recorded"),
    [("x", 1), (["a", "b"], 1), (lambda _request: "x", 0)],
    ids=["str", "list", "provider"],
)
def test_password_is_accepted_in_every_form(password: object, recorded: int) -> None:
    # TAR carries no encryption. All three password forms open alike: accepted, never
    # consulted (review O5). Only a concrete value is recorded: a provider offers a
    # password only if asked, and TAR never asks.
    from archivey.diagnostics import DiagnosticCode

    with open_archive(
        io.BytesIO(_build_tar()),
        format=ArchiveFormat.TAR,
        password=password,  # type: ignore[arg-type]
    ) as reader:
        counts = reader.diagnostics.counts
        assert counts.get(DiagnosticCode.PASSWORD_ARGUMENT_UNUSED, 0) == recorded


def test_password_provider_ok_on_unencrypted_format() -> None:
    # A PasswordProvider that is never called is not "supplying a password". Formats
    # without encryption must still open (the CLI registers a getpass provider by default).
    called = {"n": 0}

    def provider(_request: object) -> None:
        called["n"] += 1

    with open_archive(
        io.BytesIO(_build_tar()), format=ArchiveFormat.TAR, password=provider
    ) as reader:
        names = [m.name for m in reader.members()]
    assert "hello.txt" in names
    assert called["n"] == 0


def test_out_of_range_mtime_degrades_to_none() -> None:
    # A crafted PAX mtime beyond datetime's range must not sink the listing.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("weird.txt")
        info.size = 0
        info.mtime = 10**18
        t.addfile(info)
    with open_archive(io.BytesIO(buf.getvalue()), format=ArchiveFormat.TAR) as reader:
        (member,) = reader.members()
        assert member.modified is None


# ---------------------------------------------------------------------------
# Link-target name resolution (relative symlinks, hardlinks, streaming pass)
# ---------------------------------------------------------------------------


def _build_link_tar() -> bytes:
    """dir/file + a root-level decoy `file`, and links exercising target resolution."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in [
            ("file", b"ROOT"),
            ("dir/file", b"NESTED"),
            ("top.txt", b"TOP"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        rel = tarfile.TarInfo("dir/rel_link")  # -> dir/file, not the root decoy
        rel.type = tarfile.SYMTYPE
        rel.linkname = "file"
        t.addfile(rel)
        up = tarfile.TarInfo("dir/up_link")  # ../top.txt -> top.txt
        up.type = tarfile.SYMTYPE
        up.linkname = "../top.txt"
        t.addfile(up)
        absolute = tarfile.TarInfo("dir/abs_link")  # absolute: outside the archive
        absolute.type = tarfile.SYMTYPE
        absolute.linkname = "/etc/passwd"
        t.addfile(absolute)
        hard = tarfile.TarInfo("dir/hard")  # hardlink targets are archive-relative
        hard.type = tarfile.LNKTYPE
        hard.linkname = "dir/file"
        t.addfile(hard)
    return buf.getvalue()


def test_relative_symlink_resolves_against_link_directory() -> None:
    with open_archive(io.BytesIO(_build_link_tar()), format=ArchiveFormat.TAR) as ar:
        member = ar.get("dir/rel_link")
        assert member.link_target == "file"  # raw stored target is untouched
        assert member.link_target_member is not None
        assert member.link_target_member.name == "dir/file"
        assert ar.read("dir/rel_link") == b"NESTED"  # not the root-level decoy


def test_dotdot_symlink_resolves_upward() -> None:
    with open_archive(io.BytesIO(_build_link_tar()), format=ArchiveFormat.TAR) as ar:
        assert ar.get("dir/up_link").link_target_member.name == "top.txt"
        assert ar.read("dir/up_link") == b"TOP"


def test_absolute_symlink_stays_unresolved() -> None:
    from archivey.exceptions import LinkTargetNotFoundError

    with open_archive(io.BytesIO(_build_link_tar()), format=ArchiveFormat.TAR) as ar:
        member = ar.get("dir/abs_link")
        assert member.link_target == "/etc/passwd"
        assert member.link_target_member is None
        with pytest.raises(LinkTargetNotFoundError):
            ar.open(member)


def test_hardlink_target_is_archive_relative() -> None:
    with open_archive(io.BytesIO(_build_link_tar()), format=ArchiveFormat.TAR) as ar:
        assert ar.get("dir/hard").link_target_member.name == "dir/file"
        assert ar.read("dir/hard") == b"NESTED"


def test_streaming_pass_resolves_backward_links() -> None:
    # Hardlinks always point at an earlier member (the TAR model), so a single
    # streaming pass resolves them progressively; relative symlinks to earlier
    # members resolve too.
    source = NonSeekableBytesIO(_build_link_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        resolved = {
            m.name: (m.link_target_member.name if m.link_target_member else None)
            for m, _stream in ar.stream_members()
            if m.is_link
        }
    assert resolved == {
        "dir/rel_link": "dir/file",
        "dir/up_link": "top.txt",
        "dir/abs_link": None,
        "dir/hard": "dir/file",
    }


def _link_tar_bytes(specs: list[tuple[str, str, bytes | str]]) -> bytes:
    """Build a tar from (kind, name, payload) specs.

    kind: ``file`` (payload=bytes), ``sym``/``hard`` (payload=linkname).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for kind, name, payload in specs:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                info.mode = 0o644
                t.addfile(info, io.BytesIO(payload))
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                t.addfile(info)
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                t.addfile(info)
    return buf.getvalue()


_DUP_HARDLINK_TAR = _link_tar_bytes(
    [
        ("file", "A.txt", b"content1"),
        ("hard", "L.txt", "A.txt"),
        ("file", "A.txt", b"content2"),
    ]
)


def test_hardlink_duplicate_name_positional_random_access() -> None:
    with open_archive(io.BytesIO(_DUP_HARDLINK_TAR), format=ArchiveFormat.TAR) as ar:
        link = ar.get("L.txt")
        assert link.link_target_member is not None
        assert link.link_target_member.name == "A.txt"
        assert ar.read(link.link_target_member) == b"content1"
        assert ar.read("L.txt") == b"content1"


def test_hardlink_duplicate_name_positional_streaming() -> None:
    source = NonSeekableBytesIO(_DUP_HARDLINK_TAR)
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        links = {
            m.name: m.link_target_member
            for m, _ in ar.stream_members()
            if m.type == MemberType.HARDLINK
        }
    assert links["L.txt"] is not None
    assert links["L.txt"].name == "A.txt"


def test_symlink_duplicate_name_last_wins_random_access() -> None:
    data = _link_tar_bytes(
        [
            ("file", "A.txt", b"content1"),
            ("sym", "S.txt", "A.txt"),
            ("file", "A.txt", b"content2"),
        ]
    )
    with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
        link = ar.get("S.txt")
        assert link.link_target_member is not None
        assert link.link_target_member.name == "A.txt"
        assert ar.read(link.link_target_member) == b"content2"
        assert ar.read("S.txt") == b"content2"


# ---------------------------------------------------------------------------
# members_report(), post-pass cache, one-pass-only streaming
# ---------------------------------------------------------------------------


def _build_forward_symlink_tar() -> bytes:
    """Symlink appears before its target in archive order."""
    return _link_tar_bytes(
        [
            ("sym", "forward_link", "target.txt"),
            ("file", "target.txt", b"TARGET"),
        ]
    )


def test_streaming_members_report_resolves_forward_symlink() -> None:
    source = NonSeekableBytesIO(_build_forward_symlink_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        report = ar.members_report()
    assert report.error is None
    members = report.members
    link = next(m for m in members if m.name == "forward_link")
    assert link.link_target_member is not None
    assert link.link_target_member.name == "target.txt"

    with open_archive(
        io.BytesIO(_build_forward_symlink_tar()), format=ArchiveFormat.TAR
    ) as ar:
        expected = ar.get("forward_link")
    assert link.link_target_member.name == expected.link_target_member.name


def test_streaming_iter_materializes_resolved_cache() -> None:
    source = NonSeekableBytesIO(_build_forward_symlink_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        collected: list = []
        for member in ar:
            if member.name == "forward_link":
                collected.append(member)
                assert member.link_target_member is None
        report = ar.members_report_if_available()
        assert report is not None
        link = next(m for m in report if m.name == "forward_link")
        assert link.link_target_member is not None
        assert link.link_target_member.name == "target.txt"
        assert collected[0].link_target_member.name == "target.txt"


def test_streaming_stream_members_materializes_resolved_cache() -> None:
    source = NonSeekableBytesIO(_build_forward_symlink_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        collected: list = []
        for member, _stream in ar.stream_members():
            if member.name == "forward_link":
                collected.append(member)
        report = ar.members_report_if_available()
        assert report is not None
        link = next(m for m in report if m.name == "forward_link")
        assert link.link_target_member is not None
        assert collected[0].link_target_member.name == "target.txt"


def test_members_report_finishes_interrupted_pass(tmp_path: Path) -> None:
    source = NonSeekableBytesIO(_build_forward_symlink_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        for member in ar:
            if member.name == "forward_link":
                break
        report = ar.members_report()
        assert report.error is None
        members = report.members
        assert [m.name for m in members] == ["forward_link", "target.txt"]
        link = next(m for m in members if m.name == "forward_link")
        assert link.link_target_member is not None
        assert link.link_target_member.name == "target.txt"
        with pytest.raises(ArchiveyUsageError):
            list(ar)
        with pytest.raises(ArchiveyUsageError):
            list(ar.stream_members())
        with pytest.raises(ArchiveyUsageError):
            ar.extract_all(tmp_path)


def test_abandoned_partial_pass_leaves_get_members_none() -> None:
    source = NonSeekableBytesIO(_build_forward_symlink_tar())
    with open_archive(source, format=ArchiveFormat.TAR, streaming=True) as ar:
        for member in ar:
            if member.name == "forward_link":
                break
        assert ar.members_report_if_available() is None


def test_streaming_second_pass_raises_tar_and_zip(
    plain_tar: Path, tmp_path: Path
) -> None:
    zip_path = tmp_path / "second.zip"
    import zipfile

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("hello.txt", b"hello world")
    with open_archive(plain_tar, streaming=True) as ar:
        list(ar)
        with pytest.raises(ArchiveyUsageError):
            list(ar)
        with pytest.raises(ArchiveyUsageError):
            list(ar.stream_members())
    with open_archive(zip_path, streaming=True) as ar:
        list(ar)
        with pytest.raises(ArchiveyUsageError):
            list(ar)


def test_members_report_random_access_parity(plain_tar: Path, tmp_path: Path) -> None:
    import zipfile

    zip_path = tmp_path / "scan.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("hello.txt", b"hello world")
    simple_dir = tmp_path / "dirscan"
    simple_dir.mkdir()
    (simple_dir / "a.txt").write_bytes(b"x")
    for source in (plain_tar, zip_path, simple_dir):
        with open_archive(source) as ar:
            assert list(ar.members_report().members) == ar.members()
            assert [m.name for m in ar] == [m.name for m in ar.members()]


def test_members_report_before_pass_consumes_streaming_reader(
    plain_tar: Path, tmp_path: Path
) -> None:
    import zipfile

    zip_path = tmp_path / "consume.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("hello.txt", b"hello world")
    simple_dir = tmp_path / "dirconsume"
    simple_dir.mkdir()
    (simple_dir / "a.txt").write_bytes(b"x")
    for source in (plain_tar, zip_path, simple_dir):
        with open_archive(source, streaming=True) as ar:
            names = {m.name for m in ar.members_report()}
            assert len(names) > 0
            with pytest.raises(ArchiveyUsageError):
                list(ar.stream_members())


def test_link_cycle_raises_read_error() -> None:
    data = _link_tar_bytes(
        [
            ("sym", "a", "b"),
            ("sym", "b", "a"),
        ]
    )
    with (
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
        pytest.raises(ReadError, match="cycle"),
    ):
        ar.read("a")


def test_chain_through_same_named_members_not_false_cycle() -> None:
    """Member-id cycle tracking must not false-positive on distinct same-named members."""
    from archivey.cost import AccessCost, ListingCost, StreamCapability
    from archivey.internal.base_reader import BaseArchiveReader
    from archivey.types import ArchiveInfo, ArchiveMember

    class _Reader(BaseArchiveReader):
        def __init__(
            self, members: list[ArchiveMember], payloads: dict[str, bytes]
        ) -> None:
            super().__init__(ArchiveFormat.TAR, streaming=False, archive_name=None)
            self._payloads = payloads
            self._listed = members
            for m in members:
                self._index_member_name(m)
            self._publish_materialized(error=None)

        def _iter_members(self):
            materialized = self._materialized
            return iter(materialized.report.members if materialized is not None else ())

        def _open_member(self, member: ArchiveMember) -> BinaryIO:
            return io.BytesIO(self._payloads[member.name])

        def _get_archive_info(self) -> ArchiveInfo:
            return ArchiveInfo(
                format=ArchiveFormat.TAR,
                cost=AccessCost(
                    listing=ListingCost.FREE,
                    random_access=StreamCapability.SUPPORTED,
                ),
            )

        def _close_archive(self) -> None:
            return None

    # Hop-by-hop chain start → dup(sym) → tail → dup(file); two distinct "dup.txt" members.
    first = ArchiveMember(name="dup.txt", type=MemberType.SYMLINK, link_target="tail")
    second = ArchiveMember(name="dup.txt", type=MemberType.FILE)
    tail = ArchiveMember(name="tail", type=MemberType.SYMLINK, link_target="dup.txt")
    start = ArchiveMember(name="start", type=MemberType.SYMLINK, link_target="dup.txt")
    for idx, m in enumerate((first, second, tail, start)):
        m._member_id = idx
        m._archive_id = "test"
    first.link_target_member = tail
    tail.link_target_member = second
    start.link_target_member = first
    reader = _Reader(
        [first, second, tail, start],
        {"dup.txt": b"payload", "tail": b"", "start": b""},
    )
    with reader._open_with_link_follow(start, set()) as stream:
        assert stream.read() == b"payload"


# ---------------------------------------------------------------------------
# A failed streaming pass must not publish a partial member list (deep N1)
# ---------------------------------------------------------------------------


def test_error_mid_streaming_pass_poisons_members_report() -> None:
    """End-to-end N1 repro: a RAISE-disposition diagnostic fires mid-pass; the caller
    catches it; ``members_report()`` must then fail loud instead of silently returning
    the two-member prefix as the complete resolved list."""
    from archivey.diagnostics import (
        DiagnosticCode,
        DiagnosticPolicy,
    )
    from archivey.exceptions import DiagnosticRaisedError

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("a", "b", "c", "d"):
            data = b"x" * 100
            info = tarfile.TarInfo(name + ".bin")
            info.size = len(data)
            if name == "c":
                info.mtime = 2**62  # out of range -> MEMBER_TIMESTAMP_INVALID
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)

    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.MEMBER_TIMESTAMP_INVALID}
        )
    )
    with open_archive(
        buf, streaming=True, format=ArchiveFormat.TAR, config=config
    ) as reader:
        seen: list[str] = []
        with pytest.raises(DiagnosticRaisedError):
            for member in reader:
                seen.append(member.name)
        assert seen == ["a.bin", "b.bin"]
        with pytest.raises(ReadError, match="previously failed"):
            reader.members_report()
        assert reader.members_report_if_available() is None


# ---------------------------------------------------------------------------
# Header-sized allocations
# ---------------------------------------------------------------------------


def _tar_with_oversized_metadata_header(typeflag: bytes, declared: int) -> bytes:
    """A tar whose extended-header block declares ``declared`` bytes it does not have.

    ``typeflag`` ``x`` is a PAX extended header, ``L`` a GNU ``././@LongLink``. Both
    are written by ``tarfile`` itself for a name too long for ustar; only the 12-byte
    octal size field and the header checksum are rewritten.
    """
    fmt = tarfile.PAX_FORMAT if typeflag == b"x" else tarfile.GNU_FORMAT
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        info = tarfile.TarInfo("a" * 200)
        info.size = 0
        t.addfile(info)
    data = bytearray(buf.getvalue())
    assert data[156:157] == typeflag
    data[124:136] = b"%011o\0" % declared
    data[148:156] = b" " * 8  # the checksum field reads as spaces while summing
    data[148:156] = b"%06o\0 " % sum(data[:512])
    return bytes(data)


@pytest.mark.parametrize("typeflag", [b"x", b"L"])
@pytest.mark.parametrize("length", ["fact", "hint", "unknown"])
def test_extended_header_size_does_not_drive_the_allocation(
    typeflag: bytes, length: str
) -> None:
    """A 10 KB archive must not make the reader ask its source for 6 GiB.

    stdlib ``tarfile`` reads a PAX extended header or a GNU long name with a single
    ``read`` sized from the header's own 12-byte octal field — attacker-chosen, and
    allocated in full before the short read reveals the archive is tiny. Asking for
    the bytes is the observable: whether the allocation then succeeds depends on the
    machine, so it is the request that is pinned, not a ``MemoryError``.

    The three parameters are the three things the source can know about its length,
    and they take different branches of the bound. ``fact`` is a ``BytesIO``, whose
    length the boundary reads from its buffer, so the read is clamped to exactly what
    is left; it fails against an unbounded ``read(size)``, which passes 6 442 450 944
    straight through. ``hint`` advertises the fsspec ``size`` attribute, a caller's
    unverified claim, which must not clamp (an understating hint would truncate a
    legitimate read), so the read is stepped. ``unknown`` has neither, which is what
    every compressed source and every ordinary caller-supplied file-like looks like;
    it is stepped too, and fails against treating an unknown length as an unlimited
    one (``remaining is None`` forwarding ``size`` down), which passes the same
    6 442 450 944. A bound tested only where the length is known is untested on the
    branch most sources actually take.
    """
    declared = 6 * 1024**3
    data = _tar_with_oversized_metadata_header(typeflag, declared)
    source: FactSizedReadRecorder | ReadSizeRecorder = (
        FactSizedReadRecorder(data)
        if length == "fact"
        else ReadSizeRecorder(data, advertise_size=length == "hint")
    )

    # Without a metadata cap: with one, the declared size is refused before any read
    # (``test_extended_header_over_the_metadata_cap_is_refused_unread``), and the read
    # bound is what this pins.
    config = ArchiveyConfig(listing_limits=ListingLimits.UNLIMITED)
    # The archive ends inside the header's data, as it is cut short anywhere else.
    with (
        pytest.raises(TruncatedError),
        open_archive(source, format=ArchiveFormat.TAR, config=config) as reader,
    ):
        reader.members()

    assert source.requested, "the source was never read"
    # A raw source sits under a ``BufferedReader``, whose refill size is a constant of
    # the runtime (``io.DEFAULT_BUFFER_SIZE``: 8 KiB through 3.13, 128 KiB from 3.14)
    # and has nothing to do with the archive. So the bound is one refill or, whichever
    # is larger, the archive when its length is a fact and the step when it is not;
    # what every case pins is that no read scales with ``declared``, which is six
    # gigabytes.
    reach = len(data) if length == "fact" else DEFAULT_UNKNOWN_LENGTH_READ_STEP
    bound = max(reach, io.DEFAULT_BUFFER_SIZE)
    assert max(source.requested) <= bound, (
        f"asked the source for {max(source.requested)} bytes "
        f"from a {len(data)}-byte archive"
    )


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", [b"x", b"L"])
def test_extended_header_over_the_metadata_cap_is_refused_unread(
    typeflag: bytes, streaming: bool
) -> None:
    """An extended header declaring more than ``max_metadata_bytes`` is refused from
    its size field, before tarfile reads its data whole: the read would cost what
    the header declares, not what the cap allows."""
    data = _tar_with_oversized_metadata_header(typeflag, 6 * 1024**3)
    source = ReadSizeRecorder(data, advertise_size=False)
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        open_archive(source, format=ArchiveFormat.TAR, streaming=streaming),
    ):
        pass
    assert max(source.requested) <= max(
        DEFAULT_UNKNOWN_LENGTH_READ_STEP, io.DEFAULT_BUFFER_SIZE, 10240
    )


def test_plain_tar_member_past_the_walk_buffer_is_one_source_read() -> None:
    """A plain-tar member larger than the walk buffer is one source read of its size.

    The file length is a fact, so the walker asks for the member once, and a read
    larger than the walk buffer rewinds the prefetched tail instead of joining a
    second read onto it. Leaving ``TarWalker.end`` unset reads the member in
    ``READ_STEP`` pieces, so this size is absent from the recorded requests.
    Turning ``rewind_oversize`` off splits the prefetched tail from the rest, so
    the one request of this size is absent there too.
    """
    payload = b"m" * (_WALK_BUFFER + READ_STEP + 100)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("big.bin")
        info.size = len(payload)
        info.mtime = 1_700_000_000
        tar.addfile(info, io.BytesIO(payload))
    source = FactSizedReadRecorder(buf.getvalue())

    with open_archive(source, format=ArchiveFormat.TAR) as archive:
        got = b"".join(
            stream.read()
            for member, stream in archive.stream_members()
            if member.is_file
        )

    assert got == payload
    assert source.requested.count(len(payload)) == 1


def test_a_member_larger_than_the_read_step_still_reads_whole(tmp_path: Path) -> None:
    """The bound must not cut a legitimate read short.

    A member past the read step is the case where a read stops being handed straight
    down, so it is the one that would show a truncation or a stitching bug.
    Compressed, because that is the path with no cheap length and therefore the one
    that takes the stepped route.
    """
    step = DEFAULT_UNKNOWN_LENGTH_READ_STEP
    payload = bytes(range(256)) * ((step // 256) + 1024)
    assert len(payload) > step

    path = tmp_path / "big.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("big.bin")
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))

    with open_archive(path) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            assert stream.read() == payload


def _one_member_tar(
    name: str,
    codec: str,
    fmt: int,
    *,
    linkname: str | None = None,
    owner: str = "",
) -> bytes:
    """A one-member TAR whose header strings are stored in ``codec``: a regular file,
    or a symlink to ``linkname``, with ``owner`` as both ``uname`` and ``gname``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt, encoding=codec) as t:
        info = tarfile.TarInfo(name)
        info.uname = info.gname = owner
        if linkname is None:
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        else:
            info.type = tarfile.SYMTYPE
            info.linkname = linkname
            t.addfile(info)
    return buf.getvalue()


@pytest.mark.parametrize("encoding", [None, "utf-8", "latin-1", "ascii"])
def test_pax_raw_name_is_the_stored_utf8_whatever_the_encoding(
    encoding: str | None,
) -> None:
    """A PAX ``path`` record is UTF-8 whatever ``encoding=`` says; re-encoding it with
    the caller's codec either crashed the listing or fabricated bytes."""
    for name in ("日本語.txt", "café.txt"):
        data = _one_member_tar(name, "utf-8", tarfile.PAX_FORMAT)
        with open_archive(io.BytesIO(data), encoding=encoding) as ar:
            (member,) = ar.members()
            assert member.name == name
            assert member.raw_name == name.encode("utf-8")


def test_ustar_raw_name_follows_the_archive_encoding() -> None:
    data = _one_member_tar("café.txt", "latin-1", tarfile.USTAR_FORMAT)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "café.txt"
        assert member.raw_name == b"caf\xe9.txt"


# tarfile's own default is TarFile.encoding (= tarfile.ENCODING, the filesystem
# encoding on POSIX). Setting it to Latin-1 stands in for a process under a Latin-1
# locale, where every byte decodes, so none of the tests below can pass by accident.
_NON_UTF8_LOCALE = mock.patch.object(tarfile.TarFile, "encoding", "latin-1")


@pytest.mark.parametrize(
    "fmt",
    [
        pytest.param(tarfile.USTAR_FORMAT, id="ustar"),
        # A name over 100 bytes goes into a GNU long-name record.
        pytest.param(tarfile.GNU_FORMAT, id="gnu-longname"),
    ],
)
def test_utf8_name_decodes_as_utf8_under_a_non_utf8_locale(fmt: int) -> None:
    name = "café-" + "x" * (120 if fmt == tarfile.GNU_FORMAT else 0) + ".txt"
    data = _one_member_tar(name, "utf-8", fmt)
    assert (b"././@LongLink" in data) == (fmt == tarfile.GNU_FORMAT)
    with _NON_UTF8_LOCALE, open_archive(io.BytesIO(data)) as ar:
        (member,) = ar.members()
        assert member.name == name
        assert member.raw_name == name.encode("utf-8")


def test_utf8_link_target_and_owner_decode_as_utf8_under_a_non_utf8_locale() -> None:
    target = "цель/café.txt"
    data = _one_member_tar(
        "link", "utf-8", tarfile.USTAR_FORMAT, linkname=target, owner="josé"
    )
    with _NON_UTF8_LOCALE, open_archive(io.BytesIO(data)) as ar:
        (member,) = ar.members()
        assert member.link_target == target
        assert member.uname == "josé"
        assert member.gname == "josé"


def test_invalid_utf8_name_is_surrogate_escaped_under_a_non_utf8_locale() -> None:
    data = _one_member_tar("café.txt", "latin-1", tarfile.USTAR_FORMAT)
    with _NON_UTF8_LOCALE, open_archive(io.BytesIO(data)) as ar:
        (member,) = ar.members()
        assert member.name == "caf\udce9.txt"
        assert member.raw_name == b"caf\xe9.txt"


@pytest.mark.parametrize(
    "fmt",
    [
        pytest.param(tarfile.USTAR_FORMAT, id="ustar"),
        pytest.param(tarfile.GNU_FORMAT, id="gnu-longname"),
    ],
)
def test_utf8_header_name_wins_over_the_caller_encoding(fmt: int) -> None:
    """``encoding=`` applies only to bytes that are not valid UTF-8, as in every
    other format: the UTF-8 bytes ``c3 a9`` stay ``é``, not ``Ã©``."""
    name = "café-" + "x" * (120 if fmt == tarfile.GNU_FORMAT else 0) + ".txt"
    data = _one_member_tar(name, "utf-8", fmt)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == name
        assert member.raw_name == name.encode("utf-8")
    # The choice is reported, as ZIP reports it, naming the codec passed over.
    (diag,) = [
        d
        for d in member.diagnostics
        if d.code == DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
    ]
    assert diag.context.inferred_encoding == "utf-8"
    assert diag.context.declared_encoding == "latin-1"


def test_utf8_link_target_and_owner_win_over_the_caller_encoding() -> None:
    target = "цель/café.txt"
    data = _one_member_tar(
        "link", "utf-8", tarfile.USTAR_FORMAT, linkname=target, owner="josé"
    )
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.link_target == target
        assert member.uname == "josé"
        assert member.gname == "josé"


def test_caller_encoding_decodes_header_fields_that_are_not_utf8() -> None:
    data = _one_member_tar(
        "café.txt", "latin-1", tarfile.USTAR_FORMAT, linkname="à.txt", owner="josé"
    )
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "café.txt"
        assert member.raw_name == b"caf\xe9.txt"
        assert member.link_target == "à.txt"
        assert member.uname == "josé"
        # encoding= decoded it: nothing was inferred.
        counts = ar.diagnostics.counts
    assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


def test_mixed_header_names_each_decode_by_their_own_bytes() -> None:
    """One archive with a UTF-8 name and a Latin-1 name: ``encoding="latin-1"``
    fixes the Latin-1 one and leaves the UTF-8 one alone."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for raw in ("é-utf8.txt".encode(), "é-latin1.txt".encode("latin-1")):
            # tarfile writes str names; surrogateescape stores the exact bytes.
            info = tarfile.TarInfo(raw.decode("utf-8", "surrogateescape"))
            info.size = 0
            t.addfile(info)
    with open_archive(io.BytesIO(buf.getvalue()), encoding="latin-1") as ar:
        assert [m.name for m in ar.members()] == ["é-utf8.txt", "é-latin1.txt"]


def _binary_pax_tar(*, global_binary: bool) -> bytes:
    """A PAX archive whose member block says ``hdrcharset=BINARY`` and whose ``path``
    record holds the UTF-8 bytes of ``caé.txt``, optionally after a global header that
    says ``hdrcharset=BINARY`` too."""
    buf = io.BytesIO()
    with tarfile.open(
        fileobj=buf,
        mode="w",
        format=tarfile.PAX_FORMAT,
        encoding="utf-8",
        errors="surrogateescape",
        pax_headers={"hdrcharset": "BINARY"} if global_binary else None,
    ) as t:
        # A name UTF-8 cannot encode makes tarfile write hdrcharset=BINARY.
        info = tarfile.TarInfo("caf\udce9.txt")
        info.size = 0
        t.addfile(info)
    data = buf.getvalue()
    assert data.count(b"hdrcharset=BINARY") == (2 if global_binary else 1)
    # Same length, so the record's length prefix stays right: "caé" in UTF-8.
    return data.replace(b"caf\xe9.txt", b"ca\xc3\xa9.txt")


def test_binary_pax_path_that_is_valid_utf8_wins_over_the_caller_encoding() -> None:
    """``hdrcharset=BINARY`` declares no encoding, so the record decodes as a ustar
    name does: valid UTF-8 is UTF-8."""
    data = _binary_pax_tar(global_binary=False)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "caé.txt"
        assert member.raw_name == b"ca\xc3\xa9.txt"


def test_pax_member_repeating_a_global_binary_charset_reads_as_binary() -> None:
    """A member block that repeats the global ``hdrcharset=BINARY`` declares no
    encoding, like one that says it alone: valid UTF-8 wins over ``encoding=``, and
    ``raw_name`` is the stored bytes."""
    data = _binary_pax_tar(global_binary=True)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "caé.txt"
        assert member.raw_name == b"ca\xc3\xa9.txt"


def _pax_tar_with_non_utf8_path(raw: bytes) -> bytes:
    """A PAX archive whose ``path`` record holds ``raw``, which is not UTF-8."""
    data = bytearray(_one_member_tar("café.txt", "utf-8", tarfile.PAX_FORMAT))
    # Swap the PAX path value for non-UTF-8 bytes of the same length.
    stored = "path=café.txt\n".encode()
    at = data.index(stored)
    data[at + 5 : at + len(stored) - 1] = raw
    return bytes(data)


def test_pax_raw_name_with_undecodable_bytes_round_trips() -> None:
    """Bytes that are not UTF-8 fall back to the archive codec with surrogateescape;
    the surrogates send the name back through that codec, recovering the bytes. The
    fallback codec is the UTF-8 default, not the locale's."""
    raw = b"caf\xe9\xe9.txt"
    with (
        _NON_UTF8_LOCALE,
        open_archive(io.BytesIO(_pax_tar_with_non_utf8_path(raw))) as ar,
    ):
        (member,) = ar.members()
        assert member.name == "caf\udce9\udce9.txt"
        assert member.raw_name == raw


def test_pax_path_that_is_not_utf8_falls_back_to_the_caller_encoding() -> None:
    raw = b"caf\xe9\xe9.txt"
    data = _pax_tar_with_non_utf8_path(raw)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "caféé.txt"
        # raw_name is not asserted: the UTF-8 bytes of "caféé.txt" decode to the same
        # name, so which bytes were stored cannot be recovered from it.


@pytest.mark.parametrize("fmt", [tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT])
@pytest.mark.parametrize("encoding", ["cp037", "utf-16", "utf-32", "utf-7", "idna"])
def test_ascii_header_fields_ignore_an_encoding_that_reads_ascii_differently(
    fmt: int, encoding: str
) -> None:
    """ASCII is valid UTF-8, so ``encoding=`` never applies to it. Decoding with the
    codec first turned ``abc`` into ``/ÂÄ`` under EBCDIC ``cp037`` and raised
    ``UnicodeDecodeError`` under ``utf-16`` and ``utf-32``, before the listing began."""
    data = _one_member_tar("abc", "ascii", fmt, linkname="a+b", owner="root")
    with open_archive(io.BytesIO(data), encoding=encoding) as ar:
        (member,) = ar.members()
        assert member.name == "abc"
        assert member.link_target == "a+b"
        assert member.uname == member.gname == "root"
        assert not member.diagnostics


# CPython's utf-7 refuses a "+" shift that does not decode; PyPy's decodes it.
_UTF7_REFUSES = pytest.param(
    "utf-7",
    marks=pytest.mark.skipif(
        not CPYTHON,
        reason="PyPy's utf-7 codec decodes a bad '+' shift instead of refusing it",
    ),
)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", _UTF7_REFUSES, "idna"])
def test_header_name_the_encoding_cannot_decode_falls_back_to_escapes(
    encoding: str,
) -> None:
    """A codec that fails on bytes that are not UTF-8 (``utf-16`` on an odd byte
    count, ``utf-32`` on a code point out of range, ``utf-7`` on a bad ``+`` shift,
    ``idna``, which has no ``surrogateescape``) decodes the name as with no
    ``encoding=``, as ZIP, RAR and ISO do, rather than failing the open."""
    data = _one_member_tar("a+caf\xe9.tx", "latin-1", tarfile.GNU_FORMAT)
    with open_archive(io.BytesIO(data), encoding=encoding) as ar:
        (member,) = ar.members()
        assert member.name == "a+caf\udce9.tx"
        assert member.raw_name == b"a+caf\xe9.tx"


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", _UTF7_REFUSES, "idna"])
def test_pax_value_the_encoding_cannot_decode_falls_back_to_escapes(
    encoding: str,
) -> None:
    # Each codec fails on these bytes; the "+" is what makes utf-7 fail.
    raw = b"a+f\xe9\xe9.txt"
    data = _pax_tar_with_non_utf8_path(raw)
    with open_archive(io.BytesIO(data), encoding=encoding) as ar:
        (member,) = ar.members()
        assert member.name == "a+f\udce9\udce9.txt"
        assert member.extra["tar.pax_headers"]["path"] == "a+f\udce9\udce9.txt"


@pytest.mark.parametrize("fmt", [tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT])
@pytest.mark.parametrize("encoding", ["utf-16", "idna"])
def test_utf8_name_under_an_encoding_that_cannot_decode_it(
    fmt: int, encoding: str
) -> None:
    """A valid UTF-8 name is UTF-8, and the check whether ``encoding=`` would have
    read it differently must not fail when that codec cannot decode the bytes at all.
    Such a codec would not have named the member, so nothing is reported."""
    data = _one_member_tar("café.txt", "utf-8", fmt)
    with open_archive(io.BytesIO(data), encoding=encoding) as ar:
        (member,) = ar.members()
        assert member.name == "café.txt"
        assert not member.diagnostics


def test_binary_pax_record_text_matches_the_member_name() -> None:
    """Under ``hdrcharset=BINARY``, ``extra["tar.pax_headers"]`` decodes a valid UTF-8
    ``path`` as the name does, rather than with ``encoding=``."""
    data = _binary_pax_tar(global_binary=False)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == "caé.txt"
        assert member.extra["tar.pax_headers"]["path"] == "caé.txt"


@pytest.mark.parametrize("streaming", [False, True])
def test_close_releases_the_codec_stream_when_its_buffer_close_raises(
    tmp_path: Path, streaming: bool
) -> None:
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("a")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    ar: Any = open_archive(path, streaming=streaming)
    codec = ar._owned_codec_stream
    # Streaming buffers the codec stream; random access buffers the walk's view.
    buffer = ar._owned_stream if streaming else ar._walker_view
    with (
        mock.patch.object(buffer, "close", side_effect=OSError("boom")),
        pytest.raises(OSError),
    ):
        ar.close()
    assert codec.closed


def test_a_retried_listing_keeps_one_walk_view() -> None:
    """A random-access listing that fails and is retried starts a new walk; the last
    walk's buffered view is closed, not kept until the reader closes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i in range(20):
            tar.addfile(tarfile.TarInfo(f"m{i}"), io.BytesIO())
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    ar: Any = open_archive(io.BytesIO(buf.getvalue()), config=config)
    with ar:
        views = []
        for _ in range(3):
            with pytest.raises(ResourceLimitError):
                ar.members()
            views.append(ar._walker_view)
        assert len({id(view) for view in views}) == 3
        assert [view.closed for view in views] == [True, True, False]


def test_a_concurrent_reader_closes_its_streams_under_the_handle_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as t:
        t.addfile(tarfile.TarInfo("a"), io.BytesIO())
    ar: Any = open_archive(path, concurrent_operations=True)
    held = []
    release = ar._release_owned_stream

    def recorded() -> None:
        held.append(ar._handle_lock.locked())
        release()

    ar._release_owned_stream = recorded
    ar.close()
    assert held == [True]


@pytest.mark.parametrize("suffix", ["", ".gz"])
def test_a_member_stream_seeks_past_its_end_like_a_file(
    tmp_path: Path, suffix: str
) -> None:
    path = tmp_path / f"a.tar{suffix}"
    with tarfile.open(path, f"w:{suffix[1:]}") as t:
        info = tarfile.TarInfo("a")
        info.size = 3
        t.addfile(info, io.BytesIO(b"abc"))
    with open_archive(path, seekable_members=True) as ar, ar.open("a") as stream:
        assert stream.seek(10) == 10
        assert stream.read() == b""
        assert stream.seek(1) == 1
        assert stream.read() == b"bc"
        assert stream.tell() == 3


def test_small_reads_of_a_compressed_member_are_buffered(tmp_path: Path) -> None:
    """Line iteration over a .tar.gz member reads the decoded stream in buffer-sized
    pieces, not once per line."""
    path = tmp_path / "a.tar.gz"
    data = b"x" * 79 + b"\n"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("lines")
        info.size = len(data) * 1000
        t.addfile(info, io.BytesIO(data * 1000))
    ar: Any = open_archive(path)
    with ar, mock.patch.object(ar._stream, "read", wraps=ar._stream.read) as read:
        with ar.open("lines") as stream:
            assert sum(1 for _ in stream) == 1000
        assert read.call_count < 30


@pytest.mark.parametrize(
    ("kept", "chunk"),
    [
        (2_000, 100),
        (2_000, 1024),
        (10_000, 100),
        (10_000, 1024),
        (100_000, 128 * 1024),  # past the walk's 64 KiB read step
        (100_000, 1024 * 1024),  # extraction's copy chunk
    ],
)
def test_a_cut_compressed_member_delivers_its_prefix_in_both_modes(
    tmp_path: Path, kept: int, chunk: int
) -> None:
    """Small reads of a cut .tar.gz member deliver the recoverable prefix before the
    TruncatedError, the same in streaming, in a random-access pass and through
    ``open``: each buffer asks the decoder once per read, so the decoder's deferred
    error does not drop the prefix."""
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("a")
        info.size = 200_000
        t.addfile(info, io.BytesIO(random.Random(0).randbytes(200_000)))
    path.write_bytes(path.read_bytes()[:kept])

    def drain(stream: BinaryIO) -> int:
        got = 0
        with pytest.raises(TruncatedError):
            while block := stream.read(chunk):
                got += len(block)
        return got

    with open_archive(path, streaming=True) as ar:
        members = ar.stream_members()
        _, stream = next(members)
        assert stream is not None
        in_streaming = drain(stream)
        members.close()
    with open_archive(path) as ar:
        members = ar.stream_members()
        _, stream = next(members)
        assert stream is not None
        in_a_random_access_pass = drain(stream)
        members.close()
    with open_archive(path) as ar, ar.open("a") as stream:
        in_random_access = drain(stream)
    assert in_streaming > 0
    assert in_a_random_access_pass == in_streaming
    assert in_random_access == in_streaming


@pytest.mark.parametrize("suffix", [".tar", ".tar.gz"])
@pytest.mark.parametrize("size", [-1, None])
def test_a_whole_read_of_a_cut_member_raises_with_nothing_in_every_mode(
    tmp_path: Path, suffix: str, size: int | None
) -> None:
    """``read()`` with no size asks for the whole member, so a cut member raises and
    returns nothing, the same in streaming, in a random-access pass and through
    ``open``. Sized reads deliver the prefix first (the test above)."""
    path = tmp_path / f"a{suffix}"
    with tarfile.open(path, "w:gz" if suffix == ".tar.gz" else "w") as t:
        info = tarfile.TarInfo("a")
        info.size = 200_000
        t.addfile(info, io.BytesIO(random.Random(0).randbytes(200_000)))
    path.write_bytes(path.read_bytes()[:100_000])

    def read_whole(stream: BinaryIO) -> None:
        with pytest.raises(TruncatedError):
            stream.read(size)

    with open_archive(path, streaming=True) as ar:
        members = ar.stream_members()
        _, stream = next(members)
        assert stream is not None
        read_whole(stream)
        members.close()
    with open_archive(path) as ar:
        members = ar.stream_members()
        _, stream = next(members)
        assert stream is not None
        read_whole(stream)
        members.close()
    with open_archive(path) as ar, ar.open("a") as stream:
        read_whole(stream)


def test_a_member_keeps_no_parsed_pax_records() -> None:
    """The member's PAX records live on as ``extra["tar.pax_headers"]``; the parsed
    entry that carried them is dropped once the member is built, and the member keeps
    only its data span."""
    from archivey.internal.backends.tar_parser import TarSpan

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        info = tarfile.TarInfo("a")
        info.pax_headers = {"comment": "c" * 100}
        t.addfile(info, io.BytesIO())
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        (member,) = ar.members()
        assert member.extra["tar.pax_headers"]["comment"] == "c" * 100
        assert type(member._raw) is TarSpan


def test_global_pax_path_wins_over_a_gnu_long_name() -> None:
    """A global ``path`` applies to every member after it, over a GNU long name, as
    GNU tar 1.35 lists it (``tar tvf`` shows ``g``)."""
    glob = io.BytesIO()
    with tarfile.open(
        fileobj=glob, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"path": "g"}
    ):
        pass
    long_name = "é" * 120  # past ustar's 100 bytes: GNU writes a long-name block
    gnu = io.BytesIO()
    with tarfile.open(
        fileobj=gnu, mode="w", format=tarfile.GNU_FORMAT, encoding="latin-1"
    ) as t:
        info = tarfile.TarInfo(long_name)
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    # The global header's blocks, then the GNU member and its end-of-archive blocks.
    data = glob.getvalue().rstrip(b"\0")
    data += b"\0" * (-len(data) % 512) + gnu.getvalue()
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert (member.name, member.raw_name) == ("g", b"g")


def _tar_with_mtime(path: Path, mtime: float, tar_format: int) -> Path:
    with tarfile.open(path, "w", format=tar_format) as tf:
        info = tarfile.TarInfo("old.txt")
        info.mtime = mtime  # type: ignore[assignment]  # tarfile accepts a float
        tf.addfile(info, io.BytesIO(b""))
    return path


@pytest.mark.parametrize(
    ("tar_format", "mtime", "expected"),
    [
        # PAX writes a negative mtime as a "mtime" record; GNU as a base-256 field.
        pytest.param(
            tarfile.PAX_FORMAT,
            -86_400.5,
            datetime(1969, 12, 30, 23, 59, 59, 500_000, tzinfo=UTC),
            id="pax",
        ),
        pytest.param(
            tarfile.GNU_FORMAT,
            -86_400,
            datetime(1969, 12, 31, tzinfo=UTC),
            id="gnu-base256",
        ),
    ],
)
def test_pre_1970_mtime_lists_its_date(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tar_format: int,
    mtime: float,
    expected: datetime,
) -> None:
    """A negative mtime is a 1969 date on every platform.

    ``datetime.fromtimestamp`` goes through ``gmtime()`` on Windows, which rejects a
    negative value, so this member used to list as invalid there only. A
    ``fromtimestamp`` that raises the way Windows' does must not matter any more.
    """
    from archivey.internal import timestamps as timestamps_module

    class _WindowsLikeDatetime(datetime):
        @classmethod
        def fromtimestamp(cls, ts: float, tz: Any = None) -> datetime:
            if ts < 0:
                raise OSError(22, "Invalid argument (simulated Windows gmtime)")
            return datetime.fromtimestamp(ts, tz)

    monkeypatch.setattr(tar_reader_module, "datetime", _WindowsLikeDatetime)
    monkeypatch.setattr(timestamps_module, "datetime", _WindowsLikeDatetime)

    path = _tar_with_mtime(tmp_path / "old.tar", mtime, tar_format)
    if tar_format == tarfile.PAX_FORMAT:
        with tarfile.open(path) as tf:
            assert "mtime" in tf.getmembers()[0].pax_headers
    with open_archive(path) as ar:
        member = ar.get("old.txt")
        assert member.modified == expected
        assert DiagnosticCode.MEMBER_TIMESTAMP_INVALID not in ar.diagnostics.counts


def test_pre_1970_pax_atime_lists_its_date(tmp_path: Path) -> None:
    path = tmp_path / "atime.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("old.txt")
        info.pax_headers = {"atime": "-1.5"}
        tf.addfile(info, io.BytesIO(b""))
    with open_archive(path) as ar:
        assert ar.get("old.txt").accessed == datetime(
            1969, 12, 31, 23, 59, 58, 500_000, tzinfo=UTC
        )


@pytest.mark.parametrize(
    ("key", "attr"),
    [
        ("atime", "accessed"),
        ("ctime", "ctime"),
        ("LIBARCHIVE.creationtime", "created"),
        ("mtime", "modified"),
    ],
)
@pytest.mark.parametrize("raw", ["not-a-time", "1e30", "nan"])
def test_bad_pax_time_is_reported(
    tmp_path: Path, key: str, attr: str, raw: str
) -> None:
    # Every PAX time record that does not decode is reported the same way: the field
    # is None and MEMBER_TIMESTAMP_INVALID names the member field it would have
    # filled, as every format does. tarfile itself turns a PAX mtime
    # that is not a number into 0, which must not list as the Unix epoch.
    path = tmp_path / "bad_time.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("t.txt")
        info.mtime = 1_600_000_000
        info.pax_headers = {key: raw}
        tf.addfile(info, io.BytesIO(b""))
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert getattr(member, attr) is None
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_TIMESTAMP_INVALID] == 1
        (diagnostic,) = member.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        assert diagnostic.context.field == attr
        assert key in diagnostic.message


def test_several_bad_pax_times_on_one_member_are_each_reported(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bad_times.tar"
    keys = ("atime", "ctime", "LIBARCHIVE.creationtime")
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("t.txt")
        info.pax_headers = dict.fromkeys(keys, "nan")
        tf.addfile(info, io.BytesIO(b""))
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert (member.accessed, member.ctime, member.created) == (None, None, None)
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_TIMESTAMP_INVALID] == 3
        fields = sorted(d.context.field for d in member.diagnostics)
        assert fields == ["accessed", "created", "ctime"]


def _pax_mtime_archive(raw: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("t.txt")
        info.pax_headers = {"mtime": raw}
        tf.addfile(info, io.BytesIO(b""))
    return buf.getvalue()


@pytest.mark.parametrize(
    "raw",
    ["+1000", "1e3", "1_000", " 1000", "1000 ", ".5", "-.5", "0x10", "inf", "\u0663"],
)
def test_pax_time_in_python_float_syntax_is_reported(raw: str) -> None:
    """GNU tar 1.35 reads a PAX time as ``-?digits(.digits*)?`` and reports anything
    else ("Malformed extended header: invalid mtime"). ``float()`` accepts more, and
    ``1e3`` or ``1_000`` must not list as 00:16:40."""
    with open_archive(io.BytesIO(_pax_mtime_archive(raw))) as ar:
        member = ar.get("t.txt")
        assert member.modified is None
        assert ar.diagnostics.counts[DiagnosticCode.MEMBER_TIMESTAMP_INVALID] == 1


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1000", datetime(1970, 1, 1, 0, 16, 40, tzinfo=UTC)),
        ("1000.", datetime(1970, 1, 1, 0, 16, 40, tzinfo=UTC)),
        ("01000.5", datetime(1970, 1, 1, 0, 16, 40, 500000, tzinfo=UTC)),
        ("-1000", datetime(1969, 12, 31, 23, 43, 20, tzinfo=UTC)),
    ],
)
def test_pax_time_in_gnu_tar_syntax_is_read(raw: str, expected: datetime) -> None:
    with open_archive(io.BytesIO(_pax_mtime_archive(raw))) as ar:
        assert ar.get("t.txt").modified == expected
        assert DiagnosticCode.MEMBER_TIMESTAMP_INVALID not in ar.diagnostics.counts


def test_long_bad_pax_time_is_cut_in_the_report() -> None:
    with open_archive(io.BytesIO(_pax_mtime_archive("9" * 5000))) as ar:
        (diagnostic,) = ar.get("t.txt").diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        assert len(diagnostic.message) < 200
        assert "'" + "9" * 40 + "...'" in diagnostic.message


def test_pax_mtime_zero_is_the_epoch(tmp_path: Path) -> None:
    path = tmp_path / "epoch.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("t.txt")
        info.pax_headers = {"mtime": "0"}
        tf.addfile(info, io.BytesIO(b""))
    with open_archive(path) as ar:
        assert ar.get("t.txt").modified == datetime(1970, 1, 1, tzinfo=UTC)
        assert DiagnosticCode.MEMBER_TIMESTAMP_INVALID not in ar.diagnostics.counts


def _tar_hardlink_then_target() -> bytes:
    """``h`` is a hardlink to ``t``; the only ``t`` comes after it, and an earlier
    ``u`` that a later ``u`` replaces is linked from ``hu`` between the two."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in (("u", b"FIRST-U"),):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for name, target in (("h", "t"), ("hu", "u")):
            link = tarfile.TarInfo(name)
            link.type = tarfile.LNKTYPE
            link.linkname = target
            t.addfile(link)
        for name, data in (("t", b"LATER-T"), ("u", b"LATER-U")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize("streaming", [False, True])
def test_hardlink_resolves_to_an_earlier_member_only(
    tmp_path: Path, streaming: bool
) -> None:
    """A TAR hardlink refers to a file archived before it: tarfile's own lookup
    searches only the members before the link and takes the last match, and
    ``tar(1)`` links to what it already wrote. So ``h -> t`` with ``t`` only later has
    no target, and ``hu -> u`` is the first ``u``, not the later one. Random access
    and a streaming pass agree."""
    from archivey import ExtractionStatus, OnError
    from archivey.exceptions import LinkTargetNotFoundError

    data = _tar_hardlink_then_target()
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
        listed = {m.name: m for m in reader.members_report().members}
    by_name = {r.member.name: r for r in report.results}
    assert listed["h"].link_target_member is None
    assert by_name["h"].status is ExtractionStatus.FAILED
    assert isinstance(by_name["h"].error, LinkTargetNotFoundError)
    assert listed["hu"].link_target_member is not None
    assert listed["hu"].link_target_member.member_id == 0
    assert (tmp_path / "out" / "hu").read_bytes() == b"FIRST-U"
    assert (tmp_path / "out" / "t").read_bytes() == b"LATER-T"
    if not streaming:
        with (
            open_archive(io.BytesIO(data)) as reader,
            pytest.raises(LinkTargetNotFoundError),
        ):
            reader.read("h")


@pytest.mark.parametrize("codec", ["gz", "bz2", "xz"])
def test_extract_compressed_tar_decodes_once(tmp_path: Path, codec: str) -> None:
    """``extract_all`` on a compressed tar reads it in one forward pass: the
    listing limits are enforced as members arrive rather than by listing the whole
    archive first, so no seek goes back and ``STREAM_REWIND_REDECOMPRESSES``, set to
    ``RAISE``, never fires. A 2 MiB member makes a rewind large enough to report."""
    import bz2
    import gzip
    import lzma

    from archivey.diagnostics import DiagnosticPolicy

    payload = bytes(range(256)) * (8 * 1024)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        for name in ("a.bin", "b.bin"):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("h.bin")
        link.type = tarfile.LNKTYPE
        link.linkname = "a.bin"
        t.addfile(link)
    compress = {"gz": gzip.compress, "bz2": bz2.compress, "xz": lzma.compress}[codec]
    archive = tmp_path / f"x.tar.{codec}"
    archive.write_bytes(compress(raw.getvalue()))
    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.STREAM_REWIND_REDECOMPRESSES}
        )
    )
    report = open_and_extract(archive, tmp_path / "out", config=config)
    assert len(report.results) == 3
    for name in ("a.bin", "b.bin", "h.bin"):
        assert (tmp_path / "out" / name).read_bytes() == payload
    assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES not in report.diagnostics.counts


def test_extract_enforces_listing_limits_as_members_arrive(tmp_path: Path) -> None:
    """Without listing first, ``max_members`` still refuses the extraction, at the
    member that crosses it, before that member is written."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        for i in range(5):
            info = tarfile.TarInfo(f"f{i}")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
    archive = tmp_path / "x.tar"
    archive.write_bytes(raw.getvalue())
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=3))
    with pytest.raises(ResourceLimitError, match="max_members"):
        open_and_extract(archive, tmp_path / "out", config=config)
    assert not (tmp_path / "out" / "f3").exists()


class _CountingRaw(io.RawIOBase):
    """A raw source that counts the bytes read from it; seekable or not."""

    def __init__(self, data: bytes, *, seekable: bool) -> None:
        self._inner = io.BytesIO(data)
        self._seekable = seekable
        self.read_bytes = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        n = self._inner.readinto(buffer)
        self.read_bytes += n
        return n

    def seekable(self) -> bool:
        return self._seekable

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if not self._seekable:
            raise io.UnsupportedOperation("seek")
        return self._inner.seek(offset, whence)

    def tell(self) -> int:
        if not self._seekable:
            raise io.UnsupportedOperation("tell")
        return self._inner.tell()


@pytest.mark.parametrize("streaming", [False, True])
def test_a_pass_reads_no_member_data_the_consumer_does_not_reach(
    streaming: bool,
) -> None:
    """Skipping a member is lazy. A consumer that takes the first member and stops
    causes no read of that member's data area, in a streaming pass (whose skip reads
    through the data, but only before the next header) and in the random-access one
    pass. Taking the second member of a forward-only source reads through the first."""
    big = 4 * 2**20
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, size in (("a", big), ("b", 10), ("c", 10)):
            info = tarfile.TarInfo(name)
            info.size = size
            t.addfile(info, io.BytesIO(b"x" * size))
    data = buf.getvalue()

    def reads_after(members_taken: int) -> int:
        raw = _CountingRaw(data, seekable=not streaming)
        with open_archive(
            io.BufferedReader(raw), format=ArchiveFormat.TAR, streaming=streaming
        ) as reader:
            it = iter(reader.stream_members())
            for _ in range(members_taken):
                next(it)
            it.close()  # type: ignore[attr-defined]
        return raw.read_bytes

    assert reads_after(1) < 1 * 2**20
    if streaming:
        assert reads_after(2) >= big
    else:
        assert reads_after(2) < 1 * 2**20  # random access seeks past the data


@pytest.mark.parametrize("padding", [0, 4096, 32 * 1024])
@pytest.mark.parametrize("streaming", [False, True])
def test_cut_second_gzip_member_after_the_trailer_still_lists(
    padding: int, streaming: bool
) -> None:
    """A .tar.gz whose second gzip member is cut, after the tar trailer and some zero
    padding, lists its member: the cut is past everything the listing needs, and a
    read-ahead into it must not fail the open."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("f.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    plain = buf.getvalue()[: 4 * 512]  # header, data block, two-block trailer
    data = gzip.compress(plain + bytes(padding)) + b"\x1f\x8b\x08\x00" + bytes(8)
    with open_archive(io.BytesIO(data), streaming=streaming) as archive:
        names = [member.name for member, _ in archive.stream_members()]
    assert names == ["f.txt"]


def test_gnu_dumpdir_entry_is_a_directory(tmp_path: Path) -> None:
    """A GNU incremental dump's ``D`` entry is a directory, as GNU tar extracts it.

    Its data is the directory's contents list at dump time; it is skipped, and the
    member after it reads normally.
    """
    listing = b"Yf.txt\x00\x00"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        dumpdir = tarfile.TarInfo("d/")
        dumpdir.type = b"D"
        dumpdir.mode = 0o755
        dumpdir.size = len(listing)
        tf.addfile(dumpdir, io.BytesIO(listing))
        info = tarfile.TarInfo("d/f.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        members = reader.members()
        assert [(m.name, m.type) for m in members] == [
            ("d/", MemberType.DIRECTORY),
            ("d/f.txt", MemberType.FILE),
        ]
        assert members[0].size is None
        assert reader.read("d/f.txt") == b"hello"
        reader.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "d").is_dir()
    assert (tmp_path / "out" / "d" / "f.txt").read_bytes() == b"hello"


@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
def test_a_pass_keeps_no_parsed_entries(streaming: bool) -> None:
    """A pass over many members keeps no parsed entry or header block behind it.

    tarfile kept its own list of every header beside the reader's member list, so a
    listing held each header twice. Each member now keeps only its data span (a
    ``TarSpan``), held by the member alone; the entry and its header block go once the
    member is built.
    """
    import gc

    from archivey.internal.backends.tar_parser import HeaderBlock, TarEntry, TarSpan

    count = 2_000
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for i in range(count):
            tf.addfile(tarfile.TarInfo(f"held-once-{i:05d}"))

    def ours(name: bytes) -> bool:
        # A free-threaded build can still hold another test's objects after
        # gc.collect(), so only this archive's are counted.
        return name.startswith(b"held-once-")

    with open_archive(io.BytesIO(buf.getvalue()), streaming=streaming) as reader:
        members = [m for m, _ in reader.stream_members()]
        gc.collect()
        entries = sum(
            isinstance(o, TarEntry) and ours(o.name) for o in gc.get_objects()
        )
        headers = sum(
            isinstance(o, HeaderBlock) and ours(o.name) for o in gc.get_objects()
        )
        span = members[-1]._raw
        assert type(span) is TarSpan
        holders = [type(r).__name__ for r in gc.get_referrers(span)]
    if not CPYTHON:
        # PyPy also lists this frame, which holds ``span``, and a tuple of its own:
        # at most one of each, so a second tuple holding the span still fails.
        assert holders.count("frame") <= 1 and holders.count("tuple") <= 1
        holders = [h for h in holders if h not in ("frame", "tuple")]
    assert len(members) == count
    assert (entries, headers) == (0, 0)
    assert holders == ["ArchiveMember"]


def test_pax_id_that_is_not_a_number_keeps_the_header_value() -> None:
    """A PAX ``uid`` or ``gid`` that is not a number is ignored, as GNU tar ignores it:
    the header's value stays, not 0."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("a")
        info.uid, info.gid = 7, 8
        info.pax_headers = {"uid": "x1", "gid": "12"}
        tf.addfile(info)
    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        (member,) = reader.members()
    assert (member.uid, member.gid) == (7, 12)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "records",
    [
        {"size": "1" * 5000},
        {"GNU.sparse.major": "1", "GNU.sparse.realsize": "1" * 5000},
        {"GNU.sparse.size": "1" * 5000, "GNU.sparse.map": "0,1"},
    ],
    ids=["size", "sparse-realsize", "sparse-size"],
)
def test_pax_number_past_the_int_digit_limit_is_corruption(
    records: dict[str, str], streaming: bool
) -> None:
    """``int()`` refuses a string of more than 4300 digits with a builtin
    ``ValueError``. A PAX size that long is damage, typed as such. (A PAX ``uid`` or
    ``gid`` that long is ignored and the header's kept, as GNU tar keeps it:
    ``tests/test_tar_parser.py::test_pax_id_out_of_range_keeps_the_header_value``.)"""
    body = b"x" * 512
    head = b"".join(_pax_record(key, value) for key, value in records.items())
    xhdr = tarfile.TarInfo("./PaxHeaders/a")
    xhdr.type = tarfile.XHDTYPE
    xhdr.size = len(head)
    member = tarfile.TarInfo("a")
    member.size = len(body)
    data = b"".join(
        [
            xhdr.tobuf(format=tarfile.USTAR_FORMAT),
            head + bytes(-len(head) % 512),
            member.tobuf(format=tarfile.USTAR_FORMAT),
            body,
            bytes(1024),
        ]
    )
    with (
        pytest.raises(CorruptionError, match="past any file's size"),
        open_archive(
            io.BytesIO(data), format=ArchiveFormat.TAR, streaming=streaming
        ) as ar,
    ):
        for _ in ar:
            pass


def test_pax_number_with_many_leading_zeros_reads() -> None:
    """Leading zeros do not count against the digit limit: the value is small."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("a")
        info.pax_headers = {"uid": "0" * 5000 + "12"}
        tf.addfile(info)
    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        (member,) = reader.members()
    assert member.uid == 12


@pytest.mark.parametrize(
    ("typeflag", "special"),
    [
        (tarfile.CHRTYPE, "char_device"),
        (tarfile.BLKTYPE, "block_device"),
        (tarfile.FIFOTYPE, "fifo"),
    ],
)
def test_special_entries_are_other_and_name_their_type(
    tmp_path: Path, typeflag: bytes, special: str
) -> None:
    """A device or FIFO header is OTHER (the typeflag is the structure, and GNU tar
    stores no data under it), and ``extra["special_file_type"]`` says which kind."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        info = tarfile.TarInfo("dev")
        info.type = typeflag
        info.mode = 0o660
        info.devmajor, info.devminor = 1, 3
        t.addfile(info)
        reg = tarfile.TarInfo("reg.txt")
        reg.size = 2
        t.addfile(reg, io.BytesIO(b"hi"))
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["dev"].type is MemberType.OTHER
        assert by_name["dev"].extra["special_file_type"] == special
        # Only a character or block device holds a device number; GNU tar reads
        # none for a FIFO.
        if typeflag == tarfile.FIFOTYPE:
            assert "tar.devmajor" not in by_name["dev"].extra
        else:
            assert by_name["dev"].extra["tar.devmajor"] == 1
            assert by_name["dev"].extra["tar.devminor"] == 3
        assert "special_file_type" not in by_name["reg.txt"].extra
        codes = [d.code for d in ar.diagnostics.retained]
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes
        ar.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "dev").exists()
    assert (tmp_path / "out" / "reg.txt").read_bytes() == b"hi"


def test_a_sized_fifo_header_is_corruption() -> None:
    """A device or FIFO header that declares data is damage: GNU tar and libarchive
    ignore the size field of typeflags 3/4/6 and read the next header where the
    "data" starts. tarfile does the same, so an all-null payload reads as the end
    marker and every later member silently disappears; archivey refuses the header
    instead of dropping members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        info = tarfile.TarInfo("pipe")
        info.type = tarfile.FIFOTYPE
        info.size = 512
        t.addfile(info, io.BytesIO(b"\0" * 512))
        reg = tarfile.TarInfo("reg.txt")
        reg.size = 2
        t.addfile(reg, io.BytesIO(b"hi"))
    with (
        open_archive(io.BytesIO(buf.getvalue())) as ar,
        pytest.raises(CorruptionError, match="fifo.*declares 512 bytes"),
    ):
        ar.members()
    with (
        open_archive(
            NonSeekableBytesIO(buf.getvalue()), format=ArchiveFormat.TAR, streaming=True
        ) as ar,
        pytest.raises(CorruptionError, match="fifo.*declares 512 bytes"),
    ):
        list(ar.stream_members())


def _three_members(middle: Callable[[tarfile.TarFile], None]) -> bytearray:
    """``a.txt``, the member ``middle`` adds, then ``b.txt``, in a ustar archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:", format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        t.addfile(info, io.BytesIO(b"aaa"))
        middle(t)
        info = tarfile.TarInfo("b.txt")
        info.size = 3
        t.addfile(info, io.BytesIO(b"bbb"))
    return bytearray(buf.getvalue())


def _patch_header(data: bytearray, offset: int, start: int, value: bytes) -> None:
    """Write ``value`` at ``start`` in the header at ``offset``, checksum recomputed."""
    header = offset + start
    data[header : header + len(value)] = value
    data[offset + 148 : offset + 156] = b" " * 8
    checksum = sum(data[offset : offset + 512])
    data[offset + 148 : offset + 156] = b"%06o\0 " % checksum


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("start", [329, 337], ids=["devmajor", "devminor"])
def test_device_number_that_is_not_a_number_keeps_the_listing(
    streaming: bool, start: int
) -> None:
    """GNU tar 1.35 reports a device number that is not a number ("Archive contains
    'junkjunk' where numeric major_t value expected") and lists the device and every
    member after it. archivey lists them too; the device has no device numbers and
    says why."""

    def device(t: tarfile.TarFile) -> None:
        info = tarfile.TarInfo("dev")
        info.type = tarfile.CHRTYPE
        info.devmajor, info.devminor = 1, 3
        t.addfile(info)

    data = _three_members(device)
    _patch_header(data, 1024, start, b"junkjunk")
    source = NonSeekableBytesIO(bytes(data)) if streaming else io.BytesIO(bytes(data))
    with open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar:
        members = [member for member, _ in ar.stream_members()]
        assert [m.name for m in members] == ["a.txt", "dev", "b.txt"]
        dev = members[1]
        assert "tar.devmajor" not in dev.extra
        assert "tar.devminor" not in dev.extra
        (diagnostic,) = dev.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.record == "device_numbers"


@pytest.mark.parametrize("streaming", [False, True])
def test_old_gnu_sparse_realsize_out_of_range_stops_the_walk(streaming: bool) -> None:
    """archivey's own rule, not GNU tar's: GNU tar 1.35 reports a negative old GNU
    realsize ("out of off_t range"), lists the member with size 0 and lists
    ``b.txt``. archivey stops the walk there, as it does for a map slot it cannot
    read: ``a.txt`` is delivered, then CorruptionError, and nothing lists a size of
    -1."""

    def sparse(t: tarfile.TarFile) -> None:
        info = tarfile.TarInfo("sp")
        t.addfile(info)

    data = _three_members(sparse)
    data[1024 + 156 : 1024 + 157] = b"S"
    data[1024 + 257 : 1024 + 265] = b"ustar  \0"
    _patch_header(data, 1024, 483, b"\xff" * 12)
    source = NonSeekableBytesIO(bytes(data)) if streaming else io.BytesIO(bytes(data))
    names = []
    with (
        open_archive(source, format=ArchiveFormat.TAR, streaming=streaming) as ar,
        pytest.raises(CorruptionError),
    ):
        for member, _ in ar.stream_members():
            names.append(member.name)
    assert names == ["a.txt"]


def test_other_entries_that_are_not_special_files_get_no_special_file_type() -> None:
    """A GNU volume header (``V``) is OTHER but not a device, FIFO or socket, so it has no
    ``extra["special_file_type"]``: the key means "the archive recorded a special
    file" in every format, not "the member is OTHER"."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        info = tarfile.TarInfo("volume")
        info.type = b"V"
        t.addfile(info)
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        [member] = ar.members()
        assert member.type is MemberType.OTHER
        assert member.extra["tar.type"] == b"V"
        assert "special_file_type" not in member.extra


_UNKNOWN_TYPEFLAGS = [
    pytest.param(b"9", id="digit"),
    pytest.param(b"z", id="lowercase"),
    pytest.param(b"N", id="old_gnu_names"),
]
"""Typeflags no TAR writer archivey knows assigns to a member. GNU tar 1.35 extracts
each as a regular file and warns "Unknown file type '9', extracted as normal file"."""


def _unknown_type_diagnostics(diagnostics: Any) -> list[Any]:
    return [
        d.context for d in diagnostics if d.code is DiagnosticCode.MEMBER_TYPE_UNKNOWN
    ]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _UNKNOWN_TYPEFLAGS)
def test_unknown_typeflag_with_data_is_a_file(
    tmp_path: Path, typeflag: bytes, streaming: bool
) -> None:
    """An unknown typeflag that declares data lists as a FILE of that size, reads, and
    extracts, as GNU tar 1.35 extracts it (DR-25; maintainer ruling 2026-10-17).
    ``MEMBER_TYPE_UNKNOWN`` names the type byte, which ``extra["tar.type"]`` keeps."""
    data = _tar_entry_with_data(typeflag, own_name="f", data=b"hello")
    assert _stream_all(data, streaming) == [
        ("f", MemberType.FILE, b"hello"),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        for member, stream in ar.stream_members():
            if member.name == "f":
                assert stream is not None
                assert stream.read() == b"hello"
                assert member.size == 5
                assert member.extra["tar.type"] == typeflag
                [context] = _unknown_type_diagnostics(member.diagnostics)
                assert context.stored_type == typeflag.decode("latin-1")
                assert context.size == 5
                assert context.member_name == "f"
                assert context.to_dict()["kind"] == "unknown_member_type"
    if not streaming:
        with open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar:
            member = ar.get("f")
            assert ar.read(member) == b"hello"
    out = tmp_path / "out"
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        ar.extract_all(out)
    assert (out / "f").read_bytes() == b"hello"
    assert (out / "after.txt").read_bytes() == b"after\n"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", _UNKNOWN_TYPEFLAGS)
def test_unknown_typeflag_with_no_data_is_other(
    tmp_path: Path, typeflag: bytes, streaming: bool
) -> None:
    """An unknown typeflag that declares no data stays OTHER with no ``size``, and
    extraction skips it. It is reported all the same: the type is as unknown."""
    data = _tar_entry_with_data(typeflag, own_name="f", data=b"")
    assert _stream_all(data, streaming) == [
        ("f", MemberType.OTHER, None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        member = next(m for m, _ in ar.stream_members() if m.name == "f")
        assert member.size is None
        assert member.extra["tar.type"] == typeflag
        assert "special_file_type" not in member.extra
        [context] = _unknown_type_diagnostics(member.diagnostics)
        assert context.stored_type == typeflag.decode("latin-1")
        assert context.size is None
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        ar.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "f").exists()
    assert (tmp_path / "out" / "after.txt").read_bytes() == b"after\n"


@pytest.mark.parametrize("streaming", [False, True])
def test_unknown_typeflag_does_not_fail_strict(streaming: bool) -> None:
    """``MEMBER_TYPE_UNKNOWN`` is advisory: GNU tar extracts such an archive, so
    ``STRICT`` lists and reads it."""
    data = _tar_entry_with_data(b"9", own_name="f", data=b"hello")
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
    ) as ar:
        read = {
            m.name: stream.read() if stream is not None else None
            for m, stream in ar.stream_members()
        }
        assert read == {"f": b"hello", "after.txt": b"after\n"}
        assert DiagnosticCode.MEMBER_TYPE_UNKNOWN in ar.diagnostics.counts


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("typeflag", [b"V", b"M"])
def test_volume_typeflags_are_known(typeflag: bytes, streaming: bool) -> None:
    """GNU's volume header ``V`` and multi-volume continuation ``M`` are known types:
    they stay OTHER with data, as GNU tar skips or refuses them, and nothing reports an
    unknown type."""
    data = _tar_entry_with_data(typeflag, own_name="f", data=b"hello")
    assert _stream_all(data, streaming) == [
        ("f", MemberType.OTHER, None),
        ("after.txt", MemberType.FILE, b"after\n"),
    ]
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        format=ArchiveFormat.TAR,
        streaming=streaming,
    ) as ar:
        member = next(m for m, _ in ar.stream_members() if m.name == "f")
        assert member.size is None
        assert not _unknown_type_diagnostics(ar.diagnostics.retained)


def test_a_rewind_in_a_compressed_tar_logs_at_info(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Opening an earlier member of a ``.tar.gz`` decodes the stream again from the
    start. ``STREAM_REWIND_REDECOMPRESSES`` reports it as a diagnostic, and its log
    record is INFO, not WARNING: it describes the caller's access pattern, not the
    archive (``logging`` spec). The record carries the code and the occurrence id."""
    rng = random.Random(0)
    size = REWIND_REDECODE_WARN_BYTES + 1024
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, mode="w:gz") as tar:
        for name in ("a", "b"):
            info = tarfile.TarInfo(name)
            info.size = size
            tar.addfile(info, io.BytesIO(rng.randbytes(size)))
    with caplog.at_level(logging.DEBUG, logger="archivey"), open_archive(path) as ar:
        members = {m.name: m for m in ar.members()}
        for name in ("b", "a"):
            with ar.open(members[name]) as stream:
                stream.read()
        counts = ar.diagnostics.counts
        (diagnostic,) = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.STREAM_REWIND_REDECOMPRESSES
        ]
    assert counts[DiagnosticCode.STREAM_REWIND_REDECOMPRESSES] == 1
    rewinds = [r for r in caplog.records if "Backward seek" in r.getMessage()]
    assert [r.levelno for r in rewinds] == [logging.INFO]
    (record,) = rewinds
    assert record.diagnostic_code is DiagnosticCode.STREAM_REWIND_REDECOMPRESSES
    assert record.diagnostic_occurrence_id == diagnostic.occurrence_id
