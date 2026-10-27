"""ZIP backend tests — Stage 1 (member mapping, cost, O(1) lookup, non-seekable
fail-fast, multi-volume rejection) and the ZIP slice of access-mode-and-cost."""

from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import stat
import struct
import subprocess
import threading
import zipfile
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyConfig,
    CompressionAlgorithm,
    DiagnosticCode,
    DiagnosticPolicy,
    ExtractionPolicy,
    ExtractionStatus,
    MemberType,
    open_archive,
)
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.diagnostics import raw_name_to_base64
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    DiagnosticRaisedError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.hashing import crc32_digest
from archivey.types import CreateSystem, HashAlgorithm
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import NonSeekableBytesIO
from tests.zip_aes_fixture import build_aes_zip
from tests.zipcrypto import build_zipcrypto_zip, zip_with_truncated_zipcrypto_header

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def simple_zip(tmp_path: Path) -> Path:
    path = tmp_path / "simple.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("hello.txt", b"hello world")
        z.writestr("dir/nested.txt", b"nested content")
    return path


def _zip_with_unix_mode(path: Path, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name)
    info.create_system = 3  # Unix
    info.external_attr = mode << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, data)


# ---------------------------------------------------------------------------
# Cost / format properties (also covers access-mode-and-cost for ZIP)
# ---------------------------------------------------------------------------


def test_cost_receipt(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        cost = ar.cost
        assert cost.listing_cost == ListingCost.INDEXED
        assert cost.access_cost == AccessCost.DIRECT
        assert cost.stream_capability == StreamCapability.SEEKABLE


def test_archive_info(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        info = ar.info
        assert info.format == ArchiveFormat.ZIP
        assert info.is_solid is False
        assert info.is_encrypted is False
        assert info.is_multivolume is False
        assert info.member_count == 2


def test_format_detected_as_zip(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        assert ar.format == ArchiveFormat.ZIP


# ---------------------------------------------------------------------------
# Indexed listing + random access (access-mode-and-cost, default streaming=False)
# ---------------------------------------------------------------------------


def test_members_listed(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        names = {m.name for m in ar.members()}
        assert names == {"hello.txt", "dir/nested.txt"}


def test_member_list_available_without_scan(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        # The central directory is an upfront index, so the list is available with no scan.
        report = ar.members_report_if_available()
        assert report is not None
        assert report.error is None
        assert {m.name for m in report} == {"hello.txt", "dir/nested.txt"}


def test_random_access_read_by_name(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        assert ar.read("hello.txt") == b"hello world"
        assert ar.read("dir/nested.txt") == b"nested content"
        # Re-reading an earlier member out of order still works (random access).
        assert ar.read("hello.txt") == b"hello world"


def test_central_directory_lookup_no_io(simple_zip: Path) -> None:
    # reader.get("name") is served from the in-memory name map with no extra archive reads.
    with open_archive(simple_zip) as ar:
        ar.members()  # materialize
        calls = {"read_at": 0}
        original_read_at = ar._read_at  # type: ignore[attr-defined]

        def counting_read_at(offset: int, n: int) -> bytes:
            calls["read_at"] += 1
            return original_read_at(offset, n)

        ar._read_at = counting_read_at  # type: ignore[attr-defined]
        member = ar.get("hello.txt")
        assert member.name == "hello.txt"
        assert calls["read_at"] == 0  # lookup touched no archive bytes


# ---------------------------------------------------------------------------
# Member metadata mapping
# ---------------------------------------------------------------------------


def test_unix_mode_from_external_attr(tmp_path: Path) -> None:
    path = tmp_path / "moded.zip"
    _zip_with_unix_mode(path, "script.sh", b"#!/bin/sh\n", 0o755)
    with open_archive(path) as ar:
        member = ar.get("script.sh")
        assert member.mode == 0o755


def test_none_mode_when_external_attr_zero() -> None:
    # zipfile.writestr always stamps a 0o600 external_attr, so zero it in the central
    # directory (4-byte field at offset 38 of the PK\x01\x02 record) to exercise the
    # "external_attr == 0 -> mode None" rule.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plain.txt", b"x")
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    raw[cd + 38 : cd + 42] = b"\x00\x00\x00\x00"
    with open_archive(io.BytesIO(bytes(raw))) as ar:
        assert ar.get("plain.txt").mode is None


@pytest.mark.parametrize(
    ("external_attr", "mode"),
    [
        # A Unix host with only DOS attribute bits (here ARCHIVE): no mode was stored.
        # unzip 6.00 falls back to the DOS bits too, rather than chmod the file 000.
        (0x20, None),
        (0x10 | 0x01, None),
        # Permission bits without a file type, as `ZipInfo.external_attr = 0o644 << 16`
        # writes them, are a mode.
        (0o644 << 16, 0o644),
        ((0o100755 << 16) | 0x20, 0o755),
    ],
)
def test_unix_mode_needs_a_non_zero_high_word(
    external_attr: int, mode: int | None
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("a.txt")
        info.create_system = 3
        info.external_attr = external_attr
        z.writestr(info, b"x")
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        member = ar.get("a.txt")
        assert member.mode == mode
        assert member.type is MemberType.FILE


def test_directory_member_type(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        by_name = {m.name: m for m in ar.members()}
        # zipfile stores explicit directory entries with a trailing slash.
        assert by_name["hello.txt"].type == MemberType.FILE


def test_file_member_exposes_stored_crc32(simple_zip: Path) -> None:
    # archive-data-model: ZIP CRC32 under HashAlgorithm.CRC32 as 4 big-endian bytes.
    with open_archive(simple_zip) as ar:
        member = ar.get("hello.txt")
        assert member is not None
        assert member.hashes[HashAlgorithm.CRC32] == crc32_digest(
            zlib.crc32(b"hello world")
        )


def test_directory_member_has_no_crc32(tmp_path: Path) -> None:
    path = tmp_path / "withdir.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("adir/", b"")
        z.writestr("adir/file.txt", b"data")
    with open_archive(path) as ar:
        by_name = {m.name: m for m in ar.members()}
        # A directory's stored CRC is a meaningless 0; do not present it as a digest.
        assert HashAlgorithm.CRC32 not in by_name["adir/"].hashes
        assert by_name["adir/file.txt"].hashes[HashAlgorithm.CRC32] == crc32_digest(
            zlib.crc32(b"data")
        )


def test_explicit_directory_entry(tmp_path: Path) -> None:
    path = tmp_path / "withdir.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("adir/", b"")
        z.writestr("adir/file.txt", b"data")
    with open_archive(path) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["adir/"].type == MemberType.DIRECTORY


def test_symlink_member(tmp_path: Path) -> None:
    import stat as stat_module

    path = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat_module.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("target.txt", b"payload")
        z.writestr(info, b"target.txt")
    with open_archive(path) as ar:
        member = ar.get("link")
        assert member.type == MemberType.SYMLINK
        assert member.link_target == "target.txt"


def test_truncated_symlink_target_is_typed_error(tmp_path: Path) -> None:
    """Listing a ZIP truncated inside a symlink's payload raises an ArchiveyError.

    Found by the Atheris zip_tar target, when stdlib zipfile read symlink targets and
    this escaped as a raw ``EOFError``. With this fixture the central directory is
    already unreadable, so it now fails at open.
    """
    import stat as stat_module

    path = tmp_path / "trunc-link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat_module.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"/tmp/some/long/symlink/target/path")
    data = bytearray(path.read_bytes())
    # Chop the file mid-payload but leave enough of the structure for zipfile to open
    # and classify the member as a symlink (then fail while reading the target).
    assert len(data) > 40
    truncated = bytes(data[: max(40, len(data) // 2)])
    with (
        pytest.raises(CorruptionError),
        open_archive(io.BytesIO(truncated), format=ArchiveFormat.ZIP) as ar,
    ):
        list(ar)


@pytest.mark.parametrize(
    "password", [b"secret", [b"secret", b"other"]], ids=["single", "multi"]
)
def test_truncated_zipcrypto_header_is_typed_error(
    password: bytes | list[bytes],
) -> None:
    """A short ZipCrypto header is TruncatedError on both password dispatch paths.

    Found by the Atheris zip target (nightly 2026-09-01, run 33505689273), when
    stdlib's ``ZipExtFile`` still decrypted ZipCrypto and indexed ``[11]`` of
    whatever ``read(12)`` returned. Listing still succeeds; opening the encrypted
    member must raise ``TruncatedError``, not a raw ``IndexError`` and not
    ``CorruptionError``. A single password reads the header in the decrypt stage;
    two or more take the STORED confirm path through ``_read_zipcrypto_header``.
    """
    blob = zip_with_truncated_zipcrypto_header(b"secret", b"x.txt", b"hello")
    with open_archive(
        io.BytesIO(blob), format=ArchiveFormat.ZIP, password=password
    ) as ar:
        encrypted = [m for m in ar if m.is_encrypted]
        assert encrypted, (
            "fixture must list the ZipCrypto member so the crash is on open"
        )
        with pytest.raises(TruncatedError, match="Truncated ZipCrypto header"):
            ar.open(encrypted[0])


def _with_declared_compress_size(blob: bytes, size: int) -> bytes:
    """Set the first member's compressed size to ``size`` in both of its headers.

    Crafted: no producer writes an encrypted member whose declared size cannot hold
    its encryption header (DR-24 allows a crafted fixture for that). The payload
    bytes stay in the file, so nothing is cut short.
    """
    out = bytearray(blob)
    struct.pack_into("<I", out, 18, size)  # local file header, compressed size
    cd_at = out.find(b"PK\x01\x02")
    assert cd_at > 0
    struct.pack_into("<I", out, cd_at + 20, size)  # central directory, same field
    return bytes(out)


def _zipcrypto_blob() -> bytes:
    return build_zipcrypto_zip(
        b"secret", b"x.txt", b"hello world", compression=zipfile.ZIP_STORED
    )


def _aes_blob() -> bytes:
    return build_aes_zip([(b"x.txt", b"hello world")], password=b"secret", method=0)


@pytest.mark.parametrize(
    "password", [b"secret", [b"wrong", b"secret"]], ids=["single", "multi"]
)
@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_zipcrypto_blob, id="zipcrypto"),
        pytest.param(_aes_blob, id="aes", marks=requires("cryptography")),
    ],
)
def test_encryption_header_larger_than_declared_size_is_corruption(
    build: Callable[[], bytes], password: bytes | list[bytes]
) -> None:
    """A declared size too small for the encryption header is one typed error.

    The file is complete, so this is an impossible header (``CorruptionError``),
    not a short read, for ZipCrypto and WinZip AES alike, with the member named
    in the error.
    """
    blob = _with_declared_compress_size(build(), 5)
    with open_archive(
        io.BytesIO(blob), format=ArchiveFormat.ZIP, password=password
    ) as ar:
        member = ar.members()[0]
        with raises_corruption_not_truncation() as excinfo:
            ar.open(member)
    assert excinfo.value.member_name == "x.txt"
    assert excinfo.value.source_format is ArchiveFormat.ZIP


def test_archive_close_waits_for_an_in_flight_member_read() -> None:
    """Closing waits for a member stream's read that is inside the archive's source.

    The reader lifecycle waits for in-flight reader calls, not for a read on a stream
    the caller already holds; zipfile's lock, taken by every member read and by
    ``_close_archive``, is what keeps the handle open under that read.
    """
    import threading

    in_read = threading.Event()
    release = threading.Event()

    class _BlockingSource(io.BytesIO):
        armed = False

        def read(self, size: int | None = -1, /) -> bytes:
            if self.armed:
                self.armed = False
                in_read.set()
                release.wait(5)
            return super().read(size)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"data")
    source = _BlockingSource(buf.getvalue())
    ar = open_archive(source, concurrent_operations=True)
    stream = ar.open("a.txt")
    got: list[bytes] = []
    source.armed = True
    reader = threading.Thread(target=lambda: got.append(stream.read()))
    reader.start()
    assert in_read.wait(5)
    closed = threading.Event()
    closer = threading.Thread(target=lambda: (ar.close(), closed.set()))
    closer.start()
    try:
        assert not closed.wait(0.2)
    finally:
        release.set()
    assert closed.wait(5)
    reader.join(5)
    closer.join(5)
    assert got == [b"data"]


def test_archive_closed_before_the_overrun_probe() -> None:
    """A close between the last declared byte and the over-run probe keeps the read.

    The read that delivers a stored member's bytes closes the archive (the lock it
    waits on is re-entrant, so this is the threaded race above, made deterministic).
    The verifier's probe past the declared size then meets the member's closed view,
    which is "no more data", not a usage error: every declared byte was delivered.
    """
    data = b"data" * 10
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", data)

    class _ClosesOnRead(io.BytesIO):
        armed = False

        def read(self, size: int | None = -1, /) -> bytes:
            out = super().read(size)
            if self.armed:
                self.armed = False
                ar.close()
            return out

    source = _ClosesOnRead(buf.getvalue())
    ar = open_archive(source, concurrent_operations=True)
    with ar.open("a.txt") as stream:
        source.armed = True
        assert stream.read() == data


def test_unencrypted_codec_indexerror_is_not_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IndexError on the codec path is an archivey bug, not archive damage.

    Nothing on the ZIP read path translates IndexError, so a latent off-by-one in
    the codec opener (``open_codec_raw`` for an unencrypted member) still fails the
    Atheris zip target rather than being swallowed as TruncatedError.
    """
    from archivey.internal.backends import zip_reader

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("x.txt", b"hello world" * 10)

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise IndexError("index out of range")

    monkeypatch.setattr(zip_reader, "open_codec_raw", _boom)
    with (
        open_archive(io.BytesIO(buf.getvalue()), format=ArchiveFormat.ZIP) as ar,
        pytest.raises(IndexError, match="index out of range"),
    ):
        ar.open(next(iter(ar)))


def test_lzma_member_with_invalid_properties_is_corrupt_at_open() -> None:
    """Out-of-range method-14 LZMA properties raise ``lzma.LZMAError`` while the ZIP
    reader peels the header, before the codec layer runs; it must read as corruption.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_LZMA) as zf:
        zf.writestr("a.txt", b"hello" * 100)
    raw = bytearray(buf.getvalue())
    name_len, extra_len = struct.unpack("<HH", bytes(raw[26:30]))
    # Body: version (2), properties size (2), then the lc/lp/pb properties byte.
    props_at = 30 + name_len + extra_len + 4
    assert raw[props_at] == 0x5D
    raw[props_at] = 0xFF
    with (
        open_archive(io.BytesIO(bytes(raw)), format=ArchiveFormat.ZIP) as ar,
        pytest.raises(CorruptionError) as info,
    ):
        ar.open(ar.get("a.txt"))
    assert info.value.member_name == "a.txt"


def _opened_codec_reading_from(
    make_stream: Callable[[], BinaryIO],
) -> Callable[..., object]:
    """An ``open_codec_raw`` that opens the real codec, then reads from ``make_stream``.

    The member stream keeps the codec's own translator, so a test sees what the whole
    translation chain does with the error the stream raises.
    """
    from archivey.internal.streams.codecs import open_codec_raw

    def opener(*args: object, **kwargs: object) -> object:
        opened = open_codec_raw(*args, **kwargs)  # type: ignore[arg-type]  # forwarded as received
        opened.stream.close()
        return dataclasses.replace(opened, stream=make_stream())

    return opener


def test_unencrypted_member_read_indexerror_is_not_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IndexError during a ZIP member *read* is an archivey bug, not ZipCrypto truncation.

    ``_translate_exception`` is ArchiveStream's translate hook. Mapping IndexError
    there turns a codec/stream off-by-one into ``TruncatedError("Truncated ZipCrypto
    header")`` on an unencrypted DEFLATE member. A bounded ``read(n)`` is the path
    that reaches the translator; ``read()`` (n=-1) hits the fused size verifier's
    opaque-accelerator catch first. A short ZipCrypto header is checked by length in
    the decrypt stage, so no IndexError mapping exists anywhere.
    """
    from archivey.internal.backends import zip_reader

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("x.txt", b"hello world" * 10)

    class _Boom(io.BytesIO):
        def read(self, *args: object, **kwargs: object) -> bytes:
            raise IndexError("index out of range")

    monkeypatch.setattr(zip_reader, "open_codec_raw", _opened_codec_reading_from(_Boom))
    with open_archive(io.BytesIO(buf.getvalue()), format=ArchiveFormat.ZIP) as ar:
        stream = ar.open(next(iter(ar)))
        with pytest.raises(IndexError, match="index out of range"):
            stream.read(10)


def test_member_read_unsupported_operation_other_than_seek_is_not_corruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``io.UnsupportedOperation`` is also a ``ValueError``. One that is not about
    seeking says nothing about the archive, so it propagates as itself instead of
    reaching the ValueError arm, which reports corruption."""
    from archivey.internal.backends import zip_reader

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("x.txt", b"hello world" * 10)

    class _Unsupported(io.BytesIO):
        def read(self, *args: object, **kwargs: object) -> bytes:
            raise io.UnsupportedOperation("read")

    monkeypatch.setattr(
        zip_reader, "open_codec_raw", _opened_codec_reading_from(_Unsupported)
    )
    with open_archive(io.BytesIO(buf.getvalue()), format=ArchiveFormat.ZIP) as ar:
        stream = ar.open(next(iter(ar)))
        with pytest.raises(io.UnsupportedOperation) as excinfo:
            stream.read(10)
    assert type(excinfo.value) is io.UnsupportedOperation


def _symlink_zip(tmp_path: Path) -> Path:
    import stat as stat_module

    path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat_module.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("target.txt", b"payload")
        z.writestr(info, b"target.txt")
    return path


def test_zip_index_only_listing_leaves_symlink_unresolved(tmp_path: Path) -> None:
    path = _symlink_zip(tmp_path)
    with open_archive(path) as ar:
        report = ar.members_report_if_available()
        assert report is not None
        assert report.error is None
        link = next(m for m in report if m.name == "link")
        assert link.link_target is None
        assert link.link_target_member is None

        resolved = ar.members()
        link_resolved = next(m for m in resolved if m.name == "link")
        assert link_resolved.link_target == "target.txt"
        assert link_resolved.link_target_member is not None
        assert link_resolved.link_target_member.name == "target.txt"
        assert ar.read("link") == b"payload"
        ar.extract_all(tmp_path / "out")
        assert (tmp_path / "out" / "target.txt").read_bytes() == b"payload"


def test_compression_method_mapping(tmp_path: Path) -> None:
    path = tmp_path / "methods.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("stored.txt", b"a" * 100, compress_type=zipfile.ZIP_STORED)
        z.writestr("deflated.txt", b"a" * 100, compress_type=zipfile.ZIP_DEFLATED)
    with open_archive(path) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["stored.txt"].compression[0].algo == CompressionAlgorithm.STORED
        assert (
            by_name["deflated.txt"].compression[0].algo == CompressionAlgorithm.DEFLATE
        )


def test_encrypted_flag() -> None:
    # stdlib zipfile cannot write encrypted entries, so set the general-purpose
    # encryption bit (0x1) directly in the central-directory record's flag field (at
    # offset 8 of the PK\x01\x02 record) to exercise the is_encrypted mapping.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("e.txt", b"data")
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    flags = int.from_bytes(raw[cd + 8 : cd + 10], "little") | 0x1
    raw[cd + 8 : cd + 10] = flags.to_bytes(2, "little")
    with open_archive(io.BytesIO(bytes(raw))) as ar:
        assert ar.get("e.txt").is_encrypted is True


def test_size_fields(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        member = ar.get("hello.txt")
        assert member.size == len(b"hello world")
        assert member.compressed_size is not None


def test_raw_name_preserved(tmp_path: Path) -> None:
    path = tmp_path / "utf8.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("café.txt", b"x")  # forces the UTF-8 flag
    with open_archive(path) as ar:
        member = ar.get("café.txt")
        assert member.raw_name == b"caf\xc3\xa9.txt"


def test_extended_timestamp_precedence(tmp_path: Path) -> None:
    # An Extended Timestamp extra field (0x5455) carries a real Unix time and overrides the
    # 2-second-granularity DOS date_time, yielding a tz-aware UTC datetime.
    unix_time = 1_600_000_000  # 2020-09-13T12:26:40Z
    extra = struct.pack("<HHB I", 0x5455, 5, 0x01, unix_time)
    path = tmp_path / "ts.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member.modified is not None
        assert member.modified.tzinfo is not None
        assert member.modified == datetime.fromtimestamp(unix_time, tz=UTC)


def test_unknown_extra_field_before_timestamp(tmp_path: Path) -> None:
    # An unknown extra field (0x1234) preceding the Extended Timestamp (0x5455): the
    # extra-field walk must skip the unknown field by its declared length and still reach
    # and parse the timestamp (regression for the field-walking loop).
    unix_time = 1_600_000_000
    extra = struct.pack("<HH4s", 0x1234, 4, b"abcd") + struct.pack(
        "<HHBI", 0x5455, 5, 0x01, unix_time
    )
    path = tmp_path / "extra.zip"
    info = zipfile.ZipInfo("file.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        assert ar.get("file.txt").modified == datetime.fromtimestamp(unix_time, tz=UTC)


def test_extended_timestamp_fills_mtime_atime_ctime(tmp_path: Path) -> None:
    # An Extended Timestamp (0x5455) with flags 0x07 carries modification, access and
    # "creation" times (in that order). libarchive on Unix fills the third from st_ctime,
    # so from a Unix writer it goes to `ctime` and `created` stays None.
    mtime, atime, ctime = 1_600_000_000, 1_600_000_100, 1_600_000_200
    extra = struct.pack("<HHB iii", 0x5455, 13, 0x07, mtime, atime, ctime)
    path = tmp_path / "ts3.zip"
    info = zipfile.ZipInfo("t.txt")
    info.create_system = 3  # Unix; ZipInfo defaults to the running host
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member.modified == datetime.fromtimestamp(mtime, tz=UTC)
        assert member.accessed == datetime.fromtimestamp(atime, tz=UTC)
        assert member.created is None
        assert member.ctime == datetime.fromtimestamp(ctime, tz=UTC)


def _zip_with_extra(extra: bytes) -> bytes:
    """A one-member ZIP whose local and central headers both carry ``extra``."""
    buf = io.BytesIO()
    info = zipfile.ZipInfo("owned.txt")
    info.create_system = 3
    info.extra = extra
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(info, b"data")
    return buf.getvalue()


def _owner_seen(data: bytes) -> tuple[tuple[int | None, int | None], ...]:
    """The owner a file read lists, then the one the pipe pass gives after its end."""
    with open_archive(io.BytesIO(data)) as ar:
        listed = ar.get("owned.txt")
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        streamed = [member for member, _ in ar.stream_members()]
    return (listed.uid, listed.gid), (streamed[0].uid, streamed[0].gid)


_NEW_UNIX_4 = struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, 1234, 4, 5678)
_UNIX2 = struct.pack("<HHHH", 0x7855, 4, 1234, 5678)


def _pkware_unix(uid: int, gid: int) -> bytes:
    return struct.pack("<HHIIHH", 0x000D, 12, 0, 0, uid, gid)


def _old_unix(uid: int, gid: int) -> bytes:
    return struct.pack("<HHIIHH", 0x5855, 12, 0, 0, uid, gid)


# Each expected owner is what unzip 6.00 gives for the same extra blob in a local
# header (`unzip -X` as root, and its `ef_scan_for_izux`), except where a case says it
# is a central-only form.
@pytest.mark.parametrize(
    ("extra", "owner"),
    [
        pytest.param(_NEW_UNIX_4, (1234, 5678), id="new-unix-4-byte"),
        pytest.param(
            struct.pack("<HHBBHBQ", 0x7875, 13, 1, 2, 1234, 8, 2**40),
            (1234, 2**40),
            id="new-unix-mixed-widths",
        ),
        pytest.param(_pkware_unix(1234, 5678), (1234, 5678), id="pkware-unix"),
        pytest.param(
            _pkware_unix(1, 2) + _NEW_UNIX_4, (1234, 5678), id="new-unix-beats-pkware"
        ),
        pytest.param(
            # A new Unix field of another version is not one this reader knows, and
            # it still decides: unzip gives no owner rather than the next field's.
            struct.pack("<HHBBIBI", 0x7875, 11, 2, 4, 1, 4, 2) + _pkware_unix(3, 4),
            (None, None),
            id="unknown-version-decides",
        ),
        pytest.param(
            # The 16-bit Info-ZIP field's central copy is empty: no ids and no damage,
            # but it still hides a later PKWARE field, as its local copy would.
            struct.pack("<HH", 0x7855, 0) + _pkware_unix(1, 2),
            (None, None),
            id="central-unix2-hides-pkware",
        ),
        pytest.param(
            # The old Info-ZIP field's central copy holds the two times alone.
            _pkware_unix(1234, 5678) + struct.pack("<HHII", 0x5855, 8, 0, 0),
            (1234, 5678),
            id="central-old-unix-is-absent",
        ),
        pytest.param(
            # A PKWARE or old Info-ZIP field that cannot give ids changes nothing.
            _pkware_unix(1, 2) + struct.pack("<HHIIH", 0x5855, 10, 0, 0, 9),
            (1, 2),
            id="short-old-unix-after-pkware",
        ),
        pytest.param(
            _pkware_unix(1, 2) + struct.pack("<HHIIH", 0x000D, 10, 0, 0, 9),
            (1, 2),
            id="short-pkware-after-pkware",
        ),
        pytest.param(_pkware_unix(1, 2) + _pkware_unix(3, 4), (3, 4), id="last-pkware"),
        pytest.param(
            _UNIX2 + struct.pack("<HHHH", 0x7855, 4, 7, 8), (7, 8), id="last-unix2"
        ),
        pytest.param(
            # A new Unix field decides afresh, so a later readable one wins over a
            # damaged one, and an unknown version after a readable one leaves none.
            struct.pack("<HHBBI", 0x7875, 6, 1, 4, 9) + _NEW_UNIX_4,
            (1234, 5678),
            id="new-unix-after-short-new-unix",
        ),
        pytest.param(
            _NEW_UNIX_4 + struct.pack("<HHBBIBI", 0x7875, 11, 2, 4, 1, 4, 2),
            (None, None),
            id="unknown-version-after-new-unix",
        ),
        pytest.param(
            # PKWARE's field with its two times only is its central form, as for
            # 0x5855: no ids, nothing damaged.
            struct.pack("<HHII", 0x000D, 8, 0, 0),
            (None, None),
            id="pkware-times-only",
        ),
        pytest.param(
            _NEW_UNIX_4 + struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, 21, 4, 22),
            (21, 22),
            id="last-new-unix-wins",
        ),
        pytest.param(b"", (None, None), id="no-extra"),
    ],
)
def test_unix_owner_extra_fields(
    extra: bytes, owner: tuple[int | None, int | None]
) -> None:
    # Info-ZIP's zip writes 0x7875 on Unix by default; 0x000d comes from PKWARE. No
    # ZIP field records owner names.
    data = _zip_with_extra(extra)
    assert _owner_seen(data) == (owner, owner)
    with open_archive(io.BytesIO(data)) as ar:
        member = ar.get("owned.txt")
        assert member.uname is None
        assert member.gname is None
        assert member.diagnostics == ()


@pytest.mark.parametrize(
    ("extra", "owner"),
    [
        pytest.param(_UNIX2, (1234, 5678), id="unix-type-2"),
        pytest.param(_old_unix(1234, 5678), (1234, 5678), id="old-unix"),
        pytest.param(
            _pkware_unix(1, 2) + _UNIX2, (1234, 5678), id="unix2-beats-pkware"
        ),
        pytest.param(
            _UNIX2 + struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, 11, 4, 12),
            (11, 12),
            id="new-unix-beats-unix2",
        ),
        pytest.param(
            _pkware_unix(1, 2) + _old_unix(5, 6), (5, 6), id="pkware-then-old-unix"
        ),
        pytest.param(
            _old_unix(5, 6) + _pkware_unix(1, 2), (1, 2), id="old-unix-then-pkware"
        ),
    ],
)
def test_local_only_owner_fields_are_read_from_a_writer_that_copies_them(
    extra: bytes, owner: tuple[int, int]
) -> None:
    # A writer that copies the 16-bit Info-ZIP fields into the directory too gets them
    # read there; a file read and the end of a pipe pass give the same owner.
    data = _zip_with_extra(extra)
    with open_archive(io.BytesIO(data)) as ar:
        assert (ar.get("owned.txt").uid, ar.get("owned.txt").gid) == owner
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        (final,) = [member for member, _ in ar.stream_members()]
    assert (final.uid, final.gid) == owner


@pytest.mark.parametrize(
    ("field", "reason", "tag"),
    [
        pytest.param(
            struct.pack("<HHBBIB", 0x7875, 11, 1, 4, 1234, 4) + b"\x2e\x16",
            "cut_short",
            0x7875,
            id="new-unix-cut-short",
        ),
        pytest.param(
            struct.pack("<HHBBI", 0x7875, 6, 1, 4, 1234),
            "too_short",
            0x7875,
            id="no-gid",
        ),
        pytest.param(
            struct.pack("<HHBB9sBI", 0x7875, 16, 1, 9, b"\x01" * 9, 4, 2),
            "id_size",
            0x7875,
            id="new-unix-id-too-wide",
        ),
        pytest.param(
            struct.pack("<HHIIH", 0x000D, 10, 0, 0, 1234),
            "too_short",
            0x000D,
            id="pkware-short",
        ),
        pytest.param(
            # A damaged 0x7855 hides a later PKWARE field: unzip gives no owner.
            struct.pack("<HHH", 0x7855, 2, 3) + _pkware_unix(1, 2),
            "wrong_size",
            0x7855,
            id="unix2-short",
        ),
        pytest.param(
            struct.pack("<HHHHH", 0x7855, 6, 1, 2, 3),
            "wrong_size",
            0x7855,
            id="unix2-too-long",
        ),
        pytest.param(
            # A 0x7855 or 0x7875 decides afresh, so a damaged one after PKWARE's
            # leaves no owner, as unzip 6.00 gives none.
            _pkware_unix(1, 2) + struct.pack("<HHH", 0x7855, 2, 9),
            "wrong_size",
            0x7855,
            id="short-unix2-after-pkware",
        ),
        pytest.param(
            _pkware_unix(1, 2) + struct.pack("<HHBBI", 0x7875, 6, 1, 4, 9),
            "too_short",
            0x7875,
            id="short-new-unix-after-pkware",
        ),
        pytest.param(
            _NEW_UNIX_4 + struct.pack("<HHBBI", 0x7875, 6, 1, 4, 9),
            "too_short",
            0x7875,
            id="short-new-unix-after-new-unix",
        ),
        pytest.param(
            struct.pack("<HHBB3sB3s", 0x7875, 9, 1, 3, b"\x07\0\0", 3, b"\x08\0\0"),
            "id_size",
            0x7875,
            id="new-unix-3-byte-ids",
        ),
    ],
)
def test_damaged_owner_field_is_dropped_with_a_diagnostic(
    field: bytes, reason: str, tag: int
) -> None:
    data = _zip_with_extra(field)
    with open_archive(io.BytesIO(data)) as ar:
        member = ar.get("owned.txt")
        assert (member.uid, member.gid) == (None, None)
        (diagnostic,) = member.diagnostics
    assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
    assert diagnostic.context.record == "unix_owner"
    assert diagnostic.context.record_id == tag
    assert diagnostic.context.reason == reason
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(io.BytesIO(data), config=strict) as ar,
    ):
        ar.members()


def _local_only_owner_zip(field: bytes) -> bytes:
    """A ZIP whose local header carries owner ``field`` and whose directory has none."""
    data = _zip_with_extra(field)
    central_at = data.rindex(field)
    return data[:central_at] + struct.pack("<H", 0x1234) + data[central_at + 2 :]


_LOCAL_ONLY_OWNERS = [
    pytest.param(_local_only_owner_zip(_UNIX2), (None, None), id="local-only-unix2"),
    pytest.param(
        _local_only_owner_zip(_NEW_UNIX_4), (None, None), id="local-only-new-unix"
    ),
    pytest.param(_zip_with_extra(_NEW_UNIX_4), (1234, 5678), id="both-new-unix"),
]


@pytest.mark.parametrize(("data", "owner"), _LOCAL_ONLY_OWNERS)
def test_pass_yields_no_owner_until_the_directory(
    data: bytes, owner: tuple[int | None, int | None]
) -> None:
    # Extraction applies an owner as it writes a member, and a chown cannot be taken
    # back if the directory gives another owner or none. So the pass yields none, and
    # the member gets the directory's at the end of the pass, as a file read lists it.
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        during = [(m.uid, m.gid) for m, _ in ar.stream_members()]
    assert during == [(None, None)]
    assert _owner_seen(data) == (owner, owner)


@pytest.mark.parametrize("piped", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(("data", "owner"), _LOCAL_ONLY_OWNERS)
def test_trusted_applies_the_directory_owner_from_a_pipe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
    owner: tuple[int | None, int | None],
    piped: bool,
) -> None:
    # Runs without root: it records what extraction hands to the metadata step, the
    # one that chowns as root. From a pipe the member is placed once the directory
    # is read, so the only owner applied is the directory's, as from a file.
    from archivey.internal.extraction import ExtractionCoordinator

    applied: list[tuple[int | None, int | None]] = []
    original = ExtractionCoordinator._apply_metadata

    def record(
        self: ExtractionCoordinator, path: Path | int, member: ArchiveMember
    ) -> None:
        applied.append((member.uid, member.gid))
        original(self, path, member)

    monkeypatch.setattr(ExtractionCoordinator, "_apply_metadata", record)
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    with open_archive(source, streaming=piped) as ar:
        ar.extract_all(tmp_path / "out", policy=ExtractionPolicy.TRUSTED)
    assert applied == [owner]


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="chown to another uid needs root",
)
@pytest.mark.parametrize("piped", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(("data", "owner"), _LOCAL_ONLY_OWNERS)
def test_trusted_as_root_owner_matches_from_a_pipe(
    tmp_path: Path, data: bytes, owner: tuple[int | None, int | None], piped: bool
) -> None:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    dest = tmp_path / "out"
    with open_archive(source, streaming=piped) as ar:
        ar.extract_all(dest, policy=ExtractionPolicy.TRUSTED)
    st = (dest / "owned.txt").stat()
    expected = (os.geteuid(), os.getegid()) if owner == (None, None) else owner
    assert (st.st_uid, st.st_gid) == expected


@requires_binary("zip")
def test_info_zip_records_the_owner(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"data")
    archive = tmp_path / "a.zip"
    subprocess.run(["zip", "-q", str(archive), "a.txt"], cwd=tmp_path, check=True)
    st = (tmp_path / "a.txt").stat()
    with open_archive(archive) as ar:
        member = ar.get("a.txt")
        assert (member.uid, member.gid) == (st.st_uid, st.st_gid)


def test_duplicate_member_names_read_independently(tmp_path: Path) -> None:
    # Two members stored under the same name: each must read its own data. The reader keys
    # off the member's own ZipInfo handle (member._raw), not a name map, so there is no
    # collision.
    path = tmp_path / "dup.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("dup.txt", b"first")
        z.writestr("dup.txt", b"second")
    with open_archive(path) as ar:
        members = ar.members()
        assert len(members) == 2
        assert ar.read(members[0]) == b"first"
        assert ar.read(members[1]) == b"second"


# ---------------------------------------------------------------------------
# Non-seekable source fails fast
# ---------------------------------------------------------------------------


def test_non_seekable_zip_fails_fast(simple_zip: Path) -> None:
    data = simple_zip.read_bytes()
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(data), format=ArchiveFormat.ZIP)


def test_non_seekable_zip_fails_fast_via_detection(simple_zip: Path) -> None:
    # Even without an explicit format, a non-seekable ZIP opened for random access is
    # rejected at open time (the source's replay prefix serves detection, then the opener
    # enforces the source rule), and the message names the mode that works. The message
    # is asserted here as well as in tests/test_non_seekable_refusal.py, which reaches the
    # same branch with an explicit format= and no archive bytes: if a refactor ever moved
    # the check after detection I/O, the two entry points could diverge and a type-only
    # assertion would not notice.
    data = simple_zip.read_bytes()
    with pytest.raises(StreamNotSeekableError) as excinfo:
        open_archive(NonSeekableBytesIO(data))
    assert "streaming=True" in str(excinfo.value)


def test_non_seekable_zip_opens_via_detection_when_streaming(simple_zip: Path) -> None:
    data = simple_zip.read_bytes()
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        assert reader.format is ArchiveFormat.ZIP
        assert sum(1 for _ in reader.stream_members()) > 0


# ---------------------------------------------------------------------------
# Multi-volume: 7-Zip .zip.NNN byte slices join; Info-ZIP .zNN spanned sets refuse
# ---------------------------------------------------------------------------


def _stdlib_zip_bytes(name: str = "big.bin", payload: bytes = b"x" * 64) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr(name, payload)
    return buf.getvalue()


def _patch_eocd_disk_fields(
    data: bytes, *, this_disk: int, cd_start_disk: int
) -> bytes:
    """Patch classic EOCD uint16 disk fields (offsets +4 / +6 from PK\\x05\\x06)."""
    raw = bytearray(data)
    sig = raw.rfind(b"PK\x05\x06")
    assert sig >= 0, "EOCD signature not found"
    struct.pack_into("<HH", raw, sig + 4, this_disk, cd_start_disk)
    return bytes(raw)


def test_split_segment_name_rejected(tmp_path: Path) -> None:
    # A .z01 segment of a split set is rejected by name as an unsupported multi-volume ZIP.
    segment = tmp_path / "archive.z01"
    segment.write_bytes(b"\x50\x4b\x03\x04" + b"\x00" * 64)
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        open_archive(segment, format=ArchiveFormat.ZIP)
    assert "multi-volume" in str(excinfo.value).lower()

    # Middle Info-ZIP parts have no magic at offset 0; refuse by filename before detection.
    middle = tmp_path / "archive.z02"
    middle.write_bytes(b"\x00" * 64)
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        open_archive(middle)
    assert "multi-volume" in str(excinfo.value).lower()

    # Info-ZIP continues past .z99 as .z100, .z101, … — still a split segment.
    high = tmp_path / "archive.z100"
    high.write_bytes(b"\x00" * 64)
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        open_archive(high)
    assert "multi-volume" in str(excinfo.value).lower()


def test_sevenzip_split_segment_without_siblings_rejected(tmp_path: Path) -> None:
    # A 7-Zip .zip.NNN part whose siblings are not on disk cannot be rejoined.
    # Each file gets its own directory so no set can be discovered around it.
    first = tmp_path / "alone" / "archive.zip.001"
    first.parent.mkdir()
    first.write_bytes(_stdlib_zip_bytes())
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set") as excinfo:
        open_archive(first)
    assert "found part 1 only" in str(excinfo.value)
    assert "archive.zip.002" in str(excinfo.value)

    later = tmp_path / "orphan" / "archive.zip.003"
    later.parent.mkdir()
    later.write_bytes(b"\x00" * 64)  # no magic at 0
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set") as excinfo:
        open_archive(later)
    assert "found part 3 only" in str(excinfo.value)
    assert "archive.zip.001" in str(excinfo.value)
    assert "archive.zip.002" in str(excinfo.value)


def test_volume_shaped_name_honours_explicit_non_zip_format(tmp_path: Path) -> None:
    # A volume-shaped suffix must not override an explicit non-ZIP format= (P8).
    # Real tar.gz bytes under a .z01 / .zip.001 name still open when the caller asserts TAR_GZ.
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="hello.txt")
        payload = b"hello"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    raw = buf.getvalue()

    z01 = tmp_path / "payload.z01"
    z01.write_bytes(raw)
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        open_archive(z01)
    assert "multi-volume" in str(excinfo.value).lower()
    with open_archive(z01, format=ArchiveFormat.TAR_GZ) as ar:
        assert [m.name for m in ar.members()] == ["hello.txt"]
        assert ar.read("hello.txt") == b"hello"

    numbered = tmp_path / "payload.zip.001"
    numbered.write_bytes(raw)
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set"):
        open_archive(numbered)
    with open_archive(numbered, format=ArchiveFormat.TAR_GZ) as ar:
        assert [m.name for m in ar.members()] == ["hello.txt"]
        assert ar.read("hello.txt") == b"hello"


def _build_sevenzip_split_zip(tmp_path: Path) -> tuple[Path, bytes]:
    """Build a real ``7z a -tzip -mx0 -v40k`` set; return part 1 and the big member.

    ``-mx0`` stores, so ``big.bin`` is larger than one volume and its data necessarily
    crosses part boundaries — the case a rejoin that read each part independently
    would get wrong.
    """
    payload = bytes(range(256)) * 600  # 153_600 B across 40 KiB volumes -> 4 parts
    (tmp_path / "big.bin").write_bytes(payload)
    (tmp_path / "small.txt").write_bytes(b"tail\n")
    subprocess.run(
        ["7z", "a", "-tzip", "-mx0", "-v40k", "set.zip", "big.bin", "small.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return tmp_path / "set.zip.001", payload


@requires_binary("7z")
def test_sevenzip_split_zip_set_is_joined_and_read(tmp_path: Path) -> None:
    # 7-Zip's -v is a raw byte split, not a spanned set: the parts concatenate back
    # into an ordinary single-volume ZIP, exactly as they do for .7z.NNN.
    first, payload = _build_sevenzip_split_zip(tmp_path)
    assert (tmp_path / "set.zip.004").is_file(), "fixture must have several parts"

    with open_archive(first) as archive:
        assert {m.name for m in archive.members()} == {"big.bin", "small.txt"}
        assert archive.read("big.bin") == payload
        assert archive.read("small.txt") == b"tail\n"

        info = archive.info
        assert info.is_multivolume is True
        assert info.extra.get("zip.volume_count") == 4
        assert archive.cost.listing_cost == ListingCost.INDEXED
        assert archive.cost.access_cost == AccessCost.DIRECT
        assert archive.cost.stream_capability == StreamCapability.SEEKABLE


@requires_binary("7z")
def test_sevenzip_split_zip_set_opens_from_a_middle_part(tmp_path: Path) -> None:
    # A middle part carries no ZIP magic at offset 0; the set is anchored by name,
    # not by which part the caller happened to hand us.
    _, payload = _build_sevenzip_split_zip(tmp_path)
    with open_archive(tmp_path / "set.zip.002") as archive:
        assert archive.read("big.bin") == payload


@requires_binary("7z")
def test_sevenzip_split_zip_set_with_missing_part_is_truncated(tmp_path: Path) -> None:
    first, _ = _build_sevenzip_split_zip(tmp_path)
    (tmp_path / "set.zip.002").unlink()
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set"):
        open_archive(first)


def test_infozip_spanned_set_still_refused(tmp_path: Path) -> None:
    """Info-ZIP ``.z01 … .zip`` keeps refusing, siblings present or not.

    ``zip -s`` writes a true spanned set: entries are addressed by (disk, offset), so a
    linear join lists correctly and then reads only whichever members happen to sit on
    the last disk. That makes it a different thing from 7-Zip's byte slices however alike
    the two look from outside. Synthesised
    rather than built with ``zip -s`` because Info-ZIP is not installed on CI, macOS
    or Windows — a real fixture would skip everywhere and prove nothing.
    """
    # .z01 opens with the spanning marker; middle parts carry no signature at all;
    # the final .zip holds the central directory and names a non-zero disk.
    (tmp_path / "set.z01").write_bytes(b"PK\x07\x08" + b"\x00" * 64)
    (tmp_path / "set.z02").write_bytes(b"\x00" * 64)
    (tmp_path / "set.zip").write_bytes(
        _patch_eocd_disk_fields(_stdlib_zip_bytes(), this_disk=2, cd_start_disk=2)
    )
    for name in ("set.z01", "set.z02", "set.zip"):
        with pytest.raises(UnsupportedFeatureError) as excinfo:
            open_archive(tmp_path / name)
        assert "multi-volume" in str(excinfo.value).lower(), name


@pytest.mark.parametrize(
    ("this_disk", "cd_start_disk"),
    [
        (7, 0),
        (0, 7),
        (7, 7),
    ],
    ids=["this_disk", "cd_start_disk", "both"],
)
def test_eocd_nonzero_disk_fields_rejected(
    tmp_path: Path, this_disk: int, cd_start_disk: int
) -> None:
    # Info-ZIP's final .zip part carries the CD + EOCD with this_disk / cd_start_disk
    # equal to the last data volume index. Byte-equivalent: patch those EOCD fields.
    path = tmp_path / "set.zip"
    path.write_bytes(
        _patch_eocd_disk_fields(
            _stdlib_zip_bytes(), this_disk=this_disk, cd_start_disk=cd_start_disk
        )
    )
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        open_archive(path)
    assert "multi-volume" in str(excinfo.value).lower()


def _genuine_zip64_bytes(
    *,
    name: bytes = b"a.txt",
    payload: bytes = b"hello",
    classic_this_disk: int = 0xFFFF,
    classic_cd_start_disk: int = 0xFFFF,
    zip64_this_disk: int = 0,
    zip64_cd_start_disk: int = 0,
) -> bytes:
    """Craft a ZIP with real ZIP64 EOCD + locator (not just force_zip64 LFH extras)."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    lfh = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            45,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name),
            0,
        )
        + name
        + payload
    )
    cdh = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            0x2D00,
            45,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    z64_body = struct.pack(
        "<HHIIQQQQ",
        45,
        45,
        zip64_this_disk,
        zip64_cd_start_disk,
        1,
        1,
        len(cdh),
        len(lfh),
    )
    z64 = struct.pack("<IQ", 0x06064B50, len(z64_body)) + z64_body
    locator = struct.pack("<IIQI", 0x07064B50, 0, len(lfh) + len(cdh), 1)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        classic_this_disk,
        classic_cd_start_disk,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return lfh + cdh + z64 + locator + eocd


def test_eocd_zip64_disk_sentinel_still_opens(tmp_path: Path) -> None:
    # 0xFFFF in classic EOCD disk fields is the ZIP64 sentinel. Prove it against an
    # archive that actually has ZIP64 EOCD + locator (force_zip64 alone does not).
    raw = _genuine_zip64_bytes()
    assert b"PK\x06\x06" in raw and b"PK\x06\x07" in raw
    path = tmp_path / "zip64_sentinel.zip"
    path.write_bytes(raw)
    with open_archive(path) as ar:
        assert ar.read("a.txt") == b"hello"


@pytest.mark.parametrize(
    ("this_disk", "cd_start_disk"),
    [(2, 0), (0, 2)],
    ids=["this_disk", "cd_start_disk"],
)
def test_zip64_end_record_nonzero_disk_fields_rejected(
    this_disk: int, cd_start_disk: int
) -> None:
    # The ZIP64 end record's disk fields replace the classic record's 0xFFFF sentinels,
    # so a split set's last part is refused there too.
    raw = _genuine_zip64_bytes(
        zip64_this_disk=this_disk, zip64_cd_start_disk=cd_start_disk
    )
    with pytest.raises(UnsupportedFeatureError, match="(?i)multi-volume"):
        open_archive(io.BytesIO(raw))


def test_plain_prefixed_and_empty_zip_still_open(tmp_path: Path) -> None:
    plain = tmp_path / "plain.zip"
    plain.write_bytes(_stdlib_zip_bytes("a.txt", b"hi"))
    with open_archive(plain) as ar:
        assert ar.read("a.txt") == b"hi"

    prefixed = tmp_path / "prefixed.zip"
    prefixed.write_bytes(b"#!/bin/sh\necho stub\n" + _stdlib_zip_bytes("a.txt", b"hi"))
    with open_archive(prefixed) as ar:
        assert ar.read("a.txt") == b"hi"

    # Empty ZIP: EOCD present, nothing else — sharp false-positive for disk-field checks.
    bare_eocd = tmp_path / "bare_eocd.zip"
    bare_eocd.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    with open_archive(bare_eocd) as ar:
        assert ar.members() == []

    empty = tmp_path / "empty.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    empty.write_bytes(buf.getvalue())
    with open_archive(empty) as ar:
        assert ar.members() == []


# ---------------------------------------------------------------------------
# Reading via open() and stream_members()
# ---------------------------------------------------------------------------


def test_open_returns_stream(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar, ar.open("hello.txt") as f:
        assert f.read() == b"hello world"


def test_stream_members(simple_zip: Path) -> None:
    with open_archive(simple_zip) as ar:
        collected = {}
        for member, stream in ar.stream_members():
            collected[member.name] = stream.read() if stream is not None else None
        assert collected["hello.txt"] == b"hello world"
        assert collected["dir/nested.txt"] == b"nested content"


def test_read_roundtrip_from_stream_source(simple_zip: Path) -> None:
    # Opening from an already-seekable in-memory stream (no path) works too.
    data = simple_zip.read_bytes()
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.read("hello.txt") == b"hello world"


def test_concurrent_open_members_interleaved_path_source(simple_zip: Path) -> None:
    # Path source: stdlib zipfile's _SharedFile already coordinates; lock the contract in.
    with open_archive(simple_zip, concurrent_operations=True) as ar:
        s1 = ar.open("hello.txt")
        s2 = ar.open("dir/nested.txt")
        assert s1.read(5) == b"hello"
        assert s2.read(6) == b"nested"
        assert s1.read() == b" world"
        assert s2.read() == b" content"
        s1.close()
        s2.close()


def test_concurrent_open_members_interleaved_stream_source(simple_zip: Path) -> None:
    # Stream source: stdlib zipfile coordinates a passed-in handle exactly like a path
    # source (_SharedFile keeps a per-open position under ZipFile's lock), so archivey
    # adds no wrap; this test locks the concurrent-open contract in for that leg too.
    data = simple_zip.read_bytes()
    with open_archive(io.BytesIO(data), concurrent_operations=True) as ar:
        s1 = ar.open("hello.txt")
        s2 = ar.open("dir/nested.txt")
        assert s1.read(5) == b"hello"
        assert s2.read(6) == b"nested"
        assert s1.read() == b" world"
        assert s2.read() == b" content"
        s1.close()
        s2.close()


def test_read_after_source_close_raises_typed_error() -> None:
    # archive-reading "fail loudly" scenario: once the caller's source stream is closed,
    # reading a still-open member stream surfaces a typed error at the reader boundary —
    # not a raw ValueError, and not a misleading CorruptionError. The member must exceed
    # ZipExtFile's read-ahead so the second read actually touches the closed source.
    payload = bytes(range(256)) * 1024  # 256 KiB, incompressible-ish and > read-ahead
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", payload)
    source = io.BytesIO(buf.getvalue())
    with open_archive(source) as ar:
        stream = ar.open("big.bin")
        assert stream.read(16) == payload[:16]
        source.close()
        with pytest.raises(ArchiveyUsageError):
            while stream.read(65536):
                pass
        with contextlib.suppress(Exception):
            stream.close()


# ---------------------------------------------------------------------------
# Corrupt / truncated input -> CorruptionError (with the original cause attached).
# (Per-format slice of testing-contract's adversarial-corpus requirement, pulled
# forward to lock down the backend's exception translation as it lands.)
# ---------------------------------------------------------------------------


def test_truncated_zip_lists_its_cut_member_then_raises() -> None:
    # A ZIP cut inside its only member's data: no end record is left, so the member is
    # listed from its local header, and the listing and its read raise the cut.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("hello.txt", b"hello world" * 100)
    truncated = buf.getvalue()[: len(buf.getvalue()) // 2]

    with open_archive(io.BytesIO(truncated)) as reader:
        report = reader.members_report()
        (member,) = report.members
        assert member.name == "hello.txt"
        assert isinstance(report.error, TruncatedError)
        assert "inside member #0's data" in str(report.error)
        with pytest.raises(TruncatedError, match="inside member #0's data"):
            reader.read(member)


def test_corrupt_member_data_raises_corruption_on_read() -> None:
    # A structurally valid ZIP whose stored member payload has been altered: listing
    # succeeds, but reading the member trips the CRC check -> CorruptionError.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("data.txt", b"A" * 200)
    raw = bytearray(buf.getvalue())
    # STORED payload begins after the 30-byte local header + 8-byte name ("data.txt").
    raw[50] ^= 0xFF

    with open_archive(io.BytesIO(bytes(raw))) as ar:
        assert ar.members()[0].name == "data.txt"  # listing is unaffected
        with raises_corruption_not_truncation():
            ar.read("data.txt")


def test_non_utf8_local_header_name_is_reported_as_another_name() -> None:
    """A local header whose name bytes differ from the central directory's is read by
    the directory's name and reported. The names compare as bytes, so a local name
    that is not UTF-8 under the UTF-8 flag is never decoded, and the report gives
    its bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("data.txt", b"A" * 200)
    raw = bytearray(buf.getvalue())
    raw[6:8] = struct.pack("<H", struct.unpack_from("<H", raw, 6)[0] | 0x800)
    raw[30] = 0xFF  # first byte of the local name; the central name is untouched

    with open_archive(io.BytesIO(bytes(raw))) as ar:
        (member,) = ar.members()
        assert member.name == "data.txt"
        assert member.diagnostics == ()
        assert ar.read(member) == b"A" * 200
    (reported,) = member.diagnostics
    assert reported.code is DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS
    assert reported.context.field == "name"
    assert reported.context.local_raw_name_base64 == raw_name_to_base64(b"\xffata.txt")
    assert r"'\xffata.txt'" in reported.message


def _overlapping_entries_zip() -> bytes:
    """A Fifield-style overlap bomb: many central-directory entries whose data spans
    overlap a single shared compressed kernel (https://www.bamsoftware.com/hacks/zipbomb/).

    archivey computes each entry's data bound itself (``_DataBounds``) and raises
    ``CorruptionError("Overlapped entries ...")`` when a member opens.
    """
    import zlib

    n = 8
    raw = b"\x00" * (1024 * 1024)
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = comp.compress(raw) + comp.flush()
    crc, csize, usize = zlib.crc32(raw) & 0xFFFFFFFF, len(blob), len(raw)

    buf = io.BytesIO()
    names = [f"f{i}".encode() for i in range(n)]
    offsets = []
    for nm in names:  # adjacent local headers, each claiming the shared csize
        offsets.append(buf.tell())
        buf.write(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                0,
                8,
                0,
                0,
                crc,
                csize,
                usize,
                len(nm),
                0,
            )
        )
        buf.write(nm)
    buf.write(
        blob
    )  # one shared kernel; every entry's data span overruns the next header

    cd_start = buf.tell()
    for nm, off in zip(names, offsets):
        buf.write(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                8,
                0,
                0,
                crc,
                csize,
                usize,
                len(nm),
                0,
                0,
                0,
                0,
                0,
                off,
            )
        )
        buf.write(nm)
    cd_size = buf.tell() - cd_start
    buf.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n, cd_size, cd_start, 0))
    return buf.getvalue()


def test_overlapping_entries_bomb_translated_to_corruption() -> None:
    # The overlap guard is an open-time check, not a read-time one, so it exercises a path
    # distinct from the CRC check above. Every overlapping member must surface as a
    # CorruptionError naming the overlap.
    data = _overlapping_entries_zip()
    with open_archive(io.BytesIO(data)) as ar:
        overlapping = [m for m in ar.members() if m.name != "f7"]  # last entry is valid
        assert overlapping, "expected the crafted archive to list overlapping members"
        for member in overlapping:
            with raises_corruption_not_truncation() as excinfo:
                ar.read(member)
            assert "Overlapped entries" in str(excinfo.value)


def test_entries_sharing_one_local_header_read_only_once() -> None:
    # Two central directory entries that point at the same local header. The first in
    # directory order reads; the second is an overlap. stdlib raises on 3.11, on 3.12
    # before 3.12.10 and on 3.13 before 3.13.3; 3.12.10+, 3.13.3+ and 3.14 warn and read
    # both. archivey keeps refusing: many entries over one local header is the
    # overlapping-entry amplification shape (DR-9a).
    raw = bytearray(_stdlib_zip_bytes("a.txt", b"hello"))
    cd = raw.index(b"PK\x01\x02")
    eocd = raw.rindex(b"PK\x05\x06")
    entry = bytes(raw[cd:eocd])
    raw[eocd:eocd] = entry
    eocd += len(entry)
    struct.pack_into("<HHI", raw, eocd + 8, 2, 2, 2 * len(entry))
    with open_archive(io.BytesIO(bytes(raw))) as ar:
        first, second = ar.members()
        assert ar.read(first) == b"hello"
        with raises_corruption_not_truncation(match="Overlapped entries"):
            ar.read(second)


def _second_entry_over_the_first_header() -> bytes:
    """Three STORED members; the second directory entry points at the first local
    header, which stores the name ``m0.txt``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        for name in ("m0.txt", "m1.txt", "m2.txt"):
            z.writestr(name, name.encode())
    raw = bytearray(buf.getvalue())
    second = raw.index(b"PK\x01\x02", raw.index(b"PK\x01\x02") + 4)
    struct.pack_into("<I", raw, second + 42, 0)
    return bytes(raw)


@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
def test_an_overlapping_entry_with_another_name_reports_only_the_overlap(
    strict: bool,
) -> None:
    # The overlap guard refuses the read before the name check runs: no
    # MEMBER_LOCAL_NAME_DIFFERS for a read that does not go ahead, and STRICT
    # raises the overlap, not the name difference.
    policy = DiagnosticPolicy.STRICT if strict else DiagnosticPolicy()
    config = ArchiveyConfig(diagnostic_policy=policy)
    data = _second_entry_over_the_first_header()
    with open_archive(io.BytesIO(data), config=config) as ar:
        m1 = ar.members()[1]
        assert m1.name == "m1.txt"
        with raises_corruption_not_truncation(match="Overlapped entries"):
            ar.read(m1)
        assert DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS not in ar.diagnostics.counts


def test_an_overlapping_entry_fails_alone_under_strict_and_continue(
    tmp_path: Path,
) -> None:
    # The overlap refusal is a per-member CorruptionError, not the always-stop
    # DiagnosticRaisedError a STRICT name report would raise, so OnError.CONTINUE
    # extracts the members around it.
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    data = _second_entry_over_the_first_header()
    with open_archive(io.BytesIO(data), config=config) as ar:
        report = ar.extract_all(tmp_path / "out", on_error="continue")
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses == {
        "m0.txt": ExtractionStatus.EXTRACTED,
        "m1.txt": ExtractionStatus.FAILED,
        "m2.txt": ExtractionStatus.EXTRACTED,
    }
    assert (tmp_path / "out" / "m0.txt").read_bytes() == b"m0.txt"
    assert (tmp_path / "out" / "m2.txt").read_bytes() == b"m2.txt"
    assert not (tmp_path / "out" / "m1.txt").exists()


# ---------------------------------------------------------------------------
# Encrypted symlink targets and explicit metadata encoding
# ---------------------------------------------------------------------------


def _flag_first_entry_encrypted(data: bytes) -> bytes:
    """Set bit 0 (encryption) of the general-purpose flags in both headers."""
    raw = bytearray(data)
    raw[raw.find(b"PK\x03\x04") + 6] |= 1
    raw[raw.find(b"PK\x01\x02") + 8] |= 1
    return bytes(raw)


def test_encrypted_symlink_listing_without_password() -> None:
    # A symlink's target is its (encrypted) file data; listing must still succeed with
    # link_target unset — not leak zipfile's raw RuntimeError("password required").
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("link")
        info.create_system = 3  # Unix
        info.external_attr = 0o120777 << 16  # symlink mode
        z.writestr(info, b"target.txt")
    data = _flag_first_entry_encrypted(buf.getvalue())

    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        (member,) = reader.members()
        assert member.type is MemberType.SYMLINK
        assert member.is_encrypted
        assert member.link_target is None


# PKWARE Strong Encryption (APPNOTE §7). No real archive of this kind is in the
# corpora, so these are ZipCrypto members re-flagged the way PKZIP marks SES members.
_SES_EXTRA = struct.pack("<HH", 0x0017, 8) + bytes(8)


@pytest.mark.parametrize(
    ("extra_flags", "extra"),
    [
        pytest.param(0x40, b"", id="bit6"),
        pytest.param(0, _SES_EXTRA, id="extra-0x0017"),
        pytest.param(0x40, _SES_EXTRA, id="both"),
    ],
)
@pytest.mark.parametrize("password", [None, "pw"])
def test_strong_encryption_member_is_unsupported(
    extra_flags: int, extra: bytes, password: str | None
) -> None:
    data = build_zipcrypto_zip(
        b"pw",
        b"secret.txt",
        b"payload",
        compression=zipfile.ZIP_STORED,
        extra_flags=extra_flags,
        extra=extra,
    )
    with open_archive(io.BytesIO(data), password=password) as reader:
        (member,) = reader.members()
        assert member.is_encrypted
        with pytest.raises(UnsupportedFeatureError, match="Strong Encryption"):
            reader.open(member)


def test_zipcrypto_member_with_unrelated_extra_still_reads() -> None:
    # The Strong Encryption extra-field walk must step over other records whole. The
    # mtime of this extended-timestamp record (0x5455) begins with the bytes 17 00, so a
    # walk that lands inside the record's data reads a 0x0017 tag there.
    timestamp = struct.pack("<HH", 0x5455, 5) + b"\x01" + struct.pack("<i", 0x80017)
    data = build_zipcrypto_zip(
        b"pw",
        b"secret.txt",
        b"payload",
        compression=zipfile.ZIP_STORED,
        extra=timestamp,
    )
    with open_archive(io.BytesIO(data), password="pw") as reader:
        assert reader.read("secret.txt") == b"payload"


def test_strong_encryption_symlink_lists_with_target_unset() -> None:
    data = build_zipcrypto_zip(
        b"pw",
        b"link",
        b"target.txt",
        compression=zipfile.ZIP_STORED,
        unix_mode=0o120777,
        extra_flags=0x40,
    )
    with open_archive(io.BytesIO(data), password="pw") as reader:
        (member,) = reader.members()
        assert member.type is MemberType.SYMLINK
        assert member.link_target is None
        (diag,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        assert diag.context.reason == "target_data_encrypted"


def _zip_with_encrypted_directory() -> bytes:
    """A one-member ZIP whose central directory reads as Strong-Encryption encrypted.

    Strong Encryption can encrypt the central directory; an archive extra data record
    (PK\\x06\\x08) then sits where stdlib expects PK\\x01\\x02. The EOCD offsets stay
    valid: the directory's bytes are replaced by such a record plus opaque bytes of the
    same total length.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"data")
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    eocd = raw.rindex(b"PK\x05\x06")
    body = eocd - cd - 8
    raw[cd:eocd] = b"PK\x06\x08" + struct.pack("<I", body) + bytes([0xA5]) * body
    return bytes(raw)


# A self-extractor stub whose EOCD offsets were left unadjusted: the offset the EOCD
# records then points into the stub, and only the EOCD position minus the directory
# size (where stdlib reads) finds the directory.
_STUB = b"#!/bin/sh\necho stub\n" + bytes(64)


@pytest.mark.parametrize("prefix", [b"", _STUB], ids=["plain", "stub-prefixed"])
def test_encrypted_central_directory_is_unsupported(prefix: bytes) -> None:
    with pytest.raises(UnsupportedFeatureError, match="central directory"):
        open_archive(io.BytesIO(prefix + _zip_with_encrypted_directory()))


def test_encrypted_zip64_central_directory_is_unsupported() -> None:
    # A ZIP64 archive keeps the directory size in the ZIP64 end record; the classic
    # record holds only 0xFFFFFFFF there. The check reads where the directory starts.
    raw = bytearray(_genuine_zip64_bytes())
    cd = raw.index(b"PK\x01\x02")
    cd_end = raw.index(b"PK\x06\x06")
    body = cd_end - cd - 8
    raw[cd:cd_end] = b"PK\x06\x08" + struct.pack("<I", body) + bytes([0xA5]) * body
    with pytest.raises(UnsupportedFeatureError, match="central directory"):
        open_archive(io.BytesIO(bytes(raw)))


def _members_raise_corruption(data: bytes) -> None:
    """Open succeeds, and the listing raises ``CorruptionError`` at the damage.

    A damaged directory lists the entries before the damage, then raises, as a cut
    TAR does; here there is none before it.
    """
    with (
        open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader,
        raises_corruption_not_truncation(match="central directory"),
    ):
        reader.members()


def test_record_inside_a_damaged_zip64_directory_is_not_read_as_encryption() -> None:
    # A damaged ZIP64 directory with an archive extra data record signature 76 bytes
    # in: where the directory start lands if the ZIP64 record and locator are not
    # subtracted. Those bytes are directory content, so this stays corruption.
    raw = bytearray(_genuine_zip64_bytes(name=b"n" * 100))
    cd = raw.index(b"PK\x01\x02")
    raw[cd : cd + 4] = b"XXXX"
    raw[cd + 76 : cd + 80] = b"PK\x06\x08"
    _members_raise_corruption(bytes(raw))


def test_record_at_the_stale_declared_offset_is_not_read_as_encryption() -> None:
    # A damaged directory in a stub-prefixed archive, with an archive extra data record
    # signature in the stub exactly where the stale declared offset points. Only where
    # the directory really starts decides, so this stays corruption.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"data")
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    raw[cd : cd + 4] = b"XXXX"
    stub = bytearray(max(cd + 4, 64))
    stub[cd : cd + 4] = b"PK\x06\x08"
    _members_raise_corruption(bytes(stub) + bytes(raw))


def test_damaged_central_directory_stays_corruption() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"data")
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    raw[cd : cd + 4] = b"XXXX"
    _members_raise_corruption(bytes(raw))


def _zip_with_non_utf8_name(name_byte: bytes) -> bytes:
    """A ZIP whose single member name contains ``name_byte``, stored without the UTF-8 flag."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("X.txt", b"data")  # ASCII name -> no UTF-8 flag
    # Same length, so all header offsets stay valid; replaces the name in both the local
    # header and the central directory.
    return buf.getvalue().replace(b"X.txt", name_byte + b".txt")


def test_explicit_encoding_overrides_cp437_default() -> None:
    data = _zip_with_non_utf8_name(b"\xe9")

    # Default: zipfile's cp437 fallback (0xE9 -> Greek Theta).
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        (member,) = reader.members()
        assert member.name == "Θ.txt"

    # Explicit caller encoding wins, and raw_name still round-trips the stored bytes.
    with open_archive(
        io.BytesIO(data), format=ArchiveFormat.ZIP, encoding="latin-1"
    ) as reader:
        (member,) = reader.members()
        assert member.name == "é.txt"
        assert member.raw_name == b"\xe9.txt"


def _ntfs_extra(mtime_ft: int, atime_ft: int, ctime_ft: int) -> bytes:
    """An NTFS extra field (0x000A): 4 reserved bytes, then tag 1 with three FILETIMEs."""
    body = struct.pack("<I", 0) + struct.pack(
        "<HHQQQ", 0x0001, 24, mtime_ft, atime_ft, ctime_ft
    )
    return struct.pack("<HH", 0x000A, len(body)) + body


def _to_filetime(unix_time: int) -> int:
    return (unix_time + 11_644_473_600) * 10_000_000


def test_ntfs_timestamps_used_when_no_extended_timestamp(tmp_path: Path) -> None:
    # An NTFS extra field (0x000A) carries FILETIME mtime/atime/ctime; with no 0x5455
    # field and a Windows writer they populate all three member times as tz-aware UTC
    # datetimes.
    mtime, atime, ctime = 1_600_000_000, 1_600_000_100, 1_600_000_200
    path = tmp_path / "ntfs.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.create_system = 10  # NTFS
    info.extra = _ntfs_extra(
        _to_filetime(mtime), _to_filetime(atime), _to_filetime(ctime)
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member.modified == datetime.fromtimestamp(mtime, tz=UTC)
        assert member.accessed == datetime.fromtimestamp(atime, tz=UTC)
        assert member.created == datetime.fromtimestamp(ctime, tz=UTC)


@pytest.mark.parametrize(
    ("create_system", "creation_field"), [(10, "created"), (3, "ctime")]
)
def test_bad_ntfs_times_name_the_member_field(
    tmp_path: Path, create_system: int, creation_field: str
) -> None:
    # MEMBER_TIMESTAMP_INVALID names the ArchiveMember field in every format. The
    # creation FILETIME is `created` or `ctime` by host, as _zip_created splits it.
    path = tmp_path / "bad_ntfs.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.create_system = create_system
    info.extra = _ntfs_extra(2**64 - 1, 2**64 - 1, 2**64 - 1)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        fields = sorted(d.context.field for d in member.diagnostics)
    assert fields == sorted(["modified", "accessed", creation_field])


def test_extended_timestamp_beats_ntfs(tmp_path: Path) -> None:
    # Precedence: 0x5455 (Unix) > 0x000A (NTFS) > DOS date_time — regardless of the
    # fields' order in the extra blob. Here NTFS carries all three times but the UT
    # field's mtime wins for `modified`; atime/ctime stay from NTFS (UT carries none).
    ut_mtime, nt_mtime, nt_atime = 1_600_000_000, 1_500_000_000, 1_500_000_100
    extra = _ntfs_extra(
        _to_filetime(nt_mtime), _to_filetime(nt_atime), 0
    ) + struct.pack("<HHBI", 0x5455, 5, 0x01, ut_mtime)
    path = tmp_path / "both.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member.modified == datetime.fromtimestamp(ut_mtime, tz=UTC)
        assert member.accessed == datetime.fromtimestamp(nt_atime, tz=UTC)
        assert member.created is None  # NTFS ctime was 0 = "not set"
        assert member.ctime is None


_NT_CTIME, _UT_CTIME = 1_500_000_000, 1_600_000_200


@pytest.mark.parametrize(
    ("create_system", "birth_time"),
    [
        (0, True),  # MS-DOS / FAT
        (10, True),  # NTFS
        (14, True),  # VFAT
        (3, False),  # Unix: 7-Zip (NTFS) and libarchive (UT) store st_ctime
        (19, False),  # OS X: not a DOS-attribute host
        (99, False),  # unknown host: meaning unknown
    ],
)
@pytest.mark.parametrize(
    ("fields", "stored"),
    [
        ("ntfs", _NT_CTIME),
        ("ut", _UT_CTIME),
        ("both", _UT_CTIME),  # Extended Timestamp wins, as for the other times
    ],
)
def test_writer_host_decides_whether_creation_time_is_created(
    tmp_path: Path, create_system: int, birth_time: bool, fields: str, stored: int
) -> None:
    # The field that carries a "creation" time does not say what it is: 7-Zip on Unix
    # writes st_ctime into the NTFS FILETIME. The writer's host does. A DOS-attribute
    # host's time is `created`; any other host's is `ctime`.
    extra = b""
    if fields in ("ntfs", "both"):
        extra += _ntfs_extra(
            _to_filetime(1_500_000_100),
            _to_filetime(1_500_000_100),
            _to_filetime(_NT_CTIME),
        )
    if fields in ("ut", "both"):
        extra += struct.pack("<HHBii", 0x5455, 9, 0x05, 1_600_000_000, _UT_CTIME)
    path = tmp_path / "host.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.create_system = create_system
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    expected = datetime.fromtimestamp(stored, tz=UTC)
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        if birth_time:
            assert member.created == expected
            assert member.ctime is None
        else:
            assert member.created is None
            assert member.ctime == expected


@requires_binary("7z")
def test_unix_7zip_ntfs_creation_time_is_zip_ctime(tmp_path: Path) -> None:
    # The real writer behind the rule: 7-Zip on Unix stores st_ctime in the NTFS
    # creation FILETIME and marks the entry as made on Unix.
    (tmp_path / "a.txt").write_bytes(b"hi")
    archive = tmp_path / "unix7z.zip"
    result = subprocess.run(
        ["7z", "a", "-tzip", "-mtc=on", str(archive), "a.txt", "-y"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build a -mtc=on ZIP: {result.stderr}")
    with open_archive(archive) as ar:
        member = ar.get("a.txt")
        if member.create_system is not CreateSystem.UNIX:
            pytest.skip("7z on this host does not write Unix ZIP entries")
        assert member.created is None
        assert member.ctime.tzinfo is not None


def test_compressed_source_size(simple_zip: Path) -> None:
    # The archive-wide extraction ratio guard's denominator: for ZIP the source size is
    # the compressed size; known for paths and seekable streams alike.
    with open_archive(simple_zip) as ar:
        assert ar.compressed_source_size == simple_zip.stat().st_size
    data = simple_zip.read_bytes()
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as ar:
        assert ar.compressed_source_size == len(data)


def test_compressed_source_size_from_size_attribute(simple_zip: Path) -> None:
    # An fsspec-style object advertising `.size` is trusted without a seek probe.
    class _SizedBytesIO(io.BytesIO):
        @property
        def size(self) -> int:
            return len(self.getvalue())

    data = simple_zip.read_bytes()
    with open_archive(_SizedBytesIO(data), format=ArchiveFormat.ZIP) as ar:
        assert ar.compressed_source_size == len(data)


def test_member_stream_advertises_size(simple_zip: Path) -> None:
    # Member streams expose the fsspec-style `.size` from archive metadata, so a
    # nested open_archive (or any consumer) can learn the payload size cheaply.
    with open_archive(simple_zip) as ar:
        member = ar.get("hello.txt")
        assert member is not None
        with ar.open(member) as stream:
            assert stream.size == member.size == 11


def test_nested_archive_source_size_is_cheap(tmp_path: Path) -> None:
    # A zip inside a tar: opening the inner archive straight from the member stream
    # gives the bomb tracker its source size from metadata — no end-seek needed.
    import tarfile as tarfile_mod

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("data.txt", b"nested payload")
    inner_bytes = inner.getvalue()

    outer = tmp_path / "outer.tar"
    with tarfile_mod.open(outer, "w") as t:
        info = tarfile_mod.TarInfo("inner.zip")
        info.size = len(inner_bytes)
        t.addfile(info, io.BytesIO(inner_bytes))

    with open_archive(outer, seekable_members=True) as outer_ar:
        inner_stream = outer_ar.open("inner.zip")
        with open_archive(inner_stream, format=ArchiveFormat.ZIP) as inner_ar:
            assert inner_ar.compressed_source_size == len(inner_bytes)
            assert inner_ar.read("data.txt") == b"nested payload"


# Committed fixtures (tests/fixtures/zip_backslash/, generated by its generate.py) carry
# backslashes in the stored names. They run identically on every OS because archivey reads
# the raw name from ZipInfo.orig_filename, which zipfile preserves cross-platform (unlike
# .filename, which it rewrites on Windows). Building these at runtime instead would be
# impossible on Windows, where zipfile rewrites backslashes on both write and read.
_ZIP_BACKSLASH_DIR = Path(__file__).parent / "fixtures" / "zip_backslash"


def test_backslash_converted_for_dos_windows_entry() -> None:
    # A DOS/Windows-origin entry (create_system=FAT) uses "\" as a separator: converted.
    with open_archive(_ZIP_BACKSLASH_DIR / "dos_backslash.zip") as ar:
        names = [m.name for m in ar.members()]
    assert names == ["dir/sub/file.txt"]


def test_backslash_kept_literal_for_unix_entry() -> None:
    # A Unix-origin entry (create_system=3) keeps a backslash as a literal filename char.
    with open_archive(_ZIP_BACKSLASH_DIR / "unix_backslash.zip") as ar:
        names = [m.name for m in ar.members()]
    assert names == ["weird\\name.txt"]


# ---------------------------------------------------------------------------
# Unflagged member-name encoding (UTF-8 sniff + configurable legacy fallback)
# ---------------------------------------------------------------------------

_EXTERNAL_DIR = Path(__file__).parent / "fixtures" / "external"


def _stored_zip(name_bytes: bytes, *, utf8_flag: bool, comment: bytes = b"") -> bytes:
    """A minimal single-entry (stored, empty) ZIP with a raw name and chosen UTF-8 flag,
    and an optional member comment."""
    flags = 0x800 if utf8_flag else 0
    n = len(name_bytes)
    lfh = (
        struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, 0, 0, 0, 0, 0, n, 0)
        + name_bytes
    )
    cdh = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flags,
            0,
            0,
            0,
            0,
            0,
            0,
            n,
            0,
            len(comment),
            0,
            0,
            0,
            0,
        )
        + name_bytes
        + comment
    )
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cdh), len(lfh), 0)
    return lfh + cdh + eocd


def test_a_member_typed_twice_is_one_finding(tmp_path: Path) -> None:
    """Listing the same ZIP twice must not report the same member's anomalies twice.

    `extract_all` lists an indexed archive twice — once for the progress totals and the
    selector, once to drive the extraction — and this backend rebuilds its
    `ArchiveMember` objects from the central directory each time. Every diagnostic
    raised while a member is typed therefore runs again on the second pass, and
    `DiagnosticSummary.counts` is documented as exact: one member with one deceptive
    name is one finding, whether the caller listed it once or extracted it.

    This covers two of the four codes raised from that point: a rewritten name and two
    invalid timestamp fields, three findings on one member. The name-encoding inference
    has its own test below, and the link report has its own in
    `tests/test_windows_reparse.py`.

    The two timestamps are deliberately both invalid: they are separate findings on one
    member, so the deduplication has to key on the field as well as the member, not
    collapse them into one.
    """
    archive = tmp_path / "typed-twice.zip"
    # An NTFS extra field (0x000A): 4 reserved bytes, then attribute tag 1 carrying the
    # three FILETIMEs. Modification and access are far past what a datetime can hold;
    # creation is left at the "not set" zero, so the member carries two bad fields.
    ntfs = struct.pack("<IHHQQQ", 0, 0x0001, 24, 2**64 - 1, 2**64 - 1, 0)
    extra = struct.pack("<HH", 0x000A, len(ntfs)) + ntfs
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("dir//normalized.txt")
        info.extra = extra
        zf.writestr(info, b"x")

    expected = {
        DiagnosticCode.MEMBER_NAME_NORMALIZED: 1,
        DiagnosticCode.MEMBER_TIMESTAMP_INVALID: 2,
    }
    with open_archive(archive) as opened:
        listed = opened.members()
        assert [member.name for member in listed] == ["dir/normalized.txt"]
        assert {
            code: opened.diagnostics.counts.get(code) for code in expected
        } == expected

    with open_archive(archive) as opened:
        opened.extract_all(tmp_path / "out")
        assert {
            code: opened.diagnostics.counts.get(code) for code in expected
        } == expected
        # And the caller finds the reports on the objects its own pass handed back,
        # rather than on the ones the first pass built and dropped, each naming the
        # member it is about: the reports are raised before registration stamps the id,
        # so they carry the position it will be stamped from.
        (member,) = opened.members()
        assert len(member.diagnostics) == 3
        assert {d.context.member_id for d in member.diagnostics} == {member._member_id}


def test_an_inferred_encoding_is_one_finding_per_member(tmp_path: Path) -> None:
    """The same, for the name-encoding inference, which has its own emit."""
    code = DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
    with open_archive(_EXTERNAL_DIR / "encoding_infozip_jules.zip") as opened:
        opened.extract_all(tmp_path)
        assert opened.diagnostics.counts.get(code) == 4
        for member in opened.members():
            (reported,) = [d for d in member.diagnostics if d.code is code]
            assert reported.context.member_id == member._member_id


def test_unflagged_utf8_name_is_sniffed() -> None:
    # Info-ZIP fixture: names are valid UTF-8 bytes with the UTF-8 flag NOT set. Decoding
    # them as cp437 (the APPNOTE default) would mojibake; the sniff recovers UTF-8.
    with open_archive(_EXTERNAL_DIR / "encoding_infozip_jules.zip") as ar:
        names = {m.name for m in ar.members()}
        counts = ar.diagnostics.counts
    assert names == {"Español.txt", "Català.txt", "Português.txt", "emoji_😀.txt"}
    # One inference diagnostic per unflagged name that was decoded as UTF-8.
    assert counts[DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED] == 4
    # The cp437 text the sniff replaced is not reported as a normalization.
    assert DiagnosticCode.MEMBER_NAME_NORMALIZED not in counts


def test_unflagged_ascii_name_is_not_an_encoding_override(tmp_path: Path) -> None:
    # Pure ASCII is valid UTF-8 *and* identical under cp437 — the sniff "selecting" UTF-8
    # is not an observable override, so no MEMBER_NAME_ENCODING_INFERRED spam.
    path = tmp_path / "ascii.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("digital_codex/readme.txt", b"x")
        z.writestr("digital_codex/.DS_Store", b"y")
        z.writestr("__MACOSX/digital_codex/._.DS_Store", b"z")
    with open_archive(path) as ar:
        names = {m.name for m in ar.members()}
        counts = ar.diagnostics.counts
        for info in zipfile.ZipFile(path).infolist():
            assert info.flag_bits & 0x800 == 0  # unflagged (stdlib leaves ASCII clear)
    assert names == {
        "digital_codex/readme.txt",
        "digital_codex/.DS_Store",
        "__MACOSX/digital_codex/._.DS_Store",
    }
    assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


def test_explicit_encoding_keeps_the_utf8_sniff() -> None:
    # encoding= replaces only the legacy fallback: an unflagged name whose bytes are
    # valid UTF-8 is still UTF-8, and the inference is still reported.
    with open_archive(
        _EXTERNAL_DIR / "encoding_infozip_jules.zip", encoding="cp437"
    ) as ar:
        names = {m.name for m in ar.members()}
        counts = ar.diagnostics.counts
    assert "Español.txt" in names
    assert counts[DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED] >= 1


def test_explicit_encoding_does_not_decode_valid_utf8() -> None:
    # c3 a9 is UTF-8 for "é"; as Latin-1 it would be "Ã©".
    data = _stored_zip(b"\xc3\xa9txt", utf8_flag=False)
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        (member,) = ar.members()
    assert member.name == "étxt"
    assert member.raw_name == b"\xc3\xa9txt"
    # The diagnostic names the codec the caller passed, not cp437.
    (diag,) = member.diagnostics
    assert diag.code == DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
    assert diag.context.declared_encoding == "latin-1"
    assert "'latin-1'" in diag.message
    assert "cp437" not in diag.message


@pytest.mark.parametrize(
    ("encoding", "name", "codec"),
    [
        pytest.param(None, "cafΘ.txt", "cp437", id="cp437-default"),
        pytest.param("cp1252", "café.txt", "cp1252", id="caller-encoding"),
    ],
)
@pytest.mark.parametrize("streaming", [False, True], ids=["file", "pipe"])
def test_name_flagged_utf8_that_is_not_decodes_as_unflagged(
    tmp_path: Path, encoding: str | None, name: str, codec: str, streaming: bool
) -> None:
    # e9 alone is not UTF-8. The flag is read as a mistake: the name decodes the way an
    # unflagged one that is not UTF-8 does, and the report names the codec used and
    # the UTF-8 the flag declared. The comment under the same flag follows the name.
    raw = b"caf\xe9.txt"
    data = _stored_zip(raw, utf8_flag=True, comment=b"caf\xe9ine")
    source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
    with open_archive(source, encoding=encoding, streaming=streaming) as ar:
        ar.extract_all(tmp_path)
        report = ar.members_report_if_available()
        assert report is not None
        (member,) = report.members
    assert member.name == name
    assert member.comment == name.removesuffix(".txt") + "ine"
    assert member.raw_name == raw
    assert [p.name for p in tmp_path.iterdir()] == [name]
    (diag,) = member.diagnostics
    assert diag.code == DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
    assert diag.context.inferred_encoding == codec
    assert diag.context.declared_encoding == "utf-8"
    assert "UTF-8 flag is set" in diag.message


def test_strict_refuses_a_name_flagged_utf8_that_is_not() -> None:
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError, match="UTF-8 flag is set"),
        open_archive(
            io.BytesIO(_stored_zip(b"caf\xe9.txt", utf8_flag=True)), config=strict
        ) as ar,
    ):
        ar.members()


def test_two_stored_names_that_decode_alike_are_duplicates(tmp_path: Path) -> None:
    # c3 a9 (UTF-8, unflagged, so sniffed) and 82 (cp437) both decode to "é.txt". The
    # later member supersedes the earlier one like any duplicate; raw_name tells
    # them apart.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("XX.txt", b"first")
        z.writestr("Y.txt", b"second")
    data = buffer.getvalue()
    for placeholder, raw in ((b"XX.txt", b"\xc3\xa9.txt"), (b"Y.txt", b"\x82.txt")):
        assert data.count(placeholder) == 2
        data = data.replace(placeholder, raw)
    with open_archive(io.BytesIO(data)) as ar:
        first, second = ar.members()
        ar.extract_all(tmp_path)
    assert (first.name, second.name) == ("é.txt", "é.txt")
    assert (first.raw_name, second.raw_name) == (b"\xc3\xa9.txt", b"\x82.txt")
    assert (first.is_current, second.is_current) == (False, True)
    assert (tmp_path / "é.txt").read_bytes() == b"second"


@pytest.mark.parametrize(
    ("encoding", "e_acute"), [(None, b"\x82"), ("cp1252", b"\xe9")]
)
def test_a_flag_overridden_name_collides_as_a_duplicate(
    tmp_path: Path, encoding: str | None, e_acute: bytes
) -> None:
    # c3 a9 is valid UTF-8 and sniffed; the second name is flagged UTF-8 and is not, so
    # it decodes as unflagged, to "é" in the codec used. Only the flagged member is
    # reported for the flag, and it supersedes the earlier one like any duplicate.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("XX.txt", b"first")
        z.writestr("Y.txt", b"second")
    data = bytearray(buffer.getvalue().replace(b"XX.txt", b"\xc3\xa9.txt"))
    for signature, flags_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        header = data.index(signature, data.index(signature) + 1)
        (flags,) = struct.unpack_from("<H", data, header + flags_at)
        struct.pack_into("<H", data, header + flags_at, flags | 0x800)
    data = bytes(data).replace(b"Y.txt", e_acute + b".txt")
    with open_archive(io.BytesIO(data), encoding=encoding) as ar:
        first, second = ar.members()
        ar.extract_all(tmp_path)
    assert (first.name, second.name) == ("é.txt", "é.txt")
    assert (first.raw_name, second.raw_name) == (b"\xc3\xa9.txt", e_acute + b".txt")
    assert (first.is_current, second.is_current) == (False, True)
    assert (tmp_path / "é.txt").read_bytes() == b"second"
    assert [d.context.declared_encoding for d in second.diagnostics] == ["utf-8"]
    assert [d.context.declared_encoding for d in first.diagnostics] == [
        encoding or "cp437"
    ]


def test_utf8_inference_names_the_configured_fallback() -> None:
    data = _stored_zip(b"\xc3\xa9txt", utf8_flag=False)
    cfg = ArchiveyConfig(zip_unflagged_fallback_encoding="cp1252")
    with open_archive(io.BytesIO(data), config=cfg) as ar:
        (member,) = ar.members()
    (diag,) = member.diagnostics
    assert diag.context.declared_encoding == "cp1252"
    assert "'cp1252'" in diag.message


def test_explicit_encoding_replaces_the_configured_fallback() -> None:
    # 0xE9 alone is not valid UTF-8: encoding= decodes it, ahead of the config's
    # fallback, and no inference is reported because the caller chose the codec.
    data = _stored_zip(b"caf\xe9.txt", utf8_flag=False)
    cfg = ArchiveyConfig(zip_unflagged_fallback_encoding="cp437")
    with open_archive(io.BytesIO(data), config=cfg, encoding="latin-1") as ar:
        (member,) = ar.members()
        counts = ar.diagnostics.counts
    assert member.name == "café.txt"
    assert member.raw_name == b"caf\xe9.txt"
    assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


def test_explicit_encoding_escapes_bytes_it_cannot_decode() -> None:
    # The caller's codec is used as the fallback is: bytes it cannot decode become
    # surrogate escapes rather than failing the open.
    data = _stored_zip(b"caf\xe9.txt", utf8_flag=False)
    with open_archive(io.BytesIO(data), encoding="ascii") as ar:
        (member,) = ar.members()
    assert member.name == "caf\udce9.txt"
    assert member.raw_name == b"caf\xe9.txt"


def test_flag_set_name_is_not_sniffed(tmp_path: Path) -> None:
    # A set UTF-8 flag is authoritative; zipfile flags non-ASCII names, so no sniff fires.
    path = tmp_path / "flagged.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("café.txt", b"x")
    with open_archive(path) as ar:
        member = ar.members()[0]
        counts = ar.diagnostics.counts
    assert member.name == "café.txt"
    assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


def test_invalid_utf8_uses_configurable_legacy_fallback() -> None:
    # 0xE9 alone is invalid UTF-8; as cp1252 it is "é". A caller with a known-legacy corpus
    # sets the fallback so unflagged non-UTF-8 names decode deterministically.
    data = _stored_zip(b"caf\xe9.txt", utf8_flag=False)
    assert zipfile.ZipFile(io.BytesIO(data)).infolist()[0].flag_bits & 0x800 == 0
    cfg = ArchiveyConfig(zip_unflagged_fallback_encoding="cp1252")
    with open_archive(io.BytesIO(data), config=cfg) as ar:
        member = ar.members()[0]
        counts = ar.diagnostics.counts
    assert member.name == "café.txt"
    assert counts[DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED] == 1


def test_invalid_utf8_default_fallback_is_cp437_without_diagnostic() -> None:
    # With the default cp437 fallback, an unflagged non-UTF-8 name decodes as cp437 and
    # emits no inference diagnostic (cp437 is the APPNOTE default, not an override).
    data = _stored_zip(b"caf\xe9.txt", utf8_flag=False)
    with open_archive(io.BytesIO(data)) as ar:
        member = ar.members()[0]
        counts = ar.diagnostics.counts
    assert member.name == b"caf\xe9.txt".decode("cp437")
    assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


# Comments carry no encoding of their own: APPNOTE puts a member comment under the
# same UTF-8 flag as its name, and the archive comment under none. An unflagged
# comment therefore decodes as an unflagged name does.
_CP1251_ARCHIVE_COMMENT = "Привет мир"
_CP1251_MEMBER_COMMENT = "Ответ"


def _commented_zip(archive_comment: bytes, member_comment: bytes) -> bytes:
    """An ASCII-named member, so stdlib leaves the UTF-8 flag clear on it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("a.txt")
        info.comment = member_comment
        z.writestr(info, b"x")
        z.comment = archive_comment
    assert zipfile.ZipFile(buf).infolist()[0].flag_bits & 0x800 == 0
    return buf.getvalue()


@requires_binary("zip")
def test_unflagged_comments_decode_with_explicit_encoding(tmp_path: Path) -> None:
    # Info-ZIP zip stores the comment bytes it reads as they are, with no flag.
    path = tmp_path / "comments.zip"
    (tmp_path / "a.txt").write_bytes(b"hi\n")
    subprocess.run(["zip", "-q", path.name, "a.txt"], cwd=tmp_path, check=True)
    subprocess.run(
        ["zip", "-q", "-z", path.name],
        cwd=tmp_path,
        input=_CP1251_ARCHIVE_COMMENT.encode("cp1251"),
        check=True,
    )
    subprocess.run(
        ["zip", "-q", "-c", path.name, "a.txt"],
        cwd=tmp_path,
        input=_CP1251_MEMBER_COMMENT.encode("cp1251") + b"\n",
        check=True,
    )
    with zipfile.ZipFile(path) as z:
        assert z.infolist()[0].flag_bits & 0x800 == 0
        assert z.comment == _CP1251_ARCHIVE_COMMENT.encode("cp1251")
    with open_archive(path, encoding="cp1251") as ar:
        (member,) = ar.members()
        assert ar.info.comment == _CP1251_ARCHIVE_COMMENT
        assert member.comment == _CP1251_MEMBER_COMMENT


def test_unflagged_comments_take_the_configured_fallback() -> None:
    data = _commented_zip(
        _CP1251_ARCHIVE_COMMENT.encode("cp1251"),
        _CP1251_MEMBER_COMMENT.encode("cp1251"),
    )
    cfg = ArchiveyConfig(zip_unflagged_fallback_encoding="cp1251")
    with open_archive(io.BytesIO(data), config=cfg) as ar:
        (member,) = ar.members()
        assert ar.info.comment == _CP1251_ARCHIVE_COMMENT
        assert member.comment == _CP1251_MEMBER_COMMENT


def test_unflagged_comments_default_to_cp437() -> None:
    data = _commented_zip(
        _CP1251_ARCHIVE_COMMENT.encode("cp1251"),
        _CP1251_MEMBER_COMMENT.encode("cp1251"),
    )
    with open_archive(io.BytesIO(data)) as ar:
        (member,) = ar.members()
        assert ar.info.comment == _CP1251_ARCHIVE_COMMENT.encode("cp1251").decode(
            "cp437"
        )
        assert member.comment == _CP1251_MEMBER_COMMENT.encode("cp1251").decode("cp437")


def test_unflagged_utf8_comments_win_over_explicit_encoding() -> None:
    data = _commented_zip(
        _CP1251_ARCHIVE_COMMENT.encode(), _CP1251_MEMBER_COMMENT.encode()
    )
    with open_archive(io.BytesIO(data), encoding="cp1251") as ar:
        (member,) = ar.members()
        assert ar.info.comment == _CP1251_ARCHIVE_COMMENT
        assert member.comment == _CP1251_MEMBER_COMMENT
        # A comment is not a name: no name diagnostic is reported for it.
        assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in ar.diagnostics.counts


def test_flagged_member_comment_ignores_explicit_encoding(tmp_path: Path) -> None:
    # stdlib sets the UTF-8 flag for a non-ASCII name; the flag covers the comment too.
    # The comment bytes are not valid UTF-8, so the flagged reading (UTF-8, else cp437)
    # and the unflagged one (UTF-8, else encoding=) differ.
    stored = _CP1251_MEMBER_COMMENT.encode("cp1251")
    path = tmp_path / "flagged.zip"
    with zipfile.ZipFile(path, "w") as z:
        info = zipfile.ZipInfo("café.txt")
        info.comment = stored
        z.writestr(info, b"x")
    with zipfile.ZipFile(path) as z:
        assert z.infolist()[0].flag_bits & 0x800
    with open_archive(path, encoding="cp1251") as ar:
        (member,) = ar.members()
    assert member.comment == stored.decode("cp437")
    assert member.comment != _CP1251_MEMBER_COMMENT


def test_encoding_inference_is_escalatable() -> None:
    # The inference diagnostic flows through DiagnosticPolicy like any other: a caller who
    # refuses to trust the guess can escalate it to an error.
    from archivey import DiagnosticPolicy
    from archivey.exceptions import DiagnosticRaisedError

    policy = DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED})
    cfg = ArchiveyConfig(diagnostic_policy=policy)
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(_EXTERNAL_DIR / "encoding_infozip_jules.zip", config=cfg) as ar,
    ):
        ar.members()


# ---------------------------------------------------------------------------
# Extended Timestamp out-of-range guard (deep W2)
# ---------------------------------------------------------------------------


def test_extended_timestamp_pre_epoch(tmp_path: Path) -> None:
    # A signed pre-1970 Extended Timestamp is legitimate data and lists as its date.
    extra = struct.pack("<HHBi", 0x5455, 5, 0x01, -1)
    path = tmp_path / "pre-epoch.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member is not None
        assert member.modified == datetime(1969, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_extended_timestamp_pre_epoch_does_not_depend_on_gmtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows, even tz-aware fromtimestamp routes through gmtime() and raises
    # OSError for pre-1970 values, so the oldest signed value used to list as invalid
    # there only. The conversion no longer calls fromtimestamp: with one that raises
    # like Windows', the member still lists its 1901 date and no diagnostic.
    from archivey.diagnostics import DiagnosticCode
    from archivey.internal import timestamps as timestamps_module
    from archivey.internal.backends import zip_reader as zip_reader_module

    class _WindowsLikeDatetime(datetime):
        @classmethod
        def fromtimestamp(cls, ts: float, tz: object = None) -> datetime:
            if ts < 0:
                raise OSError(22, "Invalid argument (simulated Windows gmtime)")
            return datetime.fromtimestamp(ts, tz)  # type: ignore[arg-type]

    monkeypatch.setattr(zip_reader_module, "datetime", _WindowsLikeDatetime)
    monkeypatch.setattr(timestamps_module, "datetime", _WindowsLikeDatetime)

    extra = struct.pack("<HHBi", 0x5455, 5, 0x01, -(2**31))
    path = tmp_path / "neg-ts.zip"
    info = zipfile.ZipInfo("t.txt", date_time=(1990, 1, 1, 0, 0, 0))
    info.extra = extra
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, b"data")
    with open_archive(path) as ar:
        member = ar.get("t.txt")
        assert member is not None
        assert member.modified == datetime(1901, 12, 13, 20, 45, 52, tzinfo=UTC)
        assert DiagnosticCode.MEMBER_TIMESTAMP_INVALID not in ar.diagnostics.counts


# ---------------------------------------------------------------------------
# ZipInfo._raw_time must fail loud if stdlib drops it (deep W3)
# ---------------------------------------------------------------------------


def test_zipcrypto_check_byte_comes_from_the_dos_time_under_a_data_descriptor() -> None:
    # Under bit 3 the CRC was not known when the header was written, so the check byte
    # is the DOS time's high byte; otherwise the CRC's.
    from archivey.internal.backends import zip_reader

    loc = zip_reader._ZipLocator(
        index=0,
        header_offset=0,
        compressed_size=12,
        file_size=0,
        crc=0x12345678,
        flags=0x1,
        method=0,
        dos_time=0xABCD,
        name=b"x",
        aes=None,
        strong_encryption=False,
        reparse_fallback=None,
    )
    assert zip_reader._zipcrypto_check_byte(loc) == 0x12
    with_descriptor = dataclasses.replace(loc, flags=0x9)
    assert zip_reader._zipcrypto_check_byte(with_descriptor) == 0xAB


_SPECIAL_FILE_TYPES = [
    (stat.S_IFCHR, "char_device"),
    (stat.S_IFBLK, "block_device"),
    (stat.S_IFIFO, "fifo"),
    (stat.S_IFSOCK, "socket"),
]


def _zip_with_special_entry(path: Path, file_type: int, data: bytes) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, mode, payload in (
            ("dev", file_type | 0o644, data),
            ("f.txt", 0o100644, b"data"),
        ):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, payload)


@pytest.mark.parametrize(("file_type", "special"), _SPECIAL_FILE_TYPES)
def test_unix_special_file_without_data_is_other(
    tmp_path: Path, file_type: int, special: str
) -> None:
    """A device, FIFO or socket that stores no data is OTHER, as in TAR and ISO. unzip
    would write an empty regular file; extraction refuses the member instead, and
    ``extra["special_file_type"]`` says what the archive called it (DR-25)."""
    path = tmp_path / "special.zip"
    _zip_with_special_entry(path, file_type, b"")
    with open_archive(path) as ar:
        types = {m.name: m.type for m in ar.members()}
        assert types == {"dev": MemberType.OTHER, "f.txt": MemberType.FILE}
        dev = ar.get("dev")
        assert dev.size == 0
        assert dev.extra["special_file_type"] == special
        assert "special_file_type" not in ar.get("f.txt").extra
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in ar.diagnostics.counts
        ar.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "dev").exists()
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"data"


@pytest.mark.parametrize(("file_type", "special"), _SPECIAL_FILE_TYPES)
def test_unix_special_file_with_data_is_a_file(
    tmp_path: Path, file_type: int, special: str
) -> None:
    """A special-mode entry that carries data is a FILE: its bytes are the content, as
    unzip, 7-Zip, bsdtar and zipfile all deliver them. The stored type stays visible in
    ``extra`` and the member carries MEMBER_SPECIAL_FILE_HAS_DATA (DR-25)."""
    path = tmp_path / "special.zip"
    _zip_with_special_entry(path, file_type, b"xyz")
    with open_archive(path) as ar:
        dev = ar.get("dev")
        assert dev.type is MemberType.FILE
        assert dev.size == 3
        assert dev.extra["special_file_type"] == special
        assert ar.read(dev) == b"xyz"
        [diag] = [
            d
            for d in dev.diagnostics
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert diag.context.to_dict() == {
            "kind": "special_file_data",
            "archive_name": str(path),
            "member_name": "dev",
            "member_id": 0,
            "special_file_type": special,
            "size": 3,
        }
        assert special.replace("_", " ") in diag.message
        ar.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "dev").read_bytes() == b"xyz"
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"data"


def test_unknown_file_type_bits_with_data_name_an_unrecognized_type(
    tmp_path: Path,
) -> None:
    """File-type bits no Unix type uses (``0o070000``) are special but nameless: the
    key says ``"unknown"`` and the message says so in words."""
    path = tmp_path / "odd.zip"
    _zip_with_special_entry(path, 0o070000, b"xyz")
    with open_archive(path) as ar:
        dev = ar.get("dev")
        assert dev.type is MemberType.FILE
        assert dev.extra["special_file_type"] == "unknown"
        [diag] = [
            d
            for d in dev.diagnostics
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert "marks it as an unrecognized file type and stores 3 bytes" in (
            diag.message
        )
        assert ar.read(dev) == b"xyz"


def test_a_directory_marker_over_a_special_mode_keeps_the_key(tmp_path: Path) -> None:
    """The trailing ``/`` is structure and wins the type (DR-25); the FIFO mode is still
    what the archive recorded, so ``extra["special_file_type"]`` records it on the
    DIRECTORY, and the data advisory is for FILE members only."""
    path = tmp_path / "dir-fifo.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("d/")
        info.create_system = 3
        info.external_attr = (0o010755 << 16) | 0x10
        zf.writestr(info, b"")
    with open_archive(path) as ar:
        [member] = ar.members()
        assert member.type is MemberType.DIRECTORY
        assert member.extra["special_file_type"] == "fifo"
        codes = [d.code for d in ar.diagnostics.retained]
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes


def test_special_file_with_data_is_not_refused_by_strict(tmp_path: Path) -> None:
    """MEMBER_SPECIAL_FILE_HAS_DATA is advisory: a documented writer option produces
    the shape (``zip -FI``), so strict does not refuse it."""
    path = tmp_path / "special.zip"
    _zip_with_special_entry(path, stat.S_IFIFO, b"xyz")
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(path, config=config) as ar:
        assert ar.read("dev") == b"xyz"


@requires_binary("zip")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_info_zip_fifo_content_reads_as_a_file(tmp_path: Path) -> None:
    """Info-ZIP's ``zip -FI`` reads a named pipe and stores its content under the pipe's
    own FIFO mode. Every mainstream extractor writes the bytes as a regular file, and
    libarchive carries a workaround for exactly this shape; so does archivey (DR-25)."""
    src = tmp_path / "src"
    src.mkdir()
    fifo = src / "pipe1"
    os.mkfifo(fifo)
    archive = tmp_path / "fifo.zip"
    # The producer thread blocks in open() until zip opens the pipe for reading.
    feeder = threading.Thread(
        target=fifo.write_bytes, args=(b"hello from fifo\n",), daemon=True
    )
    feeder.start()
    try:
        subprocess.run(
            ["zip", "-q", "-FI", str(archive), "pipe1"],
            cwd=src,
            check=True,
            capture_output=True,
            timeout=30,
        )
    finally:
        feeder.join(timeout=30)
    with open_archive(archive) as ar:
        [member] = ar.members()
        assert member.type is MemberType.FILE
        assert member.extra["special_file_type"] == "fifo"
        assert member.size == 16
        assert ar.read(member) == b"hello from fifo\n"
        ar.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "pipe1").read_bytes() == b"hello from fifo\n"


def test_device_bits_from_a_non_unix_writer_are_ignored(tmp_path: Path) -> None:
    """The high word is a Unix mode only when "version made by" says Unix."""
    path = tmp_path / "dos.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("f")
        info.create_system = 0
        info.external_attr = (stat.S_IFCHR | 0o644) << 16
        zf.writestr(info, b"x")
    with open_archive(path) as ar:
        assert ar.members()[0].type is MemberType.FILE


# --- a directory entry that declares data ---------------------------------------------


def _zip_with_directory_data(path: Path, compress_type: int) -> None:
    """``d/`` carrying 12 bytes (APPNOTE gives a directory none), a file under it and
    the Java ``jar`` shape: a deflated empty directory body (compressed size 2)."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(zipfile.ZipInfo("d/"), b"hidden data!", compress_type=compress_type)
        z.writestr("d/f.txt", b"visible")
        z.writestr(zipfile.ZipInfo("jar/"), b"", compress_type=zipfile.ZIP_DEFLATED)


@pytest.mark.parametrize(
    "compress_type",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED],
    ids=["stored", "deflate"],
)
def test_directory_data_is_reported_and_readable_but_not_extracted(
    tmp_path: Path, compress_type: int
) -> None:
    """The entry stays a directory (every official tool creates one) with its declared
    size, ``MEMBER_DIRECTORY_DATA_IGNORED`` names the bytes extraction drops, and
    ``read()`` still delivers them, so nothing in the archive is out of reach."""
    path = tmp_path / "dirdata.zip"
    _zip_with_directory_data(path, compress_type)
    with open_archive(path) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["d/"].type is MemberType.DIRECTORY
        assert by_name["d/"].size == 12
        assert by_name["jar/"].type is MemberType.DIRECTORY
        assert by_name["jar/"].size == 0
        assert by_name["jar/"].compressed_size == 2
        diags = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert [d.context.to_dict() if d.context else None for d in diags] == [
            {
                "kind": "directory_data",
                "archive_name": str(path),
                "member_name": "d/",
                "member_id": 0,
                "size": 12,
                "compressed_size": by_name["d/"].compressed_size,
            }
        ]
        assert "12 bytes" in diags[0].message
        assert ar.read("d/") == b"hidden data!"
        assert ar.read("d/f.txt") == b"visible"
        with pytest.raises(ArchiveyUsageError, match="not a file"):
            ar.read("jar/")
        report = ar.extract_all(tmp_path / "out")
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses["d/"] is ExtractionStatus.EXTRACTED
    assert (tmp_path / "out" / "d").is_dir()
    assert (tmp_path / "out" / "d" / "f.txt").read_bytes() == b"visible"
    assert (tmp_path / "out" / "jar").is_dir()


def test_corrupted_directory_data_fails_its_digest_check(tmp_path: Path) -> None:
    """The bytes ``open()`` delivers for a directory are checked against the stored
    CRC-32 like a file's: a body that no longer matches raises instead of reading
    as clean data."""
    path = tmp_path / "dirdata.zip"
    _zip_with_directory_data(path, zipfile.ZIP_STORED)
    data = path.read_bytes()
    assert data.count(b"hidden data!") == 1
    path.write_bytes(data.replace(b"hidden data!", b"XXXXXXXXXXXX"))
    with open_archive(path) as ar:
        member = ar.get("d/")
        assert member.hashes == {
            HashAlgorithm.CRC32: crc32_digest(zlib.crc32(b"hidden data!"))
        }
        with pytest.raises(CorruptionError, match="crc32"):
            ar.read("d/")
        assert ar.read("d/f.txt") == b"visible"


@requires("cryptography")
def test_ae2_directory_data_is_checked_by_its_hmac(tmp_path: Path) -> None:
    """WinZip AE-2 stores CRC 0 by design and relies on the HMAC, for a directory entry
    as for a file: no crc32 in ``hashes``, no ``DIGEST_UNVERIFIABLE`` (the bytes are
    checked), the read returns the bytes, and a tampered HMAC is ``CorruptionError``."""
    path = tmp_path / "ae2-dir.zip"
    path.write_bytes(build_aes_zip([(b"d/", b"hidden data!")], password=b"secret"))
    with open_archive(path, password="secret") as ar:
        member = ar.get("d/")
        assert member.type is MemberType.DIRECTORY
        assert member.size == 12 and member.is_encrypted
        assert member.hashes == {}
        codes = [d.code for d in member.diagnostics]
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED in codes
        assert DiagnosticCode.DIGEST_UNVERIFIABLE not in codes
        assert ar.read("d/") == b"hidden data!"
    tampered = tmp_path / "ae2-dir-bad.zip"
    tampered.write_bytes(
        build_aes_zip([(b"d/", b"hidden data!")], password=b"secret", tamper_hmac=True)
    )
    with (
        open_archive(tampered, password="secret") as ar,
        pytest.raises(CorruptionError, match="HMAC"),
    ):
        ar.read("d/")
    # AE-1 keeps the plaintext CRC, so a directory under it carries the digest.
    ae1 = tmp_path / "ae1-dir.zip"
    ae1.write_bytes(
        build_aes_zip([(b"d/", b"hidden data!")], password=b"secret", vendor_version=1)
    )
    with open_archive(ae1, password="secret") as ar:
        assert HashAlgorithm.CRC32 in ar.get("d/").hashes
        assert ar.read("d/") == b"hidden data!"
    # An AE-1 entry whose CRC field is zeroed still has its HMAC: no digest, but the
    # bytes are checked, so nothing is reported and a tampered HMAC still raises.
    crc = struct.pack("<I", zlib.crc32(b"hidden data!"))
    ae1_bytes = ae1.read_bytes()
    assert ae1_bytes.count(crc) == 2  # local header and central directory
    zeroed = tmp_path / "ae1-dir-zero-crc.zip"
    zeroed.write_bytes(ae1_bytes.replace(crc, b"\0\0\0\0"))
    with open_archive(zeroed, password="secret") as ar:
        member = ar.get("d/")
        assert member.hashes == {}
        codes = [d.code for d in member.diagnostics]
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED in codes
        assert DiagnosticCode.DIGEST_UNVERIFIABLE not in codes
        assert ar.read("d/") == b"hidden data!"
    tampered_ae1 = build_aes_zip(
        [(b"d/", b"hidden data!")],
        password=b"secret",
        vendor_version=1,
        tamper_hmac=True,
    ).replace(crc, b"\0\0\0\0")
    (tmp_path / "ae1-dir-tampered.zip").write_bytes(tampered_ae1)
    with (
        open_archive(tmp_path / "ae1-dir-tampered.zip", password="secret") as ar,
        pytest.raises(CorruptionError, match="HMAC"),
    ):
        ar.read("d/")


def test_directory_data_with_a_zero_crc_reads_unchecked(tmp_path: Path) -> None:
    """A directory entry's CRC field is 0 by convention, so a zero over declared data
    is no digest: the member carries none, ``DIGEST_UNVERIFIABLE`` says the read is
    unchecked, and the bytes come back instead of a ``CorruptionError``."""
    path = tmp_path / "zerocrc.zip"
    _zip_with_directory_data(path, zipfile.ZIP_STORED)
    data = bytearray(path.read_bytes())
    crc = zlib.crc32(b"hidden data!")
    assert data[:4] == b"PK\x03\x04"
    assert struct.unpack_from("<I", data, 14)[0] == crc
    struct.pack_into("<I", data, 14, 0)  # local header: CRC-32
    central = data.index(b"PK\x01\x02")
    assert struct.unpack_from("<I", data, central + 16)[0] == crc
    struct.pack_into("<I", data, central + 16, 0)  # central directory: CRC-32
    path.write_bytes(bytes(data))
    with open_archive(path) as ar:
        member = ar.get("d/")
        assert member.hashes == {}
        codes = [d.code for d in member.diagnostics]
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED in codes
        [diag] = [
            d
            for d in member.diagnostics
            if d.code is DiagnosticCode.DIGEST_UNVERIFIABLE
        ]
        assert diag.context is not None
        assert diag.context.to_dict()["reason"] == "no_integrity_anchor"
        assert "CRC-32 field is 0" in diag.message
        assert ar.read("d/") == b"hidden data!"
        assert HashAlgorithm.CRC32 in ar.get("d/f.txt").hashes


def test_a_special_entry_is_refused_by_type_not_by_data(tmp_path: Path) -> None:
    """A tombstone or special entry is refused for what it is, not for lacking data, so
    the message names the type; only the directory arm reasons about data. A special
    mode over stored bytes is a ``FILE`` and reads (DR-25), so the refused shape is the
    data-less one."""
    path = tmp_path / "device.zip"
    with zipfile.ZipFile(path, "w") as z:
        empty = zipfile.ZipInfo("dev/null")
        empty.create_system = 3
        empty.external_attr = (stat.S_IFCHR | 0o666) << 16
        z.writestr(empty, b"")
        full = zipfile.ZipInfo("dev/data")
        full.create_system = 3
        full.external_attr = (stat.S_IFCHR | 0o666) << 16
        z.writestr(full, b"twelve bytes")
    with open_archive(path) as ar:
        member = ar.get("dev/null")
        assert member.type is MemberType.OTHER
        assert member.size == 0
        with pytest.raises(
            ArchiveyUsageError, match="type is 'other' \\(not a file\\)"
        ):
            ar.read(member)
        full_member = ar.get("dev/data")
        assert full_member.type is MemberType.FILE
        assert ar.read(full_member) == b"twelve bytes"


def _zip_with_declared_empty_directory_body(path: Path) -> None:
    """``d/`` storing 2000 bytes with its uncompressed size field set to 0 in both the
    local header and the central directory: a body hidden one field away from the
    declared size."""
    body = b"0123456789" * 200
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(zipfile.ZipInfo("d/"), body, compress_type=zipfile.ZIP_STORED)
        z.writestr("d/f.txt", b"visible")
    data = bytearray(path.read_bytes())
    assert data[:4] == b"PK\x03\x04"
    assert struct.unpack_from("<I", data, 22)[0] == len(body)
    struct.pack_into("<I", data, 22, 0)  # local header: uncompressed size
    central = data.index(b"PK\x01\x02")
    assert struct.unpack_from("<I", data, central + 24)[0] == len(body)
    struct.pack_into(
        "<I", data, central + 24, 0
    )  # central directory: uncompressed size
    path.write_bytes(bytes(data))


def test_declared_empty_directory_with_a_body_is_reported(tmp_path: Path) -> None:
    """A directory declaring size 0 over a 2000-byte stored body is the same hidden
    payload as a declared one: reported, refused by strict, and ``open()`` says why
    it has nothing to return."""
    path = tmp_path / "hidden.zip"
    _zip_with_declared_empty_directory_body(path)
    with open_archive(path) as ar:
        member = ar.get("d/")
        assert member.type is MemberType.DIRECTORY
        assert (member.size, member.compressed_size) == (0, 2000)
        [diag] = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert diag.context is not None
        assert diag.context.to_dict()["size"] == 0
        assert diag.context.to_dict()["compressed_size"] == 2000
        assert "declares no data but stores a 2000-byte body" in diag.message
        with pytest.raises(ArchiveyUsageError, match="declares no data"):
            ar.read("d/")
        assert ar.read("d/f.txt") == b"visible"
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(path, config=config) as ar,
        pytest.raises(DiagnosticRaisedError) as excinfo,
    ):
        ar.members()
    assert excinfo.value.diagnostic.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED


@pytest.mark.parametrize(
    "method",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
)
def test_empty_directory_body_sizes_match_zipfile(tmp_path: Path, method: int) -> None:
    """The per-method size of an empty body is what ``zipfile`` writes for a directory
    given no data, and such a directory is not reported."""
    from archivey.internal.backends.zip_reader import _ZIP_EMPTY_BODY_SIZES

    assert set(_ZIP_EMPTY_BODY_SIZES) == {
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
        zipfile.ZIP_LZMA,
    }
    path = tmp_path / "empty.zip"
    try:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(zipfile.ZipInfo("d/"), b"", compress_type=method)
    except RuntimeError as exc:  # the compressor's module is not installed
        pytest.skip(str(exc))
    with zipfile.ZipFile(path) as z:
        assert z.infolist()[0].compress_size == _ZIP_EMPTY_BODY_SIZES[method]
    with open_archive(path) as ar:
        assert [m.name for m in ar.members()] == ["d/"]
        assert not ar.diagnostics.retained


def test_directory_data_is_refused_by_strict(tmp_path: Path) -> None:
    """The shape is a spec violation that hides bytes, so strict refuses it (DR-3),
    while the jar shape, which declares no data, passes."""
    path = tmp_path / "dirdata.zip"
    _zip_with_directory_data(path, zipfile.ZIP_STORED)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(path, config=config) as ar,
        pytest.raises(DiagnosticRaisedError) as excinfo,
    ):
        ar.members()
    assert excinfo.value.diagnostic.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED

    jar_only = tmp_path / "jar.zip"
    with zipfile.ZipFile(jar_only, "w") as z:
        z.writestr(zipfile.ZipInfo("jar/"), b"", compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("jar/f.txt", b"visible")
    with open_archive(jar_only, config=config) as ar:
        assert [m.name for m in ar.members()] == ["jar/", "jar/f.txt"]
        assert not ar.diagnostics.retained


def test_relative_seek_before_0_after_a_deferred_seek_clamps() -> None:
    """A forward seek on a deflated member is deferred (the gap is decoded anyway), so
    the inner is still at 0. A ``SEEK_CUR`` from the target that lands before 0 clamps
    there, as ``io.BytesIO`` does, rather than reporting the archive as corrupt."""
    data = bytes(range(256)) * 20
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", data)
    buf.seek(0)
    with (
        open_archive(buf, seekable_members=True) as reader,
        reader.open("a.bin") as stream,
    ):
        stream.seek(100)
        assert stream.seek(-500, io.SEEK_CUR) == 0
        assert stream.read() == data


@pytest.mark.parametrize(
    "method",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
    ids=["stored", "deflate", "bzip2", "lzma"],
)
def test_member_decoder_config_matches_the_codec_openers_own(
    monkeypatch: pytest.MonkeyPatch, method: int
) -> None:
    """The decoder config a ZIP member opens with is the one the codec opener derives.

    The reader builds the per-member config in one copy, filling the input size
    itself where the opener would. It must equal what the opener derives from the
    reader's base config: an LZMA member's header read moves the body, and the
    opener then measures the rest, not the whole body. A stored member gets the
    reader's base member config itself, not a copy: the openers do no config work
    for a stored stream source.
    """
    from archivey.internal.backends import zip_reader
    from archivey.internal.streams.codecs import open_codec_raw
    from archivey.internal.streams.codecs.registry import _decoder_config
    from archivey.internal.streams.streamtools import fix_stream_start_position

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        zf.writestr("a.txt", b"hello" * 100)
    seen: list[tuple[object, object]] = []

    with open_archive(io.BytesIO(buf.getvalue()), format=ArchiveFormat.ZIP) as ar:

        def capture(codec: Any, body: Any, *, config: Any, params: Any) -> Any:
            if method == zipfile.ZIP_STORED:
                base = ar._member_decoder_config  # type: ignore[attr-defined]
                seen.append((base, config))
                return open_codec_raw(codec, body, config=config, params=params)
            expected = _decoder_config(
                codec,
                fix_stream_start_position(body),
                dataclasses.replace(
                    ar._stream_config,  # type: ignore[attr-defined]
                    expected_decompressed_size=500,
                    refuse_input_after_end=True,
                ),
                ar._diagnostics_collector,  # type: ignore[attr-defined]
            )
            got = _decoder_config(codec, fix_stream_start_position(body), config, None)
            seen.append((expected, got))
            return open_codec_raw(codec, body, config=config, params=params)

        monkeypatch.setattr(zip_reader, "open_codec_raw", capture)
        with ar.open("a.txt") as stream:
            assert stream.read() == b"hello" * 100
    ((expected, got),) = seen
    if method == zipfile.ZIP_STORED:
        assert got is expected
    else:
        assert got == expected
