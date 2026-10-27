"""Single-file compressor backend tests — Stage 2.

Covers name inference, the one-member shape, the gzip stored-name surface, per-format
size rules, DIRECT/INDEXED cost, non-seekable streaming (including `.Z`), and the
password-rejection rule. ZST/LZ4 standalone are first-class here; only their
seekable-decompressor refinements remain for Phase 8.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import hashlib
import io
import logging
import lzma
import random
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveFormat,
    ArchiveyConfig,
    MemberType,
    open_archive,
)
from archivey.cost import AccessCost, ListingCost
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    PackageNotInstalledError,
    ResourceLimitError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.single_file_reader import SingleFileReader
from archivey.internal.hashing import crc32_digest
from archivey.types import HashAlgorithm
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import (
    MemberSeek,
    NonSeekableBytesIO,
    ShortReadBytesIO,
    SizedNonSeekable,
    assert_no_member_tail_seek,
    make_lzip_member,
    make_multiblock_xz,
    make_unix_compress,
    spy_member_seeks,
    xz_cli_available,
)

# LZMA Alone, zlib and Brotli have no magic: a source not named for its format (a
# BytesIO, or the ``.bi5`` samples) reaches them only with every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def _gzip_bytes(
    payload: bytes, *, filename: str | None = None, mtime: int = 0
) -> bytes:
    buf = io.BytesIO()
    gz = gzip.GzipFile(filename=filename or "", mode="wb", fileobj=buf, mtime=mtime)
    gz.write(payload)
    gz.close()
    return buf.getvalue()


# ---------------------------------------------------------------------------
# One backend, multiple formats; one-member shape
# ---------------------------------------------------------------------------


def test_one_backend_serves_multiple_formats() -> None:
    cases = {
        ArchiveFormat.GZ: gzip.compress(b"gzipped"),
        ArchiveFormat.BZ2: bz2.compress(b"bzipped"),
        ArchiveFormat.XZ: lzma.compress(b"xzipped"),
    }
    for expected_format, data in cases.items():
        with open_archive(io.BytesIO(data)) as ar:
            assert ar.format == expected_format
            members = ar.members()
            assert len(members) == 1
            assert members[0].type == MemberType.FILE


def test_exactly_one_member_no_directories() -> None:
    with open_archive(io.BytesIO(gzip.compress(b"x"))) as ar:
        members = list(ar)
        assert len(members) == 1
        assert members[0].is_file


def test_read_roundtrip() -> None:
    with open_archive(io.BytesIO(bz2.compress(b"hello bzip"))) as ar:
        assert ar.read(ar.members()[0]) == b"hello bzip"


# ---------------------------------------------------------------------------
# Member name inference
# ---------------------------------------------------------------------------


def test_name_strips_known_compression_extension(tmp_path: Path) -> None:
    path = tmp_path / "data.txt.gz"
    with gzip.open(path, "wb") as f:
        f.write(b"content")
    with open_archive(path) as ar:
        assert ar.members()[0].name == "data.txt"


def test_name_strips_lzma_alone_extension(tmp_path: Path) -> None:
    path = tmp_path / "data.txt.lzma"
    path.write_bytes(lzma.compress(b"content", format=lzma.FORMAT_ALONE))
    with open_archive(path) as ar:
        assert ar.format == ArchiveFormat.LZMA_ALONE
        assert ar.members()[0].name == "data.txt"
        assert ar.read(ar.members()[0]) == b"content"


def test_name_appends_uncompressed_for_unknown_extension(tmp_path: Path) -> None:
    # Identified by content (gzip magic), but ".bin" is not a compression extension, so the
    # extension is preserved and ".uncompressed" appended rather than discarding info.
    path = tmp_path / "mystery.bin"
    path.write_bytes(gzip.compress(b"content"))
    with open_archive(path) as ar:
        assert ar.members()[0].name == "mystery.bin.uncompressed"


def test_name_defaults_to_data_for_anonymous_stream() -> None:
    with open_archive(io.BytesIO(gzip.compress(b"x"))) as ar:
        assert ar.members()[0].name == "data"


def test_inferred_bidi_control_name_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    name = "invoice\u202ecod.exe"
    path = tmp_path / f"{name}.gz"
    path.write_bytes(gzip.compress(b"x"))
    # rapidgzip's native path open rejects some Unicode filenames on Windows
    # (U+202E); this test covers inferred-name presentation warnings, not the
    # accelerator, so pin the stdlib gzip path.
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)
    with (
        caplog.at_level(logging.WARNING, logger="archivey.normalization"),
        open_archive(path, config=config) as archive,
    ):
        assert archive.members()[0].name == name
    warnings = [
        record for record in caplog.records if "bidirectional control" in record.message
    ]
    assert len(warnings) == 1


# ---------------------------------------------------------------------------
# gzip stored filename + mtime
# ---------------------------------------------------------------------------


def test_gzip_stored_filename_surfaced(tmp_path: Path) -> None:
    path = tmp_path / "archive.gz"
    path.write_bytes(_gzip_bytes(b"payload", filename="report.csv"))
    with open_archive(path) as ar:
        member = ar.members()[0]
        # name comes from the source filename; the stored FNAME lives in extra + raw_name.
        assert member.name == "archive"
        assert member.extra["gzip.original_filename"] == "report.csv"
        assert member.raw_name == b"report.csv"


def test_gzip_stored_filename_non_ascii_is_latin1(tmp_path: Path) -> None:
    # RFC 1952 specifies FNAME as ISO-8859-1 (Latin-1). The gzip tooling stores
    # "café.txt" as the bytes b"caf\xe9.txt"; decoding those as UTF-8 would mangle them
    # (0xE9 is not valid UTF-8), so the decoded value must use Latin-1.
    path = tmp_path / "archive.gz"
    path.write_bytes(_gzip_bytes(b"payload", filename="café.txt"))
    with open_archive(path) as ar:
        member = ar.members()[0]
        assert member.raw_name == b"caf\xe9.txt"  # verbatim stored bytes
        assert member.extra["gzip.original_filename"] == "café.txt"


def test_gzip_without_stored_filename() -> None:
    # gzip.compress writes no FNAME -> no extra key, raw_name stays None.
    with open_archive(io.BytesIO(gzip.compress(b"x"))) as ar:
        member = ar.members()[0]
        assert "gzip.original_filename" not in member.extra
        assert member.raw_name is None


def test_failed_header_peek_restores_the_stream_position(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A header peek that fails partway leaves the caller's stream where it was."""
    armed = False
    read_prefix = SingleFileReader._read_source_prefix

    def arm(self: SingleFileReader, length: int) -> bytes:
        nonlocal armed
        armed = True
        return read_prefix(self, length)

    monkeypatch.setattr(SingleFileReader, "_read_source_prefix", arm)

    class FailsMidPeek(ShortReadBytesIO):
        # Once the header peek starts: one 3-byte chunk, then the source fails.
        reads_in_peek = 0

        def read(self, n: int = -1, /) -> bytes:
            if armed:
                self.reads_in_peek += 1
                if self.reads_in_peek > 1:
                    raise OSError("device went away")
            return super().read(n)

    junk = b"junk"
    stream = FailsMidPeek(junk + gzip.compress(b"payload"), max_chunk=3)
    stream.seek(len(junk))
    with pytest.raises(OSError, match="device went away"):
        open_archive(stream)
    assert stream.tell() == len(junk)


def test_gzip_mtime_surfaced() -> None:
    data = _gzip_bytes(b"payload", mtime=1_600_000_000)
    with open_archive(io.BytesIO(data)) as ar:
        member = ar.members()[0]
        assert member.modified is not None
        assert member.modified.tzinfo is not None
        assert int(member.modified.timestamp()) == 1_600_000_000


# ---------------------------------------------------------------------------
# Per-format size rules
# ---------------------------------------------------------------------------


def test_gz_size_none_before_full_read() -> None:
    # The ISIZE trailer is in extra["gzip.isize"], never in size
    # (test_single_file_size_fill.py).
    with open_archive(io.BytesIO(gzip.compress(b"x" * 1000))) as ar:
        assert ar.members()[0].size is None


def test_bz2_size_none_before_full_read() -> None:
    with open_archive(io.BytesIO(bz2.compress(b"x" * 1000))) as ar:
        assert ar.members()[0].size is None


def test_zlib_size_none() -> None:
    with open_archive(
        io.BytesIO(zlib.compress(b"x" * 1000)), config=_ALWAYS_PROBE
    ) as ar:
        assert ar.members()[0].size is None


def test_xz_size_from_header(tmp_path: Path) -> None:
    path = tmp_path / "data.xz"
    with lzma.open(path, "wb") as f:
        f.write(b"x" * 1234)
    # The XZ index is a bounded backward peek, so a seekable source answers with or
    # without declared seek demand: seekable_members is a member-stream capability and
    # must not change metadata.
    with open_archive(path, seekable_members=True) as ar:
        assert ar.members()[0].size == 1234
    with open_archive(path) as ar:
        assert ar.members()[0].size == 1234


def test_lzip_size_from_trailer(tmp_path: Path) -> None:
    path = tmp_path / "data.lz"
    path.write_bytes(make_lzip_member(b"y" * 777))
    for kwargs in ({}, {"seekable_members": True}):
        with open_archive(path, **kwargs) as ar:  # type: ignore[arg-type]
            assert ar.members()[0].size == 777


@pytest.mark.parametrize(
    ("suffix", "make"),
    [
        (".lz", lambda payload: make_lzip_member(payload)),
        (".xz", lambda payload: lzma.compress(payload)),
    ],
)
def test_cheap_size_does_not_require_a_path_source(
    tmp_path: Path, suffix: str, make
) -> None:
    """An in-memory source gets the same size as a file with identical bytes.

    The probes were gated on ``isinstance(source, Path)`` rather than on seekability,
    so a ``BytesIO`` silently lost ``member.size`` (and, for lzip, the stored CRC-32)
    even though the bytes and the seekability were identical. Nothing about the index
    or trailer scan needs a filesystem path.
    """
    payload = b"payload" * 500
    data = make(payload)
    path = tmp_path / f"data{suffix}"
    path.write_bytes(data)

    with open_archive(path, seekable_members=True) as ar:
        from_path = ar.members()[0]
        expected_size, expected_hashes = from_path.size, dict(from_path.hashes)
    assert expected_size == len(payload)

    buf = io.BytesIO(data)
    with open_archive(buf, seekable_members=True) as ar:
        from_stream = ar.members()[0]
        assert from_stream.size == expected_size
        assert dict(from_stream.hashes) == expected_hashes
    # The probe must not close or disturb a stream the caller owns.
    assert not buf.closed
    buf.seek(0)
    assert buf.read() == data


def test_cheap_size_still_needs_seekability(suffix: str = ".lz") -> None:
    """Non-seekable sources still get no cheap size -- that gate is the real one."""
    payload = b"payload" * 500
    stream = NonSeekableBytesIO(make_lzip_member(payload))
    with open_archive(stream, streaming=True) as ar:
        assert next(iter(ar)).size is None


def test_compressed_size_on_a_non_seekable_source_ignores_its_size_claim() -> None:
    # A pipe has no ``SEEK_END`` to measure its length, so it reports ``None``, the same
    # as a pipe without the attribute. A seekable stream's ``size`` attribute is
    # reported, so this is about seekability, not about trusting the claim.
    data = gzip.compress(b"payload" * 500)
    stream = SizedNonSeekable(data, size=123_456_789)
    with open_archive(stream, streaming=True) as ar:
        assert next(iter(ar)).compressed_size is None


# ---------------------------------------------------------------------------
# A member stream as the source: a seek to its end may decode the whole member
# ---------------------------------------------------------------------------


def _container_of(kind: str, name: str, data: bytes) -> io.BytesIO:
    """``data`` as the one member ``name`` of a ZIP (deflated or stored) or a TAR."""
    buf = io.BytesIO()
    if kind == "tar":
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    else:
        method = zipfile.ZIP_DEFLATED if kind == "zip_deflated" else zipfile.ZIP_STORED
        with zipfile.ZipFile(buf, "w", method) as zf:
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def _spy_reader_init_seeks(patch: pytest.MonkeyPatch) -> list[MemberSeek]:
    """The ``ArchiveStream`` seeks made inside ``SingleFileReader.__init__``.

    That is where the metadata probes run. Detection before it and the codec open after
    it have their own rules (detection's: ``tests/test_detection_workspace.py``). The
    record and the tail rule are the shared ones in ``tests/streams_util.py``, so a
    change to what counts as a tail seek reaches both.
    """
    seeks = spy_member_seeks(patch)
    in_init: list[MemberSeek] = []
    real_init = SingleFileReader.__init__

    def init(self: SingleFileReader, *args: object, **kwargs: object) -> None:
        start = len(seeks)
        try:
            real_init(self, *args, **kwargs)  # type: ignore[arg-type]
        finally:
            in_init.extend(seeks[start:])

    patch.setattr(SingleFileReader, "__init__", init)
    return in_init


@pytest.mark.parametrize("container", ["zip_deflated", "zip_stored", "tar"])
@pytest.mark.parametrize(
    ("name", "make"),
    [
        ("m.gz", gzip.compress),
        ("m.xz", lzma.compress),
        ("m.lz", make_lzip_member),
    ],
)
def test_member_stream_source_is_not_seeked_to_its_end(
    monkeypatch: pytest.MonkeyPatch, container: str, name: str, make
) -> None:
    # A compressed file inside another archive, opened as a member stream. The member
    # advertises its length, so compressed_size needs no seek. The xz index and lzip
    # trailer sit at the end, so those probes are skipped: size=None and no CRC32.
    #
    # Every member stream counts as one whose seek may re-decode, as a group. For a
    # deflated ZIP entry that is true; for a stored ZIP entry or a TAR member, whose
    # seek is a slice of the container, it is the price of the coarse rule. The
    # stored and TAR rows pin that loss as the contract (spec: "size matrix").
    data = make(random.Random(7).randbytes(64 * 1024))
    with (
        open_archive(
            _container_of(container, name, data), seekable_members=True
        ) as outer,
        outer.open(name) as member,
        monkeypatch.context() as patch,
    ):
        assert member.seekable()
        member_id = id(member)
        seeks = _spy_reader_init_seeks(patch)
        with open_archive(member) as nested:
            (inner,) = nested.members()
    assert inner.compressed_size == len(data)
    assert inner.size is None
    assert HashAlgorithm.CRC32 not in inner.hashes
    # The whole record, so a spy that stops seeing the member fails here: .gz reads
    # its header prefix (one seek, back to 0); .xz / .lz seek nothing at open.
    expected = [MemberSeek(member_id, 0, 0)] if name == "m.gz" else []
    assert seeks == expected
    assert_no_member_tail_seek(seeks, {member_id: len(data)})


@pytest.mark.parametrize("container", ["zip_deflated", "zip_stored", "tar"])
def test_non_seekable_member_stream_reports_its_advertised_compressed_size(
    container: str,
) -> None:
    # The default nesting shape: the outer archive is opened without
    # seekable_members, so the member stream is not seekable. Its advertised length is
    # the one its container's header declares, not a caller's claim, so it is still the
    # compressed size. Metadata must not depend on the outer seekable_members.
    data = gzip.compress(b"payload" * 10)
    with (
        open_archive(_container_of(container, "x.gz", data)) as outer,
        outer.open("x.gz") as member,
    ):
        assert not member.seekable()
        with open_archive(member, streaming=True) as nested:
            sizes = [m.compressed_size for m in nested]
    assert sizes == [len(data)]


def test_member_stream_source_without_a_length_reports_no_compressed_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The outer .gz cannot advertise its member's length, so the inner reader has no
    # cheap size. It reports None rather than seeking the member to its end.
    inner_gz = gzip.compress(random.Random(7).randbytes(64 * 1024))
    with (
        open_archive(
            io.BytesIO(gzip.compress(inner_gz)), seekable_members=True
        ) as outer,
        outer.open(outer.members()[0]) as member,
        monkeypatch.context() as patch,
    ):
        assert member.seekable()
        assert getattr(member, "size", None) is None
        member_id = id(member)
        seeks = _spy_reader_init_seeks(patch)
        with open_archive(member) as nested:
            assert nested.format == ArchiveFormat.GZ
            assert nested.members()[0].compressed_size is None
    assert seeks, "the spy saw no seek during the reader's open"
    assert_no_member_tail_seek(seeks, {member_id: len(inner_gz)})


# ---------------------------------------------------------------------------
# Stored decompressed CRC (cheap dedupe; no decompression)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(b"", id="single-member"),
        pytest.param(gzip.compress(b"second"), id="second-member"),
        pytest.param(b"\0" * 8, id="nul-padding"),
    ],
)
def test_gzip_never_reports_a_crc32(
    tmp_path: Path, source_kind: str, tail: bytes
) -> None:
    """A gzip has no digest, before or after a full read.

    The trailer CRC covers the whole member only when the file holds one member, and
    proving that at open means scanning the whole file. After a read it is useless: the
    decoder has already checked each member's CRC.
    """
    data = gzip.compress(b"first") + tail
    path = tmp_path / "one.gz"
    path.write_bytes(data)
    source: Path | io.BytesIO = path if source_kind == "path" else io.BytesIO(data)
    with open_archive(source) as ar:
        member = ar.members()[0]
        assert HashAlgorithm.CRC32 not in member.hashes
        ar.read(member)
        assert HashAlgorithm.CRC32 not in member.hashes


def test_gzip_open_does_not_scan_for_a_second_member() -> None:
    """Opening and listing a large gzip reads a bounded prefix, not the whole file.

    Counted in bytes rather than by patching the scan function, so it fails against
    any open-time scan however it is imported. The open-time validation probe reads
    about 1 MiB. Before the change, the scan for a second member read this file in
    1 MiB blocks until it hit a chance ``1f 8b 08`` match, about 4 MiB in with this
    seed.
    """

    class CountingBytesIO(io.BytesIO):
        consumed = 0

        def read(self, size: int | None = -1, /) -> bytes:
            data = super().read(size)
            self.consumed += len(data)
            return data

    data = gzip.compress(random.Random(7).randbytes(8 << 20), 1)
    source = CountingBytesIO(data)
    with open_archive(source) as ar:
        assert ar.members()[0].name == "data"
    assert source.consumed < 2 << 20


def test_gzip_omits_crc32_on_nonseekable_source() -> None:
    data = gzip.compress(b"pipe-payload")
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        report = ar.members_report_if_available()
        assert report is not None
        assert HashAlgorithm.CRC32 not in report[0].hashes


def test_lzip_exposes_stored_crc32(tmp_path: Path) -> None:
    payload = b"lzip-crc-payload" * 3
    path = tmp_path / "data.lz"
    path.write_bytes(make_lzip_member(payload))
    with open_archive(path, seekable_members=True) as ar:
        member = ar.members()[0]
        assert member.size == len(payload)
        assert member.hashes[HashAlgorithm.CRC32] == crc32_digest(zlib.crc32(payload))
    # Same gate as size — and that gate is the *source's* shape, not the caller's
    # declaration, so a plain open gets both (the dedupe caller never asks to seek).
    with open_archive(path) as ar:
        member = ar.members()[0]
        assert member.size == len(payload)
        assert member.hashes[HashAlgorithm.CRC32] == crc32_digest(zlib.crc32(payload))


def test_lzip_version_0_is_unsupported_at_open(tmp_path: Path) -> None:
    """A version-0 ``.lz`` is a recognized lzip file archivey cannot read, not damage."""
    member = bytearray(make_lzip_member(b"old format"))
    member[4] = 0
    path = tmp_path / "old.lz"
    path.write_bytes(bytes(member))
    with (
        pytest.raises(UnsupportedFeatureError, match="lzip version 0 "),
        open_archive(path) as ar,
    ):
        ar.read(ar.members()[0])


def test_multi_member_lzip_exposes_combined_crc32(tmp_path: Path) -> None:
    from unittest.mock import patch

    import archivey.internal.streams.codecs.lzip_decoder as lzip_mod
    from tests.streams_util import make_multi_member_lzip

    parts = [b"alpha-payload", b"beta" * 20, b"gamma"]
    path = tmp_path / "multi.lz"
    path.write_bytes(make_multi_member_lzip(parts))
    full = b"".join(parts)

    with (
        patch.object(
            lzip_mod,
            "_iter_trailers_backwards",
            wraps=lzip_mod._iter_trailers_backwards,
        ) as scanned,
        open_archive(path, seekable_members=True) as ar,
    ):
        member = ar.members()[0]
        assert scanned.call_count == 1, "size + CRC must share one backward index scan"
        assert member.size == len(full)
        assert member.hashes[HashAlgorithm.CRC32] == crc32_digest(zlib.crc32(full))
        assert ar.read(member) == full


def test_other_single_file_codecs_omit_stored_digests(tmp_path: Path) -> None:
    payload = b"no-whole-member-crc"
    cases = {
        "data.bz2": bz2.compress(payload),
        "data.xz": lzma.compress(payload),
        "data.zz": zlib.compress(payload),
    }
    for name, blob in cases.items():
        path = tmp_path / name
        path.write_bytes(blob)
        with open_archive(path) as ar:
            assert HashAlgorithm.CRC32 not in ar.members()[0].hashes, name


def test_zlib_omits_hashes_but_verifies_adler_on_read(tmp_path: Path) -> None:
    """Adler-32 is not on member.hashes, but a corrupt trailer still fails on read."""
    path = tmp_path / "bad-adler.zz"
    blob = bytearray(zlib.compress(b"zlib-adler-payload" * 5))
    blob[-1] ^= 0xFF
    path.write_bytes(blob)
    with open_archive(path) as ar:
        member = ar.members()[0]
        assert not member.hashes
        with raises_corruption_not_truncation():
            ar.read(member)


def test_gzip_reads_and_rereads_without_a_listed_crc32(tmp_path: Path) -> None:
    payload = b"verify-unchanged"
    path = tmp_path / "ok.gz"
    path.write_bytes(gzip.compress(payload))
    with open_archive(path) as ar:
        member = ar.members()[0]
        assert ar.read(member) == payload
        # Second open still succeeds (path source; codec verifies its own trailer).
        assert ar.read(member) == payload


def test_lzma_alone_size_from_header_when_known(tmp_path: Path) -> None:
    payload = b"z" * 321
    # stdlib FORMAT_ALONE always writes the unknown-size marker. Patching the 8-byte
    # size field is enough to exercise extract_metadata; do not round-trip the patched
    # bytes — some liblzma builds (notably Windows/macOS 3.14 CI) treat that header
    # rewrite as corrupt because the encoder produced an unknown-size end marker.
    compressed = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    compressed = compressed[:5] + len(payload).to_bytes(8, "little") + compressed[13:]
    path = tmp_path / "data.lzma"
    path.write_bytes(compressed)
    with open_archive(path) as ar:
        assert ar.members()[0].size == 321


def test_lzma_alone_size_none_when_unknown_marker(tmp_path: Path) -> None:
    payload = b"z" * 321
    path = tmp_path / "data.lzma"
    path.write_bytes(lzma.compress(payload, format=lzma.FORMAT_ALONE))
    with open_archive(path) as ar:
        assert ar.members()[0].size is None
        assert ar.read(ar.members()[0]) == payload


# Real LZMA Alone streams from the CPython BPO-21872 attachments: declared size known,
# no end-of-payload marker. Provenance and why only three of the nineteen are committed:
# tests/fixtures/external/README.md. The digests are of the decompressed bytes, taken from
# `xz --format=lzma -dc` rather than from stdlib `lzma`, so the pin does not rest on the
# same library the reader uses.
_BPO21872_DIR = Path(__file__).parent / "fixtures" / "external" / "lzma_bpo21872"
_BPO21872_SAMPLES = {
    "22h_ticks_bad.bi5": (
        45480,
        "d8006300ac1a5c5b76423d24e7bb2adcae3fb00c163d917b5e8572948d699f6d",
    ),
    "23h_ticks_good.bi5": (
        34740,
        "96d031b2404fc47af4fd0838f5d0c2264a7053d16e56ef0510af44125e053157",
    ),
    "failed_file_01.lzma": (
        33812,
        "73ef3f56add4db467b4b8e4953e195e7978b02c92905d2edd1f90986918bfc2b",
    ),
}


@pytest.mark.parametrize("name", sorted(_BPO21872_SAMPLES))
def test_bpo21872_lzma_alone_samples_decode_whole(name: str) -> None:
    """Files that stdlib `lzma` used to return short must come back whole.

    CPython fixed the underlying defect in 3.7, so this pins our own stream layer,
    which chunks its reads differently from `lzma.open`. The original bug was
    sensitive to where a read landed relative to an internal buffer boundary, hence
    the several chunk sizes — 8192 is the one the bug report singles out.
    """
    expected_size, expected_digest = _BPO21872_SAMPLES[name]
    path = _BPO21872_DIR / name

    with open_archive(path, config=_ALWAYS_PROBE) as ar:
        member = ar.members()[0]
        # These carry a real known size in the header, which stdlib never writes.
        assert member.size == expected_size
        whole = ar.read(member)
    assert len(whole) == expected_size
    assert hashlib.sha256(whole).hexdigest() == expected_digest

    for chunk_size in (1, 8192, 65536):
        with open_archive(path, config=_ALWAYS_PROBE) as ar:
            stream = ar.open(ar.members()[0])
            got = bytearray()
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                got += chunk
        assert bytes(got) == whole, f"short read at chunk_size={chunk_size}"


def test_tar_lzma_alone_roundtrip(tmp_path: Path) -> None:
    import tarfile

    from archivey.types import ContainerFormat, StreamFormat

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        info = tarfile.TarInfo("nested.txt")
        payload = b"nested alone tar"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    path = tmp_path / "archive.tar.lzma"
    path.write_bytes(lzma.compress(tar_buf.getvalue(), format=lzma.FORMAT_ALONE))
    with open_archive(path) as ar:
        assert ar.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)
        member = next(m for m in ar if m.is_file)
        assert member.name == "nested.txt"
        assert ar.read(member) == b"nested alone tar"


# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------


def test_cost_is_indexed_and_direct() -> None:
    with open_archive(io.BytesIO(gzip.compress(b"x"))) as ar:
        cost = ar.cost
        assert cost.listing_cost == ListingCost.INDEXED
        assert cost.access_cost == AccessCost.DIRECT


def test_archive_info() -> None:
    with open_archive(io.BytesIO(gzip.compress(b"x"))) as ar:
        info = ar.info
        assert info.member_count == 1
        assert info.is_solid is False
        assert info.is_encrypted is False


# ---------------------------------------------------------------------------
# Non-seekable behavior
# ---------------------------------------------------------------------------


def test_non_seekable_gzip_requires_streaming_mode() -> None:
    # Random access (streaming=False) promises repeatable open()/read(), which a
    # non-seekable source cannot honor (one decompression pass) — fail fast at open,
    # like every other format (it used to open and then silently return an empty
    # stream on a re-read).
    data = gzip.compress(b"streamed payload")
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(data))


def test_non_seekable_gzip_streams_fine() -> None:
    # Single-file formats stream from a non-seekable source under streaming=True
    # (the mode a non-seekable source requires).
    data = gzip.compress(b"streamed payload")
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        # Read while the generator is live: exhaustion closes the current stream.
        pairs = list(ar.stream_members())
        assert len(pairs) == 1
        _member, stream = pairs[0]
        assert stream is not None
        # Re-open via random open is unavailable in streaming mode; drain via a fresh
        # streaming pass that reads before the generator finishes.
    with open_archive(NonSeekableBytesIO(data), streaming=True) as ar:
        for _member, stream in ar.stream_members():
            assert stream is not None
            assert stream.read() == b"streamed payload"


@requires("ncompress")
def test_unix_compress_non_seekable_requires_streaming_mode() -> None:
    """Random access still needs a seekable source — same rule as gzip."""
    data = make_unix_compress(b"lzw payload")
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(data), format=ArchiveFormat.Z)


@requires("ncompress")
def test_unix_compress_non_seekable_streams_fine() -> None:
    data = make_unix_compress(b"lzw payload")
    with open_archive(
        NonSeekableBytesIO(data), format=ArchiveFormat.Z, streaming=True
    ) as ar:
        for _member, stream in ar.stream_members():
            assert stream is not None
            assert stream.read() == b"lzw payload"


@requires("ncompress")
def test_unix_compress_seekable_reads(tmp_path: Path) -> None:
    path = tmp_path / "data.Z"
    path.write_bytes(make_unix_compress(b"lzw payload"))
    with open_archive(path) as ar:
        assert ar.format == ArchiveFormat.Z
        assert ar.read(ar.members()[0]) == b"lzw payload"


# ---------------------------------------------------------------------------
# Password rejection
# ---------------------------------------------------------------------------


def test_password_is_accepted_and_recorded() -> None:
    from archivey.diagnostics import DiagnosticCode

    with open_archive(io.BytesIO(gzip.compress(b"x")), password=b"secret") as reader:
        assert reader.diagnostics.counts[DiagnosticCode.PASSWORD_ARGUMENT_UNUSED] == 1


# ---------------------------------------------------------------------------
# Brotli (magic-less, detected by content probe)
# ---------------------------------------------------------------------------


@requires("brotli")
def test_brotli_roundtrip() -> None:
    import brotli

    data = brotli.compress(b"brotli payload")
    with open_archive(io.BytesIO(data), config=_ALWAYS_PROBE) as ar:
        assert ar.format == ArchiveFormat.BROTLI
        assert ar.read(ar.members()[0]) == b"brotli payload"


# ---------------------------------------------------------------------------
# zstd / lz4 standalone (now first-class single-file formats)
# ---------------------------------------------------------------------------


@requires_zstd()
def test_zstd_roundtrip(tmp_path: Path) -> None:
    zstd = zstd_backend()
    data = zstd.compress(b"zstd payload")
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.format == ArchiveFormat.ZST
        assert ar.members()[0].name == "data"
        assert ar.read(ar.members()[0]) == b"zstd payload"

    path = tmp_path / "file.bin.zst"
    path.write_bytes(data)
    with open_archive(path) as ar:
        assert ar.members()[0].name == "file.bin"


@requires("lz4")
def test_lz4_roundtrip() -> None:
    import lz4.frame

    data = lz4.frame.compress(b"lz4 payload")
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.format == ArchiveFormat.LZ4
        assert ar.read(ar.members()[0]) == b"lz4 payload"


# ---------------------------------------------------------------------------
# The backend uses the resolved format it is given (no re-inspection)
# ---------------------------------------------------------------------------


def test_explicit_format_bypasses_detection() -> None:
    # Forcing format=GZ routes straight to the gzip codec without re-detecting the source.
    data = gzip.compress(b"forced gzip")
    with open_archive(io.BytesIO(data), format=ArchiveFormat.GZ) as ar:
        assert ar.format == ArchiveFormat.GZ
        assert ar.read(ar.members()[0]) == b"forced gzip"


# ---------------------------------------------------------------------------
# Corrupt / truncated input -> CorruptionError / TruncatedError end-to-end.
# (Per-format slice of testing-contract's adversarial-corpus requirement, pulled
# forward so the backend wires the codec layer's translation through correctly.
# gzip is used because it is always available: zero-dep stdlib.)
# ---------------------------------------------------------------------------


# A non-seekable source keeps the codec sequential (no rapidgzip/indexed_bzip2
# accelerator), so these assert the backend's own stdlib translation deterministically,
# independent of which optional accelerators the environment has installed.


def _read_single_streamed_member(ar) -> bytes:
    for _member, stream in ar.stream_members():
        assert stream is not None
        return stream.read()
    raise AssertionError("expected one member stream")


def test_truncated_gzip_raises_truncated() -> None:
    full = gzip.compress(b"streamed payload" * 1000)
    truncated = full[: len(full) // 2]  # gzip magic intact -> detection picks GZ
    with (
        open_archive(NonSeekableBytesIO(truncated), streaming=True) as ar,
        pytest.raises(TruncatedError),
    ):
        _read_single_streamed_member(ar)


def test_truncation_is_caught_as_corruption() -> None:
    # The error-handling spec's row: data that ends early raises TruncatedError, and
    # ``except CorruptionError`` catches it.
    assert issubclass(TruncatedError, CorruptionError)
    full = gzip.compress(b"streamed payload" * 1000)
    with (
        open_archive(NonSeekableBytesIO(full[: len(full) // 2]), streaming=True) as ar,
        pytest.raises(CorruptionError) as caught,
    ):
        _read_single_streamed_member(ar)
    assert isinstance(caught.value, TruncatedError)


def test_corrupt_gzip_raises_corruption() -> None:
    data = bytearray(gzip.compress(b"streamed payload" * 100))
    data[15:35] = b"\x00" * 20  # clobber the deflate body (past the 10-byte header)
    with (
        open_archive(NonSeekableBytesIO(bytes(data)), streaming=True) as ar,
        raises_corruption_not_truncation(),
    ):
        _read_single_streamed_member(ar)


def test_open_from_mid_positioned_stream() -> None:
    # The compressed stream starts at the caller's position (an embedded .gz after junk
    # bytes); reads — including a re-open for a second read — must use that origin.
    junk = b"X" * 37
    payload = b"embedded payload " * 20
    stream = io.BytesIO(junk + gzip.compress(payload))
    stream.seek(len(junk))
    with open_archive(stream, format=ArchiveFormat.GZ) as ar:
        (member,) = ar.members()
        assert ar.read(member) == payload
        assert ar.read(member) == payload  # re-open rewinds to the embedded origin


def test_concurrent_open_same_member_interleaved() -> None:
    # Single-file routes through SharedSource: two opens of the one member stay correct
    # when read in interleaved partial chunks (and open is reentrant — no _first_stream).
    payload = b"abcdefghijklmnopqrstuvwxyz" * 40
    with open_archive(
        io.BytesIO(gzip.compress(payload)),
        concurrent_operations=True,
        seekable_members=True,
    ) as ar:
        (member,) = ar.members()
        s1 = ar.open(member)
        s2 = ar.open(member)
        assert s1.read(10) == payload[:10]
        assert s2.read(7) == payload[:7]
        assert s1.read(5) == payload[10:15]
        assert s2.read() == payload[7:]
        assert s1.read() == payload[15:]
        s1.close()
        s2.close()


def test_reentrant_open_after_first_read(tmp_path: Path) -> None:
    # Path source: open, read partially, open again, both complete independently.
    path = tmp_path / "data.txt.gz"
    payload = b"reentrant payload " * 50
    path.write_bytes(gzip.compress(payload))
    with open_archive(path, concurrent_operations=True, seekable_members=True) as ar:
        (member,) = ar.members()
        first = ar.open(member)
        assert first.read(8) == payload[:8]
        second = ar.open(member)
        assert second.read() == payload
        assert first.read() == payload[8:]
        first.close()
        second.close()


def test_read_after_reader_and_source_close_raises_typed_error() -> None:
    # archive-reading "fail loudly" scenario: when the caller closes the source out from
    # under a live member stream, the next read surfaces a typed error at the reader
    # boundary — never a raw ValueError. Archivey never closes a caller-supplied
    # BinaryIO itself, so this state is only reachable by the caller doing it.
    # Pinned to the stdlib gzip path with an incompressible payload larger than its
    # read-ahead, so the read deterministically touches the closed source (the
    # accelerator may buffer a small member whole on its first read — and terminates on
    # a dead source; see dev-docs/known-issues.md).
    payload = random.Random(0).randbytes(256 * 1024)  # incompressible: stays ~256 KiB
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)
    source = io.BytesIO(gzip.compress(payload))
    ar = open_archive(source, config=config)
    (member,) = ar.members()
    stream = ar.open(member)
    assert stream.read(16) == payload[:16]
    source.close()
    with pytest.raises(ArchiveyUsageError):
        while stream.read(65536):
            pass
    with contextlib.suppress(Exception):
        stream.close()
    with contextlib.suppress(Exception):
        ar.close()


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_xz_seek_across_blocks_through_open_archive(tmp_path: Path) -> None:
    # The shape threaded `xz -T0` writes: one stream, many blocks. With the block
    # index built by a first read, a seek resumes mid-file and the read crosses block
    # boundaries; every byte must match and a read to the end must not raise.
    payload = random.Random(1).randbytes(1_000_000)
    path = tmp_path / "rand.bin.xz"
    path.write_bytes(make_multiblock_xz(payload, block_size=131072))
    with open_archive(path, streaming=False, seekable_members=True) as ar:
        (member,) = ar.members()
        with ar.open(member) as f:
            assert f.read() == payload
            f.seek(300_000)
            assert f.read(300_000) == payload[300_000:600_000]
            f.seek(300_000)
            assert f.read() == payload[300_000:]


# ---------------------------------------------------------------------------
# Open-time validation: a source that is not decodable as the claimed codec raises
# from open_archive, not from a later read (format-single-file-compressors).
# ---------------------------------------------------------------------------


def _zstd_compress(data: bytes) -> bytes:
    return zstd_backend().compress(data)


def _brotli_compress(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data)


def _lz4_compress(data: bytes) -> bytes:
    import lz4.frame

    return lz4.frame.compress(data)


# suffix -> (compressor, skip marks). The ten single-file codecs.
_SINGLE_FILE_CODECS = {
    ".gz": (gzip.compress, ()),
    ".bz2": (bz2.compress, ()),
    ".xz": (lzma.compress, ()),
    ".lzma": (lambda d: lzma.compress(d, format=lzma.FORMAT_ALONE), ()),
    ".zz": (zlib.compress, ()),
    ".lz": (make_lzip_member, ()),
    ".zst": (_zstd_compress, (requires_zstd(),)),
    ".br": (_brotli_compress, (requires("brotli"),)),
    ".lz4": (_lz4_compress, (requires("lz4"),)),
    ".Z": (make_unix_compress, (requires("ncompress"),)),
}

_NOT_A_STREAM = {"zeros": b"\x00" * 40_000, "zero-byte": b""}


def test_open_validation_table_covers_every_single_file_codec() -> None:
    # A new standalone codec gets open-time validation without a backend change; this
    # makes it fail here until the tables below cover it too.
    from archivey.internal.streams.codecs import SINGLE_FILE_CODECS

    # The canonical extension only: an alias (``.brotli``) is the same codec.
    suffixes = {codec.extensions[0] for codec in SINGLE_FILE_CODECS if codec.extensions}
    assert suffixes == set(_SINGLE_FILE_CODECS)


def _codec_params(*, decode_only: bool = False) -> list:
    """One param per codec, skipped where the test's needs are missing.

    ``decode_only`` is for tests that never call the compressor: ``.Z`` decodes natively
    and needs ``ncompress`` only to write fixtures, so it must run in the zero-dep leg.
    """
    return [
        pytest.param(
            suffix, id=suffix, marks=() if decode_only and suffix == ".Z" else marks
        )
        for suffix, (_compress, marks) in _SINGLE_FILE_CODECS.items()
    ]


@pytest.mark.parametrize("contents", sorted(_NOT_A_STREAM))
@pytest.mark.parametrize("suffix", _codec_params(decode_only=True))
@pytest.mark.parametrize("seekable_members", [False, True])
def test_undecodable_source_raises_at_open(
    tmp_path: Path, suffix: str, contents: str, seekable_members: bool
) -> None:
    path = tmp_path / f"backup{suffix}"
    path.write_bytes(_NOT_A_STREAM[contents])
    if (suffix, contents) == (".lzma", "zeros"):
        _assert_zeros_read_as_empty_lzma(path, seekable_members=seekable_members)
        return
    # The raise must come from open_archive itself, not from a read after it.
    with pytest.raises(CorruptionError):
        open_archive(path, seekable_members=seekable_members)


def _assert_zeros_read_as_empty_lzma(
    source: Path | io.BytesIO, **kwargs: object
) -> None:
    """Zeros are the one undecodable-looking source that is a valid stream.

    Eighteen zero bytes are a complete, empty LZMA Alone stream, and the zeros after it
    are padding, as after any codec's end. So the file reads as one empty member with
    nothing to report, the way a zero-filled file reads as an empty TAR (ADR 0015).
    """
    with open_archive(source, **kwargs) as ar:  # type: ignore[arg-type]
        assert ar.read(ar.members()[0]) == b""
        assert not ar.diagnostics.counts


@pytest.mark.parametrize("suffix", _codec_params())
def test_undecodable_bytesio_raises_at_open(suffix: str) -> None:
    # A seekable stream source takes the SharedSource branch rather than the path one.
    compress, _marks = _SINGLE_FILE_CODECS[suffix]
    with open_archive(io.BytesIO(compress(b"probe")), config=_ALWAYS_PROBE) as ar:
        fmt = ar.format
    if suffix == ".lzma":
        _assert_zeros_read_as_empty_lzma(io.BytesIO(b"\x00" * 40_000), format=fmt)
        return
    with pytest.raises(CorruptionError):
        open_archive(io.BytesIO(b"\x00" * 40_000), format=fmt)


@pytest.mark.parametrize("suffix", _codec_params())
@pytest.mark.parametrize("seekable_members", [False, True])
def test_valid_empty_stream_still_opens_and_reads_empty(
    tmp_path: Path, suffix: str, seekable_members: bool
) -> None:
    compress, _marks = _SINGLE_FILE_CODECS[suffix]
    path = tmp_path / f"empty{suffix}"
    path.write_bytes(compress(b""))
    with open_archive(path, seekable_members=seekable_members) as ar:
        assert ar.read(ar.members()[0]) == b""


def test_open_time_failure_names_no_member(tmp_path: Path) -> None:
    # Nobody asked for a member yet, so the error must not attribute the failure to one.
    path = tmp_path / "backup.gz"
    path.write_bytes(b"\x00" * 40_000)
    with raises_corruption_not_truncation() as info:
        open_archive(path)
    assert info.value.member_name is None
    assert info.value.archive_name is not None


def test_non_seekable_source_still_defers_validation_to_the_read() -> None:
    # A probe read would consume a byte the one-shot member stream needs, so a
    # non-seekable source keeps failing on the read, as documented.
    with (
        open_archive(
            NonSeekableBytesIO(b"\x00" * 40_000),
            format=ArchiveFormat.GZ,
            streaming=True,
        ) as ar,
        raises_corruption_not_truncation(),
    ):
        _read_single_streamed_member(ar)


@pytest.mark.parametrize(
    "mode", [AcceleratorMode.AUTO, AcceleratorMode.ON, AcceleratorMode.OFF]
)
@pytest.mark.parametrize("contents", sorted(_NOT_A_STREAM))
def test_corrupt_bz2_raises_whatever_the_accelerator_mode(
    tmp_path: Path, contents: str, mode: AcceleratorMode
) -> None:
    # A capability flag never turns a corrupt source into an empty successful read. Under
    # seekable_members=True the bzip2 read goes through rapidgzip's bundled decoder, which
    # used to return b"" for these inputs.
    if mode is not AcceleratorMode.OFF:
        pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    path = tmp_path / "garbage.bz2"
    path.write_bytes(_NOT_A_STREAM[contents])
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with (
        pytest.raises(CorruptionError),
        open_archive(path, seekable_members=True, config=config) as ar,
    ):
        ar.read(ar.members()[0])


_ACCELERATED_CODECS = pytest.mark.parametrize(
    ("suffix", "compress", "field"),
    [
        (".gz", gzip.compress, "use_rapidgzip"),
        (".bz2", bz2.compress, "use_indexed_bzip2"),
    ],
)


@_ACCELERATED_CODECS
@pytest.mark.parametrize("as_stream", [False, True], ids=["path", "stream"])
def test_open_time_probe_starts_no_accelerator_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    compress: Callable[[bytes], bytes],
    field: str,
    as_stream: bool,
) -> None:
    # The one-byte check at open decodes with the standard library: rapidgzip runs in a
    # child process, and the probe used to start one that the member read then started
    # again (about 30 ms each). An open and a full read start exactly one.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    from archivey.internal.streams.codecs import rapidgzip_select

    started: list[object] = []
    real = rapidgzip_select.RapidgzipChildStream

    def counting(*args: object, **kwargs: object) -> object:
        started.append(args)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rapidgzip_select, "RapidgzipChildStream", counting)
    payload = random.Random(5).randbytes(1 << 16) * 4
    path = tmp_path / f"data{suffix}"
    path.write_bytes(compress(payload))
    config = ArchiveyConfig(**{field: AcceleratorMode.ON})
    # A stream source shares one handle through views, a path source hands the codec
    # the path: two different routes to the probe.
    source = io.BytesIO(path.read_bytes()) if as_stream else path
    with open_archive(source, config=config) as ar:
        assert started == []
        assert ar.read(ar.members()[0]) == payload
    assert len(started) == 1


@_ACCELERATED_CODECS
@pytest.mark.parametrize("as_stream", [False, True], ids=["path", "stream"])
def test_open_raises_for_an_accelerator_on_that_is_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    compress: Callable[[bytes], bytes],
    field: str,
    as_stream: bool,
) -> None:
    # The probe decodes with the standard library but still resolves the accelerator,
    # so ON without rapidgzip fails at open (DR-15b), not on the first read.
    from archivey.internal.streams.codecs import deps

    monkeypatch.setattr(
        deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=False)
    )
    path = tmp_path / f"data{suffix}"
    path.write_bytes(compress(b"payload"))
    source = io.BytesIO(path.read_bytes()) if as_stream else path
    with pytest.raises(PackageNotInstalledError):
        open_archive(source, config=ArchiveyConfig(**{field: AcceleratorMode.ON}))


@_ACCELERATED_CODECS
@pytest.mark.parametrize("as_stream", [False, True], ids=["path", "stream"])
def test_open_raises_for_an_accelerator_on_with_no_child_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    compress: Callable[[bytes], bytes],
    field: str,
    as_stream: bool,
) -> None:
    # ON where no rapidgzip child can run fails at open too, and starts nothing.
    from archivey.internal.streams.codecs import deps, rapidgzip_select

    monkeypatch.setattr(deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=True))
    monkeypatch.setattr(
        rapidgzip_select, "rapidgzip_child_unavailable_reason", lambda: "test says no"
    )
    path = tmp_path / f"data{suffix}"
    path.write_bytes(compress(b"payload"))
    source = io.BytesIO(path.read_bytes()) if as_stream else path
    with pytest.raises(ResourceLimitError, match="test says no"):
        open_archive(source, config=ArchiveyConfig(**{field: AcceleratorMode.ON}))


@_ACCELERATED_CODECS
def test_open_logs_no_accelerator_fallback_for_auto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    suffix: str,
    compress: Callable[[bytes], bytes],
    field: str,
) -> None:
    # Open resolves only ON. AUTO is left to the read, which sees the size the
    # registry fills in: a small file never wanted rapidgzip, so where no child can
    # run, neither the open nor the read says it fell back.
    from archivey.internal.streams.codecs import bzip2_codec, deps, rapidgzip_select

    monkeypatch.setattr(deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=True))
    for module in (bzip2_codec, rapidgzip_select):
        monkeypatch.setattr(
            module, "rapidgzip_child_unavailable_reason", lambda: "test says no"
        )
    monkeypatch.setattr(rapidgzip_select, "_child_fallback_warned", set())
    path = tmp_path / f"data{suffix}"
    path.write_bytes(compress(b"payload"))
    config = ArchiveyConfig(**{field: AcceleratorMode.AUTO})
    with (
        caplog.at_level(logging.WARNING),
        open_archive(path, seekable_members=True, config=config) as ar,
    ):
        assert ar.read(ar.members()[0]) == b"payload"
    assert "test says no" not in caplog.text


def test_open_with_accelerator_on_reports_a_refused_gzip_header_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An ON open hands a gzip whose header zlib refuses to the standard library
    # before it would start a child, so the damage is reported even where no child
    # can run, as the read reports it.
    from archivey.internal.streams.codecs import deps, rapidgzip_select

    monkeypatch.setattr(deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=True))
    monkeypatch.setattr(
        rapidgzip_select, "rapidgzip_child_unavailable_reason", lambda: "test says no"
    )
    data = bytearray(gzip.compress(b"payload", mtime=0))
    data[3] |= 0x02  # FHCRC, with a CRC16 that cannot match
    data[10:10] = b"\x00\x00"
    path = tmp_path / "bad-header.gz"
    path.write_bytes(bytes(data))
    with pytest.raises(CorruptionError, match="header crc"):
        open_archive(path, config=ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON))


def test_open_with_accelerator_on_reports_a_zlib_header_rapidgzip_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A zlib stream with a preset dictionary is not zlib to rapidgzip, so an ON open
    # hands it to the standard library before it would start a child: the data error
    # comes first even where no child can run.
    from archivey.internal.streams.codecs import deps, rapidgzip_select

    monkeypatch.setattr(deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=True))
    monkeypatch.setattr(
        rapidgzip_select, "rapidgzip_child_unavailable_reason", lambda: "test says no"
    )
    compressor = zlib.compressobj(zdict=b"dictionary bytes here")
    path = tmp_path / "data.zz"
    path.write_bytes(compressor.compress(b"payload") + compressor.flush())
    with pytest.raises(CorruptionError):
        open_archive(path, config=ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON))


def test_open_time_probe_still_rejects_a_wrong_codec_with_the_accelerator_on(
    tmp_path: Path,
) -> None:
    # The probe runs with the standard library, so a source that is not the claimed
    # codec still fails at open, not on the first read.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    path = tmp_path / "zeros.gz"
    path.write_bytes(b"\x00" * 40_000)
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)
    with raises_corruption_not_truncation():
        open_archive(path, format=ArchiveFormat.GZ, config=config)
