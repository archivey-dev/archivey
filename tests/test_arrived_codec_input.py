"""A codec over a source that cannot seek decodes what has arrived, with the same result.

On a source that cannot seek, the single-file and compressed-TAR readers feed the
decoder from what has arrived, one read of the source per feed, so a pipe whose writer
keeps it open does not hold a read until the close. A feed can then end at any byte.
These tests read every codec's end, truncation, trailing-data, concatenation and damage
cases from a source that returns 1, 7 or 4096 bytes per read. They require the same
bytes, the same error type and message, and the same trailing-data reports as a read
of the same bytes whose every read is full, and, for data that reads clean, as a
``BytesIO`` read.

A short feed is never the end of the input: only an empty read is. A codec that took
a short feed for the end would report a truncation, or end a stream before a later
member, here.

Two things can depend on the feeds, and only for data that does not read clean. A
decoder call that fails gives no output, so how many bytes come out before an error
depends on how much input that call had (:func:`_same_outcome`). And Brotli finds its
end only by failing such a call
(:func:`test_a_brotli_tar_with_bytes_after_its_end_gives_right_bytes_or_brotli_error`).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import re
import tarfile
import zlib
from collections.abc import Callable
from typing import BinaryIO

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ProcessIsolation,
    open_archive,
    open_stream,
)
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import ArchiveyError
from archivey.types import ContainerFormat
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.streams_util import (
    NonSeekableBytesIO,
    ShortReadNonSeekable,
    make_lzip_member,
    make_unix_compress,
)

# Compressible text and random bytes, so both long matches and literal runs cross the
# feed boundaries.
_RNG = random.Random(4211)
_PAYLOAD = b"".join(
    b"line %d of the arrived-feed payload\n" % i for i in range(500)
) + _RNG.randbytes(3000)
_JUNK = b"appended signature\n"
_PIECES = [1, 7, 4096]
_CONFIG = ArchiveyConfig()


def _zstd(data: bytes) -> bytes:
    return zstd_backend().compress(data)


def _lz4(data: bytes) -> bytes:
    import lz4.frame

    return lz4.frame.compress(data)


def _brotli(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data)


def _lzma_alone(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_ALONE)


# Every codec a single file or a TAR can be compressed with: (compress, stream format,
# whether two streams joined end to end read as one file, marks).
_CODECS: dict[str, tuple[Callable[[bytes], bytes], ArchiveFormat, bool, tuple]] = {
    "gz": (lambda d: gzip.compress(d, mtime=0), ArchiveFormat.GZ, True, ()),
    "bz2": (bz2.compress, ArchiveFormat.BZ2, True, ()),
    "xz": (lzma.compress, ArchiveFormat.XZ, True, ()),
    "lz": (make_lzip_member, ArchiveFormat.LZIP, True, ()),
    "lzma": (_lzma_alone, ArchiveFormat.LZMA_ALONE, True, ()),
    "zz": (zlib.compress, ArchiveFormat.ZLIB, False, ()),
    "zst": (_zstd, ArchiveFormat.ZST, True, (requires_zstd(),)),
    "lz4": (_lz4, ArchiveFormat.LZ4, True, (requires("lz4"),)),
    "br": (_brotli, ArchiveFormat.BROTLI, False, (requires("brotli"),)),
    "Z": (make_unix_compress, ArchiveFormat.Z, False, (requires("ncompress"),)),
}


def _cases(compressed: bytes, second: bytes | None) -> dict[str, bytes]:
    """The inputs every codec is read from: its end, cuts, appended bytes and damage."""
    n = len(compressed)
    cases = {
        "whole": compressed,
        "trailing-junk": compressed + _JUNK,
        "zeros-at-end": compressed + bytes(64),
        "zeros-then-junk": compressed + bytes(100) + _JUNK,
        "cut-in-header": compressed[:3],
        "cut-near-start": compressed[: max(4, n // 50)],
        "cut-in-middle": compressed[: n // 2],
        "cut-before-last-byte": compressed[:-1],
        "cut-before-trailer": compressed[: max(1, n - 9)],
    }
    for position in (n // 3, n // 2, n - 5):
        damaged = bytearray(compressed)
        damaged[position] ^= 0x55
        cases[f"flip@{position * 100 // n}%"] = bytes(damaged)
    if second is not None:
        cases["concatenated"] = compressed + second
        cases["concatenated-then-junk"] = compressed + second + _JUNK
        cases["concatenated-cut"] = compressed + second[: len(second) // 2]
        damaged_magic = bytearray(second)
        damaged_magic[0] ^= 0x40
        cases["second-magic-damaged"] = compressed + bytes(damaged_magic)
    return cases


def _tar(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in (("a.txt", payload[:700]), ("b.bin", payload)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _error(exc: ArchiveyError) -> tuple[str, str]:
    """The error's type and message, without the member it was raised for.

    Where an error surfaces can depend on the feeds (see :func:`_same_outcome`).
    """
    return type(exc).__name__, re.sub(r"member='[^']*', ", "", str(exc))


def _outcome(
    source: BinaryIO,
    fmt: ArchiveFormat,
    piece: int | None,
    config: ArchiveyConfig = _CONFIG,
) -> tuple[object, ...]:
    """Every member's name and bytes up to the error that ended the pass, if any, that
    error, and the trailing-data reports.

    ``piece`` is the caller's read size, ``None`` for one ``read()`` per member. A
    member whose read raised is listed with the bytes delivered before the error.
    """
    members: list[tuple[str, bytes | None]] = []
    error: tuple[str, str] | None = None
    try:
        with open_archive(source, format=fmt, streaming=True, config=config) as reader:
            try:
                for member, stream in reader.stream_members():
                    if stream is None:
                        members.append((member.name, None))
                        continue
                    got = bytearray()
                    try:
                        if piece is None:
                            got += stream.read()
                        else:
                            while data := stream.read(piece):
                                got += data
                    finally:
                        members.append((member.name, bytes(got)))
            except ArchiveyError as exc:
                error = _error(exc)
            reports = tuple(
                d.message
                for d in reader.diagnostics.retained
                if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
            )
    except ArchiveyError as exc:
        return ("<open>", *_error(exc))
    return (tuple(members), error, reports)


def _same_outcome(got: tuple[object, ...], expected: tuple[object, ...]) -> bool:
    """Whether two outcomes are the same, but for where an error surfaced.

    A decoder that fails gives no output for the call that failed, so how many bytes
    come out before the error depends on how much input that call had, and so can
    the read that raises it: a whole-stream checksum can fail in the last member's
    read or in the scan after the TAR trailer. The error and every byte before it
    must still be the same. Both reads list the same members up to the shorter
    listing's last one, whose bytes start the other's.
    """
    if got[0] == "<open>" or expected[0] == "<open>":
        return got == expected
    members, error, reports = got
    expected_members, expected_error, expected_reports = expected
    if error != expected_error or reports != expected_reports:
        return False
    if error is None:
        return members == expected_members
    short, long = sorted((members, expected_members), key=len)  # type: ignore[arg-type]
    if not short:
        return True
    if short[:-1] != long[: len(short) - 1]:
        return False
    (name, data), (long_name, long_data) = short[-1], long[len(short) - 1]
    if name != long_name:
        return False
    if data is None or long_data is None:
        return data == long_data
    return data.startswith(long_data) or long_data.startswith(data)


_DAMAGE = {"CorruptionError", "StreamChecksumError"}


def _same_damage(got: tuple[object, ...], expected: tuple[object, ...]) -> bool:
    """Whether both reads found damaged data and delivered the same bytes before it.

    Inside a compressed TAR, damaged data can fail two checks: the codec's and the
    TAR header's. Which one fails first depends on whether the decoder reached the
    codec's check in the call that gave the TAR's bad header, so on the feeds.
    """
    if _same_outcome(got, expected):
        return True
    if got[0] == "<open>" or expected[0] == "<open>":
        return False
    members, error, _ = got
    expected_members, expected_error, _ = expected
    if error is None or expected_error is None:
        return False
    if error[0] not in _DAMAGE or expected_error[0] not in _DAMAGE:  # type: ignore[index]
        return False
    for (name, data), (expected_name, expected_data) in zip(members, expected_members):  # type: ignore[call-overload]
        if name != expected_name:
            return False
        if not (data.startswith(expected_data) or expected_data.startswith(data)):
            return False
    return True


def _assert_same_from_every_piece_size(
    data: bytes,
    fmt: ArchiveFormat,
    piece: int | None,
    *,
    config: ArchiveyConfig = _CONFIG,
    pieces: list[int] = _PIECES,
    same: Callable[[tuple[object, ...], tuple[object, ...]], bool] = _same_outcome,
) -> None:
    # The same source with every read full: one feed takes up to 64 KiB. A source
    # that can seek is checked at open and can find a Brotli stream's end, so an
    # error can differ from it; data that reads clean reads the same. Its trailing
    # scan can also see more: a decode that fails past the trailer hands back the
    # bytes before the failure on a source that can seek (decoded again), and a pipe
    # loses its failing call's output, so the reports may differ.
    expected = _outcome(NonSeekableBytesIO(data), fmt, piece, config)
    if expected[0] != "<open>" and expected[1] is None:
        assert _outcome(io.BytesIO(data), fmt, piece, config)[:2] == expected[:2]
    for size in pieces:
        got = _outcome(ShortReadNonSeekable(data, size), fmt, piece, config)  # type: ignore[arg-type]  # RawIOBase double
        assert same(got, expected), (
            f"source returning {size}-byte pieces: {got!r:.600} != {expected!r:.600}"
        )


def _params(*, tar: bool) -> list:
    params = []
    for key, (compress, fmt, joins, marks) in _CODECS.items():
        if tar:
            fmt = ArchiveFormat(ContainerFormat.TAR, fmt.stream)
        params.append(pytest.param(key, compress, fmt, joins, id=key, marks=marks))
    return params


@pytest.mark.parametrize("read_size", [None, 4096], ids=["read-all", "read-4096"])
@pytest.mark.parametrize(("key", "compress", "fmt", "joins"), _params(tar=False))
def test_a_compressed_file_reads_the_same_from_short_feeds(
    key: str,
    compress: Callable[[bytes], bytes],
    fmt: ArchiveFormat,
    joins: bool,
    read_size: int | None,
) -> None:
    compressed = compress(_PAYLOAD)
    second = compress(_PAYLOAD[:3000]) if joins else None
    for name, data in _cases(compressed, second).items():
        try:
            _assert_same_from_every_piece_size(data, fmt, read_size)
        except AssertionError as exc:
            raise AssertionError(f"{key} {name}: {exc}") from None


@pytest.mark.parametrize(("key", "compress", "fmt", "joins"), _params(tar=False))
def test_a_decoder_in_a_child_process_reads_the_same_from_short_feeds(
    key: str,
    compress: Callable[[bytes], bytes],
    fmt: ArchiveFormat,
    joins: bool,
) -> None:
    """Each feed is a message to the child; a short one is not the end there either.

    One-byte feeds would make a round trip per byte, so this reads 7-byte pieces.
    """
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    compressed = compress(_PAYLOAD)
    second = compress(_PAYLOAD[:3000]) if joins else None
    for name, data in _cases(compressed, second).items():
        try:
            _assert_same_from_every_piece_size(
                data, fmt, None, config=config, pieces=[7, 4096]
            )
        except AssertionError as exc:
            raise AssertionError(f"{key} {name}: {exc}") from None


def _stream_outcome(source: BinaryIO, fmt: ArchiveFormat) -> tuple[object, ...]:
    """``open_stream``'s bytes, or its error, and its trailing-data reports."""
    try:
        with open_stream(source, format=fmt.stream) as stream:
            try:
                result: tuple[object, ...] = (stream.read(),)
            except ArchiveyError as exc:
                result = (type(exc).__name__, str(exc))
            reports = tuple(
                d.message
                for d in stream.diagnostics.retained
                if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
            )
    except ArchiveyError as exc:
        return ("<open>", type(exc).__name__, str(exc))
    return (*result, reports)


@pytest.mark.parametrize(("key", "compress", "fmt", "joins"), _params(tar=False))
def test_open_stream_reads_the_same_from_short_feeds(
    key: str,
    compress: Callable[[bytes], bytes],
    fmt: ArchiveFormat,
    joins: bool,
) -> None:
    compressed = compress(_PAYLOAD)
    second = compress(_PAYLOAD[:3000]) if joins else None
    for name, data in _cases(compressed, second).items():
        expected = _stream_outcome(NonSeekableBytesIO(data), fmt)
        for size in _PIECES:
            got = _stream_outcome(ShortReadNonSeekable(data, size), fmt)  # type: ignore[arg-type]  # RawIOBase double
            assert got == expected, f"{key} {name}, {size}-byte pieces"


# Brotli finds its end only by failing the call that reads past it, which loses that
# call's output (``BrotliDecoder``). On a source that cannot seek there is no replay,
# so which output is lost, and which read of a TAR raises, depends on where a feed
# ends. Those cases have a test of their own below.
_BROTLI_AFTER_END = {"trailing-junk", "zeros-at-end", "zeros-then-junk"}


@pytest.mark.parametrize(("key", "compress", "fmt", "joins"), _params(tar=True))
def test_a_compressed_tar_reads_the_same_from_short_feeds(
    key: str,
    compress: Callable[[bytes], bytes],
    fmt: ArchiveFormat,
    joins: bool,
) -> None:
    compressed = compress(_tar(_PAYLOAD))
    second = compress(bytes(1024)) if joins else None
    for name, data in _cases(compressed, second).items():
        if key == "br" and name in _BROTLI_AFTER_END:
            continue
        same = _same_damage if name.startswith("flip@") else _same_outcome
        try:
            _assert_same_from_every_piece_size(data, fmt, 4096, same=same)
        except AssertionError as exc:
            raise AssertionError(f"tar.{key} {name}: {exc}") from None


@requires("brotli")
@pytest.mark.parametrize("after", [_JUNK, bytes(64), bytes(100) + _JUNK])
def test_a_brotli_tar_with_bytes_after_its_end_gives_right_bytes_or_brotli_error(
    after: bytes,
) -> None:
    """From full feeds too, the open, a member's read or the scan past the trailer
    can fail, wherever the call that meets the end falls. Every byte delivered is
    the TAR's, and the only error is brotli's."""
    data = _brotli(_tar(_PAYLOAD)) + after
    fmt = ArchiveFormat(ContainerFormat.TAR, ArchiveFormat.BROTLI.stream)
    # Seekable: the decoder replays the failed call and finds the end.
    whole = dict(_outcome(io.BytesIO(data), fmt, 4096)[0])  # type: ignore[arg-type]
    failed = ("CorruptionError", "Error reading brotli stream: brotli: decoder failed")
    sources = [NonSeekableBytesIO(data)] + [
        ShortReadNonSeekable(data, size) for size in _PIECES
    ]
    for source in sources:
        got = _outcome(source, fmt, 4096)  # type: ignore[arg-type]  # RawIOBase double
        if got[0] == "<open>":
            assert got[1] == failed[0]
            assert str(got[2]).startswith(failed[1])
            continue
        members, error, _reports = got
        for name, delivered in members:  # type: ignore[attr-defined]
            assert whole[name].startswith(delivered)
        if error is not None:
            assert error[0] == failed[0]
            assert error[1].startswith(failed[1])


@requires("brotli")
def test_the_brotli_probe_stream_is_complete_and_empty() -> None:
    """``BrotliDecoder._bytes_after_end`` gets the combined call's error by decoding
    ``_EMPTY_STREAM`` and one more byte. That is the error for the byte after the end
    only while ``_EMPTY_STREAM`` is itself a whole stream that decodes cleanly."""
    import brotli

    from archivey.internal.streams.codecs.brotli_decoder import _EMPTY_STREAM

    assert brotli.compress(b"") == _EMPTY_STREAM
    decoder = brotli.Decompressor()
    assert decoder.process(_EMPTY_STREAM) == b""
    assert decoder.is_finished()
    with pytest.raises(brotli.error):
        brotli.Decompressor().process(_EMPTY_STREAM + b"\x00")
