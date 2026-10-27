"""Shared helpers for the Phase-2 stream-layer tests."""

from __future__ import annotations

import functools
import io
import lzma
import random
import shutil
import struct
import subprocess
import sys
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

import pytest

from tests.conftest import CPYTHON


class NonSeekableBytesIO(io.RawIOBase):
    """A ``BytesIO`` that reports (and behaves as) non-seekable, for forward-only tests."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return self._inner.read(n)

    def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
        return self._inner.readinto(b)

    def seekable(self) -> bool:
        return False

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        raise io.UnsupportedOperation("seek")

    def tell(self, /) -> int:
        return self._inner.tell()


class SizedNonSeekable(NonSeekableBytesIO):
    """A non-seekable stream with an fsspec-style ``size`` attribute it sets itself.

    ``size`` is the caller's claim and need not match ``len(data)``: a test can
    inflate it to check that nothing trusts a claim it cannot verify.
    """

    def __init__(self, data: bytes, size: int) -> None:
        super().__init__(data)
        self.size = size


class ShortReadBytesIO(io.RawIOBase):
    """A ``BytesIO`` whose ``read``/``readinto`` never return more than ``max_chunk``.

    ``io.RawIOBase.read(n)`` is documented to return *up to* ``n`` bytes, and real sources
    do: sockets, FUSE mounts, and user-written wrappers hand back short chunks mid-stream
    with no EOF in sight. :class:`NonSeekableBytesIO` and :class:`CountingBytesIO` both
    delegate to ``BytesIO``, which always returns the full count, so neither exercises
    that — which is how short-returning sources stayed invisible until they were reported
    as corrupt archives (see ``test_short_read_sources.py``).

    Seekable by default. That still leaves one axis pair untested: a source that is
    short-returning *and* non-seekable. :class:`NonSeekableBytesIO` is always full-count,
    so it cannot stand in. :class:`ShortReadNonSeekable` is this class with
    ``seekable=False``. The cap lives here so the two cannot drift.

    ``max_chunk=1`` is the worst legal case, and the one that catches a parser reading a
    fixed-size header with a single ``read(n)`` and treating the short return as EOF.

    ``consumed`` counts bytes taken from the inner, so a test can see whether a wrapper
    over-read (a ``BufferedReader`` in front of this double takes
    ``io.DEFAULT_BUFFER_SIZE`` for a ``read(20)`` — 8 KiB through 3.13,
    128 KiB from 3.14).

    ``cap_drain`` also caps ``read(-1)``. That is deliberately illegal ``RawIOBase``
    behaviour — ``read(-1)`` dispatches to ``readall()``, which must drain — and exists
    only so a full-count wrapper's drain branch can be proved not to depend on the inner
    obeying that.
    """

    def __init__(
        self,
        data: bytes,
        max_chunk: int = 1,
        *,
        seekable: bool = True,
        cap_drain: bool = False,
    ) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)
        self._max_chunk = max_chunk
        self._seekable = seekable
        self._cap_drain = cap_drain
        self.consumed = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self._seekable

    def read(self, n: int = -1, /) -> bytes:
        # read(-1) means "everything up to EOF"; it has no legal short form, unless
        # cap_drain is set to violate that on purpose (see class docstring).
        if n is None or n < 0:
            data = (
                self._inner.read(self._max_chunk)
                if self._cap_drain
                else self._inner.read()
            )
        else:
            data = self._inner.read(min(n, self._max_chunk))
        self.consumed += len(data)
        return data

    def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
        with memoryview(b) as outer, outer.cast("B") as mv:
            data = self.read(len(mv))
            mv[: len(data)] = data
            return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if not self._seekable:
            raise io.UnsupportedOperation("seek")
        return self._inner.seek(offset, whence)

    def tell(self, /) -> int:
        return self._inner.tell()


class ShortReadNonSeekable(ShortReadBytesIO):
    """Short-returning *and* non-seekable.

    :class:`ShortReadBytesIO` is seekable; :class:`NonSeekableBytesIO` delegates to
    ``BytesIO`` and is therefore always full-count. Neither covers this axis pair,
    which is why the non-seekable half of the source-boundary contract went untested.

    ``tell()`` still answers, matching :class:`NonSeekableBytesIO`:
    ``ConcatenatedFile`` probes ``tell()`` then ``seek()`` on ``BinaryIO``
    volumes, so a double that raised on both would test a different refusal
    path. Path volumes are sized with ``stat`` and are not probed.
    """

    def __init__(
        self, data: bytes, max_chunk: int = 1, *, cap_drain: bool = False
    ) -> None:
        super().__init__(data, max_chunk, seekable=False, cap_drain=cap_drain)


class CountingBytesIO(io.RawIOBase):
    """A seekable ``BytesIO`` that counts ``read`` calls and bytes read.

    Used to assert that seeking decompresses only the needed block(s) rather than the
    whole stream from the start.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)
        self.read_calls = 0
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        data = self._inner.read(n)
        if data:
            self.read_calls += 1
            self.bytes_read += len(data)
        return data

    def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
        n = self._inner.readinto(b)
        if n:
            self.read_calls += 1
            self.bytes_read += n
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._inner.seek(offset, whence)

    def tell(self, /) -> int:
        return self._inner.tell()


class FactSizedReadRecorder(io.BytesIO):
    """A ``BytesIO`` that records the size asked of every ``read`` / ``readinto``.

    Its length is a fact to the source boundary — ``BytesIO``'s own buffer says how
    big it is — so a read against it is clamped to what is left, where the same bytes
    behind :class:`ReadSizeRecorder`'s ``size`` attribute, a caller's unverified claim,
    are only stepped.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.requested: list[int] = []

    def read(self, n: int | None = -1, /) -> bytes:
        self.requested.append(-1 if n is None else n)
        return super().read(n)

    def readinto(self, b, /) -> int:  # type: ignore[override]  # test double
        self.requested.append(len(b))
        return super().readinto(b)


class ReadSizeRecorder(io.RawIOBase):
    """A seekable in-memory stream that records the size asked of every ``read``.

    With ``advertise_size`` (the default), ``size`` is the fsspec convention
    :func:`source_byte_size` honours, so the reader gets the stream's length the same
    cheap way it gets a file's. Without it the attribute is absent, which is what an
    ordinary caller-supplied seekable file-like looks like: seekable, but not a path,
    not one of the types ``source_byte_size`` will end-seek, and so unmeasurable
    cheaply. The two send a backend down different branches of its bound, and a guard
    tested only on the advertised one is untested on the branch every compressed
    source takes.
    """

    def __init__(self, data: bytes, *, advertise_size: bool = True) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)
        if advertise_size:
            self.size = len(data)
        self.requested: list[int] = []

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        self.requested.append(n)
        return self._inner.read(n)

    def readinto(self, b, /) -> int:  # type: ignore[override]  # test double
        self.requested.append(len(b))
        return self._inner.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._inner.seek(offset, whence)

    def tell(self, /) -> int:
        return self._inner.tell()


class QueuedChunks(io.RawIOBase):
    """A forward-only raw that hands over at most one queued chunk per read, then EOF.

    A sized read takes up to ``n`` bytes of the front chunk and leaves the rest
    queued. A chunk of ``None`` is a stall that lasts, as on a non-blocking pipe
    whose writer sends nothing more: every read from there on returns ``None``.
    ``calls`` counts reads. The detection workspace and ``ArchiveSource`` tests share
    this one copy so both mean the same thing by "one read" and "a stall".
    """

    def __init__(self, *chunks: bytes | None) -> None:
        super().__init__()
        self._chunks = list(chunks)
        self.calls = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes | None:
        self.calls += 1
        if not self._chunks:
            return b""
        chunk = self._chunks[0]
        if chunk is None:
            return None
        take = len(chunk) if n < 0 else min(n, len(chunk))
        if take == len(chunk):
            self._chunks.pop(0)
        else:
            self._chunks[0] = chunk[take:]
        return chunk[:take]


def lzma_alone_with_filter(data: bytes, lzma1: dict) -> bytes:
    """``lzma.compress(data, format=FORMAT_ALONE, filters=[lzma1])``, also on PyPy.

    PyPy's ``lzma`` refuses FORMAT_ALONE with a filter chain (NotImplementedError).
    The Alone format is a 13-byte header (properties byte, dictionary size, unknown
    size) before the raw LZMA1 stream, so this writes the header and compresses with
    FORMAT_RAW. ``lzma1`` must give ``dict_size``. The bytes match what CPython writes
    (``test_lzma_alone_with_filter_matches_cpython``): like liblzma's Alone encoder,
    the header declares ``dict_size`` rounded up to 2^n or 2^n + 2^(n-1).
    """
    lzma1 = {"lc": 3, "lp": 0, "pb": 2, **lzma1}
    props = (lzma1["pb"] * 5 + lzma1["lp"]) * 9 + lzma1["lc"]
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[lzma1])
    declared = lzma1["dict_size"] - 1
    for shift in (2, 3, 4, 8, 16):
        declared |= declared >> shift
    declared = min(declared + 1, 2**32 - 1)
    return bytes([props]) + struct.pack("<LQ", declared, 2**64 - 1) + raw


def make_lzip_member(data: bytes, dict_size_bits: int = 20) -> bytes:
    """Build one lzip member from ``data`` using stdlib ``lzma``.

    lzip's stream is the raw LZMA1 stream an Alone file carries after its 13-byte
    header; compress with FORMAT_RAW, then wrap in the lzip header/trailer. Not
    FORMAT_ALONE with the header stripped: PyPy's ``lzma`` refuses FORMAT_ALONE with
    a filter chain (NotImplementedError), and the raw bytes are the same.
    """
    filters: list[dict] = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": 1 << dict_size_bits,
            "lc": 3,
            "lp": 0,
            "pb": 2,
        }
    ]
    lzma_raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    header = b"LZIP" + bytes([1, dict_size_bits])
    member_total = len(header) + len(lzma_raw) + 20
    trailer = struct.pack(
        "<IQQ", zlib.crc32(data) & 0xFFFFFFFF, len(data), member_total
    )
    return header + lzma_raw + trailer


def make_multi_member_lzip(parts: list[bytes], dict_size_bits: int = 20) -> bytes:
    return b"".join(make_lzip_member(p, dict_size_bits) for p in parts)


def make_multi_stream_xz(parts: list[bytes]) -> bytes:
    return b"".join(lzma.compress(p, format=lzma.FORMAT_XZ) for p in parts)


def encode_xz_mbi(value: int) -> bytes:
    """Encode ``value`` as an XZ multibyte integer (the format of the index fields)."""
    if value == 0:
        return b"\x00"
    result = bytearray()
    while value > 0:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


def xz_cli_available() -> bool:
    """Whether the ``xz`` CLI is on PATH (needed to build a multi-block XZ stream)."""
    return shutil.which("xz") is not None


def make_multiblock_xz(data: bytes, block_size: int) -> bytes:
    """Compress ``data`` into a *single* XZ stream split into multiple blocks.

    stdlib ``lzma`` always emits one block per stream, so the multi-block layout (which
    drives ``XzDecompressorStream``'s block-resume random-access path) is produced via the
    ``xz`` CLI's ``--block-size``. Guard callers with :func:`xz_cli_available`.
    """
    result = subprocess.run(
        ["xz", "-z", "-c", f"--block-size={block_size}"],
        input=data,
        capture_output=True,
        check=True,
    )
    return result.stdout


def seekable_zstd_table(
    frames: list[tuple[int, int]], *, checksums: bool = False, descriptor: int = 0
) -> bytes:
    """The skippable frame that ends a Seekable Zstandard file, for ``frames``.

    ``frames`` holds ``(compressed_size, decompressed_size)`` per frame. ``checksums``
    writes 12-byte entries (with a zero checksum) and sets the descriptor's flag;
    ``descriptor`` adds bits to it.
    """
    entry = struct.Struct("<III" if checksums else "<II")
    body = b"".join(entry.pack(c, d, *([0] if checksums else [])) for c, d in frames)
    flags = descriptor | (0x80 if checksums else 0)
    body += struct.pack("<IBI", len(frames), flags, 0x8F92EAB1)
    return struct.pack("<II", 0x184D2A5E, len(body)) + body


def make_seekable_zstd(parts: list[bytes], *, checksums: bool = False) -> bytes:
    """A Seekable Zstandard file: one frame per part, then the seek table."""
    from tests.conftest import zstd_backend

    zstd = zstd_backend()
    frames = [zstd.compress(part) for part in parts]
    table = seekable_zstd_table(
        [(len(f), len(p)) for f, p in zip(frames, parts, strict=True)],
        checksums=checksums,
    )
    return b"".join(frames) + table


def make_bgzf_block(data: bytes, *, extra_before: bytes = b"") -> bytes:
    """One BGZF member holding ``data`` (SAM spec §4.1), as ``bgzip`` writes it.

    ``extra_before`` is raw extra-field subfields put before the ``BC`` one.
    """
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = compressor.compress(data) + compressor.flush()
    xlen = len(extra_before) + 6
    size = 12 + xlen + len(body) + 8
    header = b"\x1f\x8b\x08\x04" + b"\x00" * 4 + b"\x00\xff" + struct.pack("<H", xlen)
    extra = extra_before + b"BC" + struct.pack("<HH", 2, size - 1)
    return header + extra + body + struct.pack("<II", zlib.crc32(data), len(data))


# The empty member that ends every BGZF file, byte for byte as the spec gives it.
BGZF_EOF = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")


def make_bgzf(parts: list[bytes], *, eof: bool = True) -> bytes:
    """A BGZF file: one member per part, then the end-of-file marker."""
    return b"".join(make_bgzf_block(p) for p in parts) + (BGZF_EOF if eof else b"")


def make_unix_compress(data: bytes) -> bytes:
    """LZW-compress ``data`` into a standard unix-compress (`.Z`) stream.

    Fixtures are produced with ``ncompress`` (an LZW *compressor*); Archivey decodes
    natively. Imported lazily so this module still imports in the core-only test leg,
    where ncompress is absent (callers guard with ``requires``).
    """
    import ncompress

    out = io.BytesIO()
    ncompress.compress(io.BytesIO(data), out)
    return out.getvalue()


def lzma2_raw_filters() -> list[dict]:
    """A FORMAT_RAW LZMA2 filter spec, as a 7z folder coder would supply."""
    return [{"id": lzma.FILTER_LZMA2, "preset": 6}]


def compress_lzma2_raw(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=lzma2_raw_filters())


@functools.cache
def _hex_text_brotli() -> bytes:
    import brotli

    return brotli.compress(random.Random(0).randbytes(200_000).hex().encode())


def truncated_brotli(size: int) -> bytes:
    """A real compressed-first Brotli stream (about 200 KB) cut to ``size`` bytes.

    Compressed once per process: the compression takes about a quarter of a second.
    """
    compressed = _hex_text_brotli()
    assert len(compressed) > size
    return compressed[:size]


def brotli_compressed_metablock_header(*, first: bool = False) -> bytes:
    """Synthesize a 24-byte meta-block header that classifies as ``COMPRESSED``.

    Used by framing / completeness / SFX tests that need a chain walk to stop at a
    successor link without depending on a real Brotli encoder for that header alone.
    """
    from archivey.internal.streams.codecs.brotli_framing import (
        BrotliBlock,
        parse_metablock,
    )

    for seed in range(4096):
        hdr = bytes([(seed + j * 13) % 256 for j in range(24)])
        if parse_metablock(hdr, first=first).outcome is BrotliBlock.COMPRESSED:
            return hdr
    raise RuntimeError("no compressed meta-block header pattern found")


def _pack_bits(fields: list[tuple[int, int]]) -> bytes:
    """Pack ``(value, width)`` fields LSB-first, as Brotli does, zero-padded to a byte."""
    acc = pos = 0
    for value, width in fields:
        acc |= value << pos
        pos += width
    return acc.to_bytes((pos + 7) // 8, "little")


def brotli_declared_metablock_header(
    length: int, *, metadata: bool = False, first: bool = False
) -> bytes:
    """A non-last uncompressed (or metadata) meta-block header declaring ``length`` bytes.

    ``first`` prepends a one-bit WBITS field (window 16). The header ends byte-aligned,
    so the declared bytes follow it directly (RFC 7932 §9.2).
    """
    fields: list[tuple[int, int]] = [(0, 1)] if first else []
    fields.append((0, 1))  # ISLAST
    if metadata:
        nbytes = (max(length - 1, 1).bit_length() + 7) // 8 if length else 0
        fields += [(3, 2), (0, 1), (nbytes, 2)]  # MNIBBLES = 0, reserved, MSKIPBYTES
        if nbytes:
            fields.append((length - 1, nbytes * 8))
    else:
        nibbles = max(4, ((length - 1).bit_length() + 3) // 4)
        fields += [(nibbles - 4, 2), (length - 1, nibbles * 4), (1, 1)]
    return _pack_bits(fields)


def brotli_link_cap_residual() -> bytes:
    """Random data that every Brotli probe check accepts and a decoder rejects.

    Nine uncompressed meta-blocks of 8 KiB each: the chain walk gives up at its link
    cap (``CHAIN_MAX_LINKS``) and cannot disprove, the source is over the 64 KiB
    completion window, and nothing past the walk is decoded. A garbage compressed
    header follows, so a read copies about 72 KiB and then fails. The first block is
    uncompressed, so detection reports ``BROTLI`` / ``GUESS``.
    """
    from archivey.internal.streams.codecs.brotli_framing import CHAIN_MAX_LINKS

    rng = random.Random(7)
    parts = [
        brotli_declared_metablock_header(8192, first=(i == 0)) + rng.randbytes(8192)
        for i in range(CHAIN_MAX_LINKS + 1)
    ]
    return b"".join(parts) + brotli_compressed_metablock_header() + b"Z" * 32


def assert_seek_underflow_matches_bytesio(stream: BinaryIO) -> None:
    """A relative seek before the start clamps to 0; a negative SEEK_SET is ValueError.

    That is what ``io.BytesIO`` does. A compressed member used to raise
    ``ValueError("Invalid offset")`` on the relative case, which a backend translator
    (ZIP) then reported as ``CorruptionError`` on an undamaged archive.
    """
    content = stream.read()
    # A seek inside the member: a seek past the end is not what this test is about.
    start = min(5, len(content))
    assert stream.seek(start) == start
    assert stream.seek(-100, io.SEEK_CUR) == 0
    assert stream.read() == content
    assert stream.seek(-(len(content) + 100), io.SEEK_END) == 0
    assert stream.tell() == 0
    assert stream.read() == content
    with pytest.raises(ValueError) as excinfo:
        stream.seek(-1)
    # The caller's own error, not a translated archive error.
    assert type(excinfo.value) is ValueError
    assert_unknown_whence_is_value_error(stream)
    # The refused seeks did not move the stream.
    assert stream.tell() == len(content)


# Non-integer seek arguments, each refused by ``io.BytesIO`` with a TypeError.
NON_INTEGER_SEEKS: tuple[tuple[object, ...], ...] = (
    (1.5,),
    (None,),
    ("1",),
    (0, 1.5),
    (0, None),
)


def assert_non_integer_seek_is_type_error(stream: BinaryIO, content: bytes) -> None:
    """A float, ``None`` or str offset or whence raises ``TypeError`` as ``io.BytesIO``
    does, with its message, and leaves the stream where it was and correct.

    Passed inward, ``seek(1.5)`` made a codec stream consume a chunk before failing (a
    later ``seek(0)`` read wrong bytes), backends report damage that was not there, and
    the stored paths kept a float position (cross-format K1).
    """

    # Untyped handles: the arguments are wrong on purpose.
    seek: Callable[..., int] = stream.seek
    reference_seek: Callable[..., int] = io.BytesIO(content).seek

    def refuse(at: int) -> None:
        for args in NON_INTEGER_SEEKS:
            with pytest.raises(TypeError) as expected:
                reference_seek(*args)
            with pytest.raises(TypeError) as excinfo:
                seek(*args)
            assert type(excinfo.value) is TypeError, args
            # The message is CPython's: PyPy's io.BytesIO words it differently.
            if CPYTHON:
                assert str(excinfo.value) == str(expected.value), args
            position = stream.tell()
            assert type(position) is int and position == at, args

    # First on a fresh stream, then after a partial read.
    refuse(0)
    head = min(3, len(content))
    assert stream.read(head) == content[:head]
    refuse(head)
    assert stream.read() == content[head:]
    assert stream.seek(0) == 0
    assert stream.read() == content
    # A bool is an int to io.BytesIO too.
    if content:
        assert stream.seek(True) == 1
        assert stream.read() == content[1:]


# Non-integer read sizes, each refused by ``io.BytesIO`` with a TypeError. ``None``
# is not here: it means read to EOF.
NON_INTEGER_READS: tuple[object, ...] = (1.5, 2.0, "3", b"3")


def assert_non_integer_read_is_type_error(stream: BinaryIO, content: bytes) -> None:
    """A float or str ``read`` size raises ``TypeError`` as ``io.BytesIO`` does, with
    its message, and leaves the stream where it was and correct.

    The read after the refusal is the half that matters. Passed inward, ``read(1.5)``
    failed inside zlib after the compressed chunk had left the source, so an undamaged
    gzip or deflate member then raised ``TruncatedError`` on every read, even after
    ``seek(0)``; a stored member raised a ``TypeError`` and survived.
    """

    # Untyped handles: the arguments are wrong on purpose.
    read: Callable[..., bytes] = stream.read
    reference_read: Callable[..., bytes] = io.BytesIO(content).read

    def refuse(at: int) -> None:
        for size in NON_INTEGER_READS:
            with pytest.raises(TypeError) as expected:
                reference_read(size)
            with pytest.raises(TypeError) as excinfo:
                read(size)
            assert type(excinfo.value) is TypeError, size
            if CPYTHON:  # PyPy words it differently
                assert str(excinfo.value) == str(expected.value), size
            assert stream.tell() == at, size

    # First on a fresh stream, then after a partial read.
    refuse(0)
    head = min(3, len(content))
    assert stream.read(head) == content[:head]
    refuse(head)
    assert stream.read() == content[head:]
    assert stream.seek(0) == 0
    assert stream.read() == content
    # A bool is an int to io.BytesIO too, and None reads to EOF.
    assert stream.seek(0) == 0
    assert read(True) == content[:1]
    assert read(None) == content[1:]


# Integer read sizes outside ``Py_ssize_t``, each refused by ``io.BytesIO`` with an
# OverflowError before anything is read.
OVERSIZED_READS: tuple[int, ...] = (sys.maxsize + 1, 2**70, -sys.maxsize - 2, -(2**70))


def assert_oversized_read_is_overflow_error(stream: BinaryIO, content: bytes) -> None:
    """An integer ``read`` size too wide for ``Py_ssize_t`` raises ``OverflowError`` as
    ``io.BytesIO`` does, with its message, and leaves the stream where it was and correct.

    The read after the refusal is the half that matters. Passed inward, ``read(2**70)``
    failed inside the gzip, bzip2 or xz decoder after the compressed chunk had left the
    source, so the undamaged member then raised ``TruncatedError`` or
    ``CorruptionError`` on every read, even after ``seek(0)``.
    """

    reference_read = io.BytesIO(content).read

    def refuse(at: int) -> None:
        for size in OVERSIZED_READS:
            with pytest.raises(OverflowError) as expected:
                reference_read(size)
            with pytest.raises(OverflowError) as excinfo:
                stream.read(size)
            assert type(excinfo.value) is OverflowError, size
            if CPYTHON:  # PyPy words it differently
                assert str(excinfo.value) == str(expected.value), size
            assert stream.tell() == at, size

    # First on a fresh stream, then after a partial read.
    refuse(0)
    head = min(3, len(content))
    assert stream.read(head) == content[:head]
    refuse(head)
    assert stream.read() == content[head:]
    assert stream.seek(0) == 0
    assert stream.read() == content


def assert_unknown_whence_is_value_error(stream: BinaryIO) -> None:
    """An unknown ``whence`` is the caller's ``ValueError`` on every format.

    Without the check in ``ArchiveStream.seek`` the ZIP translator reports it as
    ``CorruptionError`` on an undamaged archive.
    """
    with pytest.raises(ValueError) as excinfo:
        stream.seek(0, 7)
    assert type(excinfo.value) is ValueError
    # The message the shared rule in ``check_seek_args`` gives, so the public layer
    # and the backends behind it cannot drift apart.
    assert str(excinfo.value) == "Invalid whence: 7"


# ---------------------------------------------------------------------------
# Seeks on a member stream: the tail rule shared by detection and the readers
# ---------------------------------------------------------------------------

# A seek that lands in a member stream's last this-many bytes is a trailer read. The
# number is the UDIF trailer window detection reads; it serves as "the tail" for the
# single-file reader's index and trailer probes too.
MEMBER_TAIL_BYTES = 512


@dataclass(frozen=True)
class MemberSeek:
    """One ``ArchiveStream.seek``: which stream, and its position before and after."""

    stream: int  # ``id`` of the ``ArchiveStream`` that was seeked
    before: int
    after: int


def spy_member_seeks(patch: pytest.MonkeyPatch) -> list[MemberSeek]:
    """Record every ``ArchiveStream.seek`` as (stream, position before, position after).

    Positions, not arguments: a ``SEEK_END``, a ``SEEK_SET`` and a relative
    ``SEEK_CUR`` that reach the same place record the same thing, so no ``whence`` can
    slip past :func:`assert_no_member_tail_seek`.
    """
    from archivey.internal.streams.archive_stream import ArchiveStream

    seeks: list[MemberSeek] = []
    real_seek = ArchiveStream.seek

    def spy(self: ArchiveStream, offset: int, whence: int = io.SEEK_SET, /) -> int:
        before = self.tell()
        pos = real_seek(self, offset, whence)
        seeks.append(MemberSeek(id(self), before, pos))
        return pos

    patch.setattr(ArchiveStream, "seek", spy)
    return seeks


def assert_no_member_tail_seek(seeks: list[MemberSeek], sizes: dict[int, int]) -> None:
    """No seek moves forward into a member stream's last ``MEMBER_TAIL_BYTES``.

    A member stream's seek may re-decode: reaching its tail decodes the whole member
    on the way. ``sizes`` maps each member's ``id`` to its length. A no-op seek that a
    read makes at its own position is free and is not counted. Detection
    (``tests/test_detection_workspace.py``) and the single-file reader's open
    (``tests/test_single_file.py``) both hold a member stream to this rule.
    """
    forward = [s for s in seeks if s.after > s.before]
    assert all(s.after < sizes[s.stream] - MEMBER_TAIL_BYTES for s in forward), seeks


# Reads a gzip file with raw rapidgzip and prints how many bytes it delivered and how many
# bits of the file it decoded (``tell_compressed``), or RAISED. It runs in a child
# interpreter because rapidgzip 0.16 aborts the process on some cuts (see
# test_accelerator_truncation_abort.py), and opens the file as archivey's worker does.
_RAPIDGZIP_SOFT_END_PROBE = """
import sys, rapidgzip
with rapidgzip.open(sys.argv[1], parallelization=0) as f:
    try:
        print(len(f.read()), f.tell_compressed())
    except ValueError:
        print("RAISED")
"""


def rapidgzip_soft_end(path: str) -> tuple[int, int] | None:
    """How many bytes raw rapidgzip delivers from the cut gzip at ``path`` before it ends
    with no error, and how many bytes of the file it decoded to get there (rounded up);
    ``None`` where this build raises or aborts on the cut instead.

    Builds differ: the macOS wheels raise on cuts that the Linux wheels end softly, and
    the Linux wheels abort on others. A test of what archivey does after a soft end
    skips where there is none."""
    proc = subprocess.run(
        [sys.executable, "-c", _RAPIDGZIP_SOFT_END_PROBE, path],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0 or proc.stdout.strip() == "RAISED":
        return None
    delivered, bits = proc.stdout.split()
    return int(delivered), -(-int(bits) // 8)


def rapidgzip_soft_end_length(path: str) -> int | None:
    """How many bytes raw rapidgzip delivers from the cut gzip at ``path`` before it ends
    with no error; ``None`` where it raises or aborts instead (:func:`rapidgzip_soft_end`)."""
    end = rapidgzip_soft_end(path)
    return None if end is None else end[0]
