"""Snappy's framing format (``.sz``), parsed here, with the raw blocks decoded by a
pluggable native backend. Experimental: nothing registers it unless a caller does.

The framing format (``framing_format.txt`` in google/snappy) is a stream identifier
chunk followed by chunks, each a 1-byte type and a 3-byte little-endian length::

    ff 06 00 00 "sNaPpY"                       stream identifier, may repeat
    00 len(3)  masked-crc32c(4)  raw block      compressed data
    01 len(3)  masked-crc32c(4)  data           uncompressed data
    02-7f                                      reserved, unskippable: refused
    80-fd, fe                                  reserved skippable / padding: skipped

The CRC-32C covers the **decoded** data of a chunk, masked as the format describes.
There is no end mark: the stream ends where the input does, which must be between
chunks. A repeated identifier is how concatenated streams look, so the whole input is
one stream here and nothing follows it.

**What the input can make this allocate.** A data chunk decodes to at most 64 KiB
(the format's limit). The raw block's own length varint is read here and checked
against that limit before a backend sees the block, and a compressed chunk longer than
Snappy's worst case for 64 KiB is refused before it is buffered. Skippable chunks
(up to 16 MiB each) are consumed as they arrive and never held. So this holds at most
one chunk of input and one decoded chunk, whatever the input declares; nothing is left
for ``DecoderLimits.max_decoder_memory`` to cap.

**Backends.** The raw Snappy decode is the only native step: :data:`BACKENDS` maps a
name to a small adapter for ``cramjam`` (Rust ``snap``) or ``compress-utils`` (its own C
decoder); ``"auto"`` picks the first installed one in :data:`AUTO_ORDER`. Every check of
the framing, the sizes and the CRC is done here, the same for both, so a backend can
differ only in which raw blocks it accepts and what bytes it returns. The decoded length
must equal the length the block declares.

**CRC-32C.** The standard library has no CRC-32C (``zlib.crc32`` is a different
polynomial). ``google-crc32c`` is used when installed; otherwise a table-driven Python
CRC runs at about 17 MB/s, which then bounds the whole decode.
"""

from __future__ import annotations

import importlib
import importlib.util
import struct
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType

STREAM_IDENTIFIER = b"\xff\x06\x00\x00sNaPpY"

_IDENTIFIER_TYPE = 0xFF
_COMPRESSED = 0x00
_UNCOMPRESSED = 0x01
_FIRST_SKIPPABLE = 0x80
_HEADER = 4
_CRC = 4
# The most data one chunk decodes to (framing_format.txt §4.2, §4.3).
MAX_CHUNK_DATA = 65536
# snappy::MaxCompressedLength(65536): 32 + n + n / 6, the longest raw block a writer
# can emit for a full chunk. A compressed chunk is the CRC plus at most this.
_MAX_RAW_BLOCK = 32 + MAX_CHUNK_DATA + MAX_CHUNK_DATA // 6
_MAX_VARINT = 5


class SnappyFormatError(Exception):
    """The input is not a valid Snappy framed stream. The codec handler maps it to
    ``CorruptionError``."""


# --- CRC-32C ----------------------------------------------------------------------------

_POLY = 0x82F63B78


def _tables() -> list[list[int]]:
    first = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY if c & 1 else c >> 1
        first.append(c)
    tables = [first]
    for _ in range(7):
        prev = tables[-1]
        tables.append([(prev[i] >> 8) ^ first[prev[i] & 0xFF] for i in range(256)])
    return tables


_T = _tables()
_EIGHT = struct.Struct("<II")


def crc32c_python(data: bytes | memoryview) -> int:
    """CRC-32C (Castagnoli) of ``data``, slicing by 8 in Python."""
    t0, t1, t2, t3, t4, t5, t6, t7 = _T
    crc = 0xFFFFFFFF
    view = memoryview(data)
    whole = len(view) // 8 * 8
    for a, b in _EIGHT.iter_unpack(view[:whole]):
        a ^= crc
        crc = (
            t7[a & 0xFF]
            ^ t6[(a >> 8) & 0xFF]
            ^ t5[(a >> 16) & 0xFF]
            ^ t4[a >> 24]
            ^ t3[b & 0xFF]
            ^ t2[(b >> 8) & 0xFF]
            ^ t1[(b >> 16) & 0xFF]
            ^ t0[b >> 24]
        )
    for byte in view[whole:]:
        crc = t0[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def crc32c_function(name: str = "auto") -> Callable[[bytes], int]:
    """The CRC-32C implementation called ``name``: ``"python"``, ``"google-crc32c"``,
    or ``"auto"`` for google-crc32c when it imports and Python otherwise."""
    if name == "python":
        return crc32c_python
    try:
        module = importlib.import_module("google_crc32c")
    except ImportError:
        if name == "auto":
            return crc32c_python
        raise
    return module.value


def masked_crc(crc: int) -> int:
    """The masked CRC that a chunk stores (framing_format.txt §3)."""
    return ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + 0xA282EAD8) & 0xFFFFFFFF


# --- raw block backends -----------------------------------------------------------------


def raw_length(block: bytes) -> int:
    """The decoded length a raw Snappy block declares in its leading varint.

    Refuses a varint that is cut, longer than 32 bits allow, or over a chunk's 64 KiB,
    before any backend allocates for it.
    """
    value = 0
    for i, byte in enumerate(block[:_MAX_VARINT]):
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            if value > MAX_CHUNK_DATA:
                raise SnappyFormatError(
                    f"compressed chunk declares {value} decoded bytes, more than the "
                    f"{MAX_CHUNK_DATA} a chunk holds"
                )
            return value
    raise SnappyFormatError("compressed chunk has no valid decoded-length varint")


@dataclass(frozen=True)
class Backend:
    """One native raw Snappy decoder."""

    name: str
    module: str
    """The module it imports."""
    package: str
    """What to ``pip install`` for it."""
    load: Callable[[], Callable[[bytes, int], bytes]]
    """Import the module and return ``decode(block, size)``: the block's bytes,
    exactly ``size`` of them, or :class:`SnappyFormatError`."""


def _cramjam() -> Callable[[bytes, int], bytes]:
    cramjam = importlib.import_module("cramjam")
    decompress_raw = cramjam.snappy.decompress_raw
    error = cramjam.DecompressionError

    def decode(block: bytes, size: int) -> bytes:
        try:
            out = decompress_raw(block)
        except error as exc:
            raise SnappyFormatError(f"cramjam refused the raw block: {exc}") from exc
        return bytes(out)

    return decode


def _compress_utils() -> Callable[[bytes, int], bytes]:
    cu: ModuleType = importlib.import_module("compress_utils")
    decompress = cu.decompress
    algorithm = cu.Algorithm.snappy
    error = cu.CompressError

    def decode(block: bytes, size: int) -> bytes:
        try:
            # expected_size is an upper bound on the output, so this cannot allocate
            # more than the varint this module already checked.
            return decompress(block, algorithm, expected_size=size)
        except error as exc:
            raise SnappyFormatError(
                f"compress-utils refused the raw block: {exc}"
            ) from exc

    return decode


BACKENDS: dict[str, Backend] = {
    "cramjam": Backend("cramjam", "cramjam", "cramjam", _cramjam),
    "compress-utils": Backend(
        "compress-utils", "compress_utils", "compress-utils", _compress_utils
    ),
}


# The order ``"auto"`` tries the backends in. compress-utils first: it matched Google
# Snappy on every input measured, while cramjam refuses three valid but unusual raw
# encodings (dev-docs/investigations/snappy-framing-backends.md). cramjam second: it has
# wheels for more interpreters, PyPy included.
AUTO_ORDER = ("compress-utils", "cramjam")


def installed_backends() -> list[str]:
    """The backends whose module is installed, in ``AUTO_ORDER``. Does not import."""
    return [
        name
        for name in AUTO_ORDER
        if importlib.util.find_spec(BACKENDS[name].module) is not None
    ]


def resolve_backend(name: str) -> Backend:
    """The backend ``name`` names; ``"auto"`` is the first installed one in
    ``AUTO_ORDER``, or the last of them when none is installed (so the missing-package
    report names it)."""
    if name != "auto":
        return BACKENDS[name]
    found = installed_backends()
    return BACKENDS[found[0] if found else AUTO_ORDER[-1]]


def decode_raw_chunk(decode: Callable[[bytes, int], bytes], block: bytes) -> bytes:
    """Decode one chunk's raw block with ``decode``, checking its declared length
    before the call and the length it decoded to after it."""
    size = raw_length(block)
    out = decode(block, size)
    if len(out) != size:
        raise SnappyFormatError(
            f"compressed chunk decodes to {len(out)} bytes, not the {size} it declares"
        )
    return out


# --- the framing ------------------------------------------------------------------------


class SnappyFramedDecompressor:
    """One Snappy framed stream, behind the one-stream decompressor interface
    (``decompress(data, max_length)``, ``eof``, ``needs_input``, ``unused_data``,
    ``end_input``).

    A chunk is decoded when all of it has arrived and the caller wants output; its
    data is then returned in ``max_length`` pieces. The stream is complete only when
    :meth:`end_input` finds the input ended between chunks, after an identifier.
    """

    def __init__(
        self, decode: Callable[[bytes, int], bytes], crc32c: Callable[[bytes], int]
    ) -> None:
        self._decode = decode
        self._crc32c = crc32c
        self._input = bytearray()
        # Bytes of a skippable chunk still to drop as they arrive.
        self._skip = 0
        self._identified = False
        self._ended = False
        self._output = memoryview(b"")
        # Offset in the stream of the start of ``_input``, for error messages.
        self._offset = 0
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._ended and data:
            raise SnappyFormatError("data after the end of the Snappy stream")
        self._input += data
        out = bytearray()
        while True:
            if self._output:
                room = len(self._output) if max_length < 0 else max_length - len(out)
                out += self._output[:room]
                self._output = self._output[room:]
                if not self._output:
                    self._output = memoryview(b"")
            if max_length >= 0 and len(out) >= max_length:
                break
            if not self._next_chunk():
                break
        return bytes(out)

    def _consume(self, n: int) -> None:
        del self._input[:n]
        self._offset += n

    def _next_chunk(self) -> bool:
        """Decode the next buffered data chunk into ``_output``, dropping identifiers
        and skippable chunks on the way. False when no data chunk is complete yet."""
        while True:
            if self._skip:
                n = min(self._skip, len(self._input))
                self._consume(n)
                self._skip -= n
                if self._skip:
                    return False
            if len(self._input) < _HEADER:
                return False
            kind = self._input[0]
            length = int.from_bytes(self._input[1:_HEADER], "little")
            at = self._offset
            if not self._identified and kind != _IDENTIFIER_TYPE:
                raise SnappyFormatError(
                    f"Snappy stream does not start with a stream identifier (chunk "
                    f"type 0x{kind:02x} at offset {at})"
                )
            if kind == _IDENTIFIER_TYPE:
                if length != len(STREAM_IDENTIFIER) - _HEADER:
                    raise SnappyFormatError(
                        f"stream identifier at offset {at} has length {length}, not 6"
                    )
                if len(self._input) < len(STREAM_IDENTIFIER):
                    return False
                if self._input[: len(STREAM_IDENTIFIER)] != STREAM_IDENTIFIER:
                    raise SnappyFormatError(f"bad stream identifier at offset {at}")
                self._consume(len(STREAM_IDENTIFIER))
                self._identified = True
                continue
            if kind in (_COMPRESSED, _UNCOMPRESSED):
                most = _CRC + (
                    _MAX_RAW_BLOCK if kind == _COMPRESSED else MAX_CHUNK_DATA
                )
                if length < _CRC or length > most:
                    raise SnappyFormatError(
                        f"data chunk at offset {at} has length {length}, outside "
                        f"{_CRC}..{most}"
                    )
                if len(self._input) < _HEADER + length:
                    return False
                stored = int.from_bytes(self._input[_HEADER : _HEADER + _CRC], "little")
                body = bytes(self._input[_HEADER + _CRC : _HEADER + length])
                self._consume(_HEADER + length)
                try:
                    data = (
                        decode_raw_chunk(self._decode, body)
                        if kind == _COMPRESSED
                        else body
                    )
                except SnappyFormatError as exc:
                    raise SnappyFormatError(f"chunk at offset {at}: {exc}") from exc
                if masked_crc(self._crc32c(data)) != stored:
                    raise SnappyFormatError(f"CRC-32C mismatch in chunk at offset {at}")
                self._output = memoryview(data)
                return True
            if kind < _FIRST_SKIPPABLE:
                raise SnappyFormatError(
                    f"reserved unskippable chunk type 0x{kind:02x} at offset {at}"
                )
            # Reserved skippable chunk or padding: dropped as it arrives.
            self._consume(_HEADER)
            self._skip = length

    def _chunk_buffered(self) -> bool:
        """Whether a call with no new input can make progress (or raise)."""
        if self._skip:
            return bool(self._input)
        if len(self._input) < _HEADER:
            return False
        kind = self._input[0]
        length = int.from_bytes(self._input[1:_HEADER], "little")
        if not self._identified and kind != _IDENTIFIER_TYPE:
            return True  # refused at once
        if kind == _IDENTIFIER_TYPE:
            valid = length == len(STREAM_IDENTIFIER) - _HEADER
        elif kind in (_COMPRESSED, _UNCOMPRESSED):
            most = _CRC + (_MAX_RAW_BLOCK if kind == _COMPRESSED else MAX_CHUNK_DATA)
            valid = _CRC <= length <= most
        else:
            return True  # skipped or refused at once
        # A chunk with an impossible length is refused without waiting for its bytes.
        return not valid or len(self._input) >= _HEADER + length

    @property
    def eof(self) -> bool:
        return self._ended and not self._output

    @property
    def needs_input(self) -> bool:
        if self._ended:
            return False
        return not self._output and not self._chunk_buffered()

    def end_input(self) -> None:
        """The input ended: the stream is complete only between chunks, after a stream
        identifier."""
        if self._ended:
            return
        if self._skip:
            raise EOFError(
                f"Snappy stream ends inside a skippable chunk, {self._skip} bytes short"
            )
        if self._input:
            raise EOFError(
                f"Snappy stream ends inside a chunk at offset {self._offset}"
            )
        if not self._identified:
            raise EOFError("Snappy stream ends before its stream identifier")
        self._ended = True
