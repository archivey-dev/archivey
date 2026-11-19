"""Snappy's framing format (``.sz``): the chunks parsed and checked here, the raw
blocks decoded by a native package when one is installed, else in Python.

The framing format (``framing_format.txt`` in google/snappy) is a stream identifier
chunk followed by chunks, each a 1-byte type and a 3-byte little-endian length::

    ff 06 00 00 "sNaPpY"                       stream identifier, may repeat
    00 len(3)  masked-crc32c(4)  raw block      compressed data
    01 len(3)  masked-crc32c(4)  data           uncompressed data
    02-7f                                      reserved, unskippable: refused
    80-fd, fe                                  reserved skippable / padding: skipped

The CRC-32C covers the **decoded** data of a chunk, masked as the format describes.
There is no end mark: the stream ends where the input does, which must be between
chunks, or in four or more zero bytes after a chunk that run to the end. Those zeros
are padding, the zero-tail rule of ``dev-docs/formats/single-file.md`` §6. Four zeros
are a compressed chunk of length 0, which is otherwise invalid; fewer may be a header
cut short, and stay a truncation. A non-zero byte after the zeros is refused. A
repeated identifier is how concatenated streams look, so the whole input is one stream
here and nothing follows it.

**What the input can make this allocate.** A data chunk decodes to at most 64 KiB
(the format's limit). The raw block's own length varint is read here and checked
against that limit before a backend sees the block, and a compressed chunk longer than
Snappy's worst case for 64 KiB is refused before it is buffered. Skippable chunks
(up to 16 MiB each) are consumed as they arrive and never held. So this holds at most
one chunk of input and one decoded chunk, whatever the input declares; nothing is left
for ``DecoderLimits.max_decoder_memory`` to cap.

**Raw blocks.** :func:`raw_block_decoder` picks ``compress-utils``, else ``cramjam``,
else :func:`decode_raw_python`. Every check of the framing, the sizes and the CRC is
done here, the same for all of them, and a block a native package refuses is decoded
again in Python, which decides (:func:`checked_by_python`). So the installed packages
change the speed, never which files read or what they read to.

**Process isolation.** Under ``ProcessIsolation.NATIVE_DECODERS`` the same packages
run in a child process held for the stream (:func:`chunk_decoder`), and the framing
and every check stay here; only the Python decoder and CRC run here when no package is
usable.

**CRC-32C.** The standard library has no CRC-32C (``zlib.crc32`` is a different
polynomial). ``google-crc32c`` (only with its C extension), else ``crc32c``, is used
when installed; otherwise a table-driven Python CRC runs at about 20 MB/s.

**Speed.** With a native decoder and the Python CRC, the CRC bounds the decode. With
nothing installed, the Python decoder costs about as much again as the Python CRC, and
a read runs at about 10 MB/s; with native packages for both, at hundreds of MB/s.
"""

from __future__ import annotations

import functools
import struct
import warnings
from array import array
from collections.abc import Callable, Iterable
from types import ModuleType
from typing import TYPE_CHECKING

from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.isolated import (
    IN_PROCESS,
    ChildSnappyNatives,
    Natives,
    SnappyChildError,
)
from archivey.types import OptionalLibrary

if TYPE_CHECKING:
    from archivey.internal.resource_usage import ResourceUsageRecorder

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
_FOUR_HALVES = struct.Struct("<4H")


@functools.cache
def _halfword_tables() -> tuple[array[int], ...]:
    """Four 65,536-entry tables, one per 16-bit half-word of an 8-byte step: each
    combines two of the byte tables. 1 MiB and about 25 ms to build, so built on the
    first Python CRC rather than at import: a process with a native CRC package never
    needs them. Kept for the process, shared by every decoder."""
    return tuple(
        array("I", (_T[2 * i + 1][x & 0xFF] ^ _T[2 * i][x >> 8] for x in range(65536)))
        for i in range(4)
    )


def crc32c_python(data: bytes | memoryview) -> int:
    """CRC-32C (Castagnoli) of ``data`` in Python: 8 bytes per step, as four 16-bit
    table lookups (about 1.5 times slicing by 8 with byte tables, measured on CPython
    3.11 to 3.13)."""
    t0, t1, t2, t3 = _halfword_tables()
    byte_table = _T[0]
    crc = 0xFFFFFFFF
    view = memoryview(data)
    whole = len(view) // 8 * 8
    for a, b, c, d in _FOUR_HALVES.iter_unpack(view[:whole]):
        a ^= crc & 0xFFFF
        b ^= crc >> 16
        crc = t3[a] ^ t2[b] ^ t1[c] ^ t0[d]
    for byte in view[whole:]:
        crc = byte_table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# The native CRC-32C packages, in the order they are tried: (library, function name).
_NATIVE_CRC = (
    (OptionalLibrary.GOOGLE_CRC32C, "value"),
    (OptionalLibrary.CRC32C, "crc32c"),
)


def _is_native(library: OptionalLibrary, module: ModuleType) -> bool:
    """Whether ``module`` computes the CRC in native code. google-crc32c imports
    without its C extension when that fails to load, falls back to its own Python CRC
    (about 3 times slower than :func:`crc32c_python`) and says so in
    ``implementation``."""
    if library is OptionalLibrary.GOOGLE_CRC32C:
        return getattr(module, "implementation", None) == "c"
    return True


def crc32c_function(
    excluded: frozenset[OptionalLibrary] = frozenset(),
    usage: ResourceUsageRecorder | None = None,
) -> Callable[[bytes], int]:
    """The CRC-32C to check chunks with in this process: ``google-crc32c``, else
    ``crc32c``, when one is installed and not ``excluded``, else
    :func:`crc32c_python`."""
    for library, function in _NATIVE_CRC:
        if library in excluded:
            continue
        with warnings.catch_warnings():
            # google-crc32c warns at import when it falls back to its Python CRC,
            # which is then skipped here.
            warnings.simplefilter("ignore", RuntimeWarning)
            module = deps.snappy_libraries[library].load()
        if module is not None and _is_native(library, module):
            if usage is not None:
                usage.note_backend("library", library.value, "snappy")
            return getattr(module, function)
    return crc32c_python


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


def _cramjam(module: ModuleType) -> Callable[[bytes, int], bytes]:
    decompress_raw = module.snappy.decompress_raw
    error = module.DecompressionError

    def decode(block: bytes, size: int) -> bytes:
        try:
            out = decompress_raw(block)
        except error as exc:
            raise SnappyFormatError(f"cramjam refused the raw block: {exc}") from exc
        return bytes(out)

    return decode


def _compress_utils(module: ModuleType) -> Callable[[bytes, int], bytes]:
    decompress = module.decompress
    algorithm = module.Algorithm.snappy
    error = module.CompressError

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


def _python_refused(reason: str) -> SnappyFormatError:
    return SnappyFormatError(f"the Python decoder refused the raw block: {reason}")


def _raw_tag_table() -> tuple[tuple[int, int, int], ...]:
    # Kind, literal length minus one / copy length, and copy offset high bits / width.
    tags = []
    for tag in range(256):
        kind = tag & 3
        if kind == 0:
            tags.append((kind, tag >> 2, 0))
        elif kind == 1:
            tags.append((kind, ((tag >> 2) & 7) + 4, (tag >> 5) << 8))
        else:
            tags.append((kind, (tag >> 2) + 1, 2 if kind == 2 else 4))
    return tuple(tags)


_RAW_TAGS = _raw_tag_table()
_RAW_OFFSET16 = struct.Struct("<H").unpack_from
_RAW_OFFSET32 = struct.Struct("<I").unpack_from


def decode_raw_python(block: bytes, size: int) -> bytes:
    """Decode a raw Snappy block in pure Python (format_description.txt).

    ``size`` is the length the leading varint declares, already checked by
    :func:`raw_length`. Refuses, as Google Snappy does: an element cut by the end of
    the block, a copy whose offset is 0 or reaches before the start of the output, and
    output that runs past ``size``. The caller checks that the output ends exactly at
    ``size``. Accepts a literal length written with a longer tag than it needs, which
    Google Snappy accepts too.
    """
    view = memoryview(block)
    end = len(block)
    tags = _RAW_TAGS
    pos = 0
    while block[pos] & 0x80:  # skip the varint raw_length() already read
        pos += 1
    pos += 1
    out = bytearray()
    while pos < end:
        tag = block[pos]
        pos += 1
        kind, n, extra = tags[tag]
        if kind == 0:
            if n >= 60:
                width = n - 59
                if pos + width > end:
                    raise _python_refused("raw block ends inside a literal length")
                n = int.from_bytes(view[pos : pos + width], "little")
                pos += width
            n += 1
            if pos + n > end:
                raise _python_refused("raw block ends inside a literal")
            if len(out) + n > size:
                raise _python_refused("raw block decodes past its declared length")
            out += view[pos : pos + n]
            pos += n
            continue
        if kind == 1:
            if pos >= end:
                raise _python_refused("raw block ends inside a copy")
            offset = extra | block[pos]
            pos += 1
        else:
            width = extra
            if pos + width > end:
                raise _python_refused("raw block ends inside a copy")
            offset = (
                _RAW_OFFSET16(block, pos)[0]
                if kind == 2
                else _RAW_OFFSET32(block, pos)[0]
            )
            pos += width
        here = len(out)
        if offset == 0 or offset > here:
            raise _python_refused(
                f"copy offset {offset} is outside the {here} bytes decoded so far"
            )
        if here + n > size:
            raise _python_refused("raw block decodes past its declared length")
        start = here - offset
        if offset >= n:
            out += out[start : start + n]
        else:
            # An overlapping copy repeats the last ``offset`` bytes.
            pattern = out[start:]
            out += (pattern * (n // offset + 1))[:n]
    return bytes(out)


# The native raw-block decoders, in the order they are tried. compress-utils first: it
# matched Google Snappy on every input measured, while cramjam refuses three valid but
# unusual raw encodings (dev-docs/investigations/snappy-framing-backends.md). cramjam
# second: it has wheels for more interpreters, PyPy included. The Python decoder is
# the fallback and needs nothing installed.
NATIVE_DECODERS: dict[
    OptionalLibrary, Callable[[ModuleType], Callable[[bytes, int], bytes]]
] = {
    OptionalLibrary.COMPRESS_UTILS: _compress_utils,
    OptionalLibrary.CRAMJAM: _cramjam,
}


def checked_by_python(
    native: Callable[[bytes, int], bytes],
) -> Callable[[bytes, int], bytes]:
    """``native``, with any block it refuses, or decodes to the wrong length, decoded
    again by :func:`decode_raw_python`, which then decides.

    So which blocks are accepted, and what they decode to, does not depend on the
    package installed (DR-1): cramjam refuses three valid encodings that Google Snappy
    and the Python decoder accept. A valid block costs nothing more; only a refused one
    is decoded twice.
    """

    def decode(block: bytes, size: int) -> bytes:
        try:
            out = native(block, size)
        except SnappyFormatError:
            return decode_raw_python(block, size)
        if len(out) != size:
            return decode_raw_python(block, size)
        return out

    return decode


def raw_block_decoder(
    excluded: frozenset[OptionalLibrary] = frozenset(),
    usage: ResourceUsageRecorder | None = None,
) -> Callable[[bytes, int], bytes]:
    """The raw-block decoder to use in this process: the first of
    :data:`NATIVE_DECODERS` that is installed and not ``excluded``, checked by the
    Python decoder, else the Python decoder alone."""
    for library, adapt in NATIVE_DECODERS.items():
        if library in excluded:
            continue
        module = deps.snappy_libraries[library].load()
        if module is not None:
            if usage is not None:
                usage.note_backend("library", library.value, "snappy")
            return checked_by_python(adapt(module))
    return decode_raw_python


def _allowed(
    libraries: Iterable[OptionalLibrary],
    excluded: frozenset[OptionalLibrary],
    natives: Natives,
) -> list[OptionalLibrary]:
    return [
        library
        for library in libraries
        if library not in excluded
        and not deps.snappy_libraries[library].child_import_failed
        and natives.package_available(deps.snappy_libraries[library])
    ]


class LocalChunks:
    """A data chunk's decode and CRC-32C in this process."""

    def __init__(
        self, decode: Callable[[bytes, int], bytes], crc32c: Callable[[bytes], int]
    ) -> None:
        self.decode = decode
        self.crc32c = crc32c

    def __call__(self, compressed: bool, body: bytes) -> tuple[bytes, int]:
        """The chunk's data (``body`` decoded when ``compressed``) and its CRC-32C."""
        data = decode_raw_chunk(self.decode, body) if compressed else body
        return data, self.crc32c(data)


class ChildChunks:
    """A data chunk's decode and CRC-32C in a child process held for the stream, one
    round trip per chunk (``ChildSnappyNatives.chunk``), whichever of the two has a
    native package there; the other runs here, in Python.

    A block the child's package refuses, or decodes to the wrong length, is decoded
    again here in Python, which decides, as :func:`checked_by_python` does in process.
    """

    def __init__(self, child: ChildSnappyNatives, decoder: bool, crc: bool) -> None:
        # An attribute, so that ``release_decoder_children`` finds the child.
        self._child = child
        self._decoder = decoder
        self._crc = crc

    def _crc32c(self, data: bytes) -> int:
        if not self._crc:
            return crc32c_python(data)
        return int.from_bytes(self._child.chunk(data, -1), "little")

    def __call__(self, compressed: bool, body: bytes) -> tuple[bytes, int]:
        if compressed and self._decoder:
            size = raw_length(body)
            try:
                out = self._child.chunk(body, size)
            except SnappyChildError:
                out = None
            if out is not None:
                data = out[:-_CRC] if self._crc else out
                if len(data) == size:
                    if self._crc:
                        return data, int.from_bytes(out[-_CRC:], "little")
                    return data, crc32c_python(data)
            data = decode_raw_chunk(decode_raw_python, body)
            return data, self._crc32c(data)
        data = decode_raw_chunk(decode_raw_python, body) if compressed else body
        return data, self._crc32c(data)


ChunkDecoder = Callable[[bool, bytes], tuple[bytes, int]]


def chunk_decoder(
    excluded: frozenset[OptionalLibrary] = frozenset(),
    natives: Natives = IN_PROCESS,
    usage: ResourceUsageRecorder | None = None,
) -> ChunkDecoder:
    """What decodes a data chunk and computes its CRC-32C.

    In this process, :func:`raw_block_decoder` and :func:`crc32c_function`. Under
    ``ProcessIsolation.NATIVE_DECODERS`` (``natives.isolated``) the same packages, in
    the same order, run in one child process held for the stream, and the framing stays
    here: one round trip per chunk carries its block there and its data and CRC back,
    far cheaper than the Python decoder and CRC. A package the child cannot import is
    skipped, and with none left the Python decoder and CRC run here, with no child.
    """
    if not natives.isolated:
        return LocalChunks(
            raw_block_decoder(excluded, usage), crc32c_function(excluded, usage)
        )
    decoders = _allowed(NATIVE_DECODERS, excluded, natives)
    crcs = _allowed((library for library, _ in _NATIVE_CRC), excluded, natives)
    if not decoders and not crcs:
        return LocalChunks(decode_raw_python, crc32c_python)
    child = natives.snappy_natives(
        [library.value for library in decoders], [library.value for library in crcs]
    )
    decoder, crc = child.chosen()
    for tried, chosen in ((decoders, decoder), (crcs, crc)):
        for library in tried:
            if library.value == chosen:
                if usage is not None:
                    usage.note_backend("library", library.value, "snappy")
                break
            # The child takes the first it can use: this one was found here but not
            # importable there (or google-crc32c without its C extension).
            deps.snappy_libraries[library].failed_in_child(
                ImportError(f"{library.value} is not usable in the decoder process")
            )
    if not decoder and not crc:
        child.close()
        return LocalChunks(decode_raw_python, crc32c_python)
    return ChildChunks(child, bool(decoder), bool(crc))


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
    :meth:`end_input` finds the input ended between chunks, or in zero padding after
    one, after an identifier.
    """

    def __init__(self, chunks: ChunkDecoder) -> None:
        # Decodes a data chunk and computes its CRC (``LocalChunks``, ``ChildChunks``).
        self._chunks = chunks
        self._input = bytearray()
        # Bytes of a skippable chunk still to drop as they arrive.
        self._skip = 0
        self._identified = False
        self._ended = False
        # Where a run of zero bytes after a chunk started, once a whole chunk header
        # of zeros was seen; ``None`` before. Zeros that run to the end of the input
        # are padding (``end_input``); a non-zero byte after them is refused.
        self._zeros_from: int | None = None
        self._output = memoryview(b"")
        # Offset in the stream of the start of ``_input``, for error messages and seek
        # points; where this decompressor started in the stream (not 0 after
        # :meth:`resume`); and the output decoded since then.
        self._offset = 0
        self._base = 0
        self._decoded = 0
        # The data chunks begun since ``take_block_starts`` last asked
        # (``BlockResumable``).
        self._block_starts: list[tuple[int, int, object]] = []
        self.unused_data = b""

    def take_block_starts(self) -> list[tuple[int, int, object]]:
        """The data chunks decoded and checked since the last call: their input and
        output offsets from this decompressor's start, and the chunk's offset in the
        stream, what :meth:`resume` takes. Every chunk is a raw block of its own with
        its own CRC-32C, and nothing in the stream covers more than one chunk, so a
        decode can start at any data chunk."""
        starts, self._block_starts = self._block_starts, []
        return starts

    def resume(self, state: object) -> None:
        """Start inside a stream: the input begins at the data chunk at offset
        ``state`` in the stream, after the stream identifier. Error messages go on
        naming offsets in the stream."""
        assert isinstance(state, int)
        assert not self._identified and not self._input
        self._identified = True
        self._offset = self._base = state

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
            if self._zeros_from is not None:
                self._drop_zeros()
                return False
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
            if kind == _COMPRESSED and length == 0:
                # A header of four zero bytes, a length no chunk has: padding, if
                # only zeros follow.
                self._zeros_from = at
                self._consume(_HEADER)
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
                    data, crc = self._chunks(kind == _COMPRESSED, body)
                except SnappyFormatError as exc:
                    raise SnappyFormatError(f"chunk at offset {at}: {exc}") from exc
                if masked_crc(crc) != stored:
                    raise SnappyFormatError(f"CRC-32C mismatch in chunk at offset {at}")
                self._output = memoryview(data)
                # An empty chunk is no point: it shares its output offset with the
                # next chunk, and two points with different states at one offset are
                # refused as a misleading index.
                if data:
                    self._block_starts.append((at - self._base, self._decoded, at))
                    self._decoded += len(data)
                return True
            if kind < _FIRST_SKIPPABLE:
                raise SnappyFormatError(
                    f"reserved unskippable chunk type 0x{kind:02x} at offset {at}"
                )
            # Reserved skippable chunk or padding: dropped as it arrives.
            self._consume(_HEADER)
            self._skip = length

    def _drop_zeros(self) -> None:
        """Drop the zero bytes buffered after a zero chunk header, or refuse the first
        byte that is not zero: zeros are padding only where they run to the end."""
        nonzero = self._input.lstrip(b"\x00")
        if nonzero:
            at = self._offset + len(self._input) - len(nonzero)
            raise SnappyFormatError(
                f"zero bytes from offset {self._zeros_from} are followed by a "
                f"non-zero byte at offset {at}: they are neither padding nor a chunk"
            )
        self._consume(len(self._input))

    def _chunk_buffered(self) -> bool:
        """Whether a call with no new input can make progress (or raise)."""
        if self._zeros_from is not None:
            return bool(self._input)
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
        """The input ended: the stream is complete only between chunks, or in zero
        padding after one (``_zeros_from``), after a stream identifier."""
        if self._ended:
            return
        if self._skip:
            raise EOFError(
                f"Snappy stream ends inside a skippable chunk, {self._skip} bytes short"
            )
        if self._input:
            # Fewer than four zero bytes are not padding: they may be the start of a
            # compressed chunk's header, cut.
            raise EOFError(
                f"Snappy stream ends inside a chunk at offset {self._offset}"
            )
        if not self._identified:
            raise EOFError("Snappy stream ends before its stream identifier")
        self._ended = True
