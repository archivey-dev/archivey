"""bzip3: the ``.bz3`` files the ``bzip3`` tool writes.

The layout, from bzip3's ``src/main.c`` and ``src/libbz3.c`` (1.5.3)::

    "BZ3v1"   block size (4, little-endian, 65 KiB to 511 MiB)
    then, to the end of the file, blocks:
        compressed size (4)   decoded size (4)   the compressed block

A compressed block starts with its CRC-32 and its BWT index, then a model byte and,
for the LZP and RLE stages the model names, a size each. A BWT index of -1 marks a
literal block: at most 64 bytes stored as they are, behind the CRC. libbzip3 checks
every block's CRC-32 as it decodes it.

**No end mark.** The file has no total size and nothing after its last block: it ends
where a block ends. A file cut at a block boundary therefore reads as a shorter valid
file; one cut inside a block raises ``TruncatedError``. Nothing can follow the last
block either, so a second ``.bz3`` written after the first is refused, as the
``bzip3`` tool refuses it.

**The decoder.** The ``bzip3`` package (imported as ``bz3``) wraps libbzip3. Its
``BZ3Decompressor`` takes any bytes, but it trusts the sizes in each block header:
a negative compressed size reaches ``memcpy`` as a huge length, and for a literal
block it returns as many bytes of its buffer as the header's decoded size says,
whatever the block held. So this module reads the framing itself, checks every size
against the block size and the block's own header, and hands the native decoder one
whole, checked block at a time. The decoder runs in a child process unless
``process_isolation`` is ``NONE``, as PPMd's does: libbzip3 had seven memory-safety
CVEs in 2023.

**Seeking.** Every block decodes on its own, and its header gives both its compressed
and decoded size. Under declared seek demand each block a read reaches is a seek point
(:class:`~archivey.internal.streams.codecs.framed_decoder.BlockResumable`), and on a
source that can seek :func:`build_bzip3_index` walks the block headers from the start
of the file without decoding, one 8-byte read per block, for every point and the size.
A seek then decodes at most one block. The walk trusts the block sizes, as the xz and
lzip indexes are trusted (threat-model O17); a block that is decoded is still checked
against its header and its CRC-32.

**What a file can make this allocate.** libbzip3 allocates its state for the block
size the header declares, before any block: a swap buffer and a suffix array of four
bytes per byte, both of ``bz3_bound(block size)``, and a 1 MiB LZP table. The binding
adds a buffer of the same bound and three copies of a decoded block (its buffer slice,
the ``bytearray`` it gathers, the ``bytes`` it returns), and this module holds one
compressed block. :func:`decoder_memory` counts all of them, about ten times the
block size, and ``DecoderLimits.max_decoder_memory`` is checked against it before
the decoder is built: under the default 2 GiB cap a block size up to about 200 MiB
reads (the ``bzip3`` tool's default is 16 MiB).
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, BinaryIO

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    exception_detail,
)
from archivey.internal.config import StreamConfig, check_decoder_memory
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.overrides import override
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import StreamIndex
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
from archivey.internal.streams.decompressor_stream import (
    SeekPoint,
    SpacedCollector,
    emit_index_thinned,
)
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.formats import Decompressor

BZIP3_MAGIC = b"BZ3v1"
_HEADER_SIZE = len(BZIP3_MAGIC) + 4
_BLOCK_HEADER_SIZE = 8
# ``bz3_new`` refuses a block size outside this range.
MIN_BLOCK_SIZE = 65 << 10
MAX_BLOCK_SIZE = 511 << 20
# A literal block (BWT index -1) holds at most this many bytes behind its CRC and index.
_MAX_LITERAL = 64
# The LZP table ``bz3_new`` allocates: 2**18 entries of 4 bytes.
_LZP_TABLE = (1 << 18) * 4

BZIP3_REQUIREMENT = MissingComponent(
    OptionalLibrary.BZIP3, "pip install archivey[bzip3]", ("bzip3",)
)


def bz3_bound(size: int) -> int:
    """``bz3_bound``: the longest a ``size``-byte block can encode to, and the size of
    libbzip3's work buffers."""
    return size + size // 50 + 32


def decoder_memory(block_size: int) -> int:
    """What decoding a file of ``block_size`` blocks holds at its peak (module
    docstring): libbzip3's state, the binding's buffer and decoded copies, and the
    compressed block held here."""
    bound = bz3_bound(block_size)
    state = bound + 4 * (bound + 128) + _LZP_TABLE
    return state + 2 * bound + 3 * block_size


def _s32(data: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little", signed=True)


class Bzip3Decompressor:
    """One ``.bz3`` file, behind the one-stream decompressor interface.

    The framing is read here and each checked block goes to the native decoder
    ``open_native`` builds, which is built once the header has been read and checked.
    Every check runs inside :meth:`decompress`, so the properties never raise.
    """

    def __init__(
        self,
        check_block_size: Callable[[int], None],
        open_native: Callable[[], Any],
        *,
        probe_block_max: int | None = None,
    ) -> None:
        self._check_block_size = check_block_size
        # Set for a detection probe: the longest compressed block it waits for.
        self._probe_block_max = probe_block_max
        self._open_native = open_native
        self._native: Any = None
        self._input = bytearray()
        self._block_size: int | None = None
        self._output = memoryview(b"")
        # Whether the next ``decompress`` has work without more input, as the last one
        # left it: a whole block is buffered, or a buffered block header fails its
        # checks and the next call raises.
        self._block_buffered = False
        # A block that fails its framing check or its decode after a good block's
        # output went into the same call: that output is returned first, and this
        # raises on the next call (spec ``compressed-streams``).
        self._raise_after: ArchiveyError | None = None
        self._ended = False
        # Nothing can follow the last block, so no byte is ever left over.
        self.unused_data = b""
        # Input bytes framed so far (the header and whole blocks) and output bytes
        # decoded, from where this decompressor started, and the blocks begun since
        # ``take_block_starts`` last asked (``BlockResumable``).
        self._consumed = 0
        self._decoded = 0
        self._block_starts: list[tuple[int, int, object]] = []

    def take_block_starts(self) -> list[tuple[int, int, object]]:
        """The blocks with output decoded since the last call: their compressed and
        output offsets from this decompressor's start, and the block size, which is
        what :meth:`resume` needs."""
        starts, self._block_starts = self._block_starts, []
        return starts

    def resume(self, state: object) -> None:
        """Start inside a file whose header declared ``state`` as its block size: the
        input begins at a block header."""
        assert isinstance(state, int)
        assert self._block_size is None and not self._input
        self._check_block_size(state)
        self._block_size = state

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._raise_after is not None:
            # Set only once every byte of output was returned.
            raise self._raise_after
        if data:
            self._input += data
        out = bytearray()
        try:
            while True:
                if self._output:
                    room = (
                        len(self._output) if max_length < 0 else max_length - len(out)
                    )
                    out += self._output[:room]
                    self._output = self._output[room:]
                if self._output or (max_length >= 0 and len(out) >= max_length):
                    break
                sizes = self._buffered_block()
                if sizes is None:
                    break
                self._decode_block(*sizes)
        except ArchiveyError as exc:
            # A block is decoded only once the output held is used up, so nothing
            # is held here: the bytes in ``out`` are all there is to return first.
            if not out:
                raise
            self._raise_after = exc
            return bytes(out)
        try:
            self._block_buffered = self._buffered_block() is not None
        except ArchiveyError:
            # The look-ahead does not raise: the next call checks the header again
            # and raises, after the output held is returned.
            self._block_buffered = True
        return bytes(out)

    @property
    def eof(self) -> bool:
        return self._ended and not self._output

    @property
    def needs_input(self) -> bool:
        # False after a failed block, so the next call is made at once and raises.
        return (
            self._raise_after is None
            and not self._output
            and not self._ended
            and not self._block_buffered
        )

    def end_input(self) -> None:
        """The input ended: it must end after the header or after a whole block."""
        if self._block_size is None:
            raise EOFError("bzip3 file ends inside its header")
        if self._input:
            raise EOFError("bzip3 file ends inside a block")
        self._ended = True

    # -- framing ----------------------------------------------------------------------

    def _read_header(self) -> bool:
        """Check the magic and the block size once they are buffered."""
        seen = min(len(self._input), len(BZIP3_MAGIC))
        if self._input[:seen] != BZIP3_MAGIC[:seen]:
            raise CorruptionError("Not a bzip3 file (bad magic)")
        if len(self._input) < _HEADER_SIZE:
            return False
        block_size = _s32(self._input, len(BZIP3_MAGIC))
        if not MIN_BLOCK_SIZE <= block_size <= MAX_BLOCK_SIZE:
            raise CorruptionError(
                f"bzip3 header declares a block size of {block_size} bytes, outside "
                f"the {MIN_BLOCK_SIZE} to {MAX_BLOCK_SIZE} bzip3 allows"
            )
        self._check_block_size(block_size)
        self._block_size = block_size
        del self._input[:_HEADER_SIZE]
        self._consumed += _HEADER_SIZE
        return True

    def _buffered_block(self) -> tuple[int, int] | None:
        """The next block's compressed and decoded sizes when the whole block is
        buffered, else ``None``. The sizes are checked as soon as they are buffered,
        so a block longer than the block size allows is refused before it is held."""
        if self._ended or (self._block_size is None and not self._read_header()):
            return None
        block_size = self._block_size
        assert block_size is not None
        if len(self._input) < _BLOCK_HEADER_SIZE:
            return None
        compressed = _s32(self._input, 0)
        decoded = _s32(self._input, 4)
        if not 0 <= compressed <= bz3_bound(block_size):
            raise CorruptionError(
                f"bzip3 block header declares {compressed} compressed bytes, outside "
                f"the 0 to {bz3_bound(block_size)} a {block_size}-byte block allows"
            )
        if not 0 <= decoded <= block_size:
            raise CorruptionError(
                f"bzip3 block header declares {decoded} decoded bytes, outside the 0 to "
                f"{block_size} of the file's block size"
            )
        if self._probe_block_max is not None and compressed > self._probe_block_max:
            # The first byte comes only once the whole block is decoded.
            raise ResourceLimitError(
                f"a bzip3 block of {compressed} compressed bytes is longer than the "
                f"{self._probe_block_max} a detection probe reads"
            )
        if len(self._input) < _BLOCK_HEADER_SIZE + compressed:
            return None
        return compressed, decoded

    def _decode_block(self, compressed: int, decoded: int) -> None:
        end = _BLOCK_HEADER_SIZE + compressed
        block = bytes(self._input[:end])
        del self._input[:end]
        _check_block(block[_BLOCK_HEADER_SIZE:], decoded)
        if self._native is None:
            assert self._block_size is not None
            self._native = self._open_native()
            self._call_native(BZIP3_MAGIC + self._block_size.to_bytes(4, "little"))
        out = self._call_native(block)
        # bzip3 0.1.10's binding returns exactly the header's decoded size, and
        # libbzip3's CRC-32 over that many bytes is what refuses a wrong one. This
        # check holds if a later binding stops slicing to the header's size.
        if len(out) != decoded:
            raise CorruptionError(
                f"bzip3 block decoded to {len(out)} bytes, not the {decoded} its header "
                "declares"
            )
        self._output = memoryview(out)
        if decoded:
            self._block_starts.append((self._consumed, self._decoded, self._block_size))
        self._consumed += end
        self._decoded += decoded

    def _call_native(self, data: bytes) -> bytes:
        try:
            return self._native.decompress(data)
        except ValueError as exc:
            raise CorruptionError(
                f"bzip3 block does not decode: {exception_detail(exc)}"
            ) from None


def _check_block(block: bytes, decoded: int) -> None:
    """Check a compressed block's own header against its sizes, as libbzip3 does not
    fully: a literal block decodes to the bytes behind its CRC and index, and any
    other block holds the sizes its model byte names."""
    if len(block) >= 8 and _s32(block, 4) == -1:
        if len(block) - 8 > _MAX_LITERAL or decoded != len(block) - 8:
            raise CorruptionError(
                f"bzip3 literal block of {len(block)} bytes declares {decoded} "
                "decoded bytes"
            )
        return
    if len(block) < 9 or len(block) < 9 + 4 * _stages(block[8]):
        raise CorruptionError(
            f"bzip3 block of {len(block)} bytes is shorter than its own header"
        )


def _stages(model: int) -> int:
    """How many sizes a block's model byte puts in its header: LZP (2) and RLE (4)."""
    return bool(model & 2) + bool(model & 4)


# A detection probe (the inner-TAR test reads 512 decoded bytes) gets nothing until the
# first block is decoded whole. It builds a decoder for blocks up to the bzip3 tool's
# default 16 MiB (about 165 MiB of decoder state, as a zstd probe may take a 128 MiB
# window), and waits for a first block of at most 1 MiB compressed, the most compressed
# input detection decodes. Past either it is "can't tell", and the open reads the file as
# a bare ``.bz3``.
_PROBE_BLOCK_SIZE_MAX = 16 << 20
_PROBE_COMPRESSED_MAX = 1 << 20


def _block_size_check(config: StreamConfig) -> Callable[[int], None]:
    """What refuses the header's block size before the decoder is built, as
    ``ResourceLimitError``, which a probe reads as "can't tell": the decoder memory
    cap, and for a detection probe also 16 MiB."""
    limits, usage = config.decoder_limits, config.usage
    probe = config.probe_read_bound is not None

    def check(block_size: int) -> None:
        if probe and block_size > _PROBE_BLOCK_SIZE_MAX:
            raise ResourceLimitError(
                f"a bzip3 header declares {block_size}-byte blocks, over the "
                f"{_PROBE_BLOCK_SIZE_MAX} a detection probe decodes"
            )
        check_decoder_memory(
            decoder_memory(block_size),
            limits=limits,
            what="a bzip3 decode",
            counted_from=(
                f"the {block_size}-byte block size the header declares (libbzip3's "
                "state, about five times the block size, plus the block buffers)"
            ),
            usage=usage,
        )

    return check


class Bzip3Codec(StreamCodec):
    """bzip3 files: blocks of a BWT and context-mixing coder behind ``BZ3v1``."""

    codec = Codec.BZIP3
    stream_format = StreamFormat.BZIP3
    magic = (MagicSignature(0, BZIP3_MAGIC, ArchiveFormat.BZIP3),)
    requirement = BZIP3_REQUIREMENT
    # Every block carries a CRC-32 that libbzip3 checks before it returns the block.
    checks_content = True
    # No end mark: the blocks run to the end of the input.
    concatenated = False

    @override
    def _backend_present(self) -> bool:
        return deps.bzip3.available()

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        del params
        isolation = config.process_isolation
        # In a child unless NONE, as PPMd: this process imports bz3 only under NONE.
        natives = ISOLATED if isolation is not ProcessIsolation.NONE else IN_PROCESS
        setting = isolation.name
        probe = config.probe_read_bound is not None
        return Bzip3Decompressor(
            _block_size_check(config),
            lambda: natives.bzip3_decompressor(setting),
            probe_block_max=_PROBE_COMPRESSED_MAX if probe else None,
        )

    @override
    def stream_index(
        self, params: CodecParams, config: StreamConfig
    ) -> StreamIndex | None:
        del params
        if not config.records_restart_points:
            return None
        # Declared seek demand or restart points only, as zstd
        # (``seekable-decompressor-streams``): no stream follows the last block, so the
        # points are the blocks.
        collector = config.collector
        return StreamIndex(
            resumes_at=lambda data: False,
            build=lambda inner, last: build_bzip3_index(inner, last, collector),
        )

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        # The decompressor turns the binding's ValueError into CorruptionError itself.
        # MemoryError propagates unchanged, as the error-handling spec asks.
        del exc
        return None


def build_bzip3_index(
    inner: BinaryIO, last_known: SeekPoint, collector: DiagnosticCollector | None
) -> tuple[list[SeekPoint], int | None]:
    """Seek points at every block with output after ``last_known``, and the total
    size, from the block headers alone.

    The walk jumps from block header to block header. It ends quietly at a header
    whose sizes the decoder would refuse, or at a block that runs past the end of the
    file: the points before it stand, and the decode raises when it gets there. The
    size is known only when the last block ends exactly at the end of the file. More
    blocks than the seek-table cap are thinned, as for BGZF.
    """
    file_size = inner.seek(0, io.SEEK_END)
    inner.seek(0)
    header = inner.read(_HEADER_SIZE)
    if len(header) < _HEADER_SIZE or header[: len(BZIP3_MAGIC)] != BZIP3_MAGIC:
        return [], None
    block_size = _s32(header, len(BZIP3_MAGIC))
    if not MIN_BLOCK_SIZE <= block_size <= MAX_BLOCK_SIZE:
        return [], None
    bound = bz3_bound(block_size)
    kept: SpacedCollector[tuple[int, int]] = SpacedCollector(lambda b: b[1])
    offset, decoded = _HEADER_SIZE, 0
    while offset + _BLOCK_HEADER_SIZE <= file_size:
        inner.seek(offset)
        sizes = inner.read(_BLOCK_HEADER_SIZE)
        if len(sizes) < _BLOCK_HEADER_SIZE:
            break
        compressed, block_decoded = _s32(sizes, 0), _s32(sizes, 4)
        end = offset + _BLOCK_HEADER_SIZE + compressed
        if not (0 <= compressed <= bound and 0 <= block_decoded <= block_size):
            break
        # ``_check_block``'s refusals on the sizes alone: a block shorter than its
        # CRC and BWT index, and one of exactly those 8 bytes (an empty literal) that
        # declares output.
        if compressed < 8 or (compressed == 8 and block_decoded):
            break
        if end > file_size:
            break
        if block_decoded:
            kept.add((offset, decoded))
        offset, decoded = end, decoded + block_decoded
    if kept.thinned:
        emit_index_thinned(collector, "bzip3", "bzip3_blocks", units="blocks")
    points = [
        SeekPoint(start, comp, block_size)
        for comp, start in kept.items
        if start > last_known.decompressed_offset
    ]
    return points, decoded if offset == file_size else None
