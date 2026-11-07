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

**What a file can make this allocate.** libbzip3 allocates its state for the block
size the header declares, before any block: a swap buffer and a suffix array of four
bytes per byte, both of ``bz3_bound(block size)``, and a 1 MiB LZP table. The binding
adds a buffer of the same bound and three copies of a decoded block (its buffer slice,
the ``bytearray`` it gathers, the ``bytes`` it returns), and this module holds one
compressed block. :func:`decoder_memory` counts all of them, about eleven times the
block size, and ``DecoderLimits.max_decoder_memory`` is checked against it before
the decoder is built: under the default 2 GiB cap a block size up to about 180 MiB
reads (the ``bzip3`` tool's default is 16 MiB).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    ResourceUnavailableError,
    exception_detail,
)
from archivey.internal.config import StreamConfig, check_decoder_memory
from archivey.internal.overrides import override
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    StreamCodec,
)
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
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
        # Whether a whole block is buffered, as the last ``decompress`` left it.
        self._block_buffered = False
        self._ended = False
        # Nothing can follow the last block, so no byte is ever left over.
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if data:
            self._input += data
        out = bytearray()
        while True:
            if self._output:
                room = len(self._output) if max_length < 0 else max_length - len(out)
                out += self._output[:room]
                self._output = self._output[room:]
            if self._output or (max_length >= 0 and len(out) >= max_length):
                break
            sizes = self._buffered_block()
            if sizes is None:
                break
            self._decode_block(*sizes)
        self._block_buffered = self._buffered_block() is not None
        return bytes(out)

    @property
    def eof(self) -> bool:
        return self._ended and not self._output

    @property
    def needs_input(self) -> bool:
        return not self._output and not self._ended and not self._block_buffered

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
        if len(out) != decoded:
            raise CorruptionError(
                f"bzip3 block decoded to {len(out)} bytes, not the {decoded} its header "
                "declares"
            )
        self._output = memoryview(out)

    def _call_native(self, data: bytes) -> bytes:
        try:
            return self._native.decompress(data)
        except ValueError as exc:
            raise CorruptionError(
                f"bzip3 block does not decode: {exception_detail(exc)}"
            ) from None
        except MemoryError as exc:
            raise ResourceUnavailableError(
                "bzip3 decoder could not allocate its state for a "
                f"{self._block_size}-byte block: {exception_detail(exc)}"
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
    """What refuses the header's block size before the decoder is built: the decoder
    memory cap, or for a detection probe 16 MiB, as ``ResourceLimitError``, which a
    probe reads as "can't tell"."""
    if config.probe_read_bound is not None:
        ceiling = _PROBE_BLOCK_SIZE_MAX

        def check_probe(block_size: int) -> None:
            if block_size > ceiling:
                raise ResourceLimitError(
                    f"a bzip3 header declares {block_size}-byte blocks, over the "
                    f"{ceiling} a detection probe decodes"
                )

        return check_probe
    limits, usage = config.decoder_limits, config.usage

    def check(block_size: int) -> None:
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
    def translate(self, exc: Exception) -> ArchiveyError | None:
        # The decompressor turns the binding's ValueError and MemoryError into
        # archivey errors itself, so nothing else reaches here from bzip3.
        del exc
        return None
