"""mozlz4: the file format Firefox stores its session, add-on and search files in.

``addonStartup.json.lz4``, ``sessionstore.jsonlz4``, ``search.json.mozlz4`` and the
``.baklz4`` backups are one raw LZ4 block behind a 12-byte header (Gecko's
``mozilla::Compression::LZ4``, written by ``lz4.sys.mjs``)::

    "mozLz40\\0"   decoded size (4, little-endian)   one LZ4 block   …to the end

It is not an LZ4 frame: there is no frame header, no checksum and no end mark. The
block runs to the end of the file, so it decodes only once the input has ended
(:meth:`MozLz4Decompressor.end_input`).

**What the file can make this allocate.** The decoded size is 32 bits, and it is the
size of the buffer the block decodes into, and python-lz4 copies that buffer into the
``bytes`` it returns, so the decode peaks at twice the size. Twice the size is
checked against ``DecoderLimits.max_decoder_memory`` before any input is held, and the
size against the most the block can decode to (255 bytes per input byte) before the
decode allocates it. A detection probe decodes at most 1 MiB (``_size_check``). The compressed block is
held whole until the input ends; it can be no longer than LZ4's bound for the declared
size (``LZ4_COMPRESSBOUND``), and a longer one is refused as it arrives.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    exception_detail,
)
from archivey.internal.config import StreamConfig, check_decoder_memory
from archivey.internal.overrides import override
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    MetadataContext,
    StreamCodec,
)
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives
from archivey.internal.streams.codecs.lz4_codec import LZ4_REQUIREMENT
from archivey.types import ArchiveFormat, ArchiveMember, MagicSignature, StreamFormat

if TYPE_CHECKING:
    from archivey.formats import Decompressor

MOZLZ4_MAGIC = b"mozLz40\x00"
_HEADER_SIZE = len(MOZLZ4_MAGIC) + 4
# LZ4_MAX_INPUT_SIZE in lz4.h: the largest input LZ4 compresses as one block, so the
# largest decoded size a writer can declare.
_MAX_DECODED = 0x7E000000


def _expand_bound(block: int) -> int:
    """The most a ``block``-byte LZ4 block can decode to: each length byte of 255
    extends a literal run or a match by 255 bytes, so output grows by at most 255
    bytes per input byte, plus a final match and its token."""
    return block * 255 + 64


def _compress_bound(size: int) -> int:
    """``LZ4_COMPRESSBOUND`` in ``lz4.h``: the longest block ``size`` bytes encode to."""
    return size + size // 255 + 16


class MozLz4Decompressor:
    """One mozlz4 file, behind the one-stream decompressor interface.

    ``decompress`` holds the input and returns nothing until :meth:`end_input`
    decodes the block; the output is then returned in ``max_length`` pieces.
    """

    def __init__(
        self, check_size: Callable[[int], None], natives: Natives = IN_PROCESS
    ) -> None:
        self._check_size = check_size
        self._natives = natives
        self._input = bytearray()
        self._size: int | None = None
        self._output: memoryview | None = None
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._output is None:
            self._input += data
            self._read_header()
            return b""
        if data:
            raise CorruptionError("mozlz4 data after the end of the input")
        end = len(self._output) if max_length < 0 else max_length
        out = bytes(self._output[:end])
        self._output = self._output[end:]
        return out

    def _read_header(self) -> None:
        """Check the magic and the declared size once they are buffered, then refuse a
        block longer than that size can encode to."""
        if self._size is None:
            seen = min(len(self._input), len(MOZLZ4_MAGIC))
            if self._input[:seen] != MOZLZ4_MAGIC[:seen]:
                raise CorruptionError("Not a mozlz4 file (bad magic)")
            if len(self._input) < _HEADER_SIZE:
                return
            size = int.from_bytes(
                self._input[len(MOZLZ4_MAGIC) : _HEADER_SIZE], "little"
            )
            if size > _MAX_DECODED:
                raise CorruptionError(
                    f"mozlz4 header declares {size} decoded bytes, more than one LZ4 "
                    "block holds"
                )
            self._check_size(size)
            self._size = size
            del self._input[:_HEADER_SIZE]
        if len(self._input) > _compress_bound(self._size):
            raise CorruptionError(
                f"mozlz4 block is longer than {self._size} decoded bytes can encode to"
            )

    @property
    def eof(self) -> bool:
        return self._output is not None and not self._output

    @property
    def needs_input(self) -> bool:
        return self._output is None

    def end_input(self) -> None:
        """The input ended: decode the block, which must give the declared size."""
        if self._output is not None:
            return
        if self._size is None:
            raise EOFError("mozlz4 file ends inside its header")
        size = self._size
        if not self._input:
            # No block at all, which only an empty file may have. LZ4 writes one zero
            # token for empty input, which decodes below like any other block.
            if size:
                raise EOFError("mozlz4 file ends after its header")
            self._output = memoryview(b"")
            return
        if size > _expand_bound(len(self._input)):
            # Refused before the decode allocates the declared size.
            raise CorruptionError(
                f"mozlz4 header declares {size} decoded bytes, more than its "
                f"{len(self._input)}-byte block can decode to"
            )
        # One copy of the input at a time: the bytearray goes before the decode.
        block = bytes(self._input)
        self._input = bytearray()
        decoded = self._natives.lz4_block_decompress(block, uncompressed_size=size)
        if len(decoded) != size:
            raise CorruptionError(
                f"mozlz4 block decodes to {len(decoded)} bytes, not the {size} its "
                "header declares"
            )
        self._output = memoryview(decoded)


# The most a detection probe decodes: a probe that reaches the end of a small file
# (the inner-TAR probe) decodes its block, and a mozlz4 file is a JSON document, not
# a container, so a probe never needs more.
_PROBE_DECODED_MAX = 1 << 20


def _size_check(config: StreamConfig) -> Callable[[int], None]:
    """What refuses the header's decoded size before any of the block is held.

    A read charges ``DecoderLimits.max_decoder_memory`` twice the declared size:
    python-lz4 decodes into a buffer of that size and copies it into the ``bytes`` it
    returns, so the peak holds both (measured: 1.9 GB declared, 3.8 GiB resident).
    A detection probe (``probe_read_bound``) decodes a block only when it reaches the
    end of the file, which happens for a small file; it refuses a declared size over
    ``max(probe_read_bound, 1 MiB)`` as ``ResourceLimitError``, which a probe reads as
    "can't tell".
    """
    bound = config.probe_read_bound
    if bound is not None:
        ceiling = max(bound, _PROBE_DECODED_MAX)

        def check_probe(size: int) -> None:
            if size > ceiling:
                raise ResourceLimitError(
                    f"a mozlz4 header declares {size} decoded bytes, over the "
                    f"{ceiling} a detection probe decodes"
                )

        return check_probe
    limits, usage = config.decoder_limits, config.usage

    def check(size: int) -> None:
        check_decoder_memory(
            2 * size,
            limits=limits,
            what="a mozlz4 decode",
            counted_from=(
                f"twice the {size}-byte decoded size the header declares (the "
                "decode buffer and the copy returned)"
            ),
            usage=usage,
        )

    return check


class MozLz4Codec(StreamCodec):
    """Firefox's mozlz4 files: one raw LZ4 block behind a magic and a decoded size."""

    codec = Codec.MOZLZ4
    stream_format = StreamFormat.MOZLZ4
    magic = (MagicSignature(0, MOZLZ4_MAGIC, ArchiveFormat.MOZLZ4),)
    extension_aliases = (".jsonlz4", ".baklz4")
    requirement = LZ4_REQUIREMENT
    # One block to the end of the input: nothing can follow it.
    concatenated = False

    @override
    def _backend_present(self) -> bool:
        return deps.lz4_block is not None

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        del params
        return MozLz4Decompressor(_size_check(config), config.natives)

    @override
    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """The decoded size from the header. The read raises unless the block decodes
        to exactly that size, so it is the member's size."""
        head = ctx.peek_header(_HEADER_SIZE)
        if len(head) == _HEADER_SIZE and head.startswith(MOZLZ4_MAGIC):
            member.size = int.from_bytes(head[len(MOZLZ4_MAGIC) :], "little")

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        if deps.lz4_block is not None and isinstance(exc, deps.lz4_block.LZ4BlockError):
            return CorruptionError(
                f"Error reading mozlz4 file: {exception_detail(exc)}"
            )
        return None
