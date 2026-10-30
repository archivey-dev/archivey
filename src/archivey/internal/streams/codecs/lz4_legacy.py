"""The legacy LZ4 frame (``lz4 -l``), which ``lz4.frame`` does not read.

The format the ``lz4`` command wrote before the frame format existed, and the one Linux
kernel images and initramfs files still use (``doc/lz4_Frame_format.md``, §Legacy
frame)::

    02 21 4c 18   size(4, little-endian)  block   size(4)  block   …

There is no frame header, no checksum and no end mark. Every block is compressed on its
own from at most 8 MiB of input, so it decodes with ``lz4.block`` and nothing carries
over from one block to the next. The stream ends where the input does, or at a size
field no writer could have produced: over ``LZ4_COMPRESSBOUND(8 MiB)``, which is how the
``lz4`` command finds another frame's magic after a legacy one (``LZ4IO_decodeLegacyStream``
in ``programs/lz4io.c``). A zero size ends it too, as zeros after a stream are padding.

**What the archive can make this allocate.** The size field is 32 bits, so a crafted
stream can declare a 4 GiB block, and a decoder that believed it would buffer that much
before decoding a byte. A size over the bound is not a block here, so the compressed
input held for one block never exceeds about 8 MiB, and each block decodes into an
8 MiB buffer whatever its header says. Both numbers are the format's, not the
archive's, so there is nothing for :class:`~archivey.DecoderLimits` to cap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives

if TYPE_CHECKING:
    from archivey.internal.streams.codecs.framed_decoder import _OneStreamDecompressor

LEGACY_MAGIC = b"\x02\x21\x4c\x18"
LEGACY_BLOCK_SIZE = 8 * 2**20
# LZ4_COMPRESSBOUND(8 MiB) in lz4.h: the largest compressed block a writer can emit.
LEGACY_BLOCK_BOUND = LEGACY_BLOCK_SIZE + LEGACY_BLOCK_SIZE // 255 + 16

_SIZE_FIELD = 4
# What ``_block_end`` returns for a size field that ends the stream.
_STREAM_END = -1


class Lz4LegacyDecompressor:
    """One legacy LZ4 stream, behind the one-stream decompressor interface.

    The interface is the one ``FramedDecoder`` drives (``decompress(data, max_length)``,
    ``eof``, ``unused_data``, ``needs_input``, ``flush``). ``eof`` is set at a size
    field that ends the stream, and by :meth:`flush` when the input ends where the
    stream may. Corrupt blocks raise ``lz4.block.LZ4BlockError``.
    """

    def __init__(self, natives: Natives = IN_PROCESS) -> None:
        self._natives = natives
        # Starts with the magic until it has been checked.
        self._input = bytearray()
        self._magic_checked = False
        self._output = memoryview(b"")
        self.eof = False
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self.eof:
            raise EOFError("End of stream already reached")
        self._input += data
        out = bytearray()
        while True:
            if self._output:
                room = len(self._output) if max_length < 0 else max_length - len(out)
                out += self._output[:room]
                self._output = self._output[room:]
                if not self._output:
                    # An empty slice still holds the whole block's buffer.
                    self._output = memoryview(b"")
            if max_length >= 0 and len(out) >= max_length:
                break
            if not self._next_block():
                break
        return bytes(out)

    def _block_end(self) -> int | None:
        """Where the next block ends in ``_input``, read from its size field.

        ``None`` while the magic or the size field is not all buffered, and
        ``_STREAM_END`` for a size that ends the stream: zero, or more than any
        writer emits.
        """
        if not self._magic_checked:
            if len(self._input) < len(LEGACY_MAGIC):
                return None
            if self._input[: len(LEGACY_MAGIC)] != LEGACY_MAGIC:
                block = deps.lz4_block
                assert block is not None  # the codec checks lz4 before opening
                raise block.LZ4BlockError("Not a legacy LZ4 stream (bad magic)")
            del self._input[: len(LEGACY_MAGIC)]
            self._magic_checked = True
        if len(self._input) < _SIZE_FIELD:
            return None
        size = int.from_bytes(self._input[:_SIZE_FIELD], "little")
        if size == 0 or size > LEGACY_BLOCK_BOUND:
            return _STREAM_END
        return _SIZE_FIELD + size

    def _next_block(self) -> bool:
        """Decode the next buffered block into ``_output``; False when there is none."""
        end = self._block_end()
        if end is None:
            return False
        if end == _STREAM_END:
            self.eof = True
            self.unused_data = bytes(self._input)
            self._input.clear()
            return False
        if len(self._input) < end:
            return False
        block = bytes(self._input[_SIZE_FIELD:end])
        del self._input[:end]
        self._output = memoryview(
            self._natives.lz4_block_decompress(
                block, uncompressed_size=LEGACY_BLOCK_SIZE
            )
        )
        return True

    @property
    def needs_input(self) -> bool:
        if self.eof or self._output:
            return self.eof
        end = self._block_end()
        return end is None or (end != _STREAM_END and len(self._input) < end)

    def flush(self) -> bytes:
        """The input ended: the stream is complete when that is between blocks, or in
        zeros after one.

        The format has no end mark, so a stream cut exactly between two blocks is
        complete by this test too: that truncation cannot be seen, and the read comes
        out short with no error, as it does with ``lz4 -dc``.
        """
        if (
            self._magic_checked
            and not self.eof
            and not self._output
            and not self._input.strip(b"\x00")
        ):
            self.eof = True
            self._input.clear()
        return b""


class Lz4Decompressor:
    """One LZ4 stream of either kind, picked from its first four bytes.

    A legacy magic gets :class:`Lz4LegacyDecompressor`; anything else goes to
    ``lz4.frame``, so a file that is not LZ4 fails with that library's own error.
    """

    def __init__(self, natives: Natives = IN_PROCESS) -> None:
        self._natives = natives
        self._head = b""
        self._inner: _OneStreamDecompressor | None = None

    def _pick(self, data: bytes) -> bytes:
        """Choose the decompressor once ``data`` tells; return what it should be fed."""
        data = self._head + data
        seen = min(len(data), len(LEGACY_MAGIC))
        if data[:seen] == LEGACY_MAGIC[:seen] and seen < len(LEGACY_MAGIC):
            self._head = data
            return b""
        self._head = b""
        if data.startswith(LEGACY_MAGIC):
            self._inner = Lz4LegacyDecompressor(self._natives)
        else:
            self._inner = self._natives.lz4_frame_decompressor()
        return data

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._inner is None:
            data = self._pick(data)
            if self._inner is None:
                return b""
        return self._inner.decompress(data, max_length)

    @property
    def eof(self) -> bool:
        return self._inner is not None and self._inner.eof

    @property
    def unused_data(self) -> bytes:
        if self._inner is None:
            return b""
        # lz4.frame reports no leftover as None.
        return self._inner.unused_data or b""

    @property
    def needs_input(self) -> bool:
        if self._inner is None:
            return True
        return self._inner.needs_input

    def flush(self) -> bytes:
        if isinstance(self._inner, Lz4LegacyDecompressor):
            return self._inner.flush()
        return b""
