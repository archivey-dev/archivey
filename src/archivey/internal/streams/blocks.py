"""``BlockStream``: a file stored as fixed-size blocks, each decoded on its own.

SquashFS, CAB, WIM, CSO and seekable zstd store a file this way, so a reader can
start at any block. The plugin API hands it out as ``archivey.plugins.block_stream``:
the plugin decodes one block, and this stream does the seeking, keeps the block it is
in, and checks each block's length.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import BinaryIO

from archivey.exceptions import CorruptionError
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    check_read_size,
    resolve_seek,
)

__all__ = ["BlockStream"]


class BlockStream(ReadOnlyIOStream):
    """The ``size`` bytes of a file in blocks of ``block_size``, the last one shorter.

    ``read_block(i)`` returns block ``i`` decoded, as bytes or as a stream. A stream is
    read for at most one byte more than the block's length, then closed, so a block
    that decodes to far more costs no more than that. It is called when a read first
    needs the block, and again after a read has moved to another block: only the
    current block is kept. A block of another length than the file needs there raises
    ``CorruptionError``. Seekable; a seek decodes nothing until the next read.
    """

    def __init__(
        self,
        size: int,
        block_size: int,
        read_block: Callable[[int], bytes | BinaryIO],
    ) -> None:
        super().__init__()
        if size < 0 or block_size <= 0:
            raise ValueError(f"size {size} or block size {block_size} out of range")
        self._size = size
        self._block_size = block_size
        self._read_block = read_block
        self._pos = 0
        self._index = -1
        self._block = b""

    @property
    def size(self) -> int:
        """The file's length."""
        return self._size

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        self._pos = resolve_seek(offset, whence, pos=self._pos, end=lambda: self._size)
        return self._pos

    def _block_at(self, index: int) -> bytes:
        if index != self._index:
            start = index * self._block_size
            expected = min(self._block_size, self._size - start)
            block = self._read_block(index)
            if isinstance(block, (bytes, bytearray, memoryview)):
                data = bytes(block)
            else:
                with block:
                    data = block.read(expected + 1)
            if len(data) != expected:
                raise CorruptionError(
                    f"block {index} holds {len(data)} bytes, not the {expected} the "
                    "file needs there"
                )
            self._index, self._block = index, data
        return self._block

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        n = check_read_size(n)
        remaining = self._size - self._pos
        if remaining <= 0 or n == 0:
            return b""
        if n < 0 or n > remaining:
            n = remaining
        chunks: list[bytes] = []
        while n:
            index, within = divmod(self._pos, self._block_size)
            block = self._block_at(index)
            chunk = block[within : within + n]
            chunks.append(chunk)
            self._pos += len(chunk)
            n -= len(chunk)
        return chunks[0] if len(chunks) == 1 else b"".join(chunks)

    def nearest_resume_offset(self, target: int) -> int:
        """The start of the block ``target`` is in: each block decodes on its own, so
        reaching ``target`` decodes only that block's bytes before it."""
        return target - target % self._block_size
