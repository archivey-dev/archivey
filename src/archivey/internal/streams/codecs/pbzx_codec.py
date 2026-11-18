"""pbzx: Apple's chunked xz framing, the ``Payload`` of a macOS ``.pkg`` and the
``Content`` of a ``.xip``.

The layout, from the ``pbzx`` tools that read it (Jonathan Levin's ``pbzx.c`` and its
forks) and the payloads Apple's ``pkgbuild`` and ``xip`` write; all numbers are 64-bit
big-endian::

    "pbzx"   chunk size C
    then each chunk:   decoded size U   stored length L   L bytes

A chunk whose ``L`` equals its ``U`` is stored as it is (data xz could not shrink);
any other chunk is one whole xz stream that decodes to exactly ``U`` bytes. Every chunk
but the last decodes to ``C`` bytes, so a chunk shorter than ``C`` ends the stream, and
anything after it is trailing data; the tools stop there too. A stream whose size is a
multiple of ``C`` ends with the input. Apple writes ``C`` = 16 MiB.

xz decodes each chunk under ``DecoderLimits.max_decoder_memory``
(:func:`~archivey.internal.streams.codecs.xz_decoder.new_capped_decompressor`). Nothing
is held whole: a stored chunk passes through as it arrives, and an xz chunk is fed to
liblzma as it arrives, so a chunk size the header declares allocates nothing.
"""

from __future__ import annotations

import functools
import lzma
import struct
from collections.abc import Callable
from typing import TYPE_CHECKING

from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.config import DecoderLimits, StreamConfig
from archivey.internal.overrides import override
from archivey.internal.streams.archive_stream import ExceptionTranslator
from archivey.internal.streams.codecs.base import Codec, CodecParams, StreamCodec
from archivey.internal.streams.codecs.xz_decoder import (
    lzma_error_to_archivey,
    new_capped_decompressor,
)
from archivey.types import ArchiveFormat, MagicSignature, StreamFormat

if TYPE_CHECKING:
    from archivey.formats import Decompressor

PBZX_MAGIC = b"pbzx"
_U64 = struct.Struct(">Q")
_HEADER_SIZE = len(PBZX_MAGIC) + _U64.size
_CHUNK_HEAD = struct.Struct(">QQ")

# What the decompressor is reading now.
_HEADER = 0
_CHUNK = 1
_STORED = 2
_XZ = 3
_END = 4


class PbzxDecompressor:
    """One pbzx stream, behind the one-stream decompressor interface."""

    def __init__(self, new_xz: Callable[[], Decompressor]) -> None:
        self._new_xz = new_xz
        self._state = _HEADER
        self._pending = bytearray()
        self._chunk_size = 0
        # The chunk being read: its decoded size, the bytes of it still to come, and
        # (xz) how many decoded bytes it has given so far.
        self._decoded_size = 0
        self._left = 0
        self._given = 0
        self._xz: Decompressor | None = None
        self.unused_data = b""

    @property
    def eof(self) -> bool:
        return self._state == _END

    @property
    def needs_input(self) -> bool:
        state = self._state
        if state == _END:
            return False
        if state == _HEADER:
            return len(self._pending) < _HEADER_SIZE
        if state == _CHUNK:
            return len(self._pending) < _CHUNK_HEAD.size
        if state == _STORED:
            return not self._pending
        xz = self._xz
        assert xz is not None
        return xz.needs_input and not (self._pending and self._left)

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._state == _END:
            if data:
                raise EOFError("pbzx data after the end of the stream")
            return b""
        self._pending += data
        out = bytearray()
        while self._state != _END:
            room = -1 if max_length < 0 else max_length - len(out)
            if room == 0:
                break
            state = self._state
            if state == _HEADER:
                if not self._read_header():
                    break
            elif state == _CHUNK:
                if not self._read_chunk_head():
                    break
            elif state == _STORED:
                if not self._pending:
                    break
                take = self._left if room < 0 else min(self._left, room)
                piece = self._pending[:take]
                del self._pending[:take]
                out += piece
                self._left -= len(piece)
                if not self._left:
                    self._end_chunk()
            elif not self._step_xz(out, room):
                break
        if self._state == _END:
            self.unused_data = bytes(self._pending)
            self._pending = bytearray()
        return bytes(out)

    def _read_header(self) -> bool:
        pending = self._pending
        seen = min(len(pending), len(PBZX_MAGIC))
        if pending[:seen] != PBZX_MAGIC[:seen]:
            raise CorruptionError("Not a pbzx stream (bad magic)")
        if len(pending) < _HEADER_SIZE:
            return False
        (size,) = _U64.unpack_from(pending, len(PBZX_MAGIC))
        if not size:
            raise CorruptionError(f"pbzx header declares a chunk size of {size}")
        del pending[:_HEADER_SIZE]
        self._chunk_size = size
        self._state = _CHUNK
        return True

    def _read_chunk_head(self) -> bool:
        pending = self._pending
        if len(pending) < _CHUNK_HEAD.size:
            return False
        decoded, stored = _CHUNK_HEAD.unpack_from(pending)
        if not 0 < decoded <= self._chunk_size:
            raise CorruptionError(
                f"pbzx chunk declares {decoded} decoded bytes, with a chunk size of "
                f"{self._chunk_size}"
            )
        if not stored:
            raise CorruptionError("pbzx chunk stores no bytes")
        del pending[: _CHUNK_HEAD.size]
        self._decoded_size = decoded
        self._left = stored
        if stored == decoded:
            self._state = _STORED
        else:
            self._xz = self._new_xz()
            self._given = 0
            self._state = _XZ
        return True

    def _step_xz(self, out: bytearray, room: int) -> bool:
        """Feed the xz chunk what has arrived of it and decode up to ``room`` bytes.
        False when nothing more can be done before more input."""
        xz = self._xz
        assert xz is not None
        feed = b""
        if xz.needs_input:
            if not self._pending:
                return False
            feed = bytes(self._pending[: self._left])
            del self._pending[: len(feed)]
            self._left -= len(feed)
        piece = xz.decompress(feed, room)
        self._given += len(piece)
        if self._given > self._decoded_size:
            raise CorruptionError(
                f"pbzx chunk decodes to more than the {self._decoded_size} bytes it "
                "declares"
            )
        out += piece
        if xz.eof:
            if xz.unused_data or self._left:
                raise CorruptionError("pbzx chunk holds bytes after its xz stream")
            if self._given != self._decoded_size:
                raise CorruptionError(
                    f"pbzx chunk decodes to {self._given} bytes, not the "
                    f"{self._decoded_size} it declares"
                )
            self._xz = None
            self._end_chunk()
            return True
        if xz.needs_input and not self._left:
            raise CorruptionError("pbzx chunk ends inside its xz stream")
        return bool(piece) or bool(feed)

    def _end_chunk(self) -> None:
        """A chunk shorter than the chunk size is the last one."""
        self._state = _CHUNK if self._decoded_size == self._chunk_size else _END

    def end_input(self) -> None:
        """The input ended: at a chunk boundary after the header that is the end of a
        stream whose size is a multiple of the chunk size."""
        if self._state == _CHUNK and not self._pending:
            self._state = _END
            return
        if self._state == _HEADER:
            raise EOFError("pbzx stream ends inside its header")
        raise EOFError("pbzx stream ends inside a chunk")


def _translate(
    exc: Exception, limits: DecoderLimits | None = None
) -> ArchiveyError | None:
    if isinstance(exc, lzma.LZMAError):
        return lzma_error_to_archivey(exc, "Error reading pbzx chunk", limits)
    return None


class PbzxCodec(StreamCodec):
    """Apple's pbzx streams: xz chunks, or stored ones, behind a chunk size."""

    codec = Codec.PBZX
    stream_format = StreamFormat.PBZX
    magic = (MagicSignature(0, PBZX_MAGIC, ArchiveFormat.PBZX),)
    # The stream ends at its short chunk, or with the input: nothing continues it.
    concatenated = False

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        del params
        new_xz = functools.partial(
            new_capped_decompressor, config.decoder_limits, natives=config.natives
        )
        return PbzxDecompressor(new_xz)

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        return _translate(exc)

    @override
    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        return functools.partial(_translate, limits=config.decoder_limits)
