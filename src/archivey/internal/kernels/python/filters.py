"""The ARM64 and RISC-V branch filters in Python, as ``archivey_codecs.filters``.

The filters themselves are :mod:`archivey.internal.streams.codecs.arm64_filter` and
:mod:`archivey.internal.streams.codecs.riscv_filter`; a decoder here runs one over a
stream fed in chunks.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.internal.kernels.python._args import u64
from archivey.internal.kernels.python._buffers import raw_bytes
from archivey.internal.streams.codecs.arm64_filter import arm64_decode
from archivey.internal.streams.codecs.riscv_filter import riscv_decode


class _BranchDecoder:
    """One stream through a branch filter. :meth:`decode` returns the decoded prefix of
    everything fed so far; the last few bytes can be the start of an instruction the
    end of the chunk cut off, so they are held back for the next call (at most 3 for
    ARM64, 7 for RISC-V). :meth:`flush` returns them unchanged at the end of the
    input."""

    __slots__ = ("_position", "_raw", "total_in", "total_out")

    _decode: Callable[[bytes, int], bytes]

    def __init__(self, start_offset: int = 0) -> None:
        self._position = u64(
            start_offset, "start_offset"
        )  # pc of the first byte in self._raw
        self._raw = b""  # input not yet decoded: the few bytes decode left
        self.total_in = 0
        self.total_out = 0

    def decode(self, data: bytes | bytearray | memoryview) -> bytes:
        data = raw_bytes(data)
        self.total_in += len(data)
        if self._raw:
            data = self._raw + data
        decoded = type(self)._decode(data, self._position)
        self._position += len(decoded)
        self._raw = data[len(decoded) :]
        self.total_out += len(decoded)
        return decoded

    def flush(self) -> bytes:
        out = self._raw
        self._position += len(out)
        self._raw = b""
        self.total_out += len(out)
        return out


class Arm64Decoder(_BranchDecoder):
    """The ARM64 filter (7z method ``0xA``, xz filter ``0x0A``)."""

    __slots__ = ()
    _decode = staticmethod(arm64_decode)


class RiscvDecoder(_BranchDecoder):
    """The RISC-V filter (7z method ``0xB``, xz filter ``0x0B``)."""

    __slots__ = ()
    _decode = staticmethod(riscv_decode)
