"""Raw LZMA1/LZMA2 filter chains for 7z and ZIP coders, with Delta, BCJ, ARM64 and
RISC-V stages.
"""

from __future__ import annotations

import lzma
import os
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal import kernels
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.kernels import BranchDecoder
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
)
from archivey.types import OptionalLibrary

if TYPE_CHECKING:
    from archivey.formats import Decompressor

# An LZMA2 uncompressed chunk carries at most 64 KiB of payload behind a 3-byte
# header (control byte + big-endian size-1); see `_Lzma2Framer`.
_LZMA2_UNCOMPRESSED_CHUNK_MAX = 1 << 16


class _Lzma2Framer:
    """Wrap plain bytes as an LZMA2 stream of *uncompressed* chunks.

    liblzma will not build a raw filter chain whose only member is a branch filter
    (``lzma.LZMADecompressor(FORMAT_RAW, [{"id": FILTER_X86}])`` raises
    ``LZMAError: Invalid or unsupported options``) — the chain has to end in a
    compression filter. Framing the input as LZMA2 uncompressed chunks supplies one
    without compressing anything: ``[<branch filter>, FILTER_LZMA2]`` then runs the
    branch filter over the payload and hands the bytes straight back.

    The first chunk's control byte is ``0x01`` (uncompressed, reset dictionary) as
    LZMA2 requires; later chunks use ``0x02``. ``end()`` emits the ``0x00`` end
    marker, which is what makes liblzma release the branch filter's final look-ahead
    bytes. Overhead is 3 bytes per 64 KiB — 0.005% of the payload.
    """

    def __init__(self) -> None:
        self._first = True

    def wrap(self, data: bytes) -> bytes:
        out = bytearray()
        for start in range(0, len(data), _LZMA2_UNCOMPRESSED_CHUNK_MAX):
            chunk = data[start : start + _LZMA2_UNCOMPRESSED_CHUNK_MAX]
            out.append(0x01 if self._first else 0x02)
            out += (len(chunk) - 1).to_bytes(2, "big")
            out += chunk
            self._first = False
        return bytes(out)

    @staticmethod
    def end() -> bytes:
        return b"\x00"


class FilterDecoder(BaseDecoder):
    """Apply a filter-only liblzma stage (a BCJ branch filter, or Delta) to plain bytes.

    The filter runs through liblzma, over an :class:`_Lzma2Framer` wrapper because
    liblzma needs a compression filter to close the chain. It must not be ``pybcj``:
    that decoder cannot be constructed for a member of 2 GiB or more, and its IA64
    filter truncates. See ``dev-docs/investigations/pybcj-upstream-report.md``.

    ``lzma_filter`` is the liblzma filter dict, options included (a BCJ
    ``start_offset``, a Delta ``dist``). ``unpack_size`` is the coder's declared
    output length, used only to decide whether the stream finished — never passed
    to the filter, which needs no bound.
    """

    def __init__(
        self,
        *,
        lzma_filter: Mapping[str, int],
        unpack_size: int,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._lzma_filter = dict(lzma_filter)
        self._unpack_size = unpack_size
        self._natives = natives
        self._produced = 0
        self._framer = _Lzma2Framer()
        self._decomp: Decompressor = natives.lzma_decompressor(
            format=lzma.FORMAT_RAW,
            filters=[self._lzma_filter, {"id": lzma.FILTER_LZMA2}],
        )
        self._pending = b""

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> FilterDecoder:
        del point, inner
        return FilterDecoder(
            lzma_filter=self._lzma_filter,
            unpack_size=self._unpack_size,
            natives=self._natives,
        )

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data = self._pending + chunk
        self._pending = b""
        if not data:
            return DecodeOut(b"")
        if max_length >= 0 and len(data) > max_length:
            # BCJ is a filter (near 1:1); feed only what the caller budget allows and
            # retain the rest — bounds peak buffer without a native max_length API.
            self._pending = data[max_length:]
            data = data[:max_length]
        out = self._decomp.decompress(self._framer.wrap(data))
        self._produced += len(out)
        return DecodeOut(out)

    def flush(self) -> DecodeOut:
        pending = self._pending
        self._pending = b""
        leftover = self._decomp.decompress(
            self._framer.wrap(pending) + _Lzma2Framer.end()
        )
        self._produced += len(leftover)
        if not self.finished:
            self._pending_error = TruncatedError("File is truncated")
        return DecodeOut(leftover)

    @property
    def finished(self) -> bool:
        return self._produced >= self._unpack_size

    @property
    @override
    def needs_input(self) -> bool:
        return not self._pending


# Decode what can be decoded of ``data`` whose first byte is at ``pc``: returns a
# prefix of the decoded stream, and the bytes after it wait for more input.
BranchDecode = Callable[[bytes, int], bytes]

# The branch filters Python's ``lzma`` will not build, and the class that decodes each
# in :func:`archivey.internal.kernels.filters`.
BRANCH_FILTERS: dict[int, str] = {
    FILTER_ARM64: "Arm64Decoder",
    FILTER_RISCV: "RiscvDecoder",
}


class BranchFilterDecoder(BaseDecoder):
    """Apply a branch filter Python's ``lzma`` will not build (ARM64, RISC-V).

    The :class:`FilterDecoder` counterpart for those filters. ``make_branch`` builds the
    filter for one pass over the stream (:func:`archivey.internal.kernels.filters`).
    Each fed chunk is decoded as far as the filter can take it as it arrives (whole
    4-byte words for ARM64, all but the last 7 bytes or so for RISC-V); the rest
    waits for the next chunk, and at the end of the input it is passed through
    unchanged, as liblzma and 7-Zip do. ``max_length`` bounds what one call
    returns; decoded bytes past it are held for the next call.
    """

    def __init__(
        self, *, make_branch: Callable[[], BranchDecoder], unpack_size: int
    ) -> None:
        self._make_branch = make_branch
        self._branch = make_branch()
        self._unpack_size = unpack_size
        self._produced = 0
        self._ready = b""  # decoded output not yet returned
        self._ready_offset = 0

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> BranchFilterDecoder:
        del point, inner
        return BranchFilterDecoder(
            make_branch=self._make_branch, unpack_size=self._unpack_size
        )

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if chunk:
            decoded = self._branch.decode(bytes(chunk))
            if self._ready_offset < len(self._ready):
                decoded = self._ready[self._ready_offset :] + decoded
            self._ready = decoded
            self._ready_offset = 0
        return DecodeOut(self._take(max_length))

    def _take(self, max_length: int) -> bytes:
        start = self._ready_offset
        end = len(self._ready)
        if 0 <= max_length < end - start:
            end = start + max_length
        out = self._ready[start:end]  # the object itself when it is all of it
        self._ready_offset = end
        self._produced += len(out)
        return out

    def flush(self) -> DecodeOut:
        held = self._branch.flush()
        out = self._take(-1) + held
        self._produced += len(held)
        if not self.finished:
            self._pending_error = TruncatedError("File is truncated")
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return self._produced >= self._unpack_size

    @property
    @override
    def needs_input(self) -> bool:
        return self._ready_offset >= len(self._ready)


def branch_maker(
    filter_id: int,
    start_offset: int,
    *,
    excluded: frozenset[OptionalLibrary],
    natives: Natives,
) -> Callable[[], BranchDecoder] | None:
    """What builds the ARM64 or RISC-V filter for ``filter_id``, as
    :func:`archivey.internal.kernels.filters` picks it. ``None`` for a filter liblzma
    decodes."""
    name = BRANCH_FILTERS.get(filter_id)
    if name is None:
        return None
    make = getattr(kernels.filters(excluded, isolated=natives.isolated), name)
    return lambda: make(start_offset)


def _filter_decoder(
    lzma_filter: Mapping[str, int],
    unpack_size: int,
    natives: Natives,
    excluded: frozenset[OptionalLibrary],
) -> FilterDecoder | BranchFilterDecoder:
    make_branch = branch_maker(
        lzma_filter["id"],
        lzma_filter.get("start_offset", 0),
        excluded=excluded,
        natives=natives,
    )
    if make_branch is not None:
        return BranchFilterDecoder(make_branch=make_branch, unpack_size=unpack_size)
    return FilterDecoder(
        lzma_filter=lzma_filter, unpack_size=unpack_size, natives=natives
    )


def FilterStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    lzma_filter: Mapping[str, int],
    unpack_size: int,
    seekable: bool = False,
    collector: DiagnosticCollector | None = None,
    owns_inner: bool = False,
    natives: Natives = IN_PROCESS,
    excluded: frozenset[OptionalLibrary],
) -> DecompressorStream:
    """Apply a filter-only stage — BCJ branch filter or Delta (forward-only).

    ``lzma_filter`` is a liblzma filter dict. The ARM64 and RISC-V filters, which
    Python's ``lzma`` refuses, run in archivey-codecs or in Python
    (:class:`BranchFilterDecoder`); ``excluded`` is the call's excluded libraries,
    which can turn ``OptionalLibrary.ARCHIVEY_CODECS`` off.

    ``owns_inner`` is True when this filter wraps a private previous stage
    (later 7z BCJ stages, including the LZMA1 cap slice). First-stage
    BCJ (Copy+BCJ, BCJ-alone) leaves the default so the pack view is borrowed.
    """
    del collector  # accepted for call-site uniformity; BCJ emits no diagnostics today
    return DecompressorStream(
        path,
        make_decoder=lambda _p, _i: _filter_decoder(
            lzma_filter, unpack_size, natives, excluded
        ),
        codec_name="filter",
        seekable=seekable,
        owns_inner=owns_inner,
    )
