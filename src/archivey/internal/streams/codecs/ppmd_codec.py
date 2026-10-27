"""PPMd (7z PPMd7 and ZIP PPMd8)."""

from __future__ import annotations

import struct
from typing import BinaryIO

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    UnsupportedFeatureError,
    exception_detail,
)
from archivey.internal.config import (
    StreamConfig,
    check_decoder_memory,
)
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
from archivey.types import MissingComponent

# 7-Zip's PPMd7 property bounds (``PPMD7_MIN_ORDER`` .. ``PPMD7_MAX_MEM_SIZE`` in
# C/Ppmd7.h). Its decoder refuses properties outside them as unsupported
# (``E_NOTIMPL`` in CPP/7zip/Compress/PpmdDecoder.cpp).
_PPMD7_MIN_ORDER = 2
_PPMD7_MAX_ORDER = 64
_PPMD7_MIN_MEM_SIZE = 1 << 11
_PPMD7_MAX_MEM_SIZE = 0xFFFFFFFF - 12 * 3


def parse_ppmd_var_h_properties(properties: bytes | None) -> tuple[int, int]:
    """Parse 7z PPMd var.H coder properties → ``(order, mem_size)``."""

    if properties is None:
        raise ValueError("PPMd requires coder properties (order + mem size)")
    if len(properties) == 5:
        order, mem = struct.unpack("<BL", properties)
    elif len(properties) == 7:
        order, mem, _, _ = struct.unpack("<BLBB", properties)
    else:
        raise ValueError(
            f"unsupported PPMd properties length {len(properties)} (expected 5 or 7)"
        )
    return int(order), int(mem)


def _check_ppmd7_properties(order: int, mem_size: int) -> None:
    """Refuse a PPMd7 order or memory size outside 7-Zip's bounds, as 7-Zip does."""
    if not _PPMD7_MIN_ORDER <= order <= _PPMD7_MAX_ORDER:
        raise UnsupportedFeatureError(
            f"7z PPMd order {order} is outside 7-Zip's range "
            f"{_PPMD7_MIN_ORDER}..{_PPMD7_MAX_ORDER}"
        )
    if not _PPMD7_MIN_MEM_SIZE <= mem_size <= _PPMD7_MAX_MEM_SIZE:
        raise UnsupportedFeatureError(
            f"7z PPMd memory size {mem_size} is outside 7-Zip's range "
            f"{_PPMD7_MIN_MEM_SIZE}..{_PPMD7_MAX_MEM_SIZE}"
        )


class PpmdCodec(StreamCodec):
    codec = Codec.PPMD
    requirement = MissingComponent(
        "pyppmd",
        "pip install archivey[recommended]",
        ("ppmd",),
        reason=deps.unused_reason("pyppmd"),
    )

    def _backend_present(self) -> bool:
        return deps.pyppmd.available()

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        # Every PPMd member decodes in a child unless NONE, so this process does not
        # import pyppmd then (it re-enables the GIL on a free-threaded build).
        if config.process_isolation is ProcessIsolation.NONE:
            present = deps.pyppmd.load() is not None
        else:
            present = deps.pyppmd.available()
        if not present:
            raise self._missing("PPMd streams")
        # ZIP method 98 supplies order/mem/restore directly (PPMd8). 7z supplies a
        # var.H properties blob (PPMd7). Prefer an explicit ``pack_size``; fall back to
        # the sized source length (``SlicingStream`` / path size) filled into
        # ``compressed_input_size`` by ``open_codec_stream``.
        pack_size = params.pack_size
        if pack_size is None:
            pack_size = config.compressed_input_size
        max_held_input = config.decoder_limits.max_ppmd_held_input
        if params.ppmd_order is not None:
            if params.ppmd_mem_size is None:
                raise ValueError("ZIP PPMd requires ppmd_order and ppmd_mem_size")
            check_decoder_memory(
                params.ppmd_mem_size,
                limits=config.decoder_limits,
                what="ZIP PPMd8 memory size",
                usage=config.usage,
            )
            return PpmdDecompressorStream(
                source,
                order=params.ppmd_order,
                mem_size=params.ppmd_mem_size,
                variant=8,
                restore_method=params.ppmd_restore_method,
                unpack_size=params.unpack_size,
                pack_size=pack_size,
                max_held_input=max_held_input,
                collector=config.collector,
                refuse_input_after_end=config.refuse_input_after_end,
                input_runs_on=params.input_runs_on,
                isolation=config.process_isolation,
            )
        if params.input_runs_on:
            raise ValueError("input_runs_on needs PPMd8: PPMd7 has no end mark")
        order, mem_size = parse_ppmd_var_h_properties(params.properties)
        check_decoder_memory(
            mem_size,
            limits=config.decoder_limits,
            what="7z PPMd var.H memory size",
            usage=config.usage,
        )
        # After the cap, so a declaration over it still names the cap.
        _check_ppmd7_properties(order, mem_size)
        return PpmdDecompressorStream(
            source,
            order=order,
            mem_size=mem_size,
            unpack_size=params.unpack_size,
            pack_size=pack_size,
            max_held_input=max_held_input,
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
            isolation=config.process_isolation,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        if (eof := self._eof_truncation(exc, "PPMd")) is not None:
            return eof
        if isinstance(exc, ValueError):
            return CorruptionError(
                f"Error reading PPMd stream: {exception_detail(exc)}"
            )
        pyppmd = deps.pyppmd.loaded()
        if pyppmd is not None and isinstance(exc, getattr(pyppmd, "PpmdError", ())):
            return CorruptionError(
                f"Error reading PPMd stream: {exception_detail(exc)}"
            )
        # A corrupt PPMd8 payload can surface as SystemError from the C extension.
        if isinstance(exc, SystemError):
            return CorruptionError(
                f"Error reading PPMd stream: {exception_detail(exc)}"
            )
        return None
