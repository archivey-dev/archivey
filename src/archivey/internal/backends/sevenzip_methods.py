"""7z coder method registry — single source for IDs, algorithms, and decode kind.

:class:`MethodKind` drives :func:`sevenzip_pipeline.plan_folder`:

- ``COPY`` / ``AES`` / ``BCJ2`` / ``SINGLE`` — self-explanatory stages
- ``LZMA_FAMILY`` — **not** "is LZMA": Delta and BCJ share this kind because they
  batch into the same liblzma staging run as LZMA1/2

BCJ entries carry both short and long on-disk method ids (``aliases``) — 7-Zip
has historically written either form. ARM64 (``0x0A``) and RISC-V (``0x0B``) have
only the short id, and are the branch filters Python's ``lzma`` will not build
(``in_liblzma_chain`` False): they are decoded in Python, always as their own stage.
"""

from __future__ import annotations

import lzma
from dataclasses import dataclass
from enum import Enum, auto

from archivey.exceptions import UnsupportedFeatureError
from archivey.internal.streams.codecs import Codec
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV
from archivey.types import CompressionAlgorithm


class MethodKind(Enum):
    """How :func:`sevenzip_pipeline.plan_folder` should stage this method.

    ``LZMA_FAMILY`` includes Delta/BCJ as well as LZMA1/2 — they compose into one
    staging run, not because they are LZMA codecs themselves.
    """

    COPY = auto()
    AES = auto()
    BCJ2 = auto()
    LZMA_FAMILY = auto()
    SINGLE = auto()


@dataclass(frozen=True, slots=True)
class SevenZipMethod:
    method_id: bytes
    algorithm: CompressionAlgorithm
    kind: MethodKind
    codec: Codec | None = None
    lzma_filter_id: int | None = None
    is_branch_filter: bool = False
    aliases: tuple[bytes, ...] = ()
    # False for a filter Python's lzma refuses: it never joins a liblzma chain.
    in_liblzma_chain: bool = True

    @property
    def is_filter(self) -> bool:
        """Delta or a branch filter (BCJ, ARM64, RISC-V). Like COPY, it outputs as many
        bytes as it reads."""
        return self.algorithm is CompressionAlgorithm.DELTA or self.is_branch_filter


def _bcj(
    short: bytes,
    long: bytes | None,
    codec: Codec,
    filter_id: int,
    *,
    in_liblzma_chain: bool = True,
) -> SevenZipMethod:
    return SevenZipMethod(
        short,
        CompressionAlgorithm.BCJ,
        MethodKind.LZMA_FAMILY,
        codec=codec,
        lzma_filter_id=filter_id,
        is_branch_filter=True,
        aliases=(long,) if long is not None else (),
        in_liblzma_chain=in_liblzma_chain,
    )


def _single(
    method_id: bytes, algo: CompressionAlgorithm, codec: Codec
) -> SevenZipMethod:
    return SevenZipMethod(method_id, algo, MethodKind.SINGLE, codec=codec)


_METHODS: tuple[SevenZipMethod, ...] = (
    SevenZipMethod(b"\x00", CompressionAlgorithm.STORED, MethodKind.COPY),
    SevenZipMethod(
        b"\x03\x01\x01",
        CompressionAlgorithm.LZMA,
        MethodKind.LZMA_FAMILY,
        codec=Codec.LZMA,
        lzma_filter_id=lzma.FILTER_LZMA1,
    ),
    SevenZipMethod(
        b"\x21",
        CompressionAlgorithm.LZMA2,
        MethodKind.LZMA_FAMILY,
        codec=Codec.LZMA2,
        lzma_filter_id=lzma.FILTER_LZMA2,
    ),
    SevenZipMethod(
        b"\x03",
        CompressionAlgorithm.DELTA,
        MethodKind.LZMA_FAMILY,
        codec=Codec.DELTA,
        lzma_filter_id=lzma.FILTER_DELTA,
    ),
    _bcj(b"\x04", b"\x03\x03\x01\x03", Codec.BCJ_X86, lzma.FILTER_X86),
    _bcj(b"\x05", b"\x03\x03\x02\x05", Codec.BCJ_PPC, lzma.FILTER_POWERPC),
    _bcj(b"\x06", b"\x03\x03\x04\x01", Codec.BCJ_IA64, lzma.FILTER_IA64),
    _bcj(b"\x07", b"\x03\x03\x05\x01", Codec.BCJ_ARM, lzma.FILTER_ARM),
    _bcj(b"\x08", b"\x03\x03\x07\x01", Codec.BCJ_ARMT, lzma.FILTER_ARMTHUMB),
    _bcj(b"\x09", b"\x03\x03\x08\x05", Codec.BCJ_SPARC, lzma.FILTER_SPARC),
    _bcj(b"\x0a", None, Codec.BCJ_ARM64, FILTER_ARM64, in_liblzma_chain=False),
    _bcj(b"\x0b", None, Codec.BCJ_RISCV, FILTER_RISCV, in_liblzma_chain=False),
    SevenZipMethod(b"\x03\x03\x01\x1b", CompressionAlgorithm.BCJ2, MethodKind.BCJ2),
    _single(b"\x04\x01\x08", CompressionAlgorithm.DEFLATE, Codec.DEFLATE),
    _single(b"\x04\x01\x09", CompressionAlgorithm.DEFLATE64, Codec.DEFLATE64),
    _single(b"\x04\x02\x02", CompressionAlgorithm.BZIP2, Codec.BZIP2),
    _single(b"\x04\xf7\x11\x01", CompressionAlgorithm.ZSTD, Codec.ZSTD),
    _single(b"\x04\xf7\x11\x02", CompressionAlgorithm.BROTLI, Codec.BROTLI),
    _single(b"\x04\xf7\x11\x04", CompressionAlgorithm.LZ4, Codec.LZ4),
    _single(b"\x03\x04\x01", CompressionAlgorithm.PPMD, Codec.PPMD),
    # Encryption, not a codec: UNKNOWN is deliberate, and folder listing skips AES
    # entries via is_aes before looking the algorithm up.
    SevenZipMethod(b"\x06\xf1\x07\x01", CompressionAlgorithm.UNKNOWN, MethodKind.AES),
)

METHOD_COPY = _METHODS[0]
METHOD_LZMA = _METHODS[1]
METHOD_LZMA2 = _METHODS[2]
METHOD_DELTA = _METHODS[3]
METHOD_AES = _METHODS[-1]

_BY_ID: dict[bytes, SevenZipMethod] = {}
for _entry in _METHODS:
    _BY_ID[_entry.method_id] = _entry
    for _alias in _entry.aliases:
        _BY_ID[_alias] = _entry


def lookup(method_id: bytes) -> SevenZipMethod | None:
    return _BY_ID.get(method_id)


def require(method_id: bytes) -> SevenZipMethod:
    method = lookup(method_id)
    if method is None:
        raise UnsupportedFeatureError(
            f"Unsupported 7z coder method {_method_hex(method_id)}"
        )
    return method


def is_bcj(method_id: bytes) -> bool:
    entry = lookup(method_id)
    return entry is not None and entry.is_branch_filter


def is_aes(method_id: bytes) -> bool:
    """True when ``method_id`` is 7z AES (primary id or any registered alias).

    Prefer this over ``lookup(...).kind is MethodKind.AES`` on listing hot paths:
    one id compare plus an empty-tuple check today, while still staying correct if
    AES ever gains aliases the way BCJ already does.
    """
    return method_id == METHOD_AES.method_id or method_id in METHOD_AES.aliases


def is_lzma_family(method_id: bytes) -> bool:
    entry = lookup(method_id)
    return entry is not None and entry.kind is MethodKind.LZMA_FAMILY


def _method_hex(method_id: bytes) -> str:
    return "0x" + method_id.hex()
