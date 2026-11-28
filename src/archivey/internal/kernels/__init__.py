"""archivey's decoding kernels, each with one API whichever decoder runs.

archivey-speedups (the optional Rust package) has fast versions of some of archivey's
Python decoders. Each kernel here is one ``archivey_speedups`` module: a call site asks
for it with the call's excluded libraries and isolation, and gets a namespace with that
module's classes and functions. They are the package's when it is installed, current
and allowed (:mod:`~archivey.internal.kernels._select`), wrapped to raise archivey's
errors (:mod:`~archivey.internal.kernels.rust`), and otherwise the Python twins
(:mod:`~archivey.internal.kernels.python`), which have the same API. The two give the
same bytes and raise the same errors (the package's parity tests compare them), so a
call site does not know which runs: the choice changes speed only. ``library`` is
archivey-speedups when the package decodes, else ``None``, for a call site that records
its backend (LZO does).

Under ``ProcessIsolation.NATIVE_DECODERS`` (``isolated``) a decoding kernel runs in a
decoder child, or as its Python twin when no child can run it; BCJ2 is not run there
yet, so its twin decodes. CRC-16/ARC and ZipCrypto run in this process under every
setting, as checksums and AES do.

Design: openspec change ``rust-codecs-package``, D4 and D5.
"""

from __future__ import annotations

import functools
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, get_args

from archivey.internal.kernels._select import (
    caused_by_panic,
    decoding_kernels,
    is_panic,
    kernels,
    panic_of,
)
from archivey.kernels import (
    BlockDecompress,
    Crc16,
    KernelName,
    LzwDecompressor,
    LzwFactory,
    LzxDecompressor,
    LzxFactory,
)
from archivey.types import OptionalLibrary

__all__ = [
    "AppleLz",
    "Bcj2",
    "Bcj2Decompressor",
    "Bcj2Factory",
    "BlockDecompress",
    "BranchDecoder",
    "BranchFactory",
    "Crc16",
    "Filters",
    "KernelLease",
    "Lzo1x",
    "Lzw",
    "LzwDecompressor",
    "LzwFactory",
    "Lzx",
    "LzxDecompressor",
    "LzxFactory",
    "Readable",
    "ZipCrypto",
    "ZipCryptoDecryptor",
    "ZipCryptoFactory",
    "bcj2",
    "caused_by_panic",
    "crc16_arc",
    "filters",
    "for_plugin",
    "is_panic",
    "lzfse",
    "lzo1x",
    "lzvn",
    "lzw",
    "lzx",
    "panic_of",
    "zipcrypto",
]

Buffer = bytes | bytearray | memoryview

_CODECS = OptionalLibrary.ARCHIVEY_SPEEDUPS


# ── The API ───────────────────────────────────────────────────────────────────────────


class Readable(Protocol):
    """An input stream of BCJ2: ``read(n)`` returns at most ``n`` bytes."""

    def read(self, n: int, /) -> Buffer: ...


class ZipCryptoDecryptor(Protocol):
    """``zipcrypto.Decryptor(password)``: the ZipCrypto key state."""

    def decrypt(self, data: Buffer, /) -> bytes: ...

    def copy(self) -> ZipCryptoDecryptor: ...

    @property
    def total_in(self) -> int: ...


class BranchDecoder(Protocol):
    """``filters.Arm64Decoder(start_offset=0)`` or ``RiscvDecoder``: one stream through
    a branch filter. :meth:`decode` returns the decoded prefix of everything fed so far,
    holding back the start of an instruction the chunk cut off (at most 3 bytes for
    ARM64, 7 for RISC-V); :meth:`flush` returns those bytes unchanged."""

    def decode(self, data: Buffer, /) -> bytes: ...

    def flush(self) -> bytes: ...

    @property
    def total_in(self) -> int: ...

    @property
    def total_out(self) -> int: ...


class Bcj2Decompressor(Protocol):
    """``bcj2.Decompressor(main, call, jump, rc, *, out_size)``: 7-Zip's BCJ2 over its
    four input streams, read with :meth:`read`."""

    def read(self, max_length: int = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def out_size(self) -> int: ...

    @property
    def decoded(self) -> int: ...

    @property
    def total_in(self) -> tuple[int, int, int, int]: ...

    @property
    def total_out(self) -> int: ...


# The constructors, with the package's signatures.


class ZipCryptoFactory(Protocol):
    def __call__(self, password: Buffer) -> ZipCryptoDecryptor: ...


class BranchFactory(Protocol):
    def __call__(self, start_offset: int = 0) -> BranchDecoder: ...


class Bcj2Factory(Protocol):
    def __call__(
        self,
        main: Readable,
        call: Readable,
        jump: Readable,
        rc: Readable,
        *,
        out_size: int,
    ) -> Bcj2Decompressor: ...


@dataclass(frozen=True, slots=True)
class ZipCrypto:
    """``archivey_speedups.zipcrypto``."""

    Decryptor: ZipCryptoFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Filters:
    """``archivey_speedups.filters``."""

    Arm64Decoder: BranchFactory
    RiscvDecoder: BranchFactory
    # Each filter is its own kernel, so each has its own ``library``.
    arm64_library: OptionalLibrary | None
    riscv_library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzo1x:
    """``archivey_speedups.lzo1x``."""

    decompress: BlockDecompress
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class AppleLz:
    """``archivey_speedups.lzfse`` or ``archivey_speedups.lzvn``: a one-shot
    ``decompress`` with ``lzo1x.decompress``'s shape."""

    decompress: BlockDecompress
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzw:
    """``archivey_speedups.lzw``."""

    Decompressor: LzwFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzx:
    """``archivey_speedups.lzx``."""

    Decompressor: LzxFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Bcj2:
    """``archivey_speedups.bcj2``."""

    Decompressor: Bcj2Factory
    library: OptionalLibrary | None


# ── The switch ────────────────────────────────────────────────────────────────────────


def _bind(cls: Callable[..., Any], module: object) -> Any:
    """``cls`` with the package module (or its stand-in) as its first argument. Its
    signature, for the reader and ``inspect``, is the rest of ``cls``'s: the
    namespace field's type gives it to the type checker."""
    return functools.partial(cls, module)


def crc16_arc(excluded: frozenset[OptionalLibrary]) -> Crc16:
    """``crc16_arc``: the package's when it is installed and ``excluded`` leaves it
    on, else the Python one. Both give the same value."""
    module = kernels("crc16_arc", excluded)
    if module is None:
        from archivey.internal.kernels import python

        return python.crc16_arc
    from archivey.internal.kernels import rust

    return rust.crc16_arc(module)


def zipcrypto(excluded: frozenset[OptionalLibrary]) -> ZipCrypto:
    """``zipcrypto``, in this process under every isolation setting."""
    module = kernels("zipcrypto", excluded)
    if module is None:
        from archivey.internal.kernels.python import zipcrypto as twin

        return ZipCrypto(Decryptor=twin.Decryptor, library=None)
    from archivey.internal.kernels import rust

    return ZipCrypto(Decryptor=_bind(rust.ZipCryptoDecryptor, module), library=_CODECS)


def filters(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Filters:
    """``filters`` (ARM64 and RISC-V). The two filters are separate kernels, so each
    is the package's or the twin as its own revision allows."""
    from archivey.internal.kernels import rust
    from archivey.internal.kernels.python import filters as twin

    arm64 = decoding_kernels("arm64", excluded, isolated=isolated)
    riscv = decoding_kernels("riscv", excluded, isolated=isolated)
    return Filters(
        Arm64Decoder=twin.Arm64Decoder
        if arm64 is None
        else _bind(rust.Arm64Decoder, arm64),
        RiscvDecoder=twin.RiscvDecoder
        if riscv is None
        else _bind(rust.RiscvDecoder, riscv),
        arm64_library=None if arm64 is None else _CODECS,
        riscv_library=None if riscv is None else _CODECS,
    )


def lzo1x(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzo1x:
    """``lzo1x``. Under ``isolated`` each block decodes in a decoder child. LZO's call
    site takes only the package from here: compress-utils comes between it and the
    Python decoder (design question 11), which the call site calls directly."""
    module = decoding_kernels("lzo1x", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzo1x as twin

        return Lzo1x(decompress=twin.decompress, library=None)
    from archivey.internal.kernels import rust

    return Lzo1x(decompress=rust.lzo1x_decompress(module), library=_CODECS)


def lzw(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzw:
    """``lzw`` (Unix ``compress``)."""
    module = decoding_kernels("lzw", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzw as twin

        return Lzw(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Lzw(Decompressor=_bind(rust.LzwDecompressor, module), library=_CODECS)


def lzx(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzx:
    """``lzx`` (CAB's LZX)."""
    module = decoding_kernels("lzx", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzx as twin

        return Lzx(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Lzx(Decompressor=_bind(rust.LzxDecompressor, module), library=_CODECS)


def bcj2(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Bcj2:
    """``bcj2`` (7-Zip's four-stream x86 filter). Under ``isolated`` the twin
    decodes, until the decoder child can carry BCJ2's four inputs."""
    module = None if isolated else kernels("bcj2", excluded)
    if module is None:
        from archivey.internal.kernels.python import bcj2 as twin

        return Bcj2(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Bcj2(Decompressor=_bind(rust.Bcj2Decompressor, module), library=_CODECS)


def lzfse(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> AppleLz:
    """``lzfse`` (Apple's LZFSE, in DMG runs). Under ``isolated`` each stream decodes
    in a decoder child."""
    return _apple_lz("lzfse", excluded, isolated=isolated)


def lzvn(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> AppleLz:
    """``lzvn`` (raw LZVN, in HFS+ compressed files). Under ``isolated`` each chunk
    decodes in a decoder child."""
    return _apple_lz("lzvn", excluded, isolated=isolated)


def _apple_lz(
    kernel: Literal["lzfse", "lzvn"],
    excluded: frozenset[OptionalLibrary],
    *,
    isolated: bool,
) -> AppleLz:
    module = decoding_kernels(kernel, excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import (
            lzfse as lzfse_twin,
            lzvn as lzvn_twin,
        )

        twin = lzfse_twin if kernel == "lzfse" else lzvn_twin
        return AppleLz(decompress=twin.decompress, library=None)
    from archivey.internal.kernels import rust

    return AppleLz(decompress=rust.apple_lz_decompress(module, kernel), library=_CODECS)


# ── The plugin helper ─────────────────────────────────────────────────────────────────


class KernelLease:
    """The kernel objects one plugin call site was handed (``ReaderContext.kernel``,
    ``CodecCall.kernel``), so that :meth:`release` gives back their decoder children
    when the reader or the stream closes, not when the collector frees them.

    It keeps weak references: an object the plugin drops is freed, and its child given
    back, as before. Only objects in a decoder child are kept.
    """

    __slots__ = ("__weakref__", "_made")

    def __init__(self) -> None:
        self._made: weakref.WeakSet[Any] = weakref.WeakSet()

    def track(self, factory: Callable[..., Any]) -> Callable[..., Any]:
        """``factory``, noting each object it makes that holds a decoder child."""

        @functools.wraps(factory)
        def make(*args: Any, **kwargs: Any) -> Any:
            made = factory(*args, **kwargs)
            if getattr(type(made), "holds_decoder_child", False):
                self._made.add(made)
            return made

        return make

    def release(self) -> None:
        """Give back the decoder child of every object still alive."""
        for made in list(self._made):
            self._made.discard(made)
            made.close()


def for_plugin(
    name: KernelName,
    excluded: frozenset[OptionalLibrary],
    *,
    isolated: bool,
    lease: KernelLease,
) -> object | None:
    """The kernel ``name`` for a plugin, or ``None`` when its Python decoder must run:
    archivey-speedups is missing, too old for it, or excluded, or no decoder child can
    run it under ``isolated``. A usage error for a name that is not a
    :data:`~archivey.kernels.KernelName`."""
    if name == "crc16_arc":
        return crc16_arc(excluded) if kernels("crc16_arc", excluded) else None
    if name == "lzo1x":
        block = lzo1x(excluded, isolated=isolated)
        return None if block.library is None else block.decompress
    if name in ("lzfse", "lzvn"):
        apple = _apple_lz(name, excluded, isolated=isolated)
        return None if apple.library is None else apple.decompress
    if name == "lzw":
        stream: Lzw | Lzx = lzw(excluded, isolated=isolated)
    elif name == "lzx":
        stream = lzx(excluded, isolated=isolated)
    else:
        from archivey.exceptions import ArchiveyUsageError

        names = ", ".join(repr(n) for n in get_args(KernelName))
        raise ArchiveyUsageError(
            f"no kernel is named {name!r}; the kernels are {names}"
        )
    return None if stream.library is None else lease.track(stream.Decompressor)
