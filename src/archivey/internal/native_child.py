"""archivey-codecs' decoding kernels in a decoder child, for ``NATIVE_DECODERS``.

``ProcessIsolation.NATIVE_DECODERS`` promises that no native decoder runs in this
process, so under it the decoding kernels (ARM64, RISC-V, LZW, LZO1X, LZX) run in
archivey's decoder child, as zlib and lzma do (openspec change ``rust-codecs-package``,
question 13). :func:`open_kernels` gives a stand-in for the ``archivey_codecs`` module
whose kernel objects each live in a child of their own (``decoder_worker._Codecs``):
the wrappers in :mod:`archivey.internal.native` use it as they use the module, so the
bytes and errors are the same as in-process. The package is never imported here.

A panic in the child comes back as :class:`ChildPanic`, which
:func:`archivey.internal.native.is_panic` counts as a panic, so it reaches the caller
as ``CorruptionError`` as in-process. When no child can start, or the child cannot
import the package, :func:`open_kernels` returns ``None`` and the call site uses its
Python twin in this process: Python is not native, so the promise holds, and the read
gives the same bytes as without the package.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, cast

from archivey.internal import logs
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.decoder_child import (
    DecoderChild,
    DecoderChildImportError,
    DecoderChildStartError,
    decoder_child_unavailable_reason,
    isolation_error,
)
from archivey.internal.streams.codecs.isolated import _ChildProxy
from archivey.types import OptionalLibrary

# The decoder worker's name for archivey-codecs (``decoder_worker.LOADERS``).
_CODEC = "archivey_codecs"


class ChildPanic(Exception):
    """A Rust panic in a kernel in the decoder child (``decoder_worker.KernelPanic``)."""


class ChildCodecError(ValueError):
    """Stand-in for ``archivey_codecs.CodecError`` raised in the decoder child."""


class ChildCorruptDataError(ChildCodecError):
    """Stand-in for ``archivey_codecs.CorruptDataError``."""


class ChildTruncatedDataError(ChildCodecError):
    """Stand-in for ``archivey_codecs.TruncatedDataError``."""


class ChildUnsupportedDataError(ChildCodecError):
    """Stand-in for ``archivey_codecs.UnsupportedDataError``."""


_ERRORS: dict[tuple[str, str], type[Exception]] = {
    # ``_codecs`` is the ``__module__`` PyO3 gives the exceptions the extension module
    # creates (``create_exception!(_codecs, ...)`` in lib.rs), not the package's name;
    # ``test_the_packages_errors_have_the_module_the_child_matches`` checks it.
    ("_codecs", "CodecError"): ChildCodecError,
    ("_codecs", "CorruptDataError"): ChildCorruptDataError,
    ("_codecs", "TruncatedDataError"): ChildTruncatedDataError,
    ("_codecs", "UnsupportedDataError"): ChildUnsupportedDataError,
    # The worker runs as ``__main__``, so the module is not matched.
    ("*", "KernelPanic"): ChildPanic,
}


def _start() -> DecoderChild:
    """A decoder child holding archivey-codecs, or ``ResourceUnavailableError`` when
    none can start: one started already (:func:`open_kernels`), so a later one failing
    is an environment fault, reported as for the other decoders."""
    reason = decoder_child_unavailable_reason(_CODEC)
    if reason is not None:
        raise isolation_error(reason)
    try:
        return DecoderChild(_CODEC, known=_ERRORS)
    except DecoderChildStartError as exc:
        raise isolation_error(str(exc)) from exc


class _KernelProxy(_ChildProxy):
    """A kernel object in a child. The attributes the child reports with each reply
    (``decoder_worker._Codecs.report``) come with an ``OK`` reply only, so a call
    that raised asks for them again: a wrapper may read some after an error."""

    def _call(self, method: str, data: bytes | None, *args: object) -> bytes:
        try:
            return self._child.call(method, data, args)
        except Exception:
            try:
                self._child.call("report", None)
            except Exception:  # noqa: BLE001, S110 - the call's own error is raised
                pass
            raise


class ChildBranchDecoder(_KernelProxy):
    """``filters.Arm64Decoder`` or ``RiscvDecoder`` in a child."""

    def decode(self, data: bytes) -> bytes:
        return self._call("decode", data)

    def flush(self) -> bytes:
        return self._call("flush", None)


class ChildLzwDecompressor(_KernelProxy):
    """``lzw.Decompressor`` in a child."""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        return self._call("decompress", data, max_length)

    def flush(self, max_length: int = -1) -> bytes:
        return self._call("flush", None, max_length)

    @property
    def eof(self) -> bool:
        return self._child.flag("eof")

    @property
    def needs_input(self) -> bool:
        return self._child.flag("needs_input")

    @property
    def truncation(self) -> str | None:
        return cast("Any", self._child.reported("truncation"))

    @property
    def header_params(self) -> tuple[int, bool] | None:
        return cast("Any", self._child.reported("header_params"))

    @property
    def nine_bit_widens(self) -> bool | None:
        return cast("Any", self._child.reported("nine_bit_widens"))

    @property
    def clear_offsets(self) -> list[tuple[int, int]]:
        return cast("Any", self._child.reported("clear_offsets"))


class ChildLzxDecompressor(_KernelProxy):
    """``lzx.Decompressor`` in a child."""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        return self._call("decompress", data, max_length)

    def flush(self, max_length: int = -1) -> bytes:
        return self._call("flush", None, max_length)

    @property
    def eof(self) -> bool:
        return self._child.flag("eof")


class _ChildLzx:
    """``lzx.Decompressor`` the class: built with ``(window_bits, output_size=)``."""

    def __init__(self, kernels: ChildCodecs) -> None:
        self._kernels = kernels

    def __call__(
        self, window_bits: int, *, output_size: int | None = None
    ) -> ChildLzxDecompressor:
        child = self._kernels.build(
            "lzx.Decompressor", window_bits, output_size=output_size
        )
        return ChildLzxDecompressor(child)


class ChildCodecs:
    """The parts of ``archivey_codecs`` that :mod:`archivey.internal.native` uses, with
    each kernel object in a decoder child of its own, taken from the pool."""

    CodecError = ChildCodecError
    CorruptDataError = ChildCorruptDataError
    TruncatedDataError = ChildTruncatedDataError
    UnsupportedDataError = ChildUnsupportedDataError

    def __init__(self, kernels: Mapping[str, int]) -> None:
        self.KERNELS = kernels
        self.filters = SimpleNamespace(
            Arm64Decoder=lambda start: ChildBranchDecoder(
                self.build("filters.Arm64Decoder", start)
            ),
            RiscvDecoder=lambda start: ChildBranchDecoder(
                self.build("filters.RiscvDecoder", start)
            ),
        )
        self.lzw = SimpleNamespace(
            Decompressor=lambda **kwargs: ChildLzwDecompressor(
                self.build("lzw.Decompressor", **kwargs)
            )
        )
        self.lzx = SimpleNamespace(Decompressor=_ChildLzx(self))
        self.lzo1x = SimpleNamespace(decompress=self._lzo1x)

    def build(self, name: str, *args: object, **kwargs: object) -> DecoderChild:
        """A child holding the kernel object ``name`` built from the arguments."""
        child = _start()
        try:
            child.call("build", None, (name, list(args), kwargs))
        except BaseException:
            child.close()
            raise
        return child

    def _lzo1x(self, block: bytes, *, max_size: int) -> bytes:
        child = _start()
        try:
            return child.call("lzo1x", block, (max_size,))
        finally:
            child.close()


# The child's ``KERNELS`` once read: every child imports the same installed package.
_table: list[dict[str, int]] = []


def open_kernels(excluded: frozenset[OptionalLibrary]) -> ChildCodecs | None:
    """archivey-codecs in decoder children, or ``None`` when the call's policy turns it
    off (``excluded``), it is not installed, or no child can start or import it.

    A failure is remembered for the rest of the process, whatever its cause (no
    interpreter, a refused start, an import that fails in the child): without that,
    every stream built would start a child only to see it fail, one per CAB folder or
    SquashFS block. An import failure is recorded on ``deps.archivey_codecs`` and logged
    once at WARNING, as for compress-utils; the others once at DEBUG."""
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    if not deps.archivey_codecs.available():
        return None
    if not _table:
        if _failed or deps.archivey_codecs.child_import_failed:
            return None
        table = _read_table()
        if table is None:
            return None
        _table.append(table)
    return ChildCodecs(_table[0])


def _read_table() -> dict[str, int] | None:
    """``KERNELS`` as a child reads it, or ``None`` when no child can run the package.
    The child goes back to the pool, so the first kernel object takes it."""
    reason = decoder_child_unavailable_reason(_CODEC)
    if reason is not None:
        _no_child(reason)
        return None
    try:
        child = DecoderChild(_CODEC, known=_ERRORS)
    except DecoderChildImportError as exc:
        _failed.append(str(exc))
        deps.archivey_codecs.failed_in_child(exc)
        return None
    except DecoderChildStartError as exc:
        _no_child(str(exc))
        return None
    try:
        child.call("kernels", None)
        table = child.result
    except Exception as exc:  # noqa: BLE001 - any failure here means no usable child
        _no_child(str(exc))
        return None
    finally:
        child.close()
    if not isinstance(table, dict):
        _no_child(f"the decoder process reported KERNELS as {table!r}")
        return None
    return cast("dict[str, int]", table)


# Why no child could run archivey-codecs, once one failed (see :func:`open_kernels`).
_failed: list[str] = []


def _no_child(reason: str) -> None:
    _failed.append(reason)
    logs.streams.debug(
        "archivey-codecs cannot run in a decoder process (%s), so archivey uses its "
        "Python decoders",
        reason,
    )
