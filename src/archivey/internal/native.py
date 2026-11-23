"""archivey-codecs: Rust versions of decoders archivey also has in Python.

When the package is installed, a call site asks here for a kernel by its name in
``archivey_codecs.KERNELS`` and gets it, or ``None`` and uses its Python twin. The two
give the same bytes and raise the same errors (the package's parity tests compare them),
so the choice changes speed only. Design: openspec change ``rust-codecs-package``, D4
(revisions) and D5 (installing and turning it off).

A kernel is used when all of these hold:

- the call's ``FormatPolicy`` does not turn ``OptionalLibrary.ARCHIVEY_CODECS`` off
  (``exclude_libraries`` or ``only_libraries``), the one switch a caller sets for it;
- the package is installed and imports;
- its ``KERNELS`` revision for that kernel is at least :data:`MIN_REVISIONS`' (an older
  one may differ from this archivey's Python twin, so it is skipped, logged once at
  DEBUG);
- under ``ProcessIsolation.NATIVE_DECODERS``, which promises that no native decoder
  runs in this process, a decoding kernel (ARM64, RISC-V, LZW, LZO1X, LZX) runs in the
  decoder child (:mod:`archivey.internal.native_child`), and the Python twin decodes
  when no child can run it. BCJ2, LZFSE and LZVN are not run there yet, so their
  Python twins decode them. CRC-16/ARC and ZipCrypto run in this process under every
  setting, as checksums and AES do.

A missed check in a kernel panics, and PyO3 raises ``pyo3_runtime.PanicException``, a
``BaseException`` that passes ``except Exception``. :func:`panic_to_corruption` turns it
into archivey's ``CorruptionError`` with the panic as its cause.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Generator, Mapping
from types import ModuleType
from typing import BinaryIO, Protocol

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal import logs, native_child
from archivey.internal.native_child import ChildCodecs, ChildPanic
from archivey.internal.streams.codecs import deps
from archivey.types import OptionalLibrary

MIN_REVISIONS: dict[str, int] = {
    "arm64": 1,
    "bcj2": 1,
    "crc16_arc": 1,
    "lzfse": 1,
    "lzo1x": 1,
    "lzvn": 1,
    "lzw": 1,
    "lzx": 2,
    "riscv": 1,
    "zipcrypto": 1,
}
"""The oldest revision of each kernel this archivey uses: the one whose output and
errors match its Python twin. A kernel not named here is not used."""

# Kernels already logged as too old, so each is logged once per process.
_too_old_logged: set[str] = set()


Kernels = ModuleType | ChildCodecs
"""The ``archivey_codecs`` module, or its stand-in whose kernels run in a decoder
child."""


def kernels(name: str, excluded: frozenset[OptionalLibrary]) -> ModuleType | None:
    """The ``archivey_codecs`` module when its ``name`` kernel is to be used in this
    process for a call whose policy turns off ``excluded``, else ``None``."""
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    module = deps.archivey_codecs.load()
    if module is None or not _current(name, getattr(module, "KERNELS", None)):
        return None
    return module


def decoding_kernels(
    name: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Kernels | None:
    """:func:`kernels` for a decoding kernel. ``isolated``: the call's
    ``process_isolation`` is ``NATIVE_DECODERS``, and the module's stand-in that runs
    each kernel in a decoder child is returned instead
    (:func:`native_child.open_kernels`)."""
    if not isolated:
        return kernels(name, excluded)
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    module = native_child.open_kernels(excluded)
    if module is None or not _current(name, module.KERNELS):
        return None
    return module


def _current(name: str, table: Mapping[str, object] | None) -> bool:
    """Whether ``table`` (``KERNELS``) has a revision of ``name`` this archivey uses;
    an older one is logged once at DEBUG."""
    have = table.get(name) if table is not None else None
    need = MIN_REVISIONS[name]
    if isinstance(have, int) and have >= need:
        return True
    if name not in _too_old_logged:
        _too_old_logged.add(name)
        logs.streams.debug(
            "archivey-codecs has %r kernel revision %r; archivey needs %d or "
            "newer, so it uses its Python decoder for it",
            name,
            have,
            need,
        )
    return False


def is_panic(exc: BaseException) -> bool:
    """Whether ``exc`` is a Rust panic raised by PyO3, here or in a decoder child."""
    if isinstance(exc, ChildPanic):
        return True
    kind = type(exc)
    return kind.__name__ == "PanicException" and kind.__module__ == "pyo3_runtime"


def panic_of(exc: BaseException) -> BaseException | None:
    """The panic in ``exc``'s ``__cause__`` chain, or ``None``. A caller that raises a
    new error in place of ``exc`` raises it ``from panic_of(exc)``, so a kernel bug
    keeps its panic as the cause."""
    seen: set[int] = set()
    cause = exc.__cause__
    while cause is not None and id(cause) not in seen:
        if is_panic(cause):
            return cause
        seen.add(id(cause))
        cause = cause.__cause__
    return None


def caused_by_panic(exc: BaseException) -> bool:
    """Whether a panic is in ``exc``'s ``__cause__`` chain: the error is a kernel bug,
    never something the archive's data or a password could cause."""
    return panic_of(exc) is not None


@contextlib.contextmanager
def panic_to_corruption(kernel: str) -> Generator[None]:
    """Raise a panic in the block as ``CorruptionError``, the panic its cause."""
    try:
        yield
    except BaseException as exc:
        if is_panic(exc):
            raise CorruptionError(
                f"archivey-codecs' {kernel} decoder failed on this data: {exc}"
            ) from exc
        raise


@contextlib.contextmanager
def codec_errors(module: Kernels, kernel: str) -> Generator[None]:
    """Raise the package's errors as archivey's, with the same message, and a panic
    as ``CorruptionError``. The kernels raise with their Python twin's message, so the
    error a caller sees is the one the twin raises."""
    try:
        with panic_to_corruption(kernel):
            yield
    except module.TruncatedDataError as exc:
        raise TruncatedError(str(exc)) from None
    except module.CorruptDataError as exc:
        raise CorruptionError(str(exc)) from None
    except module.UnsupportedDataError as exc:
        raise UnsupportedFeatureError(str(exc)) from None


class Latch:
    """The panic a kernel object raised, so that the object refuses every later
    call: after a panic its state may be half updated, so nothing more is asked of
    it. Each wrapper of a stateful kernel object holds one."""

    __slots__ = ("_failure", "_kernel")

    def __init__(self, kernel: str) -> None:
        self._kernel = kernel
        self._failure: CorruptionError | None = None

    @contextlib.contextmanager
    def guard(self) -> Generator[None]:
        """Raise the stored failure, else run the block, storing a panic in it as
        the ``CorruptionError`` it raises."""
        if self._failure is not None:
            raise self._failure
        try:
            with panic_to_corruption(self._kernel):
                yield
        except CorruptionError as exc:
            if caused_by_panic(exc):
                self._failure = exc
            raise


def _close_kernel(kernel: object) -> None:
    """Give back the decoder child a kernel object holds, if it is one
    (``native_child``): what ``release_decoder`` asks of a wrapper below."""
    close = getattr(kernel, "close", None)
    if close is not None:
        close()


# ── CRC-16/ARC ────────────────────────────────────────────────────────────────────────


def crc16_arc(
    excluded: frozenset[OptionalLibrary],
) -> Callable[[bytes | bytearray | memoryview, int], int] | None:
    """The kernel's ``crc16_arc(data, crc)``, or ``None`` to use the Python one."""
    module = kernels("crc16_arc", excluded)
    if module is None:
        return None
    native = module.crc16_arc

    def crc16(data: bytes | bytearray | memoryview, crc: int = 0) -> int:
        with panic_to_corruption("CRC-16"):
            return native(data, crc)

    return crc16


# ── ZipCrypto ─────────────────────────────────────────────────────────────────────────


class CipherState(Protocol):
    """A ZipCrypto key state: Python's ``ZipCryptoKeys`` or :class:`NativeZipCrypto`."""

    def copy(self) -> CipherState: ...

    def decrypt(self, data: bytes) -> bytes: ...


class _Decryptor(Protocol):
    """``archivey_codecs.zipcrypto.Decryptor``."""

    def copy(self) -> _Decryptor: ...

    def decrypt(self, data: bytes) -> bytes: ...


class NativeZipCrypto:
    """archivey-codecs' ZipCrypto decryptor, in the shape of ``ZipCryptoKeys``."""

    __slots__ = ("_decryptor", "_latch")

    def __init__(self, decryptor: _Decryptor) -> None:
        self._decryptor = decryptor
        self._latch = Latch("ZipCrypto")

    def copy(self) -> NativeZipCrypto:
        with self._latch.guard():
            return NativeZipCrypto(self._decryptor.copy())

    def decrypt(self, data: bytes) -> bytes:
        with self._latch.guard():
            return self._decryptor.decrypt(data)


def zipcrypto(
    excluded: frozenset[OptionalLibrary],
) -> Callable[[bytes], NativeZipCrypto] | None:
    """A constructor of key states from a password, or ``None`` to use
    ``ZipCryptoKeys``."""
    module = kernels("zipcrypto", excluded)
    if module is None:
        return None
    decryptor = module.zipcrypto.Decryptor

    def new(password: bytes) -> NativeZipCrypto:
        with panic_to_corruption("ZipCrypto"):
            return NativeZipCrypto(decryptor(password))

    return new


# ── ARM64 and RISC-V branch filters ───────────────────────────────────────────────────


class Branch(Protocol):
    """One stream through a branch filter, as archivey's filter decoder drives it."""

    def decode(self, data: bytes) -> bytes:
        """Return the decoded prefix of everything fed so far. The last few bytes can
        be the start of an instruction that the end of the chunk cut off, so they are
        held back for the next call: at most 3 for ARM64, 7 for RISC-V."""
        ...

    def flush(self) -> bytes:
        """At the end of the input: the bytes held back, unchanged."""
        ...


class _BranchDecoder(Protocol):
    """``archivey_codecs.filters.Arm64Decoder`` or ``RiscvDecoder``."""

    def decode(self, data: bytes) -> bytes: ...

    def flush(self) -> bytes: ...


class NativeBranch:
    """archivey-codecs' ARM64 or RISC-V decoder, as a :class:`Branch`."""

    __slots__ = ("_decoder", "_latch")

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def __init__(self, decoder: _BranchDecoder, kernel: str) -> None:
        self._decoder = decoder
        self._latch = Latch(kernel)

    def decode(self, data: bytes) -> bytes:
        with self._latch.guard():
            return self._decoder.decode(data)

    def flush(self) -> bytes:
        with self._latch.guard():
            return self._decoder.flush()

    def close(self) -> None:
        _close_kernel(self._decoder)


_BRANCH_CLASSES = {
    "arm64": ("Arm64Decoder", "ARM64"),
    "riscv": ("RiscvDecoder", "RISC-V"),
}


def branch_filter(
    kernel: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[int], NativeBranch] | None:
    """A constructor of :class:`NativeBranch` from the filter's start offset, or
    ``None`` to use the Python filter. ``kernel`` is ``"arm64"`` or ``"riscv"``.

    ``isolated`` is ``ProcessIsolation.NATIVE_DECODERS``, which promises that no native
    decoder runs in this process: the kernel then runs in a decoder child, and the
    Python filter decodes when no child can run it (:mod:`native_child`).
    """
    module = decoding_kernels(kernel, excluded, isolated=isolated)
    if module is None:
        return None
    class_name, label = _BRANCH_CLASSES[kernel]
    decoder = getattr(module.filters, class_name)

    def new(start_offset: int) -> NativeBranch:
        with panic_to_corruption(label):
            return NativeBranch(decoder(start_offset), label)

    return new


# ── LZFSE and LZVN ────────────────────────────────────────────────────────────────────

_APPLE_LABELS = {"lzfse": "LZFSE", "lzvn": "LZVN"}


def apple_lz(
    kernel: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[bytes, int], bytes] | None:
    """The kernel's one-shot decoder with its Python twin's contract (``(data,
    max_length)``: at most ``max_length`` bytes, the twin's errors and messages), or
    ``None`` to use the twin. ``kernel`` is ``"lzfse"`` or ``"lzvn"``.

    ``isolated`` is ``ProcessIsolation.NATIVE_DECODERS``: until the decoder child can
    run these kernels, the Python decoder keeps that setting's promise.
    """
    if isolated:
        return None
    module = kernels(kernel, excluded)
    if module is None:
        return None
    decompress = getattr(module, kernel).decompress
    label = _APPLE_LABELS[kernel]

    def decode(data: bytes, max_length: int) -> bytes:
        with codec_errors(module, label):
            return decompress(data, max_size=max_length)

    return decode


# ── Unix compress (LZW) ───────────────────────────────────────────────────────────────


class _LzwDecompressor(Protocol):
    """``archivey_codecs.lzw.Decompressor``."""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...

    def flush(self, max_length: int = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def truncation(self) -> str | None: ...

    @property
    def header_params(self) -> tuple[int, bool] | None: ...

    @property
    def nine_bit_widens(self) -> bool | None: ...

    @property
    def clear_offsets(self) -> list[tuple[int, int]]: ...


# Bytes of a ``.Z`` header: the magic and the flags byte.
_LZW_HEADER = 3


class NativeLzw:
    """archivey-codecs' LZW decoder in the shape of the Python ``LzwState``: ``feed``
    and ``flush`` return ``(bytes, units)``, a unit being one CLEAR's segment
    ``(decompressed_size, compressed_size)`` from the CLEAR before it (or from just
    after the header).

    Errors keep the Python decoder's pattern: a bad code hands back the bytes decoded
    before it, and the error raises from the next call.
    """

    __slots__ = ("_at", "_d", "_finished", "_flushed", "_latch", "_module")

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def __init__(
        self, module: Kernels, decoder: _LzwDecompressor, *, header_in_stream: bool
    ) -> None:
        self._module = module
        self._d = decoder
        self._latch = Latch("LZW")
        self._finished = False
        self._flushed = False
        # The last CLEAR's (input, output) offset: the kernel counts the header in
        # the input when it reads one from the stream, and the units start after it.
        self._at = (_LZW_HEADER if header_in_stream else 0, 0)

    @property
    def header_params(self) -> tuple[int, bool] | None:
        return self._d.header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        return self._d.nine_bit_widens

    @property
    def truncated(self) -> bool:
        return self._d.truncation is not None

    @property
    def truncation(self) -> str | None:
        return self._d.truncation

    def _units(self) -> list[tuple[int, int]]:
        units = []
        comp, decomp = self._at
        for at_in, at_out in self._d.clear_offsets:
            units.append((at_out - decomp, at_in - comp))
            comp, decomp = at_in, at_out
        self._at = (comp, decomp)
        return units

    def _call(self, call: Callable[[], bytes]) -> tuple[bytes, list[tuple[int, int]]]:
        with self._latch.guard(), codec_errors(self._module, "LZW"):
            out = call()
            units = self._units()
        return out, units

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            return b"", []
        if self._flushed:
            # A flush() that raised: the kernel raises the same error again.
            return self._call(lambda: self._d.flush(max_length))
        return self._call(lambda: self._d.decompress(data, max_length))

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        # A bad code after the output returned here raises from the next call: the
        # kernel keeps the error and raises it again.
        self._flushed = True
        out, units = self._call(self._d.flush)
        self._finished = True
        return out, units

    def is_finished(self) -> bool:
        return self._finished

    @property
    def needs_input(self) -> bool:
        return self._finished or self._d.needs_input

    def close(self) -> None:
        _close_kernel(self._d)


def lzw(
    excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[..., NativeLzw] | None:
    """A constructor of :class:`NativeLzw` taking ``LzwState``'s keyword arguments,
    or ``None`` to use ``LzwState``. ``isolated`` as for :func:`branch_filter`."""
    module = decoding_kernels("lzw", excluded, isolated=isolated)
    if module is None:
        return None
    decompressor = module.lzw.Decompressor

    def new(
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> NativeLzw:
        with codec_errors(module, "LZW"):
            d = decompressor(
                max_width=max_width,
                block_mode=block_mode,
                nine_bit_widens=nine_bit_widens,
            )
        return NativeLzw(module, d, header_in_stream=max_width is None)

    return new


# ── LZX ───────────────────────────────────────────────────────────────────────────────


class NativeLzx:
    """archivey-codecs' LZX decoder in the shape of the Python ``LzxDecoder``:
    :meth:`decode_frame` returns the next frame, pulling input through ``more`` (the
    next data block, or ``None`` after the last) and pushing it into the kernel.

    The kernel keeps its place when its input runs out inside a frame, so it asks
    for the next block exactly where the Python decoder pulls it. ``more`` raises
    for a damaged block (its checksum fails), so its error comes from the same frame
    as there.
    """

    __slots__ = ("_d", "_decoded", "_ended", "_latch", "_module", "_more", "_sized")

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def __init__(
        self,
        module: Kernels,
        window_bits: int,
        more: Callable[[], bytes | None],
        output_size: int | None,
    ) -> None:
        self._module = module
        self._latch = Latch("LZX")
        with codec_errors(module, "LZX"):
            self._d = module.lzx.Decompressor(window_bits, output_size=output_size)
        self._more = more
        self._ended = False  # ``more`` returned ``None`` and the kernel was flushed
        self._sized = output_size is not None
        self._decoded = 0  # the frames returned, each one whole

    def decode_frame(self, frame_size: int) -> bytes:
        """The next frame: ``frame_size`` bytes, 32 KiB except the last, as the
        kernel's ``output_size`` sets them."""
        with self._latch.guard(), codec_errors(self._module, "LZX"):
            d = self._d
            if not self._sized:
                # Without an output size the kernel ends the stream where its input
                # does, at a frame boundary. The Python decoder decodes the frame it
                # is asked for from the zero padding instead (and fails on it), so
                # the kernel is told this frame is wanted.
                d.set_output_size(self._decoded + frame_size)
            while True:
                out = (
                    d.flush(frame_size)
                    if self._ended
                    else d.decompress(b"", frame_size)
                )
                if out:
                    self._decoded += len(out)
                    return out
                if self._ended or d.eof:
                    # The Python decoder's refusal of a frame past its input's end.
                    raise TruncatedError("LZX stream ends before its output")
                data = self._more()
                if data is None:
                    self._ended = True
                    continue
                out = d.decompress(data, frame_size)
                if out:
                    self._decoded += len(out)
                    return out

    def close(self) -> None:
        _close_kernel(self._d)


def lzx(
    excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[int, Callable[[], bytes | None], int | None], NativeLzx] | None:
    """A constructor of :class:`NativeLzx` taking ``(window_bits, more,
    output_size)``, or ``None`` to use the Python ``LzxDecoder``. ``isolated`` as
    for :func:`branch_filter`."""
    module = decoding_kernels("lzx", excluded, isolated=isolated)
    if module is None:
        return None

    def new(
        window_bits: int, more: Callable[[], bytes | None], output_size: int | None
    ) -> NativeLzx:
        return NativeLzx(module, window_bits, more, output_size)

    return new


# ── BCJ2 ──────────────────────────────────────────────────────────────────────────────


class NativeBcj2:
    """archivey-codecs' BCJ2 decoder over four input streams, for
    ``Bcj2DecoderStream``.

    The kernel returns the bytes decoded before an error and raises the error from
    its next call. The Python decoder decodes whole ``main`` blocks and raises an
    error from the read that decodes its block, keeping the bytes decoded before it
    for later reads. :meth:`read` therefore returns every byte decoded so far
    together with the error found on the way, for the caller to keep and raise.
    """

    __slots__ = ("_d", "_latch", "_module", "_size")

    def __init__(
        self,
        module: ModuleType,
        streams: tuple[BinaryIO, BinaryIO, BinaryIO, BinaryIO],
        out_size: int,
    ) -> None:
        self._module = module
        self._latch = Latch("BCJ2")
        self._size = out_size
        with codec_errors(module, "BCJ2"):
            self._d = module.bcj2.Decompressor(*streams, out_size=out_size)

    def read(self, n: int) -> tuple[bytes, Exception | None]:
        """At least ``n`` bytes unless the output ends or an error stops it, and the
        error a block decoded on the way found, if any.

        Past ``n`` come the rest of the bytes decoded: when the blocks decoded reach
        the end of the output (the Python decoder runs the end check as soon as it
        has decoded the last byte, the kernel only once it returns it), and when an
        error waits. An error waits when the read came back short, or returned the
        last byte without passing the end check, or decoded a block (its inputs
        moved) and ``getstate()`` refuses: it refuses only while an error waits, and
        otherwise copies at most one block's output, once a block."""
        with self._latch.guard(), codec_errors(self._module, "BCJ2"):
            d = self._d
            before = d.total_in
            out = d.read(n)
            if not d.eof and d.decoded == self._size and d.total_out < self._size:
                out += d.read(-1)
            if d.eof:
                return out, None
            waits = len(out) < n or d.total_out == self._size
            if not waits and d.total_in != before:
                try:
                    d.getstate()
                except ValueError:
                    waits = True
            if not waits:
                return out, None
        try:
            with self._latch.guard(), codec_errors(self._module, "BCJ2"):
                out += d.read(-1)  # the bytes before the error, if any are left
                d.read(1)  # raises the error that waits
        except Exception as exc:  # noqa: BLE001 - a stream's own error too
            return out, exc
        raise AssertionError("the BCJ2 kernel had no error waiting")


def bcj2(
    excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[tuple[BinaryIO, BinaryIO, BinaryIO, BinaryIO], int], NativeBcj2] | None:
    """A constructor of :class:`NativeBcj2` taking ``(streams, out_size)``, or
    ``None`` to use the Python decoder. ``isolated``: under ``NATIVE_DECODERS`` the
    Python decoder is used, until the decoder child can carry BCJ2's four inputs."""
    if isolated:
        return None
    module = kernels("bcj2", excluded)
    if module is None:
        return None

    def new(
        streams: tuple[BinaryIO, BinaryIO, BinaryIO, BinaryIO], out_size: int
    ) -> NativeBcj2:
        return NativeBcj2(module, streams, out_size)

    return new
