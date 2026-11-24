"""Child-process side of the isolated native decoders (``codecs/decoder_child.py``).

A native decoder can take the whole process down on hostile input, and no ``try`` can
catch that. ``ArchiveyConfig.process_isolation`` decides which decoders run in a child
process instead: pyppmd and rapidgzip by default, every native decoder under
``NATIVE_DECODERS``, archivey-codecs' decoding kernels included. The child runs this
file as a script (``python -P decoder_worker.py``), owns one decoder object at a time,
and answers one request at a time; the parent keeps all the decoding logic.

rapidgzip's child runs this file too (``python -P decoder_worker.py rapidgzip
[bzip2]``), which loads ``rapidgzip_worker.py`` by path and hands it this module, so
the two share the frame, the error payload and the helpers below. rapidgzip has its own
messages because it is a seekable stream that reads its source through the parent, not
a decompressor object.

This file imports nothing from ``archivey``: importing any ``archivey`` module imports
the whole package, which takes longer than decoding a small member. At the top it
imports only a few small standard-library modules (``tests/test_worker_scripts.py``
lists them), so the parent, which imports it for the constants, pays almost nothing;
each codec's library is imported inside its loader, so a child imports only the codec
it is asked for.

Protocol. Every frame in both directions is ``FRAME`` (tag, integer argument, payload
size), all little-endian, then the payload.

Parent to child:

- ``OPEN``: payload ``marshal.dumps((codec, args, kwargs))``. The child replies once
  after importing the codec's library and once after building the decoder with
  ``args`` and ``kwargs``. pyppmd's constructor allocates the model the archive
  declares and aborts the process rather than raise when it cannot, so a child that
  dies between the two replies died allocating.
- ``CALL``: argument the size of a ``marshal.dumps((method, args, kwargs, has_data))``
  header at the start of the payload; the rest of the payload is the input, passed as
  the first argument when ``has_data``.
- ``GET``: payload an attribute name; the reply's output is that attribute's bytes.
- ``CLOSE``: drop the decoder. No reply; the next message is an ``OPEN``.

Child to parent, one per request (two per ``OPEN``):

- ``OK``: argument the size of a ``marshal``ed state dict at the start of the payload,
  then the output bytes. The state holds ``eof``, ``needs_input``, brotli's
  ``is_finished`` and ``can_accept_more_data``, a ``result`` that is not bytes, and the
  lengths (not the bytes) of ``unused_data`` and ``unconsumed_tail``: both are the end
  of input the parent sent, so the parent rebuilds them from its copy. For
  archivey-codecs it also holds a ``report`` of the kernel's attributes
  (:class:`_Codecs`).
- ``ERR``: payload ``ERROR_SEPARATOR``-joined module, qualified type name, errno (or
  empty) and message, UTF-8. See :func:`error_payload`.

The parent closes stdin to end the child.
"""

from __future__ import annotations

import importlib
import marshal
import signal
import struct
import sys

# Not ``typing.TYPE_CHECKING``: importing ``typing`` takes about 6 ms, on every child start.
TYPE_CHECKING = False
if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import IO, Any

# The payload size is 64 bits: a held PPMd member goes to the child in one request,
# and ``max_ppmd_held_input=None`` puts no bound on it.
FRAME = struct.Struct("<BqQ")
# The range of FRAME's integer argument, its signed 64-bit ``q``.
ARG_MIN, ARG_MAX = -(1 << 63), (1 << 63) - 1

# Parent to child.
OPEN, CALL, GET, CLOSE = 1, 2, 3, 4
# Child to parent.
OK, ERR = 1, 2

ERROR_SEPARATOR = "\n"

# The command-line argument that runs rapidgzip's worker instead of this one.
RAPIDGZIP_ARG = "rapidgzip"


def read_exact_or_none(stream: IO[bytes], size: int) -> bytes | None:
    """``size`` bytes from ``stream``, or ``None`` if it ends first. Both ends of every
    child's pipes read frames with it."""
    parts: list[bytes] = []
    while size:
        chunk = stream.read(size)
        if not chunk:
            return None
        parts.append(chunk)
        size -= len(chunk)
    return b"".join(parts)


def error_payload(exc: BaseException) -> bytes:
    """The ``ERR`` payload for ``exc``: its type's module and qualified name, its
    ``errno`` (or empty) and its message, joined by ``ERROR_SEPARATOR``."""
    cls = type(exc)
    module, name = cls.__module__, cls.__qualname__
    message = str(exc)
    if isinstance(exc, UnicodeDecodeError) and isinstance(exc.object, bytes):
        # rapidgzip quotes an input byte in some messages ("... magic string 'BZh' ...
        # with \xf2 ..."). When that byte is not UTF-8, the message fails to decode on
        # its way to Python, and this error holds the message's bytes. The message is
        # the decoder's error, so it is reported as one, readable.
        module, name = "builtins", "RuntimeError"
        message = exc.object.decode("utf-8", "replace")
    errno = getattr(exc, "errno", None)
    fields = (module, name, "" if errno is None else str(errno), message)
    return ERROR_SEPARATOR.join(fields).encode("utf-8", "replace")


def parse_error_payload(payload: bytes) -> tuple[str, str, int | None, str]:
    """``(module, name, errno, message)`` from an ``ERR`` payload."""
    text = payload.decode("utf-8", "replace")
    module, _, rest = text.partition(ERROR_SEPARATOR)
    name, _, rest = rest.partition(ERROR_SEPARATOR)
    errno_text, _, message = rest.partition(ERROR_SEPARATOR)
    try:
        errno = int(errno_text) if errno_text else None
    except ValueError:
        errno = None
    return module, name, errno, message


def disable_core_dumps() -> None:
    """Ask the system not to write a core dump when this process crashes.

    A crash here is expected on corrupt or hostile input (the reason this process
    exists), so a core is useless, and it is large: about the size of the model or
    dictionary the archive declared, or, for rapidgzip, its whole address space of
    several GB. ``RLIMIT_CORE`` of 0 stops a core file but not a core piped to a crash
    handler (``core_pattern`` starting with ``|``: apport, systemd-coredump), which the
    kernel feeds whatever the limit while this process stays alive with its pipes open
    and the parent waits: measured, 2 to 4 s per rapidgzip abort with a handler that
    only drains the pipe. Linux skips the dump entirely for a process that is not
    dumpable.

    Best effort: anything missing (no ``resource`` on Windows, a Python built without
    ``ctypes``, no ``prctl``) is skipped.
    """
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            pr_set_dumpable = 4
            ctypes.CDLL(None).prctl(pr_set_dumpable, 0, 0, 0, 0)
        except (ImportError, OSError, AttributeError):
            pass


def prepare_child() -> None:
    """What every worker does first: no core dumps, and no reaction to Ctrl-C.

    A terminal's Ctrl-C signals the whole foreground process group, this child too.
    The parent decides what an interrupt means.
    """
    disable_core_dumps()
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# Codec loaders: each imports its library and returns the constructor ``OPEN`` calls.
# The imports stay inside the functions so a child imports only its own codec. The
# optional libraries go through ``import_module``: several have no type stubs.


def _load_zlib() -> Callable[..., Any]:
    import zlib

    return zlib.decompressobj


def _load_bz2() -> Callable[..., Any]:
    import bz2

    return bz2.BZ2Decompressor


def _load_lzma() -> Callable[..., Any]:
    import lzma

    return lzma.LZMADecompressor


def _load_zstd() -> Callable[..., Any]:
    try:
        zstd = importlib.import_module("compression.zstd")  # 3.14+
    except ImportError:
        zstd = importlib.import_module("backports.zstd")
    return zstd.ZstdDecompressor


def _load_lz4_frame() -> Callable[..., Any]:
    return importlib.import_module("lz4.frame").LZ4FrameDecompressor


def _load_lz4_block() -> Callable[..., Any]:
    # A function, not an object: the "decoder" is the module, and CALL runs
    # ``decompress`` on it.
    block = importlib.import_module("lz4.block")
    return lambda: block


def compress_utils_has(module: Any, algorithm: str) -> bool:
    """Whether the compress-utils ``module`` decodes ``algorithm`` (``"lzo"``,
    ``"snappy"``). Each algorithm is a build option of compress-utils, and a build
    without one raises ``CompressError`` for every input, as it does for damaged data.
    ``is_available`` is in every version archivey accepts (0.12.1 and later)."""
    try:
        return bool(module.is_available(algorithm))
    except ValueError:  # "Unknown algorithm": a name this build does not know
        return False


class _Lzo:
    """compress-utils' LZO1X decoder: ``decompress`` is the module's, and
    :meth:`available` says whether this build has LZO1X at all."""

    def __init__(self, module: Any) -> None:
        self.decompress = module.decompress
        self._module = module

    def available(self, algorithm: str) -> bool:
        return compress_utils_has(self._module, algorithm)


def _load_lzo() -> Callable[..., Any]:
    module = importlib.import_module("compress_utils")
    return lambda: _Lzo(module)


def _load_brotli() -> Callable[..., Any]:
    return importlib.import_module("brotli").Decompressor


def _load_inflate64() -> Callable[..., Any]:
    return importlib.import_module("inflate64").Inflater


def _load_bzip3() -> Callable[..., Any]:
    return importlib.import_module("bz3.backends").BZ3Decompressor


class _Snappy:
    """Snappy's native raw-block decoder and CRC-32C, for the parent's framing
    (``snappy_framed``). ``decoders`` and ``crcs`` list the packages the parent allows,
    in its order of preference; each is used only if it imports here, and google-crc32c
    only with its C extension. :meth:`chosen` says which were found."""

    def __init__(self, decoders: list[str], crcs: list[str]) -> None:
        self._decoder = ""
        self._module: Any = None
        # Packages that import here but were built without Snappy.
        self._without: list[str] = []
        for name in decoders:
            try:
                module = importlib.import_module(name)
            except ImportError:
                continue
            if name == "compress_utils" and not compress_utils_has(module, "snappy"):
                self._without.append(name)
                continue
            self._module = module
            self._decoder = name
            break
        self._crc = ""
        self._crc32c: Callable[[bytes], int] | None = None
        for name in crcs:
            try:
                module = importlib.import_module(name)
            except ImportError:
                continue
            if name == "google_crc32c":
                if getattr(module, "implementation", None) != "c":
                    continue
                self._crc32c = module.value
            else:
                self._crc32c = module.crc32c
            self._crc = name
            break

    def chosen(self) -> tuple[str, str, list[str]]:
        """The raw-block decoder and the CRC package in use, ``""`` for none, and the
        decoders skipped because their build has no Snappy."""
        return self._decoder, self._crc, self._without

    def chunk(self, body: bytes, size: int) -> bytes:
        """One data chunk's work, so its bytes cross the pipe once each way: with
        ``size`` >= 0, ``body`` is a raw block declaring ``size`` bytes, decoded here;
        with ``size`` -1, ``body`` is the data itself and only its CRC is computed. The
        reply is the decoded data (none for ``size`` -1), then, when a CRC package is
        in use, the CRC-32C of the data as 4 little-endian bytes."""
        if size >= 0:
            if self._decoder == "compress_utils":
                # expected_size is an upper bound, already checked by the parent.
                algorithm = self._module.Algorithm.snappy
                data = self._module.decompress(body, algorithm, expected_size=size)
            else:
                data = bytes(self._module.snappy.decompress_raw(body))
            out = data
        else:
            data, out = body, b""
        if self._crc32c is None:
            return out
        return out + self._crc32c(data).to_bytes(4, "little")


def _load_snappy() -> Callable[..., Any]:
    # The packages are imported by the constructor, each only if the parent allows it.
    return _Snappy


def _load_ppmd7() -> Callable[..., Any]:
    return importlib.import_module("pyppmd").Ppmd7Decoder


def _load_ppmd8() -> Callable[..., Any]:
    return importlib.import_module("pyppmd").Ppmd8Decoder


class KernelPanic(Exception):
    """A Rust panic in an archivey-codecs kernel. PyO3 raises ``PanicException``, a
    ``BaseException`` that ``_serve`` would not report, so :class:`_Codecs` raises this
    instead, and the parent rebuilds it as a panic (``kernels.child.ChildPanic``)."""


def _kernel_call(function: Callable[..., Any], args: Any, kwargs: Any) -> Any:
    try:
        return function(*args, **kwargs)
    except Exception:
        raise
    except BaseException as exc:
        if type(exc).__name__ == "PanicException":
            raise KernelPanic(str(exc)) from None
        raise


class _Codecs:
    """archivey-codecs' decoding kernels, one kernel object at a time.

    ``build`` makes the object from its dotted name in the package (such as
    ``"lzw.Decompressor"`` or ``"lzx.Decompressor"``); every other ``CALL``
    runs that object's method of the same name. :meth:`report` goes with each reply
    (``_state``): the attributes the parent's wrappers read after each call, so that
    reading one costs no round trip.
    """

    # The kernel attributes reported with each reply, where the kernel has them.
    REPORTED = (
        "truncation",
        "header_params",
        "nine_bit_widens",
        "clear_offsets",
        "output_size",
        "total_in",
        "total_out",
    )

    def __init__(self, module: Any) -> None:
        self._module = module
        self._kernel: Any = None

    def kernels(self) -> dict[str, int]:
        """The package's ``KERNELS`` table."""
        return dict(self._module.KERNELS)

    def build(self, name: str, args: list[Any], kwargs: dict[str, Any]) -> None:
        self._kernel = None
        target = self._module
        for part in name.split("."):
            target = getattr(target, part)
        self._kernel = _kernel_call(target, args, kwargs)

    def lzo1x(self, block: bytes, out_size: int | None, max_size: int | None) -> bytes:
        """One LZO1X block: the package's ``lzo1x.decompress``."""
        return self._one_shot("lzo1x", block, out_size, max_size)

    def lzfse(self, data: bytes, out_size: int | None, max_size: int | None) -> bytes:
        """One LZFSE stream: the package's ``lzfse.decompress``."""
        return self._one_shot("lzfse", data, out_size, max_size)

    def lzvn(self, data: bytes, out_size: int | None, max_size: int | None) -> bytes:
        """Raw LZVN: the package's ``lzvn.decompress``."""
        return self._one_shot("lzvn", data, out_size, max_size)

    def _one_shot(
        self, kernel: str, data: bytes, out_size: int | None, max_size: int | None
    ) -> bytes:
        """``kernel.decompress(data, ...)``, given ``out_size`` or ``max_size``."""
        decompress = getattr(self._module, kernel).decompress
        sizes = {"out_size": out_size, "max_size": max_size}
        given = {name: size for name, size in sizes.items() if size is not None}
        return _kernel_call(decompress, (data,), given)

    def report(self) -> dict[str, object]:
        report: dict[str, object] = {}
        for name in self.REPORTED:
            value = getattr(self._kernel, name, _MISSING)
            if value is not _MISSING:
                report[name] = value
        return report

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        value = getattr(self._kernel, name)
        if not callable(value):
            return value
        return lambda *args, **kwargs: _kernel_call(value, args, kwargs)


_MISSING = object()


def _load_archivey_codecs() -> Callable[..., Any]:
    module = importlib.import_module("archivey_codecs")
    return lambda: _Codecs(module)


LOADERS: dict[str, Callable[[], Callable[..., Any]]] = {
    "zlib": _load_zlib,
    "bz2": _load_bz2,
    "lzma": _load_lzma,
    "zstd": _load_zstd,
    "lz4.frame": _load_lz4_frame,
    "lz4.block": _load_lz4_block,
    "brotli": _load_brotli,
    "lzo": _load_lzo,
    "inflate64": _load_inflate64,
    "bzip3": _load_bzip3,
    "snappy": _load_snappy,
    "ppmd7": _load_ppmd7,
    "ppmd8": _load_ppmd8,
    "archivey_codecs": _load_archivey_codecs,
}

# Codecs whose decoder's ``unused_data`` is not part of the state, because reading it
# changes it: pyppmd builds that value once, on its first read after ``eof``, and keeps
# it, so read at an early ``eof`` it would go stale. The parent asks with ``GET``.
_ASK_FOR_UNUSED = frozenset({"ppmd7", "ppmd8"})
# What an ``OK`` reply's state reports, by kind: boolean attributes, input suffixes
# (sent as their length; see the module docstring), and brotli's boolean methods.
_FLAGS = ("eof", "needs_input")
_SUFFIXES = ("unused_data", "unconsumed_tail")
_PREDICATES = ("is_finished", "can_accept_more_data")


def _state(codec: str, decoder: object, result: object) -> dict[str, object]:
    """The state dict of an ``OK`` reply: what the parent's proxy needs to answer
    ``eof`` and the rest without a round trip, plus a ``result`` that is not bytes."""
    state: dict[str, object] = {}
    for name in _FLAGS:
        value = getattr(decoder, name, None)
        # An int too: under PyPy 3.11.17, backports.zstd's ``eof`` (a C ``bool``
        # member) reads ``False`` before a frame ends and the int 1 after it.
        if isinstance(value, int):
            state[name] = bool(value)
    if codec not in _ASK_FOR_UNUSED:
        for name in _SUFFIXES:
            value = getattr(decoder, name, False)
            if isinstance(value, bytes):
                state[name] = len(value)
            elif value is None:  # lz4.frame keeps None until it has some
                state[name] = None
    for name in _PREDICATES:
        method = getattr(decoder, name, None)
        if callable(method):
            state[name] = bool(method())
    if result is not None and not isinstance(result, bytes):
        state["result"] = result
    if isinstance(decoder, _Codecs):
        state["report"] = decoder.report()
    return state


def _send(out: IO[bytes], tag: int, arg: int = 0, payload: bytes = b"") -> None:
    out.write(FRAME.pack(tag, arg, len(payload)))
    if payload:
        out.write(payload)
    out.flush()


def _reply(out: IO[bytes], codec: str, decoder: object, result: object = None) -> None:
    state = marshal.dumps(_state(codec, decoder, result))
    output = result if isinstance(result, bytes) else b""
    out.write(FRAME.pack(OK, len(state), len(state) + len(output)))
    out.write(state)
    if output:
        out.write(output)
    out.flush()


def _serve(stdin: IO[bytes], stdout: IO[bytes]) -> None:
    """Answer the parent's requests until it closes stdin (protocol in the module
    docstring). Every exception goes back to the parent as an ``ERR`` reply."""
    codec = ""
    decoder: object = None
    while True:
        header = read_exact_or_none(stdin, FRAME.size)
        if header is None:
            return
        tag, arg, size = FRAME.unpack(header)
        payload = read_exact_or_none(stdin, size) if size else b""
        if payload is None:
            return
        try:
            if tag == OPEN:
                decoder = None
                codec, args, kwargs = marshal.loads(payload)
                build = LOADERS[codec]()
                _reply(stdout, codec, None)
                decoder = build(*args, **kwargs)
                _reply(stdout, codec, decoder)
            elif tag == CALL:
                method, args, kwargs, has_data = marshal.loads(payload[:arg])
                function = getattr(decoder, method)
                if has_data:
                    result = function(payload[arg:], *args, **kwargs)
                else:
                    result = function(*args, **kwargs)
                _reply(stdout, codec, decoder, result)
            elif tag == GET:
                value = getattr(decoder, payload.decode("ascii"), b"")
                _reply(stdout, codec, decoder, bytes(value or b""))
            elif tag == CLOSE:
                codec, decoder = "", None
            else:
                raise ValueError(f"bad tag {tag}")
        except Exception as exc:  # noqa: BLE001 - reported to the parent, which raises
            _send(stdout, ERR, 0, error_payload(exc))


def main() -> None:
    import os

    rapidgzip = sys.argv[1:2] == [RAPIDGZIP_ARG]
    refs = None
    if rapidgzip and sys.platform.startswith("linux"):
        # For ``rapidgzip_worker._reset_peak``. Opened before ``prepare_child``, which
        # makes this process not dumpable: ``/proc/self`` files then belong to root,
        # and a worker that is not root can no longer open this one (measured:
        # EACCES). A descriptor opened before still writes.
        try:
            refs = os.open("/proc/self/clear_refs", os.O_WRONLY | os.O_CLOEXEC)
        except OSError:
            pass
    prepare_child()
    if rapidgzip:
        # Loaded by path: this script's directory is not on sys.path (-P), and
        # importing it through ``archivey`` would import the whole package.
        import importlib.util

        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "rapidgzip_worker.py"
        )
        spec = importlib.util.spec_from_file_location("rapidgzip_worker", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.run(sys.argv[2:], refs)
        return
    _serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
