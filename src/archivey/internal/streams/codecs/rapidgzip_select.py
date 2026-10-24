"""rapidgzip for the DEFLATE family and bzip2: whether to use it, opening it in a child
process, translating its errors, and the wrappers that keep the standard library's seek and length
contract around it.
"""

from __future__ import annotations

import io
import os
import threading
from collections.abc import Callable
from typing import BinaryIO

from archivey.config import RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE, ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceUnavailableError,
    StreamNotSeekableError,
    TruncatedError,
    exception_detail,
)
from archivey.internal import logs
from archivey.internal.config import (
    AcceleratorMode,
    StreamConfig,
)
from archivey.internal.streams.archive_stream import RewindWarning
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    CodecParams,
    CodecSource,
)
from archivey.internal.streams.codecs.rapidgzip_child import (
    RapidgzipChildStartError,
    RapidgzipChildStream,
    from_callers_source,
    rapidgzip_child_unavailable_reason,
    reported_by_child,
)
from archivey.internal.streams.decompressor_stream import (
    _StreamChecksumError,
    truncated_message,
)
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    is_seekable,
    resolve_seek,
    source_byte_size,
)
from archivey.internal.streams.streamtools.slice import SlicingStream
from archivey.types import MissingComponent


# The DEFLATE-family codecs are stdlib-backed, so they declare no ``requirement`` — rapidgzip
# is an *accelerator* they only demand when random access was explicitly requested. It still
# needs one install hint, shared with the rewind diagnostic that suggests the same package.
def _rapidgzip_requirement() -> MissingComponent:
    """rapidgzip as a missing component, with the reason archivey does not use it on this
    interpreter (``deps.unused_reason``) read when the error is raised, not at import."""
    return MissingComponent(
        "rapidgzip",
        "pip install archivey[seekable]",
        ("random-access",),
        reason=deps.unused_reason("rapidgzip"),
    )


# The settings whose AUTO fallback has been logged (_warn_child_fallback).
_child_fallback_warned: set[str] = set()
_child_fallback_lock = threading.Lock()
# What each accelerator setting covers, for the fallback warning.
_CHILD_FALLBACK_STREAMS = {
    "use_rapidgzip": "gzip, zlib and deflate streams are",
    "use_indexed_bzip2": "bzip2 streams are",
}


def _warn_child_fallback(why: str, setting: str = "use_rapidgzip") -> None:
    """Log, once per process and setting, that ``AUTO`` reads with the stdlib because no
    rapidgzip child can start. It is a fact about the environment, not about any one
    archive, so one warning says it; ``ON`` raises instead and does not come here."""
    with _child_fallback_lock:
        if setting in _child_fallback_warned:
            return
        _child_fallback_warned.add(setting)
    logs.streams.warning(
        "%s; %s read with the standard library decoder instead of rapidgzip. Set "
        "%s=AcceleratorMode.OFF to silence this warning.",
        why,
        _CHILD_FALLBACK_STREAMS[setting],
        setting,
    )


def _rapidgzip_wanted(config: StreamConfig, *, available: bool) -> bool:
    """Resolve ``use_rapidgzip`` including the DEFLATE-family AUTO size gate, before
    asking whether a child process can run it.

    AUTO also requires truncation to be verifiable: a container-declared
    ``expected_decompressed_size``, or (gzip only) a readable ISIZE trailer flagged
    via ``gzip_isize_backstop``. Without one of those, AUTO falls back to the stdlib
    backend that raises ``TruncatedError``. ``ON`` ignores this — the caller asked for
    the accelerator explicitly. ``process_isolation=NONE`` never uses it: rapidgzip
    runs only in a child process.
    """
    if config.process_isolation is ProcessIsolation.NONE:
        return False
    if (
        config.use_rapidgzip is AcceleratorMode.AUTO
        and config.expected_decompressed_size is None
        and not config.gzip_isize_backstop
    ):
        return False
    return config.use_rapidgzip.enabled_for(
        seekable=config.seekable,
        available=available,
        input_size=config.compressed_input_size,
        min_size=RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE,
    )


def _auto_without_child(config: StreamConfig, *, available: bool) -> str | None:
    """Why an ``AUTO`` open that wants rapidgzip cannot have it here (no child process
    can run it: :func:`rapidgzip_child_unavailable_reason`), or ``None``."""
    if config.use_rapidgzip is not AcceleratorMode.AUTO:
        return None
    if not _rapidgzip_wanted(config, available=available):
        return None
    return rapidgzip_child_unavailable_reason()


def _rapidgzip_enabled(config: StreamConfig, *, available: bool) -> bool:
    """Whether a DEFLATE-family stream decodes through rapidgzip (:func:`_rapidgzip_wanted`).

    AUTO stays on the stdlib backend where no child process can run rapidgzip, and
    falls back to it when a child cannot be started at open (:func:`_open_rapidgzip`).
    ``ON`` fails at open in both cases. This is a query: the warning for the first case
    is logged by the codec's ``open`` (:func:`_warn_if_auto_without_child`).
    """
    if not _rapidgzip_wanted(config, available=available):
        return False
    return _auto_without_child(config, available=available) is None


def _warn_if_auto_without_child(config: StreamConfig) -> None:
    """At a DEFLATE-family open: warn (once per process) if ``AUTO`` wanted rapidgzip
    and reads with the stdlib because no child process can run here."""
    why = _auto_without_child(config, available=deps.rapidgzip.available())
    if why is not None:
        _warn_child_fallback(why)


def _rapidgzip_rewind_warning(
    codec_name: str, config: StreamConfig
) -> RewindWarning | None:
    """How to phrase a rewind report for the DEFLATE-family codecs rapidgzip accelerates.

    Always names the accelerator; whether to report at all is the seek's re-decode
    distance. An *engaged* accelerator no longer suppresses it — measured, rapidgzip's
    index over a ``gzip.compress`` output is sparse (three points across 5 MB), so a
    backward seek into a gap re-decodes megabytes with the accelerator running.

    The old "below the AUTO size threshold, stay quiet" arm is gone: the distance
    threshold covers it, and covers it better (a small member cannot produce a large
    re-decode distance). ``suggest_install`` stays False when the accelerator is present
    or engaged, so a caller is never told to install what they already have. On an
    interpreter where archivey does not use it, ``unused_reason`` carries why
    (``deps.unused_reason``) and the report says that instead.
    """
    engaged = _deflate_family_uses_accelerator(config)
    return RewindWarning(
        codec_name,
        accelerator="rapidgzip",
        suggest_install=not engaged
        and not deps.rapidgzip.available()
        and not deps.unused_reason("rapidgzip"),
        unused_reason=deps.unused_reason("rapidgzip"),
    )


class _StdlibSeekContract(DelegatingStream):
    """Give an accelerated stream the seek contract of the standard-library path.

    ``DecompressorStream`` seeks as ``io.BytesIO`` does: a target past the end is
    returned and kept as the position (reads there return ``b""``), and a relative seek
    before the start clamps to 0; only a negative ``SEEK_SET`` raises. rapidgzip clamps
    a target past the end to the size, and the gzip child refuses a relative underflow
    with ``ValueError``. An accelerator changes speed, not behaviour, so this outermost
    layer resolves the target itself and remembers a position past the end. The seek
    that the stream below clamped has already run the end-of-data checks under it
    (``_seek_reached_end`` in ``stdlib_takeover.py``); where those handed the stream to
    the standard library, that seek returned the target and nothing is remembered here.
    A read past the end still goes to the stream below, which is at its end.
    """

    def __init__(self, inner: BinaryIO) -> None:
        super().__init__(inner)
        # The position when a seek went past the end, which the stream below cannot hold.
        self._past_end: int | None = None

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # tell() can be a round trip to the child: ask only when the seek is relative.
        pos = self.tell() if whence == io.SEEK_CUR else 0
        target = resolve_seek(offset, whence, pos=pos, end=self._end_offset)
        self._past_end = None
        if self._inner.seek(target, io.SEEK_SET) < target:
            self._past_end = target
        return target

    def _end_offset(self) -> int:
        """Return the size, by seeking the stream below to its end."""
        return self._inner.seek(0, io.SEEK_END)

    def tell(self, /) -> int:
        if self._past_end is not None:
            return self._past_end
        return self._inner.tell()

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)


def _wrap_accelerated_length(stream: BinaryIO, config: StreamConfig) -> BinaryIO:
    """Bound accelerated output to ``expected_decompressed_size`` when known.

    rapidgzip may return a silent short prefix on truncation; ``VerifyingStream``
    raises ``TruncatedError`` from the completing / empty read (ADR 0014 — never
    from ``close()``) and caps over-long output.
    """
    size = config.expected_decompressed_size
    if size is None:
        return stream
    from archivey.internal.streams.verify import VerifyingStream

    return VerifyingStream(stream, {}, expected_size=size)


def _deflate_family_uses_accelerator(config: StreamConfig) -> bool:
    """Whether gzip/zlib/deflate will open through rapidgzip for this config."""
    return deps.rapidgzip.available() and _rapidgzip_enabled(config, available=True)


def _bound_rapidgzip_source(
    source: CodecSource, params: CodecParams, config: StreamConfig
) -> CodecSource:
    """Clip a stream source to the known compressed length before rapidgzip.

    rapidgzip over-reads past EOS looking for a concatenated member (raw
    deflate) or prints trailing-garbage to stderr (bzip2). A 7z AES stage
    decrypts a padded block, so the next coder's ``pack_size`` (AES
    unpack_size) is the bound that drops those pad bytes. Only
    ``pack_size`` is pad-free; the two fallbacks assume a non-AES source
    (an AES stream's ``.size`` is the padded plaintext length). Paths stay
    paths: rapidgzip opens its own fd.
    """
    if isinstance(source, (str, os.PathLike)):
        return source
    bound = params.pack_size
    if bound is None:
        bound = config.compressed_input_size
    if bound is None:
        bound = source_byte_size(source)
    if bound is None:
        return source
    return SlicingStream(source, start=0, length=bound, owns_inner=False)


def _refuse_forward_only_accelerator(
    source: CodecSource, field_name: str, label: str
) -> None:
    """Refuse ``ON`` for an accelerator over a source that cannot seek.

    Both accelerators ask their source for ``tell`` and ``seek`` when they open. A
    forward-only stream (a pipe, or a member stream of an outer archive opened without
    ``seekable_members``) cannot answer. This check covers the open, before a child
    process starts or a byte is read, and names the setting. The two translators
    (``_translate_rapidgzip`` and ``Bzip2Codec._translate_accelerator``, both through
    ``_translate_rapidgzip_shared``) cover the late case, a source that refuses ``seek``
    or ``tell`` after it said it could seek; keep both.
    ``AUTO`` never gets here for such a source: :func:`open_codec_stream` clears its
    seek demand.
    """
    if isinstance(source, (str, os.PathLike)) or is_seekable(source):
        return
    raise StreamNotSeekableError(
        f"{field_name}=AcceleratorMode.ON needs a seekable source, and this {label} "
        f"stream is forward-only. Set {field_name} to AUTO or OFF to decode it with the "
        "standard library, or open the source seekable (for a member of an outer "
        "archive, open that archive with seekable_members=True)."
    )


def _accelerator_field(label: str) -> str:
    """The config setting that turns rapidgzip on for a ``label`` stream."""
    return "use_indexed_bzip2" if label == "bzip2" else "use_rapidgzip"


def _no_child_reason(label: str) -> str:
    """The start of the ``ResourceUnavailableError`` message for a ``label`` stream whose
    rapidgzip child cannot run."""
    field_name = _accelerator_field(label)
    return (
        f"the rapidgzip accelerator runs in a child process, and none can be started "
        f"here to decode this {label} stream. Set {field_name}=AcceleratorMode.OFF to "
        "decode it with the standard library"
    )


def _require_rapidgzip_child(label: str) -> None:
    """Raise ``ResourceUnavailableError`` where no rapidgzip child process can run here
    (:func:`rapidgzip_child_unavailable_reason`). Starts nothing."""
    unavailable = rapidgzip_child_unavailable_reason()
    if unavailable is not None:
        raise ResourceUnavailableError(f"{_no_child_reason(label)} ({unavailable}).")


def _open_rapidgzip(
    source: CodecSource, label: str, config: StreamConfig
) -> RapidgzipChildStream | None:
    """Open ``source`` through rapidgzip, in a child process; ``label`` is the codec
    (``gzip``, ``zlib``, ``deflate`` or ``bzip2``).

    rapidgzip 0.16 aborts the process on a gzip, zlib or raw DEFLATE stream that ends
    early, so it never decodes one in this process: see ``rapidgzip_child``. Its bzip2
    decoder runs in a child too, as a precaution: no abort has been seen in it, but it
    comes from the same library. A path source is opened by the child. On POSIX, a stream
    that is a byte range of a regular file (``file_region``: a ZIP member of an archive on
    disk) is read by the child from an inherited descriptor; the parent still checks
    before each call that the stream could be read, and raises what that read would. Any
    other stream source is read for the child here, so the caller's own exception from
    it still reaches the caller.

    Where no child can be started (the spawn or its temporary file refused: a process
    cap, no writable temporary directory, too many open files, a child that cannot
    import rapidgzip), ``AUTO`` returns ``None`` and the caller decodes with the
    standard library, as ``AUTO`` does when rapidgzip is absent. Each of those fails
    before the child reads any of ``source``, so the caller's source is where it was.
    ``ON`` raises ``ResourceUnavailableError`` rather than decode in-process.

    The child's memory is capped at ``DecoderLimits.max_decoder_memory``: rapidgzip
    keeps decoded chunks, so a small file that decodes to gigabytes would otherwise
    take that much. A child over the cap is stopped, and the standard library reads
    the rest of the stream (``_StdlibOnAcceleratorError``).
    """
    bzip2 = label == "bzip2"
    field_name = _accelerator_field(label)
    reason = _no_child_reason(label)
    _require_rapidgzip_child(label)
    try:
        return RapidgzipChildStream(
            source,
            label=label,
            bzip2=bzip2,
            max_memory=config.decoder_limits.max_decoder_memory,
        )
    except RapidgzipChildStartError as exc:
        if getattr(config, field_name) is not AcceleratorMode.AUTO:
            raise ResourceUnavailableError(f"{reason} ({exc}).") from exc
        _warn_child_fallback(str(exc), field_name)
        return None


def _translate_child_or_stdlib(
    exc: Exception, label: str, stdlib: Callable[[Exception], ArchiveyError | None]
) -> ArchiveyError | None:
    """The accelerator translator of a DEFLATE-family codec: rapidgzip's exceptions, then
    ``stdlib`` for an ``AUTO`` open whose child could not start and so decodes with the
    stdlib (:func:`_open_rapidgzip`) after this translator was chosen.

    An exception from the caller's own source (``from_callers_source``) is neither: it
    reaches the caller unchanged.
    """
    if from_callers_source(exc):
        return None
    return _translate_rapidgzip(exc, label) or stdlib(exc)


def _translate_rapidgzip_shared(
    exc: Exception, stream: str, engine: str
) -> ArchiveyError | None:
    """The arms that the DEFLATE-family and bzip2 translators of rapidgzip share.

    ``stream`` names the stream in a corruption message, such as ``"gzip stream
    (rapidgzip)"``; ``engine`` names the decoder in a not-seekable message. Each
    translator calls this after its own message-specific arms.
    """
    text = str(exc)
    if isinstance(exc, ValueError) and "has no valid fileno" in text:
        return StreamNotSeekableError(f"{engine} does not support non-seekable streams")
    if isinstance(exc, io.UnsupportedOperation) and ("seek" in text or "tell" in text):
        return StreamNotSeekableError(f"{engine} does not support non-seekable streams")
    if isinstance(exc, RuntimeError) and (
        "std::exception" in text or "Unknown exception" in text
    ):
        # Opaque catch-alls rapidgzip raises when a C++ fault has no typed Python
        # mapping. Both texts are matched as substrings, because the catch-all can carry
        # detail after its fixed text. On Windows a near-end truncation surfaces as a
        # bare RuntimeError("Unknown exception") (the "Unexpected end of file …" detail
        # only reaches stderr).
        # This arm is a backstop for an unmarked RuntimeError. The decoder runs in a
        # child process, and a RuntimeError the child reports is marked
        # (reported_by_child), so without this arm it lands on each translator's
        # reported_by_child arm, which gives the same CorruptionError and message.
        # Known cross-platform wrinkle: because that detail is lost, a truncation caught here
        # becomes CorruptionError, whereas the same truncated input on Linux keeps its detail
        # and maps to TruncatedError in the DEFLATE translator (or is caught by the ISIZE
        # backstop). Recovering the distinction would need the dropped stderr detail, so
        # callers must treat gzip truncation as either error type (the
        # accelerator-corruption tests accept both).
        return CorruptionError(f"Error reading {stream}: {exception_detail(exc)}")
    return None


def _translate_rapidgzip(exc: Exception, label: str) -> ArchiveyError | None:
    """Map rapidgzip exceptions for a DEFLATE-family codec (gzip / zlib / deflate)."""
    text = str(exc)
    if isinstance(exc, ValueError) and "Mismatching CRC32" in text:
        return _StreamChecksumError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, RuntimeError) and "IsalInflateWrapper" in text:
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, ValueError) and (
        "deflate block" in text or "Huffman coding is not optimal" in text
    ):
        # Corrupt deflate body / block header. Message varies by platform backend:
        # - Linux ISA-L: RuntimeError via IsalInflateWrapper (above)
        # - non-ISA-L (macOS): ValueError "Failed to decode deflate block …" or
        #   "Failed to read deflate block header … The Huffman coding is not optimal!"
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, RuntimeError) and "Invalid deflate block" in text:
        # Raw DEFLATE / zlib body corruption (or an over-long unbounded slice that
        # rapidgzip mistook for a concatenated member).
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, (ValueError, RuntimeError)) and (
        "gzip/zlib header" in text or "gzip magic" in text or "zlib header" in text
    ):
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, ValueError) and "Failed to detect a valid file format" in text:
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    if isinstance(exc, (ValueError, RuntimeError)) and (
        "End of file encountered" in text or "Unexpected end of file" in text
    ):
        return TruncatedError(
            f"{truncated_message(label)} (rapidgzip): {exception_detail(exc)}"
        )
    shared = _translate_rapidgzip_shared(
        exc, f"{label} stream (rapidgzip)", "rapidgzip"
    )
    if shared is not None:
        return shared
    if isinstance(exc, RuntimeError) and reported_by_child(exc):
        # Any other RuntimeError rapidgzip raised: it has no typed error for a fault in
        # its data, and such messages ("Next block offset index is out of sync!", from
        # its open-time probe of a truncated gzip) are not a stable list. The mark
        # tells rapidgzip's errors from a RuntimeError of the caller's own source,
        # which is raised as itself and must reach the caller unchanged.
        return CorruptionError(
            f"Error reading {label} stream (rapidgzip): {exception_detail(exc)}"
        )
    return None
