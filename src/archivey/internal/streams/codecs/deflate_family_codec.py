"""The shared open path of gzip, zlib and raw DEFLATE: the standard library, or
rapidgzip in a child process.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO, ClassVar

from archivey.exceptions import (
    ArchiveyError,
    PackageNotInstalledError,
)
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.archive_stream import (
    ExceptionTranslator,
    RewindWarning,
)
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.rapidgzip_select import (
    _bound_rapidgzip_source,
    _deflate_family_uses_accelerator,
    _open_rapidgzip,
    _rapidgzip_enabled,
    _rapidgzip_requirement,
    _rapidgzip_rewind_warning,
    _refuse_forward_only_accelerator,
    _require_rapidgzip_child,
    _StdlibSeekContract,
    _translate_child_or_stdlib,
    _warn_if_auto_without_child,
    _wrap_accelerated_length,
)
from archivey.internal.streams.codecs.stdlib_takeover import (
    _accelerator_backstop_source,
    _SourceViews,
    _StdlibOnAcceleratorError,
)


class _DeflateFamilyCodec(StreamCodec):
    """The rapidgzip accelerator plumbing that gzip, zlib and raw DEFLATE share.

    rapidgzip decodes all three, in a child process (:func:`_open_rapidgzip`). This class
    chooses the backend at open, builds the accelerated stream, and supplies the
    translator and rewind wording that go with it. A subclass supplies its
    standard-library decoder (:meth:`_open_stdlib`) and, where it has one, the check of
    the end of the data that rapidgzip does not make (:meth:`_end_check`).
    ``codec.value`` names the stream in messages.
    """

    # Whether rapidgzip reads the source clipped to the known compressed length
    # (:func:`_bound_rapidgzip_source`). rapidgzip over-reads past the end of a raw
    # DEFLATE or zlib stream looking for a concatenated member, and an AES pad after it
    # would look like a second member.
    _bounds_source: ClassVar[bool] = True
    # Whether a stream rapidgzip ends before any output goes to the standard library
    # (``empty_to_stdlib`` of :class:`_StdlibOnAcceleratorError`). zlib checks that
    # end in its own wrapper.
    _empty_to_stdlib: ClassVar[bool] = False

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if self._use_accelerator(source, config):
            stream = self._open_accelerated(source, params, config)
            if stream is not None:
                return stream
        return self._open_stdlib(source, config)

    def check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        if config.use_rapidgzip is not AcceleratorMode.ON:
            return
        if self._use_accelerator(source, config) and not self._leaves_to_stdlib(
            source, config
        ):
            _require_rapidgzip_child(self.codec.value)

    def _leaves_to_stdlib(self, source: CodecSource, config: StreamConfig) -> bool:
        """Whether an accelerated open hands ``source`` to the standard library before
        starting a child, on a look at its first bytes. Every such hand-off is declared
        here, so :meth:`open` and :meth:`check_accelerator` make it alike. Default: this
        codec has none."""
        return False

    def _open_stdlib(self, source: CodecSource, config: StreamConfig) -> BinaryIO:
        """The standard-library decoder, with the accelerator off and as its fallback."""
        raise NotImplementedError

    def _use_accelerator(self, source: CodecSource, config: StreamConfig) -> bool:
        """Whether this open decodes through rapidgzip. Raises where ``ON`` asks for it
        and cannot have it: rapidgzip is absent, or the source cannot seek."""
        label = self.codec.value
        _warn_if_auto_without_child(config)
        if not _rapidgzip_enabled(config, available=deps.rapidgzip.available()):
            return False
        if not deps.rapidgzip.available():
            raise PackageNotInstalledError(
                _rapidgzip_requirement().message(f"{label} random access")
            )
        _refuse_forward_only_accelerator(source, "use_rapidgzip", label)
        return True

    def _open_accelerated(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO | None:
        """Open ``source`` through rapidgzip, or ``None`` where the standard library
        decodes it instead: a source :meth:`_leaves_to_stdlib` hands over, or an
        ``AUTO`` open whose child could not start.

        The layers, outermost first: :class:`_StdlibSeekContract`, the
        ``VerifyingStream`` of a declared size (:func:`_wrap_accelerated_length`), the
        codec's :meth:`_end_check`, and :class:`_StdlibOnAcceleratorError` over the
        child.
        """
        if self._leaves_to_stdlib(source, config):
            return None
        label = self.codec.value
        if self._bounds_source:
            source_for_child = _bound_rapidgzip_source(source, params, config)
        else:
            source_for_child = source
        accel_source, views = _accelerator_backstop_source(source_for_child)
        # _refuse_forward_only_accelerator has refused a source that cannot seek.
        assert views is not None
        end_check = self._end_check(source, config, accel_source, views)
        child = _open_rapidgzip(accel_source, label, config)
        if child is None:
            return None
        takeover = _StdlibOnAcceleratorError(
            child,
            views=views,
            open_stdlib=lambda fallback: self._open_stdlib(fallback, config),
            label=label,
            limit=self._accelerated_limit(params, config),
            translate=self.translate,
            empty_to_stdlib=self._empty_to_stdlib,
        )
        stream: BinaryIO = takeover if end_check is None else end_check(takeover)
        return _StdlibSeekContract(_wrap_accelerated_length(stream, config))

    def _accelerated_limit(
        self, params: CodecParams, config: StreamConfig
    ) -> int | None:
        """The ``limit`` for :class:`_StdlibOnAcceleratorError`: ``None`` for a codec
        whose stream ends where the standard library ends it. That class's docstring
        says why only raw DEFLATE sets one."""
        return None

    def _end_check(
        self,
        source: CodecSource,
        config: StreamConfig,
        accel_source: CodecSource,
        views: _SourceViews,
    ) -> Callable[[_StdlibOnAcceleratorError], BinaryIO] | None:
        """The wrapper that checks the end of the accelerated data, or ``None``.

        Called before the child starts, so what it reads from the source it reads
        while nothing else does. That is also why reading ``source`` here, outside the
        lock that ``accel_source``'s views share, is sound: none of them has read yet.
        ``source`` is the caller's; ``accel_source`` is what the child reads, and
        ``views`` makes fresh views of it.
        """
        return None

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        if _deflate_family_uses_accelerator(config):
            return self._translate_accelerator
        return self.translate

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return _rapidgzip_rewind_warning(self.codec.value, config)

    def _translate_accelerator(self, exc: Exception) -> ArchiveyError | None:
        """Translate the rapidgzip accelerator's exceptions to the library's error types.

        Falls through to :meth:`translate`: an ``AUTO`` open whose child could not start
        decodes with the standard library.
        """
        return _translate_child_or_stdlib(exc, self.codec.value, self.translate)
