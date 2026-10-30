"""``ArchiveStreamImpl``, archivey's ``ArchiveStream``: wraps a member/codec stream and
translates raw exceptions.

This is the carrier for the exception-translation contract (see ``error-handling`` and
CONTRIBUTING). Any exception raised while opening or reading the wrapped stream is routed
through a per-library *translator* (raw third-party exception → ``ArchiveyError`` subclass
or ``None`` to let it propagate), then *stamped* with format/archive/member context.

Member digest/length verification (formerly a separate ``VerifyingStream`` layer) is
optional state on this handle — see ``expected_hashes`` / ``expected_size`` — so a
member is served by one public stream that collapses nested codec ``ArchiveStream``s
and hashes/bounds in the same ``read()``.
"""

from __future__ import annotations

import contextlib
import io
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, BinaryIO, NoReturn, cast

from archivey.config import REWIND_REDECODE_WARN_BYTES
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticSummary,
    StreamRewindContext,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
)
from archivey.internal.diagnostics_collector import leave_scope, resolve_collector
from archivey.internal.logs import streams as logger
from archivey.internal.streams.decompressor_stream import (
    DecompressorStream,
    retire_decoder_children,
)
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import (
    check_read_size,
    check_seek_args,
    is_closed_file_error,
    is_seekable,
    readinto_via_read,
)
from archivey.internal.streams.verification import (
    VerificationProofs,
    ask_verification_proofs,
)
from archivey.internal.streams.verify import (
    CustomDigests,
    MemberVerifier,
    build_member_verifier,
    note_raised_seek,
)
from archivey.reader import ArchiveStream
from archivey.terminal import quoted
from archivey.types import HashAlgorithm, Verification

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

    from archivey.internal.diagnostics_collector import (
        DiagnosticCollector,
        DiagnosticScope,
    )
    from archivey.types import ArchiveMember

# A translator maps a raw exception to an ArchiveyError, or returns None to signal "not
# mine — let it propagate unchanged" (the catch-all-free rule in CONTRIBUTING).
ExceptionTranslator = Callable[[Exception], ArchiveyError | None]
# A stamp attaches context (format/archive/member) to an already-translated error.
ErrorStamp = Callable[[ArchiveyError], None]
# Optional close hook (e.g. reader live-stream / lease release).
CloseHook = Callable[[], None]
# What a handle opens: a byte stream, or a member's parts (``MemberStreamParts``).
MemberOpener = Callable[[], "BinaryIO | MemberStreamParts"]


@dataclass(frozen=True)
class RewindWarning:
    """How to phrase ``STREAM_REWIND_REDECOMPRESSES`` for this stream's codec.

    It does not decide *whether* a backward seek is reported: :class:`ArchiveStream`
    measures the decoded progress the seek discards, from the position before the seek
    back to the nearest resume point for the target, and reports it once that reaches
    ``REWIND_REDECODE_WARN_BYTES``. Every decompressing codec carries one, including
    those with resume points (a multi-block ``.xz``, a multi-member ``.lz``) and those
    with an engaged accelerator, because a seek can still land far past the nearest
    resume point. Only ``STORED``, which re-decodes nothing, carries none.

    ``codec_name`` names the format. When an ``accelerator`` package (the ``[seekable]``
    extra) can provide indexed random access, the report names it. ``suggest_install`` is
    True when that package is absent and installing it would help (tell the user to
    install it). ``unused_reason`` is set instead when archivey does not use the package
    on this interpreter (``deps.unused_reason``), and the report gives that reason. With
    neither, the package is present and the report says its index had no closer point.

    ``min_redecode_bytes`` is a cost floor the predicate maxes against. Use it when the
    carrier re-decodes bytes the member stream's own ``tell()`` does not contain (a
    subprocess that restarts a solid archive from member zero). Leave it 0 when the
    discarded member-stream progress is the whole cost.
    """

    codec_name: str
    accelerator: str | None = None
    suggest_install: bool = True
    min_redecode_bytes: int = 0
    unused_reason: str = ""


def _noop_stamp(_exc: ArchiveyError) -> None:
    return None


_ARCHIVE_SOURCE_CLOSED = "Cannot read this stream: its source has been closed."


def closed_source_error(member_name: str | None = None) -> ArchiveyUsageError:
    """The error for a read that found the source under it closed.

    It is a usage error, not damage: the archive bytes are fine. Raised from both error
    boundaries, inside a member stream (``ArchiveStreamImpl._raise_translated``) and in the
    reader's own work (``BaseArchiveReader._raise_translated``), so the two give the
    same answer. ``member_name`` is the member being read, or ``None`` when no member
    is involved (listing, or a bare stream from ``open_stream``); that wording names no
    archive, because ``open_stream`` has none.
    """
    if member_name is None:
        return ArchiveyUsageError(_ARCHIVE_SOURCE_CLOSED)
    return ArchiveyUsageError(
        f"Cannot read member {quoted(member_name)}: the archive source has been closed."
    )


def as_closed_source_error(
    exc: BaseException, member_name: str | None
) -> ArchiveyUsageError | None:
    """The ``closed_source_error`` for ``exc``, or ``None`` if ``exc`` is not a closed source.

    Matches the ``io`` closed-handle ``ValueError`` itself, and also the no-member
    error that a boundary below this one already raised for it. A codec stream under a
    member (a ``.tar.gz`` decoder, a 7z folder) has no member name, so its boundary
    says "this stream"; the member boundary above it knows the member and names it.
    """
    if is_closed_file_error(exc):
        return closed_source_error(member_name)
    # Reachable because ArchiveyUsageError is not an ArchiveyError, so the callers'
    # already-typed arm does not claim it first.
    if (
        member_name is not None
        and type(exc) is ArchiveyUsageError
        and exc.raw_message == _ARCHIVE_SOURCE_CLOSED
    ):
        return closed_source_error(member_name)
    return None


class _Opened:
    """An ``ArchiveStreamImpl`` opener that is a stream already open.

    Pass ``_Opened(stream)`` as ``open_fn`` with ``lazy=False``: the handle starts open
    on ``stream``, as it would by calling ``lambda: stream``, without the call or the
    diagnostic scope the call is made in (it emits nothing). An ``ArchiveStreamImpl`` is
    still opened by the call, which collapses it into the handle. Calling it returns
    ``stream``, so it is still an opener wherever one is expected.

    With ``settle_seekable``, the handle ignores its ``seekable`` argument and asks
    ``is_seekable(stream)`` on first use (``ArchiveStreamImpl._seek_allowed``) instead. Not
    for an ``ArchiveStreamImpl``, whose own declared seekability the collapse would drop.
    Only that subclass collapses: the collapse takes over its private state.
    """

    __slots__ = ("settle_seekable", "stream")

    def __init__(self, stream: BinaryIO, *, settle_seekable: bool = False) -> None:
        assert not (settle_seekable and isinstance(stream, ArchiveStreamImpl))
        self.stream = stream
        self.settle_seekable = settle_seekable

    def __call__(self) -> BinaryIO:
        return self.stream


class MemberStreamParts:
    """A member's opened data and how to serve it, before any handle serves it.

    What ``_open_member`` returns (built by ``BaseArchiveReader._member_parts``). A lazy
    handle takes them over on its first read (``ArchiveStreamImpl._adopt``), and
    ``reader.open()`` builds its handle from them (``BaseArchiveReader._member_stream``):
    one ``ArchiveStreamImpl`` per member either way, never one inside another.

    ``inner`` is owned here until a handle takes it: code that drops the parts without
    building or adopting them closes it. ``translate`` is a codec's translator, asked
    before the reader's, or ``None``. ``stamp`` is the reader's, called with the
    member's name. ``seekable`` is ``None`` to settle it on first use. The fields from
    ``collector`` on are ``build_member_verifier``'s arguments.
    """

    __slots__ = (
        "archive_name",
        "bounded",
        "checks_content",
        "collector",
        "custom_digests",
        "digest_transforms",
        "end_check",
        "expected_hashes",
        "expected_size",
        "fill_size",
        "inner",
        "member_name",
        "rewind_warning",
        "seekable",
        "size",
        "stamp",
        "translate",
        "verify_member",
    )

    def __init__(
        self,
        inner: BinaryIO,
        member_name: str | None,
        stamp: Callable[[ArchiveyError, str | None], None],
        translate: ExceptionTranslator | None,
        seekable: bool | None,
        size: int | None,
        rewind_warning: RewindWarning | None,
        checks_content: bool,
        collector: DiagnosticCollector | None,
        archive_name: str | None,
        expected_hashes: Mapping[HashAlgorithm, bytes] | None,
        expected_size: int | None,
        digest_transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]] | None,
        verify_member: ArchiveMember | None,
        end_check: Callable[[int], None] | None,
        fill_size: bool,
        custom_digests: CustomDigests | None,
        bounded: bool,
        /,
    ) -> None:
        self.inner = inner
        self.member_name = member_name
        self.stamp = stamp
        self.translate = translate
        self.seekable = seekable
        self.size = size
        self.rewind_warning = rewind_warning
        self.checks_content = checks_content
        self.collector = collector
        self.archive_name = archive_name
        self.expected_hashes = expected_hashes
        self.expected_size = expected_size
        self.digest_transforms = digest_transforms
        self.verify_member = verify_member
        self.end_check = end_check
        self.fill_size = fill_size
        self.custom_digests = custom_digests
        self.bounded = bounded

    def build_verifier(self) -> MemberVerifier | None:
        """The member's verifier, or ``None`` when there is nothing to check.

        Call it inside the scope of the handle that serves the member, so a digest the
        verifier cannot check is reported on that handle.
        """
        return build_member_verifier(
            self.expected_hashes,
            expected_size=self.expected_size,
            collector=self.collector,
            member=self.verify_member,
            archive_name=self.archive_name,
            digest_transforms=self.digest_transforms,
            end_check=self.end_check,
            fill_size=self.fill_size,
            custom_digests=self.custom_digests,
            bounded=self.bounded,
        )


class ArchiveStreamImpl(ArchiveStream):
    """Archivey's own :class:`~archivey.ArchiveStream`: the one every reader and
    :func:`~archivey.open_stream` hands out.

    Responsibilities (one class, several optional knobs):

    1. **Translate + stamp** — raw codec/OS errors → ``ArchiveyError`` with archive
       context (``translate`` / ``stamp``).
    2. **Lazy open** — ``open_fn`` may run on first read; ``seekable`` is answered from
       the hint until then.
    3. **One handle per member** — a lazy member handle's opener returns the
       member's ``MemberStreamParts``, which ``_adopt`` takes over. An opener that
       returns another ``ArchiveStreamImpl`` (a codec stream) is collapsed:
       ``_collapse_nested`` flattens it into this handle while composing translators
       and adopting fused verification.
    4. **Fused verify** — optional ``MemberVerifier`` (digests / ``expected_size``) runs
       in ``read`` / ``close``. Distinct from bare ``size=`` (fsspec attribute only —
       does **not** enable length checks).
    5. **Lease** — ``on_close`` releases reader live-stream state, in ``close()``'s
       ``finally``. A stream the caller never closes is closed by ``IOBase.__del__``
       when it is collected, so the lease is released then.
    """

    # Per-stream state that starts the same on every stream, as class defaults: an
    # instance assigns one only when it changes, which keeps the constructor cheap
    # (``stream_members()`` builds a stream per member). Each is documented where
    # ``__init__`` or the method that changes it sets it.
    _open_error: Exception | None = None
    _open_error_tb: TracebackType | None = None
    _open_interrupted_by: type[BaseException] | None = None
    _inner: BinaryIO | None = None
    _rewind_warned = False
    _closing = False
    _verdict: ArchiveyError | None = None
    _verdict_tb: TracebackType | None = None
    _verdict_rewound = False
    _uninterrupted = True
    _ended_from_start = False
    # ``close()`` reads these three as well: ``IOBase.__del__`` closes an instance whose
    # ``__init__`` raised before assigning them, or never ran, as when a deprecated
    # ``ArchiveStream(...)`` call has the wrong arguments. ``False`` because ``None``
    # would ask the inner whether it can seek.
    _seekable_hint: bool | None = False
    _verifier: MemberVerifier | None = None
    _on_close: CloseHook | None = None
    # Set by ``_hold_inner``: wraps the inner stream when a lazy handle opens it.
    _inner_wrap: Callable[[BinaryIO], BinaryIO] | None = None

    def __init__(
        self,
        open_fn: MemberOpener,
        *,
        translate: ExceptionTranslator,
        stamp: ErrorStamp | None = None,
        lazy: bool = False,
        seekable: bool = True,
        rewind_warning: RewindWarning | None = None,
        size: int | None = None,
        collector: DiagnosticCollector | None = None,
        on_close: CloseHook | None = None,
        expected_hashes: Mapping[HashAlgorithm, bytes] | None = None,
        expected_size: int | None = None,
        digest_transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]]
        | None = None,
        verify_member: ArchiveMember | None = None,
        end_check: Callable[[int], None] | None = None,
        fill_size: bool = False,
        archive_name: str | None = None,
        verifier: MemberVerifier | None = None,
        member_name: str | None = None,
        repeat_verdict: bool = True,
        checks_content: bool = False,
        custom_digests: CustomDigests | None = None,
        bounded: bool = False,
    ) -> None:
        super().__init__()
        # Named in the closed-source error and returned by ``name``; ``None`` for a
        # stream of no member.
        self._member_name = member_name
        settle_seekable = False
        if type(open_fn) is _Opened:
            assert not lazy, "_Opened is the opener of an eager handle"
            settle_seekable = open_fn.settle_seekable
        if type(open_fn) is _Opened and not isinstance(
            open_fn.stream, ArchiveStreamImpl
        ):
            # A stream already open: the handle starts open on it, as an eager open of
            # ``lambda: stream`` would, without the call. An ``ArchiveStreamImpl`` is
            # opened the usual way, which collapses it (``_ensure_open``).
            self._inner = open_fn.stream
            self._open_fn: MemberOpener | None = None
        else:
            self._open_fn = open_fn
        # ``_open_error`` / ``_open_error_tb``: the error a failed lazy open raised,
        # and its traceback: a retry raises it again instead of calling ``open_fn`` a
        # second time. ``_open_interrupted_by``: the type of a ``BaseException``
        # (``KeyboardInterrupt``) that stopped the lazy open. Not the stream's error,
        # so it is not raised again; a retry names it.
        self._translate = translate
        self._stamp = stamp if stamp is not None else _noop_stamp
        self._open_lock = threading.Lock()
        # ``None``: whatever ``is_seekable(inner)`` answers, asked on first use. Only on
        # a handle built by ``_Opened(..., settle_seekable=True)``.
        self._seekable_hint = None if settle_seekable else seekable
        self._rewind_warning = rewind_warning
        self._size = size
        self._diagnostics_collector = collector
        self._on_close = on_close
        # ``_closing``: ``close()`` reads it. It is a class default, so it is set
        # before the verifier build below, which can raise (a digest diagnostic under
        # a RAISE policy): ``IOBase.__del__`` still calls ``close()`` on an instance
        # whose ``__init__`` raised.
        self._verifier = verifier
        # ``_verdict``: the content verdict this stream raised, if any. Every later
        # read and seek raises it again (see ``_fail``). ``_verdict_tb``: its traceback
        # as first raised, where the damage was found. ``_verdict_rewound``: whether
        # the caller has seeked since the verdict last raised. A seek restarts the
        # decode, so the prefix reads again; the read that reaches the end raises.
        # False for a stream that only a reader's own views read. A read seeks the
        # shared handle when it is not already there. Some reads still seek, and one
        # seek is enough to mark the stream rewound, so a short read that ends at the
        # damage would lose its prefix. The member streams over those views keep theirs.
        self._repeat_verdict = repeat_verdict
        # The verification level (``verified``). ``checks_content``: the decoder checks
        # every byte against a checksum of its own when it decodes from the start to
        # the end (a gzip, bzip2, lzip or zlib codec stream). That check counts only
        # for a read that reached the end with no seek since position 0
        # (``_uninterrupted``): a seek through an index skips bytes the decoder never
        # saw. ``_ended_from_start`` keeps that such a read happened; like the
        # verifier's flags it survives a rewind. ``_uninterrupted`` and
        # ``_ended_from_start`` start as class defaults (``True``, ``False``).
        self._checks_content = checks_content
        # A stream's diagnostics are what its own calls emit, from this constructor on:
        # ``read``, ``seek`` and ``close`` enter this scope, on whichever thread calls.
        # Other threads' emits into the same collector stay out, as do the reader's
        # own emits between calls (a pass walking on to the next header).
        self._diagnostics_scope: DiagnosticScope | None = (
            collector.new_scope() if collector is not None else None
        )
        # Only an eager open and a digest the verifier cannot check emit here, so a
        # lazy stream with no digest skips entering the scope: ``stream_members()``
        # builds one such stream per member. A stream built open (``_Opened``)
        # opens nothing.
        can_emit = (not lazy and self._inner is None) or (
            bool(expected_hashes) and verifier is None
        )
        with (
            collector.inside(self._diagnostics_scope)
            if can_emit
            and collector is not None
            and self._diagnostics_scope is not None
            else contextlib.nullcontext()
        ):
            self._init_checks(
                expected_hashes,
                expected_size=expected_size,
                collector=collector,
                verify_member=verify_member,
                archive_name=archive_name,
                digest_transforms=digest_transforms,
                end_check=end_check,
                fill_size=fill_size,
                lazy=lazy,
                custom_digests=custom_digests,
                bounded=bounded,
            )

    def _init_checks(
        self,
        expected_hashes: Mapping[HashAlgorithm, bytes] | None,
        *,
        expected_size: int | None,
        collector: DiagnosticCollector | None,
        verify_member: ArchiveMember | None,
        archive_name: str | None,
        digest_transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]] | None,
        end_check: Callable[[int], None] | None,
        fill_size: bool,
        lazy: bool,
        custom_digests: CustomDigests | None = None,
        bounded: bool = False,
    ) -> None:
        """The part of the constructor that can emit: inside the stream's scope."""
        # Fused member verification (None when there is nothing to check). Prefer an
        # already-built ``verifier`` (collapse adoption); otherwise build from knobs.
        # ``expected_size`` here is the verify bound only — bare ``size=`` (fsspec
        # attribute) must not enable length checks on TAR/ISO/directory handles.
        if self._verifier is None:
            self._verifier = build_member_verifier(
                expected_hashes,
                expected_size=expected_size,
                collector=collector,
                member=verify_member,
                archive_name=archive_name,
                digest_transforms=digest_transforms,
                end_check=end_check,
                fill_size=fill_size,
                custom_digests=custom_digests,
                bounded=bounded,
            )
        if not lazy and self._inner is None:
            self._ensure_open()

    @property
    def name(self) -> str:
        if self._member_name is None:
            raise AttributeError("name")
        return self._member_name

    @property
    def diagnostics(self) -> DiagnosticSummary:
        scope = self._diagnostics_scope
        if scope is None:
            return DiagnosticSummary.empty()
        return scope.summary()

    @property
    def size(self) -> int | None:
        """The fsspec-style ``size`` convention (see ``source_byte_size``): the creator may
        supply it up front (a member stream knows ``member.size`` from the archive
        metadata), else an opened inner decompressor with a cheap ``try_get_size()``
        (a size it already knows, or a scan that reads only the index/trailer) is
        consulted. A BGZF stream reports ``None`` until a seek or a read finds its size:
        its index scan reads the whole file. That scan reads payload, so the
        ``safe-extraction`` rule for a static ratio denominator requires ``None`` here;
        the live compressed-byte counter (``compressed_bytes_consumed``) or
        ``max_extracted_bytes`` then guards extraction instead. Lets a nested
        ``open_archive(reader.open("inner.zip"))`` learn its source size — e.g. for the
        extraction bomb tracker — without an expensive end-seek. A lazy, still-unopened
        stream reports ``None`` rather than opening itself just to answer.
        """
        if self._size is not None:
            return self._size
        inner = self._inner
        if inner is None:
            return None
        try_get_size = getattr(inner, "try_get_size", None)
        if callable(try_get_size):
            result = try_get_size()
            return result if isinstance(result, int) else None
        inner_size = getattr(inner, "size", None)
        if isinstance(inner_size, int) and not isinstance(inner_size, bool):
            return inner_size
        return None

    def _ensure_open(self) -> BinaryIO:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._inner is not None:
            return self._inner
        # Claim the right to call open_fn under the lock, then invoke open_fn
        # *outside* it so a backend lock acquired inside open_fn (TAR/ISO shared
        # handle) never nests under stream-state. Publish the result under the lock.
        open_fn: MemberOpener | None
        with self._open_lock:
            if self._inner is not None:
                return self._inner
            if self._open_fn is None:
                if self.closed:
                    raise ValueError("I/O operation on closed file.")
                failed = self._open_error
                if failed is not None:
                    # The open already failed: this is the same open, so it fails
                    # the same way, as a member's content verdict does (``_fail``).
                    raise failed.with_traceback(self._open_error_tb)
                interrupted = self._open_interrupted_by
                if interrupted is not None:
                    raise ArchiveyUsageError(
                        "Cannot open this member stream: an earlier attempt to open "
                        f"it was interrupted ({interrupted.__name__})."
                    )
                # Another caller claimed the open and has not finished it.
                raise ArchiveyUsageError(
                    "Cannot open this member stream: another caller is opening it. "
                    "Concurrent operations on a single stream object require caller "
                    "synchronization."
                )
            open_fn = self._open_fn
            self._open_fn = None  # claim: only one caller proceeds to open_fn
        try:
            opened = open_fn()
            if isinstance(opened, MemberStreamParts):
                # The opener of a lazy member handle is ``_open_member``: this handle
                # serves the member itself.
                opened = self._adopt(opened)
            # An opener may also return another ``ArchiveStreamImpl`` (a codec stream,
            # or a member a backend opened as a handle of its own). Collapse here so the
            # public handle is a single wrapper — but adopt the nested
            # translator/stamp/rewind_warning so codec errors stay typed.
            while isinstance(opened, ArchiveStreamImpl):
                opened = self._collapse_nested(opened)
        except Exception as e:  # noqa: BLE001 - re-raised via the translator
            # _open_fn stays None (claimed above) so a retry raises rather than
            # re-entering a half-open backend. It raises what this open raised.
            self._fail_open(e)
        except BaseException as e:
            # KeyboardInterrupt, SystemExit and the like propagate as they are (DR-15a).
            with self._open_lock:
                self._open_interrupted_by = type(e)
            raise
        with self._open_lock:
            if self.closed:
                try:
                    opened.close()
                except Exception:  # noqa: BLE001, S110 - best-effort; stream already closing
                    pass
                raise ValueError("I/O operation on closed file.")
            wrap = self._inner_wrap
            self._inner = opened if wrap is None else wrap(opened)
            return self._inner

    def _adopt(self, parts: MemberStreamParts) -> BinaryIO:
        """Take over ``parts`` as a nested member handle's collapse would have.

        This handle was built lazily for the same member by the same reader, so it
        already has the reader's translator, the member's stamp and its size and
        seekability; ``parts`` adds a codec's translator, a rewind warning, the codec's
        own check and the verifier. A stamp for another member (a link's target opened
        under the link's handle) runs first, as the nested one did.
        """
        inner = parts.inner
        try:
            # Built here, in the scope of the call that opens this handle, so a digest
            # it cannot check is reported on this handle.
            verifier = parts.build_verifier()
        except BaseException:
            with contextlib.suppress(Exception):
                inner.close()
            raise
        if verifier is not None:
            # A lazy member handle has no checks of its own (``_lazy_member_stream``).
            assert self._verifier is None, "adopting would discard a verifier"
            if self._verifier is None:
                self._verifier = verifier
        if parts.translate is not None:
            self._translate = compose_translators(parts.translate, self._translate)
        if parts.member_name != self._member_name:
            member_stamp = parts.stamp
            member_name = parts.member_name
            outer_stamp = self._stamp

            def composed_stamp(err: ArchiveyError) -> None:
                member_stamp(err, member_name)
                outer_stamp(err)

            self._stamp = composed_stamp
            if self._member_name is None:
                self._member_name = member_name
        if self._rewind_warning is None:
            self._rewind_warning = parts.rewind_warning
        self._checks_content = self._checks_content or parts.checks_content
        return inner

    def _fail_open(self, e: Exception) -> NoReturn:
        """``_fail`` for a lazy open, remembering the error for a retry to raise."""
        try:
            self._fail(e)
        except Exception as raised:
            with self._open_lock:
                self._open_error = raised
                self._open_error_tb = raised.__traceback__
            raise

    def _collapse_nested(self, nested: ArchiveStreamImpl) -> BinaryIO:
        """Reduce a nested ``ArchiveStreamImpl`` to a bytes stream for this handle.

        If ``nested`` is still lazy, its opener is taken and invoked (this handle is
        opening *now*, so deferral transfers rather than being forced early). If it is
        already open, its inner is stolen. Either way the nested wrapper is neutralized
        and will not close the result.

        Codec streams (``open_codec_stream``) carry a library-specific translator;
        member wrappers often wrap those again. Adopting nested ``translate`` /
        ``stamp`` / ``rewind_warning`` keeps BadGzipFile / zlib.error / etc. typed
        after the collapse.
        """
        if nested.closed:
            raise ValueError("I/O operation on closed file.")

        nested_translate = nested._translate
        nested_stamp = nested._stamp
        outer_translate = self._translate
        outer_stamp = self._stamp

        composed_translate = compose_translators(nested_translate, outer_translate)

        def composed_stamp(err: ArchiveyError) -> None:
            nested_stamp(err)
            outer_stamp(err)

        self._translate = composed_translate
        self._stamp = composed_stamp
        if self._member_name is None:
            self._member_name = nested._member_name
        if self._rewind_warning is None and nested._rewind_warning is not None:
            self._rewind_warning = nested._rewind_warning
        # Adopt fused verification from the nested stream (a lazy outer has none).
        if self._verifier is None and nested._verifier is not None:
            self._verifier = nested._verifier
            nested._verifier = None
        # The codec's own check, and whether the nested stream was read from the start.
        self._checks_content = self._checks_content or nested._checks_content
        self._uninterrupted = self._uninterrupted and nested._uninterrupted
        # Neutralizing ``nested`` below skips its close(), so a verifier left on it
        # would never run. No path fuses a verifier into both wrappers today.
        assert nested._verifier is None, "collapse would discard a nested verifier"

        with nested._open_lock:
            open_fn = nested._open_fn
            inner = nested._inner
            nested._open_fn = None
            nested._inner = None
        # Only the handle returned to the caller gets a lease hook; a nested wrapper
        # is backend-internal and never registered, so there is nothing to drop.
        assert nested._on_close is None, "collapse would discard a nested lease hook"
        nested._on_close = None  # keeps the clear under ``python -O``
        # Mark closed without touching stolen opener/inner.
        super(ArchiveStreamImpl, nested).close()

        if inner is not None:
            return inner
        if open_fn is not None:
            opened = open_fn()
            if isinstance(opened, MemberStreamParts):
                opened = self._adopt(opened)
            while isinstance(opened, ArchiveStreamImpl):
                opened = self._collapse_nested(opened)
            return opened
        raise ArchiveyUsageError(
            "Cannot collapse nested ArchiveStreamImpl: it has no opener and no inner "
            "stream."
        )

    def _fail_unless_closed(self, e: Exception) -> NoReturn:
        """``_fail``, unless this stream was closed while the call ran.

        On a ``CONCURRENT`` reader, ``reader.close()`` on one thread closes the member
        streams another thread may be reading. The inner then fails in whatever way
        its layer does (a closed pipe, a buffer gone), and translated that could read
        as damage. Raise the closed-file error a read after ``close()`` raises.
        """
        if self._closing or self.closed:
            raise ValueError("I/O operation on closed file.") from e
        self._fail(e)

    def _fail(self, e: Exception) -> NoReturn:
        """Translate + stamp ``e`` and raise it, remembering a content verdict.

        A content verdict is an error that says the member's data is damaged: a
        ``CorruptionError`` or ``TruncatedError``, or an error raised from one (a
        ZipCrypto member's password-or-damage ``EncryptionError``). Until a seek, every
        later read raises it again. A seek restarts the decode, so the prefix reads
        again, and the read that reaches the end raises the verdict again, whether or
        not the seek forfeited the digest check: a caller who catches it and seeks back
        cannot re-read the damaged member as complete, clean data. A content error that
        a rewound read raises is that same verdict found again (a seek to 0 re-arms the
        verifier), so the stream raises the error object it raised first. A stream built
        with ``repeat_verdict=False`` remembers nothing and raises each error as it comes.
        """
        try:
            self._raise_translated(e)
        except ArchiveyError as raised:
            if _is_content_verdict(raised) and self._inner is not None:
                # A digest mismatch found here, above the decoder: a decoder process
                # that produced the bad bytes must not serve another member.
                retire_decoder_children(self._inner)
            if not self._repeat_verdict or not _is_content_verdict(raised):
                raise
            repeat = self._verdict is not None and self._verdict_rewound
            if self._verdict is None:
                self._verdict = raised
                self._verdict_tb = raised.__traceback__
            self._verdict_rewound = False
            if not repeat:
                raise
        # A rewind re-arms the verifier, so a rewound read finds the damage again and
        # raises a new error for it: raise the one this stream already raised.
        assert self._verdict is not None
        raise self._verdict.with_traceback(self._verdict_tb)

    def _reached_end(self, n: int, data: bytes) -> bool:
        """Whether a rewound read reached the end, where the damage was found.

        A short or empty return is the end. So is a full return that lands at the
        declared size: ``read(member.size)`` after ``seek(0)`` returns every byte and
        would otherwise hand the member over whole. The position the verdict was
        raised at is no guide: a read that withheld its bytes may not have moved it.
        """
        if n < 0 or len(data) < n:
            return True
        if self._size is None or self._inner is None:
            return False
        try:
            return self._inner.tell() >= self._size
        except Exception:  # noqa: BLE001 - an unknown position leaves the short rule
            return False

    def _raise_verdict(self) -> None:
        """Raise the content verdict this stream already raised, if there is one.

        Each ``raise`` adds the caller's frames to the exception's traceback, and the
        object lives as long as the stream. Resetting it to the first traceback keeps
        a retry loop from growing it without bound, and keeps it pointing at where the
        damage was found.
        """
        if self._verdict is not None:
            raise self._verdict.with_traceback(self._verdict_tb)

    def _raise_translated(self, e: Exception) -> NoReturn:
        """Translate + stamp ``e`` and raise, or re-raise it unchanged."""
        raise_translated(e, self._translate, self._stamp, self._member_name)

    def read(self, n: int | None = -1, /) -> bytes:
        scope = self._diagnostics_scope
        if scope is None:
            return self._read(n)
        stack = scope._collector.scope_stack()
        stack.append(scope)
        try:
            return self._read(n)
        finally:
            leave_scope(stack, scope)

    def _read(self, n: int | None) -> bytes:
        """``read`` inside the stream's diagnostic scope, already entered."""
        # ``None`` reads to EOF, as on any ``io`` stream; a float or str is the caller's
        # TypeError, and an int too wide for ``Py_ssize_t`` their OverflowError, both
        # raised before anything is read. Passed inward, ``read(1.5)`` or ``read(2**70)``
        # fails inside a decoder after its compressed chunk has left the source, and the
        # member would then report damage on every later read, even after ``seek(0)``.
        n = check_read_size(n)
        # _ensure_open is outside the try: its read-after-close ValueError is the
        # wrapper's own (plain file semantics, not translated), and a lazy open failure
        # is already routed through _fail inside it.
        # Full-count ``read(n)`` (ADR 0014): one ``inner.read(n)``, so
        # ``read(member.size)`` is a real verifying event when a verifier is fused and
        # the call returns all ``member.size`` bytes. On a truncated member it can
        # return short without raising (unless the decoder itself reports the cut): the
        # ``TruncatedError`` then comes from the next read, the one that sees EOF, so a
        # caller must read until ``b""``. The ``n``-or-terminal guarantee is the
        # inner's (fill-or-EOF); a short non-empty
        # return is a terminal signal to forward, not "ask again" — retrying it would
        # pull a decoder's deferred truncation into this call. An inner that shorts
        # mid-stream needs a full-count layer in front (the ``ArchiveSource`` at the
        # boundary is one), not a loop here.
        inner = self._ensure_open()
        verdict = self._verdict
        if verdict is not None and not self._verdict_rewound:
            self._raise_verdict()
        verifier = self._verifier
        try:
            if verifier is not None:
                data = verifier.read(inner, n)
            elif n == 0:
                return b""
            else:
                data = inner.read(n)
        except Exception as e:  # noqa: BLE001 - re-raised via the translator
            self._fail_unless_closed(e)
        if verdict is None and (n < 0 or (n != 0 and not data)) and self._uninterrupted:
            # A read to the end, or one that found it, from the start with no seek
            # between: every length and end-of-data check below it ran on all of it.
            self._ended_from_start = True
        if verdict is not None and n != 0 and self._reached_end(n, data):
            # A rewound stream reached its end: the damage is still there, and the
            # seek may have paused the check that found it (a seek back to its
            # frontier resumes it). Withhold the bytes, as the
            # verifier does with the chunk that fails.
            self._verdict_rewound = False
            self._raise_verdict()
        return data

    def read_ahead(self, need: int, n: int, /) -> bytes:
        scope = self._diagnostics_scope
        if scope is None:
            return self._read_ahead(need, n)
        stack = scope._collector.scope_stack()
        stack.append(scope)
        try:
            return self._read_ahead(need, n)
        finally:
            leave_scope(stack, scope)

    def _read_ahead(self, need: int, n: int) -> bytes:
        inner = self._ensure_open()
        # A verdict raises again as ``read`` raises it. A verifier sees each byte in
        # ``read``, and bytes that skipped it would go out unchecked. No codec stream
        # under a reader's buffer has one, so this costs nothing; ``read(n)`` is still
        # right, it only waits for the whole ``n``.
        if self._verifier is not None or self._verdict is not None:
            return self._read(n)
        try:
            # Only a reader's buffer over a codec stream on a source that cannot seek
            # calls this, and that codec stream's inner is a ``DecompressorStream``.
            return cast("DecompressorStream", inner).read_ahead(need, n)
        except Exception as e:  # noqa: BLE001 - re-raised via the translator
            self._fail_unless_closed(e)

    def readinto(self, b: WriteableBuffer, /) -> int:
        # Always route through read() so the one-read / stop-on-short policy above
        # (and fused verify) stay consistent — inner.readinto may be up-to-n.
        return readinto_via_read(self, b)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        scope = self._diagnostics_scope
        if scope is None:
            return self._seek(offset, whence)
        stack = scope._collector.scope_stack()
        stack.append(scope)
        try:
            return self._seek(offset, whence)
        finally:
            leave_scope(stack, scope)

    def _seek_allowed(self) -> bool:
        """The seekability this handle was built with, settled on first use."""
        hint = self._seekable_hint
        if hint is None:
            inner = self._inner
            hint = self._seekable_hint = inner is not None and is_seekable(inner)
        return hint

    def _seek(self, offset: int, whence: int) -> int:
        if not self._seek_allowed():
            raise io.UnsupportedOperation("seek")
        # The arguments are checked after seekability, as a buffered reader over a pipe
        # does: ``seek(1.5)`` there is UnsupportedOperation, not TypeError. On a seekable
        # member a non-integer offset or whence (``1.5``, ``None``) is ``io.BytesIO``'s
        # TypeError, raised before anything moves: passed inward, a float makes some
        # backends consume a chunk before failing (wrong bytes after a later seek(0))
        # and others report damage that is not there. A bad position or whence is the
        # caller's ValueError, checked here because inside the try a backend translator
        # that reads ValueError as a corrupt offset (ZIP, ISO) would report an undamaged
        # archive as corrupt. Checked, not resolved: the inner gets the caller's whence,
        # and resolving a SEEK_END here would make a decompressor decode to its end for
        # a size this layer does not need.
        offset, whence = check_seek_args(offset, whence)
        inner = self._ensure_open()  # outside the try, same as read()
        before: int | None = None
        verifier = self._verifier
        try:
            before = inner.tell()
            if verifier is not None:
                # The verifier may defer a forward seek to the next read, which then
                # hashes the skipped bytes (``MemberVerifier.seek``).
                result = verifier.seek(inner, offset, whence)
            else:
                result = inner.seek(offset, whence)
        except Exception as e:  # noqa: BLE001 - re-raised via the translator
            self._note_raised_seek(inner, before)
            self._fail_unless_closed(e)
        if self._verdict is not None:
            self._verdict_rewound = True
        if result != before:
            self._uninterrupted = result == 0
        self._maybe_warn_rewind(before, result)
        return result

    def _note_raised_seek(self, inner: BinaryIO, before: int | None) -> None:
        """Keep the bookkeeping true to where a seek that raised left ``inner``.

        The verifier learns the new position (:func:`note_raised_seek`). The seek's
        own error is the one that propagates, so a rewind report that would raise
        here is dropped.
        """
        after = note_raised_seek(self._verifier, inner)
        # Both ``None`` is equal and keeps the flag: ``before`` is ``None`` only when
        # the ``tell()`` ahead of the seek raised, so the seek never ran.
        if after != before:
            # Where the inner was left is unknown, or somewhere the decode may have
            # jumped to.
            self._uninterrupted = after == 0
        if after is None:
            return
        if before is not None:
            try:
                self._maybe_warn_rewind(before, after)
            except Exception:  # noqa: BLE001, S110 - the seek's own error propagates instead
                pass

    def _digest_intact(self) -> bool | None:
        """Whether the fused verifier's digest can still run (``ask_digest_intact``).

        ``None`` without a fused verifier: a codec-level stream has no member digest.
        """
        verifier = self._verifier
        return verifier.digest_intact if verifier is not None else None

    def _verification_proofs(self) -> VerificationProofs:
        """What this stream and the layers below it have proved (``verification``)."""
        own = VerificationProofs(
            ended=self._ended_from_start,
            content=self._checks_content and self._ended_from_start,
            content_possible=self._checks_content,
        )
        verifier = self._verifier
        if verifier is not None:
            own = own.combine(verifier.proofs())
        return own.combine(ask_verification_proofs(self._inner))

    @property
    def verified(self) -> Verification:
        # No high-water mark is kept: every input to ``_level_now`` moves one way. The
        # stream's end flag and the verifier's and the HMAC stage's match flags are
        # only ever set, ``_inner`` is never cleared, and a password watch's doubt
        # only clears.
        return self._level_now()

    @property
    def verifiable(self) -> Verification:
        proofs = self._verification_proofs()
        if proofs.content_possible:
            ceiling = Verification.CONTENT
        elif proofs.key_in_doubt:
            ceiling = Verification.NONE
        else:
            ceiling = Verification.STRUCTURE
        return max(ceiling, self.verified)

    def _level_now(self) -> Verification:
        """The level the layers' proofs add up to."""
        if self._inner is None:
            return Verification.NONE
        proofs = self._verification_proofs()
        # A checksum that matched every byte proves the key as well: a wrong key does
        # not decrypt to data that matches it.
        if proofs.ended and proofs.content:
            return Verification.CONTENT
        if proofs.key_in_doubt:
            return Verification.NONE
        if proofs.ended:
            return Verification.STRUCTURE
        return Verification.KEY

    def nearest_resume_offset(self, target: int) -> int | None:
        # Asked of the inner: streams nest over each other.
        return ask_resume_offset(self._inner, target)

    def _maybe_warn_rewind(self, before: int, after: int) -> None:
        """Report a backward seek that discards an expensive amount of decoded progress.

        The predicate is the seek's actual cost, not the codec's identity. A format that
        *can* carry an index does not always *have* a useful one: a single-block ``.xz``
        has one seek point (the origin) and restarts from byte zero exactly like a codec
        with no index, and an engaged ``rapidgzip`` can hold an index sparse enough for
        the same thing. Keying on codec identity was silent on both.

        **The cost is what the rewind throws away**, not what the seek call itself
        decodes: ``before - nearest_resume_offset(after)`` — the bytes that must be
        decoded again to get back to where the caller was. The seek call alone is a poor
        proxy; ``seek(10)`` after reading a gigabyte decodes ten bytes and destroys a
        gigabyte of progress, and it is the gigabyte that makes a seek loop quadratic.

        **Recorded once per stream, escalated every time.** Deduplication keeps the report
        bounded and readable; the policy is control flow for a caller who asked to be
        stopped, and a guard that disarms after firing once is not a guard.
        """
        warning = self._rewind_warning
        if warning is None or after >= before:
            return
        # A stream that cannot answer has no seek-point table to answer *from*, which for
        # a decompressing stream (the only kind that carries a RewindWarning at all — see
        # StoredCodec) means the decoder restarts at the origin. Falling back to 0 keeps
        # the index-less codecs — stdlib LZMA Alone, brotli, lz4 — reporting, which is
        # the behaviour this change must not lose while replacing the codec-name rule.
        resume = self.nearest_resume_offset(after) or 0
        distance = max(before - resume, warning.min_redecode_bytes)
        if distance < REWIND_REDECODE_WARN_BYTES:
            return
        context = StreamRewindContext(
            codec=warning.codec_name,
            from_offset=before,
            to_offset=after,
            accelerator=warning.accelerator,
        )
        message = self._rewind_message(warning, distance, resume, after)
        collector = resolve_collector(self._diagnostics_collector)
        if self._rewind_warned:
            collector.escalate_only(
                code=DiagnosticCode.STREAM_REWIND_REDECOMPRESSES,
                message=message,
                context=context,
            )
            return
        self._rewind_warned = True
        collector.emit(
            code=DiagnosticCode.STREAM_REWIND_REDECOMPRESSES,
            message=message,
            context=context,
            logger=logger,
        )

    @staticmethod
    def _rewind_message(
        warning: RewindWarning, distance: int, resume: int, target: int
    ) -> str:
        """The rewind report's text.

        It says where decoding resumes (``resume``, at or before ``target``), not what
        the codec can do: a multi-block ``.xz`` has resume points, and a seek can still
        land far past the nearest one. A codec with an accelerator adds a sentence
        about it after that.
        """
        cost = (
            f"Backward seek in a {warning.codec_name} stream discards {distance} "
            f"decompressed bytes; returning to the previous position re-decompresses "
            f"them"
        )
        if resume == 0:
            where = (
                "Decoding restarts from the start of the stream: no resume point is "
                "closer to the seek target."
            )
        elif resume == target:
            where = "Decoding restarts at the seek target, which is a resume point."
        else:
            where = (
                f"Decoding restarts from the nearest resume point, {target - resume} "
                f"bytes before the seek target."
            )
        if warning.accelerator is None:
            return f"{cost}. {where}"
        if warning.unused_reason:
            return (
                f"{cost}. {where} The '{warning.accelerator}' accelerator is not "
                f"available: {warning.unused_reason}."
            )
        if warning.suggest_install:
            return (
                f"{cost}. {where} Install the 'seekable' extra ({warning.accelerator}) "
                f"for indexed random access."
            )
        return (
            f"{cost}. {where} The '{warning.accelerator}' accelerator has no closer "
            f"resume point in its index (or was not engaged for this stream)."
        )

    def tell(self, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._inner is None:
            return 0
        if self._verifier is not None:
            return self._verifier.tell(self._inner)
        return self._inner.tell()

    def _hold_inner(self, wrap: Callable[[BinaryIO], BinaryIO]) -> None:
        """Serve the member through ``wrap(inner)`` (a ratio guard), before any read.

        A lazy handle wraps the inner stream when it opens it; an open one wraps it now.
        """
        assert self._inner_wrap is None, "the inner stream is already held"
        if self._inner is not None:
            self._inner = wrap(self._inner)
        else:
            self._inner_wrap = wrap

    def _make_forward_only(self) -> None:
        """Refuse ``seek()`` on this handle from now on, whatever it was built with.

        ``stream_members()`` calls this on every handle it yields: a pass owns the
        position, so its handles never seek, on any format, even when the reader
        declared ``seekable_members=True`` and the inner stream could seek.
        """
        self._seekable_hint = False

    def seekable(self) -> bool:
        # readable()/writable()/write() come from ReadOnlyIOStream.
        # Undeclared SEEKABLE forces forward-only even when the inner handle could seek
        # (directory uniformity / declared-capabilities contract).
        if self._seekable_hint is None:
            # Settled now, by asking the inner: no need to ask it twice.
            return self._seek_allowed()
        if not self._seekable_hint:
            return False
        if self._inner is not None:
            return is_seekable(self._inner)
        return True

    def close(self) -> None:
        if self.closed:
            return
        scope = getattr(self, "_diagnostics_scope", None)
        if scope is None:
            self._close()
            return
        stack = scope._collector.scope_stack()
        stack.append(scope)
        try:
            self._close()
        finally:
            leave_scope(stack, scope)

    def _close(self) -> None:
        # First: a read failing on another thread because this close is taking the
        # inner down raises the closed-file error (``_fail_unless_closed``).
        self._closing = True
        # The finally ensures the wrapper is marked closed even when the inner close
        # raises (which is re-raised translated): a half-open wrapper would hand out
        # further reads on a dead stream, and a retried close() would fail again
        # instead of no-opping (the guard above makes it a no-op instead).
        # Catch ``Exception`` (not ``BaseException``): KeyboardInterrupt/SystemExit must
        # still propagate; dual-failure grouping is for ordinary close/teardown errors.
        close_exc: Exception | None = None
        if self._seekable_hint is None:
            # Settled before the inner goes, so a seek after close() answers as it
            # would had the handle been asked when it was built.
            try:
                self._seek_allowed()
            except Exception:  # noqa: BLE001 - an inner that cannot say cannot seek
                self._seekable_hint = False
        try:
            inner = self._inner
            verifier = self._verifier
            if inner is not None:
                try:
                    if verifier is not None:
                        # Teardown only: finish_on_close just closes the inner — every
                        # content verdict fires from a read (ADR 0014). A teardown error
                        # from inner.close() (e.g. a subprocess exit code) still
                        # propagates via the translator below.
                        verifier.finish_on_close(inner)
                    else:
                        inner.close()
                except Exception as e:  # noqa: BLE001 - re-raised via the translator
                    try:
                        self._fail(e)
                    except Exception as translated:  # noqa: BLE001 - may be ArchiveyError
                        close_exc = translated
            # Never-opened lazy handle: skip verify (solid unread members must not
            # probe / force positioning).
        finally:
            super().close()
            # A closed stream raises the closed-file error before it looks at the
            # errors it kept. Their tracebacks refer to this stream, so keeping them
            # would leave the stream for the cycle collector.
            self._open_error = None
            self._open_error_tb = None
            self._verdict = None
            self._verdict_tb = None
            on_close = self._on_close
            self._on_close = None
            teardown_exc: Exception | None = None
            if on_close is not None:
                try:
                    on_close()
                except Exception as e:  # noqa: BLE001 - combine with close failure below
                    teardown_exc = e
            if close_exc is not None and teardown_exc is not None:
                raise ExceptionGroup(
                    "member-stream close and archive teardown both failed",
                    [close_exc, teardown_exc],
                )
            if close_exc is not None:
                raise close_exc
            if teardown_exc is not None:
                raise teardown_exc

    def __repr__(self) -> str:
        return f"<{type(self).__name__} inner={self._inner!r}>"


def raise_translated(
    e: Exception,
    translate: ExceptionTranslator,
    stamp: ErrorStamp = _noop_stamp,
    member_name: str | None = None,
) -> NoReturn:
    """Translate + stamp ``e`` and raise it, or re-raise it unchanged.

    The error boundary of :class:`ArchiveStream`, also for a caller that opens a codec
    before it builds the stream that will carry its translator
    (:func:`~archivey.internal.streams.codecs.registry.open_codec_raw`), so an open
    failure raises what the stream would have raised.
    """
    if isinstance(e, ArchiveyError):
        stamp(e)
        raise e
    translated_closed = as_closed_source_error(e, member_name)
    if translated_closed is not None:
        # The *inner* stream hit a closed handle underneath it — typically the
        # caller closed the BinaryIO they passed in. Mapped here, before the
        # per-library translator, so a backend's generic ValueError mapping cannot
        # claim it. The wrapper's own read-after-close never reaches _fail (plain
        # ValueError from _ensure_open). BaseArchiveReader._raise_translated maps
        # the same error raised while a member opens, with the same message.
        logger.debug("Translated exception: %r -> %r", e, translated_closed)
        raise translated_closed from e
    translated = translate(e)
    if translated is not None:
        stamp(translated)
        logger.debug("Translated exception: %r -> %r", e, translated)
        raise translated from e
    raise e


def compose_translators(
    inner: ExceptionTranslator, outer: ExceptionTranslator
) -> ExceptionTranslator:
    """A translator that asks ``inner`` first and ``outer`` when ``inner`` declines.

    The order a collapsed nested stream uses: the codec's own taxonomy before the
    reader's.
    """

    def composed(exc: Exception) -> ArchiveyError | None:
        translated = inner(exc)
        if translated is not None:
            return translated
        return outer(exc)

    return composed


def _is_content_verdict(error: BaseException) -> bool:
    """Whether ``error``, or an error it was raised from, says the data is damaged."""
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, CorruptionError):
            return True
        seen.add(id(current))
        current = current.__cause__
    return False
