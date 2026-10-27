"""Lifecycle diagnostic collector and emission path.

Owns exact counts, bounded retention (aggregate + member attachments), watermark-based
ranged snapshots, per-operation scopes, policy resolution, logging/callback delivery,
and RAISE escalation.

Memory is bounded by design: the only lifetime-retained structure is ``_retained``, which
is capped at ``max_retained``. Exact counts are kept as a small fixed per-code ``Counter``.
Ranged snapshots are computed by differencing a cheap :class:`DiagnosticWatermark` (a
sequence number plus a per-code count snapshot) against the live counters, and an
operation's snapshot (a member stream's, an extraction's) comes from its
:class:`DiagnosticScope`, which its owner holds: a per-code count of its own, and a tag on
the retained entries. So nothing grows with the number of emitted diagnostics, and
a scope lives as long as its stream or a retained entry that names it.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from archivey.diagnostics import (
    _INFO_LOG_CODES,
    Diagnostic,
    DiagnosticCode,
    DiagnosticContext,
    DiagnosticPolicy,
    DiagnosticSummary,
    OnDiagnostic,
    validate_code_context,
)
from archivey.exceptions import ArchiveyUsageError, DiagnosticRaisedError
from archivey.internal import logs

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig
    from archivey.types import ArchiveMember

T = TypeVar("T")


@dataclass(frozen=True)
class DiagnosticWatermark:
    """Opaque collector position: the sequence number plus per-code counts at capture time.

    Creating one copies no diagnostics and costs no retention slots. Ranged snapshots
    difference two watermarks (or a watermark against "now"), so the collector needs no
    per-emission log to answer "what happened since here".
    """

    _sequence: int
    _total: int
    _counts: Mapping[DiagnosticCode, int]


@dataclass
class _RetainedEntry:
    sequence: int
    diagnostic: Diagnostic
    # The scopes open on the emitting thread, for :meth:`DiagnosticScope.summary`.
    scopes: tuple[DiagnosticScope, ...] = ()


class DiagnosticScope:
    """The emits one operation makes, whatever other threads emit meanwhile.

    A watermark answers "what happened since here" for the whole collector, so on a
    reader used from several threads it also catches the other threads' emits. A
    scope counts only the emits made on a thread while the scope is entered there
    (:meth:`DiagnosticCollector.scoped`, :meth:`DiagnosticCollector.inside`). A
    member stream enters its scope on every call, from whichever thread makes it;
    ``extract_all()`` enters one for the whole call. Scopes nest: an emit counts in
    every scope entered on its thread.
    """

    __slots__ = ("_collector", "_counts", "_total")

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector
        self._total = 0
        # A plain dict, not a Counter: every member stream builds a scope, and a
        # Counter costs over ten times as much to build.
        self._counts: dict[DiagnosticCode, int] = {}

    def summary(self) -> DiagnosticSummary:
        """The emits counted so far: exact counts, and those still retained."""
        with self._collector._lock:
            total = self._total
            retained = tuple(
                e.diagnostic
                for e in self._collector._retained
                if any(scope is self for scope in e.scopes)
            )
            return DiagnosticSummary(
                total_count=total,
                counts=dict(self._counts),
                retained=retained,
                dropped_count=total - len(retained),
            )


class _ScopeBlock:
    """The context manager :meth:`DiagnosticCollector.inside` returns."""

    __slots__ = ("_scope", "_stack")

    def __init__(self, scope: DiagnosticScope) -> None:
        self._scope = scope
        self._stack: list[DiagnosticScope] = []

    def __enter__(self) -> DiagnosticScope:
        scope = self._scope
        self._stack = stack = scope._collector.scope_stack()
        stack.append(scope)
        return scope

    def __exit__(self, *exc_info: object) -> None:
        leave_scope(self._stack, self._scope)


def leave_scope(stack: list[DiagnosticScope], scope: DiagnosticScope) -> None:
    """Take ``scope`` off this thread's ``stack``, the last time it was entered."""
    if stack and stack[-1] is scope:
        stack.pop()
        return
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] is scope:
            del stack[i]
            return


@dataclass(slots=True)
class _EmitDetail:
    diagnostic: Diagnostic
    attached: bool


@dataclass(slots=True)
class EmitLog:
    """The emits one piece of repeatable work made, in order.

    ``DiagnosticCollector.replaying`` records into it the first time and replays it
    after. ``codes`` and ``raised`` (the exception an emit itself raised, by index) are
    what a replay matches and repeats. ``details`` keeps each emit's diagnostic and
    whether it was attached, for a repeat that must re-attach them, only until
    ``settle``: work whose result is kept, such as a member object a walk already
    built, carries its attachments itself and needs only the codes.
    """

    codes: list[DiagnosticCode] = field(default_factory=list)
    raised: dict[int, BaseException] | None = None
    details: list[_EmitDetail] | None = field(default_factory=list)

    def settle(self) -> None:
        """Drop the diagnostics, keeping what a replay matches against."""
        self.details = None

    def _truncate(self, at: int) -> None:
        del self.codes[at:]
        if self.details is not None:
            del self.details[at:]
        if self.raised is not None:
            self.raised = {i: exc for i, exc in self.raised.items() if i < at} or None


@dataclass(slots=True)
class _Replay:
    log: EmitLog
    cursor: int = 0


class _ReplayingBlock:
    """The context manager :meth:`DiagnosticCollector.replaying` returns."""

    __slots__ = ("_collector", "_log", "_thread_id")

    def __init__(self, collector: DiagnosticCollector, log: EmitLog) -> None:
        self._collector = collector
        self._log = log
        self._thread_id = 0

    def __enter__(self) -> None:
        collector = self._collector
        self._thread_id = thread_id = threading.get_ident()
        # No lock: see ``DiagnosticCollector._replays``.
        collector._replays[thread_id] = _Replay(self._log)

    def __exit__(self, *exc_info: object) -> None:
        self._collector._replays.pop(self._thread_id, None)


def nothing_held() -> Exception | None:
    """The pending-raise getter of a block that never holds anything."""
    return None


class _DeferringBlock:
    """The context manager :meth:`DiagnosticCollector.deferring_raises` returns."""

    __slots__ = ("_collector", "_held", "_nested", "_thread_id")

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector
        self._held: list[Exception] = []
        self._nested = True
        self._thread_id = 0

    def __enter__(self) -> Callable[[], Exception | None]:
        collector = self._collector
        self._thread_id = thread_id = threading.get_ident()
        with collector._lock:
            self._nested = nested = thread_id in collector._deferred
            self._held = collector._deferred.setdefault(thread_id, [])
        if nested:
            return nothing_held
        return self._first_held

    def _first_held(self) -> Exception | None:
        held = self._held
        return held[0] if held else None

    def __exit__(self, *exc_info: object) -> None:
        if not self._nested:
            collector = self._collector
            with collector._lock:
                collector._deferred.pop(self._thread_id, None)


class DiagnosticCollector:
    """One collector per detection / reader / top-level extract / standalone stream."""

    def __init__(
        self,
        *,
        policy: DiagnosticPolicy | None = None,
        max_retained: int = 256,
        on_diagnostic: OnDiagnostic | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if max_retained < 0:
            raise ValueError("max_retained_diagnostic_references must be >= 0")
        self._policy = policy if policy is not None else DiagnosticPolicy()
        self._max_retained = max_retained
        self._on_diagnostic = on_diagnostic
        self._logger = logger if logger is not None else logs.diagnostics
        self._lock = threading.RLock()
        self._sequence = 0
        self._total_count = 0
        self._counts: Counter[DiagnosticCode] = Counter()
        self._retained: list[_RetainedEntry] = []
        self._slots_used = 0
        # Thread ids currently inside a delivery (log/callback) step. Keyed per thread so
        # legitimate concurrent emits on separate threads do not read as reentrancy, while
        # a callback re-entering emit on its own thread still trips the guard.
        self._emitting_threads: set[int] = set()
        # Per thread, the log a ``replaying()`` block records into or replays from. Per
        # thread, so another thread's stream on the same reader is never replayed.
        # Used without ``_lock``: each thread sets, gets and pops only its own entry,
        # and a dict's single set, get or pop is atomic (free-threaded builds too). Any
        # other operation on it (iterating, ``len``, ``clear``) would need a lock that
        # every one of those accesses takes.
        self._replays: dict[int, _Replay] = {}
        # Per thread, the raises a ``deferring_raises()`` block is holding back.
        self._deferred: dict[int, list[Exception]] = {}
        # Per thread, the scopes entered on it, outermost first (``scope_stack``). A
        # ``threading.local`` and not a locked dict: a member stream enters its scope on
        # every read, and each thread touches only its own list.
        self._local = threading.local()

    def scope_stack(self) -> list[DiagnosticScope]:
        """This thread's entered scopes, for a caller that enters one on a hot path.

        Append the scope before the work and :func:`leave_scope` after it; that is
        what :meth:`inside` does, without the context manager object.
        """
        try:
            return self._local.stack
        except AttributeError:
            stack: list[DiagnosticScope] = []
            self._local.stack = stack
            return stack

    def new_scope(self) -> DiagnosticScope:
        return DiagnosticScope(self)

    def inside(self, scope: DiagnosticScope) -> _ScopeBlock:
        """Count this thread's emits in ``scope`` while inside the block."""
        return _ScopeBlock(scope)

    def scoped(self) -> _ScopeBlock:
        """Count this thread's emits in a new :class:`DiagnosticScope` while inside.

        For a call whose result reports its own diagnostics, such as
        ``extract_all()``: on a reader opened with ``concurrent_operations=True`` other
        threads emit into the same collector meanwhile, and a watermark would hand
        their emits to this call too.
        """
        return _ScopeBlock(DiagnosticScope(self))

    def replaying(self, log: EmitLog) -> _ReplayingBlock:
        """Record this thread's emits into ``log``, or replay the ones it already holds.

        For work a reader may have to repeat, such as a random-access member walk
        started over after a failure: run each piece inside ``replaying`` with its own
        log. The first run records every emit. A repeat takes its emits from the log in
        order: nothing is counted, retained, logged or called back again, a recorded
        attachment is made to the member the repeat passes (while the log still has its
        details), and an emit that raised the first time raises the same exception
        again, so the repeat takes the path the first run took. Emits past the end of
        the log are new; they go through and are recorded. An emit whose code differs
        from the recorded one means the work is not repeating itself: the log is cut
        there, and that emit and the ones after it are recorded in its place, so the log
        always describes the latest run.

        The block is a small class rather than a ``@contextmanager`` generator: a
        random-access member walk enters one per member, so on a large listing the
        generator machinery was a measurable share of the per-member cost.
        """
        return _ReplayingBlock(self, log)

    def call_replaying(self, log: EmitLog, work: Callable[[], T]) -> T:
        """Run ``work()`` inside :meth:`replaying` with ``log``, and return its result.

        The same block without a context manager object, for a caller that enters
        one per member of a large listing.
        """
        thread_id = threading.get_ident()
        replays = self._replays
        # No lock: see ``_replays``.
        replays[thread_id] = _Replay(log)
        try:
            return work()
        finally:
            replays.pop(thread_id, None)

    def deferring_raises(self) -> _DeferringBlock:
        """Hold back this thread's emit raises until the caller can take them.

        For code that emits from the middle of a state change it cannot unwind, such as
        a decompressor stream whose decoder reports a degraded seek index halfway
        through a read. Inside the block, an emit that would raise (a ``RAISE``
        disposition, ``escalate_as``, or an ``Exception`` out of ``on_diagnostic``)
        still counts, retains, logs and calls back, but hands the exception to the block
        instead of raising it. :meth:`escalate_only` hands its raise over the same way.
        The block calls the yielded function once its state is consistent and raises
        what it returns, the first exception held. A block raises once: an exception
        held after the first is dropped, the occurrence behind it having been evaluated
        and, if recorded, delivered.

        Nested blocks on one thread share the outermost one's list: an inner block's
        function returns ``None``, so the raise waits for the outermost caller, the
        one whose state change encloses the others. A ``BaseException`` that is not an
        ``Exception`` (``KeyboardInterrupt``) is never held.

        A small class rather than a ``@contextmanager`` generator, for the same reason
        as :meth:`replaying`: a decompressor stream enters one on every ``read``.
        """
        return _DeferringBlock(self)

    def _hold(self, thread_id: int, exc: BaseException) -> bool:
        """Hold ``exc`` for this thread's ``deferring_raises`` block, if one is open."""
        if not isinstance(exc, Exception):
            return False
        with self._lock:
            held = self._deferred.get(thread_id)
            if held is None:
                return False
            held.append(exc)
            return True

    @property
    def policy(self) -> DiagnosticPolicy:
        return self._policy

    @property
    def max_retained(self) -> int:
        return self._max_retained

    def watermark(self) -> DiagnosticWatermark:
        with self._lock:
            return DiagnosticWatermark(
                _sequence=self._sequence,
                _total=self._total_count,
                _counts=dict(self._counts),
            )

    def _summary_between(
        self,
        start_seq: int,
        start_total: int,
        start_counts: Mapping[DiagnosticCode, int],
        end_seq: int,
        end_total: int,
        end_counts: Mapping[DiagnosticCode, int],
    ) -> DiagnosticSummary:
        """Build a summary for the half-open range ``(start_seq, end_seq]``.

        Counts and totals are exact deltas of the two count snapshots; retained detail is
        filtered from the (bounded) retention list by sequence. The caller holds the lock.
        """
        total = end_total - start_total
        count_map: dict[DiagnosticCode, int] = {}
        for code, n in end_counts.items():
            delta = n - start_counts.get(code, 0)
            if delta:
                count_map[code] = delta
        retained = tuple(
            e.diagnostic for e in self._retained if start_seq < e.sequence <= end_seq
        )
        return DiagnosticSummary(
            total_count=total,
            counts=count_map,
            retained=retained,
            dropped_count=total - len(retained),
        )

    def snapshot(
        self, *, since: DiagnosticWatermark | None = None
    ) -> DiagnosticSummary:
        """Fresh immutable cumulative snapshot, or the delta since ``since``."""
        with self._lock:
            if since is None:
                return self._summary_between(
                    0, 0, {}, self._sequence, self._total_count, self._counts
                )
            return self._summary_between(
                since._sequence,
                since._total,
                since._counts,
                self._sequence,
                self._total_count,
                self._counts,
            )

    def emit(
        self,
        *,
        code: DiagnosticCode,
        message: str,
        context: DiagnosticContext,
        member: ArchiveMember | None = None,
        attach_to_member: bool = False,
        logger: logging.Logger | None = None,
        escalate_as: type[BaseException] | None = None,
        escalate_message: str | None = None,
        escalate_kwargs: dict[str, object] | None = None,
    ) -> Diagnostic:
        """Emit one diagnostic through the ordered policy matrix.

        Always increments exact counts. Under IGNORE, skips retention/log/callback.
        Under COLLECT/RAISE, retains (budget permitting), logs, and callbacks.
        Under RAISE (or when ``escalate_as`` is set), raises after delivery.

        ``escalate_as`` (e.g. :class:`~archivey.exceptions.CorruptionError` for a
        rejected TAR header) takes precedence over :class:`DiagnosticRaisedError` for the
        terminal exception after the delivery steps that ran for the disposition.

        It also raises **whatever the disposition is, ``IGNORE`` included**: it marks a
        condition the caller's policy cannot suppress, not merely a choice of exception
        type. Under ``IGNORE`` that means an exception with no log line and no callback
        behind it, only the count. A caller that wants the policy to decide should pass
        ``escalate_as`` only when the disposition is already ``RAISE``.
        """
        validate_code_context(code, context)
        ignored = code in self._policy.ignore
        raising = code in self._policy.raise_on
        log = logger if logger is not None else self._logger
        thread_id = threading.get_ident()

        with self._lock:
            replay = self._replays.get(thread_id)
            if replay is not None:
                emit_log = replay.log
                at = replay.cursor
                if at < len(emit_log.codes) and emit_log.codes[at] is code:
                    replay.cursor += 1
                    if emit_log.details is not None:
                        detail = emit_log.details[at]
                        replayed = detail.diagnostic
                        if (
                            detail.attached
                            and member is not None
                            and replayed not in member._diagnostics
                        ):
                            _attach_diagnostic(member, replayed)
                    else:
                        # A settled log kept no diagnostic; this one is recorded nowhere.
                        replayed = Diagnostic(
                            occurrence_id=uuid.uuid4().hex,
                            code=code,
                            message=message,
                            context=context,
                        )
                    if emit_log.raised is not None and at in emit_log.raised:
                        again = emit_log.raised[at]
                        # Raising an object adds the frames it passes to its traceback;
                        # clear it, or each repeat makes the stored exception's longer.
                        # ``ArchiveStream._raise_verdict`` keeps the first traceback
                        # instead, because it short-circuits without reaching the damage
                        # again. A replay re-runs the work up to this emit, so the
                        # current path is where this raise happens, and ``emit`` never
                        # regains control after the recording raise to capture its
                        # traceback.
                        again.__traceback__ = None
                        if not self._hold(thread_id, again):
                            raise again
                    return replayed
                emit_log._truncate(at)
            if thread_id in self._emitting_threads:
                raise ArchiveyUsageError(
                    "Diagnostic callback/reentrancy: cannot drive another operation on "
                    "the same reader/stream while a diagnostic is being emitted."
                )
            self._sequence += 1
            sequence = self._sequence
            diagnostic = Diagnostic(
                occurrence_id=uuid.uuid4().hex,
                code=code,
                message=message,
                context=context,
            )
            self._total_count += 1
            self._counts[code] += 1
            open_scopes = getattr(self._local, "stack", None)
            scopes: tuple[DiagnosticScope, ...] = ()
            if open_scopes:
                scopes = tuple(open_scopes)
                for scope in scopes:
                    scope._total += 1
                    scope._counts[code] = scope._counts.get(code, 0) + 1

            retained_aggregate = False
            attached = False
            if not ignored:
                if self._slots_used < self._max_retained:
                    self._retained.append(
                        _RetainedEntry(
                            sequence=sequence, diagnostic=diagnostic, scopes=scopes
                        )
                    )
                    self._slots_used += 1
                    retained_aggregate = True
                if (
                    retained_aggregate
                    and attach_to_member
                    and member is not None
                    and self._slots_used < self._max_retained
                ):
                    _attach_diagnostic(member, diagnostic)
                    self._slots_used += 1
                    attached = True
            logged_at: int | None = None
            if replay is not None:
                emit_log = replay.log
                logged_at = len(emit_log.codes)
                emit_log.codes.append(code)
                if emit_log.details is not None:
                    emit_log.details.append(_EmitDetail(diagnostic, attached))
                replay.cursor = logged_at + 1

            if not ignored:
                self._emitting_threads.add(thread_id)

        try:
            if not ignored:
                level = logging.INFO if code in _INFO_LOG_CODES else logging.WARNING
                log.log(
                    level,
                    "%s",
                    diagnostic.message,
                    extra={
                        "diagnostic_code": code,
                        "diagnostic_occurrence_id": diagnostic.occurrence_id,
                    },
                )
                if self._on_diagnostic is not None:
                    try:
                        self._on_diagnostic(diagnostic)
                    except Exception as exc:
                        if not self._hold(thread_id, exc):
                            raise
            # Only the raise this emit makes is part of what a replay repeats; one out of
            # the logger or the callback, a KeyboardInterrupt included, is not.
            raised: BaseException | None = None
            if escalate_as is not None:
                msg = escalate_message if escalate_message is not None else message
                kwargs = escalate_kwargs if escalate_kwargs is not None else {}
                raised = escalate_as(msg, **kwargs)
            elif raising:
                raised = DiagnosticRaisedError(message, diagnostic=diagnostic)
            if raised is not None:
                if replay is not None and logged_at is not None:
                    # Recorded by index, for a replay to raise at the same emit.
                    if replay.log.raised is None:
                        replay.log.raised = {}
                    replay.log.raised[logged_at] = raised
                if not self._hold(thread_id, raised):
                    raise raised
        finally:
            with self._lock:
                self._emitting_threads.discard(thread_id)

        return diagnostic

    def escalate_only(
        self,
        *,
        code: DiagnosticCode,
        message: str,
        context: DiagnosticContext,
    ) -> None:
        """Evaluate ``code``'s policy and raise on ``RAISE`` — recording nothing.

        Inside a :meth:`deferring_raises` block the raise is handed to the block
        instead, which raises at most once.

        For a diagnostic that is *recorded* at most once per stream but whose policy must
        be honoured on every occurrence. Deduplication keeps the report bounded and
        readable; escalation is control flow for a caller who explicitly asked to be
        stopped, and a guard that disarms after firing once is not a guard.

        This is the rule for **every** once-per-stream code (see ``diagnostics``), not a
        per-code exception. The dedup bookkeeping stays with the emitter, which is what
        knows the scope; this collector only knows the policy.

        Nothing is counted, retained, logged or called back, so a caller reading
        ``reader.diagnostics`` sees exactly the one record the first occurrence left. The
        raised error still carries a full :class:`Diagnostic` value describing *this*
        occurrence — the caller being stopped should see the seek that stopped them, not
        the first one.
        """
        validate_code_context(code, context)
        if code not in self._policy.raise_on:
            return
        raised = DiagnosticRaisedError(
            message,
            diagnostic=Diagnostic(
                occurrence_id=uuid.uuid4().hex,
                code=code,
                message=message,
                context=context,
            ),
        )
        if not self._hold(threading.get_ident(), raised):
            raise raised


def _attach_diagnostic(member: ArchiveMember, diagnostic: Diagnostic) -> None:
    """Append a diagnostic to a member's attached tuple (library retention slot)."""
    current = member._diagnostics
    object.__setattr__(member, "_diagnostics", current + (diagnostic,))


def collector_from_config(config: ArchiveyConfig) -> DiagnosticCollector:
    """Build a collector from an :class:`~archivey.config.ArchiveyConfig`."""
    return DiagnosticCollector(
        policy=config.diagnostic_policy,
        max_retained=config.max_retained_diagnostic_references,
        on_diagnostic=config.on_diagnostic,
    )


def resolve_collector(collector: DiagnosticCollector | None) -> DiagnosticCollector:
    """Return ``collector``, or a throwaway collector built from library defaults.

    Used at emission sites that may not have a reader/stream-owned collector threaded
    through. What falls through to the throwaway:

    - is judged by the **library default** policy, not the caller's, so a caller on
      ``DiagnosticPolicy.STRICT`` does not get the raise it asked for;
    - never reaches ``reader.diagnostics`` or the caller's ``on_diagnostic`` callback.
      Only the log record survives.

    Codec streams get the caller's collector through ``StreamConfig.collector``, which
    :func:`~archivey.internal.streams.codecs.open_codec_stream` fills from its
    ``collector`` argument (except a stored stream source, whose codec emits nothing:
    there the collector reaches only the returned stream). A caller that builds a codec stream without one (the
    single-file reader's listing-time size probe, detection, direct stream tests) still
    lands here. Prefer passing the shared collector wherever one exists.

    The fallback logs at DEBUG on ``archivey.diagnostics`` with the caller's
    ``file:line`` (``stacklevel=2``). An application or test that enables DEBUG on
    that logger sees which site dropped the collector; with the default levels the
    record is not emitted.
    """
    if collector is not None:
        return collector
    logs.diagnostics.debug(
        "No diagnostic collector was passed; this emission uses a throwaway "
        "collector under the library default policy",
        stacklevel=2,
    )
    from archivey.config import DEFAULT_ARCHIVEY_CONFIG

    return collector_from_config(DEFAULT_ARCHIVEY_CONFIG)


__all__ = [
    "DiagnosticCollector",
    "DiagnosticWatermark",
    "collector_from_config",
    "resolve_collector",
]
