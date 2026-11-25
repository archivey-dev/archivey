"""Whether a reader call is allowed right now, and who cleans up afterwards.

This module holds no archive data and does no I/O. ``BaseArchiveReader`` asks it two
kinds of question: "may this call start?" (and, if not, which usage error to raise, or
whether to wait) and "am I the one who must close the archive now?". Every method is a
transition on, or a test of, four independent pieces of state:

- **Who owns the reader.** ``_root`` is the reader-wide pass in progress (``members()``
  on a default reader, ``stream_members()``, ``extract_all()``), ``_children`` are
  library-internal scopes under a pass (link reads, the extraction coordinator's own
  opens), and ``_workers`` are short ``open()`` / ``get()`` calls, and ``read()`` while
  it opens the member (and, on a ``CONCURRENT`` reader, ``members()`` /
  ``members_report()``). A pass has the reader to itself in both modes: no worker and
  no other pass runs beside it, and a data pass does not start beside a stream from
  ``open()``. Each is an :class:`OperationToken` that records the thread that took it,
  so a callback that re-enters the reader on that thread gets a message about the
  callback, not about a second caller.
- **Whether the member list exists yet** (``cache_state``). See :class:`ReaderState`.
- **How many member streams are alive** (``_live_streams``, plus ``_reservations`` for
  an ``open()`` that has passed the gate but not built its stream yet). The streams a
  ``stream_members()`` pass hands out are in neither: the pass has the reader to
  itself.
- **How far the close has got** (``lifecycle`` and the leases), below.

Leases, and why teardown is separate from close
-----------------------------------------------

Marking the reader closed does not close the archive. A lease is held by whatever still
reads through the source: the reader itself (one lease, from construction until
``close()``, kept as ``_reader_lease_held``), each live ``open()`` stream or reservation
(counted in ``_lease_count``; a pass's streams take none, as the pass's token keeps the
source open until the pass ends or is wound down), and a ``stream_members()`` pass that
``close()`` found suspended at a yield (one lease, ``_pass_wind_down_lease``, from the
close transition until ``close()`` has wound the pass down and closed the streams; a
flag for the same reason as the reader's). The underlying file handle or ``unrar`` /
``7z`` process is torn down by whoever drops the **last** lease. ``close()`` drops the
reader's lease first and then closes the still-open member streams, so with streams open
the last lease usually goes with the last stream's close, not with the reader's. That is
why :meth:`ReaderState.mark_reader_closed` and :meth:`ReaderState.release_live_stream`
both return "run teardown now", and why :meth:`ReaderState.claim_teardown` makes sure
only one caller acts on it. Teardown always follows the streams, never runs under one::

    OPEN --mark_reader_closed()--> READER_CLOSED --claim_teardown()--> TEARDOWN_RUNNING
         (drops the reader's lease)                 (lease count 0; succeeds once)
    TEARDOWN_RUNNING --complete_teardown()--> TEARDOWN_COMPLETE

A running call holds teardown back too, without a lease: a worker, a child scope, or a
pass that is not suspended at a yield (``_running_locked``). ``close()`` never waits for
one and never refuses because of one, in either mode: it marks the reader closed and
returns. The running call stops at its next checkpoint with the closed error, and the
last call out runs the reader's teardown (``teardown_hook``).
"""

from __future__ import annotations

import enum
import gc
import sys
import threading
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from archivey.exceptions import ArchiveyUsageError
from archivey.internal.callback_scope import callback_depth
from archivey.types import MemberStreams

if TYPE_CHECKING:
    from collections.abc import Callable

    from archivey.diagnostics import MemberListReport
    from archivey.internal.open_site import OpenSite
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl


T = TypeVar("T")
_P = ParamSpec("_P")

# A dropped pass or member stream releases what it held here only when it is freed.
# CPython usually frees it at once, when its last reference goes (the end of a ``for``
# loop left with ``break``, ``reader.open(m).read()``), but not when it sits in a
# reference cycle: then it waits for the cycle collector. PyPy frees every dropped
# object only at a later collection. Until then the next call would be refused as
# overlapping something nobody can reach, at a moment memory pressure decides.
# ``_retry_after_collecting`` runs that cleanup before it lets such a refusal stand.
_OVERLAP_MARK = "_archivey_overlap_refusal"


def _overlap_refused(message: str) -> ArchiveyUsageError:
    """A refusal because other work holds the reader: one that a dropped pass or
    stream can be behind, so a collection may clear it.

    It is a plain :class:`ArchiveyUsageError`, as the docs promise for an overlap; a
    private mark on the instance tells :func:`_retry_after_collecting` it may retry. A
    closed reader or a callback re-entry raises an unmarked one, which no collection
    clears."""
    exc = ArchiveyUsageError(message)
    setattr(exc, _OVERLAP_MARK, True)
    return exc


_CLOSED_MARK = "_archivey_reader_closed"


def closed_reader_error(op: str) -> ArchiveyUsageError:
    """The error a call on a closed reader raises, marked so the reader's teardown on
    the way out can tell it from any other error (it becomes the teardown error's
    ``__cause__`` holder, not a note)."""
    exc = ArchiveyUsageError(
        f"{op} is not available after the archive reader has been closed."
    )
    setattr(exc, _CLOSED_MARK, True)
    return exc


def is_closed_reader_error(exc: BaseException) -> bool:
    return getattr(exc, _CLOSED_MARK, False)


def _call_name(token: OperationToken) -> str:
    """The public call ``token`` runs for, as an error names it: a nested pass is
    named after the call it is filed under (``extract_all()``, ``verify_all()``), not
    after its own ``stream_members``."""
    root = token.parent if token.parent is not None else token
    return f"{root.name}()"


def _retry_after_collecting(
    attempt: Callable[_P, T], *args: _P.args, **kwargs: _P.kwargs
) -> T:
    """``attempt(*args)``; refused for an overlap, ``attempt`` again after a collection
    has run the cleanup of passes and streams already dropped.

    This runs on every interpreter, so whether a call is refused depends only on
    whether the earlier pass or stream is still reachable, never on when a collection
    happened to run. The collection runs only on that refusal, outside the state lock
    (the cleanup takes it). A refusal that still holds afterwards is a real overlap
    and raises.
    """
    try:
        return attempt(*args, **kwargs)
    except ArchiveyUsageError as exc:
        if not getattr(exc, _OVERLAP_MARK, False):
            raise
    gc.collect()
    return attempt(*args, **kwargs)


class PassKind(enum.Enum):
    """What a reader-wide token is for: see :meth:`ReaderState.acquire_pass`."""

    # A default reader's lookup call (``members()``, a random-access listing): the
    # token makes the list build single-owner. Not a pass in the sense of the docs.
    LOOKUP = "lookup"
    # A pass that lists only: streaming iteration, a streaming ``members_report()``.
    LIST = "list"
    # A pass that reads member data: ``stream_members()``, ``extract_all()``,
    # ``verify_all()``. It also refuses to start beside a stream from ``open()``.
    DATA = "data"


class CacheState(enum.Enum):
    """Whether the member list is built: not yet (or the last attempt failed), being
    built by one elected caller, or published."""

    UNMATERIALIZED = "unmaterialized"
    MATERIALIZING = "materializing"
    MATERIALIZED = "materialized"


class LifecycleState(enum.Enum):
    """How far ``close()`` has got: the states of the module docstring's diagram."""

    OPEN = "open"
    READER_CLOSED = "reader_closed"
    TEARDOWN_RUNNING = "teardown_running"
    TEARDOWN_COMPLETE = "teardown_complete"


class _Refused(enum.Enum):
    REFUSED = enum.auto()


# What :meth:`ReaderState.enter_stream_call` answers once the reader is closed.
REFUSED = _Refused.REFUSED


@dataclass(eq=False)
class LiveStreamReservation:
    """Opaque live-stream slot reservation.

    Disjoint from ``id()`` values in ``_live_streams``. A reservation must never
    be stored in that map: ``release_live_stream_id`` reasons about id reuse, and
    a synthetic int dropped in there would be mistakable for a stream.
    """


@dataclass(eq=False)
class OperationToken:
    """Unforgeable root, child, or short-lived worker operation-owner token."""

    name: str
    parent: OperationToken | None = None
    kind: str = "root"  # "root" | "child" | "worker" | "info"
    # The thread that acquired the token. Used to detect same-thread re-entry (a
    # diagnostic/progress callback driving the reader that is mid-operation on this very
    # thread), which must raise a usage error instead of deadlocking on a wait for itself.
    # The Thread object, not ``get_ident()``: idents are reused once a thread exits, and
    # a token can outlive its thread (a generator holding a pass is never closed), which
    # would misdiagnose a fresh thread with the same ident as re-entering.
    # ``_materializing_thread`` and ``_internal_open_threads`` stay idents: both are
    # cleared in ``finally`` on the thread that set them, so neither outlives it.
    thread: threading.Thread = field(
        default_factory=threading.current_thread, repr=False
    )
    # True while the generator holding this pass (``stream_members()``, streaming
    # ``__iter__``) is suspended at a yield. Its thread is then running the caller's
    # loop body, so a call from that thread is not re-entry from a callback and
    # ``_same_thread_token_locked`` skips the token. While the generator is executing a
    # step (where a diagnostic callback fires) the flag is False and the token counts.
    # Set with :meth:`ReaderState.set_suspended`, and cleared by :meth:`ReaderState.resume`
    # when a pass comes back from its yield. A suspended pass also does not block
    # ``close()``: the reader closes and the pass is wound down (see ``pass_closer``).
    suspended: bool = field(default=False, repr=False)
    # Winds down a ``stream_members()`` pass: closes the stream the caller may still
    # hold (nothing else closes it, as a pass's streams are not registered), then the
    # format's own member iterator, whose ``finally`` releases pass-scoped resources (a
    # solid block, an ``unrar`` pipe). When ``close()`` closes
    # the reader under a pass suspended at a yield, :meth:`ReaderState.mark_reader_closed`
    # hands it over together with a lease, so teardown waits until it has run. Set with
    # :meth:`ReaderState.set_pass_closer`, under the lock like ``suspended``.
    pass_closer: Callable[[], None] | None = field(default=None, repr=False)
    # What a root token is for (:class:`PassKind`); ``None`` for a child or worker.
    pass_kind: PassKind | None = field(default=None, repr=False)
    # The member-list report a pass pinned (``pin_report``): what
    # ``members_report_if_available()`` answers while the pass is open, or ``None``.
    report: MemberListReport | None = field(default=None, repr=False)
    # The exception the acquiring thread was handling when the token was taken (the
    # caller's own ``except`` block around the call), or ``None``. The teardown hook
    # tells "this call is raising" from "this call returns inside its caller's
    # ``except``" by comparing it with the exception in flight at the release.
    entry_exc: BaseException | None = field(
        default_factory=sys.exception, repr=False, compare=False
    )
    # Set by the first startup pin (``pin_report``) under this root: a later pass
    # filed under it (``extract_all()``'s held-source pass) runs after members were
    # processed, so it pins nothing.
    startup_pinned: bool = field(default=False, repr=False)
    _released: bool = field(default=False, repr=False)


class ReaderState:
    """Per-reader concurrency and lifecycle bookkeeping (see the module docstring).

    **Materialization** means building the member list, once. A reader does not list the
    archive when it is opened. The first call that needs members (``members()``,
    ``open()``, ``get()``) walks the whole archive and publishes one immutable snapshot,
    which every later call reads. :meth:`begin_materialization` elects the caller that
    does the walk: it returns ``True`` to that caller and ``False`` to one for whom the
    snapshot already exists. The three :class:`CacheState` values are before, during and
    after that walk.

    **The default path is the strict one.** Without ``MemberStreams.CONCURRENT``
    (``concurrent_operations=True``) this class mostly refuses: one live member stream, one
    reader-wide operation, no overlapping worker calls, and no shared-handle locks
    needed. ``CONCURRENT`` turns those refusals into waits: several live streams,
    and a second materializer waits for the first one's snapshot. ``close()`` never
    waits, in either mode. A pass (``stream_members()``, ``extract_all()``,
    ``verify_all()``, a streaming listing) has the reader to itself in both modes.
    Access to one stream stays single-owner (caller-synchronized) either way.
    """

    def __init__(
        self,
        *,
        member_streams: MemberStreams,
        open_site: OpenSite | None,
    ) -> None:
        self.member_streams = member_streams
        # The two flags as plain attributes: a ``Flag`` membership test costs about
        # half a microsecond, and every member stream asks several times.
        self.concurrent = MemberStreams.CONCURRENT in member_streams
        self.seekable = MemberStreams.SEEKABLE in member_streams
        self.open_site = open_site
        # Set by a reader whose plugin asks the caller's password provider: whether
        # this context is inside that provider call running on a given thread
        # (``_PasswordCandidates.in_provider_call_on``). A wait for an operation that
        # thread owns would then wait for the provider that waits for it.
        self.provider_reentry: Callable[[int | None], bool] | None = None
        self._lock = threading.RLock()
        self._materialization_cv = threading.Condition(self._lock)
        self.cache_state = CacheState.UNMATERIALIZED
        self.lifecycle = LifecycleState.OPEN
        # Run, outside the lock, by the call that leaves last after a close: the
        # reader sets it to a weak reference to its teardown
        # (``BaseArchiveReader._teardown_after_call``), so the state does not keep the
        # reader alive. Called, it gives the hook, or ``None`` once the reader is gone.
        self.teardown_hook: (
            Callable[[], Callable[[BaseException | None], None] | None] | None
        ) = None
        # The one reader-wide pass or default-reader lookup in progress, if any.
        self._root: OperationToken | None = None
        self._children: set[OperationToken] = set()
        self._workers: set[OperationToken] = set()
        # Live ``info`` calls (:meth:`enter_info`): counted like a worker, so teardown
        # waits for them, but no worker token, so they are admitted wherever ``info``
        # is (a pass's loop body, another thread beside a pass).
        self._info_calls: set[OperationToken] = set()
        # Member-stream calls running now (:meth:`enter_stream_call`), by thread
        # ident: each one's depth. They hold teardown and the physical close of every
        # stream back, as reader calls do: under the flag a plugin's streams share one
        # handle lock, so closing an idle stream beside a running read would wait for
        # that read (and deadlock, from a callback inside it). Idents, not threads:
        # each entry is cleared on the thread that made it, in a ``finally``.
        self._stream_calls: dict[int, int] = {}
        # Open public member streams: ``id(stream)`` to a weak reference, in the order
        # they were registered. ``reader.close()`` closes them in that order
        # (:meth:`live_streams`). Weak, so this map never keeps a dropped stream alive:
        # a dropped stream's ``close()`` runs from ``IOBase.__del__`` and releases its
        # entry (:meth:`release_live_stream_id`).
        self._live_streams: dict[int, weakref.ref[ArchiveStreamImpl]] = {}
        self._reservations: set[LiveStreamReservation] = set()
        # Leases of live streams and reservations only.
        self._lease_count = 0
        # The reader's own lease, held until close. Read by _outstanding_leases_locked
        # rather than folded into ``_lease_count``, so dropping it is one store: there
        # is no second write for an interrupt to separate it from, and a close
        # interrupted before that store is finished by the next mark_reader_closed().
        self._reader_lease_held = True
        self._teardown_claimed = False
        # The stream-shutdown claim (see :meth:`claim_stream_shutdown`): the ticket of
        # the close() that holds it, and whether that close() finished the step. An
        # interrupted holder hands the claim back, so the next close() retakes it.
        self._stream_shutdown_owner: object | None = None
        self._stream_shutdown_done = False
        # The suspended passes' ``pass_closer``s, handed over by the close transition
        # with one lease for all of them; see :meth:`take_pass_wind_down`. Like the
        # reader's lease, that lease is a flag read by _outstanding_leases_locked, so
        # taking and dropping it are one store each, and it is tracked apart from the
        # closer so close() can drop it even when an interrupt lost the closer. Only the
        # holder of the stream-shutdown claim drops it, in
        # :meth:`finish_stream_shutdown`; that is a close() or, after an interrupted
        # one, the suspended pass's own finally.
        self._pass_wind_down: list[Callable[[], None]] = []
        self._pass_wind_down_lease = False
        # Library-internal open windows (first-touch link-data reads, the one user
        # left), keyed BY THREAD: the exemption from the live-stream gate (the window's
        # only effect) applies only to the thread that entered the window. A plain
        # reader-wide depth counter would silently admit a *foreign* thread's open()
        # during the window on a non-CONCURRENT reader — and on backends without a
        # shared-handle lock the interleaved seek+read pairs then serve wrong member
        # bytes instead of the loud error this gate exists to raise.
        # Each thread's open windows, as the callback depth each was entered at
        # (``callback_scope``): a window is active only at that depth, so a caller's
        # callback run inside it does not inherit the exemption.
        self._internal_open_threads: dict[int, list[int]] = {}
        # The thread that currently owns the materialization election, for same-thread
        # re-entry detection.
        self._materializing_thread: int | None = None

    def require_open(self, op: str) -> None:
        with self._lock:
            self._require_admissible_locked(op)

    def begin_internal_opens(self) -> None:
        """Enter a library-internal open window on this thread; windows nest.

        Inside one, this thread's opens pass the live-stream gate
        (``_refuse_second_stream_locked``; see ``_internal_open_threads``), and
        nothing else: admission (a pass, a worker call, a peek) never looks at the
        window, so code the library runs inside it that is not its own (a callback, an
        application's logging handler) gets no exemption from the re-entry and
        overlap checks. Leave it with :meth:`end_internal_opens`.
        """
        tid = threading.get_ident()
        depth = callback_depth()
        with self._lock:
            self._internal_open_threads.setdefault(tid, []).append(depth)

    def end_internal_opens(self) -> None:
        tid = threading.get_ident()
        with self._lock:
            windows = self._internal_open_threads.get(tid)
            if windows:
                windows.pop()
            if not windows:
                self._internal_open_threads.pop(tid, None)

    def _internal_opens_active_locked(self) -> bool:
        """Whether the CURRENT thread is inside a library-internal open window, and
        not inside a caller's callback the library ran from it."""
        windows = self._internal_open_threads.get(threading.get_ident())
        return bool(windows) and windows[-1] == callback_depth()

    def _owner_pass_locked(self) -> OperationToken | None:
        """The pass a library-internal scope opened on this thread belongs to: the one
        pass, if any.

        At most one pass runs, in both modes, and no other call runs beside it, so a
        library-internal scope (a first-touch link-data read) can only be
        working for it. The generator holding it may be resumed on a thread other than
        the one that took it, so the thread is not checked.
        """
        return self._root

    def acquire_pass(
        self,
        name: str,
        kind: PassKind = PassKind.LOOKUP,
        report: Callable[[], MemberListReport | None] | None = None,
    ) -> OperationToken:
        """Take the token for a reader-wide pass named ``name``, or raise the usage
        error that says why it cannot start. Release it with :meth:`release_pass`.

        A pass has the reader to itself: it is refused beside another pass and beside a
        worker call in flight, in both modes, and a ``DATA`` pass also beside a member
        stream from ``open()``. ``report`` builds what the pass pins at admission
        (:meth:`pin_report`). It runs under the state lock once the pass is granted,
        so nothing can publish between the snapshot and the grant (a publisher holds a
        worker or pass token) and a refusal builds nothing. It must take no lock but
        leaf locks (the diagnostics collector's), never the walk lock."""
        return _retry_after_collecting(self._acquire_pass_once, name, kind, report)

    def _acquire_pass_once(
        self,
        name: str,
        kind: PassKind,
        report: Callable[[], MemberListReport | None] | None,
    ) -> OperationToken:
        """Acquire a root pass token, or raise why the pass cannot start."""
        with self._lock:
            self._require_admissible_locked(name)
            self._reject_same_thread_reentry_locked(f"start {name!r}")
            if self._root is not None:
                raise _overlap_refused(
                    f"Cannot start {name!r}: another reader operation "
                    f"({self._root.name!r}) is already active."
                )
            if self._workers:
                raise _overlap_refused(
                    f"Cannot start {name!r}: a concurrent open()/get()/read() call is "
                    "still in progress."
                )
            if kind is PassKind.DATA and (self._live_streams or self._reservations):
                raise _overlap_refused(
                    f"Cannot start {name!r}: a member stream from open() is still "
                    "open on this reader. Close it first."
                )
            token = OperationToken(name=name, kind="root", pass_kind=kind)
            self._root = token
            if report is not None:
                try:
                    token.report = report()
                except BaseException:
                    self._root = None
                    raise
            return token

    def acquire_child(self, parent: OperationToken, name: str) -> OperationToken:
        """A child scope named ``name`` under ``parent``, a pass the caller holds and
        names: for a library call nested in its own pass (``verify_all()``'s stream
        pass and report). Unlike an internal-open window, it covers that one call
        only, so a callback on the thread is still refused as re-entry. Release it
        with :meth:`release_pass`."""
        with self._lock:
            self._require_admissible_locked(name)
            assert parent is self._root, (parent, self._root)
            child = OperationToken(name=name, parent=parent, kind="child")
            self._children.add(child)
            return child

    def pin_report(
        self, token: OperationToken, report: MemberListReport | None
    ) -> None:
        """Set what ``members_report_if_available()`` answers while ``token``'s pass
        is open, once its startup has run and before its first member (a pass also
        pins at admission). A child token pins on the pass it is filed under
        (``verify_all()``'s and ``extract_all()``'s nested passes): the peek answers
        from the root. Only the first startup under a root pins: a later nested pass
        runs after members were processed, and the peek answers the same throughout
        the pass."""
        with self._lock:
            root = token if token.kind == "root" else token.parent
            if (
                root is not None
                and root is self._root
                and not root._released
                and not root.startup_pinned
            ):
                root.report = report
                root.startup_pinned = True

    def pin_owner_report(self, report: MemberListReport | None) -> None:
        """:meth:`pin_report` for the pass this thread works for, if any."""
        with self._lock:
            root = self._root
            if root is not None and not root._released:
                root.report = report

    def _passes_locked(self) -> tuple[OperationToken, ...]:
        """The active reader-wide pass, as a tuple of zero or one."""
        return () if self._root is None else (self._root,)

    def _executing_pass_locked(self) -> OperationToken | None:
        """The active pass if it is not suspended at a yield."""
        root = self._root
        return root if root is not None and not root.suspended else None

    def set_suspended(self, token: OperationToken, suspended: bool) -> None:
        """Mark a generator-held pass as suspended at a yield, or running again.

        Suspending is a checkpoint: on a closed reader it raises the closed error
        instead, so a pass that was running when ``close()`` came stops before it hands
        out another member, and its own ``finally`` winds it down. Unsuspending never
        raises (it runs on the way out of a yield that raised)."""
        with self._lock:
            if suspended:
                self._require_lifecycle_open_locked(_call_name(token))
            token.suspended = suspended

    def resume(self, token: OperationToken, op: str) -> None:
        """A pass is running again after its yield, and the reader must still be open:
        ``set_suspended(token, False)`` and ``require_open(op)`` under one lock, since
        a pass runs this once per member."""
        with self._lock:
            token.suspended = False
            self._require_admissible_locked(_call_name(token) if token.parent else op)

    def set_pass_closer(
        self, token: OperationToken, closer: Callable[[], None] | None
    ) -> None:
        """Record how ``close()`` winds down this pass if it is suspended at a yield."""
        with self._lock:
            token.pass_closer = closer

    def keep_own_closer(self, token: OperationToken) -> bool:
        """Whether the pass still winds itself down: ``close()`` did not take its
        closer (the reader is open, or the pass was running when it closed). Takes the
        closer, so it is decided once."""
        with self._lock:
            if token.pass_closer is None:
                return False
            token.pass_closer = None
            return True

    def take_pass_wind_down(self) -> Callable[[], None] | None:
        """Winds down the passes the close transition found suspended, each once.

        The transition also took a lease for them, so teardown cannot be claimed until
        the holder of the stream-shutdown claim has run this and called
        :meth:`finish_stream_shutdown`. ``None`` when no suspended pass had a closer,
        or an earlier, interrupted ``close()`` ran them all. The returned callable
        takes each closer out before running it, so a run that an interrupt cuts short
        leaves the rest to the next one. Several failures raise one
        ``ExceptionGroup``.
        """
        with self._lock:
            if not self._pass_wind_down:
                return None
            return self._run_pass_wind_downs

    def _run_pass_wind_downs(self) -> None:
        errors: list[Exception] = []
        while True:
            with self._lock:
                if not self._pass_wind_down:
                    break
                closer = self._pass_wind_down.pop(0)
            try:
                closer()
            except Exception as exc:  # noqa: BLE001 - raised below, together
                errors.append(exc)
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise ExceptionGroup("winding down several passes failed", errors)

    def release_pass(self, token: OperationToken) -> None:
        """End a pass, once. The children filed under the pass go with it. The last
        call out after a close runs the teardown hook."""
        with self._lock:
            if token._released:
                return
            token._released = True
            if token.parent is not None or token.kind == "child":
                self._children.discard(token)
            else:
                if self._root is token:
                    self._root = None
                self._children = {c for c in self._children if c.parent is not token}
            due = self._cleanup_due_locked()
        if due:
            self._run_teardown_hook(token)

    def _run_teardown_hook(self, token: OperationToken) -> None:
        self._run_hook(token.entry_exc)

    def _run_hook(self, entry_exc: BaseException | None) -> None:
        ref = self.teardown_hook
        hook = ref() if ref is not None else None
        if hook is not None:
            hook(entry_exc)

    def enter_child_scope(self, name: str) -> OperationToken | None:
        """A child scope under the pass this thread works for, or ``None`` if no pass.

        Picks the pass and files the child in one lock hold, so the pass cannot end
        between the two.
        """
        with self._lock:
            owner = self._owner_pass_locked()
            if owner is None:
                return None
            child = OperationToken(name=name, parent=owner, kind="child")
            self._children.add(child)
            return child

    def release_child(self, child: OperationToken) -> None:
        self.release_worker(child)

    def acquire_worker(self, name: str) -> OperationToken:
        """Take a short-lived token for one call: see :meth:`_acquire_worker_once`.
        Release it with :meth:`release_worker`."""
        return _retry_after_collecting(self._acquire_worker_once, name)

    def _acquire_worker_once(self, name: str) -> OperationToken:
        """Short-lived token for random ``open()`` / ``read()``.

        Rejected while a reader-wide pass is active, in both modes. Idle open
        streams (leases only) do not block workers.
        Stream I/O after this token is released does not re-check the gate.
        """
        with self._lock:
            self._require_admissible_locked(name)
            self._reject_same_thread_reentry_locked(f"call {name!r}")
            if self._root is not None:
                raise _overlap_refused(
                    f"Cannot call {name!r}: another reader operation "
                    f"({self._root.name!r}) is already active."
                )
            token = OperationToken(name=name, kind="worker")
            self._workers.add(token)
            return token

    def acquire_peek(
        self, name: str
    ) -> tuple[OperationToken | None, MemberListReport | None]:
        """Admit ``members_report_if_available()``: ``(token, None)``, or
        ``(None, report)`` while a pass is open.

        While a pass is open (from its loop body, a callback on its thread or, under
        ``CONCURRENT``, another thread), the peek answers the report the pass pinned and
        reads nothing, so it takes no token. Otherwise it is a lookup call: it refuses a
        closed reader and a callback's re-entry, and takes a worker token, released
        with :meth:`release_worker`. Both in one lock hold, so a pass cannot start or
        end between the test and the token.
        """
        with self._lock:
            self._require_admissible_locked(name)
            root = self._root
            if root is not None and root.pass_kind is not PassKind.LOOKUP:
                return None, root.report
            self._reject_same_thread_reentry_locked(f"call {name!r}")
            token = OperationToken(name=name, kind="worker")
            self._workers.add(token)
            return token, None

    def enter_info(self, op: str) -> OperationToken | None:
        """Admit a live ``info`` call: its token, or ``None`` when this thread is
        inside a call of the reader (a callback), where ``info`` answers the published
        snapshot instead and enters no backend code.

        A callback can run while a plugin method holds the plugin's handle lock (a
        source read inside ``open_member()``, or under a member stream's read), and a
        live ``archive_info()`` would wait for that lock. The running call it is
        inside already holds teardown back. Raises the closed error after
        ``close()``. Release with :meth:`release_worker`.
        """
        with self._lock:
            self._require_admissible_locked(op)
            current = threading.current_thread()
            if (
                self._same_thread_token_locked() is not None
                or threading.get_ident() in self._stream_calls
                or any(t.thread is current for t in self._info_calls)
            ):
                return None
            token = OperationToken(name=op, kind="info")
            self._info_calls.add(token)
            return token

    def enter_stream_call(self) -> BaseException | None | _Refused:
        """Count a member-stream call (a read, seek, ``verify()``...) that may touch
        the stream's inner layers. ``REFUSED`` once ``close()`` has come: the stream
        is closed to new calls, though its inner close waits for the last call out.
        Otherwise the exception this thread is handling, for
        :meth:`exit_stream_call`."""
        with self._lock:
            if self.lifecycle is not LifecycleState.OPEN:
                return REFUSED
            ident = threading.get_ident()
            calls = self._stream_calls
            calls[ident] = calls.get(ident, 0) + 1
        return sys.exception()

    def enter_stream_close(
        self, *, finalizing: bool
    ) -> BaseException | None | _Refused:
        """Count a member stream's own ``close()`` as a stream call
        (:meth:`enter_stream_call`), so a ``reader.close()`` meanwhile defers its
        shutdown to it. ``REFUSED`` once the reader is closed: the shutdown then owns
        the stream's inner close.

        A close from inside a stream call on this thread is a callback's (a source
        read's ``on_source_read`` inside a read of this stream or of a sibling, which
        may hold the shared handle lock): it raises ``ArchiveyUsageError`` before it
        takes any lock, instead of closing the decoder under the read or deadlocking.
        ``finalizing``: the collector's close of a dropped stream, never refused.
        """
        with self._lock:
            ident = threading.get_ident()
            if ident in self._stream_calls and not finalizing:
                raise ArchiveyUsageError(
                    "A member stream cannot be closed from a callback that runs inside "
                    "a read of a stream of the same reader. To stop the read, close "
                    "the reader."
                )
            if self.lifecycle is not LifecycleState.OPEN:
                return REFUSED
            calls = self._stream_calls
            calls[ident] = calls.get(ident, 0) + 1
        return sys.exception()

    def claim_stream_close(self, stream: ArchiveStreamImpl) -> bool:
        """True for the one caller that does ``stream``'s inner close: two
        ``close()`` calls at once, or a ``close()`` and the reader's shutdown, never
        both reach it."""
        with self._lock:
            if stream._close_claimed:
                return False
            stream._close_claimed = True
            return True

    def closing(self) -> bool:
        """Whether ``close()`` has started, read without the lock: a checkpoint's
        fast path (:meth:`check_open`), which a stale ``False`` only delays."""
        return self.lifecycle is not LifecycleState.OPEN

    def exit_stream_call(self, entry_exc: BaseException | None) -> None:
        """End a call :meth:`enter_stream_call` counted. The last call out after a
        ``close()`` runs the teardown hook: the deferred stream closes, the pass
        wind-down, then teardown."""
        with self._lock:
            ident = threading.get_ident()
            calls = self._stream_calls
            depth = calls[ident] - 1
            if depth:
                calls[ident] = depth
            else:
                del calls[ident]
            due = self._cleanup_due_locked()
        if due:
            self._run_hook(entry_exc)

    def release_worker(self, token: OperationToken) -> None:
        """Release a worker (or child) token, once. The last call out after a close
        runs the teardown hook."""
        with self._lock:
            if token._released:
                return
            token._released = True
            if token.kind == "child" or token.parent is not None:
                self._children.discard(token)
            elif token.kind == "info":
                self._info_calls.discard(token)
            else:
                self._workers.discard(token)
            due = self._cleanup_due_locked()
        if due:
            self._run_teardown_hook(token)

    def begin_materialization(self) -> bool:
        """Elect a materialization owner or wait for a published snapshot.

        Returns ``True`` if the caller must perform materialization (and later call
        :meth:`complete_materialization` or :meth:`fail_materialization`). Returns
        ``False`` if the immutable snapshot is already published (including after
        waiting under ``CONCURRENT``).

        Under ``MemberStreams.CONCURRENT``, a second caller that overlaps an in-progress
        materialization blocks on a condition until the snapshot is published or the
        attempt fails (then re-elects). Without ``CONCURRENT``, overlapping materialization
        still raises :class:`~archivey.exceptions.ArchiveyUsageError`. Uncontended paths
        take the elect-and-run branch with no wait.
        """
        with self._lock:
            while True:
                # A checkpoint: after a close, a waiter stops here instead of building.
                self._require_lifecycle_open_locked("materialization")
                if self.cache_state is CacheState.MATERIALIZED:
                    return False
                if self.cache_state is CacheState.MATERIALIZING:
                    if self._materializing_thread == threading.get_ident():
                        # Same-thread re-entry: a diagnostic/progress callback fired
                        # during materialization called back into the reader. Waiting
                        # would deadlock this thread on a notify only it can send; a
                        # non-CONCURRENT reader would raise the generic message below,
                        # which misdiagnoses the situation.
                        raise ArchiveyUsageError(
                            "Reader re-entered while it is materializing its member "
                            "list on this same thread (e.g. from a diagnostic or "
                            "progress callback). Callbacks must not call back into "
                            "the reader that triggered them."
                        )
                    if not self.concurrent:
                        raise ArchiveyUsageError(
                            "Cannot start materialization: another materialization is "
                            "already in progress."
                        )
                    self.refuse_wait_on_provider(self._materializing_thread)
                    self._materialization_cv.wait()
                    continue
                # UNMATERIALIZED — elect this caller.
                self.cache_state = CacheState.MATERIALIZING
                self._materializing_thread = threading.get_ident()
                return True

    def complete_materialization(self) -> None:
        with self._lock:
            self.cache_state = CacheState.MATERIALIZED
            self._materializing_thread = None
            self._materialization_cv.notify_all()

    def fail_materialization(self) -> None:
        with self._lock:
            if self.cache_state is CacheState.MATERIALIZING:
                self.cache_state = CacheState.UNMATERIALIZED
                self._materializing_thread = None
                self._materialization_cv.notify_all()

    def reserve_live_stream(self) -> LiveStreamReservation:
        return _retry_after_collecting(self._reserve_live_stream_once)

    def _reserve_live_stream_once(self) -> LiveStreamReservation:
        """Take a live-stream lease before the stream object exists.

        Raises :class:`~archivey.exceptions.ArchiveyUsageError` under the same
        rules as :meth:`acquire_live_stream` (including the concurrent / internal-open
        bypass). The lease is held until :meth:`bind_live_stream` or
        :meth:`release_reservation`.
        """
        with self._lock:
            self._admit_live_stream_locked()
            token = LiveStreamReservation()
            self._reservations.add(token)
            return token

    def _admit_live_stream_locked(self) -> None:
        """The live-stream gate: refuse a second stream, or take a lease for one."""
        self._require_lifecycle_open_locked("open()")
        self._refuse_second_stream_locked()
        self._lease_count += 1

    def _refuse_second_stream_locked(self) -> None:
        if not (self.concurrent or self._internal_opens_active_locked()) and (
            self._live_streams or self._reservations
        ):
            site = self.open_site
            loc = site.location if site is not None else "<unknown>"
            raise _overlap_refused(
                "A member stream is already open on this reader. Close it "
                "before opening another, or reopen the archive with "
                "concurrent_operations=True "
                f"(this archive was opened without concurrent_operations at {loc})."
            )

    def bind_live_stream(
        self, token: LiveStreamReservation, stream: ArchiveStreamImpl
    ) -> None:
        """Consume ``token``, recording ``id(stream)`` as the live stream: the point
        where the stream is published.

        Re-checks the lifecycle: a ``close()`` that came after the reservation finds
        no live stream to close, so here the reservation is dropped and the closed
        error raised; the caller closes the new stream. A close after a bind closes
        the registered stream like any other. Does not increment the lease — the
        reservation already holds it.
        """
        ref = weakref.ref(stream)
        with self._lock:
            if self.lifecycle is not LifecycleState.OPEN:
                if token in self._reservations:
                    self._reservations.discard(token)
                    self._release_lease_locked()
                raise closed_reader_error("open()")
            self._reservations.discard(token)
            self._live_streams[id(stream)] = ref

    def release_reservation(self, token: LiveStreamReservation) -> bool:
        """Drop an unbound reservation. True → the caller should run teardown.

        Idempotent: a token already bound or released is a no-op.
        """
        with self._lock:
            if token not in self._reservations:
                return False
            self._reservations.discard(token)
            return self._release_lease_locked()

    def acquire_live_stream(self, stream: ArchiveStreamImpl) -> None:
        """Register a public member stream; enforce the single-live-stream gate.

        The gate and the record of reserve-then-bind, in one step, for a caller that
        has its stream already (the extraction coordinator re-opening a retyped
        member); the eager ``open()`` path reserves first. Both share the gate check
        (``_admit_live_stream_locked``). A pass's streams do not come here: the pass
        has the reader to itself, and a data pass refused to start beside a live
        stream (:meth:`acquire_pass`).
        """
        ref = weakref.ref(stream)
        _retry_after_collecting(self._acquire_live_stream_once, stream, ref)

    def _acquire_live_stream_once(
        self, stream: ArchiveStreamImpl, ref: weakref.ref[ArchiveStreamImpl]
    ) -> None:
        with self._lock:
            self._admit_live_stream_locked()
            self._live_streams[id(stream)] = ref

    def release_live_stream(self, stream: ArchiveStreamImpl) -> bool:
        """Release a stream lease. Returns True if the caller should run teardown."""
        return self.release_live_stream_id(id(stream))

    def release_live_stream_id(self, sid: int) -> bool:
        """Release a stream lease by identity token.

        Separate from :meth:`release_live_stream` so a stream's close hook can hold
        the token instead of the stream: a hook that held the stream would keep a
        dropped stream alive, and its ``close()`` would then never run. Safe against
        id reuse: the token is removed when the stream closes, and the interpreter
        runs ``close()`` on a dropped stream (``IOBase.__del__``) before its memory
        can be handed to another object.
        """
        with self._lock:
            if self._live_streams.pop(sid, None) is None:
                return False
            return self._release_lease_locked()

    def live_streams(self) -> list[ArchiveStreamImpl]:
        """The registered member streams not yet released, in registration order."""
        with self._lock:
            refs = list(self._live_streams.values())
        return [stream for ref in refs if (stream := ref()) is not None]

    def mark_reader_closed(self) -> bool:
        """Mark the reader closed and drop the reader's lease. True → run teardown now.

        Never waits and never refuses, in either mode, whoever is running a call and
        from whatever thread (a callback of the reader's own call included). From here
        on every new call raises the closed error, and a running call stops at its next
        checkpoint (:meth:`set_suspended`, :meth:`resume`, :meth:`check_open`). A call
        still running holds teardown back: the last one out runs the teardown hook
        (:meth:`release_worker`, :meth:`release_pass`). A pass suspended at a yield is
        not running; its closer is handed to ``close()`` with a lease, so the backend's
        pass cleanup comes before teardown. A second call returns ``False`` unless an
        interrupted first one left the reader's lease to drop.
        """
        with self._lock:
            if self.lifecycle is LifecycleState.OPEN:
                self.lifecycle = LifecycleState.READER_CLOSED
                root = self._root
                if root is not None and root.suspended and root.pass_closer is not None:
                    # Lease first: an interrupt between the stores leaves a lease that
                    # close() drops, never a closer without a lease.
                    self._pass_wind_down_lease = True
                    self._pass_wind_down.append(root.pass_closer)
                    root.pass_closer = None
            return self._drop_reader_lease_locked()

    def check_open(self, op: str) -> None:
        """A checkpoint inside a running call: raise the closed error if ``close()``
        has come since the call started."""
        if self.lifecycle is not LifecycleState.OPEN:
            with self._lock:
                self._require_lifecycle_open_locked(op)

    def claim_stream_shutdown(self, ticket: object) -> bool:
        """True for the one caller that should wind the pass down and close live streams.

        The same shape as :meth:`claim_teardown`, and needed for the same reason.
        ``mark_reader_closed`` returns ``False`` both for "I performed the transition
        but leases remain" and for "a peer had already closed", so its return value
        cannot identify the thread that owns stream shutdown. Without this guard two
        concurrent ``close()`` calls both walk the stream registry — and
        ``ArchiveStream.close`` tests ``self.closed`` outside its lock, so both can
        reach ``inner.close()`` on the same stream. A backend that is not re-entrant on
        close (rapidgzip especially) would be entered twice.

        ``ticket`` is an object the calling ``close()`` made for itself; the claim is
        held by storing it, one store. :meth:`finish_stream_shutdown` spends the claim
        for good: a ``close()`` whose wind-down or stream shutdown raises an
        ``Exception`` still finishes, and the step is not retried. An interrupt is
        different: the ``close()`` hands the claim back with
        :meth:`abandon_stream_shutdown`, so the next caller of the step retakes it
        and drops the pass wind-down lease that the interrupted one still held: a later
        ``close()``, or the suspended pass's own ``finally`` when its iterator is
        closed or collected.
        """
        with self._lock:
            if self._stream_shutdown_done or self._stream_shutdown_owner is not None:
                return False
            if self._running_locked():
                # Deferred: no inner close runs beside a running call. The last call
                # out claims it (:meth:`_cleanup_due_locked`).
                return False
            self._stream_shutdown_owner = ticket
            return True

    def finish_stream_shutdown(self, ticket: object) -> None:
        """Spend the claim ``ticket`` holds and drop the pass wind-down lease.

        A no-op unless ``ticket`` holds the claim. The lease is dropped before the
        claim is marked spent: an interrupt between the two leaves a claim that
        :meth:`abandon_stream_shutdown` hands back, never a spent claim with the
        lease still held.
        """
        with self._lock:
            if self._stream_shutdown_owner is not ticket:
                return
            self._pass_wind_down = []
            self._pass_wind_down_lease = False
            self._stream_shutdown_done = True

    def stream_shutdown_done(self) -> bool:
        """Whether the stream-shutdown step finished and its claim is spent."""
        with self._lock:
            return self._stream_shutdown_done

    def lifecycle_is_open(self) -> bool:
        """Whether the reader is still open: ``close()`` has not started its transition."""
        with self._lock:
            return self.lifecycle is LifecycleState.OPEN

    def abandon_stream_shutdown(self, ticket: object) -> None:
        """Hand back the claim ``ticket`` holds, unless it was spent. For an interrupt.

        The pass wind-down lease, and the closer if nobody took it, stay: the next
        ``close()``, or the pass's own ``finally``, retakes the claim, runs what is
        left and drops the lease.
        """
        with self._lock:
            if self._stream_shutdown_owner is ticket and not self._stream_shutdown_done:
                self._stream_shutdown_owner = None

    def claim_teardown(self) -> bool:
        """True for the one caller that should run teardown now: the reader is closed,
        no lease is left, and nobody claimed it before. Finish with
        :meth:`complete_teardown`."""
        with self._lock:
            if self._teardown_claimed:
                return False
            # ``_teardown_claimed`` is set one line before the lifecycle moves to
            # TEARDOWN_RUNNING and is never reset, so READER_CLOSED is the only state
            # a claim can succeed from.
            if self.lifecycle is not LifecycleState.READER_CLOSED:
                return False
            if self._outstanding_leases_locked() > 0 or self._running_locked():
                return False
            self._teardown_claimed = True
            self.lifecycle = LifecycleState.TEARDOWN_RUNNING
            return True

    def complete_teardown(self) -> None:
        """Mark teardown finished. A teardown failure is the caller's to propagate
        (``_maybe_teardown`` raises it, alone or in an ``ExceptionGroup``); the state
        machine keeps no copy — a stored-but-never-surfaced error would be a silent
        swallow path."""
        with self._lock:
            self.lifecycle = LifecycleState.TEARDOWN_COMPLETE

    def _drop_reader_lease_locked(self) -> bool:
        """Drop the reader's own lease, once. True → the caller should run teardown."""
        if not self._reader_lease_held:
            return False
        self._reader_lease_held = False
        return self._teardown_due_locked()

    def _release_lease_locked(self) -> bool:
        """Drop one stream or reservation lease. True → the caller should run teardown."""
        if self._lease_count > 0:
            self._lease_count -= 1
        return self._teardown_due_locked()

    def _outstanding_leases_locked(self) -> int:
        return (
            self._lease_count
            + (1 if self._reader_lease_held else 0)
            + (1 if self._pass_wind_down_lease else 0)
        )

    def _running_locked(self) -> bool:
        """Whether a call is still running: a worker, a child scope, a live ``info``,
        a member-stream call, or a pass that is not suspended at a yield. Each holds
        teardown and the stream closes back."""
        root = self._root
        return bool(
            self._workers
            or self._children
            or self._info_calls
            or self._stream_calls
            or (root is not None and not root.suspended)
        )

    def _cleanup_due_locked(self) -> bool:
        """Whether the call leaving now is the last one out after a ``close()``: it
        then runs the hook, which does what ``close()`` deferred (the stream closes and
        the pass wind-down, :meth:`claim_stream_shutdown`) and then teardown."""
        return (
            self.lifecycle is LifecycleState.READER_CLOSED
            and not self._running_locked()
            and not self._teardown_claimed
        )

    def _teardown_due_locked(self) -> bool:
        return (
            self.lifecycle is LifecycleState.READER_CLOSED
            and self._outstanding_leases_locked() == 0
            and not self._running_locked()
            and not self._teardown_claimed
        )

    def refuse_wait_on_provider(self, owner: int | None) -> None:
        """Raise instead of waiting for an operation ``owner`` (a thread ident) runs,
        when this call comes from inside the password provider that operation is
        waiting for (``provider_reentry``)."""
        check = self.provider_reentry
        if check is not None and check(owner):
            raise ArchiveyUsageError(
                "Password provider reentered the archive reader that is waiting for "
                "its answer. Return a password (or None) without calling back into "
                "archivey from the provider."
            )

    def _same_thread_token_locked(self) -> OperationToken | None:
        """A token this thread holds while inside a reader call, if any.

        Any hit means the current call is re-entry from inside one of the reader's own
        calls on this thread: in practice a diagnostic or progress callback. A pass whose
        generator is suspended at a yield is skipped (see
        :attr:`OperationToken.suspended`).
        """
        current = threading.current_thread()
        for token in (*self._passes_locked(), *self._children, *self._workers):
            if token.thread is current and not token.suspended:
                return token
        return None

    def _reject_same_thread_reentry_locked(self, action: str) -> None:
        """Raise the re-entry usage error before the generic overlap messages.

        It runs first because on a non-``CONCURRENT`` reader the overlap message
        ("another reader operation is already active") would answer a callback's
        re-entry by pointing at a second caller that does not exist.
        """
        token = self._same_thread_token_locked()
        if token is not None:
            raise ArchiveyUsageError(
                f"Cannot {action}: the reader was re-entered from inside its own "
                f"{token.name!r} call on this same thread (e.g. from a diagnostic or "
                "progress callback). Callbacks must not call back into the reader "
                "that triggered them."
            )

    def _require_lifecycle_open_locked(self, op: str) -> None:
        """Raise the closed error unless the lifecycle is still OPEN."""
        if self.lifecycle is not LifecycleState.OPEN:
            raise closed_reader_error(op)

    def _require_admissible_locked(self, op: str) -> None:
        """Reject new public admissions after close."""
        self._require_lifecycle_open_locked(op)
