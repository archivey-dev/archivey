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

``_closing`` is set once a ``close()`` has passed its checks, and stays set while it drains
in-flight workers (a wait that only happens under ``CONCURRENT``; a default reader has
refused the close instead). New calls are refused from then on, and other closers wait
for the transition.
"""

from __future__ import annotations

import enum
import gc
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
    kind: str = "root"  # "root" | "child" | "worker"
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
    a second materializer waits for the first one's snapshot, and ``close()`` drains
    in-flight worker calls. A pass (``stream_members()``, ``extract_all()``,
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
        self._workers_cv = threading.Condition(self._lock)
        self._close_cv = threading.Condition(self._lock)
        self.cache_state = CacheState.UNMATERIALIZED
        self.lifecycle = LifecycleState.OPEN
        self._closing = False
        # The one reader-wide pass or default-reader lookup in progress, if any.
        self._root: OperationToken | None = None
        self._children: set[OperationToken] = set()
        self._workers: set[OperationToken] = set()
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
        # left), keyed BY THREAD: the exemption from the live-stream gate and from
        # worker rejection applies only to the thread that entered the window. A plain
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

        Inside one, this thread's opens pass the live-stream gate and the same-thread
        re-entry check, and its worker calls go under the pass this thread works for,
        when there is one (:meth:`_owner_pass_locked`; see ``_internal_open_threads``).
        Leave it with :meth:`end_internal_opens`.
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
        """Take the token for a reader-wide pass named ``name`` (or, inside this thread's
        internal-open window, a child of the pass it works for), or raise the usage
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
        """Acquire a pass token: root when free, else a child under an internal owner."""
        with self._lock:
            self._require_admissible_locked(name)
            internal = self._internal_opens_active_locked()
            owner = self._owner_pass_locked() if internal else None
            if owner is not None:
                child = OperationToken(name=name, parent=owner, kind="child")
                self._children.add(child)
                return child
            if not internal:
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
        is open. A pass pins at admission and again once its startup has run, before
        its first member. A child token pins on the pass it is filed under
        (``verify_all()``'s and ``extract_all()``'s nested passes): the peek answers
        from the root."""
        with self._lock:
            root = token if token.kind == "root" else token.parent
            if root is not None and root is self._root and not root._released:
                root.report = report

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
        """Mark a generator-held pass as suspended at a yield, or running again."""
        with self._lock:
            token.suspended = suspended

    def resume(self, token: OperationToken, op: str) -> None:
        """A pass is running again after its yield, and the reader must still be open:
        ``set_suspended(token, False)`` and ``require_open(op)`` under one lock, since
        a pass runs this once per member."""
        with self._lock:
            token.suspended = False
            self._require_admissible_locked(op)

    def set_pass_closer(
        self, token: OperationToken, closer: Callable[[], None] | None
    ) -> None:
        """Record how ``close()`` winds down this pass if it is suspended at a yield."""
        with self._lock:
            token.pass_closer = closer

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
        """End a pass, once. The children filed under the pass go with it."""
        with self._lock:
            if token._released:
                return
            token._released = True
            if token.parent is not None or token.kind == "child":
                self._children.discard(token)
                return
            if self._root is token:
                self._root = None
            self._children = {c for c in self._children if c.parent is not token}

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
        with self._lock:
            if child._released:
                return
            child._released = True
            self._children.discard(child)

    def acquire_worker(self, name: str) -> OperationToken:
        """Take a short-lived token for one call: see :meth:`_acquire_worker_once`.
        Release it with :meth:`release_worker`."""
        return _retry_after_collecting(self._acquire_worker_once, name)

    def _acquire_worker_once(self, name: str) -> OperationToken:
        """Short-lived token for random ``open()`` / ``read()``.

        Rejected while a reader-wide pass is active, in both modes, unless under
        library-internal opens. Idle open streams (leases only) do not block workers.
        Stream I/O after this token is released does not re-check the gate.
        """
        with self._lock:
            self._require_admissible_locked(name)
            internal = self._internal_opens_active_locked()
            if not internal:
                self._reject_same_thread_reentry_locked(f"call {name!r}")
            if self._root is not None and not internal:
                raise _overlap_refused(
                    f"Cannot call {name!r}: another reader operation "
                    f"({self._root.name!r}) is already active."
                )
            # Inside a library-internal window (a first-touch link-data read), the
            # OWNING THREAD's worker opens are admitted as children of the pass it
            # works for; other threads are rejected above.
            owner = self._owner_pass_locked() if internal else None
            if owner is not None:
                token = OperationToken(name=name, parent=owner, kind="child")
                self._children.add(token)
                return token
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
            if not self._internal_opens_active_locked():
                # Inside a library-internal window (a first-touch link-data read), the
                # library's own call is not re-entry.
                self._reject_same_thread_reentry_locked(f"call {name!r}")
            token = OperationToken(name=name, kind="worker")
            self._workers.add(token)
            return token, None

    def release_worker(self, token: OperationToken) -> None:
        with self._lock:
            if token._released:
                return
            token._released = True
            if token.kind == "child" or token.parent is not None:
                self._children.discard(token)
                return
            self._workers.discard(token)
            # Only a draining close() waits on this condition, and it sets ``_closing``
            # before it waits. Every open() releases a worker, so the notify is skipped
            # when no close can be waiting.
            if not self._workers and self._closing:
                self._workers_cv.notify_all()

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
                # The lifecycle only, not ``_closing``: a caller here already holds
                # its token, and a close() draining in-flight workers waits for this
                # one to finish, so refusing it would turn that wait into an error.
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
        """Consume ``token``, recording ``id(stream)`` as the live stream.

        Infallible: no lifecycle re-check. ``open()`` still holds a worker across
        reserve → open → bind, so ``close()`` cannot complete in between. Does not
        increment the lease — the reservation already holds it.
        """
        ref = weakref.ref(stream)
        with self._lock:
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
        """Mark reader closed and release the reader lease. True → run teardown now.

        Under ``MemberStreams.CONCURRENT``, blocks until in-flight worker ``open()`` /
        ``get()`` / ``members()`` calls return (``read()`` while it opens the member),
        then transitions to closed. A member stream's own reads hold no worker token.
        Escaped idle member streams keep their lifecycle leases and do not block close.
        A worker that never returns is a caller bug (same as any lock); there is no
        artificial timeout.

        Without ``CONCURRENT``, overlapping worker calls still raise
        :class:`~archivey.exceptions.ArchiveyUsageError`, as does a reader-wide pass
        that is executing. A pass whose generator is suspended at a yield does not
        block: the reader closes under it. Concurrent double-``close()`` is
        idempotent: one thread drains and closes; others wait for that transition and
        return without running teardown again.
        """
        with self._lock:
            while True:
                # First, before any wait: a thread closing from INSIDE one of its own
                # calls (a diagnostic/progress callback calling close()) would wait
                # forever for a call that cannot return until close() does, and the
                # generic messages below would send the user looking for a second
                # caller that does not exist.
                token = self._same_thread_token_locked()
                if token is not None:
                    raise ArchiveyUsageError(
                        "Cannot close the archive reader from inside one of its own "
                        f"calls ({token.name!r}; e.g. from a diagnostic or progress "
                        "callback). Callbacks must not close the reader that "
                        "triggered them."
                    )
                # Before either wait below: from inside a password provider (its
                # thread or a copied context), waiting for the operation that waits
                # on the provider, or for a closer that waits on that operation,
                # never ends.
                for token in (*self._passes_locked(), *self._workers):
                    self.refuse_wait_on_provider(token.thread.ident)
                # Another closer is draining, or close already finished.
                if self._closing or self.lifecycle is not LifecycleState.OPEN:
                    while self.lifecycle is LifecycleState.OPEN and self._closing:
                        self._close_cv.wait()
                    if self.lifecycle is LifecycleState.READER_CLOSED:
                        # A closer interrupted between the transition and its lease
                        # drop left the reader's lease counted. Finish the drop here.
                        return self._drop_reader_lease_locked()
                    if self.lifecycle is LifecycleState.OPEN:
                        # The draining closer was interrupted (its except arm below
                        # reset ``_closing``), so nothing closed the reader. Returning
                        # False would tell close() a peer had, and it would then mark
                        # itself closed with teardown never run. Retry as the closer.
                        # Invariant: False is returned only when lifecycle is not OPEN.
                        continue
                    return False
                # A pass suspended at a yield is not running: the caller holds its
                # iterator. Close anyway, as zipfile.ZipFile.close() does with member
                # handles open; resuming that iterator then raises. Only a pass that
                # is executing refuses the close.
                running = self._executing_pass_locked()
                if running is not None:
                    raise ArchiveyUsageError(
                        "Cannot close the archive reader while another reader "
                        f"operation ({running.name!r}) is active."
                    )
                if self._workers and not self.concurrent:
                    raise ArchiveyUsageError(
                        "Cannot close the archive reader while an open()/get()/read() call "
                        "is still in progress."
                    )
                self._closing = True
                try:
                    # No pass can start or resume meanwhile: a pass is refused
                    # beside a worker, a worker beside a pass, and ``_closing``
                    # refuses new calls.
                    while self._workers:
                        self._workers_cv.wait()
                    # Notify last. If an interrupt lands after the transition but
                    # before the lease drop, the retry branch above finishes the drop.
                    self.lifecycle = LifecycleState.READER_CLOSED
                    # In the same lock hold as the decision above (taken again after
                    # any wait), so a suspended pass cannot resume and release
                    # itself in between. The lease keeps teardown back until
                    # close() has run the closers: the backend's pass cleanup must
                    # come before the source is closed.
                    for token in self._passes_locked():
                        if token.pass_closer is not None:
                            # Lease first: an interrupt between the stores leaves a
                            # lease that close() drops, never a closer without a lease.
                            self._pass_wind_down_lease = True
                            self._pass_wind_down.append(token.pass_closer)
                            token.pass_closer = None
                    run_teardown = self._drop_reader_lease_locked()
                    self._close_cv.notify_all()
                    return run_teardown
                except BaseException:
                    self._closing = False
                    self._close_cv.notify_all()
                    raise

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
            if self._outstanding_leases_locked() > 0:
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

    def _teardown_due_locked(self) -> bool:
        return (
            self.lifecycle is LifecycleState.READER_CLOSED
            and self._outstanding_leases_locked() == 0
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
        """Lifecycle is still OPEN (including during draining close)."""
        if self.lifecycle is not LifecycleState.OPEN:
            raise ArchiveyUsageError(
                f"{op} is not available after the archive reader has been closed."
            )

    def _require_admissible_locked(self, op: str) -> None:
        """Reject new public admissions after close started or finished."""
        if self.lifecycle is not LifecycleState.OPEN or self._closing:
            raise ArchiveyUsageError(
                f"{op} is not available after the archive reader has been closed."
            )
