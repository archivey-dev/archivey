"""Public read-only archive interface."""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from collections.abc import Callable, Collection, Generator, Iterator
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Self, TypeVar

from archivey.config import ExtractionLimits
from archivey.cost import CostReceipt
from archivey.detection import FormatInfo
from archivey.diagnostics import DiagnosticSummary, ExtractionReport, MemberListReport
from archivey.exceptions import ArchiveyUsageError
from archivey.types import (
    AbortOn,
    AbortOnStr,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    ExtractionPolicy,
    ExtractionPolicyStr,
    ExtractionProgress,
    MemberFilter,
    MemberSelectorArg,
    OnError,
    OnErrorStr,
    OverwritePolicy,
    OverwritePolicyStr,
)

if TYPE_CHECKING:
    from archivey.internal.streams.archive_stream import ArchiveStream

# ``types.MemberSelectorArg`` is the one definition; this is its public name.
MemberSelector = MemberSelectorArg
"""Which members :meth:`~archivey.ForwardArchiveReader.stream_members` and
:meth:`~archivey.ForwardArchiveReader.extract_all` act on. One of:

- an iterable of member names (``str``) and :class:`~archivey.ArchiveMember` objects,
  read once, so a generator works. A name selects every member with exactly that name
  (a directory is ``"dir/"``); an ``ArchiveMember`` selects that member only, by
  identity. A bare ``str`` is refused: pass ``["name"]`` for one member;
- a predicate ``Callable[[ArchiveMember], bool]`` that returns ``True`` for the members
  to select;
- ``None``, for all members.
"""


_T = TypeVar("_T")


class MemberPass(Iterator[_T]):
    """A pass over an archive's members: an iterator that can also be closed, directly
    or by a ``with`` block.

    :meth:`~ForwardArchiveReader.stream_members` returns one that yields
    ``(member, stream)`` pairs, and iterating the reader returns one that yields
    members. Iterate it as any iterator. Closing it ends the pass early and releases
    the reader: the current member stream, if any, is closed. Closing does not give a
    streaming reader a second pass: iterating it, :meth:`~ForwardArchiveReader.stream_members`
    and :meth:`~ForwardArchiveReader.extract_all` still raise ``ArchiveyUsageError``,
    and :meth:`~ForwardArchiveReader.members_report` finishes the interrupted walk.
    Closing an ended pass does nothing, and advancing a closed one ends the iteration.
    Closing a pass while it is executing (another thread inside ``next()``, or a
    selector closing its own pass) raises ``ArchiveyUsageError`` and leaves the pass
    running.

    A pass that runs to its end ends on its own, and so, on CPython, does one a
    ``for`` loop leaves with ``break``. Otherwise a pass stays alive while anything
    refers to it: a variable, the target of ``with … as``, or a traceback that holds
    the loop's frame while an error is handled. It also outlives the loop on an
    interpreter that does not free it at once, such as PyPy. Close it yourself in
    those cases. While a paused :meth:`~ForwardArchiveReader.stream_members` pass is
    alive, a default reader refuses its other calls; a pass from iterating a
    random-access reader holds nothing between members::

        with reader.stream_members() as members:
            for member, stream in members:
                if member.is_file and stream is not None:
                    process(member, stream.read())
    """

    __slots__ = ("_pass",)

    def __init__(self, items: Generator[_T, None, None]) -> None:
        self._pass = items

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> _T:
        return next(self._pass)

    def close(self) -> None:
        """End the pass: close the current member stream and release the reader.

        Raises ``ArchiveyUsageError`` while the pass is executing."""
        if inspect.getgeneratorstate(self._pass) == inspect.GEN_RUNNING:
            raise _executing_pass_error()
        try:
            self._pass.close()
        except ValueError as exc:
            # A thread entered ``next()`` after the check above. Only that case is
            # translated: a ValueError the pass itself raises reaches the caller.
            # The racing next() may have returned already, so the message decides
            # too; the check above is the one that decides by state.
            if inspect.getgeneratorstate(
                self._pass
            ) == inspect.GEN_RUNNING or exc.args == ("generator already executing",):
                raise _executing_pass_error() from exc
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _executing_pass_error() -> ArchiveyUsageError:
    return ArchiveyUsageError(
        "Cannot close a member pass while it is executing: another thread is inside "
        "next(), or a selector is closing its own pass. Close the pass from outside "
        "it, once that next() call has returned."
    )


class ForwardArchiveReader(ABC):
    """An open archive that the code reads in one forward pass.

    It has every reader method except :meth:`~ArchiveReader.members`,
    :meth:`~ArchiveReader.get`, :meth:`~ArchiveReader.open` and
    :meth:`~ArchiveReader.read`, which need random access. Iterate it, call
    :meth:`stream_members` or :meth:`extract_all`, or call :meth:`members_report` for
    the member list.

    ``open_archive(..., streaming=True)`` returns this type, so a type checker flags
    those four calls, which would raise ``ArchiveyUsageError`` at run time. The default
    ``open_archive()`` returns :class:`ArchiveReader`, which adds the four, so a
    function annotated with ``ForwardArchiveReader`` accepts a reader of either mode.

    The check is static only: every reader is an ``ArchiveReader`` at run time. A
    second pass on a streaming reader still raises, and no type checker can see that.
    Use in a ``with`` block.

    **Listing APIs** (easy to mix up):

    - :meth:`~ArchiveReader.members` — complete list or raise; random-access only.
    - :meth:`members_report` — either mode. Returns a report on archive damage (check
      ``error is None`` for completeness); raises on limits and usage errors. On a
      streaming reader it uses up the forward pass (starting it, or finishing an
      interrupted one). For complete-or-raise there, raise ``report.error`` yourself.
    - :meth:`members_report_if_available` — never scans; ``None`` if not yet cached.
    """

    @property
    @abstractmethod
    def format(self) -> ArchiveFormat:
        """The detected ``(container, stream)`` format of the open archive."""
        ...

    @property
    @abstractmethod
    def format_info(self) -> FormatInfo | None:
        """How :func:`archivey.open_archive` identified the format, as
        :func:`archivey.detect_format` would report it.

        The result of the detection the open ran, kept rather than repeated: its
        ``confidence``, ``detected_by`` and ``payload_offset`` describe this reader's
        source. A directory reports ``DIRECTORY`` / ``CERTAIN`` / ``"directory"``.
        ``None`` when ``format=`` was passed, so no detection ran.
        """
        ...

    @property
    @abstractmethod
    def info(self) -> ArchiveInfo:
        """Archive-level metadata (format, solidity, counts, encryption, cost)."""
        ...

    @property
    @abstractmethod
    def cost(self) -> CostReceipt:
        """The listing/access cost receipt for this archive (see ``access-mode-and-cost``)."""
        ...

    @property
    @abstractmethod
    def diagnostics(self) -> DiagnosticSummary:
        """Fresh immutable cumulative snapshot of diagnostics for this reader."""
        ...

    @abstractmethod
    def __iter__(self) -> MemberPass[ArchiveMember]:
        """Iterate members in archive order (served from cache once materialized).

        Returns a :class:`MemberPass` of members. On a streaming reader it is the
        reader's one pass and holds the reader while paused, as a
        :meth:`stream_members` pass does; close it, or use it in a ``with`` block, to
        end it early. On a random-access reader it holds nothing between members."""
        ...

    @abstractmethod
    def members_report(self) -> MemberListReport:
        """Materialize the member listing and return a report.

        ``report.error is None`` means ``report.members`` is complete. A non-``None``
        error is terminal archive damage found while listing (a
        :class:`~archivey.exceptions.CorruptionError`, including
        :class:`~archivey.exceptions.TruncatedError`): the tuple is the recovered
        prefix. Only that damage is returned instead of raised. Every other failure
        raises, as it does from :meth:`~ArchiveReader.members`: a
        :class:`~archivey.exceptions.ResourceLimitError` when the listing exceeds
        :class:`~archivey.config.ListingLimits`, :class:`~archivey.ArchiveyUsageError`
        on misuse (closed reader, overlapping call), and other read failures (a password
        error, an escalated diagnostic, a pass that failed earlier, an I/O error).

        Random access: does not consume anything; the members are the ones
        :meth:`~ArchiveReader.members` returns. Streaming: runs the single forward pass
        to its end (from the start, or finishing one interrupted by an early
        ``break``), so no later pass is possible; after a completed pass it returns the
        cached report.

        A :meth:`stream_members` or ``for member in reader`` pass enforces
        ``ListingLimits`` too: it raises the same ``ResourceLimitError`` at the member
        that crosses a limit.

        For a complete-or-raise list on a streaming reader::

            report = reader.members_report()
            if report.error is not None:
                raise report.error
        """
        ...

    @abstractmethod
    def members_report_if_available(self) -> MemberListReport | None:
        """A member-list report if available without scanning, else ``None``.
        Never scans or consumes the forward pass, so it is safe to call on any reader
        (including a streaming one)."""
        ...

    @abstractmethod
    def __contains__(self, member: object) -> bool:
        """Whether ``member`` (an :class:`ArchiveMember`) was yielded by *this* reader.

        Identity-based and O(1) — no scan — so it is valid in any access mode; useful to
        disambiguate members when several readers are in play. Name lookup is
        :meth:`~ArchiveReader.get`, and a non-``ArchiveMember`` operand raises
        ``TypeError`` (this also keeps the ``in`` operator from silently falling back to
        a full iteration, which would consume a streaming reader's single forward
        pass)."""
        ...

    @abstractmethod
    def stream_members(
        self, members: MemberSelector = None, *, file_copy_streams: bool = True
    ) -> MemberPass[tuple[ArchiveMember, ArchiveStream | None]]:
        """Yield ``(member, stream)`` pairs in archive order with bounded memory.
        ``members`` is an optional selector: a predicate, any iterable of names or
        members (read once, so a generator works), or ``None`` for all. The yielded
        stream is valid only until the iterator advances.

        The stream is ``None`` for every member that has no data of its own: links,
        special entries, tombstones and most directories. A directory that declares
        data (``MEMBER_DIRECTORY_DATA_IGNORED``, in ZIP, TAR and RAR) gets a stream
        with the bytes :meth:`~ArchiveReader.open` delivers for it, under the same
        checks, so a forward-only reader reaches them too. The exception is a ZIP
        directory written with a data descriptor, read from a source that cannot
        seek: its size comes after its data, so it gets ``None``. Data archivey
        cannot decode is refused on the first read, as ``open()`` refuses it. Test
        ``is_file``, not ``stream is not None``, to tell a file from such a
        directory.

        The returned :class:`MemberPass` can be closed, or used in a ``with`` block, to
        end the pass early; see there for when that matters.

        The pass enforces ``ListingLimits`` as ``members()`` does. A pass that lists
        as it goes (every streaming reader, and TAR) yields the members before the
        limit and then raises ``ResourceLimitError`` at the member that crosses it;
        the other readers list the whole archive first, so they raise before the first
        yield. An archive with more members than the default ``max_members`` needs a
        higher limit, or ``ListingLimits.UNLIMITED``, to be streamed; the reader then
        keeps every member until it closes.

        A member whose data is damaged raises from its own stream read and does not
        end the pass; on a solid archive the later members of its block fail the same
        way. The pass raises only when damage to the archive's structure stops it
        finding the next member, such as a TAR cut inside a member.

        ``file_copy_streams=False`` also yields ``None`` for a file that the archive
        stores as a copy of an earlier member (``extra["is_file_copy"]``, a RAR5 file
        copy). Its bytes and digests are its source's, ``link_target_member``, so a
        caller that records hashes can reuse the source's. A solid RAR pass then keeps
        nothing for the copies; by default it keeps each source until the pass ends,
        in memory or in a temporary file within ``SpoolLimits.max_bytes``.

        The yielded stream is forward-only on every format, with or without
        ``seekable_members=True``: ``seekable()`` is ``False``, ``seek()`` raises
        ``io.UnsupportedOperation``, and ``tell()`` works. A nested archive read from
        it is a non-seekable source: ``open_archive()`` accepts it only with
        ``streaming=True`` and only for TAR, ZIP and single-file compressors. For a member
        you need to seek, nested archives included, use :meth:`~ArchiveReader.open` under
        ``seekable_members=True``.

        On a default reader the pass owns the reader while it runs:
        :meth:`~ArchiveReader.open`, :meth:`~ArchiveReader.read`,
        :meth:`~ArchiveReader.get`, :meth:`~ArchiveReader.members`,
        :meth:`members_report`, iteration and another pass raise
        ``ArchiveyUsageError`` inside the loop. On a reader opened with
        ``concurrent_operations=True`` they all work, from the loop body or from
        another thread, on every format, so the answer does not depend on the
        format. They share the pass's walk of the archive's headers, and a call that
        needs members the pass has not reached yet reads ahead for it.
        :meth:`extract_all` works beside a pass too.

        Raises:
            ArchiveyUsageError: The reader is closed; it is a streaming reader whose one
                pass has already started; or, without ``concurrent_operations=True``,
                another pass or a random-access call is running.
            ResourceLimitError: The listing exceeds :class:`~archivey.ListingLimits`.
            CorruptionError: Damage to the archive's structure stops the pass from
                finding the next member.
            DiagnosticRaisedError: A diagnostic that the
                :class:`~archivey.DiagnosticPolicy` in the config raises on, recorded
                while the pass lists the archive.

        Errors in a member's data raise from that member's stream, not from the pass:
        :class:`~archivey.CorruptionError` for damage,
        :class:`~archivey.EncryptionError`, :class:`~archivey.UnsupportedFeatureError`
        and :class:`~archivey.PackageNotInstalledError` for data archivey cannot decode,
        and :class:`~archivey.ResourceLimitError` for a member that asks a decoder for
        more memory than :class:`~archivey.DecoderLimits` allows.
        """
        ...

    @abstractmethod
    def extract_all(
        self,
        dest: str | Path,
        *,
        members: MemberSelector = None,
        filter: MemberFilter | None = None,
        policy: ExtractionPolicy | ExtractionPolicyStr = ExtractionPolicy.STRICT,
        overwrite: OverwritePolicy | OverwritePolicyStr = OverwritePolicy.ERROR,
        on_error: OnError | OnErrorStr = OnError.STOP,
        abort_on: Collection[AbortOn | AbortOnStr] = (),
        on_progress: Callable[[ExtractionProgress], None] | None = None,
        limits: ExtractionLimits | None = None,
        dry_run: bool = False,
    ) -> ExtractionReport:
        """Extract members to ``dest`` (safe-by-default; see ``safe-extraction``).

        ``members`` selects which members to extract: any iterable of names or
        ``ArchiveMember``s (read once, so a generator works), a predicate, or ``None``
        for all. ``filter`` runs after the ``policy`` transform and before the safety
        checks, so it sees unsafe members too; it may rename/sanitize a member (return
        a ``.replace()``d copy) or skip it (return ``None``), and the safety checks run
        on what it returns. The call runs under the config the reader was opened with;
        ``limits`` overrides its extraction limits for this call only. Returns an :class:`~archivey.ExtractionReport` whose diagnostic
        summary is the delta for this extraction call.

        ``abort_on`` names events that end the whole call the first time they occur —
        raising instead of returning a report. It is independent of ``on_error``: see
        :class:`~archivey.AbortOn`.

        ``dry_run=True`` runs the same extraction into a private scratch directory and
        removes it afterwards. Every check runs and every member body is read and
        verified, but files are created empty and nothing is written under ``dest``.
        What ``dest`` holds already is read, and met as a real run meets it: the
        ``overwrite`` policy applies to it, and a file or symlink in the way is
        refused, skipped, replaced or renamed around in the same way. The report reads
        as the report of a real extraction into the same ``dest`` would, with paths
        under ``dest``.

        A member refused by a safety check is skipped and reported as ``BLOCKED``; it
        raises only when ``abort_on`` names it.

        Raises:
            ExtractionError: Under ``on_error="stop"`` (the default), a member could not
                be written, such as a file already at its destination under
                ``overwrite="error"``. Its subclasses
                :class:`~archivey.FilterRejectionError`,
                :class:`~archivey.NameCollisionError` and
                :class:`~archivey.NameRewrittenError` are raised for the events
                ``abort_on`` names, whatever ``on_error`` says.
            ReadError: Under ``on_error="stop"``, a member's data could not be read: a
                :class:`~archivey.CorruptionError` for damage, an
                :class:`~archivey.EncryptionError` for a missing or wrong password, a
                :class:`~archivey.LinkTargetNotFoundError`.
            ResourceLimitError: The extraction exceeds
                :class:`~archivey.ExtractionLimits`: a total stops the extraction
                whatever ``on_error`` says, and a single member over ``max_ratio`` fails
                on its own, under ``on_error``. A member that asks a decoder for more
                memory than :class:`~archivey.DecoderLimits` allows fails on its own
                too.
            DiagnosticRaisedError: A diagnostic that the
                :class:`~archivey.DiagnosticPolicy` in the config raises on, whatever
                ``on_error`` says.
            ArchiveyUsageError: One argument has a type or value the call cannot use
                (then also a ``TypeError`` or ``ValueError``), or the reader is closed.
            OSError: ``dest`` cannot be created or written to.
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Release resources held by the reader. Idempotent.

        **Member streams do not outlive the reader.** Any still open when ``close()``
        runs are closed with it, in the order they were opened, the same way
        ``zipfile.ZipFile.close()`` and ``tarfile.TarFile.close()`` behave — reading one
        afterwards fails as it would for any closed file, and closing it again is a
        no-op. The archive's own source is released after the last of them, never
        underneath a stream still reading through it.

        A :class:`MemberPass`, from :meth:`stream_members` or from iterating a
        streaming reader, that is still alive does not stop the close: the reader
        closes, and advancing that pass afterwards raises ``ArchiveyUsageError``.

        Using the *reader* itself after ``close()`` raises ``ArchiveyUsageError``."""
        ...

    @abstractmethod
    def __enter__(self) -> Self: ...

    @abstractmethod
    def __exit__(self, *args: object) -> None: ...


class ArchiveReader(ForwardArchiveReader):
    """The public, read-only interface to an archive opened for random access.

    Returned by :func:`archivey.open_archive` with the default ``streaming=False``.
    It has every :class:`ForwardArchiveReader` method and adds four for lookup and
    random member access: :meth:`members`, :meth:`get`, :meth:`open` and
    :meth:`read`. Annotate against this type when the code needs those methods;
    concrete machinery lives in the internal ``BaseArchiveReader`` helper. Use in a
    ``with`` block.
    """

    @abstractmethod
    def members(self) -> list[ArchiveMember]:
        """All members as a list. May trigger a scan; raises ``ArchiveyUsageError``
        on a streaming reader (there, use :meth:`~ForwardArchiveReader.members_report`,
        which uses up the pass, or iterate :meth:`~ForwardArchiveReader.stream_members`
        and ignore the streams; both apply :class:`~archivey.config.ListingLimits`).
        Raises terminal archive-level listing errors instead of returning an
        incomplete list.

        Raises:
            CorruptionError: The archive is damaged partway through its member list
                (:meth:`~ForwardArchiveReader.members_report` returns the members found
                before the damage instead).
            ResourceLimitError: The listing exceeds :class:`~archivey.ListingLimits`.
            DiagnosticRaisedError: A diagnostic that the
                :class:`~archivey.DiagnosticPolicy` in the config raises on, recorded
                while the archive is listed.
            ArchiveyUsageError: The reader is closed or streaming.
        """
        ...

    @abstractmethod
    def get(
        self, name: str, default: ArchiveMember | None = None
    ) -> ArchiveMember | None:
        """Look up a member by its normalized name, returning ``default`` if absent.
        This is the name-lookup entry point; :meth:`open`/:meth:`read` also accept a
        name directly. May trigger a scan; on a streaming reader raises
        ``ArchiveyUsageError``, as does a ``name`` that is not a ``str`` (a ``bytes``
        name or an ``ArchiveMember``). With duplicate member names, returns the last
        (the one a sequential extraction would leave on disk).

        Raises:
            ArchiveyUsageError: The reader is closed or streaming, or ``name`` is not a
                ``str``.
            CorruptionError: The scan finds the member list damaged, as :meth:`members`
                raises it.
            ResourceLimitError: The listing exceeds :class:`~archivey.ListingLimits`.
            DiagnosticRaisedError: A diagnostic that the
                :class:`~archivey.DiagnosticPolicy` in the config raises on, recorded
                while the archive is listed.
        """
        ...

    @abstractmethod
    def open(self, member: str | ArchiveMember) -> ArchiveStream:
        """Open a member as a binary stream, following symlinks/hardlinks. Accepts a
        member object or a name (an unknown name raises ``KeyError``; a member object
        that was not yielded by this reader raises ``ArchiveyUsageError`` — same identity
        rule as ``member in reader``). The caller is responsible for closing the returned
        stream. Returns an :class:`~archivey.ArchiveStream` (usable as ``BinaryIO``).

        **Cost, when ``reader.cost.access_cost`` is ``SOLID``** (solid 7z/RAR, any
        compressed tar): members share one compression run, so opening one decodes
        every member before it. Doing that for each member in turn is quadratic in the
        archive size. On a 7z or RAR reader, the first call that decodes again what an
        earlier one decoded logs one INFO record per reader on the
        ``archivey.backends`` logger saying so, and a compressed tar's backward seeks
        report ``STREAM_REWIND_REDECOMPRESSES``. Prefer
        :meth:`~ForwardArchiveReader.stream_members`, which decodes the run once.

        Raises:
            KeyError: No member has that name.
            ArchiveyUsageError: The member has no data of its own (a directory whose
                header declares none, a tombstone, a special entry); the member object
                came from another reader; another member stream is open and the reader
                was opened without ``concurrent_operations=True``; or the reader is
                closed or streaming.
            LinkTargetNotFoundError: The member is a link whose target is not a member
                of the archive.
            EncryptionError: The member is encrypted and no password given decrypts it.
            CorruptionError: The member's data is damaged, raised by ``open()`` or by
                the read of the returned stream that finds the damage
                (:class:`~archivey.TruncatedError` when it seems to end early).
            UnsupportedFeatureError: The member uses a compression method or feature
                archivey cannot decode.
            PackageNotInstalledError: Decoding the member needs an optional package that
                is not installed.
            ResourceLimitError: The member asks a decoder for more memory than
                :class:`~archivey.DecoderLimits` allows, or a scan for the name exceeds
                :class:`~archivey.ListingLimits`.
            DiagnosticRaisedError: A diagnostic that the
                :class:`~archivey.DiagnosticPolicy` in the config raises on.
        """
        ...

    @abstractmethod
    def read(self, member: str | ArchiveMember) -> bytes:
        """Read a member's full contents as ``bytes`` (unbounded — prefer :meth:`open`
        or :meth:`~ForwardArchiveReader.stream_members` for anything not known to be small).

        Carries :meth:`open`'s solid-archive cost: on a ``SOLID`` archive this decodes
        every member preceding the requested one, so a loop over all members is
        quadratic. Use :meth:`~ForwardArchiveReader.stream_members` for that.

        Raises:
            KeyError: No member has that name.
            ArchiveyUsageError: As :meth:`open` raises it.
            ArchiveyError: As :meth:`open` and reading its stream raise it:
                :class:`~archivey.LinkTargetNotFoundError`,
                :class:`~archivey.EncryptionError`, :class:`~archivey.CorruptionError`,
                :class:`~archivey.UnsupportedFeatureError`,
                :class:`~archivey.PackageNotInstalledError`,
                :class:`~archivey.ResourceLimitError` or
                :class:`~archivey.DiagnosticRaisedError`.
        """
        ...
