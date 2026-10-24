"""Archivey exception hierarchy.

Two roots (intentional):

- :class:`ArchiveyError` — archive / environment / format problems. Safe to catch
  broadly when wrapping untrusted input.
- :class:`ArchiveyUsageError` — caller API misuse. Deliberately **outside** the
  ``ArchiveyError`` tree so ``except ArchiveyError`` does not hide bugs in calling
  code.

Under ``ArchiveyError`` the groups follow the cause, not the call that hit it:
:class:`OpenError` means reading never started, :class:`ReadError` means the archive's
data is bad or unreadable (a damaged header at open included), and
:class:`ExtractionError` means writing a member to disk failed; beside them sit the
feature, package, resource-limit and diagnostic errors.

A type earns a place here only when a caller would act on it differently from its
parent. Anything finer goes in the message.

Both roots **escape their message** at construction: the text call sites build
interpolates attacker-controlled member names and the paths derived from them, and
an exception message reaches a terminal by routes no single consumer configures —
including a traceback the interpreter prints on its own. See
:class:`ArchiveyError` for what stays raw and why.

Every exception in both trees survives ``pickle``, ``copy`` and ``deepcopy`` with its
``args``, message and attributes intact, so an error raised in a worker process reaches
the parent whole. As with any Python exception, ``__cause__`` and ``__context__`` are not
carried across a pickle.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from archivey.terminal import escape_control_chars

if TYPE_CHECKING:
    from archivey.diagnostics import Diagnostic
    from archivey.types import ArchiveFormat, MemberType


def _restore_exception(
    cls: type[BaseException], args: tuple[object, ...], state: dict[str, object]
) -> BaseException:
    """Rebuild a pickled or copied exception without calling its ``__init__``.

    ``BaseException``'s own reduce calls ``cls(*self.args)``, which breaks both roots
    below: ``args[0]`` is the *escaped* message, so a second pass through ``__init__``
    escapes it again, and a subclass with a required keyword argument
    (:class:`DiagnosticRaisedError`) cannot be rebuilt at all. Restoring ``args`` and
    the instance state directly avoids both.
    """
    exc = cls.__new__(cls)
    exc.args = args
    exc.__dict__.update(state)
    return exc


class ArchiveyError(Exception):
    """Root of all Archivey exceptions.

    **The message is escaped.** Call sites build messages by interpolating
    archive-derived text — a member name, or a destination path built from one — and
    those are attacker-controlled. An exception message reaches a terminal by more
    routes than any one consumer controls: ``print(e)``, ``logging.exception``, a
    third-party error reporter, and above all an uncaught exception whose traceback
    the interpreter prints itself, whose final line is ``str(e)``. Escaping in the
    handler that displays it protects only the routes someone remembered to
    configure; escaping here protects all of them, with no configuration.

    So ``message`` is stored escaped, and that escaped form is what
    :meth:`__str__`, ``args[0]`` and ``repr()`` all render. ``raw_message`` keeps the
    text as the call site wrote it, for the one job the escaped form cannot do: being
    embedded in *another* message that will escape it in turn.

    ``archive_name``, ``member_name``, ``link_target`` and ``source_format`` stay
    **raw** too, for callers that need the real value to act on rather than to print.
    :meth:`__str__` renders the names through ``!r``, which escapes them for display in
    turn — so a name available as an attribute should **not** also be interpolated into
    the message, or it prints twice. Prefer prose plus attributes:
    ``FilterRejectionError("Symlink target escapes destination", member_name=name,
    link_target=target)``.

    ``format_unconfirmed`` is a boolean (default ``False``): ``True`` when the format
    claim rested only on a content probe with nothing corroborating it (no matching
    extension, no inner-TAR upgrade), or only on the file extension because every
    content signal declined, so a decode failure should not be read as "this known
    format truncated." Confidence is irrelevant to the flag.

    **Escape exactly once, at the outermost message.** Everything a message
    interpolates should therefore be raw when it goes in — which is what the two
    helpers are for, and why neither of them is a matter of taste:

    - a member name, link target or path → :func:`~archivey.terminal.quoted`, not
      ``!r``. ``!r`` escapes first, and this escapes the backslashes it introduced.
    - a caught exception that might be one of ours → :func:`exception_detail`, not
      ``{exc}``. It gives the unescaped text of one of ours (as :func:`raw_message_of`
      does), and the type name of an exception that has no text. A handler that
      catches only a third-party decoder's type can use ``{exc}``.
    - never ``{exc!r}`` for a caught exception: it shows Python's spelling
      (``error('unpack_from requires …')``), not what is wrong with the archive, and
      escapes one of ours a second time. When the exception's own text does not
      describe the archive (``struct.error``, ``IndexError`` from a parser), write that
      description instead and keep the original as ``__cause__``.
      ``tests/test_escaping.py`` checks this rule.

    Note this is the opposite of the rule for ``logger.*`` calls, whose records the CLI
    does **not** escape: there, ``%r`` is what makes an interpolated name inert and must
    stay.
    """

    def __init__(
        self,
        message: str,
        *,
        source_format: ArchiveFormat | None = None,
        archive_name: str | None = None,
        member_name: str | None = None,
        link_target: str | None = None,
        format_unconfirmed: bool = False,
    ) -> None:
        self.raw_message = message
        message = escape_control_chars(message)
        super().__init__(message)
        self.message = message
        self.source_format = source_format
        self.archive_name = archive_name
        self.member_name = member_name
        self.link_target = link_target
        self.format_unconfirmed = format_unconfirmed

    def __reduce__(self) -> tuple[object, ...]:
        # Pickle and copy without re-running __init__; see _restore_exception.
        return (_restore_exception, (type(self), self.args, self.__dict__))

    def __str__(self) -> str:
        parts = [self.message]
        if self.archive_name:
            parts.append(f"archive={self.archive_name!r}")
        if self.member_name:
            parts.append(f"member={self.member_name!r}")
        if self.link_target:
            parts.append(f"target={self.link_target!r}")
        if self.source_format:
            # Human label (ZIP / TAR_GZ / SEVEN_Z), not ArchiveFormat.ZIP repr.
            parts.append(f"format={self.source_format.display_name}")
        if self.format_unconfirmed:
            parts.append("format_unconfirmed=True")
        if len(parts) == 1:
            return self.message
        return f"{self.message} ({', '.join(parts[1:])})"


class OpenError(ArchiveyError):
    """Reading could not start: the source is not a recognized archive, is not seekable
    where the format needs it, or a volume file cannot be opened.

    A recognized archive whose header is damaged, cut short or encrypted raises a
    :class:`ReadError` subclass instead, from ``open_archive()`` as from any later call.
    """


class FormatDetectionError(OpenError):
    """Could not detect an archive format, or detected one this call cannot use.

    The second case is ``open_stream()`` on a container such as a ZIP: detection
    succeeded, but the source is not a single-file compressed stream.
    """


class StreamNotSeekableError(OpenError):
    """Source is non-seekable but this format/backend needs seek."""


class ReadError(ArchiveyError):
    """The archive's data is bad or cannot be read, at open or later.

    Raised directly when an external decoder or a child process fails without saying
    why; the subclasses name the common causes.
    """


class CorruptionError(ReadError):
    """The archive's bytes are damaged: a checksum mismatch, a bad header or data block.

    Data that ends early is damage too, so :class:`TruncatedError` is a subclass and
    ``except CorruptionError`` catches it.
    """


class TruncatedError(CorruptionError):
    """Damage that looks like the data ending early.

    A best-effort label, not a diagnosis: damage that decodes short can raise it, and some
    cut-short headers raise a plain :class:`CorruptionError`. Do not branch on it.
    """


class EncryptionError(ReadError):
    """Password required or wrong password."""


class LinkTargetNotFoundReason(StrEnum):
    """Why a link has no member to follow to: :attr:`LinkTargetNotFoundError.reason`."""

    NOT_RECORDED = "not_recorded"
    """The archive records no target for this link. Not damage: a writer such as
    7-Zip stores some links this way, and ``ArchiveMember.link_target_unrecorded`` is
    ``True`` for them."""

    UNREADABLE = "unreadable"
    """The archive records a target, and this read could not produce it: the data
    holding it is damaged, encrypted, or out of reach. A diagnostic on the member
    says which."""

    UNRESOLVED = "unresolved"
    """The target is known, but following it reaches no member that holds data: it
    names no member of the archive, or one the link may not use (a symlink target that
    leaves the archive root, a hardlink to a later member), or the chain of links
    loops."""


class LinkTargetNotFoundError(ReadError):
    """A symlink/hardlink target, or a file copy's source, is absent from the archive.

    :attr:`reason` says why, so a caller can act on the cause without reading the
    message.
    """

    reason: LinkTargetNotFoundReason
    """Why the link has no member to follow to."""

    def __init__(
        self,
        message: str,
        *,
        reason: LinkTargetNotFoundReason,
        source_format: ArchiveFormat | None = None,
        archive_name: str | None = None,
        member_name: str | None = None,
        link_target: str | None = None,
        format_unconfirmed: bool = False,
    ) -> None:
        super().__init__(
            message,
            source_format=source_format,
            archive_name=archive_name,
            member_name=member_name,
            link_target=link_target,
            format_unconfirmed=format_unconfirmed,
        )
        self.reason = reason


class ExtractionError(ArchiveyError):
    """Error extracting a member to disk."""


class FilterRejectionError(ExtractionError):
    """A safety check refused to write the member.

    One type for every check: a path that escapes the destination (``..`` or an absolute
    path), a symlink that resolves outside it, a device node, FIFO or socket, a name the
    destination OS cannot store safely under the active policy (see ``safe-extraction``),
    and a name built to display as something it is not (a Unicode bidi override or
    isolate). The member is ``BLOCKED`` whichever check fired, and the message says which.
    """


class NameCollisionError(ExtractionError):
    """A member resolved to a destination another member of this run already claimed.

    Raised only when the caller opted in with ``AbortOn.NAME_COLLISION``; without that
    opt-in a collision is not an error at all — ``OverwritePolicy`` resolves it and both
    members' ``ExtractionResult`` records the outcome. It is raised for *every*
    non-``TRUSTED`` collision regardless of how the policy would have resolved it, since
    the trigger is the collision itself, not its resolution.
    """


class NameRewrittenError(ExtractionError):
    """A member name was rewritten: to its portable spelling, or re-rooted inside the
    destination.

    Raised only when the caller opted in with ``AbortOn.NAME_SANITIZED`` — a narrow
    escape hatch for callers who require the on-disk name to match the archive's byte
    for byte. Without the opt-in the rewrite is a success, recorded as
    ``ExtractionResult.presented_name``.
    """


class ResourceLimitError(ArchiveyError):
    """A configured resource limit was exceeded, or the system did not give a resource.

    Covers :class:`~archivey.config.ListingLimits` listing caps,
    parse-time ``max_members`` on ZIP, 7z, RAR and ISO,
    :class:`~archivey.config.ExtractionLimits` bomb guards,
    :class:`~archivey.config.DecoderLimits` caps on archive-declared decoder memory
    and key-derivation work, and :class:`~archivey.config.SpoolLimits`, the cap on
    copying a stream source to temporary storage; opening the archive from a path
    avoids that copy. A shortage of the system rather than a configured limit raises
    the subclass :class:`ResourceUnavailableError`.
    Sibling of :class:`ExtractionError` (not a subclass): these are not filter/path
    failures.
    """


class ResourceUnavailableError(ResourceLimitError):
    """The system did not give a resource the read needed; no configured limit was
    exceeded.

    Raised when a decoder or helper program is ended by SIGKILL (most often the
    out-of-memory killer), when a decoder that
    :class:`~archivey.config.ProcessIsolation` runs only in a child process cannot
    have one (a frozen application, a refused spawn), and when a PPMd decoder process
    cannot allocate the member's model (a container memory limit). The data may be
    valid: read it again with more memory, or where child processes can start. Raising
    a limit in the config does not help.

    A subclass of :class:`ResourceLimitError`, so code that catches that type catches
    this one too.
    """


class UnsupportedFeatureError(ArchiveyError):
    """The archive is recognized, but uses something archivey cannot handle.

    A variant, codec or layout of a known format (a raw CD sector image, a UDIF disk
    image, a 7z coder graph that is not a tree of chains, a multi-volume set where the
    format has none),
    or a request this archive or backend cannot serve (a password ``unrar`` cannot be
    given). The problem is the archive, not the calling code: that raises
    :class:`ArchiveyUsageError`.

    An unknown compression method, codec or version number read from a header with no
    checksum (a ZIP method, for example) may also mean that header is damaged. Archivey
    reports it as unsupported because it cannot tell the two apart.

    A refused ``seek()`` or ``tell()`` on a member stream is *not* this class: a member
    stream has to keep behaving like a file object, so it raises
    :exc:`io.UnsupportedOperation` (a subclass of :exc:`OSError` and :exc:`ValueError`).
    """


class PackageNotInstalledError(ArchiveyError):
    """A required optional package or external tool is absent.

    Raised both when a whole format needs it (opening an ISO without ``pycdlib``) and
    when one member does (a PPMd member without ``pyppmd``). The message names what to
    install.
    """


class ArchiveyUsageError(Exception):
    """Caller misuse of the Archivey API — deliberately not an :class:`ArchiveyError`.

    ``except ArchiveyError`` wraps archive/environment problems; usage errors indicate
    a bug in calling code and must not be swallowed by those handlers.

    It covers what the argument types alone cannot rule out: calling a method the
    reader's mode forbids (``members()`` on a ``streaming=True`` reader), using a closed
    reader, opening a second overlapping member stream without
    ``concurrent_operations=True`` (the message names the ``open_archive()`` call site),
    and driving the reader from inside a diagnostic callback. Those raise this class
    itself.

    A wrong argument raises it too, as a private subclass that is also a
    ``TypeError`` (an argument of a type the call cannot use: ``config="strict"``,
    ``open_archive(0)``) or a ``ValueError`` (a usable type with a value the call
    refuses: an unknown format spelling, a negative limit). So ``except TypeError``,
    ``except ValueError`` and ``except ArchiveyUsageError`` all catch a bad argument.
    The subclasses are not public names; catch the builtin or this class.

    The message is escaped on the same terms as :class:`ArchiveyError`'s. A usage
    error's text is mostly archivey's own, so the escaping is usually a no-op — but
    "mostly" is not a property worth carving an exception into, and a usage error is
    free to name the member that provoked it.

    ``refused_member_type`` marks one case by type rather than by message. It is the
    type of the member ``open()`` / ``read()`` refused because it is not a file
    (``DIRECTORY``, ``ANTI`` or ``OTHER``), and ``None`` on every other usage error.
    When the caller opened a link, it is the type of the member the link resolved to:
    a symlink to a directory gives ``MemberType.DIRECTORY``.
    """

    def __init__(
        self, message: str, *, refused_member_type: MemberType | None = None
    ) -> None:
        self.raw_message = message
        message = escape_control_chars(message)
        super().__init__(message)
        self.message = message
        self.refused_member_type = refused_member_type

    def __reduce__(self) -> tuple[object, ...]:
        # Pickle and copy without re-running __init__; see _restore_exception.
        return (_restore_exception, (type(self), self.args, self.__dict__))

    def __str__(self) -> str:
        return self.message


class _UsageTypeError(ArchiveyUsageError, TypeError):
    """A public argument of a type the call cannot use.

    Private on purpose: a caller catches ``TypeError`` or
    :class:`ArchiveyUsageError`, and neither needs a third name to do it.
    """


class _UsageValueError(ArchiveyUsageError, ValueError):
    """A public argument of a usable type whose value the call refuses.

    An unknown enum or format spelling, a negative or NaN limit, a codec name Python
    does not know. Private for the same reason as :class:`_UsageTypeError`.
    """


class DiagnosticRaisedError(ArchiveyError):
    """A diagnostic was escalated to an error via :class:`~archivey.diagnostics.DiagnosticPolicy`.

    Always-stop: extraction MUST NOT catch this as a per-member failure under
    ``OnError.CONTINUE``. Carries the escalated :class:`~archivey.diagnostics.Diagnostic`.
    """

    def __init__(
        self,
        message: str,
        *,
        diagnostic: Diagnostic,
        source_format: ArchiveFormat | None = None,
        archive_name: str | None = None,
        member_name: str | None = None,
        link_target: str | None = None,
    ) -> None:
        super().__init__(
            message,
            source_format=source_format,
            archive_name=archive_name,
            member_name=member_name,
            link_target=link_target,
        )
        self.diagnostic = diagnostic


def raw_message_of(exc: BaseException) -> str:
    """The text of ``exc`` as its call site wrote it, for embedding in a new message.

    Interpolating a caught exception into a message that will itself be escaped needs
    the *unescaped* text, or the outer escape doubles the backslashes the inner one
    wrote. Archivey's exceptions keep that text on ``raw_message``; everything else was
    never escaped and is already raw.

    Needed only where the caught type is broad enough to include one of ours — a
    ``except Exception`` around a call that may raise an ``ArchiveyError``. A handler
    catching only third-party types (``lzma.LZMAError``, ``zlib.error``) can
    interpolate the exception directly.
    """
    if isinstance(exc, (ArchiveyError, ArchiveyUsageError)):
        return exc.raw_message
    return str(exc)


def exception_detail(exc: BaseException, *, with_type: bool = False) -> str:
    """The text to show for a caught exception inside a new archivey message.

    That is the exception's own message, unescaped (:func:`raw_message_of`), or its type
    name when it has no message, so that a message never ends at a bare colon. With
    ``with_type``, the type name comes first (``AttributeError: …``): use it where the
    text alone does not say that a Python error, not the archive, is the subject. A
    type outside ``builtins`` is named with its module (``struct.error``), since its
    bare name is often just ``error``.

    Never the ``repr``: ``error('unpack_from requires …')`` is Python's spelling, not
    a description of the archive. ``str()`` of a ``KeyError`` is the repr of its key,
    so a one-key ``KeyError`` shows the key itself.
    """
    if isinstance(exc, KeyError) and len(exc.args) == 1:
        text = str(exc.args[0])
    else:
        text = raw_message_of(exc)
    cls = type(exc)
    name = (
        cls.__qualname__
        if cls.__module__ == "builtins"
        else f"{cls.__module__}.{cls.__qualname__}"
    )
    if not text:
        return name
    return f"{name}: {text}" if with_type else text
