"""Internal password candidate resolution for encrypted archive units."""

from __future__ import annotations

import threading
from collections.abc import Callable, Container, Iterator, Sequence as ABCSequence
from contextvars import ContextVar
from typing import TypeGuard, TypeVar

from archivey.config import PasswordInput, PasswordProvider, PasswordRequest
from archivey.exceptions import (
    ArchiveyUsageError,
    EncryptionError,
    _UsageTypeError,
    _UsageValueError,
)
from archivey.internal.arg_checks import describe_value
from archivey.types import ArchiveMember

_T = TypeVar("_T")

# How many answers in a row the provider may repeat for one unit before it is taken to
# have no more. Structural, not a resource bound: a repeat costs one provider call and
# no decrypt, and only the provider's own repeats count, so no archive and no keyring
# length can reach it. It exists to end a provider stuck on one answer (a constant
# ``lambda request: "secret"``) while letting a person re-type a password they think
# they mistyped. Three lets them repeat twice and still be asked.
_MAX_CONSECUTIVE_OWN_REPEATS = 3

# The provider call running in this context, if any. The reentry check reads it as
# well as the thread: a provider that hands reader work to a helper thread which
# carries its context (``asyncio.to_thread``, ``contextvars.copy_context().run``, a
# thread that inherits context) is still recognized as reentering.
_PROVIDER_CALL: ContextVar[object | None] = ContextVar(
    "archivey_password_provider_call", default=None
)


class _PasswordCandidatesExhausted(EncryptionError):
    """Internal marker: candidate decrypts failed or no candidate was supplied.

    An ``EncryptionError`` raised by the provider itself is deliberately not wrapped in
    this marker, so a backend can customize true candidate exhaustion without rewriting a
    provider-side failure.
    """

    def __init__(
        self, message: str, *, last_error: EncryptionError | None = None
    ) -> None:
        super().__init__(message)
        self.last_error = last_error


# Set on an ``EncryptionError`` by :func:`wrong_password_error`. An attribute, not a
# subclass, so the exception a caller catches, prints and names stays a plain
# ``EncryptionError`` (the error-handling spec's hierarchy has no private classes).
_WRONG_PASSWORD_MARK = "_archivey_wrong_password"


def wrong_password_error(message: str) -> EncryptionError:
    """Build the ``EncryptionError`` a backend raises when a password check fails.

    ``attempt`` keeps this message on exhaustion ("Wrong password for this ZIP
    member") and replaces any other ``EncryptionError`` text with a generic one. The
    decision reads the mark, not the wording, so rewording a backend's message cannot
    change what exhaustion reports. ``tests/test_password.py`` fails on an
    ``EncryptionError`` whose literal or f-string message says the password is wrong
    and that does not carry the mark.
    """
    error = EncryptionError(message)
    setattr(error, _WRONG_PASSWORD_MARK, True)
    return error


def is_wrong_password(error: BaseException | None) -> TypeGuard[EncryptionError]:
    """Whether ``error`` came from :func:`wrong_password_error`."""
    return (
        isinstance(error, EncryptionError)
        and getattr(error, _WRONG_PASSWORD_MARK, False) is True
    )


# Set on an ``EncryptionError`` by :func:`unverified_data_error` or
# :func:`mark_unverified_data`, as the wrong-password mark above is.
_UNVERIFIED_DATA_MARK = "_archivey_unverified_data"


def unverified_data_error(message: str) -> EncryptionError:
    """The ``EncryptionError`` for data that failed integrity under an unconfirmed password.

    Raised where nothing could confirm the password before the data was decrypted
    (ZipCrypto's one check byte, RAR 2.9-4's absent check), so the password may be
    wrong or the member damaged. A plain ``EncryptionError`` to the caller; the link
    target report reads the mark (``password_or_damage``), so it does not report a
    damaged target as a missing password.
    """
    error = EncryptionError(message)
    setattr(error, _UNVERIFIED_DATA_MARK, True)
    return error


def mark_unverified_data(error: EncryptionError) -> None:
    """Mark ``error``: its data failed its check under a password nothing confirmed."""
    setattr(error, _UNVERIFIED_DATA_MARK, True)


def is_unverified_data_error(error: BaseException) -> bool:
    """Whether ``error`` carries the mark (see :func:`mark_unverified_data`)."""
    return getattr(error, _UNVERIFIED_DATA_MARK, False) is True


def _to_bytes(password: str | bytes) -> bytes:
    """``password`` as the bytes every backend consumes.

    A ``str`` from ``sys.argv`` or ``os.fsdecode`` carries each byte that was not
    UTF-8 as a lone surrogate (``--password $'\\xe9'`` is ``'\\udce9'``);
    ``surrogateescape`` gives back the bytes the user typed, as ``os.fsencode``
    does, and a backend then judges them like any other ``bytes`` password. A lone
    surrogate outside that range stands for no byte and no character.
    """
    if isinstance(password, bytes):
        return password
    try:
        return password.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError:
        raise _UsageValueError(
            "The password contains a lone surrogate code point, which is neither "
            "text nor an escaped byte, so it cannot be encoded for any archive format."
        ) from None


class _PasswordCandidates:
    """Per-archive password state: known-good list, remaining candidates, optional provider.

    Under ``MemberStreams.CONCURRENT`` the known-good snapshot/promotion and provider
    callback are synchronized (D10): the provider is invoked with **no** Archivey lock
    held, one call at a time per reader; a second thread waits for the first call to
    return. Reentry from inside the provider raises ``ArchiveyUsageError`` when it
    comes from the provider's own thread or from a thread carrying its context; a
    helper thread with neither cannot be told apart from an independent worker, so it
    waits, and a provider that blocks on such a thread deadlocks. Concurrent
    first-touch may call the provider / attempt a candidate more than once —
    promotion still converges.
    """

    __slots__ = (
        "_candidates",
        "_known_good",
        "_provider",
        "_provider_owner",
        "_provider_turn",
        "_state_lock",
    )

    def __init__(
        self,
        *,
        candidates: ABCSequence[bytes] = (),
        provider: PasswordProvider | None = None,
    ) -> None:
        self._known_good: list[bytes] = []
        # Immutable static list: callers cannot mutate our candidate order after open.
        self._candidates: tuple[bytes, ...] = tuple(candidates)
        self._provider = provider
        self._state_lock = threading.Lock()
        # The running provider call's thread and token, or None. Identified rather
        # than counted: a count cannot tell a provider calling back into archivey (a
        # deadlock if it waited, so refused) from a second worker that needs the
        # provider at the same moment (a correct program, so it waits).
        self._provider_turn = threading.Condition(threading.Lock())
        self._provider_owner: tuple[int, object] | None = None

    @classmethod
    def from_input(cls, password: PasswordInput) -> _PasswordCandidates:
        if password is None:
            return cls()
        if isinstance(password, (str, bytes)):
            return cls(candidates=[_to_bytes(password)])
        if isinstance(password, ABCSequence) and not isinstance(password, (str, bytes)):
            candidates_list: list[bytes] = []
            for item in password:
                if not isinstance(item, (str, bytes)):
                    raise _UsageTypeError(
                        f"password= sequence items must be str or bytes, but one was "
                        f"{describe_value(item)}."
                    )
                candidates_list.append(_to_bytes(item))
            return cls(candidates=candidates_list)
        if not callable(password):
            # Anything not matched above used to be cast to a provider and stored. The
            # cast is a promise, not a check, so `password=0` survived open() and
            # surfaced at the first encrypted member as `'int' object is not callable` —
            # a raw TypeError, from a call the caller never wrote, about an argument
            # they passed several operations earlier.
            raise _UsageTypeError(
                f"password= takes a str, bytes, a sequence of those, a provider "
                f"callable, or None, but got {describe_value(password)}."
            )
        return cls(provider=password)

    def has_passwords(self) -> bool:
        with self._state_lock:
            return bool(
                self._known_good or self._candidates or self._provider is not None
            )

    def has_concrete_passwords(self) -> bool:
        """Whether the caller gave a password value (a str, bytes or a list of them).

        A provider callable alone does not count: it offers a password only if asked,
        so a format that never asks has not been given one.
        """
        with self._state_lock:
            return bool(self._known_good or self._candidates)

    def is_ambiguous(self) -> bool:
        """Whether a weak password check needs confirmation before accepting a result.

        Duplicate static values count once. A provider is always potentially ambiguous:
        it is intentionally lazy and may return another value after a failed candidate,
        so a backend cannot soundly assume that its first answer is the only one.
        """
        with self._state_lock:
            distinct = set(self._known_good) | set(self._candidates)
            return len(distinct) > 1 or self._provider is not None

    def iter_provider_answers(
        self, member: ArchiveMember | None, tried: Container[bytes]
    ) -> Iterator[bytes]:
        """Yield the provider's answers for one unit that are not in ``tried``.

        Every password in ``tried`` has already failed for this unit, so an answer found
        there is skipped rather than decrypted again (that would re-run an expensive
        decrypt or key derivation), and the provider is asked again with the next
        ``attempt``. Skipping must not end the loop: a provider that leads with a
        password it already knows, often the one an earlier unit promoted to known-good,
        may have the right one next.

        A provider's own repeat is skipped the same way and does not end the loop on its
        own: a person at a prompt may type a password again because they think they
        mistyped it, or forgot they already gave it, and should be asked again. The loop
        ends when the provider returns ``None``, or after
        ``_MAX_CONSECUTIVE_OWN_REPEATS`` answers in a row that it had already given for
        this unit. A provider stuck on one answer stops on its fourth call with one
        decrypt, while a provider walking a list of any length is never cut off.
        Termination depends only on the provider's answers, not on the caller updating
        ``tried``.
        """
        answered: set[bytes] = set()
        own_repeats = 0
        attempt = 1
        while self._provider is not None:
            password = self._call_provider(member, attempt)
            attempt += 1
            if password is None:
                return
            if password in answered:
                own_repeats += 1
                if own_repeats >= _MAX_CONSECUTIVE_OWN_REPEATS:
                    return
                continue
            own_repeats = 0
            answered.add(password)
            if password in tried:
                continue
            yield password

    def _call_provider(
        self, member: ArchiveMember | None, attempt: int
    ) -> bytes | None:
        """One provider call, with the turn-taking and reentry guard.

        A password loop belongs in ``iter_provider_answers``, which skips an
        answer already tried and stops when the provider keeps repeating itself.
        """
        assert self._provider is not None
        me = threading.get_ident()
        token = object()
        with self._provider_turn:
            owner = self._provider_owner
            if owner is not None and (
                owner[0] == me or _PROVIDER_CALL.get() is owner[1]
            ):
                raise ArchiveyUsageError(
                    "Password provider reentered a password-requiring operation on the "
                    "same archive reader. Return a password (or None) without calling "
                    "back into archivey from the provider."
                )
            # Another thread's provider call is running: wait for it rather than
            # refuse, so callbacks stay serialized (reader-concurrency).
            while self._provider_owner is not None:
                self._provider_turn.wait()
            self._provider_owner = (me, token)
        context_token = _PROVIDER_CALL.set(token)
        try:
            # Provider runs with no Archivey lock held (D10).
            raw = self._provider(PasswordRequest(member=member, attempt=attempt))
        finally:
            _PROVIDER_CALL.reset(context_token)
            with self._provider_turn:
                self._provider_owner = None
                self._provider_turn.notify()
        if raw is None:
            return None
        if not isinstance(raw, (str, bytes)):
            # Checked here because the provider is the caller's code running inside
            # ours: without this, its return value reached the cipher and failed as
            # `TypeError: a bytes-like object is required`, naming neither the
            # provider nor the password.
            raise _UsageTypeError(
                f"The password provider returned {describe_value(raw)}; it must "
                f"return a str, bytes, or None."
            )
        return _to_bytes(raw)

    def record_success(self, password: bytes) -> None:
        with self._state_lock:
            if password in self._known_good:
                self._known_good.remove(password)
            self._known_good.insert(0, password)

    def iter_candidates(self) -> Iterator[bytes]:
        """Yield passwords to try for one encrypted unit (known-good, then candidates)."""
        with self._state_lock:
            snapshot = (*self._known_good, *self._candidates)
        seen: set[bytes] = set()
        for password in snapshot:
            if password not in seen:
                seen.add(password)
                yield password

    def attempt(
        self,
        member: ArchiveMember | None,
        decrypt: Callable[[bytes], _T],
        *,
        on_failure: Callable[[bytes, Exception], EncryptionError | None] | None = None,
        promote: Callable[[_T], bool] | None = None,
        settled: Callable[[_T], bool] | None = None,
        settle: Callable[[bytes, _T], _T] | None = None,
    ) -> _T:
        """Try passwords in order; consult the provider after static candidates fail.

        ``decrypt`` must return a non-``None`` value on success: ``attempt`` uses
        ``None`` as its "wrong password, try the next candidate" sentinel, so a
        decrypt callable that returned ``None`` for a valid password would be treated
        as a failure and retried. Decrypt / key derivation runs outside password-state
        locks; only promotion and provider reentry bookkeeping take the locks.

        A successful password is promoted to known-good unless ``promote`` says
        otherwise for its result. A confirmation probe uses this to accept a candidate
        that survived without a deciding signal while keeping it out of known-good,
        where it would be tried first for every later unit.

        Without ``settled``, the first candidate ``decrypt`` accepts wins. With it, a
        result ``settled`` approves (a confirmed password) wins at once, and one it
        does not (a candidate that only survived a bounded probe) is set aside while
        the rest of the static candidates are probed:

        - **No survivor:** the provider is consulted, as without ``settled``.
        - **One survivor:** it wins. Every other candidate was rejected.
        - **Several:** ``settle(password, result)`` runs the full check on each in
          order. The first settled result wins; one that raises ``EncryptionError``
          is rejected. When none settles, the first that was not rejected wins, and
          when all were rejected the provider is consulted.

        The provider's answers are not gathered this way: it is asked one password at
        a time and may stop at any answer, so its first accepted answer wins.
        """
        last_error: EncryptionError | None = None
        tried: set[bytes] = set()

        def note_failure(password: bytes, exc: EncryptionError) -> None:
            nonlocal last_error
            last_error = exc
            if on_failure is not None:
                mapped = on_failure(password, exc)
                if mapped is not None:
                    last_error = mapped

        def accept(password: bytes, result: _T) -> _T:
            if promote is None or promote(result):
                self.record_success(password)
            return result

        def try_password(password: bytes) -> _T | None:
            tried.add(password)
            try:
                return decrypt(password)
            except EncryptionError as exc:
                note_failure(password, exc)
                return None

        survivors: list[tuple[bytes, _T]] = []
        for password in self.iter_candidates():
            result = try_password(password)
            if result is None:
                continue
            if settled is None or settled(result):
                return accept(password, result)
            survivors.append((password, result))

        if len(survivors) == 1 or (survivors and settle is None):
            return accept(*survivors[0])
        fallback: tuple[bytes, _T] | None = None
        for password, result in survivors:
            assert settle is not None
            try:
                full = settle(password, result)
            except EncryptionError as exc:
                note_failure(password, exc)
                continue
            if settled is not None and settled(full):
                return accept(password, full)
            if fallback is None:
                fallback = (password, full)
        if fallback is not None:
            return accept(*fallback)

        for password in self.iter_provider_answers(member, tried):
            result = try_password(password)
            if result is not None:
                return accept(password, result)

        message = (
            (
                last_error.message
                if is_wrong_password(last_error)
                else "Password(s) rejected for this encrypted member"
            )
            if tried
            else (
                last_error.message
                if last_error is not None
                else "Password required to read this encrypted member"
            )
        )
        exhausted = _PasswordCandidatesExhausted(message, last_error=last_error)
        if last_error is not None:
            raise exhausted from last_error
        raise exhausted
