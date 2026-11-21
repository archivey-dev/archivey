"""Resolving a plugin's :class:`~archivey.formats.NeedsPassword` request.

A plugin hands archivey a request where a unit needs the caller's password
(``format-plugins``). :func:`resolve_request` runs the candidate loop for it, the one
the built-in readers run (``_PasswordCandidates.attempt`` with a confirmation probe and
a full check, ``archive-reading`` §"Confirm candidates when a weak check permits
retries"), and builds the two errors every format shares. The plugin's ``check`` and
``full_check`` run through ``run``, which takes the plugin's guards around each call;
the provider runs outside it, with no plugin guard held.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, NamedTuple, TypeVar

from archivey.exceptions import EncryptionError
from archivey.internal.password import (
    PasswordConfirmVerdict,
    _PasswordCandidates,
    unverified_data_error,
    wrong_password_error,
)

_T = TypeVar("_T")

_Check = Callable[[bytes], Any]


class PluginPasswordBug(TypeError):
    """A plugin's check returned something other than ``(data, verdict)``."""


class SavedWinner(NamedTuple):
    """The password that won one request, kept for a repeat of the same request."""

    password: bytes
    used_full_check: bool


class Resolution(NamedTuple):
    """What resolving one request decided."""

    unlocked: Any
    verdict: PasswordConfirmVerdict
    winner: SavedWinner


def required_error(what: str) -> EncryptionError:
    """No password was given for ``what``, or the provider answered ``None`` first."""
    return EncryptionError(f"{what} is encrypted: pass password= to read it")


def _outcome(
    result: object, which: str, owner: str
) -> tuple[Any, PasswordConfirmVerdict]:
    """``result`` as ``(data, verdict)``, or a plugin bug."""
    if not isinstance(result, tuple) or len(result) != 2:
        raise PluginPasswordBug(
            f"{owner} NeedsPassword.{which} returned {type(result).__name__}, not a "
            f"(data, PasswordConfirmVerdict) tuple"
        )
    data, verdict = result
    if not isinstance(verdict, PasswordConfirmVerdict):
        raise PluginPasswordBug(
            f"{owner} NeedsPassword.{which} returned {type(verdict).__name__} as its "
            f"verdict, not a PasswordConfirmVerdict"
        )
    if data is None and verdict is not PasswordConfirmVerdict.REJECTED:
        raise PluginPasswordBug(
            f"{owner} NeedsPassword.{which} returned no data with {verdict.name}; "
            f"only REJECTED comes without data"
        )
    return data, verdict


def resolve_request(
    *,
    what: str,
    check: _Check,
    full_check: _Check | None,
    member: Any,
    passwords: _PasswordCandidates | None,
    run: Callable[[Callable[[], _T]], _T],
    unguarded: Callable[[], AbstractContextManager[object]],
    allow_provider: bool,
    saved: SavedWinner | None,
    owner: str,
) -> Resolution:
    """Try the caller's passwords on one request and return the winner.

    ``run(fn)`` calls ``fn`` (a plugin callback) under the plugin's guards, which the
    caller holds; each provider call runs inside ``unguarded()``, which lets go of them.
    With ``allow_provider=False`` (a replacement open inside a read) the provider is not
    asked. ``saved`` is the password that won the same request before: it is tried
    first, with ``full_check`` too when that resolution needed it.

    The order is the built-in one: known-good, then the static candidates (a
    ``CONFIRMED`` result wins at once; ``INCONCLUSIVE`` ones are set aside, then a lone
    survivor wins unless the provider could still be asked, several go through
    ``full_check`` in order), then the provider, one
    answer at a time, each ``INCONCLUSIVE`` answer through ``full_check`` when there is
    one. Raises the "required" ``EncryptionError`` when nothing was tried, the
    wrong-password one when every password was rejected by ``check``, and the
    unverified-data one when at least one was rejected only by ``full_check``.
    """
    tried: set[bytes] = set()
    # A password ``full_check`` alone rejected: the data's checksum failed under it,
    # which a damaged unit does for the right password too.
    rejected_by_data = False

    def probe(password: bytes) -> tuple[Any, PasswordConfirmVerdict]:
        tried.add(password)
        return _outcome(run(lambda: check(password)), "check", owner)

    def settle(password: bytes) -> tuple[Any, PasswordConfirmVerdict]:
        nonlocal rejected_by_data
        assert full_check is not None
        data, verdict = _outcome(run(lambda: full_check(password)), "full_check", owner)
        if verdict is PasswordConfirmVerdict.REJECTED:
            rejected_by_data = True
        return data, verdict

    def win(
        password: bytes, data: Any, verdict: PasswordConfirmVerdict, full: bool
    ) -> Resolution:
        if passwords is not None and (
            verdict is PasswordConfirmVerdict.CONFIRMED or not passwords.is_ambiguous()
        ):
            passwords.record_success(password)
        return Resolution(data, verdict, SavedWinner(password, full))

    if saved is not None:
        data, verdict = probe(saved.password)
        if verdict is PasswordConfirmVerdict.CONFIRMED:
            return win(saved.password, data, verdict, False)
        if verdict is PasswordConfirmVerdict.INCONCLUSIVE:
            if not (saved.used_full_check and full_check is not None):
                return win(saved.password, data, verdict, False)
            full_data, full_verdict = settle(saved.password)
            if full_verdict is not PasswordConfirmVerdict.REJECTED:
                return win(saved.password, full_data, full_verdict, True)

    if passwords is not None:
        survivors: list[tuple[bytes, Any]] = []
        for password in passwords.iter_candidates():
            if password in tried:
                continue
            data, verdict = probe(password)
            if verdict is PasswordConfirmVerdict.CONFIRMED:
                return win(password, data, verdict, False)
            if verdict is PasswordConfirmVerdict.INCONCLUSIVE:
                survivors.append((password, data))
        # A lone survivor wins unchecked only when nothing else could be asked: the
        # read's own checksum then reports a wrong one. With a provider it is settled,
        # so a wrong one leads to the provider instead.
        provider_left = allow_provider and passwords.has_provider()
        if survivors and (
            full_check is None or (len(survivors) == 1 and not provider_left)
        ):
            password, data = survivors[0]
            return win(password, data, PasswordConfirmVerdict.INCONCLUSIVE, False)
        fallback: tuple[bytes, Any] | None = None
        for password, _ in survivors:
            full_data, full_verdict = settle(password)
            if full_verdict is PasswordConfirmVerdict.CONFIRMED:
                return win(password, full_data, full_verdict, True)
            if full_verdict is PasswordConfirmVerdict.INCONCLUSIVE and fallback is None:
                fallback = (password, full_data)
        if fallback is not None:
            password, data = fallback
            return win(password, data, PasswordConfirmVerdict.INCONCLUSIVE, True)

        if allow_provider:
            answers = passwords.iter_provider_answers(member, tried)
            while True:
                with unguarded():
                    password = next(answers, None)
                if password is None:
                    break
                data, verdict = probe(password)
                if verdict is PasswordConfirmVerdict.REJECTED:
                    continue
                if verdict is PasswordConfirmVerdict.CONFIRMED or full_check is None:
                    return win(password, data, verdict, False)
                full_data, full_verdict = settle(password)
                if full_verdict is not PasswordConfirmVerdict.REJECTED:
                    return win(password, full_data, full_verdict, True)

    if not tried:
        raise required_error(what)
    if rejected_by_data:
        raise unverified_data_error(
            f"Wrong password for {what}, or its data is damaged: its checksum failed "
            f"under every password tried"
        )
    raise wrong_password_error(f"Wrong password for {what}")
