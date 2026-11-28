"""Resolving a plugin's :class:`~archivey.formats.NeedsPassword` request.

A plugin hands archivey a request where a unit needs the caller's password
(``format-plugins``). :func:`resolve_request` runs it through the built-in readers'
own candidate loop (``_PasswordCandidates.attempt`` with a confirmation probe and a
full check, ``archive-reading`` §"Confirm candidates when a weak check permits
retries"), and builds the errors every format shares. The plugin's ``check`` and
``full_check`` run through ``run``, which takes the plugin's guards around each call;
the provider runs outside it, with no plugin guard held.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, NamedTuple

from archivey.exceptions import EncryptionError
from archivey.internal.password import (
    _PasswordCandidates,
    _PasswordCandidatesExhausted,
    unverified_data_error,
    wrong_password_error,
)
from archivey.types import PasswordConfirmVerdict

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


class _PluginRaised(Exception):
    """Carries an ``EncryptionError`` a plugin callback raised through ``attempt``,
    which would otherwise take it for a rejected password. Other exceptions pass
    through ``attempt`` as they are."""

    def __init__(self, error: EncryptionError) -> None:
        super().__init__()
        self.error = error


class _Tried(NamedTuple):
    """One password's result in the loop: what ``then`` gets, and how it won."""

    password: bytes
    data: Any
    verdict: PasswordConfirmVerdict
    used_full_check: bool


def resolve_request(
    *,
    what: str,
    check: _Check,
    full_check: _Check | None,
    member: Any,
    passwords: _PasswordCandidates | None,
    run: Callable[[Callable[[], Any]], Any],
    unguarded: Callable[[], AbstractContextManager[object]],
    allow_provider: bool,
    saved: SavedWinner | None,
    owner: str,
) -> Resolution:
    """Try the caller's passwords on one request and return the winner.

    The loop is the built-in readers' own, ``_PasswordCandidates.attempt``: this
    function only adapts the plugin's ``(data, verdict)`` callbacks to it and builds
    the errors. ``run(fn)`` calls ``fn`` (a plugin callback) under the plugin's guards,
    which the caller holds; each provider call runs inside ``unguarded()``, which lets
    go of them. With ``allow_provider=False`` (a replacement open inside a read) the
    provider is not asked. ``saved`` is the password that won the same request before,
    tried first: a replacement open keeps it (settling it again with ``full_check``
    when its win needed that), and a fresh open lets an unconfirmed one compete with
    the other passwords.

    Raises the "required" ``EncryptionError`` when nothing was tried, the
    wrong-password one when every password was rejected by ``check``, and the
    unverified-data one when at least one was rejected only by ``full_check``.
    """
    tried: set[bytes] = set()
    # A password ``full_check`` alone rejected: the data's checksum failed under it,
    # which a damaged unit does for the right password too.
    rejected_by_data = False

    def call(
        fn: Callable[[], object], which: str
    ) -> tuple[Any, PasswordConfirmVerdict]:
        try:
            result = run(fn)
        except EncryptionError as exc:
            raise _PluginRaised(exc) from None
        return _outcome(result, which, owner)

    def probe(password: bytes) -> _Tried:
        tried.add(password)
        data, verdict = call(lambda: check(password), "check")
        if verdict is PasswordConfirmVerdict.REJECTED:
            raise wrong_password_error(f"Wrong password for {what}")
        return _Tried(password, data, verdict, False)

    def settle(password: bytes, _probed: _Tried) -> _Tried:
        nonlocal rejected_by_data
        assert full_check is not None
        data, verdict = call(lambda: full_check(password), "full_check")
        if verdict is PasswordConfirmVerdict.REJECTED:
            rejected_by_data = True
            raise wrong_password_error(f"Wrong password for {what}")
        return _Tried(password, data, verdict, True)

    def confirmed(result: _Tried) -> bool:
        return result.verdict is PasswordConfirmVerdict.CONFIRMED

    loop = _PasswordCandidates() if passwords is None else passwords
    carried: EncryptionError | None = None
    won: _Tried | None = None
    try:
        won = loop.attempt(
            member,
            probe,
            promote=lambda result: confirmed(result) or not loop.is_ambiguous(),
            settled=confirmed,
            settle=None if full_check is None else settle,
            first=None if saved is None else saved.password,
            first_settles=saved is not None and saved.used_full_check,
            # A replacement open keeps the password its stream was unlocked with; a
            # fresh open lets it compete, as a password confirmed since may beat it.
            first_competes=allow_provider,
            allow_provider=allow_provider,
            unguarded=unguarded,
        )
    except _PluginRaised as raised:
        carried = raised.error
    except _PasswordCandidatesExhausted:
        if not tried:
            raise required_error(what) from None
        if rejected_by_data:
            raise unverified_data_error(
                f"Wrong password for {what}, or its data is damaged: its checksum "
                f"failed under every password tried"
            ) from None
        raise wrong_password_error(f"Wrong password for {what}") from None
    if carried is not None:
        # Raised here, outside the handler, so the plugin's error keeps its own
        # traceback and context rather than the carrier's.
        raise carried
    assert won is not None
    return Resolution(
        won.data, won.verdict, SavedWinner(won.password, won.used_full_check)
    )
