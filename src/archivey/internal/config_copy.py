"""Copies of a caller's ``ArchiveyConfig`` that archivey makes for itself.

``ArchiveyConfig.__post_init__`` warns when a deprecated field is set. A copy archivey
makes with :func:`copy_config_quietly` runs that hook again; the hook asks
:func:`copying_config` and stays quiet, since the caller was already warned.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig
    from archivey.diagnostics import OnDiagnostic

_COPYING: ContextVar[bool] = ContextVar("archivey_copying_config", default=False)


def copying_config() -> bool:
    """Whether the config being built is archivey's own copy of a caller's."""
    return _COPYING.get()


@contextmanager
def _copying() -> Generator[None, None, None]:
    token = _COPYING.set(True)
    try:
        yield
    finally:
        _COPYING.reset(token)


def copy_config_quietly(config: ArchiveyConfig, **changes: Any) -> ArchiveyConfig:
    """``dataclasses.replace(config, **changes)`` for archivey's own copies.

    A deprecated field the caller set is passed on to the copy, which would warn
    again from inside the library, pointing at ``dataclasses``. The caller already
    got the warning when they built ``config``.
    """
    with _copying():
        return replace(config, **changes)


class CallbackFromCall:
    """A callback a call passed as a keyword (``open_archive(on_diagnostic=)``),
    carried in archivey's copy of the config.

    The copy reaches code that may copy it again, such as a plugin reader running
    ``dataclasses.replace(context.config, ...)``. ``ArchiveyConfig.__post_init__``
    warns only for a callback the caller put in the deprecated field itself, and this
    wrapper is how it tells the two apart.
    """

    __slots__ = ("function",)

    def __init__(self, function: Callable[..., None]) -> None:
        self.function = function

    def __call__(self, *args: Any) -> None:
        self.function(*args)


def config_with_callbacks(
    config: ArchiveyConfig,
    *,
    on_diagnostic: OnDiagnostic | None,
    inherit_from: ArchiveyConfig | None = None,
) -> ArchiveyConfig:
    """``config`` carrying the ``on_diagnostic`` one opening call reports to.

    A callback passed to the call wins over the one in ``config``'s deprecated field.
    A callback neither names comes from ``inherit_from``, the config of the reader an
    ``open_archive(parent=)`` call names, so a nested reader opened with a config of
    its own still reports where its parent does. The callback travels in the config's
    field because every reader, stream and collector already reads it there; the
    caller's object is never changed.
    """
    if on_diagnostic is not None:
        on_diagnostic = CallbackFromCall(on_diagnostic)
    else:
        on_diagnostic = config.on_diagnostic
        if on_diagnostic is None and inherit_from is not None:
            on_diagnostic = inherit_from.on_diagnostic
    if on_diagnostic is config.on_diagnostic:
        return config
    return copy_config_quietly(config, on_diagnostic=on_diagnostic)
