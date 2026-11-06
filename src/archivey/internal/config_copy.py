"""Copies of a caller's ``ArchiveyConfig`` that archivey makes for itself."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig

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
