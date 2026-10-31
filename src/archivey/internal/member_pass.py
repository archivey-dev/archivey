"""``MemberPassImpl``: archivey's own :class:`~archivey.MemberPass`, over a generator.

The reader's pass is a generator (``BaseArchiveReader._iter_pass`` and the
``stream_members`` walk); this wraps it so the public type can be closed while the
generator stays private.
"""

from __future__ import annotations

import inspect
from collections.abc import Generator
from typing import TypeVar

from archivey.exceptions import ArchiveyUsageError
from archivey.internal.overrides import override
from archivey.reader import MemberPass

_T = TypeVar("_T")


class MemberPassImpl(MemberPass[_T]):
    """The pass over ``items``, a generator the reader runs."""

    __slots__ = ("_pass",)

    def __init__(self, items: Generator[_T, None, None]) -> None:
        self._pass = items

    @override
    def __next__(self) -> _T:
        return next(self._pass)

    @override
    def close(self) -> None:
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


def _executing_pass_error() -> ArchiveyUsageError:
    return ArchiveyUsageError(
        "Cannot close a member pass while it is executing: another thread is inside "
        "next(), or a selector is closing its own pass. Close the pass from outside "
        "it, once that next() call has returned."
    )
