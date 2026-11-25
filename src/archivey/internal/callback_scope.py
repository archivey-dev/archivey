"""Whether this thread is running a caller's callback, and how deeply nested.

A library-internal open window (``ReaderState.begin_internal_opens``) exempts the
library's own opens from the re-entry and overlap checks. A callback the library runs
inside that window (a diagnostic reported while a link's target data is read) is the
caller's code, not the library's, and must not inherit the exemption: a pass it starts
would be filed under the running pass, and a lookup would skip the re-entry refusal.

Each dispatch site of a caller's callback (``on_diagnostic``, ``on_source_read``,
the password provider, ``extract_all(on_progress=, filter=)``) runs it inside
:func:`user_callback`. A window
records the depth it was entered at and is active only at that depth, so a window that
the callback's own calls open (a reader the callback opens) still works.
"""

from __future__ import annotations

import threading
from types import TracebackType

_local = threading.local()


def callback_depth() -> int:
    """How many caller's callbacks this thread is running, nested."""
    return getattr(_local, "depth", 0)


class user_callback:
    """Context manager: the body is a caller's callback (see the module docstring)."""

    __slots__ = ()

    def __enter__(self) -> None:
        _local.depth = getattr(_local, "depth", 0) + 1

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        _local.depth -= 1
