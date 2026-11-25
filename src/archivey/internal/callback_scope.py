"""Whether this thread is running a caller's callback, and how deeply nested.

A library-internal open window (``ReaderState.begin_internal_opens``, the first-touch
link-data read) exempts the library's own stream opens from the live-stream gate. It
gives admission nothing: a pass, a worker call or a peek never looks at the window, so
code the library runs inside it that is not its own (a callback, an application's
logging handler) is refused as re-entry like any other call.

As a second guard, each dispatch site of a caller's callback (``on_diagnostic``,
``on_source_read``, the password provider, ``extract_all(on_progress=, filter=)``)
runs it inside :func:`user_callback`. A window records the depth it was entered at and
is active only at that depth, so a callback does not pass the gate either, while a
window that the callback's own calls open (a reader the callback opens) still works.
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
