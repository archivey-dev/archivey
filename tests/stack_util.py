"""Run a block of code under a recursion limit set just above the caller's stack.

A tree deeper than the interpreter's recursion limit (an archive of ``a/a/a/…/f``) is
ordinary input, so code that walks one must loop rather than recurse. A test lowers
the limit instead of building a tree 1000 levels deep, so its paths stay short enough
for every platform's ``PATH_MAX`` and the run stays fast.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def recursion_limit_above_caller(headroom: int) -> Iterator[None]:
    """Set the recursion limit to the caller's stack depth plus ``headroom`` frames for
    the block, then put it back."""
    frames = 0
    frame = sys._getframe()
    while frame is not None:
        frames += 1
        frame = frame.f_back
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(frames + headroom)
    try:
        yield
    finally:
        sys.setrecursionlimit(old_limit)
