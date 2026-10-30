"""``typing.override`` (Python 3.12), and a stand-in that does nothing before it.

A method that overrides one of a base class carries ``@override``, so a type checker
reports it when the base's method is renamed or removed and the override is left
behind.
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 12):
    from typing import override
else:
    from collections.abc import Callable
    from typing import TypeVar

    _F = TypeVar("_F", bound=Callable[..., object])

    def override(method: _F, /) -> _F:
        """Return ``method`` unchanged: ``typing.override`` before Python 3.12."""
        return method


__all__ = ["override"]
