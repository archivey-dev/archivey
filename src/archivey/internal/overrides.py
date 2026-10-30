"""``typing.override`` (Python 3.12), and a stand-in that does nothing before it.

A method that overrides one of a base class carries ``@override``, and only such a
method does. ty enforces both (``missing-override-decorator`` and
``invalid-explicit-override``), so a base method renamed or removed with its override
left behind fails the check.

Type checkers see ``typing_extensions.override``: they check as Python 3.11, where the
stand-in below would hide the decorator from them. ``typing_extensions`` is read from
the checker's bundled stubs; nothing imports it at run time.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import override
elif sys.version_info >= (3, 12):
    from typing import override
else:
    from collections.abc import Callable
    from typing import TypeVar

    _F = TypeVar("_F", bound=Callable[..., object])

    def override(method: _F, /) -> _F:
        """Return ``method`` unchanged: ``typing.override`` before Python 3.12."""
        return method


__all__ = ["override"]
