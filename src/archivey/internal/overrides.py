"""``typing.override`` (Python 3.12), and a stand-in that does nothing before it.

A method that overrides one of a base class carries ``@override``, and only such a
method does (``__init__``, ``__new__``, ``__init_subclass__`` and ``__post_init__``
need none). ``ty check`` enforces both directions (``missing-override-decorator`` and
``invalid-explicit-override``) over the library sources, so a base method renamed or
removed with its override left behind fails the check. It does not open ``tests/``,
and ``pyproject.toml`` exempts the CLI and the plugin packages, which may use only the
public API.

Type checkers see ``typing_extensions.override``: they check as Python 3.11, where the
stand-in below would hide the decorator from them. ``typing_extensions`` is read from
the checker's bundled stubs; nothing imports it at run time. The cost is that neither
checker reads the stand-in any more; the Python 3.11 test jobs, which import it, are
what keep it working.
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
