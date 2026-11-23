"""The int and bool arguments a twin takes, checked as the package checks them.

The package gives the same errors on every platform: ``TypeError`` for a value of the
wrong type, prefixed with the argument's name as PyO3 prefixes it, and ``ValueError``
naming the range for an int outside it (where PyO3 alone would raise ``OverflowError``
with a platform's message). The twins call these, so a bad argument raises the same
error on both sides.
"""

from __future__ import annotations

import operator
from typing import SupportsIndex

U64_MAX = 2**64 - 1


def index(value: SupportsIndex, name: str) -> int:
    """``value`` as an int, as ``operator.index`` gives it, else ``TypeError``."""
    try:
        return operator.index(value)
    except TypeError as exc:
        raise TypeError(f"argument '{name}': {exc}") from None


def u64(value: SupportsIndex, name: str) -> int:
    """A size or offset: an int in 0 to 2**64 - 1, else ``ValueError``."""
    n = index(value, name)
    if not 0 <= n <= U64_MAX:
        raise ValueError(f"{name} {n} is outside 0 to 2**64 - 1")
    return n


def flag(value: object, name: str) -> bool | None:
    """``None`` or a bool, not any truthy value, else ``TypeError``."""
    if value is None or type(value) is bool:
        return value
    raise TypeError(
        f"argument '{name}': '{type(value).__name__}' object is not an instance of 'bool'"
    )
