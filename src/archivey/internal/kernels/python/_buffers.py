"""The input a twin takes, as the package takes it."""

from __future__ import annotations


def raw_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """The bytes of ``data`` in order, as the package's kernels copy them from any
    buffer: a view of wider items or with a stride gives its bytes, not its items.
    Count and decode these, never ``data``'s items. The buffer itself is read, never
    ``__bytes__`` (a ``bytes`` subclass may give other bytes there); anything but a
    buffer raises ``memoryview``'s ``TypeError``, as in the package."""
    return data if type(data) is bytes else memoryview(data).tobytes()
