"""``ArchiveMember.hashes`` and ``ArchiveMember.extra``, built on first read.

Listing a large archive builds one ``hashes`` dict and one ``extra`` bag per member,
mostly to hold what the member's locator (``member._raw``) already has: a ZIP member's
CRC-32 and method, a TAR member's typeflag. Few callers read either while listing, so a
reader may pass :data:`UNBUILT` for them instead, and the first read builds the value
from the locator: ``hashes`` from ``member._raw.member_hashes()`` and ``extra`` from
``member._raw.member_extra()``. The built object is stored, so later reads, and writes
into it, see that one object, as they would an eager one. Only a reader whose locator
has both methods passes :data:`UNBUILT`, and only for a member whose value they build
whole; a member with a rarer key gets its value built up front as before.

Nothing outside sees the difference: every read of the attribute, including
``repr``, ``dataclasses.asdict``, ``replace`` and pickling, goes through the descriptor
and gets the built value. Code that only asks whether ``extra`` holds a key while
listing can use :func:`extra_is_unbuilt` to skip building it: an unbuilt bag holds
only its format's own ``int`` key (``zip.compress_type``, ``tar.type``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from archivey.types import ArchiveMember


class _Unbuilt:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<unbuilt>"


# Typed ``Any`` so a reader can pass it for a ``hashes`` or ``extra`` argument.
UNBUILT: Final[Any] = _Unbuilt()


class LazyField:
    """A field of a ``slots=True`` dataclass that holds :data:`UNBUILT` until read.

    It wraps the slot the dataclass made for the field: ``__set__`` stores into it, and
    ``__get__`` reads it and, on :data:`UNBUILT`, stores and returns what the
    instance's ``_raw`` builds (its method ``build``)."""

    __slots__ = ("_build", "_slot")

    def __init__(self, slot: Any, build: str) -> None:
        self._slot = slot
        self._build = build

    def __get__(self, obj: object, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        value = self._slot.__get__(obj, objtype)
        if value is UNBUILT:
            value = getattr(obj._raw, self._build)()  # type: ignore[attr-defined]
            self._slot.__set__(obj, value)
        return value

    def __set__(self, obj: object, value: object) -> None:
        self._slot.__set__(obj, value)

    def is_unbuilt(self, obj: object) -> bool:
        return self._slot.__get__(obj, type(obj)) is UNBUILT


def install(cls: type, name: str, build: str) -> None:
    """Put a :class:`LazyField` over the slot of ``cls``'s field ``name``."""
    setattr(cls, name, LazyField(cls.__dict__[name], build))


def extra_is_unbuilt(member: ArchiveMember) -> bool:
    """Whether ``member.extra`` is still unbuilt: then it holds only its format's own
    ``int`` key, and reading it would only build that."""
    field = type(member).extra
    return isinstance(field, LazyField) and field.is_unbuilt(member)
