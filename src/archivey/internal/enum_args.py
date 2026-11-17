"""Coercion for the public API's enum-typed arguments.

Every public entry point that declares an :class:`~enum.Enum` parameter accepts the
member's **value** spelled as a string, and converts it at the boundary.
``reader.extract_all(dest, overwrite="skip")`` is the same call as
``reader.extract_all(dest, overwrite=OverwritePolicy.SKIP)``, and an unrecognised
spelling raises :class:`~archivey.ArchiveyUsageError` there and then, naming what would
have worked. The class raised is the private subclass that is also a ``ValueError``; a
value of the wrong type (an ``int``, a member of another enum) gets the one that is also
a ``TypeError``.

**Why coerce rather than refuse.** The CLI and a throwaway script both hold strings.
Coercing in one place makes the library and the CLI accept the same vocabulary instead
of two that drift.

**Why it must happen at the boundary.** The consuming code tests identity (``policy is
ExtractionPolicy.TRUSTED``), and a string is never any member, so an unconverted string
would silently take the other branch. ``overwrite="skip"`` would match neither ``ERROR``
nor ``SKIP`` and fall through to REPLACE, deleting the file the caller asked to keep;
``on_error="stop"`` would behave as ``CONTINUE``. Converting at the entry point is what
makes those unreachable.

**The cost, stated plainly.** Accepting a string makes the enum **values** public API.
``OverwritePolicy.SKIP.value`` cannot be renamed from ``"skip"`` afterwards without
breaking callers silently, in a way that renaming the *member* would not. The member
names are accepted too, for the same reason and with the same consequence. That is the
price of the CLI-friendliness this buys, and it is deliberate.

Spellings accepted for a member, all verified non-colliding by
``tests/test_enum_arguments.py``:

* its ``value`` (``"skip"``, ``"blocked_member"``, ``"auto"``)
* its member **name** (``"SKIP"``, ``"BLOCKED_MEMBER"``)
* either of those with any case, and with ``-`` and ``_`` used interchangeably — so the
  ``--abort-on blocked-member`` spelling from ``--help`` also works in a script
* any of the above with surrounding whitespace

``format=`` is not an ``Enum`` (an :class:`~archivey.ArchiveFormat` is a ``(container,
stream)`` pair), so its own spellings live in :mod:`archivey.internal.format_args`.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable
from enum import Enum
from typing import TypeVar

from archivey.exceptions import _UsageTypeError, _UsageValueError

__all__ = [
    "coerce_enum",
    "coerce_enum_collection",
    "normalize_spelling",
    "spelling_table",
]

E = TypeVar("E", bound=Enum)
T = TypeVar("T")


def normalize_spelling(text: str) -> str:
    """Fold one spelling of an enum member to its lookup key.

    Case and the ``-``/``_`` distinction are the two differences that carry no meaning
    across our spellings: the CLI writes ``blocked-member`` where the enum value is
    ``blocked_member``, and a caller typing ``"STRICT"`` means ``"strict"``. Leading and
    trailing whitespace is dropped too, so ``" skip"`` from a config file still matches.
    Everything else is preserved, including the dots in a format extension.
    """
    return text.strip().lower().replace("-", "_")


def spelling_table(
    *, fallback: Iterable[tuple[str, T]], preferred: Iterable[tuple[str, T]]
) -> dict[str, T]:
    """Normalized spelling -> value; ``preferred`` wins a tie, then the first one does."""
    table: dict[str, T] = {}
    for spelling, value in fallback:
        table.setdefault(normalize_spelling(spelling), value)
    for spelling, value in preferred:
        table[normalize_spelling(spelling)] = value
    return table


@functools.cache
def _lookup(enum_cls: type[E]) -> dict[str, E]:
    """Build (once per class) the normalized-spelling -> member map.

    Values win over names on a tie so a class whose value spells another member's name
    resolves to the value — the spelling the CLI and the docs use. No shipping enum has
    such a tie; ``test_enum_arguments.py`` fails if one is introduced, rather than
    leaving the precedence to be discovered.
    """
    return spelling_table(
        fallback=((m.name, m) for m in enum_cls),
        preferred=((m.value, m) for m in enum_cls if isinstance(m.value, str)),
    )


def _takes(enum_cls: type[Enum], also_accepts: str | None) -> str:
    """The types the caller's parameter accepts, for a wrong-type message."""
    if also_accepts:
        return f"a {also_accepts} or a {enum_cls.__name__}"
    return f"a {enum_cls.__name__}"


def _accepted(enum_cls: type[Enum]) -> str:
    """The valid spellings, for the error message. Values where there are values.

    One rendering, the library's own, at every raise site. These messages reach a
    caller who passed a bad value to a Python function; the CLI never produces them,
    because argparse ``choices=`` refuses an unknown spelling before ``run_extract``
    is called at all.
    """
    spellings = [str(m.value) if isinstance(m.value, str) else m.name for m in enum_cls]
    return ", ".join(repr(s) for s in spellings)


def coerce_enum(
    value: object,
    enum_cls: type[E],
    *,
    call: str,
    param: str,
    also_accepts: str | None = None,
) -> E:
    """Return ``value`` as a member of ``enum_cls``, or raise ``ArchiveyUsageError``.

    A member of the class passes through untouched. A string is matched against the
    spellings described in the module docstring. Anything else — including a member of a
    *different* enum, which is the mistake a type checker would have caught — is
    refused. ``None`` does arrive, from ``ArchiveyConfig(detection_budget=None)``, and
    is refused with the wrong-type message on purpose: no parameter this helper serves
    means "default" by ``None``, so there is no ``allow_none`` arm.

    ``also_accepts`` names a further type the *caller's* parameter takes but this helper
    does not handle, so the wrong-type message stays true to the signature the caller
    read. ``ArchiveyConfig(detection_budget=)`` is the case: it takes a
    ``DetectionBudget`` object as well as a preset, and a message naming only the preset
    reads as a denial that the object is allowed.
    """
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, Enum):
        # Checked ahead of the string branch on purpose: several of our enums are
        # ``StrEnum`` (``AbortOn``, ``StreamFormat``, …), so a member of the *wrong*
        # class is a string too, and would otherwise be reported as a bad spelling
        # rather than as the wrong type — which is what it is.
        raise _UsageTypeError(
            f"{call} takes {_takes(enum_cls, also_accepts)} for {param}, but got "
            f"{type(value).__name__}.{value.name}. "
            f"Accepted: {_accepted(enum_cls)}."
        )
    if isinstance(value, str):
        member = _lookup(enum_cls).get(normalize_spelling(value))
        if member is not None:
            return member
        raise _UsageValueError(
            f"{call} got {value!r} for {param}, which is not a valid "
            f"{enum_cls.__name__} value. Accepted: {_accepted(enum_cls)}."
        )
    raise _UsageTypeError(
        f"{call} takes {_takes(enum_cls, also_accepts)} (or its name as a string) for "
        f"{param}, but got {value!r} ({type(value).__name__}). "
        f"Accepted: {_accepted(enum_cls)}."
    )


def coerce_enum_collection(
    values: object,
    enum_cls: type[E],
    *,
    call: str,
    param: str,
) -> frozenset[E]:
    """Return a collection argument as a ``frozenset`` of ``enum_cls`` members.

    ``None`` and an empty collection both mean "none of them". A bare string is refused
    rather than treated as an iterable of characters: ``abort_on="blocked_member"`` is a
    plausible typo for ``abort_on=["blocked_member"]``, and iterating it would silently
    produce a nonsense set.
    """
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes)):
        raise _UsageTypeError(
            f"{call} takes a collection of {enum_cls.__name__} for {param}, but got "
            f"the bare string {values!r}. Pass a list or set, e.g. [{values!r}]."
        )
    if not isinstance(values, Iterable):
        raise _UsageTypeError(
            f"{call} takes a collection of {enum_cls.__name__} for {param}, but got "
            f"{values!r} ({type(values).__name__})."
        )
    return frozenset(
        coerce_enum(item, enum_cls, call=call, param=param) for item in values
    )
