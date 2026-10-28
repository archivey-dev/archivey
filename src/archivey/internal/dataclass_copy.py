"""``dataclasses.replace``, a few times faster, for the copies made once per member.

``dataclasses.replace`` looks up every field by name, checks it, and passes them all to
``__init__`` as keywords: a few microseconds for a dataclass of ten or twenty fields.
Extraction copies each member (``ArchiveMember.replace``) and its result
(``ExtractionResult``) at least once per member, and a reader copies its decoder config
(``StreamConfig``) and member locator for every member it opens, so that adds up. :func:`copy_with`
fetches the fields with one ``attrgetter`` and passes them by position instead. Every
positional copy of a dataclass goes through here; do not add another.

It covers dataclasses whose fields are all positional ``__init__`` parameters, with no
``__post_init__`` (which would run again on the copy, as ``dataclasses.replace`` runs
it). Any other class, and a name that is not a field, take ``dataclasses.replace`` and
its errors, so a misspelled name is still a ``TypeError`` at runtime.

``changes`` is typed ``Any``, which is not a check: type checkers verify neither the
keyword names nor the value types at a call site, as they do for
``dataclasses.replace``. A wrongly typed value is accepted and shows up only where it is
used.
"""

from __future__ import annotations

import dataclasses
from operator import attrgetter
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

_T = TypeVar("_T", bound="DataclassInstance")

# Per class: its fields' getter and each field's position, or ``None`` when the class
# needs ``dataclasses.replace``.
_PLANS: dict[
    type[DataclassInstance], tuple[attrgetter[Any], dict[str, int]] | None
] = {}


def _plan(
    cls: type[DataclassInstance],
) -> tuple[attrgetter[Any], dict[str, int]] | None:
    fields = dataclasses.fields(cls)
    if (
        len(fields) < 2  # attrgetter of one name returns the value, not a tuple
        or hasattr(cls, "__post_init__")
        or not all(f.init and not f.kw_only for f in fields)
    ):
        return None
    names = tuple(f.name for f in fields)
    return attrgetter(*names), {name: i for i, name in enumerate(names)}


def copy_with(obj: _T, /, **changes: Any) -> _T:
    """``dataclasses.replace(obj, **changes)``: a copy of the dataclass ``obj`` with
    ``changes`` applied, built by passing every field to ``__init__`` by position."""
    cls = type(obj)
    try:
        plan = _PLANS[cls]
    except KeyError:
        plan = _PLANS[cls] = _plan(cls)
    if plan is None:
        return dataclasses.replace(obj, **changes)
    getter, index = plan
    values = list(getter(obj))
    try:
        for name, value in changes.items():
            values[index[name]] = value
    except KeyError:  # not a field: ``dataclasses.replace`` raises its own error
        return dataclasses.replace(obj, **changes)
    return cls(*values)
