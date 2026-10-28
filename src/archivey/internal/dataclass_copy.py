"""``dataclasses.replace``, a few times faster, for the copies made once per member.

``dataclasses.replace`` looks up every field by name, checks it, and passes them all to
``__init__`` as keywords: a few microseconds for a dataclass of ten or twenty fields.
Extraction copies each member (``ArchiveMember.replace``) and its result
(``ExtractionResult``) once each on the default extract path, and a reader copies its
decoder config (``StreamConfig``) for every member it opens, as the ZIP reader also
copies its member locator, so that adds up. :func:`copy_with` fetches the fields with
one ``attrgetter`` and passes them by position instead. Every positional copy of a
dataclass goes through here; do not add another.

It covers a class of at least two fields whose constructor takes exactly its fields,
in field order, each as a positional parameter, which is what a call by position
needs. A ``__post_init__`` runs on the copy either way, as it does under
``dataclasses.replace``. A class whose constructor differs (an ``InitVar``, a
keyword-only or ``init=False`` field, a hand-written ``__init__`` with other
parameters), a class whose signature cannot be read, and a name that is not a field,
take ``dataclasses.replace`` and its errors, so a misspelled name is still a
``TypeError`` at runtime.

``changes`` is typed ``Any``, which is not a check: type checkers verify neither the
keyword names nor the value types at a call site, as they do for
``dataclasses.replace``. A wrongly typed value is accepted and shows up only where it is
used.
"""

from __future__ import annotations

import dataclasses
import inspect
from operator import attrgetter
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

_T = TypeVar("_T", bound="DataclassInstance")

# Per class: its fields' getter and each field's position, or ``None`` when the class
# needs ``dataclasses.replace``. Unbounded, and it holds each class it has seen: the
# classes copied are archivey's own few, and a caller's subclass of a public one
# (``ArchiveMember``) adds one entry for the life of the process.
_PLANS: dict[
    type[DataclassInstance], tuple[attrgetter[Any], dict[str, int]] | None
] = {}


def _plan(
    cls: type[DataclassInstance],
) -> tuple[attrgetter[Any], dict[str, int]] | None:
    names = tuple(f.name for f in dataclasses.fields(cls))
    if len(names) < 2:  # attrgetter of one name returns the value, not a tuple
        return None
    try:
        parameters = tuple(inspect.signature(cls).parameters.values())
    # No signature to read, or (from Python 3.14) an annotation that does not evaluate:
    # copy by name.
    except (TypeError, ValueError, NameError, AttributeError):
        return None
    # The constructor takes exactly the fields, in order, each by position.
    if tuple(p.name for p in parameters) != names or any(
        p.kind is not p.POSITIONAL_OR_KEYWORD for p in parameters
    ):
        return None
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
