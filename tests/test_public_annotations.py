"""Every public signature's annotations resolve at runtime (``typing.get_type_hints``),
so documentation generators and integrations that read them get types, not a
``NameError``. Report slicing is typed as it behaves."""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable, Iterator

import pytest

import archivey
from archivey import ExtractionReport, MemberListReport


def _annotated() -> Iterator[tuple[str, Callable[..., object] | type]]:
    for name in archivey.__all__:
        obj = getattr(archivey, name)
        if inspect.isclass(obj):
            yield name, obj
            for attr, value in vars(obj).items():
                if attr.startswith("_") and attr != "__init__":
                    continue
                if isinstance(value, property) and value.fget is not None:
                    yield f"{name}.{attr}", value.fget
                elif isinstance(value, (classmethod, staticmethod)):
                    yield f"{name}.{attr}", value.__func__
                elif inspect.isfunction(value):
                    yield f"{name}.{attr}", value
        elif inspect.isfunction(obj):
            yield name, obj


_ANNOTATED = dict(_annotated())


# Parametrized by name only: an object's repr carries its address, which differs
# between xdist workers, and they must collect the same test ids.
@pytest.mark.parametrize("name", sorted(_ANNOTATED))
def test_public_annotation_resolves(name: str) -> None:
    typing.get_type_hints(_ANNOTATED[name])


def test_report_slices_are_typed_as_tuples() -> None:
    for cls in (ExtractionReport, MemberListReport):
        hints = [
            typing.get_type_hints(f) for f in typing.get_overloads(cls.__getitem__)
        ]
        assert [h["index"] for h in hints] == [int, slice]
        assert typing.get_origin(hints[1]["return"]) is tuple
