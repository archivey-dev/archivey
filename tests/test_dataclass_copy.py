"""``copy_with``: ``dataclasses.replace`` by position, for the per-member copies."""

from __future__ import annotations

import dataclasses
import io
import zipfile
from dataclasses import dataclass, field

import pytest

from archivey import open_archive
from archivey.internal import dataclass_copy
from archivey.internal.backends.zip_reader import _ZipLocator
from archivey.internal.config import StreamConfig
from archivey.internal.dataclass_copy import copy_with
from archivey.types import ExtractionResult


# ``ArchiveMember`` has its own test (``test_replace_copies_every_field_as_...``), since
# its ``replace`` clears two fields on the copy.
@pytest.mark.parametrize("cls", [ExtractionResult, StreamConfig, _ZipLocator])
def test_copy_with_copies_every_field_as_dataclasses_replace_does(cls: type) -> None:
    # The classes copied once per member take the positional path.
    fields = dataclasses.fields(cls)
    assert dataclass_copy._plan(cls) is not None
    # A distinct object in every field, so a field copied into the wrong position
    # shows up as the wrong object, not as an equal default.
    given = {f.name: object() for f in fields}
    obj = cls(**given)
    every = {f.name: object() for f in fields}
    first = fields[0].name
    for changes in ({}, {first: None}, every):
        fast = copy_with(obj, **changes)
        slow = dataclasses.replace(obj, **changes)
        assert type(fast) is cls
        for f in fields:
            assert getattr(fast, f.name) is getattr(slow, f.name), f.name
            assert getattr(fast, f.name) is changes.get(f.name, given[f.name]), f.name


@dataclass(frozen=True)
class _PostInit:
    a: int
    b: int
    seen: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.seen.append(self.a)


@dataclass
class _KeywordOnly:
    a: int
    b: int = field(default=0, kw_only=True)


@dataclass
class _NotInInit:
    a: int
    b: int
    c: int = field(default=7, init=False)


@pytest.mark.parametrize(
    ("obj", "changes"),
    [
        (_PostInit(1, 2), {"a": 3}),
        (_KeywordOnly(1, b=2), {"b": 3}),
        (_NotInInit(1, 2), {"a": 3}),
    ],
    ids=["post-init", "keyword-only", "not-in-init"],
)
def test_copy_with_falls_back_where_position_cannot_carry_it(
    obj: object, changes: dict[str, int]
) -> None:
    assert dataclass_copy._plan(type(obj)) is None
    assert copy_with(obj, **changes) == dataclasses.replace(obj, **changes)  # type: ignore[type-var]


def test_copy_with_refuses_a_name_that_is_not_a_field() -> None:
    with pytest.raises(TypeError, match="nope"):
        copy_with(ExtractionResult(None, None, None), nope=1)  # type: ignore[arg-type]


def test_a_deflated_zip_member_copies_its_decoder_config_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader fills what the codec's own config pass would change, so opening a
    member makes one copy of the config, not two."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"hello " * 100)
    copies: list[str] = []
    real = dataclass_copy.copy_with

    def counting(obj: object, /, **changes: object) -> object:
        copies.append(type(obj).__name__)
        return real(obj, **changes)  # type: ignore[type-var]

    for module in (
        "archivey.internal.backends.zip_reader",
        "archivey.internal.streams.codecs.registry",
    ):
        monkeypatch.setattr(f"{module}.copy_with", counting)
    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == b"hello " * 100
    assert copies.count("StreamConfig") == 1
