"""``copy_with``: ``dataclasses.replace`` by position, for the per-member copies."""

from __future__ import annotations

import dataclasses
import io
import zipfile
from dataclasses import InitVar, dataclass, field

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


def test_copy_with_copies_a_post_init_class_by_position() -> None:
    # Its constructor still takes exactly its fields; ``__post_init__`` runs on the copy
    # either way, as it does under ``dataclasses.replace``.
    assert dataclass_copy._plan(_PostInit) is not None
    obj = _PostInit(1, 2)
    fast = copy_with(obj, a=3)
    slow = dataclasses.replace(obj, a=3)
    assert (fast.a, fast.b) == (slow.a, slow.b) == (3, 2)
    assert fast.seen is slow.seen is obj.seen
    assert obj.seen == [1, 3, 3]


@dataclass(frozen=True)
class _InitVarNoPostInit:
    a: int
    iv: InitVar[int] = 0
    b: int = 5


@dataclass
class _KeywordOnly:
    a: int
    b: int = field(default=0, kw_only=True)


@dataclass
class _NotInInit:
    a: int
    b: int
    c: int = field(default=7, init=False)


@dataclass(init=False)
class _NoInit:
    a: int
    b: int

    def __init__(self, b: int, a: int) -> None:
        self.a = a
        self.b = b


@pytest.mark.parametrize(
    ("obj", "changes"),
    [
        (_InitVarNoPostInit(1, 99, 7), {"a": 2}),
        (_KeywordOnly(1, b=2), {"b": 3}),
        (_NotInInit(1, 2), {"a": 3}),
        (_NoInit(b=2, a=1), {"a": 3}),
    ],
    ids=["initvar", "keyword-only", "not-in-init", "own-init"],
)
def test_copy_with_falls_back_where_position_cannot_carry_it(
    obj: object, changes: dict[str, int]
) -> None:
    # Each constructor takes something other than exactly the fields in order, so a
    # positional call would put a value in the wrong place.
    assert dataclass_copy._plan(type(obj)) is None  # type: ignore[arg-type]
    assert copy_with(obj, **changes) == dataclasses.replace(obj, **changes)  # type: ignore[type-var]


def test_copy_with_refuses_a_name_that_is_not_a_field() -> None:
    with pytest.raises(TypeError, match="nope"):
        copy_with(ExtractionResult(None, None, None), nope=1)  # type: ignore[arg-type]


def test_a_deflated_zip_member_builds_one_decoder_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader fills what the codec's own config pass would change, so reading a
    member builds one copy of its decoder config, not two. Counted at the constructor,
    so a copy made anywhere, by ``copy_with`` or ``dataclasses.replace``, counts."""
    data = {"a.txt": b"hello " * 100, "b.txt": b"world " * 100}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in data.items():
            zf.writestr(name, content)
    built = 0
    init = StreamConfig.__init__

    def counting(self: StreamConfig, *args: object, **kwargs: object) -> None:
        nonlocal built
        built += 1
        init(self, *args, **kwargs)  # type: ignore[arg-type]

    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        reader.members()
        # Pin the real plan first: computed under the patch, it would read the patched
        # signature, cache ``None`` and send every later copy to the fallback.
        monkeypatch.setitem(
            dataclass_copy._PLANS, StreamConfig, dataclass_copy._plan(StreamConfig)
        )
        monkeypatch.setattr(StreamConfig, "__init__", counting)
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == data[member.name]
    assert built == len(data)  # one per member
    assert dataclass_copy._PLANS[StreamConfig] is not None
