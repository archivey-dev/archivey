"""A member's data error stays with that member; the pass reads on past it.

``archive-reading`` "Bounded-memory sequential streaming via stream_members": a damaged
member raises from its own stream read, ``stream_members()`` then yields the members
after it whenever the walk can reach them, and the pass ends without raising. Members
after the damage in the same solid block raise their own error; a later solid block reads
cleanly. Random access (``members()`` plus ``open()``) gives each member the same outcome.

Only ``b.txt``'s data is damaged in every case; the headers and the listing are intact.
The 7z and RAR archives are committed (``tests/fixtures/damaged_member/``, built by
``scripts/fixtures/gen_damaged_member_fixtures.py``, which checks the damage against ``7z t`` and
``unrar t``). The ZIP, TAR and ISO cases are built here.
"""

from __future__ import annotations

import io
import random
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal

import pytest

from archivey import ArchiveMember, ArchiveReader, open_archive
from archivey.exceptions import CorruptionError
from tests.conftest import requires, requires_binary
from tests.streams_util import NonSeekableBytesIO

_FIXTURES = Path(__file__).parent / "fixtures" / "damaged_member"
_MEMBER_SIZE = 6000
_ABC = ("a.txt", "b.txt", "c.txt")

Outcome = Literal["ok", "raises", "wrong"]
"""``ok``: the right bytes. ``raises``: ``CorruptionError`` from the read. ``wrong``: the
format stores no member checksum, so the damaged bytes come back with no error."""


def _member_text(name: str) -> bytes:
    """Member content; ``scripts/fixtures/gen_damaged_member_fixtures.py`` imports this function."""
    vocab_rng = random.Random("damaged-member-vocab")
    vocab = [
        "".join(
            vocab_rng.choice("abcdefghijklmnopqrstuvwxyz")
            for _ in range(vocab_rng.randint(2, 9))
        )
        for _ in range(500)
    ]
    rng = random.Random(name)
    out = name[0].upper().encode() * 8
    while len(out) < _MEMBER_SIZE:
        out += b" " + rng.choice(vocab).encode()
    return out[:_MEMBER_SIZE]


def _flip_inside_b(data: bytes) -> bytes:
    """Damage one byte in the middle of ``b.txt``'s stored bytes."""
    pos = data.index(b"B" * 8) + _MEMBER_SIZE // 2
    damaged = bytearray(data)
    damaged[pos] ^= 0x5A
    return bytes(damaged)


class _UnseekableSink(io.BytesIO):
    """An output ``zipfile`` cannot seek in, so it writes data descriptors."""

    def seekable(self) -> bool:
        return False

    def seek(self, *_args: object) -> int:
        raise io.UnsupportedOperation("seek")


def _zip(method: int, *, pipe: bool = False) -> bytes:
    sink = _UnseekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(sink, "w", compression=method) as zf:
        for name in _ABC:
            zf.writestr(name, _member_text(name))
    return sink.getvalue()


def _zip_stored() -> bytes:
    return _flip_inside_b(_zip(zipfile.ZIP_STORED))


def _zip_deflated(*, pipe: bool = False) -> bytes:
    data = _zip(zipfile.ZIP_DEFLATED, pipe=pipe)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        info = zf.getinfo("b.txt")
    start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    damaged = bytearray(data)
    mid = start + info.compress_size // 2
    for i in range(16):
        damaged[mid + i] ^= 0x5A
    return bytes(damaged)


def _tar() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in _ABC:
            info = tarfile.TarInfo(name)
            info.size = _MEMBER_SIZE
            tf.addfile(info, io.BytesIO(_member_text(name)))
    return _flip_inside_b(out.getvalue())


def _iso() -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    for name in _ABC:
        data = _member_text(name)
        iso.add_fp(io.BytesIO(data), len(data), f"/{name.upper()};1", rr_name=name)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return _flip_inside_b(out.getvalue())


@dataclass(frozen=True)
class _Case:
    id: str
    source: Callable[[], bytes]
    outcomes: dict[str, Outcome]
    pipe: bool = False
    marks: tuple[pytest.MarkDecorator, ...] = ()


def _committed(name: str) -> Callable[[], bytes]:
    return lambda: (_FIXTURES / name).read_bytes()


_NON_SOLID: dict[str, Outcome] = {"a.txt": "ok", "b.txt": "raises", "c.txt": "ok"}
_SOLID: dict[str, Outcome] = {"a.txt": "ok", "b.txt": "raises", "c.txt": "raises"}
_UNCHECKED: dict[str, Outcome] = {"a.txt": "ok", "b.txt": "wrong", "c.txt": "ok"}
# Compressed RAR data needs the ``unrar`` binary; stored RAR data reads without it.
_UNRAR = (requires_binary("unrar"),)

_CASES = (
    _Case("zip-stored-crc", _zip_stored, _NON_SOLID),
    _Case("zip-deflate-stream", _zip_deflated, _NON_SOLID),
    _Case("zip-deflate-pipe", lambda: _zip_deflated(pipe=True), _NON_SOLID, pipe=True),
    _Case("7z-copy-nonsolid-crc", _committed("7z_copy_nonsolid.7z"), _NON_SOLID),
    _Case("7z-lzma-nonsolid-stream", _committed("7z_lzma_nonsolid.7z"), _NON_SOLID),
    _Case("7z-lzma-solid-one-folder", _committed("7z_lzma_solid.7z"), _SOLID),
    _Case(
        "7z-lzma-solid-two-folders",
        _committed("7z_lzma_2folders.7z"),
        {**_NON_SOLID, "d.txt": "ok"},
    ),
    _Case("rar5-stored-crc", _committed("rar5_stored.rar"), _NON_SOLID),
    _Case(
        "rar5-nonsolid-stream",
        _committed("rar5_nonsolid.rar"),
        _NON_SOLID,
        marks=_UNRAR,
    ),
    _Case("rar5-solid-stream", _committed("rar5_solid.rar"), _SOLID, marks=_UNRAR),
    _Case("tar-plain", _tar, _UNCHECKED),
    _Case("iso", _iso, _UNCHECKED, marks=(requires("pycdlib"),)),
)


def _outcome(name: str, read: Callable[[], bytes]) -> Outcome:
    try:
        data = read()
    except CorruptionError:
        # ``TruncatedError`` counts too: a flip inside an LZMA or RAR stream can
        # legitimately decode short, so either error means the member raised.
        return "raises"
    return "ok" if data == _member_text(name) else "wrong"


def _open_and_read(reader: ArchiveReader, member: ArchiveMember) -> bytes:
    # On a solid block ``open()`` decodes from the block start up to the member, so a
    # member after the damage can raise from ``open()`` rather than from ``read()``.
    with reader.open(member) as stream:
        return stream.read()


def _pass_params() -> list[object]:
    # A pipe opens only with ``streaming=True``.
    return [
        pytest.param(
            c,
            streaming,
            id=f"{c.id}-{'streaming' if streaming else 'random-access'}",
            marks=c.marks,
        )
        for c in _CASES
        for streaming in (False, True)
        if streaming or not c.pipe
    ]


@pytest.mark.parametrize("read_b", [True, False], ids=["read-b", "skip-b"])
@pytest.mark.parametrize(("case", "streaming"), _pass_params())
def test_stream_members_reads_past_a_damaged_member(
    case: _Case, streaming: bool, read_b: bool
) -> None:
    data = case.source()
    source = NonSeekableBytesIO(data) if case.pipe else io.BytesIO(data)
    seen: dict[str, Outcome | None] = {}
    with open_archive(source, streaming=streaming) as reader:
        # A plain ``for``: the pass must end with StopIteration, not raise.
        for member, stream in reader.stream_members():
            assert stream is not None
            if member.name == "b.txt" and not read_b:
                seen[member.name] = None
                continue
            seen[member.name] = _outcome(member.name, stream.read)
    expected: dict[str, Outcome | None] = dict(case.outcomes)
    if not read_b:
        expected["b.txt"] = None
    assert seen == expected


@pytest.mark.parametrize(
    "case", [pytest.param(c, id=c.id, marks=c.marks) for c in _CASES if not c.pipe]
)
def test_random_access_gives_each_member_the_same_outcome(case: _Case) -> None:
    with open_archive(io.BytesIO(case.source())) as reader:
        seen: dict[str, Outcome] = {}
        for member in reader.members():
            seen[member.name] = _outcome(
                member.name, partial(_open_and_read, reader, member)
            )
    assert seen == case.outcomes
