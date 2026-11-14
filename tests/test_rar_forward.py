"""RAR read front to back from a source that cannot seek (``rar_forward``)."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from archivey.internal.backends import rar_parser as rp
from archivey.internal.backends.rar_forward import ForwardSource, ForwardSpan

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
# Volumes of a set, and archives whose walk needs a password the test gives.
_SINGLE = sorted(
    p
    for p in _FIXTURES.glob("*.rar")
    if ".part" not in p.name and p.name != "tinyvol_rnn.rar"
)
_PASSWORD = "password"


class _Pipe(io.RawIOBase):
    """Bytes read once, in pieces of at most ``step``: a pipe."""

    def __init__(self, data: bytes, step: int = 4093) -> None:
        self._data = memoryview(data)
        self._at = 0
        self._step = step

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data)
        n = min(n, self._step)
        out = bytes(self._data[self._at : self._at + n])
        self._at += len(out)
        return out


def _fields(member: rp.RarMemberInfo) -> tuple[object, ...]:
    return (
        member.filename,
        member.header_offset,
        member.data_offset,
        member.compress_size,
        member.file_size,
        member.crc32,
        member.file_solid,
    )


def _parse(data: bytes, password: str | None) -> rp.RarArchive:
    return rp.parse_rar_archive(
        io.BytesIO(data), password=password, use_qo=False, kdf_cache=rp.RarKdfCache()
    )


@pytest.mark.parametrize("cut", [None, 0.5, 0.9])
@pytest.mark.parametrize("path", _SINGLE, ids=lambda p: p.name)
def test_a_forward_walk_lists_what_the_seekable_walk_lists(
    path: Path, cut: float | None
) -> None:
    """Every member, read from a pipe with each member's data consumed before the
    walk goes on, as the seekable walk lists it, whole or cut short; the walk never
    seeks back past what the forward source holds."""
    data = path.read_bytes()
    if cut is not None:
        data = data[: int(len(data) * cut)]
    try:
        expected = _parse(data, None)
        password = None
    except Exception:  # noqa: BLE001 - a header password, or not a walkable RAR
        try:
            expected = _parse(data, _PASSWORD)
        except Exception:  # noqa: BLE001
            pytest.skip("the seekable walk does not list this archive either")
        password = _PASSWORD
    source = ForwardSource(_Pipe(data))
    _version, walk = rp.open_forward_walk(
        source,
        password=password,
        kdf_cache=rp.RarKdfCache(),
        max_members=None,
        max_metadata_bytes=None,
    )
    got = []
    for found in rp.public_walk_errors(walk.walk()):
        assert source.tell() == found.data_offset
        span = ForwardSpan(source, found.data_offset, found.data_size)
        consumed = 0
        while chunk := span.read(1000):
            consumed += len(chunk)
        assert consumed == min(found.data_size, len(data) - found.data_offset)
        got.append(found.member)
    archive = walk.result()
    rp._settle_rar15_solid(archive)
    assert [_fields(m) for m in archive.members] == [
        _fields(m) for m in expected.members
    ]
    assert len(got) == sum(1 for m in expected.members)
    assert archive.comment == expected.comment
    assert archive.truncated == expected.truncated
    assert archive.damaged == expected.damaged


def test_the_forward_source_refuses_a_seek_back_past_what_it_holds() -> None:
    source = ForwardSource(_Pipe(bytes(range(256)) * 100), keep=1000)
    source.seek(5000)
    assert source.read(4) == bytes(range(256))[5000 % 256 : 5000 % 256 + 4]
    source.seek(4100)  # held
    with pytest.raises(io.UnsupportedOperation):
        source.seek(3000)
    with pytest.raises(io.UnsupportedOperation):
        source.seek(0, io.SEEK_END)
    source.seek(30_000)
    assert source.read(1) == b""
    assert source.seek(0, io.SEEK_END) == 25_600
