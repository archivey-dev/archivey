"""TAR header structures that expand before any listing limit sees them.

Each test builds a small crafted archive whose headers could make the parser allocate
far more than the archive's size: a chain of extended headers, a sparse map, many PAX
records of one key, or a PAX global header copied into every member. Each must be
bounded by ``max_metadata_bytes`` in both access modes (DR-9a), and an honest archive of
the same shape must still list.
"""

from __future__ import annotations

import copy
import io
import json
import pickle
import tarfile
from typing import cast

import pytest

from archivey import (
    ArchiveyConfig,
    CorruptionError,
    ListingLimits,
    ResourceLimitError,
    TruncatedError,
    open_archive,
)
from tests.memory_util import traced_peak

_TRAILER = b"\0" * 1024


def _pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 512)


def _pax_body(records: dict[str, str]) -> bytes:
    body = b""
    for keyword, value in records.items():
        text = f" {keyword}={value}\n".encode()
        length = len(text) + 1
        while len(str(length)) + len(text) != length:
            length += 1
        body += str(length).encode() + text
    return body


def _extended(body: bytes, typeflag: bytes) -> bytes:
    """One extended header (PAX ``x`` / ``g`` or GNU ``L``) carrying ``body``."""
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = typeflag
    info.size = len(body)
    return info.tobuf(format=tarfile.USTAR_FORMAT) + _pad(body)


def _plain(name: str, data: bytes = b"") -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info.tobuf(format=tarfile.USTAR_FORMAT) + _pad(data)


def _names(data: bytes, cap: int | None, *, streaming: bool) -> list[str]:
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=cap))
    with open_archive(io.BytesIO(data), config=config, streaming=streaming) as ar:
        if streaming:
            return [member.name for member, _ in ar.stream_members()]
        return [member.name for member in ar.members()]


_MODES = pytest.mark.parametrize(
    "streaming", [False, True], ids=["random-access", "streaming"]
)


# ---------------------------------------------------------------------------
# A chain of extended headers ahead of one member
# ---------------------------------------------------------------------------


def _chain(typeflag: bytes, links: int, size: int) -> bytes:
    if typeflag == tarfile.GNUTYPE_LONGNAME:
        bodies = [b"n" * size + b"\0" for _ in range(links)]
    else:
        bodies = [_pax_body({f"k{i}": "v" * size}) for i in range(links)]
    return b"".join(_extended(body, typeflag) for body in bodies) + _plain("m")


@_MODES
@pytest.mark.parametrize(
    "typeflag", [tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME], ids=["pax", "gnu-longname"]
)
def test_a_chain_of_extended_headers_draws_from_one_budget(
    typeflag: bytes, streaming: bool
) -> None:
    """Each header of a chain was checked against the whole of what the member had
    left, so four 300 KB headers listed under a 1 MiB cap. ``tarfile`` keeps every link
    of the chain alive until the member is built, so the chain is what the member
    costs."""
    data = _chain(typeflag, links=4, size=300_000) + _TRAILER
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        _names(data, 2**20, streaming=streaming)


@_MODES
def test_a_chain_under_the_budget_still_lists(streaming: bool) -> None:
    data = _chain(tarfile.XHDTYPE, links=2, size=300_000) + _TRAILER
    assert _names(data, 2**20, streaming=streaming) == ["m"]


@pytest.mark.parametrize("streaming", [True, False], ids=["streaming", "random"])
def test_the_budget_is_what_the_listing_has_not_retained(streaming: bool) -> None:
    """Every walk enforces the running total, so a member's headers get only what the
    members before it left of the cap. Three members, because the first one's headers
    are parsed as the archive opens."""
    member = _chain(tarfile.XHDTYPE, links=2, size=300_000)
    data = member * 3 + _TRAILER
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        _names(data, 2**20, streaming=streaming)


# ---------------------------------------------------------------------------
# Sparse maps
# ---------------------------------------------------------------------------


def _sparse_1_0(entries: bytes, *, count: int) -> bytes:
    pax = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "f",
        "GNU.sparse.realsize": "0",
    }
    body = b"%d\n" % count + entries
    return _extended(_pax_body(pax), tarfile.XHDTYPE) + _plain(
        "GNUSparseFile.0/f", body
    )


def _sparse_0_1(entries: int) -> bytes:
    pax = {
        "GNU.sparse.map": ",".join(["0,0"] * entries),
        "GNU.sparse.name": "f",
        "GNU.sparse.realsize": "0",
    }
    return _extended(_pax_body(pax), tarfile.XHDTYPE) + _plain("f")


def _sparse_0_0(entries: int) -> bytes:
    records = "".join(
        f"{len(r) + 3} {r}" if len(r) + 3 < 100 else f"{len(r) + 4} {r}"
        for _ in range(entries)
        for r in ("GNU.sparse.offset=0\n", "GNU.sparse.numbytes=0\n")
    )
    pax = _pax_body({"GNU.sparse.size": "0", "GNU.sparse.name": "f"})
    return _extended(pax + records.encode(), tarfile.XHDTYPE) + _plain("f")


def _old_gnu_sparse(extension_blocks: int) -> bytes:
    """An old GNU ``S`` member followed by ``extension_blocks`` blocks of 21 map
    entries each, every block but the last flagged as extended."""
    info = tarfile.TarInfo("f")
    info.type = tarfile.GNUTYPE_SPARSE
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = 1  # isextended
    header[148:156] = b" " * 8
    header[148:155] = b"%06o\0" % sum(header)
    entry = b"%011o\0" % 1 + b"%011o\0" % 1
    blocks = b""
    for i in range(extension_blocks):
        block = bytearray(entry * 21 + b"\0" * 8)
        block[504] = 1 if i < extension_blocks - 1 else 0
        blocks += bytes(block)
    return bytes(header) + blocks


# Each map; a cap its header text fits under but its entries (24 bytes each) do not,
# since a cap the header text alone passes is refused by the header check already; and
# the peak allowed, in multiples of the archive's size. A 0.0 or 0.1 map is header
# text, which ``tarfile`` parses whole (bounded by the header check) before the map's
# entries are counted. A 1.0 or old GNU map is not, so its walk costs about nothing.
_SPARSE_BOMBS = {
    "pax-1.0": (lambda: _sparse_1_0(b"0\n0\n" * 200_000, count=200_000), 64 * 1024, 1),
    "pax-0.1": (lambda: _sparse_0_1(200_000), 2 * 2**20, 5),
    "pax-0.0": (lambda: _sparse_0_0(20_000), 1_100_000, 8),
    "old-gnu": (lambda: _old_gnu_sparse(5_000), 64 * 1024, 1),
}


@_MODES
@pytest.mark.parametrize("kind", list(_SPARSE_BOMBS))
def test_a_sparse_map_is_weighed_before_it_is_parsed(
    kind: str, streaming: bool
) -> None:
    """A sparse map was parsed whole and weighed only at registration, so a map of
    hundreds of thousands of entries cost tens of MiB before ``members()`` refused it,
    and a streaming walk never refused it. It is refused as its entries are counted,
    before the list of entries is built."""
    build, cap, peak_factor = _SPARSE_BOMBS[kind]
    data = build() + _TRAILER

    def walk() -> None:
        with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
            _names(data, cap, streaming=streaming)

    walk()
    assert traced_peak(walk) < peak_factor * len(data) + 2**20


def test_a_sparse_map_within_the_budget_still_reads() -> None:
    # The member's data area is the map, padded to a block, then the stored bytes.
    stored = b"%d\n0\n3\n6\n3\n" % 2
    stored = _pad(stored) + b"abcdef"
    info = tarfile.TarInfo("GNUSparseFile.0/f")
    info.size = len(stored)
    pax = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "f",
        "GNU.sparse.realsize": "9",
    }
    data = (
        _extended(_pax_body(pax), tarfile.XHDTYPE)
        + info.tobuf(format=tarfile.USTAR_FORMAT)
        + _pad(stored)
        + _TRAILER
    )
    for streaming in (False, True):
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            for member, stream in ar.stream_members():
                assert member.name == "f"
                assert stream is not None
                assert stream.read() == b"abc\0\0\0def"


@_MODES
@pytest.mark.parametrize(
    ("entries", "count"),
    [(b"0\n" + b"1" * 21 + b"\n", 1), (b"0\n0\n", 10)],
    ids=["number-longer-than-gnu-tar-reads", "map-past-the-archive"],
)
def test_a_malformed_sparse_1_0_map_is_corruption(
    entries: bytes, count: int, streaming: bool
) -> None:
    """A map number was read into one buffer for as long as it had no newline, so the
    archive set how long it grew. GNU tar refuses a number longer than 20 digits, and
    so does the listing now. A map shorter than its count runs past the archive's end,
    and must stop there."""
    data = _sparse_1_0(entries, count=count) + _TRAILER
    with pytest.raises(CorruptionError):
        _names(data, None, streaming=streaming)


@_MODES
def test_an_old_gnu_sparse_map_cut_short_is_truncation(streaming: bool) -> None:
    """An old GNU sparse header that flags an extension block the archive does not
    have escaped as a raw ``IndexError`` from ``tarfile``'s parse."""
    header = _old_gnu_sparse(0)  # flagged as extended, with no block after it
    with pytest.raises(TruncatedError):
        _names(header, None, streaming=streaming)


# ---------------------------------------------------------------------------
# PAX global headers
# ---------------------------------------------------------------------------


def _global(records: dict[str, str]) -> bytes:
    return _extended(_pax_body(records), tarfile.XGLTYPE)


@_MODES
def test_global_records_are_held_once_not_once_per_member(streaming: bool) -> None:
    """``tarfile`` copies the global records into every later member, and the
    listing copied them again into ``extra``, so 50 KB of global records cost about
    800 KB per 512-byte member."""
    records = {f"key{i:05d}": "v" for i in range(5_000)}
    data = _global(records) + b"".join(_plain(f"m{i}") for i in range(200)) + _TRAILER

    def walk() -> None:
        assert len(_names(data, None, streaming=streaming)) == 200

    walk()
    assert traced_peak(walk) < 8 * 2**20


@_MODES
def test_repeated_pax_records_hold_one_value(streaming: bool) -> None:
    """A member's ``x`` header of 400 000 records of one key (3.6 MB of text) keeps
    one value, not an object per record: the records cost far more than their text,
    and ``max_metadata_bytes`` weighs the text."""
    body = b"9 a=bbbb\n" * 400_000
    data = _extended(body, tarfile.XHDTYPE) + _plain("f") + _TRAILER

    def walk() -> None:
        assert _names(data, None, streaming=streaming) == ["f"]

    walk()
    assert traced_peak(walk) < 4 * len(body)


def test_global_records_apply_to_the_members_after_them_only() -> None:
    """Members share one copy of the global records, so a later global header must
    not change what an earlier member reports."""
    data = (
        _global({"comment": "first"})
        + _plain("a")
        + _extended(_pax_body({"uname": "own"}), tarfile.XHDTYPE)
        + _plain("b")
        + _global({"comment": "second"})
        + _plain("c")
        + _plain("d")
        + _TRAILER
    )
    for streaming in (False, True):
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            if streaming:
                members = {m.name: m for m, _ in ar.stream_members()}
            else:
                members = {m.name: m for m in ar.members()}
        pax = {name: m.extra["tar.pax_headers"] for name, m in members.items()}
        assert pax == {
            "a": {"comment": "first"},
            "b": {"comment": "first", "uname": "own"},
            "c": {"comment": "second"},
            "d": {"comment": "second"},
        }
        assert members["b"].uname == "own"


@_MODES
def test_pax_records_in_extra_are_read_only(streaming: bool) -> None:
    """Members share one ``extra["tar.pax_headers"]`` per set of global records, so
    a change through one member would show on the others. Every change raises
    instead. The value still serializes and copies as a ``dict``, and a copy is the
    caller's to change."""
    data = (
        _global({"comment": "g"})
        + _plain("a")
        + _plain("b")
        + _extended(_pax_body({"uname": "own"}), tarfile.XHDTYPE)
        + _plain("c")
        + _TRAILER
    )
    with open_archive(io.BytesIO(data), streaming=streaming) as ar:
        if streaming:
            members = [member for member, _ in ar.stream_members()]
        else:
            members = ar.members()
    for member in members:
        pax = member.extra["tar.pax_headers"]
        mutable = cast("dict[str, str]", pax)
        changes = (
            lambda d: d.__setitem__("comment", "x"),
            lambda d: d.__delitem__("comment"),
            lambda d: d.__ior__({"comment": "x"}),
            lambda d: d.update(comment="x"),
            lambda d: d.pop("comment"),
            lambda d: d.popitem(),
            lambda d: d.setdefault("new", "x"),
            lambda d: d.clear(),
        )
        for change in changes:
            with pytest.raises(TypeError, match="read-only"):
                change(mutable)
        assert pax["comment"] == "g"
        assert json.loads(json.dumps(pax)) == dict(pax)
        for copied in (
            copy.copy(pax),
            copy.deepcopy(pax),
            pickle.loads(pickle.dumps(pax)),
            copy.deepcopy(member.extra)["tar.pax_headers"],
            pickle.loads(pickle.dumps(member.extra))["tar.pax_headers"],
        ):
            assert type(copied) is dict
            assert copied == pax
            copied["comment"] = "mine"
    assert [m.extra["tar.pax_headers"]["comment"] for m in members] == ["g"] * 3
