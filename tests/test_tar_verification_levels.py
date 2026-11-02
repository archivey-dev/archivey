"""A compressed tar's whole-stream checksum raises every member it covers.

``verification-level-redesign``, task 3.3: a ``.tar.gz`` trailer (or a bzip2 stream
CRC) covers every member's bytes, so once a walk reads the archive to the codec's end
and the checksum matches, every file is ``CHECKSUM``, read or not. Before that a file
read to its end is ``LENGTH``.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile

import pytest

from archivey import Verification, open_archive
from archivey.types import ArchiveMember
from tests.test_audit_tar_streams import _TRAILER, _gnu_sparse, _member

_FILES = {"a": b"first " * 500, "b": b"second " * 3}


def _tar(mode: str) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode=mode) as tar:
        for name, data in _FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("d")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    return out.getvalue()


def _listing(data: bytes, *, streaming: bool) -> list[ArchiveMember]:
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        if streaming:
            report = reader.members_report()
            assert report.error is None
            return list(report.members)
        return list(reader.members())


def _levels(members: list[ArchiveMember]) -> dict[str, tuple[Verification, ...]]:
    return {m.name: (m.verified, m.verifiable) for m in members}


_CHECKED = (Verification.CHECKSUM, Verification.CHECKSUM)
_DIR = (Verification.UNLOCKED, Verification.UNLOCKED)
_UNREAD = (Verification.UNLOCKED, Verification.LENGTH)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("mode", ["w:gz", "w:bz2"])
def test_a_listing_that_reaches_the_checksum_raises_every_file(
    mode: str, streaming: bool
) -> None:
    members = _listing(_tar(mode), streaming=streaming)
    assert _levels(members) == {"a": _CHECKED, "b": _CHECKED, "d/": _DIR}


@pytest.mark.parametrize("streaming", [False, True])
def test_a_plain_tar_has_no_checksum_to_raise_with(streaming: bool) -> None:
    members = _listing(_tar("w"), streaming=streaming)
    assert _levels(members) == {"a": _UNREAD, "b": _UNREAD, "d/": _DIR}


@pytest.mark.parametrize("streaming", [False, True])
def test_a_trailer_that_does_not_match_raises_nothing(streaming: bool) -> None:
    data = bytearray(_tar("w:gz"))
    data[-8] ^= 0xFF  # the gzip trailer's CRC-32
    with open_archive(io.BytesIO(bytes(data)), streaming=streaming) as reader:
        report = reader.members_report()
        assert report.error is not None
        assert {m.verified for m in report.members} <= {Verification.UNLOCKED}


def test_a_file_read_in_a_pass_reaches_checksum_at_the_archive_end() -> None:
    with open_archive(io.BytesIO(_tar("w:gz")), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            if stream is not None:
                assert stream.read() == _FILES[member.name]
                # The trailer is not reached yet: only the length is proved.
                assert member.verified is Verification.LENGTH
            seen.append(member)
    assert _levels(seen) == {"a": _CHECKED, "b": _CHECKED, "d/": _DIR}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "sizes",
    [
        pytest.param((5000, 3000), id="two-past-the-walk-buffer"),
        pytest.param((200_000,), id="one-large"),
        pytest.param((1000,) * 10, id="ten-small"),
    ],
)
def test_a_listing_that_skips_member_data_still_raises_every_file(
    sizes: tuple[int, ...], streaming: bool
) -> None:
    # A random-access walk skips each member's data. Past the walk's buffer that skip
    # must decode through, or the trailer would not count (review round 1, K1).
    rng = random.Random(len(sizes))
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for index, size in enumerate(sizes):
            info = tarfile.TarInfo(f"m{index}")
            info.size = size
            tar.addfile(info, io.BytesIO(rng.randbytes(size)))
    members = _listing(out.getvalue(), streaming=streaming)
    assert {(m.verified, m.verifiable) for m in members} == {_CHECKED}


@pytest.mark.parametrize("streaming", [False, True])
def test_a_sparse_file_is_left_to_its_own_reads(streaming: bool) -> None:
    # Its holes are not stored bytes, so the trailer does not cover all it reads as.
    sparse = _gnu_sparse("s", [(0, 512), (4096, 512)], 8192, b"x" * 1024)
    tar = _member("a", _FILES["a"]) + sparse + _TRAILER
    members = _listing(gzip.compress(tar), streaming=streaming)
    levels = _levels(members)
    assert levels["a"] == _CHECKED
    assert levels["s"] == _UNREAD
