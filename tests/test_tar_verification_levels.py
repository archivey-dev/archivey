"""A compressed tar's whole-stream checksum raises every member it covers.

``verification-level-redesign``, task 3.3: a ``.tar.gz`` trailer (or a bzip2 stream
CRC) covers every member's bytes, so once a walk reads the archive to the codec's end
and the checksum matches, every file is ``CHECKSUM``, read or not. Before that a file
read to its end is ``LENGTH``.
"""

from __future__ import annotations

import io
import tarfile

import pytest

from archivey import Verification, open_archive
from archivey.types import ArchiveMember

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
