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
from pathlib import Path

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
def test_a_symlink_stays_unlocked_when_the_trailer_raises_the_files(
    streaming: bool,
) -> None:
    """A link has no data of its own, so it stays at UNLOCKED after the gzip
    trailer has raised every file to CHECKSUM."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "a"
        tar.addfile(link)
        info = tarfile.TarInfo("a")
        info.size = len(_FILES["a"])
        tar.addfile(info, io.BytesIO(_FILES["a"]))
    members = _listing(out.getvalue(), streaming=streaming)
    assert _levels(members) == {
        "link": (Verification.UNLOCKED, Verification.UNLOCKED),
        "a": _CHECKED,
    }


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
                # The trailer covers it: CHECKSUM is its ceiling before any read.
                assert member.verifiable is Verification.CHECKSUM
                assert stream.read() == _FILES[member.name]
                # The trailer is not reached yet: only the length is proved.
                assert member.verified is Verification.LENGTH
                assert member.verifiable is Verification.CHECKSUM
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


def test_verify_stops_at_length_below_the_trailer_ceiling() -> None:
    # stream.verify() never reads past its own member, so the trailer stays ahead.
    with open_archive(io.BytesIO(_tar("w:gz")), streaming=True) as reader:
        for member, stream in reader.stream_members():
            if stream is not None:
                assert stream.verify() is Verification.LENGTH
                assert stream.verifiable is Verification.CHECKSUM
        assert {
            (m.verified, m.verifiable)
            for m in reader.members_report().members
            if m.is_file
        } == {_CHECKED}


@pytest.mark.parametrize("streaming", [False, True])
def test_a_codec_with_no_check_never_sets_a_checksum_ceiling(streaming: bool) -> None:
    import lzma

    plain = _tar("w")
    data = lzma.compress(plain, format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        assert reader.verify_all() == ()
        members = [m for m in reader.members_report().members if m.is_file]
    assert {(m.verified, m.verifiable) for m in members} == {
        (Verification.LENGTH, Verification.LENGTH)
    }


def test_a_frame_without_a_check_found_later_drops_the_ceiling() -> None:
    # The first xz stream carries a check, the second does not: CHECKSUM is the
    # ceiling until the walk finds the second, then every file falls to LENGTH.
    import lzma

    big = random.Random(7).randbytes(1 << 20)
    head = _member("big", big)
    tail = _member("a", _FILES["a"]) + _TRAILER
    data = lzma.compress(head, check=lzma.CHECK_CRC64) + lzma.compress(
        tail, check=lzma.CHECK_NONE
    )
    with open_archive(io.BytesIO(data), streaming=True) as reader:
        first = True
        for member, stream in reader.stream_members():
            if stream is not None and first:
                assert member.verifiable is Verification.CHECKSUM
                first = False
        members = [m for m in reader.members_report().members if m.is_file]
    assert {m.verifiable for m in members} == {Verification.LENGTH}


@pytest.mark.parametrize("streaming", [False, True])
def test_damage_that_ends_the_walk_keeps_the_ceiling_and_fails_the_files(
    streaming: bool,
) -> None:
    # Cut inside the end-of-archive blocks: the files are whole, the gzip trailer
    # is gone. Damage does not lower verifiable (what an undamaged archive would
    # reach), so the files stay below their CHECKSUM ceiling and verify_all()
    # returns them as failures.
    data = gzip.compress(_tar("w"), mtime=0)[:-20]
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        failures = reader.verify_all()
        report = reader.members_report()
    assert sorted(m.name for m, _e in failures) == ["a", "b"]
    assert "did not run" in str(failures[0][1])
    files = [m for m in report.members if m.is_file]
    assert {(m.verified, m.verifiable) for m in files} == {
        (Verification.LENGTH, Verification.CHECKSUM)
    }


def _plain_tar(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


@pytest.mark.parametrize(
    ("tar", "cut", "cause"),
    [
        # The read ends early: no error stopped the check.
        pytest.param(_tar("w"), 20, "ends early", id="ended"),
        # The cut lands inside the deflate data: an error stopped the check.
        pytest.param(
            _plain_tar({"a": b"x" * 3000, "b": b"y"}), 30, "truncated", id="error"
        ),
    ],
)
def test_a_check_that_did_not_run_names_the_archive_once(
    tmp_path: Path, tar: bytes, cut: int, cause: str
) -> None:
    """The error for the members a spanning check did not reach, as ``verify_all()``
    returns it, names the archive once, both when the read ended early and when an
    error stopped the check."""
    path = tmp_path / "cut.tar.gz"
    path.write_bytes(gzip.compress(tar, mtime=0)[:-cut])
    with open_archive(path) as reader:
        failures = reader.verify_all()
    assert failures
    text = str(failures[0][1])
    assert "did not run" in text
    assert cause in text
    assert text.count("archive=") == 1


def test_a_check_that_did_not_run_escapes_each_name_once() -> None:
    data = gzip.compress(_plain_tar({"a\\b": b"x" * 3000, "c": b"y"}), mtime=0)[:-20]
    with open_archive(io.BytesIO(data)) as reader:
        failures = reader.verify_all()
    assert failures
    text = str(failures[0][1])
    assert "'a\\\\b'" in text
    assert "'a\\\\\\\\b'" not in text


@pytest.mark.parametrize("cut", [8, 20])
def test_damage_found_while_listing_still_fails_the_files_later(cut: int) -> None:
    # A random-access reader walks its listing once: the files whose check the
    # damage kept from running are failures of every later verify_all() too.
    data = gzip.compress(_tar("w"), mtime=0)[:-cut]
    with open_archive(io.BytesIO(data)) as reader:
        reader.members_report()
        for _ in range(2):
            failures = reader.verify_all()
            assert sorted(m.name for m, _e in failures) == ["a", "b"]


@pytest.mark.parametrize("streaming", [False, True])
def test_a_trailer_that_fails_stays_the_ceiling_of_its_failures(
    streaming: bool,
) -> None:
    data = bytearray(gzip.compress(_tar("w"), mtime=0))
    data[-8] ^= 0xFF  # the gzip trailer's CRC-32
    with open_archive(io.BytesIO(bytes(data)), streaming=streaming) as reader:
        failures = reader.verify_all()
    assert sorted(m.name for m, _e in failures) == ["a", "b"]
    assert {m.verifiable for m, _e in failures} == {Verification.CHECKSUM}


@pytest.mark.parametrize("streaming", [False, True])
def test_an_xz_check_that_fails_keeps_the_ceiling(streaming: bool) -> None:
    # liblzma reports a failed block check as corrupt data, so it reads as damage,
    # and damage keeps the CHECKSUM ceiling: every file verify_all() could not bring
    # to it is a failure.
    import lzma

    data = bytearray(lzma.compress(_tar("w"), check=lzma.CHECK_CRC64))
    data[-13] ^= 0xFF  # the last byte of the block's CRC-64, before the index
    with open_archive(io.BytesIO(bytes(data)), streaming=streaming) as reader:
        failures = reader.verify_all()
        files = [m for m in reader.members_report().members if m.is_file]
    assert {m.verifiable for m in files} == {Verification.CHECKSUM}
    failed = {id(m) for m, _e in failures}
    for member in files:
        assert id(member) in failed or member.verified is Verification.CHECKSUM
