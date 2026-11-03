"""7z checks that span members raise the members they cover (verification levels).

``verification-level-redesign``, tasks 2 and 3.3: a 7z folder CRC over several files
raises the files with no CRC of their own to ``CHECKSUM`` once a decode from the
folder's start reaches its end and matches; a one-file folder's CRC is its file's
digest; a CRC that matches inside an encrypted folder confirms that folder's password,
and only that folder's. Archives are hand-built with the header builder of
``test_audit_sevenzip``, because the 7z CLI writes a CRC for every file.
"""

from __future__ import annotations

import io
import random

import pytest

from archivey import Verification, open_archive
from archivey.exceptions import CorruptionError
from archivey.types import ArchiveMember
from tests.conftest import requires
from tests.test_audit_sevenzip import (
    _AES,
    _COPY,
    _LZMA2,
    _aes_encrypt,
    _archive,
    _bools,
    _coder,
    _crc,
    _header,
    _linear,
    _lzma2,
    _num,
)

_A = b"first member " * 40
_B = b"second member " * 30
_C = b"third member " * 20


def _substreams(sizes: list[int], crcs: list[int | None] | None) -> bytes:
    """``SubStreamsInfo`` for one folder: its file count, sizes and, when given, CRCs."""
    out = b"\x0d" + _num(len(sizes))
    if len(sizes) > 1:
        out += b"\x09" + b"".join(_num(size) for size in sizes[:-1])
    if crcs is not None:
        defined = [crc is not None for crc in crcs]
        out += b"\x0a" + (b"\x01" if all(defined) else b"\x00" + _bools(defined))
        out += b"".join(crc.to_bytes(4, "little") for crc in crcs if crc is not None)
    return out


def _copy_folder(
    files: dict[str, bytes], *, folder_crc: int | None, file_crcs: bool = False
) -> bytes:
    """One stored folder holding ``files``, with ``folder_crc`` and no file CRCs."""
    payload = b"".join(files.values())
    sizes = [len(data) for data in files.values()]
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(payload)],
        names=list(files),
        folder_crcs=[folder_crc],
        substreams=_substreams(
            sizes, [_crc(data) for data in files.values()] if file_crcs else None
        ),
    )
    return _archive(payload, header)


def _levels(member: ArchiveMember) -> tuple[Verification, Verification]:
    return member.verified, member.verifiable


def _by_name(members: list[ArchiveMember]) -> dict[str, ArchiveMember]:
    return {member.name: member for member in members}


_THREE = {"a": _A, "b": _B, "c": _C}


def test_a_one_file_folder_crc_is_the_file_digest() -> None:
    data = _copy_folder({"a": _A}, folder_crc=_crc(_A))
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        assert member.hashes, "the folder CRC is handed to the member"
        assert _levels(member) == (Verification.UNLOCKED, Verification.CHECKSUM)
        assert reader.read(member) == _A
        assert _levels(member) == (Verification.CHECKSUM, Verification.CHECKSUM)


def test_a_folder_crc_raises_every_file_once_the_folder_is_read() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        assert not members["a"].hashes
        # One file read alone proves its length, not the folder's CRC.
        assert reader.read(members["a"]) == _A
        assert _levels(members["a"]) == (Verification.LENGTH, Verification.LENGTH)
        assert members["c"].verified is Verification.UNLOCKED
        assert reader.verify_all() == ()
        for member in members.values():
            assert _levels(member) == (Verification.CHECKSUM, Verification.CHECKSUM)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_pass_that_reads_the_folder_to_its_end_raises_every_file(
    streaming: bool,
) -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
            seen.append(member)
            if member.name != "c":
                # The folder's end is not reached yet: no CRC has passed.
                assert member.verified is Verification.LENGTH
        for member in seen:
            assert _levels(member) == (Verification.CHECKSUM, Verification.CHECKSUM)


def test_a_pass_that_stops_before_the_folder_end_raises_nothing() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            if member.name == "c":
                stream.read(10)
            else:
                stream.read()
            seen.append(member)
        levels = {member.name: member.verified for member in seen}
    assert levels == {
        "a": Verification.LENGTH,
        "b": Verification.LENGTH,
        "c": Verification.UNLOCKED,
    }


def test_a_skipped_file_still_counts_toward_the_folder_crc() -> None:
    # The pass decodes a skipped file's bytes to reach the next one, in order, so the
    # folder CRC still covers them.
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            if member.name != "b":
                stream.read()
            seen.append(member)
        levels = {member.name: member.verified for member in seen}
    assert levels == dict.fromkeys("abc", Verification.CHECKSUM)


def test_a_folder_crc_that_does_not_match_fails_every_file_it_covers() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1)
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        failures = reader.verify_all()
        assert [m.name for m, _e in failures] == ["a", "b", "c"]
        assert all(isinstance(e, CorruptionError) for _m, e in failures)
        assert "folder 0" in str(failures[0][1])
        # Levels never fall: a and b passed their length checks before the folder's
        # end; c's read raised there, as a file's own CRC failure does.
        assert {n: _levels(m) for n, m in members.items()} == {
            "a": (Verification.LENGTH, Verification.LENGTH),
            "b": (Verification.LENGTH, Verification.LENGTH),
            "c": (Verification.UNLOCKED, Verification.LENGTH),
        }
        # A second call reads c again, which reaches the folder's end again.
        assert [m.name for m, _e in reader.verify_all()] == ["a", "b", "c"]


@pytest.mark.parametrize("streaming", [False, True])
def test_a_read_that_reaches_a_mismatched_folder_end_raises(streaming: bool) -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        read = {}
        with pytest.raises(CorruptionError, match="folder 0") as caught:
            for member, stream in reader.stream_members():
                assert stream is not None
                read[member.name] = stream.read()
        assert read == {"a": _A, "b": _B}
        assert caught.value.member_name == "c"


def test_a_lone_read_of_the_last_file_reaches_the_folder_end_and_raises() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1)
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        assert reader.read(members["a"]) == _A
        with pytest.raises(CorruptionError, match="folder 0"):
            reader.read(members["c"])


def test_a_mismatched_folder_crc_spares_a_file_with_its_own_crc() -> None:
    # b's own CRC matches, so the damage the folder CRC found is not in b.
    payload = _A + _B + _C
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(payload)],
        names=list(_THREE),
        folder_crcs=[_crc(payload) ^ 1],
        substreams=_substreams([len(_A), len(_B), len(_C)], [None, _crc(_B), None]),
    )
    with open_archive(io.BytesIO(_archive(payload, header))) as reader:
        members = _by_name(reader.members())
        assert [m.name for m, _e in reader.verify_all()] == ["a", "c"]
        assert _levels(members["b"]) == (Verification.CHECKSUM, Verification.CHECKSUM)


def test_a_folder_crc_leaves_files_with_their_own_crc_to_it() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C), file_crcs=True)
    with open_archive(io.BytesIO(data)) as reader:
        members = reader.members()
        assert reader.verify_all() == ()
        assert {m.verified for m in members} == {Verification.CHECKSUM}


def test_seekable_member_reads_never_claim_the_folder_crc() -> None:
    # Random-access opens with seekable members position by seeking: the folder is not
    # decoded in order from its start, so its CRC proves nothing.
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        for name in "abc":
            assert reader.read(members[name]) == _THREE[name]
        assert {m.verified for m in members.values()} == {Verification.LENGTH}
        # Each file is at its LENGTH ceiling, so verify_all() reads none of them...
        assert reader.verify_all() == ()
        assert {m.verified for m in members.values()} == {Verification.LENGTH}
        # ...and a pass over the whole folder still raises them.
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
        assert {m.verified for m in members.values()} == {Verification.CHECKSUM}


# Encrypted folders. pack -> AES -> LZMA2 -> output: LZMA2 rejects random input, so the
# password check stops at its 64 KiB prefix, short of a CRC past it, and accepts the
# password unconfirmed.

_BIG = random.Random(7).randbytes(100_000)
_SMALL = random.Random(8).randbytes(2_000)


def _aes_lzma2_folder(
    payload: bytes, password: str
) -> tuple[bytes, bytes, list[list[int]]]:
    """``(folder, packed, coder unpack sizes)`` for one AES + LZMA2 folder."""
    compressed = _lzma2(payload, 1 << 20)
    packed = _aes_encrypt(compressed, password)
    coders = [_coder(_AES, props=b"\x00"), _coder(_LZMA2, props=bytes([16]))]
    return _linear(coders), packed, [[len(compressed), len(payload)]]


def _two_aes_folders(
    first: dict[str, tuple[bytes, bool]],
    second: dict[str, tuple[bytes, bool]],
    password: str = "pw",
) -> bytes:
    """Two AES + LZMA2 folders, no folder CRCs; each file's flag says it has a CRC."""
    folders, packs, unpack_sizes = [], [], []
    substreams = b""
    counts, sizes, crcs = [], [], []
    for files in (first, second):
        payload = b"".join(data for data, _ in files.values())
        folder, packed, unpack = _aes_lzma2_folder(payload, password)
        folders.append(folder)
        packs.append(packed)
        unpack_sizes.extend(unpack)
        counts.append(len(files))
        sizes.extend(len(data) for data, _ in list(files.values())[:-1])
        crcs.extend(_crc(data) if has else None for data, has in files.values())
    substreams = b"\x0d" + b"".join(_num(n) for n in counts)
    substreams += b"\x09" + b"".join(_num(size) for size in sizes)
    defined = [crc is not None for crc in crcs]
    substreams += b"\x0a" + (b"\x01" if all(defined) else b"\x00" + _bools(defined))
    substreams += b"".join(crc.to_bytes(4, "little") for crc in crcs if crc is not None)
    header = _header(
        folders=folders,
        coder_unpack_sizes=unpack_sizes,
        pack_sizes=[len(p) for p in packs],
        names=[*first, *second],
        substreams=substreams,
    )
    return _archive(b"".join(packs), header)


@requires("cryptography")
def test_a_later_crc_confirms_its_folder_password_and_only_that_folder() -> None:
    data = _two_aes_folders(
        {"a1": (_BIG, False), "a2": (_SMALL, True)},
        {"b1": (_BIG, False), "b2": (_SMALL, False)},
    )
    with open_archive(io.BytesIO(data), password="pw") as reader:
        members = _by_name(reader.members())
        assert reader.read(members["a1"]) == _BIG
        # Accepted on the bounded check only: nothing proved the password yet.
        assert _levels(members["a1"]) == (Verification.NONE, Verification.NONE)
        assert reader.read(members["a2"]) == _SMALL
        assert members["a2"].verified is Verification.CHECKSUM
        # a2's CRC confirmed folder A's password: a1 can now reach LENGTH.
        assert members["a1"].verifiable is Verification.LENGTH
        assert reader.read(members["a1"]) == _BIG
        assert _levels(members["a1"]) == (Verification.LENGTH, Verification.LENGTH)

        # Folder B has no CRC at all: a full read proves nothing about its password,
        # whatever folder A proved.
        for name in ("b1", "b2"):
            assert reader.read(members[name]) == {"b1": _BIG, "b2": _SMALL}[name]
            assert _levels(members[name]) == (Verification.NONE, Verification.NONE)


@requires("cryptography")
def test_verify_all_on_an_aes_folder_with_no_crc_stays_none() -> None:
    data = _two_aes_folders(
        {"a1": (_SMALL, False)},
        {"b1": (_BIG, False), "b2": (_SMALL, False)},
    )
    with open_archive(io.BytesIO(data), password="pw") as reader:
        members = reader.members()
        assert reader.verify_all() == ()
        assert {_levels(m) for m in members} == {(Verification.NONE, Verification.NONE)}


@requires("cryptography")
def test_a_crc_in_the_same_pass_confirms_the_folder_for_a_second_verify_all() -> None:
    data = _two_aes_folders(
        {"a1": (_BIG, False), "a2": (_SMALL, True)},
        {"b1": (_SMALL, True)},
    )
    with open_archive(io.BytesIO(data), password="pw") as reader:
        members = _by_name(reader.members())
        assert reader.verify_all() == ()
        # a1 was read before a2's CRC proved the password.
        assert _levels(members["a1"]) == (Verification.NONE, Verification.LENGTH)
        assert members["a2"].verified is Verification.CHECKSUM
        # A second call reads again what is below its ceiling.
        assert reader.verify_all() == ()
        assert _levels(members["a1"]) == (Verification.LENGTH, Verification.LENGTH)


@requires("cryptography")
def test_an_unconfirmed_folder_builds_its_key_anchors_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Seekable reads never confirm the folder, so each open would otherwise walk the
    # folder's member list again: quadratic over a large folder.
    import archivey.internal.backends.sevenzip_reader as sevenzip_reader_mod

    data = _two_aes_folders(
        {"a1": (_BIG, False), "a2": (_SMALL, True)}, {"b1": (_SMALL, True)}
    )
    calls = 0
    real = sevenzip_reader_mod._member_crc

    def counting(member: ArchiveMember) -> int | None:
        nonlocal calls
        calls += 1
        return real(member)

    with open_archive(io.BytesIO(data), password="pw", seekable_members=True) as r:
        members = _by_name(r.members())
        monkeypatch.setattr(sevenzip_reader_mod, "_member_crc", counting)
        assert r.read(members["a2"]) == _SMALL
        first = calls
        assert first > 0
        assert r.read(members["a2"]) == _SMALL
        assert calls == first
