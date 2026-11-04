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
from archivey.internal.streams.verification import SpanningCheckError
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
        # The folder CRC covers every file, so CHECKSUM is each one's ceiling from
        # the listing. One file read alone proves its length, not the folder's CRC.
        assert _levels(members["a"]) == (Verification.UNLOCKED, Verification.CHECKSUM)
        assert reader.read(members["a"]) == _A
        assert _levels(members["a"]) == (Verification.LENGTH, Verification.CHECKSUM)
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
        # end; c's read raised there, as a file's own CRC failure does. The folder
        # CRC stays their ceiling: they are failures, below it.
        assert {n: _levels(m) for n, m in members.items()} == {
            "a": (Verification.LENGTH, Verification.CHECKSUM),
            "b": (Verification.LENGTH, Verification.CHECKSUM),
            "c": (Verification.UNLOCKED, Verification.CHECKSUM),
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


@pytest.mark.parametrize("streaming", [False, True])
def test_a_folder_crc_finds_the_folders_last_file_once(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    # Each open asks which file ends the folder. A scan of the folder per open
    # makes a folder's read quadratic in its file count.
    from archivey.internal.backends.sevenzip_reader import SevenZipReader

    files = {f"f{i}": f"file {i}\n".encode() for i in range(50)}
    data = _copy_folder(files, folder_crc=_crc(b"".join(files.values())))
    scans: list[int] = []
    real = SevenZipReader._scan_folder_last_member

    def counting(self: SevenZipReader, folder_index: int) -> ArchiveMember | None:
        scans.append(folder_index)
        return real(self, folder_index)

    monkeypatch.setattr(SevenZipReader, "_scan_folder_last_member", counting)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        read = {}
        for member, stream in reader.stream_members():
            assert stream is not None
            read[member.name] = stream.read()
        assert read == files
        if not streaming:
            assert reader.verify_all() == ()
    assert scans == [0]


def test_a_lone_read_of_the_last_file_reaches_the_folder_end_and_raises() -> None:
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1)
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        assert reader.read(members["a"]) == _A
        with pytest.raises(CorruptionError, match="folder 0"):
            reader.read(members["c"])


def _folder_with_one_own_crc(own: str, own_crc_delta: int = 0) -> bytes:
    """``a, b, c`` in one stored folder whose CRC is off by one; only ``own`` has a
    CRC of its own, off by ``own_crc_delta``."""
    payload = _A + _B + _C
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(payload)],
        names=list(_THREE),
        folder_crcs=[_crc(payload) ^ 1],
        substreams=_substreams(
            [len(_A), len(_B), len(_C)],
            [
                _crc(data) ^ own_crc_delta if name == own else None
                for name, data in _THREE.items()
            ],
        ),
    )
    return _archive(payload, header)


@pytest.mark.parametrize(
    ("own", "failed"),
    [
        pytest.param("b", ["a", "c"], id="middle"),
        # The last file's read reaches the folder's end: its own CRC still runs
        # first, and the folder's error is not its failure.
        pytest.param("c", ["a", "b"], id="last"),
    ],
)
def test_a_mismatched_folder_crc_spares_a_file_with_its_own_crc(
    own: str, failed: list[str]
) -> None:
    # The file's own CRC matches, so the damage the folder CRC found is not in it.
    with open_archive(io.BytesIO(_folder_with_one_own_crc(own))) as reader:
        members = _by_name(reader.members())
        assert [m.name for m, _e in reader.verify_all()] == failed
        assert _levels(members[own]) == (Verification.CHECKSUM, Verification.CHECKSUM)
        assert [m.name for m, _e in reader.verify_all()] == failed


def test_a_last_file_whose_own_crc_fails_keeps_its_own_error() -> None:
    # c is damaged and says so itself: its read raises its own digest error, not
    # the folder's, and verify_all() still returns a and b for the folder CRC.
    data = _folder_with_one_own_crc("c", own_crc_delta=1)
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        with pytest.raises(CorruptionError, match="Digest mismatch") as caught:
            reader.read(members["c"])
        assert "folder" not in str(caught.value)
    with open_archive(io.BytesIO(data)) as reader:
        for _ in range(2):
            failures = {m.name: e for m, e in reader.verify_all()}
            assert sorted(failures) == ["a", "b", "c"]
            assert "Digest mismatch" in str(failures["c"])
            assert "folder 0" in str(failures["a"])
            assert failures["a"] is failures["b"]


def test_repeated_reads_of_a_damaged_last_file_hold_one_folder_error() -> None:
    # Each read of c fails the folder CRC unraised; the reader keeps one error for
    # the folder, not one per read, and verify_all() returns each file once.
    data = _folder_with_one_own_crc("c", own_crc_delta=1)
    with open_archive(io.BytesIO(data)) as reader:
        members = _by_name(reader.members())
        for _ in range(3):
            with pytest.raises(CorruptionError, match="Digest mismatch"):
                reader.read(members["c"])
        assert len(reader._unraised_spanning) == 1  # type: ignore[attr-defined]
        failures = reader.verify_all()
        assert sorted(m.name for m, _e in failures) == ["a", "b", "c"]
        by_name = {m.name: e for m, e in failures}
        assert isinstance(by_name["a"], SpanningCheckError)
        assert by_name["a"] is by_name["b"]
        assert "Digest mismatch" in str(by_name["c"])


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
        # Each file is at its LENGTH ceiling, but the folder CRC has not run: a pass
        # over the whole folder still raises them, and verify_all() makes it.
        assert reader.verify_all() == ()
        assert {m.verified for m in members.values()} == {Verification.CHECKSUM}
        assert reader._awaiting_spanning_checks() == set()  # type: ignore[attr-defined]


def _lzma2_folder(files: dict[str, bytes], *, folder_crc: int) -> bytes:
    """One LZMA2 folder holding ``files``, with ``folder_crc`` and no file CRCs."""
    payload = b"".join(files.values())
    packed = _lzma2(payload)
    header = _header(
        folders=[_linear([_coder(_LZMA2, props=b"\x10")])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(packed)],
        names=list(files),
        folder_crcs=[folder_crc],
        substreams=_substreams([len(data) for data in files.values()], None),
    )
    return _archive(packed, header)


@pytest.mark.parametrize(
    ("data", "failed"),
    [
        pytest.param(
            _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1),
            ["a", "b", "c"],
            id="copy",
        ),
        pytest.param(_folder_with_one_own_crc("c"), ["a", "b"], id="last-own-crc"),
    ],
)
def test_verify_all_after_seekable_reads_still_finds_a_mismatched_folder(
    data: bytes, failed: list[str]
) -> None:
    # The seekable reads never run the folder CRC, so the files it covers stay below
    # its CHECKSUM ceiling; verify_all() must run it, as it does when called first.
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        for name in "abc":
            assert reader.read(members[name]) == _THREE[name]
        assert all(
            m.verified is Verification.LENGTH and m.verifiable is Verification.CHECKSUM
            for name, m in members.items()
            if name in failed
        )
        for _ in range(2):
            failures = reader.verify_all()
            assert [m.name for m, _e in failures] == failed
            assert all(isinstance(e, SpanningCheckError) for _m, e in failures)


class _CountFolderOpens:
    """Count the folder decodes ``reader`` starts (``_open_folder_stream``)."""

    def __init__(self, reader: object, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        original = reader._open_folder_stream  # type: ignore[attr-defined]

        def counting(*args: object, **kwargs: object) -> object:
            self.count += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(reader, "_open_folder_stream", counting)


def test_a_seekable_read_of_the_last_file_checks_a_compressed_folder_crc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Seeking an LZMA2 decode to c decodes a and b anyway: the folder hashes them on
    # the way (DR-4a), so the read of c to its end runs the folder CRC, and
    # verify_all() has no folder left to read.
    data = _lzma2_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        assert reader.read(members["c"]) == _C
        assert {m.verified for m in members.values()} == {Verification.CHECKSUM}
        assert reader._awaiting_spanning_checks() == set()  # type: ignore[attr-defined]
        opens = _CountFolderOpens(reader, monkeypatch)
        assert reader.verify_all() == ()
        assert opens.count == 0


def test_a_seekable_read_of_the_last_file_raises_a_mismatched_folder_crc() -> None:
    # The same error, from the same read, as an in-order decode of the folder gives.
    data = _lzma2_folder(_THREE, folder_crc=_crc(_A + _B + _C) ^ 1)
    errors = []
    for seekable in (False, True):
        with open_archive(io.BytesIO(data), seekable_members=seekable) as reader:
            members = _by_name(reader.members())
            with pytest.raises(SpanningCheckError, match="folder 0") as caught:
                reader.read(members["c"])
            assert caught.value.member_name == "c"
            assert [m.name for m in caught.value.covers] == ["a", "b", "c"]
            errors.append(str(caught.value))
            failures = reader.verify_all()
            assert [m.name for m, _e in failures] == ["a", "b", "c"]
    assert errors[0] == errors[1]


class _ReadCounter:
    """Pass every call on to ``inner``, counting the reads."""

    def __init__(self, inner: object) -> None:
        self._wrapped = inner
        self.reads = 0

    def read(self, n: int = -1, /) -> bytes:
        self.reads += 1
        return self._wrapped.read(n)  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


def test_a_folder_seek_with_no_read_after_it_decodes_nothing() -> None:
    data = _lzma2_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        stream = reader._open_folder_stream(  # type: ignore[attr-defined]
            0, members["c"], seekable=True
        )
        counter = _ReadCounter(stream._inner)
        stream._inner = counter
        try:
            assert stream.seek(len(_A) + len(_B)) == len(_A) + len(_B)
            assert stream.seek(len(_A)) == len(_A)
            assert stream.tell() == len(_A)
            assert counter.reads == 0
            # The read that follows hashes the gap first, then serves the read.
            assert stream.read(len(_B)) == _B
            assert counter.reads >= 2
            assert stream.read() == _C
        finally:
            stream.close()
        assert {m.verified for m in members.values()} == {Verification.CHECKSUM}


def test_a_decode_error_in_a_hashed_gap_raises_from_the_read() -> None:
    # The gap a seek to c defers is decoded by c's first read: a damaged a raises
    # there, and again from the next read, as the codec's own lazy seek raises it.
    files = {"a": bytes(range(256)) * 800, "b": _B, "c": _C}
    payload = b"".join(files.values())
    packed = bytearray(_lzma2(payload))
    packed[0] = 0x02  # an LZMA2 control byte no chunk starts with
    header = _header(
        folders=[_linear([_coder(_LZMA2, props=b"\x10")])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(packed)],
        names=list(files),
        folder_crcs=[_crc(payload)],
        substreams=_substreams([len(data) for data in files.values()], None),
    )
    data = _archive(bytes(packed), header)
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        with reader.open(members["c"]) as stream:
            for _ in range(2):
                with pytest.raises(CorruptionError, match="Corrupt input data"):
                    stream.read(10)
        assert [m.name for m, _e in reader.verify_all()] == ["a", "b", "c"]


def test_a_seekable_read_of_a_stored_folder_leaves_the_crc_to_verify_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A stored folder jumps to c without reading a and b: nothing hashed them, so
    # verify_all() still reads the folder for its CRC.
    data = _copy_folder(_THREE, folder_crc=_crc(_A + _B + _C))
    with open_archive(io.BytesIO(data), seekable_members=True) as reader:
        members = _by_name(reader.members())
        assert reader.read(members["c"]) == _C
        assert members["a"].verified < Verification.CHECKSUM
        assert reader._awaiting_spanning_checks()  # type: ignore[attr-defined]
        opens = _CountFolderOpens(reader, monkeypatch)
        assert reader.verify_all() == ()
        assert opens.count > 0
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


@pytest.mark.parametrize("seekable", [False, True])
def test_damage_before_the_folder_end_drops_the_folder_crc_ceiling(
    seekable: bool,
) -> None:
    # The decode stops at the damage inside c's data, so the folder CRC never runs:
    # a and b, read whole, fall to LENGTH and verify_all() leaves none below its
    # ceiling (review of PR 1257, K1).
    data = bytearray(_lzma2_folder(_THREE, folder_crc=_crc(_A + _B + _C)))
    data[32 + 40] ^= 0xFF
    with open_archive(io.BytesIO(bytes(data)), seekable_members=seekable) as reader:
        members = _by_name(reader.members())
        assert members["a"].verifiable is Verification.CHECKSUM
        failures = reader.verify_all()
        failed = {m.name for m, _e in failures}
        assert "c" in failed
        for name, member in members.items():
            if name not in failed:
                assert member.verified == member.verifiable, name
        reader.verify_all()  # a second call agrees
        for name, member in members.items():
            if name not in failed:
                assert member.verified == member.verifiable, name
