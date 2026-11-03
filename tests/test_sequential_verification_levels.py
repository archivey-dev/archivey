"""A compressed ``.cpio`` or ``.ar``'s whole-stream checksum raises every member.

``verification-level-redesign``, task 3.3, for the formats the format adapter walks
(``SequentialReaderAdapter``): once the walk reads the archive to the codec's end and
its checksum (a gzip trailer, a bzip2 stream CRC, an xz check) matches, every file
whose data is a slice of the decoded bytes is ``CHECKSUM``, read or not. Before that a
file read to its end is ``LENGTH``. TAR has the same rule in its own reader
(``tests/test_tar_verification_levels.py``).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
from collections.abc import Callable, Iterator

import pytest

from archivey import ArchiveFormat, StreamFormat, Verification, open_archive
from archivey.formats import ForwardStream, MemberDigest, MemberSpan, SequentialReader
from archivey.internal.format_adapter import registration_scope
from archivey.types import ArchiveMember
from tests.test_ar import _ar
from tests.test_format_api_sequential import (
    _DECODED_ENTRIES,
    _HEADER,
    _MAGIC,
    _TYPES,
    ToysContainer,
    _DecodedReader,
    _pad,
    _RpmishReader,
    _variant,
    build_decoded,
    build_rpmish,
)

_CHECKED = (Verification.CHECKSUM, Verification.CHECKSUM)
_UNREAD = (Verification.UNLOCKED, Verification.LENGTH)

_COMPRESS: dict[str, Callable[[bytes], bytes]] = {
    "gz": gzip.compress,
    "bz2": bz2.compress,
    "xz": lzma.compress,
}


def _newc(files: dict[str, bytes]) -> bytes:
    """A newc cpio archive of regular files, then its trailer."""
    out = bytearray()
    for ino, (name, data) in enumerate([*files.items(), ("TRAILER!!!", b"")], 1):
        encoded = name.encode() + b"\0"
        mode = 0o100644 if data or name != "TRAILER!!!" else 0
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        out += b"070701" + b"".join(b"%08X" % f for f in fields) + encoded
        out += bytes(-len(out) % 4) + data + bytes(-len(data) % 4)
    return bytes(out + bytes(-len(out) % 512))


def _files(sizes: tuple[int, ...]) -> dict[str, bytes]:
    rng = random.Random(len(sizes))
    return {f"m{index}": rng.randbytes(size) for index, size in enumerate(sizes)}


def _archive(kind: str, files: dict[str, bytes]) -> bytes:
    if kind == "cpio":
        return _newc(files)
    return _ar(*((name.encode() + b"/", data) for name, data in files.items()))


def _listing(data: bytes, *, streaming: bool) -> list[ArchiveMember]:
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.members_report()
        assert report.error is None
        return list(report.members)


def _levels(members: list[ArchiveMember]) -> dict[str, tuple[Verification, ...]]:
    return {m.name: (m.verified, m.verifiable) for m in members}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("codec", list(_COMPRESS))
@pytest.mark.parametrize("kind", ["cpio", "ar"])
@pytest.mark.parametrize(
    "sizes",
    [
        pytest.param((5, 3), id="small"),
        # Past the walk's buffer, so the walk skips member data it never buffered.
        pytest.param((200_000, 70_000), id="past-the-walk-buffer"),
    ],
)
def test_a_listing_that_reaches_the_checksum_raises_every_file(
    sizes: tuple[int, ...], kind: str, codec: str, streaming: bool
) -> None:
    files = _files(sizes)
    data = _COMPRESS[codec](_archive(kind, files))
    members = _listing(data, streaming=streaming)
    assert _levels(members) == dict.fromkeys(files, _CHECKED)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("kind", ["cpio", "ar"])
def test_an_uncompressed_archive_has_no_checksum_to_raise_with(
    kind: str, streaming: bool
) -> None:
    files = _files((5, 3))
    members = _listing(_archive(kind, files), streaming=streaming)
    assert _levels(members) == dict.fromkeys(files, _UNREAD)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("kind", ["cpio", "ar"])
def test_a_trailer_that_does_not_match_raises_nothing(
    kind: str, streaming: bool
) -> None:
    # Large enough that detection reads only the start, not the bad trailer.
    data = bytearray(gzip.compress(_archive(kind, _files((200_000, 70_000)))))
    data[-8] ^= 0xFF  # the gzip trailer's CRC-32
    with open_archive(io.BytesIO(bytes(data)), streaming=streaming) as reader:
        report = reader.members_report()
        assert report.error is not None
        assert {m.verified for m in report.members} <= {Verification.UNLOCKED}


@pytest.mark.parametrize("kind", ["cpio", "ar"])
def test_a_file_read_in_a_pass_reaches_checksum_at_the_archive_end(
    kind: str,
) -> None:
    files = _files((5_000, 3))
    data = gzip.compress(_archive(kind, files))
    with open_archive(io.BytesIO(data), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == files[member.name]
            # The trailer is not reached yet: only the length is proved.
            assert member.verified is Verification.LENGTH
            seen.append(member)
    assert _levels(seen) == dict.fromkeys(files, _CHECKED)


# The trailer covers the bytes it decodes, not what a reader decodes from them again.
# Each reader here reads on to the end after its end header, as CPIO's does, so that
# the codec's trailer is reached.


class _DrainedRpmish(_RpmishReader):
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        # _RpmishReader.walk, reading on after the end header of the inner stream.
        while True:
            magic, code, name_len, length, crc = stream.read_struct(_HEADER)
            assert magic == _MAGIC
            if code == b"E":
                break
            raw = stream.read_exact(name_len)
            if code == b"Z":
                stream = stream.decompress(StreamFormat(raw.decode()))
                continue
            member = ArchiveMember(type=_TYPES[code], name=raw.decode(), raw_name=raw)
            digests = (MemberDigest("crc32", crc.to_bytes(4, "big")),)
            yield MemberSpan(member, length, digests if code == b"F" else ())
            stream.skip(_pad(length))
        while stream.read(_DRAIN):
            pass


class _DrainedDecoded(_DecodedReader):
    walks = 0

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        yield from super().walk(stream)
        while stream.read(_DRAIN):
            pass


_DRAIN = 64 * 1024


def _report(
    reader_type: type[SequentialReader],
    container: ToysContainer,
    data: bytes,
    *,
    streaming: bool,
) -> list[ArchiveMember]:
    with registration_scope():
        fmt = ArchiveFormat(
            _variant(reader_type, container).container, StreamFormat.GZIP
        )  # type: ignore[arg-type]
        with open_archive(
            io.BytesIO(gzip.compress(data)), format=fmt, streaming=streaming
        ) as reader:
            report = reader.members_report()
    assert report.error is None
    return list(report.members)


def test_a_layer_the_reader_decompresses_is_left_to_its_own_reads() -> None:
    members = _report(
        _DrainedRpmish, ToysContainer.RPMISH, build_rpmish(), streaming=True
    )
    files = {m.name: (m.verified, m.verifiable) for m in members if m.is_file}
    # docs/a.txt is stored before the switch; b.bin and empty sit in the inner stream,
    # whose own digests they still reach when read.
    inner = (Verification.UNLOCKED, Verification.CHECKSUM)
    assert files == {"docs/a.txt": _CHECKED, "b.bin": inner, "empty": inner}


@pytest.mark.parametrize("streaming", [False, True])
def test_data_the_reader_decodes_is_left_to_its_own_reads(streaming: bool) -> None:
    data = build_decoded(_DECODED_ENTRIES)
    members = _report(_DrainedDecoded, ToysContainer.DECODED, data, streaming=streaming)
    files = {m.name: m.verified for m in members if m.is_file}
    assert files == dict.fromkeys(files, Verification.UNLOCKED)
    assert len(files) == 4


def test_member_reads_during_a_random_access_listing_still_raise_every_file() -> None:
    # Member reads share the codec with the walk. A read back over bytes the walk
    # passed seeks the codec, but the walk then decodes on from where it was, so the
    # decode still runs from the start to the trailer (review round 1, K2).
    files = _files((300_000, 100_000, 5))
    data = gzip.compress(_archive("cpio", files), compresslevel=1)
    with open_archive(io.BytesIO(data), concurrent_operations=True) as reader:
        members = []
        for member, stream in reader.stream_members():
            assert stream is not None
            members.append(member)
            if member.name == "m1":
                assert stream.read() == files["m1"]
                with reader.open("m0") as earlier:
                    assert earlier.read(10) == files["m0"][:10]
    assert _levels(members) == dict.fromkeys(files, _CHECKED)
