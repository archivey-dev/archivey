"""The forward walk over ZIP local headers (``zip_local_walk``), checked against stdlib.

Archives come from stdlib ``zipfile`` written to a seekable buffer (sizes in every local
header) and to a pipe-like stream it cannot seek (bit 3 and a data descriptor on every
member, STORED ones included), and are read back through a stream that cannot seek.
"""

from __future__ import annotations

import io
import random
import struct
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

import pytest

import archivey
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import zip_local_walk
from archivey.internal.backends.zip_local_walk import (
    DATA_DESCRIPTOR_SIGNATURE,
    DataDescriptor,
    ForwardTail,
    LocalEntry,
    LocalHeaderWalk,
    MemberData,
    match_damaged_descriptor,
    match_descriptor,
)
from archivey.internal.backends.zip_parser import (
    CentralDirectoryWalk,
    CentralEntry,
    EndRecord,
)
from archivey.internal.sfx import SFX_MAX
from tests.zip_descriptors import without_descriptor_signatures


class _Unseekable(io.RawIOBase):
    """A pipe: written or read forward only."""

    def __init__(self, data: bytes = b"") -> None:
        self._data = bytearray(data)
        self._pos = 0

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        n = min(len(b), len(self._data) - self._pos)
        b[:n] = self._data[self._pos : self._pos + n]
        self._pos += n
        return n

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self._data += b
        return len(b)

    def tell(self) -> int:
        # zipfile asks where it is when it writes to a stream that cannot seek.
        return len(self._data)

    def getvalue(self) -> bytes:
        return bytes(self._data)


_RANDOM = random.Random(770)
_DATA = {
    "stored.txt": (b"stored " * 50, zipfile.ZIP_STORED),
    "deflated.txt": (b"deflate me " * 500, zipfile.ZIP_DEFLATED),
    "empty.txt": (b"", zipfile.ZIP_DEFLATED),
    "big-stored.bin": (_RANDOM.randbytes(300_000), zipfile.ZIP_STORED),
    "big-deflated.bin": (
        _RANDOM.randbytes(200_000) + b"z" * 100_000,
        zipfile.ZIP_DEFLATED,
    ),
    "dir/": (b"", zipfile.ZIP_STORED),
}


def _write(*, pipe: bool, force_zip64: bool = False) -> bytes:
    out: io.BytesIO | _Unseekable = _Unseekable() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name, (data, method) in _DATA.items():
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 2, 3, 4, 6))
            info.compress_type = method
            with zf.open(info, "w", force_zip64=force_zip64) as member:
                member.write(data)
    return out.getvalue()


@dataclass
class _Read:
    name: bytes
    offset: int
    data: bytes
    descriptor: DataDescriptor | None


def _decode(
    walk: LocalHeaderWalk, entry: LocalEntry
) -> tuple[bytes, DataDescriptor | None]:
    """Read one member the way a reader would: whole, or through its codec."""
    data = walk.member_data(entry)
    method = entry.header.method
    if method == zipfile.ZIP_STORED or not entry.deferred:
        raw = data.read()
        out = raw if method == zipfile.ZIP_STORED else zlib.decompress(raw, -15)
        return out, data.settle()
    decomp = zlib.decompressobj(-15)
    out = bytearray()
    while not decomp.eof:
        chunk = data.read(65536)
        if not chunk:
            raise AssertionError("stream ended before the codec's end")
        out += decomp.decompress(chunk)
    used = data.consumed - len(decomp.unused_data)
    descriptor = data.settle(used, crc=zlib.crc32(out), file_size=len(out))
    return bytes(out), descriptor


def _directory(walk: LocalHeaderWalk) -> tuple[list[CentralEntry], EndRecord]:
    """The directory after the members, parsed as the forward reader parses it."""
    tail = walk.read_rest(None)
    end = tail.end_record()
    return list(CentralDirectoryWalk(tail.read_at, end)), end


def _walk(
    raw: bytes, *, offset: int = 0, find_start: bool = True
) -> tuple[list[_Read], LocalHeaderWalk, EndRecord]:
    walk = LocalHeaderWalk(_Unseekable(raw), offset=offset, find_start=find_start)
    read: list[_Read] = []
    while (entry := walk.next_entry()) is not None:
        data, descriptor = _decode(walk, entry)
        read.append(_Read(entry.header.name, entry.offset, data, descriptor))
    entries, end = _directory(walk)
    assert [e.name for e in entries] == [r.name for r in read]
    assert [e.header_offset for e in entries] == [r.offset for r in read]
    return read, walk, end


@pytest.mark.parametrize("pipe", [False, True], ids=["sizes", "pipe"])
@pytest.mark.parametrize("force_zip64", [False, True], ids=["classic", "zip64"])
def test_walk_reads_what_zipfile_wrote(pipe: bool, force_zip64: bool) -> None:
    raw = _write(pipe=pipe, force_zip64=force_zip64)
    read, _, end = _walk(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        assert [r.name.decode() for r in read] == zf.namelist()
        for r in read:
            assert r.data == zf.read(r.name.decode())
            info = zf.getinfo(r.name.decode())
            if pipe and not r.name.endswith(b"/"):
                # zipfile writes a data descriptor after every member it streams.
                assert r.descriptor is not None
                assert r.descriptor.crc == info.CRC
                assert r.descriptor.compressed_size == info.compress_size
                assert r.descriptor.file_size == info.file_size
    assert end is not None
    assert end.base == 0
    assert end.entries_declared == len(_DATA)


def test_pipe_written_stored_members_defer_their_sizes() -> None:
    """The case the STORED scan exists for: zipfile, writing to a pipe, sets bit 3 on
    STORED members too (measured)."""
    raw = _write(pipe=True)
    walk = LocalHeaderWalk(_Unseekable(raw))
    entry = walk.next_entry()
    assert entry is not None
    assert entry.header.name == b"stored.txt"
    assert entry.deferred
    assert entry.header.compressed_size == 0


def test_the_stored_scan_ignores_a_descriptor_signature_inside_the_data() -> None:
    payload = b"a" * 100 + DATA_DESCRIPTOR_SIGNATURE + b"\x00" * 40 + b"tail"
    out = _Unseekable()
    with zipfile.ZipFile(out, "w") as zf:
        with zf.open("x", "w") as member:
            member.write(payload)
        with zf.open("y", "w") as member:
            member.write(b"after")
    read, _, _end = _walk(out.getvalue())
    assert [r.data for r in read] == [payload, b"after"]


def test_the_stored_scan_stops_at_a_planted_descriptor_for_a_prefix() -> None:
    """The shape the central entry check exists for: the member carries, in its own
    data, a valid descriptor for a prefix of itself followed by a header signature,
    so the forward walk ends it early. The reader catches it against the directory."""
    prefix = b"prefix bytes"
    planted = (
        DATA_DESCRIPTOR_SIGNATURE
        + struct.pack("<LLL", zlib.crc32(prefix), len(prefix), len(prefix))
        + b"PK\x01\x02"
    )
    out = _Unseekable()
    with zipfile.ZipFile(out, "w") as zf, zf.open("x", "w") as member:
        member.write(prefix + planted + b"rest")
    walk = LocalHeaderWalk(_Unseekable(out.getvalue()))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    assert data.read() == prefix
    descriptor = data.settle()
    assert descriptor is not None
    assert descriptor.compressed_size == len(prefix)


def test_an_empty_archive_starts_with_the_end_record() -> None:
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()
    read, _, end = _walk(buf.getvalue())
    assert read == []
    assert end is not None
    assert end.entries_declared == 0
    assert end.trailing == 0


def test_a_stub_before_the_archive_is_found_and_becomes_the_base() -> None:
    raw = _write(pipe=False)
    stub = b"MZ" + b"\x90" * 5000 + b"PK\x03\x04 decoy" + b"\x00" * 100
    read, walk, end = _walk(stub + raw)
    assert walk.first_offset == len(stub)
    assert end is not None
    # zipfile wrote offsets from its own start: the stub is the base.
    assert end.base == len(stub)
    assert len(read) == len(_DATA)


def test_rejected_stub_candidates_are_not_capped() -> None:
    # Detection and the seekable read cap no ZIP decoys; neither does the walk.
    raw = _write(pipe=False)
    stub = b"MZ" + (b"PK\x03\x04" + b"\x00" * 26) * 300
    read, walk, _end = _walk(stub + raw)
    assert walk.first_offset == len(stub)
    assert len(read) == len(_DATA)


def test_a_stream_that_starts_at_the_directory_lists_it() -> None:
    raw = _write(pipe=False)
    eocd = raw.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<L", raw, eocd + 16)
    walk = LocalHeaderWalk(_Unseekable(raw[cd_offset:]))
    assert walk.next_entry() is None
    assert [e.name for e in _directory(walk)[0]] == [n.encode() for n in _DATA]


def test_strong_encryption_at_the_start_is_named() -> None:
    walk = LocalHeaderWalk(_Unseekable(b"PK\x06\x08" + b"\x00" * 100))
    assert walk.next_entry() is None
    with pytest.raises(UnsupportedFeatureError, match="Strong Encryption"):
        walk.read_rest(None).end_record()


@pytest.mark.parametrize("before_limit", [4, 20, 100])
def test_a_long_header_across_the_scan_window_end_is_found(before_limit: int) -> None:
    # The candidate starts inside the window; its 65 535-byte name runs past it.
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("n" * 0xFFFF, b"data")
    stub = b"\x00" * (SFX_MAX - before_limit)
    read, walk, _end = _walk(stub + out.getvalue())
    assert walk.first_offset == len(stub)
    assert [r.data for r in read] == [b"data"]


def test_messages_before_any_member_name_no_member() -> None:
    walk = LocalHeaderWalk(_Unseekable(b"PK"), find_start=False)
    with pytest.raises(TruncatedError, match="before the first local header"):
        walk.next_entry()
    walk = LocalHeaderWalk(_Unseekable(b"junk" * 100), find_start=False)
    assert walk.next_entry() is None
    with pytest.raises(CorruptionError, match="before the first local header"):
        walk.read_rest(None).end_record()


def test_no_local_header_in_the_scan_window_is_corruption() -> None:
    walk = LocalHeaderWalk(_Unseekable(b"\x00" * 1000))
    with pytest.raises(CorruptionError, match="no ZIP local header"):
        walk.next_entry()


def test_a_stub_before_an_archive_with_no_local_header_is_kept_whole() -> None:
    """No local header in the window, but an end record: the stub and the archive
    go to ``read_rest``, so the end record is found behind the stub as a file read
    finds it."""
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()
    stub = b"MZ" + b"\x00" * 5000
    walk = LocalHeaderWalk(_Unseekable(stub + buf.getvalue()))
    assert walk.next_entry() is None
    end = walk.read_rest(None).end_record()
    assert end.entries_declared == 0


def test_an_end_record_signature_in_a_stub_past_the_window_is_no_archive() -> None:
    """Only an end record where an archive ending the stream would put it counts: a
    signature inside a stub that runs past the scan window leaves the error."""
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()
    stub = b"MZ" + b"\x00" * 100 + b"PK\x05\x06" + b"\x00" * SFX_MAX
    walk = LocalHeaderWalk(_Unseekable(stub + buf.getvalue()))
    with pytest.raises(CorruptionError, match="no ZIP local header"):
        walk.next_entry()


def test_a_tail_hands_back_its_bytes_from_an_offset_only_when_it_holds_them() -> None:
    whole = ForwardTail(
        after="after member #0", members_start=0, members_end=10, start=10,
        data=b"abcdef",
    )  # fmt: skip
    assert _read_all(whole.held_from(12)) == b"cdef"
    assert whole.held_from(9) is None
    # The head and the last bytes overlap: one run to the end of the stream.
    joined = ForwardTail(
        after="", members_start=0, members_end=10, start=13, data=b"defgh",
        head=b"abcde",
    )  # fmt: skip
    assert _read_all(joined.held_from(11)) == b"bcdefgh"
    # Bytes dropped between them: only the last ones run to the end.
    cut = ForwardTail(
        after="", members_start=0, members_end=10, start=20, data=b"xyz", head=b"abc"
    )
    assert cut.held_from(11) is None
    assert _read_all(cut.held_from(21)) == b"yz"


def _read_all(stream: BinaryIO | None) -> bytes:
    assert stream is not None
    out = b""
    while chunk := stream.read(2):
        out += chunk
    return out


def test_bytes_before_the_directory_are_kept_with_it() -> None:
    """An APK signing block sits between the last member and the directory, and the
    end record's directory offset counts it."""
    raw = bytearray(_write(pipe=False))
    eocd = raw.rindex(b"PK\x05\x06")
    _cd_size, cd_offset = struct.unpack_from("<LL", raw, eocd + 12)
    block = b"APK Sig Block 42 " * 10
    raw[cd_offset:cd_offset] = block
    struct.pack_into("<L", raw, eocd + len(block) + 16, cd_offset + len(block))
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    tail = walk.read_rest(None)
    assert tail.members_end == cd_offset
    assert tail.data.startswith(block)
    end = tail.end_record()
    assert (end.base, end.cd_start) == (0, cd_offset + len(block))


def _with_gap(raw: bytes, block: bytes) -> bytes:
    """``raw`` with ``block`` before its directory, the end record adjusted."""
    out = bytearray(raw)
    eocd = out.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<L", out, eocd + 16)
    out[cd_offset:cd_offset] = block
    struct.pack_into("<L", out, eocd + len(block) + 16, cd_offset + len(block))
    return bytes(out)


def test_a_gap_after_a_deferred_last_member_is_not_read_past() -> None:
    # A descriptor must be followed by a ZIP signature: that is what stops a planted
    # descriptor inside STORED data. So bytes after the last member's descriptor make
    # the scan take the real descriptor for data. Gaps are read past only after a
    # member whose header states its size.
    walk = LocalHeaderWalk(_Unseekable(_with_gap(_write(pipe=True), b"APK " * 10)))
    with pytest.raises(UnsupportedFeatureError, match="none matches its data"):
        while (entry := walk.next_entry()) is not None:
            _decode(walk, entry)


def test_a_gap_holding_a_directory_signature_is_read_past_by_the_end_record() -> None:
    # The end record says where the directory starts, as for a file read.
    walk = LocalHeaderWalk(
        _Unseekable(_with_gap(_write(pipe=False), b"APK PK\x01\x02 block " * 4))
    )
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    assert [e.name for e in _directory(walk)[0]] == [n.encode() for n in _DATA]


@pytest.mark.parametrize("pipe", [False, True], ids=["sizes", "pipe"])
def test_a_stream_cut_before_the_directory_is_truncation(pipe: bool) -> None:
    raw = _write(pipe=pipe)
    cut = raw[: raw.index(b"PK\x01\x02")]
    walk = LocalHeaderWalk(_Unseekable(cut))
    names = []
    with pytest.raises(TruncatedError, match="before the central directory"):
        while (entry := walk.next_entry()) is not None:
            _decode(walk, entry)
            names.append(entry.header.name)
    assert len(names) == len(_DATA)


def test_a_stream_cut_inside_sized_data_is_truncation() -> None:
    raw = _write(pipe=False)
    walk = LocalHeaderWalk(_Unseekable(raw[: raw.index(b"stored ") + 10]))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    with pytest.raises(TruncatedError, match="inside member #0"):
        data.read()


def test_a_stream_cut_inside_scanned_stored_data_is_truncation() -> None:
    raw = _write(pipe=True)
    walk = LocalHeaderWalk(_Unseekable(raw[: raw.index(b"stored ") + 10]))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    with pytest.raises(TruncatedError, match="before its data descriptor"):
        data.read()


def test_descriptors_without_their_signature_are_found_by_what_follows() -> None:
    """Early PKZIP wrote descriptors without ``PK\\x07\\x08`` (APPNOTE 4.3.9.3): the
    scan finds one by the ZIP signature after it and the size and CRC it states."""
    piped = _write(pipe=True)
    raw = without_descriptor_signatures(piped)
    assert DATA_DESCRIPTOR_SIGNATURE not in raw
    read, _, _end = _walk(raw)
    with zipfile.ZipFile(io.BytesIO(piped)) as zf:
        assert [r.data for r in read] == [zf.read(i) for i in zf.infolist()]
    stored = next(r for r in read if r.name == b"big-stored.bin")
    assert stored.descriptor is not None
    assert stored.descriptor.length == 12


def test_an_unsigned_descriptor_with_one_damaged_field_is_found() -> None:
    """Its CRC and uncompressed size still place it: the member ends there, and the
    damaged compressed size is returned as stored, for the directory to contradict."""
    raw = bytearray(without_descriptor_signatures(_write(pipe=True)))
    first = raw.index(b"stored " * 50) + len(b"stored " * 50)
    raw[first + 4] ^= 0xFF  # the compressed size's low byte
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    assert data.read() == b"stored " * 50
    descriptor = data.settle()
    assert descriptor is not None
    assert descriptor.file_size == len(b"stored " * 50)
    assert descriptor.compressed_size == len(b"stored " * 50) ^ 0xFF
    assert walk.next_entry() is not None


def test_an_unsigned_descriptor_that_matches_nothing_is_unsupported() -> None:
    """A descriptor with two fields that do not match the data cannot be told from
    data: the scan reads to the end record and gives up."""
    raw = bytearray(without_descriptor_signatures(_write(pipe=True)))
    first = raw.index(b"stored " * 50) + len(b"stored " * 50)
    raw[first + 4] ^= 0xFF  # the compressed size's low byte
    raw[first + 8] ^= 0xFF  # the uncompressed size's low byte
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    entry = walk.next_entry()
    assert entry is not None
    with pytest.raises(UnsupportedFeatureError, match="none matches its data"):
        walk.member_data(entry).read()


def test_junk_after_a_member_with_no_directory_is_corruption() -> None:
    raw = _write(pipe=False)
    first_end = raw.index(b"PK\x03\x04", 1)
    walk = LocalHeaderWalk(_Unseekable(raw[:first_end] + b"junk" * 10))
    entry = walk.next_entry()
    assert entry is not None
    _decode(walk, entry)
    assert walk.next_entry() is None
    with pytest.raises(CorruptionError, match="not a ZIP header"):
        walk.read_rest(None).end_record()


def test_a_stream_cut_inside_the_directory_is_truncation() -> None:
    raw = _write(pipe=False)
    walk = LocalHeaderWalk(_Unseekable(raw[: raw.index(b"PK\x01\x02") + 60]))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    with pytest.raises(TruncatedError, match="inside the central directory"):
        walk.read_rest(None).end_record()


def test_the_bound_keeps_the_last_bytes() -> None:
    raw = _write(pipe=False)
    cd = raw.index(b"PK\x01\x02")
    stream = raw[:cd] + b"\x01" * 300_000 + raw[cd:]
    walk = LocalHeaderWalk(_Unseekable(stream))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    keep = len(raw) - cd - 10  # the end record, not the directory's first bytes
    tail = walk.read_rest(keep)
    assert tail.data == stream[-keep:]
    assert tail.dropped == len(stream) - cd - keep
    with pytest.raises(ResourceLimitError, match="listing limits"):
        tail.end_record()


@pytest.mark.parametrize("keep", [0, 1])
def test_a_bound_under_one_chunk_keeps_that_many_bytes(keep: int) -> None:
    raw = _write(pipe=False)
    walk = LocalHeaderWalk(_Unseekable(raw))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    tail = walk.read_rest(keep)
    assert tail.data == raw[len(raw) - keep :]
    assert tail.start == len(raw) - keep
    # The first four bytes after the members are held whatever the bound.
    end = tail.members_end
    assert tail.read_at(end, 4) == raw[end : end + 4] == b"PK\x01\x02"


def test_a_directory_among_the_members_data_is_refused() -> None:
    # A declared size past the directory's start puts it back in the members' data.
    raw = bytearray(_write(pipe=False))
    eocd = raw.rindex(b"PK\x05\x06")
    (cd_size,) = struct.unpack_from("<L", raw, eocd + 12)
    struct.pack_into("<L", raw, eocd + 12, cd_size + 100)
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    with pytest.raises(CorruptionError, match="inside the members' data"):
        walk.read_rest(None).end_record()


def test_settle_skips_data_the_caller_did_not_read() -> None:
    raw = _write(pipe=False)
    walk = LocalHeaderWalk(_Unseekable(raw))
    names = []
    while (entry := walk.next_entry()) is not None:
        names.append(entry.header.name.decode())
        walk.member_data(entry).settle()
    assert names == list(_DATA)
    assert len(_directory(walk)[0]) == len(_DATA)


def test_a_codec_member_needs_the_bytes_its_codec_used() -> None:
    walk = LocalHeaderWalk(_Unseekable(_write(pipe=True)))
    stored = walk.next_entry()
    assert stored is not None
    with pytest.raises(ValueError, match="settle the previous"):
        walk.next_entry()
    walk.member_data(stored).settle()
    entry = walk.next_entry()
    assert entry is not None
    assert entry.header.name == b"deflated.txt"
    data = walk.member_data(entry)
    with pytest.raises(ValueError, match="needs `used`"):
        data.settle()


def test_a_given_offset_places_entries_and_the_base() -> None:
    # The caller skipped a 5000-byte stub itself and says where the stream starts.
    raw = _write(pipe=True)
    read, walk, end = _walk(raw, offset=5000, find_start=False)
    assert walk.first_offset == read[0].offset == 5000
    assert end is not None
    assert end.base == 5000
    assert end.cd_start == 5000 + raw.index(b"PK\x01\x02")


def _deflated_member(walk: LocalHeaderWalk) -> MemberData:
    stored = walk.next_entry()
    assert stored is not None
    walk.member_data(stored).settle()
    entry = walk.next_entry()
    assert entry is not None
    assert entry.header.name == b"deflated.txt"
    return walk.member_data(entry)


def test_settle_refuses_more_used_than_was_read() -> None:
    data = _deflated_member(LocalHeaderWalk(_Unseekable(_write(pipe=True))))
    data.read(10)
    with pytest.raises(ValueError, match="after only 10 bytes"):
        data.settle(100)


def test_settle_refuses_an_overread_past_what_was_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(zip_local_walk, "_CODEC_RETAIN", 64)
    data = _deflated_member(LocalHeaderWalk(_Unseekable(_write(pipe=True))))
    decomp = zlib.decompressobj(-15)
    while not decomp.eof:
        decomp.decompress(data.read(16))
    used = data.consumed - len(decomp.unused_data)
    data.read(200)  # well past the codec's end, beyond the 64 kept
    with pytest.raises(ValueError, match="more than the .* kept to put back"):
        data.settle(used)


@pytest.mark.parametrize(
    "read_all",
    [
        lambda d: d.read(),
        lambda d: d.readall(),
        lambda d: io.BufferedReader(d).read(),
    ],
    ids=["read", "readall", "buffered"],
)
def test_a_codec_member_refuses_an_unsized_read(read_all: Callable) -> None:
    data = _deflated_member(LocalHeaderWalk(_Unseekable(_write(pipe=True))))
    with pytest.raises(ValueError, match="no known end"):
        read_all(data)
    assert data.consumed == 0


def test_settle_checks_used_where_the_walk_knows_the_end() -> None:
    walk = LocalHeaderWalk(_Unseekable(_write(pipe=False)))
    entry = walk.next_entry()
    assert entry is not None
    with pytest.raises(ValueError, match="whose data is"):
        walk.member_data(entry).settle(entry.header.compressed_size + 1)
    # A codec may stop short of the stated size: padding after its end is fine.
    walk = LocalHeaderWalk(_Unseekable(_write(pipe=False)))
    entry = walk.next_entry()
    assert entry is not None
    assert walk.member_data(entry).settle(entry.header.compressed_size - 1) is None
    walk = LocalHeaderWalk(_Unseekable(_write(pipe=True)))
    entry = walk.next_entry()
    assert entry is not None and entry.deferred
    data = walk.member_data(entry)
    stored = data.read()
    assert data.settle(len(stored)) is not None


@pytest.mark.parametrize(
    ("descriptor", "zip64"),
    [
        (DATA_DESCRIPTOR_SIGNATURE + struct.pack("<LLL", 7, 10, 20), False),
        (struct.pack("<LLL", 7, 10, 20), False),
        (DATA_DESCRIPTOR_SIGNATURE + struct.pack("<LQQ", 7, 10, 20), True),
        # Java's ZipOutputStream: 8-byte sizes for a big member, no ZIP64 extra.
        (DATA_DESCRIPTOR_SIGNATURE + struct.pack("<LQQ", 7, 10, 20), False),
    ],
    ids=["signed", "unsigned", "zip64", "zip64-without-extra"],
)
def test_match_descriptor_shapes(descriptor: bytes, zip64: bool) -> None:
    buffer = descriptor + b"PK\x03\x04"
    found = match_descriptor(
        buffer, 0, compressed_size=10, crc=7, file_size=20, zip64=zip64, at_end=False
    )
    assert found is not None
    assert (found.crc, found.compressed_size, found.file_size) == (7, 10, 20)
    assert found.length == len(descriptor)


def test_a_4_byte_descriptor_past_4_gib_gives_back_both_full_sizes() -> None:
    # A member past 4 GiB whose descriptor has 4-byte sizes matches modulo 2**32;
    # neither size may come back truncated.
    csize, usize = 2**32 + 10, 2**32 + 20
    buffer = (
        DATA_DESCRIPTOR_SIGNATURE
        + struct.pack("<LLL", 7, csize & 0xFFFFFFFF, usize & 0xFFFFFFFF)
        + b"PK\x03\x04"
    )
    found = match_descriptor(
        buffer,
        0,
        compressed_size=csize,
        crc=7,
        file_size=usize,
        zip64=False,
        at_end=False,
    )
    assert found is not None
    assert (found.compressed_size, found.file_size) == (csize, usize)


def test_match_descriptor_needs_a_signature_after_it() -> None:
    buffer = DATA_DESCRIPTOR_SIGNATURE + struct.pack("<LLL", 7, 10, 20) + b"junk"
    assert (
        match_descriptor(
            buffer,
            0,
            compressed_size=10,
            crc=7,
            file_size=20,
            zip64=False,
            at_end=False,
        )
        is None
    )
    at_end = buffer[:-4]
    assert (
        match_descriptor(
            at_end, 0, compressed_size=10, crc=7, file_size=20, zip64=False, at_end=True
        )
        is not None
    )


_SIG = DATA_DESCRIPTOR_SIGNATURE


@pytest.mark.parametrize(
    ("descriptor", "taken"),
    [
        # Without a signature: two of the CRC (7) and sizes (10, 20) must agree.
        (struct.pack("<LLL", 8, 10, 20), True),
        (struct.pack("<LLL", 7, 11, 20), True),
        (struct.pack("<LLL", 7, 10, 21), True),
        (struct.pack("<LLL", 8, 11, 20), False),
        (struct.pack("<LLL", 8, 10, 21), False),
        # With one: the compressed size alone, or two fields.
        (_SIG + struct.pack("<LLL", 8, 10, 21), True),
        (_SIG + struct.pack("<LLL", 7, 11, 20), True),
        (_SIG + struct.pack("<LLL", 8, 11, 20), False),
        # With a damaged one: all three fields.
        (b"PK\x07\x09" + struct.pack("<LLL", 7, 10, 20), True),
        (b"PK\x07\x09" + struct.pack("<LLL", 8, 10, 20), False),
    ],
)
def test_match_damaged_descriptor_takes_one_damaged_field(
    descriptor: bytes, taken: bool
) -> None:
    buffer = descriptor + b"PK\x03\x04"
    found = match_damaged_descriptor(
        buffer, 0, compressed_size=10, crc=7, file_size=20, zip64=False, at_end=False
    )
    assert (found is not None) == taken
    if found is not None:
        # The fields as stored, so the caller and the directory can judge them.
        stored = struct.unpack("<LLL", descriptor[-12:])
        assert (found.crc, found.compressed_size, found.file_size) == stored
        assert found.length == len(descriptor)


@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
def test_match_damaged_descriptor_reads_8_byte_sizes(signed: bool) -> None:
    """A ZIP64 shape: 8-byte sizes, the uncompressed one damaged."""
    csize, usize = 2**32 + 10, 2**32 + 20
    descriptor = (_SIG if signed else b"") + struct.pack("<LQQ", 7, csize, usize + 1)
    found = match_damaged_descriptor(
        descriptor + b"PK\x03\x04",
        0,
        compressed_size=csize,
        crc=7,
        file_size=usize,
        zip64=True,
        at_end=False,
    )
    assert found is not None
    assert (found.crc, found.compressed_size, found.file_size) == (7, csize, usize + 1)
    assert found.length == len(descriptor)


def test_match_damaged_descriptor_gives_back_full_sizes_past_4_gib() -> None:
    """A 4-byte shape past 4 GiB: the size that agrees modulo 2**32 comes back whole,
    the damaged one as stored."""
    csize, usize = 2**32 + 10, 2**32 + 20
    descriptor = struct.pack("<LLL", 8, csize & 0xFFFFFFFF, usize & 0xFFFFFFFF)
    found = match_damaged_descriptor(
        descriptor + b"PK\x03\x04",
        0,
        compressed_size=csize,
        crc=7,
        file_size=usize,
        zip64=False,
        at_end=False,
    )
    assert found is not None
    assert (found.crc, found.compressed_size, found.file_size) == (8, csize, usize)
    damaged = struct.pack("<LLL", 7, csize & 0xFFFFFFFF, (usize + 1) & 0xFFFFFFFF)
    found = match_damaged_descriptor(
        damaged + b"PK\x03\x04",
        0,
        compressed_size=csize,
        crc=7,
        file_size=usize,
        zip64=False,
        at_end=False,
    )
    assert found is not None
    assert (found.compressed_size, found.file_size) == (csize, (usize + 1) & 0xFFFFFFFF)


def test_match_damaged_descriptor_needs_a_signature_after_it() -> None:
    buffer = struct.pack("<LLL", 8, 10, 20) + b"junk"
    assert (
        match_damaged_descriptor(
            buffer,
            0,
            compressed_size=10,
            crc=7,
            file_size=20,
            zip64=False,
            at_end=False,
        )
        is None
    )


def test_zip64_end_records_are_read_from_the_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as m:
        m.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
        raw = _write(pipe=True)
    assert b"PK\x06\x06" in raw
    _read, _, end = _walk(raw)
    assert end is not None
    assert end.zip64
    assert end.entries_declared == len(_DATA)


def test_an_encrypted_directory_is_unsupported() -> None:
    raw = bytearray(_write(pipe=False))
    raw[raw.index(b"PK\x01\x02") : raw.index(b"PK\x01\x02") + 4] = b"PK\x06\x08"
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    while (entry := walk.next_entry()) is not None:
        walk.member_data(entry).settle()
    with pytest.raises(UnsupportedFeatureError, match="Strong Encryption"):
        walk.read_rest(None).end_record()


def test_an_encrypted_stored_scan_matches_size_and_signature_only() -> None:
    """Under encryption the descriptor's CRC covers the plaintext, which the scan never
    sees: the size and the signature after the descriptor are what it matches."""
    raw = bytearray(_write(pipe=True))
    first = raw.index(DATA_DESCRIPTOR_SIGNATURE)
    struct.pack_into("<L", raw, first + 4, 0xDEADBEEF)  # a CRC the bytes do not have
    walk = LocalHeaderWalk(_Unseekable(bytes(raw)))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry, encrypted=True)
    assert data.read() == _DATA["stored.txt"][0]
    descriptor = data.settle()
    assert descriptor is not None
    assert descriptor.crc == 0xDEADBEEF
    second = walk.next_entry()
    assert second is not None
    assert second.header.name == b"deflated.txt"


def _planted_signed(size: int) -> bytes:
    """12-byte blocks: a descriptor signature, a wrong CRC, the block's own offset
    as its compressed size. No ZIP header follows any, so none is a candidate: what
    the scan planted before it looked for the header after a descriptor."""
    return b"".join(
        DATA_DESCRIPTOR_SIGNATURE + b"\x00" * 4 + struct.pack("<L", offset)
        for offset in range(0, size, 12)
    )


def _planted_followed(size: int) -> bytes:
    """16-byte blocks: an unsigned descriptor (a wrong CRC, the block's own offset as
    its compressed size) and a local header signature after it, so every block is a
    candidate whose size fits and reaches the CRC. The prefix keeps block 0 from
    being a valid descriptor for empty data."""
    prefix = b"pfx!"
    return prefix + b"".join(
        struct.pack("<LLL", 0, offset, 0) + b"PK\x03\x04"
        for offset in range(len(prefix), size, 16)
    )


@pytest.mark.parametrize("piece", [65536, 16])
@pytest.mark.parametrize(
    "plant", [_planted_signed, _planted_followed], ids=["signed", "followed"]
)
def test_planted_descriptor_signatures_cost_one_pass(
    monkeypatch: pytest.MonkeyPatch,
    piece: int,
    plant: Callable[[int], bytes],
) -> None:
    """A STORED member full of planted descriptors is scanned in linear time.

    With ``_planted_followed`` every candidate passes the size test and reaches the
    CRC. Fails if the CRC is recomputed from the start of the buffer for each
    candidate (quadratic bytes into ``zlib.crc32``). The 16-byte reads also fail if
    a read re-runs the CRC over bytes an earlier read already judged.
    """
    payload = plant(1_200_000)
    out = _Unseekable()
    with zipfile.ZipFile(out, "w") as zf, zf.open("x", "w") as member:
        member.write(payload)
    fed = 0

    class _CountingZlib:
        @staticmethod
        def crc32(data: bytes, value: int = 0) -> int:
            nonlocal fed
            fed += len(data)
            return zlib.crc32(data, value)

    monkeypatch.setattr(zip_local_walk, "zlib", _CountingZlib)
    walk = LocalHeaderWalk(_Unseekable(out.getvalue()))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    got = bytearray()
    while chunk := data.read(piece):
        got += chunk
    assert bytes(got) == payload
    assert data.settle() is not None
    # Once over the bytes handed out, and while scanning once over each candidate's
    # bytes past the earliest start a shape can have: up to the 12 bytes from there
    # to its own start, per candidate.
    assert fed <= 3 * len(payload)


def _member_named(walk: LocalHeaderWalk, name: bytes) -> MemberData:
    """The data of the member called ``name``, the ones before it read and settled."""
    while (entry := walk.next_entry()) is not None:
        if entry.header.name == name:
            return walk.member_data(entry)
        _decode(walk, entry)
    raise AssertionError(f"no member {name!r}")


def test_a_scan_counts_the_bytes_read_before_the_ones_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed read took more than the walk keeps: the scan starts at the kept bytes,
    and the dropped ones count into the compressed size it matches."""
    monkeypatch.setattr(zip_local_walk, "_CODEC_RETAIN", 64)
    raw = _write(pipe=True)
    stored_size = zipfile.ZipFile(io.BytesIO(raw)).getinfo("big-deflated.bin")
    walk = LocalHeaderWalk(_Unseekable(raw))
    data = _member_named(walk, b"big-deflated.bin")
    while data.consumed < 100_000:
        data.read(16)
    descriptor = walk.scan_member_data(data).settle()
    assert descriptor is not None
    assert descriptor.compressed_size == stored_size.compress_size
    after = walk.next_entry()
    assert after is not None
    assert after.header.name == b"dir/"


def test_a_scan_that_starts_past_the_descriptor_finds_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The codec's reads ran past its data's end by more than the walk keeps, so
    the descriptor is behind where the scan starts."""
    monkeypatch.setattr(zip_local_walk, "_CODEC_RETAIN", 64)
    walk = LocalHeaderWalk(_Unseekable(_write(pipe=True)))
    data = _member_named(walk, b"big-deflated.bin")
    decomp = zlib.decompressobj(-15)
    while not decomp.eof:
        decomp.decompress(data.read(16))
    data.read(200)  # past the descriptor and into the next member
    scanned = walk.scan_member_data(data)
    with pytest.raises(UnsupportedFeatureError, match="none matches its data"):
        scanned.settle()


def _rest(raw: bytes, keep: int) -> zip_local_walk.ForwardTail:
    walk = LocalHeaderWalk(_Unseekable(raw))
    while (entry := walk.next_entry()) is not None:
        _decode(walk, entry)
    return walk.read_rest(keep)


def test_past_the_bound_the_head_is_kept_only_for_a_directory_after_the_members() -> (
    None
):
    raw = _write(pipe=True)
    keep = 3 * 65_558
    junk = b"\x01" * (3 * keep)
    # A directory right after the members: its first ``keep`` bytes stay.
    tail = _rest(raw + junk, keep)
    assert tail.dropped and len(tail.head) == keep
    assert len(tail.data) == keep
    assert tail.end_record().trailing == len(junk)
    # Other bytes there: only their first four, for the message. Sized members,
    # whose end needs no signature after it.
    sized = _write(pipe=False)
    tail = _rest(sized[: sized.index(b"PK\x01\x02")] + junk, keep)
    assert tail.head == b"\x01" * 4
    with pytest.raises(CorruptionError, match="are not a ZIP header"):
        tail.end_record()


def _zip64_local_header(
    extra_sizes: bytes,
    *,
    compressed_size: int = 0xFFFF_FFFF,
    file_size: int = 0xFFFF_FFFF,
) -> bytes:
    """A STORED local header with the given 32-bit sizes (all ones by default) and a
    ZIP64 extra field holding ``extra_sizes``; no data follows."""
    name = b"big.bin"
    extra = (
        struct.pack("<HH", 0x0001, len(extra_sizes)) + extra_sizes
        if extra_sizes
        else b""
    )
    fixed = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        45,
        0,
        0,
        0,
        0,
        0,
        compressed_size,
        file_size,
        len(name),
        len(extra),
    )
    return fixed + name + extra


@pytest.mark.parametrize("size", [0xFFFF_FFFE, 0xFFFF_FFFF, 0x1_0000_0000])
def test_a_zip64_extra_size_of_all_ones_is_a_real_size(size: int) -> None:
    # zipfile writes exactly this header for a STORED member of 4294967295 bytes: the
    # extra field holds all ones as the size, which is not a deferral.
    raw = _zip64_local_header(struct.pack("<QQ", size, size))
    entry = LocalHeaderWalk(_Unseekable(raw)).next_entry()
    assert entry is not None
    assert entry.header.compressed_size == size
    assert entry.header.file_size == size


@pytest.mark.parametrize(
    ("extra_sizes", "sizes", "which"),
    [
        (b"", {}, "compressed"),
        (struct.pack("<Q", 5), {}, "compressed"),
        (b"", {"compressed_size": 5}, "uncompressed"),
        (b"", {"file_size": 5}, "compressed"),
    ],
    ids=["no-extra", "file-size-only", "uncompressed-alone", "compressed-alone"],
)
def test_a_size_no_zip64_extra_holds_is_corruption(
    extra_sizes: bytes, sizes: dict[str, int], which: str
) -> None:
    raw = _zip64_local_header(extra_sizes, **sizes)
    with pytest.raises(
        CorruptionError, match=f"defers its {which} size .* does not hold"
    ):
        LocalHeaderWalk(_Unseekable(raw)).next_entry()


def test_an_unheld_local_size_reads_by_file() -> None:
    """A file read takes the sizes from the directory and reads such a member; the
    pass has only the local header (``formats/zip.md`` §2.2.2)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"hello " * 10)
    raw = bytearray(buf.getvalue())
    struct.pack_into("<I", raw, 22, 0xFFFF_FFFF)  # the local uncompressed size
    data = bytes(raw)
    with archivey.open_archive(io.BytesIO(data)) as reader:
        assert reader.read("a.txt") == b"hello " * 10
    with (
        pytest.raises(CorruptionError, match="uncompressed size"),
        archivey.open_archive(_Unseekable(data), streaming=True) as reader,
    ):
        for _ in reader.stream_members():
            pass
