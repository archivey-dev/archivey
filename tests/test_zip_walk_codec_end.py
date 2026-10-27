"""Bit-3 ZIP members whose end only their codec finds, read from a stream that cannot seek.

Each archive is built by hand the way a streaming writer lays it out: bit 3 set, zero
sizes in the local header, the data, then a data descriptor (with or without its
signature). The walk hands the data to the codec stream the reader uses
(``refuse_input_after_end``), which stops at the codec's end; ``settle`` then finds the
descriptor by the decoded data's CRC.
"""

from __future__ import annotations

import bz2
import io
import lzma
import random
import struct
import zlib
from dataclasses import dataclass

import pytest

from archivey.config import ProcessIsolation
from archivey.exceptions import CorruptionError, ResourceLimitError, TruncatedError
from archivey.internal.backends.zip_local_walk import (
    _CODEC_RETAIN,
    DataDescriptor,
    LocalHeaderWalk,
    MemberData,
)
from archivey.internal.backends.zip_parser import CentralDirectoryWalk
from archivey.internal.config import DecoderLimits, StreamConfig
from archivey.internal.streams.codecs import ppmd_decoder
from archivey.internal.streams.codecs.base import CodecParams
from archivey.internal.streams.codecs.registry import open_codec_stream
from archivey.internal.streams.decompressor_stream import DataAfterEndError
from tests.conftest import requires, requires_zstd, zstd_backend

_RANDOM = random.Random(3)
# Past one 64 KiB feed and incompressible in part, so the codec's end falls well
# inside a later chunk the stream read.
_BIG = _RANDOM.randbytes(150_000) + b"hello world " * 20_000
_SMALL = b"small text\n" * 30

_PPMD_ORDER = 6
_PPMD_MEM_MB = 16
_LZMA_FILTER = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20}


class _Pipe(io.RawIOBase):
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        n = min(len(b), len(self._data) - self._pos)
        b[:n] = self._data[self._pos : self._pos + n]
        self._pos += n
        return n


def _deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _deflate64(data: bytes) -> bytes:
    import inflate64

    d = inflate64.Deflater()
    return d.deflate(data) + d.flush()


def _lzma(data: bytes) -> bytes:
    # ZIP method 14: version, properties size, properties, then raw LZMA1. Python's
    # raw LZMA1 encoder always writes the end-of-stream marker (bit 1 set below).
    props = lzma._encode_filter_properties(_LZMA_FILTER)  # type: ignore[attr-defined]
    header = struct.pack("<BBH", 9, 20, len(props)) + props
    return header + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[_LZMA_FILTER])


def _ppmd(data: bytes) -> bytes:
    import pyppmd

    word = (_PPMD_ORDER - 1) | ((_PPMD_MEM_MB - 1) << 4)
    enc = pyppmd.Ppmd8Encoder(_PPMD_ORDER, _PPMD_MEM_MB << 20, 0)
    return struct.pack("<H", word) + enc.encode(data) + enc.flush(True)


def _zstd(data: bytes) -> bytes:
    return zstd_backend().compress(data)


@dataclass(frozen=True)
class _Method:
    number: int
    flags: int
    compress: object


_METHODS = {
    "deflate": pytest.param(_Method(8, 0, _deflate), id="deflate"),
    "deflate64": pytest.param(
        _Method(9, 0, _deflate64), id="deflate64", marks=requires("inflate64")
    ),
    "bzip2": pytest.param(_Method(12, 0, bz2.compress), id="bzip2"),
    "lzma": pytest.param(_Method(14, 2, _lzma), id="lzma"),
    "ppmd": pytest.param(_Method(98, 0, _ppmd), id="ppmd", marks=requires("pyppmd")),
    "zstd": pytest.param(_Method(93, 0, _zstd), id="zstd", marks=requires_zstd()),
}


@dataclass(frozen=True)
class _Member:
    name: bytes
    method: int
    flags: int
    data: bytes
    packed: bytes
    #: What the descriptor states, when it should not be the true value.
    crc: int | None = None


def _member(name: bytes, method: _Method, data: bytes) -> _Member:
    packed = method.compress(data)  # type: ignore[operator]
    return _Member(name, method.number, method.flags, data, packed)


def _stored(name: bytes, data: bytes) -> _Member:
    return _Member(name, 0, 0, data, data)


def _streamed_zip(
    members: list[_Member], *, signed: bool = True, cut_after: int | None = None
) -> bytes:
    """Lay ``members`` out as a streaming writer does, then the directory.

    ``cut_after`` ends the archive right after that member's data, its descriptor
    and everything after it left out.
    """
    out = bytearray()
    central = bytearray()
    for index, m in enumerate(members):
        crc = zlib.crc32(m.data) if m.crc is None else m.crc
        offset = len(out)
        deferred = m.method != 0
        flags = m.flags | (8 if deferred else 0)
        sizes = (0, 0, 0) if deferred else (crc, len(m.packed), len(m.data))
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, m.method, 0, 0, *sizes,
            len(m.name), 0,
        )  # fmt: skip
        out += m.name + m.packed
        if index == cut_after:
            return bytes(out)
        if deferred:
            if signed:
                out += b"PK\x07\x08"
            out += struct.pack("<III", crc, len(m.packed), len(m.data))
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, m.method, 0, 0, crc,
            len(m.packed), len(m.data), len(m.name), 0, 0, 0, 0, 0, offset,
        )  # fmt: skip
        central += m.name
    cd_offset = len(out)
    out += central
    out += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central),
        cd_offset, 0,
    )  # fmt: skip
    return bytes(out)


def _params(method: int, data: MemberData) -> CodecParams:
    """Peel the method's header off ``data``, as the reader does."""
    if method == 14:
        header = data.read(4)
        props = data.read(struct.unpack_from("<H", header, 2)[0])
        f = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)  # type: ignore[attr-defined]
        return CodecParams(filters=[f])
    if method == 98:
        word = struct.unpack("<H", data.read(2))[0]
        return CodecParams(
            ppmd_order=(word & 0xF) + 1,
            ppmd_mem_size=(((word >> 4) & 0xFF) + 1) << 20,
            ppmd_restore_method=word >> 12,
            input_runs_on=True,
        )
    if method == 12:
        return CodecParams(single_stream=True)
    return CodecParams()


def _codec(method: int):
    from archivey.internal.backends.zip_reader import _ZIP_METHOD_CODECS

    return _ZIP_METHOD_CODECS[method]


def _read_member(
    walk: LocalHeaderWalk,
    *,
    limits: DecoderLimits | None = None,
    isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
) -> tuple[bytes, bytes, DataDescriptor | None] | None:
    entry = walk.next_entry()
    if entry is None:
        return None
    data = walk.member_data(entry)
    if entry.header.method == 0:
        out = data.read()
        return entry.header.name, out, data.settle()
    config = StreamConfig(
        refuse_input_after_end=True,
        decoder_limits=limits or DecoderLimits(),
        process_isolation=isolation,
    )
    stream = open_codec_stream(
        _codec(entry.header.method),
        data,
        config=config,
        params=_params(entry.header.method, data),
        seekable=False,
    )
    out = bytearray()
    try:
        while chunk := stream.read(65536):
            out += chunk
    except DataAfterEndError:
        pass  # the codec ended and the archive goes on
    finally:
        stream.close()
    descriptor = data.settle(crc=zlib.crc32(out), file_size=len(out))
    return entry.header.name, bytes(out), descriptor


def _read_all(raw: bytes, **kwargs: object) -> list[tuple[bytes, bytes]]:
    walk = LocalHeaderWalk(_Pipe(raw))
    got = []
    while (read := _read_member(walk, **kwargs)) is not None:  # type: ignore[arg-type]
        name, out, _ = read
        got.append((name, out))
    tail = walk.read_rest(None)
    entries = CentralDirectoryWalk(tail.read_at, tail.end_record())
    assert [e.name for e in entries] == [name for name, _ in got]
    return got


@pytest.mark.parametrize("method", list(_METHODS.values()))
@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
def test_a_codec_member_ends_where_its_codec_ends(
    method: _Method, signed: bool
) -> None:
    members = [
        _member(b"big", method, _BIG),
        _member(b"small", method, _SMALL),
        _member(b"empty", method, b""),
        _stored(b"stored", b"stored data"),
        _member(b"last", method, _SMALL),
    ]
    raw = _streamed_zip(members, signed=signed)
    assert _read_all(raw) == [(m.name, m.data) for m in members]


@requires_zstd()
@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
def test_a_zstd_member_of_several_frames_ends_after_its_last(signed: bool) -> None:
    # Every frame of a Zstd member is content, so the decoder reads on past each frame
    # end; with no size declared, the walk still finds the descriptor after the last.
    def frames(data: bytes) -> bytes:
        half = len(data) // 2
        return _zstd(data[:half]) + _zstd(data[half:])

    method = _Method(93, 0, frames)
    members = [
        _member(b"big", method, _BIG),
        _member(b"small", method, _SMALL),
        _stored(b"stored", b"stored data"),
    ]
    raw = _streamed_zip(members, signed=signed)
    assert _read_all(raw) == [(m.name, m.data) for m in members]


@requires("pyppmd")
def test_ppmd_with_no_size_decodes_in_a_child_unless_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every PPMd member decodes in a child by default, so where none can start the
    # member is refused; under NONE it is fed to pyppmd in pieces in this process.
    # (``test_a_codec_member_ends_where_its_codec_ends`` decodes ``_BIG``, many feeds
    # long, in the child.)
    member = _member(b"p", _METHODS["ppmd"].values[0], _BIG)
    raw = _streamed_zip([member])
    assert _read_all(raw, isolation=ProcessIsolation.NONE) == [(b"p", member.data)]
    monkeypatch.setattr(
        ppmd_decoder, "ppmd_child_unavailable_reason", lambda: "no child here"
    )
    with pytest.raises(ResourceLimitError, match="none can be started") as caught:
        _read_all(raw)
    assert "process_isolation=KNOWN_CRASHES" in str(caught.value)
    assert "ProcessIsolation.NONE" in str(caught.value)


def test_a_signed_descriptor_with_another_crc_is_found_by_its_size() -> None:
    method = _METHODS["deflate"].values[0]
    bad = _member(b"bad", method, _SMALL)
    bad = _Member(bad.name, bad.method, bad.flags, bad.data, bad.packed, crc=1234)
    raw = _streamed_zip([bad, _member(b"next", method, _BIG)])
    walk = LocalHeaderWalk(_Pipe(raw))
    read = _read_member(walk)
    assert read is not None
    descriptor = read[2]
    assert descriptor is not None
    assert descriptor.crc == 1234  # the caller judges the mismatch
    assert descriptor.compressed_size == len(bad.packed)
    after = _read_member(walk)
    assert after is not None
    assert after[:2] == (b"next", _BIG)


def _unsigned_with_another_crc() -> tuple[_Member, bytearray]:
    method = _METHODS["deflate"].values[0]
    bad = _member(b"bad", method, _SMALL)
    bad = _Member(bad.name, bad.method, bad.flags, bad.data, bad.packed, crc=1234)
    return bad, bytearray(_streamed_zip([bad, _stored(b"next", b"x")], signed=False))


def test_an_unsigned_descriptor_with_another_crc_is_found_by_its_sizes() -> None:
    """Both its sizes still agree, so one damaged field places it (DR-2): the caller
    judges the CRC, and the next member is read."""
    bad, raw = _unsigned_with_another_crc()
    walk = LocalHeaderWalk(_Pipe(bytes(raw)))
    read = _read_member(walk)
    assert read is not None
    descriptor = read[2]
    assert descriptor is not None
    assert descriptor.crc == 1234
    assert descriptor.compressed_size == len(bad.packed)
    after = _read_member(walk)
    assert after is not None
    assert after[:2] == (b"next", b"x")


def test_an_unsigned_descriptor_with_two_damaged_fields_cannot_be_found() -> None:
    bad, raw = _unsigned_with_another_crc()
    raw[30 + len(bad.name) + len(bad.packed) + 8] ^= 0x01  # the uncompressed size
    with pytest.raises(CorruptionError, match="no data descriptor after member #0"):
        _read_all(bytes(raw))


def test_a_stream_cut_after_the_codec_end_is_truncation() -> None:
    method = _METHODS["deflate"].values[0]
    raw = _streamed_zip([_member(b"cut", method, _SMALL)], cut_after=0)
    with pytest.raises(TruncatedError, match="before member #0's data descriptor"):
        _read_all(raw)


@pytest.mark.parametrize("signed", [True, False])
def test_a_settle_that_fails_ends_the_walk_with_its_error(signed: bool) -> None:
    """Where the data ends is unknown, so the walk cannot find the next header: it
    raises what ``settle`` raised, not a misuse error."""
    method = _METHODS["deflate"].values[0]
    first = _member(b"first", method, _SMALL)
    if signed:  # cut before the descriptor
        raw = _streamed_zip([first], cut_after=0)
        expected: type[Exception] = TruncatedError
    else:  # a descriptor with two fields that do not match the data
        first = _Member(
            first.name, first.method, first.flags, first.data, first.packed, crc=1
        )
        damaged = bytearray(
            _streamed_zip([first, _stored(b"next", b"x")], signed=False)
        )
        damaged[30 + len(first.name) + len(first.packed) + 8] ^= 0x01
        raw = bytes(damaged)
        expected = CorruptionError
    walk = LocalHeaderWalk(_Pipe(raw))
    with pytest.raises(expected) as settled:
        _read_member(walk)
    with pytest.raises(expected) as walked_on:
        walk.next_entry()
    assert walked_on.value is settled.value


@requires("pyppmd")
@pytest.mark.parametrize(
    "kwargs",
    [
        {"variant": 7, "unpack_size": 10, "pack_size": 5},
        {"variant": 8, "unpack_size": 10},
        {"variant": 8, "refuse_input_after_end": False},
    ],
    ids=["ppmd7", "sized", "not-refusing"],
)
def test_input_runs_on_is_for_ppmd8_without_a_size(kwargs: dict) -> None:
    kwargs = {"refuse_input_after_end": True, **kwargs}
    with pytest.raises(ValueError, match="input_runs_on is for PPMd8"):
        ppmd_decoder.PpmdDecoder(
            order=6, mem_size=1 << 20, input_runs_on=True, **kwargs
        )


@requires("pyppmd")
def test_the_ppmd_codec_refuses_input_runs_on_for_7z_properties() -> None:
    from archivey.internal.streams.codecs.ppmd_codec import PpmdCodec

    params = CodecParams(
        properties=struct.pack("<BI", 6, 1 << 20),
        unpack_size=10,
        pack_size=5,
        input_runs_on=True,
    )
    with pytest.raises(ValueError, match="input_runs_on needs PPMd8"):
        PpmdCodec().open(io.BytesIO(b"x" * 5), params, StreamConfig())


def _stored_block(data: bytes, *, final: bool) -> bytes:
    """A raw DEFLATE stored block holding ``data``."""
    return (
        bytes([int(final)]) + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data
    )


def test_a_planted_descriptor_ends_a_codec_member_early() -> None:
    # The codec analogue of the stored scan's planted prefix. Past 5 MiB of data (so
    # the walk has dropped the oldest bytes it kept), a stored block carries a
    # descriptor for the member up to that point and a local header signature. The
    # first match wins; the walk then reads on from inside the data, and only the
    # check against the central entry at the end of the pass (task 3.3b) can catch it.
    head = zlib.compressobj(1, zlib.DEFLATED, -15)
    prefix = _RANDOM.randbytes(5 << 20)
    packed = head.compress(prefix) + head.flush(zlib.Z_FULL_FLUSH)
    pos = len(packed) + 5  # the planted record follows the stored block's header
    # A crafted member makes its decoded CRC and size agree with the record (CRC-32
    # is linear, the size is its own choice); the test hands ``settle`` the
    # record's values instead of forging them.
    crc, size = 0x12345678, 1234
    planted = b"PK\x07\x08" + struct.pack("<III", crc, pos, size)
    planted += b"PK\x03\x04" + b"\0" * 20
    packed += _stored_block(planted, final=False)
    packed += _stored_block(b"tail", final=True)
    member = _Member(b"m", 8, 0, prefix + planted + b"tail", packed)
    walk = LocalHeaderWalk(_Pipe(_streamed_zip([member])))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    stream = open_codec_stream(
        _codec(8),
        data,
        config=StreamConfig(refuse_input_after_end=True),
        seekable=False,
    )
    out = bytearray()
    with pytest.raises(DataAfterEndError):
        while chunk := stream.read(1 << 20):
            out += chunk
    assert out == member.data
    # The record is among the bytes handed out, past what the walk still keeps of
    # the member's start.
    assert _CODEC_RETAIN < pos < data.consumed
    descriptor = data.settle(crc=crc, file_size=size)
    assert descriptor is not None
    assert descriptor.compressed_size == pos  # ended inside its own data
    with pytest.raises(CorruptionError):
        walk.next_entry()


def test_what_the_stream_read_past_a_large_member_is_put_back() -> None:
    # Large reads feed the codec up to 1 MiB at a time; whatever of the last feed is
    # past the end comes from the bytes the walk kept.
    method = _METHODS["deflate"].values[0]
    big = _RANDOM.randbytes(5 << 20)
    members = [_member(b"big", method, big), _stored(b"after", _SMALL)]
    walk = LocalHeaderWalk(_Pipe(_streamed_zip(members)))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    stream = open_codec_stream(
        _codec(8),
        data,
        config=StreamConfig(refuse_input_after_end=True),
        seekable=False,
    )
    out = bytearray()
    with pytest.raises(DataAfterEndError):
        while chunk := stream.read(4 << 20):
            out += chunk
    assert out == big
    assert data.consumed > len(members[0].packed)
    data.settle(crc=zlib.crc32(out), file_size=len(out))
    assert _read_member(walk) == (b"after", _SMALL, None)


def test_settle_hands_over_the_data_it_read_past_what_was_handed_out() -> None:
    """A caller whose reads stop short of the data's end (a decrypt stage that has
    not reached the authentication code) gets the rest from ``passed_over``."""
    method = _METHODS["deflate"].values[0]
    member = _member(b"a", method, _SMALL)
    walk = LocalHeaderWalk(_Pipe(_streamed_zip([member, _stored(b"next", b"x")])))
    entry = walk.next_entry()
    assert entry is not None
    data = walk.member_data(entry)
    assert data.passed_over == b""
    handed = data.read(len(member.packed) - 3)
    descriptor = data.settle(crc=zlib.crc32(_SMALL), file_size=len(_SMALL))
    assert descriptor.compressed_size == len(member.packed)
    assert handed + data.passed_over == member.packed
    after = _read_member(walk)
    assert after is not None
    assert after[:2] == (b"next", b"x")
