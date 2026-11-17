"""LZMA Alone streams with a known size and an end marker.

liblzma before 5.2.6 refuses such a stream at the marker; the python.org builds for
macOS and Windows bundle one (5.2.3 on macOS). Every later version measured refuses it
when the marker is not yet in the input of the call that writes the last declared byte.
Most tests force the workaround on, so they run on any liblzma, and emulate the old
decoder where the
path needs its failure; the first two use this process's real liblzma."""

from __future__ import annotations

import io
import lzma
from typing import Any, cast

import pytest

from archivey import open_archive
from archivey.config import DecoderLimits
from archivey.exceptions import CorruptionError, ResourceLimitError, TruncatedError
from archivey.formats import Decompressor
from archivey.internal.resource_usage import ResourceUsageRecorder
from archivey.internal.streams.codecs import lzma_codec
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives

PAYLOAD = b"payload data payload data payload data!"

# 7-Zip 23.01 (`7zz a -m0=LZMA:d=64k`), packed stream of PAYLOAD: LZMA1 with no end
# marker, as a 7z coder or the LZMA SDK's `lzma_alone` without `-eos` writes it.
_NO_MARKER_DATA = bytes.fromhex("0038184b99750f4608321e13c61072944e52151d0000")


def _header(size: int) -> bytes:
    return bytes([0x5D]) + (1 << 16).to_bytes(4, "little") + size.to_bytes(8, "little")


def _no_marker_stream() -> bytes:
    return _header(len(PAYLOAD)) + _NO_MARKER_DATA


def _marker_stream(declared: int = len(PAYLOAD)) -> bytes:
    # liblzma writes the "unknown" size and an end marker; declare a size as well.
    stream = bytearray(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
    stream[5:13] = declared.to_bytes(8, "little")
    return bytes(stream)


class _OldLiblzma:
    """Natives whose first Alone decoder fails at the declared size, as liblzma 5.2.5 does.

    liblzma 5.2.5 checks that the range coder is finished as soon as it writes the last
    declared byte. With a marker after that byte, it is not, so it returns
    ``LZMA_DATA_ERROR`` from that call, before it reads the marker; CPython drops the
    call's output. Measured on 5.2.5: a 39-byte stream fed one byte at a time fails at
    input byte 33, and the marker ends at byte 38. Use it only on a stream that has a
    marker, or to model a stream without one whose range coder is not finished.
    """

    def __init__(self, *, fail_first: bool = True) -> None:
        self.built = 0
        self._fail_first = fail_first

    def lzma_decompressor(self, **kwargs: Any) -> Decompressor:
        self.built += 1
        real = IN_PROCESS.lzma_decompressor(**kwargs)
        return _FailsAtSize(real) if self._fail_first and self.built == 1 else real


class _FailsAtSize:
    def __init__(self, real: Decompressor) -> None:
        self._real = real
        self._head = b""
        self._left: int | None = None  # declared bytes not yet written

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._left is None:
            self._head += data
            if len(self._head) >= 13:
                self._left = int.from_bytes(self._head[5:13], "little")
        out = self._real.decompress(data, max_length)
        if self._left is not None:
            self._left -= len(out)
            if self._left <= 0:
                raise lzma.LZMAError("Corrupt input data")
        return out

    @property
    def eof(self) -> bool:
        return False

    @property
    def unused_data(self) -> bytes:
        return b""

    @property
    def needs_input(self) -> bool:
        return self._real.needs_input


@pytest.fixture
def old_liblzma(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lzma_codec, "_liblzma_refuses_marker_after_known_size", lambda: True
    )


def _decode(
    data: bytes,
    *,
    chunk: int,
    max_length: int = -1,
    natives: object = IN_PROCESS,
) -> tuple[bytes, Decompressor]:
    dec = lzma_codec._new_alone_decompressor(
        None, DecoderLimits(), cast(Natives, natives)
    )
    out = b""
    pos = 0
    while not dec.eof:
        if dec.needs_input:
            if pos >= len(data):
                break
            piece = data[pos : pos + chunk]
            pos += chunk
        else:
            piece = b""
        out += dec.decompress(piece, max_length)
    return out, dec


def test_the_liblzma_check_matches_the_stdlib_decoder() -> None:
    lzma_codec._liblzma_refuses_marker_after_known_size.cache_clear()
    refuses = lzma_codec._liblzma_refuses_marker_after_known_size()
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        for byte in _marker_stream():
            decoder.decompress(bytes([byte]))
    except lzma.LZMAError:
        assert refuses
    else:
        assert refuses is not decoder.eof


@pytest.mark.parametrize("chunk", [1, 5, 13, 64])
def test_a_marker_split_across_reads_decodes_on_this_liblzma(chunk: int) -> None:
    # No forcing: whatever liblzma this process has. liblzma 5.4.5 and 5.8.1 refuse
    # this stream in the stdlib decoder for chunks up to 13 bytes.
    lzma_codec._liblzma_refuses_marker_after_known_size.cache_clear()
    out, dec = _decode(_marker_stream() + b"JUNK", chunk=chunk)
    assert out == PAYLOAD
    assert dec.eof


# The old decoder fails only on a stream with a marker; it reads one without.
_KNOWN_SIZE_CASES = [
    pytest.param(_no_marker_stream(), False, id="no-marker"),
    pytest.param(_marker_stream(), False, id="marker-new-decoder"),
    pytest.param(_marker_stream(), True, id="marker-old-decoder"),
]


@pytest.mark.usefixtures("old_liblzma")
@pytest.mark.parametrize(("stream", "old"), _KNOWN_SIZE_CASES)
@pytest.mark.parametrize("chunk", [1, 5, 1000])
@pytest.mark.parametrize("max_length", [-1, 1, 7])
def test_known_size_streams_decode_and_end_exactly(
    stream: bytes, old: bool, chunk: int, max_length: int
) -> None:
    natives = _OldLiblzma() if old else IN_PROCESS
    out, dec = _decode(
        stream + b"JUNK", chunk=chunk, max_length=max_length, natives=natives
    )
    assert out == PAYLOAD
    assert dec.eof
    if chunk == 1000:
        assert dec.unused_data == b"JUNK"


@pytest.mark.usefixtures("old_liblzma")
@pytest.mark.parametrize("old", [False, True], ids=["new-decoder", "old-decoder"])
def test_a_marker_after_the_wrong_size_is_refused(old: bool) -> None:
    natives = _OldLiblzma() if old else IN_PROCESS
    for declared in (len(PAYLOAD) - 1, len(PAYLOAD) + 1):
        with pytest.raises(lzma.LZMAError):
            _decode(_marker_stream(declared), chunk=1000, natives=natives)


@pytest.mark.usefixtures("old_liblzma")
@pytest.mark.parametrize("old", [False, True], ids=["new-decoder", "old-decoder"])
def test_a_corrupt_known_size_stream_still_fails(old: bool) -> None:
    natives = _OldLiblzma() if old else IN_PROCESS
    stream = bytearray(_marker_stream())
    stream[len(stream) - 3] ^= 0xFF  # inside the end marker
    with pytest.raises(lzma.LZMAError):
        _decode(bytes(stream), chunk=1000, natives=natives)


@pytest.mark.usefixtures("old_liblzma")
@pytest.mark.parametrize("stream", [_no_marker_stream(), _marker_stream()])
def test_concatenated_known_size_streams_read_through_the_api(stream: bytes) -> None:
    with open_archive(io.BytesIO(stream + stream), format="lzma") as archive:
        (member,) = archive.members()
        assert archive.read(member) == PAYLOAD + PAYLOAD


@pytest.mark.usefixtures("old_liblzma")
def test_unknown_size_streams_build_one_decoder() -> None:
    natives = _OldLiblzma(fail_first=False)
    out, dec = _decode(
        lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE), chunk=1000, natives=natives
    )
    assert out == PAYLOAD
    assert dec.eof
    assert natives.built == 1


@pytest.mark.usefixtures("old_liblzma")
def test_wrong_size_through_the_api_is_corruption() -> None:
    with (
        open_archive(io.BytesIO(_marker_stream(len(PAYLOAD) + 1)), format="lzma") as a,
        pytest.raises(CorruptionError),
    ):
        (member,) = a.members()
        a.read(member)


@pytest.mark.usefixtures("old_liblzma")
def test_no_marker_after_the_switch_is_refused() -> None:
    # The first decoder fails at the declared size of a stream with no marker (a range
    # coder that is not finished); the marker decoder then writes past that size.
    with pytest.raises(lzma.LZMAError, match="no end marker"):
        _decode(_no_marker_stream() + b"\x00" * 64, chunk=1, natives=_OldLiblzma())


@pytest.fixture
def old_liblzma_everywhere(monkeypatch: pytest.MonkeyPatch, old_liblzma: None) -> None:
    """Every ``_AloneDecompressor`` the API builds gets the old first decoder."""
    del old_liblzma
    real_new = lzma_codec._AloneDecompressor._new

    def new(self: lzma_codec._AloneDecompressor) -> Decompressor:
        dec = real_new(self)
        if not getattr(self, "_built_first", False):
            self._built_first = True  # type: ignore[attr-defined]
            return _FailsAtSize(dec)
        return dec

    monkeypatch.setattr(lzma_codec._AloneDecompressor, "_new", new)


class _ShortReads(io.RawIOBase):
    """A non-seekable source that returns at most ``step`` bytes per read."""

    def __init__(self, data: bytes, step: int) -> None:
        self._data = data
        self._pos = 0
        self._step = step

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        piece = self._data[self._pos : self._pos + min(len(buffer), self._step)]
        buffer[: len(piece)] = piece
        self._pos += len(piece)
        return len(piece)


@pytest.mark.usefixtures("old_liblzma_everywhere")
@pytest.mark.parametrize("step", [1, 5, 33])
def test_a_read_boundary_inside_the_marker_reads_through_the_api(step: int) -> None:
    source = cast(Any, _ShortReads(_marker_stream(), step))
    with open_archive(source, format="lzma", streaming=True) as archive:
        read = []
        for _member, stream in archive.stream_members():
            assert stream is not None
            read.append(stream.read())
        assert read == [PAYLOAD]


@pytest.mark.usefixtures("old_liblzma_everywhere")
def test_input_ending_inside_the_marker_is_truncation() -> None:
    stream = _marker_stream()
    with (
        open_archive(io.BytesIO(stream[:-2]), format="lzma") as archive,
        pytest.raises(TruncatedError),
    ):
        archive.read(archive.members()[0])


@pytest.mark.usefixtures("old_liblzma")
def test_both_dictionaries_count_against_the_cap() -> None:
    def stream(known_size: bool) -> bytes:
        data = bytearray(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
        data[1:5] = (1 << 20).to_bytes(4, "little")  # a 1 MiB dictionary
        if known_size:
            data[5:13] = len(PAYLOAD).to_bytes(8, "little")
        return bytes(data)

    tight = DecoderLimits(max_decoder_memory=3 << 19)  # 1.5 MiB: one fits, two do not
    usage = ResourceUsageRecorder()
    with pytest.raises(ResourceLimitError, match="held twice"):
        lzma_codec._new_alone_decompressor(None, tight, IN_PROCESS, usage).decompress(
            stream(True)
        )
    # The refused declaration is recorded at its full size.
    assert usage.snapshot().decoder_memory == 2 << 20
    # An unknown size needs one decoder, which fits.
    assert (
        lzma_codec._new_alone_decompressor(None, tight).decompress(stream(False))
        == PAYLOAD
    )
    roomy = DecoderLimits(max_decoder_memory=3 << 20)
    assert (
        lzma_codec._new_alone_decompressor(None, roomy).decompress(stream(True))
        == PAYLOAD
    )


@pytest.mark.usefixtures("old_liblzma")
def test_a_probe_counts_its_clamped_dictionary_twice() -> None:
    # A detection probe clamps the dictionary to its read (100 000 bytes -> 100 064);
    # with a known size it holds that dictionary twice.
    data = bytearray(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
    data[1:5] = (1 << 20).to_bytes(4, "little")
    unknown = bytes(data)
    data[5:13] = len(PAYLOAD).to_bytes(8, "little")
    tight = DecoderLimits(max_decoder_memory=150_000)
    with pytest.raises(ResourceLimitError, match="detection probe"):
        lzma_codec._new_alone_decompressor(100_000, tight).decompress(bytes(data))
    assert (
        lzma_codec._new_alone_decompressor(100_000, tight).decompress(unknown)
        == PAYLOAD
    )
