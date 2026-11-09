"""LZMA Alone streams with a known size and an end marker, on an old liblzma.

liblzma 5.2.5 and older (fixed by 5.2.12) refuses such a stream at the marker, and the python.org builds
for macOS and Windows bundle one (5.2.3 on macOS). The tests force the workaround on, so
they run on any liblzma, and emulate the old decoder where the path needs its failure.
"""

from __future__ import annotations

import io
import lzma
from typing import Any, cast

import pytest

from archivey import open_archive
from archivey.config import DecoderLimits
from archivey.exceptions import CorruptionError
from archivey.formats import Decompressor
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
    """Natives whose first Alone decoder fails at the marker, as liblzma 5.2.5 does.

    liblzma 5.2.5 writes every byte of the declared size and then returns
    ``LZMA_DATA_ERROR`` from the same call, so CPython drops that call's output.
    """

    def __init__(self, *, fail_first: bool = True) -> None:
        self.built = 0
        self._fail_first = fail_first

    def lzma_decompressor(self, **kwargs: Any) -> Decompressor:
        self.built += 1
        real = IN_PROCESS.lzma_decompressor(**kwargs)
        return _FailsAtMarker(real) if self._fail_first and self.built == 1 else real


class _FailsAtMarker:
    def __init__(self, real: Decompressor) -> None:
        self._real = real

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        out = self._real.decompress(data, max_length)
        if self._real.eof:
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
    try:
        assert lzma.decompress(_marker_stream(), format=lzma.FORMAT_ALONE) == PAYLOAD
    except lzma.LZMAError:
        assert refuses
    else:
        assert not refuses


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
