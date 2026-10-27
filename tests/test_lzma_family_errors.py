"""The LZMA family types its errors in one place each.

Raw LZMA properties are typed where they are decoded (``decode_lzma_filter_properties``),
for 7z and ZIP alike, and lzip maps liblzma's errors through the same
``lzma_error_to_archivey`` as xz and ``.lzma``.
"""

from __future__ import annotations

import lzma

import pytest

from archivey.config import DecoderLimits
from archivey.exceptions import CorruptionError, UnsupportedFeatureError
from archivey.internal.streams.codecs import (
    decode_lzma_filter_properties,
    lzip_decoder as lzip,
    lzma_codec,
)


@pytest.mark.parametrize(
    ("filter_id", "props"),
    [
        pytest.param(lzma.FILTER_LZMA1, b"\xff\x00\x00\x01\x00", id="lzma1-byte-255"),
        pytest.param(lzma.FILTER_LZMA1, b"\x5d\x00", id="lzma1-short"),
        pytest.param(lzma.FILTER_LZMA2, b"\x41", id="lzma2-dict-code-past-40"),
        pytest.param(lzma.FILTER_LZMA2, b"", id="lzma2-empty"),
    ],
)
def test_malformed_properties_are_corruption_naming_the_coder(
    filter_id: int, props: bytes
) -> None:
    with pytest.raises(CorruptionError, match="^Malformed test coder properties$"):
        decode_lzma_filter_properties(filter_id, props, what="test coder")


def test_lc_lp_over_four_stays_unsupported() -> None:
    props = bytes([8]) + (1 << 16).to_bytes(4, "little")  # lc=8, lp=0, pb=0
    with pytest.raises(UnsupportedFeatureError, match="lc=8, lp=0"):
        decode_lzma_filter_properties(lzma.FILTER_LZMA1, props, what="test coder")


def test_split_lzma_props_covers_the_format_range() -> None:
    assert lzma_codec._split_lzma_props(0x5D) == (3, 0, 2)
    assert lzma_codec._split_lzma_props(224) == (8, 4, 4)
    assert lzma_codec._split_lzma_props(225) is None
    plausible = sum(lzma_codec._alone_props_plausible(b) for b in range(256))
    decodable = sum(lzma_codec._alone_props_liblzma_decodes(b) for b in range(256))
    assert (plausible, decodable) == (225, 75)


def test_liblzma_decodes_predicate_matches_liblzma() -> None:
    """Detection branches on ``_alone_props_liblzma_decodes``; pin it against
    liblzma itself over every properties byte, not against the formula it is
    derived from."""
    liblzma_decode = getattr(lzma, "_decode_filter_properties")  # noqa: B009
    mismatches = []
    for props_byte in range(256):
        props = bytes([props_byte]) + (1 << 16).to_bytes(4, "little")
        try:
            liblzma_decode(lzma.FILTER_LZMA1, props)
            decodes = True
        except lzma.LZMAError:
            decodes = False
        if lzma_codec._alone_props_liblzma_decodes(props_byte) is not decodes:
            mismatches.append(props_byte)
    assert mismatches == []


class _FailingDecompressor:
    """Stands in for the member's ``LZMADecompressor`` with a given liblzma error."""

    needs_input = False

    def __init__(self, message: str) -> None:
        self._message = message

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        raise lzma.LZMAError(self._message)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Invalid or unsupported options", UnsupportedFeatureError),
        ("Corrupt input data", CorruptionError),
    ],
)
def test_lzip_maps_liblzma_errors_by_cause(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: type[Exception]
) -> None:
    """White-box: lzip's fixed properties give a real member no options error."""
    state = lzip._LzipState(DecoderLimits(), 0)
    state._state = lzip._LzipState._IN_MEMBER
    monkeypatch.setattr(state, "_dec", _FailingDecompressor(message))
    with pytest.raises(expected, match=message):
        state.feed(b"\x00")


@pytest.mark.parametrize(
    ("message", "raises"),
    [
        pytest.param("Invalid or unsupported options", True, id="options-is-raised"),
        pytest.param("Corrupt input data", False, id="corruption-reads-as-truncation"),
    ],
)
def test_lzip_flush_drain_swallows_only_damage(
    monkeypatch: pytest.MonkeyPatch, message: str, raises: bool
) -> None:
    """As on xz, a liblzma error at the drain is a truncated tail only when it is damage.

    White-box: the drain runs only when the decoder still holds input after the
    final ``_process`` pass, which a real stream does not reliably reach.
    """
    state = lzip._LzipState(DecoderLimits(), 0)
    state._state = lzip._LzipState._IN_MEMBER
    monkeypatch.setattr(state, "_dec", _FailingDecompressor(message))
    monkeypatch.setattr(state, "_process", lambda max_length=-1: (b"", []))
    if raises:
        with pytest.raises(UnsupportedFeatureError, match=message):
            state.flush()
        assert state.truncated is False
    else:
        assert state.flush() == (b"", [])
        assert state.truncated is True
