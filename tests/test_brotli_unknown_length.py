"""Unknown-length framing rejects only bytes reached, never a declined read."""

from __future__ import annotations

import pytest

from archivey.internal.streams.codecs.brotli_framing import _check_end, walk_chain
from tests.streams_util import brotli_declared_metablock_header


@pytest.mark.parametrize("data", [b"\x06", b"\x1a"])
@pytest.mark.parametrize("suffix", [b"", b"junk"])
def test_unknown_length_checks_trailing_bytes(data: bytes, suffix: bytes) -> None:
    # RFC 7932: 06 is an empty stream; 1a is a final empty metadata block.
    blob = data + suffix
    result = walk_chain(blob[:1], None, read_at=lambda off, n: blob[off : off + n])
    assert result.proves_invalid == bool(suffix)


def test_unknown_length_does_not_treat_prefix_exhaustion_as_eof() -> None:
    head = brotli_declared_metablock_header(100_000, first=True)
    assert not walk_chain(head + bytes(4096), None).proves_invalid
    assert not walk_chain(
        head + bytes(4096), None, read_at=lambda off, n: None
    ).proves_invalid


def test_unknown_length_rejects_a_missing_successor() -> None:
    head = brotli_declared_metablock_header(100_000, first=True)
    blob = head + bytes(5000)
    result = walk_chain(blob[:4096], None, read_at=lambda off, n: blob[off : off + n])
    assert result.proves_invalid


@pytest.mark.parametrize("payload_size", [0, 9, 10])
def test_unknown_length_checks_the_final_declared_payload(payload_size: int) -> None:
    # RFC 7932 fields: WBITS=16, ISLAST=1, ISLASTEMPTY=0, metadata,
    # MSKIPBYTES=1 and MSKIPLEN=9 (ten payload bytes), followed by byte alignment.
    head = b"\x5a\x09"
    blob = head + bytes(payload_size)
    result = walk_chain(head, None, read_at=lambda off, n: blob[off : off + n])
    assert result.proves_invalid == (payload_size != 10)


@pytest.mark.parametrize("ended", [False, True])
def test_a_partial_available_header_is_not_eof(ended: bool) -> None:
    result = walk_chain(b"", None, read_available=lambda off, n: (b"\x00", ended))
    assert result.proves_invalid == ended


@pytest.mark.parametrize(
    ("data", "ended", "invalid"),
    [
        (b"", False, False),
        (b"", True, True),
        (b"\x06", False, False),
        (b"\x06x", False, True),
    ],
)
def test_an_optional_end_observation_needs_eof_evidence(
    data: bytes, ended: bool, invalid: bool
) -> None:
    result = _check_end(b"\x06", None, 1, None, lambda off, n: (data, ended))
    assert result.proves_invalid == invalid
