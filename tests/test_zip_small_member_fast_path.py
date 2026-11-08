"""A small ZIP member read whole at open gives what the codec layer gives.

``ZipReader._speculative_small_member`` reads and checks a small stored or deflated
member in one go, and hands every doubt to the general path. These tests hold the
outcome to the general path's: the same bytes, the same error type and message, the
same verification level and the same diagnostics, on intact archives and on damaged
copies of them.
"""

from __future__ import annotations

import hashlib
import io
import random
import struct
import zipfile
import zlib
from collections.abc import Callable

import pytest

from archivey import open_archive
from archivey.internal.backends import zip_reader


def _zip_bytes() -> bytes:
    rng = random.Random(3)
    text = b"the quick brown fox jumps over the lazy dog\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("empty-stored", b"", compress_type=zipfile.ZIP_STORED)
        zf.writestr("empty-deflate", b"", compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("stored", rng.randbytes(300), compress_type=zipfile.ZIP_STORED)
        zf.writestr("deflate", text * 20, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("random", rng.randbytes(500), compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("dir/", b"")
        zf.writestr("large", text * 2000 + rng.randbytes(70_000), compress_type=8)
    return buf.getvalue()


def _outcome(data: bytes) -> list[object]:
    """Everything a caller can see: each member's bytes or error, by a pass and by
    name, each member's verification level, and the reader's diagnostics."""
    seen: list[object] = []

    def attempt(label: str, fn: Callable[[], bytes]) -> None:
        try:
            got = fn()
        except Exception as exc:  # noqa: BLE001 - the error is what is compared
            seen.append((label, type(exc).__name__, str(exc)))
        else:
            seen.append((label, hashlib.sha256(got).hexdigest()))

    try:
        with open_archive(io.BytesIO(data)) as ar, ar.stream_members() as members:
            for member, stream in members:
                if stream is not None:
                    attempt(f"pass {member.name}", stream.read)
                seen.append((member.name, member.verified, member.verifiable))
        with open_archive(io.BytesIO(data)) as ar:
            for member in ar.members():
                if member.is_file:
                    attempt(f"read {member.name}", lambda m=member: ar.read(m))
                    attempt(
                        f"chunks {member.name}",
                        lambda m=member: _read_in_chunks(ar, m),
                    )
            diagnostics = ar.diagnostics
            seen.append(sorted((c.value, n) for c, n in diagnostics.counts.items()))
    except Exception as exc:  # noqa: BLE001 - an open that fails is an outcome too
        seen.append(("open", type(exc).__name__, str(exc)))
    return seen


def _read_in_chunks(ar: object, member: object) -> bytes:
    out = bytearray()
    with ar.open(member) as stream:  # type: ignore[attr-defined]
        while chunk := stream.read(37):
            out += chunk
    return bytes(out)


def _general(monkeypatch: pytest.MonkeyPatch, data: bytes) -> list[object]:
    with monkeypatch.context() as m:
        m.setattr(zip_reader, "_SPECULATIVE_MAX", -1)
        return _outcome(data)


def test_the_fast_path_runs_on_small_members(monkeypatch: pytest.MonkeyPatch) -> None:
    taken: list[bool] = []
    real = zip_reader.ZipReader._speculative_small_member

    def spy(self: zip_reader.ZipReader, loc: object, member: object) -> object:
        parts = real(self, loc, member)  # type: ignore[arg-type]
        taken.append(parts is not None)
        return parts

    monkeypatch.setattr(zip_reader.ZipReader, "_speculative_small_member", spy)
    _outcome(_zip_bytes())
    assert any(taken)
    assert not all(taken)  # the 70 KiB member takes the general path


def test_an_intact_archive_reads_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _zip_bytes()
    assert _outcome(data) == _general(monkeypatch, data)


def _damaged_copies() -> list[tuple[str, bytes]]:
    data = _zip_bytes()
    rng = random.Random(9)
    # Every byte of the small members' local headers and payloads, sampled, and a
    # spread over the rest; each flipped, and the file cut at a spread of lengths.
    cut_points = sorted(rng.sample(range(1, len(data)), 25))
    small_end = data.index(b"PK\x03\x04", data.index(b"random") + 6)
    flips = sorted(set(range(0, small_end, 3)) | set(rng.sample(range(len(data)), 60)))
    copies = []
    for offset in flips:
        damaged = bytearray(data)
        damaged[offset] ^= 0x5A
        copies.append((f"flip@{offset}", bytes(damaged)))
    copies.extend((f"cut@{n}", data[:n]) for n in cut_points)
    return copies


@pytest.mark.parametrize(
    ("label", "data"), _damaged_copies(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_a_damaged_archive_fails_the_same(
    monkeypatch: pytest.MonkeyPatch, label: str, data: bytes
) -> None:
    assert _outcome(data) == _general(monkeypatch, data), label


def _deflate_member_zip(body: bytes, decoded: bytes) -> bytes:
    """A one-member ZIP whose deflated payload is ``body``, declared to decode to
    ``decoded`` (its CRC and size): ``body`` can hold more, or less, than one
    deflate stream."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("m", body, compress_type=zipfile.ZIP_STORED)
    data = bytearray(buf.getvalue())
    crc = zlib.crc32(decoded)
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, local + 8, 8)
    struct.pack_into("<I", data, local + 14, crc)
    struct.pack_into("<I", data, local + 22, len(decoded))
    struct.pack_into("<H", data, central + 10, 8)
    struct.pack_into("<I", data, central + 16, crc)
    struct.pack_into("<I", data, central + 24, len(decoded))
    return bytes(data)


def _raw_deflate(data: bytes) -> bytes:
    encoder = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return encoder.compress(data) + encoder.flush()


_TEXT = b"a payload that compresses well, " * 30


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_raw_deflate(_TEXT) + b"junk", id="bytes-after-the-deflate-end"),
        pytest.param(_raw_deflate(_TEXT) + _raw_deflate(b"x"), id="a-second-stream"),
        pytest.param(_raw_deflate(_TEXT)[:-2], id="cut-before-the-end"),
        pytest.param(
            _raw_deflate(_TEXT)[:-1] + bytes([_raw_deflate(_TEXT)[-1] ^ 1]),
            id="last-byte-flipped",
        ),
        pytest.param(b"\xff" * 40, id="not-deflate"),
    ],
)
def test_a_payload_that_is_not_one_deflate_stream_reads_the_same(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    data = _deflate_member_zip(body, _TEXT)
    assert _outcome(data) == _general(monkeypatch, data)


def test_a_declared_size_one_short_reads_the_same(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _deflate_member_zip(_raw_deflate(_TEXT), _TEXT[:-1])
    assert _outcome(data) == _general(monkeypatch, data)
