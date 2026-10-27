"""``RespawnStream`` over a member whose length is not known up front (``size=None``).

The known-size behaviour is tested with the RAR reader (``test_rar_reader.py``).
"""

from __future__ import annotations

import io

import pytest

from archivey import TruncatedError
from archivey.internal.streams.respawn import RespawnStream

_PAYLOAD = bytes(range(256)) * 300  # several skip chunks


def _respawn(payloads: list[bytes]) -> tuple[RespawnStream, list[int]]:
    """A stream whose n-th spawn returns ``payloads[n]`` (the last one repeats)."""
    spawns: list[int] = []

    def spawn() -> io.BytesIO:
        spawns.append(1)
        return io.BytesIO(payloads[min(len(spawns) - 1, len(payloads) - 1)])

    return RespawnStream(spawn, spawn(), size=None, what="member data"), spawns


def test_seek_end_reads_through_to_learn_the_size() -> None:
    stream, spawns = _respawn([_PAYLOAD])
    assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
    assert spawns == [1]
    assert stream.read() == b""
    assert stream.seek(-5, io.SEEK_END) == len(_PAYLOAD) - 5
    assert stream.read() == _PAYLOAD[-5:]
    assert len(spawns) == 2  # the backward seek opened it again


def test_seek_end_after_a_partial_read() -> None:
    stream, _ = _respawn([_PAYLOAD])
    assert stream.read(100) == _PAYLOAD[:100]
    assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
    assert stream.tell() == len(_PAYLOAD)
    stream.seek(100)
    assert stream.read(10) == _PAYLOAD[100:110]


def test_forward_seek_past_the_end() -> None:
    stream, spawns = _respawn([_PAYLOAD])
    assert stream.seek(len(_PAYLOAD) + 1000) == len(_PAYLOAD) + 1000
    assert stream.read() == b""
    assert stream.tell() == len(_PAYLOAD) + 1000
    assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
    assert spawns == [1]


def test_forward_seek_within_and_backward_seek() -> None:
    stream, spawns = _respawn([_PAYLOAD])
    stream.seek(70000)
    assert stream.read(4) == _PAYLOAD[70000:70004]
    stream.seek(10)
    assert stream.read(4) == _PAYLOAD[10:14]
    assert len(spawns) == 2
    stream.seek(0)
    assert stream.read() == _PAYLOAD


def test_a_shorter_respawn_after_the_size_is_known_is_truncated() -> None:
    stream, _ = _respawn([_PAYLOAD, _PAYLOAD[:1000]])
    assert stream.read() == _PAYLOAD
    stream.seek(0)
    stream.seek(5000)
    with pytest.raises(TruncatedError, match="member data ended after 1000 of"):
        stream.read(1)
