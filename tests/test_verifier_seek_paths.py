"""Edge paths of the member verifier's seeks, and the frame-watch lookup.

``MemberVerifier.seek`` defers a forward seek over bytes the inner would decode
anyway, and reads that gap through the hashers on the next read (ADR 0014). These
pin where the deferral stops (at the declared end), what a second deferred seek and a
relative seek count from, where a deferred seek past an unknown end leaves the
position, and that a rewind checks the length again. ``find_frame_watch`` is pinned
on hand-built layers.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Callable

import pytest

from archivey.exceptions import CorruptionError
from archivey.internal.streams.verification import find_frame_watch
from archivey.internal.streams.verify import MemberVerifier, VerifyingStream
from archivey.types import ArchiveMember, HashAlgorithm, MemberType

_DATA = bytes(range(256)) * 40  # 10 240 bytes


def _crc(data: bytes) -> bytes:
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")


class _DecodingInner(io.BytesIO):
    """A stream whose every seek restarts from 0, as a decoder with no index does.

    So a forward seek decodes the gap anyway, and the verifier defers it.
    """

    def nearest_resume_offset(self, target: int) -> int | None:
        return 0


def _verifying(
    data: bytes = _DATA,
    *,
    crc: bytes | None = None,
    expected_size: int | None = None,
) -> tuple[VerifyingStream, _DecodingInner]:
    inner = _DecodingInner(data)
    stream = VerifyingStream(
        inner,
        {HashAlgorithm.CRC32: crc if crc is not None else _crc(data)},
        expected_size=expected_size,
    )
    return stream, inner


def test_a_seek_to_the_declared_size_is_passed_on_not_deferred() -> None:
    # The read that concludes reads the gap itself, so the seek reaches the inner
    # at once: the inner sits at the target, not where the last read left it.
    stream, inner = _verifying(expected_size=len(_DATA))
    stream.read(10)
    assert stream.seek(len(_DATA)) == len(_DATA)
    assert inner.tell() == len(_DATA)
    assert stream.read() == b""


def test_a_seek_short_of_the_declared_size_is_deferred() -> None:
    stream, inner = _verifying(expected_size=len(_DATA))
    stream.read(10)
    assert stream.seek(len(_DATA) - 1) == len(_DATA) - 1
    assert inner.tell() == 10
    assert stream.tell() == len(_DATA) - 1
    assert stream.read() == _DATA[-1:]


def test_a_second_deferred_seek_reads_the_gap_from_where_the_inner_was_left() -> None:
    # Both seeks are deferred; the inner never moved, so the gap read starts where
    # the first read left it. Counting it from the first target would hash nothing
    # and leave the stored CRC unchecked.
    bad = _crc(_DATA)[:3] + bytes([_crc(_DATA)[3] ^ 1])
    stream, inner = _verifying(crc=bad)
    stream.read(10)
    stream.seek(1000)
    stream.seek(2000)
    assert inner.tell() == 10
    assert stream._digest_intact() is True
    assert stream.read(16) == _DATA[2000:2016]
    with pytest.raises(CorruptionError, match="Digest mismatch"):
        stream.read()


def test_a_relative_seek_back_while_a_seek_is_deferred_counts_from_the_target() -> None:
    # The inner still sits at 100 (the deferred seek has not moved it), so a
    # SEEK_CUR the verifier passes on must be rebased onto the inner's position.
    stream, inner = _verifying()
    stream.read(100)
    stream.seek(1000)
    assert inner.tell() == 100
    assert stream.seek(-950, io.SEEK_CUR) == 50
    assert inner.tell() == 50
    assert stream.read(10) == _DATA[50:60]
    assert stream.read() == _DATA[60:]


def test_a_deferred_seek_past_an_unknown_end_lands_on_its_target() -> None:
    # With no declared size the seek past the end is deferred too; the gap read
    # finds the end first, and the position still ends on the target.
    stream, _ = _verifying()
    stream.read(10)
    target = len(_DATA) + 50
    assert stream.seek(target) == target
    assert stream.read() == b""
    assert stream.tell() == target


def test_a_rewind_after_an_over_run_checks_the_length_again() -> None:
    # The rewind re-arms the checks: the second pass caps reads at the declared
    # size and refuses the extra byte again, rather than passing it through.
    data = _DATA + b"!"
    inner = _DecodingInner(data)
    verifier = MemberVerifier({}, expected_size=len(_DATA))
    with pytest.raises(CorruptionError, match="exceeds its declared size"):
        verifier.read(inner, len(_DATA))
    assert verifier.seek(inner, 0) == 0
    first = verifier.read(inner, len(_DATA) - 1)
    assert first == _DATA[:-1]
    with pytest.raises(CorruptionError, match="exceeds its declared size"):
        verifier.read(inner, 10)


def test_the_end_check_gets_the_length_a_read_found() -> None:
    member = ArchiveMember(type=MemberType.FILE, name="m")
    seen: list[int] = []
    verifier = MemberVerifier({}, member=member, fill_size=True, end_check=seen.append)
    assert verifier.read(io.BytesIO(_DATA)) == _DATA
    assert seen == [len(_DATA)]
    assert member.size == len(_DATA)


def test_a_read_that_stops_short_of_the_end_does_not_fill_the_size() -> None:
    # A seek past the end concluded the member without seeing where it ends. After a
    # seek back to the read frontier, a bounded read that stops short of the end
    # must not record its position as the end; the read on to the end does.
    member = ArchiveMember(type=MemberType.FILE, name="m")
    inner = io.BytesIO(_DATA)
    verifier = MemberVerifier({}, member=member, fill_size=True)
    verifier.read(inner, 10)
    verifier.seek(inner, len(_DATA) + 100)
    assert verifier.read(inner) == b""
    verifier.seek(inner, 10)
    assert verifier.read(inner, 5) == _DATA[10:15]
    assert member.size is None
    assert verifier.read(inner) == _DATA[15:]
    assert member.size == len(_DATA)


# find_frame_watch


def _watch() -> bool:
    return True


class _Layer:
    """A wrapper layer: an ``_inner``, and optionally what the walk keys on."""

    def __init__(
        self,
        inner: object,
        *,
        proofs: bool = False,
        forwards: object = False,
    ) -> None:
        self._inner = inner
        if proofs:
            self._verification_proofs = lambda: None
        self.forwards_verification = forwards


class _Watching:
    def __init__(self, watch: Callable[[], bool]) -> None:
        self._frames_unchecked_now = watch


class _RawWatching(io.RawIOBase):
    def __init__(self, watch: Callable[[], bool]) -> None:
        super().__init__()
        self._frames_unchecked_now = watch

    def readable(self) -> bool:
        return True


def test_frame_watch_is_found_through_a_read_buffer() -> None:
    buffered = io.BufferedReader(_RawWatching(_watch))
    assert find_frame_watch(buffered) is _watch


@pytest.mark.parametrize(
    ("proofs", "forwards", "found"),
    [
        (True, False, True),
        (False, True, True),
        # Only ``True`` itself forwards: a truthy flag is not the opt-in.
        (False, 1, False),
        (False, False, False),
    ],
)
def test_frame_watch_follows_only_layers_that_pass_proofs(
    proofs: bool, forwards: object, found: bool
) -> None:
    layer = _Layer(_Watching(_watch), proofs=proofs, forwards=forwards)
    assert (find_frame_watch(layer) is _watch) is found


class _PlainLayer:
    """A layer that says nothing about verification: it changes the bytes."""

    def __init__(self, inner: object) -> None:
        self._inner = inner


def test_frame_watch_does_not_pass_a_layer_that_says_nothing() -> None:
    assert find_frame_watch(_PlainLayer(_Watching(_watch))) is None


def test_frame_watch_stops_at_a_layer_with_no_inner() -> None:
    assert find_frame_watch(_Layer(None, forwards=True)) is None
    assert find_frame_watch(object()) is None


def _chain(depth: int) -> object:
    """``depth`` forwarding layers over a watching stream."""
    stream: object = _Watching(_watch)
    for _ in range(depth):
        stream = _Layer(stream, forwards=True)
    return stream


def test_frame_watch_walks_sixty_four_layers_and_no_more() -> None:
    # The bound only stops a cycle: a chain of 64 layers is walked to its end, one
    # of 65 is not.
    assert find_frame_watch(_chain(64)) is _watch
    assert find_frame_watch(_chain(65)) is None


def test_a_verifying_stream_reports_the_proofs_of_the_layer_below() -> None:
    # The outer checks only the length; the digest proof comes from the inner one.
    inner = VerifyingStream(io.BytesIO(_DATA), {HashAlgorithm.CRC32: _crc(_DATA)})
    outer = VerifyingStream(inner, {}, expected_size=len(_DATA))
    assert outer.read() == _DATA
    proofs = outer._verification_proofs()
    assert proofs.ended
    assert proofs.content
    assert proofs.content_possible
