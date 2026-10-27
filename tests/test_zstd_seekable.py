"""Random access in zstd: frame starts as seek points, and the Seekable Zstandard table.

``seekable-decompressor-streams`` §"zstd uses its frames and the seekable format's seek
table". The seek table is read only on declared seek demand, and trusted like the xz and
lzip indexes (threat-model O17).
"""

from __future__ import annotations

import io
import struct
from typing import Any

import pytest

from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    ReadError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.config import StreamConfig
from archivey.internal.streams.child_process import outside_death_error
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.decoder_child import isolation_error
from archivey.internal.streams.codecs.zstd_seek_table import read_seek_table
from archivey.internal.streams.decompressor_stream import DecompressorStream
from tests.conftest import requires_zstd, zstd_backend
from tests.streams_util import (
    CountingBytesIO,
    make_seekable_zstd,
    seekable_zstd_table,
)

pytestmark = requires_zstd()

PARTS = [bytes([65 + i]) * 50_000 + bytes(range(256)) * (i + 1) for i in range(6)]
FULL = b"".join(PARTS)
STARTS = [sum(len(p) for p in PARTS[:i]) for i in range(len(PARTS))]


def _collector() -> tuple[Any, list[Any]]:
    from archivey.internal.diagnostics_collector import DiagnosticCollector

    seen: list[Any] = []
    return DiagnosticCollector(on_diagnostic=seen.append), seen


def _open(source: Any, *, seekable: bool = True, collector: Any = None) -> Any:
    config = StreamConfig(seekable=seekable, collector=collector)
    return open_codec_stream(Codec.ZSTD, source, config=config)


def _engine(stream: Any) -> DecompressorStream:
    """The ``DecompressorStream`` under the ``ArchiveStream`` wrappers."""
    inner = stream
    while not isinstance(inner, DecompressorStream):
        inner = inner._inner
    return inner


def _points(stream: Any) -> list[int]:
    return [p.decompressed_offset for p in _engine(stream)._seek_points]


def _degraded(seen: list[Any]) -> list[Any]:
    return [d for d in seen if d.code is DiagnosticCode.SEEK_INDEX_DEGRADED]


@pytest.mark.parametrize("checksums", [False, True])
def test_seek_table_gives_the_size_and_frame_points_without_decoding(
    checksums: bool,
) -> None:
    data = make_seekable_zstd(PARTS, checksums=checksums)
    source = CountingBytesIO(data)
    with _open(source) as stream:
        assert stream.seek(0, io.SEEK_END) == len(FULL)
        # The footer, the table's header and its entries: nothing decoded.
        assert source.bytes_read < 200
        assert _points(stream) == STARTS
        for pos in (STARTS[4] + 7, 3, STARTS[2], len(FULL) - 1):
            assert stream.seek(pos) == pos
            assert stream.read(300) == FULL[pos : pos + 300]


def test_backward_seek_resumes_at_the_frame_it_lands_in() -> None:
    with _open(io.BytesIO(make_seekable_zstd(PARTS))) as stream:
        stream.seek(STARTS[5] + 10)
        assert stream.read(10) == FULL[STARTS[5] + 10 : STARTS[5] + 20]
        assert _engine(stream).nearest_resume_offset(STARTS[3] + 5) == STARTS[3]
        stream.seek(STARTS[3] + 5)
        assert stream.read(10) == FULL[STARTS[3] + 5 : STARTS[3] + 15]


def test_forward_read_records_frame_starts_without_a_table() -> None:
    zstd = zstd_backend()
    data = b"".join(zstd.compress(p) for p in PARTS)
    with _open(io.BytesIO(data)) as stream:
        assert stream.read() == FULL
        assert _points(stream) == STARTS
        assert stream.seek(STARTS[2] + 1) == STARTS[2] + 1
        assert stream.read(5) == FULL[STARTS[2] + 1 : STARTS[2] + 6]


def test_an_empty_frame_adds_no_point_of_its_own() -> None:
    """An empty frame shares its offset with the next; the table lists both."""
    parts = [PARTS[0], b"", PARTS[1]]
    data = make_seekable_zstd(parts)
    with _open(io.BytesIO(data)) as stream:
        assert stream.seek(0, io.SEEK_END) == STARTS[2]
        stream.seek(0)
        assert stream.read() == FULL[: STARTS[2]]
        assert _points(stream) == [0, STARTS[1]]


def _contradicted(seen: list[Any]) -> Any:
    """The one report that the decode contradicted the index."""
    (report,) = _degraded(seen)
    assert report.context.scan == "decode_check"
    assert report.context.error_type == "SeekIndexContradicted"
    return report


def test_a_seek_into_a_misplaced_frame_drops_the_table_when_the_decode_reaches_it() -> (
    None
):
    """The table puts frame 3 where frame 2 starts; decoding past frame 2 notices.

    The decode began at the table's point for frame 1, so its offsets are the table's
    too: the stream restarts it from the start and the read gets the right bytes.
    """
    data = _lying_table_file()
    collector, seen = _collector()
    with _open(io.BytesIO(data), collector=collector) as stream:
        stream.seek(STARTS[1] + 5)
        assert stream.read() == FULL[STARTS[1] + 5 :]
        _contradicted(seen)
        stream.seek(STARTS[3] + 1)
        assert stream.read(10) == FULL[STARTS[3] + 1 : STARTS[3] + 11]
        assert stream.seek(0, io.SEEK_END) == len(FULL)


def _frame_0_size_lie() -> bytes:
    """The table's compressed sizes are right, but frame 0 claims 100 output bytes."""
    zstd = zstd_backend()
    frames = [zstd.compress(p) for p in PARTS]
    sizes = [(len(f), len(p)) for f, p in zip(frames, PARTS, strict=True)]
    sizes[0] = (sizes[0][0], 100)
    return b"".join(frames) + seekable_zstd_table(sizes)


def test_a_forward_read_that_contradicts_the_table_drops_it() -> None:
    """The table puts frame 1 at 100; a read from the start finds it at ``STARTS[1]``.

    Both points have frame 1's compressed offset. The table's one is dropped with the
    rest of the table, so a later seek to 150 resumes from the start, not from frame 1.
    """
    collector, seen = _collector()
    with _open(io.BytesIO(_frame_0_size_lie()), collector=collector) as stream:
        stream.seek(50)  # reads the table
        assert stream.read(10) == FULL[50:60]
        stream.read(STARTS[1] + 10_000)  # decodes past frame 1's start
        report = _contradicted(seen)
        assert report.context.codec == "zstd"
        assert _points(stream) == [0, STARTS[1]]
        stream.seek(150)
        assert stream.read(10) == FULL[150:160]
        assert stream.seek(0, io.SEEK_END) == len(FULL)
        stream.seek(STARTS[4])
        assert stream.read(10) == FULL[STARTS[4] : STARTS[4] + 10]
    assert len(_degraded(seen)) == 1


def test_a_lie_about_the_last_frame_is_caught_by_the_decoded_size() -> None:
    """No frame follows the last, so only the total can contradict the table."""
    zstd = zstd_backend()
    frames = [zstd.compress(p) for p in PARTS]
    sizes = [(len(f), len(p)) for f, p in zip(frames, PARTS, strict=True)]
    sizes[-1] = (sizes[-1][0], 100)
    data = b"".join(frames) + seekable_zstd_table(sizes)
    collector, seen = _collector()
    with _open(io.BytesIO(data), collector=collector) as stream:
        assert stream.seek(0, io.SEEK_END) == STARTS[-1] + 100
        stream.seek(0)
        assert stream.read() == FULL
        report = _contradicted(seen)
        assert "output size" in report.message
        assert stream.seek(0, io.SEEK_END) == len(FULL)
        stream.seek(STARTS[-1] + 200)
        assert stream.read(10) == FULL[STARTS[-1] + 200 : STARTS[-1] + 210]


def test_a_size_from_a_contradicted_table_is_forgotten() -> None:
    collector, seen = _collector()
    with _open(io.BytesIO(_frame_0_size_lie()), collector=collector) as stream:
        lie = len(FULL) - len(PARTS[0]) + 100
        assert stream.seek(0, io.SEEK_END) == lie
        stream.seek(0)
        stream.read(STARTS[1] + 10)
        _contradicted(seen)
        assert _engine(stream).try_get_size() is None
        assert stream.seek(0, io.SEEK_END) == len(FULL)
        assert _engine(stream).try_get_size() == len(FULL)


def test_a_contradiction_under_strict_raises_after_the_read_and_reading_goes_on() -> (
    None
):
    from archivey import DiagnosticPolicy
    from archivey.exceptions import DiagnosticRaisedError
    from archivey.internal.diagnostics_collector import DiagnosticCollector

    collector = DiagnosticCollector(policy=DiagnosticPolicy.STRICT)
    with _open(io.BytesIO(_lying_table_file()), collector=collector) as stream:
        stream.seek(STARTS[1] + 5)
        pieces: list[bytes] = []
        raises = 0
        while True:
            try:
                chunk = stream.read(30_000)
            except DiagnosticRaisedError:
                raises += 1
                continue
            if not chunk:
                break
            pieces.append(chunk)
        assert raises == 1
        assert b"".join(pieces) == FULL[STARTS[1] + 5 :]


def test_skippable_frames_before_a_frame_add_no_point_of_their_own() -> None:
    """pzstd writes a skippable frame before each frame; the point is at the frame.

    The first one moves the origin past the leading skippable frame, which holds no
    output.
    """
    zstd = zstd_backend()
    frames = [zstd.compress(p) for p in PARTS[:3]]
    skippable = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"\x01\x02\x03\x04"
    data = b"".join(skippable + f for f in frames)
    with _open(io.BytesIO(data)) as stream:
        assert stream.read() == b"".join(PARTS[:3])
        points = [
            (p.decompressed_offset, p.compressed_offset)
            for p in _engine(stream)._seek_points
        ]
    frame_starts = [
        len(skippable) + sum(len(skippable) + len(f) for f in frames[:i])
        for i in range(3)
    ]
    assert points == list(zip([0, *STARTS[1:3]], frame_starts, strict=True))


def test_undeclared_stream_reads_no_table_and_keeps_no_points() -> None:
    with _open(io.BytesIO(make_seekable_zstd(PARTS)), seekable=False) as stream:
        assert stream.seek(STARTS[3]) == STARTS[3]
        assert stream.read(5) == FULL[STARTS[3] : STARTS[3] + 5]
        assert stream.read() == FULL[STARTS[3] + 5 :]
        assert _points(stream) == [0]


@pytest.mark.parametrize(
    ("table", "reason"),
    [
        (seekable_zstd_table([(10, 10)], descriptor=0x04), "reserved bits"),
        (seekable_zstd_table([(10**6, 10)]), "frames end at offset"),
        (struct.pack("<IBI", 10**8, 0, 0x8F92EAB1), "more than the file can hold"),
        (seekable_zstd_table([(0, 10)] * 3), "a frame of 0 bytes"),
    ],
)
def test_a_table_that_does_not_fit_the_file_degrades_to_sequential(
    table: bytes, reason: str
) -> None:
    zstd = zstd_backend()
    data = b"".join(zstd.compress(p) for p in PARTS) + table
    collector, seen = _collector()
    with _open(io.BytesIO(data), collector=collector) as stream:
        assert stream.seek(0, io.SEEK_END) == len(FULL)
        (report,) = _degraded(seen)
        assert report.context.codec == "zstd"
        assert report.context.scan == "zstd_seek_table"
        assert reason in report.message
        stream.seek(STARTS[1])
        assert stream.read(10) == FULL[STARTS[1] : STARTS[1] + 10]


def test_trailing_zeros_hide_the_table_and_the_file_still_reads() -> None:
    data = make_seekable_zstd(PARTS) + b"\x00" * 16
    collector, seen = _collector()
    with _open(io.BytesIO(data), collector=collector) as stream:
        assert stream.seek(STARTS[4]) == STARTS[4]
        assert stream.read(10) == FULL[STARTS[4] : STARTS[4] + 10]
        assert not _degraded(seen)


def _lying_table_file() -> bytes:
    """The table says frame 1 is frames 1 and 2, with frame 1's output size."""
    zstd = zstd_backend()
    frames = [zstd.compress(p) for p in PARTS]
    sizes = [(len(f), len(p)) for f, p in zip(frames, PARTS, strict=True)]
    lying = [sizes[0], (sizes[1][0] + sizes[2][0], len(PARTS[1])), *sizes[3:]]
    return b"".join(frames) + seekable_zstd_table(lying)


def test_cold_seek_trusts_a_self_consistent_table() -> None:
    """Pins threat-model O17 for zstd.

    The compressed sizes still add up, so the table is accepted. A seek past the lie,
    with no forward read before it, serves frame 3's bytes at the table's offset. A
    plain read never consults the table and reads the file right.
    """
    data = _lying_table_file()
    with _open(io.BytesIO(data)) as stream:
        assert stream.read() == FULL
    told = STARTS[2]  # where the table puts frame 3
    with _open(io.BytesIO(data)) as stream:
        assert stream.seek(told) == told
        assert stream.read(10) == PARTS[3][:10]


def test_seek_table_over_the_cap_is_thinned_and_keeps_the_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.streams import decompressor_stream

    monkeypatch.setattr(decompressor_stream, "MAX_SEEK_POINTS", 4)
    parts = [bytes([i]) * (1000 + i) for i in range(20)]
    data = make_seekable_zstd(parts)
    thinned: list[bool] = []
    frames = read_seek_table(
        io.BytesIO(data), len(data), on_thinned=lambda: thinned.append(True)
    )
    assert thinned == [True]
    assert len(frames) <= 5
    assert frames[-1].decompressed_end == sum(len(p) for p in parts)
    full = b"".join(parts)
    collector, seen = _collector()
    with _open(io.BytesIO(data), collector=collector) as stream:
        assert stream.seek(0, io.SEEK_END) == len(full)
        assert _degraded(seen)[-1].context.error_type == "SeekTableThinned"
        for pos in (5, len(full) // 3, len(full) - 3):
            stream.seek(pos)
            assert stream.read(1500) == full[pos : pos + 1500]


def test_a_file_too_short_for_a_table_has_none() -> None:
    assert read_seek_table(io.BytesIO(b"\x00" * 10), 10) == []


def _mid_frame_point_file() -> bytes:
    """Six frames whose table moves frame 2's start 10 bytes into frame 1.

    The compressed sizes still add up to the frames' length, so the table is accepted,
    and a seek into frame 2 resumes decoding at bytes that start no frame.
    """
    zstd = zstd_backend()
    frames = [zstd.compress(p) for p in PARTS]
    sizes = [(len(f), len(p)) for f, p in zip(frames, PARTS, strict=True)]
    sizes[1] = (sizes[1][0] - 10, sizes[1][1])
    sizes[2] = (sizes[2][0] + 10, sizes[2][1])
    return b"".join(frames) + seekable_zstd_table(sizes)


def test_a_point_where_the_decode_fails_drops_the_table() -> None:
    """A decode that fails at a table point contradicts the table, as two points that
    disagree do (``seekable-decompressor-streams``: the index is only an accelerator).

    The stream drops the table with ``SEEK_INDEX_DEGRADED``, decodes from the start,
    and the seek gets the right bytes rather than a ``CorruptionError``.
    """
    collector, seen = _collector()
    with _open(io.BytesIO(_mid_frame_point_file()), collector=collector) as stream:
        assert stream.seek(STARTS[2] + 5) == STARTS[2] + 5
        assert stream.read(10) == FULL[STARTS[2] + 5 : STARTS[2] + 15]
        _contradicted(seen)
        assert stream.seek(STARTS[4] + 1) == STARTS[4] + 1
        assert stream.read() == FULL[STARTS[4] + 1 :]
        assert stream.seek(0, io.SEEK_END) == len(FULL)


def test_a_point_where_the_decode_fails_reads_whole_after_the_drop() -> None:
    collector, seen = _collector()
    with _open(io.BytesIO(_mid_frame_point_file()), collector=collector) as stream:
        stream.seek(STARTS[2])
        assert stream.read() == FULL[STARTS[2] :]
        _contradicted(seen)


def _fail_once_after_a_resume(
    monkeypatch: pytest.MonkeyPatch, engine: DecompressorStream, exc: Exception
) -> None:
    """Make the first decode after the next resume at a seek point raise ``exc``."""
    reset = engine._reset_to_seek_point
    armed = [True]

    def reset_then_fail(point: Any) -> None:
        reset(point)
        if not armed[0]:
            return
        armed[0] = False

        def feed(*args: Any, **kwargs: Any) -> Any:
            raise exc

        monkeypatch.setattr(engine._decoder, "feed", feed)

    monkeypatch.setattr(engine, "_reset_to_seek_point", reset_then_fail)


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(OSError("the source went away"), id="source"),
        pytest.param(MemoryError("no memory"), id="memory"),
        pytest.param(outside_death_error(-9, "the child ended"), id="sigkill"),
        pytest.param(outside_death_error(-15, "the child ended"), id="sigterm"),
        pytest.param(isolation_error("no child can start"), id="no-child"),
        pytest.param(ReadError("the read failed"), id="read-error"),
    ],
)
def test_an_error_that_is_no_verdict_on_the_data_keeps_the_table(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    """An error from the first decode after a resume at a table point that says nothing
    about the data (the source, memory, a decoder child ended from outside or never
    started, a read that failed) says nothing about the table either: it propagates,
    and nothing is reported or dropped."""
    collector, seen = _collector()
    data = make_seekable_zstd(PARTS)
    with _open(io.BytesIO(data), collector=collector) as stream:
        stream.seek(0, io.SEEK_END)
        engine = _engine(stream)
        _fail_once_after_a_resume(monkeypatch, engine, exc)
        with pytest.raises(type(exc)) as raised:
            stream.seek(STARTS[3] + 5)
            stream.read(10)
        assert raised.value is exc
        points = [p.decompressed_offset for p in engine._seek_points]
    assert _degraded(seen) == []
    assert points == STARTS


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(CorruptionError("Not a valid frame"), id="corruption"),
        pytest.param(
            ResourceLimitError("Decoder limit reached: the frame declares a window"),
            id="declared-limit",
        ),
        pytest.param(UnsupportedFeatureError("a window too large"), id="unsupported"),
        pytest.param(ValueError("an unknown backend error"), id="unknown"),
    ],
)
def test_a_verdict_on_the_data_at_a_table_point_drops_the_table(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    """A verdict on the bytes at a table point drops the table and decodes from the
    start. A ``DecoderLimits`` refusal there is one: the size it refuses is what the
    bytes the table pointed at declare. An exception the stream does not know counts
    too, on purpose (``_is_data_verdict``). The report does not claim the table is
    wrong, since the data may be damaged instead."""
    collector, seen = _collector()
    data = make_seekable_zstd(PARTS)
    with _open(io.BytesIO(data), collector=collector) as stream:
        stream.seek(0, io.SEEK_END)
        _fail_once_after_a_resume(monkeypatch, _engine(stream), exc)
        stream.seek(STARTS[3] + 5)
        assert stream.read(10) == FULL[STARTS[3] + 5 : STARTS[3] + 15]
    report = _contradicted(seen)
    assert report.message.startswith(
        "The zstd seek table may not match the data. Decoding from its point at "
    )
    assert "the index is wrong there or the data is damaged" in report.message
