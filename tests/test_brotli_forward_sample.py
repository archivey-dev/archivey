"""The incremental trial must stop at its input cap or its decoder's end."""

from __future__ import annotations

from archivey.internal.streams.codecs.brotli_codec import _ForwardProbeSample


def test_forward_sample_caps_reads_and_replays_buffered_bytes() -> None:
    data = bytes(10_000)
    reads: list[tuple[int, int]] = []

    def available(offset: int, length: int) -> tuple[bytes, bool]:
        assert offset + length <= 5000
        reads.append((offset, length))
        return data[offset : offset + length], False

    with _ForwardProbeSample(available, 5000) as sample:
        assert len(sample.read(6000)) == 4096
        assert len(sample.read()) == 904
        assert sample.read(1) == b""
        assert reads == [(0, 4096), (4096, 904)]
        sample.seek(4000)
        assert len(sample.read(2000)) == 1000
        assert sample.tell() == 5000


def test_a_finished_probe_does_not_fetch_optional_bytes() -> None:
    def available(offset: int, length: int) -> tuple[bytes, bool]:
        raise AssertionError("the finished decoder fetched optional bytes")

    with _ForwardProbeSample(available, 5000) as sample:
        sample.finished = lambda: True
        assert sample.read(1) == b""
