"""The ``AUTO`` size gate for the bzip2 accelerator,
:data:`~archivey.config.INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`, at its shipped value.

The DEFLATE family's gate has the same tests in ``test_rapidgzip_deflate_zlib.py``.
"""

from __future__ import annotations

import bz2
import functools
import io
import random
from dataclasses import replace
from pathlib import Path

import pytest

from archivey.config import INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, bzip2_codec, open_codec_stream
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from archivey.internal.streams.streamtools.slice import SlicingStream
from tests.conftest import requires

pytestmark = requires("rapidgzip")

_SMALL = b"the quick brown fox jumps over the lazy dog\n" * 50


@functools.cache
def _at_threshold() -> tuple[bytes, bytes]:
    """Random bytes whose bzip2 stream is just past the shipped threshold (random data
    does not compress), and that stream."""
    payload = random.Random(1).randbytes(INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE + 4096)
    compressed = bz2.compress(payload)
    assert len(compressed) >= INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    return payload, compressed


def _uses_child(stream: object) -> bool:
    """Whether the codec stream reads through the rapidgzip child (it sits under the
    takeover and check layers, each holding the next as ``_inner``)."""
    inner = stream
    while inner is not None:
        if isinstance(inner, RapidgzipChildStream):
            return True
        inner = getattr(inner, "_inner", None)
    return False


def _config(mode: AcceleratorMode, compressed: bytes) -> StreamConfig:
    return StreamConfig(
        use_indexed_bzip2=mode,
        seekable=True,
        compressed_input_size=len(compressed),
    )


def test_the_auto_threshold_is_inside_the_child_break_even() -> None:
    """The child costs about 45 ms to start. A full read broke even near 0.6 MiB
    compressed with 4 cores and near 2 MiB with one
    (``scripts/investigations/bench_bzip2_child.py``),
    so the gate sits between the two."""
    assert 600 * 1024 <= INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE <= 2 * 1024 * 1024


@pytest.mark.parametrize("mode", [AcceleratorMode.OFF, AcceleratorMode.AUTO])
def test_off_and_auto_below_the_threshold_use_the_standard_library(
    mode: AcceleratorMode,
) -> None:
    compressed = bz2.compress(_SMALL)
    assert len(compressed) < INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    config = _config(mode, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert not _uses_child(s)
        assert s.read() == _SMALL


def test_on_uses_the_accelerator_below_the_threshold() -> None:
    compressed = bz2.compress(_SMALL)
    assert len(compressed) < INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    config = _config(AcceleratorMode.ON, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert _uses_child(s)
        assert s.read() == _SMALL


def test_auto_uses_the_accelerator_from_the_threshold() -> None:
    payload, compressed = _at_threshold()
    config = _config(AcceleratorMode.AUTO, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert _uses_child(s)
        assert s.read() == payload


def _sequential_config(compressed: bytes) -> StreamConfig:
    """A read with no declared seek demand over a seekable source of known size."""
    return StreamConfig(
        use_indexed_bzip2=AcceleratorMode.AUTO,
        source_seekable=True,
        source_is_file=True,
        compressed_input_size=len(compressed),
    )


def test_auto_takes_a_large_sequential_read_of_a_file_through_the_accelerator(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(bzip2_codec, "_SEQUENTIAL_PLATFORM", True)
    monkeypatch.setattr(bzip2_codec, "_usable_cpus", lambda: 4)
    payload, compressed = _at_threshold()
    path = tmp_path / "a.bz2"
    path.write_bytes(compressed)
    config = replace(_sequential_config(compressed), source_is_file=False)
    with (
        path.open("rb") as f,
        open_codec_stream(Codec.BZIP2, f, config=config) as s,
    ):
        assert _uses_child(s)
        assert s.read() == payload


def test_auto_keeps_a_sequential_read_of_a_callers_stream_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The accelerator reads its bzip2 input about twice; a caller's stream (a remote
    # file above all) would serve it all twice.
    monkeypatch.setattr(bzip2_codec, "_SEQUENTIAL_PLATFORM", True)
    monkeypatch.setattr(bzip2_codec, "_usable_cpus", lambda: 4)
    payload, compressed = _at_threshold()
    config = replace(_sequential_config(compressed), source_is_file=False)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert not _uses_child(s)
        assert s.read() == payload


@pytest.mark.parametrize(
    ("change", "cpus", "platform"),
    [
        pytest.param({}, 1, True, id="one-cpu"),
        pytest.param({}, 4, False, id="unmeasured-platform"),
        pytest.param({"source_seekable": False}, 4, True, id="forward-only-source"),
        pytest.param({"source_is_file": False}, 4, True, id="not-a-file"),
        pytest.param({"compressed_input_size": None}, 4, True, id="unknown-size"),
        pytest.param(
            {"compressed_input_size": INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE - 1},
            4,
            True,
            id="below-the-gate",
        ),
    ],
)
def test_the_sequential_gate_refuses_on_each_condition(
    monkeypatch: pytest.MonkeyPatch, change: dict, cpus: int, platform: bool
) -> None:
    monkeypatch.setattr(bzip2_codec, "_SEQUENTIAL_PLATFORM", platform)
    monkeypatch.setattr(bzip2_codec, "_usable_cpus", lambda: cpus)
    _payload, compressed = _at_threshold()
    config = replace(_sequential_config(compressed), **change)
    assert not bzip2_codec._bzip2_sequential_read_pays(config)
    assert not bzip2_codec._bzip2_wanted(config, available=True)


def test_usable_cpus_is_at_least_one() -> None:
    assert bzip2_codec._usable_cpus() >= 1


@pytest.mark.parametrize(
    ("kind", "is_file"),
    [
        pytest.param("str", True, id="str-path"),
        pytest.param("path", True, id="pathlike"),
        pytest.param("open-file", True, id="open-file"),
        pytest.param("slice", True, id="slice-of-a-file"),
        pytest.param("bytesio", False, id="bytesio"),
    ],
)
def test_prepare_config_marks_a_file_on_disk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str, is_file: bool
) -> None:
    monkeypatch.setattr(bzip2_codec, "_SEQUENTIAL_PLATFORM", True)
    _payload, compressed = _at_threshold()
    path = tmp_path / "a.bz2"
    path.write_bytes(b"x" * 16 + compressed)
    config = replace(_sequential_config(compressed), source_is_file=False)
    codec = bzip2_codec.Bzip2Codec()
    with path.open("rb") as f:
        source: object = {
            "str": str(path),
            "path": path,
            "open-file": f,
            "slice": SlicingStream(f, start=16, length=len(compressed)),
            "bytesio": io.BytesIO(compressed),
        }[kind]
        prepared = codec.prepare_config(source, config)  # type: ignore[arg-type]
    assert prepared.source_is_file is is_file


def test_prepare_config_asks_nothing_when_already_set_or_not_wanted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bzip2_codec, "_SEQUENTIAL_PLATFORM", True)
    _payload, compressed = _at_threshold()
    codec = bzip2_codec.Bzip2Codec()
    already = _sequential_config(compressed)
    assert codec.prepare_config(io.BytesIO(compressed), already) is already
    declared = replace(already, source_is_file=False, seekable=True)
    assert codec.prepare_config("unused.bz2", declared) is declared
