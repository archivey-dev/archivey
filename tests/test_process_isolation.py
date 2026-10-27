"""``ArchiveyConfig.process_isolation``: every value decodes the same bytes.

Each fixture is read under the default (``KNOWN_CRASHES``), ``NATIVE_DECODERS`` (every
native decoder in a child process) and ``NONE`` (everything in this process), and the
member contents must match byte for byte. The corpus covers the stream formats and the
containers; archives written by the ``7z`` binary add the codecs the corpus builders
cannot write (Deflate64, PPMd, BCJ filters).
"""

from __future__ import annotations

import gzip
import io
import random
import warnings
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from archivey.config import (
    AcceleratorMode,
    ArchiveyConfig,
    DecoderLimits,
    ProcessIsolation,
)
from archivey.exceptions import ArchiveyUsageError
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs import decoder_child, deps
from archivey.internal.streams.codecs.bzip2_codec import _bzip2_wanted
from archivey.internal.streams.codecs.decoder_child import POOL
from archivey.internal.streams.codecs.deflate_resume import stream_end
from archivey.internal.streams.codecs.gzip_codec import (
    _gzip_header_refused,
    _gzip_member_at,
)
from archivey.internal.streams.codecs.isolated import ISOLATED
from archivey.internal.streams.codecs.rapidgzip_select import _rapidgzip_wanted
from tests.conftest import importorskip, requires_binary, run_7z
from tests.sample_archives import CORPUS, corpus_archive_path, skip_unless_runnable
from tests.streams_util import make_multi_member_lzip, make_multi_stream_xz

_ENTRIES = {"basic", "zip-compression-methods", "large", "compressed", "single-file"}
_PARAMS = [
    pytest.param(entry, key, id=f"{entry.id}-{key}")
    for entry in CORPUS
    if entry.id in _ENTRIES
    for key in entry.formats
    if key != "dir"
]
_PAYLOAD = (b"process-isolation payload\n" * 4000) + bytes(range(256)) * 64


@pytest.fixture(autouse=True)
def _empty_pool():
    POOL.close_idle()
    yield
    POOL.close_idle()


def _contents(
    path: Path,
    isolation: ProcessIsolation,
    decoder_limits: DecoderLimits | None = None,
) -> dict[str, bytes]:
    config = ArchiveyConfig(
        process_isolation=isolation, decoder_limits=decoder_limits or DecoderLimits()
    )
    with open_archive(path, config=config) as ar:
        return {m.name: ar.read(m) for m in ar.members() if m.type is MemberType.FILE}


def _assert_same_under_every_value(path: Path) -> None:
    expected = _contents(path, ProcessIsolation.KNOWN_CRASHES)
    assert expected
    for isolation in (ProcessIsolation.NATIVE_DECODERS, ProcessIsolation.NONE):
        assert _contents(path, isolation) == expected, isolation


@pytest.mark.parametrize(("entry", "key"), _PARAMS)
def test_corpus_reads_the_same_under_every_value(entry, key, tmp_path: Path) -> None:
    skip_unless_runnable(entry, key)
    _assert_same_under_every_value(corpus_archive_path(entry, key, tmp_path))


def _7z_write(tmp_path: Path, archive_type: str, switches: list[str]) -> Path:
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    (tmp_path / "second.txt").write_bytes(b"second member\n" * 500)
    archive = tmp_path / f"out.{archive_type}"
    result = run_7z(
        ["a", f"-t{archive_type}", *switches, str(archive), src.name]
        + ["second.txt", "-y"],
        cwd=tmp_path,
        text=True,
    )
    if result.returncode != 0 or not archive.is_file():
        pytest.skip(f"7z cannot write {archive_type} {switches}: {result.stderr}")
    return archive


@requires_binary("7z")
@pytest.mark.parametrize(
    ("archive_type", "switches"),
    [
        ("zip", ["-mm=Deflate64"]),
        ("zip", ["-mm=PPMd"]),
        ("zip", ["-mm=BZip2"]),
        ("zip", ["-mm=LZMA"]),
        ("7z", ["-m0=PPMd"]),
        ("7z", ["-m0=Deflate64"]),
        ("7z", ["-m0=BZip2"]),
        ("7z", ["-m0=LZMA"]),
        ("7z", ["-m0=BCJ", "-m1=LZMA2"]),
        ("7z", ["-m0=Delta:4", "-m1=LZMA2", "-ms=off"]),
    ],
    ids=lambda v: v if isinstance(v, str) else "_".join(v),
)
def test_7z_written_archives_read_the_same_under_every_value(
    tmp_path: Path, archive_type: str, switches: list[str]
) -> None:
    if "Deflate64" in str(switches):
        importorskip("inflate64")
    if "PPMd" in str(switches):
        importorskip("pyppmd")
    _assert_same_under_every_value(_7z_write(tmp_path, archive_type, switches))


def test_none_with_rapidgzip_on_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="rapidgzip runs only in a child"):
        ArchiveyConfig(
            process_isolation=ProcessIsolation.NONE,
            use_rapidgzip=AcceleratorMode.ON,
        )


@pytest.mark.parametrize("which", ["gzip", "bzip2"])
def test_none_never_picks_rapidgzip_under_auto(which: str) -> None:
    """A stream past the ``AUTO`` size gate, with its size known, would use rapidgzip
    under the default; under ``NONE`` it uses the standard library, and no warning
    says so (``NONE`` is the caller's choice, not a fallback)."""
    big = 1 << 40
    base = StreamConfig(
        seekable=True,
        compressed_input_size=big,
        expected_decompressed_size=big,
    )
    none = replace(base, process_isolation=ProcessIsolation.NONE)
    wanted = _rapidgzip_wanted if which == "gzip" else _bzip2_wanted
    assert wanted(base, available=True)
    assert not wanted(none, available=True)


def test_gzip_under_none_reads_with_no_warning(tmp_path: Path) -> None:
    path = tmp_path / "data.bin.gz"
    path.write_bytes(gzip.compress(_PAYLOAD))
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NONE)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with open_archive(path, config=config) as ar:
            (member,) = ar.members()
            assert ar.read(member) == _PAYLOAD


@requires_binary("7z")
@pytest.mark.parametrize("feed", ["whole", "pieces"])
def test_a_ppmd_member_pyppmd_stopped_short_of_in_pieces_reads_under_every_value(
    tmp_path: Path, feed: str
) -> None:
    """Fed to pyppmd in pieces, this valid member used to stop at a false end about
    28 KiB short (pyppmd 1.3.1: a resumed worker counted its earlier output against
    the new request; ``PpmdDecoder._native_decode``). Under the limit every setting
    hands it over whole, and with a 1 MiB limit it is fed in pieces, in the child or
    in this process; it reads in full either way."""
    limits = None if feed == "whole" else DecoderLimits(max_ppmd_held_input=2**20)
    importorskip("pyppmd")
    block = random.Random(8).randbytes(1 << 20)
    (tmp_path / "repeats.bin").write_bytes(block * 8)
    archive = tmp_path / "repeats.7z"
    result = run_7z(
        ["a", "-t7z", "-m0=PPMd", str(archive), "repeats.bin"], cwd=tmp_path
    )
    if result.returncode != 0:
        pytest.skip("7z cannot write PPMd")
    # In pieces, NATIVE_DECODERS takes the KNOWN_CRASHES path for PPMd: a child.
    values = (
        list(ProcessIsolation)
        if feed == "whole"
        else [
            ProcessIsolation.KNOWN_CRASHES,
            ProcessIsolation.NONE,
        ]
    )
    for isolation in values:
        got = _contents(archive, isolation, limits)
        assert got == {"repeats.bin": block * 8}, isolation


_SINGLE_FILE = [
    pytest.param(entry, key, id=key)
    for entry in CORPUS
    if entry.id == "single-file"
    for key in entry.formats
]


@pytest.mark.parametrize(("entry", "key"), _SINGLE_FILE)
def test_closing_a_member_stream_gives_its_child_back_at_once(
    entry, key, tmp_path: Path
) -> None:
    """``close`` hands the child back while the stream object is still referenced,
    for every stream codec: a decoder that keeps its native object where
    ``release_decoder_children`` does not look fails here, rather than waiting for
    the garbage collector without a sound."""
    skip_unless_runnable(entry, key)
    path = corpus_archive_path(entry, key, tmp_path)
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with open_archive(path, config=config) as ar:
        (member,) = (m for m in ar.members() if m.type is MemberType.FILE)
        stream = ar.open(member)
        stream.read(10)
        POOL.close_idle()
        stream.close()
        assert POOL.idle_count() == 1, key
        del stream


def _keep_every_child(
    monkeypatch: pytest.MonkeyPatch,
) -> list[decoder_child.DecoderChild]:
    """Every ``DecoderChild`` built from now on, kept referenced as PyPy keeps a
    dropped one until a collection."""
    made: list[decoder_child.DecoderChild] = []
    init = decoder_child.DecoderChild.__init__

    def keep(self: decoder_child.DecoderChild, *args: object, **kwargs: object) -> None:
        made.append(self)
        init(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(decoder_child.DecoderChild, "__init__", keep)
    return made


def _leased(made: list[decoder_child.DecoderChild]) -> list[decoder_child.DecoderChild]:
    return [child for child in made if child._lease.process is not None]


def _two_parts(fmt: str) -> bytes:
    first, second = _PAYLOAD[:40_000], _PAYLOAD[40_000:]
    if fmt == "xz":
        return make_multi_stream_xz([first, second])
    if fmt == "lz":
        return make_multi_member_lzip([first, second])
    if fmt == "gz":
        return gzip.compress(first) + gzip.compress(second)
    if fmt == "lz4":
        importorskip("lz4")
        import lz4.frame

        return lz4.frame.compress(first) + lz4.frame.compress(second)
    zstd = deps.zstd
    if zstd is None:
        pytest.skip("no zstd module")
    return zstd.compress(first) + zstd.compress(second)


@pytest.mark.parametrize("fmt", ["xz", "lz", "gz", "zst", "lz4"])
def test_a_finished_stream_gives_its_child_back_before_the_next_starts(
    fmt: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decoder dropped part-way (a finished xz stream, lzip or gzip member, zstd or
    lz4 frame, and the detection probe's block decoder) gives its child back then, not
    when the garbage collector frees it: CPython frees it at once, PyPy only at a
    later collection. Each decoder is kept referenced here, as PyPy keeps it, so at
    most the one decoding now still holds a child."""
    path = tmp_path / f"two.{fmt}"
    path.write_bytes(_two_parts(fmt))
    made = _keep_every_child(monkeypatch)
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with open_archive(path, config=config) as ar:
        (member,) = (m for m in ar.members() if m.type is MemberType.FILE)
        with ar.open(member) as stream:
            assert stream.read() == _PAYLOAD
            assert len(made) >= 2, fmt
            assert len(_leased(made)) <= 1, fmt


def test_probe_decoders_give_their_children_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gzip header and member probes and the raw DEFLATE end check each build a
    decoder for one decision; each gives its child back when it returns."""
    made = _keep_every_child(monkeypatch)
    member = gzip.compress(_PAYLOAD)
    data = member + member
    assert not _gzip_header_refused(io.BytesIO(data), ISOLATED)
    assert _gzip_member_at(io.BytesIO(data), len(member), 1 << 20, ISOLATED)[0]
    assert _gzip_member_at(io.BytesIO(data), 1, 1 << 20, ISOLATED)[0] is None
    raw = zlib.compressobj(wbits=-15)
    deflated = raw.compress(_PAYLOAD) + raw.flush()
    assert stream_end(io.BytesIO(deflated), None, 1 << 30, natives=ISOLATED) == (
        len(_PAYLOAD),
        False,
    )
    assert len(made) == 4
    assert not _leased(made)


def test_a_zisofs_block_decoder_gives_its_child_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each zisofs block gets a decoder of its own, used once and dropped; each gives
    its child back when the block is read."""
    pytest.importorskip("pycdlib")
    from tests.test_iso import _ZISOFS_PLAIN, _zisofs_image

    made = _keep_every_child(monkeypatch)
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with open_archive(io.BytesIO(_zisofs_image(_ZISOFS_PLAIN)), config=config) as ar:
        assert ar.read("zzz") == _ZISOFS_PLAIN
        assert made
        assert not _leased(made)
