"""Nested archives: an archive read from a member stream of another archive.

Each case builds a chain of formats (outermost first), opens the outer archive from a
file, opens the next level from the member stream the outer level returns, and so on
down to a leaf whose member contents are checked byte for byte. This stresses the
paths a flat archive never reaches: a decoder whose source is another decoder's
output, the accelerator child processes reading their input through the parent from
another child, and readers whose source a different reader owns.

Every level is opened with the same accelerator mode and seek flag. A level whose
source cannot seek (a ``stream_members()`` stream, or a member of a reader opened
without ``seekable_members``) is opened ``streaming=True`` for a container, and
without seek demand, as a caller would. The one outcome other than a full read that a
case accepts is ``StreamNotSeekableError`` from a level whose source is forward-only:
7z, RAR and ISO need to seek, and so does an accelerator set to ``ON``. A forward-only
ZIP opens under ``ON`` and refuses at its first DEFLATE member, which every ZIP level
here has.

Tiers:

- The default run covers every ordered pair of formats with accelerators OFF; with
  them ON, every pair where a level is one they decode, both through ``open()`` and
  with the inner level forward-only; a few three-level chains; and the targeted cases
  at the end of the module.
- ``ARCHIVEY_NESTED_FULL=1`` adds the whole matrix: every pair and a three-level set,
  each with accelerators OFF, AUTO and ON, ``seekable_members`` True and False, and
  both ``open()`` and ``stream_members()``. It takes a few minutes.

Archives are built on demand into the corpus cache. RAR needs the RARLAB ``rar``
writer, which CI does not install, so the RAR levels come from committed fixtures
under ``tests/fixtures/nested/`` when it is absent (regenerate them with
``uv run python -m tests.test_nested_archives --write-rar-fixtures``).
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import itertools
import os
import random
import shutil
import sys
import tarfile
import tempfile
import threading
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

import pytest

import archivey
from archivey import (
    AcceleratorMode,
    ArchiveReader,
    ArchiveStream,
    ArchiveyConfig,
    DecoderLimits,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    StreamNotSeekableError,
)
from archivey.types import StreamFormat
from tests.conftest import ARCHIVEY_TEST_CACHE, has_binary, importorskip
from tests.sample_archives import (
    GENERATOR_VERSION,
    CorpusEntry,
    F,
    build_archive,
    publish_cached,
    skip_unless_runnable,
)

CONTAINERS = (
    "zip",
    "tar",
    "tar.gz",
    "tar.bz2",
    "tar.xz",
    "tar.zst",
    "tar.lz4",
    "tar.lz",
    "tar.zz",
    "tar.br",
    "7z",
    "rar",
    "iso",
)
STREAMS = ("gz", "bz2", "xz", "zst", "lz4", "lz", "zz", "br")
FORMATS = CONTAINERS + STREAMS

# Formats that cannot be read at all from a forward-only source.
_NEEDS_SEEK = frozenset({"7z", "rar", "iso"})

# Small, but past the 8 KiB and 64 KiB buffer and chunk sizes the stream layers use.
LEAF = (
    F("hello.txt", b"hello nested world\n" * 50),
    F("data/random.bin", random.Random(7).randbytes(4096)),
    F("data/zeros.bin", b"\0" * 70000),
)
SINGLE_LEAF = (F("payload.bin", random.Random(9).randbytes(3000) + b"x" * 70000),)

FULL = os.environ.get("ARCHIVEY_NESTED_FULL") == "1"
_HAS_RAPIDGZIP = importlib.util.find_spec("rapidgzip") is not None

RAR_FIXTURES = Path(__file__).parent / "fixtures" / "nested"
# RAR chains committed for CI, which has no RAR writer: the leaf, an outer RAR over
# every format, and the RAR-outermost triple. The chain tables they serve come below.
_RAR_FIXTURE_INNERS = (
    "zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz4", "tar.lz",
    "tar.zz", "tar.br", "7z", "rar", "iso", "gz", "bz2", "xz", "zst", "lz4", "lz",
    "zz", "br",
)  # fmt: skip
RAR_FIXTURE_CHAINS = (
    ("rar",),
    *(("rar", inner) for inner in _RAR_FIXTURE_INNERS),
    ("rar", "7z", "zip"),
)


# ---------------------------------------------------------------------------
# Building the chains
# ---------------------------------------------------------------------------


def _leaf_members(fmt: str) -> tuple:
    return SINGLE_LEAF if fmt in STREAMS else LEAF


def _level_members(chain: tuple[str, ...], data: bytes) -> tuple:
    """The members of ``chain[0]`` when it holds ``data``, the archive of ``chain[1]``."""
    name = f"inner.{chain[1]}"
    if chain[0] in STREAMS:
        return (F(name, data),)
    return (F("readme.txt", b"outer level\n"), F(name, data))


def _build(fmt: str, members: tuple) -> bytes:
    digest = hashlib.sha256(f"v{GENERATOR_VERSION}|{fmt}".encode())
    for m in members:
        digest.update(m.name.encode() + b"\0" + hashlib.sha256(m.contents).digest())
    cache = Path(ARCHIVEY_TEST_CACHE) / "nested"
    cache.mkdir(parents=True, exist_ok=True)
    final = cache / f"{digest.hexdigest()[:24]}.{fmt}"
    if not final.exists():
        fd, tmp_name = tempfile.mkstemp(dir=cache, prefix=".building-")
        os.close(fd)
        tmp = Path(tmp_name)
        tmp.unlink()  # builders create the file themselves
        try:
            build_archive(
                CorpusEntry(id="nested", members=members, formats=(fmt,)), fmt, tmp
            )
            publish_cached(tmp, final)
        finally:
            tmp.unlink(missing_ok=True)
    return final.read_bytes()


def _rar_fixture(chain: tuple[str, ...]) -> Path:
    return RAR_FIXTURES / ("-".join(chain) + ".rar")


def _chain_bytes(chain: tuple[str, ...]) -> bytes:
    """The outermost archive of ``chain``, built from the leaf up."""
    if "rar" in chain and shutil.which("rar") is None:
        # From the outermost RAR level down, the bytes are committed; the levels
        # outside it hold no RAR and are built here as usual.
        idx = chain.index("rar")
        fixture = _rar_fixture(chain[idx:])
        if not fixture.exists():
            pytest.skip(f"no RAR writer and no committed fixture {fixture.name}")
        data = fixture.read_bytes()
        top = idx
    else:
        data = _build(chain[-1], _leaf_members(chain[-1]))
        top = len(chain) - 1
    for i in reversed(range(top)):
        data = _build(chain[i], _level_members(chain[i:], data))
    return data


def _skip_unless_runnable(chain: tuple[str, ...]) -> None:
    entry = CorpusEntry(id="nested", members=LEAF, formats=())
    for fmt in set(chain):
        if fmt == "rar":
            # The writer is replaced by committed fixtures (see _chain_bytes); the
            # reader still needs unrar or unar for member data.
            if not has_binary("unrar") and not has_binary("unar"):
                pytest.skip("reading RAR member data needs unrar or unar")
            continue
        skip_unless_runnable(entry, fmt)


# ---------------------------------------------------------------------------
# Walking a chain
# ---------------------------------------------------------------------------


def _config(mode: str, decoder_limits: DecoderLimits | None = None) -> ArchiveyConfig:
    m = AcceleratorMode(mode)
    return ArchiveyConfig(
        use_rapidgzip=m,
        use_indexed_bzip2=m,
        decoder_limits=decoder_limits or DecoderLimits(),
    )


def _check_stream(stream: BinaryIO, expected: bytes, *, seek: bool) -> None:
    assert stream.read() == expected
    if seek and stream.seekable():
        rng = random.Random(len(expected))
        for _ in range(4):
            offset = rng.randrange(len(expected))
            stream.seek(offset)
            assert stream.read(3000) == expected[offset : offset + 3000]


# Levels an accelerator set to ON decodes, by the config field that selects it.
_RAPIDGZIP_FORMATS = frozenset({"gz", "zz", "tar.gz", "tar.zz"})
_BZIP2_FORMATS = frozenset({"bz2", "tar.bz2"})


def _must_refuse_forward_only(fmt: str, config: ArchiveyConfig) -> bool:
    """Whether a level of ``fmt`` must raise ``StreamNotSeekableError`` when its source
    cannot seek: the format needs to seek, or an accelerator set to ON decodes it."""
    if fmt in _NEEDS_SEEK:
        return True
    if fmt in _RAPIDGZIP_FORMATS:
        return config.use_rapidgzip is AcceleratorMode.ON
    if fmt in _BZIP2_FORMATS:
        return config.use_indexed_bzip2 is AcceleratorMode.ON
    return False


def _open_level(
    source: Path | BinaryIO,
    fmt: str,
    *,
    seek: bool,
    streaming: bool,
    config: ArchiveyConfig,
) -> ArchiveStream | ArchiveReader:
    if fmt in STREAMS:
        return archivey.open_stream(
            source, format=StreamFormat(fmt), seekable=seek, config=config
        )
    return archivey.open_archive(
        source, seekable_members=seek, streaming=streaming, config=config
    )


def _walk(
    source: Path | BinaryIO,
    chain: tuple[str, ...],
    *,
    seekable: bool,
    config: ArchiveyConfig,
    access: str,
) -> None:
    fmt = chain[0]
    forward_only = not isinstance(source, Path) and not source.seekable()
    # Seek demand on a forward-only source is refused outright by open_stream; a
    # caller asks for what the source can give.
    seek = seekable and not forward_only
    if forward_only and _must_refuse_forward_only(fmt, config):
        with pytest.raises(StreamNotSeekableError):
            _open_level(source, fmt, seek=False, streaming=True, config=config)
        return
    if forward_only and fmt == "zip" and config.use_rapidgzip is AcceleratorMode.ON:
        with (
            archivey.open_archive(source, streaming=True, config=config) as reader,
            pytest.raises(StreamNotSeekableError, match="use_rapidgzip"),
        ):
            for _member, stream in reader.stream_members():
                if stream is not None:
                    stream.read()
        return
    opened = _open_level(source, fmt, seek=seek, streaming=forward_only, config=config)
    if fmt in STREAMS:
        assert isinstance(opened, ArchiveStream)
        stream = opened
    else:
        assert isinstance(opened, ArchiveReader)
        reader = opened

    if fmt in STREAMS:
        with stream:
            if len(chain) == 1:
                _check_stream(stream, SINGLE_LEAF[0].contents, seek=seek)
            else:
                # An open_stream output has no name, so a level below it that only a
                # content probe recognises (tar.zz, tar.br) needs every probe on. A
                # member stream carries its member's name, so archive levels do not.
                _walk(
                    stream,
                    chain[1:],
                    seekable=seekable,
                    config=replace(config, always_probe_content=True),
                    access=access,
                )
        return

    with reader:
        by_stream = forward_only or access == "stream_members"
        if len(chain) == 1:
            expected = {m.name: m.contents for m in LEAF}
            seen: dict[str, bytes] = {}
            if by_stream:
                for member, stream in reader.stream_members():
                    if stream is not None:
                        seen[member.name] = stream.read()
            else:
                for member in reader.members():
                    if member.is_file:
                        with reader.open(member) as stream:
                            _check_stream(stream, expected[member.name], seek=seek)
                        seen[member.name] = expected[member.name]
            for name, contents in expected.items():
                assert seen.get(name) == contents, name
            return
        target = f"inner.{chain[1]}"
        if by_stream:
            found = False
            for member, stream in reader.stream_members():
                if member.name == target:
                    found = True
                    _walk(
                        stream,
                        chain[1:],
                        seekable=seekable,
                        config=config,
                        access=access,
                    )
            assert found, target
        else:
            with reader.open(target) as stream:
                _walk(
                    stream, chain[1:], seekable=seekable, config=config, access=access
                )


def _run(
    tmp_path: Path, chain: tuple[str, ...], mode: str, seekable: bool, access: str
) -> None:
    _skip_unless_runnable(chain)
    if mode == "on" and not _HAS_RAPIDGZIP:
        pytest.skip("accelerator ON needs rapidgzip")
    path = tmp_path / f"outer.{chain[0]}"
    path.write_bytes(_chain_bytes(chain))
    _walk(path, chain, seekable=seekable, config=_config(mode), access=access)


def _id(chain: object) -> str:
    # pytest 8.3 (the floor leg) also asks for the id of the placeholder an empty
    # parameter list gets, which is not a chain.
    return "/".join(chain) if isinstance(chain, tuple) else str(chain)


PAIRS = [tuple(p) for p in itertools.product(FORMATS, repeat=2)]
# Formats an accelerator decodes under ON: gzip, zlib and ZIP's deflate members through
# rapidgzip, bzip2 through its bzip2 backend. For the rest, ON reads as OFF does, so the
# default tier runs ON only where a level is one of these.
_ACCELERATED = frozenset({"gz", "zz", "bz2", "tar.gz", "tar.zz", "tar.bz2", "zip"})
ACCELERATED_PAIRS = [c for c in PAIRS if _ACCELERATED.intersection(c)]
# Three levels: every accelerated codec, the formats that need to seek, and RAR, each
# at every depth at least once.
TRIPLES = [
    ("zip", "tar.gz", "gz"),
    ("gz", "gz", "gz"),
    ("7z", "zip", "tar.bz2"),
    ("rar", "7z", "zip"),
    ("tar", "zz", "zip"),
    ("iso", "rar", "gz"),
    ("bz2", "tar.bz2", "bz2"),
    ("tar.zz", "zip", "zz"),
]
FULL_TRIPLE_FORMATS = (
    "zip",
    "tar.gz",
    "tar.bz2",
    "7z",
    "rar",
    "iso",
    "gz",
    "bz2",
    "zz",
)


# ---------------------------------------------------------------------------
# Default tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chain", PAIRS, ids=_id)
def test_pair_random_access(tmp_path: Path, chain: tuple[str, ...]) -> None:
    _run(tmp_path, chain, "off", seekable=True, access="open")


@pytest.mark.parametrize("chain", ACCELERATED_PAIRS, ids=_id)
def test_pair_random_access_with_accelerators_on(
    tmp_path: Path, chain: tuple[str, ...]
) -> None:
    _run(tmp_path, chain, "on", seekable=True, access="open")


@pytest.mark.parametrize("chain", [c for c in PAIRS if c[1] in _ACCELERATED], ids=_id)
def test_pair_forward_only_with_accelerators_on(
    tmp_path: Path, chain: tuple[str, ...]
) -> None:
    """The inner level reads a ``stream_members()`` stream, which never seeks."""
    _run(tmp_path, chain, "on", seekable=False, access="stream_members")


@pytest.mark.parametrize("mode", ["off", "on"])
@pytest.mark.parametrize("access", ["open", "stream_members"])
@pytest.mark.parametrize("chain", TRIPLES, ids=_id)
def test_three_levels(
    tmp_path: Path, chain: tuple[str, ...], access: str, mode: str
) -> None:
    _run(tmp_path, chain, mode, seekable=True, access=access)


# ---------------------------------------------------------------------------
# Full tier (ARCHIVEY_NESTED_FULL=1)
# ---------------------------------------------------------------------------

_full = pytest.mark.skipif(not FULL, reason="set ARCHIVEY_NESTED_FULL=1")


@_full
@pytest.mark.parametrize("access", ["open", "stream_members"])
@pytest.mark.parametrize("seekable", [False, True], ids=["fwd", "seekable"])
@pytest.mark.parametrize("mode", ["off", "auto", "on"])
@pytest.mark.parametrize(
    "chain",
    # Built only when asked for: collecting ~16,000 skipped items costs seconds.
    PAIRS + [tuple(t) for t in itertools.product(FULL_TRIPLE_FORMATS, repeat=3)]
    if FULL
    else [],
    ids=_id,
)
def test_full_matrix(
    tmp_path: Path, chain: tuple[str, ...], mode: str, seekable: bool, access: str
) -> None:
    _run(tmp_path, chain, mode, seekable, access)


# ---------------------------------------------------------------------------
# Targeted cases
# ---------------------------------------------------------------------------


def _tar_of(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip_of(members: dict[str, bytes], method: int = zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_accelerator_on_over_a_forward_only_member_is_refused_cleanly() -> None:
    """ON cannot run over a stream that cannot seek; it used to raise a bare
    ``io.UnsupportedOperation("tell")`` from inside the rapidgzip handshake."""
    pytest.importorskip("rapidgzip")
    payload = random.Random(1).randbytes(30000)
    outer = _tar_of({"inner.gz": gzip.compress(payload, mtime=0)})
    with archivey.open_archive(io.BytesIO(outer), streaming=True) as reader:
        _member, stream = next(iter(reader.stream_members()))
        assert stream is not None
        with pytest.raises(StreamNotSeekableError, match="use_rapidgzip"):
            archivey.open_stream(stream, format="gz", config=_config("on"))


def test_auto_ignores_seek_demand_on_a_forward_only_compressed_tar() -> None:
    """A compressed TAR read ``streaming=True`` from a forward-only member stream, with
    ``seekable_members=True``: AUTO picked the bzip2 accelerator for it, which failed
    at open asking the source for ``tell``."""
    leaf = {"a.bin": random.Random(2).randbytes(5000)}
    import bz2

    outer = _tar_of({"inner.tar.bz2": bz2.compress(_tar_of(leaf))})
    with archivey.open_archive(io.BytesIO(outer), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            with archivey.open_archive(
                stream, streaming=True, seekable_members=True, config=_config("auto")
            ) as inner:
                got = {m.name: s.read() for m, s in inner.stream_members() if s}
    assert got == leaf


@pytest.mark.parametrize("mode", ["off", "on"])
def test_inner_reader_closes_cleanly_after_the_outer_reader(mode: str) -> None:
    """Closing the outer reader closes the member stream the inner reader reads. The
    inner reader's close then raised ``ValueError`` from its buffer's detach."""
    if mode == "on":
        pytest.importorskip("rapidgzip")
    leaf = {"big.bin": random.Random(3).randbytes(2_000_000)}
    outer = _zip_of({"inner.tar.gz": gzip.compress(_tar_of(leaf), mtime=0)})
    reader = archivey.open_archive(io.BytesIO(outer), seekable_members=True)
    stream = reader.open("inner.tar.gz")
    inner = archivey.open_archive(stream, seekable_members=True, config=_config(mode))
    reader.close()
    try:
        data = inner.read("big.bin")
    except (ArchiveyError, ArchiveyUsageError):
        pass  # the member stream under it is closed
    else:
        assert data == leaf["big.bin"]  # everything needed was already read ahead
    inner.close()


def _child_count() -> int:
    """Live children of this process (Linux only; elsewhere the check is skipped)."""
    me = str(os.getpid())
    count = 0
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open(f"/proc/{pid}/stat") as fh:
                    fields = fh.read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if fields[1] == me and fields[0] != "Z":
                count += 1
    return count


def _peak_children(fn) -> int | None:
    if not sys.platform.startswith("linux"):
        fn()
        return None
    peak = 0
    stop = threading.Event()

    def watch() -> None:
        nonlocal peak
        while not stop.is_set():
            peak = max(peak, _child_count())
            stop.wait(0.005)

    watcher = threading.Thread(target=watch)
    watcher.start()
    try:
        fn()
    finally:
        stop.set()
        watcher.join()
    return peak


@pytest.fixture(scope="module")
def big_payload() -> bytes:
    # Random, so the gzip is as large as its input: past the 16 MiB AUTO threshold.
    return random.Random(5).randbytes(17 * 2**20)


def test_auto_uses_rapidgzip_for_a_large_gz_in_a_gz(
    tmp_path: Path, big_payload: bytes
) -> None:
    """Both levels past the AUTO threshold, both seekable: two rapidgzip children,
    the inner one fed through this process from the outer one."""
    pytest.importorskip("rapidgzip")
    inner = gzip.compress(big_payload, compresslevel=1, mtime=0)
    path = tmp_path / "big.gz.gz"
    path.write_bytes(gzip.compress(inner, compresslevel=1, mtime=0))
    config = _config("auto")

    def go() -> None:
        with (
            archivey.open_stream(path, seekable=True, config=config) as outer,
            archivey.open_stream(outer, seekable=True, config=config) as stream,
        ):
            stream.seek(12_000_000)
            assert stream.read(4096) == big_payload[12_000_000:12_004_096]
            stream.seek(100)
            assert stream.read(100) == big_payload[100:200]
            stream.seek(0)
            assert stream.read() == big_payload

    peak = _peak_children(go)
    assert peak in (None, 2)


def test_ppmd_child_decodes_a_7z_nested_in_a_ppmd_7z(tmp_path: Path) -> None:
    """Both 7z levels decode PPMd in a child process: the inner child's input comes
    from the outer child's output, through this process."""
    py7zr = pytest.importorskip("py7zr")
    importorskip("pyppmd")
    from py7zr.properties import FILTER_PPMD

    def ppmd_7z(name: str, data: bytes) -> bytes:
        buf = io.BytesIO()
        with py7zr.SevenZipFile(
            buf, "w", filters=[{"id": FILTER_PPMD, "order": 6, "mem": 24}]
        ) as zf:
            zf.writestr(data, name)
        return buf.getvalue()

    # Each member's pack is well past the 1024-byte limit, so each level decodes in
    # a child, however much of the pack one read happens to carry.
    payload = b"the quick brown fox " * 5000 + random.Random(3).randbytes(1_000_000)
    path = tmp_path / "outer.zip"
    path.write_bytes(
        _zip_of({"o.7z": ppmd_7z("inner.7z", ppmd_7z("text.txt", payload))})
    )
    config = _config("off", decoder_limits=DecoderLimits(max_ppmd_held_input=1024))

    def go() -> None:
        with (
            archivey.open_archive(path, seekable_members=True, config=config) as r1,
            r1.open("o.7z") as s1,
            archivey.open_archive(s1, seekable_members=True, config=config) as r2,
            r2.open("inner.7z") as s2,
            archivey.open_archive(s2, config=config) as r3,
        ):
            assert r3.read("text.txt") == payload

    peak = _peak_children(go)
    assert peak in (None, 2)


@pytest.mark.parametrize("mode", ["off", "on"])
def test_two_nested_archives_read_from_threads(mode: str) -> None:
    if mode == "on":
        pytest.importorskip("rapidgzip")
    a = {f"a{i}.bin": random.Random(i).randbytes(30000) for i in range(3)}
    b = {f"b{i}.bin": random.Random(100 + i).randbytes(30000) for i in range(3)}
    outer = _zip_of(
        {
            "a.tar.gz": gzip.compress(_tar_of(a), mtime=0),
            "b.tar.gz": gzip.compress(_tar_of(b), mtime=0),
        },
        zipfile.ZIP_DEFLATED,
    )
    errors: list[BaseException] = []
    config = _config(mode)
    with archivey.open_archive(
        io.BytesIO(outer),
        seekable_members=True,
        concurrent_operations=True,
        config=config,
    ) as reader:

        def work(name: str, expected: dict[str, bytes]) -> None:
            try:
                for _ in range(3):
                    with (
                        reader.open(name) as stream,
                        archivey.open_archive(
                            stream, seekable_members=True, config=config
                        ) as inner,
                    ):
                        for member_name, data in expected.items():
                            assert inner.read(member_name) == data
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [
            threading.Thread(target=work, args=args)
            for args in (("a.tar.gz", a), ("b.tar.gz", b)) * 2
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        assert not any(t.is_alive() for t in threads), "a reader thread hung"
    assert not errors, errors


def _damaged(data: bytes, how: str) -> bytes:
    if how == "truncated":
        return data[: len(data) * 2 // 3]
    flipped = bytearray(data)
    flipped[len(flipped) // 2] ^= 0xFF
    return bytes(flipped)


def _read_everything(stream: BinaryIO, fmt: str, config: ArchiveyConfig) -> None:
    """Open ``stream`` as the caller would, with no format named, and read it all.

    No format is passed: a damaged compressed TAR may no longer probe as a TAR and be
    opened as the bare compressed stream instead, which is a fair reading of it.
    """
    if fmt in STREAMS:
        with archivey.open_stream(
            stream, format=StreamFormat(fmt), seekable=True, config=config
        ) as inner:
            inner.read()
        return
    with archivey.open_archive(stream, seekable_members=True, config=config) as reader:
        for member in reader.members():
            if member.is_file:
                reader.read(member)


# For the zlib rows: auto pins that a bare zlib stream never reaches rapidgzip, so it
# raises as off does; on pins archivey's own Adler-32 check after rapidgzip.
@pytest.mark.parametrize("mode", ["off", "auto", "on"])
@pytest.mark.parametrize("how", ["truncated", "flipped"])
@pytest.mark.parametrize(
    "inner", ["tar.gz", "tar.bz2", "tar.zz", "gz", "bz2", "zz", "zip", "7z"]
)
def test_damaged_inner_archive_raises_an_archivey_error(
    tmp_path: Path, inner: str, how: str, mode: str
) -> None:
    _skip_unless_runnable(("zip", inner))
    if mode == "on" and not _HAS_RAPIDGZIP:
        pytest.skip("accelerator ON needs rapidgzip")
    inner_bytes = _damaged(_build(inner, _leaf_members(inner)), how)
    path = tmp_path / "outer.zip"
    path.write_bytes(_zip_of({f"inner.{inner}": inner_bytes}))
    config = _config(mode)
    with (
        archivey.open_archive(path, seekable_members=True, config=config) as reader,
        reader.open(f"inner.{inner}") as stream,
        pytest.raises(ArchiveyError),
    ):
        _read_everything(stream, inner, config)


# ---------------------------------------------------------------------------
# Committed RAR fixtures
# ---------------------------------------------------------------------------


def test_committed_rar_fixtures_hold_the_current_leaf() -> None:
    """A fixture built from an older LEAF would still pass the chain tests only if the
    contents check were skipped; this names the stale file instead."""
    if not RAR_FIXTURES.exists():
        pytest.skip("no committed nested RAR fixtures")
    if not has_binary("unrar") and not has_binary("unar"):
        pytest.skip("reading RAR member data needs unrar or unar")
    for chain in RAR_FIXTURE_CHAINS:
        fixture = _rar_fixture(chain)
        assert fixture.exists(), f"missing {fixture.name}; regenerate the fixtures"
    stale = (
        "is stale; run python -m tests.test_nested_archives --write-rar-fixtures on a "
        "machine with RARLAB rar"
    )
    leaf = _rar_fixture(("rar",))
    with archivey.open_archive(leaf) as reader:
        got = {m.name: reader.read(m) for m in reader.members() if m.is_file}
    assert got == {m.name: m.contents for m in LEAF}, f"{leaf.name} {stale}"
    # The stream-format chains carry SINGLE_LEAF instead; check one of them too.
    stream_leaf = _rar_fixture(("rar", "gz"))
    with (
        archivey.open_archive(stream_leaf) as reader,
        reader.open("inner.gz") as member,
        archivey.open_stream(member, format="gz") as stream,
    ):
        payload = stream.read()
    assert payload == SINGLE_LEAF[0].contents, f"{stream_leaf.name} {stale}"


def _write_rar_fixtures() -> None:
    if shutil.which("rar") is None:
        raise SystemExit("the RARLAB rar writer is not on PATH")
    RAR_FIXTURES.mkdir(parents=True, exist_ok=True)
    for chain in RAR_FIXTURE_CHAINS:
        _rar_fixture(chain).write_bytes(_chain_bytes(chain))


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-rar-fixtures"]:
        _write_rar_fixtures()
    else:
        raise SystemExit(
            "usage: python -m tests.test_nested_archives --write-rar-fixtures"
        )
