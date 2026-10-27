"""Healthy archives opened from a source whose ``read(n)`` legally returns short.

``io.RawIOBase.read(n)`` returns *up to* ``n`` bytes, and real sources use that latitude:
sockets, FUSE mounts, and user-written wrappers all hand back short chunks mid-stream with
no EOF in sight. Fixed-size structure reads used to issue a single ``read(n)`` and read the
short return as EOF — in archivey's own RAR parser, in the stdlib/third-party readers it
delegates to (``zipfile``, ``tarfile``, ``pycdlib``), and in rapidgzip's bzip2 seek-index
accelerator alike — so a **healthy** archive from such a source was reported as
``CorruptionError`` / ``TruncatedError``. Two layers fix it: the source boundary coalesces
short reads for **both** seekable and non-seekable streams, and archivey's own parsers
and views gather fixed-size structures with ``read_exact``.

Every case compares against a ``BytesIO`` open of the *same bytes*, so it asserts parity
rather than a hardcoded expectation — a format that cannot be built or read in this
environment simply matches on both sides (or skips).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive, open_stream
from archivey.exceptions import ArchiveyError
from archivey.internal.backends.rar_parser import parse_rar_archive
from archivey.internal.format_args import outer_stream_format
from archivey.types import ArchiveFormat, ContainerFormat, MemberType
from tests.sample_archives import (
    CORPUS,
    FORMAT_KEYS,
    CorpusEntry,
    corpus_archive_path as _corpus_archive_path,
    skip_unless_runnable,
)
from tests.streams_util import (
    NonSeekableBytesIO,
    ShortReadBytesIO,
    ShortReadNonSeekable,
)

FIXTURES = Path(__file__).parent / "fixtures"

# The password every generated encrypted fixture uses (see tests/fixtures/rar/README.md);
# harmless for the unencrypted ones, and it lets the encrypted-header archives list.
FIXTURE_PASSWORD = "password"

# Every source here is nameless, so the magic-less formats (zlib, Brotli, LZMA Alone and
# their TAR forms) are recognised only with every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


# One archive per format is enough: the bug is in how the container's headers are read,
# not in which members it holds, and the corpus sweep already covers member shapes.
# ``dir`` is excluded — a directory tree is not a stream source.
def _one_entry_per_format() -> list[tuple[CorpusEntry, str]]:
    cases: list[tuple[CorpusEntry, str]] = []
    for key in FORMAT_KEYS:
        if key == "dir":
            continue
        entry = next((e for e in CORPUS if key in e.formats), None)
        if entry is not None:
            cases.append((entry, key))
    return cases


_CORPUS_CASES = [
    pytest.param(entry, key, id=f"{key}-{entry.id}")
    for entry, key in _one_entry_per_format()
]


def _probe(
    source: io.BytesIO | ShortReadBytesIO | ShortReadNonSeekable | NonSeekableBytesIO,
    passwords: tuple[str, ...],
    *,
    streaming: bool = False,
    format: ArchiveFormat | None = None,
) -> list[tuple]:
    """Listing + member payloads, with per-member archivey errors recorded as their type.

    Recording the error type (rather than letting it escape) keeps the comparison a pure
    parity check: a member that is unreadable here — no ``unrar`` binary, no password —
    must be unreadable the same way from both sources, and a member that reads must return
    the same bytes.
    """
    with open_archive(
        source,
        password=passwords or None,
        streaming=streaming,
        format=format,
        config=_ALWAYS_PROBE,
    ) as reader:
        rows: list[tuple] = []
        if streaming:
            # stream_members owns each stream: read it before advancing.
            for member, stream in reader.stream_members():
                payload: bytes | str | None = None
                if member.type is MemberType.FILE:
                    try:
                        payload = stream.read() if stream is not None else None
                    except ArchiveyError as exc:
                        payload = type(exc).__name__
                rows.append(
                    (member.name, member.type, member.size, member.link_target, payload)
                )
            return rows
        for member in reader.members():
            payload = None
            if member.type is MemberType.FILE:
                try:
                    payload = reader.read(member)
                except ArchiveyError as exc:
                    payload = type(exc).__name__
            rows.append(
                (member.name, member.type, member.size, member.link_target, payload)
            )
        return rows


def _assert_short_read_parity(data: bytes, passwords: tuple[str, ...] = ()) -> None:
    baseline = _probe(io.BytesIO(data), passwords)
    assert _probe(ShortReadBytesIO(data), passwords) == baseline


@pytest.mark.parametrize(("entry", "key"), _CORPUS_CASES)
def test_corpus_archive_opens_from_short_read_source(
    entry: CorpusEntry, key: str, tmp_path: Path
) -> None:
    skip_unless_runnable(entry, key)
    data = _corpus_archive_path(entry, key, tmp_path).read_bytes()
    _assert_short_read_parity(data, entry.passwords)


# Every format open_stream accepts: the raw streams and the compressed tars, whose
# outer codec it peels. Compressed tars run the inner-tar probe through the replay
# prefix, which a raw-stream magic match does not.
_STREAM_KEYS = [
    key for key, fmt in FORMAT_KEYS.items() if outer_stream_format(fmt) is not None
]


@pytest.mark.parametrize("key", _STREAM_KEYS)
@pytest.mark.parametrize("seekable", [False, True])
def test_open_stream_decodes_from_short_read_source(
    key: str, seekable: bool, tmp_path: Path
) -> None:
    """``open_stream`` needs the same boundary as ``open_archive``.

    ``seekable=True`` is the case that bites: a seek-index accelerator
    (rapidgzip's bzip2 decoder) reads the source itself and reported a healthy stream as
    ``CorruptionError`` on a short return.
    """
    entry = next(e for e in CORPUS if key in e.formats)
    skip_unless_runnable(entry, key)
    data = _corpus_archive_path(entry, key, tmp_path).read_bytes()
    with open_stream(io.BytesIO(data), seekable=seekable) as expected_stream:
        expected = expected_stream.read()
    with open_stream(ShortReadBytesIO(data), seekable=seekable) as stream:
        assert stream.read() == expected


_FIXTURE_ARCHIVES = sorted(
    path
    for path in FIXTURES.rglob("*")
    if path.is_file() and path.suffix in {".rar", ".zip", ".7z", ".r00"}
)


@pytest.mark.parametrize(
    "path", _FIXTURE_ARCHIVES, ids=[p.name for p in _FIXTURE_ARCHIVES]
)
def test_committed_fixture_opens_from_short_read_source(path: Path) -> None:
    data = path.read_bytes()
    try:
        baseline = _probe(io.BytesIO(data), (FIXTURE_PASSWORD,))
    except ArchiveyError as exc:
        # Volume members and deliberately broken fixtures do not open from a lone
        # BytesIO at all; there is no parity to assert for them here.
        pytest.skip(f"fixture does not open standalone from a BytesIO: {exc}")
    assert _probe(ShortReadBytesIO(data), (FIXTURE_PASSWORD,)) == baseline


@pytest.mark.parametrize("rar", ["basic_nonsolid__.rar", "basic_nonsolid__rar4.rar"])
def test_rar_header_offsets_survive_short_reads(rar: str) -> None:
    """The parser's own offsets must not shift when the source returns short chunks.

    ``_read_rar5_block`` derives ``header_offset`` / ``data_offset`` from ``fd.tell()``
    between reads, so a coalescing layer that reported a *buffer* position rather than the
    logical one would silently mis-place every member. This drives ``parse_rar_archive``
    directly, so it pins the parser rather than the boundary buffering in front of it.
    """
    data = (FIXTURES / "rar" / rar).read_bytes()

    def offsets(source):
        return [
            (m.filename, m.header_offset, m.header_size, m.data_offset, m.compress_size)
            for m in parse_rar_archive(source).members
        ]

    assert offsets(ShortReadBytesIO(data)) == offsets(io.BytesIO(data))


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(gzip.compress, id="gzip"),
        pytest.param(bz2.compress, id="bzip2"),
        pytest.param(
            lambda payload: lzma.compress(payload, format=lzma.FORMAT_XZ), id="xz"
        ),
    ],
)
def test_open_stream_detects_short_read_non_seekable(
    compress: Callable[[bytes], bytes],
) -> None:
    """``open_stream`` with ``format=None`` over a short-returning pipe.

    Written on the detected path: the explicit-``format=`` variant is rescued by
    ``ensure_bufferedio`` inside ``DecompressorStream`` even when the source's replay
    prefix is never filled.
    """
    payload = b"hello from a short-returning pipe"
    data = compress(payload)
    with open_stream(io.BytesIO(data)) as expected_stream:
        expected = expected_stream.read()
    with open_stream(ShortReadNonSeekable(data, 1)) as stream:
        assert stream.read() == expected


_STREAMING_CASES = [
    pytest.param(entry, key, id=f"{key}-{entry.id}")
    for entry, key in _one_entry_per_format()
    if FORMAT_KEYS[key].container in (ContainerFormat.TAR, ContainerFormat.RAW_STREAM)
]


@pytest.mark.parametrize(("entry", "key"), _STREAMING_CASES)
@pytest.mark.parametrize(
    "explicit_format", [False, True], ids=["detected", "explicit-format"]
)
def test_streaming_format_opens_from_short_read_non_seekable(
    entry: CorpusEntry, key: str, explicit_format: bool, tmp_path: Path
) -> None:
    """Each streaming-capable format, with and without ``format=``.

    The explicit-``format=`` case skips detection, so the replay prefix is never
    filled and the source's own full-count read is the only coalescing layer. Plain uncompressed TAR is
    in this matrix: that is the path that previously leaned on ``tarfile._Stream``.
    """
    skip_unless_runnable(entry, key)
    data = _corpus_archive_path(entry, key, tmp_path).read_bytes()
    fmt = FORMAT_KEYS[key] if explicit_format else None
    baseline = _probe(
        NonSeekableBytesIO(data), entry.passwords, streaming=True, format=fmt
    )
    assert (
        _probe(
            ShortReadNonSeekable(data, 1),
            entry.passwords,
            streaming=True,
            format=fmt,
        )
        == baseline
    )
