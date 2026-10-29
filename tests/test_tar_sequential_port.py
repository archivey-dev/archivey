"""TAR on the sequential plugin shape (``tar_sequential``) reads what the built-in TAR
reader reads: every TAR shape of the sample corpus, in random access and as a stream,
with the same members, data and diagnostics."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import ArchiveFormat, StreamFormat, open_archive
from archivey.formats import register_format
from archivey.internal.backends.tar_sequential import (
    TAR_SEQUENTIAL,
    TarSequentialHandler,
)
from archivey.internal.format_adapter import registration_scope
from tests.sample_archives import CORPUS, CorpusEntry, corpus_archive_path

_STREAMS = {
    "tar": StreamFormat.UNCOMPRESSED,
    "tar.gz": StreamFormat.GZIP,
    "tar.bz2": StreamFormat.BZIP2,
    "tar.xz": StreamFormat.XZ,
}
_CASES = [
    pytest.param(entry, key, id=f"{entry.id}-{key}")
    for entry in CORPUS
    for key in entry.formats
    if key in _STREAMS
]


@pytest.fixture
def port() -> Iterator[None]:
    with registration_scope():
        register_format(TarSequentialHandler)
        yield


def _read(path: Path, fmt: ArchiveFormat | None, streaming: bool) -> object:
    try:
        with open_archive(path, format=fmt, streaming=streaming) as reader:
            members = [
                (
                    m.name,
                    m.type,
                    m.size,
                    m.link_target,
                    m.mode,
                    m.modified,
                    m.extra,
                    s.read() if s is not None else None,
                )
                for m, s in reader.stream_members()
            ]
            return members, dict(reader.diagnostics.counts)
    except Exception as exc:  # noqa: BLE001 — the error is what is compared
        return type(exc).__name__, str(exc)


@pytest.mark.usefixtures("port")
@pytest.mark.parametrize(("entry", "key"), _CASES)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
def test_port_reads_what_the_builtin_reads(
    entry: CorpusEntry, key: str, streaming: bool, tmp_path: Path
) -> None:
    path = corpus_archive_path(entry, key, tmp_path)
    fmt = ArchiveFormat(TAR_SEQUENTIAL.container, _STREAMS[key])
    assert _read(path, fmt, streaming) == _read(path, None, streaming)
