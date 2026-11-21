"""``OnError.KEEP_PARTIAL``: a file whose data fails part-way keeps what was written.

The contract is ``safe-extraction``, "Error Policy (OnError) for extraction failures".
"""

from __future__ import annotations

import gzip
import io
import tarfile
import warnings
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DecoderLimits,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
    open_archive,
)
from archivey.exceptions import ArchiveyError, ResourceLimitError, TruncatedError
from archivey.internal.extraction import _CHUNK
from tests.extract_util import open_and_extract


@contextmanager
def warnings_ignored() -> Iterator[None]:
    """``zipfile`` warns on a duplicate name, which these tests write on purpose."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        yield


# Not a multiple of the copy chunk, and more than one chunk, so a cut lands
# part-way through a member.
_PAYLOAD = bytes(range(256)) * (2 * 4096 + 7)


def _zip_with_damaged_data(path: Path) -> Path:
    """A STORED ZIP whose ``bad.bin`` has one flipped data byte, so its CRC check
    fails at the end of its data (in both access modes), then ``good.txt``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("bad.bin", _PAYLOAD)
        zf.writestr("good.txt", b"good")
    data = bytearray(buf.getvalue())
    start = data.find(_PAYLOAD[:4096])
    data[start + 100] ^= 0xFF
    path.write_bytes(bytes(data))
    return path


def _cut_tar_gz(path: Path) -> Path:
    """A ``.tar.gz`` of ``first.txt`` and ``big.bin`` (incompressible enough to cut
    inside it), cut part-way through ``big.bin``'s data."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in (("first.txt", b"first"), ("big.bin", _PAYLOAD)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    packed = gzip.compress(raw.getvalue(), compresslevel=0)
    path.write_bytes(packed[: len(packed) // 2])
    return path


@pytest.mark.parametrize("streaming", [False, True])
def test_keep_partial_keeps_a_file_whose_check_fails(
    tmp_path: Path, streaming: bool
) -> None:
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    report = open_and_extract(
        src, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    by_name = {r.member.name: r for r in report.results}
    bad = by_name["bad.bin"]
    assert bad.status is ExtractionStatus.FAILED
    assert isinstance(bad.error, ArchiveyError)
    assert bad.path == dest / "bad.bin"
    kept = (dest / "bad.bin").read_bytes()
    # The read that meets the failed check raises instead of returning its bytes, so
    # the file holds what the reads before it gave: at most one copy chunk less.
    assert len(_PAYLOAD) - _CHUNK <= len(kept) < len(_PAYLOAD)
    assert kept[:100] == _PAYLOAD[:100]
    assert kept[100] != _PAYLOAD[100]
    assert by_name["good.txt"].status is ExtractionStatus.EXTRACTED
    assert (dest / "good.txt").read_bytes() == b"good"
    assert not report.ok
    assert not list(dest.rglob(".archivey-tmp-*"))


@pytest.mark.parametrize("streaming", [False, True])
def test_continue_still_removes_the_partial_file(
    tmp_path: Path, streaming: bool
) -> None:
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, streaming=streaming, on_error="continue")
    bad = next(r for r in report.results if r.member.name == "bad.bin")
    assert bad.status is ExtractionStatus.FAILED
    assert bad.path is None
    assert not (dest / "bad.bin").exists()


@pytest.mark.parametrize("streaming", [False, True])
def test_keep_partial_keeps_the_bytes_before_a_cut(
    tmp_path: Path, streaming: bool
) -> None:
    # The cut is the archive's own damage too: the member is handled (kept, and
    # logged), and then the walk raises it, as under ``CONTINUE``.
    src = _cut_tar_gz(tmp_path / "a.tar.gz")
    dest = tmp_path / "out"
    with (
        open_archive(src, streaming=streaming) as reader,
        pytest.raises(TruncatedError),
    ):
        reader.extract_all(dest, on_error="keep_partial")
    kept = (dest / "big.bin").read_bytes()
    assert 0 < len(kept) < len(_PAYLOAD)
    assert _PAYLOAD.startswith(kept)
    assert (dest / "first.txt").read_bytes() == b"first"
    assert not list(dest.rglob(".archivey-tmp-*"))


def test_keep_partial_on_a_cut_single_file_stream(tmp_path: Path) -> None:
    packed = gzip.compress(_PAYLOAD, compresslevel=0)
    src = tmp_path / "data.bin.gz"
    src.write_bytes(packed[: len(packed) // 2])
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, on_error=OnError.KEEP_PARTIAL)
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert result.path is not None
    kept = result.path.read_bytes()
    assert 0 < len(kept) < len(_PAYLOAD)
    assert _PAYLOAD.startswith(kept)


def test_keep_partial_keeps_nothing_when_the_failure_comes_first(
    tmp_path: Path,
) -> None:
    # An existing entry under OverwritePolicy.ERROR fails the member before any of
    # its data is read: the caller's file stays as it was.
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "bad.bin").write_bytes(b"mine")
    report = open_and_extract(
        src, dest, on_error=OnError.KEEP_PARTIAL, overwrite=OverwritePolicy.ERROR
    )
    bad = next(r for r in report.results if r.member.name == "bad.bin")
    assert bad.status is ExtractionStatus.FAILED
    assert bad.path is None
    assert (dest / "bad.bin").read_bytes() == b"mine"


def test_keep_partial_under_replace_replaces_an_existing_file(tmp_path: Path) -> None:
    # The partial file lands as a complete one would: REPLACE puts it over the entry.
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "bad.bin").write_bytes(b"mine")
    report = open_and_extract(
        src, dest, on_error=OnError.KEEP_PARTIAL, overwrite=OverwritePolicy.REPLACE
    )
    bad = next(r for r in report.results if r.member.name == "bad.bin")
    assert bad.status is ExtractionStatus.FAILED
    assert bad.path == dest / "bad.bin"
    assert (dest / "bad.bin").read_bytes()[:100] == _PAYLOAD[:100]


def test_keep_partial_dry_run_writes_nothing(tmp_path: Path) -> None:
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, on_error=OnError.KEEP_PARTIAL, dry_run=True)
    bad = next(r for r in report.results if r.member.name == "bad.bin")
    assert bad.status is ExtractionStatus.FAILED
    assert bad.path is None
    assert not dest.exists() or not (dest / "bad.bin").exists()


def test_keep_partial_keeps_nothing_for_a_limit(tmp_path: Path) -> None:
    # A limit refuses the content; it does not find it damaged.
    src = tmp_path / "zeros.gz"
    src.write_bytes(gzip.compress(b"\0" * (8 * 2**20)))
    dest = tmp_path / "out"
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=10.0))
    report = open_and_extract(src, dest, config=config, on_error=OnError.KEEP_PARTIAL)
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert isinstance(result.error, ResourceLimitError)
    assert result.path is None
    assert not [p for p in dest.rglob("*") if p.is_file()]


@pytest.mark.parametrize("streaming", [False, True])
def test_a_later_copy_of_the_name_replaces_a_kept_partial_file(
    tmp_path: Path, streaming: bool
) -> None:
    # The damaged copy is not current, so random access never writes it; a forward
    # pass that wrote it takes it back. Either way only the later copy stays.
    buf = io.BytesIO()
    with (
        warnings_ignored(),
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf,
    ):
        zf.writestr("x.bin", _PAYLOAD)
        zf.writestr("x.bin", b"second")
    data = bytearray(buf.getvalue())
    data[data.find(_PAYLOAD[:4096]) + 100] ^= 0xFF
    src = tmp_path / "dup.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    report = open_and_extract(
        src, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    assert (dest / "x.bin").read_bytes() == b"second"
    statuses = [r.status for r in report.results]
    assert statuses[-1] is ExtractionStatus.EXTRACTED
    assert all(r.path is None for r in report.results[:-1])
    assert not list(dest.rglob(".archivey-tmp-*"))
