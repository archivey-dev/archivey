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
from tests.extract_util import open_and_extract
from tests.streams_util import NonSeekableBytesIO


@contextmanager
def warnings_ignored() -> Iterator[None]:
    """``zipfile`` warns on a duplicate name, which these tests write on purpose."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        yield


# How the archive is opened: from a file (random access), from a file with
# ``streaming=True`` (a forward pass), and from a pipe (non-seekable: a ZIP is staged
# and placed once its central directory is read).
_MODES = ["file", "streaming", "pipe"]


def _source(src: Path, mode: str) -> tuple[object, bool]:
    """The source to open ``src`` from in ``mode``, and its ``streaming=``."""
    if mode == "pipe":
        return NonSeekableBytesIO(src.read_bytes()), True
    return src, mode == "streaming"


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


@pytest.mark.parametrize("mode", _MODES)
def test_keep_partial_keeps_a_file_whose_check_fails(tmp_path: Path, mode: str) -> None:
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    by_name = {r.member.name: r for r in report.results}
    bad = by_name["bad.bin"]
    assert bad.status is ExtractionStatus.FAILED
    assert isinstance(bad.error, ArchiveyError)
    assert bad.path == dest / "bad.bin"
    kept = (dest / "bad.bin").read_bytes()
    # The chunk the failed check withholds from its read goes into the file too, so
    # every byte is kept, in every mode.
    assert len(kept) == len(_PAYLOAD)
    assert kept[:100] == _PAYLOAD[:100]
    assert kept[100] != _PAYLOAD[100]
    assert by_name["good.txt"].status is ExtractionStatus.EXTRACTED
    assert (dest / "good.txt").read_bytes() == b"good"
    assert not report.ok
    assert not list(dest.rglob(".archivey-tmp-*"))


@pytest.mark.parametrize("mode", _MODES)
def test_continue_still_removes_the_partial_file(tmp_path: Path, mode: str) -> None:
    src = _zip_with_damaged_data(tmp_path / "a.zip")
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(source, dest, streaming=streaming, on_error="continue")
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
        pytest.raises(TruncatedError) as raised,
    ):
        reader.extract_all(dest, on_error="keep_partial")
    # No report is returned, so the error names the partial file.
    assert any(str(dest / "big.bin") in note for note in raised.value.__notes__)
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


@pytest.mark.parametrize("mode", _MODES)
def test_a_later_copy_of_the_name_replaces_a_kept_partial_file(
    tmp_path: Path, mode: str
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
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    assert (dest / "x.bin").read_bytes() == b"second"
    statuses = [r.status for r in report.results]
    assert statuses[-1] is ExtractionStatus.EXTRACTED
    assert all(r.path is None for r in report.results[:-1])
    assert not list(dest.rglob(".archivey-tmp-*"))


@pytest.mark.parametrize("mode", _MODES)
def test_a_later_member_replaces_a_kept_partial_file(tmp_path: Path, mode: str) -> None:
    # ``A.bin`` and ``a.bin`` collide on every OS. Under REPLACE the second lands
    # over the first's partial file, and the first stays FAILED, with no path.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("A.bin", _PAYLOAD)
        zf.writestr("a.bin", b"second")
    data = bytearray(buf.getvalue())
    data[data.find(_PAYLOAD[:4096]) + 100] ^= 0xFF
    src = tmp_path / "case.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
    )
    first, second = report.results
    assert first.status is ExtractionStatus.FAILED
    assert first.path is None
    assert first.requested_path == dest / "A.bin"
    assert second.status is ExtractionStatus.EXTRACTED
    assert second.path is not None
    assert second.path.read_bytes() == b"second"
    assert [p.name for p in dest.iterdir()] == [second.path.name]


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("size", [1000, 3 * 2**20 + 5])
def test_a_check_failure_keeps_every_byte(tmp_path: Path, mode: str, size: int) -> None:
    # Bit-rot that still decodes: one flipped byte, so only the CRC fails. Below one
    # copy chunk the whole member arrives in the read that meets the check.
    payload = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("rot.bin", payload)
    data = bytearray(buf.getvalue())
    data[data.find(payload[:200]) + 50] ^= 0xFF
    src = tmp_path / "rot.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert result.path == dest / "rot.bin"
    kept = result.path.read_bytes()
    assert len(kept) == size
    assert kept[:50] == payload[:50]
    assert kept[51:] == payload[51:]


def test_a_gzip_check_failure_keeps_what_the_decoder_gave(tmp_path: Path) -> None:
    # A single-file .gz whose trailer CRC is wrong. zlib makes that check itself
    # and raises from the decode, so its last output can be lost (measured: 1 byte);
    # what is kept is a prefix of the data.
    packed = bytearray(gzip.compress(_PAYLOAD))
    packed[-8] ^= 0xFF
    src = tmp_path / "data.bin.gz"
    src.write_bytes(bytes(packed))
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, on_error=OnError.KEEP_PARTIAL)
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert result.path is not None
    kept = result.path.read_bytes()
    assert len(_PAYLOAD) - 2**20 <= len(kept) <= len(_PAYLOAD)
    assert _PAYLOAD.startswith(kept)


def _zip_with_wrong_crcs(path: Path, entries: dict[str, bytes], bad: str) -> Path:
    """A DEFLATED ZIP whose ``bad`` member stores a wrong CRC in both its local header
    and its central entry, so its data decodes in full and only the check fails."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    target = bad.encode()
    for magic, crc_at, name_len_at, name_at in (
        (b"PK\x03\x04", 14, 26, 30),
        (b"PK\x01\x02", 16, 28, 46),
    ):
        pos = 0
        while (i := data.find(magic, pos)) >= 0:
            n = int.from_bytes(data[i + name_len_at : i + name_len_at + 2], "little")
            if bytes(data[i + name_at : i + name_at + n]) == target:
                data[i + crc_at] ^= 0xFF
            pos = i + 4
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize("mode", _MODES)
def test_a_kept_member_counts_once_toward_the_ratio(tmp_path: Path, mode: str) -> None:
    # From a pipe the member is staged and then placed: its bytes count once, so a
    # member under the archive-wide ratio from a file stays under it from a pipe.
    payload = (b"\0" * 900 + bytes(range(100))) * 3000
    src = _zip_with_wrong_crcs(
        tmp_path / "ratio.zip", {"bad.bin": payload, "good.txt": b"good"}, "bad.bin"
    )
    ratio = len(payload) / src.stat().st_size
    limits = DecoderLimits(
        max_ratio=ratio * 1.5,
        ratio_activation_threshold=100_000,
        live_ratio_activation_threshold=100_000,
    )
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        config=ArchiveyConfig(decoder_limits=limits),
        on_error=OnError.KEEP_PARTIAL,
    )
    by_name = {r.member.name: r for r in report.results}
    assert by_name["bad.bin"].status is ExtractionStatus.FAILED
    assert (dest / "bad.bin").read_bytes() == payload
    assert (dest / "good.txt").read_bytes() == b"good"
