"""``OnError.KEEP_PARTIAL``: a file whose data fails part-way keeps what was written.

The contract is ``safe-extraction``, "Error Policy (OnError) for extraction failures".
"""

from __future__ import annotations

import gzip
import io
import os
import struct
import tarfile
import warnings
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, ExtractionPolicy, open_archive
from archivey.config import DecoderLimits
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.terminal import display_path
from archivey.types import ExtractionStatus, OnError, OverwritePolicy
from tests.conftest import case_sensitive
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
    kept_at = repr(display_path(dest / "big.bin"))
    assert any(kept_at in note for note in raised.value.__notes__)
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


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_a_member_longer_than_its_size_keeps_its_declared_bytes(
    tmp_path: Path, mode: str, method: int
) -> None:
    """The uncompressed size says 1000 bytes and the data holds more: the size check
    fails, and the file keeps the 1000 declared bytes in every mode. From a pipe the
    pass checks the size in its own reader, which returns the declared bytes first."""
    payload = bytes(range(256)) * 4000
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        zf.writestr("big.bin", payload)
        zf.writestr("good.txt", b"good")
    data = bytearray(buf.getvalue())
    struct.pack_into("<I", data, 22, 1000)  # the local header's size
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<I", data, central + 24, 1000)
    src = tmp_path / "long.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source, dest, streaming=streaming, on_error=OnError.KEEP_PARTIAL
    )
    by_name = {r.member.name: r for r in report.results}
    big = by_name["big.bin"]
    assert big.status is ExtractionStatus.FAILED
    assert isinstance(big.error, CorruptionError)
    assert big.path == dest / "big.bin"
    assert (dest / "big.bin").read_bytes() == payload[:1000]
    assert by_name["good.txt"].status is ExtractionStatus.EXTRACTED


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


class _SlottedOSError(OSError):
    """An ``OSError`` that refuses new attributes, so nothing can mark it."""

    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(name)


@pytest.mark.parametrize("error", [OSError, _SlottedOSError])
@pytest.mark.parametrize("mode", _MODES)
def test_a_progress_callback_error_keeps_nothing(
    tmp_path: Path, mode: str, error: type[OSError]
) -> None:
    # The caller's on_progress raises OSError part-way through a member's copy. That
    # says nothing about the member's data, so nothing lands: the existing file stays.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", _PAYLOAD)
    src = tmp_path / "a.zip"
    src.write_bytes(buf.getvalue())
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "big.bin").write_bytes(b"mine")

    raised: list[bool] = []

    def on_progress(progress: object) -> None:
        # Once, from inside the copy loop (after the first full chunk).
        if getattr(progress, "member_bytes_written", 0) and not raised:
            raised.append(True)
            raise error("disk of the progress log is full")

    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
        on_progress=on_progress,
    )
    (result,) = report.results
    assert raised
    assert result.status is ExtractionStatus.FAILED
    assert result.path is None
    assert (dest / "big.bin").read_bytes() == b"mine"
    assert not list(dest.rglob(".archivey-tmp-*"))


@pytest.mark.parametrize("mode", _MODES)
def test_trusted_later_member_on_a_kept_partial_name_clears_its_path(
    tmp_path: Path, mode: str
) -> None:
    # TRUSTED reports no collision. A filter maps ``b.bin`` onto ``a.bin``'s name, so
    # under REPLACE it lands over the partial file ``a.bin`` kept: the failed result
    # must stop naming that path.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.bin", _PAYLOAD)
        zf.writestr("b.bin", b"second")
    data = bytearray(buf.getvalue())
    data[data.find(_PAYLOAD[:4096]) + 100] ^= 0xFF
    src = tmp_path / "two.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
        policy=ExtractionPolicy.TRUSTED,
        filter=lambda m: m.replace(name="a.bin") if m.name == "b.bin" else m,
    )
    first, second = report.results
    assert first.status is ExtractionStatus.FAILED
    assert first.path is None
    assert first.requested_path == dest / "a.bin"
    assert second.status is ExtractionStatus.EXTRACTED
    assert second.path == dest / "a.bin"
    assert (dest / "a.bin").read_bytes() == b"second"


@pytest.mark.skipif(os.name == "nt", reason="needs a directory symlink")
@pytest.mark.parametrize("mode", _MODES)
def test_trusted_later_member_through_an_alias_clears_the_kept_path(
    tmp_path: Path, mode: str
) -> None:
    # The caller's ``alias`` is a link to ``real`` inside the destination. Under
    # TRUSTED and REPLACE, ``alias/a.bin`` lands over the partial file
    # ``real/a.bin`` kept: the failed result must stop naming it.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("real/a.bin", _PAYLOAD)
        zf.writestr("alias/a.bin", b"second")
    data = bytearray(buf.getvalue())
    data[data.find(_PAYLOAD[:4096]) + 100] ^= 0xFF
    src = tmp_path / "alias.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    (dest / "real").mkdir(parents=True)
    (dest / "alias").symlink_to("real", target_is_directory=True)
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
        policy=ExtractionPolicy.TRUSTED,
    )
    by_name = {r.member.name: r for r in report.results}
    first, second = by_name["real/a.bin"], by_name["alias/a.bin"]
    assert second.status is ExtractionStatus.EXTRACTED
    assert (dest / "real" / "a.bin").read_bytes() == b"second"
    assert first.status is ExtractionStatus.FAILED
    assert first.path is None


@pytest.mark.parametrize("mode", _MODES)
def test_trusted_case_variant_over_a_kept_partial(tmp_path: Path, mode: str) -> None:
    # Under TRUSTED and REPLACE, ``a.bin`` after the damaged ``A.bin``. Where the
    # filesystem folds case, it lands over the kept partial file, and the failed
    # result loses its path. Where it keeps the names apart, both files stay and
    # both results name their own.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("A.bin", _PAYLOAD)
        zf.writestr("a.bin", b"second")
    data = bytearray(buf.getvalue())
    data[data.find(_PAYLOAD[:4096]) + 100] ^= 0xFF
    src = tmp_path / "case.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    dest.mkdir()
    folds = not case_sensitive(dest)
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
        policy=ExtractionPolicy.TRUSTED,
    )
    first, second = report.results
    assert first.status is ExtractionStatus.FAILED
    assert second.status is ExtractionStatus.EXTRACTED
    assert (dest / "a.bin").read_bytes() == b"second"
    if folds:
        assert first.path is None
    else:
        assert first.path == dest / "A.bin"
        assert (dest / "A.bin").read_bytes()[:100] == _PAYLOAD[:100]


@pytest.mark.parametrize("first_damaged", [True, False], ids=["partial", "whole"])
@pytest.mark.parametrize("mode", _MODES)
def test_trusted_first_spelling_again_after_two_kept_partials(
    tmp_path: Path, mode: str, first_damaged: bool
) -> None:
    # Under TRUSTED and REPLACE: ``A.bin`` (damaged, or whole), the damaged
    # ``a.bin``, then a good member a filter maps to ``A.bin``. Where the filesystem
    # folds case, each later name lands over the one before, so every failed result
    # loses its path; a whole first member keeps its result, as TRUSTED reports no
    # collision. Where the names stay apart, only ``A.bin``'s file is replaced.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("A.bin", _PAYLOAD)
        zf.writestr("a.bin", _PAYLOAD)
        zf.writestr("good.bin", b"third")
    data = bytearray(buf.getvalue())
    for name in (b"A.bin", b"a.bin") if first_damaged else (b"a.bin",):
        # The first copy of the name is in its local header, just before its data.
        data[data.find(_PAYLOAD[:4096], data.find(name)) + 100] ^= 0xFF
    src = tmp_path / "three.zip"
    src.write_bytes(bytes(data))
    dest = tmp_path / "out"
    dest.mkdir()
    folds = not case_sensitive(dest)
    source, streaming = _source(src, mode)
    report = open_and_extract(
        source,
        dest,
        streaming=streaming,
        on_error=OnError.KEEP_PARTIAL,
        overwrite=OverwritePolicy.REPLACE,
        policy=ExtractionPolicy.TRUSTED,
        filter=lambda m: m.replace(name="A.bin") if m.name == "good.bin" else m,
    )
    first, second, third = report.results
    assert second.status is ExtractionStatus.FAILED
    assert third.status is ExtractionStatus.EXTRACTED
    assert (dest / "A.bin").read_bytes() == b"third"
    if first_damaged:
        assert first.status is ExtractionStatus.FAILED
        assert first.path is None
    else:
        assert first.status is ExtractionStatus.EXTRACTED
    if folds:
        assert second.path is None
    else:
        assert second.path == dest / "a.bin"
