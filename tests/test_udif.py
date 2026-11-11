"""UDIF disk images (``.dmg``) are recognised by the ``koly`` block and refused.

A compressed image's first block is a real zlib, bzip2 or xz stream. Detection used to
stop there, extract that one block and call the rest of the image trailing data. The
``koly`` block — 12 bytes at offset 0, or at the start of the last 512 — is the image,
and the block codec is a member of it. Reading the image is a separate feature.
"""

from __future__ import annotations

import bz2
import io
import lzma
import random
import zipfile
import zlib
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    StreamCapability,
    UnsupportedFeatureError,
    detect_format,
    format_availability,
    list_known_formats,
    list_supported_formats,
    open_archive,
)
from archivey.internal.registry import get_registry
from archivey.types import FormatSupport
from tests.streams_util import NonSeekableBytesIO

# 7-Zip's ``IsKoly``: "koly", version 4, header size 512, all big-endian.
_KOLY = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")
_TRAILER = 512
# zlib has no magic, so a nameless pipe reaches it only with every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def _udif(payload: bytes) -> bytes:
    """A UDIF image whose data fork is ``payload`` and whose trailer is ``koly``."""
    trailer = bytearray(_TRAILER)
    trailer[: len(_KOLY)] = _KOLY
    return payload + bytes(trailer)


def _udif_wrong_version(payload: bytes) -> bytes:
    image = bytearray(_udif(payload))
    image[-_TRAILER + 4 : -_TRAILER + 8] = (3).to_bytes(4, "big")
    return bytes(image)


def test_a_zlib_first_block_is_refused_instead_of_extracted(tmp_path: Path) -> None:
    # The backup-scan failure: the first block decodes, the open reports success, and
    # the rest of the image is trailing data.
    payload = b"sector" * 80
    path = tmp_path / "disk.dmg"
    path.write_bytes(_udif(zlib.compress(payload)))
    with pytest.raises(UnsupportedFeatureError, match="UDIF") as ei:
        open_archive(path)
    assert ei.value.archive_name is not None
    info = detect_format(path)
    assert info.format == ArchiveFormat.DMG
    assert info.confidence.name == "CERTAIN"
    assert info.detected_by == "magic"


def test_bzip2_and_xz_first_blocks_are_the_image_too(tmp_path: Path) -> None:
    # Those two codecs have exact magic, so a near-magic hit would win before any probe.
    # The trailer has to outrank that hit: the magic is one block of the image.
    cases = {
        "disk-bz2.dmg": bz2.compress(b"bz2-block"),
        "disk-xz.dmg": lzma.compress(b"xz-block", format=lzma.FORMAT_XZ),
    }
    for name, payload in cases.items():
        path = tmp_path / name
        path.write_bytes(_udif(payload))
        info = detect_format(path)
        assert info.format == ArchiveFormat.DMG, name
        with pytest.raises(UnsupportedFeatureError, match="UDIF"):
            open_archive(path)


def test_a_koly_header_at_offset_zero_is_the_same_image(tmp_path: Path) -> None:
    # Old images put the koly block first. The same 12 bytes, no tail read required.
    path = tmp_path / "front.dmg"
    path.write_bytes(_KOLY + b"\x00" * 500)
    info = detect_format(path)
    assert info.format == ArchiveFormat.DMG
    assert info.detected_by == "magic"
    with pytest.raises(UnsupportedFeatureError, match="UDIF"):
        open_archive(io.BytesIO(path.read_bytes()))


def test_a_real_compressor_stream_is_unchanged(tmp_path: Path) -> None:
    payload = b"plain-stream"
    streams = {
        "data.zz": zlib.compress(payload),
        "data.bz2": bz2.compress(payload),
        "data.xz": lzma.compress(payload, format=lzma.FORMAT_XZ),
    }
    for name, blob in streams.items():
        path = tmp_path / name
        path.write_bytes(blob)
        with open_archive(path) as reader:
            assert reader.read(next(iter(reader))) == payload


def test_wrong_koly_version_is_not_a_disk_image(tmp_path: Path) -> None:
    payload = b"still-zlib"
    path = tmp_path / "not-udif.zz"
    path.write_bytes(_udif_wrong_version(zlib.compress(payload)))
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZLIB
    with open_archive(path) as reader:
        assert reader.read(next(iter(reader))) == payload


def test_a_zip_named_dmg_stays_a_zip(tmp_path: Path) -> None:
    # The name is not the format. Only the koly block is.
    import zipfile

    path = tmp_path / "actually.zip.dmg"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"zip")
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZIP
    with open_archive(path) as reader:
        assert reader.read("a.txt") == b"zip"


def test_explicit_compressor_format_still_reads_the_first_block(tmp_path: Path) -> None:
    # ``format=`` skips detection. The refusal is the auto-detect answer.
    payload = b"asked-for-zlib"
    blob = _udif(zlib.compress(payload))
    with open_archive(io.BytesIO(blob), format=ArchiveFormat.ZLIB) as reader:
        assert reader.read(next(iter(reader))) == payload


def test_explicit_dmg_format_is_refused() -> None:
    with pytest.raises(UnsupportedFeatureError, match="UDIF"):
        open_archive(io.BytesIO(b"not an image"), format=ArchiveFormat.DMG)
    with pytest.raises(UnsupportedFeatureError, match="UDIF"):
        open_archive(io.BytesIO(b"not an image"), format="dmg")


def test_a_non_seekable_source_cannot_see_the_trailer() -> None:
    # The trailer is at the end. A pipe is not rewound to look for it. An image
    # longer than the far-magic window stays a zlib stream: that window is read
    # when the length is unknown, and it still ends before the block. A shorter
    # image is refused, because the same read already holds the block.
    payload = b"piped"
    compressed = zlib.compress(payload)
    blob = _udif(compressed + b"\x00" * 40_000)
    with open_archive(
        NonSeekableBytesIO(blob), streaming=True, config=_ALWAYS_PROBE
    ) as reader:
        assert reader.format == ArchiveFormat.ZLIB
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == payload


@pytest.mark.parametrize(
    ("compression", "expected"),
    [
        # A stored entry is a slice of the ZIP: its end is as cheap as a file's.
        (zipfile.ZIP_STORED, ArchiveFormat.DMG),
        # A deflated entry would decode all of itself to reach its end.
        (zipfile.ZIP_DEFLATED, ArchiveFormat.BZ2),
    ],
)
def test_a_member_stream_shows_its_trailer_when_its_end_is_cheap(
    compression: int, expected: ArchiveFormat
) -> None:
    blob = _udif(bz2.compress(random.Random(9).randbytes(200_000)))
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", compression) as archive:
        archive.writestr("disk.dmg", blob)
    outer.seek(0)
    with (
        open_archive(outer, seekable_members=True) as reader,
        reader.open("disk.dmg") as member,
    ):
        assert detect_format(member).format == expected


def test_detection_restores_the_stream_position() -> None:
    blob = _udif(zlib.compress(b"pos"))
    stream = io.BytesIO(blob)
    assert detect_format(stream).format == ArchiveFormat.DMG
    assert stream.tell() == 0
    with pytest.raises(UnsupportedFeatureError):
        open_archive(stream)
    assert stream.tell() == 0


def test_dmg_is_known_and_not_supported() -> None:
    availability = format_availability(ArchiveFormat.DMG)
    assert availability.support is FormatSupport.NONE
    assert availability.missing == ()
    # FORWARD_ONLY so the spool recipe does not copy a file open refuses either way.
    assert availability.required_source is StreamCapability.FORWARD_ONLY
    assert ArchiveFormat.DMG in list_known_formats()
    assert ArchiveFormat.DMG not in list_supported_formats()


def test_reader_for_format_refuses_dmg_without_an_archive_name() -> None:
    """The registry raise is the same text, and it has no archive name.

    ``open_archive`` refuses first so the exception can carry the name. This is
    the path a direct ``reader_for_format`` call actually takes.
    """
    with pytest.raises(UnsupportedFeatureError, match="UDIF") as excinfo:
        get_registry().reader_for_format(ArchiveFormat.DMG)
    assert excinfo.value.archive_name is None


def test_an_iso_payload_with_a_koly_trailer_is_the_iso() -> None:
    """Far magic runs first, so an ISO 9660 disk inside a UDIF image is that ISO."""
    data = bytearray(40_000)
    data[32768] = 1
    data[32769:32774] = b"CD001"
    info = detect_format(io.BytesIO(_udif(bytes(data))))
    assert info.format is ArchiveFormat.ISO
    assert info.detected_by == "magic"
