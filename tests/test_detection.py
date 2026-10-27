"""Format-detection tests — Stage 1 + Stage 2 (Brotli content probe, weak zlib).

Inner-TAR / ISO probes and SFX scanning land with their backends in later stages.
"""

from __future__ import annotations

import io
import logging
import lzma
import random
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import ClassVar

import pytest

from archivey import (
    ArchiveFormat,
    DetectionConfidence,
    FormatInfo,
    detect_format,
    open_archive,
)
from archivey.config import ArchiveyConfig
from archivey.exceptions import FormatDetectionError
from archivey.internal.source import ArchiveSource
from archivey.internal.streams import codecs as codecs_module
from archivey.internal.streams.streamtools import source_name
from archivey.types import MagicSignature
from tests.conftest import requires, requires_binary, requires_zstd, zstd_backend
from tests.detection_cost_util import within_budget
from tests.streams_util import NonSeekableBytesIO

# LZMA Alone, zlib and Brotli are recognised only by a content probe, and by default a
# probe runs only when the source's name carries that format's extension. Tests of the
# probes themselves (nameless BytesIO, or a name that points elsewhere) turn them all on.
ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Magic-byte detection
# ---------------------------------------------------------------------------


def test_magic_match_is_certain() -> None:
    info = detect_format(io.BytesIO(_zip_bytes()))
    assert info == FormatInfo(ArchiveFormat.ZIP, DetectionConfidence.CERTAIN, "magic")


def test_zip_empty_archive_magic() -> None:
    # An empty ZIP is just the end-of-central-directory record (PK\x05\x06).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    info = detect_format(io.BytesIO(buf.getvalue()))
    assert info.format == ArchiveFormat.ZIP
    assert info.detected_by == "magic"


def _with_no_span_marker(data: bytes) -> bytes:
    """``data`` behind the 4-byte ``PK00`` marker, its directory offsets moved by 4."""
    out = bytearray(b"PK00" + data)
    eocd = out.rindex(b"PK\x05\x06")
    (directory,) = struct.unpack_from("<I", out, eocd + 16)
    struct.pack_into("<I", out, eocd + 16, directory + 4)
    at = directory + 4
    while out[at : at + 4] == b"PK\x01\x02":
        (offset,) = struct.unpack_from("<I", out, at + 42)
        struct.pack_into("<I", out, at + 42, offset + 4)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", out, at + 28)
        at += 46 + name_len + extra_len + comment_len
    return bytes(out)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_zip_no_span_marker_magic(pipe: bool) -> None:
    # APPNOTE 8.5.4: PKZIP may write PK00 before the first local header of a set that
    # ended up as one segment; 7-Zip and unzip read it as an ordinary ZIP.
    data = _with_no_span_marker(_zip_bytes())
    info = detect_format(io.BytesIO(data))
    assert info == FormatInfo(ArchiveFormat.ZIP, DetectionConfidence.CERTAIN, "magic")
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, streaming=pipe) as archive:
        assert [(m.name, s.read()) for m, s in archive.stream_members()] == [
            ("a.txt", b"hello")
        ]


def test_small_archive_still_detected() -> None:
    # A tiny ZIP (far smaller than any large probe window) is still detected by magic.
    data = _zip_bytes()
    assert len(data) < 4096
    assert detect_format(io.BytesIO(data)).format == ArchiveFormat.ZIP


# ---------------------------------------------------------------------------
# Extension fallback
# ---------------------------------------------------------------------------


def test_extension_only_is_guess(tmp_path: Path) -> None:
    # No magic match, but a .zip extension -> a GUESS by extension.
    path = tmp_path / "mystery.zip"
    path.write_bytes(b"not really a zip but ends in .zip")
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZIP
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


@pytest.mark.parametrize("ext", [".jar", ".pyz", ".whl", ".apk", ".cbz"])
def test_zip_family_extension_fallback(tmp_path: Path, ext: str) -> None:
    path = tmp_path / f"mystery{ext}"
    path.write_bytes(b"not really a zip")
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZIP
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


@pytest.mark.parametrize("ext", [".rar", ".cbr"])
def test_rar_family_extension_fallback(tmp_path: Path, ext: str) -> None:
    path = tmp_path / f"mystery{ext}"
    path.write_bytes(b"not really a rar")
    info = detect_format(path)
    assert info.format == ArchiveFormat.RAR
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


@pytest.mark.parametrize("ext", [".tar", ".cbt"])
def test_tar_family_extension_fallback(tmp_path: Path, ext: str) -> None:
    path = tmp_path / f"mystery{ext}"
    path.write_bytes(b"not really a tar")
    info = detect_format(path)
    assert info.format == ArchiveFormat.TAR
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


@pytest.mark.parametrize("ext", [".7z", ".cb7"])
def test_sevenz_family_extension_fallback(tmp_path: Path, ext: str) -> None:
    path = tmp_path / f"mystery{ext}"
    path.write_bytes(b"not really a 7z")
    info = detect_format(path)
    assert info.format == ArchiveFormat.SEVEN_Z
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


def test_unrecognized_bytes_no_name_raises() -> None:
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(b"this is not any known archive format at all"))


def test_unrecognized_extension_and_bytes_raises(tmp_path: Path) -> None:
    path = tmp_path / "data.unknownext"
    path.write_bytes(b"random bytes")
    with pytest.raises(FormatDetectionError):
        detect_format(path)


# ---------------------------------------------------------------------------
# Conflict resolution: magic wins, a warning is emitted
# ---------------------------------------------------------------------------


def _tar_bytes() -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("a.txt")
        payload = io.BytesIO(b"hello")
        info.size = 5
        t.addfile(info, payload)
    return buf.getvalue()


def _sevenz_sig() -> bytes:
    return b"7z\xbc\xaf'\x1c" + b"\x00" * 32


@pytest.mark.parametrize(
    ("name", "kind", "expected"),
    [
        ("mystery.cbr", "zip", ArchiveFormat.ZIP),
        ("mystery.cbz", "rar", ArchiveFormat.RAR),
        ("mystery.cbt", "zip", ArchiveFormat.ZIP),
        ("mystery.cb7", "zip", ArchiveFormat.ZIP),
        ("mystery.cbt", "rar", ArchiveFormat.RAR),
        ("mystery.cb7", "rar", ArchiveFormat.RAR),
        ("mystery.cbz", "tar", ArchiveFormat.TAR),
        ("mystery.cbr", "7z", ArchiveFormat.SEVEN_Z),
        ("mystery.cbt", "7z", ArchiveFormat.SEVEN_Z),
    ],
)
def test_comic_extension_content_wins_with_conflict(
    tmp_path: Path, name: str, kind: str, expected: ArchiveFormat
) -> None:
    from archivey.diagnostics import DiagnosticCode
    from archivey.internal.backends.rar_parser import RAR_ID

    payloads = {
        "zip": _zip_bytes(),
        "rar": RAR_ID,
        "tar": _tar_bytes(),
        "7z": _sevenz_sig(),
    }
    path = tmp_path / name
    path.write_bytes(payloads[kind])
    info = detect_format(path)
    assert info.format == expected
    assert info.confidence == DetectionConfidence.CERTAIN
    assert info.detected_by == "magic"
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in info.diagnostics.counts


def test_magic_wins_over_conflicting_extension(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Isolates the conflict machinery from real backends: magic says SEVEN_Z, the
    # ".rar" extension says RAR. Real comic-book alias conflicts are in
    # ``test_comic_extension_content_wins_with_conflict``.
    from archivey.internal import detection as detection_module
    from archivey.internal.base_reader import ReadBackend
    from archivey.internal.registry import BackendRegistry

    class _MagicBackend(ReadBackend):
        FORMATS = (ArchiveFormat.SEVEN_Z,)
        MAGIC = (MagicSignature(0, b"\x37\x7a\xbc\xaf\x27\x1c", ArchiveFormat.SEVEN_Z),)

        def open_read(self, *a, **k):  # pragma: no cover
            raise NotImplementedError

    class _ExtBackend(ReadBackend):
        FORMATS = (ArchiveFormat.RAR,)
        EXTENSIONS: ClassVar[dict[str, ArchiveFormat]] = {".rar": ArchiveFormat.RAR}

        def open_read(self, *a, **k):  # pragma: no cover
            raise NotImplementedError

    reg = BackendRegistry()
    reg.register_reader(_MagicBackend)
    reg.register_reader(_ExtBackend)
    monkeypatch.setattr(detection_module, "get_registry", lambda: reg)

    path = tmp_path / "thing.rar"
    path.write_bytes(b"\x37\x7a\xbc\xaf\x27\x1c" + b"\x00" * 32)
    with caplog.at_level(logging.WARNING, logger="archivey.detection"):
        info = detect_format(path)
    assert info.format == ArchiveFormat.SEVEN_Z
    assert info.detected_by == "magic"
    assert any("conflict" in r.getMessage().lower() for r in caplog.records), (
        caplog.text
    )


def test_no_warning_when_extension_agrees(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(_zip_bytes())
    with caplog.at_level(logging.WARNING, logger="archivey.detection"):
        detect_format(path)
    assert not caplog.records


# ---------------------------------------------------------------------------
# Detection never consumes bytes
# ---------------------------------------------------------------------------


def test_seekable_stream_rewound_to_zero() -> None:
    stream = io.BytesIO(_zip_bytes())
    detect_format(stream)
    assert stream.tell() == 0
    # The full stream is still readable from the start.
    assert stream.read(4) == b"\x50\x4b\x03\x04"


def test_peekable_stream_not_consumed() -> None:
    from archivey.internal.source import ArchiveSource

    data = _zip_bytes()
    stream = ArchiveSource.for_stream(NonSeekableBytesIO(data))
    info = detect_format(stream)
    assert info.format == ArchiveFormat.ZIP
    # Nothing consumed: the backend can still read the whole archive.
    assert stream.read(len(data)) == data


def test_path_source_not_left_open(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    # Detecting a path opens and closes its own handle; the file stays usable afterwards.
    detect_format(path)
    assert path.read_bytes()[:4] == b"\x50\x4b\x03\x04"


# ---------------------------------------------------------------------------
# Stage 2: Brotli content probe (magic-less) + weak zlib
# ---------------------------------------------------------------------------


@requires("brotli")
def test_brotli_detected_by_content_probe() -> None:
    import brotli

    data = brotli.compress(b"some brotli payload to decode")
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.BROTLI
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"


def test_brotli_probe_skipped_when_backend_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With the Brotli backend absent, the probe is skipped and detection falls back to the
    # .br extension guess rather than failing.
    monkeypatch.setattr(
        codecs_module.deps,
        "brotli",
        codecs_module.deps.LazyOptional("brotli", present=False),
    )
    path = tmp_path / "thing.br"
    path.write_bytes(b"not a brotli stream, just bytes")
    info = detect_format(path)
    assert info.format == ArchiveFormat.BROTLI
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"


def test_zlib_weak_magic_confirmed_by_content_probe() -> None:
    data = zlib.compress(b"zlib payload")
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.ZLIB
    # The weak 2-byte header is confirmed by a content probe -> PROBABLE / content_probe.
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"


def test_zlib_probe_wins_over_misleading_extension(tmp_path: Path) -> None:
    # A genuine zlib stream named .xz: the content probe confirms zlib, so the (wrong)
    # extension does not override it.
    path = tmp_path / "thing.xz"
    path.write_bytes(zlib.compress(b"payload"))
    info = detect_format(path, config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.ZLIB
    assert info.detected_by == "content_probe"


def test_weak_zlib_magic_without_valid_stream_falls_through(tmp_path: Path) -> None:
    # A 0x78 0x9c prefix on non-zlib data: the weak magic matches but the content probe
    # fails, so detection falls through to the extension guess instead of claiming zlib.
    path = tmp_path / "thing.xz"
    path.write_bytes(b"\x78\x9c" + b"\xff" * 200)  # zlib header byte, then garbage
    info = detect_format(path)
    assert info.format == ArchiveFormat.XZ
    assert info.detected_by == "extension"


def test_lzma_alone_detected_by_content_probe() -> None:
    import lzma

    data = lzma.compress(b"lzma alone payload " * 20, format=lzma.FORMAT_ALONE)
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"


def test_lzma_alone_probe_does_not_claim_lzip() -> None:
    from tests.streams_util import make_lzip_member

    info = detect_format(io.BytesIO(make_lzip_member(b"lzip payload")))
    assert info.format == ArchiveFormat.LZIP
    assert info.detected_by == "magic"


def test_lzma_alone_probe_does_not_steal_zlib() -> None:
    data = zlib.compress(b"zlib payload that must stay zlib")
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.ZLIB


# ---------------------------------------------------------------------------
# Stage 3: inner-TAR probe over a single-file compressor
# ---------------------------------------------------------------------------


def _tar_bytes() -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        t.addfile(info, io.BytesIO(b"hello"))
    return buf.getvalue()


def test_inner_tar_over_gzip_is_tar_gz() -> None:
    import gzip

    data = gzip.compress(_tar_bytes())
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.TAR_GZ
    # The inner-tar test is structural, weaker than an exact magic.
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"


def test_gzip_without_inner_tar_stays_bare_gz() -> None:
    import gzip

    data = gzip.compress(b"just some bytes, definitely not a tar header region")
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.GZ
    assert info.detected_by == "magic"


def test_inner_tar_over_xz_is_tar_xz() -> None:
    import lzma

    data = lzma.compress(_tar_bytes(), format=lzma.FORMAT_XZ)
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.TAR_XZ


@requires("ncompress")
def test_inner_tar_over_unix_compress_is_tar_z() -> None:
    """Bounded peek reader is seekable within its limit for inner-TAR upgrade."""
    from archivey.types import ContainerFormat, StreamFormat
    from tests.streams_util import make_unix_compress

    data = make_unix_compress(_tar_bytes())
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.UNIX_COMPRESS)
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"


@requires("ncompress")
def test_unix_compress_without_inner_tar_stays_bare_z() -> None:
    from tests.streams_util import make_unix_compress

    data = make_unix_compress(b"just some bytes, definitely not a tar header region")
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.Z
    assert info.detected_by == "magic"


@pytest.mark.parametrize(
    "hex_blob",
    [
        # Atheris detect_format finds (2026-07-14..15): consecutive LZW CLEARs share a
        # decompressed_offset; must not raise AssertionError during the inner-TAR probe.
        "1f9d9d001ffd37250000000000000000000000001b001f9d9d061ffd377a00df0000000900",
        "1f9d9d28a600000000000000000040f8000020000000ffff00000000f0",
        "1f9d9e9d009e58000000002600e38623a800288027",
        "1f9d8d8d00000000000000000000000000000000000000000000000000000000e2000000000000008d0000000000000000000000000000",
        "1f9d8b008b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e01000000100000035501000000000000035500e00008",
    ],
    ids=["clear-a", "clear-b", "clear-c", "clear-d", "clear-e"],
)
def test_detect_format_atheris_z_clear_collisions_do_not_assert(hex_blob: str) -> None:
    """Atheris: hostile .Z with consecutive CLEARs must not crash detect_format."""
    data = bytes.fromhex(hex_blob)
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.Z
    assert info.detected_by == "magic"


def test_inner_tar_over_lzma_alone_is_tar_lzma() -> None:
    import lzma

    from archivey.types import ContainerFormat, StreamFormat

    data = lzma.compress(_tar_bytes(), format=lzma.FORMAT_ALONE)
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)


def test_tlz_lzip_stays_tar_lzip(tmp_path: Path) -> None:
    from archivey.diagnostics import DiagnosticCode
    from archivey.types import ContainerFormat, StreamFormat
    from tests.streams_util import make_lzip_member

    path = tmp_path / "compat_lzip.tlz"
    path.write_bytes(make_lzip_member(_tar_bytes()))
    info = detect_format(path)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT not in info.diagnostics.counts


def test_tlz_alone_content_wins_with_extension_conflict(tmp_path: Path) -> None:
    import lzma

    from archivey.diagnostics import DiagnosticCode
    from archivey.types import ContainerFormat, StreamFormat

    # Default config: .tlz names LZIP, yet it also runs the LZMA Alone probe, so the
    # content still wins here without always_probe_content.
    path = tmp_path / "compat_lzma.tlz"
    path.write_bytes(lzma.compress(_tar_bytes(), format=lzma.FORMAT_ALONE))
    info = detect_format(path)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in info.diagnostics.counts


def _large_block_tar_bz2() -> bytes:
    """A ``.tar.bz2`` whose first bzip2 block is far larger than the detection prefix.

    bzip2 is block-transform (BWT) based: it emits *no* decompressed output until a whole
    block (up to 900 KB) has been read. A first member of incompressible data makes the
    first block's *compressed* size exceed ``DETECTION_LIMIT`` (4096), so the header region
    (``ustar`` at offset 257) is unreachable from the peeked prefix alone.
    """
    import bz2
    import os
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = os.urandom(200_000)  # incompressible => first block compresses poorly
        info = tarfile.TarInfo("first.bin")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return bz2.compress(buf.getvalue(), 9)


def test_inner_tar_over_bzip2_large_block_is_tar_bz2() -> None:
    # Regression: a tar.bz2 whose first block exceeds the 4 KiB detection prefix must still
    # be recognized as TAR_BZ2 — the probe reads a full block from the source, not just the
    # prefix. Previously this decoded to zero bytes and was mis-reported as bare BZ2.
    info = detect_format(io.BytesIO(_large_block_tar_bz2()))
    assert info.format == ArchiveFormat.TAR_BZ2
    assert info.detected_by == "content_probe"


def test_inner_tar_over_bzip2_large_block_non_seekable() -> None:
    # Same, from a non-seekable pipe wrapped as the opener does: the source's replay prefix buffers
    # enough of the prefix for the probe to reach the header region, and the source is not
    # consumed (the backend can still read the whole archive afterwards).
    from archivey.internal.source import ArchiveSource

    data = _large_block_tar_bz2()
    stream = ArchiveSource.for_stream(NonSeekableBytesIO(data))
    info = detect_format(stream)
    assert info.format == ArchiveFormat.TAR_BZ2
    assert stream.read(len(data)) == data


def test_bare_bzip2_large_block_stays_bare_bz2() -> None:
    # A large-block bare .bz2 that is NOT a tar must not be mis-promoted: the probe reads a
    # full block, finds no ustar, and reports bare BZ2 (bounded read, no false positive).
    import bz2
    import os

    data = bz2.compress(b"not a tar; " + os.urandom(200_000), 9)
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.BZ2
    assert info.detected_by == "magic"


def test_inner_tar_probe_skipped_when_codec_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With the zstd backend absent, a .tar.zst can't be probed: per the spec, detection
    # reports the *bare* compressor (ZST, by its magic) and defers the inner-TAR
    # determination to open time — without warning about the benign tar.zst/zst mismatch.
    monkeypatch.setattr(codecs_module.deps, "zstd", None)
    path = tmp_path / "thing.tar.zst"
    path.write_bytes(
        b"\x28\xb5\x2f\xfd" + b"\x00" * 64
    )  # zstd magic, unprobeable payload
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZST
    assert info.detected_by == "magic"


def test_deferred_inner_tar_does_not_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A .tar.gz whose payload is NOT a tar: magic says bare GZ, extension says TAR_GZ. That
    # benign (same-stream) mismatch must not emit a conflict warning.
    import gzip

    path = tmp_path / "thing.tar.gz"
    path.write_bytes(gzip.compress(b"not a tar at all"))
    with caplog.at_level(logging.WARNING, logger="archivey.detection"):
        info = detect_format(path)
    assert info.format == ArchiveFormat.GZ
    assert not caplog.records


# ---------------------------------------------------------------------------
# Stage 4: ISO extended-peek window (CD001 at offset 32 769)
# ---------------------------------------------------------------------------


@requires("pycdlib")
def test_iso_detected_via_extended_window() -> None:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_fp(io.BytesIO(b"x"), 1, "/X.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    info = detect_format(io.BytesIO(out.getvalue()))
    assert info.format == ArchiveFormat.ISO
    assert info.confidence == DetectionConfidence.CERTAIN
    assert info.detected_by == "magic"


def test_stream_too_short_for_iso_falls_through() -> None:
    # Far shorter than the 32 774-byte ISO window, and not any other format: ruled out as
    # ISO and raises FormatDetectionError (never rejected *solely* for being too short).
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(b"tiny non-archive payload"))


def test_small_zip_still_detected_despite_iso_probe() -> None:
    # A 2 KiB-ish ZIP is matched by its offset-0 magic without ever taking the ISO window.
    data = _zip_bytes()
    assert detect_format(io.BytesIO(data)).format == ArchiveFormat.ZIP


# ---------------------------------------------------------------------------
# Stream-position contract: detection reads from and restores the current position
# ---------------------------------------------------------------------------


def test_detection_from_mid_positioned_stream() -> None:
    # The archive starts wherever the caller positioned the stream: detection must peek
    # from there (an embedded archive after junk bytes) and restore the position.
    junk = b"JUNKJUNK" * 16
    stream = io.BytesIO(junk + _zip_bytes())
    stream.seek(len(junk))
    info = detect_format(stream)
    assert info.format == ArchiveFormat.ZIP
    assert stream.tell() == len(junk)  # starting position restored, not rewound to 0


# ---------------------------------------------------------------------------
# detection-format-gaps: formats archivey decodes but could not recognise
#
# ``confidence`` is documented as provisional (a graded-evidence regrade was decided
# against for 0.2.0 but could still come), so the durable pins here are ``format`` and
# ``detected_by``; a ``confidence`` assertion would be updated deliberately.
# ---------------------------------------------------------------------------


_ZSTD_SKIPPABLE_MAGIC = 0x184D2A50


def _skippable_frame(payload: bytes, *, magic: int = _ZSTD_SKIPPABLE_MAGIC) -> bytes:
    """One zstd skippable frame: magic, little-endian uint32 size, then the payload."""
    return struct.pack("<II", magic, len(payload)) + payload


def _zstd_frame(payload: bytes = b"zstd payload that compresses " * 40) -> bytes:
    return zstd_backend().compress(payload)


@requires_zstd()
def test_zstd_behind_one_skippable_frame() -> None:
    data = _skippable_frame(b"\x00\x00\x00\x00") + _zstd_frame()
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.ZST
    assert info.detected_by == "magic"
    assert info.confidence == DetectionConfidence.CERTAIN  # pre-ledger
    # The walk agrees with the decoder: this is a stream zstd itself reads.
    assert zstd_backend().decompress(data)


@requires_zstd()
def test_zstd_behind_chained_skippable_frames() -> None:
    # Differing payload sizes, so a fixed-stride walk would land in the wrong place.
    data = (
        _skippable_frame(b"a" * 4)
        + _skippable_frame(b"b" * 17)
        + _skippable_frame(b"c" * 4, magic=0x184D2A5F)  # the last legal skippable magic
        + _zstd_frame()
    )
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.ZST
    assert info.detected_by == "magic"
    assert zstd_backend().decompress(data)


def test_zstd_skippable_frames_alone_are_not_a_zstd_claim() -> None:
    # No regular frame means no compressed payload: claiming ZST here would open as one
    # fabricated empty member.
    data = _skippable_frame(b"x" * 10) + _skippable_frame(b"y" * 6)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


@requires_zstd()
def test_zstd_skippable_frame_larger_than_the_prefix_is_not_claimed() -> None:
    # A legal 1 MiB skippable frame: the walk cannot reach the frame behind it inside the
    # peeked prefix, and must decline rather than extend the read.
    data = struct.pack("<II", _ZSTD_SKIPPABLE_MAGIC, 1 << 20) + _zstd_frame()
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


def test_zstd_skippable_walk_arithmetic() -> None:
    # The walk itself: exact arithmetic over the peeked bytes, no decoding. `None` is the
    # declined answer (a declared size past the prefix), distinct from offset 0.
    from archivey.internal.streams.codecs.zstd_framing import skippable_prefix_end

    assert skippable_prefix_end(b"\x28\xb5\x2f\xfd" + b"\x00" * 32) == 0  # regular only
    assert skippable_prefix_end(b"\x00" * 64) == 0  # not a frame magic at all
    assert skippable_prefix_end(_skippable_frame(b"\x00" * 4) + b"tail") == 12
    chained = (
        _skippable_frame(b"a" * 4)
        + _skippable_frame(b"b" * 17)
        + _skippable_frame(b"c" * 4)
    )
    assert skippable_prefix_end(chained + b"tail") == 49
    assert skippable_prefix_end(chained) == 49  # skippable-only: an offset, not a claim
    assert (
        skippable_prefix_end(struct.pack("<II", _ZSTD_SKIPPABLE_MAGIC, 1 << 20)) is None
    )


@pytest.mark.parametrize("wbits", [9, 10, 11, 12, 13, 14, 15])
def test_zlib_detected_at_every_legal_window_size(wbits: int) -> None:
    # Six of the seven windows were missed by the four-entry header allow-list.
    compressor = zlib.compressobj(6, zlib.DEFLATED, wbits)
    data = compressor.compress(b"zlib payload " * 100) + compressor.flush()
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.ZLIB
    assert info.detected_by == "content_probe"


def test_zlib_grammar_accepts_a_preset_dictionary_header() -> None:
    # FDICT is a legal zlib header bit, so the gate must not reject it: whether archivey
    # can read the stream is the decode's answer, not the header's.
    compressor = zlib.compressobj(6, zlib.DEFLATED, 15, zdict=b"the quick brown fox")
    data = compressor.compress(b"payload " * 100) + compressor.flush()
    assert (data[1] >> 5) & 1, "fixture must actually set FDICT"
    assert codecs_module.zlib_codec._zlib_header_plausible(data)
    # archivey holds no preset dictionary, so the decode fails and the candidate falls
    # through — the "dictionary available" half of the grammar is unreachable from
    # detection until the codec layer can be handed one.
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


def test_zlib_grammar_admits_exactly_66_header_pairs() -> None:
    # Pins the derivation, not a hand-listed set: CM == 8, CINFO <= 7, mod-31 check.
    accepted = [
        (cmf, flg)
        for cmf in range(256)
        for flg in range(256)
        if codecs_module.zlib_codec._zlib_header_plausible(bytes((cmf, flg)))
    ]
    assert len(accepted) == 66
    assert sum(1 for _, flg in accepted if (flg >> 5) & 1) == 34  # FDICT set


def test_zlib_grammar_rejects_a_zeroed_header() -> None:
    # CM == 0 fails the grammar, so zero-filled padding never reaches the decode.
    assert not codecs_module.zlib_codec._zlib_header_plausible(b"\x00\x00")


def test_lzma_alone_declaring_zero_output_is_not_claimed() -> None:
    # 18 zero bytes are a *valid, complete, empty* Alone stream — a legal header (props
    # 0 = lc0/lp0/pb0, dictionary 0, declared size 0) plus a five-byte range-coder init,
    # which must begin with a zero. Zero-filled padding is everywhere in the founding
    # corpus, so a stream declaring no output must not be claimed: the header says there
    # is nothing to open, and only the header can say so here (the bounded probe reads
    # off the end of the trailing zeros and reports truncation, which reads as a match).
    for size in (18, 4097, 32768, 40000):
        with pytest.raises(FormatDetectionError):
            detect_format(io.BytesIO(b"\x00" * size))


def test_lzma_alone_zero_output_gate_costs_no_real_stream(tmp_path: Path) -> None:
    # Every liblzma producer writes the all-ones "unknown" sentinel — for empty input and
    # for known-size input alike — so the gate never fires on one.
    for payload in (b"", b"hello world", b"a" * (1 << 20)):
        header = lzma.compress(payload, format=lzma.FORMAT_ALONE)[:13]
        assert int.from_bytes(header[5:13], "little") == (1 << 64) - 1

    # A size-*known* stream must keep detecting — that is what the gate must not widen
    # into. The LZMA SDK's own lzma_alone writes the actual uncompressed size rather than
    # the sentinel (`LzmaUtil.c` File_GetLength -> the 8-byte field verbatim), and this
    # header shape was checked byte-for-byte against that tool's real output.
    payload = b"payload data " * 8
    known = bytearray(lzma.compress(payload, format=lzma.FORMAT_ALONE))
    known[5:13] = len(payload).to_bytes(8, "little")
    assert lzma.decompress(bytes(known), format=lzma.FORMAT_ALONE) == payload
    info = detect_format(io.BytesIO(bytes(known)), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"

    # Size 0 *is* producible by that same tool: a 0-byte input gives a real dictionary
    # with size 0. The gate costs that stream nothing, which is the point — it was never
    # claimed by the probe anyway (an empty decode is not a claim), and a `.lzma` name
    # still opens it. Verified against lzma_alone's real 18-byte output for /dev/null.
    sdk_empty = (
        bytes([0x5D])
        + (1 << 25).to_bytes(4, "little")
        + (0).to_bytes(8, "little")
        + b"\x00" * 5  # range-coder init
    )
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    assert decompressor.decompress(sdk_empty) == b""
    assert decompressor.eof  # genuinely a complete, empty stream

    assert (
        codecs_module.LzmaAloneCodec().content_probe(
            sdk_empty, source_length=len(sdk_empty)
        )
        is False
    )
    path = tmp_path / "empty.lzma"
    path.write_bytes(sdk_empty)
    info = detect_format(path)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "extension"


def test_lzma_alone_with_zero_dictionary_size_is_detected() -> None:
    # Every 32-bit dictionary value is legal; decoders round below 4 KiB up to 4 KiB.
    data = bytearray(lzma.compress(b"alone payload " * 50, format=lzma.FORMAT_ALONE))
    data[1:5] = b"\x00\x00\x00\x00"
    payload = bytes(data)
    assert lzma.decompress(payload, format=lzma.FORMAT_ALONE)  # the decoder accepts it
    info = detect_format(io.BytesIO(payload), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"


@pytest.mark.parametrize(
    ("props", "legal"),
    [(0x5D, True), (0x4C, True), (0x4D, True), (0x7F, True), (224, True), (225, False)],
)
def test_lzma_alone_header_gate_admits_the_formats_full_properties_range(
    props: int, legal: bool
) -> None:
    """The gate admits every legal properties byte, including the 150 liblzma refuses
    (``MZ``, COFF and ELF first bytes among them); the decode decides."""
    header = (
        bytes([props]) + (1 << 16).to_bytes(4, "little") + (6).to_bytes(8, "little")
    )
    assert codecs_module.lzma_codec._alone_header_plausible(header) is legal


@pytest.mark.parametrize(
    ("head", "run", "refused"),
    [
        (0, 16, True),
        (0, 15, False),  # one short of the run
        (31, 16, True),  # the last start inside the 32-byte span
        (32, 16, False),  # the first start outside it
    ],
)
def test_lzma_alone_zero_run_rule_boundaries(
    head: int, run: int, refused: bool
) -> None:
    header = bytes([0x5D]) + (1 << 16).to_bytes(4, "little") + b"\xff" * 8
    prefix = header + b"\x01" * head + b"\0" * run + b"\x01" * 64
    has_run = codecs_module.lzma_codec._alone_payload_has_zero_run(prefix)
    assert has_run is refused


_ALONE_HEADERS = [
    # props 0x5D, 64 KiB dictionary, unknown size: what liblzma writes.
    bytes([0x5D]) + (1 << 16).to_bytes(4, "little") + b"\xff" * 8,
    # ``ID3\x03\x00\x00`` + a syncsafe size: an ID3v2.3 tag read as an Alone header.
    b"ID3\x03\x00\x00\x00\x00\x10\x00\x00\x00\x00",
    # props 0 (lc=lp=pb=0), 16 MiB dictionary, a known size: what the LZMA SDK writes.
    bytes([0x00]) + (1 << 24).to_bytes(4, "little") + (1 << 20).to_bytes(8, "little"),
]


@pytest.mark.parametrize("header", _ALONE_HEADERS, ids=["liblzma", "id3", "sdk"])
@pytest.mark.parametrize("head", [b"", b"\x00\x01\x70"], ids=["zeros", "short-head"])
@pytest.mark.parametrize("size", [4096, 256 * 1024])
def test_lzma_alone_header_then_zero_run_is_not_claimed(
    header: bytes, head: bytes, size: int
) -> None:
    # A range coder fed zeros decodes zero literals without error, so these decode as a
    # valid stream; a short head before the run, as in ``00 01 70``, does not change that.
    # No measured encoder writes such a payload, so a zero run near the start is refused.
    data = header + head + b"\0" * (size - len(header) - len(head))
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    assert len(decoder.decompress(data, max_length=4096)) == 4096  # no error
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


@pytest.mark.parametrize("size", [1, 2, 3, 100, 1 << 20])
@pytest.mark.parametrize("preset", [0, 6, 9 | lzma.PRESET_EXTREME])
def test_lzma_alone_of_zeros_from_liblzma_is_still_detected(
    size: int, preset: int
) -> None:
    data = lzma.compress(b"\0" * size, format=lzma.FORMAT_ALONE, preset=preset)
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"


def test_lzma_alone_whose_payload_is_all_zeros_is_still_detected() -> None:
    # The LZMA SDK encoder (7-Zip) codes two zero bytes as seven zero bytes of payload:
    # two zero literals are all-zero bits, and the flush writes the still-zero low. It
    # is the longest zero run measured from a real encoder. Bytes as 7-Zip 23.01 wrote
    # them (``-m0=LZMA:d=64k``), under the header its lzma_alone tool would add.
    data = (
        bytes([0x5D])
        + (1 << 16).to_bytes(4, "little")
        + (2).to_bytes(8, "little")
        + b"\0" * 7
    )
    assert lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(data) == b"\0\0"
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"


def _sdk_lzma_alone(tmp_path: Path, payload: bytes, level: int) -> bytes:
    """An Alone file holding the LZMA SDK encoder's output for ``payload``.

    7-Zip cannot write ``.lzma`` itself, so this takes the LZMA1 packed stream out of a
    one-file ``.7z`` (it sits between the 32-byte signature header and the next header,
    which ``-mhc=off`` leaves uncompressed) and puts the 13-byte header in front.
    """
    src = tmp_path / "in.bin"
    src.write_bytes(payload)
    out = tmp_path / f"out{level}.7z"
    subprocess.run(
        [
            "7z", "a", "-t7z", f"-mx={level}", "-mhc=off", "-mf=off",
            "-m0=LZMA:d=64k:lc=3:lp=0:pb=2", str(out), str(src),
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    archive = out.read_bytes()
    packed = archive[32 : 32 + struct.unpack_from("<Q", archive, 12)[0]]
    header = bytes([0x5D]) + (1 << 16).to_bytes(4, "little")
    return header + len(payload).to_bytes(8, "little") + packed


@requires_binary("7z")
@pytest.mark.parametrize(
    "payload",
    [b"\0", b"\0\0", b"\0" * 1000, b"\0" * (1 << 20), b"A" * (1 << 20)],
    ids=["1-zero", "2-zeros", "1k-zeros", "1m-zeros", "1m-A"],
)
@pytest.mark.parametrize("level", [1, 5, 9])
def test_lzma_alone_of_zeros_from_the_lzma_sdk_is_still_detected(
    tmp_path: Path, payload: bytes, level: int
) -> None:
    data = _sdk_lzma_alone(tmp_path, payload, level)
    assert lzma.decompress(data, format=lzma.FORMAT_ALONE) == payload
    info = detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"


# --- far magic ahead of the content probes ---------------------------------------------

_ISO_SYSTEM_AREA = 32768


def _iso_bytes(system_area: bytes) -> bytes:
    """A real pycdlib ISO with its reserved system area overwritten.

    Only the reserved area changes — the filesystem stays byte-identical, so any other
    tool keeps reading the image.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_fp(io.BytesIO(b"x" * 32), 32, "/X.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = bytearray(out.getvalue())
    assert not any(data[:_ISO_SYSTEM_AREA]), (
        "pycdlib should leave the system area zeroed"
    )
    data[: len(system_area)] = system_area
    return bytes(data)


def _system_area_the_brotli_probe_accepts(source_length: int) -> bytes:
    """Boot-image-shaped system-area bytes the Brotli probe accepts, or ``pytest.skip``.

    A bootable or hybrid ISO reserves its first 32 KiB for a bootloader, and that data
    class — high-entropy packed code — is what the Brotli probe measurably accepts. The
    bytes are *searched* rather than hard-coded so this test cannot rot into a vacuous
    pass: if the probe stops accepting any candidate, it says so instead of passing
    because nothing claimed the image.
    """
    from archivey.internal.detection_workspace import DETECTION_LIMIT
    from archivey.internal.streams.codecs import BrotliCodec

    probe = BrotliCodec()
    for seed in range(256):
        candidate = random.Random(seed).randbytes(_ISO_SYSTEM_AREA)
        if probe.content_probe(
            candidate[:DETECTION_LIMIT], source_length=source_length
        ):
            return candidate
    pytest.skip(
        "no boot-shaped system area in the search range is accepted by the probe"
    )


@requires("pycdlib", "brotli")
def test_bootable_iso_is_not_claimed_by_the_content_probe() -> None:
    # The live wrong answer the reorder closes: exact magic sits at 32 769 the whole
    # time, and a probe hit on the boot area used to win, opening a whole filesystem as
    # one fabricated `*.uncompressed` member.
    length = len(_iso_bytes(b"\x00" * _ISO_SYSTEM_AREA))
    data = _iso_bytes(_system_area_the_brotli_probe_accepts(length))
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.ISO
    assert info.detected_by == "magic"
    assert info.confidence == DetectionConfidence.CERTAIN  # pre-ledger


@requires("pycdlib")
def test_zeroed_system_area_iso_still_detected() -> None:
    # Regression pin for removing the LZMA Alone zero-dictionary guard: a zero-filled
    # system area is exactly what that guard was covering, and far magic now answers it
    # before any probe runs.
    data = _iso_bytes(b"\x00" * _ISO_SYSTEM_AREA)
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.ISO
    assert info.detected_by == "magic"
    assert info.confidence == DetectionConfidence.CERTAIN  # pre-ledger


def test_small_source_takes_no_extended_peek(tmp_path: Path) -> None:
    # The far-magic step is size-gated: a source known to be smaller than the ISO window
    # never pays the 32 KiB peek. The receipt records what was actually fetched.
    path = tmp_path / "tiny.zip"
    path.write_bytes(b"tiny non-archive payload")
    info = detect_format(path)
    assert info.detected_by == "extension"
    assert info.cost_receipt is not None
    assert info.cost_receipt.unique_bytes_read <= 4096
    assert info.cost_receipt.far_bytes == 0


def test_detection_receipt_is_not_merged_into_archive_cost(tmp_path: Path) -> None:
    # Detection's I/O happens before a reader exists, so ``ar.cost`` must not absorb it.
    from archivey import open_archive

    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    info = detect_format(path)
    assert info.cost_receipt is not None
    assert info.cost_receipt.unique_bytes_read > 0
    with open_archive(path) as ar:
        # Archive-open CostReceipt is about listing/access axes, not detection bytes.
        assert ar.info.cost.listing_cost is not None
        assert not hasattr(ar.info.cost, "unique_bytes_read")
        assert not hasattr(ar.info.cost, "prefix_bytes")


def test_unknown_length_short_source_falls_through_to_the_extension(
    tmp_path: Path,
) -> None:
    # Unknown length, far too short for the ISO window: the far-magic step takes a short
    # peek, matches nothing and falls through — being short is never itself a rejection.
    from archivey.internal.source import ArchiveSource

    stream = ArchiveSource.for_stream(NonSeekableBytesIO(b"short mystery bytes"))
    with pytest.raises(FormatDetectionError):
        detect_format(stream)

    path = tmp_path / "short.zip"
    path.write_bytes(b"short mystery bytes")
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZIP
    assert info.detected_by == "extension"


# --- the conflict diagnostic names the evidence that actually won -----------------------
#
# Four branches outrank the extension and all four call ``_warn_on_conflict``, which used
# to say "magic bytes indicate X" from every one of them. These pin one message per branch
# so the wording cannot drift back to a single hardcoded claim.


def _conflict_message(path: Path) -> str:
    """The one ``FORMAT_EXTENSION_CONFLICT`` message ``detect_format`` emitted."""
    from archivey.diagnostics import DiagnosticCode

    info = detect_format(path)
    messages = [
        d.message
        for d in info.diagnostics.retained
        if d.code is DiagnosticCode.FORMAT_EXTENSION_CONFLICT
    ]
    assert len(messages) == 1, f"expected exactly one conflict, got {messages}"
    return messages[0]


def _assert_names_only(message: str, expected: str) -> None:
    """``message`` makes ``expected``'s claim and none of the other branches' claims.

    Asserting only that the right phrase is *present* would pass a regression that
    reintroduced one hardcoded claim for every branch, as long as the expected phrase
    survived somewhere in the string — which is close to the shape of the defect these
    tests exist to close. The shared tail is pinned here too, once, rather than in four
    places that could drift apart.

    ``expected`` stays a literal so the wording itself is pinned; the enum is consulted
    only to enumerate what must be *absent*, so a branch added later is excluded from
    every other branch's message without anyone remembering to update this list.
    """
    from archivey.internal import detection as detection_module

    phrases = {member.value for member in detection_module._ConflictEvidence}
    assert expected in phrases, f"{expected!r} is not one of {phrases}"
    assert expected in message, message
    for other in phrases - {expected}:
        assert other not in message, message
    assert message.endswith("; using that result over the extension."), message


def test_content_probe_conflict_names_the_probe_not_magic(tmp_path: Path) -> None:
    # The defect. On the probe branch "magic bytes indicate X" is false twice over: no
    # magic was read, and the answer that won is the weakest signal archivey has — the
    # one a reader deciding whether to believe us is most entitled to doubt.
    path = tmp_path / "compat_lzma.tlz"  # the extension says TAR_LZIP
    path.write_bytes(lzma.compress(_tar_bytes(), format=lzma.FORMAT_ALONE))
    message = _conflict_message(path)
    _assert_names_only(message, "content inspection indicates")
    # Stricter than the shared check on this branch alone: the word itself is the lie.
    assert "magic" not in message


def test_near_magic_conflict_still_names_magic(tmp_path: Path) -> None:
    path = tmp_path / "mislabelled.tlz"
    path.write_bytes(_zip_bytes())
    _assert_names_only(_conflict_message(path), "magic bytes indicate")


@requires("pycdlib")
def test_far_magic_conflict_names_magic(tmp_path: Path) -> None:
    # Far magic is exact magic too, just at an offset the default window does not reach,
    # so the near-magic wording is the right one to inherit.
    path = tmp_path / "mislabelled_iso.tlz"
    path.write_bytes(_iso_bytes(b"\x00" * _ISO_SYSTEM_AREA))
    _assert_names_only(_conflict_message(path), "magic bytes indicate")


def test_sfx_conflict_names_the_stub_scan(tmp_path: Path) -> None:
    # A scan hit is magic as well, but found where the other branches never look. Saying
    # so is the difference between "this file is not what its name claims" and "this file
    # has something in front of the archive", which are different things to go fix.
    path = tmp_path / "installer.tlz"
    path.write_bytes(b"MZ" + b"\x90" * 4094 + _zip_bytes())
    _assert_names_only(
        _conflict_message(path), "archive magic behind an executable stub indicates"
    )


# --- the detection cost ledger charges what detection does ------------------------------


def test_far_budget_below_the_iso_span_records_the_far_tier_as_cut_short(
    tmp_path: Path,
) -> None:
    # S19-K1: a positive ``max_far_bytes`` too small for CD001 used to peek a window that
    # could not match and record nothing, so a GUESS looked like a complete search.
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkipReason

    # Only the descriptor magic matters to detection, so no pycdlib (absent from the
    # minimal dependency configuration).
    image = bytearray(40_000)
    image[32768:32774] = b"\x01CD001"
    path = tmp_path / "disc.iso"
    path.write_bytes(bytes(image))
    assert detect_format(path).detected_by == "magic"
    budget = replace(BALANCED_BUDGET, max_far_bytes=4096)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.detected_by == "extension"
    assert any(
        s.tier == "far_magic" and s.reason is TierSkipReason.BUDGET_EXHAUSTED
        for s in info.unavailable_tiers
    ), info.unavailable_tiers
    # The unmatchable window is not peeked at all.
    assert info.cost_receipt is not None
    assert info.cost_receipt.far_bytes == 0


def test_far_budget_skip_is_not_recorded_for_a_source_too_short_for_the_iso_span() -> (
    None
):
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET

    budget = replace(BALANCED_BUDGET, max_far_bytes=4096)
    info = detect_format(
        io.BytesIO(_zip_bytes()), config=ArchiveyConfig(detection_budget=budget)
    )
    assert not any(s.tier == "far_magic" for s in info.unavailable_tiers)


def test_zero_far_budget_records_the_far_tier_as_not_enabled(tmp_path: Path) -> None:
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkip, TierSkipReason

    image = bytearray(40_000)
    image[32768:32774] = b"\x01CD001"
    path = tmp_path / "disc.iso"
    path.write_bytes(bytes(image))
    # A zero decode allowance adds a later tier's record, which pins the order.
    budget = replace(BALANCED_BUDGET, max_far_bytes=0, max_decode_input=0)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.detected_by == "extension"
    assert info.unavailable_tiers == (
        TierSkip("far_magic", TierSkipReason.NOT_ENABLED_BY_POLICY),
        TierSkip("content_probe", TierSkipReason.NOT_ENABLED_BY_POLICY),
    )
    assert info.cost_receipt is not None
    assert info.cost_receipt.far_bytes == 0


def test_stub_volume_fallback_keeps_the_stub_pass_cost(tmp_path: Path) -> None:
    # S19-K3: the stub pass runs the full SFX scan; its receipt and skips used to be
    # dropped in favour of the cheap second pass on the sibling volume.
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkip, TierSkipReason

    stub = tmp_path / "vol.exe"
    stub.write_bytes(b"MZ" + b"\x00" * (3 * 1024 * 1024))
    # Big enough that the volume pass takes a full near peek on top of the scan.
    (tmp_path / "vol.7z.001").write_bytes(_sevenz_sig() + b"\x00" * 8192)
    info = detect_format(stub)
    assert info.format == ArchiveFormat.SEVEN_Z
    receipt = info.cost_receipt
    assert receipt is not None
    assert receipt.scanned_bytes == BALANCED_BUDGET.max_scan_bytes
    assert receipt.unique_bytes_read > BALANCED_BUDGET.max_scan_bytes
    # Two passes, said as data, and each within its budget. The receipt is the stub
    # pass's work plus the volume pass's, not the stub pass's alone. That the oracle
    # needs both budgets is pinned on hand-built receipts, in
    # ``test_within_budget_judges_each_pass_against_its_own_budget``: the volume pass
    # here reads less than the SFX validator allowance, so a one-pass check passes too.
    assert receipt.passes == 2
    assert within_budget(receipt, BALANCED_BUDGET)
    # The same stub alone, named so the extension answers after its scan misses.
    (tmp_path / "alone").mkdir()
    lone = tmp_path / "alone" / "lone.7z"
    lone.write_bytes(stub.read_bytes())
    stub_only = detect_format(lone).cost_receipt
    assert stub_only is not None
    assert stub_only.passes == 1
    assert receipt.unique_bytes_read > stub_only.unique_bytes_read
    # A prefix budget below the near-magic span makes each pass record the same
    # ``near_magic`` skip; the receipt keeps it once.
    short_prefix = replace(BALANCED_BUDGET, max_prefix_bytes=64)
    info = detect_format(stub, config=ArchiveyConfig(detection_budget=short_prefix))
    assert info.format == ArchiveFormat.SEVEN_Z
    near_magic = TierSkip("near_magic", TierSkipReason.BUDGET_EXHAUSTED)
    assert info.unavailable_tiers.count(near_magic) == 1


def _incompressible_tar_bz2(first_member: int) -> bytes:
    import bz2
    import os
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = os.urandom(first_member)
        info = tarfile.TarInfo("first.bin")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return bz2.compress(buf.getvalue(), 9)


def test_inner_tar_probe_stays_inside_the_decode_budget() -> None:
    # S19-K5: the probe read up to 1 MiB of compressed input whatever
    # ``max_decode_input`` said, so FAST decoded ~900 KB against its 64 KiB.
    from archivey.detection_cost import (
        BALANCED_BUDGET,
        FAST_BUDGET,
        TierSkipReason,
    )

    data = _incompressible_tar_bz2(850_000)
    fast = detect_format(
        io.BytesIO(data), config=ArchiveyConfig(detection_budget=FAST_BUDGET)
    )
    assert fast.format == ArchiveFormat.BZ2
    assert fast.cost_receipt is not None
    assert fast.cost_receipt.decode_input <= FAST_BUDGET.max_decode_input
    assert within_budget(fast.cost_receipt, FAST_BUDGET), fast.cost_receipt
    assert any(
        s.tier == "inner_tar" and s.reason is TierSkipReason.BUDGET_EXHAUSTED
        for s in fast.unavailable_tiers
    ), fast.unavailable_tiers

    balanced = detect_format(
        io.BytesIO(data), config=ArchiveyConfig(detection_budget=BALANCED_BUDGET)
    )
    assert balanced.format == ArchiveFormat.TAR_BZ2
    assert not any(s.tier == "inner_tar" for s in balanced.unavailable_tiers)


def test_inner_tar_probe_charges_a_decode_that_fails() -> None:
    # S19-K5: the failure path returned before charging, so a decode that ran and then
    # raised billed nothing.
    import bz2

    good = bz2.compress(_tar_bytes(), 9)
    corrupt = bytearray(good)
    for i in range(10, len(corrupt) - 10):
        corrupt[i] ^= 0x5A
    info = detect_format(io.BytesIO(bytes(corrupt)))
    assert info.format == ArchiveFormat.BZ2
    assert info.cost_receipt is not None
    assert info.cost_receipt.decode_input > 0


def test_inner_tar_probe_is_skipped_when_the_output_budget_is_below_one_header() -> (
    None
):
    # The probe always asks for one 512-byte TAR header block, so an output budget
    # below that would be overspent the moment the probe ran.
    import bz2
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkipReason

    budget = replace(BALANCED_BUDGET, max_decode_output=256)
    info = detect_format(
        io.BytesIO(bz2.compress(_tar_bytes(), 9)),
        config=ArchiveyConfig(detection_budget=budget),
    )
    assert info.format == ArchiveFormat.BZ2
    assert info.cost_receipt is not None
    assert info.cost_receipt.decode_input == 0
    assert info.cost_receipt.decode_output == 0
    assert within_budget(info.cost_receipt, budget)
    assert any(
        s.tier == "inner_tar" and s.reason is TierSkipReason.BUDGET_EXHAUSTED
        for s in info.unavailable_tiers
    )


def test_inner_tar_probe_is_off_when_the_decode_budget_is_zero() -> None:
    import bz2
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkipReason

    budget = replace(BALANCED_BUDGET, max_decode_input=0, max_decode_output=0)
    info = detect_format(
        io.BytesIO(bz2.compress(_tar_bytes(), 9)),
        config=ArchiveyConfig(detection_budget=budget),
    )
    assert info.format == ArchiveFormat.BZ2
    assert info.cost_receipt is not None
    assert info.cost_receipt.decode_input == 0
    assert any(
        s.tier == "inner_tar" and s.reason is TierSkipReason.NOT_ENABLED_BY_POLICY
        for s in info.unavailable_tiers
    )


def test_sfx_miss_in_a_budget_shortened_window_records_the_scan_as_cut_short(
    tmp_path: Path,
) -> None:
    # Round 2 review: a FAST scan (256 KiB) missed a payload at 1 MiB and recorded
    # nothing, so the extension guess read as a complete search.
    from archivey.detection_cost import (
        BALANCED_BUDGET,
        FAST_BUDGET,
        TierSkip,
        TierSkipReason,
    )

    path = tmp_path / "x.zip"
    path.write_bytes(b"MZ" + b"\x00" * (1024 * 1024 - 2) + _zip_bytes())
    cut_short = TierSkip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED)

    balanced = detect_format(
        path, config=ArchiveyConfig(detection_budget=BALANCED_BUDGET)
    )
    assert balanced.detected_by == "sfx_scan"
    assert cut_short not in balanced.unavailable_tiers

    fast = detect_format(path, config=ArchiveyConfig(detection_budget=FAST_BUDGET))
    assert fast.detected_by == "extension"
    assert cut_short in fast.unavailable_tiers

    # A BALANCED miss on a source longer than SFX_MAX: the structural bound ended
    # the scan, not the budget, so nothing is recorded.
    long_miss = tmp_path / "stub.zip"
    long_miss.write_bytes(b"MZ" + b"\x00" * (3 * 1024 * 1024))
    missed = detect_format(
        long_miss, config=ArchiveyConfig(detection_budget=BALANCED_BUDGET)
    )
    assert missed.detected_by == "extension"
    assert cut_short not in missed.unavailable_tiers
    assert (
        cut_short
        in detect_format(
            long_miss, config=ArchiveyConfig(detection_budget=FAST_BUDGET)
        ).unavailable_tiers
    )


def test_sfx_miss_in_a_source_shorter_than_the_window_is_not_cut_short(
    tmp_path: Path,
) -> None:
    from archivey.detection_cost import FAST_BUDGET

    path = tmp_path / "stub.zip"
    path.write_bytes(b"MZ" + b"\x00" * 8190)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=FAST_BUDGET))
    assert info.detected_by == "extension"
    assert not any(s.tier == "sfx_scan" for s in info.unavailable_tiers)


def test_zero_max_scan_bytes_records_sfx_scan_not_enabled(tmp_path: Path) -> None:
    # A zero field turns its tier off, recorded as not enabled like the other tiers,
    # not as a search the budget cut short.
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkip, TierSkipReason

    path = tmp_path / "x.zip"
    path.write_bytes(b"MZ" + b"\x00" * 4094 + _zip_bytes())
    # The control: under the default budget the scan finds the appended payload.
    found = detect_format(path, config=ArchiveyConfig(detection_budget=BALANCED_BUDGET))
    assert found.detected_by == "sfx_scan"
    assert not any(s.tier == "sfx_scan" for s in found.unavailable_tiers)
    budget = replace(BALANCED_BUDGET, max_scan_bytes=0)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.detected_by == "extension"
    sfx = [s for s in info.unavailable_tiers if s.tier == "sfx_scan"]
    assert sfx == [TierSkip("sfx_scan", TierSkipReason.NOT_ENABLED_BY_POLICY)]


def test_zero_max_prefix_bytes_records_near_magic_not_enabled(tmp_path: Path) -> None:
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET, TierSkip, TierSkipReason

    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    found = detect_format(path, config=ArchiveyConfig(detection_budget=BALANCED_BUDGET))
    assert found.detected_by == "magic"
    budget = replace(BALANCED_BUDGET, max_prefix_bytes=0)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.detected_by == "extension"
    near = [s for s in info.unavailable_tiers if s.tier == "near_magic"]
    assert near == [TierSkip("near_magic", TierSkipReason.NOT_ENABLED_BY_POLICY)]


@pytest.mark.parametrize("as_str", [False, True])
def test_detect_format_reports_directory_for_a_directory_path(
    tmp_path: Path, as_str: bool
) -> None:
    """A directory is DIRECTORY, as open_archive reads it, not an IsADirectoryError."""
    tree = tmp_path / "tree"
    tree.mkdir()
    info = detect_format(str(tree) if as_str else tree)
    assert info.format == ArchiveFormat.DIRECTORY
    assert info.confidence is DetectionConfidence.CERTAIN
    assert info.detected_by == "directory"


def test_detect_format_directory_carries_a_zero_receipt(tmp_path: Path) -> None:
    info = detect_format(tmp_path)
    assert info.cost_receipt is not None
    assert info.cost_receipt.unique_bytes_read == 0
    assert info.cost_receipt.passes == 1


def test_content_probes_share_one_decode_allowance() -> None:
    # The probes draw on ``max_decode_input`` as the inner-TAR probe does, so a budget
    # that allows no decoding runs no probe, and one that runs out stops them.
    from dataclasses import replace

    from archivey.config import DEFAULT_ARCHIVEY_CONFIG
    from archivey.detection_cost import (
        BALANCED_BUDGET,
        TierSkip,
        TierSkipReason,
    )
    from archivey.internal.detection import _detect_format_body
    from archivey.internal.detection_cost_receipt import MutableDetectionCostReceipt
    from archivey.internal.diagnostics_collector import collector_from_config
    from archivey.internal.registry import get_registry

    data = zlib.compress(b"zlib payload")
    probes = [fmt for fmt, _ in get_registry().content_probes()]
    # Each probe ahead of zlib is charged its sample, so zlib needs one sample per
    # probe up to and including itself.
    zlib_needs = (probes.index(ArchiveFormat.ZLIB) + 1) * len(data)

    def detect(
        max_decode_input: int,
    ) -> tuple[FormatInfo | None, MutableDetectionCostReceipt]:
        budget = replace(BALANCED_BUDGET, max_decode_input=max_decode_input)
        receipt = MutableDetectionCostReceipt()
        collector = collector_from_config(DEFAULT_ARCHIVEY_CONFIG)
        try:
            info = _detect_format_body(
                io.BytesIO(data), collector, budget, receipt, always_probe=True
            )
        except FormatDetectionError:
            info = None
        return info, receipt

    info, receipt = detect(0)
    assert info is None
    assert receipt.decode_input == 0
    assert TierSkip("content_probe", TierSkipReason.NOT_ENABLED_BY_POLICY) in (
        receipt.skips
    )

    info, receipt = detect(zlib_needs - 1)
    assert info is None
    assert receipt.decode_input <= zlib_needs - 1
    assert TierSkip("content_probe", TierSkipReason.BUDGET_EXHAUSTED) in receipt.skips

    info, receipt = detect(zlib_needs)
    assert info is not None and info.format == ArchiveFormat.ZLIB
    assert receipt.decode_input == zlib_needs


def test_reader_keeps_the_detection_it_opened_by(tmp_path: Path) -> None:
    from archivey import open_archive

    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"hello")
    with open_archive(path) as reader:
        info = reader.format_info
        assert info == detect_format(path)
        assert info is not None and info.detected_by == "magic"

    # format= skips detection, so there is nothing to report.
    with open_archive(path, format=ArchiveFormat.ZIP) as reader:
        assert reader.format_info is None

    tree = tmp_path / "tree"
    tree.mkdir()
    with open_archive(tree) as reader:
        # cost_receipt is compare=False on FormatInfo, so check it separately: both
        # paths share one answer, zero receipt included.
        assert reader.format_info == detect_format(tree)
        assert reader.format_info is not None
        assert reader.format_info.cost_receipt == detect_format(tree).cost_receipt


def _budget_config() -> ArchiveyConfig:
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET

    return ArchiveyConfig(
        detection_budget=replace(BALANCED_BUDGET, max_scan_bytes=64 * 1024),
        # Non-None on purpose: the probe configs must not inherit it, and the
        # ``on_diagnostic is None`` assertions only mean something if it is set here.
        on_diagnostic=lambda _diagnostic: None,
    )


def _record_detect(
    monkeypatch: pytest.MonkeyPatch, module: object
) -> list[tuple[str, ArchiveyConfig | None]]:
    """Record each call through ``module.detect_format`` as (source name, config).

    A resolved source is named as ``open_archive`` names it: a joined split set by
    its first part.
    """
    calls: list[tuple[str, ArchiveyConfig | None]] = []
    real = module.detect_format

    def recording(source: object, *args: object, **kwargs: object) -> FormatInfo:
        config = kwargs.get("config")
        assert config is None or isinstance(config, ArchiveyConfig)
        name = source_name(source) if isinstance(source, ArchiveSource) else source
        calls.append((Path(str(name)).name, config))
        return real(source, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(module, "detect_format", recording)
    return calls


def test_format_argument_stub_checks_detect_under_the_config_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``format=``, the stub-only check and the stub/first-volume conflict check
    both run detection. They spend the caller's budget, and nothing else of the
    caller's config reaches them (a discarded probe's diagnostics are not the
    reader's)."""
    import archivey.core as core_module
    from archivey import open_archive

    stub = tmp_path / "vol.exe"
    stub.write_bytes(b"MZ" + b"\x00" * 1022)
    data = (Path(__file__).parent / "fixtures" / "sevenzip" / "lz4.7z").read_bytes()
    half = len(data) // 2
    (tmp_path / "vol.7z.001").write_bytes(data[:half])
    (tmp_path / "vol.7z.002").write_bytes(data[half:])
    config = _budget_config()
    calls = _record_detect(monkeypatch, core_module)
    with open_archive(stub, format=ArchiveFormat.SEVEN_Z, config=config) as reader:
        assert any(m.is_file for m in reader)
    assert sorted(name for name, _ in calls) == ["vol.7z.001", "vol.exe"]
    for _name, probe in calls:
        assert probe is not None and probe is not config
        assert probe.detection_budget is config.detection_budget
        assert probe.on_diagnostic is None


def test_empty_listing_rescan_detects_under_the_config_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rescan that words an empty-listing advisory under ``format=`` spends the
    caller's budget, and only that."""
    from archivey import open_archive
    from archivey.internal import detection as detection_module

    config = _budget_config()
    calls = _record_detect(monkeypatch, detection_module)
    path = tmp_path / "zeros.tar"
    path.write_bytes(b"\x00" * (32 * 1024))
    with open_archive(path, format=ArchiveFormat.TAR, config=config) as reader:
        assert list(reader) == []
    assert [name for name, _ in calls] == ["zeros.tar"]
    probe = calls[0][1]
    assert probe is not None and probe is not config
    assert probe.detection_budget is config.detection_budget
    assert probe.on_diagnostic is None


def test_empty_listing_rescan_stays_internal(tmp_path: Path) -> None:
    """Under a policy that raises on the conflict, the rescan's own findings neither
    reach the caller nor raise inside it: an empty ZIP named ``x.tar.gz`` opened with ``format=ZIP`` reports the
    empty archive and nothing else, because detection does identify it as ZIP."""
    from archivey import open_archive
    from archivey.diagnostics import Diagnostic, DiagnosticCode, DiagnosticPolicy

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    path = tmp_path / "x.tar.gz"
    path.write_bytes(buf.getvalue())
    seen: list[Diagnostic] = []
    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on=frozenset({DiagnosticCode.FORMAT_EXTENSION_CONFLICT})
        ),
        on_diagnostic=seen.append,
    )
    with open_archive(path, format=ArchiveFormat.ZIP, config=config) as reader:
        assert list(reader) == []
    assert [d.code for d in seen] == [DiagnosticCode.EMPTY_ARCHIVE]


def test_open_archive_detects_under_the_config_budget(tmp_path: Path) -> None:
    """``ArchiveyConfig.detection_budget`` reaches the detection ``open_archive`` runs."""
    from dataclasses import replace

    from archivey import open_archive
    from archivey.detection_cost import BALANCED_BUDGET

    path = tmp_path / "payload.bin"
    path.write_bytes(b"MZ" + b"\x00" * (64 * 1024) + _zip_bytes())
    with open_archive(path) as reader:
        assert reader.format == ArchiveFormat.ZIP

    narrow = ArchiveyConfig(
        detection_budget=replace(BALANCED_BUDGET, max_scan_bytes=16 * 1024)
    )
    with pytest.raises(FormatDetectionError):
        open_archive(path, config=narrow)
    with pytest.raises(FormatDetectionError):
        detect_format(path, config=narrow)


def test_empty_source_says_it_is_empty(tmp_path: Path) -> None:
    for source in (io.BytesIO(b""), NonSeekableBytesIO(b"")):
        with pytest.raises(FormatDetectionError, match="no bytes to read"):
            detect_format(source)
    # Detection reads from the current position, so a non-empty file whose handle is
    # at its end has nothing to read either; the message must not call it empty.
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello world, not an archive at all")
    with path.open("rb") as f:
        f.seek(0, io.SEEK_END)
        with pytest.raises(FormatDetectionError) as caught:
            detect_format(f)
    assert "positioned at its end" in str(caught.value)
    with pytest.raises(FormatDetectionError, match="no magic bytes"):
        detect_format(io.BytesIO(b"plain text, not an archive"))


def test_mutable_receipt_freezes_every_public_counter() -> None:
    """The mutable receipt and ``freeze()`` agree with the public receipt's counters.

    Both write the field list out by hand. A counter added to the public receipt and
    missed in one of them would read 0 on every ``FormatInfo.cost_receipt``; this
    fails instead.
    """
    from dataclasses import fields

    from archivey.detection_cost import DetectionCostReceipt
    from archivey.internal.detection_cost_receipt import MutableDetectionCostReceipt

    public = [f.name for f in fields(DetectionCostReceipt)]
    mutable = [f.name for f in fields(MutableDetectionCostReceipt)]
    # ``skips`` is reported on its own, not in the frozen receipt.
    assert [name for name in mutable if name != "skips"] == public

    # Each counter a distinct value, so a swapped or dropped copy shows.
    receipt = MutableDetectionCostReceipt(
        **{name: 1000 + i for i, name in enumerate(public)}
    )
    frozen = receipt.freeze()
    assert {name: getattr(frozen, name) for name in public} == {
        name: 1000 + i for i, name in enumerate(public)
    }
