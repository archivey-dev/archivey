"""Reproducers for defects found by `scripts/scan_archives.py` over a real backup tree.

The scan dry-ran 57 390 archives; `dev-docs/investigations/2026-10-backup-scan.md` has
the counts and the clusters these come from. The inputs here are synthetic: each one is
built from the structure that the real files shared, never from their content.

Each test asserts the behaviour a fix should give. A test whose defect still stands is
marked ``xfail(strict=True)`` and the ``reason`` names it; the marker comes off when the
fix lands, so an unmarked test pins a fix, or the mechanism a reproducer relies on.

The probe reproducers pass ``always_probe_content=True``: by default a nameless source
runs no content probe, so they would pass without reaching the probe they pin.
"""

from __future__ import annotations

import io
import lzma
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CompressionAlgorithm,
    DiagnosticCode,
    DiagnosticPolicy,
    FormatDetectionError,
    MemberType,
)
from archivey.diagnostics import LocalHeaderContext, raw_name_to_base64
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    EncryptionError,
    UnsupportedFeatureError,
)
from archivey.internal import detection
from archivey.internal.hashing import crc32_digest
from archivey.internal.streams import codecs as codecs_module
from archivey.types import HashAlgorithm
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO
from tests.zip_aes_fixture import build_aes_zip

# --- LZMA Alone: zero runs decode as an endless stream of zero literals. -------------
#
# The Alone probe checks the 13-byte header, then decodes a sample and requires output.
# A range coder fed zero bytes decodes zero literals without error, so any header that
# passes the gate and is followed by a zero run used to be accepted. Random blobs, which
# the spec's "0 in 20 000" measurement used, never contain such runs; real files often do.
# The probe now refuses a zero run at the start of the range-coder data.

_SYNCSAFE_MASK = 0x7F


def _syncsafe(n: int) -> bytes:
    return bytes((n >> shift) & _SYNCSAFE_MASK for shift in (21, 14, 7, 0))


def _id3v23_mp3_with_padding() -> bytes:
    """An MP3 whose ID3v2.3 tag holds only padding, followed by MPEG audio frames.

    ``ID3`` reads as Alone properties 0x49 (lc=1, lp=3, pb=1, legal), ``D3 03 00`` as a
    209 732-byte dictionary, and the zero padding as range-coder data. The scan found 55
    such MP3s (and some ``.jar`` and ``.data`` files) reported as ``raw_stream.lzma``.
    """
    padding = b"\0" * 2048
    tag = b"ID3\x03\x00\x00" + _syncsafe(len(padding)) + padding
    # An MPEG-1 Layer III frame header, then frame data that is not zero.
    audio = bytes([0xFF, 0xFB, 0x90, 0x64]) + bytes(range(256)) * 64
    return tag + audio


_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def test_id3_tagged_mp3_is_not_lzma_alone() -> None:
    with pytest.raises(FormatDetectionError):
        archivey.detect_format(
            io.BytesIO(_id3v23_mp3_with_padding()), config=ALWAYS_PROBE
        )


def test_a_nameless_mp3_reaches_no_probe_by_default() -> None:
    # The scan's MP3s had names; a nameless one never reaches a content probe at all.
    with pytest.raises(FormatDetectionError, match="always_probe_content"):
        archivey.detect_format(io.BytesIO(_id3v23_mp3_with_padding()))


def test_ole_magic_then_zeros_is_not_lzma_alone() -> None:
    # 0xD0 is legal Alone properties (lc=1, lp=3, pb=4). OLE files (.doc, .xls, .msi,
    # Thumbs.db) are sector-aligned and often hold long zero runs early on. The OLE
    # signature stops the content probes, so the Alone probe never sees this input.
    data = _OLE_MAGIC + b"\0" * 4088
    with pytest.raises(FormatDetectionError):
        archivey.detect_format(io.BytesIO(data), config=ALWAYS_PROBE)
    # The probe refuses it on its own too: the stopping signature is defence in depth.
    probe = codecs_module.LzmaAloneCodec().content_probe
    assert probe(data, source_length=len(data)) is False


def test_zero_run_after_an_alone_header_decodes_without_error() -> None:
    # Pins the mechanism the probe's zero-run check guards against: liblzma itself
    # accepts this, so only the probe can refuse it.
    header = bytes.fromhex("5d00001000ffffffffffffffff")
    out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
        header + b"\0" * 4096, max_length=1 << 16
    )
    assert out == b"\0" * (1 << 16)


# --- Brotli on OLE files: the OLE signature stops the content probes. --------------


@requires("brotli")
def test_ole_header_then_zeros_is_not_brotli() -> None:
    # The first 32 bytes every version-3 compound file starts with: magic, a zero CLSID,
    # minor version 0x3E, major version 3, byte-order mark 0xFFFE, sector shift 9.
    header = _OLE_MAGIC + b"\0" * 16 + struct.pack("<HHHH", 0x3E, 3, 0xFFFE, 9)
    data = header + b"\0" * (256 * 1024 - len(header))
    with pytest.raises(FormatDetectionError):
        archivey.detect_format(io.BytesIO(data), config=ALWAYS_PROBE)


def _ole_header() -> bytes:
    return _OLE_MAGIC + b"\0" * 16 + struct.pack("<HHHH", 0x3E, 3, 0xFFFE, 9)


def test_ole_file_with_an_archive_extension_still_gets_the_extension_guess(
    tmp_path: Path,
) -> None:
    # The OLE signature stops the content probes only. The extension fallback still
    # runs, as it does after a confirmed executable.
    path = tmp_path / "mislabelled.br"
    path.write_bytes(_ole_header() + b"\0" * (64 * 1024))
    info = archivey.detect_format(path)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "extension"


def _small_zip() -> bytes:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("embedded.txt", b"embedded object\n")
    return inner.getvalue()


def test_ole_file_holding_a_zip_is_not_scanned_as_self_extracting() -> None:
    # An OLE file is not an executable stub, so its signature does not start the SFX
    # scan. A ZIP stored inside a document is part of the document, not its payload.
    data = _ole_header() + b"\0" * 2016 + _small_zip() + b"\0" * (64 * 1024)
    with pytest.raises(FormatDetectionError):
        archivey.detect_format(io.BytesIO(data))


def test_a_probe_stopping_signature_also_stops_the_sfx_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The rule holds for every entry, not only for OLE, whose signature raises no
    # executable cue. A signature that starts with ``MZ`` raises a weak cue; the scan
    # would find the ZIP behind it and report the file as that ZIP.
    signature = b"MZ-not-an-archive"
    monkeypatch.setattr(
        detection, "_PROBE_STOPPING_SIGNATURES", ((signature, "a test signature"),)
    )
    data = signature + b"\0" * 2000 + _small_zip() + b"\0" * (64 * 1024)
    with pytest.raises(FormatDetectionError):
        archivey.detect_format(io.BytesIO(data))


def test_the_error_names_the_signature_that_stopped_the_probes() -> None:
    data = _OLE_MAGIC + b"\0" * 4088
    with pytest.raises(FormatDetectionError, match="OLE compound file"):
        archivey.detect_format(io.BytesIO(data))


# --- ZIP: the central directory and the local header disagree. ---------------------


def _one_member_zip(
    data: bytes,
    *,
    central_name: bytes = b"member.bin",
    local_name: bytes | None = None,
    central_crc: int | None = None,
    declared_size: int | None = None,
    deflate: bool = False,
    local_method: int | None = None,
    central_method: int | None = None,
) -> bytes:
    """One member whose local header differs from its central entry as asked.

    ``local_name`` defaults to ``central_name``. ``local_method`` and ``central_method``
    replace the method in that header only. ``central_crc`` replaces the CRC in the
    central directory only; the local header keeps the true one. ``declared_size``
    replaces the uncompressed size in both headers; the CRC stays that of all of
    ``data``.
    """
    if local_name is None:
        local_name = central_name
    crc = zlib.crc32(data)
    if deflate:
        packer = zlib.compressobj(9, zlib.DEFLATED, -15)
        body = packer.compress(data) + packer.flush()
    else:
        body = data
    method = 8 if deflate else 0
    size = len(data) if declared_size is None else declared_size
    dos_date = 0x21  # 1980-01-01
    lfh = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0,
            method if local_method is None else local_method,
            0,
            dos_date,
            crc,
            len(body),
            size,
            len(local_name),
            0,
        )
        + local_name
        + body
    )
    cdh = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            20,
            0,
            method if central_method is None else central_method,
            0,
            dos_date,
            crc if central_crc is None else central_crc,
            len(body),
            size,
            len(central_name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + central_name
    )
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cdh), len(lfh), 0)
    return lfh + cdh + eocd


def _read_only_member(
    blob: bytes,
    *,
    pipe: bool = False,
    strict: bool = False,
    policy: DiagnosticPolicy | None = None,
) -> bytes:
    if strict:
        policy = DiagnosticPolicy.STRICT
    config = ArchiveyConfig(diagnostic_policy=policy) if policy else ArchiveyConfig()
    if pipe:
        with archivey.open_archive(
            NonSeekableBytesIO(blob), streaming=True, config=config
        ) as ar:
            read = []
            for _, stream in ar.stream_members():
                assert stream is not None
                read.append(stream.read())
            (data,) = read
            # The directory, which the pass reads after the member, can still fail
            # it; the report says.
            assert ar.members_report().error is None
            return data
    with archivey.open_archive(io.BytesIO(blob), config=config) as ar:
        (member,) = ar.members()
        with ar.open(member) as stream:
            return stream.read()


def _local_header_reports(blob: bytes, *, pipe: bool) -> list[LocalHeaderContext]:
    """What the member reported about its local header, once its data was read."""
    source = NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    with archivey.open_archive(source, streaming=pipe) as ar:
        if pipe:
            for _, stream in ar.stream_members():
                assert stream is not None
                stream.read()
            (member,) = ar.members_report().members
        else:
            (member,) = ar.members()
            ar.read(member)
    return [
        diagnostic.context
        for diagnostic in member.diagnostics
        if diagnostic.code
        in (
            DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS,
            DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS,
            DiagnosticCode.MEMBER_LOCAL_CRC_USED,
        )
        and isinstance(diagnostic.context, LocalHeaderContext)
    ]


# Case 1 and 2 of the maintainer's ruling (2026-10-10, ``native-zip-reader`` design.md,
# question A): read. Case 1 reports ``MEMBER_LOCAL_NAME_DIFFERS``, which STRICT refuses;
# case 2 reports ``MEMBER_LOCAL_CRC_USED``, which STRICT reads (2026-10-15).


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_local_name_in_another_codepage_still_reads(pipe: bool) -> None:
    # Seen in the scan: the central directory holds 0xF4 (ô in Latin-1/cp1252) and the
    # local header 0x93 (ô in cp437/cp850), both without the UTF-8 flag. Archivey takes
    # every name from the central directory, so the local copy decides nothing else.
    blob = _one_member_zip(
        b"payload", central_name=b"Patag\xf4nia.mp3", local_name=b"Patag\x93nia.mp3"
    )
    assert _read_only_member(blob, pipe=pipe) == b"payload"
    (context,) = _local_header_reports(blob, pipe=pipe)
    assert context.field == "name"
    assert context.local_raw_name_base64 == raw_name_to_base64(b"Patag\x93nia.mp3")
    assert context.local_crc32 is None
    with pytest.raises(DiagnosticRaisedError):
        _read_only_member(blob, pipe=pipe, strict=True)


def _directory_codes(blob: bytes, *, pipe: bool, policy: DiagnosticPolicy) -> list[str]:
    """The codes the one directory member of ``blob`` carries once a read has gone
    through its data: ``read()`` from a file, the pass from a pipe."""
    source = NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    config = ArchiveyConfig(diagnostic_policy=policy)
    with archivey.open_archive(source, streaming=pipe, config=config) as ar:
        if pipe:
            for _ in ar.stream_members():
                pass
            report = ar.members_report()
            assert report.error is None
            (member,) = report.members
        else:
            (member,) = ar.members()
            if member.size:
                assert ar.read(member) == b"x" * member.size
    assert (member.name, member.type) == ("crack/", MemberType.DIRECTORY)
    return sorted(str(diagnostic.code) for diagnostic in member.diagnostics)


@pytest.mark.parametrize("data", [b"", b"x" * 22], ids=["empty", "with-data"])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_local_name_with_a_backslash_names_a_directory_without_a_report(
    pipe: bool, data: bytes
) -> None:
    # Seen in the scan: ``crack/`` in the directory, ``crack\\`` in the local header.
    # A directory's name decides nothing its local header could change, and
    # extraction reads no directory's data, so neither read reports it, even under
    # a policy that raises on the code, and even when ``read()`` has gone through
    # declared data.
    blob = _one_member_zip(data, central_name=b"crack/", local_name=b"crack\\")
    policy = DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS})
    codes = _directory_codes(blob, pipe=pipe, policy=policy)
    assert codes == ([] if not data else ["member_directory_data_ignored"])


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_zero_central_crc_over_directory_data_reads_alike(pipe: bool) -> None:
    # A directory keeps no digest when its CRC-32 field is 0, whatever the local
    # header says: the bytes ``read()`` gives are unchecked from a file, and the pass
    # does not count the local value against the directory's 0.
    blob = _one_member_zip(b"x" * 22, central_name=b"crack/", central_crc=0)
    codes = _directory_codes(blob, pipe=pipe, policy=DiagnosticPolicy())
    assert codes == ["digest_unverifiable", "member_directory_data_ignored"]


# The local header and the directory name different compression methods. The member
# decodes by the local method, which sits next to the data and is the one a pipe has, so
# a file and a pipe read the same bytes (maintainer ruling 2026-10-21: the local header
# is the likelier to be right). It reports ``MEMBER_LOCAL_METHOD_DIFFERS``, which STRICT
# refuses. The CRC-32 still checks the bytes. The listing keeps the directory's method,
# as it keeps every field. unzip, 7-Zip and stdlib ``zipfile`` differ on this shape.

_METHOD_TEXT = b"hello world " * 450


@pytest.mark.parametrize(
    ("deflate", "central_method"),
    [(False, 8), (True, 0), (True, 12)],
    ids=[
        "directory-deflate-over-stored",
        "directory-stored-over-deflate",
        "directory-bzip2-number-over-deflate",
    ],
)
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_local_method_that_differs_decodes_by_the_local_header(
    pipe: bool, deflate: bool, central_method: int
) -> None:
    # The body and the local header agree; only the directory names another method.
    blob = _one_member_zip(_METHOD_TEXT, deflate=deflate, central_method=central_method)
    assert _read_only_member(blob, pipe=pipe) == _METHOD_TEXT
    (context,) = _local_header_reports(blob, pipe=pipe)
    assert (context.field, context.local_method, context.central_method) == (
        "method",
        8 if deflate else 0,
        central_method,
    )
    assert (context.local_raw_name_base64, context.local_crc32) == (None, None)
    with pytest.raises(DiagnosticRaisedError):
        _read_only_member(blob, pipe=pipe, strict=True)


def test_the_listing_keeps_the_directory_method() -> None:
    """``compression`` and ``extra["zip.compress_type"]`` come from the directory, as
    every listed field does (a CRC-32 of 0 aside). The diagnostic carries both
    methods."""
    blob = _one_member_zip(_METHOD_TEXT, deflate=True, central_method=0)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert ar.read(member) == _METHOD_TEXT
        assert member.extra["zip.compress_type"] == 0
        assert [method.algo for method in member.compression] == [
            CompressionAlgorithm.STORED
        ]


def test_a_method_difference_is_reported_once_per_member() -> None:
    """A second open reports nothing more by default, and still raises under STRICT,
    as the name report does."""
    blob = _one_member_zip(_METHOD_TEXT, central_method=8)
    code = DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        ar.read(member)
        ar.read(member)
        assert ar.diagnostics.counts[code] == 1
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with archivey.open_archive(io.BytesIO(blob), config=config) as ar:
        (member,) = ar.members()
        for _ in range(2):
            with pytest.raises(DiagnosticRaisedError):
                ar.read(member)


@pytest.mark.parametrize("data", [b"", b"x" * 22], ids=["empty", "with-data"])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_directory_whose_headers_name_different_methods_reports_nothing(
    pipe: bool, data: bytes
) -> None:
    # As for the name: extraction reads no directory's data, so neither read reports
    # it, even under a policy that raises on the code.
    blob = _one_member_zip(data, central_name=b"crack/", central_method=8)
    policy = DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS})
    codes = _directory_codes(blob, pipe=pipe, policy=policy)
    assert codes == ([] if not data else ["member_directory_data_ignored"])


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_local_method_that_does_not_fit_the_data_is_corruption(pipe: bool) -> None:
    # The local header says stored over a deflated body, as in the shape unzip fails
    # with exit 2: decoding by the local method gives bytes the CRC-32 refuses, or
    # fewer than the declared size, from a file and a pipe alike.
    blob = _one_member_zip(_METHOD_TEXT, deflate=True, local_method=0)
    with pytest.raises(CorruptionError):
        _read_only_member(blob, pipe=pipe)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_method_difference_is_reported_on_a_member_that_fails_its_crc(
    pipe: bool,
) -> None:
    """The directory names another method and another CRC-32. A file read reports the
    method as it opens the member, then refuses the data on the directory's CRC-32;
    the pass reads the data by the local header and fails the member at the end, on
    the CRC-32 the headers disagree on. Both report the method once and raise."""
    blob = _one_member_zip(_METHOD_TEXT, central_method=8, central_crc=0x1234_5678)
    source = NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    with archivey.open_archive(source, streaming=pipe) as ar:
        try:
            with pytest.raises(CorruptionError, match="(?i)crc"):
                if pipe:
                    for _, stream in ar.stream_members():
                        assert stream is not None
                        stream.read()
                else:
                    ar.read("member.bin")
        finally:
            counts = ar.diagnostics.counts
    assert counts[DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS] == 1


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_method_difference_beside_an_overlapping_size_differs_by_read(
    pipe: bool,
) -> None:
    """The directory names another method and a compressed size that runs past the
    directory's start. A file read's overlap guard refuses the member while checking
    its local header, before any report; the pass, which keeps no such bound, reports
    the method and fails the member at the end on the sizes. A recorded difference
    (DR-5a): both raise ``CorruptionError``, only the pass reports."""
    blob = bytearray(_one_member_zip(_METHOD_TEXT, central_method=8))
    struct.pack_into("<I", blob, blob.index(b"PK\x01\x02") + 20, len(_METHOD_TEXT) * 2)
    source = NonSeekableBytesIO(bytes(blob)) if pipe else io.BytesIO(bytes(blob))
    match = "bytes stored against" if pipe else "Overlapped entries"
    with archivey.open_archive(source, streaming=pipe) as ar:
        try:
            with pytest.raises(CorruptionError, match=match):
                if pipe:
                    for _, stream in ar.stream_members():
                        assert stream is not None
                        stream.read()
                else:
                    ar.read("member.bin")
        finally:
            counts = ar.diagnostics.counts
    assert counts.get(DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS, 0) == (
        1 if pipe else 0
    )


def test_a_damaged_local_header_is_refused_before_an_unsupported_method() -> None:
    """The open checks the local header, the overlap guard included, before it looks
    up the codec: a member whose method no reader supports and whose local header is
    damaged raises the damage."""
    blob = bytearray(_one_member_zip(b"payload", local_method=77, central_method=77))
    blob[0] ^= 0xFF  # the local header's signature
    with archivey.open_archive(io.BytesIO(bytes(blob)), format=ArchiveFormat.ZIP) as ar:
        (member,) = ar.members()
        with pytest.raises(CorruptionError, match="Bad magic number"):
            ar.read(member)


def _drain_aes(blob: bytes, *, pipe: bool) -> None:
    """Read every member of the WinZip AES ``blob`` with the right password, and
    check, whatever it raises, that no method difference was reported."""
    source = NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    with archivey.open_archive(source, streaming=pipe, password=b"pw") as ar:
        try:
            if pipe:
                for _, stream in ar.stream_members():
                    if stream is not None:
                        stream.read()
            else:
                ar.read("a.txt")
        finally:
            counts = ar.diagnostics.counts
            assert DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS not in counts


def _aes_record_method_offsets(blob: bytes) -> list[int]:
    """Where each 0x9901 record's real-method field sits: local first, then central."""
    found, start = [], 0
    while (at := blob.find(b"\x01\x99\x07\x00", start)) != -1:
        found.append(at + 4 + 5)  # tag, size, then version (2), "AE" (2), strength (1)
        start = at + 1
    return found


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_winzip_aes_in_the_directory_only_is_corruption(pipe: bool) -> None:
    """Method 99 in the directory and 8 in the local header: the AES record is the
    directory's, so the headers disagree on the encryption and a file read refuses the
    member. A pipe has the local header alone, which says ZipCrypto (bit 0, method 8),
    so the AES data fails its check byte there: refused too, as a wrong password.
    Neither reports a method difference."""
    blob = bytearray(build_aes_zip([(b"a.txt", b"h" * 22)], password=b"pw"))
    struct.pack_into("<H", blob, 8, 8)  # the local header's method
    expected = (
        pytest.raises(EncryptionError)
        if pipe
        else pytest.raises(CorruptionError, match="disagree on its encryption")
    )
    with expected:
        _drain_aes(bytes(blob), pipe=pipe)


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_winzip_aes_in_the_local_header_only_is_corruption(pipe: bool) -> None:
    """Method 99 in the local header and 8 in the directory: a file read refuses it on
    the headers. The pass decodes by the local AES record and fails the member at the
    end, once the directory disagrees. Both raise ``CorruptionError`` and neither
    reports a method difference."""
    blob = bytearray(build_aes_zip([(b"a.txt", b"h" * 22)], password=b"pw"))
    struct.pack_into("<H", blob, blob.index(b"PK\x01\x02") + 10, 8)
    with pytest.raises(CorruptionError) as caught:
        _drain_aes(bytes(blob), pipe=pipe)
    assert not isinstance(caught.value, EncryptionError)


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_winzip_aes_records_naming_different_methods_are_corruption(
    pipe: bool,
) -> None:
    """Method 99 in both headers, but the local AES record says stored where the
    directory's says deflate. A file read refuses the member on the records. The pass
    decodes by the local record; both sizes are set to the deflated length, so the
    stored "decode" of AE-2 data, which no CRC-32 checks, matches every size, and the
    member fails at the end of the pass on the records."""
    blob = bytearray(build_aes_zip([(b"a.txt", b"h" * 2000)], password=b"pw"))
    local_field, central_field = _aes_record_method_offsets(bytes(blob))
    assert struct.unpack_from("<H", blob, central_field) == (8,)
    struct.pack_into("<H", blob, local_field, 0)
    central = blob.index(b"PK\x01\x02")
    (stored_size,) = struct.unpack_from("<I", blob, 18)
    deflated = stored_size - 16 - 2 - 10  # salt (AES-256), check value, HMAC
    struct.pack_into("<I", blob, 22, deflated)
    struct.pack_into("<I", blob, central + 24, deflated)
    with pytest.raises(CorruptionError, match="AES compression method 0 against 8"):
        _drain_aes(bytes(blob), pipe=pipe)


def _aes_zip_with_a_patched_record(
    *, offset: int, value: int, size: int = 1, central: bool = False, **build: int
) -> bytes:
    """A one-member WinZip AES ZIP whose local (or ``central``) 0x9901 record has
    ``value`` written ``offset`` bytes into it: -4 is the tag, 0 the version, 4 the
    strength."""
    blob = bytearray(build_aes_zip([(b"a.txt", b"h" * 2000)], password=b"pw", **build))
    local_field, central_field = _aes_record_method_offsets(bytes(blob))
    at = (central_field if central else local_field) - 5 + offset
    blob[at : at + size] = value.to_bytes(size, "little")
    return bytes(blob)


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(
    ("build", "offset", "value", "differ", "pipe_error"),
    [
        # A local key length the right password does not fit: refused mid-pass.
        ({}, 4, 1, "AES key strength 1 against 3", EncryptionError),
        ({"strength": 1}, 4, 3, "AES key strength 3 against 1", EncryptionError),
        # AE-1 checks a CRC-32 that AE-2 data leaves at 0: refused mid-pass.
        ({}, 0, 1, "AE-1 against AE-2", "CRC-32 mismatch"),
        # AE-2 checks no CRC-32, so the pass reads the data and refuses the member at
        # its end, on the records.
        ({"vendor_version": 1}, 0, 2, "AE-2 against AE-1", "AE-2 against AE-1"),
    ],
    ids=["strength-1-over-3", "strength-3-over-1", "ae1-over-ae2", "ae2-over-ae1"],
)
def test_winzip_aes_records_that_differ_in_any_field_are_corruption(
    pipe: bool,
    build: dict[str, int],
    offset: int,
    value: int,
    differ: str,
    pipe_error: str | type[Exception],
) -> None:
    """Method 99 in both headers and the same real method, but another AES version
    or strength in the local record. A file read decodes by the central record and
    the pass by the local one, so a file read refuses the member on the records,
    naming the field; the pass refuses it too, mid-pass or at its end."""
    blob = _aes_zip_with_a_patched_record(
        offset=offset, value=value, size=2 if offset == 0 else 1, **build
    )
    expected: type[Exception] = CorruptionError
    match = differ
    if pipe and isinstance(pipe_error, type):
        expected, match = pipe_error, "Wrong password"
    elif pipe:
        match = pipe_error
    with pytest.raises(expected, match=match):
        _drain_aes(blob, pipe=pipe)


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(
    ("offset", "value", "central"),
    [(-4, 0x9902, False), (4, 7, False), (-4, 0x9902, True)],
    ids=["local-tag", "local-strength", "central-tag"],
)
def test_a_missing_winzip_aes_record_is_named(
    pipe: bool, offset: int, value: int, central: bool
) -> None:
    """Method 99 in both headers, but one side's 0x9901 record is absent (another
    tag) or unparseable (strength 7). A file read names the side that lacks it; a
    pipe, which decodes by the local record, refuses a missing local one as
    unsupported before the directory arrives, and names a missing central one at
    the end of the pass."""
    blob = _aes_zip_with_a_patched_record(
        offset=offset, value=value, size=2 if offset == -4 else 1, central=central
    )
    side = "the directory" if central else "the local header"
    expected: type[Exception] = CorruptionError
    match = f"{side} holds no valid WinZip AES record"
    if pipe and not central:
        expected, match = UnsupportedFeatureError, "without a valid WinZip AES"
    with pytest.raises(expected, match=match) as caught:
        _drain_aes(blob, pipe=pipe)
    assert "None" not in str(caught.value)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_zero_central_crc_with_a_right_local_crc_reads(pipe: bool) -> None:
    # Every .air package in the scan (6) stores ``META-INF/AIR/hash`` this way: the
    # packager writes the 32-byte hash after the central entry was made.
    blob = _one_member_zip(b"h" * 32, central_name=b"META-INF/AIR/hash", central_crc=0)
    assert _read_only_member(blob, pipe=pipe) == b"h" * 32
    (context,) = _local_header_reports(blob, pipe=pipe)
    assert (context.field, context.local_crc32) == ("crc32", zlib.crc32(b"h" * 32))
    assert context.local_raw_name_base64 is None
    # The data is still checked, against the local value, so STRICT reads it; only a
    # policy that raises on the code itself refuses it.
    assert _read_only_member(blob, pipe=pipe, strict=True) == b"h" * 32
    with pytest.raises(DiagnosticRaisedError):
        _read_only_member(blob, pipe=pipe, policy=DiagnosticPolicy.PEDANTIC)


def test_zero_central_crc_reports_the_local_crc_as_the_digest() -> None:
    """The listing, before any read, carries the value the data is checked against."""
    blob = _one_member_zip(b"h" * 32, central_name=b"META-INF/AIR/hash", central_crc=0)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        counts = ar.diagnostics.counts
    assert member.hashes == {HashAlgorithm.CRC32: crc32_digest(zlib.crc32(b"h" * 32))}
    assert counts[DiagnosticCode.MEMBER_LOCAL_CRC_USED] == 1


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_zero_central_crc_with_a_wrong_local_crc_is_still_corruption(
    pipe: bool,
) -> None:
    # The local value stands in for the directory's 0; the data is still checked.
    blob = bytearray(
        _one_member_zip(b"h" * 32, central_name=b"META-INF/AIR/hash", central_crc=0)
    )
    blob[14] ^= 0xFF  # the local header's CRC-32
    with pytest.raises(CorruptionError):
        _read_only_member(bytes(blob), pipe=pipe)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_zero_crc_in_both_headers_over_data_is_still_corruption(pipe: bool) -> None:
    # Nothing stands in: both copies say 0 and the data's CRC-32 is not 0.
    blob = bytearray(
        _one_member_zip(b"h" * 32, central_name=b"META-INF/AIR/hash", central_crc=0)
    )
    blob[14:18] = b"\0\0\0\0"
    with pytest.raises(CorruptionError):
        _read_only_member(bytes(blob), pipe=pipe)


@requires("cryptography")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_ae2_zero_central_crc_ignores_a_local_crc(pipe: bool) -> None:
    """AE-2 stores CRC-32 0 by design and its HMAC checks the data, so a non-zero
    local CRC-32 stands in for nothing: no digest and no report, from a file or a pipe."""
    blob = bytearray(build_aes_zip([(b"a.txt", b"h" * 22)], password=b"pw"))
    assert blob[14:18] == b"\0\0\0\0"  # the local header's CRC-32
    blob[14:18] = struct.pack("<I", zlib.crc32(b"h" * 22))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    source = NonSeekableBytesIO(bytes(blob)) if pipe else io.BytesIO(bytes(blob))
    with archivey.open_archive(
        source, streaming=pipe, password="pw", config=config
    ) as ar:
        if pipe:
            read = [stream.read() for _, stream in ar.stream_members() if stream]
            (member,) = ar.members_report().members
        else:
            (member,) = ar.members()
            read = [ar.read(member)]
        counts = ar.diagnostics.counts
    assert read == [b"h" * 22]
    assert member.hashes == {}
    assert DiagnosticCode.MEMBER_LOCAL_CRC_USED not in counts


# Case 3 stays refused: the declared size is the bound that stops decoding (DR-9a).


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_understated_size_with_a_matching_crc_is_refused(pipe: bool) -> None:
    # Seen in the scan: 12 deflated MP3s in one archive (two copies), each declaring
    # about 3.5% less than it decodes to; the CRC covers the full output. unzip
    # ignores the size and passes; 7-Zip fails.
    data = bytes(range(256)) * 400
    blob = _one_member_zip(data, declared_size=len(data) * 965 // 1000, deflate=True)
    with pytest.raises(CorruptionError, match="exceeds its declared size"):
        _read_only_member(blob, pipe=pipe)
