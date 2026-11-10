"""uuencode and base64 files (``internal/streams/codecs/text_codecs.py``)."""

from __future__ import annotations

import base64
import binascii
import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ContainerFormat,
    CorruptionError,
    DetectionConfidence,
    DiagnosticCode,
    FormatDetectionError,
    StreamFormat,
    TruncatedError,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.internal.streams.codecs.text_codecs import (
    MAX_LEADING_TEXT,
    Base64Decompressor,
    UuDecompressor,
    _b64_lines_check,
    _decoded_has_magic,
)

_PAYLOAD = os.urandom(10_000)


def _uu(data: bytes, name: str = "stored.bin", mode: int = 0o640) -> bytes:
    lines = [binascii.b2a_uu(data[i : i + 45]) for i in range(0, len(data), 45)]
    return f"begin {mode:o} {name}\n".encode() + b"".join(lines) + b"`\nend\n"


def _uu_b64(data: bytes, name: str = "stored.bin") -> bytes:
    return f"begin-base64 600 {name}\n".encode() + base64.encodebytes(data) + b"====\n"


def _zip_bytes() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("inside.txt", b"zipped\n" * 100)
    return out.getvalue()


def _tar_bytes() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        info = tarfile.TarInfo("t.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"tar\n"))
    return out.getvalue()


def _read_only(path: Path, **kwargs: object) -> bytes:
    with open_archive(path, **kwargs) as archive:  # type: ignore[arg-type]
        (member,) = archive.members()
        return archive.read(member)


# --- uuencode ------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 44, 45, 46, 10_000])
def test_uuencode_round_trips(size: int, tmp_path: Path) -> None:
    path = tmp_path / "data.bin.uu"
    path.write_bytes(_uu(_PAYLOAD[:size]))
    assert _read_only(path) == _PAYLOAD[:size]


def test_uuencode_member_keeps_its_file_name_and_shows_the_stored_one(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data.bin.uu"
    path.write_bytes(_uu(b"x", name="../../etc/evil"))
    with open_archive(path) as archive:
        (member,) = archive.members()
        assert archive.format == ArchiveFormat.UU
    assert member.name == "data.bin"
    assert member.raw_name == b"../../etc/evil"
    assert member.extra["uu.original_filename"] == "../../etc/evil"
    assert member.mode == 0o640


def test_begin_base64_reads(tmp_path: Path) -> None:
    path = tmp_path / "data.uue"
    path.write_bytes(_uu_b64(_PAYLOAD))
    assert _read_only(path) == _PAYLOAD


def test_an_unnamed_uuencoded_file_is_detected_by_its_begin_line(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attachment"
    path.write_bytes(_uu(_PAYLOAD))
    info = detect_format(path)
    assert (info.format, info.confidence, info.detected_by) == (
        ArchiveFormat.UU,
        DetectionConfidence.PROBABLE,
        "content_probe",
    )


def test_mail_text_before_begin_is_skipped_for_a_uu_name(tmp_path: Path) -> None:
    text = b"From: someone\nSubject: the file\n\nHere it is:\n\n"
    path = tmp_path / "post.uu"
    path.write_bytes(text + _uu(_PAYLOAD) + b"\n-- \nsignature\n")
    info = detect_format(path)
    assert (info.format, info.detected_by) == (ArchiveFormat.UU, "content_probe")
    with open_archive(path) as archive:
        (member,) = archive.members()
        assert archive.read(member) == _PAYLOAD
        codes = [d.code for d in archive.diagnostics.retained]
    # The signature after 'end' is not the file's: it is reported, not read.
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


def test_mail_text_before_begin_is_not_detected_without_the_name(
    tmp_path: Path,
) -> None:
    path = tmp_path / "post"
    path.write_bytes(b"Hello,\n\n" + _uu(_PAYLOAD))
    with pytest.raises(FormatDetectionError):
        detect_format(path)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            b"begin 644 the story\nOnce upon a time, there was a file.\n", id="uu"
        ),
        pytest.param(b"begin-base64 644 notes\nThis\nis a note\n", id="base64-word"),
    ],
)
def test_a_begin_line_alone_is_not_enough(text: bytes, tmp_path: Path) -> None:
    path = tmp_path / "prose"
    path.write_bytes(text)
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_a_short_begin_base64_body_before_its_closing_line_is_detected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "small"
    path.write_bytes(b"begin-base64 644 abc\nQUJD\n====\n")
    assert detect_format(path).format == ArchiveFormat.UU
    assert _read_only(path) == b"ABC"


def test_a_uuencoded_line_with_a_checksum_character_decodes(tmp_path: Path) -> None:
    # Some old encoders add a checksum character after the declared groups.
    line = binascii.b2a_uu(b"A" * 45).rstrip(b"\n") + b"X"
    path = tmp_path / "old.uu"
    path.write_bytes(b"begin 644 x\n" + line + b"\n`\nend\n")
    assert _read_only(path) == b"A" * 45


def test_a_tar_inside_uuencode_lists_the_tar(tmp_path: Path) -> None:
    path = tmp_path / "files.tar.uu"
    path.write_bytes(_uu(_tar_bytes()))
    with open_archive(path) as archive:
        assert archive.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.UU)
        assert [m.name for m in archive.members()] == ["t.txt"]


def test_uuencode_without_its_end_line_is_truncated(tmp_path: Path) -> None:
    path = tmp_path / "cut.uu"
    path.write_bytes(_uu(_PAYLOAD)[:-10])
    with pytest.raises(TruncatedError):
        _read_only(path)


def test_a_bad_uuencoded_line_is_corruption(tmp_path: Path) -> None:
    data = bytearray(_uu(_PAYLOAD))
    data[200] = ord("~")  # outside the uuencode range
    path = tmp_path / "bad.uu"
    path.write_bytes(bytes(data))
    with pytest.raises(CorruptionError, match="uuencoded line"):
        _read_only(path)


def test_too_much_text_before_begin_is_refused() -> None:
    decoder = UuDecompressor()
    with pytest.raises(CorruptionError, match="no uuencode 'begin' line"):
        decoder.decompress((b"x" * 80 + b"\n") * (MAX_LEADING_TEXT // 81 + 2))


def test_a_uuencoded_member_seeks(tmp_path: Path) -> None:
    path = tmp_path / "data.bin.uu"
    path.write_bytes(_uu(_PAYLOAD))
    with open_archive(path, seekable_members=True) as archive:
        (member,) = archive.members()
        with archive.open(member) as stream:
            stream.seek(7000)
            assert stream.read(100) == _PAYLOAD[7000:7100]
            stream.seek(10)
            assert stream.read(10) == _PAYLOAD[10:20]


def test_open_stream_decodes_uuencode(tmp_path: Path) -> None:
    path = tmp_path / "data"
    path.write_bytes(_uu(_PAYLOAD))
    with open_stream(path, format=StreamFormat.UU) as stream:
        assert stream.read() == _PAYLOAD


# --- base64 --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encode",
    [
        pytest.param(base64.encodebytes, id="76-wide"),
        pytest.param(lambda d: base64.b64encode(d) + b"\n", id="one-line"),
        pytest.param(
            lambda d: b"\r\n".join(
                base64.b64encode(d)[i : i + 64]
                for i in range(0, len(base64.b64encode(d)), 64)
            ),
            id="64-wide-crlf",
        ),
        pytest.param(lambda d: base64.b64encode(d).rstrip(b"="), id="unpadded"),
    ],
)
@pytest.mark.parametrize("size", [1, 2, 3, 10_000])
def test_base64_round_trips(encode: object, size: int, tmp_path: Path) -> None:
    path = tmp_path / "data.bin.b64"
    path.write_bytes(encode(_PAYLOAD[:size]))  # type: ignore[operator]
    assert _read_only(path) == _PAYLOAD[:size]


def test_unnamed_base64_of_an_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "pasted"
    path.write_bytes(base64.encodebytes(_zip_bytes()))
    info = detect_format(path)
    assert (info.format, info.confidence, info.detected_by) == (
        ArchiveFormat.BASE64,
        DetectionConfidence.PROBABLE,
        "content_probe",
    )
    assert _read_only(path) == _zip_bytes()


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(base64.encodebytes(os.urandom(4000)), id="base64-of-noise"),
        pytest.param(
            b"".join(os.urandom(32).hex().encode() + b"\n" for _ in range(60)),
            id="hex-dump",
        ),
        pytest.param(b"abcdefghijklmnopqrstuvwxyz0123456789ABCD\n" * 60, id="ids"),
    ],
)
def test_text_that_only_looks_like_base64_is_not_detected(
    text: bytes, tmp_path: Path
) -> None:
    # Without a name, base64 must decode to a known format's magic. Base64 of random
    # bytes starts with gzip's or .Z's two-byte magic about once in 32 768 tries.
    path = tmp_path / "notes"
    path.write_bytes(text)
    lines = text.split(b"\n")[:4]
    if _b64_lines_check(lines) and _decoded_has_magic(  # pragma: no cover - rare
        base64.b64decode(b"".join(lines))
    ):
        pytest.skip("random bytes began with a known magic")
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_prose_after_unpadded_base64_is_corruption(tmp_path: Path) -> None:
    # A space is outside the alphabet; dropping it would decode the note as data.
    path = tmp_path / "data.b64"
    path.write_bytes(base64.b64encode(b"ABC") + b"\nnote here\n")
    with pytest.raises(CorruptionError, match="not base64"):
        _read_only(path)


def test_garbage_in_base64_is_corruption(tmp_path: Path) -> None:
    path = tmp_path / "bad.b64"
    path.write_bytes(base64.encodebytes(_PAYLOAD)[:300] + b"!!!!" + b"A" * 100)
    with pytest.raises(CorruptionError, match="not base64"):
        _read_only(path)


def test_text_after_the_padding_is_trailing_data(tmp_path: Path) -> None:
    path = tmp_path / "data.b64"
    path.write_bytes(base64.encodebytes(b"ab") + b"\nthat was it\n")
    with open_archive(path) as archive:
        (member,) = archive.members()
        assert archive.read(member) == b"ab"
        codes = [d.code for d in archive.diagnostics.retained]
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 100])
def test_base64_decodes_fed_a_byte_at_a_time(size: int) -> None:
    # Text after unpadded base64 (a multiple of 3 bytes) would read as more of it, so
    # only padded text is followed by some.
    rest = b"rest" if size % 3 else b""
    text = base64.encodebytes(_PAYLOAD[:size]) + rest
    decoder = Base64Decompressor()
    out = bytearray()
    for i in range(len(text)):
        out += decoder.decompress(text[i : i + 1])
    decoder.end_input()
    out += decoder.decompress(b"")
    assert bytes(out) == _PAYLOAD[:size]
    assert decoder.eof
    assert decoder.unused_data == rest


@pytest.mark.parametrize("size", [0, 1, 45, 100])
def test_uuencode_decodes_fed_a_byte_at_a_time(size: int) -> None:
    text = _uu(_PAYLOAD[:size])
    decoder = UuDecompressor()
    out = bytearray()
    for i in range(len(text)):
        out += decoder.decompress(text[i : i + 1])
    assert bytes(out) == _PAYLOAD[:size]
    assert decoder.eof
