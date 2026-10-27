"""Bytes after the end of a 7z archive are ``ARCHIVE_TRAILING_DATA`` (DR-3).

A 7z archive ends at its next header or its last packed stream, whichever is later. A
non-zero byte after that is a warning by default and refused under
``DiagnosticPolicy.STRICT``; zero padding is silent. 7-Zip 23.01 warns "There are data
after the end of archive" for any tail, zeros included.
"""

from __future__ import annotations

import io
import struct
import zlib

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import DiagnosticRaisedError
from archivey.internal.backends.sevenzip_parser import (
    PlainHeader,
    materialize_archive,
    parse_header_block,
    read_signature_and_next_header,
)
from archivey.internal.trailing_scan import MAX_TRAILING_SCAN

_PAYLOAD = b"hello, trailing data\n"


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _stored_7z(
    name: str = "f.txt", payload: bytes = _PAYLOAD, *, header_first: bool = False
) -> bytes:
    """One member stored with the COPY coder, folder CRC set.

    ``header_first`` puts the next header before the packed stream, a layout the format
    allows and 7-Zip 23.01 refuses ("Headers Error").
    """
    assert len(payload) < 0x80  # every 7z number below fits one byte
    names = b"\x00" + name.encode("utf-16le") + b"\x00\x00"
    header = _header(names, payload, pack_pos=0)
    if header_first:
        header = _header(names, payload, pack_pos=len(header))
        start_header = struct.pack("<QQI", 0, len(header), _crc(header))
        body = header + payload
    else:
        start_header = struct.pack("<QQI", len(payload), len(header), _crc(header))
        body = payload + header
    signature = (
        b"7z\xbc\xaf\x27\x1c\x00\x04"
        + struct.pack("<I", _crc(start_header))
        + start_header
    )
    return signature + body


def _header(names: bytes, payload: bytes, *, pack_pos: int) -> bytes:
    assert pack_pos < 0x80
    return (
        b"\x01"  # kHeader
        b"\x04"  # kMainStreamsInfo
        b"\x06"  # kPackInfo
        + bytes([pack_pos])
        + b"\x01\x09"  # one stream, kSize
        + bytes([len(payload)])
        + b"\x00"  # kEnd
        + b"\x07\x0b\x01\x00"  # kUnPackInfo, kFolder, one folder, not external
        + b"\x01\x01\x00"  # one coder: id size 1, COPY
        + b"\x0c"  # kCodersUnPackSize
        + bytes([len(payload)])
        + b"\x0a\x01"  # kCRC, all defined
        + struct.pack("<I", _crc(payload))
        + b"\x00"  # kEnd (unpack info)
        + b"\x00"  # kEnd (streams info)
        + b"\x05\x01"  # kFilesInfo, one file
        + b"\x11"  # kName
        + bytes([len(names)])
        + names
        + b"\x00"  # kEnd (files info)
        + b"\x00"  # kEnd (header)
    )


def _empty_7z(next_header_offset: int = 0) -> bytes:
    """No members: NextHeaderSize 0. With offset 0 it is the 32 bytes py7zr writes."""
    start_header = struct.pack("<QQI", next_header_offset, 0, 0)
    return (
        b"7z\xbc\xaf\x27\x1c\x00\x04"
        + struct.pack("<I", _crc(start_header))
        + start_header
    )


def _trailing(data: bytes) -> list[ArchiveEofContext]:
    with open_archive(io.BytesIO(data)) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["f.txt"]
        with reader.open(members[0]) as stream:
            assert stream.read() == _PAYLOAD
        found = [
            d.context
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert all(isinstance(c, ArchiveEofContext) for c in found)
    return found  # type: ignore[return-value]


def test_archive_that_ends_at_its_header_reports_nothing() -> None:
    assert _trailing(_stored_7z()) == []


def test_zero_padding_after_the_header_is_silent() -> None:
    assert _trailing(_stored_7z() + b"\x00" * 4096) == []


@pytest.mark.parametrize("zeros", [0, 100, 70_000])
def test_junk_after_the_header_is_reported(zeros: int) -> None:
    (context,) = _trailing(_stored_7z() + b"\x00" * zeros + b"JUNK")
    assert context.format == "7z"
    assert context.expected_marker == "zeros_to_eof"
    assert context.observed_kind == "nonzero"
    assert context.observed_bytes == zeros


def test_junk_past_the_scan_bound_goes_unseen() -> None:
    data = _stored_7z() + b"\x00" * MAX_TRAILING_SCAN + b"JUNK"
    assert _trailing(data) == []


def test_two_archives_concatenated_list_the_first_and_report_the_second() -> None:
    (context,) = _trailing(_stored_7z() + _stored_7z(name="g.txt"))
    assert context.observed_bytes == 0


def test_strict_policy_refuses_trailing_data() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(io.BytesIO(_stored_7z() + b"JUNK"), config=config) as reader,
    ):
        reader.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    assert isinstance(ei.value.diagnostic.context, ArchiveEofContext)
    assert ei.value.diagnostic.context.observed_bytes == 0


def test_strict_policy_accepts_zero_padding() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    data = _stored_7z() + b"\x00" * 512
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert [m.name for m in reader.members()] == ["f.txt"]


def test_self_extractor_tail_is_reported_after_the_payload() -> None:
    # A stub before the archive moves its origin; the scan starts at the archive's
    # own end, not at the end the signature header gives from byte 0 of the file.
    stub = b"MZ" + b"\x90" * 510
    (context,) = _trailing(stub + _stored_7z() + b"\x00" * 10 + b"cfg")
    assert context.observed_bytes == 10


def test_packed_stream_after_the_next_header_is_part_of_the_archive() -> None:
    data = _stored_7z(header_first=True)
    assert _trailing(data) == []
    (context,) = _trailing(data + b"\x00" * 3 + b"JUNK")
    assert context.observed_bytes == 3


def _empty_trailing(data: bytes, config: ArchiveyConfig | None = None) -> list[int]:
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert reader.members() == []
        return [
            d.context.observed_bytes
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
            and isinstance(d.context, ArchiveEofContext)
        ]


def test_empty_archive_ends_at_its_signature_header() -> None:
    assert _empty_trailing(_empty_7z()) == []
    assert _empty_trailing(_empty_7z() + b"JUNK") == [0]
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    assert _empty_trailing(_empty_7z() + b"\x00" * 512, strict) == []


def test_empty_archive_ends_at_its_next_header_offset() -> None:
    # NextHeaderOffset counts even when the header is empty: the four bytes before it
    # are inside the archive, the ones after it are not.
    data = _empty_7z(next_header_offset=4) + b"SKIP"
    assert _empty_trailing(data) == []
    assert _empty_trailing(data + b"JUNK") == [0]


def test_encoded_header_streams_count_toward_the_end() -> None:
    # 7-Zip writes an encoded header's packed stream just before the next header, so
    # no real file puts it last; the end still takes it into account.
    data = _stored_7z()
    signature = read_signature_and_next_header(io.BytesIO(data))
    block = parse_header_block(signature.header_data)
    assert isinstance(block, PlainHeader)
    plain_end = materialize_archive(signature, block).end_offset
    assert plain_end == signature.end_offset
    widened = materialize_archive(signature, block, encoded_streams_end=plain_end + 9)
    assert widened.end_offset == plain_end + 9
