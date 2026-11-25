"""A ZIP64 extra field that no central directory field defers to.

APPNOTE 4.5.3 has the field hold only the values whose header field is all ones, so
archivey, stdlib and unzip use the entry's own values. When the field's values differ
from them, a reader that takes the field anyway sees another member, which
``MEMBER_HEADER_AMBIGUOUS`` (``zip64_unused``) reports.
"""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from archivey import (
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    open_archive,
)
from archivey.diagnostics import HeaderAmbiguityContext
from archivey.exceptions import DiagnosticRaisedError
from tests.streams_util import NonSeekableBytesIO

PAYLOAD = b"hello"


def _zip(zip64_data: bytes | None) -> bytes:
    """One stored member whose central entry (and local header, as stdlib writes
    ``ZipInfo.extra`` to both) carries a ZIP64 field with ``zip64_data``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("a.txt")
        if zip64_data is not None:
            info.extra = struct.pack("<HH", 1, len(zip64_data)) + zip64_data
        zf.writestr(info, PAYLOAD)
    return buf.getvalue()


def _contexts(archive: bytes, *, streaming: bool) -> list[HeaderAmbiguityContext]:
    """The ``zip64_unused`` reports, after the member is read through."""
    source = NonSeekableBytesIO(archive) if streaming else io.BytesIO(archive)
    with open_archive(source, pipe=streaming) as ar:
        if streaming:
            for member, stream in ar.stream_members():
                assert member.name == "a.txt"
                assert stream.read() == PAYLOAD
        else:
            (member,) = ar.members()
            assert member.size == len(PAYLOAD)
            assert ar.read(member) == PAYLOAD
        return [
            d.context
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_HEADER_AMBIGUOUS
            and isinstance(d.context, HeaderAmbiguityContext)
            and d.context.ambiguity == "zip64_unused"
        ]


@pytest.mark.parametrize("streaming", [False, True], ids=["file", "pipe"])
def test_differing_sizes_are_reported_and_the_entry_wins(streaming: bool) -> None:
    archive = _zip(struct.pack("<QQ", 10**12, 10**12))
    (context,) = _contexts(archive, streaming=streaming)
    assert context.member_name == "a.txt"
    assert context.field == "uncompressed size"
    assert context.more_fields == 1


def test_only_the_values_that_differ_count() -> None:
    # The uncompressed size agrees; the compressed size does not.
    archive = _zip(struct.pack("<QQ", len(PAYLOAD), 10**12))
    (context,) = _contexts(archive, streaming=False)
    assert context.field == "compressed size"
    assert context.more_fields == 0


@pytest.mark.parametrize(
    "zip64_data",
    [
        None,
        struct.pack("<QQ", len(PAYLOAD), len(PAYLOAD)),
        # The local header offset of the only member is 0.
        struct.pack("<QQQ", len(PAYLOAD), len(PAYLOAD), 0),
        # Too short to hold a whole value: nothing a reader could take.
        b"\xff\xff\xff\xff",
    ],
    ids=["no field", "matching sizes", "matching sizes and offset", "short"],
)
@pytest.mark.parametrize("streaming", [False, True], ids=["file", "pipe"])
def test_agreeing_or_absent_fields_report_nothing(
    zip64_data: bytes | None, streaming: bool
) -> None:
    assert _contexts(_zip(zip64_data), streaming=streaming) == []


def test_the_message_pairs_each_value_with_the_entry_s() -> None:
    archive = _zip(struct.pack("<QQQ", 10**12, 10**12, 7))
    with open_archive(io.BytesIO(archive)) as ar:
        ar.members()
        (message,) = [
            d.message
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_HEADER_AMBIGUOUS
        ]
    assert (
        "gives uncompressed size 1000000000000 where the entry stores 5; "
        "compressed size 1000000000000 where the entry stores 5; "
        "local header offset 7 where the entry stores 0." in message
    )


@pytest.mark.parametrize("streaming", [False, True], ids=["file", "pipe"])
def test_strict_refuses_the_member(streaming: bool) -> None:
    archive = _zip(struct.pack("<QQ", 10**12, 10**12))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    source = NonSeekableBytesIO(archive) if streaming else io.BytesIO(archive)
    with open_archive(source, pipe=streaming, config=config) as ar:
        if streaming:
            # A pipe applies the directory after the member is yielded, so the
            # refusal comes when the pass reaches it.
            with pytest.raises(DiagnosticRaisedError):
                for _member, stream in ar.stream_members():
                    stream.read()
        else:
            with pytest.raises(DiagnosticRaisedError):
                ar.members()
