"""ZIP extra fields: the Unix fields' times, and the fields archivey takes nothing from.

macOS ``ditto`` and Archive Utility write only the Info-ZIP old Unix field (``0x5855``),
so its times are all a macOS archive has beyond the DOS stamp. The fields archivey does
not read are kept raw in ``extra["zip.extra_fields"]``. The owner ids the same fields
carry are tested in ``test_zip.py``.
"""

from __future__ import annotations

import io
import os
import struct
import subprocess
import zipfile
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.exceptions import ResourceLimitError
from tests.conftest import requires_binary
from tests.streams_util import NonSeekableBytesIO

_DOS_TIME = (2020, 1, 2, 3, 4, 6)
_ATIME = 1_600_000_000
_MTIME = 1_700_000_000
_UT_MTIME = 1_500_000_000
_NTFS_TIME = 1_400_000_000


def _field(tag: int, data: bytes) -> bytes:
    return struct.pack("<HH", tag, len(data)) + data


def _zip(extra: bytes, name: str = "a.txt") -> bytes:
    """A one-member ZIP whose local and central headers both carry ``extra``."""
    buf = io.BytesIO()
    info = zipfile.ZipInfo(name, _DOS_TIME)
    info.create_system = 3
    info.extra = extra
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(info, b"hi")
    return buf.getvalue()


def _utc(seconds: int) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


# The central copy macOS writes holds the two times; the local one adds the ids.
OLD_UNIX = _field(0x5855, struct.pack("<ii", _ATIME, _MTIME))
OLD_UNIX_IDS = _field(0x5855, struct.pack("<iiHH", _ATIME, _MTIME, 501, 20))
PKWARE_UNIX = _field(0x000D, struct.pack("<iiHH", _ATIME, _MTIME, 501, 20))
EXT_TIMESTAMP = _field(0x5455, b"\x01" + struct.pack("<i", _UT_MTIME))
NEW_UNIX = _field(0x7875, struct.pack("<BBIBI", 1, 4, 501, 4, 20))
UNIX2_EMPTY = _field(0x7855, b"")
_FILETIME = (_NTFS_TIME + 11_644_473_600) * 10**7
NTFS = _field(0x000A, b"\0" * 4 + struct.pack("<HHQQQ", 1, 24, _FILETIME, _FILETIME, 0))
# With a creation time too, which no Unix field replaces.
NTFS_CREATED = _field(
    0x000A, b"\0" * 4 + struct.pack("<HHQQQ", 1, 24, _FILETIME, _FILETIME, _FILETIME)
)

_DOS = datetime(*_DOS_TIME)
_UNIX_TIMES = (_utc(_MTIME), _utc(_ATIME))

# (modified, accessed) for each blob, as unzip 6.00 sets them (checked against it by
# ``test_unix_field_times_match_unzip`` where the binary is installed).
UNIX_TIME_CASES = [
    pytest.param(OLD_UNIX, _UNIX_TIMES, id="old-unix-central"),
    pytest.param(OLD_UNIX_IDS, _UNIX_TIMES, id="old-unix-local"),
    pytest.param(PKWARE_UNIX, _UNIX_TIMES, id="pkware-unix"),
    # An Extended Timestamp anywhere wins.
    pytest.param(OLD_UNIX + EXT_TIMESTAMP, (_utc(_UT_MTIME), None), id="then-ut"),
    pytest.param(EXT_TIMESTAMP + OLD_UNIX, (_utc(_UT_MTIME), None), id="after-ut"),
    # A newer Unix field before it hides it, as it hides its ids; after it, it does not.
    pytest.param(NEW_UNIX + OLD_UNIX, (_DOS, None), id="after-new-unix"),
    pytest.param(UNIX2_EMPTY + OLD_UNIX, (_DOS, None), id="after-unix2"),
    pytest.param(OLD_UNIX + NEW_UNIX, _UNIX_TIMES, id="then-new-unix"),
    # Above the NTFS times, which unzip on Unix does not read at all.
    pytest.param(NTFS + OLD_UNIX, _UNIX_TIMES, id="after-ntfs"),
    pytest.param(OLD_UNIX + NTFS, _UNIX_TIMES, id="then-ntfs"),
    # Of two Unix fields, the last one long enough for both times wins.
    pytest.param(
        _field(0x5855, struct.pack("<ii", _ATIME - 1, _MTIME - 1)) + PKWARE_UNIX,
        _UNIX_TIMES,
        id="two-unix-fields",
    ),
]


@pytest.mark.parametrize(("extra", "times"), UNIX_TIME_CASES)
def test_unix_field_times(
    extra: bytes, times: tuple[datetime, datetime | None]
) -> None:
    data = _zip(extra)
    with open_archive(io.BytesIO(data)) as archive:
        (member,) = archive.members()
        assert (member.modified, member.accessed) == times
        assert member.diagnostics == ()
    # A pipe pass reads the local header's copy, which is the same blob here.
    with open_archive(NonSeekableBytesIO(data), streaming=True) as archive:
        ((streamed, _),) = list(archive.stream_members())
        assert (streamed.modified, streamed.accessed) == times


@requires_binary("unzip")
@pytest.mark.skipif(os.name != "posix", reason="unzip sets times on POSIX")
@pytest.mark.parametrize(("extra", "times"), UNIX_TIME_CASES)
def test_unix_field_times_match_unzip(
    tmp_path: Path, extra: bytes, times: tuple[datetime, datetime | None]
) -> None:
    (tmp_path / "a.zip").write_bytes(_zip(extra))
    subprocess.run(["unzip", "-qo", "a.zip", "-d", "out"], cwd=tmp_path, check=True)
    st = (tmp_path / "out" / "a.txt").stat()
    modified, accessed = times
    if modified.tzinfo is None:
        # The DOS stamp is local time, which unzip reads in the test's time zone.
        modified = modified.astimezone(UTC)
    assert _utc(int(st.st_mtime)) == modified
    # unzip sets both times in one call, and nothing reads the file before the stat,
    # so a relatime or noatime mount keeps the access time. Where archivey
    # lists none, unzip fills it from the modification time; there is nothing to
    # compare.
    if accessed is not None:
        assert _utc(int(st.st_atime)) == accessed


def test_macos_archive_times_are_utc() -> None:
    # ditto -c -k: the central copy holds the two times only.
    with open_archive(io.BytesIO(_zip(OLD_UNIX))) as archive:
        (member,) = archive.members()
    assert member.modified is not None
    assert member.modified.tzinfo is UTC
    assert member.modified == _utc(_MTIME)


VENDOR = _field(0x4242, b"vendor data")
JAR_MARKER = _field(0xCAFE, b"")


@pytest.mark.parametrize(
    ("extra", "unparsed"),
    [
        pytest.param(b"", None, id="none"),
        pytest.param(NTFS_CREATED + OLD_UNIX_IDS + NEW_UNIX, None, id="all-read"),
        # Its two times are replaced by the Unix field's and it has no creation time,
        # so the member keeps nothing from it.
        pytest.param(NTFS + OLD_UNIX, {0x000A: NTFS[4:]}, id="ntfs-overridden"),
        pytest.param(VENDOR, {0x4242: b"vendor data"}, id="vendor"),
        pytest.param(JAR_MARKER, {0xCAFE: b""}, id="jar-marker"),
        pytest.param(
            VENDOR + _field(0x4242, b"second") + JAR_MARKER,
            {0x4242: b"vendor data", 0xCAFE: b""},
            id="first-copy-kept",
        ),
        # Known, but the Extended Timestamp's times win and its ids are 16-bit and
        # absent: nothing was taken from it.
        pytest.param(
            OLD_UNIX + EXT_TIMESTAMP,
            {0x5855: OLD_UNIX[4:]},
            id="known-but-unused",
        ),
        # Its times were used, so it is read, though its ids came from 0x7875.
        pytest.param(OLD_UNIX + NEW_UNIX, None, id="read-for-times"),
        pytest.param(_field(0x5455, b""), {0x5455: b""}, id="empty-extended-timestamp"),
    ],
)
def test_unparsed_extra_fields(extra: bytes, unparsed: dict[int, bytes] | None) -> None:
    data = _zip(extra)
    with open_archive(io.BytesIO(data)) as archive:
        (member,) = archive.members()
        assert member.extra.get("zip.extra_fields") == unparsed
        if unparsed is not None:
            assert member.extra["zip.extra_fields"] == unparsed
    # A pipe pass gives the directory's fields once it reaches the directory.
    with open_archive(NonSeekableBytesIO(data), streaming=True) as archive:
        ((streamed, _),) = list(archive.stream_members())
    assert streamed.extra.get("zip.extra_fields") == unparsed


def _unicode_path(name: bytes, stored: bytes) -> bytes:
    return _field(0x7075, struct.pack("<BI", 1, zlib.crc32(stored)) + name)


def test_unicode_path_field_is_read_when_it_names_the_member() -> None:
    field = _unicode_path("á.txt".encode(), b"a.txt")
    with open_archive(io.BytesIO(_zip(field))) as archive:
        (member,) = archive.members()
    assert member.name == "á.txt"
    assert "zip.extra_fields" not in member.extra


def test_stale_unicode_path_field_is_unparsed() -> None:
    # A field about another name (its CRC does not match) names nothing.
    field = _unicode_path(b"other.txt", b"other.txt")
    with open_archive(io.BytesIO(_zip(field))) as archive:
        (member,) = archive.members()
    assert member.name == "a.txt"
    assert member.extra["zip.extra_fields"] == {0x7075: field[4:]}


def test_unicode_path_field_on_a_mislabelled_utf8_name_is_unparsed() -> None:
    # The flag says UTF-8 and the bytes are not, so the field is never read: the
    # member keeps the header's name and the field stays in the dict.
    stored = b"\xed.txt"
    field = _unicode_path("á.txt".encode(), stored)
    buf = io.BytesIO()
    info = zipfile.ZipInfo("X.txt", _DOS_TIME)
    info.extra = field
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(info, b"hi")
    data = bytearray(buf.getvalue().replace(b"X.txt", stored))
    # zipfile clears the UTF-8 flag on an ASCII name, so it is set in both headers.
    for signature, flags_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        data[data.index(signature) + flags_at + 1] |= 0x08  # bit 11 (0x0800)
    with open_archive(io.BytesIO(bytes(data))) as archive:
        (member,) = archive.members()
    assert member.raw_name == stored
    assert member.extra["zip.extra_fields"] == {0x7075: field[4:]}


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param(_field(0x4242, b"x" * 60_000), id="one-big-field"),
        # An empty field retains about 70 bytes and has no data to weigh: each counts.
        pytest.param(
            b"".join(_field(0x1000 + tag, b"") for tag in range(16_000)),
            id="many-empty-fields",
        ),
    ],
)
def test_unparsed_fields_count_against_the_listing_limit(extra: bytes) -> None:
    data = _zip(extra)
    with open_archive(io.BytesIO(data)) as archive:
        assert archive.members()[0].extra["zip.extra_fields"]
    limited = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=10_000))
    with (
        pytest.raises(ResourceLimitError),
        open_archive(io.BytesIO(data), config=limited) as archive,
    ):
        archive.members()
