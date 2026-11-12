"""The RPM reader against packages rpmbuild wrote (``fixtures/rpm/make-rpms.sh``), and
against packages this file builds: the stripped payload form (``07070X``) rpm 4.18
writes only for a file of 4 GiB or more, and damaged packages."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import archivey
from archivey import (
    AccessCost,
    ArchiveyConfig,
    CorruptionError,
    DiagnosticPolicy,
    ListingCost,
    ListingLimits,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.diagnostics import (
    DiagnosticCode,
    HeaderAmbiguityContext,
    UnknownMemberTypeContext,
)
from archivey.formats import SequentialReader
from archivey.internal.backends import rpm_reader
from archivey.internal.backends.rpm_reader import RpmReader
from tests.conftest import requires_zstd
from tests.memory_util import traced_peak
from tests.public_names import assert_only_public_archivey
from tests.streams_util import NonSeekableBytesIO

RPM = archivey.ArchiveFormat.RPM
DATA = Path(__file__).parent / "fixtures" / "rpm"
# zstd needs backports.zstd before Python 3.14, which the core-only leg does not install.
COMPRESSORS = [
    "gzip",
    "xz",
    pytest.param("zstd", marks=requires_zstd()),
    "bzip2",
    "lzma",
    "none",
]

# The tree make-rpms.sh packages, as archivey lists it.
CONTENT = {
    "usr/bin/at-hi": b"#!/bin/sh\necho hi\n",
    "usr/share/at/dir/blocks.bin": random.Random(1).randbytes(10000),
    "usr/share/at/dir/sub/text.txt": "".join(
        f"line {i}\n" for i in range(2500)
    ).encode(),
    "usr/share/at/dir/hard.txt": b"hello\n",
    "usr/share/at/a.txt": b"hello\n",
    "usr/share/at/zero.txt": b"",
    "usr/share/at/dir/zero-hard.txt": b"",
}
TYPES = {
    "usr/bin/at-hi": MemberType.FILE,
    "usr/share/at/": MemberType.DIRECTORY,
    "usr/share/at/chr": MemberType.OTHER,
    "usr/share/at/dir/": MemberType.DIRECTORY,
    "usr/share/at/dir/blocks.bin": MemberType.FILE,
    "usr/share/at/dir/link": MemberType.SYMLINK,
    "usr/share/at/dir/sub/": MemberType.DIRECTORY,
    "usr/share/at/dir/sub/text.txt": MemberType.FILE,
    "usr/share/at/empty/": MemberType.DIRECTORY,
    # In each hard-link set the last file in header (name) order carries the data.
    "usr/share/at/dir/hard.txt": MemberType.FILE,
    "usr/share/at/a.txt": MemberType.HARDLINK,
    "usr/share/at/zero.txt": MemberType.FILE,
    "usr/share/at/dir/zero-hard.txt": MemberType.HARDLINK,
}


def _check_listing(members: list[archivey.ArchiveMember]) -> None:
    by_name = {m.name: m for m in members}
    assert len(by_name) == len(members)
    # The ghost file is listed in the header only: not a member.
    assert by_name.keys() == TYPES.keys()
    for name, kind in TYPES.items():
        assert by_name[name].type is kind, name
    assert by_name["usr/share/at/dir/link"].link_target == "../a.txt"
    assert by_name["usr/share/at/a.txt"].link_target == "usr/share/at/dir/hard.txt"
    assert by_name["usr/share/at/dir/zero-hard.txt"].link_target == (
        "usr/share/at/zero.txt"
    )
    assert by_name["usr/share/at/chr"].extra["special_file_type"] == "char_device"
    names = [m.name for m in members]
    for member in members:
        if member.type is MemberType.HARDLINK:
            assert names.index(member.link_target) < names.index(member.name)
    hi = by_name["usr/bin/at-hi"]
    assert hi.mode == 0o755
    assert hi.uname == "root"
    assert hi.gname == "root"
    assert hi.modified is not None
    assert hi.modified.timestamp() == 1700000000
    assert hi.raw_name == b"/usr/bin/at-hi"


@pytest.mark.parametrize("compressor", COMPRESSORS)
def test_list_and_read(compressor: str) -> None:
    with open_archive(DATA / f"payload-{compressor}.rpm") as reader:
        assert reader.format == RPM
        info = reader.info
        assert info.format_version == "4"
        # Uncompressed, the payload reads as a CPIO archive does.
        compressed = compressor != "none"
        assert info.is_solid is compressed
        # The file list is the header's: listing decodes none of the payload.
        assert info.cost.listing_cost is ListingCost.INDEXED
        assert info.cost.access_cost is (
            AccessCost.SOLID if compressed else AccessCost.DIRECT
        )
        assert info.extra["rpm.name"] == "archivey-test"
        assert info.extra["rpm.version"] == "1.0"
        assert info.extra["rpm.release"] == "1"
        assert info.extra["rpm.epoch"] == 2
        assert info.extra["rpm.arch"] == "noarch"
        assert info.extra["rpm.source"] is False
        assert info.extra["rpm.signed"] is False
        assert info.extra["rpm.payload_compressor"] == compressor
        _check_listing(reader.members())
        for name, data in CONTENT.items():
            assert reader.read(name) == data, name
        # The header's SHA-256 file digests are checked.
        with reader.open("usr/share/at/dir/blocks.bin") as stream:
            stream.read()
            assert stream.verified is archivey.Verification.CHECKSUM


@pytest.mark.parametrize("compressor", ["gzip", "none"])
def test_stream_from_a_pipe(compressor: str) -> None:
    data = (DATA / f"payload-{compressor}.rpm").read_bytes()
    seen: dict[str, bytes] = {}
    members = []
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        assert reader.format == RPM
        for member, stream in reader.stream_members():
            members.append(member)
            if stream is not None:
                seen[member.name] = stream.read()
    _check_listing(members)
    assert seen == {
        name: data for name, data in CONTENT.items() if TYPES[name] is MemberType.FILE
    }


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_extract(tmp_path: Path, pipe: bool) -> None:
    path = DATA / "payload-xz.rpm"
    source = NonSeekableBytesIO(path.read_bytes()) if pipe else path
    dest = tmp_path / "out"
    with open_archive(source, streaming=pipe) as reader:
        reader.extract_all(dest, on_blocked="skip")
    for name, content in CONTENT.items():
        assert (dest / name).read_bytes() == content
    at = dest / "usr" / "share" / "at"
    assert os.readlink(at / "dir" / "link") == os.path.join("..", "a.txt")
    assert (at / "a.txt").stat().st_ino == (at / "dir" / "hard.txt").stat().st_ino
    assert (at / "empty").is_dir()
    assert not (at / "ghost.log").exists()


@pytest.mark.parametrize("compressor", ["gzip", "none"])
def test_seeks_inside_a_member(compressor: str) -> None:
    data = CONTENT["usr/share/at/dir/blocks.bin"]
    with (
        open_archive(DATA / f"payload-{compressor}.rpm", seekable_members=True) as r,
        r.open("usr/share/at/dir/blocks.bin") as stream,
    ):
        stream.seek(7000)
        assert stream.read(100) == data[7000:7100]
        stream.seek(10)
        assert stream.read(10) == data[10:20]


def test_a_source_package() -> None:
    with open_archive(DATA / "source.rpm") as reader:
        assert reader.info.extra["rpm.source"] is True
        [member] = reader.members()
        assert member.name == "archivey-test.spec"
        assert reader.read(member.name).startswith(b"Name: archivey-test\n")


def test_detection() -> None:
    for path in DATA.glob("*.rpm"):
        assert detect_format(path).format == RPM, path.name
    # By the lead's magic, whatever the name.
    data = (DATA / "payload-gzip.rpm").read_bytes()
    assert detect_format(io.BytesIO(data)).format == RPM


def test_the_reader_uses_only_public_archivey() -> None:
    """Written as a format added from outside would be."""
    assert_only_public_archivey(rpm_reader.__file__)


def test_the_reader_is_a_sequential_reader() -> None:
    assert issubclass(RpmReader, SequentialReader)


# Packages built here -------------------------------------------------------------

_INT8, _INT16, _INT32, _INT64, _STRING, _BIN, _STRING_ARRAY = 2, 3, 4, 5, 6, 7, 8
_ALIGN = {_INT16: 2, _INT32: 4, _INT64: 8}
_FORMATS = {_INT16: ">H", _INT32: ">I", _INT64: ">Q"}


def _header(tags: dict[int, tuple[int, object]]) -> bytes:
    """An RPM header store: the intro, the index sorted by tag, and the data."""
    index = b""
    store = b""
    for tag in sorted(tags):
        kind, value = tags[tag]
        store += b"\0" * (-len(store) % _ALIGN.get(kind, 1))
        offset = len(store)
        if kind == _STRING:
            assert isinstance(value, bytes)
            store += value + b"\0"
            count = 1
        elif kind == _STRING_ARRAY:
            assert isinstance(value, list)
            store += b"".join(v + b"\0" for v in value)
            count = len(value)
        elif kind == _BIN:
            assert isinstance(value, bytes)
            store += value
            count = len(value)
        else:
            assert isinstance(value, list)
            store += b"".join(struct.pack(_FORMATS[kind], v) for v in value)
            count = len(value)
        index += struct.pack(">IIiI", tag, kind, offset, count)
    return (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + struct.pack(">II", len(tags), len(store))
        + index
        + store
    )


@dataclass
class _F:
    path: bytes
    mode: int = 0o100644
    data: bytes = b""
    link: bytes = b""
    flags: int = 0
    inode: int = 0
    # The FILEINODES value as stored, when it must be one a set would not use (0).
    raw_inode: int | None = None


@dataclass
class _Package:
    files: list[_F]
    stripped: bool = False
    compressor: bytes | None = b"gzip"
    digest_algo: int | None = 8
    lead_major: int = 3
    signature: dict[int, tuple[int, object]] = field(default_factory=dict)
    # Signature-header tags to store the main header's digest under, as rpm does:
    # 273 (SHA-256) and 269 (SHA-1).
    header_digests: tuple[int, ...] = ()
    extra_tags: dict[int, tuple[int, object]] = field(default_factory=dict)
    drop_tags: tuple[int, ...] = ()
    # Change the payload's entries: the files to store, in order, by index.
    order: list[int] | None = None
    tamper_digest: int | None = None
    after_trailer: bytes = b""
    # End a stripped payload with rpm's index -1 rather than the newc trailer.
    stripped_end: bool = False
    # Name the files with OLDFILENAMES, as packages before rpm 4.0 did.
    old_names: bool = False


def _size(f: _F) -> int:
    if f.mode & 0o170000 == 0o120000:
        return len(f.link)
    return len(f.data)


def _build(package: _Package) -> bytes:
    files = package.files
    paths = [f.path for f in files]
    dirs: list[bytes] = []
    indexes = []
    bases = []
    for path in paths:
        head, _, base = path.rpartition(b"/")
        head += b"/"
        if head not in dirs:
            dirs.append(head)
        indexes.append(dirs.index(head))
        bases.append(base)
    digests = []
    for i, f in enumerate(files):
        if f.mode & 0o170000 == 0o100000:
            digest = hashlib.sha256(f.data).hexdigest().encode()
            if package.tamper_digest == i:
                digest = hashlib.sha256(f.data + b"!").hexdigest().encode()
            digests.append(digest)
        else:
            digests.append(b"")
    sizes = [_size(f) for f in files]
    tags: dict[int, tuple[int, object]] = {
        63: (_BIN, b"\0" * 16),
        1000: (_STRING, b"built"),
        1001: (_STRING, b"1"),
        1002: (_STRING, b"1"),
        1022: (_STRING, b"noarch"),
        1030: (_INT16, [f.mode for f in files]),
        1034: (_INT32, [0 for _ in files]),
        1035: (_STRING_ARRAY, digests),
        1036: (_STRING_ARRAY, [f.link for f in files]),
        1037: (_INT32, [f.flags for f in files]),
        1039: (_STRING_ARRAY, [b"root" for _ in files]),
        1040: (_STRING_ARRAY, [b"root" for _ in files]),
        1044: (_STRING, b"built-1-1.src.rpm"),
        1095: (_INT32, [1 for _ in files]),
        1096: (
            _INT32,
            [
                f.raw_inode if f.raw_inode is not None else f.inode or i + 1
                for i, f in enumerate(files)
            ],
        ),
        1116: (_INT32, indexes),
        1117: (_STRING_ARRAY, bases),
        1118: (_STRING_ARRAY, dirs),
        1124: (_STRING, b"cpio"),
    }
    if package.stripped:
        tags[5008] = (_INT64, sizes)
    else:
        tags[1028] = (_INT32, sizes)
    if package.compressor is not None:
        tags[1125] = (_STRING, package.compressor)
    if package.digest_algo is not None:
        tags[5011] = (_INT32, [package.digest_algo])
    if package.old_names:
        for tag in (1116, 1117, 1118):
            del tags[tag]
        tags[1027] = (_STRING_ARRAY, paths)
    tags.update(package.extra_tags)
    for tag in package.drop_tags:
        del tags[tag]
    if not files:
        for tag in (1030, 1034, 1035, 1036, 1037, 1039, 1040, 1095, 1096, 1116):
            tags.pop(tag)
        for tag in (1117, 1118, 1028, 5008):
            tags.pop(tag, None)

    # Hard-link sets: data with the last in index order. As rpm builds them, only
    # regular files that are not ghosts join one.
    sets: dict[int, list[int]] = {}
    for i, f in enumerate(files):
        regular = f.mode & 0o170000 == 0o100000
        if f.inode and regular and not f.flags & (1 << 6):
            sets.setdefault(f.inode, []).append(i)
    payload = io.BytesIO()

    def pad() -> None:
        payload.write(b"\0" * (-payload.tell() % 4))

    order = package.order
    if order is None:
        order = [i for i, f in enumerate(files) if not f.flags & (1 << 6)]
    for i in order:
        f = files[i]
        data = f.link if f.mode & 0o170000 == 0o120000 else f.data
        linked = sets.get(f.inode, [])
        if i in linked and linked[-1] != i:
            data = b""
        pad()
        if package.stripped:
            payload.write(b"07070X" + b"%08x" % i)
        else:
            name = b"." + f.path + b"\0"
            fields = [i + 1, f.mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
            payload.write(b"070701" + b"".join(b"%08x" % v for v in fields) + name)
        pad()
        payload.write(data)
    pad()
    if package.stripped_end:
        payload.write(b"07070Xffffffff")
    else:
        trailer = b"TRAILER!!!\0"
        fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0]
        payload.write(b"070701" + b"".join(b"%08x" % v for v in fields) + trailer)
    pad()
    raw = payload.getvalue() + package.after_trailer
    if package.compressor == b"gzip":
        raw = gzip.compress(raw, mtime=0)
    lead = b"\xed\xab\xee\xdb" + bytes([package.lead_major, 0]) + b"\0" * 90
    header = _header(tags)
    hashes = {273: hashlib.sha256, 269: hashlib.sha1}
    digests = {
        tag: (_STRING, hashes[tag](header).hexdigest().encode())
        for tag in package.header_digests
    }
    signature = _header({62: (_BIN, b"\0" * 16), **digests, **package.signature})
    signature += b"\0" * (-len(signature) % 8)
    return lead + signature + header + raw


def _tree() -> list[_F]:
    return [
        _F(b"/opt/t", mode=0o040755),
        _F(b"/opt/t/a.txt", data=b"alpha\n"),
        _F(b"/opt/t/big.bin", data=random.Random(2).randbytes(5000)),
        _F(b"/opt/t/ghost.log", flags=1 << 6),
        _F(b"/opt/t/h1", data=b"linked\n", inode=90),
        _F(b"/opt/t/h2", data=b"linked\n", inode=90),
        _F(b"/opt/t/link", mode=0o120777, link=b"a.txt"),
    ]


def _open(data: bytes, **kwargs: object) -> archivey.ArchiveReader:
    return open_archive(io.BytesIO(data), format=RPM, **kwargs)  # type: ignore[arg-type]


def _listing(data: bytes) -> dict[str, tuple[MemberType, bytes | None]]:
    out: dict[str, tuple[MemberType, bytes | None]] = {}
    with _open(data) as reader:
        for member, stream in reader.stream_members():
            out[member.name] = (member.type, stream.read() if stream else None)
    return out


def _read_a(data: bytes) -> bytes:
    """Read ``opt/t/a.txt``: the payload is read only when a member's data is."""
    with _open(data) as reader:
        assert len(reader.members()) == len(_EXPECTED)
        return reader.read("opt/t/a.txt")


def _reads(data: bytes) -> dict[str, bytes | str]:
    """Each file's data, or the message of the error reading it raised."""
    out: dict[str, bytes | str] = {}
    with _open(data) as reader:
        for member in reader.members():
            if member.type is MemberType.FILE:
                try:
                    out[member.name] = reader.read(member)
                except CorruptionError as error:
                    out[member.name] = str(error)
    return out


# The order rpm writes the payload in: hard-link sets after the other files.
_ORDER = [
    "opt/t/",
    "opt/t/a.txt",
    "opt/t/big.bin",
    "opt/t/link",
    "opt/t/h2",
    "opt/t/h1",
]

_EXPECTED = {
    "opt/t/": (MemberType.DIRECTORY, None),
    "opt/t/a.txt": (MemberType.FILE, b"alpha\n"),
    "opt/t/big.bin": (MemberType.FILE, random.Random(2).randbytes(5000)),
    "opt/t/h2": (MemberType.FILE, b"linked\n"),
    "opt/t/h1": (MemberType.HARDLINK, None),
    "opt/t/link": (MemberType.SYMLINK, None),
}


@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
@pytest.mark.parametrize("compressor", [b"gzip", None], ids=["gzip", "none"])
def test_built_packages(stripped: bool, compressor: bytes | None) -> None:
    data = _build(_Package(_tree(), stripped=stripped, compressor=compressor))
    assert _listing(data) == _EXPECTED


def test_a_stripped_payload_reads_from_a_pipe() -> None:
    data = _build(_Package(_tree(), stripped=True))
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        names = [m.name for m, _ in reader.stream_members()]
    assert names == _ORDER


@pytest.mark.parametrize(
    ("number", "value", "key", "expected"),
    [
        pytest.param(
            1000, (_STRING_ARRAY, [b"ab"] * 200_000), "rpm.name", "ab", id="name"
        ),
        pytest.param(1003, (_INT32, list(range(150_000))), "rpm.epoch", 0, id="epoch"),
    ],
)
def test_a_one_value_tag_declaring_a_long_array_reads_only_its_first(
    number: int, value: tuple[int, object], key: str, expected: object
) -> None:
    # NAME, VERSION, EPOCH and the other tags read for one value built the whole
    # array the entry declares to take its first element: a 60 MiB data store of
    # such arrays took 1.22 GB to open. Here the peak was 12 to 16 times the
    # package; now it is about one package.
    data = _build(_Package(_tree(), extra_tags={number: value}))

    def open_it() -> None:
        with _open(data) as reader:
            extra = reader.info.extra
            assert extra[key] == expected

    open_it()
    peak = traced_peak(open_it)
    assert peak < 4 * len(data), peak / len(data)


def test_the_one_value_accessors_check_the_entry_as_the_array_ones_do() -> None:
    # string() and number() read only the first value, and still refuse every
    # entry that strings() and ints() refuse, with the same message.
    # No NUL after the second string's.
    data = b"ab\0cd\0" + bytes(range(1, 7))
    cases = {
        "one string": (_STRING, 1, 0),
        "array": (_STRING_ARRAY, 2, 3),
        "array past the last NUL": (_STRING_ARRAY, 3, 0),
        "array longer than the store": (_STRING_ARRAY, 99, 0),
        "string at the end": (_STRING, 1, len(data)),
        "string with no NUL": (_STRING, 1, 6),
        "int32": (_INT32, 1, 6),
        "int32 array past the end": (_INT32, 2, 6),
        "int16": (_INT16, 1, 10),
        "int8 array": (_INT8, 3, 1),
        "binary": (_BIN, 1, 0),
        # _read_header refuses a count of 0; the accessors still agree on it.
        "empty array": (_STRING_ARRAY, 0, 3),
        "empty array at the end": (_STRING_ARRAY, 0, len(data)),
        "empty int32 array at the end": (_INT32, 0, len(data)),
        "empty int16 array at the end": (_INT16, 0, len(data)),
    }
    for what, (kind, count, offset) in cases.items():
        header = rpm_reader.Header(
            {1: rpm_reader._Entry(kind, count, offset)}, data, "header"
        )
        for one, many in (
            (header.string, header.strings),
            (header.number, header.ints),
        ):
            try:
                expected: object = many(1)
            except CorruptionError as exc:
                with pytest.raises(CorruptionError) as caught:
                    one(1)
                assert str(caught.value) == str(exc), what
            else:
                assert isinstance(expected, list)
                assert one(1) == (expected[0] if expected else None), what
        assert header.string(2) is None
        assert header.number(2) is None


def test_a_digest_mismatch_raises() -> None:
    data = _build(_Package(_tree(), tamper_digest=1))
    with _open(data) as reader:
        assert reader.read("opt/t/big.bin")
        with pytest.raises(CorruptionError):
            reader.read("opt/t/a.txt")


@pytest.mark.parametrize(
    ("algo", "verified"),
    [(None, False), (99, False), (8, True)],
    ids=["md5-default-but-sha256-stored", "unknown", "sha256"],
)
def test_the_digest_algorithm(algo: int | None, verified: bool) -> None:
    """Without FILEDIGESTALGO the digests are MD5, which a SHA-256 does not match;
    an algorithm rpm does not name leaves the files unchecked."""
    data = _build(_Package(_tree(), digest_algo=algo))
    with _open(data) as reader:
        if algo is None:
            with pytest.raises(CorruptionError):
                reader.read("opt/t/a.txt")
            return
        with reader.open("opt/t/a.txt") as stream:
            stream.read()
            checked = stream.verified is archivey.Verification.CHECKSUM
        assert checked is verified


def test_a_ghost_stored_anyway_is_skipped() -> None:
    """rpm < 4.11 sometimes stored a ghost; rpm skips it."""
    files = _tree()
    files[3].data = b"ghost data"
    data = _build(_Package(files, order=[0, 1, 2, 3, 4, 5, 6]))
    assert _listing(data) == _EXPECTED


@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_file_missing_from_the_payload_fails_alone(
    stripped: bool, pipe: bool
) -> None:
    """The listing is the header's; the file whose entry is missing fails when its
    data is read, and the files after it read."""
    data = _build(_Package(_tree(), order=[0, 2, 4, 5, 6], stripped=stripped))
    with _open(data) as reader:
        assert [m.name for m in reader.members()] == _ORDER
    if not pipe:
        reads = _reads(data)
    else:
        reads = {}
        source = NonSeekableBytesIO(data)
        with open_archive(source, format=RPM, streaming=True) as reader:
            for member, stream in reader.stream_members():
                if stream is not None:
                    try:
                        reads[member.name] = stream.read()
                    except CorruptionError as error:
                        reads[member.name] = str(error)
    message = reads.pop("opt/t/a.txt")
    assert isinstance(message, str)
    assert "holds no data for '/opt/t/a.txt'" in message
    assert reads == {
        name: content
        for name, (kind, content) in _EXPECTED.items()
        if kind is MemberType.FILE and name != "opt/t/a.txt"
    }


@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
def test_a_second_entry_for_a_file_is_skipped(stripped: bool) -> None:
    data = _build(_Package(_tree(), order=[0, 1, 1, 2, 4, 5, 6], stripped=stripped))
    assert _listing(data) == _EXPECTED


def test_a_payload_name_the_header_does_not_list() -> None:
    data = _build(_Package(_tree(), compressor=None))
    data = data.replace(b"./opt/t/a.txt", b"./opt/t/x.txt")
    with pytest.raises(CorruptionError, match="does not list"):
        _read_a(data)
    # Structural damage: every file read after it in the same pass fails too, rather
    # than the cursor parsing on from inside the broken entry.
    errors: dict[str, str] = {}
    with open_archive(NonSeekableBytesIO(data), format=RPM, streaming=True) as r:
        for member, stream in r.stream_members():
            if stream is not None:
                with pytest.raises(CorruptionError) as caught:
                    stream.read()
                errors[member.name] = str(caught.value)
    assert "does not list" in errors.pop("opt/t/a.txt")
    assert sorted(errors) == ["opt/t/big.bin", "opt/t/h2"]
    assert all("cannot be read to" in message for message in errors.values())


def test_a_newc_size_that_disagrees_with_the_header() -> None:
    files = _tree()
    package = _Package(files, compressor=None)
    data = _build(package)
    entry = b"./opt/t/a.txt\0"
    at = data.index(entry) - 104 + 48
    assert data[at : at + 8] == b"%08x" % 6
    data = data[:at] + b"%08x" % 7 + data[at + 8 :]
    with pytest.raises(CorruptionError, match="the header gives 6"):
        _read_a(data)


def test_a_stripped_index_past_the_file_list() -> None:
    data = _build(_Package(_tree(), stripped=True, compressor=None))
    data = data.replace(b"07070X00000001", b"07070X00000064")
    with pytest.raises(CorruptionError, match="names file 100 of 7"):
        _read_a(data)


def test_data_after_the_trailer_is_not_read() -> None:
    """No member's data is there: like rpm, archivey reads no further than the data
    it needs."""
    data = _build(_Package(_tree(), after_trailer=b"\0\0junk"))
    assert _listing(data) == _EXPECTED
    with _open(data) as reader:
        for member in reader.members():
            if member.type is MemberType.FILE:
                reader.read(member)
        assert not reader.diagnostics.retained


def test_a_cut_package_raises_truncated() -> None:
    data = _build(_Package(_tree(), compressor=None))
    # Cut in the headers, and in a file's data. A cut past the last file's data is
    # not read, as no member's data is there.
    for cut in (50, 200, len(data) - 300):
        with pytest.raises(TruncatedError), _open(data[:cut]) as reader:
            for _member, stream in reader.stream_members():
                if stream is not None:
                    stream.read()


@pytest.mark.parametrize(
    ("package", "error", "match"),
    [
        (_Package([], lead_major=1), UnsupportedFeatureError, "lead version 1"),
        (
            _Package([], extra_tags={1124: (_STRING, b"drpm")}),
            UnsupportedFeatureError,
            "delta RPM",
        ),
        (_Package([], compressor=b"lzip"), UnsupportedFeatureError, "'lzip'"),
    ],
    ids=["lead-1", "drpm", "compressor"],
)
def test_refused_packages(
    package: _Package, error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match), _open(_build(package)) as reader:
        reader.members()


def test_an_empty_package() -> None:
    with _open(_build(_Package([]))) as reader:
        assert reader.members() == []


@pytest.mark.parametrize(
    ("tag", "signed"),
    [(268, True), (267, True), (1002, True), (1005, True), (1006, True), (259, False)],
)
def test_a_signature_is_reported(tag: int, signed: bool) -> None:
    """The signature header's tags as rpm writes them: RSA and DSA over the header,
    PGP and GPG over header and payload. 259 is what rpm calls 1002 once read."""
    data = _build(_Package(_tree(), signature={tag: (_BIN, b"sig")}))
    with _open(data) as reader:
        assert reader.info.extra["rpm.signed"] is signed


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_changed_header_byte_raises(pipe: bool) -> None:
    """The fixture's signature header stores SHA-256 and SHA-1 digests of the main
    header. One byte of the symlink's target changed there, which only the header's
    digest covers, is damage, in both access modes."""
    data = (DATA / "payload-gzip.rpm").read_bytes()
    assert data.count(b"../a.txt\0") == 1  # in the header: the payload is gzip
    data = data.replace(b"../a.txt\0", b"../b.txt\0")
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with (
        pytest.raises(CorruptionError, match="SHA-256 digest"),
        open_archive(source, streaming=pipe) as reader,
    ):
        list(reader.stream_members())


@pytest.mark.parametrize(
    ("tags", "algorithm"),
    [((273,), "SHA-256"), ((269,), "SHA-1"), ((273, 269), "SHA-256")],
    ids=["sha256", "sha1", "both"],
)
@pytest.mark.parametrize("changed", [False, True], ids=["honest", "changed"])
def test_the_header_digest(
    tags: tuple[int, ...], algorithm: str, changed: bool
) -> None:
    data = _build(_Package(_tree(), header_digests=tags))
    if not changed:
        assert _listing(data) == _EXPECTED
        return
    assert data.count(b"noarch\0") == 1
    data = data.replace(b"noarch\0", b"noarcx\0")
    with (
        pytest.raises(CorruptionError, match=f"the {algorithm} digest"),
        _open(data) as reader,
    ):
        reader.members()


def test_every_header_digest_is_checked() -> None:
    """A correct SHA-256 does not excuse a wrong SHA-1."""
    data = _build(
        _Package(_tree(), header_digests=(273,), signature={269: (_STRING, b"00" * 20)})
    )
    with pytest.raises(CorruptionError, match="SHA-1 digest"), _open(data) as r:
        r.members()


def test_a_header_digest_that_is_not_hexadecimal() -> None:
    data = _build(_Package(_tree(), signature={273: (_STRING, b"zz")}))
    with pytest.raises(CorruptionError, match="not hexadecimal"), _open(data) as r:
        r.members()


def test_the_rpm_6_format_version() -> None:
    data = _build(_Package(_tree(), stripped=True, extra_tags={5114: (_INT32, [6])}))
    with _open(data) as reader:
        assert reader.info.format_version == "6"


def test_a_header_with_no_immutable_region_is_format_version_3() -> None:
    """rpm's rule: no RPMFORMAT and no immutable region (tag 63) is an RPM 3 header."""
    data = _build(_Package(_tree(), drop_tags=(63,)))
    with _open(data) as reader:
        assert reader.info.format_version == "3"


def test_a_header_over_max_metadata_bytes() -> None:
    data = _build(_Package(_tree()))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=200))
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        _open(data, config=config) as reader,
    ):
        reader.members()


@pytest.mark.parametrize(
    "damage",
    [
        "magic",
        "count",
        "offset",
        "duplicate",
        "column",
        "dirindex",
        "string",
        "type",
    ],
)
def test_hostile_headers(damage: str) -> None:
    files = _tree()
    package = _Package(files, compressor=None)
    data = _build(package)
    lead = 96
    signature = data.index(b"\x8e\xad\xe8\x01", lead + 1)
    if damage == "magic":
        data = data[:signature] + b"\0" + data[signature + 1 :]
    elif damage == "count":
        data = (
            data[: signature + 8] + struct.pack(">I", 0x10000) + data[signature + 12 :]
        )
    else:
        tags: dict[int, tuple[int, object]] = {}
        if damage == "offset":
            raw = bytearray(data)
            # The first index entry's offset, past the store.
            struct.pack_into(">i", raw, signature + 16 + 8, 1 << 20)
            data = bytes(raw)
        elif damage == "duplicate":
            raw = bytearray(data)
            first = raw[signature + 16 : signature + 20]
            raw[signature + 32 : signature + 36] = first
            data = bytes(raw)
        else:
            if damage == "column":
                tags[1030] = (_INT16, [0o100644])
            elif damage == "dirindex":
                tags[1116] = (_INT32, [9] * len(files))
            elif damage == "string":
                tags[1000] = (_BIN, b"no-nul")
                tags[1001] = (_INT16, [1])
            elif damage == "type":
                tags[1117] = (_INT32, [1] * len(files))
            data = _build(_Package(files, compressor=None, extra_tags=tags))
    with pytest.raises(CorruptionError), _open(data) as reader:
        reader.members()


def test_a_name_that_is_not_utf8_follows_encoding() -> None:
    files = [_F(b"/opt/caf\xe9.txt", data=b"x")]
    data = _build(_Package(files))
    with _open(data, encoding="latin-1") as reader:
        assert [m.name for m in reader.members()] == ["opt/café.txt"]


def test_a_stripped_payload_can_end_with_index_minus_one() -> None:
    """rpm's rpmcpioHeaderRead (lib/cpio.c) ends a stripped payload at index -1."""
    data = _build(_Package(_tree(), stripped=True, stripped_end=True))
    assert _listing(data) == _EXPECTED


@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
def test_a_hard_link_stored_after_its_data(stripped: bool) -> None:
    """The set's last file (h2, with the data) before an earlier link (h1): rpm
    installs it, so h1 is listed, as a link to h2."""
    data = _build(_Package(_tree(), order=[0, 1, 2, 5, 4, 6], stripped=stripped))
    assert _listing(data) == _EXPECTED
    with _open(data) as reader:
        links = {m.name: m.link_target for m in reader.members()}
    assert links["opt/t/h1"] == "opt/t/h2"


def test_more_files_than_max_members_is_refused_before_the_list_is_built() -> None:
    data = _build(_Package(_tree()))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=3))
    with (
        pytest.raises(ResourceLimitError, match="lists 7 files"),
        _open(data, config=config) as reader,
    ):
        reader.members()


def test_a_shared_directory_is_not_joined_into_every_name_up_front() -> None:
    """DIRINDEXES lets every file share one long directory: joining the names up
    front would take files x directory bytes for a header of files + directory."""
    import tracemalloc

    files = 4000
    directory = b"/" + b"d" * 4000 + b"/"
    tags: dict[int, tuple[int, object]] = {
        63: (_BIN, b"\0" * 16),
        1000: (_STRING, b"wide"),
        1028: (_INT32, [0] * files),
        1030: (_INT16, [0o100644] * files),
        1116: (_INT32, [0] * files),
        1117: (_STRING_ARRAY, [b"%d" % i for i in range(files)]),
        1118: (_STRING_ARRAY, [directory]),
        1124: (_STRING, b"cpio"),
    }
    trailer = b"TRAILER!!!\0"
    fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0]
    payload = b"070701" + b"".join(b"%08x" % v for v in fields) + trailer + b"\0" * 3
    lead = b"\xed\xab\xee\xdb\x03" + b"\0" * 91
    signature = _header({62: (_BIN, b"\0" * 16)})
    data = lead + signature + _header(tags) + payload
    # Joined, the names alone would be 16 MB.
    tracemalloc.start()
    try:
        config = ArchiveyConfig(
            listing_limits=ListingLimits(max_metadata_bytes=2 * 2**20)
        )
        with (
            pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
            _open(data, config=config) as r,
        ):
            r.members()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 2**20


def test_a_hard_link_set_costs_memory_in_its_size_not_its_square() -> None:
    """Every file sharing one inode is one hard-link set. The set's file list is
    shared by its files: a copy per file would take memory with the square of the
    set's size (about 130 MiB for these 4000 files, 500 MiB for 8000) from a header
    of a few bytes per file."""
    import tracemalloc

    files = [_F(b"/opt/f%06d" % i, inode=7) for i in range(4000)]
    data = _build(_Package(files, compressor=None))
    tracemalloc.start()
    try:
        with _open(data) as r:
            members = r.members()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(members) == 4000
    assert peak < 16 * 2**20


def test_an_integer_column_is_counted_before_it_is_unpacked() -> None:
    """A per-file integer column declaring far more values than files is refused
    without unpacking them."""
    import tracemalloc

    modes = (_INT16, [0o100644] * 2_000_000)
    data = _build(
        _Package([_F(b"/opt/a", data=b"x")], compressor=None, extra_tags={1030: modes})
    )
    tracemalloc.start()
    try:
        with pytest.raises(CorruptionError, match="values of tag 1030"):
            _open(data).close()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The package itself is 4 MB; unpacked, the column was about 96 MB.
    assert peak < 32 * 1024 * 1024


def test_an_unknown_file_type_is_listed_and_reported() -> None:
    data = _build(
        _Package(
            [_F(b"/opt/odd", mode=0o030644), _F(b"/opt/a", data=b"x")],
            compressor=None,
        )
    )
    with _open(data) as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read("opt/a") == b"x"
        codes = [d.code for d in reader.diagnostics.retained]
    odd = members["opt/odd"]
    assert odd.type is MemberType.OTHER
    assert odd.extra["special_file_type"] == "unknown"
    assert codes == [DiagnosticCode.MEMBER_TYPE_UNKNOWN]
    assert [d.code for d in odd.diagnostics] == [DiagnosticCode.MEMBER_TYPE_UNKNOWN]


@pytest.mark.parametrize(
    "mode", [0o010644, 0o040755, 0o030644], ids=["fifo", "dir", "unknown"]
)
def test_payload_bytes_for_a_type_rpm_reads_none_for_are_damage(mode: int) -> None:
    """rpm takes a size of 0 for these whatever the entry says, and would read the
    bytes as the next entry's header."""
    data = _build(
        _Package([_F(b"/opt/x", mode=mode, data=b"0123456789")], compressor=None)
    )
    data = _build(
        _Package(
            [_F(b"/opt/x", mode=mode, data=b"0123456789"), _F(b"/opt/z", data=b"z")],
            compressor=None,
        )
    )
    with (
        pytest.raises(CorruptionError, match="the header gives 0"),
        _open(data) as reader,
    ):
        reader.read("opt/z")


@pytest.mark.parametrize("pipe", [False, True], ids=["bytesio", "pipe"])
def test_streaming_header_store_size_does_not_drive_the_allocation(
    pipe: bool,
) -> None:
    """A streaming open reads the signature header's data store in steps, so a 1 KB
    package that declares a 60 MiB store is not given 60 MiB of memory before it is
    found cut. Before the fix the walk asked its stream for the declared size in one
    read, which peaked at 60 MiB from a ``BytesIO`` and 120 MiB from a pipe."""
    lead = b"\xed\xab\xee\xdb\x03" + b"\0" * 91
    signature = (
        b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", 1, 60 * 2**20) + b"\0" * 16
    )
    data = lead + signature + b"x" * 1000
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)

    def walk() -> None:
        with (
            pytest.raises(TruncatedError),
            open_archive(source, format=RPM, streaming=True) as reader,
        ):
            for _member, _stream in reader.stream_members():
                pass

    peak = traced_peak(walk)
    assert peak < 8 * 2**20, f"peak {peak} bytes for a {len(data)}-byte package"


def _retype(data: bytes, tag: int, kind: int) -> bytes:
    """The package with the main header's index entry for ``tag`` given type ``kind``."""
    # The signature header starts at 96, after the lead: the next magic is the main one.
    header = data.index(b"\x8e\xad\xe8\x01", 96 + 1)
    (count,) = struct.unpack_from(">I", data, header + 8)
    raw = bytearray(data)
    for i in range(count):
        at = header + 16 + 16 * i
        if struct.unpack_from(">I", raw, at)[0] == tag:
            struct.pack_into(">I", raw, at + 4, kind)
            return bytes(raw)
    raise AssertionError(f"no tag {tag}")


@pytest.mark.parametrize("tag", [1027, 1035, 1036, 1039, 1040])
def test_a_single_string_entry_with_a_count_over_one_is_damage(tag: int) -> None:
    """rpm's headerVerifyInfo refuses a STRING entry whose count is not 1. A count
    equal to the file count must not pass a per-file column check with one value."""
    files = _tree()
    package = _Package(files, compressor=None)
    if tag == 1027:
        package = _Package(
            files,
            compressor=None,
            drop_tags=(1116, 1117, 1118),
            extra_tags={1027: (_STRING_ARRAY, [f.path for f in files])},
        )
    data = _retype(_build(package), tag, _STRING)
    with pytest.raises(CorruptionError, match=f"tag {tag}"), _open(data) as reader:
        for _, stream in reader.stream_members():
            if stream is not None:
                stream.read()


# Edges the mutation sweep found untested: each test below fails when one bound,
# default or branch of the reader changes.


def _raw_header(entries: list[tuple[int, int, int, int]], store: bytes) -> bytes:
    """A header from raw index entries (tag, type, offset, count), unchecked."""
    index = b"".join(struct.pack(">IIiI", *entry) for entry in entries)
    return (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + struct.pack(">II", len(entries), len(store))
        + index
        + store
    )


def _with_main_header(header: bytes) -> bytes:
    """A package whose main header is ``header``, with no payload."""
    lead = b"\xed\xab\xee\xdb\x03" + b"\0" * 91
    signature = _header({62: (_BIN, b"\0" * 16)})
    return lead + signature + b"\0" * (-len(signature) % 8) + header


def _store(entries: dict[int, rpm_reader._Entry], data: bytes) -> rpm_reader.Header:
    return rpm_reader.Header(entries, data, "header")


_CHAR, _INT8, _INT64, _I18NSTRING = 1, 2, 5, 9


@pytest.mark.parametrize(
    ("kind", "count", "fmt"),
    [
        (_CHAR, 3, "B"),
        (_INT8, 2, "B"),
        (_INT16, 2, "H"),
        (_INT32, 1, "I"),
        (_INT64, 1, "Q"),
    ],
)
def test_an_integer_entry_that_ends_at_the_store_end_reads(
    kind: int, count: int, fmt: str
) -> None:
    data = bytes(range(1, 9))
    offset = len(data) - struct.calcsize(f">{count}{fmt}")
    header = _store({7: rpm_reader._Entry(kind, count, offset)}, data)
    expected = list(struct.unpack_from(f">{count}{fmt}", data, offset))
    assert header.ints(7) == expected
    assert header.number(7) == expected[0]


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        (
            rpm_reader._Entry(_INT32, 2, 4),
            "tag 7 runs past the end of the header's data",
        ),
        (
            rpm_reader._Entry(_INT16, 3, 4),
            "tag 7 runs past the end of the header's data",
        ),
        (rpm_reader._Entry(_BIN, 1, 0), "tag 7 has type 7, not an integer"),
        (rpm_reader._Entry(_STRING, 1, 0), "tag 7 has type 6, not an integer"),
    ],
    ids=["int32-past", "int16-past", "bin", "string"],
)
def test_an_integer_entry_that_cannot_be_read_names_its_tag(
    entry: rpm_reader._Entry, match: str
) -> None:
    header = rpm_reader.Header({7: entry}, bytes(8), "signature header")
    with pytest.raises(CorruptionError, match=f"^RPM signature header: {match}"):
        header.ints(7)


def test_a_string_entry_reads_its_values_and_no_further() -> None:
    data = b"one\0two\0three\0"
    header = _store(
        {
            1: rpm_reader._Entry(_STRING, 1, 0),
            2: rpm_reader._Entry(_STRING_ARRAY, 2, 4),
            3: rpm_reader._Entry(_I18NSTRING, 1, 8),
        },
        data,
    )
    assert header.strings(1) == [b"one"]
    assert header.string(1) == b"one"
    assert header.strings(2) == [b"two", b"three"]
    assert header.strings(3) == [b"three"]
    assert header.strings(4) is None
    assert header.count(2) == 2
    assert header.count(4) == 0


def test_a_string_entry_with_a_count_over_one_is_damage() -> None:
    """A STRING holds one value; rpm's headerVerifyInfo refuses any other count."""
    header = _store({1: rpm_reader._Entry(_STRING, 5, 0)}, b"one\0two\0three\0")
    for read in (header.strings, header.string):
        with pytest.raises(
            CorruptionError, match="tag 1 is a single string with count 5"
        ):
            read(1)


@pytest.mark.parametrize(
    ("entry", "data", "match"),
    [
        (rpm_reader._Entry(_INT32, 1, 0), b"x\0", "tag 7 has type 4, not a string"),
        (
            rpm_reader._Entry(_STRING_ARRAY, 4, 0),
            b"a\0b",
            "tag 7 declares 4 strings in fewer bytes",
        ),
        (
            rpm_reader._Entry(_STRING_ARRAY, 3, 2),
            b"a\0b\0",
            "tag 7 declares 3 strings in fewer bytes",
        ),
        (
            rpm_reader._Entry(_STRING_ARRAY, 2, 0),
            b"a\0bc",
            "tag 7 has a string with no NUL before the data's end",
        ),
        (
            rpm_reader._Entry(_STRING, 1, 0),
            b"a",
            "tag 7 has a string with no NUL before the data's end",
        ),
    ],
    ids=["type", "count", "count-past-offset", "no-nul", "no-nul-at-0"],
)
def test_a_string_entry_that_cannot_be_read_names_its_tag(
    entry: rpm_reader._Entry, data: bytes, match: str
) -> None:
    header = _store({7: entry}, data)
    with pytest.raises(CorruptionError, match=f"^RPM header: {match}"):
        header.strings(7)


def test_a_string_count_that_fills_the_store_exactly_reads() -> None:
    """Three strings of one NUL each in three bytes: as many values as bytes."""
    header = _store({7: rpm_reader._Entry(_STRING_ARRAY, 3, 0)}, b"\0\0\0")
    assert header.strings(7) == [b"", b"", b""]


@pytest.mark.parametrize(
    ("count", "size", "match"),
    [
        (0x10000, 0, "declares 65536 tags and 0 bytes of data, over rpm's own bounds"),
        (0, 0x10000000, "declares 0 tags and 268435456 bytes of data, over rpm's"),
    ],
    ids=["tags", "data"],
)
def test_a_header_over_rpms_bounds_is_refused_before_it_is_read(
    count: int, size: int, match: str
) -> None:
    intro = b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", count, size)
    data = _with_main_header(intro)
    with pytest.raises(CorruptionError, match=f"RPM header at offset \\d+ {match}"):
        _open(data).close()


def test_a_header_at_rpms_tag_bound_is_read() -> None:
    """0xFFFF tags is rpm's largest header: read, so the next check speaks (no tag
    here has a count)."""
    entries = [(1000 + i, _INT32, 0, 0) for i in range(0xFFFF)]
    data = _with_main_header(_raw_header(entries, b""))
    with pytest.raises(CorruptionError, match="has offset 0 and count 0"):
        _open(data).close()


def test_a_header_at_rpms_data_bound_is_charged_not_refused() -> None:
    """A store of 0x0FFFFFFF bytes is in rpm's bounds: it reaches the metadata
    budget, not the bounds check."""
    intro = b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", 0, 0x0FFFFFFF)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=1 << 20))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        _open(_with_main_header(intro), config=config).close()


def test_the_bad_header_is_named_in_the_message() -> None:
    lead = b"\xed\xab\xee\xdb\x03" + b"\0" * 91
    with pytest.raises(CorruptionError, match="^No RPM signature header at offset 96"):
        _open(lead + b"\0" * 16).close()
    with pytest.raises(CorruptionError, match="^No RPM lead at offset 0"):
        open_archive(io.BytesIO(b"\0" * 200), format=RPM).close()


def test_an_entry_may_start_at_the_store_end() -> None:
    """An offset equal to the store's size passes the index check (rpm's too); only
    reading the value would fail, and nobody reads an unknown tag."""
    tags = {5999: (_INT32, [7])}
    data = _build(_Package(_tree(), compressor=None, extra_tags=tags))
    header_at = data.index(b"\x8e\xad\xe8\x01", 100)
    count, size = struct.unpack_from(">II", data, header_at + 8)
    raw = bytearray(data)
    for i in range(count):
        at = header_at + 16 + 16 * i
        if struct.unpack_from(">I", raw, at)[0] == 5999:
            struct.pack_into(">i", raw, at + 8, size)
    assert _listing(bytes(raw)) == _EXPECTED


def test_an_rpm_6_lead_is_read_and_a_later_one_is_refused() -> None:
    """RPM 6 packages carry lead version 4; anything past it is unknown."""
    data = _build(_Package(_tree(), lead_major=4))
    assert _listing(data) == _EXPECTED
    with pytest.raises(UnsupportedFeatureError, match="^RPM lead version 5"):
        _open(_build(_Package(_tree(), lead_major=5))).close()


@pytest.mark.parametrize(
    ("payload_format", "match"),
    [
        (b"drpm", "^RPM payload format 'drpm' \\(a delta RPM\\)"),
        (b"tar", "^RPM payload format 'tar'"),
    ],
)
def test_a_payload_format_that_is_not_cpio_is_refused(
    payload_format: bytes, match: str
) -> None:
    tags = {1124: (_STRING, payload_format)}
    with pytest.raises(UnsupportedFeatureError, match=match):
        _open(_build(_Package([], extra_tags=tags))).close()


def test_no_digest_algorithm_means_md5() -> None:
    """rpm's default when FILEDIGESTALGO is absent (rpmfiNew): an MD5 digest that
    matches is checked, and passes."""
    files = [_F(b"/opt/a", data=b"alpha\n")]
    md5 = hashlib.md5(b"alpha\n").hexdigest().encode()
    data = _build(
        _Package(files, digest_algo=None, extra_tags={1035: (_STRING_ARRAY, [md5])})
    )
    with _open(data) as reader, reader.open("opt/a") as stream:
        assert stream.read() == b"alpha\n"
        assert stream.verified is archivey.Verification.CHECKSUM


def test_a_digest_that_is_not_hexadecimal_names_the_file() -> None:
    files = [_F(b"/opt/a", data=b"x")]
    data = _build(_Package(files, extra_tags={1035: (_STRING_ARRAY, [b"zz"])}))
    with (
        pytest.raises(
            CorruptionError,
            match="^RPM header: the digest of '/opt/a' is not hexadecimal",
        ),
        _open(data) as reader,
    ):
        reader.read("opt/a")


def test_max_members_equal_to_the_file_count_is_not_refused() -> None:
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=7))
    with _open(_build(_Package(_tree())), config=config) as reader:
        assert len(reader.members()) == len(_EXPECTED)


def test_more_directories_than_max_members_is_refused() -> None:
    """DIRNAMES is a list the reader keeps too, so it is held to the same bound."""
    files = [_F(b"/opt/a", data=b"x")]
    dirs = [b"/opt/", b"/d1/", b"/d2/"]
    data = _build(_Package(files, extra_tags={1118: (_STRING_ARRAY, dirs)}))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    with pytest.raises(ResourceLimitError, match="lists 3 directories"):
        _open(data, config=config).close()


def test_old_style_file_names_are_read() -> None:
    """Packages before rpm 4.0 list whole paths in OLDFILENAMES."""
    data = _build(_Package(_tree(), old_names=True))
    assert _listing(data) == _EXPECTED


@pytest.mark.parametrize(
    ("drop", "tags", "match"),
    [
        ((1116,), {}, "lists 7 base names and 0 directory indexes"),
        ((), {1116: (_INT32, [0] * 6)}, "lists 7 base names and 6 directory"),
        ((1030,), {}, "^RPM header lists files with no tag 1030"),
        ((1028,), {}, "^RPM header lists files with no tag 1028"),
        ((), {1034: (_INT32, [0] * 6)}, "lists 7 files and 6 values of tag 1034"),
        (
            (),
            {1039: (_STRING_ARRAY, [b"root"] * 6)},
            "lists 7 files and 6 values of tag 1039",
        ),
    ],
    ids=[
        "no-dirindexes",
        "short-dirindexes",
        "no-modes",
        "no-sizes",
        "mtimes",
        "users",
    ],
)
def test_a_file_list_whose_columns_disagree_is_refused(
    drop: tuple[int, ...], tags: dict[int, tuple[int, object]], match: str
) -> None:
    package = _Package(_tree(), drop_tags=drop, extra_tags=tags)
    with pytest.raises(CorruptionError, match=match):
        _open(_build(package)).close()


def test_a_directory_index_equal_to_the_directory_count_is_refused() -> None:
    files = [_F(b"/opt/a", data=b"x")]
    data = _build(_Package(files, extra_tags={1116: (_INT32, [1])}))
    with pytest.raises(
        CorruptionError, match="directory index 1 of 'a' is past the 1 directory names"
    ):
        _open(data).close()


def test_a_package_without_optional_columns_lists_its_files() -> None:
    """FILEFLAGS, FILEMTIMES, FILEUSERNAME and FILEGROUPNAME are optional: no
    flags means no ghosts, and the rest leave the member's fields unset."""
    files = [_F(b"/opt/a", data=b"x"), _F(b"/opt/d", mode=0o040755)]
    data = _build(_Package(files, drop_tags=(1034, 1037, 1039, 1040)))
    with _open(data) as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read("opt/a") == b"x"
    assert set(members) == {"opt/a", "opt/d/"}
    for member in members.values():
        assert member.modified is None
        assert member.uname is None
        assert member.gname is None


def test_a_members_fields_come_from_the_header() -> None:
    files = [
        _F(b"/opt/a", mode=0o104755, data=b"x"),
        _F(b"/opt/d", mode=0o042750),
        _F(b"/opt/l", mode=0o120777, link=b"a"),
    ]
    tags = {
        1034: (_INT32, [1_700_000_000, 0, 1]),
        1039: (_STRING_ARRAY, [b"caf\xe9", b"root", b"bin"]),
        1040: (_STRING_ARRAY, [b"wheel", b"g\xff", b"bin"]),
    }
    data = _build(_Package(files, extra_tags=tags))
    with _open(data) as reader:
        members = {m.name: m for m in reader.members()}
    a, d, link = members["opt/a"], members["opt/d/"], members["opt/l"]
    assert a.size == 1
    assert d.size is None
    assert link.size is None
    assert a.mode == 0o4755
    assert d.mode == 0o2750
    assert a.modified is not None
    assert a.modified.utcoffset() is not None
    assert a.modified.timestamp() == 1_700_000_000
    assert a.uname == "caf\ufffd"
    assert a.gname == "wheel"
    assert d.gname == "g\ufffd"
    assert link.link_target == "a"


def test_a_symlink_with_no_target_is_refused_unless_it_is_a_ghost() -> None:
    files = [_F(b"/opt/a", data=b"x"), _F(b"/opt/l", mode=0o120777)]
    with pytest.raises(
        CorruptionError, match="^RPM header: symlink '/opt/l' has no target"
    ):
        _open(_build(_Package(files))).close()
    files[1].flags = 1 << 6
    assert set(_listing(_build(_Package(files)))) == {"opt/a"}


def test_without_device_numbers_there_are_no_hard_link_sets() -> None:
    """rpm builds a set from a device and an inode (rpmfilesBuildNLink): with no
    FILEDEVICES, two files that share an inode are two files."""
    files = [_F(b"/opt/h1", data=b"one"), _F(b"/opt/h2", data=b"two")]
    tags = {1096: (_INT32, [5, 5])}
    data = _build(_Package(files, drop_tags=(1095,), extra_tags=tags))
    assert _listing(data) == {
        "opt/h1": (MemberType.FILE, b"one"),
        "opt/h2": (MemberType.FILE, b"two"),
    }


@pytest.mark.parametrize(
    ("first", "second", "second_listed"),
    [
        (
            _F(b"/opt/a", data=b"one", raw_inode=0),
            _F(b"/opt/b", data=b"two", raw_inode=0),
            (MemberType.FILE, b"two"),
        ),
        (
            _F(b"/opt/a", data=b"one", inode=7),
            _F(b"/opt/b", data=b"two", inode=7, flags=1 << 6),
            None,
        ),
        (
            _F(b"/opt/a", data=b"one", inode=7),
            _F(b"/opt/b", mode=0o120777, link=b"a", inode=7),
            (MemberType.SYMLINK, None),
        ),
    ],
    ids=["inode-0", "ghost", "symlink"],
)
def test_only_regular_files_with_a_positive_inode_share_data(
    first: _F, second: _F, second_listed: tuple[MemberType, bytes | None] | None
) -> None:
    """Two files that share an inode, where the second is a file with inode 0, a
    ghost or a symlink: it never joins a hard-link set, so the first file keeps its
    own data rather than coming back as a hard link."""
    listing = _listing(_build(_Package([first, second])))
    assert listing["opt/a"] == (MemberType.FILE, b"one")
    assert listing.get("opt/b") == second_listed


def test_an_uncompressed_payload_pads_from_its_own_start() -> None:
    """CPIO aligns to 4 bytes from the payload's first byte: a header whose size is
    not a multiple of 4 moves the payload off the file's alignment."""
    tags = {5999: (_STRING, b"xy")}
    data = _build(_Package(_tree(), compressor=None, extra_tags=tags))
    header_at = data.index(b"\x8e\xad\xe8\x01", 100)
    count, size = struct.unpack_from(">II", data, header_at + 8)
    # Off by an odd count, where padding forwards and backwards differ.
    assert (header_at + 16 + 16 * count + size) % 2
    assert _listing(data) == _EXPECTED
    data = _build(_Package(_tree(), compressor=None, stripped=True, extra_tags=tags))
    assert _listing(data) == _EXPECTED


def test_a_stripped_index_equal_to_the_file_count_is_refused() -> None:
    data = _build(_Package(_tree(), stripped=True, compressor=None))
    data = data.replace(b"07070X00000001", b"07070X00000007")
    with pytest.raises(CorruptionError, match="names file 7 of 7"):
        _read_a(data)


@pytest.mark.parametrize(
    ("name_size", "match"),
    [(0, "a name of 0 bytes"), (4097, "a name of 4097 bytes")],
)
def test_a_payload_name_size_out_of_bounds_is_refused(
    name_size: int, match: str
) -> None:
    data = _build(_Package(_tree(), compressor=None))
    entry = b"./opt/t/a.txt\0"
    at = data.index(entry) - 104 + 88
    data = data[:at] + b"%08x" % name_size + data[at + 8 :]
    with pytest.raises(CorruptionError, match=match):
        _read_a(data)


def test_a_payload_name_of_rpms_longest_size_is_read() -> None:
    """4096 bytes, NUL included, is the longest name rpm reads (lib/cpio.c)."""
    path = b"/opt/" + b"n" * (4096 - len(b"./opt/") - 1)
    data = _build(_Package([_F(path, data=b"x")]))
    assert _listing(data) == {path[1:].decode(): (MemberType.FILE, b"x")}


def test_a_payload_field_that_is_not_hexadecimal_names_it() -> None:
    data = _build(_Package(_tree(), compressor=None))
    entry = b"./opt/t/a.txt\0"
    at = data.index(entry) - 104 + 48
    data = data[:at] + b"0000 006" + data[at + 8 :]
    with pytest.raises(
        CorruptionError, match=r"the filesize field '0000 006' is not a number"
    ):
        _read_a(data)


def test_an_unknown_file_type_diagnostic_names_the_member_and_type() -> None:
    data = _build(_Package([_F(b"/opt/odd", mode=0o030644)], compressor=None))
    with _open(data) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    context = diagnostic.context
    assert isinstance(context, UnknownMemberTypeContext)
    assert (context.member_name, context.stored_type) == ("opt/odd", "0o30000")
    assert context.size is None


def test_a_ghost_before_a_symlink_with_no_target_does_not_hide_it() -> None:
    files = [
        _F(b"/opt/g", flags=1 << 6),
        _F(b"/opt/l", mode=0o120777),
    ]
    with pytest.raises(CorruptionError, match="symlink '/opt/l' has no target"):
        _open(_build(_Package(files))).close()


def test_inode_1_is_a_hard_link_set_like_any_positive_inode() -> None:
    files = [_F(b"/opt/a", data=b"x", inode=1), _F(b"/opt/b", data=b"x", inode=1)]
    assert _listing(_build(_Package(files))) == {
        "opt/b": (MemberType.FILE, b"x"),
        "opt/a": (MemberType.HARDLINK, None),
    }


@pytest.mark.parametrize(
    "order", [None, [2, 0, 1], [1, 2, 0]], ids=["header", "last-first", "middle-first"]
)
@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
def test_a_hard_link_set_of_three_takes_its_data_from_the_last(
    order: list[int] | None, stripped: bool
) -> None:
    """The set's last file in header order carries the data, whatever the payload
    order: with three files, the last is not the second."""
    files = [_F(b"/opt/%d" % i, data=b"shared", inode=4) for i in range(3)]
    data = _build(_Package(files, order=order, stripped=stripped))
    with _open(data) as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read("opt/2") == b"shared"
    assert members["opt/2"].type is MemberType.FILE
    for name in ("opt/0", "opt/1"):
        assert members[name].type is MemberType.HARDLINK
        assert members[name].link_target == "opt/2"
        assert members[name].size is None


def test_a_payload_name_of_one_byte_is_an_empty_name() -> None:
    """A name size of 1 is the NUL alone: read, then not found in the header."""
    data = _build(_Package(_tree(), compressor=None))
    entry = b"./opt/t/a.txt\0"
    at = data.index(entry)
    raw = bytearray(data)
    raw[at - 104 + 88 : at - 104 + 96] = b"%08x" % 1
    raw[at] = 0
    with pytest.raises(CorruptionError, match="stores '', which the header does not"):
        _read_a(bytes(raw))


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_listing_reads_none_of_the_payload(pipe: bool) -> None:
    """The member list is the header's: a payload that does not decode lists, and
    fails only when a member's data is read."""
    good = _build(_Package(_tree()))
    payload_at = good.index(b"\x1f\x8b")
    data = good[:payload_at] + b"\x1f\x8b\x08\x00" + b"\0" * 6 + b"\xff" * 64
    if pipe:
        with open_archive(NonSeekableBytesIO(data), format=RPM, streaming=True) as r:
            listed = []
            for member, stream in r.stream_members():
                listed.append(member.name)
                if member.name == "opt/t/a.txt":
                    assert stream is not None
                    with pytest.raises(CorruptionError):
                        stream.read()
        assert listed == _ORDER
        return
    with _open(data) as reader:
        assert [m.name for m in reader.members()] == _ORDER
        assert reader.info.cost.listing_cost is ListingCost.INDEXED
        with pytest.raises(CorruptionError):
            reader.read("opt/t/a.txt")


def test_the_fixtures_list_in_the_order_rpm_wrote_them() -> None:
    """rpm writes hard-link sets after the other files: the listing follows, so a pass
    reads the payload forward once."""
    with open_archive(DATA / "payload-xz.rpm") as reader:
        names = [m.name for m in reader.members()]
    assert names[-4:] == [
        "usr/share/at/dir/hard.txt",
        "usr/share/at/a.txt",
        "usr/share/at/zero.txt",
        "usr/share/at/dir/zero-hard.txt",
    ]


def _differing_link() -> bytes:
    """``_tree()`` with ``opt/t/link`` pointing at ``q.txt`` in the header and at
    ``r.txt`` in its payload entry."""
    files = _tree()
    files[6].link = b"q.txt"
    # In rpm's order, so reading the hard-link set's data passes the link's entry.
    data = _build(_Package(files, compressor=None, order=[0, 1, 2, 6, 4, 5]))
    at = data.rindex(b"q.txt")
    return data[:at] + b"r.txt" + data[at + 5 :]


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_symlink_whose_payload_target_differs_is_reported(pipe: bool) -> None:
    """The header's target is kept, as rpm installs it; the payload's, which
    ``rpm2cpio | cpio`` would make, is reported once a read passes the entry."""
    data = _differing_link()
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, format=RPM, streaming=pipe) as reader:
        targets = {}
        for member, stream in reader.stream_members():
            targets[member.name] = member.link_target
            if stream is not None:
                stream.read()
        if not pipe:
            # Opened again, each read walks past the entry again: still one report.
            for name in ("opt/t/h2", "opt/t/big.bin", "opt/t/h2"):
                reader.read(name)
        reports = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_HEADER_AMBIGUOUS
        ]
    assert targets["opt/t/link"] == "q.txt"
    (report,) = reports
    context = report.context
    assert isinstance(context, HeaderAmbiguityContext)
    assert (context.member_name, context.ambiguity, context.field) == (
        "opt/t/link",
        "copies_differ",
        "FILELINKTOS",
    )
    assert "'r.txt'" in report.message


def test_a_symlink_whose_payload_target_differs_fails_the_read_under_strict() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with _open(_differing_link(), config=config) as reader:
        reader.members()
        assert reader.read("opt/t/a.txt") == b"alpha\n"
        with pytest.raises(archivey.ArchiveyError):
            reader.read("opt/t/h2")


def test_a_matching_payload_target_is_not_reported() -> None:
    with _open(_build(_Package(_tree(), compressor=None))) as reader:
        for member in reader.members():
            if member.type is MemberType.FILE:
                reader.read(member)
        assert not reader.diagnostics.retained
