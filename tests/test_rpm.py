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
    ListingCost,
    ListingLimits,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
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
        assert info.cost.listing_cost is (
            ListingCost.REQUIRES_DECOMPRESSION
            if compressed
            else ListingCost.REQUIRES_SCANNING
        )
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
        reader.extract_all(dest)
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

_INT16, _INT32, _INT64, _STRING, _BIN, _STRING_ARRAY = 3, 4, 5, 6, 7, 8
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


@dataclass
class _Package:
    files: list[_F]
    stripped: bool = False
    compressor: bytes | None = b"gzip"
    digest_algo: int | None = 8
    lead_major: int = 3
    signature: dict[int, tuple[int, object]] = field(default_factory=dict)
    extra_tags: dict[int, tuple[int, object]] = field(default_factory=dict)
    drop_tags: tuple[int, ...] = ()
    # Change the payload's entries: the files to store, in order, by index.
    order: list[int] | None = None
    tamper_digest: int | None = None
    after_trailer: bytes = b""
    # End a stripped payload with rpm's index -1 rather than the newc trailer.
    stripped_end: bool = False


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
        1096: (_INT32, [f.inode or i + 1 for i, f in enumerate(files)]),
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
    tags.update(package.extra_tags)
    for tag in package.drop_tags:
        del tags[tag]
    if not files:
        for tag in (1030, 1034, 1035, 1036, 1037, 1039, 1040, 1095, 1096, 1116):
            tags.pop(tag)
        for tag in (1117, 1118, 1028, 5008):
            tags.pop(tag, None)

    # Hard-link sets: data with the last in index order.
    sets: dict[int, list[int]] = {}
    for i, f in enumerate(files):
        if f.inode:
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
        if f.inode and sets[f.inode][-1] != i:
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
    signature = _header({62: (_BIN, b"\0" * 16), **package.signature})
    signature += b"\0" * (-len(signature) % 8)
    return lead + signature + _header(tags) + raw


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
    assert names == list(_EXPECTED)


@pytest.mark.parametrize(
    "tag",
    [
        (1000, (_STRING_ARRAY, [b"ab"] * 200_000)),  # NAME
        (1003, (_INT32, list(range(150_000)))),  # EPOCH
    ],
    ids=["name-strings", "epoch-ints"],
)
def test_a_one_value_tag_declaring_a_long_array_reads_only_its_first(
    tag: tuple[int, tuple[int, object]],
) -> None:
    # NAME, VERSION, EPOCH and the other tags read for one value built the whole
    # array the entry declares to take its first element: a 60 MiB data store of
    # such arrays took 1.22 GB to open. Here the peak was 12 to 16 times the
    # package; now it is about one package.
    number, value = tag
    data = _build(_Package(_tree(), extra_tags={number: value}))

    def open_it() -> None:
        with _open(data) as reader:
            extra = reader.info.extra
            assert extra["rpm.name" if number == 1000 else "rpm.epoch"] in ("ab", 0)

    open_it()
    peak = traced_peak(open_it)
    assert peak < 4 * len(data), peak / len(data)


def test_the_one_value_accessors_check_the_entry_as_the_array_ones_do() -> None:
    # string() and number() read only the first value, and still refuse every
    # entry that strings() and ints() refuse, with the same message.
    from archivey.internal.backends.rpm_reader import Header, _Entry

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
        "int8 array": (2, 3, 1),
        "binary": (_BIN, 1, 0),
    }
    for what, (kind, count, offset) in cases.items():
        header = Header({1: _Entry(kind, count, offset)}, data, "header")
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
                assert one(1) == expected[0], what
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


@pytest.mark.parametrize(
    ("order", "match"),
    [
        ([0, 1, 2, 4, 5], "ends without 1 of the header's files"),
        ([0, 1, 1, 2, 4, 5, 6], "twice"),
    ],
    ids=["missing", "twice"],
)
@pytest.mark.parametrize("stripped", [False, True], ids=["newc", "stripped"])
def test_a_payload_that_does_not_match_the_header(
    order: list[int], match: str, stripped: bool
) -> None:
    data = _build(_Package(_tree(), order=order, stripped=stripped))
    with pytest.raises(CorruptionError, match=match), _open(data) as reader:
        reader.members()


def test_a_payload_name_the_header_does_not_list() -> None:
    data = _build(_Package(_tree(), compressor=None))
    data = data.replace(b"./opt/t/a.txt", b"./opt/t/x.txt")
    with pytest.raises(CorruptionError, match="does not list"), _open(data) as reader:
        reader.members()


def test_a_newc_size_that_disagrees_with_the_header() -> None:
    files = _tree()
    package = _Package(files, compressor=None)
    data = _build(package)
    entry = b"./opt/t/a.txt\0"
    at = data.index(entry) - 104 + 48
    assert data[at : at + 8] == b"%08x" % 6
    data = data[:at] + b"%08x" % 7 + data[at + 8 :]
    with pytest.raises(CorruptionError, match="the header gives 6"), _open(data) as r:
        r.members()


def test_a_stripped_index_past_the_file_list() -> None:
    data = _build(_Package(_tree(), stripped=True, compressor=None))
    data = data.replace(b"07070X00000001", b"07070X00000064")
    with pytest.raises(CorruptionError, match="names file 100 of 7"), _open(data) as r:
        r.members()


def test_data_after_the_trailer_is_reported() -> None:
    data = _build(_Package(_tree(), after_trailer=b"\0\0junk"))
    with _open(data) as reader:
        reader.members()
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.ARCHIVE_TRAILING_DATA in codes


def test_zero_padding_after_the_trailer_is_not_reported() -> None:
    data = _build(_Package(_tree(), after_trailer=b"\0" * 1000))
    with _open(data) as reader:
        reader.members()
        assert not reader.diagnostics.retained


def test_a_cut_package_raises_truncated() -> None:
    data = _build(_Package(_tree(), compressor=None))
    for cut in (50, 200, len(data) - 300, len(data) - 10):
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
        with (
            pytest.raises(CorruptionError, match="ends without 4000"),
            _open(data) as r,
        ):
            r.members()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 2**20


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
    assert "special_file_type" not in odd.extra
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
    with pytest.raises(CorruptionError, match="the header gives 0"):
        _open(data).members()
