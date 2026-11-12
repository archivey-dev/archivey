"""The Debian package reader against packages written by dpkg-deb
(``fixtures/deb/make-archives.sh``), and against packages this file builds, read from a
file and from a pipe."""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import tarfile
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    CorruptionError,
    HashAlgorithm,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from tests.conftest import requires_zstd
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO

DEB = ArchiveFormat.DEB
DATA = Path(__file__).parent / "fixtures" / "deb"
SCRIPT = b"#!/bin/sh\necho hello\n"
BLOB = __import__("random").Random(1).randbytes(5001)

# What dpkg-deb -R unpacks: the data tar at the root, the control tar under DEBIAN/.
LISTED = {
    "DEBIAN/": MemberType.DIRECTORY,
    "DEBIAN/control": MemberType.FILE,
    "DEBIAN/md5sums": MemberType.FILE,
    "DEBIAN/postinst": MemberType.FILE,
    ".": MemberType.DIRECTORY,
    "usr/": MemberType.DIRECTORY,
    "usr/bin/": MemberType.DIRECTORY,
    "usr/bin/hello": MemberType.FILE,
    "usr/bin/hello-hard": MemberType.HARDLINK,
    "usr/share/": MemberType.DIRECTORY,
    "usr/share/doc/": MemberType.DIRECTORY,
    "usr/share/doc/hello/": MemberType.DIRECTORY,
    "usr/share/doc/hello/data.bin": MemberType.FILE,
    "usr/share/doc/hello/link": MemberType.SYMLINK,
}
FIXTURES = [
    pytest.param("xz", id="xz"),
    pytest.param("gzip", id="gzip"),
    pytest.param("zstd", id="zstd", marks=requires_zstd()),
]


def _tar(members: list[tuple[str, bytes | None]], compress: str = "") -> bytes:
    """A tar of (name, data) pairs, ``data`` None for a directory, compressed with
    ``compress`` (``""``, ``gz``, ``xz``, ``bz2`` or ``lzma``). A name ending in
    ``@link`` is a hard link and one ending in ``@symlink`` a symlink, ``data`` its
    target."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1_700_000_000
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif name.endswith("@link"):
                info.name = name.removesuffix("@link")
                info.type = tarfile.LNKTYPE
                info.linkname = data.decode()
                tar.addfile(info)
            elif name.endswith("@symlink"):
                info.name = name.removesuffix("@symlink")
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode()
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    raw = out.getvalue()
    if compress == "gz":
        import gzip

        return gzip.compress(raw, mtime=0)
    if compress == "xz":
        return lzma.compress(raw)
    if compress == "bz2":
        return bz2.compress(raw)
    if compress == "lzma":
        return lzma.compress(raw, format=lzma.FORMAT_ALONE)
    return raw


def _ar(*members: tuple[bytes, bytes]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
        out += b"100644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n" + data
        out += b"\n" * (len(data) & 1)
    return bytes(out)


CONTROL = b"Package: tiny\nVersion: 2:1.0-3\nArchitecture: amd64\n"


def _md5sums(files: dict[str, bytes]) -> bytes:
    return b"".join(
        hashlib.md5(data).hexdigest().encode() + b"  " + name.encode() + b"\n"
        for name, data in files.items()
    )


FILES = {"usr/a": b"alpha", "usr/b": b"beta" * 1000}


def _deb(
    *,
    version: bytes = b"2.0\n",
    control: list[tuple[str, bytes | None]] | None = None,
    data: list[tuple[str, bytes | None]] | None = None,
    control_kind: str = "",
    data_kind: str = "xz",
    before: tuple[tuple[bytes, bytes], ...] = (),
    between: tuple[tuple[bytes, bytes], ...] = (),
    after: tuple[tuple[bytes, bytes], ...] = (),
    version_name: bytes = b"debian-binary",
) -> bytes:
    if control is None:
        control = [
            ("./", None),
            ("./control", CONTROL),
            ("./md5sums", _md5sums(FILES)),
        ]
    if data is None:
        data = [("./", None), ("./usr/", None)]
        data += [(f"./{name}", content) for name, content in FILES.items()]
    control_name = b"control.tar" + (
        b"." + control_kind.encode() if control_kind else b""
    )
    data_name = b"data.tar" + (b"." + data_kind.encode() if data_kind else b"")
    return _ar(
        *before,
        (version_name, version),
        (control_name, _tar(control, control_kind)),
        *between,
        (data_name, _tar(data, data_kind)),
        *after,
    )


def _source(data: bytes, pipe: bool) -> io.BytesIO:
    return NonSeekableBytesIO(data) if pipe else io.BytesIO(data)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize("kind", FIXTURES)
def test_dpkg_deb_packages_list_as_dpkg_deb_unpacks_them(kind: str, pipe: bool) -> None:
    raw = (DATA / f"hello-{kind}.deb").read_bytes()
    with open_archive(_source(raw, pipe), streaming=pipe) as reader:
        listed = {}
        for member, stream in reader.stream_members():
            listed[member.name] = (member.type, stream.read() if stream else None)
            if member.name == "usr/share/doc/hello/data.bin":
                assert member.verified == Verification.CHECKSUM
                assert member.hashes[HashAlgorithm.MD5] == hashlib.md5(BLOB).digest()
        info = reader.info
        assert not reader.diagnostics.retained
    assert {name: kind for name, (kind, _) in listed.items()} == LISTED
    assert list(listed) == list(LISTED)
    assert listed["usr/bin/hello"][1] == SCRIPT
    assert listed["usr/share/doc/hello/data.bin"][1] == BLOB
    assert listed["DEBIAN/control"][1].startswith(b"Package: hello\n")
    assert info.format == DEB
    assert info.format_version == "2.0"
    assert info.is_solid
    assert dict(info.extra) == {
        "deb.package": "hello",
        "deb.version": "1.0-1",
        "deb.architecture": "all",
    }


def test_members_open_in_any_order() -> None:
    with open_archive(DATA / "hello-xz.deb") as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read("usr/share/doc/hello/data.bin") == BLOB
        assert reader.read("DEBIAN/postinst") == b"#!/bin/sh\nexit 0\n"
        assert reader.read("usr/bin/hello") == SCRIPT
    assert members["usr/bin/hello-hard"].link_target == "usr/bin/hello"
    assert members["usr/share/doc/hello/link"].link_target == "../../../bin/hello"
    assert members["DEBIAN/postinst"].mode == 0o755
    # Only the data files md5sums lists carry a digest.
    with_md5 = {n for n, m in members.items() if HashAlgorithm.MD5 in m.hashes}
    assert with_md5 == {"usr/bin/hello", "usr/share/doc/hello/data.bin"}


def test_a_member_seeks_back_and_forth() -> None:
    """With ``seekable_members=True`` (the shared seek matrix has no deb row)."""
    with (
        open_archive(DATA / "hello-xz.deb", seekable_members=True) as reader,
        reader.open("usr/share/doc/hello/data.bin") as stream,
    ):
        assert stream.seekable()
        stream.seek(4000)
        assert stream.read(10) == BLOB[4000:4010]
        stream.seek(5)
        assert stream.read(10) == BLOB[5:15]
        stream.seek(0)
        assert stream.read() == BLOB


def test_detection_and_the_raw_ar_view() -> None:
    path = DATA / "hello-xz.deb"
    assert detect_format(path).format == DEB
    with open_archive(path, format=ArchiveFormat.AR) as reader:
        names = [m.name for m in reader.members()]
    assert names == ["debian-binary", "control.tar.xz", "data.tar.xz"]


def test_a_gnu_ar_name_with_a_slash_is_a_deb() -> None:
    raw = _deb(version_name=b"debian-binary/")
    assert detect_format(io.BytesIO(raw)).format == DEB


@pytest.mark.parametrize(
    ("control_kind", "data_kind"),
    [("", ""), ("gz", "bz2"), ("xz", "lzma")],
    ids=["plain", "gz-bz2", "xz-lzma"],
)
def test_every_compression_dpkg_deb_reads(control_kind: str, data_kind: str) -> None:
    raw = _deb(control_kind=control_kind, data_kind=data_kind)
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as reader:
        read = {m.name: s.read() for m, s in reader.stream_members() if s}
        extra = dict(reader.info.extra)
    assert read["usr/a"] == b"alpha"
    assert read["usr/b"] == b"beta" * 1000
    assert extra["deb.version"] == "2:1.0-3"


def test_a_wrong_md5_fails_the_read() -> None:
    sums = _md5sums({"usr/a": b"other", "usr/b": FILES["usr/b"]})
    raw = _deb(control=[("./control", CONTROL), ("./md5sums", sums)])
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.read("usr/b") == FILES["usr/b"]
        with pytest.raises(CorruptionError):
            reader.read("usr/a")


def test_md5sums_lines_that_name_nothing_are_skipped() -> None:
    sums = b"\n".join(
        [
            b"not-a-digest  usr/a",
            hashlib.md5(b"alpha").hexdigest().encode() + b" *./usr/a",
            b"0" * 32 + b"  usr/missing",
            b"",
            b"z" * 32 + b"  usr/b",
        ]
    )
    raw = _deb(control=[("./control", CONTROL), ("./md5sums", sums)])
    with open_archive(io.BytesIO(raw)) as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read("usr/a") == b"alpha"
        assert reader.read("usr/b") == FILES["usr/b"]
    assert members["usr/a"].hashes == {
        HashAlgorithm.MD5: hashlib.md5(b"alpha").digest()
    }
    assert not members["usr/b"].hashes


def test_another_major_version_is_refused() -> None:
    with pytest.raises(UnsupportedFeatureError, match="version 3"):
        open_archive(io.BytesIO(_deb(version=b"3.0\n")), format=DEB)


def test_a_major_version_too_long_for_int_is_refused() -> None:
    # int() raises ValueError on more than 4300 digits; the digits are compared as
    # bytes, so the refusal is the one any other major version gets.
    version = b"1" * 5000 + b".0\n"
    with pytest.raises(UnsupportedFeatureError, match=r"version 1{20}\.\.\. \(5000"):
        open_archive(io.BytesIO(_deb(version=version)), format=DEB)
    # Leading zeros do not change the version.
    with open_archive(io.BytesIO(_deb(version=b"0" * 5000 + b"2.0\n"))) as reader:
        assert reader.read("usr/a") == b"alpha"


@pytest.mark.parametrize(
    "version", [b"", b"two\n", b"2\n"], ids=["empty", "word", "no-minor"]
)
def test_a_version_that_is_not_one_is_damage(version: bytes) -> None:
    with pytest.raises(CorruptionError, match="format version"):
        open_archive(io.BytesIO(_deb(version=version)), format=DEB)


def test_underscore_members_are_skipped_and_others_refused() -> None:
    skipped = _deb(between=((b"_gpgorigin", b"signature"),))
    with open_archive(io.BytesIO(skipped)) as reader:
        assert reader.read("usr/a") == b"alpha"
    stray = _deb(between=((b"extra", b"x"),))
    with (
        pytest.raises(CorruptionError, match="unexpected member"),
        open_archive(io.BytesIO(stray), format=DEB) as reader,
    ):
        reader.members()


def test_members_after_the_data_tar_are_not_read() -> None:
    raw = _deb(after=((b"trailing", b"anything"),)) + b"not even ar"
    with open_archive(io.BytesIO(raw)) as reader:
        assert "usr/a" in [m.name for m in reader.members()]


def test_the_version_member_must_come_first() -> None:
    raw = _deb(version_name=b"debian-binary", before=((b"_first", b"x"),))
    with pytest.raises(CorruptionError, match="debian-binary"):
        open_archive(io.BytesIO(raw), format=DEB)


def test_the_control_tar_must_come_before_the_data_tar() -> None:
    raw = _ar((b"debian-binary", b"2.0\n"), (b"data.tar", _tar([("a", b"a")])))
    with pytest.raises(CorruptionError, match="no control.tar"):
        open_archive(io.BytesIO(raw), format=DEB)


# Data-tar members that make the DEBIAN path, each of which dpkg-deb -R 1.22 refuses
# with "unexpected pre-existing pathname .../DEBIAN" (GNU tar drops the root and refuses
# a ".." name first). The listed name each refusal reports is the second item.
_DATA_IN_DEBIAN = [
    pytest.param("./DEBIAN/control", "DEBIAN/control", b"Package: fake\n", id="dot"),
    pytest.param("DEBIAN/postinst", "DEBIAN/postinst", b"echo evil\n", id="plain"),
    pytest.param("/DEBIAN/control", "/DEBIAN/control", b"x", id="rooted"),
    pytest.param(".//DEBIAN/control", "DEBIAN/control", b"x", id="double-slash"),
    pytest.param("./usr/../DEBIAN/x", "usr/../DEBIAN/x", b"x", id="dotdot"),
    pytest.param("./DEBIAN/", "DEBIAN/", None, id="directory"),
    pytest.param("./DEBIAN", "DEBIAN", b"x", id="file"),
    pytest.param("./DEBIAN@symlink", "DEBIAN", b"usr", id="symlink"),
    # Stricter than dpkg-deb -R, which writes a literal "usr\..\DEBIAN" directory on
    # POSIX: sanitize_names, and Windows, read the backslashes as separators.
    pytest.param(
        "usr\\..\\DEBIAN/postinst", "usr\\..\\DEBIAN/postinst", b"x", id="backslash"
    ),
    # Stricter too: GNU tar writes a literal "C:" directory, but extraction drops a
    # drive root on every OS.
    pytest.param("C:/DEBIAN/control", "C:/DEBIAN/control", b"x", id="drive"),
    # Stricter too: STRICT and Win32 trim a trailing dot or space, and a
    # case-insensitive filesystem makes debian/ and DEBIAN/ one directory.
    pytest.param("DEBIAN./postinst", "DEBIAN./postinst", b"x", id="trailing-dot"),
    pytest.param("DEBIAN /postinst", "DEBIAN /postinst", b"x", id="trailing-space"),
    pytest.param("./debian/postinst", "debian/postinst", b"x", id="lower-case"),
    pytest.param("./Debian./x", "Debian./x", b"x", id="mixed"),
]


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(("stored", "listed", "content"), _DATA_IN_DEBIAN)
def test_a_data_member_in_debian_is_refused(
    stored: str, listed: str, content: bytes | None, pipe: bool
) -> None:
    """dpkg-deb -R unpacks the data tar, then refuses to unpack the control tar into the
    DEBIAN it finds there. Listing the data copy would replace the real control file."""
    data = [("./", None), ("./usr/", None), ("./usr/a", b"alpha"), (stored, content)]
    raw = _deb(data=data)
    seen = []
    with (
        pytest.raises(CorruptionError, match="DEBIAN/") as caught,
        open_archive(_source(raw, pipe), streaming=pipe) as reader,
    ):
        for member, _stream in reader.stream_members():
            seen.append(member.name)
    assert caught.value.member_name == listed
    assert repr(listed) in str(caught.value)
    # The members before it are delivered, the real control file among them.
    assert seen[:3] == ["DEBIAN/", "DEBIAN/control", "DEBIAN/md5sums"]
    assert seen[-1] == "usr/a"


def test_extracting_a_package_with_data_in_debian_raises(tmp_path: Path) -> None:
    data = [("./usr/", None), ("./usr/a", b"alpha"), ("./DEBIAN/control", b"fake\n")]
    with (
        pytest.raises(CorruptionError, match="DEBIAN/"),
        open_archive(io.BytesIO(_deb(data=data))) as reader,
    ):
        reader.extract_all(tmp_path)
    assert (tmp_path / "DEBIAN" / "control").read_bytes() == CONTROL


@pytest.mark.parametrize(
    "name", ["usr\\..\\DEBIAN/postinst", "usr/../DEBIAN/postinst", "/DEBIAN/postinst"]
)
def test_sanitize_names_cannot_move_a_data_member_into_debian(
    name: str, tmp_path: Path
) -> None:
    data = [("./usr/", None), ("./usr/a", b"alpha"), (name, b"echo evil\n")]
    with (
        pytest.raises(CorruptionError, match="DEBIAN/"),
        open_archive(io.BytesIO(_deb(data=data))) as reader,
    ):
        reader.extract_all(tmp_path, filter=archivey.sanitize_names)
    assert sorted(p.name for p in (tmp_path / "DEBIAN").iterdir()) == [
        "control",
        "md5sums",
    ]


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize(
    ("stored", "listed"),
    [
        pytest.param("./../usr/a", "DEBIAN/../usr/a", id="dotdot"),
        pytest.param("../../x", "DEBIAN/../../x", id="above"),
        pytest.param("..\\usr\\a", "DEBIAN/..\\usr\\a", id="backslash"),
    ],
)
def test_a_control_member_outside_debian_is_refused(
    stored: str, listed: str, pipe: bool
) -> None:
    """GNU tar under dpkg-deb -R refuses a ".." name; sanitize_names would write this
    member into the data tree."""
    control = [("./", None), ("./control", CONTROL), (stored, b"from control")]
    seen = []
    with (
        pytest.raises(CorruptionError, match="outside DEBIAN/") as caught,
        open_archive(_source(_deb(control=control), pipe), streaming=pipe) as reader,
    ):
        for member, _stream in reader.stream_members():
            seen.append(member.name)
    assert caught.value.member_name == listed
    assert seen == ["DEBIAN/", "DEBIAN/control"]


def test_a_control_member_with_dotdot_inside_debian_is_listed() -> None:
    control = [
        ("./", None),
        ("./control", CONTROL),
        ("./a/../postinst", b"#!/bin/sh\n"),
    ]
    with open_archive(io.BytesIO(_deb(control=control))) as reader:
        assert reader.read("DEBIAN/a/../postinst") == b"#!/bin/sh\n"


def test_a_control_hard_link_out_of_debian_is_refused() -> None:
    control = [("./", None), ("./control", CONTROL), ("./x@link", b"../usr/a")]
    with (
        pytest.raises(CorruptionError, match="hard link") as caught,
        open_archive(io.BytesIO(_deb(control=control))) as reader,
    ):
        reader.members()
    assert caught.value.member_name == "DEBIAN/x"
    assert caught.value.link_target == "DEBIAN/../usr/a"


@pytest.mark.parametrize("name", ["DEBIAN./postinst", "DEBIAN /postinst"])
def test_default_extraction_cannot_trim_a_data_member_into_debian(
    name: str, tmp_path: Path
) -> None:
    data = [("./usr/", None), ("./usr/a", b"alpha"), (name, b"echo evil\n")]
    with (
        pytest.raises(CorruptionError, match="DEBIAN/"),
        open_archive(io.BytesIO(_deb(data=data))) as reader,
    ):
        reader.extract_all(tmp_path)
    assert sorted(p.name for p in (tmp_path / "DEBIAN").iterdir()) == [
        "control",
        "md5sums",
    ]


@pytest.mark.parametrize(
    "stored", ["../debian/x", "../DEBIAN./x"], ids=["lower-case", "trailing-dot"]
)
def test_the_control_side_is_not_folded(stored: str) -> None:
    """A control member must stay under DEBIAN/ exactly: "debian/x" is data on Linux."""
    control = [("./", None), ("./control", CONTROL), (stored, b"x")]
    with (
        pytest.raises(CorruptionError, match="outside DEBIAN/"),
        open_archive(io.BytesIO(_deb(control=control))) as reader,
    ):
        reader.members()


def test_a_data_hard_link_to_a_control_file_is_refused() -> None:
    """GNU tar under dpkg-deb -R finds no DEBIAN/control in the data tar to link to."""
    data = [("./usr/", None), ("./usr/a@link", b"DEBIAN/control")]
    with (
        pytest.raises(CorruptionError, match="hard link") as caught,
        open_archive(io.BytesIO(_deb(data=data))) as reader,
    ):
        reader.members()
    assert caught.value.member_name == "usr/a"
    assert caught.value.link_target == "DEBIAN/control"


def test_debian_elsewhere_in_the_data_tar_is_an_ordinary_name() -> None:
    """dpkg-deb -R accepts each of these, and so does archivey: a longer first segment
    is another directory, only the first segment counts, and a symlink's target is a
    path, not a member."""
    data = [
        ("./debianx/", None),
        ("./debianx/x", b"longer"),
        ("./usr/", None),
        ("./usr/DEBIAN/", None),
        ("./usr/DEBIAN/x", b"nested"),
        ("./usr/c@symlink", b"../DEBIAN/control"),
    ]
    with open_archive(io.BytesIO(_deb(data=data))) as reader:
        assert reader.read("debianx/x") == b"longer"
        assert reader.read("usr/DEBIAN/x") == b"nested"
        assert reader.get("usr/c").link_target == "../DEBIAN/control"
        assert reader.read("DEBIAN/control") == CONTROL


def test_held_control_files_count_against_max_metadata_bytes() -> None:
    raw = _deb()

    def config(limit: int | None) -> archivey.ArchiveyConfig:
        limits = archivey.ListingLimits(max_metadata_bytes=limit)
        return archivey.ArchiveyConfig(listing_limits=limits)

    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes=40"),
        open_archive(io.BytesIO(raw), config=config(40)) as reader,
    ):
        reader.members()
    # The sum counts, with the members listed so far: control and md5sums each
    # fit, together they do not.
    held = 4 + len(CONTROL) + len(_md5sums(FILES))
    with (
        pytest.raises(
            ResourceLimitError, match="for the Debian package control file md5sums"
        ),
        open_archive(io.BytesIO(raw), config=config(held - 1)) as reader,
    ):
        reader.members()
    with open_archive(io.BytesIO(raw), config=config(4096)) as reader:
        assert reader.read("usr/a") == b"alpha"


def test_the_md5sums_map_is_charged_for_each_entry() -> None:
    """For short ASCII names the digest map holds about three times the bytes of
    md5sums itself: a name
    and a digest object per line, and the dict's slot. Each entry is charged, so a
    limit twice the file's size refuses a file of short lines."""
    count = 20_000
    sums = b"".join(b"%032x  usr/f%d\n" % (i, i) for i in range(count))
    raw = _deb(control=[("./control", CONTROL), ("./md5sums", sums)])
    limits = archivey.ListingLimits(max_metadata_bytes=2 * len(sums))
    config = archivey.ArchiveyConfig(listing_limits=limits)
    with (
        pytest.raises(ResourceLimitError, match="md5sums entries"),
        open_archive(io.BytesIO(raw), config=config) as reader,
    ):
        reader.members()
    limits = archivey.ListingLimits(max_metadata_bytes=5 * len(sums))
    config = archivey.ArchiveyConfig(listing_limits=limits)
    with open_archive(io.BytesIO(raw), config=config) as reader:
        assert reader.read("usr/a") == b"alpha"


@pytest.mark.parametrize(
    "tail", ["\U0001f600".encode(), b"\xff"], ids=["astral", "undecodable"]
)
def test_md5sums_names_are_charged_at_their_str_width(tail: bytes) -> None:
    """CPython stores a str at 1, 2 or 4 bytes a character, as its widest character
    needs. An emoji makes a long name 4 bytes a character, and an undecodable byte
    (a lone surrogate after decoding) 2: about 4 or 2 times the name's UTF-8 bytes.
    The charge follows the width, so 2.5 times the file's size is refused."""
    sums = b"".join(
        b"%032x  usr/%s%d%s\n" % (i, b"a" * 1000, i, tail) for i in range(2000)
    )
    raw = _deb(control=[("./control", CONTROL), ("./md5sums", sums)])
    limits = archivey.ListingLimits(max_metadata_bytes=int(2.5 * len(sums)))
    config = archivey.ArchiveyConfig(listing_limits=limits)
    with (
        pytest.raises(ResourceLimitError, match="md5sums entries"),
        open_archive(io.BytesIO(raw), config=config) as reader,
    ):
        reader.members()


def test_reads_out_of_order_charge_the_control_files_once() -> None:
    """Each out-of-order read walks the package again; the control files it holds
    again were charged by the listing. Before, every walk added them to a total of
    its own, so a few reads crossed a limit the listing met."""
    raw = _deb()
    with open_archive(io.BytesIO(raw)) as reader:
        reader.members()
        # The figure the limit checks.
        listed = reader._resource_usage().listing_metadata_bytes
    # The digest map's entries, charged as the walk adds them.
    from archivey.internal.backends.deb_reader import _MD5_ENTRY

    entries = sum(len(name) + _MD5_ENTRY for name in FILES)  # ASCII names
    held = 4 + len(CONTROL) + len(_md5sums(FILES)) + entries
    limits = archivey.ListingLimits(max_metadata_bytes=listed + held)
    config = archivey.ArchiveyConfig(listing_limits=limits)
    with open_archive(io.BytesIO(raw), config=config) as reader:
        files = [m.name for m in reader.members() if m.type is MemberType.FILE]
        for name in reversed(files):
            reader.read(name)


def test_a_hard_link_in_the_control_tar_names_its_target_under_debian() -> None:
    control = [
        ("./", None),
        ("./control", CONTROL),
        ("./postinst", b"#!/bin/sh\n"),
        ("./preinst@link", b"./postinst"),
    ]
    with open_archive(io.BytesIO(_deb(control=control))) as reader:
        link = reader.get("DEBIAN/preinst")
        assert link.type is MemberType.HARDLINK
        assert link.link_target == "DEBIAN/postinst"
        assert reader.read(link) == b"#!/bin/sh\n"


def test_a_huge_version_member_is_refused_before_it_is_read() -> None:
    # A header that declares 10 GB over a few bytes of body: the size is checked
    # against max_metadata_bytes before any of it is read.
    raw = bytearray(_deb())
    raw[8 + 48 : 8 + 58] = b"9999999999"

    def refuse() -> None:
        with (
            pytest.raises(ResourceLimitError, match="debian-binary member"),
            open_archive(NonSeekableBytesIO(bytes(raw)), streaming=True) as reader,
        ):
            reader.members()

    refuse()
    assert traced_peak(refuse) < 4 * 2**20


def test_the_package_fields_appear_once_the_control_tar_is_read() -> None:
    with open_archive(io.BytesIO(_deb())) as reader:
        assert dict(reader.info.extra) == {}
        assert reader.info.format_version == "2.0"
        reader.members()
        assert reader.info.extra["deb.package"] == "tiny"


def test_md5_is_checked_where_fips_refuses_it_for_security(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new = hashlib.new

    def fips_new(name: str, *args: object, **kwargs: object) -> object:
        if name == "md5" and kwargs.get("usedforsecurity", True):
            raise ValueError("[digital envelope routines] unsupported")
        return new(name, *args, **kwargs)  # pyrefly: ignore[bad-argument-type]

    monkeypatch.setattr(hashlib, "new", fips_new)
    with open_archive(io.BytesIO(_deb())) as reader:
        for member, stream in reader.stream_members():
            if member.name == "usr/a":
                assert stream is not None
                assert stream.read() == b"alpha"
                assert member.verified is Verification.CHECKSUM
                break
        else:
            pytest.fail("usr/a is not listed")


def test_a_cut_package_raises() -> None:
    raw = (DATA / "hello-xz.deb").read_bytes()
    for cut in (4, 70, len(raw) - 100):
        with (
            pytest.raises((TruncatedError, CorruptionError)),
            open_archive(io.BytesIO(raw[:cut]), format=DEB) as reader,
        ):
            for _member, stream in reader.stream_members():
                if stream is not None:
                    stream.read()
