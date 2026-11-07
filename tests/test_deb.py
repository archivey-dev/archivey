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
    ``compress`` (``""``, ``gz``, ``xz``, ``bz2`` or ``lzma``)."""
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
    with open_archive(io.BytesIO(raw), config=config(4096)) as reader:
        assert reader.read("usr/a") == b"alpha"


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
