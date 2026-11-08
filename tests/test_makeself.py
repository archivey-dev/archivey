"""The makeself reader against archives makeself 2.2.0 to 2.7.1 wrote
(``fixtures/makeself/make-runs.sh``), and against headers this file edits: damage, and
text that tries to pass for the header's variables."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
import re
import tarfile
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveyConfig,
    ContainerFormat,
    CorruptionError,
    ListingLimits,
    ResourceLimitError,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.formats import SequentialReader
from archivey.internal.backends import makeself_reader
from archivey.internal.backends.makeself_reader import MakeselfReader
from tests.conftest import requires_zstd
from tests.streams_util import NonSeekableBytesIO

MAKESELF = archivey.ArchiveFormat.MAKESELF
DATA = Path(__file__).parent / "fixtures" / "makeself"

# What make-runs.sh packs: makeself tars the folder from inside it.
FILES = {
    "a.txt": b"hello\n",
    "sub/b.txt": b"second file\n",
    "setup.sh": b"#!/bin/sh\necho installed\n",
}


def _requires(module: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(
        importlib.util.find_spec(module) is None, reason=f"requires {module}"
    )


READABLE = [
    ("gzip-2.2.0.run", "gzip"),
    ("gzip-2.4.0.run", "gzip"),
    ("gzip-2.4.5.run", "gzip"),
    ("gzip-2.7.1.run", "gzip"),
    ("bzip2-2.7.1.run", "bzip2"),
    ("xz-2.7.1.run", "xz"),
    pytest.param("zstd-2.7.1.run", "zstd", marks=requires_zstd()),
    pytest.param("lz4-2.7.1.run", "lz4", marks=_requires("lz4")),
    pytest.param("lzo-2.7.1.run", "lzop", marks=_requires("lzo")),
    ("nocomp-2.7.1.run", "none"),
    ("base64-2.7.1.run", "gzip"),
    ("base64-2.4.0.run", "none"),
    ("sha256-2.7.1.run", "gzip"),
]


def _contents(reader: archivey.ArchiveReader) -> dict[str, bytes]:
    return {
        member.name: reader.read(member)
        for member in reader.members()
        if member.is_file
    }


@pytest.mark.parametrize(("name", "compression"), READABLE)
def test_every_release_and_compressor_lists_and_verifies(
    name: str, compression: str
) -> None:
    version = name.removesuffix(".run").split("-")[1]
    with open_archive(DATA / name) as reader:
        assert reader.format == MAKESELF
        assert _contents(reader) == FILES
        assert reader.verify_all() == ()
        for member in reader.members():
            if member.is_file:
                assert member.verified is Verification.CHECKSUM, member.name
        info = reader.info
        assert info.format_version == version
        assert info.is_solid
        assert info.extra["makeself.compression"] == compression
        assert info.extra["makeself.payloads"] == 1
        assert info.extra["makeself.label"] == f"Label {version}"
        assert info.extra["makeself.script"] == "./setup.sh"
        assert info.extra["makeself.signed"] is False
        if name.startswith("base64"):
            assert info.extra["makeself.encryption"] == "base64"
        else:
            assert "makeself.encryption" not in info.extra


def test_detection_by_the_header_whatever_the_name() -> None:
    for path in DATA.glob("*.run"):
        found = detect_format(path)
        assert found.format == MAKESELF, path.name
        assert not found.prefixed
        assert found.payload_offset == 0
    data = (DATA / "gzip-2.7.1.run").read_bytes()
    assert detect_format(io.BytesIO(data)).format == MAKESELF


def test_a_pipe_reads_in_one_pass() -> None:
    data = (DATA / "xz-2.7.1.run").read_bytes()
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert {k: v for k, v in got.items() if k in FILES} == FILES


def test_two_payloads_list_one_after_the_other() -> None:
    """makeself 2.4.0 --append adds a second TAR with its own size and digests."""
    with open_archive(DATA / "append-2.4.0.run") as reader:
        names = [m.name for m in reader.members() if m.is_file]
        assert names[-1] == "c.txt"
        assert set(names[:-1]) == set(FILES)
        assert reader.read("c.txt") == b"appended\n"
        assert reader.info.extra["makeself.payloads"] == 2
        assert reader.verify_all() == ()
        assert all(
            m.verified is Verification.CHECKSUM for m in reader.members() if m.is_file
        )


def test_extracts(tmp_path: Path) -> None:
    with open_archive(DATA / "gzip-2.7.1.run") as reader:
        reader.extract_all(tmp_path)
    for name, data in FILES.items():
        assert (tmp_path / name).read_bytes() == data
    assert os.readlink(tmp_path / "link") == "a.txt"


def test_an_encrypted_payload_is_refused_by_name() -> None:
    with pytest.raises(UnsupportedFeatureError, match="encrypted with openssl"):
        open_archive(DATA / "openssl-2.7.1.run")


def test_the_reader_is_a_sequential_reader() -> None:
    assert issubclass(MakeselfReader, SequentialReader)


# Damage -------------------------------------------------------------------------


def _split(data: bytes) -> tuple[bytes, bytes]:
    """A fixture's header and payloads."""
    skip = int(re.search(rb'^skip="([0-9]+)"$', data, re.MULTILINE).group(1))
    end = 0
    for _ in range(skip):
        end = data.index(b"\n", end) + 1
    return data[:end], data[end:]


def _rebuilt(header: bytes, payloads: bytes) -> bytes:
    """``header`` with its ``skip`` line set to its line count, then ``payloads``."""
    header = re.sub(
        rb'^skip="[0-9]+"$',
        b'skip="%d"' % header.count(b"\n"),
        header,
        count=1,
        flags=re.MULTILINE,
    )
    return header + payloads


def _edited(old: bytes, new: bytes, name: str = "gzip-2.7.1.run") -> bytes:
    header, payloads = _split((DATA / name).read_bytes())
    assert header.count(old) == 1, old
    return _rebuilt(header.replace(old, new), payloads)


def test_a_changed_payload_fails_its_digests() -> None:
    data = bytearray((DATA / "nocomp-2.7.1.run").read_bytes())
    data[data.rindex(b"hello\n")] = ord("j")
    with open_archive(io.BytesIO(bytes(data))) as reader:
        with pytest.raises(CorruptionError, match="CRC and MD5 do not match"):
            reader.members()
        failures = reader.verify_all()
        assert {m.name for m, _ in failures} == set(FILES)
        assert all("do not match" in str(e) for _, e in failures)
        for member, _ in failures:
            assert member.verified is not Verification.CHECKSUM


def test_a_cut_payload_raises_and_fails_what_it_covers() -> None:
    data = (DATA / "gzip-2.7.1.run").read_bytes()[:-30]
    with open_archive(io.BytesIO(data)) as reader:
        with pytest.raises(TruncatedError):
            reader.members()
        assert {m.name for m, _ in reader.verify_all()} >= {"a.txt", "setup.sh"}


def test_bytes_after_the_last_payload_are_reported() -> None:
    data = (DATA / "gzip-2.7.1.run").read_bytes() + b"junk"
    with open_archive(io.BytesIO(data)) as reader:
        assert _contents(reader) == FILES
        assert reader.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


def test_license_text_cannot_pass_for_a_variable() -> None:
    """The license is a quoted value, so lines inside it are not assignments."""
    licence = b'licensetxt="Terms.\nskip=\\"3\\"\nfilesizes=\\"1\\"\nMS_Printf()\n"'
    data = _edited(b'licensetxt=""', licence)
    with open_archive(io.BytesIO(data)) as reader:
        assert _contents(reader) == FILES


def test_a_variable_set_twice_is_damage() -> None:
    data = _edited(b'totalsize="224"', b'totalsize="224"\nfilesizes="10"')
    with pytest.raises(CorruptionError, match="assigns 'filesizes' twice"):
        open_archive(io.BytesIO(data))


@pytest.mark.parametrize(
    ("old", "new", "error", "match"),
    [
        (b'filesizes="224"', b'filesizes="22x"', CorruptionError, "not a number"),
        (b'totalsize="224"', b'totalsize="225"', CorruptionError, "not the sum"),
        (
            b'MD5="5ff768fef803869ef92ad9422d26cee0"',
            b'MD5="5ff7"',
            CorruptionError,
            "hexadecimal",
        ),
        (b'filesizes="224"\n', b"", CorruptionError, "no filesizes"),
        (
            b'        eval "gzip -cd"\n',
            b'        eval "brotli -d"\n',
            CorruptionError,
            "more than one way",
        ),
        (
            b'decrypt_cmd=""',
            b'decrypt_cmd="rot13"',
            UnsupportedFeatureError,
            "decrypted with 'rot13'",
        ),
    ],
)
def test_a_damaged_header_is_refused(
    old: bytes, new: bytes, error: type[Exception], match: str
) -> None:
    data = _edited(old, new)
    with pytest.raises(error, match=match):
        open_archive(io.BytesIO(data))


def test_an_unknown_compressor_is_refused_by_name() -> None:
    header, payloads = _split((DATA / "gzip-2.7.1.run").read_bytes())
    header = header.replace(b'eval "gzip -cd"', b'eval "brotli -d"')
    with pytest.raises(UnsupportedFeatureError, match="'brotli -d'"):
        open_archive(io.BytesIO(_rebuilt(header, payloads)))


def test_old_offset_lines_must_agree() -> None:
    data = (DATA / "gzip-2.4.0.run").read_bytes()
    old = b'offset=`head -n 588 "$1" | wc -c | tr -d " "`'
    assert data.count(old) == 1
    data = data.replace(old, old.replace(b"588", b"587"))
    with pytest.raises(CorruptionError, match="different lengths"):
        open_archive(io.BytesIO(data))


def test_a_header_cut_short_is_truncated() -> None:
    data = (DATA / "gzip-2.7.1.run").read_bytes()[:5000]
    with pytest.raises(TruncatedError, match="inside the 762 header lines"):
        open_archive(io.BytesIO(data))


def test_the_header_is_charged_to_max_metadata_bytes() -> None:
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=4096))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=4096"):
        open_archive(DATA / "gzip-2.7.1.run", config=config)


def test_a_header_past_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(makeself_reader, "HEADER_MAX", 8192)
    with pytest.raises(UnsupportedFeatureError, match="longer than 8192 bytes"):
        open_archive(DATA / "gzip-2.7.1.run")


# A forced format ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt",
    [
        archivey.ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP),
        archivey.ArchiveFormat.TAR,
        archivey.ArchiveFormat.ZIP,
    ],
)
def test_another_forced_format_fails_and_names_makeself(
    fmt: archivey.ArchiveFormat,
) -> None:
    with pytest.raises(CorruptionError, match="is a makeself archive"):
        open_archive(DATA / "gzip-2.7.1.run", format=fmt)


def test_the_hint_is_only_for_makeself() -> None:
    with pytest.raises(CorruptionError) as caught:
        open_archive(io.BytesIO(b"#!/bin/sh\necho hi\n" * 100), format="tar.gz")
    assert "makeself" not in str(caught.value)


def test_forced_makeself_reads_as_detection_does() -> None:
    with open_archive(DATA / "gzip-2.4.0.run", format=MAKESELF) as reader:
        assert _contents(reader) == FILES


# Units ----------------------------------------------------------------------------------


def test_cksum_matches_posix() -> None:
    for data, expected in ((b"123456789", 930766865), (b"", 4294967295)):
        crc = makeself_reader._Cksum()
        crc.update(data[:4])
        crc.update(data[4:])
        assert crc.value() == expected


@pytest.mark.parametrize(
    ("command", "decrypt", "expected"),
    [
        (b"gzip -cd", b"", (StreamFormat.GZIP, None)),
        (b"bzip3 -dj4", b"", (StreamFormat.BZIP3, None)),
        (b"bzip3 -dj", b"", (StreamFormat.BZIP3, None)),
        (
            b"(type compress >/dev/null 2>&1 && compress -fcd || gzip -cd)",
            b"",
            (StreamFormat.UNIX_COMPRESS, None),
        ),
        (b"cat", b"base64 --decode", (StreamFormat.UNCOMPRESSED, "base64")),
        (
            b"xz -d",
            b"openssl enc -aes-256-cbc -d -salt -pbkdf2 -md sha256",
            (StreamFormat.XZ, "openssl"),
        ),
        (b"gzip -cd", b"gpg --yes -d", (StreamFormat.GZIP, "gpg")),
        (
            b"openssl aes-256-cbc -d -a -md sha256",
            b"",
            (StreamFormat.UNCOMPRESSED, "openssl"),
        ),
        (b"gpg -d", b"", (StreamFormat.UNCOMPRESSED, "gpg")),
    ],
)
def test_payload_commands(
    command: bytes, decrypt: bytes, expected: tuple[StreamFormat, str | None]
) -> None:
    assert makeself_reader._decoders(command, decrypt) == expected


def test_a_payload_built_here_reads() -> None:
    """A header from the 2.7.1 fixture over a TAR built here, digests recomputed."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("x.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"xyz"))
    payload = gzip.compress(buffer.getvalue(), mtime=0)
    header, _ = _split((DATA / "gzip-2.7.1.run").read_bytes())
    crc = makeself_reader._Cksum()
    crc.update(payload)
    header = re.sub(
        rb'^CRCsum="[0-9]+"$', b'CRCsum="%d"' % crc.value(), header, flags=re.MULTILINE
    )
    header = re.sub(
        rb'^MD5="[0-9a-f]+"$',
        b'MD5="%s"' % hashlib.md5(payload).hexdigest().encode(),
        header,
        flags=re.MULTILINE,
    )
    for name in (b"filesizes", b"totalsize"):
        header = re.sub(
            rb"^%s=\"[0-9]+\"$" % name,
            b'%s="%d"' % (name, len(payload)),
            header,
            flags=re.MULTILINE,
        )
    with open_archive(io.BytesIO(header + payload)) as reader:
        assert reader.read("x.txt") == b"xyz"
        assert reader.verify_all() == ()
