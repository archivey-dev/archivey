"""XAR archives (``.xar``, macOS ``.pkg``), read through the XAR backend."""

from __future__ import annotations

import hashlib
import io
import zlib
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    CompressionAlgorithm,
    CorruptionError,
    DiagnosticCode,
    HashAlgorithm,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.config import AcceleratorMode
from archivey.diagnostics import MemberTimestampContext, UnknownMemberTypeContext
from tests.conftest import requires
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO
from tests.xar_util import ENCODINGS, HEADER, XarFile, pack_xar, write_xar

BSDTAR = Path(__file__).parent / "fixtures" / "external" / "xar_bsdtar"
STAMP = datetime(2024, 3, 1, 12, tzinfo=UTC)
TEXT = b"".join(b"line %d of the text\n" % i for i in range(3000))
TREE = [
    XarFile("text.txt", TEXT),
    XarFile(
        "dir",
        type="directory",
        children=[XarFile("inner.bin", bytes(range(256)) * 40)],
    ),
]


def _open(raw: bytes, **kwargs: object) -> archivey.ArchiveReader:
    return open_archive(io.BytesIO(raw), **kwargs)  # type: ignore[arg-type]


def _limits(**kwargs: int) -> archivey.ArchiveyConfig:
    return archivey.ArchiveyConfig(listing_limits=archivey.ListingLimits(**kwargs))


# --- archives bsdtar wrote --------------------------------------------------------


_COMPRESSION = {
    "none": CompressionAlgorithm.STORED,
    "gzip": CompressionAlgorithm.DEFLATE,
    "bzip2": CompressionAlgorithm.BZIP2,
    "lzma": CompressionAlgorithm.LZMA,
    "xz": CompressionAlgorithm.XZ,
}


@pytest.mark.parametrize("encoding", list(_COMPRESSION))
def test_bsdtar_archives_list_and_read(encoding: str) -> None:
    path = BSDTAR / f"{encoding}.xar"
    assert detect_format(path).format == ArchiveFormat.XAR
    with open_archive(path) as reader:
        assert reader.format == ArchiveFormat.XAR
        assert reader.info.format_version == "1"
        members = {m.name: m for m in reader.members()}
        assert list(members) == [
            "b.txt",
            "dir/",
            "dir/a.txt",
            "link",
            "hard.txt",
            "caf�.txt",
        ]
        text = members["b.txt"]
        assert text.type is MemberType.FILE
        assert text.mode == 0o640
        assert (text.uname, text.uid) == ("root", 0)
        assert text.modified == STAMP
        assert text.compression[0].algo is _COMPRESSION[encoding]
        assert set(text.hashes) == {HashAlgorithm.SHA1}
        assert members["dir/"].type is MemberType.DIRECTORY
        # The entry bsdtar marks "original" carries the data.
        assert members["dir/a.txt"].type is MemberType.FILE
        assert members["link"].type is MemberType.SYMLINK
        assert members["link"].link_target == "dir/a.txt"
        assert members["hard.txt"].type is MemberType.HARDLINK
        assert members["hard.txt"].link_target == "dir/a.txt"
        assert members["caf�.txt"].raw_name == "caf�.txt".encode()
        read = {}
        for member, stream in reader.stream_members():
            if stream is not None and member.is_file:
                read[member.name] = stream.read()
                assert member.verified is Verification.CHECKSUM
        assert read["dir/a.txt"] == b"hello\n"
        assert read["caf�.txt"] == b"latin-1 name\n"
        assert len(read["b.txt"]) == text.size
        assert reader.verify_all().failures == ()
        assert not reader.diagnostics.retained


# --- archives the test writer writes ----------------------------------------------


@pytest.mark.parametrize("encoding", list(ENCODINGS))
def test_every_encoding_reads_and_is_checked(encoding: str) -> None:
    raw = write_xar([XarFile("a.txt", TEXT, encoding=encoding)])
    with _open(raw) as reader:
        (member,) = reader.members()
        assert member.size == len(TEXT)
        assert reader.read("a.txt") == TEXT
        assert member.verified is Verification.CHECKSUM


@pytest.mark.parametrize("digest", ["md5", "sha1", "sha256", "sha512"])
def test_every_file_checksum_is_a_member_hash(digest: str) -> None:
    raw = write_xar([XarFile("a.txt", TEXT, digest=digest)])
    with _open(raw) as reader:
        (member,) = reader.members()
        assert list(member.hashes) == [HashAlgorithm(digest)]
        assert reader.read("a.txt") == TEXT
        assert member.verified is Verification.CHECKSUM


@pytest.mark.parametrize(
    ("attrs", "style"),
    [(' style="sha224"', "sha224"), ("", ""), (' style=""', "")],
    ids=["unsupported style", "no style", "empty style"],
)
def test_a_file_checksum_archivey_cannot_check_is_reported(
    attrs: str, style: str
) -> None:
    digest = hashlib.sha224(b"0123456789").hexdigest()
    toc = (
        '<?xml version="1.0"?><xar><toc><file id="1"><name>a</name><type>file</type>'
        "<data><length>10</length><offset>0</offset><size>10</size>"
        '<encoding style="application/octet-stream"/>'
        f"<extracted-checksum{attrs}>{digest}</extracted-checksum></data>"
        "</file></toc></xar>"
    ).encode()
    with _open(pack_xar(toc, b"0123456789", algorithm=0)) as reader:
        (member,) = reader.members()
        assert member.hashes == {}
        (diagnostic,) = member.diagnostics
        assert diagnostic.code is DiagnosticCode.DIGEST_UNVERIFIABLE
        assert diagnostic.context.algorithm == style  # type: ignore[union-attr]
        assert reader.read("a") == b"0123456789"
        assert member.verified is Verification.LENGTH


def test_a_file_with_no_checksum_reports_nothing() -> None:
    toc = (
        b'<?xml version="1.0"?><xar><toc><file id="1"><name>a</name><type>file</type>'
        b"<data><length>10</length><offset>0</offset><size>10</size>"
        b'<encoding style="application/octet-stream"/></data></file></toc></xar>'
    )
    with _open(pack_xar(toc, b"0123456789", algorithm=0)) as reader:
        (member,) = reader.members()
        assert not member.diagnostics


def test_a_file_that_fails_its_checksum_is_reported() -> None:
    raw = bytearray(write_xar([XarFile("a.txt", TEXT, encoding="none")]))
    raw[-1] ^= 1
    with _open(bytes(raw)) as reader:
        ((member, error),) = reader.verify_all().failures
        assert member.name == "a.txt"
        assert isinstance(error, CorruptionError)
    with _open(bytes(raw)) as reader, pytest.raises(CorruptionError):
        reader.read("a.txt")


# --- bytes after a member's stream ---------------------------------------------------

# Two zlib streams, A then B, in one member. libarchive fails on anything after a
# member's stream ("XAR decompressor made no progress"), and so does archivey, with or
# without rapidgzip: under it the Adler-32 at the end covers only B, and the second
# decode that mismatch starts finds the first stream ending early.
_FIRST = b"first stream " * 400
_SECOND = b"second stream " * 300
_ACCELERATOR_MODES = [
    pytest.param(AcceleratorMode.OFF, id="off"),
    pytest.param(AcceleratorMode.ON, id="rapidgzip", marks=requires("rapidgzip")),
]


def _member_stored_as(stored: bytes, data: bytes, encoding: str = "gzip") -> bytes:
    """A XAR of one file ``a`` whose heap holds ``stored`` and whose TOC declares the
    size and sha1 of ``data``."""
    style = ENCODINGS[encoding][0]
    digest = hashlib.sha1(data).hexdigest()
    return _single(
        f"<length>{len(stored)}</length><offset>0</offset><size>{len(data)}</size>"
        f"<encoding style={quoteattr(style)}/>"
        f'<extracted-checksum style="sha1">{digest}</extracted-checksum>',
        heap=stored,
    )


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(
    "declared", [_FIRST + _SECOND, _FIRST], ids=["declares-both", "declares-first"]
)
@pytest.mark.parametrize("chunk", [-1, 1024], ids=["whole", "bounded"])
def test_a_second_zlib_stream_in_a_member_is_refused(
    mode: AcceleratorMode, declared: bytes, chunk: int
) -> None:
    raw = _member_stored_as(zlib.compress(_FIRST) + zlib.compress(_SECOND), declared)
    config = archivey.ArchiveyConfig(use_rapidgzip=mode)
    with (
        _open(raw, config=config) as reader,
        reader.open("a") as stream,
        pytest.raises(CorruptionError),
    ):
        while stream.read(chunk) and chunk > 0:
            pass


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
def test_an_empty_second_zlib_stream_in_a_member_is_refused(
    mode: AcceleratorMode,
) -> None:
    # rapidgzip's output is A, and the last trailer is the empty stream's Adler-32
    # (1), so the check's second decode reaches the first stream's end exactly at
    # the output's end, with input left (round 1 K1).
    raw = _member_stored_as(zlib.compress(_FIRST) + zlib.compress(b""), _FIRST)
    config = archivey.ArchiveyConfig(use_rapidgzip=mode)
    with (
        _open(raw, config=config) as reader,
        pytest.raises(CorruptionError, match="after its end"),
    ):
        reader.read("a")


@pytest.mark.parametrize("encoding", ["gzip", "bzip2", "lzma", "xz"])
@pytest.mark.parametrize("tail", [b"junk", b"\0\0\0\0"], ids=["junk", "zeros"])
def test_bytes_after_a_member_stream_are_refused(encoding: str, tail: bytes) -> None:
    if encoding == "xz" and tail[0] == 0:
        pytest.skip("four zero bytes are xz stream padding, part of the format")
    raw = _member_stored_as(ENCODINGS[encoding][1](TEXT) + tail, TEXT, encoding)
    with _open(raw) as reader, pytest.raises(CorruptionError, match="after its end"):
        reader.read("a")


def test_nested_files_take_their_directory_path_in_document_order() -> None:
    with _open(write_xar(TREE)) as reader:
        assert [m.name for m in reader.members()] == [
            "text.txt",
            "dir/",
            "dir/inner.bin",
        ]
        assert reader.read("dir/inner.bin") == bytes(range(256)) * 40


@pytest.mark.parametrize("checksum", ["none", "md5", "sha1"])
def test_the_toc_checksum_algorithms(checksum: str) -> None:
    with _open(write_xar(TREE, checksum=checksum)) as reader:
        assert len(reader.members()) == 3


def test_a_toc_that_fails_its_checksum_is_refused() -> None:
    raw = write_xar(TREE, corrupt_toc_checksum=True)
    with pytest.raises(CorruptionError, match="fails its checksum"):
        _open(raw)


def _named_algorithm(name: bytes, style: str, size: int, digest: bytes) -> bytes:
    toc = (
        f'<xar><toc><checksum style="{style}"><offset>0</offset><size>{size}</size>'
        '</checksum><file id="1"><name>a</name><type>directory</type></file>'
        "</toc></xar>"
    ).encode()
    return pack_xar(toc, digest, algorithm=3, header_extra=name.ljust(36, b"\0"))


def test_a_toc_checked_with_a_named_algorithm() -> None:
    toc_text = (
        b'<xar><toc><checksum style="sha256"><offset>0</offset><size>32</size>'
        b'</checksum><file id="1"><name>a</name><type>directory</type></file>'
        b"</toc></xar>"
    )
    digest = hashlib.sha256(zlib.compress(toc_text)).digest()
    raw = pack_xar(
        toc_text, digest, algorithm=3, header_extra=b"sha256".ljust(36, b"\0")
    )
    with _open(raw) as reader:
        assert [m.name for m in reader.members()] == ["a/"]
    bad = pack_xar(
        toc_text, bytes(32), algorithm=3, header_extra=b"sha256".ljust(36, b"\0")
    )
    with pytest.raises(CorruptionError, match="fails its checksum"):
        _open(bad)


def test_a_toc_checked_with_an_unknown_algorithm_is_unsupported() -> None:
    raw = _named_algorithm(b"whirlpool", "whirlpool", 64, bytes(64))
    with pytest.raises(UnsupportedFeatureError, match="whirlpool"):
        _open(raw)


@pytest.mark.parametrize(
    ("toc", "algorithm", "message"),
    [
        ("", 1, "the table of contents has none"),
        (
            '<checksum style="md5"><offset>0</offset><size>20</size></checksum>',
            1,
            "names sha1 and the table of contents 'md5'",
        ),
        (
            '<checksum style="sha1"><offset>0</offset><size>16</size></checksum>',
            1,
            "16",
        ),
        (
            '<checksum style="sha1"><offset>x</offset><size>20</size></checksum>',
            1,
            "offset",
        ),
        (
            '<checksum style="sha1"><offset>-1</offset><size>20</size></checksum>',
            1,
            "offset -1, size 20",
        ),
        ("", 9, "checksum algorithm 9"),
    ],
)
def test_toc_checksum_damage(toc: str, algorithm: int, message: str) -> None:
    xml = f'<xar><toc>{toc}<file id="1"><name>a</name></file></toc></xar>'.encode()
    raw = pack_xar(xml, bytes(20), algorithm=algorithm)
    with pytest.raises(CorruptionError, match=message):
        _open(raw, format=ArchiveFormat.XAR)


def test_a_hard_link_written_before_its_original_waits_for_it() -> None:
    files = [
        XarFile("link.txt", type="hardlink", type_attrs=' link="7"'),
        XarFile(
            "data.txt",
            b"shared",
            type="hardlink",
            type_attrs=' link="original"',
            id="7",
        ),
    ]
    with _open(write_xar(files)) as reader:
        members = reader.members()
        assert [(m.name, m.type) for m in members] == [
            ("data.txt", MemberType.FILE),
            ("link.txt", MemberType.HARDLINK),
        ]
        assert members[1].link_target == "data.txt"
        assert reader.read("link.txt") == b"shared"


def test_a_hard_link_to_a_missing_entry_is_refused() -> None:
    files = [XarFile("link.txt", type="hardlink", type_attrs=' link="99"')]
    with _open(write_xar(files)) as reader, pytest.raises(CorruptionError, match="99"):
        reader.members()


@pytest.mark.parametrize(
    "files",
    [
        [XarFile("link.txt", type="hardlink")],
        # An empty link must not bind to an entry whose id is empty too.
        [
            XarFile("link.txt", type="hardlink", type_attrs=' link=""'),
            XarFile("data.txt", b"x", id=""),
        ],
    ],
)
def test_a_hard_link_that_names_no_entry_is_refused(files: list[XarFile]) -> None:
    with (
        _open(write_xar(files)) as reader,
        pytest.raises(CorruptionError, match="'link.txt' names no entry"),
    ):
        reader.members()


def test_a_base64_name_decodes_with_the_encoding_given() -> None:
    files = [XarFile("", b"x", name_xml='<name enctype="base64">Y2Fm6S50eHQ=</name>')]
    raw = write_xar(files)
    with _open(raw, encoding="latin-1") as reader:
        (member,) = reader.members()
        assert member.name == "caf\xe9.txt"
        assert member.raw_name == b"caf\xe9.txt"
    with _open(raw) as reader:
        (member,) = reader.members()
        assert member.name == "caf\udce9.txt"


def test_a_name_that_is_not_base64_is_refused() -> None:
    files = [XarFile("", b"x", name_xml='<name enctype="base64">!!</name>')]
    with pytest.raises(CorruptionError, match="base64"):
        _open(write_xar(files))


@pytest.mark.parametrize(
    ("files", "message"),
    [
        ([XarFile("", b"x", name_xml="")], "has no name"),
        ([XarFile("", b"x", name_xml="<name></name>")], "empty name"),
        ([XarFile("a", b"x", extra="<name>b</name>")], "two names"),
        # The same text under another encoding is another name.
        (
            [XarFile("Zm9v", b"x", extra='<name enctype="base64">Zm9v</name>')],
            "two names",
        ),
    ],
)
def test_name_damage(files: list[XarFile], message: str) -> None:
    with pytest.raises(CorruptionError, match=message):
        _open(write_xar(files))


def test_a_name_repeated_the_same_is_one_name() -> None:
    """Apple's productbuild writes each top-level file's <name> twice, the same both
    times: every real installer package seen (Node.js 22, GitHub CLI 2.62, Miniconda)
    was refused before. The repeat is one name, as xar and pkgutil read it, also for a
    directory and the files under it."""
    files = [
        XarFile("Distribution", b"<installer/>", extra="<name>Distribution</name>"),
        XarFile(
            "Resources",
            type="directory",
            extra="<name>Resources</name>",
            children=[XarFile("LICENSE", b"text", extra="<name>LICENSE</name>")],
        ),
    ]
    with _open(write_xar(files)) as reader:
        assert [m.name for m in reader.members()] == [
            "Distribution",
            "Resources/",
            "Resources/LICENSE",
        ]
        assert reader.read("Resources/LICENSE") == b"text"


def test_a_directory_listing_files_before_its_name_is_refused() -> None:
    xml = (
        b'<xar><toc><file id="1"><type>directory</type>'
        b'<file id="2"><name>a</name></file><name>d</name></file></toc></xar>'
    )
    with pytest.raises(CorruptionError, match="before its name"):
        _open(pack_xar(xml, b"", algorithm=0), format=ArchiveFormat.XAR)


def test_device_entries_are_other_and_unknown_types_are_reported() -> None:
    files = [
        XarFile("pipe", type="fifo"),
        XarFile("odd", b"payload", type="whiteout"),
        XarFile("empty-odd", type="whiteout"),
    ]
    with _open(write_xar(files)) as reader:
        pipe, odd, empty_odd = reader.members()
        assert pipe.type is MemberType.OTHER
        assert not pipe.diagnostics
        # A type xar does not write keeps its data readable.
        assert odd.type is MemberType.FILE
        assert reader.read("odd") == b"payload"
        assert [d.code for d in odd.diagnostics] == [DiagnosticCode.MEMBER_TYPE_UNKNOWN]
        assert empty_odd.type is MemberType.OTHER
        assert [d.code for d in empty_odd.diagnostics] == [
            DiagnosticCode.MEMBER_TYPE_UNKNOWN
        ]


def test_owner_mode_and_times() -> None:
    extra = (
        "<mode>04755</mode><uid>501</uid><gid>20</gid><user>davi</user>"
        "<group>staff</group><mtime>2024-03-01T12:00:00Z</mtime>"
        "<atime>2024-03-02T12:00:00.5Z</atime><ctime>2024-03-03T12:00:00Z</ctime>"
    )
    with _open(write_xar([XarFile("a", b"x", extra=extra)])) as reader:
        (member,) = reader.members()
        assert member.mode == 0o4755
        assert (member.uid, member.gid) == (501, 20)
        assert (member.uname, member.gname) == ("davi", "staff")
        assert member.modified == STAMP
        assert member.accessed == datetime(2024, 3, 2, 12, 0, 0, 500000, tzinfo=UTC)
        assert member.ctime == datetime(2024, 3, 3, 12, tzinfo=UTC)
        assert member.created is None


def test_an_unreadable_time_is_reported_and_bad_numbers_are_skipped() -> None:
    extra = (
        "<mtime>yesterday</mtime><atime>2024-13-01T00:00:00Z</atime>"
        "<mode>9z</mode><uid>-x</uid>"
    )
    with _open(write_xar([XarFile("a", b"x", extra=extra)])) as reader:
        (member,) = reader.members()
        assert (member.modified, member.accessed) == (None, None)
        assert member.mode is None
        assert member.uid is None
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ] * 2


def test_a_time_without_its_zone_is_not_guessed() -> None:
    extra = "<mtime>2024-03-01T12:00:00</mtime>"
    with _open(write_xar([XarFile("a", b"x", extra=extra)])) as reader:
        (member,) = reader.members()
        assert member.modified is None
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ]


def _single(data_xml: str, heap: bytes = b"0123456789") -> bytes:
    xml = (
        '<xar><toc><file id="1"><name>a</name><type>file</type>'
        f"<data>{data_xml}</data></file></toc></xar>"
    ).encode()
    return pack_xar(xml, heap, algorithm=0)


def test_an_unknown_encoding_lists_and_refuses_to_read() -> None:
    raw = _single(
        "<length>4</length><offset>0</offset><size>4</size>"
        '<encoding style="application/x-zstd"/>'
    )
    with _open(raw, format=ArchiveFormat.XAR) as reader:
        (member,) = reader.members()
        assert member.compression[0].algo is CompressionAlgorithm.UNKNOWN
        with pytest.raises(UnsupportedFeatureError, match="x-zstd"):
            reader.read("a")


@pytest.mark.parametrize(
    ("data_xml", "error", "message"),
    [
        ("<length>4</length><offset>0</offset>", CorruptionError, "no offset"),
        (
            "<length>4</length><offset>-1</offset><size>4</size>",
            CorruptionError,
            "negative",
        ),
        (
            (
                "<length>4</length><offset>0</offset><size>4</size>"
                '<extracted-checksum style="sha1">abc</extracted-checksum>'
            ),
            CorruptionError,
            "malformed sha1",
        ),
    ],
)
def test_data_damage_at_open(data_xml: str, error: type, message: str) -> None:
    with pytest.raises(error, match=message):
        _open(_single(data_xml), format=ArchiveFormat.XAR)


@pytest.mark.parametrize(
    ("data_xml", "error", "message"),
    [
        (
            "<length>40</length><offset>0</offset><size>40</size>",
            TruncatedError,
            "ends inside",
        ),
        (
            "<length>4</length><offset>0</offset><size>5</size>",
            CorruptionError,
            "says 5",
        ),
    ],
)
def test_data_damage_on_read(data_xml: str, error: type, message: str) -> None:
    with _open(_single(data_xml), format=ArchiveFormat.XAR) as reader:
        reader.members()
        with pytest.raises(error, match=message):
            reader.read("a")


def test_stored_data_reads_from_the_heap_offset() -> None:
    raw = _single("<length>4</length><offset>3</offset><size>4</size>")
    with _open(raw, format=ArchiveFormat.XAR) as reader:
        assert reader.read("a") == b"3456"


def test_a_document_type_is_refused() -> None:
    xml = (
        b'<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
        b"<xar><toc><file><name>&b;</name></file></toc></xar>"
    )
    with pytest.raises(CorruptionError, match="document type"):
        _open(pack_xar(xml, b"", algorithm=0), format=ArchiveFormat.XAR)


def test_toc_damage() -> None:
    with pytest.raises(CorruptionError, match="not XML"):
        _open(pack_xar(b"<xar><toc>", b"", algorithm=0), format=ArchiveFormat.XAR)
    deep = b"<xar>" + b"<toc>" * 2100 + b"</toc>" * 2100 + b"</xar>"
    with pytest.raises(CorruptionError, match="nests more than 2048"):
        _open(pack_xar(deep, b"", algorithm=0), format=ArchiveFormat.XAR)


def test_text_of_many_lines_is_not_kept_one_piece_per_line() -> None:
    # expat hands character data over one line at a time unless asked to buffer it,
    # and the parser kept each piece in a list: 8 bytes of list slot for each byte of
    # a TOC of "a\n" lines, so a 64 MiB TOC took 704 MB to open. Here the peak was
    # 11x the TOC. Buffered, it is about 4x: the TOC, the pieces and their join.
    head = b'<xar><toc><file id="1"><name>a</name><type>file</type><mode>'
    tail = b"</mode></file></toc></xar>"
    xml = head + b"a\n" * (1 << 20) + tail
    raw = pack_xar(xml, b"", algorithm=0)

    def list_it() -> None:
        with _open(raw, format=ArchiveFormat.XAR) as reader:
            assert [m.name for m in reader.members()] == ["a"]

    list_it()
    peak = traced_peak(list_it)
    assert peak < 7 * len(xml), peak


def test_a_tag_of_millions_of_attributes_is_refused_before_expat_builds_it() -> None:
    # expat builds a tag's whole attribute dict before any handler runs: a 13 MB TOC
    # of one <file> with a million attributes took 1.67 GB. A scan refuses the tag
    # first, so the peak stays near the TOC.
    attrs = b"".join(b' a%d="%d"' % (i, i) for i in range(200_000))
    xml = b'<xar><toc><file id="1"' + attrs + b"><name>a</name></file></toc></xar>"
    raw = pack_xar(xml, b"", algorithm=0)

    def open_it() -> None:
        with pytest.raises(CorruptionError, match="tag of more than 65536"):
            _open(raw, format=ArchiveFormat.XAR)

    open_it()
    peak = traced_peak(open_it)
    assert peak < 4 * len(xml), peak


def test_the_tag_scan_counts_attributes_not_value_bytes() -> None:
    # A long value is one piece: it costs its own bytes and nothing more. A ">" in a
    # value does not end the tag, so it cannot split a long tag into short ones.
    name = "n" * 200_000
    xml = (
        b'<xar><toc><file id="1" note="'
        + b"x" * 100_000
        + b'"><name>'
        + name.encode()
        + b"</name><type>file</type></file></toc></xar>"
    )
    with _open(pack_xar(xml, b"", algorithm=0), format=ArchiveFormat.XAR) as reader:
        assert [m.name for m in reader.members()] == [name]
    split = b"".join(b' a%d=">"' % i for i in range(20_000))
    xml = b'<xar><toc><file id="1"' + split + b"><name>a</name></file></toc></xar>"
    with pytest.raises(CorruptionError, match="tag of more than"):
        _open(pack_xar(xml, b"", algorithm=0), format=ArchiveFormat.XAR)


def test_a_utf16_toc_is_refused_so_the_tag_scan_sees_what_expat_parses() -> None:
    # In UTF-16-LE, U+4E3E is the bytes 3E 4E: a byte scan would see a ">" after
    # each attribute name and count many short tags, while expat parses one tag
    # and builds all its attributes. A NUL byte marks every UTF-16 TOC.
    attrs = "".join(f' \u4e3e{i}="{i}"' for i in range(200_000))
    xml = (
        '<xar><toc><file id="1"' + attrs + "><name>a</name></file></toc></xar>"
    ).encode("utf-16")
    raw = pack_xar(xml, b"", algorithm=0)

    def open_it() -> None:
        with pytest.raises(CorruptionError, match="NUL byte"):
            _open(raw, format=ArchiveFormat.XAR)

    open_it()
    peak = traced_peak(open_it)
    assert peak < 4 * len(xml), peak


def test_the_toc_size_must_match_its_header() -> None:
    xml = b"<xar><toc></toc></xar>"
    with pytest.raises(CorruptionError, match="not the 23"):
        _open(pack_xar(xml, b"", algorithm=0, toc_size=23), format=ArchiveFormat.XAR)
    with pytest.raises(CorruptionError, match="not the 21"):
        _open(pack_xar(xml, b"", algorithm=0, toc_size=21), format=ArchiveFormat.XAR)


def test_a_toc_that_does_not_decompress() -> None:
    raw = bytearray(pack_xar(b"<xar><toc></toc></xar>", b"", algorithm=0))
    raw[28] ^= 0xFF
    with pytest.raises(CorruptionError, match="does not decompress"):
        _open(bytes(raw), format=ArchiveFormat.XAR)


def test_header_damage() -> None:
    xml = b"<xar><toc></toc></xar>"
    with pytest.raises(UnsupportedFeatureError, match="XAR version 2"):
        _open(pack_xar(xml, b"", algorithm=0, version=2), format=ArchiveFormat.XAR)
    raw = pack_xar(xml, b"", algorithm=0)
    with pytest.raises(TruncatedError, match="table of contents"):
        _open(raw[:35], format=ArchiveFormat.XAR)
    short = raw[:4] + b"\x00\x10" + raw[6:]
    with pytest.raises(CorruptionError, match="says it is 16 bytes"):
        _open(short, format=ArchiveFormat.XAR)


def test_max_members_is_checked_while_the_toc_is_parsed() -> None:
    raw = write_xar([XarFile(f"f{i}", b"x") for i in range(5)])
    with _open(raw, config=_limits(max_members=5)) as reader:
        assert len(reader.members()) == 5
    with pytest.raises(ResourceLimitError, match="max_members=4"):
        _open(raw, config=_limits(max_members=4))


def test_a_huge_toc_is_refused_before_it_is_decoded() -> None:
    xml = b"<xar><toc>" + b" " * 200_000 + b"</toc></xar>"
    raw = pack_xar(xml, b"", algorithm=0)
    with _open(raw, config=_limits(max_metadata_bytes=len(xml))) as reader:
        assert reader.members() == []
    # The header's size is checked: the stored TOC is a few hundred bytes.
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=200021"):
        _open(raw, config=_limits(max_metadata_bytes=len(xml) - 1))
    # A stored size past the limit is refused before the read, not as a cut archive.
    xml = b"<xar><toc></toc></xar>"
    stored = zlib.compress(xml)
    header = HEADER.pack(b"xar!", HEADER.size, 1, 1 << 40, len(xml), 0)
    with pytest.raises(ResourceLimitError, match="1099511627776 bytes stored"):
        _open(header + stored, config=_limits(max_metadata_bytes=1000))


def test_deep_paths_are_charged_to_max_metadata_bytes() -> None:
    # Each nested path repeats its parents: 100 one-letter levels build 2 * 100**2
    # bytes of names and raw names from a TOC a third that size.
    tree = XarFile("d", type="directory")
    for _ in range(99):
        tree = XarFile("d", type="directory", children=[tree])
    raw = write_xar([tree])
    charged = 2 * 100**2
    # The members' own retained names weigh a little more, checked once they are made.
    with _open(raw, config=_limits(max_metadata_bytes=charged + 100)) as reader:
        assert len(reader.members()) == 100
    # One byte short is refused while the TOC is parsed, before any member exists.
    with pytest.raises(
        ResourceLimitError,
        match=f"max_metadata_bytes={charged - 1} .*{charged} bytes of paths before",
    ):
        _open(raw, config=_limits(max_metadata_bytes=charged - 1))


def test_a_file_without_data_is_empty() -> None:
    with _open(write_xar([XarFile("empty.txt")])) as reader:
        (member,) = reader.members()
        assert member.type is MemberType.FILE
        assert member.size == 0
        assert reader.read("empty.txt") == b""


def test_a_pipe_is_refused() -> None:
    with pytest.raises(archivey.StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(write_xar(TREE)), format=ArchiveFormat.XAR)


def test_a_toc_stream_cut_after_its_data_is_refused() -> None:
    """The zlib stream gives every byte the header says, but its Adler-32 is cut."""
    xml = b"<xar><toc></toc></xar>"
    stored = zlib.compress(xml)[:-4]
    header = HEADER.pack(b"xar!", HEADER.size, 1, len(stored), len(xml), 0)
    with pytest.raises(CorruptionError, match="not the 22"):
        _open(header + stored, format=ArchiveFormat.XAR)


def test_compressed_members_seek() -> None:
    with (
        _open(write_xar(TREE), seekable_members=True) as reader,
        reader.open("text.txt") as stream,
    ):
        stream.seek(1000)
        assert stream.read(20) == TEXT[1000:1020]
        stream.seek(10)
        assert stream.read(5) == TEXT[10:15]


# --- edges the mutation sweep found untested ---------------------------------------


def test_extended_attributes_do_not_replace_a_files_checksum() -> None:
    """Apple's xar writes ``<ea>`` elements inside ``<file>``, after ``<data>``, each
    with its own ``<name>`` and ``<extracted-checksum>``: they are skipped."""
    digest = hashlib.sha1(b"alpha").hexdigest()
    toc = (
        '<xar><toc><file id="1"><name>a.txt</name><type>file</type>'
        "<data><length>5</length><offset>0</offset><size>5</size>"
        '<encoding style="application/octet-stream"/>'
        f'<extracted-checksum style="sha1">{digest}</extracted-checksum></data>'
        '<ea id="0"><name>com.apple.quarantine</name><length>4</length>'
        "<offset>5</offset><size>4</size>"
        '<extracted-checksum style="md5">' + "0" * 32 + "</extracted-checksum>"
        "</ea></file></toc></xar>"
    ).encode()
    with _open(pack_xar(toc, b"alpha1234", algorithm=0)) as reader:
        (member,) = reader.members()
        assert member.name == "a.txt"
        assert member.hashes == {HashAlgorithm.SHA1: bytes.fromhex(digest)}
        assert reader.read("a.txt") == b"alpha"


def test_toc_level_elements_beside_the_checksum_are_skipped() -> None:
    """xar writes ``<creation-time>`` in the TOC, before or after its checksum."""
    head = "<creation-time>2024-03-01T12:00:00</creation-time>"
    for checksum in ("none", "sha1"):
        raw = write_xar(TREE, checksum=checksum, toc_head=head)
        with _open(raw) as reader:
            assert len(reader.members()) == 3


def test_the_toc_checksum_is_read_at_its_heap_offset() -> None:
    """The TOC names where in the heap its checksum sits; it need not be first."""
    toc = (
        b'<xar><toc><checksum style="sha1"><offset>5</offset><size>20</size>'
        b'</checksum><file id="1"><name>a</name><type>directory</type></file>'
        b"</toc></xar>"
    )
    digest = hashlib.sha1(zlib.compress(toc)).digest()
    with _open(pack_xar(toc, b"\xff" * 5 + digest)) as reader:
        assert [m.name for m in reader.members()] == ["a/"]
    with pytest.raises(CorruptionError, match="fails its checksum"):
        _open(pack_xar(toc, digest + b"\xff" * 5))


@pytest.mark.parametrize(
    "data_xml",
    [
        "<length>-4</length><offset>0</offset><size>4</size>",
        "<length>4</length><offset>0</offset><size>-4</size>",
    ],
    ids=["length", "size"],
)
def test_a_negative_length_or_size_is_refused(data_xml: str) -> None:
    with pytest.raises(CorruptionError, match="'a' has a negative data field"):
        _open(_single(data_xml), format=ArchiveFormat.XAR)


def test_a_named_algorithm_needs_room_for_its_name() -> None:
    """Algorithm 3 names its hash after the 28 header bytes: a 28-byte header has no
    name, which is damage, not an unknown hash."""
    xml = b"<xar><toc></toc></xar>"
    with pytest.raises(CorruptionError, match="^XAR checksum algorithm 3"):
        _open(pack_xar(xml, b"", algorithm=3), format=ArchiveFormat.XAR)


def test_an_unknown_algorithm_number_is_damage_even_with_a_longer_header() -> None:
    xml = b"<xar><toc></toc></xar>"
    raw = pack_xar(xml, b"", algorithm=9, header_extra=b"sha256".ljust(36, b"\0"))
    with pytest.raises(CorruptionError, match="^XAR checksum algorithm 9"):
        _open(raw, format=ArchiveFormat.XAR)


def test_elements_nested_to_the_depth_cap_are_read() -> None:
    """2048 open elements, ``<xar>`` included, is the deepest TOC read."""
    deep = b"<xar>" + b"<toc>" * 2047 + b"</toc>" * 2047 + b"</xar>"
    with _open(pack_xar(deep, b"", algorithm=0), format=ArchiveFormat.XAR) as reader:
        assert reader.members() == []


def test_a_file_reports_its_stored_size() -> None:
    raw = write_xar([XarFile("a", b"a" * 1000, encoding="gzip")])
    with _open(raw) as reader:
        (member,) = reader.members()
    assert member.size == 1000
    assert member.compressed_size == len(zlib.compress(b"a" * 1000))


def test_an_unknown_type_diagnostic_names_the_member_type_and_size() -> None:
    raw = write_xar([XarFile("odd", b"12345", type="whiteout")])
    with _open(raw) as reader:
        (member,) = reader.members()
        (diagnostic,) = member.diagnostics
    assert diagnostic.code is DiagnosticCode.MEMBER_TYPE_UNKNOWN
    context = diagnostic.context
    assert isinstance(context, UnknownMemberTypeContext)
    assert (context.member_name, context.stored_type, context.size) == (
        "odd",
        "whiteout",
        5,
    )


@pytest.mark.parametrize(
    ("stored", "attr"),
    [("mtime", "modified"), ("atime", "accessed"), ("ctime", "ctime")],
)
def test_an_unreadable_time_diagnostic_names_its_field(stored: str, attr: str) -> None:
    raw = write_xar([XarFile("a", b"x", extra=f"<{stored}>soon</{stored}>")])
    with _open(raw) as reader:
        (member,) = reader.members()
        (diagnostic,) = member.diagnostics
    assert diagnostic.message.startswith(f"Invalid XAR {stored} for 'a': 'soon'")
    context = diagnostic.context
    assert isinstance(context, MemberTimestampContext)
    assert context.member_name == "a"
    assert (context.field, context.source, context.value_repr) == (attr, "xar", "soon")
