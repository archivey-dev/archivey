"""macOS installer packages (``.pkg``) and Xcode archives (``.xip``): a XAR whose
``Payload``, ``Scripts`` and ``Content`` members are listed as the files they hold.

The packages are written with ``tests/xar_util.py`` around payloads from
``tests/pbzx_util.py``, laid out as ``pkgbuild`` and ``productbuild`` lay them out: a
component package holds ``Bom``, ``PackageInfo``, ``Payload`` and ``Scripts``; a product
archive holds a ``Distribution`` and one folder per component package.
"""

from __future__ import annotations

import base64
import gzip
import io
import lzma
import random
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CompressionAlgorithm,
    FormatPolicy,
    MemberType,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    StreamNotSeekableError,
    UnsupportedFeatureError,
)
from archivey.internal import format_adapter
from archivey.internal.backends.pkg_reader import is_package
from tests import xar_util
from tests.pbzx_util import make_pbzx, odc_cpio
from tests.streams_util import NonSeekableBytesIO
from tests.xar_util import XarFile, write_xar

_BIG = bytes(range(256)) * 400
_PAYLOAD = odc_cpio(
    [
        (".", None),
        ("./Applications", None),
        ("./Applications/App.txt", b"hello"),
        ("./Applications/big.bin", _BIG),
    ]
)
_SCRIPTS = odc_cpio([("./postinstall", b"#!/bin/sh\nexit 0\n")])


def _component(
    payload: bytes = _PAYLOAD,
    scripts: bytes | None = _SCRIPTS,
    *,
    pbzx: bool = True,
    payload_encoding: str = "none",
) -> list[XarFile]:
    """A component package's members: the payload in pbzx (``pkgbuild`` today) or
    gzip (older ones), the scripts in gzip."""
    files = [
        XarFile("Bom", b"BOMStore"),
        XarFile("PackageInfo", b"<pkg-info/>"),
        XarFile(
            "Payload",
            make_pbzx(payload) if pbzx else gzip.compress(payload),
            encoding=payload_encoding,
        ),
    ]
    if scripts is not None:
        files.append(XarFile("Scripts", gzip.compress(scripts), encoding="none"))
    return files


def _product(*components: list[XarFile]) -> bytes:
    folders = [
        XarFile(f"app{n}.pkg", type="directory", children=files)
        for n, files in enumerate(components)
    ]
    return write_xar([XarFile("Distribution", b"<installer-gui-script/>"), *folders])


_PRODUCT = _product(_component())
_LISTED = [
    ("Distribution", MemberType.FILE),
    ("app0.pkg/", MemberType.DIRECTORY),
    ("app0.pkg/Bom", MemberType.FILE),
    ("app0.pkg/PackageInfo", MemberType.FILE),
    ("app0.pkg/Payload/", MemberType.DIRECTORY),
    ("app0.pkg/Payload/Applications/", MemberType.DIRECTORY),
    ("app0.pkg/Payload/Applications/App.txt", MemberType.FILE),
    ("app0.pkg/Payload/Applications/big.bin", MemberType.FILE),
    ("app0.pkg/Scripts/postinstall", MemberType.FILE),
]


def test_a_product_archive_lists_its_payloads_files() -> None:
    with open_archive(io.BytesIO(_PRODUCT)) as archive:
        assert archive.format == ArchiveFormat.PKG
        assert [(m.name, m.type) for m in archive.members()] == _LISTED
        assert archive.read("app0.pkg/Payload/Applications/App.txt") == b"hello"
        assert archive.read("app0.pkg/Payload/Applications/big.bin") == _BIG
        assert archive.read("app0.pkg/Scripts/postinstall").startswith(b"#!/bin/sh")
        assert archive.read("app0.pkg/PackageInfo") == b"<pkg-info/>"
        assert not archive.diagnostics.retained


def test_format_xar_lists_the_payloads_as_they_are() -> None:
    with open_archive(io.BytesIO(_PRODUCT), format=ArchiveFormat.XAR) as archive:
        names = [m.name for m in archive.members()]
    assert names == [
        "Distribution",
        "app0.pkg/",
        "app0.pkg/Bom",
        "app0.pkg/PackageInfo",
        "app0.pkg/Payload",
        "app0.pkg/Scripts",
    ]


def test_a_component_package_lists_its_payload_at_the_top() -> None:
    blob = write_xar(_component(pbzx=False))
    with open_archive(io.BytesIO(blob)) as archive:
        assert archive.format == ArchiveFormat.PKG
        names = [m.name for m in archive.members()]
        assert "Payload/Applications/App.txt" in names
        assert "Scripts/postinstall" in names
        assert archive.read("Payload/Applications/big.bin") == _BIG


def test_a_payload_the_xar_layer_compresses_reads() -> None:
    """``Payload`` itself stored with a XAR encoding: the CPIO is under both."""
    blob = write_xar(_component(payload_encoding="gzip"))
    with open_archive(io.BytesIO(blob)) as archive:
        assert archive.read("Payload/Applications/App.txt") == b"hello"


def test_a_xip_lists_its_content() -> None:
    content = odc_cpio([("./Xcode.app", None), ("./Xcode.app/Info.plist", b"plist")])
    blob = write_xar(
        [
            XarFile("Content", make_pbzx(content), encoding="none"),
            XarFile("Metadata", b"<plist/>"),
        ]
    )
    assert detect_format(io.BytesIO(blob)).format == ArchiveFormat.PKG
    with open_archive(io.BytesIO(blob)) as archive:
        assert [m.name for m in archive.members()] == [
            "Content/Xcode.app/",
            "Content/Xcode.app/Info.plist",
            "Metadata",
        ]
        assert archive.read("Content/Xcode.app/Info.plist") == b"plist"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (None, ArchiveFormat.PKG),
        ("Installer.pkg", ArchiveFormat.PKG),
        ("Installer.PKG", ArchiveFormat.PKG),
        ("Xcode.xip", ArchiveFormat.PKG),
        ("bundle.xar", ArchiveFormat.XAR),
    ],
)
def test_detection(tmp_path: Path, name: str | None, expected: ArchiveFormat) -> None:
    """A XAR is a package by its extension, else by the names its table of contents
    starts with; one named ``.xar`` stays a XAR."""
    if name is None:
        assert detect_format(io.BytesIO(_PRODUCT)).format == expected
        return
    path = tmp_path / name
    path.write_bytes(_PRODUCT)
    assert detect_format(path).format == expected


def _signature() -> str:
    """A ``<signature>`` with a certificate chain, as a signed package's table of
    contents starts: three certificates of random bytes, which hardly compress."""
    rng = random.Random(1666)
    certs = "".join(
        f"<X509Certificate>{base64.b64encode(rng.randbytes(n)).decode()}"
        "</X509Certificate>"
        for n in (1500, 1100, 1200)
    )
    return (
        '<signature style="RSA"><offset>20</offset><size>256</size>'
        '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        f"<X509Data>{certs}</X509Data></KeyInfo></signature>"
    )


@pytest.mark.parametrize(
    ("files", "listed"),
    [
        (_component(scripts=None), "Payload/Applications/App.txt"),
        (
            [
                XarFile("Content", make_pbzx(_PAYLOAD), encoding="none"),
                XarFile("Metadata", b"<plist/>"),
            ],
            "Content/Applications/App.txt",
        ),
    ],
    ids=["component", "xip"],
)
def test_a_signed_package_without_a_name_is_a_package(
    files: list[XarFile], listed: str
) -> None:
    """The certificates fill the bytes before the first ``<file>`` past the 4 KiB
    near window; detection reads on into the table of contents."""
    blob = write_xar(files, toc_head=_signature())
    assert detect_format(io.BytesIO(blob)).format == ArchiveFormat.PKG
    with open_archive(io.BytesIO(blob)) as archive:
        assert listed in [m.name for m in archive.members()]
    # A forward-only source gives the check only the near window: detection does not
    # wait on a pipe for the rest, and a package cannot be opened from one anyway.
    assert detect_format(NonSeekableBytesIO(blob)).format == ArchiveFormat.XAR


def test_a_plain_xar_is_not_a_package() -> None:
    blob = write_xar([XarFile("a.txt", b"a"), XarFile("Payload", b"not a cpio")])
    assert detect_format(io.BytesIO(blob)).format == ArchiveFormat.XAR
    assert not is_package(lambda end: blob[:end], None)


def test_a_payload_that_holds_no_cpio_is_listed_as_it_is() -> None:
    files = _component()
    files[2] = XarFile("Payload", b"something else", encoding="none")
    with open_archive(io.BytesIO(write_xar(files))) as archive:
        assert archive.read("Payload") == b"something else"


def test_a_payload_in_an_encoding_archivey_does_not_read_is_listed_as_it_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other members list and read; reading the payload is refused."""
    monkeypatch.setitem(
        xar_util.ENCODINGS, "lzfse", ("application/x-lzfse", lambda data: data)
    )
    files = _component(scripts=None)
    files[2] = XarFile("Payload", make_pbzx(_PAYLOAD), encoding="lzfse")
    with open_archive(io.BytesIO(write_xar(files))) as archive:
        assert archive.format == ArchiveFormat.PKG
        assert [m.name for m in archive.members()] == ["Bom", "PackageInfo", "Payload"]
        assert archive.read("Bom") == b"BOMStore"
        with pytest.raises(UnsupportedFeatureError):
            archive.read("Payload")


@pytest.mark.parametrize(
    ("encoding", "excluded"),
    [
        # Refused when the member is opened.
        ("gzip", CompressionAlgorithm.DEFLATE),
        # Refused only once the decoder reads the block header.
        ("xz-bcj", CompressionAlgorithm.BCJ),
    ],
    ids=["codec", "xz-filter"],
)
def test_a_payload_the_configuration_turns_off_is_listed_as_it_is(
    monkeypatch: pytest.MonkeyPatch, encoding: str, excluded: CompressionAlgorithm
) -> None:
    """A payload whose XAR encoding ``FormatPolicy`` excludes is the file it is, as an
    encoding archivey does not read is; reading it is refused by the policy."""
    monkeypatch.setitem(
        xar_util.ENCODINGS,
        "xz-bcj",
        (
            "application/x-xz",
            # An explicit check: PyPy's lzma passes the default check (-1) through to
            # liblzma for a filter chain, which refuses it ("Internal error"). CRC64
            # is the default, so CPython writes the same bytes either way.
            lambda data: lzma.compress(
                data,
                check=lzma.CHECK_CRC64,
                filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}],
            ),
        ),
    )
    files = _component(scripts=None)
    files[2] = XarFile("Payload", make_pbzx(_PAYLOAD), encoding=encoding)
    blob = write_xar(files)
    with open_archive(io.BytesIO(blob)) as archive:
        assert "Payload/Applications/App.txt" in [m.name for m in archive.members()]
    config = ArchiveyConfig(formats=FormatPolicy(exclude=[excluded]))
    with open_archive(io.BytesIO(blob), config=config) as archive:
        assert [m.name for m in archive.members()] == ["Bom", "PackageInfo", "Payload"]
        with pytest.raises(UnsupportedFeatureError):
            archive.read("Payload")


@pytest.mark.parametrize(
    "payload",
    [
        gzip.compress(b"hello world, not a cpio" * 10),
        make_pbzx(b"not cpio at all" * 10),
        b"070707 but not a header",
    ],
    ids=["gzip", "pbzx", "cpio-magic"],
)
def test_a_payload_that_starts_like_a_cpio_but_holds_none_is_listed_as_it_is(
    payload: bytes,
) -> None:
    """Its first bytes match, but no CPIO header follows: the payload is listed as
    the file it is, and the other members stay readable."""
    files = _component()
    files[2] = XarFile("Payload", payload, encoding="none")
    with open_archive(io.BytesIO(write_xar(files))) as archive:
        assert archive.format == ArchiveFormat.PKG
        assert "Payload" in [m.name for m in archive.members()]
        assert archive.read("Payload") == payload
        assert archive.read("Bom")


def test_a_payload_that_fails_its_xar_checksum_is_refused() -> None:
    """A byte of a file's data changed in a stored chunk: the CPIO still reads, and
    the payload's XAR checksum catches it."""
    files = _component()
    files[2] = XarFile("Payload", make_pbzx(_PAYLOAD, store=True), encoding="none")
    blob = bytearray(write_xar(files))
    blob[blob.index(b"hello")] ^= 0x20
    with (
        pytest.raises(CorruptionError, match="Payload.*sha1 checksum"),
        open_archive(io.BytesIO(bytes(blob)), format=ArchiveFormat.PKG) as archive,
    ):
        archive.members()


@pytest.mark.parametrize(
    ("entries", "links"),
    [
        ([("./../Bom", b"x")], None),
        ([("./../../Distribution", b"x")], None),
        ([("./a/../../Scripts/postinstall", b"x")], None),
        ([("./a", b"x"), ("./../Bom", b"")], {"./../Bom": "./a"}),
    ],
    ids=["sibling", "package-top", "through-a-folder", "file-escapes"],
)
def test_a_payload_file_outside_its_folder_is_refused(
    entries: list[tuple[str, bytes | None]], links: dict[str, str] | None
) -> None:
    blob = _product(_component(odc_cpio(entries, links=links)))
    with (
        pytest.raises(CorruptionError, match=r"outside app0\.pkg/Payload/"),
        open_archive(io.BytesIO(blob)) as archive,
    ):
        archive.members()


def test_a_hard_link_to_a_path_outside_its_folder_is_refused() -> None:
    payload = odc_cpio([("./../x", b"x"), ("./b", b"")], links={"./b": "./../x"})
    blob = _product(_component(payload))
    with (
        pytest.raises(CorruptionError, match=r"outside app0\.pkg/Payload/"),
        open_archive(io.BytesIO(blob)) as archive,
    ):
        archive.members()


@pytest.mark.parametrize(
    "entries",
    [
        [("./l", b".."), ("./l/Bom", b"x")],
        [("./l", b"../.."), ("./l/Distribution", b"x")],
    ],
    ids=["sibling", "package-top"],
)
def test_a_payload_file_that_leaves_its_folder_through_a_symlink_is_refused(
    entries: list[tuple[str, bytes | None]],
) -> None:
    """A payload symlink ``l -> ..`` makes ``l/Bom`` the package's own ``Bom`` for a
    caller that writes the listed files itself (archivey's extraction refuses a path
    through a symlink it made)."""
    blob = _product(_component(odc_cpio(entries, modes={"./l": 0o120777})))
    with (
        pytest.raises(CorruptionError, match="under a symlink"),
        open_archive(io.BytesIO(blob)) as archive,
    ):
        archive.members()


@pytest.mark.parametrize("folder", ["../app0.pkg", "x\\..\\y", "..\\x", "a\\..", "C:"])
def test_a_payload_in_a_folder_that_is_no_folder_is_listed_as_it_is(
    folder: str,
) -> None:
    """A component folder named so that it is not a folder of the package: its
    ``Payload`` is the file it is, and the listing's name checks take it from there,
    never a usage error."""
    blob = write_xar(
        [
            XarFile("Distribution", b"<installer-gui-script/>"),
            XarFile(folder, type="directory", children=_component()),
        ]
    )
    with open_archive(io.BytesIO(blob), format=ArchiveFormat.PKG) as archive:
        payloads = [m for m in archive.members() if m.name.endswith("Payload")]
    assert [m.type for m in payloads] == [MemberType.FILE]


@pytest.mark.parametrize("before", [False, True], ids=["after", "before"])
def test_a_xar_member_inside_a_payload_folder_is_refused(before: bool) -> None:
    """Only the payload's own files, checked against its symlinks, may land in its
    folder: a XAR directory ``Payload/`` beside the payload file, holding ``l/Bom``
    under the payload's ``l -> ..``, would write into the package's ``Bom``."""
    payload = odc_cpio([("./l", b"..")], modes={"./l": 0o120777})
    intruder = XarFile(
        "Payload",
        type="directory",
        children=[XarFile("l", type="directory", children=[XarFile("Bom", b"x")])],
    )
    files = _component(payload)
    files.insert(0 if before else len(files), intruder)
    with (
        pytest.raises(CorruptionError, match="inside the folder of a payload"),
        open_archive(io.BytesIO(_product(files))) as archive,
    ):
        archive.members()


def _two_payloads(nested: bool) -> bytes:
    """A flat package whose second payload lands under the first one's symlink to
    ``..``: a XAR file ``Payload`` with a child payload ``Scripts``, or two files
    named ``Payload``."""
    if nested:
        link, inner = "./Scripts", odc_cpio([("./Bom", b"x")])
        children = [XarFile("Scripts", make_pbzx(inner), encoding="none")]
    else:
        link, inner = "./l", odc_cpio([("./l/Bom", b"x")])
        children = []
    outer = make_pbzx(odc_cpio([(link, b"..")], modes={link: 0o120777}))
    files = [
        XarFile("PackageInfo", b"<pkg-info/>"),
        XarFile("Payload", outer, encoding="none", children=children),
    ]
    if not nested:
        files.append(XarFile("Payload", make_pbzx(inner), encoding="none"))
    return write_xar(files)


@pytest.mark.parametrize("nested", [True, False], ids=["inside", "twice"])
def test_a_payload_in_another_payloads_folder_is_refused(nested: bool) -> None:
    """Each payload's symlinks are checked against its own files only, so no payload
    folder may be another one's or lie inside it."""
    with (
        pytest.raises(CorruptionError, match="in the folder of another payload"),
        open_archive(io.BytesIO(_two_payloads(nested))) as archive,
    ):
        archive.members()


def test_a_payload_symlink_that_stays_in_its_folder_is_listed() -> None:
    entries: list[tuple[str, bytes | None]] = [("./a", b"x"), ("./l", b"a")]
    payload = odc_cpio(entries, modes={"./l": 0o120777})
    with open_archive(io.BytesIO(_product(_component(payload)))) as archive:
        link = archive.get("app0.pkg/Payload/l")
        assert link.type is MemberType.SYMLINK
        assert link.link_target == "a"


def test_a_hard_link_inside_a_payload_names_its_prefixed_target() -> None:
    payload = odc_cpio([("./a", b"data"), ("./b", b"data")], links={"./b": "./a"})
    with open_archive(io.BytesIO(_product(_component(payload)))) as archive:
        link = archive.get("app0.pkg/Payload/b")
        assert link.type is MemberType.HARDLINK
        assert link.link_target == "app0.pkg/Payload/a"
        assert archive.read(link) == b"data"


def test_members_open_in_any_order_and_again() -> None:
    blob = _product(_component(), _component())
    with open_archive(io.BytesIO(blob)) as archive:
        archive.members()
        assert archive.read("app1.pkg/Payload/Applications/big.bin") == _BIG
        assert archive.read("app0.pkg/Scripts/postinstall").startswith(b"#!")
        assert archive.read("app0.pkg/Payload/Applications/App.txt") == b"hello"
        assert archive.read("app0.pkg/Payload/Applications/App.txt") == b"hello"
        assert archive.read("app1.pkg/Payload/Applications/App.txt") == b"hello"


def test_two_members_of_one_payload_read_at_once() -> None:
    with open_archive(io.BytesIO(_PRODUCT), concurrent_operations=True) as archive:
        archive.members()
        with (
            archive.open("app0.pkg/Payload/Applications/App.txt") as first,
            archive.open("app0.pkg/Payload/Applications/big.bin") as second,
        ):
            assert second.read(10) == _BIG[:10]
            assert first.read() == b"hello"
            assert second.read() == _BIG[10:]


def test_a_report_from_inside_a_payload_is_made_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CPIO reader reports the unknown type while listing. Reading the members
    after it reads the payload again, and that report is not made again."""
    payload = odc_cpio(
        [("./a", b"a"), ("./odd", b"x"), ("./z", b"z")],
        modes={"./odd": 0o170644},
    )
    with open_archive(io.BytesIO(_product(_component(payload)))) as archive:
        members = archive.members()
        assert archive.read("app0.pkg/Payload/z") == b"z"
        assert archive.read("app0.pkg/Payload/odd") == b"x"
        assert archive.read("app0.pkg/Payload/a") == b"a"
        unknown = [
            d
            for d in archive.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_TYPE_UNKNOWN
        ]
    assert len(unknown) == 1
    odd = next(m for m in members if m.name == "app0.pkg/Payload/odd")
    assert unknown[0].context.member_id == odd._member_id  # type: ignore[attr-defined]


def test_an_in_order_pass_reads_each_payload_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    opened: list[object] = []
    original = format_adapter._PluginAdapter._nested_spans

    def counting(self: object, *args: object, **kwargs: object) -> object:
        opened.append(args[2])
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(format_adapter._PluginAdapter, "_nested_spans", counting)
    blob = _product(_component(), _component())
    with open_archive(io.BytesIO(blob)) as archive:
        archive.members()
        listed = len(opened)
        assert listed == 4  # two payloads and two scripts
        archive.extract_all(tmp_path)
        # Each payload and scripts archive is read again once, from its first file
        # to its last.
        assert len(opened) == 2 * listed
    assert (tmp_path / "app1.pkg/Payload/Applications/big.bin").read_bytes() == _BIG
    assert (tmp_path / "app0.pkg/Scripts/postinstall").read_bytes().startswith(b"#!")
    assert (tmp_path / "app0.pkg/PackageInfo").read_bytes() == b"<pkg-info/>"


def test_stream_members_reads_every_file() -> None:
    with open_archive(io.BytesIO(_PRODUCT)) as archive:
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert read["app0.pkg/Payload/Applications/big.bin"] == _BIG
    assert read["Distribution"] == b"<installer-gui-script/>"


def test_members_seek() -> None:
    with (
        open_archive(io.BytesIO(_PRODUCT), seekable_members=True) as archive,
        archive.open("app0.pkg/Payload/Applications/big.bin") as stream,
    ):
        stream.seek(70_000)
        assert stream.read(10) == _BIG[70_000:70_010]
        stream.seek(5)
        assert stream.read(10) == _BIG[5:15]


def test_a_pipe_is_refused() -> None:
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(_PRODUCT), format=ArchiveFormat.PKG)


def test_listing_says_it_decodes() -> None:
    with open_archive(io.BytesIO(_PRODUCT)) as archive:
        cost = archive.cost
    assert cost.listing_cost.name == "REQUIRES_SCANNING"
    assert cost.access_cost.name == "SOLID"
