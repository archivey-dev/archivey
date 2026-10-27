"""The plugin API (``archivey.plugins``): an indexed plugin through the public surface.

The test format, TOYA, is defined here with ``archivey.plugins`` and the root API
only: a magic line, a count, one index entry per member (name, type, size, CRC-32,
data offset), then the data. Each test registers it on a registry restored afterwards
(``toya`` fixture).
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import struct
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyUsageError,
    CompressionAlgorithm,
    CorruptionError,
    FormatSupport,
    HashAlgorithm,
    MemberType,
    PackageNotInstalledError,
    PluginContainer,
    StreamFormat,
    TruncatedError,
    detect_format,
    format_availability,
    open_archive,
)
from archivey.diagnostics import (
    DiagnosticCode,
    MemberTimestampContext,
    SymlinkTargetContext,
)
from archivey.internal import format_args
from archivey.internal.plugin_adapter import registration_scope
from archivey.plugins import (
    FormatPlugin,
    IndexedReader,
    Magic,
    MemberData,
    MemberDigest,
    MemberRecord,
    PluginArchiveInfo,
    PluginContext,
    PluginSource,
    buffered_stream,
    register_format,
)
from tests.conftest import requires, requires_zstd

_MAGIC = b"TOYARC1\n"


class ToyContainer(PluginContainer):
    TOYA = "toya"


TOYA = ArchiveFormat(ToyContainer.TOYA, StreamFormat.UNCOMPRESSED)


def build_toya(
    entries: list[tuple[str | bytes, MemberType, bytes]],
    *,
    sizes: dict[int, int] | None = None,
    crcs: dict[int, int] | None = None,
) -> bytes:
    """A TOYA archive; ``sizes`` and ``crcs`` override what the index declares."""
    names = [n.encode() if isinstance(n, str) else n for n, _, _ in entries]
    index_len = 12 + sum(2 + len(n) + 1 + 4 + 4 + 8 for n in names)
    index = bytearray(_MAGIC + struct.pack("<I", len(entries)))
    data = bytearray()
    for i, ((_, kind, payload), name) in enumerate(zip(entries, names, strict=True)):
        size = (sizes or {}).get(i, len(payload))
        crc = (crcs or {}).get(i, zlib.crc32(payload))
        index += struct.pack("<H", len(name)) + name
        index += struct.pack("<BIIQ", kind is MemberType.DIRECTORY, size, crc, 0)
        struct.pack_into("<Q", index, len(index) - 8, index_len + len(data))
        data += payload
    return bytes(index + data)


class ToyReader(IndexedReader[tuple[int, int]]):
    def __init__(self, source: PluginSource, context: PluginContext) -> None:
        self._source = source
        self._context = context
        head = source.read_at(0, 12)
        if len(head) < 12:
            raise TruncatedError("TOYA index is cut short")
        (self._count,) = struct.unpack_from("<I", head, 8)

    def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
        pos = 12
        for _ in range(self._count):
            (name_len,) = struct.unpack("<H", self._source.read_at(pos, 2))
            raw = self._source.read_at(pos + 2, name_len)
            pos += 2 + name_len
            is_dir, size, crc, offset = struct.unpack(
                "<BIIQ", self._source.read_at(pos, 17)
            )
            pos += 17
            kind = MemberType.DIRECTORY if is_dir else MemberType.FILE
            member = ArchiveMember(
                type=kind,
                name=self._context.decode_name(raw),
                raw_name=raw,
                size=0 if is_dir else size,
                hashes={} if is_dir else {HashAlgorithm.CRC32: crc.to_bytes(4)},
            )
            yield MemberRecord(member, locator=(offset, size))

    def open_member(
        self, member: ArchiveMember, locator: tuple[int, int]
    ) -> MemberData:
        offset, size = locator
        return MemberData(self._source.view(offset, size))

    def archive_info(self) -> PluginArchiveInfo:
        return PluginArchiveInfo(format_version="1", comment="toy")


class ToyPlugin(FormatPlugin):
    format = TOYA
    extensions = (".toya",)
    magic = (Magic(0, _MAGIC),)
    uses_encoding = True

    def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
        return ToyReader(source, context)


@pytest.fixture
def clean_registry() -> Iterator[None]:
    with registration_scope():
        yield


@pytest.fixture
def toya(clean_registry: None) -> ArchiveFormat:
    register_format(ToyPlugin)
    return TOYA


_ENTRIES: list[tuple[str | bytes, MemberType, bytes]] = [
    ("docs", MemberType.DIRECTORY, b""),
    ("docs/a.txt", MemberType.FILE, b"alpha\n"),
    ("b.bin", MemberType.FILE, bytes(range(256)) * 4),
]


def _write(tmp_path: Path, data: bytes, name: str = "t.toya") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_format_identity() -> None:
    assert TOYA.display_name == "TOYA"
    assert TOYA.file_extension() == "toya"
    assert TOYA.container is ToyContainer.TOYA
    assert ArchiveFormat(ToyContainer.TOYA, "uncompressed") == TOYA


def test_open_list_and_read(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader:
        assert reader.format == toya
        assert reader.format_info is not None
        assert reader.format_info.from_plugin
        names = [m.name for m in reader.members()]
        assert names == ["docs/", "docs/a.txt", "b.bin"]
        assert reader.read("docs/a.txt") == b"alpha\n"
        with reader.open("b.bin") as stream:
            assert stream.read() == bytes(range(256)) * 4
            assert stream.verified is archivey.Verification.CONTENT
        info = reader.info
        assert info.format == toya
        assert info.comment == "toy"
        assert info.format_version == "1"


def test_stream_members_and_extract(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path, streaming=True) as reader:
        seen = {
            m.name: (s.read() if s is not None else None)
            for m, s in reader.stream_members()
        }
    assert seen["docs/a.txt"] == b"alpha\n"
    dest = tmp_path / "out"
    with open_archive(path) as reader:
        reader.extract_all(dest)
    assert (dest / "docs" / "a.txt").read_bytes() == b"alpha\n"
    assert (dest / "b.bin").read_bytes() == bytes(range(256)) * 4


def test_detection(toya: ArchiveFormat, tmp_path: Path) -> None:
    data = build_toya(_ENTRIES)
    info = detect_format(io.BytesIO(data))
    assert info.format == toya
    assert info.detected_by == "magic"
    assert info.from_plugin
    by_name = detect_format(_write(tmp_path, b"not toya at all", "x.toya"))
    assert by_name.format == toya
    assert by_name.detected_by == "extension"
    assert not detect_format(io.BytesIO(b"PK\x05\x06" + bytes(18))).from_plugin


def test_format_spelling_and_queries(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES), "t.bin")
    with open_archive(path, format="toya") as reader:
        assert reader.format == toya
    assert format_availability("toya").support is FormatSupport.FULL
    assert toya in archivey.list_known_formats()
    assert toya in archivey.list_supported_formats()


def test_short_member_raises_truncated(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES, sizes={2: 4096}))
    with open_archive(path) as reader, pytest.raises(TruncatedError):
        reader.read("b.bin")


def test_wrong_digest_raises(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES, crcs={1: 0}))
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read("docs/a.txt")


def test_dotdot_member_not_written_outside(toya: ArchiveFormat, tmp_path: Path) -> None:
    entries = [("../escape.txt", MemberType.FILE, b"x"), *_ENTRIES[1:]]
    path = _write(tmp_path, build_toya(entries))
    dest = tmp_path / "out"
    dest.mkdir()
    with open_archive(path) as reader:
        reader.extract_all(dest)
    assert not (tmp_path / "escape.txt").exists()
    assert (dest / "docs" / "a.txt").read_bytes() == b"alpha\n"
    assert (dest / "b.bin").exists()


def test_name_is_normalized(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya([("./a//b.txt", MemberType.FILE, b"b")]))
    with open_archive(path) as reader:
        (member,) = reader.members()
        assert member.name == "a/b.txt"
        assert reader.diagnostics.counts.get(
            archivey.DiagnosticCode.MEMBER_NAME_NORMALIZED
        )


def test_builtin_magic_wins(clean_registry: None) -> None:
    class ZipLike(PluginContainer):
        ZIPLIKE = "ziplike"

    class ZipLikePlugin(ToyPlugin):
        format = ArchiveFormat(ZipLike.ZIPLIKE, StreamFormat.UNCOMPRESSED)
        extensions = ()
        magic = (Magic(0, b"PK\x03\x04"),)

    register_format(ZipLikePlugin)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a", b"a")
    assert detect_format(io.BytesIO(buf.getvalue())).format == ArchiveFormat.ZIP


@pytest.mark.parametrize(
    ("attrs", "match"),
    [
        ({"extensions": (".zip",)}, "already claimed"),
        ({"extensions": ("toya",)}, "a dot followed by"),
        ({"extensions": (".",)}, "a dot followed by"),
        ({"extensions": (".ZIP",)}, "already claimed by ZIP"),
        ({"magic": (Magic(-1, b"x"),)}, "non-negative offset"),
        ({"magic": (Magic(0, b""),)}, "non-negative offset"),
        ({"probe": 3}, "must be callable"),
        ({"format": "toya"}, "must be an ArchiveFormat"),
        ({"format": ArchiveFormat.ZIP}, "PluginContainer"),
        (
            {"format": ArchiveFormat(ToyContainer.TOYA, StreamFormat.GZIP)},
            "UNCOMPRESSED",
        ),
    ],
)
def test_registration_refusals(
    clean_registry: None, attrs: dict[str, object], match: str
) -> None:
    bad = type("BadPlugin", (ToyPlugin,), attrs)
    with pytest.raises(ArchiveyUsageError, match=match):
        register_format(bad)


def test_registration_refuses_clashes(clean_registry: None) -> None:
    register_format(ToyPlugin)
    with pytest.raises(ArchiveyUsageError, match="already registered"):
        register_format(ToyPlugin)

    class Builtin(PluginContainer):
        ZIP = "zip"

    class Other(PluginContainer):
        TOYA = "toya"

    for container in (Builtin.ZIP, Other.TOYA):
        plugin = type(
            "Clash",
            (ToyPlugin,),
            {
                "format": ArchiveFormat(container, StreamFormat.UNCOMPRESSED),
                "extensions": (),
            },
        )
        with pytest.raises(ArchiveyUsageError):
            register_format(plugin)
    with pytest.raises(ArchiveyUsageError):
        register_format(int)  # type: ignore[arg-type]


def test_missing_requirement(clean_registry: None, tmp_path: Path) -> None:
    class Needs(PluginContainer):
        NEEDS = "needsmod"

    class NeedsPlugin(ToyPlugin):
        format = ArchiveFormat(Needs.NEEDS, StreamFormat.UNCOMPRESSED)
        extensions = (".needsmod",)
        magic = ()
        requires = ("archivey_no_such_module_for_test",)
        install_hint = "pip install no-such-module"

    register_format(NeedsPlugin)
    availability = format_availability(NeedsPlugin.format)
    assert availability.support is FormatSupport.NONE
    assert availability.missing[0].advice == "pip install no-such-module"
    path = _write(tmp_path, build_toya(_ENTRIES), "t.needsmod")
    with pytest.raises(PackageNotInstalledError):
        open_archive(path)


def test_translate_exception(clean_registry: None, tmp_path: Path) -> None:
    class Failing(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            raise ValueError("bad index")

        def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
            if isinstance(exc, ValueError):
                return CorruptionError(str(exc))
            return None

    class FailingPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return Failing(source, context)

    register_format(FailingPlugin)
    path = _write(tmp_path, build_toya(_ENTRIES))
    with (
        open_archive(path) as reader,
        pytest.raises(CorruptionError, match="bad index"),
    ):
        reader.members()


def test_concurrent_reader(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path, concurrent_operations=True) as reader:
        a = reader.open("docs/a.txt")
        b = reader.open("b.bin")
        assert a.read(2) == b"al"
        assert b.read(3) == bytes(range(3))
        assert a.read() == b"pha\n"
        a.close()
        b.close()


def test_cli_lists_plugin_format(
    toya: ArchiveFormat, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from archivey.cli.main import main

    path = _write(tmp_path, build_toya(_ENTRIES))
    assert main(["list", str(path)]) == 0
    assert "docs/a.txt" in capsys.readouterr().out


def _plugin_with(
    name: str,
    *,
    reader: type[ToyReader] = ToyReader,
    **attrs: object,
) -> type[ToyPlugin]:
    """A TOYA variant registered under its own container, reading with ``reader``."""
    container = PluginContainer(f"{name}Container", {name.upper(): name})  # type: ignore[call-overload]
    fmt = ArchiveFormat(container[name.upper()], StreamFormat.UNCOMPRESSED)

    def open_(
        self: FormatPlugin, source: PluginSource, context: PluginContext
    ) -> ToyReader:
        return reader(source, context)

    body: dict[str, object] = {
        "format": fmt,
        "extensions": (f".{name}",),
        "magic": (),
        "open": open_,
    }
    body.update(attrs)
    plugin = type(f"{name.title()}Plugin", (ToyPlugin,), body)
    register_format(plugin)
    return plugin


@pytest.mark.parametrize(
    ("container_value", "owner"),
    [("tar.gz", "TAR_GZ"), ("TAR_GZ", "TAR_GZ"), ("zz", "ZLIB")],
)
def test_registration_refuses_a_taken_spelling(
    clean_registry: None, container_value: str, owner: str
) -> None:
    """A container value or member name that spells another format is refused, so a
    plugin never registers with no ``format=`` spelling of its own."""
    container = PluginContainer("Taken", {"MINE": container_value})  # type: ignore[call-overload]
    plugin = type(
        "Taken",
        (ToyPlugin,),
        {
            "format": ArchiveFormat(container.MINE, StreamFormat.UNCOMPRESSED),
            "extensions": (),
        },
    )
    with pytest.raises(ArchiveyUsageError, match=f"already names {owner};"):
        register_format(plugin)

    named_zip = PluginContainer("NamedZip", {"ZIP": "mine"})  # type: ignore[call-overload]
    plugin = type(
        "NamedZip",
        (ToyPlugin,),
        {
            "format": ArchiveFormat(named_zip.ZIP, StreamFormat.UNCOMPRESSED),
            "extensions": (),
        },
    )
    with pytest.raises(ArchiveyUsageError, match="'ZIP' already names ZIP;"):
        register_format(plugin)


def test_unknown_format_message_lists_plugins(
    toya: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, build_toya(_ENTRIES))
    with pytest.raises(ArchiveyUsageError, match="'toya'"):
        open_archive(path, format="toyaa")


def test_registration_scope_undoes_registration() -> None:
    with registration_scope():
        register_format(ToyPlugin)
        assert TOYA in archivey.list_known_formats()
    assert TOYA not in archivey.list_known_formats()
    with pytest.raises(ArchiveyUsageError):
        format_args.coerce_archive_format("toya", call="test")
    with registration_scope():
        register_format(ToyPlugin)


def test_checked_counts_as_content(clean_registry: None, tmp_path: Path) -> None:
    """A member with no checksum archivey can compute reaches CONTENT only when the
    plugin says its library checked the data."""

    class Unhashed(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                record.member.hashes = {}
                yield record

    class Checked(Unhashed):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            data = super().open_member(member, locator)
            return MemberData(data.stream, checked=True)

    _plugin_with("unhashed", reader=Unhashed)
    _plugin_with("checked", reader=Checked)
    for ext, expected in (
        ("unhashed", archivey.Verification.STRUCTURE),
        ("checked", archivey.Verification.CONTENT),
    ):
        path = _write(tmp_path, build_toya(_ENTRIES), f"t.{ext}")
        with open_archive(path) as reader, reader.open("docs/a.txt") as stream:
            assert stream.read() == b"alpha\n"
            assert stream.verified is expected


def test_expected_hashes_from_open_member(clean_registry: None, tmp_path: Path) -> None:
    """A checksum known only once the member is opened is checked like a listed one."""

    class LateHash(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                record.member.hashes = {}
                yield record

        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            data = super().open_member(member, locator)
            crc = 0 if member.name == "b.bin" else zlib.crc32(b"alpha\n")
            return MemberData(
                data.stream, expected_hashes={HashAlgorithm.CRC32: crc.to_bytes(4)}
            )

    _plugin_with("latehash", reader=LateHash)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.latehash")
    with open_archive(path) as reader:
        with reader.open("docs/a.txt") as stream:
            assert stream.read() == b"alpha\n"
            assert stream.verified is archivey.Verification.CONTENT
        with pytest.raises(CorruptionError):
            reader.read("b.bin")


def test_long_member_raises_corruption(clean_registry: None, tmp_path: Path) -> None:
    class Overrun(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, size = locator
            return MemberData(self._source.view(offset, size + 3))

    _plugin_with("overrun", reader=Overrun)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.overrun")
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read("docs/a.txt")


def test_probe_detects_a_format_with_no_magic(clean_registry: None) -> None:
    seen: list[bytes] = []

    def probe(prefix: bytes) -> bool:
        seen.append(prefix)
        return prefix.startswith(_MAGIC)

    plugin = _plugin_with("probed", probe=probe)
    # Like a built-in probe, it runs on a nameless source only when asked to.
    config = archivey.ArchiveyConfig(always_probe_content=True)
    info = detect_format(io.BytesIO(build_toya(_ENTRIES)), config=config)
    assert info.format == plugin.format
    assert info.detected_by == "content_probe"
    assert info.from_plugin
    assert seen
    with pytest.raises(archivey.FormatDetectionError):
        detect_format(io.BytesIO(b"nothing here" * 10), config=config)


@pytest.mark.parametrize("name", ["a.zip", "a.tar", "a.iso"])
def test_probe_does_not_run_on_a_name_another_format_owns(
    clean_registry: None, tmp_path: Path, name: str
) -> None:
    # Every plugin format shares the UNCOMPRESSED stream with ZIP and TAR, so the
    # name gate must match the format, not the stream.
    calls: list[bytes] = []

    def probe(prefix: bytes) -> bool:
        calls.append(prefix)
        return True

    plugin = _plugin_with("probed", probe=probe)
    data = build_toya(_ENTRIES)
    assert detect_format(_write(tmp_path, data, name)).format != plugin.format
    assert not calls
    assert detect_format(_write(tmp_path, data, "a.probed")).format == plugin.format
    assert calls


def test_archive_info_fields(toya: ArchiveFormat, tmp_path: Path) -> None:
    class Solid(ToyReader):
        member_list_upfront = False

        def archive_info(self) -> PluginArchiveInfo:
            return PluginArchiveInfo(is_solid=True, extra={"solid.blocks": 1})

    _plugin_with("solid", reader=Solid)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.solid")
    with open_archive(path, format="solid") as reader:
        info = reader.info
        assert info.is_solid
        assert info.cost.access_cost is archivey.AccessCost.SOLID
        assert info.cost.listing_cost is archivey.ListingCost.REQUIRES_SCANNING
        assert info.extra["solid.blocks"] == 1
    with open_archive(_write(tmp_path, build_toya(_ENTRIES))) as reader:
        assert reader.info.cost.access_cost is archivey.AccessCost.DIRECT
        assert reader.info.cost.listing_cost is archivey.ListingCost.INDEXED


def test_archive_info_errors_are_translated(
    clean_registry: None, tmp_path: Path
) -> None:
    class Failing(ToyReader):
        def archive_info(self) -> PluginArchiveInfo:
            raise ValueError("bad header")

        def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
            if isinstance(exc, ValueError):
                return CorruptionError(str(exc))
            return None

    _plugin_with("badinfo", reader=Failing)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.badinfo")
    with (
        open_archive(path) as reader,
        pytest.raises(CorruptionError, match="bad header"),
    ):
        reader.info  # noqa: B018


def test_decode_name_fallbacks(toya: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toya([(b"caf\xe9.txt", MemberType.FILE, b"x")]))
    with open_archive(path, encoding="latin-1") as reader:
        assert [m.name for m in reader.members()] == ["café.txt"]
    with open_archive(path) as reader:
        (member,) = reader.members()
        assert member.name == "caf\udce9.txt"
        assert member.raw_name == b"caf\xe9.txt"


def test_encoding_unused_when_the_plugin_takes_none(
    clean_registry: None, tmp_path: Path
) -> None:
    _plugin_with("noenc", uses_encoding=False)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.noenc")
    with open_archive(path, encoding="latin-1") as reader:
        assert reader.diagnostics.counts.get(
            archivey.DiagnosticCode.ENCODING_ARGUMENT_UNUSED
        )


def test_plugin_source_path_and_size(clean_registry: None, tmp_path: Path) -> None:
    seen: list[tuple[Path | None, int]] = []

    class Recording(ToyReader):
        def __init__(self, source: PluginSource, context: PluginContext) -> None:
            super().__init__(source, context)
            seen.append((source.path, source.size))

    _plugin_with("rec", reader=Recording)
    data = build_toya(_ENTRIES)
    path = _write(tmp_path, data, "t.rec")
    with open_archive(path):
        pass
    with open_archive(io.BytesIO(data), format="rec"):
        pass
    assert seen == [(path, len(data)), (None, len(data))]


class _BroadTranslator(ToyReader):
    """Maps every exception to corruption, as a careless plugin might."""

    def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
        return CorruptionError(str(exc))


def test_interface_violations_are_not_reported_as_corruption(
    clean_registry: None, tmp_path: Path
) -> None:
    class BadData(_BroadTranslator):
        def open_member(  # type: ignore[override]
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> object:
            return self._source.view(*locator)

    class BadMember(_BroadTranslator):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            yield MemberRecord("not a member", locator=(0, 0))  # type: ignore[arg-type]

    class BadOpen(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return object()  # type: ignore[return-value]

    _plugin_with("baddata", reader=BadData)
    _plugin_with("badmember", reader=BadMember)
    _plugin_with("badopen", open=BadOpen.open)
    data = build_toya(_ENTRIES)
    with (
        open_archive(_write(tmp_path, data, "t.baddata")) as reader,
        pytest.raises(TypeError, match="not MemberData"),
    ):
        reader.read("docs/a.txt")
    with (
        open_archive(_write(tmp_path, data, "t.badmember")) as reader,
        pytest.raises(TypeError, match="not an ArchiveMember"),
    ):
        reader.members()
    with pytest.raises(TypeError, match="not an IndexedReader"):
        open_archive(_write(tmp_path, data, "t.badopen"))


# ── PluginContext.decompress ────────────────────────────────────────────────────────


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _lzma_raw(data: bytes, filter_id: int) -> tuple[bytes, bytes]:
    filters = [{"id": filter_id, "dict_size": 1 << 16}]
    props = lzma._encode_filter_properties(filters[0])  # type: ignore[attr-defined]
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters), props


_PLAIN = b"plugin member data " * 200


def _compressed_plugin(
    method: CompressionAlgorithm | StreamFormat,
    properties: bytes | None = None,
    translated: list[Exception] | None = None,
) -> type[FormatPlugin]:
    """A TOYA plugin whose one member is stored compressed with ``method``; the
    member's data runs to the end of the file."""

    class CompressedReader(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, _ = locator
            return MemberData(
                self._context.decompress(
                    self._source.view(offset),
                    method,
                    size=member.size,
                    properties=properties,
                )
            )

        def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
            if translated is not None:
                translated.append(exc)
            return None

    class CompressedPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return CompressedReader(source, context)

    return CompressedPlugin


def _compressed_archive(tmp_path: Path, stored: bytes, plain: bytes = _PLAIN) -> Path:
    data = build_toya(
        [("m.bin", MemberType.FILE, stored)],
        sizes={0: len(plain)},
        crcs={0: zlib.crc32(plain)},
    )
    return _write(tmp_path, data)


def _compress(method: CompressionAlgorithm, data: bytes) -> bytes:
    if method is CompressionAlgorithm.STORED:
        return data
    if method is CompressionAlgorithm.DEFLATE:
        return _raw_deflate(data)
    if method is CompressionAlgorithm.BZIP2:
        return bz2.compress(data)
    if method is CompressionAlgorithm.DEFLATE64:
        import inflate64

        deflater = inflate64.Deflater()
        return deflater.deflate(data) + deflater.flush()
    if method is CompressionAlgorithm.ZSTD:
        from tests.conftest import zstd_backend

        return zstd_backend().compress(data)
    if method is CompressionAlgorithm.LZ4:
        import lz4.frame

        return lz4.frame.compress(data)
    assert method is CompressionAlgorithm.BROTLI
    import brotli

    return brotli.compress(data)


@pytest.mark.parametrize(
    "method",
    [
        CompressionAlgorithm.STORED,
        CompressionAlgorithm.DEFLATE,
        CompressionAlgorithm.BZIP2,
        CompressionAlgorithm.LZMA,
        CompressionAlgorithm.LZMA2,
        pytest.param(CompressionAlgorithm.DEFLATE64, marks=requires("inflate64")),
        pytest.param(CompressionAlgorithm.ZSTD, marks=requires_zstd()),
        pytest.param(CompressionAlgorithm.LZ4, marks=requires("lz4")),
        pytest.param(CompressionAlgorithm.BROTLI, marks=requires("brotli")),
    ],
)
def test_decompress_methods(
    clean_registry: None, tmp_path: Path, method: CompressionAlgorithm
) -> None:
    properties = None
    if method not in (CompressionAlgorithm.LZMA, CompressionAlgorithm.LZMA2):
        stored = _compress(method, _PLAIN)
    else:
        filter_id = (
            lzma.FILTER_LZMA1
            if method is CompressionAlgorithm.LZMA
            else lzma.FILTER_LZMA2
        )
        stored, properties = _lzma_raw(_PLAIN, filter_id)
    register_format(_compressed_plugin(method, properties))
    with (
        open_archive(_compressed_archive(tmp_path, stored)) as reader,
        reader.open("m.bin") as stream,
    ):
        assert stream.read() == _PLAIN
        assert stream.verified is archivey.Verification.CONTENT


@pytest.mark.parametrize(
    "method",
    [
        pytest.param(CompressionAlgorithm.ZSTD, marks=requires_zstd()),
        pytest.param(CompressionAlgorithm.LZ4, marks=requires("lz4")),
    ],
)
def test_decompress_reads_every_frame(
    clean_registry: None, tmp_path: Path, method: CompressionAlgorithm
) -> None:
    """Zstd and LZ4 data may be several frames, and a member reads them all."""
    half = len(_PLAIN) // 2
    stored = _compress(method, _PLAIN[:half]) + _compress(method, _PLAIN[half:])
    register_format(_compressed_plugin(method))
    with open_archive(_compressed_archive(tmp_path, stored)) as reader:
        assert reader.read("m.bin") == _PLAIN


def test_decompress_second_bzip2_stream_is_corrupt(
    clean_registry: None, tmp_path: Path
) -> None:
    """A bzip2 member is one stream, as in ZIP and 7z."""
    half = len(_PLAIN) // 2
    stored = bz2.compress(_PLAIN[:half]) + bz2.compress(_PLAIN[half:])
    register_format(_compressed_plugin(CompressionAlgorithm.BZIP2))
    with (
        open_archive(_compressed_archive(tmp_path, stored)) as reader,
        pytest.raises(CorruptionError),
    ):
        reader.read("m.bin")


def test_decompress_passes_sizes_to_the_codec(
    clean_registry: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each call gets the member's sizes, which the accelerators choose by, as ZIP
    gives them per member."""
    from archivey.internal import plugin_adapter

    seen: list[tuple[int | None, int | None]] = []
    real = plugin_adapter.open_codec_stream

    def spy(*args: object, config: object, **kwargs: object) -> object:
        seen.append(
            (
                config.expected_decompressed_size,  # type: ignore[attr-defined]
                config.compressed_input_size,  # type: ignore[attr-defined]
            )
        )
        return real(*args, config=config, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(plugin_adapter, "open_codec_stream", spy)
    stored = _raw_deflate(_PLAIN)
    register_format(_compressed_plugin(CompressionAlgorithm.DEFLATE))
    with open_archive(_compressed_archive(tmp_path, stored)) as reader:
        assert reader.read("m.bin") == _PLAIN
    assert seen == [(len(_PLAIN), len(stored))]


def test_decompress_data_after_end_is_corrupt(
    clean_registry: None, tmp_path: Path
) -> None:
    register_format(_compressed_plugin(CompressionAlgorithm.DEFLATE))
    path = _compressed_archive(tmp_path, _raw_deflate(_PLAIN) + b"junk")
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read("m.bin")


def test_decompress_errors_skip_the_plugin_translator(
    clean_registry: None, tmp_path: Path
) -> None:
    translated: list[Exception] = []
    register_format(
        _compressed_plugin(CompressionAlgorithm.DEFLATE, translated=translated)
    )
    path = _compressed_archive(tmp_path, b"\xff" * 64)
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read("m.bin")
    assert translated == []


@pytest.mark.parametrize(
    ("method", "properties", "error"),
    [
        (CompressionAlgorithm.PPMD, None, archivey.UnsupportedFeatureError),
        (CompressionAlgorithm.LZMA, None, CorruptionError),
        (CompressionAlgorithm.LZMA2, b"\x00\x00", CorruptionError),
    ],
)
def test_decompress_refusals(
    clean_registry: None,
    tmp_path: Path,
    method: CompressionAlgorithm,
    properties: bytes | None,
    error: type[Exception],
) -> None:
    register_format(_compressed_plugin(method, properties))
    with (
        open_archive(_compressed_archive(tmp_path, b"x")) as reader,
        pytest.raises(error),
    ):
        reader.read("m.bin")


def _stream(method: StreamFormat, data: bytes) -> bytes:
    if method is StreamFormat.ZLIB:
        return zlib.compress(data)
    if method is StreamFormat.GZIP:
        import gzip

        return gzip.compress(data, mtime=0)
    if method is StreamFormat.BZIP2:
        return bz2.compress(data)
    if method is StreamFormat.XZ:
        return lzma.compress(data, format=lzma.FORMAT_XZ)
    assert method is StreamFormat.LZMA_ALONE
    return lzma.compress(data, format=lzma.FORMAT_ALONE)


@pytest.mark.parametrize(
    "method",
    [
        StreamFormat.ZLIB,
        StreamFormat.GZIP,
        StreamFormat.BZIP2,
        StreamFormat.XZ,
        StreamFormat.LZMA_ALONE,
    ],
)
def test_decompress_stream_formats(
    clean_registry: None, tmp_path: Path, method: StreamFormat
) -> None:
    register_format(_compressed_plugin(method))
    path = _compressed_archive(tmp_path, _stream(method, _PLAIN))
    with open_archive(path) as reader, reader.open("m.bin") as stream:
        assert stream.read() == _PLAIN
        assert stream.verified is archivey.Verification.CONTENT


def test_decompress_stream_format_reads_as_its_files_do(
    clean_registry: None, tmp_path: Path
) -> None:
    """Unlike a bzip2 member, a ``.bz2`` stream may hold several, as bzip2 decodes."""
    half = len(_PLAIN) // 2
    stored = bz2.compress(_PLAIN[:half]) + bz2.compress(_PLAIN[half:])
    register_format(_compressed_plugin(StreamFormat.BZIP2))
    with open_archive(_compressed_archive(tmp_path, stored)) as reader:
        assert reader.read("m.bin") == _PLAIN


@pytest.mark.parametrize(
    "method", [StreamFormat.ZLIB, StreamFormat.GZIP, StreamFormat.XZ]
)
def test_decompress_stream_format_reports_data_after_end(
    clean_registry: None, tmp_path: Path, method: StreamFormat
) -> None:
    """As for a file of that format: reported, and raised only under a strict policy."""
    register_format(_compressed_plugin(method))
    path = _compressed_archive(tmp_path, _stream(method, _PLAIN) + b"junk")
    with open_archive(path) as reader:
        assert reader.read("m.bin") == _PLAIN
        assert reader.diagnostics.counts == {DiagnosticCode.ARCHIVE_TRAILING_DATA: 1}
    strict = archivey.ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)
    with (
        open_archive(path, config=strict) as reader,
        pytest.raises(archivey.ArchiveyError),
    ):
        reader.read("m.bin")


class _Trickle(io.RawIOBase):
    """A raw stream that returns at most 7 bytes a read, as ``io.RawIOBase`` may."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        chunk = self._data.read(min(len(buffer), 7))
        buffer[: len(chunk)] = chunk
        return len(chunk)


@pytest.mark.parametrize("wrap", [lambda stream: stream, buffered_stream])
def test_a_raw_stream_reads_whole_lengths(
    clean_registry: None, tmp_path: Path, wrap: Callable[[_Trickle], BinaryIO]
) -> None:
    """A plugin's stream may return short reads, as an ``io.RawIOBase`` may: the
    member stream still returns what ``read(n)`` asks for, and closing it closes the
    plugin's stream."""
    opened: list[_Trickle] = []

    class TrickleReader(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, length = locator
            opened.append(_Trickle(self._source.read_at(offset, length)))
            return MemberData(wrap(opened[-1]))

    class TricklePlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return TrickleReader(source, context)

    register_format(TricklePlugin)
    path = _compressed_archive(tmp_path, _PLAIN)
    with open_archive(path) as reader, reader.open("m.bin") as stream:
        assert stream.read(1000) == _PLAIN[:1000]
        assert stream.read() == _PLAIN[1000:]
    assert opened[0].closed


def test_only_streams_that_may_read_short_are_wrapped() -> None:
    """A buffered stream and archivey's own streams already return whole reads."""
    from archivey.internal import plugin_adapter
    from archivey.internal.streams.streamtools import SharedSource

    assert plugin_adapter._reads_full(io.BytesIO())
    with SharedSource(io.BytesIO(b"abc")).view(0, 3) as view:
        assert plugin_adapter._reads_full(view)
    assert not plugin_adapter._reads_full(_Trickle(b""))


def test_buffered_stream_keeps_a_buffered_stream_and_refuses_others() -> None:
    buffered = io.BytesIO(b"x")
    assert buffered_stream(buffered) is buffered
    with pytest.raises(TypeError, match="RawIOBase"):
        buffered_stream(object())  # type: ignore[arg-type]


def test_translate_exception_mid_read(clean_registry: None, tmp_path: Path) -> None:
    class FailingStream(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def readinto(self, buffer: object) -> int:
            raise ValueError("library failed mid-read")

    class FailingReader(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            return MemberData(FailingStream())  # type: ignore[arg-type]

        def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
            if isinstance(exc, ValueError):
                return CorruptionError(str(exc))
            return None

    class FailingPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return FailingReader(source, context)

    register_format(FailingPlugin)
    path = _write(tmp_path, build_toya(_ENTRIES))
    with (
        open_archive(path) as reader,
        pytest.raises(CorruptionError, match="mid-read") as info,
    ):
        reader.read("docs/a.txt")
    assert info.value.member_name == "docs/a.txt"


# ── Seekable members over a plugin stream that reads forward only ───────────────────


class _ForwardOnly(io.RawIOBase):
    def __init__(self, data: bytes, opened: list[int]) -> None:
        self._data = io.BytesIO(data)
        opened.append(1)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        chunk = self._data.read(len(buffer))
        buffer[: len(chunk)] = chunk
        return len(chunk)


def _forward_only_plugin(
    opened: list[int], *, listed_size: bool = True
) -> type[FormatPlugin]:
    class ForwardOnlyReader(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                if not listed_size and record.member.is_file:
                    record.member.size = None
                yield record

        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, size = locator
            return MemberData(
                _ForwardOnly(self._source.read_at(offset, size), opened)  # type: ignore[arg-type]
            )

    class ForwardOnlyPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return ForwardOnlyReader(source, context)

    return ForwardOnlyPlugin


def test_seekable_member_over_forward_only_stream(
    clean_registry: None, tmp_path: Path
) -> None:
    opened: list[int] = []
    register_format(_forward_only_plugin(opened))
    data = bytes(range(256)) * 4
    path = _write(tmp_path, build_toya(_ENTRIES))
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("b.bin") as stream,
    ):
        assert stream.seekable()
        stream.seek(500)
        assert stream.read(4) == data[500:504]
        assert len(opened) == 1  # a forward seek reads through
        stream.seek(10)
        assert stream.read(4) == data[10:14]
        assert len(opened) == 2  # a backward seek opens the member again
        stream.seek(0)
        assert stream.read() == data
        assert stream.verified is archivey.Verification.CONTENT


def test_forward_only_stream_without_seekable_members(
    clean_registry: None, tmp_path: Path
) -> None:
    register_format(_forward_only_plugin([]))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader, reader.open("b.bin") as stream:
        assert not stream.seekable()


# ── Digests archivey computes with a hasher the plugin supplies ─────────────────────


class _Sum16:
    """A checksum archivey has no hasher for: the byte sum modulo 2¹⁶."""

    def __init__(self) -> None:
        self._value = 0

    def update(self, data: bytes, /) -> None:
        self._value = (self._value + sum(data)) & 0xFFFF

    def digest(self) -> bytes:
        return self._value.to_bytes(2, "little")


def _sum16(data: bytes) -> bytes:
    hasher = _Sum16()
    hasher.update(data)
    return hasher.digest()


def _digest_plugin(digests: dict[str, MemberDigest]) -> type[FormatPlugin]:
    """TOYA with no CRC-32 in the listing: only ``digests`` (by member name) checks."""

    class DigestReader(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                record.member.hashes = {}
                yield record

        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, size = locator
            return MemberData(
                self._source.view(offset, size), digests=(digests[member.name],)
            )

    class DigestPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return DigestReader(source, context)

    return DigestPlugin


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (
            lambda data: MemberDigest(
                "sha1", hashlib.sha1(data).digest(), hashlib.sha1
            ),
            "sha1",
        ),
        (lambda data: MemberDigest("sum16", _sum16(data), _Sum16), "sum16"),
    ],
)
def test_member_digest_checked(
    clean_registry: None, tmp_path: Path, make: object, name: str
) -> None:
    data = bytes(range(256)) * 4
    good = make(data)  # type: ignore[operator]
    register_format(_digest_plugin({"b.bin": good}))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader, reader.open("b.bin") as stream:
        assert stream.read() == data
        assert stream.verified is archivey.Verification.CONTENT


def test_member_digest_mismatch_raises(clean_registry: None, tmp_path: Path) -> None:
    bad = MemberDigest("sha1", bytes(20), hashlib.sha1)
    register_format(_digest_plugin({"b.bin": bad}))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader, pytest.raises(CorruptionError, match="sha1"):
        reader.read("b.bin")


def test_member_digest_across_seeks(clean_registry: None, tmp_path: Path) -> None:
    data = bytes(range(256)) * 4
    register_format(
        _digest_plugin({"b.bin": MemberDigest("sum16", _sum16(data), _Sum16)})
    )
    path = _write(tmp_path, build_toya(_ENTRIES))
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("b.bin") as stream,
    ):
        stream.read(300)
        stream.seek(100)  # bytes read again are not fed to the hasher twice
        assert stream.read() == data[100:]
        assert stream.verified is archivey.Verification.CONTENT


def test_seekable_member_with_no_listed_size(
    clean_registry: None, tmp_path: Path
) -> None:
    opened: list[int] = []
    register_format(_forward_only_plugin(opened, listed_size=False))
    data = bytes(range(256)) * 4
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path, seekable_members=True) as reader:
        assert reader.get("b.bin").size is None
        with reader.open("b.bin") as stream:
            assert stream.seekable()
            assert stream.seek(-4, io.SEEK_END) == len(data) - 4
            assert stream.read() == data[-4:]
            stream.seek(10)
            assert stream.read(4) == data[10:14]
            stream.seek(0)
            assert stream.read() == data
            assert stream.verified is archivey.Verification.CONTENT


@pytest.mark.parametrize(
    ("digests", "expected", "match"),
    [
        (
            (MemberDigest("crc32", b"\0\0\0\0", hashlib.sha1),),
            {},
            "HashAlgorithm archivey computes itself",
        ),
        (
            (MemberDigest("SHA1", b"\0" * 20, hashlib.sha1),),
            {"sha1": b"\0" * 20},
            "already lists as a hash",
        ),
        # Refused even with no hasher for the listed one: two stored values, one name.
        (
            (MemberDigest("crc16", b"\x12\x34", hashlib.sha1),),
            {"crc16": b"\x12\x34"},
            "already lists as a hash",
        ),
        (
            (
                MemberDigest("sha1", b"x", hashlib.sha1),
                MemberDigest("SHA1", b"y", hashlib.sha1),
            ),
            {},
            "another digest of the member also uses",
        ),
    ],
)
def test_member_digest_names_must_not_clash(
    clean_registry: None,
    tmp_path: Path,
    digests: tuple[MemberDigest, ...],
    expected: dict[str, bytes],
    match: str,
) -> None:
    """A digest named like a ``HashAlgorithm`` or a hash the member lists, or like
    another digest, would share one key with it in the verifier; all are refused, and the refused member's stream is closed. The
    reader translates broadly, so a refusal inside the error boundary would come out
    as ``CorruptionError``."""
    opened: list[BinaryIO] = []

    class Clashing(_BroadTranslator):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            stream = self._source.view(*locator)
            opened.append(stream)
            return MemberData(stream, expected_hashes=expected, digests=digests)

    _plugin_with("clash", reader=Clashing)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.clash")
    with open_archive(path) as reader, pytest.raises(ValueError, match=match):
        reader.read("docs/a.txt")
    assert opened
    assert opened[0].closed


def test_member_stream_is_closed_when_a_hasher_factory_fails(
    clean_registry: None, tmp_path: Path
) -> None:
    opened: list[BinaryIO] = []

    def no_hasher() -> hashlib._Hash:
        raise ValueError("unsupported hash type crc16")

    class FailingFactory(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            stream = self._source.view(*locator)
            opened.append(stream)
            return MemberData(
                stream, digests=(MemberDigest("crc16", b"\x12\x34", no_hasher),)
            )

    _plugin_with("nohasher", reader=FailingFactory)
    path = _write(tmp_path, build_toya(_ENTRIES), "t.nohasher")
    with open_archive(path) as reader, pytest.raises(ValueError, match="crc16"):
        reader.read("docs/a.txt")
    assert opened
    assert opened[0].closed


# ── Reports, config and the plugin-level translator ─────────────────────────────────


def _reporting_plugin(
    report: Callable[[PluginContext, ArchiveMember], None],
) -> type[FormatPlugin]:
    """TOYA whose reader calls ``report(context, member)`` on ``docs/a.txt``."""

    class ReportingReader(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                if record.member.name == "docs/a.txt":
                    report(self._context, record.member)
                yield record

    class ReportingPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return ReportingReader(source, context)

    return ReportingPlugin


def test_report_fills_archive_and_member(clean_registry: None, tmp_path: Path) -> None:
    def report(context: PluginContext, member: ArchiveMember) -> None:
        context.report(
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
            "bad date",
            MemberTimestampContext(
                member_name=member.name,
                field="modified",
                source="toya",
                value_repr="0",
            ),
            member=member,
        )

    register_format(_reporting_plugin(report))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader:
        member = reader.get("docs/a.txt")
        (found,) = member.diagnostics
        assert found.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        assert found.context.archive_name is not None
        assert found.context.member_id == member.member_id == 1  # type: ignore[union-attr]


def test_report_refuses_a_mismatched_context(
    clean_registry: None, tmp_path: Path
) -> None:
    def report(context: PluginContext, member: ArchiveMember) -> None:
        context.report(
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
            "wrong context",
            SymlinkTargetContext(member_name=member.name, reason="x"),
        )

    register_format(_reporting_plugin(report))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader, pytest.raises(ArchiveyUsageError):
        reader.members()


def test_link_target_unavailable(clean_registry: None, tmp_path: Path) -> None:
    def report(context: PluginContext, member: ArchiveMember) -> None:
        context.link_target_unavailable(
            member,
            reason="target_record_malformed",
            message="lost",
            target_in_archive=True,
        )
        with pytest.raises(ArchiveyUsageError):
            context.report(
                DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE,
                "lost",
                SymlinkTargetContext(member_name=member.name, reason="x"),
            )

    register_format(_reporting_plugin(report))
    path = _write(tmp_path, build_toya(_ENTRIES))
    with open_archive(path) as reader:
        member = reader.get("docs/a.txt")
        assert member.link_target is None
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]


def test_context_config_is_the_callers(clean_registry: None, tmp_path: Path) -> None:
    seen: list[archivey.ArchiveyConfig] = []

    def report(context: PluginContext, member: ArchiveMember) -> None:
        seen.append(context.config)

    register_format(_reporting_plugin(report))
    config = archivey.ArchiveyConfig()
    with open_archive(_write(tmp_path, build_toya(_ENTRIES)), config=config) as reader:
        reader.members()
    assert seen == [config]


def test_plugin_translates_errors_from_open(
    clean_registry: None, tmp_path: Path
) -> None:
    class FailingOpenPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            raise ValueError("bad header")

        def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
            if isinstance(exc, ValueError):
                return CorruptionError(str(exc))
            return None

    register_format(FailingOpenPlugin)
    with pytest.raises(CorruptionError, match="bad header"):
        open_archive(_write(tmp_path, build_toya(_ENTRIES)))


# ── MemberData.bounded ─────────────────────────────────────────────────────────────


class _CountingReads(io.BytesIO):
    def __init__(self, data: bytes, reads: list[int]) -> None:
        super().__init__(data)
        self._reads = reads

    def read(self, n: int | None = -1, /) -> bytes:
        data = super().read(n)
        self._reads.append(len(data))
        return data


def _bounded_plugin(
    reads: list[int], *, bounded: bool, extra: bytes = b"", cut: int = 0
) -> type[FormatPlugin]:
    class BoundedReader(ToyReader):
        def open_member(
            self, member: ArchiveMember, locator: tuple[int, int]
        ) -> MemberData:
            offset, size = locator
            data = self._source.read_at(offset, size - cut) + extra
            return MemberData(_CountingReads(data, reads), bounded=bounded)  # type: ignore[arg-type]

    class BoundedPlugin(ToyPlugin):
        def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
            return BoundedReader(source, context)

    return BoundedPlugin


@pytest.mark.parametrize("bounded", [False, True])
def test_bounded_skips_the_read_past_the_end(
    clean_registry: None, tmp_path: Path, bounded: bool
) -> None:
    reads: list[int] = []
    register_format(_bounded_plugin(reads, bounded=bounded))
    with open_archive(_write(tmp_path, build_toya(_ENTRIES))) as reader:
        assert reader.read("b.bin") == bytes(range(256)) * 4
    # Without the promise archivey reads once more at the end, to look for extra data.
    assert reads.count(0) == (0 if bounded else 1)


def test_bounded_short_stream_is_truncated(
    clean_registry: None, tmp_path: Path
) -> None:
    register_format(_bounded_plugin([], bounded=True, cut=10))
    with (
        open_archive(_write(tmp_path, build_toya(_ENTRIES))) as reader,
        pytest.raises(TruncatedError),
    ):
        reader.read("b.bin")


def test_bounded_long_stream_is_cut_at_the_size(
    clean_registry: None, tmp_path: Path
) -> None:
    """A broken promise loses the over-run check, but never hands over the extra."""
    register_format(_bounded_plugin([], bounded=True, extra=b"EXTRA"))
    with open_archive(_write(tmp_path, build_toya(_ENTRIES))) as reader:
        assert reader.read("b.bin") == bytes(range(256)) * 4


def test_a_reader_can_normalize_names_itself(
    clean_registry: None, tmp_path: Path
) -> None:
    """A reader that names a member in a report while listing normalizes the name
    first; archivey still reports the change, from ``stored_name``."""

    class SelfNormalizing(ToyReader):
        def iter_members(self) -> Iterator[MemberRecord[tuple[int, int]]]:
            for record in super().iter_members():
                member = record.member
                stored = member.name
                member.name = self._context.normalize_name(stored, member.type)
                yield MemberRecord(member, record.locator, stored_name=stored)

    _plugin_with("selfnorm", reader=SelfNormalizing)
    data = build_toya(
        [("./a//b.txt", MemberType.FILE, b"b"), ("d", MemberType.DIRECTORY, b"")]
    )
    with open_archive(_write(tmp_path, data, "t.selfnorm")) as reader:
        assert [m.name for m in reader.members()] == ["a/b.txt", "d/"]
        # A directory's trailing slash is not a reported change.
        counts = reader.diagnostics.counts
        assert counts.get(archivey.DiagnosticCode.MEMBER_NAME_NORMALIZED) == 1
