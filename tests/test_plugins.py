"""The plugin API (``archivey.plugins``): an indexed plugin through the public surface.

The test format, TOYA, is defined here with ``archivey.plugins`` and the root API
only: a magic line, a count, one index entry per member (name, type, size, CRC-32,
data offset), then the data. Each test registers it on a registry restored afterwards
(``toya`` fixture).
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyUsageError,
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
from archivey.internal import format_args
from archivey.internal.plugin_adapter import registration_scope
from archivey.plugins import (
    FormatPlugin,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    PluginArchiveInfo,
    PluginContext,
    PluginSource,
    register_format,
)

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
