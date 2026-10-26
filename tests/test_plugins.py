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
from collections.abc import Iterator
from pathlib import Path

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
from archivey.internal import format_args
from archivey.internal.registry import get_registry
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
def clean_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = get_registry()
    monkeypatch.setattr(reg, "_readers", dict(reg._readers))
    monkeypatch.setattr(reg, "_plugin_classes", list(reg._plugin_classes))
    monkeypatch.setattr(reg, "_extension_map_cache", None)
    monkeypatch.setattr(format_args, "_plugin_spellings", {})


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
        try:
            reader.extract_all(dest)
        except archivey.ArchiveyError:
            pass
    assert not (tmp_path / "escape.txt").exists()


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
        ({"extensions": ("toya",)}, "start with a dot"),
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
    method: CompressionAlgorithm,
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


@pytest.mark.parametrize(
    "method",
    [
        CompressionAlgorithm.STORED,
        CompressionAlgorithm.DEFLATE,
        CompressionAlgorithm.BZIP2,
        CompressionAlgorithm.LZMA,
        CompressionAlgorithm.LZMA2,
    ],
)
def test_decompress_methods(
    clean_registry: None, tmp_path: Path, method: CompressionAlgorithm
) -> None:
    properties = None
    if method is CompressionAlgorithm.STORED:
        stored = _PLAIN
    elif method is CompressionAlgorithm.DEFLATE:
        stored = _raw_deflate(_PLAIN)
    elif method is CompressionAlgorithm.BZIP2:
        stored = bz2.compress(_PLAIN)
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


def _forward_only_plugin(opened: list[int]) -> type[FormatPlugin]:
    class ForwardOnlyReader(ToyReader):
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
