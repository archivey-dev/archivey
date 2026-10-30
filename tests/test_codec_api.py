"""``archivey.formats.register_codec``: one ``CodecHandler`` makes a compression format
readable everywhere a built-in codec is (single file, ``.tar.x``, a sequential plugin
pair, ``open_stream``, ``ReaderContext.decompress``), under the same rules."""

from __future__ import annotations

import io
import logging
import tarfile
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    ContainerFormat,
    CorruptionError,
    DiagnosticCode,
    FormatDetectionError,
    FormatPolicy,
    FormatSupport,
    MemberType,
    PackageNotInstalledError,
    PluginStream,
    ResourceLimitError,
    StreamFormat,
    TruncatedError,
    Verification,
    detect_format,
    format_availability,
    list_supported_formats,
    open_archive,
    open_stream,
)
from archivey.exceptions import ArchiveyError
from archivey.formats import CodecHandler, Magic, register_codec, register_format
from archivey.internal.format_adapter import registration_scope
from tests.streams_util import NonSeekableBytesIO
from tests.test_format_api import _compressed_archive, _compressed_plugin
from tests.test_format_api_sequential import (
    _DATA,
    _ENTRIES,
    _RPM_NAMES,
    ToysContainer,
    ToysHandler,
    _RpmishReader,
    _variant,
    build_rpmish,
    build_toys,
)

_MAGIC = b"TOY1"


class ToyStream(PluginStream):
    TOY = "toy"


TOY = ArchiveFormat(ContainerFormat.RAW_STREAM, ToyStream.TOY)
TAR_TOY = ArchiveFormat(ContainerFormat.TAR, ToyStream.TOY)


def toy_compress(data: bytes) -> bytes:
    """A TOY stream: the magic, literal records of up to 127 bytes, a zero byte, then
    the CRC-32 of the output. (A record of 128 to 255 is a run: the next byte, repeated
    ``(code - 127) * 1024`` times.)"""
    out = bytearray(_MAGIC)
    for at in range(0, len(data), 127):
        piece = data[at : at + 127]
        out += bytes([len(piece)]) + piece
    return bytes(out + b"\x00" + zlib.crc32(data).to_bytes(4, "big"))


class ToyError(ValueError):
    pass


class ToyDecompressor:
    """The ``bz2.BZ2Decompressor`` interface over a TOY stream."""

    def __init__(self) -> None:
        self._in = bytearray()
        self._out = bytearray()
        self._crc = 0
        self._started = False
        self._ended = False
        self.unused_data = b""

    @property
    def eof(self) -> bool:
        # As the standard library's: the end is reached once its output is returned.
        return self._ended and not self._out

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._ended and data:
            raise EOFError("end of stream already reached")
        self._in += data
        self._parse()
        n = len(self._out) if max_length < 0 else min(max_length, len(self._out))
        out = bytes(self._out[:n])
        del self._out[:n]
        return out

    def _parse(self) -> None:
        if not self._started:
            if len(self._in) < 4:
                return
            if self._in[:4] != _MAGIC:
                raise ToyError("not a TOY stream")
            del self._in[:4]
            self._started = True
        while self._in and not self._ended:
            code = self._in[0]
            if code == 0:
                if len(self._in) < 5:
                    return
                if int.from_bytes(self._in[1:5], "big") != self._crc:
                    raise ToyError("CRC mismatch")
                self.unused_data = bytes(self._in[5:])
                self._in.clear()
                self._ended = True
            elif code < 128:
                if len(self._in) < 1 + code:
                    return
                piece = bytes(self._in[1 : 1 + code])
                del self._in[: 1 + code]
                self._emit(piece)
            else:
                if len(self._in) < 2:
                    return
                piece = bytes([self._in[1]]) * ((code - 127) * 1024)
                del self._in[:2]
                self._emit(piece)

    def _emit(self, piece: bytes) -> None:
        self._crc = zlib.crc32(piece, self._crc)
        self._out += piece

    @property
    def needs_input(self) -> bool:
        return not self._out and not self._ended


class ToyHandler(CodecHandler):
    stream_format = ToyStream.TOY
    extension_aliases = (".toyz",)
    magic = (Magic(0, _MAGIC),)
    checks_content = True

    def decompressor(self) -> ToyDecompressor:
        return ToyDecompressor()

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, ToyError):
            return CorruptionError(f"bad TOY stream: {exc}")
        return None


@pytest.fixture
def toy() -> Iterator[ArchiveFormat]:
    with registration_scope():
        register_codec(ToyHandler)
        yield TOY


_TEXT = b"the quick brown fox jumps over the lazy dog\n" * 300


def _tar(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


# --- one file ---------------------------------------------------------------------------


def test_a_single_file_is_detected_and_read(toy: ArchiveFormat, tmp_path: Path) -> None:
    path = tmp_path / "notes.txt.toy"
    path.write_bytes(toy_compress(_TEXT))
    info = detect_format(path)
    assert info.format == toy
    assert info.from_plugin
    with open_archive(path) as reader:
        assert reader.format == toy
        assert reader.format.display_name == "TOY"
        (member,) = reader.members()
        assert member.name == "notes.txt"
        assert reader.read(member) == _TEXT


def test_a_stream_without_its_name_is_found_by_magic(toy: ArchiveFormat) -> None:
    with open_archive(io.BytesIO(toy_compress(_TEXT))) as reader:
        assert reader.format == toy
        assert reader.read(reader.members()[0]) == _TEXT


@pytest.mark.parametrize("fmt", ["toy", "TOY", ToyStream.TOY, TOY])
def test_open_stream_takes_the_codec(toy: ArchiveFormat, fmt: object) -> None:
    with open_stream(io.BytesIO(toy_compress(_TEXT)), format=fmt) as stream:  # type: ignore[arg-type]
        assert stream.read() == _TEXT


def test_a_misspelled_format_lists_the_codec(toy: ArchiveFormat) -> None:
    with pytest.raises(ArchiveyUsageError, match="'toy'"):
        open_stream(io.BytesIO(toy_compress(_TEXT)), format="toi")


def test_open_stream_detects_the_codec_and_reads_a_pipe(toy: ArchiveFormat) -> None:
    with open_stream(NonSeekableBytesIO(toy_compress(_TEXT))) as stream:
        assert stream.read() == _TEXT


def test_a_backward_seek_decodes_again_from_the_start(toy: ArchiveFormat) -> None:
    with open_stream(io.BytesIO(toy_compress(_TEXT)), seekable=True) as stream:
        assert stream.read(1000) == _TEXT[:1000]
        stream.seek(10)
        assert stream.read(20) == _TEXT[10:30]


def test_the_alias_extension_names_the_format(
    toy: ArchiveFormat, tmp_path: Path
) -> None:
    path = tmp_path / "a.toyz"
    path.write_bytes(toy_compress(b"x"))
    with open_archive(path) as reader:
        assert reader.format == toy


def test_concatenated_streams_read_as_one(toy: ArchiveFormat) -> None:
    data = toy_compress(b"first ") + toy_compress(b"second")
    with open_stream(io.BytesIO(data)) as stream:
        assert stream.read() == b"first second"


def test_zero_padding_after_the_end_is_accepted(toy: ArchiveFormat) -> None:
    with open_stream(io.BytesIO(toy_compress(b"abc") + bytes(100))) as stream:
        assert stream.read() == b"abc"


def test_trailing_data_is_reported(toy: ArchiveFormat) -> None:
    data = toy_compress(_TEXT) + b"GARBAGE"
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read(reader.members()[0]) == _TEXT
        codes = {d.code for d in reader.diagnostics.retained}
    assert DiagnosticCode.ARCHIVE_TRAILING_DATA in codes


@pytest.mark.parametrize(("checks", "level"), [(True, "CONTENT"), (False, "STRUCTURE")])
def test_checks_content_sets_the_verification_level(checks: bool, level: str) -> None:
    class Handler(ToyHandler):
        checks_content = checks

    with registration_scope():
        register_codec(Handler)
        with (
            open_archive(io.BytesIO(toy_compress(_TEXT))) as reader,
            reader.open(reader.members()[0]) as stream,
        ):
            assert stream.verifiable == Verification[level]
            assert stream.read() == _TEXT
            assert stream.verified == Verification[level]


class OnceStream(PluginStream):
    ONCE = "toyonce"


def test_a_codec_that_is_not_concatenated_reads_one_stream() -> None:
    class OnceHandler(ToyHandler):
        stream_format = OnceStream.ONCE
        extension_aliases = ()
        concatenated = False

    with registration_scope():
        register_codec(OnceHandler)
        data = toy_compress(b"first ") + toy_compress(b"second")
        with open_archive(io.BytesIO(data)) as reader:
            assert reader.read(reader.members()[0]) == b"first "
            codes = {d.code for d in reader.diagnostics.retained}
    assert DiagnosticCode.ARCHIVE_TRAILING_DATA in codes


class ProbedStream(PluginStream):
    PROBED = "toyprobed"


_PROBED_MAGIC = b"PRB!"


class ProbedDecompressor(ToyDecompressor):
    """A TOY stream behind another 4-byte prefix that no magic declares."""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if not self._started and len(self._in) + len(data) >= 4:
            data = bytes(self._in) + data
            self._in.clear()
            if data[:4] != _PROBED_MAGIC:
                raise ToyError("not a probed TOY stream")
            data = _MAGIC + data[4:]
        return super().decompress(data, max_length)


class ProbedHandler(CodecHandler):
    stream_format = ProbedStream.PROBED
    probe = staticmethod(lambda prefix: prefix.startswith(_PROBED_MAGIC))

    def decompressor(self) -> ProbedDecompressor:
        return ProbedDecompressor()


def _probed(data: bytes) -> bytes:
    return _PROBED_MAGIC + toy_compress(data)[4:]


def test_a_probe_finds_a_codec_with_no_magic(tmp_path: Path) -> None:
    probed = ArchiveFormat(ContainerFormat.RAW_STREAM, ProbedStream.PROBED)
    data = _probed(_TEXT)
    with registration_scope():
        register_codec(ProbedHandler)
        # As for a built-in probe: not on an unnamed source by default...
        with pytest.raises(FormatDetectionError):
            detect_format(io.BytesIO(data))
        # ...but on a source with the format's extension, with
        # always_probe_content, and in open_stream.
        path = tmp_path / "notes.toyprobed"
        path.write_bytes(data)
        assert detect_format(path).format == probed
        config = ArchiveyConfig(always_probe_content=True)
        assert detect_format(io.BytesIO(data), config=config).format == probed
        with open_stream(io.BytesIO(data)) as stream:
            assert stream.read() == _TEXT


def test_a_probe_that_raises_is_no_match(caplog: pytest.LogCaptureFixture) -> None:
    def probe(prefix: bytes) -> bool:
        raise RuntimeError("broken probe")

    class RaisingHandler(ProbedHandler):
        pass

    RaisingHandler.probe = staticmethod(probe)
    config = ArchiveyConfig(always_probe_content=True)
    with registration_scope():
        register_codec(RaisingHandler)
        with caplog.at_level(logging.DEBUG, logger="archivey.detection"):
            with pytest.raises(FormatDetectionError):
                detect_format(io.BytesIO(_probed(_TEXT)), config=config)
            with pytest.raises(FormatDetectionError):
                detect_format(io.BytesIO(_probed(_TEXT)), config=config)
    # Logged as a format plugin's probe is: WARNING once, then DEBUG.
    levels = [r.levelno for r in caplog.records if "plugin probe" in r.getMessage()]
    assert levels == [logging.WARNING, logging.DEBUG]


def test_a_cut_stream_is_truncated(toy: ArchiveFormat) -> None:
    data = toy_compress(_TEXT)[:-3]
    with open_stream(io.BytesIO(data)) as stream, pytest.raises(TruncatedError):
        stream.read()


def test_an_empty_stream_after_the_magic_is_truncated(toy: ArchiveFormat) -> None:
    with (
        open_stream(io.BytesIO(_MAGIC), format=ToyStream.TOY) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


def test_the_decoders_error_goes_through_translate_exception(
    toy: ArchiveFormat,
) -> None:
    data = bytearray(toy_compress(_TEXT))
    data[-1] ^= 0xFF
    with (
        open_stream(io.BytesIO(bytes(data))) as stream,
        pytest.raises(CorruptionError, match="CRC mismatch"),
    ):
        stream.read()


def test_the_ratio_limit_holds(toy: ArchiveFormat) -> None:
    # 32 MiB of zeros from about 500 bytes: 256 run records of 128 KiB each.
    data = _MAGIC + bytes([255, 0]) * 256 + b"\x00"
    data += zlib.crc32(bytes(128 * 1024 * 256)).to_bytes(4, "big")
    with open_archive(io.BytesIO(data)) as reader:
        member = reader.members()[0]
        with pytest.raises(ResourceLimitError):
            reader.read(member)


# --- inside other formats ---------------------------------------------------------------


def test_a_tar_inside_the_codec_is_detected(toy: ArchiveFormat) -> None:
    data = toy_compress(_tar({"a.txt": b"alpha", "b.txt": _TEXT}))
    info = detect_format(io.BytesIO(data))
    assert info.format == TAR_TOY
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.format == TAR_TOY
        assert [m.name for m in reader.members()] == ["a.txt", "b.txt"]
        assert reader.read(reader.members()[1]) == _TEXT


def test_the_tar_pair_has_its_extension(toy: ArchiveFormat, tmp_path: Path) -> None:
    path = tmp_path / "x.tar.toy"
    path.write_bytes(toy_compress(_tar({"a.txt": b"alpha"})))
    assert detect_format(path).format == TAR_TOY
    with open_archive(path, streaming=True) as reader:
        assert [m.name for m, _ in reader.stream_members()] == ["a.txt"]


@pytest.mark.parametrize(
    "codec_first", [True, False], ids=["codec-first", "plugin-first"]
)
def test_a_sequential_plugin_reads_inside_the_codec(
    codec_first: bool, tmp_path: Path
) -> None:
    # Whichever is registered first, the pair exists: the tables are made when asked.
    with registration_scope():
        if codec_first:
            register_codec(ToyHandler)
            register_format(ToysHandler)
        else:
            register_format(ToysHandler)
            register_codec(ToyHandler)
        pair = ArchiveFormat(ToysHandler.format.container, ToyStream.TOY)
        path = tmp_path / "a.toys.toy"
        path.write_bytes(toy_compress(build_toys(_ENTRIES)))
        assert detect_format(path).format == pair
        # Found by the inner probe too, without the name.
        assert detect_format(io.BytesIO(path.read_bytes())).format == pair
        with open_archive(path) as reader:
            assert reader.format == pair
            files = {
                m.name: reader.read(m)
                for m in reader.members()
                if m.type is MemberType.FILE
            }
        assert files == {
            name: data for name, kind, data in _ENTRIES if kind is MemberType.FILE
        }
        assert pair in list_supported_formats()


def test_forward_stream_decompress_takes_the_codec(
    toy: ArchiveFormat, tmp_path: Path
) -> None:
    """A sequential plugin hands the rest of its archive to a registered codec."""

    class ToyRpmishReader(_RpmishReader):
        stream_formats = ToyStream

    with registration_scope():
        rpmish = _variant(ToyRpmishReader, ToysContainer.RPMISH)
        path = tmp_path / "a.toys"
        path.write_bytes(build_rpmish(ToyStream.TOY, toy_compress))
        with open_archive(path, format=rpmish) as reader:
            assert [m.name for m in reader.members()] == _RPM_NAMES
            assert reader.read("b.bin") == _DATA["b.bin"]
            assert reader.read("docs/a.txt") == b"alpha\n"


def test_reader_context_decompress_takes_the_codec(
    toy: ArchiveFormat, tmp_path: Path
) -> None:
    plain = b"plugin member data " * 200
    with registration_scope():
        register_format(_compressed_plugin(ToyStream.TOY))
        path = _compressed_archive(tmp_path, toy_compress(plain), plain)
        with open_archive(path) as reader:
            assert reader.read(reader.members()[0]) == plain


# --- the registry -----------------------------------------------------------------------


def test_the_formats_are_listed_and_available(toy: ArchiveFormat) -> None:
    supported = list_supported_formats()
    assert TOY in supported
    assert TAR_TOY in supported
    assert format_availability(TOY).support is FormatSupport.FULL
    assert format_availability("toy").format == TOY


class _NeedsMissingModule(ToyHandler):
    requires = ("archivey_no_such_module",)
    install_hint = "pip install archivey-no-such-module"


def test_a_missing_module_makes_the_formats_unavailable() -> None:
    with registration_scope():
        register_codec(_NeedsMissingModule)
        availability = format_availability(TOY)
        assert availability.support is FormatSupport.NONE
        (missing,) = availability.missing
        assert missing.name == "archivey_no_such_module"
        assert missing.install_hint == "pip install archivey-no-such-module"
        assert format_availability(TAR_TOY).support is FormatSupport.NONE
        assert TOY not in list_supported_formats()
        with pytest.raises(PackageNotInstalledError, match="archivey-no-such-module"):
            open_archive(io.BytesIO(toy_compress(b"x")), format=TOY)


def test_plugins_false_turns_the_codec_off(toy: ArchiveFormat) -> None:
    config = ArchiveyConfig(formats=FormatPolicy(plugins=False))
    with pytest.raises(ArchiveyError):
        open_archive(io.BytesIO(toy_compress(b"x")), format=TOY, config=config)
    excluded = ArchiveyConfig(formats=FormatPolicy(exclude={ToyStream.TOY}))
    with pytest.raises(ArchiveyError):
        open_archive(io.BytesIO(toy_compress(b"x")), format=TOY, config=excluded)


class _Builtin(ToyHandler):
    stream_format = StreamFormat.GZIP  # type: ignore[assignment]


class _GzValue(PluginStream):
    GZ = "gz"


class _BuiltinValue(ToyHandler):
    stream_format = _GzValue.GZ


class _OtherToy(PluginStream):
    TOY = "toy"


class _SameValue(ToyHandler):
    stream_format = _OtherToy.TOY


class _TarExtension(PluginStream):
    TGZ2 = "tgz2"


class _ClaimedAlias(ToyHandler):
    stream_format = _TarExtension.TGZ2
    extension_aliases = (".gz",)


class _BadValues(PluginStream):
    EMPTY = ""
    DOTTED = "a.b"
    SLASHED = "a/b"


def _with_value(value: PluginStream) -> type[CodecHandler]:
    return type("BadValue", (ToyHandler,), {"stream_format": value})


class _DottedAlias(ToyHandler):
    stream_format = _TarExtension.TGZ2
    extension_aliases = (".x.y",)


@pytest.mark.parametrize(
    ("handler", "match"),
    [
        (_with_value(_BadValues.EMPTY), "extension '.' must be"),
        (_with_value(_BadValues.DOTTED), "extension '.a.b' must be"),
        (_with_value(_BadValues.SLASHED), "extension '.a/b' must be"),
        (_DottedAlias, "extension '.x.y' must be"),
        (_Builtin, "must be a PluginStream member"),
        (_BuiltinValue, "is a built-in format's"),
        (_ClaimedAlias, "already claimed"),
        (object, "takes a CodecHandler subclass"),
    ],
)
def test_registration_refuses(handler: type, match: str) -> None:
    with registration_scope(), pytest.raises(ArchiveyUsageError, match=match):
        register_codec(handler)


def test_a_value_is_registered_once() -> None:
    with registration_scope():
        register_codec(ToyHandler)
        with pytest.raises(ArchiveyUsageError, match="already used"):
            register_codec(_SameValue)


def test_a_scope_removes_the_codec(tmp_path: Path) -> None:
    with registration_scope():
        register_codec(ToyHandler)
    assert TOY not in list_supported_formats()
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(toy_compress(b"x")))
