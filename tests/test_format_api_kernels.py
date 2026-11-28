"""``ReaderContext.kernel`` and ``CodecCall.kernel``: a plugin asks for one of
archivey-speedups' kernels by name. It gets the kernel when it can run, and ``None``
when it can't, so the plugin falls back to its own Python decoder. archivey gives back
the decoder child of every kernel object it handed out when the stream or the reader
closes."""

from __future__ import annotations

import io
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest

from archivey import (
    ArchiveyConfig,
    ArchiveyUsageError,
    FormatPolicy,
    MemberType,
    open_archive,
    open_stream,
)
from archivey.formats import (
    CodecCall,
    ReaderContext,
    ReaderSource,
    register_codec,
    register_format,
)
from archivey.internal import kernels
from archivey.internal.format_adapter import registration_scope
from archivey.internal.streams.codecs import deps
from archivey.types import OptionalLibrary
from tests.test_codec_api import TOY, ToyDecompressor, ToyHandler
from tests.test_format_api import ToyHandler as ToyaHandler, ToyReader, build_toya

_NAMES = ("crc16_arc", "lzfse", "lzo1x", "lzvn", "lzw", "lzx")
_OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-speedups"}))


class _AskingReader(ToyReader):
    """A TOYA reader that asks for each kernel at open."""

    asked: ClassVar[dict[str, object]] = {}

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        _AskingReader.asked = {name: context.kernel(name) for name in _NAMES}  # type: ignore[call-overload]


class _AskingToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _AskingReader(source, context)


class _AskingToyHandler(ToyHandler):
    asked: ClassVar[dict[str, object]] = {}

    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        _AskingToyHandler.asked = {name: call.kernel(name) for name in _NAMES}  # type: ignore[call-overload]
        return super().decompressor(call)


def _toya(tmp_path: Path) -> Path:
    path = tmp_path / "a.toya"
    path.write_bytes(build_toya([("a.txt", MemberType.FILE, b"alpha\n")]))
    return path


def _toy_stream() -> bytes:
    payload = b"hello"
    return (
        b"TOY1"
        + bytes([len(payload)])
        + payload
        + b"\x00"
        + zlib.crc32(payload).to_bytes(4, "big")
    )


@pytest.fixture
def plugins() -> Iterator[None]:
    with registration_scope():
        register_codec(_AskingToyHandler)
        register_format(_AskingToyaHandler)
        yield


@pytest.mark.parametrize("config", [None, _OFF], ids=["default", "speedups-off"])
def test_a_reader_gets_a_kernel_only_when_it_can_run(
    plugins: None, tmp_path: Path, config: ArchiveyConfig | None
) -> None:
    with open_archive(_toya(tmp_path), config=config) as archive:
        archive.members()
    runs = config is None and deps.archivey_speedups.available()
    for name, got in _AskingReader.asked.items():
        assert (got is not None) is runs, name
        assert got is None or callable(got)


@pytest.mark.parametrize("config", [None, _OFF], ids=["default", "speedups-off"])
def test_a_codec_gets_a_kernel_only_when_it_can_run(
    plugins: None, config: ArchiveyConfig | None
) -> None:
    with open_stream(io.BytesIO(_toy_stream()), format=TOY, config=config) as stream:
        assert stream.read() == b"hello"
    runs = config is None and deps.archivey_speedups.available()
    for name, got in _AskingToyHandler.asked.items():
        assert (got is not None) is runs, name


def test_an_unknown_kernel_name_is_a_usage_error() -> None:
    call = CodecCall()
    with pytest.raises(ArchiveyUsageError, match="'bcj2'"):
        call.kernel("bcj2")  # type: ignore[call-overload]


# --- giving back the decoder children ---------------------------------------------------


class _FakeChild:
    """A kernel object in a decoder child, as archivey's proxies mark it."""

    holds_decoder_child = True
    made: ClassVar[list[_FakeChild]] = []

    def __init__(self, **_: Any) -> None:
        self.closed = 0
        _FakeChild.made.append(self)

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def fake_lzw(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _FakeChild.made = []
    monkeypatch.setattr(
        kernels,
        "lzw",
        lambda excluded, *, isolated: kernels.Lzw(
            Decompressor=_FakeChild,  # type: ignore[arg-type]
            library=OptionalLibrary.ARCHIVEY_SPEEDUPS,
        ),
    )
    yield


class _LzwToyHandler(ToyHandler):
    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        make = call.kernel("lzw")
        assert make is not None
        make()
        return super().decompressor(call)


class _LzwReader(ToyReader):
    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        make = context.kernel("lzw")
        assert make is not None
        make()


class _LzwToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _LzwReader(source, context)


def test_closing_a_stream_gives_back_its_codecs_kernel_children(
    fake_lzw: None,
) -> None:
    with registration_scope():
        register_codec(_LzwToyHandler)
        with open_stream(io.BytesIO(_toy_stream()), format=TOY) as stream:
            assert stream.read() == b"hello"
            assert [c.closed for c in _FakeChild.made] == [0]
    assert [c.closed for c in _FakeChild.made] == [1]


def test_closing_a_reader_gives_back_its_kernel_children(
    fake_lzw: None, tmp_path: Path
) -> None:
    with registration_scope():
        register_format(_LzwToyaHandler)
        with open_archive(_toya(tmp_path)) as archive:
            archive.members()
            assert [c.closed for c in _FakeChild.made] == [0]
    assert [c.closed for c in _FakeChild.made] == [1]


def test_a_kernel_object_not_in_a_child_is_not_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class InProcess(_FakeChild):
        holds_decoder_child = False

    _FakeChild.made = []
    monkeypatch.setattr(
        kernels,
        "lzw",
        lambda excluded, *, isolated: kernels.Lzw(
            Decompressor=InProcess,  # type: ignore[arg-type]
            library=OptionalLibrary.ARCHIVEY_SPEEDUPS,
        ),
    )
    with registration_scope():
        register_format(_LzwToyaHandler)
        with open_archive(_toya(tmp_path)) as archive:
            archive.members()
    assert [c.closed for c in _FakeChild.made] == [0]


def test_the_kernel_types_are_public() -> None:
    import archivey.kernels as public

    for name in (
        "BlockDecompress",
        "Crc16",
        "KernelName",
        "LzwDecompressor",
        "LzwFactory",
        "LzxDecompressor",
        "LzxFactory",
    ):
        assert hasattr(public, name), name
