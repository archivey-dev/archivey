"""``ReaderContext.speedup`` and ``CodecCall.speedup``: a plugin asks for one of
archivey-speedups' kernels by name. It gets the kernel when it can run, and ``None``
when it can't, so the plugin falls back to its own Python decoder. archivey gives back
the decoder child of every kernel object it handed out when the stream or the reader
closes."""

from __future__ import annotations

import dataclasses
import io
import pickle
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar, get_args, get_type_hints

import pytest

from archivey import (
    ArchiveyConfig,
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    FormatPolicy,
    MemberType,
    TruncatedError,
    open_archive,
    open_stream,
)
from archivey.config import ProcessIsolation
from archivey.formats import (
    CodecCall,
    Magic,
    ReaderContext,
    ReaderSource,
    register_codec,
    register_format,
)
from archivey.internal import kernels
from archivey.internal.format_adapter import registration_scope
from archivey.internal.streams.codecs import deps
from archivey.speedups import SpeedupName
from archivey.types import OptionalLibrary
from tests.conftest import importorskip
from tests.test_codec_api import TOY, ToyDecompressor, ToyHandler
from tests.test_format_api import ToyHandler as ToyaHandler, ToyReader, build_toya

_NAMES: tuple[SpeedupName, ...] = get_args(SpeedupName)
_OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-speedups"}))


class _AskingReader(ToyReader):
    """A TOYA reader that asks for each kernel at open."""

    asked: ClassVar[dict[str, object]] = {}

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        _AskingReader.asked = {name: context.speedup(name) for name in _NAMES}


class _AskingToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _AskingReader(source, context)


class _AskingToyHandler(ToyHandler):
    asked: ClassVar[dict[str, object]] = {}

    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        _AskingToyHandler.asked = {name: call.speedup(name) for name in _NAMES}
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
        # A name that is not a kernel, on purpose.
        call.speedup("bcj2")  # pyrefly: ignore[no-matching-overload]  # ty: ignore[no-matching-overload]


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
        make = call.speedup("lzw")
        assert make is not None
        make()
        return super().decompressor(call)


class _LzwReader(ToyReader):
    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        make = context.speedup("lzw")
        assert make is not None
        make()


class _LzwToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _LzwReader(source, context)


_ISOLATED = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)


@pytest.fixture
def isolation_seen(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Each ``isolated`` a plugin's ``speedup("lzw")`` passed on."""
    seen: list[bool] = []

    def lzw(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> kernels.Lzw:
        seen.append(isolated)
        return kernels.Lzw(
            Decompressor=_FakeChild,  # type: ignore[arg-type]
            library=OptionalLibrary.ARCHIVEY_SPEEDUPS,
        )

    monkeypatch.setattr(kernels, "lzw", lzw)
    return seen


@pytest.mark.parametrize(
    ("config", "isolated"),
    [(None, False), (_ISOLATED, True)],
    ids=["default", "native"],
)
def test_a_readers_kernel_follows_the_callers_isolation(
    isolation_seen: list[bool],
    tmp_path: Path,
    config: ArchiveyConfig | None,
    isolated: bool,
) -> None:
    with registration_scope():
        register_format(_LzwToyaHandler)
        with open_archive(_toya(tmp_path), config=config) as archive:
            archive.members()
    assert isolation_seen == [isolated]


@pytest.mark.parametrize(
    ("config", "isolated"),
    [(None, False), (_ISOLATED, True)],
    ids=["default", "native"],
)
def test_a_codecs_kernel_follows_the_callers_isolation(
    isolation_seen: list[bool], config: ArchiveyConfig | None, isolated: bool
) -> None:
    with registration_scope():
        register_codec(_LzwToyHandler)
        with open_stream(
            io.BytesIO(_toy_stream()), format=TOY, config=config
        ) as stream:
            assert stream.read() == b"hello"
    assert isolation_seen == [isolated]


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


def test_the_kernel_types_are_public() -> None:
    import archivey.speedups as public

    for name in (
        "BlockDecompress",
        "Crc16",
        "SpeedupName",
        "LzwDecompressor",
        "LzwFactory",
        "LzxDecompressor",
        "LzxFactory",
    ):
        assert hasattr(public, name), name


# --- review round (Codex): ownership per decoder, setup failures, CRC, the record ---


class _Equal(ToyDecompressor):
    """A decoder wrapper with value equality: every one equals every other."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Equal)

    def __hash__(self) -> int:
        return 0


class _Unhashable(ToyDecompressor):
    __hash__ = None  # type: ignore[assignment]


class _EqualToyHandler(ToyHandler):
    made: ClassVar[type[ToyDecompressor]] = _Equal

    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        make = call.speedup("lzw")
        assert make is not None
        make()
        return type(self).made()


def test_two_equal_decoders_give_back_only_their_own_children(fake_lzw: None) -> None:
    with registration_scope():
        register_codec(_EqualToyHandler)
        first = open_stream(io.BytesIO(_toy_stream()), format=TOY)
        second = open_stream(io.BytesIO(_toy_stream()), format=TOY)
        assert first.read() == second.read() == b"hello"
        first.close()
        assert [c.closed for c in _FakeChild.made] == [1, 0]
        second.close()
    assert [c.closed for c in _FakeChild.made] == [1, 1]


def test_an_unhashable_decoder_gives_back_its_children(
    fake_lzw: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_EqualToyHandler, "made", _Unhashable)
    with registration_scope():
        register_codec(_EqualToyHandler)
        with open_stream(io.BytesIO(_toy_stream()), format=TOY) as stream:
            assert stream.read() == b"hello"
    assert [c.closed for c in _FakeChild.made] == [1]


class _SetupError(Exception):
    pass


class _FailingToyHandler(ToyHandler):
    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        make = call.speedup("lzw")
        assert make is not None
        make()
        raise _SetupError("bad header")

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, _SetupError):
            return CorruptionError(str(exc))
        return None


def test_a_codec_whose_setup_fails_gives_back_its_children(fake_lzw: None) -> None:
    with registration_scope():
        register_codec(_FailingToyHandler)
        with (
            pytest.raises(ArchiveyError) as raised,
            open_stream(io.BytesIO(_toy_stream()), format=TOY) as stream,
        ):
            stream.read()
        # The traceback still holds the call; the children are back all the same.
        assert raised.value is not None
        assert _FakeChild.made
        assert all(c.closed == 1 for c in _FakeChild.made)


class _FailingReader(ToyReader):
    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        make = context.speedup("lzw")
        assert make is not None
        make()
        raise CorruptionError("bad header")


class _FailingToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _FailingReader(source, context)


def test_a_reader_whose_open_fails_gives_back_its_children(
    fake_lzw: None, tmp_path: Path
) -> None:
    with registration_scope():
        register_format(_FailingToyaHandler)
        with pytest.raises(CorruptionError) as raised:
            open_archive(_toya(tmp_path))
        assert raised.value is not None
        assert [c.closed for c in _FakeChild.made] == [1]


def test_crc16_runs_in_process_when_no_decoder_child_can_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A checksum runs in this process under every isolation setting, so
    ``"crc16_arc"`` is handed out under ``NATIVE_DECODERS`` while the decoders,
    with no decoder child to run them, are not."""

    def crc(data: bytes, value: int = 0, /) -> int:
        return value

    monkeypatch.setattr(kernels, "kernels", lambda name, excluded: True)
    monkeypatch.setattr(kernels, "crc16_arc", lambda excluded: crc)
    monkeypatch.setattr(kernels, "decoding_kernels", lambda *a, **k: None)
    with registration_scope():
        register_codec(_AskingToyHandler)
        register_format(_AskingToyaHandler)
        with open_archive(_toya(tmp_path), config=_ISOLATED) as archive:
            archive.members()
        with open_stream(
            io.BytesIO(_toy_stream()), format=TOY, config=_ISOLATED
        ) as stream:
            assert stream.read() == b"hello"
    for asked in (_AskingReader.asked, _AskingToyHandler.asked):
        assert asked.pop("crc16_arc") is crc
        assert set(asked.values()) == {None}


def test_codec_call_stays_a_plain_record() -> None:
    call = CodecCall(size=5)
    assert pickle.loads(pickle.dumps(call)) == call
    # The documented fields only. archivey's state for ``speedup()`` is an init-only
    # argument, which ``dataclasses.replace`` still carries over.
    names = {"size", "properties", "limits", "probe_bound"}
    assert {f.name for f in dataclasses.fields(CodecCall)} == names
    assert set(dataclasses.asdict(call)) == names
    get_type_hints(CodecCall)


def test_a_stream_whose_setup_fails_closes_the_decoder_it_made() -> None:
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    class Source(io.BufferedReader):
        def seekable(self) -> bool:
            raise OSError("gone")

    closed: list[bool] = []

    class Decoder:
        def close(self) -> None:
            closed.append(True)

    with pytest.raises(OSError, match="gone"):
        DecompressorStream(
            Source(io.BytesIO(b"x")),
            make_decoder=lambda point, inner: Decoder(),  # type: ignore[arg-type,return-value]
        )
    assert closed == [True]


# A ``.Z`` stream of b"hello hello hello\n" (made with ncompress).
_DOT_Z = b"\x1f\x9d\x90h\xca\xb0a\xf3\x06D\xc0\x81\x05\x0f\x12T\x00"


class _LzwCodecDecompressor:
    """The adapter the plugin guide shows: an LZW speedup (or its Python twin) as a
    codec's decompressor, its ``flush()`` behind ``end_input()``."""

    def __init__(self, make: Any) -> None:
        self._lzw = make()
        self._ended = False

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if not self._ended:
            return self._lzw.decompress(data, max_length)
        out = self._lzw.flush(max_length)
        if not out and self._lzw.truncation is not None:
            raise EOFError(self._lzw.truncation)
        return out

    def end_input(self) -> None:
        self._ended = True

    @property
    def eof(self) -> bool:
        # A cut-short stream is not complete: the next call raises.
        return self._lzw.eof and self._lzw.truncation is None

    @property
    def needs_input(self) -> bool:
        return self._lzw.needs_input and not self._ended

    @property
    def unused_data(self) -> bytes:
        return self._lzw.unused_data


class _DotZHandler(ToyHandler):
    magic = (Magic(0, b"\x1f\x9d"),)
    checks_content = False

    def decompressor(self, call: CodecCall) -> _LzwCodecDecompressor:  # type: ignore[override]
        from archivey.internal.kernels.python import lzw as twin

        return _LzwCodecDecompressor(call.speedup("lzw") or twin.Decompressor)


def test_the_guides_lzw_adapter_reads_a_whole_stream() -> None:
    with registration_scope():
        register_codec(_DotZHandler)
        with open_stream(io.BytesIO(_DOT_Z), format=TOY) as stream:
            assert stream.read() == b"hello hello hello\n"


def test_a_childs_clear_offsets_is_a_fresh_list() -> None:
    from archivey.internal.kernels.child import ChildLzwDecompressor

    class Child:
        def __init__(self) -> None:
            self.report = {"clear_offsets": [(1, 2)]}

        def reported(self, name: str) -> object:
            return self.report[name]

    proxy = ChildLzwDecompressor(Child())  # type: ignore[arg-type]
    proxy.clear_offsets.append((3, 4))
    assert proxy.clear_offsets == [(1, 2)]


# --- review round 3 ---


class _CopyingToyHandler(ToyHandler):
    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        inner = dataclasses.replace(call, properties=call.properties)
        make = inner.speedup("lzw")
        assert make is not None
        make()
        return super().decompressor(call)


def test_a_copied_call_keeps_the_callers_isolation_and_lease(
    isolation_seen: list[bool],
) -> None:
    _FakeChild.made = []
    with registration_scope():
        register_codec(_CopyingToyHandler)
        with open_stream(
            io.BytesIO(_toy_stream()), format=TOY, config=_ISOLATED
        ) as stream:
            assert stream.read() == b"hello"
    assert isolation_seen == [True]
    assert [c.closed for c in _FakeChild.made] == [1]


class _ChildHolding(ToyDecompressor):
    holds_decoder_child = True
    closed = 0

    def close(self) -> None:
        type(self).closed += 1


class _ChildHoldingToyHandler(ToyHandler):
    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        return _ChildHolding()


def test_a_decompressor_holding_a_child_is_still_closed() -> None:
    _ChildHolding.closed = 0
    with registration_scope():
        register_codec(_ChildHoldingToyHandler)
        with open_stream(io.BytesIO(_toy_stream()), format=TOY) as stream:
            assert stream.read() == b"hello"
    assert _ChildHolding.closed == 1


def test_the_codec_wrapper_copies_without_recursing() -> None:
    import copy

    from archivey.internal.codec_adapter import LeasedDecompressor
    from archivey.internal.kernels import KernelLease

    wrapper = LeasedDecompressor(ToyDecompressor(), KernelLease())  # type: ignore[arg-type]
    copied = copy.copy(wrapper)
    assert copied.eof is False
    # The copy is a wrapper of the same decompressor, not one holding its state.
    assert copied._plugin is wrapper._plugin
    assert copied._lease is wrapper._lease


# --- review round 5 ---


def test_a_failed_setup_closes_its_source_when_the_decoder_close_fails() -> None:
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    closed: list[str] = []

    class Source(io.BufferedReader):
        def seekable(self) -> bool:
            raise OSError("gone")

        def close(self) -> None:
            closed.append("source")
            super().close()

    class Decoder:
        def close(self) -> None:
            closed.append("decoder")
            raise RuntimeError("decoder close failed")

    source = Source(io.BytesIO(b"x"))  # held, so no finalizer closes it instead
    with pytest.raises(OSError, match="gone"):
        DecompressorStream(
            source,
            make_decoder=lambda point, inner: Decoder(),  # type: ignore[arg-type,return-value]
            owns_inner=True,
        )
    assert closed == ["decoder", "source"]


@pytest.mark.parametrize("cut", [2, len(_DOT_Z) - 1], ids=["header", "last-code"])
def test_the_guides_lzw_adapter_reports_a_truncated_stream(cut: int) -> None:
    with registration_scope():
        register_codec(_DotZHandler)
        with (
            open_stream(io.BytesIO(_DOT_Z[:cut]), format=TOY) as stream,
            pytest.raises(TruncatedError),
        ):
            stream.read()


def test_the_guides_lzw_adapter_keeps_the_output_before_a_truncation() -> None:
    with registration_scope():
        register_codec(_DotZHandler)
        with open_stream(io.BytesIO(_DOT_Z[:-1]), format=TOY) as stream:
            assert stream.read(17) == b"hello hello hello"
            with pytest.raises(TruncatedError):
                stream.read()


class _CapturingToyHandler(ToyHandler):
    calls: ClassVar[list[CodecCall]] = []

    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        type(self).calls.append(call)
        return super().decompressor(call)


def test_a_real_call_converts_to_json() -> None:
    import json

    _CapturingToyHandler.calls = []
    with registration_scope():
        register_codec(_CapturingToyHandler)
        with open_stream(io.BytesIO(_toy_stream()), format=TOY) as stream:
            assert stream.read() == b"hello"
    (call,) = _CapturingToyHandler.calls[-1:]
    as_dict = dataclasses.asdict(call)
    assert set(as_dict) == {"size", "properties", "limits", "probe_bound"}
    json.dumps(as_dict)


# --- review round (Fable, cold): real speedup objects, the reader's lease ------------

_HALF = 8  # bytes of _DOT_Z decoded before the stream or reader closes
_ISOLATION = pytest.mark.parametrize(
    "config", [None, _ISOLATED], ids=["in-process", "native"]
)


def _after_close(decoder: Any, config: ArchiveyConfig | None) -> None:
    """A real object closed by archivey: in this process closing does nothing, so it
    decodes the rest; in a decoder child it refuses, its child given back."""
    if config is None:
        assert (
            decoder.decompress(_DOT_Z[_HALF:]) + decoder.flush() == b"o hello hello\n"
        )
    else:
        with pytest.raises(ArchiveyUsageError, match="closed"):
            decoder.decompress(_DOT_Z[_HALF:])


class _RealLzwReader(ToyReader):
    made: ClassVar[list[Any]] = []

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        super().__init__(source, context)
        make = context.speedup("lzw")
        assert make is not None
        decoder = make()
        assert decoder.decompress(_DOT_Z[:_HALF]) == b"hell"
        _RealLzwReader.made.append(decoder)


class _RealLzwToyaHandler(ToyaHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
        return _RealLzwReader(source, context)


class _RealLzwToyHandler(ToyHandler):
    made: ClassVar[list[Any]] = []

    def decompressor(self, call: CodecCall) -> ToyDecompressor:
        make = call.speedup("lzw")
        assert make is not None
        decoder = make()
        assert decoder.decompress(_DOT_Z[:_HALF]) == b"hell"
        _RealLzwToyHandler.made.append(decoder)
        return super().decompressor(call)


@_ISOLATION
def test_a_readers_real_speedup_is_closed_with_the_reader(
    tmp_path: Path, config: ArchiveyConfig | None
) -> None:
    importorskip("archivey_speedups")
    _RealLzwReader.made = []
    with registration_scope():
        register_format(_RealLzwToyaHandler)
        with open_archive(_toya(tmp_path), config=config) as archive:
            archive.members()
    (decoder,) = _RealLzwReader.made
    _after_close(decoder, config)


@_ISOLATION
def test_a_codecs_real_speedup_is_closed_with_the_stream(
    config: ArchiveyConfig | None,
) -> None:
    importorskip("archivey_speedups")
    _RealLzwToyHandler.made = []
    with registration_scope():
        register_codec(_RealLzwToyHandler)
        with open_stream(
            io.BytesIO(_toy_stream()), format=TOY, config=config
        ) as stream:
            assert stream.read() == b"hello"
    (decoder,) = _RealLzwToyHandler.made
    _after_close(decoder, config)


@_ISOLATION
def test_the_guides_lzw_adapter_decodes_as_the_twin_does_with_a_real_speedup(
    config: ArchiveyConfig | None,
) -> None:
    importorskip("archivey_speedups")

    class Handler(_DotZHandler):
        def decompressor(self, call: CodecCall) -> _LzwCodecDecompressor:  # type: ignore[override]
            make = call.speedup("lzw")
            assert make is not None
            return _LzwCodecDecompressor(make)

    with registration_scope():
        register_codec(Handler)
        with open_stream(io.BytesIO(_DOT_Z), format=TOY, config=config) as stream:
            assert stream.read() == b"hello hello hello\n"
        with (
            open_stream(io.BytesIO(_DOT_Z[:-1]), format=TOY, config=config) as stream,
            pytest.raises(TruncatedError),
        ):
            stream.read()


def test_a_readers_first_speedup_calls_share_one_lease(
    monkeypatch: pytest.MonkeyPatch, fake_lzw: None, tmp_path: Path
) -> None:
    import threading

    # Two threads that ask at once both see no lease yet if it is made on first use;
    # the barrier holds each in the lease's constructor until the other arrives.
    barrier = threading.Barrier(2, timeout=1)

    class Racing(kernels.KernelLease):
        def __init__(self) -> None:
            super().__init__()
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass

    monkeypatch.setattr(kernels, "KernelLease", Racing)

    class Reader(ToyReader):
        def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
            super().__init__(source, context)

            def ask() -> None:
                make = context.speedup("lzw")
                assert make is not None
                _keep.append(make())

            threads = [threading.Thread(target=ask) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

    class Handler(ToyaHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
            return Reader(source, context)

    _keep: list[Any] = []
    with registration_scope():
        register_format(Handler)
        with open_archive(_toya(tmp_path)) as archive:
            archive.members()
    assert [c.closed for c in _FakeChild.made] == [1, 1]


def test_the_stateful_speedups_and_their_twins_have_close() -> None:
    from archivey.internal.kernels.python import lzw as lzw_twin, lzx as lzx_twin
    from archivey.speedups import LzwDecompressor, LzxDecompressor

    assert "close" in LzwDecompressor.__dict__
    assert "close" in LzxDecompressor.__dict__
    # A plugin's own twin needs no child, so its close does nothing.
    for twin in (lzw_twin.Decompressor(), lzx_twin.Decompressor(16, output_size=1)):
        twin.close()
        twin.close()


@_ISOLATION
def test_a_reader_closes_its_real_speedup_early(
    tmp_path: Path, config: ArchiveyConfig | None
) -> None:
    """A reader done with a member closes its decoder there, so a child per member is
    not held until the reader closes; archivey's close at the end is then harmless."""
    importorskip("archivey_speedups")
    closed_early: list[Any] = []

    class Reader(ToyReader):
        def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
            super().__init__(source, context)
            make = context.speedup("lzw")
            assert make is not None
            decoder = make()
            assert decoder.decompress(_DOT_Z) + decoder.flush() == (
                b"hello hello hello\n"
            )
            decoder.close()
            closed_early.append(decoder)

    class Handler(ToyaHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyReader:
            return Reader(source, context)

    with registration_scope():
        register_format(Handler)
        with open_archive(_toya(tmp_path), config=config) as archive:
            (decoder,) = closed_early
            if config is not None:
                # Its child is given back now, while the reader is still open.
                with pytest.raises(ArchiveyUsageError, match="closed"):
                    decoder.decompress(b"")
            archive.members()
