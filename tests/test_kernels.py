"""archivey-codecs kernels: when archivey uses one, and that the result is the same.

The selection rows (design D4, D5) run with a fake package, so they need nothing
installed. The read tests use the real package and skip without it.
"""

from __future__ import annotations

import gc
import inspect
import io
import logging
import random
import struct
import traceback
import types
import weakref
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, NoReturn

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    FormatPolicy,
    OptionalLibrary,
    ProcessIsolation,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
    open_archive,
    open_stream,
)
from archivey.internal import kernels
from archivey.internal.backends import lha_reader, zipcrypto
from archivey.internal.kernels import _select, child as kernel_child, rust
from archivey.internal.kernels.python import (
    filters as filters_twin,
    lzw as lzw_twin,
    zipcrypto as zipcrypto_twin,
)
from archivey.internal.streams.codecs import decoder_child, decoder_worker, deps
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64
from archivey.internal.streams.codecs.bcj2_filter import (
    _BLOCK as _BCJ2_BLOCK,
    Bcj2DecoderStream,
)
from archivey.internal.streams.codecs.decoder_child import (
    DecoderChildStartError,
    rebuild_error,
)
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
from archivey.internal.streams.codecs.lzfse_decoder import (
    decoder,
    lzfse_decompress,
    lzvn_decompress,
)
from archivey.internal.streams.codecs.lzma_filter_decoder import (
    branch_maker,
)
from archivey.internal.streams.codecs.lzo_decoder import (
    LzoError,
    lzo1x_decompress_python,
    lzo1x_decompressor,
)
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV
from archivey.internal.streams.codecs.unix_compress_decoder import (
    UnixCompressDecoder,
)
from tests.bcj2_util import bcj2_encode
from tests.cab_util import CabFile, CabFolder, LzxEncoder, write_cab
from tests.conftest import CPYTHON, requires
from tests.lha_util import Member, archive
from tests.streams_util import make_unix_compress
from tests.zipcrypto import build_stored_zipcrypto_zip, build_zipcrypto_zip

EXCLUDED = frozenset({OptionalLibrary.ARCHIVEY_CODECS})
TWIN_BRANCHES = (filters_twin.Arm64Decoder, filters_twin.RiscvDecoder)
OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-codecs"}))
DMG_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"
RISCV_7Z = Path(__file__).parent / "fixtures" / "sevenzip" / "riscv_lzma2.7z"
# 12 000 lines of text in lzop blocks, as tests/fixtures/external/lzop/README says.
LZOP_TEXT = Path(__file__).parent / "fixtures" / "external" / "lzop" / "text.txt.lzo"
# Python's LZO1X decoder: compress-utils, tried after archivey-codecs, is off too.
PYTHON_LZO = ArchiveyConfig(
    formats=FormatPolicy(exclude_libraries={"archivey-codecs", "compress_utils"})
)
LZOP_DATA = b"".join(b"line %d of the lzop fixture\n" % i for i in range(12000))


class PanicException(BaseException):
    """Stands in for PyO3's ``pyo3_runtime.PanicException``."""


PanicException.__module__ = "pyo3_runtime"


class _FakeDecryptor:
    """Stands in for ``archivey_codecs.zipcrypto.Decryptor``: Python's keys, recorded.

    With ``panic`` set, decrypting member data (anything but the 12-byte header)
    raises the fake panic; with ``panic_header`` set, decrypting the header does.
    ``calls`` counts ``decrypt`` and ``copy`` calls.
    """

    built: ClassVar[list[bytes]] = []
    panic: ClassVar[bool] = False
    panic_header: ClassVar[bool] = False
    calls: ClassVar[int] = 0

    def __init__(self, password: bytes, keys: zipcrypto_twin.Decryptor | None = None):
        if keys is None:
            type(self).built.append(password)
            keys = zipcrypto_twin.Decryptor(password)
        self._password = password
        self._keys = keys

    def copy(self) -> _FakeDecryptor:
        type(self).calls += 1
        return _FakeDecryptor(self._password, self._keys.copy())

    def decrypt(self, data: bytes) -> bytes:
        type(self).calls += 1
        header = len(data) == zipcrypto.ZIPCRYPTO_HEADER_LEN
        if self.panic_header if header else self.panic:
            raise PanicException("index out of bounds")
        return self._keys.decrypt(data)


class _FakeBranch:
    """Stands in for ``archivey_codecs.filters.Arm64Decoder`` and ``RiscvDecoder``:
    the Python filter, recorded. With ``panic`` set, decoding raises the fake panic."""

    built: ClassVar[list[int]] = []
    panic: ClassVar[bool] = False
    calls: ClassVar[int] = 0

    def __init__(self, start_offset: int = 0) -> None:
        type(self).built.append(start_offset)
        self._python = self.twin(start_offset)

    twin: ClassVar[type] = filters_twin.Arm64Decoder

    def decode(self, data: bytes) -> bytes:
        type(self).calls += 1
        if self.panic:
            raise PanicException("attempt to subtract with overflow")
        return self._python.decode(data)

    def flush(self) -> bytes:
        type(self).calls += 1
        return self._python.flush()


class _FakeArm64(_FakeBranch):
    twin = filters_twin.Arm64Decoder


class _FakeRiscv(_FakeBranch):
    twin = filters_twin.RiscvDecoder


class _FakeLzw:
    """Stands in for ``archivey_codecs.lzw.Decompressor``: records that it was built,
    and panics on the first ``decompress``."""

    built: ClassVar[int] = 0
    needs_input = True
    eof = False
    header_params = None
    nine_bit_widens = None
    truncation = None
    clear_offsets: ClassVar[list[tuple[int, int]]] = []

    def __init__(self, **kwargs: object) -> None:
        type(self).built += 1

    calls: ClassVar[int] = 0

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        type(self).calls += 1
        raise PanicException("index out of bounds")

    def flush(self, max_length: int = -1) -> bytes:
        type(self).calls += 1
        return b""


class _FakeLzo1x:
    """Stands in for ``archivey_codecs.lzo1x``: Python's decoder, with the kernel's
    ``max_size`` contract, recorded. With ``panic`` set, decoding raises the fake
    panic."""

    calls: ClassVar[list[int]] = []
    panic: ClassVar[bool] = False
    error: ClassVar[type[Exception]] = ValueError

    @classmethod
    def decompress(cls, data: bytes, *, max_size: int) -> bytes:
        cls.calls.append(max_size)
        if cls.panic:
            raise PanicException("slice index out of range")
        try:
            return lzo1x_decompress_python(data, max_size)
        except LzoError as exc:
            raise cls.error(str(exc)) from None


def _fake(monkeypatch: pytest.MonkeyPatch, **kernels: int) -> types.SimpleNamespace:
    """Install a fake ``archivey_codecs`` whose ``KERNELS`` is ``kernels``."""

    def crc16_arc(data: bytes, value: int = 0) -> int:
        raise PanicException("index out of bounds")

    monkeypatch.setattr(_FakeDecryptor, "built", [])
    monkeypatch.setattr(_FakeDecryptor, "panic", False)
    monkeypatch.setattr(_FakeBranch, "built", [])
    monkeypatch.setattr(_FakeBranch, "panic", False)
    monkeypatch.setattr(_FakeLzw, "built", 0)
    monkeypatch.setattr(_FakeLzw, "calls", 0)
    monkeypatch.setattr(_FakeBranch, "calls", 0)
    monkeypatch.setattr(_FakeDecryptor, "panic_header", False)
    monkeypatch.setattr(_FakeDecryptor, "calls", 0)
    monkeypatch.setattr(_FakeLzo1x, "calls", [])
    monkeypatch.setattr(_FakeLzo1x, "panic", False)
    codec_error = type("CodecError", (ValueError,), {})
    corrupt_error = type("CorruptDataError", (codec_error,), {})
    monkeypatch.setattr(_FakeLzo1x, "error", corrupt_error)
    module = types.SimpleNamespace(
        KERNELS=kernels,
        crc16_arc=crc16_arc,
        zipcrypto=types.SimpleNamespace(Decryptor=_FakeDecryptor),
        filters=types.SimpleNamespace(Arm64Decoder=_FakeArm64, RiscvDecoder=_FakeRiscv),
        lzw=types.SimpleNamespace(Decompressor=_FakeLzw),
        lzo1x=_FakeLzo1x,
        CodecError=codec_error,
        TruncatedDataError=type("TruncatedDataError", (ValueError,), {}),
        CorruptDataError=corrupt_error,
        UnsupportedDataError=type("UnsupportedDataError", (ValueError,), {}),
    )
    package = deps.LazyOptional(OptionalLibrary.ARCHIVEY_CODECS, present=True)
    package._module = module  # type: ignore[assignment]
    monkeypatch.setattr(deps, "archivey_codecs", package)
    monkeypatch.setattr(_select, "_too_old_logged", set())
    return module


def _child_kernels(monkeypatch: pytest.MonkeyPatch, module: object) -> list[frozenset]:
    """Make ``kernel_child.open_kernels``, the kernels run in a decoder child under
    ``NATIVE_DECODERS``, return ``module`` (``None``: no child can run them). Returns
    the ``excluded`` sets it was called with."""
    calls: list[frozenset] = []

    def open_kernels(excluded: frozenset) -> object:
        calls.append(excluded)
        return module

    monkeypatch.setattr(kernel_child, "open_kernels", open_kernels)
    return calls


# ── Selection ─────────────────────────────────────────────────────────────────────────


def test_an_absent_package_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        deps,
        "archivey_codecs",
        deps.LazyOptional(OptionalLibrary.ARCHIVEY_CODECS, present=False),
    )
    assert _select.kernels("crc16_arc", frozenset()) is None
    assert kernels.crc16_arc(frozenset()) is lha_reader.crc16


def test_an_excluded_package_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, crc16_arc=1)
    assert _select.kernels("crc16_arc", EXCLUDED) is None
    assert kernels.crc16_arc(EXCLUDED) is lha_reader.crc16


def test_a_current_kernel_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _fake(monkeypatch, crc16_arc=1, zipcrypto=2)
    assert _select.kernels("crc16_arc", frozenset()) is module
    assert _select.kernels("zipcrypto", frozenset()) is module  # newer is fine


@pytest.mark.parametrize("kernels", [{}, {"crc16_arc": 0}, {"crc16_arc": "1"}])
def test_an_old_or_missing_kernel_is_not_used_and_logged_once(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kernels: dict[str, object],
) -> None:
    _fake(monkeypatch, **kernels)  # type: ignore[arg-type]
    with caplog.at_level(logging.DEBUG, logger="archivey.streams"):
        assert _select.kernels("crc16_arc", frozenset()) is None
        assert _select.kernels("crc16_arc", frozenset()) is None
    logged = [r for r in caplog.records if "'crc16_arc' kernel revision" in r.message]
    assert len(logged) == 1
    assert "needs 1 or newer" in logged[0].message


def test_a_panic_reaches_the_caller_as_corruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, crc16_arc=1)
    crc = kernels.crc16_arc(frozenset())
    with pytest.raises(CorruptionError, match="CRC-16 decoder failed") as info:
        crc(b"abc", 0)
    assert isinstance(info.value.__cause__, PanicException)


def _assert_raised_again(again: BaseException, first: BaseException) -> None:
    """``again`` is ``first`` raised again by a latch: a new copy, never the kept
    instance, with its type, message and panic cause."""
    assert again is not first
    assert (type(again), str(again)) == (type(first), str(first))
    assert type(again.__cause__) is type(first.__cause__)
    assert kernels.caused_by_panic(again)


class _Latched:
    """A wrapper of a kernel object, as ``rust.py``'s, whose call panics."""

    def __init__(self, panic: type[BaseException]) -> None:
        self._latch = _select.Latch("lzw")
        self._panic = panic

    def call(self) -> None:
        with self._latch.guard():
            raise self._panic("index out of bounds")


@pytest.mark.parametrize(
    "panic",
    [PanicException, kernel_child.ChildPanic],
    ids=["in-process", "child"],
)
def test_a_latch_raises_a_fresh_copy_each_time(panic: type[BaseException]) -> None:
    """A latched failure is raised again as a new copy, still caused by the panic,
    and holds no frame: the wrapper goes with its last reference, with no garbage
    collection (``kept_errors``)."""
    wrapper = _Latched(panic)
    ref = weakref.ref(wrapper)
    raised: list[tuple[int, bool]] = []
    gc.disable()
    try:
        for _ in range(3):
            try:
                wrapper.call()
            except CorruptionError as exc:
                frames = len(list(traceback.walk_tb(exc.__traceback__)))
                raised.append((frames, kernels.caused_by_panic(exc)))
                del exc
        del wrapper
        if not CPYTHON:
            # PyPy frees nothing without a collection; the wrapper must still go
            # with one, so no raised copy keeps it alive.
            gc.collect()
        alive = ref() is not None
    finally:
        gc.enable()
    assert not alive
    assert all(by_panic for _, by_panic in raised)
    # A raise again does not add its frames to an earlier raise's traceback.
    assert raised[1][0] == raised[2][0]


class _NestedLatched:
    """A wrapper whose call raises a ``CorruptionError`` caused by another that a
    panic caused, as a BCJ2 input callback can."""

    def __init__(self) -> None:
        self._latch = _select.Latch("bcj2")

    def call(self) -> None:
        with self._latch.guard():
            try:
                raise kernel_child.ChildPanic("index out of bounds")
            except kernel_child.ChildPanic as panic:
                try:
                    raise CorruptionError("inner") from panic
                except CorruptionError as inner:
                    raise CorruptionError("outer") from inner


def test_a_latch_keeps_a_panic_deeper_in_the_chain() -> None:
    wrapper = _NestedLatched()
    for _ in range(3):
        with pytest.raises(CorruptionError, match="outer") as info:
            wrapper.call()
        assert kernels.caused_by_panic(info.value)


def test_a_panic_in_an_lha_read_is_corruption(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, crc16_arc=1)
    raw = archive([Member(b"a.txt", b"hello")])
    with pytest.raises(CorruptionError, match="CRC-16 decoder failed"):
        open_archive(io.BytesIO(raw), format=ArchiveFormat.LHA)
    # The switch turns the kernel off: the Python CRC reads the same archive.
    with open_archive(io.BytesIO(raw), format=ArchiveFormat.LHA, config=OFF) as reader:
        assert reader.read("a.txt") == b"hello"


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
@pytest.mark.parametrize(
    "compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED], ids=["stored", "deflate"]
)
def test_zip_readers_use_the_kernel_unless_switched_off(
    monkeypatch: pytest.MonkeyPatch, streaming: bool, compression: int
) -> None:
    _fake(monkeypatch, zipcrypto=1)
    data = b"secret data " * 500
    raw = build_zipcrypto_zip(b"pw", b"a.txt", data, compression=compression)

    def read(config: ArchiveyConfig | None) -> bytes:
        with open_archive(
            io.BytesIO(raw), password=b"pw", config=config, streaming=streaming
        ) as reader:
            if streaming:
                for member, stream in reader.stream_members():
                    assert stream is not None
                    return stream.read()
            return reader.read("a.txt")
        raise AssertionError("no member")

    assert read(None) == data
    assert _FakeDecryptor.built
    _FakeDecryptor.built.clear()
    assert read(OFF) == data
    assert _FakeDecryptor.built == []


def test_zip_candidate_passwords_use_the_kernel_unless_switched_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, zipcrypto=1)
    raw = build_stored_zipcrypto_zip([(b"right", b"a.txt", b"payload " * 1000)])
    for config, used in ((None, True), (OFF, False)):
        _FakeDecryptor.built.clear()
        with open_archive(
            io.BytesIO(raw), password=[b"wrong1", b"right"], config=config
        ) as reader:
            assert reader.read("a.txt") == b"payload " * 1000
        assert bool(_FakeDecryptor.built) is used


@pytest.mark.parametrize(
    "passwords", [b"pw", [b"wrong1", b"pw"]], ids=["one-password", "candidates"]
)
@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_a_panic_in_a_zipcrypto_read_is_corruption(
    monkeypatch: pytest.MonkeyPatch, streaming: bool, passwords: object
) -> None:
    """A panic while decrypting member data is a ``CorruptionError`` naming the
    kernel, not a wrong-password error: no key can make the cipher panic. With
    candidate passwords, the read does not move on to the next one."""
    _fake(monkeypatch, zipcrypto=1)
    _FakeDecryptor.panic = True
    raw = build_zipcrypto_zip(
        b"pw", b"a.txt", b"x" * 5000, compression=zipfile.ZIP_DEFLATED
    )
    with (
        pytest.raises(CorruptionError, match="ZipCrypto decoder failed") as info,
        open_archive(
            io.BytesIO(raw), password=passwords, streaming=streaming
        ) as reader,
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    assert not isinstance(info.value, EncryptionError)
    assert isinstance(info.value.__cause__, PanicException)
    # The switch turns the kernel off: Python's keys read the same archive.
    with open_archive(io.BytesIO(raw), password=b"pw", config=OFF) as reader:
        assert reader.read("a.txt") == b"x" * 5000


@pytest.mark.parametrize(
    ("filter_id", "kernel"), [(FILTER_ARM64, "arm64"), (FILTER_RISCV, "riscv")]
)
def test_branch_filters_use_the_kernel_unless_switched_off_or_no_child(
    monkeypatch: pytest.MonkeyPatch, filter_id: int, kernel: str
) -> None:
    module = _fake(monkeypatch, **{kernel: 1})

    def built(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> object:
        make = branch_maker(
            filter_id,
            0x1000,
            excluded=excluded,
            natives=ISOLATED if isolated else IN_PROCESS,
        )
        assert make is not None
        return make()

    assert isinstance(built(frozenset(), isolated=False), rust.BranchDecoder)
    assert _FakeBranch.built == [0x1000]
    assert isinstance(built(EXCLUDED, isolated=False), TWIN_BRANCHES)
    # Under NATIVE_DECODERS: the decoder child's kernel, else the Python filter.
    _child_kernels(monkeypatch, None)
    assert isinstance(built(frozenset(), isolated=True), TWIN_BRANCHES)
    _child_kernels(monkeypatch, module)
    assert isinstance(built(frozenset(), isolated=True), rust.BranchDecoder)
    assert _FakeBranch.built == [0x1000, 0x1000]


def test_an_old_branch_kernel_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, arm64=0, riscv=1)
    make = branch_maker(FILTER_ARM64, 0, excluded=frozenset(), natives=IN_PROCESS)
    assert make is not None
    assert isinstance(make(), TWIN_BRANCHES)
    assert branch_maker(0x03, 0, excluded=frozenset(), natives=IN_PROCESS) is None


def test_a_branch_filter_refuses_every_call_after_a_panic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, arm64=1)
    make = branch_maker(FILTER_ARM64, 0, excluded=frozenset(), natives=IN_PROCESS)
    assert make is not None
    branch = make()
    assert branch.decode(b"\x00" * 8) == b"\x00" * 8
    _FakeBranch.panic = True
    with pytest.raises(CorruptionError, match="ARM64 decoder failed") as info:
        branch.decode(b"\x00" * 8)
    calls = _FakeBranch.calls
    for again in (branch.flush, lambda: branch.decode(b"\x00" * 8)):
        with pytest.raises(CorruptionError) as repeat:
            again()
        _assert_raised_again(repeat.value, info.value)
    assert _FakeBranch.calls == calls


def test_a_7z_riscv_read_uses_the_kernel_unless_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, riscv=1)
    isolated = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    results = []
    for config, used in ((None, True), (OFF, False), (isolated, False)):
        _FakeBranch.built.clear()
        with open_archive(RISCV_7Z, config=config) as reader:
            results.append([reader.read(m) for m in reader.members()])
        assert bool(_FakeBranch.built) is used
    assert results[0] == results[1] == results[2]


def test_a_panic_in_a_7z_riscv_read_is_corruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, riscv=1)
    _FakeBranch.panic = True
    with (
        pytest.raises(CorruptionError, match="RISC-V decoder failed") as info,
        open_archive(RISCV_7Z) as reader,
    ):
        for member in reader.members():
            reader.read(member)
    assert isinstance(info.value.__cause__, PanicException)
    with open_archive(RISCV_7Z, config=OFF) as reader:
        assert all(reader.read(m) for m in reader.members())


def test_lzw_uses_the_kernel_unless_switched_off_or_no_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _fake(monkeypatch, lzw=1)
    assert kernels.lzw(frozenset(), isolated=False).library is not None
    assert kernels.lzw(EXCLUDED, isolated=False).library is None
    _child_kernels(monkeypatch, None)
    assert kernels.lzw(frozenset(), isolated=True).library is None
    calls = _child_kernels(monkeypatch, module)
    assert kernels.lzw(frozenset(), isolated=True).library is not None
    assert kernels.lzw(EXCLUDED, isolated=True).library is None
    assert calls == [frozenset()]
    _fake(monkeypatch, lzw=0)
    assert kernels.lzw(frozenset(), isolated=False).library is None


def test_an_lzw_state_refuses_every_call_after_a_panic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, lzw=1)
    lzw = kernels.lzw(frozenset(), isolated=False)
    assert lzw.library is OptionalLibrary.ARCHIVEY_CODECS
    d = lzw.Decompressor()
    with pytest.raises(CorruptionError, match="LZW decoder failed") as info:
        d.decompress(b"\x1f\x9d\x90abc")
    assert _FakeLzw.calls == 1
    for again in (d.flush, lambda: d.decompress(b"more")):
        with pytest.raises(CorruptionError) as repeat:
            again()
        _assert_raised_again(repeat.value, info.value)
    assert _FakeLzw.calls == 1


@requires("ncompress")
def test_a_panic_in_a_z_read_is_corruption(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, lzw=1)
    data = b"hello LZW " * 500
    raw = make_unix_compress(data)
    with (
        pytest.raises(CorruptionError, match="LZW decoder failed") as info,
        open_stream(io.BytesIO(raw), format=StreamFormat.UNIX_COMPRESS) as stream,
    ):
        stream.read()
    assert isinstance(info.value.__cause__, PanicException)
    assert _FakeLzw.built
    isolated = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    for config in (OFF, isolated):
        _FakeLzw.built = 0
        with open_stream(
            io.BytesIO(raw), format=StreamFormat.UNIX_COMPRESS, config=config
        ) as stream:
            assert stream.read() == data
        assert _FakeLzw.built == 0


# ``ab`` and one long match of distance 2: 1000 bytes from a few.
_LZO_BLOCK = bytes([19]) + b"ab" + b"\x20" + bytes(3) + bytes([200, 4, 0]) + b"\x11\0\0"


def test_lzo_uses_the_kernel_unless_switched_off_or_no_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deps,
        "compress_utils",
        deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS, present=False),
    )
    module = _fake(monkeypatch, lzo1x=1)
    _child_kernels(monkeypatch, None)
    for excluded, natives, used in (
        (frozenset(), IN_PROCESS, True),
        (EXCLUDED, IN_PROCESS, False),
        (frozenset(), ISOLATED, False),
    ):
        _FakeLzo1x.calls = []
        decode = lzo1x_decompressor(excluded, natives)
        assert decode(_LZO_BLOCK, 1000) == lzo1x_decompress_python(_LZO_BLOCK, 1000)
        assert bool(_FakeLzo1x.calls) is used
        assert (decode is lzo1x_decompress_python) is not used
    # The decoder child's kernel (here the fake stands in for it).
    _child_kernels(monkeypatch, module)
    _FakeLzo1x.calls = []
    decode = lzo1x_decompressor(frozenset(), ISOLATED)
    assert decode(_LZO_BLOCK, 1000) == lzo1x_decompress_python(_LZO_BLOCK, 1000)
    assert _FakeLzo1x.calls
    _fake(monkeypatch, lzo1x=0)
    assert lzo1x_decompressor(frozenset(), IN_PROCESS) is lzo1x_decompress_python


def test_an_lzo_block_shorter_than_its_limit_is_decoded_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SquashFS block gives only the most it can decode to: the kernel takes it as
    ``max_size`` and decodes the block once."""
    _fake(monkeypatch, lzo1x=1)
    decode = lzo1x_decompressor(frozenset(), IN_PROCESS)
    assert decode(_LZO_BLOCK, 4096) == lzo1x_decompress_python(_LZO_BLOCK, 4096)
    assert _FakeLzo1x.calls == [4096]
    with pytest.raises(LzoError, match="decodes to more than 999 bytes"):
        decode(_LZO_BLOCK, 999)


def test_a_panic_in_an_lzo_read_is_corruption(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, lzo1x=1)
    _FakeLzo1x.panic = True
    decode = lzo1x_decompressor(frozenset(), IN_PROCESS)
    with pytest.raises(CorruptionError, match="LZO1X decoder failed") as info:
        decode(_LZO_BLOCK, 1000)
    assert isinstance(info.value.__cause__, PanicException)
    with (
        pytest.raises(CorruptionError, match="LZO1X decoder failed"),
        open_stream(LZOP_TEXT) as stream,
    ):
        stream.read()
    _FakeLzo1x.calls = []
    with open_stream(LZOP_TEXT, config=OFF) as stream:
        assert stream.read() == LZOP_DATA
    assert _FakeLzo1x.calls == []


@pytest.mark.parametrize("codecs", [True, False], ids=["rust", "python"])
@pytest.mark.parametrize("sizes", [{}, {"out_size": 3, "max_size": 3}])
def test_lzo_takes_exactly_one_size(
    monkeypatch: pytest.MonkeyPatch, codecs: bool, sizes: dict[str, int]
) -> None:
    """Both sides refuse a call with both sizes or neither, before decoding."""
    _fake(monkeypatch, lzo1x=1)
    excluded = frozenset() if codecs else EXCLUDED
    lzo = kernels.lzo1x(excluded, isolated=False)
    assert (lzo.library is not None) is codecs
    with pytest.raises(TypeError, match="exactly one of out_size= and max_size="):
        lzo.decompress(_LZO_BLOCK, **sizes)
    assert _FakeLzo1x.calls == []


def test_a_zipcrypto_state_refuses_every_call_after_a_panic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a panic the kernel's state may be half updated: the wrapper raises the
    same error again and never calls the kernel object."""
    _fake(monkeypatch, zipcrypto=1)
    keys = zipcrypto.new_keys(b"pw")
    _FakeDecryptor.panic = True
    with pytest.raises(CorruptionError, match="ZipCrypto decoder failed") as info:
        keys.decrypt(b"x" * 100)
    calls = _FakeDecryptor.calls
    for again in (lambda: keys.decrypt(b"x" * 100), keys.copy):
        with pytest.raises(CorruptionError) as repeat:
            again()
        _assert_raised_again(repeat.value, info.value)
    assert _FakeDecryptor.calls == calls
    # Errors other than a panic leave the state usable.
    _FakeDecryptor.panic = False
    other = zipcrypto.new_keys(b"pw")
    with pytest.raises(TypeError):
        other.decrypt(None)  # type: ignore[arg-type]
    assert other.decrypt(b"abc") == zipcrypto_twin.Decryptor(b"pw").decrypt(b"abc")


def test_a_panic_on_the_zipcrypto_header_closes_the_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.backends.zip_reader import ZipReader

    _fake(monkeypatch, zipcrypto=1)
    _FakeDecryptor.panic_header = True
    opened: list[io.IOBase] = []
    original = ZipReader._open_raw_payload

    def track(self: ZipReader, loc: object, member: object) -> object:
        raw = original(self, loc, member)  # type: ignore[arg-type]
        opened.append(raw)  # type: ignore[arg-type]
        return raw

    monkeypatch.setattr(ZipReader, "_open_raw_payload", track)
    raw = build_zipcrypto_zip(b"pw", b"a.txt", b"x" * 5000)
    with (
        pytest.raises(CorruptionError, match="ZipCrypto decoder failed"),
        open_archive(io.BytesIO(raw), password=b"pw") as reader,
    ):
        reader.read("a.txt")
    assert opened
    assert all(stream.closed for stream in opened)


def test_only_a_panic_cause_keeps_corruption_from_the_password_check() -> None:
    plain = CorruptionError("bad")
    assert not kernels.caused_by_panic(plain)
    try:
        try:
            raise PanicException("boom")
        except PanicException as panic:
            raise CorruptionError("wrapped") from panic
    except CorruptionError as exc:
        assert kernels.caused_by_panic(exc)
        try:
            raise CorruptionError("outer") from exc
        except CorruptionError as outer:
            assert kernels.caused_by_panic(outer)


def test_other_exceptions_pass_unchanged() -> None:
    with pytest.raises(KeyboardInterrupt), _select.panic_to_corruption("x"):
        raise KeyboardInterrupt


# ── LZFSE and LZVN ────────────────────────────────────────────────────────────────────


def _fake_apple(
    monkeypatch: pytest.MonkeyPatch,
    panic: bool = False,
    child: bool = False,
    **kernels: int,
):
    """A fake package whose ``lzfse`` and ``lzvn`` run the Python decoders with the
    kernel's ``max_size`` contract, recording each call as ``(kernel, max_size)``;
    with ``panic`` set, each raises the fake panic instead. Under ``NATIVE_DECODERS``
    the fake also stands in for the decoder child's package when ``child`` is set;
    otherwise no child can run the package."""
    module = _fake(monkeypatch, **kernels)
    _child_kernels(monkeypatch, module if child else None)
    calls: list[tuple[str, int]] = []

    def kernel(name: str, python):
        def decompress(data: bytes, *, max_size: int) -> bytes:
            calls.append((name, max_size))
            if panic:
                raise PanicException("index out of bounds")
            try:
                return python(data, max_size)
            except TruncatedError as exc:
                raise module.TruncatedDataError(exc.raw_message) from None
            except CorruptionError as exc:
                raise module.CorruptDataError(exc.raw_message) from None

        return types.SimpleNamespace(decompress=decompress)

    module.lzfse = kernel("lzfse", lzfse_decompress)
    module.lzvn = kernel("lzvn", lzvn_decompress)
    return calls


def _read_all(path: Path, config: ArchiveyConfig | None = None) -> dict[str, bytes]:
    with open_archive(path, config=config) as reader:
        return {m.name: reader.read(m) for m in reader.members() if m.is_file}


def test_lzfse_uses_the_kernel_unless_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_apple(monkeypatch, lzfse=1, lzvn=1)
    lzfse = decoder("lzfse", frozenset(), isolated=False)
    lzvn = decoder("lzvn", frozenset(), isolated=False)
    stream = b"bvx-\x03\0\0\0abc" + b"bvx$"
    assert lzfse(stream, 3) == b"abc"
    assert lzvn(bytes([0x40, 0x01]) + b"a" + bytes([0x06]) + bytes(7), 4) == b"aaaa"
    assert calls == [("lzfse", 3), ("lzvn", 4)]
    # The kernel's errors come back as the Python decoder's, with its message.
    with pytest.raises(CorruptionError, match="decodes to more than 2 bytes"):
        lzfse(stream, 2)
    with pytest.raises(TruncatedError, match="ends before its end-of-stream block"):
        lzfse(stream[:-1], 3)
    # Switched off, or isolated with no decoder child that can run the package.
    for excluded, isolated in ((EXCLUDED, False), (frozenset(), True)):
        assert decoder("lzfse", excluded, isolated=isolated) is lzfse_decompress
        assert decoder("lzvn", excluded, isolated=isolated) is lzvn_decompress
    # Isolated with a decoder child: the child's kernels.
    calls = _fake_apple(monkeypatch, child=True, lzfse=1, lzvn=1)
    assert decoder("lzfse", frozenset(), isolated=True)(stream, 3) == b"abc"
    assert decoder("lzvn", frozenset(), isolated=True)(b"\x06" + bytes(7), 0) == b""
    assert calls == [("lzfse", 3), ("lzvn", 0)]
    _fake_apple(monkeypatch, lzfse=0, lzvn=1)
    assert decoder("lzfse", frozenset(), isolated=False) is lzfse_decompress


def test_dmg_and_hfs_reads_use_the_kernels_unless_switched_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ULFO image's runs go through the LZFSE kernel, and its decmpfs file
    ``compressed.txt`` (type 8) through the LZVN one, in the decoder child under
    ``NATIVE_DECODERS``; with the switch off, or under ``NATIVE_DECODERS`` with no
    child that can run the package, the Python decoders read the same bytes."""
    path = DMG_FIXTURES / "hfs-ULFO.dmg"
    expected = _read_all(path, OFF)
    calls = _fake_apple(monkeypatch, lzfse=1, lzvn=1)
    assert _read_all(path) == expected
    assert {name for name, _size in calls} == {"lzfse", "lzvn"}
    calls.clear()
    isolated = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    for config in (OFF, isolated):
        assert _read_all(path, config) == expected
    assert calls == []
    calls = _fake_apple(monkeypatch, child=True, lzfse=1, lzvn=1)
    assert _read_all(path, isolated) == expected
    assert {name for name, _size in calls} == {"lzfse", "lzvn"}


@pytest.mark.parametrize(
    ("name", "kernel", "match"),
    [
        ("hfs-ULFO.dmg", "lzfse", "lzfse run .* LZFSE decoder failed"),
        # compressed.txt is decmpfs type 8: LZVN chunks in its resource fork.
        ("hfs-UDRO.dmg", "lzvn", "compressed data of file .* LZVN decoder failed"),
    ],
)
def test_a_panic_in_a_dmg_read_is_corruption_caused_by_it(
    monkeypatch: pytest.MonkeyPatch, name: str, kernel: str, match: str
) -> None:
    """A panic in either kernel reaches the caller as ``CorruptionError`` that names
    the run or the file, with the panic as its cause."""
    _fake_apple(monkeypatch, panic=True, **{kernel: 1})
    with pytest.raises(CorruptionError, match=match) as info:
        _read_all(DMG_FIXTURES / name)
    assert kernels.caused_by_panic(info.value)
    assert isinstance(info.value.__cause__, PanicException)


def test_opening_a_dmg_without_lzfse_runs_looks_up_no_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The LZFSE decoder is chosen at the first LZFSE run: opening and listing an
    image with none (UDRO) never looks up the LZFSE or LZVN kernel."""
    looked_up: list[str] = []
    lookup = kernels.decoding_kernels

    def spy(name: str, excluded: frozenset[OptionalLibrary], *, isolated: bool):
        looked_up.append(name)
        return lookup(name, excluded, isolated=isolated)

    monkeypatch.setattr(kernels, "decoding_kernels", spy)
    with open_archive(DMG_FIXTURES / "hfs-UDRO.dmg") as reader:
        assert reader.members()
    assert not {"lzfse", "lzvn"} & set(looked_up)
    _read_all(DMG_FIXTURES / "hfs-ULFO.dmg")
    assert "lzfse" in looked_up


# ── The real package ──────────────────────────────────────────────────────────────────

needs_codecs = pytest.mark.skipif(
    not deps.archivey_codecs.available(), reason="archivey-codecs is not installed"
)


@needs_codecs
def test_lha_uses_the_kernel_and_reads_the_same() -> None:
    assert kernels.crc16_arc(frozenset()) is not lha_reader.crc16
    data = bytes(range(256)) * 400
    raw = archive([Member(b"a.bin", data), Member(b"b.txt", b"text\n" * 100)])
    results = []
    for config in (None, OFF):
        with open_archive(
            io.BytesIO(raw), format=ArchiveFormat.LHA, config=config
        ) as reader:
            results.append({m.name: reader.read(m) for m in reader.members()})
    assert results[0] == results[1]
    assert results[0]["a.bin"] == data
    bad = bytearray(raw)
    bad[-50] ^= 1  # inside the last member's data: its CRC-16 fails
    errors = []
    for config in (None, OFF):
        with open_archive(
            io.BytesIO(bytes(bad)), format=ArchiveFormat.LHA, config=config
        ) as reader:
            try:
                for m in reader.members():
                    reader.read(m)
            except CorruptionError as exc:
                errors.append(str(exc))
    assert len(errors) == 2
    assert errors[0] == errors[1]


@needs_codecs
@pytest.mark.parametrize(
    "compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED], ids=["stored", "deflate"]
)
def test_zipcrypto_uses_the_kernel_and_reads_the_same(compression: int) -> None:
    keys = zipcrypto.new_keys(b"pw")
    assert isinstance(keys, rust.ZipCryptoDecryptor)
    assert isinstance(zipcrypto.new_keys(b"pw", EXCLUDED), zipcrypto_twin.Decryptor)
    data = b"secret data " * 5000
    raw = build_zipcrypto_zip(b"pw", b"a.txt", data, compression=compression)
    for config in (None, OFF):
        with open_archive(io.BytesIO(raw), password=b"pw", config=config) as reader:
            assert reader.read("a.txt") == data


@needs_codecs
def test_zipcrypto_candidate_passwords_pick_the_same_one() -> None:
    raw = build_stored_zipcrypto_zip([(b"right", b"a.txt", b"payload " * 1000)])
    for config in (None, OFF):
        with open_archive(
            io.BytesIO(raw), password=[b"wrong1", b"right", b"wrong2"], config=config
        ) as reader:
            assert reader.read("a.txt") == b"payload " * 1000


@needs_codecs
def test_zipcrypto_kernel_matches_python_keys() -> None:
    header = bytes(range(12))
    body = bytes(range(256)) * 300
    native_keys, native_check = zipcrypto.keys_after_header(b"pw", header)
    python_keys, python_check = zipcrypto.keys_after_header(b"pw", header, EXCLUDED)
    assert native_check == python_check
    copy = native_keys.copy()
    assert native_keys.decrypt(body) == python_keys.decrypt(body)
    assert copy.decrypt(body[:10]) == zipcrypto.keys_after_header(
        b"pw", header, EXCLUDED
    )[0].decrypt(body[:10])
    assert zipcrypto.parallel_plaintext_crc32(
        [b"a", b"pw"], header, io.BytesIO(body)
    ) == zipcrypto.parallel_plaintext_crc32(
        [b"a", b"pw"], header, io.BytesIO(body), excluded=EXCLUDED
    )


@needs_codecs
@pytest.mark.parametrize(
    "name", ["riscv_lzma2.7z", "riscv_offset_lzma2.7z", "riscv_special_lzma2.7z"]
)
def test_7z_riscv_uses_the_kernel_and_reads_the_same(name: str) -> None:
    make = branch_maker(FILTER_RISCV, 0, excluded=frozenset(), natives=IN_PROCESS)
    assert make is not None
    assert isinstance(make(), rust.BranchDecoder)
    results = []
    for config in (None, OFF):
        with open_archive(RISCV_7Z.with_name(name), config=config) as reader:
            results.append([reader.read(m) for m in reader.members()])
    assert results[0] == results[1]


def _read_z(raw: bytes, config: ArchiveyConfig | None, piece: int) -> tuple:
    """All of ``raw`` read in ``piece``-byte reads, then the error, if any."""
    out = bytearray()
    with open_stream(
        io.BytesIO(raw), format=StreamFormat.UNIX_COMPRESS, config=config
    ) as stream:
        try:
            while chunk := stream.read(piece):
                out += chunk
        except (CorruptionError, TruncatedError) as exc:
            return bytes(out), type(exc).__name__, str(exc)
    return bytes(out), None, None


@needs_codecs
@requires("ncompress")
@pytest.mark.parametrize("piece", [1, 4096, -1])
def test_z_uses_the_kernel_and_reads_the_same(piece: int) -> None:
    lzw = kernels.lzw(frozenset(), isolated=False)
    assert lzw.library is OptionalLibrary.ARCHIVEY_CODECS
    assert isinstance(lzw.Decompressor(), rust.LzwDecompressor)
    data = (bytes(range(256)) * 50 + b"text " * 30000) * 3
    raw = make_unix_compress(data)
    # 1-byte reads are slow, so they read the first 1500 bytes, damaged inside them.
    window = 1500 if piece == 1 else len(raw)
    base = raw[:window]
    cases = [base, base[:-7], raw[:2], raw[:3]]
    damaged = []
    for at in (300, 500, 1100):
        bad = bytearray(base)
        bad[at] ^= 0xFF
        damaged.append(bytes(bad))
    for case in cases + damaged:
        assert _read_z(case, None, piece) == _read_z(case, OFF, piece)
    for case in damaged:
        # Each damaged case reaches a bad code, so the error path is compared.
        assert _read_z(case, OFF, piece)[1] == "CorruptionError"
    if piece != 1:
        assert _read_z(raw, None, piece)[0] == data


@needs_codecs
@requires("ncompress")
def test_z_seeks_back_through_clear_points_with_the_kernel() -> None:
    """A seekable stream records CLEAR points and restarts at one on a seek back:
    the kernel's offsets give the same points and the same bytes."""
    rng = random.Random(3)
    data = b"the quick brown fox " * 20_000 + rng.randbytes(300_000)
    raw = make_unix_compress(data)
    for config in (None, OFF):
        with open_stream(
            io.BytesIO(raw),
            format=StreamFormat.UNIX_COMPRESS,
            seekable=True,
            config=config,
        ) as stream:
            assert stream.read() == data
            for at in (650_000, 123_456, 7, 699_999):
                stream.seek(at)
                assert stream.read(1000) == data[at : at + 1000]


@requires("ncompress")
@pytest.mark.parametrize("twin", [False, True], ids=["kernel", "twin"])
def test_a_finished_z_decoder_is_not_fed_again(twin: bool) -> None:
    """The decoder contract: ``needs_input`` false means ``feed(b"")`` may be called.
    At its end the kernel takes no more calls (``decompress`` raises ``EOFError``), so
    a finished ``.Z`` decoder reports ``needs_input``; and a stream read past the end
    returns ``b""``."""
    if not twin and not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    data = b"read me to the end " * 3000
    raw = make_unix_compress(data)
    make = (
        lzw_twin.Decompressor
        if twin
        else kernels.lzw(frozenset(), isolated=False).Decompressor
    )
    decoder = UnixCompressDecoder(make, comp_cursor=0, decomp_cursor=0)
    out = decoder.feed(raw).data
    while not decoder.needs_input:
        out += decoder.feed(b"").data
    out += decoder.flush().data
    assert out == data
    assert decoder.finished
    assert decoder.needs_input
    config = OFF if twin else None
    with open_stream(
        io.BytesIO(raw), format=StreamFormat.UNIX_COMPRESS, config=config
    ) as stream:
        assert stream.read() == data
        assert stream.read() == b""


@pytest.mark.parametrize("twin", [False, True], ids=["kernel", "twin"])
def test_a_zero_byte_bcj2_read_reads_no_input(twin: bool) -> None:
    """``read(0)`` decodes nothing and reads no input; a later read still runs the
    end check. With an error held, ``read(0)`` raises it."""
    if not twin and not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    make = kernels.bcj2(EXCLUDED if twin else frozenset(), isolated=False).Decompressor
    main = io.BytesIO(b"x")
    d = make(main, io.BytesIO(), io.BytesIO(), io.BytesIO(), out_size=0)
    assert d.read(0) == b""
    assert main.tell() == 0
    with pytest.raises(CorruptionError, match="BCJ2 main stream has bytes past"):
        d.read()
    with pytest.raises(CorruptionError, match="BCJ2 main stream has bytes past"):
        d.read(0)


class _InterruptedOnce(io.BytesIO):
    """A stream whose ``at``-th read raises ``KeyboardInterrupt``."""

    def __init__(self, data: bytes, at: int) -> None:
        super().__init__(data)
        self._reads = 0
        self._at = at

    def read(self, n: int | None = -1, /) -> bytes:
        self._reads += 1
        if self._reads == self._at:
            raise KeyboardInterrupt
        return super().read(n)


@pytest.mark.parametrize("twin", [False, True], ids=["kernel", "twin"])
@pytest.mark.parametrize("which", range(4), ids=["main", "call", "jump", "rc"])
def test_an_interrupted_bcj2_input_read_stops_the_decoder(
    twin: bool, which: int
) -> None:
    """An interrupt in an input's ``read()`` is kept like any error: later reads give
    a prefix of the output and then raise it again, and never decode on from the
    half-done step."""
    if not twin and not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    size = 200_000
    streams = bcj2_encode(random.Random(4), size)
    make = kernels.bcj2(EXCLUDED if twin else frozenset(), isolated=False).Decompressor
    data = make(*(io.BytesIO(s) for s in streams), out_size=size).read()
    assert len(data) == size
    inputs: list[io.BytesIO] = [io.BytesIO(s) for s in streams]
    # The second read lands mid-output for ``main``; ``rc`` is read once only.
    inputs[which] = _InterruptedOnce(streams[which], at=1 if which == 3 else 2)
    d = make(*inputs, out_size=size)
    out = bytearray()
    interrupts = 0
    for _ in range(200):
        try:
            chunk = d.read(4096)
        except KeyboardInterrupt:
            interrupts += 1
            if interrupts == 3:
                break
            continue
        if not chunk:
            break
        out += chunk
    # The interrupt comes back on each later read, from the end check when it came
    # there (``call`` and ``jump`` are read for the last time by the check).
    assert interrupts == 3
    assert data.startswith(out)


def _params(fn: Callable[..., object]) -> list[tuple[str, object, object]]:
    return [
        (p.name, p.kind, p.default) for p in inspect.signature(fn).parameters.values()
    ]


def test_the_switch_gives_the_same_signature_on_both_sides() -> None:
    """A constructor from the switch has its parameters, names, kinds and defaults,
    whichever side it is: a wrong keyword fails on both."""
    if not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    for build in (
        lambda e: kernels.zipcrypto(e).Decryptor,
        lambda e: kernels.filters(e, isolated=False).Arm64Decoder,
        lambda e: kernels.filters(e, isolated=False).RiscvDecoder,
        lambda e: kernels.lzw(e, isolated=False).Decompressor,
        lambda e: kernels.lzx(e, isolated=False).Decompressor,
        lambda e: kernels.bcj2(e, isolated=False).Decompressor,
        lambda e: kernels.lzo1x(e, isolated=False).decompress,
    ):
        assert _params(build(frozenset())) == _params(build(EXCLUDED))
    with pytest.raises(TypeError):
        kernels.lzx(frozenset(), isolated=False).Decompressor(15, out_size=3)


@pytest.mark.parametrize("excluded", [frozenset(), EXCLUDED], ids=["rust", "python"])
def test_a_zipcrypto_decryptor_takes_a_buffer_password_by_keyword(
    excluded: frozenset[OptionalLibrary],
) -> None:
    """As ``ZipCryptoFactory`` types it: ``password=``, any buffer."""
    make = kernels.zipcrypto(excluded).Decryptor
    want = make(b"key").decrypt(b"abc")
    assert make(password=bytearray(b"key")).decrypt(b"abc") == want
    assert make(password=memoryview(b"key")).decrypt(b"abc") == want


def test_the_child_does_not_send_lzx_buffered_input() -> None:
    """The worker reports no ``unused_data``: LZX's getter copies its buffered input,
    and no proxy reads it."""
    archivey_codecs = deps.archivey_codecs.load()
    if archivey_codecs is None:
        pytest.skip("needs archivey-codecs")
    worker = decoder_worker._Codecs(archivey_codecs)
    worker.build("lzx.Decompressor", [15], {"output_size": 5})
    assert "unused_data" not in worker.report()


def _z_with_a_bad_last_code() -> tuple[bytes, bytes]:
    """A widening 9-bit ``.Z`` stream whose last code is bad, and its clean data. The
    table fills near the end, so the bad code is met by the final pass, after it has
    decoded the bytes before it."""
    from tests.test_codecs import _lzw_compress

    data = random.Random(8).randbytes(280)
    raw = bytearray(_lzw_compress(data, 9, block_mode=True, nine_bit_widens=True))
    raw[-1] ^= 0x80
    return bytes(raw), data


@pytest.mark.parametrize("twin", [False, True], ids=["kernel", "twin"])
def test_a_bad_code_met_by_the_final_pass_still_raises(
    twin: bool, tmp_path: Path
) -> None:
    """The final pass hands back the bytes before a bad code, and the decoder stays
    open until the error raises: on the next call, through the stream, and through
    ``open_archive``."""
    if not twin and not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    raw, data = _z_with_a_bad_last_code()
    lzw = (
        types.SimpleNamespace(Decompressor=lzw_twin.Decompressor)
        if twin
        else kernels.lzw(frozenset(), isolated=False)
    )
    d = lzw.Decompressor()
    out = d.decompress(raw) + d.flush()
    assert out and data.startswith(out)
    assert not d.eof
    with pytest.raises(CorruptionError, match="invalid code"):
        d.flush()
    config = OFF if twin else None
    with open_stream(
        io.BytesIO(raw), format=StreamFormat.UNIX_COMPRESS, config=config
    ) as stream:
        got = b""
        with pytest.raises(CorruptionError, match="invalid code"):
            while chunk := stream.read(100):
                got += chunk
        assert got == out
    path = tmp_path / "data.bin.Z"
    path.write_bytes(raw)
    with open_archive(path, config=config) as archive:
        member = archive.members()[0]
        with pytest.raises(CorruptionError, match="invalid code"):
            archive.read(member)


def _z_points(make: Callable[..., object], raw: bytes) -> tuple[bytes, list]:
    decoder = UnixCompressDecoder(
        make,  # type: ignore[arg-type]
        comp_cursor=0,
        decomp_cursor=0,
    )
    out = bytearray()
    points = []
    for start in range(0, len(raw), 5000):
        got = decoder.feed(raw[start : start + 5000], 7000)
        out += got.data
        points += got.points
        while not decoder.needs_input:
            got = decoder.feed(b"", 7000)
            out += got.data
            points += got.points
    got = decoder.flush()
    return bytes(out + got.data), points + got.points


@needs_codecs
@requires("ncompress")
def test_z_clear_points_match_and_restart_with_the_kernel() -> None:
    rng = random.Random(3)
    # Text, then random bytes: the ratio drops, so compress writes CLEAR codes.
    data = b"the quick brown fox " * 20_000 + rng.randbytes(300_000)
    raw = make_unix_compress(data)
    make = kernels.lzw(frozenset(), isolated=False).Decompressor
    out, points = _z_points(make, raw)
    assert out == data
    assert (out, points) == _z_points(lzw_twin.Decompressor, raw)
    assert len(points) >= 3  # the header point and the CLEARs
    template = UnixCompressDecoder(make, comp_cursor=0, decomp_cursor=0)
    template.feed(raw[:3])  # reads the header
    for point in points[1:]:
        restarted = template.recreate(point, io.BytesIO())
        got = restarted.feed(raw[point.compressed_offset :]).data
        while not restarted.needs_input:
            got += restarted.feed(b"").data
        got += restarted.flush().data
        assert got == data[point.decompressed_offset :]


def _drive_lzw(d: kernels.LzwDecompressor, data: bytes, cap: int) -> tuple:
    """Pass all of ``data`` with output capped at ``cap``, then call ``flush()``
    twice uncapped and ``decompress()`` once more: the bytes, the CLEAR offsets,
    each call's error, and which calls returned output."""
    out = bytearray()
    units: list = []
    events: list = []

    def call(step: Callable[[], bytes]) -> bool:
        try:
            got = step()
        except (CorruptionError, UnsupportedFeatureError, ValueError, EOFError) as exc:
            events.append((type(exc).__name__, str(exc)))
            return False
        out.extend(got)
        units.extend(d.clear_offsets)
        events.append(("ok", bool(got)))
        return True

    # One capped call leaves most of the stream for flush().
    call(lambda: d.decompress(data, cap))
    for step in (d.flush, d.flush, lambda: d.decompress(b"x")):
        call(step)
    errors = [e for e in events if e[0] != "ok"]
    return bytes(out), units, errors, events[-3:]


@needs_codecs
@requires("ncompress")
def test_lzw_bad_code_inside_flush_raises_from_the_next_call() -> None:
    """A bad code met by ``flush()`` after some output: ``flush()`` returns that
    output and the next call raises, in the kernel and its Python twin alike."""
    make = kernels.lzw(frozenset(), isolated=False).Decompressor
    rng = random.Random(11)
    inside_flush = 0
    for _ in range(200):
        data = b"".join(
            rng.choice((b"abc", b"hello ", bytes([rng.randrange(256)])))
            for _ in range(rng.randint(50, 3000))
        )
        bad = bytearray(make_unix_compress(data))
        for _ in range(rng.randint(1, 3)):
            bad[rng.randrange(3, len(bad))] ^= rng.randrange(1, 256)
        cap = rng.choice((1, 50, 1000))
        rust = _drive_lzw(make(), bytes(bad), cap)
        python = _drive_lzw(lzw_twin.Decompressor(), bytes(bad), cap)
        assert rust[:3] == python[:3]
        first_flush, second_flush, _ = rust[3]
        if first_flush == ("ok", True) and second_flush[0] != "ok":
            inside_flush += 1
    assert inside_flush > 0


@pytest.mark.parametrize("twin", [False, True], ids=["kernel", "twin"])
def test_lzw_drained_to_eof_raises_a_bad_code_one_flush_returns(twin: bool) -> None:
    """The archivey-codecs README's example: ``flush()`` called until ``eof`` raises
    a bad code that one ``flush()`` passes over, returning the output before it."""
    if not twin and not deps.archivey_codecs.available():
        pytest.skip("needs archivey-codecs")
    raw, data = _z_with_a_bad_last_code()
    lzw = (
        types.SimpleNamespace(Decompressor=lzw_twin.Decompressor)
        if twin
        else kernels.lzw(frozenset(), isolated=False)
    )
    d = lzw.Decompressor()
    out = d.decompress(raw)
    with pytest.raises(CorruptionError, match="invalid code"):
        while not d.eof:
            out += d.flush()
    assert out and data.startswith(out)


class _OtherByteArray(bytearray):
    """A ``bytearray`` whose ``__bytes__`` gives other bytes than its buffer."""

    def __bytes__(self) -> bytes:
        return b"\x11\x00\x00"


@needs_codecs
def test_an_isolated_kernel_reads_a_buffer_as_its_own_bytes() -> None:
    """A decoder child gets the buffer's own bytes, as the in-process kernel and
    the twin read them, never ``__bytes__``."""
    data = random.Random(3).randbytes(64)
    for isolated in (False, True):
        decoder = kernels.filters(frozenset(), isolated=isolated).Arm64Decoder()
        try:
            got = decoder.decode(_OtherByteArray(data)) + decoder.flush()
        finally:
            close = getattr(decoder, "close", None)
            if close is not None:
                close()
        twin = filters_twin.Arm64Decoder()
        assert got == twin.decode(data) + twin.flush(), isolated
    block = _OtherByteArray(b"\x00" * 4)  # damaged as its own bytes
    outcomes = []
    for isolated in (False, True):
        decode = kernels.lzo1x(frozenset(), isolated=isolated).decompress
        try:
            outcomes.append(("ok", decode(block, max_size=64)))
        except CorruptionError as exc:
            outcomes.append(("corrupt", str(exc)))
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == "corrupt"


@needs_codecs
def test_lzo_kernel_matches_python_on_damaged_blocks() -> None:
    """Every damaged or cut block gives the same bytes or the same error message
    as the Python decoder, at an exact size and at a larger SquashFS-style one."""
    kernel = lzo1x_decompressor(frozenset(), IN_PROCESS)
    assert kernel is not lzo1x_decompress_python
    rng = random.Random(7)
    for _ in range(3000):
        bad = bytearray(_LZO_BLOCK)
        for _ in range(rng.randint(1, 3)):
            bad[rng.randrange(len(bad))] = rng.randrange(256)
        if rng.random() < 0.3:
            bad = bad[: rng.randrange(len(bad))]
        for limit in (1000, 1050, 0):
            results = []
            for decode in (kernel, lzo1x_decompress_python):
                try:
                    results.append(("ok", decode(bytes(bad), limit)))
                except LzoError as exc:
                    results.append(("error", str(exc)))
            assert results[0] == results[1], bytes(bad).hex()


@needs_codecs
@pytest.mark.parametrize("damage", [None, 60, 400, -20])
def test_lzop_uses_the_kernel_and_reads_the_same(damage: int | None) -> None:
    data = LZOP_DATA
    raw = bytearray(LZOP_TEXT.read_bytes())
    if damage is not None:
        raw[damage] ^= 0x55
    results = []
    for config in (None, PYTHON_LZO):
        try:
            with open_stream(io.BytesIO(bytes(raw)), config=config) as stream:
                results.append(("ok", stream.read()))
        except (CorruptionError, TruncatedError) as exc:
            results.append((type(exc).__name__, str(exc)))
    assert results[0] == results[1]
    assert (results[0] == ("ok", data)) is (damage is None)


@needs_codecs
@pytest.mark.parametrize("name", ["lzo.sqfs", "lzo1x-1.sqfs"])
def test_squashfs_lzo_uses_the_kernel_and_reads_the_same(name: str) -> None:
    path = Path(__file__).parent / "fixtures" / "squashfs" / name
    results = []
    for config in (None, PYTHON_LZO):
        with open_archive(path, config=config) as reader:
            results.append(
                {m.name: reader.read(m) for m in reader.members() if m.is_file}
            )
    assert results[0] == results[1]
    assert results[0]


@needs_codecs
@pytest.mark.parametrize("name", ["hfs-ULFO.dmg", "apfs-ULFO.dmg", "hfs-UDZO.dmg"])
def test_dmg_uses_the_kernels_and_reads_the_same(name: str) -> None:
    """The real kernels read every file the Python decoders read, ``compressed.txt``
    (LZVN in its resource fork) included."""
    path = DMG_FIXTURES / name
    assert decoder("lzfse", frozenset(), isolated=False) is not lzfse_decompress
    assert _read_all(path) == _read_all(path, OFF)


@needs_codecs
def test_damaged_lzfse_runs_fail_the_same_way() -> None:
    """Damage inside the image's LZFSE runs gives the same error with the kernel as
    with the Python decoder."""
    from tests.test_lzfse_decoder import _LZFSE, _tables

    path = DMG_FIXTURES / "hfs-ULFO.dmg"
    raw = path.read_bytes()
    runs = [
        (off, length)
        for _crc, table in _tables(path)
        for kind, _sectors, off, length in table
        if kind == _LZFSE
    ]
    rng = random.Random(5)
    differing = 0
    for _ in range(30):
        bad = bytearray(raw)
        off, length = rng.choice(runs)
        at = off + rng.randrange(length)
        bad[at] ^= 1 << rng.randrange(8)
        results = []
        for config in (None, OFF):
            try:
                with open_archive(io.BytesIO(bytes(bad)), config=config) as reader:
                    got = {
                        m.name: reader.read(m) for m in reader.members() if m.is_file
                    }
                results.append(("ok", got))
            except (CorruptionError, TruncatedError, UnsupportedFeatureError) as exc:
                results.append((type(exc).__name__, str(exc)))
        assert results[0] == results[1], at
        differing += results[0][0] != "ok"
    assert differing


# ── LZX (CAB) ─────────────────────────────────────────────────────────────────────────


def _cab_results(raw: bytes, config: ArchiveyConfig | None, order: list[str]) -> list:
    """Each member read in ``order``: its bytes, or the error it raised."""
    results: list = []
    try:
        reader = open_archive(io.BytesIO(raw), config=config)
    except ArchiveyError as exc:
        return [(type(exc).__name__, str(exc))]
    with reader:
        for name in order:
            try:
                results.append(reader.read(name))
            except ArchiveyError as exc:
                results.append((type(exc).__name__, str(exc)))
    return results


def _lzx_cabs() -> list[tuple[str, bytes, list[str]]]:
    """Cabinets of one LZX folder each: windows, block types, E8, with and without
    block checksums, blocks shorter and longer than a frame."""
    rng = random.Random(23)
    text = b"".join(b"line %d of the cabinet\n" % i for i in range(9000))
    code = bytes(rng.choice([0xE8, 0x00, 0x01, 0xFF, 0x90]) for _ in range(70000))
    files = [
        CabFile("a.txt", text),
        CabFile("b.bin", rng.randbytes(40000)),
        CabFile("c.exe", code),
    ]
    names = [f.name for f in files]
    cabs = []
    for window, blocks, e8, checksums in (
        (15, ("verbatim",), 0, True),
        (16, ("aligned", "uncompressed"), 0, False),
        (17, ("verbatim", "uncompressed", "aligned"), 12_000_000, True),
        (21, ("verbatim",), 12_000_000, False),
    ):
        encoder = LzxEncoder(
            window_bits=window, blocks=blocks, block_size=20001, e8_file_size=e8
        )
        folder = CabFolder("lzx", window, encoder, checksums=checksums)
        cabs.append((f"lzx-{window}", write_cab(files, [folder]), names))
    return cabs


@needs_codecs
def test_cab_lzx_uses_the_kernel_and_reads_the_same() -> None:
    """Every member of clean, damaged and cut cabinets gives the same bytes or the
    same error with the kernel as with the Python decoder, in order and backwards.
    A damaged block whose checksum fails raises from the frame that needs it, though
    the kernel was given that block earlier."""
    assert kernels.lzx(frozenset(), isolated=False).library is not None
    rng = random.Random(29)
    for _, raw, names in _lzx_cabs():
        start = raw.index(b"a.txt\0") + 32  # past the file table, into the blocks
        variants = [raw, raw[: len(raw) // 2], raw[: len(raw) - 3]]
        # Cut where a data block starts: the block table is short, so the folder has
        # no output size and the input ends at a frame the reader still asks for.
        variants += [raw[:at] for at, _ in _cab_blocks(raw)]
        for _ in range(25):
            bad = bytearray(raw)
            for _ in range(rng.randint(1, 3)):
                bad[rng.randrange(start, len(bad))] ^= rng.randrange(1, 256)
            variants.append(bytes(bad))
        for variant in variants:
            for order in (names, names[::-1]):
                assert _cab_results(variant, None, order) == _cab_results(
                    variant, OFF, order
                )


def test_cab_lzx_kernel_is_not_used_when_switched_off_or_no_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _fake(monkeypatch, lzx=2)
    assert kernels.lzx(frozenset(), isolated=False).library is not None
    assert kernels.lzx(EXCLUDED, isolated=False).library is None
    _child_kernels(monkeypatch, None)
    assert kernels.lzx(frozenset(), isolated=True).library is None
    _child_kernels(monkeypatch, module)
    assert kernels.lzx(frozenset(), isolated=True).library is not None
    _fake(monkeypatch, lzx=1)
    assert kernels.lzx(frozenset(), isolated=False).library is None


class _FakeLzx:
    """Stands in for ``archivey_codecs.lzx.Decompressor``: panics on any call."""

    built: ClassVar[int] = 0

    def __init__(self, window_bits: int, *, output_size: int | None = None) -> None:
        type(self).built += 1

    needs_input = True
    eof = False

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        raise PanicException("index out of bounds")

    flush = decompress


def test_a_panic_in_a_cab_lzx_read_is_corruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _fake(monkeypatch, lzx=2)
    module.lzx = types.SimpleNamespace(Decompressor=_FakeLzx)
    monkeypatch.setattr(_FakeLzx, "built", 0)
    _, raw, names = _lzx_cabs()[0]
    with open_archive(io.BytesIO(raw)) as reader:
        with pytest.raises(CorruptionError, match="LZX decoder failed") as info:
            reader.read(names[0])
        assert isinstance(info.value.__cause__, PanicException)
    assert _FakeLzx.built
    isolated = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    for config in (OFF, isolated):
        _FakeLzx.built = 0
        with open_archive(io.BytesIO(raw), config=config) as reader:
            assert reader.read(names[0]).startswith(b"line 0 ")
        assert _FakeLzx.built == 0


def _cab_blocks(raw: bytes) -> list[tuple[int, int]]:
    """Each CFDATA block of a one-folder cabinet with no reserve: where its header
    starts, and its payload size."""
    first, count = struct.unpack_from("<IH", raw, 36)
    blocks, at = [], first
    for _ in range(count):
        stored = struct.unpack_from("<H", raw, at + 4)[0]
        blocks.append((at, stored))
        at += 8 + stored
    return blocks


@needs_codecs
@pytest.mark.parametrize("window", [15, 21])
def test_cab_lzx_unchecked_damage_before_a_failed_block_reads_the_same(
    window: int,
) -> None:
    """A block stored with checksum 0 is not checked, so damage in it reaches the
    decoder; the next block fails its checksum. Which error a member gets depends
    on whether the Python decoder pulls the failed block before it meets the
    damage, and the kernel must decide the same way."""
    text = b"".join(b"line %d\n" % i for i in range(30000))
    files = [CabFile("a", text[:66536]), CabFile("b", text[66536:])]
    encoder = LzxEncoder(
        window_bits=window, blocks=("verbatim", "uncompressed"), block_size=9000
    )
    raw = write_cab(files, [CabFolder("lzx", window, encoder)])
    blocks = _cab_blocks(raw)
    differ = 0
    for failed in range(1, len(blocks)):
        unchecked, size = blocks[failed - 1]
        for back in (1, 2, 3, 5, 9, 17, 255, size // 2, size - 1):
            if not 0 < back <= size:
                continue
            bad = bytearray(raw)
            bad[unchecked : unchecked + 4] = bytes(4)
            bad[unchecked + 8 + size - back] ^= 0x40
            bad[blocks[failed][0]] ^= 1
            for order in (["a", "b"], ["b", "a"]):
                kernel = _cab_results(bytes(bad), None, order)
                python = _cab_results(bytes(bad), OFF, order)
                differ += kernel != python
    assert differ == 0


# ── BCJ2 ──────────────────────────────────────────────────────────────────────────────


def _bcj2_calls(
    streams: tuple[bytes, ...], size: int, excluded: frozenset, reads: list[int]
) -> list:
    """Each read of ``reads`` (then a seek back and one read): its bytes, or the
    error it raised. Reads go on after an error, as a caller may."""
    stream = Bcj2DecoderStream(
        *(io.BytesIO(s) for s in streams),
        unpack_size=size,
        excluded=excluded,
        isolated=False,
    )
    results: list = []

    def call(step: Callable[[], object]) -> None:
        try:
            results.append(step())
        except ArchiveyError as exc:
            results.append((type(exc).__name__, str(exc)))

    for n in reads:
        call(lambda n=n: stream.read(n))
    call(lambda: stream.seek(0))
    call(lambda: stream.read(reads[0]))
    return results


def _bcj2_cases(rng: random.Random) -> list[tuple[tuple[bytes, ...], int]]:
    """Valid BCJ2 streams, and the same cut short, with bytes added, or with a
    range-coder byte changed; and a declared size off from the streams'."""
    cases = []
    for case in range(60):
        size = rng.choice((0, 1, 5, 1000, 70_000, 200_000))
        streams = list(bcj2_encode(rng, size))
        out_size = size
        which, how = rng.randrange(4), case % 5
        s = streams[which]
        if how == 1 and s:
            streams[which] = s[: rng.randrange(len(s))]
        elif how == 2:
            streams[which] = s + rng.randbytes(rng.randint(1, 5))
        elif how == 3 and len(streams[3]) > 5:
            rc = bytearray(streams[3])
            rc[rng.randrange(5, len(rc))] ^= 1 << rng.randrange(8)
            streams[3] = bytes(rc)
        elif how == 4:
            out_size = rng.choice((size + 1000, max(0, size - 50)))
        cases.append((tuple(streams), out_size))
    return cases


@needs_codecs
def test_bcj2_uses_the_kernel_and_reads_the_same() -> None:
    """Every read gives the same bytes or raises the same error with the kernel as
    with the Python decoder, at the same read: the kernel hands back the bytes
    before an error first, and the wrapper raises the error from that read."""
    assert kernels.bcj2(frozenset(), isolated=False).library is not None
    rng = random.Random(31)
    for streams, size in _bcj2_cases(rng):
        reads = [rng.choice((1, 100, 4096, 65536, 300_000)) for _ in range(8)]
        kernel = _bcj2_calls(streams, size, frozenset(), reads)
        python = _bcj2_calls(streams, size, EXCLUDED, reads)
        assert kernel == python


def test_bcj2_kernel_is_not_used_when_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, bcj2=1)
    assert kernels.bcj2(frozenset(), isolated=False).library is not None
    assert kernels.bcj2(EXCLUDED, isolated=False).library is None
    assert kernels.bcj2(frozenset(), isolated=True).library is None
    _fake(monkeypatch, bcj2=0)
    assert kernels.bcj2(frozenset(), isolated=False).library is None


class _FakeBcj2:
    """Stands in for ``archivey_codecs.bcj2.Decompressor``: panics on a read."""

    built: ClassVar[int] = 0
    calls: ClassVar[int] = 0
    eof = False
    decoded = total_out = 0
    total_in = (0, 0, 0, 0)

    def __init__(self, *streams: object, out_size: int) -> None:
        type(self).built += 1

    def read(self, max_length: int = -1) -> bytes:
        type(self).calls += 1
        raise PanicException("index out of bounds")


def test_a_panic_in_a_bcj2_read_is_corruption_and_refuses_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _fake(monkeypatch, bcj2=1)
    module.bcj2 = types.SimpleNamespace(Decompressor=_FakeBcj2)
    monkeypatch.setattr(_FakeBcj2, "calls", 0)
    streams = bcj2_encode(random.Random(1), 1000)
    stream = Bcj2DecoderStream(
        *(io.BytesIO(s) for s in streams),
        unpack_size=1000,
        excluded=frozenset(),
        isolated=False,
    )
    with pytest.raises(CorruptionError, match="BCJ2 decoder failed") as info:
        stream.read(10)
    assert isinstance(info.value.__cause__, PanicException)
    with pytest.raises(CorruptionError) as again:
        stream.read(10)
    _assert_raised_again(again.value, info.value)
    assert _FakeBcj2.calls == 1
    python = Bcj2DecoderStream(
        *(io.BytesIO(s) for s in streams),
        unpack_size=1000,
        excluded=frozenset(),
        isolated=True,
    )
    assert len(python.read(1000)) == 1000


class _FailingInput(io.BytesIO):
    """An input stream whose reads raise ``OSError`` from ``at`` on."""

    def __init__(self, data: bytes, at: int) -> None:
        super().__init__(data)
        self._at = at

    def read(self, n: int | None = -1, /) -> bytes:
        if self.tell() >= self._at:
            raise OSError("input went away")
        left = self._at - self.tell()
        return super().read(left if n is None or n < 0 else min(n, left))


def _bcj2_failing_calls(
    streams: tuple[bytes, ...], which: int, excluded: frozenset
) -> list:
    """Reads of a stream whose input ``which`` fails halfway: each read's size, or
    the error it raised and whether it is the first error raised again."""
    inputs = [io.BytesIO(s) for s in streams]
    inputs[which] = _FailingInput(streams[which], len(streams[which]) // 2)
    stream = Bcj2DecoderStream(
        *inputs, unpack_size=200_000, excluded=excluded, isolated=False
    )
    results: list = []
    first: Exception | None = None
    for _ in range(10):
        try:
            results.append(len(stream.read(30_000)))
        except OSError as exc:
            first = first or exc
            results.append((type(exc).__name__, str(exc), exc is first))
    return results


@pytest.mark.parametrize("which", range(4))
def test_bcj2_input_error_raises_the_same_and_again_after(which: int) -> None:
    """An input's ``OSError`` stops decoding as a decode error does: the reads after
    it raise the same error object, with the kernel and with the Python decoder."""
    streams = bcj2_encode(random.Random(5), 200_000)
    python = _bcj2_failing_calls(streams, which, EXCLUDED)
    errors = [r for r in python if isinstance(r, tuple)]
    assert len(errors) > 1
    assert all(again for *_, again in errors)
    if kernels.bcj2(frozenset(), isolated=False).library is not None:
        assert _bcj2_failing_calls(streams, which, frozenset()) == python


class _CountingBcj2:
    """Stands in for ``archivey_codecs.bcj2.Decompressor``: returns zeros and
    records the largest read."""

    largest: ClassVar[int] = 0
    eof = False
    total_in = (0, 0, 0, 0)

    def __init__(self, *streams: object, out_size: int) -> None:
        self._size = out_size
        self.decoded = self.total_out = 0

    def read(self, max_length: int = -1) -> bytes:
        n = self._size - self.total_out
        if max_length >= 0:
            n = min(n, max_length)
            type(self).largest = max(type(self).largest, max_length)
        self.total_out += n
        self.decoded = self.total_out
        self.eof = self.total_out == self._size
        return bytes(n)


def test_bcj2_kernel_seek_forward_decodes_one_block_at_a_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A long forward seek on the kernel path holds one block of output at a time,
    as the Python path does, not the whole gap."""
    module = _fake(monkeypatch, bcj2=1)
    module.bcj2 = types.SimpleNamespace(Decompressor=_CountingBcj2)
    monkeypatch.setattr(_CountingBcj2, "largest", 0)
    size = 50 * _BCJ2_BLOCK
    stream = Bcj2DecoderStream(
        *(io.BytesIO() for _ in range(4)),
        unpack_size=size,
        excluded=frozenset(),
        isolated=False,
    )
    assert stream.seek(size - 10) == size - 10
    assert stream.read(100) == bytes(10)
    assert 0 < _CountingBcj2.largest <= _BCJ2_BLOCK


# ── In the decoder child (NATIVE_DECODERS) ────────────────────────────────────────────

ISOLATED_CONFIG = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)


@pytest.fixture
def child_builds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The kernel objects built in a decoder child, by their name in the package
    (``"lzo1x"``, ``"lzfse"`` or ``"lzvn"`` for each one-shot decode)."""
    built: list[str] = []
    build, one_shot = kernel_child.ChildCodecs.build, kernel_child.ChildCodecs.one_shot

    def spy_build(
        self: kernel_child.ChildCodecs, name: str, *args: object, **kwargs: object
    ) -> object:
        built.append(name)
        return build(self, name, *args, **kwargs)

    def spy_one_shot(
        self: kernel_child.ChildCodecs, kernel: str, block: bytes, **sizes: int
    ) -> bytes:
        built.append(kernel)
        return one_shot(self, kernel, block, **sizes)

    monkeypatch.setattr(kernel_child.ChildCodecs, "build", spy_build)
    monkeypatch.setattr(kernel_child.ChildCodecs, "one_shot", spy_one_shot)
    return built


@needs_codecs
@requires("ncompress")
def test_z_in_the_child_reads_the_same(child_builds: list[str]) -> None:
    data = (bytes(range(256)) * 50 + b"text " * 30000) * 3
    raw = make_unix_compress(data)
    cases = [raw, raw[:-7], raw[:3]]
    for at in (300, 500, 1100):
        bad = bytearray(raw)
        bad[at] ^= 0xFF
        cases.append(bytes(bad))
    for case in cases:
        assert _read_z(case, ISOLATED_CONFIG, 4096) == _read_z(case, OFF, 4096)
    assert _read_z(raw, ISOLATED_CONFIG, -1)[0] == data
    assert set(child_builds) == {"lzw.Decompressor"}


@needs_codecs
def test_cab_lzx_in_the_child_reads_the_same(child_builds: list[str]) -> None:
    rng = random.Random(31)
    for _, raw, names in _lzx_cabs()[:2]:
        start = raw.index(b"a.txt\0") + 32
        variants = [raw, raw[: len(raw) // 2]]
        for _ in range(4):
            bad = bytearray(raw)
            bad[rng.randrange(start, len(bad))] ^= rng.randrange(1, 256)
            variants.append(bytes(bad))
        for variant in variants:
            for order in (names, names[::-1]):
                assert _cab_results(variant, ISOLATED_CONFIG, order) == (
                    _cab_results(variant, OFF, order)
                )
    assert "lzx.Decompressor" in child_builds


@needs_codecs
def test_cab_lzx_failed_block_in_the_child_reads_the_same(
    child_builds: list[str],
) -> None:
    """A failed block's error comes from the frame that reads it, with the kernel in
    a child."""
    text = b"".join(b"line %d\n" % i for i in range(30000))
    files = [CabFile("a", text[:66536]), CabFile("b", text[66536:])]
    encoder = LzxEncoder(
        window_bits=15, blocks=("verbatim", "uncompressed"), block_size=9000
    )
    raw = write_cab(files, [CabFolder("lzx", 15, encoder)])
    blocks = _cab_blocks(raw)
    for failed in (1, len(blocks) // 2):
        unchecked, size = blocks[failed - 1]
        for back in (1, size // 2):
            bad = bytearray(raw)
            bad[unchecked : unchecked + 4] = bytes(4)
            bad[unchecked + 8 + size - back] ^= 0x40
            bad[blocks[failed][0]] ^= 1
            for order in (["a", "b"], ["b", "a"]):
                assert _cab_results(bytes(bad), ISOLATED_CONFIG, order) == (
                    _cab_results(bytes(bad), OFF, order)
                )
    assert "lzx.Decompressor" in child_builds


@needs_codecs
@pytest.mark.parametrize("name", ["riscv_lzma2.7z", "riscv_special_lzma2.7z"])
def test_7z_riscv_in_the_child_reads_the_same(
    name: str, child_builds: list[str]
) -> None:
    results = []
    for config in (ISOLATED_CONFIG, OFF):
        with open_archive(RISCV_7Z.with_name(name), config=config) as reader:
            results.append([reader.read(m) for m in reader.members()])
    assert results[0] == results[1]
    assert set(child_builds) == {"filters.RiscvDecoder"}


@needs_codecs
@pytest.mark.parametrize("damage", [None, 400])
def test_lzop_in_the_child_reads_the_same(
    damage: int | None, child_builds: list[str]
) -> None:
    raw = bytearray(LZOP_TEXT.read_bytes())
    if damage is not None:
        raw[damage] ^= 0x55
    results = []
    for config in (ISOLATED_CONFIG, PYTHON_LZO):
        try:
            with open_stream(io.BytesIO(bytes(raw)), config=config) as stream:
                results.append(("ok", stream.read()))
        except (CorruptionError, TruncatedError) as exc:
            results.append((type(exc).__name__, str(exc)))
    assert results[0] == results[1]
    assert (results[0] == ("ok", LZOP_DATA)) is (damage is None)
    assert set(child_builds) == {"lzo1x"}


@needs_codecs
@pytest.mark.parametrize("name", ["hfs-ULFO.dmg", "apfs-ULFO.dmg"])
def test_dmg_in_the_child_reads_the_same(name: str, child_builds: list[str]) -> None:
    """LZFSE runs and LZVN decmpfs chunks decode in the decoder child, to the same
    bytes as the Python decoders."""
    path = DMG_FIXTURES / name
    assert _read_all(path, ISOLATED_CONFIG) == _read_all(path, OFF)
    assert "lzfse" in child_builds
    assert set(child_builds) <= {"lzfse", "lzvn"}


@needs_codecs
def test_damaged_lzfse_runs_in_the_child_fail_the_same_way(
    child_builds: list[str],
) -> None:
    """Damage inside an image's LZFSE runs gives the same error from the decoder
    child's kernel as from the Python decoder."""
    from tests.test_lzfse_decoder import _LZFSE, _tables

    path = DMG_FIXTURES / "hfs-ULFO.dmg"
    raw = path.read_bytes()
    runs = [
        (off, length)
        for _crc, table in _tables(path)
        for kind, _sectors, off, length in table
        if kind == _LZFSE
    ]
    rng = random.Random(6)
    differing = 0
    for _ in range(8):
        bad = bytearray(raw)
        off, length = rng.choice(runs)
        bad[off + rng.randrange(length)] ^= 1 << rng.randrange(8)
        results = []
        for config in (ISOLATED_CONFIG, OFF):
            try:
                with open_archive(io.BytesIO(bytes(bad)), config=config) as reader:
                    got = {
                        m.name: reader.read(m) for m in reader.members() if m.is_file
                    }
                results.append(("ok", got))
            except (CorruptionError, TruncatedError, UnsupportedFeatureError) as exc:
                results.append((type(exc).__name__, str(exc)))
        assert results[0] == results[1]
        differing += results[0][0] != "ok"
    assert differing
    assert "lzfse" in child_builds


def test_a_panic_in_the_child_is_reported_as_one() -> None:
    """PyO3's panic is a ``BaseException`` the worker would not report, so its host
    raises ``KernelPanic``; the parent rebuilds that as ``ChildPanic``, which the
    wrappers take for a panic: ``CorruptionError``, and every later call refused."""

    class _Kernel:
        def decode(self, data: bytes) -> bytes:
            raise PanicException("index out of bounds")

    module = types.SimpleNamespace(
        filters=types.SimpleNamespace(Arm64Decoder=lambda start: _Kernel())
    )
    host = decoder_worker._Codecs(module)
    host.build("filters.Arm64Decoder", [0], {})
    with pytest.raises(decoder_worker.KernelPanic) as raised:
        host.decode(b"\0" * 8)
    payload = decoder_worker.error_payload(raised.value)
    rebuilt = rebuild_error(payload, kernel_child._ERRORS)
    assert isinstance(rebuilt, kernel_child.ChildPanic)
    assert kernels.is_panic(rebuilt)

    class _Proxy:
        calls = 0

        def decode(self, data: bytes) -> bytes:
            self.calls += 1
            raise rebuild_error(payload, kernel_child._ERRORS)

        def flush(self) -> bytes:
            return b""

    proxy = _Proxy()
    stand_in = types.SimpleNamespace(
        filters=types.SimpleNamespace(Arm64Decoder=lambda start: proxy),
        TruncatedDataError=kernel_child.ChildTruncatedDataError,
        CorruptDataError=kernel_child.ChildCorruptDataError,
        UnsupportedDataError=kernel_child.ChildUnsupportedDataError,
    )
    branch = rust.Arm64Decoder(stand_in, 0)  # type: ignore[arg-type]
    with pytest.raises(CorruptionError, match="ARM64 decoder failed") as info:
        branch.decode(b"\0" * 8)
    assert isinstance(info.value.__cause__, kernel_child.ChildPanic)
    with pytest.raises(CorruptionError) as again:
        branch.flush()
    _assert_raised_again(again.value, info.value)
    assert proxy.calls == 1


def test_the_childs_codec_errors_are_rebuilt_as_the_packages() -> None:
    for name, kind in (
        ("CorruptDataError", kernel_child.ChildCorruptDataError),
        ("TruncatedDataError", kernel_child.ChildTruncatedDataError),
        ("UnsupportedDataError", kernel_child.ChildUnsupportedDataError),
        ("CodecError", kernel_child.ChildCodecError),
    ):
        error = type(name, (ValueError,), {"__module__": "_codecs"})("bad code 7")
        rebuilt = rebuild_error(
            decoder_worker.error_payload(error), kernel_child._ERRORS
        )
        assert type(rebuilt) is kind
        assert str(rebuilt) == "bad code 7"
        assert isinstance(rebuilt, kernel_child.ChildCodecs.CodecError)


@pytest.mark.parametrize("how", ["no child", "start fails", "import fails"])
def test_no_child_means_the_python_twin(
    how: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """When no child can run archivey-codecs, the Python twin decodes in this
    process: it is not native, so NATIVE_DECODERS' promise holds. The failure is
    remembered, so later streams start no child to see it fail again."""
    _fake(monkeypatch, lzw=1)
    monkeypatch.setattr(kernel_child, "_table", [])
    monkeypatch.setattr(kernel_child, "_failed", [])
    asked: list[str] = []

    def unavailable(name: str) -> str | None:
        asked.append(name)
        return "frozen" if how == "no child" else None

    monkeypatch.setattr(kernel_child, "decoder_child_unavailable_reason", unavailable)
    starts = []
    error = (
        DecoderChildStartError
        if how == "start fails"
        else decoder_child.DecoderChildImportError
    )

    def refuse(*args: object, **kwargs: object) -> NoReturn:
        starts.append(args)
        raise error("cannot start the decoder process: no")

    monkeypatch.setattr(kernel_child, "DecoderChild", refuse)
    with caplog.at_level(logging.DEBUG, logger="archivey"):
        for _ in range(3):
            assert kernels.lzw(frozenset(), isolated=True).library is None
    assert len(asked) == 1
    assert len(starts) == (0 if how == "no child" else 1)
    logged = "cannot be imported" if how == "import fails" else "cannot run in a"
    assert sum(logged in r.message for r in caplog.records) == 1
    assert deps.archivey_codecs.child_import_failed is (how == "import fails")
    assert _FakeLzw.built == 0


@needs_codecs
def test_the_packages_errors_have_the_module_the_child_matches() -> None:
    """The child's errors are rebuilt by their module and name
    (``kernel_child._ERRORS``): PyO3 sets that module to ``_codecs``."""
    import archivey_codecs

    for name in (
        "CodecError",
        "CorruptDataError",
        "TruncatedDataError",
        "UnsupportedDataError",
    ):
        kind = getattr(archivey_codecs, name)
        assert (kind.__module__, kind.__qualname__) in kernel_child._ERRORS


@needs_codecs
def test_cab_members_open_at_once_give_their_children_back(
    child_builds: list[str],
) -> None:
    """Two LZX folders' members open together both park when they close: the one
    replaced gives back its decoder child at once (the leak oracle checks)."""
    text = b"".join(b"line %d\n" % i for i in range(9000))
    folders = [
        CabFolder("lzx", 15, LzxEncoder(window_bits=15)),
        CabFolder("lzx", 15, LzxEncoder(window_bits=15)),
    ]
    raw = write_cab(
        [CabFile("a", text, folder=0), CabFile("b", text, folder=1)], folders
    )
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    gc_was = gc.isenabled()
    gc.disable()
    try:
        with open_archive(
            io.BytesIO(raw), config=config, concurrent_operations=True
        ) as reader:
            first, second = reader.open("a"), reader.open("b")
            assert first.read() == second.read() == text
            first.close()
            second.close()
            leased = [
                child
                for child in gc.get_objects()
                if isinstance(child, decoder_child.DecoderChild)
                and child._lease.process is not None
            ]
            assert len(leased) == 1  # the parked one, given back at close
    finally:
        if gc_was:
            gc.enable()
    assert child_builds.count("lzx.Decompressor") == 2


def test_an_excluded_package_starts_no_child(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, lzw=1)
    monkeypatch.setattr(kernel_child, "_table", [])

    def refuse(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("a child was started")

    monkeypatch.setattr(kernel_child, "DecoderChild", refuse)
    assert kernels.lzw(EXCLUDED, isolated=True).library is None
    assert kernel_child.open_kernels(EXCLUDED) is None


@needs_codecs
def test_an_old_kernel_in_the_child_is_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kernel_child, "_table", [{"lzw": 0, "lzx": 2}])
    monkeypatch.setattr(_select, "_too_old_logged", set())
    assert kernels.lzw(frozenset(), isolated=True).library is None
    assert kernels.lzx(frozenset(), isolated=True).library is not None
