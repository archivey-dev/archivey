"""archivey-codecs kernels: when archivey uses one, and that the result is the same.

The selection rows (design D4, D5) run with a fake package, so they need nothing
installed. The read tests use the real package and skip without it.
"""

from __future__ import annotations

import io
import logging
import random
import struct
import types
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

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
from archivey.internal import native
from archivey.internal.backends import lha_reader, zipcrypto
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64, arm64_decode
from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
from archivey.internal.streams.codecs.lzma_filter_decoder import (
    PythonBranch,
    branch_maker,
)
from archivey.internal.streams.codecs.lzo_decoder import (
    LzoError,
    lzo1x_decompress_python,
    lzo1x_decompressor,
)
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV, riscv_decode
from archivey.internal.streams.codecs.unix_compress_decoder import (
    LzwState,
    UnixCompressDecoder,
)
from tests.bcj2_util import bcj2_encode
from tests.cab_util import CabFile, CabFolder, LzxEncoder, write_cab
from tests.conftest import requires
from tests.lha_util import Member, archive
from tests.streams_util import make_unix_compress
from tests.zipcrypto import build_stored_zipcrypto_zip, build_zipcrypto_zip

EXCLUDED = frozenset({OptionalLibrary.ARCHIVEY_CODECS})
OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-codecs"}))
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

    def __init__(self, password: bytes, keys: zipcrypto.ZipCryptoKeys | None = None):
        if keys is None:
            type(self).built.append(password)
            keys = zipcrypto.ZipCryptoKeys(password)
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
        self._python = PythonBranch(self.decode_with, start_offset)

    @staticmethod
    def decode_with(data: bytes, pc: int) -> bytes:
        """The Python filter this fake stands in for: set by each subclass."""
        raise NotImplementedError

    def decode(self, data: bytes) -> bytes:
        type(self).calls += 1
        if self.panic:
            raise PanicException("attempt to subtract with overflow")
        return self._python.decode(data)

    def flush(self) -> bytes:
        type(self).calls += 1
        return self._python.flush()


class _FakeArm64(_FakeBranch):
    decode_with = staticmethod(arm64_decode)


class _FakeRiscv(_FakeBranch):
    decode_with = staticmethod(riscv_decode)


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
    monkeypatch.setattr(_FakeLzo1x, "error", codec_error)
    module = types.SimpleNamespace(
        KERNELS=kernels,
        crc16_arc=crc16_arc,
        zipcrypto=types.SimpleNamespace(Decryptor=_FakeDecryptor),
        filters=types.SimpleNamespace(Arm64Decoder=_FakeArm64, RiscvDecoder=_FakeRiscv),
        lzw=types.SimpleNamespace(Decompressor=_FakeLzw),
        lzo1x=_FakeLzo1x,
        CodecError=codec_error,
        TruncatedDataError=type("TruncatedDataError", (ValueError,), {}),
        CorruptDataError=type("CorruptDataError", (ValueError,), {}),
        UnsupportedDataError=type("UnsupportedDataError", (ValueError,), {}),
    )
    package = deps.LazyOptional(OptionalLibrary.ARCHIVEY_CODECS, present=True)
    package._module = module  # type: ignore[assignment]
    monkeypatch.setattr(deps, "archivey_codecs", package)
    monkeypatch.setattr(native, "_too_old_logged", set())
    return module


# ── Selection ─────────────────────────────────────────────────────────────────────────


def test_an_absent_package_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        deps,
        "archivey_codecs",
        deps.LazyOptional(OptionalLibrary.ARCHIVEY_CODECS, present=False),
    )
    assert native.kernels("crc16_arc", frozenset()) is None
    assert lha_reader.crc16_for(frozenset()) is lha_reader.crc16


def test_an_excluded_package_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, crc16_arc=1)
    assert native.kernels("crc16_arc", EXCLUDED) is None
    assert lha_reader.crc16_for(EXCLUDED) is lha_reader.crc16


def test_a_current_kernel_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _fake(monkeypatch, crc16_arc=1, zipcrypto=2)
    assert native.kernels("crc16_arc", frozenset()) is module
    assert native.kernels("zipcrypto", frozenset()) is module  # newer is fine


@pytest.mark.parametrize("kernels", [{}, {"crc16_arc": 0}, {"crc16_arc": "1"}])
def test_an_old_or_missing_kernel_is_not_used_and_logged_once(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    kernels: dict[str, object],
) -> None:
    _fake(monkeypatch, **kernels)  # type: ignore[arg-type]
    with caplog.at_level(logging.DEBUG, logger="archivey.streams"):
        assert native.kernels("crc16_arc", frozenset()) is None
        assert native.kernels("crc16_arc", frozenset()) is None
    logged = [r for r in caplog.records if "'crc16_arc' kernel revision" in r.message]
    assert len(logged) == 1
    assert "needs 1 or newer" in logged[0].message


def test_a_panic_reaches_the_caller_as_corruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, crc16_arc=1)
    crc = lha_reader.crc16_for(frozenset())
    with pytest.raises(CorruptionError, match="CRC-16 decoder failed") as info:
        crc(b"abc", 0)
    assert isinstance(info.value.__cause__, PanicException)


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
def test_branch_filters_use_the_kernel_unless_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch, filter_id: int, kernel: str
) -> None:
    _fake(monkeypatch, **{kernel: 1})

    def built(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> object:
        make = branch_maker(
            filter_id,
            0x1000,
            excluded=excluded,
            natives=ISOLATED if isolated else IN_PROCESS,
        )
        assert make is not None
        return make()

    assert isinstance(built(frozenset(), isolated=False), native.NativeBranch)
    assert _FakeBranch.built == [0x1000]
    # Turned off, or under NATIVE_DECODERS until the decoder child runs the kernel.
    assert isinstance(built(EXCLUDED, isolated=False), PythonBranch)
    assert isinstance(built(frozenset(), isolated=True), PythonBranch)
    assert _FakeBranch.built == [0x1000]


def test_an_old_branch_kernel_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, arm64=0, riscv=1)
    make = branch_maker(FILTER_ARM64, 0, excluded=frozenset(), natives=IN_PROCESS)
    assert make is not None
    assert isinstance(make(), PythonBranch)
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
        assert repeat.value is info.value
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


def test_lzw_uses_the_kernel_unless_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, lzw=1)
    assert native.lzw(frozenset(), isolated=False) is not None
    assert native.lzw(EXCLUDED, isolated=False) is None
    assert native.lzw(frozenset(), isolated=True) is None
    _fake(monkeypatch, lzw=0)
    assert native.lzw(frozenset(), isolated=False) is None


def test_an_lzw_state_refuses_every_call_after_a_panic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, lzw=1)
    make = native.lzw(frozenset(), isolated=False)
    assert make is not None
    state = make()
    with pytest.raises(CorruptionError, match="LZW decoder failed") as info:
        state.feed(b"\x1f\x9d\x90abc")
    assert _FakeLzw.calls == 1
    for again in (state.flush, lambda: state.feed(b"more")):
        with pytest.raises(CorruptionError) as repeat:
            again()
        assert repeat.value is info.value
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


def test_lzo_uses_the_kernel_unless_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deps,
        "compress_utils",
        deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS, present=False),
    )
    _fake(monkeypatch, lzo1x=1)
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
        assert repeat.value is info.value
    assert _FakeDecryptor.calls == calls
    # Errors other than a panic leave the state usable.
    _FakeDecryptor.panic = False
    other = zipcrypto.new_keys(b"pw")
    with pytest.raises(TypeError):
        other.decrypt(None)  # type: ignore[arg-type]
    assert other.decrypt(b"abc") == zipcrypto.ZipCryptoKeys(b"pw").decrypt(b"abc")


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
    assert not native.caused_by_panic(plain)
    try:
        try:
            raise PanicException("boom")
        except PanicException as panic:
            raise CorruptionError("wrapped") from panic
    except CorruptionError as exc:
        assert native.caused_by_panic(exc)
        try:
            raise CorruptionError("outer") from exc
        except CorruptionError as outer:
            assert native.caused_by_panic(outer)


def test_other_exceptions_pass_unchanged() -> None:
    with pytest.raises(KeyboardInterrupt), native.panic_to_corruption("x"):
        raise KeyboardInterrupt


# ── The real package ──────────────────────────────────────────────────────────────────

needs_codecs = pytest.mark.skipif(
    not deps.archivey_codecs.available(), reason="archivey-codecs is not installed"
)


@needs_codecs
def test_lha_uses_the_kernel_and_reads_the_same() -> None:
    assert lha_reader.crc16_for(frozenset()) is not lha_reader.crc16
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
    assert isinstance(keys, native.NativeZipCrypto)
    assert isinstance(zipcrypto.new_keys(b"pw", EXCLUDED), zipcrypto.ZipCryptoKeys)
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
    assert isinstance(make(), native.NativeBranch)
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
    make = native.lzw(frozenset(), isolated=False)
    assert make is not None
    assert isinstance(make(), native.NativeLzw)
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


def _z_points(make_state: object, raw: bytes) -> tuple[bytes, list]:
    decoder = UnixCompressDecoder(
        make_state(),  # type: ignore[operator]
        comp_cursor=0,
        decomp_cursor=0,
        make_state=make_state,  # type: ignore[arg-type]
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
    make = native.lzw(frozenset(), isolated=False)
    assert make is not None
    out, points = _z_points(make, raw)
    assert out == data
    assert (out, points) == _z_points(LzwState, raw)
    assert len(points) >= 3  # the header point and the CLEARs
    template = UnixCompressDecoder(
        make(), comp_cursor=0, decomp_cursor=0, make_state=make
    )
    template.feed(raw[:3])  # reads the header
    for point in points[1:]:
        restarted = template.recreate(point, io.BytesIO())
        got = restarted.feed(raw[point.compressed_offset :]).data
        while not restarted.needs_input:
            got += restarted.feed(b"").data
        got += restarted.flush().data
        assert got == data[point.decompressed_offset :]


def _drive_lzw(state: object, data: bytes, cap: int) -> tuple:
    """Feed all of ``data`` with output capped at ``cap``, then call ``flush()``
    twice and ``feed()`` once more: the bytes, the CLEAR units, each call's
    error, and which calls returned output."""
    out = bytearray()
    units: list = []
    events: list = []

    def call(step: object) -> bool:
        try:
            got, more = step()  # type: ignore[operator]
        except (CorruptionError, UnsupportedFeatureError) as exc:
            events.append((type(exc).__name__, str(exc)))
            return False
        out.extend(got)
        units.extend(more)
        events.append(("ok", bool(got)))
        return True

    # One capped feed leaves most of the stream for flush().
    call(lambda: state.feed(data, cap))  # type: ignore[attr-defined]
    for step in (state.flush, state.flush, lambda: state.feed(b"x")):  # type: ignore[attr-defined]
        call(step)
    errors = [e for e in events if e[0] != "ok"]
    return bytes(out), units, errors, events[-3:]


@needs_codecs
@requires("ncompress")
def test_lzw_bad_code_inside_flush_raises_from_the_next_call() -> None:
    """A bad code met by ``flush()`` after some output: ``flush()`` returns that
    output and the next call raises, as ``LzwState`` does."""
    make = native.lzw(frozenset(), isolated=False)
    assert make is not None
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
        python = _drive_lzw(LzwState(), bytes(bad), cap)
        assert rust[:3] == python[:3]
        first_flush, second_flush, _ = rust[3]
        if first_flush == ("ok", True) and second_flush[0] != "ok":
            inside_flush += 1
    assert inside_flush > 0


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
    assert native.lzx(frozenset(), isolated=False) is not None
    rng = random.Random(29)
    for _, raw, names in _lzx_cabs():
        start = raw.index(b"a.txt\0") + 32  # past the file table, into the blocks
        variants = [raw, raw[: len(raw) // 2], raw[: len(raw) - 3]]
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


def test_cab_lzx_kernel_is_not_used_when_switched_off_or_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake(monkeypatch, lzx=1)
    assert native.lzx(frozenset(), isolated=False) is not None
    assert native.lzx(EXCLUDED, isolated=False) is None
    assert native.lzx(frozenset(), isolated=True) is None
    _fake(monkeypatch, lzx=0)
    assert native.lzx(frozenset(), isolated=False) is None


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
    module = _fake(monkeypatch, lzx=1)
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
    assert native.bcj2(frozenset(), isolated=False) is not None
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
    assert native.bcj2(frozenset(), isolated=False) is not None
    assert native.bcj2(EXCLUDED, isolated=False) is None
    assert native.bcj2(frozenset(), isolated=True) is None
    _fake(monkeypatch, bcj2=0)
    assert native.bcj2(frozenset(), isolated=False) is None


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
    assert again.value is info.value
    assert _FakeBcj2.calls == 1
    python = Bcj2DecoderStream(
        *(io.BytesIO(s) for s in streams),
        unpack_size=1000,
        excluded=frozenset(),
        isolated=True,
    )
    assert len(python.read(1000)) == 1000
