"""archivey-codecs kernels: when archivey uses one, and that the result is the same.

The selection rows (design D4, D5) run with a fake package, so they need nothing
installed. The read tests use the real package and skip without it.
"""

from __future__ import annotations

import io
import logging
import random
import types
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
    EncryptionError,
    FormatPolicy,
    OptionalLibrary,
    ProcessIsolation,
    StreamFormat,
    TruncatedError,
    open_archive,
    open_stream,
)
from archivey.internal import native
from archivey.internal.backends import lha_reader, zipcrypto
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64, arm64_decode
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
from archivey.internal.streams.codecs.lzma_filter_decoder import (
    PythonBranch,
    branch_maker,
)
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV, riscv_decode
from archivey.internal.streams.codecs.unix_compress_decoder import (
    LzwState,
    UnixCompressDecoder,
)
from tests.conftest import requires
from tests.lha_util import Member, archive
from tests.streams_util import make_unix_compress
from tests.zipcrypto import build_stored_zipcrypto_zip, build_zipcrypto_zip

EXCLUDED = frozenset({OptionalLibrary.ARCHIVEY_CODECS})
OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-codecs"}))
RISCV_7Z = Path(__file__).parent / "fixtures" / "sevenzip" / "riscv_lzma2.7z"


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
    module = types.SimpleNamespace(
        KERNELS=kernels,
        crc16_arc=crc16_arc,
        zipcrypto=types.SimpleNamespace(Decryptor=_FakeDecryptor),
        filters=types.SimpleNamespace(Arm64Decoder=_FakeArm64, RiscvDecoder=_FakeRiscv),
        lzw=types.SimpleNamespace(Decompressor=_FakeLzw),
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
    cases = [raw, raw[:-7], raw[:2], raw[:3]]
    for at in (len(raw) // 3, len(raw) // 2, len(raw) - 40):
        bad = bytearray(raw)
        bad[at] ^= 0x5A
        cases.append(bytes(bad))
    for case in cases:
        if piece == 1:
            case = case[:1500]
        assert _read_z(case, None, piece) == _read_z(case, OFF, piece)
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
