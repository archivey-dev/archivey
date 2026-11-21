"""archivey-codecs kernels: when archivey uses one, and that the result is the same.

The selection rows (design D4, D5) run with a fake package, so they need nothing
installed. The read tests use the real package and skip without it.
"""

from __future__ import annotations

import io
import logging
import types
import zipfile
from typing import ClassVar

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
    EncryptionError,
    FormatPolicy,
    OptionalLibrary,
    open_archive,
)
from archivey.internal import native
from archivey.internal.backends import lha_reader, zipcrypto
from archivey.internal.streams.codecs import deps
from tests.lha_util import Member, archive
from tests.zipcrypto import build_stored_zipcrypto_zip, build_zipcrypto_zip

EXCLUDED = frozenset({OptionalLibrary.ARCHIVEY_CODECS})
OFF = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"archivey-codecs"}))


class PanicException(BaseException):
    """Stands in for PyO3's ``pyo3_runtime.PanicException``."""


PanicException.__module__ = "pyo3_runtime"


class _FakeDecryptor:
    """Stands in for ``archivey_codecs.zipcrypto.Decryptor``: Python's keys, recorded.

    With ``panic`` set, decrypting member data (anything but the 12-byte header)
    raises the fake panic.
    """

    built: ClassVar[list[bytes]] = []
    panic: ClassVar[bool] = False

    def __init__(self, password: bytes, keys: zipcrypto.ZipCryptoKeys | None = None):
        if keys is None:
            type(self).built.append(password)
            keys = zipcrypto.ZipCryptoKeys(password)
        self._password = password
        self._keys = keys

    def copy(self) -> _FakeDecryptor:
        return _FakeDecryptor(self._password, self._keys.copy())

    def decrypt(self, data: bytes) -> bytes:
        if self.panic and len(data) != zipcrypto.ZIPCRYPTO_HEADER_LEN:
            raise PanicException("index out of bounds")
        return self._keys.decrypt(data)


def _fake(monkeypatch: pytest.MonkeyPatch, **kernels: int) -> types.SimpleNamespace:
    """Install a fake ``archivey_codecs`` whose ``KERNELS`` is ``kernels``."""

    def crc16_arc(data: bytes, value: int = 0) -> int:
        raise PanicException("index out of bounds")

    monkeypatch.setattr(_FakeDecryptor, "built", [])
    monkeypatch.setattr(_FakeDecryptor, "panic", False)
    module = types.SimpleNamespace(
        KERNELS=kernels,
        crc16_arc=crc16_arc,
        zipcrypto=types.SimpleNamespace(Decryptor=_FakeDecryptor),
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
