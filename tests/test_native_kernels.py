"""archivey-codecs kernels: when archivey uses one, and that the result is the same.

The selection rows (design D4, D5) run with a fake package, so they need nothing
installed. The read tests use the real package and skip without it.
"""

from __future__ import annotations

import io
import logging
import types
import zipfile

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
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


def _fake(monkeypatch: pytest.MonkeyPatch, **kernels: int) -> types.SimpleNamespace:
    """Install a fake ``archivey_codecs`` whose ``KERNELS`` is ``kernels``."""

    def crc16_arc(data: bytes, value: int = 0) -> int:
        raise PanicException("index out of bounds")

    module = types.SimpleNamespace(KERNELS=kernels, crc16_arc=crc16_arc)
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
    logged = [r for r in caplog.records if "crc16_arc kernel revision" in r.message]
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
