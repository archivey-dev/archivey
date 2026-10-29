"""Damaged DEFLATE member payloads in ZIP and 7z fail the same way under rapidgzip.

rapidgzip ends some cut or damaged streams softly, by design. For a bare gzip stream the
codec backstops that (``test_accelerator_corruption.py``); for a container member the
guard is the member's size and CRC. These tests force the accelerator on, check that a
rapidgzip decoder process really served the member, and compare the outcome with the
standard library's.
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest

from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from tests.conftest import requires, requires_binary
from tests.test_audit2_zip import _build_zip, _Entry, _outcome, _raw_deflate

pytestmark = requires("rapidgzip")

# About 4.6 MiB of text that compresses to about 1.4 MiB: several rapidgzip chunks.
_PAYLOAD = b"".join(b"%d " % i for i in range(700_000))


def _flip_middle(data: bytes) -> bytes:
    out = bytearray(data)
    middle = len(out) // 2
    for i in range(middle, middle + 16):
        out[i] ^= 0x5A
    return bytes(out)


def _outcomes(blob: bytes, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """The outcome of a full read with the accelerator off and on, with and without
    declared seeking; also asserts that every ``ON`` read started a rapidgzip child."""
    started = 0
    init = RapidgzipChildStream.__init__

    def counting_init(self: RapidgzipChildStream, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        nonlocal started
        started += 1
        init(self, *args, **kwargs)

    monkeypatch.setattr(RapidgzipChildStream, "__init__", counting_init)
    results: dict[str, object] = {}
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        for seekable in (False, True):
            started = 0
            config = ArchiveyConfig(use_rapidgzip=mode)
            results[f"{mode.name}/{seekable}"] = _outcome(
                blob, config=config, seekable_members=seekable
            )
            assert started == (1 if mode is AcceleratorMode.ON else 0)
    return results


def _assert_all_raise(results: dict[str, object], expected: type[Exception]) -> None:
    for key, (verdict, error) in results.items():  # type: ignore[misc]
        assert verdict == "raise", key
        assert error is expected, key


_STREAM = _raw_deflate(_PAYLOAD, level=6)


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        pytest.param(_flip_middle(_STREAM), CorruptionError, id="flipped-middle"),
        pytest.param(_STREAM[:-64] + bytes(64), CorruptionError, id="zeroed-tail"),
        pytest.param(_STREAM[: len(_STREAM) // 2], TruncatedError, id="cut-in-half"),
    ],
)
def test_a_damaged_zip_deflate_member_fails_alike_with_rapidgzip_on(
    stored: bytes, expected: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sizes and CRC describe the intact payload; the stored stream is damaged."""
    blob = _build_zip([_Entry(b"a", stored, method=8, plain=_PAYLOAD)])
    _assert_all_raise(_outcomes(blob, monkeypatch), expected)


def test_an_intact_zip_deflate_member_reads_alike_with_rapidgzip_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = _build_zip([_Entry(b"a", _STREAM, method=8, plain=_PAYLOAD)])
    assert len(set(_outcomes(blob, monkeypatch).values())) == 1


def _7z_deflate(tmp_path: Path) -> tuple[bytes, int]:
    """A 7z holding one Deflate member, and where its packed stream ends."""
    (tmp_path / "a.txt").write_bytes(_PAYLOAD)
    archive = tmp_path / "a.7z"
    subprocess.run(
        ["7z", "a", "-m0=Deflate", "-bd", "-bso0", str(archive), "a.txt"],
        cwd=tmp_path,
        check=True,
    )
    data = archive.read_bytes()
    (next_header_offset,) = struct.unpack_from("<Q", data, 12)
    # The packed stream sits between the 32-byte start header and the next header.
    return data, 32 + next_header_offset


@requires_binary("7z")
@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        pytest.param("flip", TruncatedError, id="flipped-middle"),
        pytest.param("zero", CorruptionError, id="zeroed-tail"),
    ],
)
def test_a_damaged_7z_deflate_member_fails_alike_with_rapidgzip_on(
    damage: str,
    expected: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, packed_end = _7z_deflate(tmp_path)
    if damage == "flip":
        packed = _flip_middle(data[32:packed_end])
    else:
        packed = data[32 : packed_end - 64] + bytes(64)
    blob = data[:32] + packed + data[packed_end:]
    results = _outcomes(blob, monkeypatch)
    _assert_all_raise(results, expected)


@requires_binary("7z")
def test_an_intact_7z_deflate_member_reads_alike_with_rapidgzip_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = _7z_deflate(tmp_path)
    assert len(set(_outcomes(data, monkeypatch).values())) == 1
