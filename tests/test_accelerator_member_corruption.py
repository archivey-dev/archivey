"""Damaged DEFLATE member payloads in ZIP and 7z fail the same way under rapidgzip.

rapidgzip ends some cut or damaged streams softly, by design. For a bare gzip stream the
codec backstops that (``test_accelerator_corruption.py``); for a container member the
guard is the member's size and CRC. These tests force the accelerator on, check that the
accelerated path was selected (one rapidgzip child stream opened per ``ON`` read; the
standard library may still finish the decode after a crash or a soft end), and compare
the outcome with the standard library's alone.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.exceptions import CorruptionError
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from tests.conftest import requires, requires_binary, run_7z
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


def _outcomes(
    blob: bytes, monkeypatch: pytest.MonkeyPatch
) -> dict[str, tuple[str, object]]:
    """The outcome of a full read with the accelerator off and on, with and without
    declared seeking; also asserts that every ``ON`` read opened exactly one rapidgzip
    child stream and every ``OFF`` read none."""
    started = 0
    init = RapidgzipChildStream.__init__

    def counting_init(
        self: RapidgzipChildStream, *args: object, **kwargs: object
    ) -> None:
        nonlocal started
        started += 1
        init(self, *args, **kwargs)

    monkeypatch.setattr(RapidgzipChildStream, "__init__", counting_init)
    results: dict[str, tuple[str, object]] = {}
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        for seekable in (False, True):
            started = 0
            config = ArchiveyConfig(use_rapidgzip=mode)
            results[f"{mode.name}/{seekable}"] = _outcome(
                blob, config=config, seekable_members=seekable
            )
            assert started == (1 if mode is AcceleratorMode.ON else 0)
    return results


def _assert_all_raise_alike(results: dict[str, tuple[str, object]]) -> None:
    """All four reads raise the same class, and it is damage. Which side of the
    truncated/corrupt split a case lands on is best-effort (DR-4), so only agreement
    and the base class are pinned."""
    assert len(set(results.values())) == 1, results
    ((verdict, error),) = set(results.values())
    assert verdict == "raise"
    assert isinstance(error, type) and issubclass(error, CorruptionError)


_INTACT = ("ok", hashlib.sha256(_PAYLOAD).hexdigest())


_STREAM = _raw_deflate(_PAYLOAD, level=6)


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param(_flip_middle(_STREAM), id="flipped-middle"),
        pytest.param(_STREAM[:-64] + bytes(64), id="zeroed-tail"),
        pytest.param(_STREAM[: len(_STREAM) // 2], id="cut-in-half"),
    ],
)
def test_a_damaged_zip_deflate_member_fails_alike_with_rapidgzip_on(
    stored: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sizes and CRC describe the intact payload; the stored stream is damaged."""
    blob = _build_zip([_Entry(b"a", stored, method=8, plain=_PAYLOAD)])
    _assert_all_raise_alike(_outcomes(blob, monkeypatch))


def test_an_intact_zip_deflate_member_reads_alike_with_rapidgzip_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = _build_zip([_Entry(b"a", _STREAM, method=8, plain=_PAYLOAD)])
    assert set(_outcomes(blob, monkeypatch).values()) == {_INTACT}


def _7z_deflate(tmp_path: Path) -> tuple[bytes, int]:
    """A 7z holding one Deflate member, and where its next header starts."""
    (tmp_path / "a.txt").write_bytes(_PAYLOAD)
    archive = tmp_path / "a.7z"
    run_7z(
        ["a", "-m0=Deflate", "-bd", "-bso0", str(archive), "a.txt"],
        cwd=tmp_path,
        check=True,
    )
    data = archive.read_bytes()
    (next_header_offset,) = struct.unpack_from("<Q", data, 12)
    return data, 32 + next_header_offset


@requires_binary("7z")
@pytest.mark.parametrize(
    "damage",
    [pytest.param("flip", id="flipped-middle"), pytest.param("zero", id="zeroed-tail")],
)
def test_a_damaged_7z_deflate_member_fails_alike_with_rapidgzip_on(
    damage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, packed_end = _7z_deflate(tmp_path)
    # The packed stream sits between the 32-byte start header and the next header. That
    # holds for a plain next header (kHeader, 0x01); a compressed one (kEncodedHeader)
    # would put its own packed stream at the end of that region, where the damage goes.
    assert data[packed_end] == 0x01, "7z wrote a compressed header"
    if damage == "flip":
        packed = _flip_middle(data[32:packed_end])
    else:
        packed = data[32 : packed_end - 64] + bytes(64)
    blob = data[:32] + packed + data[packed_end:]
    _assert_all_raise_alike(_outcomes(blob, monkeypatch))


@requires_binary("7z")
def test_an_intact_7z_deflate_member_reads_alike_with_rapidgzip_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = _7z_deflate(tmp_path)
    assert set(_outcomes(data, monkeypatch).values()) == {_INTACT}
