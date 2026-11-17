"""Correctness regressions from the outside RAR sweep of 2026-11-15.

Each test asserts the expected reading behavior. Unresolved findings carry strict
xfail markers whose reasons identify the defects.
"""

from __future__ import annotations

import io
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    CorruptionError,
    SpoolLimits,
    TruncatedError,
    open_archive,
)
from archivey.internal.hashing.blake2sp import blake2sp as blake2sp_digest
from tests.conftest import requires_unrar_cli, unrar_reads_from_pipes
from tests.test_rar_forward import _pipe

pytestmark = pytest.mark.skipif(
    not unrar_reads_from_pipes(), reason="requires RARLAB unrar 7.00 or later"
)


@requires_unrar_cli()
def test_a_truncated_pipe_member_never_verifies_zero_padding(tmp_path: Path) -> None:
    payload = bytes(6 << 20)
    # Built by hand, as ``rar a -ma5 -m0`` stores it: CI never installs the RAR writer.
    cut = _rar5(_rar5_file("a", payload))[: 5 << 20]
    path = tmp_path / "cut.rar"
    path.write_bytes(cut)
    oracle = subprocess.run(
        ["unrar", "t", "-cfg-", "-inul", str(path)], check=False, capture_output=True
    )
    assert oracle.returncode == 3
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=2 << 20))
    with open_archive(io.BytesIO(cut), streaming=True, config=config) as reader:
        members = reader.stream_members()
        member, stream = next(members)
        assert member.size == len(payload)
        assert stream is not None
        with pytest.raises(TruncatedError):
            stream.read()
    # The missing bytes are zero in the original. Invented padding therefore passes
    # the member's CRC. The error must come from the source ending, not the digest.
    with open_archive(_pipe(cut), streaming=True, config=config) as reader:
        members = reader.stream_members()
        member, stream = next(members)
        assert member.size == len(payload)
        assert stream is not None
        with pytest.raises(TruncatedError, match="cut short"):
            stream.read()


def _vint(value: int) -> bytes:
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _block(body: bytes) -> bytes:
    framed = _vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(framed)) + framed


def _rar5_file(
    name: str,
    payload: bytes,
    *,
    padded: bool = False,
    blake2sp: bool | bytes = False,
) -> bytes:
    """A stored RAR5 FILE header and its data, with a CRC32 or a BLAKE2sp digest.

    ``blake2sp`` may be the digest itself: the pure-Python hasher takes about two
    seconds per MiB. With ``padded``, the header's extra area holds one padding
    byte. The native walk permits this byte, and RARLAB unrar tests the complete
    member successfully.
    """
    extra = b""
    if blake2sp:
        digest = blake2sp if isinstance(blake2sp, bytes) else blake2sp_digest(payload)
        record = _vint(2) + _vint(0) + digest  # HASH, BLAKE2sp
        extra += _vint(len(record)) + record
    if padded:
        extra += b"\x00"
    fields = (
        _vint(0 if blake2sp else 4)  # file flags: CRC32 unless BLAKE2sp
        + _vint(len(payload))
        + _vint(0o100644)
        + (b"" if blake2sp else struct.pack("<I", zlib.crc32(payload)))
        + _vint(0)  # stored
        + _vint(1)  # Unix
        + _vint(len(name.encode()))
        + name.encode()
    )
    header = (
        (b"\x02\x03" + _vint(len(extra)) if extra else b"\x02\x02")  # type, flags
        + _vint(len(payload))
        + fields
        + extra
    )
    return _block(header) + payload


def _rar5(*files: bytes) -> bytes:
    """A RAR5 archive holding ``files`` built by :func:`_rar5_file`."""
    return (
        b"Rar!\x1a\x07\x01\x00"
        + _block(b"\x01\x00\x00")  # MAIN
        + b"".join(files)
        + _block(b"\x05\x00\x00")  # ENDARC
    )


@requires_unrar_cli()
@pytest.mark.xfail(
    strict=True,
    raises=CorruptionError,
    reason="R2: Splitting a RAR5 member rejects extra-area padding that unrar accepts",
)
def test_extra_area_padding_survives_a_rolling_volume_split(tmp_path: Path) -> None:
    payload = bytes(range(251)) * 40
    raw = _rar5(_rar5_file("a", payload, padded=True))
    path = tmp_path / "padded.rar"
    path.write_bytes(raw)
    subprocess.run(
        ["unrar", "t", "-cfg-", "-inul", str(path)], check=True, capture_output=True
    )
    oracle = subprocess.run(
        ["unrar", "p", "-cfg-", "-inul", str(path), "a"],
        check=True,
        capture_output=True,
    )
    assert oracle.stdout == payload
    with open_archive(path) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read() == payload
    with open_archive(_pipe(raw), streaming=True) as reader:
        assert [
            (m.name, s.read() if s else None) for m, s in reader.stream_members()
        ] == [("a", payload)]
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=4000))
    with open_archive(_pipe(raw), streaming=True, config=config) as reader:
        assert [
            (m.name, s.read() if s else None) for m, s in reader.stream_members()
        ] == [("a", payload)]
