"""Regression tests for the second audit: TAR and single-file compressed streams.

Each test asserts the promised behaviour that one of that audit's findings broke. The
promise each test checks is named in its docstring.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import random
import struct
import tarfile
import zlib
from pathlib import Path

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveFormat,
    ArchiveyConfig,
    ExtractionPolicy,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    DiagnosticRaisedError,
    UnsupportedFeatureError,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.codecs.xz_decoder import XzDecompressorStream
from tests.conftest import requires
from tests.test_audit_tar_streams import _TRAILER, _gnu_sparse, _member

_ACCEL_ON = ArchiveyConfig(
    use_rapidgzip=AcceleratorMode.ON, use_indexed_bzip2=AcceleratorMode.ON
)


def _read_single(
    data: bytes,
    fmt: ArchiveFormat,
    *,
    config: ArchiveyConfig | None = None,
    streaming: bool = False,
    seekable_members: bool = False,
) -> tuple[bytes, dict[DiagnosticCode, int]]:
    """The one member of a single-file stream, and the diagnostics the read left."""
    with open_archive(
        io.BytesIO(data),
        format=fmt,
        config=config,
        streaming=streaming,
        seekable_members=seekable_members and not streaming,
    ) as ar:
        if streaming:
            out = b""
            for _member_, stream in ar.stream_members():
                assert stream is not None
                out = stream.read()
        else:
            with ar.open(ar.members()[0]) as stream:
                out = stream.read()
        return out, dict(ar.diagnostics.counts)


# ---------------------------------------------------------------------------
# T14: xz with a check type liblzma does not implement reads with DIGEST_UNVERIFIABLE
# ---------------------------------------------------------------------------


def _xz_with_check_id(raw: bytes, check_id: int) -> bytes:
    """``raw`` as a one-block xz whose stream flags name ``check_id``.

    Built as CRC32 (a 4-byte check field), then the header and footer flags rewritten
    with their CRCs fixed. IDs 2 and 3 are reserved with a 4-byte field too, so the
    block layout stays valid; liblzma knows the size but not the algorithm.
    """
    data = bytearray(lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32))
    flags = bytes([0, check_id])
    data[6:8] = flags
    data[8:12] = struct.pack("<I", zlib.crc32(flags))
    data[-4:-2] = flags
    data[-12:-8] = struct.pack("<I", zlib.crc32(bytes(data[-8:-2])))
    return bytes(data)


def _flip_in_stored_body(compressed: bytes, raw: bytes) -> bytes:
    """``compressed`` with one bit flipped inside ``raw``'s verbatim-stored bytes."""
    middle = len(raw) // 2
    at = compressed.find(raw[middle : middle + 100])
    assert at >= 0, "fixture premise: the body is stored verbatim (LZMA2 raw chunk)"
    damaged = bytearray(compressed)
    damaged[at + 50] ^= 0x01
    return bytes(damaged)


_STRICT = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("check_id", [2, 3])
def test_xz_unsupported_check_type_is_not_silent(
    check_id: int, streaming: bool
) -> None:
    """D6b: 'every integrity check the archive offers must have run'. The stream
    declares a check; liblzma cannot compute it and skips it without telling
    CPython (which never asks for LZMA_TELL_UNSUPPORTED_CHECK), so a flipped byte in
    the body reads as good data. ``xz -t`` says "Unsupported type of integrity
    check; not verifying file integrity" and exits 2. The maintainer's ruling is to
    warn and keep reading: ``DIGEST_UNVERIFIABLE``, which ``STRICT`` refuses."""
    raw = random.Random(1).randbytes(5000)
    damaged = _flip_in_stored_body(_xz_with_check_id(raw, check_id), raw)
    out, diagnostics = _read_single(damaged, ArchiveFormat.XZ, streaming=streaming)
    assert out != raw, "fixture premise: the flipped byte reaches the output"
    assert DiagnosticCode.DIGEST_UNVERIFIABLE in diagnostics, (
        "damaged xz content returned with no error and no diagnostic"
    )
    with pytest.raises(DiagnosticRaisedError):
        _read_single(damaged, ArchiveFormat.XZ, config=_STRICT, streaming=streaming)


@pytest.mark.parametrize("streaming", [False, True])
def test_xz_without_a_check_is_not_unverifiable(streaming: bool) -> None:
    """Check ID 0 declares no check, so there is nothing that failed to run."""
    raw = random.Random(3).randbytes(5000)
    data = lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE)
    out, diagnostics = _read_single(
        data, ArchiveFormat.XZ, config=_STRICT, streaming=streaming
    )
    assert out == raw
    assert DiagnosticCode.DIGEST_UNVERIFIABLE not in diagnostics


def test_xz_unsupported_check_in_a_later_stream_is_reported() -> None:
    """A multi-stream file whose second stream alone names an unsupported check."""
    first = lzma.compress(b"a" * 100, format=lzma.FORMAT_XZ)
    second = _xz_with_check_id(b"b" * 100, 3)
    out, diagnostics = _read_single(first + second, ArchiveFormat.XZ)
    assert out == b"a" * 100 + b"b" * 100
    assert DiagnosticCode.DIGEST_UNVERIFIABLE in diagnostics


def test_xz_unsupported_check_reached_by_a_block_resume_is_reported_once() -> None:
    """A cold seek into the second stream resumes from its block and never reads that
    stream's header; the check comes from the index. Decoding it again from the start
    does not report it a second time."""
    first = lzma.compress(b"a" * 1000, format=lzma.FORMAT_XZ)
    second = _xz_with_check_id(b"b" * 1000, 2)
    collector = DiagnosticCollector()
    stream = XzDecompressorStream(io.BytesIO(first + second), collector=collector)
    stream.seek(-10, os.SEEK_END)
    assert stream.read() == b"b" * 10
    assert collector.snapshot().counts[DiagnosticCode.DIGEST_UNVERIFIABLE] == 1
    stream.seek(0)
    stream.read()
    assert collector.snapshot().counts[DiagnosticCode.DIGEST_UNVERIFIABLE] == 1


@pytest.mark.parametrize("streaming", [False, True])
def test_tar_xz_unsupported_check_type_is_not_silent(streaming: bool) -> None:
    """The same gap through the TAR reader: the member reads back damaged, and the
    archive's diagnostics say the xz check did not run."""
    payload = random.Random(2).randbytes(200_000)
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as t:
        info = tarfile.TarInfo("a")
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
    raw_tar = tar.getvalue()
    damaged = _flip_in_stored_body(_xz_with_check_id(raw_tar, 2), payload)
    with open_archive(
        io.BytesIO(damaged), format=ArchiveFormat.TAR_XZ, streaming=streaming
    ) as ar:
        read = [s.read() for _m, s in ar.stream_members() if s is not None]
        diagnostics = dict(ar.diagnostics.counts)
    assert read != [payload], "fixture premise: the flipped byte reaches the member"
    assert DiagnosticCode.DIGEST_UNVERIFIABLE in diagnostics
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(
            io.BytesIO(damaged),
            format=ArchiveFormat.TAR_XZ,
            streaming=streaming,
            config=_STRICT,
        ) as ar,
    ):
        for _m, s in ar.stream_members():
            if s is not None:
                s.read()


# ---------------------------------------------------------------------------
# T15: the bzip2 accelerator never checks a stream's combined CRC
# ---------------------------------------------------------------------------

_BZ2_BLOCK_MAGIC = f"{0x314159265359:048b}"
_BZ2_EOS_MAGIC = f"{0x177245385090:048b}"


def _bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def _from_bits(bits: str) -> bytes:
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _bz2_without_a_block() -> tuple[bytes, bytes]:
    """A four-block ``.bz2`` and the same stream with its second block cut out.

    Blocks are bit-aligned and each carries its own CRC, so the three that remain
    still decode and pass their checks. Only the stream's combined CRC, in the
    end-of-stream marker, covers the block sequence.
    """
    payload = b"".join(random.Random(i).randbytes(60_000) for i in range(6))
    good = bz2.compress(payload, 1)
    bits = _bits(good)
    starts = []
    at = bits.find(_BZ2_BLOCK_MAGIC)
    while at != -1:
        starts.append(at)
        at = bits.find(_BZ2_BLOCK_MAGIC, at + 1)
    assert len(starts) >= 3, "fixture premise: several blocks"
    return payload, _from_bits(bits[: starts[1]] + bits[starts[2] :])


def _bz2_with_bad_combined_crc() -> tuple[bytes, bytes]:
    payload = random.Random(3).randbytes(300_000)
    bits = list(_bits(bz2.compress(payload)))
    at = "".join(bits).rfind(_BZ2_EOS_MAGIC) + 48 + 5
    bits[at] = "1" if bits[at] == "0" else "0"
    return payload, _from_bits("".join(bits))


def test_bz2_fixtures_are_refused_by_the_standard_library() -> None:
    """Premise for T15: both damaged streams fail ``bz2`` and archivey's own
    standard-library path."""
    for _payload, damaged in (_bz2_without_a_block(), _bz2_with_bad_combined_crc()):
        with pytest.raises(OSError):
            bz2.decompress(damaged)
        with pytest.raises(CorruptionError):
            _read_single(damaged, ArchiveFormat.BZ2)


@requires("rapidgzip")
def test_bz2_accelerator_refuses_a_stream_with_a_block_removed() -> None:
    """compressed-streams: 'An accelerator preserves the error contract of the path
    it replaces'; bzip2.md says every block's CRC and the combined CRC are checked on
    read. Under the default config a caller who declares ``seekable_members=True``
    gets the accelerator (AUTO), and 100 000 of the 360 000 bytes are silently
    missing from the result."""
    payload, damaged = _bz2_without_a_block()
    try:
        out, _diagnostics = _read_single(
            damaged, ArchiveFormat.BZ2, config=ArchiveyConfig(), seekable_members=True
        )
    except CorruptionError:
        return
    # Not a bare ``==``: pytest's diff of two 360 kB byte strings can take minutes.
    if out != payload:
        pytest.fail(f"read {len(out)} of {len(payload)} bytes with no error")


@requires("rapidgzip")
def test_bz2_accelerator_checks_the_combined_crc() -> None:
    """The narrow form: one bit flipped in the end-of-stream CRC."""
    _payload, damaged = _bz2_with_bad_combined_crc()
    with pytest.raises(CorruptionError):
        _read_single(
            damaged, ArchiveFormat.BZ2, config=_ACCEL_ON, seekable_members=True
        )


@requires("rapidgzip")
def test_bz2_accelerator_combined_crc_check_per_stream() -> None:
    """The check runs per stream: concatenated streams (with an empty one between)
    followed by zero padding read clean, and a stream with a block removed is refused
    when it is not the first."""
    payload, damaged = _bz2_without_a_block()
    head = b"head" * 1000
    good = (
        bz2.compress(head) + bz2.compress(b"") + bz2.compress(payload, 1) + b"\0" * 64
    )
    out, _diagnostics = _read_single(
        good, ArchiveFormat.BZ2, config=_ACCEL_ON, seekable_members=True
    )
    if out != head + payload:
        pytest.fail(f"read {len(out)} of {len(head + payload)} bytes")
    with pytest.raises(CorruptionError):
        _read_single(
            bz2.compress(head) + damaged,
            ArchiveFormat.BZ2,
            config=_ACCEL_ON,
            seekable_members=True,
        )


# ---------------------------------------------------------------------------
# T16: the gzip accelerator and the members the standard library refuses
# ---------------------------------------------------------------------------


def _gzip_cases() -> dict[str, bytes]:
    payload = random.Random(4).randbytes(200_000)
    member = gzip.compress(payload, mtime=0)
    header = bytearray(member[:10])
    header[3] |= 0x02  # FHCRC
    crc16 = (zlib.crc32(bytes(header)) & 0xFFFF) ^ 0x0001
    return {
        "header-crc-mismatch": bytes(header) + struct.pack("<H", crc16) + member[10:],
        "reserved-flag-bit": member[:3] + bytes([0x20]) + member[4:],
    }


@requires("rapidgzip")
@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("header-crc-mismatch", CorruptionError),
        ("reserved-flag-bit", UnsupportedFeatureError),
    ],
)
def test_gzip_accelerator_refuses_what_the_stdlib_refuses(
    case: str, error: type[Exception]
) -> None:
    """compressed-streams: 'An accelerator preserves the error contract of the path
    it replaces'. The standard-library path refuses each (zlib: "header crc
    mismatch", "unknown header flags set");
    under ``use_rapidgzip=ON`` each read as good data. The first member's header is
    now checked with zlib before rapidgzip is started. RFC 1952 §2.3.1.2 requires an
    error for reserved flag bits; gzip calls them "not supported", so that refusal is
    UnsupportedFeatureError, and a header CRC mismatch is corruption."""
    data = _gzip_cases()[case]
    with pytest.raises(error):
        _read_single(data, ArchiveFormat.GZ)
    with pytest.raises(error):
        _read_single(data, ArchiveFormat.GZ, config=_ACCEL_ON, seekable_members=True)


@requires("rapidgzip")
@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("header-crc-mismatch", CorruptionError),
        ("reserved-flag-bit", UnsupportedFeatureError),
    ],
)
def test_gzip_accelerator_refuses_a_later_member_the_stdlib_refuses(
    case: str, error: type[Exception]
) -> None:
    """The same refusals on a member after the first.

    rapidgzip 0.16 rejects a later header CRC itself. A later reserved flag it
    accepts, and the further-member scan skips that header, so the trailer check
    hands the read to zlib. Either way the error class matches the standard library.
    The accelerator may differ only on a wrong ISIZE of a member other than the last.
    """
    data = gzip.compress(b"A" * 10_000, mtime=0) + _gzip_cases()[case]
    with pytest.raises(error):
        _read_single(data, ArchiveFormat.GZ)
    with pytest.raises(error):
        _read_single(data, ArchiveFormat.GZ, config=_ACCEL_ON, seekable_members=True)


def _two_gzip_members(first_isize_delta: int, second_crc_delta: int = 0) -> bytes:
    """Two members of the same payload; the first's ISIZE and the second's CRC-32 can be
    made wrong."""
    payload = random.Random(4).randbytes(200_000)
    member = gzip.compress(payload, mtime=0)
    crc, isize = struct.unpack("<II", member[-8:])
    first = member[:-4] + struct.pack("<I", isize + first_isize_delta)
    second = member[:-8] + struct.pack("<II", crc ^ second_crc_delta, isize)
    return first + second


@requires("rapidgzip")
def test_gzip_accelerator_reads_a_wrong_isize_on_a_member_before_the_last() -> None:
    """compressed-streams: an accelerator MAY differ on a wrong ISIZE on a member other
    than the last, when every member's CRC-32 is checked. zlib raises ("incorrect
    length check"); rapidgzip reads both members, each under its CRC."""
    data = _two_gzip_members(first_isize_delta=7)
    with pytest.raises(CorruptionError):
        _read_single(data, ArchiveFormat.GZ)
    out, _diagnostics = _read_single(
        data, ArchiveFormat.GZ, config=_ACCEL_ON, seekable_members=True
    )
    assert out == random.Random(4).randbytes(200_000) * 2


@requires("rapidgzip")
@pytest.mark.parametrize("accelerated", [False, True])
def test_gzip_wrong_crc_on_a_later_member_raises(accelerated: bool) -> None:
    """The CRC-32 that makes the ISIZE difference harmless is checked on both paths,
    on the second member too."""
    data = _two_gzip_members(first_isize_delta=0, second_crc_delta=1)
    with pytest.raises(CorruptionError):
        _read_single(
            data,
            ArchiveFormat.GZ,
            config=_ACCEL_ON if accelerated else None,
            seekable_members=accelerated,
        )


@requires("rapidgzip")
def test_gzip_accelerator_reads_a_header_with_a_good_crc() -> None:
    """The header check refuses only what zlib refuses: FNAME plus a matching FHCRC
    reads back whole under the accelerator."""
    payload = random.Random(5).randbytes(200_000)
    member = gzip.compress(payload, mtime=0)
    header = bytearray(member[:10])
    header[3] |= 0x02 | 0x08  # FHCRC, FNAME
    header += b"name.bin\0"
    crc16 = zlib.crc32(bytes(header)) & 0xFFFF
    data = bytes(header) + struct.pack("<H", crc16) + member[10:]
    out, _diagnostics = _read_single(
        data, ArchiveFormat.GZ, config=_ACCEL_ON, seekable_members=True
    )
    if out != payload:
        pytest.fail(f"read {len(out)} of {len(payload)} bytes")


# ---------------------------------------------------------------------------
# T17: accelerator member streams seek differently from the stdlib ones
# ---------------------------------------------------------------------------


def _single_member_stream_positions(
    data: bytes, fmt: ArchiveFormat, config: ArchiveyConfig
) -> tuple[object, object]:
    with (
        open_archive(
            io.BytesIO(data), format=fmt, config=config, seekable_members=True
        ) as ar,
        ar.open(ar.members()[0]) as stream,
    ):
        past_end = stream.seek(1500)
        stream.seek(100)
        try:
            underflow: object = stream.seek(-500, io.SEEK_CUR)
        except Exception as exc:  # noqa: BLE001 - the type is what is compared
            underflow = type(exc)
    return past_end, underflow


@requires("rapidgzip")
@pytest.mark.parametrize("codec", ["gz", "bz2"])
def test_accelerated_member_stream_seeks_like_the_stdlib_one(codec: str) -> None:
    """An accelerator changes speed, not behaviour. On a 1000-byte member the
    stdlib path (and ``io.BytesIO``) returns 1500 for ``seek(1500)`` and clamps
    ``seek(-500, SEEK_CUR)`` from 100 to 0. rapidgzip returns 1000 for the first; the
    gzip child raises ``ValueError: negative seek position -400`` for the second."""
    payload = b"x" * 1000
    if codec == "gz":
        data, fmt = gzip.compress(payload), ArchiveFormat.GZ
    else:
        data, fmt = bz2.compress(payload), ArchiveFormat.BZ2
    off = ArchiveyConfig(
        use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
    )
    assert _single_member_stream_positions(data, fmt, off) == (1500, 0)
    assert _single_member_stream_positions(data, fmt, _ACCEL_ON) == (1500, 0)


# ---------------------------------------------------------------------------
# T18: a TAR uid/gid outside uid_t reaches os.chown as a raw OverflowError
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("uid", [2**40, -2], ids=["2**40", "-2"])
def test_tar_out_of_range_uid_does_not_abort_trusted_extraction(
    uid: int, streaming: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """error-handling: nothing the library raises is a builtin. A PAX ``uid`` record
    (or a base-256 uid field) can hold any integer; the TAR reader passes it through
    unchecked, and ``_apply_metadata`` catches only ``OSError`` around ``os.chown``,
    which raises ``OverflowError`` before any syscall. ``geteuid`` is patched to 0,
    which is all the TRUSTED-as-root branch checks; the overflow happens before the
    kernel could refuse a non-root caller."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    data = _member("f", b"x", pax_headers={"uid": str(uid)}) + _TRAILER
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            ar.extract_all(tmp_path / "out", policy=ExtractionPolicy.TRUSTED)
    except ArchiveyError:
        pass


# ---------------------------------------------------------------------------
# T19: a sparse member's real size is not held to the T3 bound
# ---------------------------------------------------------------------------


def _sparse_huge(kind: str, realsize: int) -> bytes:
    if kind == "old-gnu":
        return (
            _gnu_sparse("sp", [(0, 10)], realsize, b"A" * 10)
            + _member("b", b"bye")
            + _TRAILER
        )
    pax = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "sp",
        "GNU.sparse.realsize": str(realsize),
    }
    body = b"1\n0\n5\n".ljust(512, b"\0") + b"BBBBB"
    return _member("GNUSparseFile.0/sp", body, pax_headers=pax) + _TRAILER


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("kind", ["old-gnu", "pax-1.0"])
@pytest.mark.parametrize("realsize", [2**63, 2**70], ids=["2**63", "2**70"])
def test_tar_sparse_realsize_past_any_file_is_typed(
    realsize: int, kind: str, streaming: bool
) -> None:
    """error-handling: archive content never surfaces as a builtin exception. T3
    refused a plain size of 2**63 or more; a sparse member's logical size comes from
    the GNU ``realsize`` field or ``GNU.sparse.realsize`` instead, and nothing bounded
    it. tarfile fills the trailing hole with ``NUL * length``, which raises
    ``OverflowError: cannot fit 'int' into an index-sized integer`` (and at 2**63
    exactly, ``MemoryError``). A 2 KiB archive; a chunked read(65536) works."""
    data = _sparse_huge(kind, realsize)
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            for member, stream in ar.stream_members():
                if stream is not None and member.name == "sp":
                    stream.read()
    except ArchiveyError:
        pass
