"""Regression tests for the second audit's native 7z findings (S9 onwards).

Every test asserts the behaviour the backend should have, and names the finding that
broke it. Hand-built archives reuse the header builders of
``tests/test_audit_sevenzip.py``.
"""

from __future__ import annotations

import io
import lzma
import os
import struct
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, DecoderLimits
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from tests.conftest import (
    requires,
    requires_binary,
    requires_zstd,
    run_7z,
    zstd_backend,
)
from tests.test_audit_sevenzip import (
    _COPY,
    _DELTA,
    _LZMA,
    _LZMA2,
    _PPMD,
    _archive,
    _coder,
    _crc,
    _folder,
    _header,
    _linear,
    _lzma2,
    _read_only_member,
)

_ZSTD = b"\x04\xf7\x11\x01"
_PAYLOAD = bytes(range(256)) * 4  # 1024 bytes


def _two_coder_folder(outer: bytes, inner: bytes) -> bytes:
    """Coder 0 (``outer``) reads coder 1's output; coder 1 (``inner``) reads the pack.

    This is 7-Zip's own layout for ``-m0=<outer> -m1=<inner>``: the folder output is
    coder 0, and ``coder_unpack_sizes`` lists coder 0's size first.
    """
    return _folder([outer, inner], bind_pairs=[(0, 1)])


def _run_7z(args: list[str], cwd: Path) -> None:
    result = run_7z(args, cwd=cwd, check=False, text=True)
    if result.returncode != 0:
        pytest.skip(f"7z CLI could not build the fixture: {result.stdout[-400:]}")


# ---------------------------------------------------------------------------
# S9: every coder's declared unpack size is enforced, not only the folder output's
# ---------------------------------------------------------------------------
#
# 7-Zip gives every coder its own output size and reports "Data Error" when a coder's
# output does not match it (7-Zip 23.01, ``7z t`` on each archive below). archivey
# used to check only the last size of each liblzma chain and skip COPY entirely, so
# these archives read clean, with a CRC over bytes 7-Zip never produces.


def test_lzma2_coder_decoding_past_its_own_size_before_a_filter_is_corruption() -> None:
    packed = lzma.compress(
        _PAYLOAD,
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_DELTA, "dist": 1},
            {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 16},
        ],
    )
    header = _header(
        folders=[
            _two_coder_folder(
                _coder(_DELTA, props=b"\x00"), _coder(_LZMA2, props=b"\x10")
            )
        ],
        # Delta (folder output) 1024, LZMA2 512: the LZMA2 stream holds 1024.
        coder_unpack_sizes=[[1024, 512]],
        pack_sizes=[len(packed)],
        names=["a"],
        folder_crcs=[_crc(_PAYLOAD)],
    )
    with pytest.raises(CorruptionError):
        _read_only_member(_archive(packed, header))


def test_lzma1_coder_decoding_past_its_own_size_before_a_filter_is_corruption() -> None:
    lzma1 = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}
    encoder = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=[lzma1])
    packed = encoder.compress(_PAYLOAD) + encoder.flush()
    expected = lzma.decompress(
        lzma.compress(_PAYLOAD, format=lzma.FORMAT_RAW, filters=[lzma1]),
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_DELTA, "dist": 1}, lzma1],
    )
    header = _header(
        folders=[
            _two_coder_folder(
                _coder(_DELTA, props=b"\x00"),
                _coder(_LZMA, props=lzma._encode_filter_properties(lzma1)),  # type: ignore[attr-defined]
            )
        ],
        # The LZMA1 coder declares 512; the chain is capped at the Delta's 1024, so
        # LZMA1 is asked for 512 bytes past its own declared end.
        coder_unpack_sizes=[[1024, 512]],
        pack_sizes=[len(packed)],
        names=["a"],
        folder_crcs=[_crc(expected)],
    )
    with pytest.raises(CorruptionError):
        _read_only_member(_archive(packed, header))


def test_filter_declaring_less_than_its_lzma2_input_is_corruption() -> None:
    # The mirror of the first S9 case: Delta declares 512 from an LZMA2 coder that
    # declares (and decodes) 1024. Delta is size-preserving, so no valid folder does it.
    packed = lzma.compress(
        _PAYLOAD,
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_DELTA, "dist": 1},
            {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 16},
        ],
    )
    header = _header(
        folders=[
            _two_coder_folder(
                _coder(_DELTA, props=b"\x00"), _coder(_LZMA2, props=b"\x10")
            )
        ],
        coder_unpack_sizes=[[512, 1024]],
        pack_sizes=[len(packed)],
        names=["a"],
        folder_crcs=[_crc(_PAYLOAD[:512])],
    )
    with pytest.raises(CorruptionError):
        _read_only_member(_archive(packed, header))


def test_copy_coder_declared_size_bounds_what_the_next_coder_reads() -> None:
    packed = _lzma2(_PAYLOAD)
    header = _header(
        folders=[_two_coder_folder(_coder(_LZMA2, props=b"\x10"), _coder(_COPY))],
        # COPY declares 10 bytes; 7-Zip hands LZMA2 those 10 and reports Data Error.
        coder_unpack_sizes=[[len(_PAYLOAD), 10]],
        pack_sizes=[len(packed)],
        names=["a"],
        folder_crcs=[_crc(_PAYLOAD)],
    )
    with pytest.raises(CorruptionError):
        _read_only_member(_archive(packed, header))


# ---------------------------------------------------------------------------
# S10: a zstd window counts in the folder-wide decoder-memory sum
# ---------------------------------------------------------------------------


@requires_zstd()
def test_zstd_window_counts_toward_the_folder_decoder_memory_sum() -> None:
    # One folder, two decoders live at once: zstd (32 MiB window, the frame header's
    # declaration) feeding LZMA2 (32 MiB dictionary). Each passes a 48 MiB cap alone;
    # together they are 64 MiB. The sum check used to see only the LZMA2 dictionary,
    # and with one counted decoder it did not run at all.
    zstd = zstd_backend()
    inner = lzma.compress(
        b"abc" * 1000,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 32 << 20}],
    )
    compressor = zstd.ZstdCompressor(options={zstd.CompressionParameter.window_log: 25})
    packed = compressor.compress(inner) + compressor.flush()
    # Frame header: no single-segment flag, window descriptor 2**25 (exponent 15).
    assert packed[4] & 0x20 == 0
    assert packed[5] == (25 - 10) << 3
    header = _header(
        folders=[_two_coder_folder(_coder(_LZMA2, props=bytes([26])), _coder(_ZSTD))],
        coder_unpack_sizes=[[3000, len(inner)]],
        pack_sizes=[len(packed)],
        names=["a"],
        folder_crcs=[_crc(b"abc" * 1000)],
    )
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=48 << 20))
    with pytest.raises(ResourceLimitError):
        _read_only_member(_archive(packed, header), config=config)


# ---------------------------------------------------------------------------
# S11: PPMd order and memory size are validated as 7-Zip does
# ---------------------------------------------------------------------------


def _ppmd_archive(order: int, mem_size: int) -> bytes:
    import pyppmd

    payload = b"hello world " * 50
    encoder = pyppmd.Ppmd7Encoder(6, 1 << 20)
    packed = encoder.encode(payload) + encoder.flush()
    header = _header(
        folders=[_linear([_coder(_PPMD, props=struct.pack("<BL", order, mem_size))])],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(packed)],
        names=["a"],
    )
    return _archive(packed, header)


@requires("pyppmd")
@pytest.mark.parametrize("order", [0, 1, 65, 255])
def test_ppmd_order_outside_7zip_range_is_refused(order: int) -> None:
    # 7-Zip (PpmdDecoder.cpp) refuses order < 2 or > 64 and mem < 2**11 as
    # unsupported properties. Before the fix, order 0/1 surfaced as TruncatedError
    # ("File is truncated") and 65/255 decoded.
    with pytest.raises(ArchiveyError) as excinfo:
        _read_only_member(_ppmd_archive(order, 1 << 20))
    assert not isinstance(excinfo.value, TruncatedError)


@requires("pyppmd")
@pytest.mark.parametrize("mem_size", [0, 16, 2047])
def test_ppmd_memory_size_under_7zip_minimum_is_refused(mem_size: int) -> None:
    # No member CRC, so nothing catches the bytes pyppmd returns for a model that
    # 7-Zip refuses to build.
    with pytest.raises((UnsupportedFeatureError, CorruptionError)):
        _read_only_member(_ppmd_archive(6, mem_size))


@requires("pyppmd")
def test_ppmd_memory_size_over_7zip_maximum_is_refused_without_a_cap() -> None:
    # 7-Zip's ceiling is 0xFFFFFFFF - 36. Under the default cap the memory limit
    # answers first (tests/test_decoder_limits.py); with no cap, the range check does.
    config = ArchiveyConfig(decoder_limits=DecoderLimits.UNLIMITED)
    with pytest.raises(UnsupportedFeatureError):
        _read_only_member(_ppmd_archive(6, 0xFFFFFFFF), config=config)


# ---------------------------------------------------------------------------
# S12: LZMA1 with lc + lp > 4 (valid 7-Zip output) is not reported as corruption
# ---------------------------------------------------------------------------


@requires_binary("7z")
def test_lzma1_lc8_archive_is_not_reported_as_corruption(tmp_path: Path) -> None:
    payload = os.urandom(3000)
    (tmp_path / "r.bin").write_bytes(payload)
    _run_7z(["a", "-m0=LZMA:lc=8", "lc8.7z", "r.bin"], tmp_path)
    try:
        with open_archive(tmp_path / "lc8.7z") as reader:
            (member,) = reader.members()
            with reader.open(member) as stream:
                assert stream.read() == payload
    except UnsupportedFeatureError:
        pass  # liblzma cannot decode lc + lp > 4; saying so is acceptable.


# ---------------------------------------------------------------------------
# S13: the ARM64 branch filter, 7-Zip 23's default for ARM64 executables (fixed)
# ---------------------------------------------------------------------------


def _arm64_elf(size: int) -> bytes:
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack(
        "<HHIQQQIHHHHHH", 2, 183, 1, 0x400000, 64, 0, 0, 64, 56, 0, 64, 0, 0
    )
    return header + os.urandom(size // 2) + bytes(size - size // 2)


@requires_binary("7z")
@pytest.mark.parametrize("explicit", [True, False], ids=["mf-arm64", "default"])
def test_arm64_filtered_archive_reads(tmp_path: Path, explicit: bool) -> None:
    # 7-Zip 23.01 picks ARM64 by itself for an AArch64 ELF with the execute bit
    # (``Method = ARM64 LZMA2``), as it picks BCJ for x86.
    payload = _arm64_elf(40_000)
    exe = tmp_path / "armexe"
    exe.write_bytes(payload)
    exe.chmod(0o755)
    _run_7z(["a", *(["-mf=ARM64"] if explicit else []), "a.7z", "armexe"], tmp_path)
    listing = run_7z(["l", "-slt", "a.7z"], cwd=tmp_path, text=True).stdout
    if "ARM64" not in listing:
        pytest.skip("this 7z did not write the ARM64 filter")
    with open_archive(tmp_path / "a.7z") as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read() == payload


# ---------------------------------------------------------------------------
# S14: the signature header's major version is checked at offset 0
# ---------------------------------------------------------------------------


def test_unknown_major_version_is_refused() -> None:
    data = bytearray(
        _archive(
            b"hello",
            _header(
                folders=[_linear([_coder(_COPY)])],
                coder_unpack_sizes=[[5]],
                pack_sizes=[5],
                names=["a"],
                folder_crcs=[_crc(b"hello")],
            ),
        )
    )
    # Byte 6 is outside the StartHeader CRC. 7-Zip 23.01 says "Can't open as archive";
    # the SFX validator also refuses it (``validate_sevenzip_signature_header``).
    data[6] = 1
    with pytest.raises(ArchiveyError), open_archive(io.BytesIO(bytes(data))) as reader:
        reader.members()
