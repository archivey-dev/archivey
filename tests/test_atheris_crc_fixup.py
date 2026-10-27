"""Unit tests for Atheris CRC mutate-then-fixup helpers (no atheris import required)."""

from __future__ import annotations

import io
import struct
import zlib
from pathlib import Path

import pytest

from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.backends.sevenzip_reader import load_sevenzip_archive
from tests.atheris_fuzz.crc_fixup import (
    fixup_sevenzip_header_crcs,
    fixup_zip_local_and_cd_crc,
)
from tests.corruption_util import raises_corruption_not_truncation
from tests.sample_archives import CORPUS, corpus_archive_path


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


@pytest.fixture(scope="module")
def basic_7z(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    pytest.importorskip("py7zr")
    entry = next(e for e in CORPUS if e.id == "basic" and "7z" in e.formats)
    path = corpus_archive_path(entry, "7z", tmp_path_factory.mktemp("crc-7z"))
    return path.read_bytes()


def _next_header_slice(data: bytes) -> tuple[int, int]:
    off, size, _crc = struct.unpack("<QQI", data[12:32])
    start = 32 + off
    return start, start + size


def test_fixup_sevenzip_restores_crcs_after_bitflip(basic_7z: bytes) -> None:
    start, end = _next_header_slice(basic_7z)
    assert end > start
    data = bytearray(basic_7z)
    # Flip a byte inside the next-header body (the CRC-gated region).
    data[start] ^= 0x01
    broken = bytes(data)

    # Without fixup the next-header CRC must fail.
    with raises_corruption_not_truncation(match="next header CRC"):
        load_sevenzip_archive(io.BytesIO(broken))

    fixed = fixup_sevenzip_header_crcs(broken, broken=False)
    # Signature + next-header CRCs must match recomputed values.
    start_header = fixed[12:32]
    assert int.from_bytes(fixed[8:12], "little") == _crc32(start_header)
    off, size, nh_crc = struct.unpack("<QQI", start_header)
    header = fixed[32 + off : 32 + off + size]
    assert nh_crc == _crc32(header)

    # Fixed-up blob must pass the CRC gate (may still raise typed errors for content).
    try:
        load_sevenzip_archive(io.BytesIO(fixed))
    except CorruptionError as exc:
        assert "next header CRC" not in str(exc)
        assert "signature header CRC" not in str(exc)
    except ArchiveyError:
        pass


def test_fixup_sevenzip_broken_mode_still_rejects(basic_7z: bytes) -> None:
    start, _end = _next_header_slice(basic_7z)
    flipped = bytearray(basic_7z)
    flipped[start] ^= 0x02
    fixed_broken = fixup_sevenzip_header_crcs(bytes(flipped), broken=True)
    with raises_corruption_not_truncation(match="next header CRC"):
        load_sevenzip_archive(io.BytesIO(fixed_broken))


def test_fixup_sevenzip_noop_on_non_magic() -> None:
    blob = b"not a 7z archive" + b"\x00" * 64
    assert fixup_sevenzip_header_crcs(blob, broken=False) == blob


def test_fixup_sevenzip_known_good_header_unchanged(basic_7z: bytes) -> None:
    # Re-patching a valid archive should yield byte-identical CRCs (body untouched).
    fixed = fixup_sevenzip_header_crcs(basic_7z, broken=False)
    assert fixed[12:] == basic_7z[12:]  # start_header + body identical
    assert fixed[8:12] == basic_7z[8:12]


def _zip_cd_crc_slice(data: bytes) -> tuple[int, bytes]:
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = int.from_bytes(data[eocd + 16 : eocd + 20], "little")
    assert data[cd_offset : cd_offset + 4] == b"PK\x01\x02"
    return cd_offset, data[cd_offset + 16 : cd_offset + 20]


def test_fixup_zip_stored_member_crc(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"hello zip crc")
    data = path.read_bytes()

    # Corrupt the central-directory CRC field, then fix it back.
    cd_offset, good_crc = _zip_cd_crc_slice(data)
    corrupted = bytearray(data)
    corrupted[cd_offset + 16] ^= 0xFF
    restored = fixup_zip_local_and_cd_crc(bytes(corrupted), broken=False)
    assert restored[cd_offset + 16 : cd_offset + 20] == good_crc

    broken = fixup_zip_local_and_cd_crc(data, broken=True)
    assert broken[cd_offset + 16 : cd_offset + 20] != good_crc


def test_fixup_zip_deflate_member_crc(tmp_path: Path) -> None:
    """Deflate (method 8): recompute CRC from a successful raw inflate of the payload."""
    import zipfile

    payload = b"deflate zip crc payload " * 20
    path = tmp_path / "deflate.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("d.txt", payload)
    data = path.read_bytes()

    cd_offset, good_crc = _zip_cd_crc_slice(data)
    expected = _crc32(payload).to_bytes(4, "little")
    assert good_crc == expected

    corrupted = bytearray(data)
    corrupted[cd_offset + 16] ^= 0xFF
    restored = fixup_zip_local_and_cd_crc(bytes(corrupted), broken=False)
    assert restored[cd_offset + 16 : cd_offset + 20] == expected

    # Local header CRC must match too.
    local_off = int.from_bytes(restored[cd_offset + 42 : cd_offset + 46], "little")
    assert restored[local_off + 14 : local_off + 18] == expected

    broken = fixup_zip_local_and_cd_crc(data, broken=True)
    assert broken[cd_offset + 16 : cd_offset + 20] != expected


def test_fixup_zip_broken_flips_when_no_recompute(tmp_path: Path) -> None:
    """Unsupported method: broken mode still flips CD/local CRC for reject coverage."""
    import zipfile

    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"x")
    data = bytearray(path.read_bytes())
    # Point the local method at an unsupported value so inflate/recompute is skipped.
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = int.from_bytes(data[eocd + 16 : eocd + 20], "little")
    local_off = int.from_bytes(data[cd_offset + 42 : cd_offset + 46], "little")
    data[local_off + 8 : local_off + 10] = (99).to_bytes(2, "little")
    original_crc = bytes(data[cd_offset + 16 : cd_offset + 20])
    flipped = fixup_zip_local_and_cd_crc(bytes(data), broken=True)
    assert flipped[cd_offset + 16 : cd_offset + 20] != original_crc


@pytest.fixture(scope="module")
def basic_rar5() -> bytes:
    return (
        Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"
    ).read_bytes()


@pytest.fixture(scope="module")
def basic_rar4() -> bytes:
    return (
        Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__rar4.rar"
    ).read_bytes()


@pytest.fixture(scope="module")
def comment_rar4() -> bytes:
    return (
        Path(__file__).parent / "fixtures" / "rar" / "rar15-comment.rar"
    ).read_bytes()


def test_fixup_rar5_restores_crcs_after_bitflip(basic_rar5: bytes) -> None:
    from archivey.internal.backends.rar_parser import parse_rar_archive
    from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs

    flipped = bytearray(basic_rar5)
    flipped[24] ^= 0x01  # in the first FILE header, after MAIN
    broken = bytes(flipped)
    damaged = parse_rar_archive(io.BytesIO(broken))
    assert damaged.members == []
    assert damaged.damaged is not None
    assert "RAR5 header CRC" in damaged.damaged

    fixed = fixup_rar_header_crcs(broken, broken=False)
    arc = parse_rar_archive(io.BytesIO(fixed))
    assert arc.version == 5
    assert len(arc.members) >= 1


def test_fixup_rar5_broken_mode_still_rejects(basic_rar5: bytes) -> None:
    from archivey.internal.backends.rar_parser import parse_rar_archive
    from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs

    fixed_broken = fixup_rar_header_crcs(basic_rar5, broken=True)
    with raises_corruption_not_truncation(match="RAR5 header CRC"):
        parse_rar_archive(io.BytesIO(fixed_broken))


def test_fixup_rar3_restores_crcs_after_bitflip(basic_rar4: bytes) -> None:
    from archivey.internal.backends.rar_parser import parse_rar_archive
    from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs

    # Corrupt the MAIN block CRC16 (first two bytes after the 7-byte RAR3 magic).
    flipped = bytearray(basic_rar4)
    flipped[7] ^= 0xFF
    broken = bytes(flipped)
    with raises_corruption_not_truncation(match="RAR3 .*CRC"):
        parse_rar_archive(io.BytesIO(broken))

    fixed = fixup_rar_header_crcs(broken, broken=False)
    arc = parse_rar_archive(io.BytesIO(fixed))
    assert arc.version == 4
    assert len(arc.members) >= 1


def test_fixup_rar3_comment_archive_crc_pos(comment_rar4: bytes) -> None:
    """Comment subblocks: CRC must not cover the full header_size."""
    from archivey.internal.backends.rar_parser import parse_rar_archive
    from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs

    assert fixup_rar_header_crcs(comment_rar4, broken=False) == comment_rar4
    flipped = bytearray(comment_rar4)
    flipped[30] ^= 0x01
    fixed = fixup_rar_header_crcs(bytes(flipped), broken=False)
    try:
        parse_rar_archive(io.BytesIO(fixed))
    except CorruptionError as exc:
        assert "CRC" not in str(exc)
    except ArchiveyError:
        pass


def test_fixup_rar_noop_on_non_magic() -> None:
    from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs

    blob = b"not a rar archive" + b"\x00" * 64
    assert fixup_rar_header_crcs(blob, broken=False) == blob


def _tar_bytes() -> bytes:
    import tarfile

    payload = b"atheris\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("dir/file.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_fixup_tar_checksum_keeps_a_mutated_header_readable() -> None:
    """A one-byte name edit fails the checksum. The fixup puts it back."""
    from archivey import open_archive
    from tests.atheris_fuzz.crc_fixup import fixup_tar_header_checksums

    original = bytearray(_tar_bytes())
    original[0] ^= 0x01
    broken = bytes(original)
    with (
        pytest.raises(ArchiveyError),
        open_archive(io.BytesIO(broken), format="tar") as arc,
    ):
        list(arc)

    fixed = fixup_tar_header_checksums(broken, broken=False)
    with open_archive(io.BytesIO(fixed), format="tar") as arc:
        names = [member.name for member in arc]
    assert names


def test_fixup_tar_broken_mode_still_rejects() -> None:
    """Broken mode starts from a valid archive and writes a sum off by one."""
    from archivey import open_archive
    from tests.atheris_fuzz.crc_fixup import (
        _tar_block_checksum,
        fixup_tar_header_checksums,
    )

    original = _tar_bytes()
    fixed_broken = fixup_tar_header_checksums(original, broken=True)
    field = fixed_broken[148:156]
    assert field.endswith(b"\x00 ")
    stored = int(field[:6], 8)
    assert stored == _tar_block_checksum(original[:512]) ^ 1
    with (
        pytest.raises(ArchiveyError),
        open_archive(io.BytesIO(fixed_broken), format="tar") as arc,
    ):
        list(arc)


def test_fixup_tar_leaves_the_end_marker() -> None:
    from tests.atheris_fuzz.crc_fixup import fixup_tar_header_checksums

    blob = _tar_bytes()
    assert blob.endswith(bytes(1024))
    fixed = fixup_tar_header_checksums(blob, broken=False)
    assert fixed.endswith(bytes(1024))
    assert fixup_tar_header_checksums(b"short", broken=False) == b"short"


def test_fixup_tar_does_not_rewrite_file_bytes() -> None:
    """A member longer than the checksum field keeps those payload bytes."""
    import tarfile

    from tests.atheris_fuzz.crc_fixup import fixup_tar_header_checksums

    payload = bytes((index * 3) % 251 for index in range(512))
    assert payload[257:262] != b"ustar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("wide.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    fixed = fixup_tar_header_checksums(buf.getvalue(), broken=False)
    assert payload in fixed
