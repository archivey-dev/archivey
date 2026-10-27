"""On-demand benchmark fixtures (not committed).

Two scales:

- ``ci`` — small archives for the PR structural gate (fast; solid O(n²) still visible).
- ``realistic`` — multi-MiB corpora for wall-time ratios vs stdlib (VISION ≤1.3× surface).

Large solid 7z/RAR archives are generated when py7zr / ``rar`` are available.
WinZip AES ZIPs need the ``[crypto]`` extra to build (and to decrypt under archivey).
"""

from __future__ import annotations

import gzip
import io
import os
import random
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

# Password for the generated WinZip AES fixture (must match harness open).
ZIP_AES_PASSWORD = b"bench-secret"
# Password for the generated ZipCrypto fixture (must match harness open).
ZIPCRYPTO_PASSWORD = b"bench-secret"
# Cap on the ZipCrypto member: the pure-Python cipher runs at a few MiB/s, so a
# ``realistic``-sized member would dominate the run (and the fixture's own build).
ZIPCRYPTO_MAX_SIZE = 1024 * 1024

# ---------------------------------------------------------------------------
# Scale profiles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scale:
    name: str
    common_members: int
    common_member_size: int
    gzip_size: int
    solid_members: int
    solid_member_size: int
    # Tiny-payload listing corpora (header/member-build cost, not codec cost).
    list_members: int
    nonsolid_list_members: int


SCALES: dict[str, Scale] = {
    # ~128 KiB ZIP/TAR, 64 KiB gzip, ~2 MiB solid — PR structural gate.
    # common_members is 32 (not 8) so per-member costs show in wall time and
    # in the solid/listing cases. The seek baselines cannot catch a
    # construction-probe regression on their own: source_seek_count counts
    # logical seeks on the measurement wrapper, not syscalls, so a
    # buffer-locality regression moves real I/O without moving this number
    # (PR #328 F4 / F13). The unit guard is
    # tests/test_binaryio.py::TestSourceByteSize::test_buffered_reader_over_file_is_not_seeked.
    "ci": Scale(
        name="ci",
        common_members=32,
        common_member_size=4 * 1024,
        gzip_size=64 * 1024,
        solid_members=32,
        solid_member_size=64 * 1024,
        list_members=1_000,
        nonsolid_list_members=256,
    ),
    # ~16 MiB ZIP/TAR, 32 MiB gzip, ~16 MiB solid — wall-time vs stdlib.
    "realistic": Scale(
        name="realistic",
        common_members=64,
        common_member_size=256 * 1024,
        gzip_size=32 * 1024 * 1024,
        solid_members=64,
        solid_member_size=256 * 1024,
        list_members=10_000,
        nonsolid_list_members=1_000,
    ),
}

DEFAULT_SCALE = "ci"


@dataclass(frozen=True)
class FixtureSet:
    """Paths to archives used by one harness run."""

    root: Path
    scale: Scale
    zip_path: Path
    zip_lzma_path: Path
    zip_aes_path: Path | None
    zipcrypto_path: Path
    tar_path: Path
    targz_path: Path
    tarbz2_path: Path
    gzip_path: Path
    unix_compress_text_path: Path | None
    unix_compress_zeros_path: Path | None
    solid_7z: Path | None
    many_7z: Path | None
    nonsolid_7z: Path | None
    bcj_7z: dict[str, Path]
    solid_rar: Path | None
    many_rar: Path | None
    nonsolid_rar: Path | None
    unpacked_solid_7z: int
    unpacked_bcj_7z: int
    unpacked_solid_rar: int
    unpacked_zip_aes: int
    unpacked_zipcrypto: int


def _payload(i: int, size: int) -> bytes:
    """Semi-compressible member payload (not pure zeros; not fully random).

    A 512-byte unique header plus a repeating 4 KiB patterned block — closer to
    text/log-ish ratios than ``os.urandom``, while still exercising the decompressor.
    """
    header = f"archivey-bench-{i}\n".encode()
    pattern = bytes((j * 17 + i) % 256 for j in range(4096))
    body_len = max(0, size - len(header))
    reps, rem = divmod(body_len, len(pattern))
    return header + pattern * reps + pattern[:rem]


def build_zip(path: Path, scale: Scale) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(scale.common_members):
            zf.writestr(f"f{i:04d}.bin", _payload(i, scale.common_member_size))


def build_zip_lzma(path: Path, scale: Scale) -> None:
    """ZIP with LZMA members — exercises the native ZIP codec path (#106)."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_LZMA) as zf:
        # Fewer members than the deflate corpus: LZMA setup dominates at ci scale.
        n = max(2, scale.common_members // 2)
        for i in range(n):
            zf.writestr(f"lzma{i:04d}.bin", _payload(i, scale.common_member_size))


def build_zip_aes(
    path: Path, scale: Scale, *, password: bytes = ZIP_AES_PASSWORD
) -> int:
    """Build a multi-member WinZip AES-256 (AE-2) ZIP; return unpacked bytes.

    Requires ``cryptography`` (the same ``[crypto]`` extra needed to decrypt). Returns
    0 and leaves ``path`` absent when the extra is missing.
    """
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return 0
    from tests.zip_aes_fixture import build_aes_zip

    # AE-2 / AES-256 / underlying method = deflate. A handful of members is enough to
    # exercise per-member password confirm + HMAC VerifyingStream without dominating ci.
    n = max(2, min(4, scale.common_members))
    members = [
        (f"aes{i:04d}.bin".encode(), _payload(i, scale.common_member_size))
        for i in range(n)
    ]
    path.write_bytes(
        build_aes_zip(
            members,
            password=password,
            vendor_version=2,
            strength=3,
            method=8,
        )
    )
    return sum(len(payload) for _name, payload in members)


def _zipcrypto_payload(scale: Scale) -> bytes:
    size = min(scale.common_members * scale.common_member_size, ZIPCRYPTO_MAX_SIZE)
    return _payload(0, size)


def build_zipcrypto(path: Path, scale: Scale) -> int:
    """Build a one-member ZipCrypto ZIP; return unpacked bytes.

    The member is STORED so the ciphertext is as long as the payload: with deflate the
    patterned payload compresses to almost nothing and the case would time the codec,
    not the decrypt loop it exists to guard.
    """
    from tests.zipcrypto import build_zipcrypto_zip

    payload = _zipcrypto_payload(scale)
    path.write_bytes(
        build_zipcrypto_zip(
            ZIPCRYPTO_PASSWORD,
            b"zipcrypto.bin",
            payload,
            compression=zipfile.ZIP_STORED,
        )
    )
    return len(payload)


def build_tar(path: Path, scale: Scale, *, mode: str = "w") -> None:
    """Build a tar archive. ``mode`` may be ``w``, ``w:gz``, or ``w:bz2``."""
    with tarfile.open(path, mode) as tf:
        for i in range(scale.common_members):
            data = _payload(i, scale.common_member_size)
            info = tarfile.TarInfo(name=f"f{i:04d}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def build_gzip(path: Path, scale: Scale) -> None:
    path.write_bytes(gzip.compress(_payload(0, scale.gzip_size), compresslevel=6))


def _text_payload(size: int) -> bytes:
    """Deterministic word salad: LZW dictionary entries stay short, as on real text."""
    rng = random.Random(0)
    words = [
        bytes(
            rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))
        )
        for _ in range(2000)
    ]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words)
        out += b"\n" if rng.random() < 0.08 else b" "
    return bytes(out[:size])


def build_unix_compress(path: Path, data: bytes) -> bool:
    """Write ``data`` as a ``.Z`` with ncompress (a dev dependency). False without it."""
    try:
        import ncompress
    except ImportError:
        return False
    path.write_bytes(ncompress.compress(data))
    return True


def unix_compress_zeros_size(scale: Scale) -> int:
    """A zero run builds dictionary entries far past the decoder's flat-entry cap."""
    return 4 * scale.gzip_size


def build_solid_7z(path: Path, scale: Scale) -> int:
    """Build a solid LZMA2 7z; return total unpacked file bytes."""
    import py7zr

    src = path.parent / f"{path.stem}-src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    total = 0
    files: dict[str, bytes] = {}
    for i in range(scale.solid_members):
        data = _payload(i, scale.solid_member_size)
        name = f"m{i:03d}.bin"
        files[name] = data
        total += len(data)
        (src / name).write_bytes(data)
    with py7zr.SevenZipFile(path, "w", filters=[{"id": py7zr.FILTER_LZMA2}]) as archive:
        for name in sorted(files):
            archive.write(src / name, arcname=name)
    return total


def _code_payload(i: int, size: int) -> bytes:
    """x86-like member payload with real CALL/JMP rel32 targets to convert.

    The BCJ branch filter only does work on ``E8``/``E9`` opcodes followed by a
    32-bit displacement; a text-ish or random payload leaves it converting almost
    nothing, which would make the BCJ cases measure LZMA and not the filter. This
    repeats a 16-byte block holding one ``call rel32`` and one ``jmp rel32``, so
    roughly one branch per eight bytes — dense, but that is what the filter exists
    for. Same block as ``tests/test_sevenzip_reader.py::_BCJ_CODE_PATTERN``.
    """
    block = bytes(
        [0x8B, 0x45, 0xF8, 0xE8, 0x10, 0x20, 0x00, 0x00]
        + [0x89, 0x45, 0xFC, 0xE9, 0x00, 0x01, 0x00, 0x00]
    )
    header = f"archivey-bench-code-{i}\n".encode()
    body_len = max(0, size - len(header))
    reps, rem = divmod(body_len, len(block))
    return header + block * reps + block[:rem]


def build_bcj_7z(path: Path, scale: Scale, *, second_method: str) -> int:
    """Build a solid BCJ-filtered 7z via the ``7z`` CLI; 0 if unavailable.

    Written with the CLI rather than py7zr on purpose: the LZMA1 variant the CLI
    emits carries no end-of-stream marker, which is the shape that forces archivey
    to stage the branch filter separately instead of handing liblzma one combined
    raw chain. ``second_method`` is ``LZMA2``, ``LZMA`` or ``Copy``; ``Copy`` leaves
    the branch filter as the whole of the decode cost.
    """
    if shutil.which("7z") is None:
        return 0
    src = path.parent / f"{path.stem}-src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    total = 0
    for i in range(_bcj_members(scale)):
        data = _code_payload(i, scale.solid_member_size)
        total += len(data)
        (src / f"c{i:03d}.bin").write_bytes(data)
    cmd = [
        "7z",
        "a",
        "-t7z",
        "-m0=BCJ",
        f"-m1={second_method}",
        str(path),
        str(src / "*"),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path.exists():
            path.unlink()
        return 0
    return total if path.exists() else 0


def _bcj_members(scale: Scale) -> int:
    """Members in the BCJ corpora — a quarter of the solid corpus.

    Enough bytes for the filter to show up in wall time, few enough that three
    extra 7z cases do not dominate a structural run.
    """
    return max(2, scale.solid_members // 4)


def unpacked_bcj(scale: Scale) -> int:
    """Unpacked bytes of a BCJ corpus, for a fixture reused from a previous run."""
    return sum(
        len(_code_payload(i, scale.solid_member_size))
        for i in range(_bcj_members(scale))
    )


# Payload size for the tiny-member listing corpora. Public because
# ``scripts/gen_rar_fixtures.py`` builds the committed RAR listing fixtures from the
# same recipe — ``SCALES`` and this constant are the single source of truth.
LIST_MEMBER_SIZE = 16


def build_many_member_7z(path: Path, scale: Scale) -> None:
    """Solid COPY 7z with many tiny members — listing cost dominates.

    py7zr always packs FILTER_COPY members into one solid folder, which is exactly
    the shape where per-folder listing caches amortize.
    """
    import py7zr

    with py7zr.SevenZipFile(path, "w", filters=[{"id": py7zr.FILTER_COPY}]) as archive:
        for i in range(scale.list_members):
            archive.writestr(f"f{i:05d}.txt", f"payload-{i}\n"[:LIST_MEMBER_SIZE])


def build_nonsolid_7z(path: Path, scale: Scale) -> bool:
    """Non-solid 7z (one folder per file) via ``7z -ms=off``; False if unavailable.

    py7zr cannot emit this shape. Used as a listing negative control: the
    per-folder cache misses every member, so wall time should not improve vs
    a naive loop — and must not regress from extra per-miss work.
    """
    if shutil.which("7z") is None:
        return False
    src = path.parent / f"{path.stem}-src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    for i in range(scale.nonsolid_list_members):
        (src / f"f{i:05d}.txt").write_text(f"payload-{i}\n"[:LIST_MEMBER_SIZE])
    # -mx=0 store; -ms=off forces one folder per file.
    cmd = ["7z", "a", "-t7z", "-ms=off", "-mx=0", str(path), str(src / "*")]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path.exists():
            path.unlink()
        return False
    return path.exists()


def build_solid_rar(path: Path, scale: Scale) -> int | None:
    """Build a solid RAR via the ``rar`` binary; return unpacked bytes or None if unavailable."""
    if shutil.which("rar") is None:
        return None
    src = path.parent / f"{path.stem}-src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    total = 0
    for i in range(scale.solid_members):
        data = _payload(i, scale.solid_member_size)
        total += len(data)
        (src / f"m{i:03d}.bin").write_bytes(data)
    cmd = ["rar", "a", "-m3", "-s", "-ep1", str(path), str(src / "*")]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return total if path.exists() else None


def _build_store_rar(path: Path, count: int, *, solid: bool) -> bool:
    """Store (``-m0``) RAR with ``count`` tiny members; ``solid`` selects ``-s`` / ``-s-``.

    Soft-fails when the ``rar`` writer is missing (CI installs ``unrar`` only).
    """
    if shutil.which("rar") is None:
        return False
    src = path.parent / f"{path.stem}-src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    for i in range(count):
        (src / f"f{i:05d}.txt").write_text(f"payload-{i}\n"[:LIST_MEMBER_SIZE])
    solid_flag = "-s" if solid else "-s-"
    cmd = ["rar", "a", "-m0", solid_flag, "-ep1", "-idq", str(path), str(src / "*")]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path.exists():
            path.unlink()
        return False
    return path.exists()


def build_many_member_rar(path: Path, scale: Scale) -> bool:
    """Solid store RAR with many tiny members — listing cost dominates."""
    return _build_store_rar(path, scale.list_members, solid=True)


def build_nonsolid_rar(path: Path, scale: Scale) -> bool:
    """Non-solid store RAR; listing negative control vs solid many."""
    return _build_store_rar(path, scale.nonsolid_list_members, solid=False)


def _unpacked_solid(scale: Scale) -> int:
    return sum(
        len(_payload(i, scale.solid_member_size)) for i in range(scale.solid_members)
    )


def materialize_fixtures(
    root: Path | None = None,
    *,
    scale: str | Scale = DEFAULT_SCALE,
) -> FixtureSet:
    """Create (or reuse) the comparison corpus under ``root``."""
    if isinstance(scale, str):
        if scale not in SCALES:
            raise ValueError(f"unknown scale {scale!r}; choose from {sorted(SCALES)}")
        scale_obj = SCALES[scale]
    else:
        scale_obj = scale

    if root is None:
        cache = os.environ.get("ARCHIVEY_BENCH_CACHE")
        root = (
            Path(cache) if cache else Path(tempfile.mkdtemp(prefix="archivey-bench-"))
        )
    # Isolate scales so a cached ``ci`` zip is never reused as ``realistic``.
    root = root / scale_obj.name
    root.mkdir(parents=True, exist_ok=True)

    zip_path = root / "common.zip"
    zip_lzma_path = root / "common-lzma.zip"
    zip_aes_path_candidate = root / "common-aes.zip"
    zipcrypto_path = root / "common-zipcrypto.zip"
    tar_path = root / "common.tar"
    targz_path = root / "common.tar.gz"
    tarbz2_path = root / "common.tar.bz2"
    gzip_path = root / "common.gz"
    z_text_candidate = root / "text.Z"
    z_zeros_candidate = root / "zeros.Z"
    if not zip_path.exists():
        build_zip(zip_path, scale_obj)
    if not zip_lzma_path.exists():
        build_zip_lzma(zip_lzma_path, scale_obj)
    if not zipcrypto_path.exists():
        build_zipcrypto(zipcrypto_path, scale_obj)
    if not tar_path.exists():
        build_tar(tar_path, scale_obj)
    if not targz_path.exists():
        build_tar(targz_path, scale_obj, mode="w:gz")
    if not tarbz2_path.exists():
        build_tar(tarbz2_path, scale_obj, mode="w:bz2")
    if not gzip_path.exists():
        build_gzip(gzip_path, scale_obj)
    z_text_path: Path | None = z_text_candidate
    if not z_text_candidate.exists() and not build_unix_compress(
        z_text_candidate, _text_payload(scale_obj.gzip_size)
    ):
        z_text_path = None
    z_zeros_path: Path | None = z_zeros_candidate
    if not z_zeros_candidate.exists() and not build_unix_compress(
        z_zeros_candidate, bytes(unix_compress_zeros_size(scale_obj))
    ):
        z_zeros_path = None

    zip_aes_path: Path | None = None
    unpacked_zip_aes = 0
    if zip_aes_path_candidate.exists():
        zip_aes_path = zip_aes_path_candidate
        # Rebuild would need cryptography; reuse size from the same recipe.
        n = max(2, min(4, scale_obj.common_members))
        unpacked_zip_aes = sum(
            len(_payload(i, scale_obj.common_member_size)) for i in range(n)
        )
    else:
        built = build_zip_aes(zip_aes_path_candidate, scale_obj)
        if built > 0 and zip_aes_path_candidate.exists():
            zip_aes_path = zip_aes_path_candidate
            unpacked_zip_aes = built

    solid_7z: Path | None = None
    many_7z: Path | None = None
    nonsolid_7z: Path | None = None
    unpacked_7z = 0
    try:
        import py7zr
    except ImportError:
        py7zr = None  # type: ignore[assignment]
    if py7zr is not None:
        solid_7z = root / "solid-large.7z"
        if not solid_7z.exists():
            unpacked_7z = build_solid_7z(solid_7z, scale_obj)
        else:
            unpacked_7z = _unpacked_solid(scale_obj)
        many_7z = root / "many-list.7z"
        if not many_7z.exists():
            build_many_member_7z(many_7z, scale_obj)
        nonsolid_path = root / "nonsolid-list.7z"
        if nonsolid_path.exists() or build_nonsolid_7z(nonsolid_path, scale_obj):
            nonsolid_7z = nonsolid_path

    # BCJ corpora need only the ``7z`` CLI, not py7zr: they are built outside the
    # py7zr branch so a missing py7zr does not silently drop the branch-filter cases.
    bcj_7z: dict[str, Path] = {}
    unpacked_bcj_bytes = 0
    for label, second_method in (
        ("lzma2", "LZMA2"),
        ("lzma1", "LZMA"),
        ("copy", "Copy"),
    ):
        bcj_path = root / f"bcj-{label}.7z"
        if bcj_path.exists():
            built = unpacked_bcj(scale_obj)
        else:
            built = build_bcj_7z(bcj_path, scale_obj, second_method=second_method)
        if built > 0 and bcj_path.exists():
            bcj_7z[label] = bcj_path
            unpacked_bcj_bytes = built

    solid_rar: Path | None = None
    many_rar: Path | None = None
    nonsolid_rar: Path | None = None
    unpacked_rar = 0
    rar_path = root / "solid-large.rar"
    if rar_path.exists():
        solid_rar = rar_path
        unpacked_rar = _unpacked_solid(scale_obj)
    else:
        built_rar = build_solid_rar(rar_path, scale_obj)
        if built_rar is not None:
            solid_rar = rar_path
            unpacked_rar = built_rar
    many_rar_path = root / "many-list.rar"
    if many_rar_path.exists() or build_many_member_rar(many_rar_path, scale_obj):
        many_rar = many_rar_path
    nonsolid_rar_path = root / "nonsolid-list.rar"
    if nonsolid_rar_path.exists() or build_nonsolid_rar(nonsolid_rar_path, scale_obj):
        nonsolid_rar = nonsolid_rar_path

    return FixtureSet(
        root=root,
        scale=scale_obj,
        zip_path=zip_path,
        zip_lzma_path=zip_lzma_path,
        zip_aes_path=zip_aes_path,
        zipcrypto_path=zipcrypto_path,
        tar_path=tar_path,
        targz_path=targz_path,
        tarbz2_path=tarbz2_path,
        gzip_path=gzip_path,
        unix_compress_text_path=z_text_path,
        unix_compress_zeros_path=z_zeros_path,
        solid_7z=solid_7z,
        many_7z=many_7z,
        nonsolid_7z=nonsolid_7z,
        bcj_7z=bcj_7z,
        solid_rar=solid_rar,
        many_rar=many_rar,
        nonsolid_rar=nonsolid_rar,
        unpacked_solid_7z=unpacked_7z,
        unpacked_bcj_7z=unpacked_bcj_bytes,
        unpacked_solid_rar=unpacked_rar,
        unpacked_zip_aes=unpacked_zip_aes,
        unpacked_zipcrypto=len(_zipcrypto_payload(scale_obj)),
    )
