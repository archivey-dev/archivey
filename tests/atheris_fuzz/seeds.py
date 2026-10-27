"""Seed corpus for Atheris targets: declarative corpus + adversarial fixtures + tiny blobs."""

from __future__ import annotations

import base64
import gzip
import io
import lzma
import shutil
import sys
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

from tests.conftest import run_7z, sevenzip_lists_arm64
from tests.sample_archives import CORPUS, corpus_archive_path

# Small corpus entry ids that build quickly and cover common layouts.
_SEED_ENTRY_IDS = frozenset(
    {"basic", "encoding", "large", "adversarial", "adversarial-tar"}
)
# Encrypted ZIP when the 7z CLI is available (AES / ZipCrypto fixtures).
_ENC_SEED_ENTRY_IDS = frozenset({"encrypted", "encrypted-mixed", "encrypted-multi"})
# A 7zAES-encoded header (py7zr, in process), so the 7z targets reach the
# encrypted-header branch with the corpus password.
_SEVENZIP_ENC_SEED_ENTRY_IDS = frozenset({"encrypted-header"})

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADVERSARIAL_DIR = _REPO_ROOT / "tests" / "fixtures" / "adversarial"

_SAMPLE = b"atheris seed payload\n" * 8


def _corpus_seeds(
    format_key: str,
    tmp: Path,
    *,
    entry_ids: frozenset[str] = _SEED_ENTRY_IDS,
    allow_binaries: bool = False,
) -> list[bytes]:
    out: list[bytes] = []
    for entry in CORPUS:
        if entry.id not in entry_ids:
            continue
        if format_key not in entry.formats:
            continue
        if entry.requires_binaries and not allow_binaries:
            continue
        try:
            path = corpus_archive_path(entry, format_key, tmp)
        except (OSError, RuntimeError, ValueError, ImportError):
            continue
        if path.is_file():
            out.append(path.read_bytes())
    return out


def _adversarial_seeds(*suffixes: str) -> list[bytes]:
    if not _ADVERSARIAL_DIR.is_dir():
        return []
    out: list[bytes] = []
    for path in sorted(_ADVERSARIAL_DIR.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if suffixes and not any(name.endswith(s) for s in suffixes):
            continue
        try:
            out.append(path.read_bytes())
        except OSError:
            continue
    return out


def sevenzip_seeds() -> list[bytes]:
    from archivey.internal.backends.sevenzip_parser import MAGIC_7Z

    tiny = [
        b"",
        MAGIC_7Z,
        MAGIC_7Z + bytes(26),
        b"not a 7z archive",
        MAGIC_7Z + b"\x00\x04" + b"\xff" * 24,
    ]
    with tempfile.TemporaryDirectory(prefix="atheris-seed-7z-") as tmp:
        tmp_path = Path(tmp)
        corpus = _corpus_seeds("7z", tmp_path)
        enc = _corpus_seeds("7z", tmp_path, entry_ids=_SEVENZIP_ENC_SEED_ENTRY_IDS)
        return (
            tiny
            + corpus
            + enc
            + _uncompressed_header_sevenzip_seeds(tmp_path)
            + _adversarial_seeds(".7z")
        )


def _synthetic_zip_seeds() -> list[bytes]:
    """Stored + deflate ZIPs so CRC fixup / native codec paths have known-good seeds."""
    out: list[bytes] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("stored.txt", _SAMPLE)
    out.append(buf.getvalue())

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("deflate.txt", _SAMPLE * 4)
        zf.writestr("empty.txt", b"")
    out.append(buf.getvalue())
    return out


def zip_seeds() -> list[bytes]:
    tiny = [b"", b"PK\x03\x04", b"PK\x05\x06" + bytes(18), b"not a zip"]
    with tempfile.TemporaryDirectory(prefix="atheris-seed-zip-") as tmp:
        tmp_path = Path(tmp)
        corpus = _corpus_seeds("zip", tmp_path)
        # Encrypted / AES corpus when 7z can build them (optional).
        enc = _corpus_seeds(
            "zip",
            tmp_path,
            entry_ids=_ENC_SEED_ENTRY_IDS,
            allow_binaries=True,
        )
        return (
            tiny
            + _synthetic_zip_seeds()
            + _zip_layout_seeds()
            + corpus
            + enc
            + _adversarial_seeds(".zip")
        )


def tar_seeds() -> list[bytes]:
    tiny = [b"", b"ustar\x00", b"not a tar"]
    with tempfile.TemporaryDirectory(prefix="atheris-seed-tar-") as tmp:
        return (
            tiny
            + _synthetic_tar_seeds()
            + _corpus_seeds("tar", Path(tmp))
            + _corpus_seeds("tar.gz", Path(tmp))
            + _adversarial_seeds(".tar", ".tar.gz", ".tgz")
        )


def iso_seeds() -> list[bytes]:
    tiny = [b"", b"\x00" * 32768, b"not an iso"]
    with tempfile.TemporaryDirectory(prefix="atheris-seed-iso-") as tmp:
        return tiny + _corpus_seeds("iso", Path(tmp)) + _adversarial_seeds(".iso")


def rar_seeds() -> list[bytes]:
    """Tiny magics + on-disk RAR fixtures (RAR3/RAR5, solid, links, volumes, …)."""
    from archivey.internal.backends.rar_parser import RAR5_ID, RAR_ID

    tiny = [
        b"",
        RAR_ID,
        RAR5_ID,
        b"not rar",
        RAR_ID + b"\x00" * 32,
        RAR5_ID + b"\xff" * 64,
        # SFX-shaped: garbage prefix then magic (parser scans up to SFX_MAX).
        b"MZ" + b"\x00" * 64 + RAR5_ID + b"\x00" * 16,
    ]
    fixture_dir = _REPO_ROOT / "tests" / "fixtures" / "rar"
    fixtures: list[bytes] = []
    if fixture_dir.is_dir():
        for path in sorted(fixture_dir.glob("*.rar")):
            # Skip volume continuation alone — needs part1 as first volume.
            if path.name.endswith(".part2.rar") or ".part2." in path.name:
                continue
            # Header-encrypted archives need a password; still useful as reject-path seeds.
            try:
                fixtures.append(path.read_bytes())
            except OSError:
                continue
    return tiny + fixtures + _adversarial_seeds(".rar")


def detect_format_seeds() -> list[bytes]:
    """Mixed prefixes for ``detect_format`` — prefer short heads of real archives."""
    seeds: list[bytes] = [b"", b"\x00" * 16, b"PK", b"7z", b"Rar!", b"ustar"]
    for builder in (sevenzip_seeds, zip_seeds, tar_seeds, iso_seeds, rar_seeds):
        try:
            for blob in builder():
                seeds.append(blob[: min(len(blob), 512)])
                if len(blob) > 512:
                    seeds.append(blob[:4096])
        except (OSError, RuntimeError, ValueError, ImportError):
            continue
    seeds.extend(decoy_dense_seeds())
    # UDIF's koly block and a short stub in front of a ZIP. detect_format names both;
    # the open_detected target is what then opens them.
    seeds.append(_koly_block())
    seeds.append(b"BZh9" + b"\x00" * 32 + _koly_block())
    seeds.append(b"MZ" + b"\x00" * 64 + _synthetic_zip_seeds()[0])
    # Dedup while preserving order.
    seen: set[bytes] = set()
    out: list[bytes] = []
    for s in seeds:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def decoy_dense_prefix(mutator_tail: bytes = b"", *, window: int = 64 * 1024) -> bytes:
    """Pack near-miss headers for every scan-tier format into a bounded window.

    Used by the ``detect_format`` fuzz target so aggregate cost-vs-budget is exercised
    against many candidate-looking hits, not only against sparse mutator luck. The
    measured amplification that motivates a bound — 209 715 valid gzip headers in 2 MiB
    yielding 683-fold decode work — is a scan-tier property; this seed family keeps that
    class of input in the corpus for any scan tier that grades them.
    """
    # Near-miss / exact needles packed back-to-back. Exact magics that would short-circuit
    # detection at offset 0 are shifted so the densest region sits past the near window.
    needles = (
        b"\x1f\x8b\x08",  # gzip
        b"BZh9",  # bzip2
        b"\xfd7zXZ\x00",  # xz
        b"\x28\xb5\x2f\xfd",  # zstd
        b"7z\xbc\xaf'\x1c",  # 7z
        b"Rar!\x1a\x07\x00",  # RAR4
        b"Rar!\x1a\x07\x01\x00",  # RAR5
        b"PK\x03\x04",  # ZIP local
        b"ustar",  # TAR
        b"\xff\xd8\xff",  # JPEG (non-cueing prefix for later ZIP-tail work)
    )
    pad = b"\x00" * 16
    block = pad.join(needles) + pad
    body = (block * ((window // len(block)) + 1))[:window]
    if mutator_tail:
        body = body[: max(0, window - len(mutator_tail))] + mutator_tail[: window // 4]
        body = body[:window]
    return body


def decoy_dense_seeds() -> list[bytes]:
    return [
        decoy_dense_prefix(),
        decoy_dense_prefix(b"\xff" * 64),
        decoy_dense_prefix(window=4096),
        decoy_dense_prefix(window=256 * 1024),
    ]


def _safe_compress(fn: Callable[[], bytes]) -> list[bytes]:
    try:
        return [fn()]
    except (OSError, RuntimeError, ValueError, ImportError, lzma.LZMAError):
        return []


def unix_compress_seeds() -> list[bytes]:
    tiny = [
        b"",
        b"\x1f\x9d",
        b"\x1f\x9d\x90",
        b"not compress",
        b"\x1f\x9d" + b"\xff" * 64,
    ]
    good: list[bytes] = []
    try:
        from tests.streams_util import make_unix_compress

        good.append(make_unix_compress(_SAMPLE))
        good.append(make_unix_compress(b""))
    except (OSError, RuntimeError, ValueError, ImportError):
        pass
    return tiny + good + _adversarial_seeds(".Z", ".z")


def xz_seeds() -> list[bytes]:
    tiny = [b"", b"\xfd7zXZ\x00", b"not xz", b"\xfd7zXZ\x00" + b"\xff" * 32]
    good = _safe_compress(lambda: lzma.compress(_SAMPLE, format=lzma.FORMAT_XZ))
    return tiny + good + _adversarial_seeds(".xz")


def lzip_seeds() -> list[bytes]:
    tiny = [b"", b"LZIP", b"LZIP\x01", b"not lzip"]
    good: list[bytes] = []
    try:
        from tests.streams_util import make_lzip_member

        good.append(make_lzip_member(_SAMPLE))
    except (OSError, RuntimeError, ValueError, ImportError, lzma.LZMAError):
        pass
    return tiny + good + _adversarial_seeds(".lz")


def gzip_seeds() -> list[bytes]:
    tiny = [b"", b"\x1f\x8b", b"\x1f\x8b\x08", b"not gzip"]
    good = [gzip.compress(_SAMPLE), gzip.compress(b"")]
    return tiny + good + _adversarial_seeds(".gz")


def bzip2_seeds() -> list[bytes]:
    import bz2

    tiny = [b"", b"BZ", b"BZh", b"not bzip2"]
    good = [bz2.compress(_SAMPLE)]
    return tiny + good + _adversarial_seeds(".bz2", ".bz")


def _accel_payload() -> bytes:
    """About 200 KiB, half text and half incompressible: several DEFLATE blocks and two
    bzip2 blocks (``-1``), so a seek has more than one restart point to choose from."""
    import random

    noise = random.Random(0x5EED).randbytes(96 * 1024)
    return (_SAMPLE * 600)[: 100 * 1024] + noise


def accel_gzip_seeds() -> list[bytes]:
    payload = _accel_payload()
    member = gzip.compress(payload, compresslevel=6, mtime=0)
    small = gzip.compress(_SAMPLE, mtime=0)
    named = io.BytesIO()
    with gzip.GzipFile(fileobj=named, mode="wb", filename="seed.txt", mtime=0) as gz:
        gz.write(_SAMPLE)
    return (
        gzip_seeds()
        + [
            member,
            member + gzip.compress(_SAMPLE, mtime=0),  # two members
            named.getvalue(),  # FNAME header field
            member[: len(member) // 2],  # cut mid-data
            # The shape this target found: a last member cut right after its header,
            # where rapidgzip ends with no error, after a further member.
            small + small + small[:10],
        ]
    )


def accel_bzip2_seeds() -> list[bytes]:
    import bz2

    payload = _accel_payload()
    stream = bz2.compress(payload, compresslevel=1)
    return (
        bzip2_seeds()
        + [
            stream,
            stream + bz2.compress(_SAMPLE),  # two streams
            stream[: len(stream) // 2],  # cut mid-block
        ]
    )


def _with_declared_size(size: int, data: bytes) -> bytes:
    """Prefix ``data`` with the declared size ``targets.split_declared_size`` reads."""
    return size.to_bytes(4, "little") + data


def _raw_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


def accel_zlib_seeds() -> list[bytes]:
    payload = _accel_payload()
    full = zlib.compress(payload)
    return [
        _with_declared_size(0, b""),
        _with_declared_size(len(_SAMPLE), zlib.compress(_SAMPLE)),
        _with_declared_size(len(payload), full),
        _with_declared_size(len(payload), full[: len(full) // 2]),
        _with_declared_size(len(payload) // 2, full),  # size understated
    ]


def accel_deflate_seeds() -> list[bytes]:
    payload = _accel_payload()
    full = _raw_deflate(payload)
    return [
        _with_declared_size(0, b""),
        _with_declared_size(0, _raw_deflate(b"")),
        _with_declared_size(len(_SAMPLE), _raw_deflate(_SAMPLE)),
        _with_declared_size(len(payload), full),
        _with_declared_size(len(payload), full[: len(full) // 2]),
        _with_declared_size(len(payload) + 1, full),  # size overstated
        # The input this target found: one non-final block of 168 bytes, no final
        # block, and a declared size of 168. rapidgzip ends it with no error.
        base64.b64decode("qAAAAOIsyUhOVizKLShNTVEoSKzMyU9M4UocfIIA"),
    ]


def lzma_alone_seeds() -> list[bytes]:
    tiny = [b"", b"]\x00\x00", b"not lzma"]
    good = _safe_compress(lambda: lzma.compress(_SAMPLE, format=lzma.FORMAT_ALONE))
    return tiny + good + _adversarial_seeds(".lzma")


def zlib_seeds() -> list[bytes]:
    tiny = [b"", b"x\x9c", b"not zlib"]
    good = [zlib.compress(_SAMPLE)]
    return tiny + good


def zstd_seeds() -> list[bytes]:
    tiny = [b"", b"\x28\xb5\x2f\xfd", b"not zstd"]
    good: list[bytes] = []
    try:
        import zstandard

        good.append(zstandard.ZstdCompressor().compress(_SAMPLE))
    except (OSError, RuntimeError, ValueError, ImportError):
        pass
    return tiny + good + _adversarial_seeds(".zst", ".zstd")


def brotli_seeds() -> list[bytes]:
    tiny = [b"", b"not brotli", b"\x81"]
    good: list[bytes] = []
    try:
        import brotli

        good.append(brotli.compress(_SAMPLE))
    except (OSError, RuntimeError, ValueError, ImportError):
        pass
    return tiny + good


def lz4_seeds() -> list[bytes]:
    tiny = [b"", b'\x04"M\x18', b"not lz4"]
    good: list[bytes] = []
    try:
        import lz4.frame

        good.append(lz4.frame.compress(_SAMPLE))
    except (OSError, RuntimeError, ValueError, ImportError):
        pass
    return tiny + good + _adversarial_seeds(".lz4")


def deflate64_seeds() -> list[bytes]:
    """Hostile / tiny blobs — real Deflate64 fixtures are rare; magics still useful."""
    tiny = [b"", b"not deflate64", b"\x00" * 16, b"\xff" * 64]
    # Prefer any on-disk fixtures that look like Deflate64 ZIP members if present.
    return tiny + _adversarial_seeds(".deflate64")


def _koly_block() -> bytes:
    """A 512-byte UDIF trailer: ``koly``, version 4, header size 512."""
    block = bytearray(512)
    block[0:4] = b"koly"
    block[4:8] = (4).to_bytes(4, "big")
    block[8:12] = (512).to_bytes(4, "big")
    return bytes(block)


def _synthetic_tar_seeds() -> list[bytes]:
    """PAX, GNU and ustar archives, including a name that needs an extended header.

    The TAR target recomputes header checksums, so these blocks are the structures
    a mutation of the type flag or the size can stay inside.
    """
    payload = b"atheris tar payload\n" * 4
    out: list[bytes] = []
    for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
            info = tarfile.TarInfo("dir/nested/file.txt")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
            # ustar refuses a name past 100 bytes. PAX and GNU store it in an
            # extended header, which is the block the checksum fixup must keep valid.
            if fmt != tarfile.USTAR_FORMAT:
                long = tarfile.TarInfo("nested/" + ("a" * 180) + ".txt")
                long.size = 4
                tf.addfile(long, io.BytesIO(b"long"))
        out.append(buf.getvalue())
    return out


class _WritablePipe(io.RawIOBase):
    """A non-seekable buffer ``zipfile`` can write a data-descriptor archive to."""

    def __init__(self) -> None:
        self._data = bytearray()

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self._data += b
        return len(b)

    def tell(self) -> int:
        # zipfile asks for the offset while it writes a stream it cannot seek.
        return len(self._data)

    def getvalue(self) -> bytes:
        return bytes(self._data)


def _zip_layout_seeds() -> list[bytes]:
    """ZIP shapes the stored/deflate seeds do not have.

    A data-descriptor member (sizes live after the payload), a ZIP64 end record on
    a small archive, and the local headers of a stored archive with the central
    directory cut off.
    """
    out: list[bytes] = []
    pipe = _WritablePipe()
    with zipfile.ZipFile(pipe, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("descriptor.txt", _SAMPLE)
        zf.writestr("empty.txt", b"")
    out.append(pipe.getvalue())

    previous = zipfile.ZIP_FILECOUNT_LIMIT
    try:
        # zipfile emits ZIP64 records once the count limit is already exceeded.
        zipfile.ZIP_FILECOUNT_LIMIT = 0  # type: ignore[misc]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("zip64.txt", b"zip64 seed")
        out.append(buf.getvalue())
    finally:
        zipfile.ZIP_FILECOUNT_LIMIT = previous  # type: ignore[misc]

    stored = _synthetic_zip_seeds()[0]
    central = stored.find(b"PK\x01\x02")
    if central > 0:
        out.append(stored[:central])
    return out


def _x86_like(size: int = 4096) -> bytes:
    """Bytes with CALL/JMP/Jcc opcodes, so a BCJ2 seed has call and jump streams."""
    chunk = b"\xe8\x10\x00\x00\x00\xe9\x08\x00\x00\x00\x0f\x84\x04\x00\x00\x00"
    return (chunk * ((size // len(chunk)) + 1))[:size]


# ``-mhc=off`` leaves the next header uncompressed, so a mutated coder field is
# still a header. Dictionaries stay at 1 MiB, inside the fuzz decoder cap.
# ``aes`` is the exception: ``-mhe=on`` encrypts that header. It is here for the
# password path, not because its coder fields are in the clear.
# Each row is the seed name, the ``7z`` switches, ``"one"`` or ``"both"``
# members, and the package a decode of that seed needs. ``None`` decodes with
# no optional package. The seed is still built when the package is absent.
_UNCOMPRESSED_HEADER_SPECS: tuple[tuple[str, tuple[str, ...], str, str | None], ...] = (
    ("copy", ("-mhc=off", "-m0=Copy"), "one", None),
    ("lzma2", ("-mhc=off", "-m0=LZMA2", "-md=1m"), "one", None),
    ("bcj", ("-mhc=off", "-m0=LZMA2", "-m1=BCJ", "-md=1m"), "one", None),
    ("delta", ("-mhc=off", "-m0=LZMA2", "-m1=Delta:4", "-md=1m"), "one", None),
    (
        "bcj2",
        (
            "-mhc=off",
            "-m0=BCJ2",
            "-m1=LZMA2",
            "-m2=LZMA",
            "-m3=LZMA",
            "-mb0s0:1",
            "-mb0s1:2",
            "-mb0s2:3",
            "-md=1m",
        ),
        "one",
        None,
    ),
    ("arm64", ("-mhc=off", "-m0=ARM64", "-m1=Copy"), "one", None),
    ("ppmd", ("-mhc=off", "-m0=PPMd:mem=8m"), "one", "pyppmd"),
    (
        "aes",
        ("-mhc=off", "-mhe=on", "-ppassword", "-m0=LZMA2", "-md=1m"),
        "one",
        "cryptography",
    ),
    ("solid", ("-mhc=off", "-ms=on", "-m0=LZMA2", "-md=1m"), "both", None),
)


def _header_spec_builds(switches: tuple[str, ...], *, arm64: bool) -> bool:
    """Whether ``switches`` are expected from a ``7z`` with this ARM64 answer.

    ``-m0=ARM64`` is expected only when ``arm64`` is true.
    """
    return "-m0=ARM64" not in switches or arm64


def uncompressed_header_spec_names() -> list[str]:
    """Spec names this ``7z`` is expected to build.

    A row whose switches include ``-m0=ARM64`` is required only when
    :func:`tests.conftest.sevenzip_lists_arm64` is true. Every other spec is
    required whenever ``7z`` is on PATH.
    """
    arm64 = sevenzip_lists_arm64()
    return [
        name
        for name, switches, _which, _package in _UNCOMPRESSED_HEADER_SPECS
        if _header_spec_builds(switches, arm64=arm64)
    ]


def _uncompressed_header_sevenzip_archives(
    tmp: Path,
) -> list[tuple[str, bytes, str | None]]:
    """``(name, bytes, package)`` for each spec in :func:`uncompressed_header_spec_names`.

    ``package`` is the optional import a decode of that seed needs, or ``None``.
    A missing ``7z`` returns an empty list. A spec ``7z`` rejects is omitted and
    its switches and stderr are written to stderr, so the loss is not silent.
    A row with ``-m0=ARM64`` is not attempted when ``7z i`` does not list that
    filter, and that skip is written to stderr too.
    """
    if shutil.which("7z") is None:
        return []
    payload = tmp / "code.bin"
    payload.write_bytes(_x86_like())
    other = tmp / "other.bin"
    other.write_bytes(b"second member\n" * 32)
    arm64 = sevenzip_lists_arm64()
    out: list[tuple[str, bytes, str | None]] = []
    for name, switches, which, package in _UNCOMPRESSED_HEADER_SPECS:
        if not _header_spec_builds(switches, arm64=arm64):
            # ``_header_spec_builds`` declines only ``-m0=ARM64``.
            print(
                f"7z seed {name} skipped: this 7z does not list the ARM64 filter",
                file=sys.stderr,
            )
            continue
        archive = tmp / f"{name}.7z"
        inputs = [payload.name, other.name] if which == "both" else [payload.name]
        result = run_7z(
            ["a", "-y", "-bd", *switches, archive.name, *inputs],
            cwd=tmp,
            check=False,
        )
        if result.returncode == 0 and archive.is_file():
            out.append((name, archive.read_bytes(), package))
            continue
        detail = result.stderr.decode("utf-8", "replace").strip()
        print(
            f"7z seed {name} was not built ({result.returncode}): "
            f"{' '.join(switches)}\n{detail}",
            file=sys.stderr,
        )
    return out


def _uncompressed_header_sevenzip_seeds(tmp: Path) -> list[bytes]:
    """The archives from :func:`_uncompressed_header_sevenzip_archives`, bytes only."""
    return [
        blob for _name, blob, _package in _uncompressed_header_sevenzip_archives(tmp)
    ]


def _compressed_tar_seeds() -> list[bytes]:
    """A PAX tar inside gzip, bzip2 and xz.

    With no file name, only the content probe reports these as compressed tar.
    The bytes are also a single-file gzip/bzip2/xz.
    """
    raw = _synthetic_tar_seeds()[0]
    out = [gzip.compress(raw)]
    try:
        import bz2

        out.append(bz2.compress(raw))
    except (OSError, RuntimeError, ValueError, ImportError):
        pass
    out.extend(_safe_compress(lambda: lzma.compress(raw, format=lzma.FORMAT_XZ)))
    return out


def _take_small(blobs: list[bytes], *, limit: int, max_bytes: int) -> list[bytes]:
    out: list[bytes] = []
    for blob in blobs:
        if not blob or len(blob) > max_bytes:
            continue
        out.append(blob)
        if len(out) >= limit:
            break
    return out


def open_detected_seeds() -> list[bytes]:
    """Short real archives, SFX prefixes, UDIF trailers and compressed tars.

    Large fixtures are left to the format's own target. This target's per-input
    limit has to cover detection plus a bounded read, so a multi-megabyte seed
    would fail the slice before any mutation.
    """
    seeds: list[bytes] = [b"", b"MZ", b"not an archive"]
    builders = (
        zip_seeds,
        tar_seeds,
        sevenzip_seeds,
        rar_seeds,
        iso_seeds,
        gzip_seeds,
        bzip2_seeds,
        xz_seeds,
        lzip_seeds,
        lzma_alone_seeds,
        zlib_seeds,
        zstd_seeds,
        brotli_seeds,
        lz4_seeds,
        unix_compress_seeds,
    )
    for builder in builders:
        try:
            seeds.extend(_take_small(builder(), limit=4, max_bytes=48 * 1024))
        except (OSError, RuntimeError, ValueError, ImportError):
            continue
    prefixed: list[bytes] = []
    for blob in seeds:
        if blob.startswith((b"PK\x03\x04", b"7z\xbc\xaf'\x1c", b"Rar!")):
            prefixed.append(b"MZ" + b"\x00" * 128 + blob)
        if len(prefixed) >= 6:
            break
    seeds.extend(prefixed)
    # Uncompressed-header 7z archives are small and are the coder-graph seeds.
    # ``_take_small`` on ``sevenzip_seeds`` fills up on the tiny magics first.
    with tempfile.TemporaryDirectory(prefix="atheris-seed-open-7z-") as tmp:
        seeds.extend(_uncompressed_header_sevenzip_seeds(Path(tmp)))
    seeds.append(_koly_block())
    seeds.append(b"BZh9" + b"\x00" * 64 + _koly_block())
    seeds.append(b"\xfd7zXZ\x00" + b"\x00" * 64 + _koly_block())
    seeds.extend(_compressed_tar_seeds())
    return seeds


def filter_seeds() -> list[bytes]:
    """One seed per filter kind, plus a BCJ2 split with a declared output size.

    Byte 0 selects the filter. The rest is payload, except the BCJ2 seed, whose
    next twelve bytes are four split weights and an output size. The kind count
    is the one ``filters_one`` uses.
    """
    from tests.atheris_fuzz.targets import FILTER_KIND_COUNT

    sample = _x86_like(2048)
    seeds = [b"", *(bytes([kind]) + sample for kind in range(FILTER_KIND_COUNT))]
    weights = b"\x40\x00\x10\x00\x10\x00\x08\x00"
    unpack = (4096).to_bytes(4, "little")
    seeds.append(bytes([0]) + weights + unpack + sample)
    return seeds


def write_seed_corpus(directory: Path, seeds: list[bytes]) -> int:
    """Write seed files for libFuzzer ``-seed_inputs`` / corpus dir. Returns count."""
    directory.mkdir(parents=True, exist_ok=True)
    written = 0
    for i, seed in enumerate(seeds):
        path = directory / f"seed-{i:04d}"
        path.write_bytes(seed)
        written += 1
    return written
