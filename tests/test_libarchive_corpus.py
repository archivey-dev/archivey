"""Compare Archivey against libarchive on libarchive's own uuencoded test archives.

Off by default. Point ``ARCHIVEY_LIBARCHIVE_TEST_FILES`` at libarchive's
``libarchive/test`` directory (clone https://github.com/libarchive/libarchive and
use ``…/libarchive/test``)::

    ARCHIVEY_LIBARCHIVE_TEST_FILES=/path/to/libarchive/libarchive/test \\
      uv run --no-sync pytest tests/test_libarchive_corpus.py -q

Reference ``.uu`` blobs are decoded into ``ARCHIVEY_TEST_CACHE`` on first use.
Skips archives libarchive cannot open, non-primary split volumes, libarchive
fuzz/crash fixtures, and formats Archivey does not implement.

Triage (2026-07, vs libarchive ``libarchive/test``) — known failures marked
``xfail``:

**Compress / filter**
* **GAP** ``.tlz`` with raw LZMA Alone payloads — extension maps to TAR+lzip;
  Archivey has no TAR+LZMA-Alone stream format.
* **HARNESS** bare ``.lz`` that libarchive does not list as an archive
  (``test_compat_lzip_3``).

**ZIP**
* **GAP** ZIPX XZ (method 95) — no codec path yet.
* ZIPX PPMd / Zstd decode via the shared codec layer when `[recommended]` is
  installed; WinZip AES (method 99) decrypts via the same extra.
* **GAP** ZIP members whose payload exceeds the declared size (libarchive
  fixtures) — size/CRC checks reject them.
* **GAP** assorted ZIP edge cases (extra padding, UTF-8 path presentation,
  MSDOS directory typing).

**TAR / sparse / nested**
* **GAP** GNU sparse variants / PAX edge headers that stdlib ``tarfile`` rejects.
* **NESTED** ``*.iso.Z`` / ``*.cpio.gz`` — outer compress around a non-TAR
  container Archivey does not compose (skipped, not xfail).

**RAR**
* **GAP** some RAR5 extra-field / crypt-only headers; multi-volume sets need
  sibling volumes (skipped like other split volumes).
"""

from __future__ import annotations

import binascii
import io
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import FormatDetectionError, MemberType, detect_format, open_archive
from archivey.types import ArchiveFormat, ContainerFormat, StreamFormat
from tests.conftest import ARCHIVEY_TEST_CACHE, binary_refusal, requires
from tests.sample_archives import publish_cached

_ENV = "ARCHIVEY_LIBARCHIVE_TEST_FILES"
_CACHE_SUBDIR = "libarchive-corpus"

# Passwords documented beside libarchive's own read tests.
_PASSWORDS: dict[str, str] = {
    "test_read_format_7zip_encryption.7z": "12345678",
    "test_read_format_zip_zipx_encrypted.zipx": "test_password_zipx",
    "test_read_format_zip_traditional_encryption_data.zip": "12345678",
    "test_read_format_zip_encryption_data.zip": "12345678",
    "test_read_format_zip_encryption_header.zip": "12345678",
    "test_read_format_zip_encryption_partially.zip": "12345678",
    "test_read_format_zip_winzip_aes128.zip": "password",
    "test_read_format_zip_winzip_aes256.zip": "password",
    "test_read_format_zip_winzip_aes256_large.zip": "password",
    "test_read_format_zip_winzip_aes256_stored.zip": "password",
}

# Try these when an archive name hints at encryption but has no explicit mapping.
_ENCRYPTION_NAME_HINTS = ("encrypt", "aes", "password", "psw")
_FALLBACK_PASSWORDS = ("password", "test_password_zipx", "12345678", "secret")

# Continuation volumes — open via the first part only.
_SKIP_NAMES = frozenset(
    {
        "test_read_splitted_rar_ab",
        "test_read_splitted_rar_ac",
        "test_read_splitted_rar_ad",
        "test_read_splitted_rar_aa",
        "test_read_large_splitted_rar_ab",
        "test_read_large_splitted_rar_ac",
        "test_read_large_splitted_rar_ad",
        "test_read_large_splitted_rar_ae",
        "test_splitted_rar_seek_support_ab",
        "test_splitted_rar_seek_support_ac",
        "test_splitted_rar_seek_support_aa",
        # RAR5 multiarchive fixtures need sibling volumes beside part01.
        "test_read_format_rar5_multiarchive.part01.rar",
        "test_read_format_rar5_multiarchive_solid.part01.rar",
        # Nested: outer unix-compress / gzip around ISO or cpio (no composed format).
        "test_read_format_iso.iso.Z",
        "test_read_format_iso_2.iso.Z",
        "test_read_format_iso_3.iso.Z",
        "test_read_format_iso_joliet.iso.Z",
        "test_read_format_iso_joliet_by_nero.iso.Z",
        "test_read_format_iso_joliet_long.iso.Z",
        "test_read_format_iso_joliet_rockridge.iso.Z",
        "test_read_format_iso_multi_extent.iso.Z",
        "test_read_format_iso_rockridge.iso.Z",
        "test_read_format_iso_rockridge_ce.iso.Z",
        "test_read_format_iso_rockridge_ce_loop.iso.Z",
        "test_read_format_iso_rockridge_new.iso.Z",
        "test_read_format_iso_rockridge_rr_moved.iso.Z",
        "test_read_format_iso_xorriso.iso.Z",
        "test_read_format_iso_zisofs.iso.Z",
        "test_write_disk_appledouble.cpio.gz",
        # GNU sparse skip-entry OOMs/segfaults the process — skip rather than xfail.
        "test_read_format_gtar_sparse_skip_entry.tar.Z",
    }
)

_PART_RE = re.compile(
    r"\.part(?P<num>[2-9]\d*)\.rar\Z|\.part0*(?P<num2>[2-9]\d*)\.rar\Z",
    re.IGNORECASE,
)

# Triaged divergences. Values are (strict, reason).
_XFAIL: dict[str, tuple[bool, str]] = {
    # --- compress / filter ---
    "test_compat_lzma_1.tlz": (
        True,
        "GAP: .tlz extension maps to TAR+lzip; payload is raw LZMA Alone",
    ),
    "test_compat_lzma_2.tlz": (
        True,
        "GAP: .tlz extension maps to TAR+lzip; payload is raw LZMA Alone",
    ),
    "test_compat_lzma_3.tlz": (
        True,
        "GAP: .tlz extension maps to TAR+lzip; payload is raw LZMA Alone",
    ),
    "test_compat_lzip_3.lz": (
        True,
        "HARNESS: libarchive lists no members for this bare lzip fixture",
    ),
    # --- ZIP ---
    # ZIPX PPMd8 / Zstd / WinZip AES now decode via the shared codec / cryptography paths;
    # they are no longer xfailed (AES fixtures use passwords from `_PASSWORDS`).
    "test_read_format_zip_xz_multi.zipx": (
        True,
        "GAP: ZIPX XZ unsupported (no ZIP method-95 codec path yet)",
    ),
    "test_read_data_into_fd_size_exceeds_declared_deflate.zip": (
        True,
        "GAP: stdlib zipfile rejects payload larger than declared size",
    ),
    "test_read_data_into_fd_size_exceeds_declared_stored.zip": (
        True,
        "GAP: stdlib zipfile rejects payload larger than declared size",
    ),
    "test_read_format_zip_size_exceeds_declared_deflate.zip": (
        True,
        "GAP: stdlib zipfile rejects payload larger than declared size",
    ),
    "test_read_format_zip_size_exceeds_declared_stored.zip": (
        True,
        "GAP: stdlib zipfile rejects payload larger than declared size",
    ),
    "test_read_format_zip.zip": (
        True,
        "GAP: libarchive ZIP fixture trips stdlib CRC check on file2",
    ),
    "test_read_format_zip_extra_padding.zip": (
        True,
        "GAP: ZIP with extra padding rejected by stdlib zipfile",
    ),
    "test_read_format_zip_7075_utf8_paths.zip": (
        True,
        "GAP: UTF-8 path presentation differs from libarchive",
    ),
    "test_read_format_zip_msdos.zip": (
        True,
        "GAP: MSDOS directory entry typed as FILE vs DIRECTORY",
    ),
    # --- TAR / sparse / PAX ---
    "test_read_format_gtar_sparse_1_17_posix10_modified.tar": (
        True,
        "GAP: modified GNU sparse header not handled by stdlib tarfile",
    ),
    "test_read_format_tar_V_negative_size.tar": (
        True,
        "GAP: negative TAR size / invalid offset rejected by stdlib tarfile",
    ),
    "test_read_pax_empty_val_no_nl.tar": (
        True,
        "GAP: empty PAX value without newline rejected by stdlib tarfile",
    ),
    "test_read_format_tar_empty_with_gnulabel.tar": (
        True,
        "GAP: empty TAR with GNU label member-set differs from libarchive",
    ),
    "test_read_format_gtar_redundant_L.tar.Z": (
        True,
        "GAP: GNU long-name (L) handling differs from libarchive",
    ),
    "test_read_format_gtar_sparse_length.tar.Z": (
        True,
        "GAP: GNU sparse length / hole presentation differs from libarchive",
    ),
    "test_read_format_tar_empty_pax.tar.Z": (
        True,
        "GAP: empty PAX TAR over unix-compress rejected by stdlib tarfile",
    ),
    # --- RAR ---
    "test_read_format_rar5_only_crypt_exfld.rar": (
        True,
        "GAP: RAR5 crypt-only extra field parsing",
    ),
    "test_read_format_rar5_unsupported_exfld.rar": (
        True,
        "GAP: RAR5 unsupported extra field parsing",
    ),
    "test_read_format_rar_unbound_staticdata.rar": (
        True,
        "GAP: RAR3 unbound static data / zero header size",
    ),
    "test_read_format_rar5_extra_field_version.rar": (
        True,
        "GAP: RAR5 version extra-field member naming",
    ),
}

# libarchive's own robustness/fuzz fixtures — not conformance oracles for Archivey.
_SKIP_SUBSTRINGS = (
    "fuzz",
    "oom",
    "malformed",
    "overflow",
    "crash",
    "invalid",
    "truncat",
    "corrupt",
    "endarc_huge",
    "newsub_huge",
    "symlink_huge",
    "distance_overflow",
    "readtables_overflow",
)


def _files_dir() -> Path | None:
    raw = os.environ.get(_ENV)
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.is_dir() else None


def _cache_dir() -> Path:
    root = Path(ARCHIVEY_TEST_CACHE) / _CACHE_SUBDIR
    root.mkdir(parents=True, exist_ok=True)
    return root


def _decode_uu(source: Path, dest: Path) -> None:
    """Decode a classic ``begin … end`` uuencode file without stdlib ``uu``.

    ``uu`` was removed in Python 3.13; ``binascii.a2b_uu`` remains. Libarchive's
    ``*.uu`` fixtures use the traditional format this helper understands.
    """
    if dest.exists() and dest.stat().st_size > 0:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    started = False
    out = io.BytesIO()
    with source.open("rb") as encoded:
        for raw_line in encoded:
            line = raw_line.rstrip(b"\r\n")
            if not started:
                if line.startswith(b"begin "):
                    started = True
                continue
            if line == b"end" or line.startswith(b"end "):
                break
            if not line:
                continue
            try:
                out.write(binascii.a2b_uu(line))
            except binascii.Error as exc:
                # Some encoders write a length byte that overstates trailing
                # padding; tolerate a short final fragment like stdlib uu did.
                nbytes = (line[0] - 32) & 63
                if nbytes:
                    raise ValueError(f"uu decode failed on {source.name}") from exc
    if not started:
        raise ValueError(f"no uu begin line in {source.name}")
    # Publish through a temp file so a parallel worker never reads a half-written dest.
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".decoding-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(out.getvalue())
        publish_cached(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


def _safe_decode_uu(source: Path, dest: Path) -> bool:
    try:
        _decode_uu(source, dest)
    except (OSError, ValueError, binascii.Error):
        return False  # dest is only ever written whole, so there is nothing to clean up
    return True


def _materialize_archive(uu_path: Path) -> Path | None:
    name = uu_path.name
    if not name.endswith(".uu"):
        return None
    base = name[:-3]
    dest = _cache_dir() / base
    if not _safe_decode_uu(uu_path, dest):
        return None
    try:
        info = detect_format(dest)
    except (FormatDetectionError, OSError, ValueError):
        if dest.exists():
            dest.unlink(missing_ok=True)
        return None
    if info.format.container is ContainerFormat.UNKNOWN:
        if dest.exists():
            dest.unlink(missing_ok=True)
        return None
    # Nested outer-compress around ISO/cpio: detect as bare compressor, not a
    # composed Archivey format. Skip rather than compare against libarchive's
    # multi-filter open.
    if info.format.container is ContainerFormat.RAW_STREAM and (
        base.lower().endswith(".iso.z")
        or base.lower().endswith(".cpio.gz")
        or base.lower().endswith(".cpio.z")
    ):
        return None
    return dest


def _password_candidates(archive_name: str) -> tuple[str | None, ...]:
    explicit = _PASSWORDS.get(archive_name)
    if explicit is not None:
        return (explicit,)
    lower = archive_name.lower()
    if any(hint in lower for hint in _ENCRYPTION_NAME_HINTS):
        return (None, *_FALLBACK_PASSWORDS)
    return (None,)


def _archivey_password(archive_name: str) -> str | tuple[str, ...] | None:
    """Password argument for ``open_archive`` (omit bare ``None`` candidates)."""
    cands = [p for p in _password_candidates(archive_name) if p is not None]
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    return tuple(cands)


def _normalize_name(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("./").rstrip("/")
    return normalized or "."


def _libarchive_expect_type(entry: object) -> MemberType:
    if entry.isdir:  # type: ignore[attr-defined]
        return MemberType.DIRECTORY
    if entry.issym:  # type: ignore[attr-defined]
        return MemberType.SYMLINK
    if entry.islnk:  # type: ignore[attr-defined]
        return MemberType.HARDLINK
    return MemberType.FILE


def _iter_uu_sources(root: Path) -> Iterator[Path]:
    for uu_path in sorted(root.glob("*.uu")):
        base = uu_path.name[:-3]
        if base in _SKIP_NAMES:
            continue
        lower = base.lower()
        if any(token in lower for token in _SKIP_SUBSTRINGS):
            continue
        if _PART_RE.search(base):
            continue
        yield uu_path


def _collect_libarchive_oracle(
    archive: Path, libarchive_mod: object
) -> tuple[dict[str, object], dict[str, bytes], dict[str, str | None]]:
    libarchive = libarchive_mod
    last_error: Exception | None = None
    for password in _password_candidates(archive.name):
        oracle_infos: dict[str, object] = {}
        oracle_bytes: dict[str, bytes] = {}
        oracle_link_targets: dict[str, str | None] = {}
        try:
            with libarchive.file_reader(  # type: ignore[attr-defined]
                str(archive), passphrase=password
            ) as entries:
                for entry in entries:
                    key = _normalize_name(entry.pathname)
                    oracle_infos[key] = entry
                    expect_type = _libarchive_expect_type(entry)
                    if expect_type is MemberType.FILE:
                        oracle_bytes[key] = b"".join(
                            block for block in entry.get_blocks()
                        )
                    elif expect_type in (MemberType.SYMLINK, MemberType.HARDLINK):
                        oracle_link_targets[key] = entry.linkpath or entry.linkname
            return oracle_infos, oracle_bytes, oracle_link_targets
        except Exception as exc:  # noqa: BLE001 — try the next passphrase candidate
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"libarchive did not attempt to open {archive.name}")


def _uu_param(path: Path) -> pytest.ParameterSet:
    name = path.name[:-3]
    xfail = _XFAIL.get(name)
    if xfail is None:
        return pytest.param(path, id=name)
    strict, reason = xfail
    return pytest.param(
        path, id=name, marks=pytest.mark.xfail(strict=strict, reason=reason)
    )


_ROOT = _files_dir()
_UU_SOURCES = list(_iter_uu_sources(_ROOT)) if _ROOT is not None else []

pytestmark = [
    pytest.mark.skipif(
        _ROOT is None,
        reason=f"set {_ENV} to libarchive's libarchive/test directory to run this corpus",
    ),
    requires("libarchive"),
]


@pytest.fixture(scope="module")
def libarchive_mod():
    return pytest.importorskip("libarchive")


@pytest.mark.parametrize(
    "uu_source",
    [_uu_param(p) for p in _UU_SOURCES],
)
def test_native_matches_libarchive_on_libarchive_corpus(
    uu_source: Path, libarchive_mod: object
) -> None:
    archive = _materialize_archive(uu_source)
    if archive is None:
        pytest.skip(f"unsupported or undecodable fixture {uu_source.name}")

    if archive.suffix.lower() == ".rar" and (
        (refusal := binary_refusal("unrar")) is not None
    ):
        pytest.skip(f"RAR data tests need a RARLAB data program: {refusal}")

    try:
        oracle_infos, oracle_bytes, oracle_link_targets = _collect_libarchive_oracle(
            archive, libarchive_mod
        )
    except Exception as exc:  # noqa: BLE001 — oracle may reject unsupported fixtures
        pytest.skip(f"libarchive cannot open {archive.name}: {exc}")

    password = _archivey_password(archive.name)
    if password is not None and (
        archive.name.endswith(".7z") or "aes" in archive.name.lower()
    ):
        pytest.importorskip("cryptography")

    with open_archive(archive, password=password) as native:
        native_by_name = {_normalize_name(m.name): m for m in native.members()}

        assert set(native_by_name) == set(oracle_infos), (
            f"member name mismatch for {archive.name}: "
            f"only_native={sorted(set(native_by_name) - set(oracle_infos))} "
            f"only_libarchive={sorted(set(oracle_infos) - set(native_by_name))}"
        )

        for key, entry in oracle_infos.items():
            member = native_by_name[key]
            expect_type = _libarchive_expect_type(entry)
            assert member.type is expect_type, (
                f"{archive.name}:{key}: type {member.type} != {expect_type}"
            )
            if expect_type is MemberType.FILE:
                assert member.size == entry.size, (
                    f"{archive.name}:{key}: size {member.size} != {entry.size}"
                )
                assert native.read(member) == oracle_bytes[key], (
                    f"{archive.name}:{key}: byte mismatch"
                )
            elif expect_type in (MemberType.SYMLINK, MemberType.HARDLINK):
                expected_target = oracle_link_targets.get(key)
                assert member.link_target == expected_target, (
                    f"{archive.name}:{key}: link_target "
                    f"{member.link_target!r} != {expected_target!r}"
                )


def test_libarchive_corpus_discovered_archives() -> None:
    """Sanity: the env-pointed directory actually contains libarchive fixtures."""
    assert _ROOT is not None
    assert _UU_SOURCES, f"no .uu reference archives found under {_ROOT}"
    names = {p.name[:-3] for p in _UU_SOURCES}
    assert (
        "test_compat_gzip_1.tgz" in names
        or "test_read_format_zip.zip" in names
        or any(name.endswith(".zip") for name in names)
    )


def test_tar_z_detection_upgrades_via_inner_probe() -> None:
    """Regression: unix-compress inner-TAR probe must upgrade ``*.tar.Z`` fixtures."""
    if _ROOT is None:
        pytest.skip(f"set {_ENV} to run")
    uu = _ROOT / "test_compat_mac-1.tar.Z.uu"
    if not uu.exists():
        pytest.skip("libarchive fixture test_compat_mac-1.tar.Z.uu not present")
    archive = _materialize_archive(uu)
    assert archive is not None
    info = detect_format(archive)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.UNIX_COMPRESS)
