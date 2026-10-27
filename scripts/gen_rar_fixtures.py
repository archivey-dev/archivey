"""Regenerate ``tests/fixtures/rar/`` archives with the RARLAB ``rar`` CLI.

Usage (from the repo root)::

    uv run python scripts/gen_rar_fixtures.py

Requires the RARLAB ``rar`` binary on ``PATH``. RAR 7 dropped ``-ma4`` (RAR4
writing); when the system ``rar`` cannot write RAR4, this script downloads
Ubuntu's ``rar`` 6.23 package (linux x86-64), checks it against a pinned SHA-256,
unpacks only the ``rar`` binary into the user cache, and uses that for the RAR4
fixtures. The package is never installed. ``--only`` limits which fixtures are
written, so new ones can be added without rewriting the existing ones.

Legacy RAR 1.5 / 2.x archives (``rar15-comment.rar``, ``rar202-comment-nopsw.rar``)
cannot be produced by modern ``rar`` and are left untouched — they were copied
from markokr/rarfile's ``test/files`` (ISC).
"""

from __future__ import annotations

import argparse
import binascii
import fnmatch
import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "tests" / "fixtures" / "rar"

# The last RARLAB ``rar`` that writes RAR4 (``-ma4``), as Ubuntu 22.04 ships it. The
# SHA-256 is the one Ubuntu's jammy-updates multiverse ``Packages`` index lists for this
# file; that index is covered by the signed ``InRelease``. Ubuntu's archive rather
# than rarlab.com, because some build environments (Claude Code sessions among them)
# can reach the first and not the second.
_RAR623_DEB_URL = (
    "https://archive.ubuntu.com/ubuntu/pool/multiverse/r/rar/"
    "rar_6.23-1~22.04.1_amd64.deb"
)
_RAR623_DEB_SHA256 = "6f83c3b3880f0f44ce8f682b3a02fae027e9c6e61c006ef65a48bf0d9257efed"
_RAR623_DEB_MEMBER = "./usr/bin/rar"

# Fixtures modern ``rar`` cannot recreate — do not delete/overwrite.
_LEGACY_KEEP = frozenset(
    {
        "rar15-comment.rar",
        "rar202-comment-nopsw.rar",
    }
)


@dataclass(frozen=True)
class _File:
    name: str  # archive-relative path; dirs end with /
    data: bytes | None = None  # None => directory
    link_target: str | None = None  # symlink target
    hardlink_to: str | None = None  # path of existing file to link


_BASIC: tuple[_File, ...] = (
    _File("file1.txt", b"Hello, world!"),
    _File("subdir/", None),
    _File("empty_file.txt", b""),
    _File("empty_subdir/", None),
    _File("subdir/file2.txt", b"Hello, universe!"),
    _File("implicit_subdir/file3.txt", b"Hello there!"),
)

_COMMENT: tuple[_File, ...] = (
    _File("abc.txt", b"ABC"),
    _File("subdir/", None),
    _File("subdir/123.txt", b"1234567890"),
)

# Texts of the compressed RAR4 comment fixtures; the tests repeat them.
_COMPRESSED_COMMENT_ASCII = "A compressed RAR4 archive comment.\n" * 20
_COMPRESSED_COMMENT_UNICODE = "Caf\u00e9 \u2014 a compressed UTF-16 comment.\n" * 20

_ENCRYPTION: tuple[_File, ...] = (
    _File("secret.txt", b"This is secret"),
    _File("also_secret.txt", b"This is also secret"),
)


def _hex_lines(seed: bytes, size: int) -> bytes:
    """``size`` bytes of SHA-256 hex lines: about half the bits are entropy, so ``-m3``
    packs them to roughly half their size, and every byte depends on ``seed``."""
    lines = (
        hashlib.sha256(seed + i.to_bytes(4, "big")).hexdigest().encode() + b"\n"
        for i in range(size // 65 + 1)
    )
    return b"".join(lines)[:size]


# Stored encrypted members of sizes on and off the 16-byte AES block, which archivey
# decrypts itself: the ciphertext is padded to whole blocks and cut back to the size.
_ENCRYPTION_STORED_SIZES: tuple[_File, ...] = tuple(
    _File(f"size_{size}.bin", _hex_lines(b"stored_sizes", size))
    for size in (0, 7, 16, 3000, 3001)
)


# About 100 KB packed per archive under ``-m3``: two members of 100 000 bytes each,
# both past the 64 KiB confirm prefix.
_ENCRYPTION_LARGE: tuple[_File, ...] = (
    _File("large1.txt", _hex_lines(b"large1", 100_000)),
    _File("large2.txt", _hex_lines(b"large2", 100_000)),
)

_ENCRYPTION_LARGE_STORED: tuple[_File, ...] = (
    _File("large_stored.txt", _hex_lines(b"large_stored", 100_000)),
)

_SYMLINKS: tuple[_File, ...] = (
    _File("file1.txt", b"Hello, world!"),
    _File("symlink_to_file1.txt", link_target="file1.txt"),
    _File("subdir/", None),
    _File("subdir/link_to_file1.txt", link_target="../file1.txt"),
    _File("subdir_link", link_target="subdir"),
    _File("subdir_link_with_slash", link_target="subdir/"),
)

_HARDLINKS: tuple[_File, ...] = (
    _File("file1.txt", b"Hello 1!"),
    _File("subdir/file2.txt", b"Hello 2!"),
    _File("subdir/hardlink_to_file1.txt", hardlink_to="file1.txt"),
    _File("hardlink_to_file2.txt", hardlink_to="subdir/file2.txt"),
)

# Compressed on purpose: stored members never reach unrar, so a wildcard name on
# the direct-slice route is not the bug. Tiny payloads store as M0 even with
# ``-m3``; pad so packed < unpacked. ``subdir/aY.txt`` is a nested basename match
# for ``a*.txt`` (unrar MATCH_WILDSUBPATH). Windows cannot create ``*``/``?`` on
# disk at test time; the archives are committed.
_WILDCARD_PAD = b"0123456789abcdef" * 512  # 8 KiB, compressible
_WILDCARD_NAMES: tuple[_File, ...] = (
    _File("subdir/aY.txt", b"nested-aY\n" + _WILDCARD_PAD),
    _File("a*.txt", b"target-star\n" + _WILDCARD_PAD),
    _File("aX.txt", b"other-aX\n" + _WILDCARD_PAD),
    _File("b?.txt", b"target-q\n" + _WILDCARD_PAD),
    _File("b1.txt", b"other-b1\n" + _WILDCARD_PAD),
    _File("only*.dat", b"unique\n" + _WILDCARD_PAD),
)

# Directory-component glob: ``d*/x.txt`` is refused (matcher over-matches
# ``aaa/x.txt``). Add-order puts the over-match first so an unfixed skip
# truncates rather than accidentally succeeding.
_WILDCARD_DIRGLOB: tuple[_File, ...] = (
    _File("aaa/x.txt", b"aaa\n" + _WILDCARD_PAD),
    _File("dX/x.txt", b"dX\n" + _WILDCARD_PAD),
    _File("d*/x.txt", b"dstar\n" + _WILDCARD_PAD),
)

# Literal backslash vs separator: ``a\\b*.txt`` is refused. ``a/b1.txt`` is
# first so an unfixed skip that folds ``\\`` to ``/`` truncates.
_WILDCARD_BACKSLASH: tuple[_File, ...] = (
    _File("a/b1.txt", b"slashdir\n" + _WILDCARD_PAD),
    _File(r"a\b_TGT.txt", b"literal-bs-tgt\n" + _WILDCARD_PAD),
    _File(r"a\b*.txt", b"literal-bs-glob\n" + _WILDCARD_PAD),
)

_WILDCARD_VER_V1 = b"data-v1\n" + _WILDCARD_PAD
_WILDCARD_VER_V2 = b"data-v2!!\n" + _WILDCARD_PAD
_WILDCARD_VER_TARGET = b"data-tgt\n" + _WILDCARD_PAD
_WILDCARD_VER_GLOB = b"data-star\n" + _WILDCARD_PAD

# WinRAR ``-ver`` revisions of a single path (oldest → newest / live).
_FILE_VERSION_REVISIONS: tuple[bytes, ...] = (
    b"version-one",
    b"version-two!!",
    b"version-three!!!",
)

# Pinned wall-clocks for the ``-tsmca`` fixtures. ctime is inode-change on
# Unix and is whatever the writer saw; tests require it present, not equal.
_XTIME_PAYLOAD = b"xtime-payload\n"
_XTIME_MTIME = "2020-01-15 12:00:00"
_XTIME_ATIME = "2021-06-20 18:30:00"

_FILE_VERSION_SOLID_V1 = b"AAA-v1"
_FILE_VERSION_SOLID_OTHER = b"BBB-payload"
_FILE_VERSION_SOLID_V2 = b"AAA-v2-longer"

# 1 MiB repeating pad: a solid later-member rewind crosses the diagnostic
# threshold, and unrar is still writing when a test seeks mid-stream.
_SEEK_RESPAWN_PAD = b"0123456789abcdef" * (1024 * 1024 // 16)
_SEEK_RESPAWN: tuple[_File, ...] = (
    _File("prefix.bin", _SEEK_RESPAWN_PAD),
    _File("tail.txt", b"tail-member\n"),
)

# ``-s2``: solid groups of two files, so ``c.txt`` starts a second solid stream (its
# solid flag is clear) and ``d.txt`` continues it.
_SOLID_GROUPS: tuple[_File, ...] = tuple(
    _File(f"{name}.txt", f"member {name} text\n".encode() * 60) for name in "abcd"
)


def _touch_times(path: Path, *, mtime: str, atime: str) -> None:
    env = os.environ.copy()
    env["TZ"] = "UTC"
    subprocess.run(["touch", "-d", mtime, str(path)], check=True, env=env)
    subprocess.run(["touch", "-a", "-d", atime, str(path)], check=True, env=env)


def _build_xtime(rar_bin: Path, out: Path, *, extra: Sequence[str] = ()) -> None:
    """One stored ``file.txt`` with mtime+ctime+atime (``-tsmca``)."""
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        path = root / "file.txt"
        path.write_bytes(_XTIME_PAYLOAD)
        _touch_times(path, mtime=_XTIME_MTIME, atime=_XTIME_ATIME)
        _rar_a(rar_bin, out, ["file.txt"], cwd=root, extra=(*extra, "-m0", "-tsmca"))
    print(f"wrote {_shown(out)}")


def _run(cmd: Sequence[str], *, cwd: Path) -> None:
    env = os.environ.copy()
    env["TZ"] = "UTC"
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, env=env)


def _write_tree(root: Path, files: Iterable[_File]) -> list[str]:
    """Materialize members under ``root``; return rar add names in order."""
    names: list[str] = []
    for item in files:
        rel = item.name.rstrip("/")
        path = root / rel
        if item.data is None and item.link_target is None and item.hardlink_to is None:
            path.mkdir(parents=True, exist_ok=True)
            names.append(rel)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if item.link_target is not None:
            if path.exists() or path.is_symlink():
                path.unlink()
            path.symlink_to(item.link_target)
        elif item.hardlink_to is not None:
            if path.exists() or path.is_symlink():
                path.unlink()
            os.link(root / item.hardlink_to, path)
        else:
            assert item.data is not None
            path.write_bytes(item.data)
        names.append(rel)
    return names


def _supports_ma4(rar_bin: Path) -> bool:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "x.txt").write_bytes(b"x")
        probe = tmp / "probe.rar"
        try:
            _run(
                [str(rar_bin), "a", "-idq", "-ma4", "-m0", str(probe), "x.txt"], cwd=tmp
            )
        except subprocess.CalledProcessError:
            return False
        return probe.is_file()


def _cache_dir() -> Path:
    raw = os.environ.get("XDG_CACHE_HOME")
    base = Path(raw) if raw else Path.home() / ".cache"
    return base / "archivey" / "rar-gen"


def _shown(path: Path) -> Path:
    """``path`` relative to the repo when it is inside it (``--only`` builds elsewhere)."""
    return path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path


def _ar_member(archive: bytes, name: str) -> bytes:
    """The body of member ``name`` in a Unix ``ar`` archive (a ``.deb``)."""
    if not archive.startswith(b"!<arch>\n"):
        raise RuntimeError("not an ar archive")
    pos = 8
    while pos + 60 <= len(archive):
        header = archive[pos : pos + 60]
        member = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        body = archive[pos + 60 : pos + 60 + size]
        if member == name:
            return body
        pos += 60 + size + (size & 1)
    raise RuntimeError(f"{name} not found in the package")


def _zstd_decompress(data: bytes) -> bytes:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # 3.14+
    except ImportError:
        from backports import zstd  # type: ignore[no-redef]
    return zstd.decompress(data)


def _fetch_rar623() -> Path:
    """Download Ubuntu's pinned rar 6.23 package; unpack ``rar`` into the user cache."""
    dest_dir = _cache_dir() / "rar-6.23-ubuntu"
    rar_bin = dest_dir / "rar"
    if rar_bin.is_file() and os.access(rar_bin, os.X_OK) and _supports_ma4(rar_bin):
        return rar_bin

    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {_RAR623_DEB_URL}", file=sys.stderr)
    # A fixed https URL naming one package version (_RAR623_DEB_URL above).
    with urllib.request.urlopen(_RAR623_DEB_URL) as response:
        package = response.read()
    digest = hashlib.sha256(package).hexdigest()
    if digest != _RAR623_DEB_SHA256:
        raise RuntimeError(
            f"SHA-256 mismatch for the rar 6.23 package: {digest} != "
            f"{_RAR623_DEB_SHA256}"
        )
    data_tar = _zstd_decompress(_ar_member(package, "data.tar.zst"))
    with tarfile.open(fileobj=io.BytesIO(data_tar)) as tf:
        member = tf.getmember(_RAR623_DEB_MEMBER)
        extracted = tf.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"{_RAR623_DEB_MEMBER} is not a regular file")
        rar_bin.write_bytes(extracted.read())
    rar_bin.chmod(rar_bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if not _supports_ma4(rar_bin):
        raise RuntimeError(f"downloaded {rar_bin} still lacks -ma4")
    return rar_bin


def _resolve_rar(*, need_ma4: bool) -> Path:
    override = os.environ.get("ARCHIVEY_RAR_BIN")
    if override:
        path = Path(override)
        if not path.is_file():
            raise SystemExit(f"ARCHIVEY_RAR_BIN={override!r} is not a file")
        if need_ma4 and not _supports_ma4(path):
            raise SystemExit(f"ARCHIVEY_RAR_BIN={override!r} does not support -ma4")
        return path

    which = shutil.which("rar")
    if which is None:
        print(
            "No system rar; fetching rar 6.23"
            + (" for -ma4 support" if need_ma4 else ""),
            file=sys.stderr,
        )
        return _fetch_rar623()

    system = Path(which)
    if need_ma4 and not _supports_ma4(system):
        print(
            f"System rar ({system}) lacks -ma4; fetching rar 6.23 for RAR4 fixtures",
            file=sys.stderr,
        )
        return _fetch_rar623()
    return system


def _rar_a(
    rar_bin: Path,
    archive: Path,
    names: Sequence[str],
    *,
    cwd: Path,
    extra: Sequence[str] = (),
) -> None:
    if archive.exists():
        archive.unlink()
    # Drop sibling volumes if regenerating a multi-volume stem.
    stem = archive.name
    if stem.endswith(".rar"):
        base = stem[: -len(".rar")]
        for sibling in archive.parent.glob(f"{base}.part*.rar"):
            sibling.unlink()
        for sibling in archive.parent.glob(f"{base}.r[0-9][0-9]"):
            sibling.unlink()
    cmd = [str(rar_bin), "a", "-idq", "-oh", "-ol", *extra, str(archive), *names]
    _run(cmd, cwd=cwd)


def _rar_a_update(
    rar_bin: Path,
    archive: Path,
    names: Sequence[str],
    *,
    cwd: Path,
    extra: Sequence[str] = (),
) -> None:
    """Append/update members into an existing archive (keeps ``-ver`` history)."""
    cmd = [str(rar_bin), "a", "-idq", "-oh", "-ol", *extra, str(archive), *names]
    _run(cmd, cwd=cwd)


def _build_file_version(
    rar_bin: Path,
    out: Path,
    revisions: Sequence[bytes],
    *,
    extra: Sequence[str] = (),
    path_name: str = "file.txt",
) -> None:
    """Write ``path_name`` through ``revisions`` with ``-ver`` (last = live)."""
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / path_name
        target.parent.mkdir(parents=True, exist_ok=True)
        extras = [*extra, "-ver"]
        for i, payload in enumerate(revisions):
            target.write_bytes(payload)
            if i == 0:
                _rar_a(rar_bin, out, [path_name], cwd=root, extra=extras)
            else:
                _rar_a_update(rar_bin, out, [path_name], cwd=root, extra=extras)
    print(f"wrote {_shown(out)}")


def _build_file_version_solid(rar_bin: Path, out: Path) -> None:
    """Solid RAR5 with ``a.txt`` history + a second payload for demux order checks."""
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.txt").write_bytes(_FILE_VERSION_SOLID_V1)
        (root / "b.txt").write_bytes(_FILE_VERSION_SOLID_OTHER)
        extras = ("-s", "-m3", "-ver")
        _rar_a(rar_bin, out, ["a.txt", "b.txt"], cwd=root, extra=extras)
        (root / "a.txt").write_bytes(_FILE_VERSION_SOLID_V2)
        _rar_a_update(rar_bin, out, ["a.txt"], cwd=root, extra=extras)
    print(f"wrote {_shown(out)}")


def _ci_listing_recipe() -> tuple[int, int, int]:
    """``(solid members, nonsolid members, payload size)`` for the listing fixtures.

    The committed ``many_list_store*`` archives stand in for the on-demand corpora
    when the ``rar`` writer is absent (CI installs ``unrar`` only), so their member
    counts and payload size must match ``benchmarks.fixtures`` exactly — import them
    rather than restating the numbers here. Imported inside the function because this
    file runs as a script: the repo root is not on ``sys.path`` at module load.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from benchmarks.fixtures import LIST_MEMBER_SIZE, SCALES

    ci = SCALES["ci"]
    return ci.list_members, ci.nonsolid_list_members, LIST_MEMBER_SIZE


def _build_store_listing_rar(
    rar_bin: Path,
    out: Path,
    *,
    count: int,
    member_size: int,
    solid: bool,
) -> None:
    """Store (``-m0``) RAR of ``count`` tiny members; mirrors ``_build_store_rar``."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        names: list[str] = []
        for i in range(count):
            name = f"f{i:05d}.txt"
            (root / name).write_text(f"payload-{i}\n"[:member_size])
            names.append(name)
        _rar_a(
            rar_bin,
            out,
            names,
            cwd=root,
            extra=("-m0", "-s" if solid else "-s-", "-ep1"),
        )
    print(f"wrote {_shown(out)}")


def _build_glob_named(
    rar_bin: Path,
    out: Path,
    files: Sequence[_File],
    *,
    extra: Sequence[str] = (),
) -> None:
    """Add glob-named members one path at a time so ``rar a`` does not glob argv."""
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        extras = [*extra, "-r"]
        first = True
        for item in files:
            _write_tree(root, (item,))
            if first:
                _rar_a(rar_bin, out, ["."], cwd=root, extra=extras)
                first = False
            else:
                _rar_a_update(rar_bin, out, ["."], cwd=root, extra=extras)
    print(f"wrote {_shown(out)}")


def _build_wildcard_one_encrypted(rar_bin: Path, out: Path) -> None:
    """The plaintext glob names, then one member added with a password.

    Every glob-named member is plaintext, yet the archive has encryption: a read of
    one of them must hand ``unrar`` or ``unar`` no password.
    """
    _build_glob_named(rar_bin, out, _WILDCARD_NAMES, extra=("-m3",))
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "secret.txt").write_bytes(b"secret\n" + _WILDCARD_PAD)
        _rar_a_update(
            rar_bin, out, ["secret.txt"], cwd=root, extra=("-m3", "-ppassword")
        )
    print(f"wrote {_shown(out)}")


def _build_wildcard_ver(rar_bin: Path, out: Path) -> None:
    """Live glob member plus ``-ver`` history that the mask would also match.

    ``unrar p -n./data*`` without ``-ver`` omits ``data.bin;1``. The skip must
    too, or the prefix overshoots and the live glob is reported truncated.
    ``rar a data*`` globs argv, so the glob file is added from a one-file tree
    with ``-ep``.
    """
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        extras = ("-m3", "-ver")
        (root / "data.bin").write_bytes(_WILDCARD_VER_V1)
        _rar_a(rar_bin, out, ["data.bin"], cwd=root, extra=extras)
        (root / "data.bin").write_bytes(_WILDCARD_VER_V2)
        _rar_a_update(rar_bin, out, ["data.bin"], cwd=root, extra=extras)
        (root / "data_TARGET").write_bytes(_WILDCARD_VER_TARGET)
        _rar_a_update(rar_bin, out, ["data_TARGET"], cwd=root, extra=extras)
        star = root / "star_only"
        star.mkdir()
        (star / "data*").write_bytes(_WILDCARD_VER_GLOB)
        _rar_a_update(rar_bin, out, ["."], cwd=star, extra=(*extras, "-r", "-ep"))
    print(f"wrote {_shown(out)}")


# unar 1.10.1 writes nothing for a compressed RAR5 member when a Huffman lookup near
# its end peeks past the last packed byte, and exits 0.
# ``scripts/find_unar_probe_member.py`` explains why and found both ``f.txt`` members:
# the shortest over ``ab`` that RAR 7.00 ``-m3`` compresses and unar drops, alone and
# after ``a.txt`` in a solid archive (``--after hello``). In one run over the
# five-member solid archive, unar drops ``c.txt``, writes stale window bytes of
# ``d.txt``'s length and drops ``e.txt``: read by offset, the stale bytes fill
# ``c.txt``'s place. Another ``rar`` build may compress them differently;
# rerun the search, and check ``unar -o - <archive>`` still shows the fault after a
# regeneration.
_UNAR_DROP_MEMBER = _File("f.txt", b"aaaaabababbabb")
_UNAR_DROP_SOLID: tuple[_File, ...] = (
    _File("a.txt", b"hello"),
    _File("f.txt", b"ababbaa"),
)
_UNAR_STALE: tuple[_File, ...] = (
    _File("a.txt", b"alpha alpha delta tag alpha tag"),
    _File(
        "b.txt",
        b"lea tag da beta ma da alpha lea gamma delta gamma gamma ma beta da lea "
        b"beta da da delta",
    ),
    _File("c.txt", b"lea delta delta tag ma el ma"),
    _File("d.txt", b"delta el alpha lea delta gamma ma ma beta da"),
    _File(
        "e.txt", b"ma da ma lea delta delta delta alpha el el beta el alpha alpha ma"
    ),
)


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _read_vint(data: bytes | bytearray, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _strip_file_crc32(archive: Path, member: str) -> None:
    """Drop ``member``'s CRC32 from its RAR5 FILE header, leaving it no digest.

    RAR5 makes the CRC32 optional (file flag ``0x0004``); ``rar`` always writes one.
    The header is rewritten without it and its header CRC recomputed.
    """
    data = bytearray(archive.read_bytes())
    pos = 8  # the RAR5 signature
    while pos < len(data):
        size, body_at = _read_vint(data, pos + 4)
        end = body_at + size
        block_type, q = _read_vint(data, body_at)
        flags, q = _read_vint(data, q)
        if flags & 0x0001:  # extra area
            _, q = _read_vint(data, q)
        data_size = 0
        if flags & 0x0002:  # data area
            data_size, q = _read_vint(data, q)
        if block_type == 2:
            flags_at = q
            file_flags, q = _read_vint(data, q)
            flags_end = q
            _, q = _read_vint(data, q)  # unpacked size
            _, q = _read_vint(data, q)  # attributes
            if file_flags & 0x0002:  # mtime
                q += 4
            crc_at = q
            if file_flags & 0x0004:
                q += 4
            _, q = _read_vint(data, q)  # compression info
            _, q = _read_vint(data, q)  # host OS
            name_len, q = _read_vint(data, q)
            if file_flags & 0x0004 and data[q : q + name_len] == member.encode():
                body = (
                    data[body_at:flags_at]
                    + _vint(file_flags & ~0x0004)
                    + data[flags_end:crc_at]
                    + data[crc_at + 4 : end]
                )
                head = _vint(len(body)) + body
                crc = binascii.crc32(head) & 0xFFFFFFFF
                data[pos:end] = crc.to_bytes(4, "little") + head
                archive.write_bytes(bytes(data))
                return
        if block_type == 5:  # end of archive
            break
        pos = end + data_size
    raise ValueError(f"no RAR5 FILE header with a CRC32 for {member!r} in {archive}")


def _build_unar_drop(rar5_bin: Path, out_dir: Path) -> None:
    """Members unar 1.10.1 drops; in a solid run, other bytes then sit in their place."""
    builds: list[tuple[str, tuple[_File, ...], tuple[str, ...], str | None]] = [
        ("unar_drop__.rar", (_UNAR_DROP_MEMBER,), ("-m3",), None),
        (
            "unar_drop_solid__.rar",
            _UNAR_DROP_SOLID,
            ("-s", "-m3"),
            None,
        ),
        ("unar_stale_solid__.rar", _UNAR_STALE, ("-s", "-m3"), None),
        # The dropped member with no digest: only its size is left to check, and the
        # stale bytes that follow it in the run are long enough to pass that.
        ("unar_stale_nocrc_solid__.rar", _UNAR_STALE, ("-s", "-m3"), "c.txt"),
    ]
    for out_name, files, extra, strip in builds:
        out = out_dir / out_name
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            names = _write_tree(root, files)
            _rar_a(rar5_bin, out, names, cwd=root, extra=extra)
        if strip is not None:
            _strip_file_crc32(out, strip)
        print(f"wrote {_shown(out)}")


def _cut_set_payload(index: int, size: int) -> bytes:
    """Member ``index`` of the ``tinyvol_cut*`` sets: text that compresses about
    twofold. ``tests/test_rar_missing_last_volume.py`` rebuilds the same bytes."""
    digest = b"".join(
        hashlib.sha256(f"{index}:{block}".encode()).digest()
        for block in range(size // 32 + 1)
    )
    return bytes(b"abcdefgh \n"[byte % 10] for byte in digest[:size])


# ``tinyvol_cut*``: (stem, member size, ``rar`` switches). Four members over several
# volumes; the last volume is deleted, so the fourth member runs into it.
_CUT_SETS: tuple[tuple[str, int, tuple[str, ...]], ...] = (
    ("tinyvol_cut", 1000, ("-m0", "-v1500b")),
    ("tinyvol_cut_solid", 2000, ("-s", "-m3", "-v900b")),
)


def _build_missing_last_volume(rar5_bin: Path, out_dir: Path) -> None:
    """Volume sets with their last volume deleted, stored and solid."""
    for stem, size, extra in _CUT_SETS:
        for stale in out_dir.glob(f"{stem}.part*.rar"):
            stale.unlink()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            names = [f"{letter}.txt" for letter in "abcd"]
            for index, name in enumerate(names):
                (root / name).write_bytes(_cut_set_payload(index, size))
            _rar_a(rar5_bin, out_dir / f"{stem}.rar", names, cwd=root, extra=extra)
        volumes = sorted(out_dir.glob(f"{stem}.part*.rar"))
        if len(volumes) < 4:
            raise RuntimeError(f"expected {stem} to span at least four volumes")
        volumes[-1].unlink()
        for volume in volumes[:-1]:
            print(f"wrote {_shown(volume)}")


def generate_all(*, rar5_bin: Path, rar4_bin: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def build(
        rar_bin: Path,
        out_name: str,
        files: Sequence[_File],
        *,
        extra: Sequence[str] = (),
        comment: str | None = None,
    ) -> None:
        out = out_dir / out_name
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            extras = list(extra)
            if comment is not None:
                cpath = root / ".archive_comment.txt"
                cpath.write_text(comment, encoding="utf-8")
                extras.append(f"-z{cpath}")
            has_glob = any("*" in f.name or "?" in f.name for f in files)
            # ``rar a a*.txt`` globs. Add glob-named trees one path at a time so
            # prefix-skip fixtures keep add order.
            if has_glob:
                extras.append("-r")
                first = True
                for item in files:
                    _write_tree(root, (item,))
                    if first:
                        _rar_a(rar_bin, out, ["."], cwd=root, extra=extras)
                        first = False
                    else:
                        _rar_a_update(rar_bin, out, ["."], cwd=root, extra=extras)
            else:
                names = _write_tree(root, files)
                _rar_a(rar_bin, out, names, cwd=root, extra=extras)
        print(f"wrote {_shown(out)}")

    # --- RAR5 ---
    build(rar5_bin, "basic_nonsolid__.rar", _BASIC, extra=("-m0",))
    build(rar5_bin, "basic_solid__.rar", _BASIC, extra=("-s", "-m3"))
    build(rar5_bin, "solid_groups__.rar", _SOLID_GROUPS, extra=("-s2", "-m3"))
    build(
        rar5_bin,
        "seek_respawn_solid__.rar",
        _SEEK_RESPAWN,
        extra=("-s", "-m3", "-ds"),
    )
    build(
        rar5_bin,
        "comment__.rar",
        _COMMENT,
        extra=("-m0",),
        comment="This is a\nmulti-line comment",
    )
    build(
        rar5_bin,
        "encryption__.rar",
        _ENCRYPTION,
        extra=("-m3", "-ppassword"),
    )
    # Solid and encrypted: one `unrar p` pass needs one password for every member.
    build(
        rar5_bin,
        "encryption_solid__.rar",
        _ENCRYPTION,
        extra=("-s", "-m3", "-ppassword"),
    )
    build(
        rar5_bin,
        "encrypted_header__.rar",
        _BASIC,
        extra=("-m3", "-hpheader_password"),
    )
    build(
        rar5_bin,
        "symlinks_solid__.rar",
        _SYMLINKS,
        extra=("-s", "-m3"),
    )
    build(
        rar5_bin,
        "hardlinks_solid__.rar",
        _HARDLINKS,
        extra=("-s", "-m3"),
    )
    build(rar5_bin, "wildcard_names__.rar", _WILDCARD_NAMES, extra=("-m3",))
    build(
        rar5_bin,
        "wildcard_names_solid__.rar",
        _WILDCARD_NAMES,
        extra=("-s", "-m3"),
    )
    _build_glob_named(
        rar5_bin, out_dir / "wildcard_dirglob__.rar", _WILDCARD_DIRGLOB, extra=("-m3",)
    )
    _build_glob_named(
        rar5_bin,
        out_dir / "wildcard_backslash__.rar",
        _WILDCARD_BACKSLASH,
        extra=("-m3",),
    )
    _build_wildcard_one_encrypted(
        rar5_bin, out_dir / "wildcard_names_one_encrypted__.rar"
    )
    _build_wildcard_ver(rar5_bin, out_dir / "wildcard_ver__.rar")
    _build_xtime(rar5_bin, out_dir / "xtime__.rar")
    # Solid, with the second member stored (``-msbin``): rar sets that member's own
    # solid flag although its bytes sit in the file as plaintext. The first member is
    # compressed, so the archive is solid in more than name.
    build(
        rar5_bin,
        "stored_solid_member__.rar",
        (
            _File("first.txt", b"compressible line\n" * 128),
            _File("second.bin", hashlib.sha256(b"stored_solid_member").digest() * 64),
        ),
        extra=("-s", "-m3", "-msbin"),
    )
    build(
        rar5_bin,
        "stored_m0.rar",
        (_File("store.txt", b"stored payload"),),
        extra=("-m0",),
    )
    build(
        rar5_bin,
        "blake2sp.rar",
        (_File("store.txt", b"stored payload"),),
        extra=("-m0", "-htb"),
    )
    build(
        rar5_bin,
        "encryption_blake2sp.rar",
        (_File("store.txt", b"stored payload"),),
        extra=("-m0", "-htb", "-ppassword"),
    )
    build(
        rar5_bin,
        "encryption_stored__.rar",
        (_File("secret.txt", b"This is secret"),),
        # Stored *and* encrypted, with the default CRC32 rather than ``-htb``:
        # the digest then lives in the fixed FILE header and survives damage to
        # the extra area, which is what lets a cut-short header be settled by
        # the checksum alone (``test_rar_header_record_leniency``).
        extra=("-m0", "-ppassword"),
    )
    build(
        rar5_bin,
        "encryption_stored_sizes__.rar",
        _ENCRYPTION_STORED_SIZES,
        extra=("-m0", "-ppassword"),
    )
    _build_unar_drop(rar5_bin, out_dir)
    _build_file_version(
        rar5_bin,
        out_dir / "file_version__.rar",
        _FILE_VERSION_REVISIONS,
        extra=("-m0",),
    )
    _build_file_version_solid(rar5_bin, out_dir / "file_version_solid__.rar")

    # Many-member store listing fixtures (ci-scale structural gate; no ``rar`` in CI).
    # ``-m0`` never sets the archive solid bit — ``-s`` / ``-s-`` still distinguish
    # the regeneration commands.
    many_members, nonsolid_members, member_size = _ci_listing_recipe()
    _build_store_listing_rar(
        rar5_bin,
        out_dir / "many_list_store__.rar",
        count=many_members,
        member_size=member_size,
        solid=True,
    )
    _build_store_listing_rar(
        rar5_bin,
        out_dir / "many_list_store_nonsolid__.rar",
        count=nonsolid_members,
        member_size=member_size,
        solid=False,
    )

    # Multi-volume: 1600-byte payload, 900-byte volumes → two parts.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "payload.bin").write_bytes(b"ABCDEFGH" * 200)
        out = out_dir / "tinyvol.rar"
        _rar_a(
            rar5_bin,
            out,
            ["payload.bin"],
            cwd=root,
            extra=("-m0", "-v900b"),
        )
        part1 = out_dir / "tinyvol.part1.rar"
        part2 = out_dir / "tinyvol.part2.rar"
        if not part1.is_file() or not part2.is_file():
            raise RuntimeError(f"expected {part1.name} and {part2.name}")
        if out.is_file():
            out.unlink()
        print(f"wrote {_shown(part1)}")
        print(f"wrote {_shown(part2)}")

    # Compressed multi-volume: the reader joins a stored member's parts itself, so
    # tests that need unrar to read across volumes (and the volumes to be copied for
    # it) use this one. SHA-256 blocks keep the 1600 bytes from compressing below
    # one volume.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "payload.bin").write_bytes(
            b"".join(hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(50))
        )
        out = out_dir / "tinyvol_m3.rar"
        _rar_a(
            rar5_bin,
            out,
            ["payload.bin"],
            cwd=root,
            extra=("-m3", "-v900b"),
        )
        part1 = out_dir / "tinyvol_m3.part1.rar"
        part2 = out_dir / "tinyvol_m3.part2.rar"
        if (
            not part1.is_file()
            or not part2.is_file()
            or (out_dir / "tinyvol_m3.part3.rar").exists()
        ):
            raise RuntimeError("expected tinyvol_m3 to span exactly two volumes")
        if out.is_file():
            out.unlink()
        print(f"wrote {_shown(part1)}")
        print(f"wrote {_shown(part2)}")

    # Header-encrypted volumes: every part carries its own encryption record with
    # the same salt, so a listing must derive the header key once, not per part.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "payload.bin").write_bytes(b"ABCDEFGH" * 200)
        out = out_dir / "tinyvol_hp.rar"
        _rar_a(
            rar5_bin,
            out,
            ["payload.bin"],
            cwd=root,
            extra=("-m0", "-v900b", "-hpheader_password"),
        )
        # ``_rar_a`` unlinks earlier ``tinyvol_hp.part*.rar`` first, so these are
        # this run's parts. The tests expect exactly four.
        parts = [out_dir / f"tinyvol_hp.part{n}.rar" for n in range(1, 5)]
        if (
            not all(part.is_file() for part in parts)
            or (out_dir / "tinyvol_hp.part5.rar").exists()
        ):
            raise RuntimeError("expected tinyvol_hp to span exactly four volumes")
        if out.is_file():
            out.unlink()
        for part in parts:
            print(f"wrote {_shown(part)}")

    # Stored, encrypted and split: each part has its own encryption record, so
    # archivey does not decrypt it itself, and a program reads it.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "payload.bin").write_bytes(b"ABCDEFGH" * 200)
        out = out_dir / "tinyvol_enc.rar"
        _rar_a(
            rar5_bin,
            out,
            ["payload.bin"],
            cwd=root,
            extra=("-m0", "-v1200b", "-ppassword"),
        )
        part1 = out_dir / "tinyvol_enc.part1.rar"
        part2 = out_dir / "tinyvol_enc.part2.rar"
        if (
            not part1.is_file()
            or not part2.is_file()
            or (out_dir / "tinyvol_enc.part3.rar").exists()
        ):
            raise RuntimeError("expected tinyvol_enc to span exactly two volumes")
        if out.is_file():
            out.unlink()
        print(f"wrote {_shown(part1)}")
        print(f"wrote {_shown(part2)}")

    _build_missing_last_volume(rar5_bin, out_dir)

    # --- RAR4 (needs -ma4) ---
    # Classic extension volumes (name.rar + name.r00…): RAR4-only via -vn.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "payload.bin").write_bytes(b"ABCDEFGH" * 200)
        out = out_dir / "tinyvol_rnn.rar"
        _rar_a(
            rar4_bin,
            out,
            ["payload.bin"],
            cwd=root,
            extra=("-ma4", "-m0", "-vn", "-v900b"),
        )
        vol0 = out_dir / "tinyvol_rnn.rar"
        vol1 = out_dir / "tinyvol_rnn.r00"
        if not vol0.is_file() or not vol1.is_file():
            raise RuntimeError(f"expected {vol0.name} and {vol1.name}")
        print(f"wrote {_shown(vol0)}")
        print(f"wrote {_shown(vol1)}")

    _build_xtime(rar4_bin, out_dir / "xtime__rar4.rar", extra=("-ma4",))
    build(rar4_bin, "basic_nonsolid__rar4.rar", _BASIC, extra=("-ma4", "-m0"))
    build(rar4_bin, "basic_solid__rar4.rar", _BASIC, extra=("-ma4", "-s", "-m3"))
    build(
        rar4_bin,
        "encryption__rar4.rar",
        _ENCRYPTION,
        extra=("-ma4", "-m3", "-ppassword"),
    )
    build(
        rar4_bin,
        "encrypted_header__rar4.rar",
        _BASIC,
        extra=("-ma4", "-m3", "-hpheader_password"),
    )
    build(
        rar4_bin,
        "symlinks_solid__rar4.rar",
        _SYMLINKS,
        extra=("-ma4", "-s", "-m3"),
    )
    build(
        rar4_bin,
        "wildcard_names__rar4.rar",
        _WILDCARD_NAMES,
        extra=("-ma4", "-m3"),
    )
    # RAR 2.9-4 archive comments in a compressed ``CMT`` SERVICE header: ``rar``
    # compresses a comment that shrinks, so the text repeats. Without ``-sc`` the
    # ASCII comment is stored as 8-bit text. ``-scfc`` reads the comment file as
    # UTF-8 and stores it as UTF-16LE with ``SUBHEAD_FLAGS_CMT_UNICODE`` set.
    build(
        rar4_bin,
        "comment_compressed__rar4.rar",
        _COMMENT,
        extra=("-ma4", "-m3"),
        comment=_COMPRESSED_COMMENT_ASCII,
    )
    build(
        rar4_bin,
        "comment_compressed_unicode__rar4.rar",
        _COMMENT,
        extra=("-ma4", "-m3", "-scfc"),
        comment=_COMPRESSED_COMMENT_UNICODE,
    )
    _build_file_version(
        rar4_bin,
        out_dir / "file_version__rar4.rar",
        _FILE_VERSION_REVISIONS,
        extra=("-ma4", "-m0"),
    )
    # Encrypted RAR4 members larger than the 64 KiB password-confirm prefix. RAR3/4
    # data carries no password check, so a wrong password from a list can survive the
    # prefix; these exercise the full check that settles it. ``-p`` encrypts the data
    # only, so the listing needs no password.
    build(
        rar4_bin,
        "encryption_large__rar4.rar",
        _ENCRYPTION_LARGE,
        extra=("-ma4", "-m3", "-ppassword"),
    )
    build(
        rar4_bin,
        "encryption_large_solid__rar4.rar",
        _ENCRYPTION_LARGE,
        extra=("-ma4", "-s", "-m3", "-ppassword"),
    )
    build(
        rar4_bin,
        "encryption_large_stored__rar4.rar",
        _ENCRYPTION_LARGE_STORED,
        extra=("-ma4", "-m0", "-ppassword"),
    )

    build(
        rar4_bin,
        "encryption_stored_sizes__rar4.rar",
        _ENCRYPTION_STORED_SIZES,
        extra=("-ma4", "-m0", "-ppassword"),
    )
    # RAR 2.9-4 keeps a symlink's target as the member's stored data, so ``-p``
    # encrypts it; listing with the password decrypts it.
    build(
        rar4_bin,
        "symlinks_encrypted__rar4.rar",
        _SYMLINKS,
        extra=("-ma4", "-m3", "-ppassword"),
    )

    kept = ", ".join(sorted(_LEGACY_KEEP))
    print(f"left legacy fixtures untouched: {kept}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT_DIR,
        help=f"output directory (default: {OUT_DIR})",
    )
    parser.add_argument(
        "--only",
        action="append",
        metavar="GLOB",
        help=(
            "write only the fixtures whose file name matches GLOB (repeatable); "
            "everything is still built, in a temporary directory, and the rest is "
            "discarded, so existing fixtures stay byte-identical"
        ),
    )
    args = parser.parse_args(argv)
    out_dir = args.out_dir.resolve()

    rar5 = _resolve_rar(need_ma4=False)
    if _supports_ma4(rar5):
        rar4 = rar5
    else:
        rar4 = _resolve_rar(need_ma4=True)

    print(f"rar5 binary: {rar5}", file=sys.stderr)
    print(f"rar4 binary: {rar4}", file=sys.stderr)
    if not args.only:
        generate_all(rar5_bin=rar5, rar4_bin=rar4, out_dir=out_dir)
        return 0
    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td)
        generate_all(rar5_bin=rar5, rar4_bin=rar4, out_dir=scratch)
        chosen = sorted(
            path
            for path in scratch.iterdir()
            if any(fnmatch.fnmatchcase(path.name, glob) for glob in args.only)
        )
        if not chosen:
            raise SystemExit(f"--only matched no fixture: {args.only}")
        out_dir.mkdir(parents=True, exist_ok=True)
        for path in chosen:
            shutil.copyfile(path, out_dir / path.name)
            print(f"kept {path.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
