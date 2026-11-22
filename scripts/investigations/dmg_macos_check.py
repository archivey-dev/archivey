"""Check archivey's DMG reader and test writer against Apple's own tools (DMG plan, M).

Runs on macOS only, where ``hdiutil`` and ``fsck_hfs`` are. Two parts:

- **writer** (M.1): every image ``tests/dmg_build.py`` writes, in each partition layout
  and run codec, must pass ``hdiutil verify``; its HFS+ volume must pass
  ``fsck_hfs -n``; and once attached read-only, the mounted volume must hold what the
  writer put there (file bytes, hard links, symlinks, resource forks, extended
  attributes, compressed files read back through the file system).
- **reader** (M.2): ``hdiutil create`` makes a fresh image of a small tree in every
  format (UDZO, UDBZ, ULFO, ULMO, UDRO, UDCO) and filesystem (HFS+, HFSX); archivey's
  listing, file hashes and one extended attribute must match the mounted volume's.
  The source tree holds a decmpfs-compressed file; each row notes whether it is still
  compressed inside the image.

Run::

    uv run python scripts/investigations/dmg_macos_check.py --out results.md

It writes a Markdown table per part, and exits non-zero when any image fails, or when M.2
compared no image. Only a format in ``OPTIONAL_FORMATS`` may be skipped, when this
``hdiutil`` refuses to create it; any other failed ``hdiutil create`` is a failure. The
``dmg-macos`` workflow runs it after a merge to ``main`` that touches the DMG code and
every week.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

TIMEOUT = 300
FORMATS = ("UDZO", "UDBZ", "ULFO", "ULMO", "UDRO", "UDCO")
# Formats that a newer hdiutil may no longer create; a refusal skips the row.
OPTIONAL_FORMATS = frozenset({"UDCO"})
FILESYSTEMS = ("HFS+", "HFSX")
# The M.2 source tree's extended attribute and transparently compressed file.
XATTR_FILE, XATTR_NAME, XATTR_VALUE = "hello.txt", "com.example.test", b"xattr value"
COMPRESSED_FILE = "compressed.txt"
# Errors that a check of one image records as that image's problem.
_IMAGE_ERRORS = (RuntimeError, OSError, subprocess.TimeoutExpired)
# The file system's own entries, which neither side is asked to agree on.
_SYSTEM = {".fseventsd", ".Trashes", ".HFS+ Private Directory Data\r"}


@dataclass
class Result:
    name: str
    problems: list[str] = field(default_factory=list)
    skipped: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        if self.skipped:
            return f"skipped: {self.skipped}"
        return "ok" if not self.problems else "FAILED"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), capture_output=True, text=True, timeout=TIMEOUT, check=False
    )


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


@contextmanager
def _attached(image: Path, *, mount: bool) -> Iterator[tuple[list[str], Path | None]]:
    """The image attached read-only: its HFS device nodes, and its mount point."""
    args = ["hdiutil", "attach", "-readonly", "-nobrowse", "-noverify", "-plist"]
    mount_dir = None
    if mount:
        mount_dir = Path(tempfile.mkdtemp(prefix="dmg-mount-"))
        args += ["-mountpoint", str(mount_dir)]
    else:
        args.append("-nomount")
    try:
        done = _run(*args, str(image))
    except subprocess.TimeoutExpired:
        _remove_mount_dir(mount_dir)
        raise
    if done.returncode != 0:
        _remove_mount_dir(mount_dir)
        raise RuntimeError(f"hdiutil attach failed: {done.stderr.strip()}")
    try:
        entities = plistlib.loads(done.stdout.encode())["system-entities"]
        devices = [e["dev-entry"] for e in entities if "dev-entry" in e]
        hfs = [
            e["dev-entry"]
            for e in entities
            if "Apple_HFS" in e.get("content-hint", "")
            or e.get("content-hint", "") == "48465300-0000-11AA-AA11-00306543ECAC"
        ]
        if not devices:
            raise ValueError(
                f"no dev-entry; keys {sorted({k for e in entities for k in e})}"
            )
        # The shortest dev-entry is the whole disk (/dev/disk4, not /dev/disk4s1),
        # which is the node hdiutil detach takes.
        whole = min(devices, key=len)
    except (plistlib.InvalidFileException, KeyError, TypeError, ValueError) as exc:
        _remove_mount_dir(mount_dir)
        raise RuntimeError(
            f"hdiutil attach printed no usable device list: {exc}"
        ) from exc
    try:
        yield hfs or [whole], mount_dir
    finally:
        detached = _run("hdiutil", "detach", whole, "-force")
        if detached.returncode == 0:
            _remove_mount_dir(mount_dir)


def _remove_mount_dir(mount_dir: Path | None) -> None:
    """Remove an empty mount point; one still in use after a failed detach stays."""
    if mount_dir is not None:
        try:
            mount_dir.rmdir()
        except OSError:
            pass


def _mounted_links(root: Path) -> set[frozenset[str]]:
    """The mounted volume's hard links: each set of names that share one inode."""
    by_inode: dict[int, set[str]] = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = Path(dirpath) / name
            rel = _nfc(full.relative_to(root).as_posix())
            info = full.lstat()
            if rel.split("/", 1)[0] in _SYSTEM or not stat.S_ISREG(info.st_mode):
                continue
            if info.st_nlink > 1:
                by_inode.setdefault(info.st_ino, set()).add(rel)
    return {frozenset(names) for names in by_inode.values() if len(names) > 1}


def _mounted_tree(root: Path) -> dict[str, tuple[str, object]]:
    """What the mounted volume holds: name -> (kind, value)."""
    found: dict[str, tuple[str, object]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames]:
            full = Path(dirpath) / name
            rel = _nfc(full.relative_to(root).as_posix())
            if rel.split("/", 1)[0] in _SYSTEM:
                continue
            mode = full.lstat().st_mode
            if stat.S_ISLNK(mode):
                found[rel] = ("symlink", os.readlink(full))
            elif stat.S_ISDIR(mode):
                found[rel] = ("dir", None)
            elif stat.S_ISREG(mode):
                found[rel] = ("file", hashlib.sha256(full.read_bytes()).hexdigest())
            else:
                found[rel] = ("other", None)
    return found


def _xattr(path: Path, name: str) -> bytes | None:
    done = subprocess.run(
        ["xattr", "-px", name, str(path)], capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        return None
    return bytes.fromhex("".join(done.stdout.split()))


# ── M.1: the writer's images ─────────────────────────────────────────────────────────


def _writer_cases() -> Iterator[tuple[str, bytes, list]]:
    from tests import dmg_build as d
    from tests.test_dmg import _tree

    hfs = {"name": "Vol", "attributes_in_fork": ("user.big",)}
    codecs = {
        "raw": d.RAW,
        "zlib": d.ZLIB,
        "bzip2": d.BZIP2,
        "xz": d.LZMA,
        "adc": d.ADC,
        "lzfse": d.LZFSE,
    }
    for layout in ("gpt", "apm", "none"):
        for label, codec in codecs.items():
            image = d.dmg_of(_tree(), layout=layout, codec=codec, hfs_options=hfs)
            yield f"{layout} {label}", image, _tree()
    for label, options in (("hfsx", {"hfsx": True}), ("journal", {"journal": "clean"})):
        image = d.dmg_of(_tree(), hfs_options={**hfs, **options})
        yield f"gpt zlib {label}", image, _tree()


def _check_writer_image(name: str, image: bytes, nodes: list, work: Path) -> Result:
    result = Result(name)
    path = work / f"{name.replace(' ', '-')}.dmg"
    path.write_bytes(image)
    try:
        verify = _run("hdiutil", "verify", str(path))
        if verify.returncode != 0:
            result.problems.append(
                f"hdiutil verify: {verify.stderr.strip() or verify.stdout.strip()}"
            )
        with _attached(path, mount=False) as (devices, _):
            for device in devices:
                fsck = _run("fsck_hfs", "-n", device)
                said = fsck.stdout + fsck.stderr
                if fsck.returncode != 0 and (
                    "ermission denied" in said or "not permitted" in said
                ):
                    fsck = _run("sudo", "-n", "fsck_hfs", "-n", device)
                if fsck.returncode != 0:
                    lines = (fsck.stdout + fsck.stderr).strip().splitlines()
                    tail = " ".join(lines[-4:])
                    result.problems.append(f"fsck_hfs -n {device}: {tail}")
        with _attached(path, mount=True) as (_, root):
            assert root is not None
            result.problems += _compare_with_nodes(root, nodes)
    except _IMAGE_ERRORS as exc:
        result.problems.append(f"{type(exc).__name__}: {exc}")
    path.unlink(missing_ok=True)
    return result


def _compare_with_nodes(root: Path, nodes: list) -> list[str]:
    """What differs between the mounted volume and the writer's nodes. A read the
    file system refuses is that node's problem, so every node is still checked."""
    problems = []
    data = {n.path: n.data for n in nodes if n.kind == "file"}
    for node in nodes:
        full = root / node.path
        step = "lstat"
        try:
            if not os.path.lexists(full):
                problems.append(f"{node.path}: not on the mounted volume")
                continue
            if node.kind == "file":
                step = "read"
                if full.read_bytes() != node.data:
                    problems.append(f"{node.path}: the mounted file's bytes differ")
                if node.resource_fork:
                    step = "read the resource fork"
                    fork = (full / "..namedfork" / "rsrc").read_bytes()
                    if fork != node.resource_fork:
                        problems.append(f"{node.path}: the resource fork differs")
                for key, value in node.xattrs.items():
                    if _xattr(full, key) != value:
                        problems.append(
                            f"{node.path}: extended attribute {key} differs"
                        )
            elif node.kind == "hardlink":
                step = "read"
                if full.read_bytes() != data[node.target]:
                    problems.append(f"{node.path}: the hard link's bytes differ")
                step = "stat"
                if os.stat(full).st_ino != os.stat(root / node.target).st_ino:
                    problems.append(f"{node.path}: not the same file as {node.target}")
            elif node.kind == "symlink":
                step = "readlink"
                if os.readlink(full) != node.target:
                    problems.append(f"{node.path}: symlink target differs")
            elif node.kind == "dir" and not full.is_dir():
                problems.append(f"{node.path}: not a directory")
        except OSError as exc:
            problems.append(f"{node.path}: {step} failed: {exc.strerror or exc}")
    return problems


# ── M.2: archivey against fresh hdiutil images ──────────────────────────────────────


def _make_source(src: Path) -> None:
    """The M.2 source tree. Raises RuntimeError when a macOS tool does not do its part,
    so that the run fails instead of silently comparing less."""
    (src / "sub dir").mkdir(parents=True)
    (src / XATTR_FILE).write_bytes(b"hello dmg\n")
    (src / "text.txt").write_bytes(b"compressible line\n" * 20000)
    (src / "random.bin").write_bytes(os.urandom(300_000))
    (src / "sub dir" / "café.txt").write_bytes(b"accent")
    os.link(src / "hello.txt", src / "sub dir" / "hardlink.txt")
    os.symlink("hello.txt", src / "link-rel")
    value = XATTR_VALUE.decode()
    _checked("xattr", "-w", XATTR_NAME, value, str(src / XATTR_FILE))
    plain = src.parent / "plain.txt"
    plain.write_bytes(b"compressible line\n" * 20000)
    # ditto stores the copy through decmpfs, as the committed fixtures' compressed.txt.
    _checked("ditto", "--hfsCompression", str(plain), str(src / COMPRESSED_FILE))
    if not _is_decmpfs(src / COMPRESSED_FILE):
        raise RuntimeError(
            f"ditto --hfsCompression left {COMPRESSED_FILE} uncompressed"
        )


def _checked(*args: str) -> None:
    done = _run(*args)
    if done.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:2])} failed: {done.stderr.strip()}")


def _is_decmpfs(path: Path) -> bool:
    return bool(getattr(os.lstat(path), "st_flags", 0) & stat.UF_COMPRESSED)


def _archivey_tree(
    image: Path,
) -> tuple[dict[str, tuple[str, object]], bytes | None, set[frozenset[str]]]:
    """archivey's listing (name -> (kind, value)), the source tree's extended
    attribute as archivey lists it, and its hard links as sets of names."""
    from archivey import MemberType, open_archive

    found: dict[str, tuple[str, object]] = {}
    xattr = None
    hashes: dict[str, str] = {}
    with open_archive(image) as reader:
        members = reader.members()
        for member in members:
            name = _nfc(member.name.rstrip("/"))
            if name.split("/", 1)[0] in _SYSTEM:
                continue
            if name == XATTR_FILE:
                listed = member.extra.get("dmg.xattrs")
                if isinstance(listed, dict):
                    xattr = listed.get(XATTR_NAME)
            if member.type is MemberType.FILE:
                hashes[name] = hashlib.sha256(reader.read(member)).hexdigest()
                found[name] = ("file", hashes[name])
            elif member.type is MemberType.DIRECTORY:
                found[name] = ("dir", None)
            elif member.type is MemberType.SYMLINK:
                found[name] = ("symlink", member.link_target)
            elif member.type is MemberType.HARDLINK:
                found[name] = ("hardlink", _nfc(member.link_target or ""))
            else:
                found[name] = ("other", None)
    groups: dict[str, set[str]] = {}
    for name, (kind, target) in list(found.items()):
        if kind == "hardlink":
            groups.setdefault(str(target), {str(target)}).add(name)
            found[name] = ("file", hashes.get(str(target)))
    return found, xattr, {frozenset(names) for names in groups.values()}


def _check_fresh_image(fmt: str, fs: str, src: Path, work: Path) -> Result:
    result = Result(f"{fmt} {fs}")
    image = work / f"{fmt}-{fs.replace('+', 'P')}.dmg"
    made = _run(
        "hdiutil",
        "create",
        "-srcfolder",
        str(src),
        "-format",
        fmt,
        "-fs",
        fs,
        "-volname",
        "Vol",
        "-ov",
        str(image),
    )
    if made.returncode != 0:
        message = f"hdiutil create: {made.stderr.strip()[:200]}"
        if fmt in OPTIONAL_FORMATS:
            result.skipped = message
        else:
            result.problems.append(message)
        return result
    ours_xattr, ours_links = None, set()
    try:
        ours, ours_xattr, ours_links = _archivey_tree(image)
    except Exception as exc:  # noqa: BLE001 - every refusal is a result here
        result.problems.append(f"archivey: {type(exc).__name__}: {exc}")
        ours = {}
    try:
        with _attached(image, mount=True) as (_, root):
            assert root is not None
            theirs = _mounted_tree(root)
            theirs_links = _mounted_links(root)
            theirs_xattr = _xattr(root / XATTR_FILE, XATTR_NAME)
            if _is_decmpfs(root / COMPRESSED_FILE):
                result.notes.append(f"{COMPRESSED_FILE} is decmpfs in the image")
            else:
                result.notes.append(f"{COMPRESSED_FILE} is NOT decmpfs in the image")
    except _IMAGE_ERRORS as exc:
        result.problems.append(f"{type(exc).__name__}: {exc}")
        theirs, theirs_xattr, theirs_links = {}, None, set()
    if theirs_xattr != XATTR_VALUE:
        result.problems.append(
            f"mounted {XATTR_FILE}: extended attribute {XATTR_NAME} is {theirs_xattr!r}"
        )
    if ours and theirs and ours_links != theirs_links:
        result.problems.append(
            f"hard links: archivey {sorted(map(sorted, ours_links))}, "
            f"mounted {sorted(map(sorted, theirs_links))}"
        )
    if ours and ours_xattr != theirs_xattr:
        result.problems.append(
            f"{XATTR_FILE}: archivey lists {XATTR_NAME} as {ours_xattr!r}, "
            f"mounted {theirs_xattr!r}"
        )
    if ours or theirs:
        for name in sorted(set(ours) | set(theirs)):
            if ours.get(name) != theirs.get(name):
                result.problems.append(
                    f"{name}: archivey {ours.get(name)}, mounted {theirs.get(name)}"
                )
    image.unlink(missing_ok=True)
    return result


# ── Report ───────────────────────────────────────────────────────────────────────────


def _table(title: str, results: list[Result]) -> list[str]:
    lines = [
        f"## {title}",
        "",
        "| Image | Outcome | Problems | Notes |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        shown = "; ".join(r.problems[:12]).replace("|", "\\|")
        if len(r.problems) > 12:
            shown += f"; and {len(r.problems) - 12} more"
        notes = "; ".join(r.notes).replace("|", "\\|")
        lines.append(f"| {r.name} | {r.outcome} | {shown} | {notes} |")
    return [*lines, ""]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--part", choices=("writer", "reader", "both"), default="both")
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("this check needs macOS (hdiutil, fsck_hfs)", file=sys.stderr)
        return 2
    lines = ["# DMG check against hdiutil and fsck_hfs", ""]
    failed = False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            if args.part in ("writer", "both"):
                writer = [
                    _check_writer_image(n, i, nodes, work)
                    for n, i, nodes in _writer_cases()
                ]
                lines += _table("Writer images (M.1)", writer)
                failed |= any(r.problems for r in writer)
            if args.part in ("reader", "both"):
                src = work / "src"
                try:
                    _make_source(src)
                except _IMAGE_ERRORS as exc:
                    lines += ["## M.2", "", f"The source tree failed: {exc}", ""]
                    failed = True
                else:
                    reader = [
                        _check_fresh_image(fmt, fs, src, work)
                        for fmt in FORMATS
                        for fs in FILESYSTEMS
                    ]
                    lines += _table(
                        "archivey against fresh hdiutil images (M.2)", reader
                    )
                    failed |= any(r.problems for r in reader)
                    if not any(not r.skipped for r in reader):
                        lines += ["M.2 compared no image.", ""]
                        failed = True
    except Exception as exc:
        # Keep the parts that finished in the report; the traceback still fails the run.
        lines += ["", f"The check stopped: {type(exc).__name__}: {exc}"]
        raise
    finally:
        text = "\n".join(lines)
        print(text)
        if args.out is not None:
            args.out.write_text(text + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
