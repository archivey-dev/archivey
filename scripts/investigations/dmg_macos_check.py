"""Check archivey's DMG reader and test writer against Apple's own tools (DMG plan, M).

Runs on macOS only, where ``hdiutil`` and ``fsck_hfs`` are. Two parts:

- **writer** (M.1): every image ``tests/dmg_build.py`` writes, in each partition layout
  and run codec, must pass ``hdiutil verify``; its HFS+ volume must pass
  ``fsck_hfs -n``; and once attached read-only, the mounted volume must hold what the
  writer put there (file bytes, hard links, symlinks, resource forks, extended
  attributes, compressed files read back through the file system).
- **reader** (M.2): ``hdiutil create`` makes a fresh image of a small tree in every
  format (UDZO, UDBZ, ULFO, ULMO, UDRO, UDCO) and filesystem (HFS+, HFSX); archivey's
  listing and file hashes must match the mounted volume's.

Run::

    uv run python scripts/investigations/dmg_macos_check.py --out results.md

It writes a Markdown table per part, and exits non-zero when any image fails. A format
this ``hdiutil`` cannot create is reported and not counted as a failure. The
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
FILESYSTEMS = ("HFS+", "HFSX")
# The file system's own entries, which neither side is asked to agree on.
_SYSTEM = {".fseventsd", ".Trashes", ".HFS+ Private Directory Data\r"}


@dataclass
class Result:
    name: str
    problems: list[str] = field(default_factory=list)
    skipped: str = ""

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
    done = _run(*args, str(image))
    if done.returncode != 0:
        raise RuntimeError(f"hdiutil attach failed: {done.stderr.strip()}")
    entities = plistlib.loads(done.stdout.encode())["system-entities"]
    devices = [e["dev-entry"] for e in entities if "dev-entry" in e]
    hfs = [
        e["dev-entry"]
        for e in entities
        if "Apple_HFS" in e.get("content-hint", "")
        or e.get("content-hint", "") == "48465300-0000-11AA-AA11-00306543ECAC"
    ]
    whole = min(devices, key=len)
    try:
        yield hfs or [whole], mount_dir
    finally:
        _run("hdiutil", "detach", whole, "-force")
        if mount_dir is not None:
            mount_dir.rmdir()


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
    verify = _run("hdiutil", "verify", str(path))
    if verify.returncode != 0:
        result.problems.append(
            f"hdiutil verify: {verify.stderr.strip() or verify.stdout.strip()}"
        )
    try:
        with _attached(path, mount=False) as (devices, _):
            for device in devices:
                fsck = _run("fsck_hfs", "-n", device)
                if "ermission denied" in fsck.stdout + fsck.stderr:
                    fsck = _run("sudo", "-n", "fsck_hfs", "-n", device)
                if fsck.returncode != 0:
                    tail = " ".join(fsck.stdout.strip().splitlines()[-3:])
                    result.problems.append(f"fsck_hfs -n {device}: {tail}")
        with _attached(path, mount=True) as (_, root):
            assert root is not None
            result.problems += _compare_with_nodes(root, nodes)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        result.problems.append(str(exc))
    path.unlink()
    return result


def _compare_with_nodes(root: Path, nodes: list) -> list[str]:
    problems = []
    data = {n.path: n.data for n in nodes if n.kind == "file"}
    for node in nodes:
        full = root / node.path
        if not os.path.lexists(full):
            problems.append(f"{node.path}: not on the mounted volume")
            continue
        if node.kind == "file":
            if full.read_bytes() != node.data:
                problems.append(f"{node.path}: the mounted file's bytes differ")
            if node.resource_fork:
                fork = (full / "..namedfork" / "rsrc").read_bytes()
                if fork != node.resource_fork:
                    problems.append(f"{node.path}: the resource fork differs")
            for key, value in node.xattrs.items():
                if _xattr(full, key) != value:
                    problems.append(f"{node.path}: extended attribute {key} differs")
        elif node.kind == "hardlink":
            if full.read_bytes() != data[node.target]:
                problems.append(f"{node.path}: the hard link's bytes differ")
            if os.stat(full).st_ino != os.stat(root / node.target).st_ino:
                problems.append(f"{node.path}: not the same file as {node.target}")
        elif node.kind == "symlink":
            if os.readlink(full) != node.target:
                problems.append(f"{node.path}: symlink target differs")
        elif node.kind == "dir" and not full.is_dir():
            problems.append(f"{node.path}: not a directory")
    return problems


# ── M.2: archivey against fresh hdiutil images ──────────────────────────────────────


def _make_source(src: Path) -> None:
    (src / "sub dir").mkdir(parents=True)
    (src / "hello.txt").write_bytes(b"hello dmg\n")
    (src / "text.txt").write_bytes(b"compressible line\n" * 20000)
    (src / "random.bin").write_bytes(os.urandom(300_000))
    (src / "sub dir" / "café.txt").write_bytes(b"accent")
    os.link(src / "hello.txt", src / "sub dir" / "hardlink.txt")
    os.symlink("hello.txt", src / "link-rel")
    _run("xattr", "-w", "com.example.test", "xattr value", str(src / "hello.txt"))
    plain = src.parent / "plain.txt"
    plain.write_bytes(b"compressible line\n" * 20000)
    # ditto stores the copy through decmpfs, as the committed fixtures' compressed.txt.
    _run("ditto", "--hfsCompression", str(plain), str(src / "compressed.txt"))


def _archivey_tree(image: Path) -> dict[str, tuple[str, object]]:
    from archivey import MemberType, open_archive

    found: dict[str, tuple[str, object]] = {}
    hashes: dict[str, str] = {}
    with open_archive(image) as reader:
        members = reader.members()
        for member in members:
            name = _nfc(member.name.rstrip("/"))
            if name.split("/", 1)[0] in _SYSTEM:
                continue
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
    for name, (kind, target) in list(found.items()):
        if kind == "hardlink":
            found[name] = ("file", hashes.get(str(target)))
    return found


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
        result.skipped = f"hdiutil create: {made.stderr.strip()[:120]}"
        return result
    try:
        ours = _archivey_tree(image)
    except Exception as exc:  # noqa: BLE001 - every refusal is a result here
        result.problems.append(f"archivey: {type(exc).__name__}: {exc}")
        ours = {}
    try:
        with _attached(image, mount=True) as (_, root):
            assert root is not None
            theirs = _mounted_tree(root)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        result.problems.append(str(exc))
        theirs = {}
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
    lines = [f"## {title}", "", "| Image | Outcome | Problems |", "| --- | --- | --- |"]
    for r in results:
        shown = "; ".join(r.problems[:5]).replace("|", "\\|")
        lines.append(f"| {r.name} | {r.outcome} | {shown} |")
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
            _make_source(src)
            reader = [
                _check_fresh_image(fmt, fs, src, work)
                for fmt in FORMATS
                for fs in FILESYSTEMS
            ]
            lines += _table("archivey against fresh hdiutil images (M.2)", reader)
            failed |= any(r.problems for r in reader)
    text = "\n".join(lines)
    print(text)
    if args.out is not None:
        args.out.write_text(text + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
