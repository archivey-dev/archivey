"""Wall time of archivey against other readers: py7zr, rarfile, libarchive-c, and on
many small members the standard library's zipfile and tarfile.

Run::

    uv run --extra all python -m benchmarks.peers --scale realistic

This is a report, not a gate. ``benchmarks.harness`` compares against the stdlib and
the nightly fails when those ratios drift; the peers here stay out of it because
their ratios do not fit its ceiling (libarchive lists a solid 7z without decoding it,
rarfile starts one ``unrar`` process per member) and libarchive-c needs the system
``libarchive`` library, which a runner may not have. A missing peer is reported as
skipped.

Two corpora. The harness corpus (64 members of 256 KiB, and the many-member listing
archives) is mostly codec and listing work. The small-member corpus (4 000 files of
20-600 random bytes in a three-level tree, as ZIP, TAR, tar.gz and 7z) is mostly the
cost each member pays, which the harness corpus barely shows.

Each row times archivey and one peer on the same file, alternating the order, and
reports the median of each side (``--rounds``, default 9 timed calls per side).
Before timing, ``read_all`` checks that both sides return the same number of bytes,
so a peer that silently reads less cannot look fast.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import logging
import random
import shutil
import statistics
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable
from pathlib import Path

from archivey import ExtractionLimits, open_archive
from benchmarks.fixtures import FixtureSet, materialize_fixtures
from benchmarks.harness import (
    _py7zr_available,
    _py7zr_open_list,
    _rarfile_available,
    _rarfile_open_list,
    _unrar_available,
)

# --- archivey ---


def _ay_list(path: Path) -> None:
    with open_archive(path) as reader:
        list(reader.members())


def _ay_read_all(path: Path) -> int:
    total = 0
    with open_archive(path) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                total += len(stream.read())
    return total


def _ay_extract(path: Path, dest: Path) -> None:
    # The bench payloads repeat a 4 KiB block, so solid LZMA2 packs them past the
    # default 1000:1 ratio guard. The peers have no such limits, so all three
    # extraction limits are off here: ratio, total bytes and entry count.
    with open_archive(path) as reader:
        reader.extract_all(dest, limits=ExtractionLimits.UNLIMITED)


# --- zipfile and tarfile (small-member corpus only; the harness compares the rest) ---


def _zipfile_list(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        archive.infolist()


def _zipfile_read_all(path: Path) -> int:
    total = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.is_dir():
                total += len(archive.read(info))
    return total


def _zipfile_extract(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        archive.extractall(dest)


def _tarfile_list(path: Path) -> None:
    with tarfile.open(path) as archive:
        archive.getmembers()


def _tarfile_read_all(path: Path) -> int:
    # One forward pass, as archivey's stream_members() reads it.
    total = 0
    with tarfile.open(path, "r|*") as archive:
        for info in archive:
            stream = archive.extractfile(info)
            if stream is not None:
                total += len(stream.read())
    return total


def _tarfile_extract(path: Path, dest: Path) -> None:
    with tarfile.open(path) as archive:
        archive.extractall(dest, filter="data")


# --- py7zr (listing op shared with the harness) ---


def _py7zr_read_all(path: Path) -> int:
    import py7zr
    from py7zr.io import BytesIOFactory

    factory = BytesIOFactory(limit=1 << 40)
    with py7zr.SevenZipFile(path) as archive:
        archive.extractall(factory=factory)
    return sum(f.size() for f in factory.products.values())


def _py7zr_extract(path: Path, dest: Path) -> None:
    import py7zr

    with py7zr.SevenZipFile(path) as archive:
        archive.extractall(dest)


# --- rarfile (listing op shared with the harness; member data goes through one
# ``unrar p`` process per member) ---


def _rarfile_read_all(path: Path) -> int:
    import rarfile

    total = 0
    with rarfile.RarFile(path) as archive:
        for info in archive.infolist():
            if not info.is_dir():
                total += len(archive.read(info))
    return total


def _rarfile_extract(path: Path, dest: Path) -> None:
    import rarfile

    with rarfile.RarFile(path) as archive:
        archive.extractall(dest)


# --- libarchive-c (reads RAR itself, without unrar) ---


def _libarchive_list(path: Path) -> None:
    import libarchive

    with libarchive.file_reader(str(path)) as archive:
        for entry in archive:
            _ = entry.pathname


def _libarchive_read_all(path: Path) -> int:
    import libarchive

    total = 0
    with libarchive.file_reader(str(path)) as archive:
        for entry in archive:
            if entry.isfile:
                total += len(b"".join(entry.get_blocks()))
    return total


def _libarchive_extract(path: Path, dest: Path) -> None:
    import libarchive

    # extract_file writes into the working directory; resolve first so a relative
    # archive path still names the same file after the chdir.
    source = str(path.resolve())
    with contextlib.chdir(dest):
        libarchive.extract_file(source)


def _peer_available(name: str) -> str | None:
    """None when ``name`` can run here, else the reason it cannot."""
    if name in ("zipfile", "tarfile"):
        return None
    if name == "py7zr":
        return None if _py7zr_available() else "py7zr not importable"
    if name == "rarfile":
        return None if _rarfile_available() else "rarfile not importable"
    if name == "libarchive-c":
        try:
            importlib.import_module("libarchive")
        # Without the system library, libarchive-c fails in ctypes: OSError when the
        # library will not load, AttributeError when a symbol is missing, TypeError on
        # Windows when find_library finds nothing and LoadLibrary gets None.
        except (ImportError, OSError, AttributeError, TypeError) as exc:
            return f"{name} not importable ({type(exc).__name__})"
        return None
    raise ValueError(f"unknown peer {name!r}")


PEER_OPS: dict[str, dict[str, Callable[..., object]]] = {
    "zipfile": {
        "list": _zipfile_list,
        "read_all": _zipfile_read_all,
        "extract": _zipfile_extract,
    },
    "tarfile": {
        "list": _tarfile_list,
        "read_all": _tarfile_read_all,
        "extract": _tarfile_extract,
    },
    "py7zr": {
        "list": _py7zr_open_list,
        "read_all": _py7zr_read_all,
        "extract": _py7zr_extract,
    },
    "rarfile": {
        "list": _rarfile_open_list,
        "read_all": _rarfile_read_all,
        "extract": _rarfile_extract,
    },
    "libarchive-c": {
        "list": _libarchive_list,
        "read_all": _libarchive_read_all,
        "extract": _libarchive_extract,
    },
}
AY_OPS: dict[str, Callable[..., object]] = {
    "list": _ay_list,
    "read_all": _ay_read_all,
    "extract": _ay_extract,
}


def _median_pair(
    ay: Callable[[], object],
    peer: Callable[[], object],
    rounds: int,
    reset: Callable[[], None],
) -> tuple[float, float]:
    """Median wall time of each side, alternating which side runs first.

    ``reset`` runs untimed before every call (extract uses it to empty the target).
    """
    times: dict[int, list[float]] = {0: [], 1: []}
    sides = (ay, peer)
    reset()
    ay()  # warmup: page cache, imports
    reset()
    peer()
    for i in range(rounds):
        for side in (0, 1) if i % 2 == 0 else (1, 0):
            reset()
            t0 = time.perf_counter()
            sides[side]()
            times[side].append(time.perf_counter() - t0)
    return statistics.median(times[0]), statistics.median(times[1])


SMALL_MEMBERS = {"ci": 200, "realistic": 4000}


def _small_member_archives(root: Path, count: int) -> dict[str, Path | None]:
    """ZIP, TAR, tar.gz and 7z of ``count`` files of 20-600 random bytes, in 40
    directories of 7 subdirectories each (fewer at ci scale). Built once per ``root``.
    The 7z entry is ``None`` when py7zr, its writer, is missing."""
    base = root / f"small-{count}"
    tree = base / "tree"
    out: dict[str, Path | None] = {
        "zip": base / "small.zip",
        "tar": base / "small.tar",
        "tar.gz": base / "small.tar.gz",
        "7z": base / "small.7z",
    }
    if not tree.exists():
        rng = random.Random(1)
        staging = base / "tree.part"
        shutil.rmtree(staging, ignore_errors=True)
        for i in range(count):
            folder = staging / f"d{i % 40}" / f"s{i % 7}"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"f{i}.txt").write_bytes(rng.randbytes(rng.randint(20, 600)))
        staging.rename(tree)
    if not (path := out["zip"]).exists():
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for entry in sorted(tree.rglob("*")):
                archive.write(entry, entry.relative_to(base).as_posix())
    for key, mode in (("tar", "w"), ("tar.gz", "w:gz")):
        if not (path := out[key]).exists():
            with tarfile.open(path, mode) as archive:
                archive.add(tree, arcname="tree")
    if not (path := out["7z"]).exists():
        if not _py7zr_available():
            out["7z"] = None
        else:
            import py7zr

            with py7zr.SevenZipFile(path, "w") as archive:
                archive.writeall(tree, arcname="tree")
    return out


def _cases(fx: FixtureSet) -> list[tuple[str, Path | None, list[str], list[str]]]:
    """(label, path, operations, peers). A ``None`` path is reported as skipped."""
    full = ["list", "read_all", "extract"]
    count = SMALL_MEMBERS[fx.scale.name]
    small = _small_member_archives(fx.root, count)
    tiny = f"{count:,} small".replace(",", " ")
    many = f"{fx.scale.list_members:,} members".replace(",", " ")
    nonsolid = f"{fx.scale.nonsolid_list_members:,} non-solid".replace(",", " ")
    seven, rar = ["py7zr", "libarchive-c"], ["rarfile", "libarchive-c"]
    return [
        ("ZIP", fx.zip_path, full, ["libarchive-c"]),
        ("TAR", fx.tar_path, full, ["libarchive-c"]),
        ("7z solid", fx.solid_7z, full, seven),
        (f"7z {many}", fx.many_7z, ["list"], seven),
        (f"7z {nonsolid}", fx.nonsolid_7z, ["list"], seven),
        ("RAR solid", fx.solid_rar, full, rar),
        (f"RAR {many}", fx.many_rar, ["list"], rar),
        (f"RAR {nonsolid}", fx.nonsolid_rar, ["list"], rar),
        (f"ZIP {tiny}", small["zip"], full, ["zipfile", "libarchive-c"]),
        (f"TAR {tiny}", small["tar"], full, ["tarfile", "libarchive-c"]),
        (f"tar.gz {tiny}", small["tar.gz"], full, ["tarfile", "libarchive-c"]),
        (f"7z {tiny}", small["7z"], full, seven),
    ]


def run(scale: str, rounds: int) -> None:
    """Print one markdown table row per (archive, operation, peer) as it finishes.

    Ratio is archivey / peer.
    """
    fx = materialize_fixtures(scale=scale)
    work = Path(tempfile.mkdtemp(prefix="archivey-peers-"))
    print("| Archive | Operation | Peer | archivey | peer | ratio |")
    print("| --- | --- | --- | ---: | ---: | ---: |", flush=True)
    try:
        for label, path, ops, peers in _cases(fx):
            for peer in peers:
                for op in ops:
                    why = _peer_available(peer)
                    if path is None:
                        why = "fixture not built (writer missing)"
                    # archivey (and rarfile) read RAR data through unrar.
                    elif (
                        label.startswith("RAR")
                        and op != "list"
                        and not _unrar_available()
                    ):
                        why = why or "RARLAB unrar not on PATH"
                    if why is not None:
                        print(f"| {label} | {op} | {peer} | — | — | {why} |")
                        continue
                    assert path is not None
                    print(_row(label, path, op, peer, rounds, work), flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _row(label: str, path: Path, op: str, peer: str, rounds: int, work: Path) -> str:
    ay_op, peer_op = AY_OPS[op], PEER_OPS[peer][op]
    dest = work / "out"

    def reset() -> None:
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir()

    if op == "extract":
        ay, other = (lambda: ay_op(path, dest)), (lambda: peer_op(path, dest))
    else:
        ay, other = (lambda: ay_op(path)), (lambda: peer_op(path))
    if op == "read_all":
        got, want = other(), ay()
        assert got == want, f"{label}: {peer} read {got} bytes, archivey {want}"
    ay_s, peer_s = _median_pair(ay, other, rounds, reset)
    return (
        f"| {label} | {op} | {peer} | {ay_s * 1e3:.1f} ms | {peer_s * 1e3:.1f} ms "
        f"| {ay_s / peer_s:.2f}× |"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scale", choices=("ci", "realistic"), default="realistic")
    parser.add_argument("--rounds", type=int, default=9, help="timed calls per side")
    args = parser.parse_args(argv)
    # Diagnostic logs (ZIP name-encoding advisories) skew short samples; see harness.
    logging.disable(logging.CRITICAL)
    run(args.scale, args.rounds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
