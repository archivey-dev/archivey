"""Non-gating ZIP listing baseline (many small members, two writers).

Times ``open_archive(p).members()`` on two 20 000-member ZIPs next to
``zipfile.ZipFile(p).infolist()``: one written by ``zipfile.writestr`` (no extra
fields), and one written by Info-ZIP ``zip -r`` from a tree of 200 folders (each entry
carries the extended-timestamp and new-Unix owner fields). The Info-ZIP shape is skipped
when ``zip`` is not on PATH. There is **no** pass/fail threshold: re-run before any
performance claim about ZIP listing, and compare before/after with the same recipe on
the same host. To compare two revisions, point ``PYTHONPATH`` at each one's ``src/`` in
turn and alternate the runs (``benchmarks/harness.py`` docstring, "Comparing two
revisions"); one run each way cannot resolve a 5% change.

Example::

    uv run python benchmarks/zip_listing_baseline.py

Sample run (2026-10-16, Linux x86_64 4-core VM, CPython 3.12, illustrative only)::

    zipfile.writestr  archivey   329.6 ms   zipfile    55.8 ms  (20000 members)
    zip -r            archivey   526.0 ms   zipfile    69.2 ms  (20200 members)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
import timeit
import zipfile
from pathlib import Path

from archivey import open_archive


def _make_writestr_zip(path: Path, members: int) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(members):
            zf.writestr(f"dir{i // 100}/file{i}.txt", b"x" * (i % 50))


def _make_infozip_zip(path: Path, tree: Path, members: int) -> None:
    for i in range(members):
        folder = tree / f"dir{i // 100}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"file{i}.txt").write_bytes(b"x" * (i % 50))
    subprocess.run(
        ["zip", "-q", "-r", str(path), "."],
        cwd=tree,
        check=True,
        stdin=subprocess.DEVNULL,
    )


def _best(stmt: object, repeat: int) -> float:
    return min(timeit.repeat(stmt, number=1, repeat=repeat))  # type: ignore[arg-type]


def _measure(label: str, path: Path, repeat: int) -> None:
    def archivey_list() -> None:
        with open_archive(path) as reader:
            reader.members()

    def zipfile_list() -> None:
        with zipfile.ZipFile(path) as zf:
            zf.infolist()

    archivey_list()  # warm imports and caches once
    ours = _best(archivey_list, repeat)
    theirs = _best(zipfile_list, repeat)
    with zipfile.ZipFile(path) as zf:
        count = len(zf.infolist())
    print(
        f"{label:17s} archivey {ours * 1e3:7.1f} ms   zipfile {theirs * 1e3:6.1f} ms"
        f"  ({count} members)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--members", type=int, default=20_000)
    parser.add_argument("--repeat", type=int, default=11)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plain = root / "writestr.zip"
        _make_writestr_zip(plain, args.members)
        _measure("zipfile.writestr", plain, args.repeat)
        if shutil.which("zip") is None:
            print("zip -r            skipped: Info-ZIP zip is not on PATH")
            return
        infozip = root / "infozip.zip"
        _make_infozip_zip(infozip, root / "tree", args.members)
        _measure("zip -r", infozip, args.repeat)


if __name__ == "__main__":
    main()
