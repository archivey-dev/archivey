"""Compare archivey's DMG reader with 7-Zip on real disk images (DMG plan, B.10).

The images are third-party apps from GitHub release pages, so they are not committed.
The URL list is ``openspec/changes/dmg-reader/resources/dmgurls.txt``. Each URL is
downloaded once into the cache directory; then each image is listed and extracted by
archivey and by 7-Zip, and the files are compared by SHA-256, with the differences the
plan accepts (design §9.3):

- 7-Zip writes both paths of a file hard link as empty files and the data under
  ``[HFS+ Private Data]``; archivey lists the first path as the file.
- 7-Zip skips absolute symlinks; archivey lists them (only files are compared).
- 7-Zip writes extended attributes and resource forks as ``name:...`` side files.
- 7-Zip 23.01 cannot read xz runs; archivey can. Such an image is reported as
  ``7-Zip cannot decode a run``, not compared.

Run::

    uv run python scripts/investigations/dmg_corpus.py --cache ~/.cache/dmg-corpus

It prints one line per image (``same``, ``differs``, ``archivey refused``, ...) and a
summary, and exits non-zero when any image both tools read differs.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_URLS = _REPO / "openspec" / "changes" / "dmg-reader" / "resources" / "dmgurls.txt"
_PRIVATE = "[HFS+ Private Data]"


def _download(url: str, cache: Path) -> Path | None:
    name = hashlib.sha256(url.encode()).hexdigest()[:12] + "-" + url.rsplit("/", 1)[-1]
    path = cache / name
    if path.exists():
        return path
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            tmp = path.with_suffix(".part")
            with tmp.open("wb") as out:
                shutil.copyfileobj(response, out, 1 << 20)
        tmp.rename(path)
    except OSError as exc:
        print(f"  download failed: {exc}", file=sys.stderr)
        return None
    return path


def _archivey(path: Path) -> tuple[dict[str, str], set[str], str | None]:
    """archivey's files by NFC name and SHA-256, the paths 7-Zip writes empty (hard
    links and special files), and the error, if the image was refused."""
    from archivey import MemberType, open_archive

    files: dict[str, str] = {}
    empty: set[str] = set()
    try:
        with open_archive(path) as reader:
            for member, stream in reader.stream_members():
                name = unicodedata.normalize("NFC", member.name)
                if member.type is MemberType.FILE and stream is not None:
                    digest = hashlib.sha256()
                    while chunk := stream.read(1 << 20):
                        digest.update(chunk)
                    files[name] = digest.hexdigest()
                elif member.type in (MemberType.HARDLINK, MemberType.OTHER):
                    empty.add(name)
    except Exception as exc:  # noqa: BLE001 - every refusal is a result here
        return files, empty, f"{type(exc).__name__}: {exc}"
    return files, empty, None


def _sevenzip(path: Path, work: Path) -> dict[str, str] | None:
    """7-Zip's files by NFC name and SHA-256; None when it read nothing, and an empty
    dict when it refused a run's method (7-Zip 23.01 has no xz runs) and so wrote the
    partitions undecoded."""
    out = work / "7z"
    result = subprocess.run(
        ["7z", "x", "-y", f"-o{out}", str(path)],
        capture_output=True,
        check=False,
        timeout=3600,
        text=True,
        errors="replace",
    )
    if "Unsupported Method" in result.stdout + result.stderr:
        shutil.rmtree(out, ignore_errors=True)
        return {}
    if not out.exists():
        return None
    files = {}
    for root, _dirs, names in os.walk(out):
        for n in names:
            full = Path(root) / n
            if full.is_symlink() or not full.is_file() or ":" in n:
                continue
            rel = full.relative_to(out).as_posix().split("/", 1)[-1]
            files[unicodedata.normalize("NFC", rel)] = hashlib.sha256(
                full.read_bytes()
            ).hexdigest()
    shutil.rmtree(out, ignore_errors=True)
    return files


_EMPTY = hashlib.sha256(b"").hexdigest()


def _compare(
    ours: dict[str, str], empty: set[str], theirs: dict[str, str]
) -> list[str]:
    inodes = {v for k, v in theirs.items() if k.startswith(_PRIVATE)}
    theirs = {k: v for k, v in theirs.items() if not k.startswith(_PRIVATE)}
    problems = []
    for name, digest in theirs.items():
        if name in empty:
            if digest != _EMPTY:
                problems.append(f"{name}: 7-Zip wrote data for a link")
            continue
        mine = ours.get(name)
        if mine is None:
            problems.append(f"{name}: only 7-Zip lists it")
        elif mine != digest:
            if digest == _EMPTY and mine in inodes:
                continue  # a hard link's first path: 7-Zip writes it empty
            problems.append(f"{name}: contents differ")
    for name in set(ours) - set(theirs):
        problems.append(f"{name}: only archivey lists it")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--urls", type=Path, default=_URLS)
    parser.add_argument(
        "--no-keep", action="store_true", help="delete each image once compared"
    )
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    if shutil.which("7z") is None:
        print("7z is not installed", file=sys.stderr)
        return 2
    urls = [u.strip() for u in args.urls.read_text().splitlines() if u.strip()]
    tally: dict[str, int] = {}
    failed = False
    for url in urls:
        print(url, flush=True)
        path = _download(url, args.cache)
        if path is None:
            outcome = "not downloaded"
        else:
            ours, empty, error = _archivey(path)
            with tempfile.TemporaryDirectory() as work:
                theirs = _sevenzip(path, Path(work))
            if error is not None:
                outcome = "archivey refused"
                print(f"  {error}")
            elif theirs is None:
                outcome = "7-Zip read nothing"
            elif not theirs:
                outcome = "7-Zip cannot decode a run"
            else:
                problems = _compare(ours, empty, theirs)
                outcome = "differs" if problems else "same"
                failed = failed or bool(problems)
                for line in problems[:10]:
                    print(f"  {line}")
            print(f"  {outcome} ({len(ours)} files)")
            if args.no_keep:
                path.unlink()
        tally[outcome] = tally.get(outcome, 0) + 1
    print()
    for outcome, count in sorted(tally.items()):
        print(f"{outcome}: {count}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
