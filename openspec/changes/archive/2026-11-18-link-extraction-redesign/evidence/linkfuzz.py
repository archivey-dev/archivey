"""Differential fuzz of archivey link extraction.

Random small TARs (files, dirs, symlinks, hard links, duplicate names) are extracted
four ways: made/held (hard-link sources selected or excluded) x streaming off/on.
Every run is compared to the made, non-streaming one: statuses, result paths and
the disk. Prints each divergent archive, minimised greedily.

usage: python linkfuzz.py SEED COUNT [strict|standard|trusted]

Set FUZZ_TMP to a scratch directory; put the tree under test first on PYTHONPATH.
"""

from __future__ import annotations

import io
import os
import random
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

from archivey import ExtractionPolicy, OnBlocked, OnError, OverwritePolicy, open_archive

NAMES = ["a", "b", "a/x", "b/x", "a/x/y", "A", "c"]
SYM_TARGETS = ["a", "b", "c", "x", "../x", "a/..", ".", "b/x"]


def tar_bytes(specs):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for kind, name, payload in specs:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                info.mode = 0o644
                t.addfile(info, io.BytesIO(payload))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
            else:
                info.type = tarfile.LNKTYPE
                info.linkname = payload
            t.addfile(info)
    return buf.getvalue()


def gen(rng: random.Random):
    specs = [("file", "src1", b"1"), ("file", "src2", b"2")]
    earlier_files = ["src1", "src2"]
    for i in range(rng.randint(2, 7)):
        name = rng.choice(NAMES)
        kind = rng.choices(["file", "dir", "sym", "hard"], [3, 3, 3, 4])[0]
        if kind == "file":
            specs.append(("file", name, f"f{i}".encode()))
            earlier_files.append(name)
        elif kind == "dir":
            specs.append(("dir", name, None))
        elif kind == "sym":
            specs.append(("sym", name, rng.choice(SYM_TARGETS)))
        else:
            specs.append(("hard", name, rng.choice(earlier_files)))
    return specs


def snapshot(dest: Path):
    out = {}
    for root, dirs, files in os.walk(dest):
        for n in sorted(dirs + files):
            p = Path(root) / n
            rel = p.relative_to(dest).as_posix()
            if rel.startswith("src"):
                continue
            if p.is_symlink():
                out[rel] = ("L", os.readlink(p))
            elif p.is_dir():
                out[rel] = ("D",)
            else:
                out[rel] = ("F", p.read_bytes())
    return out


def run(
    data,
    base: Path,
    label: str,
    *,
    held: bool,
    streaming: bool,
    overwrite,
    policy,
    dry: bool = False,
):
    dest = base / label
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as reader:
            report = reader.extract_all(
                dest,
                overwrite=overwrite,
                policy=policy,
                on_error=OnError.CONTINUE,
                on_blocked=OnBlocked.SKIP,
                members=(lambda m: not m.name.startswith("src")) if held else None,
                dry_run=dry,
            )
        results = [
            (
                r.member.name,
                r.status.name,
                None if r.path is None else r.path.relative_to(dest).as_posix(),
            )
            for r in report.results
            if not r.member.name.startswith("src")
        ]
    except Exception as exc:  # noqa: BLE001
        results = ("RAISED", type(exc).__name__, str(exc)[:200])
    if dry:
        return results, None
    return results, snapshot(dest) if dest.exists() else {}


MODES = {
    "held": {"held": True, "streaming": False},
    "stream": {"held": False, "streaming": True},
    "dry": {"held": False, "streaming": False, "dry": True},
}


def diverges(specs, overwrite, policy):
    data = tar_bytes(specs)
    base = Path(tempfile.mkdtemp(dir=os.environ.get("FUZZ_TMP")))
    try:
        ref = run(
            data,
            base,
            "ref",
            held=False,
            streaming=False,
            overwrite=overwrite,
            policy=policy,
        )
        bad = []
        for label, kw in MODES.items():
            got = run(data, base, label, overwrite=overwrite, policy=policy, **kw)
            if kw.get("dry"):
                got = (got[0], ref[1])
            if got != ref:
                bad.append((label, got))
        return ref, bad
    finally:
        shutil.rmtree(base, ignore_errors=True)


def minimise(specs, overwrite, policy, label):
    cur = list(specs)
    changed = True
    while changed:
        changed = False
        for i in range(2, len(cur)):
            trial = cur[:i] + cur[i + 1 :]
            _, bad = diverges(trial, overwrite, policy)
            if any(lbl == label for lbl, _ in bad):
                cur = trial
                changed = True
                break
    return cur


def main():
    import logging

    logging.disable(logging.CRITICAL)
    seed, count = int(sys.argv[1]), int(sys.argv[2])
    policies = (
        [ExtractionPolicy(sys.argv[3])]
        if len(sys.argv) > 3
        else [ExtractionPolicy.STANDARD]
    )
    rng = random.Random(seed)
    seen = set()
    hits = dict.fromkeys(MODES, 0)
    for n in range(count):
        specs = gen(rng)
        for policy in policies:
            for overwrite in OverwritePolicy:
                _ref, bad = diverges(specs, overwrite, policy)
                for label, got in bad:
                    hits[label] += 1
                    small = minimise(specs, overwrite, policy, label)
                    key = (label, overwrite.name, tuple(small))
                    if key in seen:
                        continue
                    seen.add(key)
                    sref, sbad = diverges(small, overwrite, policy)
                    sgot = dict(sbad).get(label)
                    print(f"== {label} {policy.name} {overwrite.name} case#{n}")
                    for s in small:
                        print("   ", s)
                    print("   ref:", sref[0])
                    print("   got:", sgot[0] if sgot else None)
                    if sgot and sref[1] != sgot[1]:
                        print("   disk ref:", sref[1])
                        print("   disk got:", sgot[1])
                    sys.stdout.flush()
    print("divergent runs per mode:", hits, "of", count * len(policies) * 4)
    print("distinct minimised cases:", len(seen))


if __name__ == "__main__":
    main()
