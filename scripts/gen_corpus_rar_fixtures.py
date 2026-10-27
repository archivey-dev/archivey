"""Regenerate the committed RAR archives for the declarative corpus.

Usage (from the repo root, on a machine with the RARLAB ``rar`` binary)::

    uv run python scripts/gen_corpus_rar_fixtures.py

Writes ``tests/fixtures/corpus/rar/<entry id>.rar`` for every corpus entry that
declares ``rar``, plus ``tests/fixtures/corpus/manifest.json`` recording the cache key
of the entry definition each archive was built from.

**Why these are committed at all.** Everything else in the corpus is generated on
demand, which is what keeps it declarative. RAR cannot be: writing it needs RARLAB
``rar``, which is trialware where ``unrar`` is freeware, so requiring it would turn the
RAR column into a licensing decision — and it would still only cover Linux, since the
macOS runner has no writer either. The result was that RAR's corpus rows ran nowhere.
Committing the archives runs them on every platform and costs no license.

**Why the manifest.** Committed binaries rot: edit a corpus entry and the archive still
sits there, silently testing the old shape. The manifest pins each fixture to
``_cache_key(entry, "rar")``, the same content hash the on-demand cache uses. A mismatch
is rebuilt here, and is a hard error in the test suite anywhere ``rar`` is missing — see
``tests/sample_archives.committed_fixture``. A regenerated RAR is never byte-identical
to its predecessor (archives embed timestamps), so the manifest is the check; a hash of
the bytes could not be one.

This is a sibling of ``scripts/gen_rar_fixtures.py``, which regenerates the *targeted*
reader fixtures in ``tests/fixtures/rar/``. That set exercises RAR-specific shapes
(volumes, ``-ver`` file versions, RAR4 vs RAR5, tweaked checksums); this one exercises
the cross-format corpus contract. They are deliberately separate.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.sample_archives import (  # noqa: E402
    CORPUS,
    CORPUS_FIXTURE_DIR,
    CORPUS_FIXTURE_MANIFEST,
    _cache_key,
    build_archive,
)


def _entries() -> list:
    return [entry for entry in CORPUS if "rar" in entry.formats]


def generate(out_dir: Path, manifest_path: Path) -> int:
    if shutil.which("rar") is None:
        print(
            "error: the RARLAB `rar` binary is not on PATH.\n"
            "       Install it (Debian/Ubuntu: `apt-get install rar`) and re-run.\n"
            "       `unrar` is not enough — it only reads.",
            file=sys.stderr,
        )
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    fixtures: dict[str, str] = {}
    for entry in _entries():
        target = out_dir / f"{entry.id}.rar"
        with tempfile.TemporaryDirectory() as td:
            staged = Path(td) / target.name
            build_archive(entry, "rar", staged)
            shutil.move(str(staged), target)
        fixtures[f"rar/{entry.id}"] = _cache_key(entry, "rar")
        print(
            f"  wrote {target.relative_to(REPO_ROOT)} ({target.stat().st_size} bytes)"
        )

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "_comment": (
                    "Cache key of the corpus entry each committed fixture was built "
                    "from. Regenerate with scripts/gen_corpus_rar_fixtures.py; a "
                    "mismatch fails the suite rather than testing stale bytes."
                ),
                "fixtures": dict(sorted(fixtures.items())),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  wrote {manifest_path.relative_to(REPO_ROOT)} ({len(fixtures)} fixtures)")

    stale = {p.name for p in out_dir.glob("*.rar") if f"rar/{p.stem}" not in fixtures}
    if stale:
        print(f"  note: {sorted(stale)} are no longer in the corpus — delete them")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=CORPUS_FIXTURE_DIR / "rar",
        help="output directory (default: tests/fixtures/corpus/rar)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=CORPUS_FIXTURE_MANIFEST,
        help="manifest path (default: tests/fixtures/corpus/manifest.json)",
    )
    args = parser.parse_args(argv)
    return generate(args.out_dir, args.manifest)


if __name__ == "__main__":
    raise SystemExit(main())
