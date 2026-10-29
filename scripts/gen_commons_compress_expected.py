#!/usr/bin/env python3
"""Rewrite the pins of ``tests/test_commons_compress_corpus.py``.

The pins hold, for every file in Commons Compress's ``src/test/resources``, a summary
of Commons Compress's listing and of Archivey's, from a path and from a pipe. The
Commons Compress side comes from ``scripts/commons_compress/CcList.java``, run once on
the same checkout (it needs Java and a Commons Compress build with its optional codecs
on the classpath)::

    cd /path/to/commons-compress && mvn -q package -DskipTests
    mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt
    javac -cp "target/classes:$(cat cp.txt)" -d /tmp/cclist \\
        /path/to/archivey/scripts/commons_compress/CcList.java
    find src/test/resources -type f | sort \\
        | java -cp "/tmp/cclist:target/classes:$(cat cp.txt)" CcList > cc.jsonl

Then, from the archivey checkout, with the plugins in ``packages/`` installed::

    uv run python scripts/gen_commons_compress_expected.py \\
        /path/to/commons-compress cc.jsonl

The test's ``_TRIAGE`` must then give a reason for every file where the two disagree;
``test_every_divergence_from_commons_compress_is_triaged`` says which.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.test_commons_compress_corpus import (  # noqa: E402
    EXPECTED_PATH,
    SLOW,
    installed_plugins,
    list_with_archivey,
    normalize_name,
    summarize,
)

_RESOURCES = "src/test/resources/"
_KINDS = {"dir": "directory", None: "other"}


def _row(entry: dict[str, Any]) -> list[Any]:
    """One CC entry in the test's row form; see ``list_with_archivey``."""
    kind = _KINDS.get(entry.get("kind"), entry.get("kind"))
    failed = "error" in entry or entry.get("read") == "unsupported"
    read = None if failed or kind != "file" else entry.get("read")
    if read is None and not failed and kind == "file" and entry.get("size") == 0:
        read = 0  # A 7z member with no stream: empty, where Archivey reads 0 bytes.
        entry = {**entry, "crc": 0}
    return [
        normalize_name(entry.get("name")),
        kind,
        read,
        entry.get("crc") if read is not None else None,
        True if failed else None,
    ]


def cc_summary(record: dict[str, Any]) -> dict[str, Any] | None:
    """Commons Compress's best reading: its file API when it has one, else its stream
    API, else a compressor and the archive inside it. ``None`` when it read nothing."""
    if "stream" in record:
        view = record.get("file") or record["stream"]
        rows = [_row(e) for e in view["entries"]]
        listing: dict[str, Any] = {"members": rows}
    elif "compressor" in record:
        compressor = record["compressor"]
        if "inner" in compressor:
            view = compressor["inner"]
            rows = [_row(e) for e in view["entries"]]
            listing = {"members": rows}
        elif "read" in compressor:
            listing = {
                "members": [
                    ["<data>", "file", compressor["read"], compressor["crc"], None]
                ]
            }
            view = {}
        else:
            view = compressor
            listing = {"members": []}
    else:
        return None
    if view.get("error"):
        listing["error"] = view["error"].split(":", 1)[0]
    return summarize(listing)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("checkout", type=Path, help="a Commons Compress clone")
    parser.add_argument("cc_listing", type=Path, help="CcList.java's output (JSONL)")
    args = parser.parse_args(argv)
    resources = args.checkout / _RESOURCES
    commit = subprocess.run(
        ["git", "-C", str(args.checkout), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    cc: dict[str, dict[str, Any] | None] = {}
    for line in args.cc_listing.open(encoding="utf-8"):
        record = json.loads(line)
        if _RESOURCES not in record["path"]:
            raise SystemExit(
                f"{record['path']!r} in the listing is not under {_RESOURCES}"
            )
        cc[record["path"].split(_RESOURCES, 1)[1]] = cc_summary(record)

    # The listing must come from this checkout: the commit recorded below is its HEAD.
    in_checkout = {
        p.relative_to(resources).as_posix() for p in resources.rglob("*") if p.is_file()
    }
    if in_checkout != set(cc):
        raise SystemExit(
            "the listing is not of this checkout; run CcList on it again. Only in the "
            f"checkout: {sorted(in_checkout - set(cc))[:5]}; only in the listing: "
            f"{sorted(set(cc) - in_checkout)[:5]}"
        )

    files: dict[str, dict[str, Any]] = {}
    with installed_plugins():
        for path in sorted(p for p in resources.rglob("*") if p.is_file()):
            name = path.relative_to(resources).as_posix()
            if name in SLOW:
                continue
            entry: dict[str, Any] = {
                "cc": cc[name],
                "path": summarize(list_with_archivey(path, pipe=False)),
            }
            pipe = summarize(list_with_archivey(path, pipe=True))
            if pipe != entry["path"]:
                entry["pipe"] = pipe
            files[name] = entry

    EXPECTED_PATH.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "_comment": (
            "Pins for tests/test_commons_compress_corpus.py; rewrite with "
            "scripts/gen_commons_compress_expected.py."
        ),
        "commons_compress": commit,
        "files": files,
    }
    EXPECTED_PATH.write_text(
        json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(files)} pins to {EXPECTED_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
