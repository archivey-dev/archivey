"""Assert relative markdown links under maintainer/agent trees resolve.

``check_docs_nav.py`` covers published ``docs/`` only. Pair-workflow and skill docs
add many ``../`` hops into ``dev-docs/``; those rot silently when a directory moves.
This pass checks path existence only (no anchors, no absolute URLs).

Fenced code blocks are stripped first so ASCII diagrams that contain ``](`` (e.g.
``POLICY_TRANSFORMS[STRICT](member)``) are not treated as links.

    uv run --no-sync python scripts/checks/check_internal_md_links.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Relative markdown links only (no scheme:). Anchors alone (#foo) are ignored.
PAGE_LINK = re.compile(r"\[[^\]]*\]\(([^):\s]*?)(?:#[^)\s]*)?\)")
FENCED = re.compile(r"```.*?```", re.DOTALL)

TREES = (
    ROOT / "dev-docs",
    ROOT / ".claude" / "skills",
    ROOT / "review",
)
# Agent entry points at the repository root.
ROOT_FILES = (ROOT / "AGENTS.md", ROOT / "CLAUDE.md", ROOT / "CONTRIBUTING.md")


def iter_sources() -> list[Path]:
    sources = [path for path in ROOT_FILES if path.is_file()]
    for tree in TREES:
        sources.extend(iter_markdown(tree))
    return sources


def iter_markdown(tree: Path) -> list[Path]:
    if not tree.is_dir():
        return []
    return sorted(path for path in tree.rglob("*.md") if path.is_file())


def link_targets(text: str) -> set[str]:
    stripped = FENCED.sub("", text)
    return set(PAGE_LINK.findall(stripped))


def main() -> int:
    problems: list[str] = []
    sources = iter_sources()
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for target in sorted(link_targets(text)):
            if not target or target.startswith("#"):
                continue
            path_part = target.split("?", 1)[0]
            resolved = (source.parent / path_part).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                problems.append(
                    f"{source.relative_to(ROOT)} links to {target!r}, "
                    f"which resolves outside the repository."
                )
                continue
            if not resolved.exists():
                problems.append(
                    f"{source.relative_to(ROOT)} links to {target!r}, "
                    f"which does not exist "
                    f"(expected {resolved.relative_to(ROOT)})."
                )

    if problems:
        print(f"{len(problems)} broken relative link(s):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(
        f"internal md links: {len(sources)} files under dev-docs/, .claude/skills/, "
        "review/ and the root agent files, all resolve."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
