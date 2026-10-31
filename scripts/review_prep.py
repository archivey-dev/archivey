#!/usr/bin/env python3
"""Checks an implementer runs before adding the `review` label, and again before each re-label.

The review loop's findings, measured over 38 pull requests (2026-09-23/24), are dominated
by three shapes that a script can find faster than a reviewer:

- a symbol or an exception type changed in `src/` and is still described the old way in a
  spec or a handbook page (``sweep``; the CHANGELOG is left out, since the release writes it);
- a paragraph edited in place and not rewrapped, leaving a line far wider than the rest of
  its file (``width``);
- a new test the PR body says fails on `main`, which passes there (``red-on-base``).

It also prints the review tier the changed paths put the pull request in (``tier``): how
deep a review round goes, and whether the public API moved. The reviewer runs the same
command, so the PR body's Risk section can be checked against it.

67 of the 70 findings raised after round 1 were caused by the previous round's fix, so the
same checks apply to the fix commits before the label goes on again.

    uv run python scripts/review_prep.py                 # sweep + width against origin/main
    uv run python scripts/review_prep.py --base HEAD~1   # just the last commit's fixes
    uv run python scripts/review_prep.py red-on-base tests/test_x.py::test_y ...
    uv run python scripts/review_prep.py tier            # light, standard or deep, and why

``sweep`` only reports: whether a hit is stale needs reading. ``width`` exits 1 when an
added line is wider than its file allows. ``red-on-base`` prints a table to paste into the
PR body in place of a prose "fails on main" claim.

``sweep``, ``width`` and ``tier`` are stdlib only and run under any Python 3.10+, so a
reviewer without the project environment runs ``python3 scripts/review_prep.py tier``;
``red-on-base`` runs pytest, so it needs the project's environment and refuses to start
without one.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Where a claim about `src/` behaviour is written down, apart from `src/` itself.
DOC_ROOTS = (
    "openspec/specs",
    "openspec/changes",
    "docs",
    "dev-docs",
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "VISION.md",
    ".claude/skills",
)
DOC_SUFFIXES = {".md", ".yml", ".yaml"}
# An archived change records what was true when it landed; it is not stale when code moves.
DOC_EXCLUDE = ("openspec/changes/archive/", "dev-docs/history/")

PY_WIDTH = 88
# How far past its file's width an added line may run before it is reported. Comments of
# 89-95 columns are common in the tree and nobody has flagged one; the findings were a
# paragraph edited in place and never rewrapped, which lands at 105-150.
SLACK = 10
# A markdown file counts as hard-wrapped when nearly all of its prose lines fit this width.
MD_WRAPPED_BELOW = 100
MD_WRAPPED_SHARE = 0.98

_DEF_RE = re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_]\w*)")
_CONST_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*(?::[^=]+)?=")
_RAISE_RE = re.compile(r"\braise\s+([A-Z]\w*(?:Error|Exception|Warning))\b")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s?(.*)$")
# `.gitattributes` sets `*.py diff=python`, so a hunk header names the enclosing def, not
# the last column-0 line (the class).
_HUNK_DEF_RE = re.compile(r"(?:def|class)\s+([A-Za-z_]\w*)")
_URL_RE = re.compile(r"https?://")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


# --- diff parsing ---------------------------------------------------------------------


@dataclass
class FileDiff:
    path: str
    added: list[tuple[int, str]] = field(
        default_factory=list
    )  # (new line number, text)
    removed: list[tuple[str, str]] = field(default_factory=list)  # (hunk context, text)
    renamed_from: str = ""  # the old path, when git paired a deletion with an addition
    deleted: bool = False


def parse_diff(text: str) -> list[FileDiff]:
    """Split a ``git diff -U0`` into per-file added and removed lines."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line = 0
    context = ""
    old_path = ""
    for line in text.splitlines():
        if line.startswith("diff --git "):
            current = None
            continue
        if current is None and line.startswith("rename from "):
            old_path = line.removeprefix("rename from ")
            continue
        if current is None and line.startswith("rename to "):
            # A pure rename has no ---/+++ lines and no hunks; this is all of it.
            current = FileDiff(line.removeprefix("rename to "), renamed_from=old_path)
            files.append(current)
            continue
        if line.startswith("--- "):
            if current is None:
                old_path = line[4:].removeprefix("a/")
            continue
        if line.startswith("+++ "):
            path = line[4:]
            if current is None:
                current = FileDiff(path.removeprefix("b/"))
                files.append(current)
            if path == "/dev/null":
                # A deleted file's removed lines count too: deleting a module is the
                # commonest way a name disappears.
                current.path, current.deleted = old_path, True
            continue
        if current is None:
            continue
        hunk = _HUNK_RE.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            context = hunk.group(2)
            continue
        if line.startswith("+"):
            current.added.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            current.removed.append((context, line[1:]))
    return files


# --- sweep: names and exception types that moved --------------------------------------


@dataclass(frozen=True)
class Moved:
    kind: str  # "name", "raise" or "module"
    old: str
    where: str  # file, and for a raise the enclosing function
    near: str = ""  # a raise: the function whose docs should mention the new type


def _module_patterns(path: str) -> list[str]:
    """How docs name a module: dotted, or by its path from the package's parent down."""
    parts = Path(path.removeprefix("src/")).with_suffix("").parts
    return [".".join(parts), "/".join(parts[-2:]) + ".py"]


def moved_claims(
    files: Iterable[FileDiff], head_text: Callable[[str], str | None] = lambda p: None
) -> list[Moved]:
    """Names defined in removed `src/` lines that no added line defines again, exception
    types a file stopped raising, and `src/` modules renamed or deleted.

    ``head_text(path)`` returns the file as it stands after the change, so a type still
    raised from an untouched line is not reported as gone.
    """
    files = list(files)
    out: list[Moved] = []
    for f in files:
        old = f.renamed_from or (f.path if f.deleted else "")
        if old.startswith("src/") and old.endswith(".py"):
            where = f"moved to {f.path}" if f.renamed_from else "deleted"
            out.extend(Moved("module", pat, where) for pat in _module_patterns(old))
    files = [f for f in files if f.path.startswith("src/") and f.path.endswith(".py")]
    defined_now = {
        m.group(1)
        for f in files
        for _, text in f.added
        for m in (_DEF_RE.match(text) or _CONST_RE.match(text),)
        if m
    }
    seen: set[tuple[str, str]] = set()
    for f in files:
        now = "" if f.deleted else (head_text(f.path) or "")
        raised_now = {
            m.group(1)
            for text in [now, *(t for _, t in f.added)]
            for m in _RAISE_RE.finditer(text)
        }
        for context, text in f.removed:
            m = _DEF_RE.match(text) or _CONST_RE.match(text)
            if m and m.group(1) not in defined_now and ("name", m.group(1)) not in seen:
                seen.add(("name", m.group(1)))
                out.append(Moved("name", m.group(1), f.path))
            for r in _RAISE_RE.finditer(text):
                exc = r.group(1)
                if exc in raised_now or ("raise", f"{f.path}:{exc}") in seen:
                    continue
                seen.add(("raise", f"{f.path}:{exc}"))
                func = _HUNK_DEF_RE.search(context)
                out.append(Moved("raise", exc, f.path, func.group(1) if func else ""))
    return out


def doc_files() -> list[Path]:
    paths: list[Path] = []
    for root in DOC_ROOTS:
        p = ROOT / root
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            paths.extend(
                q for q in p.rglob("*") if q.suffix in DOC_SUFFIXES and q.is_file()
            )
    # The contract first: a stale spec or published doc matters more than a stale plan.
    return [
        p
        for p in sorted(paths, key=lambda q: (not _authoritative(q), q))
        if not any(p.relative_to(ROOT).as_posix().startswith(x) for x in DOC_EXCLUDE)
    ]


def _authoritative(p: Path) -> bool:
    return p.relative_to(ROOT).as_posix().startswith(("openspec/specs/", "docs/"))


def sweep(moved: list[Moved], docs: list[Path]) -> list[str]:
    report: list[str] = []
    texts = {p: p.read_text(encoding="utf-8", errors="replace") for p in docs}
    for m in moved:
        word = re.compile(rf"(?<!\w){re.escape(m.old)}(?!\w)")
        hits: list[str] = []
        for p, text in texts.items():
            # A raise is only worth a look where the doc also names the function.
            if m.kind == "raise" and (not m.near or m.near not in text):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if word.search(line):
                    hits.append(
                        f"    {p.relative_to(ROOT).as_posix()}:{n}: {line.strip()[:120]}"
                    )
        if not hits:
            continue
        if m.kind == "name":
            head = (
                f"`{m.old}` is no longer defined in src/ ({m.where}), still named in:"
            )
        elif m.kind == "module":
            head = f"`{m.old}` was {m.where}, still named in:"
        else:
            head = (
                f"`{m.near or '?'}` in {m.where} no longer raises `{m.old}`; docs naming "
                f"both still say `{m.old}` at:"
            )
        report.append(head)
        report.extend(hits[:15])
        if len(hits) > 15:
            report.append(f"    … and {len(hits) - 15} more")
    return report


# --- width: added lines wider than their file ------------------------------------------


def _md_prose(text: str) -> dict[int, str]:
    """Lines a rewrap would touch, by line number: outside code fences, not tables, not
    bare URLs. Needs the whole file: fence state cannot be read from a fragment."""
    out: dict[int, str] = {}
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced or line.lstrip().startswith("|") or _URL_RE.search(line):
            continue
        out[n] = line
    return out


def md_limit(base_text: str | None) -> int | None:
    """The width a markdown file is wrapped at, or None when it is not hard-wrapped.

    Judged from the file as it was before this change, so an edit cannot widen its own
    limit. Some docs here are wrapped at 88, some at 91, and some not at all.
    """
    if base_text is None:
        return None
    prose = [line for line in _md_prose(base_text).values() if line.strip()]
    if len(prose) < 10:
        return None
    fitting = sorted(len(line) for line in prose if len(line) <= MD_WRAPPED_BELOW)
    if len(fitting) / len(prose) < MD_WRAPPED_SHARE:
        return None
    return max(PY_WIDTH, fitting[-1])


def base_text(base: str, path: str) -> str | None:
    """``path`` as it is at ``base`` (any revision), or None where it does not exist."""
    try:
        return git("show", f"{base}:{path}")
    except subprocess.CalledProcessError:
        return None


def width(files: Iterable[FileDiff], base: str, head: str = "HEAD") -> list[str]:
    report: list[str] = []
    for f in files:
        if f.path.endswith(".py"):
            # Tests are left out: nobody has flagged a long line in one, and their
            # literal fixtures make the check noisy.
            limit: int | None = (
                PY_WIDTH if f.path.startswith(("src/", "scripts/")) else None
            )
            candidates = f.added
        elif f.path.endswith(".md"):
            limit = md_limit(base_text(base, f.path))
            prose = _md_prose(base_text(head, f.path) or "")
            candidates = [(n, text) for n, text in f.added if n in prose]
        else:
            continue
        if limit is None:
            continue
        for n, text in candidates:
            if (
                len(text) > limit + SLACK
                and not _URL_RE.search(text)
                and "noqa: E501" not in text
            ):
                report.append(f"{f.path}:{n}: {len(text)} > {limit} columns")
    return report


# --- tier: how deep the review goes ----------------------------------------------------

# A pull request is light only when every path it changes is here: user and maintainer
# prose, tests and benchmarks. Two rules keep the rest out:
# - What an agent or a review round reads as its own instructions or contracts is never
#   light: the skills and commands (`.claude/`, `.cursor/`, so they are not listed here)
#   and the files in NOT_LIGHT.
# - Neither is a gate inside a light folder: the skip markers and the benchmark gate.
# `openspec/` is not light either, because a spec is a contract.
LIGHT_PREFIXES = (
    "docs/",
    "dev-docs/",
    "tests/",
    "benchmarks/",
)
LIGHT_FILES = ("mkdocs.yml",)
NOT_LIGHT = (
    # Instructions and contracts
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "dev-docs/design-rules.md",
    "dev-docs/threat-model.md",
    "dev-docs/api-surface.txt",
    "dev-docs/review-loop.md",
    # Gates
    "tests/conftest.py",
    "benchmarks/wall_baseline.py",
)

# Paths where one bug breaks a safety guarantee for every format: writes stay inside the
# destination, resources stay bounded, archive-supplied input never reaches a command
# line or a terminal as anything but inert text. One of them makes the pull request deep.
# Edit the list here; the skill does not repeat it.
#
# Format parsers and codecs (`internal/backends/`, `internal/streams/codecs/`) stay
# standard by design, though they read hostile bytes: listing them would make nearly
# every format PR deep, and they have their own defences that a review round does not
# replace (the fuzzing jobs, the CVE replays, the hostile-input checklist every standard
# round runs).
DEEP_SECURITY = (
    "src/archivey/paths.py",
    "src/archivey/config.py",
    "src/archivey/internal/config.py",
    "src/archivey/terminal.py",
    "src/archivey/internal/extraction.py",
    "src/archivey/internal/file_copy_pass.py",
    "src/archivey/internal/link_watch.py",
    "src/archivey/internal/long_paths.py",
    "src/archivey/internal/naming.py",
    "src/archivey/internal/unix_mode.py",
    "src/archivey/internal/windows_reparse.py",
    "src/archivey/internal/bomb_tracker.py",
    "src/archivey/internal/listing_limits.py",
    "src/archivey/internal/resource_usage.py",
    "src/archivey/internal/external/",
    "src/archivey/internal/streams/child_process.py",
)
# A new file under one of these may be a new format reader, parser or codec: the pull
# request gets the security pass (skill §1) whatever its tier. Other changes there get it
# when the PR body's `Security:` line or the reviewer applies the template's rules.
SECURITY_NEW_FILES = (
    "src/archivey/internal/backends/",
    "src/archivey/internal/streams/codecs/",
)
# The release's and the review loop's own files: deep, with the pull request's author as
# the attacker (skill §1). The loop's rules are here because a pull request is reviewed
# under its own copy of them (dev-docs/review-loop.md, Known rough edges).
DEEP_PROCESS = (
    ".github/workflows/",
    "scripts/release.py",
    ".github/review-loop-prompt.md",
    ".claude/skills/code-review-skill/",
    "scripts/review_loop_close.sh",
    "scripts/review_loop_gate.py",
    "scripts/review_loop_prompt.py",
    "scripts/review_prep.py",
    "scripts/review_shape.py",
)

# --- who merges: the decisions the maintainer keeps ------------------------------------

# A pull request of any tier that makes one of these decisions goes to the maintainer to
# merge; an agent merges the rest once the review approves and CI is green (maintainer,
# 2026-10-31: "I'm tired of having to merge all deep PRs, I don't actually look at
# them"). The reviewer adds what a script cannot see, such as a new subsystem or a
# reversed ruling, in its maintainer decisions block. The merging agent runs the base
# branch's copy of this script (address-review-findings §7), and this script is on the
# gate list, so a pull request cannot take itself off the list.
MAINTAINER_FILES = {
    "scripts/release.py": "touches the release path",
    ".github/workflows/publish.yml": "touches the release path",
    # The merge gate: whether a round runs and approves, when the loop stops, who merges.
    "scripts/review_loop_gate.py": "touches the merge gate",
    "scripts/review_loop_close.sh": "touches the merge gate",
    "scripts/review_prep.py": "touches the merge gate",
    ".github/workflows/review-loop.yml": "touches the merge gate",
    ".github/workflows/risk-label.yml": "touches the merge gate",
}
# The prose that says who merges: a changed line there that talks about merging moves
# the rule the script and the merging agent follow.
MERGE_RULE_FILES = (
    "AGENTS.md",
    ".claude/skills/address-review-findings/SKILL.md",
    "dev-docs/review-loop.md",
    "dev-docs/design-rules.md",
)
_MERGE_WORD_RE = re.compile(r"\bmerg(?:e|es|ed|ing)\b", re.IGNORECASE)
DECISIONS_DIR = "dev-docs/decisions/"
# Most threat model edits describe a new defence. The maintainer's call is a defended
# property dropped or cut down, or a non-guarantee accepted: each is a `###` section
# under one of these two `##` headings.
THREAT_MODEL = "dev-docs/threat-model.md"
_DEFENDED, _ACCEPTED = "Defended properties", "Accepted non-guarantees"
# A defended property whose body loses more than a third of its non-blank lines was cut
# down, not rewrapped (compared in integers: kept * 3 < before * 2).
CONFIG = "src/archivey/config.py"
WORKFLOWS = ".github/workflows/"
# The checks `main` requires before a merge (the repository's ruleset).
REQUIRED_CHECKS = (
    "CI gate",
    "Docs build",
    "OpenSpec spec prose",
    "OpenSpec changes archived",
)
# A workflow line that grants a token scope, reads or passes on a secret (`secrets.`,
# `secrets: inherit`), runs on the base repository's trust with its token and secrets
# (`pull_request_target`, `workflow_run`, and the comment and review triggers), or
# reads the `github` context in an expression: any field but a few fixed ones can carry
# text someone outside chose (a title, a branch, an actor's name). A new `run:` step
# with no expression is not matched; the Opus pass and Cursor review it.
_GITHUB_FIXED = (
    "sha|repository|repository_id|repository_owner|repository_owner_id|run_id"
    "|run_number|run_attempt|workflow|job|server_url|api_url|graphql_url|event_name"
    "|base_ref|ref_type|action_path|workspace|retention_days"
)
_WORKFLOW_POWER_RE = re.compile(
    r"\bpermissions\s*:|\bsecrets\s*[.:\[)]"
    r"|\b(?:pull_request_target|workflow_run|issue_comment|pull_request_review"
    r"|pull_request_review_comment|discussion_comment)\b"
    rf"|\$\{{\{{[^}}]*\bgithub\s*(?:\[|\.\s*(?!(?:{_GITHUB_FIXED})\b)\w)"
    r"|^\s*(?:actions|attestations|checks|contents|deployments|discussions|id-token"
    r"|issues|models|packages|pages|pull-requests|repository-projects|security-events"
    r"|statuses)\s*:\s*['\"]?(?:read|write|none)\b"
)
# An action or reusable workflow a step runs; a new one is new code with the job's token,
# a local one (`./`) included, since it may be a workflow that takes secrets.
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s]+)")
# A dataclass field with a default, as config.py writes its limits and options: one
# indent level, so a method's parameters (deeper) are not fields.
_DEFAULT_RE = re.compile(r"^ {4}([a-z_]\w*)\s*:[^=]*=\s*(.*\S)")
_API_KEY_RE = re.compile(r" \[| = |(?<=\w)\(|: ")
_CALLABLES = {"function", "method", "init", "classmethod", "staticmethod"}
# A new name at these places is one the maintainer picks: a module, a class, function,
# constant or alias exported from `archivey` itself, a CLI verb.
_TOP_LEVEL_RE = re.compile(
    r"^(?:module \S+|cli-verb \S+|(?:class|function|constant|alias) archivey\.\w+)$"
)


def _actions(lines: Iterable[str]) -> set[str]:
    return {m.group(1) for t in lines if (m := _USES_RE.match(t))}


def _api_key(line: str) -> str:
    """An api-surface line without its signature, type or value: what names it."""
    kind, _, rest = line.partition(" ")
    return f"{kind} {_API_KEY_RE.split(rest, maxsplit=1)[0]}"


def _params(line: str) -> list[str]:
    """The parameter names of a callable's api-surface line, without types or defaults."""
    start = line.find("(")
    names, depth, item = [], 0, ""
    for ch in line[start + 1 :] if start >= 0 else "":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            names.append(item)
            item = ""
        else:
            item += ch
    names.append(item)
    return [m.group(1) for n in names if (m := re.match(r"\s*(\*{0,2}\w+|\*|/)", n))]


def _positional(line: str) -> list[str]:
    """The parameters a caller can pass by position: those before `*` or `*args`."""
    names: list[str] = []
    for p in _params(line):
        if p.startswith("*"):
            break
        if p != "/":
            names.append(p)
    return names


def _literals(line: str) -> set[str]:
    """The fixed strings a line offers: a `Literal[...]` alias's members, a CLI option's
    choices, an enum value's wire string."""
    found = set(re.findall(r"'([^']*)'", line)) if "Literal[" in line else set()
    if m := re.search(r"choices=\{([^}]*)\}", line):
        found |= {c.strip() for c in m.group(1).split(",")}
    if line.startswith("value ") and " = " in line:
        found.add(line.split(" = ", 1)[1])
    return found


def _api_changes(removed: Iterable[str], added: Iterable[str]) -> list[str]:
    """Names, parameters and fixed strings the api-surface diff takes away, and the new
    top-level names it adds. A changed type or a new optional parameter is neither."""
    old = {_api_key(t): t for t in removed if t and t[0] != "#"}
    new = {_api_key(t): t for t in added if t and t[0] != "#"}
    found = [f"removes or renames a public name: {k}" for k in sorted(old.keys() - new)]
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        if key.split(" ", 1)[0] in _CALLABLES:
            gone = [p for p in _params(before) if p not in _params(after)]
            found += [f"removes a parameter: {key} {p}" for p in gone]
            # A caller passing them positionally breaks when they move or one is put
            # before them.
            old_pos, new_pos = _positional(before), _positional(after)
            if not gone and new_pos[: len(old_pos)] != old_pos:
                found.append(f"reorders positional parameters: {key}")
        found += [
            f"removes a public value: {key} {v}"
            for v in sorted(_literals(before) - _literals(after))
        ]
    found += [
        f"adds a top-level name: {k}"
        for k in sorted(new.keys() - old)
        if _TOP_LEVEL_RE.match(k)
    ]
    return found


def _requirement_names(pyproject: str | None) -> dict[str, set[str]]:
    """Runtime requirement names per group ("" for the core list)."""
    if pyproject is None:
        return {}
    import tomllib  # 3.11+; the caller says so on 3.10

    def names(reqs: object) -> set[str]:
        if not isinstance(reqs, list):
            raise TypeError(f"not a list of requirements: {reqs!r}")
        found = set()
        for req in reqs:
            if not isinstance(req, str):
                raise TypeError(f"not a requirement string: {req!r}")
            if m := name.match(req):
                found.add(re.sub(r"[-_.]+", "-", m.group(1)).lower())
        return found

    project = tomllib.loads(pyproject).get("project", {})
    groups = {"": project.get("dependencies", [])}
    groups.update(project.get("optional-dependencies", {}))
    name = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
    return {group: names(reqs) for group, reqs in groups.items()}


def _threat_sections(text: str | None) -> dict[str, dict[str, int]]:
    """Each `###` heading under a `##` section of the threat model, keyed by the section's
    title without its number, with the count of non-blank lines in its body."""
    sections: dict[str, dict[str, int]] = {}
    current, heading = "", ""
    for line in (text or "").splitlines():
        if line.startswith("## "):
            current = re.sub(r"^##\s+[\d.]*\s*", "", line).strip()
            heading = ""
            sections.setdefault(current, {})
        elif line.startswith("### "):
            heading = line[4:].strip()
            sections.setdefault(current, {})[heading] = 0
        elif heading and line.strip():
            sections[current][heading] += 1
    return sections


def _threat_changes(before_text: str | None, after_text: str | None) -> list[str]:
    before, after = _threat_sections(before_text), _threat_sections(after_text)
    found: list[str] = []
    if before_text and (_DEFENDED not in after or _ACCEPTED not in after):
        # A renamed section would hide every change below it.
        return [f"renames or drops a section of {THREAT_MODEL}"]
    defended_before, defended_after = (
        before.get(_DEFENDED, {}),
        after.get(_DEFENDED, {}),
    )
    for h in sorted(defended_before):
        if h not in defended_after:
            found.append(f"drops or renames a defended property: {h}")
        elif defended_after[h] * 3 < defended_before[h] * 2:
            found.append(
                f"cuts down a defended property: {h}"
                f" ({defended_before[h]} -> {defended_after[h]} lines)"
            )
    accepted = after.get(_ACCEPTED, {}).keys() - before.get(_ACCEPTED, {}).keys()
    found += [f"accepts a new non-guarantee: {h}" for h in sorted(accepted)]
    return found


def maintainer_decisions(
    files: Iterable[FileDiff],
    added: Iterable[str] = (),
    pyprojects: tuple[str | None, str | None] | None = None,
    threat_models: tuple[str | None, str | None] | None = None,
    known_actions: Iterable[str] = (),
) -> list[str]:
    """What in this diff is the maintainer's call. ``pyprojects`` and ``threat_models``
    are those files at the base and the head, when the diff touches them;
    ``known_actions`` are the actions the base's workflows already run."""
    known_actions = set(known_actions)
    found: list[str] = []
    if threat_models is not None:
        found += _threat_changes(*threat_models)
    for f in files:
        paths = [f.path] + ([f.renamed_from] if f.renamed_from else [])
        for path in paths:
            if path in MAINTAINER_FILES:
                found.append(f"{MAINTAINER_FILES[path]}: {path}")
        removed, added_lines = [t for _, t in f.removed], [t for _, t in f.added]
        if f.path == API_SURFACE:
            found += _api_changes(removed, added_lines)
        if f.path == CONFIG:
            # A changed value, or a new field with one; a changed annotation is not.
            old = {
                m.group(1): m.group(2) for t in removed if (m := _DEFAULT_RE.match(t))
            }
            new = {
                m.group(1): m.group(2)
                for t in added_lines
                if (m := _DEFAULT_RE.match(t))
            }
            found += [
                f"changes a default in {CONFIG}: {n}"
                for n in sorted(new)
                if old.get(n) != new[n]
            ]
        if f.path in MERGE_RULE_FILES and any(
            _MERGE_WORD_RE.search(t) for t in removed + added_lines
        ):
            found.append(f"edits the merge rule: {f.path}")
        if f.path.startswith(WORKFLOWS):
            if any(_WORKFLOW_POWER_RE.search(t) for t in removed + added_lines):
                found.append(
                    f"changes a workflow's permissions, secrets or triggers: {f.path}"
                )
            found += [
                f"adds an action: {a} ({f.path})"
                for a in sorted(
                    _actions(added_lines) - _actions(removed) - known_actions
                )
            ]
            gone = [c for c in REQUIRED_CHECKS if any(c in t for t in removed)]
            found += [f"changes a required check: {c} ({f.path})" for c in gone]
    found += [
        f"adds a workflow: {p}" for p in sorted(set(added)) if p.startswith(WORKFLOWS)
    ]
    found += [
        f"adds an architecture decision: {p}"
        for p in sorted(set(added))
        if p.startswith(DECISIONS_DIR)
    ]
    if pyprojects is not None:
        try:
            before, after = (_requirement_names(t) for t in pyprojects)
        except (
            ImportError,
            ValueError,
            TypeError,
        ) as e:  # no tomllib (3.10), or a TOMLDecodeError
            found.append(
                f"pyproject.toml changed: check its dependencies by hand ({e})"
            )
        else:
            for group, names in after.items():
                where = f" ({group})" if group else ""
                found += [
                    f"adds a runtime dependency: {n}{where}"
                    for n in sorted(names - before.get(group, set()))
                ]
    return list(dict.fromkeys(found))


API_SURFACE = "dev-docs/api-surface.txt"


def _matches(path: str, entries: Iterable[str]) -> bool:
    return any(path.startswith(e) if e.endswith("/") else path == e for e in entries)


@dataclass
class Tier:
    name: str  # "light", "standard" or "deep"
    reasons: list[str]
    api_changed: bool
    # New files under a parser or codec directory: the security pass runs on any tier.
    new_parsers: list[str] = field(default_factory=list)
    # What makes the maintainer merge it (maintainer_decisions); empty: an agent merges.
    maintainer: list[str] = field(default_factory=list)
    # Workflows that would make it deep but run on nobody else's input with a read-only
    # token (quiet_workflow): standard instead, and the security pass still runs.
    quiet_workflows: list[str] = field(default_factory=list)


def tier(paths: Iterable[str], added: Iterable[str] = ()) -> Tier:
    """Classify the changed paths (renames give both sides) into a review tier.
    `added` are the paths the diff creates."""
    paths = sorted(set(paths))
    new_parsers = sorted(p for p in set(added) if _matches(p, SECURITY_NEW_FILES))
    security = [p for p in paths if _matches(p, DEEP_SECURITY)]
    process = [p for p in paths if _matches(p, DEEP_PROCESS)]
    api_changed = API_SURFACE in paths
    if security or process:
        return Tier("deep", security + process, api_changed, new_parsers)
    heavier = [
        p
        for p in paths
        if _matches(p, NOT_LIGHT)
        or not (
            _matches(p, LIGHT_PREFIXES)
            or p in LIGHT_FILES
            or ("/" not in p and p.endswith(".md"))
        )
    ]
    if paths and not heavier:
        return Tier("light", [], api_changed, new_parsers)
    return Tier("standard", heavier, api_changed, new_parsers)


def _name_status(base: str, head: str) -> list[list[str]]:
    """``git diff --name-status -M``: a status letter, then the path, or for a rename the
    old path and the new one. ``-M`` keeps a moved file a rename whatever the machine's
    ``diff.renames`` says."""
    out = git("diff", "--name-status", "-M", f"{base}...{head}")
    return [line.split("\t") for line in out.splitlines() if line]


def changed_paths(base: str, head: str) -> list[str]:
    # A rename lists the old path and the new one; both count.
    return [p for status, *paths in _name_status(base, head) for p in paths]


def added_paths(base: str, head: str) -> list[str]:
    return [paths[0] for status, *paths in _name_status(base, head) if status == "A"]


# The triggers a quiet workflow may have: someone with write access starts it, or the
# clock does. Nothing a fork or an issue author chose reaches it.
_QUIET_TRIGGERS = frozenset({"workflow_dispatch", "schedule"})
# Every reader below fails closed: a spelling it does not read makes the workflow not
# quiet, so the pull request stays deep. YAML and GitHub's expressions allow more forms
# than a line regex can follow (quoted keys and values, flow mappings, `secrets['X']`),
# and the unsafe answer must not be the default one.
_ON_RE = re.compile(r"""^(?:on|"on"|'on'|true)\s*:\s*(.*?)\s*(?:#.*)?$""")
_BARE_KEY_RE = re.compile(r"^(\s+)([\w-]+)\s*:(?:\s.*)?$")
_PERMISSIONS_RE = re.compile(r"^(\s*)permissions\s*:\s*(.*?)\s*(?:#.*)?$")
_READ_SCOPE_RE = re.compile(r"^\s+[\w-]+\s*:\s*(?:read|none)\s*(?:#.*)?$")
# The job's own token, which `permissions:` bounds; any other mention of `secrets`
# (another secret, `secrets: inherit`, `toJSON(secrets)`) is not quiet.
_JOB_TOKEN_RE = re.compile(
    r"""\bsecrets\s*(?:\.\s*GITHUB_TOKEN|\[\s*(['"])GITHUB_TOKEN\1\s*\])(?![\w-])"""
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _triggers(text: str) -> set[str] | None:
    """The event names under a workflow's top-level ``on:``, or None where the script
    cannot tell: no ``on:`` or two of them, or any line of the block it does not read."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if _ON_RE.match(line)]
    if len(starts) != 1:
        return None
    i = starts[0]
    m = _ON_RE.match(lines[i])
    assert m is not None
    if inline := m.group(1):
        if inline.startswith("[") and inline.endswith("]"):
            inline = inline[1:-1]
        names = [n.strip() for n in inline.split(",")]
        return set(names) if all(re.fullmatch(r"[\w-]+", n) for n in names) else None
    found: set[str] = set()
    indent = None
    for nxt in lines[i + 1 :]:
        if not nxt.strip() or nxt.lstrip().startswith("#"):
            continue
        if not nxt[0].isspace():
            break
        if indent is None:
            indent = _indent(nxt)
        if _indent(nxt) > indent:
            continue  # an event's own settings: inputs, cron lines
        k = _BARE_KEY_RE.match(nxt)
        if _indent(nxt) < indent or k is None:
            return None  # a quoted key, a list item, a dedent: not read here
        found.add(k.group(2))
    return found or None


def _read_only_permissions(lines: list[str]) -> bool:
    """A top-level ``permissions:`` exists, and every ``permissions:`` grants only
    ``read`` or ``none``, each scope on its own line (an allowlist: a quoted value or a
    flow mapping is not read here, so it is not read-only)."""
    top = False
    for i, line in enumerate(lines):
        m = _PERMISSIONS_RE.match(line)
        if m is None:
            if re.match(
                r"""^\s*(?:-\s*)?["']permissions["']\s*:|^\s*-\s*permissions\s*:""",
                line,
            ):
                return False  # a quoted or list-item key: not read here
            continue
        top |= m.group(1) == ""
        value = m.group(2)
        if value:
            if value not in {"read-all", "{}"}:
                return False
            continue
        for nxt in lines[i + 1 :]:
            if not nxt.strip() or nxt.lstrip().startswith("#"):
                continue
            if _indent(nxt) <= len(m.group(1)):
                break
            if not _READ_SCOPE_RE.match(nxt):
                return False
    return top  # without one, the repository's default token, whatever that is set to


def quiet_workflow(text: str | None) -> bool:
    """A workflow that only a dispatch or the schedule starts, with an explicit token
    scope that writes nothing and no secret but the job's own token. Every `github`
    field it reads was then set by someone with write access or by the repository: no
    outside attacker supplies its input, so it is not deep for its own sake. It still
    reaches shared CI state that `permissions:` does not scope, such as the Actions
    cache and artifacts other jobs restore, so the security pass stays on (tier_report).
    A new one, or a change to its triggers or token, still goes to the maintainer
    (maintainer_decisions)."""
    if text is None:
        return False
    triggers = _triggers(text)
    if not triggers or not triggers <= _QUIET_TRIGGERS:
        return False
    lines = text.splitlines()
    if not _read_only_permissions(lines):
        return False
    # Comments are read too: a `#` inside a `run:` string would otherwise hide the rest
    # of its line, and a comment that names a secret only costs a deep review.
    return not any(re.search(r"\bsecrets\b", _JOB_TOKEN_RE.sub("", t)) for t in lines)


def review_tier(base: str, head: str) -> Tier:
    paths, added = changed_paths(base, head), added_paths(base, head)
    t = tier(paths, added)
    quiet = [
        p
        for p in t.reasons
        if p.startswith(WORKFLOWS)
        and p not in MAINTAINER_FILES
        and quiet_workflow(base_text(head, p))
    ]
    if t.name == "deep" and quiet and len(quiet) == len(t.reasons):
        rest = tier([p for p in paths if p not in quiet], added)
        # Standard even when `rest` is light: a workflow is code that runs in CI, so it
        # keeps the Opus pass when the rest of the diff is prose, tests or benchmarks.
        t = Tier(
            "standard",
            quiet + rest.reasons,
            t.api_changed,
            t.new_parsers,
            quiet_workflows=quiet,
        )
    files = parse_diff(git("diff", "-U0", "-M", f"{base}...{head}"))
    # `base...head` diffs from the merge base, so the "before" texts come from there too.
    fork = git("merge-base", base, head).strip()
    both = {
        path: (base_text(fork, path), base_text(head, path))
        for path in ("pyproject.toml", THREAT_MODEL)
        if path in paths
    }
    known: set[str] = set()
    if any(p.startswith(WORKFLOWS) for p in paths):
        for wf in git("ls-tree", "--name-only", f"{fork}:{WORKFLOWS}").split():
            known |= _actions((base_text(fork, WORKFLOWS + wf) or "").splitlines())
    t.maintainer = maintainer_decisions(
        files, added, both.get("pyproject.toml"), both.get(THREAT_MODEL), known
    )
    return t


def _not_light(reasons: list[str]) -> str:
    shown = reasons[:5]
    more = f" (+{len(reasons) - len(shown)} more)" if len(reasons) > 5 else ""
    return f"  not light because of: {', '.join(shown)}{more}"


def tier_report(t: Tier) -> list[str]:
    lines = [f"tier: {t.name}"]
    if t.name == "deep":
        lines += [f"  deep path: {p}" for p in t.reasons]
    elif t.quiet_workflows:
        lines += [
            f"  quiet workflow (dispatch or schedule, read-only token): {p}"
            for p in t.quiet_workflows
        ]
        if rest := t.reasons[len(t.quiet_workflows) :]:
            lines.append(_not_light(rest))
    elif t.name == "standard" and not t.reasons:
        lines.append("  no committed changes against the base")
    elif t.name == "standard":
        lines.append(_not_light(t.reasons))
    if t.name == "deep" or t.new_parsers or t.quiet_workflows:
        lines.append("security pass: yes")
        lines += [
            f"  new file under a parser or codec directory: {p}" for p in t.new_parsers
        ]
    else:
        lines.append(
            "security pass: per the Risk line's rules (pull_request_template.md)"
        )
    lines.append(
        f"public API: {'changed (' + API_SURFACE + ')' if t.api_changed else 'unchanged'}"
    )
    if t.maintainer:
        lines.append("merge: the maintainer merges this one")
        shown = t.maintainer[:8]
        lines += [f"  maintainer decision: {d}" for d in shown]
        if len(t.maintainer) > len(shown):
            lines.append(f"  (+{len(t.maintainer) - len(shown)} more)")
    elif t.name == "deep":
        lines.append(
            "merge: an agent merges once the Opus pass and Cursor approve and CI is green"
        )
    elif t.name == "standard":
        # review_loop_gate.py OPUS_PASS_TIERS: standard and deep get the Opus pass.
        lines.append(
            "merge: an agent merges once the Opus pass approves and CI is green"
        )
    else:
        lines.append("merge: an agent merges once the review approves and CI is green")
    return lines


# --- red-on-base: do the new tests fail without this PR's src/? -------------------------


def red_on_base(base: str, test_ids: list[str]) -> int:
    merge_base = git("merge-base", base, "HEAD").strip()
    tmp = Path(tempfile.mkdtemp(prefix="red-on-base-"))
    tree = tmp / "tree"
    try:
        git("worktree", "add", "--detach", str(tree), merge_base)
        # This branch's tests against the base's src/: the tests are the claim, the base
        # is what they must fail against.
        shutil.rmtree(tree / "tests")
        shutil.copytree(ROOT / "tests", tree / "tests")
        env = dict(os.environ, PYTHONPATH=str(tree / "src"))
        # `python -m pytest` exits 1 both for a failing test and for no pytest at all;
        # without this, the second prints "fails" for a run that never happened.
        probe = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            cwd=tree,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            sys.exit(
                f"red-on-base: pytest is not importable from {sys.executable}.\n"
                "Run it in the project's environment: "
                "uv run python scripts/review_prep.py red-on-base ..."
            )
        # The project environment also has this branch's archivey installed. PYTHONPATH
        # outranks an editable install's path entry but not a meta-path finder, and the
        # latter would measure the branch and call every test "passes". Check, not assume.
        where = subprocess.run(
            [sys.executable, "-c", "import archivey; print(archivey.__file__)"],
            cwd=tree,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if not Path(where).resolve().is_relative_to((tree / "src").resolve()):
            sys.exit(
                f"red-on-base: `import archivey` resolves to {where or 'nothing'}, "
                f"not the merge base's {tree / 'src'}; the table would measure the wrong code."
            )
        rows: list[tuple[str, str]] = []
        for test_id in test_ids:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--no-header",
                    "-rN",
                    test_id,
                ],
                cwd=tree,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            rows.append((test_id, _outcome(proc.returncode, proc.stdout + proc.stderr)))
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(tree)],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"New tests against `src/` at the merge base ({merge_base[:10]}):\n")
    print("| Test | On the base |")
    print("|---|---|")
    for test_id, outcome in rows:
        print(f"| `{test_id}` | {outcome} |")
    passing = [t for t, o in rows if o.startswith("passes")]
    if passing:
        print(f"\n{len(passing)} test(s) pass without this change: they do not pin it.")
    return 1 if passing else 0


_FAILED_RE = re.compile(r"^=*\s*\d+ failed\b", re.MULTILINE)


def _outcome(returncode: int, output: str) -> str:
    if returncode == 0:
        return "passes"
    # Exit 1 alone is not evidence: pytest's summary must say something failed.
    if returncode == 1 and _FAILED_RE.search(output):
        return "fails"
    # A collection error is most often an import of a name this PR adds. That is red, but
    # it proves the import, not the behaviour the test names.
    why = next(
        (
            line.strip().removeprefix("E").strip()
            for line in output.splitlines()
            if "cannot import name" in line or "No module named" in line
        ),
        "",
    )
    if why:
        return f"errors at collection: {why[:90]}"
    if returncode in (4, 5) or "ERROR: not found" in output:
        return "not found (check the id)"
    return f"did not run (exit {returncode}; read the output)"


# --- entry point ------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--base", default="origin/main", help="compare against (origin/main)"
    )
    parser.add_argument("--head", default="HEAD", help=argparse.SUPPRESS)
    parser.add_argument(
        "command",
        nargs="?",
        default="all",
        choices=["all", "sweep", "width", "red-on-base", "tier"],
    )
    parser.add_argument("tests", nargs="*", help="red-on-base: pytest node ids")
    args = parser.parse_args(argv)

    if args.command == "red-on-base":
        if not args.tests:
            parser.error("red-on-base needs at least one pytest node id")
        return red_on_base(args.base, args.tests)

    if args.command == "tier":
        print("\n".join(tier_report(review_tier(args.base, args.head))))
        return 0

    files = parse_diff(git("diff", "-U0", f"{args.base}...{args.head}"))
    status = 0
    if args.command in ("all", "sweep"):
        moved = moved_claims(files, lambda path: base_text(args.head, path))
        found = sweep(moved, doc_files())
        print(
            "=== sweep: docs still naming what this branch moved (read each; may be fine)"
        )
        print("\n".join(found) if found else "nothing found")
    if args.command in ("all", "width"):
        found = width(files, args.base, args.head)
        print("=== width: added lines wider than their file (rewrap the paragraph)")
        print("\n".join(found) if found else "nothing found")
        status = 1 if found else 0
    if args.command == "all":
        print(
            "=== tier: how deep the review goes (copy into the PR body's Risk section)"
        )
        print("\n".join(tier_report(review_tier(args.base, args.head))))
    return status


if __name__ == "__main__":
    sys.exit(main())
