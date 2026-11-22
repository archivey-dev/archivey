#!/usr/bin/env python3
"""Checks an implementer runs before adding the `review` label, and again before each re-label.

The review loop's findings, measured over 38 pull requests (2026-09-23/24), are dominated
by three shapes that a script can find faster than a reviewer:

- a symbol or an exception type changed in `src/` and is still described the old way in a
  spec or a handbook page (``sweep``; the CHANGELOG is left out, since the release does
  its final pass);
- an added Markdown prose line over 100 columns (``width``, the same rule CI runs in
  ``scripts/checks/check_line_width.py``; Python lines are ruff's E501);
- a new test the PR body says fails on `main`, which passes there (``red-on-base``).

It also prints the review tier the changed paths put the pull request in (``tier``): how
deep a review round goes, and whether the public API moved. The reviewer runs the same
command, so the PR body's Risk section can be checked against it.

67 of the 70 findings raised after round 1 were caused by the previous round's fix, so the
same checks apply to the fix commits before the label goes on again.

    uv run python scripts/review/review_prep.py                 # sweep + width against origin/main
    uv run python scripts/review/review_prep.py --base HEAD~1   # just the last commit's fixes
    uv run python scripts/review/review_prep.py red-on-base tests/test_x.py::test_y ...
    uv run python scripts/review/review_prep.py tier            # light, standard or deep, and why

``sweep`` only reports: whether a hit is stale needs reading. ``width`` exits 1 when an
added Markdown line is over 100 columns. ``red-on-base`` prints a table to paste into
the PR body in place of a prose "fails on main" claim.

``sweep``, ``width`` and ``tier`` are stdlib only and run under any Python 3.10+, so a
reviewer without the project environment runs ``python3 scripts/review/review_prep.py tier``;
``red-on-base`` runs pytest, so it needs the project's environment and refuses to start
without one.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

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

_DEF_RE = re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_]\w*)")
_CONST_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*(?::[^=]+)?=")
_RAISE_RE = re.compile(r"\braise\s+([A-Z]\w*(?:Error|Exception|Warning))\b")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s?(.*)$")
# `.gitattributes` sets `*.py diff=python`, so a hunk header names the enclosing def, not
# the last column-0 line (the class).
_HUNK_DEF_RE = re.compile(r"(?:def|class)\s+([A-Za-z_]\w*)")


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


# --- width: added Markdown prose lines over 100 columns -------------------------------


def _line_width_module():
    """`scripts/checks/check_line_width.py`, loaded by path: `scripts/` is not a package."""
    script = Path(__file__).resolve().parents[1] / "checks" / "check_line_width.py"
    spec = importlib.util.spec_from_file_location("check_line_width", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_line_width", module)
    spec.loader.exec_module(module)
    return module


def base_text(base: str, path: str) -> str | None:
    """``path`` as it is at ``base`` (any revision), or None where it does not exist."""
    try:
        return git("show", f"{base}:{path}")
    except subprocess.CalledProcessError:
        return None


def width(files: Iterable[FileDiff], head: str = "HEAD") -> list[str]:
    """The same rule CI runs, so the two never disagree.

    Markdown is `check_line_width.problems`: an added prose line over 100 columns that
    ``check_line_width.py --fix`` can break. Python lines are ruff's (E501 at 100),
    which ``check.sh`` and CI already run, so they are not checked twice here.
    """
    line_width = _line_width_module()
    report: list[str] = []
    for f in files:
        if not f.path.endswith(".md"):
            continue
        text = base_text(head, f.path)
        if text is not None:
            report += line_width.problems(f.path, text, {n for n, _ in f.added})
    return report


# --- tier: how deep the review goes ----------------------------------------------------

# The tests of the scripts (CONTRIBUTING.md §Testing standards): tests like `tests/`,
# for the tier.
SCRIPT_TESTS = "scripts/tests/"

# A pull request is light only when every path it changes is here: maintainer prose,
# tests and benchmarks. Three rules keep the rest out:
# - What an agent or a review round reads as its own instructions or contracts is never
#   light: the skills and commands (`.claude/`, `.cursor/`, so they are not listed here)
#   and the files in NOT_LIGHT.
# - Neither is a gate inside a light folder: the skip markers and the benchmark gate.
# - Neither are the user docs (`docs/`, the README, the CHANGELOG, SECURITY.md): Opus
#   reviews them (design-rules.md DR-22b), and only the standard and deep tiers get the
#   Opus round (`review_loop_gate.OPUS_PASS_TIERS`).
# `openspec/` is not light either, because a spec is a contract.
LIGHT_PREFIXES = (
    "dev-docs/",
    "tests/",
    SCRIPT_TESTS,
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
    # User docs, which Opus reviews (DR-22b)
    "docs/",
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    # Gates
    "tests/conftest.py",
    "benchmarks/wall_baseline.py",
)

# A pull request is deep when its review needs a second model: it moves the public API,
# adds a reader, parser, codec or native kernel, changes code in a layer every format
# goes through, or its author or reviewer raised it (a `Review-Tier: deep` trailer).
# Deep is about the code a bug would sit in, not about who could attack the files: the
# release's and the review loop's own files are standard with the security pass
# (PROCESS_FILES), and the maintainer merges the ones that decide a merge
# (MAINTAINER_FILES). Maintainer, 2026-11-22: "deep is for things that affect the
# overall architecture, non-straightforward changes, tricky code and so on, which are
# much more important than the CI workflows and skills we're using it for."

# Paths where one bug breaks a safety guarantee for every format: writes stay inside the
# destination, resources stay bounded, archive-supplied input never reaches a command
# line or a terminal as anything but inert text. A change to their code makes the pull
# request deep; a change to a docstring or a comment alone does not (_code_changed).
# Edit the list here; the skill does not repeat it.
DEEP_SECURITY = (
    "src/archivey/paths.py",
    "src/archivey/config.py",
    "src/archivey/internal/config.py",
    "src/archivey/terminal.py",
    "src/archivey/internal/extraction.py",
    "src/archivey/internal/file_copy_pass.py",
    "src/archivey/internal/link_watch.py",
    "src/archivey/internal/dependency_index.py",
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
# The layer every format goes through: the reader base and the plugin adapter, reader
# state and its locks, passwords, the source, and the streams that check and defer
# errors. A bug here reaches every format at once, as one in DEEP_SECURITY does.
DEEP_CORE = (
    "src/archivey/internal/base_reader.py",
    "src/archivey/internal/format_adapter.py",
    "src/archivey/internal/reader_state.py",
    "src/archivey/internal/password.py",
    "src/archivey/internal/plugin_passwords.py",
    "src/archivey/internal/source.py",
    "src/archivey/internal/streams/archive_stream.py",
    "src/archivey/internal/streams/decompressor_stream.py",
    "src/archivey/internal/streams/verify.py",
)
# A new file under one of these is a new reader, parser, codec or native kernel: deep,
# with the security pass. An edit to an existing one is standard, since nearly every
# format PR edits one and they have their own defences that a review round does not
# replace (the fuzzing jobs, the CVE replays, the hostile-input checklist every standard
# round runs); the PR body's `Security:` line or the reviewer still gives it the pass,
# and the author raises it to deep when the change is tricky.
NEW_PARSER_DIRS = (
    "src/archivey/internal/backends/",
    "src/archivey/internal/streams/codecs/",
    "packages/archivey-codecs/src/kernels/",
)
# The public API: archivey's (generated, `scripts/checks/api_surface.py`) and
# archivey-codecs' type stubs, which are that package's API.
API_SURFACE = "dev-docs/api-surface.txt"
CODECS_API = "packages/archivey-codecs/python/archivey_codecs/"
# The trailer that raises a pull request to deep, in any of its commit messages:
# `Review-Tier: deep (why)`. History keeps it, so a later push cannot lower the tier.
# Git parses the trailers (`%(trailers)`: the last paragraph only), so a body line that
# happens to start with the key is not one.
TIER_TRAILER = "Review-Tier"
_DEEP_VALUE_RE = re.compile(r"^deep\b[ \t]*(.*)$", re.IGNORECASE)
# The release's and the review loop's own files: standard, with the security pass and
# the pull request's author as the attacker (skill §1). The loop's rules are here
# because a pull request is reviewed under its own copy of them
# (dev-docs/review-loop.md, Known rough edges); the ones that decide a merge also go to
# the maintainer (MAINTAINER_FILES).
PROCESS_FILES = (
    ".github/workflows/",
    "scripts/release/release.py",
    ".github/review-loop-prompt.md",
    ".claude/skills/code-review-skill/",
    "scripts/review/review_loop_close.sh",
    "scripts/review/review_loop_gate.py",
    "scripts/review/review_loop_prompt.py",
    "scripts/review/review_loop_trace.py",
    "scripts/review/review_prep.py",
    "scripts/review/review_shape.py",
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
    "scripts/release/release.py": "touches the release path",
    ".github/workflows/publish.yml": "touches the release path",
    # The merge gate: whether a round runs and approves, when the loop stops, who merges.
    "scripts/review/review_loop_gate.py": "touches the merge gate",
    "scripts/review/review_loop_close.sh": "touches the merge gate",
    "scripts/review/review_prep.py": "touches the merge gate",
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
    r"\bpermissions\s*:|(?i:\bsecrets\s*[.:\[)])"
    r"|\b(?:pull_request_target|workflow_run|issue_comment|pull_request_review"
    r"|pull_request_review_comment|discussion_comment)\b"
    rf"|(?i:\$\{{\{{[^}}]*\bgithub\s*(?:\[|\.\s*(?!(?:{_GITHUB_FIXED})\b)\w))"
    r"|^\s*(?:actions|attestations|checks|contents|deployments|discussions|id-token"
    r"|issues|models|packages|pages|pull-requests|repository-projects|security-events"
    r"|statuses)\s*:\s*(?:['\"]?(?:read|write|none)\b|[>|]|$)"
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


def _matches(path: str, entries: Iterable[str]) -> bool:
    return any(path.startswith(e) if e.endswith("/") else path == e for e in entries)


@dataclass
class Tier:
    name: str  # "light", "standard" or "deep"
    # What decided it: for deep, the lines `deep: ...` prints; otherwise the paths that
    # kept it from light.
    reasons: list[str]
    # New files under a parser, codec or kernel directory (deep, with the security
    # pass).
    new_parsers: list[str] = field(default_factory=list)
    # What makes the maintainer merge it (maintainer_decisions); empty: an agent merges.
    maintainer: list[str] = field(default_factory=list)
    # The release's and the review loop's files it touches: the security pass, with the
    # pull request's author as the attacker.
    process: list[str] = field(default_factory=list)
    # The public API files it changes: archivey's surface and archivey-codecs' stubs.
    api_paths: list[str] = field(default_factory=list)

    @property
    def api_changed(self) -> bool:
        return bool(self.api_paths)


def tier(
    paths: Iterable[str],
    added: Iterable[str] = (),
    code_changed: Callable[[str], bool] | None = None,
    raised: Iterable[str] = (),
) -> Tier:
    """Classify the changed paths (renames give both sides) into a review tier.
    `added` are the paths the diff creates. `code_changed(path)` says whether a
    DEEP_SECURITY or DEEP_CORE path changed more than its docstrings and comments
    (every one did, when it is not given). `raised` are the reasons of the
    `Review-Tier: deep` trailers in the pull request's commits."""
    paths = sorted(set(paths))
    added = set(added)
    changed = code_changed or (lambda path: True)
    new_parsers = sorted(
        p for p in added if _matches(p, NEW_PARSER_DIRS) and not p.endswith(".md")
    )
    api = [p for p in paths if p == API_SURFACE or _matches(p, (CODECS_API,))]
    api = [p for p in api if p == API_SURFACE or p.endswith(".pyi")]
    core = [p for p in paths if _matches(p, DEEP_SECURITY + DEEP_CORE) and changed(p)]
    process = [p for p in paths if _matches(p, PROCESS_FILES)]
    deep = (
        [f"public API: {p}" for p in api]
        + [f"new reader, parser, codec or kernel: {p}" for p in new_parsers]
        + [f"shared layer: {p}" for p in core]
        + [f"raised in a commit: {r or '(no reason given)'}" for r in raised]
    )
    if deep:
        return Tier("deep", deep, new_parsers, process=process, api_paths=api)
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
        return Tier("light", [], new_parsers, process=process, api_paths=api)
    return Tier("standard", heavier, new_parsers, process=process, api_paths=api)


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return tree


def _code_changed(before: str | None, after: str | None) -> bool:
    """Whether a Python file changed more than its docstrings and comments. A file added
    or removed, one that does not parse, and anything not Python count as changed."""
    if before is None or after is None:
        return True
    try:
        old, new = (_strip_docstrings(ast.parse(t)) for t in (before, after))
    except SyntaxError:
        return True
    return ast.dump(old) != ast.dump(new)


def raised_tiers(values: str) -> list[str]:
    """The reasons of the `deep` values among these `Review-Tier` trailer values, one
    per line, as `git log --format=%(trailers:key=Review-Tier,valueonly)` prints them."""
    return [
        m.group(1).strip().strip("()").strip()
        for line in values.splitlines()
        if (m := _DEEP_VALUE_RE.match(line.strip()))
    ]


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


def review_tier(base: str, head: str) -> Tier:
    paths, added = changed_paths(base, head), added_paths(base, head)
    # `base...head` diffs from the merge base, so the "before" texts come from there too.
    fork = git("merge-base", base, head).strip()

    def code_changed(path: str) -> bool:
        if not path.endswith(".py"):
            return True
        return _code_changed(base_text(fork, path), base_text(head, path))

    raised = raised_tiers(
        git(
            "log",
            f"--format=%(trailers:key={TIER_TRAILER},valueonly,separator=%x0a)",
            f"{fork}..{head}",
        )
    )
    t = tier(paths, added, code_changed, raised)
    files = parse_diff(git("diff", "-U0", "-M", f"{base}...{head}"))
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
        lines += [f"  deep: {r}" for r in t.reasons]
    elif t.name == "standard" and not t.reasons:
        lines.append("  no committed changes against the base")
    elif t.name == "standard":
        lines.append(_not_light(t.reasons))
    if t.name == "deep" or t.process:
        lines.append("security pass: yes")
        lines += [
            f"  new reader, parser, codec or kernel file: {p}" for p in t.new_parsers
        ]
        lines += [
            f"  release or review-loop file (attacker: the pull request's author): {p}"
            for p in t.process
        ]
    else:
        lines.append(
            "security pass: per the Risk line's rules (pull_request_template.md)"
        )
    lines.append(
        f"public API: {'changed (' + ', '.join(t.api_paths) + ')' if t.api_paths else 'unchanged'}"
    )
    if t.maintainer:
        lines.append("merge: the maintainer merges this one")
        shown = t.maintainer[:8]
        lines += [f"  maintainer decision: {d}" for d in shown]
        if len(t.maintainer) > len(shown):
            lines.append(f"  (+{len(t.maintainer) - len(shown)} more)")
    elif t.name == "deep":
        lines.append(
            "merge: an agent merges once the Opus pass and a Codex or Cursor review "
            "approve and CI is green"
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
                "uv run python scripts/review/review_prep.py red-on-base ..."
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
        found = width(files, args.head)
        print(
            "=== width: added Markdown lines over 100 columns (run check_line_width.py --fix)"
        )
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
