#!/usr/bin/env python3
"""Replay the review skill on PRs whose bugs got past the review loop, and score it.

Each case in ``dev-docs/review-eval/cases.toml`` is a merged PR, the commit its last
review round saw, and a bug that commit had (found later and fixed by another PR). A run
reviews each case afresh with the *current* ``code-review-skill`` and asks a judge
whether the review names the bug. Rerun it whenever the skill, its references, the
workflow prompt or the reviewer model changes, and compare with the baseline in
``dev-docs/review-eval/results.md``.

    python3 scripts/review_eval.py list
    python3 scripts/review_eval.py run --out /tmp/eval-1                 # every case
    python3 scripts/review_eval.py run --out /tmp/eval-1 --case ID ...   # some
    python3 scripts/review_eval.py judge --out /tmp/eval-1               # rescore only

A case is reviewed in a fresh repository that holds only the history up to the
reviewed commit, with ``main`` at its merge base, so neither the fix nor the later
rounds are there to find. The current skill and ``scripts/review_prep.py`` are copied
over the old ones. ``gh`` is replaced by a stub, and the prompt says to post nothing and
edit nothing: the review is the reviewer's final answer, saved as ``review.md``.

Each review is a full review round, so a run of every case costs real quota: run one case
first when trying a change, and the whole set when the change is done.

Needs the ``claude`` CLI on PATH; nothing from the project's environment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import posixpath
import shutil
import subprocess
import sys
import time
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "dev-docs" / "review-eval"
CASES = EVAL_DIR / "cases.toml"
BODIES = EVAL_DIR / "pr-bodies"
SKILL = Path(".claude/skills/code-review-skill")
# Copied with the skill: its §1 tells the reviewer to run the tier command.
COPIED = (SKILL, Path("scripts/review_prep.py"))

REVIEW_MODEL = "claude-sonnet-5-5"  # what .github/workflows/review-loop.yml runs
# The loop's tools less WebFetch: a fetch of the PR's page on GitHub would show the
# later rounds and the fix.
REVIEW_TOOLS = "Read,Grep,Glob,Bash"
JUDGE_MODEL = "claude-sonnet-5-5"
TIMEOUT = 3600
_READERS = {"sed", "cat", "head", "tail", "nl"}
# What `summary` counts as the reviewer's guides, by path prefix.
GUIDES = (
    ".claude/skills/code-review-skill/",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "dev-docs/",
    "openspec/",
)

GH_STUB = """#!/bin/sh
echo "gh is not available in this replay: the PR is checked out here (git diff main...HEAD)." >&2
exit 1
"""

REVIEW_PROMPT = """\
You are replaying a code review of pull request #{pr} in archivey-dev/archivey, for an
evaluation of the review process. Its title and description are below. This
directory is the repository at the PR's head; `main` is the base it was reviewed
against, so the change under review is `git diff main...HEAD`. This is review round 1.

Follow this repository's own review skill, in full, as if it had been invoked by name:
read `.claude/skills/code-review-skill/SKILL.md` first, then the one reference doc its
§1 names for this kind of review, and obey them over any generic review habit.

This replay differs from a real round in four ways:

- There is no GitHub. Do not run `gh`, do not reach the network, and post nothing.
- Do not edit, create or delete any file, and do not commit. You are reviewing.
- Stay inside this directory: do not read any other checkout of the repository.
- Instead of posting, give the whole review as your final answer: blocks 1 to 3 of §3,
  with every finding written out in full (its ID, severity, confidence, `file:line`
  and text), including the ones a real round would post as inline comments.

Do not re-run the gates. The review skill's files and `scripts/review_prep.py` show as
modified in the working tree: they are today's versions, copied in, not part of the PR.

----- PR #{pr} -----
{body}
"""

JUDGE_PROMPT = """\
You are scoring a code review against one known bug. The review was written for a
pull request that, as later work found, contained this bug:

<bug>
Files: {files}
{bug}
</bug>

The review counts as catching the bug if: {caught_if}

A finding that names the right place but a different problem does not count. A
finding that describes the same failure in other words counts. "partial" is for a
finding that points at the bug's cause or symptom but stops short of what the
criterion asks (for example it raises it as a question, or names the right
mechanism for the wrong input).

<review>
{review}
</review>

Answer with one JSON object and nothing else:
{{"caught": "yes" | "partial" | "no", "finding": "the finding's ID, or empty",
"severity": "its severity marker as written, or empty",
"reason": "one or two sentences"}}
"""


@dataclass(frozen=True)
class Case:
    id: str
    pr: int
    round: int
    head: str
    base: str
    fixed_by: str
    files: list[str]
    bug: str
    caught_if: str

    @property
    def body(self) -> str:
        return (BODIES / f"{self.pr}.md").read_text(encoding="utf-8")


def load_cases() -> list[Case]:
    with CASES.open("rb") as f:
        raw = tomllib.load(f)["case"]
    return [
        Case(**{k: (v.strip() if isinstance(v, str) else v) for k, v in c.items()})
        for c in raw
    ]


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def skill_version() -> str:
    """The skill's tree hash at HEAD, marked dirty when the working tree differs."""
    tree = git("rev-parse", f"HEAD:{SKILL}")[:12]
    dirty = git("status", "--porcelain", "--", str(SKILL), "scripts/review_prep.py")
    return tree + ("-dirty" if dirty else "")


def ensure_commits(case: Case) -> None:
    """Fetch ``case.head`` from GitHub's ``refs/pull/<pr>/head`` when this clone lacks
    it: a PR branch is deleted at merge, so most reviewed commits are reachable only
    there."""

    def have(sha: str) -> bool:
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=ROOT,
            check=False,
            stderr=subprocess.DEVNULL,
        )
        return probe.returncode == 0

    if not have(case.head):
        subprocess.run(
            ["git", "fetch", "-q", "--no-tags", "origin",
             f"refs/pull/{case.pr}/head:refs/review-eval/pr{case.pr}"],
            cwd=ROOT, check=False,
        )  # fmt: skip
    for name, sha in (("head", case.head), ("base", case.base)):
        if not have(sha):
            raise RuntimeError(
                f"{case.id}: {name} {sha[:12]} is not in this clone; run `git fetch "
                f"origin refs/pull/{case.pr}/head:refs/review-eval/pr{case.pr}` (head) "
                "or unshallow the clone (base)"
            )


def prepare(case: Case, work: Path, install: bool = False) -> Path:
    """A repository holding history up to ``case.head`` only, ``main`` at its base."""
    ensure_commits(case)
    repo = work / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    # Fetch through a temporary ref: a local fetch by bare SHA is not always allowed.
    # Unique, so runs of the same case at once do not share it.
    ref = f"refs/review-eval/{case.id}-{uuid.uuid4().hex[:8]}"
    git("update-ref", ref, case.head)
    try:
        git("init", "-q", cwd=repo)
        git("fetch", "-q", "--no-tags", str(ROOT), f"{ref}:refs/heads/pr", cwd=repo)
    finally:
        git("update-ref", "-d", ref)
    git("checkout", "-q", "pr", cwd=repo)
    git("branch", "main", case.base, cwd=repo)
    # Tools such as `review_prep.py tier` diff against origin/main by default.
    git("update-ref", "refs/remotes/origin/main", case.base, cwd=repo)
    for path in COPIED:
        dest = repo / path
        if dest.is_dir():
            shutil.rmtree(dest)
        if (ROOT / path).is_dir():
            shutil.copytree(ROOT / path, dest)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, dest)
    if install:
        # What `scripts/setup-dev-env.sh` installs, at the PR's own lockfile.
        subprocess.run(
            ["uv", "sync", "-q", "--frozen", "--group", "dev", "--extra", "all"],
            cwd=repo, check=True, capture_output=True, text=True,
        )  # fmt: skip
    stub = work / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "gh").write_text(GH_STUB)
    (stub / "gh").chmod(0o755)
    return repo


def claude(
    prompt: str,
    *,
    model: str,
    cwd: Path,
    tools: str,
    env: dict[str, str],
    effort: str | None = None,
    transcript: Path | None = None,
) -> dict:
    fmt = ["stream-json", "--verbose"] if transcript else ["json"]
    cmd = [
        "claude", "-p", prompt,
        "--model", model,
        "--output-format", *fmt,
        "--no-session-persistence",
        "--strict-mcp-config",
        "--setting-sources", "",
        "--tools", tools,
    ]  # fmt: skip
    if tools:
        cmd += ["--allowedTools", tools]
    if effort:
        cmd += ["--effort", effort]
    try:
        out = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=TIMEOUT,
            check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        # Keep what a run that hit the limit read; it is the one most worth a look.
        if transcript and exc.stdout:
            partial = exc.stdout
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            transcript.write_text(partial, encoding="utf-8")
        raise
    if transcript:
        transcript.write_text(out.stdout, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError(f"claude exited {out.returncode}: {out.stderr[-2000:]}")
    if not transcript:
        return json.loads(out.stdout)
    events = [json.loads(line) for line in out.stdout.splitlines() if line.strip()]
    return next(e for e in reversed(events) if e.get("type") == "result")


def _shell_read(command: str) -> str | None:
    """The one file a lone `sed`/`cat`/`head`/`tail`/`nl` command prints, or None: a
    second command (on a new line too), a comment or a second file makes it None."""
    words = command.split()
    if not words or words[0] not in _READERS or any(c in command for c in ";|&<>`$#\n"):
        return None
    operands: list[str] = []
    takes_value = False
    for word in words[1:]:
        if takes_value:
            takes_value = False
        elif word in ("-n", "-c") and words[0] in ("head", "tail"):
            takes_value = True
        elif not word.startswith("-"):
            operands.append(word)
    if words[0] == "sed":
        operands = operands[1:]  # the first is its program
    return operands[0].strip("'\"") if len(operands) == 1 else None


def reads(transcript: Path, root: Path | None = None) -> dict:
    """What a review read: each file the Read tool opened, or a lone shell command
    printed, with the characters it returned; other tools' output by tool; and the
    run's token totals from its result event. Kept to judge what the reviewer's
    guides cost; a file read twice counts twice. A file read inside a longer shell
    command counts under `(Bash)`, so a per-file figure is a lower bound. Paths under
    `root` are made relative to it, so a Read and a shell read of a file add up."""
    files: dict[str, int] = {}
    pending: dict[str, str] = {}
    totals: dict = {}
    for line in transcript.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("type") == "result":
            # The streamed assistant events carry only partial output counts.
            totals = event.get("usage") or {}
        message = event.get("message") or {}
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if part.get("type") == "tool_use":
                name = part.get("name", "?")
                args = part.get("input", {})
                # Other tools' output is pooled under the tool's name.
                if name == "Read":
                    key = args.get("file_path")
                elif name == "Bash":
                    key = _shell_read(args.get("command", ""))
                else:
                    key = None
                pending[part["id"]] = key or f"({name})"
            elif (
                part.get("type") == "tool_result" and part.get("tool_use_id") in pending
            ):
                body = part.get("content")
                if isinstance(body, list):
                    body = "".join(b.get("text", "") for b in body)
                path = pending.pop(part["tool_use_id"])
                if not path.startswith("("):
                    # Lexically, so `./x` and `a/../x` land on `x`; `/` on every OS.
                    path = posixpath.normpath(path.replace("\\", "/"))
                    base = root.as_posix() if root else None
                    if base and PurePosixPath(path).is_relative_to(base):
                        path = str(PurePosixPath(path).relative_to(base))
                files[path] = files.get(path, 0) + len(body or "")
    usage = {
        key: totals.get(field, 0)
        for key, field in (
            ("input", "input_tokens"),
            ("cache_read", "cache_read_input_tokens"),
            ("cache_write", "cache_creation_input_tokens"),
            ("output", "output_tokens"),
        )
    }
    return {"files": files, "usage": usage}


def review(
    case: Case, out: Path, model: str, effort: str | None = None, install: bool = False
) -> None:
    work = out / case.id
    work.mkdir(parents=True, exist_ok=True)
    repo = prepare(case, work, install)
    env = dict(os.environ)
    env["PATH"] = f"{work / 'bin'}{os.pathsep}{env['PATH']}"
    if install:
        env["PATH"] = f"{repo / '.venv' / 'bin'}{os.pathsep}{env['PATH']}"
        env["VIRTUAL_ENV"] = str(repo / ".venv")
    # `--setting-sources ""` already keeps the old head's SessionStart hook from
    # loading; this keeps it a no-op should a run load project settings again.
    env["CLAUDE_CODE_REMOTE"] = "false"
    # Without a token `gh api` and the like fail too, not just the stubbed command.
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN"):
        env.pop(name, None)
    started = time.monotonic()
    result = claude(
        REVIEW_PROMPT.format(pr=case.pr, body=case.body),
        model=model, cwd=repo, tools=REVIEW_TOOLS, env=env, effort=effort,
        transcript=work / "transcript.jsonl",
    )  # fmt: skip
    # The review first, so an event `reads` cannot parse does not lose it.
    (work / "review.md").write_text(result.get("result", ""), encoding="utf-8")
    read = reads(work / "transcript.jsonl", repo)
    (work / "reads.json").write_text(json.dumps(read, indent=2) + "\n")
    meta = {
        "case": case.id,
        "pr": case.pr,
        "head": case.head,
        "model": model,
        "effort": effort,
        "installed": install,
        "tools": REVIEW_TOOLS,
        "skill": skill_version(),
        "seconds": round(time.monotonic() - started),
        "cost_usd": result.get("total_cost_usd"),
        "turns": result.get("num_turns"),
        "is_error": result.get("is_error"),
    }
    (work / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    shutil.rmtree(repo)


def judge(case: Case, out: Path, model: str) -> dict:
    work = out / case.id
    text = (work / "review.md").read_text(encoding="utf-8")
    result = claude(
        JUDGE_PROMPT.format(
            files=", ".join(case.files), bug=case.bug, caught_if=case.caught_if,
            review=text,
        ),
        model=model, cwd=work, tools="", env=dict(os.environ),
    )  # fmt: skip
    raw = result.get("result", "").strip()
    start, end = raw.find("{"), raw.rfind("}")
    try:
        verdict = json.loads(raw[start : end + 1])
    except ValueError:
        verdict = {
            "caught": "error",
            "finding": "",
            "severity": "",
            "reason": raw[:300],
        }
    verdict["judge_model"] = model
    (work / "judge.json").write_text(json.dumps(verdict, indent=2) + "\n")
    return verdict


def summary(cases: list[Case], out: Path) -> str:
    lines = [
        "| Case | PR | Caught | Finding | Cost (USD) | Minutes |",
        "|---|---|---|---|---|---|",
    ]
    score = 0.0
    unscored = []
    turns = guides = contributing = 0
    for case in cases:
        work = out / case.id
        meta = json.loads((work / "meta.json").read_text())
        turns += meta.get("turns") or 0
        if (work / "reads.json").exists():
            files = json.loads((work / "reads.json").read_text())["files"]
            guides += sum(n for f, n in files.items() if f.startswith(GUIDES))
            contributing += files.get("CONTRIBUTING.md", 0)
        verdict = json.loads((work / "judge.json").read_text())
        if verdict["caught"] not in ("yes", "partial", "no"):
            unscored.append(case.id)
        score += {"yes": 1.0, "partial": 0.5}.get(verdict["caught"], 0.0)
        finding = " ".join(
            filter(None, (verdict.get("finding"), verdict.get("severity")))
        )
        cost = meta.get("cost_usd")
        cost_text = "?" if cost is None else f"{cost:.2f}"
        lines.append(
            f"| {case.id} | #{case.pr} | {verdict['caught']} | {finding or '-'} | "
            f"{cost_text} | {meta['seconds'] // 60} |"
        )
    lines.append("")
    lines.append(f"Score: {score:g} of {len(cases)} (yes = 1, partial = 0.5).")
    lines.append(
        f"Turns: {turns}. Guide characters read: {guides}, of them "
        f"`CONTRIBUTING.md`: {contributing}."
    )
    if unscored:
        lines.append(
            f"Not scored (judge reply unreadable; rerun `judge`): {', '.join(unscored)}."
        )
    text = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(text)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list the cases")
    for name in ("run", "judge"):
        p = sub.add_parser(name, help=f"{name} the cases")
        p.add_argument("--out", type=Path, required=True, help="results directory")
        p.add_argument("--case", action="append", help="a case id (default: all)")
        p.add_argument("--judge-model", default=JUDGE_MODEL)
        if name == "run":
            p.add_argument("--model", default=REVIEW_MODEL)
            p.add_argument("--effort", help="the reviewer's effort level")
            p.add_argument(
                "--install", action="store_true",
                help="install the project's environment at the PR's lockfile first",
            )  # fmt: skip
            p.add_argument("--jobs", type=int, default=1, help="reviews at a time")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.command == "list":
        for c in cases:
            print(f"{c.id:45} #{c.pr}  fixed by {c.fixed_by}")
        return 0
    if args.case:
        unknown = set(args.case) - {c.id for c in cases}
        if unknown:
            parser.error(f"unknown case: {', '.join(sorted(unknown))}")
        cases = [c for c in cases if c.id in args.case]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    def one(case: Case) -> None:
        if args.command == "run":
            review(case, out, args.model, args.effort, args.install)
        verdict = judge(case, out, args.judge_model)
        print(f"{case.id}: {verdict['caught']}", flush=True)

    jobs = getattr(args, "jobs", 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        failed = False
        for case, fut in [(c, pool.submit(one, c)) for c in cases]:
            try:
                fut.result()
            except Exception as exc:  # noqa: BLE001 - report each case, keep going
                print(f"{case.id}: failed: {exc}", file=sys.stderr)
                failed = True
    if not failed:
        print(summary(cases, out), end="")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
