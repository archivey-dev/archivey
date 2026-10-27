#!/usr/bin/env python3
"""Do the mechanical parts of a release, so a patch release takes minutes.

The steps a person still decides are the CHANGELOG text and when to merge. Everything
else is here. A release is four commands, run from a clean, up-to-date ``main``:

1. ``notes`` prints the merged pull requests since the last tag, as raw material for
   the CHANGELOG entry, and says whether the release can be a patch: it compares the
   public API at the tag with ``HEAD`` (``scripts/api_surface.py``) and lists the
   merged pull requests labelled ``needs-minor``. Write the entry under
   ``## [Unreleased]`` in a normal PR, or as the first commit of step 2.
2. ``start X.Y.Z`` sets the version in both pyproject files (and the ``archivey-cli``
   pin), refreshes ``uv.lock``, moves the ``[Unreleased]`` text under a dated
   ``[X.Y.Z]`` heading with its compare links, commits on ``release/vX.Y.Z``, pushes,
   opens the release pull request and starts the TestPyPI dry run and the
   ``RELEASE_GATE_WORKFLOWS`` on that branch.
3. After the release pull request merges: ``tag X.Y.Z`` checks that each release gate
   passed on the pull request's last commit, then creates the GitHub release
   ``vX.Y.Z`` on that pull request's merge commit, with the CHANGELOG section as its
   body. Pull requests merged after it are not in the release. The tag starts
   ``publish.yml``, which uploads to PyPI. Run it with your own ``gh`` login: agent
   sessions cannot push tags or create releases.
4. ``finish`` sets ``main`` to the next ``.dev0`` version in a small pull request, so
   installs from ``main`` stay distinguishable from the release.

``--dry-run`` on any step prints the commands and changes nothing. The text edits are
pure functions, tested in ``tests/test_release_script.py``.

Stdlib only; GitHub is reached through the ``gh`` command.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_PYPROJECT = ROOT / "pyproject.toml"
CLI_PYPROJECT = ROOT / "packages" / "archivey-cli" / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
REPO_URL = "https://github.com/archivey-dev/archivey"

#: The label on a merged pull request whose change needs a minor release although the
#: API surface file does not show it, such as a call that now gives a different result.
NEEDS_MINOR_LABEL = "needs-minor"

#: The versions this script writes: a final release, a pre-release, or a ``.devN``.
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+((a|b|rc)\d+)?(\.dev\d+)?$")
_FINAL_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
_PRE_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)(?:a|b|rc)\d+$")
_PROJECT_VERSION_RE = re.compile(r'^(version = ")([^"]+)(")$', re.MULTILINE)
_PIN_RE = re.compile(r'("archivey\[recommended\]==)([^"]+)(")')
_UNRELEASED_RE = re.compile(r"^## \[Unreleased\][^\n]*\n", re.MULTILINE)
_HEADING_RE = re.compile(r"^## \[", re.MULTILINE)
_TRAILER_RE = re.compile(r"^(<!--|\[[^\]]+\]: )", re.MULTILINE)
_LINK_RE = re.compile(r"^\[[^\]]+\]: ", re.MULTILINE)

#: The test workflows that do not run in full on every pull request and every push to
#: main. ``start`` runs each one on the release branch and ``tag`` refuses until each one
#: is green on the release pull request's last commit. That covers the release branch's
#: content. A squash merge also brings in whatever reached ``main`` while the release
#: pull request was open, which only ``ci.yml`` has seen; when that matters, merge
#: ``main`` into the release branch and run the gates again before merging.
#: ``benchmark-wall.yml`` is left out: the release checklist §2 runs
#: the benchmark by hand. ``tests/test_release_script.py`` fails when a scheduled
#: workflow is neither here nor in its list of workflows that are not gates.
RELEASE_GATE_WORKFLOWS = (
    "accelerator-crash-search.yml",
    "accelerator-fuzz-soak.yml",
    # Its pull request mode runs each target for 1 to 3 seconds; a dispatched run uses
    # the nightly budgets, about ten times longer.
    "atheris-fuzz.yml",
    "rapidgzip-resume-stress.yml",
    # Pull requests skip PyPy's core-only suite; a dispatched run includes it.
    "ci.yml",
)


class ReleaseError(Exception):
    """A precondition failed; the message says what to fix."""


def check_version(version: str) -> str:
    if not VERSION_RE.match(version):
        raise ReleaseError(
            f"{version!r} is not a version like 0.2.1, 0.3.0rc1 or 0.2.2.dev0"
        )
    return version


def project_version(pyproject_text: str) -> str:
    """The first ``version = "..."`` line, which is ``[project].version`` in both files."""
    match = _PROJECT_VERSION_RE.search(pyproject_text)
    if match is None:
        raise ReleaseError("no version line in pyproject.toml")
    return match.group(2)


def set_project_version(pyproject_text: str, version: str) -> str:
    """Replace ``[project].version``, and the ``archivey[recommended]==`` pin if present."""
    text, count = _PROJECT_VERSION_RE.subn(
        rf"\g<1>{version}\g<3>", pyproject_text, count=1
    )
    if count != 1:
        raise ReleaseError("no version line in pyproject.toml")
    return _PIN_RE.sub(rf"\g<1>{version}\g<3>", text)


def next_dev_version(version: str) -> str:
    """The ``.dev0`` that follows a release: 0.2.0 -> 0.2.1.dev0, 0.3.0rc1 -> 0.3.0rc2.dev0.

    After a pre-release, the next pre-release number keeps the order right: PEP 440 sorts
    ``0.3.0.dev0`` before ``0.3.0rc1``, but ``0.3.0rc2.dev0`` after it.
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$", check_version(version))
    if match is None:
        raise ReleaseError(f"{version!r} is a .dev version, not a release")
    major, minor, patch, pre, pre_number = match.groups()
    if pre:
        return f"{major}.{minor}.{patch}{pre}{int(pre_number) + 1}.dev0"
    return f"{major}.{minor}.{int(patch) + 1}.dev0"


def next_release_version(previous_tag: str | None, needs_minor: bool) -> str:
    """The release after the final tag ``previous_tag``: v0.2.0 -> 0.2.1, or 0.3.0.

    Before 1.0 a minor release is where breaking changes go, so nothing here suggests a
    major release. ``cmd_notes`` passes the last final tag, never a pre-release.
    """
    if previous_tag is None:
        return "0.1.0"
    match = _FINAL_TAG_RE.match(previous_tag)
    if match is None:
        raise ReleaseError(f"{previous_tag!r} is not a final release tag like v0.2.0")
    major, minor, patch = (int(part) for part in match.groups())
    if needs_minor:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _pre_release_floor(tag: str | None) -> str | None:
    """``X.Y.Z`` when ``tag`` is a pre-release ``vX.Y.Z(a|b|rc)N``; otherwise None."""
    match = _PRE_TAG_RE.match(tag or "")
    return match.group(1) if match else None


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def next_release_line(
    final: str, newest: str | None, verdict: str, labelled: list[str] | str
) -> str:
    """The last line of ``notes``: the next version, whether it is a patch, and why.

    ``final`` is the last final tag the API was measured from, ``newest`` the newest tag
    of any kind, ``verdict`` the API report's ``minor``/``patch``/``none``, and
    ``labelled`` the ``needs-minor`` pull requests or why they could not be listed.
    The version is decided once (the bucket, then a published pre-release as a floor),
    and the sentence says whatever decided it.
    """
    reasons = []
    if verdict == "minor":
        reasons.append("the public API changed")
    if isinstance(labelled, list) and labelled:
        reasons.append(f"{len(labelled)} merged pull request(s) are labelled")
    version = next_release_version(final, bool(reasons))
    floor = _pre_release_floor(newest)
    if floor is not None and _version_key(floor) > _version_key(version):
        version = floor
        reasons.append(f"{newest} is already out")
    base = _version_key(next_release_version(final, False))
    chosen = _version_key(version)
    kind = (
        "major" if chosen[0] > base[0] else "minor" if chosen[1] > base[1] else "patch"
    )
    why = f": {'; '.join(reasons)}" if reasons else ""
    if kind != "patch":
        return f"This is a {kind} release, {version}{why}."
    if isinstance(labelled, str):
        return (
            f"The API allows a patch release, {version}{why}; check the labels by hand."
        )
    return f"This can be a patch release, {version}{why}."


def _link_section_start(text: str) -> int:
    """Where the trailing link definitions start.

    Everything is measured from the last ``## [`` heading: the link section starts after
    an HTML comment that follows that heading (its example links stay inside it), else
    at the first link definition after it, else at the end of the file.
    """
    last = max((m.end() for m in _HEADING_RE.finditer(text)), default=0)
    end = text.rfind("-->")
    if end > last:
        return end + 3
    link = _LINK_RE.search(text, last)
    return link.start() if link else len(text)


def _section_end(text: str, start: int) -> int:
    """Where the section starting at ``start`` ends.

    That is the next ``## [`` heading, or for the last section the first trailing
    comment or link definition.
    """
    following = _HEADING_RE.search(text, start)
    if following:
        return following.start()
    trailer = _TRAILER_RE.search(text, start)
    return trailer.start() if trailer else len(text)


def changelog_for_release(
    text: str, version: str, previous_tag: str | None, date: str
) -> str:
    """Move the ``[Unreleased]`` text under ``## [version] - date`` and fix the links.

    If a ``## [version] - Unreleased`` heading already exists (the 0.2.0 entry was
    written ahead of time), it gets the date instead, and ``[Unreleased]`` must be
    empty. Otherwise ``[Unreleased]`` must hold the entry.
    """
    unreleased = _UNRELEASED_RE.search(text)
    if unreleased is None:
        raise ReleaseError("CHANGELOG.md has no '## [Unreleased]' heading")
    body_start = unreleased.end()
    body_end = _section_end(text, body_start)
    body = text[body_start:body_end].strip()

    prewritten = re.compile(
        rf"^## \[{re.escape(version)}\] - Unreleased$", re.MULTILINE
    )
    if prewritten.search(text):
        if body:
            raise ReleaseError(
                f"CHANGELOG.md has text under [Unreleased] and a prewritten [{version}] entry;"
                " move the text into one of them"
            )
        text = prewritten.sub(f"## [{version}] - {date}", text, count=1)
    else:
        if not body:
            raise ReleaseError(
                "CHANGELOG.md has nothing under [Unreleased]; write the entry first"
                " (`scripts/release.py notes` lists the merged pull requests)"
            )
        text = (
            text[:body_start]
            + f"\n## [{version}] - {date}\n\n{body}\n\n"
            + text[body_end:].lstrip("\n")
        )
    return _set_links(text, version, previous_tag)


def _set_links(text: str, version: str, previous_tag: str | None) -> str:
    tag = f"v{version}"
    unreleased_link = f"[Unreleased]: {REPO_URL}/compare/{tag}...HEAD"
    if previous_tag:
        version_link = f"[{version}]: {REPO_URL}/compare/{previous_tag}...{tag}"
    else:
        version_link = f"[{version}]: {REPO_URL}/releases/tag/{tag}"

    start = _link_section_start(text)
    head, links = text[:start], text[start:]
    lines = [line for line in links.strip("\n").splitlines() if line.strip()]
    lines = [
        line
        for line in lines
        if not line.startswith("[Unreleased]:") and not line.startswith(f"[{version}]:")
    ]
    lines = [unreleased_link, version_link, *lines]
    return head.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"


def changelog_section(text: str, version: str) -> str:
    """The body of ``## [version]``, for the GitHub release notes."""
    heading = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n", text, re.MULTILINE)
    if heading is None:
        raise ReleaseError(f"CHANGELOG.md has no [{version}] entry")
    end = _section_end(text, heading.end())
    return text[heading.end() : end].strip() + "\n"


# ── Side effects ─────────────────────────────────────────────────────────────────────


class Runner:
    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run

    def run(self, *cmd: str, input_text: str | None = None) -> None:
        print("+ " + shlex.join(cmd), flush=True)
        if not self.dry_run:
            subprocess.run(cmd, cwd=ROOT, check=True, text=True, input=input_text)

    def read(self, *cmd: str) -> str | None:
        """The output of a command that changes nothing; a dry run prints it and returns None."""
        if self.dry_run:
            print("+ " + shlex.join(cmd), flush=True)
            return None
        # stderr goes to the terminal, so a failing ``gh`` says why.
        return subprocess.run(
            cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True
        ).stdout

    def write(self, path: Path, text: str) -> None:
        print(f"+ write {path.relative_to(ROOT).as_posix()}", flush=True)
        if not self.dry_run:
            path.write_text(text, encoding="utf-8")


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def _previous_tag() -> str | None:
    try:
        return _git("describe", "--tags", "--abbrev=0", "--match", "v*")
    except subprocess.CalledProcessError:
        return None


def _previous_final_tag() -> str | None:
    """The newest ``vX.Y.Z`` tag reachable from ``HEAD``, skipping pre-releases."""
    tags = _git("tag", "--list", "v*", "--merged", "HEAD", "--sort=-v:refname")
    for tag in tags.splitlines():
        if _FINAL_TAG_RE.match(tag):
            return tag
    return None


def _require_clean_main() -> None:
    if _git("status", "--porcelain"):
        raise ReleaseError("the working tree has changes; commit or stash them first")
    if _git("rev-parse", "--abbrev-ref", "HEAD") != "main":
        raise ReleaseError("check out main first")
    _git("fetch", "origin", "main")
    if _git("rev-parse", "HEAD") != _git("rev-parse", "origin/main"):
        raise ReleaseError("main is not at origin/main; run `git pull --ff-only` first")


def _versioned_pyprojects(version: str) -> dict[Path, str]:
    """Both pyproject.toml files with ``version`` set, computed before anything is written."""
    return {
        path: set_project_version(path.read_text(encoding="utf-8"), version)
        for path in (ROOT_PYPROJECT, CLI_PYPROJECT)
    }


def _write_versions(runner: Runner, pyprojects: dict[Path, str]) -> None:
    for path, text in pyprojects.items():
        runner.write(path, text)
    runner.run("uv", "lock")


def _gate_dispatch(workflow: str, branch: str) -> list[str]:
    return ["gh", "workflow", "run", workflow, "--ref", branch]


def gate_problems(runs: list[dict[str, str]], head_sha: str) -> str | None:
    """Why the dispatched runs of one gate do not pass ``head_sha``, or None if they do.

    ``runs`` is ``gh run list --json`` output, newest first. Only a run on ``head_sha``
    counts: a commit pushed to the release pull request after the dispatch needs a new
    run. The newest run on it decides, so a red run after a green one holds the release:
    most gates hunt for crashes, and a second run that finds one is the news.
    """
    on_head = [run for run in runs if run.get("headSha") == head_sha]
    if not on_head:
        return f"no run on {head_sha[:12]}"
    latest = on_head[0]
    if latest.get("status") == "completed" and latest.get("conclusion") == "success":
        return None
    if latest.get("status") != "completed":
        return f"still running ({latest.get('url', '')})"
    return f"{latest.get('conclusion') or 'failed'} ({latest.get('url', '')})"


def _check_gates(runner: Runner, branch: str) -> str:
    """Refuse unless each release gate passed on the release pull request's last commit.

    Returns the pull request's merge commit, which is what the tag points at; a dry run
    returns a placeholder for it.
    """
    pr = runner.read(
        "gh", "pr", "view", branch, "--json", "headRefOid,mergeCommit"
    )  # fmt: skip
    head = merge = None
    if pr is not None:
        data = json.loads(pr)
        head = data["headRefOid"]
        merge = (data.get("mergeCommit") or {}).get("oid")
        if not merge:
            raise ReleaseError(f"the pull request from {branch} has not merged yet")
    failing: list[str] = []
    for workflow in RELEASE_GATE_WORKFLOWS:
        out = runner.read(
            "gh", "run", "list", "--workflow", workflow, "--branch", branch,
            "--event", "workflow_dispatch", "--limit", "20",
            "--json", "headSha,status,conclusion,url",
        )  # fmt: skip
        if head is None or out is None:  # a dry run
            continue
        problem = gate_problems(json.loads(out), head)
        if problem is not None:
            failing.append(
                f"  {workflow}: {problem}\n    {shlex.join(_gate_dispatch(workflow, branch))}"
            )
    if failing:
        # The branch is usually deleted when its pull request merges, and a dispatch
        # needs a branch, so put it back at the gated commit first.
        restore = shlex.join(["git", "push", "origin", f"{head}:refs/heads/{branch}"])
        raise ReleaseError(
            f"the newest run of these release gates is not green on the last commit of"
            f" {branch} ({head}). If {branch} was deleted on merge, restore it with"
            f" `{restore}`. Then start each gate with the command below, wait for it,"
            " and run tag again:\n" + "\n".join(failing)
        )
    return merge or "<release-PR-merge-commit>"


def _api_change(previous: str) -> tuple[str, str]:
    """(``minor``, ``patch`` or ``none``; the report) for the public API since ``previous``.

    Both sides are written by this checkout's ``scripts/api_surface.py``, the old one from
    a temporary worktree of the tag, so a change in the script's format between releases
    does not show as an API change. Each side reads its own tree's ``docs/api.md`` for the
    names of a module without ``__all__``. The tag's side takes its list of public
    modules from the tag's ``dev-docs/api-surface.txt`` (``--modules-from``), so a module
    made public since the tag shows as added; ``HEAD`` uses the script's own list. A tag
    older than that file is measured with this checkout's list.
    """
    script = ROOT / "scripts" / "api_surface.py"
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "tree"
        _git("worktree", "add", "--detach", str(tree), previous)
        try:
            old_cmd = [sys.executable, "-I", str(script), "--src", str(tree / "src")]
            old_surface = tree / "dev-docs" / "api-surface.txt"
            if old_surface.exists():
                old_cmd += ["--modules-from", str(old_surface)]
            old = subprocess.run(
                old_cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True
            ).stdout
        finally:
            _git("worktree", "remove", "--force", str(tree))
        old_file = Path(tmp) / "old.txt"
        old_file.write_text(old, encoding="utf-8")
        out = subprocess.run(
            [sys.executable, "-I", str(script), "--src", str(ROOT / "src"),
             "--compare-to", str(old_file)],
            cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
        ).stdout  # fmt: skip
    verdict, _, text = out.partition("\n")
    return verdict, text.rstrip()


def _needs_minor_prs(previous: str) -> list[str] | str:
    """Merged pull requests since ``previous`` labelled ``needs-minor``, or why not.

    A string says why the list cannot be trusted: ``gh`` is missing or fails, or the
    label does not exist, which ``gh pr list --label`` answers with an empty list.
    """
    since = _git("log", "-1", "--format=%cI", previous)
    try:
        labels = subprocess.run(
            ["gh", "label", "list", "--search", NEEDS_MINOR_LABEL,
             "--json", "name", "--limit", "100"],
            cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
        ).stdout  # fmt: skip
        # With no match, ``gh label list --json`` prints nothing rather than ``[]``.
        names = {label["name"] for label in json.loads(labels or "[]")}
        if NEEDS_MINOR_LABEL not in names:
            return (
                f"The `{NEEDS_MINOR_LABEL}` label does not exist on the repository;"
                " create it so pull requests can carry it."
            )
        out = subprocess.run(
            ["gh", "pr", "list", "--state", "merged", "--base", "main",
             "--label", NEEDS_MINOR_LABEL, "--search", f"merged:>{since}",
             "--limit", "200", "--json", "number,title"],
            cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
        ).stdout  # fmt: skip
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return (
            f"Could not list the `{NEEDS_MINOR_LABEL}` pull requests (is `gh` set up?)."
        )
    return [f"#{pr['number']} {pr['title']}" for pr in json.loads(out or "[]")]


def cmd_notes(_args: argparse.Namespace) -> None:
    previous = _previous_tag()
    since = f"{previous}..HEAD" if previous else "HEAD"
    print(f"Merged since {previous or 'the first commit'}:\n")
    print(_git("log", "--first-parent", "--format=- %s", since))
    # Patch or minor is measured from the last final release: after 0.3.0rc1, the
    # question is what 0.3.0 changes against 0.2.x.
    final = _previous_final_tag()
    if final is None:
        print("\nNo final release yet, so there is no API to compare against.")
        return
    verdict, api_report = _api_change(final)
    print(f"\nPublic API since {final}:\n{api_report}")
    labelled = _needs_minor_prs(final)
    if isinstance(labelled, str):
        print(f"\n{labelled}")
    elif labelled:
        print(f"\nMerged pull requests labelled `{NEEDS_MINOR_LABEL}`:")
        print("\n".join(f"- {pr}" for pr in labelled))
    print("\n" + next_release_line(final, previous, verdict, labelled))


def cmd_start(args: argparse.Namespace) -> None:
    version = check_version(args.version)
    if ".dev" in version:
        raise ReleaseError("a release version has no .dev suffix")
    runner = Runner(args.dry_run)
    if not args.dry_run:
        _require_clean_main()
    # Everything that can refuse runs before the first change, so a refusal leaves
    # main as it was.
    pyprojects = _versioned_pyprojects(version)
    changelog = changelog_for_release(
        CHANGELOG.read_text(encoding="utf-8"),
        version,
        _previous_tag(),
        str(dt.date.today()),
    )
    branch = f"release/v{version}"
    runner.run("git", "switch", "-c", branch)
    _write_versions(runner, pyprojects)
    runner.write(CHANGELOG, changelog)
    runner.run("git", "add", "pyproject.toml", "packages/archivey-cli/pyproject.toml")
    runner.run("git", "add", "uv.lock", "CHANGELOG.md")
    runner.run("git", "commit", "-m", f"Release {version}")
    runner.run("git", "push", "-u", "origin", branch)
    body = (
        f"Sets the version to {version} in both packages and dates the CHANGELOG entry.\n\n"
        "Started by `scripts/release.py start`. The TestPyPI dry run and the release"
        " gates (`RELEASE_GATE_WORKFLOWS` in the script) run on this branch. Merge when"
        " they and CI are green. After merge: `scripts/release.py tag"
        f" {version}`, then `scripts/release.py finish`.\n"
    )
    runner.run(
        "gh", "pr", "create", "--base", "main", "--head", branch,
        "--title", f"Release {version}", "--body", body,
    )  # fmt: skip
    if not args.no_testpypi:
        runner.run(
            "gh",
            "workflow",
            "run",
            "publish.yml",
            "--ref",
            branch,
            "-f",
            "target=testpypi",
        )
    for workflow in RELEASE_GATE_WORKFLOWS:
        runner.run(*_gate_dispatch(workflow, branch))
    print(
        "\nNext: wait for CI, the TestPyPI run and the release gates, read the CHANGELOG"
        f" entry, merge, then run `scripts/release.py tag {version}`."
    )


def cmd_tag(args: argparse.Namespace) -> None:
    version = check_version(args.version)
    runner = Runner(args.dry_run)
    if not args.dry_run:
        _require_clean_main()
    for path in (ROOT_PYPROJECT, CLI_PYPROJECT):
        current = project_version(path.read_text(encoding="utf-8"))
        if current != version:
            raise ReleaseError(
                f"{path.relative_to(ROOT).as_posix()} is at version {current}, not {version};"
                " merge the release PR"
            )
    notes = changelog_section(CHANGELOG.read_text(encoding="utf-8"), version)
    target = _check_gates(runner, args.branch or f"release/v{version}")
    pre = re.search(r"(a|b|rc)\d+$", version) is not None
    cmd = ["gh", "release", "create", f"v{version}", "--target", target]
    cmd += ["--title", f"archivey {version}", "--notes-file", "-"]
    if pre:
        cmd.append("--prerelease")
    runner.run(*cmd, input_text=notes)
    print(
        "\nThe tag starts publish.yml (Actions, Publish), which uploads to PyPI after the"
        " `pypi` environment approval. Then run `scripts/release.py finish`."
    )


def cmd_finish(args: argparse.Namespace) -> None:
    runner = Runner(args.dry_run)
    if not args.dry_run:
        _require_clean_main()
    current = project_version(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    dev = args.version or next_dev_version(current)
    check_version(dev)
    if ".dev" not in dev:
        raise ReleaseError(f"finish sets a .dev version, not {dev!r}")
    pyprojects = _versioned_pyprojects(dev)
    branch = f"release/v{dev}"
    runner.run("git", "switch", "-c", branch)
    _write_versions(runner, pyprojects)
    runner.run(
        "git",
        "add",
        "pyproject.toml",
        "packages/archivey-cli/pyproject.toml",
        "uv.lock",
    )
    runner.run("git", "commit", "-m", f"Start {dev} after the {current} release")
    runner.run("git", "push", "-u", "origin", branch)
    runner.run(
        "gh", "pr", "create", "--base", "main", "--head", branch,
        "--title", f"Start {dev}",
        "--body", f"Moves main past the {current} release, so installs from main show a"
        " .dev version.\n",
    )  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print, change nothing")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "notes",
        help="list merged pull requests since the last tag, and say patch or minor",
    )
    start = sub.add_parser("start", help="open the release pull request")
    start.add_argument("version")
    start.add_argument(
        "--no-testpypi", action="store_true", help="skip the TestPyPI dry run"
    )
    tag = sub.add_parser(
        "tag", help="create the GitHub release and tag after the merge"
    )
    tag.add_argument("version")
    tag.add_argument(
        "--branch",
        help="the release pull request's branch, if `start` did not open it"
        " (default: release/vVERSION)",
    )
    finish = sub.add_parser("finish", help="move main to the next .dev0 version")
    finish.add_argument("version", nargs="?", help="default: the next patch .dev0")
    args = parser.parse_args(argv)
    commands = {
        "notes": cmd_notes,
        "start": cmd_start,
        "tag": cmd_tag,
        "finish": cmd_finish,
    }
    try:
        commands[args.command](args)
    except ReleaseError as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"release: command failed: {shlex.join(exc.cmd)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
