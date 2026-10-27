"""The text edits `scripts/release.py` makes, exercised without git or GitHub.

A wrong edit here ships: a version that disagrees between the two packages fails the
publish job after the tag, and a CHANGELOG entry moved to the wrong place becomes the
GitHub release notes. So the edits are pinned here, including on the real files.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release.py"

_spec = importlib.util.spec_from_file_location("release_script", SCRIPT)
assert _spec is not None and _spec.loader is not None
release = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = release
_spec.loader.exec_module(release)

URL = release.REPO_URL


@pytest.mark.parametrize(
    "version", ["0.2.1", "1.0.0", "0.3.0rc1", "0.3.0b2", "0.2.1.dev0"]
)
def test_accepted_versions(version: str) -> None:
    assert release.check_version(version) == version


@pytest.mark.parametrize("version", ["v0.2.1", "0.2", "0.2.1-rc1", "0.2.1.post1", ""])
def test_refused_versions(version: str) -> None:
    with pytest.raises(release.ReleaseError):
        release.check_version(version)


@pytest.mark.parametrize(
    ("released", "dev"),
    [
        ("0.2.0", "0.2.1.dev0"),
        ("0.2.9", "0.2.10.dev0"),
        ("0.3.0rc1", "0.3.0rc2.dev0"),
        ("1.0.0a1", "1.0.0a2.dev0"),
    ],
)
def test_next_dev_version(released: str, dev: str) -> None:
    assert release.next_dev_version(released) == dev


def test_next_dev_version_refuses_a_dev_version() -> None:
    with pytest.raises(release.ReleaseError):
        release.next_dev_version("0.2.1.dev0")


def test_set_project_version_on_both_real_files() -> None:
    for path in (release.ROOT_PYPROJECT, release.CLI_PYPROJECT):
        text = path.read_text(encoding="utf-8")
        new = release.set_project_version(text, "9.8.7")
        assert release.project_version(new) == "9.8.7"
        # Only the version line and the pin change.
        changed = [
            (a, b)
            for a, b in zip(text.splitlines(), new.splitlines(), strict=True)
            if a != b
        ]
        assert 1 <= len(changed) <= 2
    cli = release.set_project_version(
        release.CLI_PYPROJECT.read_text(encoding="utf-8"), "9.8.7"
    )
    assert '"archivey[recommended]==9.8.7"' in cli


def test_set_project_version_leaves_dependency_floors_alone() -> None:
    text = (
        'version = "0.2.0"\ndependencies = ["pyppmd>=1.3.1"]\n[tool.x]\nversion = "1"\n'
    )
    assert release.set_project_version(text, "0.2.1") == (
        'version = "0.2.1"\ndependencies = ["pyppmd>=1.3.1"]\n[tool.x]\nversion = "1"\n'
    )


CHANGELOG = f"""# Changelog

Intro.

## [Unreleased]

### Fixed

- Fixed 3 bugs in ZIP reading.

## [0.2.0] - 2026-11-01

First release.

<!--
Example links:
[Unreleased]: https://example.invalid
-->

[Unreleased]: {URL}/compare/v0.2.0...HEAD
[0.2.0]: {URL}/releases/tag/v0.2.0
"""


def test_changelog_moves_unreleased_under_the_new_heading() -> None:
    out = release.changelog_for_release(CHANGELOG, "0.2.1", "v0.2.0", "2026-11-20")
    assert "## [Unreleased]\n\n## [0.2.1] - 2026-11-20\n\n### Fixed\n\n- Fixed 3" in out
    assert "\n## [0.2.0] - 2026-11-01\n" in out
    assert out.endswith(
        f"[Unreleased]: {URL}/compare/v0.2.1...HEAD\n"
        f"[0.2.1]: {URL}/compare/v0.2.0...v0.2.1\n"
        f"[0.2.0]: {URL}/releases/tag/v0.2.0\n"
    )
    # The example inside the comment is not a link definition and stays as it was.
    assert "[Unreleased]: https://example.invalid\n-->" in out


def test_changelog_section_is_the_release_notes() -> None:
    out = release.changelog_for_release(CHANGELOG, "0.2.1", "v0.2.0", "2026-11-20")
    assert (
        release.changelog_section(out, "0.2.1")
        == "### Fixed\n\n- Fixed 3 bugs in ZIP reading.\n"
    )
    assert release.changelog_section(out, "0.2.0") == "First release.\n"


def test_changelog_refuses_an_empty_entry() -> None:
    empty = CHANGELOG.replace("### Fixed\n\n- Fixed 3 bugs in ZIP reading.\n\n", "")
    with pytest.raises(release.ReleaseError, match="nothing under"):
        release.changelog_for_release(empty, "0.2.1", "v0.2.0", "2026-11-20")


def test_changelog_dates_a_prewritten_entry() -> None:
    text = CHANGELOG.replace(
        "### Fixed\n\n- Fixed 3 bugs in ZIP reading.\n\n", ""
    ).replace(
        "## [0.2.0] - 2026-11-01",
        "## [0.3.0] - Unreleased\n\nWritten ahead.\n\n## [0.2.0] - 2026-11-01",
    )
    out = release.changelog_for_release(text, "0.3.0", "v0.2.0", "2026-12-01")
    assert "## [0.3.0] - 2026-12-01\n\nWritten ahead." in out
    assert f"[0.3.0]: {URL}/compare/v0.2.0...v0.3.0\n" in out


def test_changelog_refuses_two_places_for_one_entry() -> None:
    text = CHANGELOG.replace(
        "## [0.2.0] - 2026-11-01", "## [0.3.0] - Unreleased\n\n## [0.2.0] - 2026-11-01"
    )
    with pytest.raises(release.ReleaseError, match="move the text"):
        release.changelog_for_release(text, "0.3.0", "v0.2.0", "2026-12-01")


def test_real_changelog_can_release_0_2_0() -> None:
    """The 0.2.0 entry was written ahead of time; the script only dates it."""
    text = release.CHANGELOG.read_text(encoding="utf-8")
    if "## [0.2.0] - Unreleased" not in text:
        pytest.skip("0.2.0 is released")
    out = release.changelog_for_release(text, "0.2.0", "v0.2.0rc1", "2026-11-01")
    assert "## [0.2.0] - 2026-11-01" in out
    assert out.count("## [Unreleased]") == 1
    assert f"[0.2.0]: {URL}/compare/v0.2.0rc1...v0.2.0\n" in out
    assert release.changelog_section(out, "0.2.0").startswith("First public release.")


def test_dry_run_changes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    before = {
        p: p.read_bytes() for p in (release.ROOT_PYPROJECT, release.CLI_PYPROJECT)
    }
    assert release.main(["--dry-run", "finish", "0.9.9.dev0"]) == 0
    assert {p: p.read_bytes() for p in before} == before
    out = capsys.readouterr().out
    assert "+ git switch -c release/v0.9.9.dev0" in out
    assert "+ gh pr create" in out


def test_start_refuses_before_changing_anything(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty [Unreleased] is refused before the branch or any file is touched."""
    release.CHANGELOG.write_text(
        CHANGELOG.replace("### Fixed\n\n- Fixed 3 bugs in ZIP reading.\n\n", ""),
        encoding="utf-8",
    )
    assert release.main(["--dry-run", "start", "0.9.9"]) == 1
    captured = capsys.readouterr()
    assert "nothing under" in captured.err
    assert "+ " not in captured.out


def test_changelog_without_a_comment_keeps_the_top_of_the_file() -> None:
    text = CHANGELOG.split("<!--", 1)[0] + f"[0.2.0]: {URL}/releases/tag/v0.2.0\n"
    out = release.changelog_for_release(text, "0.2.1", "v0.2.0", "2026-11-20")
    assert out.startswith(text.split("## [Unreleased]", 1)[0])
    assert out.endswith(
        f"[Unreleased]: {URL}/compare/v0.2.1...HEAD\n"
        f"[0.2.1]: {URL}/compare/v0.2.0...v0.2.1\n"
        f"[0.2.0]: {URL}/releases/tag/v0.2.0\n"
    )
    assert "\n\n\n" not in out


def test_changelog_without_a_comment_or_links_appends_them() -> None:
    text = CHANGELOG.split("<!--", 1)[0].rstrip("\n") + "\n"
    out = release.changelog_for_release(text, "0.2.1", "v0.2.0", "2026-11-20")
    assert out.startswith(text.split("## [Unreleased]", 1)[0])
    assert out.endswith(
        "First release.\n\n"
        f"[Unreleased]: {URL}/compare/v0.2.1...HEAD\n"
        f"[0.2.1]: {URL}/compare/v0.2.0...v0.2.1\n"
    )


def _real_changelog_with_entry(with_comment: bool) -> tuple[str, str]:
    text = release.CHANGELOG.read_text(encoding="utf-8")
    if not with_comment:
        start, end = text.rindex("<!--"), text.rindex("-->") + 3
        text = text[:start] + text[end:].lstrip("\n")
    head, rest = text.split("## [Unreleased]\n", 1)
    body = "### Fixed\n\n- Fixed 2 bugs in TAR reading.\n"
    return head + "## [Unreleased]\n\n" + body + "\n" + rest.lstrip("\n"), body


@pytest.mark.parametrize("comment", ["at the end", "none", "at the top"])
def test_real_changelog_shape_survives_any_release(comment: str) -> None:
    """Holds for every future release, unlike the 0.2.0 test above."""
    text, body = _real_changelog_with_entry(comment != "none")
    if comment == "at the top":
        start, end = text.rindex("<!--"), text.rindex("-->") + 3
        block = text[start:end]
        text = text[:start].rstrip("\n") + "\n" + text[end:].lstrip("\n")
        text = text.replace("## [Unreleased]", block + "\n\n## [Unreleased]", 1)
    out = release.changelog_for_release(text, "9.9.9", "v9.9.8", "2030-01-01")
    head = text.split("## [Unreleased]", 1)[0]
    assert out.startswith(head)
    assert out.splitlines()[0] == "# Changelog"
    assert out.count("## [Unreleased]") == 1
    assert "\n\n\n" not in out
    assert release.changelog_section(out, "9.9.9") == body
    assert out.count("\n\n") >= text.count("\n\n")  # no blank line lost
    links = (
        f"[Unreleased]: {URL}/compare/v9.9.9...HEAD\n"
        f"[9.9.9]: {URL}/compare/v9.9.8...v9.9.9\n"
    )
    assert links in out
    assert out.index(links) > out.rindex("## [")


def test_finish_refuses_a_release_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert release.main(["--dry-run", "finish", "0.3.0"]) == 1
    captured = capsys.readouterr()
    assert "not '0.3.0'" in captured.err
    assert "+ " not in captured.out


@pytest.fixture
def fake_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the three files the script edits, outside git, so dry runs can succeed."""
    for name in ("pyproject.toml", "packages/archivey-cli/pyproject.toml"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(
            (ROOT / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "ROOT_PYPROJECT", tmp_path / "pyproject.toml")
    monkeypatch.setattr(
        release, "CLI_PYPROJECT", tmp_path / "packages/archivey-cli/pyproject.toml"
    )
    monkeypatch.setattr(release, "CHANGELOG", tmp_path / "CHANGELOG.md")
    return tmp_path


def _snapshot(root: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_dry_run_start_prints_the_steps_in_order(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(fake_root)
    assert release.main(["--dry-run", "start", "0.2.1"]) == 0
    assert _snapshot(fake_root) == before
    steps = [
        line.split()[1:3] for line in capsys.readouterr().out.splitlines()
        if line.startswith("+ ")
    ]  # fmt: skip
    assert steps == [
        ["git", "switch"],
        ["write", "pyproject.toml"],
        ["write", "packages/archivey-cli/pyproject.toml"],
        ["uv", "lock"],
        ["write", "CHANGELOG.md"],
        ["git", "add"],
        ["git", "add"],
        ["git", "commit"],
        ["git", "push"],
        ["gh", "pr"],
        ["gh", "workflow"],
        *[["gh", "workflow"]] * len(release.RELEASE_GATE_WORKFLOWS),
    ]


def test_dry_run_tag_checks_both_packages(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for path in (release.ROOT_PYPROJECT, release.CLI_PYPROJECT):
        path.write_text(
            release.set_project_version(path.read_text(encoding="utf-8"), "0.2.1"),
            encoding="utf-8",
        )
    release.CHANGELOG.write_text(
        release.changelog_for_release(CHANGELOG, "0.2.1", "v0.2.0", "2026-11-20"),
        encoding="utf-8",
    )
    assert release.main(["--dry-run", "tag", "0.2.1"]) == 0
    out = capsys.readouterr().out
    assert "+ gh release create v0.2.1 --target '<release-PR-merge-commit>'" in out

    cli = release.CLI_PYPROJECT
    cli.write_text(
        release.set_project_version(cli.read_text(encoding="utf-8"), "0.2.0"),
        encoding="utf-8",
    )
    assert release.main(["--dry-run", "tag", "0.2.1"]) == 1
    assert "archivey-cli/pyproject.toml is at version 0.2.0" in capsys.readouterr().err


def test_dry_run_start_dispatches_each_gate_once(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert release.main(["--dry-run", "start", "0.2.1", "--no-testpypi"]) == 0
    dispatches = [
        line for line in capsys.readouterr().out.splitlines()
        if line.startswith("+ gh workflow run")
    ]  # fmt: skip
    assert dispatches == [
        f"+ gh workflow run {workflow} --ref release/v0.2.1"
        for workflow in release.RELEASE_GATE_WORKFLOWS
    ]


HEAD = "a" * 40
OLD = "b" * 40
MERGE = "c" * 40


def _run(sha: str, status: str = "completed", conclusion: str = "success") -> dict:
    return {
        "headSha": sha,
        "status": status,
        "conclusion": conclusion,
        "url": f"https://example.invalid/{sha[:4]}",
    }


@pytest.fixture
def released_root(fake_root: Path) -> Path:
    """``fake_root`` after the release PR for 0.2.1 merged."""
    for path in (release.ROOT_PYPROJECT, release.CLI_PYPROJECT):
        path.write_text(
            release.set_project_version(path.read_text(encoding="utf-8"), "0.2.1"),
            encoding="utf-8",
        )
    release.CHANGELOG.write_text(
        release.changelog_for_release(CHANGELOG, "0.2.1", "v0.2.0", "2026-11-20"),
        encoding="utf-8",
    )
    return fake_root


def _fake_gh(
    monkeypatch: pytest.MonkeyPatch,
    runs: dict[str, list[dict]],
    merge_commit: str | None = MERGE,
) -> list[list[str]]:
    """Answer ``gh pr view`` with HEAD and ``gh run list`` from ``runs``; record the rest.

    The commands that would change something are recorded and not run.
    """
    changes: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd = list(cmd)
        if cmd[:3] == ["gh", "pr", "view"]:
            merged = {"oid": merge_commit} if merge_commit else None
            out = json.dumps({"headRefOid": HEAD, "mergeCommit": merged})
        elif cmd[:3] == ["gh", "run", "list"]:
            assert cmd[cmd.index("--branch") + 1] == "release/v0.2.1"
            out = json.dumps(runs.get(cmd[cmd.index("--workflow") + 1], []))
        else:
            changes.append(cmd)
            out = ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(release, "_require_clean_main", lambda: None)
    monkeypatch.setattr(release.subprocess, "run", fake_run)
    return changes


def _all_green() -> dict[str, list[dict]]:
    return {w: [_run(HEAD)] for w in release.RELEASE_GATE_WORKFLOWS}


def test_tag_passes_when_every_gate_is_green_on_the_head(
    released_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = _all_green()
    # A newer red run on an old commit does not matter.
    runs[release.RELEASE_GATE_WORKFLOWS[0]].insert(0, _run(OLD, conclusion="failure"))
    changes = _fake_gh(monkeypatch, runs)
    assert release.main(["tag", "0.2.1"]) == 0
    assert [cmd[:6] for cmd in changes] == [
        ["gh", "release", "create", "v0.2.1", "--target", MERGE]
    ]


def test_tag_refuses_before_the_release_pr_merges(
    released_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changes = _fake_gh(monkeypatch, _all_green(), merge_commit=None)
    assert release.main(["tag", "0.2.1"]) == 1
    assert changes == []
    assert "has not merged yet" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("gate_runs", "reason"),
    [
        ([], "no run on aaaaaaaaaaaa"),
        ([_run(OLD)], "no run on aaaaaaaaaaaa"),
        ([_run(HEAD, conclusion="failure")], "failure"),
        ([_run(HEAD, status="in_progress", conclusion="")], "still running"),
        # Newest first: a red run after a green one on the same commit holds the release.
        ([_run(HEAD, conclusion="failure"), _run(HEAD)], "failure"),
        (
            [_run(HEAD, status="in_progress", conclusion=""), _run(HEAD)],
            "still running",
        ),
    ],
    ids=["missing", "older-commit", "red", "running", "red-after-green", "rerunning"],
)
def test_tag_refuses_a_gate_without_a_green_run_on_the_head(
    released_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gate_runs: list[dict],
    reason: str,
) -> None:
    first, *rest = release.RELEASE_GATE_WORKFLOWS
    runs = _all_green()
    runs[first] = gate_runs
    runs[rest[-1]] = []
    changes = _fake_gh(monkeypatch, runs)
    assert release.main(["tag", "0.2.1"]) == 1
    assert changes == []
    err = capsys.readouterr().err
    assert f"{first}: {reason}" in err
    assert f"{rest[-1]}: no run on" in err
    assert "newest run of these release gates is not green" in err
    assert f"git push origin {HEAD}:refs/heads/release/v0.2.1" in err
    for workflow in (first, rest[-1]):
        assert f"gh workflow run {workflow} --ref release/v0.2.1" in err
    for workflow in rest[:-1]:
        assert f"{workflow}:" not in err


def test_dry_run_tag_prints_the_gate_checks(
    released_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert release.main(["--dry-run", "tag", "0.2.1"]) == 0
    out = capsys.readouterr().out
    assert "+ gh pr view release/v0.2.1 --json headRefOid" in out
    for workflow in release.RELEASE_GATE_WORKFLOWS:
        assert f"+ gh run list --workflow {workflow} --branch release/v0.2.1" in out
    assert out.index("+ gh run list") < out.index("+ gh release create")


WORKFLOWS = ROOT / ".github" / "workflows"
# Scheduled workflows that are not release gates, and why.
NOT_RELEASE_GATES = {
    "benchmark-wall.yml": "the release checklist §2 runs the benchmark by hand",
    "conflict-notice.yml": "comments on conflicted pull requests; it tests nothing",
    "ppmd-native-stress.yml": "it finds pyppmd's known native crashes, which archivey "
    "contains in a child process; a red run must not hold a release",
}


def _triggers(path: Path) -> dict:
    # pyyaml is in the dev group, which the core-only leg does not install.
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # YAML 1.1 reads the bare key `on` as True.
    triggers = data.get("on", data.get(True))
    return triggers if isinstance(triggers, dict) else dict.fromkeys(triggers)


def test_every_scheduled_workflow_is_classified() -> None:
    """A new scheduled workflow fails here until it is a gate or has a reason not to be."""
    scheduled = {
        path.name for path in WORKFLOWS.glob("*.y*ml") if "schedule" in _triggers(path)
    }
    gates = set(release.RELEASE_GATE_WORKFLOWS)
    assert not gates & set(NOT_RELEASE_GATES)
    assert scheduled - gates - set(NOT_RELEASE_GATES) == set()
    assert set(NOT_RELEASE_GATES) <= scheduled


def test_every_gate_can_be_dispatched() -> None:
    for workflow in release.RELEASE_GATE_WORKFLOWS:
        assert "workflow_dispatch" in _triggers(WORKFLOWS / workflow), workflow


def test_tag_checks_the_gates_on_another_branch(
    released_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A release PR opened by hand names its branch with ``--branch``."""
    assert release.main(["--dry-run", "tag", "0.2.1", "--branch", "hand-made"]) == 0
    out = capsys.readouterr().out
    assert "+ gh pr view hand-made --json headRefOid" in out
    for workflow in release.RELEASE_GATE_WORKFLOWS:
        assert f"+ gh run list --workflow {workflow} --branch hand-made" in out


@pytest.mark.parametrize(
    ("tag", "needs_minor", "expected"),
    [
        ("v0.2.0", False, "0.2.1"),
        ("v0.2.0", True, "0.3.0"),
        ("v0.3.4", True, "0.4.0"),
        ("v1.2.3", False, "1.2.4"),
        (None, False, "0.1.0"),
    ],
)
def test_next_release_version(
    tag: str | None, needs_minor: bool, expected: str
) -> None:
    assert release.next_release_version(tag, needs_minor) == expected


@pytest.mark.parametrize(
    "tag", ["0.2.0", "v0.2", "v0.2.0.dev0", "v0.2.0-hotfix", "v0.3.0rc1", "v0.2.1b2"]
)
def test_next_release_version_takes_only_final_tags(tag: str) -> None:
    # notes measures from the last final tag, so a pre-release here is a caller's bug.
    with pytest.raises(release.ReleaseError):
        release.next_release_version(tag, False)


def _fake_gh_output(monkeypatch: pytest.MonkeyPatch, outputs: dict[str, str]) -> None:
    """Answer each ``gh <verb>`` call with the given stdout; git still runs for real."""
    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):
        if cmd[0] == "gh":
            return subprocess.CompletedProcess(cmd, 0, stdout=outputs[cmd[1]])
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(release.subprocess, "run", fake_run)


def test_missing_label_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``gh label list --json`` prints nothing at all when no label matches.
    _fake_gh_output(monkeypatch, {"label": ""})
    result = release._needs_minor_prs("HEAD")
    assert isinstance(result, str)
    assert "does not exist" in result


def test_labelled_pull_requests_are_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_gh_output(
        monkeypatch,
        {
            "label": json.dumps([{"name": "needs-minor"}]),
            "pr": json.dumps([{"number": 7, "title": "Refuse more names"}]),
        },
    )
    assert release._needs_minor_prs("HEAD") == ["#7 Refuse more names"]


def _notes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    newest: str | None,
    final: str | None,
    verdict: str = "none",
) -> str:
    monkeypatch.setattr(release, "_git", lambda *args: "")
    monkeypatch.setattr(release, "_previous_tag", lambda: newest)
    monkeypatch.setattr(release, "_previous_final_tag", lambda: final)
    monkeypatch.setattr(release, "_api_change", lambda tag: (verdict, "report"))
    monkeypatch.setattr(release, "_needs_minor_prs", lambda tag: [])
    release.cmd_notes(argparse.Namespace())
    return capsys.readouterr().out


def test_notes_never_suggests_a_version_behind_a_published_pre_release(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _notes(monkeypatch, capsys, newest="v0.3.0rc1", final="v0.2.0")
    assert "Public API since v0.2.0" in out
    assert out.rstrip().endswith(
        "This is a minor release, 0.3.0: v0.3.0rc1 is already out."
    )


def test_notes_says_why_it_stops_without_a_final_release(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _notes(monkeypatch, capsys, newest="v0.2.0rc1", final=None)
    assert "No final release yet" in out


@pytest.mark.parametrize(
    ("newest", "verdict", "labelled", "expected"),
    [
        ("v0.2.0", "none", [], "This can be a patch release, 0.2.1."),
        ("v0.2.0", "patch", [], "This can be a patch release, 0.2.1."),
        (
            "v0.2.0",
            "none",
            "label missing",
            "The API allows a patch release, 0.2.1; check the labels by hand.",
        ),
        (
            "v0.2.0",
            "minor",
            [],
            "This is a minor release, 0.3.0: the public API changed.",
        ),
        (
            "v0.2.0",
            "none",
            ["#7 Refuse more names"],
            "This is a minor release, 0.3.0: 1 merged pull request(s) are labelled.",
        ),
        (
            "v0.3.0rc1",
            "none",
            "label missing",
            "This is a minor release, 0.3.0: v0.3.0rc1 is already out.",
        ),
        (
            "v0.2.1rc1",
            "none",
            [],
            "This can be a patch release, 0.2.1.",
        ),
        (
            "v0.2.1rc1",
            "minor",
            [],
            "This is a minor release, 0.3.0: the public API changed.",
        ),
        (
            "v0.2.2rc1",
            "none",
            [],
            "This can be a patch release, 0.2.2: v0.2.2rc1 is already out.",
        ),
        (
            "v1.0.0rc1",
            "none",
            [],
            "This is a major release, 1.0.0: v1.0.0rc1 is already out.",
        ),
    ],
)
def test_next_release_line(
    newest: str, verdict: str, labelled: list[str] | str, expected: str
) -> None:
    assert release.next_release_line("v0.2.0", newest, verdict, labelled) == expected
