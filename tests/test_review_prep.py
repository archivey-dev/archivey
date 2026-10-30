"""`scripts/review_prep.py`, the checks an implementer runs before adding the `review` label.

The diff parsing runs on a real ``git diff`` from a scratch repository; the reports are pure
functions over text and are tested on it directly. The pytest call in ``red-on-base`` is
not run here.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_prep.py"

_spec = importlib.util.spec_from_file_location("review_prep", SCRIPT)
assert _spec is not None and _spec.loader is not None
prep = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package; `@dataclass` looks its module up by name while executing.
sys.modules["review_prep"] = prep
_spec.loader.exec_module(prep)

BEFORE = {
    "src/archivey/a.py": """\
class Reader:
    def open_member(self):
        if short:
            raise TruncatedError("short")
        return 1


class OldName:
    pass


def other():
    return 2
""",
    "src/archivey/gone.py": """\
MAX_THING = 4


def helper():
    raise ValueError("x")
""",
    "src/archivey/old_mod.py": "".join(f"LINE_{i} = {i}\n" for i in range(20)),
    "docs/x.md": "one\ntwo\nthree\n",
}
AFTER = {
    "src/archivey/a.py": BEFORE["src/archivey/a.py"]
    .replace("TruncatedError", "CorruptionError")
    .replace("OldName", "NewName")
    .replace("return 2", "x = 1\n    return 2"),
    "src/archivey/sub/new_mod.py": BEFORE["src/archivey/old_mod.py"],
    "docs/x.md": "one\ntwo\nthree\nnew line\n",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(repo: Path, files: dict[str, str]) -> None:
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)


@pytest.fixture(scope="module")
def diff(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A real ``git diff -U0`` under this repo's `.gitattributes`, not a hand-written one:
    the hunk header the raise filter keys on is whatever git emits here."""
    repo = tmp_path_factory.mktemp("repo")
    _git(repo, "init", "-q")
    shutil.copy(ROOT / ".gitattributes", repo / ".gitattributes")
    _write(repo, BEFORE)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    for path in BEFORE:
        (repo / path).unlink()
    _write(repo, AFTER)
    _git(repo, "add", "-A")
    return _git(repo, "diff", "-U0", "-M", "--cached")


def test_parse_diff_keeps_line_numbers_deletions_and_renames(diff: str) -> None:
    files = {f.path: f for f in prep.parse_diff(diff)}
    assert set(files) == {
        "src/archivey/a.py",
        "src/archivey/gone.py",
        "src/archivey/sub/new_mod.py",
        "docs/x.md",
    }
    assert files["docs/x.md"].added == [(4, "new line")]
    assert (13, "    x = 1") in files["src/archivey/a.py"].added
    # Deleting a module is the commonest way a name disappears; its lines must count.
    gone = files["src/archivey/gone.py"]
    assert gone.deleted and gone.removed[0][1] == "MAX_THING = 4"
    # A pure rename has no hunks at all.
    moved = files["src/archivey/sub/new_mod.py"]
    assert moved.renamed_from == "src/archivey/old_mod.py" and not moved.removed


def test_moved_claims_finds_removed_names_dropped_raises_and_modules(diff: str) -> None:
    moved = prep.moved_claims(prep.parse_diff(diff))
    names = {m.old for m in moved if m.kind == "name"}
    assert names == {"OldName", "MAX_THING", "helper"}
    raises = {(m.old, m.near) for m in moved if m.kind == "raise"}
    # The method, not the class: needs `*.py diff=python` in `.gitattributes`.
    assert ("TruncatedError", "open_member") in raises
    modules = {(m.old, m.where) for m in moved if m.kind == "module"}
    assert modules == {
        ("archivey.old_mod", "moved to src/archivey/sub/new_mod.py"),
        ("archivey/old_mod.py", "moved to src/archivey/sub/new_mod.py"),
        ("archivey.gone", "deleted"),
        ("archivey/gone.py", "deleted"),
    }


def test_a_type_still_raised_elsewhere_in_the_file_has_not_stopped(diff: str) -> None:
    head = {"src/archivey/a.py": "def f():\n    raise TruncatedError('other site')\n"}
    moved = prep.moved_claims(prep.parse_diff(diff), head.get)
    assert "TruncatedError" not in {m.old for m in moved if m.kind == "raise"}


def test_a_name_defined_again_is_not_moved(diff: str) -> None:
    diff = diff.replace("+class NewName:", "+class OldName(Base):")
    names = {
        m.old for m in prep.moved_claims(prep.parse_diff(diff)) if m.kind == "name"
    }
    assert "OldName" not in names


def test_sweep_reports_a_doc_still_naming_a_removed_name(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(prep, "ROOT", tmp_path)
    spec = tmp_path / "openspec" / "specs" / "x" / "spec.md"
    spec.parent.mkdir(parents=True)
    spec.write_text("The reader SHALL use `OldName`.\nUnrelated OldNamed line.\n")
    report = prep.sweep([prep.Moved("name", "OldName", "src/a.py")], [spec])
    assert report[0].startswith("`OldName` is no longer defined")
    assert report[1:] == [
        "    openspec/specs/x/spec.md:1: The reader SHALL use `OldName`."
    ]


def test_sweep_only_reports_a_raise_where_the_doc_names_the_function(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(prep, "ROOT", tmp_path)
    near = tmp_path / "near.md"
    near.write_text("`open_member` raises `TruncatedError` on a short read.\n")
    far = tmp_path / "far.md"
    far.write_text("Everything else raises `TruncatedError`.\n")
    moved = [prep.Moved("raise", "TruncatedError", "src/a.py", "open_member")]
    report = prep.sweep(moved, [near, far])
    assert [line for line in report if line.startswith("    ")] == [
        "    near.md:1: `open_member` raises `TruncatedError` on a short read."
    ]


def _wrapped(width: int, lines: int = 20) -> str:
    return "\n".join("w" * width for _ in range(lines)) + "\n"


def test_md_limit_reads_the_files_own_width() -> None:
    assert prep.md_limit(_wrapped(91)) == 91
    assert prep.md_limit(_wrapped(70)) == 88  # never narrower than the code width
    # One long line per paragraph: the file is not hard-wrapped, so there is no limit.
    assert prep.md_limit(_wrapped(300)) is None
    # Too little prose to tell, and a file this change creates.
    assert prep.md_limit(_wrapped(80, lines=3)) is None
    assert prep.md_limit(None) is None


def test_md_limit_ignores_tables_code_and_urls() -> None:
    text = _wrapped(88) + "| " + "x" * 200 + " |\n```\n" + "y" * 200 + "\n```\n"
    assert prep.md_limit(text) == 88


def test_width_flags_only_lines_far_past_their_file(monkeypatch) -> None:
    monkeypatch.setattr(prep, "base_text", lambda rev, path: _wrapped(88))
    limit = 88 + prep.SLACK
    diff = prep.FileDiff("docs/x.md", added=[(1, "a" * limit), (2, "b" * (limit + 1))])
    source = prep.FileDiff("src/archivey/x.py", added=[(7, "# " + "c" * 120)])
    test = prep.FileDiff("tests/test_x.py", added=[(3, "d" * 150)])
    url = prep.FileDiff("src/archivey/y.py", added=[(1, "# https://" + "e" * 150)])
    report = prep.width([diff, source, test, url], "base")
    assert report == [
        f"docs/x.md:2: {limit + 1} > 88 columns",
        "src/archivey/x.py:7: 122 > 88 columns",
    ]


def test_width_leaves_lines_inside_an_existing_code_fence(monkeypatch) -> None:
    base = _wrapped(88) + "```\nshort\n```\n"
    head = _wrapped(88) + "```\n" + "c" * 148 + "\n```\n" + "p" * 148 + "\n"
    texts = {"base": base, "HEAD": head}
    monkeypatch.setattr(prep, "base_text", lambda rev, path: texts[rev])
    # Line 22 is inside the fence, whose markers are not in the diff; 24 is prose after it.
    diff = prep.FileDiff("docs/x.md", added=[(22, "c" * 148), (24, "p" * 148)])
    assert prep.width([diff], "base") == ["docs/x.md:24: 148 > 88 columns"]


def test_outcome_names_what_a_non_red_run_means() -> None:
    assert prep._outcome(0, "") == "passes"
    assert prep._outcome(1, "F\n1 failed in 0.12s\n") == "fails"
    # Exit 1 is also `python -m pytest` with no pytest installed: not a failure.
    assert prep._outcome(1, "/usr/bin/python3: No module named pytest").startswith(
        "errors at collection"
    )
    assert prep._outcome(1, "").startswith("did not run")
    assert (
        prep._outcome(4, "ERROR: not found: tests/x.py::nope")
        == "not found (check the id)"
    )
    imported = "E   ImportError: cannot import name 'thing' from 'archivey.x'"
    assert prep._outcome(2, imported).startswith("errors at collection: ImportError")


def test_tier_is_light_only_when_every_path_is_prose_or_tests() -> None:
    light = prep.tier(["docs/extracting.md", "tests/test_x.py", "README.md"])
    assert (light.name, light.api_changed) == ("light", False)
    # A spec is a contract, and a nested `.md` outside the light folders is not prose.
    assert prep.tier(["docs/x.md", "openspec/specs/cli/spec.md"]).name == "standard"
    assert prep.tier(["src/archivey/core.py", "tests/test_x.py"]).name == "standard"
    assert prep.tier([]).name == "standard"
    # Gates and contracts inside the light folders are taken back out.
    for gate in ("tests/conftest.py", "dev-docs/threat-model.md"):
        assert prep.tier([gate]).name == "standard", gate
    # So are an agent's own instructions, wherever they live.
    for instructions in (
        "AGENTS.md",
        ".claude/skills/steward/SKILL.md",
        ".cursor/x.md",
    ):
        assert prep.tier([instructions]).name == "standard", instructions


def test_tier_path_lists_name_paths_that_exist() -> None:
    # A renamed file would stop matching and quietly drop its pull requests to standard.
    for entry in prep.DEEP_SECURITY + prep.DEEP_MAINTAINER + prep.NOT_LIGHT:
        path = ROOT / entry
        assert path.is_dir() if entry.endswith("/") else path.is_file(), entry


def test_the_maintainer_merges_changes_to_the_review_rules() -> None:
    """A pull request is reviewed under its own copy of these, so a person merges it."""
    for rules in (
        ".github/review-loop-prompt.md",
        ".claude/skills/code-review-skill/SKILL.md",
        "scripts/review_loop_gate.py",
        "scripts/review_prep.py",
        "scripts/review_shape.py",
    ):
        t = prep.tier([rules])
        assert (t.name, t.maintainer_merges) == ("deep", True), rules


def test_tier_is_deep_on_a_safety_path_and_the_maintainer_merges_workflows() -> None:
    safety = prep.tier(["src/archivey/internal/extraction.py", "docs/x.md"])
    assert (safety.name, safety.maintainer_merges) == ("deep", False)
    assert safety.reasons == ["src/archivey/internal/extraction.py"]
    assert prep.tier(["src/archivey/internal/external/unar.py"]).name == "deep"
    workflow = prep.tier([".github/workflows/ci.yml"])
    assert (workflow.name, workflow.maintainer_merges) == ("deep", True)
    # AGENTS.md quotes the merge line.
    assert prep.tier_report(workflow)[:3] == [
        "tier: deep",
        "  deep path: .github/workflows/ci.yml",
        "  merge: the maintainer merges this one (workflow or release)",
    ]
    # A directory entry matches by prefix, a file entry only exactly.
    assert prep.tier(["src/archivey/paths.pyi"]).name == "standard"


def test_tier_reports_a_public_api_change() -> None:
    t = prep.tier(["src/archivey/core.py", "dev-docs/api-surface.txt"])
    assert t.api_changed
    assert prep.tier_report(t)[-1] == "public API: changed (dev-docs/api-surface.txt)"
