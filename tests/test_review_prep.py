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
_gate_spec = importlib.util.spec_from_file_location(
    "review_loop_gate", ROOT / "scripts" / "review_loop_gate.py"
)
assert _gate_spec is not None and _gate_spec.loader is not None
gate = importlib.util.module_from_spec(_gate_spec)
sys.modules.setdefault("review_loop_gate", gate)
_gate_spec.loader.exec_module(gate)

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
    for entry in (
        prep.DEEP_SECURITY
        + prep.DEEP_PROCESS
        + prep.NOT_LIGHT
        + tuple(prep.MAINTAINER_FILES)
    ):
        path = ROOT / entry
        assert path.is_dir() if entry.endswith("/") else path.is_file(), entry
    for path in (prep.DECISIONS_DIR, prep.WORKFLOWS):
        assert (ROOT / path).is_dir(), path
    assert (ROOT / prep.THREAT_MODEL).is_file()
    assert (ROOT / prep.CONFIG).is_file()


def test_required_checks_are_job_names_in_the_workflows() -> None:
    names = {
        line.strip().removeprefix("name: ")
        for wf in (ROOT / prep.WORKFLOWS).glob("*.yml")
        for line in wf.read_text().splitlines()
        if line.strip().startswith("name: ")
    }
    for check in prep.REQUIRED_CHECKS:
        assert check in names, check


def test_the_review_rules_are_deep_and_the_gate_goes_to_the_maintainer() -> None:
    """A pull request is reviewed under its own copy of these. The prompt and the skill
    merge like any deep pull request; the files that decide whether a round runs and
    approves, and who merges, go to the maintainer."""
    for rules in (
        ".github/review-loop-prompt.md",
        ".claude/skills/code-review-skill/SKILL.md",
    ):
        assert prep.tier([rules]).name == "deep", rules
        assert prep.maintainer_decisions([prep.FileDiff(rules)]) == [], rules
    for gate in (
        "scripts/review_loop_gate.py",
        "scripts/review_loop_close.sh",
        "scripts/review_prep.py",
        ".github/workflows/review-loop.yml",
        ".github/workflows/risk-label.yml",
    ):
        assert prep.tier([gate]).name == "deep", gate
        assert prep.maintainer_decisions([prep.FileDiff(gate)]) == [
            f"touches the merge gate: {gate}"
        ]


def test_tier_is_deep_on_a_safety_path_and_on_workflows() -> None:
    safety = prep.tier(["src/archivey/internal/extraction.py", "docs/x.md"])
    assert safety.name == "deep"
    assert safety.reasons == ["src/archivey/internal/extraction.py"]
    assert prep.tier(["src/archivey/internal/external/unar.py"]).name == "deep"
    workflow = prep.tier([".github/workflows/ci.yml"])
    assert prep.tier_report(workflow)[:2] == [
        "tier: deep",
        "  deep path: .github/workflows/ci.yml",
    ]
    # A directory entry matches by prefix, a file entry only exactly.
    assert prep.tier(["src/archivey/paths.pyi"]).name == "standard"


def test_the_merge_line_names_the_maintainers_decisions() -> None:
    t = prep.tier(["scripts/release.py"])
    t.maintainer = ["touches the release path: scripts/release.py"]
    # AGENTS.md, the risk-label workflow and the PR template quote the first line.
    assert prep.tier_report(t)[-2:] == [
        "merge: the maintainer merges this one",
        "  maintainer decision: touches the release path: scripts/release.py",
    ]
    # With no decision, the line names what must approve first: the Opus pass runs on
    # the tiers review_loop_gate.py lists, and Cursor on deep alone.
    assert gate.OPUS_PASS_TIERS == {"standard", "deep"}
    for paths, line in (
        ([".github/workflows/ci.yml"], "the Opus pass and Cursor approve"),
        (["src/archivey/core.py"], "the Opus pass approves"),
        (["docs/x.md"], "the review approves"),
    ):
        assert prep.tier_report(prep.tier(paths))[-1] == (
            f"merge: an agent merges once {line} and CI is green"
        ), paths


def _diff(path: str, added: list[str] = (), removed: list[str] = ()) -> prep.FileDiff:
    return prep.FileDiff(
        path,
        added=[(n, t) for n, t in enumerate(added, 1)],
        removed=[("", t) for t in removed],
    )


def test_maintainer_decisions_in_the_api_surface() -> None:
    api = _diff(
        prep.API_SURFACE,
        added=[
            "class archivey.AbortOn(StrEnum, Flag)",  # same name: not a removal
            "class archivey.NewThing",
            "init archivey.NewThing(x: int) -> None",  # not top level by kind
            "method archivey.AbortOn.helper(self) -> None",  # not top level
            "module archivey.extras",
            "cli-verb verify",
            # A widened type and a new optional parameter take nothing away.
            "method archivey.R.open(self, name: str | bytes, *, mode: str = 'r') -> X",
            # A removed parameter, a narrowed choice, a renamed wire string do.
            "method archivey.R.get(self, name: str) -> X",
            # Moving a positional parameter, or putting a new one before it, breaks a
            # positional call; a new keyword-only one does not.
            "method archivey.R.swap(self, b: int, a: int) -> X",
            "method archivey.R.ins(self, new: int, a: int) -> X",
            "method archivey.R.kw(self, a: int, *, new: int = 0) -> X",
            "cli-option extract --overwrite [action=Store choices={error, rename}]",
            "value archivey.AbortOn.BLOCKED_MEMBER = 'blocked'",
            "alias archivey.AbortOnStr = Literal['blocked']",
        ],
        removed=[
            "class archivey.AbortOn(StrEnum)",
            "field archivey.Member.size: int",
            "# a comment",
            "method archivey.R.open(self, name: str) -> X",
            "method archivey.R.get(self, name: str, default: X | None = None) -> X",
            "method archivey.R.swap(self, a: int, b: int) -> X",
            "method archivey.R.ins(self, a: int) -> X",
            "method archivey.R.kw(self, a: int) -> X",
            "cli-option extract --overwrite [action=Store choices={error, rename, skip}]",
            "value archivey.AbortOn.BLOCKED_MEMBER = 'blocked_member'",
            "alias archivey.AbortOnStr = Literal['blocked_member']",
        ],
    )
    assert prep.maintainer_decisions([api]) == [
        "removes or renames a public name: field archivey.Member.size",
        "removes a public value: alias archivey.AbortOnStr blocked_member",
        "removes a public value: cli-option extract --overwrite skip",
        "removes a parameter: method archivey.R.get default",
        "reorders positional parameters: method archivey.R.ins",
        "reorders positional parameters: method archivey.R.swap",
        "removes a public value: value archivey.AbortOn.BLOCKED_MEMBER 'blocked_member'",
        "adds a top-level name: class archivey.NewThing",
        "adds a top-level name: cli-verb verify",
        "adds a top-level name: module archivey.extras",
    ]


def test_maintainer_decisions_in_config_workflows_and_decisions() -> None:
    config = _diff(
        prep.CONFIG,
        added=[
            "    max_ratio: float | None = _InheritedFloat(600.0)",
            "    # max_x = 1",
        ],
        removed=["    max_ratio: float | None = _InheritedFloat(800.0)"],
    )
    assert prep.maintainer_decisions([config]) == [
        f"changes a default in {prep.CONFIG}: max_ratio"
    ]
    wf = ".github/workflows/ci.yml"
    assert prep.maintainer_decisions([_diff(wf, added=["      - run: make"])]) == []
    # Fields of the github context nobody outside chooses stay quiet.
    fixed = "      - run: echo ${{ github.sha }} ${{ github.repository }} ${{ github.run_id }}"
    assert prep.maintainer_decisions([_diff(wf, added=[fixed])]) == []
    for line in (
        "      contents: write",
        "permissions:",
        "      TOKEN: ${{ secrets.X }}",
        "  pull_request_target:",
        "  workflow_run:",
        "  issue_comment:",
        '          echo "${{ github.event.pull_request.title }}"',
        "          git checkout ${{ github.head_ref }}",
        '          echo "${{ github.ref_name }}"',
        "          echo \"${{ github['event'].pull_request.title }}\"",
        "          echo ${{github.actor}}",
        "          gh api -H 'x: ${{ github.token }}'",
    ):
        assert prep.maintainer_decisions([_diff(wf, added=[line])]) == [
            f"changes a workflow's permissions, secrets or triggers: {wf}"
        ], line
    # An action new to the repository's workflows; a version bump or one already run
    # elsewhere is not.
    step = "      - uses: some/action@v1"
    assert prep.maintainer_decisions([_diff(wf, added=[step])]) == [
        f"adds an action: some/action ({wf})"
    ]
    bump = _diff(wf, added=[step], removed=["      - uses: some/action@v0"])
    assert prep.maintainer_decisions([bump]) == []
    assert (
        prep.maintainer_decisions(
            [_diff(wf, added=[step])], known_actions={"some/action"}
        )
        == []
    )
    assert prep.maintainer_decisions([_diff(wf, added=["      - uses: ./local"])]) == []
    assert prep.maintainer_decisions([_diff(wf, removed=["    name: CI gate"])]) == [
        f"changes a required check: CI gate ({wf})"
    ]
    adr = "dev-docs/decisions/0042-x.md"
    assert prep.maintainer_decisions([_diff(adr)], added=[adr]) == [
        f"adds an architecture decision: {adr}"
    ]
    # Editing an existing one is not a new decision.
    assert prep.maintainer_decisions([_diff(adr)]) == []
    assert (
        prep.maintainer_decisions([_diff("scripts/x.py")], added=["scripts/x.py"]) == []
    )


THREAT_BASE = (
    "## 3. Defended properties\n"
    "### Stays inside\none\n"
    "### Bounded\none\ntwo\nthree\n"
    "## 4. Accepted non-guarantees\n"
    "### No CPU bound\n"
)


def test_maintainer_decisions_in_dependencies() -> None:
    pytest.importorskip("tomllib")
    before = '[project]\ndependencies = []\n[project.optional-dependencies]\na = ["Py_PPMd>=1"]\n'
    after = (
        '[project]\ndependencies = ["new-dep"]\n'
        '[project.optional-dependencies]\na = ["py-ppmd>=2", "lz4"]\n'
    )
    assert prep.maintainer_decisions([], pyprojects=(before, after)) == [
        "adds a runtime dependency: new-dep",
        "adds a runtime dependency: lz4 (a)",
    ]
    # A file that does not parse costs the dependency check, not the whole report.
    (found,) = prep.maintainer_decisions([], pyprojects=(before, "not = = toml\n"))
    assert found.startswith("pyproject.toml changed: check its dependencies by hand (")


def test_maintainer_decisions_in_the_threat_model() -> None:
    new = (
        THREAT_BASE.replace("### Stays inside\none\n", "").replace(
            "two\nthree\n", "two\nthree\nfour\n"
        )
        + "### X\n"
    )
    assert prep.maintainer_decisions([], threat_models=(THREAT_BASE, new)) == [
        "drops or renames a defended property: Stays inside",
        "accepts a new non-guarantee: X",
    ]
    # A property emptied under its heading is cut down; a rewrap or a new defence is not.
    cut = THREAT_BASE.replace("two\nthree\n", "")
    assert prep.maintainer_decisions([], threat_models=(THREAT_BASE, cut)) == [
        "cuts down a defended property: Bounded (3 -> 1 lines)"
    ]
    longer = THREAT_BASE.replace("one\ntwo", "one, now longer\ntwo\nmore")
    assert prep.maintainer_decisions([], threat_models=(THREAT_BASE, longer)) == []
    # A renumbered section is not twelve dropped properties; a renamed one is reported.
    renumbered = THREAT_BASE.replace("## 3.", "## 4.").replace("## 4. Acc", "## 5. Acc")
    assert prep.maintainer_decisions([], threat_models=(THREAT_BASE, renumbered)) == []
    renamed = THREAT_BASE.replace("Defended properties", "Properties")
    assert prep.maintainer_decisions([], threat_models=(THREAT_BASE, renamed)) == [
        f"renames or drops a section of {prep.THREAT_MODEL}"
    ]


def test_the_threat_model_has_the_sections_the_check_reads() -> None:
    sections = prep._threat_sections((ROOT / prep.THREAT_MODEL).read_text())
    assert sections.get(prep._DEFENDED) and sections.get(prep._ACCEPTED)


def test_review_tier_reads_adds_renames_and_texts_from_git(
    tmp_path: Path, monkeypatch
) -> None:
    """The git wiring: a renamed parser is no new parser whatever ``diff.renames``
    says, an added one is, and the before and after texts come from the merge base and
    the head in that order (swap them and a dropped property reads as a new one)."""
    pytest.importorskip("tomllib")
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "diff.renames", "false")
    backends = "src/archivey/internal/backends"
    body = "\n".join(f"line {i}" for i in range(40)) + "\n"
    pyproject = '[project]\ndependencies = ["a"]\n'
    _write(
        tmp_path,
        {
            f"{backends}/zip_parser.py": body,
            prep.THREAT_MODEL: THREAT_BASE,
            "pyproject.toml": pyproject,
            ".github/workflows/ci.yml": "jobs:\n  - uses: actions/checkout@v4\n",
        },
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "checkout", "-qb", "pr")
    _git(tmp_path, "mv", f"{backends}/zip_parser.py", f"{backends}/zip2_parser.py")
    _write(
        tmp_path,
        {
            f"{backends}/cab_reader.py": "new\n",
            "dev-docs/decisions/0099-x.md": "adr\n",
            prep.THREAT_MODEL: THREAT_BASE.replace("### Stays inside\none\n", "")
            + "### X\n",
            "pyproject.toml": pyproject.replace('"a"', '"a", "b"'),
            ".github/workflows/docs.yml": "jobs:\n  - uses: actions/checkout@v5\n",
        },
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "pr")
    # main moves on after the fork: the "before" texts must not come from its tip.
    _git(tmp_path, "checkout", "-q", "main")
    _write(tmp_path, {"pyproject.toml": pyproject.replace('"a"', '"a", "b"')})
    _git(tmp_path, "commit", "-qam", "main moves")
    monkeypatch.setattr(prep, "ROOT", tmp_path)
    t = prep.review_tier("main", "pr")
    assert t.new_parsers == [f"{backends}/cab_reader.py"]
    assert t.maintainer == [
        "drops or renames a defended property: Stays inside",
        "accepts a new non-guarantee: X",
        "adds an architecture decision: dev-docs/decisions/0099-x.md",
        "adds a runtime dependency: b",
    ]
    assert f"{backends}/zip_parser.py" in prep.changed_paths("main", "pr")


def test_a_new_parser_or_codec_file_gets_the_security_pass_on_any_tier() -> None:
    new = "src/archivey/internal/backends/cab_reader.py"
    t = prep.tier([new, "tests/test_cab.py"], added=[new, "tests/test_cab.py"])
    assert (t.name, t.new_parsers) == ("standard", [new])
    report = prep.tier_report(t)
    i = report.index("security pass: yes")
    assert report[i + 1] == f"  new file under a parser or codec directory: {new}"
    # Editing one is up to the Risk line's rules; so is a new file elsewhere.
    edited = prep.tier(["src/archivey/internal/streams/codecs/lzo.py"])
    assert edited.new_parsers == []
    assert any(
        line.startswith("security pass: per the Risk line")
        for line in prep.tier_report(edited)
    )
    # A deep pull request always gets it.
    deep = prep.tier(["src/archivey/internal/extraction.py"])
    assert "security pass: yes" in prep.tier_report(deep)


def test_security_new_file_prefixes_exist() -> None:
    for entry in prep.SECURITY_NEW_FILES:
        assert (ROOT / entry).is_dir(), entry


def test_tier_reports_a_public_api_change() -> None:
    t = prep.tier(["src/archivey/core.py", "dev-docs/api-surface.txt"])
    assert t.api_changed
    assert "public API: changed (dev-docs/api-surface.txt)" in prep.tier_report(t)
