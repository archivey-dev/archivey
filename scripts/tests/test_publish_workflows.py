"""publish.yml and speedups-publish.yml: which run reaches which index.

A PyPI upload cannot be taken back, so the ``if:`` of each publish job is evaluated
here for every kind of run, rather than compared as text. The evaluator knows only the
operators these expressions use and refuses any other token, so a later edit that
needs more is tested only once the evaluator learns it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class Run(NamedTuple):
    event: str
    ref: str
    target: str  # "" when the run has no inputs


def _runs(tag: str) -> dict[str, Run]:
    return {
        "tag push": Run("push", f"refs/tags/{tag}", ""),
        "dispatch on a tag, testpypi": Run(
            "workflow_dispatch", f"refs/tags/{tag}", "testpypi"
        ),
        "dispatch on a tag, pypi": Run("workflow_dispatch", f"refs/tags/{tag}", "pypi"),
        "dispatch on main, testpypi": Run(
            "workflow_dispatch", "refs/heads/main", "testpypi"
        ),
        "dispatch on main, pypi": Run("workflow_dispatch", "refs/heads/main", "pypi"),
        "pull request": Run("pull_request", "refs/pull/1/merge", ""),
    }


# A tag that each workflow's push trigger matches.
CASES = {"publish.yml": "v1.2.3", "speedups-publish.yml": "speedups-v1.2.3"}

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'[^']*')|(?P<op>&&|\|\||==|\(|\)|,)"
    r"|(?P<name>startsWith|github\.repository|github\.event_name|github\.ref"
    r"|inputs\.target))"
)


def evaluate(expr: str, run: Run) -> bool:
    """``expr`` (a GitHub Actions ``if:``) for ``run`` in the canonical repository."""
    values = {
        "github.repository": repr("archivey-dev/archivey"),
        "github.event_name": repr(run.event),
        "github.ref": repr(run.ref),
        "inputs.target": repr(run.target),
    }
    out = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if m is None:
            raise AssertionError(f"unknown token in {expr!r} at {expr[pos:]!r}")
        pos = m.end()
        if m["str"]:
            out.append(repr(m["str"][1:-1]))
        elif m["op"]:
            out.append({"&&": " and ", "||": " or "}.get(m["op"], m["op"]))
        elif m["name"] == "startsWith":
            out.append("_starts")
        else:
            out.append(values[m["name"]])
    return bool(eval("".join(out), {"__builtins__": {}, "_starts": str.startswith}))


def _jobs(name: str) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))["jobs"]


@pytest.mark.parametrize("workflow", sorted(CASES))
def test_pypi_only_from_a_tag_push_or_a_dispatch_with_target_pypi(
    workflow: str,
) -> None:
    jobs = _jobs(workflow)
    for label, run in _runs(CASES[workflow]).items():
        pypi = evaluate(jobs["pypi"]["if"], run)
        testpypi = evaluate(jobs["testpypi"]["if"], run)
        wanted = (run.event == "push") or (
            run.event == "workflow_dispatch" and run.target == "pypi"
        )
        assert pypi == wanted, (workflow, label)
        assert not (pypi and testpypi), (workflow, label)
        if run.event == "pull_request":
            assert not testpypi, (workflow, label)


def test_the_evaluator_refuses_what_it_does_not_know() -> None:
    with pytest.raises(AssertionError, match="unknown token"):
        evaluate("contains(github.ref, 'x')", _runs("v1")["tag push"])
