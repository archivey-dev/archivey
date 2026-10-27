"""The issue forms and the pull request template under `.github/`.

GitHub drops an issue form that does not parse, and a link to a moved file or a renamed
section stays dead; neither turns a check red. So the forms are loaded here, and every
link they make into this repository must point at a file that exists.

Every file this reads is excluded by ci.yml's path filter, so the gate that counts is the
step in docs-checks.yml that runs this file on every pull request. That step adds PyYAML
itself, so `test_form_parses` cannot skip there.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
FORMS = sorted((GITHUB / "ISSUE_TEMPLATE").glob("*.yml"))
# The files that link into the repository. config.yml links only to the advisory form.
LINKED = [
    GITHUB / "ISSUE_TEMPLATE" / "bug_report.yml",
    GITHUB / "ISSUE_TEMPLATE" / "feature_request.yml",
    GITHUB / "pull_request_template.md",
]
# The same pattern as scripts/check_docs_nav.py: `tree/` for directories, and a path
# quoted in YAML does not keep its closing quote.
_REPO_LINK = re.compile(
    r"https://github\.com/archivey-dev/archivey/(?:blob|tree)/main/([^)\s\"'#]+)"
)


def test_the_forms_exist() -> None:
    assert {p.name for p in FORMS} >= {
        "bug_report.yml",
        "feature_request.yml",
        "config.yml",
    }


@pytest.mark.parametrize("path", FORMS, ids=lambda p: p.name)
def test_form_parses(path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    if path.name != "config.yml":
        assert data["name"] and data["description"] and data["body"]


@pytest.mark.parametrize("path", LINKED, ids=lambda p: p.name)
def test_repository_links_resolve(path: Path) -> None:
    targets = _REPO_LINK.findall(path.read_text(encoding="utf-8"))
    assert targets, (
        f"{path.name} has no repository link; the pattern may have missed one"
    )
    missing = [t for t in targets if not (ROOT / t).exists()]
    assert not missing, f"{path.name} links to missing files: {missing}"


def test_feature_form_quotes_a_real_heading() -> None:
    form = (GITHUB / "ISSUE_TEMPLATE" / "feature_request.yml").read_text(
        encoding="utf-8"
    )
    quoted = re.search(r'section "([^"]+)"', form)
    assert quoted is not None
    project = (ROOT / "openspec" / "project.md").read_text(encoding="utf-8")
    assert f"## {quoted.group(1)}\n" in project
