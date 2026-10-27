"""Guardrails for the problem catalogue (`review/problem-catalogue/`, Topic 10).

The catalogue is prose, so almost none of it is testable. Three properties are, and each
one guards a failure that would be invisible on inspection (the redaction property is
asserted from both ends, which is why there are four tests):

1. **The redacted view is derivable and current.** `catalogue-neutral.md` is generated
   from `catalogue.md` by `scripts/derive_neutral_catalogue.py`. The brief's §Definition
   of done #4 wants it committed so redaction is not a manual step at experiment time;
   the hazard of committing a generated file is that it silently goes stale, so this
   asserts it matches its generator.

2. **No entry's fields 1–3 leak the solution.** The catalogue's whole second use is a
   fresh-design comparison run against fields 1–3 alone (`experiment.md`). A problem
   phrased in this library's vocabulary makes that comparison a leading question, and the
   brief names it as the one constraint whose violation silently destroys the artifact.
   The check is a name sweep, not a judgement of voice — the voice is a human review pass
   — but it catches the mechanical half.

3. **Every entry has all four fields.** §Definition of done #2. A missing field 4 is
   allowed only as an explicit statement that the problem is unresolved, which is why the
   assertion looks for the word rather than for the field.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "review" / "problem-catalogue" / "catalogue.md"
NEUTRAL = ROOT / "review" / "problem-catalogue" / "catalogue-neutral.md"
DERIVE = ROOT / "scripts" / "derive_neutral_catalogue.py"

ENTRY_RE = re.compile(
    r"^### ((?:FQ|UL|SEC|PLAT|PERF|API|PKG|CONC)-\d+) — (.*)$", re.MULTILINE
)

# Names that only exist inside this library. A problem, symptom or evidence line that
# reaches for one of these has described the answer instead of the force, so the
# experiment can no longer ask the question the entry was written to pose.
#
# Deliberately not listed: ordinary English words the catalogue must be free to use
# ("member", "reader", "stream", "archive"), and the *file paths* in field 3 — a test
# path is evidence that a case exists and describes no architecture.
ARCHIVEY_NAMES = (
    "ArchiveReader",
    "ArchiveMember",
    "ArchiveSource",
    "ArchiveStream",
    "ArchiveyError",
    "ArchiveyUsageError",
    "ArchiveyConfig",
    "ArchiveFormat",
    "BaseArchiveReader",
    "BombTracker",
    # Folded into ArchiveyUsageError before 0.2.0, and kept on purpose, like
    # PeekableStream below: older catalogue prose can still reach for it.
    "ConcurrentAccessError",
    "CorruptionError",
    "CostReceipt",
    "DecompressorStream",
    "Diagnostic",
    "ExtractionCoordinator",
    "ExtractionLimits",
    "ExtractionPolicy",
    "ExtractionResult",
    "MemberStreams",
    "OverwritePolicy",
    # Deleted when ArchiveSource absorbed it, and kept on purpose: catalogue prose
    # written before then can still reach for it, and it names this library all the same.
    "PeekableStream",
    "SharedSource",
    "SlicingStream",
    "TruncatedError",
    "VerifyingStream",
    "open_archive(",
    "open_stream(",
    "stream_members(",
)


def _entries(text: str) -> list[tuple[str, str]]:
    """Return (id, body) for every entry, body running to the next entry or section."""
    matches = list(ENTRY_RE.finditer(text))
    assert matches, "no catalogue entries found — has the heading format changed?"
    out = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append((m.group(1), text[m.start() : end]))
    return out


@pytest.fixture(scope="module")
def catalogue_text() -> str:
    return CATALOGUE.read_text(encoding="utf-8")


def test_neutral_catalogue_is_derivable_and_current() -> None:
    """`catalogue-neutral.md` matches what its generator produces.

    Definition of done #4. If this fails, run
    `python scripts/derive_neutral_catalogue.py` — do not edit the derived file.
    """
    assert NEUTRAL.exists(), f"{NEUTRAL} is missing; run {DERIVE.name}"
    result = subprocess.run(  # fixed argv, repo-local script
        [sys.executable, str(DERIVE), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_every_entry_has_all_four_fields(catalogue_text: str) -> None:
    """Definition of done #2: fields 1-3 always, field 4 or an explicit unresolved."""
    missing: list[str] = []
    for entry_id, body in _entries(catalogue_text):
        for field in ("**Problem.**", "**Symptom.**", "**Evidence.**", "**Sources.**"):
            if field not in body:
                missing.append(f"{entry_id}: no {field}")
        if "**Answer today.**" not in body:
            missing.append(f"{entry_id}: no answer field")
        elif not re.search(r"[Uu]nresolved", body) and "**Answer today.**" not in body:
            missing.append(f"{entry_id}: answer neither given nor declared unresolved")
    assert not missing, "\n".join(missing)


def test_no_entry_states_its_problem_in_archivey_vocabulary(
    catalogue_text: str,
) -> None:
    """The neutrality rule, mechanically: fields 1-3 name nothing of ours.

    Fields 2 and 3 are held to the same bar as field 1 because the experiment is handed
    all three (`catalogue.md` §The neutrality rule). Field 4 is exempt — naming the
    mechanism is its entire job — so the check stops at the answer field.
    """
    leaks: list[str] = []
    for entry_id, body in _entries(catalogue_text):
        redacted = body.split("**Answer today.**")[0]
        for name in ARCHIVEY_NAMES:
            if name in redacted:
                leaks.append(f"{entry_id}: fields 1-3 name {name!r}")
    assert not leaks, (
        "A problem stated in terms of its solution is not a problem. Rewrite as what "
        "the world does:\n" + "\n".join(leaks)
    )


def test_neutral_view_carries_no_answer_or_source_lines(catalogue_text: str) -> None:
    """The redacted view really is redacted, and drops no entry while redacting.

    Both halves matter and they fail in opposite directions: an answer line surviving
    means the experiment sees archivey's design, and an entry going missing means it is
    asked about a smaller problem space than the catalogue records.
    """
    body = NEUTRAL.read_text(encoding="utf-8")
    # The header explains which fields were stripped, so only inspect past it.
    _, _, entries = body.partition("\n## ")
    assert "**Answer today.**" not in entries
    assert "**Sources.**" not in entries
    assert len(_entries(entries)) == len(_entries(catalogue_text))
