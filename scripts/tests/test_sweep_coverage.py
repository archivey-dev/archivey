"""The sweep coverage counter, exercised without GitHub.

`scripts/review/sweep_coverage.py` turns the `SWEPT` marker comments on #315 into a coverage
figure. It exists because the figure used to be read off thread counts and was wrong
twice running — 24% and then 35% against a truth of 12% and 23% — which left the
repository's largest and most exposed file in the swept column having never been read.

A maintainer tool that is quietly wrong is not caught by anything else: it is not in CI
and its output is a number nobody can eyeball. So the counting rules are pinned here. The
cases that matter most are the ones where a slip would *lower* the count silently, because
that is the direction that sends an agent back over code somebody already read, and the
one where it would raise it, because that is how a file goes unswept while the page says
otherwise.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "review" / "sweep_coverage.py"
)

_spec = importlib.util.spec_from_file_location("sweep_coverage", SCRIPT)
assert _spec is not None and _spec.loader is not None
sweep = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package, so the module is loaded by path. It has to be in
# `sys.modules` before it executes: `@dataclass` looks its own module up by name.
sys.modules[_spec.name] = sweep
_spec.loader.exec_module(sweep)


def marker(
    path: str = "src/archivey/a.py",
    *,
    batch: str = "S1",
    date: str = "2026-09-17",
    lines: int = 100,
    findings: int = 0,
    ids: str = "-",
    reviewer: str = "cursor",
    head: str = "94468bd",
    dash: str = "—",
    extra: str = "",
) -> str:
    """One marker line in the shape `whole-file-sweep.md` defines."""
    return (
        f"**SWEPT** `{path}` {dash} pass={batch} date={date} lines={lines} "
        f"findings={findings} ids={ids} reviewer={reviewer} head={head}{extra}"
    )


# --- parsing ------------------------------------------------------------------------


def test_a_well_formed_marker_parses() -> None:
    markers, malformed = sweep.parse_markers(
        marker(findings=3, ids="S1-K1,S1-K2,S1-K3")
    )
    assert malformed == []
    assert len(markers) == 1
    assert markers[0].path == "src/archivey/a.py"
    assert markers[0].batch == "S1"
    assert markers[0].lines == 100
    assert markers[0].findings == 3


def test_a_hyphen_reads_the_same_as_an_em_dash() -> None:
    """Both separators are in use on #315, and a marker posted by hand may use either."""
    em_dash, _ = sweep.parse_markers(marker(dash="—"))
    hyphen, _ = sweep.parse_markers(marker(dash="-"))
    assert (
        [m.path for m in em_dash] == [m.path for m in hyphen] == ["src/archivey/a.py"]
    )


def test_the_marker_is_found_inside_a_whole_comment_body() -> None:
    """The script is fed unfiltered comment bodies, prose and all."""
    body = (
        "Read this one end to end. Nothing came back.\n\n"
        + marker()
        + "\n\nThe compressed path is covered by the parcels."
    )
    markers, malformed = sweep.parse_markers(body)
    assert malformed == []
    assert len(markers) == 1


def test_prose_that_merely_mentions_a_sweep_is_not_a_marker() -> None:
    markers, malformed = sweep.parse_markers(
        "We **SWEPT** this file last week, see `src/archivey/a.py`."
    )
    assert (markers, malformed) == ([], [])


def test_a_missing_required_field_is_reported_not_counted() -> None:
    """Silently dropping it would undercount; silently accepting it would hide a bug."""
    line = marker().replace(" head=94468bd", "")
    markers, malformed = sweep.parse_markers(line)
    assert markers == []
    assert malformed and "head" in malformed[0]


def test_a_non_integer_line_count_is_reported_not_counted() -> None:
    markers, malformed = sweep.parse_markers(marker(lines="many"))  # type: ignore[arg-type]
    assert markers == []
    assert malformed and "integers" in malformed[0]


def test_an_extra_field_does_not_disturb_the_required_ones() -> None:
    """`backfilled=` rides on the sixteen reconstructed markers and means nothing here."""
    markers, malformed = sweep.parse_markers(marker(extra=" backfilled=2026-09-19"))
    assert malformed == []
    assert markers[0].lines == 100


def test_ids_are_opaque() -> None:
    """A finding ID is never renumbered, so `ids=` need not share the `pass=` prefix."""
    markers, malformed = sweep.parse_markers(marker(batch="S16", ids="R1-K1,R2-K7"))
    assert malformed == []
    assert markers[0].batch == "S16"


# --- counting rules -----------------------------------------------------------------


def test_a_re_sweep_counts_the_file_once_and_the_newest_read_wins() -> None:
    markers, _ = sweep.parse_markers(
        marker(date="2026-09-08", lines=81) + "\n" + marker(date="2026-09-19", lines=93)
    )
    latest = sweep.newest_per_path(markers)
    assert list(latest) == ["src/archivey/a.py"]
    assert latest["src/archivey/a.py"].lines == 93


def test_the_newest_wins_whatever_order_the_comments_arrive_in() -> None:
    markers, _ = sweep.parse_markers(
        marker(date="2026-09-19", lines=93) + "\n" + marker(date="2026-09-08", lines=81)
    )
    assert sweep.newest_per_path(markers)["src/archivey/a.py"].lines == 93


def test_two_markers_in_one_pass_are_a_double_post() -> None:
    """Not a re-sweep: either two agents read the same file or one posted twice."""
    markers, _ = sweep.parse_markers(marker() + "\n" + marker())
    assert sweep.duplicates_within_a_pass(markers) == [("src/archivey/a.py", "S1", 2)]


def test_the_same_file_in_two_passes_is_not_a_double_post() -> None:
    markers, _ = sweep.parse_markers(
        marker(batch="S1", date="2026-09-17")
        + "\n"
        + marker(batch="S9", date="2026-09-19")
    )
    assert sweep.duplicates_within_a_pass(markers) == []


# --- ordering -----------------------------------------------------------------------


def test_batches_sort_by_number_not_by_string() -> None:
    """Lexicographic order puts S15 between S1 and S2, which reads as a gap in the plan."""
    batches = ["S2", "S15", "S0", "S16", "S1"]
    assert sorted(batches, key=sweep.batch_sort_key) == ["S0", "S1", "S2", "S15", "S16"]


def test_a_lettered_batch_sorts_beside_its_number() -> None:
    assert sorted(["S3b", "S4", "S3", "S3a"], key=sweep.batch_sort_key) == [
        "S3",
        "S3a",
        "S3b",
        "S4",
    ]


def test_an_unnumbered_batch_id_sorts_rather_than_raising() -> None:
    assert sorted(["S2", "backfill", "S1"], key=sweep.batch_sort_key) == [
        "S1",
        "S2",
        "backfill",
    ]


# --- drift --------------------------------------------------------------------------


def test_drift_is_measured_against_the_tree_not_the_marker() -> None:
    """`lines=` records the file as read; the tree says what it is now."""
    assert sweep.has_drifted(514, 716)
    assert sweep.has_drifted(155, 135)


def test_a_file_within_tolerance_has_not_drifted() -> None:
    assert not sweep.has_drifted(100, 109)
    assert not sweep.has_drifted(100, 91)


def test_the_tolerance_boundary_is_not_drift() -> None:
    """Exactly 10% is the edge of the band, not past it."""
    assert not sweep.has_drifted(100, 110)
    assert not sweep.has_drifted(100, 90)
    assert sweep.has_drifted(100, 111)
    assert sweep.has_drifted(100, 89)


def test_a_marker_recording_no_lines_is_not_infinite_drift() -> None:
    assert not sweep.has_drifted(0, 0)


# --- orphans and re-anchoring -------------------------------------------------------


def test_a_marker_for_a_missing_path_is_orphaned() -> None:
    markers, _ = sweep.parse_markers(marker("src/archivey/old.py"))
    latest = sweep.newest_per_path(markers)
    assert sweep.orphaned_paths(markers, latest, {"src/archivey/new.py": 100}) == [
        "src/archivey/old.py"
    ]


def test_a_re_anchor_marker_counts_the_new_path_and_answers_the_orphan() -> None:
    text = "\n".join(
        [
            marker("src/archivey/old.py"),
            marker("src/archivey/new.py", extra=" moved_from=src/archivey/old.py"),
        ]
    )
    markers, malformed = sweep.parse_markers(text)
    assert malformed == []
    latest = sweep.newest_per_path(markers)
    tree = {"src/archivey/new.py": 100}
    assert "src/archivey/new.py" in latest
    assert latest["src/archivey/new.py"].moved_from == "src/archivey/old.py"
    assert sweep.orphaned_paths(markers, latest, tree) == []


def test_a_re_anchor_whose_own_path_is_gone_answers_nothing() -> None:
    """Only a marker that itself counts can vouch for the path it replaced."""
    text = "\n".join(
        [
            marker("src/archivey/old.py"),
            marker("src/archivey/gone.py", extra=" moved_from=src/archivey/old.py"),
        ]
    )
    markers, _ = sweep.parse_markers(text)
    latest = sweep.newest_per_path(markers)
    assert sweep.orphaned_paths(markers, latest, {"src/archivey/new.py": 100}) == [
        "src/archivey/gone.py",
        "src/archivey/old.py",
    ]


def test_a_re_sweep_after_a_re_anchor_keeps_the_old_path_answered() -> None:
    """The re-sweep supersedes the re-anchor for coverage, not for the orphan report."""
    text = "\n".join(
        [
            marker("src/archivey/old.py"),
            marker("src/archivey/new.py", extra=" moved_from=src/archivey/old.py"),
            marker("src/archivey/new.py", batch="S30", date="2026-10-01"),
        ]
    )
    markers, _ = sweep.parse_markers(text)
    latest = sweep.newest_per_path(markers)
    assert latest["src/archivey/new.py"].batch == "S30"
    assert sweep.orphaned_paths(markers, latest, {"src/archivey/new.py": 100}) == []
