"""A symlink that a later member makes escape is removed and reported BLOCKED.

Threat model O22. A symlink is checked against the live tree when it is created, but a
later member can change what it resolves to: ``l -> a/../secret`` is inside the
destination while ``a`` does not exist, and outside it once ``a -> .`` is extracted.
The coordinator records which destination paths each link's resolution depended on,
and when a later member changes one of them it rechecks those links and removes any
that now escape.
"""

from __future__ import annotations

import io
import os
import tarfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import archivey
from archivey import (
    ExtractionLimits,
    ExtractionStatus,
    FilterRejectionError,
    ResourceLimitError,
)
from archivey.internal import extraction, filters, link_watch
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.bomb_tracker import BombTracker
from archivey.internal.extraction import (
    ExtractionCoordinator,
    _RunState,
    _symlink_problem,
)
from archivey.types import ArchiveMember, MemberType

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")

Entry = tuple[str, str, str | bytes | None]


def _build_tar(path: Path, entries: list[Entry]) -> None:
    with tarfile.open(path, "w") as tf:
        for name, kind, extra in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = extra if isinstance(extra, bytes) else b"data"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = str(extra)
                tf.addfile(info)
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = str(extra)
                tf.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)


def _escaping_links(dest: Path) -> list[str]:
    """Every link under ``dest`` that resolves outside it, as ``name -> target``."""
    dest_root = dest.resolve()
    found = []
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            path = Path(root) / name
            if path.is_symlink():
                resolved = path.resolve()
                if not (resolved == dest_root or resolved.is_relative_to(dest_root)):
                    found.append(f"{path.relative_to(dest)} -> {os.readlink(path)}")
    return found


def _extract(
    tmp_path: Path,
    entries: list[Entry],
    *,
    streaming: bool,
    **kwargs: object,
) -> tuple[Path, dict[str, archivey.ExtractionResult]]:
    (tmp_path / "secret").write_text("OUTSIDE")
    archive = tmp_path / "a.tar"
    _build_tar(archive, entries)
    dest = tmp_path / "out"
    kwargs.setdefault("on_error", "continue")
    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(dest, **kwargs)
    by_name: dict[str, archivey.ExtractionResult] = {}
    for result in report.results:
        by_name[result.member.name.rstrip("/")] = result
    return dest, by_name


def _assert_blocked_as_escape(result: archivey.ExtractionResult) -> None:
    assert result.status is ExtractionStatus.BLOCKED
    assert result.path is None
    assert isinstance(result.error, FilterRejectionError)
    assert "escapes" in str(result.error)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_link_made_escaping_by_a_later_symlink_is_removed(
    tmp_path: Path, streaming: bool
) -> None:
    dest, results = _extract(
        tmp_path, [("l", "sym", "a/../secret"), ("a", "sym", ".")], streaming=streaming
    )

    _assert_blocked_as_escape(results["l"])
    assert results["a"].status is ExtractionStatus.EXTRACTED
    assert not os.path.lexists(dest / "l")
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_a_loop_a_later_symlink_closes_is_named_as_a_loop(
    tmp_path: Path, streaming: bool
) -> None:
    # `p -> q/p` dangles inside dest when written; `q -> .` then closes the loop.
    dest, results = _extract(
        tmp_path, [("p", "sym", "q/p"), ("q", "sym", ".")], streaming=streaming
    )

    result = results["p"]
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message == (
        "Symlink target is part of a symlink loop: a later member changed a path it "
        "resolves through"
    )
    assert results["q"].status is ExtractionStatus.EXTRACTED
    assert not os.path.lexists(dest / "p")


@pytest.mark.parametrize("streaming", [False, True])
def test_the_link_is_gone_before_the_next_member_is_handled(
    tmp_path: Path, streaming: bool
) -> None:
    # "Not left on disk" is not enough: nothing may see the escaping link between
    # members. Progress reports arrive after each member, so they are the probe.
    seen: list[tuple[str, list[str]]] = []
    dest = tmp_path / "out"

    def probe(progress: archivey.ExtractionProgress) -> None:
        seen.append((progress.member.name, _escaping_links(dest)))

    _extract(
        tmp_path,
        [("l", "sym", "a/../secret"), ("a", "sym", "."), ("f", "file", b"x")],
        streaming=streaming,
        on_progress=probe,
    )

    assert [name for name, _ in seen] == ["l", "a", "f"]
    assert all(escaping == [] for _, escaping in seen), seen


@pytest.mark.parametrize("streaming", [False, True])
def test_progress_tallies_follow_the_revision(tmp_path: Path, streaming: bool) -> None:
    reports: list[archivey.ExtractionProgress] = []
    _extract(
        tmp_path,
        [("l", "sym", "a/../secret"), ("a", "sym", ".")],
        streaming=streaming,
        on_progress=reports.append,
    )

    # ``l`` was reported extracted when it was written; the report after ``a``
    # counts it as blocked instead.
    assert (reports[0].members_extracted, reports[0].members_blocked) == (1, 0)
    assert (reports[-1].members_extracted, reports[-1].members_blocked) == (1, 1)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_link_escaping_through_a_chain_of_links_is_removed(
    tmp_path: Path, streaming: bool
) -> None:
    # ``l`` never names ``b``: it reaches it through ``a``. When ``b -> .`` appears,
    # ``a`` still resolves inside, but ``l`` now climbs out of the root.
    dest, results = _extract(
        tmp_path,
        [("l", "sym", "a/../secret"), ("a", "sym", "b"), ("b", "sym", ".")],
        streaming=streaming,
    )

    _assert_blocked_as_escape(results["l"])
    assert results["a"].status is ExtractionStatus.EXTRACTED
    assert results["b"].status is ExtractionStatus.EXTRACTED
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_a_link_through_a_removed_link_is_rechecked(
    tmp_path: Path, streaming: bool
) -> None:
    # ``m`` resolves through ``l``, which lands three levels down. Once ``l`` escapes
    # and is removed, ``l/../..`` is read lexically, and from there ``m`` climbs out.
    dest, results = _extract(
        tmp_path,
        [
            ("d/e/f/", "dir", None),
            ("l", "sym", "a/../d/e/f"),
            ("m", "sym", "l/../../secret"),
            ("a", "sym", "."),
        ],
        streaming=streaming,
    )

    _assert_blocked_as_escape(results["l"])
    _assert_blocked_as_escape(results["m"])
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_replace_swapping_a_directory_for_a_symlink_rechecks(
    tmp_path: Path, streaming: bool
) -> None:
    # ``a`` is a real directory when ``l`` is made. REPLACE removes it (only an empty
    # directory can be replaced) and puts a symlink in its place.
    dest = tmp_path / "out"
    (dest / "a").mkdir(parents=True)
    dest, results = _extract(
        tmp_path,
        [("l", "sym", "a/../secret"), ("a", "sym", ".")],
        streaming=streaming,
        overwrite="replace",
    )

    assert results["a"].status is ExtractionStatus.EXTRACTED
    _assert_blocked_as_escape(results["l"])
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_replace_swapping_a_symlink_for_a_directory_rechecks(
    tmp_path: Path, streaming: bool
) -> None:
    # The removal direction: ``x -> a/b`` makes ``x/../..`` land on the root. Once
    # ``x`` is a plain directory, ``x/../..`` is the root's parent.
    dest = tmp_path / "out"
    (dest / "a" / "b").mkdir(parents=True)
    (dest / "x").symlink_to("a/b")
    dest, results = _extract(
        tmp_path,
        [("l", "sym", "x/../../secret"), ("x/", "dir", None)],
        streaming=streaming,
        overwrite="replace",
    )

    assert results["l"].status is ExtractionStatus.BLOCKED
    assert (dest / "x").is_dir() and not (dest / "x").is_symlink()
    assert _escaping_links(dest) == []


@pytest.mark.parametrize(
    "later",
    [("x", "sym", "a"), ("x", "file", b"x"), ("x", "sym", "dropped")],
    ids=["symlink", "file", "filtered-out"],
)
def test_a_later_copy_of_the_same_name_rechecks_in_a_streaming_pass(
    tmp_path: Path, later: Entry
) -> None:
    # A streaming pass writes the first ``x`` and takes it back when the second copy
    # arrives, under the default overwrite policy: the second copy lands in its
    # place, or, when the filter drops it, the first one is removed.
    dest, results = _extract(
        tmp_path,
        [
            ("a/b/", "dir", None),
            ("x", "sym", "a/b"),
            ("l", "sym", "x/../../secret"),
            later,
        ],
        streaming=True,
        filter=lambda m: None if m.link_target == "dropped" else m,
    )

    assert results["l"].status is ExtractionStatus.BLOCKED
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_rename_rechecks_the_path_actually_written(
    tmp_path: Path, streaming: bool
) -> None:
    # ``A`` collides with ``a`` (STRICT compares names case-insensitively) and is
    # renamed to ``A (1)``, the component ``l`` named.
    dest, results = _extract(
        tmp_path,
        [
            ("a", "file", b"x"),
            ("l", "sym", "A (1)/../secret"),
            ("A", "sym", "."),
        ],
        streaming=streaming,
        overwrite="rename",
    )

    assert results["A"].path == dest / "A (1)"
    _assert_blocked_as_escape(results["l"])
    assert _escaping_links(dest) == []


def test_a_hardlink_placed_by_the_orphan_pass_rechecks(tmp_path: Path) -> None:
    # The second pass places ``x`` (a hardlink whose source the filter excluded) over
    # a symlink the destination already held, and ``l`` depended on that symlink.
    dest = tmp_path / "out"
    (dest / "a" / "b").mkdir(parents=True)
    (dest / "x").symlink_to("a/b")
    dest, results = _extract(
        tmp_path,
        [
            ("f", "file", b"content"),
            ("l", "sym", "x/../../secret"),
            ("x", "hard", "f"),
        ],
        streaming=False,
        overwrite="replace",
        filter=lambda m: None if m.name == "f" else m,
    )

    assert results["x"].status is ExtractionStatus.EXTRACTED
    assert results["l"].status is ExtractionStatus.BLOCKED
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_abort_on_blocked_member_stops_on_a_revised_link(
    tmp_path: Path, streaming: bool
) -> None:
    with pytest.raises(FilterRejectionError, match="escapes"):
        _extract(
            tmp_path,
            [("l", "sym", "a/../secret"), ("a", "sym", "."), ("f", "file", b"x")],
            streaming=streaming,
            abort_on={"blocked_member"},
        )
    dest = tmp_path / "out"
    assert _escaping_links(dest) == []
    assert not (dest / "f").exists()


@pytest.mark.parametrize("streaming", [False, True])
def test_a_revised_link_does_not_stop_the_run_under_on_error_stop(
    tmp_path: Path, streaming: bool
) -> None:
    # The revision is a policy block, not a failure, so OnError.STOP goes on.
    dest, results = _extract(
        tmp_path,
        [("l", "sym", "a/../secret"), ("a", "sym", "."), ("f", "file", b"x")],
        streaming=streaming,
        on_error="stop",
    )

    _assert_blocked_as_escape(results["l"])
    assert results["a"].status is ExtractionStatus.EXTRACTED
    assert results["f"].status is ExtractionStatus.EXTRACTED
    assert (dest / "f").read_bytes() == b"x"


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("prefix", ["", "/."], ids=["plain", "dot"])
def test_an_absolute_target_inside_the_destination_is_rechecked(
    tmp_path: Path, streaming: bool, prefix: str
) -> None:
    # An absolute target that lands inside the destination passes when created;
    # its components are the destination's own paths, not the link directory's.
    # A leading ``//`` is not a case here: it is a UNC root on Windows, so it is
    # refused before any of this on every OS (test_link_target_portability.py).
    dest_root = (tmp_path / "out").resolve()
    dest, results = _extract(
        tmp_path,
        [("l", "sym", f"{prefix}{dest_root}/a/../secret"), ("a", "sym", ".")],
        streaming=streaming,
    )

    _assert_blocked_as_escape(results["l"])
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("first", "second"),
    [("L", "l"), ("é", "é")],
    ids=["case", "normalization"],
)
def test_links_whose_names_differ_only_by_folding_are_both_rechecked(
    tmp_path: Path, streaming: bool, first: str, second: str
) -> None:
    # TRUSTED keeps both names, and a case-sensitive filesystem that does not
    # normalize holds both links. Recording the second must not forget the first.
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / first).touch()
    folds = (dest / second).exists()
    (dest / first).unlink()
    if folds:
        pytest.skip("the filesystem folds these two names into one")
    dest, results = _extract(
        tmp_path,
        [
            (first, "sym", "a/../secret"),
            (second, "sym", "b/../secret"),
            ("a", "sym", "."),
            ("b", "sym", "."),
        ],
        streaming=streaming,
        policy="trusted",
    )

    _assert_blocked_as_escape(results[first])
    _assert_blocked_as_escape(results[second])
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "entries",
    [
        # The component before ``..`` exists as a directory, before or after the link.
        [("a/", "dir", None), ("l", "sym", "a/../f"), ("f", "file", b"x")],
        [("l", "sym", "a/../f"), ("a/", "dir", None), ("f", "file", b"x")],
        # It becomes a symlink that keeps the target inside.
        [("d/e/", "dir", None), ("l", "sym", "a/../f"), ("a", "sym", "d/e")],
        # A build-tool shape: a relative link into a sibling package.
        [
            ("pkg/lib/", "dir", None),
            ("pkg/bin/tool", "sym", "../lib/../lib/main.js"),
            ("pkg/lib/main.js", "file", b"x"),
        ],
    ],
    ids=["dir-first", "dir-later", "symlink-inside", "sibling-package"],
)
def test_a_legitimate_dotdot_target_is_kept(
    tmp_path: Path, streaming: bool, entries: list[Entry]
) -> None:
    dest, results = _extract(tmp_path, entries, streaming=streaming)

    assert all(r.status is ExtractionStatus.EXTRACTED for r in results.values()), {
        name: (r.status, r.error) for name, r in results.items()
    }
    assert _escaping_links(dest) == []


def _node_modules_entries(packages: int) -> list[Entry]:
    """A ``node_modules``-shaped tree, links first so every target is created later."""
    entries: list[Entry] = [("node_modules/.bin/", "dir", None)]
    for i in range(packages):
        entries.append(
            (f"node_modules/.bin/p{i}", "sym", f"../p{i}/bin/../lib/cli.js"),
        )
    for i in range(packages):
        entries += [
            (f"node_modules/p{i}/bin/", "dir", None),
            (f"node_modules/p{i}/lib/cli.js", "file", b"x"),
            (f"node_modules/p{i}/bin/cli", "sym", "../lib/cli.js"),
        ]
    return entries


def _count_lstat_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packages: int
) -> int:
    calls = 0
    real_lstat = os.lstat

    def counting_lstat(path: object) -> os.stat_result:
        nonlocal calls
        calls += 1
        return real_lstat(path)

    work = tmp_path / str(packages)
    work.mkdir()
    with monkeypatch.context() as m:
        m.setattr(os, "lstat", counting_lstat)
        dest, results = _extract(work, _node_modules_entries(packages), streaming=True)
    assert all(r.status is ExtractionStatus.EXTRACTED for r in results.values())
    assert _escaping_links(dest) == []
    return calls


def test_symlink_heavy_extraction_stays_linear_in_link_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Resolving a link and walking its dependencies both cost one lstat per component
    # visited, and nothing here changes a path a link depends on. Doubling the
    # packages must roughly double the work, not quadruple it.
    small = _count_lstat_calls(tmp_path, monkeypatch, 100)
    large = _count_lstat_calls(tmp_path, monkeypatch, 200)

    assert small > 0
    assert large <= 2.2 * small, (small, large)


def test_rechecks_are_bounded_by_max_entries(tmp_path: Path) -> None:
    # Every ``x`` copy after the first replaces the one before it, and each
    # replacement rechecks every link that went through ``x``: links x copies work.
    # The bound stops the run instead, and nothing escaping is left behind.
    links = [(f"l{i}", "sym", f"x/../../f{i}") for i in range(30)]
    copies = [("x", "sym", "a/b")] * 30
    with pytest.raises(ResourceLimitError, match="max_entries"):
        _extract(
            tmp_path,
            [("a/b/", "dir", None), ("x", "sym", "a/b"), *links, *copies],
            streaming=True,
            limits=ExtractionLimits(max_entries=200),
        )
    assert _escaping_links(tmp_path / "out") == []


def test_removing_a_link_rechecks_a_link_that_passed_through_it_earlier(
    tmp_path: Path,
) -> None:
    # A unit test of the index: the queue order can recheck ``m`` before ``l``, and
    # ``m`` passes while ``l`` is still there. Removing ``l`` changes where ``m``
    # resolves, so ``m`` must be rechecked again. ``escapes`` is a stub, because
    # extraction order cannot force this queue order.
    root = tmp_path.resolve()
    (root / "d").mkdir()
    (root / "l").symlink_to("a/../d")
    (root / "m").symlink_to("l/x")
    watch = link_watch.LinkWatch(root, budget=None)
    watch.track(root / "m", "l/x", result_index=0)
    watch.track(root / "l", "a/../d", result_index=1)
    calls: list[str] = []

    def escapes(path: Path, target: str) -> bool:
        calls.append(path.name)
        return path.name == "l" or not os.path.lexists(root / "l")

    watch.note_change(root / "a")
    outcome = watch.recheck(escapes)

    assert calls == ["m", "l", "m"]
    assert [link.path.name for link in outcome.escaped] == ["l", "m"]
    assert not os.path.lexists(root / "m")


def _refuse_unlinking(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make ``os.unlink`` of an entry called ``name`` fail, as a filesystem that
    refuses the removal does."""
    real_unlink = os.unlink

    def unlink(path: object, *args: object, **kwargs: object) -> None:
        if os.path.basename(os.fspath(path)) == name:  # type: ignore[arg-type]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[arg-type]
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "unlink", unlink)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_link_the_recheck_cannot_remove_ends_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    # The link stays on disk and leads out of the destination, so the run must not
    # go on as if it were removed, whatever ``on_error`` says.
    _refuse_unlinking(monkeypatch, "l")
    with pytest.raises(PermissionError) as raised:
        _extract(
            tmp_path,
            [("l", "sym", "a/../secret"), ("a", "sym", ".")],
            streaming=streaming,
        )
    assert "Could not remove symlink 'l', which is still on disk" in "".join(
        raised.value.__notes__
    )


def test_a_link_that_escapes_when_created_and_cannot_be_removed_ends_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No archive makes the creation-time resolution fail on POSIX after the
    # universal check passed, so the check is stubbed to report an escape.
    monkeypatch.setattr(
        extraction, "_symlink_problem", lambda *_args: filters.SYMLINK_ESCAPES
    )
    _refuse_unlinking(monkeypatch, "l")
    with pytest.raises(PermissionError):
        _extract(tmp_path, [("l", "sym", "x")], streaming=False)
    assert os.path.islink(tmp_path / "out" / "l")


def test_an_anti_item_deleting_a_symlink_rechecks(tmp_path: Path) -> None:
    # Exercised at the coordinator level, as in test_extraction's anti-item tests: a
    # backend reaches this only with a 7z anti-item whose name differs from the link's
    # by case alone.
    root = tmp_path / "out"
    (root / "a" / "b").mkdir(parents=True)
    (root / "x").symlink_to("a/b")
    (root / "l").symlink_to("x/../../secret")
    coordinator = ExtractionCoordinator()
    watch = link_watch.LinkWatch(root.resolve(), budget=None)
    coordinator._state = _RunState(
        dest=root,
        dest_root=root.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        written_paths={root / "x"},
        links=watch,
    )
    watch.track(root / "l", "x/../../secret", result_index=0)
    watch.recheck(lambda path, target: False)  # l passed when it was created

    anti = ArchiveMember(type=MemberType.ANTI, name="x")
    coordinator._apply_anti_item(anti, root / "x")
    outcome = watch.recheck(
        lambda path, target: _symlink_problem(path, target, root.resolve()) is not None
    )

    assert [link.path.name for link in outcome.escaped] == ["l"]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "target",
    ["m/../a/../secret", "./a/../secret", "m/./../a/../secret"],
    ids=["after-a-missing-component", "after-a-dot", "after-a-dot-and-dotdot"],
)
def test_the_walk_records_the_components_after_a_missing_one(
    tmp_path: Path, streaming: bool, target: str
) -> None:
    # ``m`` never exists, so ``m/..`` is taken lexically and the walk goes on to
    # ``a``. When ``a -> .`` appears, ``l`` climbs out: ``a`` must have been recorded
    # although a missing component and a ``..`` came before it.
    dest, results = _extract(
        tmp_path, [("l", "sym", target), ("a", "sym", ".")], streaming=streaming
    )

    _assert_blocked_as_escape(results["l"])
    assert _escaping_links(dest) == []


@pytest.mark.parametrize("streaming", [False, True])
def test_a_target_that_climbs_past_the_filesystem_root_is_rechecked(
    tmp_path: Path, streaming: bool
) -> None:
    # ``..`` at ``/`` stays at ``/``, so a relative target with more ``..`` than the
    # link is deep comes back into the destination by name.
    dest_root = (tmp_path / "out").resolve()
    climb = "../" * (len(dest_root.parts) + 2)
    target = f"{climb}{dest_root.relative_to('/')}/a/../secret"
    dest, results = _extract(
        tmp_path, [("l", "sym", target), ("a", "sym", ".")], streaming=streaming
    )

    _assert_blocked_as_escape(results["l"])
    assert _escaping_links(dest) == []


def _recorder(escape: bool) -> tuple[list[str], Callable[[Path, str], bool]]:
    """An ``escapes`` stub that answers ``escape`` and the names it was asked about."""
    calls: list[str] = []

    def escapes(path: Path, target: str) -> bool:
        calls.append(path.name)
        return escape

    return calls, escapes


def _watched(root: Path, *links: tuple[str, str]) -> link_watch.LinkWatch:
    """A watch over ``links`` created under ``root``, with the first recheck done."""
    watch = link_watch.LinkWatch(root, budget=None)
    for index, (name, target) in enumerate(links):
        (root / name).symlink_to(target)
        watch.track(root / name, target, result_index=index)
    watch.recheck(lambda path, target: False)
    return watch


def test_a_chain_of_64_links_is_followed_and_65_is_not(tmp_path: Path) -> None:
    # The walk follows up to 64 links, more than any kernel resolves: a change past
    # that point cannot move a resolution the OS would accept.
    root = tmp_path.resolve()
    for length, rechecked in ((64, True), (65, False)):
        base = root / str(length)
        base.mkdir()
        chain = [(f"l{i}", f"l{i + 1}") for i in range(length)]
        watch = _watched(base, *chain, (f"l{length}", "a/../x"))
        calls, escapes = _recorder(False)
        watch.note_change(base / "a")
        watch.recheck(escapes)
        assert ("l0" in calls) is rechecked, length


def test_the_recheck_budget_counts_one_per_resolution(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    for budget in (0, 1, 2, 3):
        base = root / str(budget)
        base.mkdir()
        watch = _watched(base, ("l1", "a/x"), ("l2", "a/x"), ("l3", "a/x"))
        watch._budget = budget
        calls, escapes = _recorder(False)
        watch.note_change(base / "a")
        outcome = watch.recheck(escapes)
        assert calls == ["l1", "l2", "l3"][:budget]
        # The links left when the budget runs out are removed, not left unchecked.
        assert [link.path.name for link in outcome.unchecked] == ["l1", "l2", "l3"][
            budget:
        ]
        assert sorted(p.name for p in base.iterdir()) == ["l1", "l2", "l3"][:budget]


def test_an_entry_that_replaced_a_watched_link_is_left_alone(tmp_path: Path) -> None:
    # A later member put a file where ``l1`` was: it is not the link that was
    # checked, so the recheck neither resolves nor removes it, and goes on to ``l2``.
    root = tmp_path.resolve()
    watch = _watched(root, ("l1", "a/x"), ("l2", "a/x"))
    (root / "l1").unlink()
    (root / "l1").write_text("a file now")
    calls, escapes = _recorder(True)
    watch.note_change(root / "a")
    outcome = watch.recheck(escapes)

    assert calls == ["l2"]
    assert [link.path.name for link in outcome.escaped] == ["l2"]
    assert (root / "l1").read_text() == "a file now"
    assert not os.path.lexists(root / "l2")


@pytest.mark.parametrize(
    ("replacement", "live"), [("a/x", True), ("other", False)], ids=["same", "other"]
)
def test_without_inode_numbers_a_link_is_told_apart_by_its_target(
    tmp_path: Path, replacement: str, live: bool
) -> None:
    # FUSE and network mounts can report inode 0 for every file.
    root = tmp_path.resolve()
    watch = _watched(root, ("l", "a/x"))
    (link,) = watch._by_path.values()
    link.identity = (0, 0)
    (root / "l").unlink()
    (root / "l").symlink_to(replacement)
    calls, escapes = _recorder(False)
    watch.note_change(root / "a")
    watch.recheck(escapes)

    assert calls == (["l"] if live else [])


def test_a_target_through_a_sibling_directory_is_not_indexed_under_the_root(
    tmp_path: Path,
) -> None:
    # ``../other/a`` is at the destination's depth but not inside it: a change at the
    # destination's own ``a`` cannot move it.
    root = (tmp_path / "out").resolve()
    root.mkdir()
    (tmp_path / "other").mkdir()
    watch = _watched(root, ("l", "../other/a/x"))
    calls, escapes = _recorder(False)
    watch.note_change(root / "a")
    watch.recheck(escapes)

    assert calls == []
