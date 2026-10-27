"""Tests for MemberSelector collection form (Phase 5 stage 4)."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import (
    ARCHIVE_INTEGRITY_CODES,
    DiagnosticCode,
    DiagnosticPolicy,
    DiagnosticSummary,
    SelectorUnmatchedContext,
)
from archivey.exceptions import DiagnosticRaisedError


def _tar_with_duplicate_names() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for content in (b"first", b"second"):
            info = tarfile.TarInfo("dup.txt")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_stream_members_name_selects_all_duplicates() -> None:
    with open_archive(io.BytesIO(_tar_with_duplicate_names())) as ar:
        selected = [
            (member.name, stream.read() if stream is not None else None)
            for member, stream in ar.stream_members(members=["dup.txt"])
        ]
    assert selected == [("dup.txt", b"first"), ("dup.txt", b"second")]


def test_stream_members_member_selects_by_identity() -> None:
    with open_archive(io.BytesIO(_tar_with_duplicate_names())) as ar:
        first, second = ar.members()
        selected = [
            stream.read() if stream is not None else None
            for _member, stream in ar.stream_members(members=[first])
        ]
    assert selected == [b"first"]
    assert first is not second


def test_stream_members_mixed_collection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in (("keep.txt", b"keep"), ("skip.txt", b"skip")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        skip = ar.get("skip.txt")
        assert skip is not None
        selected = [
            member.name
            for member, _stream in ar.stream_members(members=["keep.txt", skip])
        ]
    assert selected == ["keep.txt", "skip.txt"]


class _CallableNames(list):
    """A selector that satisfies both arms of the ``members=`` union.

    ``Collection`` is not final, so an object can be a collection of names *and*
    callable. Which arm wins used to fall out of the order of the checks in
    :func:`archivey.internal.selection.normalize_member_selector`; it is now a
    decision, and this class is what pins it.
    """

    def __call__(self, member: object) -> bool:
        return True


def test_stream_members_callable_collection_is_read_as_a_collection() -> None:
    """A selector that is both callable and a collection selects as a collection.

    Mutant: move the ``callable(members)`` check back above the collection arm and
    this returns both members, because the predicate answers ``True`` for every one.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in (("keep.txt", b"keep"), ("skip.txt", b"skip")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        selected = [
            member.name
            for member, _stream in ar.stream_members(
                members=_CallableNames(["keep.txt"])
            )
        ]
    assert selected == ["keep.txt"]


# --- Exact name matching and unmatched entries (change member-selector-exact-names) ---


def _tar(entries: list[tuple[str, bytes | None]]) -> bytes:
    """A TAR of ``(name, content)``; ``None`` content makes a directory entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _zip(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def _unmatched(summary: DiagnosticSummary) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for diagnostic in summary.retained:
        if diagnostic.code is DiagnosticCode.MEMBER_SELECTOR_UNMATCHED:
            context = diagnostic.context
            assert isinstance(context, SelectorUnmatchedContext)
            found.append((context.entry, context.entry_kind))
    return found


_DIR_TAR = [("dir", None), ("dir/f.txt", b"f")]


def test_a_name_without_the_slash_does_not_select_the_directory() -> None:
    """Names match exactly: ``"dir"`` is not ``"dir/"``, and the miss is reported.

    Mutant: add the ``name + "/"`` spelling to the selector's name keys and ``dir/`` is
    selected with no diagnostic.
    """
    with open_archive(io.BytesIO(_tar(_DIR_TAR))) as ar:
        assert [m.name for m in ar.members()] == ["dir/", "dir/f.txt"]
        assert list(ar.stream_members(members=["dir"])) == []
        assert _unmatched(ar.diagnostics) == [("dir", "name")]


def test_extract_all_selects_the_directory_by_its_stored_name(tmp_path: Path) -> None:
    with open_archive(io.BytesIO(_tar(_DIR_TAR))) as ar:
        report = ar.extract_all(tmp_path, members=["dir/"])
    assert [r.member.name for r in report] == ["dir/"]
    assert (tmp_path / "dir").is_dir()
    assert not (tmp_path / "dir" / "f.txt").exists()
    assert _unmatched(report.diagnostics) == []


def test_a_name_with_the_slash_does_not_select_a_file() -> None:
    with open_archive(io.BytesIO(_tar([("x", b"file")]))) as ar:
        assert [m.name for m, _s in ar.stream_members(members=["x/"])] == []
        assert _unmatched(ar.diagnostics) == [("x/", "name")]


def test_a_name_selects_only_the_member_with_that_exact_name() -> None:
    with open_archive(io.BytesIO(_tar([("x", b"file"), ("x", None)]))) as ar:
        assert [m.name for m, _s in ar.stream_members(members=["x"])] == ["x"]
        assert [m.name for m, _s in ar.stream_members(members=["x/"])] == ["x/"]


def test_stream_members_reports_each_unmatched_name_once() -> None:
    with open_archive(io.BytesIO(_tar([("a.txt", b"a")]))) as ar:
        selected = [
            m.name
            for m, _s in ar.stream_members(
                members=["nope.txt", "a.txt", "nope.txt", "other"]
            )
        ]
        assert selected == ["a.txt"]
        assert _unmatched(ar.diagnostics) == [
            ("nope.txt", "name"),
            ("other", "name"),
        ]


def test_stream_members_stopped_early_reports_nothing() -> None:
    """An entry can still match a later member, so a pass the caller left early has
    no answer to give."""
    with open_archive(io.BytesIO(_tar([("a.txt", b"a"), ("b.txt", b"b")]))) as ar:
        for _member, _stream in ar.stream_members(members=["a.txt", "b.txt", "z"]):
            break
        assert _unmatched(ar.diagnostics) == []


def test_a_predicate_selector_reports_nothing() -> None:
    with open_archive(io.BytesIO(_tar([("a.txt", b"a")]))) as ar:
        assert list(ar.stream_members(members=lambda m: False)) == []
        assert _unmatched(ar.diagnostics) == []


def test_a_member_from_another_reader_is_reported_by_name() -> None:
    data = _tar([("a.txt", b"a")])
    with open_archive(io.BytesIO(data)) as other:
        foreign = other.members()[0]
    with open_archive(io.BytesIO(data)) as ar:
        assert list(ar.stream_members(members=[foreign])) == []
        assert _unmatched(ar.diagnostics) == [("a.txt", "member")]


def test_extract_all_reports_unmatched_after_a_scanned_pass(tmp_path: Path) -> None:
    """TAR has no free member list, so the answer comes at the end of the pass."""
    with open_archive(io.BytesIO(_tar([("a.txt", b"a")]))) as ar:
        report = ar.extract_all(tmp_path, members=["a.txt", "typo.txt"])
    assert [r.member.name for r in report] == ["a.txt"]
    assert _unmatched(report.diagnostics) == [("typo.txt", "name")]


def test_extract_all_on_a_forward_only_stream_reports_unmatched(tmp_path: Path) -> None:
    source = io.BytesIO(_tar([("a.txt", b"a")]))
    with open_archive(source, streaming=True) as ar:
        report = ar.extract_all(tmp_path, members=["typo.txt"])
    assert list(report) == []
    assert _unmatched(report.diagnostics) == [("typo.txt", "name")]


def test_extract_all_with_a_free_list_refuses_before_writing(tmp_path: Path) -> None:
    """ZIP lists for free, so a RAISE disposition refuses with nothing on disk."""
    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.MEMBER_SELECTOR_UNMATCHED}
        )
    )
    data = _zip([("a.txt", b"a")])
    dest = tmp_path / "out" / "deeper"
    with (
        open_archive(io.BytesIO(data), config=config) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.extract_all(dest, members=["a.txt", "typo.txt"])
    assert list(tmp_path.iterdir()) == []


def test_extract_all_with_a_free_list_collects_by_default(tmp_path: Path) -> None:
    with open_archive(io.BytesIO(_zip([("a.txt", b"a")]))) as ar:
        report = ar.extract_all(tmp_path, members=["typo.txt", "a.txt"])
    assert [r.member.name for r in report] == ["a.txt"]
    assert _unmatched(report.diagnostics) == [("typo.txt", "name")]


@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
@pytest.mark.parametrize("fmt", ["zip", "tar"])
def test_extract_all_reads_a_one_shot_iterable_once(
    tmp_path: Path, fmt: str, streaming: bool
) -> None:
    """A generator passed as ``members=`` selects the same members as a list.

    A generator can be read once, so ``extract_all()`` must read it once: a second
    read finds it empty, extracts nothing and reports nothing.

    Mutant: normalize the caller's ``members`` again inside the coordinator and the
    report is empty, with no unmatched entry.
    """
    if fmt == "zip":
        data = _zip([("a.txt", b"a"), ("b.txt", b"b")])
    else:
        data = _tar([("a.txt", b"a"), ("b.txt", b"b")])
    with open_archive(io.BytesIO(data), streaming=streaming) as ar:
        report = ar.extract_all(tmp_path, members=(n for n in ["a.txt", "typo.txt"]))
    assert [r.member.name for r in report] == ["a.txt"]
    assert (tmp_path / "a.txt").read_bytes() == b"a"
    assert not (tmp_path / "b.txt").exists()
    assert _unmatched(report.diagnostics) == [("typo.txt", "name")]


def test_stream_members_reads_a_one_shot_iterable_once() -> None:
    with open_archive(io.BytesIO(_zip([("a.txt", b"a"), ("b.txt", b"b")]))) as ar:
        selected = [
            m.name for m, _s in ar.stream_members(n for n in ["b.txt", "typo.txt"])
        ]
        assert selected == ["b.txt"]
        assert _unmatched(ar.diagnostics) == [("typo.txt", "name")]


def test_strict_policy_does_not_raise_on_an_unmatched_entry(tmp_path: Path) -> None:
    """Argument hygiene, not archive integrity: out of ``STRICT``."""
    assert DiagnosticCode.MEMBER_SELECTOR_UNMATCHED not in ARCHIVE_INTEGRITY_CODES
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(io.BytesIO(_zip([("a.txt", b"a")])), config=config) as ar:
        report = ar.extract_all(tmp_path, members=["typo.txt"])
    assert _unmatched(report.diagnostics) == [("typo.txt", "name")]


_RAISE_UNMATCHED = ArchiveyConfig(
    diagnostic_policy=DiagnosticPolicy(
        raise_on={DiagnosticCode.MEMBER_SELECTOR_UNMATCHED}
    )
)


def test_extract_all_raise_on_a_scanned_format_keeps_what_was_written(
    tmp_path: Path,
) -> None:
    """TAR knows the answer only at the end of the pass, so under RAISE the members
    before it are already on disk when the error replaces the report."""
    data = _tar([("a.txt", b"a"), ("b.txt", b"b")])
    with (
        open_archive(io.BytesIO(data), config=_RAISE_UNMATCHED) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.extract_all(tmp_path, members=["a.txt", "typo.txt"])
    assert (tmp_path / "a.txt").read_bytes() == b"a"
    assert not (tmp_path / "b.txt").exists()


def test_stream_members_raise_comes_after_the_last_member() -> None:
    data = _tar([("a.txt", b"a"), ("b.txt", b"b")])
    seen: list[str] = []
    with (
        open_archive(io.BytesIO(data), config=_RAISE_UNMATCHED) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        for member, _stream in ar.stream_members(members=["a.txt", "typo.txt"]):
            seen.append(member.name)
    assert seen == ["a.txt"]


def test_get_matches_the_stored_directory_name_exactly() -> None:
    """get() matches names exactly, the same as members=."""
    with open_archive(io.BytesIO(_tar(_DIR_TAR))) as ar:
        assert ar.get("dir") is None
        member = ar.get("dir/")
        assert member is not None
        assert member.name == "dir/"


def test_a_repeated_member_entry_is_reported_once() -> None:
    data = _tar([("a.txt", b"a")])
    with open_archive(io.BytesIO(data)) as other:
        foreign = other.members()[0]
    with open_archive(io.BytesIO(data)) as ar:
        assert list(ar.stream_members(members=[foreign, foreign])) == []
        assert _unmatched(ar.diagnostics) == [("a.txt", "member")]


def test_the_unmatched_report_names_the_directory_spelling() -> None:
    """``"dir"`` against ``dir/`` is the one miss the strict rule creates, so its
    message names the stored spelling. A plain typo gets no such hint."""
    with open_archive(io.BytesIO(_tar(_DIR_TAR))) as ar:
        list(ar.stream_members(members=["dir", "typo"]))
        messages = {
            d.context.entry: d.message
            for d in ar.diagnostics.retained
            if isinstance(d.context, SelectorUnmatchedContext)
        }
    assert "'dir/'" in messages["dir"]
    assert "archive holds" not in messages["typo"]


def test_a_symlink_target_without_the_slash_resolves_to_the_directory() -> None:
    """Link targets are raw names, which carry no trailing ``/``; lookup tries both.

    Mutant: make ``link_target_name_keys`` return only the name itself and
    ``link_target_member`` becomes ``None``.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        directory = tarfile.TarInfo("subdir")
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        link = tarfile.TarInfo("subdir_link")
        link.type = tarfile.SYMTYPE
        link.linkname = "subdir"
        tar.addfile(link)
    with open_archive(io.BytesIO(buf.getvalue())) as ar:
        member = ar.get("subdir_link")
        assert member is not None
        assert member.link_target_member is not None
        assert member.link_target_member.name == "subdir/"
