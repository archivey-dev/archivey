"""Audit reproducers for the extraction coordinator (2026-09-28 security audit).

Each test asserts the promised behaviour and is marked ``xfail(strict=True)`` until the
bug is fixed; the ``reason`` names the defect. Triage is pending.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import archivey
from archivey import ExtractionStatus
from archivey.cli.exit_codes import EXIT_OK
from archivey.cli.main import main
from archivey.diagnostics import (
    DiagnosticCode,
    MemberNameControlsContext,
    SymlinkTargetContext,
)
from tests.conftest import requires_binary
from tests.extract_util import open_and_extract
from tests.test_link_target_cap import _sevenzip_with_link


def _build_tar(path: Path, entries: list[tuple[str, str, object]]) -> None:
    with tarfile.open(path, "w") as tf:
        for name, kind, extra in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert isinstance(extra, bytes)
                info.size = len(extra)
                tf.addfile(info, io.BytesIO(extra))
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


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("streaming", [False, True])
def test_symlink_made_escaping_by_a_later_member_is_not_left_on_disk(
    tmp_path: Path, streaming: bool
) -> None:
    (tmp_path / "secret").write_text("OUTSIDE")
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("l", "sym", "a/../secret"), ("a", "sym", ".")])
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        reader.extract_all(dest, on_error="continue")

    # docs/extracting.md: "Escaping links are removed and rejected." After the run no
    # link under dest may resolve outside it.
    dest_root = dest.resolve()
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            path = Path(root) / name
            if path.is_symlink():
                resolved = path.resolve()
                assert resolved == dest_root or resolved.is_relative_to(dest_root), (
                    f"{path} -> {os.readlink(path)} resolves to {resolved}"
                )


@pytest.mark.parametrize("streaming", [False, True])
def test_hardlink_to_directory_member_reports_an_accurate_error(
    tmp_path: Path, streaming: bool
) -> None:
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("d", "dir", None), ("h", "hard", "d")])

    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out", on_error="continue")

    by_name = {r.member.name.rstrip("/"): r for r in report.results}
    assert by_name["d"].status is ExtractionStatus.EXTRACTED
    link = by_name["h"]
    assert link.status is ExtractionStatus.FAILED
    message = str(link.error)
    assert "excluded" not in message
    assert "FILE member" not in message
    assert "director" in message.lower()


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_empty_symlink_target_is_not_an_untyped_os_error(tmp_path: Path) -> None:
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("s", "sym", ""), ("f", "file", b"data")])

    # docs/extracting.md: "genuine I/O errors propagate unchanged". An empty target is
    # a property of the archive, not of the filesystem, so it must be reported as a
    # typed outcome (LINK_TARGET_UNAVAILABLE or an ArchiveyError), not an OSError.
    report = open_and_extract(archive, tmp_path / "out")

    by_name = {r.member.name: r for r in report.results}
    link = by_name["s"]
    assert link.error is None or isinstance(link.error, archivey.ArchiveyError)
    assert by_name["f"].status is ExtractionStatus.EXTRACTED


def _empty_target_archive(kind: str, tmp_path: Path) -> Path:
    """An archive of ``kind`` holding ``link``, a symlink whose stored target is empty.

    Named as ``_sevenzip_with_link`` names its members, with ``target.txt`` beside it.
    """
    if kind == "tar":
        archive = tmp_path / "a.tar"
        _build_tar(archive, [("link", "sym", ""), ("target.txt", "file", b"data")])
        return archive
    if kind == "zip":
        archive = tmp_path / "a.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, b"")
            zf.writestr("target.txt", b"data")
        return archive
    assert kind == "7z"
    archive = tmp_path / "a.7z"
    archive.write_bytes(_sevenzip_with_link(tmp_path, b"", sibling=b"data"))
    return archive


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "kind",
    [
        "tar",
        "zip",
        pytest.param("7z", marks=requires_binary("7z")),
    ],
)
def test_empty_symlink_target_is_reported_as_no_target(
    tmp_path: Path, kind: str, streaming: bool
) -> None:
    # An empty target is the archive recording no target: listed without one, with a
    # SYMLINK_TARGET_UNAVAILABLE diagnostic, and extracted as LINK_TARGET_UNAVAILABLE.
    archive = _empty_target_archive(kind, tmp_path)
    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out")
        link = next(r for r in report.results if r.member.name == "link")
        assert link.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
        assert link.error is None
        assert link.member.link_target is None
        reasons = [
            d.context.reason
            for d in link.member.diagnostics
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
            and isinstance(d.context, SymlinkTargetContext)
        ]
        assert reasons == ["target_empty"]
    assert not os.path.lexists(tmp_path / "out" / "link")
    assert (tmp_path / "out" / "target.txt").read_bytes() == b"data"


def test_member_under_an_earlier_file_member_is_not_an_untyped_os_error(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("d", "file", b"x"), ("d/f", "file", b"y")])

    # The conflict is in the archive, not the filesystem, so it must be a typed
    # per-member outcome and not abort the run as a bare OSError.
    report = open_and_extract(archive, tmp_path / "out", on_error="continue")
    by_name = {r.member.name: r for r in report.results}
    assert by_name["d"].status is ExtractionStatus.EXTRACTED
    child = by_name["d/f"]
    assert child.error is None or isinstance(child.error, archivey.ArchiveyError)

    with pytest.raises(archivey.ArchiveyError):
        open_and_extract(archive, tmp_path / "out2")


@pytest.mark.parametrize("child_kind", ["file", "dir"])
def test_member_under_an_earlier_file_member_names_the_file(
    tmp_path: Path, child_kind: str
) -> None:
    archive = tmp_path / "a.tar"
    child: tuple[str, str, object] = (
        ("d/f", "file", b"y") if child_kind == "file" else ("d/y", "dir", None)
    )
    _build_tar(archive, [("d", "file", b"x"), child, ("e", "file", b"z")])

    report = open_and_extract(archive, tmp_path / "out", on_error="continue")

    by_name = {r.member.name.rstrip("/"): r for r in report.results}
    failed = by_name[child[0]]
    assert failed.status is ExtractionStatus.FAILED
    assert isinstance(failed.error, archivey.ExtractionError)
    assert "'d'" in str(failed.error)
    assert (tmp_path / "out" / "d").read_bytes() == b"x"
    assert by_name["e"].status is ExtractionStatus.EXTRACTED


def test_member_under_a_preexisting_file_meets_the_overwrite_policy(
    tmp_path: Path,
) -> None:
    # The run did not write `d`: the caller did. `d/f` implies a directory `d`, and
    # that meets OverwritePolicy as an explicit `d/` entry would. The default ERROR
    # fails the member with an ExtractionError, not the FileExistsError of `mkdir`.
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("d/f", "file", b"y")])
    out = tmp_path / "out"
    out.mkdir()
    (out / "d").write_bytes(b"mine")

    with pytest.raises(archivey.ExtractionError, match="Destination already exists"):
        open_and_extract(archive, out)
    assert (out / "d").read_bytes() == b"mine"


def test_cli_test_passes_links_with_no_target_or_an_outside_target(
    tmp_path: Path,
) -> None:
    # `archivey test` re-reads only a link whose target listing could not produce. A
    # link that records no target, or whose target is read and points outside the
    # archive, is not a fault.
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, target in (("empty", b""), ("outside", b"../elsewhere")):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
        zf.writestr("f", b"data")

    assert main(["test", str(archive)]) == EXIT_OK


_BIDI_TARGET = "evil\u202egnp.exe"


def _bidi_target_archive(kind: str, tmp_path: Path) -> Path:
    """A ``kind`` archive whose symlink ``link`` stores ``_BIDI_TARGET``."""
    if kind == "tar":
        archive = tmp_path / "a.tar"
        _build_tar(archive, [("link", "sym", _BIDI_TARGET)])
        return archive
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, _BIDI_TARGET.encode("utf-8"))
    return archive


def _target_bidi_contexts(member: archivey.ArchiveMember) -> list[object]:
    return [
        d.context
        for d in member.diagnostics
        if d.code is DiagnosticCode.MEMBER_NAME_BIDI_CONTROL
    ]


# tar: the target is in the header. zip: the target is the member's data.
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_link_target_bidi_control_is_reported_once(
    tmp_path: Path, kind: str, streaming: bool
) -> None:
    archive = _bidi_target_archive(kind, tmp_path)
    with archivey.open_archive(archive, streaming=streaming) as reader:
        if not streaming:
            # Listing reads the target; extraction then looks at it again, and must
            # not report it a second time.
            reader.members()
        report = reader.extract_all(tmp_path / "out", on_error="continue")
        (result,) = report.results
        link = result.member
        # Presented exactly as stored.
        assert link.link_target == _BIDI_TARGET
        (context,) = _target_bidi_contexts(link)
        (diagnostic,) = [
            d
            for d in link.diagnostics
            if d.code is DiagnosticCode.MEMBER_NAME_BIDI_CONTROL
        ]
    assert diagnostic.message.startswith("Link target of 'link' contains a bidi")
    assert isinstance(context, MemberNameControlsContext)
    assert context.field == "link_target"
    assert context.member_name == "link"
    assert context.controls == "U+202E"
    assert context.archive_name == str(archive)
    assert context.raw_name_base64 == "bGluaw=="  # b"link"
    assert context.member_id == link._member_id


def test_member_name_bidi_control_context_says_name(tmp_path: Path) -> None:
    archive = tmp_path / "a.tar"
    _build_tar(archive, [("evil\u202egnp.exe", "file", b"x")])
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
        (context,) = _target_bidi_contexts(member)
        (diagnostic,) = member.diagnostics
    assert diagnostic.message.startswith("Member name contains a bidi")
    assert isinstance(context, MemberNameControlsContext)
    assert context.field == "name"
    assert context.archive_name == str(archive)


def test_byte_cap_message_counts_only_what_was_written() -> None:
    from archivey.internal.bomb_tracker import BombTracker

    tracker = BombTracker(max_bytes=100, max_ratio=None)
    tracker.count(60)
    with pytest.raises(archivey.ResourceLimitError) as info:
        tracker.count(60)
    # The refused chunk was never written, so it is not reported or counted as written.
    assert "written 60 bytes; the next 60-byte chunk would make 120" in str(info.value)
    assert tracker.total_bytes == 60
    with pytest.raises(archivey.ResourceLimitError, match="written 60 bytes"):
        tracker.count_copy(41, at_link_limit=False)
    tracker.count_copy(40, at_link_limit=False)
    assert tracker.total_bytes == 100
