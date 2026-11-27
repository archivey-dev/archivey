"""The public names the CLI uses in place of library internals.

``archivey.paths.numbered_name``, ``ExtractionResult.rewrites`` (``NameRewrite``),
``ArchiveMember.link_target_unrecorded``, ``LinkTargetNotFoundError.reason``
(``LinkTargetNotFoundReason``) and ``ArchiveyUsageError.refused_member_type`` replaced
an internal import, two private-field reads and two error-message matches in
``archivey.cli``. Each gets its own contract test here, and the CLI tests at the end
pin that the CLI prints what it printed before.
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
from archivey import ExtractionPolicy, open_archive
from archivey.cli.exit_codes import EXIT_OK
from archivey.cli.main import main
from archivey.exceptions import LinkTargetNotFoundError, LinkTargetNotFoundReason
from archivey.internal.base_reader import MAX_LINK_TARGET_BYTES
from archivey.paths import numbered_name
from archivey.types import (
    ArchiveMember,
    ExtractionStatus,
    MemberType,
    NameRewrite,
    OverwritePolicy,
)


def _tar(path: Path, entries: list[tuple[str, str, bytes | str]]) -> Path:
    """A TAR of ``(name, kind, payload)``: ``kind`` is ``file``, ``dir``, ``sym`` or
    ``hard``."""
    with tarfile.open(path, "w") as tf:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert isinstance(payload, bytes)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            else:
                assert kind in ("sym", "hard") and isinstance(payload, str)
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = payload
                tf.addfile(info)
    return path


def _zip_symlinks(path: Path, links: dict[str, bytes]) -> Path:
    """A ZIP whose members are Unix symlinks storing ``links[name]`` as their target."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, target in links.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
        zf.writestr("f.txt", b"data")
    return path


# --- archivey.paths.numbered_name ---


# Nothing collects doctests, so the ``>>>`` examples in ``numbered_name``'s docstring
# are prose. Each of the three is a case below, which is what pins it: change both.
@pytest.mark.parametrize(
    ("name", "n", "is_dir", "expected"),
    [
        ("photo.jpg", 1, False, "photo (1).jpg"),
        ("photo.jpg", 12, False, "photo (12).jpg"),
        ("notes.tar.gz", 2, False, "notes.tar (2).gz"),
        ("README", 1, False, "README (1)"),
        (".bashrc", 1, False, ".bashrc (1)"),
        ("photos.2024", 1, True, "photos.2024 (1)"),
        ("dir", 3, True, "dir (3)"),
    ],
)
def test_numbered_name_spells_a_rename(
    name: str, n: int, is_dir: bool, expected: str
) -> None:
    assert numbered_name(name, n, is_dir=is_dir) == expected


def test_paths_is_public_and_not_re_exported() -> None:
    import archivey.paths

    assert archivey.paths.__all__ == ["match_glob", "match_tar_glob", "numbered_name"]
    assert "numbered_name" not in archivey.__all__
    assert not hasattr(archivey, "numbered_name")


@pytest.mark.parametrize("is_dir", [False, True], ids=["file", "dir"])
def test_extraction_renames_with_numbered_name(tmp_path: Path, is_dir: bool) -> None:
    """``OverwritePolicy.RENAME`` writes a collided member under the name this function
    gives, so a front end using it picks the name extraction would."""
    name = "photos.2024" if is_dir else "photo.jpg"
    out = tmp_path / "out"
    out.mkdir()
    # A file already there: a directory member would merge into a directory.
    (out / name).write_bytes(b"mine")
    archive = _tar(tmp_path / "a.tar", [(name, "dir" if is_dir else "file", b"1")])
    with open_archive(archive) as reader:
        report = reader.extract_all(out, overwrite=OverwritePolicy.RENAME)
    (result,) = report.results
    assert result.status is ExtractionStatus.EXTRACTED
    assert result.path == out / numbered_name(name, 1, is_dir=is_dir)
    assert (out / name).read_bytes() == b"mine"


# --- ExtractionResult.rewrites / NameRewrite ---


def _result_for(
    tmp_path: Path,
    name: str,
    policy: ExtractionPolicy,
    filter: archivey.types.MemberFilter | None = None,
) -> archivey.types.ExtractionResult:
    archive = _tar(tmp_path / "a.tar", [(name, "file", b"x")])
    with open_archive(archive) as reader:
        report = reader.extract_all(tmp_path / "out", policy=policy, filter=filter)
    (result,) = report.results
    assert result.status is ExtractionStatus.EXTRACTED
    return result


@pytest.mark.parametrize(
    ("name", "policy", "presented", "rewrites"),
    [
        ("plain.txt", ExtractionPolicy.STRICT, None, set()),
        ("/etc/x", ExtractionPolicy.STANDARD, "/etc/x", {NameRewrite.REROOTED}),
        ("/etc/x", ExtractionPolicy.TRUSTED, "/etc/x", {NameRewrite.REROOTED}),
        ("foo.", ExtractionPolicy.STRICT, "foo.", {NameRewrite.PORTABLE_NAME}),
        (
            "what?.txt",
            ExtractionPolicy.STANDARD,
            "what?.txt",
            {NameRewrite.PORTABLE_NAME},
        ),
        ("a\\b", ExtractionPolicy.STANDARD, "a\\b", {NameRewrite.PORTABLE_NAME}),
        (
            "/a/what?.txt",
            ExtractionPolicy.STANDARD,
            "/a/what?.txt",
            {NameRewrite.REROOTED, NameRewrite.PORTABLE_NAME},
        ),
        # TRUSTED re-roots but never respells.
        (
            "/a/what?.txt",
            ExtractionPolicy.TRUSTED,
            "/a/what?.txt",
            {NameRewrite.REROOTED},
        ),
    ],
    ids=[
        "none",
        "reroot",
        "reroot-trusted",
        "trailing-dot",
        "escape",
        "backslash",
        "reroot-and-escape",
        "reroot-trusted-no-escape",
    ],
)
def test_rewrites_names_each_rewrite_that_ran(
    tmp_path: Path,
    name: str,
    policy: ExtractionPolicy,
    presented: str | None,
    rewrites: set[NameRewrite],
) -> None:
    if policy is ExtractionPolicy.TRUSTED and "?" in name and os.name == "nt":
        pytest.skip("Windows refuses '?' in a name written as stored")
    result = _result_for(tmp_path, name, policy)
    assert result.presented_name == presented
    assert result.rewrites == rewrites
    assert isinstance(result.rewrites, frozenset)


def test_a_filter_rename_then_a_portable_rewrite_records_only_the_rewrite(
    tmp_path: Path,
) -> None:
    def rename(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name="renamed?.txt")

    result = _result_for(tmp_path, "/etc/x", ExtractionPolicy.STANDARD, rename)
    # The filter replaced the re-rooted name, so the re-root is not a rewrite.
    assert result.presented_name == "renamed?.txt"
    assert result.rewrites == {NameRewrite.PORTABLE_NAME}


def test_a_filter_rename_of_a_rerooted_name_is_no_rewrite(tmp_path: Path) -> None:
    def rename(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name="mine.txt")

    result = _result_for(tmp_path, "/etc/x", ExtractionPolicy.STANDARD, rename)
    assert result.presented_name is None
    assert result.rewrites == frozenset()


def test_rewrites_survive_when_a_streamed_copy_is_superseded(tmp_path: Path) -> None:
    """A streamed copy taken back when a later copy of its name arrives keeps the
    rewrites it recorded (``_supersede_written_copy`` rebuilds the result)."""
    archive = _tar(
        tmp_path / "a.tar", [("/etc/x", "file", b"1"), ("/etc/x", "file", b"2")]
    )
    with open_archive(archive, streaming=True) as reader:
        report = reader.extract_all(tmp_path / "out", policy=ExtractionPolicy.STANDARD)
    first, second = report.results
    assert first.status is ExtractionStatus.SUPERSEDED
    assert second.status is ExtractionStatus.EXTRACTED
    assert first.rewrites == second.rewrites == {NameRewrite.REROOTED}
    assert first.presented_name == second.presented_name == "/etc/x"


def test_rewrites_survive_the_second_pass_for_an_orphaned_hardlink(
    tmp_path: Path,
) -> None:
    """A hardlink whose source the filter dropped is written in the second pass, which
    rebuilds its result (``_revise_result``); the first pass's rewrites stay on it."""
    archive = _tar(
        tmp_path / "a.tar",
        [("file.txt", "file", b"data"), ("/etc/hard.txt", "hard", "file.txt")],
    )

    def drop_source(member: ArchiveMember) -> ArchiveMember | None:
        return None if member.name == "file.txt" else member

    with open_archive(archive) as reader:
        report = reader.extract_all(
            tmp_path / "out", policy=ExtractionPolicy.STANDARD, filter=drop_source
        )
    (result,) = report.results
    assert result.status is ExtractionStatus.EXTRACTED
    assert result.member.type is MemberType.HARDLINK
    assert result.rewrites == {NameRewrite.REROOTED}
    assert result.presented_name == "/etc/hard.txt"


# --- ArchiveMember.link_target_unrecorded ---


def test_link_target_unrecorded_is_true_only_for_a_link_the_archive_left_empty(
    tmp_path: Path,
) -> None:
    archive = _zip_symlinks(
        tmp_path / "a.zip",
        {
            "empty": b"",
            "inside": b"f.txt",
            "too-long": b"x" * (MAX_LINK_TARGET_BYTES + 1),
        },
    )
    with open_archive(archive) as reader:
        by_name = {m.name: m for m in reader.members()}
    assert by_name["empty"].link_target is None
    assert by_name["empty"].link_target_unrecorded
    # The archive stores this target; the reader refused to read it.
    assert by_name["too-long"].link_target is None
    assert not by_name["too-long"].link_target_unrecorded
    assert not by_name["inside"].link_target_unrecorded
    assert not by_name["f.txt"].link_target_unrecorded


def test_link_target_unrecorded_is_false_before_the_target_is_read(
    tmp_path: Path,
) -> None:
    """Under ``read_link_targets=False`` nothing has looked, so nothing is known."""
    archive = _zip_symlinks(tmp_path / "a.zip", {"empty": b""})
    config = archivey.ArchiveyConfig(read_link_targets=False)
    with open_archive(archive, config=config) as reader:
        link = reader.get("empty")
        assert link is not None
        assert link.link_target is None
        assert not link.link_target_unrecorded


def test_link_target_unrecorded_on_a_plain_member() -> None:
    assert not ArchiveMember(type=MemberType.FILE, name="f").link_target_unrecorded
    assert not ArchiveMember(type=MemberType.SYMLINK, name="l").link_target_unrecorded


# --- LinkTargetNotFoundError.reason ---


def _open_error(reader: archivey.ArchiveReader, name: str) -> LinkTargetNotFoundError:
    with pytest.raises(LinkTargetNotFoundError) as info:
        reader.open(name)
    return info.value


def test_reason_says_why_a_link_has_no_member_to_follow(tmp_path: Path) -> None:
    archive = _zip_symlinks(
        tmp_path / "a.zip",
        {
            "empty": b"",
            "too-long": b"x" * (MAX_LINK_TARGET_BYTES + 1),
            "missing": b"nowhere.txt",
            "loop-a": b"loop-b",
            "loop-b": b"loop-a",
        },
    )
    with open_archive(archive) as reader:
        assert (
            _open_error(reader, "empty").reason is LinkTargetNotFoundReason.NOT_RECORDED
        )
        assert (
            _open_error(reader, "too-long").reason
            is LinkTargetNotFoundReason.UNREADABLE
        )
        assert (
            _open_error(reader, "missing").reason is LinkTargetNotFoundReason.UNRESOLVED
        )
        cycle = _open_error(reader, "loop-a")
        assert cycle.reason is LinkTargetNotFoundReason.UNRESOLVED
        # Still a ReadError, as a cycle was before it became this type.
        assert isinstance(cycle, archivey.exceptions.ReadError)
        assert cycle.raw_message == "Link cycle detected"


def test_extraction_fails_a_link_with_the_same_reason(tmp_path: Path) -> None:
    archive = _zip_symlinks(
        tmp_path / "a.zip", {"too-long": b"x" * (MAX_LINK_TARGET_BYTES + 1)}
    )
    with open_archive(archive) as reader:
        report = reader.extract_all(tmp_path / "out", on_error="continue")
    link = next(r for r in report.results if r.member.name == "too-long")
    assert link.status is ExtractionStatus.FAILED
    assert isinstance(link.error, LinkTargetNotFoundError)
    assert link.error.reason is LinkTargetNotFoundReason.UNREADABLE


def test_a_hardlink_with_no_source_fails_as_unresolved(tmp_path: Path) -> None:
    archive = tmp_path / "a.tar"
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("hl")
        info.type = tarfile.LNKTYPE
        info.linkname = "absent"
        tf.addfile(info)
    with open_archive(archive) as reader:
        report = reader.extract_all(tmp_path / "out", on_error="continue")
    (result,) = report.results
    assert isinstance(result.error, LinkTargetNotFoundError)
    assert result.error.reason is LinkTargetNotFoundReason.UNRESOLVED


# --- ArchiveyUsageError.refused_member_type ---


def test_refused_member_type_marks_an_open_of_a_member_with_no_bytes(
    tmp_path: Path,
) -> None:
    archive = _tar(
        tmp_path / "a.tar",
        [("d", "dir", b""), ("to-dir", "sym", "d"), ("f", "file", b"x")],
    )
    with open_archive(archive) as reader:
        for name in ("d/", "to-dir"):
            with pytest.raises(archivey.ArchiveyUsageError) as info:
                reader.open(name)
            assert info.value.refused_member_type is MemberType.DIRECTORY, name
        with pytest.raises(archivey.ArchiveyUsageError) as info:
            reader.open(0)  # type: ignore[arg-type]  # the misuse under test
        assert info.value.refused_member_type is None
    with pytest.raises(archivey.ArchiveyUsageError) as info:
        reader.open("f")  # the reader is closed
    assert info.value.refused_member_type is None


def test_refused_member_type_survives_a_pickle() -> None:
    import pickle

    exc = archivey.ArchiveyUsageError(
        "not a file", refused_member_type=MemberType.OTHER
    )
    assert pickle.loads(pickle.dumps(exc)).refused_member_type is MemberType.OTHER


# --- The CLI's output is what it was before ---


def test_cli_extract_reports_each_rewrite_kind_as_before(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A re-root is counted once (listed under -v), a portable rewrite alone gets its
    own line, and a member that had both is reported as a re-root."""
    archive = _tar(
        tmp_path / "t.tar",
        [
            ("/etc/a", "file", b"1"),
            ("/b/what?.txt", "file", b"2"),
            ("c\\d", "file", b"3"),
            ("plain", "file", b"4"),
        ],
    )

    def extract(dest: str, *extra: str) -> int:
        return main(["x", str(archive), "-d", dest, "--policy", "standard", *extra])

    assert extract(str(tmp_path / "out")) == EXIT_OK
    err = capsys.readouterr().err.splitlines()
    assert err[:2] == [
        "name rewritten: c\\\\d -> c/d",
        "re-rooted 2 absolute member names inside the destination",
    ]
    assert err[2].startswith("4 extracted, 0 renamed, 0 skipped")
    assert len(err) == 3

    assert extract(str(tmp_path / "out2"), "-v") == EXIT_OK
    err = capsys.readouterr().err.splitlines()
    assert "re-rooted: /etc/a -> etc/a" in err
    assert "re-rooted: /b/what?.txt -> b/what%3F.txt" in err
    assert "name rewritten: c\\\\d -> c/d" in err
    assert not any(line.startswith("name rewritten: /") for line in err)


def test_cli_extract_and_test_treat_a_targetless_link_as_before(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _zip_symlinks(tmp_path / "a.zip", {"empty": b"", "inside": b"f.txt"})
    assert main(["test", str(archive)]) == EXIT_OK
    capsys.readouterr()
    assert main(["x", str(archive), "-d", str(tmp_path / "out")]) == EXIT_OK
    err = capsys.readouterr().err
    assert "link target unavailable: empty" in err
