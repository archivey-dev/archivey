"""Tests for member-name normalization rules (archive-data-model spec).

Normalization is meaning-preserving: a leading ``/`` and any ``..`` are retained faithfully
(rejected at extraction time, not silently re-rooted here); ``\\``→``/`` conversion is
format/entry-aware via ``backslash_is_separator``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from archivey import ExtractionPolicy
from archivey.internal.naming import normalize_member_name
from archivey.types import MemberType
from tests.extract_util import open_and_extract


@pytest.mark.parametrize(
    ("decoded", "member_type", "backslash_is_separator", "expected"),
    [
        # Backslash: converted for a Windows-origin entry, literal for a POSIX one.
        ("foo\\bar\\baz.txt", MemberType.FILE, True, "foo/bar/baz.txt"),
        ("weird\\name.txt", MemberType.FILE, False, "weird\\name.txt"),
        # Meaning-ALTERING rewrites are gone: leading "/" and ".." are retained.
        (
            "/etc/passwd",
            MemberType.FILE,
            False,
            "/etc/passwd",
        ),  # leading slash retained
        ("foo/../bar", MemberType.FILE, False, "foo/../bar"),  # internal .. retained
        (
            "../../etc/passwd",
            MemberType.FILE,
            False,
            "../../etc/passwd",
        ),  # escaping retained
        # Meaning-PRESERVING clean-ups still apply.
        ("./foo/bar", MemberType.FILE, False, "foo/bar"),  # leading ./ stripped
        ("foo//bar", MemberType.FILE, False, "foo/bar"),  # double slash collapsed
        ("a//b/./c", MemberType.FILE, False, "a/b/c"),  # combined cleanups
        ("mydir", MemberType.DIRECTORY, False, "mydir/"),  # dir trailing slash
        ("mydir/", MemberType.DIRECTORY, False, "mydir/"),  # already has slash
        # Non-directory trailing slash: empty segment dropped (fast path must not keep it).
        ("a/", MemberType.FILE, False, "a"),
        ("pkg/", MemberType.SYMLINK, False, "pkg"),
        ("/", MemberType.DIRECTORY, False, "."),  # bare root becomes dot
        ("", MemberType.FILE, False, "."),  # empty becomes dot
    ],
)
def test_normalize(
    decoded: str, member_type: MemberType, backslash_is_separator: bool, expected: str
) -> None:
    assert (
        normalize_member_name(
            decoded, member_type, backslash_is_separator=backslash_is_separator
        )
        == expected
    )


def test_file_trailing_slash_matches_slow_walk() -> None:
    """Regression: fast path must not keep a trailing slash on FILE/SYMLINK.

    TAR/7z/RAR/ISO classify type independently of the name; a crafted FILE named
    ``a/`` must normalize to ``a`` (empty segment dropped), same as the slow walk.
    """
    for member_type in (MemberType.FILE, MemberType.SYMLINK, MemberType.OTHER):
        assert (
            normalize_member_name("a/", member_type, backslash_is_separator=False)
            == "a"
        )
        assert (
            normalize_member_name(
                "dir/file/", member_type, backslash_is_separator=False
            )
            == "dir/file"
        )
    # DIRECTORY still keeps / requires the trailing slash.
    assert (
        normalize_member_name("a/", MemberType.DIRECTORY, backslash_is_separator=False)
        == "a/"
    )


def test_warns_when_name_changes(caplog: pytest.LogCaptureFixture) -> None:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.naming import emit_member_name_normalized
    from archivey.types import ArchiveMember

    presented = "foo//bar"
    name = normalize_member_name(
        presented, MemberType.FILE, backslash_is_separator=False
    )
    member = ArchiveMember(type=MemberType.FILE, name=name, raw_name=None)
    collector = DiagnosticCollector()
    with caplog.at_level(logging.WARNING, logger="archivey.normalization"):
        emit_member_name_normalized(collector, member=member, presented_name=presented)
    assert any("normalized" in r.message for r in caplog.records)
    assert collector.snapshot().total_count == 1


def test_no_warning_when_unchanged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="archivey.normalization"):
        # A faithful name with an internal ".." is no longer rewritten, so no warning.
        normalize_member_name(
            "foo/../bar", MemberType.FILE, backslash_is_separator=False
        )
    assert not caplog.records


def test_no_warning_for_directory_trailing_slash_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # tarfile strips the trailing slash; adding it back is not an observable override.
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.naming import emit_member_name_normalized
    from archivey.types import ArchiveMember

    member = ArchiveMember(type=MemberType.DIRECTORY, name="pkg/", raw_name=None)
    collector = DiagnosticCollector()
    with caplog.at_level(logging.WARNING, logger="archivey.normalization"):
        emit_member_name_normalized(collector, member=member, presented_name="pkg")
    assert not caplog.records
    assert collector.snapshot().total_count == 0


@pytest.mark.parametrize(
    ("member_type", "name", "presented", "link_stored_as_directory", "reports"),
    [
        # A leading ``./`` alone, or with a directory's added ``/``, is not reported.
        (MemberType.FILE, "a.txt", "./a.txt", False, False),
        (MemberType.FILE, "a.txt", "././a.txt", False, False),
        (MemberType.DIRECTORY, "d/", "./d", False, False),
        (MemberType.DIRECTORY, ".", "./", False, False),
        # It combines with the link-stored-as-directory rule (a ZIP reparse point).
        (MemberType.SYMLINK, "s", "./s/", True, False),
        # A TAR link named ``s/`` keeps its report, with or without ``./``.
        (MemberType.SYMLINK, "s", "./s/", False, True),
        (MemberType.FILE, "a/b", "./a//b", False, True),
        (MemberType.FILE, "a.txt", ".//a.txt", False, True),
    ],
)
def test_a_dot_prefix_combines_with_the_other_suppressions(
    member_type: MemberType,
    name: str,
    presented: str,
    link_stored_as_directory: bool,
    reports: bool,
) -> None:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.naming import emit_member_name_normalized
    from archivey.types import ArchiveMember

    member = ArchiveMember(type=member_type, name=name, raw_name=None)
    collector = DiagnosticCollector()
    emit_member_name_normalized(
        collector,
        member=member,
        presented_name=presented,
        link_stored_as_directory=link_stored_as_directory,
    )
    assert collector.snapshot().total_count == (1 if reports else 0)


def test_a_zip_member_with_a_leading_dot_slash_is_not_reported(tmp_path: Path) -> None:
    import zipfile

    from archivey import open_archive

    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("./a.txt", b"x")
    with open_archive(path) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        assert reader.diagnostics.total_count == 0


def test_a_long_run_of_dot_slashes_is_stripped_in_linear_time() -> None:
    """A million ``./`` before ``a``: stripping by index is linear (about 0.1 s, 0.3 s
    under branch coverage). Slicing once per ``./`` copied the rest of the name each
    time and ran past the pytest timeout; the bound leaves room for a loaded runner."""
    import time

    from archivey.internal.naming import _without_dot_prefix

    started = time.perf_counter()
    assert _without_dot_prefix("./" * 1_000_000 + "a") == "a"
    assert time.perf_counter() - started < 5


def test_link_target_backslash_is_literal() -> None:
    # A link target follows the same backslash rule as member names: the backend already
    # converted separators where the format treats "\" as one, so here it is a literal
    # filename character (a POSIX tar can legitimately contain "b\c" as a name).
    from archivey.internal.naming import resolve_link_target_name

    assert (
        resolve_link_target_name("dir/link", "b\\c", MemberType.SYMLINK) == "dir/b\\c"
    )
    assert (
        resolve_link_target_name("link", "dir\\file", MemberType.HARDLINK)
        == "dir\\file"
    )


def test_infer_member_name_from_archive() -> None:
    from archivey.internal.backends.sevenzip_reader import _SEVENZIP_STEM_SUFFIX_RE
    from archivey.internal.naming import infer_member_name_from_archive

    assert infer_member_name_from_archive(None) == "data"
    assert infer_member_name_from_archive("") == "data"
    assert infer_member_name_from_archive("mystery.bin") == "mystery.bin.uncompressed"
    assert (
        infer_member_name_from_archive("file.gz", strip_suffixes={".gz", ".bz2"})
        == "file"
    )
    assert (
        infer_member_name_from_archive(
            "archive.7z.001",
            strip_suffix_re=_SEVENZIP_STEM_SUFFIX_RE,
        )
        == "archive"
    )


@pytest.mark.parametrize(
    ("archive_name", "expected"),
    [
        ("data.tgz", "data.tar"),
        ("DATA.TXZ", "DATA.tar"),
        ("data.tbz2", "data.tar"),
        ("data.tar.gz", "data.tar"),
        ("notes.gz", "notes"),
        (".tgz", ".tgz.uncompressed"),
    ],
)
def test_single_file_name_turns_a_short_tar_suffix_into_tar(
    archive_name: str, expected: str
) -> None:
    """``gzip -d data.tgz`` writes ``data.tar``; the one member is named the same."""
    from archivey.internal.backends.single_file_reader import _infer_member_name

    assert _infer_member_name(archive_name) == expected


@pytest.mark.parametrize(
    "archive_name",
    ["..gz", "...gz", " .gz", ".gz", ". .gz"],
)
def test_infer_member_name_never_yields_a_dots_only_stem(archive_name: str) -> None:
    """Stripping the suffix can leave "." or "..", which is not a filename.

    Extraction refuses those downstream, so the caller got an empty directory and a
    warning for a perfectly good payload. They fall through to ``.uncompressed``.
    """
    from archivey.internal.naming import infer_member_name_from_archive

    name = infer_member_name_from_archive(archive_name, strip_suffixes={".gz"})
    assert name == archive_name + ".uncompressed"


@pytest.mark.parametrize(
    "policy",
    [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED],
)
def test_dots_only_stem_extracts_under_every_policy(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The ``.uncompressed`` fallback has to satisfy the strictest policy, not just STRICT.

    The stem is chosen at listing time, before any extraction policy is known, so one
    name serves all three. ``....gz`` is the case that made the difference: the bare
    stem ``...`` is refused under ``STRICT`` only, which is exactly the shape a
    policy-blind chooser gets wrong in one direction.
    """
    import gzip

    src = tmp_path / "....gz"
    src.write_bytes(gzip.compress(b"payload"))
    dest = tmp_path / "out"

    open_and_extract(src, dest, policy=policy)

    assert (dest / "....gz.uncompressed").read_bytes() == b"payload"


def test_hardlink_target_retains_dot_dot_like_member_names() -> None:
    """A hardlink target is a stored member name: ``a/../b`` names the member stored
    as ``a/../b``, never the unrelated ``b``, and one that climbs out of the root
    names the member stored that way too (extraction refuses both). Only a RAR file
    copy's caller keeps the escape test. A symlink target is a filesystem path, so its
    ``..`` is collapsed."""
    from archivey.internal.naming import resolve_link_target_name

    assert resolve_link_target_name("x", "a/../b", MemberType.HARDLINK) == "a/../b"
    assert resolve_link_target_name("x", "./a//b/./c", MemberType.HARDLINK) == "a/b/c"
    assert (
        resolve_link_target_name("x", "a/../../b", MemberType.HARDLINK) == "a/../../b"
    )
    assert resolve_link_target_name("x", "a/..", MemberType.HARDLINK) == "a/.."
    for escaping in ("a/../../b", "a/..", "../b"):
        assert (
            resolve_link_target_name(
                "x", escaping, MemberType.HARDLINK, within_root=True
            )
            is None
        )
    assert resolve_link_target_name("x", "/abs", MemberType.HARDLINK) == "/abs"
    assert resolve_link_target_name("d/l", "../b", MemberType.SYMLINK) == "b"
    assert resolve_link_target_name("d/l", "../../b", MemberType.SYMLINK) is None


def test_tar_hardlink_through_dot_dot_reads_the_member_it_names(
    tmp_path: Path,
) -> None:
    import io
    import tarfile

    from archivey import open_archive

    path = tmp_path / "links.tar"
    with tarfile.open(path, "w") as tf:
        for name, data in (("b", b"SECRET-B"), ("a/../b", b"REAL-TARGET")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("x")
        link.type = tarfile.LNKTYPE
        link.linkname = "a/../b"
        tf.addfile(link)
    with open_archive(path) as ar:
        members = {m.name: m for m in ar.members()}
        target = members["x"].link_target_member
        assert target is not None and target.name == "a/../b"
        assert ar.read("x") == b"REAL-TARGET"
