"""``extract_all`` over an archive whose listing ends in damage.

The members listed before the damage are written, and then the call raises the
listing's error: the same order as ``stream_members()`` (the prefix, then the error),
unrar and 7-Zip. Measured with unrar 7.00 and p7zip 16.02 on these same cuts: both
write the members before the cut and exit non-zero ("Unexpected end of archive").

Only TAR and RAR have a random-access listing that is a walk and can end part-way.
A 7z or ZIP listing is one index read at open: damage there fails the open, with
no prefix.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, ListingLimits, MemberType, OnError, open_archive
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
)
from archivey.exceptions import CorruptionError, ResourceLimitError
from tests.conftest import requires_binary
from tests.test_audit2_cross_format import _rar4_blocks, _rar5_blocks

_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _rar_cut(fixture: str, *, rar4: bool, file_index: int) -> bytes:
    """The fixture cut 5 bytes into the header of its ``file_index``-th FILE block."""
    data = (_RAR_FIXTURES / fixture).read_bytes()
    walker, file_type = (_rar4_blocks, 0x74) if rar4 else (_rar5_blocks, 2)
    files = [b for b in walker(data) if b[1] == file_type]
    return data[: files[file_index][0] + 5]


def _tar_with_hardlink() -> bytes:
    """``a.txt``, ``b.txt`` (a hard link to ``a.txt``), then ``c.txt`` and ``d.txt``
    with the header of ``c.txt`` damaged: its checksum field is not a number."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"aaa"))
        link = tarfile.TarInfo("b.txt")
        link.type = tarfile.LNKTYPE
        link.linkname = "a.txt"
        tf.addfile(link)
        for name in ("c.txt", "d.txt"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tf.addfile(info, io.BytesIO(b"ccc"))
    data = bytearray(buf.getvalue())
    # 512 header + 512 data for a.txt, 512 header for b.txt; c.txt's header at 1536.
    data[1536 + 148 : 1536 + 156] = b"XXXXXXXX"
    return bytes(data)


# (id, cut archive, the regular files listed before the damage)
_CASES = [
    pytest.param(
        _rar_cut("basic_nonsolid__.rar", rar4=False, file_index=2),
        {"file1.txt", "empty_file.txt"},
        id="rar5",
    ),
    pytest.param(
        _rar_cut("basic_nonsolid__rar4.rar", rar4=True, file_index=2),
        {"file1.txt", "empty_file.txt"},
        id="rar4",
    ),
    pytest.param(
        _rar_cut("basic_solid__.rar", rar4=False, file_index=2),
        {"file1.txt", "empty_file.txt"},
        id="rar5-solid",
        # Solid RAR5 member data needs RARLAB unrar.
        marks=requires_binary("unrar"),
    ),
    pytest.param(
        _rar_cut("hardlinks_solid__.rar", rar4=False, file_index=3),
        {"file1.txt", "subdir/file2.txt", "subdir/hardlink_to_file1.txt"},
        id="rar5-hardlink",
        # Solid RAR5 member data needs RARLAB unrar.
        marks=requires_binary("unrar"),
    ),
    pytest.param(_tar_with_hardlink(), {"a.txt", "b.txt"}, id="tar"),
]


def _listing(data: bytes) -> tuple[dict[str, bytes], type[BaseException], str]:
    """The prefix's file contents and the listing error, as the reader reports them."""
    with open_archive(io.BytesIO(data)) as reader:
        report = reader.members_report()
        assert report.error is not None  # precondition: the listing ends in damage
        contents = {}
        for member in report.members:
            if member.is_file or member.type is MemberType.HARDLINK:
                contents[member.name] = reader.read(member)
    return contents, type(report.error), str(report.error)


def _files_on_disk(dest: Path) -> dict[str, bytes]:
    found = {}
    for root, _dirs, files in os.walk(dest):
        for name in files:
            path = Path(root) / name
            found[path.relative_to(dest).as_posix()] = path.read_bytes()
    return found


@pytest.mark.parametrize("on_error", [OnError.STOP, OnError.CONTINUE])
@pytest.mark.parametrize("listed_first", [False, True], ids=["fresh", "listed"])
@pytest.mark.parametrize(("data", "prefix"), _CASES)
def test_extract_writes_the_listed_prefix_then_raises(
    tmp_path: Path,
    data: bytes,
    prefix: set[str],
    listed_first: bool,
    on_error: OnError,
) -> None:
    contents, error_type, message = _listing(data)
    assert set(contents) == prefix  # precondition
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        if listed_first:
            reader.members_report()
        with pytest.raises(error_type) as excinfo:
            reader.extract_all(dest, on_error=on_error)
    assert str(excinfo.value) == message
    assert _files_on_disk(dest) == contents


@pytest.mark.parametrize(("data", "prefix"), _CASES)
def test_streaming_extract_writes_the_same_prefix(
    tmp_path: Path, data: bytes, prefix: set[str]
) -> None:
    contents, error_type, message = _listing(data)
    assert set(contents) == prefix  # precondition
    dest = tmp_path / "out"
    with (
        open_archive(io.BytesIO(data), streaming=True) as reader,
        pytest.raises(error_type) as excinfo,
    ):
        reader.extract_all(dest)
    assert str(excinfo.value) == message
    assert _files_on_disk(dest) == contents


@pytest.mark.parametrize("listed_first", [False, True], ids=["fresh", "listed"])
@pytest.mark.parametrize(("data", "prefix"), _CASES)
def test_selection_inside_the_prefix_still_raises(
    tmp_path: Path, data: bytes, prefix: set[str], listed_first: bool
) -> None:
    # Every selected member is listed before the damage; whether more would match
    # after it is unknown, so the call still reports the damage.
    contents, error_type, message = _listing(data)
    first = min(prefix)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        if listed_first:
            reader.members_report()
        with pytest.raises(error_type) as excinfo:
            reader.extract_all(dest, members=[first])
    assert str(excinfo.value) == message
    assert _files_on_disk(dest) == {first: contents[first]}


@pytest.mark.parametrize("listed_first", [False, True], ids=["fresh", "listed"])
@pytest.mark.parametrize(
    ("data", "link", "source"),
    [
        pytest.param(
            _rar_cut("hardlinks_solid__.rar", rar4=False, file_index=3),
            "subdir/hardlink_to_file1.txt",
            "file1.txt",
            id="rar5",
            marks=requires_binary("unrar"),
        ),
        pytest.param(_tar_with_hardlink(), "b.txt", "a.txt", id="tar"),
    ],
)
def test_hardlink_whose_source_was_not_selected_is_written_before_the_raise(
    tmp_path: Path, data: bytes, link: str, source: str, listed_first: bool
) -> None:
    # The link and its source are both before the damage (a hard link only points
    # back), so the second pass that re-reads the excluded source has what it needs.
    contents, error_type, message = _listing(data)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        if listed_first:
            reader.members_report()
        with pytest.raises(error_type) as excinfo:
            reader.extract_all(dest, members=[link])
    assert str(excinfo.value) == message
    assert _files_on_disk(dest) == {link: contents[source]}


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            _rar_cut("basic_nonsolid__.rar", rar4=False, file_index=2), id="rar5"
        ),
        pytest.param(
            _rar_cut("basic_nonsolid__rar4.rar", rar4=True, file_index=2), id="rar4"
        ),
    ],
)
def test_a_rar_listing_limit_on_a_cut_archive_refuses_at_open(data: bytes) -> None:
    # RAR weighs both listing limits as its header walk runs, so the names of the
    # members before the cut cross the metadata budget inside ``open_archive``, with
    # the walk's own wording; there is no reader to extract from. A limit crossed
    # inside the listed prefix during extraction cannot be built for RAR any more.
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=40))
    with pytest.raises(
        ResourceLimitError,
        match=r"max_metadata_bytes=40 \(RAR headers of \d+ members hold \d+ bytes\)",
    ):
        open_archive(io.BytesIO(data), config=config)


@pytest.mark.parametrize("raise_unmatched", [False, True], ids=["default", "raise"])
@pytest.mark.parametrize("listed_first", [False, True], ids=["fresh", "listed"])
@pytest.mark.parametrize(("data", "prefix"), _CASES)
def test_an_entry_unmatched_in_the_prefix_is_not_reported(
    tmp_path: Path,
    data: bytes,
    prefix: set[str],
    listed_first: bool,
    raise_unmatched: bool,
) -> None:
    # The entry could match a member past the damage, which was never listed, so it
    # is not reported unmatched: under RAISE the caller gets the listing's error, not
    # DiagnosticRaisedError, and the prefix member is still written.
    raise_on = {DiagnosticCode.MEMBER_SELECTOR_UNMATCHED} if raise_unmatched else set()
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy(raise_on=raise_on))
    contents, error_type, message = _listing(data)
    first = min(prefix)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data), config=config) as reader:
        if listed_first:
            reader.members_report()
        with pytest.raises(error_type) as excinfo:
            reader.extract_all(dest, members=["typo.txt", first])
        counts = reader.diagnostics.counts
    assert str(excinfo.value) == message
    assert counts.get(DiagnosticCode.MEMBER_SELECTOR_UNMATCHED, 0) == 0
    assert _files_on_disk(dest) == {first: contents[first]}


def test_a_fresh_corruption_error_from_the_pass_propagates_at_once(
    tmp_path: Path,
) -> None:
    # Only the reader's own walk-error object marks listing damage. A pass that wraps
    # it in a new CorruptionError is a member fault: it propagates at once, so the
    # second pass does not run and the selected hard link stays unwritten.
    data = _tar_with_hardlink()
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        real_pass = reader._stream_members

        def wrapping_pass(*args, **kwargs):
            try:
                yield from real_pass(*args, **kwargs)
            except CorruptionError as exc:
                raise CorruptionError(f"wrapped: {exc}") from exc

        reader._stream_members = wrapping_pass  # type: ignore[method-assign]
        with pytest.raises(CorruptionError) as excinfo:
            reader.extract_all(dest, members=["b.txt"])
        assert excinfo.value is not reader._walk_error
    assert str(excinfo.value).startswith("wrapped: ")
    assert _files_on_disk(dest) == {}
