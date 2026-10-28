"""One member list per reader, filled by one backend walk.

The base reader owns the list (``one-member-listing-per-reader``): the index-only peek,
``members()``, the streaming pass and a backend's own data pass all read the same
``ArchiveMember`` objects, and ``_iter_members()`` runs once for a walk that completes.
Before this, ZIP and ISO built a second set of objects for every peek, and 7z and solid
RAR streamed members nobody had registered.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import threading
import time
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import ExtractionStatus, open_archive
from archivey.config import ArchiveyConfig, ListingLimits, PasswordRequest
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
)
from archivey.exceptions import (
    ArchiveyUsageError,
    DiagnosticRaisedError,
    ReadError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.measurement import enable_measurement
from archivey.reader import ArchiveReader
from archivey.types import ArchiveMember, MemberType
from tests.conftest import complete_listing, requires

_FIXTURES = Path(__file__).parent / "fixtures"
_RAR5_SOLID = _FIXTURES / "rar" / "symlinks_solid__.rar"
_RAR4_SOLID = _FIXTURES / "rar" / "symlinks_solid__rar4.rar"
_LINKS_SOLID = _FIXTURES / "sevenzip" / "links_mid_folder_solid.7z"
_LINKS_NONSOLID = _FIXTURES / "sevenzip" / "links_mid_folder_nonsolid.7z"
# Where each link's data ends in the solid fixture's one folder (see its README):
# a_link at 0, then b.txt (3200), c_link, d.txt (3153), e_link as the last member.
_LINK_ENDS = (5, 3210, 6368)
_FOLDER_SIZE = 6368

_MODES = [pytest.param(False, id="random-access"), pytest.param(True, id="streaming")]


def _base(reader: ArchiveReader) -> BaseArchiveReader:
    assert isinstance(reader, BaseArchiveReader)
    return reader


def _symlink_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3  # Unix
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def _zip(tmp_path: Path, entries: list[tuple[str, bytes, bool]]) -> Path:
    """A ZIP of ``(name, data, is_symlink)`` entries, in order."""
    path = tmp_path / "t.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data, is_link in entries:
            if is_link:
                zf.writestr(_symlink_info(name), data)
            else:
                zf.writestr(name, data)
    return path


def _iso(tmp_path: Path) -> Path:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(b"one"), 3, "/A.TXT;1", rr_name="a.txt")
    iso.add_fp(io.BytesIO(b"two"), 3, "/B.TXT;1", rr_name="b.txt")
    iso.add_symlink("/SYM.TXT;1", "sym", "a.txt")
    path = tmp_path / "t.iso"
    iso.write(str(path))
    iso.close()
    return path


def _archive(kind: str, tmp_path: Path) -> Path:
    if kind == "zip":
        return _zip(
            tmp_path,
            [
                ("a.txt", b"one", False),
                ("link", b"a.txt", True),
                ("b.txt", b"x", False),
            ],
        )
    if kind == "iso":
        return _iso(tmp_path)
    if kind == "7z":
        return _LINKS_SOLID
    assert kind == "rar"
    return _RAR5_SOLID


_KINDS = [
    pytest.param("zip", id="zip"),
    pytest.param("iso", id="iso", marks=requires("pycdlib")),
    pytest.param("7z", id="7z"),
    pytest.param("rar", id="rar"),
]


def _count_walks(
    monkeypatch: pytest.MonkeyPatch, reader: ArchiveReader
) -> Callable[[], int]:
    """Count calls to the backend's ``_iter_members`` from here on."""
    cls = type(reader)
    original = cls._iter_members
    calls = [0]

    def counting(self: BaseArchiveReader) -> Iterator[ArchiveMember]:
        calls[0] += 1
        return original(self)

    monkeypatch.setattr(cls, "_iter_members", counting)
    return lambda: calls[0]


# --------------------------------------------------------------------------------
# One set of objects, one walk
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(_LINKS_SOLID, id="7z"),
        pytest.param(_RAR5_SOLID, id="solid-rar"),
        pytest.param(_RAR4_SOLID, id="solid-rar4"),
    ],
)
@pytest.mark.parametrize("streaming", _MODES)
def test_stream_members_registers_every_member(path: Path, streaming: bool) -> None:
    """7z and solid RAR used to stream their private list, never registered.

    A pass to the end also leaves each yielded symlink with the target ``members()``
    would set. Random access used to leave 7z and RAR4 targets unset. No ``unrar``
    gate: the pass reads no stream, and a RAR4 target is read from the archive bytes.
    """
    with open_archive(path) as listing:
        expected = _link_targets(listing.members())
    assert expected and all(expected.values())
    with open_archive(path, streaming=streaming) as reader:
        members = [m for m, _ in reader.stream_members()]
        assert members
        assert [m.member_id for m in members] == list(range(len(members)))
        assert all(m in reader for m in members)
        assert _link_targets(members) == expected


@pytest.mark.parametrize("kind", _KINDS)
def test_peek_twice_then_members_is_one_walk_of_one_set(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with open_archive(_archive(kind, tmp_path)) as reader:
        walks = _count_walks(monkeypatch, reader)
        first = reader.members_report_if_available()
        second = reader.members_report_if_available()
        assert first is not None and second is not None
        listed = reader.members()
        assert len(listed) == len(first.members) > 0
        assert all(a is b for a, b in zip(first.members, second.members, strict=True))
        assert all(a is b for a, b in zip(first.members, listed, strict=True))
        assert walks() == 1


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("streaming", _MODES)
def test_extract_all_walks_once(
    kind: str,
    streaming: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with open_archive(_archive(kind, tmp_path), streaming=streaming) as reader:
        walks = _count_walks(monkeypatch, reader)
        reader.extract_all(tmp_path / "out", on_error="continue")
        assert walks() == 1


def _tar_gz(tmp_path: Path) -> Path:
    path = tmp_path / "t.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name in ("a.txt", "b.txt", "c.txt"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"abc"))
    return path


_RESTART_KINDS = [*_KINDS, pytest.param("tar", id="tar")]


def _restart_archive(kind: str, tmp_path: Path) -> Path:
    return _tar_gz(tmp_path) if kind == "tar" else _archive(kind, tmp_path)


def _dropped(reader: ArchiveReader, how: str) -> list[ArchiveMember]:
    """Start a pass, take two members and drop it."""
    if how == "iter":
        members = iter(reader)
        taken = [next(members), next(members)]
    else:
        passing = reader.stream_members()
        taken = [next(passing)[0], next(passing)[0]]
        passing.close()
    return taken


@pytest.mark.parametrize("kind", _RESTART_KINDS)
@pytest.mark.parametrize("how", ["iter", "stream_members"])
def test_a_dropped_pass_restarted_hands_out_the_same_members(
    kind: str, how: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Random access: the restart yields the members already seen, then the rest."""
    with open_archive(_restart_archive(kind, tmp_path)) as reader:
        walks = _count_walks(monkeypatch, reader)
        taken = _dropped(reader, how)
        if how == "iter":
            again = list(reader)
        else:
            again = [m for m, _ in reader.stream_members()]
        assert again[:2] == taken
        assert all(a is b for a, b in zip(taken, again[:2], strict=True))
        assert [m.member_id for m in again] == list(range(len(again)))
        assert again == reader.members()
        assert walks() == 1


@pytest.mark.parametrize("kind", _RESTART_KINDS)
@pytest.mark.parametrize("how", ["iter", "stream_members"])
def test_a_dropped_streaming_pass_is_finished_by_members_report(
    kind: str, how: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Streaming: a second pass is refused; ``members_report()`` continues the walk."""
    with open_archive(_restart_archive(kind, tmp_path), streaming=True) as reader:
        walks = _count_walks(monkeypatch, reader)
        taken = _dropped(reader, how)
        with pytest.raises(ArchiveyUsageError, match=r"members_report\(\)"):
            list(reader)
        listed = complete_listing(reader)
        assert all(a is b for a, b in zip(taken, listed[:2], strict=True))
        assert [m.member_id for m in listed] == list(range(len(listed)))
        assert len(listed) > 2
        assert walks() == 1


def test_a_peeked_zip_symlink_is_filled_in_place(tmp_path: Path) -> None:
    path = _zip(tmp_path, [("a.txt", b"one", False), ("link", b"a.txt", True)])
    with open_archive(path) as reader:
        report = reader.members_report_if_available()
        assert report is not None
        link = report.members[1]
        assert link.link_target is None  # the peek reads no member data
        (_, listed_link) = reader.members()
        assert listed_link is link
        assert link.link_target == "a.txt"
        assert link.link_target_member is report.members[0]


def test_a_bidi_name_is_counted_once_on_the_object_the_caller_holds(
    tmp_path: Path,
) -> None:
    path = _zip(tmp_path, [("a\u202eb.txt", b"x", False)])
    with open_archive(path) as reader:
        report = reader.members_report_if_available()
        assert report is not None
        (held,) = report.members
        reader.members()
        assert reader.diagnostics.counts[DiagnosticCode.MEMBER_NAME_BIDI_CONTROL] == 1
        assert [d.code for d in held.diagnostics] == [
            DiagnosticCode.MEMBER_NAME_BIDI_CONTROL
        ]


def test_streaming_extract_all_supersedes_a_zip_duplicate(tmp_path: Path) -> None:
    """The pass yields the peek's stamped objects, so it agrees with random access.

    Before, the pass yielded a second set whose ``is_current`` was stamped only at EOF,
    so the shadowed entry was written and the later one failed on the existing file.
    """
    path = _zip(tmp_path, [("a.txt", b"first", False), ("a.txt", b"last", False)])
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        with open_archive(path, streaming=streaming) as reader:
            report = reader.extract_all(dest)
        assert [r.status for r in report.results] == [
            ExtractionStatus.SUPERSEDED,
            ExtractionStatus.EXTRACTED,
        ]
        assert (dest / "a.txt").read_bytes() == b"last"


@pytest.mark.parametrize("link_first", [False, True], ids=["file-first", "link-first"])
def test_a_pass_abandoned_after_a_peek_finalizes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_first: bool
) -> None:
    """The peek drains the walk; the pass still finalizes only on its own cursor.

    The pass reads a symlink's target as it passes it, so only a link it already
    yielded has been read."""
    entries = [("a.txt", b"one", False), ("link", b"a.txt", True)]
    path = _zip(tmp_path, entries[::-1] if link_first else entries)
    reads: list[str] = []
    cls = type(_base(open_archive(path)))
    original = cls._ensure_link_target

    def recording(self: BaseArchiveReader, member: ArchiveMember) -> None:
        reads.append(member.name)
        original(self, member)

    monkeypatch.setattr(cls, "_ensure_link_target", recording)
    with open_archive(path, streaming=True) as reader:
        for _member, _stream in reader.stream_members():
            assert reader.members_report_if_available() is not None
            break
        assert _base(reader)._materialized is None
        assert reads == (["link"] if link_first else [])
        # The same pass, finished, does finalize.
        link = next(m for m in complete_listing(reader) if m.name == "link")
        assert link.link_target == "a.txt"
        assert reads == ["link"]


def _normalizing(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    """Make ``module``'s name normalization change every name, so each member reports."""
    import importlib

    backend = importlib.import_module(f"archivey.internal.{module}")
    original = backend.normalize_member_name

    def renamed(name: str, *args: object, **kwargs: object) -> str:
        return "n_" + original(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(backend, "normalize_member_name", renamed)


@pytest.mark.parametrize(
    ("kind", "module"),
    [
        pytest.param("zip", "backends.zip_reader", id="zip"),
        # ISO is read through archivey.formats: the adapter normalizes its names.
        pytest.param("iso", "format_adapter", id="iso", marks=requires("pycdlib")),
        pytest.param("7z", "backends.sevenzip_reader", id="7z"),
        pytest.param("rar", "backends.rar_reader", id="rar"),
    ],
)
def test_typing_time_diagnostics_name_the_member_id(
    kind: str, module: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A diagnostic raised while a member is typed names the id it is stamped with.

    Only ZIP did before; 7z, RAR and ISO reported ``None``. ``extract_all`` also pins
    the count: one member, one report, however many listing calls it makes.
    """
    _normalizing(monkeypatch, module)
    with open_archive(_archive(kind, tmp_path)) as reader:
        reader.extract_all(tmp_path / "out", on_error="continue")
        members = reader.members()
        reports = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_NAME_NORMALIZED
        ]
        assert len(reports) == len(members)
        for member in members:
            (own,) = [
                d
                for d in member.diagnostics
                if d.code is DiagnosticCode.MEMBER_NAME_NORMALIZED
            ]
            assert own.context.member_id == member.member_id


# --------------------------------------------------------------------------------
# When the walk ends, and how it fails
# --------------------------------------------------------------------------------


def _failing_once(
    monkeypatch: pytest.MonkeyPatch,
    cls: type[BaseArchiveReader],
    at: int,
    *,
    inside: bool = False,
) -> None:
    """The first walk raises ``RuntimeError`` after ``at`` members; later walks work.

    By default the interrupt lands between two members, before the backend types the
    next one. With ``inside``, it lands after the backend typed member ``at``, and its
    typing-time diagnostics were emitted, but before that member was yielded.
    """
    original = cls._iter_members
    failed = [False]

    def walk(self: BaseArchiveReader) -> Iterator[ArchiveMember]:
        members = original(self)
        index = 0
        while True:
            if index == at and not failed[0] and not inside:
                failed[0] = True
                raise RuntimeError("interrupted walk")
            member = next(members, None)
            if member is None:
                return
            if index == at and not failed[0]:
                failed[0] = True
                raise RuntimeError("interrupted walk")
            yield member
            index += 1

    monkeypatch.setattr(cls, "_iter_members", walk)


def test_a_failed_random_access_walk_is_discarded_and_walked_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _zip(
        tmp_path,
        [("a.txt", b"1", False), ("b.txt", b"2", False), ("c.txt", b"3", False)],
    )
    with open_archive(path) as reader:
        _failing_once(monkeypatch, type(reader), at=2)
        walks = _count_walks(monkeypatch, reader)
        with pytest.raises(RuntimeError):
            reader.members()
        listed = reader.members()
        assert walks() == 2
        assert [(m.name, m.member_id) for m in listed] == [
            ("a.txt", 0),
            ("b.txt", 1),
            ("c.txt", 2),
        ]
        assert reader.members_report_if_available().members == tuple(listed)  # type: ignore[union-attr]


_BIDI = DiagnosticCode.MEMBER_NAME_BIDI_CONTROL
_NORMALIZED = DiagnosticCode.MEMBER_NAME_NORMALIZED


def _retry_zip(tmp_path: Path) -> Path:
    """A presentation diagnostic and a typing-time one before the walk fails, one after."""
    return _zip(
        tmp_path,
        [
            ("re\u202evil.txt", b"1", False),
            ("./b.txt", b"2", False),
            ("./c.txt", b"3", False),
        ],
    )


@pytest.mark.parametrize("inside", [False, True], ids=["between", "inside"])
def test_a_walk_walked_again_emits_each_member_diagnostic_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside: bool
) -> None:
    """ZIP builds fresh objects on every walk; the retry must not count them again.

    Interrupted inside member 2, the failed walk has already emitted that member's
    typing-time diagnostic, onto an object nobody will hold.
    """
    with open_archive(_retry_zip(tmp_path)) as reader:
        _failing_once(monkeypatch, type(reader), at=2, inside=inside)
        with pytest.raises(RuntimeError):
            reader.members()
        listed = reader.members()
        counts = reader.diagnostics.counts
        assert counts[_BIDI] == 1
        assert counts[_NORMALIZED] == 2
        # The objects handed out are the ones the diagnostics were attached to.
        assert [d.code for d in listed[0].diagnostics] == [_BIDI]
        assert [d.code for d in listed[1].diagnostics] == [_NORMALIZED]
        assert [d.code for d in listed[2].diagnostics] == [_NORMALIZED]


def _normalized_names_zip(tmp_path: Path, count: int) -> Path:
    return _zip(tmp_path, [(f"./f{i}.txt", b"x", False) for i in range(count)])


def test_a_walk_keeps_a_diagnostic_only_for_the_member_being_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The replay log holds codes for the members built, not their diagnostics.

    With no retention budget, nothing may keep a diagnostic past the member being
    typed: the one the interrupt landed in.
    """
    config = ArchiveyConfig(max_retained_diagnostic_references=0)
    with open_archive(_normalized_names_zip(tmp_path, 50), config=config) as reader:
        _failing_once(monkeypatch, type(reader), at=40, inside=True)
        with pytest.raises(RuntimeError):
            reader.members()
        logs = reader._walk_emits
        assert sorted(logs) == list(range(41))
        assert [p for p, log in logs.items() if log.details is not None] == [40]
        assert len(reader.members()) == 50
        assert reader.diagnostics.counts[_NORMALIZED] == 50
        assert reader._walk_emits == {}


def test_a_streaming_walk_keeps_no_replay_log(tmp_path: Path) -> None:
    """A streaming walk is never started over, so it has nothing to replay."""
    with open_archive(_normalized_names_zip(tmp_path, 20), streaming=True) as reader:
        for _member, _stream in reader.stream_members():
            assert reader._walk_emits == {}
        assert reader.diagnostics.counts[_NORMALIZED] == 20


def test_a_member_refused_by_the_limit_is_not_counted_again_by_a_pass(
    tmp_path: Path,
) -> None:
    """The refused member was typed and checked before the limit fired.

    A ``stream_members()`` pass after the refusal walks again over the member
    ``members()`` refused, and is refused at it too, without a second finding.
    """
    # TAR: ZIP, 7z, RAR and ISO apply max_members at open, so no pass gets this far.
    path = tmp_path / "t.tar"
    with tarfile.open(path, "w") as tf:
        for name, data in (("a.txt", b"1"), ("b.txt", b"2"), ("re\u202evil.txt", b"3")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    with open_archive(path, config=config) as reader:
        with pytest.raises(ResourceLimitError):
            reader.members()
        with pytest.raises(ResourceLimitError):
            for _member, _stream in reader.stream_members():
                pass
        assert reader.diagnostics.counts[_BIDI] == 1


def test_a_strict_policy_refuses_again_on_a_walk_walked_again(
    tmp_path: Path,
) -> None:
    """A presentation check whose emit raised has not run; the retry raises too."""
    path = _zip(tmp_path, [("a.txt", b"1", False), ("re\u202evil.txt", b"2", False)])
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(path, config=config) as reader:
        with pytest.raises(DiagnosticRaisedError):
            reader.members()
        with pytest.raises(DiagnosticRaisedError):
            reader.members()


def test_a_typing_time_raise_is_raised_again_on_a_walk_walked_again(
    tmp_path: Path,
) -> None:
    """An emit that raised stops the retry in the same place, counted once."""
    policy = DiagnosticPolicy(
        raise_on={_NORMALIZED},
    )
    with open_archive(
        _retry_zip(tmp_path), config=ArchiveyConfig(diagnostic_policy=policy)
    ) as reader:
        with pytest.raises(DiagnosticRaisedError) as first:
            reader.members()
        with pytest.raises(DiagnosticRaisedError) as second:
            reader.members()
        assert second.value is first.value
        assert reader.diagnostics.counts[_NORMALIZED] == 1


def test_a_failed_streaming_walk_poisons_the_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _zip(
        tmp_path,
        [("a.txt", b"1", False), ("b.txt", b"2", False), ("c.txt", b"3", False)],
    )
    with open_archive(path, streaming=True) as reader:
        _failing_once(monkeypatch, type(reader), at=2)
        seen = []
        with pytest.raises(RuntimeError):
            for member, _stream in reader.stream_members():
                seen.append(member)
        assert len(seen) == 2
        with pytest.raises(ReadError, match="previously failed"):
            reader.members_report()
        with pytest.raises(ReadError, match="previously failed"):
            reader.members_report_if_available()
        assert _base(reader)._materialized is None


def _truncated_tar_with_duplicate(tmp_path: Path) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for data in (b"first", b"last"):
            info = tarfile.TarInfo("a.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        big = b"z" * 100_000
        info = tarfile.TarInfo("big.bin")
        info.size = len(big)
        tar.addfile(info, io.BytesIO(big))
        info = tarfile.TarInfo("after.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "trunc.tar"
    path.write_bytes(buf.getvalue()[:60_000])
    return path


def test_terminal_damage_stamps_last_entry_wins_over_the_prefix(
    tmp_path: Path,
) -> None:
    """Removing the old ``is_current_first`` stamp sites must not drop this one."""
    path = _truncated_tar_with_duplicate(tmp_path)
    with open_archive(path, streaming=True) as reader:
        with pytest.raises(TruncatedError):
            for _member, _stream in reader.stream_members():
                pass
        report = reader.members_report()
    assert isinstance(report.error, TruncatedError)
    assert [(m.name, m.is_current) for m in report.members[:2]] == [
        ("a.txt", False),
        ("a.txt", True),
    ]


# --------------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------------


def test_a_peek_racing_members_shares_one_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _zip(tmp_path, [(f"f{i}.txt", b"x", False) for i in range(20)])
    with open_archive(path, concurrent_operations=True) as reader:
        cls = type(reader)
        original = cls._iter_members
        calls = [0]

        def slow(self: BaseArchiveReader) -> Iterator[ArchiveMember]:
            calls[0] += 1
            for member in original(self):
                time.sleep(0.002)
                yield member

        monkeypatch.setattr(cls, "_iter_members", slow)
        results: dict[str, object] = {}
        barrier = threading.Barrier(2)

        def peek() -> None:
            barrier.wait()
            results["peek"] = reader.members_report_if_available()

        def listing() -> None:
            barrier.wait()
            results["members"] = reader.members()

        threads = [threading.Thread(target=peek), threading.Thread(target=listing)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        peeked = results["peek"].members  # type: ignore[attr-defined]
        listed = results["members"]
        assert calls[0] == 1
        assert all(a is b for a, b in zip(peeked, listed, strict=True))  # type: ignore[call-overload]


def test_a_peek_inside_a_streaming_loop_hands_the_pass_its_objects(
    tmp_path: Path,
) -> None:
    path = _zip(tmp_path, [(f"f{i}.txt", b"x", False) for i in range(3)])
    with open_archive(path, streaming=True) as reader:
        yielded = []
        peeked: tuple[ArchiveMember, ...] = ()
        for member, _stream in reader.stream_members():
            yielded.append(member)
            if not peeked:
                report = reader.members_report_if_available()
                assert report is not None
                peeked = report.members
        assert len(yielded) == 3
        assert all(a is b for a, b in zip(yielded, peeked, strict=True))


# --------------------------------------------------------------------------------
# 7z link targets: one decode per folder
# --------------------------------------------------------------------------------


def _decoded(reader: ArchiveReader) -> int:
    stats = reader.io_stats()
    assert stats is not None
    return stats.bytes_decompressed


def _link_targets(members: list[ArchiveMember]) -> dict[str, str | None]:
    return {m.name: m.link_target for m in members if m.type is MemberType.SYMLINK}


_EXPECTED_TARGETS = {
    "tree/a_link": "b.txt",
    "tree/c_link": "b.txt",
    "tree/e_link": "d.txt",
}


def test_7z_listing_decodes_a_folder_once_up_to_its_last_link() -> None:
    with enable_measurement(), open_archive(_LINKS_SOLID) as reader:
        members = reader.members()
        assert _link_targets(members) == _EXPECTED_TARGETS
        # Once, to the last link's end; per link it would be the sum of the ends.
        assert _decoded(reader) == _LINK_ENDS[-1] != sum(_LINK_ENDS)


@pytest.mark.parametrize("streaming", _MODES)
@pytest.mark.parametrize("read_streams", [True, False], ids=["read-all", "read-none"])
def test_7z_pass_reads_links_through_its_own_decode(
    read_streams: bool, streaming: bool
) -> None:
    """A pass to the end sets the targets on the members it yielded, in both modes.

    Random access used to leave them unset until ``members()`` was called, which then
    decoded the folder a second time for them.
    """
    with (
        enable_measurement(),
        open_archive(_LINKS_SOLID, streaming=streaming) as reader,
    ):
        yielded = []
        for member, stream in reader.stream_members():
            yielded.append(member)
            if read_streams and stream is not None:
                stream.read()
        # The yielded objects themselves, before anything else could resolve them.
        assert _link_targets(yielded) == _EXPECTED_TARGETS
        expected = _FOLDER_SIZE if read_streams else _LINK_ENDS[-1]
        assert _decoded(reader) == expected
        members = complete_listing(reader)
        assert _link_targets(members) == _EXPECTED_TARGETS
        assert _decoded(reader) == expected


@pytest.mark.parametrize("streaming", _MODES)
def test_7z_abandoned_pass_keeps_link_bytes_and_resolves_nothing(
    streaming: bool,
) -> None:
    """A pass left before its end publishes nothing and sets no target.

    It keeps the link bytes it read, for a later listing. Fails if finalization moves
    above the yields (or into a ``finally``).
    """
    with open_archive(_LINKS_SOLID, streaming=streaming) as reader:
        links: list[ArchiveMember] = []
        for member, _stream in reader.stream_members():
            if member.type is MemberType.SYMLINK:
                links.append(member)
                if len(links) == 2:
                    break
        assert len(links) == 2
        base = _base(reader)
        assert base._materialized is None  # type: ignore[attr-defined]
        assert [m.link_target for m in links] == [None, None]
        kept = base._link_data  # type: ignore[attr-defined]
        assert set(kept) == {m.member_id for m in links}


@pytest.mark.parametrize("streaming", _MODES)
@pytest.mark.parametrize(
    ("abandon_after", "expected"),
    [
        # The pass read every link, so listing decodes nothing more.
        pytest.param(3, _LINK_ENDS[-1], id="after-last-link"),
        # A solid decode cannot resume: the last link costs a decode from the start.
        pytest.param(2, _LINK_ENDS[1] + _LINK_ENDS[-1], id="after-second-link"),
    ],
)
def test_7z_listing_after_an_abandoned_pass_reuses_its_link_bytes(
    abandon_after: int, expected: int, streaming: bool
) -> None:
    """Listing used to drop what the abandoned pass read and decode the folder again.

    A streaming reader refuses ``members()``, so it lists with ``members_report()``.
    """
    with (
        enable_measurement(),
        open_archive(_LINKS_SOLID, streaming=streaming) as reader,
    ):
        seen = 0
        for member, _stream in reader.stream_members():
            seen += member.type is MemberType.SYMLINK
            if seen == abandon_after:
                break
        assert _decoded(reader) == _LINK_ENDS[abandon_after - 1]
        members = complete_listing(reader) if streaming else reader.members()
        assert _link_targets(members) == _EXPECTED_TARGETS
        assert _decoded(reader) == expected


@pytest.mark.parametrize("streaming", _MODES)
def test_7z_nonsolid_decodes_each_link_folder_once(streaming: bool) -> None:
    with (
        enable_measurement(),
        open_archive(_LINKS_NONSOLID, streaming=streaming) as reader,
    ):
        if streaming:
            for _member, _stream in reader.stream_members():
                pass
            members = complete_listing(reader)
        else:
            members = reader.members()
        assert _link_targets(members) == _EXPECTED_TARGETS
        assert _decoded(reader) == 3 * len("b.txt")


_NO_LINK_READS = ArchiveyConfig(read_link_targets=False)


@pytest.mark.parametrize("streaming", _MODES)
def test_7z_without_link_reads_decodes_nothing_for_links(streaming: bool) -> None:
    with (
        enable_measurement(),
        open_archive(_LINKS_SOLID, streaming=streaming, config=_NO_LINK_READS) as r,
    ):
        if not streaming:
            r.members()
        for _member, _stream in r.stream_members():
            pass
        members = complete_listing(r)
        assert _link_targets(members) == dict.fromkeys(_EXPECTED_TARGETS)
        assert _decoded(r) == 0
        assert DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE not in r.diagnostics.counts


@pytest.mark.parametrize("streaming", _MODES)
def test_7z_extract_all_without_link_reads_decodes_each_folder_once(
    streaming: bool, tmp_path: Path
) -> None:
    with (
        enable_measurement(),
        open_archive(_LINKS_SOLID, streaming=streaming, config=_NO_LINK_READS) as r,
    ):
        report = r.extract_all(tmp_path)
        assert _decoded(r) == _FOLDER_SIZE
    statuses = {res.member.name: res.status for res in report.results}
    for name, target in _EXPECTED_TARGETS.items():
        assert statuses[name] is ExtractionStatus.EXTRACTED
        assert os.readlink(tmp_path / name) == target


@pytest.mark.parametrize("streaming", _MODES)
def test_7z_link_excluded_by_the_selector_still_resolves_by_default(
    streaming: bool,
) -> None:
    with open_archive(_LINKS_SOLID, streaming=streaming) as reader:
        for _member, _stream in reader.stream_members(
            lambda m: m.type is not MemberType.SYMLINK
        ):
            pass
        members = complete_listing(reader)
    assert _link_targets(members) == _EXPECTED_TARGETS


# --------------------------------------------------------------------------------
# read_link_targets=False
# --------------------------------------------------------------------------------


class _Provider:
    """A password provider that records every request."""

    def __init__(self, answer: str | None = None) -> None:
        self.answer = answer
        self.requests: list[PasswordRequest] = []

    def __call__(self, request: PasswordRequest) -> str | None:
        self.requests.append(request)
        return self.answer


def _encrypted(fmt: str) -> Path:
    """``a.txt``, ``b_link`` (→ ``a.txt``), ``c.txt``, encrypted with ``SECRET``.

    Committed rather than built with the ``7z`` CLI at test time: not every platform's
    ``7z`` stores a symlink as a link.
    """
    return _FIXTURES / "sevenzip" / f"encrypted_link.{fmt}"


@pytest.mark.parametrize("fmt", ["7z", "zip"])
@pytest.mark.parametrize("streaming", _MODES)
def test_without_link_reads_a_pass_reads_and_prompts_for_nothing(
    fmt: str, streaming: bool
) -> None:
    provider = _Provider()
    with (
        enable_measurement(),
        open_archive(
            _encrypted(fmt),
            streaming=streaming,
            password=provider,
            config=_NO_LINK_READS,
        ) as reader,
    ):
        for _member, _stream in reader.stream_members(lambda m: False):
            pass
        members = complete_listing(reader)
        assert _decoded(reader) == 0
        assert provider.requests == []
        (link,) = [m for m in members if m.type is MemberType.SYMLINK]
        assert link.link_target is None
        assert (
            DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE not in reader.diagnostics.counts
        )


@pytest.mark.parametrize(
    "fmt",
    [
        # 7-Zip encrypts a .7z with AES, which needs `cryptography` to decode.
        pytest.param("7z", id="7z", marks=requires("cryptography")),
        pytest.param("zip", id="zip"),
    ],
)
@pytest.mark.parametrize("streaming", _MODES)
def test_without_link_reads_extract_all_filters_before_reading(
    fmt: str, streaming: bool, tmp_path: Path
) -> None:
    archive = _encrypted(fmt)
    seen: list[tuple[str, str | None]] = []

    def recording(member: ArchiveMember) -> ArchiveMember:
        seen.append((member.name, member.link_target))
        return member

    with open_archive(
        archive, streaming=streaming, password="SECRET", config=_NO_LINK_READS
    ) as reader:
        report = reader.extract_all(tmp_path / "out", filter=recording)
    assert ("b_link", None) in seen
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses["b_link"] is ExtractionStatus.EXTRACTED
    assert os.readlink(tmp_path / "out" / "b_link") == "a.txt"

    # A filter that drops targetless links: the provider is never consulted for one.
    provider = _Provider()

    def drop_targetless(member: ArchiveMember) -> ArchiveMember | None:
        if member.type is MemberType.SYMLINK and member.link_target is None:
            return None
        return member

    with open_archive(
        archive, streaming=streaming, password=provider, config=_NO_LINK_READS
    ) as reader:
        reader.extract_all(
            tmp_path / "out2",
            members=lambda m: m.type is MemberType.SYMLINK,
            filter=drop_targetless,
        )
    assert provider.requests == []


def test_without_link_reads_extraction_fills_only_the_links_it_wrote(
    tmp_path: Path,
) -> None:
    path = _zip(
        tmp_path,
        [
            ("a.txt", b"one", False),
            ("link-a", b"a.txt", True),
            ("link-b", b"a.txt", True),
        ],
    )
    with open_archive(path, config=_NO_LINK_READS) as reader:
        reader.extract_all(tmp_path / "out", members=["link-a"])
        by_name = {m.name: m for m in reader.members()}
    assert by_name["link-a"].link_target == "a.txt"
    assert by_name["link-b"].link_target is None


def test_without_link_reads_open_follows_a_link(tmp_path: Path) -> None:
    path = _zip(tmp_path, [("a.txt", b"one", False), ("link", b"a.txt", True)])
    with open_archive(path, config=_NO_LINK_READS) as reader:
        assert reader.get("link").link_target is None  # type: ignore[union-attr]
        assert reader.read("link") == b"one"
        assert reader.get("link").link_target == "a.txt"  # type: ignore[union-attr]


def test_without_link_reads_rar4_targets_stay_unset_and_rar5_are_kept() -> None:
    with open_archive(_RAR4_SOLID, config=_NO_LINK_READS) as reader:
        rar4 = _link_targets(reader.members())
    with open_archive(_RAR5_SOLID, config=_NO_LINK_READS) as reader:
        rar5 = _link_targets(reader.members())
    assert rar4 and set(rar4.values()) == {None}
    assert rar5 and None not in rar5.values()
