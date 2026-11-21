"""The CLI's line for the reads of the archive's file (``on_source_read``)."""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Any

import pytest

from archivey import ExtractionProgress, SourceProgress
from archivey.cli import cat_cmd, extract_cmd, info_cmd, list_cmd, test_cmd
from archivey.cli.main import main
from archivey.cli.progress import STATUS_DELAY, ProgressCallback
from archivey.types import ArchiveMember, MemberType


class _FakeBar:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.n = 0
        self.total = kwargs.get("total")
        self.desc = kwargs.get("desc")
        self.postfix = ""
        self.closed = False

    def set_description(self, desc: str, refresh: bool = True) -> None:
        self.desc = desc

    def set_postfix_str(self, s: str = "", refresh: bool = True) -> None:
        assert not refresh, "a refresh shows the line before its delay"
        self.postfix = s

    def update(self, n: float) -> None:
        self.n += n

    def refresh(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _Bars:
    def __init__(self) -> None:
        self.made: list[_FakeBar] = []

    def __call__(self, **kwargs: Any) -> _FakeBar:
        bar = _FakeBar(**kwargs)
        self.made.append(bar)
        return bar


def _callback() -> tuple[ProgressCallback, _Bars]:
    bars = _Bars()
    return ProgressCallback(bars, io.StringIO()), bars


def _local(
    position: int, size: int | None = 1000, nest_level: int = 0
) -> SourceProgress:
    return SourceProgress(
        "a.tar.xz", size, position, position, read_start=0, nest_level=nest_level
    )


def _member_event(written: int, total: int | None) -> ExtractionProgress:
    member = ArchiveMember(type=MemberType.FILE, name="m.bin", size=None)
    return ExtractionProgress(
        member=member,
        bytes_written=written,
        total_bytes_estimated=total,
        members_done=0,
        members_total=None,
        member_bytes_written=written,
        members_extracted=0,
        members_blocked=0,
    )


def test_reads_before_a_member_show_a_delayed_status_line() -> None:
    cb, bars = _callback()
    cb.source_read(_local(300))
    cb.source_read(_local(600))
    (status,) = bars.made
    assert status.kwargs["delay"] == STATUS_DELAY
    assert status.kwargs["leave"] is False
    assert (status.n, status.total) == (600, 1000)
    cb.close()
    assert status.closed


def test_a_position_past_the_size_and_backward_moves_are_shown() -> None:
    cb, bars = _callback()
    cb.source_read(_local(1000))
    cb.source_read(_local(1200))  # clamped to the size
    cb.source_read(_local(100))  # ZIP: directory first, then the members
    assert bars.made[0].n == 100


def test_nested_reads_are_left_to_the_member_bar() -> None:
    cb, bars = _callback()
    cb.source_read(_local(300, nest_level=1))
    assert bars.made == []


def test_the_member_bar_replaces_the_status_line() -> None:
    cb, bars = _callback()
    cb.source_read(_local(300))
    cb(_member_event(50, 500))
    status, member = bars.made
    assert status.closed
    # The output total is known: the bar counts output bytes.
    assert (member.n, member.total) == (50, 500)
    cb.source_read(_local(700))
    assert member.n == 50


def test_an_unknown_output_total_counts_the_position_in_the_file() -> None:
    cb, bars = _callback()
    cb.source_read(_local(100))
    cb(_member_event(50, None))
    member = bars.made[-1]
    assert (member.n, member.total) == (100, 1000)
    cb.source_read(_local(800))
    assert member.n == 800
    cb(_member_event(5000, None))
    assert member.n == 800


def test_a_pipe_has_no_size_so_the_bar_counts_output() -> None:
    cb, bars = _callback()
    cb.source_read(_local(100, size=None))
    cb(_member_event(50, None))
    member = bars.made[-1]
    assert (member.n, member.total) == (50, None)


def test_a_url_shows_its_requests() -> None:
    cb, bars = _callback()
    cb.source_read(
        SourceProgress(
            "https://example.invalid/a.zip",
            10 << 20,
            3 << 20,
            5 << 20,
            requests=4,
            request_start=4 << 20,
            request_end=5 << 20,
            request_received=1 << 20,
            request_done=True,
        )
    )
    assert bars.made[0].postfix == "4 requests, 3.0 MiB fetched"


def test_nothing_is_shown_after_close() -> None:
    cb, bars = _callback()
    cb.close()
    cb.source_read(_local(300))
    cb(_member_event(50, 500))
    assert bars.made == []


def _tar_gz(tmp_path: Path) -> Path:
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        data = os.urandom(3 << 20)
        info = tarfile.TarInfo("big.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize("verb", ["list", "info", "test", "extract", "cat"])
def test_every_verb_reports_the_reads_of_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    path = _tar_gz(tmp_path)
    seen: list[SourceProgress] = []
    made: list[ProgressCallback] = []

    class _Recording(ProgressCallback):
        def source_read(self, progress: SourceProgress) -> None:
            seen.append(progress)
            super().source_read(progress)

    def make(**kwargs: Any) -> ProgressCallback:
        assert kwargs["hide_progress"] is False
        cb = _Recording(_Bars(), io.StringIO())
        made.append(cb)
        return cb

    module = {
        "list": list_cmd,
        "info": info_cmd,
        "test": test_cmd,
        "extract": extract_cmd,
        "cat": cat_cmd,
    }[verb]
    monkeypatch.setattr(module, "make_progress_callback", make)
    argv = [verb, str(path)]
    if verb == "extract":
        argv += ["-d", str(tmp_path / "out")]
    out: Any = io.StringIO()
    if verb == "cat":
        out = io.TextIOWrapper(io.BytesIO())
    assert main(argv, out=out, err=io.StringIO()) == 0
    assert seen
    if verb in ("list", "test", "extract", "cat"):
        # Read to the end: the whole .tar.gz, the trailer probes included.
        assert max(p.position for p in seen) == path.stat().st_size
    assert made[0]._closed


def test_hide_progress_shows_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _tar_gz(tmp_path)
    calls: list[bool] = []

    def make(**kwargs: Any) -> None:
        calls.append(kwargs["hide_progress"])

    monkeypatch.setattr(list_cmd, "make_progress_callback", make)
    assert main(["list", "--hide-progress", str(path)], out=io.StringIO()) == 0
    assert calls == [True]


def test_tqdm_takes_the_status_line_s_arguments() -> None:
    # tqdm 4.67 takes ``delay``; the floor in pyproject must keep it.
    tqdm = pytest.importorskip("tqdm")
    bar = tqdm.tqdm(total=10, file=io.StringIO(), delay=STATUS_DELAY, leave=False)
    bar.update(1)
    bar.close()
