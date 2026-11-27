"""Lazy tqdm progress helper (tqdm ships in the ``[recommended]`` extra).

One :class:`ProgressCallback` per command shows one line on stderr. It takes two kinds
of event:

- :class:`~archivey.types.ExtractionProgress` from ``test`` and ``extract``: output
  bytes against the selected members' total.
- :class:`~archivey.types.SourceProgress` from ``ArchiveyConfig.on_source_read``
  (:meth:`ProgressCallback.source_read`), for every verb: how far the archive's own file
  has been read. Before the first member (and in ``list``, ``info`` and ``cat``) it is
  a status line that appears only after :data:`STATUS_DELAY` seconds and is cleared at
  the end. In ``test`` and ``extract``, when the output total is unknown (a
  ``.tar.xz`` has no index), the bar shows the position in the file instead.

For a URL the line also counts the range requests and the bytes they fetched.

Every verb prints its stderr lines, and the CLI's log lines, through
:meth:`ProgressCallback.guard`, which clears the line before each one, so no line is
glued onto a bar.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from typing import Any, Protocol, TextIO, cast

from archivey.cli.format import escape_member_name
from archivey.cli.logging_config import log_lines_through
from archivey.types import ExtractionProgress, SourceProgress


class _TqdmBar(Protocol):
    n: float | int
    total: float | int | None
    desc: str | None

    def set_description(self, desc: str, refresh: bool = True) -> None: ...
    def set_postfix_str(self, s: str = "", refresh: bool = True) -> None: ...
    def update(self, n: float) -> bool | None: ...
    def clear(self) -> None: ...
    def refresh(self) -> None: ...
    def close(self) -> None: ...


STATUS_DELAY = 0.5
"""Seconds a read of the archive's file runs before its status line appears: a quick
command shows nothing."""


class ProgressCallback:
    """Callable progress sink that owns a tqdm bar and can be closed explicitly."""

    def __init__(self, bar_factory: Callable[..., _TqdmBar], display: TextIO) -> None:
        self._bar_factory = bar_factory
        self._display = display
        self._bar: _TqdmBar | None = None
        # The status line of the archive's own file, shown until the first member.
        self._status: _TqdmBar | None = None
        # The latest report of the file the command opened (``nest_level`` 0).
        self._source: SourceProgress | None = None
        # Whether the member bar counts the position in the file (output total unknown).
        self._by_position = False
        self._closed = False
        # Whether a line printed through :meth:`guard` is part-way written: the member
        # bar is cleared until the line ends.
        self._mid_line = False
        # Points the CLI's log lines back at the unguarded stream; set by guard().
        self._restore_log: Callable[[], None] = lambda: None

    def source_read(self, progress: SourceProgress) -> None:
        """``ArchiveyConfig.on_source_read``: archivey read more of the archive's file."""
        if progress.nest_level != 0 or self._closed:
            # A nested archive's reads are part of a member's: the member bar shows them.
            return
        self._source = progress
        bar = self._bar
        if bar is not None:
            if self._by_position:
                self._show_position(bar, progress)
            return
        status = self._status
        if status is None:
            status = self._bar_factory(
                total=progress.size,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                file=self._display,
                leave=False,
                desc="reading",
                delay=STATUS_DELAY,
                dynamic_ncols=True,
                disable=False,
            )
            self._status = status
        self._show_position(status, progress)

    def _show_position(self, bar: _TqdmBar, progress: SourceProgress) -> None:
        """Show where in the file the latest read ended; for a URL, its requests."""
        position = progress.position
        if progress.size is not None:
            position = min(position, progress.size)
            if bar.total != progress.size:
                bar.total = progress.size
        delta = position - int(bar.n)
        if progress.requests is not None:
            # No refresh here: a refresh shows the status line before its delay, and
            # tqdm then leaves it on screen at close. ``update`` shows it.
            bar.set_postfix_str(_fetched(progress), refresh=False)
        if delta:
            # ``update`` with a negative step moves back: ZIP reads its directory at
            # the end first, then the members from the start.
            bar.update(delta)

    def clear_status(self) -> None:
        """Clear the status line before a line is printed; it comes back with the
        next read after :data:`STATUS_DELAY`."""
        status = self._status
        if status is not None:
            self._status = None
            status.close()

    def guard(self, stream: TextIO) -> TextIO:
        """``stream``, which clears the status line and the member bar before each line
        written to it and shows the bar again after. A command prints its stderr
        lines through it, and the CLI's log lines go through it until :meth:`close`,
        so no line is glued onto a bar. ``stream`` itself when the bars are shown on
        another stream.

        Writes are whole lines: a line's last write ends with ``\\n`` (``print``
        writes the text, then the newline). A write that leaves its line open keeps
        the bars cleared until the line ends.
        """
        if stream is not self._display:
            return stream
        # It forwards everything else to ``stream``.
        guarded = cast(
            "TextIO", _ClearingStream(stream, self._before_write, self._after_line)
        )
        self._restore_log = log_lines_through(stream, guarded)
        return guarded

    def _before_write(self) -> None:
        if self._mid_line:
            return
        self._mid_line = True
        self.clear_status()
        if self._bar is not None:
            self._bar.clear()

    def _after_line(self) -> None:
        self._mid_line = False
        if self._bar is not None:
            self._bar.refresh()

    def __call__(self, progress: ExtractionProgress) -> None:
        if self._closed:
            return
        total = progress.total_bytes_estimated
        source = self._source
        bar = self._bar
        if bar is None:
            self.clear_status()
            # The output total is unknown (no index), but the file's size is: the bar
            # counts the position in the file, which a start-to-end read moves along.
            self._by_position = (
                total is None and source is not None and source.size is not None
            )
            # mininterval=0 / miniters=1: small archives finish in one callback; the
            # default 0.1s throttle would hide the bar entirely.
            bar = self._bar_factory(
                total=source.size if self._by_position and source else total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                file=self._display,
                leave=True,
                desc=escape_member_name(progress.member.name),
                mininterval=0,
                miniters=1,
                dynamic_ncols=True,
                disable=False,
            )
            self._bar = bar
        safe_name = escape_member_name(progress.member.name)
        if bar.desc != safe_name:
            bar.set_description(safe_name, refresh=False)
        if self._by_position:
            assert source is not None
            self._show_position(bar, source)
            bar.refresh()
        else:
            if total is not None and bar.total != total:
                bar.total = total
            if source is not None and source.requests is not None:
                bar.set_postfix_str(_fetched(source), refresh=False)
            delta = progress.bytes_written - int(bar.n)
            if delta > 0:
                bar.update(delta)
            else:
                bar.refresh()
        if (
            progress.members_total is not None
            and progress.members_done >= progress.members_total
        ):
            self.close()

    def close(self) -> None:
        """Close the bar; later events show nothing."""
        self._closed = True
        self._restore_log()
        self.clear_status()
        bar = self._bar
        if bar is not None:
            bar.close()
            self._bar = None


class _ClearingStream:
    """A text stream that clears the progress lines before a line is written to it
    (:meth:`ProgressCallback.guard`). Everything else goes to the stream."""

    def __init__(
        self,
        stream: TextIO,
        before_write: Callable[[], None],
        after_line: Callable[[], None],
    ) -> None:
        self._stream = stream
        self._before_write = before_write
        self._after_line = after_line

    def write(self, text: str) -> int:
        if not text:
            return 0
        self._before_write()
        written = self._stream.write(text)
        if text.endswith("\n"):
            self._after_line()
        return written

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _fetched(progress: SourceProgress) -> str:
    """``3 requests, 1.2 MiB fetched``: what a URL source's requests brought."""
    count = progress.requests or 0
    noun = "request" if count == 1 else "requests"
    return f"{count} {noun}, {_size(progress.bytes_read)} fetched"


def _size(n: int) -> str:
    """``n`` bytes in the binary units tqdm's bar shows (``1.2 MiB``)."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _display_stream(preferred: TextIO) -> TextIO | None:
    """Pick a stream that can show an interactive progress bar.

    Prefer ``preferred`` when it is a TTY. If it has been redirected, fall back to
    ``sys.__stderr__`` when that is still a console (some runners wrap ``sys.stderr``
    while leaving the real console usable).
    """
    if preferred.isatty():
        return preferred
    fallback = getattr(sys, "__stderr__", None)
    if fallback is not None and fallback is not preferred and fallback.isatty():
        return fallback
    return None


def make_progress_callback(
    *,
    hide_progress: bool,
    stream: TextIO | None = None,
) -> ProgressCallback | None:
    """Return an ``on_progress`` callback, or ``None`` when progress should be suppressed.

    Imports ``tqdm`` lazily so a core-only install never loads it at import time.
    """
    if hide_progress:
        return None

    out = stream if stream is not None else sys.stderr
    display = _display_stream(out)
    if display is None:
        return None

    try:
        from tqdm import tqdm
    except ImportError:
        return None

    # The bars are drawn by this process alone. tqdm's default lock is a
    # multiprocessing lock, which on Python 3.14+ starts a helper process (about
    # 14 ms) at the first bar.
    tqdm.set_lock(threading.RLock())
    return ProgressCallback(tqdm, display)
