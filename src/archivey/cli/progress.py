"""Lazy tqdm progress helper (tqdm ships in the ``[recommended]`` extra)."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Protocol, TextIO

from archivey import ExtractionProgress
from archivey.cli.format import escape_member_name


class _TqdmBar(Protocol):
    n: float | int
    total: float | int | None
    desc: str | None

    def set_description(self, desc: str, refresh: bool = True) -> None: ...
    def update(self, n: float) -> bool | None: ...
    def refresh(self) -> None: ...
    def close(self) -> None: ...


class ProgressCallback:
    """Callable progress sink that owns a tqdm bar and can be closed explicitly."""

    def __init__(self, bar_factory: Callable[..., _TqdmBar], display: TextIO) -> None:
        self._bar_factory = bar_factory
        self._display = display
        self._bar: _TqdmBar | None = None

    def __call__(self, progress: ExtractionProgress) -> None:
        total = progress.total_bytes_estimated
        bar = self._bar
        if bar is None:
            # mininterval=0 / miniters=1: small archives finish in one callback; the
            # default 0.1s throttle would hide the bar entirely.
            bar = self._bar_factory(
                total=total,
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
        if total is not None and bar.total != total:
            bar.total = total
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
        bar = self._bar
        if bar is not None:
            bar.close()
            self._bar = None


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

    return ProgressCallback(tqdm, display)
