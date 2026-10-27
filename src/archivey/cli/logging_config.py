"""CLI logging setup (library loggers → stderr), scoped to one invocation."""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TextIO

# The library logs this when ``extract_all`` skips a member under CONTINUE (both sites in
# ``archivey/internal/extraction.py`` point back here). ``extract`` reports the
# outcome from the returned report instead.
_MEMBER_SKIP_MESSAGE = "Skipping %s %r: %s"
# The library logs this (``_note_solid_open`` in ``archivey/internal/base_reader.py``)
# the first time an ``open()`` decodes a solid block again. Its advice is about the
# library API, so it is dropped while the CLI's own opens run.
_SOLID_REOPEN_MESSAGE = (
    "Archive %r is solid: opening %r decoded again %d bytes an earlier open() "
    "on this reader had decoded, because each open() or read() decodes its "
    "member's solid block from the start. Reading many members this way is "
    "quadratic in the block size; stream_members() decodes each block once. "
    "Logged once per reader."
)


class _MemberSkipHold(logging.Filter):
    """Hold back the library's member-skip warnings while ``held`` is a list, and drop
    its solid re-open advice while ``own_opens`` is set."""

    def __init__(self, handler: logging.Handler) -> None:
        super().__init__()
        self.handler = handler
        self.held: list[logging.LogRecord] | None = None
        self.own_opens = False

    def filter(self, record: logging.LogRecord) -> bool:
        if self.own_opens and record.msg == _SOLID_REOPEN_MESSAGE:
            return False
        if self.held is not None and record.msg == _MEMBER_SKIP_MESSAGE:
            self.held.append(record)
            return False
        return True


# The hold on the handler of the invocation in progress; None outside cli_logging. A
# context variable, so two invocations on different threads each find their own.
_hold: ContextVar[_MemberSkipHold | None] = ContextVar("_hold", default=None)


@contextmanager
def cli_logging(*, verbose: bool, err: TextIO) -> Generator[None, None, None]:
    """Route the ``archivey`` logger tree to ``err`` for one CLI invocation (D4).

    Default level is WARNING so normalization / diagnostic warnings are visible
    with a real formatter instead of Python's last-resort handler; ``-v`` lowers
    the level to INFO. The handler is installed only for the duration of the
    invocation and ``propagate`` is left untouched: with a handler present the
    last-resort handler never fires, and library records still reach root-level
    handlers (pytest's caplog, an embedding app). Mutating ``propagate`` or
    keeping a process-global handler would leak state into everything else in
    the process — on pytest 8.3 (the supported floor) it silently blinds every
    later caplog-based warning assertion.

    The handler does **not** escape. Archive-derived text is escaped where it becomes
    a message — exceptions escape their own (:mod:`archivey.exceptions`), and log call
    sites interpolate member names with ``%r`` — so escaping again here would double
    every backslash the exception already wrote. It would also be the weaker place to
    do it: a formatter only guards records reaching a handler the CLI installed, and
    an uncaught exception's traceback never passes through one.
    """
    root = logging.getLogger("archivey")
    handler: logging.StreamHandler[TextIO] = logging.StreamHandler(err)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    hold = _MemberSkipHold(handler)
    handler.addFilter(hold)
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO if verbose else logging.WARNING)
    token = _hold.set(hold)
    try:
        yield
    finally:
        _hold.reset(token)
        root.removeHandler(handler)
        root.setLevel(old_level)
        handler.close()


@contextmanager
def member_skips_reported_elsewhere() -> Generator[None, None, None]:
    """Keep the library's ``Skipping …`` warnings off stderr for a run that reports.

    ``extract`` prints a ``blocked:`` or ``failed:`` line for each ``BLOCKED`` or
    ``FAILED`` result in the report ``extract_all`` returns, so the warning would report
    those members twice. The report is what the CLI follows, not the warnings: when a
    later copy of a duplicate name supersedes an earlier one, the library drops the
    earlier copy's error with it (random access never tries that copy), and so does
    the CLI, so a streaming and a random-access run report the same outcomes.

    When the run raises instead, there is no report: the held warnings are written
    then, before the caller prints why the run stopped. Only the CLI's own handler is
    held back; handlers an embedding application installed still see every record.
    """
    hold = _hold.get()
    if hold is None or hold.held is not None:
        yield
        return
    hold.held = []
    try:
        yield
    except BaseException:
        # Release the hold before writing: handle() passes each record back through
        # this filter, which would otherwise append it to the list being written.
        held, hold.held = hold.held, None
        for record in held:
            hold.handler.handle(record)
        raise
    finally:
        hold.held = None


@contextmanager
def cli_opens_members() -> Generator[None, None, None]:
    """Drop the library's solid re-open advice while the CLI opens members itself.

    The advice names ``stream_members()``, which an operator running the CLI is not
    calling: the opens are the CLI's (``archivey test`` opening links whose target the
    pass could not read). Only the CLI's own handler drops it; handlers an embedding
    application installed still see the record.
    """
    hold = _hold.get()
    if hold is None or hold.own_opens:
        yield
        return
    hold.own_opens = True
    try:
        yield
    finally:
        hold.own_opens = False
