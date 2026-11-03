"""The logger hierarchy lives in ``archivey.internal.logs``; nothing else types a name."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

import archivey
from archivey.internal import logs
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    resolve_collector,
)

_SRC = Path(archivey.__file__).parent

# The only sites allowed to name a logger themselves (see the ``logs`` docstring).
_ALLOWED = {
    # The CLI installs its handler on the root.
    ("cli/logging_config.py", "archivey"),
    # streamtools imports nothing from archivey, by design.
    ("internal/streams/streamtools/binaryio.py", "archivey.streams"),
}


def test_no_module_hand_types_an_archivey_logger_name() -> None:
    found: set[tuple[str, str]] = set()
    pattern = re.compile(r"""getLogger\(\s*["'](archivey[^"']*)["']""")
    # Any other argument (``__name__``, a variable) also names a logger by hand.
    other = re.compile(r"""getLogger\((?!\s*["']archivey)""")
    for path in _SRC.rglob("*.py"):
        rel = path.relative_to(_SRC).as_posix()
        if rel == "internal/logs.py":
            continue
        text = path.read_text(encoding="utf-8")
        found.update((rel, name) for name in pattern.findall(text))
        found.update((rel, "<not a literal>") for _ in other.findall(text))
    assert found == _ALLOWED


def test_the_streamtools_logger_is_the_hierarchy_logger() -> None:
    from archivey.internal.streams.streamtools import binaryio

    assert binaryio.logger is logs.streams


def test_diagnostic_warnings_go_to_the_logs_diagnostics_logger() -> None:
    assert DiagnosticCollector()._logger is logs.diagnostics
    assert logs.diagnostics.name == "archivey.diagnostics"


def test_the_fallback_collector_logs_its_call_site(
    caplog: pytest.LogCaptureFixture,
) -> None:
    real = DiagnosticCollector()
    with caplog.at_level(logging.DEBUG, logger="archivey.diagnostics"):
        assert resolve_collector(real) is real
        assert caplog.records == []
        fallback = resolve_collector(None)

    assert fallback is not real
    (record,) = caplog.records
    assert record.levelno == logging.DEBUG
    assert "library default policy" in record.getMessage()
    # stacklevel=2: the record names the site that dropped the collector.
    assert record.pathname == __file__
