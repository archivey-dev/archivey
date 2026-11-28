"""Open an archive and extract all of it in one call, for tests that only care about
extraction.

The library has no one-shot ``extract()`` (ADR 0019): callers write
``with open_archive(source) as reader: reader.extract_all(dest)``. This helper is that
pair of lines, so a test that checks what extraction did doesn't repeat it. Open
arguments go to :func:`archivey.open_archive` and everything else to
:meth:`~archivey.ForwardArchiveReader.extract_all`, so the report's diagnostics are
extraction-only, as a caller's would be.

Unlike ``extract_all()`` itself, it returns the report when members were refused: most
tests check what happened to each member, refused ones included, so they want the
report back rather than the ``FilterRejectionError`` the library raises by default. A
failed member still raises its own error, as under the default, so a test of damaged
data needs no extra argument. Given ``on_problem=``, it passes that through unchanged,
which is how a test of the library's default passes ``on_problem="finish"``.

It also checks, after every run that returned or raised, that no ``.archivey-tmp-*``
staging file is left under the destination: only a hard kill may leave one
(docs/extracting.md), so every extraction the suite runs through here guards that.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveFormat, ArchiveyConfig, ExtractionReport, open_archive
from archivey.config import PasswordInput
from archivey.types import ExtractionStatus
from tests.streams_util import open_mode


def open_and_extract(
    source: Any,
    dest: str | Path,
    *,
    format: ArchiveFormat | str | None = None,
    streaming: bool = False,
    password: PasswordInput = None,
    config: ArchiveyConfig | None = None,
    **extract_kwargs: Any,
) -> ExtractionReport:
    with open_archive(
        source,
        format=format,
        **open_mode(source, streaming=streaming),
        password=password,
        config=config,
    ) as reader:
        chosen = "on_problem" in extract_kwargs or any(
            name in extract_kwargs for name in ("on_error", "on_blocked", "abort_on")
        )
        if not chosen:
            extract_kwargs["on_problem"] = "continue"
        try:
            report = reader.extract_all(dest, **extract_kwargs)
        finally:
            assert_no_staging_files(dest)
        if not chosen:
            for result in report.results:
                if (
                    result.status is ExtractionStatus.FAILED
                    and result.error is not None
                ):
                    raise result.error
        return report


def assert_no_staging_files(dest: str | Path) -> None:
    """Fail if an ``.archivey-tmp-*`` staging file is left anywhere under ``dest``.

    Walks without following symlinks, and skips a directory it cannot read (tests
    that lock a directory's mode) rather than failing on it."""
    strays = [
        os.path.join(root, name)
        for root, dirs, files in os.walk(dest)
        for name in dirs + files
        if name.startswith(".archivey-tmp-")
    ]
    assert not strays, f"staging files left behind: {strays}"


def lock_directories_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply each directory member's mode when the directory is created.

    Extraction applies it when the run ends, so an archive alone cannot leave a
    directory the run wrote read-only while the run goes on. A test that needs that
    state (a write refused, a read-only directory replaced) uses this.
    """
    from archivey.internal.extraction import ExtractionCoordinator

    monkeypatch.setattr(
        ExtractionCoordinator,
        "_defer_directory_metadata",
        ExtractionCoordinator._apply_metadata,
    )
