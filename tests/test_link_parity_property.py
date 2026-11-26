"""Differential property test of link extraction: one archive, four ways to extract it.

Random small TARs of files, directories, symlinks, hard links and repeated names are
extracted as the reference run (random access, every member selected) and three more
ways, each of which the spec says gives the same outcome:

- **held**: the hard-link sources ``src1`` and ``src2`` are excluded by ``members``, so
  every hard link to them is held back as a placeholder and filled after the pass.
- **stream**: a forward-only pass (``streaming=True``).
- **dry**: ``dry_run=True``, compared on results only.

Each must give the reference run's statuses and paths, and the same tree on disk. The
one accepted difference is the streaming one: a hard link whose source has no written
copy left fails on a forward-only stream ("cannot be recovered on a forward-only
stream"). A streaming run that has one is not compared with the reference, since that
failure changes members before it as well as after it (a name the link would have
overwritten stays as it was). The test finds such a link by its "Skipping hardlink"
warning, since a later copy of the link's name revises its result to ``SUPERSEDED``,
and asserts what still holds there: only hard links fail that way, and never in the
other runs.

This started as the design's hand-run fuzzer (the archived
``link-extraction-redesign`` change, ``evidence/linkfuzz.py``). A shrunk
counterexample is pinned as an ``@example``.

CI budget: 300 examples with the shared ``archivey`` profile's fixed derandomized
choice, or ``ARCHIVEY_FUZZ_EXAMPLES`` when that is larger: a few seconds. A mismatch can
be rarer than 1 in 1,000 archives, so the daily CI run adds a soak:
``ARCHIVEY_LINK_PARITY_EXAMPLES=N`` runs N examples with a new random choice each time
(``ci.yml``, ``link-parity-soak``), on a case-sensitive and a case-insensitive
filesystem. A failure prints the archive and the ``@reproduce_failure`` line. Either
variable above the default turns off the suite's 60-second test timeout for this test.
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

try:
    from hypothesis import example, given, settings, strategies as st
except ImportError:  # pragma: no cover - [core-only] leg
    if os.environ.get("ARCHIVEY_LINK_PARITY_EXAMPLES"):
        # The soak asked for examples: a skip would pass it having run none.
        raise
    pytest.skip("hypothesis not installed (dev group)", allow_module_level=True)

from archivey import (
    ExtractionPolicy,
    OnBlocked,
    OnError,
    OverwritePolicy,
    open_archive,
)

pytestmark = pytest.mark.skipif(
    not hasattr(os, "symlink") or os.name == "nt", reason="POSIX symlinks"
)

# Few names, so that names repeat, nest under each other and differ only in case.
_NAMES = ["a", "b", "a/x", "b/x", "a/x/y", "A", "c"]
_SYM_TARGETS = ["a", "b", "c", "x", "../x", "a/..", ".", "b/x"]
_SOURCES = ["src1", "src2"]
_UNRECOVERABLE = "cannot be recovered on a forward-only stream"
# The soak: a count of examples, drawn at random rather than the profile's fixed choice.
_SOAK = int(os.environ.get("ARCHIVEY_LINK_PARITY_EXAMPLES", "0"))
_EXAMPLES = _SOAK or max(settings.default.max_examples, 300)

Spec = tuple[str, str, Any]


@st.composite
def _archives(draw: st.DrawFn) -> list[Spec]:
    """``src1`` and ``src2`` first (the sources the held run excludes), then 2 to 7
    members; a hard link names an earlier file."""
    specs: list[Spec] = [("file", "src1", b"1"), ("file", "src2", b"2")]
    files = list(_SOURCES)
    for i in range(draw(st.integers(2, 7))):
        name = draw(st.sampled_from(_NAMES))
        kind = draw(st.sampled_from(["file", "dir", "sym", "hard", "hard"]))
        if kind == "file":
            specs.append(("file", name, f"f{i}".encode()))
            files.append(name)
        elif kind == "dir":
            specs.append(("dir", name, None))
        elif kind == "sym":
            specs.append(("sym", name, draw(st.sampled_from(_SYM_TARGETS))))
        else:
            specs.append(("hard", name, draw(st.sampled_from(files))))
    return specs


def _tar(specs: list[Spec]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for kind, name, payload in specs:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                info.mode = 0o644
                t.addfile(info, io.BytesIO(payload))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
            else:
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = payload
            t.addfile(info)
    return buf.getvalue()


def _tree(dest: Path) -> dict[str, tuple[Any, ...]]:
    """What is on disk under ``dest``, leaving out the sources (the held run does not
    write them)."""
    out: dict[str, tuple[Any, ...]] = {}
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            path = Path(root) / name
            rel = path.relative_to(dest).as_posix()
            if rel in _SOURCES:
                continue
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            elif path.is_dir():
                out[rel] = ("dir",)
            else:
                out[rel] = ("file", path.read_bytes())
    return out


def _extract(
    data: bytes,
    dest: Path,
    *,
    overwrite: OverwritePolicy,
    policy: ExtractionPolicy,
    held: bool = False,
    streaming: bool = False,
    dry: bool = False,
) -> tuple[list[tuple[str, str, str | None, str]], dict[str, tuple[Any, ...]] | None]:
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.extract_all(
            dest,
            overwrite=overwrite,
            policy=policy,
            on_error=OnError.CONTINUE,
            on_blocked=OnBlocked.SKIP,
            members=(lambda m: m.name not in _SOURCES) if held else None,
            dry_run=dry,
        )
    results = [
        (
            r.member.name,
            r.status.name,
            None if r.path is None else r.path.relative_to(dest).as_posix(),
            "" if r.error is None else str(r.error),
        )
        for r in report.results
        if r.member.name not in _SOURCES
    ]
    if dry:
        return results, None
    return results, _tree(dest) if dest.exists() else {}


def _outcome(
    run: tuple[list[tuple[str, str, str | None, str]], Any],
) -> tuple[list[tuple[str, str, str | None]], Any]:
    """A run's results without the error texts, which may name the run's own paths,
    and its tree."""
    results, tree = run
    return [(name, status, path) for name, status, path, _ in results], tree


@pytest.fixture(scope="module")
def scratch() -> Iterator[Path]:
    """Module-scoped, so it composes with ``@given``; each example makes its own
    directory under it."""
    root = Path(tempfile.mkdtemp(prefix="archivey-link-parity-"))
    yield root
    shutil.rmtree(root, ignore_errors=True)


class _Unrecoverable(logging.Handler):
    """Collects the "Skipping hardlink ..." warnings of the streaming exception. The
    result is not enough: a later copy of the link's name revises the failed link's
    result to ``SUPERSEDED``, which carries no error."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if _UNRECOVERABLE in message:
            self.seen.append(message)


_UNRECOVERABLE_LOG = _Unrecoverable()


@pytest.fixture(autouse=True)
def _quiet() -> Iterator[None]:
    # Every refused or failed member logs; thousands of runs would flood the output.
    # Archivey's records go to the collector alone.
    archivey_logger = logging.getLogger("archivey")
    propagate = archivey_logger.propagate
    archivey_logger.propagate = False
    archivey_logger.addHandler(_UNRECOVERABLE_LOG)
    yield
    archivey_logger.removeHandler(_UNRECOVERABLE_LOG)
    archivey_logger.propagate = propagate


# A deeper run outlasts the suite's per-test timeout; the 300 stay under it, and keep
# the suite's ``--timeout``.
@(pytest.mark.timeout(0) if _EXAMPLES > 300 else lambda f: f)
@settings(max_examples=_EXAMPLES, derandomize=not _SOAK)
@given(
    specs=_archives(),
    overwrite=st.sampled_from(list(OverwritePolicy)),
    policy=st.sampled_from(list(ExtractionPolicy)),
)
# A held link at a name that a directory, then two files, take after it: before
# placeholders (#1620) the held run did not match the made one.
@example(
    specs=[
        ("file", "src1", b"1"),
        ("file", "src2", b"2"),
        ("hard", "a", "src1"),
        ("dir", "a", None),
        ("file", "a", b"f2"),
        ("file", "a", b"f3"),
    ],
    overwrite=OverwritePolicy.REPLACE,
    policy=ExtractionPolicy.TRUSTED,
)
# On a case-insensitive filesystem only: `a` replaces the file `A` with a placeholder,
# and `a/x` replaces that with a directory. The held run failed `a/x` (#1641).
@example(
    specs=[
        ("file", "src1", b"1"),
        ("file", "src2", b"2"),
        ("file", "A", b"f0"),
        ("hard", "a", "src1"),
        ("hard", "a/x", "src1"),
    ],
    overwrite=OverwritePolicy.REPLACE,
    policy=ExtractionPolicy.STRICT,
)
# On a case-insensitive filesystem only: the hard link ``A`` lands on ``a``'s entry and
# is taken back when the file ``A`` comes, which leaves a link to ``src1`` there. The
# made run sent the file ``A`` over ``src1``, its file's only claim (#1814).
@example(
    specs=[
        ("file", "src1", b"1"),
        ("file", "src2", b"2"),
        ("file", "a", b"f0"),
        ("hard", "A", "src1"),
        ("file", "A", b"f2"),
        ("file", "a", b"f3"),
    ],
    overwrite=OverwritePolicy.REPLACE,
    policy=ExtractionPolicy.STRICT,
)
def test_held_streamed_and_dry_runs_match_the_made_run(
    scratch: Path,
    specs: list[Spec],
    overwrite: OverwritePolicy,
    policy: ExtractionPolicy,
) -> None:
    data = _tar(specs)
    _UNRECOVERABLE_LOG.seen.clear()
    base = Path(tempfile.mkdtemp(dir=scratch))
    try:
        kw = {"overwrite": overwrite, "policy": policy}
        ref = _extract(data, base / "ref", **kw)
        held = _extract(data, base / "held", held=True, **kw)
        assert _outcome(held) == _outcome(ref), "held-back links differ from made ones"
        # The sources are left out of the comparison: the reference writes them.
        assert not any((base / "held" / name).exists() for name in _SOURCES)
        dry = _extract(data, base / "dry", dry=True, **kw)
        assert _outcome(dry)[0] == _outcome(ref)[0], "the dry run differs"
        for run in (ref, held, dry):
            assert not any(_UNRECOVERABLE in error for *_, error in run[0])
        assert not _UNRECOVERABLE_LOG.seen
        stream = _extract(data, base / "stream", streaming=True, **kw)
        kinds = [(name, kind) for kind, name, _ in specs if name not in _SOURCES]
        # A directory member's name has a trailing slash in the results.
        assert [name.rstrip("/") for name, *_ in stream[0]] == [n for n, _ in kinds]
        unrecoverable = [
            kind
            for (_, kind), (*_, error) in zip(kinds, stream[0], strict=True)
            if _UNRECOVERABLE in error
        ]
        # The documented streaming difference, which only a hard link meets. The log
        # also has the links whose results a later copy of their name revised.
        assert set(unrecoverable) <= {"hard"}
        assert all(m.startswith("Skipping hardlink ") for m in _UNRECOVERABLE_LOG.seen)
        if not _UNRECOVERABLE_LOG.seen:
            assert _outcome(stream) == _outcome(ref), "the streaming run differs"
        # Excluded sources on a forward-only stream: no link to one can be made.
        stream_held = _extract(
            data, base / "stream-held", held=True, streaming=True, **kw
        )
        members = [spec for spec in specs if spec[1] not in _SOURCES]
        for (kind, name, target), (_, status, *_) in zip(
            members, stream_held[0], strict=True
        ):
            if kind == "hard" and target in _SOURCES:
                assert status not in {"EXTRACTED", "OVERWRITTEN"}, name
    finally:
        shutil.rmtree(base, ignore_errors=True)
