"""Dry-run every archive under a directory: statistics, and a list of files to check.

    python scripts/scan_archives.py ~/backups -o scan.csv [--password-file FILE]

Each archive goes through ``extract_all(dry_run=True)``, the real extraction pass with
file bodies discarded, so nothing is kept on disk. Files are found by content, not by
extension; a file ``detect_format`` cannot place is skipped. The scan runs every content
probe (``always_probe_content=True``), so a raw LZMA Alone, zlib or Brotli file is found
whatever its name, and a probe's false claims show up in the results.

Three outputs:

- ``scan.csv``: one short row per archive. The ``flags`` column says why an archive is
  worth a closer look (``bug``, ``open_error``, ``failed_members``, ``over:max_ratio``,
  ``diag:archive_trailing_data``, ...); filter on it. Empty flags means nothing stood
  out.
- ``scan.log``: the detail for every flagged archive (error messages, the members
  that failed, what declared the largest decoder allocation, archivey's own warnings,
  tracebacks), then the summary.
- The summary, also printed at the end: counts by format and outcome, how many
  archives carry each flag and diagnostic, and for every configurable limit the
  largest value seen, the 99th and 50th percentiles, and how many archives are over
  the default or past half of it without being over. Ctrl-C stops the scan and still
  writes the summary for the archives done so far.

**Resuming.** ``scan.progress`` records every file the scan has finished with, archive
or not, and every directory whose whole subtree is done. ``--resume`` continues an
interrupted scan from it: finished directories are not listed again, finished files
are not opened again, and the CSV and log are appended to. The summary covers the
whole scan, earlier rows read back from the CSV. A resume does not look for changes
in what was already scanned; a changed tree is a new scan. The checkpoint and the CSV
hold paths as the root was typed, so a resume must name the root the same way (a
relative root from the same directory); another spelling is refused. Without
``--resume``, the script refuses to start over a scan that has not finished.

- A file or directory that could not be read is logged under ``not read`` and counted
  in the summary. It is not marked done, so a resume tries it again.
- A file that Ctrl-C interrupted is scanned again on resume.
- A file that the process died on (a native crash, the OOM killer, ``kill -9``) is
  scanned once more on resume, since one stop may have had another cause. If the
  process dies on it again, the next resume writes a row for it with the ``crashed``
  flag and goes on.
- A last line cut off mid-write, in the CSV or in ``scan.progress``, is removed on
  resume; that file is scanned again.

**Limits.** By default the scan turns off the limits that only count something (bytes,
entries, ratio, members, metadata, key-derivation rounds, spool), so the columns show
the true value rather than stopping at the cap. The two that protect the scanning
machine, ``max_decoder_memory`` and ``max_ppmd_held_input``, stay at their
defaults. ``--default-limits`` scans under the full default config instead.

**Where a dry run says less than a real run.** Two of the divergences the dry run
documents (``extract`` in ``src/archivey/internal/extraction.py`` has the full list)
land on this scan's columns. A link whose target leaves the destination and comes back
through a symlink outside it, or climbs above the directory holding it, is refused in
the scratch tree where a real run could accept it, so ``blocked_members`` can name a
member a real extraction would write. And the scratch tree is one filesystem, so a
hardlink never falls back to a copy: ``bytes_written`` is a floor for
``max_extracted_bytes`` when a real destination spans a mount point.

**Resource columns.** ``decoder_memory``, ``kdf_rounds``, ``spool_bytes`` and
``metadata_bytes`` come from the reader's private resource-usage record
(``reader._resource_usage()``). The three peaks are read when the reader closes, even
if the scan raised, since a failing archive is a row they are for; ``metadata_bytes``
is written once the listing was reached, so a row that never listed leaves it empty.
The record is internal, so the script checks it is there and prints ``warning:
resource usage not recorded`` rather than leaving the columns silently empty. ``decoder_memory`` is the largest allocation
an archive *declared* that archivey checks itself; xz, LZMA Alone and zstd hand the
limit to liblzma / libzstd and are not counted, and neither is a size a detection
probe checks. A file the reader could not open has no record, so its row leaves these
columns empty.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import logging
import os
import sys
import tempfile
import time
import traceback
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, NamedTuple

import archivey
from archivey import (
    ArchiveyConfig,
    ArchiveyError,
    DecoderLimits,
    DiagnosticCode,
    EncryptionError,
    ExtractionLimits,
    ExtractionStatus,
    FormatDetectionError,
    ListingLimits,
    MemberType,
    PasswordInput,
    SpoolLimits,
)

# --- Per-archive capture ---------------------------------------------------------


@dataclass
class _Warnings:
    # Archivey's own WARNING log records for the archive being scanned.
    messages: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.messages = []


WARNINGS = _Warnings()
# Set when a reader had no resource-usage record; reported once, in the summary.
USAGE_MISSING = False


class _WarningCapture(logging.Handler):
    """Keep archivey's WARNING records for the archive being scanned.

    Most of them repeat a diagnostic or a failed result, which the CSV already counts,
    but two do not: a dry-run scratch directory that could not be removed, and the
    once-per-process notice that gzip falls back to the stdlib decoder because no
    rapidgzip child can start, which changes what ``seconds`` means for every gzip row.
    So each one goes to its archive's log rather than being dropped.
    """

    def emit(self, record: logging.LogRecord) -> None:
        WARNINGS.messages.append(record.getMessage())


# --- Scanning ----------------------------------------------------------------------


def _scan_config(default_limits: bool) -> ArchiveyConfig:
    if default_limits:
        return ArchiveyConfig(always_probe_content=True)
    return ArchiveyConfig(
        always_probe_content=True,
        extraction_limits=ExtractionLimits.UNLIMITED,
        listing_limits=ListingLimits.UNLIMITED,
        spool_limits=SpoolLimits.UNLIMITED,
        decoder_limits=replace(DecoderLimits(), max_key_derivation_rounds=None),
    )


# Each resource column and the default limit it is measured against.
_LIMITS: tuple[tuple[str, str, float | None], ...] = (
    ("bytes_written", "max_extracted_bytes", ExtractionLimits().max_extracted_bytes),
    ("entries_written", "max_entries", ExtractionLimits().max_entries),
    ("archive_ratio", "max_ratio", ExtractionLimits().max_ratio),
    ("max_member_ratio", "max_ratio", ExtractionLimits().max_ratio),
    ("members", "max_members", ListingLimits().max_members),
    ("metadata_bytes", "max_metadata_bytes", ListingLimits().max_metadata_bytes),
    ("decoder_memory", "max_decoder_memory", DecoderLimits().max_decoder_memory),
    (
        "kdf_rounds",
        "max_key_derivation_rounds",
        DecoderLimits().max_key_derivation_rounds,
    ),
    ("spool_bytes", "spool_limits.max_bytes", SpoolLimits().max_bytes),
)
# A value past this share of its default, and not over it, gets a ``near:`` flag.
_NEAR = 0.5
# Diagnostics too common in ordinary archives to flag on their own.
_ROUTINE_DIAGNOSTICS = frozenset(
    {"member_name_normalized", "member_name_encoding_inferred"}
)
_SLOW_SECONDS = 60.0
_LOGGED_MEMBER_ERRORS = 10

COLUMNS = [
    "path",
    "file_size",
    "format",
    "detected",
    "version",
    "solid",
    "encrypted",
    "open",
    "extract",
    "flags",
    "seconds",
    "members",
    "entries_written",
    "bytes_written",
    "archive_ratio",
    "max_member_ratio",
    "metadata_bytes",
    "decoder_memory",
    "kdf_rounds",
    "spool_bytes",
    "codecs",
    "diagnostics",
    "error",
]
_NUMERIC_COLUMNS = frozenset({"seconds", *(column for column, _, _ in _LIMITS)})


@dataclass
class _Row:
    path: str
    file_size: int | None = None
    # The text columns of the CSV, and the numeric ones below, by column name.
    text: dict[str, str] = field(default_factory=dict)
    numbers: dict[str, float] = field(default_factory=dict)
    diagnostics: Counter[str] = field(default_factory=Counter)
    flags: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def flag(self, name: str) -> None:
        if name not in self.flags:
            self.flags.append(name)

    def failure(self, stage: str, exc: BaseException) -> None:
        """Record an exception that ended ``stage`` (detect, open, extract or scan)."""
        bug = not isinstance(exc, ArchiveyError)
        label = f"BUG:{type(exc).__name__}" if bug else type(exc).__name__
        self.text["extract" if stage == "extract" else "open"] = label
        self.text.setdefault("error", str(exc)[:200])
        self.log.append(f"{stage}: {type(exc).__name__}: {exc}")
        if bug:
            self.flag("bug")
            self.log.append(traceback.format_exc().rstrip())
        elif isinstance(exc, EncryptionError):
            self.flag("needs_password")
        else:
            self.flag(f"{stage}_error")

    @classmethod
    def from_csv(cls, record: Mapping[str, str]) -> _Row:
        """Rebuild a row written by an earlier run, for the summary of a resumed scan."""
        row = cls(path=record["path"])
        if record.get("file_size"):
            row.file_size = int(record["file_size"])
        for column in COLUMNS:
            value = record.get(column) or ""
            if not value or column in ("path", "file_size"):
                continue
            if column == "flags":
                row.flags = value.split()
            elif column == "diagnostics":
                for item in value.split():
                    code, _, count = item.rpartition("=")
                    row.diagnostics[code] = int(count)
            elif column in _NUMERIC_COLUMNS:
                row.numbers[column] = float(value)
            else:
                row.text[column] = value
        return row

    def csv_row(self) -> dict[str, object]:
        out: dict[str, object] = {"path": self.path, "file_size": self.file_size}
        out.update(self.text)
        out.update(self.numbers)
        out["flags"] = " ".join(self.flags)
        out["diagnostics"] = " ".join(
            f"{code}={n}" for code, n in sorted(self.diagnostics.items())
        )
        return out


def _format_name(fmt: archivey.ArchiveFormat) -> str:
    """``tar.gz``, ``zip``, ``raw_stream.xz``: the pair, without the class name."""
    stream = fmt.stream.value
    if stream == "uncompressed":
        return fmt.container.value
    return f"{fmt.container.value}.{stream}"


def _ratio(out: int, compressed: int | None) -> float | None:
    return round(out / compressed, 1) if compressed else None


def scan_one(
    path: Path, config: ArchiveyConfig, password: PasswordInput = None
) -> _Row | None:
    """Scan one file; ``None`` when it is not an archive.

    Every exit that returns a row goes through ``_finish``, so the flags the scan
    found reach the CSV whichever stage stopped it.
    """
    row = _Row(path=str(path), file_size=path.stat().st_size)
    WARNINGS.reset()
    try:
        info = archivey.detect_format(path, config=config)
    except FormatDetectionError:
        return None
    except Exception as exc:  # noqa: BLE001 - every failure becomes a row
        row.failure("detect", exc)
        return _finish(row)
    row.text["format"] = _format_name(info.format)
    row.text["detected"] = f"{info.detected_by}/{info.confidence.value}"
    if info.payload_offset:
        row.flag("sfx")
    if info.detected_by == "extension":
        row.flag("extension_only")

    started = time.perf_counter()
    try:
        _open_and_extract(path, config, row, password, info.diagnostics.counts)
    except Exception as exc:  # noqa: BLE001 - e.g. the reader's close() raising
        row.failure("scan", exc)
    seconds = time.perf_counter() - started
    row.numbers["seconds"] = round(seconds, 2)
    if seconds > _SLOW_SECONDS:
        row.flag("slow")
    return _finish(row)


def _finish(row: _Row) -> _Row:
    """Derive the flags from everything recorded."""
    for message in WARNINGS.messages:
        row.log.append(f"warning: {message}")
        if message.startswith("Could not remove dry-run scratch directory"):
            row.flag("scratch_left_behind")
    _flag_limits(row)
    for code in sorted(row.diagnostics):
        if code not in _ROUTINE_DIAGNOSTICS:
            row.flag(f"diag:{code}")
    return row


def _open_and_extract(
    path: Path,
    config: ArchiveyConfig,
    row: _Row,
    password: PasswordInput,
    detection_diagnostics: Mapping[DiagnosticCode, int],
) -> None:
    try:
        reader = archivey.open_archive(path, config=config, password=password)
    except Exception as exc:  # noqa: BLE001
        row.failure("open", exc)
        # An open reader repeats detection's diagnostics in its own; without one,
        # they are only on the detection result, and a misdetection that made the
        # open fail is exactly where they matter.
        for code, count in detection_diagnostics.items():
            row.diagnostics[code.value] += count
        return
    with reader:
        try:
            _scan_open_reader(reader, config, row)
        finally:
            # Read even when the scan raised: a failing archive is a row the record
            # is for, and the reader's declarations so far are still in it.
            _read_usage(reader, row)


def _scan_open_reader(
    reader: archivey.ArchiveReader, config: ArchiveyConfig, row: _Row
) -> None:
    """Fill ``row`` from an open reader: its info, a dry-run extraction, the listing."""
    row.text["open"] = "ok"
    ai = reader.info
    row.text["format"] = _format_name(ai.format)
    row.text["version"] = ai.format_version or ""
    row.text["solid"] = "yes" if ai.is_solid else ""
    row.text["encrypted"] = "yes" if ai.is_encrypted else ""

    member_bytes: dict[int, int] = {}  # id(member) -> bytes written
    total = [0]

    def on_progress(p: archivey.ExtractionProgress) -> None:
        member_bytes[id(p.member)] = p.member_bytes_written
        total[0] = p.bytes_written

    report = None
    try:
        with tempfile.TemporaryDirectory(prefix="archivey-scan-") as tmp:
            report = reader.extract_all(
                Path(tmp) / "out",
                dry_run=True,
                on_error="continue",
                on_progress=on_progress,
            )
    except Exception as exc:  # noqa: BLE001
        row.failure("extract", exc)
    row.numbers["bytes_written"] = total[0]

    listed = reader.members_report_if_available()
    members = listed.members if listed is not None else ()
    if listed is not None:
        row.numbers["members"] = len(members)
        row.text["codecs"] = " ".join(
            sorted(
                {
                    "+".join(c.algo.value for c in m.compression)
                    for m in members
                    if m.compression
                }
            )
        )
        if any(m.type is MemberType.OTHER for m in members):
            row.flag("device_or_fifo")
    # Once the listing was reached, an archive that listed nothing counts 0.
    usage = _usage(reader)
    if usage is not None:
        row.numbers["metadata_bytes"] = usage.listing_metadata_bytes
    for code, count in reader.diagnostics.counts.items():
        row.diagnostics[code.value] += count

    if report is not None:
        _read_report(report, members, member_bytes, config, row)


class _Usage(NamedTuple):
    decoder_memory: int
    decoder_memory_what: str
    key_derivation_rounds: int
    spool_bytes: int
    listing_metadata_bytes: int


def _usage(reader: archivey.ArchiveReader) -> _Usage | None:
    """The reader's private resource-usage record, or ``None`` when it changed shape.

    The record is internal, so a missing method or a renamed field sets
    ``USAGE_MISSING`` rather than failing the row.
    """
    global USAGE_MISSING
    try:
        usage = reader._resource_usage()
        return _Usage(
            usage.decoder_memory,
            usage.decoder_memory_what,
            usage.key_derivation_rounds,
            usage.spool_bytes,
            usage.listing_metadata_bytes,
        )
    except AttributeError:
        USAGE_MISSING = True
        return None


def _read_usage(reader: archivey.ArchiveReader, row: _Row) -> None:
    """Copy the record's three peaks into the row (``metadata_bytes`` is elsewhere)."""
    usage = _usage(reader)
    if usage is None:
        return
    for column, value in (
        ("decoder_memory", usage.decoder_memory),
        ("kdf_rounds", usage.key_derivation_rounds),
        ("spool_bytes", usage.spool_bytes),
    ):
        if value:
            row.numbers[column] = value
    what = usage.decoder_memory_what
    if what:
        row.log.append(
            f"largest decoder allocation: {usage.decoder_memory} bytes, {what}"
        )


def _read_report(
    report: archivey.ExtractionReport,
    members: tuple[archivey.ArchiveMember, ...],
    member_bytes: dict[int, int],
    config: ArchiveyConfig,
    row: _Row,
) -> None:
    statuses = Counter(r.status for r in report.results)
    failed = [r for r in report.results if r.status is ExtractionStatus.FAILED]
    blocked = [r for r in report.results if r.status is ExtractionStatus.BLOCKED]
    row.text["extract"] = "ok" if not failed and not blocked else "partial"
    if failed:
        row.flag("failed_members")
    if blocked:
        row.flag("blocked_members")
    for r in (failed + blocked)[:_LOGGED_MEMBER_ERRORS]:
        row.log.append(f"{r.status.value} {r.member.name!r}: {r.error}")
        row.text.setdefault("error", f"{type(r.error).__name__}: {r.error}"[:200])
    if any(isinstance(r.error, EncryptionError) for r in failed):
        row.flag("needs_password")
    # ``max_entries`` counts what an extraction leaves on disk, and refunds a
    # superseded entry, so EXTRACTED is the matching count here.
    row.numbers["entries_written"] = statuses[ExtractionStatus.EXTRACTED]
    written = int(row.numbers["bytes_written"])

    # A clean run writes exactly what the members declare; anything else is worth a
    # look. Only checked when every file member declares a size. This relies on the
    # default ``overwrite=ERROR``: a collision is a FAILED result, which makes the run
    # "partial" and skips the check. Under ``overwrite="skip"`` a NOT_OVERWRITTEN
    # member would declare a size and write nothing.
    files = [m for m in members if m.type is MemberType.FILE and m.is_current]
    if row.text["extract"] == "ok" and files and all(m.size is not None for m in files):
        declared = sum(m.size or 0 for m in files)
        if declared != written:
            row.flag("size_mismatch")
            row.log.append(f"members declare {declared} bytes, {written} were written")

    # ``max_ratio`` only looks at output past ``ratio_activation_threshold``, so the
    # ratio columns follow the same rule and compare with the limit.
    floor = config.extraction_limits.ratio_activation_threshold
    archive_ratio = _ratio(written, row.file_size)
    if written > floor and archive_ratio is not None:
        row.numbers["archive_ratio"] = archive_ratio
    best: tuple[float, str] | None = None
    for r in report.results:
        out = member_bytes.get(id(r.member), 0)
        ratio = _ratio(out, r.member.compressed_size)
        if ratio is not None and out > floor and (best is None or ratio > best[0]):
            best = (ratio, r.member.name)
    if best is not None:
        row.numbers["max_member_ratio"] = best[0]
        row.log.append(f"highest member ratio: {best[0]}:1, {best[1]!r}")


def _flag_limits(row: _Row) -> None:
    for column, limit, default in _LIMITS:
        value = row.numbers.get(column)
        if value is None or default is None:
            continue
        if value > default:
            row.flag(f"over:{limit}")
        elif value > default * _NEAR:
            row.flag(f"near:{limit}")


def _list_dir(directory: str) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """The regular files and subdirectories of ``directory``, each sorted, and failures.

    Symlinks are neither followed nor scanned. The failures are ``(path, error)``
    pairs: the directory itself when it cannot be listed, or an entry whose type could
    not be read.
    """
    files: list[str] = []
    dirs: list[str] = []
    failures: list[tuple[str, str]] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir():
                        dirs.append(entry.path)
                    elif entry.is_file():
                        files.append(entry.path)
                except OSError as exc:
                    failures.append((entry.path, str(exc)))
    except OSError as exc:
        failures.append((directory, str(exc)))
    return sorted(files), sorted(dirs), failures


def _walk(
    root: Path, done_dirs: frozenset[str] = frozenset()
) -> Iterator[tuple[str, str, str]]:
    """Walk the tree depth first, listing each directory only when it is reached.

    Yields ``(kind, path, error)``:

    - ``("file", path, "")`` for each regular file;
    - ``("dir", path, "")`` after the last item under a directory, so a directory is
      reported only once its whole subtree has been handed out;
    - ``("skip", path, error)`` for a directory that could not be listed or an entry
      whose type could not be read.

    A directory in ``done_dirs`` is not listed at all.
    """
    if root.is_file():
        yield ("file", str(root), "")
        return
    top = str(root)
    if top in done_dirs:
        return
    # Each entry: a directory, and an iterator over the subdirectories still to visit.
    stack: list[tuple[str, Iterator[str]]] = []

    def enter(directory: str) -> Iterator[tuple[str, str, str]]:
        files, dirs, failures = _list_dir(directory)
        stack.append((directory, iter([d for d in dirs if d not in done_dirs])))
        for path, error in failures:
            yield ("skip", path, error)
        for path in files:
            yield ("file", path, "")

    yield from enter(top)
    while stack:
        directory, subdirs = stack[-1]
        nxt = next(subdirs, None)
        if nxt is None:
            stack.pop()
            yield ("dir", directory, "")
        else:
            yield from enter(nxt)


# A file left unfinished by this many runs, none of them stopped by Ctrl-C, is recorded
# as ``crashed`` instead of being scanned again. The first retry is there because one
# stop may have had another cause, such as the OOM killer picking this process.
_CRASH_ATTEMPTS = 2


def _cut_torn_tail(path: Path, keep: int) -> None:
    """Truncate ``path`` to its first ``keep`` bytes, if it is longer."""
    if path.stat().st_size > keep:
        with path.open("r+b") as fh:
            fh.truncate(keep)


class _Progress:
    """The checkpoint a resumed scan starts from: one JSON object per line.

    The first line holds the scan's root, as typed and resolved, and
    ``--default-limits``. Then each file gets ``{"start": path}`` before it is scanned,
    and one of three entries after: ``{"file": path}`` when it is done,
    ``{"interrupted": path}`` when Ctrl-C stopped its scan, or ``{"skipped": path}``
    when it could not be read. ``{"dir": path}`` follows once a directory's whole
    subtree is done, and ``{"complete": true}`` once the walk has reached its end. JSON
    keeps any path intact, newlines and undecodable bytes included.
    """

    def __init__(
        self, path: Path, root: Path, default_limits: bool, resume: bool
    ) -> None:
        self.path = path
        self.done_dirs: set[str] = set()
        self.done_files: set[str] = set()
        # Runs that stopped while scanning a file, other than by Ctrl-C.
        self.attempts: Counter[str] = Counter()
        # Both spellings: the resolved root tells a different tree under the same
        # name apart, and the typed one is the prefix of every path the checkpoint
        # and the CSV hold, so a resume must spell the root the same way to match.
        header = {
            "root": str(root),
            "resolved_root": str(root.resolve()),
            "default_limits": default_limits,
        }
        if resume:
            if not path.exists():
                raise SystemExit(f"--resume: no progress file {path}")
            self._load(header)
        self._file = path.open("a" if resume else "w", encoding="utf-8")
        if not resume:
            self._write(header)

    @staticmethod
    def unfinished_scan(path: Path) -> bool:
        """Whether ``path`` holds a scan whose last run has not reached its end.

        Only the last entry counts: a resume of a finished scan (to retry what it could
        not read) appends after the earlier ``complete``, and can be interrupted.
        """
        if not path.exists():
            return False
        with path.open("rb") as fh:
            fh.seek(max(0, fh.seek(0, os.SEEK_END) - 4096))
            tail = fh.read().splitlines()
        return not tail or tail[-1] != json.dumps({"complete": True}).encode()

    def _load(self, header: dict[str, object]) -> None:
        # A run killed mid-write leaves a torn last line; the next run would glue its
        # first entry onto it, so the file is cut back to its last complete line.
        data = self.path.read_bytes()
        keep = data.rfind(b"\n") + 1
        lines = data[:keep].decode("utf-8").splitlines()
        if not lines:
            raise SystemExit(
                f"--resume: {self.path} has no header; delete it to start a new scan"
            )
        _cut_torn_tail(self.path, keep)
        for number, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"--resume: {self.path} line {number}: {exc}"
                ) from None
            if number == 1:
                if entry != header:
                    raise SystemExit(
                        f"--resume: {self.path} is a scan with {entry}, "
                        f"not {header}; resume with the same root and options, or "
                        "delete it (or choose another -o) to start a new scan"
                    )
            elif "start" in entry:
                self.attempts[entry["start"]] += 1
            elif "interrupted" in entry:
                self.attempts[entry["interrupted"]] -= 1
            elif "skipped" in entry:
                self.attempts[entry["skipped"]] -= 1
            elif "file" in entry:
                self.done_files.add(entry["file"])
                del self.attempts[entry["file"]]
            elif "dir" in entry:
                self.done_dirs.add(entry["dir"])
        self.attempts = +self.attempts  # drop the paths at zero

    def _write(self, entry: Mapping[str, object]) -> None:
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def start(self, path: str) -> None:
        self._write({"start": path})

    def interrupted(self, path: str) -> None:
        self._write({"interrupted": path})

    def skipped(self, path: str) -> None:
        self._write({"skipped": path})

    def file_done(self, path: str) -> None:
        self._write({"file": path})

    def dir_done(self, path: str) -> None:
        self._write({"dir": path})

    def walk_done(self) -> None:
        self._write({"complete": True})

    def close(self) -> None:
        self._file.close()


def _open_csv(path: Path, mode: str) -> Any:
    # ``surrogateescape``: a file name that is not valid UTF-8 keeps its bytes.
    return path.open(mode, newline="", encoding="utf-8", errors="surrogateescape")


def _count_records(text: str) -> int:
    return sum(1 for _ in csv.reader(io.StringIO(text, newline="")))


def _complete_rows(text: str) -> str:
    """``text`` without its last, torn, record.

    A quoted path can hold a line break, so the record boundary is the last
    ``\\r\\n`` whose prefix parses as one record fewer, not simply the last one.
    """
    records = _count_records(text)
    end = len(text)
    while (end := text.rfind("\r\n", 0, end)) >= 0:
        prefix = text[: end + 2]
        if _count_records(prefix) == records - 1:
            return prefix
    return ""


def _load_rows(csv_path: Path) -> list[_Row]:
    """Read back an earlier run's rows, cutting a torn last row off the file.

    ``csv.writer`` ends every row with ``\\r\\n``. A file that does not end with it
    was cut mid-row: the file is truncated where that row starts, so its archive is
    scanned again rather than counted as done, and the next row does not land on its
    tail. Truncating cannot lose a complete row the way rewriting the file could if it
    were interrupted. A row with the wrong number of fields anywhere else is refused.
    """
    with _open_csv(csv_path, "r") as fh:
        text = fh.read()
    if text and not text.endswith("\r\n"):
        text = _complete_rows(text)
        _cut_torn_tail(csv_path, len(text.encode("utf-8", "surrogateescape")))
    rows = []
    for record in csv.DictReader(io.StringIO(text, newline="")):
        if None in record or None in record.values():
            raise SystemExit(
                f"--resume: {csv_path} has a damaged row for {record.get('path')!r}; "
                "fix or remove it, then resume"
            )
        rows.append(_Row.from_csv(record))
    return rows


def _passwords(args: argparse.Namespace) -> list[str]:
    passwords = list(args.password)
    if args.password_file is not None:
        lines = args.password_file.read_text(encoding="utf-8").splitlines()
        passwords += [line for line in lines if line]
    return passwords


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", type=Path, help="file or directory to scan")
    parser.add_argument("-o", "--output", type=Path, default=Path("scan.csv"))
    parser.add_argument(
        "--password",
        action="append",
        default=[],
        help=(
            "a password to try on encrypted archives; repeat for several "
            "(visible in process lists: prefer --password-file)"
        ),
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="a file of passwords to try, one per line",
    )
    parser.add_argument(
        "--default-limits",
        action="store_true",
        help="scan under the default limits instead of turning the counting ones off",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "continue an interrupted scan into the same output, skipping what its "
            ".progress file records as done; name the root exactly as the first run did"
        ),
    )
    args = parser.parse_args(argv)
    passwords = _passwords(args) or None

    archivey_logger = logging.getLogger("archivey")
    archivey_logger.addHandler(_WarningCapture(logging.WARNING))
    # The capture keeps every record for the log; stderr is for the progress lines.
    archivey_logger.propagate = False
    config = _scan_config(args.default_limits)
    log_path = args.output.with_suffix(".log")

    progress_path = args.output.with_suffix(".progress")
    if not args.resume and _Progress.unfinished_scan(progress_path):
        raise SystemExit(
            f"{progress_path} holds an unfinished scan: continue it with --resume, "
            "or delete it (or choose another -o) to start over"
        )
    rows: list[_Row] = []
    if args.resume:
        if not args.output.exists():
            raise SystemExit(f"--resume: no CSV {args.output}")
        rows = _load_rows(args.output)
    progress = _Progress(progress_path, args.root, args.default_limits, args.resume)
    # A row reaches the CSV before its file is marked done, so a run stopped between
    # the two must not write the row twice.
    done_files = progress.done_files | {row.path for row in rows}
    crashed = {
        path: n
        for path, n in progress.attempts.items()
        if path not in done_files and n >= _CRASH_ATTEMPTS
    }
    for path, n in progress.attempts.items():
        if path not in done_files and n < _CRASH_ATTEMPTS:
            print(
                f"the previous run stopped while scanning {path}; scanning it again, "
                "and recording it as crashed if that run stops there too",
                file=sys.stderr,
            )
    mode = "a" if args.resume else "w"
    # What this run could not read. A directory with any of it underneath is not
    # marked done, so a resumed scan lists it again and retries.
    skipped: list[str] = []
    with (
        _open_csv(args.output, mode) as csv_file,
        log_path.open(mode, encoding="utf-8", errors="surrogateescape") as log,
        contextlib.closing(progress),
    ):
        writer = csv.DictWriter(csv_file, fieldnames=COLUMNS)
        if not args.resume or csv_file.tell() == 0:
            writer.writeheader()
        if args.resume:
            log.write(f"== resumed with {len(rows)} archives already scanned\n\n")

        def record(row: _Row) -> None:
            rows.append(row)
            writer.writerow(row.csv_row())
            csv_file.flush()
            if row.flags:
                log.write(f"== {row.path}\nflags: {' '.join(row.flags)}\n")
                log.writelines(f"  {line}\n" for line in row.log)
                log.write("\n")
                log.flush()
            status = " ".join(row.flags) or "ok"
            print(f"{len(rows):>6} {status:<40.40} {row.path}", file=sys.stderr)

        def skip(path: str, error: str) -> None:
            skipped.append(path)
            log.write(f"== {path}\nnot read: {error}\n\n")
            log.flush()
            print(f"skipped {path}: {error}", file=sys.stderr)

        for path, n in crashed.items():
            row = _Row(path=path, text={"open": "crashed"}, flags=["crashed"])
            row.text["error"] = f"the scan process died while scanning it, {n} times"
            row.log.append(row.text["error"])
            with contextlib.suppress(OSError):
                row.file_size = Path(path).stat().st_size
            record(row)
            progress.file_done(path)
            done_files.add(path)

        current: str | None = None
        try:
            for kind, name, error in _walk(args.root, frozenset(progress.done_dirs)):
                if kind == "dir":
                    prefix = os.path.join(name, "")
                    if not any(
                        path == name or path.startswith(prefix) for path in skipped
                    ):
                        progress.dir_done(name)
                    continue
                if kind == "skip":
                    skip(name, error)
                    continue
                if name in done_files:
                    continue
                current = name
                progress.start(name)
                try:
                    row = scan_one(Path(name), config, passwords)
                except OSError as exc:
                    skip(name, str(exc))
                    progress.skipped(name)
                else:
                    if row is not None:
                        record(row)
                    progress.file_done(name)
                current = None
            progress.walk_done()
        except KeyboardInterrupt:
            if current is not None:
                progress.interrupted(current)
            print(
                f"\ninterrupted; summarizing what was scanned "
                f"(--resume continues from {progress_path})",
                file=sys.stderr,
            )
        summary = _summary(rows)
        if skipped:
            summary += f"not read: {len(skipped)} files or directories (see above)\n"
        if USAGE_MISSING:
            summary += "warning: resource usage not recorded (internals changed)\n"
        log.write(summary)
    print(f"\n{summary}\nwrote {args.output} and {log_path}", file=sys.stderr)
    return 0


def _counts(title: str, counter: Counter[str]) -> list[str]:
    lines = [f"{title}:"]
    lines += [f"  {n:>7}  {key}" for key, n in counter.most_common()]
    return lines


def _percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))]


def _summary(rows: list[_Row]) -> str:
    lines = [f"== summary: {len(rows)} archives"]
    lines += _counts("formats", Counter(r.text.get("format", "?") for r in rows))
    lines += _counts("open", Counter(r.text.get("open", "?") for r in rows))
    lines += _counts("extract", Counter(r.text.get("extract", "-") for r in rows))
    lines += _counts("flags (archives)", Counter(f for r in rows for f in r.flags))
    lines += _counts(
        "diagnostics (archives)", Counter(c for r in rows for c in r.diagnostics)
    )
    # ``near`` here is the ``near:`` flag's definition: past half, not over.
    lines.append(
        f"{'limit':<26}{'default':>14}{'max':>14}{'p99':>14}{'p50':>12}"
        f"{'near':>7}{'over':>6}"
    )
    for column, _limit, default in _LIMITS:
        seen = [r.numbers[column] for r in rows if column in r.numbers]
        if not seen:
            lines.append(f"{column:<26}{default!s:>14}  no values")
            continue
        over = near = 0
        if default is not None:
            over = sum(1 for s in seen if s > default)
            near = sum(1 for s in seen if default * _NEAR < s <= default)
        lines.append(
            f"{column:<26}{default!s:>14}{max(seen):>14.0f}"
            f"{_percentile(seen, 0.99):>14.0f}{_percentile(seen, 0.5):>12.0f}"
            f"{near:>7}{over:>6}"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
