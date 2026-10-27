"""Capability declaration vs observed behaviour, against the declarative corpus.

Evidence for ``dev-docs/investigations/capability-declaration-vs-behaviour.md``.
The predicates live here so a later run does not depend on a snapshot of the
library's docstrings. This script observes; it does not change the library.

Re-run from the repo root::

    uv run --no-sync python scripts/exploration/capability_declaration_sweep.py
    uv run --no-sync python scripts/exploration/capability_declaration_sweep.py \\
        --compare
    uv run --no-sync python scripts/exploration/capability_declaration_sweep.py \\
        --write-snapshot

``--compare`` diffs **verdicts** against the committed JSON snapshot (numeric
drift in seek counts is printed, not a failure). ``--write-snapshot`` refreshes
that JSON after you have updated the markdown.

Skip reasons from ``skip_unless_runnable`` are recorded as ``UNTESTED``, never
as ``OK``. Registry formats with no corpus key are ``UNTESTED-NO-CORPUS``.

This script does **not** xfail anything. Measurement holes stay holes.
``test_member_stream_contract.py`` already pins zip-aes SEEKABLE with
``xfail(strict=True)``. Required RAR/zip-aes rows (see ``REQUIRED_RAN``)
must run or the process exits non-zero — dropping them re-acquires the
stored-only RAR blind spot.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, BinaryIO, TextIO

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import pytest  # noqa: E402

from archivey import (  # noqa: E402
    ArchiveyUsageError,
    StreamNotSeekableError,
    format_availability,
    list_supported_formats,
    open_archive,
)
from archivey.config import PasswordInput  # noqa: E402
from archivey.cost import AccessCost, ListingCost, StreamCapability  # noqa: E402
from archivey.internal.measurement import enable_measurement  # noqa: E402
from archivey.types import (  # noqa: E402
    ArchiveFormat,
    CompressionAlgorithm,
    MemberStreams,
)
from tests.sample_archives import (  # noqa: E402
    CORPUS,
    FORMAT_KEYS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)

SNAPSHOT = (
    _REPO / "dev-docs" / "investigations" / "capability-declaration-vs-behaviour.json"
)
SCHEMA = 1
PRIMARY_ENTRY_IDS = ("basic", "single-file", "single-file-meta")
ALWAYS_ENTRY_IDS = (
    "encrypted",
    "encrypted-mixed",
    "encrypted-header",
    "encrypted-multi",
    "large",
    "compressed",
    "sevenzip-stored",
)

# Must actually run, not merely be listed. The 2026-09-05 sweep called RAR
# SEEKABLE OK on basic/large because those fixtures are STORED and never
# reach unrar; encrypted (and later packed ``compressed``) are the rows that
# do. zip-aes is the remaining SEEKABLE lie. A skip here is a broken run,
# not UNTESTED-as-pass.
REQUIRED_RAN: tuple[tuple[str, str, str], ...] = (
    ("encrypted", "rar", "unrar data path (encryption)"),
    ("encrypted-mixed", "rar", "stored+encrypted members in one archive"),
    ("compressed", "rar", "packed RAR, not the stored-slice path"),
    ("encrypted", "zip-aes", "WinZip AES decrypt wrapper"),
    ("encrypted-mixed", "zip-aes", "AES vs plaintext disagreement"),
)

OK = "OK"
DND = "DECLARED-NOT-DELIVERED"
DNDC = "DELIVERED-NOT-DECLARED"
HOLE = "MEASUREMENT-HOLE"
UNTESTED = "UNTESTED"
UNTESTED_NO_CORPUS = "UNTESTED-NO-CORPUS"
ERROR = "ERROR"
FAILURE_VERDICTS = frozenset({DND, DNDC, ERROR})


class NonSeekable(io.RawIOBase):
    """Forward-only view over bytes — a pipe/socket without a real pipe."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        return self._inner.read(n)

    def readinto(self, b: Any) -> int:
        return self._inner.readinto(b)

    def seekable(self) -> bool:
        return False


@dataclass
class Check:
    name: str
    verdict: str
    declared: str
    observed: str
    detail: str = ""

    def to_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Row:
    entry: str
    key: str
    skipped: str | None = None
    checks: list[Check] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "key": self.key,
            "skipped": self.skipped,
            "checks": [c.to_json() for c in self.checks],
        }


def _git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=_REPO,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _bin_version(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        return "missing"
    # zip with no args dumps binary; the others print a banner on stdin-empty.
    argv = [path, "-h"] if name == "zip" else [path]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=8, check=False)
    except OSError as exc:
        return f"{path} ({exc})"
    text = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    for ln in text.splitlines():
        stripped = "".join(ch for ch in ln.strip() if ch.isprintable())
        if not stripped:
            continue
        if stripped.startswith(("ERROR", "Command Line")):
            continue
        if any(ch.isdigit() for ch in stripped):
            return f"{path} {stripped[:80]}"
    return path


def _password(entry: CorpusEntry) -> PasswordInput:
    pws = list(entry.passwords)
    return pws or None


def _skip_reason(entry: CorpusEntry, key: str) -> str | None:
    try:
        skip_unless_runnable(entry, key)
    except pytest.skip.Exception as exc:
        return str(exc) or "skipped"
    return None


def _selected_rows() -> list[tuple[CorpusEntry, str]]:
    """One primary row per FORMAT_KEYS key, plus encrypted / large / packing extras.

    New corpus ids in ALWAYS_ENTRY_IDS and new FORMAT_KEYS keys are picked up
    without editing this list. That is the point: the enrolment is the corpus.
    """
    by_id = {e.id: e for e in CORPUS}
    seen: set[tuple[str, str]] = set()
    rows: list[tuple[CorpusEntry, str]] = []

    def add(entry: CorpusEntry, key: str) -> None:
        ident = (entry.id, key)
        if ident in seen or key not in entry.formats:
            return
        seen.add(ident)
        rows.append((entry, key))

    for key in FORMAT_KEYS:
        for pref in PRIMARY_ENTRY_IDS:
            entry = by_id.get(pref)
            if entry is not None and key in entry.formats:
                add(entry, key)
                break
        else:
            for entry in CORPUS:
                if key in entry.formats:
                    add(entry, key)
                    break

    for extra_id in ALWAYS_ENTRY_IDS:
        extra = by_id.get(extra_id)
        if extra is None:
            continue
        for key in extra.formats:
            add(extra, key)
    return rows


def _file_members(reader: Any) -> list[Any]:
    return [m for m in reader.members() if m.is_file]


def _algos(member: Any) -> str:
    chain = getattr(member, "compression", None) or ()
    return "+".join(c.algo.value for c in chain) or "(none)"


def _is_only_stored(member: Any) -> bool:
    chain = getattr(member, "compression", None) or ()
    return bool(chain) and all(c.algo is CompressionAlgorithm.STORED for c in chain)


def _declared(reader: Any) -> MemberStreams:
    # The declared flags have no public attribute (the ``reader.member_streams``
    # property was removed at the 0.2.0 freeze); an exploration script that compares
    # declaration with behaviour reads the reader's own field.
    return reader._member_streams


def _flag_label(value: MemberStreams) -> str:
    if value == MemberStreams(0):
        return "DEFAULT"
    names = []
    if MemberStreams.SEEKABLE in value:
        names.append("SEEKABLE")
    if MemberStreams.CONCURRENT in value:
        names.append("CONCURRENT")
    return "+".join(names)


def _check_seekable_opt_in(reader: Any) -> Check:
    declared = _flag_label(_declared(reader))
    files = _file_members(reader)
    if not files:
        return Check("seekable_opt_in", UNTESTED, declared, "no FILE members")
    per: list[str] = []
    failed: list[str] = []
    for member in files:
        stream = reader.open(member)
        try:
            seekable = stream.seekable()
            data = stream.read()
            if not seekable:
                failed.append(f"{member.name!r} seekable=False codec={_algos(member)}")
                per.append(f"{member.name}=False")
                continue
            try:
                stream.seek(0)
                again = stream.read()
            except (OSError, ValueError) as exc:
                failed.append(f"{member.name!r} seek raised {type(exc).__name__}")
                per.append(f"{member.name}=raise")
                continue
            if again != data:
                failed.append(f"{member.name!r} seek(0) reread mismatch")
                per.append(f"{member.name}=mismatch")
                continue
            if data:
                mid = min(10, len(data) - 1)
                stream.seek(mid)
                tail = stream.read()
                if tail != data[mid:]:
                    failed.append(f"{member.name!r} mid-seek mismatch")
                    per.append(f"{member.name}=mid-mismatch")
                    continue
            per.append(f"{member.name}=True")
        finally:
            stream.close()
    observed = ", ".join(per)
    if failed:
        return Check("seekable_opt_in", DND, declared, observed, "; ".join(failed))
    return Check("seekable_opt_in", OK, declared, observed)


def _check_seekable_default(reader: Any) -> Check:
    declared = _flag_label(_declared(reader))
    files = _file_members(reader)
    if not files:
        return Check("seekable_default", UNTESTED, declared, "no FILE members")
    seekable_true: list[str] = []
    seek_worked: list[str] = []
    for member in files:
        stream = reader.open(member)
        try:
            if stream.seekable():
                seekable_true.append(member.name)
            try:
                stream.seek(0)
                seek_worked.append(member.name)
            except (OSError, ValueError):
                pass
        finally:
            stream.close()
    if seekable_true or seek_worked:
        return Check(
            "seekable_default",
            DNDC,
            declared,
            f"seekable={seekable_true or None} seek_worked={seek_worked or None}",
        )
    return Check("seekable_default", OK, declared, "seekable=False, seek raises")


def _check_concurrent(reader: Any, *, expected: bool) -> Check:
    name = "concurrent_opt_in" if expected else "concurrent_default"
    declared = _flag_label(_declared(reader))
    files = _file_members(reader)
    if not files:
        return Check(name, UNTESTED, declared, "no FILE members")
    first = files[0]
    second = files[1] if len(files) > 1 else files[0]
    s1 = reader.open(first)
    try:
        try:
            s2 = reader.open(second)
        except ArchiveyUsageError:
            if expected:
                return Check(
                    name,
                    DND,
                    declared,
                    "second open raised ArchiveyUsageError",
                )
            return Check(name, OK, declared, "second open ArchiveyUsageError")
        try:
            a = s1.read()
            b = s2.read()
        finally:
            s2.close()
    finally:
        s1.close()
    if not expected:
        return Check(
            name,
            DNDC,
            declared,
            f"overlapping open worked ({first.name!r}, {second.name!r})",
        )
    if not a and first.size not in (0, None):
        return Check(name, DND, declared, f"{first.name!r} read empty")
    if not b and second.size not in (0, None):
        return Check(name, DND, declared, f"{second.name!r} read empty")
    return Check(
        name,
        OK,
        declared,
        f"overlapping open of {first.name!r} and {second.name!r}",
    )


def _check_listing(reader: Any) -> Check:
    cost = reader.cost
    stats = reader.io_stats()
    n = len(list(reader.members()))
    seeks = stats.source_seek_count if stats is not None else None
    decomp = stats.bytes_decompressed if stats is not None else None
    consumed = stats.compressed_bytes_consumed if stats is not None else None
    declared = cost.listing_cost.value
    observed = f"n={n} seeks={seeks} decomp={decomp} consumed={consumed}"
    if stats is None:
        return Check("listing_cost", HOLE, declared, "io_stats is None")
    if cost.listing_cost is ListingCost.INDEXED and seeks == 0:
        return Check(
            "listing_cost",
            HOLE,
            declared,
            observed,
            "INDEXED but source_seek_count=0; cannot falsify a header walk",
        )
    if cost.listing_cost is ListingCost.REQUIRES_SCANNING and seeks == 0:
        return Check(
            "listing_cost",
            HOLE,
            declared,
            observed,
            "REQUIRES_SCANNING with no visible seeks (Path / os.walk)",
        )
    if (
        cost.listing_cost is ListingCost.REQUIRES_DECOMPRESSION
        and decomp == 0
        and consumed in (0, None)
    ):
        return Check(
            "listing_cost",
            HOLE,
            declared,
            observed,
            "REQUIRES_DECOMPRESSION but listing shows no decode / consume",
        )
    return Check("listing_cost", OK, declared, observed)


def _check_access(reader: Any) -> Check:
    cost = reader.cost
    files = _file_members(reader)
    declared = cost.access_cost.value
    if not files:
        return Check("access_cost", UNTESTED, declared, "no FILE members")
    nonempty = [m for m in files if (m.size or 0) > 0]
    last = nonempty[-1] if nonempty else files[-1]
    before = reader.io_stats()
    before_decomp = before.bytes_decompressed if before is not None else None
    stream = reader.open(last)
    try:
        data = stream.read()
    finally:
        stream.close()
    after = reader.io_stats()
    after_decomp = after.bytes_decompressed if after is not None else None
    delta = (
        None
        if before_decomp is None or after_decomp is None
        else after_decomp - before_decomp
    )
    total = sum(m.size or 0 for m in files)
    last_size = last.size or len(data)
    observed = (
        f"delta={delta} last={last_size} total={total} solid={reader.info.is_solid}"
    )
    if delta is None:
        return Check("access_cost", HOLE, declared, observed, "io_stats missing")
    if cost.access_cost is AccessCost.DIRECT:
        # Stored members can count 0; a solid decode of the whole folder is a lie.
        if total > last_size and delta >= total:
            return Check(
                "access_cost",
                DND,
                declared,
                observed,
                "DIRECT but last-member read decompressed the whole payload",
            )
        return Check("access_cost", OK, declared, observed)
    # SOLID: 7z folder decode shows delta==total; compressed tar often only
    # counts the opened member (measurement hole, not a pass).
    if len(files) == 1:
        return Check(
            "access_cost", OK, declared, observed, "N=1, cannot see prefix cost"
        )
    if delta <= last_size:
        return Check(
            "access_cost",
            HOLE,
            declared,
            observed,
            "SOLID but last-member Δdecomp ≈ last size (wrap counts the opened member)",
        )
    return Check("access_cost", OK, declared, observed)


def _check_member_count(reader: Any) -> Check:
    listed = len(list(reader.members()))
    count = reader.info.member_count
    declared = "None" if count is None else str(count)
    observed = f"declared={declared} listed={listed}"
    if count is None:
        return Check(
            "member_count",
            OK,
            declared,
            observed,
            "None is allowed when a count would require a scan",
        )
    if count != listed:
        return Check("member_count", DND, declared, observed)
    return Check("member_count", OK, declared, observed)


def _check_is_encrypted(reader: Any, entry: CorpusEntry) -> Check:
    archive_enc = reader.info.is_encrypted
    member_enc = [m.name for m in reader.members() if m.is_encrypted]
    declared = "header-level only (ArchiveInfo docstring)"
    observed = f"archive={archive_enc} members={member_enc}"
    header = entry.encrypt_header
    if header:
        if archive_enc:
            return Check("is_encrypted", OK, declared, observed, "header-encrypted")
        return Check(
            "is_encrypted",
            DND,
            declared,
            observed,
            "encrypt_header corpus row but archive is_encrypted is False",
        )
    if member_enc and archive_enc:
        return Check(
            "is_encrypted",
            DND,
            declared,
            observed,
            "per-member/folder encryption reported as archive is_encrypted",
        )
    return Check("is_encrypted", OK, declared, observed)


def _check_is_solid(reader: Any) -> Check:
    info_solid = reader.info.is_solid
    access_solid = reader.cost.access_cost is AccessCost.SOLID
    declared = f"is_solid={info_solid}"
    observed = f"access_cost={reader.cost.access_cost.value}"
    if info_solid != access_solid:
        return Check(
            "is_solid",
            DND,
            declared,
            observed,
            "ArchiveInfo.is_solid disagrees with CostReceipt.access_cost",
        )
    return Check("is_solid", OK, declared, observed)


def _check_is_multivolume(reader: Any) -> Check:
    value = reader.info.is_multivolume
    if value:
        return Check(
            "is_multivolume",
            DND,
            "False (corpus has no multi-volume row)",
            "True",
        )
    return Check("is_multivolume", OK, "False", "False")


def _check_source_path(reader: Any) -> Check:
    cap = reader.cost.stream_capability
    declared = cap.value
    if cap is StreamCapability.SEEKABLE:
        return Check("source_path", OK, declared, declared)
    return Check(
        "source_path",
        DND,
        "seekable (Path open)",
        declared,
    )


def _check_source_pipe(path: Path, entry: CorpusEntry) -> Check:
    if path.is_dir():
        return Check("source_pipe", UNTESTED, "n/a", "directory")
    data = path.read_bytes()
    try:
        with open_archive(
            NonSeekable(data),
            streaming=True,
            password=_password(entry),
        ) as reader:
            cap = reader.cost.stream_capability
            # members() is random-access; a streaming reader wants stream_members().
            n = 0
            for _member, stream in reader.stream_members():
                n += 1
                if stream is not None:
                    stream.close()
            verdict = OK if cap is StreamCapability.FORWARD_ONLY else DNDC
            return Check(
                "source_pipe",
                verdict,
                "forward_only (or refuse)",
                f"{cap.value} members={n}",
            )
    except StreamNotSeekableError:
        return Check(
            "source_pipe",
            OK,
            "forward_only (or refuse)",
            "raise StreamNotSeekableError",
            "no CostReceipt; format refuses a pipe even with streaming=True",
        )
    except ArchiveyUsageError as exc:
        return Check(
            "source_pipe",
            ERROR,
            "forward_only (or refuse)",
            f"ArchiveyUsageError: {exc}"[:200],
        )
    except Exception as exc:  # noqa: BLE001 - per-cell observation
        return Check(
            "source_pipe",
            ERROR,
            "forward_only (or refuse)",
            f"{type(exc).__name__}: {exc}"[:200],
        )


def _check_lifetime(path: Path, entry: CorpusEntry, *, seekable_members: bool) -> Check:
    name = "lifetime_seekable" if seekable_members else "lifetime_default"
    leftover: BinaryIO | None = None
    with open_archive(
        path,
        password=_password(entry),
        seekable_members=seekable_members,
    ) as reader:
        files = _file_members(reader)
        if not files:
            return Check(name, UNTESTED, "closed on reader.close", "no FILE members")
        leftover = reader.open(files[0])
    assert leftover is not None
    try:
        leftover.read(1)
    except (ValueError, OSError) as exc:
        return Check(
            name,
            OK,
            "closed on reader.close",
            f"{type(exc).__name__}: {exc}"[:80],
        )
    leftover.close()
    return Check(
        name,
        DND,
        "closed on reader.close",
        "read after archive close did not raise",
    )


def _check_lifetime_stream_members(path: Path, entry: CorpusEntry) -> Check:
    leftover: BinaryIO | None = None
    with open_archive(path, password=_password(entry)) as reader:
        for member, stream in reader.stream_members():
            if member.is_file and stream is not None:
                leftover = stream
                break
        else:
            return Check(
                "lifetime_stream_members",
                UNTESTED,
                "closed on reader.close",
                "no FILE stream from stream_members()",
            )
    assert leftover is not None
    try:
        leftover.read(1)
    except (ValueError, OSError) as exc:
        return Check(
            "lifetime_stream_members",
            OK,
            "closed on reader.close",
            f"{type(exc).__name__}: {exc}"[:80],
        )
    leftover.close()
    return Check(
        "lifetime_stream_members",
        DND,
        "closed on reader.close",
        "stream_members handle readable after archive close",
    )


def _check_stream_members_seekable(path: Path, entry: CorpusEntry) -> Check:
    """A stream_members() handle never seeks, even under seekable_members=True.

    The spec (archive-reading) makes every pass handle forward-only on every format:
    ``seekable()`` is False and ``seek()`` raises ``io.UnsupportedOperation``. A pass
    handle that seeks is DELIVERED-NOT-DECLARED.
    """
    with open_archive(path, password=_password(entry), seekable_members=True) as reader:
        flags: list[str] = []
        seeking: list[str] = []
        for member, stream in reader.stream_members():
            if not member.is_file or stream is None:
                continue
            seekable = stream.seekable()
            try:
                stream.seek(0)
                seek_ok = True
            except io.UnsupportedOperation:
                seek_ok = False
            flags.append(f"{member.name}={seekable}")
            if seekable or seek_ok:
                seeking.append(f"{member.name!r} seekable={seekable} seek_ok={seek_ok}")
        declared = "forward-only (never seeks)"
        if not flags:
            return Check(
                "stream_members_seekable", UNTESTED, declared, "no FILE stream"
            )
        observed = ", ".join(flags)
        if seeking:
            return Check(
                "stream_members_seekable", DNDC, declared, observed, "; ".join(seeking)
            )
        return Check("stream_members_seekable", OK, declared, observed)


def _check_mechanism(reader: Any, entry: CorpusEntry, key: str) -> Check | None:
    """Guard the paths that a stored-only / unencrypted matrix would miss."""
    files = _file_members(reader)
    stored = [m.name for m in files if _is_only_stored(m)]
    packed = [m.name for m in files if not _is_only_stored(m)]
    encrypted = [m.name for m in files if m.is_encrypted]
    if key == "rar" and entry.id == "compressed":
        if not packed:
            return Check(
                "mechanism",
                ERROR,
                "packed RAR (unrar data path)",
                f"all STORED {stored}",
                "compressed row took the stored-slice path",
            )
        return Check(
            "mechanism",
            OK,
            "packed RAR (unrar data path)",
            f"packed={packed}",
        )
    if key == "rar" and entry.id.startswith("encrypted"):
        if not encrypted:
            return Check(
                "mechanism",
                ERROR,
                "encrypted RAR (unrar data path)",
                "no encrypted FILE",
            )
        return Check(
            "mechanism",
            OK,
            "encrypted RAR (unrar data path)",
            f"encrypted={encrypted} stored={stored}",
        )
    if key == "zip-aes" and entry.id.startswith("encrypted"):
        if not encrypted:
            return Check(
                "mechanism",
                ERROR,
                "WinZip AES members",
                "no encrypted FILE",
            )
        return Check(
            "mechanism",
            OK,
            "WinZip AES members",
            f"encrypted={encrypted}",
        )
    return None


def _coverage_problems(payload: dict[str, Any]) -> list[str]:
    by = {(row["entry"], row["key"]): row for row in payload["rows"]}
    problems: list[str] = []
    for entry, key, why in REQUIRED_RAN:
        row = by.get((entry, key))
        if row is None:
            problems.append(f"missing {entry}/{key} ({why})")
            continue
        if row.get("skipped"):
            problems.append(f"skipped {entry}/{key}: {row['skipped']} ({why})")
            continue
        mech = next(
            (c for c in row.get("checks") or [] if c["name"] == "mechanism"),
            None,
        )
        if mech is not None and mech["verdict"] == ERROR:
            problems.append(
                f"{entry}/{key} mechanism: {mech.get('observed', '')} ({why})"
            )
    return problems


def _measure_row(entry: CorpusEntry, key: str, tmp: Path) -> Row:
    reason = _skip_reason(entry, key)
    if reason is not None:
        return Row(entry.id, key, skipped=reason)
    path = corpus_archive_path(entry, key, tmp / f"{entry.id}-{key}")
    row = Row(entry.id, key)
    pw = _password(entry)
    try:
        # Listing/info/access on a fresh open so payload seeks from the
        # seekability probes do not leak into io_stats.
        with enable_measurement(), open_archive(path, password=pw) as reader:
            list(reader.members())
            row.checks.append(_check_listing(reader))
            row.checks.append(_check_member_count(reader))
            row.checks.append(_check_is_encrypted(reader, entry))
            row.checks.append(_check_is_solid(reader))
            row.checks.append(_check_is_multivolume(reader))
            row.checks.append(_check_source_path(reader))
            row.checks.append(_check_access(reader))
            mech = _check_mechanism(reader, entry, key)
            if mech is not None:
                row.checks.append(mech)
        with open_archive(path, password=pw, seekable_members=True) as reader:
            row.checks.append(_check_seekable_opt_in(reader))
        with open_archive(path, password=pw) as reader:
            row.checks.append(_check_seekable_default(reader))
            row.checks.append(_check_concurrent(reader, expected=False))
        with open_archive(path, password=pw, concurrent_operations=True) as reader:
            row.checks.append(_check_concurrent(reader, expected=True))
        row.checks.append(_check_source_pipe(path, entry))
        row.checks.append(_check_lifetime(path, entry, seekable_members=False))
        row.checks.append(_check_lifetime(path, entry, seekable_members=True))
        row.checks.append(_check_lifetime_stream_members(path, entry))
        row.checks.append(_check_stream_members_seekable(path, entry))
    except Exception as exc:  # noqa: BLE001 - per-row observation
        row.checks.append(
            Check(
                "open",
                ERROR,
                "open_archive",
                f"{type(exc).__name__}: {exc}"[:300],
            )
        )
    return row


def _registry_gaps() -> list[dict[str, str]]:
    corpus_formats = {FORMAT_KEYS[k] for k in FORMAT_KEYS}
    gaps = []
    for fmt in list_supported_formats():
        if fmt in corpus_formats or fmt == ArchiveFormat.UNKNOWN:
            continue
        avail = format_availability(fmt)
        gaps.append(
            {
                "format": str(fmt),
                "ext": fmt.file_extension(),
                "support": avail.support.name,
                "verdict": UNTESTED_NO_CORPUS,
            }
        )
    return gaps


def _machine() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "git": _git_head(),
        "date": date.today().isoformat(),
        "rar": _bin_version("rar"),
        "unrar": _bin_version("unrar"),
        "7z": _bin_version("7z"),
        "zip": _bin_version("zip"),
    }


def run_sweep() -> dict[str, Any]:
    rows: list[Row] = []
    with tempfile.TemporaryDirectory(prefix="capability-sweep-") as raw:
        tmp = Path(raw)
        for entry, key in _selected_rows():
            rows.append(_measure_row(entry, key, tmp))
    return {
        "schema": SCHEMA,
        "machine": _machine(),
        "registry_not_in_corpus": _registry_gaps(),
        "rows": [r.to_json() for r in rows],
    }


def _index(payload: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, str]]:
    out: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in payload["rows"]:
        if row.get("skipped"):
            out[(row["entry"], row["key"], "skip")] = {
                "verdict": UNTESTED,
                "observed": row["skipped"],
            }
            continue
        for check in row["checks"]:
            out[(row["entry"], row["key"], check["name"])] = check
    return out


def compare(current: dict[str, Any], previous: dict[str, Any], out: TextIO) -> int:
    """Return 1 if a verdict moved, else 0. Numeric-only drift is printed."""
    cur = _index(current)
    prev = _index(previous)
    keys = sorted(set(cur) | set(prev))
    verdict_changes = 0
    for key in keys:
        a = prev.get(key)
        b = cur.get(key)
        label = "/".join(key)
        if a is None:
            out.write(f"ADDED    {label}  {b['verdict']}\n")
            if b["verdict"] in FAILURE_VERDICTS:
                verdict_changes += 1
            continue
        if b is None:
            out.write(f"REMOVED  {label}  was {a['verdict']}\n")
            verdict_changes += 1
            continue
        if a["verdict"] != b["verdict"]:
            out.write(
                f"VERDICT  {label}  {a['verdict']} -> {b['verdict']}"
                f"  observed={b.get('observed', '')}\n"
            )
            verdict_changes += 1
            continue
        if a.get("observed") != b.get("observed"):
            out.write(
                f"NUMERIC  {label}  {a.get('observed', '')!r} -> {b.get('observed', '')!r}\n"
            )
    if verdict_changes == 0:
        out.write("No verdict changes against the snapshot.\n")
    else:
        out.write(f"{verdict_changes} verdict change(s).\n")
    return 1 if verdict_changes else 0


def _print_tables(payload: dict[str, Any], out: TextIO) -> None:
    machine = payload["machine"]
    out.write(f"git {machine['git']}  python {machine['python']}  {machine['date']}\n")
    out.writelines(
        f"UNTESTED-NO-CORPUS  {gap['format']}  ext={gap['ext']}"
        f"  support={gap['support']}\n"
        for gap in payload["registry_not_in_corpus"]
    )
    out.write("\n")
    header = f"{'entry':<20} {'key':<12} {'check':<26} {'verdict':<24} observed\n"
    out.write(header)
    out.write("-" * 120 + "\n")
    failures: list[str] = []
    skips = 0
    for row in payload["rows"]:
        if row.get("skipped"):
            skips += 1
            out.write(
                f"{row['entry']:<20} {row['key']:<12} {'skip':<26} {UNTESTED:<24} "
                f"{row['skipped']}\n"
            )
            continue
        for check in row["checks"]:
            line = (
                f"{row['entry']:<20} {row['key']:<12} {check['name']:<26} "
                f"{check['verdict']:<24} {check['observed']}"
            )
            out.write(line + "\n")
            if check["verdict"] in FAILURE_VERDICTS or check["verdict"] == HOLE:
                failures.append(line)
    out.write("\n--- holes and failures ---\n")
    if not failures:
        out.write("(none)\n")
    else:
        for line in failures:
            out.write(line + "\n")
    counts: dict[str, int] = {}
    for row in payload["rows"]:
        for check in row.get("checks") or []:
            counts[check["verdict"]] = counts.get(check["verdict"], 0) + 1
        if row.get("skipped"):
            counts[UNTESTED] = counts.get(UNTESTED, 0) + 1
    out.write("\ncounts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    out.write(f"  skipped_rows={skips}  rows={len(payload['rows'])}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        type=Path,
        help="Write the raw observation dump (in addition to stdout tables).",
    )
    parser.add_argument(
        "--compare",
        nargs="?",
        const=str(SNAPSHOT),
        default=None,
        help=f"Diff verdicts against a snapshot (default {SNAPSHOT}).",
    )
    parser.add_argument(
        "--write-snapshot",
        nargs="?",
        const=str(SNAPSHOT),
        default=None,
        help=f"Refresh the committed snapshot (default {SNAPSHOT}).",
    )
    args = parser.parse_args(argv)

    os.chdir(_REPO)
    payload = run_sweep()
    _print_tables(payload, sys.stdout)

    coverage = _coverage_problems(payload)
    if coverage:
        sys.stdout.write("\n--- required rows ---\n")
        for line in coverage:
            sys.stdout.write(line + "\n")

    if args.json is not None:
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}", file=sys.stderr)
    if args.write_snapshot is not None:
        if coverage:
            print(
                "refusing --write-snapshot: required rows did not run",
                file=sys.stderr,
            )
        else:
            path = Path(args.write_snapshot)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            print(f"wrote snapshot {path}", file=sys.stderr)

    compare_rc = 0
    if args.compare is not None:
        prev_path = Path(args.compare)
        if not prev_path.is_file():
            print(f"no snapshot at {prev_path} (nothing to compare)", file=sys.stderr)
            compare_rc = 2
        else:
            previous = json.loads(prev_path.read_text(encoding="utf-8"))
            print(f"\n--- compare {prev_path} ---")
            compare_rc = compare(payload, previous, sys.stdout)
    if coverage:
        return 3
    return compare_rc


if __name__ == "__main__":
    raise SystemExit(main())
