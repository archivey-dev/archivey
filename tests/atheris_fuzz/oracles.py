"""Oracle targets: the same archive read two ways must agree.

The format targets in :mod:`tests.atheris_fuzz.targets` look for one failure: an
exception outside ``ArchiveyError``. These targets also compare two reads of the same
input and fail with ``AssertionError`` when the reads disagree:

- ``diff_modes``: a seekable open, a seekable source that returns 1 to 7 bytes per
  read, a forward reader (``streaming=True``) and a pipe that returns 1 to 7 bytes
  per read list the same members with the same bytes. A member read must return full
  counts (ADR 0014): a short ``read(member.size)`` followed by more bytes is a cut file.
- ``seek_member``: with ``seekable_members=True``, seeks and reads (``SEEK_SET``,
  ``SEEK_CUR``, ``SEEK_END``) return the bytes of a sequential read.
- ``extract_diff``: ``extract_all`` from a seekable reader and from a streaming reader
  leaves the same tree, under a policy the input picks.
- ``tiny_limits``: tiny listing, metadata and decoder limits with
  ``DiagnosticPolicy.PEDANTIC``, so the limit and diagnostic paths raise only typed
  errors.

Reads compare only when both are clean. When one raises and the other does not, that
is a finding too, except where the source decides by design (below).

Found with these targets on 2026-11-08: CAB and ISO zisofs member reads short at each
block (a cut file with no error), a corrupt compressed TAR read as cut on a seekable
source, and a quadratic hard-link extraction (the scaling sweep, not these targets).

Known by-design differences that the targets leave out:

- A ZIP from a pipe yields the members its local headers name, and the central
  directory at the end can drop some of them (with a warning) or retype a symlink
  that a local header cannot mark. A damaged data descriptor fails on a pipe but not
  from a file, where the central directory gives the sizes. So the forward and pipe
  comparisons skip ZIP; the short-read seekable comparison still covers it.
- A codec over a pipe cannot decode the bytes before damage again, so it raises at
  the read that meets the damage. From a seekable source the codec hands those bytes
  back first, and damage past the TAR's end-of-archive marker is only a warning (the
  codec reports a failed check the same way as junk after the stream). So a pipe
  may raise where the forward read on a seekable source is clean; the opposite, and
  two clean reads that differ, still fail.
- RAR runs ``unrar`` for every member, too slow for these targets; ``rar`` covers it.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from archivey import (
    AcceleratorMode,
    ArchiveyConfig,
    ArchiveyError,
    ContainerFormat,
    DecoderLimits,
    ListingLimits,
    detect_format,
    open_archive,
)
from archivey.detection_cost import BALANCED_BUDGET
from archivey.diagnostics import DiagnosticPolicy
from tests.atheris_fuzz.targets import _FUZZ_DECODER_LIMITS, _PASSWORD_CANDIDATES
from tests.streams_util import ShortReadBytesIO, ShortReadNonSeekable

_CONFIG = ArchiveyConfig(
    detection_budget=BALANCED_BUDGET,
    always_probe_content=True,
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
    decoder_limits=_FUZZ_DECODER_LIMITS,
)
_TINY_CONFIG = ArchiveyConfig(
    detection_budget=BALANCED_BUDGET,
    always_probe_content=True,
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
    decoder_limits=DecoderLimits(max_decoder_memory=1 << 20),
    listing_limits=ListingLimits(max_members=5, max_metadata_bytes=2048),
    diagnostic_policy=DiagnosticPolicy.PEDANTIC,
)
# Formats a forward reader and a pipe can read.
_FORWARD = frozenset(
    {
        ContainerFormat.TAR,
        ContainerFormat.RAW_STREAM,
        ContainerFormat.AR,
        ContainerFormat.CPIO,
        ContainerFormat.RPM,
    }
    | {
        getattr(ContainerFormat, name)
        for name in ("DEB", "MAKESELF")
        if hasattr(ContainerFormat, name)
    }
)
_MAX_MEMBERS = 2000
_MEMBER_CAP = 1 << 20
_TOTAL_CAP = 8 << 20
# Reads of 1 to 7 bytes cost a call each: past this size the short-read and pipe
# comparisons would outrun the per-input timeout, so a larger input is compared
# seekable against forward only.
_SHORT_READ_CAP = 32 * 1024
_SEEK_FILES = 4
_SEEKS = 6

Row = tuple[tuple[str, str, str | None], str | None]
Listing = tuple[list[Row] | None, bool, str | None]


def _container(data: bytes) -> ContainerFormat | None:
    try:
        info = detect_format(io.BytesIO(data), config=_CONFIG)
    except ArchiveyError:
        return None
    container = info.format.container
    if container in (
        ContainerFormat.UNKNOWN,
        ContainerFormat.DIRECTORY,
        ContainerFormat.RAR,
    ):
        return None
    return container


def _password(container: ContainerFormat) -> list[str | bytes] | None:
    if container in (ContainerFormat.ZIP, ContainerFormat.SEVEN_Z):
        return _PASSWORD_CANDIDATES
    return None


def _drain(stream: Any, size: int | None, what: str) -> bytes:
    """Read a member; a full-count read that stops short and then goes on fails."""
    out = bytearray()
    if size is not None and 0 < size <= _MEMBER_CAP:
        first = stream.read(size)
        out += first
        if len(first) < size:
            more = stream.read(size - len(first))
            if more:
                raise AssertionError(
                    f"{what}: read({size}) returned {len(first)} bytes, and the next "
                    f"read {len(more)} more (ADR 0014: a short read is the end)"
                )
            return bytes(out)
    while len(out) < _MEMBER_CAP:
        chunk = stream.read(min(1 << 16, _MEMBER_CAP - len(out)))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def _digest(data: bytes) -> str:
    return f"{hashlib.sha1(data).hexdigest()[:16]}:{len(data)}"


def _listing_seekable(
    source: Any, container: ContainerFormat, config: ArchiveyConfig = _CONFIG
) -> tuple[list[Row], bool]:
    rows: list[Row] = []
    clean = True
    total = 0
    with open_archive(source, config=config, password=_password(container)) as reader:
        for i, member in enumerate(reader):
            if i >= _MAX_MEMBERS:
                return rows, False
            digest = None
            if member.is_file and total < _TOTAL_CAP:
                try:
                    with reader.open(member) as stream:
                        data = _drain(stream, member.size, member.name)
                    total += len(data)
                    digest = _digest(data)
                except ArchiveyError as exc:
                    digest = f"ERR:{type(exc).__name__}"
                    clean = False
            rows.append(((member.name, member.type.name, member.link_target), digest))
    return rows, clean


def _listing_forward(
    source: Any, container: ContainerFormat, config: ArchiveyConfig = _CONFIG
) -> tuple[list[Row], bool]:
    seen: list[tuple[Any, str | None]] = []
    clean = True
    total = 0
    with open_archive(
        source, config=config, password=_password(container), streaming=True
    ) as reader:
        for i, (member, stream) in enumerate(reader.stream_members()):
            if i >= _MAX_MEMBERS:
                return [], False
            digest = None
            if member.is_file and stream is not None and total < _TOTAL_CAP:
                try:
                    data = _drain(stream, member.size, member.name)
                    total += len(data)
                    digest = _digest(data)
                except ArchiveyError as exc:
                    digest = f"ERR:{type(exc).__name__}"
                    clean = False
            seen.append((member, digest))
    # A member is final only once the pass is over: compare that state.
    return [
        ((m.name, m.type.name, m.link_target), digest if m.is_file else None)
        for m, digest in seen
    ], clean


def _run(
    fn: Callable[..., tuple[list[Row], bool]], *args: Any, **kwargs: Any
) -> Listing:
    try:
        rows, clean = fn(*args, **kwargs)
    except ArchiveyError as exc:
        return None, False, type(exc).__name__
    return rows, clean, None


def _compare(
    tag: str,
    container: ContainerFormat,
    a: Listing,
    b: Listing,
    *,
    second_may_fail: bool = False,
) -> None:
    rows_a, clean_a, error_a = a
    rows_b, clean_b, error_b = b
    name = container.name
    if clean_a and clean_b:
        if rows_a != rows_b:
            assert rows_a is not None and rows_b is not None
            at = next(
                (
                    i
                    for i, (x, y) in enumerate(zip(rows_a, rows_b, strict=False))
                    if x != y
                ),
                min(len(rows_a), len(rows_b)),
            )
            raise AssertionError(
                f"{name} {tag}: listings differ at member {at}: "
                f"{rows_a[at] if at < len(rows_a) else '-'} vs "
                f"{rows_b[at] if at < len(rows_b) else '-'}"
            )
    elif clean_a and error_b and not second_may_fail:
        raise AssertionError(
            f"{name} {tag}: the first read is clean, the second raised {error_b}"
        )
    elif clean_b and error_a:
        raise AssertionError(
            f"{name} {tag}: the first read raised {error_a}, the second is clean"
        )


def diff_modes_one(data: bytes) -> None:
    container = _container(data)
    if container is None:
        return
    chunk = 1 + data[-1] % 7
    small = len(data) <= _SHORT_READ_CAP
    base = _run(_listing_seekable, io.BytesIO(data), container)
    if small:
        _compare(
            "short reads",
            container,
            base,
            _run(_listing_seekable, ShortReadBytesIO(data, max_chunk=chunk), container),
        )
    if container in _FORWARD:
        forward = _run(_listing_forward, io.BytesIO(data), container)
        _compare("forward", container, base, forward)
        if small:
            pipe = ShortReadNonSeekable(data, max_chunk=chunk)
            _compare(
                "pipe",
                container,
                forward,
                _run(_listing_forward, pipe, container),
                second_may_fail=True,
            )


def seek_member_one(data: bytes) -> None:
    container = _container(data)
    if container is None:
        return
    pick = hashlib.sha256(data).digest()
    try:
        with open_archive(
            io.BytesIO(data),
            config=_CONFIG,
            password=_password(container),
            seekable_members=True,
        ) as reader:
            members = [
                m
                for _, m in zip(range(_MAX_MEMBERS), reader, strict=False)
                if m.is_file
            ]
            for k, member in enumerate(members[:_SEEK_FILES]):
                try:
                    with reader.open(member) as stream:
                        ref = _drain(stream, None, member.name)
                    if len(ref) >= _MEMBER_CAP:
                        continue
                    with reader.open(member) as stream:
                        _check_seeks(
                            stream, ref, pick, k, f"{container.name} {member.name}"
                        )
                except ArchiveyError:
                    continue
    except ArchiveyError:
        return


def _check_seeks(stream: Any, ref: bytes, pick: bytes, k: int, what: str) -> None:
    assert stream.seekable(), f"{what}: seekable_members=True but not seekable"
    for j in range(_SEEKS):
        r = pick[(k * _SEEKS + j) % len(pick)]
        pos = (r * 7919 * (j + 1)) % (len(ref) + 2)
        n = 1 + (r * 31) % 4096
        assert stream.seek(pos) == pos, f"{what}: seek({pos}) returned another offset"
        got = stream.read(n)
        assert got == ref[pos : pos + n], (
            f"{what}: read({n}) at {pos} gave {len(got)} bytes that differ from the "
            f"sequential read ({len(ref[pos : pos + n])} bytes)"
        )
        assert stream.tell() == pos + len(got), f"{what}: tell() after a read"
    assert stream.seek(0, os.SEEK_END) == len(ref), f"{what}: SEEK_END"
    back = stream.seek(-min(5, len(ref)), os.SEEK_CUR)
    assert stream.read() == ref[back:], f"{what}: read after SEEK_CUR"


_EXTRACT_ROOT = Path(tempfile.mkdtemp(prefix="archivey-fuzz-extract-"))


def _tree(root: Path) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                out.append((rel, "link", os.readlink(path)))
            elif stat.S_ISDIR(mode):
                out.append((rel, "dir", None))
            else:
                out.append((rel, "file", _digest(path.read_bytes())))
    return out


def _extract(
    data: bytes, container: ContainerFormat, *, streaming: bool, dest: Path, policy: str
) -> tuple[list[tuple[str, str, str | None]], str | None]:
    shutil.rmtree(dest, ignore_errors=True)
    try:
        with open_archive(
            io.BytesIO(data),
            config=_CONFIG,
            password=_password(container),
            streaming=streaming,
        ) as reader:
            reader.extract_all(dest, on_error="continue", policy=policy)  # type: ignore[arg-type]
    except ArchiveyError as exc:
        return _tree(dest), type(exc).__name__
    return _tree(dest), None


def extract_diff_one(data: bytes) -> None:
    container = _container(data)
    if container is None:
        return
    policy = ("strict", "standard", "trusted")[data[0] % 3]
    seekable_dest = _EXTRACT_ROOT / "seekable"
    streaming_dest = _EXTRACT_ROOT / "streaming"
    try:
        tree_a, error_a = _extract(
            data, container, streaming=False, dest=seekable_dest, policy=policy
        )
        tree_b, error_b = _extract(
            data, container, streaming=True, dest=streaming_dest, policy=policy
        )
    finally:
        shutil.rmtree(seekable_dest, ignore_errors=True)
        shutil.rmtree(streaming_dest, ignore_errors=True)
    name = container.name
    if error_a is None and error_b is None:
        assert tree_a == tree_b, (
            f"{name}: policy={policy}: seekable and streaming extraction leave "
            f"different trees: {sorted(set(tree_a) ^ set(tree_b))[:4]}"
        )
    else:
        assert (error_a is None) == (error_b is None), (
            f"{name}: policy={policy}: seekable raised {error_a}, streaming {error_b}"
        )


def tiny_limits_one(data: bytes) -> None:
    container = _container(data)
    if container is None:
        return
    try:
        _listing_seekable(io.BytesIO(data), container, _TINY_CONFIG)
    except ArchiveyError:
        pass
    if container in _FORWARD or container is ContainerFormat.ZIP:
        try:
            _listing_forward(io.BytesIO(data), container, _TINY_CONFIG)
        except ArchiveyError:
            pass


def oracle_seeds() -> list[bytes]:
    """Every format's seeds up to 256 KiB: the oracles detect the format first."""
    from tests.atheris_fuzz import seeds

    out: list[bytes] = []
    for fn in (
        seeds.open_detected_seeds,
        seeds.zip_seeds,
        seeds.tar_seeds,
        seeds.ar_seeds,
        seeds.cpio_seeds,
        seeds.rpm_seeds,
        seeds.cab_seeds,
        seeds.xar_seeds,
        seeds.squashfs_seeds,
        seeds.iso_seeds,
        seeds.sevenzip_seeds,
    ):
        out.extend(seed for seed in fn() if 0 < len(seed) <= 256 * 1024)
    return out


ORACLE_TARGETS: dict[str, Callable[[bytes], None]] = {
    "diff_modes": diff_modes_one,
    "seek_member": seek_member_one,
    "extract_diff": extract_diff_one,
    "tiny_limits": tiny_limits_one,
}
