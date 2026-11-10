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
  leaves the same tree, under a policy the input picks, and writes nothing outside
  its destination.
- ``tiny_limits``: tiny listing, metadata and decoder limits with
  ``DiagnosticPolicy.PEDANTIC``, so the limit and diagnostic paths raise only typed
  errors.

When both opens succeed, the listings compare member by member, and a member read
that raises is a row of its own (``ERR:<type>``), so a member that fails in one mode
only is a finding. When one open raises and the other read is clean, that is a
finding too, except where the source decides by design (below).

Known by-design differences that the targets leave out:

- A ZIP from a pipe yields the members its local headers name, and the central
  directory at the end can drop some of them (with a warning) or retype a symlink
  that a local header cannot mark. A damaged data descriptor fails on a pipe but not
  from a file, where the central directory gives the sizes. So the pipe comparison
  skips ZIP. A forward reader over a seekable source reads the central directory,
  so the forward comparison covers ZIP.
- A codec over a pipe cannot decode the bytes before damage again, so it raises at
  the read that meets the damage. From a seekable source the codec hands those bytes
  back first, and damage past the TAR's end-of-archive marker is only a warning (the
  codec reports a failed check the same way as junk after the stream). So a pipe
  may raise, at open or at a member, where the forward read on a seekable source is
  clean; the opposite, and two clean reads that differ, still fail.
- RAR runs ``unrar`` for every member, too slow for these targets; ``rar`` covers it.
"""

from __future__ import annotations

import hashlib
import io
import os
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
from archivey.types import ExtractionPolicyStr
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
# Formats a pipe can read in one pass and give the same listing as a file.
_PIPE = frozenset(
    {
        ContainerFormat.TAR,
        ContainerFormat.RAW_STREAM,
        ContainerFormat.AR,
        ContainerFormat.CPIO,
        ContainerFormat.RPM,
    }
)
# Formats a forward reader over a seekable source reads like a seekable one.
_FORWARD = _PIPE | {ContainerFormat.ZIP}
_POLICIES: tuple[ExtractionPolicyStr, ...] = ("strict", "standard", "trusted")
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
# Rows (None when the open or the walk raised), whether the listing is complete
# (False past _MAX_MEMBERS), and the open or walk error's type name.
Listing = tuple[list[Row] | None, bool, str | None]
_ERR = "ERR:"


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
                    digest = f"{_ERR}{type(exc).__name__}"
            rows.append(((member.name, member.type.name, member.link_target), digest))
    return rows, True


def _listing_forward(
    source: Any, container: ContainerFormat, config: ArchiveyConfig = _CONFIG
) -> tuple[list[Row], bool]:
    seen: list[tuple[Any, str | None]] = []
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
                    digest = f"{_ERR}{type(exc).__name__}"
            seen.append((member, digest))
    # A member is final only once the pass is over: compare that state.
    return [
        ((m.name, m.type.name, m.link_target), digest if m.is_file else None)
        for m, digest in seen
    ], True


def _run(
    fn: Callable[..., tuple[list[Row], bool]], *args: Any, **kwargs: Any
) -> Listing:
    try:
        rows, complete = fn(*args, **kwargs)
    except ArchiveyError as exc:
        return None, True, type(exc).__name__
    return rows, complete, None


def _clean(listing: Listing) -> bool:
    rows, complete, error = listing
    return (
        rows is not None
        and complete
        and error is None
        and not any(d is not None and d.startswith(_ERR) for _, d in rows)
    )


def _compare(
    tag: str,
    container: ContainerFormat,
    a: Listing,
    b: Listing,
    *,
    second_may_fail: bool = False,
) -> None:
    """Fail when two reads of one input disagree.

    With ``second_may_fail``, ``b`` may raise where ``a`` is clean: at open, or as a
    member read (``ERR:``) where ``a`` has the member's bytes, after which the rest
    of ``b`` is not compared.
    """
    rows_a, complete_a, error_a = a
    rows_b, complete_b, error_b = b
    name = container.name
    if not (complete_a and complete_b):
        return
    if rows_a is not None and rows_b is not None:
        for at in range(max(len(rows_a), len(rows_b))):
            x = rows_a[at] if at < len(rows_a) else None
            y = rows_b[at] if at < len(rows_b) else None
            if x == y:
                continue
            if (
                second_may_fail
                and x is not None
                and y is not None
                and x[0] == y[0]
                and y[1] is not None
                and y[1].startswith(_ERR)
            ):
                return
            raise AssertionError(
                f"{name} {tag}: listings differ at member {at}: "
                f"{x if x is not None else '-'} vs {y if y is not None else '-'}"
            )
    elif _clean(a) and error_b and not second_may_fail:
        raise AssertionError(
            f"{name} {tag}: the first read is clean, the second raised {error_b}"
        )
    elif _clean(b) and error_a:
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
        if small and container in _PIPE:
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


def _make_accessible(root: Path) -> None:
    """Give the owner access to every path under ``root``, so it can be read and removed.

    Extraction applies member modes: a file at ``0o000`` cannot be read, and a
    directory at ``0o500`` cannot be emptied, by a user that is not root.
    """
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode):
                os.chmod(path, 0o700)
            elif stat.S_ISREG(mode):
                os.chmod(path, 0o600)


def _tree(root: Path) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    if not root.exists():
        return out
    _make_accessible(root)
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
    data: bytes,
    container: ContainerFormat,
    *,
    streaming: bool,
    dest: Path,
    policy: ExtractionPolicyStr,
) -> tuple[list[tuple[str, str, str | None]], str | None]:
    try:
        with open_archive(
            io.BytesIO(data),
            config=_CONFIG,
            password=_password(container),
            streaming=streaming,
        ) as reader:
            reader.extract_all(dest, on_error="continue", policy=policy)
    except ArchiveyError as exc:
        return _tree(dest), type(exc).__name__
    return _tree(dest), None


def extract_diff_one(data: bytes) -> None:
    container = _container(data)
    if container is None:
        return
    policy = _POLICIES[data[0] % len(_POLICIES)]
    name = container.name
    # A fresh parent per input: nothing one input leaves can change the next, and
    # anything in the parent besides the two destinations was written outside them.
    with tempfile.TemporaryDirectory(prefix="archivey-fuzz-extract-") as tmp:
        parent = Path(tmp)
        dests: dict[str, Path] = {
            "seekable": parent / "seekable",
            "streaming": parent / "streaming",
        }
        try:
            tree_a, error_a = _extract(
                data, container, streaming=False, dest=dests["seekable"], policy=policy
            )
            tree_b, error_b = _extract(
                data, container, streaming=True, dest=dests["streaming"], policy=policy
            )
            outside = sorted(p.name for p in parent.iterdir() if p.name not in dests)
            assert not outside, (
                f"{name}: policy={policy}: extraction wrote outside its destination: "
                f"{outside[:4]}"
            )
        finally:
            _make_accessible(parent)
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
    if container in _FORWARD:
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
