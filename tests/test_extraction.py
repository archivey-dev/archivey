"""Safe-extraction tests: universal filters, policy transforms, BombTracker, and the
ExtractionCoordinator across ZIP / TAR / directory backends.

Covers the ``safe-extraction`` capability and the ``testing-contract`` adversarial
scenarios (path traversal, symlink escape, zip bomb, entry-count bomb).
"""

from __future__ import annotations

import errno
import gzip
import io
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import warnings
import zipfile
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from archivey import (
    AbortOn,
    ExtractionLimits,
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
    open_archive,
)
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ExtractionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
    NameCollisionError,
    NameRewrittenError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError, BombTracker
from archivey.internal.extraction import _CHUNK, ExtractionCoordinator
from archivey.internal.filters import (
    POLICY_TRANSFORMS,
    _resolve_with_pathlib,
    apply_name_policy,
    check_universal,
    resolve_or_raise_on_loop,
    transform_standard,
    transform_strict,
)
from archivey.internal.link_watch import LinkWatch
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.types import ArchiveFormat, ArchiveInfo, ArchiveMember, MemberType
from tests.conftest import binary_refusal, case_sensitive
from tests.corruption_util import raises_corruption_not_truncation
from tests.extract_util import open_and_extract
from tests.streams_util import SizedNonSeekable

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _member(
    name: str,
    *,
    raw: bytes | None = None,
    type: MemberType = MemberType.FILE,
    mode: int | None = None,
    link_target: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> ArchiveMember:
    return ArchiveMember(
        type=type,
        name=name,
        raw_name=raw if raw is not None else name.encode(),
        mode=mode,
        link_target=link_target,
        uid=uid,
        gid=gid,
    )


def _tar_bytes(specs: list[tuple], *, mode: str = "w") -> bytes:
    """Build a tar from (kind, name, payload) specs.

    kind: "file" (payload=bytes), "sym"/"hard" (payload=linkname), "dir" (payload=None).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for kind, name, payload in specs:
            if kind == "file":
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o644
                t.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                t.addfile(info)
            elif kind == "sym":
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                t.addfile(info)
            elif kind == "hard":
                info = tarfile.TarInfo(name)
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                t.addfile(info)
    return buf.getvalue()


def _write_zip(path: Path, entries: dict[str, bytes], mode: int | None = None) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            if mode is not None:
                info = zipfile.ZipInfo(name)
                info.create_system = 3  # Unix
                info.external_attr = mode << 16
                z.writestr(info, data)
            else:
                z.writestr(name, data)


# ---------------------------------------------------------------------------
# check_universal — universal path-safety (task 1.4 / testing-contract)
# ---------------------------------------------------------------------------


# Names are faithful now (normalization keeps a leading "/" and every ".."), so the
# check runs on member.name directly.
@pytest.mark.parametrize(
    "name",
    [
        "../evil",  # escaping traversal
        "../../etc/passwd",
        "foo/../bar",  # internal traversal is also rejected under the default RAISE
        "/etc/x",  # absolute
    ],
)
def test_check_universal_rejects_traversal(tmp_path: Path, name: str) -> None:
    with pytest.raises(FilterRejectionError):
        check_universal(_member(name), tmp_path)


def test_check_universal_rejects_null_byte(tmp_path: Path) -> None:
    with pytest.raises(FilterRejectionError):
        check_universal(_member("a\x00b"), tmp_path)


@pytest.mark.parametrize("name", ["C:evil", "c:evil", "C:\\evil"])
def test_check_universal_rejects_drive_letter(tmp_path: Path, name: str) -> None:
    with pytest.raises(FilterRejectionError, match="Absolute path"):
        check_universal(_member(name), tmp_path)


@pytest.mark.parametrize("name", ["Ä:foo", "Ω:foo", "日:foo"])
def test_non_ascii_letter_before_colon_is_not_a_drive_letter(name: str) -> None:
    """A drive letter is a single *ASCII* letter, as the comment beside the test says.

    ``str.isalpha()`` is Unicode-wide, so these names were classified as Windows
    absolute paths. Asserted on the predicate rather than through ``check_universal``
    because what happens to such a name afterwards is platform-specific: on Windows the
    colon makes it a drive-relative / ADS spelling and the destination-root check
    rejects it, correctly and for a different reason.
    """
    from archivey.internal.filters import _is_absolute

    assert _is_absolute(name) is False
    assert _is_absolute("C" + name[1:]) is True


@pytest.mark.skipif(
    os.name != "posix", reason="a colon in a filename is only ordinary on POSIX"
)
@pytest.mark.parametrize("name", ["Ä:foo", "Ω:foo", "日:foo"])
def test_check_universal_allows_non_ascii_letter_before_colon(
    tmp_path: Path, name: str
) -> None:
    """Under TRUSTED this check is the only thing between the member and the disk.

    These are ordinary POSIX filenames, and the drive-letter test was blocking them.
    """
    check_universal(_member(name), tmp_path)


def test_check_universal_rejects_root_named_file(tmp_path: Path) -> None:
    with pytest.raises(FilterRejectionError, match="extraction root"):
        check_universal(_member("."), tmp_path)
    with pytest.raises(FilterRejectionError, match="extraction root"):
        check_universal(_member(""), tmp_path)


def test_check_universal_allows_root_directory(tmp_path: Path) -> None:
    check_universal(_member(".", type=MemberType.DIRECTORY), tmp_path)


def test_check_universal_rejects_special_file(tmp_path: Path) -> None:
    with pytest.raises(FilterRejectionError):
        check_universal(_member("dev", type=MemberType.OTHER), tmp_path)


def test_check_universal_rejects_symlink_escape(tmp_path: Path) -> None:
    m = _member("link", type=MemberType.SYMLINK, link_target="../../etc/passwd")
    with pytest.raises(FilterRejectionError):
        check_universal(m, tmp_path)


def test_check_universal_names_a_symlink_escape_not_a_hardlink_target(
    tmp_path: Path,
) -> None:
    sym = _member("link", type=MemberType.SYMLINK, link_target="../outside.txt")
    with pytest.raises(
        FilterRejectionError, match="Symlink target escapes destination"
    ):
        check_universal(sym, tmp_path)
    # A hardlink target names a member and never becomes a path, so it is not
    # checked here; the coordinator refuses a link whose source was refused instead.
    hard = _member("h", type=MemberType.HARDLINK, link_target="../outside.txt")
    check_universal(hard, tmp_path)


def test_check_universal_rejects_null_byte_in_symlink_target(tmp_path: Path) -> None:
    m = _member("link", type=MemberType.SYMLINK, link_target="target\x00hidden")
    with pytest.raises(FilterRejectionError, match="Null byte in link target"):
        check_universal(m, tmp_path)


def test_check_universal_allows_internal_symlink(tmp_path: Path) -> None:
    m = _member("sub/link", type=MemberType.SYMLINK, link_target="../file.txt")
    check_universal(m, tmp_path)  # resolves to <dest>/file.txt, inside root


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize(
    ("name", "in_loop"),
    [("p/f", False), ("f", True), ("", True)],
    ids=["parent", "dest", "dest-root-member"],
)
def test_check_universal_names_a_loop_in_the_destination(
    tmp_path: Path, name: str, in_loop: bool
) -> None:
    # A loop the destination already had, below dest or at dest itself. Path.resolve()
    # raises on it before Python 3.13 and returns a path from 3.13; the answer must not
    # depend on which.
    os.symlink("p", tmp_path / "p")
    dest = tmp_path / "p" if in_loop else tmp_path
    member = _member(name, type=MemberType.DIRECTORY) if name == "" else _member(name)
    with pytest.raises(ExtractionError) as info:
        check_universal(member, dest)
    assert type(info.value) is ExtractionError
    assert "A path in the destination does not resolve (a symlink loop)" in str(
        info.value
    )


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_check_universal_names_a_path_past_path_max_in_the_destination(
    tmp_path: Path,
) -> None:
    # Not a loop: the destination's link chain is longer than PATH_MAX when expanded.
    _link_chain_past_path_max(tmp_path)
    with pytest.raises(ExtractionError) as info:
        check_universal(_member("up/f"), tmp_path)
    assert type(info.value) is ExtractionError
    assert (
        "A path in the destination does not resolve (a path that cannot be looked up)"
        in str(info.value)
    )


def test_check_universal_enforced_under_trusted(tmp_path: Path) -> None:
    # Universal checks are non-bypassable, even under TRUSTED.
    with pytest.raises(FilterRejectionError):
        check_universal(_member("../evil"), tmp_path)
    # ...and TRUSTED's transform itself is identity (path safety is separate).
    m = _member("ok", mode=0o777)
    assert POLICY_TRANSFORMS[ExtractionPolicy.TRUSTED](m).mode == 0o777


@pytest.mark.skipif(
    os.name != "posix", reason="surrogateescape filename bytes are a POSIX concept"
)
@pytest.mark.parametrize(
    "name_bytes",
    [
        b"caf\xe9.txt",  # Latin-1 'é' — undecodable as UTF-8, kept via surrogateescape
        b"\xff\xfe.bin",  # arbitrary high bytes
        b"dir\xe9/file\xff.txt",  # hostile bytes in a subdir component too
    ],
    ids=["latin1", "highbytes", "subdir"],
)
def test_surrogateescape_name_extracts_safely_or_is_cleanly_refused(
    tmp_path: Path, name_bytes: bytes
) -> None:
    # The accept side of the encoding contract (companion to the check_universal
    # totality/materializability property tests). A member name carrying non-UTF-8
    # filename bytes is decoded with surrogateescape on read and PASSES the universal
    # filter (the bytes are fsencodable, so representable *as bytes*). What happens at
    # the write() syscall is then the *target filesystem's* call, and we only promise
    # safety, not faithful round-trip:
    #   * On a bytes-transparent FS (ext4/most Linux) the file lands under the exact
    #     original filename bytes — no crash, no mojibake.
    #   * On a UTF-8-enforcing FS (APFS/macOS raises OSError EILSEQ "Illegal byte
    #     sequence") the OS refuses the name; extraction surfaces that as a normal
    #     write failure — no traversal, nothing created outside dest, no process abort.
    # Sanitizing such names into an always-writable "safe" form is a deliberate,
    # policy-gated feature (threat-model O3/O7), intentionally NOT done here.
    stored = name_bytes.decode("utf-8", errors="surrogateescape")
    buf = io.BytesIO()
    with tarfile.open(
        fileobj=buf, mode="w", encoding="utf-8", errors="surrogateescape"
    ) as tf:
        info = tarfile.TarInfo(stored)
        info.size = 3
        tf.addfile(info, io.BytesIO(b"abc"))

    dest = tmp_path / "out"
    try:
        open_and_extract(
            io.BytesIO(buf.getvalue()), dest, policy=ExtractionPolicy.TRUSTED
        )
    except ExtractionError:
        # The filesystem rejected the byte sequence at write time (e.g. APFS/macOS
        # raises OSError EILSEQ); the coordinator translates that to a typed
        # ExtractionError. That is the honest "the OS won't represent this name"
        # outcome — safe. The only guarantee is that nothing escaped: whatever
        # exists is under dest.
        for p in dest.rglob("*"):
            assert (
                dest.resolve() in p.resolve().parents or p.resolve() == dest.resolve()
            )
        return

    # The FS accepted the bytes: the file exists under the exact original filename bytes.
    on_disk = {os.fsencode(p.name) for p in dest.rglob("*") if p.is_file()}
    assert os.path.basename(name_bytes) in on_disk


def test_unrepresentable_name_oserror_is_translated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A destination filesystem that refuses a filter-accepted name at write time
    # (OSError EILSEQ, e.g. non-UTF-8 bytes on APFS/macOS) must surface as a typed
    # ExtractionError naming the member, not a bare OSError. Simulated here (ext4
    # accepts any bytes) by making the atomic file write raise EILSEQ.
    import archivey.internal.extraction as extraction_mod

    def fake_replace(src: object, dst: object, /) -> None:
        raise OSError(errno.EILSEQ, "Illegal byte sequence")

    monkeypatch.setattr(extraction_mod.os, "replace", fake_replace)

    archive = _tar_bytes([("file", "member.txt", b"hi")])
    dest = tmp_path / "out"
    with pytest.raises(ExtractionError, match="member.txt"):
        open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.TRUSTED)


# ---------------------------------------------------------------------------
# Policy transforms (task 1.4)
# ---------------------------------------------------------------------------


def test_strict_keeps_execute_and_strips_group_other_write() -> None:
    out = transform_strict(_member("f", mode=0o777))
    assert out.mode == 0o755  # execute kept, group/other write stripped
    assert out.uid is None and out.gid is None


def test_strict_dir_normalized_to_755() -> None:
    out = transform_strict(_member("d/", type=MemberType.DIRECTORY, mode=0o777))
    assert out.mode == 0o755


def test_strict_strips_setuid() -> None:
    out = transform_strict(_member("f", mode=0o4755))
    assert out.mode & 0o7000 == 0
    assert out.mode == 0o755


def test_standard_preserves_execute() -> None:
    out = transform_standard(_member("f", mode=0o755))
    assert out.mode == 0o755  # execute kept
    out2 = transform_standard(_member("f", mode=0o4755))
    assert out2.mode == 0o755  # only setuid stripped


def test_strict_mode_none_defaults() -> None:
    assert transform_strict(_member("f")).mode == 0o644
    assert transform_strict(_member("d/", type=MemberType.DIRECTORY)).mode == 0o755


@pytest.mark.parametrize(
    "stored,expected",
    [
        (0o600, 0o600),
        (0o640, 0o640),
        (0o660, 0o640),  # umask 007: group-shared, must not gain other-read
        (0o664, 0o644),
        (0o666, 0o644),
        (0o755, 0o755),
        (0o700, 0o700),
        (0o744, 0o744),
        (0o011, 0o000),  # no owner execute: group/other execute go too, as in tarfile
        (0o655, 0o644),
        (0o604, 0o604),
        (0o000, 0o000),
    ],
)
def test_strict_file_mode_is_masked_never_widened(stored: int, expected: int) -> None:
    """STRICT clears bits a file stored; it never sets one the file did not have.

    ``min(mode, 0o644)`` compared the modes as integers, so ``0o660`` came out as
    ``0o644`` and gained other-read under the policy meant to distrust the archive.
    """
    out = transform_strict(_member("f", mode=stored))
    assert out.mode == expected
    assert out.mode is not None and out.mode & ~stored == 0


# ---------------------------------------------------------------------------
# BombTracker (task 2.3)
# ---------------------------------------------------------------------------


def test_cumulative_byte_limit() -> None:
    t = BombTracker(max_bytes=100, max_ratio=1e9)
    t.start_member(_member("f"))
    t.count(60)
    with pytest.raises(AlwaysStopResourceLimitError):
        t.count(50)  # crosses 100


def test_per_member_ratio() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=10)
    t.start_member(_member("f").replace(compressed_size=1))
    with pytest.raises(ResourceLimitError) as ei:
        t.count(20)  # member_bytes 20 > floor 10, ratio 20:1 > 2
    assert not isinstance(ei.value, AlwaysStopResourceLimitError)  # skippable
    assert not isinstance(ei.value, ExtractionError)


def test_ratio_activation_threshold_false_positive_guard() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=100)
    t.start_member(_member("f").replace(compressed_size=1))
    t.count(50)  # below floor 100 -> no trip despite 50:1


def test_archive_wide_ratio() -> None:
    # Static denominator: the reader reports a cheaply-known outer compressed size.
    t = BombTracker(
        max_bytes=10**12,
        max_ratio=2.0,
        ratio_activation_threshold=10,
        source=SimpleNamespace(
            compressed_source_size=10, compressed_bytes_consumed=None
        ),
    )
    t.start_member(_member("f"))  # no per-member compressed_size
    with pytest.raises(AlwaysStopResourceLimitError):
        t.count(30)  # total 30 > floor 10, 30/10 = 3 > 2


def test_archive_wide_ratio_live_denominator() -> None:
    # No static size (e.g. a pipe): the tracker samples the reader's live count of
    # compressed bytes consumed instead.
    t = BombTracker(
        max_bytes=10**12,
        max_ratio=2.0,
        ratio_activation_threshold=10,
        source=SimpleNamespace(
            compressed_source_size=None, compressed_bytes_consumed=10
        ),
        live_ratio_activation_threshold=10,
    )
    t.start_member(_member("f"))
    with pytest.raises(AlwaysStopResourceLimitError):
        t.count(30)  # total 30 > floor 10, live 30/10 = 3 > 2


def test_live_ratio_waits_for_its_own_floor() -> None:
    # The live denominator is what has been read so far, so a blank start reads far
    # above the ratio the whole archive ends at. The live check waits for its own,
    # larger floor; the static check keeps the ordinary one.
    source = SimpleNamespace(compressed_source_size=None, compressed_bytes_consumed=10)
    t = BombTracker(
        max_bytes=10**12,
        max_ratio=2.0,
        ratio_activation_threshold=10,
        source=source,
        live_ratio_activation_threshold=100,
    )
    t.start_member(_member("f"))
    t.count(90)  # 90:10 is 9:1, but output is still under the live floor
    source.compressed_bytes_consumed = 60  # the data after the blank start arrives
    t.count(20)  # past the floor: 110:60 is under 2:1
    with pytest.raises(AlwaysStopResourceLimitError, match="Live decompression"):
        t.count(30)  # 140:60 is over 2:1


def test_live_ratio_default_floor() -> None:
    # The default live floor sits between the ordinary floor and the byte cap, so the
    # live ratio is reachable under default limits and judges a pipe before the cap.
    d = ExtractionLimits()
    assert (
        d.ratio_activation_threshold
        <= d.live_ratio_activation_threshold
        < d.max_extracted_bytes
    )
    floor = d.live_ratio_activation_threshold
    for output, trips in [(floor, False), (floor + 1, True)]:
        t = BombTracker(
            d.max_extracted_bytes,
            d.max_ratio,
            d.ratio_activation_threshold,
            d.max_entries,
            source=SimpleNamespace(
                compressed_source_size=None, compressed_bytes_consumed=1024
            ),
            live_ratio_activation_threshold=floor,
        )
        t.start_member(_member("f"))
        if trips:
            with pytest.raises(AlwaysStopResourceLimitError, match="Live"):
                t.count(output)
        else:
            t.count(output)


def test_extraction_limits_positional_order_is_stable() -> None:
    # The live floor was added after ``max_entries``, so a caller passing the first
    # four fields positionally still sets ``max_entries``.
    limits = ExtractionLimits(2 * 2**30, 1000.0, 5 * 2**20, 1000)
    assert limits.max_entries == 1000
    assert limits.live_ratio_activation_threshold == 256 * 2**20


def test_ratio_skipped_when_denominators_unknown() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=1)
    t.start_member(_member("f"))  # compressed_size None, no source size
    t.count(10_000)  # no ratio applies; cumulative under limit


def test_recorded_size_refuses_a_member_before_its_data() -> None:
    # The member's recorded size already decides the per-member ratio, so the member
    # is refused before count() sees a byte, with the same skippable error.
    t = BombTracker(max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=10)
    t.start_member(_member("f").replace(size=21, compressed_size=10))
    with pytest.raises(ResourceLimitError, match="from recorded sizes") as ei:
        t.check_recorded_size()
    assert not isinstance(ei.value, AlwaysStopResourceLimitError)
    assert t.total_bytes == 0


@pytest.mark.parametrize(
    ("size", "compressed_size"),
    [
        (20, 10),  # exactly at the ratio: count() would not trip either
        (10, 1),  # 10:1, but not past the 10-byte floor
        (None, 1),  # no recorded size: left to count()
        (10**6, None),  # no compressed size: per-member ratio does not apply
        (10**6, 0),
    ],
)
def test_recorded_size_passes_what_count_would_pass(
    size: int | None, compressed_size: int | None
) -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=10)
    t.start_member(_member("f").replace(size=size, compressed_size=compressed_size))
    t.check_recorded_size()
    if size is not None:
        t.count(size)  # and the measured check agrees


def test_recorded_size_leaves_the_archive_wide_ratio_to_count() -> None:
    # The archive's recorded sizes are not checked up front: a size nothing has
    # verified must not stop the whole run (see the forged-size test below).
    source = SimpleNamespace(compressed_source_size=10, compressed_bytes_consumed=None)
    t = BombTracker(
        max_bytes=10**12, max_ratio=2.0, ratio_activation_threshold=10, source=source
    )
    t.start_member(_member("f").replace(size=1000))
    t.check_recorded_size()
    with pytest.raises(AlwaysStopResourceLimitError, match="Archive-wide"):
        t.count(1000)


def test_max_entries_guard() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=1e9, max_entries=2)
    t.start_member(_member("a"))
    t.start_member(_member("b"))
    with pytest.raises(AlwaysStopResourceLimitError):
        t.start_member(_member("c"))


def test_entry_count_independent_of_bytes() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=1e9, max_entries=1)
    t.start_member(_member("a"))
    with pytest.raises(AlwaysStopResourceLimitError):
        t.start_member(_member("b"))  # trips on count, not bytes


def test_bomb_tracker_member_bytes_mirrors_count() -> None:
    t = BombTracker(max_bytes=10**12, max_ratio=1e9)
    t.start_member(_member("f"))
    assert t.member_bytes == 0
    t.count(100)
    assert t.member_bytes == 100
    assert t.total_bytes == 100
    t.start_member(_member("g"))
    assert t.member_bytes == 0
    assert t.total_bytes == 100


def test_file_writer_rejects_missing_stream() -> None:
    # A FILE reaching the writer with stream=None is a backend bug (a zero-byte FILE still
    # yields a real, empty stream). The writer must raise rather than silently create an
    # empty file and mask the bug (task 5a.5).
    with pytest.raises(ExtractionError, match="no data stream"):
        ExtractionCoordinator._copy_to_fileobj(None, io.BytesIO(), None)


# ---------------------------------------------------------------------------
# Coordinator — ZIP vertical slice (tasks 3.x, 5.x)
# ---------------------------------------------------------------------------


def test_extract_zip_basic(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"hello.txt": b"hi", "dir/nested.txt": b"deep"})
    dest = tmp_path / "out"
    results = open_and_extract(src, dest).results
    assert (dest / "hello.txt").read_bytes() == b"hi"
    assert (dest / "dir" / "nested.txt").read_bytes() == b"deep"
    assert {r.status for r in results} == {ExtractionStatus.EXTRACTED}


# Windows has no Unix permission bits — os.chmod there can only toggle the read-only
# flag, so a regular file always reads back ~0o666 with no execute/group/other bits. The
# permission-normalization behavior is a POSIX concept, so assert it only on POSIX.
_posix_perms = pytest.mark.skipif(
    os.name != "posix", reason="Unix permission bits (chmod) are a no-op on Windows"
)


@_posix_perms
def test_extract_zip_strict_normalizes_mode(tmp_path: Path) -> None:
    src = tmp_path / "m.zip"
    _write_zip(src, {"x.sh": b"#!/bin/sh"}, mode=0o777)
    dest = tmp_path / "out"
    open_and_extract(src, dest, policy=ExtractionPolicy.STRICT)
    assert (dest / "x.sh").stat().st_mode & 0o777 == 0o755


@_posix_perms
def test_trusted_mode_less_file_gets_the_umask_default(tmp_path: Path) -> None:
    """A member storing no mode extracts like an ordinary file creation under TRUSTED.

    A Windows-created ZIP entry stores no Unix mode. STRICT and STANDARD substitute
    ``0o644``; TRUSTED passes ``None`` through, and the file used to keep ``mkstemp``'s
    ``0o600`` — the most permissive policy producing the least readable files.
    """
    src = tmp_path / "w.zip"
    with zipfile.ZipFile(src, "w") as z:
        info = zipfile.ZipInfo("a.txt")
        info.create_system = 0  # MS-DOS: no Unix mode in external_attr
        info.external_attr = 0
        z.writestr(info, b"hello")
    with open_archive(src) as r:
        assert next(iter(r.members())).mode is None

    umask = os.umask(0o022)
    os.umask(umask)
    dest = tmp_path / "out"
    open_and_extract(src, dest, policy=ExtractionPolicy.TRUSTED)
    assert (dest / "a.txt").stat().st_mode & 0o7777 == 0o666 & ~umask
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert not [p for p in dest.iterdir() if p.name.startswith(".archivey-tmp-")]


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="chown to another uid needs root",
)
@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o6755, 0o1755])
def test_trusted_as_root_keeps_setuid_setgid_through_chown(
    tmp_path: Path, mode: int
) -> None:
    """TRUSTED as root applies the stored mode *after* the ownership.

    Linux ``chown`` clears setuid/setgid on a regular file even for root, so chmod then
    chown landed ``0o4755`` as ``0o755``. ``tar -xp`` as root keeps them; so must this.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("tool")
        info.size = 2
        info.mode = mode
        info.uid = info.gid = 1000
        t.addfile(info, io.BytesIO(b"hi"))
    dest = tmp_path / "out"
    open_and_extract(io.BytesIO(buf.getvalue()), dest, policy=ExtractionPolicy.TRUSTED)
    st = (dest / "tool").stat()
    assert st.st_mode & 0o7777 == mode
    assert (st.st_uid, st.st_gid) == (1000, 1000)


def _tar_file_and_link(file_mode: int, link_mode: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("src.bin")
        info.size = 3
        info.mode = file_mode
        t.addfile(info, io.BytesIO(b"abc"))
        link = tarfile.TarInfo("link.bin")
        link.type = tarfile.LNKTYPE
        link.linkname = "src.bin"
        link.mode = link_mode
        t.addfile(link)
    return buf.getvalue()


@_posix_perms
@pytest.mark.parametrize(
    "policy,expected",
    [(ExtractionPolicy.STRICT, 0o755), (ExtractionPolicy.STANDARD, 0o777)],
)
def test_materialized_hardlink_mode_is_capped_like_a_files(
    tmp_path: Path, policy: ExtractionPolicy, expected: int
) -> None:
    """A hardlink written as real content gets the policy's file-mode treatment.

    Extracting only the link orphans its source, so the link carries the content and
    its own mode. The transforms used to cap only FILE members, so ``0o4777`` landed
    as is under STRICT and STANDARD alike.
    """
    archive = _tar_file_and_link(0o600, 0o4777)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive)) as r:
        r.extract_all(dest, members=["link.bin"], policy=policy)
    assert (dest / "link.bin").read_bytes() == b"abc"
    assert (dest / "link.bin").stat().st_mode & 0o7777 == expected


@_posix_perms
def test_cross_device_hardlink_copy_mode_is_capped_under_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The EXDEV copy takes the link's mode, so that mode has to be capped first."""

    def always_exdev(source: object, target: object, *a: object, **k: object) -> None:
        raise OSError(errno.EXDEV, "cross-device")

    monkeypatch.setattr(os, "link", always_exdev)
    dest = tmp_path / "out"
    open_and_extract(io.BytesIO(_tar_file_and_link(0o600, 0o4777)), dest)
    assert (dest / "src.bin").stat().st_mode & 0o7777 == 0o600
    assert (dest / "link.bin").stat().st_mode & 0o7777 == 0o755


@_posix_perms
@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
def test_filter_dropping_the_mode_still_gets_the_policy_default(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """A filter runs after the transform; a ``mode=None`` it returns is not TRUSTED's.

    The umask-default creation mode belongs to TRUSTED alone. Under a permissive
    umask it would give a group- or world-writable file, so STRICT and STANDARD fall
    back to their documented ``0o644`` for a file and ``0o755`` for a directory.
    """
    archive = _tar_bytes([("dir", "d", None), ("file", "d/f.txt", b"x")])

    def drop_mode(m: ArchiveMember) -> ArchiveMember:
        return m.replace(mode=None)

    old = os.umask(0o002)
    try:
        dest = tmp_path / "out"
        with open_archive(io.BytesIO(archive)) as r:
            r.extract_all(dest, filter=drop_mode, policy=policy)
    finally:
        os.umask(old)
    assert (dest / "d" / "f.txt").stat().st_mode & 0o7777 == 0o644
    assert (dest / "d").stat().st_mode & 0o7777 == 0o755


def _tar_with_dir_modes(specs: list[tuple[str, int | None, int]]) -> bytes:
    """A tar from ``(name, mode, mtime)`` specs: a name ending in ``/`` is a
    directory, anything else a one-byte file; a ``mode`` of ``None`` is a symlink
    whose target is that name with the ``->`` part split off (``"l->t"``)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, mode, mtime in specs:
            if mode is None:
                link, target = name.split("->")
                info = tarfile.TarInfo(link)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                tf.addfile(info)
                continue
            info = tarfile.TarInfo(name.rstrip("/"))
            info.mode = mode
            info.mtime = mtime
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


def _restore_modes(root: Path) -> None:
    """Make every directory under ``root`` writable again, so pytest can remove it."""
    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)


_DIR_MTIME = 1_500_000_000
_SUB_MTIME = 1_400_000_000


@_posix_perms
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize(
    ("policy", "stored", "expected"),
    [
        (ExtractionPolicy.STANDARD, 0o644, 0o644),
        (ExtractionPolicy.STANDARD, 0o555, 0o555),
        (ExtractionPolicy.TRUSTED, 0o000, 0o000),
        (ExtractionPolicy.STRICT, 0o500, 0o755),
    ],
)
def test_directory_metadata_is_applied_after_its_children(
    tmp_path: Path,
    streaming: bool,
    policy: ExtractionPolicy,
    stored: int,
    expected: int,
) -> None:
    """A directory stored without owner write or search permission still gets its
    children, and ends with its stored mode and mtime, as with GNU tar and bsdtar.

    The directory's mode and mtime are applied once the run is done, deepest first:
    applied at once, the mode refused every child to a non-root user, and every child
    written moved the mtime. Root skips the permission checks, so there only the
    final mode and mtime show the order.
    """
    archive = _tar_with_dir_modes(
        [
            ("etc/", stored, _DIR_MTIME),
            ("etc/a", 0o644, 0),
            ("etc/sub/", stored, _SUB_MTIME),
            ("etc/sub/b", 0o644, 0),
        ]
    )
    dest = tmp_path / "out"
    try:
        report = open_and_extract(
            io.BytesIO(archive), dest, policy=policy, streaming=streaming
        )
        assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 4
        # Each directory is read, then opened up so the one below it can be read: a
        # chmod leaves the mtime alone.
        etc, sub = dest / "etc", dest / "etc" / "sub"
        for directory, mtime in ((etc, _DIR_MTIME), (sub, _SUB_MTIME)):
            st = directory.stat()
            assert st.st_mode & 0o7777 == expected
            assert int(st.st_mtime) == mtime
            os.chmod(directory, 0o700)
        assert (etc / "a").read_bytes() == b"x"
        assert (sub / "b").read_bytes() == b"x"
    finally:
        _restore_modes(dest)


class _NoInode:
    """A stat result that reports inode 0, as some FUSE and network mounts do."""

    def __init__(self, st: os.stat_result) -> None:
        self._st = st

    @property
    def st_ino(self) -> int:
        return 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._st, name)


@_posix_perms
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_directory_metadata_is_applied_where_inodes_are_zero(
    tmp_path: Path, streaming: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every directory gets its own member's metadata on a filesystem that reports
    inode 0 for every entry: two directories are not taken for one."""
    lstat, fstat = os.lstat, os.fstat
    monkeypatch.setattr(os, "lstat", lambda *a, **k: _NoInode(lstat(*a, **k)))
    monkeypatch.setattr(os, "fstat", lambda fd: _NoInode(fstat(fd)))
    archive = _tar_with_dir_modes(
        [("one/", 0o555, _DIR_MTIME), ("two/", 0o551, _SUB_MTIME)]
    )
    dest = tmp_path / "out"
    try:
        open_and_extract(
            io.BytesIO(archive),
            dest,
            policy=ExtractionPolicy.STANDARD,
            streaming=streaming,
        )
        monkeypatch.undo()
        for name, mode, mtime in (
            ("one", 0o555, _DIR_MTIME),
            ("two", 0o551, _SUB_MTIME),
        ):
            st = (dest / name).stat()
            assert (name, st.st_mode & 0o7777, int(st.st_mtime)) == (name, mode, mtime)
    finally:
        monkeypatch.undo()
        _restore_modes(dest)


@_posix_perms
def test_directory_metadata_is_applied_when_the_run_stops(tmp_path: Path) -> None:
    """A refused member stops the run (``AbortOn.BLOCKED_MEMBER``), and the
    directories written before it still end with their stored mode and mtime."""
    archive = _tar_with_dir_modes(
        [("d/", 0o555, _DIR_MTIME), ("d/f", 0o644, 0), ("../x", 0o644, 0)]
    )
    dest = tmp_path / "out"
    try:
        with pytest.raises(FilterRejectionError):
            open_and_extract(
                io.BytesIO(archive),
                dest,
                policy=ExtractionPolicy.STANDARD,
                abort_on=[AbortOn.BLOCKED_MEMBER],
                streaming=True,
            )
        assert (dest / "d").stat().st_mode & 0o7777 == 0o555
        assert int((dest / "d").stat().st_mtime) == _DIR_MTIME
        assert (dest / "d" / "f").read_bytes() == b"x"
    finally:
        _restore_modes(dest)


@_posix_perms
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_deferred_directory_metadata_never_follows_a_symlink(tmp_path: Path) -> None:
    """A directory replaced by a symlink before the run ends keeps nothing of its
    member's metadata: the symlink's target is not changed."""
    archive = _tar_with_dir_modes(
        [
            ("t/", 0o755, 0),
            ("d/", 0o700, _DIR_MTIME),
            ("d->t", None, 0),
        ]
    )
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.STANDARD,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "d").is_symlink()
    assert (dest / "t").stat().st_mode & 0o7777 == 0o755
    assert int((dest / "t").stat().st_mtime) != _DIR_MTIME


def _extract_removing_a_directory(
    dest: Path,
    monkeypatch: pytest.MonkeyPatch,
    specs: list[tuple[str, int | None, int]],
    policy: ExtractionPolicy = ExtractionPolicy.STANDARD,
) -> list[ExtractionStatus]:
    """Extract ``specs`` under ``policy`` and REPLACE, where a symlink member named ``d``
    is refused after REPLACE has removed the empty directory at its name.

    Python 3.11 and 3.12 refuse the loop ``d -> d`` because ``Path.resolve()`` raises
    on it; from 3.13 it does not raise, and the link is kept. The re-check is patched
    to refuse it on every version. Inodes are reported as 0, so the identity check
    cannot tell two directories at one place apart, as on a filesystem that reuses a
    freed inode."""
    import archivey.internal.extraction as extraction_mod

    problem = extraction_mod._symlink_problem
    monkeypatch.setattr(
        extraction_mod,
        "_symlink_problem",
        lambda link, target, root: (
            extraction_mod.SYMLINK_LOOPS
            if link.name == "d"
            else problem(link, target, root)
        ),
    )
    lstat, fstat = os.lstat, os.fstat
    monkeypatch.setattr(os, "lstat", lambda *a, **k: _NoInode(lstat(*a, **k)))
    monkeypatch.setattr(os, "fstat", lambda fd: _NoInode(fstat(fd)))
    try:
        report = open_and_extract(
            io.BytesIO(_tar_with_dir_modes(specs)),
            dest,
            policy=policy,
            overwrite=OverwritePolicy.REPLACE,
            on_error="continue",
        )
    finally:
        monkeypatch.undo()
    return [r.status for r in report.results]


def _assert_plain_parent(directory: Path) -> None:
    """``directory`` was made as a parent: the creation default and the current time."""
    umask = os.umask(0)
    os.umask(umask)
    st = directory.stat()
    assert st.st_mode & 0o7777 == 0o777 & ~umask
    assert abs(st.st_mtime - time.time()) < 300


@_posix_perms
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_deferred_metadata_of_a_directory_removed_by_another_spelling_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``s/d/`` is written through the archive's own ``s -> .``, so it is the
    directory ``d``. REPLACE removes that empty directory for the symlink ``d -> d``,
    which is then refused, and ``d/x`` creates ``d`` again as a plain parent. The
    removed member's mode and mtime must not land on that new directory: the removal
    names ``d``, and the pending metadata has to be found from that name."""
    dest = tmp_path / "out"
    statuses = _extract_removing_a_directory(
        dest,
        monkeypatch,
        [
            ("s->.", None, 0),
            ("s/d/", 0o700, _DIR_MTIME),
            ("d->d", None, 0),
            ("d/x", 0o644, 0),
        ],
    )
    assert statuses == [
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.BLOCKED,
        ExtractionStatus.EXTRACTED,
    ]
    _assert_plain_parent(dest / "d")


@_posix_perms
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
@pytest.mark.parametrize(
    ("policy", "removed_status"),
    [
        (ExtractionPolicy.STANDARD, ExtractionStatus.OVERWRITTEN),
        # TRUSTED keys results on the exact name, so ``D/``'s result is not revised;
        # its pending metadata is still dropped.
        (ExtractionPolicy.TRUSTED, ExtractionStatus.EXTRACTED),
    ],
    ids=["standard", "trusted"],
)
def test_deferred_metadata_of_a_directory_removed_by_a_case_variant_is_dropped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy: ExtractionPolicy,
    removed_status: ExtractionStatus,
) -> None:
    """On a case-insensitive filesystem ``D/`` and ``d`` are one entry. REPLACE removes
    the empty ``D/`` for the refused symlink ``d``, and ``d/x`` creates ``d`` again as a
    plain parent, which must not get ``D/``'s mode and mtime."""
    dest = tmp_path / "out"
    dest.mkdir()
    if case_sensitive(dest):
        pytest.skip("needs a case-insensitive filesystem, where D/ and d are one entry")
    statuses = _extract_removing_a_directory(
        dest,
        monkeypatch,
        [("D/", 0o700, _DIR_MTIME), ("d->d", None, 0), ("d/x", 0o644, 0)],
        policy,
    )
    assert statuses == [
        removed_status,
        ExtractionStatus.BLOCKED,
        ExtractionStatus.EXTRACTED,
    ]
    _assert_plain_parent(dest / "d")


@_posix_perms
@pytest.mark.parametrize(
    "policy",
    [ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED],
    ids=["standard", "trusted"],
)
def test_deferred_metadata_of_a_case_variant_directory_still_there_is_kept(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """On a case-sensitive filesystem ``X/`` and ``x/`` are two directories under one
    casefolded key. REPLACE removing ``x/`` for the file ``x`` must not drop the
    pending metadata of ``X/``, which is still there."""
    dest = tmp_path / "out"
    dest.mkdir()
    if not case_sensitive(dest):
        pytest.skip(
            "needs a case-sensitive filesystem, where X/ and x/ are two entries"
        )
    archive = _tar_with_dir_modes(
        [("X/", 0o700, _DIR_MTIME), ("x/", 0o750, _SUB_MTIME), ("x", 0o644, 0)]
    )
    open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=policy,
        overwrite=OverwritePolicy.REPLACE,
    )
    st = (dest / "X").stat()
    assert (st.st_mode & 0o7777, int(st.st_mtime)) == (0o700, _DIR_MTIME)
    assert (dest / "x").read_bytes() == b"x"


@_posix_perms
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
@pytest.mark.parametrize(
    ("specs", "mode", "mtime"),
    [
        # The run creates ``d`` as the parent of ``s/d/f``; ``d/`` names it again.
        (
            [("s->.", None, 0), ("s/d/f", 0o644, 0), ("d/", 0o700, _DIR_MTIME)],
            0o700,
            _DIR_MTIME,
        ),
        # Two directory members reach one directory: the one written last applies.
        (
            [("s->.", None, 0), ("d/", 0o700, _DIR_MTIME), ("s/d/", 0o750, _SUB_MTIME)],
            0o750,
            _SUB_MTIME,
        ),
        (
            [("s->.", None, 0), ("s/d/", 0o750, _SUB_MTIME), ("d/", 0o700, _DIR_MTIME)],
            0o700,
            _DIR_MTIME,
        ),
    ],
    ids=["created-as-parent", "written-then-through-link", "through-link-then-written"],
)
def test_a_directory_this_run_made_is_ours_under_every_spelling(
    tmp_path: Path, specs: list[tuple[str, int | None, int]], mode: int, mtime: int
) -> None:
    """A directory member that names, under another spelling, a directory this run
    already wrote or created is not the caller's directory: its stored mode and mtime
    are applied, and no ``kept_mode`` is reported."""
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar_with_dir_modes(specs)), dest, policy=ExtractionPolicy.STANDARD
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert all(r.kept_mode is None for r in report.results)
    st = (dest / "d").stat()
    assert (st.st_mode & 0o7777, int(st.st_mtime)) == (mode, mtime)


@_posix_perms
@pytest.mark.parametrize(
    "policy",
    [ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED],
    ids=["standard", "trusted"],
)
def test_a_directory_this_run_made_is_ours_under_a_case_variant(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """On a case-insensitive filesystem ``D/`` and ``d/`` are one directory, under
    every policy. ``d/`` names the directory ``D/`` wrote, so it is not the caller's:
    no ``kept_mode`` is reported, and its stored mode and mtime, written last, apply."""
    dest = tmp_path / "out"
    dest.mkdir()
    if case_sensitive(dest):
        pytest.skip(
            "needs a case-insensitive filesystem, where D/ and d/ are one entry"
        )
    archive = _tar_with_dir_modes(
        [("D/", 0o700, _DIR_MTIME), ("d/", 0o750, _SUB_MTIME)]
    )
    report = open_and_extract(io.BytesIO(archive), dest, policy=policy)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 2
    assert all(r.kept_mode is None for r in report.results)
    st = (dest / "d").stat()
    assert (st.st_mode & 0o7777, int(st.st_mtime)) == (0o750, _SUB_MTIME)


@_posix_perms
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_deferred_metadata_reaches_a_directory_through_a_locked_spelling(
    tmp_path: Path,
) -> None:
    """``a/b/c/s/u/`` is written through the archive's own ``a/b/c/s -> ../../../t``,
    so it is the directory ``t/u``. ``a/b/c`` is stored ``0o000`` and is deeper, so
    its mode is applied first. ``t/u`` still gets its stored mode and mtime: it is
    opened as ``t/u``, not through ``a/b/c``, which the owner can no longer search."""
    probe = tmp_path / "probe"
    probe.mkdir(mode=0o000)
    try:
        os.listdir(probe)
    except PermissionError:
        pass
    else:
        pytest.skip("permission checks are bypassed here (root with DAC override)")
    archive = _tar_with_dir_modes(
        [
            ("t/", 0o755, 0),
            ("a/b/c/", 0o000, _SUB_MTIME),
            ("a/b/c/s->../../../t", None, 0),
            ("a/b/c/s/u/", 0o750, _DIR_MTIME),
        ]
    )
    dest = tmp_path / "out"
    try:
        report = open_and_extract(
            io.BytesIO(archive), dest, policy=ExtractionPolicy.STANDARD
        )
        assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 4
        st = (dest / "t" / "u").stat()
        assert (st.st_mode & 0o7777, int(st.st_mtime)) == (0o750, _DIR_MTIME)
        assert (dest / "a" / "b" / "c").stat().st_mode & 0o7777 == 0o000
    finally:
        _restore_modes(dest)


@_posix_perms
def test_extract_zip_standard_keeps_execute(tmp_path: Path) -> None:
    src = tmp_path / "m.zip"
    _write_zip(src, {"x.sh": b"#!/bin/sh"}, mode=0o755)
    dest = tmp_path / "out"
    open_and_extract(src, dest, policy=ExtractionPolicy.STANDARD)
    assert (dest / "x.sh").stat().st_mode & 0o111  # execute preserved


def test_subset_selection(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    dest = tmp_path / "out"
    with open_archive(src) as r:
        results = r.extract_all(dest, members=["a.txt", "c.txt"]).results
    assert (dest / "a.txt").exists() and (dest / "c.txt").exists()
    assert not (dest / "b.txt").exists()
    assert len(results) == 2


def test_user_filter_rename(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"a"})
    dest = tmp_path / "out"

    def rename(m: ArchiveMember) -> ArchiveMember:
        return m.replace(name="renamed.txt")

    with open_archive(src) as r:
        r.extract_all(dest, filter=rename)
    assert (dest / "renamed.txt").read_bytes() == b"a"


def test_user_filter_skip(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"a", "b.txt": b"b"})
    dest = tmp_path / "out"

    def skip_b(m: ArchiveMember) -> ArchiveMember | None:
        return None if m.name == "b.txt" else m

    with open_archive(src) as r:
        report = r.extract_all(dest, filter=skip_b)
    assert (dest / "a.txt").exists()
    assert not (dest / "b.txt").exists()
    # Filter returning None is a caller-elected exclusion: no ExtractionResult (D1).
    assert [r.member.name for r in report.results] == ["a.txt"]
    assert report.results[0].status is ExtractionStatus.EXTRACTED


# ---------------------------------------------------------------------------
# Overwrite policy (task 3.x)
# ---------------------------------------------------------------------------


def test_overwrite_error(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"old")
    with pytest.raises(ExtractionError):
        open_and_extract(src, dest, overwrite=OverwritePolicy.ERROR)
    assert (dest / "a.txt").read_bytes() == b"old"  # untouched


def test_overwrite_skip(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"old")
    results = open_and_extract(src, dest, overwrite=OverwritePolicy.SKIP).results
    assert (dest / "a.txt").read_bytes() == b"old"
    assert results[0].status is ExtractionStatus.NOT_OVERWRITTEN


def test_overwrite_replace(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"old")
    open_and_extract(src, dest, overwrite=OverwritePolicy.REPLACE)
    assert (dest / "a.txt").read_bytes() == b"new"


@pytest.mark.parametrize(
    "overwrite", [OverwritePolicy.REPLACE, OverwritePolicy.ERROR, OverwritePolicy.SKIP]
)
def test_error_when_dest_is_a_file_never_deletes_it(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """A file at the dest path is a hard error under every policy — never deleted.

    Extracting must not remove a path the caller pointed at by mistake (e.g. a CLI given
    a file where a directory was meant), and must not surface a raw ``FileExistsError``.
    """
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.write_bytes(b"important data")
    with pytest.raises(ExtractionError, match="not a directory"):
        open_and_extract(src, dest, overwrite=overwrite)
    assert dest.is_file()
    assert dest.read_bytes() == b"important data"  # untouched


@pytest.mark.parametrize(
    "overwrite", [OverwritePolicy.REPLACE, OverwritePolicy.ERROR, OverwritePolicy.SKIP]
)
def test_error_when_dest_is_a_dangling_symlink_never_deletes_it(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """A dangling symlink at the dest is a hard error — the link is preserved, not removed.

    ``lexists`` (not ``exists``) sees the broken link; otherwise ``exists`` reports False
    and ``mkdir`` raises a raw ``FileExistsError`` on the occupied path.
    """
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    target = tmp_path / "nonexistent-target"
    dest.symlink_to(target)  # dangling: target does not exist
    assert dest.is_symlink() and not dest.exists()

    with pytest.raises(ExtractionError, match="not a directory"):
        open_and_extract(src, dest, overwrite=overwrite)

    assert dest.is_symlink()  # preserved, not unlinked
    assert not target.exists()  # never created behind the link


def test_dest_symlink_to_dir_is_followed_into_target(tmp_path: Path) -> None:
    """A dest symlink pointing at a real directory is followed (tar -C / unzip -d).

    Members land in the pointed-to directory and the caller's symlink is left in place;
    the dest root is trusted, unlike archive-internal symlinks.
    """
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    target = tmp_path / "real_target"
    target.mkdir()
    dest = tmp_path / "out"
    dest.symlink_to(target)

    open_and_extract(src, dest, overwrite=OverwritePolicy.REPLACE)

    assert dest.is_symlink()  # symlink preserved, not replaced with a real dir
    assert (target / "a.txt").read_bytes() == b"new"  # extracted into the target


def test_replace_symlink_no_write_through(tmp_path: Path) -> None:
    # A planted symlink at the destination path must be unlinked, not written through.
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    os.symlink(outside, dest / "a.txt")
    open_and_extract(src, dest, overwrite=OverwritePolicy.REPLACE)
    assert (dest / "a.txt").read_bytes() == b"new"
    assert not (dest / "a.txt").is_symlink()
    assert outside.read_bytes() == b"secret"  # target never written through


def test_dangling_symlink_counts_as_existing(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    os.symlink(tmp_path / "does-not-exist", dest / "a.txt")  # dangling
    with pytest.raises(ExtractionError):
        open_and_extract(src, dest, overwrite=OverwritePolicy.ERROR)


def test_replace_failure_preserves_existing_file(tmp_path: Path) -> None:
    # A mid-extraction failure under REPLACE must not clobber the existing file: FILE writes
    # land via a temp + os.replace, so the old data survives and no temp is left behind.
    src = tmp_path / "big.zip"
    _write_zip(src, {"a.txt": b"x" * 100_000})
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"OLD DATA")
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            overwrite=OverwritePolicy.REPLACE,
            limits=ExtractionLimits(max_extracted_bytes=1000),
        )
    assert (dest / "a.txt").read_bytes() == b"OLD DATA"  # untouched
    assert not list(dest.glob(".archivey-tmp-*"))  # temp cleaned up


def test_no_temp_files_after_success(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"hi", "dir/b.txt": b"bye"})
    dest = tmp_path / "out"
    open_and_extract(src, dest)
    assert not list(dest.rglob(".archivey-tmp-*"))


# ---------------------------------------------------------------------------
# OnError policy (failures-only; blocks always continue)
# ---------------------------------------------------------------------------


def test_on_error_continue_records_rejected(tmp_path: Path) -> None:
    # A member with a hostile stored name is rejected; CONTINUE keeps going.
    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("../evil.txt", b"bad")
        z.writestr("good.txt", b"good")
    dest = tmp_path / "out"
    results = open_and_extract(src, dest, on_error=OnError.CONTINUE).results
    statuses = {r.member.name: r.status for r in results}
    assert ExtractionStatus.BLOCKED in statuses.values()
    assert (dest / "good.txt").read_bytes() == b"good"


def test_on_error_stop_continues_on_policy_block(tmp_path: Path) -> None:
    # STOP governs failures only: a path-safety block is recorded and extraction
    # continues to later members (does not raise FilterRejectionError).
    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("../evil.txt", b"bad")
        z.writestr("good.txt", b"good")
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, on_error=OnError.STOP)
    statuses = {r.member.name: r.status for r in report.results}
    assert ExtractionStatus.BLOCKED in statuses.values()
    assert statuses["good.txt"] is ExtractionStatus.EXTRACTED
    assert (dest / "good.txt").read_bytes() == b"good"
    assert not any(p.name == "evil.txt" for p in dest.rglob("*"))


def test_on_error_stop_raises_on_member_failure(tmp_path: Path) -> None:
    # Genuine member failure (CRC mismatch) still raises immediately under STOP.
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    src = zip_with_flipped_cd_crc(
        tmp_path / "badcrc.zip",
        {"a.txt": b"hello", "b.txt": b"world"},
        corrupt_name="b.txt",
    )
    dest = tmp_path / "out"
    with raises_corruption_not_truncation():
        open_and_extract(src, dest, on_error=OnError.STOP)
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert not (dest / "b.txt").exists()


def test_on_error_stop_blocks_then_raises_on_failure(tmp_path: Path) -> None:
    # Mixed archive under STOP: policy blocks continue; first real failure raises.
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    src = zip_with_flipped_cd_crc(
        tmp_path / "mixed.zip",
        {
            "../evil.txt": b"bad",
            "good.txt": b"good",
            "corrupt.txt": b"payload",
        },
        corrupt_name="corrupt.txt",
    )
    dest = tmp_path / "out"
    with raises_corruption_not_truncation():
        open_and_extract(src, dest, on_error=OnError.STOP)
    assert (dest / "good.txt").read_bytes() == b"good"
    assert not (dest / "corrupt.txt").exists()
    assert not any(p.name == "evil.txt" for p in dest.rglob("*"))


# ---------------------------------------------------------------------------
# Bomb limits end-to-end (task 6.2)
# ---------------------------------------------------------------------------


def test_cumulative_bomb_halts_even_under_continue(tmp_path: Path) -> None:
    src = tmp_path / "big.zip"
    _write_zip(src, {"a.txt": b"x" * 5000, "b.txt": b"y" * 5000})
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            limits=ExtractionLimits(max_extracted_bytes=6000),
            on_error=OnError.CONTINUE,
        )


def test_zip_bomb_per_member_ratio(tmp_path: Path) -> None:
    # Highly compressible payload above the activation threshold trips the ratio.
    src = tmp_path / "bomb.zip"
    payload = b"\x00" * (8 * 1024 * 1024)  # 8 MiB of zeros -> tiny compressed
    _write_zip(src, {"bomb.bin": payload})
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            limits=ExtractionLimits(max_ratio=10.0, ratio_activation_threshold=1024),
        )


def _zero_zip(tmp_path: Path) -> Path:
    """A ZIP whose ``bomb.bin`` (8 MiB of zeros) is far over 10:1, next to a small file."""
    src = tmp_path / "bomb.zip"
    _write_zip(src, {"small.txt": b"hello", "bomb.bin": b"\x00" * (8 * 2**20)})
    return src


_TIGHT_RATIO = ExtractionLimits(max_ratio=10.0, ratio_activation_threshold=1024)


def test_zip_bomb_member_is_refused_before_any_byte_is_written(tmp_path: Path) -> None:
    # Its recorded size decides the verdict, so nothing of it is decoded or written;
    # under on_error="continue" it fails alone and the other member is extracted.
    dest = tmp_path / "out"
    written: list[int] = []
    report = open_and_extract(
        _zero_zip(tmp_path),
        dest,
        limits=_TIGHT_RATIO,
        on_error=OnError.CONTINUE,
        on_progress=lambda p: written.append(p.bytes_written),
    )
    by_name = {r.member.name: r for r in report.results}
    bomb = by_name["bomb.bin"]
    assert bomb.status is ExtractionStatus.FAILED
    assert isinstance(bomb.error, ResourceLimitError)
    assert "from recorded sizes" in str(bomb.error)
    assert by_name["small.txt"].status is ExtractionStatus.EXTRACTED
    assert max(written) == len(b"hello")
    assert not (dest / "bomb.bin").exists()


_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _bomb_7z(tmp_path: Path) -> tuple[Path, str, str]:
    exe = shutil.which("7z")
    if exe is None:
        pytest.skip("7z not installed")
    work = tmp_path / "in"
    work.mkdir()
    (work / "small.txt").write_bytes(b"hello")
    (work / "bomb.bin").write_bytes(b"\x00" * (8 * 2**20))
    subprocess.run(
        [exe, "a", "-bd", "-bso0", "-ms=off", "bomb.7z", "small.txt", "bomb.bin"],
        cwd=work,
        check=True,
    )
    return work / "bomb.7z", "bomb.bin", "small.txt"


def _bomb_rar(tmp_path: Path) -> tuple[Path, str, str]:
    # Committed, so the leg runs wherever unrar is installed (no rar writer needed).
    # prefix.bin records 1 MiB from 91 bytes. unrar reads tail.txt.
    if (refusal := binary_refusal("unrar")) is not None:
        pytest.skip(refusal)
    return _RAR_FIXTURES / "seek_respawn_solid__.rar", "prefix.bin", "tail.txt"


@pytest.mark.parametrize("build", [_bomb_7z, _bomb_rar], ids=["7z", "rar"])
def test_7z_and_rar_bomb_members_are_refused_before_any_byte_is_written(
    tmp_path: Path, build
) -> None:
    src, bomb, small = build(tmp_path)
    written: list[int] = []
    report = open_and_extract(
        src,
        tmp_path / "out",
        limits=_TIGHT_RATIO,
        on_error=OnError.CONTINUE,
        on_progress=lambda p: written.append(p.bytes_written),
    )
    by_name = {r.member.name: r for r in report.results}
    assert "from recorded sizes" in str(by_name[bomb].error)
    assert by_name[small].status is ExtractionStatus.EXTRACTED
    assert max(written) == by_name[small].member.size


def test_orphan_hardlink_source_is_refused_from_its_recorded_size(
    tmp_path: Path,
) -> None:
    # Extracting only a hard link writes its excluded source's content at the link's
    # path, so the source's recorded sizes decide (8 bytes from 5 here).
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError, match="from recorded sizes"):
        open_and_extract(
            _RAR_FIXTURES / "hardlinks_solid__.rar",
            dest,
            members=["hardlink_to_file2.txt"],
            limits=ExtractionLimits(max_ratio=1.0, ratio_activation_threshold=1),
        )
    assert not (dest / "hardlink_to_file2.txt").exists()


def test_recorded_size_check_runs_on_a_dry_run(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError, match="from recorded sizes"):
        open_and_extract(_zero_zip(tmp_path), dest, limits=_TIGHT_RATIO, dry_run=True)
    assert not dest.exists()


def test_recorded_size_check_skips_members_the_run_does_not_decode(
    tmp_path: Path,
) -> None:
    # A member left out by members=, dropped by the filter, or skipped over an existing
    # file is never decoded, so neither check refuses it.
    src = _zero_zip(tmp_path)
    report = open_and_extract(
        src, tmp_path / "a", limits=_TIGHT_RATIO, members=["small.txt"]
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED]
    report = open_and_extract(
        src,
        tmp_path / "b",
        limits=_TIGHT_RATIO,
        filter=lambda m: None if m.name == "bomb.bin" else m,
    )
    assert [r.member.name for r in report.results] == ["small.txt"]
    dest = tmp_path / "c"
    dest.mkdir()
    (dest / "bomb.bin").write_bytes(b"kept")
    report = open_and_extract(
        src, dest, limits=_TIGHT_RATIO, overwrite=OverwritePolicy.SKIP
    )
    assert {r.member.name: r.status for r in report.results} == {
        "small.txt": ExtractionStatus.EXTRACTED,
        "bomb.bin": ExtractionStatus.NOT_OVERWRITTEN,
    }
    assert (dest / "bomb.bin").read_bytes() == b"kept"


def test_forged_recorded_size_fails_only_its_member(tmp_path: Path) -> None:
    # A member whose recorded sizes overstate its data fails alone; the intact member
    # after it is still extracted and the report comes back. An up-front archive-wide
    # check on the recorded sizes stopped the whole run here.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.bin", b"\x01" * (2 * 2**20), compress_type=zipfile.ZIP_STORED)
        z.writestr("bomb.bin", b"hello", compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("c.txt", b"intact", compress_type=zipfile.ZIP_STORED)
    raw = bytearray(buf.getvalue())
    with zipfile.ZipFile(io.BytesIO(bytes(raw))) as z:
        local = z.getinfo("bomb.bin").header_offset
    # Compressed 1 MiB, uncompressed 8 MiB, in the local header and the directory.
    struct.pack_into("<II", raw, local + 18, 2**20, 8 * 2**20)
    entry = raw.index(b"PK\x01\x02")
    while raw[entry + 46 : entry + 54] != b"bomb.bin":
        entry = raw.index(b"PK\x01\x02", entry + 4)
    struct.pack_into("<II", raw, entry + 20, 2**20, 8 * 2**20)
    src = tmp_path / "forged.zip"
    src.write_bytes(bytes(raw))
    dest = tmp_path / "out"
    report = open_and_extract(
        src,
        dest,
        limits=ExtractionLimits(max_ratio=1.2, ratio_activation_threshold=1024),
        on_error=OnError.CONTINUE,
    )
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses == {
        "a.bin": ExtractionStatus.EXTRACTED,
        "bomb.bin": ExtractionStatus.FAILED,
        "c.txt": ExtractionStatus.EXTRACTED,
    }
    assert (dest / "c.txt").read_bytes() == b"intact"


def test_entry_count_bomb(tmp_path: Path) -> None:
    src = tmp_path / "many.zip"
    _write_zip(src, {f"f{i}.txt": b"" for i in range(50)})
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            limits=ExtractionLimits(max_entries=10),
            on_error=OnError.CONTINUE,
        )


def test_selector_skips_do_not_count_toward_max_entries(tmp_path: Path) -> None:
    # Only members actually written count toward max_entries (resolved 2026-07 decision):
    # a member excluded by the selector creates nothing on disk, so a tiny cap survives a
    # huge archive when only one member is selected.
    src = tmp_path / "many.zip"
    _write_zip(src, {f"f{i}.txt": b"x" for i in range(20)})
    dest = tmp_path / "out"
    with open_archive(src) as r:
        results = r.extract_all(
            dest, members=["f0.txt"], limits=ExtractionLimits(max_entries=1)
        ).results
    assert (dest / "f0.txt").read_bytes() == b"x"
    assert len(results) == 1


def test_filter_skips_do_not_count_toward_max_entries(tmp_path: Path) -> None:
    # A member the user filter drops (returns None) likewise creates nothing on disk and
    # must not consume the entry-count budget.
    src = tmp_path / "many.zip"
    _write_zip(src, {f"f{i}.txt": b"x" for i in range(20)})
    dest = tmp_path / "out"

    def keep_one(m: ArchiveMember) -> ArchiveMember | None:
        return m if m.name == "f0.txt" else None

    with open_archive(src) as r:
        results = r.extract_all(
            dest, filter=keep_one, limits=ExtractionLimits(max_entries=1)
        ).results
    assert (dest / "f0.txt").read_bytes() == b"x"
    assert [res.status for res in results] == [ExtractionStatus.EXTRACTED]


def test_rejected_members_do_not_count_toward_max_entries(tmp_path: Path) -> None:
    # A member rejected by the universal safety check writes nothing, so it must not
    # consume the entry-count budget either: two good files + one hostile member with
    # max_entries=2 completes under CONTINUE (before the fix the rejected member counted
    # and tripped the guard on the second good file).
    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("good1.txt", b"a")
        z.writestr("../evil.txt", b"bad")
        z.writestr("good2.txt", b"b")
    dest = tmp_path / "out"
    with open_archive(src) as r:
        results = r.extract_all(
            dest, limits=ExtractionLimits(max_entries=2), on_error=OnError.CONTINUE
        ).results
    statuses = {res.member.name: res.status for res in results}
    assert statuses["good1.txt"] is ExtractionStatus.EXTRACTED
    assert statuses["good2.txt"] is ExtractionStatus.EXTRACTED
    assert ExtractionStatus.BLOCKED in statuses.values()


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


def test_on_progress_called_per_member(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"a", "b.txt": b"b"})
    dest = tmp_path / "out"
    seen: list[str] = []
    open_and_extract(src, dest, on_progress=lambda p: seen.append(p.member.name))
    assert set(seen) == {"a.txt", "b.txt"}


def test_progress_totals_respect_selector(tmp_path: Path) -> None:
    # Totals cover what the call will actually attempt: with a selector, members_total
    # and total_bytes_estimated count only the selected members, and members_done can
    # reach members_total.
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"aaaa", "b.txt": b"b" * 100, "c.txt": b"cc"})
    dest = tmp_path / "out"
    progress = []
    with open_archive(src) as r:
        r.extract_all(dest, members=["a.txt", "c.txt"], on_progress=progress.append)
    last = progress[-1]
    assert last.members_total == 2
    assert last.members_done == 2
    assert last.total_bytes_estimated == 6  # a.txt (4) + c.txt (2); b.txt excluded


def test_progress_counts_filter_skipped_members_as_done(tmp_path: Path) -> None:
    # A user-filter skip is still a processed member: members_done must reach
    # members_total at the end (the filter cannot be pre-applied to the totals).
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    dest = tmp_path / "out"
    progress = []
    with open_archive(src) as r:
        r.extract_all(
            dest,
            filter=lambda m: None if m.name == "b.txt" else m,
            on_progress=progress.append,
        )
    last = progress[-1]
    assert last.members_total == 3
    assert last.members_done == 3
    assert not (dest / "b.txt").exists()


def test_on_progress_large_file_emits_intra_member(tmp_path: Path) -> None:
    # A FILE larger than one copy chunk must produce multiple callbacks with
    # non-decreasing member_bytes_written, ending at the member size.
    payload = b"x" * (2 * _CHUNK + 100)
    src = tmp_path / "big.zip"
    _write_zip(src, {"big.bin": payload})
    dest = tmp_path / "out"
    reports: list = []
    open_and_extract(src, dest, on_progress=reports.append)

    for_member = [p for p in reports if p.member.name == "big.bin"]
    assert len(for_member) > 1
    mbw = [p.member_bytes_written for p in for_member]
    assert mbw == sorted(mbw)
    assert mbw[-1] == len(payload)
    # Intra-member reports keep members_done at the pre-completion count; the
    # terminal report advances it.
    assert for_member[0].members_done == 0
    assert for_member[-1].members_done == 1
    assert (dest / "big.bin").read_bytes() == payload


def test_on_progress_sub_chunk_file_single_callback(tmp_path: Path) -> None:
    src = tmp_path / "a.zip"
    _write_zip(src, {"small.txt": b"hello"})
    dest = tmp_path / "out"
    reports: list = []
    open_and_extract(src, dest, on_progress=reports.append)
    assert len(reports) == 1
    assert reports[0].member_bytes_written == 5
    assert reports[0].member.name == "small.txt"


def test_on_progress_dir_symlink_hardlink_zero_member_bytes(tmp_path: Path) -> None:
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("dir", "d/", None),
                ("file", "d/f.txt", b"data"),
                ("sym", "link", "d/f.txt"),
                ("hard", "hard.txt", "d/f.txt"),
            ]
        )
    )
    dest = tmp_path / "out"
    reports: list = []
    open_and_extract(src, dest, on_progress=reports.append)

    dir_reports = [p for p in reports if p.member.type == MemberType.DIRECTORY]
    assert len(dir_reports) == 1
    assert dir_reports[0].member_bytes_written == 0

    sym_reports = [p for p in reports if p.member.type == MemberType.SYMLINK]
    assert len(sym_reports) == 1
    assert sym_reports[0].member_bytes_written == 0

    hard_reports = [p for p in reports if p.member.type == MemberType.HARDLINK]
    assert len(hard_reports) == 1
    assert hard_reports[0].member_bytes_written == 0

    file_reports = [p for p in reports if p.member.is_file]
    assert len(file_reports) == 1
    assert file_reports[0].member_bytes_written == 4


def test_on_progress_unknown_size_terminal_equals_observed(tmp_path: Path) -> None:
    payload = b"z" * 12345
    src = tmp_path / "blob.gz"
    src.write_bytes(gzip.compress(payload))
    dest = tmp_path / "out"
    reports: list = []
    with open_archive(src) as r:
        assert r.members()[0].size is None
        r.extract_all(dest, on_progress=reports.append)

    assert len(reports) >= 1
    terminal = reports[-1]
    assert (
        terminal.member.size is None
        or terminal.member_bytes_written == terminal.member.size
    )
    assert terminal.member_bytes_written == len(payload)
    assert (dest / "blob").read_bytes() == payload


def test_on_progress_none_leaves_byte_totals_unchanged(tmp_path: Path) -> None:
    # Zero-cost path: no callback must not change written bytes or bomb accounting.
    payload = b"y" * (_CHUNK + 50)
    src = tmp_path / "a.zip"
    _write_zip(src, {"a.txt": payload, "b.txt": b"bb"})
    dest = tmp_path / "out"
    results = open_and_extract(src, dest).results
    assert {r.status for r in results} == {ExtractionStatus.EXTRACTED}
    assert (dest / "a.txt").read_bytes() == payload
    assert (dest / "b.txt").read_bytes() == b"bb"
    # Ratio/limits still enforced when on_progress is unset.
    dest2 = tmp_path / "out2"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest2,
            limits=ExtractionLimits(max_extracted_bytes=100),
        )


def test_extract_from_non_seekable_pipe_in_streaming_mode(tmp_path: Path) -> None:
    # Extraction is a single forward pass, so a pipe opened with streaming=True
    # extracts in full: it needs no random access.
    from tests.streams_util import NonSeekableBytesIO

    raw = _tar_bytes(
        [("file", "a.txt", b"hello"), ("file", "b.txt", b"world")], mode="w:gz"
    )
    dest = tmp_path / "out"
    results = open_and_extract(NonSeekableBytesIO(raw), dest, streaming=True).results
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "b.txt").read_bytes() == b"world"
    assert {r.status for r in results} == {ExtractionStatus.EXTRACTED}


# ---------------------------------------------------------------------------
# TAR symlinks (tasks 3.4, 4.5)
# ---------------------------------------------------------------------------


def test_tar_symlink_created(tmp_path: Path) -> None:
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("file", "file.txt", b"data"), ("sym", "link", "file.txt")])
    )
    dest = tmp_path / "out"
    open_and_extract(src, dest)
    link = dest / "link"
    assert link.is_symlink()
    assert os.readlink(link) == "file.txt"
    assert link.read_bytes() == b"data"


def test_tar_symlink_dangling_to_filtered_target(tmp_path: Path) -> None:
    # A symlink is target-independent: it is created even when its target is excluded,
    # and may dangle. No copy, no error.
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("file", "file.txt", b"data"), ("sym", "link", "file.txt")])
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        r.extract_all(dest, members=["link"])  # exclude file.txt
    link = dest / "link"
    assert link.is_symlink()
    assert not (dest / "file.txt").exists()
    assert not link.exists()  # dangles (target excluded)


def test_tar_symlink_escape_rejected(tmp_path: Path) -> None:
    src = tmp_path / "a.tar"
    src.write_bytes(_tar_bytes([("sym", "evil", "../../etc/passwd")]))
    dest = tmp_path / "out"
    report = open_and_extract(src, dest)  # default STOP; blocks always continue
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message == "Symlink target escapes destination"
    assert not (dest / "evil").exists()


def test_tar_symlink_escape_continue_records_rejected(tmp_path: Path) -> None:
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("sym", "evil", "../../etc/passwd"), ("file", "ok.txt", b"ok")])
    )
    dest = tmp_path / "out"
    results = open_and_extract(src, dest, on_error=OnError.CONTINUE).results
    statuses = {r.member.name: r.status for r in results}
    assert statuses["evil"] is ExtractionStatus.BLOCKED
    assert (dest / "ok.txt").read_bytes() == b"ok"


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize(
    "links",
    [
        [("d", "d")],
        [("a", "b"), ("b", "a")],
        [("a", "b"), ("b", "c"), ("c", "a")],
        [("x/a", "../y/b"), ("y/b", "../x/a")],
    ],
    ids=["self", "pair", "triple", "across-dirs"],
)
def test_tar_symlink_closing_a_loop_is_rejected(
    tmp_path: Path, links: list[tuple[str, str]]
) -> None:
    # The link that closes the loop is refused, on every Python version: Path.resolve()
    # raises on a loop before 3.13 and returns a path from 3.13, so the check must
    # not depend on it raising.
    src = tmp_path / "a.tar"
    src.write_bytes(_tar_bytes([("sym", name, target) for name, target in links]))
    dest = tmp_path / "out"
    results = open_and_extract(src, dest, on_error=OnError.CONTINUE).results
    statuses = {r.member.name: r.status for r in results}
    closing = links[-1][0]
    assert statuses == {
        name: ExtractionStatus.BLOCKED
        if name == closing
        else ExtractionStatus.EXTRACTED
        for name, _ in links
    }
    error = next(r.error for r in results if r.member.name == closing)
    assert isinstance(error, FilterRejectionError)
    # Named as a loop, not as an escape: every target here is inside dest.
    assert error.message == "Symlink target is part of a symlink loop"
    assert not os.path.lexists(dest / closing)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
@pytest.mark.parametrize("source", ["directory", "tar"])
def test_extracting_under_a_symlink_loop_raises_eloop(
    tmp_path: Path, source: str, dry_run: bool
) -> None:
    # A dest below a looping link is refused with the OSError mkdir raises, for every
    # backend and on every Python version. Before 3.13 Path.resolve() raised
    # RuntimeError there, and the directory backend's into-itself check let it out.
    if source == "directory":
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.txt").write_bytes(b"x")
    else:
        src = tmp_path / "a.tar"
        src.write_bytes(_tar_bytes([("file", "f.txt", b"x")]))
    os.symlink("loop", tmp_path / "loop")
    with open_archive(src) as reader, pytest.raises(OSError) as info:
        reader.extract_all(tmp_path / "loop" / "out", dry_run=dry_run)
    assert info.value.errno == errno.ELOOP
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([src.name, "loop"])


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
@pytest.mark.parametrize("source", ["directory", "tar"])
def test_extracting_into_a_self_looping_symlink_raises_extraction_error(
    tmp_path: Path, source: str, dry_run: bool
) -> None:
    # A dest that is itself a looping link exists and is not a directory, so every
    # backend refuses it as it refuses a regular file there. The directory backend's
    # into-itself check must not answer first with the loop's OSError.
    if source == "directory":
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.txt").write_bytes(b"x")
    else:
        src = tmp_path / "a.tar"
        src.write_bytes(_tar_bytes([("file", "f.txt", b"x")]))
    os.symlink("loop", tmp_path / "loop")
    with (
        open_archive(src) as reader,
        pytest.raises(ExtractionError, match="exists and is not a directory"),
    ):
        reader.extract_all(tmp_path / "loop", dry_run=dry_run)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([src.name, "loop"])


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("shape", ["self", "ancestor"])
def test_resolve_or_raise_on_loop_raises_eloop(tmp_path: Path, shape: str) -> None:
    # One OSError on every Python version, naming the path asked about: before 3.13
    # resolve() raises RuntimeError itself, from 3.13 only the stat sees the loop.
    os.symlink("loop", tmp_path / "loop")
    path = tmp_path / "loop" if shape == "self" else tmp_path / "loop" / "x" / "y"
    with pytest.raises(OSError) as info:
        resolve_or_raise_on_loop(path)
    assert type(info.value) is OSError
    assert info.value.errno == errno.ELOOP
    assert info.value.filename == str(path)


def test_resolve_or_raise_on_loop_keeps_a_missing_component(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    path = tmp_path / "d" / "missing" / "f"
    assert resolve_or_raise_on_loop(path) == tmp_path.resolve() / "d" / "missing" / "f"


def _link_chain_past_path_max(root: Path) -> None:
    """``root/up``: links whose expansion is longer than PATH_MAX, leading to
    ``root``'s parent."""
    component = "d" * 200
    path_max = os.pathconf(root, "PC_PATH_MAX")
    depth = path_max // len(component) + 1
    here = root
    for _ in range(depth):
        (here / component).mkdir()
        os.symlink(component, here / "s")
        here = here / "s"  # The short spelling, which stays under PATH_MAX.
    os.symlink(os.path.join(*[".."] * (depth + 1)), here / "x")
    os.symlink(os.path.join(*["s"] * depth, "x", ".."), root / "up")


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_resolve_or_raise_on_loop_raises_when_a_component_cannot_be_looked_up(
    tmp_path: Path,
) -> None:
    # os.path.realpath keeps the long name and drops it again at the "..", so it
    # gives a path inside tmp_path, while the kernel follows `up` one link at a time
    # to tmp_path's parent.
    _link_chain_past_path_max(tmp_path)
    assert os.path.realpath(tmp_path / "up").startswith(str(tmp_path.resolve()))
    with pytest.raises(OSError) as info:
        resolve_or_raise_on_loop(tmp_path / "up")
    assert info.value.errno == errno.ENAMETOOLONG
    assert info.value.filename == str(tmp_path / "up")


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_resolve_or_raise_on_loop_swallows_enoent_from_the_stat(
    tmp_path: Path,
) -> None:
    # A dangling link inside dest must resolve to its target name, not count as a loop
    # (an escape, at the call sites).
    os.symlink("nowhere", tmp_path / "dangling")
    assert resolve_or_raise_on_loop(tmp_path / "dangling") == (
        tmp_path.resolve() / "nowhere"
    )


def test_windows_resolution_treats_winerror_1921_as_a_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows reports a loop as ERROR_CANT_RESOLVE_FILENAME, not ELOOP. Raised here by
    # a stubbed stat so the branch runs on every platform.
    def stat(self: Path, **kwargs: object) -> os.stat_result:
        exc = OSError(errno.EINVAL, "The name of the file cannot be resolved")
        exc.winerror = 1921  # type: ignore[attr-defined]
        raise exc

    # resolve() is stubbed to return the path as 3.13+ does on a loop: before 3.13
    # resolve() calls stat itself and would turn the stub's error into RuntimeError,
    # so the stat branch would never run.
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(Path, "stat", stat)
    path = tmp_path / "x"
    with pytest.raises(OSError) as info:
        _resolve_with_pathlib(path)
    assert type(info.value) is OSError
    assert info.value.errno == errno.ELOOP
    assert info.value.filename == str(path)
    # The Windows code stays visible on the chained original.
    assert getattr(info.value.__cause__, "winerror", None) == 1921


# ---------------------------------------------------------------------------
# Chained-symlink attack (task 5a.4, ported from the DEV oracle suite)
#
# The classic escape: member 1 plants a directory symlink `sub` that points OUTSIDE the
# destination, then member 2 is written "through" it as `sub/<payload>`, so a naive
# extractor lands the payload outside dest. archivey blocks this on two layers, and both
# the SYMLINK-payload and FILE-payload variants of member 2 must be neutralized:
#   * the escaping parent symlink is rejected up front by the universal check
#     ("Symlink target escapes destination"), so it is never planted, and
#   * the universal check re-resolves each member's PARENT directory on the real
#     filesystem, so a payload written through an already-planted hostile parent symlink
#     is rejected ("Member resolves outside the destination root") before any bytes are
#     written outside dest.
# Both are FilterRejectionError; the message says which layer caught the member.
# ---------------------------------------------------------------------------


def test_chained_symlink_attack_symlink_payload_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    src = tmp_path / "attack.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("sym", "sub", str(outside)),  # parent symlink escaping dest
                ("sym", "sub/leak", "target"),  # SYMLINK payload written through it
            ]
        )
    )
    dest = tmp_path / "out"
    report = open_and_extract(src, dest)  # default STOP; blocks always continue
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses["sub"] is ExtractionStatus.BLOCKED
    sub_error = next(r.error for r in report.results if r.member.name == "sub")
    assert isinstance(sub_error, FilterRejectionError)
    # The absolute target is a drive path on Windows, refused by that rule first.
    assert sub_error.message == (
        "Symlink target is a Windows drive or UNC path"
        if os.name == "nt"
        else "Symlink target escapes destination"
    )
    # Parent escape never planted, so the payload symlink resolves inside dest.
    assert list(outside.iterdir()) == []  # nothing leaked outside the destination
    assert not (dest / "sub").is_symlink()


def test_chained_symlink_attack_file_payload_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    src = tmp_path / "attack.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("sym", "sub", str(outside)),  # parent symlink escaping dest
                ("file", "sub/leak.txt", b"pwned"),  # FILE payload written through it
            ]
        )
    )
    dest = tmp_path / "out"
    # Under CONTINUE the escaping parent symlink is rejected (never planted) while the run
    # proceeds, proving the FILE payload cannot follow it out of dest.
    results = open_and_extract(src, dest, on_error=OnError.CONTINUE).results
    statuses = {r.member.name: r.status for r in results}
    assert statuses["sub"] is ExtractionStatus.BLOCKED
    assert not (outside / "leak.txt").exists()
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(
    os.name != "posix",
    reason="directory symlinks / os.symlink semantics are POSIX here",
)
def test_file_payload_through_preexisting_parent_symlink_rejected(
    tmp_path: Path,
) -> None:
    # The runtime layer: a hostile symlink already sits at the destination (e.g. planted by
    # a prior partial run). The universal check resolves the member's parent on disk, so a
    # FILE written through it is rejected before any bytes escape.
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "out"
    dest.mkdir()
    os.symlink(outside, dest / "sub", target_is_directory=True)
    src = tmp_path / "a.tar"
    src.write_bytes(_tar_bytes([("file", "sub/leak.txt", b"pwned")]))
    report = open_and_extract(src, dest)  # default STOP; blocks always continue
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message == "Member resolves outside the destination root"
    assert not (outside / "leak.txt").exists()


@pytest.mark.skipif(
    os.name != "posix",
    reason="directory symlinks / os.symlink semantics are POSIX here",
)
def test_symlink_payload_through_preexisting_parent_symlink_rejected(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "out"
    dest.mkdir()
    os.symlink(outside, dest / "sub", target_is_directory=True)
    src = tmp_path / "a.tar"
    src.write_bytes(_tar_bytes([("sym", "sub/leak", "x")]))
    report = open_and_extract(src, dest)  # default STOP; blocks always continue
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message == "Member resolves outside the destination root"
    assert not (outside / "leak").exists()


# ---------------------------------------------------------------------------
# TAR hardlinks (tasks 4.1, 4.3)
# ---------------------------------------------------------------------------


def test_tar_hardlink_shares_inode(tmp_path: Path) -> None:
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("file", "file.txt", b"data"), ("hard", "hard.txt", "file.txt")])
    )
    dest = tmp_path / "out"
    open_and_extract(src, dest)
    assert (dest / "file.txt").read_bytes() == b"data"
    assert (dest / "hard.txt").read_bytes() == b"data"
    assert os.path.samefile(dest / "file.txt", dest / "hard.txt")


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("second_link", "overwrite"),
    [
        # A tar that lists the same hard link twice: the second copy supersedes the
        # first, whose parked name is already the same file as the source.
        ("h", OverwritePolicy.ERROR),
        # Under REPLACE, STANDARD folds ``H`` onto ``h``, a link to the same file.
        ("H", OverwritePolicy.REPLACE),
    ],
)
def test_link_onto_a_name_of_the_same_file_leaves_no_temp(
    tmp_path: Path, streaming: bool, second_link: str, overwrite: OverwritePolicy
) -> None:
    # POSIX rename(2) does nothing, and reports success, when the temp link and the
    # destination are already names of the same file. The temp name then stayed in the
    # destination as a stray ``.archivey-tmp-*`` entry.
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [("file", "f", b"data"), ("hard", "h", "f"), ("hard", second_link, "f")]
        )
    )
    dest = tmp_path / "out"

    report = open_and_extract(src, dest, streaming=streaming, overwrite=overwrite)

    assert report.results[-1].status is ExtractionStatus.EXTRACTED
    assert sorted(p.name for p in dest.iterdir()) == ["f", "h"]
    assert (dest / "h").read_bytes() == b"data"
    assert os.path.samefile(dest / "f", dest / "h")


def test_a_temp_that_cannot_be_removed_does_not_fail_the_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The swap removes the temp name after ``os.replace``. When that unlink fails (on
    # Windows, a scanner holding the file open), the member is already in place, so the
    # failure must not turn a completed write into FAILED.
    src = tmp_path / "a.tar"
    src.write_bytes(_tar_bytes([("file", "f", b"AAA")]))
    dest = tmp_path / "out"
    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        if os.path.basename(path).startswith(".archivey-tmp-"):
            raise PermissionError(errno.EACCES, "held open", str(path))
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    with open_archive(src) as r:
        report = r.extract_all(dest)

    assert [res.status for res in report.results] == [ExtractionStatus.EXTRACTED]
    assert (dest / "f").read_bytes() == b"AAA"


def test_tar_hardlink_orphan_recovered_seekable(tmp_path: Path) -> None:
    # A filter excludes the source but keeps the link; a seekable source recovers the
    # content in a second pass, writing it to the link path (source name never created).
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("file", "file.txt", b"data"), ("hard", "hard.txt", "file.txt")])
    )
    dest = tmp_path / "out"

    def drop_source(m: ArchiveMember) -> ArchiveMember | None:
        return None if m.name == "file.txt" else m

    with open_archive(src) as r:
        results = r.extract_all(dest, filter=drop_source).results
    assert (dest / "hard.txt").read_bytes() == b"data"
    assert not (dest / "file.txt").exists()
    assert [r.status for r in results] == [ExtractionStatus.EXTRACTED]


@pytest.mark.parametrize("linked", [False, True], ids=["written", "linked"])
def test_orphan_written_file_blocks_a_later_orphan_under_it(
    tmp_path: Path, linked: bool
) -> None:
    # The second pass records what it writes as the run's own, as the main pass does:
    # a later orphan that needs that file as a parent directory gets the same error
    # naming the file, not a bare FileExistsError. With ``linked``, an earlier link
    # ``x`` carries the content and ``a`` is linked to it, so ``a`` is recorded by the
    # link path rather than the write path.
    first_links = [("hard", "x", "s1")] if linked else []
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("file", "s1", b"one"),
                ("file", "s2", b"two"),
                *first_links,
                ("hard", "a", "s1"),
                ("hard", "a/b", "s2"),
            ]
        )
    )

    def drop_sources(m: ArchiveMember) -> ArchiveMember | None:
        return None if m.name in ("s1", "s2") else m

    with open_archive(src) as r:
        results = r.extract_all(
            tmp_path / "out", filter=drop_sources, on_error=OnError.CONTINUE
        ).results
    by_name = {res.member.name: res for res in results}
    assert by_name["a"].status is ExtractionStatus.EXTRACTED
    failed = by_name["a/b"]
    assert failed.status is ExtractionStatus.FAILED
    assert isinstance(failed.error, ExtractionError)
    assert "'a' is a non-directory already extracted" in str(failed.error)


def test_tar_hardlink_orphan_forward_only_onerror(tmp_path: Path) -> None:
    from tests.streams_util import NonSeekableBytesIO

    raw = _tar_bytes([("file", "file.txt", b"data"), ("hard", "hard.txt", "file.txt")])

    def drop_source(m: ArchiveMember) -> ArchiveMember | None:
        return None if m.name == "file.txt" else m

    # STOP: raises on the unrecoverable orphan.
    dest = tmp_path / "out_stop"
    with (
        open_archive(NonSeekableBytesIO(raw), streaming=True) as r,
        pytest.raises(ExtractionError),
    ):
        r.extract_all(dest, filter=drop_source)

    # CONTINUE: records FAILED, does not raise.
    dest2 = tmp_path / "out_continue"
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        results = r.extract_all(
            dest2, filter=drop_source, on_error=OnError.CONTINUE
        ).results
    statuses = {r.member.name: r.status for r in results}
    assert statuses["hard.txt"] is ExtractionStatus.FAILED
    assert not (dest2 / "hard.txt").exists()


# ---------------------------------------------------------------------------
# Seekable + non-seekable compressed TAR (tasks 5.3, 6.3)
# ---------------------------------------------------------------------------


def test_seekable_targz_extract(tmp_path: Path) -> None:
    src = tmp_path / "a.tar.gz"
    src.write_bytes(
        _tar_bytes([("file", "a.txt", b"hello"), ("dir", "d", None)], mode="w:gz")
    )
    dest = tmp_path / "out"
    open_and_extract(src, dest)
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "d").is_dir()


def test_seekable_targz_archive_wide_ratio(tmp_path: Path) -> None:
    # A small .tar.gz whose decompressed output far exceeds max_ratio * file_size trips
    # the archive-wide ratio (member compressed_size is unknown for TAR).
    src = tmp_path / "bomb.tar.gz"
    payload = b"\x00" * (4 * 1024 * 1024)
    src.write_bytes(_tar_bytes([("file", "z.bin", payload)], mode="w:gz"))
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            limits=ExtractionLimits(max_ratio=5.0, ratio_activation_threshold=1024),
        )


def test_non_seekable_targz_extract(tmp_path: Path) -> None:
    from tests.streams_util import NonSeekableBytesIO

    raw = _tar_bytes(
        [("file", "a.txt", b"hello"), ("file", "b.txt", b"world")], mode="w:gz"
    )
    dest = tmp_path / "out"
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        r.extract_all(dest)
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "b.txt").read_bytes() == b"world"


def test_cross_device_hardlink_reuses_sibling(tmp_path: Path, monkeypatch) -> None:
    # B->A lands "cross-device" (os.link against A fails EXDEV -> copy). A later C->A on
    # the same device as B is created with os.link(B, C), reusing the sibling copy.
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("file", "A.txt", b"payload"),
                ("hard", "B.txt", "A.txt"),
                ("hard", "C.txt", "A.txt"),
            ]
        )
    )
    dest = tmp_path / "out"
    real_link = os.link

    def fake_link(source, target, *a, **k):
        # Every attempt against A's own copy is "cross-device"; links to B's copy work.
        if os.fspath(source).endswith("A.txt"):
            raise OSError(errno.EXDEV, "cross-device")
        return real_link(source, target, *a, **k)

    monkeypatch.setattr(os, "link", fake_link)
    open_and_extract(src, dest)

    assert (dest / "B.txt").read_bytes() == b"payload"
    assert (dest / "C.txt").read_bytes() == b"payload"
    assert os.path.samefile(dest / "B.txt", dest / "C.txt")  # C linked to B's copy
    assert not os.path.samefile(dest / "A.txt", dest / "B.txt")  # B is a separate copy


def test_cross_device_hardlink_copy_counts_toward_max_extracted_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The EXDEV fallback writes a full copy, so the byte cap has to see it.

    Every link fails cross-device here, so each of the four links is a 1000-byte copy:
    5000 bytes land on disk from a member that decodes to 1000. A 2500-byte cap has to
    stop that, where before it saw only the source's own 1000.
    """
    payload = os.urandom(1000)
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [("file", "A.bin", payload)]
            + [("hard", f"L{i}.bin", "A.bin") for i in range(4)]
        )
    )

    def always_exdev(source: object, target: object, *a: object, **k: object) -> None:
        raise OSError(errno.EXDEV, "cross-device")

    monkeypatch.setattr(os, "link", always_exdev)
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError, match="max_extracted_bytes=2500"):
        open_and_extract(src, dest, limits=ExtractionLimits(max_extracted_bytes=2500))

    # Under the cap, every copy still lands, byte for byte.
    dest2 = tmp_path / "out2"
    open_and_extract(src, dest2, limits=ExtractionLimits(max_extracted_bytes=5000))
    for i in range(4):
        assert (dest2 / f"L{i}.bin").read_bytes() == payload


def test_copied_bytes_count_toward_the_byte_cap_but_not_the_ratio() -> None:
    """Nothing decompressed a cross-device copy, so only the byte cap sees it.

    Whether the copy happens depends on the destination's mount points, not on the
    archive, so letting it trip the archive-wide ratio would blame the archive.
    """
    source = SimpleNamespace(compressed_source_size=10, compressed_bytes_consumed=10)
    t = BombTracker(
        max_bytes=5000,
        max_ratio=2.0,
        ratio_activation_threshold=0,
        source=source,  # type: ignore[arg-type]
    )
    t.start_member(_member("a"))
    t.count(15)  # decoded: ratio 1.5, under the limit
    t.count_copy(4000, at_link_limit=False)  # copied: would be ratio 400 if counted
    t.count(1)  # the next decoded chunk re-checks the ratio on decoded bytes only
    assert t.total_bytes == 4016
    with pytest.raises(AlwaysStopResourceLimitError, match="max_extracted_bytes"):
        t.count_copy(1000, at_link_limit=False)


def test_link_limit_copies_count_toward_the_archive_wide_ratio() -> None:
    """A copy made at the filesystem's link-count limit is driven by the archive's
    declared link count, so the archive-wide ratio counts it; the per-member ratio does
    not, since the link member's compressed size says nothing about the copy."""
    source = SimpleNamespace(compressed_source_size=10, compressed_bytes_consumed=10)
    t = BombTracker(
        max_bytes=None,
        max_ratio=2.0,
        ratio_activation_threshold=0,
        source=source,  # type: ignore[arg-type]
    )
    t.start_member(_member("link").replace(compressed_size=1))
    t.count_copy(15, at_link_limit=True)  # ratio 1.5 archive-wide; 15:1 per member
    with pytest.raises(
        AlwaysStopResourceLimitError,
        match=r"\(0 bytes decoded, plus 25 bytes copied for hard links",
    ):
        t.count_copy(10, at_link_limit=True)


@_posix_perms
def test_cross_device_hardlink_copy_takes_the_link_members_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hand-written copy still lands with the link member's own mode.

    The copy is created private and chmodded before the swap, the same as a FILE write,
    so the source's ``0o600`` does not leak onto a link that stored ``0o640``.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("A.bin")
        info.size = 3
        info.mode = 0o600
        t.addfile(info, io.BytesIO(b"abc"))
        link = tarfile.TarInfo("L.bin")
        link.type = tarfile.LNKTYPE
        link.linkname = "A.bin"
        link.mode = 0o640
        t.addfile(link)

    def always_exdev(source: object, target: object, *a: object, **k: object) -> None:
        raise OSError(errno.EXDEV, "cross-device")

    monkeypatch.setattr(os, "link", always_exdev)
    dest = tmp_path / "out"
    open_and_extract(io.BytesIO(buf.getvalue()), dest, policy=ExtractionPolicy.TRUSTED)
    assert (dest / "A.bin").stat().st_mode & 0o7777 == 0o600
    assert (dest / "L.bin").stat().st_mode & 0o7777 == 0o640
    assert (dest / "L.bin").read_bytes() == b"abc"


# ---------------------------------------------------------------------------
# Live (streaming) decompression-ratio guard (live-decompression-ratio-guard)
# ---------------------------------------------------------------------------


def test_counting_reader_counts_bytes() -> None:
    from archivey.internal.streams.counting import CountingReader

    cr = CountingReader(io.BytesIO(b"abcdefghij"))
    assert cr.bytes_read == 0
    assert cr.read(4) == b"abcd"
    assert cr.bytes_read == 4
    assert cr.read() == b"efghij"
    assert cr.bytes_read == 10


def test_compressed_bytes_consumed_grows_on_piped_targz() -> None:
    from tests.streams_util import NonSeekableBytesIO

    raw = _tar_bytes([("file", "a.txt", b"x" * 200_000)], mode="w:gz")
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        # A compressed pipe has no cheaply-knowable total, but the live counter is present.
        assert r.compressed_source_size is None
        assert r.compressed_bytes_consumed is not None
        for _member, stream in r.stream_members():
            if stream is not None:
                stream.read()
        assert r.compressed_bytes_consumed > 0


def test_streaming_targz_bomb_caught_by_live_ratio(tmp_path: Path) -> None:
    from tests.streams_util import NonSeekableBytesIO

    # 8 MiB of zeros -> a tiny gz; from a pipe both static denominators are unknown, so
    # only the live ratio (and the absolute cap, set high) can catch it.
    raw = _tar_bytes([("file", "z.bin", b"\x00" * (8 * 1024 * 1024))], mode="w:gz")
    dest = tmp_path / "out"
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        assert r.compressed_source_size is None  # no static archive-wide denominator
        with pytest.raises(ResourceLimitError):
            r.extract_all(
                dest,
                limits=ExtractionLimits(
                    max_ratio=10.0,
                    ratio_activation_threshold=1024,
                    live_ratio_activation_threshold=1024,
                    max_extracted_bytes=100
                    * 2**20,  # high, so the cap is not what trips
                ),
            )


def test_streaming_live_ratio_halts_under_continue(tmp_path: Path) -> None:
    from tests.streams_util import NonSeekableBytesIO

    raw = _tar_bytes([("file", "z.bin", b"\x00" * (8 * 1024 * 1024))], mode="w:gz")
    dest = tmp_path / "out"
    with (
        open_archive(NonSeekableBytesIO(raw), streaming=True) as r,
        pytest.raises(ResourceLimitError),
    ):
        r.extract_all(
            dest,
            limits=ExtractionLimits(
                max_ratio=10.0,
                ratio_activation_threshold=1024,
                live_ratio_activation_threshold=1024,
                max_extracted_bytes=100 * 2**20,
            ),
            on_error=OnError.CONTINUE,  # global guard halts anyway
        )


def test_streaming_plain_tar_no_live_ratio_trip(tmp_path: Path) -> None:
    from tests.streams_util import NonSeekableBytesIO

    payload = os.urandom(2 * 1024 * 1024)  # incompressible; plain (uncompressed) tar
    raw = _tar_bytes([("file", "a.bin", payload)], mode="w")
    dest = tmp_path / "out"
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        assert r.compressed_bytes_consumed is None  # uncompressed: nothing counted
        r.extract_all(
            dest,
            limits=ExtractionLimits(max_ratio=10.0, ratio_activation_threshold=1024),
        )
    assert (dest / "a.bin").read_bytes() == payload


def test_seekable_targz_uses_static_not_live(tmp_path: Path) -> None:
    # A path (seekable) .tar.gz has a knowable compressed_source_size, so the static
    # archive-wide ratio applies and no live counter is created.
    src = tmp_path / "a.tar.gz"
    src.write_bytes(_tar_bytes([("file", "a.txt", b"hi")], mode="w:gz"))
    with open_archive(src) as r:
        assert r.compressed_source_size is not None
        assert r.compressed_bytes_consumed is None


def test_streaming_bare_gz_bomb_caught_by_live_ratio(tmp_path: Path) -> None:
    # A bare .gz single-file compressor from a pipe (SingleFileReader) is covered too.

    from tests.streams_util import NonSeekableBytesIO

    raw = gzip.compress(b"\x00" * (8 * 1024 * 1024))
    dest = tmp_path / "out"
    with open_archive(NonSeekableBytesIO(raw), streaming=True) as r:
        assert r.compressed_source_size is None
        assert (
            r.compressed_bytes_consumed is not None
        )  # counter wired for single-file too
        with pytest.raises(ResourceLimitError):
            r.extract_all(
                dest,
                limits=ExtractionLimits(
                    max_ratio=10.0,
                    ratio_activation_threshold=1024,
                    live_ratio_activation_threshold=1024,
                    max_extracted_bytes=100 * 2**20,
                ),
            )


@pytest.mark.parametrize("mode", ["gz", "tar.gz"])
def test_pipe_size_claim_does_not_switch_off_live_ratio(
    tmp_path: Path, mode: str
) -> None:
    # Regression: a non-seekable caller stream's ``size`` attribute became the static
    # archive-wide denominator, and because a static denominator existed the live byte
    # counter was not installed. An inflated claim (1 GB for a ~1 KiB gzip) therefore
    # switched off both archive-wide ratio guards. Nothing can check a pipe's claim, so
    # the claim is not a denominator: the live counter stays.
    payload = b"\x00" * (1024 * 1024)
    if mode == "gz":
        raw = gzip.compress(payload)
    else:
        raw = _tar_bytes([("file", "z.bin", payload)], mode="w:gz")
    limits = ExtractionLimits(
        max_ratio=10.0,
        ratio_activation_threshold=1024,
        live_ratio_activation_threshold=1024,
        max_extracted_bytes=100 * 2**20,  # high, so the cap is not what trips
    )
    with open_archive(SizedNonSeekable(raw, size=10**9), streaming=True) as r:
        assert r.compressed_source_size is None
        assert r.compressed_bytes_consumed is not None
        with pytest.raises(ResourceLimitError, match="Live decompression ratio"):
            r.extract_all(tmp_path / "out", limits=limits)


def test_piped_blank_start_passes_like_a_file(tmp_path: Path) -> None:
    # Regression: a .tar.gz whose member starts with a long run of zeros was refused
    # from a pipe ("Live decompression ratio 1008:1") while the same file extracted
    # from disk. The live denominator is only what has been read so far, so the blank
    # start read as a bomb until the data after it arrived. Scaled down here: 16 MiB of
    # zeros then 1 MiB of random bytes, about 17:1 overall.
    from tests.streams_util import NonSeekableBytesIO

    payload = b"\x00" * (16 * 2**20) + os.urandom(2**20)
    raw = _tar_bytes([("file", "img.bin", payload)], mode="w:gz")
    limits = ExtractionLimits(
        max_ratio=100.0,
        ratio_activation_threshold=1024,
        # Over the blank start, under the whole output: the pipe leg crosses the live
        # floor once the data has arrived, and passes on the true ratio.
        live_ratio_activation_threshold=16 * 2**20 + 512 * 1024,
    )
    for name, src in [
        ("file", io.BytesIO(raw)),
        ("pipe", NonSeekableBytesIO(raw)),
    ]:
        with open_archive(src, streaming=True) as r:
            r.extract_all(tmp_path / name, limits=limits)
        assert (tmp_path / name / "img.bin").read_bytes() == payload

    # A live floor under the blank start judges it before the data arrives: this is the
    # trade-off the floor sets, and what the old behaviour did at 5 MiB.
    with (
        open_archive(NonSeekableBytesIO(raw), streaming=True) as r,
        pytest.raises(ResourceLimitError, match="Live decompression ratio"),
    ):
        r.extract_all(
            tmp_path / "low",
            limits=replace(limits, live_ratio_activation_threshold=1024),
        )


def test_non_seekable_member_stream_keeps_its_declared_size(tmp_path: Path) -> None:
    # A member stream is non-seekable without ``seekable_members``, but its ``size`` is
    # the length its container declares, not a caller's claim: it stays the static
    # denominator, and no live counter is installed.
    inner = gzip.compress(b"\x00" * 4096)
    outer = tmp_path / "outer.tar"
    with tarfile.open(outer, "w") as t:
        info = tarfile.TarInfo("inner.gz")
        info.size = len(inner)
        t.addfile(info, io.BytesIO(inner))
    with open_archive(outer) as outer_ar, outer_ar.open("inner.gz") as member_stream:
        assert not member_stream.seekable()
        with open_archive(member_stream, streaming=True) as inner_ar:
            assert inner_ar.compressed_source_size == len(inner)
            assert inner_ar.compressed_bytes_consumed is None


def test_plain_tar_from_sized_pipe_has_no_archive_wide_denominator() -> None:
    # Pins the documented gap: a plain tar from a non-seekable caller stream has no
    # trusted size, and only a compressed container installs the live counter, so
    # neither archive-wide denominator exists and only max_extracted_bytes applies.
    raw = _tar_bytes([("file", "a.bin", b"x" * 4096)])
    with open_archive(SizedNonSeekable(raw, size=len(raw)), streaming=True) as r:
        assert r.compressed_source_size is None
        assert r.compressed_bytes_consumed is None


def test_forged_member_declaration_is_refused_only_after_the_decode(
    tmp_path: Path,
) -> None:
    # Pins the documented gap: a nested archive's static denominator is the length
    # its container declares, unchecked until the member ends. An outer ZIP declaring
    # 1 GB for a ~4 KiB inner.gz makes the ratio unreachable, so the inner payload
    # decodes to its end; the container's end-of-member check then refuses it, and
    # the failed extraction leaves no file behind.
    inner = gzip.compress(b"\x00" * (4 * 2**20))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("inner.gz", inner)
    raw = bytearray(buf.getvalue())
    forged = 10**9
    struct.pack_into("<I", raw, 22, forged)  # local header: uncompressed size
    cd = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, cd + 24, forged)  # central directory: same field
    outer = tmp_path / "outer.zip"
    outer.write_bytes(bytes(raw))
    limits = ExtractionLimits(
        max_ratio=10.0, ratio_activation_threshold=1024, max_extracted_bytes=100 * 2**20
    )
    out = tmp_path / "out"
    with open_archive(outer) as outer_ar, outer_ar.open("inner.gz") as member_stream:
        assert not member_stream.seekable()
        with open_archive(member_stream, streaming=True) as inner_ar:
            assert inner_ar.compressed_source_size == forged
            assert inner_ar.compressed_bytes_consumed is None
            with pytest.raises(TruncatedError):
                inner_ar.extract_all(out, limits=limits)
    assert not out.exists() or not any(out.iterdir())


# ---------------------------------------------------------------------------
# Orphaned-hardlink second pass + selector semantics + live-guard coverage
# (post-4b review regressions — each test pins a bug found reviewing #28/#31)
# ---------------------------------------------------------------------------


def _orphan_tar(tmp_path: Path, links: list[str]) -> Path:
    """A tar with source ``A.txt`` followed by hardlinks to it (the orphan-recovery shape:
    extracting only the links leaves the source excluded)."""
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [("file", "A.txt", b"hello world")]
            + [("hard", ln, "A.txt") for ln in links]
        )
    )
    return src


def test_orphan_first_link_skipped_writes_to_next(tmp_path: Path) -> None:
    # Regression: with the excluded source's FIRST link skipped (OverwritePolicy.SKIP over
    # an existing destination), the coordinator crashed with a raw KeyError when linking
    # the second orphan (source_paths never got an entry). The content must instead be
    # written to the first link whose destination is writable.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "L1.txt").write_bytes(b"pre-existing")

    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            members=["L1.txt", "L2.txt"],  # source A.txt excluded
            overwrite=OverwritePolicy.SKIP,
            on_error=OnError.CONTINUE,
        ).results

    statuses = {res.member.name: res.status for res in results}
    assert statuses["L1.txt"] is ExtractionStatus.NOT_OVERWRITTEN
    assert statuses["L2.txt"] is ExtractionStatus.EXTRACTED
    assert (dest / "L1.txt").read_bytes() == b"pre-existing"  # untouched under SKIP
    assert (
        dest / "L2.txt"
    ).read_bytes() == b"hello world"  # content moved to next link
    assert not (dest / "A.txt").exists()  # excluded source never materialized by name


def test_orphan_link_failing_after_the_content_was_placed_fails_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The second pass writes the excluded source's content at L1, then links L2 to
    # it. A failure linking L2 is L2's own: L1's content is on disk, so L1 stays
    # EXTRACTED and no failure group joins the two.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    calls: list[str] = []
    resolve = ExtractionCoordinator._resolve_collision

    def fail_in_second_pass(
        self: ExtractionCoordinator, original: ArchiveMember, *args: object
    ) -> object:
        # L2's destination is resolved once in each pass.
        calls.append(original.name)
        if original.name == "L2.txt" and calls.count("L2.txt") == 2:
            raise OSError(errno.EIO, "injected")
        return resolve(self, original, *args)

    monkeypatch.setattr(
        ExtractionCoordinator, "_resolve_collision", fail_in_second_pass
    )
    with open_archive(src) as r:
        results = r.extract_all(
            dest, members=["L1.txt", "L2.txt"], on_error=OnError.CONTINUE
        ).results

    by_name = {res.member.name: res for res in results}
    assert by_name["L1.txt"].status is ExtractionStatus.EXTRACTED
    assert (dest / "L1.txt").read_bytes() == b"hello world"
    assert calls.count("L2.txt") == 2
    assert by_name["L2.txt"].status is ExtractionStatus.FAILED
    assert by_name["L2.txt"].failure_group_id is None


@pytest.mark.parametrize(
    ("overwrite", "held", "message"),
    [
        (OverwritePolicy.ERROR, "file", "Destination already exists"),
        (OverwritePolicy.REPLACE, "full-dir", "Destination is a directory"),
    ],
    ids=["error-over-file", "replace-over-full-dir"],
)
def test_orphan_link_refused_by_the_policy_fails_alone(
    tmp_path: Path, overwrite: OverwritePolicy, held: str, message: str
) -> None:
    # The excluded source's content goes to the first link the OverwritePolicy lets
    # it take. L1's destination is refused, so L1 fails on its own, nothing of the
    # source has been read, and L2 gets the content: the source did not fail, so no
    # failure group joins the two.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    if held == "file":
        (dest / "L1.txt").write_bytes(b"pre-existing")
    else:
        (dest / "L1.txt").mkdir()
        (dest / "L1.txt" / "keep").write_bytes(b"pre-existing")

    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            members=["L1.txt", "L2.txt"],
            overwrite=overwrite,
            on_error=OnError.CONTINUE,
        ).results

    by_name = {res.member.name: res for res in results}
    first = by_name["L1.txt"]
    assert first.status is ExtractionStatus.FAILED
    assert message in str(first.error)
    assert first.failure_group_id is None
    assert first.failure_group_size is None
    assert first.requested_path == dest / "L1.txt"
    assert by_name["L2.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["L2.txt"].failure_group_id is None
    assert (dest / "L2.txt").read_bytes() == b"hello world"
    if held == "file":
        assert (dest / "L1.txt").read_bytes() == b"pre-existing"
    else:
        assert (dest / "L1.txt" / "keep").read_bytes() == b"pre-existing"
    assert not (dest / "A.txt").exists()


def test_orphan_link_refused_by_the_policy_stops_under_stop(tmp_path: Path) -> None:
    # Under OnError.STOP the first link's own failure ends the run, as any other
    # link's would.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "L1.txt").write_bytes(b"pre-existing")

    with (
        open_archive(src) as r,
        pytest.raises(ExtractionError, match="Destination already exists"),
    ):
        r.extract_all(
            dest, members=["L1.txt", "L2.txt"], overwrite=OverwritePolicy.ERROR
        )
    assert not (dest / "L2.txt").exists()


def test_orphan_source_failure_keeps_earlier_link_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # L1 is skipped, then reading the source fails while it is copied into L2's temp
    # file. The source failed, so L2 and L3 fail as one group of two; L1's
    # NOT_OVERWRITTEN stands.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt", "L3.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "L1.txt").write_bytes(b"pre-existing")

    def boom(*args: object, **kwargs: object) -> None:
        raise ExtractionError("forced second-pass failure")

    monkeypatch.setattr(ExtractionCoordinator, "_copy_to_fileobj", staticmethod(boom))
    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            members=["L1.txt", "L2.txt", "L3.txt"],
            overwrite=OverwritePolicy.SKIP,
            on_error=OnError.CONTINUE,
        ).results

    by_name = {res.member.name: res for res in results}
    assert by_name["L1.txt"].status is ExtractionStatus.NOT_OVERWRITTEN
    assert by_name["L1.txt"].failure_group_id is None
    failed = [by_name["L2.txt"], by_name["L3.txt"]]
    assert [r.status for r in failed] == [ExtractionStatus.FAILED] * 2
    assert failed[0].failure_group_id is not None
    assert failed[0].failure_group_id == failed[1].failure_group_id
    assert [r.failure_group_size for r in failed] == [2, 2]
    assert (dest / "L1.txt").read_bytes() == b"pre-existing"
    assert not (dest / "L2.txt").exists()
    assert not (dest / "L3.txt").exists()
    assert sorted(p.name for p in dest.iterdir()) == ["L1.txt"]  # no temp left


def test_orphan_source_refused_from_its_recorded_size_fails_as_a_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The recorded-size refusal is a property of the source, which every link would
    # meet: it fails the links as one group, and no link is tried after it.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"

    def refuse(self: BombTracker) -> None:
        raise ResourceLimitError("forced recorded-size refusal")

    monkeypatch.setattr(BombTracker, "check_recorded_size", refuse)
    with open_archive(src) as r:
        results = r.extract_all(
            dest, members=["L1.txt", "L2.txt"], on_error=OnError.CONTINUE
        ).results

    assert [res.status for res in results] == [ExtractionStatus.FAILED] * 2
    assert results[0].failure_group_id is not None
    assert results[0].failure_group_id == results[1].failure_group_id
    assert [res.failure_group_size for res in results] == [2, 2]
    assert not (dest / "L1.txt").exists()
    assert not (dest / "L2.txt").exists()


def _orphan_tar_with_link_in_ro(tmp_path: Path) -> Path:
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("file", "A.txt", b"hello world"),
                ("hard", "ro/L1.txt", "A.txt"),
                ("hard", "L2.txt", "A.txt"),
            ]
        )
    )
    return src


def _assert_first_link_failed_alone(results, dest: Path) -> None:
    by_name = {res.member.name: res for res in results}
    first = by_name["ro/L1.txt"]
    assert first.status is ExtractionStatus.FAILED
    assert isinstance(first.error, PermissionError)
    assert first.failure_group_id is None
    assert first.failure_group_size is None
    assert first.requested_path == dest / "ro" / "L1.txt"
    assert by_name["L2.txt"].status is ExtractionStatus.EXTRACTED
    assert (dest / "L2.txt").read_bytes() == b"hello world"
    assert list((dest / "ro").iterdir()) == []


def test_orphan_link_whose_temp_file_is_refused_fails_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Creating the temp file comes before the first read of the source, so a
    # directory that refuses it fails that link alone and the next link gets the
    # content. The refusal is injected, so this runs as root too; the test below
    # makes the real one.
    src = _orphan_tar_with_link_in_ro(tmp_path)
    dest = tmp_path / "out"
    mkstemp = tempfile.mkstemp

    def refuse_in_ro(*args: object, **kwargs: object) -> tuple[int, str]:
        if Path(str(kwargs["dir"])).name == "ro":
            raise PermissionError(errno.EACCES, "Permission denied", kwargs["dir"])
        return mkstemp(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(tempfile, "mkstemp", refuse_in_ro)
    with open_archive(src) as r:
        results = r.extract_all(
            dest, members=["ro/L1.txt", "L2.txt"], on_error=OnError.CONTINUE
        ).results
    _assert_first_link_failed_alone(results, dest)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX directory permissions")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes anywhere"
)
def test_orphan_link_in_a_read_only_directory_fails_alone(tmp_path: Path) -> None:
    # The same, with the caller's read-only directory refusing the temp file.
    src = _orphan_tar_with_link_in_ro(tmp_path)
    dest = tmp_path / "out"
    (dest / "ro").mkdir(parents=True)
    (dest / "ro").chmod(0o500)
    try:
        with open_archive(src) as r:
            results = r.extract_all(
                dest,
                members=["ro/L1.txt", "L2.txt"],
                overwrite=OverwritePolicy.ERROR,
                on_error=OnError.CONTINUE,
            ).results
    finally:
        (dest / "ro").chmod(0o700)
    _assert_first_link_failed_alone(results, dest)


def test_orphan_all_links_skipped_writes_nothing(tmp_path: Path) -> None:
    # Companion to the above: when EVERY selected link's destination already exists under
    # SKIP, all links are recorded NOT_OVERWRITTEN, existing files stay untouched, and no stray
    # content or temp file is written anywhere.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "L1.txt").write_bytes(b"keep-1")
    (dest / "L2.txt").write_bytes(b"keep-2")

    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            members=["L1.txt", "L2.txt"],
            overwrite=OverwritePolicy.SKIP,
        ).results

    assert [res.status for res in results] == [ExtractionStatus.NOT_OVERWRITTEN] * 2
    assert (dest / "L1.txt").read_bytes() == b"keep-1"
    assert (dest / "L2.txt").read_bytes() == b"keep-2"
    assert sorted(p.name for p in dest.iterdir()) == ["L1.txt", "L2.txt"]  # no strays


def test_orphan_all_links_refused_writes_nothing(tmp_path: Path) -> None:
    # The ERROR sibling of the above: every link's destination is refused, so each
    # link fails on its own (no failure group), the caller's files stay untouched,
    # and nothing else is written.
    src = _orphan_tar(tmp_path, ["L1.txt", "L2.txt"])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "L1.txt").write_bytes(b"keep-1")
    (dest / "L2.txt").write_bytes(b"keep-2")

    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            members=["L1.txt", "L2.txt"],
            overwrite=OverwritePolicy.ERROR,
            on_error=OnError.CONTINUE,
        ).results

    assert [res.status for res in results] == [ExtractionStatus.FAILED] * 2
    for res, name in zip(results, ["L1.txt", "L2.txt"], strict=True):
        assert "Destination already exists" in str(res.error)
        assert res.failure_group_id is None
        assert res.failure_group_size is None
        assert res.requested_path == dest / name
    assert (dest / "L1.txt").read_bytes() == b"keep-1"
    assert (dest / "L2.txt").read_bytes() == b"keep-2"
    assert sorted(p.name for p in dest.iterdir()) == ["L1.txt", "L2.txt"]  # no strays


def test_orphan_materialized_source_carries_link_metadata(tmp_path: Path) -> None:
    # Regression: the second-pass-materialized source was written with member=None, so no
    # chmod/utime ever ran and the file kept mkstemp's 0600 forever. The link's transformed
    # copy supplies the on-disk identity (spec: "the copy supplies ... mode, timestamps");
    # hardlinks share one inode, so it must be applied to the file carrying the content.
    import stat as stat_mod

    link_mtime = 1_600_000_000
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("A.txt")
        info.size = 11
        info.mode = 0o644
        info.mtime = (
            1_500_000_000  # source's own mtime differs, proving we use the link's
        )
        t.addfile(info, io.BytesIO(b"hello world"))
        info = tarfile.TarInfo("L1.txt")
        info.type = tarfile.LNKTYPE
        info.linkname = "A.txt"
        info.mode = 0o644
        info.mtime = link_mtime
        t.addfile(info)
    src = tmp_path / "a.tar"
    src.write_bytes(buf.getvalue())
    dest = tmp_path / "out"

    with open_archive(src) as r:
        results = r.extract_all(dest, members=["L1.txt"]).results

    assert [res.status for res in results] == [ExtractionStatus.EXTRACTED]
    st = (dest / "L1.txt").lstat()
    if os.name == "posix":  # Windows has no Unix permission bits (see _posix_perms)
        assert stat_mod.S_IMODE(st.st_mode) == 0o644  # not mkstemp's 0600
    assert int(st.st_mtime) == link_mtime  # the link member's mtime, not the source's


def test_hardlink_duplicate_name_extraction_links_first_inode(tmp_path: Path) -> None:
    src = tmp_path / "dup-hardlink.tar"
    src.write_bytes(
        _tar_bytes(
            [
                ("file", "A.txt", b"content1"),
                ("hard", "L.txt", "A.txt"),
                ("file", "A.txt", b"content2"),
            ]
        )
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        results = r.extract_all(dest, overwrite=OverwritePolicy.REPLACE).results
    # First A.txt is superseded; hardlink still materializes its target bytes;
    # the live A.txt is the last entry.
    assert [res.status for res in results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "L.txt").read_bytes() == b"content1"
    assert (dest / "A.txt").read_bytes() == b"content2"
    # L was linked against the first A.txt inode; the second duplicate replaced the path.
    if os.name == "posix":
        assert not os.path.samefile(dest / "A.txt", dest / "L.txt")


# Streaming and random-access extraction of an archive holding one name more than once
# must leave the same tree on disk and report the same statuses. Random access knows the
# later copy exists before writing the earlier one, so it never writes it; a streaming
# pass writes the earlier copy, then has to take it back when the later one arrives.
_DUPLICATE_NAME_CASES: dict[str, list[tuple]] = {
    "file twice": [("file", "a.txt", b"first"), ("file", "a.txt", b"last")],
    "file three times": [
        ("file", "a.txt", b"one"),
        ("file", "b.txt", b"b"),
        ("file", "a.txt", b"two"),
        ("file", "a.txt", b"three"),
    ],
    "hardlink to the shadowed copy": [
        ("file", "A.txt", b"content1"),
        ("hard", "L.txt", "A.txt"),
        ("file", "A.txt", b"content2"),
    ],
    "hardlink to a name held once": [
        ("file", "B.txt", b"b"),
        ("hard", "L.txt", "B.txt"),
        ("file", "A.txt", b"one"),
        ("file", "A.txt", b"two"),
    ],
    "file then symlink": [
        ("file", "a", b"data"),
        ("file", "t.txt", b"target"),
        ("sym", "a", "t.txt"),
    ],
    "symlink then file": [
        ("file", "t.txt", b"target"),
        ("sym", "a", "t.txt"),
        ("file", "a", b"data"),
    ],
    "directory twice": [
        ("dir", "d", None),
        ("file", "d/x.txt", b"x"),
        ("dir", "d", None),
    ],
    "file then directory": [
        ("file", "d", b"data"),
        ("dir", "d", None),
        ("file", "d/x.txt", b"x"),
    ],
}
# Not in the table: a case variant between two copies (``A.txt``, ``a.txt``, ``A.txt``).
# Random access writes ``a.txt`` against an empty key; a streaming pass collides it with
# the first ``A.txt``, which it cannot yet know is shadowed. That needs the future.


def _tree(root: Path) -> dict[object, object]:
    """Everything under ``root``: file bytes, symlink targets, and bare directories.

    On POSIX, files that share an inode are also listed under ``("hardlinks",)`` as groups
    of paths, so a copy where the other mode made a link shows up.
    """
    tree: dict[object, object] = {}
    inodes: dict[tuple[int, int], list[str]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            tree[rel] = ("symlink", os.readlink(path))
        elif path.is_dir():
            tree[rel] = "dir"
        else:
            tree[rel] = path.read_bytes()
            st = path.stat()
            inodes.setdefault((st.st_dev, st.st_ino), []).append(rel)
    if os.name == "posix":
        # A tuple key, so no member path can land on it.
        tree[("hardlinks",)] = sorted(g for g in inodes.values() if len(g) > 1)
    return tree


@pytest.mark.parametrize("prefilled", [False, True], ids=["fresh", "prefilled"])
@pytest.mark.parametrize("case", sorted(_DUPLICATE_NAME_CASES))
@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.ERROR,
        OverwritePolicy.SKIP,
        OverwritePolicy.REPLACE,
        OverwritePolicy.RENAME,
    ],
)
def test_duplicate_names_extract_the_same_in_both_modes(
    tmp_path: Path, case: str, overwrite: OverwritePolicy, prefilled: bool
) -> None:
    """``prefilled`` puts a file of the caller's at each repeated name beforehand."""
    if prefilled and case in ("hardlink to the shadowed copy", "directory twice"):
        # A member between the copies depends on what the earlier copy did to the
        # caller's file: a known difference, see
        # test_streaming_duplicate_name_known_differences.
        pytest.skip("the earlier copy's effect on another member cannot be undone")
    specs = _DUPLICATE_NAME_CASES[case]
    names = [name.rstrip("/") for _kind, name, _payload in specs]
    repeated = {name for name in names if names.count(name) > 1}
    if os.name != "posix" and any(kind == "sym" for kind, *_ in specs):
        pytest.skip("symlinks need privileges on Windows")
    archive = _tar_bytes(specs)
    outcomes = {}
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        if prefilled:
            dest.mkdir()
            for name in repeated:
                (dest / name).write_bytes(b"OLD")
        with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
            results = reader.extract_all(
                dest, overwrite=overwrite, on_error=OnError.CONTINUE
            ).results
        outcomes[streaming] = (
            [
                (r.member.name, r.status, r.path and r.path.relative_to(dest))
                for r in results
            ],
            _tree(dest),
        )
    assert outcomes[True] == outcomes[False]


def test_streaming_duplicate_name_supersedes_the_written_copy(tmp_path: Path) -> None:
    """The default ERROR policy used to refuse the later copy of a streamed TAR member."""
    archive = _tar_bytes([("file", "a.txt", b"first"), ("file", "a.txt", b"last")])
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive), streaming=True) as reader:
        results = reader.extract_all(dest).results
    assert [(r.status, r.path) for r in results] == [
        (ExtractionStatus.SUPERSEDED, None),
        (ExtractionStatus.EXTRACTED, dest / "a.txt"),
    ]
    assert (dest / "a.txt").read_bytes() == b"last"


def test_streaming_duplicate_name_removes_the_copy_a_filter_drops(
    tmp_path: Path,
) -> None:
    """The earlier copy is superseded by the later one's presence, not by its write."""
    archive = _tar_bytes([("file", "a.txt", b"first"), ("file", "a.txt", b"last")])
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        seen: list[str] = []

        def drop_second(member: ArchiveMember) -> ArchiveMember | None:
            seen.append(member.name)  # noqa: B023 - called within this iteration
            return member if len(seen) == 1 else None  # noqa: B023 - called within this iteration

        with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
            results = reader.extract_all(dest, filter=drop_second).results
        assert [r.status for r in results] == [ExtractionStatus.SUPERSEDED]
        assert not (dest / "a.txt").exists()


def test_streaming_duplicate_name_removes_the_copy_when_the_later_one_fails(
    tmp_path: Path,
) -> None:
    archive = _tar_bytes([("file", "a.txt", b"first"), ("file", "a.txt", b"last")])
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        seen: list[str] = []

        def fail_second(member: ArchiveMember) -> ArchiveMember | None:
            seen.append(member.name)  # noqa: B023 - called within this iteration
            if len(seen) == 2:  # noqa: B023 - called within this iteration
                # A one-pass extraction keeps the earlier copy until the later one's
                # outcome is known, so a later copy that lands replaces it atomically.
                # TAR extracts in one pass in both modes: random access enforces the
                # listing limits as members arrive rather than listing first.
                assert (dest / "a.txt").exists()  # noqa: B023 - called within this iteration
                raise ExtractionError("refused", member_name=member.name)
            return member

        with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
            results = reader.extract_all(
                dest, filter=fail_second, on_error=OnError.CONTINUE
            ).results
        assert [r.status for r in results] == [
            ExtractionStatus.SUPERSEDED,
            ExtractionStatus.FAILED,
        ]
        assert not (dest / "a.txt").exists()


@pytest.mark.parametrize(
    "limits",
    [
        ExtractionLimits(max_extracted_bytes=100_000),
        ExtractionLimits(max_entries=2),
    ],
    ids=["bytes", "entries"],
)
def test_streaming_duplicate_name_is_not_counted_against_the_limits(
    tmp_path: Path, limits: ExtractionLimits
) -> None:
    """A copy taken back stops counting, as random access never counted it."""
    payload = bytes(range(256)) * 160  # 40 960 bytes, three copies exceed the cap
    archive = _tar_bytes([("file", "a.txt", payload)] * 3)
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
            results = reader.extract_all(dest, limits=limits).results
        assert [r.status for r in results] == [
            ExtractionStatus.SUPERSEDED,
            ExtractionStatus.SUPERSEDED,
            ExtractionStatus.EXTRACTED,
        ]
        assert (dest / "a.txt").read_bytes() == payload


def test_streaming_duplicate_name_holds_a_copy_it_could_not_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused removal leaves the run's own entry, which the next copy replaces."""
    archive = _tar_bytes(
        [
            ("file", "a.txt", b"one"),
            ("file", "a.txt", b"two"),
            ("file", "a.txt", b"three"),
        ]
    )
    dest = tmp_path / "out"
    real_unlink = os.unlink

    def refusing_unlink(path: object, *args: object, **kwargs: object) -> None:
        if Path(str(path)) == dest / "a.txt":
            raise PermissionError(errno.EACCES, "refused", str(path))
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    seen: list[str] = []

    def drop_second(member: ArchiveMember) -> ArchiveMember | None:
        seen.append(member.name)
        return None if len(seen) == 2 else member

    monkeypatch.setattr(os, "unlink", refusing_unlink)
    with open_archive(io.BytesIO(archive), streaming=True) as reader:
        results = reader.extract_all(dest, filter=drop_second).results
    assert [r.status for r in results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "a.txt").read_bytes() == b"three"


def test_streaming_duplicate_name_holds_an_unremoved_copy_across_take_backs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held copy survives a member that takes back another copy of the name."""
    archive = _tar_bytes([("file", "a.txt", b"%d" % n) for n in range(1, 5)])
    renames = {2: "b.txt", 3: "c.txt"}
    dest = tmp_path / "out"
    real_unlink = os.unlink

    def refusing_unlink(path: object, *args: object, **kwargs: object) -> None:
        if Path(str(path)) == dest / "a.txt":
            raise PermissionError(errno.EACCES, "refused", str(path))
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    seen: list[str] = []

    def rename_middle(member: ArchiveMember) -> ArchiveMember | None:
        seen.append(member.name)
        new_name = renames.get(len(seen))
        return member.replace(name=new_name) if new_name else member

    monkeypatch.setattr(os, "unlink", refusing_unlink)
    with open_archive(io.BytesIO(archive), streaming=True) as reader:
        results = reader.extract_all(dest, filter=rename_middle).results
    assert [r.status for r in results] == [ExtractionStatus.SUPERSEDED] * 3 + [
        ExtractionStatus.EXTRACTED
    ]
    tree = _tree(dest)
    tree.pop(("hardlinks",), None)
    assert tree == {"a.txt": b"4"}


def test_streaming_duplicate_name_unremoved_copy_still_collides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy the filesystem would not remove keeps its collision claim."""
    archive = _tar_bytes(
        [
            ("file", "a.txt", b"one"),
            ("file", "a.txt", b"two"),
            ("file", "A.TXT", b"upper"),
        ]
    )
    dest = tmp_path / "out"
    real_unlink = os.unlink

    def refusing_unlink(path: object, *args: object, **kwargs: object) -> None:
        if Path(str(path)) == dest / "a.txt":
            raise PermissionError(errno.EACCES, "refused", str(path))
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    seen: list[str] = []

    def drop_second(member: ArchiveMember) -> ArchiveMember | None:
        seen.append(member.name)
        return None if len(seen) == 2 else member

    monkeypatch.setattr(os, "unlink", refusing_unlink)
    with open_archive(io.BytesIO(archive), streaming=True) as reader:
        results = reader.extract_all(
            dest,
            filter=drop_second,
            policy=ExtractionPolicy.STANDARD,
            on_error=OnError.CONTINUE,
        ).results
    assert [(r.status, r.collided_with) for r in results] == [
        (ExtractionStatus.SUPERSEDED, None),
        (ExtractionStatus.FAILED, dest / "a.txt"),
    ]


def test_streaming_duplicate_name_renames_onto_an_unremoved_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parking a held copy frees its derived name for RENAME's next scan."""
    archive = _tar_bytes(
        [
            ("file", "A.txt", b"upper"),
            ("file", "a.txt", b"one"),
            ("file", "a.txt", b"two"),
            ("file", "A.TXT", b"caps"),
            ("file", "a.txt", b"three"),
        ]
    )
    dest = tmp_path / "out"
    real_unlink = os.unlink

    def refusing_unlink(path: object, *args: object, **kwargs: object) -> None:
        if Path(str(path)) == dest / "a (1).txt":
            raise PermissionError(errno.EACCES, "refused", str(path))
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    seen: list[str] = []

    def drop_second_copy(member: ArchiveMember) -> ArchiveMember | None:
        seen.append(member.name)
        return None if len(seen) == 3 else member

    monkeypatch.setattr(os, "unlink", refusing_unlink)
    with open_archive(io.BytesIO(archive), streaming=True) as reader:
        reader.extract_all(
            dest,
            filter=drop_second_copy,
            policy=ExtractionPolicy.STANDARD,
            overwrite=OverwritePolicy.RENAME,
        )
    tree = _tree(dest)
    tree.pop(("hardlinks",), None)
    assert tree == {"A.txt": b"upper", "A (2).TXT": b"caps", "a (1).txt": b"three"}


def test_streaming_duplicate_name_kept_by_a_hardlink_still_counts(
    tmp_path: Path,
) -> None:
    """A taken-back copy that a hardlink still holds stays on disk, so it stays counted."""
    payload = bytes(range(256)) * 160  # 40 960 bytes
    specs: list[tuple] = []
    for n in range(3):
        specs += [("file", "A.txt", payload), ("hard", f"L{n}.txt", "A.txt")]
    archive = _tar_bytes(specs)
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        with (
            open_archive(io.BytesIO(archive), streaming=streaming) as reader,
            pytest.raises(ResourceLimitError, match="max_extracted_bytes"),
        ):
            reader.extract_all(
                dest,
                on_error=OnError.CONTINUE,
                limits=ExtractionLimits(max_extracted_bytes=100_000),
            )


class _FileThenAntiReader(BaseArchiveReader):
    """``a.txt`` then an anti-item for it, with no upfront member list, so a streaming
    pass learns of the anti-item only when it arrives."""

    _MEMBER_LIST_UPFRONT = False

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=5)
        yield ArchiveMember(type=MemberType.ANTI, name="a.txt")

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        return self._wrap_member_stream(io.BytesIO(b"first"), member.name, size=5)

    def _get_archive_info(self) -> ArchiveInfo:
        return ArchiveInfo(
            format=ArchiveFormat.SEVEN_Z,
            format_version=None,
            is_solid=False,
            member_count=None,
            comment=None,
            is_encrypted=False,
            is_multivolume=False,
            cost=CostReceipt(
                listing_cost=ListingCost.REQUIRES_SCANNING,
                access_cost=AccessCost.DIRECT,
                stream_capability=StreamCapability.SEEKABLE,
            ),
        )

    def _close_archive(self) -> None:
        pass


def test_streaming_duplicate_name_anti_item_removes_the_written_copy(
    tmp_path: Path,
) -> None:
    """An anti-item supersedes the written copy of its name; it does not land on it."""
    outcomes = {}
    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        with _FileThenAntiReader(ArchiveFormat.SEVEN_Z, streaming, "x.7z") as reader:
            results = reader.extract_all(dest).results
        outcomes[streaming] = ([r.status for r in results], _tree(dest))
    assert "a.txt" not in outcomes[False][1]
    assert outcomes[True] == outcomes[False]


def test_streaming_duplicate_name_known_differences(tmp_path: Path) -> None:
    """The two cases ``safe-extraction`` records as differing, pinned so a change shows.

    Both need the future: a one-pass extraction never sees a later copy the selector
    excludes, and the caller's own file was replaced by the earlier copy before the
    later copy was known. "Random access" here is a reader that lists before it
    extracts, a ZIP; a random-access TAR extracts in one pass, so it answers as a
    streaming pass does (the ``tar`` rows).
    """
    tar = _tar_bytes([("file", "a.txt", b"first"), ("file", "a.txt", b"last")])
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf, warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # the duplicate is the point
        zf.writestr("a.txt", b"first")
        zf.writestr("a.txt", b"last")
    archives = {False: zip_buf.getvalue(), True: tar, "tar": tar}

    def outcome(streaming: bool | str, dest: Path, **kwargs: object) -> tuple:
        with open_archive(
            io.BytesIO(archives[streaming]), streaming=streaming is True
        ) as reader:
            results = reader.extract_all(dest, **kwargs).results  # type: ignore[arg-type]
        target = dest / "a.txt"
        return (
            [r.status for r in results],
            target.read_bytes() if target.exists() else None,
        )

    # A selection that takes the earlier copy only.
    for streaming, expected in (
        (False, ([ExtractionStatus.SUPERSEDED], None)),
        (True, ([ExtractionStatus.EXTRACTED], b"first")),
        ("tar", ([ExtractionStatus.EXTRACTED], b"first")),
    ):
        picked: list[str] = []

        def first_only(member: ArchiveMember) -> bool:
            picked.append(member.name)  # noqa: B023 - called within this iteration
            return len(picked) == 1  # noqa: B023 - called within this iteration

        dest = tmp_path / f"select-{streaming}"
        assert outcome(streaming, dest, members=first_only) == expected

    # A file of the caller's under REPLACE, and a later copy that does not land.
    for streaming, expected in (
        (False, ([ExtractionStatus.SUPERSEDED], b"OLD")),
        (True, ([ExtractionStatus.SUPERSEDED], None)),
        ("tar", ([ExtractionStatus.SUPERSEDED], None)),
    ):
        seen: list[str] = []

        def drop_second(member: ArchiveMember) -> ArchiveMember | None:
            seen.append(member.name)  # noqa: B023 - called within this iteration
            return member if len(seen) == 1 else None  # noqa: B023 - called within this iteration

        dest = tmp_path / f"replace-{streaming}"
        dest.mkdir()
        (dest / "a.txt").write_bytes(b"OLD")
        assert (
            outcome(
                streaming,
                dest,
                filter=drop_second,
                overwrite=OverwritePolicy.REPLACE,
            )
            == expected
        )


def test_hardlink_before_source_is_not_linked_forward(tmp_path: Path) -> None:
    # A TAR hardlink refers to a file archived before it (tarfile searches only the
    # members before the link; tar(1) links to what it already wrote). A hardlink that
    # PRECEDES the only member of its target's name therefore has no target: it fails
    # with LinkTargetNotFoundError, and the later file extracts on its own, read once.
    # (A hardlink whose earlier source is not selected still goes through the second
    # pass, which re-reads that source.)
    payload = b"payload bytes"
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("hard", "L1.txt", "A.txt"), ("file", "A.txt", payload)])
    )
    dest = tmp_path / "out"
    progress_bytes: list[int] = []

    with open_archive(src) as r:
        results = r.extract_all(
            dest,
            on_error=OnError.CONTINUE,
            on_progress=lambda p: progress_bytes.append(p.bytes_written),
        ).results

    by_name = {res.member.name: res for res in results}
    assert by_name["A.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["L1.txt"].status is ExtractionStatus.FAILED
    assert isinstance(by_name["L1.txt"].error, LinkTargetNotFoundError)
    assert (dest / "A.txt").read_bytes() == payload
    assert not (dest / "L1.txt").exists()
    assert progress_bytes[-1] == len(payload)  # bytes read/counted once


def test_selector_archivemember_entry_matches_by_identity(tmp_path: Path) -> None:
    # The collection selector's ArchiveMember entries match by object identity (the Phase 5
    # semantics, now specced in safe-extraction): with duplicate names, passing one member
    # object selects only that occurrence — while a str entry matches every duplicate.
    # Non-current duplicates are reported as SUPERSEDED (no write).
    src = tmp_path / "a.tar"
    src.write_bytes(
        _tar_bytes([("file", "dup.txt", b"first"), ("file", "dup.txt", b"second")])
    )

    with open_archive(src) as r:
        first, second = r.members()
        assert first.name == second.name == "dup.txt"
        assert first.is_current is False
        assert second.is_current is True
        results = r.extract_all(tmp_path / "by_member", members=[first]).results
    assert len(results) == 1
    assert results[0].status is ExtractionStatus.SUPERSEDED
    assert not (tmp_path / "by_member" / "dup.txt").exists()

    with open_archive(src) as r:
        results = r.extract_all(
            tmp_path / "by_name", members=["dup.txt"], overwrite=OverwritePolicy.REPLACE
        ).results
    assert len(results) == 2  # a str entry matches every same-named duplicate
    assert [res.status for res in results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
    ]
    assert (tmp_path / "by_name" / "dup.txt").read_bytes() == b"second"


def test_opaque_seekable_compressed_source_gets_live_ratio(tmp_path: Path) -> None:
    # Regression: the live counter was only wired for NON-seekable streams, while the
    # static denominator needs a cheaply-sizable source — so a compressed archive on a
    # seekable-but-opaque stream (a custom stream type: not SEEK_END-whitelisted, no
    # `.size`, no try_get_size()) had NO archive-wide ratio guard at all, leaving only the
    # absolute byte cap. The counter must engage exactly when the static size is absent.
    from tests.streams_util import (
        CountingBytesIO,  # seekable, opaque to source_byte_size
    )

    raw = _tar_bytes([("file", "z.bin", b"\x00" * (8 * 1024 * 1024))], mode="w:gz")
    dest = tmp_path / "out"
    with open_archive(CountingBytesIO(raw)) as r:
        assert r.compressed_source_size is None  # opaque: no static denominator...
        assert (
            r.compressed_bytes_consumed is not None
        )  # ...so the live counter is wired
        with pytest.raises(ResourceLimitError):
            r.extract_all(
                dest,
                limits=ExtractionLimits(
                    max_ratio=10.0,
                    ratio_activation_threshold=1024,
                    live_ratio_activation_threshold=1024,
                    max_extracted_bytes=100
                    * 2**20,  # high, so the cap is not what trips
                ),
            )


# ---------------------------------------------------------------------------
# Cross-platform name safety (safe-extraction O2/O3/O4/O7) — asserted
# deterministically on every platform, not gated on the runner OS.
# See dev-docs/decisions/0013-cross-platform-name-safety-policies.md.
# ---------------------------------------------------------------------------


def _overwritten(report) -> list:
    """Members a later REPLACE clobbered — the result-side record of a collision.

    Collisions left the diagnostics channel: ``ExtractionResult`` is now the only
    record, and a REPLACE merge shows up as the earlier member being revised to
    ``OVERWRITTEN`` rather than as a diagnostic count."""
    return [r for r in report.results if r.status is ExtractionStatus.OVERWRITTEN]


def _surrogate_tar(stored_name: str, payload: bytes = b"abc") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(
        fileobj=buf, mode="w", encoding="utf-8", errors="surrogateescape"
    ) as tf:
        info = tarfile.TarInfo(stored_name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


# --- O2: casefold / normalization collisions -------------------------------


def test_o2_casefold_collision_strict_error_is_deterministic(tmp_path: Path) -> None:
    # README and readme are distinct in the archive but the same file on Windows/macOS.
    # Under STRICT the second is a deterministic collision on EVERY platform (on
    # case-sensitive Linux it would otherwise silently become a second file).
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        overwrite=OverwritePolicy.ERROR,
        on_error=OnError.CONTINUE,
    )
    statuses = [r.status for r in report.results]
    assert statuses == [ExtractionStatus.EXTRACTED, ExtractionStatus.FAILED]
    # The collision is recorded on the loser's own result: requested_path is the
    # destination it intended *before* resolution (its own spelling), and the error says
    # why it did not get it. path stays None — nothing of this member is on disk.
    assert report.results[1].requested_path == dest / "readme"
    assert report.results[1].path is None
    assert report.results[1].error is not None
    assert not _overwritten(report)  # ERROR never clobbers, so nothing is OVERWRITTEN


def test_o2_casefold_collision_strict_replace_no_silent_merge(tmp_path: Path) -> None:
    # REPLACE must not silently merge into two files on a case-sensitive FS: the second
    # member deterministically overwrites the first at one path, and it is recorded.
    # This is the case that was SILENT before extraction-results-authoritative — both
    # members reported a plain EXTRACTED at the same path.
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    on_disk = sorted(p.name for p in dest.iterdir())
    assert on_disk == ["README"]  # one file, not README + readme
    assert (dest / "README").read_bytes() == b"B"  # second member won

    first, second = report.results
    assert first.status is ExtractionStatus.OVERWRITTEN
    assert first.path is None  # nothing at that path is this member's content
    assert first.requested_path == dest / "README"  # ...but it did write there
    assert second.status is ExtractionStatus.EXTRACTED
    assert second.path == first.requested_path  # the join between the pair


def test_o2_collision_trusted_defers_to_local_os(tmp_path: Path) -> None:
    # TRUSTED keys on the exact path and never raises a collision event (it defers to the
    # OS). The deterministic, OS-independent assertion is "no member was clobbered".
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.TRUSTED,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert not _overwritten(report)
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)


def test_o2_nfc_nfd_collision_strict(tmp_path: Path) -> None:
    nfc = unicodedata.normalize("NFC", "café.txt")
    nfd = unicodedata.normalize("NFD", "café.txt")
    assert nfc != nfd
    archive = _tar_bytes([("file", nfc, b"A"), ("file", nfd, b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    assert len(_overwritten(report)) == 1
    assert len(list(dest.iterdir())) == 1


# --- O3/O4: reserved names, colon, trailing dot/space ----------------------


@pytest.mark.parametrize(
    "name", ["NUL", "nul", "COM1", "LPT9", "NUL.txt", "AUX.tar.gz"]
)
@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
def test_o3_reserved_name_rejected(tmp_path: Path, name: str, policy) -> None:
    archive = _tar_bytes([("file", name, b"x")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, policy=policy, on_error=OnError.CONTINUE
    )
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message.startswith("Windows-reserved device name in path")


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows itself refuses the NUL device name at write time; TRUSTED defers to "
    "the OS, so the 'written' outcome is a POSIX-only assertion (spec: 'written if the "
    "OS allows').",
)
def test_o3_reserved_name_written_under_trusted(tmp_path: Path) -> None:
    archive = _tar_bytes([("file", "NUL", b"x")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, policy=ExtractionPolicy.TRUSTED
    )
    # TRUSTED does not apply the O3 name rejection — the member is not BLOCKED by policy.
    assert report.results[0].status is ExtractionStatus.EXTRACTED
    assert (dest / "NUL").read_bytes() == b"x"


@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
def test_o4_colon_rejected_strict_and_standard(tmp_path: Path, policy) -> None:
    archive = _tar_bytes([("file", "file:hidden", b"x")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, policy=policy, on_error=OnError.CONTINUE
    )
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message.startswith("Colon in path segment")


@pytest.mark.parametrize("name,portable", [("foo.", "foo"), ("bar ", "bar")])
def test_o3_trailing_dot_space_stripped_strict_kept_standard(
    tmp_path: Path, name: str, portable: str
) -> None:
    archive = _tar_bytes([("file", name, b"x")])
    # STRICT rewrites the Windows-mangled shape to its portable spelling (a legitimate
    # macOS/Linux name, not an attack), extracts it, and surfaces the rename.
    strict = open_and_extract(
        io.BytesIO(archive), tmp_path / "strict", policy=ExtractionPolicy.STRICT
    )
    assert strict.results[0].status is ExtractionStatus.EXTRACTED
    assert sorted(p.name for p in (tmp_path / "strict").iterdir()) == [portable]
    # The rewrite is recorded on the result, not as a diagnostic: presented_name is the
    # spelling before the rewrite, path.name is what landed.
    assert strict.results[0].presented_name == name
    assert strict.results[0].path is not None
    assert strict.results[0].path.name == portable
    # STANDARD does NOT rewrite the name (so no presented_name) — it keeps it faithful.
    # The on-disk name is then the OS's call: POSIX writes it verbatim; Windows itself trims
    # the trailing dot/space, so we only assert the faithful on-disk name off Windows.
    standard = open_and_extract(
        io.BytesIO(archive), tmp_path / "standard", policy=ExtractionPolicy.STANDARD
    )
    assert standard.results[0].status is ExtractionStatus.EXTRACTED
    assert standard.results[0].presented_name is None
    if os.name != "nt":
        assert sorted(p.name for p in (tmp_path / "standard").iterdir()) == [name]


@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
@pytest.mark.parametrize(
    ("first", "second"), [("notes", "notes. "), ("d/x", "d./x")], ids=["file", "folder"]
)
def test_o3_trailing_dot_name_collides_with_trimmed_name(
    tmp_path: Path, policy: ExtractionPolicy, first: str, second: str
) -> None:
    # Win32 writes 'notes.' as 'notes', so the pair is one file there. STANDARD keeps the
    # name, and the collision must still be caught on every platform, as for README and
    # readme: ERROR fails the second member instead of a silent replace on Windows. The
    # trim applies to every segment, so a folder 'd.' meets 'd' too.
    archive = _tar_bytes([("file", first, b"A"), ("file", second, b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=policy,
        overwrite=OverwritePolicy.ERROR,
        on_error=OnError.CONTINUE,
    )
    statuses = [r.status for r in report.results]
    assert statuses == [ExtractionStatus.EXTRACTED, ExtractionStatus.FAILED]
    assert (dest / first).read_bytes() == b"A"
    assert sorted(p.name for p in dest.iterdir()) == [first.split("/")[0]]
    loser = report.results[1]
    assert loser.path is None
    assert loser.requested_path is not None
    assert loser.collided_with == dest / first


def test_o3_trailing_dot_rename_skips_trimmed_claim(tmp_path: Path) -> None:
    # RENAME derives 'notes (1). ' for the second member; its trimmed key 'notes (1)' must
    # be free too, or the renamed member would merge with a third on Windows.
    archive = _tar_bytes(
        [
            ("file", "notes", b"A"),
            ("file", "notes (1)", b"B"),
            ("file", "notes. ", b"C"),
        ]
    )
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.STANDARD,
        overwrite=OverwritePolicy.RENAME,
    )
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    third = report.results[2].path
    assert third is not None
    assert third.name.rstrip(". ") not in ("notes", "notes (1)")
    assert third.read_bytes() == b"C"


def test_o3_trailing_dot_directory_tree_stays_connected(tmp_path: Path) -> None:
    # The reported real-world case: a macOS folder named 'stuff_etc.' with a file inside.
    # STRICT must strip the same segment identically in the dir entry and its children, so
    # the tree stays connected (no orphaned files under a differently-named parent).
    archive = _tar_bytes(
        [
            ("dir", "codex/", None),
            ("dir", "codex/stuff_etc./", None),
            ("file", "codex/stuff_etc./owl.jpg", b"img"),
        ]
    )
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.STRICT)
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    assert (dest / "codex" / "stuff_etc" / "owl.jpg").read_bytes() == b"img"


def test_o3_all_dots_segment_rejected(tmp_path: Path) -> None:
    # A segment that is ENTIRELY dots/spaces has no portable spelling (stripping would
    # collapse the path), so it is still rejected rather than rewritten.
    archive = _tar_bytes([("file", "a/.../b.txt", b"x")])
    report = open_and_extract(
        io.BytesIO(archive),
        tmp_path / "out",
        policy=ExtractionPolicy.STRICT,
        on_error=OnError.CONTINUE,
    )
    assert report.results[0].status is ExtractionStatus.BLOCKED
    error = report.results[0].error
    assert isinstance(error, FilterRejectionError)
    assert error.message.startswith("Path segment is entirely dots/spaces")


def test_o3_strip_passes_through_bare_dot_root(tmp_path: Path) -> None:
    # A bare "." segment (the root dir; normalize_member_name maps a ZIP/TAR root "/" to
    # ".") is a path spelling, not a trailing-dot hazard — the strip must NOT collapse it to
    # empty and reject it. A "/"-rooted zip extracts cleanly under STRICT.
    archive = tmp_path / "rooted.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zipfile.ZipInfo("/"), b"")
        zf.writestr("a.txt", b"hello")
    report = open_and_extract(archive, tmp_path / "out", policy=ExtractionPolicy.STRICT)
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"hello"


def test_o3_bare_dot_root_not_trailing_dot_under_strict() -> None:
    # normalize_member_name maps a bare ZIP/TAR root ("/") to "." — that is a path
    # segment spelling, not a Win32 trailing-dot hazard like "foo.".
    member = _member(".", type=MemberType.DIRECTORY)
    assert apply_name_policy(member, ExtractionPolicy.STRICT) is member


# --- O7: surrogateescape sanitize ------------------------------------------


def test_o7_surrogateescape_sanitized_under_strict(tmp_path: Path) -> None:
    # caf<0xe9>.txt carries a raw non-UTF-8 byte; STRICT rewrites it to a portable spelling
    # deterministically on every OS (rather than depending on whether the FS accepts it).
    stored = b"caf\xe9.txt".decode("utf-8", errors="surrogateescape")
    archive = _surrogate_tar(stored)
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.STRICT)
    assert report.results[0].status is ExtractionStatus.EXTRACTED
    assert sorted(p.name for p in dest.iterdir()) == ["caf%E9.txt"]


def test_o7_percent_escaped_when_sanitizing(tmp_path: Path) -> None:
    # A literal '%' in a name that also carries a non-UTF-8 byte is escaped as %25 so the
    # spelling is unambiguously reversible.
    stored = b"a%b\xe9".decode("utf-8", errors="surrogateescape")
    archive = _surrogate_tar(stored)
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.STRICT)
    assert sorted(p.name for p in dest.iterdir()) == ["a%25b%E9"]
    assert report.results[0].status is ExtractionStatus.EXTRACTED


def test_o7_plain_percent_name_untouched(tmp_path: Path) -> None:
    # A name with no non-UTF-8 bytes is never rewritten, even if it contains '%'.
    archive = _tar_bytes([("file", "50%.txt", b"x")])
    dest = tmp_path / "out"
    open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.STRICT)
    assert sorted(p.name for p in dest.iterdir()) == ["50%.txt"]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("foo. /bar", "foo/bar"),
        ("foo. \\bar", "foo/bar"),
        ("a\\b.\\c ", "a/b/c"),
        ("mixed. /x \\y.", "mixed/x/y"),
    ],
)
def test_o3_strip_treats_a_backslash_as_a_separator(name: str, expected: str) -> None:
    """Trailing dot/space stripping splits on ``\\`` too, like the rest of the module.

    TAR keeps ``\\`` as a literal character and Windows writes it as a separator, so
    ``foo. \\bar`` has to lose its trailing space as ``foo. /bar`` does. The name
    policy then writes each ``\\`` as ``/``, so the result is the same on every OS.
    """
    out = apply_name_policy(_member(name), ExtractionPolicy.STRICT)
    assert out.name == expected


@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
@pytest.mark.parametrize("name", ["a/.../b", "a/ /b", "a\\...\\b", "a/. \\b"])
def test_o3_all_dots_segment_rejected_after_either_separator(
    name: str, policy: ExtractionPolicy
) -> None:
    # STANDARD keeps a trailing dot, but a segment of only dots or spaces has no
    # spelling Win32 keeps: 'a/.../b' would merge into 'a/b' there.
    with pytest.raises(FilterRejectionError, match="entirely dots/spaces"):
        apply_name_policy(_member(name), policy)


# --- OverwritePolicy.RENAME ------------------------------------------------


def test_rename_inserts_counter_before_suffix(tmp_path: Path) -> None:
    # RENAME applies to destination collisions, not archive duplicate names
    # (duplicates are SUPERSEDED / last-entry-wins instead).
    archive = _tar_bytes([("file", "photo.jpg", b"from-archive")])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "photo.jpg").write_bytes(b"preexisting")
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )
    assert len(report.results) == 1
    assert report.results[0].status is ExtractionStatus.EXTRACTED
    assert sorted(p.name for p in dest.iterdir()) == [
        "photo (1).jpg",
        "photo.jpg",
    ]
    assert (dest / "photo.jpg").read_bytes() == b"preexisting"
    assert (dest / "photo (1).jpg").read_bytes() == b"from-archive"
    # The rename is observable via requested_path != path.
    written = report.results[0]
    assert written.path.name == "photo (1).jpg"
    assert written.requested_path.name == "photo.jpg"
    assert written.requested_path != written.path


@pytest.mark.parametrize(
    "name,expected",
    [
        (".bashrc", ".bashrc (1)"),  # leading-dot dotfile: no suffix split
        ("archive.tar.gz", "archive.tar (1).gz"),  # single final suffix
        ("noext", "noext (1)"),  # no suffix
    ],
)
def test_rename_suffix_edge_cases(tmp_path: Path, name: str, expected: str) -> None:
    archive = _tar_bytes([("file", name, b"from-archive")])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / name).write_bytes(b"preexisting")
    open_and_extract(io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME)
    assert expected in {p.name for p in dest.iterdir()}
    assert (dest / name).read_bytes() == b"preexisting"


def _case_variants(word: str) -> list[str]:
    """Every upper/lower spelling of ``word``: distinct names, one collision key."""
    out = [""]
    for ch in word:
        out = [prefix + c for prefix in out for c in (ch.lower(), ch.upper())]
    return out


def test_rename_resumes_the_counter_instead_of_rescanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``k`` members colliding on one key cost ``k`` probes, not ``k²``.

    64 case variants of one name, under STRICT, all share a collision key. Restarting
    at ``(1)`` for each made the k-th member walk ``(1)`` … ``(k)``, computing a
    collision key per probe: about 2000 here, and hours for an archive of a few hundred
    KB. Resuming from the last ``N`` keeps it to one probe per member.
    """
    import archivey.internal.extraction as extraction_mod

    names = [f"{v}.txt" for v in _case_variants("abcdef")]
    archive = _tar_bytes([("file", n, n.encode()) for n in names])

    probes = 0
    real_collision_key = extraction_mod.collision_key

    def counting_collision_key(name: str, policy: ExtractionPolicy) -> str:
        nonlocal probes
        if " (" in name:
            probes += 1
        return real_collision_key(name, policy)

    monkeypatch.setattr(extraction_mod, "collision_key", counting_collision_key)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )

    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    # One derived name tried per colliding member, plus the claim registered for it.
    # Rescanning from (1) made this about 2000.
    assert probes <= 2 * (len(names) - 1)
    assert report.results[0].path == dest / "abcdef.txt"
    derived = sorted(
        int(r.path.name.rsplit("(", 1)[1].split(")")[0])
        for r in report.results[1:]
        if r.path is not None
    )
    assert derived == list(range(1, len(names)))


def test_rename_resume_skips_a_name_already_on_disk(tmp_path: Path) -> None:
    """Resuming does not skip the on-disk check: a pre-existing ``(2)`` is stepped over.

    The counter only says which names this run has already taken; a name someone put in
    the destination beforehand is found by the ``lstat`` exactly as before.
    """
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "aB (2).txt").write_bytes(b"pre-existing")
    archive = _tar_bytes(
        [("file", "ab.txt", b"0"), ("file", "Ab.txt", b"1"), ("file", "aB.txt", b"2")]
    )
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )
    assert [r.path.name for r in report.results if r.path is not None] == [
        "ab.txt",
        "Ab (1).txt",
        "aB (3).txt",
    ]
    assert (dest / "aB (2).txt").read_bytes() == b"pre-existing"


@pytest.mark.parametrize("obstacle", ["file", "symlink"])
def test_rename_directory_over_a_non_directory_keeps_it(
    tmp_path: Path, obstacle: str
) -> None:
    """A directory member landing on a file or symlink is renamed, never deletes it.

    RENAME used to fall through to REPLACE's unlink for directory members, so the
    caller's file was removed and the directory reported EXTRACTED with no rename.
    The derived name appends to the whole segment, and the members inside the
    directory follow it there.
    """
    dest = tmp_path / "out"
    dest.mkdir()
    if obstacle == "file":
        (dest / "dd.d").write_bytes(b"keep")
    else:
        (dest / "target").write_bytes(b"keep")
        (dest / "dd.d").symlink_to("target")
    archive = _tar_bytes(
        [("dir", "dd.d", None), ("file", "dd.d/f", b"inner"), ("dir", "dd.d/s", None)]
    )
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )

    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    if obstacle == "file":
        assert (dest / "dd.d").read_bytes() == b"keep"
    else:
        assert os.readlink(dest / "dd.d") == "target"
        assert (dest / "target").read_bytes() == b"keep"
    renamed = dest / "dd.d (1)"
    assert renamed.is_dir()
    assert (renamed / "f").read_bytes() == b"inner"
    assert (renamed / "s").is_dir()
    directory, inner, subdir = report.results
    assert directory.path == renamed
    assert directory.requested_path == dest / "dd.d"
    assert directory.collided_with is None  # a pre-existing obstacle, not this run's
    assert inner.path == renamed / "f"
    assert inner.requested_path == dest / "dd.d" / "f"
    assert subdir.path == renamed / "s"


def test_rename_directory_over_a_file_this_run_wrote(tmp_path: Path) -> None:
    """A directory member colliding with a file this run wrote is a collision event."""
    archive = _tar_bytes([("file", "x", b"first"), ("dir", "x", None)])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )
    first, directory = report.results
    assert first.status is ExtractionStatus.EXTRACTED
    assert (dest / "x").read_bytes() == b"first"
    assert directory.status is ExtractionStatus.EXTRACTED
    assert directory.path == dest / "x (1)"
    assert directory.path.is_dir()
    assert directory.collided_with == dest / "x"


def _zip_bytes(specs: list[tuple]) -> bytes:
    """A zip from the same (kind, name, payload) specs as ``_tar_bytes`` (files and
    directories only), read with random access rather than as a stream."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # duplicate names are the point
        with zipfile.ZipFile(buf, "w") as z:
            for kind, name, payload in specs:
                if kind == "dir":
                    z.writestr(name.rstrip("/") + "/", b"")
                else:
                    z.writestr(name, payload)
    return buf.getvalue()


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_rename_file_named_like_a_renamed_directory_is_not_inside_it(
    tmp_path: Path, build
) -> None:
    """A file that only shares a renamed directory's name takes the next free name.

    The renamed-directory lookup used to match the member's own path, so the file was
    sent onto the directory's derived name and renamed again from there: ``dd (1) (1)``,
    a name no member asked for. ``dd`` is the caller's and ``dd (1)`` this run's
    directory, so the file belongs at ``dd (2)``.
    """
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "dd").write_bytes(b"callers")
    archive = build([("dir", "dd/", None), ("file", "dd", b"member")])
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )

    directory, member = report.results
    assert directory.path == dest / "dd (1)"
    assert member.status is ExtractionStatus.EXTRACTED
    assert member.requested_path == dest / "dd"
    assert member.path == dest / "dd (2)"
    assert (dest / "dd (2)").read_bytes() == b"member"
    assert (dest / "dd").read_bytes() == b"callers"
    assert not (dest / "dd (1) (1)").exists()


def test_rename_file_after_a_directory_that_went_around_it(tmp_path: Path) -> None:
    """``[file x, dir x/, file x]``: the later ``x`` replaces the first, not ``x (1)/``.

    The directory collided with the first ``x`` and went to ``x (1)/``. The later
    ``x`` is a second copy of the first, so it lands at ``x`` again; it used to follow
    the directory to ``x (1) (1)`` and leave nothing at ``x``.
    """
    archive = _tar_bytes(
        [("file", "x", b"1"), ("dir", "x/", None), ("file", "x", b"3")]
    )
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )

    first, directory, last = report.results
    assert first.status is ExtractionStatus.SUPERSEDED
    assert directory.path == dest / "x (1)"
    assert last.status is ExtractionStatus.EXTRACTED
    assert last.path == dest / "x"
    assert (dest / "x").read_bytes() == b"3"
    assert not (dest / "x (1) (1)").exists()


def test_rename_second_copy_of_a_renamed_directory_merges_into_it(
    tmp_path: Path,
) -> None:
    """A directory member does match its own renamed path: a second ``dd/`` merges.

    In a streaming pass the first copy is still in place, superseded, when the second
    arrives, so without the self-match the second copy would get a name of its own and
    split the tree between ``dd (1)/`` and ``dd (2)/``.
    """
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "dd").write_bytes(b"callers")
    archive = _tar_bytes(
        [
            ("dir", "dd/", None),
            ("file", "dd/f", b"1"),
            ("dir", "dd/", None),
            ("file", "dd/g", b"2"),
        ]
    )
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.RENAME
    )

    assert [r.status for r in report.results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.EXTRACTED,
    ]
    assert report.results[2].path == dest / "dd (1)"
    assert (dest / "dd (1)" / "f").read_bytes() == b"1"
    assert (dest / "dd (1)" / "g").read_bytes() == b"2"
    assert sorted(p.name for p in dest.iterdir()) == ["dd", "dd (1)"]


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_replace_directory_over_a_file_this_run_wrote_revises_it(
    tmp_path: Path, build
) -> None:
    """REPLACE: a directory member that removes a file this run wrote revises that
    member to OVERWRITTEN, as any other replacement does, instead of leaving it
    reporting EXTRACTED at a path that now holds a directory."""
    archive = build([("file", "x", b"first"), ("dir", "x/", None)])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )

    first, directory = report.results
    assert first.status is ExtractionStatus.OVERWRITTEN
    assert directory.status is ExtractionStatus.EXTRACTED
    assert directory.path == dest / "x"
    assert directory.requested_path == dest / "x"
    assert directory.collided_with == dest / "x"
    assert (dest / "x").is_dir()


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_replace_file_over_an_empty_directory_this_run_wrote_revises_it(
    tmp_path: Path, build
) -> None:
    """REPLACE: a file member that removes an empty directory this run wrote revises
    that directory's result to OVERWRITTEN, instead of leaving it reporting EXTRACTED
    at a path that now holds a file. The file collided with that directory, so
    ``collided_with`` names it, which joins to the directory's ``requested_path``."""
    archive = build([("dir", "x/", None), ("file", "x", b"file")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )

    directory, member = report.results
    assert directory.status is ExtractionStatus.OVERWRITTEN
    assert directory.path is None
    assert directory.requested_path == dest / "x"
    assert member.status is ExtractionStatus.EXTRACTED
    assert member.path == dest / "x"
    assert member.collided_with == dest / "x"
    assert (dest / "x").read_bytes() == b"file"


_DIRECTORY_THEN_FILE = {
    "explicit": [("dir", "x/", None), ("file", "x/f", b"in"), ("file", "x", b"file")],
    "implicit": [("file", "x/f", b"in"), ("file", "x", b"file")],
}


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
@pytest.mark.parametrize("shape", list(_DIRECTORY_THEN_FILE))
@pytest.mark.parametrize(
    ("overwrite", "status"),
    [
        (OverwritePolicy.ERROR, ExtractionStatus.FAILED),
        (OverwritePolicy.SKIP, ExtractionStatus.NOT_OVERWRITTEN),
        # The directory holds ``x/f``, so REPLACE does not remove it.
        (OverwritePolicy.REPLACE, ExtractionStatus.FAILED),
        (OverwritePolicy.RENAME, ExtractionStatus.EXTRACTED),
    ],
)
def test_file_over_a_directory_this_run_wrote_records_the_collision(
    tmp_path: Path,
    build,
    shape: str,
    overwrite: OverwritePolicy,
    status: ExtractionStatus,
) -> None:
    """A file member landing on a directory this run made, from a directory entry or
    as the parent of an earlier member, collided with it under every policy:
    ``collided_with`` names the directory, as it names a file this run wrote. The
    directory and what it holds are kept."""
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(build(_DIRECTORY_THEN_FILE[shape])),
        dest,
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )

    member = report.results[-1]
    assert member.member.name == "x"
    assert member.status is status
    assert member.requested_path == dest / "x"
    assert member.collided_with == dest / "x"
    if status is ExtractionStatus.EXTRACTED:
        assert member.path == dest / "x (1)"
    assert (dest / "x" / "f").read_bytes() == b"in"


@pytest.mark.parametrize("shape", list(_DIRECTORY_THEN_FILE))
def test_file_over_a_directory_this_run_wrote_is_no_collision_under_trusted(
    tmp_path: Path, shape: str
) -> None:
    """TRUSTED reports no collision event, for a directory as for a file."""
    report = open_and_extract(
        io.BytesIO(_tar_bytes(_DIRECTORY_THEN_FILE[shape])),
        tmp_path / "out",
        policy=ExtractionPolicy.TRUSTED,
        overwrite=OverwritePolicy.SKIP,
    )
    member = report.results[-1]
    assert member.status is ExtractionStatus.NOT_OVERWRITTEN
    assert member.collided_with is None


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX")
def test_file_over_a_run_directory_names_the_directory_as_its_member_spelled_it(
    tmp_path: Path,
) -> None:
    """The only directory member reached ``d/x`` as ``s/x`` through the archive's own
    ``s -> d``. ``collided_with`` is that member's ``path``, so it joins to its
    result, not the spelling the file member used."""
    archive = _tar_bytes(
        [
            ("dir", "d/", None),
            ("sym", "s", "d"),
            ("dir", "s/x/", None),
            ("file", "d/x", b"file"),
        ]
    )
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest, overwrite=OverwritePolicy.SKIP)
    directory, member = report.results[2:]
    assert directory.path == dest / "s" / "x"
    assert member.status is ExtractionStatus.NOT_OVERWRITTEN
    assert member.requested_path == dest / "d" / "x"
    assert member.collided_with == directory.path


def test_file_over_a_directory_already_there_is_no_collision(tmp_path: Path) -> None:
    """A directory that was in ``dest`` before the run is not this run's: the file
    meets it under SKIP with ``collided_with`` left ``None``."""
    dest = tmp_path / "out"
    (dest / "x").mkdir(parents=True)
    report = open_and_extract(
        io.BytesIO(_tar_bytes([("file", "x", b"file")])),
        dest,
        overwrite=OverwritePolicy.SKIP,
    )
    (member,) = report.results
    assert member.status is ExtractionStatus.NOT_OVERWRITTEN
    assert member.collided_with is None


def test_file_over_a_directory_already_there_is_no_collision_after_a_merge(
    tmp_path: Path,
) -> None:
    """A directory member that merges into a directory already in ``dest`` reports
    it, but the directory is still the caller's: a file landing on it afterwards
    gets ``collided_with`` ``None``, and ``NAME_COLLISION`` does not fire."""
    dest = tmp_path / "out"
    (dest / "x").mkdir(parents=True)
    report = open_and_extract(
        io.BytesIO(_tar_bytes([("dir", "x/", None), ("file", "x", b"file")])),
        dest,
        overwrite=OverwritePolicy.SKIP,
        abort_on={AbortOn.NAME_COLLISION},
    )
    directory, member = report.results
    assert directory.status is ExtractionStatus.EXTRACTED
    assert directory.path == dest / "x"
    assert member.status is ExtractionStatus.NOT_OVERWRITTEN
    assert member.collided_with is None


def test_replace_revises_a_directory_reached_through_the_archives_symlink(
    tmp_path: Path,
) -> None:
    """``s/sub/`` and ``d/sub/`` are one directory when ``s -> d``: removing it revises
    both results, not only the one spelled the way the replacing member spells it."""
    archive = _tar_bytes(
        [
            ("dir", "d/", None),
            ("sym", "s", "d"),
            ("dir", "s/sub/", None),
            ("dir", "d/sub/", None),
            ("file", "d/sub", b"file"),
        ]
    )
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )

    top, link, via_link, direct, member = report.results
    assert via_link.status is ExtractionStatus.OVERWRITTEN
    assert direct.status is ExtractionStatus.OVERWRITTEN
    assert top.status is ExtractionStatus.EXTRACTED
    assert link.status is ExtractionStatus.EXTRACTED
    assert member.status is ExtractionStatus.EXTRACTED
    assert member.collided_with == direct.requested_path == dest / "d" / "sub"
    assert (dest / "d" / "sub").read_bytes() == b"file"


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_replace_keeps_a_case_variant_directory_that_is_still_there(
    tmp_path: Path, build
) -> None:
    """The casefolded key also covers ``X/`` beside ``x/`` on a case-sensitive
    filesystem. Removing ``x/`` must not revise ``X/``, which is still on disk."""
    dest = tmp_path / "out"
    dest.mkdir()
    if not case_sensitive(dest):
        pytest.skip(
            "needs a case-sensitive filesystem, where X/ and x/ are two entries"
        )
    archive = build([("dir", "X/", None), ("dir", "x/", None), ("file", "x", b"f")])
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    upper, lower, member = report.results
    assert lower.status is ExtractionStatus.OVERWRITTEN
    assert upper.status is ExtractionStatus.EXTRACTED
    assert (dest / "X").is_dir()
    assert member.status is ExtractionStatus.EXTRACTED
    assert member.collided_with == lower.requested_path == dest / "x"


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_replace_revises_a_case_variant_directory_it_removed(
    tmp_path: Path, build
) -> None:
    """On a case-insensitive filesystem ``x`` lands on the entry ``X/`` made, so
    removing it revises ``X/``. The casefolded collision key is what finds it."""
    dest = tmp_path / "out"
    dest.mkdir()
    if case_sensitive(dest):
        pytest.skip("needs a case-insensitive filesystem, where X/ and x are one entry")
    archive = build([("dir", "X/", None), ("file", "x", b"f")])
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    directory, member = report.results
    assert directory.status is ExtractionStatus.OVERWRITTEN
    assert directory.path is None
    assert member.status is ExtractionStatus.EXTRACTED
    assert (dest / "x").read_bytes() == b"f"


@pytest.mark.parametrize("build", [_tar_bytes, _zip_bytes], ids=["tar", "zip"])
def test_progress_during_a_replace_follows_the_directory_it_removed(
    tmp_path: Path, build
) -> None:
    """While ``x`` replaces the empty ``x/`` this run wrote, ``members_extracted`` no
    longer counts ``x/``: the revision happens before the write, and the intra-member
    reports used to carry a tally copied before it."""
    archive = build([("dir", "x/", None), ("file", "x", b"\0" * (3 << 20))])
    reports: list[tuple[str, int, int]] = []
    open_and_extract(
        io.BytesIO(archive),
        tmp_path / "out",
        overwrite=OverwritePolicy.REPLACE,
        on_progress=lambda p: reports.append(
            (p.member.name, p.member_bytes_written, p.members_extracted)
        ),
    )
    during = [r for r in reports[:-1] if r[0] == "x"]
    assert during, reports
    assert all(extracted == 0 for _, _, extracted in during), reports
    assert reports[-1] == ("x", 3 << 20, 1)


def test_requested_path_equals_path_for_normal_write(tmp_path: Path) -> None:
    archive = _tar_bytes([("file", "a.txt", b"x")])
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest)
    result = report.results[0]
    assert result.requested_path == result.path == dest / "a.txt"


# --- Additional O2 edge cases (review follow-up) ---------------------------


def test_o2_casefold_collision_standard_replace_no_silent_merge(tmp_path: Path) -> None:
    # STANDARD collision-tracks exactly like STRICT (only TRUSTED defers).
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.STANDARD,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert sorted(p.name for p in dest.iterdir()) == ["README"]
    assert (dest / "README").read_bytes() == b"B"
    assert len(_overwritten(report)) == 1


def test_o7_sanitized_name_collides_with_literal_percent_name(tmp_path: Path) -> None:
    # A surrogateescape name sanitizes to caf%E9.txt, which must collide with a member
    # literally named caf%E9.txt (the sanitized spelling feeds the collision map).
    literal = "caf%E9.txt"
    surro = b"caf\xe9.txt".decode("utf-8", errors="surrogateescape")
    buf = io.BytesIO()
    with tarfile.open(
        fileobj=buf, mode="w", encoding="utf-8", errors="surrogateescape"
    ) as tf:
        for nm, data in [(literal, b"A"), (surro, b"B")]:
            info = tarfile.TarInfo(nm)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(buf.getvalue()), dest, overwrite=OverwritePolicy.REPLACE
    )
    assert sorted(p.name for p in dest.iterdir()) == ["caf%E9.txt"]
    assert len(_overwritten(report)) == 1
    # The member that won carries both signals: it was rewritten (presented_name is the
    # surrogateescape spelling) and it clobbered the literal-percent member.
    assert report.results[1].presented_name == surro
    assert report.results[0].status is ExtractionStatus.OVERWRITTEN


def test_o2_orphan_hardlink_honours_collision_map(tmp_path: Path) -> None:
    # Deferred (orphaned) hardlink recovery must not bypass the collision map: a hardlink
    # whose source is excluded is orphaned before its casefold-partner file is written, so
    # the second pass has to re-check the (now-populated) map instead of silently writing a
    # second casefold-equivalent file on a case-sensitive FS.
    archive = _tar_bytes(
        [
            ("file", "src.bin", b"data"),
            ("hard", "readme", "src.bin"),
            ("file", "README", b"other"),
        ]
    )
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive)) as reader:
        report = reader.extract_all(
            dest,
            overwrite=OverwritePolicy.REPLACE,
            members=lambda m: (
                m.name != "src.bin"
            ),  # exclude the source -> readme orphans
        )
    # One casefold-equivalent file, not README + readme.
    assert sorted(p.name for p in dest.iterdir()) == ["README"]
    # The deferred link won the contested destination, so the first-pass writer is the
    # one revised to OVERWRITTEN — the second pass revises results just like the first.
    assert len(_overwritten(report)) == 1
    assert _overwritten(report)[0].member.name == "README"


def test_o2_orphan_hardlink_collision_split_under_trusted(tmp_path: Path) -> None:
    # TRUSTED defers: readme and README are distinct on a case-sensitive FS, so the orphan
    # recovery writes both (no collision event). Asserts the OS-independent invariant that
    # TRUSTED raises no collision diagnostic.
    archive = _tar_bytes(
        [
            ("file", "src.bin", b"data"),
            ("hard", "readme", "src.bin"),
            ("file", "README", b"other"),
        ]
    )
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive)) as reader:
        report = reader.extract_all(
            dest,
            policy=ExtractionPolicy.TRUSTED,
            overwrite=OverwritePolicy.REPLACE,
            members=lambda m: m.name != "src.bin",
        )
    assert not _overwritten(report)


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_o2_hardlink_folded_onto_its_own_source(
    tmp_path: Path, streaming: bool
) -> None:
    # `A` folds onto `a` under STRICT and STANDARD, so REPLACE routes the link onto the
    # path its own source was written to. The link wins that path as any later member
    # would: the source is revised to OVERWRITTEN, and the file keeps its content.
    archive = _tar_bytes([("file", "a", b"data"), ("hard", "A", "a")])
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
        report = reader.extract_all(
            dest, overwrite=OverwritePolicy.REPLACE, on_error=OnError.CONTINUE
        )
    assert [(r.member.name, r.status) for r in report.results] == [
        ("a", ExtractionStatus.OVERWRITTEN),
        ("A", ExtractionStatus.EXTRACTED),
    ]
    assert report.results[1].path == dest / "a"
    assert sorted(p.name for p in dest.iterdir()) == ["a"]
    assert (dest / "a").read_bytes() == b"data"


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_duplicate_hardlink_name_under_replace_leaves_no_temp(
    tmp_path: Path, streaming: bool, policy: ExtractionPolicy
) -> None:
    # The first `b` is superseded and parked at its name, which keeps the source's
    # inode but is no longer a recorded source path. The second `b` is then linked
    # onto another name of the same file, where rename(2) does nothing; the temp
    # name was left behind.
    archive = _tar_bytes(
        [("file", "a", b"data"), ("hard", "b", "a"), ("hard", "b", "a")]
    )
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive), streaming=streaming) as reader:
        report = reader.extract_all(
            dest,
            policy=policy,
            overwrite=OverwritePolicy.REPLACE,
            on_error=OnError.CONTINUE,
        )
    assert [(r.member.name, r.status) for r in report.results] == [
        ("a", ExtractionStatus.EXTRACTED),
        ("b", ExtractionStatus.SUPERSEDED),
        ("b", ExtractionStatus.EXTRACTED),
    ]
    assert sorted(p.name for p in dest.iterdir()) == ["a", "b"]
    assert os.path.samefile(dest / "a", dest / "b")


def test_o2_orphan_hardlinks_folded_onto_each_other(tmp_path: Path) -> None:
    # The second pass writes the excluded source's content at `L`; `l` folds onto it.
    # Under REPLACE `l` takes that path, and `L` is revised to OVERWRITTEN.
    archive = _tar_bytes(
        [("file", "src", b"data"), ("hard", "L", "src"), ("hard", "l", "src")]
    )
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive)) as reader:
        report = reader.extract_all(
            dest,
            members=["L", "l"],
            overwrite=OverwritePolicy.REPLACE,
            on_error=OnError.CONTINUE,
        )
    assert [(r.member.name, r.status) for r in report.results] == [
        ("L", ExtractionStatus.OVERWRITTEN),
        ("l", ExtractionStatus.EXTRACTED),
    ]
    assert report.results[1].path == dest / "L"
    assert sorted(p.name for p in dest.iterdir()) == ["L"]
    assert (dest / "L").read_bytes() == b"data"


# ---------------------------------------------------------------------------
# Bidi override/isolate names are refused; directional marks are not
# ---------------------------------------------------------------------------


def _tar_with_member(path: Path, name: str, *, link_target: str | None = None) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        if link_target is None:
            info = tarfile.TarInfo(name)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"abc"))
        else:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = link_target
            tar.addfile(info)
    path.write_bytes(buf.getvalue())
    return path


@pytest.mark.parametrize(
    "name",
    ["invoice\u202ecod.exe", "a\u2066b.txt", "x\u202ay", "z\u202c.bin"],
    ids=["rlo", "lri", "lre", "pdf"],
)
@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD])
def test_bidi_override_name_is_refused_by_default(
    name: str, policy: ExtractionPolicy, tmp_path: Path
) -> None:
    """The reordering controls make a name display as something it is not.

    Refused at the default policy and at `STANDARD`. Like every other name rejection it
    surfaces as a `BLOCKED` result rather than a raised error at the `extract_all()` level —
    `OnError` governs failures, not blocks.
    """
    src = _tar_with_member(tmp_path / "a.tar", name)
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, policy=policy, on_error=OnError.STOP)
    (result,) = report.results
    assert result.status is ExtractionStatus.BLOCKED
    assert not list(dest.rglob("*"))


@pytest.mark.parametrize(
    "name",
    ["invoice\u202ecod.exe", "a\u2066b.txt", "x\u202ay", "z\u202c.bin"],
    ids=["rlo", "lri", "lre", "pdf"],
)
def test_bidi_override_name_extracts_under_trusted(name: str, tmp_path: Path) -> None:
    """`TRUSTED` lets a deceptive name through, deliberately (ADR 0017).

    The rejection is **policy-keyed**, not universal, and this is the half that says so.
    Unlike everything in `check_universal` — traversal, absolute paths, NUL, a device
    node — the write itself is completely safe here: the file lands inside `dest` under
    exactly its stored bytes, and only a human reading the directory afterwards is
    misled. `ExtractionPolicy` is the axis that owns name rejection, and `TRUSTED`
    already means "faithful bytes, no name rejection or rewrite".

    Without this, a caller who genuinely wants the bytes — a mirroring tool, a format
    converter, a forensic extract — has no route at any policy, which is what ADR 0013
    rejected for unrepresentable names ("extracting beats refusing").
    """
    src = _tar_with_member(tmp_path / "a.tar", name)
    dest = tmp_path / "out"
    report = open_and_extract(
        src, dest, policy=ExtractionPolicy.TRUSTED, on_error=OnError.STOP
    )
    (result,) = report.results
    assert result.status is ExtractionStatus.EXTRACTED
    assert (dest / name).is_file()  # faithful bytes: stored name, unmodified


@pytest.mark.parametrize(
    "name", ["invoice\u202ecod.exe", "a\u2066b.txt"], ids=["rlo", "lri"]
)
def test_apply_name_policy_rejects_bidi_override(name: str, tmp_path: Path) -> None:
    """The typed error itself, at the boundary that produces it.

    `apply_name_policy`, not `check_universal`: the check is policy-keyed (ADR 0017), so
    it lives with the other name-safety rules rather than with the path-escape ones.
    Pinned at this boundary so a move back to `check_universal` — which would silently
    re-break `TRUSTED` — fails here.
    """
    from archivey.exceptions import FilterRejectionError
    from archivey.internal.filters import apply_name_policy

    check_universal(_member(name), tmp_path)  # not a universal violation
    with pytest.raises(FilterRejectionError, match="^Bidirectional override"):
        apply_name_policy(_member(name), ExtractionPolicy.STRICT)
    assert (
        apply_name_policy(_member(name), ExtractionPolicy.TRUSTED).name == name
    )  # unchanged


def test_bidi_override_in_a_symlink_target_is_refused(tmp_path: Path) -> None:
    """The same disguise with an extra hop: a plausible-looking target on disk."""
    from archivey.exceptions import FilterRejectionError
    from archivey.internal.filters import apply_name_policy

    member = _member("link", type=MemberType.SYMLINK, link_target="rea\u202edm.txt")
    check_universal(member, tmp_path)  # not a universal violation
    with pytest.raises(FilterRejectionError):
        apply_name_policy(member, ExtractionPolicy.STRICT)

    src = _tar_with_member(tmp_path / "a.tar", "link", link_target="rea\u202edm.txt")
    dest = tmp_path / "out"
    report = open_and_extract(src, dest, on_error=OnError.STOP)
    assert report.results[0].status is ExtractionStatus.BLOCKED
    assert not list(dest.rglob("*"))


@pytest.mark.parametrize(
    "name",
    ["\u200fdoc.pdf", "\u200etotal-2024.txt", "\u061cفهرس.txt"],
    ids=["rlm", "lrm", "alm"],
)
def test_bidi_directional_marks_still_extract(name: str, tmp_path: Path) -> None:
    """The regression this change is most at risk of causing.

    The library's advisory set contains all twelve bidi codepoints, marks included.
    Rejecting *that* set would break legitimate Arabic and Hebrew filenames, which is
    why the reject set is the two override/isolate ranges written out explicitly.
    Marks reorder nothing; they only set the direction of one neutral character.
    """
    src = _tar_with_member(tmp_path / "a.tar", name)
    dest = tmp_path / "out"
    open_and_extract(src, dest, on_error=OnError.STOP)
    assert [p.name for p in dest.iterdir()] == [name]


def test_rtl_script_without_controls_extracts_silently(tmp_path: Path) -> None:
    """RTL *script* is not a bidi control: the direction comes from the letters."""
    name = "فهرس.txt"  # فهرس.txt
    src = _tar_with_member(tmp_path / "a.tar", name)
    dest = tmp_path / "out"
    with open_archive(src) as reader:
        reader.members()
        assert DiagnosticCode.MEMBER_NAME_BIDI_CONTROL not in reader.diagnostics.counts
    open_and_extract(src, dest, on_error=OnError.STOP)
    assert [p.name for p in dest.iterdir()] == [name]


def test_bidi_override_is_a_blocked_result_under_continue(tmp_path: Path) -> None:
    """It inherits the whole `FilterRejectionError` lifecycle, which is what a batch wants."""
    src = _tar_with_member(tmp_path / "a.tar", "invoice\u202ecod.exe")
    report = open_and_extract(src, tmp_path / "out", on_error=OnError.CONTINUE)
    (result,) = report.results
    assert result.status is ExtractionStatus.BLOCKED
    assert result.path is None


# ---------------------------------------------------------------------------
# extraction-results-authoritative: results are the sole record, and abort_on
# is the named replacement for the escalation that left with the diagnostics.
# ---------------------------------------------------------------------------


def test_three_spellings_filter_rename_then_portable_rewrite(tmp_path: Path) -> None:
    """A caller filter rename followed by a portable rewrite produces three names.

    ``member.name`` is the archive's, ``presented_name`` is the filter's output, and
    ``path.name`` is what landed. Only ``presented_name`` records the middle one, which
    is why the rewrite could not be expressed as ``requested_path != path``.
    """
    archive = _tar_bytes([("file", "orig.txt", b"x")])
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(archive)) as reader:
        report = reader.extract_all(
            dest,
            policy=ExtractionPolicy.STRICT,
            filter=lambda m: m.replace(name="renamed."),  # trailing dot -> rewritten
        )
    (result,) = report.results
    assert result.member.name == "orig.txt"
    assert result.presented_name == "renamed."
    assert result.path is not None
    assert result.path.name == "renamed"
    # The rewrite is independent of the rename marker: this member was not renamed by a
    # collision, so requested_path still equals path.
    assert result.requested_path == result.path


def test_abort_on_name_collision_replace(tmp_path: Path) -> None:
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    with pytest.raises(NameCollisionError):
        open_and_extract(
            io.BytesIO(archive),
            dest,
            overwrite=OverwritePolicy.REPLACE,
            abort_on={AbortOn.NAME_COLLISION},
        )
    # Abort stops the run, it does not roll it back: the first member's bytes remain.
    assert (dest / "README").read_bytes() == b"A"


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.REPLACE,
        OverwritePolicy.SKIP,
        OverwritePolicy.ERROR,
        OverwritePolicy.RENAME,
    ],
)
def test_abort_on_name_collision_fires_on_every_resolution(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """The trigger is the collision, not its outcome — parity with the escalation this
    replaces, which fired on all four resolutions."""
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    with pytest.raises(NameCollisionError):
        open_and_extract(
            io.BytesIO(archive),
            tmp_path / "out",
            overwrite=overwrite,
            on_error=OnError.CONTINUE,
            abort_on={AbortOn.NAME_COLLISION},
        )


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.REPLACE,
        OverwritePolicy.SKIP,
        OverwritePolicy.ERROR,
        OverwritePolicy.RENAME,
    ],
)
def test_abort_on_name_collision_fires_for_a_directory_member(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """A directory member landing on a file this run wrote is a collision too, under
    every resolution: the abort follows the collision, not the policy."""
    archive = _tar_bytes([("file", "x", b"A"), ("dir", "x/", None)])
    dest = tmp_path / "out"
    with pytest.raises(NameCollisionError) as excinfo:
        open_and_extract(
            io.BytesIO(archive),
            dest,
            overwrite=overwrite,
            on_error=OnError.CONTINUE,
            abort_on={AbortOn.NAME_COLLISION},
        )
    assert excinfo.value.member_name == "x/"
    assert (dest / "x").read_bytes() == b"A"


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.REPLACE,
        OverwritePolicy.SKIP,
        OverwritePolicy.ERROR,
        OverwritePolicy.RENAME,
    ],
)
@pytest.mark.parametrize("parent", ["explicit", "implicit"])
def test_abort_on_name_collision_fires_for_a_file_over_a_run_directory(
    tmp_path: Path, overwrite: OverwritePolicy, parent: str
) -> None:
    """A file member landing on a directory this run wrote, or created as a parent,
    is a collision too, under every resolution. The abort comes before the policy
    touches the directory, so an empty one is not removed under REPLACE."""
    entries = [("file", "x", b"B")]
    if parent == "explicit":
        entries.insert(0, ("dir", "x/", None))
    else:
        entries.insert(0, ("file", "x/f", b"A"))
    dest = tmp_path / "out"
    with pytest.raises(NameCollisionError) as excinfo:
        open_and_extract(
            io.BytesIO(_tar_bytes(entries)),
            dest,
            overwrite=overwrite,
            on_error=OnError.CONTINUE,
            abort_on={AbortOn.NAME_COLLISION},
        )
    assert excinfo.value.member_name == "x"
    assert "with a directory this run created at" in str(excinfo.value)
    assert (dest / "x").is_dir()


def test_abort_on_name_collision_not_triggered_by_a_directory_under_trusted(
    tmp_path: Path,
) -> None:
    """TRUSTED has no collision events, for a directory member as for a file."""
    archive = _tar_bytes([("file", "x", b"A"), ("dir", "x/", None)])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.TRUSTED,
        overwrite=OverwritePolicy.RENAME,
        abort_on={AbortOn.NAME_COLLISION},
    )
    directory = report.results[1]
    assert directory.path == dest / "x (1)"
    assert directory.collided_with is None


def test_abort_on_name_collision_not_triggered_under_trusted(tmp_path: Path) -> None:
    """TRUSTED keys on the exact path, so there is no collision event to abort on."""
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.TRUSTED,
        overwrite=OverwritePolicy.REPLACE,
        abort_on={AbortOn.NAME_COLLISION},
    )
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)


def test_abort_on_name_sanitized(tmp_path: Path) -> None:
    archive = _tar_bytes([("file", "foo.", b"x"), ("file", "later.txt", b"y")])
    dest = tmp_path / "out"
    with pytest.raises(NameRewrittenError):
        open_and_extract(
            io.BytesIO(archive),
            dest,
            policy=ExtractionPolicy.STRICT,
            abort_on={AbortOn.NAME_SANITIZED},
        )
    assert not (dest / "later.txt").exists()  # no later member processed


def test_name_sanitized_without_opt_in_is_a_success(tmp_path: Path) -> None:
    archive = _tar_bytes([("file", "foo.", b"x")])
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(archive), dest, policy=ExtractionPolicy.STRICT)
    assert report.results[0].status is ExtractionStatus.EXTRACTED
    assert report.results[0].presented_name == "foo."


def test_abort_on_is_independent_of_on_error(tmp_path: Path) -> None:
    """A blocked member aborts under either OnError when BLOCKED_MEMBER is set, and
    never aborts when it is not."""
    archive = _tar_bytes([("file", "NUL", b"x"), ("file", "ok.txt", b"y")])
    for on_error in (OnError.STOP, OnError.CONTINUE):
        dest = tmp_path / f"abort-{on_error.value}"
        with pytest.raises(FilterRejectionError):
            open_and_extract(
                io.BytesIO(archive),
                dest,
                on_error=on_error,
                abort_on={AbortOn.BLOCKED_MEMBER},
            )
        assert not (dest / "ok.txt").exists()
    for on_error in (OnError.STOP, OnError.CONTINUE):
        dest = tmp_path / f"noabort-{on_error.value}"
        report = open_and_extract(io.BytesIO(archive), dest, on_error=on_error)
        assert report.results[0].status is ExtractionStatus.BLOCKED
        assert (dest / "ok.txt").read_bytes() == b"y"


def test_hardlink_failure_group_is_recorded_on_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One failed source, N failed links: the fan-out correlation lives on the results.

    Previously carried by ``ExtractionOutcomeContext``; after the move, results are the
    only place a caller can tell "N separate failures" from "one failure seen N times".
    ``requested_path`` must survive the second-pass rebuild too — the first pass set it.
    """
    archive = _tar_bytes(
        [
            ("file", "src.bin", b"data"),
            ("hard", "link1", "src.bin"),
            ("hard", "link2", "src.bin"),
        ]
    )
    dest = tmp_path / "out"

    def boom(*args: object, **kwargs: object) -> None:
        raise ExtractionError("forced second-pass failure")

    # Failing the copy, after the temp file exists: a failure of the source's data.
    monkeypatch.setattr(ExtractionCoordinator, "_copy_to_fileobj", staticmethod(boom))
    with open_archive(io.BytesIO(archive)) as reader:
        report = reader.extract_all(
            dest,
            on_error=OnError.CONTINUE,
            members=lambda m: m.name != "src.bin",  # orphan both links
        )
    failed = [r for r in report.results if r.status is ExtractionStatus.FAILED]
    assert len(failed) == 2
    assert failed[0].failure_group_id is not None
    assert failed[0].failure_group_id == failed[1].failure_group_id
    assert [r.failure_group_size for r in failed] == [2, 2]
    # The destination each link intended survives the rebuild.
    assert [r.requested_path for r in failed] == [dest / "link1", dest / "link2"]


def test_failure_group_fields_are_both_or_neither(tmp_path: Path) -> None:
    """An ordinary failure is not a group of one."""
    archive = _tar_bytes([("file", "a.txt", b"x")])
    report = open_and_extract(io.BytesIO(archive), tmp_path / "out")
    (result,) = report.results
    assert result.failure_group_id is None
    assert result.failure_group_size is None


def test_failed_replace_does_not_mark_earlier_member_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OVERWRITTEN means "written, then lost to a later REPLACE that landed".

    If the replacing write fails, the earlier member keeps its content and its
    EXTRACTED result — the revision is gated on the new write succeeding.
    """
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"

    original = ExtractionCoordinator._write_file_atomic
    calls = {"n": 0}

    def fail_second(self, *args: object, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] > 1:
            raise ExtractionError("forced failure on the replacing write")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ExtractionCoordinator, "_write_file_atomic", fail_second)
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        overwrite=OverwritePolicy.REPLACE,
        on_error=OnError.CONTINUE,
    )
    first, second = report.results
    assert first.status is ExtractionStatus.EXTRACTED  # not OVERWRITTEN
    assert second.status is ExtractionStatus.FAILED
    # The atomic write means the first member's bytes were never at risk.
    assert (dest / "README").read_bytes() == b"A"


def test_progress_extracted_tally_follows_a_retroactive_overwrite(
    tmp_path: Path,
) -> None:
    """``members_extracted`` is a tally of EXTRACTED *results*, so it has to follow a
    result that is revised to OVERWRITTEN — otherwise the final progress report claims
    more extracted members than the report contains."""
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    seen: list[tuple[int, int]] = []
    report = open_and_extract(
        io.BytesIO(archive),
        tmp_path / "out",
        overwrite=OverwritePolicy.REPLACE,
        on_progress=lambda p: seen.append((p.members_done, p.members_extracted)),
    )
    extracted_rows = sum(
        1 for r in report.results if r.status is ExtractionStatus.EXTRACTED
    )
    assert extracted_rows == 1
    assert seen[-1] == (2, 1)


def test_failed_replace_that_destroyed_content_marks_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REPLACE that cleared the destination and *then* failed still loses the earlier
    member's content, so that member must stop advertising a live path.

    Only reachable on the non-atomic write paths (symlink here): a FILE write lands via
    os.replace and never destroys the destination up front.
    """
    archive = _tar_bytes([("file", "README", b"A"), ("sym", "readme", "elsewhere.txt")])
    dest = tmp_path / "out"

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("forced failure after the destination was cleared")

    monkeypatch.setattr("archivey.internal.extraction.os.symlink", boom)
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        overwrite=OverwritePolicy.REPLACE,
        on_error=OnError.CONTINUE,
    )
    first, second = report.results
    assert second.status is ExtractionStatus.FAILED
    # The first member's bytes were unlinked to make room for a write that never landed.
    assert not (dest / "README").exists()
    assert first.status is ExtractionStatus.OVERWRITTEN
    assert first.path is None
    assert first.requested_path == dest / "README"


def test_hardlink_write_is_atomic_over_an_existing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed hardlink write must not have already destroyed the destination.

    The link is built at a temp sibling and os.replace'd in, so a failure leaves the
    previous entry intact — the same guarantee FILE writes have always had.
    """
    archive = _tar_bytes([("file", "src.bin", b"data"), ("hard", "README", "src.bin")])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "README").write_bytes(b"pre-existing")

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("forced failure while placing the link")

    monkeypatch.setattr("archivey.internal.extraction.os.replace", boom)
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        overwrite=OverwritePolicy.REPLACE,
        on_error=OnError.CONTINUE,
    )
    assert report.results[-1].status is ExtractionStatus.FAILED
    # The destination survived the failed replacement...
    assert (dest / "README").read_bytes() == b"pre-existing"
    # ...and no staging file was left behind.
    assert not [p for p in dest.iterdir() if p.name.startswith(".archivey-tmp-")]


def test_hardlink_replaces_a_destination_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    """os.replace moves the link itself, so the atomic swap keeps the never-write-through
    guarantee that the previous unlink-then-link had."""
    dest = tmp_path / "out"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"must not be touched")
    (dest / "README").symlink_to(outside)

    archive = _tar_bytes([("file", "src.bin", b"data"), ("hard", "README", "src.bin")])
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    assert not (dest / "README").is_symlink()
    assert (dest / "README").read_bytes() == b"data"
    assert outside.read_bytes() == b"must not be touched"


def test_anti_delete_releases_the_collision_claim(tmp_path: Path) -> None:
    """An anti-item delete must clear the collision map, not just ``written_paths``.

    Both track what this run put on disk. Leaving a claim behind means a later member
    resolving to the same key collides against content that no longer exists — a
    spurious ``NameCollisionError`` under ``abort_on``, or an ``OVERWRITTEN`` revision
    of a member that was already deleted.

    Exercised at the coordinator level: reaching it through a backend needs two members
    with the same collision key both marked current, which last-entry-wins prevents.
    """
    from archivey.internal.extraction import _Claim, _RunState

    dest = tmp_path / "out"
    dest.mkdir()
    written = dest / "README"
    written.write_bytes(b"A")

    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STRICT)
    written_paths = {written}
    # The claim the earlier FILE member left behind, keyed casefold(NFC(...)).
    collision_map = {"readme": _Claim(written, 0, written)}
    anti = ArchiveMember(type=MemberType.ANTI, name="README")

    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader. It writes to the link watch only
        # when it removes a symlink, and these remove none, so a fresh one is enough.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths=written_paths,
        collision_map=collision_map,
    )
    result = coordinator._apply_anti_item(anti, written)

    assert result.status is ExtractionStatus.EXTRACTED
    assert not written.exists()
    assert written_paths == set()
    assert collision_map == {}  # the claim went with the content


def test_anti_no_op_leaves_an_unrelated_claim_alone(tmp_path: Path) -> None:
    """A no-op anti (nothing written this run at that path) releases nothing."""
    from archivey.internal.extraction import _Claim, _RunState

    dest = tmp_path / "out"
    dest.mkdir()
    pre_existing = dest / "README"
    pre_existing.write_bytes(b"not ours")

    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STRICT)
    other = dest / "other.txt"
    collision_map = {"other.txt": _Claim(other, 0, other)}
    anti = ArchiveMember(type=MemberType.ANTI, name="README")

    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader. It writes to the link watch only
        # when it removes a symlink, and these remove none, so a fresh one is enough.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths=set(),
        collision_map=collision_map,
    )
    coordinator._apply_anti_item(anti, pre_existing)

    assert pre_existing.read_bytes() == b"not ours"  # never ours to delete
    assert collision_map == {"other.txt": _Claim(other, 0, other)}


def test_anti_item_finds_a_case_variant_through_the_collision_map(
    tmp_path: Path,
) -> None:
    """Under STRICT an anti-item ``readme`` deletes the ``README`` this run wrote.

    The collision map already treats the two as one name, on every platform; the
    anti-item used to compare exact paths instead, so on a case-insensitive filesystem
    the file it names survived.
    """
    from archivey.internal.extraction import _Claim, _RunState

    dest = tmp_path / "out"
    dest.mkdir()
    written = dest / "README"
    written.write_bytes(b"A")

    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STRICT)
    written_paths = {written}
    collision_map = {"readme": _Claim(written, 0, written)}
    anti = ArchiveMember(type=MemberType.ANTI, name="readme")

    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader. It writes to the link watch only
        # when it removes a symlink, and these remove none, so a fresh one is enough.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths=written_paths,
        collision_map=collision_map,
    )
    result = coordinator._apply_anti_item(anti, dest / "readme")

    assert result.status is ExtractionStatus.EXTRACTED
    assert result.path == written
    assert not written.exists()
    assert written_paths == set()
    assert collision_map == {}


@pytest.mark.skipif(
    os.name == "nt",
    reason="TRUSTED defers to the local OS, and on Windows both the filesystem and "
    "Path equality fold case, so there `readme` is the `README` this run wrote",
)
def test_anti_item_is_exact_under_trusted(tmp_path: Path) -> None:
    """TRUSTED keys on the exact name, so ``readme`` leaves ``README`` alone."""
    from archivey.internal.extraction import _Claim, _RunState

    dest = tmp_path / "out"
    dest.mkdir()
    written = dest / "README"
    written.write_bytes(b"A")

    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.TRUSTED)
    written_paths = {written}
    collision_map = {"README": _Claim(written, 0, written)}
    anti = ArchiveMember(type=MemberType.ANTI, name="readme")

    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader. It writes to the link watch only
        # when it removes a symlink, and these remove none, so a fresh one is enough.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths=written_paths,
        collision_map=collision_map,
    )
    coordinator._apply_anti_item(anti, dest / "readme")

    assert written.read_bytes() == b"A"
    assert written_paths == {written}
    assert collision_map == {"README": _Claim(written, 0, written)}


def test_anti_item_prefers_the_exact_directory_it_names(tmp_path: Path) -> None:
    """An exact path this run wrote wins over a case-variant claim in the map.

    Directories are not in the collision map, so a run can write directory ``x`` and
    file ``X`` (claimed under key ``x``). An anti-item ``x`` names the directory.
    """
    from archivey.internal.extraction import _Claim, _RunState

    dest = tmp_path / "out"
    dest.mkdir()
    directory = dest / "x"
    directory.mkdir()
    file_ = dest / "X"
    if file_.exists():
        pytest.skip("case-insensitive filesystem: x and X are one entry")
    file_.write_bytes(b"F")

    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STRICT)
    written_paths = {directory, file_}
    collision_map = {"x": _Claim(file_, 1, file_)}
    anti = ArchiveMember(type=MemberType.ANTI, name="x")

    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader. It writes to the link watch only
        # when it removes a symlink, and these remove none, so a fresh one is enough.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths=written_paths,
        collision_map=collision_map,
    )
    result = coordinator._apply_anti_item(anti, directory)

    assert result.path == directory
    assert not directory.exists()
    assert file_.read_bytes() == b"F"
    assert collision_map == {"x": _Claim(file_, 1, file_)}


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.ERROR,
        OverwritePolicy.SKIP,
        OverwritePolicy.REPLACE,
        OverwritePolicy.RENAME,
    ],
)
def test_collided_with_names_the_blocking_path_for_a_this_run_collision(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """Under every resolution, a member blocked by a member of THIS run says so.

    This is the fact the removed EXTRACTION_NAME_COLLISION diagnostic carried
    (``prior_path``). It is set for all four resolutions because the collision, not its
    outcome, is what happened.
    """
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )
    blocked = report.results[-1]
    assert blocked.collided_with == dest / "README"
    # The member that got there first collided with nothing.
    assert report.results[0].collided_with is None


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.ERROR,
        OverwritePolicy.SKIP,
        OverwritePolicy.REPLACE,
        OverwritePolicy.RENAME,
    ],
)
def test_collided_with_names_the_file_a_directory_member_landed_on(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """The same holds for a directory member over a file this run wrote: the field
    means the same under every policy, not only under RENAME."""
    archive = _tar_bytes([("file", "x", b"A"), ("dir", "x/", None)])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=overwrite, on_error=OnError.CONTINUE
    )
    first, directory = report.results
    assert directory.collided_with == dest / "x"
    assert first.collided_with is None


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.ERROR,
        OverwritePolicy.SKIP,
        OverwritePolicy.REPLACE,
        OverwritePolicy.RENAME,
    ],
)
def test_collided_with_is_none_for_a_pre_existing_destination(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """An obstacle that was on disk before extraction is not a collision event.

    Same statuses as the this-run cases above under every policy, so without this field
    the two are indistinguishable from a single result. The diagnostic was silent here
    too, so ``None`` is parity rather than lost information.
    """
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"already here")
    report = open_and_extract(
        io.BytesIO(_tar_bytes([("file", "a.txt", b"X")])),
        dest,
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )
    assert report.results[-1].collided_with is None
    assert report.results[-1].requested_path == dest / "a.txt"


def test_collided_with_is_not_set_under_trusted(tmp_path: Path) -> None:
    """TRUSTED defers to the local OS: no collision *event*, so nothing to record.

    Mirrors the condition the removed diagnostic fired under, which excluded TRUSTED.
    """
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive),
        dest,
        policy=ExtractionPolicy.TRUSTED,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert all(r.collided_with is None for r in report.results)


def test_collided_with_joins_to_the_blocking_member_by_path_equality(
    tmp_path: Path,
) -> None:
    """The point of carrying a path: finding *who* blocked you needs no collision keys.

    Under REPLACE the blocking member is revised to OVERWRITTEN and no longer holds a
    live ``path``, so the join falls back to its ``requested_path`` — the one wrinkle,
    and far smaller than re-deriving NFC+casefold collision keys across the report.
    """
    archive = _tar_bytes([("file", "README", b"A"), ("file", "readme", b"B")])
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(archive), dest, overwrite=OverwritePolicy.REPLACE
    )
    blocked = report.results[-1]
    assert blocked.collided_with is not None

    blocker = next(
        r
        for r in report.results
        if r is not blocked and (r.path or r.requested_path) == blocked.collided_with
    )
    assert blocker.member.name == "README"
    assert blocker.status is ExtractionStatus.OVERWRITTEN


@pytest.mark.parametrize("atomic", [False, True])
def test_unknown_overwrite_policy_raises_instead_of_unlinking(
    tmp_path: Path, atomic: bool
) -> None:
    """A policy the chain does not name must not fall through to the REPLACE arm.

    Stands in for an ``OverwritePolicy`` member added without updating the chain: the
    existing entry survives and the gap surfaces as an internal error.
    """
    existing = tmp_path / "keep.txt"
    existing.write_bytes(b"keep me")
    future = cast(OverwritePolicy, SimpleNamespace(name="FUTURE"))
    coordinator = ExtractionCoordinator(overwrite=future)
    member = ArchiveMember(type=MemberType.FILE, name="keep.txt")

    with pytest.raises(AssertionError, match="unreachable"):
        coordinator._prepare_destination(member, existing, atomic=atomic)
    assert existing.read_bytes() == b"keep me"


@pytest.mark.parametrize("on_error", list(OnError))
def test_stops_on_failure_names_every_on_error_member(on_error: OnError) -> None:
    """Every declared ``OnError`` member has an explicit answer."""
    coordinator = ExtractionCoordinator(on_error=on_error)
    assert coordinator._stops_on_failure() is (on_error is OnError.STOP)


def test_unknown_on_error_raises_instead_of_continuing() -> None:
    """An ``OnError`` member the chain does not name is not treated as CONTINUE."""
    future = cast(OnError, SimpleNamespace(name="FUTURE"))
    coordinator = ExtractionCoordinator(on_error=future)
    with pytest.raises(AssertionError, match="unreachable"):
        coordinator._stops_on_failure()


# ---------------------------------------------------------------------------
# A parent the archive implies, where the caller has a non-directory
# ---------------------------------------------------------------------------


def _implied_parent_archive(fmt: str, names: list[str]) -> bytes:
    """A TAR or ZIP of ``names``: a name ending in ``/`` is a directory entry, any
    other a file holding its own name."""
    if fmt == "tar":
        return _tar_bytes(
            [
                ("dir", name, None)
                if name.endswith("/")
                else ("file", name, name.encode())
                for name in names
            ]
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"" if name.endswith("/") else name.encode())
    return buf.getvalue()


def _extract_over_callers_file(
    data: bytes,
    dest: Path,
    *,
    streaming: bool,
    overwrite: OverwritePolicy,
    obstacle: str = "file",
) -> tuple[list[tuple[str, ExtractionStatus, str | None, str | None]], list[str]]:
    """Extract ``data`` with ``on_error=CONTINUE`` into ``dest``, where the caller
    has ``foo`` (a file holding ``MINE``, or a dangling symlink); return each result
    as ``(name, status, path, requested_path)`` with errors checked to be typed, and
    the tree."""
    dest.mkdir()
    if obstacle == "file":
        (dest / "foo").write_bytes(b"MINE")
    else:
        (dest / "foo").symlink_to("nowhere")
    report = open_and_extract(
        io.BytesIO(data),
        dest,
        streaming=streaming,
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )
    results = []
    for r in report.results:
        if r.error is not None:
            # Never a raw OSError: the policy's own error, naming the caller's entry.
            assert isinstance(r.error, ExtractionError), r.error
            assert "Destination already exists" in str(r.error)
            assert (dest / "foo").as_posix() in str(r.error)
        assert r.collided_with is None  # the caller's entry is no collision event
        results.append(
            (
                r.member.name.rstrip("/"),
                r.status,
                None if r.path is None else r.path.relative_to(dest).as_posix(),
                None
                if r.requested_path is None
                else r.requested_path.relative_to(dest).as_posix(),
            )
        )
    tree = sorted(
        p.relative_to(dest).as_posix()
        + ("/" if p.is_dir() and not p.is_symlink() else "")
        for p in dest.rglob("*")
    )
    return results, tree


_IMPLIED = ["foo/x.txt", "foo/a/y.txt", "foo/z.txt"]


@pytest.mark.parametrize("fmt", ["tar", "zip"])
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
def test_implied_parent_over_callers_file_follows_overwrite_policy(
    tmp_path: Path, fmt: str, streaming: bool, overwrite: OverwritePolicy
) -> None:
    """``foo/x.txt`` with no ``foo/`` entry, where the caller has a file ``foo``:
    the implied directory meets ``OverwritePolicy`` as an explicit ``foo/`` entry
    would, and no raw ``OSError`` comes out of the library. The tree ends as it does
    with the explicit entry, and the file members get the same results."""
    implied, tree = _extract_over_callers_file(
        _implied_parent_archive(fmt, _IMPLIED),
        tmp_path / "implied",
        streaming=streaming,
        overwrite=overwrite,
    )
    explicit, explicit_tree = _extract_over_callers_file(
        _implied_parent_archive(fmt, ["foo/", *_IMPLIED]),
        tmp_path / "explicit",
        streaming=streaming,
        overwrite=overwrite,
    )
    assert tree == explicit_tree
    assert implied == [r for r in explicit if r[0] != "foo"]

    statuses = {name: status for name, status, _, _ in implied}
    if overwrite is OverwritePolicy.ERROR:
        assert set(statuses.values()) == {ExtractionStatus.FAILED}
        assert tree == ["foo"]
    elif overwrite is OverwritePolicy.SKIP:
        assert set(statuses.values()) == {ExtractionStatus.NOT_OVERWRITTEN}
        assert tree == ["foo"]
    elif overwrite is OverwritePolicy.REPLACE:
        assert set(statuses.values()) == {ExtractionStatus.EXTRACTED}
        assert tree == ["foo/", "foo/a/", "foo/a/y.txt", "foo/x.txt", "foo/z.txt"]
        assert (tmp_path / "implied/foo/x.txt").read_bytes() == b"foo/x.txt"
    else:
        assert overwrite is OverwritePolicy.RENAME
        assert implied == [
            (name, ExtractionStatus.EXTRACTED, name.replace("foo/", "foo (1)/"), name)
            for name in _IMPLIED
        ]
        assert tree == [
            "foo",
            "foo (1)/",
            "foo (1)/a/",
            "foo (1)/a/y.txt",
            "foo (1)/x.txt",
            "foo (1)/z.txt",
        ]
    if overwrite is not OverwritePolicy.REPLACE:
        assert (tmp_path / "implied/foo").read_bytes() == b"MINE"


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX")
@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
def test_implied_parent_over_callers_dangling_symlink(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """A dangling symlink of the caller's is an entry that is not a directory too.
    The symlink is never written through."""
    implied, tree = _extract_over_callers_file(
        _implied_parent_archive("tar", ["foo/x.txt"]),
        tmp_path / "implied",
        streaming=False,
        overwrite=overwrite,
        obstacle="symlink",
    )
    explicit, explicit_tree = _extract_over_callers_file(
        _implied_parent_archive("tar", ["foo/", "foo/x.txt"]),
        tmp_path / "explicit",
        streaming=False,
        overwrite=overwrite,
        obstacle="symlink",
    )
    assert tree == explicit_tree
    assert implied == [r for r in explicit if r[0] != "foo"]
    assert not (tmp_path / "nowhere").exists()
    assert not (tmp_path / "implied/nowhere").exists()


@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
def test_implied_parent_over_callers_file_under_stop(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """Under the default ``OnError.STOP``, ``ERROR`` raises its ``ExtractionError``,
    not the ``FileExistsError`` ``mkdir`` gives; the other policies finish."""
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "foo").write_bytes(b"MINE")
    data = _implied_parent_archive("tar", ["foo/x.txt"])
    if overwrite is OverwritePolicy.ERROR:
        with pytest.raises(ExtractionError, match="Destination already exists"):
            open_and_extract(io.BytesIO(data), dest, overwrite=overwrite)
        assert (dest / "foo").read_bytes() == b"MINE"
    else:
        report = open_and_extract(io.BytesIO(data), dest, overwrite=overwrite)
        assert len(report.results) == 1


def test_implied_parent_renamed_once_for_later_members(tmp_path: Path) -> None:
    """Under ``RENAME`` the first member that implies ``foo`` picks ``foo (1)``; the
    later ones, and a later ``foo/`` entry, follow it there rather than each picking
    a name of its own."""
    data = _implied_parent_archive("tar", ["foo/x.txt", "foo/", "foo/y.txt"])
    results, tree = _extract_over_callers_file(
        data, tmp_path / "out", streaming=False, overwrite=OverwritePolicy.RENAME
    )
    assert [path for _, _, path, _ in results] == [
        "foo (1)/x.txt",
        "foo (1)",
        "foo (1)/y.txt",
    ]
    assert tree == ["foo", "foo (1)/", "foo (1)/x.txt", "foo (1)/y.txt"]


def test_a_staging_file_the_filesystem_keeps_is_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A write that fails after staging removes its temp file; a removal the
    filesystem refuses leaves it, and says so."""
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("f.txt", b"data")

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError(5, "simulated metadata failure")

    real_unlink = os.unlink

    def refuse_temp(path: str | os.PathLike[str], *args: object, **kw: object) -> None:
        if os.path.basename(path).startswith(".archivey-tmp-"):
            raise PermissionError(13, "Permission denied", str(path))
        real_unlink(path, *args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(ExtractionCoordinator, "_apply_metadata", fail)
    monkeypatch.setattr(os, "unlink", refuse_temp)
    with open_archive(archive) as reader:
        reader.extract_all(tmp_path / "out", on_error="continue")
    assert "staged for 'f.txt'" in caplog.text
