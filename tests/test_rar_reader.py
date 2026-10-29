"""Native RAR reader fixture coverage."""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import ExtractionStatus, open_archive
from archivey.config import (
    REWIND_REDECODE_WARN_BYTES,
    ArchiveyConfig,
    ListingLimits,
    PasswordRequest,
    RarDecompressor,
)
from archivey.cost import AccessCost
from archivey.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    DiagnosticPolicy,
    MemberHeaderRecordContext,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    DiagnosticRaisedError,
    EncryptionError,
    PackageNotInstalledError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import rar_reader, rar_unrar
from archivey.internal.backends.rar_parser import (
    RAR5_ID,
    RAR5_QO_UNMATCHED_COPIES,
    RAR_ID,
    RarArchive,
    RarMemberInfo,
    _decode_rar3_unicode_name,
    load_vint,
    parse_rar_archive,
    parse_rar_volumes,
)
from archivey.internal.external.cli import terminate_process
from archivey.internal.streams.respawn import RespawnStream
from archivey.reader import ArchiveReader
from archivey.terminal import display_path
from archivey.types import (
    EXTRA_RAR_EXTRACT_VERSION,
    ArchiveMember,
    CompressionAlgorithm,
    HashAlgorithm,
    MemberType,
)
from tests.conftest import (
    requires,
    requires_binary,
    requires_unrar_cli,
)
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import NonSeekableBytesIO, ShortReadNonSeekable

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

_BASIC_CONTENTS = {
    "file1.txt": b"Hello, world!",
    "empty_file.txt": b"",
    "subdir/file2.txt": b"Hello, universe!",
    "implicit_subdir/file3.txt": b"Hello there!",
}

# Compressed fixtures: stored members never reach unrar, so they would not pin this.
# ``subdir/aY.txt`` is an earlier basename match for ``a*.txt`` (prefix skip).
# Windows cannot create these names on disk — committed only.
_WILDCARD_PAD = b"0123456789abcdef" * 512
_WILDCARD_CONTENTS = {
    "subdir/aY.txt": b"nested-aY\n" + _WILDCARD_PAD,
    "a*.txt": b"target-star\n" + _WILDCARD_PAD,
    "aX.txt": b"other-aX\n" + _WILDCARD_PAD,
    "b?.txt": b"target-q\n" + _WILDCARD_PAD,
    "b1.txt": b"other-b1\n" + _WILDCARD_PAD,
    "only*.dat": b"unique\n" + _WILDCARD_PAD,
}
_WILDCARD_FIXTURES = (
    "wildcard_names__.rar",
    "wildcard_names_solid__.rar",
    "wildcard_names__rar4.rar",
)
# Reading a glob-named member whose mask also matches earlier members is refused by
# default (see ``test_glob_member_with_earlier_matches_is_refused``). The skip that
# makes such a read correct is still live behind this flag, and these tests are what
# pin it, so they opt in explicitly.
_ALLOW_GLOB_CONCAT = ArchiveyConfig(rar_allow_glob_member_concatenation=True)
# Under ``AUTO`` a member unrar cannot name goes to an accepted unar when one is
# installed (``test_auto_reads_with_unar_a_member_unrar_cannot_name``). The refusal
# tests pin the unrar side, so they choose unrar explicitly.
_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")
_WILDCARD_DIRGLOB_CONTENTS = {
    "aaa/x.txt": b"aaa\n" + _WILDCARD_PAD,
    "dX/x.txt": b"dX\n" + _WILDCARD_PAD,
    "d*/x.txt": b"dstar\n" + _WILDCARD_PAD,
}
# ``member.name`` folds a stored backslash to ``/`` (RAR treats it as a separator).
_WILDCARD_BACKSLASH_SLASH = b"slashdir\n" + _WILDCARD_PAD
_WILDCARD_BACKSLASH_REFUSED = ("a/b_TGT.txt", "a/b*.txt")
_WILDCARD_VER_CONTENTS = {
    "data.bin;1": b"data-v1\n" + _WILDCARD_PAD,
    "data.bin": b"data-v2!!\n" + _WILDCARD_PAD,
    "data_TARGET": b"data-tgt\n" + _WILDCARD_PAD,
    "data*": b"data-star\n" + _WILDCARD_PAD,
}
# 1 MiB repeating pad so a solid later-member rewind crosses the diagnostic
# threshold without monkeypatching it, and so unrar is still writing when a
# test seeks mid-stream (the 64 KiB pipe buffer fills).
_SEEK_RESPAWN_PAD = b"0123456789abcdef" * (1024 * 1024 // 16)
_SEEK_RESPAWN_TAIL = b"tail-member\n"
_SEEK_RESPAWN_FIXTURE = "seek_respawn_solid__.rar"


def _fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path


def _named_unrar_p_bytes(path: Path, member: str) -> bytes:
    """Named ``unrar p`` stdout for ``member``.

    Goes through ``rar_unrar.open_unrar_p`` so this is the oracle, outside the
    ``rar_reader`` spy — a library spawn would otherwise be counted as ours.

    Requires exit 0: a no-match is rc 10 with empty stdout, which is not
    "the link emitted nothing".
    """
    proc, stdout = rar_unrar.open_unrar_p(path, member=member)
    try:
        data = stdout.read()
    finally:
        stdout.close()
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            terminate_process(proc)
            raise
    assert rc == 0, f"unrar p member={member!r} exited {rc} (10 is no-match)"
    return data


def _assert_solid_link_emission(
    path: Path, member: ArchiveMember, *, rar5: bool
) -> None:
    """Packed/unpacked sizes do not predict ``unrar p``; ``is_payload_file`` does."""
    raw = member._raw
    assert isinstance(raw, RarMemberInfo)
    assert raw.is_payload_file() is False
    assert member.size is not None and member.size > 0
    if rar5:
        assert member.compressed_size == 0
    else:
        assert member.compressed_size is not None and member.compressed_size > 0
    assert _named_unrar_p_bytes(path, member.name) == b""


@requires_binary("unrar")
def test_named_unrar_p_bytes_rejects_no_match() -> None:
    """A no-match is empty stdout at rc 10 — not "the link emitted nothing"."""
    with pytest.raises(AssertionError, match="exited 10"):
        _named_unrar_p_bytes(_fixture("symlinks_solid__.rar"), "NO_SUCH_MEMBER_xyz.txt")


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["basic_nonsolid__.rar", "basic_nonsolid__rar4.rar"],
)
def test_basic_nonsolid_list_and_read(name: str) -> None:
    with open_archive(_fixture(name)) as archive:
        assert archive.info.is_solid is False
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == set(_BASIC_CONTENTS)
        for member_name, expected in _BASIC_CONTENTS.items():
            assert archive.read(files[member_name]) == expected


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["basic_solid__.rar", "basic_solid__rar4.rar"],
)
def test_basic_solid_stream_and_random(name: str) -> None:
    with open_archive(_fixture(name)) as archive:
        assert archive.info.is_solid is True
        # RAR exposes no per-solid-block boundaries, so solidity is one archive-level
        # flag and the block count is unknown rather than 1.
        assert archive.cost.access_cost is AccessCost.SOLID
        assert archive.cost.solid_block_count is None
        streamed = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if member.is_file and stream is not None
        }
        assert streamed == _BASIC_CONTENTS
        assert archive.read("file1.txt") == _BASIC_CONTENTS["file1.txt"]


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["basic_solid__.rar", "basic_solid__rar4.rar"],
)
def test_solid_pass_spawns_unrar_only_on_the_first_read(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A solid pass nobody reads from costs no ``unrar`` process.

    ``stream_members`` promises unread members are not opened or decompressed and
    do not request passwords; a pipe spawned at pass start would break all three.
    """
    spawns: list[Path] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        spawns.append(path)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(_fixture(name)) as archive:
        assert archive.info.is_solid is True
        for _member, _stream in archive.stream_members():
            pass
    assert spawns == []

    with open_archive(_fixture(name)) as archive:
        for member, stream in archive.stream_members():
            if member.name == "file1.txt":
                assert stream is not None
                assert stream.read() == _BASIC_CONTENTS["file1.txt"]
    assert len(spawns) == 1


def _solid_with_a_large_file_copy_source(tmp_path: Path) -> bytes:
    """A solid RAR5 whose one source of a file copy (``rar -oi``) is larger than the
    8 MiB a solid pass keeps in memory, so keeping it would need the temporary file."""
    if shutil.which("rar") is None:
        pytest.skip("needs rar")
    src = tmp_path / "src"
    src.mkdir()
    payload = b"".join(b"%08d\n" % i for i in range(1_000_000))
    assert len(payload) > 8 << 20
    (src / "a_source.txt").write_bytes(payload)
    (src / "b_copy.txt").write_bytes(payload)
    archive = tmp_path / "large_copy.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-s", "-oi:1000", str(archive)]
        + ["a_source.txt", "b_copy.txt"],
        cwd=src,
        check=True,
        timeout=120,
    )
    return archive.read_bytes()


@pytest.mark.parametrize("shape", ["basic_solid", "large_file_copy_source"])
def test_solid_stream_members_of_a_stream_source_writes_nothing_until_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, shape: str
) -> None:
    """A solid pass nobody reads from writes nothing to temporary storage.

    Neither the copy of the stream source that ``unrar`` needs nor the file a pass
    keeps a large file-copy source in may appear before a member is read.
    """
    if shape == "basic_solid":
        data = _fixture("basic_solid__.rar").read_bytes()
    else:
        data = _solid_with_a_large_file_copy_source(tmp_path)
    created = _rar_temp_artifacts(monkeypatch)
    with open_archive(io.BytesIO(data)) as archive:
        assert archive.info.is_solid is True
        for _member, _stream in archive.stream_members():
            pass
        assert created == []


@requires_binary("unrar")
def test_refused_second_open_does_not_spawn_unrar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ArchiveyUsageError`` must mean the second ``unrar`` was never spawned.

    ``basic_solid__.rar`` is ``-m3`` (not stored): ``open()`` takes the named-unrar
    path. A spawn-then-cleanup fix still raises and leaves no live process, so this
    counts ``open_unrar_p`` calls rather than leftover children.
    """
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(_fixture("basic_solid__.rar")) as archive:
        files = [m for m in archive.members() if m.is_file]
        assert len(files) >= 2
        s1 = archive.open(files[0])
        assert len(spawns) == 1
        with pytest.raises(ArchiveyUsageError):
            archive.open(files[1])
        assert len(spawns) == 1
        s1.close()
        s2 = archive.open(files[1])
        assert len(spawns) == 2
        s2.close()


@requires_binary("unrar")
@pytest.mark.parametrize("name", ["basic_solid__.rar", "basic_solid__rar4.rar"])
def test_unrar_route_is_not_seekable_by_default(name: str) -> None:
    """Without ``seekable_members``, a compressed member stays a pipe."""
    with open_archive(_fixture(name)) as archive, archive.open("file1.txt") as stream:
        assert stream.seekable() is False
        with pytest.raises(io.UnsupportedOperation):
            stream.seek(0)


@requires_binary("unrar")
@pytest.mark.parametrize("name", ["basic_solid__.rar", "basic_solid__rar4.rar"])
def test_seekable_members_respawns_unrar_on_backward_seek(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``seekable_members=True`` must honour backward seek on the named-unrar route.

    Direct-slice stored members already seek. This pins the pipe route: a backward
    seek closes the process; the following read respawns ``unrar``. A buffer-the-
    member fix would not call ``open_unrar_p`` a second time at all.
    """
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    expected = _BASIC_CONTENTS["file1.txt"]
    with (
        open_archive(_fixture(name), seekable_members=True) as archive,
        archive.open("file1.txt") as stream,
    ):
        assert stream.seekable() is True
        assert stream.read(5) == expected[:5]
        assert len(spawns) == 1
        stream.seek(0)
        assert len(spawns) == 1
        assert stream.read() == expected
        assert len(spawns) == 2
        stream.seek(5)
        assert stream.read() == expected[5:]
        stream.seek(len(expected) + 100)
        assert stream.read() == b""


def test_unrar_respawn_overrun_probe_sees_trailing_bytes() -> None:
    """Declared-size clamp must not hide extra pipe bytes from fused verify.

    ``read()`` at ``pos == size`` still reaches the inner stream so the one-byte
    overrun probe can fire. A buffer-and-clamp wrapper would return ``b""``.
    """
    payload = b"hello world!!extra"
    declared = 13

    def spawn() -> io.BytesIO:
        return io.BytesIO(payload)

    stream = RespawnStream(spawn, spawn(), size=declared, what="unrar output")
    assert stream.read(declared) == payload[:declared]
    assert stream.read(1) == payload[declared : declared + 1]
    stream.seek(0)
    assert stream.read(declared) == payload[:declared]
    assert stream.read(1) == payload[declared : declared + 1]


def test_unrar_respawn_boundary_read_is_one_byte() -> None:
    """At declared size, ``read(-1)`` must not drain the rest of the pipe."""
    payload = b"hello world!!EXTRA"
    declared = 13

    def spawn() -> io.BytesIO:
        return io.BytesIO(payload)

    stream = RespawnStream(spawn, spawn(), size=declared, what="unrar output")
    assert stream.read(declared) == payload[:declared]
    assert stream.read(-1) == payload[declared : declared + 1]


def test_unrar_respawn_overrun_probe_noop_seek_does_not_kill_pipe() -> None:
    """After a probe byte past declared size, clamp ``_inner_pos`` so SEEK_CUR is free.

    The probe is the fused-verify one-byte read at ``pos == size``. Without the
    clamp, ``_inner_pos`` sits at ``_size + 1`` and the next seek — including a
    no-op ``SEEK_CUR`` — kills the live process. That only happens when unrar
    emitted extra bytes (already ``CorruptionError`` on the same call).
    """
    payload = b"hello world!!extra"
    declared = 13
    closed: list[bool] = []

    class _TrackClose(io.BytesIO):
        def close(self) -> None:
            if not self.closed:
                closed.append(True)
            super().close()

    def spawn() -> io.BytesIO:
        return _TrackClose(payload)

    inner = spawn()
    stream = RespawnStream(spawn, inner, size=declared, what="unrar output")
    assert stream.read(declared) == payload[:declared]
    assert stream.read(1) == payload[declared : declared + 1]
    assert closed == []
    assert stream.seek(0, io.SEEK_CUR) == declared + 1
    assert closed == []
    assert stream.seek(0) == 0
    assert closed == [True]


def test_unrar_respawn_failed_seek_leaves_position() -> None:
    """A raising ``seek()`` must not reset tell() to 0."""

    class _CloseBoom(io.BytesIO):
        def close(self) -> None:
            already = self.closed
            super().close()
            if not already:
                raise OSError("close failed")

    def spawn() -> io.BytesIO:
        return io.BytesIO(b"x" * 20)

    stream = RespawnStream(spawn, _CloseBoom(b"x" * 20), size=20, what="unrar output")
    assert stream.read(10) == b"x" * 10
    assert stream.tell() == 10
    with pytest.raises(OSError, match="close failed"):
        stream.seek(2)
    assert stream.tell() == 10


def test_unrar_respawn_seek_end_does_not_drain_or_respawn() -> None:
    """``seek(0, SEEK_END); seek(0)`` before a read must not spawn a second process."""
    payload = b"hello world!"
    spawns = 0

    def spawn() -> io.BytesIO:
        nonlocal spawns
        spawns += 1
        return io.BytesIO(payload)

    stream = RespawnStream(spawn, spawn(), size=len(payload), what="unrar output")
    assert spawns == 1
    assert stream.seek(0, io.SEEK_END) == len(payload)
    assert spawns == 1
    assert stream.seek(0) == 0
    assert spawns == 1
    assert stream.read() == payload
    assert spawns == 1


def test_bounded_member_pipe_drain_coalesces_short_reads() -> None:
    """``read(-1)`` must gather the declared size, not stop on a short inner read.

    ``_BoundedMemberPipe.read`` did one ``inner.read(remaining)``. A short-returning
    pipe then left ``tell()`` mid-member and leaked the rest to the next ``read``.
    ``SlicingStream.read(-1)`` with a declared length uses ``read_exact``.
    """
    payload = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX"
    assert len(payload) == 60
    inner = ShortReadNonSeekable(payload, max_chunk=7)
    pipe = rar_reader._bounded_member_pipe(inner, prefix=0, size=60)
    assert pipe.read() == payload
    assert pipe.tell() == 60
    assert pipe.read() == b""
    assert pipe.read(1) == b""
    pipe.close()
    assert inner.closed  # owns_inner=True: the factory owns the unrar pipe


def test_bounded_member_pipe_skips_prefix_and_translates_eof() -> None:
    inner = NonSeekableBytesIO(b"PREFpayload-body")
    pipe = rar_reader._bounded_member_pipe(inner, prefix=4, size=12)
    assert pipe.read() == b"payload-body"
    assert pipe.tell() == 12
    pipe.close()
    assert inner.closed  # owns_inner=True: the factory owns the unrar pipe

    short = NonSeekableBytesIO(b"xx")
    with pytest.raises(TruncatedError, match="glob-matched member"):
        rar_reader._bounded_member_pipe(short, prefix=10, size=4)
    assert short.closed


@requires_binary("unrar")
def test_seekable_unrar_emits_stream_rewind() -> None:
    """A small rewind of a later solid member is still loud: the prefix counts."""
    with (
        open_archive(_fixture(_SEEK_RESPAWN_FIXTURE), seekable_members=True) as archive,
        archive.open("tail.txt") as stream,
    ):
        stream.read(8)
        stream.seek(0)
        assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES in dict(
            stream.diagnostics.counts
        )
        assert stream.read() == _SEEK_RESPAWN_TAIL


def test_rewind_warning_min_redecode_bytes_is_a_cost_floor() -> None:
    """A carrier-declared floor must fire even when discarded member progress is tiny."""
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.streams.archive_stream import (
        ArchiveStreamImpl,
        RewindWarning,
    )

    collector = DiagnosticCollector()
    payload = b"abcdefghij"
    warning = RewindWarning(
        codec_name="rar",
        suggest_install=False,
        min_redecode_bytes=REWIND_REDECODE_WARN_BYTES,
    )
    stream = ArchiveStreamImpl(
        lambda: io.BytesIO(payload),
        translate=lambda _exc: None,
        rewind_warning=warning,
        collector=collector,
    )
    try:
        stream.read(5)
        stream.seek(0)
        assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES in dict(
            stream.diagnostics.counts
        )
    finally:
        stream.close()

    quiet = ArchiveStreamImpl(
        lambda: io.BytesIO(payload),
        translate=lambda _exc: None,
        rewind_warning=RewindWarning(codec_name="rar", suggest_install=False),
        collector=DiagnosticCollector(),
    )
    try:
        quiet.read(5)
        quiet.seek(0)
        assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES not in dict(
            quiet.diagnostics.counts
        )
    finally:
        quiet.close()


@requires_binary("unrar")
def test_seekable_unrar_respawns_while_process_still_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backward seek must reap a live ``unrar``, not only an already-exited one."""
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with (
        open_archive(_fixture(_SEEK_RESPAWN_FIXTURE), seekable_members=True) as archive,
        archive.open("prefix.bin") as stream,
    ):
        first = stream.read(1024)
        assert first == _SEEK_RESPAWN_PAD[:1024]
        assert len(spawns) == 1
        stream.seek(0)
        assert stream.read(1024) == first
        assert len(spawns) == 2


@requires_binary("unrar")
def test_seekable_members_does_not_respawn_on_stored_direct_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stored nonsolid members stay a file view; seeking must not spawn ``unrar``."""
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    expected = _BASIC_CONTENTS["file1.txt"]
    with (
        open_archive(
            _fixture("basic_nonsolid__.rar"), seekable_members=True
        ) as archive,
        archive.open("file1.txt") as stream,
    ):
        assert stream.seekable() is True
        assert stream.read(5) == expected[:5]
        stream.seek(0)
        assert stream.read() == expected
    assert spawns == []


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["symlinks_solid__.rar", "symlinks_solid__rar4.rar"],
)
def test_solid_symlink_demux_and_link_targets(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Solid demux skips links; packed vs unpacked sizes differ by generation.

    Measured on this pair: RAR5 links are packed 0 / unpacked 6–12 / emit 0;
    RAR4 (old on-disk family) links are packed 6–12 / unpacked 6–12 / emit 0.
    ``is_payload_file()`` is the predictor. The ``__rar4`` archive is RAR3-family;
    its link members are stored M0 (``compress_size == file_size``). There is no
    RAR 1.5/2.x solid-symlink fixture in the tree.
    """
    path = _fixture(name)
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(archive_path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(archive_path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(path) as archive:
        assert archive.info.is_solid is True
        rar5 = archive.info.format_version == "5"
        by_name = {m.name: m for m in archive.members()}
        assert by_name["symlink_to_file1.txt"].type is MemberType.SYMLINK
        assert by_name["symlink_to_file1.txt"].link_target == "file1.txt"
        assert by_name["subdir/link_to_file1.txt"].link_target == "../file1.txt"
        # Listing and ``_ensure_link_target`` must not take the payload pipe.
        assert spawns == []

        links = [m for m in archive.members() if m.type is MemberType.SYMLINK]
        assert {m.name for m in links} == {
            "symlink_to_file1.txt",
            "subdir/link_to_file1.txt",
            "subdir_link",
            "subdir_link_with_slash",
        }
        # Positive control: the oracle can produce bytes, so empty link stdout
        # is not a silent no-match.
        assert _named_unrar_p_bytes(path, "file1.txt") == b"Hello, world!"
        for member in links:
            _assert_solid_link_emission(path, member, rar5=rar5)
            raw = member._raw
            assert isinstance(raw, RarMemberInfo)
            if not rar5:
                # Stored M0. Fails if a regeneration starts compressing targets.
                assert raw.compress_size == raw.file_size

        # Follow the link: named ``unrar p`` is the target file, not the symlink.
        assert archive.read("symlink_to_file1.txt") == b"Hello, world!"
        assert spawns == ["file1.txt"]

        payload_names: list[str] = []
        pipe_bytes = 0
        for member, stream in archive.stream_members():
            if member.is_file and stream is not None:
                data = stream.read()
                payload_names.append(member.name)
                pipe_bytes += len(data)
                assert data == b"Hello, world!"
            else:
                assert stream is None
                assert member.type in (
                    MemberType.SYMLINK,
                    MemberType.DIRECTORY,
                    MemberType.HARDLINK,
                )
        # Only payload FILE members advance the unrar p pipe.
        # None is the unnamed solid ALL-pipe the sequential pass takes.
        assert payload_names == ["file1.txt"]
        assert pipe_bytes == 13
        assert spawns == ["file1.txt", None]


@requires_binary("unrar")
def test_solid_hardlink_demux_and_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    """RAR5 solid hardlinks match RAR5 symlinks: packed 0 / unpacked > 0 / emit 0."""
    path = _fixture("hardlinks_solid__.rar")
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(archive_path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(archive_path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(path) as archive:
        assert archive.info.is_solid is True
        assert archive.info.format_version == "5"
        by_name = {m.name: m for m in archive.members()}
        assert by_name["subdir/hardlink_to_file1.txt"].type is MemberType.HARDLINK
        assert by_name["subdir/hardlink_to_file1.txt"].link_target == "file1.txt"
        assert by_name["hardlink_to_file2.txt"].link_target == "subdir/file2.txt"
        assert spawns == []

        hardlinks = [m for m in archive.members() if m.type is MemberType.HARDLINK]
        assert {m.name for m in hardlinks} == {
            "subdir/hardlink_to_file1.txt",
            "hardlink_to_file2.txt",
        }
        assert _named_unrar_p_bytes(path, "file1.txt") == b"Hello 1!"
        for member in hardlinks:
            _assert_solid_link_emission(path, member, rar5=True)

        payloads = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if member.is_file and stream is not None
        }
        assert payloads == {
            "file1.txt": b"Hello 1!",
            "subdir/file2.txt": b"Hello 2!",
        }
        assert archive.read("subdir/hardlink_to_file1.txt") == b"Hello 1!"
        # None is the unnamed solid ALL-pipe; file1.txt is the followed target.
        assert spawns == [None, "file1.txt"]


@requires("cryptography")
@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["encrypted_header__.rar", "encrypted_header__rar4.rar"],
)
def test_encrypted_header_lists_with_password(name: str) -> None:
    path = _fixture(name)
    with pytest.raises(EncryptionError):
        open_archive(path)
    with open_archive(path, password="header_password") as archive:
        assert archive.info.is_encrypted is True
        assert archive.read("file1.txt") == b"Hello, world!"


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["encryption__.rar", "encryption__rar4.rar"],
)
def test_encrypted_data_requires_password(name: str) -> None:
    path = _fixture(name)
    with open_archive(path) as archive:
        assert archive.info.is_encrypted is True
        with pytest.raises((EncryptionError, CorruptionError)):
            archive.read("secret.txt")
    with open_archive(path, password="password") as archive:
        assert archive.read("secret.txt") == b"This is secret"
        assert archive.read("also_secret.txt") == b"This is also secret"


@requires("cryptography")
@requires_binary("unrar")
@pytest.mark.parametrize(
    ("name", "password"),
    [
        # -p: members share one salt; PswCheck and HashKey once each, however
        # often members are opened.
        ("encryption__.rar", "password"),
        # -hp: the members' PswCheck is the header parse's own derivation.
        ("encrypted_header__.rar", "header_password"),
        # -hp volume set: every part repeats the header's encryption record.
        ("tinyvol_hp.part1.rar", "header_password"),
    ],
)
def test_rar5_reader_derives_each_key_once(
    name: str, password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One cache serves the header parse and every member read.

    Before it, a member open derived four keys (PswCheck and HashKey, twice
    each), an ``-hp`` archive re-derived its header PswCheck per member, and a
    volume set re-derived the header keys per part. Each derivation costs up to
    ``2**24`` PBKDF2 rounds, at the archive's choosing.
    """
    from archivey.internal.backends import rar_parser

    derived: list[tuple[bytes, int]] = []
    real = rar_parser.pbkdf2_hmac

    def counting(
        hash_name: str, secret: bytes, salt: bytes, iterations: int, dklen: int
    ) -> bytes:
        derived.append((salt, iterations))
        return real(hash_name, secret, salt, iterations, dklen)

    monkeypatch.setattr(rar_parser, "pbkdf2_hmac", counting)
    with open_archive(_fixture(name), password=password) as archive:
        files = [m for m in archive.members() if m.is_file]
        assert files
        for _ in range(2):
            for member in files:
                archive.read(member)
        for _member, stream in archive.stream_members():
            if stream is not None:
                stream.read()
    assert derived
    assert len(derived) == len(set(derived)), derived


@requires_binary("unrar")
@pytest.mark.parametrize(
    ("name", "member_name", "payload"),
    [
        ("encryption__.rar", "secret.txt", b"This is secret"),
        ("encryption_blake2sp.rar", "store.txt", b"stored payload"),
    ],
)
def test_rar5_encrypted_data_password_list_order_does_not_matter(
    name: str, member_name: str, payload: bytes
) -> None:
    """A candidate list with the right password second used to fail on RAR5 data.

    Headers are clear, so nothing tried the list at open, and every ``unrar`` spawn was
    handed the first candidate. The member's PswCheck now picks the right one.
    """
    path = _fixture(name)
    with open_archive(path, password=["wrong", "password"]) as archive:
        assert archive.read(member_name) == payload
    with open_archive(path, password=["wrong", "password"]) as archive:
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
        assert read[member_name] == payload


@requires_binary("unrar")
def test_rar5_solid_encrypted_pass_gets_the_matching_password() -> None:
    """A ``stream_members()`` pass is one ``unrar p`` spawn for the whole archive."""
    path = _fixture("encryption_solid__.rar")
    with open_archive(path, password=["wrong", "password"]) as archive:
        assert archive.info.is_solid
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert read == {
        "also_secret.txt": b"This is also secret",
        "secret.txt": b"This is secret",
    }
    with open_archive(path, password=["wrong", "password"]) as archive:
        assert archive.read("secret.txt") == b"This is secret"


@requires_binary("unrar")
def test_rar5_solid_plain_member_gets_the_archive_password() -> None:
    """A plain member of a solid archive decodes through its encrypted predecessors.

    ``rar`` cannot append a plain member to a solid encrypted archive (it asks for
    the password and then encrypts the new member too), so the plain member is made
    by dropping ``secret.txt``'s encryption record after listing. Its bytes are
    still encrypted, so ``unrar`` only returns them with the password the other
    member's check picked; the first candidate is wrong.
    """
    path = _fixture("encryption_solid__.rar")
    with open_archive(path, password=["wrong", "password"]) as archive:
        member = archive.get("secret.txt")
        assert member is not None
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        member._raw = dataclasses.replace(raw, file_encryption=None)
        assert archive.read(member) == b"This is secret"


@requires_binary("unrar")
def test_rar5_encrypted_data_asks_provider_again_after_a_wrong_answer() -> None:
    asked: list[tuple[str | None, int]] = []

    def provider(request: PasswordRequest) -> str:
        member = request.member
        asked.append((member.name if member is not None else None, request.attempt))
        return "wrong" if request.attempt == 1 else "password"

    with open_archive(_fixture("encryption__.rar"), password=provider) as archive:
        assert archive.read("secret.txt") == b"This is secret"
        assert archive.read("also_secret.txt") == b"This is also secret"
    # The second member shares the first one's encryption record: no second prompt.
    assert asked == [("secret.txt", 1), ("secret.txt", 2)]


@requires_binary("unrar")
def test_rar5_tweaked_digest_checked_with_the_password_that_matched() -> None:
    """The HashKey comes from the candidate PswCheck accepted, not the first one.

    Deriving it from the first candidate would silently skip the tweaked-digest check
    (its PswCheck fails, so no key) and read a corrupt member as good.
    """
    path = _fixture("encryption_blake2sp.rar")
    with open_archive(path, password=["wrong", "password"]) as reader:
        member = next(m for m in reader.members() if m.is_file)
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        member._raw = dataclasses.replace(raw, blake2sp_hash=bytes(32))
        with raises_corruption_not_truncation(match="blake2sp"):
            reader.read(member)


@requires_binary("unrar")
def test_stored_m0_direct_read() -> None:
    with open_archive(_fixture("stored_m0.rar")) as archive:
        member = next(m for m in archive.members() if m.is_file)
        assert member.compression[0].algo is CompressionAlgorithm.STORED
        assert member.extra[EXTRA_RAR_EXTRACT_VERSION] == 50
        assert archive.read(member) == b"stored payload"


@pytest.mark.parametrize(
    ("name", "member_name", "algo", "level", "extract_version"),
    [
        ("stored_m0.rar", "store.txt", CompressionAlgorithm.STORED, None, 50),
        ("basic_solid__.rar", "file1.txt", CompressionAlgorithm.RAR, 3, 50),
        ("basic_solid__rar4.rar", "file1.txt", CompressionAlgorithm.RAR, 3, 29),
        ("rar15-comment.rar", "FILE1.TXT", CompressionAlgorithm.RAR, 3, 15),
        ("rar15-comment.rar", "FILE2.TXT", CompressionAlgorithm.STORED, None, 15),
        (
            "rar202-comment-nopsw.rar",
            "FILE1.TXT",
            CompressionAlgorithm.STORED,
            None,
            20,
        ),
    ],
)
def test_member_reports_exact_compression_and_extract_version(
    name: str,
    member_name: str,
    algo: CompressionAlgorithm,
    level: int | None,
    extract_version: int,
) -> None:
    with open_archive(_fixture(name)) as archive:
        member = next(m for m in archive.members() if m.name == member_name)
        method = member.compression[0]
        assert method.algo is algo
        assert method.level is level
        assert member.extra[EXTRA_RAR_EXTRACT_VERSION] == extract_version


def test_rar3_unp_ver_byte_is_reported_unvalidated() -> None:
    """RAR3 copies UNP_VER as stored; a value outside {15,20,29,50} still lists."""
    main_hdr, end_hdr = _rar3_main_and_end()
    file_hdr = _rar3_file_block(
        b"a.txt", flags=0, pack_lo=0, unp_lo=0, extract_version=200
    )
    blob = RAR_ID + main_hdr + file_hdr + end_hdr
    parsed = parse_rar_archive(io.BytesIO(blob))
    assert parsed.members[0].extract_version == 200
    with open_archive(io.BytesIO(blob)) as archive:
        member = next(m for m in archive.members() if m.name == "a.txt")
        assert member.extra[EXTRA_RAR_EXTRACT_VERSION] == 200


def test_unknown_method_byte_omits_level() -> None:
    """A method byte outside M0–M5 lists as UNKNOWN with no leftover level."""
    info = RarMemberInfo(
        filename="a.txt",
        orig_filename=b"a.txt",
        file_size=0,
        compress_size=0,
        compress_type=0x40,
        crc32=None,
        blake2sp_hash=None,
        mtime=None,
        ctime=None,
        atime=None,
        mode=None,
        host_os=None,
        flags=0,
        file_redir=None,
        file_encryption=None,
        header_offset=0,
        header_size=0,
        data_offset=0,
        extract_version=50,
        file_solid=False,
        is_directory=False,
        is_symlink=False,
        is_hardlink_or_copy=False,
        is_encrypted=False,
        volume_index=0,
        split_before=False,
        split_after=False,
    )
    method = rar_reader._compression_for(info)[0]
    assert method.algo is CompressionAlgorithm.UNKNOWN
    assert method.level is None


_FILE_VERSION_CONTENTS = {
    "file.txt;1": b"version-one",
    "file.txt;2": b"version-two!!",
    "file.txt": b"version-three!!!",
}


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["file_version__.rar", "file_version__rar4.rar"],
)
def test_file_version_list_and_read(name: str) -> None:
    with open_archive(_fixture(name)) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == set(_FILE_VERSION_CONTENTS)
        for member_name, expected in _FILE_VERSION_CONTENTS.items():
            member = files[member_name]
            if member_name == "file.txt":
                assert member.is_current is True
                assert "rar.file_version" not in member.extra
            else:
                assert member.is_current is False
                assert member.extra["rar.file_version"] == int(
                    member_name.rsplit(";", 1)[1]
                )
            assert archive.read(member) == expected
            assert archive.read(member_name) == expected


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    ["file_version__.rar", "file_version__rar4.rar"],
)
def test_file_version_extract_all_skips_history(name: str, tmp_path: Path) -> None:
    dest = tmp_path / "out"
    dest.mkdir()
    with open_archive(_fixture(name)) as archive:
        results = archive.extract_all(dest).results
    by_name = {r.member.name: r for r in results if r.member.is_file}
    assert by_name["file.txt;1"].status is ExtractionStatus.SUPERSEDED
    assert by_name["file.txt;2"].status is ExtractionStatus.SUPERSEDED
    assert by_name["file.txt"].status is ExtractionStatus.EXTRACTED
    assert (dest / "file.txt").read_bytes() == _FILE_VERSION_CONTENTS["file.txt"]
    assert not (dest / "file.txt;1").exists()
    assert not (dest / "file.txt;2").exists()


@requires_binary("unrar")
def test_file_version_solid_demux_aligned() -> None:
    expected = {
        "a.txt;1": b"AAA-v1",
        "b.txt": b"BBB-payload",
        "a.txt": b"AAA-v2-longer",
    }
    with open_archive(_fixture("file_version_solid__.rar")) as archive:
        assert archive.info.is_solid is True
        streamed = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if member.is_file and stream is not None
        }
        assert streamed == expected
        for member_name, payload in expected.items():
            assert archive.read(member_name) == payload
        history = archive.get("a.txt;1")
        assert history is not None
        assert history.is_current is False
        assert history.extra["rar.file_version"] == 1


@requires_binary("unrar")
def test_blake2sp_only_hash() -> None:
    with open_archive(_fixture("blake2sp.rar")) as archive:
        member = next(m for m in archive.members() if m.is_file)
        assert HashAlgorithm.CRC32 not in member.hashes
        assert HashAlgorithm.BLAKE2SP in member.hashes
        assert archive.read(member) == b"stored payload"


@requires_binary("unrar")
def test_blake2sp_verified_no_unverifiable_diagnostic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with (
        caplog.at_level(logging.WARNING, logger="archivey.integrity"),
        open_archive(_fixture("blake2sp.rar")) as archive,
    ):
        member = next(m for m in archive.members() if m.is_file)
        assert archive.read(member) == b"stored payload"
        assert archive.diagnostics.total_count == 0
    assert not any(
        "Cannot verify digest 'blake2sp'" in rec.message for rec in caplog.records
    )


@requires_binary("unrar")
def test_blake2sp_corrupt_payload_raises(tmp_path: Path) -> None:
    raw = _fixture("blake2sp.rar").read_bytes()
    payload = b"stored payload"
    offset = raw.find(payload)
    assert offset >= 0
    mutated = bytearray(raw)
    mutated[offset] ^= 0x01
    corrupt = tmp_path / "blake2sp_corrupt.rar"
    corrupt.write_bytes(mutated)
    with open_archive(corrupt) as archive:
        member = next(m for m in archive.members() if m.is_file)
        assert HashAlgorithm.BLAKE2SP in member.hashes
        with raises_corruption_not_truncation(match="blake2sp"):
            archive.read(member)


@requires_unrar_cli()
def test_blake2sp_unrar_oracle_crosscheck() -> None:
    fixture = _fixture("blake2sp.rar")
    with open_archive(fixture) as archive:
        member = next(m for m in archive.members() if m.is_file)
        native = archive.read(member)
    proc = subprocess.run(
        ["unrar", "p", "-inul", str(fixture)],
        check=True,
        capture_output=True,
    )
    assert proc.stdout == native == b"stored payload"


def test_multi_volume_roundtrip() -> None:
    part1 = _fixture("tinyvol.part1.rar")
    assert (_FIXTURES / "tinyvol.part2.rar").is_file()
    with open_archive(part1) as archive:
        assert archive.info.is_multivolume is True
        assert archive.info.extra.get("rar.volume_count") == 2
        data = archive.read("payload.bin")
        assert data == b"ABCDEFGH" * 200
        assert archive.cost.notes == ()


def _stdin_payload(stem: str) -> bytes:
    """The bytes ``scripts/gen_rar_fixtures.py`` piped to ``rar -si`` for ``stem``."""
    seed, size = {
        "stdin_vol": (b"stdin-vol", 2000),
        "stdin_vol_m3": (b"stdin-vol-m3", 4000),
    }[stem]
    lines = (
        hashlib.sha256(seed + i.to_bytes(4, "big")).hexdigest().encode() + b"\n"
        for i in range(size // 65 + 1)
    )
    return b"".join(lines)[:size]


@pytest.mark.parametrize(
    "stem",
    [
        "stdin_vol",
        pytest.param("stdin_vol_m3", marks=requires_unrar_cli()),
    ],
)
def test_volumes_written_from_stdin_take_the_size_from_the_last_part(
    stem: str, tmp_path: Path
) -> None:
    """``rar a -v -si`` marks every part but the last "size unknown" and leaves a
    placeholder in the size field; the last part has the real size. The placeholder
    was listed as the size, so reads failed as truncated and extraction as a ratio
    bomb."""
    payload = _stdin_payload(stem)
    with open_archive(_fixture(f"{stem}.part1.rar")) as archive:
        [member] = archive.members()
        assert member.size == len(payload)
        assert archive.read(member) == payload
    with open_archive(_fixture(f"{stem}.part1.rar")) as archive:
        assert [s.read() for _, s in archive.stream_members() if s] == [payload]
    with open_archive(_fixture(f"{stem}.part1.rar")) as archive:
        archive.extract_all(tmp_path)
    assert (tmp_path / "stdin.txt").read_bytes() == payload


def _flag_size_unknown(data: bytes, *, placeholder: bool = False) -> bytes:
    """``data`` with the "size unknown" file flag (``0x08``) set on every RAR5 FILE
    header, and each header CRC redone. ``placeholder`` also writes 127 over the first
    member's size, a two-byte vint (rar pads it), so the header keeps its length."""
    out = bytearray(data)
    pos = 8  # past the RAR5 signature
    while pos < len(out):
        size, body_at = load_vint(out, pos + 4)
        block_type, q = load_vint(out, body_at)
        flags, q = load_vint(out, q)
        if flags & 0x0001:  # extra area
            _, q = load_vint(out, q)
        data_size = 0
        if flags & 0x0002:  # data area
            data_size, q = load_vint(out, q)
        if block_type == 2:  # FILE; its one-byte file flags are at q
            out[q] |= 0x08
            if placeholder:
                assert out[q + 2] == 0x00  # a padded two-byte size vint
                out[q + 1 : q + 3] = b"\xff\x00"
                placeholder = False
            crc = zlib.crc32(out[pos + 4 : body_at + size]) & 0xFFFFFFFF
            out[pos : pos + 4] = crc.to_bytes(4, "little")
        if block_type == 5:  # end of archive
            break
        pos = body_at + size + data_size
    return bytes(out)


def test_stored_member_of_unknown_size_takes_its_packed_size() -> None:
    """With the "size unknown" flag and no later part, a stored member's size is its
    packed size, which is what ``unrar`` reads; the size field is ignored."""
    data = _flag_size_unknown(
        _fixture("basic_nonsolid__.rar").read_bytes(), placeholder=True
    )
    with open_archive(io.BytesIO(data)) as archive:
        member = archive.members()[0]
        assert member.name == "file1.txt"
        assert member.size == 13
        assert archive.read(member) == b"Hello, world!"


def test_stored_last_part_of_unknown_size_is_not_sized_alone(tmp_path: Path) -> None:
    """The flag on every part, the last one included: the member's packed size is the
    sum of its parts, not the last part's share."""
    for part in (1, 2, 3):
        name = f"stdin_vol.part{part}.rar"
        data = _fixture(name).read_bytes()
        (tmp_path / name).write_bytes(_flag_size_unknown(data) if part == 3 else data)
    payload = _stdin_payload("stdin_vol")
    with open_archive(tmp_path / "stdin_vol.part1.rar") as archive:
        [member] = archive.members()
        assert member.size == len(payload)
        assert archive.read(member) == payload


def test_encrypted_stored_member_of_unknown_size_keeps_its_declared_size() -> None:
    """Ciphertext is padded to the AES block, so the packed size is not the member's
    size; the declared one is kept."""
    data = _flag_size_unknown(_fixture("encryption_stored_sizes__.rar").read_bytes())
    with open_archive(io.BytesIO(data), password="password") as archive:
        [member] = [m for m in archive.members() if m.name == "size_7.bin"]
        assert member.size == 7
        assert len(archive.read(member)) == 7


def test_multi_volume_rnn_roundtrip() -> None:
    """Classic RAR4 volumes: ``name.rar`` + ``name.r00`` (``-vn`` naming)."""
    first = _fixture("tinyvol_rnn.rar")
    assert (_FIXTURES / "tinyvol_rnn.r00").is_file()
    with open_archive(first) as archive:
        assert archive.info.is_multivolume is True
        assert archive.info.extra.get("rar.volume_count") == 2
        assert archive.read("payload.bin") == b"ABCDEFGH" * 200


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("name", "member_name"),
    [
        ("tinyvol.part1.rar", "payload.bin"),
        ("tinyvol_rnn.rar", "payload.bin"),
        ("stored_solid_member__.rar", "second.bin"),
    ],
)
def test_stored_slice_matches_unrar(name: str, member_name: str) -> None:
    """Joined parts and a solid-flagged stored member read what ``unrar p`` prints."""
    fixture = _fixture(name)
    with open_archive(fixture) as archive:
        native = archive.read(member_name)
    proc = subprocess.run(
        ["unrar", "p", "-inul", str(fixture), member_name],
        check=True,
        capture_output=True,
    )
    assert proc.stdout == native


# ``tinyvol_m3``: the same split, compressed, so unrar still reads it across volumes
# (a stored member's parts are joined natively).
_M3_PAYLOAD = b"".join(hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(50))


@requires_binary("unrar")
def test_multi_volume_compressed_roundtrip() -> None:
    with open_archive(_fixture("tinyvol_m3.part1.rar")) as archive:
        assert archive.info.extra.get("rar.volume_count") == 2
        assert archive.read("payload.bin") == _M3_PAYLOAD


def _single_stream_copy_note_present(notes: tuple[str, ...]) -> bool:
    return any("will copy the whole archive to disk" in note for note in notes)


def _stream_volumes_copy_note_present(notes: tuple[str, ...]) -> bool:
    return any("will copy every volume to a temp directory" in note for note in notes)


def test_path_source_has_no_stream_copy_cost_note() -> None:
    with open_archive(_fixture("basic_solid__.rar")) as archive:
        assert archive.cost.notes == ()


@requires_binary("unrar")
def test_path_source_compressed_read_has_no_stream_copy_cost_note() -> None:
    with open_archive(_fixture("basic_solid__.rar")) as archive:
        held = archive.cost
        assert held.notes == ()
        archive.read("file1.txt")
        assert archive.cost == held


def test_stream_source_has_copy_cost_note_at_open() -> None:
    blob = _fixture("stored_m0.rar").read_bytes()
    with open_archive(io.BytesIO(blob)) as archive:
        held = archive.cost
        assert _single_stream_copy_note_present(held.notes)
        member = next(m for m in archive.members() if m.is_file)
        assert archive.read(member) == b"stored payload"
        assert archive.cost == held


@requires_binary("unrar")
def test_stream_compressed_read_keeps_open_time_cost_note() -> None:
    blob = _fixture("basic_solid__.rar").read_bytes()
    with open_archive(io.BytesIO(blob)) as archive:
        held = archive.cost
        assert _single_stream_copy_note_present(held.notes)
        archive.read("file1.txt")
        assert archive.cost == held


@requires_binary("unrar")
def test_multi_volume_stream_materialization() -> None:
    paths = [_fixture("tinyvol_m3.part1.rar"), _FIXTURES / "tinyvol_m3.part2.rar"]
    streams = [p.open("rb") for p in paths]
    try:
        with open_archive(streams) as archive:
            assert archive.info.is_multivolume is True
            held = archive.cost
            assert _stream_volumes_copy_note_present(held.notes)
            assert archive.read("payload.bin") == _M3_PAYLOAD
            assert archive.cost == held
    finally:
        for stream in streams:
            stream.close()


def _rar_volume_temp_dirs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Record every temp directory the stream-volume copy creates."""
    created: list[Path] = []
    real = rar_reader.tempfile.mkdtemp

    def spy(*args: object, **kwargs: object) -> str:
        made = real(*args, **kwargs)  # type: ignore[arg-type]
        created.append(Path(made))
        return made

    monkeypatch.setattr(rar_reader.tempfile, "mkdtemp", spy)
    return created


def _rar_temp_artifacts(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Record every temp file *and* directory the reader creates.

    ``_rar_volume_temp_dirs`` covers the volume-set shape only; a single stream
    source spools through ``mkstemp``, and a solid pass keeps a large file-copy
    source in a ``tempfile.TemporaryFile``, so a test that must prove nothing was
    written needs all three. ``tempfile`` is the shared module, so the spies see
    calls from every backend module.
    """
    created: list[Path] = []
    real_mkdtemp = rar_reader.tempfile.mkdtemp
    real_mkstemp = rar_reader.tempfile.mkstemp
    real_temporary_file = rar_reader.tempfile.TemporaryFile

    def spy_mkdtemp(*args: object, **kwargs: object) -> str:
        made = real_mkdtemp(*args, **kwargs)  # type: ignore[arg-type]
        created.append(Path(made))
        return made

    def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, made = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
        created.append(Path(made))
        return fd, made

    def spy_temporary_file(*args: object, **kwargs: object) -> object:
        made = real_temporary_file(*args, **kwargs)  # type: ignore[arg-type]
        # Unnamed on POSIX (``name`` is the descriptor), so the entry is a label.
        created.append(Path(tempfile.gettempdir(), f"<TemporaryFile {made.name}>"))
        return made

    monkeypatch.setattr(rar_reader.tempfile, "mkdtemp", spy_mkdtemp)
    monkeypatch.setattr(rar_reader.tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(rar_reader.tempfile, "TemporaryFile", spy_temporary_file)
    return created


def test_stream_volume_listing_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Listing a stream-volume set is served from the originals, not from copies.

    The header walk reads each volume through its own ``SharedSource`` view, so a
    caller that only lists pays no disk write. Before this, the constructor copied
    every volume whether or not anything read a member.
    """
    created = _rar_volume_temp_dirs(monkeypatch)
    streams = [
        io.BytesIO(_fixture("tinyvol.part1.rar").read_bytes()),
        io.BytesIO((_FIXTURES / "tinyvol.part2.rar").read_bytes()),
    ]
    with open_archive(streams) as archive:
        assert [m.name for m in archive.members()] == ["payload.bin"]
        assert archive.info.is_multivolume is True
        assert archive.info.extra.get("rar.volume_count") == 2
        assert created == []


@requires_binary("unrar")
def test_stream_volume_read_materializes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The copy happens on the first read unrar serves, and only once."""
    created = _rar_volume_temp_dirs(monkeypatch)
    streams = [
        io.BytesIO(_fixture("tinyvol_m3.part1.rar").read_bytes()),
        io.BytesIO((_FIXTURES / "tinyvol_m3.part2.rar").read_bytes()),
    ]
    with open_archive(streams) as archive:
        assert created == []
        assert archive.read("payload.bin") == _M3_PAYLOAD
        assert len(created) == 1
        # unrar resolves siblings by name, so the whole set is written, not one volume.
        assert sorted(p.name for p in created[0].iterdir()) == [
            "archive.part1.rar",
            "archive.part2.rar",
        ]
        assert archive.read("payload.bin") == _M3_PAYLOAD
        assert len(created) == 1
        temp_dir = created[0]
    assert not temp_dir.exists()


@requires_binary("unrar")
@pytest.mark.parametrize(
    "source_factory",
    [
        pytest.param(
            lambda: io.BytesIO(_fixture("basic_solid__.rar").read_bytes()),
            id="single-stream",
        ),
        pytest.param(
            lambda: [
                io.BytesIO(_fixture("tinyvol_m3.part1.rar").read_bytes()),
                io.BytesIO((_FIXTURES / "tinyvol_m3.part2.rar").read_bytes()),
            ],
            id="stream-volumes",
        ),
    ],
)
def test_concurrent_stream_materialize_writes_once_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    source_factory: Callable[[], io.BytesIO | list[io.BytesIO]],
) -> None:
    """Two overlapping compressed opens must share one temp copy.

    ``_ensure_archive_path`` used to check-then-write with no lock. Under
    ``concurrent_operations=True`` both threads copied, and close only removed
    the winner's path, leaking the other into ``/tmp``.
    """
    created = _rar_temp_artifacts(monkeypatch)

    def _delay(fn: Callable[..., object]) -> Callable[..., object]:
        def delayed(*args: object, **kwargs: object) -> object:
            time.sleep(0.1)
            return fn(*args, **kwargs)

        return delayed

    monkeypatch.setattr(
        rar_reader.tempfile, "mkstemp", _delay(rar_reader.tempfile.mkstemp)
    )
    monkeypatch.setattr(
        rar_reader.tempfile, "mkdtemp", _delay(rar_reader.tempfile.mkdtemp)
    )

    source = source_factory()
    try:
        with open_archive(source, concurrent_operations=True) as archive:
            names = [m.name for m in archive.members() if m.is_file]
            target = names[0]
            errors: list[BaseException] = []
            start = threading.Barrier(2)

            def worker() -> None:
                try:
                    start.wait(timeout=5)
                    with archive.open(target) as stream:
                        stream.read()
                except BaseException as exc:  # noqa: BLE001 - collect; asserted empty below
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                assert not thread.is_alive()
            assert errors == []
            assert len(created) == 1
        assert not created[0].exists()
    finally:
        for path in created:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink(missing_ok=True)


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_incomplete_multi_volume_lists_then_raises(streaming: bool) -> None:
    """A lone volume 1 whose end block says another volume follows.

    Ruled 2026-10-06 (this used to refuse at open): list the members the volumes
    present hold, then raise ``TruncatedError``, as for a cut single file and as
    ``unrar`` does. The one member here runs into the missing volume, so its read
    is a truncation too.
    """
    part1 = _fixture("tinyvol.part1.rar").read_bytes()
    with open_archive(io.BytesIO(part1), streaming=streaming) as archive:
        report = archive.members_report()
        assert [m.name for m in report.members] == ["payload.bin"]
        assert isinstance(report.error, TruncatedError)
        assert "expects another volume (volume 2 is missing)" in str(report.error)
    with open_archive(io.BytesIO(part1), streaming=streaming) as archive:
        if not streaming:
            with pytest.raises(TruncatedError, match="multi-volume"):
                archive.members()
        seen: list[str] = []
        with pytest.raises(TruncatedError, match="multi-volume"):
            for member, stream in archive.stream_members():
                assert stream is not None
                with pytest.raises(TruncatedError, match="continues into a volume"):
                    stream.read()
                seen.append(member.name)
        assert seen == ["payload.bin"]


@requires_binary("unrar")
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("rar15-comment.rar", {"FILE1.TXT": b"foooo\r\n", "FILE2.TXT": b"baaaar\r\n"}),
        (
            "rar202-comment-nopsw.rar",
            {"FILE1.TXT": b"file1\r\n", "FILE2.TXT": b"file2\r\n"},
        ),
    ],
)
def test_rar15_and_rar2_list_and_read(name: str, expected: dict[str, bytes]) -> None:
    """RAR 1.5 / 2.x archives list and read via native headers + unrar."""
    with open_archive(_fixture(name)) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == set(expected)
        for member_name, payload in expected.items():
            assert archive.read(files[member_name]) == payload


@requires("rarfile")
@requires_unrar_cli()
@pytest.mark.parametrize("name", ["rar15-comment.rar", "rar202-comment-nopsw.rar"])
def test_rar15_and_rar2_comments_match_rarfile(name: str) -> None:
    """Legacy embedded archive and member comments match the reference reader."""
    rarfile = pytest.importorskip("rarfile")
    path = _fixture(name)
    with rarfile.RarFile(path) as oracle:
        expected_archive_comment = oracle.comment
        expected_member_comments = {
            info.filename.replace("\\", "/").rstrip("/"): info.comment
            for info in oracle.infolist()
            if not info.is_dir()
        }

    with open_archive(path) as archive:
        assert archive.info.comment == expected_archive_comment
        assert {
            member.name: member.comment
            for member in archive.members()
            if member.is_file
        } == expected_member_comments


def _rar3_old_comment_subblock(text: bytes) -> bytes:
    """Build an old-style stored COMMENT subblock with its CRC16."""
    from archivey.internal.backends.rar_parser import _crc32

    comment_body = (
        struct.pack(
            "<HBBH",
            len(text),
            20,  # RAR 2.0 extract version
            0x30,  # M0 stored
            _crc32(text) & 0xFFFF,
        )
        + text
    )
    header_without_crc = (
        struct.pack(
            "<BHH",
            0x75,  # OLD_COMMENT
            0,
            7 + len(comment_body),
        )
        + comment_body
    )
    return struct.pack("<H", _crc32(header_without_crc) & 0xFFFF) + header_without_crc


def test_rar3_stored_old_style_main_comment_needs_no_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stored legacy comment is listed natively with no binary on PATH."""
    from archivey.internal.backends.rar_parser import (
        _RAR3_MAIN_COMMENT,
        _crc32,
        rar3_main_crc_end,
    )

    text = b"stored old-style comment"
    subblock = _rar3_old_comment_subblock(text)
    flags = _RAR3_MAIN_COMMENT
    main_body = b"\0" * 6 + subblock
    main_without_crc = struct.pack("<BHH", 0x73, flags, 7 + len(main_body)) + main_body
    # Old COMMENT subblocks are inside header_size but outside the MAIN CRC.
    main_crc = _crc32(main_without_crc[: rar3_main_crc_end(flags) - 2]) & 0xFFFF
    main_hdr = struct.pack("<H", main_crc) + main_without_crc
    end_without_crc = struct.pack("<BHH", 0x7B, 0, 7)
    end_hdr = struct.pack("<H", _crc32(end_without_crc) & 0xFFFF) + end_without_crc

    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    with open_archive(io.BytesIO(RAR_ID + main_hdr + end_hdr)) as archive:
        assert archive.info.comment == text.decode()


@pytest.mark.parametrize(
    "flag", [rar_unrar._RAR3_FILE_PASSWORD, rar_unrar._RAR3_FILE_SALT]
)
@pytest.mark.parametrize("compress_type", [0x30, 0x33])
def test_rar3_encrypted_old_style_comment_is_skipped_up_front(
    monkeypatch: pytest.MonkeyPatch, flag: int, compress_type: int
) -> None:
    """An encrypted old-style comment decodes to None and never spawns ``unrar``.

    The comment subblock keeps no salt, so the synthetic FILE header could not carry
    one. No writer produces such a comment, so this is the only test of the branch.
    """

    def _no_spawn(*args: object, **kwargs: object) -> None:
        raise AssertionError("unrar must not be spawned for an encrypted comment")

    monkeypatch.setattr(rar_unrar, "open_unrar_p", _no_spawn)
    packed = b"old-style comment"
    assert (
        rar_unrar.decompress_rar3_blob(
            extract_version=29,
            compress_type=compress_type,
            packed=packed,
            unpacked_size=len(packed),
            flags=flag,
            crc16=zlib.crc32(packed) & 0xFFFF,
        )
        is None
    )


@pytest.mark.parametrize(
    "flag", [rar_unrar._RAR3_FILE_PASSWORD, rar_unrar._RAR3_FILE_SALT]
)
@pytest.mark.parametrize("compress_type", [0x30, 0x33])
def test_rar3_parser_drops_encrypted_old_style_comment(
    flag: int, compress_type: int
) -> None:
    """The listing path drops an encrypted comment, stored ones included.

    A stored comment with only the SALT flag used to be taken as plaintext whenever
    its CRC16 matched, which a crafted archive can arrange.
    """
    from archivey.internal.backends import rar_parser as rp

    payload = b"secret comment"
    body = (
        rp._S_COMMENT_HDR.pack(
            len(payload), 29, compress_type, zlib.crc32(payload) & 0xFFFF
        )
        + payload
    )
    block = (
        rp._S_BLK_HDR.pack(
            0, rp._RAR3_OLD_COMMENT, flag, rp._S_BLK_HDR.size + len(body)
        )
        + body
    )
    assert rp._parse_rar3_old_comment_subblocks(block, 0, encoding=None) is None


def test_rar3_service_comment_maps_to_member_comment() -> None:
    """RAR3's existing solid CMT attachment reaches ArchiveMember.comment."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SOLID

    main_hdr, end_hdr = _rar3_main_and_end()
    comment = b"member comment"
    file_hdr = _rar3_file_block(b"item.txt", flags=0, pack_lo=0, unp_lo=0)
    service_hdr = _rar3_file_block(
        b"CMT",
        flags=_RAR3_FILE_SOLID,
        pack_lo=len(comment),
        unp_lo=len(comment),
        block_type=0x7A,
    )

    with open_archive(
        io.BytesIO(RAR_ID + main_hdr + file_hdr + service_hdr + comment + end_hdr)
    ) as archive:
        member = archive.get("item.txt")
        assert member is not None
        assert member.comment == comment.decode()


def test_rar3_service_comment_is_weighed_by_the_walk_as_it_attaches() -> None:
    """A ``CMT`` comment reaches its member after the member was weighed, so the walk
    weighs it as it attaches: ``item.txt`` (8 + 8 bytes) and its 14-byte comment
    make 30, refused at 29 by the walk itself and listed at 30."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SOLID

    main_hdr, end_hdr = _rar3_main_and_end()
    comment = b"member comment"
    file_hdr = _rar3_file_block(b"item.txt", flags=0, pack_lo=0, unp_lo=0)
    service_hdr = _rar3_file_block(
        b"CMT",
        flags=_RAR3_FILE_SOLID,
        pack_lo=len(comment),
        unp_lo=len(comment),
        block_type=0x7A,
    )
    blob = RAR_ID + main_hdr + file_hdr + service_hdr + comment + end_hdr

    def limits(max_metadata_bytes: int) -> ArchiveyConfig:
        return ArchiveyConfig(
            listing_limits=ListingLimits(max_metadata_bytes=max_metadata_bytes)
        )

    with pytest.raises(
        ResourceLimitError, match=r"=29 \(RAR headers of 1 members hold 30 bytes\)"
    ):
        open_archive(io.BytesIO(blob), config=limits(29))
    with open_archive(io.BytesIO(blob), config=limits(30)) as archive:
        member = archive.get("item.txt")
        assert member is not None
        assert member.comment == comment.decode()


# unrar reads a RAR 2.9-4 ``CMT`` as UTF-16LE only when bit 0 of the SERVICE
# header's attribute field (``SUBHEAD_FLAGS_CMT_UNICODE``) is set, and as 8-bit
# text cut at the first NUL otherwise (``Archive::ReadCommentData``). Checked with
# ``unrar l`` 7.00 on archives built like these.
@pytest.mark.parametrize(
    ("stored", "attributes", "expected"),
    [
        pytest.param(b"caf\xe9 ok", 0, "caf\xe9 ok", id="ansi-odd-length"),
        # An even length used to decode as UTF-16LE: '\u6163\u6166\u20e9\u6b6f'.
        pytest.param(b"caf\xe9 ok!", 0, "caf\xe9 ok!", id="ansi-even-length"),
        pytest.param("caf\xe9 ok!".encode(), 0, "caf\xe9 ok!", id="utf8"),
        # A byte windows-1252 leaves undefined survives, as it does in a name.
        pytest.param(b"\x81\x81\x81", 0, "\udc81" * 3, id="undefined-cp1252"),
        pytest.param(
            "caf\xe9 ok!".encode("utf-16le"), 1, "caf\xe9 ok!", id="unicode-flag"
        ),
        pytest.param(
            "a\U0001f600".encode("utf-16le") + b"\0\0junk",
            1,
            "a\U0001f600",
            id="unicode-flag-cut-at-nul",
        ),
        # unrar reads CmtSize / 2 units, so the odd trailing byte is not a U+FFFD.
        pytest.param(
            "hi".encode("utf-16le") + b"\xff", 1, "hi", id="unicode-flag-odd-length"
        ),
        # A unit without its partner stays as that unit, as in a RAR3 Unicode name.
        pytest.param(
            b"h\x00i\x00\x00\xd8 \x00", 1, "hi\ud800 ", id="unicode-flag-lone-surrogate"
        ),
        # Without the flag the UTF-16LE bytes are 8-bit text up to the first NUL.
        pytest.param("caf\xe9".encode("utf-16le"), 0, "c", id="utf16-no-flag"),
    ],
)
def test_rar3_service_comment_text_encoding(
    stored: bytes, attributes: int, expected: str
) -> None:
    main_hdr, end_hdr = _rar3_main_and_end()
    service_hdr = _rar3_file_block(
        b"CMT",
        flags=0,
        pack_lo=len(stored),
        unp_lo=len(stored),
        block_type=0x7A,
        attributes=attributes,
    )
    with open_archive(
        io.BytesIO(RAR_ID + main_hdr + service_hdr + stored + end_hdr)
    ) as archive:
        assert archive.info.comment == expected


def test_rar3_old_style_comment_is_not_guessed_as_utf16() -> None:
    """A RAR 1.5-2.x COMMENT subblock is always 8-bit text (``DoGetComment``)."""
    from archivey.internal.backends.rar_parser import _parse_rar3_old_comment_subblocks

    text = b"caf\xe9 ok!"
    block = _rar3_old_comment_subblock(text)
    assert _parse_rar3_old_comment_subblocks(block, 0, encoding=None) == "caf\xe9 ok!"


def test_rar3_old_style_comment_is_cut_at_the_first_nul() -> None:
    """unrar reads an old-style comment as a C string (``DoGetComment``).

    The stored subblock and the compressed one (``rar_reader``, after ``unrar``
    unpacks it) both go through ``_decode_comment_text``.
    """
    from archivey.internal.backends.rar_parser import (
        _decode_comment_text,
        _parse_rar3_old_comment_subblocks,
    )

    block = _rar3_old_comment_subblock(b"hi\0rest")
    assert _parse_rar3_old_comment_subblocks(block, 0, encoding=None) == "hi"
    assert _decode_comment_text(b"caf\xe9\0\xff", encoding=None) == "caf\xe9"


# A RAR 1.5-4 comment, like a RAR 1.5-4 8-bit name, does not record its code page, so
# ``encoding=`` decodes the bytes that are not valid UTF-8 in place of windows-1252.
# These archives are built by hand: RAR 7, the available writer, no longer writes the
# RAR 1.5-4 format.
_CP1251_COMMENT = "Привет мир"


@pytest.mark.parametrize(
    ("stored", "encoding", "expected"),
    [
        pytest.param(
            _CP1251_COMMENT.encode("cp1251"), "cp1251", _CP1251_COMMENT, id="cp1251"
        ),
        pytest.param(
            _CP1251_COMMENT.encode("cp866"), "cp866", _CP1251_COMMENT, id="cp866"
        ),
        pytest.param(
            "日本語".encode("shift_jis"), "shift_jis", "日本語", id="shift-jis"
        ),
        # Valid UTF-8 wins over encoding=, as it does for a name.
        pytest.param(
            _CP1251_COMMENT.encode(), "cp1251", _CP1251_COMMENT, id="utf8-wins"
        ),
        # Without encoding=, the windows-1252 fallback stays.
        pytest.param(
            _CP1251_COMMENT.encode("cp1251"),
            None,
            _CP1251_COMMENT.encode("cp1251").decode("windows-1252"),
            id="no-encoding",
        ),
    ],
)
@pytest.mark.parametrize("archive_comment_form", ["main-subblock", "cmt-service"])
def test_rar3_comments_decode_with_explicit_encoding(
    stored: bytes, encoding: str | None, expected: str, archive_comment_form: str
) -> None:
    from archivey.internal.backends.rar_parser import (
        _RAR3_FILE_COMMENT,
        _RAR3_FILE_SOLID,
    )

    main_hdr, end_hdr = _rar3_main_and_end()
    if archive_comment_form == "main-subblock":
        # The archive comment of a RAR 1.5-2.x archive: a subblock in the MAIN header.
        main_hdr = _rar3_main_with_comment(_rar3_old_comment_subblock(stored))
        archive_cmt = b""
    else:
        # The archive comment of a RAR 2.9-4 archive: a stored CMT SERVICE header.
        archive_cmt = (
            _rar3_file_block(
                b"CMT",
                flags=0,
                pack_lo=len(stored),
                unp_lo=len(stored),
                block_type=0x7A,
            )
            + stored
        )
    # One member comment as an old-style COMMENT subblock (RAR 1.5-2.x) ...
    old_style = _rar3_file_block(
        b"old.txt",
        flags=_RAR3_FILE_COMMENT,
        pack_lo=0,
        unp_lo=0,
        trailing_subblock=_rar3_old_comment_subblock(stored),
    )
    # ... and one as a solid CMT SERVICE header after its member (RAR 2.9-4).
    service = _rar3_file_block(b"svc.txt", flags=0, pack_lo=0, unp_lo=0)
    service_cmt = _rar3_file_block(
        b"CMT",
        flags=_RAR3_FILE_SOLID,
        pack_lo=len(stored),
        unp_lo=len(stored),
        block_type=0x7A,
    )
    data = (
        RAR_ID
        + main_hdr
        + archive_cmt
        + old_style
        + service
        + service_cmt
        + stored
        + end_hdr
    )
    with open_archive(io.BytesIO(data), encoding=encoding) as archive:
        assert archive.info.comment == expected
        old_member = archive.get("old.txt")
        service_member = archive.get("svc.txt")
        assert old_member is not None and service_member is not None
        assert old_member.comment == expected
        assert service_member.comment == expected
        # A comment is not a name: no name diagnostic is reported for it.
        counts = archive.diagnostics.counts
        assert DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED not in counts


def test_rar3_compressed_comments_take_explicit_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compressed old-style comment, once unpacked, goes through the same decode.

    The decompressor is replaced by one that returns the comment text, so the test
    walks ``_resolve_rar3_comment`` for the MAIN and the member comment without a
    RAR 1.5-4 writer.
    """
    from archivey.internal.backends import rar_parser as rp

    unpacked = _CP1251_COMMENT.encode("cp1251") + b"\0rest"
    crc16 = zlib.crc32(unpacked) & 0xFFFF
    body = rp._S_COMMENT_HDR.pack(len(unpacked), 29, 0x33, crc16) + b"\x00" * 16
    subblock = (
        rp._S_BLK_HDR.pack(0, rp._RAR3_OLD_COMMENT, 0, rp._S_BLK_HDR.size + len(body))
        + body
    )
    member = _rar3_file_block(
        b"m.txt",
        flags=rp._RAR3_FILE_COMMENT,
        pack_lo=0,
        unp_lo=0,
        trailing_subblock=subblock,
    )
    _, end_hdr = _rar3_main_and_end()
    data = RAR_ID + _rar3_main_with_comment(subblock) + member + end_hdr

    def _fake_decode(**kwargs: object) -> bytes:
        return unpacked

    monkeypatch.setattr(rar_reader, "decompress_rar3_blob", _fake_decode)
    for encoding, expected in [
        ("cp1251", _CP1251_COMMENT),
        (None, _CP1251_COMMENT.encode("cp1251").decode("windows-1252")),
    ]:
        with open_archive(io.BytesIO(data), encoding=encoding) as archive:
            assert archive.info.comment == expected
            got = archive.get("m.txt")
            assert got is not None
            assert got.comment == expected


def test_rar3_and_zip_comments_agree_on_an_undecodable_byte() -> None:
    """0x98 is undefined in cp1251: both formats keep it as a lone surrogate."""
    import zipfile

    stored = b"a\x98b"
    main_hdr, end_hdr = _rar3_main_and_end()
    archive_cmt = _rar3_file_block(
        b"CMT", flags=0, pack_lo=len(stored), unp_lo=len(stored), block_type=0x7A
    )
    rar_data = RAR_ID + main_hdr + archive_cmt + stored + end_hdr
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("a.txt", b"x")
        z.comment = stored

    with open_archive(io.BytesIO(rar_data), encoding="cp1251") as archive:
        rar_comment = archive.info.comment
    with open_archive(io.BytesIO(zip_buf.getvalue()), encoding="cp1251") as archive:
        zip_comment = archive.info.comment
    assert rar_comment == zip_comment == "a\udc98b"


def test_rar5_comment_service_stays_archive_only() -> None:
    """RAR5 CMT is an archive comment, never an invented member comment."""
    with open_archive(_fixture("comment__.rar")) as archive:
        assert archive.info.comment == "This is a\nmulti-line comment"
        assert all(member.comment is None for member in archive.members())


def test_extract_version_20_payload_accepted() -> None:
    """Craft a RAR3 archive whose payload FILE declares extract version 20."""
    from archivey.internal.backends.rar_parser import _RAR3_LONG_BLOCK, _crc32

    name = b"x.txt"
    payload = b"hi"
    # FILE fields include pack_size as the first le32; with LONG_BLOCK that
    # field is also the block add_size so the parser skips the payload.
    file_fields = struct.pack(
        "<LLBLLBBHL",
        len(payload),
        len(payload),
        3,  # Unix
        zlib.crc32(payload) & 0xFFFFFFFF,
        0,
        20,  # extract version → also used by RAR2-era and some RAR3 stored members
        0x30,  # M0
        len(name),
        0o100644,
    )
    file_fields += name
    flags = _RAR3_LONG_BLOCK
    header_without_crc = struct.pack(
        "<BHH",
        0x74,
        flags,
        7 + len(file_fields),
    )
    header_without_crc += file_fields
    file_crc = _crc32(header_without_crc) & 0xFFFF
    file_hdr = struct.pack("<H", file_crc) + header_without_crc

    main_body = b"\x00" * 6  # reserved
    main_without_crc = struct.pack("<BHH", 0x73, 0, 7 + len(main_body)) + main_body
    main_crc = _crc32(main_without_crc) & 0xFFFF
    main_hdr = struct.pack("<H", main_crc) + main_without_crc

    end_without_crc = struct.pack("<BHH", 0x7B, 0, 7)
    end_crc = _crc32(end_without_crc) & 0xFFFF
    end_hdr = struct.pack("<H", end_crc) + end_without_crc

    blob = RAR_ID + main_hdr + file_hdr + payload + end_hdr
    archive = parse_rar_archive(io.BytesIO(blob))
    assert len(archive.members) == 1
    member = archive.members[0]
    assert member.filename == "x.txt"
    assert member.extract_version == 20
    assert member.file_size == 2
    assert member.compress_size == 2


def _rar3_file_block(
    name: bytes,
    *,
    flags: int,
    pack_lo: int,
    unp_lo: int,
    pack_hi: int = 0,
    unp_hi: int = 0,
    method: int = 0x30,
    block_type: int = 0x74,
    extract_version: int = 20,
    trailing_subblock: bytes = b"",
    attributes: int = 0o100644,
    crc32: int = 0,
    salt: bytes = b"",
) -> bytes:
    """Build one RAR3 FILE block with a valid 16-bit header CRC.

    ``trailing_subblock`` (an old-style COMMENT, say) counts in ``header_size`` but
    sits after the CRC-covered fields, which is where RAR 1.5/2.x put it. ``salt``
    is the 8-byte field the SALT flag adds after the name, inside the CRC.
    """
    from archivey.internal.backends.rar_parser import (
        _RAR3_FILE_LARGE,
        _RAR3_LONG_BLOCK,
        _crc32,
    )

    file_fields = struct.pack(
        "<LLBLLBBHL",
        pack_lo,
        unp_lo,
        3,  # Unix
        crc32,
        0,  # dos time
        extract_version,
        method,
        len(name),
        attributes,
    )
    if flags & _RAR3_FILE_LARGE:
        file_fields += struct.pack("<LL", pack_hi, unp_hi)
    file_fields += name + salt
    flags |= _RAR3_LONG_BLOCK
    header_size = 7 + len(file_fields) + len(trailing_subblock)
    header_without_crc = struct.pack("<BHH", block_type, flags, header_size)
    header_without_crc += file_fields
    file_crc = _crc32(header_without_crc) & 0xFFFF
    return struct.pack("<H", file_crc) + header_without_crc + trailing_subblock


def _rar3_main_and_end() -> tuple[bytes, bytes]:
    from archivey.internal.backends.rar_parser import _crc32

    main_without_crc = struct.pack("<BHH", 0x73, 0, 7 + 6) + b"\x00" * 6
    main_hdr = struct.pack("<H", _crc32(main_without_crc) & 0xFFFF) + main_without_crc
    end_without_crc = struct.pack("<BHH", 0x7B, 0, 7)
    end_hdr = struct.pack("<H", _crc32(end_without_crc) & 0xFFFF) + end_without_crc
    return main_hdr, end_hdr


def _rar3_next_volume_end() -> bytes:
    """An ENDARC block whose flags say another volume follows."""
    from archivey.internal.backends.rar_parser import _crc32

    end_without_crc = struct.pack("<BHH", 0x7B, 0x0001, 7)
    return struct.pack("<H", _crc32(end_without_crc) & 0xFFFF) + end_without_crc


def _rar3_compressed_comment_subblock(unpacked_size: int) -> bytes:
    """An old-style COMMENT subblock declaring a *compressed* (non-M0) payload.

    The packed bytes are junk: the tests below never let ``unrar`` see them. Only the
    declared ``unpacked_size`` matters, which is what the listing budget weighs.
    """
    from archivey.internal.backends import rar_parser as rp

    body = rp._S_COMMENT_HDR.pack(unpacked_size, 29, 0x33, 0) + b"\x00" * 16
    return (
        rp._S_BLK_HDR.pack(0, rp._RAR3_OLD_COMMENT, 0, rp._S_BLK_HDR.size + len(body))
        + body
    )


def _rar3_main_with_comment(subblock: bytes) -> bytes:
    """A RAR3 MAIN header carrying an old-style COMMENT subblock (RAR 1.5-2.x)."""
    from archivey.internal.backends.rar_parser import (
        _RAR3_MAIN_COMMENT,
        _crc32,
        rar3_main_crc_end,
    )

    main_body = b"\0" * 6 + subblock
    main_without_crc = (
        struct.pack("<BHH", 0x73, _RAR3_MAIN_COMMENT, 7 + len(main_body)) + main_body
    )
    # Old COMMENT subblocks are inside header_size but outside the MAIN CRC.
    crc_end = rar3_main_crc_end(_RAR3_MAIN_COMMENT) - 2
    main_crc = _crc32(main_without_crc[:crc_end]) & 0xFFFF
    return struct.pack("<H", main_crc) + main_without_crc


def _rar3_commented_archive(
    count: int, unpacked_size: int, *, archive_comment_size: int | None = None
) -> bytes:
    """RAR3 archive of ``count`` members, each with a compressed old-style comment.

    ``archive_comment_size`` also gives the MAIN header a compressed comment.
    """
    from archivey.internal.backends.rar_parser import _RAR3_FILE_COMMENT

    main_hdr, end_hdr = _rar3_main_and_end()
    if archive_comment_size is not None:
        main_hdr = _rar3_main_with_comment(
            _rar3_compressed_comment_subblock(archive_comment_size)
        )
    members = b"".join(
        _rar3_file_block(
            f"m{i}.txt".encode(),
            flags=_RAR3_FILE_COMMENT,
            pack_lo=0,
            unp_lo=0,
            trailing_subblock=_rar3_compressed_comment_subblock(unpacked_size),
        )
        for i in range(count)
    )
    return RAR_ID + main_hdr + members + end_hdr


def _count_comment_decodes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Replace the ``unrar`` comment decode with a counter that decodes nothing."""
    calls: list[int] = []

    def _fake_decode(**kwargs: object) -> None:
        calls.append(1)

    monkeypatch.setattr(rar_reader, "decompress_rar3_blob", _fake_decode)
    return calls


def test_rar3_compressed_comments_over_metadata_budget_refused_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compressed RAR3 comments are weighed by their declared size before any decode.

    Each one costs an ``unrar`` spawn and expands to up to 64 KiB, so a crafted
    archive with a million commented members is a million forks and up to 64 GiB.
    The declared sizes are summed up front, so the refusal spawns nothing.
    """
    calls = _count_comment_decodes(monkeypatch)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=100_000))
    blob = _rar3_commented_archive(count=2, unpacked_size=60_000)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        open_archive(io.BytesIO(blob), config=config)
    assert calls == []


# Two members named ``m0.txt``/``m1.txt`` (12 bytes each as name and raw name) with
# comments of this declared size weigh exactly 100 000 bytes.
_AT_BUDGET_COMMENT = 50_000 - 2 * len("m0.txt")


def test_rar3_compressed_comments_within_metadata_budget_are_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At or under the budget every comment is still decoded, and ``None`` lifts it.

    The names count too: ``m0.txt`` weighs 12 bytes (``name`` and ``raw_name``), so
    two members with 49 988-byte comments sit exactly at 100 000.
    """
    blob = _rar3_commented_archive(count=2, unpacked_size=_AT_BUDGET_COMMENT)
    for limits in (
        ListingLimits(max_metadata_bytes=100_000),
        ListingLimits(max_metadata_bytes=None),
    ):
        calls = _count_comment_decodes(monkeypatch)
        config = ArchiveyConfig(listing_limits=limits)
        with open_archive(io.BytesIO(blob), config=config) as archive:
            assert [m.name for m in archive.members()] == ["m0.txt", "m1.txt"]
        assert len(calls) == 2


def test_rar3_compressed_archive_comment_counts_toward_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The MAIN header's compressed comment is weighed with the members' comments.

    The members alone (names and comments) sit exactly at the budget, so only the
    archive comment's bytes push the total over it.
    """
    calls = _count_comment_decodes(monkeypatch)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=100_000))
    at_budget = _rar3_commented_archive(count=2, unpacked_size=_AT_BUDGET_COMMENT)
    with open_archive(io.BytesIO(at_budget), config=config):
        pass
    assert len(calls) == 2

    calls.clear()
    over = _rar3_commented_archive(
        count=2, unpacked_size=_AT_BUDGET_COMMENT, archive_comment_size=1
    )
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        open_archive(io.BytesIO(over), config=config)
    assert calls == []


# The comment texts ``scripts/gen_rar_fixtures.py`` gives the two
# ``comment_compressed*__rar4.rar`` fixtures. ``rar`` 6.23 compresses each into a
# RAR 2.9-4 ``CMT`` SERVICE header; the unicode one is UTF-16LE with
# ``SUBHEAD_FLAGS_CMT_UNICODE`` set.
_COMPRESSED_CMT_TEXTS = {
    "comment_compressed__rar4.rar": "A compressed RAR4 archive comment.\n" * 20,
    "comment_compressed_unicode__rar4.rar": (
        "Caf\u00e9 \u2014 a compressed UTF-16 comment.\n" * 20
    ),
}


@requires_binary("unrar")
@pytest.mark.parametrize("name", sorted(_COMPRESSED_CMT_TEXTS))
def test_rar3_compressed_service_comment_is_read(name: str) -> None:
    """A compressed ``CMT`` SERVICE header is decoded by ``unrar``, as
    ``unrar l`` shows it. It used to be skipped, and the archive listed with no
    comment."""
    with open_archive(_fixture(name)) as archive:
        assert archive.info.comment == _COMPRESSED_CMT_TEXTS[name]
        assert len(archive.members()) == 3


def test_rar3_compressed_service_comment_without_a_decompressor_is_none() -> None:
    """With no program to decode it, the comment is ``None``, as a compressed
    RAR 1.5-2.x comment is, and the listing is unchanged."""
    config = ArchiveyConfig(rar_decompressor=RarDecompressor.NONE)
    with open_archive(
        _fixture("comment_compressed__rar4.rar"), config=config
    ) as archive:
        assert archive.info.comment is None
        assert len(archive.members()) == 3


def _rar3_compressed_cmt(
    *,
    unpacked_size: int,
    packed: bytes = b"\x00" * 16,
    crc32: int = 0,
    flags: int = 0,
    attributes: int = 0,
    salt: bytes = b"",
) -> bytes:
    """A RAR 2.9-4 ``CMT`` SERVICE header with ``-m3`` (0x33) data, then the data.

    ``salt`` is the 8-byte field the SALT flag adds after the name.
    """
    return (
        _rar3_file_block(
            b"CMT",
            flags=flags,
            pack_lo=len(packed),
            unp_lo=unpacked_size,
            method=0x33,
            block_type=0x7A,
            extract_version=29,
            attributes=attributes,
            salt=salt,
            crc32=crc32,
        )
        + packed
    )


def test_rar3_compressed_service_comment_counts_toward_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The declared size of a compressed ``CMT`` is weighed before any decode,
    as a compressed RAR 1.5-2.x comment is: at the budget it is decoded, one byte
    over it the listing is refused and ``unrar`` never runs."""
    main_hdr, end_hdr = _rar3_main_and_end()
    size = 1000

    def config(max_metadata_bytes: int) -> ArchiveyConfig:
        return ArchiveyConfig(
            listing_limits=ListingLimits(max_metadata_bytes=max_metadata_bytes)
        )

    blob = RAR_ID + main_hdr + _rar3_compressed_cmt(unpacked_size=size) + end_hdr
    calls = _count_comment_decodes(monkeypatch)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        open_archive(io.BytesIO(blob), config=config(size - 1))
    assert calls == []
    with open_archive(io.BytesIO(blob), config=config(size)) as archive:
        assert archive.info.comment is None  # the counter decodes nothing
    assert len(calls) == 1


def test_rar3_compressed_member_service_comment_is_weighed_as_it_attaches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A solid ``CMT`` after a member attaches to it. When compressed, the walk
    weighs its declared size, here larger than its 8 packed bytes: ``item.txt``
    (8 + 8 bytes) and a 14-byte comment make 30, refused at 29 by the walk itself
    and listed at 30."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SOLID

    text = b"member comment"
    main_hdr, end_hdr = _rar3_main_and_end()
    file_hdr = _rar3_file_block(b"item.txt", flags=0, pack_lo=0, unp_lo=0)
    blob = (
        RAR_ID
        + main_hdr
        + file_hdr
        + _rar3_compressed_cmt(
            unpacked_size=len(text),
            packed=b"\x00" * 8,
            crc32=zlib.crc32(text),
            flags=_RAR3_FILE_SOLID,
        )
        + end_hdr
    )

    def config(max_metadata_bytes: int) -> ArchiveyConfig:
        return ArchiveyConfig(
            listing_limits=ListingLimits(max_metadata_bytes=max_metadata_bytes)
        )

    calls: list[int] = []

    def _fake_decode(**kwargs: object) -> bytes:
        calls.append(1)
        return text

    monkeypatch.setattr(rar_reader, "decompress_rar3_blob", _fake_decode)
    with pytest.raises(
        ResourceLimitError, match=r"=29 \(RAR headers of 1 members hold 30 bytes\)"
    ):
        open_archive(io.BytesIO(blob), config=config(29))
    assert calls == []
    with open_archive(io.BytesIO(blob), config=config(30)) as archive:
        member = archive.get("item.txt")
        assert member is not None
        assert member.comment == text.decode()
        assert archive.info.comment is None


@pytest.mark.parametrize(
    ("decoded", "attributes", "expected"),
    [
        pytest.param(b"ok\0rest", 0, "ok", id="8bit"),
        pytest.param("caf\u00e9".encode("utf-16le"), 1, "caf\u00e9", id="unicode"),
        # The CRC32 is checked in full, not only its low 16 bits.
        pytest.param(None, 0, None, id="crc-mismatch"),
    ],
)
def test_rar3_compressed_service_comment_checks_crc32_and_unicode_flag(
    monkeypatch: pytest.MonkeyPatch,
    decoded: bytes | None,
    attributes: int,
    expected: str | None,
) -> None:
    main_hdr, end_hdr = _rar3_main_and_end()
    good = decoded if decoded is not None else b"right text"
    crc = zlib.crc32(good)
    # Same low 16 bits as the declared CRC32, different high bits.
    output = good if decoded is not None else b"wrong text"
    if decoded is None:
        while zlib.crc32(output) & 0xFFFF != crc & 0xFFFF or zlib.crc32(output) == crc:
            output = hashlib.sha256(output).digest()[: len(good)]
    blob = (
        RAR_ID
        + main_hdr
        + _rar3_compressed_cmt(
            unpacked_size=len(good), crc32=crc, attributes=attributes
        )
        + end_hdr
    )
    monkeypatch.setattr(rar_reader, "decompress_rar3_blob", lambda **_: output)
    with open_archive(io.BytesIO(blob)) as archive:
        assert archive.info.comment == expected


def test_rar3_compressed_service_comment_over_rar_maximum_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``rar`` writes no comment over 256 KiB. One that declares more is dropped
    by the walk: not weighed against the budget, not decoded."""
    from archivey.internal.backends.rar_parser import RAR3_MAX_COMMENT_SIZE

    main_hdr, end_hdr = _rar3_main_and_end()
    blob = (
        RAR_ID
        + main_hdr
        + _rar3_compressed_cmt(unpacked_size=RAR3_MAX_COMMENT_SIZE + 1)
        + end_hdr
    )
    calls = _count_comment_decodes(monkeypatch)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=1000))
    with open_archive(io.BytesIO(blob), config=config) as archive:
        assert archive.info.comment is None
    assert calls == []


def test_rar3_compressed_service_comment_at_rar_maximum_is_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compressed ``CMT`` that declares exactly 256 KiB is kept by the walk and
    decoded once: the cap is inclusive."""
    from archivey.internal.backends.rar_parser import RAR3_MAX_COMMENT_SIZE

    main_hdr, end_hdr = _rar3_main_and_end()
    blob = (
        RAR_ID
        + main_hdr
        + _rar3_compressed_cmt(unpacked_size=RAR3_MAX_COMMENT_SIZE)
        + end_hdr
    )
    calls = _count_comment_decodes(monkeypatch)
    config = ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=2 * RAR3_MAX_COMMENT_SIZE)
    )
    with open_archive(io.BytesIO(blob), config=config) as archive:
        assert archive.info.comment is None  # the counter decodes nothing
    assert len(calls) == 1


class _CountingBytesIO(io.BytesIO):
    """A ``BytesIO`` that adds up the bytes each ``read`` returns.

    It counts ``read`` alone, so a bound on it holds only while the RAR walk reads
    through ``read`` and not ``readinto``.
    """

    bytes_read = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data


def test_rar3_compressed_service_comment_with_oversized_packed_data_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compressed ``CMT`` packs smaller than its text, which the 256 KiB cap
    bounds. One whose packed data is larger than the cap is dropped by the walk:
    its packed bytes are not read, kept or handed to ``unrar``. Otherwise a small
    declared size would let archive-sized packed bytes past ``max_metadata_bytes``."""
    from archivey.internal.backends.rar_parser import RAR3_MAX_COMMENT_SIZE

    packed = b"\x00" * (RAR3_MAX_COMMENT_SIZE + 1)
    main_hdr, end_hdr = _rar3_main_and_end()
    blob = (
        RAR_ID
        + main_hdr
        + _rar3_compressed_cmt(unpacked_size=100, packed=packed)
        + end_hdr
    )
    source = _CountingBytesIO(blob)
    assert parse_rar_archive(source).comment is None
    # The walk reads only headers (62 bytes, a few of them twice: 70 measured),
    # nothing of the 256 KiB of packed data it skips.
    headers = len(blob) - len(packed)
    assert source.bytes_read <= 2 * headers
    calls = _count_comment_decodes(monkeypatch)
    with open_archive(io.BytesIO(blob)) as archive:
        assert archive.info.comment is None
    assert calls == []


def test_rar3_compressed_service_comments_weighed_by_packed_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compressed ``CMT`` holds its packed bytes until the decode, so the walk
    weighs them when they are more than the declared size. Here each of 20 solid
    ``CMT`` headers declares 1 byte over 1000 packed bytes: refused at a 10 000
    byte budget, which their declared sizes (20 bytes) would pass."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SOLID

    main_hdr, end_hdr = _rar3_main_and_end()
    parts = [RAR_ID, main_hdr]
    for i in range(20):
        parts.append(
            _rar3_file_block(f"m{i:02}.txt".encode(), flags=0, pack_lo=0, unp_lo=0)
        )
        parts.append(
            _rar3_compressed_cmt(
                unpacked_size=1, packed=b"\x00" * 1000, flags=_RAR3_FILE_SOLID
            )
        )
    blob = b"".join(parts) + end_hdr
    calls = _count_comment_decodes(monkeypatch)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=10_000))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        open_archive(io.BytesIO(blob), config=config)
    assert calls == []


def test_rar3_salted_compressed_service_comment_is_not_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``CMT`` header with the SALT flag and no PASSWORD flag passes the walk's
    encryption test; its flags reach ``decompress_rar3_blob``, which refuses it
    before building an archive or running ``unrar``."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SALT

    spawned: list[object] = []

    def _no_spawn(*args: object, **kwargs: object) -> None:
        spawned.append(args)
        raise AssertionError("unrar must not be spawned for a salted comment")

    monkeypatch.setattr(rar_unrar, "open_unrar_p", _no_spawn)
    main_hdr, end_hdr = _rar3_main_and_end()
    text = b"salted"
    blob = (
        RAR_ID
        + main_hdr
        + _rar3_compressed_cmt(
            unpacked_size=len(text),
            crc32=zlib.crc32(text),
            flags=_RAR3_FILE_SALT,
            salt=b"\x01" * 8,
        )
        + end_hdr
    )
    config = ArchiveyConfig(rar_decompressor=RarDecompressor.UNRAR)
    with open_archive(io.BytesIO(blob), config=config) as archive:
        assert archive.info.comment is None
    assert spawned == []


def test_rar3_large_packed_member_skips_full_64bit_size() -> None:
    """F5: a RAR3 ``FILE_LARGE`` member's packed-data skip must use the full 64-bit
    size (HIGH_PACK_SIZE), not just the low 32 bits.

    The first member claims a 4 GiB packed size (low 32 = 0, high = 1) with no actual
    data, immediately followed by a second FILE header. Skipping only the low 32 bits
    (0 bytes) would misparse that second header as a member; skipping the full 4 GiB
    lands past EOF, so exactly one member is seen.
    """
    from archivey.internal.backends.rar_parser import _RAR3_FILE_LARGE

    main_hdr, end_hdr = _rar3_main_and_end()
    big = _rar3_file_block(
        b"big.bin", flags=_RAR3_FILE_LARGE, pack_lo=0, unp_lo=0, pack_hi=1, unp_hi=1
    )
    trailing = _rar3_file_block(b"sneaky.txt", flags=0, pack_lo=0, unp_lo=0)
    blob = RAR_ID + main_hdr + big + trailing + end_hdr
    archive = parse_rar_archive(io.BytesIO(blob))
    assert [m.filename for m in archive.members] == ["big.bin"]
    assert archive.members[0].compress_size == 1 << 32


def test_rar3_mismatched_split_continuation_is_corruption() -> None:
    """F6: a SPLIT_BEFORE continuation that names a different file after a non-split
    member must not be silently merged into the previous member."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SPLIT_BEFORE

    main_hdr, end_hdr = _rar3_main_and_end()
    first = _rar3_file_block(b"a.txt", flags=0, pack_lo=0, unp_lo=0)
    forged = _rar3_file_block(
        b"b.txt", flags=_RAR3_FILE_SPLIT_BEFORE, pack_lo=0, unp_lo=0
    )
    blob = RAR_ID + main_hdr + first + forged + end_hdr
    with raises_corruption_not_truncation():
        parse_rar_archive(io.BytesIO(blob))


def test_rar3_same_name_split_before_without_split_after_is_corruption() -> None:
    """F6: same filename + SPLIT_BEFORE still rejects when the previous part was not
    marked SPLIT_AFTER (not a genuine volume continuation)."""
    from archivey.internal.backends.rar_parser import _RAR3_FILE_SPLIT_BEFORE

    main_hdr, end_hdr = _rar3_main_and_end()
    first = _rar3_file_block(b"a.txt", flags=0, pack_lo=0, unp_lo=0)
    cont = _rar3_file_block(
        b"a.txt", flags=_RAR3_FILE_SPLIT_BEFORE, pack_lo=0, unp_lo=0
    )
    blob = RAR_ID + main_hdr + first + cont + end_hdr
    with raises_corruption_not_truncation():
        parse_rar_archive(io.BytesIO(blob))


def test_rar3_split_after_then_different_name_is_corruption() -> None:
    """F6: a SPLIT_AFTER part followed by SPLIT_BEFORE with a different name is not a
    continuation — reject rather than fold the unrelated member's size/CRC in."""
    from archivey.internal.backends.rar_parser import (
        _RAR3_FILE_SPLIT_AFTER,
        _RAR3_FILE_SPLIT_BEFORE,
    )

    main_hdr, end_hdr = _rar3_main_and_end()
    first = _rar3_file_block(
        b"a.txt", flags=_RAR3_FILE_SPLIT_AFTER, pack_lo=0, unp_lo=0
    )
    forged = _rar3_file_block(
        b"b.txt", flags=_RAR3_FILE_SPLIT_BEFORE, pack_lo=0, unp_lo=0
    )
    blob = RAR_ID + main_hdr + first + forged + end_hdr
    with raises_corruption_not_truncation():
        parse_rar_archive(io.BytesIO(blob))


def test_rar3_matching_split_continuation_merges() -> None:
    """F6 positive path: same name + previous SPLIT_AFTER collapses into one member.

    Three volumes, so every continuation after the second compares against the
    volume the member started in, not the one before it.
    """
    from archivey.internal.backends.rar_parser import (
        _RAR3_FILE_SPLIT_AFTER,
        _RAR3_FILE_SPLIT_BEFORE,
    )

    main_hdr, end_hdr = _rar3_main_and_end()
    next_hdr = _rar3_next_volume_end()
    first = _rar3_file_block(
        b"a.txt", flags=_RAR3_FILE_SPLIT_AFTER, pack_lo=3, unp_lo=3
    )
    middle = _rar3_file_block(
        b"a.txt",
        flags=_RAR3_FILE_SPLIT_BEFORE | _RAR3_FILE_SPLIT_AFTER,
        pack_lo=4,
        unp_lo=4,
    )
    last = _rar3_file_block(
        b"a.txt", flags=_RAR3_FILE_SPLIT_BEFORE, pack_lo=5, unp_lo=5
    )
    # Each continuation opens the next volume; a volume holds one part of a member.
    volumes = [
        RAR_ID + main_hdr + first + b"AAA" + next_hdr,
        RAR_ID + main_hdr + middle + b"BBBB" + next_hdr,
        RAR_ID + main_hdr + last + b"CCCCC" + end_hdr,
    ]
    archive = parse_rar_volumes([io.BytesIO(volume) for volume in volumes])
    assert [m.filename for m in archive.members] == ["a.txt"]
    member = archive.members[0]
    assert member.compress_size == 12
    assert member.spanned_volumes is True
    assert not (member.split_before or member.split_after)
    base = 0
    expected = []
    for volume, tail, size in zip(
        volumes, (next_hdr, next_hdr, end_hdr), (3, 4, 5), strict=True
    ):
        expected.append((base + len(volume) - len(tail) - size, size))
        base += len(volume)
    assert member.data_parts == expected


def test_rar5_hostile_packed_size_is_corruption() -> None:
    """Atheris: huge RAR5 vint add_size must not raise raw OverflowError on seek."""
    import zlib

    def vint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def block(body: bytes) -> bytes:
        header_wo_crc = vint(len(body)) + body
        crc = zlib.crc32(header_wo_crc) & 0xFFFFFFFF
        return struct.pack("<I", crc) + header_wo_crc

    main = block(vint(1) + vint(0) + vint(0))  # MAIN, no flags, main_flags=0
    hostile = block(vint(99) + vint(0x02) + vint(1 << 70))  # unknown + DATA + huge
    blob = RAR5_ID + main + hostile
    with raises_corruption_not_truncation(match="seekable range|packed size"):
        parse_rar_archive(io.BytesIO(blob))


def test_rar5_out_of_range_windowstime_is_tolerated() -> None:
    """Atheris: hostile FILETIME must not raise raw ValueError from fromtimestamp."""
    from archivey.internal.backends.rar_parser import _load_windowstime

    # FILETIME ticks far beyond datetime's year range.
    buf = struct.pack("<II", 0xFFFFFFFF, 0x7FFFFFFF)
    dt, pos = _load_windowstime(buf, 0)
    assert dt is None
    assert pos == 8


def test_rar5_zero_windowstime_is_unset() -> None:
    """FILETIME ticks=0 follows the shared helper's unset rule (None, not 1601)."""
    from archivey.internal.backends.rar_parser import _load_windowstime

    dt, pos = _load_windowstime(struct.pack("<II", 0, 0), 0)
    assert dt is None
    assert pos == 8


def _pack_dos(year: int, month: int, day: int, hour: int, minute: int, sec: int) -> int:
    return (
        ((year - 1980) << 25)
        | (month << 21)
        | (day << 16)
        | (hour << 11)
        | (minute << 5)
        | (sec // 2)
    )


def test_parse_rar5_xtime_keeps_ctime_and_atime_with_ns() -> None:
    """RAR5 extra 0x03: HAS_CTIME / HAS_ATIME are stored, including unix-ns words."""
    from archivey.internal.backends.rar_parser import (
        _RAR5_XTIME_HAS_ATIME,
        _RAR5_XTIME_HAS_CTIME,
        _RAR5_XTIME_HAS_MTIME,
        _RAR5_XTIME_UNIXTIME,
        _RAR5_XTIME_UNIXTIME_NS,
        _parse_rar5_xtime,
    )

    tflags = (
        _RAR5_XTIME_UNIXTIME
        | _RAR5_XTIME_HAS_MTIME
        | _RAR5_XTIME_HAS_CTIME
        | _RAR5_XTIME_HAS_ATIME
        | _RAR5_XTIME_UNIXTIME_NS
    )
    mtime_s, ctime_s, atime_s = 1_600_000_000, 1_600_000_200, 1_600_000_100
    blob = bytes([tflags]) + struct.pack(
        "<IIIIII",
        mtime_s,
        ctime_s,
        atime_s,
        123_456_789,
        234_567_890,
        345_678_901,
    )
    mtime, ctime, atime = _parse_rar5_xtime(blob, 0, None)
    assert mtime == datetime(2020, 9, 13, 12, 26, 40, 123456, tzinfo=UTC)
    assert ctime == datetime(2020, 9, 13, 12, 30, 0, 234567, tzinfo=UTC)
    assert atime == datetime(2020, 9, 13, 12, 28, 20, 345678, tzinfo=UTC)


def test_parse_rar5_xtime_mtime_only_leaves_ctime_atime_none() -> None:
    from archivey.internal.backends.rar_parser import (
        _RAR5_XTIME_HAS_MTIME,
        _RAR5_XTIME_UNIXTIME,
        _RAR5_XTIME_UNIXTIME_NS,
        _parse_rar5_xtime,
    )

    tflags = _RAR5_XTIME_UNIXTIME | _RAR5_XTIME_HAS_MTIME | _RAR5_XTIME_UNIXTIME_NS
    blob = bytes([tflags]) + struct.pack("<II", 1_600_000_000, 500_000_000)
    mtime, ctime, atime = _parse_rar5_xtime(blob, 0, None)
    assert mtime == datetime(2020, 9, 13, 12, 26, 40, 500000, tzinfo=UTC)
    assert ctime is None
    assert atime is None


def test_parse_rar5_xtime_second_record_without_flags_keeps_ctime_atime() -> None:
    """A later 0x03 extra with tflags=0 must not wipe ctime/atime from an earlier one."""
    from archivey.internal.backends.rar_parser import (
        _RAR5_XTIME_HAS_ATIME,
        _RAR5_XTIME_HAS_CTIME,
        _RAR5_XTIME_HAS_MTIME,
        _RAR5_XTIME_UNIXTIME,
        _parse_rar5_xtime,
    )

    tflags = (
        _RAR5_XTIME_UNIXTIME
        | _RAR5_XTIME_HAS_MTIME
        | _RAR5_XTIME_HAS_CTIME
        | _RAR5_XTIME_HAS_ATIME
    )
    first = bytes([tflags]) + struct.pack(
        "<III", 1_600_000_000, 1_600_000_200, 1_600_000_100
    )
    mtime, ctime, atime = _parse_rar5_xtime(first, 0, None)
    mtime2, ctime2, atime2 = _parse_rar5_xtime(bytes([0]), 0, mtime, ctime, atime)
    assert (mtime2, ctime2, atime2) == (mtime, ctime, atime)
    assert ctime2 is not None
    assert atime2 is not None


def test_parse_rar5_xtime_truncated_ns_does_not_raise() -> None:
    """HAS_MTIME|UNIXTIME_NS with a FILETIME and no ns word lists, modified=None."""
    from archivey.internal.backends.rar_parser import (
        _RAR5_XTIME_HAS_MTIME,
        _RAR5_XTIME_UNIXTIME_NS,
        _parse_rar5_xtime,
    )

    tflags = _RAR5_XTIME_HAS_MTIME | _RAR5_XTIME_UNIXTIME_NS
    blob = bytes([tflags]) + struct.pack("<II", 0, 0)
    mtime, ctime, atime = _parse_rar5_xtime(blob, 0, None)
    assert mtime is None
    assert ctime is None
    assert atime is None


def test_parse_rar3_ext_time_slot_order_is_mtime_ctime_atime() -> None:
    """RAR3 EXTTIME nibbles: >>12 mtime, >>8 ctime, >>4 atime (UnRAR / rarfile)."""
    from archivey.internal.backends.rar_parser import (
        _parse_dos_time,
        _parse_rar3_ext_time,
    )

    dos_mtime = _pack_dos(2020, 1, 15, 12, 0, 0)
    dos_ctime = _pack_dos(2019, 6, 1, 8, 0, 0)
    dos_atime = _pack_dos(2021, 6, 20, 18, 30, 0)
    # Bit 3 of each nibble = present; no remnant bytes, so ctime/atime are DOS stamps.
    flags = (0x8 << 12) | (0x8 << 8) | (0x8 << 4)
    blob = struct.pack("<HII", flags, dos_ctime, dos_atime)
    mtime, ctime, atime, pos = _parse_rar3_ext_time(blob, 0, _parse_dos_time(dos_mtime))
    assert pos == len(blob)
    assert mtime == datetime(2020, 1, 15, 12, 0, 0)
    assert ctime == datetime(2019, 6, 1, 8, 0, 0)
    assert atime == datetime(2021, 6, 20, 18, 30, 0)
    assert mtime.tzinfo is None
    assert ctime.tzinfo is None
    assert atime.tzinfo is None


def test_rar5_xtime_fixture_surfaces_accessed_and_ctime() -> None:
    """Listing, no unrar: RAR5 ``-tsmca`` fills accessed and ``ctime`` as aware UTC."""
    with open_archive(_fixture("xtime__.rar")) as archive:
        member = archive.get("file.txt")
        assert member.modified == datetime(2020, 1, 15, 12, 0, tzinfo=UTC)
        assert member.accessed == datetime(2021, 6, 20, 18, 30, tzinfo=UTC)
        # Unix-built fixture: the creation slot is st_ctime, so it is not ``created``.
        assert member.created is None
        ctime = member.ctime
        assert ctime.tzinfo is UTC
        assert ctime != member.modified
        assert ctime != member.accessed


def test_rar4_xtime_fixture_surfaces_accessed_and_ctime() -> None:
    """Listing, no unrar: RAR4 EXTTIME fills accessed and ``ctime`` as naive wall-clock."""
    with open_archive(_fixture("xtime__rar4.rar")) as archive:
        member = archive.get("file.txt")
        assert member.modified == datetime(2020, 1, 15, 12, 0, 0)
        assert member.accessed == datetime(2021, 6, 20, 18, 30, 0)
        assert member.modified.tzinfo is None
        assert member.accessed.tzinfo is None
        assert member.created is None  # Unix-built: the slot is st_ctime
        ctime = member.ctime
        assert ctime.tzinfo is None
        assert ctime != member.modified
        assert ctime != member.accessed


@pytest.mark.parametrize(
    "name",
    [
        "stored_m0.rar",  # RAR5 extra has mtime+ns only
        "basic_nonsolid__rar4.rar",  # EXTTIME mtime nibble only
        "rar15-comment.rar",  # no EXTTIME
    ],
)
def test_xtime_absent_accessed_created_are_none(name: str) -> None:
    with open_archive(_fixture(name)) as archive:
        files = [m for m in archive.members() if m.is_file]
        assert files
        for member in files:
            assert member.accessed is None
            assert member.created is None
            assert member.modified is not None
            assert member.ctime is None


_CTIME = datetime(2019, 6, 1, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("host_os", "ctime", "birth_time"),
    [
        (3, _CTIME, False),  # Unix: st_ctime
        (2, _CTIME, True),  # Win32
        (0, _CTIME, True),  # RAR3 MS-DOS/FAT
        (5, _CTIME, True),  # RAR3 BeOS
        (7, _CTIME, False),  # unknown host: meaning unknown
        (None, _CTIME, False),
        (3, None, False),
        (2, None, False),
    ],
)
def test_created_or_ctime_follows_host_os(
    host_os: int | None, ctime: datetime | None, birth_time: bool
) -> None:
    """The slot is ``created`` from a birth-time host and ``ctime`` from any other."""
    reader = object.__new__(rar_reader.RarReader)
    reader._diagnostics_collector = None
    reader._archive_name = "<test>"
    info = RarMemberInfo(
        filename="a.txt",
        orig_filename=b"a.txt",
        file_size=0,
        compress_size=0,
        compress_type=0x30,
        crc32=None,
        blake2sp_hash=None,
        mtime=None,
        ctime=ctime,
        atime=None,
        mode=None,
        host_os=host_os,
        flags=0,
        file_redir=None,
        file_encryption=None,
        header_offset=0,
        header_size=0,
        data_offset=0,
        extract_version=50,
        file_solid=False,
        is_directory=False,
        is_symlink=False,
        is_hardlink_or_copy=False,
        is_encrypted=False,
        volume_index=0,
        split_before=False,
        split_after=False,
    )
    member = rar_reader.RarReader._to_member(reader, info, 0)
    assert member.created == (ctime if birth_time else None)
    assert member.ctime == (None if birth_time else ctime)


def test_rar_reader_masks_hostile_unix_mode() -> None:
    """Atheris: huge RAR5 mode vint must not OverflowError in ``stat.S_IMODE``."""
    from archivey.internal.backends.rar_parser import RarMemberInfo
    from archivey.internal.backends.rar_reader import RarReader

    info = RarMemberInfo(
        filename="a.txt",
        orig_filename=b"a.txt",
        file_size=0,
        compress_size=0,
        compress_type=0x30,
        crc32=None,
        blake2sp_hash=None,
        mtime=None,
        ctime=None,
        atime=None,
        mode=(1 << 80) | 0o100644,
        host_os=3,
        flags=0,
        file_redir=None,
        file_encryption=None,
        header_offset=0,
        header_size=0,
        data_offset=0,
        extract_version=50,
        file_solid=False,
        is_directory=False,
        is_symlink=False,
        is_hardlink_or_copy=False,
        is_encrypted=False,
        volume_index=0,
        split_before=False,
        split_after=False,
    )
    # Build a reader without opening a real archive — call the mapper directly.
    reader = object.__new__(RarReader)
    reader._diagnostics_collector = None
    reader._archive_name = "<test>"
    member = RarReader._to_member(reader, info, 0)
    assert member.mode == 0o0644

    # Win32 attrs are masked to 32 bits (FILE_ATTRIBUTE_* width).
    info_win = dataclasses.replace(info, host_os=2, mode=(1 << 40) | 0x20)
    member_win = RarReader._to_member(reader, info_win, 0)
    assert member_win.mode is None
    assert member_win.windows_attrs == 0x20


def _clear_unrar_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rar_unrar, "_cached_unrar", {})


def _stub_which_rarlab(
    monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Path]
) -> None:
    """Make ``shutil.which`` return the given names while those files exist.

    Windows ``which`` only returns names in ``PATHEXT`` (``.exe`` / ``.cmd`` / …).
    An extensionless ``unrar`` on PATH is invisible there, so a lookalike that
    only sets PATH never reaches the banner probe.

    Patches ``which`` on the ``shutil`` *module object* (not a local alias);
    ``monkeypatch`` restores it.
    """
    resolved = {name: str(path) for name, path in mapping.items()}

    def which(command: str, path: str | None = None, **_kwargs: object) -> str | None:
        dest = resolved.get(command)
        if dest is not None and Path(dest).is_file():
            return dest
        return None

    monkeypatch.setattr(rar_unrar.shutil, "which", which)


def _stub_which_unrar(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Make ``shutil.which('unrar')`` return ``path``; ``rar`` stays missing."""
    _stub_which_rarlab(monkeypatch, {"unrar": path})


def _accepted_unrar_banner(_path: str = "") -> rar_unrar._UnrarBanner:
    """Stand-in for a RARLAB probe that meets the 6.0 floor."""
    return rar_unrar._UnrarBanner(is_rarlab=True, version=(7, 0))


def _lookalike_unrar_banner(_path: str = "") -> rar_unrar._UnrarBanner:
    return rar_unrar._UnrarBanner(is_rarlab=False, version=None)


def _stub_unrar_banner(
    monkeypatch: pytest.MonkeyPatch, path: Path, banner: str
) -> list[int]:
    """Stub ``which`` and ``subprocess.run`` so the probe sees ``banner``.

    Counts ``run`` calls so a cache hit can be shown not to re-spawn. Does not
    execute ``path`` — a shell-script fake is not a Win32 executable.
    """
    _stub_which_unrar(monkeypatch, path)
    runs: list[int] = []

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        runs.append(1)
        return subprocess.CompletedProcess(
            argv, 0, stdout=banner.encode("utf-8"), stderr=b""
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    return runs


def test_non_rarlab_unrar_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_text("#!/bin/sh\necho 'unrar-free fake'\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()


def test_non_rarlab_unrar_negative_probe_is_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_text("#!/bin/sh\necho 'unrar-free fake'\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_unrar(monkeypatch, fake)

    probes = 0

    def count_probe(_path: str) -> rar_unrar._UnrarBanner:
        nonlocal probes
        probes += 1
        return _lookalike_unrar_banner()

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", count_probe)
    for _ in range(2):
        with pytest.raises(PackageNotInstalledError, match="RARLAB"):
            rar_unrar.find_rarlab_unrar()

    assert probes == 1


def test_unrar_on_path_is_the_rarlab_build() -> None:
    """Environment guard: an ``unrar`` the finder rejects makes RAR data tests fail confusingly.

    On CI this duplicates the ``Verify RARLAB unrar on PATH`` step. Unique value is
    developer machines: one named failure instead of a wall of
    ``PackageNotInstalledError``. Finder unit behaviour is
    ``test_non_rarlab_unrar_rejected``. This does not cover a binary installed
    off PATH (that is the macOS ``~/.local/bin`` trap).
    """
    if shutil.which("unrar") is None:
        pytest.skip("no unrar on PATH — RAR data tests skip, the documented state")
    rar_unrar.find_rarlab_unrar()


@pytest.mark.parametrize(
    ("unrar_banner", "rar_banner", "data_skips", "cli_skips"),
    [
        ("unrar-free fake", None, True, True),
        ("unrar-free fake", "7.00", False, True),
        ("7.00", "7.00", False, False),
        (None, "7.00", False, True),
    ],
    ids=["lookalike-unrar", "lookalike-unrar-beside-rar", "rarlab-unrar", "rar-only"],
)
def test_unrar_marks_follow_archiveys_rule(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unrar_banner: str | None,
    rar_banner: str | None,
    data_skips: bool,
    cli_skips: bool,
) -> None:
    """``requires_binary("unrar")`` skips where archivey has no RARLAB program to read
    RAR data with; ``requires_unrar_cli()``, for a test that runs the ``unrar`` command,
    also skips where that command is missing or is not the one archivey accepts. A
    RARLAB ``rar`` with no ``unrar``, or beside a lookalike, is where the two differ."""
    programs: dict[str, Path] = {}
    banners: dict[str, str] = {}
    if unrar_banner is not None:
        unrar = tmp_path / "unrar"
        unrar.write_bytes(b"u")
        programs["unrar"] = unrar
        banners[os.path.abspath(str(unrar))] = (
            _RARLAB_BANNER.format(version=unrar_banner)
            if unrar_banner[0].isdigit()
            else unrar_banner
        )
    if rar_banner is not None:
        rar = tmp_path / "rar"
        rar.write_bytes(b"r")
        programs["rar"] = rar
        banners[os.path.abspath(str(rar))] = _RARLAB_RAR_BANNER.format(
            version=rar_banner
        )
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, programs)

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        banner = banners[os.path.abspath(argv[0])]
        return subprocess.CompletedProcess(
            argv, 0, stdout=banner.encode("utf-8"), stderr=b""
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    data_mark = requires_binary("unrar")
    assert data_mark.args == (data_skips,), data_mark.kwargs["reason"]
    cli_mark = requires_unrar_cli()
    assert cli_mark.args == (cli_skips,), cli_mark.kwargs["reason"]


def test_missing_unrar_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()


def test_missing_unrar_rechecks_which_and_does_not_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A ``which`` miss is not cached; the expensive banner probe is never run."""
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)

    which_calls = 0
    probe_calls = 0
    which = rar_unrar.shutil.which

    def count_which(
        command: str, path: str | None = None, **kwargs: object
    ) -> str | None:
        nonlocal which_calls
        which_calls += 1
        return which(command, path=path, **kwargs)

    def count_probe(path: str) -> rar_unrar._UnrarBanner:
        nonlocal probe_calls
        probe_calls += 1
        return _lookalike_unrar_banner()

    monkeypatch.setattr(rar_unrar.shutil, "which", count_which)
    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", count_probe)
    for _ in range(2):
        with pytest.raises(PackageNotInstalledError, match="RARLAB"):
            rar_unrar.find_rarlab_unrar()

    assert which_calls == 4  # unrar + rar, twice; misses are not cached
    assert probe_calls == 0


def _usable_rarlab_unrar_or_skip(reason: str) -> str:
    """Skip unless ``PATH`` has a RARLAB unrar that meets the version floor."""
    try:
        return rar_unrar.find_rarlab_unrar()
    except PackageNotInstalledError:
        pytest.skip(reason)


def test_path_change_invalidates_cached_unrar_miss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rarlab_unrar = _usable_rarlab_unrar_or_skip(
        "no usable RARLAB unrar 6.0+ on PATH — cannot test cache invalidation"
    )

    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()

    monkeypatch.setenv("PATH", str(Path(rarlab_unrar).parent))
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(rarlab_unrar)


def test_unrar_installed_after_miss_is_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``which`` re-runs on a miss: installing into an unchanged PATH is visible."""
    rarlab_unrar = _usable_rarlab_unrar_or_skip(
        "no usable RARLAB unrar 6.0+ on PATH — cannot test install-after-miss"
    )

    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()

    dest = tmp_path / ("unrar.exe" if os.name == "nt" else "unrar")
    shutil.copy(rarlab_unrar, dest)
    dest.chmod(0o755)
    # Windows ``which`` appends the PATHEXT spelling (``.EXE``), not the
    # filename casing we wrote. ``Path`` equality is case-insensitive there.
    assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(dest)))


def test_transient_probe_oserror_is_not_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_unrar(monkeypatch, fake)

    calls = 0

    def flaky(_path: str) -> rar_unrar._UnrarBanner:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(errno.EMFILE, "Too many open files")
        return _accepted_unrar_banner()

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", flaky)
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(str(fake))
    assert calls == 2


def test_stat_error_on_candidate_is_package_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    # Do not use ``_stub_which_unrar``: it stats the candidate, and this test
    # patches ``os.stat``.
    monkeypatch.setattr(
        rar_unrar.shutil,
        "which",
        lambda command, path=None, **_k: str(fake) if command == "unrar" else None,
    )

    def boom(
        _path: str | bytes | os.PathLike[str], *_a: object, **_k: object
    ) -> object:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(rar_unrar.os, "stat", boom)
    with pytest.raises(PackageNotInstalledError, match="RARLAB") as info:
        rar_unrar.find_rarlab_unrar()
    assert isinstance(info.value.__cause__, PermissionError)


def test_replaced_cached_unrar_is_reprobed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Stat-identity change (size/mtime) forces a new banner probe."""
    fake = tmp_path / "unrar"
    fake.write_bytes(b"a")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_unrar(monkeypatch, fake)

    probes = 0

    def count_probe(_path: str) -> rar_unrar._UnrarBanner:
        nonlocal probes
        probes += 1
        return _accepted_unrar_banner()

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", count_probe)
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(str(fake))
    fake.write_bytes(b"bbbb")
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(str(fake))
    assert probes == 2


def test_deleted_cached_unrar_is_not_returned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"")
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_unrar(monkeypatch, fake)
    # A shell script is not a Win32 executable; this test pins cache
    # invalidation, not banner sniffing.
    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", _accepted_unrar_banner)

    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(str(fake))
    fake.unlink()

    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()


_RARLAB_BANNER = (
    "UNRAR {version} freeware      Copyright (c) 1993-2024 Alexander Roshal"
)
_RARLAB_RAR_BANNER = (
    "RAR {version}     Copyright (c) 1993-2024 Alexander Roshal\n"
    "Trial version             Type 'rar -?' for help"
)


@pytest.mark.parametrize(
    ("banner", "version"),
    [
        (_RARLAB_BANNER.format(version="7.00"), (7, 0)),
        (_RARLAB_BANNER.format(version="7.0"), (7, 0)),
        (_RARLAB_BANNER.format(version="7.11"), (7, 11)),
        ("UNRAR 7.00 (RARLAB)", (7, 0)),
        ("UNRAR\t7.00 (RARLAB)", (7, 0)),
    ],
)
def test_parse_unrar_banner_accepts_rarlab_floor(
    banner: str, version: tuple[int, int]
) -> None:
    parsed = rar_unrar._parse_unrar_banner(banner)
    assert parsed.is_rarlab is True
    assert parsed.version == version


def test_parse_unrar_banner_version_on_the_next_line_is_not_read() -> None:
    # The gap is ``[ \t]+``: a ``RAR`` token at the end of one line does not take a
    # version from the start of the next.
    parsed = rar_unrar._parse_unrar_banner("UNRAR\n7.00 (RARLAB) Alexander Roshal")
    assert parsed.is_rarlab is True
    assert parsed.version is None


def test_parse_unrar_banner_old_rarlab_is_still_rarlab() -> None:
    parsed = rar_unrar._parse_unrar_banner(_RARLAB_BANNER.format(version="6.24"))
    assert parsed.is_rarlab is True
    assert parsed.version == (6, 24)


def test_parse_unrar_banner_unparseable_rarlab() -> None:
    parsed = rar_unrar._parse_unrar_banner(
        "UNRAR freeware      Copyright (c) 1993-2024 Alexander Roshal"
    )
    assert parsed.is_rarlab is True
    assert parsed.version is None


def test_parse_unrar_banner_overlong_digits_are_unparseable() -> None:
    """A 5000-digit run must not ``int()``; treat it as an unparseable RARLAB banner."""
    parsed = rar_unrar._parse_unrar_banner(
        _RARLAB_BANNER.format(version="9" * 5000 + ".0")
    )
    assert parsed.is_rarlab is True
    assert parsed.version is None


def test_parse_unrar_banner_lookalike_is_not_rarlab() -> None:
    parsed = rar_unrar._parse_unrar_banner("unrar-free fake")
    assert parsed.is_rarlab is False
    assert parsed.version is None


def test_parse_unrar_banner_version_without_vendor_is_not_rarlab() -> None:
    """A version token is not enough: too-old applies only to genuine RARLAB."""
    parsed = rar_unrar._parse_unrar_banner("UNRAR 6.24 freeware")
    assert parsed.is_rarlab is False
    assert parsed.version is None


def test_parse_unrar_banner_accepts_rarlab_writer() -> None:
    parsed = rar_unrar._parse_unrar_banner(_RARLAB_RAR_BANNER.format(version="7.00"))
    assert parsed.is_rarlab is True
    assert parsed.version == (7, 0)


def test_parse_unrar_banner_rar_token_does_not_match_inside_unrar() -> None:
    """``RAR x.yy`` must not fire on the ``RAR`` suffix of ``UNRAR x.yy``."""
    parsed = rar_unrar._parse_unrar_banner(_RARLAB_BANNER.format(version="7.00"))
    assert parsed.is_rarlab is True
    assert parsed.version == (7, 0)
    assert (
        rar_unrar._RAR_VERSION_RE.search(_RARLAB_BANNER.format(version="7.00")) is None
    )


def test_parse_unrar_banner_writer_version_without_vendor_is_not_rarlab() -> None:
    parsed = rar_unrar._parse_unrar_banner("RAR 7.00 Trial version")
    assert parsed.is_rarlab is False
    assert parsed.version is None


@pytest.mark.parametrize(
    "version_text", ["6.00", "6.02", "6.24", "7.00", "7.0", "7.11"]
)
def test_rarlab_unrar_at_or_above_floor_is_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version_text: str
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    runs = _stub_unrar_banner(
        monkeypatch, fake, _RARLAB_BANNER.format(version=version_text)
    )
    for _ in range(2):
        assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(fake)))
    assert runs == [1]
    key = os.path.abspath(str(fake))
    cached = rar_unrar._cached_unrar[key]
    assert cached.is_rarlab is True
    major, minor = (int(p) for p in version_text.split("."))
    assert cached.version == (major, minor)


def test_rarlab_unrar_below_floor_is_rejected_and_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    banner = _RARLAB_BANNER.format(version="5.91")
    runs = _stub_unrar_banner(monkeypatch, fake, banner)

    shown = display_path(os.path.abspath(str(fake)))
    for _ in range(2):
        with pytest.raises(PackageNotInstalledError, match="6.0") as info:
            rar_unrar.find_rarlab_unrar()
        msg = str(info.value)
        assert "5.91" in msg
        assert shown in msg
        assert "unrar-free" not in msg

    assert runs == [1]
    key = os.path.abspath(str(fake))
    cached = rar_unrar._cached_unrar[key]
    assert cached.is_rarlab is True
    assert cached.version == (5, 91)


def test_unparseable_rarlab_banner_is_rejected_and_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    runs = _stub_unrar_banner(
        monkeypatch,
        fake,
        "UNRAR freeware      Copyright (c) 1993-2024 Alexander Roshal",
    )

    shown = display_path(os.path.abspath(str(fake)))
    for _ in range(2):
        with pytest.raises(
            PackageNotInstalledError, match="could not be parsed"
        ) as info:
            rar_unrar.find_rarlab_unrar()
        msg = str(info.value)
        assert "6.0" in msg
        assert shown in msg
        assert "unrar-free" not in msg

    assert runs == [1]
    key = os.path.abspath(str(fake))
    cached = rar_unrar._cached_unrar[key]
    assert cached.is_rarlab is True
    assert cached.version is None


def test_overlong_banner_version_is_package_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A banner digit run past CPython's ``int()`` limit stays an ``ArchiveyError``."""
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_unrar_banner(
        monkeypatch, fake, _RARLAB_BANNER.format(version="9" * 5000 + ".0")
    )
    with pytest.raises(PackageNotInstalledError, match="could not be parsed"):
        rar_unrar.find_rarlab_unrar()


def test_unrar_not_installed_message_names_lookalikes() -> None:
    """Copy of the not-installed message — behaviour tests only match ``RARLAB``."""
    msg = rar_unrar._NOT_INSTALLED_MSG
    assert "unrar or rar" in msg
    for name in ("unrar-free", "unar", "7z", "7zz"):
        assert name in msg
    assert "rar_decompressor" in msg
    assert "RAR5 check" in msg and "1.10.8+ds1-10" in msg


def test_rarlab_rar_is_accepted_when_unrar_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "rar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"rar": fake})
    probed: list[str] = []

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        probed.append(os.path.abspath(argv[0]))
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=_RARLAB_RAR_BANNER.format(version="7.00").encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(fake)))
    assert probed == [os.path.abspath(str(fake))]


def test_rarlab_unrar_is_preferred_when_rar_is_also_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    unrar = tmp_path / "unrar"
    rar = tmp_path / "rar"
    unrar.write_bytes(b"u")
    rar.write_bytes(b"r")
    unrar.chmod(0o755)
    rar.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"unrar": unrar, "rar": rar})
    probed: list[str] = []
    banners = {
        os.path.abspath(str(unrar)): _RARLAB_BANNER.format(version="7.00"),
        os.path.abspath(str(rar)): _RARLAB_RAR_BANNER.format(version="7.00"),
    }

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        probed.append(os.path.abspath(argv[0]))
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=banners[os.path.abspath(argv[0])].encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(unrar)))
    assert probed == [os.path.abspath(str(unrar))]


def test_lookalike_unrar_does_not_hide_rarlab_rar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    unrar = tmp_path / "unrar"
    rar = tmp_path / "rar"
    unrar.write_bytes(b"u")
    rar.write_bytes(b"r")
    unrar.chmod(0o755)
    rar.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"unrar": unrar, "rar": rar})
    banners = {
        os.path.abspath(str(unrar)): "unrar-free fake",
        os.path.abspath(str(rar)): _RARLAB_RAR_BANNER.format(version="7.00"),
    }

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=banners[os.path.abspath(argv[0])].encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(rar)))


def test_non_rarlab_rar_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "rar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"rar": fake})
    _stub_unrar_banner(monkeypatch, fake, "unar 1.10.1")
    with pytest.raises(PackageNotInstalledError, match="RARLAB"):
        rar_unrar.find_rarlab_unrar()


def test_rarrc_cannot_break_probe_or_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Probe and ``p`` argv include ``-cfg-`` so user config cannot inject switches.

    ``subprocess`` is stubbed — the ``~/.rarrc`` uses real ``switches=`` syntax
    only for realism; the assertion is ``-cfg-`` in both argvs.
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / ".rarrc").write_text("switches=-idq\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    fake = tmp_path / "bin" / "unrar"
    fake.parent.mkdir()
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake.parent))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"unrar": fake})

    probe_argv: list[list[str]] = []
    spawn_argv: list[list[str]] = []

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        probe_argv.append(list(argv))
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=_RARLAB_BANNER.format(version="7.00").encode("utf-8"),
            stderr=b"",
        )

    class _FakeStdout:
        def read(self, _n: int = -1) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class _FakeProc:
        stdin = None
        stdout = _FakeStdout()

        def poll(self) -> int:
            return 0

    def popen(
        cmd: list[str],
        **_kwargs: object,
    ) -> _FakeProc:
        spawn_argv.append(list(cmd))
        return _FakeProc()

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    monkeypatch.setattr(rar_unrar.subprocess, "Popen", popen)
    assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(fake)))
    assert probe_argv == [[str(fake), rar_unrar._RAR_DISABLE_CONFIG]]

    archive = tmp_path / "probe.rar"
    archive.write_bytes(b"x")
    rar_unrar.open_unrar_p(archive)
    assert spawn_argv[0][:4] == [
        str(fake),
        "p",
        "-inul",
        rar_unrar._RAR_DISABLE_CONFIG,
    ]


def test_lookalike_unrar_and_rarlab_rar_both_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A negative ``unrar`` cache entry must not force a ``rar`` re-probe every call."""
    unrar = tmp_path / "unrar"
    rar = tmp_path / "rar"
    unrar.write_bytes(b"u")
    rar.write_bytes(b"r")
    unrar.chmod(0o755)
    rar.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"unrar": unrar, "rar": rar})
    banners = {
        os.path.abspath(str(unrar)): "unrar-free fake",
        os.path.abspath(str(rar)): _RARLAB_RAR_BANNER.format(version="7.00"),
    }
    probed: list[str] = []

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        probed.append(os.path.abspath(argv[0]))
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=banners[os.path.abspath(argv[0])].encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    for _ in range(2):
        assert Path(rar_unrar.find_rarlab_unrar()) == Path(os.path.abspath(str(rar)))
    assert probed == [os.path.abspath(str(unrar)), os.path.abspath(str(rar))]


def test_open_unrar_p_spawns_p_not_extract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "unrar"
    fake.write_bytes(b"x")
    fake.chmod(0o755)
    archive = tmp_path / "member.rar"
    archive.write_bytes(b"x")
    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: str(fake))

    class _FakeStdout:
        def read(self, _n: int = -1) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class _FakeProc:
        stdin = None
        stdout = _FakeStdout()

        def poll(self) -> int:
            return 0

    captured: list[list[str]] = []

    def popen(
        cmd: list[str],
        **_kwargs: object,
    ) -> _FakeProc:
        captured.append(list(cmd))
        return _FakeProc()

    monkeypatch.setattr(rar_unrar.subprocess, "Popen", popen)
    rar_unrar.open_unrar_p(archive, member="payload.txt")
    assert captured[0][1] == "p"
    assert "x" not in captured[0][:4]


def test_floor_refusal_lists_both_binaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    unrar = tmp_path / "unrar"
    rar = tmp_path / "rar"
    unrar.write_bytes(b"u")
    rar.write_bytes(b"r")
    unrar.chmod(0o755)
    rar.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)
    _stub_which_rarlab(monkeypatch, {"unrar": unrar, "rar": rar})
    banners = {
        os.path.abspath(str(unrar)): _RARLAB_BANNER.format(version="5.91"),
        os.path.abspath(str(rar)): _RARLAB_RAR_BANNER.format(version="5.80"),
    }

    def run(
        argv: list[str],
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=banners[os.path.abspath(argv[0])].encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(rar_unrar.subprocess, "run", run)
    with pytest.raises(PackageNotInstalledError, match="6.0") as info:
        rar_unrar.find_rarlab_unrar()
    msg = str(info.value)
    assert display_path(os.path.abspath(str(unrar))) in msg
    assert display_path(os.path.abspath(str(rar))) in msg


def test_listing_and_stored_reads_need_no_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The native-metadata split, end to end: no binary on PATH at all.

    The whole point of parsing headers ourselves is that listing an archive — and
    reading a member we can slice directly — never needs the external decompressor.
    Only a member that must go through ``unrar`` fails, and it fails by naming it.
    """
    monkeypatch.setenv("PATH", str(tmp_path))
    _clear_unrar_cache(monkeypatch)

    with open_archive(_fixture("basic_nonsolid__.rar")) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == set(_BASIC_CONTENTS)
        # Stored, unencrypted, nonsolid, unsplit -> sliced from the source directly.
        for member_name, expected in _BASIC_CONTENTS.items():
            assert archive.read(files[member_name]) == expected

    # The archive comment is compressed, so no binary leaves it unset without
    # turning a successful listing into an open failure. Its member comments
    # are stored old-style blocks and remain available natively.
    with open_archive(_fixture("rar15-comment.rar")) as archive:
        assert archive.info.comment is None
        assert {
            member.name: member.comment
            for member in archive.members()
            if member.is_file
        } == {
            "FILE1.TXT": "file1comment -----",
            "FILE2.TXT": "file2comment -----",
        }

    with open_archive(_fixture("symlinks_solid__rar4.rar")) as archive:
        assert [m.name for m in archive.members()]  # listing still works
        compressed = next(
            m for m in archive.members() if m.is_file and m.compressed_size > 0
        )
        with pytest.raises(PackageNotInstalledError, match="RARLAB"):
            archive.read(compressed)


def test_stored_nonsolid_archive_spawns_no_unrar_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reading every member of a stored nonsolid archive costs zero subprocesses."""
    spawns: list[object] = []
    real_open = rar_reader.open_unrar_p

    def spy(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        spawns.append(args)
        return real_open(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)
    with open_archive(_fixture("basic_nonsolid__.rar")) as archive:
        for member in archive.members():
            if member.is_file:
                archive.read(member)
    assert spawns == []


@requires("cryptography")
def test_header_crypto_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.streams import crypto

    monkeypatch.setattr(crypto, "_crypto_available", lambda: False)
    with pytest.raises(PackageNotInstalledError, match="cryptography"):
        open_archive(_fixture("encrypted_header__.rar"), password="header_password")


def test_rar_parser_max_members_at_parse() -> None:
    """Member-table bombs fail at parse with the caller's listing budget, not OOM."""
    path = _fixture("basic_nonsolid__.rar")
    with path.open("rb") as fh:
        n = len(parse_rar_archive(fh).members)
    assert n > 2
    with path.open("rb") as fh:
        assert len(parse_rar_archive(fh, max_members=n).members) == n
    with path.open("rb") as fh, pytest.raises(ResourceLimitError, match="max_members"):
        parse_rar_archive(fh, max_members=2)
    with path.open("rb") as fh:
        # None is ListingLimits.UNLIMITED: no count bound.
        assert len(parse_rar_archive(fh, max_members=None).members) == n


def test_rar_parser_omitted_max_members_matches_listing_limits_default() -> None:
    """Direct callers that omit max_members get ListingLimits()'s default, not None."""
    # Default is bound at def time; monkeypatching ListingLimits cannot exercise it.
    from inspect import signature

    from archivey.internal.backends.rar_parser import (
        _DEFAULT_MAX_MEMBERS,
        parse_rar_volumes,
    )

    assert _DEFAULT_MAX_MEMBERS == ListingLimits().max_members
    assert signature(parse_rar_archive).parameters["max_members"].default == (
        _DEFAULT_MAX_MEMBERS
    )
    assert signature(parse_rar_volumes).parameters["max_members"].default == (
        _DEFAULT_MAX_MEMBERS
    )


@pytest.mark.parametrize(
    "name",
    ["basic_nonsolid__.rar", "basic_nonsolid__rar4.rar"],
)
@pytest.mark.parametrize("streaming", [False, True])
def test_rar_open_enforces_listing_limits(name: str, streaming: bool) -> None:
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    with pytest.raises(ResourceLimitError, match="max_members"):
        open_archive(_fixture(name), config=cfg, streaming=streaming)


def test_rar_split_continuation_does_not_consume_member_slot() -> None:
    """A FILE split across volumes is one logical member, not two slots."""
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=1))
    with open_archive(_fixture("tinyvol.part1.rar"), config=cfg) as reader:
        assert len(reader.members()) == 1


def test_rar_split_continuation_in_the_same_volume_is_refused() -> None:
    """A volume holds at most one part of a member, so parts stay bounded by volumes.

    Each repeated continuation would be one more retained part that ``max_members``
    does not count; a crafted volume of 200 000 one-byte parts held 26 MB after open.
    """
    main_hdr, end_hdr = _rar3_main_and_end()
    parts = [_rar3_file_block(b"a", flags=0x02, pack_lo=1, unp_lo=3) + b"x"]
    parts.append(_rar3_file_block(b"a", flags=0x03, pack_lo=1, unp_lo=3) + b"y")
    parts.append(_rar3_file_block(b"a", flags=0x01, pack_lo=1, unp_lo=3) + b"z")
    blob = RAR_ID + main_hdr + b"".join(parts) + end_hdr
    with pytest.raises(CorruptionError, match="same volume"):
        parse_rar_archive(io.BytesIO(blob))


def test_rar_unlimited_lifts_member_cap() -> None:
    tight = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    with pytest.raises(ResourceLimitError, match="max_members"):
        open_archive(_fixture("basic_nonsolid__.rar"), config=tight)
    unlimited = ArchiveyConfig(listing_limits=ListingLimits.UNLIMITED)
    with open_archive(_fixture("basic_nonsolid__.rar"), config=unlimited) as reader:
        assert len(reader.members()) > 2


def test_fix_rar3_astral_truncation() -> None:
    """RAR3 compresses names as UTF-16, which truncates non-BMP chars to a PUA/surrogate
    code unit; the 8-bit name field is preferred when it recovers the real character."""
    from archivey.internal.backends.rar_parser import _fix_rar3_astral_truncation

    # U+1F600 truncated to U+F600 in the UTF-16 name; the UTF-8 8-bit name recovers it.
    truncated = "emoji_\uf600.txt"
    recovered = "emoji_\U0001f600.txt"
    assert _fix_rar3_astral_truncation(truncated, recovered.encode()) == recovered
    # No 8-bit/UTF-16 disagreement -> keep the decompressed name unchanged.
    assert _fix_rar3_astral_truncation("plain.txt", b"plain.txt") == "plain.txt"
    # A PUA char present in both fields (genuine, not a truncation) is preserved.
    pua = "\uf600.txt"
    assert _fix_rar3_astral_truncation(pua, pua.encode()) == pua
    # An 8-bit field that is not valid UTF-8 cannot override; keep the UTF-16 name.
    assert _fix_rar3_astral_truncation("name.txt", b"\xff\xfe") == "name.txt"


def test_rar3_non_bmp_filename_not_truncated() -> None:
    """Regression: an emoji in a RAR3 name must survive as U+1F600, not the PUA U+F600
    the raw UTF-16 field decodes to (external fixture from the v1 reader's bug)."""
    with open_archive(_fixture("encoding__rar4.rar")) as archive:
        names = {m.name for m in archive.members()}
    assert "emoji_😀.txt" in names
    # None of the recovered names retain a surrogate/PUA truncation artifact.
    for name in names:
        assert not any(
            0xE000 <= ord(c) <= 0xF8FF or 0xD800 <= ord(c) <= 0xDFFF for c in name
        )


def _rle_name_encdata(opcode_runs: int) -> bytes:
    """RAR3 compressed-name bytes that are all maximum-length RLE runs.

    RAR3 stores names compressed. The RLE opcode emits up to 129 UTF-16 code
    units per encoding byte by copying the 8-bit name field — so an *empty*
    8-bit field plus a long run of RLE opcodes is the worst case.
    """
    return b"\x00" + (b"\xff" + b"\x7f" * 4) * opcode_runs


def test_rar3_compressed_name_decode_is_bounded() -> None:
    """Empty-8-bit + RLE-heavy encdata must fail closed, not spend listing CPU.

    Bound: ``len(decoded) <= len(std_name) + len(encdata)`` — every output unit
    is either copied from the 8-bit field or paid for by an encoding byte. With
    an empty 8-bit field that collapses to ``len(encdata)``, which is what this
    vector checks; a compact RLE copy of a long 8-bit name is allowed to exceed
    ``len(encdata)`` alone.

    ``name_size`` is a ``uint16``, so the pre-fix buffer was at most ~13.5 MB
    (bounded, transient, discarded before any member existed). The lever was
    CPU: ~11 s for one header at that ceiling, not an unbounded vint-style
    allocation. This vector must return None rather than emit the amplified
    name.
    """
    encdata = _rle_name_encdata(1000)
    assert _decode_rar3_unicode_name(b"", encdata) is None

    # t=0 with a flags byte and no payload must not emit a leftover unit.
    assert _decode_rar3_unicode_name(b"", b"\x00\x00") is None


def test_rar3_rle_name_still_decodes_when_the_8bit_field_is_present() -> None:
    """Failing closed on overrun must not change a well-formed RLE copy from the 8-bit name.

    hi=0, flags=0xC0 (first opcode is RLE), n=1 → copy 3 bytes of std_name as ASCII.
    """
    assert _decode_rar3_unicode_name(b"abc", b"\x00\xc0\x01") == "abc"


def test_rar3_rle_name_may_be_longer_than_encdata() -> None:
    """A compact RLE copy of a long 8-bit name is well-formed.

    Output can exceed ``len(encdata)`` so long as it stays within
    ``len(std_name) + len(encdata)``.
    """
    std_name = b"a" * 50
    # hi=0, flags=0xC0 (RLE), n=48 → copy 50 ASCII bytes.
    decoded = _decode_rar3_unicode_name(std_name, b"\x00\xc0\x30")
    assert decoded == "a" * 50
    assert len(decoded) > len(b"\x00\xc0\x30")
    assert len(decoded) <= len(std_name) + 3


def test_rar3_rle_name_zero_correction_keeps_hi_byte() -> None:
    """``n & 0x80`` with correction byte 0 still uses ``hi``, not high-byte 0.

    The ASCII RLE path (no 0x80) emits high-byte 0; the correction path must
    not collapse into it just because the correction value is zero.
    """
    # hi=0x04, flags=0xC0 (RLE), n=0x80 (k=2, correction follows), correction=0.
    decoded = _decode_rar3_unicode_name(b"ab", b"\x04\xc0\x80\x00")
    assert decoded == "\u0461\u0462"


def test_rar3_unicode_name_keeps_a_lone_surrogate_unit() -> None:
    """A unit without its partner stays as that unit, never U+FFFD."""
    # hi=0xD8, flags=0x40 (opcode 1: low byte 0x00 under ``hi``).
    assert _decode_rar3_unicode_name(b"a", b"\xd8\x40\x00") == "\ud800"


def _reference_decode_rar3_unicode_name(std_name: bytes, encdata: bytes) -> str | None:
    """Per-byte transcription of the pre-rewrite ``_UnicodeFilename.decode``.

    Independent oracle for the property test — keep this as the old class
    algorithm, not a copy of ``_decode_rar3_unicode_name``.
    """
    pos = 0
    encpos = 0
    buf = bytearray()
    failed = False

    def enc_byte() -> int:
        nonlocal encpos, failed
        try:
            c = encdata[encpos]
            encpos += 1
            return c
        except IndexError:
            failed = True
            return 0

    def std_byte() -> int:
        nonlocal failed
        try:
            return std_name[pos]
        except IndexError:
            failed = True
            return ord("?")

    def put(lo: int, hi_byte: int) -> None:
        nonlocal pos
        buf.append(lo)
        buf.append(hi_byte)
        pos += 1

    hi = enc_byte()
    flagbits = 0
    flags = 0
    while not failed and encpos < len(encdata):
        if flagbits == 0:
            flags = enc_byte()
            flagbits = 8
            if failed:
                break
        flagbits -= 2
        t = (flags >> flagbits) & 3
        if t == 0:
            lo = enc_byte()
            if failed:
                break
            put(lo, 0)
        elif t == 1:
            lo = enc_byte()
            if failed:
                break
            put(lo, hi)
        elif t == 2:
            lo = enc_byte()
            if failed:
                break
            c_hi = enc_byte()
            if failed:
                break
            put(lo, c_hi)
        else:
            n = enc_byte()
            if failed:
                break
            if n & 0x80:
                correction = enc_byte()
                if failed:
                    break
                for _ in range((n & 0x7F) + 2):
                    lo = (std_byte() + correction) & 0xFF
                    if failed:
                        break
                    put(lo, hi)
            else:
                for _ in range(n + 2):
                    lo = std_byte()
                    if failed:
                        break
                    put(lo, 0)
    if failed:
        return None
    # The one deliberate change from the old class: a lone surrogate unit stays in
    # the name (``surrogatepass``), as the parser now keeps it.
    return buf.decode("utf-16le", "surrogatepass")


def test_rar3_unicode_name_decode_matches_reference_and_stays_bounded() -> None:
    """Random ``(std_name, encdata)`` pairs match the pre-rewrite decoder and
    never exceed ``len(std_name) + len(encdata)`` on success.
    """
    pytest.importorskip("hypothesis")
    from hypothesis import example, given, strategies as st

    opcodeish = st.sampled_from([0x00, 0x40, 0x80, 0xC0, 0xFF, 0x7F, 0x01, 0x81])
    encdata_st = st.one_of(
        st.binary(max_size=13),
        st.tuples(
            st.binary(min_size=1, max_size=1), st.lists(opcodeish, max_size=12)
        ).map(lambda hi_and_rest: hi_and_rest[0] + bytes(hi_and_rest[1])),
    )

    @given(
        std_name=st.one_of(
            st.binary(max_size=11), st.binary(min_size=129, max_size=200)
        ),
        encdata=encdata_st,
    )
    @example(b"", _rle_name_encdata(8))
    @example(b"", b"\x00\x00")
    @example(b"abc", b"\x00\xc0\x01")
    @example(b"ab", b"\x04\xc0\x80\x00")
    @example(b"x" * 129, b"\x00\xc0\x7f")  # plain run k=129
    @example(b"x" * 129, b"\x04\xc0\xff\x05")  # correction run k=129, c=5
    @example(b"x" * 129, b"\x04\xc0\xff\x00")  # correction run k=129, c=0
    @example(b"a", b"\xd8\x40\x00")  # one unit, U+D800 with no partner
    def inner(std_name: bytes, encdata: bytes) -> None:
        got = _decode_rar3_unicode_name(std_name, encdata)
        assert got == _reference_decode_rar3_unicode_name(std_name, encdata)
        if got is not None:
            assert len(got) <= len(std_name) + len(encdata)

    inner()


# Fixtures built by review/archive/2026-07-16-rar-reader/make_hostile_fixtures.py:
# nonsolid, compressed members whose stored names are a bare unrar switch and an
# ``@listfile`` argument, alongside a normal control member.
_HOSTILE_ARGV_CONTENTS = {
    "canary.txt": b"CANARY-CANARY-CANARY-\n" * 64,
    "-inul": b"DASH-INUL-PAYLOAD-\n" * 64,
    "@atfile": b"AT-ATFILE-PAYLOAD-\n" * 64,
}


@requires_binary("unrar")
@pytest.mark.parametrize("name", ["hostile_argv__.rar", "hostile_argv__rar4.rar"])
def test_hostile_member_name_reads_its_own_bytes(name: str) -> None:
    """F3 (review/archive/2026-07-16-rar-reader/unrar-boundary.md): a member whose
    stored name is a bare ``unrar`` switch (``-inul``) or an ``@listfile`` argument
    (``@atfile``) must be addressed to exactly that member.

    Fixed by passing the member via a ``-n./`` include mask instead of positionally,
    so ``unrar`` cannot parse the name as a switch or a local-file read. Each hostile
    member now returns its own bytes, and never another member's.
    """
    with open_archive(_fixture(name)) as archive:
        members = {m.name: m for m in archive.members() if m.is_file}
        assert {"canary.txt", "-inul", "@atfile"} <= set(members)
        for member_name, expected in _HOSTILE_ARGV_CONTENTS.items():
            assert archive.read(members[member_name]) == expected, (
                f"reading {member_name!r} did not return its own bytes (F3 argv injection)"
            )


# Bounded work: the cap rejects after a handful of bytes. An O(n^2) read of the 2 MB
# run would blow any budget, so the mark is generous rather than a wall-clock assert.
@pytest.mark.timeout(30)
def test_rar5_header_size_vint_is_bounded() -> None:
    """F2: the RAR5 header-size vint pre-read is length-capped, so a crafted run of
    continuation bytes cannot drive an unbounded, O(n^2) read of the source."""
    payload = RAR5_ID + b"\x00\x00\x00\x00" + b"\x80" * 2_000_000
    with pytest.raises(ArchiveyError):
        parse_rar_archive(io.BytesIO(payload))


# Generous on purpose: a quadratic regression blows any budget, and the body takes
# ~2.7 s under coverage, so a tight mark only fails loaded CI runners at random.
@pytest.mark.timeout(30)
def test_rar5_qo_non_file_records_parse_in_linear_time() -> None:
    """Non-FILE QO records (2 MiB of SERVICE copies) parse under the timeout."""
    from archivey.internal.backends import rar_parser

    hdr = bytes([2, 3, 0])  # hdrlen=2, type=SERVICE, flags=0
    cached = zlib.crc32(hdr).to_bytes(4, "little") + hdr
    qbody = bytes([0, 1, len(cached)]) + cached
    size = bytes([len(qbody)])
    rec = zlib.crc32(size + qbody).to_bytes(4, "little") + size + qbody
    payload = rec * (2 * 1024 * 1024 // len(rec))
    result = rar_parser._parse_rar5_qo_payload(
        payload, 10**9, 0, max_members=None, max_metadata_bytes=None
    )
    assert result is None


def test_qo_overlapping_spans_are_rejected() -> None:
    """Inconsistent QO spans must not be trusted for the skip-walk."""
    from types import SimpleNamespace

    from archivey.internal.backends.rar_parser import _qo_spans_consistent

    first = SimpleNamespace(header_offset=100, data_offset=150, compress_size=80)
    second = SimpleNamespace(header_offset=200, data_offset=220, compress_size=10)
    assert not _qo_spans_consistent([first, second], min_offset=100, qopen_abs=400)
    ok = SimpleNamespace(header_offset=230, data_offset=250, compress_size=10)
    assert _qo_spans_consistent([first, ok], min_offset=100, qopen_abs=400)


def test_load_vint_single_and_multi_byte() -> None:
    """RAR5 vint decode: single-byte hot path and multi-byte continuation agree."""
    assert load_vint(b"\x00", 0) == (0, 1)
    assert load_vint(b"\x7f", 0) == (127, 1)
    assert load_vint(bytes([0x80 | 1, 0x02]), 0) == (1 + (2 << 7), 2)
    # Non-zero start offset (rewrite bound is relative to ``pos``, not buffer start).
    assert load_vint(b"\xff" + bytes([0x80 | 1, 0x02]), 1) == (1 + (2 << 7), 3)
    # Maximum-length valid vint: 10 continuation bytes + terminator.
    assert load_vint(b"\x80" * 10 + b"\x01", 0) == (1 << 70, 11)
    with raises_corruption_not_truncation():
        load_vint(b"", 0)
    with raises_corruption_not_truncation():
        load_vint(b"\x80" * 11, 0)


def test_unrar_member_include_switch_builds_n_mask() -> None:
    """Every member name becomes a ``-n./`` include mask, with ``*`` narrowed to
    ``?`` (see :func:`_unrar_mask_for`), including names that would be switches or
    an ``@listfile`` if passed positionally."""
    from archivey.internal.backends.rar_unrar import _member_include_switch

    def switch(text: str) -> str | bytes:
        # UTF-8 bytes on POSIX, whatever the filesystem encoding; text on Windows.
        return text if sys.platform == "win32" else text.encode()

    assert _member_include_switch("-inul") == switch("-n./-inul")
    assert _member_include_switch("@atfile") == switch("-n./@atfile")
    assert _member_include_switch("dir/normal.txt") == switch("-n./dir/normal.txt")
    assert _member_include_switch("weird*.txt") == switch("-n./weird?.txt")
    assert _member_include_switch("a?b.txt") == switch("-n./a?b.txt")
    assert _member_include_switch("café.txt") == switch("-n./café.txt")


def test_unrar_mask_for_narrows_stars_to_question_marks() -> None:
    """The mask never carries a ``*``, and never stops matching its own member.

    ``?`` is one character, so substituting it for ``*`` keeps the mask the same
    length as the name and leaves a ``?`` exactly where the name has its literal
    ``*`` — the member still matches. Everything else is untouched.
    """
    from archivey.internal.backends.rar_unrar import _unrar_mask_for

    assert _unrar_mask_for("plain.txt") == "plain.txt"
    assert _unrar_mask_for("a?b.txt") == "a?b.txt"
    assert _unrar_mask_for("a*b.txt") == "a?b.txt"
    assert _unrar_mask_for("*") == "?"
    assert _unrar_mask_for("a*a*a*b") == "a?a?a?b"
    assert _unrar_mask_for("dir/a*.txt") == "dir/a?.txt"
    for name in ("a*b", "*", "**", "a*?b", "only*.dat"):
        assert "*" not in _unrar_mask_for(name)
        assert len(_unrar_mask_for(name)) == len(name)


def test_unrar_mask_selection_treats_brackets_as_literal() -> None:
    """``unrar -n`` does not treat ``[]`` as a character class; the skip must not
    either, or a name with both brackets and a glob would desync from the pipe."""
    from archivey.internal.backends.rar_unrar import unrar_mask_selects

    def selects(name: str, mask: str) -> bool:
        return unrar_mask_selects("./" + mask, name, dot_rule=True)

    assert selects("a*.txt", "a?.txt")
    assert selects("aX.txt", "a?.txt")
    assert selects("subdir/aY.txt", "a?.txt")
    assert not selects("b1.txt", "a?.txt")
    # Fixed length: what a ``*`` mask would have swallowed, a ``?`` mask does not.
    assert not selects("aXX.txt", "a?.txt")
    assert not selects("a.txt", "a?.txt")
    assert selects("b?.txt", "b?.txt")
    assert selects("b1.txt", "b?.txt")
    assert selects("foo[a].txt", "foo[a].txt")
    assert not selects("fooa.txt", "foo[a].txt")
    assert selects("foo[a]X.txt", "foo[a]?.txt")
    assert not selects("fooaX.txt", "foo[a]?.txt")
    assert selects("subdir/aY.txt", "subdir/a?.txt")
    assert not selects("aX.txt", "subdir/a?.txt")
    assert not selects("other/aY.txt", "subdir/a?.txt")
    assert selects("aY.txt", "aY.txt")
    assert not selects("subdir/aY.txt", "aY.txt")
    # A glob in a directory component matches the whole path, so it does not
    # select a longer directory (these names are still refused before a read).
    assert not selects("aaa/x.txt", "d?/x.txt")
    assert selects("dX/x.txt", "d?/x.txt")


def test_unrar_mask_selection_follows_unrar_path_rules() -> None:
    """The rules measured against ``unrar`` 7.00 in ``test_rar_unrar_names.py``."""
    from archivey.internal.backends.rar_unrar import unrar_mask_selects

    def selects(name: str, mask: str) -> bool:
        return unrar_mask_selects("./" + mask, name, dot_rule=True)

    # A mask selects everything below the path it names.
    assert selects("ab/x.txt", "ab")
    assert not selects("abc", "ab")
    # A trailing dot in the mask may stand for nothing, not the other way round.
    assert selects("ab", "ab.")
    assert selects("ab.", "ab..")
    assert not selects("ab.", "ab")
    # Leading ``./`` and ``../`` parts are dropped from the name as well.
    assert selects("../ab", "ab")
    assert selects("x/../ab", "ab")


def test_unrar_mask_selection_on_windows_takes_either_separator_in_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows ``unrar`` turns ``/`` into ``\\`` in the name (``ConvertFileHeader``)
    and in the mask (``CheckArgs``), so a directory part compares equal whichever
    separator either side was written with. The index keys must agree, or an exact
    mask would not find its member. Linux keeps ``\\`` as a name character.
    """
    from archivey.internal.backends import rar_unrar
    from archivey.internal.backends.rar_unrar import (
        unrar_mask_keys,
        unrar_mask_selects,
        unrar_selection_keys,
    )

    monkeypatch.setattr(rar_unrar.sys, "platform", "win32")
    for name in ("subdir/aY.txt", "subdir\\aY.txt"):
        assert unrar_mask_selects("./subdir/a?.txt", name, dot_rule=True)
        assert unrar_mask_selects("./subdir/aY.txt", name, dot_rule=True)
        assert unrar_mask_selects("./subdir", name, dot_rule=True)
        assert not unrar_mask_selects("./other/a?.txt", name, dot_rule=True)
        keys = unrar_mask_keys("./subdir/aY.txt")
        assert keys is not None
        assert set(keys) & set(unrar_selection_keys(name))
    monkeypatch.setattr(rar_unrar.sys, "platform", "linux")
    assert unrar_mask_selects("./subdir/a?.txt", "subdir/aY.txt", dot_rule=True)
    assert not unrar_mask_selects("./subdir/a?.txt", "subdir\\aY.txt", dot_rule=True)


def test_unrar_name_pos_takes_a_drive_only_after_an_ascii_letter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``GetNamePos`` falls back to 2 only for ``IsDriveLetter``: A-Z, then ``:``."""
    from archivey.internal.backends import rar_unrar
    from archivey.internal.backends.rar_unrar import _unrar_name_pos

    monkeypatch.setattr(rar_unrar.sys, "platform", "win32")
    assert _unrar_name_pos("c:ab") == 2
    assert _unrar_name_pos("Z:ab") == 2
    for name in ("1:ab", ":x", "é:ab", "ı:ab"):
        assert _unrar_name_pos(name) == 0, name
    monkeypatch.setattr(rar_unrar.sys, "platform", "linux")
    assert _unrar_name_pos("c:ab") == 0


def test_unrar_mask_selection_windows_fold_does_not_change_wildcard_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``?`` is length-sensitive; ``str.casefold()`` is not length-preserving.

    ``ß`` casefolds to ``ss``. Whole-string folding then makes ``aßb.txt``
    (7) miss mask ``a?b.txt`` (7) on Windows, while Windows ``unrar`` folds
    per character via ``toupperw`` and still emits the member. The skip
    would land one member short. Folding one character at a time keeps
    the lengths aligned.

    The ``AXB.TXT`` assertions pin the fold itself: literals that differ only
    in case. The three ``ß`` checks stay green if ``.upper()`` is deleted.
    """
    from archivey.internal.backends import rar_unrar
    from archivey.internal.backends.rar_unrar import unrar_mask_selects

    monkeypatch.setattr(rar_unrar.sys, "platform", "win32")
    assert unrar_mask_selects("./a?b.txt", "aßb.txt", dot_rule=True)
    assert unrar_mask_selects("./aßb.txt", "aßb.txt", dot_rule=True)
    assert not unrar_mask_selects("./a??b.txt", "aßb.txt", dot_rule=True)
    # Literals that differ only in case: the per-character fold, not the
    # length check. Deleting ``.upper()`` leaves the three assertions above
    # green and fails these.
    assert unrar_mask_selects("./a?b.txt", "AXB.TXT", dot_rule=True)
    assert not unrar_mask_selects("./a?c.txt", "AXB.TXT", dot_rule=True)
    # An exact name folds too: Windows unrar would pipe both.
    assert unrar_mask_selects("./same.txt", "SAME.TXT", dot_rule=True)


def test_unrar_glob_mask_is_linear_on_a_hostile_member_name() -> None:
    """A hostile member name must not make either matcher backtrack.

    Both operands come from the archive: ``_unrar_selection`` matches every
    earlier member's name against the mask built from the target's. Two matchers
    used to backtrack on it. Archivey's regex spelled ``*`` as ``.*`` and cost ~8x
    per added ``*`` — 18.2 s at eight of them. ``unrar`` 7.00's own mask matcher
    has the same defect and took 15.6 s on the same name, which no archivey-side
    matcher could reach. Narrowing ``*`` to ``?`` in the mask removes the ``*``
    both of them were backtracking on, and took the subprocess to 0.009 s.

    The bound here is wall clock rather than a call count because the defect was
    the shape of the search, not how often it ran.
    """
    from archivey.internal.backends.rar_unrar import _unrar_mask_for, _unrar_match

    name = "a" * 60 + ".txt"
    for stars in (8, 64, 256):
        hostile = "a" + "*a" * stars + "b.txt"
        mask = _unrar_mask_for(hostile)
        started = time.perf_counter()
        assert not _unrar_match(mask, name, dot_rule=True)
        elapsed = time.perf_counter() - started
        # Microseconds in practice; the old form needed 18 s at stars=8 alone.
        assert elapsed < 1.0, f"{stars} wildcards took {elapsed:.3f}s"


def test_unrar_match_is_a_single_walk() -> None:
    """Pin the ``?``-only grammar, including where it differs from ``fnmatch``:
    ``[]`` literal, ``\\`` literal, ``?`` matching a newline, and a pattern dot
    that may stand for nothing at the end of the name."""
    from archivey.internal.backends.rar_unrar import _unrar_match

    assert _unrar_match("", "", dot_rule=True)
    assert not _unrar_match("?", "", dot_rule=True)
    assert not _unrar_match("", "a", dot_rule=True)
    assert _unrar_match("a?c", "a.c", dot_rule=True)
    assert _unrar_match("a?c", "a\nc", dot_rule=True)
    assert _unrar_match("a?c", "abc", dot_rule=True)
    assert not _unrar_match("a?c", "ac", dot_rule=True)
    assert not _unrar_match("a?c", "abbc", dot_rule=True)
    assert _unrar_match("a[b]c", "a[b]c", dot_rule=True)
    assert not _unrar_match("a[b]c", "abc", dot_rule=True)
    assert _unrar_match(r"a\bc", r"a\bc", dot_rule=True)
    assert not _unrar_match(r"a\bc", "abc", dot_rule=True)
    assert _unrar_match("a+c", "a+c", dot_rule=True)
    assert not _unrar_match("a+c", "aac", dot_rule=True)
    assert _unrar_match("a.", "a", dot_rule=True)
    assert _unrar_match("a..", "a", dot_rule=True)
    assert not _unrar_match("a", "a.", dot_rule=True)
    assert not _unrar_match("a.b", "a", dot_rule=True)
    assert _unrar_match("a.\\bc", "a\\bc", dot_rule=True)
    # unrar 7.30 beta 2 has no such dot: the mask a. selects a. and nothing else.
    assert not _unrar_match("a.\\bc", "a\\bc", dot_rule=False)
    assert not _unrar_match("a.", "a", dot_rule=False)
    assert not _unrar_match("a..", "a.", dot_rule=False)
    assert _unrar_match("a.", "a.", dot_rule=False)
    assert _unrar_match("a?c", "a.c", dot_rule=False)
    # A ``*`` here means the mask was not built by ``_unrar_mask_for`` and the
    # skip is about to be sized against a mask unrar never saw.
    with pytest.raises(AssertionError):
        _unrar_match("a*c", "abc", dot_rule=True)


def test_unrar_mask_narrowing_keeps_the_member() -> None:
    """The mask built from a name always still selects that name.

    A glob member name is matched against its siblings, so wildcards appear on
    the *name* side too — an alphabet of plain characters cannot show it. If a
    mask stopped selecting its own member, the member would go unreadable.
    Which siblings the narrowed mask selects besides is computed from that mask
    itself (``unrar_mask_selects``), so it need not be a subset of what the
    ``*`` mask selected, and under unrar's DOS extension rules it is not always.
    """
    import itertools

    from archivey.internal.backends.rar_unrar import _unrar_mask_for, _unrar_match

    alphabet = "a*?."
    words = [
        "".join(w) for n in range(5) for w in itertools.product(alphabet, repeat=n)
    ]
    unreachable = [
        (w, dot_rule)
        for w in words
        for dot_rule in (True, False)
        if not _unrar_match(_unrar_mask_for(w), w, dot_rule=dot_rule)
    ]
    assert not unreachable, f"mask stopped matching its own member: {unreachable[:5]}"


def test_unrar_glob_demux_ok_basename_only() -> None:
    """Demux is offered only for a glob confined to the basename, no backslash."""
    from archivey.internal.backends.rar_unrar import _unrar_glob_demux_ok

    assert _unrar_glob_demux_ok("a*.txt")
    assert _unrar_glob_demux_ok("subdir/a*.txt")
    assert _unrar_glob_demux_ok("b?.txt")
    assert not _unrar_glob_demux_ok("d*/x.txt")
    assert not _unrar_glob_demux_ok("*/x.txt")
    assert not _unrar_glob_demux_ok(r"a\b*.txt")
    assert not _unrar_glob_demux_ok(r"subdir\a*.txt")


@requires_binary("unrar")
@pytest.mark.parametrize("name", list(_WILDCARD_FIXTURES))
def test_wildcard_member_name_reads_its_own_bytes(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``unrar -n./a*.txt`` concatenates every match; we skip to the named member.

    ``subdir/aY.txt`` is an earlier basename match, so ``a*.txt`` is the prefix-skip
    case. The size bound still drops ``aX.txt`` after it. Nonsolid fixtures must
    actually compress (tiny ``-m3`` members store as M0 and never reach this path).
    """
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(_fixture(name), config=_ALLOW_GLOB_CONCAT) as archive:
        files = [m for m in archive.members() if m.is_file]
        assert {m.name for m in files} == set(_WILDCARD_CONTENTS)
        names = [m.name for m in files]
        assert names.index("subdir/aY.txt") < names.index("a*.txt")
        assert archive.read("a*.txt") == _WILDCARD_CONTENTS["a*.txt"]
        assert "a*.txt" in spawns
        for member_name, expected in _WILDCARD_CONTENTS.items():
            assert archive.read(member_name) == expected


@requires_binary("unrar")
@pytest.mark.parametrize("name", list(_WILDCARD_FIXTURES))
def test_glob_member_with_earlier_matches_is_refused(name: str) -> None:
    """A glob name whose mask also matches earlier members is refused by default.

    ``unrar -n./a*.txt`` decompresses every match and emits them concatenated, so
    reading ``a*.txt`` pays for ``subdir/aY.txt`` first. The skip returns the right
    bytes, but the decode already happened and nothing bounds it: ``ExtractionLimits``
    do not reach ``open()``/``read()``. Names like this are almost always constructed,
    so they are refused on solid archives too, where those bytes are already inside
    ``AccessCost.SOLID``. Maintainer (davitf, 2026-09-19): refuse, with the config
    flag as the escape hatch.
    """
    with (
        open_archive(_fixture(name), config=_UNRAR_ONLY) as archive,
        pytest.raises(
            UnsupportedFeatureError, match="rar_allow_glob_member_concatenation"
        ),
    ):
        archive.read("a*.txt")


@requires_binary("unrar")
@pytest.mark.parametrize("name", list(_WILDCARD_FIXTURES))
def test_glob_member_matching_nothing_else_still_reads(name: str) -> None:
    """A glob name that matches no other member has no prefix, so it is not refused.

    ``only*.dat`` is the accidental ``report*.pdf`` case: the mask matches only
    itself, the skip ``_unrar_selection`` sizes is 0, and the refusal never triggers. This is the
    boundary the refusal must not overshoot, so it is pinned without the flag.
    """
    with open_archive(_fixture(name)) as archive:
        assert archive.read("only*.dat") == _WILDCARD_CONTENTS["only*.dat"]


@requires_binary("unrar", "unar")
@pytest.mark.parametrize(
    ("name", "contents"),
    [
        ("wildcard_names__.rar", _WILDCARD_CONTENTS),
        ("wildcard_names__rar4.rar", _WILDCARD_CONTENTS),
        ("wildcard_dirglob__.rar", _WILDCARD_DIRGLOB_CONTENTS),
    ],
)
def test_auto_reads_with_unar_a_member_unrar_cannot_name(
    name: str, contents: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``AUTO``, a member whose name unrar refuses goes to an accepted unar.

    unar names entries by index, so neither a glob mask that also matches earlier
    members nor a glob in a directory component costs it anything. Only those members
    take it; every other member still goes to unrar.
    """
    unar_indexes: list[list[int]] = []
    unar_passwords: list[object] = []
    original = rar_reader.open_unar_stdout

    def spy(path: Path, indexes: list[int], **kwargs: object):
        unar_indexes.append(list(indexes))
        unar_passwords.append(kwargs.get("password"))
        return original(path, indexes, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unar_stdout", spy)
    # A caller's password never reaches unar's command line on this path.
    with open_archive(_fixture(name), password="s3cret") as archive:
        for member_name, expected in contents.items():
            assert archive.read(member_name) == expected
        streamed = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert {k: v for k, v in streamed.items() if k in contents} == contents
    refused = {"a*.txt"} if name != "wildcard_dirglob__.rar" else {"d*/x.txt"}
    # One unar run per read of a refused member: the read above and the pass.
    assert len(unar_indexes) == 2 * len(refused)
    assert unar_passwords == [None] * len(unar_indexes)


@requires_binary("unrar", "unar")
def test_auto_keeps_the_unrar_refusal_when_unar_refuses_the_archive() -> None:
    """unar 1.10 misreads a RAR5 solid archive with data after a directory, so it is
    not used there, and the unrar refusal stands."""
    with (
        open_archive(_fixture("wildcard_names_solid__.rar")) as archive,
        pytest.raises(
            UnsupportedFeatureError, match="rar_allow_glob_member_concatenation"
        ),
    ):
        archive.read("a*.txt")


@requires_binary("unrar")
def test_auto_keeps_the_unrar_refusal_without_an_accepted_unar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_unar(*, purpose: str) -> str:
        raise PackageNotInstalledError(f"no unar {purpose}")

    monkeypatch.setattr(rar_reader, "find_unar", no_unar)
    with (
        open_archive(_fixture("wildcard_names__.rar")) as archive,
        pytest.raises(
            UnsupportedFeatureError, match="rar_allow_glob_member_concatenation"
        ),
    ):
        archive.read("a*.txt")


@requires_binary("unrar", "unar")
def test_plaintext_members_of_an_encrypted_archive_get_no_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A spawn that reads one member gets a password only when that member needs one.

    The archive is non-solid and its one encrypted member comes last, so the
    plaintext members are read with no password, by unrar and, for the glob name
    unrar cannot address, by unar. Only the encrypted member's read carries it.
    """
    passwords: list[tuple[str, object]] = []
    original_unar = rar_reader.open_unar_stdout
    original_unrar = rar_reader.open_unrar_p

    def unar_spy(path: Path, indexes: list[int], **kwargs: object):
        passwords.append(("unar", kwargs.get("password")))
        return original_unar(path, indexes, **kwargs)  # type: ignore[arg-type]

    def unrar_spy(path: Path, **kwargs: object):
        passwords.append(("unrar", kwargs.get("password")))
        return original_unrar(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unar_stdout", unar_spy)
    monkeypatch.setattr(rar_reader, "open_unrar_p", unrar_spy)
    with open_archive(
        _fixture("wildcard_names_one_encrypted__.rar"), password="password"
    ) as archive:
        assert archive.read("aX.txt").startswith(b"other-aX\n")
        assert archive.read("a*.txt").startswith(b"target-star\n")
        assert archive.read("secret.txt").startswith(b"secret\n")
    assert passwords == [("unrar", None), ("unar", None), ("unrar", "password")]


@requires_binary("unrar", "unar")
def test_auto_keeps_the_unrar_refusal_when_unar_would_need_a_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prefix before the RAR means unar reads a copy, which the open-time cost
    notes under unrar do not announce, so the unrar refusal stands."""
    created = _rar_temp_artifacts(monkeypatch)
    path = tmp_path / "prefixed.rar"
    path.write_bytes(
        b"MZ" + bytes(4094) + _fixture("wildcard_names__.rar").read_bytes()
    )
    with (
        open_archive(path) as archive,
        pytest.raises(
            UnsupportedFeatureError, match="rar_allow_glob_member_concatenation"
        ),
    ):
        archive.read("a*.txt")
    assert created == []


@requires_binary("unrar")
def test_glob_concatenation_flag_names_itself_in_the_refusal() -> None:
    """The refusal tells the caller the byte count and the exact flag to set."""
    with (
        open_archive(_fixture("wildcard_names__.rar"), config=_UNRAR_ONLY) as archive,
        pytest.raises(UnsupportedFeatureError) as excinfo,
    ):
        archive.read("a*.txt")
    message = str(excinfo.value)
    assert "rar_allow_glob_member_concatenation" in message
    assert str(len(_WILDCARD_CONTENTS["subdir/aY.txt"])) in message


@requires_binary("unrar")
def test_solid_glob_refusal_does_not_claim_an_avoidable_decode() -> None:
    """On a solid archive the glob prefix is already inside ``AccessCost.SOLID``.

    The refusal still fires — the names are constructed — but the message must
    not describe those bytes as an avoidable extra decode.
    """
    with (
        open_archive(
            _fixture("wildcard_names_solid__.rar"), config=_UNRAR_ONLY
        ) as archive,
        pytest.raises(UnsupportedFeatureError) as excinfo,
    ):
        archive.read("a*.txt")
    message = str(excinfo.value)
    assert "rar_allow_glob_member_concatenation" in message
    assert "would decompress" not in message


@requires_binary("unrar")
def test_wildcard_solid_stream_members_reads_all() -> None:
    """The unnamed ALL-pipe has no ``-n`` mask, so wildcard names already demux by
    size; this pins that the glob skip on the named route did not leak into it.

    Also davitf's carve-out (2026-09-19): a solid streaming pass builds no mask, so
    the glob refusal cannot reach it. No flag here, deliberately — the exemption
    falls out of the code rather than being special-cased.
    """
    with open_archive(_fixture("wildcard_names_solid__.rar")) as archive:
        got = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if member.is_file and stream is not None
        }
    assert got == _WILDCARD_CONTENTS


@requires_binary("unrar")
def test_wildcard_nonsolid_stream_members_hits_the_refusal() -> None:
    """A nonsolid streaming pass takes the named route, so the refusal reaches it.

    ``_iter_with_data`` falls through to per-member named opens for nonsolid archives,
    so ``stream_members()`` builds the same ``-n`` mask a random ``open()`` does and
    carries the same concatenation — worse, in fact, since the pass decodes the prefix
    member once as itself and again inside the target's pipe. The solid pass above is
    exempt only because it builds no mask at all.

    Maintainer (davitf, 2026-09-19), asked whether iteration should be exempted:
    "right now don't exempt iteration, it can fail as the other modes." So this is
    the decided behaviour, not a placeholder.
    """
    with (
        open_archive(_fixture("wildcard_names__.rar"), config=_UNRAR_ONLY) as archive,
        pytest.raises(UnsupportedFeatureError, match="would decompress") as excinfo,
    ):
        for member, stream in archive.stream_members():
            if stream is not None:
                stream.read()
    assert str(len(_WILDCARD_CONTENTS["subdir/aY.txt"])) in str(excinfo.value)


@requires_binary("unrar")
def test_seekable_wildcard_respawn_still_skips_glob_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backward seek on a glob name must respawn *and* re-skip the prefix.

    ``a*.txt`` is not first among matches (``subdir/aY.txt`` is), so a respawn
    that forgot the skip would return the nested file after ``seek(0)``.
    """
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    expected = _WILDCARD_CONTENTS["a*.txt"]
    with (
        open_archive(
            _fixture("wildcard_names_solid__.rar"),
            seekable_members=True,
            config=_ALLOW_GLOB_CONCAT,
        ) as archive,
        archive.open("a*.txt") as stream,
    ):
        assert stream.seekable() is True
        # Prefix skip is eager at pipe construction, which for a respawn is
        # the following read — not seek(). A no-byte seek must not spawn.
        stream.seek(0, io.SEEK_END)
        stream.seek(0)
        assert spawns == ["a*.txt"]
        assert stream.read(6) == expected[:6]
        assert spawns == ["a*.txt"]
        stream.seek(0)
        assert spawns == ["a*.txt"]
        assert stream.read() == expected
        assert spawns == ["a*.txt", "a*.txt"]


_SEPARATOR_OR_DIR_GLOB = (
    "unrar reads with a backslash, or with a glob in a directory component, "
    "cannot be read through unrar"
)


@requires_binary("unrar")
def test_wildcard_dirglob_and_backslash_names_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A glob in a directory component, or a backslash in the stored name, stays a
    typed refusal — otherwise unrar's mask (and our skip) desyncs, including on
    Windows where ``\\`` is a separator and a non-glob ``a\\b_TGT.txt`` emits nothing."""
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        member = kwargs.get("member")
        # An 8-bit RAR3 name is passed as its stored bytes (ASCII in these fixtures).
        spawns.append(member.decode() if isinstance(member, bytes) else member)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)

    with open_archive(
        _fixture("wildcard_dirglob__.rar"), config=_UNRAR_ONLY
    ) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert "d*/x.txt" in files
        for name, expected in _WILDCARD_DIRGLOB_CONTENTS.items():
            if name == "d*/x.txt":
                continue
            assert archive.read(name) == expected
        before = list(spawns)
        with pytest.raises(UnsupportedFeatureError, match=_SEPARATOR_OR_DIR_GLOB):
            archive.read("d*/x.txt")
        assert spawns == before

    with open_archive(
        _fixture("wildcard_backslash__.rar"), config=_UNRAR_ONLY
    ) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert archive.read("a/b1.txt") == _WILDCARD_BACKSLASH_SLASH
        before = list(spawns)
        for name in _WILDCARD_BACKSLASH_REFUSED:
            assert name in files
            with pytest.raises(UnsupportedFeatureError, match=_SEPARATOR_OR_DIR_GLOB):
                archive.read(name)
        assert spawns == before


@requires_binary("unrar")
@pytest.mark.parametrize("config", [_UNRAR_ONLY, None], ids=["unrar", "auto"])
def test_refused_glob_open_of_a_stream_source_writes_nothing(
    config: ArchiveyConfig | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused ``open()`` must not spool the source to disk on its way to the raise.

    Both refusals in ``_open_member`` — the backslash / directory-glob one and the
    glob-concatenation one — are decided entirely from the parsed member table, and
    neither spawns ``unrar``. ``_ensure_archive_path()`` therefore has no reason to
    run first, and when the source is a stream, running it first copies the whole
    archive (the whole *set*, for volumes) for a read that never happens. That also
    put the two halves of this PR at odds: the concatenation refusal exists to stop
    an unbounded decode, and it was paying an unbounded disk copy to reach the raise.
    Under ``AUTO`` the unar fallback is not taken for a stream source, since unar
    would need its own copy, so the refusal stands there too.
    """
    for fixture, member in (
        ("wildcard_names__.rar", "a*.txt"),
        ("wildcard_dirglob__.rar", "d*/x.txt"),
    ):
        created = _rar_temp_artifacts(monkeypatch)
        data = _fixture(fixture).read_bytes()
        with open_archive(io.BytesIO(data), config=config) as archive:
            assert member in {m.name for m in archive.members()}
            assert created == []
            with pytest.raises(UnsupportedFeatureError):
                archive.read(member)
            assert created == []


@requires_binary("unrar")
def test_wildcard_ver_live_glob_skips_history_rows() -> None:
    """``unrar p -n./data*`` without ``-ver`` omits history; the skip must too."""
    with open_archive(
        _fixture("wildcard_ver__.rar"), config=_ALLOW_GLOB_CONCAT
    ) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == set(_WILDCARD_VER_CONTENTS)
        for member_name, expected in _WILDCARD_VER_CONTENTS.items():
            assert archive.read(member_name) == expected


@requires("cryptography")
@pytest.mark.parametrize(
    "name", ["encrypted_header__.rar", "encrypted_header__rar4.rar"]
)
def test_header_encryption_wrong_password_is_encryption_error(name: str) -> None:
    """F1: a wrong header password surfaces as ``EncryptionError`` (not
    ``CorruptionError``) even without a check value (always RAR3, checkval-less RAR5),
    so password-candidate iteration keeps trying instead of aborting."""
    path = _fixture(name)
    with (
        pytest.raises(EncryptionError),
        open_archive(path, password="DEFINITELY_WRONG") as archive,
    ):
        archive.members()
    # A candidate list whose first entry is wrong must fall through to the correct one.
    with open_archive(
        path, password=["DEFINITELY_WRONG", "header_password"]
    ) as archive:
        assert len(archive.members()) > 0


class _FakeUnrarProc:
    """Minimal ``Popen`` stand-in for ``_UnrarOwnedStream`` exit-code tests."""

    def __init__(self, returncode: int) -> None:
        self.returncode = returncode

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


class _CloseRaises(io.BytesIO):
    """Stdout stand-in whose close() fails after the BytesIO close succeeds."""

    def close(self) -> None:
        super().close()
        raise OSError("stdout close failed")


def _close_unrar_owned(
    *,
    rc: int,
    named_member: bool = False,
    has_verifiable_hash: bool = False,
    encrypted: bool = False,
    stdout: bytes = b"",
) -> None:
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        io.BytesIO(stdout),
        _FakeUnrarProc(rc),  # type: ignore[arg-type]
        named_member=named_member,
        has_verifiable_hash=has_verifiable_hash,
        encrypted=encrypted,
    )
    stream.close()


def test_unrar_owned_stream_maps_exit_11_to_encryption_error() -> None:
    """F4: unrar exit 11 (bad password) always maps, even when a hash is present."""
    with pytest.raises(EncryptionError):
        _close_unrar_owned(rc=11, has_verifiable_hash=True)


@pytest.mark.parametrize("rc", [2, 3])
def test_unrar_owned_stream_maps_fatal_crc_when_no_hash(rc: int) -> None:
    """F4: exits 2/3 map to CorruptionError when archivey has no verifiable hash."""
    with raises_corruption_not_truncation(match="fatal or CRC"):
        _close_unrar_owned(rc=rc, named_member=True, has_verifiable_hash=False)


@pytest.mark.parametrize("rc", [2, 3])
def test_unrar_owned_stream_suppresses_fatal_crc_when_hash_present(rc: int) -> None:
    """F4: with a verifiable hash, archivey's digest check is authoritative — ignore
    unrar's sometimes-spurious CRC/fatal codes (legacy RAR 1.5 false positives)."""
    _close_unrar_owned(rc=rc, named_member=True, has_verifiable_hash=True)


def test_unrar_owned_stream_zero_length_read_is_not_end_of_file() -> None:
    """read(0) and an empty readinto return nothing and leave the exit status alone."""
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        io.BytesIO(b""),
        _FakeUnrarProc(11),  # type: ignore[arg-type]
        named_member=True,
        encrypted=True,
    )
    assert stream.read(0) == b""
    assert stream.readinto(bytearray()) == 0
    with pytest.raises(EncryptionError):
        stream.read()
    stream.close()


@pytest.mark.parametrize("rc", [2, 3])
def test_unrar_owned_stream_encrypted_empty_maps_to_encryption_error_on_read(
    rc: int,
) -> None:
    """RAR4 wrong password: exit 2/3 + empty stdout → EncryptionError on the
    completing/empty read (eager finalize), including when a hash would suppress CRC."""
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        io.BytesIO(b""),
        _FakeUnrarProc(rc),  # type: ignore[arg-type]
        named_member=True,
        has_verifiable_hash=True,
        encrypted=True,
    )
    with pytest.raises(EncryptionError):
        stream.read()
    stream.close()  # already mapped on read — must not raise again


@pytest.mark.parametrize("rc", [2, 3])
def test_unrar_owned_stream_encrypted_empty_maps_to_encryption_error_on_close(
    rc: int,
) -> None:
    """Early-stop close still maps encrypted empty exit 2/3 when no completing read."""
    with pytest.raises(EncryptionError):
        _close_unrar_owned(
            rc=rc,
            named_member=True,
            has_verifiable_hash=True,
            encrypted=True,
        )


def test_unrar_owned_stream_maps_exit_10_for_named_open() -> None:
    """F4: exit 10 (no files matched) on a named ``-n`` open is CorruptionError."""
    with raises_corruption_not_truncation(match="no matching member"):
        _close_unrar_owned(rc=10, named_member=True, has_verifiable_hash=False)


def test_unrar_owned_stream_suppresses_exit_10_when_hash_present() -> None:
    """F4: exit 10 is also suppressed when archivey verifies the member itself."""
    _close_unrar_owned(rc=10, named_member=True, has_verifiable_hash=True)


def test_unrar_owned_stream_ignores_exit_10_on_solid_all_pipe() -> None:
    """F4: exit 10 on the solid ALL-pipe is not an error (empty match is expected
    when no named filter is used)."""
    _close_unrar_owned(rc=10, named_member=False, has_verifiable_hash=False)


def test_unrar_owned_stream_success_and_warning_pass() -> None:
    """F4: exits 0 (success) and 1 (warning) close cleanly."""
    _close_unrar_owned(rc=0, named_member=True)
    _close_unrar_owned(rc=1, named_member=True)


def test_unrar_owned_stream_negative_rc_from_terminate_is_not_error() -> None:
    """F4: a negative return code means we terminated the process (early close)."""
    _close_unrar_owned(rc=-15, named_member=True, has_verifiable_hash=False)


def test_unrar_owned_stream_close_does_not_mask_inner_close_error() -> None:
    """inner.close() must not be replaced by the exit-mapped error in close()."""
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        _CloseRaises(b""),
        _FakeUnrarProc(11),  # type: ignore[arg-type]
        named_member=True,
        has_verifiable_hash=True,
    )
    with pytest.raises(OSError, match="stdout close failed") as caught:
        stream.close()
    assert isinstance(caught.value.__cause__, EncryptionError)


def test_unrar_owned_stream_close_raises_inner_error_on_quiet_unrar_exit() -> None:
    """inner.close() still raises when unrar already exited 0 (no mapped error)."""
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        _CloseRaises(b""),
        _FakeUnrarProc(0),  # type: ignore[arg-type]
        named_member=True,
        has_verifiable_hash=True,
    )
    with pytest.raises(OSError, match="stdout close failed") as caught:
        stream.close()
    assert caught.value.__cause__ is None


def test_unrar_owned_stream_tell_counts_bytes_and_refuses_after_close() -> None:
    """``tell()`` answers from the bytes read, not the pipe, and like a file it
    raises ``ValueError`` once the stream is closed."""
    from archivey.internal.backends.rar_reader import _UnrarOwnedStream

    stream = _UnrarOwnedStream(
        io.BytesIO(b"0123456789abcdef"),
        _FakeUnrarProc(0),  # type: ignore[arg-type]
        named_member=True,
    )
    assert stream.tell() == 0
    assert stream.read(10) == b"0123456789"
    assert stream.tell() == 10
    stream.close()
    with pytest.raises(ValueError, match="closed file"):
        stream.tell()


def test_open_unrar_p_missing_stdout_pipe_is_typed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An `unrar` spawn that yields no stdout pipe must not cross as a raw RuntimeError.

    Defensive: `Popen` is asked for `stdout=PIPE`, so this should be unreachable. It is
    typed anyway because every archive-read failure surfaces as an `ArchiveyError`, and
    the raw error would otherwise escape `open_archive` untranslated (review F15).
    """

    class _NoStdout:
        stdout = None
        stdin = None
        terminated = False
        waited = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            self.waited = True
            return 0

    proc = _NoStdout()
    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: "/bin/true")
    monkeypatch.setattr(rar_unrar.subprocess, "Popen", lambda *a, **k: proc)

    with pytest.raises(ArchiveyError):
        rar_unrar.open_unrar_p(tmp_path / "nonexistent.rar")
    # The child is terminated *and* reaped, like every other exit from this module
    # (a bare kill() would leave it unreaped until the next Popen sweeps it).
    assert proc.terminated is True
    assert proc.waited is True


def _count_packed_skips(path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, int]:
    """Return ``(skip_count, member_count)`` for one ``parse_rar_archive`` call."""
    from archivey.internal.backends import rar_parser

    skips = 0
    original = rar_parser._seek_after_packed

    def counting(source: object, data_offset: int, add_size: int) -> object:
        nonlocal skips
        skips += 1
        return original(source, data_offset, add_size)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_parser, "_seek_after_packed", counting)
    try:
        with path.open("rb") as handle:
            archive = rar_parser.parse_rar_archive(handle)
        return skips, len(archive.members)
    finally:
        monkeypatch.setattr(rar_parser, "_seek_after_packed", original)


def _rar_a(
    tmp_path: Path, name: str, files: dict[str, bytes], extra: list[str]
) -> Path:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for rel, content in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        names.append(rel)
    out = tmp_path / name
    result = subprocess.run(
        ["rar", "a", "-idq", "-ep1", *extra, str(out), *names],
        cwd=src,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0 or not out.is_file():
        pytest.skip(f"rar cannot build {name}: {result.stderr!r}")
    return out


def test_listing_without_qo_walks_header_to_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """formats/rar.md §1: no QO → listing seeks once per member (walk)."""
    small_skips, small_n = _count_packed_skips(
        _fixture("basic_nonsolid__.rar"), monkeypatch
    )
    assert small_skips >= small_n, (
        f"{small_skips} data skips for {small_n} members — expected at least one "
        "per member, i.e. a header-to-header walk"
    )
    large_skips, large_n = _count_packed_skips(
        _fixture("many_list_store__.rar"), monkeypatch
    )
    assert large_n > 10 * small_n
    assert large_skips > 10 * small_skips


def test_listing_with_qo_does_not_seek_per_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """formats/rar.md §1: QO present → skips do not scale with member count."""
    corpus = Path(__file__).parent / "fixtures" / "corpus" / "rar" / "large.rar"
    if not corpus.is_file():
        pytest.skip("missing corpus large.rar")
    skips, n = _count_packed_skips(corpus, monkeypatch)
    assert n >= 1
    # MAIN + QO (+ optional CMT/RR). A FILE walk would also skip each packed
    # member, so the count would be at least n plus those few service seeks.
    assert skips < n + 2, (
        f"{skips} packed skips for {n} members — QO listing should not seek "
        "once per FILE"
    )
    assert skips <= 6


@requires_binary("rar")
def test_listing_qo_skip_count_does_not_scale_with_member_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    small_files = {f"s{i:02d}.txt": f"s{i}\n".encode() for i in range(8)}
    large_files = {f"n{i:03d}.txt": f"n{i}\n".encode() for i in range(40)}
    small = _rar_a(tmp_path / "small", "small.rar", small_files, ["-m0", "-qo+"])
    large = _rar_a(tmp_path / "large", "large.rar", large_files, ["-m0", "-qo+"])
    small_skips, small_n = _count_packed_skips(small, monkeypatch)
    large_skips, large_n = _count_packed_skips(large, monkeypatch)
    assert small_n == 8
    assert large_n == 40
    assert small_skips < small_n
    assert large_skips < large_n
    # Same O(1) shape: 40 members must not cost ~5× the 8-member archive.
    assert large_skips < small_skips * 2 + 3


@requires_binary("rar")
def test_qo_listing_stored_read_and_comment(tmp_path: Path) -> None:
    """QO table is what extract reads: stored slice + archive comment still work."""
    cmt = tmp_path / "cmt.txt"
    cmt.write_text("hello-comment\n", encoding="utf-8")
    files = {
        "a.txt": b"alpha-payload\n",
        "b.bin": b"\x00\x01\x02" * 10,
        "c.txt": b"nested\n",
    }
    archive_path = _rar_a(
        tmp_path / "qo",
        "qo.rar",
        files,
        ["-m0", "-qo+", f"-z{cmt}"],
    )
    with open_archive(archive_path) as archive:
        assert archive.info.comment == "hello-comment\n"
        listed = {m.name: m for m in archive.members() if m.is_file}
        assert set(listed) == set(files)
        for name, expected in files.items():
            assert archive.read(listed[name]) == expected


@requires_binary("rar")
def test_unreadable_qo_falls_back_to_file_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.backends import rar_parser

    files = {f"f{i}.txt": f"body-{i}\n".encode() for i in range(5)}
    archive_path = _rar_a(tmp_path / "fb", "fb.rar", files, ["-m0", "-qo+"])
    data = bytearray(archive_path.read_bytes())
    payload_at = _rar5_qo_data_offset(archive_path)
    data[payload_at + 8] ^= 0xFF
    broken = tmp_path / "broken.rar"
    broken.write_bytes(data)
    calls: list[object] = []
    original = rar_parser._parse_rar5_qo_payload

    def wrapping(*args: object, **kwargs: object) -> object:
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(rar_parser, "_parse_rar5_qo_payload", wrapping)
    with open_archive(broken) as archive:
        listed = {m.name for m in archive.members() if m.is_file}
        assert listed == set(files)
        assert archive.read("f0.txt") == b"body-0\n"
    assert calls, "QO payload was never reached — the flip hit the header"


@requires_binary("rar")
def test_qo_over_max_members_raises_not_unusable(tmp_path: Path) -> None:
    """An over-limit QO raises ResourceLimitError; it is not swallowed as unusable."""
    from archivey.internal.backends import rar_parser

    files = {f"f{i}.txt": f"body-{i}\n".encode() for i in range(5)}
    archive_path = _rar_a(tmp_path / "lim", "lim.rar", files, ["-m0", "-qo+"])
    with archive_path.open("rb") as source:
        assert source.read(len(RAR5_ID)) == RAR5_ID
        parsed = rar_parser._read_rar5_block(source)
        assert parsed is not None
        (
            block_type,
            _flags,
            hdata,
            _pos,
            header_offset,
            _header_size,
            data_offset,
            add_size,
            extra_size,
        ) = parsed
        assert block_type == rar_parser._RAR5_MAIN
        qopen = rar_parser._rar5_locator_qopen_abs(hdata, extra_size, header_offset)
        assert qopen is not None
        rar_parser._seek_after_packed(source, data_offset, add_size)
        with pytest.raises(ResourceLimitError, match="max_members"):
            rar_parser._try_list_via_rar5_qo(
                source,
                qopen_abs=qopen,
                volume_index=0,
                min_file_offset=source.tell(),
                max_members=2,
                max_metadata_bytes=None,
            )


@requires_binary("rar")
def test_auto_qo_lists_small_files_omitted_from_cache(tmp_path: Path) -> None:
    """WinRAR AUTO QO caches large files only; local FILE headers still list."""
    files = {
        "tiny.txt": b"t" * 240,
        "large.bin": b"L" * 10240,
    }
    archive_path = _rar_a(tmp_path / "auto", "auto.rar", files, ["-m0"])
    qo_names = _qo_cached_filenames(archive_path)
    assert "tiny.txt" not in qo_names, f"AUTO cached {qo_names}; skip-walk untested"
    assert "large.bin" in qo_names
    with open_archive(archive_path) as archive:
        listed = {m.name for m in archive.members() if m.is_file}
        assert listed == set(files)
        assert archive.read("tiny.txt") == files["tiny.txt"]
        assert archive.read("large.bin") == files["large.bin"]


def _rar5_block_ranges(path: Path) -> list[tuple[int, int, int]]:
    """Return ``(block_type, header_offset, packed_end)`` for each RAR5 block."""
    from archivey.internal.backends import rar_parser

    ranges: list[tuple[int, int, int]] = []
    with path.open("rb") as source:
        assert source.read(len(RAR5_ID)) == RAR5_ID
        while True:
            parsed = rar_parser._read_rar5_block(source)
            if parsed is None:
                break
            (
                block_type,
                _flags,
                _hdata,
                _pos,
                header_offset,
                _header_size,
                data_offset,
                add_size,
                _extra_size,
            ) = parsed
            ranges.append((block_type, header_offset, data_offset + add_size))
            if block_type == rar_parser._RAR5_ENDARC:
                break
            rar_parser._seek_after_packed(source, data_offset, add_size)
    return ranges


def _rar5_qo_data_offset(path: Path) -> int:
    """Packed-data start of the QO SERVICE, or raise if none."""
    from archivey.internal.backends import rar_parser

    with path.open("rb") as source:
        assert source.read(len(RAR5_ID)) == RAR5_ID
        while True:
            parsed = rar_parser._read_rar5_block(source)
            if parsed is None:
                break
            (
                block_type,
                block_flags,
                hdata,
                pos,
                header_offset,
                header_size,
                data_offset,
                add_size,
                extra_size,
            ) = parsed
            if block_type == rar_parser._RAR5_SERVICE:
                member = rar_parser._parse_rar5_file_block(
                    hdata,
                    pos,
                    block_flags=block_flags,
                    extra_size=extra_size,
                    header_offset=header_offset,
                    header_size=header_size,
                    data_offset=data_offset,
                    add_size=add_size,
                    volume_index=0,
                )
                if member.filename == rar_parser._RAR5_QO_NAME:
                    return data_offset
            if block_type == rar_parser._RAR5_ENDARC:
                break
            rar_parser._seek_after_packed(source, data_offset, add_size)
    raise AssertionError("no QO SERVICE")


def _qo_cached_filenames(path: Path) -> set[str]:
    """Filenames stored in QO (not the local FILE headers AUTO omitted)."""
    from archivey.internal.backends import rar_parser

    with path.open("rb") as source:
        assert source.read(len(RAR5_ID)) == RAR5_ID
        parsed = rar_parser._read_rar5_block(source)
        assert parsed is not None
        (
            block_type,
            _flags,
            hdata,
            _pos,
            header_offset,
            _header_size,
            data_offset,
            add_size,
            extra_size,
        ) = parsed
        assert block_type == rar_parser._RAR5_MAIN
        qopen = rar_parser._rar5_locator_qopen_abs(hdata, extra_size, header_offset)
        assert qopen is not None
        rar_parser._seek_after_packed(source, data_offset, add_size)
        listed = rar_parser._try_list_via_rar5_qo(
            source,
            qopen_abs=qopen,
            volume_index=0,
            min_file_offset=source.tell(),
            max_members=None,
            max_metadata_bytes=None,
        )
        assert listed is not None
        members, _end = listed
        return {m.filename for m in members}


def _listing_snapshot(archive: RarArchive) -> tuple[object, ...]:
    return (
        archive.version,
        archive.is_solid,
        archive.has_header_encryption,
        archive.comment,
        archive.sfx_offset,
        archive.is_volume,
        archive.needs_next_volume,
        tuple(dataclasses.asdict(m) for m in archive.members),
    )


def _assert_qo_walk_parity(path: Path, *, password: str | bytes | None = None) -> None:
    """QO listing and the FILE-header walk must produce identical member tables."""
    assert _qo_cached_filenames(path), (
        f"{path} has no QO table — comparison is walk vs walk"
    )
    with path.open("rb") as handle:
        via_qo = parse_rar_archive(handle, password=password, use_qo=True)
    with path.open("rb") as handle:
        via_walk = parse_rar_archive(handle, password=password, use_qo=False)
    assert _listing_snapshot(via_qo) == _listing_snapshot(via_walk)


def _qo_vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _qo_with_unmatched_copy(path: Path) -> bytes:
    """``path`` (``-m0 -qo+``, members ``a.txt`` then ``b.txt``) with ``a.txt``'s QO
    copy replaced by a copy of ``b.txt``'s header that points 10 bytes into
    ``a.txt``'s data, so no header the walk reaches matches it. The spans stay
    consistent, so QO is still used: ``a.txt`` is listed from its own header and
    ``b.txt`` from its copy. The payload keeps its length, zero-padded at the end as
    the QO parser allows, so no header changes."""
    from archivey.internal.backends import rar_parser

    data = bytearray(path.read_bytes())
    archive = parse_rar_archive(io.BytesIO(bytes(data)), use_qo=False)
    a, b = archive.members
    payload_at = _rar5_qo_data_offset(path)
    # The copies' offsets count back from the QO header's own offset.
    with path.open("rb") as source:
        source.seek(len(RAR5_ID))
        while True:
            parsed = rar_parser._read_rar5_block(source)
            assert parsed is not None
            header_offset, data_offset, add_size = parsed[4], parsed[6], parsed[7]
            if data_offset == payload_at:
                qo_header, payload_size = header_offset, add_size
                break
            rar_parser._seek_after_packed(source, data_offset, add_size)
    payload = bytes(data[payload_at : payload_at + payload_size])
    records: list[tuple[int, bytes]] = []
    pos = 0
    end = len(payload.rstrip(b"\0"))
    while pos < end:
        body_size, body_at = load_vint(payload, pos + 4)
        body = payload[body_at : body_at + body_size]
        _, bp = load_vint(body, 0)
        offset_from_qo, _ = load_vint(body, bp)
        records.append((qo_header - offset_from_qo, payload[pos : body_at + body_size]))
        pos = body_at + body_size
    by_offset = dict(records)
    assert set(by_offset) == {a.header_offset, b.header_offset}  # precondition

    b_record = by_offset[b.header_offset]
    _, b_body_at = load_vint(b_record, 4)
    b_body = b_record[b_body_at:]
    flags, bp = load_vint(b_body, 0)
    _, bp = load_vint(b_body, bp)
    bogus = a.data_offset + 10
    body = _qo_vint(flags) + _qo_vint(qo_header - bogus) + b_body[bp:]
    size = _qo_vint(len(body))
    bogus_record = struct.pack("<I", zlib.crc32(size + body)) + size + body
    rebuilt = b"".join(
        bogus_record if offset == a.header_offset else record
        for offset, record in records
    )
    assert len(rebuilt) <= len(payload)  # precondition: no header has to change
    data[payload_at : payload_at + len(payload)] = rebuilt.ljust(len(payload), b"\0")
    return bytes(data)


def _qo_two_member_archive(tmp_path: Path) -> Path:
    return _rar_a(
        tmp_path / "qo2",
        "qo2.rar",
        {"a.txt": b"a" * 200, "b.txt": b"b"},
        ["-m0", "-qo+"],
    )


def _unmatched_copy_diagnostics(archive: ArchiveReader) -> list[Diagnostic]:
    return [
        d
        for d in archive.diagnostics.retained
        if d.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        and isinstance(d.context, MemberHeaderRecordContext)
        and d.context.record == RAR5_QO_UNMATCHED_COPIES
    ]


@requires_binary("rar")
def test_a_qo_copy_the_walk_never_reaches_is_reported(tmp_path: Path) -> None:
    """A clean walk that never lands on a QO copy's ``header_offset`` leaves the
    listing as it is and reports the copy on the QO header, so a strict policy can
    refuse a damaged or crafted quick-open record."""
    path = _qo_two_member_archive(tmp_path)
    patched = tmp_path / "unmatched.rar"
    patched.write_bytes(_qo_with_unmatched_copy(path))
    assert _qo_cached_filenames(patched) == {"b.txt"}  # QO is still used
    data = patched.read_bytes()
    via_qo = parse_rar_archive(io.BytesIO(data), use_qo=True)
    via_walk = parse_rar_archive(io.BytesIO(data), use_qo=False)
    assert _listing_snapshot(via_qo) == _listing_snapshot(via_walk)
    with open_archive(patched) as archive:
        assert [m.name for m in archive.members()] == ["a.txt", "b.txt"]
        assert archive.read("a.txt") == b"a" * 200
        (diagnostic,) = _unmatched_copy_diagnostics(archive)
    context = diagnostic.context
    assert isinstance(context, MemberHeaderRecordContext)
    assert context.member_name == ""
    assert context.member_id is None
    assert diagnostic.message == (
        "This archive's QO quick-open service header holds 1 FILE header copy "
        "that matched no header the walk reached. rar writes no copy that matches "
        "no header, so this record is damaged or crafted. The listing comes from "
        "the headers the walk read, which is what unrar lists too."
    )
    with (
        pytest.raises(DiagnosticRaisedError) as raised,
        open_archive(
            patched,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as archive,
    ):
        archive.members()
    assert raised.value.diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
    assert isinstance(raised.value.diagnostic.context, MemberHeaderRecordContext)
    assert raised.value.diagnostic.context.record == RAR5_QO_UNMATCHED_COPIES


@requires_binary("rar")
def test_an_intact_qo_reports_no_unmatched_copy(tmp_path: Path) -> None:
    with open_archive(_qo_two_member_archive(tmp_path)) as archive:
        archive.members()
        assert not _unmatched_copy_diagnostics(archive)


@requires_binary("rar")
def test_an_unmatched_qo_copy_is_kept_past_the_damaged_header_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap counts headers whose walk did not finish, and its overflow message
    says so; the QO entry is not one, so neither the walk nor the volume merge
    turns it away or counts it there."""
    from archivey.internal.backends import rar_parser

    monkeypatch.setattr(rar_parser, "_MAX_DAMAGED_SERVICE_HEADERS", 0)
    data = _qo_with_unmatched_copy(_qo_two_member_archive(tmp_path))
    archive = parse_rar_archive(io.BytesIO(data), use_qo=True)
    (entry,) = archive.damaged_service_headers
    assert entry.skipped_header_records[0][0] == RAR5_QO_UNMATCHED_COPIES
    assert archive.damaged_service_headers_omitted == 0
    merged: list[rar_parser.DamagedServiceHeader] = []
    assert rar_parser._append_damaged_service_header(merged, entry)
    assert merged == [entry]


@requires_binary("rar")
def test_unmatched_qo_copies_are_not_reported_without_a_clean_end(
    tmp_path: Path,
) -> None:
    """A walk that was cut or stopped at a damaged header leaves copies unreached
    for that reason alone; a damaged end block makes the archive corrupt already,
    and the claim would rest on a header that failed its check; a walk that did not
    use QO has no copies to leave."""
    data = _qo_with_unmatched_copy(_qo_two_member_archive(tmp_path))
    whole = parse_rar_archive(io.BytesIO(data), use_qo=True)
    assert len(whole.damaged_service_headers) == 1  # control
    no_qo = parse_rar_archive(io.BytesIO(data), use_qo=False)
    assert no_qo.damaged_service_headers == []
    cut = parse_rar_archive(io.BytesIO(data[:-3]), use_qo=True)
    assert cut.truncated is not None  # the cut is inside the end block
    assert [m.filename for m in cut.members] == ["a.txt", "b.txt"]
    assert cut.damaged_service_headers == []

    # a.txt is not in the patched QO, so the walk reads its own header, fails its
    # CRC and stops there: both copies are unreached.
    (a, _b) = no_qo.members
    bad_header = bytearray(data)
    bad_header[a.header_offset] ^= 0xFF
    damaged = parse_rar_archive(io.BytesIO(bytes(bad_header)), use_qo=True)
    assert damaged.damaged is not None
    assert damaged.members == []
    assert damaged.damaged_service_headers == []

    # The end block is the last 8 bytes and nothing follows it, so the walk keeps
    # the listing and records the damage.
    assert data[-3] == 5  # precondition: ENDARC's type byte
    bad_end = bytearray(data)
    bad_end[-8] ^= 0xFF
    end = parse_rar_archive(io.BytesIO(bytes(bad_end)), use_qo=True)
    assert end.end_block_damaged_volumes
    assert [m.filename for m in end.members] == ["a.txt", "b.txt"]
    assert end.damaged_service_headers == []


@requires_binary("rar")
@requires_binary("unrar")
def test_unrar_lists_the_walk_not_an_unmatched_qo_copy(tmp_path: Path) -> None:
    """The oracle: ``unrar`` substitutes a copy only for a header it reaches, so it
    lists the same two members and reads ``a.txt`` from its own header."""
    patched = tmp_path / "unmatched.rar"
    patched.write_bytes(_qo_with_unmatched_copy(_qo_two_member_archive(tmp_path)))
    listed = subprocess.run(
        ["unrar", "lb", "--", str(patched)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert listed == ["a.txt", "b.txt"]
    read = subprocess.run(
        ["unrar", "p", "-inul", "--", str(patched), "a.txt"],
        capture_output=True,
        check=True,
    ).stdout
    assert read == b"a" * 200


def test_qo_listing_matches_file_walk_on_corpus() -> None:
    """formats/rar.md §1.1: committed QO archive matches the FILE walk."""
    corpus = Path(__file__).parent / "fixtures" / "corpus" / "rar" / "large.rar"
    if not corpus.is_file():
        pytest.skip("missing corpus large.rar")
    _assert_qo_walk_parity(corpus)


@requires_binary("rar")
@pytest.mark.parametrize(
    ("files", "extra"),
    [
        ({"a.txt": b"alpha\n", "b.bin": b"B" * 64}, ["-m0", "-qo+"]),
        ({"tiny.txt": b"t" * 240, "large.bin": b"L" * 10240}, ["-m0"]),
        ({"s.txt": b"solid\n", "t.txt": b"two\n"}, ["-m3", "-s", "-qo+"]),
        ({"e.txt": b"secret\n"}, ["-m0", "-qo+", "-ppw"]),
        ({"x.txt": b"stamp\n"}, ["-m0", "-qo+", "-ts+"]),
        ({"empty.txt": b"", "dir/nested.txt": b"n\n"}, ["-m0", "-qo+"]),
    ],
    ids=["qo+", "auto", "solid", "member-encrypted", "xtime", "empty-and-nested"],
)
def test_qo_listing_matches_file_walk_live(
    tmp_path: Path, files: dict[str, bytes], extra: list[str]
) -> None:
    archive_path = _rar_a(tmp_path / "parity", "parity.rar", files, extra)
    _assert_qo_walk_parity(archive_path)


@requires_binary("rar")
def test_qo_listing_matches_file_walk_with_comment(tmp_path: Path) -> None:
    cmt = tmp_path / "cmt.txt"
    cmt.write_text("hello-comment\n", encoding="utf-8")
    archive_path = _rar_a(
        tmp_path / "cmt",
        "cmt.rar",
        {"a.txt": b"alpha\n"},
        ["-m0", "-qo+", f"-z{cmt}"],
    )
    _assert_qo_walk_parity(archive_path)


@requires_binary("rar")
def test_rar_a_rewrites_qo_and_lists_the_new_member(tmp_path: Path) -> None:
    """``rar a`` rewrites QO at a new tail; the added member is not FILE-after-QO."""
    from archivey.internal.backends import rar_parser

    first = {"a.txt": b"alpha\n"}
    archive_path = _rar_a(tmp_path / "incr", "incr.rar", first, ["-m0", "-qo+"])
    src = tmp_path / "incr" / "src"
    (src / "b.txt").write_bytes(b"beta\n")
    result = subprocess.run(
        ["rar", "a", "-idq", "-ep1", "-m0", "-qo+", str(archive_path), "b.txt"],
        cwd=src,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"rar cannot add: {result.stderr!r}")

    ranges = _rar5_block_ranges(archive_path)
    file_starts = [h for t, h, _ in ranges if t == rar_parser._RAR5_FILE]
    service_starts = [h for t, h, _ in ranges if t == rar_parser._RAR5_SERVICE]
    assert file_starts
    assert service_starts
    assert max(file_starts) < min(service_starts)

    data = archive_path.read_bytes()
    qo_at = data.rfind(b"QO")
    assert qo_at != -1
    assert data.find(b"b.txt", qo_at) != -1

    with open_archive(archive_path) as archive:
        listed = {m.name for m in archive.members() if m.is_file}
        assert listed == {"a.txt", "b.txt"}
        assert archive.read("a.txt") == b"alpha\n"
        assert archive.read("b.txt") == b"beta\n"
    _assert_qo_walk_parity(archive_path)


@requires_binary("rar")
def test_file_header_after_qo_is_still_listed(tmp_path: Path) -> None:
    """A FILE after QO (crafted; not the ``rar a`` path) is adopted, not dropped."""
    from archivey.internal.backends import rar_parser

    host = _rar_a(tmp_path / "host", "host.rar", {"a.txt": b"alpha\n"}, ["-m0", "-qo+"])
    donor = _rar_a(
        tmp_path / "donor", "donor.rar", {"b.txt": b"beta\n"}, ["-m0", "-qo-"]
    )
    donor_ranges = _rar5_block_ranges(donor)
    file_range = next(
        (h, end) for t, h, end in donor_ranges if t == rar_parser._RAR5_FILE
    )
    host_ranges = _rar5_block_ranges(host)
    endarc_at = next(h for t, h, _ in host_ranges if t == rar_parser._RAR5_ENDARC)
    spliced = tmp_path / "spliced.rar"
    host_bytes = host.read_bytes()
    donor_bytes = donor.read_bytes()
    spliced.write_bytes(
        host_bytes[:endarc_at]
        + donor_bytes[file_range[0] : file_range[1]]
        + host_bytes[endarc_at:]
    )
    file_starts = [
        h for t, h, _ in _rar5_block_ranges(spliced) if t == rar_parser._RAR5_FILE
    ]
    service_starts = [
        h for t, h, _ in _rar5_block_ranges(spliced) if t == rar_parser._RAR5_SERVICE
    ]
    assert file_starts[-1] > service_starts[0]

    with open_archive(spliced) as archive:
        listed = {m.name for m in archive.members() if m.is_file}
        assert listed == {"a.txt", "b.txt"}
        assert archive.read("a.txt") == b"alpha\n"
        assert archive.read("b.txt") == b"beta\n"


def test_password_with_a_line_break_is_refused_not_clamped() -> None:
    """`unrar` reads the password as one line, so a longer one is silently cut.

    Measured against RARLAB `rar` 7.00 before this guard: an archive whose password is
    "ab" decrypted when "ab\nXX" was supplied — a wrong password accepted, with nothing
    downstream able to tell. The native header path hashes the whole string, so the same
    argument also meant two different things on the two paths.
    """
    from archivey.exceptions import UnsupportedFeatureError
    from archivey.internal.backends.rar_unrar import _password_stdin_bytes

    for rar5 in (False, True):
        assert _password_stdin_bytes("ab", rar5=rar5) == b"ab"
        assert _password_stdin_bytes(b"ab", rar5=rar5) == b"ab"
        for bad in ["ab\nXX", "ab\rXX", b"ab\nXX", b"ab\rXX"]:
            with pytest.raises(UnsupportedFeatureError, match="line break"):
                _password_stdin_bytes(bad, rar5=rar5)


# 128 UTF-16 units: RAR keeps the first 127, which ends on half of the emoji's pair.
_PASSWORD_CUT_INSIDE_A_PAIR = "a" * 126 + "\U0001f600"


def test_rar5_password_cut_inside_a_surrogate_pair_is_a_wrong_password_for_unrar() -> (
    None
):
    """RAR5 hashes UTF-8, so a cut with no UTF-8 form cannot be the real password.

    The native RAR5 path rejects the same candidate with the wrong-password
    ``EncryptionError`` (``test_a_rar5_password_cut_inside_a_surrogate_pair_is_a_wrong_
    candidate``); the ``unrar`` path raised ``UnsupportedFeatureError`` instead.
    """
    from archivey.internal.backends.rar_unrar import _password_stdin_bytes
    from archivey.internal.password import is_wrong_password

    with pytest.raises(EncryptionError) as excinfo:
        _password_stdin_bytes(_PASSWORD_CUT_INSIDE_A_PAIR, rar5=True)
    assert is_wrong_password(excinfo.value)
    # One unit shorter, the whole emoji is cut off and the rest is sent.
    assert _password_stdin_bytes("a" * 127 + "\U0001f600", rar5=True) == b"a" * 127


def test_rar4_password_cut_inside_a_surrogate_pair_is_refused_not_wrong() -> None:
    """RAR 1.5-4 hashes the UTF-16 units as they are, lone half included.

    The native RAR3 key derivation accepts exactly this password, so a header CRC
    can prove it right. Calling it wrong would be false: the limit is ``unrar``'s
    stdin, which cannot carry half a character.
    """
    from archivey.exceptions import UnsupportedFeatureError
    from archivey.internal.backends.rar_parser import _normalize_password_utf16le
    from archivey.internal.backends.rar_unrar import _password_stdin_bytes

    # The native path keeps the lone high surrogate.
    assert _normalize_password_utf16le(_PASSWORD_CUT_INSIDE_A_PAIR).endswith(
        b"\x3d\xd8"
    )
    with pytest.raises(UnsupportedFeatureError, match="unrar reads the password"):
        _password_stdin_bytes(_PASSWORD_CUT_INSIDE_A_PAIR, rar5=False)
    assert _password_stdin_bytes("a" * 127 + "\U0001f600", rar5=False) == b"a" * 127


@requires_binary("unrar")
def test_rar4_member_password_cut_inside_a_surrogate_pair_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end on RAR4 data encryption, which is decrypted by ``unrar``.

    The refusal comes before any ``unrar`` process starts. Asserting only
    ``EncryptionError`` would also pass if the password were mangled and sent,
    because ``unrar``'s own wrong-password exit maps to that class too.
    """
    from archivey.exceptions import UnsupportedFeatureError
    from archivey.internal.backends import rar_unrar

    def _no_spawn(*args: object, **kwargs: object) -> None:
        raise AssertionError("unrar must not be spawned for this password")

    monkeypatch.setattr(rar_unrar, "spawn_for_stdout", _no_spawn)
    path = _fixture("encryption__rar4.rar")
    with (
        open_archive(path, password=_PASSWORD_CUT_INSIDE_A_PAIR) as archive,
        pytest.raises(UnsupportedFeatureError, match="unrar reads the password"),
    ):
        archive.read("secret.txt")


@requires_binary("unrar")
@pytest.mark.parametrize("name", ["rar15-comment.rar", "blake2sp.rar"])
def test_unencrypted_archive_opens_with_a_line_break_password(name: str) -> None:
    """A configured password is not a used password.

    `unrar` only consults it when something is encrypted, so refusing the newline at
    the point the password is *passed* stopped plain archives from opening at all —
    `rar15-comment.rar` has an old-style compressed comment that is unpacked through
    `unrar` inside `__init__`. A password read from a file carries a trailing newline,
    so this is the ordinary input, not an exotic one.
    """
    path = _fixture(name)
    with open_archive(path, password="secret\n") as archive:
        members = [m for m in archive.members() if m.is_file]
        assert members
        for member in members:
            assert isinstance(archive.read(member), bytes)


@requires_binary("unrar")
def test_wrong_password_after_a_line_break_does_not_decrypt() -> None:
    """End to end: the prefix before the break must not be enough to read a member."""
    from archivey.exceptions import UnsupportedFeatureError

    path = _fixture("encryption__.rar")
    with open_archive(path, password="password") as archive:
        assert archive.read("secret.txt") == b"This is secret"
    with (
        open_archive(path, password="password\nIGNORED") as archive,
        pytest.raises((UnsupportedFeatureError, EncryptionError)),
    ):
        archive.read("secret.txt")


# ``wrong3`` survives the 64 KiB prefix of ``large1.txt`` in both compressed fixtures:
# ``unrar p`` emits all 100 000 bytes for it, so only the CRC tells it from the right
# password (checked with unrar 7.00 when the fixtures were made).
_RAR4_PREFIX_SURVIVOR = "wrong3"
_RAR4_LARGE = {
    "encryption_large__rar4.rar": ("large1.txt", "large2.txt"),
    "encryption_large_solid__rar4.rar": ("large1.txt", "large2.txt"),
    "encryption_large_stored__rar4.rar": ("large_stored.txt",),
}


def _unrar_payload(path: Path, member: str) -> bytes:
    return subprocess.run(
        ["unrar", "p", "-inul", "-ppassword", str(path), member],
        check=True,
        capture_output=True,
    ).stdout


@requires_unrar_cli()
@pytest.mark.parametrize("name", sorted(_RAR4_LARGE))
@pytest.mark.parametrize(
    "passwords",
    [
        ["wrong", "password"],
        [_RAR4_PREFIX_SURVIVOR, "password"],
        ["wrong", _RAR4_PREFIX_SURVIVOR, "password"],
        ["password", _RAR4_PREFIX_SURVIVOR],
    ],
)
def test_rar4_password_list_order_does_not_matter(
    name: str, passwords: list[str]
) -> None:
    """RAR3/4 data has no password check; a list is judged by decoding the member.

    ``unrar`` used to get the first candidate. A wrong password that survives the
    bounded probe is now settled by the member's CRC.
    """
    path = _fixture(name)
    expected = {member: _unrar_payload(path, member) for member in _RAR4_LARGE[name]}
    with open_archive(path, password=passwords) as archive:
        assert {m: archive.read(m) for m in expected} == expected
    with open_archive(path, password=passwords) as archive:
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert read == expected


@requires_binary("unrar")
@pytest.mark.parametrize("name", sorted(_RAR4_LARGE))
def test_rar4_password_list_with_no_right_password_is_an_encryption_error(
    name: str,
) -> None:
    path = _fixture(name)
    member = _RAR4_LARGE[name][0]
    with (
        open_archive(path, password=["wrong", "wrong1"]) as archive,
        pytest.raises(EncryptionError),
    ):
        archive.read(member)


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name", ["encryption_large__rar4.rar", "encryption_large_solid__rar4.rar"]
)
def test_rar4_lone_wrong_survivor_fails_on_its_crc(name: str) -> None:
    """A lone survivor of the probe is accepted, as one password is; the CRC catches it.

    No full check runs for a single survivor, so the read is what a single wrong
    password gives: the member's CRC mismatches at its end.
    """
    path = _fixture(name)
    with (
        open_archive(path, password=[_RAR4_PREFIX_SURVIVOR, "wrong"]) as archive,
        pytest.raises(CorruptionError, match="Digest mismatch"),
    ):
        archive.read("large1.txt")


@requires_binary("unrar")
@pytest.mark.parametrize("passwords", [["wrong3", "password"], ["password", "wrong3"]])
def test_rar4_damaged_member_is_not_reported_as_a_wrong_password(
    tmp_path: Path, passwords: list[str]
) -> None:
    """Decoding cannot tell a wrong key from damage, so the error claims neither.

    A byte flipped inside the first member's compressed data makes the right
    password fail its decode too; the list then has no survivor, and the message
    must leave open that the member, not the password, is at fault.
    """
    data = bytearray(_fixture("encryption_large__rar4.rar").read_bytes())
    data[20000] ^= 0xFF
    path = tmp_path / "damaged.rar"
    path.write_bytes(data)
    with (
        open_archive(path, password=passwords) as archive,
        pytest.raises(EncryptionError) as info,
    ):
        archive.read("large1.txt")
    assert "Wrong password" not in str(info.value)
    assert "may be damaged" in str(info.value)


@requires_unrar_cli()
@requires("cryptography")
def test_rar4_stored_password_list_is_judged_without_unrar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every wrong key decrypts a stored member to full length; the CRC check is native."""
    path = _fixture("encryption_large_stored__rar4.rar")
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        spawns.append(kwargs.get("password"))
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)
    with open_archive(path, password=["wrong", "other", "password"]) as archive:
        assert archive.read("large_stored.txt") == _unrar_payload(
            path, "large_stored.txt"
        )
    # None: the check and the read itself both decrypt the stored member natively.
    assert spawns == []


@requires_unrar_cli()
def test_rar4_stored_password_list_without_cryptography_goes_through_unrar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no AES backend the stored member is judged by ``unrar`` instead."""
    monkeypatch.setattr(rar_reader, "_crypto_available", lambda: False)
    path = _fixture("encryption_large_stored__rar4.rar")
    with open_archive(path, password=["wrong", "password"]) as archive:
        assert archive.read("large_stored.txt") == _unrar_payload(
            path, "large_stored.txt"
        )


@requires_binary("unrar")
def test_rar4_member_confirmed_by_its_crc_is_not_reported_unverified() -> None:
    """The full check vouched for this member, so an abandoned read is not reported."""
    path = _fixture("encryption_large__rar4.rar")
    with open_archive(path, password=[_RAR4_PREFIX_SURVIVOR, "password"]) as archive:
        with archive.open("large1.txt") as stream:
            stream.read(10)
        assert (
            DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED not in archive.diagnostics.counts
        )
        # large2.txt: the prefix rejects wrong3 there, so the right password is
        # accepted on a probe alone and an abandoned read is still reported.
        with archive.open("large2.txt") as stream:
            stream.read(10)
        assert DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED in archive.diagnostics.counts
