"""A symlink whose target starts at ``/``: written as stored under ``TRUSTED`` only.

A root filesystem or an initramfs image holds hundreds of these
(``usr/bin/pwsh -> /opt/microsoft/powershell/7/pwsh``, ``etc/localtime ->
/usr/share/zoneinfo/...``). GNU tar, cpio and unsquashfs write them as stored, so under
``TRUSTED`` archivey does too. ``STRICT`` and ``STANDARD`` keep refusing them. Under
every policy no member is written through a link that leads out: the member's parent
must resolve inside the destination (``safe-extraction`` spec).
"""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from archivey import (
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
)
from archivey.fsspec import ArchiveyFileSystem
from tests.conftest import requires_binary
from tests.extract_util import open_and_extract

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")

_MODES = pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])

# A small root filesystem, in the order ``tar -C rootfs -cf`` stores one.
_ROOTFS: list[tuple[str, str, str | bytes]] = [
    ("dir", "usr/", ""),
    ("dir", "usr/bin/", ""),
    ("file", "usr/bin/env", b"#!env\n"),
    ("sym", "usr/bin/pwsh", "/opt/microsoft/powershell/7/pwsh"),
    ("dir", "usr/lib/", ""),
    ("file", "usr/lib/libc.so.6", b"libc"),
    ("sym", "bin", "usr/bin"),
    ("sym", "lib", "usr/lib"),
    ("dir", "etc/", ""),
    ("sym", "etc/localtime", "/usr/share/zoneinfo/Etc/UTC"),
    ("sym", "etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"),
    ("sym", "etc/mtab", "/proc/self/mounts"),
    ("file", "etc/hostname", b"image\n"),
    ("hard", "etc/mtab.again", "etc/mtab"),
]
_ROOTED = {"usr/bin/pwsh", "etc/localtime", "etc/resolv.conf", "etc/mtab"}


def _tar(entries: list[tuple[str, str, str | bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for kind, name, value in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 1_700_000_000
            if kind == "file":
                assert isinstance(value, bytes)
                info.size = len(value)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(value))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
            else:
                assert isinstance(value, str)
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = value
            tf.addfile(info)
    return buf.getvalue()


def _tree(root: Path) -> dict[str, tuple[str, str | bytes | None]]:
    out: dict[str, tuple[str, str | bytes | None]] = {}
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            out[rel] = ("link", os.readlink(path))
        elif path.is_dir():
            out[rel] = ("dir", None)
        else:
            out[rel] = ("file", path.read_bytes())
    return out


@_MODES
def test_trusted_writes_an_image_as_stored(tmp_path: Path, streaming: bool) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar(_ROOTFS)),
        dest,
        streaming=streaming,
        policy=ExtractionPolicy.TRUSTED,
        on_error=OnError.CONTINUE,
    )
    assert {r.member.name: r.status for r in report} == dict.fromkeys(
        (name for _kind, name, _value in _ROOTFS), ExtractionStatus.EXTRACTED
    )
    for kind, name, value in _ROOTFS:
        if kind == "sym":
            assert os.readlink(dest / name) == value
    # A hard link to a symlink is a second name for it, as GNU tar makes it.
    assert os.readlink(dest / "etc/mtab.again") == "/proc/self/mounts"


@pytest.mark.parametrize(
    "policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD], ids=str
)
@_MODES
def test_the_other_policies_still_refuse_them(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar(_ROOTFS)),
        dest,
        streaming=streaming,
        policy=policy,
        on_error=OnError.CONTINUE,
    )
    refused = {r.member.name for r in report if r.status is ExtractionStatus.BLOCKED}
    # The hard link is the symlink it names, with that symlink's target.
    assert refused == _ROOTED | {"etc/mtab.again"}
    assert all(not os.path.lexists(dest / name) for name in refused)
    assert (dest / "bin/env").read_bytes() == b"#!env\n"


@requires_binary("tar")
def test_trusted_writes_the_tree_gnu_tar_writes(tmp_path: Path) -> None:
    archive = tmp_path / "rootfs.tar"
    archive.write_bytes(_tar(_ROOTFS))
    ours, theirs = tmp_path / "ours", tmp_path / "theirs"
    theirs.mkdir()
    open_and_extract(archive, ours, policy=ExtractionPolicy.TRUSTED)
    subprocess.run(
        ["tar", "-xf", str(archive), "-C", str(theirs), "--no-same-owner"], check=True
    )
    assert _tree(ours) == _tree(theirs)


def _outside_layout(tmp_path: Path) -> tuple[Path, Path]:
    dest = tmp_path / "dest"
    dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim").write_bytes(b"original")
    os.chmod(outside, 0o751)
    os.chmod(outside / "victim", 0o640)
    for path in (outside / "victim", outside):
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    return dest, outside


def _snapshot(path: Path) -> list[tuple[str, int, int, bytes | None]]:
    return [
        (
            p.name,
            p.lstat().st_mode,
            p.lstat().st_mtime_ns,
            p.read_bytes() if p.is_file() else None,
        )
        for p in sorted([path, *path.rglob("*")])
    ]


@pytest.mark.parametrize("overwrite", list(OverwritePolicy), ids=str)
@_MODES
def test_nothing_is_written_through_a_rooted_link(
    tmp_path: Path, streaming: bool, overwrite: OverwritePolicy
) -> None:
    """Every way a later member could reach through ``etc -> <outside>``: a file, a
    directory and a hard link under it, a relative link through it, a directory
    member over it, and the same through ``victim -> <outside>/victim``."""
    dest, outside = _outside_layout(tmp_path)
    before = _snapshot(outside)
    entries: list[tuple[str, str, str | bytes]] = [
        ("sym", "etc", str(outside)),
        ("sym", "victim", str(outside / "victim")),
        ("file", "etc/victim", b"overwritten"),
        ("file", "etc/new", b"overwritten"),
        ("dir", "etc/sub/", ""),
        ("hard", "h", "etc/victim"),
        ("sym", "rel", "etc/victim"),
        ("dir", "etc/", ""),
        ("file", "victim", b"overwritten"),
    ]
    report = open_and_extract(
        io.BytesIO(_tar(entries)),
        dest,
        streaming=streaming,
        policy=ExtractionPolicy.TRUSTED,
        on_error=OnError.CONTINUE,
        overwrite=overwrite,
    )
    statuses = {r.member.name: r.status for r in report}
    for name in ("etc/victim", "etc/new", "etc/sub/", "rel"):
        assert statuses[name] is ExtractionStatus.BLOCKED, name
    assert statuses["h"] is not ExtractionStatus.EXTRACTED
    assert _snapshot(outside) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest", "outside"]
    if overwrite is OverwritePolicy.REPLACE:
        # The later members replace the links; they do not write through them.
        assert (dest / "etc").is_dir() and not (dest / "etc").is_symlink()
        assert (dest / "victim").read_bytes() == b"overwritten"


def test_dry_run_reports_what_trusted_writes(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar(_ROOTFS)),
        dest,
        policy=ExtractionPolicy.TRUSTED,
        dry_run=True,
    )
    assert {
        r.member.name for r in report if r.status is ExtractionStatus.EXTRACTED
    } == {name for _kind, name, _value in _ROOTFS}
    assert not dest.exists()


def test_the_archivey_file_system_lists_them_under_trusted(tmp_path: Path) -> None:
    archive = tmp_path / "rootfs.tar"
    archive.write_bytes(_tar([*_ROOTFS, ("file", "etc/mtab/inside", b"x")]))
    with ArchiveyFileSystem(str(archive), policy=ExtractionPolicy.TRUSTED) as fs:
        info = fs.info("usr/bin/pwsh")
        assert info["islink"]
        assert info["destination"] == "/opt/microsoft/powershell/7/pwsh"
        # It leads out of the destination, so it reads as nothing.
        assert info["type"] == "other"
        # Nothing is written through it, so nothing under it is listed.
        assert not fs.exists("etc/mtab/inside")
        assert fs.cat("bin/env") == b"#!env\n"
    with ArchiveyFileSystem(str(archive), policy=ExtractionPolicy.STANDARD) as fs:
        assert not fs.exists("usr/bin/pwsh")


@pytest.mark.parametrize(
    "entries",
    [
        [("sym", "r", "x/victim"), ("sym", "x", "{outside}")],
        [("sym", "r", "a/b/victim"), ("dir", "a/", ""), ("sym", "a/b", "{outside}")],
    ],
    ids=["at-top", "under-a-directory"],
)
@_MODES
def test_an_earlier_link_through_a_later_rooted_link_is_removed(
    tmp_path: Path, streaming: bool, entries: list[tuple[str, str, str | bytes]]
) -> None:
    """A relative link made before the rooted link it resolves through is rechecked
    once the rooted link appears, and removed: only a stored target from ``/`` may
    lead out."""
    dest, outside = _outside_layout(tmp_path)
    filled = [
        (kind, name, value.format(outside=outside) if isinstance(value, str) else value)
        for kind, name, value in entries
    ]
    report = open_and_extract(
        io.BytesIO(_tar(filled)),
        dest,
        streaming=streaming,
        policy=ExtractionPolicy.TRUSTED,
        on_error=OnError.CONTINUE,
    )
    statuses = {r.member.name: r.status for r in report}
    assert statuses["r"] is ExtractionStatus.BLOCKED
    assert not os.path.lexists(dest / "r")
    rooted = filled[-1][1]
    assert statuses[rooted] is ExtractionStatus.EXTRACTED
    assert os.readlink(dest / rooted) == str(outside)
