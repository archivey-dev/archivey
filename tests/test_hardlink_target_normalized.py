"""A hard link's ``link_target`` is normalized in every format (maintainer ruling
2026-11-11).

A hard link names another member, so its target lists in that member's name form:
``./b`` lists as ``b``, in TAR as in CPIO and a plugin format. A target that ends in
``/`` keeps the ``/``: it names a directory, and does not resolve to a file of the
same name. A symlink's target stays as stored.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from archivey import ExtractionStatus, OnError, open_archive
from archivey.exceptions import LinkTargetNotFoundError
from archivey.internal.naming import (
    link_target_name_keys,
    normalize_hardlink_target,
    resolve_link_target_name,
)
from archivey.types import MemberType

_MODES = pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])


def _gnu_tar() -> str | None:
    tar = shutil.which("tar")
    if tar is None:
        return None
    try:
        version = subprocess.run(
            [tar, "--version"], capture_output=True, check=True, text=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return tar if "GNU tar" in version else None


_GNU_TAR = _gnu_tar()
needs_gnu_tar = pytest.mark.skipif(
    _GNU_TAR is None or not hasattr(os, "link"), reason="needs GNU tar and os.link"
)


def _gnu_tar_of(tmp_path: Path, files: dict[str, bytes], *args: str) -> Path:
    """GNU tar's archive of a tree where ``b`` is a hard link to ``a``, written with
    ``tar -cf out.tar -C tree <args>``."""
    assert _GNU_TAR is not None
    tree = tmp_path / "tree"
    (tree / "d").mkdir(parents=True)
    for name, data in files.items():
        (tree / name).write_bytes(data)
    os.link(tree / "d" / "a", tree / "d" / "b")
    out = tmp_path / "out.tar"
    subprocess.run([_GNU_TAR, "-cf", str(out), "-C", str(tree), *args], check=True)
    return out


def _newc(*members: tuple[bytes, int, int, bytes]) -> bytes:
    """A newc CPIO of (name, mode, inode, data) members, each inode with two names,
    then the trailer."""
    out = bytearray()
    for name, mode, ino, data in (*members, (b"TRAILER!!!", 0, 0, b"")):
        stored = name + b"\0"
        nlink = 1 if ino == 0 else 2
        fields = (ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(stored), 0)
        header = b"070701" + b"".join(b"%08X" % value for value in fields)
        out += header + stored + bytes(-(len(header) + len(stored)) % 4)
        out += data + bytes(-len(data) % 4)
    return bytes(out)


def _tar(entries: list[tuple[str, str | None]]) -> bytes:
    """A tar of ``(name, linkname)`` entries: a file holding its own name when
    ``linkname`` is ``None``, a directory when the name ends in ``/``, else a hard
    link to ``linkname`` as given."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, linkname in entries:
            info = tarfile.TarInfo(name)
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif linkname is None:
                data = name.encode()
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                tf.addfile(info)
    return buf.getvalue()


def _links(source: io.BytesIO | Path) -> dict[str, tuple[MemberType, str | None]]:
    with open_archive(source) as reader:
        return {m.name: (m.type, m.link_target) for m in reader.members()}


@needs_gnu_tar
def test_the_same_tree_in_tar_and_cpio_lists_the_same_link_target(
    tmp_path: Path,
) -> None:
    """GNU tar run on ``.`` stores ``./d/b`` linking to ``./d/a``. A newc CPIO of the
    same tree, its names written as ``find .`` gives them, holds the data on the
    last name. Both list the link as ``d/b`` with the target ``d/a``: the ``name`` of
    the member it links to."""
    tar = _gnu_tar_of(tmp_path, {"d/a": b"data"}, "./d/a", "./d/b")
    with tarfile.open(tar) as tf:
        assert [(m.name, m.linkname) for m in tf] == [("./d/a", ""), ("./d/b", "./d/a")]
    cpio = _newc(
        (b"./d/b", 0o100644, 7, b""),
        (b"./d/a", 0o100644, 7, b"data"),
    )
    tar_links = _links(tar)
    cpio_links = _links(io.BytesIO(cpio))
    assert tar_links["d/b"] == cpio_links["d/b"] == (MemberType.HARDLINK, "d/a")
    with open_archive(tar) as reader:
        link = reader.get("d/b")
        assert link.link_target_member is reader.get("d/a")
        assert reader.read("d/b") == b"data"


@pytest.mark.parametrize(
    ("stored", "listed"),
    [
        ("./b", "b"),
        ("././b", "b"),
        ("d//./b", "d/b"),
        ("./d/../b", "d/../b"),
        ("/b", "/b"),
        ("b", "b"),
    ],
)
def test_a_tar_hard_link_target_lists_as_a_name(stored: str, listed: str) -> None:
    """``./b`` lists as ``b``; ``..`` and a leading ``/`` stay, as in a name."""
    links = _links(io.BytesIO(_tar([(stored, None), ("hl", stored)])))
    assert links["hl"] == (MemberType.HARDLINK, listed)
    assert listed in links


def test_a_symlink_target_stays_as_stored() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("sl")
        info.type = tarfile.SYMTYPE
        info.linkname = ".//b/"
        tf.addfile(info)
    assert _links(io.BytesIO(buf.getvalue()))["sl"] == (MemberType.SYMLINK, ".//b/")


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("./b", "b"),
        ("b/", "b/"),
        ("./b//", "b/"),
        ("b/.", "b"),
        ("./", "."),
        ("a\\b", "a\\b"),
    ],
)
def test_normalize_hardlink_target(target: str, expected: str) -> None:
    assert normalize_hardlink_target(target) == expected


def test_a_trailing_slash_target_looks_up_only_a_directory() -> None:
    target = resolve_link_target_name("hl", "b/", MemberType.HARDLINK)
    assert target == "b/"
    assert link_target_name_keys(target) == ("b/",)
    assert resolve_link_target_name("hl", "b", MemberType.HARDLINK) == "b"


@_MODES
def test_a_hard_link_target_ending_in_slash_does_not_resolve_to_a_file(
    tmp_path: Path, streaming: bool
) -> None:
    data = _tar([("b", None), ("hl", "./b/")])
    with open_archive(io.BytesIO(data)) as reader:
        link = reader.get("hl")
        assert link.link_target == "b/"
        assert link.link_target_member is None
        with pytest.raises(LinkTargetNotFoundError):
            reader.read("hl")
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
    results = {r.member.name: r for r in report.results}
    assert results["b"].status is ExtractionStatus.EXTRACTED
    assert results["hl"].status is ExtractionStatus.FAILED
    assert isinstance(results["hl"].error, LinkTargetNotFoundError)
    assert not os.path.lexists(tmp_path / "out" / "hl")


def test_a_hard_link_target_ending_in_slash_names_a_directory() -> None:
    with open_archive(io.BytesIO(_tar([("d/", None), ("hl", "./d/")]))) as reader:
        link = reader.get("hl")
        assert link.link_target == "d/"
        assert link.link_target_member is reader.get("d/")


@needs_gnu_tar
@_MODES
def test_gnu_tar_hard_links_of_dot_extract(tmp_path: Path, streaming: bool) -> None:
    """``tar -cf out.tar -C tree .``: every name and target starts with ``./``.
    Which of the two names is the link follows the directory's order."""
    tar = _gnu_tar_of(tmp_path, {"d/a": b"data"}, ".")
    links = _links(tar)
    link, source = (
        ("d/b", "d/a") if links["d/b"][0] is MemberType.HARDLINK else ("d/a", "d/b")
    )
    assert links[link] == (MemberType.HARDLINK, source)
    assert links[source] == (MemberType.FILE, None)
    dest = tmp_path / "x"
    with open_archive(io.BytesIO(tar.read_bytes()), streaming=streaming) as reader:
        report = reader.extract_all(dest)
    assert {r.status for r in report.results} == {ExtractionStatus.EXTRACTED}
    assert (dest / "d" / "b").read_bytes() == b"data"
    assert os.path.samefile(dest / "d" / "a", dest / "d" / "b")


@needs_gnu_tar
@_MODES
def test_gnu_tar_links_to_the_name_it_archived_first(
    tmp_path: Path, streaming: bool
) -> None:
    """Named in the other order, GNU tar stores ``./d/b`` as the file and ``./d/a``
    as the link to it."""
    tar = _gnu_tar_of(tmp_path, {"d/a": b"data"}, "./d/b", "./d/a")
    links = _links(tar)
    assert links["d/b"] == (MemberType.FILE, None)
    assert links["d/a"] == (MemberType.HARDLINK, "d/b")
    dest = tmp_path / "x"
    with open_archive(io.BytesIO(tar.read_bytes()), streaming=streaming) as reader:
        reader.extract_all(dest)
    assert os.path.samefile(dest / "d" / "a", dest / "d" / "b")


@needs_gnu_tar
@_MODES
def test_a_gnu_tar_link_keeps_the_source_before_it_when_the_source_is_appended(
    tmp_path: Path, streaming: bool
) -> None:
    """``tar -rf`` appends a new ``./d/a`` after the link to the old one. The link
    lists its target as ``d/a`` and takes the bytes of the ``d/a`` before it."""
    assert _GNU_TAR is not None
    tar = _gnu_tar_of(tmp_path, {"d/a": b"old"}, "./d/a", "./d/b")
    newer = tmp_path / "newer"
    (newer / "d").mkdir(parents=True)
    (newer / "d" / "a").write_bytes(b"newer")
    subprocess.run([_GNU_TAR, "-rf", str(tar), "-C", str(newer), "./d/a"], check=True)
    with open_archive(tar) as reader:
        members = reader.members()
        assert [(m.name, m.link_target) for m in members] == [
            ("d/a", None),
            ("d/b", "d/a"),
            ("d/a", None),
        ]
        assert members[1].link_target_member is members[0]
        assert reader.read(members[1]) == b"old"
    dest = tmp_path / "x"
    with open_archive(io.BytesIO(tar.read_bytes()), streaming=streaming) as reader:
        reader.extract_all(dest)
    assert (dest / "d" / "b").read_bytes() == b"old"
    assert (dest / "d" / "a").read_bytes() == b"newer"


@_MODES
def test_a_dot_slash_link_before_its_source_still_fails(
    tmp_path: Path, streaming: bool
) -> None:
    data = _tar([("hl", "./a"), ("a", None)])
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
    results = {r.member.name: r for r in report.results}
    assert results["hl"].member.link_target == "a"
    assert results["hl"].status is ExtractionStatus.FAILED
    assert isinstance(results["hl"].error, LinkTargetNotFoundError)
    assert results["a"].status is ExtractionStatus.EXTRACTED
