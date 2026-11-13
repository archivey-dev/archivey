"""``archivey.fsspec.ArchiveyFileSystem``, the ``archivey://`` protocol (``fsspec-integration``).

The tree is the extraction view of the member names (design D3, DR-23a): these tests
check it against what ``extract_all`` writes, and the file system's lifetime, pickling,
links, errors and the consumers that motivate it.
"""

from __future__ import annotations

import gc
import io
import os
import pickle
import subprocess
import sys
import tarfile
import threading
import time
import warnings
import weakref
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from archivey import (  # noqa: E402
    ArchiveyConfig,
    ArchiveyUsageError,
    Budget,
    DiagnosticCode,
    ExtractionPolicy,
    open_archive,
)
from archivey.fsspec import ArchiveyFileSystem  # noqa: E402
from tests.conftest import case_sensitive  # noqa: E402
from tests.memory_util import traced_peak  # noqa: E402


@pytest.fixture
def memfs() -> Iterator[Any]:
    fs = fsspec.filesystem("memory")
    yield fs
    fs.store.clear()
    fs.pseudo_dirs.clear()
    fs.pseudo_dirs.append("")


def _zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
        warnings.simplefilter("ignore", UserWarning)  # "Duplicate name", on purpose
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(
    files: dict[str, bytes], symlinks: dict[str, str] | None = None
) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


HOSTILE_ZIP = [
    ("a/b", b"first"),
    ("a/../../x", b"escape"),
    ("/etc/y", b"absolute"),
    ("a/b", b"second"),
    ("c.txt", b"plain"),
]


@pytest.fixture
def hostile(memfs: Any) -> str:
    memfs.pipe("/d/hostile.zip", _zip_bytes(HOSTILE_ZIP))
    return "memory://d/hostile.zip"


def test_entry_point_registers_the_protocol() -> None:
    assert fsspec.get_filesystem_class("archivey") is ArchiveyFileSystem


def test_strict_tree_shows_current_entries_and_reports_refusals(hostile: str) -> None:
    with ArchiveyFileSystem(hostile) as fs:
        assert fs.find("", withdirs=True) == ["a", "a/b", "c.txt"]
        assert fs.cat("a/b") == b"second"
        refused = [
            d
            for d in fs.reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_PATH_REFUSED
        ]
        assert sorted(d.context.member_name for d in refused) == [
            "/etc/y",
            "a/../../x",
        ]
        assert {d.context.policy for d in refused} == {"strict"}


def test_a_chained_url_takes_its_options_by_protocol_name(
    hostile: str, caplog: pytest.LogCaptureFixture
) -> None:
    """``fsspec.open`` (and pandas' ``storage_options``) hand each layer of a chained
    URL the options under its protocol name: a policy and a config reach the file
    system, and a refusal reaches ``on_diagnostic`` and the log."""
    seen: list[DiagnosticCode] = []
    config = ArchiveyConfig(on_diagnostic=lambda d: seen.append(d.code))
    with fsspec.open(
        f"archivey://etc/y::{hostile}",
        archivey={"policy": "standard", "config": config},
    ) as f:
        assert f.read() == b"absolute"  # rerooted under STANDARD, refused under STRICT
    assert DiagnosticCode.MEMBER_PATH_REFUSED in seen
    assert "'a/../../x' is not in the archivey:// tree" in caplog.text


def test_standard_tree_reroots_absolute_names(hostile: str) -> None:
    with ArchiveyFileSystem(hostile, policy="standard") as fs:
        assert fs.find("") == ["a/b", "c.txt", "etc/y"]
        assert fs.cat("etc/y") == b"absolute"


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_tree_matches_what_extract_all_writes(
    memfs: Any, tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """DR-23a: the tree and extraction share their name code, so they agree."""
    data = _zip_bytes(
        [
            ("/abs/one", b"1"),
            ("dir/CON.txt", b"reserved"),
            ("dir/ok:name", b"colon"),
            ("x/./y", b"dot"),
            ("x\\back", b"backslash"),
            ("plain", b"p"),
        ]
    )
    memfs.pipe("/d/names.zip", data)
    with ArchiveyFileSystem("memory://d/names.zip", policy=policy) as fs:
        tree = {p: fs.cat(p) for p in fs.find("")}
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(dest, policy=policy, on_error="continue", on_blocked="skip")
    written = {
        p.relative_to(dest).as_posix(): p.read_bytes()
        for p in dest.rglob("*")
        if p.is_file()
    }
    if os.name == "nt" and policy is ExtractionPolicy.TRUSTED:
        # TRUSTED keeps names Windows treats otherwise: a colon names a stream of the
        # file, and a reserved name or a backslash depends on the Windows version.
        # What becomes of them depends on the destination, which the tree does not
        # model, so each is left out of both sides.
        assert tree.pop("dir/ok:name") == b"colon"
        for name in ("dir/CON.txt", "x\\back", "x/back"):
            tree.pop(name, None)
            written.pop(name, None)
    assert tree == written


def _tar_entries(entries: list[tuple[str, str, bytes | str]]) -> bytes:
    """A TAR of ``(kind, name, data or link target)`` entries, in order."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for kind, name, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert isinstance(payload, bytes)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
                continue
            assert isinstance(payload, str)
            info.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE}.get(
                kind, tarfile.LNKTYPE
            )
            info.linkname = payload
            if kind == "dir":
                # TarInfo's default 0o644 leaves a directory unsearchable to anyone
                # but root once extraction applies the mode.
                info.mode = 0o755
            tf.addfile(info)
    return buf.getvalue()


# Every case where extraction decides from the members before one, or from a link.
LINKS_AND_COLLISIONS = [
    ("file", "A.txt", b"upper"),
    ("file", "a.txt", b"lower"),  # collides with A.txt under STRICT and STANDARD
    ("file", "x", b"plain"),
    ("file", "/x", b"abs"),  # its re-root collides with x
    ("file", "f", b"plain f"),
    ("file", "f.", b"dot"),  # its portable spelling collides with f
    ("file", "dup", b"first"),
    ("file", "dup", b"second"),  # the current entry wins
    ("file", "/etc/y", b"SECRET"),
    ("hard", "h", "/etc/y"),  # a hard link to a member STRICT refuses
    ("sym", "s", "/etc/y"),  # a symlink with an absolute target
    ("sym", "ok", "x"),
    ("dir", "d", ""),
    ("sym", "dl", "d"),  # a symlink to a directory
    ("file", "p", b"file p"),
    ("file", "p/q", b"under a file"),
    # Paths through the archive's own symlinks, written where the link leads.
    ("file", "dl/y", b"through dl"),  # written as d/y
    ("dir", "dl/sub", ""),  # d/sub
    ("file", "dl/new/z", b"new dir"),  # d/new/z: a directory made through the link
    ("sym", "chain", "dl"),
    ("file", "chain/w", b"two links"),  # d/w
    ("dir", "s2", ""),
    ("sym", "s2/up", "../d"),
    ("file", "s2/up/v", b"up and over"),  # d/v
    ("file", "d/y", b"collides"),  # d/y was written through dl
    ("sym", "dead", "nothere"),
    ("file", "dead/u", b"dangling"),  # refused: the link leads to no directory
    ("sym", "tofile", "x"),
    ("file", "tofile/u", b"under a file"),  # refused
    ("sym", "loop1", "loop2"),
    ("sym", "loop2", "loop1"),  # refused: a loop
    ("sym", "dot", "."),
    ("sym", "s2/out", "../dot/.."),  # refused: leaves through a link
    ("sym", "m/n/self", "self"),  # refused: a loop; its parents m and m/n stay
    # Hard links extraction does not make: no source, a later one, a directory.
    ("hard", "hmissing", "nothere"),
    ("hard", "hforward", "later"),
    ("file", "later", b"after its link"),
    ("hard", "hdir", "d"),
    ("hard", "hsym", "ok"),  # a hard link to a symlink is written as that symlink
    # Case: directories and link targets are exact names, as on a case-sensitive
    # disk; only files and links collide by the policy's key.
    ("file", "c", b"lower c"),
    ("dir", "C", ""),  # written beside c
    ("sym", "Q", "q"),  # dangling, not a loop through itself
    ("hard", "hc", "c"),
    ("file", "HC", b"collides"),  # refused under STRICT and STANDARD: hc has its key
    # A hard link extraction makes in its second pass keeps its name from a later
    # member: k is made from r's bytes, and K, after it, collides with it.
    ("file", "R", b"first R"),
    ("file", "r", b"lost r"),  # not written under STRICT and STANDARD: R has its key
    ("hard", "k", "r"),  # its source is not on disk: made in the second pass
    ("file", "K", b"later K"),  # refused under STRICT and STANDARD: k has its key
    # A symlink reads what its target text leads to among the written paths, not the
    # member stored under that name.
    ("sym", "told", "d/y"),  # "through dl": the stored d/y lost its name to dl/y
    ("sym", "viachain", "dl/w"),  # "two links": no member is named dl/w
    ("sym", "toa", "a.txt"),  # dangling under STRICT and STANDARD: a.txt lost
    ("sym", "tof", "f."),  # dangling under STRICT, which writes f. as f
    ("sym", "toetc", "etc/y"),  # "SECRET" where /etc/y is re-rooted
]


def _written(dest: Path) -> dict[str, tuple[Any, ...]]:
    out: dict[str, tuple[Any, ...]] = {}
    for path in dest.rglob("*"):
        rel = path.relative_to(dest).as_posix()
        if path.is_symlink():
            # What the link reads on disk: the bytes of the file it leads to, or
            # nothing for a directory, a dangling link or a loop.
            out[rel] = ("link", path.read_bytes() if path.is_file() else None)
        elif path.is_dir():
            out[rel] = ("dir",)
        else:
            out[rel] = ("file", path.read_bytes())
    return out


def _listed(fs: ArchiveyFileSystem) -> dict[str, tuple[Any, ...]]:
    out: dict[str, tuple[Any, ...]] = {}
    for path, info in fs.find("", withdirs=True, detail=True).items():
        # Written as a symlink: a symlink, or a hard link to one. A hard link that
        # stays one has a file as its source, so a hard link that is not a file, or
        # whose destination is not its source's name, is a symlink's second name.
        if info.get("islink") and (
            info["member"].type.value == "symlink"
            or info["type"] != "file"
            or info["destination"] != info["member"].link_target
        ):
            out[path] = ("link", fs.cat(path) if info["type"] == "file" else None)
        elif info["type"] == "directory":
            out[path] = ("dir",)
        else:
            out[path] = ("file", fs.cat(path))
    return out


def _tree_paths(fs: ArchiveyFileSystem) -> set[str]:
    """Every path in the file system's tree, each one ``info`` answers by its exact
    name: a node's path is its parents' components."""
    out: set[str] = set()
    stack = [("", fs._get_tree().root)]
    while stack:
        prefix, node = stack.pop()
        for part, child in (node.children or {}).items():
            out.add(prefix + part)
            stack.append((f"{prefix}{part}/", child))
    return out


def test_a_hard_link_to_a_symlink_reads_its_target_from_its_own_directory(
    memfs: Any, tmp_path: Path
) -> None:
    """Extraction writes ``x`` as a symlink with ``d/l``'s target text, ``t``, which
    then leads to the root ``t`` from ``x``'s directory, not to ``d/t``."""
    data = _tar_entries(
        [
            ("file", "t", b"root t"),
            ("dir", "d", ""),
            ("file", "d/t", b"d t"),
            ("sym", "d/l", "t"),
            ("hard", "x", "d/l"),
        ]
    )
    memfs.pipe("/d/hs.tar", data)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(dest)
    if (dest / "x").is_symlink():
        assert (dest / "x").read_bytes() == b"root t"
    with ArchiveyFileSystem("memory://d/hs.tar") as fs:
        assert fs.cat("x") == b"root t"
        assert fs.cat("d/l") == b"d t"
        assert fs.info("x")["destination"] == "t"


# Symlinks whose target text names a member the policy wrote elsewhere, or not at
# all: on disk the target resolves among the written paths, not the stored names.
_SYMLINKS_BY_WRITTEN_PATH = {
    "loser through a link": (
        [
            ("dir", "d", ""),
            ("file", "d/y", b"A"),
            ("sym", "l", "d"),
            ("file", "l/y", b"B"),  # written as d/y: loses to the d/y before it
            ("sym", "s", "l/y"),
        ],
        ExtractionPolicy.STRICT,
    ),
    "renamed loser": (
        [("file", "data", b"Y"), ("file", "data.", b"X"), ("sym", "s", "data.")],
        ExtractionPolicy.STRICT,
    ),
    "case loser": (
        [("file", "README", b"A"), ("file", "readme", b"B"), ("sym", "s", "readme")],
        ExtractionPolicy.STRICT,
    ),
    "renamed target": (
        [("file", "data.", b"A"), ("sym", "s", "data.")],
        ExtractionPolicy.STRICT,
    ),
    "target named as written": (
        [("file", "data.", b"A"), ("sym", "s", "data")],
        ExtractionPolicy.STRICT,
    ),
    "target through a link": (
        [
            ("dir", "d", ""),
            ("file", "d/f", b"A"),
            ("sym", "l", "d"),
            ("sym", "s", "l/f"),
        ],
        ExtractionPolicy.STRICT,
    ),
    "re-rooted target": (
        [("file", "/abs/f", b"A"), ("sym", "s", "abs/f")],
        ExtractionPolicy.STANDARD,
    ),
    "hard link to a symlink, case loser": (
        [
            ("file", "README", b"A"),
            ("file", "readme", b"B"),
            ("sym", "s", "readme"),
            ("hard", "h", "s"),
        ],
        ExtractionPolicy.STRICT,
    ),
}


@pytest.mark.skipif(os.name == "nt", reason="a Windows disk trims a trailing dot")
@pytest.mark.parametrize("shape", list(_SYMLINKS_BY_WRITTEN_PATH))
def test_a_symlink_reads_what_its_target_reaches_on_disk(
    memfs: Any, tmp_path: Path, shape: str
) -> None:
    entries, policy = _SYMLINKS_BY_WRITTEN_PATH[shape]
    if "case" in shape and not case_sensitive(tmp_path):
        pytest.skip("a disk that folds case reaches the winner under another case")
    data = _tar_entries(entries)
    memfs.pipe("/d/sl.tar", data)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(dest, policy=policy, on_error="continue", on_blocked="skip")
    links = [p.name for p in dest.iterdir() if p.is_symlink()]
    assert links
    with ArchiveyFileSystem("memory://d/sl.tar", policy=policy) as fs:
        for name in links:
            if (dest / name).is_dir():
                assert fs.info(name)["type"] == "directory"
            elif (dest / name).exists():
                assert fs.info(name)["type"] == "file"
                assert fs.cat(name) == (dest / name).read_bytes()
            else:
                assert fs.info(name)["type"] == "other"
                with pytest.raises(FileNotFoundError):
                    fs.cat(name)


def test_a_symlink_to_a_directory_lists_and_reads_through(memfs: Any) -> None:
    data = _tar_entries(
        [
            ("dir", "d", ""),
            ("file", "d/f", b"A"),
            ("sym", "d/up", ".."),  # back to the root: listed, not walked into
            ("sym", "s", "d"),
        ]
    )
    memfs.pipe("/d/sd.tar", data)
    with ArchiveyFileSystem("memory://d/sd.tar") as fs:
        assert fs.isdir("s")
        assert fs.ls("s", detail=False) == ["s/f", "s/up"]
        assert fs.cat("s/f") == b"A"
        assert fs.info("s/f")["name"] == "s/f"
        assert fs.info("s/up")["islink"]
        assert fs.cat("s/up/d/f") == b"A"
        assert sorted(fs.find("", withdirs=True)) == ["d", "d/f", "d/up", "s"]


def test_a_symlink_to_the_root_is_a_directory(memfs: Any, tmp_path: Path) -> None:
    data = _tar_entries(
        [
            ("file", "f", b"A"),
            ("sym", "s", "."),
            ("dir", "d", ""),
            ("sym", "d/up", ".."),
        ]
    )
    memfs.pipe("/d/sr.tar", data)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(dest)
    with ArchiveyFileSystem("memory://d/sr.tar") as fs:
        for link in ("s", "d/up"):
            assert (dest / link).is_dir()
            assert fs.info(link)["type"] == "directory"
            listed = sorted(
                name.rpartition("/")[2] for name in fs.ls(link, detail=False)
            )
            assert listed == sorted(os.listdir(dest / link))
            assert fs.cat(f"{link}/f") == b"A"


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_tree_matches_extraction_on_links_and_collisions(
    memfs: Any, tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """Red with any of these rules removed: the collision key (the plain name in its
    place), the hard-link source check, the symlink target check, the refusal of a
    path under a file, or following the archive's own links (a link treated as a
    file, or its loop and way-out checks)."""
    data = _tar_entries(LINKS_AND_COLLISIONS)
    memfs.pipe("/d/lc.tar", data)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(dest, policy=policy, on_error="continue", on_blocked="skip")
    with ArchiveyFileSystem("memory://d/lc.tar", policy=policy) as fs:
        written = _written(dest)
        listed = _listed(fs)
        cached = _tree_paths(fs)
        folded: list[str] = []
        if not case_sensitive(tmp_path):
            # A disk that folds case (Windows, macOS) cannot hold these beside the
            # member before them: the directory C beside the file c under every
            # policy, and under TRUSTED, which keys on the exact name, the files
            # too. Q -> q names itself there, a loop extraction refuses, and a link
            # to a lost name reaches the winner. The tree does not model the disk.
            folded += ["C", "Q", "toa"]
            if policy is ExtractionPolicy.TRUSTED:
                folded += ["a.txt", "HC", "r", "k"]
        if os.name == "nt":
            # Windows also trims a trailing dot.
            folded.append("tof")
            if policy is ExtractionPolicy.TRUSTED:
                folded.append("f.")
        for name in folded:
            assert name in listed
            del listed[name]
            cached.discard(name)
            written.pop(name, None)
        if os.name == "nt":
            # Windows collapses ``..`` before following links, so ``../dot/..`` from
            # s2 names the destination itself and extraction keeps the link. The
            # tree follows links as POSIX does and refuses it.
            assert "s2/out" not in listed
            written.pop("s2/out", None)
        assert listed == written
        # Every path ``info`` answers, not only those ``find`` walks to: ``find``
        # does not descend into a file, so it alone misses ``p/q``.
        assert cached == set(written)


def test_a_name_nested_far_past_the_recursion_limit_is_listed(memfs: Any) -> None:
    name = "a/" * 1200 + "f"
    memfs.pipe("/d/deep.tar", _tar_entries([("file", name, b"deep")]))
    with ArchiveyFileSystem("memory://d/deep.tar") as fs:
        assert fs.info(name)["size"] == 4
        assert fs.cat(name) == b"deep"
        assert fs.ls("a/a", detail=False) == ["a/a/a"]
        assert fs.find("") == [name]
        assert fs.du("") == 4


def test_the_tree_grows_with_the_names_not_with_their_depth() -> None:
    """The tree holds one node per component, never a path string per directory, so
    a name 8000 components deep in a 20 KB TAR costs memory in proportion to its
    length: 132 MB with a full path for every ancestor (S48-K4)."""
    data = _tar_entries([("file", "a/" * 8000 + "f", b"deep")])
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        fs.reader.members()  # the reader's own listing is not the tree's
        peak = traced_peak(lambda: fs.ls(""))
        start = time.perf_counter()
        assert fs.find("") == ["a/" * 8000 + "f"]
        elapsed = time.perf_counter() - start
    # Measured: under 6 MB, and under 0.05 s for the walk, which lists each
    # directory from its node, not from its path.
    assert peak < 32 * 2**20
    assert elapsed < 2.0


def test_a_target_longer_than_a_symlink_can_hold_is_refused_unwalked() -> None:
    """A target over 4096 bytes is refused before it is walked, as ``symlink()``
    refuses it once extraction has made the parents: a target of 60 000 ``./``
    components took 8 s to list, and was listed (S48-K5)."""
    data = _tar_entries(
        [("dir", "d", ""), ("sym", "p/s", "./" * 60_000 + "d"), ("sym", "t", "d")]
    )
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        fs.reader.members()
        start = time.perf_counter()
        assert fs.find("", withdirs=True) == ["d", "p", "t"]
        elapsed = time.perf_counter() - start
        (refusal,) = [
            d
            for d in fs.reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_PATH_REFUSED
        ]
        assert refusal.context.member_name == "p/s"
        assert "longer than 4096 bytes" in refusal.context.reason
    # Measured: under 0.01 s. The bound is loose for slow CI runners.
    assert elapsed < 2.0


def test_a_target_of_4096_bytes_resolves() -> None:
    target = "./" * 2047 + "d"  # 4095 bytes, as long as Linux writes
    data = _tar_entries([("dir", "d", ""), ("sym", "s", target), ("file", "d/f", b"F")])
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        assert fs.info("s")["type"] == "directory"
        assert fs.cat("s/f") == b"F"


@pytest.mark.parametrize("end", ["nope", "f"], ids=["missing", "file"])
def test_a_link_whose_walk_ends_on_no_directory_is_walked_once(end: str) -> None:
    """A walk that ends on a missing name or on a file, or is refused, is held until
    a member makes a name it found missing. Here 2000 names and 2000 links go
    through a chain of 20 links, each 2400 components long (``d/..`` cannot be
    skipped unwalked: ``d`` could be a link), which ends on ``end``."""
    entries: list[tuple[str, str, bytes | str]] = [
        ("dir", "d", ""),
        ("file", "f", b"F"),
    ]
    entries += [("sym", f"l{n}", "d/../" * 800 + f"l{n + 1}") for n in range(19)]
    entries.append(("sym", "l19", "d/../" * 800 + end))
    entries += [("file", f"l0/{n}", b"") for n in range(2000)]
    entries += [("sym", f"x{n}", "l0") for n in range(2000)]
    data = _tar_entries(entries)
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        fs.reader.members()
        start = time.perf_counter()
        assert fs.info("x1999")["type"] == ("file" if end == "f" else "other")
        elapsed = time.perf_counter() - start
        assert not fs.exists("l0/0")
    # Measured: under 0.3 s, and 4.4 s to 12.7 s with every walk done again.
    assert elapsed < 2.0


@pytest.mark.parametrize(
    "entries",
    [
        # A's check holds K's walk, which finds p missing; p/z then makes p.
        [("sym", "K", "p"), ("sym", "A", "K/z"), ("file", "p/z", b"Z")],
        # J's held walk follows K's: making p drops both.
        [
            ("sym", "K", "p"),
            ("sym", "J", "K"),
            ("sym", "A", "J/z"),
            ("file", "p/z", b"Z"),
        ],
        # K/a is refused while p is missing; K/b is written once p/z made p.
        [("sym", "K", "p"), ("file", "K/a", b""), ("file", "p/z", b"Z")],
    ],
    ids=["made-later", "through-a-held-link", "names-under-it"],
)
def test_a_held_walk_is_dropped_when_its_missing_name_is_made(
    entries: list[tuple[str, str, bytes | str]],
) -> None:
    data = _tar_entries([*entries, ("sym", "M", "K/z"), ("file", "K/b", b"B")])
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        assert fs.cat("M") == b"Z"
        assert fs.cat("p/b") == b"B"
        if any(name == "A" for _, name, _ in entries):
            assert fs.cat("A") == b"Z"


def test_a_link_that_many_paths_go_through_is_walked_once() -> None:
    """A link's walk is kept once it met no missing component: 2000 names under a
    link to a directory 400 deep, and 2000 links through it, took 5 s to list when
    each walked the target again.

    400 deep, not deeper: the strict check resolves the link's target as a path,
    and on macOS (``PATH_MAX`` 1024) a longer one cannot be looked up, so
    extraction there refuses the link."""
    deep = "d/" * 400
    entries: list[tuple[str, str, bytes | str]] = [
        ("dir", deep, ""),
        ("sym", "l", deep),
    ]
    entries += [("file", f"l/{n}", b"%d" % n) for n in range(2000)]
    entries += [("sym", f"x{n}", "l") for n in range(2000)]
    data = _tar_entries(entries)
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        fs.reader.members()
        start = time.perf_counter()
        assert fs.info("x1999")["type"] == "directory"
        elapsed = time.perf_counter() - start
        assert fs.cat("x7/7") == b"7"
        assert fs.cat(deep + "1999") == b"1999"
    # Measured: under 0.15 s.
    assert elapsed < 2.0


def test_a_walk_kept_for_a_refused_link_is_dropped() -> None:
    """``p/n`` is refused (``d/L`` leads it out), and the directory ``p`` made for it
    is removed. Its target went through ``K -> p``, which then reached that ``p``:
    a walk kept from there would make ``M -> K/z`` miss the ``p`` made later."""
    data = _tar_entries(
        [
            ("dir", "d", ""),
            ("sym", "d/L", ".."),
            ("sym", "K", "p"),
            ("sym", "p/n", "../K/../d/L/.."),
            ("file", "p/z", b"Z"),
            ("sym", "M", "K/z"),
        ]
    )
    with ArchiveyFileSystem(io.BytesIO(data)) as fs:
        assert fs.find("", withdirs=True) == ["K", "M", "d", "d/L", "p", "p/z"]
        assert fs.cat("M") == b"Z"


def test_a_closed_file_system_lists_nothing(hostile: str) -> None:
    """``close`` drops the tree, so a listing made before it is not served after it
    (S48-K6): ``ls`` and ``info`` raise as they do when nothing listed first."""
    fs = ArchiveyFileSystem(hostile)
    assert fs.ls("", detail=False)
    fs.close()
    with pytest.raises(ArchiveyUsageError):
        fs.ls("")
    with pytest.raises(ArchiveyUsageError):
        fs.info("c.txt")
    assert fs._tree is None


def test_walk_matches_fsspecs_own(memfs: Any) -> None:
    """The stack-based ``walk`` yields what fsspec's recursive one does."""
    from fsspec.spec import AbstractFileSystem

    names = {"a/b/c.txt": b"1", "a/d.txt": b"2", "e/f/g/h.txt": b"3", "i.txt": b"4"}
    memfs.pipe("/d/w.tar", _tar_bytes(names))
    with ArchiveyFileSystem("memory://d/w.tar") as fs:
        for kwargs in (
            {},
            {"maxdepth": 1},
            {"maxdepth": 2},
            {"topdown": False},
            {"topdown": False, "maxdepth": 2},
            {"detail": True},
        ):
            ours = list(fs.walk("", **kwargs))
            theirs = list(AbstractFileSystem.walk(fs, "", **kwargs))
            assert ours == theirs, kwargs
        assert list(fs.walk("a")) == list(AbstractFileSystem.walk(fs, "a"))
        # ``ls`` lists one directory's entries, sorted, each as ``info`` gives it.
        for path, expected in (
            ("", ["a", "e", "i.txt"]),
            ("a", ["a/b", "a/d.txt"]),
            ("a/", ["a/b", "a/d.txt"]),
            ("a/b", ["a/b/c.txt"]),
            ("e/f", ["e/f/g"]),
        ):
            assert fs.ls(path, detail=False) == expected
            assert fs.ls(path, detail=True) == [fs.info(name) for name in expected]
        # A file lists as itself, as current fsspec's ``ls`` does; the oldest
        # fsspec CI installs lists nothing, so this is not compared with it.
        for path in ("a/b/c.txt", "i.txt"):
            assert fs.ls(path) == [fs.info(path)]
            assert fs.ls(path, detail=False) == [path]
        with pytest.raises(FileNotFoundError):
            fs.ls("missing")


def test_info_carries_size_mtime_and_member(memfs: Any) -> None:
    memfs.pipe("/d/t.tar", _tar_bytes({"f.txt": b"hello"}))
    with ArchiveyFileSystem("memory://d/t.tar") as fs:
        info = fs.info("f.txt")
        assert info["type"] == "file"
        assert info["size"] == 5
        assert info["mtime"] == 1_700_000_000
        assert info["member"].name == "f.txt"
        assert fs.info("")["type"] == "directory"


def test_links_open_their_target_and_unresolved_ones_are_other(memfs: Any) -> None:
    memfs.pipe(
        "/d/l.tar",
        _tar_bytes({"a/f.txt": b"data"}, symlinks={"link": "a/f.txt", "dead": "nope"}),
    )
    with ArchiveyFileSystem("memory://d/l.tar") as fs:
        link = fs.info("link")
        assert link["type"] == "file"
        assert link["islink"] is True
        assert link["destination"] == "a/f.txt"
        assert fs.cat("link") == b"data"
        assert fs.info("dead")["type"] == "other"
        with pytest.raises(FileNotFoundError):
            fs.open("dead")


def test_errors(hostile: str) -> None:
    with ArchiveyFileSystem(hostile) as fs:
        with pytest.raises(FileNotFoundError):
            fs.open("missing")
        with pytest.raises(FileNotFoundError):
            fs.info("a/../../x")
        with pytest.raises(IsADirectoryError):
            fs.open("a")
        with pytest.raises(NotImplementedError):
            fs.open("c.txt", "wb")
        for write in (
            lambda: fs.rm("c.txt"),
            lambda: fs.mkdir("n"),
            lambda: fs.pipe_file("n", b"x"),
            lambda: fs.touch("n"),
            lambda: fs.mv("c.txt", "d"),
        ):
            with pytest.raises(NotImplementedError):
                write()


def test_text_mode_reads_through_rb(hostile: str) -> None:
    with fsspec.open("archivey://c.txt::" + hostile, "r") as f:
        assert f.read() == "plain"


def test_bad_policy_is_a_usage_error(hostile: str) -> None:
    with pytest.raises(ArchiveyUsageError):
        ArchiveyFileSystem(hostile, policy="lenient")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]


def test_seekable_member_stream(memfs: Any) -> None:
    payload = bytes(range(256)) * 400
    memfs.pipe("/d/s.zip", _zip_bytes([("p.bin", payload)]))
    with ArchiveyFileSystem("memory://d/s.zip") as fs, fs.open("p.bin") as f:
        f.seek(-10, io.SEEK_END)
        assert f.read() == payload[-10:]
        f.seek(5)
        assert f.read(5) == payload[5:10]


def test_pickles_as_its_arguments(hostile: str) -> None:
    fs = ArchiveyFileSystem(hostile, policy="standard")
    clone = pickle.loads(pickle.dumps(fs))
    try:
        assert clone.reader is not fs.reader
        assert clone.policy is ExtractionPolicy.STANDARD
        assert clone.find("") == fs.find("")
    finally:
        fs.close()
        clone.close()


def test_pickles_an_open_file_fo(hostile: str) -> None:
    fs = ArchiveyFileSystem(fsspec.open(hostile))
    clone = pickle.loads(pickle.dumps(fs))
    try:
        assert clone.cat("c.txt") == b"plain"
    finally:
        fs.close()
        clone.close()


def test_a_file_object_fo_refuses_to_pickle() -> None:
    fs = ArchiveyFileSystem(io.BytesIO(_zip_bytes([("c.txt", b"x")])))
    try:
        with pytest.raises(TypeError, match="file object"):
            pickle.dumps(fs)
    finally:
        fs.close()


def test_close_closes_the_reader(hostile: str) -> None:
    fs = ArchiveyFileSystem(hostile)
    fs.close()
    with pytest.raises(ArchiveyUsageError):
        fs.reader.members()
    fs.close()  # a second close does nothing


def test_dropped_urls_leave_no_reader_open(memfs: Any) -> None:
    """``cachable = False`` and the finalizer: fsspec's instance cache would otherwise
    keep every reader for the life of the process (design D3, DR-9a)."""
    data = _zip_bytes([("m", b"x")])
    file_systems: list[weakref.ref[Any]] = []
    readers: list[Any] = []
    for n in range(1000):
        memfs.pipe(f"/many/a{n}.zip", data)
        of = fsspec.open(f"archivey://m::memory://many/a{n}.zip")
        with of as f:
            assert f.read() == b"x"
        file_systems.append(weakref.ref(of.fs))
        readers.append(of.fs.reader)
        del of, f
    # PyPy can need more than one collection to clear weak references and run
    # their callbacks.
    for _ in range(3):
        gc.collect()
    assert all(ref() is None for ref in file_systems)
    assert all(reader._closed for reader in readers)


def test_a_stream_keeps_its_file_system_alive(hostile: str) -> None:
    stream = fsspec.open("archivey://c.txt::" + hostile).open()
    gc.collect()
    try:
        assert stream.read() == b"plain"
    finally:
        stream.close()


def test_two_threads_read_two_members(memfs: Any) -> None:
    left, right = b"L" * 300_000, b"R" * 300_000
    memfs.pipe("/d/two.zip", _zip_bytes([("l", left), ("r", right)]))
    results: dict[str, bytes] = {}
    with ArchiveyFileSystem("memory://d/two.zip") as fs:
        barrier = threading.Barrier(2)

        def read(name: str) -> None:
            with fs.open(name) as f:
                barrier.wait()
                chunks = []
                while chunk := f.read(4096):
                    chunks.append(chunk)
                results[name] = b"".join(chunks)

        threads = [threading.Thread(target=read, args=(n,)) for n in ("l", "r")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert results == {"l": left, "r": right}


def test_nested_chain(memfs: Any) -> None:
    inner = _zip_bytes([("deep.txt", b"inside")])
    memfs.pipe("/d/outer.tar", _tar_bytes({"inner.zip": inner}))
    with fsspec.open(
        "archivey://deep.txt::archivey://inner.zip::memory://d/outer.tar"
    ) as f:
        assert f.read() == b"inside"


def test_pandas_reads_a_member(memfs: Any) -> None:
    pd = pytest.importorskip("pandas")
    memfs.pipe("/d/t.zip", _zip_bytes([("d/t.csv", b"x,y\n1,2\n3,4\n")]))
    frame = pd.read_csv("archivey://d/t.csv::memory://d/t.zip")
    assert frame.to_dict("list") == {"x": [1, 3], "y": [2, 4]}


def test_pyarrow_reads_parquet(memfs: Any) -> None:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    table = pa.table({"n": list(range(1000))})
    buf = io.BytesIO()
    pq.write_table(table, buf)
    memfs.pipe("/d/p.zip", _zip_bytes([("t.parquet", buf.getvalue())]))
    with ArchiveyFileSystem("memory://d/p.zip") as fs:
        assert pq.read_table("t.parquet", filesystem=fs).equals(table)


_WORKER = """
import pickle, sys
fs = pickle.loads(sys.stdin.buffer.read())
try:
    sys.stdout.buffer.write(fs.cat("w.txt"))
finally:
    fs.close()
"""


def test_another_process_reads_through_a_pickled_file_system(tmp_path: Path) -> None:
    """dask sends the file system to worker processes by pickling it (design D3)."""
    archive = tmp_path / "w.zip"
    archive.write_bytes(_zip_bytes([("w.txt", b"worker")]))
    with ArchiveyFileSystem(str(archive)) as fs:
        payload = pickle.dumps(fs)
    done = subprocess.run(
        [sys.executable, "-c", _WORKER],
        input=payload,
        capture_output=True,
        check=True,
        timeout=120,
    )
    assert done.stdout == b"worker"


def test_dask_bag_reads_members(tmp_path: Path) -> None:
    db = pytest.importorskip("dask.bag")
    archive = tmp_path / "t.zip"
    archive.write_bytes(_zip_bytes([("a.txt", b"1\n2\n"), ("b.txt", b"3\n")]))
    bag = db.read_text(f"archivey://*.txt::{archive.as_posix()}")
    assert sorted(bag.compute(scheduler="threads")) == ["1\n", "2\n", "3\n"]


_DASK_IN_PROCESSES = """
import multiprocessing, sys
from concurrent.futures import ProcessPoolExecutor

import dask.bag as db
import dask.dataframe as dd

outer, flat = sys.argv[1:]
# spawn starts each worker from nothing, so a task reaches it only pickled, as on a
# dask cluster.
with ProcessPoolExecutor(2, mp_context=multiprocessing.get_context("spawn")) as pool:
    bag = db.read_text(f"archivey://*.txt::archivey://inner.zip::{outer}")
    lines = sorted(bag.compute(scheduler="processes", pool=pool))
    assert lines == ["1\\n", "2\\n", "3\\n"], lines
    frame = dd.read_csv(f"archivey://p/*.csv::{flat}")
    assert frame.npartitions == 2, frame.npartitions
    total = frame["n"].sum().compute(scheduler="processes", pool=pool)
    assert total == 6, total
print("ok")
"""


def test_pandas_reads_through_a_nested_chain(memfs: Any) -> None:
    pd = pytest.importorskip("pandas")
    inner = _zip_bytes([("t.csv", b"x\n5\n6\n")])
    memfs.pipe("/d/outer.tar", _tar_bytes({"inner.zip": inner}))
    frame = pd.read_csv("archivey://t.csv::archivey://inner.zip::memory://d/outer.tar")
    assert frame["x"].tolist() == [5, 6]


def test_dask_worker_processes_read_through_the_file_system(tmp_path: Path) -> None:
    """dask's process scheduler pickles each task's file system into a worker.

    It runs in its own interpreter: the pool's resource tracker would otherwise stay a
    child of the test process for the rest of the session. ``memory://`` is per
    process, so the archives are local files.
    """
    pytest.importorskip("dask.bag")
    pytest.importorskip("dask.dataframe")
    outer = tmp_path / "outer.tar"
    inner = _zip_bytes([("a.txt", b"1\n2\n"), ("b.txt", b"3\n")])
    outer.write_bytes(_tar_bytes({"inner.zip": inner}))
    flat = tmp_path / "t.zip"
    flat.write_bytes(_zip_bytes([("p/a.csv", b"n\n1\n2\n"), ("p/b.csv", b"n\n3\n")]))
    done = subprocess.run(
        [sys.executable, "-c", _DASK_IN_PROCESSES, outer.as_posix(), flat.as_posix()],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


def test_a_budget_reaches_the_reader_and_refuses_pickling(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes([("a.txt", b"x" * 100)]))
    budget = Budget(max_decoded_bytes=1000)
    with ArchiveyFileSystem(str(path), budget=budget) as fs:
        assert fs.cat("a.txt") == b"x" * 100
        assert budget.decoded_bytes == 100
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(fs)
