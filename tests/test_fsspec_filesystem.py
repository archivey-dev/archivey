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
import warnings
import weakref
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from archivey import (  # noqa: E402
    ArchiveyUsageError,
    DiagnosticCode,
    ExtractionPolicy,
    open_archive,
)
from archivey.fsspec import ArchiveyFileSystem  # noqa: E402


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
        reader.extract_all(dest, policy=policy, on_error="continue")
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
]


def _written(dest: Path) -> dict[str, tuple[Any, ...]]:
    out: dict[str, tuple[Any, ...]] = {}
    for path in dest.rglob("*"):
        rel = path.relative_to(dest).as_posix()
        if path.is_symlink():
            out[rel] = ("link",)
        elif path.is_dir():
            out[rel] = ("dir",)
        else:
            out[rel] = ("file", path.read_bytes())
    return out


def _listed(fs: ArchiveyFileSystem) -> dict[str, tuple[Any, ...]]:
    out: dict[str, tuple[Any, ...]] = {}
    for path, info in fs.find("", withdirs=True, detail=True).items():
        if info.get("islink") and info["member"].type.value == "symlink":
            out[path] = ("link",)
        elif info["type"] == "directory":
            out[path] = ("dir",)
        else:
            out[path] = ("file", fs.cat(path))
    return out


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
        reader.extract_all(dest, policy=policy, on_error="continue")
    with ArchiveyFileSystem("memory://d/lc.tar", policy=policy) as fs:
        written = _written(dest)
        listed = _listed(fs)
        assert fs.dir_cache is not None
        cached = set(fs.dir_cache)
        if os.name == "nt" and policy is ExtractionPolicy.TRUSTED:
            # TRUSTED keys on the exact name, and a Windows disk folds case and trims
            # a trailing dot, so it writes each of these over the member before it.
            # The tree does not model the disk.
            for name in ("a.txt", "f."):
                assert name in listed
                del listed[name]
                cached.discard(name)
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
