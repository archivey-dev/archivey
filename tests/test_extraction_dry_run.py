"""``dry_run=True``: the same extraction, into a scratch directory, with no content kept.

The contract is parity: a dry run reports what a real extraction into the same
destination reports, member for member, and leaves nothing behind. Most tests here
run both and compare, over the declarative corpus, the adversarial name corpus, the
symlink-redirection cases that only a real filesystem answers (threat model O22), and
destinations that already hold files, directories and symlinks.
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import re
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey import (
    AbortOn,
    ExtractionError,
    ExtractionLimits,
    ExtractionPolicy,
    ExtractionStatus,
    MemberType,
    NameCollisionError,
    OnError,
    OverwritePolicy,
    ResourceLimitError,
    open_archive,
)
from archivey.cli.exit_codes import EXIT_OK, EXIT_POLICY
from archivey.cli.main import main
from archivey.internal import dry_run as dry_run_module
from archivey.terminal import display_path
from tests.conftest import CPYTHON
from tests.create_adversarial import adversarial_archives
from tests.extract_util import lock_directories_at_once, open_and_extract
from tests.sample_archives import CORPUS, corpus_archive_path, skip_unless_runnable

_POLICIES = list(ExtractionPolicy)
_TMP_NAME = re.compile(r"\.archivey-tmp-[^'\"/]+")
_SINGLE_FILE_KEYS = {"gz", "gz-meta", "bz2", "xz", "zst", "lz4", "lz", "zz", "br"}


@pytest.fixture(autouse=True)
def _private_tempdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``tempfile`` at a directory of this test's own, to see what is left."""
    scratch_parent = tmp_path / "tmp"
    scratch_parent.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch_parent))
    return scratch_parent


def _assert_nothing_left(tmp_path: Path, dest: Path) -> None:
    assert not os.path.lexists(dest), "a dry run created its destination"
    assert list((tmp_path / "tmp").iterdir()) == [], "scratch directory left behind"


def _rel(path: Path | None, dest: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(dest).as_posix()
    except ValueError:  # spelled unlike dest: shown as is, to fail the comparison
        return f"elsewhere: {path.as_posix()}"


def _normalize(text: str, dest: Path, cwd: Path) -> str:
    """``text`` with dest factored out, keeping apart how it was spelled.

    Each spelling gets its own label: ``<given>`` for an absolute dest as given,
    ``<abs>`` for ``os.path.abspath`` of it, ``<resolved>`` for its resolution and
    ``<rel>`` for a relative dest as given. A run that reports ``out/x`` where the other
    reports ``/tmp/.../out/x``, or a symlink's target where the other names the
    symlink, does not compare equal.
    """
    absolute = os.path.abspath(cwd / dest)
    try:
        resolved = str((cwd / dest).resolve())
    except (OSError, RuntimeError):  # a symlink loop on the way
        resolved = absolute
    labels = {resolved: "<resolved>", absolute: "<abs>"}
    if dest.is_absolute():
        labels.setdefault(str(dest), "<given>")
    # Messages render paths through ``display_path`` (``/``-separated), so on Windows a
    # spelling also shows up in its posix form.
    for spelling, label in list(labels.items()):
        labels.setdefault(display_path(spelling), label)
    for spelling in sorted(labels, key=len, reverse=True):
        text = text.replace(spelling, labels[spelling])
    for spelling in (str(cwd.resolve()), display_path(cwd.resolve())):
        text = text.replace(spelling, "<cwd>")
    if not dest.is_absolute():
        text = re.sub(rf"(?<=['\"]){re.escape(str(dest))}(?=['\"/\\])", "<rel>", text)
    # The real run's OSError comes from the OS call, which gets a Path; the dry run's
    # comes from archivey's own raise, which passes str(dest). PyPy keeps the Path in
    # the message (CPython stores a str either way), so only there do the spellings
    # differ. Elsewhere this stays off, so a Path in an archivey message still shows.
    if not CPYTHON:
        text = re.sub(r"\b(?:Posix|Windows)Path\(('[^']*')\)", r"\1", text)
    # The staging file's random suffix is the one thing two runs never share.
    return _TMP_NAME.sub(".archivey-tmp-*", text)


def _shape(results, dest: Path, cwd: Path) -> list[tuple[object, ...]]:
    """What a caller can observe of a report, with the destination factored out."""
    shape = []
    for r in results:
        error = r.error
        message = None if error is None else _normalize(str(error), dest, cwd)
        shape.append(
            (
                r.member.name,
                r.status,
                _rel(r.path, dest),
                _rel(r.requested_path, dest),
                _rel(r.collided_with, dest),
                r.presented_name,
                r.failure_group_size,
                r.kept_mode,
                type(error),
                message,
            )
        )
    return shape


def _both(
    source,
    tmp_path: Path,
    *,
    relative: bool = False,
    dest_name: str = "out",
    populate: Callable[[Path], None] | None = None,
    **kwargs,
):
    """Extract ``source`` for real and as a dry run; return both report shapes.

    Each run extracts into ``<tmp_path>/<real|dry>/<dest_name>``. With ``relative``,
    it is given ``dest_name`` relative to the current directory, as the CLI gives it.
    ``populate``, given the absolute dest, fills it before each run; the dry run must
    then leave it exactly as it was.
    """
    kwargs.setdefault("on_error", OnError.CONTINUE)
    open_kwargs = kwargs.pop("open_kwargs", {})
    outcomes = []
    before = None
    for kind, dry_run in (("real", False), ("dry", True)):
        cwd = tmp_path / kind
        cwd.mkdir(exist_ok=True)
        dest = Path(dest_name) if relative else cwd / dest_name
        if populate is not None:
            populate(cwd / dest_name)
            if dry_run:
                before = _snapshot(cwd / dest_name)
        previous = os.getcwd()
        os.chdir(cwd)
        try:
            with open_archive(source(), **open_kwargs) as reader:
                try:
                    report = reader.extract_all(dest, dry_run=dry_run, **kwargs)
                except (archivey.ArchiveyError, OSError) as exc:
                    outcomes.append(
                        ("raised", type(exc), _normalize(str(exc), dest, cwd))
                    )
                else:
                    outcomes.append(_shape(report.results, dest, cwd))
        finally:
            os.chdir(previous)
    dry_dest = tmp_path / "dry" / dest_name
    if populate is None:
        _assert_nothing_left(tmp_path, dry_dest)
    else:
        assert _snapshot(dry_dest) == before, "a dry run changed its destination"
        assert list((tmp_path / "tmp").iterdir()) == [], "scratch directory left behind"
    return outcomes[0], outcomes[1]


def _snapshot(root: Path) -> dict[str, tuple[object, ...]] | None:
    """Every entry under ``root``, with its kind, mode, mtime and content or target;
    ``None`` when ``root`` is absent."""
    if not os.path.lexists(root):
        return None
    found: dict[str, tuple[object, ...]] = {}
    st = root.stat()
    found["."] = ("root", st.st_mode, st.st_mtime_ns)
    for parent, dirnames, filenames in os.walk(root):
        for name in (*dirnames, *filenames):
            path = Path(parent) / name
            st = path.lstat()
            if path.is_symlink():
                detail: object = os.readlink(path)
            elif path.is_dir():
                detail = None
            else:
                detail = path.read_bytes()
            rel = path.relative_to(root).as_posix()
            found[rel] = (st.st_mode, st.st_mtime_ns, detail)
    return found


# --- parity over the corpora --------------------------------------------------------

_CORPUS_PARAMS = [
    pytest.param(entry, key, id=f"{entry.id}-{key}")
    for entry in CORPUS
    for key in entry.formats
    if key not in _SINGLE_FILE_KEYS
]


@pytest.mark.parametrize(("entry", "key"), _CORPUS_PARAMS)
def test_corpus_dry_run_matches_real_extraction(entry, key, tmp_path: Path) -> None:
    skip_unless_runnable(entry, key)
    path = corpus_archive_path(entry, key, tmp_path)
    passwords = list(entry.passwords) or None
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(
            lambda: path,
            work,
            policy=policy,
            open_kwargs={"password": passwords},
        )
        assert dry == real, policy


_ADVERSARIAL = adversarial_archives()


@pytest.mark.parametrize(
    ("entry", "blob"), _ADVERSARIAL, ids=[entry.id for entry, _ in _ADVERSARIAL]
)
def test_adversarial_dry_run_matches_real_extraction(
    entry, blob: bytes, tmp_path: Path
) -> None:
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(lambda: io.BytesIO(blob), work, policy=policy)
        assert dry == real, policy


# --- the checks only a filesystem answers -------------------------------------------


def _tar(entries: list[tuple[str, str, object]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, extra in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = extra if isinstance(extra, bytes) else b"data"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = extra if isinstance(extra, int) else 0o755
                tf.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = str(extra)
                tf.addfile(info)
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = str(extra)
                tf.addfile(info)
    return buf.getvalue()


_FILESYSTEM_CASES = {
    # A file written through a symlinked parent the archive made itself.
    "through-own-symlink": [("d", "dir", None), ("l", "sym", "d"), ("l/f", "file", 0)],
    # O22: a link that a later member makes escape.
    "made-escaping-later": [
        ("l", "sym", "a/../../secret"),
        ("a", "sym", "."),
    ],
    # A chain of links that ends outside.
    "escaping-chain": [
        ("x", "sym", "y"),
        ("y", "sym", ".."),
        ("x/f", "file", 0),
    ],
    # A hardlink to a file, one whose source the archive never wrote, one to a
    # refused source (refused too), and one through a refused middle name to a
    # written file (linked).
    "hardlinks": [
        ("f", "file", b"content"),
        ("h", "hard", "f"),
        ("orphan", "hard", "missing"),
        ("../x", "file", b"payload"),
        ("refused", "hard", "../x"),
        ("../m", "hard", "f"),
        ("via", "hard", "../m"),
    ],
    # A hard link that STRICT and STANDARD fold onto its own source's path.
    "hardlink-onto-own-source": [("a", "file", b"data"), ("A", "hard", "a")],
    # A hard link listed twice: the superseded copy is parked at the same name.
    "hardlink-listed-twice": [
        ("a", "file", b"data"),
        ("b", "hard", "a"),
        ("b", "hard", "a"),
    ],
    # Duplicate names and a file where a directory was.
    "duplicates": [
        ("a", "file", b"one"),
        ("a", "file", b"two"),
        ("d", "file", 0),
        ("d/f", "file", 0),
    ],
    # A file landing on a directory this run made, which holds a member: REPLACE
    # fails it with an error that names the directory under ``dest``.
    "file-over-run-directory": [
        ("x/f", "file", 0),
        ("y", "dir", None),
        ("y/f", "file", 0),
        ("x", "file", 0),
        ("y", "file", 0),
    ],
}


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("case", sorted(_FILESYSTEM_CASES))
@pytest.mark.parametrize(
    "overwrite",
    [OverwritePolicy.ERROR, OverwritePolicy.RENAME, OverwritePolicy.REPLACE],
)
@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
def test_filesystem_dependent_outcomes_match(
    case: str,
    overwrite: OverwritePolicy,
    streaming: bool,
    relative: bool,
    tmp_path: Path,
) -> None:
    blob = _tar(_FILESYSTEM_CASES[case])
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(
            lambda: io.BytesIO(blob),
            work,
            relative=relative,
            policy=policy,
            overwrite=overwrite,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize(
    "overwrite",
    [OverwritePolicy.ERROR, OverwritePolicy.RENAME, OverwritePolicy.REPLACE],
)
def test_orphan_links_folded_onto_each_other_match(
    overwrite: OverwritePolicy, streaming: bool, tmp_path: Path
) -> None:
    # Two selected links that fold together, their source excluded: the second pass
    # writes the source's content at the first and REPLACE routes the second onto it.
    blob = _tar([("src", "file", b"data"), ("L", "hard", "src"), ("l", "hard", "src")])
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(
            lambda: io.BytesIO(blob),
            work,
            members=["L", "l"],
            policy=policy,
            overwrite=overwrite,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
@pytest.mark.parametrize(
    "held",
    [
        pytest.param({"h1": b"mine"}, id="file"),
        pytest.param({"h1/keep": b"mine"}, id="full-dir"),
    ],
)
def test_orphan_first_link_destination_taken_matches(
    held: dict[str, object],
    overwrite: OverwritePolicy,
    streaming: bool,
    tmp_path: Path,
) -> None:
    # The source excluded and its first link's destination held by the caller: the
    # policy decides that link alone, and the content goes to the next link.
    blob = _tar(
        [("src", "file", b"data"), ("h1", "hard", "src"), ("h2", "hard", "src")]
    )
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(
            lambda: io.BytesIO(blob),
            work,
            populate=lambda dest: _put(dest, held),
            members=["h1", "h2"],
            policy=policy,
            overwrite=overwrite,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy


def _dest_named_links(dest: Path) -> list[tuple[str, str, object]]:
    """Links whose targets name ``dest`` itself, so each run needs its own archive."""
    return [
        ("data", "file", b"content"),
        # Absolute, into dest: kept by a real extraction.
        ("abs", "sym", f"{dest}/data"),
        ("abs-dotdot", "sym", f"{dest}/sub/../data"),
        # Absolute, into dest past a component that does not exist.
        ("abs-gone", "sym", f"{dest.parent}/gone/../{dest.name}/data"),
        # A file written through an absolute link to a directory in dest.
        ("sub", "dir", None),
        ("abs-dir", "sym", f"{dest}/sub"),
        ("abs-dir/f", "file", 0),
        # Absolute, outside dest: refused by a real extraction too.
        ("abs-out", "sym", "/archivey-dry-run-test-elsewhere"),
        # Relative, out of dest by name and back in.
        ("up", "sym", f"../{dest.name}/data"),
        # O22 on an absolute target: inside when made, outside once "a" is dest.
        ("later", "sym", f"{dest}/a/b/../../data"),
        ("a", "sym", "."),
        # A hardlink whose (archive-relative) target is absolute.
        ("hard-abs", "hard", f"{dest}/data"),
    ]


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_link_targets_that_name_dest_match(streaming: bool, tmp_path: Path) -> None:
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        blobs = {
            dry_run: _tar(_dest_named_links(work / kind / "out"))
            for dry_run, kind in ((False, "real"), (True, "dry"))
        }
        calls = iter((False, True))
        real, dry = _both(
            lambda: io.BytesIO(blobs[next(calls)]),  # noqa: B023 - called within this iteration
            work,
            policy=policy,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy
        statuses = {entry[0]: entry[1] for entry in dry}
        assert statuses["abs"] is ExtractionStatus.EXTRACTED
        assert statuses["up"] is ExtractionStatus.EXTRACTED
        assert statuses["abs-gone"] is ExtractionStatus.EXTRACTED
        assert statuses["abs-dir/f"] is ExtractionStatus.EXTRACTED
        assert statuses["later"] is ExtractionStatus.BLOCKED


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_link_past_a_missing_name_meets_what_dest_holds(
    streaming: bool, tmp_path: Path
) -> None:
    # A link member whose absolute target reaches dest past a component that does
    # not exist, then goes on through the caller's symlink out of dest.
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        blobs = {
            dry_run: _tar([("l", "sym", f"{work / kind}/gone/../out/evil/x")])
            for dry_run, kind in ((False, "real"), (True, "dry"))
        }
        calls = iter((False, True))
        real, dry = _both(
            lambda: io.BytesIO(blobs[next(calls)]),  # noqa: B023 - called within this iteration
            work,
            policy=policy,
            populate=lambda dest: _put(
                dest, {"evil": ("sym", "/archivey-dry-run-test-elsewhere")}
            ),
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy
        if policy is not ExtractionPolicy.TRUSTED:
            assert real[0][1] is ExtractionStatus.BLOCKED, policy


# --- what the dry run does and does not touch ---------------------------------------


def test_bodies_are_read_and_verified(tmp_path: Path) -> None:
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("good.txt", b"fine")
        zf.writestr("bad.txt", b"payload that gets damaged")
    blob = bytearray(path.read_bytes())
    at = blob.index(b"payload that gets damaged")
    blob[at] ^= 0xFF
    path.write_bytes(bytes(blob))

    dest = tmp_path / "out"
    report = open_and_extract(path, dest, on_error=OnError.CONTINUE, dry_run=True)
    statuses = {r.member.name: r.status for r in report.results}
    assert statuses == {
        "good.txt": ExtractionStatus.EXTRACTED,
        "bad.txt": ExtractionStatus.FAILED,
    }
    _assert_nothing_left(tmp_path, dest)


def test_limits_still_apply(tmp_path: Path) -> None:
    blob = _tar([("big", "file", b"x" * 4096)])
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(blob)) as reader, pytest.raises(ResourceLimitError):
        reader.extract_all(
            dest, limits=ExtractionLimits(max_extracted_bytes=1024), dry_run=True
        )
    _assert_nothing_left(tmp_path, dest)


def test_existing_destination_is_met_but_not_changed(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a").write_bytes(b"mine")
    blob = _tar([("a", "file", b"theirs")])
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, on_error=OnError.CONTINUE, dry_run=True)
    # The run meets "a" as a real run would, under the default OverwritePolicy.ERROR.
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert isinstance(result.error, ExtractionError)
    assert f"Destination already exists: {display_path(dest / 'a')}" in str(
        result.error
    )
    assert (dest / "a").read_bytes() == b"mine"
    assert sorted(p.name for p in dest.iterdir()) == ["a"]


def _zip_blob(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _put(dest: Path, entries: dict[str, object]) -> None:
    """Create ``entries`` under ``dest``: bytes for a file, ``None`` for a directory,
    ``("sym", target)`` for a symlink, an int for a directory with that mode. A
    target's ``{dest}`` and ``{parent}`` name ``dest`` and the directory holding it."""
    dest.mkdir(parents=True, exist_ok=True)
    for name, what in entries.items():
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(what, bytes):
            path.write_bytes(what)
        elif what is None:
            path.mkdir()
        elif isinstance(what, int):
            path.mkdir()
            path.chmod(what)
        else:
            _, target = what  # type: ignore[misc]
            os.symlink(_expand(str(target), dest), path)


def _expand(text: str, dest: Path) -> str:
    """A row's ``{dest}`` and ``{parent}`` placeholders, filled for one run's
    ``dest``. Any other placeholder raises ``KeyError`` rather than staying a
    literal that both runs would build alike."""
    return text.format(dest=dest, parent=dest.parent) if "{" in text else text


# Each case: what dest holds before the run, and the archive's members.
_EXISTING_CASES: dict[str, tuple[dict[str, object], list[tuple[str, str, object]]]] = {
    # The reported case: a file member over a file of the caller's.
    "file-over-file": (
        {"hello.txt": b"mine", "other": b"untouched"},
        [("hello.txt", "file", b"theirs")],
    ),
    # Deeper, so the directory on the way is copied in too, with RENAME's next name
    # taken already.
    "file-over-file-in-dir": (
        {"sub/a": b"mine", "sub/a (1)": b"mine too"},
        [("sub/a", "file", b"theirs"), ("sub/b", "file", b"new")],
    ),
    # A directory member, and a file member, where the caller has a directory: with
    # entries (REPLACE refuses it) and empty (REPLACE removes it).
    "over-directories": (
        {"full/x": b"mine", "empty": None},
        [("full", "file", b"f"), ("empty", "file", b"e"), ("d", "dir", None)],
    ),
    # A directory member over a file, then a file inside it.
    "directory-over-file": (
        {"d": b"mine"},
        [("d", "dir", None), ("d/f", "file", b"f")],
    ),
    # A file inside a directory the archive only implies, where dest has a file.
    "implicit-parent-is-a-file": (
        {"p": b"mine"},
        [("p/f", "file", b"f")],
    ),
    # A hardlink to a member, where both names are taken already.
    "hardlink-over-files": (
        {"f": b"mine", "h": b"mine"},
        [("f", "file", b"content"), ("h", "hard", "f")],
    ),
    # RENAME's first numbered name is taken in dest, but the base name is free: the
    # member collides with a directory the run made, so RENAME still tries it.
    "rename-past-a-held-numbered-name": (
        {"a (1)": b"mine"},
        [("a/x", "file", b"x"), ("a", "file", b"a")],
    ),
    # The same, where the member collides with another member's case variant.
    "rename-case-variant-past-a-held-numbered-name": (
        {"A (1)": b"mine"},
        [("a", "file", b"a"), ("A", "file", b"A")],
    ),
}

_EXISTING_LINK_CASES: dict[
    str, tuple[dict[str, object], list[tuple[str, str, object]]]
] = {
    # A symlink of the caller's where a member lands: replaced, never written
    # through, and an error under ERROR.
    "file-over-symlink": (
        {"real": b"mine", "ln": ("sym", "real")},
        [("ln", "file", b"theirs")],
    ),
    # A dangling one counts as existing.
    "file-over-dangling-symlink": (
        {"dangling": ("sym", "nowhere")},
        [("dangling", "file", b"theirs")],
    ),
    # A file under the caller's symlink to a directory in dest: written through it.
    "through-symlink-inside": (
        {"sub/x": b"mine", "ln": ("sym", "sub"), "abs": ("sym", "{dest}/sub")},
        [("ln/x", "file", b"theirs"), ("ln/y", "file", b"y"), ("abs/z", "file", b"")],
    ),
    # Under one whose absolute target reaches dest past a component that does not
    # exist: the OS cannot follow it, so the member lands on the link itself.
    "through-symlink-past-a-missing-name": (
        {"sub/x": b"mine", "ln": ("sym", "{parent}/gone/../out/sub")},
        [("ln/y", "file", b"y")],
    ),
    # The same, where what it reaches in dest is a symlink out of dest: refused.
    "through-symlink-past-a-missing-name-and-out": (
        {
            "sub": ("sym", "/archivey-dry-run-test-elsewhere"),
            "ln": ("sym", "{parent}/gone/../out/sub"),
        },
        [("ln/y", "file", b"y")],
    ),
    # And under one that leaves dest: refused.
    "through-symlink-outside": (
        {"out": ("sym", "../../elsewhere")},
        [("out/f", "file", b"theirs")],
    ),
    # A link member resolved through the caller's links: in, then out.
    "link-member-through-symlink": (
        {"sub/x": b"mine", "ln": ("sym", "sub"), "up": ("sym", "..")},
        [("in", "sym", "ln/x"), ("out", "sym", "up/secret")],
    ),
    # A directory member over the caller's symlink to a directory.
    "directory-over-symlink": (
        {"sub": None, "ln": ("sym", "sub")},
        [("ln", "dir", None), ("ln/f", "file", b"f")],
    ),
    # A file member over a directory of dest that holds entries, reached through
    # the caller's symlink: REPLACE refuses it, as the directory is not empty.
    "file-over-full-directory-through-symlink": (
        {"sub/b/keep.txt": b"mine", "a": ("sym", "sub")},
        [("a/b", "file", b"theirs")],
    ),
    # A symlink of the caller's that loops: the error names it in dest.
    "under-a-looping-symlink": (
        {"a": ("sym", "a")},
        [("a/c", "file", b"x")],
    ),
    # A link member whose target is missing when it is made, and that a later member
    # makes resolve through the caller's symlink out of dest: the recheck refuses it.
    "link-member-escapes-after-a-later-member": (
        {"real/esc": ("sym", "../../outside")},
        [("l", "sym", "a/esc"), ("a", "sym", "real")],
    ),
    # A link member whose relative target passes a missing name and takes it off with
    # a later "..": the checks resolve it to the caller's symlink out of dest.
    "link-member-past-a-missing-name": (
        {"real/esc": ("sym", "../../outside")},
        [("l", "sym", "gone/../real/esc")],
    ),
    "link-member-past-two-missing-names": (
        {"real/esc": ("sym", "../../outside")},
        [("l", "sym", "x/y/../../real/esc")],
    ),
    "link-member-past-a-missing-name-deeper": (
        {"real/sub/esc": ("sym", "../../../outside")},
        [("l", "sym", "g/../real/sub/esc")],
    ),
    # A nested link member, whose directory is not on disk yet, with an absolute
    # target that names dest and goes on through the caller's symlink out of it.
    "nested-link-member-absolute-into-dest": (
        {"x": ("sym", "../outside")},
        [("a/l", "sym", "{dest}/x"), ("a/b/l", "sym", "{dest}/x")],
    ),
    # The same, where the later member replaces a directory the run made.
    "link-member-escapes-after-a-later-member-replaces-a-directory": (
        {"real/esc": ("sym", "../../outside")},
        [("a", "dir", None), ("l", "sym", "a/esc"), ("a", "sym", "real")],
    ),
}


def _existing_case_params(cases: dict[str, object]) -> list[object]:
    return [pytest.param(name, id=name) for name in sorted(cases)]


def _run_existing_case(
    held: dict[str, object],
    members: list[tuple[str, str, object]],
    overwrite: OverwritePolicy,
    streaming: bool,
    tmp_path: Path,
    *,
    relative: bool = False,
    dest_name: str = "out",
) -> None:
    def source() -> io.BytesIO:
        # A "{dest}" or "{parent}" in a link target names the run's own dest, as
        # given, so each run builds its own archive. ``_both`` calls this in the run's directory.
        dest = Path.cwd() / dest_name
        return io.BytesIO(
            _tar(
                [
                    (
                        name,
                        kind,
                        _expand(extra, dest) if isinstance(extra, str) else extra,
                    )
                    for name, kind, extra in members
                ]
            )
        )

    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        if dest_name != "out":
            _spell_dest_ways(work)
        real, dry = _both(
            source,
            work,
            relative=relative,
            dest_name=dest_name,
            populate=lambda dest: _put(dest, held),
            policy=policy,
            overwrite=overwrite,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy


def _spell_dest_ways(work: Path) -> None:
    """What ``link/out`` and ``x/../out`` need under each run's directory."""
    for kind in ("real", "dry"):
        cwd = work / kind
        (cwd / "realdir").mkdir(parents=True)
        (cwd / "link").symlink_to("realdir")
        (cwd / "x").mkdir()


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
@pytest.mark.parametrize("case", _existing_case_params(_EXISTING_CASES))
def test_existing_contents_meet_the_overwrite_policy_alike(
    case: str, overwrite: OverwritePolicy, streaming: bool, tmp_path: Path
) -> None:
    held, members = _EXISTING_CASES[case]
    _run_existing_case(held, members, overwrite, streaming, tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
@pytest.mark.parametrize("case", _existing_case_params(_EXISTING_LINK_CASES))
def test_existing_symlinks_are_met_alike(
    case: str, overwrite: OverwritePolicy, streaming: bool, tmp_path: Path
) -> None:
    held, members = _EXISTING_LINK_CASES[case]
    _run_existing_case(held, members, overwrite, streaming, tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_symlink_loop_error_names_dest_in_its_cause(tmp_path: Path) -> None:
    # The report shape compares the message only; the cause keeps a file name too.
    dest = tmp_path / "out"
    _put(dest, {"a": ("sym", "a")})
    blob = _tar([("a/c", "file", b"x")])
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, on_error=OnError.CONTINUE, dry_run=True)
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    cause = result.error.__cause__
    assert isinstance(cause, OSError)
    assert cause.filename == str(dest.resolve() / "a")


@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
def test_existing_contents_match_from_a_zip(
    overwrite: OverwritePolicy, tmp_path: Path
) -> None:
    # The reported case, as reported: a zip holding hello.txt, and out/hello.txt.
    blob = _zip_blob({"hello.txt": b"theirs"})
    real, dry = _both(
        lambda: io.BytesIO(blob),
        tmp_path,
        populate=lambda dest: _put(dest, {"hello.txt": b"mine"}),
        overwrite=overwrite,
    )
    assert dry == real
    (entry,) = dry
    expected = {
        OverwritePolicy.ERROR: ExtractionStatus.FAILED,
        OverwritePolicy.SKIP: ExtractionStatus.NOT_OVERWRITTEN,
        OverwritePolicy.REPLACE: ExtractionStatus.EXTRACTED,
        OverwritePolicy.RENAME: ExtractionStatus.EXTRACTED,
    }
    assert entry[1] is expected[overwrite]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_destination_mode_is_kept_alike(tmp_path: Path) -> None:
    # A `./` member over dest, and a directory member over one of its directories:
    # each keeps the caller's mode and reports it.
    # The high bits are kept too: setgid on a directory, sticky on dest (as on /tmp).
    blob = _tar([("./", "dir", 0o755), ("sub", "dir", 0o755)])

    def populate(dest: Path) -> None:
        _put(dest, {"sub": 0o2750})
        dest.chmod(0o1700)

    real, dry = _both(lambda: io.BytesIO(blob), tmp_path, populate=populate)
    assert dry == real
    assert [entry[7] for entry in dry] == [0o1700, 0o2750]


def test_record_leaves_out_what_dest_held(tmp_path: Path) -> None:
    # What the CLI reads to name where a single root lands: only the run's own
    # entries, not the caller's that the pass met on its way.
    dest = tmp_path / "out"
    _put(dest, {"keep": b"mine", "sub/old": b"mine", "skipped": b"mine"})
    blob = _tar(
        [("sub/new", "file", b"n"), ("skipped", "file", b"s"), ("keep2", "file", b"")]
    )
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, overwrite=OverwritePolicy.SKIP, dry_run=True)
    assert report._dry_run_top_level == (("keep2", False), ("sub", True))
    blob = _tar([("sub/new", "file", b"n")])
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, dry_run=True)
    assert report._dry_run_top_level == (("sub", True),)
    assert report._dry_run_entries == (("sub", True), ("sub/new", False))


_NON_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes anywhere"
)


_SPELLINGS = pytest.mark.parametrize(
    "dest_name", ["out", "link/out", "x/../out"], ids=["plain", "symlink", "dotdot"]
)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
@_SPELLINGS
@pytest.mark.parametrize("overwrite", [OverwritePolicy.ERROR, OverwritePolicy.RENAME])
@pytest.mark.parametrize(
    "case",
    _existing_case_params(_EXISTING_CASES)
    + _existing_case_params(_EXISTING_LINK_CASES),
)
def test_existing_contents_match_with_each_dest_spelling(
    case: str,
    overwrite: OverwritePolicy,
    dest_name: str,
    relative: bool,
    tmp_path: Path,
) -> None:
    held, members = {**_EXISTING_CASES, **_EXISTING_LINK_CASES}[case]
    _run_existing_case(
        held,
        members,
        overwrite,
        False,
        tmp_path,
        relative=relative,
        dest_name=dest_name,
    )


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_hardlink_to_an_absolute_source_meets_dest_alike(tmp_path: Path) -> None:
    # The link's source is not selected, so the policy checks it re-rooted, as
    # "a/b/f": through the caller's "a/b", which leaves dest.
    blob = _tar([("/a/b/f", "file", b"data"), ("link", "hard", "/a/b/f")])
    real, dry = _both(
        lambda: io.BytesIO(blob),
        tmp_path,
        populate=lambda dest: _put(dest, {"a/b": ("sym", "../../..")}),
        members=["link"],
        policy=ExtractionPolicy.STANDARD,
    )
    assert dry == real
    assert dry[0][1] is ExtractionStatus.BLOCKED


@pytest.mark.parametrize("on_error", [OnError.CONTINUE, OnError.STOP])
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_chained_hardlink_source_meets_dest_alike(
    streaming: bool, on_error: OnError, tmp_path: Path
) -> None:
    # "outer" names "mid", which names "escaped/f": the policy checks the end of
    # the chain, through the caller's "escaped", which leaves dest.
    blob = _tar(
        [
            ("escaped/f", "file", b"data"),
            ("mid", "hard", "escaped/f"),
            ("outer", "hard", "mid"),
        ]
    )
    for policy in _POLICIES:
        work = tmp_path / policy.value
        (work / "tmp").mkdir(parents=True)
        tempfile.tempdir = str(work / "tmp")
        real, dry = _both(
            lambda: io.BytesIO(blob),
            work,
            populate=lambda dest: _put(dest, {"escaped": ("sym", "../..")}),
            members=["outer"],
            policy=policy,
            on_error=on_error,
            open_kwargs={"streaming": streaming},
        )
        assert dry == real, policy
        assert real[0][1] is ExtractionStatus.BLOCKED, policy


def test_matching_an_absolute_target_is_linear_in_its_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A link target's depth is the archive's to choose. Matching it against dest
    # resolves one short path per component that exists, and nothing past the
    # first that does not.
    asked: list[str] = []
    realpath = os.path.realpath

    def counted(path, *args, **kwargs):
        asked.append(os.fspath(path))
        return realpath(path, *args, **kwargs)

    dest = tmp_path / "out"
    with dry_run_module.scratch_for(dest) as dry:
        monkeypatch.setattr(os.path, "realpath", counted)
        missing = "/" + "/".join(f"archivey-no-such-{i}" for i in range(2000))
        assert dry.target_on_disk(missing) == missing
        assert asked == []
        # Every prefix exists: each step resolves the last prefix plus one name.
        climbing = str(tmp_path) + "/x/.." * 1000 + "/elsewhere"
        (tmp_path / "x").mkdir()
        assert dry.target_on_disk(climbing) == climbing
        monkeypatch.undo()
    assert len(asked) <= 2001 + len(tmp_path.parts)
    assert max(len(path) for path in asked) <= len(str(tmp_path)) + 20


def test_matching_a_missing_target_joins_a_linear_amount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Past a component that does not exist no filesystem call is made, so what the
    # match costs there is the joining of path strings: pathlib joins a path's parts
    # each time it is hashed, compared or shown. Counted as the characters handed
    # to ``os.path.join``, which pathlib joins through from Python 3.12 (3.11 joins
    # with ``str.join``, unseen here), it stays linear in the target's length.
    joined = 0
    join = os.path.join

    def counted(*parts):
        nonlocal joined
        joined += sum(len(os.fspath(part)) for part in parts)
        return join(*parts)

    dest = tmp_path / "out"
    deep = "/".join(f"n{i}" for i in range(2000))
    targets = [
        # Missing from its first component: no match.
        f"/archivey-no-such/{deep}",
        # Down past a missing name and back up into dest: a match.
        f"{tmp_path}/gone/{deep}/" + "../" * 2001 + "out/data",
    ]
    with dry_run_module.scratch_for(dest) as dry:
        monkeypatch.setattr(os.path, "join", counted)
        matched = [dry.target_on_disk(target) for target in targets]
        monkeypatch.undo()
        # Rewritten through the gap, as ``gone`` is on the way.
        detour = dry.scratch.parent / "missing" / ".." / dry.scratch.name / "data"
    assert matched == [targets[0], str(detour)]
    assert joined <= 4 * sum(len(target) for target in targets)


def test_record_keeps_the_top_when_the_tree_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # What dest held does not change what the record says sits at its top, even
    # when the rest of the tree cannot be walked.
    monkeypatch.setattr(dry_run_module, "scratch_tree", lambda root: None)
    blob = _tar([("r", "dir", None), ("r/f", "file", b"f")])
    tops = []
    for held in ({}, {"unrelated": b"mine"}):
        dest = tmp_path / f"out{len(tops)}"
        if held:
            _put(dest, held)
        with open_archive(io.BytesIO(blob)) as reader:
            report = reader.extract_all(dest, dry_run=True)
        tops.append(report._dry_run_top_level)
        assert report._dry_run_entries is None
    assert tops == [(("r", True),), (("r", True),)]


def test_record_leaves_out_a_directory_member_that_failed(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    _put(dest, {"d": b"mine"})
    blob = _tar([("d", "dir", None)])
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, on_error=OnError.CONTINUE, dry_run=True)
    assert [r.status for r in report.results] == [ExtractionStatus.FAILED]
    assert report._dry_run_top_level == ()


def test_dry_run_copies_only_what_the_pass_names(tmp_path: Path) -> None:
    # A crowded dest costs the dry run a listing, not a copy of every entry: each
    # member finds in the scratch copy only what earlier members and their paths
    # brought in.
    dest = tmp_path / "out"
    _put(dest, {f"f{i}": b"" for i in range(200)} | {"sub/x": b"", "sub/y": b""})
    seen: list[list[str]] = []

    def look(member):
        (work,) = (tmp_path / "tmp").glob(f"{dry_run_module.DRY_RUN_PREFIX}*/out")
        seen.append(sorted(p.relative_to(work).as_posix() for p in work.rglob("*")))
        return member

    blob = _tar([("f7", "file", b"n"), ("sub", "dir", None), ("last", "file", b"")])
    with open_archive(io.BytesIO(blob)) as reader:
        reader.extract_all(
            dest, overwrite=OverwritePolicy.REPLACE, filter=look, dry_run=True
        )
    # "sub" named as a directory brings one of its entries, so a REPLACE there
    # finds it not empty.
    assert seen == [[], ["f7"], ["f7", "sub", "sub/x"]]


def test_numbered_name_held_under_another_normalization_is_copied_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On a filesystem that compares names normalization-insensitively (APFS), a
    # RENAME of the composed name "á" finds the decomposed "á (1)" taken. The
    # dry run copies it in, under the name dest holds it by. Such a filesystem is
    # simulated: dest's lookups fold names as ``_fold`` does.
    composed = unicodedata.normalize("NFC", "á")
    decomposed = unicodedata.normalize("NFD", "á")
    dest = tmp_path / "out"
    _put(dest, {f"{decomposed} (1)": b"mine"})
    real_lexists = os.path.lexists

    def lexists(path) -> bool:
        if real_lexists(path):
            return True
        path = Path(path)
        if path.parent != dest:
            return False
        key = dry_run_module._fold(path.name)
        return any(dry_run_module._fold(n) == key for n in os.listdir(dest))

    with dry_run_module.scratch_for(dest) as dry:
        monkeypatch.setattr(os.path, "lexists", lexists)
        dry._bring(dry.scratch, composed)
        monkeypatch.undo()
        assert os.listdir(dry.scratch) == [f"{decomposed} (1)"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
@_NON_ROOT
def test_unwritable_directory_in_dest_is_an_exemption(tmp_path: Path) -> None:
    # Stated exemption: a refusal that comes from the permissions of a directory of
    # dest appears only in a real run, as the scratch copy can always be written.
    blob = _tar([("ro/f", "file", b"f")])
    try:
        real, dry = _both(
            lambda: io.BytesIO(blob),
            tmp_path,
            populate=lambda dest: _put(dest, {"ro": 0o555}),
        )
    finally:
        for kind in ("real", "dry"):
            (tmp_path / kind / "out" / "ro").chmod(0o755)
    assert real[0][1] is ExtractionStatus.FAILED
    assert real[0][8] is PermissionError
    assert dry[0][1] is ExtractionStatus.EXTRACTED


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_symlink_the_os_will_not_create_is_an_exemption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stated exemption: a symlink of dest that the OS will not create in the
    # scratch tree (Windows without the privilege) is copied as an empty file, so
    # a member under it meets a file where a real run writes through the link.
    monkeypatch.setattr(
        dry_run_module.DryRun, "_copy_link", lambda self, source, path: False
    )
    blob = _tar([("ln/x", "file", b"theirs")])
    real, dry = _both(
        lambda: io.BytesIO(blob),
        tmp_path,
        populate=lambda dest: _put(dest, {"sub": None, "ln": ("sym", "sub")}),
    )
    assert real[0][1] is ExtractionStatus.EXTRACTED
    assert dry[0][1] is ExtractionStatus.FAILED
    assert "Destination already exists" in str(dry[0][9])


def _cli_both(
    blob: bytes, held: dict[str, object], argv: list[str], tmp_path: Path
) -> tuple[tuple[int, str], tuple[int, str]]:
    """``archivey x`` run for real and with ``--dry-run`` in a cwd holding ``held``
    and the archive: the exit code and stderr of each, with what only a dry run
    prints taken out."""
    runs = []
    previous = os.getcwd()
    for dry in (False, True):
        cwd = tmp_path / ("dry" if dry else "real")
        _put(cwd, held)
        (cwd / "a.tar").write_bytes(blob)
        os.chdir(cwd)
        try:
            extra = ["--dry-run"] if dry else []
            code, err = _cli(["x", "a.tar", "--hide-progress", *argv, *extra])
        finally:
            os.chdir(previous)
        for only_dry in (
            "dry run, nothing written: ",
            "dry run: nothing was written\n",
        ):
            err = err.replace(only_dry, "")
        if dry:
            # Only the dry run prints it, so the real half asserts its absence.
            err = re.sub(r"(?m)^peak use of the reader limits: .*\n", "", err)
        for would, did in (
            ("would extract into", "extracting into"),
            ("would keep in", "kept in"),
        ):
            err = err.replace(would, did)
        runs.append((code, err.replace(str(cwd), "<cwd>")))
    return runs[0], runs[1]


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
@pytest.mark.parametrize("case", _existing_case_params(_EXISTING_CASES))
def test_cli_dry_run_into_a_populated_cwd_matches(
    case: str, overwrite: str, tmp_path: Path
) -> None:
    held, members = _EXISTING_CASES[case]
    # The CLI runs build one archive for both runs, so a row here cannot name dest.
    assert not any(isinstance(extra, str) and "{" in extra for _, _, extra in members)
    real, dry = _cli_both(
        _tar(members), held, ["-d", ".", "--overwrite", overwrite], tmp_path
    )
    assert dry == real


@pytest.mark.parametrize("overwrite", ["error", "rename"])
def test_cli_dry_run_names_where_a_root_lands_past_a_file(
    overwrite: str, tmp_path: Path
) -> None:
    # A root "foo/" stored as a directory member, with the operator's file "foo".
    # The dry run does not list the hoist's own rename (the cli spec), so only the
    # exit code and where the summary says the content lands are compared.
    blob = _tar([("foo", "dir", None), ("foo/x.txt", "file", b"x")])
    real, dry = _cli_both(blob, {"foo": b"mine"}, ["--overwrite", overwrite], tmp_path)
    assert dry[0] == real[0]
    assert (
        dry[1].splitlines()[-1].split(" → ")[1]
        == (real[1].splitlines()[-1].split(" → ")[1])
    )


def test_destination_that_is_a_file_is_refused(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    dest.write_bytes(b"")
    with (
        open_archive(io.BytesIO(_tar([("a", "file", 0)]))) as reader,
        pytest.raises(ExtractionError, match="not a directory"),
    ):
        reader.extract_all(dest, dry_run=True)
    assert list((tmp_path / "tmp").iterdir()) == []


def test_destination_under_a_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "afile").write_bytes(b"")
    blob = _tar([("a", "file", 0)])
    raised = []
    for dry_run in (False, True):
        dest = tmp_path / "afile" / ("dry" if dry_run else "real") / "out"
        with open_archive(io.BytesIO(blob)) as reader, pytest.raises(OSError) as caught:
            reader.extract_all(dest, dry_run=dry_run)
        raised.append(caught.value)
    real, dry = raised
    if os.name != "nt":
        assert type(dry) is type(real)
    assert "archivey-dry-run-" not in str(dry)
    assert list((tmp_path / "tmp").iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes and symlinks")
@_NON_ROOT
@pytest.mark.parametrize(
    "shape", ["unwritable-parent", "unwritable-grandparent", "symlink-loop"]
)
@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
def test_destination_that_cannot_be_created_is_refused_alike(
    shape: str, relative: bool, tmp_path: Path
) -> None:
    for kind in ("real", "dry"):
        cwd = tmp_path / kind
        cwd.mkdir()
        if shape == "symlink-loop":
            (cwd / "base").symlink_to("base")
        else:
            (cwd / "base").mkdir(mode=0o555)
    tail = "a/out" if shape == "unwritable-grandparent" else "out"
    try:
        real, dry = _both(
            lambda: io.BytesIO(_tar([("data", "file", 0)])),
            tmp_path,
            relative=relative,
            dest_name=f"base/{tail}",
        )
    finally:
        for kind in ("real", "dry"):
            if not (tmp_path / kind / "base").is_symlink():
                (tmp_path / kind / "base").chmod(0o755)
    assert real[0] == "raised"
    assert dry == real
    assert not os.path.lexists(tmp_path / "dry" / "base" / tail)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
@_NON_ROOT
@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
@pytest.mark.parametrize(
    "dest_name", ["out", "link/out", "x/../out"], ids=["plain", "symlink", "dotdot"]
)
def test_member_errors_match_with_either_dest_spelling(
    relative: bool, dest_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_directories_at_once(monkeypatch)
    for kind in ("real", "dry"):
        cwd = tmp_path / kind
        (cwd / "realdir").mkdir(parents=True)
        (cwd / "link").symlink_to("realdir")
        (cwd / "x").mkdir()
    # The directory is locked before its file is written, so the write fails.
    blob = _tar([("ro", "dir", 0o555), ("ro/f", "file", 0)])
    real, dry = _both(
        lambda: io.BytesIO(blob),
        tmp_path,
        relative=relative,
        dest_name=dest_name,
        policy=ExtractionPolicy.TRUSTED,
    )
    (tmp_path / "real" / dest_name / "ro").chmod(0o755)
    assert real[-1][1] is ExtractionStatus.FAILED
    assert dry == real


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
@_NON_ROOT
def test_errors_and_warnings_name_dest(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_directories_at_once(monkeypatch)
    # The directory is locked before its file is written, so the write fails.
    blob = _tar([("ro", "dir", 0o555), ("ro/f", "file", 0)])
    dest = tmp_path / "out"
    with (
        caplog.at_level(logging.WARNING, logger="archivey"),
        open_archive(io.BytesIO(blob)) as reader,
    ):
        report = reader.extract_all(
            dest,
            policy=ExtractionPolicy.TRUSTED,
            on_error=OnError.CONTINUE,
            dry_run=True,
        )
    failed = report.results[-1]
    assert failed.status is ExtractionStatus.FAILED
    assert isinstance(failed.error, PermissionError)
    assert str(dest / "ro") in str(failed.error)
    assert "archivey-dry-run-" not in str(failed.error)
    assert str(dest / "ro") in caplog.text
    assert "archivey-dry-run-" not in caplog.text

    with (
        open_archive(io.BytesIO(blob)) as reader,
        pytest.raises(PermissionError) as caught,
    ):
        reader.extract_all(
            dest,
            policy=ExtractionPolicy.TRUSTED,
            on_error=OnError.STOP,
            dry_run=True,
        )
    assert str(dest / "ro") in str(caught.value)
    assert "archivey-dry-run-" not in str(caught.value)
    _assert_nothing_left(tmp_path, dest)


@pytest.mark.parametrize(
    "fd_walk",
    [False, *([True] if dry_run_module._FD_WALK else [])],
    ids=lambda v: "fd-walk" if v else "path-walk",
)
def test_scratch_is_removed_when_the_archive_locks_its_own_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fd_walk: bool
) -> None:
    # The directories get their modes when the run ends; the scratch directory is
    # removed after that, by either walk.
    monkeypatch.setattr(dry_run_module, "_FD_WALK", fd_walk)
    blob = _tar([("ro/f", "file", 0), ("ro", "dir", 0o555), ("zero", "dir", 0)])
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, policy=ExtractionPolicy.TRUSTED, dry_run=True)
    assert {r.status for r in report.results} == {ExtractionStatus.EXTRACTED}
    _assert_nothing_left(tmp_path, dest)


@pytest.mark.skipif(os.name == "nt", reason="PATH_MAX is a POSIX limit")
def test_scratch_is_removed_when_its_tree_is_deeper_than_path_max(
    tmp_path: Path,
) -> None:
    # Each directory is reached through a short symlink to it, so every member name
    # is short while the real paths in the scratch tree are longer than PATH_MAX.
    # Removing that tree by full path failed with ENAMETOOLONG, and the scratch
    # directory stayed in the temp directory. The deep part covers the descriptor
    # walk; a directory down there keeps no mode (its path is too long to set one,
    # as in a real run). The locked ``ro`` up front covers the chmod: its file
    # cannot be removed until ``ro`` is opened up. The last links resolve past
    # PATH_MAX, so the filter refuses them; the members under them still go in under
    # real directories named ``l``, so the tree stays deeper than PATH_MAX.
    component = "d" * 250
    depth = os.pathconf(tmp_path, "PC_PATH_MAX") // len(component) + 2
    entries: list[tuple[str, str, object]] = [("ro/f", "file", 0), ("ro", "dir", 0o555)]
    path = ""
    for _ in range(depth):
        entries.append((f"{path}{component}", "dir", None))
        entries.append((f"{path}l", "sym", component))
        path += "l/"
    entries.append((f"{path}f", "file", 0))
    entries.append((path.rstrip("/") + "/" + component, "dir", 0o555))
    blob = _tar(entries)
    dest = tmp_path / "out"
    with open_archive(io.BytesIO(blob)) as reader:
        report = reader.extract_all(dest, policy=ExtractionPolicy.TRUSTED, dry_run=True)
    blocked = [r.member for r in report.results if r.status is ExtractionStatus.BLOCKED]
    assert blocked
    assert all(m.type is MemberType.SYMLINK for m in blocked)
    assert {r.status for r in report.results} == {
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.BLOCKED,
    }
    _assert_nothing_left(tmp_path, dest)


def test_scratch_is_removed_on_abort_and_the_message_names_dest(
    tmp_path: Path,
) -> None:
    blob = _tar([("A", "file", 0), ("a", "file", 0)])
    dest = tmp_path / "out"
    with (
        open_archive(io.BytesIO(blob)) as reader,
        pytest.raises(NameCollisionError) as caught,
    ):
        reader.extract_all(dest, abort_on=[AbortOn.NAME_COLLISION], dry_run=True)
    assert display_path(dest / "A") in str(caught.value)
    assert "archivey-dry-run-" not in str(caught.value)
    _assert_nothing_left(tmp_path, dest)


# --- CLI ---------------------------------------------------------------------------


def _cli(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out=out, err=err)
    return code, err.getvalue()


def test_cli_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "bundle.tar"
    archive.write_bytes(_tar([("a", "file", b"x"), ("../up", "file", 0)]))
    monkeypatch.chdir(tmp_path)
    code, err = _cli(["x", "bundle.tar", "--dry-run", "--hide-progress"])
    assert code == EXIT_POLICY
    assert "would extract into bundle/" in err
    assert "blocked: ../up" in err
    assert "dry run, nothing written: 1 extracted" in err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.tar", "tmp"]
    assert list((tmp_path / "tmp").iterdir()) == []


def test_cli_dry_run_reports_peak_use_of_the_reader_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    py7zr = pytest.importorskip("py7zr")
    archive = tmp_path / "a.7z"
    # Above the 16 MiB dictionary py7zr compresses the archive header with, so the
    # member's declaration is the largest one checked.
    filters = [{"id": py7zr.FILTER_LZMA2, "preset": 9}]
    with py7zr.SevenZipFile(archive, "w", filters=filters) as out:
        out.writestr(b"x" * 1000, "a.txt")
    # The dictionary size the LZMA2 coder declares, from its one properties byte.
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
        (method,) = member.compression
        assert method.properties is not None
        prop = method.properties[0]
        declared = (2 | (prop & 1)) << (prop // 2 + 11)
    monkeypatch.chdir(tmp_path)
    code, err = _cli(["x", "a.7z", "--dry-run", "--hide-progress"])
    assert code == 0
    (line,) = [
        ln for ln in err.splitlines() if ln.startswith("peak use of the reader limits")
    ]
    assert f"decoder memory {declared} bytes (" in line
    assert "LZMA2 dictionary size" in line
    assert "listing 1 member, " in line
    # A real run does not print it.
    code, err = _cli(["x", "a.7z", "-d", "real", "--hide-progress"])
    assert code == 0
    assert "peak use of the reader limits" not in err


def test_cli_dry_run_reports_key_derivation_rounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    py7zr = pytest.importorskip("py7zr")
    pytest.importorskip("cryptography")
    archive = tmp_path / "a.7z"
    with py7zr.SevenZipFile(archive, "w", password="pw") as out:  # type: ignore[attr-defined]
        out.writestr(b"x" * 1000, "a.txt")
    monkeypatch.chdir(tmp_path)
    code, err = _cli(["x", "a.7z", "--password", "pw", "--dry-run", "--hide-progress"])
    assert code == 0
    (line,) = [
        ln for ln in err.splitlines() if ln.startswith("peak use of the reader limits")
    ]
    # py7zr derives 7zAES keys with 2**19 SHA-256 rounds, once for the one folder.
    assert f"{2**19} key-derivation rounds" in line


def test_cli_dry_run_prints_no_usage_line_when_every_part_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with tarfile.open(tmp_path / "a.tar", "w"):
        pass
    monkeypatch.chdir(tmp_path)
    code, err = _cli(["x", "a.tar", "--dry-run", "--hide-progress"])
    assert code == 0
    assert "dry run, nothing written: 0 extracted" in err
    assert "peak use of the reader limits" not in err


_SAME_AS_REAL = "same as the real run"  # the hoist line the real run printed, predicted

_TOO_LONG = "x" * 300  # longer than any filesystem's name limit: fails at write time


def _files(*names: str) -> list[tuple[str, str, object]]:
    return [(name, "file", b"x") for name in names]


@pytest.mark.parametrize(
    ("entries", "existing", "expected"),
    [
        (_files("src/a", "src/b"), None, "would move to src/\n"),
        (
            _files("bundle/a", "bundle/b"),
            None,
            "would remove wrapper; content at bundle/\n",
        ),
        (_files("src/a", "src/b"), "src", "would move to src/, which exists already"),
        # The root exists only because a member under it was given a directory.
        (_files(f"src/{_TOO_LONG}"), None, "would move to src/\n"),
        # The failed member's directory would be the file an earlier member wrote.
        (_files("a", "a/f"), None, "would move to a\n"),
        # The failure is creating the root itself: nothing is left to move.
        (_files(f"{_TOO_LONG}/f"), None, None),
        # ...so the one root a real run moves is the other one.
        (_files("good/f", f"{_TOO_LONG}/f"), None, "would move to good/\n"),
        # A link to itself. The loop is refused as an escape and the directory made
        # for it is left, which is moved.
        # Not skipped on Windows on purpose: without the symlink privilege the link
        # fails to be created instead. Whichever happens, the dry run has to say what
        # the real one did.
        ([("root/a", "sym", "a")], None, _SAME_AS_REAL),
    ],
    ids=[
        "moved",
        "flattened",
        "onto-existing",
        "only-a-failed-member",
        "failed-under-a-file",
        "failed-creating-the-root",
        "beside-a-root-that-failed",
        "blocked-after-its-directory",
    ],
)
def test_cli_dry_run_names_where_a_single_root_lands(
    entries: list[tuple[str, str, object]],
    existing: str | None,
    expected: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = _tar(entries)
    runs = {}
    for dry_run in (False, True):
        cwd = tmp_path / ("dry" if dry_run else "real")
        cwd.mkdir()
        (cwd / "bundle.tar").write_bytes(blob)
        if existing is not None:
            (cwd / existing).mkdir()
        monkeypatch.chdir(cwd)
        argv = ["x", "bundle.tar", "--hide-progress"]
        runs[dry_run] = _cli([*argv, "--dry-run"] if dry_run else argv)
    (real_code, real_err), (dry_code, dry_err) = runs[False], runs[True]
    if expected is None:
        assert "would move" not in dry_err
        assert "would remove wrapper" not in dry_err
    elif expected is _SAME_AS_REAL:
        predicted = [
            f"would move to {line[len('moved to ') :]}"
            if line.startswith("moved to ")
            else f"would keep in {line[len('kept in ') :]}"
            for line in real_err.splitlines()
            if line.startswith(("moved to ", "kept in "))
        ]
        assert len(predicted) == 1, real_err
        assert predicted[0] in dry_err.splitlines()
    else:
        assert expected in dry_err
    assert dry_code == real_code
    # The summary names where the real run put the content.
    assert (
        real_err.splitlines()[-1].split(" → ")[1]
        == (dry_err.splitlines()[-1].split(" → ")[1])
    )
    expected_left = ["bundle.tar"] + ([existing] if existing else [])
    assert sorted(p.name for p in (tmp_path / "dry").iterdir()) == expected_left
    assert list((tmp_path / "tmp").iterdir()) == []


def _zip(names: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return buf.getvalue()


@pytest.mark.parametrize(
    ("archive", "make", "extra"),
    [
        ("bundle.zip", lambda: _zip(["src/a", "src/b"]), []),
        ("bundle.zip", lambda: _zip(["only.txt"]), []),
        ("data.txt.gz", lambda: gzip.compress(b"x"), []),
        ("bundle.zip", lambda: _zip(["a", "b"]), ["-d", "."]),
    ],
    ids=["single-root-dir", "single-file", "raw-stream", "two-tops-into-cwd"],
)
def test_cli_dry_run_summary_names_what_extracts_into_the_cwd(
    archive: str,
    make: Callable[[], bytes],
    extra: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nothing is hoisted here: the content goes straight into the cwd, and the summary
    # names the single entry it lands as.
    blob = make()
    runs = {}
    for dry_run in (False, True):
        cwd = tmp_path / ("dry" if dry_run else "real")
        cwd.mkdir()
        (cwd / archive).write_bytes(blob)
        monkeypatch.chdir(cwd)
        argv = ["x", archive, "--hide-progress", *extra]
        runs[dry_run] = _cli([*argv, "--dry-run"] if dry_run else argv)
    (real_code, real_err), (dry_code, dry_err) = runs[False], runs[True]
    assert dry_code == real_code
    assert (
        real_err.splitlines()[-1].split(" → ")[1]
        == (dry_err.splitlines()[-1].split(" → ")[1])
    )
    assert [p.name for p in (tmp_path / "dry").iterdir()] == [archive]


def test_cli_dry_run_with_dest(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.tar"
    archive.write_bytes(_tar([("a", "file", b"x")]))
    dest = tmp_path / "out"
    code, err = _cli(
        ["x", str(archive), "-d", str(dest), "--dry-run", "--hide-progress"]
    )
    assert code == EXIT_OK
    assert "dry run, nothing written: 1 extracted" in err
    assert not dest.exists()
