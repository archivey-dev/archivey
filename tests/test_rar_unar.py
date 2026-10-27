"""``unar`` as the opt-in RAR data program (``ArchiveyConfig.rar_decompressor="unar"``).

Three layers, tested separately:

- the format-agnostic process layer (``archivey.internal.external``): identification,
  argv, exit-status mapping;
- the RAR policy (``rar_unar``): which reads are refused before ``unar`` runs;
- the reader end to end, against RARLAB ``unrar`` on every committed RAR fixture.

The parity test is the evidence for the policy: every member ``unar`` is allowed to read
must come back byte-identical to ``unrar``'s, and every member it is not allowed to read
must be refused with ``UnsupportedFeatureError``, never read wrong.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import (
    ArchiveReader,
    ArchiveyConfig,
    RarDecompressor,
    SpoolLimits,
    open_archive,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    PackageNotInstalledError,
    ReadError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import rar_parser, rar_reader, rar_unar
from archivey.internal.external import cli, unar
from tests.conftest import requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.test_unar_probe import GOOD_UNAR_EXTRACT

_RAR = Path(__file__).parent / "fixtures" / "rar"
_CORPUS = Path(__file__).parent / "fixtures" / "corpus" / "rar"
_UNAR = ArchiveyConfig(rar_decompressor=RarDecompressor.UNAR)
_UNRAR = ArchiveyConfig(rar_decompressor=RarDecompressor.UNRAR)
_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="uses POSIX shell scripts as stand-in binaries"
)


def _fixtures() -> list[Path]:
    paths = sorted(_RAR.glob("*.rar")) + sorted(_CORPUS.glob("*.rar"))
    # Later volumes of a set are read through volume 1.
    return [p for p in paths if ".part" not in p.name or ".part1." in p.name]


# Members unar must refuse, with the reason each refusal names. Anything not listed
# must read back exactly as unrar reads it.
_REFUSED: dict[tuple[str, str], str] = {
    **{
        ("basic_solid__.rar", name): "RAR5 solid"
        for name in ("file1.txt", "subdir/file2.txt", "implicit_subdir/file3.txt")
    },
    **{
        ("wildcard_names_solid__.rar", name): "RAR5 solid"
        for name in ("a*.txt", "aX.txt", "b?.txt", "b1.txt", "only*.dat")
    },
    ("rar15-comment.rar", "FILE1.TXT"): "RAR 1.5",
}
# Members unar 1.10.1 drops, and the members after them in a solid run, whose bytes
# then go missing or are stale: ``scripts/gen_rar_fixtures.py`` ``_build_unar_drop``.
# Each must read back exactly or fail as truncated or corrupt, never as wrong bytes.
_UNAR_DROPS: frozenset[tuple[str, str]] = frozenset(
    {
        ("unar_drop__.rar", "f.txt"),
        ("unar_drop_solid__.rar", "f.txt"),
        *(
            (fixture, name)
            for fixture in ("unar_stale_solid__.rar", "unar_stale_nocrc_solid__.rar")
            for name in ("c.txt", "d.txt", "e.txt")
        ),
    }
)
_DROP_ERRORS = ("TruncatedError", "CorruptionError")
# The password each encrypted fixture was written with.
_PASSWORDS = {
    "encryption__.rar": "password",
    "encryption__rar4.rar": "password",
    "encryption_large__rar4.rar": "password",
    "encryption_large_solid__rar4.rar": "password",
    "encryption_large_stored__rar4.rar": "password",
    "encryption_blake2sp.rar": "password",
    "encryption_solid__.rar": "password",
    "encryption_stored__.rar": "password",
    "encryption_stored_sizes__.rar": "password",
    "encryption_stored_sizes__rar4.rar": "password",
    "symlinks_encrypted__rar4.rar": "password",
    "encrypted.rar": "password",
    "encrypted-mixed.rar": "password",
    "encrypted_header__.rar": "header_password",
    "encrypted_header__rar4.rar": "header_password",
    "tinyvol_hp.part1.rar": "header_password",
    "tinyvol_enc.part1.rar": "password",
}
# RAR 2.x-4.x encryption: unar 1.10.1 returns nothing even with the right password.
_RAR4_ENCRYPTED = {
    "encryption__rar4.rar",
    "encrypted_header__rar4.rar",
    "encryption_large__rar4.rar",
    "encryption_large_solid__rar4.rar",
    "encryption_large_stored__rar4.rar",
    "encryption_stored_sizes__rar4.rar",
    "symlinks_encrypted__rar4.rar",
}
# Encrypted members of zero bytes.
_EMPTY_ENCRYPTED = {("encryption_stored_sizes__.rar", "size_0.bin")}
# A RAR5 volume set with encrypted headers: XADMaster 1.10.8 returns nothing.
_HEADER_ENCRYPTED_VOLUMES = {"tinyvol_hp.part1.rar"}


def _parity_cases() -> list[object]:
    cases: list[object] = []
    for path in _fixtures():
        cases.append(pytest.param(path, None, id=path.name))
        if path.name in _PASSWORDS:
            cases.append(
                pytest.param(path, _PASSWORDS[path.name], id=f"{path.name}-password")
            )
    return cases


def _outcome(read: object) -> str:
    try:
        data = read()  # type: ignore[operator]
    except ArchiveyError as exc:
        return f"{type(exc).__name__}: {exc}"
    assert isinstance(data, bytes)
    return hashlib.sha256(data).hexdigest()


def _read_members(
    path: Path,
    config: ArchiveyConfig,
    *,
    streamed: bool,
    password: str | None = None,
) -> dict:
    results: dict[str, str] = {}
    try:
        with open_archive(path, config=config, password=password) as archive:
            # Compressed old-style comments go through the selected program too.
            results["<comment>"] = repr(archive.info.comment)
            if streamed:
                for member, stream in archive.stream_members():
                    results[f"<comment> {member.name}"] = repr(member.comment)
                    if stream is not None:
                        results[member.name] = _outcome(stream.read)
            else:
                for member in archive.members():
                    results[f"<comment> {member.name}"] = repr(member.comment)
                    if member.is_file:
                        results[member.name] = _outcome(
                            lambda m=member: archive.read(m)
                        )
    except ArchiveyError as exc:
        results["<open>"] = f"{type(exc).__name__}: {exc}"
    return results


@requires_binary("unar", "unrar")
@pytest.mark.parametrize("streamed", [False, True], ids=["open", "stream"])
@pytest.mark.parametrize(("path", "password"), _parity_cases())
def test_unar_matches_unrar_or_refuses(
    path: Path, password: str | None, streamed: bool
) -> None:
    with_unrar = _read_members(path, _UNRAR, streamed=streamed, password=password)
    with_unar = _read_members(path, _UNAR, streamed=streamed, password=password)
    assert with_unar.keys() == with_unrar.keys()
    for name, got in with_unar.items():
        reason = _REFUSED.get((path.name, name))
        if path.name in _RAR4_ENCRYPTED and got.startswith("UnsupportedFeatureError"):
            assert "encrypted RAR 2.x-4.x data" in got
            continue
        if (
            path.name in _HEADER_ENCRYPTED_VOLUMES
            and password is not None
            and not name.startswith("<")
        ):
            assert got.startswith("UnsupportedFeatureError"), (name, got)
            assert "multi-volume RAR5 set with encrypted headers" in got
            continue
        if reason is not None:
            assert got.startswith("UnsupportedFeatureError"), (name, got)
            assert reason in got
            continue
        if with_unrar[name].startswith("UnsupportedFeatureError") and not (
            got.startswith("UnsupportedFeatureError")
        ):
            # unrar refuses glob names it cannot select by mask; unar selects by
            # index, so it reads them. Their bytes are checked against the digest.
            assert "include mask" in with_unrar[name] or "backslash" in with_unrar[name]
            continue
        if got.startswith("EncryptionError") and (
            with_unrar[name].startswith("EncryptionError")
            or (password is None and path.name in _PASSWORDS)
        ):
            # A missing or wrong password: same error type, each program's wording.
            # Without a password, unrar's solid pass reports a later member of the
            # same pipe as truncated; unar's pipe is empty, which says why.
            continue
        if (
            password is None
            and (path.name, name) in _EMPTY_ENCRYPTED
            and with_unrar[name].startswith("EncryptionError")
            and got == hashlib.sha256(b"").hexdigest()
        ):
            # An empty encrypted member with no password: unrar exits with its
            # password code, and unar writes the nothing there is to write. Only
            # without cryptography, which otherwise decrypts it for both.
            continue
        if (path.name, name) in _UNAR_DROPS and got.startswith(_DROP_ERRORS):
            continue
        assert got == with_unrar[name], name


def _unrar_bytes(path: Path) -> dict[str, bytes]:
    with open_archive(path, config=_UNRAR) as archive:
        return {m.name: archive.read(m) for m in archive.members() if m.is_file}


@requires_binary("unar", "unrar")
@pytest.mark.parametrize("how", ["read", "stream", "extract"])
@pytest.mark.parametrize(
    "name",
    [
        "unar_drop__.rar",
        "unar_drop_solid__.rar",
        "unar_stale_solid__.rar",
        "unar_stale_nocrc_solid__.rar",
    ],
)
def test_a_member_unar_drops_is_an_error_not_wrong_bytes(
    tmp_path: Path, name: str, how: str
) -> None:
    """unar 1.10.1 drops a compressed RAR5 member when a Huffman lookup peeks past
    its packed data, with exit 0. In one solid run over ``unar_stale_*``, ``c.txt`` is
    dropped and stale window bytes follow, so the bytes at ``c.txt``'s offset are not
    its own.
    ``unar_stale_nocrc_solid__.rar`` has ``c.txt``'s CRC32 removed: only a run of its
    own, which is exact or empty, keeps those bytes from being served as it."""
    path = _RAR / name
    expected = _unrar_bytes(path)
    got: dict[str, bytes | ArchiveyError] = {}
    with open_archive(path, config=_UNAR) as archive:
        if "nocrc" in name:
            assert not archive.get("c.txt").hashes
        if how == "read":
            for member in archive.members():
                if member.is_file:
                    try:
                        got[member.name] = archive.read(member)
                    except ArchiveyError as exc:
                        got[member.name] = exc
        elif how == "stream":
            for member, stream in archive.stream_members():
                if stream is not None:
                    try:
                        got[member.name] = stream.read()
                    except ArchiveyError as exc:
                        got[member.name] = exc
        else:
            report = archive.extract_all(tmp_path / "out", on_error="continue")
            for result in report:
                if result.error is not None:
                    assert isinstance(result.error, ArchiveyError), result
                    got[result.member.name] = result.error
                else:
                    assert result.path is not None
                    got[result.member.name] = result.path.read_bytes()
    assert got.keys() == expected.keys()
    for member_name, outcome in got.items():
        if isinstance(outcome, ArchiveyError):
            assert (name, member_name) in _UNAR_DROPS, (member_name, outcome)
            assert isinstance(outcome, (TruncatedError, CorruptionError)), outcome
        else:
            assert outcome == expected[member_name], member_name


@requires_binary("unar")
def test_glob_named_member_needs_no_escape_hatch() -> None:
    """unrar refuses ``a*.txt`` by default; unar names it by index and reads it alone."""
    path = _RAR / "wildcard_names__.rar"
    with open_archive(path, config=_UNAR) as archive:
        assert archive.read("a*.txt")


@requires_binary("unar", "unrar")
def test_member_before_the_first_empty_entry_still_streams() -> None:
    """The solid pass names only readable members, so unar never reaches the crash.

    ``subdir/aY.txt`` comes before the directory entry that makes unar 1.10.1 crash.
    An all-entries run would lose its last buffered bytes to that crash.
    """
    path = _RAR / "wildcard_names_solid__.rar"
    with open_archive(path, config=_UNRAR) as archive:
        expected = archive.read("subdir/aY.txt")
    with open_archive(path, config=_UNAR) as archive:
        for member, stream in archive.stream_members():
            if member.name == "subdir/aY.txt":
                assert stream is not None
                assert stream.read() == expected
                return
    raise AssertionError("subdir/aY.txt not streamed")


@requires_binary("unar")
def test_listing_a_refused_archive_is_not_refused() -> None:
    """Refusals are per read: a pass that reads nothing, or skips them, is fine."""
    path = _RAR / "basic_solid__.rar"
    with open_archive(path, config=_UNAR) as archive:
        names = [member.name for member, _stream in archive.stream_members()]
    assert "file1.txt" in names


@requires_binary("unar", "unrar")
@pytest.mark.parametrize("name", ["compressed.rar"], ids=str)
def test_prefixed_archive_is_copied_for_unar(tmp_path: Path, name: str) -> None:
    """unar finds no RAR after a prefix, so a prefixed archive is copied from its start."""
    original = (_CORPUS / name).read_bytes()
    prefixed = tmp_path / "prefixed.rar"
    prefixed.write_bytes(b"\x00" * 4096 + original)
    expected = _read_members(_CORPUS / name, _UNRAR, streamed=False)
    with open_archive(prefixed, config=_UNRAR) as archive:
        assert archive.cost.notes == ()
    with open_archive(prefixed, config=_UNAR) as archive:
        assert any("copy the whole archive" in n for n in archive.cost.notes)
        assert any("so unar can read it" in n for n in archive.cost.notes)
    assert _read_members(prefixed, _UNAR, streamed=False) == expected
    assert _read_members(prefixed, _UNAR, streamed=True) == expected
    with open_archive(
        io.BytesIO(prefixed.read_bytes()), format="rar", config=_UNAR
    ) as archive:
        got = {
            member.name: hashlib.sha256(archive.read(member)).hexdigest()
            for member in archive.members()
            if member.is_file
        }
    assert got == {k: v for k, v in expected.items() if not k.startswith("<comment>")}


def _unar_limited(max_bytes: int) -> ArchiveyConfig:
    return ArchiveyConfig(
        rar_decompressor=RarDecompressor.UNAR,
        spool_limits=SpoolLimits(max_bytes=max_bytes),
    )


def _file_digests(archive: ArchiveReader) -> dict[str, str]:
    return {
        member.name: hashlib.sha256(archive.read(member)).hexdigest()
        for member in archive.members()
        if member.is_file
    }


@requires_binary("unar", "unrar")
def test_prefixed_stream_copy_for_unar_is_bounded_by_the_spool_limit() -> None:
    """A prefixed stream is copied for unar from where the RAR starts, and that copy
    is a spool copy like unrar's: a limit below its size refuses the read."""
    original = (_CORPUS / "compressed.rar").read_bytes()
    prefixed = b"\x00" * 4096 + original
    with open_archive(io.BytesIO(prefixed), format="rar", config=_UNRAR) as archive:
        expected = _file_digests(archive)
    with open_archive(
        io.BytesIO(prefixed), format="rar", config=_unar_limited(len(original))
    ) as archive:
        assert _file_digests(archive) == expected
    with open_archive(
        io.BytesIO(prefixed), format="rar", config=_unar_limited(len(original) - 1)
    ) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes"):
            archive.read(member)


def _spy_links(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the names ``unar``'s private directory is given."""
    names: list[str] = []
    link = rar_reader._link_file

    def spy(source: Path, dest: Path) -> None:
        names.append(dest.name)
        link(source, dest)

    monkeypatch.setattr(rar_reader, "_link_file", spy)
    return names


@requires_binary("unar")
def test_a_single_archive_is_linked_as_archive_rar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single archive gets a name no other file continues; a set keeps its scheme."""
    names = _spy_links(monkeypatch)
    with open_archive(_CORPUS / "compressed.rar", config=_UNAR) as archive:
        _file_digests(archive)
    assert names == ["archive.rar"]
    names.clear()
    # Compressed, so unar reads it; a stored split member is joined natively.
    with open_archive(_RAR / "tinyvol_m3.part1.rar", config=_UNAR) as archive:
        _file_digests(archive)
    assert names == ["archive.part1.rar", "archive.part2.rar"]


def _no_links(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("links refused for this test")

    monkeypatch.setattr(os, "symlink", refuse)
    monkeypatch.setattr(os, "link", refuse)


@requires_binary("unar", "unrar")
@pytest.mark.parametrize(
    "names",
    [
        (_CORPUS / "compressed.rar",),
        # Compressed, so unar reads it; a stored split member is joined natively.
        (_RAR / "tinyvol_m3.part1.rar", _RAR / "tinyvol_m3.part2.rar"),
    ],
    ids=["single", "volumes"],
)
def test_a_volume_that_cannot_be_linked_is_copied_within_the_spool_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, names: tuple[Path, ...]
) -> None:
    """Where the system allows neither link, unar gets a copy, and the copy is spooled
    like any other: read correctly within the limit, refused over it."""
    # This test's own temp root: the shared one also holds other xdist workers' dirs.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with open_archive(names[0], format="rar", config=_UNRAR) as archive:
        expected = _file_digests(archive)
    total = sum(path.stat().st_size for path in names)
    _no_links(monkeypatch)
    with open_archive(names[0], format="rar", config=_unar_limited(total)) as archive:
        assert _file_digests(archive) == expected
    before = set(tmp_path.glob("archivey-unar-*"))
    with open_archive(
        names[0], format="rar", config=_unar_limited(total - 1)
    ) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes"):
            archive.read(member)
        # The links failed, so the directory was made; the refused copy removed it.
        assert set(tmp_path.glob("archivey-unar-*")) == before


@requires_binary("unar", "unrar")
def test_a_stream_source_is_copied_once_into_unars_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stream source is copied once, straight into unar's private directory, so it is
    charged once against the spool limit: it reads at a limit of exactly its size and
    is refused one byte under, before any directory is made (review round 2, K11)."""
    # This test's own temp root: the shared one also holds other xdist workers' dirs.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    path = _CORPUS / "compressed.rar"
    data = path.read_bytes()
    with open_archive(path, format="rar", config=_UNRAR) as archive:
        expected = _file_digests(archive)
    config = _unar_limited(len(data))
    with open_archive(io.BytesIO(data), format="rar", config=config) as archive:
        assert _file_digests(archive) == expected
    before = set(tmp_path.glob("archivey-unar-*"))
    config = _unar_limited(len(data) - 1)
    with open_archive(io.BytesIO(data), format="rar", config=config) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes"):
            archive.read(member)
        assert set(tmp_path.glob("archivey-unar-*")) == before


@requires_binary("unar", "rar")
def test_numbered_neighbour_is_not_read_as_the_next_volume(tmp_path: Path) -> None:
    """unar picks a volume set by file name: ``backup2.rar`` beside ``backup1.rar``
    must still read as itself, not as volume 2 of a set that starts at its neighbour.
    """
    for number in (1, 2):
        source = tmp_path / f"src{number}" / "data.txt"
        source.parent.mkdir()
        source.write_bytes(f"contents of archive {number}\n".encode() * 50)
        subprocess.run(
            ["rar", "a", "-idq", "-ep", "-m3", str(tmp_path / f"backup{number}.rar")]
            + [str(source)],
            check=True,
        )
    for number in (1, 2):
        with open_archive(tmp_path / f"backup{number}.rar", config=_UNAR) as archive:
            assert archive.read("data.txt") == (
                f"contents of archive {number}\n".encode() * 50
            )


@requires_binary("unar")
def test_seekable_member_respawns_unar() -> None:
    path = _RAR / "seek_respawn_solid__.rar"
    with (
        open_archive(path, config=_UNAR, seekable_members=True) as archive,
        archive.open("tail.txt") as stream,
    ):
        first = stream.read()
        stream.seek(0)
        assert stream.read() == first


# --- selection is explicit -----------------------------------------------------------


@requires_binary("unrar")
def test_unrar_setting_never_runs_unar(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unar spawned with unrar selected")

    monkeypatch.setattr(rar_reader, "open_unar_stdout", refuse)
    with open_archive(_CORPUS / "compressed.rar", config=_UNRAR) as archive:
        for member, stream in archive.stream_members():
            if stream is not None:
                stream.read()
                assert member.name


def test_selected_unar_missing_does_not_fall_back_to_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    unar.clear_unar_cache()
    with open_archive(_CORPUS / "compressed.rar", config=_UNAR) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(PackageNotInstalledError, match="unar 1.10 or later"):
            archive.read(member)


def test_config_accepts_the_name() -> None:
    config = ArchiveyConfig(rar_decompressor="UNAR")  # pyright: ignore[reportArgumentType]
    assert config.rar_decompressor is RarDecompressor.UNAR
    config = ArchiveyConfig(rar_decompressor="auto")  # pyright: ignore[reportArgumentType]
    assert config.rar_decompressor is RarDecompressor.AUTO
    assert ArchiveyConfig().rar_decompressor is RarDecompressor.AUTO


_AUTO = ArchiveyConfig(rar_decompressor=RarDecompressor.AUTO)


def _path_with(tmp_path: Path, *programs: str) -> str:
    """A PATH holding only links to the named programs."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for program in programs:
        found = shutil.which(program)
        assert found is not None
        (bin_dir / program).symlink_to(found)
    return str(bin_dir)


@requires_binary("unar", "unrar")
def test_auto_prefers_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unar spawned while unrar is available")

    monkeypatch.setattr(rar_reader, "open_unar_stdout", refuse)
    with open_archive(_CORPUS / "compressed.rar", config=_AUTO) as archive:
        assert rar_reader.AUTO_CHOSE_UNAR_NOTE not in archive.cost.notes
        for member in archive.members():
            if member.is_file:
                archive.read(member)


@_posix_only
@requires_binary("unar", "unrar")
def test_auto_uses_unar_when_unrar_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    expected = _read_members(_CORPUS / "compressed.rar", _UNRAR, streamed=False)
    monkeypatch.setenv("PATH", _path_with(tmp_path, "unar"))
    unar.clear_unar_cache()
    spawned: list[object] = []
    real = rar_reader.open_unar_stdout

    def counting(*args: object, **kwargs: object) -> object:
        spawned.append(args)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unar_stdout", counting)
    assert _read_members(_CORPUS / "compressed.rar", _AUTO, streamed=False) == expected
    with open_archive(_CORPUS / "compressed.rar", config=_AUTO) as archive:
        assert archive.cost.notes[0] == rar_reader.AUTO_CHOSE_UNAR_NOTE
    assert spawned


@_posix_only
def test_auto_with_neither_names_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    unar.clear_unar_cache()
    with open_archive(_CORPUS / "compressed.rar", config=_AUTO) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(PackageNotInstalledError, match="RARLAB"):
            archive.read(member)


@requires_binary("unar")
def test_wrong_password_is_an_encryption_error() -> None:
    with (
        open_archive(
            _RAR / "encryption__.rar", config=_UNAR, password="wrong"
        ) as archive,
        pytest.raises(EncryptionError),
    ):
        archive.read("secret.txt")


@requires_binary("unar")
def test_empty_pipe_for_encrypted_data_is_a_password_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """unar answers a wrong password with exit 0 and no bytes; that is not truncation.

    The RAR5 PswCheck stops a wrong password before unar runs, so the check is
    skipped here to let one reach unar.
    """
    monkeypatch.setattr(rar_reader, "_psw_check_usable", lambda _enc: False)
    with (
        open_archive(
            _RAR / "encryption__.rar", config=_UNAR, password="wrong"
        ) as archive,
        pytest.raises(EncryptionError, match="missing or wrong"),
    ):
        archive.read("secret.txt")


@requires_binary("unar", "rar")
@pytest.mark.parametrize(
    ("password", "readable"),
    [("-starts with a dash", True), ("ünïcode", False)],
    ids=["dash", "non-ascii"],
)
def test_password_on_the_command_line(
    tmp_path: Path, password: str, readable: bool
) -> None:
    """A password is a separate argv item, so a leading ``-`` is still the value.

    unar 1.10.1 does not decrypt with a non-ASCII password, so one is refused.
    """
    (tmp_path / "f.txt").write_bytes(b"hello\n")
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", f"-p{password}", "t.rar", "f.txt"],
        cwd=tmp_path,
        check=True,
    )
    with open_archive(tmp_path / "t.rar", config=_UNAR, password=password) as archive:
        if readable:
            assert archive.read("f.txt") == b"hello\n"
        else:
            with pytest.raises(UnsupportedFeatureError, match="not ASCII"):
                archive.read("f.txt")


# --- argv -----------------------------------------------------------------------------


def test_argv_names_entries_by_index_after_a_terminator() -> None:
    cmd = unar.unar_argv("/bin/unar", "-x.rar", [3, 0])
    assert cmd[:8] == ["/bin/unar", "-o", "-", "-q", "-nr", "-k", "skip", "-i"]
    assert cmd[8] == "--"
    assert Path(cmd[9]).is_absolute() and cmd[9].endswith("-x.rar")
    assert cmd[10:] == ["3", "0"]


def test_argv_puts_the_password_before_the_terminator() -> None:
    cmd = unar.unar_argv("/bin/unar", "/a.rar", [0], password="-p x")
    assert cmd[cmd.index("-p") + 1] == "-p x"
    assert cmd.index("-p") < cmd.index("--")
    with pytest.raises(ValueError, match="non-ASCII"):
        unar.unar_argv("/bin/unar", "/a.rar", [0], password="é")


def test_argv_without_indexes_selects_all() -> None:
    cmd = unar.unar_argv("/bin/unar", "/a.rar", None)
    assert "-i" not in cmd
    assert cmd[-2:] == ["--", str(Path("/a.rar").absolute())]


@pytest.mark.parametrize("indexes", [[], [-1]])
def test_argv_refuses_an_empty_or_negative_selection(indexes: list[int]) -> None:
    # `unar -i` with no index selects every entry; that is never what [] means.
    with pytest.raises(ValueError):
        unar.unar_argv("/bin/unar", "/a.rar", indexes)


# --- identification -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "unar v1.10.1, a tool for extracting the contents of archive files.\n",
            cli.Banner(identified=True, version=(1, 10, 1)),
        ),
        (
            "unar v1.10.7, a tool for extracting the contents of archive files.",
            cli.Banner(identified=True, version=(1, 10, 7)),
        ),
        (
            # Homebrew's bottle (XADMaster 1.10.8) prints its build date.
            (
                "unar v1.10.7 (Oct 10 2023), a tool for extracting the contents of "
                "archive files."
            ),
            cli.Banner(identified=True, version=(1, 10, 7)),
        ),
        ("unar v1.10.1\n", cli.Banner(identified=False, version=None)),
        ("UNRAR 7.00 freeware\n", cli.Banner(identified=False, version=None)),
        (
            "unar v" + "9" * 5000 + ".1, a tool for extracting",
            cli.Banner(identified=False, version=None),
        ),
    ],
)
def test_banner(text: str, expected: cli.Banner) -> None:
    assert unar.parse_unar_banner(text) == expected


def _stand_in(directory: Path, script: str) -> Path:
    binary = directory / "unar"
    binary.write_text("#!/bin/sh\n" + script)
    binary.chmod(0o755)
    return binary


@pytest.fixture
def fresh_unar_cache() -> object:
    unar.clear_unar_cache()
    yield
    unar.clear_unar_cache()


@_posix_only
@pytest.mark.usefixtures("fresh_unar_cache")
def test_lookalike_is_refused_and_probed_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "probes"
    _stand_in(tmp_path, f'echo x >> "{marker}"\necho "something else"\n')
    monkeypatch.setenv("PATH", str(tmp_path))
    for _ in range(3):
        with pytest.raises(PackageNotInstalledError, match="not found on PATH"):
            unar.find_unar(purpose="for a test")
    assert marker.read_text().count("x") == 1


@_posix_only
@pytest.mark.usefixtures("fresh_unar_cache")
def test_too_old_is_refused_with_its_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, 'echo "unar v1.9.2, a tool for extracting the contents"\n')
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError, match=r"reports version 1\.9\.2"):
        unar.find_unar(purpose="for a test")


@_posix_only
@pytest.mark.usefixtures("fresh_unar_cache")
def test_hung_probe_costs_one_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "probes"
    _stand_in(tmp_path, f'echo x >> "{marker}"\nexec sleep 60\n')
    # The stand-in comes first; the rest of PATH is kept so it can find ``sleep``.
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(cli, "PROBE_TIMEOUT_SECONDS", 0.2)
    for _ in range(3):
        with pytest.raises(PackageNotInstalledError, match="0.2 seconds"):
            unar.find_unar(purpose="for a test")
    assert marker.read_text().count("x") == 1


@_posix_only
@pytest.mark.usefixtures("fresh_unar_cache")
def test_replaced_binary_is_probed_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, 'echo "not it"\n')
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError):
        unar.find_unar(purpose="for a test")
    # Past the banner, ``find_unar`` checks that the program decodes a RAR5 member
    # (``tests/test_unar_probe.py``); this one prints that member for any other argv.
    binary = _stand_in(
        tmp_path,
        'if [ "$1" = "-h" ]; then\n'
        '  echo "unar v1.10.8, a tool for extracting the contents of"; exit 0\n'
        "fi\n" + GOOD_UNAR_EXTRACT,
    )
    assert unar.find_unar(purpose="for a test") == os.path.abspath(binary)


# --- exit status ----------------------------------------------------------------------


def _child(script: str) -> tuple[subprocess.Popen[bytes], unar.UnarOutputStream]:
    proc = subprocess.Popen(
        [sys.executable, "-c", script], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL
    )
    assert proc.stdout is not None
    return proc, unar.UnarOutputStream(
        proc.stdout,  # type: ignore[arg-type]
        proc,
        has_verifiable_digest=False,
    )


def test_failure_exit_raises_on_the_completing_read() -> None:
    _proc, stream = _child("import sys; sys.stdout.write('abc'); sys.exit(1)")
    assert stream.read(3) == b"abc"
    with raises_corruption_not_truncation(match="exit 1"):
        stream.read()
    stream.close()


def test_a_zero_length_read_is_not_end_of_file() -> None:
    proc, stream = _child("import sys; sys.exit(1)")
    proc.wait()
    assert stream.read(0) == b""
    assert stream.readinto(bytearray()) == 0
    with raises_corruption_not_truncation(match="exit 1"):
        stream.read()
    stream.close()


@_posix_only
def test_crash_raises_on_the_completing_read() -> None:
    _proc, stream = _child("import os, signal; os.kill(os.getpid(), signal.SIGSEGV)")
    with pytest.raises(ReadError, match="signal"):
        stream.read()
    stream.close()


def test_a_program_archivey_stops_after_end_of_file_is_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A program that closed stdout but exits slower than the wait at end of file is
    stopped by close(); the signal is archivey's own, so the full read is not an error.
    """
    monkeypatch.setattr(unar.UnarOutputStream, "_EOF_EXIT_WAIT", 0.05)
    proc, stream = _child(
        "import os, sys, time\n"
        "sys.stdout.buffer.write(b'x' * 10); sys.stdout.flush()\n"
        "os.close(1); time.sleep(2)"
    )
    assert stream.read() == b"x" * 10
    assert stream.read() == b""
    stream.close()
    assert proc.returncode is not None


def test_close_before_end_of_file_is_not_an_error() -> None:
    proc, stream = _child("import sys\nwhile True: sys.stdout.write('x' * 65536)")
    assert stream.read(10) == b"x" * 10
    stream.close()
    assert proc.returncode is not None


def test_a_stream_that_cannot_be_built_stops_its_process() -> None:
    """The stream owns the process from its constructor: a raise there reaps it.

    The raise itself must reap, not the collection of the half-built stream
    (``IOBase.__del__`` calls ``close()`` on it too). Binding ``refused`` keeps its
    traceback, and with it the half-built stream, alive past the assertion.

    The raise comes from the inner's ``seekable()``, which
    ``DelegatingStream.__init__`` asks last, through ``is_seekable``; that lets
    anything but ``AttributeError`` through, as a closed file's ``ValueError``
    would. A raise from there leaves every field ``close()`` reads set, so the
    finalizer's ``close()`` succeeds. Replacing the whole ``__init__`` instead
    left fields unset, and that ``close()`` raised ``AttributeError`` as an
    unraisable warning whenever the stream was collected.
    """

    class _RefusesSeekable(io.RawIOBase):
        def __init__(self, inner: BinaryIO) -> None:
            super().__init__()
            self._inner = inner

        def seekable(self) -> bool:
            raise RuntimeError("wrapper refused")

        def close(self) -> None:
            self._inner.close()
            super().close()

    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    try:
        with pytest.raises(RuntimeError, match="wrapper refused") as refused:
            unar.UnarOutputStream(
                _RefusesSeekable(proc.stdout),  # type: ignore[arg-type]
                proc,
                has_verifiable_digest=False,
            )
        assert proc.returncode is not None
        del refused
    finally:
        proc.stdout.close()
        cli.terminate_process(proc)


def test_digest_checked_pipe_ignores_the_exit_status() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.exit(2)"],
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    stream = unar.UnarOutputStream(
        proc.stdout,  # type: ignore[arg-type]
        proc,
        has_verifiable_digest=True,
    )
    assert stream.read() == b""
    stream.close()


@requires_binary("unar")
def test_refusal_names_the_way_out() -> None:
    with (
        open_archive(
            _RAR / "encryption__rar4.rar", config=_UNAR, password="password"
        ) as archive,
        pytest.raises(UnsupportedFeatureError) as info,
    ):
        archive.read("secret.txt")
    assert "rar_decompressor to 'unrar'" in str(info.value)


def test_rar4_member_after_encrypted_data_in_its_solid_stream_is_refused() -> None:
    """``open()`` refuses a plain member that unar reaches only through encrypted data.

    ``rar`` 6.23 will not append a plain member to a solid RAR4 archive that starts
    with an encrypted one, so the first member of a solid fixture is marked
    encrypted after parsing. No program runs: this checks the refusal only.
    """
    with open(_RAR / "basic_solid__rar4.rar", "rb") as f:
        archive = rar_parser.parse_rar_archive(f)
    compressed = [m for m in archive.members if not rar_unar.uses_no_dictionary(m)]
    assert len(compressed) >= 2 and all(m.file_solid for m in compressed[1:])
    compressed[0].is_encrypted = True
    policy = rar_unar.UnarRarPolicy(archive)
    for info in compressed[1:]:
        reason = policy.member_refusal(info)
        assert reason == rar_unar.REFUSE_RAR4_AFTER_ENCRYPTED
        assert "encrypted RAR 2.x-4.x data" in reason
    compressed[1].file_solid = False
    policy = rar_unar.UnarRarPolicy(archive)
    assert policy.member_refusal(compressed[1]) is None


@requires_binary("unar")
def test_solid_pass_refuses_readable_members_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pass that names members stops at the cap; a member past it still opens alone.

    The fixture has no member unar refuses, so the last payload member is marked
    refused to make the pass name members, and the cap is lowered to one.
    """

    def refuse_last(archive: object) -> set[int]:
        payload = [m for m in archive.members if m.is_payload_file()]  # type: ignore[attr-defined]
        return {id(payload[-1])}

    monkeypatch.setattr(rar_unar, "_rar5_solid_after_empty", refuse_last)
    monkeypatch.setattr(rar_unar, "MAX_SELECTED_ENTRIES", 1)
    path = _RAR / "basic_solid__rar4.rar"
    outcomes: dict[str, str] = {}
    with open_archive(path, config=_UNAR) as archive:
        for member, stream in archive.stream_members():
            if stream is not None:
                outcomes[member.name] = _outcome(stream.read)
        past_cap = [name for name, got in outcomes.items() if "at most" in got]
        read = [name for name, got in outcomes.items() if "Error" not in got]
        assert len(read) == 1, outcomes
        assert past_cap, outcomes
        assert len(archive.read(past_cap[0])) == archive.get(past_cap[0]).size


@requires_binary("unar", "unrar")
@pytest.mark.parametrize(
    "names",
    [
        ("tinyvol.part1.rar", "tinyvol.part2.rar"),
        ("tinyvol_rnn.rar", "tinyvol_rnn.r00"),
    ],
    ids=["partN", "old-style"],
)
def test_stream_volume_set_reads_with_unar(
    monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...]
) -> None:
    """Stream volumes are written under names archivey picks; both programs must find
    them. unar looks for volume 2 only under the scheme the header names. The members
    are stored, which the reader would join itself, so slicing is turned off."""
    monkeypatch.setattr(
        rar_reader.RarReader, "_is_directly_sliceable", lambda self, info: False
    )
    expected = _read_members(_RAR / names[0], _UNRAR, streamed=False)

    def streams() -> list[io.BytesIO]:
        return [io.BytesIO((_RAR / name).read_bytes()) for name in names]

    for config, streamed in itertools.product((_UNRAR, _UNAR), (False, True)):
        with open_archive(streams(), config=config) as archive:
            if streamed:
                got = {
                    member.name: _outcome(stream.read)
                    for member, stream in archive.stream_members()
                    if stream is not None
                }
            else:
                got = {
                    member.name: _outcome(lambda m=member: archive.read(m))
                    for member in archive.members()
                    if member.is_file
                }
        assert got == {
            k: v for k, v in expected.items() if not k.startswith("<comment>")
        }


def test_unrar_name_walk_on_an_unencodable_next_name_is_not_found(
    tmp_path: Path,
) -> None:
    """The name after an extension of U+D7FF and ``99`` holds a lone surrogate.

    A POSIX filesystem cannot encode it, and ``os.stat`` raised
    ``UnicodeEncodeError`` out of ``open_archive`` for an explicit sequence starting
    with such a volume. A name that cannot exist on disk is one unrar cannot find.
    """
    paths = [tmp_path / "a.\ud7ff99", tmp_path / "b.rar"]
    assert not rar_reader._unrar_finds_exactly(
        paths, is_volume=True, old_numbering=True
    )


@pytest.mark.parametrize(
    ("extra", "old_numbering", "in_place"),
    [
        (None, False, True),
        ("x.part3.rar", False, False),
        # unrar retries the old-scheme name of the last volume when the
        # new-scheme one is missing (``OldSchemeTested`` in ``volume.cpp``).
        ("x.part2.r00", False, False),
        (None, True, False),
    ],
)
def test_unrar_in_place_check_covers_the_old_scheme_retry(
    tmp_path: Path, extra: str | None, old_numbering: bool, in_place: bool
) -> None:
    """unrar is pointed at the given files only when no file beside the last one
    answers to a name it would try next, under either scheme. A new-numbering
    header on ``partN`` names otherwise reads in place; an old-numbering one looks
    for ``x.part1.r00`` after volume 1, so it is staged."""
    paths = [tmp_path / "x.part1.rar", tmp_path / "x.part2.rar"]
    for path in paths:
        path.write_bytes(b"")
    if extra is not None:
        (tmp_path / extra).write_bytes(b"")
    assert (
        rar_reader._unrar_finds_exactly(
            paths, is_volume=True, old_numbering=old_numbering
        )
        is in_place
    )


@requires_binary("unar")
@pytest.mark.parametrize("streamed", [False, True])
def test_unar_is_refused_past_its_old_style_volume_limit(
    monkeypatch: pytest.MonkeyPatch, streamed: bool
) -> None:
    """unar stops after ``.z99`` (901 volumes) and calls the member damaged, so a
    longer old-style set is refused before unar runs. The limit is lowered to one
    so the two-volume fixture stands in for a 902-volume set. The fixture's member is
    stored, which the reader would join itself, so slicing is turned off."""
    monkeypatch.setattr(rar_reader, "_UNAR_MAX_OLD_STYLE_VOLUMES", 1)
    monkeypatch.setattr(
        rar_reader.RarReader, "_is_directly_sliceable", lambda self, info: False
    )
    names = ("tinyvol_rnn.rar", "tinyvol_rnn.r00")
    source: object = (
        [io.BytesIO((_RAR / name).read_bytes()) for name in names]
        if streamed
        else _RAR / names[0]
    )
    with open_archive(source, config=_UNAR) as archive:  # type: ignore[arg-type]
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(UnsupportedFeatureError, match="old-style"):
            archive.read(member)
