"""Native RAR reader cross-checks against rarfile."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from archivey.types import (
    EXTRA_RAR_EXTRACT_VERSION,
    CompressionAlgorithm,
)
from tests.conftest import requires, requires_unrar_cli
from tests.sample_archives import CORPUS, CorpusEntry, corpus_archive_path

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

_ORACLE_FIXTURES = [
    pytest.param("basic_nonsolid__.rar", None, id="basic-rar5"),
    pytest.param("basic_nonsolid__rar4.rar", None, id="basic-rar4"),
    pytest.param("basic_solid__.rar", None, id="solid-rar5"),
    pytest.param("basic_solid__rar4.rar", None, id="solid-rar4"),
    pytest.param("encryption__.rar", "password", id="enc-rar5"),
    pytest.param("encrypted_header__.rar", "header_password", id="hdr-rar5"),
    pytest.param("xtime__.rar", None, id="xtime-rar5"),
    pytest.param("xtime__rar4.rar", None, id="xtime-rar4"),
]


def _rarfile():
    return pytest.importorskip("rarfile")


def _fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path


def _norm_ts(dt: datetime) -> datetime:
    """Truncate to microseconds (we drop RAR5 ns); keep naive vs aware.

    rarfile hands back its ``nsdatetime`` subclass when a RAR5 time has a
    sub-microsecond part, and its ``__eq__`` compares the nanoseconds too.
    ``datetime.combine`` rebuilds a plain ``datetime``, which drops them.
    """
    dt = datetime.combine(dt.date(), dt.timetz())
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=UTC)
    return dt


def _assert_compression_matches(member, info) -> None:
    method = member.compression[0]
    compress_type = info.compress_type
    assert member.extra[EXTRA_RAR_EXTRACT_VERSION] == info.extract_version
    if compress_type == 0x30:
        assert method.algo is CompressionAlgorithm.STORED
        assert method.level is None
    elif 0x31 <= compress_type <= 0x35:
        assert method.algo is CompressionAlgorithm.RAR
        assert method.level == compress_type - 0x30
    else:
        assert method.algo is CompressionAlgorithm.UNKNOWN
        assert method.level is None


def _assert_timestamps_match(member, info) -> None:
    for field, native, oracle in (
        ("modified", member.modified, getattr(info, "mtime", None)),
        # rarfile reports the raw creation slot whatever the host; archivey reports
        # it as ``created`` from a birth-time host and as ``ctime`` otherwise.
        (
            "created/ctime",
            member.created or member.ctime,
            getattr(info, "ctime", None),
        ),
        ("accessed", member.accessed, getattr(info, "atime", None)),
    ):
        if native is None and oracle is None:
            continue
        assert native is not None, f"{field}: native None, rarfile={oracle}"
        assert oracle is not None, f"{field}: rarfile None, native={native}"
        n, o = _norm_ts(native), _norm_ts(oracle)
        assert n == o, f"{field}: native={n} rarfile={o}"


@requires("rarfile")
@requires_unrar_cli()
@pytest.mark.parametrize(("name", "password"), _ORACLE_FIXTURES)
def test_native_rar_matches_rarfile_metadata_and_bytes(
    name: str, password: str | None
) -> None:
    rarfile = _rarfile()
    archive = _fixture(name)
    if "header" in name:
        pytest.importorskip("cryptography")

    with rarfile.RarFile(archive) as oracle:
        if password:
            oracle.setpassword(password)
        oracle_infos = {
            info.filename.replace("\\", "/").rstrip("/"): info
            for info in oracle.infolist()
            if not info.is_dir()
        }
        oracle_bytes = {
            filename: oracle.read(info)
            for filename, info in oracle_infos.items()
            if not getattr(info, "is_symlink", lambda: False)()
            and not getattr(info, "redir_type", None)
        }

    with open_archive(archive, password=password) as native:
        native_files = {
            member.name.rstrip("/"): member
            for member in native.members()
            if member.type is MemberType.FILE
        }
        # rarfile omits ``-ver`` history rows; those are covered by dedicated
        # file-version tests and must not break list equality here.
        native_for_oracle = {
            name: member
            for name, member in native_files.items()
            if "rar.file_version" not in member.extra
        }
        assert set(native_for_oracle) == set(oracle_infos), (
            f"member name mismatch for {name}: "
            f"only_native={sorted(set(native_for_oracle) - set(oracle_infos))} "
            f"only_rarfile={sorted(set(oracle_infos) - set(native_for_oracle))}"
        )
        # Compare file members that rarfile exposes as regular files.
        common = set(native_for_oracle) & set(oracle_bytes)
        assert common, "expected overlapping file members with rarfile"
        for filename in common:
            member = native_for_oracle[filename]
            info = oracle_infos[filename]
            assert member.size == info.file_size
            assert native.read(member) == oracle_bytes[filename]
            _assert_timestamps_match(member, info)
            _assert_compression_matches(member, info)


@requires("rarfile")
@requires_unrar_cli()
@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(entry, id=entry.id)
        for entry in CORPUS
        if entry.id in {"basic", "encoding", "permissions"} and "rar" in entry.formats
    ],
)
def test_corpus_rar_matches_rarfile(entry: CorpusEntry, tmp_path: Path) -> None:
    """Native reader vs rarfile on committed corpus RAR fixtures (no ``rar`` writer)."""
    rarfile = _rarfile()
    archive = corpus_archive_path(entry, "rar", tmp_path)
    password = entry.passwords[0] if entry.passwords else None

    with rarfile.RarFile(archive) as oracle:
        if password:
            oracle.setpassword(password)
        oracle_files = {
            info.filename.replace("\\", "/"): oracle.read(info)
            for info in oracle.infolist()
            if not info.is_dir()
        }

    with open_archive(archive, password=password) as native:
        # Exclude WinRAR ``-ver`` history (rarfile omits these rows).
        native_files = {
            member.name: native.read(member)
            for member in native.members()
            if member.type is MemberType.FILE and "rar.file_version" not in member.extra
        }
        assert native_files == oracle_files
