"""Stored, encrypted RAR members that archivey decrypts itself, without a program.

A stored member's packed bytes are its content once decrypted, so with
``cryptography`` installed archivey reads it under every ``rar_decompressor`` value,
``NONE`` included: AES-128 for RAR 2.9-4, AES-256 for RAR5. A member split across
volumes, a compressed one, or any of them without ``cryptography`` still needs a
program.
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, RarDecompressor, open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    PackageNotInstalledError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import rar_reader, rar_unrar
from tests.conftest import requires, requires_binary, requires_unrar_cli

_RAR = Path(__file__).parent / "fixtures" / "rar"
_RAR5 = _RAR / "encryption_stored_sizes__.rar"
_RAR4 = _RAR / "encryption_stored_sizes__rar4.rar"
_SIZES = (0, 7, 16, 3000, 3001)
_NONE = ArchiveyConfig(rar_decompressor=RarDecompressor.NONE)
_UNRAR = ArchiveyConfig(rar_decompressor=RarDecompressor.UNRAR)


def _payload(size: int) -> bytes:
    """The bytes ``scripts/gen_rar_fixtures.py`` (``_hex_lines``) wrote."""
    lines = (
        hashlib.sha256(b"stored_sizes" + i.to_bytes(4, "big")).hexdigest().encode()
        + b"\n"
        for i in range(size // 65 + 1)
    )
    return b"".join(lines)[:size]


def _refuse_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"a process was started: {args[:1]}")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


def _without_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing() -> str:
        raise PackageNotInstalledError(rar_unrar._NOT_INSTALLED_MSG)

    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", missing)
    monkeypatch.setattr(rar_reader, "find_rarlab_unrar", missing)


@requires("cryptography")
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
@pytest.mark.parametrize("config", [_NONE, _UNRAR], ids=["none", "unrar"])
def test_members_decrypt_without_a_program(
    monkeypatch: pytest.MonkeyPatch, path: Path, config: ArchiveyConfig
) -> None:
    _refuse_processes(monkeypatch)
    with open_archive(path, config=config, password="password") as archive:
        # Nothing here needs a program, so there is nothing to warn about.
        assert archive.cost.notes == ()
        for size in _SIZES:
            assert archive.read(f"size_{size}.bin") == _payload(size)
        read = {m.name: s.read() for m, s in archive.stream_members() if s is not None}
    assert read == {f"size_{size}.bin": _payload(size) for size in _SIZES}


@requires("cryptography")
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
def test_decrypted_member_seeks(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    _refuse_processes(monkeypatch)
    expected = _payload(3001)
    with (
        open_archive(
            path, config=_NONE, password="password", seekable_members=True
        ) as archive,
        archive.open("size_3001.bin") as stream,
    ):
        assert stream.seekable()
        assert stream.read(100) == expected[:100]
        # Back, into the middle of a block, and past the last block boundary.
        for offset in (37, 2999, 2992, 0, 3001):
            stream.seek(offset)
            assert stream.read() == expected[offset:]


@requires("cryptography")
def test_rar5_wrong_password_is_refused_before_any_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_processes(monkeypatch)
    with (
        open_archive(_RAR5, config=_NONE, password="wrong") as archive,
        pytest.raises(EncryptionError, match="Wrong password"),
    ):
        archive.open("size_3000.bin")


@requires("cryptography")
def test_rar4_wrong_password_fails_at_the_checksum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RAR 2.9-4 records no password check, so the CRC at the end is the test."""
    _refuse_processes(monkeypatch)
    with open_archive(_RAR4, config=_NONE, password="wrong") as archive:
        with pytest.raises(CorruptionError, match="Digest mismatch"):
            archive.read("size_3000.bin")
        # A read abandoned before that check is reported, as for a read by unrar.
        with archive.open("size_3000.bin") as stream:
            stream.read(10)
        assert DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED in archive.diagnostics.counts


@requires("cryptography")
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
def test_password_list_picks_the_right_one(
    monkeypatch: pytest.MonkeyPatch, path: Path
) -> None:
    _refuse_processes(monkeypatch)
    with open_archive(
        path, config=_NONE, password=["wrong", "other", "password"]
    ) as archive:
        assert archive.read("size_3001.bin") == _payload(3001)


@requires("cryptography")
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
def test_no_password_is_refused(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    _refuse_processes(monkeypatch)
    with (
        open_archive(path, config=_NONE) as archive,
        pytest.raises(EncryptionError, match="Password required"),
    ):
        archive.read("size_7.bin")


@requires("cryptography")
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
def test_damaged_ciphertext_fails_the_checksum(
    monkeypatch: pytest.MonkeyPatch, path: Path
) -> None:
    _refuse_processes(monkeypatch)
    with open_archive(path, config=_NONE, password="password") as archive:
        member = archive.get("size_3000.bin")
        assert member is not None
        raw = member._raw
        assert isinstance(raw, rar_reader.RarMemberInfo)
        offset = raw.data_offset + 1000
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    with (
        open_archive(
            io.BytesIO(bytes(data)), config=_NONE, password="password"
        ) as archive,
        pytest.raises(CorruptionError, match="Digest mismatch"),
    ):
        archive.read("size_3000.bin")


def test_without_cryptography_under_none_names_the_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_processes(monkeypatch)
    monkeypatch.setattr(rar_reader, "_crypto_available", lambda: False)
    with open_archive(_RAR4, config=_NONE, password="password") as archive:
        assert any("rar_decompressor is 'none'" in n for n in archive.cost.notes)
        with pytest.raises(PackageNotInstalledError, match="cryptography"):
            archive.read("size_7.bin")


@requires_binary("unrar")
def test_without_cryptography_unrar_reads_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rar_reader, "_crypto_available", lambda: False)
    spawns: list[object] = []
    original = rar_reader.open_unrar_p

    def spy(path: Path, **kwargs: object):
        spawns.append(path)
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)
    with open_archive(_RAR4, config=_UNRAR, password="password") as archive:
        assert archive.read("size_3001.bin") == _payload(3001)
    assert spawns


def test_without_cryptography_or_unrar_names_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_processes(monkeypatch)
    _without_unrar(monkeypatch)
    monkeypatch.setattr(rar_reader, "_crypto_available", lambda: False)
    with (
        open_archive(_RAR5, config=_UNRAR, password="password") as archive,
        pytest.raises(PackageNotInstalledError) as info,
    ):
        archive.read("size_7.bin")
    assert "unrar" in str(info.value)
    assert "cryptography" in str(info.value)


@requires("cryptography")
def test_without_unrar_reads_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The caller-visible win: no RARLAB binary, and the member still reads."""
    _refuse_processes(monkeypatch)
    _without_unrar(monkeypatch)
    with open_archive(_RAR5, config=_UNRAR, password="password") as archive:
        assert archive.read("size_3001.bin") == _payload(3001)


@requires("cryptography")
def test_split_member_is_left_to_a_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each part of a split member has its own encryption record."""
    _refuse_processes(monkeypatch)
    with (
        open_archive(
            _RAR / "tinyvol_enc.part1.rar", config=_NONE, password="password"
        ) as archive,
        pytest.raises(UnsupportedFeatureError, match="does not decrypt itself"),
    ):
        archive.read("payload.bin")


@requires_binary("unrar")
def test_split_member_reads_through_unrar() -> None:
    with open_archive(
        _RAR / "tinyvol_enc.part1.rar", config=_UNRAR, password="password"
    ) as archive:
        assert archive.read("payload.bin") == b"ABCDEFGH" * 200


@requires("cryptography")
@requires_unrar_cli()
@pytest.mark.parametrize("path", [_RAR5, _RAR4], ids=["rar5", "rar4"])
def test_bytes_match_unrar(path: Path) -> None:
    with open_archive(path, config=_UNRAR, password="password") as archive:
        for size in _SIZES:
            name = f"size_{size}.bin"
            assert (
                archive.read(name)
                == subprocess.run(
                    ["unrar", "p", "-inul", "-ppassword", str(path), name],
                    check=True,
                    capture_output=True,
                ).stdout
            )


def test_split_member_reports_the_last_parts_tweaked_crc() -> None:
    """The merged member takes the last part's encryption record with its digest.

    That record says the CRC is tweaked, so it is not a plaintext digest and is kept
    in ``extra`` instead of ``hashes``. With the first part's record it was published
    as a plaintext CRC32 that no content matches.
    """
    with open_archive(
        _RAR / "tinyvol_enc.part1.rar", config=_NONE, password="password"
    ) as archive:
        member = archive.get("payload.bin")
        assert member is not None
        assert member.hashes == {}
        assert member.extra["rar.tweaked_crc32"] == 0x1DF2A612


_SYMLINKS_RAR4 = _RAR / "symlinks_encrypted__rar4.rar"
_SYMLINK_TARGETS = {
    "symlink_to_file1.txt": "file1.txt",
    "subdir/link_to_file1.txt": "../file1.txt",
    "subdir_link": "subdir",
    "subdir_link_with_slash": "subdir/",
}


def _link_targets(archive: object) -> dict[str, str | None]:
    return {
        m.name: m.link_target
        for m in archive.members()  # type: ignore[attr-defined]
        if m.name in _SYMLINK_TARGETS
    }


def _unavailable_reasons(archive: object) -> list[str]:
    return [
        d.context.reason
        for d in archive.diagnostics.retained  # type: ignore[attr-defined]
        if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    ]


@requires("cryptography")
@pytest.mark.parametrize(
    "password", ["password", ["wrong", "password"]], ids=["one", "list"]
)
def test_encrypted_rar4_symlink_targets_list_with_the_password(
    monkeypatch: pytest.MonkeyPatch, password: str | list[str]
) -> None:
    """RAR 2.9-4 keeps a symlink's target as its stored data, which ``-p`` encrypts."""
    _refuse_processes(monkeypatch)
    with open_archive(_SYMLINKS_RAR4, config=_NONE, password=password) as archive:
        assert _link_targets(archive) == _SYMLINK_TARGETS
        assert _unavailable_reasons(archive) == []


@requires("cryptography")
def test_encrypted_rar4_symlink_targets_without_a_password_are_locked() -> None:
    with open_archive(_SYMLINKS_RAR4, config=_NONE) as archive:
        assert set(_link_targets(archive).values()) == {None}
        assert _unavailable_reasons(archive) == ["password_required"] * 4


@requires("cryptography")
@pytest.mark.parametrize(
    "password", ["wrong", ["wrong", "alsowrong"]], ids=["one", "list"]
)
def test_encrypted_rar4_symlink_target_under_a_wrong_password_is_not_damage(
    password: str | list[str],
) -> None:
    """No password check: a wrong password fails the CRC, as damage would."""
    with open_archive(_SYMLINKS_RAR4, config=_NONE, password=password) as archive:
        assert set(_link_targets(archive).values()) == {None}
        assert _unavailable_reasons(archive) == ["password_or_damage"] * 4


def test_encrypted_rar4_symlink_targets_without_cryptography() -> None:
    from unittest import mock

    with (
        mock.patch.object(rar_reader, "_crypto_available", lambda: False),
        open_archive(_SYMLINKS_RAR4, config=_NONE, password="password") as a,
    ):
        assert set(_link_targets(a).values()) == {None}
        assert _unavailable_reasons(a) == ["target_data_encrypted"] * 4


@requires("cryptography")
@requires_binary("unrar")
def test_encrypted_rar4_symlinks_extract(tmp_path: Path) -> None:
    # file1.txt is compressed, so unrar reads it; the links are decrypted here.
    with open_archive(_SYMLINKS_RAR4, config=_UNRAR, password="password") as archive:
        archive.extract_all(tmp_path)
    assert (tmp_path / "symlink_to_file1.txt").read_bytes() == b"Hello, world!"
    assert os.readlink(tmp_path / "subdir_link") == "subdir"
