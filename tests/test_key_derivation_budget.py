"""``DecoderLimits.max_key_derivation_rounds``: the total an archive may make us hash.

RAR5 and 7z headers say how many rounds turn a password into a key, and how many
distinct keys (salts) there are. Each derivation is capped at ``2**24`` elsewhere;
this pins the total, charged per derivation that actually runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, DecoderLimits
from archivey.exceptions import ResourceLimitError
from archivey.internal.backends.sevenzip_aes import SevenZipKeyCache
from archivey.internal.config import KeyDerivationBudget
from tests.conftest import requires, requires_binary

_RAR = Path(__file__).parent / "fixtures" / "rar"

# rar 7.00 writes kdf_count 15: the key at 2**15 rounds, the PswCheck at +32, the
# HashKey at +16. RAR3 costs a fixed 2**18.
_RAR5_KEY = 1 << 15
_RAR5_CHECK = (1 << 15) + 32
_RAR5_HASH_KEY = (1 << 15) + 16
_RAR3 = 1 << 18


def _config(rounds: int | None) -> ArchiveyConfig:
    return ArchiveyConfig(
        decoder_limits=DecoderLimits(max_key_derivation_rounds=rounds)
    )


def test_default_and_unlimited() -> None:
    assert DecoderLimits().max_key_derivation_rounds == 2**25
    assert DecoderLimits.UNLIMITED.max_key_derivation_rounds is None


def test_budget_refuses_before_crossing_and_counts_what_it_allowed() -> None:
    budget = KeyDerivationBudget(DecoderLimits(max_key_derivation_rounds=10))
    budget.spend(6, what="test derivation")
    budget.spend(4, what="test derivation")
    with pytest.raises(ResourceLimitError, match="max_key_derivation_rounds=10"):
        budget.spend(1, what="test derivation")
    # The refusal charged nothing, so the budget is exactly spent, not over it.
    assert "10 of 10" in repr(budget)
    KeyDerivationBudget(DecoderLimits.UNLIMITED).spend(2**40, what="test derivation")


@requires("cryptography")
@pytest.mark.parametrize(
    ("rounds", "ok"),
    [(_RAR5_KEY + _RAR5_CHECK, True), (_RAR5_KEY + _RAR5_CHECK - 1, False)],
)
def test_rar5_header_encrypted_volume_set_charges_one_set_of_keys(
    rounds: int, ok: bool
) -> None:
    """Four parts repeat one encryption record: the listing costs two derivations."""
    part1 = _RAR / "tinyvol_hp.part1.rar"
    if ok:
        with open_archive(
            part1, password="header_password", config=_config(rounds)
        ) as a:
            assert [m.name for m in a.members()] == ["payload.bin"]
    else:
        with pytest.raises(ResourceLimitError, match="RAR5 key derivation"):
            open_archive(part1, password="header_password", config=_config(rounds))


@requires("cryptography")
def test_rar5_wrong_candidates_are_charged_and_a_spent_budget_stops_the_list() -> None:
    """A wrong candidate's PswCheck costs as much as the right one's.

    The refusal must surface as ``ResourceLimitError``: re-read as a wrong password it
    would move on to the next candidate and report the archive as undecryptable.
    """
    path = _RAR / "encrypted_header__.rar"
    passwords = ["wrong", "header_password"]
    enough = 2 * _RAR5_CHECK + _RAR5_KEY
    with open_archive(path, password=passwords, config=_config(enough)) as archive:
        assert archive.members()
    with pytest.raises(ResourceLimitError):
        open_archive(path, password=passwords, config=_config(enough - 1))


@requires("cryptography")
@requires_binary("unrar")
def test_rar5_member_reads_are_charged_once_per_record() -> None:
    """A ``-p`` archive: listing is free, the first read pays PswCheck and HashKey,
    and every later read of either member reuses them."""
    path = _RAR / "encryption__.rar"
    enough = _RAR5_CHECK + _RAR5_HASH_KEY
    with open_archive(path, password="password", config=_config(enough)) as archive:
        for _ in range(3):
            assert archive.read("secret.txt") == b"This is secret"
            assert archive.read("also_secret.txt") == b"This is also secret"
    with open_archive(path, password="password", config=_config(enough - 1)) as archive:
        assert archive.members()
        with pytest.raises(ResourceLimitError, match="RAR5 key derivation"):
            archive.read("secret.txt")


@requires("cryptography")
def test_rar5_stored_member_read_also_charges_the_data_key() -> None:
    """A stored member archivey decrypts itself needs the AES key too: three
    derivations from one chain, each charged."""
    path = _RAR / "encryption_stored__.rar"
    enough = _RAR5_CHECK + _RAR5_HASH_KEY + _RAR5_KEY
    with open_archive(path, password="password", config=_config(enough)) as archive:
        assert archive.read("secret.txt") == b"This is secret"
    with (
        open_archive(path, password="password", config=_config(enough - 1)) as archive,
        pytest.raises(ResourceLimitError, match="RAR5 key derivation"),
    ):
        archive.read("secret.txt")


@requires("cryptography")
def test_rar3_header_derivation_is_charged_at_its_fixed_cost() -> None:
    path = _RAR / "encrypted_header__rar4.rar"
    with open_archive(path, password="header_password", config=_config(_RAR3)) as a:
        assert a.members()
    with pytest.raises(ResourceLimitError, match="RAR3 key derivation"):
        open_archive(path, password="header_password", config=_config(_RAR3 - 1))


def test_sevenzip_cache_charges_misses_only() -> None:
    budget = KeyDerivationBudget(DecoderLimits(max_key_derivation_rounds=1 << 4))
    cache = SevenZipKeyCache(budget=budget)
    password = "pw".encode("utf-16-le")
    # First byte: salt/IV flag bits over NumCyclesPower; then sizes, salt, IV.
    cycles_4 = b"\x44\x00\x00"  # IV flag only: no salt, one IV byte
    first = cache.aes_params_from_properties(password, cycles_4)
    assert cache.aes_params_from_properties(password, cycles_4).key == first.key
    # The no-hash sentinel does no hashing, so it is free even on a spent budget.
    cache.aes_params_from_properties(password, b"\x7f\x00\x00")
    with pytest.raises(ResourceLimitError, match="7z key derivation"):
        # Same cost, new salt b"\x01": a miss the spent budget refuses.
        cache.aes_params_from_properties(password, b"\xc4\x00\x01\x00")


@requires("cryptography")
@requires_binary("7z")
def test_sevenzip_encrypted_archive_is_refused_over_budget(tmp_path: Path) -> None:
    """7-Zip 23.01 always writes NumCyclesPower 19 and no salt: one derivation."""
    source = tmp_path / "a.txt"
    source.write_bytes(b"hello budget")
    archive = tmp_path / "enc.7z"
    subprocess.run(
        ["7z", "a", "-t7z", "-psecret", "-mhe=on", str(archive), str(source)],
        check=True,
        capture_output=True,
    )
    with open_archive(archive, password="secret", config=_config(1 << 19)) as a:
        assert a.read("a.txt") == b"hello budget"
    with pytest.raises(ResourceLimitError, match="7z key derivation"):
        open_archive(archive, password="secret", config=_config((1 << 19) - 1))


@requires("cryptography")
@requires_binary("7z")
@pytest.mark.parametrize(
    ("password", "rounds"),
    [
        pytest.param("secret", (1 << 19) - 1, id="one-derivation-short"),
        # The wrong candidate spends the whole budget; the right one is refused
        # for the budget, not reported as a wrong password.
        pytest.param(["wrong", "secret"], 1 << 19, id="wrong-candidate-spends-it"),
    ],
)
def test_sevenzip_folder_confirm_reports_the_budget_not_a_wrong_password(
    tmp_path: Path, password: str | list[str], rounds: int
) -> None:
    """Plain headers: the key is derived when the folder opens, inside the
    password-confirm callback, which maps other errors to EncryptionError."""
    source = tmp_path / "a.txt"
    source.write_bytes(b"hello budget")
    archive = tmp_path / "enc.7z"
    subprocess.run(
        ["7z", "a", "-t7z", "-psecret", "-mhe=off", str(archive), str(source)],
        check=True,
        capture_output=True,
    )
    with (
        open_archive(archive, password=password, config=_config(rounds)) as a,
        pytest.raises(ResourceLimitError, match="7z key derivation"),
    ):
        a.read("a.txt")
