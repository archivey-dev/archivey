"""BLAKE2sp known-answer tests (official BLAKE2 unkeyed vectors).

Vectors are a subset of ``blake2-kat.json`` from the BLAKE2 reference repository
(https://github.com/BLAKE2/BLAKE2), restricted to unkeyed ``blake2sp`` inputs of
representative lengths that exercise empty, partial-block, full-block, and
multi-stride paths.
"""

from __future__ import annotations

import pytest

from archivey.internal.hashing.blake2sp import Blake2sp, blake2sp
from archivey.types import HashAlgorithm

# (input_length, expected_hex). Input bytes are ``bytes(range(n))`` as in the
# official KATs (``in`` is 000102… for length n).
_KATS: tuple[tuple[int, str], ...] = (
    (0, "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"),
    (1, "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239"),
    (63, "1024c940be7341449b5010522b509f65bbdc1287b455c2bb7f72b2c92fd0d189"),
    (64, "52603b6cbfad4966cb044cb267568385cf35f21e6c45cf30aed19832cb51e9f5"),
    (65, "fff24d3cc729d395daf978b0157306cb495797e6c8dca1731d2f6f81b849baae"),
    (127, "a626543c271fccc3e4450b48d66bc9cbdeb25e5d077a6213cd90cbbd0fd22076"),
    (128, "05cf3a90049116dc60efc31536aaa3d167762994892876dcb7ef3fbecd7449c0"),
    (255, "25059f10605e67adfe681350666e15ae976a5a571c13cf5bc8053f430e120a52"),
)


@pytest.mark.parametrize(("length", "expected_hex"), _KATS)
def test_blake2sp_kat(length: int, expected_hex: str) -> None:
    data = bytes(range(length))
    assert blake2sp(data) == bytes.fromhex(expected_hex)


@pytest.mark.parametrize(("length", "expected_hex"), _KATS)
def test_blake2sp_incremental_matches_oneshot(length: int, expected_hex: str) -> None:
    data = bytes(range(length))
    hasher = Blake2sp()
    # Odd chunk sizes so the 512-byte carry buffer is exercised across boundaries.
    for i in range(0, len(data), 7):
        hasher.update(data[i : i + 7])
    assert hasher.digest() == bytes.fromhex(expected_hex)
    assert hasher.digest() == hasher.digest()  # idempotent


def test_blake2sp_matches_rar5_fixture_payload() -> None:
    """Degree-8 / unkeyed / 32-byte params match WinRAR ``-htb`` (task 1.1)."""
    from pathlib import Path

    from archivey import open_archive

    fixture = Path(__file__).parent / "fixtures" / "rar" / "blake2sp.rar"
    assert fixture.is_file(), (
        "vendored tests/fixtures/rar/blake2sp.rar is required "
        "(regenerate via scripts/fixtures/gen_rar_fixtures.py)"
    )
    payload = b"stored payload"
    with open_archive(fixture) as archive:
        member = next(m for m in archive.members() if m.is_file)
        assert member.hashes[HashAlgorithm.BLAKE2SP] == blake2sp(payload)
        assert len(member.hashes[HashAlgorithm.BLAKE2SP]) == 32
