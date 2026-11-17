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


# Past the official vectors' 255 bytes: inputs around and past the 512-byte stride
# (eight 64-byte leaf blocks), where full strides go to the leaves. Input bytes are
# ``i & 0xFF`` for i in range(n); digests computed by 7-Zip 23.01
# (``7zz h -scrcBLAKE2sp``).
_LONG: tuple[tuple[int, str], ...] = (
    (511, "50285271956932d39b0967202b56006cbb6d738ee29e5a867edf72c8c4386f1b"),
    (512, "322ce06cc141a0b3d89bcdcfcb385975dbca56e5719a78c34000fcec2e15b55d"),
    (513, "1336628c7f1541c7815fc0ff1fb5dfb07a85cf5a17a2872a3ce4b322d4a03d0b"),
    (1023, "13bc5720de247edd4dc087a08a1e44388bf2047b102c5d878a86c8aa10e50019"),
    (1024, "c9f79171d19c3703b7ebf9f762ce3fd24b302e2281f72da31a65014ff923c859"),
    (1025, "1cf65560deef7dad5282fa8b42e289d71a43b972b24eb3c8ed4d6e725e5f14ad"),
    (1536, "399bf742b49a597858a1b0c2b599f9fd4d6d66204941a893bc79fcf097e9d992"),
    (4097, "ff56cf04d1724a53f37ffea682e83bbcd0033f6fc0dfef6a21dbf621a79eb667"),
)


@pytest.mark.parametrize(("length", "expected_hex"), _LONG)
@pytest.mark.parametrize("chunk", [None, 1, 300, 512, 700])
def test_blake2sp_past_one_stride(
    length: int, expected_hex: str, chunk: int | None
) -> None:
    data = bytes(i & 0xFF for i in range(length))
    hasher = Blake2sp()
    step = chunk or max(length, 1)
    for i in range(0, len(data), step):
        hasher.update(data[i : i + step])
    assert hasher.digest() == bytes.fromhex(expected_hex)


def test_blake2sp_refuses_an_update_after_the_digest() -> None:
    hasher = Blake2sp()
    hasher.update(b"abc")
    digest = hasher.digest()
    with pytest.raises(ValueError, match="finalized"):
        hasher.update(b"d")
    assert hasher.digest() == digest


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
