"""The ZipCrypto decrypt loop against the textbook cipher in :mod:`tests.zipcrypto`.

The Python twin's ``zipcrypto.Decryptor.decrypt`` rewrites the APPNOTE §6.1
arithmetic for speed (a keystream lookup table, ``k0`` held as two parts). These tests
pin it to the plain formula the fixture writer encrypts with, across call boundaries
and the internal chunk size.
"""

from __future__ import annotations

import random

import pytest

from archivey.internal.backends import zipcrypto as zip_backend
from archivey.internal.kernels.python import zipcrypto
from archivey.types import OptionalLibrary
from tests.zipcrypto import _encrypt, _Keys


def test_keystream_table_matches_formula() -> None:
    keys = _Keys(b"")
    table = zipcrypto._keystream_table()
    for k2 in range(0x10000):
        keys.k2 = k2 | 0x5A5A0000  # high bits must not matter
        assert table[k2] == keys.keystream_byte()


@pytest.mark.parametrize("password", [b"", b"x", b"correct horse battery staple"])
def test_password_setup_matches_formula(password: bytes) -> None:
    ours, ref = zipcrypto.Decryptor(password), _Keys(password)
    assert (ours.k0, ours.k1, ours.k2) == (ref.k0, ref.k1, ref.k2)


@pytest.mark.parametrize(
    "split_sizes",
    [
        [0, 1, 11, 1],
        [zipcrypto._DECRYPT_CHUNK - 1, 2, zipcrypto._DECRYPT_CHUNK + 1],
        [3 * zipcrypto._DECRYPT_CHUNK + 5],
    ],
)
def test_decrypt_across_calls_matches_encrypt(split_sizes: list[int]) -> None:
    rng = random.Random(len(split_sizes))
    payload = rng.randbytes(sum(split_sizes))
    ciphertext = _encrypt(b"pw", 0x42, payload)

    # The Python cipher, whose key words are compared below.
    keys, check = zip_backend.keys_after_header(
        b"pw", ciphertext, frozenset({OptionalLibrary.ARCHIVEY_SPEEDUPS})
    )
    assert isinstance(keys, zipcrypto.Decryptor)
    assert check == 0x42
    body = ciphertext[zip_backend.ZIPCRYPTO_HEADER_LEN :]
    pieces, pos = [], 0
    for size in split_sizes:
        pieces.append(keys.decrypt(body[pos : pos + size]))
        pos += size
    assert b"".join(pieces) == payload

    ref = _Keys(b"pw")
    for b in (*bytes(range(11)), 0x42, *payload):
        ref.update(b)
    assert (keys.k0, keys.k1, keys.k2) == (ref.k0, ref.k1, ref.k2)
