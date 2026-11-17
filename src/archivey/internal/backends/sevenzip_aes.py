"""7z AES key derivation and coder properties (``7zAes.cpp``).

The AES primitive itself is format-neutral and lives in
:mod:`archivey.internal.streams.crypto`; what is here is 7z's own framing around it:
the ``NumCyclesPower`` SHA-256 KDF, the coder-property blob that carries its salt and
IV, and the per-reader cache of derived keys. RAR derives its keys in ``rar_parser``
and WinZip AES in ``zip_aes``, each for the same reason.
"""

from __future__ import annotations

import functools
import hashlib

from archivey.exceptions import UnsupportedFeatureError
from archivey.internal.config import KeyDerivationBudget
from archivey.internal.streams.crypto import AES_BLOCK_SIZE, AesParams

# 7-Zip's own decoder clamp (7zAes.cpp ``k_NumCyclesPower_Supported_MAX``): accept
# ``NumCyclesPower <= 24`` or the ``0x3F`` no-hash sentinel; reject 25–62.
_SEVENZIP_MAX_CYCLES_POWER = 24
_SEVENZIP_NO_HASH_SENTINEL = 0x3F


def _unsupported_cycles(cycles: int) -> UnsupportedFeatureError:
    return UnsupportedFeatureError(
        f"7z NumCyclesPower {cycles} exceeds the supported maximum "
        f"({_SEVENZIP_MAX_CYCLES_POWER}); values 25–62 are rejected to match 7-Zip "
        "(and to bound KDF cost)."
    )


def derive_sevenzip_aes_key(password: bytes, *, salt: bytes, cycles: int) -> bytes:
    """Derive a 32-byte AES-256 key with the 7z SHA-256 scheme.

    ``password`` is the raw password bytes already encoded as UTF-16LE (callers that
    hold a ``str`` should encode first). ``cycles`` is ``NumCyclesPower`` from the AES
    coder properties (``0..0x3f``). The ``0x3f`` special case copies salt+password into
    a 32-byte key without hashing.

    Values ``25..62`` are rejected with :class:`UnsupportedFeatureError`, matching
    7-Zip's own decoder clamp (``k_NumCyclesPower_Supported_MAX = 24``).
    """
    if cycles < 0 or cycles > _SEVENZIP_NO_HASH_SENTINEL:
        raise ValueError(f"NumCyclesPower out of range: {cycles}")
    if cycles == _SEVENZIP_NO_HASH_SENTINEL:
        # The 0x3f sentinel means "no hashing": key = (salt + password), zero-padded to 32.
        return (salt + password + bytes(32))[:32]
    if cycles > _SEVENZIP_MAX_CYCLES_POWER:
        raise _unsupported_cycles(cycles)
    # Batch rounds to cut hashlib.update call overhead (same approach as py7zr).
    cat_cycle = 6
    if cycles > cat_cycle:
        rounds = 1 << cat_cycle
        stages = 1 << (cycles - cat_cycle)
    else:
        rounds = 1 << cycles
        stages = 1
    digest = hashlib.sha256()
    salt_password = salt + password
    s = 0
    for _ in range(stages):
        digest.update(
            b"".join(
                salt_password + (s + i).to_bytes(8, "little") for i in range(rounds)
            )
        )
        s += rounds
    return digest.digest()


def parse_sevenzip_aes_properties(properties: bytes) -> tuple[int, bytes, bytes]:
    """Parse 7z AES coder properties → ``(num_cycles_power, salt, iv)``.

    Raises ``ValueError`` when the property blob is malformed, and
    :class:`UnsupportedFeatureError` when ``NumCyclesPower`` is 25–62 (7-Zip's
    ``E_NOTIMPL`` clamp).
    """
    if not properties:
        raise ValueError("empty 7z AES properties")
    first = properties[0]
    cycles = first & 0x3F
    if cycles > _SEVENZIP_MAX_CYCLES_POWER and cycles != _SEVENZIP_NO_HASH_SENTINEL:
        raise _unsupported_cycles(cycles)
    if first & 0xC0 == 0:
        # No salt and no IV: 7-Zip takes the one-byte blob as a zero IV and an empty
        # salt (``7zAes.cpp``, ``size == 1 ? S_OK : E_INVALIDARG``), and so does
        # py7zr. Anything after that byte has no field to belong to.
        if len(properties) != 1:
            raise ValueError(
                f"7z AES properties length {len(properties)} != expected 1 "
                "(no salt or IV flags set)"
            )
        return cycles, b"", bytes(AES_BLOCK_SIZE)
    salt_size = (first >> 7) & 1
    iv_size = (first >> 6) & 1
    if len(properties) < 2:
        raise ValueError("truncated 7z AES properties")
    second = properties[1]
    salt_size += second >> 4
    iv_size += second & 0x0F
    expected = 2 + salt_size + iv_size
    if len(properties) != expected:
        raise ValueError(
            f"7z AES properties length {len(properties)} != expected {expected}"
        )
    salt = properties[2 : 2 + salt_size]
    iv = properties[2 + salt_size : 2 + salt_size + iv_size]
    if len(iv) < AES_BLOCK_SIZE:
        iv = iv + bytes(AES_BLOCK_SIZE - len(iv))
    return cycles, salt, iv


class SevenZipKeyCache:
    """:func:`derive_sevenzip_aes_key` behind a per-instance ``functools.cache``.

    One per reader, so the cached candidate passwords and derived keys go when the
    reader does; ``@functools.cache`` on a method would keep them, and every reader,
    until the process exits. Keyed by ``(password, salt, cycles)``, with the password
    already UTF-16LE. Unbounded: an entry is added only by the derivation it caches,
    and each needs a distinct salt, so entries are bounded by the folders the listing
    limits already cap times the candidate passwords. Unlike RAR's, a 7z derivation
    can cost almost nothing (the ``0x3F`` sentinel hashes nothing), so the bound is
    that count, not the CPU cost of filling it. Neither this class nor the cache
    wrapper has a ``repr`` that shows passwords or keys.

    Each miss is charged ``2**cycles`` to ``budget``
    (:attr:`~archivey.config.DecoderLimits.max_key_derivation_rounds`) before it
    runs. The charge sits inside the cached function, which ``functools.cache``
    calls only on a miss. The reader passes a budget built from its own limits; a
    cache made without one charges the default limits.
    """

    __slots__ = ("_derive",)

    def __init__(self, *, budget: KeyDerivationBudget | None = None) -> None:
        charge = budget if budget is not None else KeyDerivationBudget()

        def derive(password: bytes, *, salt: bytes, cycles: int) -> bytes:
            # Out-of-range and no-hash (0x3F) values cost nothing: the first raises
            # in derive_sevenzip_aes_key before any hashing, the second never hashes.
            if 0 <= cycles <= _SEVENZIP_MAX_CYCLES_POWER:
                charge.spend(1 << cycles, what="7z key derivation")
            return derive_sevenzip_aes_key(password, salt=salt, cycles=cycles)

        self._derive = functools.cache(derive)

    def aes_params_from_properties(
        self, password: bytes, properties: bytes
    ) -> AesParams:
        """The key and IV for one AES coder, from its properties and the password.

        ``password`` is already the key-derivation bytes (UTF-16LE for a UTF-8
        password, the raw bytes otherwise; see the 7z reader's
        ``_password_to_kdf_bytes``). Raises as
        :func:`parse_sevenzip_aes_properties` does.
        """
        cycles, salt, iv = parse_sevenzip_aes_properties(properties)
        key = self._derive(password, salt=salt, cycles=cycles)
        return AesParams(key=key, iv=iv)
