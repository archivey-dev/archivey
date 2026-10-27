"""Native RAR header-parser pins (not the reader / unrar boundary)."""

from __future__ import annotations

import hashlib
import hmac
import io
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_parser import (
    RarKdfCache,
    _check_rar5_password,
    _HeaderDecryptStream,
    _rar3_s2k,
    _Rar3Sha1,
    _rar5_dictionary_size,
    parse_rar_archive,
    parse_rar_volumes,
    rar5_data_key,
    rar5_hash_key,
)
from archivey.internal.backends.sevenzip_aes import SevenZipKeyCache
from tests.conftest import requires, requires_binary, requires_unrar_cli
from tests.corruption_util import raises_corruption_not_truncation

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.is_file():
        pytest.fail(f"committed fixture {name} is missing")
    return path


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


@requires("cryptography")
def test_header_decrypt_tell_is_ciphertext_cursor_not_plaintext() -> None:
    """A short read leaves leftover plaintext in ``_buf``; ``tell`` stays on the
    ciphertext block boundary. Subtracting leftover would report the plaintext
    offset and is the wrong ``data_offset`` for the next salt/IV (#315 threads 1–2).
    """
    key = b"\x00" * 16
    iv = b"\x01" * 16
    plaintext = b"0123456789abcdef" * 2  # two AES blocks
    ciphertext = _aes_cbc_encrypt(key, iv, plaintext)
    stream = _HeaderDecryptStream(io.BytesIO(ciphertext), key, iv)

    first = stream.read(7)
    assert first == plaintext[:7]
    assert len(stream._buf) == 9
    assert stream.tell() == 16
    # Thread 1 counterfactual: tell() - len(_buf) would be 7, the plaintext
    # offset, which is the wrong data_offset for the next salt/IV. The walk
    # pin is test_encrypted_header_plaintext_tell_breaks_the_walk.

    rest = stream.read(9)
    assert rest == plaintext[7:16]
    assert stream._buf == b""
    assert stream.tell() == 16


@requires("cryptography")
def test_header_decrypt_read_is_bounded_by_caller_not_8kib() -> None:
    """#332 CR1 / CR-P1: ``read`` does not impose an 8 KiB cap. Callers already
    bound the ask (RAR5 ``_RAR5_MAX_HEADER``, RAR3 ``uint16`` header_size).
    Unbounded ``read(-1)`` stays rejected.
    """
    key = b"\x00" * 16
    iv = b"\x01" * 16
    plaintext = b"0123456789abcdef" * ((9 * 1024) // 16)  # 9 KiB, 16-aligned
    ciphertext = _aes_cbc_encrypt(key, iv, plaintext)
    stream = _HeaderDecryptStream(io.BytesIO(ciphertext), key, iv)
    got = stream.read(len(plaintext))
    assert got == plaintext

    with raises_corruption_not_truncation(match="Unbounded read"):
        stream.read(-1)


@requires("cryptography")
def test_rar3_wrong_header_password_is_encryption_error() -> None:
    """Raising the per-read cap must not turn a RAR3 wrong password into
    ``CorruptionError`` — candidate iteration only retries ``EncryptionError``.
    """
    path = _fixture("encrypted_header__rar4.rar")
    with (
        path.open("rb") as handle,
        pytest.raises(EncryptionError, match="wrong password"),
    ):
        parse_rar_archive(handle, password="not-the-password")


@requires("cryptography")
@pytest.mark.parametrize(
    ("name", "cut", "start"),
    [
        # Cut inside the first encrypted header's 16-byte IV (RAR5) / 8-byte salt
        # (RAR3), which start at bytes 46 and 20.
        ("encrypted_header__.rar", 50, 46),
        ("encrypted_header__rar4.rar", 24, 20),
    ],
)
def test_short_header_salt_or_iv_is_a_cut_not_a_wrong_password(
    name: str, cut: int, start: int
) -> None:
    """The salt/IV read does not depend on the password, so running out of bytes there
    is damage. It used to be re-wrapped as ``EncryptionError``, which sent the reader
    through every password candidate and reported a truncated archive as a wrong
    password, even with the right one. A salt or IV the file holds only part of ends
    the walk as a cut, which the reader reports as ``TruncatedError`` after the
    members listed.
    """
    data = _fixture(name).read_bytes()[:cut]
    archive = parse_rar_archive(io.BytesIO(data), password="header_password")
    assert archive.members == []
    assert archive.truncated is not None
    assert f"encrypted header that starts at byte {start}" in archive.truncated


@requires("cryptography")
@pytest.mark.parametrize(("cut", "expected"), [(436, 4), (492, 5), (564, 6)])
def test_rar3_file_ending_where_a_header_salt_starts_is_a_clean_end(
    cut: int, expected: int
) -> None:
    """RAR3 with encrypted headers ending exactly where the next salt would start
    lists the members before it, as a plain RAR3 walk does and as unrar does (exit 0
    for ``l`` and ``t``). RAR 1.5-4 writers may omit the end block, so nothing tells
    this from an archive that ended there. 564 drops only the 24-byte end block."""
    full = _fixture("encrypted_header__rar4.rar").read_bytes()
    complete = parse_rar_archive(io.BytesIO(full), password="header_password")
    archive = parse_rar_archive(io.BytesIO(full[:cut]), password="header_password")
    assert archive.truncated is None
    names = [m.filename for m in archive.members]
    assert names == [m.filename for m in complete.members][:expected]


@requires("cryptography")
@pytest.mark.parametrize(
    "name", ["encrypted_header__.rar", "encrypted_header__rar4.rar"]
)
def test_a_password_with_no_unicode_form_is_a_wrong_candidate(name: str) -> None:
    """``bytes`` that are not UTF-8 cannot be any RAR password. On the header walk that
    is a wrong candidate, so the loop reaches the right one; alone it is
    ``EncryptionError``, never a raw ``UnicodeDecodeError``."""
    import archivey

    data = _fixture(name).read_bytes()
    with archivey.open_archive(
        io.BytesIO(data), password=[b"\xff\xfe", "header_password"]
    ) as reader:
        assert reader.members()
    with pytest.raises(EncryptionError):
        archivey.open_archive(io.BytesIO(data), password=b"\xff\xfe")


@requires("cryptography")
def test_a_rar5_password_cut_inside_a_surrogate_pair_is_a_wrong_candidate() -> None:
    """RAR5 truncates the password to 127 UTF-16 units before its UTF-8 step, so an
    astral character straddling the cut leaves half a pair with no UTF-8 form. That
    candidate is rejected and the list moves on, instead of ``UnicodeDecodeError``."""
    import archivey

    data = _fixture("encrypted_header__.rar").read_bytes()
    straddling = "a" * 126 + "\U0001f600"  # 128 UTF-16 units; the emoji spans 127/128
    with archivey.open_archive(
        io.BytesIO(data), password=[straddling, "header_password"]
    ) as reader:
        assert reader.members()


@requires("cryptography")
@pytest.mark.parametrize(
    "name",
    ["encrypted_header__.rar", "encrypted_header__rar4.rar"],
)
def test_encrypted_header_data_offset_skips_aes_block_padding(name: str) -> None:
    """On real ``-hp`` fixtures, every FILE header_size is not 16-aligned, and
    ``data_offset - header_offset`` is the padded ciphertext span. That span is
    what ``tell()`` reports; a plaintext ``tell`` would equal ``header_size``.
    """
    path = _fixture(name)
    with path.open("rb") as handle:
        archive = parse_rar_archive(handle, password="header_password")
    assert archive.has_header_encryption
    assert archive.members
    saw_unaligned_header = False
    for member in archive.members:
        span = member.data_offset - member.header_offset
        assert span % 16 == 0, (
            f"{member.filename}: ciphertext span {span} is not AES-aligned"
        )
        assert span >= member.header_size
        if member.header_size % 16 != 0:
            saw_unaligned_header = True
            assert span > member.header_size
    assert saw_unaligned_header, (
        "fixture no longer has a non-16-aligned header_size; the tell() pin "
        "needs a header that leaves AES padding in _buf"
    )


@requires("cryptography")
@pytest.mark.parametrize(
    ("name", "expected_names"),
    # None: the walk raises. A list: the walk lists those members and reports a cut.
    [("encrypted_header__.rar", None), ("encrypted_header__rar4.rar", ["file1.txt"])],
)
def test_encrypted_header_plaintext_tell_breaks_the_walk(
    name: str, expected_names: list[str] | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red-green for thread 1: if ``tell`` subtracted leftover ``_buf``, listing
    these fixtures fails — the next salt/IV is read from inside AES padding.

    The misread IV decrypts a garbage RAR5 header size, which raises. In RAR3 the
    misread salt decrypts a garbage header after file1.txt's header has proved the key
    by its CRC16, and its size runs to the end of the file, so the walk lists
    file1.txt and reports a cut in the header that starts at byte 114.
    """
    from archivey.internal.backends import rar_parser

    orig_tell = rar_parser._HeaderDecryptStream.tell

    def plaintext_tell(self: rar_parser._HeaderDecryptStream) -> int:
        return orig_tell(self) - len(self._buf)

    monkeypatch.setattr(rar_parser._HeaderDecryptStream, "tell", plaintext_tell)
    path = _fixture(name)
    with path.open("rb") as handle:
        if expected_names is None:
            with pytest.raises(CorruptionError, match="RAR5 header too large"):
                parse_rar_archive(handle, password="header_password")
            return
        archive = parse_rar_archive(handle, password="header_password")
    assert [m.filename for m in archive.members] == expected_names
    assert archive.truncated is not None
    assert "encrypted header that starts at byte 114" in archive.truncated


def test_rar3_sha1_hashes_then_mutates_bytearray_seed() -> None:
    """The maintainer's reading of the rarbug (#315 thread 8): hashlib SHA-1 of
    this chunk is correct, then complete SHA-1 blocks in the input bytearray
    are scrambled so a reused seed hashes different bytes next time.

    ``dpos`` starts at the first block boundary in this chunk, so with an empty
    hasher the first 64 bytes stay put and the second block is rewritten.
    ``bytes`` input cannot be mutated and must fail loud — a silent skip would
    derive a different key.
    """
    seed = bytearray(range(128))
    original = bytes(seed)
    hasher = _Rar3Sha1()
    hasher.update(seed)
    assert hasher.digest() == hashlib.sha1(original).digest()
    assert bytes(seed[:64]) == original[:64]
    assert bytes(seed[64:]) != original[64:]

    frozen = bytes(range(128))
    hasher_b = _Rar3Sha1()
    with pytest.raises(TypeError, match="mutable seed"):
        hasher_b.update(frozen)
    assert frozen == bytes(range(128))


def test_rar3_sha1_short_seed_is_not_mutated() -> None:
    """Seed ≤ 64 bytes never crosses a SHA-1 block, so the WinRAR mutation
    does not run. ``header_password`` + 8-byte salt is in this class.
    """
    seed = bytearray("header_password".encode("utf-16le") + b"\x00" * 8)
    assert len(seed) <= 64
    original = bytes(seed)
    hasher = _Rar3Sha1()
    hasher.update(seed)
    assert bytes(seed) == original


def test_rar3_s2k_matches_the_pinned_rarfile_key_for_a_long_password() -> None:
    """A long password+salt (> 64 bytes), which exercises the mutation path, must
    derive the key/IV that rarfile's ``rar3_s2k`` recorded for it.

    The expected pair is what ``rarfile.rar3_s2k(password, salt)`` returns (rarfile
    4.2). It is pinned rather than recomputed because rarfile's pure-Python KDF took
    as long as ours, 4.5 s, and pinning also runs the check where rarfile is absent.
    """
    password = "x" * 40  # 80 UTF-16LE bytes + 8-byte salt > 64
    salt = bytes(range(8))
    assert _rar3_s2k(password, salt) == (
        bytes.fromhex("548d90a03d1323e2dbb745ea3cb7edd8"),
        bytes.fromhex("6cd51fd9a536aebc2b6749963f02c501"),
    )


_TINYVOL_HP = [f"tinyvol_hp.part{n}.rar" for n in range(1, 5)]


def _count_rar5_derivations(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the round count of every RAR5 PBKDF2 the parser runs."""
    from archivey.internal.backends import rar_parser

    rounds: list[int] = []
    real = rar_parser.pbkdf2_hmac

    def counting(
        name: str, password: bytes, salt: bytes, iterations: int, dklen: int
    ) -> bytes:
        rounds.append(iterations)
        return real(name, password, salt, iterations, dklen)

    monkeypatch.setattr(rar_parser, "pbkdf2_hmac", counting)
    return rounds


@requires("cryptography")
def test_header_encrypted_volume_set_derives_each_key_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every part of an ``-hp`` set repeats the encryption record, salt included.

    Each volume used to derive the PswCheck and the header key again: eight
    derivations for this four-part set, each costing up to ``2**24`` rounds at
    the archive's choosing. One cache across the set does each once.
    """
    rounds = _count_rar5_derivations(monkeypatch)
    handles = [_fixture(name).open("rb") for name in _TINYVOL_HP]
    try:
        archive = parse_rar_volumes(handles, password="header_password")
    finally:
        for handle in handles:
            handle.close()
    assert archive.has_header_encryption
    assert [m.filename for m in archive.members] == ["payload.bin"]
    assert {m.volume_index for m in archive.members} == {0}
    # AES key at 2**kdf_count, PswCheck at +32; kdf_count is RARLAB's 15.
    assert sorted(rounds) == [1 << 15, (1 << 15) + 32]


@requires("cryptography")
@pytest.mark.parametrize(
    "name",
    ["encrypted_header__.rar", "encrypted_header__rar4.rar"],
)
def test_kdf_cache_carries_header_keys_between_parses(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second parse through the same cache derives nothing.

    The reader parses once per password candidate, and a caller that passes its
    own cache shares header keys with its member reads.
    """
    from archivey.internal.backends import rar_parser

    rounds = _count_rar5_derivations(monkeypatch)
    rar3_calls: list[bytes] = []
    real_rar3 = rar_parser._rar3_key_iv

    def counting_rar3(wstr: bytes, salt: bytes) -> tuple[bytes, bytes]:
        rar3_calls.append(salt)
        return real_rar3(wstr, salt)

    monkeypatch.setattr(rar_parser, "_rar3_key_iv", counting_rar3)
    cache = RarKdfCache()
    path = _fixture(name)
    with path.open("rb") as handle:
        first = parse_rar_archive(handle, password="header_password", kdf_cache=cache)
    derived = len(rounds) + len(rar3_calls)
    assert derived > 0
    with path.open("rb") as handle:
        second = parse_rar_archive(handle, password="header_password", kdf_cache=cache)
    assert len(rounds) + len(rar3_calls) == derived
    assert [m.filename for m in second.members] == [m.filename for m in first.members]


@requires("cryptography")
@pytest.mark.parametrize(
    "name",
    ["encrypted_header__.rar", "encrypted_header__rar4.rar"],
)
def test_kdf_cache_does_not_answer_for_another_password(name: str) -> None:
    """The cache is keyed by password: a wrong candidate after the right one
    still fails, and the right one after a wrong one still succeeds."""
    cache = RarKdfCache()
    path = _fixture(name)
    for password, ok in (
        ("not-the-password", False),
        ("header_password", True),
        ("not-the-password", False),
    ):
        with path.open("rb") as handle:
            if ok:
                archive = parse_rar_archive(handle, password=password, kdf_cache=cache)
                assert archive.members
            else:
                with pytest.raises((CorruptionError, EncryptionError)):
                    parse_rar_archive(handle, password=password, kdf_cache=cache)


def test_rar5_key_hash_key_and_check_match_one_unrar_chain() -> None:
    """UnRAR reads the AES key, HashKey and PswCheck from one PBKDF2 chain at ``n``,
    ``n + 16`` and ``n + 32`` rounds without resetting the running XOR. Each of
    ours is its own ``pbkdf2_hmac`` run; walking the chain by hand must agree.
    Checked against a mutation: ``rar5_hash_key`` deriving at ``+32`` instead of
    ``+16`` fails the second assertion."""
    password, salt, shift = "pässwörd", bytes(range(16)), 4
    u = hmac.new(password.encode(), salt + b"\0\0\0\1", hashlib.sha256).digest()
    acc = bytearray(u)
    chain = {1: bytes(acc)}
    for rounds in range(2, (1 << shift) + 33):
        u = hmac.new(password.encode(), u, hashlib.sha256).digest()
        acc = bytearray(a ^ b for a, b in zip(acc, u, strict=True))
        chain[rounds] = bytes(acc)
    n = 1 << shift
    assert rar5_data_key(password, salt, shift) == chain[n]
    assert rar5_hash_key(password, salt, shift) == chain[n + 16]
    pwd_check = bytearray(8)
    for i, v in enumerate(chain[n + 32]):
        pwd_check[i & 7] ^= v
    check_value = bytes(pwd_check) + hashlib.sha256(pwd_check).digest()[:4]
    assert _check_rar5_password(check_value, shift, salt, password)


@requires("cryptography")
def test_kdf_caches_keep_passwords_and_keys_out_of_repr() -> None:
    """Both caches hold candidate passwords and the keys derived from them."""
    rar = RarKdfCache()
    with _fixture("encrypted_header__.rar").open("rb") as handle:
        parse_rar_archive(handle, password="header_password", kdf_cache=rar)
    sevenzip = SevenZipKeyCache()
    # NumCyclesPower 4, IV flag only: no salt, one IV byte.
    sevenzip.aes_params_from_properties(
        "header_password".encode("utf-16-le"), b"\x44\x00\x00"
    )
    for cache in (rar, sevenzip):
        text = repr(cache)
        assert "header_password" not in text
        assert "\\x" not in text, text


@requires("cryptography")
@requires_binary("unrar")
def test_header_encrypted_volume_set_reads_back() -> None:
    """The committed ``-hp`` volume set is a real set, not only a listing."""
    from archivey import open_archive

    with open_archive(_fixture(_TINYVOL_HP[0]), password="header_password") as archive:
        assert archive.read("payload.bin") == b"ABCDEFGH" * 200


# A plain RAR cut part-way through a header lists the members before it and sets
# ``truncated``. The first FILE header starts at byte 20 in the RAR4 fixture and at
# byte 23 in the RAR5 one; the RAR5 header-size vint follows its 4-byte CRC.
_PLAIN_RAR4 = "basic_nonsolid__rar4.rar"
_PLAIN_RAR5 = "basic_nonsolid__.rar"


@pytest.mark.parametrize(
    ("name", "cut", "start"),
    [
        (_PLAIN_RAR4, 21, 20),  # inside the 7-byte block header
        (_PLAIN_RAR4, 40, 20),  # inside the header body
        (_PLAIN_RAR5, 25, 23),  # inside the CRC
        (_PLAIN_RAR5, 40, 23),  # inside the header body
    ],
)
def test_plain_header_cut_is_truncated(name: str, cut: int, start: int) -> None:
    data = _fixture(name).read_bytes()[:cut]
    archive = parse_rar_archive(io.BytesIO(data), password=None)
    assert archive.members == []
    assert archive.truncated is not None
    assert f"inside the header that starts at byte {start}" in archive.truncated
    assert archive.end_block_missing_volumes == []


def test_volume_set_header_cut_names_the_volume() -> None:
    """The walk's byte offset is within the cut volume, not the concatenated space
    the member offsets use, so the message says which volume it is in. Volume 2's
    first FILE header starts at byte 25."""
    part1 = _fixture("tinyvol.part1.rar").read_bytes()
    part2 = _fixture("tinyvol.part2.rar").read_bytes()[:30]
    archive = parse_rar_volumes([io.BytesIO(part1), io.BytesIO(part2)], password=None)
    assert archive.truncated is not None
    assert "header that starts at byte 25 (volume 2 of the set" in archive.truncated


@pytest.mark.parametrize(
    ("first", "rest"),
    [
        # RAR5: MAIN's volume number says this is not the first volume.
        ("tinyvol.part2.rar", "tinyvol.part1.rar"),
        # RAR4 has no volume number; the first FILE continues an earlier volume.
        ("tinyvol_rnn.r00", "tinyvol_rnn.rar"),
    ],
)
def test_set_not_starting_at_volume_one_needs_first_volume(
    first: str, rest: str
) -> None:
    """A later volume alone, or listed first, is refused rather than listed as a
    fragment of a member."""
    lone = _fixture(first).read_bytes()
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        parse_rar_archive(io.BytesIO(lone), password=None)
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        parse_rar_volumes([io.BytesIO(lone)], password=None)
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        parse_rar_volumes(
            [io.BytesIO(lone), io.BytesIO(_fixture(rest).read_bytes())],
            password=None,
        )


def _rar4_volume_renumbered(data: bytes, number: int) -> bytes:
    """A RAR 1.5-4 volume with its MAIN first-volume flag cleared and its end
    block's 0-based volume number set to ``number``, CRC16s fixed.

    ``tinyvol_rnn.rar`` renumbered 1 is what a middle volume 2 looks like when
    volume 1 ended on a member boundary: its first member does not continue an
    earlier one, and it says another volume follows. ``unrar l`` reports it as
    "volume 2" (measured, 7.00).
    """
    out = bytearray(data)
    pos = 7
    while pos + 7 <= len(out):
        block_type, flags, size = struct.unpack_from("<BHH", out, pos + 2)
        add = 0
        if flags & 0x8000 or block_type == 0x74:
            (add,) = struct.unpack_from("<I", out, pos + 7)
        if block_type == 0x73:
            struct.pack_into("<H", out, pos + 3, flags & ~0x0100)
        if block_type == 0x7B:
            assert flags & 0x000A == 0x000A  # data CRC, then the volume number
            struct.pack_into("<H", out, pos + 11, number)
        if block_type in (0x73, 0x7B):
            crc = zlib.crc32(bytes(out[pos + 2 : pos + size])) & 0xFFFF
            struct.pack_into("<H", out, pos, crc)
        pos += size + add
    return bytes(out)


def test_rar4_later_volume_starting_on_a_member_boundary_needs_first_volume() -> None:
    """No member continues from an earlier volume, so only the end block's volume
    number tells it from volume 1. It is refused like any later volume, rather than
    listed as volume 1 of a set "missing volume 2"."""
    data = _fixture("tinyvol_rnn.rar").read_bytes()
    later = _rar4_volume_renumbered(data, 1)
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        parse_rar_archive(io.BytesIO(later), password=None)
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        open_archive(io.BytesIO(later))
    # Volume number 0 is volume 1: the renumbering alone changes nothing.
    first = parse_rar_archive(
        io.BytesIO(_rar4_volume_renumbered(data, 0)), password=None
    )
    assert first.is_volume and first.needs_next_volume


def test_set_whose_last_volume_expects_another_is_truncated() -> None:
    """The set ends but its last volume says another follows. The members are kept
    and the truncation is recorded for the reader to raise after them; the member
    running into the missing volume stays ``split_after``."""
    archive = parse_rar_volumes(
        [io.BytesIO(_fixture("tinyvol_rnn.rar").read_bytes())], password=None
    )
    assert archive.truncated is not None
    assert "end of archive expects another volume (volume 2 is missing)" in (
        archive.truncated
    )
    (member,) = archive.members
    assert member.split_after


def test_lone_later_volume_path_lists_as_a_set_missing_volume_1(
    tmp_path: Path,
) -> None:
    """Ruled 2026-10-06 (this used to refuse with "Need first volume"): a later
    volume alone is a set missing the others. Its one member continues from volume 1,
    so it lists and its read is a truncation."""
    lone = tmp_path / "lone.part2.rar"
    lone.write_bytes(_fixture("tinyvol.part2.rar").read_bytes())
    with open_archive(lone) as archive:
        report = archive.members_report()
        assert [m.name for m in report.members] == ["payload.bin"]
        assert isinstance(report.error, TruncatedError)
        assert "volume 1 is missing" in str(report.error)
        with pytest.raises(TruncatedError, match="starts in a volume that is missing"):
            archive.read(report.members[0])


def test_a_lone_later_volume_stream_still_needs_its_first_volume() -> None:
    """A stream has no name to number it, so it stays refused."""
    lone = _fixture("tinyvol.part2.rar").read_bytes()
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        open_archive(io.BytesIO(lone))


def test_rar5_cut_inside_a_multibyte_header_size_is_truncated() -> None:
    """The fixture's size vints are one byte, so this writes the first byte of a
    two-byte one and ends the file there."""
    data = _fixture(_PLAIN_RAR5).read_bytes()[:27] + b"\xa7"
    archive = parse_rar_archive(io.BytesIO(data), password=None)
    assert archive.truncated is not None
    assert "header that starts at byte 23" in archive.truncated


@pytest.mark.parametrize(
    ("name", "at", "length", "replacement", "match"),
    [
        # RAR3 header size (bytes 25-26) below the 7-byte block header.
        (_PLAIN_RAR4, 25, 2, b"\x05\x00", "Invalid RAR3 header size"),
        # RAR5 header-size vint (byte 27) over the 2 MiB cap: 0x400000.
        (_PLAIN_RAR5, 27, 1, b"\x80\x80\x80\x02", "RAR5 header too large"),
        # RAR5 header-size vint longer than 10 bytes.
        (_PLAIN_RAR5, 27, 1, b"\x80" * 12, "variable-length integer too long"),
    ],
    ids=["rar4-size-too-small", "rar5-size-too-large", "rar5-vint-too-long"],
)
def test_plain_header_with_an_invalid_size_is_corruption_not_a_cut(
    name: str, at: int, length: int, replacement: bytes, match: str
) -> None:
    """Only a file that ends before a header's declared bytes is a cut. A declared
    size that is invalid while the bytes are present stays ``CorruptionError``."""
    data = _fixture(name).read_bytes()
    data = data[:at] + replacement + data[at + length :]
    with raises_corruption_not_truncation(match=match):
        parse_rar_archive(io.BytesIO(data), password=None)


# --- declared dictionary size ---------------------------------------------------


@pytest.mark.parametrize(
    ("compress_info", "expected"),
    [
        (0, 128 * 1024),  # RAR 5.0, exponent 0
        (13 << 10, 2**30),  # RAR 5.0, exponent 13
        (15 << 10, 4 * 2**30),  # RAR 5.0's largest
        (16 << 10, 128 * 1024),  # RAR 5.0 reads 4 bits: bit 14 is not part of it
        (1 | 16 << 10, 8 * 2**30),  # RAR 7.0 reads 5 bits
        (1 | 16 << 10 | 16 << 15, 12 * 2**30),  # plus 16/32 of the power of two
        (1 | 31 << 10 | 31 << 15, (2**17 << 31) * 63 // 32),
    ],
)
def test_rar5_dictionary_size_follows_unrar(compress_info: int, expected: int) -> None:
    assert _rar5_dictionary_size(compress_info) == expected


@pytest.mark.parametrize(
    "name",
    ["seek_respawn_solid__.rar", "basic_solid__rar4.rar", "basic_nonsolid__rar4.rar"],
)
def test_parsed_dictionary_size_is_set_and_zero_for_directories(name: str) -> None:
    with _fixture(name).open("rb") as f:
        archive = parse_rar_archive(f)
    for info in archive.members:
        if info.is_directory:
            assert info.dictionary_size == 0
        elif archive.version == 5:
            assert info.dictionary_size >= 128 * 1024
        else:
            # RAR3/4: 64 KiB << a 3-bit exponent, at most 4 MiB.
            assert 64 * 1024 <= info.dictionary_size <= 4 * 2**20
    assert any(not info.is_directory for info in archive.members)


def test_volume_set_packed_data_past_end_names_the_volume() -> None:
    """The walk's offsets are within one volume, so in a set the reason names it:
    byte 832 of a set whose volume 1 is 917 bytes would point into volume 1."""
    part1 = _fixture("tinyvol.part1.rar").read_bytes()
    part2 = _fixture("tinyvol.part2.rar").read_bytes()[:100]
    archive = parse_rar_volumes([io.BytesIO(part1), io.BytesIO(part2)], password=None)
    assert archive.truncated is not None
    assert "packed data ends at byte 832" in archive.truncated
    assert "(volume 2 of the set; the offset is within that volume)" in (
        archive.truncated
    )


class _CountingReader(io.BytesIO):
    """A ``BytesIO`` that adds up the bytes each ``read`` returns."""

    bytes_read = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data


def _rar5_block(
    block_type: int, body: bytes, *, extra: bytes = b"", data_size: int | None = None
) -> bytes:
    """One plain RAR5 header with a correct CRC, optional extra area and data size.

    Local because ``test_rar_header_record_leniency._rar5_header`` takes no data size,
    which the quick-open SERVICE header below needs.
    """
    flags = 0
    fields = b""
    if extra:
        flags |= 0x0001
        fields += _vint(len(extra))
    if data_size is not None:
        flags |= 0x0002
        fields += _vint(data_size)
    inner = _vint(block_type) + _vint(flags) + fields + body + extra
    sized = _vint(len(inner)) + inner
    return struct.pack("<I", zlib.crc32(sized) & 0xFFFFFFFF) + sized


def _vint(value: int, width: int = 0) -> bytes:
    """A RAR5 variable-length integer, padded with continuation bytes to ``width``."""
    out = bytearray()
    while True:
        out.append((value & 0x7F) | (0x80 if value > 0x7F else 0))
        value >>= 7
        if not value:
            break
    while len(out) < width:
        out[-1] |= 0x80
        out.append(0)
    return bytes(out)


def _rar5_stored(block_type: int, name: bytes, data_size: int) -> bytes:
    """A plain RAR5 FILE (2) or SERVICE (3) header for stored data of ``data_size``."""
    body = (
        _vint(0)  # file flags
        + _vint(data_size)  # unpacked size
        + _vint(0)  # attributes
        + _vint(0)  # compression info: stored
        + _vint(1)  # host OS: Unix
        + _vint(len(name))
        + name
    )
    return _rar5_block(block_type, body, data_size=data_size)


def test_repeated_rar5_main_headers_read_the_quick_open_payload_once() -> None:
    """A second MAIN header must not buy another read of the quick-open payload.

    ``unrar`` accepts more than one MAIN header, and the walk parses each one. Each
    MAIN here is 17 bytes and its locator points at the same 1 MiB QO payload, so a
    walk that tries the locator on every MAIN reads that payload once per header:
    300 MiB from a 1 MiB archive, and up to 16 MiB per header at the payload limit.
    Only the first MAIN of a volume is asked for the quick-open table.
    """
    count, qo_size = 300, 2**20

    def main(distance: int) -> bytes:
        # The distance is a fixed-width vint so that every MAIN is the same size and
        # ``qo_at`` can be computed before the distances are known. Unpadded, the
        # locators would miss the payload and the test would read nothing.
        locator = _vint(1) + _vint(0x01) + _vint(distance, width=5)
        return _rar5_block(1, _vint(0), extra=_vint(len(locator)) + locator)

    main_size = len(main(0))
    data = bytearray(b"Rar!\x1a\x07\x01\x00")
    qo_at = len(data) + count * main_size
    for _ in range(count):
        data += main(qo_at - len(data))
    data += _rar5_stored(3, b"QO", qo_size) + bytes(qo_size)
    data += _rar5_block(5, _vint(0))

    source = _CountingReader(bytes(data))
    archive = parse_rar_archive(source)
    assert archive.members == []
    # One read of the payload fits under this bound and two do not.
    assert source.bytes_read < len(data) + qo_size // 2


def _rar3_cmt(pack_size: int, *, flags: int = 0, method: int = 0x30) -> bytes:
    """A RAR 2.9-4 ``CMT`` SUB header, stored by default, CRC16 correct, LONG_BLOCK
    clear by default.

    Local because ``test_rar_reader._rar3_file_block`` always sets LONG_BLOCK, the one
    flag these tests need clear.
    """
    name = b"CMT"
    fixed = struct.pack(
        "<LLBLLBBHL", pack_size, pack_size, 3, 0, 0, 29, method, len(name), 0
    )
    body = struct.pack("<BHH", 0x7A, flags, 7 + len(fixed) + len(name)) + fixed + name
    return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body


def _rar3_main_and_end() -> tuple[bytes, bytes]:
    """The signature plus a plain MAIN header, and an end block; CRC16s correct."""
    main_body = struct.pack("<BHH", 0x73, 0, 13) + bytes(6)
    end_body = struct.pack("<BHH", 0x7B, 0x4000, 7)
    start = b"Rar!\x1a\x07\x00" + struct.pack("<H", zlib.crc32(main_body) & 0xFFFF)
    end = struct.pack("<H", zlib.crc32(end_body) & 0xFFFF) + end_body
    return start + main_body, end


@pytest.mark.parametrize(
    "long_block", [True, False], ids=["long_block", "no_long_block"]
)
def test_a_rar3_stored_comment_is_read_whether_or_not_long_block_is_set(
    long_block: bool,
) -> None:
    """unrar takes a SUB header's data size from PACK_SIZE whatever LONG_BLOCK says,
    so the comment is listed and the walk resumes after it, at the end block."""
    start, end = _rar3_main_and_end()
    text = b"hello comment"
    flags = 0x8000 if long_block else 0
    data = start + _rar3_cmt(len(text), flags=flags) + text + end
    archive = parse_rar_archive(io.BytesIO(data))
    assert archive.comment == "hello comment"
    assert archive.truncated is None


@pytest.mark.parametrize(
    "long_block", [True, False], ids=["long_block", "no_long_block"]
)
def test_a_rar3_stored_comment_past_the_end_of_the_file_is_a_cut(
    long_block: bool,
) -> None:
    """A PACK_SIZE that runs past the end of the file is a cut, as a member's data
    running past it is: no comment, and ``truncated`` says where the data ends. The
    LONG_BLOCK flag does not change that."""
    start, end = _rar3_main_and_end()
    flags = 0x8000 if long_block else 0
    data = start + _rar3_cmt(2**20, flags=flags) + b"short" + end
    archive = parse_rar_archive(io.BytesIO(data))
    assert archive.comment is None
    assert archive.truncated is not None
    assert "past the end of the file" in archive.truncated


def _rar3_member_then_cut_comment() -> bytes:
    """MAIN, a stored ``a.txt``, then a stored ``CMT`` whose PACK_SIZE (1 MiB) runs
    past the end of the file: only 5 data bytes and the end block follow it."""
    start, end = _rar3_main_and_end()
    member = _rar3_stored_file(b"a.txt", b"hello", flags=0x8000) + b"hello"
    return start + member + _rar3_cmt(2**20, flags=0x8000) + b"short" + end


def test_a_rar3_comment_past_the_end_of_the_file_keeps_the_members_before_it() -> None:
    """The comment read used to raise out of the walk, which discarded ``a.txt``.
    unrar 7.00 lists ``a.txt``, then reports "Unexpected end of archive"."""
    with open_archive(io.BytesIO(_rar3_member_then_cut_comment())) as archive:
        report = archive.members_report()
        assert [m.name for m in report.members] == ["a.txt"]
        assert isinstance(report.error, TruncatedError)
        assert archive.info.comment is None
        with archive.open(report.members[0]) as stream:
            assert stream.read() == b"hello"


@requires_binary("unrar")
def test_unrar_lists_the_member_before_a_rar3_comment_cut(tmp_path: Path) -> None:
    """The oracle for the test above."""
    path = tmp_path / "cut_comment.rar"
    path.write_bytes(_rar3_member_then_cut_comment())
    result = subprocess.run(
        ["unrar", "l", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert "a.txt" in result.stdout
    assert "Unexpected end of archive" in result.stdout + result.stderr


def test_a_rar3_compressed_comment_past_the_end_of_the_file_is_a_cut() -> None:
    """The rule does not depend on the method: a compressed (``-m3``) ``CMT``
    whose PACK_SIZE runs past the end of the file is a cut too."""
    start, end = _rar3_main_and_end()
    member = _rar3_stored_file(b"a.txt", b"hello", flags=0x8000) + b"hello"
    data = start + member + _rar3_cmt(4096, flags=0x8000, method=0x33) + b"short" + end
    archive = parse_rar_archive(io.BytesIO(data))
    assert [m.filename for m in archive.members] == ["a.txt"]
    assert archive.comment is None
    assert archive.truncated is not None


def _rar5_member_then_cut_comment() -> bytes:
    """MAIN, a stored ``a.txt``, then a stored ``CMT`` whose data (1 MiB) runs past
    the end of the file: only 5 data bytes and the end block follow it."""
    return (
        b"Rar!\x1a\x07\x01\x00"
        + _rar5_block(1, _vint(0))
        + _rar5_stored(2, b"a.txt", 5)
        + b"hello"
        + _rar5_stored(3, b"CMT", 2**20)
        + b"short"
        + _rar5_block(5, _vint(0))
    )


def test_a_rar5_comment_past_the_end_of_the_file_keeps_the_members_before_it() -> None:
    """The RAR5 ``CMT`` read had the same flaw: a stored comment whose data runs past
    the end of the file raised out of the walk and discarded ``a.txt``."""
    data = _rar5_member_then_cut_comment()
    archive = parse_rar_archive(io.BytesIO(data))
    assert [m.filename for m in archive.members] == ["a.txt"]
    assert archive.comment is None
    assert archive.truncated is not None
    with open_archive(io.BytesIO(data)) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == ["a.txt"]
        assert isinstance(report.error, TruncatedError)


@requires_binary("unrar")
def test_unrar_lists_the_member_before_a_rar5_comment_cut(tmp_path: Path) -> None:
    """The oracle for the RAR5 test above."""
    path = tmp_path / "cut_comment5.rar"
    path.write_bytes(_rar5_member_then_cut_comment())
    result = subprocess.run(
        ["unrar", "l", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert "a.txt" in result.stdout
    assert "Unexpected end of archive" in result.stdout + result.stderr


_BIG_COMMENT = 2**20


@pytest.mark.parametrize("version", ["rar3", "rar5"])
def test_a_comment_over_the_metadata_budget_is_refused_before_it_is_read(
    version: str,
) -> None:
    """A stored comment has no size cap of its own, so its bytes, all present, used
    to be read whole and only then weighed: a 1 KiB budget held the whole comment
    before refusing. Its packed size is now checked against ``max_metadata_bytes``
    before the read."""
    if version == "rar3":
        start, end = _rar3_main_and_end()
        cmt = _rar3_cmt(_BIG_COMMENT, flags=0x8000)
    else:
        start = b"Rar!\x1a\x07\x01\x00" + _rar5_block(1, _vint(0))
        end = _rar5_block(5, _vint(0))
        cmt = _rar5_stored(3, b"CMT", _BIG_COMMENT)
    source = _CountingReader(start + cmt + b"x" * _BIG_COMMENT + end)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=1024"):
        parse_rar_archive(source, max_metadata_bytes=1024)
    assert source.bytes_read < _BIG_COMMENT


def test_a_rar3_comment_is_read_only_from_the_bytes_the_walk_skips() -> None:
    """A RAR 1.5-4 ``CMT`` header must not read bytes the walk then parses again.

    Each of these 35-byte ``CMT`` headers has LONG_BLOCK clear and claims everything
    after it as its comment. A comment read of PACK_SIZE paired with a walk that skips
    only the LONG_BLOCK size made every one of them re-read the rest of the archive:
    300 headers read 300 copies of a 256 KiB tail. The read and the skip are one span,
    so the first header's comment covers the rest and the walk ends there.
    """
    count, tail = 300, 256 * 1024
    start, end = _rar3_main_and_end()
    header_size = len(_rar3_cmt(0))
    rest = count * header_size + len(end) + tail
    data = bytearray(start)
    for index in range(count):
        data += _rar3_cmt(rest - (index + 1) * header_size)
    data += end + bytes(tail)

    source = _CountingReader(bytes(data))
    archive = parse_rar_archive(source)
    assert archive.members == []
    # One read of the tail fits under this bound and two do not.
    assert source.bytes_read < len(data) + tail // 2


def _rar3_stored_file(name: bytes, data: bytes, *, flags: int) -> bytes:
    """One RAR 1.5-4 FILE header for a stored member, CRC16 correct."""
    fixed = struct.pack(
        "<LLBLLBBHL",
        len(data),  # PACK_SIZE
        len(data),  # UNP_SIZE
        3,  # host OS: Unix
        zlib.crc32(data) & 0xFFFFFFFF,
        0x21 << 9 | 1 << 5,  # DOS time
        29,  # extract version
        0x30,  # method: stored
        len(name),
        0o100644,
    )
    body = struct.pack("<BHH", 0x74, flags, 7 + len(fixed) + len(name)) + fixed + name
    return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body


def _rar4_member_carrying_a_member() -> bytes:
    """``carrier.bin`` holds a complete FILE header and data for ``hidden.txt``.

    The carrier's header has LONG_BLOCK (0x8000) clear. Its PACK_SIZE still covers
    ``hidden.txt``, and unrar takes a FILE header's data size from PACK_SIZE whatever
    LONG_BLOCK says, so for unrar ``hidden.txt`` is only bytes inside ``carrier.bin``.
    No writer clears LONG_BLOCK on a FILE header, so the archive is crafted.
    """
    start, end = _rar3_main_and_end()
    hidden = _rar3_stored_file(b"hidden.txt", b"smuggled\n", flags=0x8000)
    hidden += b"smuggled\n"
    return start + _rar3_stored_file(b"carrier.bin", hidden, flags=0) + hidden + end


def test_a_rar4_file_header_skips_its_pack_size_without_long_block() -> None:
    """A member's data must not be listed as more members.

    The walk skipped a FILE header's data only when LONG_BLOCK was set, so with the
    flag clear it parsed ``carrier.bin``'s data as headers and listed (and read)
    ``hidden.txt``, a member unrar does not have.
    """
    archive = parse_rar_archive(io.BytesIO(_rar4_member_carrying_a_member()))
    assert [m.filename for m in archive.members] == ["carrier.bin"]
    assert archive.members[0].compress_size == 51


@requires_unrar_cli()
def test_unrar_skips_a_rar4_file_headers_pack_size_without_long_block(
    tmp_path: Path,
) -> None:
    """The rule above is unrar's: it lists only the carrier and has no ``hidden.txt``."""
    path = tmp_path / "carrier.rar"
    path.write_bytes(_rar4_member_carrying_a_member())
    listed = subprocess.run(
        ["unrar", "lb", str(path)], capture_output=True, text=True, check=True
    )
    # Names are matched inside the output rather than split out of it: unrar on the
    # Windows runner ends a bare listing line with a literal ``\x0d``.
    assert "carrier.bin" in listed.stdout
    assert "hidden.txt" not in listed.stdout
    with open_archive(path) as archive:
        assert [m.name for m in archive.members_report().members] == ["carrier.bin"]
