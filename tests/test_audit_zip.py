"""Audit reproducers for the ZIP backend (extraction-security audit).

Each test asserts the promised behaviour and is marked ``xfail(strict=True)`` while the
bug stands; the ``reason`` names the defect. Remove the marker when the fix lands.
"""

from __future__ import annotations

import base64
import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

import archivey
from archivey.exceptions import (
    ResourceLimitError,
    ResourceUnavailableError,
    UnsupportedFeatureError,
)
from tests.extract_util import open_and_extract
from tests.zipcrypto import _Keys, build_zipcrypto_zip

# 7-Zip 16.02 `7z a -tzip -mm=LZMA:eos=off`: one LZMA (method 14) member `f.txt` with
# general-purpose bit 1 clear, so the LZMA stream has no end-of-stream marker and the
# decoder must stop at the declared uncompressed size (APPNOTE 4.4.4, bit 1). 7-Zip
# and stdlib zipfile both read it.
_LZMA_NO_EOS_ZIP = base64.b64decode(
    "UEsDBD8AAAAOAGliPF0isOxhKQAAAEYAAAAFAAAAZi50eHQXAQUAXQAQAAAANhpKHwigJcHelLqQzDsr"
    "HzU68l/Vnn5zst7TcnaHoFBLAQI/Az8AAAAOAGliPF0isOxhKQAAAEYAAAAFACQAAAAAAAAAIICkgQAA"
    "AABmLnR4dAoAIAAAAAAAAQAYADqmUpRDT90BAAAAAAAAAAAAAAAAAAAAAFBLBQYAAAAAAQABAFcAAABM"
    "AAAAAAA="
)
_LZMA_NO_EOS_PAYLOAD = b"".join(b"line %d\n" % i for i in range(10))


def test_lzma_member_without_eos_marker_extracts(tmp_path: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(_LZMA_NO_EOS_ZIP)) as zf:
        info = zf.infolist()[0]
        assert info.compress_type == zipfile.ZIP_LZMA
        assert not info.flag_bits & 0x2
        assert zf.read(info) == _LZMA_NO_EOS_PAYLOAD  # stdlib reads it

    open_and_extract(io.BytesIO(_LZMA_NO_EOS_ZIP), tmp_path / "out")
    assert (tmp_path / "out" / "f.txt").read_bytes() == _LZMA_NO_EOS_PAYLOAD

    # The canonical read loop: keep reading until b"".
    with archivey.open_archive(io.BytesIO(_LZMA_NO_EOS_ZIP)) as ar:
        (member,) = ar.members()
        with ar.open(member) as stream:
            chunks = []
            while chunk := stream.read(16):
                chunks.append(chunk)
    assert b"".join(chunks) == _LZMA_NO_EOS_PAYLOAD


# A ZipCrypto LZMA member written with password b"right" and the 11 random header bytes
# below. They were searched for (offline, in C) so that the wrong password b"wrong"
# passes the one-byte header check (1 in 256) and decrypts the ZIP LZMA header to a
# well-formed 5-byte properties blob whose dictionary size is over 2 GiB. That is what
# about one colliding wrong password in five does to any ZipCrypto LZMA member.
_LZMA_COLLISION_HEADER = bytes.fromhex("40c0c20000000000555555")
_LZMA_COLLISION_PAYLOAD = b"archivey audit lzma payload\n" * 64


def _zipcrypto_lzma_with_colliding_wrong_password() -> bytes:
    data = _LZMA_COLLISION_PAYLOAD
    name = b"a.txt"
    blob = bytearray(
        build_zipcrypto_zip(b"right", name, data, compression=zipfile.ZIP_LZMA)
    )
    start = 30 + len(name)
    (compressed_size,) = struct.unpack_from("<I", blob, 18)
    # Decrypt the builder's member to recover the ZIP LZMA body, then re-encrypt it
    # behind the searched header.
    keys = _Keys(b"right")
    plaintext = bytearray()
    for cipher in blob[start : start + compressed_size]:
        plain = cipher ^ keys.keystream_byte()
        plaintext.append(plain)
        keys.update(plain)
    stored = bytes(plaintext[12:])
    header = _LZMA_COLLISION_HEADER + bytes([zlib.crc32(data) >> 24])
    keys = _Keys(b"right")
    encrypted = bytearray()
    for plain in header + stored:
        encrypted.append(plain ^ keys.keystream_byte())
        keys.update(plain)
    assert blob[start + len(encrypted) : start + len(encrypted) + 4] == b"PK\x01\x02"
    blob[start : start + len(encrypted)] = encrypted
    return bytes(blob)


def test_colliding_wrong_candidate_does_not_hide_the_right_password() -> None:
    blob = _zipcrypto_lzma_with_colliding_wrong_password()
    with archivey.open_archive(io.BytesIO(blob), password="right") as ar:
        assert ar.read(ar.members()[0]) == _LZMA_COLLISION_PAYLOAD  # fixture sanity

    # format-zip "Confirm multi-candidate ZipCrypto passwords": a wrong candidate that
    # passes the verification byte is rejected and the correct one reads (LZMA row).
    with archivey.open_archive(io.BytesIO(blob), password=["wrong", "right"]) as ar:
        assert ar.read(ar.members()[0]) == _LZMA_COLLISION_PAYLOAD


def test_colliding_lone_wrong_password_is_a_noted_resource_limit() -> None:
    blob = _zipcrypto_lzma_with_colliding_wrong_password()
    # format-zip (maintainer decision 2026-09-28): the decrypted LZMA properties ask
    # for a dictionary over max_decoder_memory. With one password nothing tells a
    # wrong key's garbage from a real size, so the open raises ResourceLimitError
    # (raising the cap is what a right password needs) and says the ZipCrypto
    # password may be wrong.
    with archivey.open_archive(io.BytesIO(blob), password="wrong") as ar:
        member = ar.members()[0]
        with pytest.raises(ResourceLimitError) as excinfo:
            ar.read(member)
    assert "password may be wrong" in str(excinfo.value)
    assert excinfo.value.member_name == "a.txt"


def test_colliding_wrong_candidates_only_raise_the_noted_resource_limit() -> None:
    blob = _zipcrypto_lzma_with_colliding_wrong_password()
    # Several candidates, none right: the first limit a candidate's settings tripped
    # is raised, with the same note, rather than the password-or-damage error.
    with archivey.open_archive(
        io.BytesIO(blob), password=["wrong", "also-wrong"]
    ) as ar:
        member = ar.members()[0]
        with pytest.raises(ResourceLimitError) as excinfo:
            ar.read(member)
    assert "password may be wrong" in str(excinfo.value)


def _patched_data_zip(payload: bytes) -> bytes:
    """One DEFLATE member with general-purpose bit 5 ("compressed patched data") set."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("a.txt", (2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, payload)
    blob = bytearray(buf.getvalue())
    cd = blob.rfind(b"PK\x01\x02")
    for flags_at in (6, cd + 8):
        (flags,) = struct.unpack_from("<H", blob, flags_at)
        struct.pack_into("<H", blob, flags_at, flags | 0x20)
    return bytes(blob)


def test_compressed_patched_data_member_is_refused() -> None:
    # The body is a patch against some other file, not the file. stdlib zipfile
    # refuses it (NotImplementedError "compressed patched data (flag bit 5)"); the
    # spec says an unsupported entry gets UnsupportedFeatureError and "no guessed
    # output". Here the stored CRC is the one of the bytes returned, so no check
    # notices.
    blob = _patched_data_zip(b"patch-stream-bytes " * 20)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf, pytest.raises(NotImplementedError):
        zf.read("a.txt")
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        member = ar.members()[0]
        with pytest.raises(UnsupportedFeatureError):
            ar.read(member)


def test_idna_encoding_does_not_raise_raw_unicode_error() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", b"x")
    with archivey.open_archive(io.BytesIO(buf.getvalue()), encoding="idna") as ar:
        try:
            members = ar.members()
        except archivey.ArchiveyError:
            return  # a typed refusal is acceptable
        assert [m.name for m in members] == ["hello.txt"]


def test_idna_encoding_leaves_ascii_names_and_their_raw_name() -> None:
    # "a..b" is valid UTF-8, so it is UTF-8 whatever encoding= says, and the idna
    # codec (which cannot encode the empty label back) never touches it.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a..b", b"x")
        zf.writestr("ok.txt", b"y")
    with archivey.open_archive(io.BytesIO(buf.getvalue()), encoding="idna") as ar:
        members = ar.members()
    assert [(m.name, m.raw_name) for m in members] == [
        ("a..b", b"a..b"),
        ("ok.txt", b"ok.txt"),
    ]


def test_idna_encoding_on_a_legacy_name_keeps_the_fallback() -> None:
    # A non-UTF-8 unflagged name goes to encoding= with surrogateescape; idna refuses
    # that handler, so the configured fallback (cp437) decodes it instead.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("cafX.txt", b"x")  # ASCII, so the UTF-8 flag stays clear
    blob = buf.getvalue().replace(b"cafX.txt", b"caf\x82.txt")  # cp437 0x82 = é
    with archivey.open_archive(io.BytesIO(blob), encoding="idna") as ar:
        assert [m.name for m in ar.members()] == ["café.txt"]


def test_idna_unflagged_fallback_keeps_the_cp437_name() -> None:
    # A non-UTF-8 unflagged name goes to zip_unflagged_fallback_encoding, decoded
    # with surrogateescape; idna refuses that handler, so the cp437 name is kept.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("café.txt", b"x")  # cp437-encodable: flag bit 11 stays clear
    config = archivey.ArchiveyConfig(zip_unflagged_fallback_encoding="idna")
    with archivey.open_archive(io.BytesIO(buf.getvalue()), config=config) as ar:
        assert [m.name for m in ar.members()] == ["café.txt"]


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("password", ["right", ["wrong", "right"]])
def test_no_decoder_child_under_zipcrypto_is_not_a_noted_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    password: str | list[str],
    streaming: bool,
) -> None:
    """A decoder child that cannot start is the system running short, not settings a
    wrong key decrypted: it stays ``ResourceUnavailableError``, with no password note
    (format-zip, "Read ZipCrypto-encrypted members")."""
    blob = build_zipcrypto_zip(
        b"right", b"a.txt", _LZMA_COLLISION_PAYLOAD, compression=zipfile.ZIP_LZMA
    )
    monkeypatch.setattr(sys, "executable", str(tmp_path / "no-such-python"))
    config = archivey.ArchiveyConfig(
        process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS
    )
    with (
        archivey.open_archive(
            io.BytesIO(blob), password=password, config=config, streaming=streaming
        ) as ar,
        pytest.raises(ResourceUnavailableError) as excinfo,
    ):
        if streaming:
            for _member, stream in ar.stream_members():
                assert stream is not None
                stream.read()
        else:
            ar.read(ar.members()[0])
    assert "password may be wrong" not in str(excinfo.value)
