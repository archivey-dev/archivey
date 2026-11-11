"""The 7z AES tail key check: zero padding in the last CBC block confirms a password.

Every test here would pass on the slow path the check is meant to skip (the integrity
anchor rejects a wrong password anyway), so each one spies on which rung decided:
``aes_tail_confirms`` for the cheap check, ``_confirm_folder_password`` for the anchor
decode.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from archivey import open_archive
from archivey.exceptions import CorruptionError
from archivey.internal.backends import (
    sevenzip_pipeline as pipeline_mod,
    sevenzip_reader as reader_mod,
)
from archivey.internal.backends.sevenzip_aes import parse_sevenzip_aes_properties
from archivey.internal.password_confirm import PasswordConfirmVerdict
from tests.conftest import requires
from tests.test_sevenzip_reader import _write_py7zr_archive

pytestmark = [requires("cryptography"), requires("py7zr")]

_PASSWORD = "secret"


def _filters(*names: str) -> list[dict[str, int]]:
    py7zr = pytest.importorskip("py7zr")
    return [{"id": getattr(py7zr, f"FILTER_{name}")} for name in names]


def _copy_aes(tmp_path: Path, size: int, name: str = "a.7z") -> tuple[Path, bytes]:
    """A one-member store+AES archive whose payload is ``size`` bytes."""
    payload = bytes((i * 7 + 3) % 251 for i in range(size))
    archive = tmp_path / name
    _write_py7zr_archive(
        archive,
        {"a.bin": payload},
        filters=_filters("COPY", "CRYPTO_AES256_SHA256"),
        password=_PASSWORD,
    )
    return archive, payload


class _Spies:
    """Record each tail check's answer and each anchor decode."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tail: list[bool] = []
        self.anchor = 0
        original_tail = reader_mod.aes_tail_confirms
        original_confirm = reader_mod.SevenZipReader._confirm_folder_password

        def tail(*args: Any, **kwargs: Any) -> bool:
            answer = original_tail(*args, **kwargs)
            self.tail.append(answer)
            return answer

        def confirm(reader: Any, *args: Any, **kwargs: Any) -> PasswordConfirmVerdict:
            self.anchor += 1
            return original_confirm(reader, *args, **kwargs)

        monkeypatch.setattr(reader_mod, "aes_tail_confirms", tail)
        monkeypatch.setattr(
            reader_mod.SevenZipReader, "_confirm_folder_password", confirm
        )


def _padding(archive: Path) -> int:
    with open_archive(archive, password=_PASSWORD) as reader:
        tail = pipeline_mod.folder_aes_tail(reader._archive.folders[0])
        assert tail is not None
        return reader._archive.pack_sizes[0] - tail.unpack_size


def _read_all(archive: Path, **kwargs: Any) -> bytes:
    with open_archive(archive, **kwargs) as reader:
        member = next(m for m in reader.members() if m.is_file)
        return reader.read(member)


@pytest.mark.parametrize(
    ("size", "padding"), [(32, 0), (30, 2), (29, 3), (28, 4), (23, 9), (17, 15), (9, 7)]
)
def test_padding_matrix_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: int, padding: int
) -> None:
    archive, payload = _copy_aes(tmp_path, size)
    assert _padding(archive) == padding
    spies = _Spies(monkeypatch)
    assert _read_all(archive, password=_PASSWORD) == payload
    if padding >= pipeline_mod.AES_TAIL_MIN_PADDING:
        # Confirmed on the tail: no anchor decode ran.
        assert spies.tail == [True]
        assert spies.anchor == 0
    else:
        # Too few padding bytes to say anything: the anchor decides.
        assert spies.tail == [False]
        assert spies.anchor == 1


def test_lzma2_member_confirms_on_the_tail_when_it_has_the_padding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The padding of a compressed member depends on its compressed size, so try
    # payloads until one leaves at least AES_TAIL_MIN_PADDING bytes.
    for size in range(200, 240):
        payload = (b"lzma2 tail check " * 40)[:size] + bytes([size % 256])
        archive = tmp_path / f"lzma2-{size}.7z"
        _write_py7zr_archive(
            archive,
            {"a.bin": payload},
            filters=_filters("LZMA2", "CRYPTO_AES256_SHA256"),
            password=_PASSWORD,
        )
        if _padding(archive) >= pipeline_mod.AES_TAIL_MIN_PADDING:
            break
    else:
        pytest.fail("no payload size left enough padding")
    spies = _Spies(monkeypatch)
    assert _read_all(archive, password=_PASSWORD) == payload
    assert spies.tail == [True]
    assert spies.anchor == 0


def _rewrite_padding(archive: Path, fill: bytes) -> None:
    """Re-encrypt the last CBC block of a store+AES archive with non-zero padding.

    Made by patching the ciphertext, not by hoping a writer pads with residue. The
    member's CRC does not cover the padding, so the archive stays valid.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    with open_archive(archive, password=_PASSWORD) as reader:
        sz = reader._archive
        tail = pipeline_mod.folder_aes_tail(sz.folders[0])
        assert tail is not None and tail.coder.properties is not None
        start = sz.pack_pos + sz.pack_positions[0]  # pack_pos counts the signature
        pack_size = sz.pack_sizes[0]
        padding = pack_size - tail.unpack_size
        _cycles, _salt, iv = parse_sevenzip_aes_properties(tail.coder.properties)
    key = (
        reader_mod.SevenZipKeyCache()
        .aes_params_from_properties(
            _PASSWORD.encode("utf-16-le"), tail.coder.properties
        )
        .key
    )
    data = bytearray(archive.read_bytes())
    last = start + pack_size - 16
    prev = bytes(data[last - 16 : last]) if pack_size > 16 else iv
    block = bytes(data[last : last + 16])
    plain = Cipher(algorithms.AES(key), modes.CBC(prev)).decryptor().update(block)
    assert plain[-padding:] == bytes(padding)
    plain = plain[:-padding] + (fill * 16)[:padding]
    data[last : last + 16] = (
        Cipher(algorithms.AES(key), modes.CBC(prev)).encryptor().update(plain)
    )
    archive.write_bytes(bytes(data))


def test_non_zero_padding_drops_no_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A writer that pads with residue must keep its correct password: the check
    # says nothing, and the anchor finds it.
    archive, payload = _copy_aes(tmp_path, 23)
    _rewrite_padding(archive, b"\xa5")
    spies = _Spies(monkeypatch)
    assert _read_all(archive, password=_PASSWORD) == payload
    assert spies.tail == [False]
    assert spies.anchor == 1


def test_wrong_candidates_do_not_confirm_on_the_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, payload = _copy_aes(tmp_path, 23)
    spies = _Spies(monkeypatch)
    passwords = ["wrong-1", "wrong-2", _PASSWORD]
    assert _read_all(archive, password=passwords) == payload
    # The two wrong candidates found no zero tail and fell through to the anchor,
    # which rejected them; the right one confirmed on the tail alone.
    assert spies.tail == [False, False, True]
    assert spies.anchor == 2


def test_a_false_confirm_on_short_padding_does_not_stop_the_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seven padding bytes: a wrong key finds them zero 1 time in 2^56, at four bytes
    # 1 in 2^32. Stand in for that by making every tail check pass. With several
    # candidates such a tail settles nothing, so the anchor rejects the wrong one and
    # the right one is still tried.
    archive, payload = _copy_aes(tmp_path, 9)
    assert _padding(archive) < pipeline_mod.AES_TAIL_STRONG_PADDING
    spies = _Spies(monkeypatch)
    monkeypatch.setattr(reader_mod, "aes_tail_confirms", lambda *_a, **_k: True)
    assert _read_all(archive, password=["wrong-1", _PASSWORD]) == payload
    assert spies.anchor == 2


def test_short_padding_still_confirms_a_lone_password_on_the_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With one candidate there is nothing a false confirm could hide.
    archive, payload = _copy_aes(tmp_path, 9)
    spies = _Spies(monkeypatch)
    assert _read_all(archive, password=_PASSWORD) == payload
    assert spies.tail == [True]
    assert spies.anchor == 0


def test_the_tail_picks_the_right_password_when_no_anchor_can(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A folder with no CRC anywhere leaves every candidate INCONCLUSIVE at the
    # anchor, and the reader used to take the first one blind. Stand in for that
    # folder by making the anchor say nothing.
    archive, payload = _copy_aes(tmp_path, 23)
    spies = _Spies(monkeypatch)
    calls: list[int] = []

    def no_anchor(*_args: Any, **_kwargs: Any) -> PasswordConfirmVerdict:
        calls.append(1)
        return PasswordConfirmVerdict.INCONCLUSIVE

    monkeypatch.setattr(
        reader_mod.SevenZipReader, "_confirm_folder_password", no_anchor
    )
    passwords = ["wrong-1", _PASSWORD]
    assert _read_all(archive, password=passwords) == payload
    assert spies.tail == [False, True]
    assert calls == [1]


def test_the_tail_check_decodes_no_folder_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, payload = _copy_aes(tmp_path, 4096 - 7)
    pipelines: list[int] = []
    original: Callable[..., Any] = reader_mod.open_folder_pipeline

    def counting(*args: Any, **kwargs: Any) -> Any:
        pipelines.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(reader_mod, "open_folder_pipeline", counting)
    assert _read_all(archive, password=_PASSWORD) == payload
    # One pipeline, for the member read. The confirm used to open its own.
    assert pipelines == [1]


def test_aes_output_longer_than_its_pack_stream_is_corrupt_not_a_wrong_password(
    tmp_path: Path,
) -> None:
    # A block-aligned pack size shorter than the AES coder's declared output reads
    # short under the correct password, which used to be reported as a wrong one.
    archive, _payload = _copy_aes(tmp_path, 40)
    with open_archive(archive, password=_PASSWORD) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert reader._archive.pack_sizes[0] == 48
        reader._archive.pack_sizes[0] = 32
        with pytest.raises(CorruptionError, match="AES never outputs") as excinfo:
            reader.read(member)
    assert "password" not in str(excinfo.value).lower()


def test_a_pack_size_forged_longer_still_reads(tmp_path: Path) -> None:
    # More packed bytes than output plus a block is not refused: the bytes the
    # decoder needs are all there. The tail check just does not run.
    archive, payload = _copy_aes(tmp_path, 40)
    with open_archive(archive, password=_PASSWORD) as reader:
        member = next(m for m in reader.members() if m.is_file)
        reader._archive.pack_sizes[0] = 48 + 5
        assert reader.read(member) == payload


def test_key_derivation_runs_once_per_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The tail check and the member read share the reader's key cache.
    archive, payload = _copy_aes(tmp_path, 23)
    calls: list[bytes] = []
    original = hashlib.sha256

    def counting(*args: Any, **kwargs: Any) -> Any:
        calls.append(b"")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        "archivey.internal.backends.sevenzip_aes.hashlib.sha256", counting
    )
    assert _read_all(archive, password=_PASSWORD) == payload
    assert len(calls) == 1


@pytest.mark.parametrize("pad", [b"\0", b"\xa5"], ids=["zero-tail", "residue-tail"])
def test_a_folder_with_no_crc_confirmed_on_its_tail_is_unlocked(pad: bytes) -> None:
    # The tail proves the key, so the members start at UNLOCKED, a full read reaches
    # LENGTH, and a read abandoned part-way is not reported as unverified. It proves
    # nothing about the data: DIGEST_UNVERIFIABLE still fires. With residue in the
    # padding the tail proves nothing, so the same steps stay at NONE and the abandoned
    # read is reported, which keeps the first half from passing vacuously.
    import io

    from archivey import Verification
    from archivey.diagnostics import DiagnosticCode
    from tests.test_audit_sevenzip import (
        _AES,
        _LZMA2,
        _aes_encrypt,
        _archive,
        _coder,
        _header,
        _linear,
        _lzma2,
    )

    for size in range(3000, 3100):
        payload = bytes((i * 31 + size) % 256 for i in range(size))
        compressed = _lzma2(payload, 1 << 20)
        if -len(compressed) % 16 >= pipeline_mod.AES_TAIL_MIN_PADDING:
            break
    packed = _aes_encrypt(compressed, "pw", pad=pad)
    folder = _linear([_coder(_AES, props=b"\x00"), _coder(_LZMA2, props=bytes([16]))])
    header = _header(
        folders=[folder],
        coder_unpack_sizes=[[len(compressed), len(payload)]],
        pack_sizes=[len(packed)],
        names=["x"],
    )
    data = _archive(packed, header)
    confirmed = pad == b"\0"
    with open_archive(io.BytesIO(data), password="pw") as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read(1) == payload[:1]
        partial = member.verified
        counts = reader.diagnostics.counts  # type: ignore[attr-defined]
        abandoned = counts.get(DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED, 0)
    assert partial is (Verification.UNLOCKED if confirmed else Verification.NONE)
    assert abandoned == (0 if confirmed else 1)

    with open_archive(io.BytesIO(data), password="pw") as reader:
        (member,) = reader.members()
        assert reader.read(member) == payload
        level = Verification.LENGTH if confirmed else Verification.NONE
        assert (member.verified, member.verifiable) == (level, level)
        counts = reader.diagnostics.counts  # type: ignore[attr-defined]
        assert counts.get(DiagnosticCode.DIGEST_UNVERIFIABLE, 0) == 1
        assert counts.get(DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED, 0) == 0
