"""End-to-end: the 7z password-confirmation ladder decodes only what it must.

The budget tests assert *bytes decoded by the confirm pipeline*, not wall time, and each
carries its own mutation check: the same measurement taken with the ladder forced onto
the path the test exists to rule out, so a measurement that could not tell the two
apart fails here instead of passing quietly (design §5 preamble of the
bounded-password-confirmation change). The behaviour tests pin an error type or a
diagnostic instead, and need no counter-measurement.

Fixtures are written into ``tmp_path`` by the ``7z`` CLI, a few MiB each; the property
they pin (confirm stops at the first member's CRC, or at the prefix) does not depend on
the folder being 200 MiB.
"""

from __future__ import annotations

import random
import subprocess
from pathlib import Path
from typing import BinaryIO

import pytest

import archivey.internal.backends.sevenzip_reader as sevenzip_reader_mod
from archivey import open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import ArchiveyError, EncryptionError
from archivey.internal.password_confirm import (
    PASSWORD_CONFIRM_PREFIX_BYTES,
    PasswordConfirmPlan,
    plan_password_confirm,
)
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation

pytestmark = [requires("cryptography"), requires_binary("7z")]

_SMALL = 4096
_BIG = 4 * 1024 * 1024
_PASSWORD = "secret"


class _CountingStream:
    """Counts the bytes read through a folder pipeline."""

    def __init__(self, inner: BinaryIO) -> None:
        self._inner = inner
        self.bytes_read = 0

    def read(self, n: int = -1, /) -> bytes:
        data = self._inner.read(n)
        self.bytes_read += len(data)
        return data

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def _count_pipelines(monkeypatch: pytest.MonkeyPatch) -> list[_CountingStream]:
    streams: list[_CountingStream] = []
    original = sevenzip_reader_mod.open_folder_pipeline

    def counting(*args: object, **kwargs: object) -> _CountingStream:
        stream = _CountingStream(original(*args, **kwargs))  # type: ignore[arg-type]
        streams.append(stream)
        return stream

    monkeypatch.setattr(sevenzip_reader_mod, "open_folder_pipeline", counting)
    return streams


def _payload(size: int, seed: int) -> bytes:
    # Compressible but not trivially so: LZMA2 still has work to do.
    words = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot"]
    out = bytearray()
    i = seed
    while len(out) < size:
        out += words[(i * 7 + i // 3) % len(words)] + b" "
        i += 1
    return bytes(out[:size])


def _build(
    tmp_path: Path, name: str, files: dict[str, bytes], *, method: str, solid: bool
) -> Path:
    src = tmp_path / f"{name}-src"
    src.mkdir()
    for file_name, data in files.items():
        (src / file_name).write_bytes(data)
    archive = tmp_path / f"{name}.7z"
    result = subprocess.run(
        [
            "7z",
            "a",
            "-t7z",
            f"-p{_PASSWORD}",
            "-mhe=off",
            f"-m0={method}",
            f"-ms={'on' if solid else 'off'}",
            str(archive),
            *files,
            "-y",
        ],
        cwd=src,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build the fixture: {result.stderr}")
    return archive


def _first_member_read(archive: Path, password: object) -> tuple[bytes, object]:
    with open_archive(archive, password=password) as reader:  # type: ignore[arg-type]
        members = [m for m in reader.members() if m.is_file]
        with reader.open(members[0]) as stream:
            data = stream.read(1)
        return data, reader.diagnostics


def _walk_whole_unit(
    substreams: object, tail_crc: object, *, budget: int, codec_rejects: bool
) -> PasswordConfirmPlan:
    # The mutation: the pre-change ladder, which walked every member CRC to the end.
    items = list(substreams)  # type: ignore[call-overload]
    return PasswordConfirmPlan(tuple(items), None, confirms=True, bounded=False)


def _build_solid_copy(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """A solid store+AES folder. The ``7z`` CLI writes one folder per file for Copy."""
    py7zr = pytest.importorskip("py7zr")
    from tests.test_sevenzip_reader import _write_py7zr_archive

    archive = tmp_path / "solid-copy.7z"
    _write_py7zr_archive(
        archive,
        files,
        filters=[
            {"id": py7zr.FILTER_COPY},
            {"id": py7zr.FILTER_CRYPTO_AES256_SHA256},
        ],
        password=_PASSWORD,
    )
    return archive


@pytest.mark.parametrize("method", ["LZMA2", "Copy"])
def test_solid_folder_confirm_decodes_only_the_first_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    small, big = _payload(_SMALL, 1), _payload(_BIG, 2)
    files = {"a.bin": small, "b.bin": big}
    if method == "Copy":
        archive = _build_solid_copy(tmp_path, files)
    else:
        archive = _build(tmp_path, "solid", files, method=method, solid=True)
    with open_archive(archive, password=_PASSWORD) as reader:
        assert reader.info.is_solid, "fixture must hold both members in one folder"
    streams = _count_pipelines(monkeypatch)
    data, _ = _first_member_read(archive, _PASSWORD)
    assert data == small[:1]
    confirm = streams[0]
    # The first member's CRC settles the key.
    assert confirm.bytes_read == _SMALL

    # Mutation check: with the plan walking the folder, the same count sees it all.
    monkeypatch.setattr(sevenzip_reader_mod, "plan_password_confirm", _walk_whole_unit)
    streams.clear()
    _first_member_read(archive, _PASSWORD)
    assert streams[0].bytes_read == _SMALL + _BIG


def test_lzma2_late_crc_confirm_reads_the_prefix_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = _payload(_BIG, 3)
    archive = _build(tmp_path, "lzma2", {"big.bin": big}, method="LZMA2", solid=True)
    streams = _count_pipelines(monkeypatch)
    data, diagnostics = _first_member_read(archive, _PASSWORD)
    assert data == big[:1]
    # A rejecting codec settles a wrong key inside the prefix; the CRC at 4 MiB is not
    # walked.
    assert streams[0].bytes_read == PASSWORD_CONFIRM_PREFIX_BYTES
    # Accepted without a checksum, then abandoned: reported.
    assert diagnostics.counts.get(DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED) == 1

    # Mutation check: a plan that walks to the CRC reads the whole member.
    monkeypatch.setattr(sevenzip_reader_mod, "plan_password_confirm", _walk_whole_unit)
    streams.clear()
    _first_member_read(archive, _PASSWORD)
    assert streams[0].bytes_read == _BIG

    monkeypatch.undo()
    with pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"):
        _first_member_read(archive, "wrong")


def test_lzma2_late_crc_full_read_is_not_reported(tmp_path: Path) -> None:
    big = _payload(_BIG, 3)
    archive = _build(tmp_path, "lzma2", {"big.bin": big}, method="LZMA2", solid=True)
    with open_archive(archive, password=_PASSWORD) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert reader.read(member) == big
        assert (
            DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED not in reader.diagnostics.counts
        )


def test_lzma2_late_crc_full_read_after_a_refused_seek_is_not_reported(
    tmp_path: Path,
) -> None:
    # A caught seek(-1) moves nothing, so the full read after it still reaches the
    # CRC; reporting it would raise under PEDANTIC on a well-formed archive.
    big = _payload(_BIG, 3)
    archive = _build(tmp_path, "lzma2", {"big.bin": big}, method="LZMA2", solid=True)
    with open_archive(archive, password=_PASSWORD, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            first = stream.read(1)
            with pytest.raises(ValueError):
                stream.seek(-1)
            assert first + stream.read() == big
        assert (
            DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED not in reader.diagnostics.counts
        )


def test_lzma2_late_crc_seek_then_full_read_is_not_reported(tmp_path: Path) -> None:
    # The bytes the forward seek skips must be decoded anyway, so the next read hashes
    # them and the CRC is kept: reading on to EOF checks it, and nothing is reported.
    big = _payload(_BIG, 3)
    archive = _build(tmp_path, "lzma2", {"big.bin": big}, method="LZMA2", solid=True)
    with open_archive(archive, password=_PASSWORD, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            stream.seek(1)
            assert stream.read() == big[1:]
        assert DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED not in (
            reader.diagnostics.counts
        )


def test_copy_late_crc_is_walked_and_confirms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = _payload(_BIG, 4)
    archive = _build(tmp_path, "copy", {"big.bin": big}, method="Copy", solid=True)
    streams = _count_pipelines(monkeypatch)
    data, diagnostics = _first_member_read(archive, _PASSWORD)
    assert data == big[:1]
    # Copy cannot reject a wrong key, so the CRC at the end is walked...
    assert streams[0].bytes_read == _BIG
    # ...and, having matched, the key is confirmed: an abandoned read is not reported.
    assert DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED not in diagnostics.counts

    monkeypatch.undo()
    with pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"):
        _first_member_read(archive, "wrong")


def _flip_packed_byte(archive: Path, offset: int) -> None:
    """Flip one byte of the packed data, ``offset`` bytes past the 32-byte signature header."""
    blob = bytearray(archive.read_bytes())
    blob[32 + offset] ^= 0xFF
    archive.write_bytes(bytes(blob))


def test_damage_the_confirm_decodes_reads_as_a_wrong_password(tmp_path: Path) -> None:
    """7z has no password check value, so the confirm cannot tell damage from a wrong key.

    Copy rejects nothing, so the confirm walks to the CRC at the end of the member, and
    damage anywhere in it rejects the right password as it would a wrong one.
    """
    big = _payload(_BIG, 6)
    archive = _build(tmp_path, "copy", {"big.bin": big}, method="Copy", solid=True)
    _flip_packed_byte(archive, _BIG // 2)
    with pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"):
        _first_member_read(archive, _PASSWORD)


def test_damage_past_the_confirm_prefix_is_corruption(tmp_path: Path) -> None:
    """LZMA2 settles a wrong key inside the prefix; damage past it reaches the read."""
    # Random, so LZMA2 stores it in raw chunks and the packed data is about as long as
    # the payload: the offset below is inside it, far past the 64 KiB prefix.
    big = random.Random(7).randbytes(_BIG)
    archive = _build(tmp_path, "lzma2", {"big.bin": big}, method="LZMA2", solid=True)
    assert archive.stat().st_size > 32 + _BIG
    _flip_packed_byte(archive, _BIG - 4096)
    with open_archive(archive, password=_PASSWORD) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with raises_corruption_not_truncation():
            reader.read(member)


def test_store_aes_ambiguous_candidates_the_crc_picks_the_right_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Task 5.4: store+AES, the only anchor at the folder end, a wrong candidate first."""
    big = _payload(_BIG, 5)
    archive = _build(tmp_path, "copy", {"big.bin": big}, method="Copy", solid=True)
    with open_archive(archive, password=["wrong", _PASSWORD]) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert reader.read(member) == big

    # Treat Copy as rejecting, so the bounded plan stops at the prefix: both
    # candidates survive it as INCONCLUSIVE, and the full check, which walks to the
    # anchor, still picks the right one.
    monkeypatch.setattr(sevenzip_reader_mod, "_folder_codec_rejects", lambda _f: True)
    with open_archive(archive, password=["wrong", _PASSWORD]) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert reader.read(member) == big

    # Mutation check: take the full check away too (it gets the bounded plan). The
    # first INCONCLUSIVE survivor, "wrong", is then served.
    original_plan = sevenzip_reader_mod.SevenZipReader._folder_password_confirm_plan

    def bounded_only(
        self: sevenzip_reader_mod.SevenZipReader,
        folder_index: int,
        *,
        full: bool = False,
    ) -> PasswordConfirmPlan:
        return original_plan(self, folder_index)

    monkeypatch.setattr(
        sevenzip_reader_mod.SevenZipReader,
        "_folder_password_confirm_plan",
        bounded_only,
    )
    with open_archive(archive, password=["wrong", _PASSWORD]) as reader:
        member = next(m for m in reader.members() if m.is_file)
        try:
            served = reader.read(member)
        except ArchiveyError:
            served = None
        assert served != big


def test_inconclusive_candidate_is_not_promoted_when_ambiguous(
    tmp_path: Path,
) -> None:
    big = _payload(_BIG, 6)
    archive = _build(
        tmp_path,
        "lzma2-two",
        {"a.bin": big, "b.bin": _payload(_BIG, 7)},
        method="LZMA2",
        solid=False,
    )
    with open_archive(archive, password=["other", _PASSWORD]) as reader:
        members = [m for m in reader.members() if m.is_file]
        with reader.open(members[0]) as stream:
            assert stream.read(1) == big[:1]
        # "secret" survived its prefix without a CRC match, and another candidate
        # exists: accepted for this folder, kept out of known-good.
        assert reader._passwords._known_good == []

    with open_archive(archive, password=_PASSWORD) as reader:
        members = [m for m in reader.members() if m.is_file]
        with reader.open(members[0]) as stream:
            stream.read(1)
        # One distinct candidate: nothing else could be the right one, so promote.
        assert reader._passwords._known_good == [_PASSWORD.encode()]


def test_plan_confirm_is_what_the_reader_calls() -> None:
    # The mutation checks above patch this name; make sure it is the planner itself.
    assert sevenzip_reader_mod.plan_password_confirm is plan_password_confirm


class _PackCounter:
    """Counts the packed bytes read from one folder's pack view."""

    def __init__(self, inner: BinaryIO) -> None:
        self._inner = inner
        self.bytes_read = 0

    def read(self, n: int = -1, /) -> bytes:
        data = self._inner.read(n)
        self.bytes_read += len(data)
        return data

    def readinto(self, buffer: bytearray | memoryview, /) -> int:
        count = self._inner.readinto(buffer)  # type: ignore[attr-defined]
        self.bytes_read += count or 0
        return count  # type: ignore[no-any-return]

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def _count_pack_reads(monkeypatch: pytest.MonkeyPatch) -> list[_PackCounter]:
    counters: list[_PackCounter] = []
    reader_cls = sevenzip_reader_mod.SevenZipReader
    original = reader_cls._folder_pack_views

    def counting(self: object, folder_index: int) -> list[_PackCounter]:
        views = original(self, folder_index)  # type: ignore[arg-type]
        wrapped = [_PackCounter(view) for view in views]
        counters.extend(wrapped)
        return wrapped

    monkeypatch.setattr(reader_cls, "_folder_pack_views", counting)
    return counters


# Small enough that bzip2 cannot finish its first block (it emits nothing until a
# whole block, ~900 KB here, is read), so the capped input runs out before the prefix.
_SMALL_CAP = 256 * 1024


def _bounded_plan(
    substreams: object, tail_crc: object, *, budget: int, codec_rejects: bool
) -> PasswordConfirmPlan:
    return plan_password_confirm(
        substreams,  # type: ignore[arg-type]
        tail_crc,  # type: ignore[arg-type]
        budget=budget,
        codec_rejects=codec_rejects,
    )


def test_input_cap_bounds_the_packed_bytes_and_running_out_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The compressed half of the budget: a block codec reads at most the cap."""
    import random

    data = random.Random(7).randbytes(3 * 1024 * 1024)
    archive = _build(tmp_path, "bzip2", {"big.bin": data}, method="BZip2", solid=True)
    monkeypatch.setattr(
        sevenzip_reader_mod, "PASSWORD_CONFIRM_MAX_INPUT_BYTES", _SMALL_CAP
    )
    counters = _count_pack_reads(monkeypatch)
    with open_archive(archive, password=_PASSWORD) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            assert stream.read(1) == data[:1]
        confirm = counters[0]
        assert 0 < confirm.bytes_read <= _SMALL_CAP
        # The cap, not the key, ended the confirm: accepted as INCONCLUSIVE, so the
        # abandoned read is reported.
        assert (
            reader.diagnostics.counts.get(DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED)
            == 1
        )
        # The member itself still reads in full and checks its CRC.
        assert reader.read(member) == data

    # A wrong key is still refused under the cap: bzip2 rejects it well inside it.
    with pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"):
        _first_member_read(archive, "wrong")

    # Mutation check: an unbounded plan takes no cap, and the same count sees bzip2
    # read its whole first block.
    def unbounded(*args: object, **kwargs: object) -> PasswordConfirmPlan:
        plan = _bounded_plan(*args, **kwargs)  # type: ignore[arg-type]
        return PasswordConfirmPlan(
            plan.segments, plan.unit_crc, plan.confirms, bounded=False
        )

    monkeypatch.setattr(sevenzip_reader_mod, "plan_password_confirm", unbounded)
    counters.clear()
    _first_member_read(archive, _PASSWORD)
    assert counters[0].bytes_read > _SMALL_CAP
