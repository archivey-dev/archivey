"""``reader.verify_all()`` and the member's verification level.

One test (or a few) per item of the contract in the ``verification-level-redesign``
change (design Decision 6). Items 6 and 7 (codec frame checks, checks that span
members) land with the codec and 7z work; the tests here cover what holds today.
"""

from __future__ import annotations

import io
import struct
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    Verification,
    open_archive,
)
from archivey.config import PasswordRequest
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    DiagnosticRaisedError,
    EncryptionError,
    TruncatedError,
)
from archivey.internal.streams.verification import raise_member_level
from archivey.types import ArchiveMember, MemberType

NONE = Verification.NONE
PASSWORD = Verification.PASSWORD
LENGTH = Verification.LENGTH
CHECKSUM = Verification.CHECKSUM

_DATA = b"verify all\n" * 4000
_COLLISION = (
    Path(__file__).parent / "fixtures" / "zipcrypto" / "check_byte_collision.zip"
)


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", _DATA)
        zf.writestr("b.txt", _DATA[::-1])
        zf.writestr("d/", b"")
    return path


def _corrupt_first_crc(path: Path) -> Path:
    """Flip ``a.txt``'s CRC-32 in its local header and the central directory."""
    raw = bytearray(path.read_bytes())
    for at in (raw.index(b"PK\x03\x04") + 14, raw.index(b"PK\x01\x02") + 16):
        (crc,) = struct.unpack_from("<I", raw, at)
        struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    path.write_bytes(bytes(raw))
    return path


def _tar(tmp_path: Path, keep: int | None = None) -> Path:
    """Three 5000-byte members; ``keep`` cuts the file to that many bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("a", "b", "c"):
            info = tarfile.TarInfo(name)
            info.size = 5000
            tf.addfile(info, io.BytesIO(name.encode() * 5000))
    path = tmp_path / "a.tar"
    path.write_bytes(buf.getvalue()[:keep])
    return path


def _levels(members: list[ArchiveMember]) -> dict[str, tuple[Verification, ...]]:
    return {m.name: (m.verified, m.verifiable) for m in members}


# --- 1. failures are returned, not raised -----------------------------------------


def test_verify_all_returns_a_damaged_member_and_reads_on(tmp_path: Path) -> None:
    with open_archive(_corrupt_first_crc(_zip(tmp_path))) as reader:
        failures = reader.verify_all()
        assert [(m.name, type(e)) for m, e in failures] == [("a.txt", CorruptionError)]
        assert _levels(reader.members())["b.txt"] == (CHECKSUM, CHECKSUM)


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_verify_all_stops_at_listing_damage_without_raising(
    tmp_path: Path, streaming: bool
) -> None:
    # Cut inside b's data: b fails, and the listing cannot find c.
    with open_archive(_tar(tmp_path, keep=512 * 14), streaming=streaming) as reader:
        failures = reader.verify_all()
        assert [(m.name, type(e)) for m, e in failures] == [("b", TruncatedError)]
        report = reader.members_report()
        assert isinstance(report.error, TruncatedError)
        assert _levels(list(report.members)) == {
            "a": (LENGTH, LENGTH),
            "b": (PASSWORD, LENGTH),
        }


def test_verify_all_on_a_closed_reader_is_a_usage_error(tmp_path: Path) -> None:
    reader = open_archive(_zip(tmp_path))
    reader.close()
    with pytest.raises(ArchiveyUsageError):
        reader.verify_all()


def test_verify_all_raises_an_escalated_diagnostic(tmp_path: Path) -> None:
    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING}
        )
    )
    path = _tar(tmp_path, keep=512 * 33)  # every member whole, no end marker
    with (
        open_archive(path, config=config) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        reader.verify_all()


# --- 2. afterwards every member is at its ceiling -----------------------------------


def test_verify_all_brings_every_member_to_its_ceiling(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        assert reader.verify_all() == ()
        assert _levels(reader.members()) == {
            "a.txt": (CHECKSUM, CHECKSUM),
            "b.txt": (CHECKSUM, CHECKSUM),
            # No data of its own: nothing to read, so it is at its ceiling already.
            "d/": (PASSWORD, PASSWORD),
        }


def test_verify_all_returns_members_it_has_no_password_for() -> None:
    with open_archive(_COLLISION) as reader:
        failures = reader.verify_all()
        assert {m.name for m, _ in failures} == {"stored.txt", "deflated.txt"}
        assert all(isinstance(e, EncryptionError) for _, e in failures)
        assert all(m.verified is NONE for m in reader.members())


def test_verify_all_with_the_password_reaches_checksum() -> None:
    with open_archive(_COLLISION, password="secret") as reader:
        assert reader.verify_all() == ()
        assert set(_levels(reader.members()).values()) == {(CHECKSUM, CHECKSUM)}


# --- 3. a stream mirrors its member -------------------------------------------------


def test_a_held_stream_mirrors_what_verify_all_proved(tmp_path: Path) -> None:
    with open_archive(
        _zip(tmp_path), seekable_members=True, concurrent_operations=True
    ) as reader:
        stream = reader.open("a.txt")
        assert (stream.verified, stream.verifiable) == (PASSWORD, CHECKSUM)
        stream.read(10)
        assert reader.verify_all() == ()
        assert (stream.verified, stream.verifiable) == (CHECKSUM, CHECKSUM)
        # 10. verify_all() did not touch it.
        assert stream.tell() == 10
        assert stream.read() == _DATA[10:]
        stream.close()


def test_a_stream_read_raises_its_member(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        member = reader.get("a.txt")
        with reader.open(member) as stream:
            stream.read()
        assert (member.verified, member.verifiable) == (CHECKSUM, CHECKSUM)


def test_a_stream_of_a_copy_raises_the_readers_member(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        member = reader.get("a.txt")
        copy = member.replace(mode=0o600)
        with reader.open(copy) as stream:
            stream.read()
            assert stream.verified is CHECKSUM
        assert member.verified is CHECKSUM
        # The copy keeps the values it was copied with.
        assert copy.verified is PASSWORD


# --- 4 and 8. a proved member reads nothing ------------------------------------------


@pytest.mark.parametrize("password_only", [False, True])
def test_verify_on_a_proved_member_opens_nothing(
    tmp_path: Path, password_only: bool
) -> None:
    with open_archive(_zip(tmp_path), seekable_members=True) as reader:
        reader.verify_all()
        with reader.open("a.txt") as stream:
            # 8. Asking for the level reads nothing either.
            assert stream.verified is CHECKSUM
            assert stream.verify(password_only=password_only) is CHECKSUM
            assert stream.tell() == 0
            assert stream.read() == _DATA


def test_verify_on_a_forward_only_proved_member_still_consumes_it(
    tmp_path: Path,
) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        reader.verify_all()
        for member, stream in reader.stream_members():
            if stream is None:
                continue
            assert stream.verify() is member.verified
            assert stream._inner is None
            with pytest.raises(ArchiveyUsageError, match="verify"):
                stream.read(1)


def test_a_member_with_no_provable_key_is_still_read() -> None:
    # The target NONE is never "reached": the read runs, so its length checks do.
    with open_archive(_COLLISION, password="secret") as reader:
        member = reader.get("stored.txt")
        # As a member whose key nothing can prove: its ceiling settles at NONE.
        raise_member_level(member, NONE, NONE)
        assert (member.verified, member.verifiable) == (NONE, NONE)
        with reader.open(member) as stream:
            stream.verify()
            assert stream._inner is not None


# --- 5. levels never fall -----------------------------------------------------------


def test_a_failed_read_leaves_the_level_where_it_was(tmp_path: Path) -> None:
    with open_archive(_corrupt_first_crc(_zip(tmp_path))) as reader:
        member = reader.get("a.txt")
        with reader.open(member) as stream, pytest.raises(CorruptionError):
            stream.read()
        assert (member.verified, member.verifiable) == (PASSWORD, CHECKSUM)
        assert member.verified <= member.verifiable


def test_raise_member_level_never_lowers(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        member = reader.get("a.txt")
        raise_member_level(member, CHECKSUM, CHECKSUM)
        raise_member_level(member, LENGTH, LENGTH)
        assert (member.verified, member.verifiable) == (CHECKSUM, CHECKSUM)


def test_concurrent_raises_keep_the_maximum(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        member = reader.get("a.txt")
        levels = [LENGTH, CHECKSUM, PASSWORD] * 200
        barrier = threading.Barrier(3)

        def raise_all(offset: int) -> None:
            barrier.wait()
            for level in levels[offset:] + levels[:offset]:
                raise_member_level(member, level, CHECKSUM)

        threads = [threading.Thread(target=raise_all, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert (member.verified, member.verifiable) == (CHECKSUM, CHECKSUM)


# --- 10. a second call --------------------------------------------------------------


def test_a_second_call_retries_the_members_that_failed() -> None:
    answer: list[str | None] = [None]
    asked: list[PasswordRequest] = []

    def provider(request: PasswordRequest) -> str | None:
        asked.append(request)
        return answer[0]

    with open_archive(_COLLISION, password=provider) as reader:
        assert len(reader.verify_all()) == 2
        first = len(asked)
        assert first > 0
        answer[0] = "secret"
        assert reader.verify_all() == ()
        assert len(asked) > first
        assert set(_levels(reader.members()).values()) == {(CHECKSUM, CHECKSUM)}


def test_a_second_call_skips_proved_members(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        reader.verify_all()
        seen: list[str] = []
        for member, _stream in reader.stream_members(
            lambda m: m.verified < m.verifiable or m.verifiable is NONE
        ):
            seen.append(member.name)
        assert seen == []
        assert reader.verify_all() == ()


# --- 11. streaming: one pass --------------------------------------------------------


def test_streaming_verify_all_is_the_one_pass(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path), streaming=True) as reader:
        assert reader.verify_all() == ()
        report = reader.members_report()
        assert report.error is None
        assert _levels(list(report.members))["a.txt"] == (CHECKSUM, CHECKSUM)
        with pytest.raises(ArchiveyUsageError):
            reader.verify_all()


# --- 12. archive-level findings are diagnostics, not levels -------------------------


def test_a_missing_end_marker_is_a_diagnostic(tmp_path: Path) -> None:
    with open_archive(_tar(tmp_path, keep=512 * 33)) as reader:
        assert reader.verify_all() == ()
        assert reader.members_report().error is None
        assert reader.diagnostics.counts[DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING]
        assert {m.verified for m in reader.members()} == {LENGTH}


def test_member_level_is_not_part_of_equality(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        member = reader.get("a.txt")
        before = member.replace()
        reader.verify_all()
        assert member == before
        assert member.type is MemberType.FILE
