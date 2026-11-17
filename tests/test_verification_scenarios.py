"""Scenario rows of the ``verification-level-redesign`` spec deltas (task 4.2).

Most rows of the three scenario tables already have a test where their format's
checks are tested: ``test_verification_level.py`` and ``test_codec_frame_checks.py``
(the ``compressed-streams`` level matrix), ``test_stream_verify.py`` (its verify
matrix), ``test_verify_all.py`` (the ``archive-reading`` matrix), and the 7z, TAR and
CPIO/ar files for checks that span members. This module holds the rows that had none.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from archivey import Verification, open_archive
from archivey.exceptions import ArchiveyUsageError, TruncatedError
from tests.conftest import requires
from tests.test_audit_sevenzip import _archive, _header
from tests.test_sevenzip_verification_levels import _BIG, _aes_lzma2_folder

NONE = Verification.NONE
UNLOCKED = Verification.UNLOCKED
LENGTH = Verification.LENGTH
CHECKSUM = Verification.CHECKSUM

_DATA = b"scenario\n" * 3000


def _zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", _DATA)
        zf.writestr("b.txt", _DATA[::-1])
    return out.getvalue()


def _aes_no_crc(*, missing: int = 0) -> bytes:
    """One 7z AES + LZMA2 folder holding one file, with no CRC anywhere. ``missing``
    declares that many more bytes than the folder decodes to (a truncated member)."""
    folder, packed, unpack = _aes_lzma2_folder(_BIG, "pw")
    sizes = [[unpack[0][0], unpack[0][1] + missing]]
    header = _header(
        folders=[folder],
        coder_unpack_sizes=sizes,
        pack_sizes=[len(packed)],
        names=["x"],
    )
    return _archive(packed, header)


# --- archive-data-model: member level matrix ---------------------------------------


def test_a_final_member_still_rises() -> None:
    with open_archive(io.BytesIO(_zip())) as reader:
        member = reader.get("a.txt")
        assert member is not None
        assert member.member_state_final
        assert member.verified is UNLOCKED
        assert reader.read(member) == _DATA
        assert member.member_state_final
        assert member.verified is CHECKSUM


@requires("cryptography")
def test_an_aes_folder_with_no_crc_settles_to_none_at_its_first_open() -> None:
    with open_archive(io.BytesIO(_aes_no_crc()), password="pw") as reader:
        (member,) = reader.members()
        assert member.verified is NONE
        listed = member.verifiable
        with reader.open(member) as stream:
            assert stream.read(10) == _BIG[:10]
            # Opening found nothing that can prove the key: the ceiling settles.
            assert member.verifiable <= listed
            settled = member.verifiable
            assert settled is NONE
        assert reader.read(member) == _BIG
        assert (member.verified, member.verifiable) == (NONE, NONE)


# --- archive-reading: verify_all matrix ---------------------------------------------


@requires("cryptography")
def test_verify_all_returns_a_truncated_unprovable_member_on_every_call() -> None:
    with open_archive(io.BytesIO(_aes_no_crc(missing=10)), password="pw") as reader:
        (member,) = reader.members()
        for _ in range(2):
            ((failed, error),) = reader.verify_all().failures
            assert failed is member
            assert isinstance(error, TruncatedError)


def test_verify_all_after_a_streaming_pass_started_is_a_usage_error() -> None:
    with open_archive(io.BytesIO(_zip()), streaming=True) as reader:
        members = reader.stream_members()
        next(members)
        with pytest.raises(ArchiveyUsageError):
            reader.verify_all()
        members.close()


# --- compressed-streams: verify matrix ----------------------------------------------


@requires("cryptography")
def test_verify_on_a_truncated_unprovable_member_raises_every_time() -> None:
    with open_archive(io.BytesIO(_aes_no_crc(missing=10)), password="pw") as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            for _ in range(2):
                with pytest.raises(TruncatedError):
                    stream.verify()


@requires("cryptography")
def test_verify_on_an_intact_unprovable_member_reads_to_the_end() -> None:
    with open_archive(io.BytesIO(_aes_no_crc()), password="pw") as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            # The target NONE is never "reached" up front, so the read runs to the
            # end (the truncated case above raises from there) and proves nothing.
            assert stream.verify() is NONE
            with pytest.raises(ArchiveyUsageError):
                stream.read()
        assert (member.verified, member.verifiable) == (NONE, NONE)
