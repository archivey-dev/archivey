"""Behavior and construction checks for the generated adversarial string corpus."""

from __future__ import annotations

import errno
import io
import logging
import os
import re
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from archivey import ExtractionPolicy, ExtractionStatus, open_archive
from archivey.exceptions import (
    ExtractionError,
    FilterRejectionError,
)
from tests import create_adversarial as gen
from tests.create_adversarial import (
    Adversarial,
    adversarial_archives,
    clean_base_archives,
)

_CASES = adversarial_archives()
_IDS = [entry.id for entry, _ in _CASES]


def _zip_header(blob: bytes, signature: bytes, fixed_size: int, name: bytes) -> int:
    """Independent test parser for one local/central header."""
    matches: list[int] = []
    start = blob.find(signature)
    while start >= 0:
        length_offset = start + (26 if fixed_size == 30 else 28)
        name_length = struct.unpack_from("<H", blob, length_offset)[0]
        if blob[start + fixed_size : start + fixed_size + name_length] == name:
            matches.append(start)
        start = blob.find(signature, start + 1)
    assert len(matches) == 1
    return matches[0]


def _zip_headers(blob: bytes, name: bytes) -> tuple[int, int]:
    return (
        _zip_header(blob, b"PK\x03\x04", 30, name),
        _zip_header(blob, b"PK\x01\x02", 46, name),
    )


@pytest.mark.parametrize(("entry", "blob"), _CASES, ids=_IDS)
def test_adversarial_archive_construction(entry: Adversarial, blob: bytes) -> None:
    """The bytes themselves prove that each case mutates its advertised field."""
    if entry.fmt == "tar":
        assert blob.count(entry.stored_name) == 1
        offset = blob.index(entry.stored_name)
        assert offset % 512 == 0, "mutated bytes are not the TAR name field"
        header_start = (offset // 512) * 512
        header = bytearray(blob[header_start : header_start + 512])
        stored_checksum = int(header[148:154], 8)
        header[148:156] = b" " * 8
        assert sum(header) == stored_checksum
        return

    local, central = _zip_headers(blob, entry.stored_name)
    local_flags = struct.unpack_from("<H", blob, local + 6)[0]
    central_flags = struct.unpack_from("<H", blob, central + 8)[0]
    assert bool(local_flags & 0x0800) is entry.utf8_flag
    assert bool(central_flags & 0x0800) is entry.utf8_flag
    assert struct.unpack_from("<H", blob, local + 8)[0] == zipfile.ZIP_STORED
    assert struct.unpack_from("<H", blob, central + 10)[0] == zipfile.ZIP_STORED

    if entry.field == "link_target":
        assert entry.expected_link_target is not None
        target = entry.expected_link_target.encode("utf-8")
        name_length, extra_length = struct.unpack_from("<HH", blob, local + 26)
        payload_start = local + 30 + name_length + extra_length
        assert blob[payload_start : payload_start + len(target)] == target
        local_crc = struct.unpack_from("<I", blob, local + 14)[0]
        central_crc = struct.unpack_from("<I", blob, central + 16)[0]
        assert local_crc == central_crc == zlib.crc32(target)
    elif entry.field == "comment":
        assert entry.expected_comment is not None
        raw_comment = entry.expected_comment.encode("cp437")
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", blob, central + 28
        )
        comment_start = central + 46 + name_length + extra_length
        assert comment_length == len(raw_comment)
        assert blob[comment_start : comment_start + comment_length] == raw_comment


def test_clean_bases_are_generated_deterministically_in_memory() -> None:
    first = clean_base_archives()
    second = clean_base_archives()
    assert first == second
    assert gen._NAME in first["zip"] and gen._LINK in first["zip"]
    assert gen._NAME in first["tar"] and gen._LINK in first["tar"]
    for blob in first.values():
        with open_archive(io.BytesIO(blob)) as archive:
            assert [member.name for member in archive.members()] == [
                gen._NAME.decode(),
                "link",
            ]


@pytest.mark.parametrize(("entry", "blob"), _CASES, ids=_IDS)
def test_adversarial_open_list_read_semantics(
    entry: Adversarial,
    blob: bytes,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="archivey.normalization"),
        open_archive(io.BytesIO(blob)) as archive,
    ):
        members = archive.members()
        target = members[1] if entry.field == "link_target" else members[0]
        assert target.name == entry.expected_name
        assert target.raw_name == entry.expected_raw_name
        if entry.field == "comment":
            assert target.comment == entry.expected_comment
        if entry.field == "link_target":
            assert target.link_target == entry.expected_link_target
        if target.is_file:
            assert archive.read(target) == b"payload for the adversarial name member\n"

    if entry.warning_text is not None:
        warnings = [
            record for record in caplog.records if entry.warning_text in record.message
        ]
        assert len(warnings) == 1


def _assert_extraction_stayed_in_tested_scope(
    dest: Path,
    returned_paths: list[Path],
    possible_escape_targets: tuple[Path, ...],
    case_id: str,
) -> None:
    """Check evidence this test can actually observe; make no global no-write claim."""
    dest_root = dest.resolve()
    for path in returned_paths:
        resolved = path.resolve()
        assert resolved == dest_root or resolved.is_relative_to(dest_root), (
            f"{case_id}: returned extraction path escaped to {resolved}"
        )
    created_escape_targets = [
        path for path in possible_escape_targets if os.path.lexists(path)
    ]
    assert not created_escape_targets, (
        f"{case_id}: explicit sandbox escape target was created: "
        f"{created_escape_targets!r}"
    )


def test_escape_check_detects_regular_file_outside_destination(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    dest = sandbox / "out"
    dest.mkdir(parents=True)
    escaped = sandbox / "escaped.txt"
    escaped.write_text("escaped")
    with pytest.raises(AssertionError, match="explicit sandbox escape"):
        _assert_extraction_stayed_in_tested_scope(dest, [], (escaped,), "self-check")


# The checks behind each refusal outcome, told apart by message: a name that leaves
# the destination (or cannot name a path) versus a link target that does.
_REFUSAL_MESSAGE = {
    "path_traversal": (
        r"^(Null byte in member name|Member name cannot be encoded|Absolute path"
        r"|Path traversal|Member name refers to the extraction root"
        r"|Member resolves outside the destination root)"
    ),
    "symlink_escape": (
        r"^(Null byte in link target|Link target cannot be encoded"
        r"|(Symlink|Hardlink) target escapes destination)"
    ),
}


@pytest.mark.parametrize(("entry", "blob"), _CASES, ids=_IDS)
def test_adversarial_extract_has_exact_outcome(
    entry: Adversarial, blob: bytes, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox"
    dest = sandbox / "out"
    possible_escape_targets = (
        sandbox / "escaped.txt",
        tmp_path / "escaped.txt",
    )
    returned_paths: list[Path] = []
    with open_archive(io.BytesIO(blob)) as archive:
        members = archive.members()
        target = members[1] if entry.field == "link_target" else members[0]

        if entry.extract_outcome in _REFUSAL_MESSAGE:
            results = archive.extract_all(
                dest, members=[target], policy=ExtractionPolicy.TRUSTED
            ).results
            assert len(results) == 1
            assert results[0].status is ExtractionStatus.BLOCKED
            error = results[0].error
            assert isinstance(error, FilterRejectionError)
            # One exception type covers every safety check, so the message is what
            # says which one refused the member.
            assert re.search(_REFUSAL_MESSAGE[entry.extract_outcome], error.message), (
                error.message
            )
        elif entry.extract_outcome == "deceptive_name":
            # A bidi override/isolate in the name reorders the surrounding text, so the
            # extracted file would display as something it is not.
            #
            # This is **policy-keyed**, not universal (ADR 0017): the write itself is
            # perfectly safe — the file lands inside dest under exactly its stored
            # bytes — so `TRUSTED`, which means "faithful bytes, no name rejection",
            # extracts it, while the default `STRICT` and `STANDARD` refuse. This whole
            # module drives extraction at `TRUSTED` to prove the *universal* checks hold
            # at the most permissive policy, so both halves are asserted here rather than
            # leaving the file's one policy-keyed case looking universal.
            #
            # The sibling case with a directional *mark* (which reorders nothing) is an
            # ordinary "success" at every policy — that pair is the regression net for
            # the reject set being the override ranges only.
            trusted = archive.extract_all(
                dest, members=[target], policy=ExtractionPolicy.TRUSTED
            ).results
            assert len(trusted) == 1
            assert trusted[0].status is ExtractionStatus.EXTRACTED
            for result in trusted:
                if result.path is not None:
                    returned_paths.append(result.path)

            for policy in (ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD):
                blocked = archive.extract_all(
                    dest / policy.value, members=[target], policy=policy
                ).results
                assert len(blocked) == 1
                assert blocked[0].status is ExtractionStatus.BLOCKED
                assert isinstance(blocked[0].error, FilterRejectionError)
                assert "Bidirectional override" in blocked[0].error.message
        elif entry.extract_outcome == "filesystem_name_refusal":
            # A UTF-8-enforcing filesystem (e.g. APFS) refuses the surrogateescape
            # name with EILSEQ; the coordinator translates that to ExtractionError
            # (landed on main via hypothesis-property-tests). Byte-preserving
            # filesystems extract the member normally.
            try:
                results = archive.extract_all(
                    dest, members=[target], policy=ExtractionPolicy.TRUSTED
                ).results
            except ExtractionError as exc:
                cause = exc.__cause__
                assert isinstance(cause, OSError)
                assert cause.errno == errno.EILSEQ
            else:
                assert len(results) == 1
                assert results[0].status is ExtractionStatus.EXTRACTED
                for result in results:
                    if result.path is not None:
                        returned_paths.append(result.path)
        else:
            assert entry.extract_outcome == "success"
            results = archive.extract_all(
                dest, members=[target], policy=ExtractionPolicy.TRUSTED
            ).results
            assert len(results) == 1
            assert results[0].status is ExtractionStatus.EXTRACTED
            for result in results:
                if result.path is not None:
                    returned_paths.append(result.path)

    _assert_extraction_stayed_in_tested_scope(
        dest, returned_paths, possible_escape_targets, entry.id
    )
