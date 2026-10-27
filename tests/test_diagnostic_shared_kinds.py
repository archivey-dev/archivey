"""``validate_code_context`` on codes that share a context kind.

Six context kinds each serve more than one code, told apart by one context field
(``diagnostics`` §"Complete initial warning taxonomy": "typed context distinguishes
variants"). The kind match alone accepts a mismatched pairing, so every such code
must also check its field.
"""

from __future__ import annotations

from collections import Counter

import pytest

from archivey.diagnostics import (
    _CODE_CONTEXT_KINDS,
    _SHARED_KIND_DISCRIMINATORS,
    ArchiveEofContext,
    DiagnosticCode,
    DiagnosticContext,
    LocalHeaderContext,
    MemberNameControlsContext,
    ScanRaceContext,
    UnconfirmedFormatContext,
    UnusedArgumentContext,
    validate_code_context,
)

_MATCHED: list[tuple[DiagnosticCode, DiagnosticContext]] = [
    (
        DiagnosticCode.MEMBER_NAME_BIDI_CONTROL,
        MemberNameControlsContext(category="bidi"),
    ),
    (
        DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER,
        MemberNameControlsContext(category="zero_width"),
    ),
    (
        DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER,
        MemberNameControlsContext(category="invisible"),
    ),
    (DiagnosticCode.SCAN_DIRECTORY_VANISHED, ScanRaceContext(entry_kind="directory")),
    (DiagnosticCode.SCAN_ENTRY_VANISHED, ScanRaceContext(entry_kind="entry")),
    (
        DiagnosticCode.ENCODING_ARGUMENT_UNUSED,
        UnusedArgumentContext(argument="encoding"),
    ),
    (
        DiagnosticCode.PASSWORD_ARGUMENT_UNUSED,
        UnusedArgumentContext(argument="password"),
    ),
    (
        DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY,
        UnconfirmedFormatContext(chosen_by="argument"),
    ),
    (
        DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED,
        UnconfirmedFormatContext(chosen_by="extension"),
    ),
    (
        DiagnosticCode.PROBE_FORMAT_UNCONFIRMED,
        UnconfirmedFormatContext(chosen_by="content_probe"),
    ),
    (
        DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
        ArchiveEofContext(expected_marker="two_zero_blocks"),
    ),
    (
        DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
        ArchiveEofContext(expected_marker="second_zero_block"),
    ),
    (
        DiagnosticCode.ARCHIVE_TRAILING_DATA,
        ArchiveEofContext(expected_marker="zeros_to_eof"),
    ),
    (
        DiagnosticCode.ARCHIVE_TRAILING_DATA,
        ArchiveEofContext(expected_marker="end_of_stream"),
    ),
    (DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS, LocalHeaderContext(field="name")),
    (DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS, LocalHeaderContext(field="method")),
    (DiagnosticCode.MEMBER_LOCAL_CRC_USED, LocalHeaderContext(field="crc32")),
]


def test_every_shared_kind_code_has_a_discriminator() -> None:
    per_kind = Counter(_CODE_CONTEXT_KINDS.values())
    shared = {code for code, kind in _CODE_CONTEXT_KINDS.items() if per_kind[kind] > 1}
    assert shared == set(_SHARED_KIND_DISCRIMINATORS)
    assert shared == {code for code, _ in _MATCHED}


@pytest.mark.parametrize(
    ("code", "context"), _MATCHED, ids=lambda value: getattr(value, "name", "")
)
def test_matching_pair_is_accepted(
    code: DiagnosticCode, context: DiagnosticContext
) -> None:
    validate_code_context(code, context)


# Each code paired with a sibling's context: same kind, wrong discriminator.
_MISMATCHED = [
    (code, other_context)
    for code, _ in _MATCHED
    for other_code, other_context in _MATCHED
    if other_code is not code and other_context.kind == _CODE_CONTEXT_KINDS[code]
]


@pytest.mark.parametrize(
    ("code", "context"),
    _MISMATCHED,
    ids=[f"{code.name}-{i}" for i, (code, _) in enumerate(_MISMATCHED)],
)
def test_sibling_context_is_rejected(
    code: DiagnosticCode, context: DiagnosticContext
) -> None:
    field_name, allowed = _SHARED_KIND_DISCRIMINATORS[code]
    with pytest.raises(ValueError, match=rf"^{code.name} requires {field_name}="):
        validate_code_context(code, context)
    assert getattr(context, field_name) not in allowed


def test_mismatches_cover_all_six_shared_kinds() -> None:
    kinds = {context.kind for _, context in _MISMATCHED}
    assert kinds == {
        "member_name_controls",
        "scan_race",
        "unused_argument",
        "unconfirmed_format",
        "archive_eof",
        "local_header",
    }
