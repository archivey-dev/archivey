"""The diagnostic codes merged in 0.6.0, and the old spellings that still convert.

Seven codes became three (DR-13: a caller would not branch on them differently, and the
context's field already tells them apart). Each old member name and value still
converts to the new member through 0.6.x, with a ``DeprecationWarning`` at the caller's
line (DR-12a); 0.7.0 removes them.
"""

from __future__ import annotations

import warnings

import pytest

from archivey.diagnostics import (
    ARCHIVE_INTEGRITY_CODES,
    DiagnosticCode,
    DiagnosticPolicy,
    DirectoryDataContext,
    LinkDataContext,
    LocalHeaderContext,
    ScanRaceContext,
    validate_code_context,
)

_MERGED = {
    "SCAN_DIRECTORY_VANISHED": "SCAN_ENTRY_VANISHED",
    "MEMBER_LOCAL_NAME_DIFFERS": "MEMBER_LOCAL_HEADER_DIFFERS",
    "MEMBER_LOCAL_METHOD_DIFFERS": "MEMBER_LOCAL_HEADER_DIFFERS",
    "MEMBER_LOCAL_OFFSET_SHIFTED": "MEMBER_LOCAL_HEADER_DIFFERS",
    "MEMBER_DIRECTORY_DATA_IGNORED": "MEMBER_DATA_IGNORED",
    "MEMBER_LINK_DATA_IGNORED": "MEMBER_DATA_IGNORED",
}


def test_the_enum_has_46_codes() -> None:
    assert len(DiagnosticCode) == 46
    names = {code.name for code in DiagnosticCode}
    assert names.isdisjoint(_MERGED)
    assert {"SCAN_ENTRY_VANISHED", "MEMBER_LOCAL_HEADER_DIFFERS"} <= names
    assert "MEMBER_DATA_IGNORED" in names


def test_the_new_values() -> None:
    assert DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS.value == (
        "member_local_header_differs"
    )
    assert DiagnosticCode.MEMBER_DATA_IGNORED.value == "member_data_ignored"


def test_the_merged_codes_keep_their_integrity_side() -> None:
    assert DiagnosticCode.SCAN_ENTRY_VANISHED in ARCHIVE_INTEGRITY_CODES
    assert DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS in ARCHIVE_INTEGRITY_CODES
    assert DiagnosticCode.MEMBER_DATA_IGNORED in ARCHIVE_INTEGRITY_CODES
    assert DiagnosticCode.MEMBER_LOCAL_CRC_USED not in ARCHIVE_INTEGRITY_CODES


@pytest.mark.parametrize(
    ("code", "context"),
    [
        (DiagnosticCode.SCAN_ENTRY_VANISHED, ScanRaceContext(entry_kind="directory")),
        (DiagnosticCode.SCAN_ENTRY_VANISHED, ScanRaceContext(entry_kind="entry")),
        (DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS, LocalHeaderContext(field="name")),
        (
            DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS,
            LocalHeaderContext(field="method"),
        ),
        (
            DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS,
            LocalHeaderContext(field="offset"),
        ),
        (DiagnosticCode.MEMBER_DATA_IGNORED, DirectoryDataContext()),
        (DiagnosticCode.MEMBER_DATA_IGNORED, LinkDataContext()),
    ],
    ids=lambda value: getattr(value, "name", getattr(value, "kind", "")),
)
def test_a_merged_code_takes_each_context_it_replaced(code, context) -> None:
    validate_code_context(code, context)


def test_the_local_crc_code_stays_apart() -> None:
    with pytest.raises(ValueError, match="MEMBER_LOCAL_HEADER_DIFFERS requires field"):
        validate_code_context(
            DiagnosticCode.MEMBER_LOCAL_HEADER_DIFFERS,
            LocalHeaderContext(field="crc32"),
        )
    with pytest.raises(ValueError, match="MEMBER_LOCAL_CRC_USED requires field"):
        validate_code_context(
            DiagnosticCode.MEMBER_LOCAL_CRC_USED, LocalHeaderContext(field="name")
        )


@pytest.mark.parametrize(("old", "new"), sorted(_MERGED.items()))
def test_an_old_member_name_warns_at_the_callers_line(old: str, new: str) -> None:
    with pytest.warns(DeprecationWarning, match=rf"DiagnosticCode\.{old}.*{new}") as w:
        member = getattr(DiagnosticCode, old)
    assert member is DiagnosticCode[new]
    assert w[0].filename == __file__


@pytest.mark.parametrize(("old", "new"), sorted(_MERGED.items()))
def test_an_old_member_name_by_item_warns(old: str, new: str) -> None:
    with pytest.warns(DeprecationWarning, match=rf"DiagnosticCode\.{old}") as w:
        member = DiagnosticCode[old]
    assert member is DiagnosticCode[new]
    assert w[0].filename == __file__


@pytest.mark.parametrize(("old", "new"), sorted(_MERGED.items()))
def test_an_old_value_warns_at_the_callers_line(old: str, new: str) -> None:
    with pytest.warns(DeprecationWarning, match=rf"{old.lower()!s}") as w:
        member = DiagnosticCode(old.lower())
    assert member is DiagnosticCode[new]
    assert w[0].filename == __file__


@pytest.mark.parametrize(
    "spelling", ["scan_directory_vanished", "SCAN-DIRECTORY-VANISHED"]
)
def test_a_policy_takes_an_old_spelling_with_a_warning(spelling: str) -> None:
    with pytest.warns(DeprecationWarning, match="scan_directory_vanished") as w:
        policy = DiagnosticPolicy(raise_on={spelling})
    assert policy.raise_on == {DiagnosticCode.SCAN_ENTRY_VANISHED}
    assert w[0].filename == __file__


def test_a_current_code_never_warns() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for code in DiagnosticCode:
            assert getattr(DiagnosticCode, code.name) is code
            assert DiagnosticCode(code.value) is code
        DiagnosticPolicy(raise_on={"scan_entry_vanished"})


def test_an_unknown_name_still_fails() -> None:
    with pytest.raises(AttributeError):
        DiagnosticCode.NO_SUCH_CODE  # type: ignore[attr-defined]  # noqa: B018
    with pytest.raises(KeyError):
        DiagnosticCode["NO_SUCH_CODE"]
    with pytest.raises(ValueError):
        DiagnosticCode("no_such_code")
