"""Unicode format characters a reader cannot see, in member names and link targets.

A zero-width space makes ``invoice.pdf`` and ``invoice<U+200B>.pdf`` display the same
and extract side by side. Two codes report the format characters (Unicode category Cf)
that ``MEMBER_NAME_BIDI_CONTROL`` does not:

- ``MEMBER_NAME_ZERO_WIDTH_CHARACTER`` for U+200B, U+2060 and U+FEFF, which have no use
  in a filename. The ``DiagnosticPolicy.STRICT`` diagnostic policy raises on it.
- ``MEMBER_NAME_INVISIBLE_CHARACTER`` for every other Cf character.
  ``DiagnosticPolicy.STRICT`` does not raise on it, because a zero-width joiner is part
  of ordinary emoji sequences.

No extraction filter refuses either.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

import archivey
from archivey import ArchiveyConfig
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
    MemberNameControlsContext,
)
from archivey.exceptions import DiagnosticRaisedError

_ZERO_WIDTH = DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER
_INVISIBLE = DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER
_BIDI = DiagnosticCode.MEMBER_NAME_BIDI_CONTROL


def _archive(tmp_path: Path, kind: str, names: list[str]) -> Path:
    """A ``kind`` archive holding one small file under each of ``names``."""
    if kind == "zip":
        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as zf:
            for i, name in enumerate(names):
                zf.writestr(name, f"{i}".encode())
        return path
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        for i, name in enumerate(names):
            data = f"{i}".encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _contexts(member: archivey.ArchiveMember, code: DiagnosticCode) -> list[object]:
    return [d.context for d in member.diagnostics if d.code is code]


def _policy(policy: DiagnosticPolicy) -> ArchiveyConfig:
    return ArchiveyConfig(diagnostic_policy=policy)


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_zero_width_space_is_reported_and_both_files_extract(
    tmp_path: Path, kind: str
) -> None:
    archive = _archive(tmp_path, kind, ["invoice.pdf", "invoice\u200b.pdf"])
    dest = tmp_path / "out"
    with archivey.open_archive(archive) as reader:
        plain, hidden = reader.members()
        assert plain.diagnostics == ()
        (context,) = _contexts(hidden, _ZERO_WIDTH)
        assert _contexts(hidden, _INVISIBLE) == []
        reader.extract_all(dest)
        assert reader.diagnostics.counts[_ZERO_WIDTH] == 1
    assert isinstance(context, MemberNameControlsContext)
    assert context.category == "zero_width"
    assert context.field == "name"
    assert context.controls == "U+200B"
    assert context.member_name == "invoice\u200b.pdf"
    assert (dest / "invoice.pdf").read_bytes() == b"0"
    assert (dest / "invoice\u200b.pdf").read_bytes() == b"1"


def test_strict_refuses_a_zero_width_character(tmp_path: Path) -> None:
    archive = _archive(tmp_path, "zip", ["invoice.pdf", "invoice\u200b.pdf"])
    with (
        archivey.open_archive(archive, config=_policy(DiagnosticPolicy.STRICT)) as r,
        pytest.raises(DiagnosticRaisedError) as excinfo,
    ):
        r.members()
    assert excinfo.value.diagnostic.code is _ZERO_WIDTH


def test_strict_does_not_refuse_an_invisible_character(tmp_path: Path) -> None:
    # Woman technologist: woman, ZWJ, laptop.
    archive = _archive(tmp_path, "zip", ["👩\u200d💻.txt"])
    with archivey.open_archive(archive, config=_policy(DiagnosticPolicy.STRICT)) as r:
        report = r.extract_all(tmp_path / "out")
        assert len(report.results) == 1
        assert r.diagnostics.counts[_INVISIBLE] == 1


def test_pedantic_refuses_an_invisible_character(tmp_path: Path) -> None:
    archive = _archive(tmp_path, "zip", ["a\u200db.txt"])
    with (
        archivey.open_archive(archive, config=_policy(DiagnosticPolicy.PEDANTIC)) as r,
        pytest.raises(DiagnosticRaisedError) as excinfo,
    ):
        r.members()
    assert excinfo.value.diagnostic.code is _INVISIBLE


def test_raise_on_refuses_an_invisible_character(tmp_path: Path) -> None:
    archive = _archive(tmp_path, "zip", ["a\u200db.txt"])
    policy = DiagnosticPolicy(raise_on=frozenset({"member_name_invisible_character"}))
    with (
        archivey.open_archive(archive, config=_policy(policy)) as reader,
        pytest.raises(DiagnosticRaisedError) as excinfo,
    ):
        reader.members()
    assert excinfo.value.diagnostic.code is _INVISIBLE


@pytest.mark.parametrize(
    ("char", "code", "spelling"),
    [
        ("\u200b", _ZERO_WIDTH, "U+200B"),  # zero-width space
        ("\u2060", _ZERO_WIDTH, "U+2060"),  # word joiner
        ("\ufeff", _ZERO_WIDTH, "U+FEFF"),  # byte order mark
        ("\u00ad", _INVISIBLE, "U+00AD"),  # soft hyphen
        ("\u200c", _INVISIBLE, "U+200C"),  # zero-width non-joiner
        ("\u200d", _INVISIBLE, "U+200D"),  # zero-width joiner
        ("\U000e0067", _INVISIBLE, "U+E0067"),  # tag character, as in flag emoji
    ],
)
def test_each_format_character_is_named_under_its_code(
    tmp_path: Path, char: str, code: DiagnosticCode, spelling: str
) -> None:
    archive = _archive(tmp_path, "zip", [f"a{char}b.txt"])
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
        (diagnostic,) = member.diagnostics
    assert diagnostic.code is code
    assert isinstance(diagnostic.context, MemberNameControlsContext)
    assert diagnostic.context.controls == spelling


@pytest.mark.parametrize(
    "name",
    [
        "café.txt",  # printable non-ASCII
        "a\u00a0b.txt",  # no-break space: category Zs, shown as a space
        "❤\ufe0f.txt",  # variation selector: category Mn, not Cf
        "evil\u202egnp.exe",  # bidi override: MEMBER_NAME_BIDI_CONTROL only
        "\u200fדוח.pdf",  # bidi mark: MEMBER_NAME_BIDI_CONTROL only
    ],
)
def test_other_characters_are_not_reported_as_invisible(
    tmp_path: Path, name: str
) -> None:
    archive = _archive(tmp_path, "zip", [name])
    with archivey.open_archive(archive) as reader:
        reader.members()
        counts = reader.diagnostics.counts
        assert _INVISIBLE not in counts
        assert _ZERO_WIDTH not in counts


def test_each_character_is_reported_under_one_code(tmp_path: Path) -> None:
    archive = _archive(tmp_path, "zip", ["a\u202eb\u200dc\u200bd\u00ade.txt"])
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
        found = {
            d.code: (d.context.category, d.context.controls)
            for d in member.diagnostics
            if isinstance(d.context, MemberNameControlsContext)
        }
    assert found == {
        _BIDI: ("bidi", "U+202E"),
        _ZERO_WIDTH: ("zero_width", "U+200B"),
        _INVISIBLE: ("invisible", "U+200D,U+00AD"),
    }


_TARGET = "invoice\u200b.pdf"


def _link_archive(tmp_path: Path, kind: str) -> Path:
    """A ``kind`` archive whose symlink ``link`` stores ``_TARGET``."""
    if kind == "tar":
        path = tmp_path / "a.tar"
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = _TARGET
            tf.addfile(info)
        return path
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, _TARGET.encode("utf-8"))
    return path


# tar: the target is in the header. zip: the target is the member's data.
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_link_target_zero_width_character_is_reported_once(
    tmp_path: Path, kind: str, streaming: bool
) -> None:
    archive = _link_archive(tmp_path, kind)
    with archivey.open_archive(archive, streaming=streaming) as reader:
        if not streaming:
            reader.members()
        report = reader.extract_all(tmp_path / "out", on_error="continue")
        (result,) = report.results
        link = result.member
        assert link.link_target == _TARGET
        (context,) = _contexts(link, _ZERO_WIDTH)
        assert reader.diagnostics.counts[_ZERO_WIDTH] == 1
    assert isinstance(context, MemberNameControlsContext)
    assert context.field == "link_target"
    assert context.member_name == "link"
    assert context.controls == "U+200B"


def test_a_refused_name_retried_reports_its_other_codes_once(tmp_path: Path) -> None:
    """A walk started over after the second of a name's emits raised.

    The first emit (bidi, a warning here) already counted; the retry must replay it,
    not count it again, while the refusal still raises.
    """
    archive = _archive(tmp_path, "zip", ["a\u200fb\u200bc.txt"])
    policy = DiagnosticPolicy(raise_on=frozenset({"member_name_zero_width_character"}))
    seen: list[DiagnosticCode] = []
    config = ArchiveyConfig(
        diagnostic_policy=policy, on_diagnostic=lambda d: seen.append(d.code)
    )
    with archivey.open_archive(archive, config=config) as reader:
        for _ in range(2):
            with pytest.raises(DiagnosticRaisedError) as excinfo:
                reader.members()
            assert excinfo.value.diagnostic.code is _ZERO_WIDTH
        assert reader.diagnostics.counts[_BIDI] == 1
        assert reader.diagnostics.counts[_ZERO_WIDTH] == 1
    assert seen == [_BIDI, _ZERO_WIDTH]
