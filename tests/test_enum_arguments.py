"""The public API's enum arguments accept string spellings, and refuse bad ones loudly.

Two things are under test, and the second is the reason the first exists.

**The contract.** Every ``Enum`` parameter on a public entry point takes the member, its
``value`` or its name, in any case, with ``-`` and ``_`` interchangeable; anything else
raises :class:`ArchiveyUsageError` at the call, naming the spellings that would have
worked.

**The bugs it closes.** The consuming code tests these with ``is``, so before coercion an
unrecognised value was not refused — it silently took the other branch.
``extract(overwrite="skip")`` (the one-shot call, since removed) fell through to
REPLACE and deleted the file the caller asked to keep; ``extract(on_error="stop")``
behaved as CONTINUE and swallowed a corruption error. Both have a red-green test here.

The collision guards matter more than they look: coercion is only safe while no two
members share a normalized spelling. They fail on the day a new value introduces an
ambiguity, rather than leaving it to resolve silently to the wrong member.
"""

from __future__ import annotations

import ast
import os
import struct
import zipfile
from enum import Enum
from pathlib import Path
from typing import get_args

import pytest

from archivey import (
    AbortOn,
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
)
from archivey.cli.choices import cli_choices, from_cli_choice
from archivey.cli.errors import CliError
from archivey.cli.main import build_parser
from archivey.config import AcceleratorMode, ArchiveyConfig, RarDecompressor
from archivey.detection_cost import DetectionBudgetPreset
from archivey.diagnostics import DiagnosticCode, DiagnosticCodeStr
from archivey.exceptions import ArchiveyError, ArchiveyUsageError
from archivey.internal.enum_args import (
    coerce_enum,
    coerce_enum_collection,
    normalize_spelling,
    spelling_table,
)
from archivey.types import (
    AbortOnStr,
    ContainerFormat,
    ExtractionPolicyStr,
    OnErrorStr,
    OverwritePolicyStr,
    StreamFormat,
)
from tests.extract_util import open_and_extract

# Every enum reachable from a public argument.
PUBLIC_ENUMS: tuple[type[Enum], ...] = (
    ExtractionPolicy,
    OverwritePolicy,
    OnError,
    AbortOn,
    AcceleratorMode,
    RarDecompressor,
    DetectionBudgetPreset,
    ContainerFormat,
    StreamFormat,
)


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("hello.txt", "original")
    return path


# --- the coercion contract ---------------------------------------------------------


@pytest.mark.parametrize("enum_cls", PUBLIC_ENUMS, ids=lambda c: c.__name__)
def test_no_two_members_share_a_normalized_spelling(enum_cls: type[Enum]) -> None:
    """The guard that makes case- and dash-insensitivity safe to offer.

    If this fails, a new member's value or name collides with another's under
    ``normalize_spelling``, and one of the two has become unreachable by that spelling.
    Fix the value, do not relax the normalization — callers are already using it.
    """
    seen: dict[str, str] = {}
    for member in enum_cls:
        spellings = {normalize_spelling(member.name)}
        if isinstance(member.value, str):
            spellings.add(normalize_spelling(member.value))
        for spelling in spellings:
            clash = seen.get(spelling)
            assert clash is None or clash == member.name, (
                f"{enum_cls.__name__}: {spelling!r} spells both {clash} and "
                f"{member.name}"
            )
            seen[spelling] = member.name


def test_spelling_table_prefers_preferred_then_the_first_fallback() -> None:
    # The tie-break ``_lookup`` and the format tables rely on, pinned on the helper
    # itself because no shipping enum or format has a tie to exercise it.
    assert spelling_table(fallback=[("a", 1)], preferred=[("A", 2)]) == {"a": 2}
    assert spelling_table(fallback=[("a", 1), ("A", 2)], preferred=[]) == {"a": 1}


@pytest.mark.parametrize("enum_cls", PUBLIC_ENUMS, ids=lambda c: c.__name__)
def test_every_member_is_reachable_by_every_documented_spelling(
    enum_cls: type[Enum],
) -> None:
    for member in enum_cls:
        spellings = [member.name, member.name.lower(), member.name.replace("_", "-")]
        if isinstance(member.value, str):
            spellings += [
                member.value,
                member.value.upper(),
                member.value.replace("_", "-"),
                f"  {member.value}  ",
            ]
        for spelling in spellings:
            assert coerce_enum(spelling, enum_cls, call="t()", param="p=") is member, (
                f"{enum_cls.__name__}: {spelling!r} did not resolve to {member.name}"
            )


@pytest.mark.parametrize("enum_cls", PUBLIC_ENUMS, ids=lambda c: c.__name__)
def test_an_unknown_spelling_names_the_ones_that_work(enum_cls: type[Enum]) -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        coerce_enum("definitely-not-a-member", enum_cls, call="t()", param="p=")

    message = str(exc_info.value)
    assert enum_cls.__name__ in message
    for member in enum_cls:
        expected = str(member.value) if isinstance(member.value, str) else member.name
        assert repr(expected) in message


def test_a_member_of_the_wrong_enum_is_a_type_error_not_a_spelling_error() -> None:
    """``AbortOn`` mixes in ``str``, so it would otherwise land in the string branch."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        coerce_enum(AbortOn.BLOCKED_MEMBER, OverwritePolicy, call="t()", param="p=")

    message = str(exc_info.value)
    assert "AbortOn.BLOCKED_MEMBER" in message
    assert "OverwritePolicy" in message


def test_a_bare_string_is_not_a_collection_of_one() -> None:
    """``abort_on="blocked_member"`` is a typo, not eleven single-character members."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        coerce_enum_collection("blocked_member", AbortOn, call="t()", param="abort_on=")

    assert "['blocked_member']" in str(exc_info.value)


def test_usage_errors_escape_archiveyerror_handlers() -> None:
    """ADR 0012: a caller mistake must not be swallowed by the untrusted-input handler."""
    with pytest.raises(ArchiveyUsageError):
        try:
            coerce_enum("nope", OverwritePolicy, call="t()", param="p=")
        except ArchiveyError:  # pragma: no cover - the point is that it does not fire
            pytest.fail("ArchiveyUsageError was swallowed by `except ArchiveyError`")


# --- the bugs it closes ------------------------------------------------------------


def test_overwrite_as_a_string_skips_instead_of_replacing(
    archive: Path, tmp_path: Path
) -> None:
    """Red-green for the data loss: ``"skip"`` used to fall through to REPLACE.

    The branch chain is ``is ERROR`` / ``is SKIP`` / else replace, so a string matched
    neither and landed on the one branch that unlinks the existing entry — destroying
    the local file the caller had asked to keep.
    """
    dest = tmp_path / "out"
    open_and_extract(archive, dest)
    (dest / "hello.txt").write_text("LOCAL EDIT")

    report = open_and_extract(archive, dest, overwrite="skip")

    assert (dest / "hello.txt").read_text() == "LOCAL EDIT"
    assert [r.status for r in report.results] == [ExtractionStatus.NOT_OVERWRITTEN]


def test_overwrite_as_a_string_agrees_with_the_member(
    archive: Path, tmp_path: Path
) -> None:
    results = {}
    for label, value in (("str", "replace"), ("enum", OverwritePolicy.REPLACE)):
        dest = tmp_path / label
        open_and_extract(archive, dest)
        (dest / "hello.txt").write_text("LOCAL EDIT")
        report = open_and_extract(archive, dest, overwrite=value)
        results[label] = (
            (dest / "hello.txt").read_text(),
            [r.status for r in report.results],
        )
    assert results["str"] == results["enum"]


def test_on_error_as_a_string_stops_instead_of_continuing(tmp_path: Path) -> None:
    """Red-green: every site is ``is OnError.STOP``, so a string took the CONTINUE path.

    A STORED member with its data bytes flipped fails its CRC on read and nothing else,
    which is the per-member failure ``on_error`` governs.
    """
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("ok1.txt", "fine")
        zf.writestr("broken.txt", "y" * 2000)
        zf.writestr("ok2.txt", "also fine")

    raw = bytearray(path.read_bytes())
    offset = raw.find(b"PK\x03\x04")
    while offset != -1:
        name_len, extra_len = struct.unpack_from("<HH", raw, offset + 26)
        name = bytes(raw[offset + 30 : offset + 30 + name_len])
        data = offset + 30 + name_len + extra_len
        if name == b"broken.txt":
            for i in range(data + 100, data + 200):
                raw[i] ^= 0xFF
            break
        offset = raw.find(b"PK\x03\x04", offset + 1)
    path.write_bytes(bytes(raw))

    with pytest.raises(ArchiveyError):
        open_and_extract(path, tmp_path / "stop_str", on_error="stop")

    # The opposite value still reports rather than raising, so the test above is not
    # just asserting that any extraction of this archive fails.
    report = open_and_extract(path, tmp_path / "continue", on_error="continue")
    assert ExtractionStatus.FAILED in [r.status for r in report.results]


@pytest.mark.parametrize(
    ("param", "value"),
    [
        ("policy", "nonsense"),
        ("overwrite", "nonsense"),
        ("on_error", "nonsense"),
    ],
)
def test_extract_refuses_a_bad_spelling_with_a_usage_error(
    archive: Path, tmp_path: Path, param: str, value: str
) -> None:
    """Not a ``KeyError`` from a transform table, and not silence."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_and_extract(archive, tmp_path / "out", **{param: value})

    assert param in str(exc_info.value)


def test_extract_refuses_before_it_writes_anything(
    archive: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "out"
    with pytest.raises(ArchiveyUsageError):
        open_and_extract(archive, dest, overwrite="nonsense")

    assert not dest.exists() or not os.listdir(dest)


def test_abort_on_accepts_the_spelling_the_cli_advertises(
    archive: Path, tmp_path: Path
) -> None:
    """``--abort-on blocked-member`` from ``--help``, pasted into a script."""
    open_and_extract(archive, tmp_path / "out", abort_on=["blocked-member"])


# --- the same contract on the other entry points -----------------------------------


def test_archivey_config_stores_the_member_not_the_string() -> None:
    """The field is read with ``is``, so a surviving string would read as AUTO."""
    config = ArchiveyConfig(use_rapidgzip="on", use_indexed_bzip2="off")
    assert config.use_rapidgzip is AcceleratorMode.ON
    assert config.use_indexed_bzip2 is AcceleratorMode.OFF


def test_archivey_config_refuses_a_bad_accelerator_spelling() -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        ArchiveyConfig(use_rapidgzip="sometimes")

    assert "use_rapidgzip" in str(exc_info.value)


def test_detection_budget_takes_a_preset_by_name(archive: Path) -> None:
    from archivey.detection_cost import FAST_BUDGET
    from archivey.internal.detection import detect_format

    config = ArchiveyConfig(detection_budget="fast")
    assert config.detection_budget == FAST_BUDGET
    assert detect_format(archive, config=config).format is not None


def test_detection_budget_refuses_an_unknown_preset_name() -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        ArchiveyConfig(detection_budget="turbo")

    assert "'fast'" in str(exc_info.value)


def test_detection_budget_still_takes_a_budget_object(archive: Path) -> None:
    """The preset arm is an addition, not a replacement."""
    from dataclasses import replace

    from archivey.detection_cost import BALANCED_BUDGET
    from archivey.internal.detection import detect_format

    budget = replace(BALANCED_BUDGET, max_scan_bytes=1024)
    config = ArchiveyConfig(detection_budget=budget)
    assert config.detection_budget is budget
    assert detect_format(archive, config=config).format is not None


def test_a_wrong_typed_budget_message_names_every_type_it_accepts() -> None:
    """``detection_budget=`` takes three shapes, so a message naming two reads as a denial.

    A caller holding a ``DetectionBudget`` who mistypes the argument would otherwise
    be told the field takes a preset, and conclude their object is not allowed.
    """
    with pytest.raises(ArchiveyUsageError) as exc_info:
        ArchiveyConfig(detection_budget=0)

    message = str(exc_info.value)
    assert "DetectionBudget or a DetectionBudgetPreset" in message
    assert "its name as a string" in message


# --- the Literal aliases track their enums ------------------------------------------

#: Each public enum and the ``Literal`` alias that spells it for a type checker.
LITERAL_ALIASES: tuple[tuple[type[Enum], object], ...] = (
    (ExtractionPolicy, ExtractionPolicyStr),
    (OverwritePolicy, OverwritePolicyStr),
    (OnError, OnErrorStr),
    (AbortOn, AbortOnStr),
    (DiagnosticCode, DiagnosticCodeStr),
)


#: Enums coerced at a public boundary that deliberately carry no ``Literal`` alias,
#: with the reason, so the next reader does not "fix" the gap by adding one back.
ALIASES_NOT_WANTED = {
    "AcceleratorMode": (
        "ArchiveyConfig's accelerator fields stay annotated AcceleratorMode rather "
        "than AcceleratorMode | str: what the field holds after construction is always "
        "a member, and the union would describe the constructor's input on the "
        "attribute every consumer reads, obliging each of them to handle a string that "
        "cannot arrive. See the archived coerce-public-enum-arguments design note."
    ),
    "ProcessIsolation": (
        "ArchiveyConfig.process_isolation stays annotated ProcessIsolation, for the "
        "same reason as AcceleratorMode: __post_init__ converts the name, so the field "
        "always holds a member."
    ),
    "RarDecompressor": (
        "ArchiveyConfig.rar_decompressor stays annotated RarDecompressor, for the same "
        "reason as AcceleratorMode: __post_init__ converts the name, so the field always "
        "holds a member."
    ),
    "ContainerFormat": (
        "ArchiveFormat's container field, for the same reason as AcceleratorMode: "
        "__post_init__ converts a hand-built string pair, so the field always holds a "
        "member, and the code that reads it tests it with `is`."
    ),
    "DetectionBudgetPreset": (
        "ArchiveyConfig.detection_budget stays annotated DetectionBudget, for the same "
        "reason as AcceleratorMode: __post_init__ converts a preset member or its name, "
        "so the field always holds a budget, and every consumer reads it as one. Its "
        "only other consumer, detect_format(budget=), was removed."
    ),
    "StreamFormat": (
        "ArchiveFormat's stream field; see ContainerFormat. format= arguments take "
        "their string spellings through archivey.internal.format_args instead."
    ),
}


def _enums_coerced_under_src() -> set[str]:
    """Every enum class handed to ``coerce_enum`` / ``coerce_enum_collection``.

    Read statically, because the set is not available at runtime: the coercions happen
    inside the functions that take the arguments, so nothing collects them. The enum is
    the second positional argument at every call site; one that passed it some other way
    would make this scan silently narrower, so that raises here instead of skipping.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "archivey"
    found: set[str] = set()
    for path in sorted(src.rglob("*.py")):
        if path.name == "enum_args.py":
            # Where the helpers live: its one call is the collection form delegating to
            # the scalar form over a type variable, not a boundary naming an enum.
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            if name not in ("coerce_enum", "coerce_enum_collection"):
                continue
            if len(node.args) < 2 or not isinstance(node.args[1], ast.Name):
                raise AssertionError(
                    f"{path.name}:{node.lineno} calls {name} without the enum as its "
                    "second positional argument, so this scan can no longer see it"
                )
            found.add(node.args[1].id)
    return found


def test_every_coerced_enum_is_aliased_or_exempt_on_the_record() -> None:
    """The guard on the alias table itself, which the per-pair tests below do not give.

    ``test_the_literal_alias_matches_its_enum`` goes red when an enum already in
    ``LITERAL_ALIASES`` grows a member. Nothing watched the tuple: a sixth enum-typed
    public parameter would get the coercion, get its spec row and get no alias, so a
    type checker would reject the string the runtime accepts, with nothing going red.
    That is the shape the CLI's derived ``choices=`` closed one level down.
    """
    coerced = _enums_coerced_under_src()
    assert coerced, "the scan found no call sites, so it was guarding nothing"

    aliased = {enum_cls.__name__ for enum_cls, _ in LITERAL_ALIASES}
    missing = coerced - aliased - set(ALIASES_NOT_WANTED)
    assert not missing, (
        f"{sorted(missing)} are coerced from a string at a public boundary but have no "
        "Literal alias. Add one beside the enum and list it in LITERAL_ALIASES, or "
        "record in ALIASES_NOT_WANTED why the alias is deliberately absent."
    )

    stale = set(ALIASES_NOT_WANTED) - coerced
    assert not stale, (
        f"{sorted(stale)} are listed as deliberately un-aliased but nothing coerces "
        "them any more; drop the entry."
    )
    assert not (aliased & set(ALIASES_NOT_WANTED))


def _expected_literal_spellings(enum_cls: type[Enum]) -> set[str]:
    """Every spelling the alias beside ``enum_cls`` is supposed to carry.

    The canonical ``value``, plus the dash form wherever a value has an underscore —
    that one is what the CLI's ``--help`` prints, so a caller pasting from it must not
    be type-errored for using the spelling we advertise.
    """
    spellings: set[str] = set()
    for member in enum_cls:
        value = member.value
        assert isinstance(value, str), f"{enum_cls.__name__}.{member.name} is not a str"
        spellings.add(value)
        if "_" in value:
            spellings.add(value.replace("_", "-"))
    return spellings


@pytest.mark.parametrize(
    ("enum_cls", "alias"), LITERAL_ALIASES, ids=lambda x: getattr(x, "__name__", "")
)
def test_the_literal_alias_matches_its_enum(
    enum_cls: type[Enum], alias: object
) -> None:
    """The guard that makes the hand-maintained alias safe to hand-maintain.

    A ``Literal`` cannot be generated from an enum, so it is written out and can go
    stale: a member added later is accepted at runtime and rejected by a type checker,
    which is the worst of both. This fails the moment the two disagree, so the cost of
    the alias is paid here rather than by a caller.
    """
    assert set(get_args(alias)) == _expected_literal_spellings(enum_cls)


@pytest.mark.parametrize(
    ("enum_cls", "alias"), LITERAL_ALIASES, ids=lambda x: getattr(x, "__name__", "")
)
def test_every_literal_spelling_actually_coerces(
    enum_cls: type[Enum], alias: object
) -> None:
    """The alias promises a type checker what the runtime must then accept."""
    for spelling in get_args(alias):
        assert coerce_enum(spelling, enum_cls, call="t()", param="p=") in list(enum_cls)


# --- the CLI speaks the same vocabulary -------------------------------------------


CLI_ENUM_OPTIONS = [
    ("--policy", ExtractionPolicy),
    ("--overwrite", OverwritePolicy),
    ("--abort-on", AbortOn),
]


def _parser_choices(option: str) -> list[str]:
    """The ``choices=`` argparse will enforce for ``option``, read off the real parser."""
    parser = build_parser()
    for action in parser._actions:  # argparse exposes no public reader
        if option in action.option_strings:
            assert action.choices is not None, f"{option} has no choices"
            return list(action.choices)
    for sub in parser._subparsers._group_actions if parser._subparsers else []:
        for name, subparser in getattr(sub, "choices", {}).items():
            if name != "extract":
                continue
            for action in subparser._actions:
                if option in action.option_strings:
                    assert action.choices is not None, f"{option} has no choices"
                    return list(action.choices)
    raise AssertionError(f"{option} is not declared on `archivey extract`")


@pytest.mark.parametrize(("option", "enum_cls"), CLI_ENUM_OPTIONS, ids=lambda x: str(x))
def test_the_cli_offers_every_member_of_its_enum(
    option: str, enum_cls: type[Enum]
) -> None:
    """The CLI's spellings are derived from the enum, so a new member reaches it at once.

    These were three hand-written lists, with nothing checking them against the enums
    they mirror. They happened to agree, but a member added to ``AbortOn`` would have
    been accepted by the library, promised by the ``Literal`` alias and documented — and
    then refused by ``archivey extract`` with an argparse invalid-choice error, with
    nothing in this suite going red.
    """
    assert set(_parser_choices(option)) == {
        str(member.value).replace("_", "-") for member in enum_cls
    }


@pytest.mark.parametrize(("option", "enum_cls"), CLI_ENUM_OPTIONS, ids=lambda x: str(x))
def test_the_cli_accepts_every_spelling_the_library_accepts(
    option: str, enum_cls: type[Enum], tmp_path: Path
) -> None:
    """One vocabulary, not a narrower CLI copy of it.

    Driven through the real parser rather than through the fold helper, because the
    property is about argparse's wiring: ``type=`` runs before ``choices=``, which is
    the whole reason ``--abort-on blocked_member`` gets through. Calling the helper and
    then checking membership would pass with the ``type=`` removed, which is the
    pre-fix state where the CLI refused a spelling the library accepts.
    """
    parser = build_parser()
    archive = str(tmp_path / "a.zip")

    for member in enum_cls:
        value = str(member.value)
        for spelling in (value, value.replace("_", "-"), value.upper()):
            args = parser.parse_args(["extract", archive, option, spelling])
            parsed = getattr(args, option.lstrip("-").replace("-", "_"))
            got = parsed[-1] if isinstance(parsed, list) else parsed
            # The conversion ``run_extract`` performs, not the library's own.
            assert from_cli_choice(enum_cls, got) is member


def test_a_cli_choice_maps_back_even_when_the_value_holds_a_dash() -> None:
    """The way back is a lookup, not the substitution run in reverse.

    Undoing ``_`` -> ``-`` would turn a value that already holds a dash into one no
    member has, and the enum constructor would raise a bare ``ValueError`` that
    ``main()`` does not catch.
    """

    class Toy(Enum):
        DRY_RUN = "dry_run"
        NO_OP = "no-op"

    assert cli_choices(Toy) == ["dry-run", "no-op"]
    assert from_cli_choice(Toy, "dry-run") is Toy.DRY_RUN
    assert from_cli_choice(Toy, "no-op") is Toy.NO_OP


def test_an_unknown_cli_choice_is_a_usage_error() -> None:
    """A caller that skips the parser gets the accepted spellings, not ``ValueError``."""
    with pytest.raises(CliError, match="invalid choice 'nope' \\(choose from "):
        from_cli_choice(ExtractionPolicy, "nope")


@pytest.mark.parametrize(("option", "enum_cls"), CLI_ENUM_OPTIONS, ids=lambda x: str(x))
def test_a_refused_cli_spelling_is_quoted_as_the_caller_typed_it(
    option: str,
    enum_cls: type[Enum],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The fold widens what is accepted; it must not rewrite what is refused.

    argparse quotes the post-``type=`` value in ``invalid choice:``, so a fold that ran
    unconditionally made ``--policy Trusted_`` come back as ``invalid choice:
    'trusted-'`` — a trailing dash the caller never typed, and a spelling legal nowhere.
    The fold now applies only when it lands on a real choice, so an unrecognised value
    reaches the message untouched.
    """
    parser = build_parser()
    archive = str(tmp_path / "a.zip")
    # Upper case and a trailing underscore: both are things the fold rewrites, so a
    # fold that fired here would quote something other than this string.
    typo = f"{next(iter(enum_cls)).value}_".upper() + "X"

    with pytest.raises(SystemExit):
        parser.parse_args(["extract", archive, option, typo])

    stderr = capsys.readouterr().err
    assert f"invalid choice: {typo!r}" in stderr
