"""No raw exception escapes the public API on a wrong argument.

Every finding this file guards was found the same way: call a public entry point with
a value a caller plausibly writes, and look at what comes back. The failures were not
subtle — ``AttributeError: 'str' object has no attribute 'diagnostic_policy'`` from
``config="strict"``, ``LookupError`` from a misspelled ``encoding=``, a silently empty
extraction from ``members="notes.txt"`` — but each was reachable only by making that
one call, and nothing made the whole surface answerable at once.

So the point of this file is the **sweep**, not the individual cases, and it takes two
tests to be one. :func:`test_no_raw_exception_escapes` walks a table of (entry point,
argument, wrong value) and asserts that what escapes is on the contract's list. That
half can only ever check the rows it was handed, so
:func:`test_every_public_argument_is_swept` reads the public signatures back and fails
when an argument has neither a row nor a written exemption — which is what makes an
argument added with no check a failure here rather than a silence.

**What the contract permits**, and therefore what this test allows through
(``error-handling`` and ``archive-reading``):

* :class:`~archivey.ArchiveyUsageError` — a detected caller bug (ADR 0012), outside
  ``ArchiveyError`` so ``except ArchiveyError`` cannot swallow it. The only answer, and
  it must also be a ``TypeError`` or a ``ValueError`` (DR-15), so a caller's
  ``except TypeError`` catches a wrong type as it would anywhere else in Python. That
  holds for **source** and ``dest`` too: ``open_archive(0)`` raises a usage error that
  is a ``TypeError``, never a bare one.
* An empty string as a **source** or ``dest`` is a usage error that is also a
  ``ValueError``: ``Path("")`` is ``Path(".")``, so it would otherwise name the current
  directory. Every path argument must have an empty-string row
  (:func:`test_every_path_argument_has_an_empty_row`), and the sweep requires such a
  row's error to be a ``ValueError`` whose message says the path is empty.
* :class:`~archivey.exceptions.ArchiveyError` — an archive/environment failure, and
  only on a source row, where a wrong-typed value can also be real archive bytes.
* ``TypeError`` for ``len()``/``in``, which this file does not exercise.
* ``KeyError`` for an unknown member name (``archive-reading`` specifies it), plus
  ``io.UnsupportedOperation`` for an unsupported ``seek`` and ``ValueError`` for I/O
  on a closed stream — neither of which this file exercises.

Anything else is a finding. In particular an ``AttributeError`` is **never** allowed:
every one of them here named a private attribute of ours in the message, which is the
"no internal leakage" rule in ``CONTRIBUTING.md``.
"""

from __future__ import annotations

import dataclasses
import inspect
import io
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveReader,
    ArchiveyConfig,
    DecoderLimits,
    DiagnosticPolicy,
    ExtractionLimits,
    ListingLimits,
    SpoolLimits,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.detection_cost import (
    BALANCED_BUDGET,
    DetectionBudget,
    DetectionBudgetPreset,
)
from archivey.exceptions import ArchiveyError, ArchiveyUsageError

# An ArchiveyError is permitted only for the arguments named here; see the module
# docstring.
_ARCHIVE_ERROR_OK = frozenset({"source"})

# The path arguments. Each must have an empty-string row; see the module docstring.
_PATH_ARGUMENTS = frozenset({"source", "dest"})


@pytest.fixture(autouse=True)
def _scratch_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run every probe from a scratch directory.

    The empty-path rows name the current directory if their refusal regresses, and
    an extraction there would land in the checkout.
    """
    scratch = tmp_path / "scratch-cwd"
    scratch.mkdir()
    monkeypatch.chdir(scratch)


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("h.txt", "hi")
        zf.writestr("b.txt", "bye")
    return path


class _Case(NamedTuple):
    """One (entry point, argument, wrong value) probe.

    The wrong value is wrongly typed or wrongly valued: whatever a caller plausibly
    writes that the entry point must refuse.

    ``entry`` is the name as :func:`_public_surface` and :data:`_NOT_SWEPT` spell it,
    and it is what the inventory matches on. Keying by argument name alone was not
    enough: a ``limits`` row on ``extract`` made ``extract_all(limits=…)`` look swept,
    so removing that check would not have failed the inventory.

    ``argument`` also decides whether a bare ``TypeError`` is allowed, so a row added
    with an unfamiliar name gets the strict treatment by default.

    ``empty_path`` marks a row that passes an empty string as a path, alone or inside
    a volume list. Only such a row may answer with the empty-path ``ValueError``.
    :func:`_case` sets it from the value, so no label or list has to agree with it.
    """

    entry: str
    argument: str
    label: str
    call: Callable[[], Any]
    empty_path: bool


def _is_empty_path(argument: str, bad: Any) -> bool:
    if argument not in _PATH_ARGUMENTS:
        return False
    if isinstance(bad, list):
        return any(isinstance(item, str) and item == "" for item in bad)
    return isinstance(bad, str) and bad == ""


def _case(
    entry: str,
    argument: str,
    bad: Any,
    call: Callable[[], Any],
    *,
    label: str | None = None,
) -> _Case:
    return _Case(
        entry,
        argument,
        label or f"{entry}({argument}={bad!r})",
        call,
        _is_empty_path(argument, bad),
    )


def _cases(archive: Path, dest: Path) -> list[_Case]:
    """Every public argument, with each wrong value a caller plausibly writes."""
    d = iter(range(10_000))

    def out() -> Path:
        # Do not create the directory. extract_all used to check
        # members= only after dest existed, and a helper that mkdir'd first
        # made any "refusal must not touch the disk" assertion dead on arrival.
        return dest / f"d{next(d)}"

    rows: list[_Case] = []

    for bad in ("x", ArchiveyConfig, 0, ()):
        rows += [
            _case(
                "open_archive",
                "config",
                bad,
                lambda b=bad: open_archive(archive, config=b),
            ),
            _case(
                "open_stream",
                "config",
                bad,
                lambda b=bad: open_stream(archive, config=b),
            ),
            _case(
                "detect_format",
                "config",
                bad,
                lambda b=bad: detect_format(archive, config=b),
            ),
        ]

    # ``DetectionBudget`` has no defaults, so each row starts from a real preset and
    # replaces one field. Every field is a byte count compared or sliced with, and
    # ``None`` there is not "off": it fails mid-detection.
    for budget_field in dataclasses.fields(DetectionBudget):
        for bad in ("x", -1, True, 1.5, None):
            rows.append(
                _case(
                    "DetectionBudget",
                    budget_field.name,
                    bad,
                    lambda b=bad, f=budget_field.name: dataclasses.replace(
                        BALANCED_BUDGET, **{f: b}
                    ),
                )
            )

    for bad in ("x", 0, ExtractionLimits):
        rows += [
            _case(
                "extract_all",
                "limits",
                bad,
                lambda b=bad: _extract_all(archive, out(), None, limits=b),
            ),
        ]

    for bad in ("not-a-codec", "rot13", b"utf-8", 0, ()):
        rows += [
            _case(
                "open_archive",
                "encoding",
                bad,
                lambda b=bad: open_archive(archive, encoding=b),
            ),
        ]

    # Object shape of detection_budget=, not preset spellings. ``"balanced"`` is a real
    # DetectionBudgetPreset value, coerced by ``enum_args`` and asserted in
    # ``tests/test_enum_arguments.py``; the values below are none of the three types.
    for bad in (0, object(), "x"):
        rows.append(
            _case(
                "ArchiveyConfig",
                "detection_budget",
                bad,
                lambda b=bad: ArchiveyConfig(detection_budget=b),
            )
        )

    for bad in (0, "callback", []):
        rows += [
            _case(
                "extract_all",
                "on_progress",
                bad,
                lambda b=bad: _extract_all(archive, out(), None, on_progress=b),
            ),
            _case(
                "extract_all",
                "filter",
                bad,
                lambda b=bad: _extract_all(archive, out(), None, filter=b),
            ),
        ]

    for bad in (0, None, object(), b"h.txt", 1.5):
        rows += [
            _case(
                "open",
                "member",
                bad,
                lambda b=bad: _open_member(archive, b),
                label=f"reader.open({bad!r})",
            ),
            _case(
                "read",
                "member",
                bad,
                lambda b=bad: _read_member(archive, b),
                label=f"reader.read({bad!r})",
            ),
            _case(
                "get",
                "name",
                bad,
                lambda b=bad: _get_member(archive, b),
                label=f"reader.get({bad!r})",
            ),
        ]
    # A member object, which ``open()`` takes: ``get()`` looks up by name only, and
    # this used to escape as ``TypeError: unhashable type: 'ArchiveMember'``.
    rows.append(
        _case(
            "get",
            "name",
            "<ArchiveMember>",
            lambda: _get_member(archive, None, by_member=True),
            label="reader.get(<ArchiveMember>)",
        )
    )

    for bad in ("h.txt", [0], [None], [1.5], 0):
        rows += [
            _case(
                "extract_all",
                "members",
                bad,
                lambda b=bad: _extract_all(archive, out(), b),
            ),
            _case(
                "stream_members",
                "members",
                bad,
                lambda b=bad: _stream_members(archive, b),
            ),
        ]

    for bad in (0, 1, None, "yes"):
        rows.append(
            _case(
                "stream_members",
                "file_copy_streams",
                bad,
                lambda b=bad: _stream_members(archive, None, file_copy_streams=b),
            )
        )

    for bad in (0, object(), [0], [None], 1.5):
        rows += [
            _case(
                "open_archive",
                "password",
                bad,
                lambda b=bad: open_archive(archive, password=b),
            ),
        ]

    for bad in (
        0,
        object(),
        b"PK\x03\x04",
        bytearray(b"PK\x03\x04"),
        memoryview(b"PK\x03\x04"),
        None,
        io.StringIO("x"),
        io.BufferedWriter(io.BytesIO()),
        "",
    ):
        rows += [
            _case(
                "open_archive",
                "source",
                bad,
                lambda b=bad: open_archive(b),
                label=f"open_archive({bad!r})",
            ),
            _case(
                "open_stream",
                "source",
                bad,
                lambda b=bad: open_stream(b),
                label=f"open_stream({bad!r})",
            ),
            _case(
                "detect_format",
                "source",
                bad,
                lambda b=bad: detect_format(b),
                label=f"detect_format({bad!r})",
            ),
        ]

    # An empty string inside a volume list, in either position: each item is a path.
    for volumes in ([archive, ""], ["", archive]):
        rows.append(
            _case(
                "open_archive",
                "source",
                volumes,
                lambda v=volumes: open_archive(v),
                label=f"open_archive([{', '.join(repr(str(p)) for p in volumes)}])",
            )
        )

    for bad in (0, None, object(), ""):
        rows.append(
            _case(
                "extract_all", "dest", bad, lambda b=bad: _extract_all(archive, b, None)
            )
        )

    for bad in ("x", -1, True, 1.5):
        rows += [
            _case(
                "ListingLimits",
                "max_members",
                bad,
                lambda b=bad: ListingLimits(max_members=b),
            ),
            _case(
                "ListingLimits",
                "max_metadata_bytes",
                bad,
                lambda b=bad: ListingLimits(max_metadata_bytes=b),
            ),
            _case(
                "ExtractionLimits",
                "max_extracted_bytes",
                bad,
                lambda b=bad: ExtractionLimits(max_extracted_bytes=b),
            ),
            _case(
                "ExtractionLimits",
                "max_entries",
                bad,
                lambda b=bad: ExtractionLimits(max_entries=b),
            ),
            _case(
                "DecoderLimits",
                "max_decoder_memory",
                bad,
                lambda b=bad: DecoderLimits(max_decoder_memory=b),
            ),
            _case(
                "DecoderLimits",
                "max_key_derivation_rounds",
                bad,
                lambda b=bad: DecoderLimits(max_key_derivation_rounds=b),
            ),
            _case(
                "DecoderLimits",
                "max_ppmd_held_input",
                bad,
                lambda b=bad: DecoderLimits(max_ppmd_held_input=b),
            ),
            _case(
                "SpoolLimits",
                "max_bytes",
                bad,
                lambda b=bad: SpoolLimits(max_bytes=b),
            ),
        ]

    # The two activation thresholds are the limit fields that are not ``| None``, so
    # None belongs in their bad set: it disables nothing, it breaks the comparison.
    for bad in ("x", -1, True, 1.5, None):
        rows.append(
            _case(
                "ExtractionLimits",
                "ratio_activation_threshold",
                bad,
                lambda b=bad: ExtractionLimits(ratio_activation_threshold=b),
            )
        )
        rows.append(
            _case(
                "ExtractionLimits",
                "live_ratio_activation_threshold",
                bad,
                lambda b=bad: ExtractionLimits(live_ratio_activation_threshold=b),
            )
        )

    # A NaN compares false against everything and nothing exceeds an infinity, so
    # either one silently switches the ratio guard off. Only the float fields can
    # carry them.
    for bad in ("x", -1, True, float("nan"), float("inf"), float("-inf")):
        rows.append(
            _case(
                "ExtractionLimits",
                "max_ratio",
                bad,
                lambda b=bad: ExtractionLimits(max_ratio=b),
            )
        )

    # ``config=`` is checked at the entry points, but the object it names has fields of
    # its own, and those are read wherever they are needed rather than at the boundary.
    for bad in ("none", 0, ExtractionLimits, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "extraction_limits",
                bad,
                lambda b=bad: _with_config(archive, out(), extraction_limits=b),
            )
        )
    for bad in ("x", 0, ListingLimits, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "listing_limits",
                bad,
                lambda b=bad: _with_config(archive, out(), listing_limits=b),
            )
        )
    for bad in ("x", 0, DecoderLimits, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "decoder_limits",
                bad,
                lambda b=bad: _with_config(archive, out(), decoder_limits=b),
            )
        )
    for bad in ("x", 0, SpoolLimits, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "spool_limits",
                bad,
                lambda b=bad: _with_config(archive, out(), spool_limits=b),
            )
        )
    for bad in ("x", 0, DiagnosticPolicy, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "diagnostic_policy",
                bad,
                lambda b=bad: _with_config(archive, out(), diagnostic_policy=b),
            )
        )
    for bad in ("x", -1, True, 1.5, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "max_retained_diagnostic_references",
                bad,
                lambda b=bad: _with_config(
                    archive, out(), max_retained_diagnostic_references=b
                ),
            )
        )
    for bad in (0, "callback", []):
        rows.append(
            _case(
                "ArchiveyConfig",
                "on_diagnostic",
                bad,
                lambda b=bad: _with_config(archive, out(), on_diagnostic=b),
            )
        )
    # Guard switches: "false" is truthy, so a string would turn a refusal off.
    for field_name in (
        "rar_allow_glob_member_concatenation",
        "read_link_targets",
        "always_probe_content",
    ):
        for bad in ("false", 0, 1, None):
            rows.append(
                _case(
                    "ArchiveyConfig",
                    field_name,
                    bad,
                    lambda b=bad, f=field_name: _with_config(archive, out(), **{f: b}),
                )
            )
    for bad in ("not-a-codec", "rot13", b"cp437", 0, None):
        rows.append(
            _case(
                "ArchiveyConfig",
                "zip_unflagged_fallback_encoding",
                bad,
                lambda b=bad: _with_config(
                    archive, out(), zip_unflagged_fallback_encoding=b
                ),
            )
        )

    return rows


def _open_member(archive: Path, member: Any) -> Any:
    with open_archive(archive) as reader:
        return reader.open(member)


def _extract_all(archive: Path, dest: str | Path, members: Any, **kwargs: Any) -> Any:
    with open_archive(archive) as reader:
        return reader.extract_all(dest, members=members, **kwargs)


def _get_member(archive: Path, name: Any, *, by_member: bool = False) -> Any:
    with open_archive(archive) as reader:
        if by_member:
            name = reader.members()[0]
        return reader.get(name)


def _read_member(archive: Path, member: Any) -> Any:
    with open_archive(archive) as reader:
        return reader.read(member)


def _stream_members(archive: Path, members: Any, **kwargs: Any) -> Any:
    with open_archive(archive) as reader:
        # Do not wrap in list(): a check left inside the generator would still
        # raise on first next() and look like a call-time refusal.
        return reader.stream_members(members=members, **kwargs)


def _with_config(archive: Path, dest: Path, **field: Any) -> Any:
    """Build a config with one bad field and put it through a full extraction.

    Construction is where the refusal should happen, but the call is what proves it:
    every one of these fields used to survive construction and fail somewhere inside
    the extraction instead, naming a private attribute.
    """
    with open_archive(archive, config=ArchiveyConfig(**field)) as reader:
        return reader.extract_all(dest)


def test_no_raw_exception_escapes(archive: Path, tmp_path: Path) -> None:
    """Every wrong public argument fails inside the error contract."""
    dest = tmp_path / "out"
    dest.mkdir()

    offenders: list[str] = []
    for case in _cases(archive, dest):
        label, call = case.label, case.call
        lenient = case.argument in _ARCHIVE_ERROR_OK
        try:
            call()
        except ArchiveyUsageError as exc:
            # DR-15: a wrong argument is also the builtin a Python caller catches.
            if not isinstance(exc, (TypeError, ValueError)):
                offenders.append(
                    f"{label}: ArchiveyUsageError that is neither a TypeError nor "
                    f"a ValueError: {exc}"
                )
            elif case.empty_path and not (
                isinstance(exc, ValueError) and "empty path" in str(exc)
            ):
                offenders.append(
                    f"{label}: an empty path must be refused as a ValueError naming "
                    f"the empty path, got {type(exc).__name__}: {exc}"
                )
        except ArchiveyError as exc:
            # Only the source rows may answer this way, and only because a wrong-typed
            # source can also be a real one that fails to open (``b"PK\x03\x04"`` is a
            # truncated ZIP, not a type error). Everywhere else an ``ArchiveyError``
            # means the wrong argument was taken for archive data.
            if not lenient:
                offenders.append(
                    f"{label}: {type(exc).__name__} (want ArchiveyUsageError): {exc}"
                )
        except Exception as exc:  # noqa: BLE001 — the point is to catch everything
            offenders.append(f"{label}: raw {type(exc).__name__}: {exc}")
        else:
            offenders.append(f"{label}: no error at all")

    assert not offenders, "raw exceptions escaped the public API:\n" + "\n".join(
        offenders
    )


# Arguments the sweep deliberately does not cover, and why. Anything not listed here
# and not exercised by a row in :func:`_cases` fails
# :func:`test_every_public_argument_is_swept` — which is the half of this file that can
# notice an argument nobody thought about.
_NOT_SWEPT: dict[tuple[str, str], str] = {
    # ``format=`` is owned by ``internal/format_args``, which **coerces** it: a
    # recognised spelling becomes the ``ArchiveFormat``, and anything else raises
    # ``ArchiveyUsageError`` at the entry point, before a row here would ever see it.
    # Kept out of this table so the two do not drift into disagreeing about the answer;
    # ``tests/test_format_arguments.py`` asserts the behaviour. (``ArchiveFormat`` is a
    # plain class, not an enum — it is grouped with the enums by nobody but its
    # argument name.)
    ("open_archive", "format"): "coerced by format_args; test_format_arguments.py",
    ("open_stream", "format"): "coerced by format_args; test_format_arguments.py",
    # The enum-typed arguments, owned by ``internal/enum_args``, which **coerces**
    # them: a recognised spelling becomes the member, so a refusal here would
    # contradict it. ``tests/test_enum_arguments.py`` asserts what they do; this
    # module must not assert the opposite.
    #
    # These are guarded, and the coercion runs at the entry point, so a bad value
    # raises ``ArchiveyUsageError`` before reaching the code this table is about.
    # But read the exemption for what it is: it records that another module *owns*
    # the argument, never that the argument is safe today. Neither test above can
    # tell those apart, so a wrong exemption here is live rather than stale — the
    # blind spot left once ``test_not_swept_entries_are_all_live`` has done its half.
    # Measured on this tree rather than assumed: ``policy="looose"``,
    # ``overwrite=0``, ``on_error="halt"``, ``abort_on="blocked"`` and ``abort_on=0``
    # all answer ``ArchiveyUsageError``. Anything that turns out not to be covered
    # belongs in _cases, not here.
    ("extract_all", "policy"): "coerced by enum_args; test_enum_arguments.py",
    ("extract_all", "overwrite"): "coerced by enum_args; test_enum_arguments.py",
    ("extract_all", "on_error"): "coerced by enum_args; test_enum_arguments.py",
    # Collection[AbortOn], not an enum, so the container shape is a second way to get
    # it wrong. ``coerce_enum_collection`` refuses both: a bare string, which would
    # otherwise iterate into characters and silently disable every abort, and a
    # non-iterable, which would otherwise be a raw TypeError.
    ("extract_all", "abort_on"): (
        "Collection[AbortOn]; container-shape refusal is coerce_enum_collection "
        "in enum_args"
    ),
    ("ArchiveyConfig", "use_rapidgzip"): "coerced by enum_args, in __post_init__",
    ("ArchiveyConfig", "rar_decompressor"): "coerced by enum_args, in __post_init__",
    ("ArchiveyConfig", "process_isolation"): "coerced by enum_args, in __post_init__",
    (
        "ArchiveyConfig",
        "use_indexed_bzip2",
    ): "coerced by enum_args, in __post_init__",
    # Flags read for their truthiness. There is no wrong type to find: every value
    # means something, and ``streaming="no"`` opening in streaming mode is Python
    # behaving as written, not a leak.
    ("open_archive", "streaming"): "truthiness flag",
    ("open_archive", "seekable_members"): "truthiness flag",
    ("open_archive", "concurrent_operations"): "truthiness flag",
    ("open_stream", "seekable"): "truthiness flag",
    ("detect_format", "follow_stub_volumes"): "truthiness flag",
    ("extract_all", "dry_run"): "truthiness flag",
    # ``get`` answers an absent *name* with the default, like ``dict.get``. A value
    # that is not a name at all is swept above: ``get(b"h.txt")`` used to answer
    # "absent" for a member that exists, which is a wrong answer, not a lookup miss.
    ("get", "default"): "any object is a valid default",
}


def _public_surface() -> list[tuple[str, list[str]]]:
    """(name, argument names) for every public entry point this file is about."""
    surface: list[tuple[str, list[str]]] = []
    for func in (open_archive, open_stream, detect_format):
        surface.append((func.__name__, list(inspect.signature(func).parameters)))
    for method in ("open", "read", "extract_all", "stream_members", "get"):
        names = list(inspect.signature(getattr(ArchiveReader, method)).parameters)
        surface.append((method, [n for n in names if n != "self"]))
    for cls in (
        ArchiveyConfig,
        DecoderLimits,
        DetectionBudget,
        ExtractionLimits,
        ListingLimits,
        SpoolLimits,
    ):
        surface.append((cls.__name__, [f.name for f in dataclasses.fields(cls)]))
    return surface


def test_every_public_argument_is_swept(archive: Path, tmp_path: Path) -> None:
    """A public argument added without a row fails here.

    This is the half of the file that can fail for something *absent*.
    :func:`test_no_raw_exception_escapes` only ever checks the rows it was given, so on
    its own it goes quiet exactly when a new argument arrives unguarded — the failure
    mode of every "we swept it once" claim in this repo. Reading the signatures back
    means the table has to keep up with the API or say in :data:`_NOT_SWEPT` why not.
    """
    dest = tmp_path / "covered"
    dest.mkdir()
    swept = {(case.entry, case.argument) for case in _cases(archive, dest)}

    missing: list[str] = []
    for name, arguments in _public_surface():
        for argument in arguments:
            if (name, argument) in swept or (name, argument) in _NOT_SWEPT:
                continue
            missing.append(f"{name}({argument}=…)")

    assert not missing, (
        "public arguments with no row in _cases() and no entry in _NOT_SWEPT:\n"
        + "\n".join(missing)
    )


def test_every_path_argument_has_an_empty_row(archive: Path, tmp_path: Path) -> None:
    """Every swept path argument also has an empty-string row.

    :func:`test_every_public_argument_is_swept` keys on (entry, argument), so a path
    argument with only a wrong-type row satisfies it. This derives the empty-string
    requirement from the rows themselves, so a new path argument added without that
    row fails here.
    """
    dest = tmp_path / "covered"
    dest.mkdir()
    cases = _cases(archive, dest)
    path_rows = {(c.entry, c.argument) for c in cases if c.argument in _PATH_ARGUMENTS}
    empty_rows = {(c.entry, c.argument) for c in cases if c.empty_path}

    missing = sorted(path_rows - empty_rows)
    assert not missing, "path arguments with no empty-string row:\n" + "\n".join(
        f"{entry}({argument}=…)" for entry, argument in missing
    )


def test_not_swept_entries_are_all_live(archive: Path, tmp_path: Path) -> None:
    """:data:`_NOT_SWEPT` does not outlive the arguments it excuses.

    An exemption for an argument that no longer exists is how an exclusion list turns
    into a place to hide one: the name stays, a real argument is added with it later,
    and nothing notices. An exemption for an argument that *is* swept is the same rot
    from the other end — it reads as a decision not to check something this file does
    check, so a later reader trusts the wrong half.
    """
    dest = tmp_path / "live"
    dest.mkdir()
    swept = {(case.entry, case.argument) for case in _cases(archive, dest)}
    live = {
        (name, argument)
        for name, arguments in _public_surface()
        for argument in arguments
    }
    stale = sorted(
        f"{name}({argument}=…)"
        for name, argument in _NOT_SWEPT
        if (name, argument) not in live
    )
    assert not stale, "_NOT_SWEPT names arguments that no longer exist:\n" + "\n".join(
        stale
    )

    contradicted = sorted(
        f"{name}({argument}=…)"
        for name, argument in _NOT_SWEPT
        if (name, argument) in swept
    )
    assert not contradicted, (
        "_NOT_SWEPT excuses arguments that _cases() does sweep:\n"
        + "\n".join(contradicted)
    )


def test_no_usage_error_message_names_a_private_attribute(
    archive: Path, tmp_path: Path
) -> None:
    """A refusal explains the argument; it never leaks an internal field name.

    Every case in the sweep failed this way before the boundary checks existed
    (``'str' object has no attribute 'max_extracted_bytes'``), and the message is
    what makes the difference between a refusal and a crash.
    """
    dest = tmp_path / "out2"
    dest.mkdir()

    leaks: list[str] = []
    for case in _cases(archive, dest):
        label, call = case.label, case.call
        try:
            call()
        except Exception as exc:  # noqa: BLE001 — inspecting whatever comes back
            message = str(exc)
            if "has no attribute" in message or "_archive_id" in message:
                leaks.append(f"{label}: {message}")

    assert not leaks, "usage errors named a private attribute:\n" + "\n".join(leaks)


def test_valid_arguments_still_work(archive: Path, tmp_path: Path) -> None:
    """The guards refuse only what they are meant to refuse."""
    dest = tmp_path / "ok"
    dest.mkdir()

    assert detect_format(archive).format.container.name == "ZIP"
    for budget in (DetectionBudgetPreset.BALANCED, BALANCED_BUDGET):
        config = ArchiveyConfig(detection_budget=budget)
        assert detect_format(archive, config=config).format.container.name == "ZIP"
    with open_archive(archive, config=ArchiveyConfig()) as reader:
        assert reader.extract_all(dest / "a").results
    with open_archive(archive, encoding="UTF8") as reader:  # an alias, not a name
        assert reader.extract_all(dest / "c").results
    with open_archive(archive) as reader:
        assert reader.extract_all(dest / "b", limits=ExtractionLimits.UNLIMITED).results
    with open_archive(archive) as reader:
        assert reader.extract_all(dest / "d", on_progress=lambda _p: None).results

    with open_archive(archive) as reader:
        members = list(reader)
        assert reader.open("h.txt").read() == b"hi"
        assert reader.open(members[0]) is not None
        report = reader.extract_all(dest / "e", members=["h.txt"])
        assert [r.member.name for r in report.results] == ["h.txt"]
        report = reader.extract_all(dest / "f", members=members[:1])
        assert len(report.results) == 1

    assert ListingLimits(max_members=None) == ListingLimits(max_members=None)
    assert ExtractionLimits(max_ratio=2.5).max_ratio == 2.5


def test_unknown_member_name_still_raises_keyerror(archive: Path) -> None:
    """``KeyError`` for an absent name is specified, and the member guard keeps it.

    The guard added for a wrong-typed member sits on the other branch; a string that
    names nothing must still behave like a mapping lookup (``archive-reading``).
    """
    with open_archive(archive) as reader, pytest.raises(KeyError):
        reader.open("nope.txt")


def test_get_refuses_a_bytes_name_and_keeps_the_default_for_an_absent_one(
    archive: Path,
) -> None:
    """``get(b"h.txt")`` used to return ``None`` although ``h.txt`` exists.

    The refusal is for the wrong type only: an absent ``str`` name still answers with
    the default, like ``dict.get``.
    """
    sentinel = object()
    with open_archive(archive) as reader:
        with pytest.raises(ArchiveyUsageError, match=r"b'h\.txt' \(bytes\)"):
            reader.get(b"h.txt")  # type: ignore[arg-type]
        assert reader.get("nope.txt") is None
        assert reader.get("nope.txt", sentinel) is sentinel  # type: ignore[arg-type]
        found = reader.get("h.txt")
        assert found is not None and found.name == "h.txt"


def test_extract_all_wrong_typed_members_does_not_create_dest(
    archive: Path, tmp_path: Path
) -> None:
    """A members= refusal must not have already created dest (K3)."""
    dest = tmp_path / "should_not_exist"
    with open_archive(archive) as reader, pytest.raises(ArchiveyUsageError):
        reader.extract_all(dest, members=0)
    assert not dest.exists()


def test_stream_members_wrong_typed_members_raises_at_the_call(archive: Path) -> None:
    """stream_members(members=0) must refuse before returning a generator (K3)."""
    with open_archive(archive) as reader, pytest.raises(ArchiveyUsageError):
        reader.stream_members(members=0)


def test_members_bytes_message_does_not_advise_wrapping(
    archive: Path, tmp_path: Path
) -> None:
    """Pass [b'notes.txt'] is itself a usage error; do not suggest it (K4)."""
    dest = tmp_path / "b"
    with open_archive(archive) as reader, pytest.raises(ArchiveyUsageError) as caught:
        reader.extract_all(dest, members=b"notes.txt")
    assert "Pass [" not in str(caught.value)


def _as_any(value: object) -> Any:
    """Hand a deliberately wrong-typed value to a typed parameter, as an untyped caller would."""
    return value


def test_class_passed_for_a_field_suggests_calling_it() -> None:
    """``extraction_limits=ExtractionLimits`` (unparenthesised) is named back with the fix."""
    with pytest.raises(
        ArchiveyUsageError, match=r"did you mean ExtractionLimits\(\)\?"
    ):
        ArchiveyConfig(extraction_limits=_as_any(ExtractionLimits))


def test_class_of_the_wrong_kind_gets_no_constructor_hint() -> None:
    """Calling the wrong class would only trade one usage error for another."""
    with pytest.raises(ArchiveyUsageError) as info:
        ArchiveyConfig(extraction_limits=_as_any(ListingLimits))
    message = str(info.value)
    assert "the ListingLimits class itself" in message
    assert "did you mean" not in message


def _closed_reader_members(archive: Path) -> Any:
    reader = open_archive(archive)
    reader.close()
    return reader.members()


class _BytesPath:
    """A path-like whose ``__fspath__`` returns bytes, as ``os`` and ``shutil`` accept."""

    def __fspath__(self) -> bytes:
        return b"/nonexistent-archivey-dest"


class _EmptyStrPath:
    """A path-like whose ``__fspath__`` returns ``""``, which ``Path()`` reads as ``"."``."""

    def __fspath__(self) -> str:
        return ""


def _a_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "a-directory"
    directory.mkdir(exist_ok=True)
    return directory


def _parts_of_two_sets(tmp_path: Path) -> list[Path]:
    parts = [tmp_path / "alpha.zip.001", tmp_path / "beta.zip.002"]
    for part in parts:
        part.write_bytes(b"PK")
    return parts


def _foreign_member(archive: Path, tmp_path: Path) -> Any:
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("h.txt", "other")
    with open_archive(other) as reader:
        foreign = reader.members()[0]
    return _open_member(archive, foreign)


# (label, call, the builtin the error must also be). One row per boundary helper and
# per entry point, not the sweep: that is :func:`test_no_raw_exception_escapes`.
_BUILTIN_CASES: list[tuple[str, Callable[[Path, Path], Any], type[Exception]]] = [
    ("open_archive(0)", lambda a, t: open_archive(0), TypeError),
    ("open_archive(StringIO)", lambda a, t: open_archive(io.StringIO("x")), TypeError),
    ("open_archive([])", lambda a, t: open_archive([]), ValueError),
    ("open_stream(0)", lambda a, t: open_stream(0), TypeError),
    ("detect_format(0)", lambda a, t: detect_format(0), TypeError),
    (
        "open_archive(config='strict')",
        lambda a, t: open_archive(a, config="strict"),
        TypeError,
    ),
    ("open_archive(password=0)", lambda a, t: open_archive(a, password=0), TypeError),
    ("open_archive(encoding=0)", lambda a, t: open_archive(a, encoding=0), TypeError),
    (
        "open_archive(encoding='rot13')",
        lambda a, t: open_archive(a, encoding="rot13"),
        ValueError,
    ),
    (
        "open_archive(format='nonsense')",
        lambda a, t: open_archive(a, format="nonsense"),
        ValueError,
    ),
    ("open_archive(format=0)", lambda a, t: open_archive(a, format=0), TypeError),
    (
        "open_stream(format='zip')",
        lambda a, t: open_stream(a, format="zip"),
        ValueError,
    ),
    (
        "open_archive(streaming=True, concurrent_operations=True)",
        lambda a, t: open_archive(a, streaming=True, concurrent_operations=True),
        ValueError,
    ),
    (
        "ListingLimits(max_members='x')",
        lambda a, t: ListingLimits(max_members="x"),
        TypeError,
    ),
    (
        "ListingLimits(max_members=-1)",
        lambda a, t: ListingLimits(max_members=-1),
        ValueError,
    ),
    (
        "ExtractionLimits(max_ratio=nan)",
        lambda a, t: ExtractionLimits(max_ratio=float("nan")),
        ValueError,
    ),
    (
        "ArchiveyConfig(use_rapidgzip='sometimes')",
        lambda a, t: ArchiveyConfig(use_rapidgzip="sometimes"),
        ValueError,
    ),
    (
        "DiagnosticPolicy(ignore=0)",
        lambda a, t: DiagnosticPolicy(ignore=0),  # type: ignore[arg-type]
        TypeError,
    ),
    ("extract_all(0)", lambda a, t: _extract_all(a, 0, None), TypeError),
    (
        "extract_all(overwrite='nonsense')",
        lambda a, t: _extract_all(a, t / "o1", None, overwrite="nonsense"),
        ValueError,
    ),
    (
        "extract_all(abort_on='blocked_member')",
        lambda a, t: _extract_all(a, t / "o2", None, abort_on="blocked_member"),
        TypeError,
    ),
    (
        "extract_all(members='h.txt')",
        lambda a, t: _extract_all(a, t / "o3", "h.txt"),
        TypeError,
    ),
    (
        "extract_all(filter returning 0)",
        lambda a, t: _extract_all(a, t / "o4", None, filter=lambda m: 0),
        TypeError,
    ),
    (
        "stream_members(file_copy_streams='no')",
        lambda a, t: _stream_members(a, None, file_copy_streams="no"),
        TypeError,
    ),
    ("reader.open(0)", lambda a, t: _open_member(a, 0), TypeError),
    ("reader.open(foreign member)", _foreign_member, ValueError),
    # A path-like around bytes: ``Path()`` would raise "argument should be a str or an
    # os.PathLike object where __fspath__ returns a str", naming nothing of ours.
    (
        "extract_all(bytes path-like)",
        lambda a, t: _extract_all(a, _BytesPath(), None),
        TypeError,
    ),
    # A mapping iterates as its keys, so the removed ``{code: disposition}`` shape
    # would drop every disposition; it is refused as the wrong type.
    (
        "DiagnosticPolicy(ignore={code: 'raise'})",
        lambda a, t: DiagnosticPolicy(ignore={"archive_trailing_data": "raise"}),  # type: ignore[arg-type]
        TypeError,
    ),
    (
        "DiagnosticPolicy(ignore=x, raise_on=x)",
        lambda a, t: DiagnosticPolicy(
            ignore=["archive_trailing_data"], raise_on=["archive_trailing_data"]
        ),
        ValueError,
    ),
    # Refusals made after looking at what an argument names are value errors too: the
    # argument is a usable type and the call refuses its value (DR-15).
    (
        "open_stream(directory)",
        lambda a, t: open_stream(_a_directory(t)),
        ValueError,
    ),
    (
        "open_archive(directory, format=ZIP)",
        lambda a, t: open_archive(_a_directory(t), format=ArchiveFormat.ZIP),
        ValueError,
    ),
    (
        "open_archive(parts of two sets)",
        lambda a, t: open_archive(_parts_of_two_sets(t)),
        ValueError,
    ),
    (
        "open_archive(file, format=DIRECTORY)",
        lambda a, t: open_archive(a, format=ArchiveFormat.DIRECTORY),
        ValueError,
    ),
    (
        "open_archive(format=UNKNOWN)",
        lambda a, t: open_archive(a, format=ArchiveFormat.UNKNOWN),
        ValueError,
    ),
    ("reader.get(bytes)", lambda a, t: _get_member(a, b"h.txt"), TypeError),
    ("reader.get(0)", lambda a, t: _get_member(a, 0), TypeError),
    # An empty string is a usable type whose value is refused: it would name the
    # current directory.
    ("open_archive('')", lambda a, t: open_archive(""), ValueError),
    ("extract_all('')", lambda a, t: _extract_all(a, "", None), ValueError),
    # The empty check runs on what ``__fspath__`` returns, not on the wrapper object.
    (
        "extract_all(empty path-like)",
        lambda a, t: _extract_all(a, _EmptyStrPath(), None),
        ValueError,
    ),
]


@pytest.mark.parametrize(
    ("call", "builtin"),
    [pytest.param(call, builtin, id=label) for label, call, builtin in _BUILTIN_CASES],
)
def test_wrong_argument_is_caught_by_the_builtin_and_the_usage_error(
    archive: Path,
    tmp_path: Path,
    call: Callable[[Path, Path], Any],
    builtin: type[Exception],
) -> None:
    """DR-15: ``except TypeError`` / ``except ValueError`` and
    ``except ArchiveyUsageError`` each catch a wrong argument; ``except ArchiveyError``
    does not."""
    with pytest.raises(builtin) as caught:
        call(archive, tmp_path)
    assert isinstance(caught.value, ArchiveyUsageError)
    assert not isinstance(caught.value, ArchiveyError)
    # Exactly one of the two: a wrong type is not also a bad value.
    other = ValueError if builtin is TypeError else TypeError
    assert not isinstance(caught.value, other)


def test_misuse_that_is_not_an_argument_stays_a_plain_usage_error(
    archive: Path,
) -> None:
    """A closed reader is a usage error, but not a ``TypeError`` or ``ValueError``."""
    with pytest.raises(ArchiveyUsageError) as caught:
        _closed_reader_members(archive)
    assert not isinstance(caught.value, (TypeError, ValueError))


def test_argument_error_classes_are_not_public() -> None:
    """The two subclasses are private: no new public name (DR-15 ruling, 2026-10-10)."""
    import archivey
    from archivey import exceptions

    for name in ("_UsageTypeError", "_UsageValueError"):
        assert not hasattr(archivey, name)
        assert name not in archivey.__all__
        assert issubclass(getattr(exceptions, name), ArchiveyUsageError)


def test_empty_string_path_is_refused(
    archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty string is a wrong argument, not the current directory.

    The sweep proves each empty-path row raises within the contract; this proves the
    working directory is left alone. ``Path("")`` is ``Path(".")``, so an empty string
    (an unset environment variable, typically) used to open the working directory as a
    directory archive, or extract into it.
    """
    dest = tmp_path / "out"
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "precious.txt").write_text("keep")
    monkeypatch.chdir(cwd)

    rows = [case for case in _cases(archive, dest) if case.empty_path]
    assert rows
    for case in rows:
        with pytest.raises(ValueError, match="empty path") as caught:
            case.call()
        assert isinstance(caught.value, ArchiveyUsageError)
    assert sorted(p.name for p in cwd.iterdir()) == ["precious.txt"]


def test_max_ppmd_in_process_input_kwarg_is_gone() -> None:
    """``max_ppmd_in_process_input`` became ``max_ppmd_held_input`` with no alias.

    Python rejects unknown kwargs on its own; this locks the removal, so accepting the
    old spelling again has to delete this test.
    """
    with pytest.raises(TypeError, match="max_ppmd_in_process_input"):
        DecoderLimits(max_ppmd_in_process_input=1)  # type: ignore[call-arg]
