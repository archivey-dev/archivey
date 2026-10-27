"""Escaping of attacker-controlled text, and the escape-exactly-once rule around it.

Assertions here are on *behaviour* — inertness, round-trip distinctions, absence of
doubling — rather than on golden strings, because the rendering of an individual escape
is delegated to ``repr`` and is not a documented CPython guarantee.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re

import pytest

from archivey.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    MemberNameControlsContext,
)
from archivey.exceptions import ArchiveyError, ExtractionError, raw_message_of
from archivey.terminal import escape_control_chars, quoted

# Characters that must never survive into a terminal unescaped.
_DANGEROUS = ("\x1b", "\r", "\n", "\x00", "\x9b")


@pytest.mark.parametrize(
    "text",
    [
        "\x1b[2K\r",  # the line-erase spoof
        "\x00",
        "\x7f",
        "\x9b",  # C1 CSI — a single-character ESC[
        "\xa0",
        "\u202e",  # RLO
        "\u200b",
        "\ud800",  # lone high surrogate
        "\U0001d173",  # astral non-printable
        # surrogateescape of byte 0x80. Not a duplicate of "\ud800": ruff compares lone
        # surrogates lossily.
        "\udc80",  # noqa: PT014
    ],
)
def test_dangerous_characters_do_not_survive(text: str) -> None:
    out = escape_control_chars(text)
    assert not any(ch in out for ch in _DANGEROUS)
    assert out.isprintable()


@pytest.mark.parametrize("text", ["café", "日本語.txt", "dir/file.txt", "", "a b"])
def test_printable_text_is_unchanged(text: str) -> None:
    """Ordinary names — including non-ASCII ones — must stay readable.

    This is what rules out ``ascii()`` and the ``unicode_escape`` codec, which mangle
    every non-ASCII character.
    """
    assert escape_control_chars(text) == text


def test_astral_code_points_render_as_a_readable_escape() -> None:
    """A 5-hex-digit ``\\uXXXXX`` would read back as a 4-digit escape plus a stray digit."""
    out = escape_control_chars("x\U0001d173y")
    assert out.startswith("x") and out.endswith("y")
    body = out[1:-1]
    assert body.startswith("\\U")
    # Recoverable: the escape names the code point it replaced.
    assert int(body[2:], 16) == 0x1D173  # noqa: FURB166 - the prefix is \\U, not 0x


def test_literal_backslash_is_distinguishable_from_a_real_control_char() -> None:
    """The reason backslash is escaped at all."""
    assert escape_control_chars("a\\nb") != escape_control_chars("a\nb")


def test_surrogateescaped_bytes_show_the_underlying_octet() -> None:
    """A name decoded with ``surrogateescape`` never contained U+DC80; it contained 0x80."""
    assert escape_control_chars("\udc80") == "\\x80"
    # …and a backslash before one is not mistaken for part of the escape.
    assert escape_control_chars("literal\\\udc80text") == "literal\\\\\\x80text"


@pytest.mark.parametrize("cp", [0xDC00, 0xDC7F, 0xDD00, 0xDFFF])
def test_lone_surrogates_outside_the_escape_range_are_not_reinterpreted(
    cp: int,
) -> None:
    """``surrogateescape`` only produces U+DC80–U+DCFF.

    A surrogate arriving by any other route is not a byte, and reversing it into one
    would report a character the name never contained.
    """
    out = escape_control_chars(chr(cp))
    assert out != f"\\x{cp & 0xFF:02x}"
    assert out.isprintable()


# --- escape exactly once, at the outermost message ---------------------------------


def test_message_escapes_archive_derived_text() -> None:
    exc = ExtractionError("Destination exists: /out/ev\x1b[2Kil\rSPOOF.txt")
    assert "\x1b" not in exc.message
    assert "\x1b" not in str(exc)
    assert "\x1b" not in repr(exc)
    assert "\\x1b[2K" in exc.message


def test_structured_fields_stay_raw() -> None:
    name = "ev\x1b[2Kil.txt"
    exc = ExtractionError("boom", member_name=name)
    assert exc.member_name == name  # data, for acting on
    assert "\x1b" not in str(exc)  # display, rendered through !r


def test_quoted_does_not_escape_so_the_message_escapes_once() -> None:
    """``{name!r}`` would escape first, and the message escape would double it."""
    name = "ev\x1b[2Kil.txt"
    via_quoted = ExtractionError(f"Blocked: {quoted(name)}").message
    via_repr = ExtractionError(f"Blocked: {name!r}").message
    assert "\\x1b" in via_quoted and "\\\\x1b" not in via_quoted
    assert "\\\\x1b" in via_repr  # the doubling quoted() exists to avoid


def test_raw_message_of_avoids_doubling_when_wrapping() -> None:
    inner = ExtractionError("bad: /out/ev\x1b[2Kil.txt")
    wrapped = ExtractionError(f"context: {raw_message_of(inner)}").message
    naive = ExtractionError(f"context: {inner.message}").message
    assert "\\x1b" in wrapped and "\\\\x1b" not in wrapped
    assert "\\\\x1b" in naive


def test_raw_message_of_passes_foreign_exceptions_through() -> None:
    """A third-party exception was never escaped, so its text is already raw."""
    assert raw_message_of(ValueError("plain")) == "plain"


def test_diagnostic_message_is_escaped_and_context_is_raw() -> None:
    name = "ev\x1b[2Kil.txt"
    d = Diagnostic(
        occurrence_id="1",
        code=DiagnosticCode.MEMBER_NAME_BIDI_CONTROL,
        message=f"Member name has controls: {quoted(name)}",
        context=MemberNameControlsContext(member_name=name),
    )
    assert "\x1b" not in d.message
    assert "\\\\x1b" not in d.message  # escaped once, not twice
    assert d.context.member_name == name
    assert d.to_dict()["message"] == d.message


# --- the rule holds for future call sites too --------------------------------------

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "archivey"
_ESCAPING_CALL = re.compile(r"Error$|^emit$|Issue$")
# Builtins escape nothing, so ``!r`` is the safe form in their messages.
_FOREIGN = {
    "FileNotFoundError",
    "KeyError",
    "TypeError",
    "ValueError",
    "OSError",
    "AttributeError",
}
_ARCHIVE_WORDS = {
    "name",
    "filename",
    "path",
    "member",
    "entry",
    "target",
    "directory",
    "dest",
    "link",
}


# Modules whose "names" are archivey's own vocabulary, not the archive's.
# ``reader_state`` is the concurrency state machine: its ``name`` is an
# ``OperationToken.name`` — an API operation such as ``"members"`` or ``"open"`` — so
# ``!r`` there is correct and ``quoted()`` would be actively misleading.
#
# Keys are POSIX-spelled, and the scans below compare against ``as_posix()``: comparing
# against ``str(path)`` matched nothing on Windows, where the separator is a backslash.
_NON_ARCHIVE_MODULES = {"internal/reader_state.py"}


def test_module_exemptions_name_real_files() -> None:
    """An exemption that matches nothing is worse than none — it looks like coverage.

    A misspelling, a moved module, or a platform separator mismatch would all silently
    re-arm the checks below rather than failing here.
    """
    for module in _NON_ARCHIVE_MODULES:
        assert (_SRC / module).is_file(), module


def _is_archive_derived(expr: str, module: str) -> bool:
    """Does this interpolated expression carry archive-controlled text?

    Splits on non-letters rather than matching with ``\\b``: an underscore is a *word*
    character, so ``\\bmember\\b`` does not match inside ``member_name`` — which is how
    five sites and two whole files slipped past the first version of this check.

    The exemptions are deliberately narrow and named. This is a spelling heuristic: it
    cannot tell an operation name from a member name, so anything it lets through has
    to be justified here rather than by loosening the word list.
    """
    if module in _NON_ARCHIVE_MODULES:
        return False
    if expr.endswith(".value"):
        return False  # an enum member's value, e.g. member.type.value
    return any(tok.lower() in _ARCHIVE_WORDS for tok in re.split(r"[^A-Za-z]+", expr))


def test_no_message_site_interpolates_an_archive_derived_name_with_repr() -> None:
    """``!r`` inside a self-escaping message double-escapes; ``quoted()`` is the form.

    A static check rather than a runtime one: the failure it guards against is cosmetic
    per-site and would otherwise only be noticed for a hostile archive.
    """
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = (
                getattr(node.func, "id", None) or getattr(node.func, "attr", None) or ""
            )
            if fname in _FOREIGN or not _ESCAPING_CALL.search(fname):
                continue
            targets = list(node.args[:1]) + [
                k.value for k in node.keywords if k.arg == "message"
            ]
            for target in targets:
                if not isinstance(target, ast.JoinedStr):
                    continue
                for value in target.values:
                    if (
                        isinstance(value, ast.FormattedValue)
                        and value.conversion == ord("r")
                        and _is_archive_derived(
                            ast.unparse(value.value), path.relative_to(_SRC).as_posix()
                        )
                        # A caught exception's !r is a different rule, checked by
                        # test_no_message_shows_a_caught_exception_as_its_repr.
                        and not _is_exception_named(ast.unparse(value.value))
                    ):
                        offenders.append(
                            f"{path.relative_to(_SRC).as_posix()}:{node.lineno} "
                            f"{{{ast.unparse(value.value)}!r}} in {fname}(...)"
                        )
    assert not offenders, (
        "use quoted() instead of !r for archive-derived text in a self-escaping "
        "message:\n  " + "\n  ".join(offenders)
    )


_EXCEPTION_WORDS = {"e", "exc", "err", "error", "cause", "caused", "fault", "exception"}

# Sites that may still show a caught exception as its repr, keyed by
# (module, enclosing function, interpolated expression) so a moved line keeps its entry.
_EXCEPTION_REPR_ALLOWED: set[tuple[str, str, str]] = set()


def _is_exception_named(expr: str) -> bool:
    return any(tok.lower() in _EXCEPTION_WORDS for tok in re.split(r"[^A-Za-z]+", expr))


def _exception_repr_sites() -> set[tuple[str, str, str]]:
    """Every f-string ``{x!r}`` in ``src/archivey`` whose ``x`` is named like a caught
    exception, keyed as in ``_EXCEPTION_REPR_ALLOWED``.

    Every f-string, not only those passed to an exception: a message is often built in
    a variable or a tuple first (``rapidgzip_child``'s ``_death``). That is
    deliberately wider than the message sites: a ``logger.*`` f-string that needs the
    repr (log records are not escaped) goes in the allowlist."""
    found: set[tuple[str, str, str]] = set()

    def walk(node: ast.AST, module: str, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, module, child.name)
                continue
            if (
                isinstance(child, ast.FormattedValue)
                and child.conversion == ord("r")
                and _is_exception_named(ast.unparse(child.value))
            ):
                found.add((module, function, ast.unparse(child.value)))
            walk(child, module, function)

    for path in sorted(_SRC.rglob("*.py")):
        walk(
            ast.parse(path.read_text(encoding="utf-8")),
            path.relative_to(_SRC).as_posix(),
            "<module>",
        )
    return found


def test_no_message_shows_a_caught_exception_as_its_repr() -> None:
    """``{exc!r}`` shows Python's spelling of an error (``error('unpack_from …')``),
    not what is wrong with the archive, and doubles the escape of one of ours.
    ``exception_detail(exc)`` is the form (the rule in ``ArchiveyError``'s docstring).
    """
    offenders = _exception_repr_sites() - _EXCEPTION_REPR_ALLOWED
    assert not offenders, (
        "use exception_detail(exc) instead of {exc!r} in a message:\n  "
        + "\n  ".join(f"{m} {f}(): {{{e}!r}}" for m, f, e in sorted(offenders))
    )


def test_exception_repr_allowlist_names_real_sites() -> None:
    """An allowlist entry that matches nothing hides the day its site is fixed or
    moved; drop it then, so it cannot excuse a new site under the same name."""
    stale = _EXCEPTION_REPR_ALLOWED - _exception_repr_sites()
    assert not stale, f"no such {{x!r}} site any more: {sorted(stale)}"


def test_library_log_sites_still_escape_interpolated_names() -> None:
    """The mirror-image rule: the CLI does *not* escape log records.

    ``%r`` is what makes a name interpolated into a log record inert, so these call
    sites must keep it — the opposite of the message rule above.
    """
    bad: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        if "cli" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in {"debug", "info", "warning", "error", "exception"}
            ):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            fmt = str(node.args[0].value)
            for spec, arg in zip(re.findall(r"%[sr]", fmt), node.args[1:]):
                if spec == "%s" and _is_archive_derived(
                    ast.unparse(arg), path.relative_to(_SRC).as_posix()
                ):
                    bad.append(
                        f"{path.relative_to(_SRC).as_posix()}:{node.lineno} {fmt!r}"
                    )
    assert not bad, (
        "interpolate names into log records with %r, not %s:\n  " + "\n  ".join(bad)
    )


def test_uncaught_exception_message_is_inert() -> None:
    """No display site is involved on this path — the interpreter renders it."""
    exc = ArchiveyError("boom: /out/ev\x1b[2Kil\rSPOOF.txt")
    rendered = f"{type(exc).__name__}: {exc}"
    assert not any(ch in rendered for ch in _DANGEROUS)


def test_paths_in_messages_do_not_double_their_separators() -> None:
    """A native path would have every separator doubled by the backslash escape.

    Rendering ``/``-separated first leaves the escape nothing to double. Building the
    path with ``/`` rather than a literal makes this meaningful on both platforms: it
    is ``out\\sub\\a.txt`` on Windows and ``out/sub/a.txt`` here, and the assertion is
    the same either way.
    """
    from pathlib import Path

    from archivey.terminal import display_path

    nested = Path("out") / "sub" / "a.txt"
    assert display_path(nested) == "out/sub/a.txt"
    assert "\\" not in ExtractionError(f"Destination: {display_path(nested)}").message


def test_display_path_uses_the_native_flavour_so_names_keep_their_backslashes() -> None:
    """A backslash is a legal filename character on POSIX, and must stay escaped.

    ``display_path`` converts *separators*, which means using the running platform's
    path flavour. Rewriting every backslash unconditionally would corrupt a legitimate
    POSIX member named ``a\\b`` into a two-segment path — turning a display fix into a
    correctness bug, and hiding exactly the character the escaping exists to show.
    """
    from archivey.terminal import display_path

    if os.sep == "/":
        rendered = display_path("a\\b")
        assert rendered == "a\\b"
        assert "\\\\" in ExtractionError(f"Blocked: {rendered}").message


def test_open_site_location_is_posix_rendered() -> None:
    """The breadcrumb exists to be pasted back; doubled separators defeat that."""
    from archivey.internal.open_site import OpenSite

    assert OpenSite(filename="/src/app.py", lineno=12).location == "/src/app.py:12"


def test_no_message_site_rewraps_an_already_escaped_message() -> None:
    """``SomeError(exc.message)`` re-escapes text that was escaped once already.

    Not an f-string, so the interpolation guards above never see it — this pattern is
    how two sites (`zip_reader`, `sevenzip_reader`) kept doubling after the first sweep.
    ``raw_message_of(exc)`` is the form.
    """
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            fname = (
                getattr(node.func, "id", None) or getattr(node.func, "attr", None) or ""
            )
            if fname in _FOREIGN or not _ESCAPING_CALL.search(fname):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Attribute) and arg.attr == "message":
                offenders.append(
                    f"{path.relative_to(_SRC).as_posix()}:{node.lineno} "
                    f"{fname}({ast.unparse(arg)})"
                )
    assert not offenders, (
        "use raw_message_of(exc) — passing an escaped .message into a new message "
        "escapes it twice:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("plain.txt", "'plain.txt'"),
        ("it's.txt", '"it\'s.txt"'),  # switch, rather than escape
        ('say "hi".txt', "'say \"hi\".txt'"),
        ("", "''"),
    ],
)
def test_quoted_chooses_a_delimiter_that_does_not_appear_inside(
    name: str, expected: str
) -> None:
    """Escaping the quote would write a backslash for the message escape to double."""
    assert quoted(name) == expected


def test_quoted_never_introduces_a_backslash() -> None:
    """The escape-once property: quoted() must add delimiters and nothing else.

    Checked against a name containing both quote characters — the ambiguous fallback —
    because that is where an implementation would be tempted to escape.
    """
    both = "a'b\"c"
    assert "\\" not in quoted(both)
    assert "\\\\" not in ExtractionError(f"Blocked: {quoted(both)}").message


def test_link_target_is_a_structured_field_not_message_text() -> None:
    """Six two-name messages became prose; the target renders once, escaped, in __str__."""
    from archivey.exceptions import FilterRejectionError

    exc = FilterRejectionError(
        "Symlink target escapes destination",
        member_name="ev\x1b[2Kil",
        link_target="../etc/pa\x1b[2Ksswd",
    )
    assert exc.link_target == "../etc/pa\x1b[2Ksswd"  # raw, for acting on
    rendered = str(exc)
    assert "\x1b" not in rendered
    assert "target=" in rendered and "member=" in rendered
    assert "\\\\x1b" not in rendered  # escaped once


def test_names_are_not_rendered_twice() -> None:
    """The message no longer repeats what member= already shows."""
    from archivey.exceptions import FilterRejectionError

    rendered = str(
        FilterRejectionError("Null byte in member name", member_name="a.txt")
    )
    assert rendered.count("a.txt") == 1


def test_the_o9_signature_message_renders_its_path_posix() -> None:
    """`Destination already exists` is the message the whole change was reproduced on.

    It was the last site still interpolating a native path, missed because the audit
    that found the others matched ``\\bdest\\b``, which does not fire inside
    ``dest_path`` — the same word-boundary trap as the call-site guard above.
    """
    from pathlib import Path

    from archivey.terminal import display_path

    dest = Path("out") / "sub" / "a.txt"
    message = ExtractionError(
        f"Destination already exists: {display_path(dest)}"
    ).message
    assert message.endswith("out/sub/a.txt")
    assert "\\" not in message


def test_no_message_interpolates_a_native_path() -> None:
    """Every path in a message goes through display_path(), so nothing doubles.

    A static sweep rather than a per-site test: the failure is invisible on Linux, where
    a native path has no backslashes to double.
    """
    path_words = {"dest", "path", "target", "dir", "root", "destination", "wrapper"}
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        module = path.relative_to(_SRC).as_posix()
        if module in _NON_ARCHIVE_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = (
                getattr(node.func, "id", None) or getattr(node.func, "attr", None) or ""
            )
            if fname in _FOREIGN or not _ESCAPING_CALL.search(fname):
                continue
            targets = list(node.args[:1]) + [
                k.value for k in node.keywords if k.arg == "message"
            ]
            for target in targets:
                if not isinstance(target, ast.JoinedStr):
                    continue
                for value in target.values:
                    if not isinstance(value, ast.FormattedValue):
                        continue
                    expr = ast.unparse(value.value)
                    if value.conversion == ord("r") or "display_path(" in expr:
                        continue
                    if "quoted(" in expr or re.fullmatch(r"exc|e|err|error", expr):
                        continue
                    if any(
                        tok.lower() in path_words
                        for tok in re.split(r"[^A-Za-z]+", expr)
                    ):
                        offenders.append(f"{module}:{node.lineno} {{{expr}}}")
    assert not offenders, (
        "wrap paths in display_path() so Windows separators are not doubled by the "
        "escape:\n  " + "\n  ".join(offenders)
    )


# --- CLI print sites ----------------------------------------------------------------
#
# The sweeps above guard *messages*, keyed on the constructor. A CLI ``print()`` is not
# one, so nothing looked at the print sites, and two hand audits in a row each found
# sites the previous one missed (the closing summary, the hoist lines, every ``info``
# field). These two sweeps replace the third audit.

_CLI = _SRC / "cli"

# Calls whose result is terminal-safe by construction.
_CLI_RENDERERS = {
    "escape_member_name",
    "escape_path",
    "escape_control_chars",
    "format_error_detail",
    "format_member_line",  # escapes the name and link target itself
    "format_long_listing",  # escapes the name, link target and method itself
    "format_field_value",  # escapes text; bytes print as hex
}

# Functions that write their arguments to a terminal stream. ``_field`` is ``info``'s
# line printer and ``_report_quietly`` is ``main``'s last-resort error printer; both
# take text they are told is already safe, and checking their call sites here is what
# makes that true.
_CLI_PRINTERS = {"print", "_field", "_report_quietly"}

# What a print site may still interpolate raw once the sweep has traced it as far as it
# can, keyed ``module: expression``: attributes, calls into other modules, and ``str``
# parameters, which the sweep cannot follow. Each is safe by type or escaped where it
# was built; say which. An entry that no longer matches fails
# ``test_cli_print_allowances_name_real_sites``. Keys are ``ast.unparse`` output, whose
# quoting of an f-string with quotes inside its fields differs between Python versions,
# so hoist such an f-string into a local rather than key on it.
_CLI_PRINT_ALLOWED = {
    "common.py: stats.bytes_decompressed": "int counter",
    "common.py: str(stats.compressed_bytes_consumed)": "int counter",
    "common.py: stats.source_seek_count": "int counter",
    "extract_cmd.py: ', '.join(parts)": "counts, built two lines above",
    "extract_cmd.py: '; '.join(parts)": (
        "_usage_line: int counts, and the declaring text through escape_member_name"
    ),
    "extract_cmd.py: result.kept_mode": "int mode, printed as octal",
    "extract_cmd.py: stat.S_IMODE(os.stat(dest).st_mode)": (
        "int mode of the operator's directory, printed as octal"
    ),
    "extract_cmd.py: dest_label": (
        "the hoist's label, built with escape_path in maybe_hoist_single_root"
    ),
    "info_cmd.py: key": "_field's key; its call sites are checked here",
    "info_cmd.py: text": "_field's text; its call sites are checked here",
    "test_cmd.py: max(members_total - ok - failed, 0)": (
        "_not_tested's return: arithmetic on int counts"
    ),
    "list_cmd.py: report.error": "an ArchiveyError, which escapes itself",
    "list_cmd.py: line": (
        "a format_long_listing or format_member_details line: every archive value "
        "escaped there, diagnostic messages stored escaped"
    ),
    "main.py: message": "_report_quietly's message; its call sites are checked here",
    "main.py: archivey.__version__": "archivey's own version",
    "main.py: format_format_label(fmt)": "format label from the format registry",
    "main.py: avail.support.value": "enum value",
    "main.py: exc.code": "a SystemExit message raised by the CLI itself",
    "main.py: '; '.join(groups)": (
        "dependency names and install hints from archivey, grouped by "
        "_format_missing_components"
    ),
}

# Parameter annotations that make a value safe by type.
_SAFE_ANNOTATIONS = {"int", "int | None", "bool"}


def _call_name(node: ast.Call) -> str:
    return getattr(node.func, "id", None) or getattr(node.func, "attr", None) or ""


class _PrintTracer:
    """Follow a printed expression back to the values it is built from.

    A local name is followed to every assignment of it in the enclosing function, and a
    call to a function of the same module to every value it returns. What cannot be
    followed — an attribute, a call into another module, an unannotated or ``str``
    parameter, a loop variable — is a *leaf*, and a leaf passes only through
    ``_CLI_PRINT_ALLOWED``. Following names is what lets
    ``label = f"{escape_path(...)}"`` pass on its own evidence instead of on the
    spelling ``label``.
    """

    def __init__(self, tree: ast.Module) -> None:
        self.functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def leaves(
        self, node: ast.expr, scope: ast.AST, seen: frozenset[str] = frozenset()
    ) -> list[ast.expr]:
        if isinstance(node, ast.Constant):
            return []
        if isinstance(node, ast.JoinedStr):
            found: list[ast.expr] = []
            for value in node.values:
                # ``!r`` is inert: ``repr`` escapes every non-printable character.
                if isinstance(value, ast.FormattedValue) and value.conversion != ord(
                    "r"
                ):
                    found.extend(self.leaves(value.value, scope, seen))
            return found
        if isinstance(node, ast.IfExp):  # the condition is not printed
            return self.leaves(node.body, scope, seen) + self.leaves(
                node.orelse, scope, seen
            )
        if isinstance(node, ast.BinOp):
            return self.leaves(node.left, scope, seen) + self.leaves(
                node.right, scope, seen
            )
        if isinstance(node, ast.BoolOp):  # ``a or b`` prints whichever operand wins
            return [
                leaf
                for value in node.values
                for leaf in self.leaves(value, scope, seen)
            ]
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _CLI_RENDERERS:
                return []
            local = (
                self._function(name, scope) if isinstance(node.func, ast.Name) else None
            )
            if local is None:
                return [node]
            if name in seen:
                return []
            return [
                leaf
                for ret in ast.walk(local)
                if isinstance(ret, ast.Return) and ret.value is not None
                for leaf in self.leaves(ret.value, local, seen | {name})
            ]
        if isinstance(node, ast.Name):
            return self._name_leaves(node, scope, seen)
        return [node]

    def _function(
        self, name: str, scope: ast.AST
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """The function a bare ``name(...)`` in *scope* calls: one defined in *scope*'s
        own body, else a module-level one.

        A def nested deeper (inside a branch, a loop or another function) is not looked
        at: a call to one resolves to the module-level function of that name if there is
        one, and is otherwise left unresolved, which reports it as unescaped. The nested
        helper the CLI has, ``shown``, sits in its function's body."""
        for child in getattr(scope, "body", []):
            if (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == name
            ):
                return child
        return self.functions.get(name)

    def _name_leaves(
        self, node: ast.Name, scope: ast.AST, seen: frozenset[str]
    ) -> list[ast.expr]:
        key = f"{id(scope)}:{node.id}"
        if key in seen:
            return []
        seen = seen | {key}
        found: list[ast.expr] = []
        bound = False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                if arg.arg == node.id:
                    bound = True
                    annotation = ast.unparse(arg.annotation) if arg.annotation else ""
                    if annotation not in _SAFE_ANNOTATIONS:
                        found.append(node)
        for child in ast.walk(scope):
            if isinstance(child, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == node.id for t in child.targets
            ):
                value: ast.expr | None = child.value
            elif (
                isinstance(child, (ast.AnnAssign, ast.AugAssign))
                and isinstance(child.target, ast.Name)
                and child.target.id == node.id
            ):
                value = child.value
            elif isinstance(child, (ast.For, ast.comprehension)) and any(
                isinstance(t, ast.Name) and t.id == node.id
                for t in ast.walk(child.target)
            ):
                bound = True
                found.append(node)  # a loop variable: not followed
                continue
            else:
                continue
            bound = True
            if value is not None:
                found.extend(self.leaves(value, scope, seen))
        if not bound:
            found.append(node)  # a module global or a closure variable
        return found


def _cli_print_sites() -> list[tuple[str, int, str]]:
    """``(module, line, expression)`` for every untraced value a CLI printer writes."""
    sites: set[tuple[str, int, str]] = set()
    for path in sorted(_CLI.rglob("*.py")):
        module = path.relative_to(_CLI).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        tracer = _PrintTracer(tree)
        for scope in ast.walk(tree):
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(scope):
                if (
                    not isinstance(node, ast.Call)
                    or _call_name(node) not in _CLI_PRINTERS
                ):
                    continue
                # The last argument of ``_field`` and ``_report_quietly`` is the
                # stream, not text.
                text_args = {"_field": 2, "_report_quietly": 1}.get(_call_name(node))
                args = node.args[:text_args] if text_args else node.args
                for arg in args:
                    for leaf in tracer.leaves(arg, scope):
                        sites.add((module, node.lineno, ast.unparse(leaf)))
    return sorted(sites)


def test_cli_print_sites_escape_what_they_print() -> None:
    """A value a CLI printer writes is escaped, or allowed here with a reason.

    Keyed on the *expression* at its module, so a new print site interpolating a raw
    member name, path or archive field fails here even though nothing else changed.
    """
    offenders = [
        f"{module}:{line} {{{expr}}}"
        for module, line, expr in _cli_print_sites()
        if f"{module}: {expr}" not in _CLI_PRINT_ALLOWED
    ]
    assert not offenders, (
        "escape archive-derived text at the print site (escape_member_name, "
        "escape_path, format_error_detail), or add the value to _CLI_PRINT_ALLOWED "
        "with the reason it is safe:\n  " + "\n  ".join(offenders)
    )


def test_cli_print_allowances_name_real_sites() -> None:
    """A stale allowance is a hole waiting for the next site with that spelling."""
    live = {f"{module}: {expr}" for module, _line, expr in _cli_print_sites()}
    assert not set(_CLI_PRINT_ALLOWED) - live


def test_cli_does_not_escape_a_native_path() -> None:
    """A path is rendered ``/``-separated before it is escaped, so nothing doubles.

    Invisible on a POSIX runner, where a native path has no backslash to double —
    hence a static sweep. ``escape_path`` does both steps; a bare escape of something
    path-shaped has to show where it was made relative or ``/``-separated.
    """
    path_words = {"dest", "path", "target", "dir", "root", "destination", "wrapper"}
    made_posix = ("_relative_name(", "display_path(", ".as_posix()")
    offenders: list[str] = []
    for path in sorted(_CLI.rglob("*.py")):
        module = path.relative_to(_CLI).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) not in {
                "escape_member_name",
                "escape_control_chars",
            }:
                continue
            for arg in node.args:
                expr = ast.unparse(arg)
                if any(marker in expr for marker in made_posix):
                    continue
                if expr.endswith(".link_target"):
                    continue  # the archive's own string, not a native path
                if any(
                    tok.lower() in path_words for tok in re.split(r"[^A-Za-z]+", expr)
                ):
                    offenders.append(
                        f"{module}:{node.lineno} {_call_name(node)}({expr})"
                    )
    assert not offenders, (
        "use escape_path() for a path, so Windows separators are not doubled:\n  "
        + "\n  ".join(offenders)
    )
