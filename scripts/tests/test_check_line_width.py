"""``scripts/checks/check_line_width.py``: what the check reports and what the fixer moves."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "checks" / "check_line_width.py"
)
_spec = importlib.util.spec_from_file_location("check_line_width", SCRIPT)
assert _spec is not None and _spec.loader is not None
lw = importlib.util.module_from_spec(_spec)
sys.modules["check_line_width"] = lw  # dataclasses look the module up by name
_spec.loader.exec_module(lw)

LONG = (
    "This sentence was edited and now runs well past the limit, because the edit added a "
    "clause in the middle of it and nobody rewrapped the paragraph afterwards at all."
)


def _md_reflow(text: str, touched: set[int], width: int = 88) -> str:
    lines = lw.split_lines(text)
    out = lw.reflow(lines, lw.segment(lines, docstring=False), touched, width)
    return "\n".join(out) + "\n"


# --- The check ---------------------------------------------------------------------------


def test_an_added_prose_line_over_100_is_reported() -> None:
    text = f"# Title\n\n{LONG}\nNext line.\n"
    assert len(LONG) > lw.LIMIT
    found = lw.problems("dev-docs/x.md", text, {3})
    assert found == [f"dev-docs/x.md:3: {len(LONG)} columns > 100"]


def test_a_long_line_the_change_did_not_add_is_not_reported() -> None:
    text = f"{LONG}\nshort\n"
    assert lw.problems("dev-docs/x.md", text, {2}) == []


@pytest.mark.parametrize(
    "line",
    [
        "| " + "cell " * 30 + "|",
        "## " + "heading " * 20,
        "[ref]: https://example.com/" + "a" * 100,
        "https://example.com/" + "a" * 100,
        "<details><summary>" + "x " * 50 + "</summary>",
    ],
)
def test_lines_that_cannot_or_must_not_be_wrapped_are_not_reported(line: str) -> None:
    assert lw.problems("dev-docs/x.md", f"{line}\n", {1}) == []


def test_a_code_block_line_is_not_reported() -> None:
    text = "Text.\n\n```\n" + "x = 1  " * 20 + "\n```\n"
    assert lw.problems("dev-docs/x.md", text, {4}) == []


def test_docs_and_skipped_folders() -> None:
    assert lw.wrap_width("docs/reading.md") == 100
    assert lw.wrap_width("dev-docs/review-loop.md") == 88
    assert lw.wrap_width("src/archivey/core.py") == 88
    # GitHub renders a newline in a pull request body as a line break.
    assert lw.wrap_width(".github/pull_request_template.md") is None
    assert lw.problems(".github/pull_request_template.md", f"{LONG}\n", {1}) == []


def test_parse_added_reads_hunks_and_renames() -> None:
    diff = (
        "diff --git a/a.md b/a.md\n--- a/a.md\n+++ b/a.md\n"
        "@@ -3 +3,2 @@\n-old\n+new\n+newer\n@@ -10,0 +12 @@\n+one\n"
        "diff --git a/gone.md b/gone.md\n--- a/gone.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert lw.parse_added(diff) == {"a.md": {3, 4, 12}}


def test_split_lines_counts_like_git() -> None:
    # str.splitlines would split at U+2028 too, and shift every later line number.
    assert lw.split_lines("a b\nc\n") == ["a b", "c"]


# --- The fixer: Markdown -----------------------------------------------------------------


def test_the_fixer_starts_at_the_edit_and_resumes_the_old_breaks() -> None:
    before = "The first line of this paragraph is not touched by the edit and keeps its break.\n"
    after = "A last line that the old wrap already had.\nAnd one more.\n"
    text = before + LONG + "\n" + after
    out = _md_reflow(text, {1})
    lines = out.splitlines()
    assert lines[0] == before.rstrip("\n")  # never moved
    assert all(len(line) <= 88 for line in lines)
    assert out.split() == text.split()


def test_a_filled_paragraph_comes_out_unchanged() -> None:
    text = (
        "A paragraph wrapped by hand at a slightly shorter width than eighty-eight,\n"
        "with a break before a new sentence, which the author wanted there.\n"
        "That break was deliberate, and the fixer must leave it.\n"
    )
    assert _md_reflow(text, {0, 1}) == text


def test_a_ragged_touched_line_is_filled() -> None:
    text = (
        "A paragraph where the edit left a short line behind it, like this one:\n"
        "cost.) Before that,\n"
        "the rest of the paragraph continued on the following lines as it always did.\n"
    )
    out = _md_reflow(text, {1})
    assert "cost.) Before that, the rest" in out
    assert out.split() == text.split()


def test_code_spans_stay_whole_even_across_old_breaks() -> None:
    text = (
        "Run `uv sync --frozen --group dev\n--extra all` before the tests, which is what "
        "the setup script does on every machine it provisions for a session.\n"
    )
    out = _md_reflow(text, {1})
    assert "`uv sync --frozen --group dev --extra all`" in out


def test_a_line_never_starts_with_a_block_marker() -> None:
    words = "word " * 15 + "fixed in #370 and"
    text = words + " also - this.\n"
    for width in range(60, 100):
        out = _md_reflow(text, {0}, width)
        for line in out.splitlines()[1:]:
            assert not line.startswith(("#", "- ", "> ")), (width, line)


def test_list_items_keep_their_marker_and_hanging_indent() -> None:
    text = f"- {LONG}\n  continued.\n- Next item.\n"
    out = _md_reflow(text, {0})
    lines = out.splitlines()
    assert lines[0].startswith("- ")
    assert all(line.startswith("  ") for line in lines[1:-1])
    assert lines[-1] == "- Next item."


def test_quotes_keep_their_marker() -> None:
    out = _md_reflow(f"> {LONG}\n", {0})
    assert all(line.startswith("> ") for line in out.splitlines())


def test_a_hard_break_line_is_left_alone() -> None:
    text = f"**Date:** 2026-09-01  \n{LONG}\n"
    out = _md_reflow(text, {0, 1})
    assert out.splitlines()[0] == "**Date:** 2026-09-01  "


def test_a_quote_after_a_paragraph_is_not_joined_to_it() -> None:
    text = "**Before:**\n> quoted text that is long enough " + "to wrap " * 12 + "\n"
    out = _md_reflow(text, {1})
    assert out.splitlines()[0] == "**Before:**"


# --- The fixer: Python -------------------------------------------------------------------


def _py_reflow(source: str, touched: set[int]) -> str:
    lines = lw.split_lines(source)
    layout = lw.python_layout(source)
    assert layout is not None
    return "\n".join(lw.reflow_python(lines, layout, touched)) + "\n"


def test_a_comment_block_is_rewrapped_with_its_marker() -> None:
    source = f"def f():\n    # {LONG}\n    # Second line.\n    return 1\n"
    out = _py_reflow(source, {1})
    comments = [line for line in out.splitlines() if line.lstrip().startswith("#")]
    assert len(comments) > 2
    assert all(line.startswith("    # ") and len(line) <= 88 for line in comments)
    compile(out, "x", "exec")


def test_a_docstring_paragraph_is_rewrapped_and_its_sections_are_kept() -> None:
    source = (
        "def f(x):\n"
        '    """Summary.\n'
        "\n"
        f"    {LONG}\n"
        "\n"
        "    Args:\n"
        "        x: an argument whose description is long enough that the fixer has to wrap it.\n"
        "            And its hanging continuation.\n"
        "\n"
        "    >>> f(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)\n"
        '    """\n'
    )
    out = _py_reflow(source, {3, 6, 9})
    lines = out.splitlines()
    assert "    Args:" in lines
    assert any(line.startswith("        x: an argument") for line in lines)
    assert any(
        line.startswith("            ") and "continuation" in line for line in lines
    )
    assert source.splitlines()[9] in lines  # the doctest line is not touched
    compile(out, "x", "exec")


def test_a_string_passed_to_a_call_is_never_rewrapped() -> None:
    source = (
        "run(\n"
        '    """\n'
        "    import io, resource, struct\n"
        "    from archivey.exceptions import ResourceUnavailableError\n"
        '    """\n'
        ")\n"
    )
    assert _py_reflow(source, {2, 3}) == source


def test_a_ruled_section_comment_is_not_wrapped() -> None:
    source = (
        "# --- cli review follow-ups (P3 / P5 / P6 / P10 / P11 / P12 / P13 / D1) "
        + ("-" * 30 + "\nx = 1\n")
    )
    assert _py_reflow(source, {0}) == source


# --- End to end --------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_check_and_fix_against_a_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    doc = tmp_path / "notes.md"
    doc.write_text(f"# Notes\n\nShort paragraph.\n\n{LONG}\n")  # an old long line
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    doc.write_text(f"# Notes\n\nShort paragraph. {LONG}\n\n{LONG}\n")
    monkeypatch.setattr(lw, "ROOT", tmp_path)

    assert lw.main(["--base", "main"]) == 1
    report = capsys.readouterr().out
    assert "notes.md:3:" in report
    assert "notes.md:5:" not in report  # was already there
    assert "--fix" in report

    assert lw.main(["--base", "main", "--fix"]) == 0
    lines = doc.read_text().splitlines()
    assert lines[-1] == LONG  # untouched
    assert all(len(line) <= 88 for line in lines[:-1])


def test_two_block_markers_after_a_long_first_word_do_not_hang() -> None:
    # The break once stepped back and forth between two unsafe words forever.
    words = ["`" + "x" * 80 + "`", "#12", "#13", "end"]
    lines = lw.fill(words, "", "", 88, set())
    assert [text for _, text in lines] == ["`" + "x" * 80 + "` #12 #13", "end"]
    link = "[the thread](https://github.com/archivey-dev/archivey/pull/1508#discussion_r12345678)"
    text = f"Short line.\n{link} #1508 #1510 then the rest of the sentence goes on for a while.\n"
    out = _md_reflow(text, {1})
    assert out.split() == text.split()


def test_a_sentence_broken_after_a_colon_stays_one_docstring_paragraph() -> None:
    source = (
        "def f():\n"
        '    """Summary.\n'
        "\n"
        "    The record is internal, so the script checks it is there and prints ``warning:\n"
        "    resource usage not recorded`` rather than leaving the columns silently empty. "
        "``decoder_memory`` is the largest allocation\n"
        "    an archive declared.\n"
        '    """\n'
    )
    out = _py_reflow(source, {4})
    assert "``warning: resource usage not recorded``" in " ".join(out.split())
    body = out.splitlines()[3:-1]
    assert all(len(line) <= 88 for line in body)
    assert all(len(line) > 44 for line in body[:-1])  # no ragged line


def test_a_section_opener_still_ends_its_paragraph() -> None:
    source = (
        "def f(x):\n"
        '    """Summary.\n'
        "\n"
        "    Some text that runs on long enough to need wrapping when the fixer rewraps it, "
        "as this line is far past the width.\n"
        "    Args:\n"
        "        x: the argument.\n"
        '    """\n'
    )
    out = _py_reflow(source, {3})
    assert "    Args:" in out.splitlines()


def test_a_quoted_path_in_the_diff_is_read() -> None:
    diff = '--- a/x\n+++ "b/tab\\there.md"\n@@ -0,0 +1 @@\n+x\n'
    assert lw.parse_added(diff) == {"tab\there.md": {1}}
    diff = '--- a/x\n+++ "b/na\\303\\257ve.md"\n@@ -0,0 +1 @@\n+x\n'
    assert lw.parse_added(diff) == {"na\u00efve.md": {1}}


def test_a_line_the_fixer_cannot_shorten_is_not_reported() -> None:
    span = "`" + "uv sync --frozen --group dev --extra all " * 3 + "`"
    assert lw.breakable(f"- Run {span} before the tests.", 100)
    # After --fix the span sits alone on its line: one token, so the check passes.
    assert not lw.breakable(f"  {span}", 100)
    link = (
        "[`cpio_reader.py`](https://github.com/archivey-dev/archivey/blob/main/"
        + "x" * 60
        + ")"
    )
    assert not lw.breakable(link, 100)
    assert lw.breakable("word " * 30, 100)


def test_a_short_line_ending_in_a_colon_inside_a_code_span_is_not_a_label() -> None:
    source = (
        "def f():\n"
        '    """Summary.\n'
        "\n"
        "    prints a ``warning:\n"
        "    resource usage not recorded`` rather than leaving the columns silently empty.\n"
        '    """\n'
    )
    out = _py_reflow(source, {3})
    assert "``warning: resource usage not recorded``" in out
