"""Fail on an added Markdown line over 100 columns, and rewrap only what a change touched.

Prose here is hard-wrapped: Markdown at 100 columns under `docs/` and at 88 elsewhere,
Python comments and docstrings at 88. Nothing checked Markdown, and `ruff format` wraps
Python code but never a comment or a docstring, so an edited paragraph kept its new
104-column line, or its short ragged one, until a reviewer spent a round on it. Python
lines are now ruff's job (E501 at 100, `pyproject.toml`). This covers Markdown, and gives
both a fixer.

    python3 scripts/checks/check_line_width.py               # check, against origin/main
    python3 scripts/checks/check_line_width.py --fix         # rewrap what the change touched
    python3 scripts/checks/check_line_width.py --staged      # check the index (git hook)
    python3 scripts/checks/check_line_width.py --base <ref>  # what CI passes

**The check** looks only at the lines the change adds, compared with the merge base. It
fails on one that is longer than `LIMIT` (100, the same in every folder) when the line is
prose (a paragraph, list item or quote) and can be broken: it has a space after its
indent, at or before the limit. Table rows, headings, code blocks, HTML, link definitions
and lines that are one long URL are never reported. Lines that were already over are not
either, so nobody has to clean up a file to touch it: about 740 Markdown lines over 100
predate this check. A whole-file formatter (mdformat, Prettier) was not used for that
reason: it rewraps every paragraph of every file it is run on, which buries the change
under a reflow diff.

**The fixer** (`--fix`) rewraps each paragraph that holds an added line, in Markdown and
in Python comment blocks and docstrings, to the file's own width (88, or 100 under
`docs/`). It starts at the first added line and stops as soon as its line breaks meet
the old ones again after the last added line. Lines before the edit never move, and a
paragraph that was already filled comes out unchanged, so the diff is the edit and the
lines it pushed. It keeps list markers, hanging indents, quote markers and
`` `code spans` `` whole, and never starts a line with a token that Markdown reads as a
list, a heading or a quote. It writes only the working tree; read the diff before
committing.

`.github/` is skipped: GitHub renders a newline in an issue or pull request body as a
line break, so its templates are not wrapped. So are `review/` (generated review
reports), `dev-docs/history/` and the OpenSpec archive.

Stdlib only.
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: The check fails on an added Markdown prose line longer than this, in every folder.
#: Python lines are ruff's: E501 reports any line over the same 100 (pyproject.toml).
LIMIT = 100
#: Widths the fixer wraps to, so a rewrapped paragraph matches the text around it.
PYTHON_WIDTH = 88
MARKDOWN_WIDTH = 88
#: Folder prefixes whose Markdown is wrapped wider than `MARKDOWN_WIDTH`.
MARKDOWN_WIDTH_BY_PREFIX = {"docs/": 100}
#: Path prefixes the check leaves alone. See the module docstring for why.
SKIPPED_PREFIXES = (
    ".github/",
    "review/",
    "openspec/changes/archive/",
    "dev-docs/history/",
)
#: Python lives here; `ruff` checks the same folders.
PYTHON_PREFIXES = ("src/", "tests/", "scripts/", "benchmarks/")

FIX_HINT = "python3 scripts/checks/check_line_width.py --fix"


def wrap_width(path: str) -> int | None:
    """The width the fixer wraps ``path`` to, or None when the tool skips the file."""
    if path.startswith(SKIPPED_PREFIXES):
        return None
    if path.endswith(".md"):
        for prefix, width in MARKDOWN_WIDTH_BY_PREFIX.items():
            if path.startswith(prefix):
                return width
        return MARKDOWN_WIDTH
    if path.endswith(".py") and path.startswith(PYTHON_PREFIXES):
        return PYTHON_WIDTH
    return None


def split_lines(text: str) -> list[str]:
    """Split at newlines only, the way git and tokenize count lines.

    ``str.splitlines`` also splits at U+2028, form feeds and other separators a test
    file may hold inside a string, which would shift every line number after them.
    """
    lines = text.split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


# --- Which lines the change adds -------------------------------------------------------

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def git(*args: str) -> str:
    # quotePath off: a path with non-ASCII bytes stays as it is in the diff headers,
    # instead of a quoted "b/na\303\257ve.md" that would not match "b/".
    return subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _unquote(name: str) -> str:
    """Undo git's C-style quoting of a path holding a ``"``, a tab or a backslash."""
    if not (name.startswith('"') and name.endswith('"')):
        return name
    try:
        raw = ast.literal_eval(name)
    except (ValueError, SyntaxError):
        return name
    # Octal escapes are bytes of the UTF-8 name.
    return raw.encode("latin-1", "backslashreplace").decode("utf-8", "replace")


def parse_added(diff: str) -> dict[str, set[int]]:
    """Map each file in a ``git diff -U0`` to the 1-based numbers of its added lines."""
    added: dict[str, set[int]] = {}
    path: str | None = None
    for line in split_lines(diff):
        if line.startswith("+++ "):
            name = _unquote(line[4:])
            path = name[2:] if name.startswith("b/") else None
            continue
        match = HUNK.match(line)
        if match and path is not None:
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            added.setdefault(path, set()).update(range(start, start + count))
    return added


def added_lines(base: str | None, staged: bool) -> dict[str, set[int]]:
    common = ["diff", "-U0", "-M", "--no-color", "--no-ext-diff", "--diff-filter=AMR"]
    if staged:
        return parse_added(git(*common, "--cached"))
    merge_base = git("merge-base", base or "origin/main", "HEAD").strip()
    added = parse_added(git(*common, merge_base))
    # A new file not yet added to git is all added lines.
    for name in split_lines(git("ls-files", "--others", "--exclude-standard")):
        path = ROOT / name
        if wrap_width(name) is not None and path.is_file():
            count = len(split_lines(path.read_text(encoding="utf-8", errors="replace")))
            added[name] = set(range(1, count + 1))
    return added


# --- Splitting text into paragraphs ----------------------------------------------------

FENCE = re.compile(r"^\s*(```+|~~~+)")
QUOTE = re.compile(r"^(?:[ \t]*>[ \t]?)+")
LIST_ITEM = re.compile(r"^([ \t]*)([-*+]|\d{1,9}[.)])([ \t]+)(?=\S)")
#: An rST field (``:param x:``), which a docstring treats as a list item.
FIELD = re.compile(r"^([ \t]*):[\w ]+:\s")
HEADING = re.compile(r"^\s*#{1,6}(\s|$)")
RULE = re.compile(r"^\s*([-*_=])(\s*\1){2,}\s*$")
#: A ruled section title in a comment: "# --- Check -----", "# ==== Setup".
SECTION_RULE = re.compile(r"^\s*([-=*#~])\1{2,}|([-=*#~])\2{3,}\s*$")
LINK_DEF = re.compile(r"^\s*\[[^\]]+\]:\s")
ADMONITION = re.compile(r"^\s*(!!!|\?\?\?\+?)\s")
PRAGMA = re.compile(r"^(noqa|type:|pyright:|pyrefly:|ty:|fmt:|isort:|-\*-|!)")


@dataclass
class Paragraph:
    start: int  # index of the first line
    end: int  # index after the last line
    first_prefix: str
    cont_prefix: str


@dataclass
class Layout:
    paragraphs: list[Paragraph]
    #: Indices of prose lines, the only ones the check reports.
    prose: set[int]


def _indent(text: str) -> str:
    return text[: len(text) - len(text.lstrip(" \t"))]


def _hard_break(line: str) -> bool:
    return line.endswith(("  ", "\\")) or line.rstrip().endswith("<br>")


def segment(lines: list[str], *, docstring: bool) -> Layout:
    """Split ``lines`` into the paragraphs a fixer may rewrap.

    ``docstring`` selects the rules for a Python comment block or docstring body, where
    a line ending in ``:`` introduces a section or a literal block, and ``>>>`` starts
    an example, instead of the Markdown ones (fences, tables, headings and the rest).
    """
    paragraphs: list[Paragraph] = []
    prose: set[int] = set()
    fence: str | None = None
    current: Paragraph | None = None
    #: The kind of the last block before a blank line, to tell code from a list's or an
    #: admonition's indented continuation.
    after_blank_context = "none"
    previous_blank = True
    frozen_until_blank = False
    #: Inside an indented code block: the indent width its lines keep. A blank line
    #: does not end it; a less indented line does.
    code_block: int | None = None
    #: The previous line was structural (a heading, an rST underline): an indented line
    #: right after it starts a code block, as one after a blank line does.
    after_structural = False

    def close() -> None:
        nonlocal current
        if current is not None:
            paragraphs.append(current)
            current = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        if fence is not None:
            if stripped.startswith(fence):
                fence = None
            continue
        if not docstring:
            fence_match = FENCE.match(line)
            if fence_match:
                close()
                fence = fence_match.group(1)[:3]
                previous_blank = False
                continue
        if not stripped:
            close()
            frozen_until_blank = after_structural = False
            previous_blank = True
            continue
        quote_match = QUOTE.match(line) if not docstring else None
        quote = quote_match.group(0) if quote_match else ""
        rest = line[len(quote) :]
        rest_stripped = rest.strip()
        if not rest_stripped:  # an empty quote line (">") separates paragraphs too
            close()
            previous_blank = True
            continue
        indent = _indent(rest)
        width_of_indent = len(indent.expandtabs(4))
        if code_block is not None:
            if width_of_indent >= code_block:
                previous_blank = False
                continue
            code_block = None
        list_match = LIST_ITEM.match(rest) or (FIELD.match(rest) if docstring else None)

        if frozen_until_blank or (
            docstring and rest_stripped.startswith((">>>", "... "))
        ):
            close()
            frozen_until_blank = docstring
            previous_blank = False
            continue
        structural = (
            _hard_break(line)  # a deliberate line break: the line stays as it is
            or rest_stripped.startswith(("|", "<", "+--", "+=="))
            or HEADING.match(rest)
            or RULE.match(rest)
            or LINK_DEF.match(rest)
            or ADMONITION.match(rest)
            or (docstring and PRAGMA.match(rest_stripped))
            or (docstring and SECTION_RULE.search(rest))
        )
        if docstring and rest_stripped.startswith("#"):
            structural = False  # "#" is not a heading inside a comment
        if structural:
            close()
            after_blank_context = "admonition" if ADMONITION.match(rest) else "none"
            previous_blank = False
            after_structural = True
            continue
        # Four or more spaces after a blank line, outside a list or admonition, is an
        # indented code block (or an rST literal block after "::"). Every line after it
        # that is indented as far belongs to it.
        code_indent = width_of_indent >= 4
        if (
            (previous_blank or after_structural)
            and code_indent
            and list_match is None
            and after_blank_context == "none"
        ):
            close()
            code_block = width_of_indent
            previous_blank = after_structural = False
            continue
        after_structural = False

        prose.add(index)
        starts_new = (
            current is None
            or list_match is not None
            or (docstring and stripped.endswith(":") and len(stripped.split()) <= 3)
            or current.cont_prefix != quote + indent
            and not _first_continuation(current, index, quote + indent)
        )
        if starts_new:
            close()
            if list_match is not None:
                marker = list_match.group(0)
                first_prefix = quote + marker
                cont_prefix = quote + " " * len(marker.expandtabs(4))
                after_blank_context = "list"
            else:
                first_prefix = quote + indent
                cont_prefix = first_prefix
                if previous_blank and not code_indent:
                    after_blank_context = "none"
            current = Paragraph(index, index + 1, first_prefix, cont_prefix)
        else:
            assert current is not None
            if current.end - current.start == 1 and list_match is None:
                current.cont_prefix = quote + indent  # a hanging indent
            current.end = index + 1
        previous_blank = False
        if docstring and _opens_section(stripped, lines, index):
            close()
    close()
    return Layout(paragraphs, prose)


def _opens_section(stripped: str, lines: list[str], index: int) -> bool:
    """True when a docstring or comment line ending in ``:`` opens a section or block.

    ``Args:``, ``Example::`` and a line followed by a blank or a deeper-indented line
    do. A wrapped sentence that happens to break after a colon (``prints ``warning:``)
    does not: the next line goes on at the same indent.
    """
    if not stripped.endswith(":"):
        return False
    if stripped.endswith("::") or len(stripped.split()) <= 3:
        return True
    following = lines[index + 1] if index + 1 < len(lines) else ""
    if not following.strip():
        return True
    return len(_indent(following)) > len(_indent(lines[index]))


def _first_continuation(paragraph: Paragraph, index: int, prefix: str) -> bool:
    """A second line may set a deeper hanging indent than the first line's."""
    return (
        paragraph.end == index
        and paragraph.end - paragraph.start == 1
        and paragraph.first_prefix == paragraph.cont_prefix
        and len(prefix) > len(paragraph.cont_prefix)
        and prefix.startswith(paragraph.cont_prefix)
        # deeper by whitespace only, not by a quote marker
        and not prefix[len(paragraph.cont_prefix) :].strip()
    )


# --- Rewrapping ------------------------------------------------------------------------

CODE_SPAN = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)")
#: How full a line must stay when the fixer ends it early on an old line break.
RESUME_FILL = 0.75
#: A token that Markdown would read as a block start at the beginning of a line.
UNSAFE_START = re.compile(r"^([#>|<]|[-*+=_]+$|\d{1,9}[.)]$|!!!|\?\?\?)")


def tokens(text: str) -> list[tuple[str, int]]:
    """Split ``text`` on whitespace, keeping each `` `code span` `` in one token.

    Each token comes with the offset just after its last character.
    """
    protected = [False] * len(text)
    for match in CODE_SPAN.finditer(text):
        for position in range(match.start(), match.end()):
            protected[position] = True
    words: list[tuple[str, int]] = []
    word: list[str] = []
    for position, char in enumerate(text):
        if char.isspace() and not protected[position]:
            if word:
                words.append(("".join(word), position))
                word = []
        else:
            word.append(char)
    if word:
        words.append(("".join(word), len(text)))
    return words


def fill(
    words: list[str],
    first_prefix: str,
    cont_prefix: str,
    width: int,
    stops: set[int],
) -> list[tuple[int, str]]:
    """Fill ``words`` greedily. Return each line with the index of its last word.

    Stops, without the remaining words, after a line that ends on a word index in
    ``stops``: an old line break the rest of the old text can resume from. A line may
    end early on one to get there, as long as it stays at least `RESUME_FILL` full.
    """
    lines: list[tuple[int, str]] = []
    position = 0
    prefix = first_prefix
    while position < len(words):
        end = position + 1
        length = len(prefix) + len(words[position])
        while end < len(words) and length + 1 + len(words[end]) <= width:
            length += 1 + len(words[end])
            end += 1
        # End early on an old line break, so the old lines after it can stay.
        for stop in sorted((s for s in stops if position <= s < end - 1), reverse=True):
            if (
                len(prefix + " ".join(words[position : stop + 1]))
                >= width * RESUME_FILL
            ):
                end = stop + 1
            break
        # Never start the next line with a token Markdown reads as a block start: give
        # it the previous word too, or keep it on this line when this line has only one.
        if end < len(words) and UNSAFE_START.match(words[end]):
            end = _safe_break(words, position, end)
        lines.append((end - 1, prefix + " ".join(words[position:end])))
        position = end
        prefix = cont_prefix
        if end - 1 in stops:
            break
    return lines


def _safe_break(words: list[str], position: int, end: int) -> int:
    """Move a line break off a word Markdown would read as a block start.

    Prefer an earlier break, so the line gets shorter; when every word after the line's
    first is unsafe, keep them on the line until a safe word or the end. One direction
    each, so it always ends.
    """
    for candidate in range(end - 1, position, -1):
        if not UNSAFE_START.match(words[candidate]):
            return candidate
    while end < len(words) and UNSAFE_START.match(words[end]):
        end += 1
    return end


def needs_reflow(old: list[str], first: int, last: int, width: int) -> bool:
    """True when a touched line is too long, or ragged: shorter than half the width with
    more of the paragraph after it.

    A touched line that is merely shorter than a full line is left alone: authors break
    a line before a new sentence on purpose, and refilling it would move every line
    after it. So is a paragraph whose only long lines are ones the change did not touch.
    """
    if any(len(line) > width for line in old[first : last + 1]):
        return True
    return any(
        len(line) < width // 2 for line in old[first : min(last + 1, len(old) - 1)]
    )


def reflow_paragraph(
    lines: list[str], paragraph: Paragraph, touched: set[int], width: int
) -> list[str]:
    """Rewrap ``paragraph`` from its first touched line. Return its new lines."""
    old = lines[paragraph.start : paragraph.end]
    first = min(touched) - paragraph.start
    last = max(touched) - paragraph.start
    if not needs_reflow(old, first, last, width):
        return old
    # Join the whole paragraph first: a code span may run across a line break.
    contents: list[str] = []
    for offset, text in enumerate(old):
        prefix = paragraph.first_prefix if offset == 0 else paragraph.cont_prefix
        content = text[len(prefix) :] if text.startswith(prefix) else text.strip()
        contents.append(content.strip())
    found = tokens(" ".join(contents))
    # For each old line, the index of the word it ends on, or -1 when it ends inside a
    # code span, where a new line cannot start or end.
    word_end = {end: index for index, (_, end) in enumerate(found)}
    all_ends: list[int] = []
    position = 0
    for content in contents:
        position += len(content)
        all_ends.append(word_end.get(position, -1))
        position += 1
    # Start at a line that begins on a word: back up out of a code span.
    while first > 0 and all_ends[first - 1] == -1:
        first -= 1
    skip = all_ends[first - 1] + 1 if first > 0 else 0
    words = [word for word, _ in found[skip:]]
    if not words:
        return old
    ends = [end - skip if end >= 0 else -1 for end in all_ends[first:]]
    # Old line breaks after the last touched line, where the new lines may meet them.
    stops = {
        word
        for offset, word in enumerate(ends, start=first)
        if offset >= last and word >= 0
    }
    first_prefix = paragraph.first_prefix if first == 0 else paragraph.cont_prefix
    new = fill(words, first_prefix, paragraph.cont_prefix, width, stops)
    resumed_at = new[-1][0]
    tail_offset = next(
        (offset for offset, word in enumerate(ends, start=first) if word == resumed_at),
        len(old) - 1,
    )
    return old[:first] + [text for _, text in new] + old[tail_offset + 1 :]


def reflow(
    lines: list[str], layout: Layout, touched: set[int], width: int
) -> list[str]:
    """Rewrap every paragraph of ``layout`` that holds a ``touched`` line index."""
    out = list(lines)
    for paragraph in sorted(layout.paragraphs, key=lambda p: -p.start):
        hit = {i for i in touched if paragraph.start <= i < paragraph.end}
        if hit:
            new = reflow_paragraph(lines, paragraph, hit, width)
            out[paragraph.start : paragraph.end] = new
    return out


# --- Python: comment blocks and docstrings ---------------------------------------------


@dataclass
class Region:
    """Lines of a Python file seen as text: a comment block or a docstring body."""

    start: int  # index of the first line
    end: int  # index after the last line
    prefix: str  # what each line starts with: "    # " or the docstring's indent
    kind: str  # "comment" or "docstring"


@dataclass
class PythonLayout:
    regions: list[Region]


def python_layout(source: str) -> PythonLayout | None:
    try:
        tree = ast.parse(source)
        toks = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError, ValueError):
        return None
    lines = split_lines(source)
    comment_lines: dict[int, str] = {}  # index -> comment marker prefix
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            before = lines[row - 1][:col]
            if not before.strip():
                marker = "#:" if tok.string.startswith("#:") else "#"
                comment_lines[row - 1] = before + marker
    # A docstring is a string that is a whole statement: a module, class or function
    # docstring, or an attribute's. A string passed to a call (a child process's source,
    # a fixture's text) is code or data, and is never rewrapped.
    docstrings: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and node.end_lineno is not None
            and node.end_lineno > node.lineno
        ):
            opener = lines[node.lineno - 1]
            if opener[node.col_offset :].lstrip("rRuU").startswith(('"""', "'''")):
                docstrings.append(
                    (node.lineno - 1, node.end_lineno - 1, _indent(opener))
                )

    regions: list[Region] = []
    index_list = sorted(comment_lines)
    block: list[int] = []
    for index in [*index_list, None]:
        if block and (
            index is None
            or index != block[-1] + 1
            or comment_lines[index] != comment_lines[block[0]]
        ):
            regions.append(
                Region(
                    block[0], block[-1] + 1, comment_lines[block[0]] + " ", "comment"
                )
            )
            block = []
        if index is not None:
            block.append(index)
    for open_index, close_index, indent in docstrings:
        # The opening line holds the quotes and the summary, and the closing line the
        # closing quotes (and any text before them); only the lines between are body.
        if open_index + 1 < close_index:
            regions.append(Region(open_index + 1, close_index, indent, "docstring"))
    return PythonLayout(regions)


def region_text(lines: list[str], region: Region) -> list[str]:
    """The region's lines without their comment marker or docstring indent."""
    out = []
    marker = region.prefix.rstrip()
    for line in lines[region.start : region.end]:
        if region.kind == "comment":
            text = line.lstrip(" \t")[len(marker.lstrip(" \t")) :]
            out.append(text.removeprefix(" "))
        else:
            out.append(
                line[len(region.prefix) :]
                if line.startswith(region.prefix)
                else line.lstrip()
            )
    return out


def reflow_python(
    lines: list[str], layout: PythonLayout, touched: set[int]
) -> list[str]:
    out = list(lines)
    for region in sorted(layout.regions, key=lambda r: -r.start):
        hit = {i - region.start for i in touched if region.start <= i < region.end}
        if not hit:
            continue
        texts = region_text(lines, region)
        if region.kind == "comment" and any(PRAGMA.match(t.strip()) for t in texts):
            continue
        sub = segment(texts, docstring=True)
        prefix = region.prefix
        new = reflow(texts, sub, hit, PYTHON_WIDTH - len(prefix))
        rebuilt = [
            (prefix + text).rstrip() if text else prefix.rstrip() for text in new
        ]
        if region.kind == "docstring":
            rebuilt = [line if line.strip() else "" for line in rebuilt]
        out[region.start : region.end] = rebuilt
    return out


# --- Check ---------------------------------------------------------------------------


def breakable(line: str, limit: int) -> bool:
    """True when a break at a space after the indent leaves a first line within limit."""
    start = len(line) - len(line.lstrip(" \t>-*+"))
    space = line.find(" ", start)
    return space != -1 and space <= limit


def problems(path: str, text: str, added: set[int]) -> list[str]:
    """The added Markdown prose lines of ``path`` longer than `LIMIT`."""
    if not path.endswith(".md") or wrap_width(path) is None:
        return []
    lines = split_lines(text)
    prose = segment(lines, docstring=False).prose
    found: list[str] = []
    for number in sorted(added):
        index = number - 1
        if (
            index < len(lines)
            and len(lines[index]) > LIMIT
            and index in prose
            and breakable(lines[index], LIMIT)
        ):
            found.append(f"{path}:{number}: {len(lines[index])} columns > {LIMIT}")
    return found


def fix(path: str, added: set[int]) -> bool:
    """Rewrap the paragraphs of ``path`` that hold an added line. True if it changed."""
    width = wrap_width(path)
    file = ROOT / path
    if width is None or not file.is_file():
        return False
    text = file.read_text(encoding="utf-8")
    lines = split_lines(text)
    touched = {n - 1 for n in added if n - 1 < len(lines)}
    if path.endswith(".md"):
        new = reflow(lines, segment(lines, docstring=False), touched, width)
    else:
        layout = python_layout(text)
        if layout is None:
            return False
        new = reflow_python(lines, layout, touched)
    if new == lines:
        return False
    file.write_text(
        "\n".join(new) + ("\n" if text.endswith("\n") else ""), encoding="utf-8"
    )
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--base", help="compare with the merge base of this ref (default origin/main)"
    )
    parser.add_argument(
        "--staged", action="store_true", help="check the index against HEAD"
    )
    parser.add_argument(
        "--fix", action="store_true", help="rewrap the paragraphs the change touched"
    )
    args = parser.parse_args(argv)

    try:
        added = added_lines(args.base, args.staged)
    except subprocess.CalledProcessError as error:
        print(f"check_line_width: git failed: {error.stderr.strip()}", file=sys.stderr)
        return 2
    added = {
        path: lines for path, lines in added.items() if wrap_width(path) is not None
    }

    if args.fix:
        for path in sorted(added):
            if fix(path, added[path]):
                print(f"rewrapped {path}")
        # The fixer changed line numbers; read the added lines again.
        added = {
            path: lines
            for path, lines in added_lines(args.base, args.staged).items()
            if wrap_width(path) is not None
        }

    found: list[str] = []
    for path in sorted(added):
        file = ROOT / path
        if args.staged:
            try:
                text = git("show", f":{path}")
            except subprocess.CalledProcessError:
                continue
        elif file.is_file():
            text = file.read_text(encoding="utf-8", errors="replace")
        else:
            continue
        found.extend(problems(path, text, added[path]))
    if not found:
        print(f"ok: no added Markdown prose line is over {LIMIT} columns")
        return 0
    print(f"Added Markdown prose lines over {LIMIT} columns:")
    for problem in found:
        print(f"  {problem}")
    if not args.fix:
        print(f"\nRewrap the paragraphs you touched with: {FIX_HINT}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
