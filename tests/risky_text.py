"""Hypothesis strategies that draw the characters and names most likely to break
name handling, each risky class as a branch of its own so no run depends on luck.

A plain ``st.text()`` alphabet or a ``from_regex`` with ``\\d`` reaches a Unicode digit or
a fullwidth slash only by luck: ``0.7z.\\u066000`` broke the volume schemes in one run
out of many. These strategies make each risky class a branch of its own:

- :data:`risky_chars` / :func:`risky_text`: one class per entry of :data:`RISKY_CHARS`.
- :func:`with_lookalike`: a well-formed name with one ASCII character swapped for a
  Unicode lookalike (ARABIC-INDIC ONE for ``1``, DIVISION SLASH for ``/``), so the
  name still reaches the code past the first pattern match.
- :func:`with_risky_char`: a well-formed name with one risky character inserted.
- :data:`risky_components`: whole path components that are risky on some platform.

``hypothesis`` is a ``dev``-group dependency: import this module only from test
modules that already skip without it.
"""

from __future__ import annotations

from hypothesis import strategies as st

# Each group is a class of input that has broken, or could break, a name check.
RISKY_CHARS: dict[str, tuple[str, ...]] = {
    # ``\d`` and ``str.isdigit()`` accept these; ``int()`` reads most of them.
    "unicode_digits": (
        "\u0660",  # ARABIC-INDIC DIGIT ZERO
        "\u0661",
        "\u06f0",  # EXTENDED ARABIC-INDIC DIGIT ZERO
        "\u0967",  # DEVANAGARI DIGIT ONE
        "\uff10",  # FULLWIDTH DIGIT ZERO
        "\uff11",
        "\U0001d7ce",  # MATHEMATICAL BOLD DIGIT ZERO
        "\u00b2",  # SUPERSCRIPT TWO: isdigit() but not \d, and int() refuses it
    ),
    # Look like a separator or a dot; some normalize to one under NFKC.
    "separator_lookalikes": (
        "\u2215",  # DIVISION SLASH
        "\u2044",  # FRACTION SLASH
        "\uff0f",  # FULLWIDTH SOLIDUS
        "\uff3c",  # FULLWIDTH REVERSE SOLIDUS
        "\u29f5",  # REVERSE SOLIDUS OPERATOR
        "\uff0e",  # FULLWIDTH FULL STOP
        "\u2024",  # ONE DOT LEADER
        "\uff1a",  # FULLWIDTH COLON
    ),
    # Change how a name displays without changing what it is.
    "invisible_and_bidi": (
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u200b",  # ZERO WIDTH SPACE
        "\u200d",  # ZERO WIDTH JOINER
        "\ufeff",  # BYTE ORDER MARK
        "\u0301",  # COMBINING ACUTE ACCENT
        "\u00a0",  # NO-BREAK SPACE: \s, but not " "
        "\u3000",  # IDEOGRAPHIC SPACE
    ),
    # Fold or case-map to a different length or to ASCII.
    "case_fold": (
        "\u00df",  # LATIN SMALL LETTER SHARP S: casefold() is "ss"
        "\u1e9e",  # LATIN CAPITAL LETTER SHARP S
        "\u212a",  # KELVIN SIGN: lower() is "k"
        "\u0130",  # LATIN CAPITAL LETTER I WITH DOT ABOVE: lower() is two characters
        "\u0131",  # LATIN SMALL LETTER DOTLESS I: upper() is "I"
        "\u017f",  # LATIN SMALL LETTER LONG S: upper() is "S"
        "\ufb00",  # LATIN SMALL LIGATURE FF
    ),
    # Controls and line ends: ``$`` matches before a final newline, ``\Z`` does not.
    "controls": ("\x00", "\n", "\r", "\t", "\x1b", "\x7f", "\u0085", "\u2028"),
    # Lone surrogates: \udc80-\udcff encode under surrogateescape on POSIX, the rest
    # raise.
    "surrogates": ("\ud800", "\udbff", "\udc00", "\udc7f", "\udc80", "\udcff"),
}

# One Unicode lookalike (or more) for each ASCII character a name pattern keys on.
LOOKALIKES: dict[str, tuple[str, ...]] = {
    **{
        str(d): (chr(0x0660 + d), chr(0x06F0 + d), chr(0xFF10 + d), chr(0x0966 + d))
        for d in range(10)
    },
    "/": ("\u2215", "\u2044", "\uff0f"),
    "\\": ("\uff3c", "\u29f5"),
    ".": ("\uff0e", "\u2024"),
    ":": ("\uff1a",),
    "k": ("\u212a",),
    "K": ("\u212a",),
    "s": ("\u017f",),
    "i": ("\u0131",),
    "I": ("\u0130",),
}

risky_chars = st.one_of(*(st.sampled_from(chars) for chars in RISKY_CHARS.values()))
"""One risky character, each class about as likely as any other."""

# Components that some platform treats specially, or that sit on a length limit.
risky_components = st.sampled_from(
    [
        "a" * 255,  # the usual NAME_MAX
        "a" * 256,
        "\u00e9" * 128,  # 256 UTF-8 bytes from 128 characters
        "a.",  # Windows drops a trailing dot
        "a ",  # and a trailing space
        " a",
        "CON",
        "aux",
        "NUL.txt",
        "COM1",
        "LPT\u00b9",  # Windows also reserves superscript-digit ports
        "a:b",  # an NTFS alternate data stream
        "a~1",  # an 8.3 short-name shape
        "A",  # pairs with "a" on a case-insensitive filesystem
        "a",
    ]
)


def risky_text(min_size: int = 0, max_size: int = 16) -> st.SearchStrategy[str]:
    """Text built mostly from risky characters, with some ASCII to hold it together."""
    return st.text(
        st.one_of(risky_chars, st.sampled_from("a0./\\")),
        min_size=min_size,
        max_size=max_size,
    )


@st.composite
def with_lookalike(draw: st.DrawFn, names: st.SearchStrategy[str]) -> str:
    """A name from ``names`` with one ASCII digit, separator, dot or letter swapped
    for a Unicode lookalike (unchanged when the name holds none of them)."""
    base = draw(names)
    positions = [i for i, ch in enumerate(base) if ch in LOOKALIKES]
    if not positions:
        return base
    i = draw(st.sampled_from(positions))
    return base[:i] + draw(st.sampled_from(LOOKALIKES[base[i]])) + base[i + 1 :]


@st.composite
def with_risky_char(draw: st.DrawFn, names: st.SearchStrategy[str]) -> str:
    """A name from ``names`` with one risky character inserted at any position."""
    base = draw(names)
    i = draw(st.integers(min_value=0, max_value=len(base)))
    return base[:i] + draw(risky_chars) + base[i:]
