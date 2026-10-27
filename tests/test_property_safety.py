"""Property-based tests for the load-bearing safety logic (threat-model O5 part 2).

Hypothesis strategies over ``normalize_member_name``, ``check_universal``,
``resolve_link_target_name``, volume-sibling discovery, and format detection on a
peekable source. Each test asserts a structural **invariant** (not a golden oracle).
A shrunk counterexample must be pinned as an ``@example`` / unit case (task 0.3).

CI budget: the shared ``archivey`` Hypothesis profile in ``conftest.py``
(``max_examples=100``, ``deadline=None``, ``derandomize=True``). Deepen locally with
``ARCHIVEY_FUZZ_EXAMPLES=2000``.

``hypothesis`` is a ``dev``-group dependency; under ``[core-only]`` this module skips
collection so the suite still collects cleanly.
"""

from __future__ import annotations

import io
import logging
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

try:
    from hypothesis import example, given, strategies as st
except ImportError:  # pragma: no cover - [core-only] leg
    pytest.skip("hypothesis not installed (dev group)", allow_module_level=True)

from archivey.exceptions import (
    ArchiveyError,
    FilterRejectionError,
)
from archivey.internal.detection import detect_format
from archivey.internal.filters import _is_absolute, check_universal
from archivey.internal.logs import normalization as normalization_logger
from archivey.internal.naming import (
    normalize_member_name,
    resolve_link_target_name,
)
from archivey.internal.source import ArchiveSource
from archivey.internal.volumes import (
    _NUMBERED_VOLUME_RE,
    _OLD_RAR_CONTINUATION_RE,
    _RAR_PART_RE,
    _VOLUME_SCHEMES,
    _numbered_part_number,
    _rar_part_number,
    discover_volume_siblings,
    next_rar_volume_name,
    rar_volume_name,
)
from archivey.types import ArchiveMember, MemberType
from tests.risky_text import (
    risky_components,
    risky_text,
    with_lookalike,
    with_risky_char,
)
from tests.streams_util import NonSeekableBytesIO

# ---------------------------------------------------------------------------
# Shared fixtures + strategies
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _silence_normalization_logger() -> Iterator[None]:
    """Silence the (spec-permitted) normalization warnings for this module's runs.

    Module-scoped so it composes with ``@given`` (a function-scoped fixture would trip
    Hypothesis's health check), and restored afterwards so other test modules keep the
    logger's normal level.
    """
    old_level = normalization_logger.level
    normalization_logger.setLevel(logging.CRITICAL)
    yield
    normalization_logger.setLevel(old_level)


@pytest.fixture(scope="module")
def dest_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One extraction-root dir for all ``check_universal`` examples.

    The filter never writes under ``dest``; per-example tempdirs would only add
    thousands of mkdir/rmtree calls at the deep profile.
    """
    return tmp_path_factory.mktemp("dest")


_SEP_SPLIT = re.compile(r"[\\/]")

# Text that includes path-hostile characters (controls, surrogates, separators) without
# drowning in huge strings.
_name_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Z", "C"),
    ),
    min_size=0,
    max_size=64,
)

# Characters hostile to filesystem encodings: lone surrogates around the surrogateescape
# range (\udc80-\udcff encodes on POSIX; the rest raises), plus a NUL. Under the general
# text alphabet these are a vanishing slice (the derandomized 100-example budget draws
# zero surrogates; even 2000 examples drew one) — this dedicated branch makes the
# encoding-hostility *class* reachable on every run, not just via pinned @examples.
_hostile_encoding_chars = st.sampled_from(
    ["\ud800", "\udbff", "\udc00", "\udc7f", "\udc80", "\udcff", "\x00"]
)

_hostile_pathish = st.lists(
    st.one_of(
        st.sampled_from([".", "..", "a", "b", "dir"]),
        _hostile_encoding_chars,
        st.tuples(st.sampled_from(["a", "b"]), _hostile_encoding_chars).map("".join),
    ),
    min_size=1,
    max_size=4,
).map(lambda parts: "/".join(parts))

# A well-formed relative path for the risky branches below to alter.
_ascii_path = st.from_regex(r"[a-z0-9_.]{1,8}(/[a-z0-9_.]{1,8}){0,2}", fullmatch=True)

# Path-flavoured names: mix separators, dots, drives, UNC-ish prefixes, hostile encodings.
_pathish = st.one_of(
    _name_text,
    st.sampled_from(
        [
            "",
            ".",
            "..",
            "/",
            "\\",
            "../evil",
            "foo/../bar",
            "/etc/passwd",
            "C:\\Windows\\x",
            "C:foo",
            "\\\\server\\share",
            "a\x00b",
            "foo\\bar",
            "./x",
            "a//b/./c",
            "dir/",
            "..\\..\\x",
        ]
    ),
    st.lists(
        st.sampled_from([".", "..", "", "a", "b", "foo", "bar", "C:", "x\x00y"]),
        min_size=0,
        max_size=6,
    ).map(lambda parts: "/".join(parts)),
    st.lists(
        st.sampled_from([".", "..", "a", "b", "foo"]),
        min_size=1,
        max_size=5,
    ).map(lambda parts: "\\".join(parts)),
    _hostile_pathish,
    # Risky Unicode on its own, and swapped or inserted into a well-formed path so it
    # reaches the checks past the first separator split.
    risky_text(),
    with_lookalike(_ascii_path),
    with_risky_char(_ascii_path),
    st.lists(
        st.one_of(risky_components, st.sampled_from(["a", "..", "."])),
        min_size=1,
        max_size=3,
    ).map("/".join),
)

_member_types = st.sampled_from(list(MemberType))
_file_dir_types = st.sampled_from([MemberType.FILE, MemberType.DIRECTORY])
_link_types = st.sampled_from([MemberType.SYMLINK, MemberType.HARDLINK])

# Safe relative file names for the "never raises" side of check_universal.
_safe_file_name = st.from_regex(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,20}(/[A-Za-z0-9][A-Za-z0-9._-]{0,20}){0,3}",
    fullmatch=True,
).filter(lambda s: ".." not in s.split("/") and s not in ("", "."))

# The reject-side strategies below are built *constructively* rather than as
# ``_pathish.filter(...)``: the guaranteed-property fraction of _pathish is small (and
# shifts as _pathish grows — e.g. the hostile-encoding branch), which trips Hypothesis's
# ``filter_too_much`` health check on the floor version. Breadth of hostile characters in
# these classes is the totality test's job; here we only need the rule to fire reliably.
_plain_component = st.sampled_from([".", "a", "b", "foo", "bar", "x", "dir"])

# Guaranteed to contain a ``..`` path component (on either separator).
_dotdot_names = st.builds(
    lambda pre, post, sep: sep.join([*pre, "..", *post]),
    st.lists(_plain_component, max_size=3),
    st.lists(_plain_component, max_size=3),
    st.sampled_from(["/", "\\"]),
)

# Guaranteed absolute: POSIX root, UNC/rooted backslash, or a drive letter.
_relative_tail = st.lists(_plain_component, min_size=0, max_size=3).map("/".join)
_absolute_names = st.one_of(
    _relative_tail.map(lambda tail: "/" + tail),
    _relative_tail.map(lambda tail: "\\" + tail),
    st.builds(
        lambda drive, tail: f"{drive}:{tail}",
        st.sampled_from(["C", "D", "Z"]),
        _relative_tail,
    ),
)

# Guaranteed absolute *symlink target* (starts with ``/`` → resolves to ``None``).
_absolute_targets = _pathish.map(lambda t: "/" + t)


def _components_after_sep(name: str, *, backslash_is_separator: bool) -> list[str]:
    """Path components after optional ``\\``→``/`` conversion (empty/``.`` dropped)."""
    s = name.replace("\\", "/") if backslash_is_separator else name
    return [p for p in s.split("/") if p not in (".", "")]


def _had_leading_absolute_meaning(name: str, *, backslash_is_separator: bool) -> bool:
    if name.startswith("/"):
        return True
    return backslash_is_separator and name.startswith("\\")


def _member(
    name: str,
    *,
    type: MemberType = MemberType.FILE,
    link_target: str | None = None,
) -> ArchiveMember:
    # Avoid encode failures on lone surrogates; raw_name is unused by check_universal.
    return ArchiveMember(
        type=type,
        name=name,
        raw_name=None,
        link_target=link_target,
    )


def _has_dotdot_component(name: str) -> bool:
    return ".." in _SEP_SPLIT.split(name)


# ---------------------------------------------------------------------------
# 2. normalize_member_name
# ---------------------------------------------------------------------------


@given(
    decoded=_pathish,
    member_type=_member_types,
    backslash_is_separator=st.booleans(),
)
def test_normalize_total_and_idempotent(
    decoded: str,
    member_type: MemberType,
    backslash_is_separator: bool,
) -> None:
    out = normalize_member_name(
        decoded, member_type, backslash_is_separator=backslash_is_separator
    )
    again = normalize_member_name(
        out, member_type, backslash_is_separator=backslash_is_separator
    )
    assert isinstance(out, str)
    assert again == out


@given(
    decoded=_pathish,
    member_type=_member_types,
    backslash_is_separator=st.booleans(),
)
def test_normalize_never_introduces_escape(
    decoded: str,
    member_type: MemberType,
    backslash_is_separator: bool,
) -> None:
    out = normalize_member_name(
        decoded, member_type, backslash_is_separator=backslash_is_separator
    )
    in_parts = _components_after_sep(
        decoded, backslash_is_separator=backslash_is_separator
    )
    out_parts = [p for p in out.split("/") if p not in (".", "")]
    if ".." in out_parts:
        assert ".." in in_parts
    if out.startswith("/"):
        assert _had_leading_absolute_meaning(
            decoded, backslash_is_separator=backslash_is_separator
        )


@given(decoded=_pathish, member_type=_file_dir_types)
def test_normalize_backslash_flag(decoded: str, member_type: MemberType) -> None:
    with_sep = normalize_member_name(decoded, member_type, backslash_is_separator=True)
    literal = normalize_member_name(decoded, member_type, backslash_is_separator=False)
    if "\\" in decoded:
        # With the flag, every backslash becomes a separator (no literal ``\\`` left
        # unless the input had a forward-slash-only path — then both match).
        assert "\\" not in with_sep
        # Without the flag, backslashes are filename characters and survive unless
        # other rules drop the whole segment set to ``.``.
        if literal != ".":
            assert "\\" in literal or literal == with_sep


@example(
    decoded="foo/../bar", member_type=MemberType.FILE, backslash_is_separator=False
)
@example(
    decoded="/etc/passwd", member_type=MemberType.FILE, backslash_is_separator=False
)
@example(decoded="foo\\bar", member_type=MemberType.FILE, backslash_is_separator=True)
@given(
    decoded=_pathish,
    member_type=_member_types,
    backslash_is_separator=st.booleans(),
)
def test_normalize_pinned_examples_still_hold(
    decoded: str,
    member_type: MemberType,
    backslash_is_separator: bool,
) -> None:
    # Explicit @example pins; body reuses the total/idempotent invariant.
    out = normalize_member_name(
        decoded, member_type, backslash_is_separator=backslash_is_separator
    )
    assert isinstance(out, str)
    assert (
        normalize_member_name(
            out, member_type, backslash_is_separator=backslash_is_separator
        )
        == out
    )


# ---------------------------------------------------------------------------
# 3. check_universal
# ---------------------------------------------------------------------------


@given(name=_dotdot_names)
def test_check_universal_rejects_dotdot(dest_root: Path, name: str) -> None:
    assert _has_dotdot_component(name)  # strategy guarantees the class under test
    with pytest.raises(FilterRejectionError):
        check_universal(_member(name), dest_root)


@given(name=_absolute_names)
def test_check_universal_rejects_absolute(dest_root: Path, name: str) -> None:
    assert _is_absolute(name)  # strategy guarantees the class under test
    with pytest.raises(FilterRejectionError):
        check_universal(_member(name), dest_root)


@given(
    prefix=st.text(min_size=0, max_size=20).filter(lambda s: "\x00" not in s),
    suffix=st.text(min_size=0, max_size=20).filter(lambda s: "\x00" not in s),
)
def test_check_universal_rejects_null_byte(
    dest_root: Path, prefix: str, suffix: str
) -> None:
    name = prefix + "\x00" + suffix
    with pytest.raises(FilterRejectionError):
        check_universal(_member(name), dest_root)


@given(name=st.sampled_from(["", ".", "./", ".//"]))
def test_check_universal_rejects_root_named_file(dest_root: Path, name: str) -> None:
    # After strip of trailing ``/``, these refer to the extraction root as a file.
    rel = name.rstrip("/")
    if rel not in ("", "."):
        return
    with pytest.raises(FilterRejectionError):
        check_universal(_member(name, type=MemberType.FILE), dest_root)


@given(name=_safe_file_name)
def test_check_universal_allows_safe_relative_file(dest_root: Path, name: str) -> None:
    check_universal(_member(name, type=MemberType.FILE), dest_root)


# Pinned counterexamples (task 0.3): a lone high surrogate in a non-final component
# (or in a link target) used to escape as a raw UnicodeEncodeError from the parent /
# link-target resolution; an embedded NUL in a link target as a raw ValueError. Fixed
# in filters.py by typed string-level rejections before any resolve.
@example(name="\ud800/x", member_type=MemberType.FILE, link_target=None)
@example(name="lnk", member_type=MemberType.SYMLINK, link_target="\ud800")
@example(name="lnk", member_type=MemberType.HARDLINK, link_target="a/\ud800/b")
@example(name="lnk", member_type=MemberType.SYMLINK, link_target="a\x00b")
@given(
    name=_pathish,
    member_type=_member_types,
    link_target=st.one_of(st.none(), _pathish),
)
def test_check_universal_total(
    dest_root: Path,
    name: str,
    member_type: MemberType,
    link_target: str | None,
) -> None:
    try:
        check_universal(
            _member(name, type=member_type, link_target=link_target), dest_root
        )
    except ArchiveyError:
        pass
    except Exception as exc:  # noqa: BLE001 — property: no raw exceptions
        pytest.fail(f"raw exception from check_universal: {type(exc).__name__}: {exc}")


# A hardlink target the platform cannot encode is fine: the string never reaches the OS.
@example(name="0", member_type=MemberType.HARDLINK, link_target="\ud800")
@given(
    name=_pathish,
    member_type=_member_types,
    link_target=st.one_of(st.none(), _pathish),
)
def test_check_universal_accepts_only_materializable(
    dest_root: Path,
    name: str,
    member_type: MemberType,
    link_target: str | None,
) -> None:
    # Accept-side invariant (brackets the surrogate counterexample from the other
    # direction): whatever check_universal *accepts* must be materializable on the
    # filesystem — its name, and a link target it will os.symlink/link, must both
    # os.fsencode. A name the platform cannot encode has to be rejected, not passed
    # through to crash the extractor's mkdir/symlink. On POSIX only the surrogateescape
    # range encodes; Windows' surrogatepass encodes every lone surrogate, so this stays
    # a tautology there rather than a false failure.
    try:
        check_universal(
            _member(name, type=member_type, link_target=link_target), dest_root
        )
    except ArchiveyError:
        return  # rejected — nothing to materialize
    # Accepted: the name (and a symlink's target, which the extractor writes) must
    # encode. A hardlink's target is never written: it names an earlier member, and
    # the link is made to the file that member became (see ``check_universal``).
    os.fsencode(name)
    if link_target is not None and member_type is MemberType.SYMLINK:
        os.fsencode(link_target)


# ---------------------------------------------------------------------------
# 4. resolve_link_target_name
# ---------------------------------------------------------------------------


@given(link_name=_pathish, target=_pathish, member_type=_link_types)
def test_resolve_link_total(
    link_name: str, target: str, member_type: MemberType
) -> None:
    try:
        result = resolve_link_target_name(link_name, target, member_type)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(
            f"raw exception from resolve_link_target_name: {type(exc).__name__}: {exc}"
        )
    assert result is None or isinstance(result, str)


@given(link_name=_pathish, target=_absolute_targets)
def test_resolve_symlink_absolute_is_none(link_name: str, target: str) -> None:
    assert target.startswith("/")  # strategy guarantees the class under test
    assert resolve_link_target_name(link_name, target, MemberType.SYMLINK) is None


@example(link_name="a/b", target="../x", member_type=MemberType.HARDLINK)
@given(link_name=_pathish, target=_pathish, member_type=_link_types)
def test_resolve_link_never_returns_escaping_name(
    link_name: str, target: str, member_type: MemberType
) -> None:
    """A symlink target, and a hardlink-kind target under ``within_root`` (a RAR file
    copy), never resolves outside the archive namespace. A plain hardlink target is a
    member name and may (``../x``); extraction refuses a link whose source was
    refused."""
    result = resolve_link_target_name(link_name, target, member_type, within_root=True)
    if result is None:
        return
    # Returned names must not escape the archive namespace (same gate as the impl).
    # A hardlink target keeps a leading "/": it names the member stored with one
    # (``tar -P``).
    if member_type is MemberType.HARDLINK:
        result = result.lstrip("/")
    assert result not in ("", ".", "/", "..")
    assert not result.startswith("../")
    assert not result.startswith("/")


@given(
    link_dir=st.from_regex(
        r"[A-Za-z0-9_]{1,8}(/[A-Za-z0-9_]{1,8}){0,2}", fullmatch=True
    ),
    target=st.from_regex(r"[A-Za-z0-9_]{1,12}", fullmatch=True),
)
def test_resolve_symlink_joins_to_link_dir(link_dir: str, target: str) -> None:
    link_name = f"{link_dir}/link"
    result = resolve_link_target_name(link_name, target, MemberType.SYMLINK)
    assert result == f"{link_dir}/{target}"


@given(
    target=st.from_regex(
        r"[A-Za-z0-9_]{1,12}(/[A-Za-z0-9_]{1,8}){0,2}", fullmatch=True
    ),
)
def test_resolve_hardlink_uses_target_as_archive_path(target: str) -> None:
    result = resolve_link_target_name("ignored/link", target, MemberType.HARDLINK)
    assert result == target


@example(target="../x")
@example(target="/../a")
@example(target="a/../b")
@given(target=_pathish)
def test_resolve_hardlink_keeps_dot_dot_like_a_member_name(target: str) -> None:
    """Without ``within_root``, a hardlink target resolves to the name
    ``normalize_member_name`` gives a member stored under it, ``..`` included."""
    result = resolve_link_target_name("ignored/link", target, MemberType.HARDLINK)
    if result is None:
        return
    assert result == normalize_member_name(
        target, MemberType.FILE, backslash_is_separator=False
    )


@example(link_name="a/b", target="../x", member_type=MemberType.SYMLINK)
@example(link_name="a/b", target="/etc/passwd", member_type=MemberType.SYMLINK)
@example(link_name="a/b", target="../../x", member_type=MemberType.HARDLINK)
@given(link_name=_pathish, target=_pathish, member_type=_link_types)
def test_resolve_link_pinned_examples(
    link_name: str, target: str, member_type: MemberType
) -> None:
    result = resolve_link_target_name(link_name, target, member_type)
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# 5. Volume discovery (pure parse + tmp_path discovery)
# ---------------------------------------------------------------------------


# ``[0-9]``, not ``\d``: on a ``str`` pattern ``\d`` draws any Unicode digit, which
# reached ``0.7z.\u066000`` only by luck. The lookalike branch draws that class on
# purpose, one swapped digit, dot or letter in an otherwise valid volume name.
_valid_volume_names = st.one_of(
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.7z\.[0-9]{1,4}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.zip\.[0-9]{1,4}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.exe\.[0-9]{1,4}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.z[0-9]{2,3}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.part[0-9]{1,3}\.rar", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.part[0-9]{1,3}\.sfx", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.r[0-9]{2}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_]{1,12}\.rar", fullmatch=True),
)
_volume_style_names = st.one_of(
    _valid_volume_names,
    with_lookalike(_valid_volume_names),
    with_risky_char(_valid_volume_names),
    _name_text,
)


# A part number past ``sys.get_int_max_str_digits()`` (4300 by default) made ``int()``
# raise, which the strategy's short digit runs never reach.
@example(name="x.zip." + "1" * 5000)
@example(name="x.part" + "1" * 5000 + ".rar")
@example(name="x.part" + "1" * 5000 + ".exe")
# The old-scheme letter past ``U+10FFFF`` has no successor, and ``chr()`` raised.
@example(name="a.\U0010ffff99")
@given(name=_volume_style_names)
def test_volume_part_helpers_total(name: str) -> None:
    for number in (
        _numbered_part_number(name),
        _rar_part_number(name),
    ):
        assert isinstance(number, int) and number >= 0
    following = next_rar_volume_name(name, old_numbering=True)
    assert following is None or isinstance(following, str)
    # Regex matchers themselves must not raise.
    _NUMBERED_VOLUME_RE.match(name)
    _RAR_PART_RE.match(name)
    _OLD_RAR_CONTINUATION_RE.match(name)


# Discovery classifies a name by the first scheme that matches, so the schemes'
# trailing anchors must keep them disjoint: ``my.part1.zip.001`` is numbered only.
@example(name="my.part1.zip.001")
@example(name="my.part1.exe")
@example(name="my.part1.r00")
# ``\d`` matched Arabic-Indic zeros, so this was numbered and old-scheme RAR at once.
@example(name="0.7z.\u066000")
@given(name=_volume_style_names)
def test_volume_schemes_are_disjoint(name: str) -> None:
    matched = [p.pattern for p in _VOLUME_SCHEMES if p.match(name) is not None]
    assert len(matched) <= 1, matched


# ``rar_volume_name`` is the closed form of unrar's next-name walk: archivey stages a
# set under these names, and unrar must find each one from the one before it.
# A newline in the stem defeated the ``.partN`` pattern's ``.`` until it took
# ``re.DOTALL``, and the walk stopped after volume 1.
@example(stem="a\nb", index=1, old_numbering=False)
@given(
    # Name punctuation is drawn often, so stems like ``x.part3`` come up.
    stem=st.text(
        st.one_of(
            st.sampled_from(".partPART0189"), st.characters(blacklist_characters="/")
        ),
        max_size=12,
    ),
    index=st.integers(min_value=1, max_value=1499),
    old_numbering=st.booleans(),
)
def test_rar_volume_name_is_the_next_name_unrar_walks(
    stem: str, index: int, old_numbering: bool
) -> None:
    current = rar_volume_name(stem, index, old_numbering=old_numbering)
    assert next_rar_volume_name(
        current, old_numbering=old_numbering
    ) == rar_volume_name(stem, index + 1, old_numbering=old_numbering)


@given(
    # A base ending in `.partN` is the shape that used to capture the numbered-volume
    # key: every part of `my.part1.zip.001 … .003` parsed as 1, so concatenation order
    # fell back to whatever `iterdir` returned.
    base=st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,8}(\.part[1-9])?", fullmatch=True),
    extension=st.sampled_from(["7z", "zip", "exe"]),
    parts=st.lists(
        st.integers(min_value=1, max_value=99), min_size=2, max_size=5, unique=True
    ),
)
def test_volume_part_numbers_sort_stable(
    base: str, extension: str, parts: list[int]
) -> None:
    names = [f"{base}.{extension}.{p:03d}" for p in parts]
    parsed = [_numbered_part_number(n) for n in names]
    assert parsed == parts
    assert sorted(parsed) == sorted(parts)
    assert len(parsed) == len(set(parsed))


@given(
    scheme=st.sampled_from(["7z", "exe", "rar_part", "rar_sfx", "rar_rnn"]),
    base=st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,8}", fullmatch=True),
    n_parts=st.integers(min_value=2, max_value=4),
    missing_anchor=st.booleans(),
)
def test_discover_volume_siblings_total(
    scheme: str,
    base: str,
    n_parts: int,
    missing_anchor: bool,
) -> None:
    names: list[str]
    if scheme == "7z":
        names = [f"{base}.7z.{i:03d}" for i in range(1, n_parts + 1)]
    elif scheme == "exe":
        names = [f"{base}.exe.{i:03d}" for i in range(1, n_parts + 1)]
    elif scheme == "rar_part":
        names = [f"{base}.part{i}.rar" for i in range(1, n_parts + 1)]
    elif scheme == "rar_sfx":
        names = [f"{base}.part1.sfx"] + [
            f"{base}.part{i}.rar" for i in range(2, n_parts + 1)
        ]
    else:
        names = [f"{base}.rar"] + [f"{base}.r{i:02d}" for i in range(n_parts - 1)]

    if missing_anchor and names:
        # Drop the first volume so discovery must return None or a partial set safely.
        names = names[1:]

    with tempfile.TemporaryDirectory() as root:
        root_path = Path(root)
        for name in names:
            (root_path / name).write_bytes(b"")

        if not names:
            return
        anchor = root_path / names[0]
        try:
            result = discover_volume_siblings(anchor)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"raw exception from discover_volume_siblings: "
                f"{type(exc).__name__}: {exc}"
            )
        assert result is None or isinstance(result, list)
        if result is not None:
            assert len(result) >= 2
            assert all(isinstance(p, Path) for p in result)
            # Ordered by part number — no duplicates.
            assert len(result) == len(set(result))


def test_discover_volume_siblings_missing_path(tmp_path: Path) -> None:
    assert discover_volume_siblings(tmp_path / "nope.7z.001") is None


# ---------------------------------------------------------------------------
# 5.2 Detection over arbitrary peekable prefixes
# ---------------------------------------------------------------------------


@given(data=st.binary(min_size=0, max_size=512))
def test_detect_format_peekable_total_and_unadvanced(data: bytes) -> None:
    stream = ArchiveSource.for_stream(NonSeekableBytesIO(data))
    try:
        detect_format(stream)
    except ArchiveyError:
        pass  # typically FormatDetectionError; any typed error satisfies totality
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"raw exception from detect_format: {type(exc).__name__}: {exc}")
    # Peek/replay invariant: nothing consumed; full prefix still readable.
    assert stream.read(len(data)) == data
    assert stream.read(1) == b""


@given(data=st.binary(min_size=0, max_size=512))
def test_detect_format_bytesio_total_and_rewound(data: bytes) -> None:
    buf = io.BytesIO(data)
    try:
        detect_format(buf)
    except ArchiveyError:
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"raw exception from detect_format: {type(exc).__name__}: {exc}")
    assert buf.tell() == 0


@example(data=b"")
@example(data=b"\x00" * 64)
@example(data=b"PK\x03\x04" + b"\x00" * 32)
@given(data=st.binary(min_size=0, max_size=256))
def test_detect_format_pinned_examples(data: bytes) -> None:
    buf = io.BytesIO(data)
    try:
        detect_format(buf)
    except ArchiveyError:
        pass
    assert buf.tell() == 0
