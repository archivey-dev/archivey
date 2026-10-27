"""Path helpers for a front end: destination naming rules, and member selection by glob.

A front end that moves or renames what extraction wrote should name things the way
extraction does, so the result is the one a direct extraction would have given.
archivey's own CLI moves a single top-level directory up out of its wrapper folder
with this rule.

The library's ``members=``, ``get()`` and ``open()`` match stored names exactly. A caller
who wants shell-style patterns passes :func:`match_glob` or :func:`match_tar_glob` as
``members=``. They read the same pattern differently, so pick the one whose rules you
want: ``"*.md"`` is top-level ``.md`` files to one and ``.md`` files at any depth to the
other.

**Public, not re-exported.** Import from here (``from archivey.paths import
numbered_name``); these names are not in :mod:`archivey`. Everything in ``__all__``
carries the same compatibility promise as ``archivey.__all__``.

- :func:`numbered_name` — the ``name (N)`` spelling of an
  ``OverwritePolicy.RENAME`` rename.
- :func:`match_glob` — a ``members=`` predicate from glob patterns, where ``*`` stays
  inside one folder and ``**`` matches any depth. archivey's own CLI matches this way.
- :func:`match_tar_glob` — a ``members=`` predicate from ``tar``-style patterns, where
  ``*`` also matches ``/`` and a folder's name selects everything in it.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePath
from typing import TYPE_CHECKING

from archivey.exceptions import _UsageValueError

if TYPE_CHECKING:
    from collections.abc import Callable

    from archivey.types import ArchiveMember

__all__ = ["match_glob", "match_tar_glob", "numbered_name"]


def numbered_name(name: str, n: int, *, is_dir: bool) -> str:
    """Return ``name`` with the counter ``n`` added, as ``OverwritePolicy.RENAME`` spells it.

    When a member's destination is taken, ``OverwritePolicy.RENAME`` writes it under the
    first free name of this form, counting from ``n=1``. A file keeps its extension:
    the counter goes before the final suffix. A directory has no suffix, so the counter
    goes after the whole name.

    ``name`` is a single path component, not a path: only its final suffix moves.

    >>> numbered_name("photo.jpg", 1, is_dir=False)
    'photo (1).jpg'
    >>> numbered_name("notes.tar.gz", 2, is_dir=False)
    'notes.tar (2).gz'
    >>> numbered_name("photos.2024", 1, is_dir=True)
    'photos.2024 (1)'

    Args:
        name: The name that is taken.
        n: The counter, ``1`` or more.
        is_dir: Whether ``name`` is a directory.

    Returns:
        The candidate name. This function does not look at the filesystem: the caller
        checks whether the candidate is free and tries ``n + 1`` when it is not.
    """
    if is_dir:
        return f"{name} ({n})"
    path = PurePath(name)
    return f"{path.stem} ({n}){path.suffix}"


def match_glob(
    *patterns: str, with_contents: bool = False
) -> Callable[[ArchiveMember | str], bool]:
    """Return a ``members=`` predicate that selects the members matching any of ``patterns``.

    >>> with archivey.open_archive("site.zip") as archive:  # doctest: +SKIP
    ...     archive.extract_all("out/", members=match_glob("docs/**", "*.md"))

    The patterns are matched against the whole member name, ``/``-separated, and
    case-sensitively:

    - ``*`` matches any run of characters inside one folder: ``*.md`` selects
      ``README.md`` but not ``docs/guide.md``.
    - ``?`` matches one character other than ``/``.
    - ``[abc]``, ``[a-z]`` and ``[!abc]`` match one character from, or not from, the set,
      never ``/``. ``[*]`` matches a literal ``*``.
    - ``**`` as a whole path component matches any number of folders, including none:
      ``**/*.md`` selects ``README.md`` and ``docs/api/guide.md``, and ``docs/**``
      selects the ``docs/`` folder and everything under it. Elsewhere, ``**`` is ``*``.

    ``*`` and ``?`` match a leading ``.`` too, so hidden files are not skipped.

    A directory member is matched by its name without the trailing ``/``, so ``docs/*``
    selects the folder ``docs/api/`` as well as the file ``docs/index.md``. A pattern that
    ends in ``/`` selects only directories: ``*/`` selects every top-level folder.

    With ``with_contents=True``, a member is also selected when a folder it is in
    matches, so a folder comes with everything under it: ``match_glob("docs",
    with_contents=True)`` selects ``docs/`` and ``docs/api/guide.md``, and
    ``match_glob("*/", with_contents=True)`` selects everything that is in a folder.
    archivey's command-line tool matches its patterns this way.

    A ``\\`` in a pattern is an ordinary character, on Windows too, because member names
    use ``/`` and a TAR member name can contain a ``\\``.

    A pattern that matches nothing is not reported: ``MEMBER_SELECTOR_UNMATCHED`` covers
    only the names in the collection form of ``members=``.

    For ``tar``'s rules, where
    ``*`` also matches ``/`` and ``docs`` selects the folder and everything in it, use
    :func:`match_tar_glob`: ``match_tar_glob("*.md")`` selects ``.md`` files at every
    depth, while ``match_glob("*.md")`` selects top-level ones only.

    Args:
        *patterns: One or more glob patterns. A member is selected when any of them
            matches.
        with_contents: Also select every member inside a matching folder.

    Returns:
        A callable that takes an :class:`~archivey.ArchiveMember` and returns whether it
        is selected. It also takes a member name as a ``str``, where a trailing ``/``
        marks a directory.

    Raises:
        ArchiveyUsageError: No pattern was given, a pattern has an empty component
            (``""``, ``"/"``, ``"a//b"``; a leading ``/`` is allowed), or a ``[...]``
            set is malformed, such as the reversed range ``[z-a]``. It is also a
            ``ValueError``.
    """
    return _MemberGlob(patterns, with_contents=with_contents)


def match_tar_glob(*patterns: str) -> Callable[[ArchiveMember | str], bool]:
    """Return a ``members=`` predicate that matches ``patterns`` the way ``tar`` does.

    >>> with archivey.open_archive("site.tar") as archive:  # doctest: +SKIP
    ...     archive.extract_all("out/", members=match_tar_glob("docs", "*.md"))

    Each pattern is matched against the whole member name with
    ``fnmatch.fnmatchcase``, so it is case-sensitive and:

    - ``*`` matches any run of characters, ``/`` included: ``*.md`` selects
      ``README.md`` and ``docs/api/guide.md``. ``**`` is the same as ``*``.
    - ``?`` matches any one character, ``[abc]`` / ``[!abc]`` one character from, or not
      from, the set.
    - A pattern that names a folder, with or without its trailing ``/``, selects the
      folder and everything under it: ``docs`` and ``docs/`` both select ``docs/`` and
      ``docs/api/guide.md``, but not a file named ``docs.txt``.

    For patterns where ``*`` stays inside one folder, use :func:`match_glob`. A ``\\`` in
    a pattern is an ordinary character, on Windows too. A pattern that matches nothing is
    not reported.

    Args:
        *patterns: One or more patterns. A member is selected when any of them matches.

    Returns:
        A callable that takes an :class:`~archivey.ArchiveMember`, or a member name as a
        ``str``, and returns whether it is selected.

    Raises:
        ArchiveyUsageError: No pattern was given, or a pattern has an empty component
            (``""``, ``"/"``, ``"a//b"``; a leading ``/`` is allowed). It is also a
            ``ValueError``.
    """
    return _TarGlob(patterns)


class _TarGlob:
    """The predicate :func:`match_tar_glob` returns; its ``repr`` names the patterns."""

    __slots__ = ("_forms", "patterns")

    def __init__(self, patterns: tuple[str, ...]) -> None:
        if not patterns:
            raise _UsageValueError("match_tar_glob() needs at least one pattern")
        for pattern in patterns:
            # The same rule as match_glob: member names never hold an empty component,
            # so a pattern with one ("", "/", "a//b", "docs//") could match nothing.
            body = pattern.removesuffix("/")
            if not body.strip("/") or "" in body.split("/")[1:]:
                raise _UsageValueError(
                    f"match_tar_glob(): {pattern!r} has an empty component; a pattern "
                    "must name something between its '/' separators"
                )
        self.patterns = patterns
        forms: list[str] = []
        for pattern in patterns:
            base = pattern.rstrip("/")
            # The pattern as written; and, for a folder named without or with its "/",
            # the folder entry and everything under it. "*" matching "/" is what makes
            # "base/*" reach every depth.
            forms.extend((pattern, base + "/", base + "/*"))
        # dict.fromkeys: "docs/" as written is already its own "base + /" form.
        self._forms = tuple(dict.fromkeys(forms))

    def __call__(self, member: ArchiveMember | str) -> bool:
        name = member if isinstance(member, str) else member.name
        # fnmatchcase: the same answer on every platform (fnmatch folds case on Windows).
        return any(fnmatch.fnmatchcase(name, form) for form in self._forms)

    def __repr__(self) -> str:
        return f"match_tar_glob({', '.join(map(repr, self.patterns))})"


class _MemberGlob:
    """The predicate :func:`match_glob` returns; its ``repr`` names the patterns."""

    __slots__ = ("_any", "_dirs_only", "patterns", "with_contents")

    def __init__(self, patterns: tuple[str, ...], *, with_contents: bool) -> None:
        if not patterns:
            raise _UsageValueError("match_glob() needs at least one pattern")
        for pattern in patterns:
            # Member names never hold an empty component ("a//b" is stored as "a/b"),
            # so one in a pattern could match nothing. A leading "/" is not one: an
            # absolute member name keeps it, and "/etc/**" selects "/etc/passwd".
            body = pattern.removesuffix("/")
            if not body.strip("/") or "" in body.split("/")[1:]:
                raise _UsageValueError(
                    f"match_glob(): {pattern!r} has an empty component; a pattern "
                    "must name something between its '/' separators"
                )
            try:
                re.compile(_glob_to_regex(body))
            except re.error as exc:
                # exc.msg, not str(exc): the position it adds is in the translated
                # regex, not in the caller's pattern.
                raise _UsageValueError(
                    f"match_glob(): {pattern!r} has a malformed [...] set: {exc.msg}"
                ) from None
        self.patterns = patterns
        self.with_contents = with_contents
        # Patterns ending in "/" select directories only, so they get their own regex.
        any_kind = [p for p in patterns if not p.endswith("/")]
        dirs_only = [p.removesuffix("/") for p in patterns if p.endswith("/")]
        any_kind_regexes = [f"(?:{_glob_to_regex(p)})" for p in any_kind]
        dirs_only_regexes = [f"(?:{_glob_to_regex(p)})" for p in dirs_only]
        self._dirs_only = _compile_alternatives(dirs_only_regexes)
        if with_contents:
            # A member inside a matching folder: the name continues past a "/" after a
            # prefix the pattern matches. That prefix is a folder, so a dirs-only
            # pattern counts for it too. (?<=.): a "/" at index 0 starts an absolute
            # name and ends no folder.
            contents = "(?:(?<=.)/.+)"
            any_kind_regexes = [f"{r}{contents}?" for r in any_kind_regexes] + [
                f"{r}{contents}" for r in dirs_only_regexes
            ]
        self._any = _compile_alternatives(any_kind_regexes)

    def __call__(self, member: ArchiveMember | str) -> bool:
        if isinstance(member, str):
            name = member
            is_dir = name.endswith("/")
        else:
            name = member.name
            # Every directory name ends in "/" except the root entry ".", which a
            # "tar cf x.tar ." archive lists; is_dir is what marks that one.
            is_dir = member.is_dir or name.endswith("/")
        name = name.removesuffix("/")
        if self._any is not None and self._any.fullmatch(name):
            return True
        return bool(
            is_dir and self._dirs_only is not None and self._dirs_only.fullmatch(name)
        )

    def __repr__(self) -> str:
        args = ", ".join(map(repr, self.patterns))
        return (
            f"match_glob({args}{', with_contents=True' if self.with_contents else ''})"
        )


def _compile_alternatives(regexes: list[str]) -> re.Pattern[str] | None:
    if not regexes:
        return None
    # DOTALL: a member name can contain a newline, and "**" becomes ".*".
    return re.compile("|".join(regexes), re.DOTALL)


def _glob_to_regex(pattern: str) -> str:
    """Translate one glob pattern into a regex for ``fullmatch`` on a ``/``-joined name."""
    out: list[str] = []
    # Whether the regex so far ends in a component, so the next component needs a "/"
    # before it. A "**" component supplies its own separators.
    after_component = False
    # A run of "**" components selects what one does; collapsing it also keeps the
    # regex from holding several optional groups that backtrack against each other.
    components: list[str] = []
    for component in pattern.split("/"):
        if not (component == "**" and components and components[-1] == "**"):
            components.append(component)
    for index, component in enumerate(components):
        last = index == len(components) - 1
        if component == "**":
            if last:
                # "a/**" also matches "a" itself; a pattern of just "**" matches anything.
                out.append("(?:/.*)?" if after_component else ".*")
            else:
                out.append("(?:/.+)?/" if after_component else "(?:.+/)?")
            after_component = False
            continue
        if after_component:
            out.append("/")
        out.append(_component_to_regex(component))
        after_component = True
    return "".join(out)


def _component_to_regex(component: str) -> str:
    out: list[str] = []
    i, n = 0, len(component)
    while i < n:
        c = component[i]
        i += 1
        if c == "*":
            # "**" inside a component is one "*", as in pathlib and glob.
            while i < n and component[i] == "*":
                i += 1
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i
            if j < n and component[j] == "!":
                j += 1
            if j < n and component[j] == "]":
                j += 1
            while j < n and component[j] != "]":
                j += 1
            if j >= n:
                # No closing "]": the "[" is an ordinary character, as in fnmatch.
                out.append(re.escape(c))
                continue
            body = component[i:j]
            i = j + 1
            negate = body.startswith("!")
            if negate:
                body = body[1:]
            body = _set_body_to_regex(body)
            # The lookahead refuses "/"; putting "/" inside the set would join it to the
            # caller's characters ("[!-a]" would become the range "/-a").
            out.append(f"(?!/)[{'^' if negate else ''}{body}]")
        else:
            out.append(re.escape(c))
    return "".join(out)


def _set_body_to_regex(body: str) -> str:
    """Escape a ``[...]`` body for a regex class, keeping only the ``-`` of each range.

    Every other character is escaped, so ``re`` never sees a ``--`` it could read as set
    difference (it warns about that) or a ``&&``, ``~~`` or ``||``. A reversed range such
    as ``z-a`` still reaches ``re`` and raises ``re.error``.
    """
    out: list[str] = []
    k = 0
    while k < len(body):
        if k + 2 < len(body) and body[k + 1] == "-":
            out.append(f"{re.escape(body[k])}-{re.escape(body[k + 2])}")
            k += 3
        else:
            out.append(re.escape(body[k]))
            k += 1
    return "".join(out)
