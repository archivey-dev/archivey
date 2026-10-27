"""Member-name normalization and link-target name resolution.

Implements the ``ArchiveMember.name`` normalization rules from the
``archive-data-model`` spec. Format backends call :func:`normalize_member_name`
when decoding a stored name so that every backend produces names under the same
deterministic rules, while keeping the verbatim bytes in ``ArchiveMember.raw_name``.
:func:`resolve_link_target_name` maps a link member's stored target string to the
archive-namespace name it refers to (see ``archive-reading``: link following).
"""

from __future__ import annotations

import os
import posixpath
import re
import unicodedata
from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Literal

from archivey.diagnostics import (
    DiagnosticCode,
    MemberNameControlsContext,
    NameNormalizationContext,
    raw_name_to_base64,
)
from archivey.internal.logs import normalization as logger
from archivey.terminal import quoted
from archivey.types import MemberType, StreamFormat

if TYPE_CHECKING:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.types import ArchiveMember

# Unicode bidi formatting controls can make the displayed order of a filename differ
# materially from its stored order (for example, disguising an executable suffix).
#
# TWO SETS, AND THE DIFFERENCE MATTERS. Everything here is worth *telling* a caller
# about; only the reordering subset below is refused during extraction.
BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)

# The embeddings, overrides and isolates: U+202A-202E (LRE/RLE/PDF/LRO/RLO) and
# U+2066-2069 (LRI/RLI/FSI/PDI). These open a *span* and reorder the surrounding text,
# which is exactly and only what the "\u2026gnp.exe" disguise needs.
#
# Deliberately NOT the three directional marks in the set above (U+061C ALM, U+200E LRM,
# U+200F RLM): those set the direction of a single neutral character, reorder nothing,
# and do occur in legitimate Arabic and Hebrew filenames. Enumerated rather than written
# as `BIDI_CONTROLS - {marks}` so the marks stay one deliberate edit away from being
# rejected, not one typo away.
BIDI_REORDERING_CONTROLS = frozenset(
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)

# The other Unicode format characters (category Cf) display as nothing, so a name that
# holds one looks like a name that does not: "invoice\u200b.pdf" beside "invoice.pdf".
#
# TWO CODES AGAIN, split the way the bidi sets are. These three have no use inside a
# filename: zero-width space U+200B, word joiner U+2060 and BOM / zero-width no-break
# space U+FEFF. They get MEMBER_NAME_ZERO_WIDTH_CHARACTER, which is in
# ARCHIVE_INTEGRITY_CODES, so the STRICT *diagnostic policy* raises on it. Every other
# Cf character gets the advisory MEMBER_NAME_INVISIBLE_CHARACTER: ZWJ U+200D and ZWNJ
# U+200C are part of emoji sequences and of Persian and Indic spelling, the tag
# characters U+E0020-E007F spell subdivision flags, and a soft hyphen U+00AD is a
# hyphenation hint. No extraction filter refuses either set: writing them is safe
# (DR-17), only the name read back later can mislead.
ZERO_WIDTH_CHARACTERS = frozenset("\u200b\u2060\ufeff")

_Category = Literal["bidi", "zero_width", "invisible"]


def _emit_name_controls(
    collector: DiagnosticCollector,
    *,
    member: ArchiveMember,
    text: str,
    field: Literal["name", "link_target"],
    archive_name: str | None,
) -> None:
    """Emit ``MEMBER_NAME_BIDI_CONTROL``, ``MEMBER_NAME_ZERO_WIDTH_CHARACTER`` and
    ``MEMBER_NAME_INVISIBLE_CHARACTER`` for ``text``, the member's name or its link
    target as ``field`` says.

    Bidi controls and the zero-width characters are Unicode category Cf too; each goes
    to its own code only, so the invisible set is every other Cf character. Each code is
    emitted at most once, naming every character of its set in order. ASCII text
    contains none of them, so it skips the per-character scan (listing hot path; perf
    review H3 / Q1).
    """
    if text.isascii():
        return
    bidi: list[str] = []
    zero_width: list[str] = []
    invisible: list[str] = []
    for char in text:
        if char in BIDI_CONTROLS:
            bidi.append(char)
        elif char in ZERO_WIDTH_CHARACTERS:
            zero_width.append(char)
        elif unicodedata.category(char) == "Cf":
            invisible.append(char)
    if not bidi and not zero_width and not invisible:
        return
    where = (
        "Member name" if field == "name" else f"Link target of {quoted(member.name)}"
    )
    found_sets: tuple[tuple[DiagnosticCode, _Category, list[str], str], ...] = (
        (
            DiagnosticCode.MEMBER_NAME_BIDI_CONTROL,
            "bidi",
            bidi,
            "a bidirectional control character",
        ),
        (
            DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER,
            "zero_width",
            zero_width,
            "a zero-width character",
        ),
        (
            DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER,
            "invisible",
            invisible,
            "an invisible format character",
        ),
    )
    for code, category, found, what in found_sets:
        if found:
            _emit_controls(
                collector,
                code=code,
                message=f"{where} contains {what}: {quoted(text)}",
                member=member,
                found=found,
                field=field,
                category=category,
                archive_name=archive_name,
            )


def _emit_controls(
    collector: DiagnosticCollector,
    *,
    code: DiagnosticCode,
    message: str,
    member: ArchiveMember,
    found: list[str],
    field: Literal["name", "link_target"],
    category: _Category,
    archive_name: str | None,
) -> None:
    collector.emit(
        code=code,
        message=message,
        context=MemberNameControlsContext(
            archive_name=archive_name,
            member_name=member.name,
            member_id=member._member_id,
            raw_name_base64=raw_name_to_base64(member.raw_name),
            controls=",".join(f"U+{ord(char):04X}" for char in found),
            field=field,
            category=category,
        ),
        member=member,
        attach_to_member=True,
        logger=logger,
    )


def name_controls_possible(member: ArchiveMember) -> bool:
    """Whether :func:`emit_member_name_controls` or :func:`emit_link_target_controls`
    could emit anything for ``member``: its name or its known target is not ASCII.

    The emitters skip ASCII text themselves; this lets a caller skip setup it would only
    need for an emit (listing hot path).
    """
    target = member.link_target
    return not member.name.isascii() or (target is not None and not target.isascii())


def emit_member_name_controls(
    collector: DiagnosticCollector,
    *,
    member: ArchiveMember,
    archive_name: str | None = None,
) -> None:
    """Emit ``MEMBER_NAME_BIDI_CONTROL`` when a presented name carries a bidi control,
    ``MEMBER_NAME_ZERO_WIDTH_CHARACTER`` when it carries one of
    ``ZERO_WIDTH_CHARACTERS``, and ``MEMBER_NAME_INVISIBLE_CHARACTER`` when it carries
    another Cf character.

    Called by ``BaseArchiveReader`` while assigning member identity, not by individual
    decoders, so directory and inferred single-file names receive the same diagnostics
    and a backend that uses :func:`normalize_member_name` cannot emit a duplicate.

    The context records *which* characters were found rather than just that there were
    some: overrides and isolates reorder surrounding text and are what the ``…gnp.exe``
    disguise needs, while the three directional marks occur in legitimate Arabic and
    Hebrew filenames; a zero-width space has no use in a name, while a zero-width
    joiner is part of ordinary emoji. A caller (or a policy) may want to treat them
    differently.
    """
    _emit_name_controls(
        collector,
        member=member,
        text=member.name,
        field="name",
        archive_name=archive_name,
    )


def emit_link_target_controls(
    collector: DiagnosticCollector,
    *,
    member: ArchiveMember,
    archive_name: str | None = None,
) -> None:
    """The same check as :func:`emit_member_name_controls`, on a link's stored target,
    with ``field="link_target"``.

    The same characters, the same codes and the same context as for a name: a target is
    displayed to a person as a path, and the same disguise works on it. The caller runs
    this once per member, when the target becomes known.
    """
    target = member.link_target
    if target is None:
        return
    _emit_name_controls(
        collector,
        member=member,
        text=target,
        field="link_target",
        archive_name=archive_name,
    )


def _is_usable_stem(stem: str) -> bool:
    """Whether a stripped stem is a filename rather than a path-navigation spelling.

    The name is chosen at listing time, before any extraction policy is known, so it
    has to satisfy the strictest one. ``.`` and ``..`` are refused by
    ``filters.check_universal`` under every policy; an all-dots/spaces segment such as
    ``...`` is refused by ``_strip_trailing_dot_space`` under ``STRICT`` and ``STANDARD``.
    Producing any of them here costs the caller the payload under at least one policy
    and gives an unusable member name under the others.
    """
    return stem.rstrip(". ") != ""


# The one-word spellings of a compressed tar. Decompressing one gives a tar, so the
# single-file name replaces the suffix with ``.tar``, as ``gzip -d`` and ``xz -d`` do
# (the keys). The tar reader's extension table reads the codecs too (the values), so
# one map serves detection by name and naming.
COMPRESSED_TAR_SHORT_SUFFIXES: dict[str, StreamFormat] = {
    ".tgz": StreamFormat.GZIP,
    ".tbz2": StreamFormat.BZIP2,
    ".tbz": StreamFormat.BZIP2,
    ".txz": StreamFormat.XZ,
    ".tzst": StreamFormat.ZSTD,
    ".tlz": StreamFormat.LZIP,
}


def infer_member_name_from_archive(
    archive_name: str | None,
    *,
    strip_suffixes: Collection[str] = (),
    replace_suffixes: Mapping[str, str] | None = None,
    strip_suffix_re: re.Pattern[str] | None = None,
) -> str:
    """Infer a presented member name from the archive source path.

    Shared by single-file compressors and nameless 7z members (see
    ``format-single-file-compressors`` / ``format-7z``):

    - No usable archive filename → ``\"data\"``.
    - Basename matches ``strip_suffix_re`` or ends with a ``strip_suffixes`` entry
      (case-insensitive; longest match wins) → remaining stem, when that stem is a
      usable filename. A ``replace_suffixes`` entry matches the same way and appends
      its replacement to the stem (``.tgz`` → ``.tar``).
    - Otherwise → ``basename + \".uncompressed\"``.

    A stem of only dots and spaces (``\"..gz\"`` → ``\".\"``) is not a name: extraction
    refuses it and the caller gets an empty directory for an intact payload. Those fall
    through to the ``.uncompressed`` spelling, which the length guard already gives
    ``\".gz\"``. That also renames the cases the looser policies used to extract:
    ``\"....gz\"`` presented ``\"...\"`` and extracted under ``STANDARD`` / ``TRUSTED``,
    and now presents ``\"....gz.uncompressed\"`` under every policy.
    """
    if archive_name is None:
        return "data"
    base = os.path.basename(archive_name.rstrip("/"))
    if not base or base in {".", ".."}:
        return "data"

    if strip_suffix_re is not None:
        stem = strip_suffix_re.sub("", base)
        if stem != base and _is_usable_stem(stem):
            return stem

    lower = base.lower()
    best: str | None = None
    best_tail = ""
    best_len = -1
    candidates = [(suffix, "") for suffix in strip_suffixes]
    candidates += (replace_suffixes or {}).items()
    for suffix, tail in candidates:
        if not suffix:
            continue
        suf = suffix if suffix.startswith(".") else f".{suffix}"
        if lower.endswith(suf.lower()) and len(suf) > best_len and len(base) > len(suf):
            best = base[: -len(suf)]
            best_tail = tail
            best_len = len(suf)
    if best is not None and _is_usable_stem(best):
        return best + best_tail

    return base + ".uncompressed"


def normalize_member_name(
    decoded: str, member_type: MemberType, *, backslash_is_separator: bool
) -> str:
    """Normalize a decoded member name using only **meaning-preserving** rules.

    ``member.name`` is a faithful presentation of the stored path: a leading ``/`` and any
    ``..`` component are **retained** (they are rejected at extraction time — see
    ``safe-extraction`` — not silently re-rooted here). Rules, applied in order:

      1. Replace ``\\`` with ``/`` **only when** ``backslash_is_separator`` is true — the
         backend supplies this per the source format/entry (Windows-origin entries convert;
         TAR and other POSIX formats keep ``\\`` as a literal filename character).
      2. Drop ``.`` segments and empty segments (collapsing ``//`` and ``/./``); keep ``..``.
      3. Append ``/`` for directory members if not already present.
      4. Never produce an empty string — an empty name or a bare root becomes ``"."``.

    When normalization changes the presented path, callers should emit
    :func:`emit_member_name_normalized` once the :class:`~archivey.types.ArchiveMember`
    exists (member-eligible diagnostic).
    """
    name = decoded

    # 1. Backslashes -> forward slashes, only when the format/entry treats them as separators.
    if backslash_is_separator and "\\" in name:
        name = name.replace("\\", "/")

    # Fast path: already a clean relative path — no absolute prefix, no empty/`.`
    # segments to drop. ``..`` is retained as-is under the rules below, so a path
    # that only contains ordinary segments (and optional ``..``) needs no rebuild.
    # Listing hot path (ZIP/TAR open+list); keep behaviour identical to the full walk.
    # A trailing ``/`` on a non-directory is an empty segment the slow walk drops
    # (FILE ``"a/"`` → ``"a"``); only DIRECTORY may keep/require it.
    if (
        name
        and not name.startswith("/")
        and "//" not in name
        and not name.startswith("./")
        and "/./" not in name
        and not name.endswith("/.")
        and name != "."
        and (not name.endswith("/") or member_type == MemberType.DIRECTORY)
    ):
        if member_type == MemberType.DIRECTORY and not name.endswith("/"):
            return name + "/"
        return name

    # 2. Meaning-preserving segment clean-up. Preserve a leading "/" (absolute — rejected at
    #    extraction) and every ".." (retained faithfully); drop only "." and empty segments.
    is_absolute = name.startswith("/")
    kept = [part for part in name.split("/") if part not in (".", "")]
    if not kept:
        name = "."  # empty name or a bare root
    else:
        name = "/".join(kept)
        if is_absolute:
            name = "/" + name

    # 3. Trailing "/" for directories.
    if member_type == MemberType.DIRECTORY and name != "." and not name.endswith("/"):
        name = name + "/"

    return name


def emit_member_name_normalized(
    collector: DiagnosticCollector,
    *,
    member: ArchiveMember,
    presented_name: str,
    archive_name: str | None = None,
    link_stored_as_directory: bool = False,
    member_id: int | None = None,
) -> None:
    """Emit ``MEMBER_NAME_NORMALIZED`` when normalization changed ``presented_name``.

    A backend calls this while it types the member, which happens once per reader (the
    base owns one member walk), so one call is one finding.

    ``member_id`` names the member in the report: the caller's position in the walk,
    since registration has not stamped the id yet and stamps that same position. Left
    out, the report carries whatever the member already has.

    Suppresses the no-op case where a DIRECTORY member only gained the canonical
    trailing slash (Python's ``tarfile`` strips it on read) — that is not an
    observable override, and warning once per directory on every ordinary tar is
    noise (R3 / Brief 4).

    ``link_stored_as_directory`` is the mirror of that case, and the caller must say
    so rather than leaving it to be inferred here: a ZIP directory reparse point (a
    junction, or a directory symlink) is stored with the directory convention's
    trailing slash and is still a link, so normalization drops the slash. Only the ZIP
    backend can tell that from a TAR ``SYMTYPE`` entry named ``link/``, where the
    trailing slash *is* an anomaly worth reporting — and ``MEMBER_NAME_NORMALIZED`` is
    an archive-integrity code, so inferring the suppression from the name's shape would
    silently stop a strict policy refusing that TAR.
    """
    # The ZIP and TAR listings skip the call when the two names are equal, so a case
    # that reports equal names would not reach their members.
    if member.name == presented_name:
        return
    if (
        member.type is MemberType.DIRECTORY
        and presented_name + "/" == member.name
        and not presented_name.endswith("/")
    ):
        return
    if (
        link_stored_as_directory
        and presented_name == member.name + "/"
        and not member.name.endswith("/")
    ):
        return
    collector.emit(
        code=DiagnosticCode.MEMBER_NAME_NORMALIZED,
        message=(
            f"Member name normalized: {quoted(presented_name)} -> {quoted(member.name)}"
        ),
        context=NameNormalizationContext(
            archive_name=archive_name,
            member_name=member.name,
            member_id=member_id if member_id is not None else member._member_id,
            raw_name_base64=raw_name_to_base64(member.raw_name),
            presented_name=presented_name,
            normalized_name=member.name,
        ),
        member=member,
        attach_to_member=True,
        logger=logger,
    )


def resolve_link_target_name(
    link_name: str, target: str, member_type: MemberType, *, within_root: bool = False
) -> str | None:
    """The archive-namespace member name a link's stored target refers to, or ``None``
    when the target cannot name a member of this archive.

    The two link kinds store targets in different namespaces:

    - A **hardlink** target is archive-relative from the root (the TAR model: the
      linkname is the earlier member's own stored path), so it is in the member-name
      namespace and cleaned the way :func:`normalize_member_name` cleans a name: ``.``
      and empty segments dropped, ``..`` **retained**. ``a/../b`` names the member
      stored as ``a/../b``, never the unrelated member ``b``.
    - A **symlink** target is a filesystem path relative to the link's *own directory*
      (``dir/link -> file`` means ``dir/file``), so it is joined to that directory and
      ``..`` is collapsed, as the filesystem would resolve it.

    Returns ``None`` for a symlink target that cannot be a member: an absolute one (a
    filesystem path outside the archive namespace) or one that ``..``-escapes the
    archive root. A hardlink target is a member name, not a path, so neither test
    applies to it: ``../x`` names the member stored as ``../x``, and a leading ``/`` is
    kept, as :func:`normalize_member_name` keeps it in a name (``tar -P`` stores ``/a``
    and a hardlink ``/b`` naming ``/a``). Extraction never follows the target path. It
    links to the member at the end of the hard-link chain, and refuses the link when it
    refuses that member. ``within_root`` restores the escape test for a hardlink-kind
    target, for a caller that has no such refusal: a RAR file copy is a FILE, and
    extraction writes its source's bytes under the copy's own name. That test runs on
    the collapsed form, with a leading ``/`` set aside. A hardlink target with no
    segment left (``.``, ``/``) names nothing. The caller looks the result up against
    normalized member names with :func:`link_target_name_keys`.

    A backslash in ``target`` is a literal character, exactly as in member names: the
    backend that decoded the member already converted ``\\`` to ``/`` where the source
    format/entry treats it as a separator (see :func:`normalize_member_name`'s
    ``backslash_is_separator``), and applies the same rule to the link target it stores.
    Converting unconditionally here would corrupt a POSIX-origin target that legitimately
    contains a backslash.
    """
    if not target:
        return None
    if member_type == MemberType.SYMLINK:
        if target.startswith("/"):
            return None  # absolute: outside the archive namespace
        base_dir = posixpath.dirname(link_name.rstrip("/"))
        joined = posixpath.join(base_dir, target)
        root = ""
    else:
        # A hardlink's leading "/" is part of the member name it refers to.
        root = "/" if target.startswith("/") else ""
        joined = target.lstrip("/")
        if not within_root:
            segments = [seg for seg in joined.split("/") if seg not in ("", ".")]
            return root + "/".join(segments) if segments else None
    resolved = posixpath.normpath(joined)
    if resolved in (".", "/") or resolved.startswith(("../", "/")) or resolved == "..":
        return None  # escapes the archive root (or names the root itself)
    if member_type == MemberType.SYMLINK:
        return resolved
    return root + "/".join(seg for seg in joined.split("/") if seg not in ("", "."))


def link_target_name_keys(target_name: str) -> tuple[str, ...]:
    """The normalized member names that a resolved link target can refer to.

    A link target is a raw name as the archiver stored it, and an archiver does not write
    a trailing ``/`` on a directory target. The normalized name of a directory member
    does carry one (:func:`normalize_member_name`). So a target without the ``/`` also
    refers to the directory spelling. A target that ends in ``/`` refers only to itself:
    the ``/`` says the target is a directory.

    Names a caller passes (``members=``, ``get()``, ``open()``) are normalized names
    already and match exactly; they do not go through this.
    """
    if target_name.endswith("/"):
        return (target_name,)
    return (target_name, target_name + "/")
