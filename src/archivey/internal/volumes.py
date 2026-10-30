"""Multi-volume path discovery and joining (concatenation; RAR keeps volume-1 path)."""

from __future__ import annotations

import errno
import io
import os
import re
import stat
import sys
from bisect import bisect_right
from collections import Counter, OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NoReturn, TypeGuard

from archivey.exceptions import (
    OpenError,
    ResourceUnavailableError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
    _UsageValueError,
)
from archivey.internal.arg_checks import (
    check_path_not_empty,
    raise_if_text_stream,
    reject_source,
)
from archivey.internal.source import ArchiveSource, seek_is_expensive
from archivey.internal.streams.streamtools import (
    is_stream,
    readinto_via_read,
    resolve_seek,
    source_name,
)
from archivey.internal.streams.streamtools.binaryio import read_blocking
from archivey.terminal import display_path

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

SourceItem = str | Path | BinaryIO
SourceSequence = Sequence[SourceItem]

# 7-Zip's ``-v`` writes ``name.7z.001``/``name.zip.001`` — in both cases a *raw byte
# split* of one finished archive, so the parts concatenate back into the original and
# one pattern serves both. An SFX module replaces the archive extension with ``.exe``
# (``7z a -sfx … -v`` → ``vol.exe.001`` … ``.00N``); the stub ``vol.exe`` has no
# ``.NNN`` suffix and is not a sibling. After detection misses, ``open_archive``
# follows that stub to the split first volume beside it (``first_volume_for_stub``).
# ``.sfx`` is not in this pattern: 7-Zip does not emit
# ``name.sfx.001``, and arbitrary ``name.foo.001`` is not a 7-Zip split. Info-ZIP's
# ``name.z01 … name.zip`` deliberately does not match this pattern: that is a true
# spanned set addressed by (disk, offset). A linear join of one lists correctly and
# then reads only whichever members happen to sit on the last disk, so it is refused
# in the ZIP backend instead. ``name.z01`` does match the broad old-scheme RAR shape
# below, and what keeps it out of a RAR set there is stated beside that pattern.
#
# **Three digits minimum, not one or more.** 7-Zip numbers from ``.001`` and widens past
# part 999, so nothing it emits needs fewer. Accepting one or two would swallow
# ``name.zip.1`` / ``name.zip.2`` — what wget and naive rotation produce for two
# downloads of the *same* file — and concatenate two independent complete archives,
# handing back the wrong file's contents with no error. The completeness check cannot
# catch it either: ``[1, 2]`` is exactly ``1..N``. ``.exe`` is format-agnostic (7-Zip
# writes it for a 7z or ZIP payload), so this pattern is not kept in step with
# ``is_zip_split_segment_name`` (still ``zip\.[0-9]{3,}`` / ``.zNN``). A lone
# numbered part (``.7z.001`` / ``.zip.001`` / ``.exe.001``) is refused at
# ``open_archive`` as an incomplete set, naming the missing parts — not as a ZIP
# spanned-set error. Info-ZIP ``.zNN`` stays that ZIP refusal.
#
# The part number is capped at 999 999 parts, which no real set comes near. The cap is
# on the value, not the width: leading zeros are matched outside the ``part`` group, so
# ``split -d -a 7`` output (``big.zip.0000001``) is still a set while ``a.zip.9999999``
# is not a part name. The captured group is at most six digits whatever the name, which
# keeps a part number read from a name small and keeps ``int()`` safe. A name from a
# directory listing is bounded by the filesystem's name limit, but a stream's ``name``
# and a path in an explicit sequence are checked before any file is opened, and Python
# refuses to parse an integer past ``sys.get_int_max_str_digits()`` digits (4300 by
# default) with a bare ``ValueError``. A larger number is not a part number, so the
# lone-part refusal below does not apply: a ``.7z`` or ``.exe`` name goes to ordinary
# detection, while a ``.zip`` name still matches the uncapped
# ``is_zip_split_segment_name`` and is refused as a spanned ZIP. The ``.partN`` pattern
# below has the same cap for the same reason.
# The largest part the six-digit ``part`` groups below can hold.
_MAX_VOLUME_PART = 999_999
# This pattern and ``_RAR_PART_RE`` end in ``\Z``, not ``$``: ``$`` also matches before
# a final newline, which would read ``name.7z.001\n`` as a volume name. Digits are
# ``[0-9]``, not ``\d``: on a ``str`` pattern ``\d`` matches any Unicode digit, so
# ``0.7z.\u066000`` (an Arabic-Indic zero, then two ASCII zeros) was a numbered part
# (``\d{3,6}`` took all three) *and* an old-scheme RAR continuation (its
# ``[^.0-9]`` took the Arabic-Indic zero as the letter), so the schemes overlapped.
# ``re.ASCII`` does the same for ``re.IGNORECASE``, which otherwise folds ``\u0131``
# and ``\u0130`` into ``i`` and ``\u017f`` into ``s`` and so read ``x.z\u0131p.001`` as
# a ZIP volume.
_NUMBERED_VOLUME_RE = re.compile(
    r"^(?P<base>.+\.(?:7z|zip|exe))\.0*(?P<part>[0-9]{3,6})\Z", re.IGNORECASE | re.ASCII
)
# WinRAR ``-v`` writes ``name.partN.rar``. An SFX first volume keeps the ``partN``
# marker and changes only the last extension: ``name.part1.sfx`` (Linux rar) or
# ``name.part1.exe`` (Windows), with later volumes still ``.partN.rar``. The stem
# before ``.part`` is the set's base, so mixed extensions on one stem are one set.
_RAR_PART_RE = re.compile(
    r"^(?P<base>.+)\.part0*(?P<part>[0-9]{1,6})\.(?:rar|sfx|exe)\Z",
    re.IGNORECASE | re.ASCII,
)
# Any old-scheme continuation name. WinRAR and unrar go ``.rar``, ``.r00`` … ``.r99``,
# then ``.s00`` … ``.z99`` and on past ``z`` (``.{00``, ``.|00`` …): the next name adds
# one to the letter's character code (:func:`next_rar_volume_name`).
#
# The shape is deliberately broad. It also matches Info-ZIP's ``backup.z01`` and
# unrelated extensions such as ``cert.p12`` or ``image.e01``, so it only makes a name
# a candidate, and two guards in discovery decide. First, volume 1 (``<base>.rar`` /
# ``.exe`` / ``.sfx``) must sit beside the name: an Info-ZIP spanned set has none, so
# ``backup.z01`` is not a RAR volume and still reaches the ZIP backend's spanned-set
# refusal. Second, the walk of the names unrar would look for from volume 1 must reach
# the name, so ``notes.a01`` beside ``notes.rar`` is not a volume either. The cost of
# the breadth: opening a name of this shape pays one directory listing, where the fast
# reject in ``discover_volume_siblings`` turns other names away before any filesystem
# call. The explicit-sequence check classifies old-scheme parts with this same
# pattern, so it reads the base discovery groups on. It has neither guard, though, so
# there the breadth costs a false refusal: a stray of this shape (``readme.p12``,
# ``notes.e01``) in an explicit sequence counts as an old-scheme part, so beside parts
# of another scheme or another base the check refuses the sequence as two sets. No
# narrower pattern is sound. The name alone cannot tell ``beta.s00`` from
# ``readme.p12``, and the walk can reach any letter before ``_MAX_VOLUME_PART`` stops
# it. ``\Z``, not ``$``: ``$`` also matches before a final newline.
_OLD_RAR_CONTINUATION_RE = re.compile(r"^(?P<base>.+)\.[^.0-9][0-9]{2}\Z")
_OLD_RAR_EXT_RE = re.compile(r"(?P<letter>[^.0-9])(?P<num>[0-9]{2})")

# The three volume naming schemes, each with a ``base`` group. All three branches of
# ``discover_volume_siblings`` group candidates on ``base.lower()``, so an explicit
# sequence is held to the same grouping in all three.
_NUMBERED_SCHEME, _RAR_PART_SCHEME, _OLD_RAR_SCHEME = range(3)
_VOLUME_SCHEMES = (_NUMBERED_VOLUME_RE, _RAR_PART_RE, _OLD_RAR_CONTINUATION_RE)
# Each entry describes the shape a name matched, not what the file is: the third
# also matches ``notes.e01``, so it must not claim ``.r00``.
_SCHEME_NAMES = (
    "name.EXT.NNN",
    "name.partN.rar",
    "name.xNN (the old RAR scheme's shape: .r00, .s01, ...)",
)


def _volume_scheme_and_base(name: str) -> tuple[int, str] | None:
    """Classify a name carrying a part marker, with the base its scheme reads.

    ``None`` for a name no scheme claims, which includes an old-scheme volume 1.
    That one has no part marker; callers test its suffix themselves.

    The schemes cannot overlap, so their order does not matter. Each pattern's
    trailing anchor rules out the others: a numbered name ends in digits,
    ``_RAR_PART_RE`` requires a final ``.rar`` / ``.sfx`` / ``.exe``, and an old-scheme
    continuation's last extension must start with a non-digit. That anchor is what
    keeps ``my.part1.zip.001`` in the numbered scheme on its full ``my.part1.zip``
    base rather than under ``.part``. ``test_volume_schemes_are_disjoint`` holds it.
    """
    for index, pattern in enumerate(_VOLUME_SCHEMES):
        match = pattern.match(name)
        if match is not None:
            return index, match.group("base")
    return None


# Volume 1 of an old-scheme set, in order of preference.
_OLD_RAR_FIRST_VOLUME_SUFFIXES = (".rar", ".exe", ".sfx")


# unrar's new-scheme step: ``N`` in ``name.partN.rar`` goes up by one and keeps its
# zero padding. It differs from ``_RAR_PART_RE``, which classifies a name rather than
# predicting unrar: no digit cap, an empty base, any character (a newline too) in the
# base. It accepts only ``.rar``, because ``next_rar_volume_name`` rewrites ``.exe``
# and ``.sfx`` to ``.rar`` first.
_UNRAR_PART_NAME_RE = re.compile(
    r"(?P<head>.*\.part)(?P<num>[0-9]+)(?P<ext>\.rar)",
    re.IGNORECASE | re.DOTALL | re.ASCII,
)


def rar_volume_name(stem: str, index: int, *, old_numbering: bool) -> str:
    """File name of volume ``index`` (1-based) of a set archivey writes or links.

    The closed form of :func:`next_rar_volume_name`'s walk from ``<stem>.rar`` or
    ``<stem>.part1.rar``. Old-style names run ``.rar``, ``.r00`` … ``.z99`` and on
    past ``z``; unrar reads a set of 1 500 volumes named that way. It does not follow
    ``partN`` names for an old-style set, so those are never used for one.
    """
    if not old_numbering:
        return f"{stem}.part{index}.rar"
    if index == 1:
        return f"{stem}.rar"
    number = index - 2
    return f"{stem}.{chr(ord('r') + number // 100)}{number % 100:02d}"


def next_rar_volume_name(name: str, *, old_numbering: bool) -> str | None:
    """The name unrar tries for the volume after ``name``, or ``None`` if unsure.

    A subset of unrar's ``NextVolumeName``: an ``.exe``, ``.sfx`` or missing
    extension counts as ``.rar``. The new scheme increments ``N`` in
    ``name.partN.rar``. The old scheme goes ``.rar`` -> ``.r00``, ``.r99`` ->
    ``.s00``, ``.z99`` -> ``.{00``, and the ``r`` of a ``.RAR`` keeps its case. Any
    other shape is ``None``. Shared by old-scheme discovery and the RAR backend,
    which predicts the names unrar will walk. The missing-extension case serves the
    backend's caller-supplied names; discovery never reaches it, because its volume
    1 always carries ``.rar``, ``.exe`` or ``.sfx``.
    """
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, "rar"
    elif ext.lower() in ("", "exe", "sfx"):
        ext = "rar"
    if not old_numbering:
        match = _UNRAR_PART_NAME_RE.fullmatch(f"{stem}.{ext}")
        if match is None:
            return None
        digits = match["num"]
        number = str(int(digits) + 1).zfill(len(digits))
        return f"{match['head']}{number}{match['ext']}"
    if ext.lower() == "rar":
        return f"{stem}.{ext[0]}00"
    match = _OLD_RAR_EXT_RE.fullmatch(ext)
    if match is None:
        return None
    letter, number = match["letter"], int(match["num"]) + 1
    if number == 100:
        code = ord(letter) + 1
        if code > sys.maxunicode:
            # No character follows U+10FFFF, so there is no next name to look for.
            return None
        letter, number = chr(code), 0
    return f"{stem}.{letter}{number:02d}"


# Each ordering key reads the part number back out of the pattern that classified the
# name, so a base that happens to contain another pattern's marker cannot capture it.
# A scan for the first ``.partN`` anywhere in the name used to, and sorted every part of
# ``my.part1.zip.001 … .003`` under the same key 1 — leaving the concatenation order to
# ``iterdir``, which is arbitrary.
def _numbered_part_number(name: str) -> int:
    match = _NUMBERED_VOLUME_RE.match(name)
    return int(match.group("part")) if match is not None else 0


def _rar_part_number(name: str) -> int:
    match = _RAR_PART_RE.match(name)
    return int(match.group("part")) if match is not None else 0


def _part_digits(pattern: re.Pattern[str], name: str) -> tuple[int, int] | None:
    """Where the digits of the part number in ``name`` start and end, zeros included."""
    match = pattern.match(name)
    if match is None:
        return None
    marker = name[match.end("base") : match.end("part")]
    width = len(marker) - len(marker.rstrip("0123456789"))
    return match.end("part") - width, match.end("part")


def _part_width(pattern: re.Pattern[str], name: str) -> int:
    """How many digits, leading zeros included, carry the part number in ``name``."""
    digits = _part_digits(pattern, name)
    return 0 if digits is None else digits[1] - digits[0]


def _predicted_volume_name(scheme: int, named: str, part: int) -> str:
    """The name unrar or 7-Zip looks for as ``part``, starting from ``named``.

    Both tools keep the spelling and zero padding of the name they were given and
    replace only the number, which widens once it outgrows the padding (from
    ``q.part1.rar``, part 10 is ``q.part10.rar``). unrar also reads an ``.exe`` /
    ``.sfx`` first volume as ``.rar`` (:func:`next_rar_volume_name`).
    """
    digits = _part_digits(_VOLUME_SCHEMES[scheme], named)
    if digits is None:
        return named
    start, end = digits
    tail = named[end:]
    if scheme == _RAR_PART_SCHEME and tail.lower() != ".rar":
        tail = ".rar"
    return f"{named[:start]}{str(part).zfill(end - start)}{tail}"


def _pick_volume(
    candidates: list[Path], part: int, scheme: int, named: str, base: str
) -> Path:
    """One file for a part number that several names in the directory carry.

    ``q.part2.rar`` and ``q.part02.rar`` are both part 2, as are ``x.7z.002`` and
    ``x.7z.0002``, and on a case-sensitive filesystem so is ``Q.PART2.RAR``. unrar and
    7-Zip do not choose between them: each predicts the next name from the current one
    by adding one to the number and keeping the spelling and zero padding, starting
    from the name opened (unrar first goes back to volume 1 the same way). The padding
    widens when the number outgrows it, so from ``q.part1.rar`` part 10 is
    ``q.part10.rar``, not a stray ``q.part010.rar``. So the order of preference is:

    1. the name the caller opened, as spelled;
    2. a name padded like the predicted one (:func:`_predicted_volume_name`);
    3. the predicted name as spelled;
    4. a name spelling ``base`` as the opened name does, the rule old-scheme
       discovery applies to case variants (:func:`_old_rar_listed_file`);
    5. (RAR) a ``.rar`` over an SFX ``.exe`` / ``.sfx``, because unrar's predicted
       names carry ``.rar`` whichever way it walks, part 1 included;
    6. the lowest name.

    The last step makes the pick deterministic, where taking the first match in
    ``iterdir`` order read a stray of another width into the set.
    """
    pattern = _VOLUME_SCHEMES[scheme]
    predicted = _predicted_volume_name(scheme, named, part)
    predicted_width = _part_width(pattern, predicted)

    def rank(candidate: Path) -> tuple[bool, bool, bool, bool, bool, str]:
        name = candidate.name
        return (
            name != named,
            _part_width(pattern, name) != predicted_width,
            name != predicted,
            not name.startswith(base),
            scheme == _RAR_PART_SCHEME and not name.lower().endswith(".rar"),
            name,
        )

    return min(candidates, key=rank)


def _pick_volumes(parent: Path, scheme: int, base: str, name: str) -> list[Path] | None:
    """The sibling volumes of ``name``, one per part number, ordered by part."""
    pattern = _VOLUME_SCHEMES[scheme]
    part_of = _rar_part_number if scheme == _RAR_PART_SCHEME else _numbered_part_number
    grouped: dict[int, list[Path]] = {}
    for candidate in _siblings_with_base(parent, pattern, base):
        grouped.setdefault(part_of(candidate.name), []).append(candidate)
    if len(grouped) <= 1:
        return None
    return [
        _pick_volume(grouped[part], part, scheme, name, base)
        for part in sorted(grouped)
    ]


def _is_old_scheme_first_volume_name(name: str) -> bool:
    """``<base>.rar`` / ``.exe`` / ``.sfx`` as old-scheme volume 1, not a partN/NNN name."""
    if (
        _NUMBERED_VOLUME_RE.match(name) is not None
        or _RAR_PART_RE.match(name) is not None
    ):
        return False
    return name.lower().endswith(_OLD_RAR_FIRST_VOLUME_SUFFIXES)


def _old_rar_listed_file(
    by_name: dict[str, list[Path]], wanted: str, base: str
) -> Path | None:
    """The file in the listing named ``wanted`` in any case, or ``None``.

    Of several that differ only in case, a name starting with ``base`` as spelled
    wins, then ``wanted`` as spelled, then the first by name.
    """
    candidates = sorted(
        (
            candidate
            for candidate in by_name.get(wanted.lower(), ())
            if candidate.is_file()
        ),
        key=lambda candidate: (
            not candidate.name.startswith(base),
            candidate.name != wanted,
            candidate.name,
        ),
    )
    return candidates[0] if candidates else None


# Both RAR signatures start with these bytes; every volume of a set carries one.
_RAR_MARKER_PREFIX = b"Rar!\x1a\x07"


def rar_volume_number(name: str) -> int | None:
    """The 1-based position of a RAR volume in its set, read from its name alone.

    ``name.partN.rar`` (or ``.sfx`` / ``.exe``) is ``N``. In the old scheme volume 1
    is ``<base>.rar`` / ``.exe`` / ``.sfx`` and ``.r00`` is volume 2, the closed form
    of unrar's walk (:func:`rar_volume_name`). ``None`` for a name neither scheme
    numbers: an old-scheme letter below ``r``, or past ``z`` in upper case, where
    unrar's walk steps through punctuation that has no lower-case pair.
    """
    match = _RAR_PART_RE.match(name)
    if match is not None:
        return int(match.group("part"))
    if _is_old_scheme_first_volume_name(name):
        return 1
    if _OLD_RAR_CONTINUATION_RE.match(name) is None:
        return None
    ext = name[name.rfind(".") + 1 :]
    letter = ext[0].lower() if "A" <= ext[0] <= "Z" else ext[0]
    offset = ord(letter) - ord("r")
    if offset < 0:
        return None
    number = offset * 100 + int(ext[1:]) + 2
    return number if number <= _MAX_VOLUME_PART else None


def _starts_like_rar(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(_RAR_MARKER_PREFIX)) == _RAR_MARKER_PREFIX
    except OSError:
        return False


def _collect_old_rar_volumes(parent: Path, base: str) -> list[Path] | None:
    """Volume 1, then each name unrar would look for next, then any past a gap.

    Volume 1 is ``<base>.rar``, else ``<base>.exe``, else ``<base>.sfx``. Every name,
    volume 1 included, is matched case-insensitively from one directory listing, as
    the other schemes group siblings, so ``ARCHIVE.RAR`` + ``ARCHIVE.R00`` is a set
    on a case-sensitive filesystem too. That holds once this function runs: opened
    from an SFX stub, ``discover_volume_siblings``' fast reject first needs
    ``<stem>.r00`` or ``<stem>.R00`` with the stub's own base spelling. Of two names
    that differ only in case, the one spelling ``base`` as given wins, then the one
    spelling the predicted name as given. The walk is bounded by ``_MAX_VOLUME_PART``, and by the listing: each step
    needs a file in it.

    Past the first missing name, and when volume 1 itself is missing, the other
    old-scheme names of the listing are placed by :func:`rar_volume_number`, so a
    set with a gap is still one set (ruled 2026-10-06: list everything in the
    volumes present). Those names are taken only when the file starts with a RAR
    signature, because the shape alone also matches an Info-ZIP ``backup.z01`` or a
    ``notes.t01``; the contiguous walk from volume 1 needs no such check, as before.
    """
    by_name: dict[str, list[Path]] = {}
    for candidate in parent.iterdir():
        by_name.setdefault(candidate.name.lower(), []).append(candidate)
    first = None
    for suffix in _OLD_RAR_FIRST_VOLUME_SUFFIXES:
        first = _old_rar_listed_file(by_name, f"{base}{suffix}", base)
        if first is not None:
            break
    volumes: list[Path] = []
    if first is not None:
        volumes.append(first)
        current = first.name
        while len(volumes) < _MAX_VOLUME_PART:
            predicted = next_rar_volume_name(current, old_numbering=True)
            if predicted is None:
                break
            following = _old_rar_listed_file(by_name, predicted, base)
            if following is None:
                break
            volumes.append(following)
            current = following.name
    # Past a gap, or with no volume 1: the rest of the listing, by number.
    walked = len(volumes) + (0 if first is not None else 1)
    folded = base.lower()
    beyond: dict[int, Path] = {}
    for lower_name in by_name:
        match = _OLD_RAR_CONTINUATION_RE.match(lower_name)
        if match is None or match.group("base") != folded:
            continue
        number = rar_volume_number(lower_name)
        if number is None or number <= walked or number in beyond:
            continue
        candidate = _old_rar_listed_file(by_name, lower_name, base)
        if candidate is not None and _starts_like_rar(candidate):
            beyond[number] = candidate
    volumes.extend(beyond[number] for number in sorted(beyond))
    return volumes if len(volumes) > 1 else None


def _siblings_with_base(
    parent: Path, pattern: re.Pattern[str], base: str
) -> list[Path]:
    """The files in ``parent`` that ``pattern`` reads with ``base``, case-folded.

    The name tests run before ``is_file``, so a large directory costs a ``stat`` per
    matching name, not one per entry.
    """
    folded = base.lower()
    return [
        candidate
        for candidate in parent.iterdir()
        if (match := pattern.match(candidate.name)) is not None
        and match.group("base").lower() == folded
        and candidate.is_file()
    ]


def discover_volume_siblings(path: Path) -> list[Path] | None:
    """Return ordered sibling paths when ``path`` is part of a volume set, else ``None``."""
    name = path.name
    lower = name.lower()
    # Fast reject before any filesystem op: most opens (ZIP/TAR/gz/plain .7z) are
    # not volume-shaped. Saves a ``stat`` per open_archive (perf review L3).
    # ``_volume_scheme_and_base`` also classifies SFX first members
    # (``*.exe.001``, ``*.part1.sfx``).
    classified = _volume_scheme_and_base(name)
    if classified is None:
        # Old-scheme volume 1: ``<base>.rar``, or an SFX ``<base>.exe`` /
        # ``<base>.sfx`` when no ``.rar`` is beside the continuations. This is
        # ``_is_old_scheme_first_volume_name`` without its two regex guards: the
        # classification just above already found that neither pattern matches,
        # and this path should stay cheap.
        if not lower.endswith(_OLD_RAR_FIRST_VOLUME_SUFFIXES):
            return None
        parent = path.parent
        # A stub ``*.exe`` / ``*.sfx`` is a volume candidate only when ``<stem>.r00`` or
        # ``<stem>.R00`` exists (up to two ``is_file``, no ``iterdir``) so 7-Zip
        # ``vol.exe`` + ``vol.exe.001`` still falls through to stub-follow. The probe
        # matches the extension's case but spells the base as the stub does, so
        # ``archive.exe`` beside ``ARCHIVE.R00`` is not an entry point (the set is
        # still found from ``ARCHIVE.R00``). Closing that would cost an ``iterdir``
        # on every ``.exe`` / ``.sfx`` open.
        if not lower.endswith(".rar") and not any(
            (parent / f"{path.stem}.{letter}00").is_file() for letter in ("r", "R")
        ):
            return None
        if not path.is_file():
            return None
        return _collect_old_rar_volumes(parent, name[: name.rfind(".")])
    if not path.is_file():
        return None
    scheme, base = classified
    parent = path.parent

    if scheme in (_NUMBERED_SCHEME, _RAR_PART_SCHEME):
        return _pick_volumes(parent, scheme, base, name)

    # A continuation belongs to the set when the walk from volume 1 reaches it, or
    # when it is a RAR volume past a gap or with volume 1 missing; ``siblings[0]`` is
    # then the first volume present. An unrelated ``notes.a01`` beside ``notes.rar``
    # is neither, and stays a lone file.
    volumes = _collect_old_rar_volumes(parent, base)
    if volumes is None:
        return None
    if any(volume.name.lower() == lower for volume in volumes):
        return volumes
    return None


def is_sfx_stub_name(name: str) -> bool:
    """True for ``*.exe`` / ``*.sfx`` names that are not already volume-shaped."""
    return _is_old_scheme_first_volume_name(name) and not name.lower().endswith(".rar")


def first_volume_for_stub(path: Path) -> Path | None:
    """Return the split first volume beside a stub-only ``.exe`` / ``.sfx``, if any.

    7-Zip's ``-sfx -v`` always writes a standalone stub with no archive magic, then
    names the volumes three different ways:

    - Linux: ``vol.exe.001`` (the stub's own name plus ``.001``)
    - Windows 7z: ``vol.7z.001``
    - Windows ZIP: ``vol.zip.001``

    Opening the stub should work for every one of those, otherwise ``open_archive``
    on ``vol.exe`` succeeds on Linux and fails on Windows for the same producer
    flag. The stub is still not a volume sibling — this only names the file to
    hand to :func:`discover_volume_siblings`.

    A path that is already volume-shaped (``vol.exe.001``, ``rv.part1.exe``) is not
    a stub. Two matching first volumes beside the stub is a refusal, not a guess.
    """
    name = path.name
    if not is_sfx_stub_name(name):
        return None
    if not path.is_file():
        return None
    # Exact names, not ``iterdir``. A random ``.exe`` with no volumes beside it
    # is the common miss; walking a large directory there is wasted work.
    # Windows ``is_file`` is case-insensitive; Linux is not, so ``VOL.ZIP.001``
    # beside ``vol.exe`` is only found there if the caller used that casing.
    stem = name[: name.rfind(".")]
    candidates = (
        path.parent / f"{name}.001",
        path.parent / f"{stem}.7z.001",
        path.parent / f"{stem}.zip.001",
    )
    found = [candidate for candidate in candidates if candidate.is_file()]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        names = ", ".join(sorted(candidate.name for candidate in found))
        raise UnsupportedFeatureError(
            f"{display_path(path)} has no archive magic, and more than one split "
            f"first volume sits beside it ({names}). Open one of those files.",
            archive_name=path.as_posix(),
        )
    return None


# LRU of open Path volume handles. Two or three absorb SharedView pairs that
# straddle a part boundary (concurrent_operations=True). Not a refusal: a 100-part
# set still reads. Past this many distinct Path volumes in the working set, each
# cache miss is an open()+close() on that read. Growing the cache to the volume
# count would hold one descriptor per part again.
_PATH_HANDLE_CACHE_SIZE = 3


def _fd_limit_text() -> str:
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, AttributeError, OSError, ValueError):
        return "the process file-descriptor limit"
    return f"the process file-descriptor limit is {soft}"


def _raise_volume_open_error(path: Path, exc: OSError) -> NoReturn:
    """Raise for a failed ``stat`` or ``open`` of the volume at ``path``: the
    ``OSError`` itself, as a missing or unreadable first path does, except when the
    process is out of file descriptors. That is the system running short, not the
    file, so it is :class:`ResourceUnavailableError`, with ``exc`` as its cause."""
    if exc.errno in (errno.EMFILE, errno.ENFILE):
        raise ResourceUnavailableError(
            f"Too many open files to open volume; {_fd_limit_text()}",
            archive_name=path.as_posix(),
        ) from exc
    raise exc


@dataclass
class _CachedPathHandle:
    stream: BinaryIO
    synced: bool = False


class ConcatenatedFile(io.RawIOBase, BinaryIO):
    """Seekable read-only concatenation of volume streams.

    Path volumes are sized with ``stat`` and opened lazily into a small LRU of
    handles (``_PATH_HANDLE_CACHE_SIZE``). Sequential drains and a pair of
    alternating views stay inside that cache; a working set larger than the
    constant evicts on every miss, and those reads pay ``open``+``close``.
    Bytes are sampled at ``open()`` / ``read()``, not pinned by a
    construction-time descriptor: replacing a part after construction is
    visible on the next open of that part.
    Caller-supplied streams stay open, are never closed here, and are re-seeked
    before every read (the caller may have moved them). A stream volume is its
    whole extent, not the part after wherever its cursor happens to sit: sizing
    seeks to the end and every read seeks to an offset measured from 0, so the
    position the caller hands it in is ignored. Pass a sliced view to contribute
    a window of a larger stream.
    """

    def __init__(self, sources: Sequence[Path | BinaryIO]) -> None:
        super().__init__()
        # First, before anything that can raise: ``close()`` reads it, and
        # ``IOBase.__del__`` calls ``close()`` on an instance whose ``__init__``
        # refused its input.
        self._path_handles: OrderedDict[int, _CachedPathHandle] = OrderedDict()
        if not sources:
            raise _UsageValueError("at least one volume is required")
        # Retained so format-specific openers (RAR) can recover real volume paths —
        # unrar needs sibling files on disk, not a concatenated byte stream.
        self._volume_paths: list[Path] = [
            source for source in sources if isinstance(source, Path)
        ]
        self._volume_items: list[Path | BinaryIO] = list(sources)
        # Every read seeks the volume it lands in, so one member stream among the
        # parts makes a read near its end a re-decode of that member.
        self._seek_is_expensive = any(
            not isinstance(source, Path) and seek_is_expensive(source)
            for source in sources
        )
        offsets = [0]
        total = 0
        for source in sources:
            if isinstance(source, Path):
                # No handle: a 100-part set must not hold 100 descriptors from
                # construction, and sizing does not need one.
                try:
                    st = os.stat(source)
                except OSError as exc:
                    # A path the caller listed that is missing or unreadable raises
                    # its OSError, as the first path does. A numbering gap among
                    # paths that exist is TruncatedError in
                    # _validate_numbered_volume_completeness — discovery expected a
                    # part that is not in the set.
                    _raise_volume_open_error(source, exc)
                if not stat.S_ISREG(st.st_mode):
                    raise OpenError(
                        "volume is not a regular file",
                        archive_name=source.as_posix(),
                    )
                size = st.st_size
            else:
                try:
                    pos = source.tell()
                    size = source.seek(0, os.SEEK_END)
                    source.seek(pos)
                except (OSError, AttributeError, io.UnsupportedOperation) as exc:
                    # Same refusal as a non-seekable *single* source, so it gets
                    # the same type: a volume set is concatenated by offset and
                    # cannot be joined from a forward-only stream. Paths are
                    # always seekable; this check is for caller-supplied streams
                    # only. (Keep "type:" out of a comment's first position;
                    # tests/test_no_stray_type_comments.py.)
                    raise StreamNotSeekableError(
                        "all volume streams must be seekable"
                    ) from exc
            total += size
            offsets.append(total)
        self._offsets = offsets
        self._size = total
        self._pos = 0
        self.volume_count = len(sources)
        self._vol_index = 0
        self._vol_offset = 0
        self._recompute_cursor()

    @property
    def volume_paths(self) -> list[Path]:
        """Path volumes in order, when every volume was a ``Path``; else empty."""
        if len(self._volume_paths) != self.volume_count:
            return []
        return list(self._volume_paths)

    @property
    def volume_items(self) -> list[Path | BinaryIO]:
        """Original volume sources in order (paths and/or streams)."""
        return list(self._volume_items)

    @property
    def seek_is_expensive(self) -> bool:
        """Whether a stream volume may re-decode on a seek (see ``seek_is_expensive``)."""
        return self._seek_is_expensive

    @property
    def volume_ranges(self) -> list[tuple[int, int]]:
        """``(start, size)`` of each volume in the concatenated byte space.

        Lets a format opener read one volume at a time through whatever it
        already holds over the concatenation — a ``SharedSource`` view, say —
        instead of reopening the originals. RAR's header walk needs each volume
        as an independent stream positioned at its start, which the whole
        concatenation cannot provide.
        """
        return [
            (self._offsets[index], self._offsets[index + 1] - self._offsets[index])
            for index in range(self.volume_count)
        ]

    @property
    def size(self) -> int:
        return self._size

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._pos

    def _close_all_path_handles(self) -> None:
        handles = list(self._path_handles.values())
        self._path_handles.clear()
        for handle in handles:
            handle.stream.close()

    def _open_path_volume(self, path: Path) -> BinaryIO:
        try:
            return open(path, "rb")
        except OSError as exc:
            _raise_volume_open_error(path, exc)

    def _recompute_cursor(self) -> None:
        """Set volume index/offset from ``_pos``. Sequential ``read`` advances instead."""
        if self._pos >= self._size:
            self._vol_index = self.volume_count
            self._vol_offset = 0
            return
        index = bisect_right(self._offsets, self._pos) - 1
        self._vol_index = index
        self._vol_offset = self._pos - self._offsets[index]
        cached = self._path_handles.get(index)
        if cached is not None:
            cached.synced = False

    def _advance_volume(self) -> None:
        self._vol_index += 1
        self._vol_offset = 0
        n = self.volume_count
        while (
            self._vol_index < n
            and self._offsets[self._vol_index + 1] == self._offsets[self._vol_index]
        ):
            self._vol_index += 1
        cached = self._path_handles.get(self._vol_index)
        if cached is not None:
            # Sequential advance into a cached volume: the handle still sits
            # wherever the last user left it. Clear synced so the next read
            # seeks it; do not assume it is at 0 just because we did not seek.
            cached.synced = False

    def _ensure_current_stream(self) -> BinaryIO:
        source = self._volume_items[self._vol_index]
        if not isinstance(source, Path):
            # Caller-owned: never close it. ``_path_handles`` is Path-only, so a
            # mixed set can keep a Path handle cached while this stream is current.
            return source
        cached = self._path_handles.get(self._vol_index)
        if cached is not None:
            self._path_handles.move_to_end(self._vol_index)
            return cached.stream
        while len(self._path_handles) >= _PATH_HANDLE_CACHE_SIZE:
            _old_index, old = self._path_handles.popitem(last=False)
            old.stream.close()
        stream = self._open_path_volume(source)
        self._path_handles[self._vol_index] = _CachedPathHandle(stream)
        return stream

    def _seek_current_stream(self, stream: BinaryIO) -> None:
        source = self._volume_items[self._vol_index]
        if isinstance(source, Path):
            cached = self._path_handles[self._vol_index]
            if cached.synced:
                return
            stream.seek(self._vol_offset)
            cached.synced = True
            return
        # Borrowed: the caller may have moved it. Seek every time, as we did
        # when every volume was an already-open handle. ``synced`` is Path-only
        # because that invariant is not enforceable on a stream we do not own.
        stream.seek(self._vol_offset)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        self._pos = resolve_seek(offset, whence, pos=self._pos, end=lambda: self._size)
        self._recompute_cursor()
        return self._pos

    def readinto(self, b: WriteableBuffer, /) -> int:
        # RawIOBase's own readinto raises NotImplementedError; this class overrides
        # read() instead, so buffering it (io.BufferedReader) needs this bridge.
        return readinto_via_read(self, b)

    def read(self, n: int = -1) -> bytes:
        self._checkClosed()
        if self._pos >= self._size:
            return b""
        if n is None or n < 0:
            n = self._size - self._pos
        else:
            n = min(n, self._size - self._pos)
        # A raise discards ``out``. Put ``_pos`` back so a retry re-delivers
        # the prefix instead of skipping it.
        start_pos = self._pos
        out = bytearray()
        try:
            while n > 0 and self._pos < self._size:
                vol_end = self._offsets[self._vol_index + 1]
                available = vol_end - self._pos
                to_read = min(n, available)
                stream = self._ensure_current_stream()
                self._seek_current_stream(stream)
                # ``None`` is a non-blocking caller stream with nothing ready, not
                # a volume that ended early: it raises ``BlockingIOError``.
                chunk = read_blocking(stream, to_read)
                if not chunk:
                    source = self._volume_items[self._vol_index]
                    archive_name = (
                        source.as_posix() if isinstance(source, Path) else None
                    )
                    raise TruncatedError(
                        "volume ended before its recorded size",
                        archive_name=archive_name,
                    )
                got = len(chunk)
                out.extend(chunk)
                self._pos += got
                self._vol_offset += got
                n -= got
                if self._pos >= vol_end:
                    self._advance_volume()
        except BaseException:  # restore cursor; the original error re-raises
            self._pos = start_pos
            self._recompute_cursor()
            raise
        return bytes(out)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._close_all_path_handles()
        finally:
            super().close()


_MAX_ENUMERATED_PARTS = 8


class JoinedViews(ConcatenatedFile):
    """Views over one source read back to back as one stream; closes the views.

    For a member whose bytes sit in several places in the archive: a RAR member split
    across volumes, an ISO file in more than one extent.
    """

    def __init__(self, views: list[BinaryIO]) -> None:
        self._views = views
        super().__init__(views)

    def close(self) -> None:
        if self.closed:
            return
        try:
            super().close()
        finally:
            for view in self._views:
                view.close()


def _enumerate_parts(parts: Sequence[int], total: int | None = None) -> str:
    """Render part numbers for an error message, capped so a big set stays readable.

    ``total`` is how many there really are, when ``parts`` is only the prefix worth
    printing. Counting the prefix instead would understate the answer, which is the
    one thing this message exists to give.
    """
    total = len(parts) if total is None else total
    if len(parts) <= _MAX_ENUMERATED_PARTS and total == len(parts):
        return ", ".join(str(part) for part in parts)
    shown = ", ".join(str(part) for part in parts[:_MAX_ENUMERATED_PARTS])
    return f"{shown}, … ({total} in total)"


def _numbered_volume_sequence_error(base: str, numbered: Sequence[int]) -> str:
    """Say what is wrong with a numbered set: a repeat, a part below 1, a gap, or order.

    The branches run in that order because each one establishes the premise the next
    needs: after the repeat branch the parts are distinct, and after the below-1
    branch they all lie in ``1..max``, which is what makes ``max - len`` the exact
    number missing.

    Everything this builds is bounded by ``len(numbered)`` — the number of files on
    disk — never by the part numbers themselves. A part number comes from a filename
    (``_NUMBERED_VOLUME_RE`` accepts parts up to 999 999), so sizing anything by
    ``max(numbered)`` would let a sibling named ``foo.7z.999999`` decide an
    allocation. The set is required to be exactly ``1..N``, so only a part
    at or below ``N`` can be described as missing; anything above it is out of range
    by construction.
    """
    counts = Counter(numbered)
    repeated = sorted(part for part, count in counts.items() if count > 1)
    if repeated:
        noun = "part" if len(repeated) == 1 else "parts"
        return (
            f"Repeated volume in multi-volume set for {base}: "
            f"{noun} {_enumerate_parts(repeated)} given more than once"
        )
    # A part below 1 has to be named before any counting, because the arithmetic
    # below assumes every part is in 1..max and a 0 makes the count come out at or
    # under zero — which would report a set with a real gap as merely out of order,
    # while it is in ascending order and so cannot be reordered into shape.
    # ``split -b … -d`` numbers from 000 and leaves a base name the pattern matches,
    # so this is a real shape, not a hostile one. Bounded by the file count.
    below_one = sorted(part for part in counts if part < 1)
    if below_one:
        noun = "part" if len(below_one) == 1 else "parts"
        return (
            f"Multi-volume set for {base} is not numbered from 1: "
            f"{noun} {_enumerate_parts(below_one)} — parts must run 1, 2, … N"
        )
    # No repeats and nothing below 1, so the parts on disk are distinct and all lie
    # in 1..max. The count of missing ones is then arithmetic and needs no list: the
    # set has to run 1..max, and len(numbered) of them are here. Only the prefix that
    # will actually be printed is enumerated, bounded by the file count plus the cap
    # — never by the part numbers, which come from filenames.
    total_missing = max(numbered) - len(numbered)
    if total_missing > 0:
        scan_to = min(max(numbered), len(numbered) + _MAX_ENUMERATED_PARTS)
        missing = [part for part in range(1, scan_to + 1) if part not in counts]
        noun = "part" if total_missing == 1 else "parts"
        return (
            f"Incomplete multi-volume set for {base}: "
            f"missing {noun} {_enumerate_parts(missing, total_missing)}"
        )
    return (
        f"Out-of-order multi-volume set for {base}: parts "
        f"{_enumerate_parts(numbered)} — concatenation needs them in ascending order"
    )


def _old_rar_bases(paths: Sequence[Path]) -> frozenset[str]:
    """The case-folded bases of every old-scheme continuation in the sequence."""
    return frozenset(
        match.group("base").lower()
        for match in (_OLD_RAR_CONTINUATION_RE.match(path.name) for path in paths)
        if match is not None
    )


def _is_old_rar_first_volume_name_in(name: str, old_rar_bases: frozenset[str]) -> bool:
    """Is this ``.partN.rar`` really volume 1 of an old-scheme set based on its stem?

    ``Show.part1.rar`` reads two ways, and neither the name nor the order the patterns
    are tried in can settle it: part 1 of the ``.partN`` set based on ``Show``, or
    volume 1 of the old-scheme set based on ``Show.part1``. Only the rest of the
    sequence knows — if ``Show.part1.r00`` is in it, the second reading is the one
    that makes the sequence a single archive, and it is the one
    :func:`discover_volume_siblings` produces from any of its continuation names. Not
    from ``Show.part1.rar`` itself: ``_RAR_PART_RE`` claims that name first there
    too, the grouping finds a single part number and discovery returns ``None``, so
    volume 1 of such a set is not an entry point. That gap is discovery's, not this
    function's, and closing it would change behaviour.

    For a single name, the patterns' trailing anchors keep ``my.part1.zip.001`` in
    the numbered scheme. This is a similar hazard one level up, where a name has to be
    read against the sequence around it rather than on its own.
    """
    if _RAR_PART_RE.match(name) is None:
        return False
    return name[: name.rfind(".")].lower() in old_rar_bases


def _sequence_scheme_and_base(
    name: str, old_rar_bases: frozenset[str]
) -> tuple[int, str] | None:
    """:func:`_volume_scheme_and_base`, with the sequence's old-scheme bases."""
    if _is_old_rar_first_volume_name_in(name, old_rar_bases):
        return None
    return _volume_scheme_and_base(name)


def _different_sets_error(first: str, second: str) -> _UsageValueError:
    # DR-15's value half: the volume sequence is a usable type whose value (parts of
    # two sets) the call refuses. That holds when sibling discovery built the sequence
    # from one path too: the path named a part of a set archivey cannot join.
    return _UsageValueError(
        f"Volume parts belong to different sets: {display_path(first)} and "
        f"{display_path(second)}. A volume sequence must be the parts of one archive; "
        f"concatenating parts of two would produce bytes that are neither."
    )


def _validate_volume_sequence_bases(paths: Sequence[Path]) -> None:
    """Require the sequence to name the parts of one archive, as far as names can say.

    Parts of two different sets concatenate into bytes that are neither archive, and
    the numbering cannot tell you so: ``alpha.zip.001`` and ``beta.zip.002`` are a
    perfectly good ``1, 2``. Discovery already filters siblings by base, so this is
    the explicit path's equivalent — ``open_archive([…])`` with a caller's own
    ``sorted(glob("*.zip.*"))`` or ``sorted(glob("*.rar"))`` over a directory holding
    more than one set.

    Three things are checked, and the second and third exist because one alone leaves
    the caller above unprotected:

    1. Every name carrying a part marker must be in the same scheme. A base means
       something different in each — ``alpha.part1.rar``'s is the stem before
       ``.part``, ``alpha.zip.001``'s includes the archive extension — so comparing
       across them is meaningless, and a sequence populating two of them is two sets.
       One name reads two ways and is settled by the sequence rather than by itself:
       ``Show.part1.rar`` beside ``Show.part1.r00`` is that set's volume 1, not a
       ``.partN`` part — see :func:`_is_old_rar_first_volume_name_in`.
    2. Within that scheme the bases must agree, compared case-folded the way
       ``discover_volume_siblings`` groups siblings, so this never refuses a set
       discovery would have accepted.
    3. A name with no part marker that is nonetheless volume-shaped — ``<base>.rar``,
       or ``<base>.exe`` / ``.sfx`` for an SFX — is volume 1 of an old-scheme set and
       only belongs beside old-scheme parts (``.r00`` … ``.s00`` …) sharing its stem.
       Beside a ``.partN`` set it has no role at all, since that scheme spells its own
       volume 1 ``alpha.part1.rar``. Beside a numbered set only the executable
       spellings make sense, as the stub 7-Zip writes next to ``vol.exe.001``; a
       ``.rar`` there is a second archive. Without this the sequences the first two
       checks do catch are trivially reachable in the shapes they do not:
       ``[alpha.part1.rar, alpha.part2.rar, beta.rar]`` is one ``sorted(glob("*.rar"))``
       away.

    A name that is neither is passed over rather than ending the check — the globs
    above also return ``alpha.zip.bak`` and ``notes.zip.old``, and stopping at one
    would leave the parts around it unchecked depending only on where the stray
    sorted. A stray whose extension is one non-digit and two digits (``readme.p12``,
    ``notes.e01``) is not passed over: it has the old-scheme part shape, so beside
    parts of another scheme or another base, rule 1 or 2 refuses the sequence. That
    false refusal is the recorded cost of classifying old-scheme parts with
    discovery's own pattern (see the comment at ``_OLD_RAR_CONTINUATION_RE``).

    What this guarantees is still narrower than "the parts of one archive", and three
    residues stay.

    A sequence in which *no* name carries a part number is not checked at all, because
    nothing in it says any of those names is a volume: ``[alpha.rar, beta.rar]`` is two
    complete archives and joins. Rule 3 reads a bare ``<base>.rar`` against the marked
    parts around it, and with none there is nothing to read it against — refusing it
    instead would refuse a single-volume RAR passed as a one-element list, which is a
    documented way to call this.

    Parts with the same base in *different directories* join, which discovery could
    never produce but ``docs/opening.md`` advertises this path for.

    And on a case-sensitive filesystem ``gamma.zip.001`` and ``GAMMA.zip.002`` are
    genuinely distinct files that the case-folding lets through.
    """
    marked_scheme: int | None = None
    marked_base = ""
    unmarked: list[str] = []
    old_rar_bases = _old_rar_bases(paths)
    for path in paths:
        classified = _sequence_scheme_and_base(path.name, old_rar_bases)
        if classified is None:
            if _is_old_scheme_first_volume_name(
                path.name
            ) or _is_old_rar_first_volume_name_in(path.name, old_rar_bases):
                unmarked.append(path.name)
            continue
        scheme, part_base = classified
        if marked_scheme is None:
            marked_scheme, marked_base = scheme, part_base
        elif scheme != marked_scheme:
            raise _UsageValueError(
                f"Volume parts belong to different sets: {display_path(marked_base)} "
                f"is named {_SCHEME_NAMES[marked_scheme]} and "
                f"{display_path(part_base)} is named {_SCHEME_NAMES[scheme]}. A volume "
                f"sequence must be the parts of one archive, which are all named the "
                f"same way; concatenating parts of two would produce bytes that are "
                f"neither."
            )
        elif part_base.lower() != marked_base.lower():
            raise _different_sets_error(marked_base, part_base)

    if marked_scheme is None:
        # Nothing in the sequence carries a part number, so nothing in it says any of
        # these names is a volume at all and there is no set to be inconsistent with.
        # This is the third residue: `[alpha.rar, beta.rar]` is two complete archives
        # and still joins. Refusing it would mean refusing a single-volume RAR passed
        # as a one-element list, which is a documented way to call this.
        return

    for name in unmarked:
        stem = name[: name.rfind(".")]
        if marked_scheme == _OLD_RAR_SCHEME:
            # Volume 1 of the old scheme. `_collect_old_rar_volumes` looks this name
            # up as the continuations' base plus a suffix, so the stem is that base.
            if stem.lower() != marked_base.lower():
                raise _different_sets_error(marked_base, stem)
        elif marked_scheme == _NUMBERED_SCHEME and name.lower().endswith(
            (".exe", ".sfx")
        ):
            # The 7-Zip stub beside `vol.exe.001`. Its own name is not derived from the
            # parts' base (`vol.exe`), so there is nothing to compare — only the
            # executable spelling says whether it can be a stub at all, and a `.rar`
            # in this position is a second archive.
            continue
        else:
            raise _different_sets_error(marked_base, stem)


def _validate_numbered_volume_completeness(paths: Sequence[Path]) -> None:
    """Require ``name.EXT.001 … .00N`` parts to be numbered 1..N with no gaps.

    Concatenating a set with a hole produces bytes that are neither the original
    archive nor recognisably broken at the join, so the missing part is caught here
    by name rather than left to surface as corruption somewhere in the middle. Only
    the numbered scheme has a number to check: RAR volumes are self-describing and
    the RAR backend reads their order from headers. Whether the parts belong together
    at all is :func:`_validate_volume_sequence_bases`, which :func:`join_volumes`
    runs first.
    """
    base = ""
    numbered: list[int] = []
    skipped = False
    for path in paths:
        match = _NUMBERED_VOLUME_RE.match(path.name)
        if match is None:
            skipped = True
            continue
        base = base or match.group("base")
        numbered.append(int(match.group("part")))
    # Completeness is gated on every path having matched, unlike the base check.
    # Returning here rather than checking would mean a caller joining arbitrary
    # files, one of which happens to be named `foo.zip.002`, is newly refused as an
    # incomplete set — and `[stub.exe, vol.exe.001, vol.exe.002]` would change
    # meaning. Parts that do match must agree on a base however many strays sit
    # between them, which is why that check is not gated the same way.
    if skipped:
        return
    if numbered != list(range(1, len(numbered) + 1)):
        raise TruncatedError(_numbered_volume_sequence_error(base, numbered))


def incomplete_lone_numbered_volume_error(
    archive_name: str | None,
) -> TruncatedError | None:
    """``TruncatedError`` when ``archive_name`` is a numbered volume part.

    Discovery returns ``None`` for a single matching file, so a lone
    ``name.7z.001`` / ``name.zip.001`` / ``name.exe.001`` would otherwise fall
    through to detection and surface as ``CorruptionError``. The missing parts
    are a truncated set, not a format-specific spanned-ZIP refusal. Callers
    skip this when ``format=`` is an explicit non-ZIP / non-7z (P8).
    """
    if not archive_name:
        return None
    filename = Path(archive_name).name
    match = _NUMBERED_VOLUME_RE.match(filename)
    if match is None:
        return None
    base = match.group("base")
    part = int(match.group("part"))
    # The part number comes from the name alone, so it must not size the list: a
    # lone ``a.zip.999999`` used to spell out every earlier part and build a ~14 MB
    # message (``a.zip.9999999``, ~150 MB, before part numbers were capped). Only the
    # prefix worth printing is enumerated, the same cap
    # :func:`_numbered_volume_sequence_error` uses, and the rest is a count.
    earlier = part - 1
    missing = [
        f"{base}.{n:03d}" for n in range(1, min(earlier, _MAX_ENUMERATED_PARTS) + 1)
    ]
    if earlier > _MAX_ENUMERATED_PARTS:
        missing.append(f"… ({earlier} earlier parts in total)")
    if part < _MAX_VOLUME_PART:
        # At the cap the successor is a name the pattern refuses, so it is not named.
        missing.append(f"{base}.{part + 1:03d}")
        missing_text = ", ".join(missing) + ", …"
    else:
        missing_text = ", ".join(missing)
    return TruncatedError(
        f"Incomplete multi-volume set for {base}: "
        f"found part {part} only; missing {missing_text}"
    )


def join_volumes(paths: Sequence[Path]) -> ConcatenatedFile:
    """Concatenate an ordered volume set into one seekable file-like object."""

    if not paths:
        raise _UsageValueError("volume path sequence must not be empty")
    # Both checks are on names alone, and run for every scheme: a sequence naming two
    # archives is refused whatever they are named, and the numbering is then checked
    # where there is one.
    _validate_volume_sequence_bases(paths)
    _validate_numbered_volume_completeness(paths)
    return ConcatenatedFile(paths)


OpenSourceInput = SourceItem | SourceSequence


@dataclass(frozen=True)
class ResolvedSource:
    """The one source detection and the backend read, plus multi-volume metadata."""

    source: ArchiveSource
    archive_name: str | None
    volume_count: int


def _coerce_path_or_stream(item: object) -> Path | BinaryIO:
    if isinstance(item, (str, Path)):
        check_path_not_empty(item, call="open_archive()")
        return Path(item)
    # A caller stream goes into the join as it is: ``ConcatenatedFile`` gathers short
    # reads itself and never closes a stream part, and the source over the join bounds.
    raise_if_text_stream(item)
    if not is_stream(item):
        reject_source(item)
    return item


def _is_source_sequence(source: object) -> TypeGuard[Sequence[object]]:
    """Whether ``source`` is a list of volumes rather than one source.

    Narrows to ``Sequence[object]``, not ``Sequence[SourceItem]``: the elements are
    not checked here. Each one is checked where it is used, by
    :func:`_coerce_path_or_stream` or :func:`_resolve_single`. The byte-buffer types
    are excluded because they are sequences of ``int``, never of sources; they reach
    the single-source refusal and are named there. The parameter is ``object`` because
    the caller's value arrives unchecked, byte buffers included.
    """
    if isinstance(source, (str, Path, bytes, bytearray, memoryview)):
        return False
    if is_stream(source):
        return False
    return isinstance(source, Sequence)


def resolve_source(source: OpenSourceInput) -> ResolvedSource:
    """Turn ``source`` into the one :class:`ArchiveSource` every later step reads.

    This is the boundary every archive source crosses on its way to detection and a
    backend: whatever the caller passed, what comes out carries full-count reads, the
    ownership rule (archivey closes what it built, never the caller's object), bounded
    reads and the cheap facts. A volume list becomes one source over a
    :class:`ConcatenatedFile`, which gathers each caller stream in it to the full count
    and borrows it.

    The caller must close the returned source. A path source opens nothing until it is
    read, so resolving one only to inspect it costs no descriptor.
    """
    if _is_source_sequence(source):
        raw_items = list(source)
        if not raw_items:
            raise _UsageValueError("source sequence must not be empty")
        if len(raw_items) == 1:
            return _resolve_single(raw_items[0])
        items = [_coerce_path_or_stream(item) for item in raw_items]
        paths = [item for item in items if isinstance(item, Path)]
        joined = (
            join_volumes(paths) if len(paths) == len(items) else ConcatenatedFile(items)
        )
        name = source_name(items[0])
        return ResolvedSource(
            ArchiveSource.for_volumes(joined, name=name),
            name,
            len(items),
        )
    return _resolve_single(source)


def _resolve_single(source: object) -> ResolvedSource:
    if isinstance(source, (str, Path)):
        check_path_not_empty(source, call="open_archive()")
        path = Path(source)
        if path.is_dir():
            return ResolvedSource(ArchiveSource.for_path(path), str(path), 1)
        siblings = discover_volume_siblings(path)
        if siblings is not None:
            # Numbered parts are byte slices, so they are joined into one stream.
            # RAR keeps volume 1's path instead: unrar walks the set itself and needs
            # the sibling files on disk.
            name = source_name(siblings[0])
            if _NUMBERED_VOLUME_RE.match(siblings[0].name):
                return ResolvedSource(
                    ArchiveSource.for_volumes(join_volumes(siblings), name=name),
                    name,
                    len(siblings),
                )
            return ResolvedSource(
                ArchiveSource.for_path(siblings[0], volume_count=len(siblings)),
                name,
                len(siblings),
            )
        if _NUMBERED_VOLUME_RE.match(path.name):
            # A lone numbered part is refused by name before anything is read, as an
            # incomplete set. A part that is not there at all is a missing file, not
            # "found part 3 only". ``stat`` raises what the OS says (ENOENT, EACCES,
            # ELOOP) with the path as ``filename``; ``exists()`` would turn all of
            # them into a false "does not exist".
            path.stat()
        return ResolvedSource(ArchiveSource.for_path(path), source_name(path), 1)
    if not is_stream(source):
        # str/Path are handled above, so anything left that is not a stream is a
        # source type archivey does not take. ``reject_source`` is NoReturn, which
        # is what keeps ``source`` narrowed to ``BinaryIO`` below.
        reject_source(source)
    archive_source = ArchiveSource.for_stream(source)
    return ResolvedSource(archive_source, source_name(archive_source), 1)
