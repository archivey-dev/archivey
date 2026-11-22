"""The ar reader: the GNU (System V) and BSD dialects, read in one forward pass.

On-disk layout: the magic ``!<arch>\\n``, then one member after another to the end of
the file, each data area padded with ``\\n`` to an even length::

    [ 60-byte header ][ data ][ pad ]

The header is ASCII, space-padded: name (16), mtime (12, decimal), uid (6), gid (6),
mode (8, octal), size (10, decimal), then the two bytes ``\\x60\\n``. A field may be
blank. Every member is a file: ar has no directories or links.

The dialects differ in how a name longer than 15 bytes is stored:

- **GNU** (System V, also Windows ``.lib``): a short name ends with ``/``. A member
  named ``//`` holds the long names, one after another, each ended by ``/\\n`` (or
  ``\\0`` in Windows libraries), and a member named ``/123`` takes the long name at
  offset 123 of that table. The table comes before the members that use it, so the
  walk keeps it. The symbol table is a member named ``/`` (``/SYM64/`` for 64-bit
  offsets).
- **BSD** (and macOS): a short name is stored as it is. A member named ``#1/20`` has a
  20-byte name at the **start of its data area**, which the header's size counts, so
  its data starts after the name rather than after the header. macOS pads that name
  with NULs, and pads each member with ``\\n`` so the next header starts on 8 bytes,
  counting that padding in the member's size: the padding is then part of the member,
  as llvm-ar and bsdtar extract it. The symbol table is a member named ``__.SYMDEF``
  (or ``__.SYMDEF SORTED``, ``__.SYMDEF_64``).

Symbol tables are the linker's index, not files: the walk skips them, and the archive
info says one was there. A *thin* archive (``!<thin>\\n``) stores only the names of
files kept outside it and is refused.

The reader is written against ``archivey.formats`` and archivey's public names only,
as a format added from outside would be; ``register_builtin_format`` and the
salvage search (``internal.salvage``, which has no plugin hook yet) are the internal
names it uses (``tests/test_ar.py`` checks). With ``open_archive(salvage=True)`` the
walk searches past damage for the next header (``_search``). Handbook page:
``dev-docs/formats/ar.md``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.salvage import HeaderSearch, WalkSalvage
from archivey.terminal import quoted
from archivey.types import ArchiveFormat, ArchiveInfoExtra, ArchiveMember, MemberType

MAGIC = b"!<arch>\n"
THIN_MAGIC = b"!<thin>\n"
HEADER_SIZE = 60
_HEADER_END = b"`\n"
# A BSD name longer than this is damage: no file system takes a path this long.
MAX_NAME_BYTES = 64 * 1024
_GNU_SYMBOL_TABLES = (b"/", b"/SYM64/")
_BSD_SYMBOL_TABLES = (
    b"__.SYMDEF",
    b"__.SYMDEF SORTED",
    b"__.SYMDEF_64",
    b"__.SYMDEF_64 SORTED",
)


def _field(raw: bytes, base: int, what: str, offset: int) -> int | None:
    """A numeric header field, or None when it is blank. Spaces on either side are
    padding, as GNU ar and libarchive read them; a sign is refused."""
    text = raw.strip(b" ")
    if not text:
        return None
    # Digits valid in the base: isdigit() alone would let 8 and 9 into an octal mode.
    if not text.isdigit() or (base == 8 and not set(text) <= set(b"01234567")):
        raise CorruptionError(
            f"ar header at offset {offset}: the {what} field "
            f"{quoted(raw.decode('ascii', 'surrogateescape'))} is not a number"
        )
    return int(text, base)


# What ends an entry of the GNU long-name table.
_NAME_END = re.compile(rb"[\n\0]")


_OCTAL = frozenset(b"01234567")
_DIGITS_AND_SPACES = re.compile(rb"[0-9 ]*\Z")


class _Entry(NamedTuple):
    """What one ar header holds: its size field, and a member (with how many of its
    bytes are data), a long-name table, or neither (a symbol table)."""

    size: int
    member: ArchiveMember | None = None
    data_length: int = 0
    unchecked: tuple[str, ...] = ("position",)
    table: bytes | None = None


def _passes(window: bytes, at: int) -> bool:
    """Whether a header the salvage search accepts starts at ``at`` of ``window``:
    60 bytes ending in the header end, with a size, an octal or blank mode, and
    date, uid and gid fields of digits and spaces only."""
    header = window[at : at + HEADER_SIZE]
    if len(header) < HEADER_SIZE or header[58:] != _HEADER_END:
        return False
    size = header[48:58].strip(b" ")
    mode = header[40:48].strip(b" ")
    return (
        size.isdigit()
        and set(mode) <= _OCTAL
        and _DIGITS_AND_SPACES.match(header[16:40]) is not None
    )


def _search_at(step: int) -> HeaderSearch:
    """The salvage search for an ar header at every ``step`` bytes."""

    def find_header(window: bytes, start: int) -> int | None:
        at = start + 58
        while True:
            end = window.find(_HEADER_END, at)
            if end < 0:
                return None
            candidate = end - 58
            if candidate % step == 0 and _passes(window, candidate):
                return candidate
            at = end + 1

    return HeaderSearch(find_header, step, HEADER_SIZE)


# Headers start on 2 bytes, counted from the archive's start; after a lost start
# that start is not known, and the first header is searched for at every byte.
AR_HEADER_SEARCH = _search_at(2)
_SEARCH_ANY_BYTE = _search_at(1)


def ar_confirmed(salvage: WalkSalvage, after: int) -> bool:
    """Whether the header at ``after``, past a member's padded data, passes the
    search's check, or the archive ends there. A probe the decoding limits refuse
    reads as nothing, and the layer does not hold the bytes before ``after`` then
    either: unconfirmed."""
    head = salvage.read_at(after, HEADER_SIZE)
    if not head:
        # The last pad byte may be missing (a writer that leaves it off).
        return salvage.holds(after - 1)
    return _passes(head, 0)


class ArReader(SequentialReader):
    """Walks an ar archive of either dialect."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        # Both are what the walk has seen so far: in a streaming pass they can change
        # until the walk ends (a table after the first member, a dialect only a later
        # name shows). GNU ar and llvm-ar write the table first.
        self._dialect: str | None = None
        self._symbol_table = False

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        extra = ArchiveInfoExtra({"ar.symbol_table": self._symbol_table})
        if self._dialect is not None:
            extra["ar.dialect"] = self._dialect
        # A dialect is not a version: like TAR's, it is not in format_version.
        return ReaderArchiveInfo(extra=extra)

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        # Salvage (``open_archive(salvage=True)``): the layer's search, the first
        # damage the walk met, where the next search starts, and the origin of the
        # candidate positions: 0, the first header found after a lost start, or
        # ``None`` while a lost start's search runs at every byte.
        salvage = self._context._salvage(stream) if self._context._salvage else None
        damage: CorruptionError | None = None
        search_from: int | None = None
        base: int | None = 0
        magic = stream.read(len(MAGIC))
        if magic == THIN_MAGIC:
            raise UnsupportedFeatureError(
                "thin ar archive: its members are files stored outside the archive"
            )
        if magic != MAGIC:
            if not magic:
                error: CorruptionError = TruncatedError("ar archive is empty")
            elif MAGIC.startswith(magic):
                error = TruncatedError("ar archive ends inside its magic")
            else:
                error = CorruptionError("No ar magic at offset 0")
            if salvage is None or not salvage.lost_start:
                raise error
            # A lost start: the first header is found by a search from 0.
            damage = error
            search_from = 0
            base = None
        names: bytes | None = None
        while True:
            # Whether the search found this header, or the walk walked on to it.
            searched = search_from is not None
            if search_from is not None:
                assert salvage is not None and damage is not None
                hit = self._search(salvage, stream, search_from, base, names)
                search_from = None
                if hit is None:
                    raise salvage.ending(damage)
                offset, entry = hit
                base = offset % 2
            else:
                offset = stream.offset
                raw = stream.read(HEADER_SIZE)
                if not raw:
                    if salvage is not None:
                        if damage is not None:
                            raise salvage.ending(damage)
                        salvage.state.finish()
                    return
                try:
                    entry = self._entry(
                        stream, raw, offset, names, salvaging=damage is not None
                    )
                except CorruptionError as err:
                    if salvage is None:
                        raise
                    # Damage: the walk searches on from the damaged header, and the
                    # pass ends in this error.
                    damage = damage or err
                    search_from = offset
                    continue
            confirmed = True
            if damage is not None:
                # Past the damage every header is one the default does not reach. It
                # claims its data only when the header after it passes too.
                assert salvage is not None
                size = entry.size
                if not searched and not salvage.holds(offset + HEADER_SIZE + size):
                    # Data that runs past the layer's end, as ``_search`` refuses for
                    # a found header: not listed, since reading it would end the pass
                    # in TruncatedError. The search goes on past this header.
                    search_from = salvage.after(offset)
                    continue
                confirmed = ar_confirmed(
                    salvage, offset + HEADER_SIZE + size + (size & 1)
                )
                if not confirmed:
                    # The search goes on inside its data, past this header, which it
                    # must not find again.
                    search_from = salvage.after(offset)
            if entry.table is not None:
                names = entry.table
                continue
            member = entry.member
            if member is None:
                # A symbol table, skipped.
                continue
            if damage is not None:
                assert salvage is not None
                salvage.found(
                    member,
                    offset=offset,
                    confirmed=confirmed,
                    unchecked=entry.unchecked,
                    searched=searched,
                )
            yield MemberSpan(member, entry.data_length)
            # The pad byte; a writer that leaves it off the last member is harmless.
            stream.read(entry.size & 1)

    def _entry(
        self,
        stream: ForwardStream,
        raw: bytes,
        offset: int,
        names: bytes | None,
        *,
        salvaging: bool,
    ) -> _Entry:
        """What the header ``raw`` at ``offset`` holds, the stream moved past what
        the walk reads of it: a member's data is left for archivey. ``salvaging``
        (past damage in salvage mode) keeps a GNU ``/123`` name whose table is not
        there, and takes a second long-name table."""
        if len(raw) < HEADER_SIZE:
            raise TruncatedError(
                f"ar archive ends {len(raw)} bytes into the header at offset {offset}"
            )
        if raw[58:] != _HEADER_END:
            raise CorruptionError(f"No ar member header at offset {offset}")
        size = _field(raw[48:58], 10, "size", offset)
        if size is None:
            raise CorruptionError(f"ar header at offset {offset} has no size")
        unchecked: tuple[str, ...] = ("position",)
        name_field = raw[:16].rstrip(b" ")
        if name_field.startswith(b"#1/"):
            self._dialect = self._dialect or "bsd"
            name_size = _field(name_field[3:], 10, "name length", offset)
            if name_size is None:
                raise CorruptionError(
                    f"ar header at offset {offset}: the name length is blank"
                )
            if not name_size or name_size > min(size, MAX_NAME_BYTES):
                raise CorruptionError(
                    f"ar header at offset {offset}: a name of {name_size} bytes "
                    f"in a member of {size}"
                )
            name = stream.read_exact(name_size).rstrip(b"\0")
            data_length = size - name_size
            if name in _BSD_SYMBOL_TABLES:
                self._symbol_table = True
                stream.skip(data_length)
                stream.read(size & 1)
                return _Entry(size)
        elif name_field in _GNU_SYMBOL_TABLES or name_field in _BSD_SYMBOL_TABLES:
            # The symbol table's spelling names the dialect too.
            gnu = name_field in _GNU_SYMBOL_TABLES
            self._dialect = self._dialect or ("gnu" if gnu else "bsd")
            self._symbol_table = True
            stream.skip(size)
            stream.read(size & 1)
            return _Entry(size)
        elif name_field == b"//":
            self._dialect = "gnu"
            if names is not None and not salvaging:
                raise CorruptionError(
                    f"ar archive has a second long-name table at offset {offset}"
                )
            # The table is held for the whole walk: text the listing retains.
            self._context.charge_metadata(size, what="the ar long-name table")
            table = stream.read_exact(size)
            stream.read(size & 1)
            return _Entry(size, table=table)
        else:
            found = self._short_name(name_field, names, offset, salvaging=salvaging)
            if found is None:
                # A long name whose table the damage took: the raw name stays.
                name = name_field
                unchecked = ("position", "name")
            else:
                name = found
            data_length = size
        if not name:
            raise CorruptionError(f"ar header at offset {offset} has no name")
        member = self._member(raw, name, data_length, offset)
        return _Entry(size, member=member, data_length=data_length, unchecked=unchecked)

    def _search(
        self,
        salvage: WalkSalvage,
        stream: ForwardStream,
        start: int,
        base: int | None,
        names: bytes | None,
    ) -> tuple[int, _Entry] | None:
        """The next header the salvage search finds from ``start`` that the walk
        reads and whose data the layer holds, with its offset; the stream is moved
        past what the walk reads of it. ``None`` when none is found."""
        search = _SEARCH_ANY_BYTE if base is None else AR_HEADER_SEARCH
        while True:
            result = salvage.search(search, start=start, base=base or 0)
            if result.found is None:
                return None
            at = result.found
            salvage.seek(at)
            try:
                entry = self._entry(
                    stream, stream.read(HEADER_SIZE), at, names, salvaging=True
                )
            except CorruptionError:
                start = at
                continue
            if not salvage.holds(at + HEADER_SIZE + entry.size):
                start = at
                continue
            return at, entry

    def _short_name(
        self, field: bytes, names: bytes | None, offset: int, *, salvaging: bool = False
    ) -> bytes | None:
        """The name a GNU or short BSD name field gives; ``None``, when
        ``salvaging``, for a long name the table does not hold."""
        if field.startswith(b"/") and field[1:].isdigit():
            self._dialect = "gnu"
            if names is None:
                if salvaging:
                    return None
                raise CorruptionError(
                    f"ar header at offset {offset} names entry {field[1:].decode()} "
                    "of a long-name table the archive has not given"
                )
            at = int(field[1:])
            if at >= len(names):
                if salvaging:
                    return None
                raise CorruptionError(
                    f"ar header at offset {offset}: long-name offset {at} is past the "
                    f"{len(names)}-byte table"
                )
            # The entry ends at its first newline or NUL, or at the end of the table.
            # One scan stops at whichever comes first, so a lookup costs the entry's
            # length and not the table's, and only the entry is sliced.
            found = _NAME_END.search(names, at)
            stop = len(names) if found is None else found.start()
            return names[at:stop].removesuffix(b"/")
        if field.endswith(b"/"):
            self._dialect = "gnu"
            return field[:-1]
        self._dialect = self._dialect or "bsd"
        return field

    def _member(self, raw: bytes, name: bytes, size: int, offset: int) -> ArchiveMember:
        context = self._context
        mtime = _field(raw[16:28], 10, "mtime", offset)
        mode = _field(raw[40:48], 8, "mode", offset)
        member = ArchiveMember(
            type=MemberType.FILE,
            name=context.decode_name(name),
            raw_name=name,
            size=size,
            mode=None if mode is None else mode & 0o7777,
            uid=_field(raw[28:34], 10, "uid", offset),
            gid=_field(raw[34:40], 10, "gid", offset),
        )
        # A blank field records no time; 12 decimal digits reach past what a
        # datetime holds, which is reported.
        if mtime is not None:
            context.set_unix_time(member, "modified", mtime, source="ar")
        return member


class ArHandler(SequentialFormatHandler):
    """ar archives in the GNU (System V) and BSD dialects: ``.a``, ``.ar``, ``.lib``."""

    format = ArchiveFormat.AR
    extensions = (".a", ".ar", ".lib")
    # A thin archive is claimed too, so that opening one says why it cannot be read.
    magic = (Magic(0, MAGIC), Magic(0, THIN_MAGIC))
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> ArReader:
        return ArReader(context)


ArReadBackend = register_builtin_format(ArHandler, SUPPORTS_SALVAGE=True)
