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
  with NULs, and pads each member with ``\n`` so the next header starts on 8 bytes,
  counting that padding in the member's size: the padding is then part of the member,
  as llvm-ar and bsdtar extract it. The symbol table is a member named ``__.SYMDEF`` (or ``__.SYMDEF
  SORTED``, ``__.SYMDEF_64``).

Symbol tables are the linker's index, not files: the walk skips them, and the archive
info says one was there. A *thin* archive (``!<thin>\\n``) stores only the names of
files kept outside it and is refused.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

from archivey import (
    ArchiveMember,
    CorruptionError,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.plugins import (
    ForwardStream,
    MemberSpan,
    PluginArchiveInfo,
    PluginContext,
    SequentialReader,
)

MAGIC = b"!<arch>\n"
THIN_MAGIC = b"!<thin>\n"
HEADER_SIZE = 60
_HEADER_END = b"`\n"
# A BSD name longer than this is damage: no file system takes a path this long.
MAX_NAME_BYTES = 64 * 1024
# The GNU long-name table is held in memory for the whole walk. Even very large static
# libraries keep it to a few MiB.
MAX_NAME_TABLE_BYTES = 16 * 1024 * 1024

_GNU_SYMBOL_TABLES = (b"/", b"/SYM64/")
_BSD_SYMBOL_TABLES = (
    b"__.SYMDEF",
    b"__.SYMDEF SORTED",
    b"__.SYMDEF_64",
    b"__.SYMDEF_64 SORTED",
)


def _field(raw: bytes, base: int, what: str, offset: int) -> int | None:
    """A numeric header field, or None when it is blank."""
    text = raw.rstrip(b" ")
    if not text:
        return None
    try:
        if not text.isdigit():
            raise ValueError(text)
        return int(text, base)
    except ValueError:
        raise CorruptionError(
            f"ar header at offset {offset}: the {what} field {raw!r} is not a number"
        ) from None


def _time(mtime: int | None) -> datetime | None:
    """The modification time, or None when the field is blank or past what a
    ``datetime`` holds (12 decimal digits reach the year 33658)."""
    if mtime is None:
        return None
    try:
        return datetime.fromtimestamp(mtime, UTC)
    except (OverflowError, ValueError, OSError):
        return None


class ArReader(SequentialReader):
    """Walks an ar archive of either dialect."""

    def __init__(self, context: PluginContext) -> None:
        self._context = context
        self._dialect: str | None = None
        self._symbol_table = False

    def archive_info(self) -> PluginArchiveInfo:
        extra: dict[str, object] = {"ar.symbol_table": self._symbol_table}
        if self._dialect is not None:
            extra["ar.dialect"] = self._dialect
        return PluginArchiveInfo(format_version=self._dialect, extra=extra)

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        magic = stream.read(len(MAGIC))
        if magic == THIN_MAGIC:
            raise UnsupportedFeatureError(
                "thin ar archive: its members are files stored outside the archive"
            )
        if magic != MAGIC:
            if not magic:
                raise TruncatedError("ar archive is empty")
            if MAGIC.startswith(magic):
                raise TruncatedError("ar archive ends inside its magic")
            raise CorruptionError("No ar magic at offset 0")
        names: bytes | None = None
        while True:
            offset = stream.offset
            raw = stream.read(HEADER_SIZE)
            if not raw:
                return
            if len(raw) < HEADER_SIZE:
                raise TruncatedError(
                    f"ar archive ends {len(raw)} bytes into the header at offset "
                    f"{offset}"
                )
            if raw[58:] != _HEADER_END:
                raise CorruptionError(f"No ar member header at offset {offset}")
            size = _field(raw[48:58], 10, "size", offset)
            if size is None:
                raise CorruptionError(f"ar header at offset {offset} has no size")
            name_field = raw[:16].rstrip(b" ")
            if name_field.startswith(b"#1/"):
                self._dialect = self._dialect or "bsd"
                name_size = _field(name_field[3:], 10, "name length", offset)
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
                    continue
            elif name_field in _GNU_SYMBOL_TABLES or name_field in _BSD_SYMBOL_TABLES:
                self._symbol_table = True
                stream.skip(size)
                stream.read(size & 1)
                continue
            elif name_field == b"//":
                self._dialect = "gnu"
                if names is not None:
                    raise CorruptionError(
                        f"ar archive has a second long-name table at offset {offset}"
                    )
                if size > MAX_NAME_TABLE_BYTES:
                    raise ResourceLimitError(
                        f"ar long-name table of {size} bytes, over "
                        f"{MAX_NAME_TABLE_BYTES}"
                    )
                names = stream.read_exact(size)
                stream.read(size & 1)
                continue
            else:
                name = self._short_name(name_field, names, offset)
                data_length = size
            if not name:
                raise CorruptionError(f"ar header at offset {offset} has no name")
            yield MemberSpan(self._member(raw, name, data_length, offset), data_length)
            # The pad byte; a writer that leaves it off the last member is harmless.
            stream.read(size & 1)

    def _short_name(self, field: bytes, names: bytes | None, offset: int) -> bytes:
        """The name a GNU or short BSD name field gives."""
        if field.startswith(b"/") and field[1:].isdigit():
            self._dialect = "gnu"
            if names is None:
                raise CorruptionError(
                    f"ar header at offset {offset} names entry {field[1:].decode()} "
                    "of a long-name table the archive has not given"
                )
            at = int(field[1:])
            if at >= len(names):
                raise CorruptionError(
                    f"ar header at offset {offset}: long-name offset {at} is past the "
                    f"{len(names)}-byte table"
                )
            entry = names[at:]
            for end in (b"\n", b"\0"):
                cut = entry.find(end)
                if cut >= 0:
                    entry = entry[:cut]
            return entry.removesuffix(b"/")
        if field.endswith(b"/"):
            self._dialect = "gnu"
            return field[:-1]
        self._dialect = self._dialect or "bsd"
        return field

    def _member(self, raw: bytes, name: bytes, size: int, offset: int) -> ArchiveMember:
        context = self._context
        mtime = _field(raw[16:28], 10, "mtime", offset)
        mode = _field(raw[40:48], 8, "mode", offset)
        return ArchiveMember(
            type=MemberType.FILE,
            name=context.decode_name(name),
            raw_name=name,
            size=size,
            modified=_time(mtime),
            mode=None if mode is None else mode & 0o7777,
            uid=_field(raw[28:34], 10, "uid", offset),
            gid=_field(raw[34:40], 10, "gid", offset),
        )
