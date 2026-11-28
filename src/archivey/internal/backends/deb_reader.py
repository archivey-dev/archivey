"""The Debian package reader: a ``.deb`` read as the files it installs.

A ``.deb`` is an ar archive of three members, in this order::

    debian-binary        "2.0\\n": the package format version
    control.tar[.gz|.xz|.zst]          the maintainer files: control, md5sums, scripts
    data.tar[.gz|.xz|.zst|.bz2|.lzma]  the files the package installs

The listing is what ``dpkg-deb -R`` unpacks: the data tar's members under their own
names, and the control tar's under ``DEBIAN/``. ``debian-binary`` is not listed; opening
the file with ``format=ArchiveFormat.AR`` gives the three ar members instead. Both tars
are read through :meth:`ReaderContext.open_nested`, in the one forward pass, so a
``.deb`` reads from a pipe.

As ``dpkg-deb`` does, the walk refuses a version other than ``2.x``, skips members
whose name starts with ``_`` before the data tar, refuses any other member there, and
stops after the data tar. It also keeps the two tars apart, as ``dpkg-deb -R`` does: a
data-tar member that can extract to ``DEBIAN`` or under it, in any spelling or through a
data-tar symlink, is refused, and so is a control-tar member that extracts outside
``DEBIAN/``, a hard link in either tar whose target crosses to the other, and a data-tar
symlink whose target lands in ``DEBIAN``, at once or once a later symlink moves it.
``dpkg-deb -R`` unpacks the data tar first, then fails on a ``DEBIAN`` path the data tar
made, and GNU tar refuses a ``..`` name. ``DEBIAN/md5sums`` lists an MD5 per installed
file: the walk holds it (it is part of the control tar, so it arrives first) and gives
each data file its digest in ``ArchiveMember.hashes``, which a read then checks. A line
that is not an MD5 and a name is skipped, as ``dpkg --verify`` skips it.

The reader uses archivey's public names only, as a format added from outside would
(``tests/test_plugin_modules_use_public_api.py`` checks), apart from the salvage
search's names (``internal.salvage``, which has no plugin hook yet). With
``open_archive(salvage=True)``, damage to an ar header after ``debian-binary`` starts
a search for the next one (``_search``), with the package's own copy of the ar
reader's checks.

Handbook page: ``dev-docs/formats/deb.md``.
"""

from __future__ import annotations

import io
import itertools
import re
import typing
from collections.abc import Generator, Iterator
from typing import TYPE_CHECKING, BinaryIO

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
from archivey.internal.salvage import HeaderSearch, WalkSalvage, walk_salvage
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ContainerFormat,
    HashAlgorithm,
    MemberType,
    StreamFormat,
)

# ``typing.override`` (Python 3.12) where there is one. A format written outside
# archivey carries the same lines, so the module imports no internal name for it.
if TYPE_CHECKING:
    from typing_extensions import override
else:
    override = getattr(typing, "override", lambda method: method)

AR_MAGIC = b"!<arch>\n"
HEADER_SIZE = 60
VERSION_MEMBER = b"debian-binary"
# The first member's name field, as dpkg-deb (no slash) and GNU ar (a slash) write it.
MAGIC = (
    AR_MAGIC + VERSION_MEMBER.ljust(16),
    AR_MAGIC + (VERSION_MEMBER + b"/").ljust(16),
)
# The control tar's members are listed under it, and no data member may reach it
# (ReaderContext.open_nested(under=, keep_out=)).
CONTROL_DIR = "DEBIAN/"
# dpkg-deb accepts these compressions for each tar.
_CONTROL_STREAMS = {
    b"": StreamFormat.UNCOMPRESSED,
    b".gz": StreamFormat.GZIP,
    b".xz": StreamFormat.XZ,
    b".zst": StreamFormat.ZSTD,
}
_DATA_STREAMS = {
    **_CONTROL_STREAMS,
    b".bz2": StreamFormat.BZIP2,
    b".lzma": StreamFormat.LZMA_ALONE,
}
# The control file's fields the archive info carries (as deb.package and so on).
_FIELDS = (b"package", b"version", b"architecture")
_HEX = frozenset(b"0123456789abcdefABCDEF")
# The digits of an unsupported major version an error message shows.
_VERSION_SHOWN = 20
# What one md5sums entry holds beyond its name's characters (_str_bytes), as 64-bit
# CPython measures it: the name's str header (40 to 56 bytes), the 16-byte digest object
# (49) and the entry's share of the dict, a 24-byte slot, its index and the spare room a
# dict keeps (31 bytes an entry over 500 000 entries, up to 60 just after the dict
# grows). A constant, not sys.getsizeof(), which PyPy does not implement.
_MD5_ENTRY = 56 + 49 + 48


def _str_bytes(text: str) -> int:
    """The bytes CPython stores for ``text``'s characters: 1, 2 or 4 a character, as
    its widest character needs. One emoji makes a long name 4 bytes a character, and
    one undecodable byte (a lone surrogate) 2."""
    if text.isascii():
        return len(text)
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        pass
    else:
        return len(text)
    # In UTF-16 a character above U+FFFF takes 4 bytes, and every other one 2.
    if len(text.encode("utf-16-le", "surrogatepass")) > 2 * len(text):
        return 4 * len(text)
    return 2 * len(text)


# The salvage search of the package's ar level. The same checks as the ar reader's
# (``ar_reader._passes``, ``AR_HEADER_SEARCH`` and ``ar_confirmed``), kept here
# because the deb reader uses public names only, as a format from outside would:
# importing the ar reader would make one plugin depend on another.
# ``tests/test_salvage_cpio_ar.py`` checks that the two copies agree.
_AR_HEADER_END = b"`\n"
_OCTAL = frozenset(b"01234567")
_DIGITS_AND_SPACES = re.compile(rb"[0-9 ]*\Z")


def _ar_passes(window: bytes, at: int) -> bool:
    """Whether an ar header the salvage search accepts starts at ``at`` of
    ``window``: 60 bytes ending in the header end, with a size, an octal or blank
    mode, and date, uid and gid fields of digits and spaces only."""
    header = window[at : at + HEADER_SIZE]
    if len(header) < HEADER_SIZE or header[58:] != _AR_HEADER_END:
        return False
    size = header[48:58].strip(b" ")
    mode = header[40:48].strip(b" ")
    return (
        size.isdigit()
        and set(mode) <= _OCTAL
        and _DIGITS_AND_SPACES.match(header[16:40]) is not None
    )


def _find_ar_header(window: bytes, start: int, stop: int) -> int | None:
    """The first ar header at an even candidate position from ``start`` and before
    ``stop`` that passes (``HeaderSearch.find_header``)."""
    at = start + 58
    while True:
        end = window.find(_AR_HEADER_END, at, stop + 59)
        if end < 0:
            return None
        candidate = end - 58
        if candidate % 2 == 0 and _ar_passes(window, candidate):
            return candidate
        at = end + 1


# ar headers start on 2 bytes, counted from the package's start.
_AR_HEADER_SEARCH = HeaderSearch(_find_ar_header, 2, HEADER_SIZE)


def _ar_confirmed(salvage: WalkSalvage, after: int) -> bool:
    """Whether the header at ``after``, past a member's padded data, passes the
    search's check, or the package ends there."""
    head = salvage.read_at(after, HEADER_SIZE)
    if not head:
        # The last pad byte may be missing (a writer that leaves it off).
        return salvage.holds(after - 1)
    return _ar_passes(head, 0)


def _tar_format(
    name: bytes, kind: bytes, streams: dict[bytes, StreamFormat]
) -> ArchiveFormat | None:
    """The format of ``control.tar.xz`` and its kin, or None for another name."""
    stem = kind + b".tar"
    if not name.startswith(stem):
        return None
    stream = streams.get(name[len(stem) :])
    return None if stream is None else ArchiveFormat(ContainerFormat.TAR, stream)


class DebReader(SequentialReader):
    """Walks a ``.deb``: its two tars, through the nested-archive hook."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._version: str | None = None
        self._fields: dict[bytes, str] = {}
        self._md5: dict[str, bytes] = {}

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        # What the walk has seen so far: in a streaming pass the fields arrive with the
        # control tar.
        fields = self._fields
        extra = ArchiveInfoExtra()
        if b"package" in fields:
            extra["deb.package"] = fields[b"package"]
        if b"version" in fields:
            extra["deb.version"] = fields[b"version"]
        if b"architecture" in fields:
            extra["deb.architecture"] = fields[b"architecture"]
        return ReaderArchiveInfo(
            is_solid=True, format_version=self._version, extra=extra
        )

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        magic = stream.read(len(AR_MAGIC))
        if magic != AR_MAGIC:
            if AR_MAGIC.startswith(magic):
                raise TruncatedError("Debian package ends inside its ar magic")
            raise CorruptionError("No ar magic at offset 0")
        name, size = self._header(stream)
        if name != VERSION_MEMBER:
            raise CorruptionError(
                "Debian package does not start with its debian-binary member"
            )
        # dpkg-deb allocates whatever size the header gives; archivey counts it
        # against max_metadata_bytes before reading it, like the control files.
        self._count(size, "debian-binary member")
        self._read_version(stream.read_exact(size))
        stream.read(size & 1)
        # Salvage (``open_archive(salvage=True)``): where an ar header after
        # debian-binary is damaged, the walk searches on for the next ar header, as
        # the ar reader does, and lists the tar it finds; the pass ends in the first
        # damage. The tars themselves are read as they are.
        salvage = walk_salvage(self._context, stream)
        damage: CorruptionError | None = None
        search_from: int | None = None
        control = False
        # A control tar past the damage that nothing confirmed has been listed. At
        # most one is: a later unconfirmed one may sit inside the data of the one
        # listed, and would list its members again, so the listing would grow with
        # the square of the layer. A confirmed one is still read after it.
        stray_control = False
        while True:
            # Whether the search found this header, or the walk walked on to it.
            searched = search_from is not None
            if search_from is not None:
                assert salvage is not None and damage is not None
                hit = self._search(salvage, stream, search_from)
                search_from = None
                if hit is None:
                    raise salvage.ending(damage)
                offset, name, size = hit
            else:
                offset = stream.offset
                try:
                    name, size = self._header(stream)
                except CorruptionError as err:
                    if salvage is None or not salvage.is_damage(err):
                        raise
                    damage = damage or err
                    search_from = offset
                    continue
            confirmed = True
            if damage is not None:
                # Past the damage, a member claims its data only when the header
                # after it passes too, or the package ends there.
                assert salvage is not None
                if not searched and not salvage.holds(offset + HEADER_SIZE + size):
                    # Data that runs past the layer's end, as ``_search`` refuses for
                    # a found header: not listed, since reading it would end the pass
                    # in TruncatedError. The search goes on past this header.
                    search_from = salvage.after(offset)
                    continue
                confirmed = _ar_confirmed(
                    salvage, offset + HEADER_SIZE + size + (size & 1)
                )
                if not confirmed:
                    # The search goes on inside its data, past this header.
                    search_from = salvage.after(offset)
            if name.startswith(b"_"):
                stream.skip(size)
                stream.read(size & 1)
                continue
            fmt = (
                None
                if control or (stray_control and not confirmed)
                else _tar_format(name, b"control", _CONTROL_STREAMS)
            )
            if fmt is not None:
                # Only a control tar the walk counts (``confirmed``) is the package's:
                # its fields, its md5sums and the end of the search for one. One
                # nothing confirms is listed and changes nothing else, so a later
                # control tar is still read.
                spans = self._opened(
                    self._control(stream.take(size), fmt, settles=confirmed), damage
                )
                if spans is None:
                    # Past the damage, a control tar that does not open is not one:
                    # the search goes on past its header.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                whole = yield from self._found(
                    salvage if damage else None, spans, offset, confirmed, searched
                )
                control = control or confirmed
                stray_control = stray_control or not confirmed
                if not whole:
                    # The control tar failed after listing members: the search goes
                    # on past its header, for the data tar.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                stream.read(size & 1)
                continue
            fmt = _tar_format(name, b"data", _DATA_STREAMS)
            if fmt is None:
                if damage is not None:
                    # A header past the damage that is not a package member: the
                    # search goes on past it.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                if not control:
                    raise CorruptionError(
                        "Debian package has no control.tar member after debian-binary"
                    )
                raise CorruptionError(
                    "Debian package has an unexpected member before its data.tar"
                )
            if not control and damage is None:
                raise CorruptionError(
                    "Debian package has no control.tar member after debian-binary"
                )
            spans = self._opened(self._data(stream.take(size), fmt), damage)
            if spans is None:
                # Past the damage, a data tar that does not open is not one: the
                # search goes on past its header, as for a control tar.
                assert salvage is not None
                search_from = salvage.after(offset)
                continue
            yield from self._found(
                salvage if damage else None, spans, offset, confirmed, searched
            )
            # dpkg-deb reads no further: members after the data tar are not part of
            # the package.
            if salvage is not None:
                if damage is not None:
                    raise salvage.ending(damage)
                salvage.state.finish()
            return

    @staticmethod
    def _opened(
        spans: Iterator[MemberSpan], damage: CorruptionError | None
    ) -> Iterator[MemberSpan] | None:
        """``spans`` with its first member read, or ``None`` when the tar is past
        ``damage`` and reading its first member raises ``CorruptionError``.

        The salvage search checks little of an ar header (a name, a size, a date), so
        a header past the damage can name a tar whose payload is not one. Such a tar
        lists nothing and is not the package's: the walk searches on, and the pass
        ends in the first damage. Before any damage, or once the tar has listed a
        member, its error is the package's and is raised.
        """
        if damage is None:
            return spans
        try:
            first = next(spans)
        except StopIteration:
            return iter(())
        except CorruptionError as exc:
            if not WalkSalvage.is_damage(exc):
                raise
            return None
        return itertools.chain((first,), spans)

    @staticmethod
    def _found(
        salvage: WalkSalvage | None,
        spans: Iterator[MemberSpan],
        offset: int,
        confirmed: bool,
        searched: bool,
    ) -> Generator[MemberSpan, None, bool]:
        """``spans``, each member flagged with ``MEMBER_FOUND_BY_SCAN`` when
        ``salvage`` is given: the tar's ar header at ``offset`` is past damage, found
        by the search (``searched``) or walked on to.

        Returns whether the tar listed to its end. Past damage, a tar that raises
        ``CorruptionError`` after its first member ends there and returns ``False``:
        the pass still ends in the first damage, the package's own error. Before
        damage, and for an exception ``on_source_read`` raised, the error is raised.
        """
        try:
            for span in spans:
                if salvage is not None:
                    salvage.found(
                        span.member,
                        offset=offset,
                        confirmed=confirmed,
                        searched=searched,
                    )
                yield span
        except CorruptionError as exc:
            if salvage is None or not salvage.is_damage(exc):
                raise
            return False
        return True

    def _search(
        self, salvage: WalkSalvage, stream: ForwardStream, start: int
    ) -> tuple[int, bytes, int] | None:
        """The next ar header the salvage search finds from ``start`` whose data
        the package holds, with its offset, name and size; the stream is moved to
        its data. ``None`` when none is found."""
        while True:
            result = salvage.search(_AR_HEADER_SEARCH, start=start)
            if result.found is None:
                return None
            at = result.found
            salvage.seek(at)
            try:
                name, size = self._header(stream)
            except CorruptionError as exc:
                if not salvage.is_damage(exc):
                    raise
                start = at
                continue
            if not salvage.holds(at + HEADER_SIZE + size):
                start = at
                continue
            return at, name, size

    def _header(self, stream: ForwardStream) -> tuple[bytes, int]:
        """The next ar member's name and size."""
        offset = stream.offset
        raw = stream.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            raise TruncatedError(
                f"Debian package ends {len(raw)} bytes into the ar header at offset "
                f"{offset}"
            )
        if raw[58:] != b"`\n":
            raise CorruptionError(f"No ar member header at offset {offset}")
        text = raw[48:58].strip(b" ")
        if not text.isdigit():
            raise CorruptionError(
                f"ar header at offset {offset}: the size field is not a number"
            )
        # dpkg-deb writes short names only; GNU ar ends them with a slash.
        return raw[:16].rstrip(b" ").removesuffix(b"/"), int(text)

    def _read_version(self, data: bytes) -> None:
        version = data.split(b"\n", 1)[0].strip()
        major, dot, _minor = version.partition(b".")
        if not (major.isdigit() and dot):
            raise CorruptionError("Debian package has no format version")
        # The digits are compared as bytes: int() refuses more than 4300 digits with
        # a ValueError, and the member may hold millions.
        digits = major.lstrip(b"0") or b"0"
        if digits != b"2":
            shown = digits[:_VERSION_SHOWN].decode("ascii")
            if len(digits) > _VERSION_SHOWN:
                shown += f"... ({len(digits)} digits)"
            raise UnsupportedFeatureError(
                f"Debian package format version {shown}: archivey reads 2.x, "
                "as dpkg-deb does"
            )
        self._version = version.decode("ascii", "replace")

    def _control(
        self, data: BinaryIO, fmt: ArchiveFormat, *, settles: bool = True
    ) -> Iterator[MemberSpan]:
        """The control tar's members, under ``DEBIAN/``.

        ``control`` and ``md5sums`` are read whole on the way, for the archive info and
        the data files' digests, so their spans are served from those held bytes.
        ``open_nested(under=)`` refuses a member whose prefixed name extracts outside
        ``DEBIAN/`` (``../usr/x``), a hard link whose prefixed target does, and a
        member under a symlink of the control tar. The folder is compared as spelled:
        folding would accept ``../debian/x``, which is data on Linux. Not when ``settles`` is false
        (a tar past damage that nothing confirms): its members are listed as they are,
        and it holds and charges nothing.
        """
        for span in self._context.open_nested(data, fmt, under=CONTROL_DIR):
            member = span.member
            inner = member.name.removeprefix(CONTROL_DIR)
            if (
                settles
                and member.type is MemberType.FILE
                and inner in ("control", "md5sums")
            ):
                held, span = self._hold(span, inner)
                if inner == "control":
                    self._read_control(held)
                else:
                    self._read_md5sums(held)
            yield span

    def _data(self, data: BinaryIO, fmt: ArchiveFormat) -> Iterator[MemberSpan]:
        """The data tar's members, each file with its digest from ``md5sums``.

        A member that can extract to ``DEBIAN`` or under it, under any spelling that
        extraction or the filesystem makes one with it, is refused, and so is a hard
        link whose target can. The test is stricter than ``dpkg-deb -R``, which GNU
        tar on Linux reads byte for byte: ``usr\\..\\DEBIAN/x`` (``sanitize_names``
        and Windows read the backslashes as separators), ``C:/DEBIAN/x`` (extraction
        drops a drive root on every OS), ``DEBIAN./x`` and ``DEBIAN /x`` (``STRICT``
        and Win32 trim the dot or space) and ``debian/x`` (one directory with
        ``DEBIAN/`` on a case-insensitive filesystem). ``open_nested(keep_out=)``
        makes every check of this docstring.

        The control files are listed under ``DEBIAN/``, so a data copy of
        ``DEBIAN/control`` would replace the real control file in the listing and in
        extraction, and a hard link would read a control file's bytes.

        The same holds through the data tar's symlinks: a symlink whose
        target lands in ``DEBIAN`` is refused (``foo -> DEBIAN``,
        ``usr/l -> ../DEBIAN``, ``x -> /DEBIAN/control``), and so is a member or a
        hard-link target that lands there through an earlier symlink (``d -> .``, then
        ``d/DEBIAN/control``). A later symlink that sends an earlier one's target there
        is refused too (``x -> y/DEBIAN/control``, then ``y -> .`` refuses ``y``), and
        so is one whose target lands there lexically, as a read of the symlink resolves
        it (``x -> y/../DEBIAN/control``). So that this holds for every selection of
        members, a member under a data symlink is refused, and so is a symlink at the
        path of a directory or another symlink. A hard link to a symlink
        is checked as the symlink extraction makes of it (``q/h`` linked to
        ``a/b/x -> ../DEBIAN`` names ``DEBIAN``). Otherwise extraction writes through
        the symlink into a control file, and a read of the symlink returns one.
        ``dpkg-deb -R`` unpacks the data tar first, so there such a symlink names
        nothing; refusing it is stricter, as the spellings above are.
        """
        for span in self._context.open_nested(data, fmt, keep_out=(CONTROL_DIR,)):
            member = span.member
            if member.type is MemberType.FILE:
                digest = self._md5.get(member.name)
                if digest is not None:
                    member.hashes = {**member.hashes, HashAlgorithm.MD5: digest}
            yield span

    def _hold(self, span: MemberSpan, name: str) -> tuple[bytes, MemberSpan]:
        """A control file's bytes, read whole, against ``max_metadata_bytes``, and its
        span with the data served from them."""
        # ``name`` is "control" or "md5sums", never a name from elsewhere.
        self._count(span.member.size or 0, f"control file {name}")
        return self._context.read_nested(span)

    def _count(self, size: int, what: str) -> None:
        """Charge ``size`` more held bytes to the listing, refusing before they are
        read. ``debian-binary``, ``control`` and ``md5sums`` are held whole, and
        their sizes come from the package. Each entry of the digest map is charged
        too, as it is added, at an estimate of what it holds. A walk started over to
        reach member data charges nothing: the listing walk did."""
        self._context.charge_metadata(size, what=f"the Debian package {what}")

    def _read_control(self, data: bytes) -> None:
        """The first paragraph's Package, Version and Architecture fields."""
        for line in data.split(b"\n"):
            if not line.strip():
                break
            field, colon, value = line.partition(b":")
            key = field.strip().lower()
            if colon and key in _FIELDS and not line[:1].isspace():
                self._fields[key] = value.strip().decode("utf-8", "replace")

    def _read_md5sums(self, data: bytes) -> None:
        """``<32 hex digits> <name>`` per line, the name relative to the root.

        The lines are read one at a time, not split into a list, and each entry the
        map keeps is charged to ``max_metadata_bytes`` before it is added: the file's
        own bytes were charged when it was held, and the map holds about three times
        as much again for short ASCII names, more for names stored wider."""
        context = self._context
        md5 = self._md5
        for line in io.BytesIO(data):
            digest, _space, name = line.removesuffix(b"\n").partition(b" ")
            # md5sum writes two spaces, the second a " " (text) or "*" (binary) mark.
            name = name[1:] if name[:1] in (b" ", b"*") else name
            if len(digest) != 32 or not set(digest) <= _HEX or not name:
                continue
            path = context.normalize_name(context.decode_name(name), MemberType.FILE)
            if path not in md5:
                self._count(_str_bytes(path) + _MD5_ENTRY, "md5sums entries")
            md5[path] = bytes.fromhex(digest.decode("ascii"))


class DebHandler(SequentialFormatHandler):
    """Debian binary packages: ``.deb``, and the installer's ``.udeb`` and debug
    symbols' ``.ddeb``, which share the layout."""

    format = ArchiveFormat.DEB
    extensions = (".deb", ".udeb", ".ddeb")
    magic = tuple(Magic(0, m) for m in MAGIC)
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> DebReader:
        return DebReader(context)
