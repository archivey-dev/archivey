"""An XAR reader (``.xar``, macOS ``.pkg`` and ``.xip``), written against
``archivey.formats``.

The layout, from Apple's ``xar`` sources (``include/xar.h.in``, ``lib/archive.c``) and
libarchive's ``archive_read_support_format_xar.c``: a big-endian header (``xar!``, its
own size, version 1, the compressed and decoded sizes of the table of contents, and the
checksum algorithm), then the table of contents, an XML document compressed with zlib,
then the heap. The TOC lists each file as a ``<file>`` element, nested under its
directory's, with its type, mode, owners and times, and, for one with data, a ``<data>``
element: where its bytes sit in the heap, their stored and decoded lengths, the
encoding, and checksums of both. The TOC's own checksum sits in the heap too, at the
offset ``<toc><checksum>`` gives.

The reader reads the whole TOC at open, bounded by ``max_metadata_bytes`` before it is
decoded and by ``max_members`` while it is parsed, and checks its checksum. The XML is
parsed with expat, refusing a document type declaration, so no entity is ever
expanded. A member's data is decoded through archivey's codecs, refusing any byte
after the end of its stream, and checked against its extracted checksum. A ``.pkg``'s
payloads are listed as the files they are (``Payload``, a gzip-compressed CPIO), not
opened. Handbook page: ``dev-docs/formats/xar.md``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import struct
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import NamedTuple
from xml.parsers import expat

from archivey.diagnostics import (
    DiagnosticCode,
    DigestContext,
    MemberTimestampContext,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    HashAlgorithm,
    MemberType,
    StreamFormat,
)

MAGIC = b"xar!"
_HEADER = struct.Struct(">4sHHQQI")

# The header's checksum algorithm: 3 means the name follows the fixed header.
_CKSUM_NONE = 0
_CKSUM_SHA1 = 1
_CKSUM_MD5 = 2
_CKSUM_OTHER = 3
_CKSUM_NAMES = {_CKSUM_SHA1: "sha1", _CKSUM_MD5: "md5"}

_DIGESTS = {
    "md5": HashAlgorithm.MD5,
    "sha1": HashAlgorithm.SHA1,
    "sha256": HashAlgorithm.SHA256,
    "sha512": HashAlgorithm.SHA512,
}
_DIGEST_SIZES = {"md5": 16, "sha1": 20, "sha256": 32, "sha512": 64}

# The encodings Apple's xar and libarchive write. ``application/x-gzip`` is a zlib
# stream, not gzip; ``application/x-lzma`` is LZMA Alone.
_ENCODINGS: dict[str, tuple[StreamFormat | None, CompressionAlgorithm]] = {
    "application/octet-stream": (None, CompressionAlgorithm.STORED),
    "application/x-gzip": (StreamFormat.ZLIB, CompressionAlgorithm.DEFLATE),
    "application/x-bzip2": (StreamFormat.BZIP2, CompressionAlgorithm.BZIP2),
    "application/x-lzma": (StreamFormat.LZMA_ALONE, CompressionAlgorithm.LZMA),
    "application/x-xz": (StreamFormat.XZ, CompressionAlgorithm.XZ),
}

_TYPES = {
    "file": MemberType.FILE,
    "directory": MemberType.DIRECTORY,
    "symlink": MemberType.SYMLINK,
    "hardlink": MemberType.HARDLINK,
    "fifo": MemberType.OTHER,
    "character special": MemberType.OTHER,
    "block special": MemberType.OTHER,
    "socket": MemberType.OTHER,
}

# Elements of a <file> whose text the reader keeps; others (extended attributes,
# Finder info, inode numbers) are skipped.
_FIELDS = frozenset(
    {"type", "link", "mode", "uid", "gid", "user", "group", "mtime", "atime", "ctime"}
)
_DATA_FIELDS = frozenset({"length", "offset", "size"})
# Element nesting deeper than this is refused, so the parser's stack stays small. Real
# file nesting is bounded by PATH_MAX (4096 bytes: 2048 one-letter names and slashes),
# which needs far fewer than 2048 elements. The cap does not bound what building the
# paths costs: each path is charged to ``max_metadata_bytes`` as it is built.
_MAX_DEPTH = 2048

# The most pieces one tag may hold before expat parses it. expat builds a tag's whole
# attribute dict before any handler runs, so the TOC byte cap does not bound it: a
# 13 MB TOC of one element with millions of attributes took 1.67 GB. A piece is one
# character outside quotes or one whole quoted value, so the count grows with the
# attributes and not with a long value, which costs only its own bytes. Honest tags
# have a handful of attributes and are a few hundred bytes long.
_MAX_TAG_PIECES = 65536
# A tag (or a comment or processing instruction, which honest TOCs keep short) of
# more than ``_MAX_TAG_PIECES`` pieces. ``<`` cannot appear in an attribute value,
# but ``>`` can, so quoted values are taken whole. Each piece starts with a different
# character, so a short tag fails at once, without backtracking.
_LONG_TAG = re.compile(rb"""<(?>[^<>"']|"[^"]*"|'[^']*'){%d}""" % _MAX_TAG_PIECES)


class _Data(NamedTuple):
    """A ``<data>`` element: where a file's bytes are and how to decode them."""

    offset: int
    """Where the stored bytes start, from the start of the heap."""
    length: int
    """How many bytes are stored."""
    size: int
    """How many bytes they decode to."""
    encoding: str
    """The ``<encoding style=…>`` MIME type: ``"application/octet-stream"`` (stored)
    when there is no ``<encoding>``, ``""`` when it has no ``style``. A key of
    ``_ENCODINGS`` when known."""
    digest: tuple[str, bytes] | None
    """The extracted checksum, as ``(algorithm, digest)``, or ``None`` when there is
    none or its style is not one of ``_DIGESTS`` (see ``unchecked_style``)."""
    unchecked_style: str | None
    """The style of an ``<extracted-checksum>`` archivey cannot compute, as written
    (``""`` when it names none); ``None`` when there is no such checksum."""


class _Entry(NamedTuple):
    id: str
    path: str
    raw_path: bytes
    kind: str
    link: str | None
    """The ``<type link=…>`` attribute of a hard link: ``"original"`` on the entry
    that holds the data, another entry's id on each link to it."""
    target: str | None
    """A symlink's target, from the ``<link>`` element."""
    fields: dict[str, str]
    data: _Data | None


class _Toc(NamedTuple):
    entries: list[_Entry]
    checksum: tuple[str, int, int] | None
    """The TOC checksum's style, heap offset and size."""


class _Frame:
    """One open ``<file>``: what its elements said so far."""

    __slots__ = (
        "data",
        "digest",
        "digest_style",
        "encoding",
        "fields",
        "has_data",
        "id",
        "index",
        "link",
        "name_xml",
        "path",
        "raw_path",
    )

    def __init__(self, id_: str, index: int) -> None:
        self.id = id_
        self.index = index
        self.fields: dict[str, str] = {}
        self.data: dict[str, str] = {}
        self.link: str | None = None
        self.encoding = "application/octet-stream"
        # None until an <extracted-checksum> is seen.
        self.digest_style: str | None = None
        self.digest = ""
        self.has_data = False
        self.path: str | None = None
        self.raw_path = b""
        # The first <name>, as stored (whether base64, and its text): a repeat of
        # it is accepted (``_set_path``).
        self.name_xml: tuple[bool, str] | None = None


class _TocParser:
    """Turns the TOC's XML into entries, one per ``<file>``, in document order."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._limit = context.config.listing_limits.max_members
        # One slot per <file>, filled when the element closes (see _open_file).
        self._entries: list[_Entry | None] = []
        self.checksum: tuple[str, int, int] | None = None
        # The names of the elements open now, outermost first.
        self._stack: list[str] = []
        # The <file> elements open now, outermost first.
        self._files: list[_Frame] = []
        # The text since the last element started or ended.
        self._text: list[str] = []
        # Whether the <name> being read has enctype="base64".
        self._name_base64 = False
        # The fields of <toc><checksum> while it is open.
        self._toc_checksum: dict[str, str] | None = None
        self._charged = 0
        self._budget = context.config.listing_limits.max_metadata_bytes

    def parse(self, xml: bytes) -> _Toc:
        if _LONG_TAG.search(xml) is not None:
            raise CorruptionError(
                "the XAR table of contents has a tag of more than "
                f"{_MAX_TAG_PIECES} characters and attributes"
            )
        parser = expat.ParserCreate()
        # Entities are declared only inside a document type declaration: refusing
        # that keeps every entity from being expanded.
        parser.StartDoctypeDeclHandler = self._refuse_doctype
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = self._text.append
        # Unbuffered, expat hands text over in pieces split at each newline, two
        # per "a\n" line, and a list slot per piece is 8 bytes per byte of text.
        # Buffered, a piece is up to expat's default buffer (8 KiB of UTF-8), and
        # ``_end`` joins the pieces either way.
        parser.buffer_text = True
        try:
            parser.Parse(xml, True)
        except expat.ExpatError as exc:
            raise CorruptionError(
                f"the XAR table of contents is not XML: {exc}"
            ) from None
        entries = [entry for entry in self._entries if entry is not None]
        return _Toc(entries, self.checksum)

    @staticmethod
    def _refuse_doctype(*_args: object) -> None:
        raise CorruptionError("the XAR table of contents declares a document type")

    def _start(self, name: str, attrs: dict[str, str]) -> None:
        """expat's start-element callback: the attributes the reader needs."""
        self._stack.append(name)
        self._text.clear()
        if len(self._stack) > _MAX_DEPTH:
            raise CorruptionError(
                f"the XAR table of contents nests more than {_MAX_DEPTH} elements"
            )
        parent = self._stack[-2] if len(self._stack) > 1 else None
        if name == "file" and parent in ("toc", "file"):
            self._open_file(attrs)
            return
        if not self._files:
            if name == "checksum" and parent == "toc":
                self._toc_checksum = {"style": attrs.get("style", "")}
            return
        frame = self._files[-1]
        if parent == "file" and name == "type":
            frame.link = attrs.get("link")
        elif parent == "file" and name == "name":
            self._name_base64 = attrs.get("enctype") == "base64"
        elif parent == "data" and name == "encoding":
            frame.encoding = attrs.get("style", "")
        elif parent == "data" and name == "extracted-checksum":
            frame.digest_style = attrs.get("style", "")

    def _open_file(self, attrs: dict[str, str]) -> None:
        if self._files and self._files[-1].path is None:
            # Every writer puts a directory's <name> before its children.
            raise CorruptionError("a XAR directory lists files before its name")
        if self._limit is not None and len(self._entries) >= self._limit:
            raise ResourceLimitError(
                f"the XAR table of contents lists more than max_members={self._limit} "
                "files"
            )
        # The slot keeps document order: a directory before the files inside it.
        self._files.append(_Frame(attrs.get("id", ""), len(self._entries)))
        self._entries.append(None)

    def _end(self, name: str) -> None:
        """expat's end-element callback: the element's text, and a finished file."""
        text = "".join(self._text)
        self._text.clear()
        self._stack.pop()
        parent = self._stack[-1] if self._stack else None
        if name == "file" and self._files and parent in ("toc", "file"):
            self._finish_file(self._files.pop())
            return
        if not self._files:
            if self._toc_checksum is not None and parent == "checksum":
                self._toc_checksum[name] = text
            elif name == "checksum" and self._toc_checksum is not None:
                self._set_toc_checksum(self._toc_checksum)
                self._toc_checksum = None
            return
        frame = self._files[-1]
        if parent == "file" and name == "name":
            self._set_path(frame, text)
        elif parent == "file" and name in _FIELDS:
            frame.fields[name] = text
        elif parent == "data" and name in _DATA_FIELDS:
            frame.data[name] = text
        elif parent == "data" and name == "extracted-checksum":
            frame.digest = text.strip()
        elif parent == "file" and name == "data":
            frame.has_data = True

    def _set_path(self, frame: _Frame, text: str) -> None:
        if frame.path is not None:
            # Apple's productbuild writes each top-level file's <name> twice, the
            # same both times (Node.js, GitHub CLI and Miniconda installers do this);
            # xar and pkgutil read it as one name. Two different names stay refused:
            # nothing says which one the file is.
            if (self._name_base64, text) == frame.name_xml:
                return
            raise CorruptionError(f"XAR file {quoted(frame.path)} has two names")
        frame.name_xml = (self._name_base64, text)
        if self._name_base64:
            try:
                raw = base64.b64decode(text, validate=True)
            except binascii.Error:
                raise CorruptionError("a XAR file name is not valid base64") from None
            name = self._context.decode_name(raw)
        else:
            raw = text.encode("utf-8", "surrogateescape")
            name = text
        if not name:
            raise CorruptionError("a XAR file has an empty name")
        enclosing = self._files[-2] if len(self._files) > 1 else None
        if enclosing is None or enclosing.path is None:
            path, raw_path = name, raw
        else:
            path = f"{enclosing.path}/{name}"
            raw_path = enclosing.raw_path + b"/" + raw
        self._charge(len(path) + len(raw_path), path)
        frame.path, frame.raw_path = path, raw_path

    def _charge(self, nbytes: int, path: str) -> None:
        """Charge each full path, its name and raw bytes together, to
        ``max_metadata_bytes`` as it is built: nested directories make the paths grow
        with the square of the depth, far past the size of the TOC, before any member
        is made."""
        self._charged += nbytes
        if self._budget is not None and self._charged > self._budget:
            raise ResourceLimitError(
                f"Listing limit reached: max_metadata_bytes={self._budget} (at least "
                f"{self._charged} bytes of paths before the members are made, at "
                f"{quoted(path[:200])})"
            )

    def _set_toc_checksum(self, fields: dict[str, str]) -> None:
        try:
            offset = int(fields.get("offset", ""))
            size = int(fields.get("size", ""))
        except ValueError:
            raise CorruptionError(
                "the XAR table of contents' checksum has no offset or size"
            ) from None
        if min(offset, size) < 0:
            raise CorruptionError(
                f"the XAR table of contents' checksum is at offset {offset}, size {size}"
            )
        self.checksum = (fields.get("style", ""), offset, size)

    def _finish_file(self, frame: _Frame) -> None:
        if frame.path is None:
            raise CorruptionError("a XAR file has no name")
        self._entries[frame.index] = _Entry(
            id=frame.id,
            path=frame.path,
            raw_path=frame.raw_path,
            kind=frame.fields.get("type", "file").strip(),
            link=frame.link,
            target=frame.fields.get("link"),
            fields=frame.fields,
            data=self._data(frame) if frame.has_data else None,
        )

    @staticmethod
    def _data(frame: _Frame) -> _Data:
        path = frame.path or ""
        try:
            offset = int(frame.data["offset"])
            length = int(frame.data["length"])
            size = int(frame.data["size"])
        except (KeyError, ValueError):
            raise CorruptionError(
                f"XAR file {quoted(path)} has data with no offset, length or size"
            ) from None
        if min(offset, length, size) < 0:
            raise CorruptionError(f"XAR file {quoted(path)} has a negative data field")
        digest = None
        unchecked = None
        style = (frame.digest_style or "").lower()
        if frame.digest_style is not None and style not in _DIGESTS:
            unchecked = frame.digest_style
        elif style in _DIGESTS:
            try:
                value = bytes.fromhex(frame.digest)
            except ValueError:
                value = b""
            if len(value) != _DIGEST_SIZES[style]:
                raise CorruptionError(
                    f"XAR file {quoted(path)} has a malformed {style} checksum"
                )
            digest = (style, value)
        return _Data(offset, length, size, frame.encoding, digest, unchecked)


def _timestamp(text: str) -> datetime | None:
    """An xar time (``2024-05-01T12:00:00Z``, fractions allowed) as aware UTC."""
    text = text.strip()
    if not text.endswith("Z"):
        return None
    text = text[:-1]
    for pattern in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


class _Location(NamedTuple):
    data: _Data | None
    """``None`` for a member with no data, which opens empty."""


class XarReader(IndexedReader[_Location]):
    """One open XAR archive."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        header = self._read(0, _HEADER.size, "the header")
        _magic, header_size, version, toc_stored, toc_size, algorithm = _HEADER.unpack(
            header
        )
        if version != 1:
            raise UnsupportedFeatureError(f"XAR version {version}: archivey reads 1")
        if header_size < _HEADER.size:
            raise CorruptionError(f"the XAR header says it is {header_size} bytes")
        self._algorithm = self._checksum_name(algorithm, header_size)
        limit = context.config.listing_limits.max_metadata_bytes
        if limit is not None and max(toc_size, toc_stored) > limit:
            # The stored size too: the TOC is read whole before it is decoded.
            raise ResourceLimitError(
                f"the XAR table of contents is {toc_stored} bytes stored and decodes "
                f"to {toc_size}, over max_metadata_bytes={limit}"
            )
        stored = self._read(header_size, toc_stored, "the table of contents")
        decoder = zlib.decompressobj()
        try:
            xml = decoder.decompress(stored, toc_size + 1)
        except zlib.error as exc:
            raise CorruptionError(
                f"the XAR table of contents does not decompress: {exc}"
            ) from None
        if len(xml) != toc_size or not decoder.eof:
            raise CorruptionError(
                f"the XAR table of contents decodes to {len(xml)} bytes, not the "
                f"{toc_size} its header says"
            )
        self._heap = header_size + toc_stored
        toc = _TocParser(context).parse(xml)
        self._check_toc(toc, stored)
        self._entries = toc.entries

    def _read(self, pos: int, length: int, what: str) -> bytes:
        try:
            return self._source.read_exact(pos, length)
        except TruncatedError:
            raise TruncatedError(
                f"the XAR archive ends inside {what} at offset {pos}"
            ) from None

    def _checksum_name(self, algorithm: int, header_size: int) -> str | None:
        """The TOC checksum algorithm the header names, as a ``hashlib`` name, or
        ``None`` when the TOC is not checked."""
        if algorithm == _CKSUM_NONE:
            return None
        if algorithm in _CKSUM_NAMES:
            return _CKSUM_NAMES[algorithm]
        if algorithm == _CKSUM_OTHER and header_size > _HEADER.size:
            raw = self._read(_HEADER.size, header_size - _HEADER.size, "the header")
            name = raw.split(b"\0", 1)[0].decode("ascii", "replace").lower()
            if name in _DIGESTS:
                return name
            raise UnsupportedFeatureError(
                f"the XAR table of contents is checked with {quoted(name)}, which archivey "
                "does not compute"
            )
        raise CorruptionError(f"XAR checksum algorithm {algorithm}")

    def _check_toc(self, toc: _Toc, stored: bytes) -> None:
        """Check the TOC against the checksum the heap holds for it."""
        if self._algorithm is None:
            return
        if toc.checksum is None:
            raise CorruptionError(
                "the XAR header names a checksum, and the table of contents has none"
            )
        style, offset, size = toc.checksum
        if style.lower() != self._algorithm:
            raise CorruptionError(
                f"the XAR header names {self._algorithm} and the table of contents "
                f"{quoted(style)}"
            )
        if size != _DIGEST_SIZES[self._algorithm]:
            raise CorruptionError(f"the XAR {style} checksum is {size} bytes")
        expected = self._read(self._heap + offset, size, "the TOC checksum")
        actual = hashlib.new(self._algorithm, stored, usedforsecurity=False).digest()
        if actual != expected:
            raise CorruptionError("the XAR table of contents fails its checksum")

    @override
    def iter_members(self) -> Iterator[MemberRecord[_Location]]:
        by_id: dict[str, ArchiveMember] = {}
        # A hard link names an earlier member, and bsdtar can write one before the
        # entry that holds the data: such a link waits for it.
        waiting: dict[str, list[_Entry]] = {}
        for entry in self._entries:
            if self._is_link(entry):
                if not entry.link:
                    raise CorruptionError(
                        f"XAR hard link {quoted(entry.path)} names no entry"
                    )
                original = by_id.get(entry.link)
                if original is None:
                    waiting.setdefault(entry.link, []).append(entry)
                    continue
                yield self._record(entry, original.name)
                continue
            record = self._record(entry, None)
            yield record
            if not entry.id:
                continue
            by_id.setdefault(entry.id, record.member)
            for later in waiting.pop(entry.id, ()):
                yield self._record(later, record.member.name)
        if waiting:
            ids = ", ".join(quoted(key) for key in sorted(waiting))
            raise CorruptionError(
                f"a XAR hard link names entry {ids}, which the table of contents does "
                "not hold"
            )

    @staticmethod
    def _is_link(entry: _Entry) -> bool:
        return entry.kind == "hardlink" and entry.link != "original"

    def _record(self, entry: _Entry, target: str | None) -> MemberRecord[_Location]:
        member = self._member(entry)
        if target is not None:
            member.link_target = target
        data = entry.data if member.is_file else None
        return MemberRecord(member, _Location(data))

    def _member(self, entry: _Entry) -> ArchiveMember:
        fields = entry.fields
        kind = _TYPES.get(entry.kind)
        if kind is MemberType.HARDLINK and entry.link == "original":
            kind = MemberType.FILE
        known = kind is not None
        if kind is None:
            # A type xar does not write: its data stays readable (DR-25).
            kind = MemberType.FILE if entry.data is not None else MemberType.OTHER
        member = ArchiveMember(
            type=kind,
            name=entry.path,
            raw_name=entry.raw_path,
        )
        if kind is MemberType.FILE:
            member.size = entry.data.size if entry.data is not None else 0
            if entry.data is not None:
                encoding = _ENCODINGS.get(entry.data.encoding)
                algo = encoding[1] if encoding else CompressionAlgorithm.UNKNOWN
                member.compression = (CompressionMethod(algo),)
                member.compressed_size = entry.data.length
                if entry.data.digest is not None:
                    style, value = entry.data.digest
                    member.hashes = {_DIGESTS[style]: value}
                if entry.data.unchecked_style is not None:
                    self._report_unchecked(member, entry.data.unchecked_style)
        elif kind is MemberType.SYMLINK:
            member.link_target = entry.target
        mode = fields.get("mode")
        if mode is not None:
            try:
                member.mode = int(mode, 8) & 0o7777
            except ValueError:
                pass
        for field in ("uid", "gid"):
            if field in fields:
                try:
                    setattr(member, field, int(fields[field]))
                except ValueError:
                    pass
        member.uname = fields.get("user")
        member.gname = fields.get("group")
        for stored, attr in (("mtime", "modified"), ("atime", "accessed")):
            if stored in fields:
                self._set_time(member, attr, stored, fields[stored])
        if "ctime" in fields:
            self._set_time(member, "ctime", "ctime", fields["ctime"])
        if not known:
            self._context.report(
                DiagnosticCode.MEMBER_TYPE_UNKNOWN,
                f"XAR file {quoted(member.name)} has type {quoted(entry.kind)}",
                UnknownMemberTypeContext(
                    member_name=member.name,
                    stored_type=entry.kind,
                    size=member.size,
                ),
                member=member,
            )
        return member

    def _report_unchecked(self, member: ArchiveMember, style: str) -> None:
        """A file checksum of a style archivey does not compute, or of none: the data
        reads unchecked, as ZIP and 7z report a member with nothing to check."""
        named = f"style {quoted(style)}" if style else "no style"
        self._context.report(
            DiagnosticCode.DIGEST_UNVERIFIABLE,
            f"XAR file {quoted(member.name)} has an extracted checksum of {named}, "
            "which archivey cannot compute; its data is read without that check",
            DigestContext(
                member_name=member.name,
                algorithm=style,
                reason="unknown_algorithm_or_backend",
            ),
            member=member,
        )

    def _set_time(
        self, member: ArchiveMember, attr: str, stored: str, text: str
    ) -> None:
        value = _timestamp(text)
        if value is not None:
            setattr(member, attr, value)
            return
        self._context.report(
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
            f"Invalid XAR {stored} for {quoted(member.name)}: {quoted(text)}",
            MemberTimestampContext(
                member_name=member.name,
                field=attr,
                source="xar",
                value_repr=text,
            ),
            member=member,
        )

    @override
    def open_member(self, member: ArchiveMember, locator: _Location) -> MemberData:
        data = locator.data
        if data is None:
            return MemberData(_empty(), bounded=True)
        encoding = _ENCODINGS.get(data.encoding)
        if encoding is None:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} is stored with encoding {quoted(data.encoding)}, "
                "which archivey does not read"
            )
        start = self._heap + data.offset
        end = start + data.length
        size = self._source.size
        if size is not None:
            cut = end > size
        else:
            # A source whose size is not known: is byte ``end - 1`` there? That is
            # ``end > size`` asked of the source, also for an empty member. Otherwise
            # the codec would meet the cut first and report it as damage.
            cut = end > 0 and not self._source.read_at(end - 1, 1)
        if cut:
            raise TruncatedError(
                f"the XAR archive ends inside the data of {quoted(member.name)}"
            )
        view = self._source.view(start, data.length)
        stream_format = encoding[0]
        if stream_format is None:
            if data.length != data.size:
                raise CorruptionError(
                    f"{quoted(member.name)} is stored as {data.length} bytes and "
                    f"says {data.size}"
                )
            return MemberData(view)
        # A member's data is exactly one stream: libarchive fails on anything after
        # its end, so a byte there (a second zlib stream, junk, zeros) is refused,
        # as in a ZIP member, not reported as trailing data.
        decompress_coder = self._context._decompress_coder
        assert decompress_coder is not None  # set by the adapter
        return MemberData(decompress_coder(view, stream_format, data.size))

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(format_version="1")


def _empty() -> io.BytesIO:
    return io.BytesIO(b"")


class XarHandler(IndexedFormatHandler):
    """XAR archives: ``.xar``, and macOS ``.pkg`` and ``.xip``."""

    format = ArchiveFormat.XAR
    extensions = (".xar", ".pkg", ".xip")
    magic = (Magic(0, MAGIC + b"\0"),)
    uses_encoding = True
    non_seekable_reason = "its files' data sit anywhere in the heap after the index"

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> XarReader:
        return XarReader(source, context)


XarReadBackend = register_builtin_format(XarHandler)
