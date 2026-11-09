"""The RPM reader: a package's file list from its header, and its files' data from
the CPIO payload, read in one forward pass.

On-disk layout (``rpm.org`` *V4 Package format* and *V6 Package format*)::

    [ lead, 96 bytes ][ signature header ][ pad to 8 ][ main header ][ payload ]

The **lead** starts with ``ED AB EE DB``; the rest is historical. Both headers have one
shape: the magic ``8E AD E8 01``, four reserved bytes, the number of index entries and
the size of the data store (big-endian), then the entries (tag, type, offset, count;
16 bytes each) and the store. The **payload** is a CPIO archive inside the compressor
the main header names (``PAYLOADCOMPRESSOR``), and runs to the end of the file.

The main header holds the file list: names (``DIRNAMES``/``BASENAMES``/``DIRINDEXES``,
or ``OLDFILENAMES`` in old packages), modes, sizes, times, owners, link targets and
digests. The payload holds one CPIO entry per file that is not a ``%ghost``, and the
reader maps each entry to its file the way ``rpm`` does (``lib/rpmfi.c``):

- a **newc** (``070701``) or **crc** (``070702``) entry by its name, ``./usr/bin/x``
  for the header's ``/usr/bin/x``;
- a **stripped** entry (``07070X``, then the file's index as 8 hexadecimal digits and
  nothing else) by that index. RPM 6 packages always use it, and RPM 4 packages that
  hold a file of 4 GiB or more (``LONGFILESIZES``).

Every member's metadata comes from the header, as ``rpm`` installs it; a newc entry's
own size is only checked against it. Members are named as the payload stores them,
``./usr/bin/x``, so ``usr/bin/x`` once normalized: what ``rpm2cpio | cpio -i``
extracts, relative to the directory it is given. A regular file's data follows its
entry, except in a hard-link set (regular files that share ``FILEDEVICES`` and
``FILEINODES``): there only the set's last file in header order carries the data, the
earlier entries coming first, empty. As for CPIO, this reader holds those back, yields
the last as the ``FILE`` and the others as ``HARDLINK`` members to it. A symlink's
target is its entry's data; the reader takes it from ``FILELINKTOS`` and skips those
bytes. A ``%ghost`` file is listed in the header but never stored, and ``rpm2cpio``
does not give it either: it is not a member. The payload ends with a newc
``TRAILER!!!`` entry, and every file that is not a ghost must have been found by then.

The signature header stores digests of the main header, from its magic to the end
of its data store: ``RPMSIGTAG_SHA256`` and the older ``RPMSIGTAG_SHA1``. The walk
checks every one of them the package stores as it reads the header, so damage to what
only the header holds (a link target, a mode, an owner) is ``CorruptionError`` before
any member is listed. The digests are not signed: they detect damage, not tampering. ``FILEDIGESTS`` holds each regular file's digest in the
algorithm ``FILEDIGESTALGO`` names (MD5 when absent): it is checked as the member is
read. Signatures are reported in the archive info, not checked.

The reader is written against ``archivey.formats`` and archivey's public names only,
as a format added from outside would be; ``register_builtin_format`` is the one
internal name it uses (``tests/test_rpm.py`` checks). Handbook page:
``dev-docs/formats/rpm.md``.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    Hasher,
    Magic,
    MemberDigest,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ArchiveMember,
    MemberType,
    StreamFormat,
)

LEAD_MAGIC = b"\xed\xab\xee\xdb"
LEAD_SIZE = 96
HEADER_MAGIC = b"\x8e\xad\xe8\x01"
# rpm's own bounds on a header (lib/header_internal.h): more is damage.
MAX_HEADER_TAGS = 0xFFFF
MAX_HEADER_DATA = 0x0FFFFFFF
# The longest CPIO name rpm reads (lib/cpio.c).
MAX_PAYLOAD_NAME = 4096
TRAILER = b"TRAILER!!!"
# How far past the trailer the check for trailing bytes reads: rpm reads nothing
# there, so this only bounds a report, and padding a writer adds is far shorter.
TRAILING_SCAN = 1024 * 1024

# Header data types (rpm.org "Package Header format").
_CHAR, _INT8, _INT16, _INT32, _INT64 = 1, 2, 3, 4, 5
_STRING, _BIN, _STRING_ARRAY, _I18NSTRING = 6, 7, 8, 9
_INT_SIZES = {_CHAR: 1, _INT8: 1, _INT16: 2, _INT32: 4, _INT64: 8, _BIN: 1}

# Tags (rpm.org "RPM Tags").
TAG_HEADERIMMUTABLE = 63
TAG_NAME = 1000
TAG_VERSION = 1001
TAG_RELEASE = 1002
TAG_EPOCH = 1003
TAG_ARCH = 1022
TAG_OLDFILENAMES = 1027
TAG_FILESIZES = 1028
TAG_FILEMODES = 1030
TAG_FILEMTIMES = 1034
TAG_FILEDIGESTS = 1035
TAG_FILELINKTOS = 1036
TAG_FILEFLAGS = 1037
TAG_FILEUSERNAME = 1039
TAG_FILEGROUPNAME = 1040
TAG_SOURCERPM = 1044
TAG_FILEDEVICES = 1095
TAG_FILEINODES = 1096
TAG_DIRINDEXES = 1116
TAG_BASENAMES = 1117
TAG_DIRNAMES = 1118
TAG_PAYLOADFORMAT = 1124
TAG_PAYLOADCOMPRESSOR = 1125
TAG_LONGFILESIZES = 5008
TAG_FILEDIGESTALGO = 5011
TAG_RPMFORMAT = 5114
# Signature-header tags that hold a signature (rather than a digest or a size), as
# rpm numbers them on disk (include/rpm/rpmtag.h, rpmSigTag_e): RPMSIGTAG_PGP (1002),
# RPMSIGTAG_GPG (1005) and the obsolete RPMSIGTAG_PGP5 (1006) over header and payload;
# RPMSIGTAG_DSA (267), RPMSIGTAG_RSA (268) and the OpenPGP tag (278) over the header.
# 259 and 262 are the names rpm gives 1002 and 1005 once read, never written.
_SIGNATURE_TAGS = frozenset({267, 268, 278, 1002, 1005, 1006})
# Signature-header tags that hold a digest of the main header, from its magic to the
# end of its data store, as lowercase hexadecimal: RPMSIGTAG_SHA256 (273) and
# RPMSIGTAG_SHA1 (269). Every one the package stores is checked.
_HEADER_DIGESTS: tuple[tuple[int, str, Callable[[], Hasher]], ...] = (
    (273, "SHA-256", hashlib.sha256),
    (269, "SHA-1", hashlib.sha1),
)

RPMFILE_GHOST = 1 << 6

# PAYLOADCOMPRESSOR values, as rpmio names its compressors.
_COMPRESSORS = {
    b"gzip": StreamFormat.GZIP,
    b"bzip2": StreamFormat.BZIP2,
    b"xz": StreamFormat.XZ,
    b"lzma": StreamFormat.LZMA_ALONE,
    b"zstd": StreamFormat.ZSTD,
}
# FILEDIGESTALGO values (the OpenPGP hash algorithm ids rpm uses).
_DIGESTS: dict[int, tuple[str, Callable[[], Hasher]]] = {
    1: ("md5", hashlib.md5),
    2: ("sha1", hashlib.sha1),
    8: ("sha256", hashlib.sha256),
    9: ("sha384", hashlib.sha384),
    10: ("sha512", hashlib.sha512),
    11: ("sha224", hashlib.sha224),
}

_S_IFMT = 0o170000
_S_IFREG = 0o100000
_S_IFDIR = 0o040000
_S_IFLNK = 0o120000
_SPECIAL = {
    0o020000: "char_device",
    0o060000: "block_device",
    0o010000: "fifo",
    0o140000: "socket",
}

_NEWC = b"070701"
_CRC = b"070702"
_STRIPPED = b"07070X"
_NEWC_FIELDS = 13

# What the held links are, in a limit error (ReaderContext.hold).
_HELD = "RPM hard links waiting for their data"


@dataclass
class _Entry:
    type: int
    count: int
    offset: int


class Header:
    """One parsed header: the index, and the data store its values are read from."""

    def __init__(self, entries: dict[int, _Entry], data: bytes, what: str) -> None:
        self._entries = entries
        self._data = data
        self._what = what

    def __contains__(self, tag: int) -> bool:
        return tag in self._entries

    def _bad(self, tag: int, why: str) -> CorruptionError:
        return CorruptionError(f"RPM {self._what}: tag {tag} {why}")

    def _int_entry(self, tag: int) -> tuple[_Entry, int, int] | None:
        """The tag's entry, its integer width and where its array ends, checked to be
        an integer array inside the data store; None when the tag is absent."""
        entry = self._entries.get(tag)
        if entry is None:
            return None
        size = _INT_SIZES.get(entry.type)
        if size is None or entry.type == _BIN:
            raise self._bad(tag, f"has type {entry.type}, not an integer")
        end = entry.offset + size * entry.count
        if end > len(self._data):
            raise self._bad(tag, "runs past the end of the header's data")
        return entry, size, end

    def ints(self, tag: int) -> list[int] | None:
        """An integer array, unsigned, or None when the tag is absent."""
        found = self._int_entry(tag)
        if found is None:
            return None
        entry, size, end = found
        if size == 1:
            return list(self._data[entry.offset : end])
        fmt = {2: "H", 4: "I", 8: "Q"}[size]
        return list(
            struct.unpack_from(f">{entry.count}{fmt}", self._data, entry.offset)
        )

    def number(self, tag: int) -> int | None:
        """The first value of an integer array, checked as :meth:`ints` checks it,
        without building the array: a tag read for one value may declare a count
        as large as the data store. None when the tag is absent or declares no
        values."""
        found = self._int_entry(tag)
        if found is None:
            return None
        entry, size, _end = found
        if entry.count == 0:
            return None  # as ``ints`` gives [] for a count of 0
        if size == 1:
            return self._data[entry.offset]
        fmt = {2: ">H", 4: ">I", 8: ">Q"}[size]
        return struct.unpack_from(fmt, self._data, entry.offset)[0]

    def strings(self, tag: int) -> list[bytes] | None:
        """A string array (a single string as a list of one), or None when absent."""
        entry = self._entries.get(tag)
        if entry is None:
            return None
        if entry.type not in (_STRING, _STRING_ARRAY, _I18NSTRING):
            raise self._bad(tag, f"has type {entry.type}, not a string")
        count = 1 if entry.type == _STRING else entry.count
        if count > len(self._data) - entry.offset:
            raise self._bad(tag, f"declares {count} strings in fewer bytes")
        values = []
        at = entry.offset
        for _ in range(count):
            end = self._data.find(b"\0", at)
            if end < 0:
                raise self._bad(tag, "has a string with no NUL before the data's end")
            values.append(self._data[at:end])
            at = end + 1
        return values

    def count(self, tag: int) -> int:
        """How many values the tag's entry declares, 0 when it is absent."""
        entry = self._entries.get(tag)
        return 0 if entry is None else entry.count

    def string(self, tag: int) -> bytes | None:
        """The first string of the tag's entry, checked as :meth:`strings` checks it,
        without building the list: a tag read for one value, such as ``NAME``, may
        declare a count as large as the data store. None when the tag is absent or
        declares no strings."""
        entry = self._entries.get(tag)
        if entry is None:
            return None
        if entry.type not in (_STRING, _STRING_ARRAY, _I18NSTRING):
            raise self._bad(tag, f"has type {entry.type}, not a string")
        count = 1 if entry.type == _STRING else entry.count
        if count > len(self._data) - entry.offset:
            raise self._bad(tag, f"declares {count} strings in fewer bytes")
        if count == 0:
            return None  # as ``strings`` gives [] for a count of 0
        first_end = self._data.find(b"\0", entry.offset)
        # Each of the declared strings ends at a NUL, as ``strings`` requires. A
        # single string needs only the first; an array is counted to the end.
        if first_end < 0 or (
            count > 1 and self._data.count(b"\0", entry.offset) < count
        ):
            raise self._bad(tag, "has a string with no NUL before the data's end")
        return self._data[entry.offset : first_end]


def _read_header(
    stream: ForwardStream,
    what: str,
    context: ReaderContext,
    hashers: tuple[Hasher, ...] = (),
) -> tuple[Header, int]:
    """A header at the stream's position, and how many bytes it took. The walk keeps
    it, so its index and data store are charged to ``max_metadata_bytes`` before
    they are read. Each of ``hashers`` is fed every byte of the header."""
    offset = stream.offset
    intro = stream.read_exact(16)
    if intro[:4] != HEADER_MAGIC:
        raise CorruptionError(f"No RPM {what} at offset {offset}")
    count, size = struct.unpack(">II", intro[8:])
    if count > MAX_HEADER_TAGS or size > MAX_HEADER_DATA:
        raise CorruptionError(
            f"RPM {what} at offset {offset} declares {count} tags and {size} bytes "
            "of data, over rpm's own bounds"
        )
    total = 16 * count + size
    context.charge_metadata(total, what=f"the RPM {what}")
    index = stream.read_exact(16 * count)
    data = stream.read_exact(size)
    for hasher in hashers:
        for part in (intro, index, data):
            hasher.update(part)
    entries: dict[int, _Entry] = {}
    for tag, kind, at, n in struct.iter_unpack(">IIiI", index):
        if tag in entries:
            raise CorruptionError(f"RPM {what}: tag {tag} appears twice")
        if at < 0 or at > size or n == 0:
            raise CorruptionError(
                f"RPM {what}: tag {tag} has offset {at} and count {n} in a store "
                f"of {size} bytes"
            )
        entries[tag] = _Entry(kind, n, at)
    return Header(entries, data, what), 16 + total


@dataclass(slots=True)
class _File:
    """One file of the header's list.

    The name stays split as the header stores it, directory and base, and the member
    is made only when the payload reaches the file: ``DIRINDEXES`` lets many files
    share one long directory, so joining every name up front would cost far more
    than the header (rpm joins them lazily too, ``rpmfilesFN``).
    """

    index: int
    directory: bytes
    base: bytes
    mode: int
    size: int
    flags: int
    links: tuple[int, ...] = ()
    member: ArchiveMember | None = None
    found: bool = False

    @property
    def raw_name(self) -> bytes:
        return self.directory + self.base


@dataclass
class _Package:
    """What the walk learns from the lead and the headers."""

    files: list[_File]
    # (directory, base) -> file index: the bytes objects the header's lists hold.
    by_name: dict[tuple[bytes, bytes], int]
    compressor: StreamFormat | None
    # FILEDIGESTALGO's name and hash constructor; None for an algorithm not in _DIGESTS.
    digest_algorithm: tuple[str, Callable[[], Hasher]] | None
    # The header's per-file columns, indexed like ``files``; None for an absent tag.
    digests: list[bytes] | None
    mtimes: list[int] | None
    users: list[bytes] | None
    groups: list[bytes] | None
    targets: list[bytes] | None
    # Earlier links of a hard-link set, waiting for the set's last file (by its index),
    # which carries the data.
    held: dict[int, list[_File]] = field(default_factory=dict)
    # The payload offset of the first CPIO entry: CPIO pads to 4 bytes from there.
    base: int = 0


class RpmReader(SequentialReader):
    """Walks an RPM package: its headers, then its CPIO payload."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._extra = ArchiveInfoExtra({})
        self._version: str | None = None
        # Until the walk reads the header, which the open's first step does: solid,
        # the answer for a compressed payload.
        self._solid = True

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        # A compressed payload is solid; rpm's ufdio (none) is read as a CPIO is.
        return ReaderArchiveInfo(
            is_solid=self._solid, format_version=self._version, extra=self._extra
        )

    # The walk ---------------------------------------------------------------------

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        package = self._read_package(stream)
        self._solid = package.compressor is not None
        payload = stream
        if package.compressor is not None:
            payload = stream.decompress(package.compressor)
        # CPIO pads to 4 bytes from the payload's start, which an uncompressed payload
        # does not share with the file's.
        package.base = payload.offset
        files = package.files
        while True:
            file, size = self._next_entry(payload, package)
            if file is None:
                break
            if file.flags & RPMFILE_GHOST:
                # rpm < 4.11 sometimes stored one; rpm skips it, and so does the walk.
                payload.skip(size)
                continue
            if file.found:
                raise CorruptionError(
                    f"RPM payload stores {_shown(file.raw_name)} twice"
                )
            file.found = True
            yield from self._entry(payload, package, file)
        missing = [f for f in files if not f.found and not f.flags & RPMFILE_GHOST]
        if missing:
            raise CorruptionError(
                f"RPM payload ends without {len(missing)} of the header's files, "
                f"the first {_shown(missing[0].raw_name)}"
            )
        self._check_end(payload)

    def _read_package(self, stream: ForwardStream) -> _Package:
        """Read the lead and both headers, leaving the stream at the payload."""
        lead = stream.read_exact(LEAD_SIZE)
        if lead[:4] != LEAD_MAGIC:
            raise CorruptionError("No RPM lead at offset 0")
        major = lead[4]
        if major not in (3, 4):
            raise UnsupportedFeatureError(f"RPM lead version {major}")
        signature, used = _read_header(stream, "signature header", self._context)
        stream.skip(-used % 8)
        checks = _header_digests(signature)
        header, _ = _read_header(
            stream, "header", self._context, tuple(h for _, _, h in checks)
        )
        for name, expected, hasher in checks:
            if hasher.digest() != expected:
                raise CorruptionError(
                    f"RPM header does not match the {name} digest in the signature "
                    "header"
                )
        payload_format = header.string(TAG_PAYLOADFORMAT)
        if payload_format not in (None, b"cpio"):
            raise UnsupportedFeatureError(
                f"RPM payload format {payload_format.decode('ascii', 'replace')!r}"
                + (" (a delta RPM)" if payload_format == b"drpm" else "")
            )
        compressor_name = header.string(TAG_PAYLOADCOMPRESSOR)
        compressor = None
        if compressor_name is not None:
            compressor = _COMPRESSORS.get(compressor_name)
            if compressor is None and compressor_name not in (b"identity", b"ufdio"):
                raise UnsupportedFeatureError(
                    f"RPM payload compressor {_shown(compressor_name)} is not supported"
                )
        self._describe(signature, header, compressor_name)
        files, columns = self._files(header)
        algorithm = header.number(TAG_FILEDIGESTALGO)
        digest = _DIGESTS.get(1 if algorithm is None else algorithm)
        digests = self._strings_column(header, TAG_FILEDIGESTS, len(files))
        by_name = {(file.directory, file.base): file.index for file in files}
        return _Package(files, by_name, compressor, digest, digests, *columns)

    def _describe(
        self,
        signature: Header,
        header: Header,
        compressor: bytes | None,
    ) -> None:
        """Fill the archive info: the package's identity, whether it is signed, and the
        package format version."""
        extra = ArchiveInfoExtra({})

        def text(tag: int) -> str | None:
            value = header.string(tag)
            return None if value is None else value.decode("utf-8", "replace")

        if (name := text(TAG_NAME)) is not None:
            extra["rpm.name"] = name
        if (version := text(TAG_VERSION)) is not None:
            extra["rpm.version"] = version
        if (release := text(TAG_RELEASE)) is not None:
            extra["rpm.release"] = release
        if (arch := text(TAG_ARCH)) is not None:
            extra["rpm.arch"] = arch
        epoch = header.number(TAG_EPOCH)
        if epoch is not None:
            extra["rpm.epoch"] = epoch
        # A source package has no SOURCERPM; the lead's type field says so too.
        extra["rpm.source"] = TAG_SOURCERPM not in header
        extra["rpm.signed"] = any(tag in signature for tag in _SIGNATURE_TAGS)
        extra["rpm.payload_compressor"] = (
            "none" if compressor is None else compressor.decode("ascii", "replace")
        )
        self._extra = extra
        # rpm's own detection (RPMTAG_RPMFORMAT): the tag when a v6 package stores
        # it, else 4 for a header with an immutable region, else 3. The lead's
        # version field is 3 in v4 packages and 4 in v6 ones, so it says nothing.
        version = header.number(TAG_RPMFORMAT)
        if version is None:
            version = 4 if TAG_HEADERIMMUTABLE in header else 3
        self._version = str(version)

    def _files(
        self, header: Header
    ) -> tuple[
        list[_File],
        tuple[
            list[int] | None, list[bytes] | None, list[bytes] | None, list[bytes] | None
        ],
    ]:
        """The header's file list, checked, and the columns members are made from."""
        names_tag = TAG_BASENAMES if TAG_BASENAMES in header else TAG_OLDFILENAMES
        count = header.count(names_tag)
        # Before any per-file list is built: each file costs far more in memory than
        # the few header bytes it can take.
        max_members = self._context.config.listing_limits.max_members
        if max_members is not None:
            for tag, what in ((names_tag, "files"), (TAG_DIRNAMES, "directories")):
                if header.count(tag) > max_members:
                    raise ResourceLimitError(
                        f"Listing limit reached: max_members={max_members} "
                        f"(the RPM header lists {header.count(tag)} {what})"
                    )
        basenames = header.strings(TAG_BASENAMES)
        if basenames is not None:
            dirnames = header.strings(TAG_DIRNAMES) or []
            declared = header.count(TAG_DIRINDEXES) if TAG_DIRINDEXES in header else 0
            if declared != len(basenames):
                raise CorruptionError(
                    f"RPM header lists {len(basenames)} base names and "
                    f"{declared} directory indexes"
                )
            indexes = header.ints(TAG_DIRINDEXES) or []
            split = []
            for base, at in zip(basenames, indexes, strict=True):
                if at >= len(dirnames):
                    raise CorruptionError(
                        f"RPM header: directory index {at} of {_shown(base)} is past "
                        f"the {len(dirnames)} directory names"
                    )
                split.append((dirnames[at], base))
        else:
            split = [_split(name) for name in header.strings(TAG_OLDFILENAMES) or []]

        def column(tag: int, required: bool = False) -> list[int] | None:
            if tag not in header:
                if required and count:
                    raise CorruptionError(f"RPM header lists files with no tag {tag}")
                return None
            # Compared before the values are unpacked: no list longer than the files.
            if header.count(tag) != count:
                raise CorruptionError(
                    f"RPM header lists {count} files and {header.count(tag)} values "
                    f"of tag {tag}"
                )
            return header.ints(tag)

        modes = column(TAG_FILEMODES, required=True) or []
        sizes = column(TAG_LONGFILESIZES) if TAG_LONGFILESIZES in header else None
        if sizes is None:
            sizes = column(TAG_FILESIZES, required=True) or []
        flags = column(TAG_FILEFLAGS) or [0] * count
        mtimes = column(TAG_FILEMTIMES)
        inodes = column(TAG_FILEINODES)
        devices = column(TAG_FILEDEVICES)
        targets = self._strings_column(header, TAG_FILELINKTOS, count)
        users = self._strings_column(header, TAG_FILEUSERNAME, count)
        groups = self._strings_column(header, TAG_FILEGROUPNAME, count)

        files = [
            _File(i, split[i][0], split[i][1], modes[i], sizes[i], flags[i])
            for i in range(count)
        ]
        for file in files:
            if file.flags & RPMFILE_GHOST:
                continue
            kind = file.mode & _S_IFMT
            if kind == _S_IFLNK and (targets is None or not targets[file.index]):
                raise CorruptionError(
                    f"RPM header: symlink {_shown(file.raw_name)} has no target"
                )
        # Hard-link sets, as rpm builds them (rpmfilesBuildNLink): regular files that
        # are not ghosts and share a device and a positive inode number.
        if inodes is not None and devices is not None:
            sets: dict[tuple[int, int], list[int]] = {}
            for file in files:
                if (
                    file.mode & _S_IFMT == _S_IFREG
                    and not file.flags & RPMFILE_GHOST
                    and inodes[file.index] > 0
                ):
                    key = (devices[file.index], inodes[file.index])
                    sets.setdefault(key, []).append(file.index)
            for members in sets.values():
                if len(members) > 1:
                    # One tuple per set, shared by its files: a tuple per file would
                    # take memory with the square of the set's size, and a header
                    # can give every file one inode.
                    links = tuple(members)
                    for i in members:
                        files[i].links = links
        return files, (mtimes, users, groups, targets)

    def _member(self, package: _Package, file: _File) -> ArchiveMember:
        """The member for a file the payload has reached."""
        context = self._context
        kind = file.mode & _S_IFMT
        special = _SPECIAL.get(kind)
        if kind == _S_IFREG:
            member_type = MemberType.FILE
        elif kind == _S_IFDIR:
            member_type = MemberType.DIRECTORY
        elif kind == _S_IFLNK:
            member_type = MemberType.SYMLINK
        else:
            # A device, FIFO, socket or a type rpm does not name: no payload data,
            # since rpm reads none for it (iterReadArchiveNext), so OTHER (DR-25).
            member_type = MemberType.OTHER
        raw_name = file.raw_name
        # The header's names are absolute; the payload stores ``./usr/bin/x``,
        # which is what rpm2cpio and cpio extract, inside the directory given.
        users, groups, mtimes = package.users, package.groups, package.mtimes
        member = ArchiveMember(
            type=member_type,
            name=context.decode_name(
                b"." + raw_name if raw_name.startswith(b"/") else raw_name
            ),
            raw_name=raw_name,
            size=file.size if member_type is MemberType.FILE else None,
            modified=None if mtimes is None else _time(mtimes[file.index]),
            mode=file.mode & 0o7777,
            uname=None
            if users is None
            else users[file.index].decode("utf-8", "replace"),
            gname=None
            if groups is None
            else groups[file.index].decode("utf-8", "replace"),
        )
        if member_type is MemberType.SYMLINK:
            assert package.targets is not None  # _files checked it
            member.link_target = context.decode_name(package.targets[file.index])
        if special is not None:
            member.extra["special_file_type"] = special
        elif member_type is MemberType.OTHER:
            context.report(
                DiagnosticCode.MEMBER_TYPE_UNKNOWN,
                f"RPM member {_shown(raw_name)} has the unknown file type {kind:#o}",
                UnknownMemberTypeContext(
                    member_name=member.name, stored_type=f"{kind:#o}", size=None
                ),
                member=member,
            )
        file.member = member
        return member

    @staticmethod
    def _strings_column(header: Header, tag: int, count: int) -> list[bytes] | None:
        if tag in header and header.count(tag) != count:
            raise CorruptionError(
                f"RPM header lists {count} files and {header.count(tag)} values of "
                f"tag {tag}"
            )
        return header.strings(tag)

    # The payload ------------------------------------------------------------------

    def _next_entry(
        self, payload: ForwardStream, package: _Package
    ) -> tuple[_File | None, int]:
        """The file the next payload entry stores, and the size its entry gives (the
        header's for a stripped entry); ``(None, 0)`` at the trailer."""
        payload.skip(-(payload.offset - package.base) % 4)
        offset = payload.offset
        magic = payload.read_exact(6)
        if magic == _STRIPPED:
            raw = payload.read_exact(8)
            index = _hex(raw, "file index", offset)
            payload.skip(-(payload.offset - package.base) % 4)
            # rpm's own end mark for a stripped payload (lib/cpio.c,
            # rpmcpioHeaderRead: an index of -1 is RPMERR_ITER_END). rpm 4.18 and 6.0
            # write the newc trailer after a stripped payload too, and read either.
            if index == 0xFFFFFFFF:
                return None, 0
            if index >= len(package.files):
                raise CorruptionError(
                    f"RPM payload entry at offset {offset} names file {index} of "
                    f"{len(package.files)}"
                )
            file = package.files[index]
            return file, self._expected_size(file)
        if magic not in (_NEWC, _CRC):
            raise CorruptionError(f"No RPM payload entry at offset {offset}")
        raw = payload.read_exact(8 * _NEWC_FIELDS)
        size = _hex(raw[48:56], "filesize", offset)
        name_size = _hex(raw[88:96], "namesize", offset)
        if not 0 < name_size <= MAX_PAYLOAD_NAME:
            raise CorruptionError(
                f"RPM payload entry at offset {offset}: a name of {name_size} bytes"
            )
        name = payload.read_exact(name_size)
        if name[-1:] != b"\0":
            raise CorruptionError(
                f"RPM payload entry at offset {offset}: the name is not NUL-terminated"
            )
        name = name[:-1]
        payload.skip(-(payload.offset - package.base) % 4)
        if name == TRAILER:
            return None, 0
        # rpm writes "./usr/bin/x" for "/usr/bin/x" (or "usr/bin/x" with
        # %_noPayloadPrefix); rpmfilesFindOFN looks the header name up.
        # A source package's names are relative, and stored as they are.
        rest = name.removeprefix(b"./")
        index = package.by_name.get(_split(b"/" + rest))
        if index is None:
            index = package.by_name.get(_split(rest))
        if index is None:
            raise CorruptionError(
                f"RPM payload entry at offset {offset} stores {_shown(name)}, which the "
                "header does not list"
            )
        file = package.files[index]
        if file.flags & RPMFILE_GHOST:
            return file, size
        expected = self._expected_size(file)
        if size != expected:
            raise CorruptionError(
                f"RPM payload entry at offset {offset} gives {_shown(name)} {size} bytes; "
                f"the header gives {expected}"
            )
        return file, size

    @staticmethod
    def _expected_size(file: _File) -> int:
        """The bytes of payload data that follow a file's entry, as rpm reads them."""
        kind = file.mode & _S_IFMT
        if kind == _S_IFLNK:
            return file.size
        if kind == _S_IFREG and (not file.links or file.links[-1] == file.index):
            return file.size
        return 0

    def _entry(
        self, payload: ForwardStream, package: _Package, file: _File
    ) -> Iterator[MemberSpan]:
        """The members one payload entry gives: its own, unless it is an earlier link
        of a hard-link set, which is held until the set's last file comes, or yielded
        at once as a link to that file if it already came; then the held links of the
        set it ends."""
        member = self._member(package, file)
        if member.type is MemberType.SYMLINK:
            # The target, which the header already gave.
            yield MemberSpan(member, 0)
            payload.skip(file.size)
            return
        if member.type is not MemberType.FILE:
            yield MemberSpan(member, 0)
            return
        if file.links and file.links[-1] != file.index:
            # An earlier link of a set: empty, its data comes with the set's last.
            data = package.files[file.links[-1]]
            if data.member is not None:
                # The payload stored the set's last file first, which rpm installs
                # all the same: a link to it, now.
                yield self._link(member, data.member)
                return
            self._context.hold(member, reason=_HELD)
            package.held.setdefault(file.links[-1], []).append(file)
            return
        yield MemberSpan(member, file.size, self._digests(package, file))
        for link in package.held.pop(file.index, []):
            assert link.member is not None
            yield self._link(link.member, member)

    @staticmethod
    def _link(member: ArchiveMember, data: ArchiveMember) -> MemberSpan:
        """Turn ``member`` into a hard link to ``data``, the member with the bytes."""
        member.type = MemberType.HARDLINK
        member.link_target = data.name
        member.size = None
        return MemberSpan(member, 0)

    @staticmethod
    def _digests(package: _Package, file: _File) -> tuple[MemberDigest, ...]:
        if package.digests is None or package.digest_algorithm is None:
            return ()
        text = package.digests[file.index]
        if not text:
            return ()
        try:
            expected = bytes.fromhex(text.decode("ascii"))
        except ValueError:
            raise CorruptionError(
                f"RPM header: the digest of {_shown(file.raw_name)} is not hexadecimal"
            ) from None
        name, new = package.digest_algorithm
        return (MemberDigest(name, expected, new),)

    def _check_end(self, payload: ForwardStream) -> None:
        """After the trailer: zero padding only. rpm writes none, and reads no
        further."""
        scanned = 0
        while scanned < TRAILING_SCAN:
            chunk = payload.read(min(64 * 1024, TRAILING_SCAN - scanned))
            if not chunk:
                return
            stripped = chunk.lstrip(b"\0")
            if stripped:
                at = scanned + len(chunk) - len(stripped)
                self._context.report(
                    DiagnosticCode.ARCHIVE_TRAILING_DATA,
                    f"RPM payload has data {at} bytes after its trailer",
                    ArchiveEofContext(
                        format="rpm",
                        expected_marker="zeros_to_eof",
                        observed_bytes=at,
                        observed_kind="nonzero",
                    ),
                )
                return
            scanned += len(chunk)


def _header_digests(signature: Header) -> list[tuple[str, bytes, Hasher]]:
    """Each digest of the main header the signature header stores: the algorithm's
    name, the digest and a hasher to compare it with. Empty when the package stores
    none: old packages, and packages a tool rewrote, can lack them, and that is not
    damage."""
    checks = []
    for tag, name, new in _HEADER_DIGESTS:
        text = signature.string(tag)
        if text is None:
            continue
        try:
            expected = bytes.fromhex(text.decode("ascii"))
        except ValueError:
            raise CorruptionError(
                f"RPM signature header: the header's {name} digest is not hexadecimal"
            ) from None
        checks.append((name, expected, new()))
    return checks


def _split(name: bytes) -> tuple[bytes, bytes]:
    """A path as the header stores it: the directory, with its slash, and the base."""
    cut = name.rfind(b"/") + 1
    return name[:cut], name[cut:]


def _shown(raw: bytes) -> str:
    """A name from the package, quoted for a message that escapes itself.

    No ``!r``: the exception escapes control characters already, and ``repr`` would
    have them escaped twice (``archivey.terminal.quoted``, for bytes).
    """
    return "'" + raw.decode("utf-8", "backslashreplace") + "'"


def _hex(raw: bytes, what: str, offset: int) -> int:
    try:
        text = raw.decode("ascii")
        # int() would also take spaces, a sign and underscores.
        if not text.isalnum():
            raise ValueError(text)
        return int(text, 16)
    except ValueError:
        raise CorruptionError(
            f"RPM payload entry at offset {offset}: the {what} field {raw!r} is not "
            "a number"
        ) from None


def _time(mtime: int) -> datetime | None:
    try:
        return datetime.fromtimestamp(mtime, UTC)
    except (OverflowError, ValueError, OSError):
        return None


class RpmHandler(SequentialFormatHandler):
    """RPM packages, binary and source: ``.rpm``."""

    format = ArchiveFormat.RPM
    extensions = (".rpm",)
    magic = (Magic(0, LEAD_MAGIC),)
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> RpmReader:
        return RpmReader(context)


RpmReadBackend = register_builtin_format(RpmHandler)
