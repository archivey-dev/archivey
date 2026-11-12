"""The RPM reader: a package's file list from its header, and each file's data from
the CPIO payload when that data is read.

On-disk layout (``rpm.org`` *V4 Package format* and *V6 Package format*)::

    [ lead, 96 bytes ][ signature header ][ pad to 8 ][ main header ][ payload ]

The **lead** starts with ``ED AB EE DB``; the rest is historical. Both headers have one
shape: the magic ``8E AD E8 01``, four reserved bytes, the number of index entries and
the size of the data store (big-endian), then the entries (tag, type, offset, count;
16 bytes each) and the store. The **payload** is a CPIO archive inside the compressor
the main header names (``PAYLOADCOMPRESSOR``), and runs to the end of the file.

The main header holds the file list: names (``DIRNAMES``/``BASENAMES``/``DIRINDEXES``,
or ``OLDFILENAMES`` in old packages), modes, sizes, times, owners, link targets and
digests. The walk lists every member from it and reads no payload byte: the reader
sets ``data_on_demand``, and each file's data stream finds the file's payload entry
when it is first read (:class:`_Payload`). Every member's metadata comes from the
header, as ``rpm`` installs it. Members are named as the payload stores them,
``./usr/bin/x``, so ``usr/bin/x`` once normalized: what ``rpm2cpio | cpio -i``
extracts, relative to the directory it is given. They come in the order rpm writes the
payload (:func:`_write_order`), so a pass reads it forward once.

The payload holds one CPIO entry per file that is not a ``%ghost``, mapped to its file
the way ``rpm`` does (``lib/rpmfi.c``):

- a **newc** (``070701``) or **crc** (``070702``) entry by its name, ``./usr/bin/x``
  for the header's ``/usr/bin/x``;
- a **stripped** entry (``07070X``, then the file's index as 8 hexadecimal digits and
  nothing else) by that index. RPM 6 packages always use it, and RPM 4 packages that
  hold a file of 4 GiB or more (``LONGFILESIZES``).

A regular file's data follows its entry, except in a hard-link set (regular files that
share ``FILEDEVICES`` and ``FILEINODES``): there only the set's last file in header
order carries the data. The walk yields that file as the ``FILE`` and the others after
it as ``HARDLINK`` members to it. A symlink's target is its entry's data; the reader
takes it from ``FILELINKTOS``. A ``%ghost`` file is listed in the header but never
stored, and ``rpm2cpio`` does not give it either: it is not a member.

The signature header stores digests of the main header, from its magic to the end
of its data store: ``RPMSIGTAG_SHA256`` and the older ``RPMSIGTAG_SHA1``. The walk
checks every one of them the package stores as it reads the header, so damage to what
only the header holds (a link target, a mode, an owner) is ``CorruptionError`` before
any member is listed. The digests are not signed: they detect damage, not tampering.
``FILEDIGESTS`` holds each regular file's digest in the algorithm ``FILEDIGESTALGO``
names (MD5 when absent): it is checked as the member is read. Signatures are reported in
the archive info, not checked.

The reader is written against ``archivey.formats`` and archivey's public names only,
as a format added from outside would be; ``register_builtin_format`` is the one
internal name it uses (``tests/test_rpm.py`` checks). Handbook page:
``dev-docs/formats/rpm.md``.
"""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from archivey.diagnostics import (
    DiagnosticCode,
    HeaderAmbiguityContext,
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
    unix_member_type,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.terminal import quoted
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

    def _string_entry(self, tag: int) -> _Entry | None:
        """The tag's entry, checked to be a string or a string array; None when the
        tag is absent. A single STRING must declare one value, as _read_header and
        rpm's headerVerifyInfo require."""
        entry = self._entries.get(tag)
        if entry is None:
            return None
        if entry.type not in (_STRING, _STRING_ARRAY, _I18NSTRING):
            raise self._bad(tag, f"has type {entry.type}, not a string")
        if entry.type == _STRING and entry.count != 1:
            raise self._bad(tag, f"is a single string with count {entry.count}")
        return entry

    def strings(self, tag: int) -> list[bytes] | None:
        """A string array (a single string as a list of one), or None when absent."""
        entry = self._string_entry(tag)
        if entry is None:
            return None
        count = entry.count
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
        entry = self._string_entry(tag)
        if entry is None:
            return None
        count = entry.count
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
        if kind == _STRING and n != 1:
            # rpm's headerVerifyInfo refuses this too: a STRING holds one value.
            raise CorruptionError(
                f"RPM {what}: tag {tag} is a single string with count {n}"
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
    # Its place in the order rpm writes the payload in (``_write_order``).
    rank: int = 0

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
    # The payload offset of the first CPIO entry: CPIO pads to 4 bytes from there.
    base: int = 0
    # The files that are not ghosts, by index, in the order rpm writes their entries.
    order: list[int] = field(default_factory=list)


class RpmReader(SequentialReader):
    """Walks an RPM package: lists its files from the header, and reads each file's
    data from the CPIO payload when that data is read."""

    data_on_demand = True

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._extra = ArchiveInfoExtra({})
        self._version: str | None = None
        # Until the walk reads the header, which the open's first step does: solid,
        # the answer for a compressed payload.
        self._solid = True
        # Symlinks whose payload target was reported as differing, by file index:
        # once per reader, though each walk started over passes the entry again.
        self._reported_targets: set[int] = set()

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
            # Nothing is decoded until a member's data is read.
            payload = stream.decompress(package.compressor)
        # CPIO pads to 4 bytes from the payload's start, which an uncompressed payload
        # does not share with the file's.
        package.base = payload.offset
        cursor = _Payload(self, payload, package)
        # Every member from the header, before any payload byte is read, in the order
        # rpm writes the payload in, so a pass reads it forward. An earlier link of a
        # hard-link set waits for the set's last file, which carries the data: a link
        # names an earlier member.
        held: dict[int, list[ArchiveMember]] = {}
        files = package.files
        for index in package.order:
            file = files[index]
            member = self._member(package, file)
            if member.type is not MemberType.FILE:
                yield MemberSpan(member)
                continue
            if file.links and file.links[-1] != file.index:
                self._context.hold(member, reason=_HELD)
                held.setdefault(file.links[-1], []).append(member)
                continue
            yield MemberSpan(
                member,
                digests=self._digests(package, file),
                data=_PayloadData(cursor, file),
            )
            for link in held.pop(file.index, []):
                yield self._link(link, member)

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
        package = _Package(files, by_name, compressor, digest, digests, *columns)
        package.order = _write_order(files)
        return package

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
        # A device, FIFO, socket or a type rpm does not name has no payload data,
        # since rpm reads none for it (iterReadArchiveNext), so it is OTHER (DR-25).
        member_type, special = unix_member_type(file.mode, has_data=False)
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
            mode=file.mode & 0o7777,
            uname=None
            if users is None
            else users[file.index].decode("utf-8", "replace"),
            gname=None
            if groups is None
            else groups[file.index].decode("utf-8", "replace"),
        )
        if mtimes is not None:
            context.set_unix_time(member, "modified", mtimes[file.index], source="rpm")
        if member_type is MemberType.SYMLINK:
            assert package.targets is not None  # _files checked it
            member.link_target = context.decode_name(package.targets[file.index])
        if special is not None:
            member.extra["special_file_type"] = special
        if special == "unknown":
            kind = file.mode & _S_IFMT
            context.report(
                DiagnosticCode.MEMBER_TYPE_UNKNOWN,
                f"RPM member {_shown(raw_name)} has the unknown file type {kind:#o}",
                UnknownMemberTypeContext(
                    member_name=member.name, stored_type=f"{kind:#o}", size=None
                ),
                member=member,
            )
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
        header's for a stripped entry), which the caller checks against the header's;
        ``(None, 0)`` at the trailer."""
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
        return package.files[index], size

    @staticmethod
    def _expected_size(file: _File) -> int:
        """The bytes of payload data that follow a file's entry, as rpm reads them."""
        kind = file.mode & _S_IFMT
        if kind == _S_IFLNK:
            return file.size
        if kind == _S_IFREG and (not file.links or file.links[-1] == file.index):
            return file.size
        return 0

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


class _Payload:
    """One walk's place in the payload, shared by the data streams of the members it
    yields (``SequentialReader.data_on_demand``). It moves forward only, and reads
    nothing until a member's data is read.

    rpm writes the entries in the order the walk yields the members in
    (:func:`_write_order`), so they find theirs in that order: entries passed on the way
    (directories, symlinks, earlier hard links, files nobody read, ghosts rpm < 4.11
    stored) are skipped, and so is a second entry for a file. A file whose entry is
    not there fails alone: the search for it stops at the next entry that carries
    data for a later file, and leaves that entry for that file's read. Damage to the
    payload's structure (an entry that does not parse, names no file of the header,
    or gives a size other than the header's, which rpm reads by) fails the read that
    finds it, and every later read of the walk.
    """

    def __init__(
        self, reader: RpmReader, payload: ForwardStream, package: _Package
    ) -> None:
        self._reader = reader
        self._payload = payload
        self._package = package
        # The entry read but not yet used: its file and the size its entry gives.
        self._pending: tuple[_File, int] | None = None
        # Where the data being read ends, past which the next search starts.
        self._data_end = payload.offset
        # The data stream reading now; one that is not it may no longer read.
        self.current: _PayloadData | None = None
        self._ended = False
        self._broken: CorruptionError | None = None

    def find(self, data: _PayloadData) -> None:
        """Move to the data of ``data``'s file and make ``data`` the stream reading."""
        if self._broken is not None:
            raise CorruptionError(
                f"RPM payload cannot be read to {_shown(data.file.raw_name)}: "
                f"{self._broken}"
            ) from self._broken
        try:
            size = self._find(data.file)
        except CorruptionError as error:
            if not isinstance(error, _MemberDamage):
                self._broken = error
            raise
        self.current = data
        self._data_end = self._payload.offset + size

    def _find(self, file: _File) -> int:
        payload = self._payload
        reader = self._reader
        # What the last data read left of its data. A search that stopped short read
        # the next entry's header, which waits in ``_pending``, so the stream may be
        # past the data's end.
        if self._data_end > payload.offset:
            payload.skip(self._data_end - payload.offset)
        self._data_end = payload.offset
        while True:
            if self._pending is None:
                if self._ended:
                    raise self._missing(file)
                found, size = reader._next_entry(payload, self._package)
                if found is None:
                    self._ended = True
                    raise self._missing(file)
                self._pending = found, size
            found, size = self._pending
            expected = reader._expected_size(found)
            # Only a regular file's entry holds a member's data. A ghost's never does,
            # whatever its entry gives, and neither does an earlier file of a
            # hard-link set, whose entry is empty (``_expected_size`` is 0 where the
            # header gives its size).
            carries = (
                found.mode & _S_IFMT == _S_IFREG
                and not found.flags & RPMFILE_GHOST
                and expected == found.size
            )
            if carries and found.rank > file.rank:
                # rpm writes the data in this order, so the file's would have come.
                raise self._missing(file)
            if not found.flags & RPMFILE_GHOST and size != expected:
                # rpm reads the header's size (iterReadArchiveNext), so for rpm every
                # entry after this one is out of place: the payload is damaged here.
                raise CorruptionError(
                    f"RPM payload entry for {_shown(found.raw_name)} gives {size} "
                    f"bytes; the header gives {expected}"
                )
            self._pending = None
            if found is file:
                return size
            if found.mode & _S_IFMT == _S_IFLNK and not found.flags & RPMFILE_GHOST:
                # Its size is the header's target length (checked above), so the read
                # is no larger than a string the header already holds.
                self._compare_target(found, payload.read_exact(size))
                self._data_end = payload.offset
                continue
            self._skip(size)

    def _compare_target(self, file: _File, stored: bytes) -> None:
        """Report a symlink whose payload entry stores another target than the
        header, whose target the member keeps (``FILELINKTOS``, as rpm installs it)."""
        reader = self._reader
        targets = self._package.targets
        assert targets is not None  # _files refuses a symlink with no target
        listed = targets[file.index]
        if stored == listed or file.index in reader._reported_targets:
            return
        reader._reported_targets.add(file.index)
        context = reader._context
        raw = file.raw_name
        name = context.normalize_name(
            context.decode_name(b"." + raw if raw.startswith(b"/") else raw),
            MemberType.SYMLINK,
        )
        context.report(
            DiagnosticCode.MEMBER_HEADER_AMBIGUOUS,
            f"RPM symlink {_shown(raw)}: the payload stores the target "
            f"{_shown(stored)}, the header {_shown(listed)}; the header's is used",
            HeaderAmbiguityContext(
                member_name=name, ambiguity="copies_differ", field="FILELINKTOS"
            ),
        )

    def _skip(self, size: int) -> None:
        self._pending = None
        self._payload.skip(size)
        self._data_end = self._payload.offset

    def read(self, data: _PayloadData, n: int) -> bytes:
        if self.current is not data:
            raise CorruptionError(
                f"RPM payload is past the data of {_shown(data.file.raw_name)}"
            )
        n = min(n, self._data_end - self._payload.offset)
        return self._payload.read(n) if n > 0 else b""

    @staticmethod
    def _missing(file: _File) -> _MemberDamage:
        return _MemberDamage(
            f"RPM payload holds no data for {_shown(file.raw_name)} where rpm's order "
            "puts it"
        )


class _MemberDamage(CorruptionError):
    """Damage that fails one member's read and leaves the payload readable."""


class _PayloadData(io.RawIOBase):
    """A file's data, found in the payload when first read (:class:`_Payload`)."""

    def __init__(self, cursor: _Payload, file: _File) -> None:
        self._cursor = cursor
        self.file = file
        self._started = False

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, buffer: Any) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not self._started:
            self._started = True
            self._cursor.find(self)
        data = self._cursor.read(self, len(buffer))
        buffer[: len(data)] = data
        return len(data)

    @override
    def close(self) -> None:
        # ``getattr``: a close on an instance whose ``__init__`` did not run.
        cursor = getattr(self, "_cursor", None)
        if cursor is not None and cursor.current is self:
            cursor.current = None
        super().close()


def _write_order(files: list[_File]) -> list[int]:
    """The files that are not ghosts, by index, in the order rpm writes their payload
    entries, each file's ``rank`` set to its place in it.

    rpm 4.12 and later (``lib/rpmfi.c``, ``iterWriteArchiveNextFile``) and rpm 4.11
    (``lib/fsm.c``, ``writeLinks``) both write every file that is not in a hard-link
    set in header order, then each set, ordered by its first file, with its files in
    header order and the data with the last.
    """
    order = [f.index for f in files if not f.links and not f.flags & RPMFILE_GHOST]
    for file in files:
        if file.links and file.links[0] == file.index:
            order.extend(file.links)
    for rank, index in enumerate(order):
        files[index].rank = rank
    return order


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
            f"RPM payload entry at offset {offset}: the {what} field "
            f"{quoted(raw.decode('ascii', 'surrogateescape'))} is not a number"
        ) from None


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
