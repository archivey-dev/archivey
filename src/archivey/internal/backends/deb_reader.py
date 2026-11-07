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
stops after the data tar. ``DEBIAN/md5sums`` lists an MD5 per installed file: the walk
holds it (it is part of the control tar, so it arrives first) and gives each data file
its digest in ``ArchiveMember.hashes``, which a read then checks. A line that is not an
MD5 and a name is skipped, as ``dpkg --verify`` skips it.

Handbook page: ``dev-docs/formats/deb.md``.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from typing import BinaryIO

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
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
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ContainerFormat,
    HashAlgorithm,
    MemberType,
    StreamFormat,
)

AR_MAGIC = b"!<arch>\n"
HEADER_SIZE = 60
VERSION_MEMBER = b"debian-binary"
# The first member's name field, as dpkg-deb (no slash) and GNU ar (a slash) write it.
MAGIC = (
    AR_MAGIC + VERSION_MEMBER.ljust(16),
    AR_MAGIC + (VERSION_MEMBER + b"/").ljust(16),
)
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
        # Bytes of control and md5sums held so far, against max_metadata_bytes.
        self._held = 0

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
        control = False
        while True:
            name, size = self._header(stream)
            if name.startswith(b"_"):
                stream.skip(size)
                stream.read(size & 1)
                continue
            if not control:
                fmt = _tar_format(name, b"control", _CONTROL_STREAMS)
                if fmt is None:
                    raise CorruptionError(
                        "Debian package has no control.tar member after debian-binary"
                    )
                yield from self._control(stream.take(size), fmt)
                control = True
            else:
                fmt = _tar_format(name, b"data", _DATA_STREAMS)
                if fmt is None:
                    raise CorruptionError(
                        "Debian package has an unexpected member before its data.tar"
                    )
                yield from self._data(stream.take(size), fmt)
                # dpkg-deb reads no further: members after the data tar are not part
                # of the package.
                return
            stream.read(size & 1)

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
        if int(major) != 2:
            raise UnsupportedFeatureError(
                f"Debian package format version {int(major)}: archivey reads 2.x, "
                "as dpkg-deb does"
            )
        self._version = version.decode("ascii", "replace")

    def _control(self, data: BinaryIO, fmt: ArchiveFormat) -> Iterator[MemberSpan]:
        context = self._context
        for span in context.open_nested(data, fmt):
            member = span.member
            inner = member.name
            member.name = CONTROL_DIR if inner == "." else CONTROL_DIR + inner
            if member.type is MemberType.HARDLINK and member.link_target:
                target = context.normalize_name(member.link_target, MemberType.FILE)
                member.link_target = CONTROL_DIR + target
            if member.type is MemberType.FILE and inner in ("control", "md5sums"):
                held = self._hold(span, inner)
                if inner == "control":
                    self._read_control(held)
                else:
                    self._read_md5sums(held)
                span = span._replace(data=io.BytesIO(held))
            yield span

    def _data(self, data: BinaryIO, fmt: ArchiveFormat) -> Iterator[MemberSpan]:
        context = self._context
        for span in context.open_nested(data, fmt):
            member = span.member
            if member.type is MemberType.HARDLINK and member.link_target:
                # The nested reader hands the target over as the tar stores it
                # ("./usr/bin/x"), and the listing normalizes names, not targets.
                member.link_target = context.normalize_name(
                    member.link_target, MemberType.FILE
                )
            elif member.type is MemberType.FILE:
                digest = self._md5.get(member.name)
                if digest is not None:
                    member.hashes = {**member.hashes, HashAlgorithm.MD5: digest}
            yield span

    def _hold(self, span: MemberSpan, name: str) -> bytes:
        """A control file's bytes, read whole, against ``max_metadata_bytes``."""
        # ``name`` is "control" or "md5sums", never a name from elsewhere.
        self._count(span.member.size or 0, f"control file {name}")
        return span.data.read() if span.data is not None else b""

    def _count(self, size: int, what: str) -> None:
        """Count ``size`` more held bytes, refusing before they are read.

        ``debian-binary``, ``control`` and ``md5sums`` are held whole, and their
        sizes come from the package, so their total is what the limit bounds.
        """
        limit = self._context.config.listing_limits.max_metadata_bytes
        if limit is not None and self._held + size > limit:
            raise ResourceLimitError(
                f"Debian package {what} of {size} bytes takes the metadata "
                f"held to {self._held + size} bytes, over max_metadata_bytes={limit}"
            )
        self._held += size

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
        """``<32 hex digits> <name>`` per line, the name relative to the root."""
        context = self._context
        for line in data.split(b"\n"):
            digest, _space, name = line.partition(b" ")
            # md5sum writes two spaces, the second a " " (text) or "*" (binary) mark.
            name = name[1:] if name[:1] in (b" ", b"*") else name
            if len(digest) != 32 or not set(digest) <= _HEX or not name:
                continue
            path = context.normalize_name(context.decode_name(name), MemberType.FILE)
            self._md5[path] = bytes.fromhex(digest.decode("ascii"))


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


DebReadBackend = register_builtin_format(DebHandler)
