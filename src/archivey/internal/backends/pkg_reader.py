"""The macOS installer package reader: a ``.pkg`` or ``.xip`` read as the files its
payloads hold.

A ``.pkg`` is a XAR archive (``xar_reader``). A component package holds ``Bom``,
``PackageInfo``, ``Payload`` and often ``Scripts`` at its top; a product archive holds
a ``Distribution`` and one folder per component package (``app.pkg/``) with those files
inside. ``Payload`` and ``Scripts`` are CPIO archives, compressed with gzip or pbzx
(Apple's chunked xz, ``StreamFormat.PBZX``). A ``.xip`` holds ``Metadata`` and
``Content``, a pbzx CPIO.

The listing is what ``pkgutil --expand-full`` unpacks: each ``Payload``, ``Scripts``
and ``Content`` member is listed as the files its CPIO holds, under a folder of the
member's name (``app.pkg/Payload/Applications/App.app/...``), and every other member
as it is (``Distribution``, ``PackageInfo``, ``Bom``). Opening the file with
``format=ArchiveFormat.XAR`` gives the XAR members instead. A payload that is not one
of those CPIO forms is listed as it is: one stored with a XAR encoding archivey does not
read or the configuration turns off, one whose first bytes are no gzip, pbzx or CPIO
magic, or one whose first CPIO header cannot be read.

The payloads are read through :meth:`ReaderContext.open_nested`, so listing decodes
each one, and the XAR checksum of a payload is checked as the listing reads it. A
payload file that extracts outside its folder (``../Bom``), or a hard link whose target
does, is refused: it would replace another member of the package.

Handbook page: ``dev-docs/formats/xar.md``.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import itertools
import re
import typing
import zlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from archivey.exceptions import CorruptionError, UnsupportedFeatureError
from archivey.formats import (
    IndexedFormatHandler,
    MemberData,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    collision_key,
    extracted_segments,
)
from archivey.internal.backends.xar_reader import (
    _HEADER,
    MAGIC,
    XarReader,
    _Inner,
    _Location,
)
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    ContainerFormat,
    ExtractionPolicy,
    MemberType,
    StreamFormat,
)

# ``typing.override`` (Python 3.12) where there is one. A format written outside
# archivey carries the same lines, so the module imports no internal name for it.
if TYPE_CHECKING:
    from typing_extensions import override
else:
    override = getattr(typing, "override", lambda method: method)

# The members that hold a CPIO: ``Payload`` and ``Scripts`` of a package, at the top
# of a component package or in a product archive's component folder, and the top
# ``Content`` of a ``.xip``.
_PACKAGE_PAYLOADS = frozenset({"Payload", "Scripts"})
_XIP_PAYLOAD = "Content"

# What a payload starts with, and the format of the CPIO it holds.
_GZIP_MAGIC = b"\x1f\x8b"
_PBZX_MAGIC = b"pbzx"
_CPIO_MAGIC = b"0707"
_SNIFF = 4

# Names only an installer package's table of contents holds, for detection.
_PACKAGE_NAMES = re.compile(rb"<name>(?:Distribution|PackageInfo)</name>")
_PACKAGE_EXTENSIONS = (".pkg", ".mpkg", ".xip")
# The most of the stored (compressed) table of contents detection reads. A signed
# package or ``.xip`` puts its certificate chain (``<signature>``, ``<x-signature>``)
# before the first ``<file>``, and base64 certificates hardly compress, so the names
# can sit well past the 4 KiB near window.
_TOC_READ = 1 << 16
# The most of the table of contents detection decodes from what it read.
_TOC_PEEK = 1 << 18


def is_package(peek: Callable[[int], bytes], name: str | None) -> bool:
    """Whether a XAR is an installer package (``ReadBackend.MAGIC_REFINEMENTS``): by its
    name when it has a package's extension or ``.xar``, else by the names at the start
    of its table of contents. ``peek(end)`` returns the source's first ``end`` bytes,
    or on a forward-only source what detection already holds; this asks once for at
    most the header and ``_TOC_READ`` bytes of the stored table of contents."""
    if name is not None:
        lowered = name.lower()
        if lowered.endswith(_PACKAGE_EXTENSIONS):
            return True
        if lowered.endswith(".xar"):
            return False
    head = peek(_HEADER.size)
    if len(head) < _HEADER.size or not head.startswith(MAGIC):
        return False
    _magic, header_size, _version, toc_stored, _toc_size, _algo = _HEADER.unpack_from(
        head
    )
    stored = peek(header_size + min(toc_stored, _TOC_READ))[header_size:]
    try:
        xml = zlib.decompressobj().decompress(stored, _TOC_PEEK)
    except zlib.error:
        return False
    if _PACKAGE_NAMES.search(xml) is not None:
        return True
    return b"<name>Content</name>" in xml and b"<name>Metadata</name>" in xml


def _payload_folder(member: ArchiveMember) -> bool:
    """Whether ``member`` is a payload this reader lists as its files."""
    if member.type is not MemberType.FILE:
        return False
    parts = member.name.split("/")
    if len(parts) == 1:
        return parts[0] in _PACKAGE_PAYLOADS or parts[0] == _XIP_PAYLOAD
    return len(parts) == 2 and parts[1] in _PACKAGE_PAYLOADS


def _inner_format(head: bytes) -> ArchiveFormat | None:
    if head.startswith(_GZIP_MAGIC):
        return ArchiveFormat(ContainerFormat.CPIO, StreamFormat.GZIP)
    if head.startswith(_PBZX_MAGIC):
        return ArchiveFormat(ContainerFormat.CPIO, StreamFormat.PBZX)
    if head.startswith(_CPIO_MAGIC):
        return ArchiveFormat.CPIO
    return None


def _key(segments: list[str]) -> list[str]:
    return [collision_key(s, ExtractionPolicy.STANDARD) for s in segments]


class _Payload(io.RawIOBase):
    """A payload's bytes as the inner reader reads them: first the bytes read to tell
    its format, then the rest. Closing it leaves the payload open, so the reader can
    read what the inner archive left and check the payload's XAR checksum."""

    def __init__(self, head: bytes, stream: BinaryIO, digest: Any) -> None:
        self._head = head
        self._stream = stream
        self._digest = digest
        if digest is not None:
            digest.update(head)

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, buffer: Any) -> int:
        if self._head:
            n = min(len(buffer), len(self._head))
            buffer[:n] = self._head[:n]
            self._head = self._head[n:]
            return n
        data = self._stream.read(len(buffer)) or b""
        if self._digest is not None:
            self._digest.update(data)
        buffer[: len(data)] = data
        return len(data)

    def drain(self) -> None:
        """Read what the inner archive left of the payload."""
        self._head = b""
        while True:
            data = self._stream.read(1 << 16)
            if not data:
                return
            if self._digest is not None:
                self._digest.update(data)


class PkgReader(XarReader):
    """One open installer package: a XAR whose payloads are listed as their files."""

    # Listing decodes the payloads.
    member_list_upfront = False

    @override
    def iter_members(self) -> Iterator[MemberRecord[_Location]]:
        for record in super().iter_members():
            if record.locator.data is None or not _payload_folder(record.member):
                yield record
                continue
            yield from self._expand(record)

    def _expand(
        self, record: MemberRecord[_Location]
    ) -> Iterator[MemberRecord[_Location]]:
        """The files of the payload ``record``, or ``record`` itself when it does not
        hold a CPIO."""
        payload, location = record.member, record.locator
        try:
            stream = cast(BinaryIO, super().open_member(payload, location).stream)
        except UnsupportedFeatureError:
            # A XAR encoding archivey does not read, or one the configuration turns
            # off (``FormatPolicy``): the file it is, which reading refuses with the
            # same error.
            yield record
            return
        with contextlib.closing(stream):
            try:
                head = stream.read(_SNIFF) or b""
            except UnsupportedFeatureError:
                # The same, found only once the decoder reads: an xz encoding whose
                # block runs a filter the configuration turns off (BCJ).
                yield record
                return
            fmt = _inner_format(head)
            if fmt is None:
                yield record
                return
            digest = None
            expected = None
            if payload.hashes:
                ((algorithm, expected),) = list(payload.hashes.items())[:1]
                digest = hashlib.new(algorithm.value, usedforsecurity=False)
            data = _Payload(head, stream, digest)
            folder = payload.name
            folder_key = _key(extracted_segments(folder))
            inner_location = _Inner(payload, location, fmt)
            spans = iter(self._context.open_nested(data, fmt))
            try:
                first = next(spans, None)
            except CorruptionError:
                # It starts like a CPIO but none follows: the file it is. A payload
                # that fails after its first member has listed files, and raises.
                yield record
                return
            for span in itertools.chain(() if first is None else (first,), spans):
                member = span.member
                inner = member.name
                member.name = folder if inner in (".", "./") else f"{folder}/{inner}"
                self._check_inside(folder, folder_key, member.name, member)
                if member.type is MemberType.HARDLINK and member.link_target:
                    member.link_target = f"{folder}/{member.link_target}"
                    self._check_inside(folder, folder_key, member.link_target, member)
                yield MemberRecord(member, _Location(None, inner_location))
            data.drain()
            if digest is not None and digest.digest() != expected:
                raise CorruptionError(
                    f"XAR file {quoted(folder)} fails its {digest.name} checksum"
                )

    @staticmethod
    def _check_inside(
        folder: str, folder_key: list[str], path: str, member: ArchiveMember
    ) -> None:
        if _key(extracted_segments(path)[: len(folder_key)]) != folder_key:
            raise CorruptionError(
                f"macOS package payload {quoted(folder)} has a member that extracts "
                "outside its folder",
                member_name=member.name,
            )

    @override
    def open_member(self, member: ArchiveMember, locator: _Location) -> MemberData:
        inner = locator.inner
        if inner is None:
            return super().open_member(member, locator)
        stream = super().open_member(inner.payload, inner.location).stream
        # From open_member, open_nested yields one span: this member's, reached again
        # (ReaderContext.open_nested).
        span = next(iter(self._context.open_nested(stream, inner.format)))
        data = span.data
        return MemberData(data if data is not None else io.BytesIO(b""))

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        # The files of one payload share its decode.
        return ReaderArchiveInfo(is_solid=True, format_version="1")


class PkgHandler(IndexedFormatHandler):
    """macOS installer packages (``.pkg``) and Xcode archives (``.xip``)."""

    format = ArchiveFormat.PKG
    extensions = _PACKAGE_EXTENSIONS
    uses_encoding = True
    non_seekable_reason = "its files' data sit anywhere in the heap after the index"

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> PkgReader:
        return PkgReader(source, context)
