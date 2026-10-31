"""Forward walk over a ZIP's local headers: the parser half of a read with no seek.

A ZIP can be read start to end from a pipe, a socket or a remote object read once::

    [ stub? ]
    [ local file header · data · data descriptor? ] × n   # PK\\x03\\x04, PK\\x07\\x08
    [ bytes before the directory? ]                       # an APK signing block
    [ central directory header ] × n                      # PK\\x01\\x02
    [ ZIP64 end record · ZIP64 locator ]?                 # PK\\x06\\x06, PK\\x06\\x07
    [ end of central directory record · comment ]         # PK\\x05\\x06

:class:`LocalHeaderWalk` reads that layout from a stream it only reads, never seeks.
It counts the bytes consumed, which is the offset every local entry is matched by
against the directory. Call graph: :meth:`LocalHeaderWalk.next_entry` (one
:class:`LocalEntry` per member, in file order) → :meth:`LocalHeaderWalk.member_data`
(the member's compressed bytes, through a reader that knows where they end) →
:meth:`MemberData.settle` (the data descriptor, when bit 3 defers the sizes to one) →
after the last member, :meth:`LocalHeaderWalk.read_rest` (the bytes after the members,
up to a bound, for the caller to parse with the seekable read's ``find_end_record`` and
``CentralDirectoryWalk``, so a forward read lists what a file read lists except where
:meth:`ForwardTail.end_record` refuses a record it cannot see).

Where a member's data ends
(``openspec/changes/archive/2026-10-30-native-zip-reader/design.md``):

- Bit 3 clear: the local header's ``compressed_size`` bytes.
- Bit 3 and STORED: a scan for a descriptor, with or without its ``PK\\x07\\x08``,
  whose CRC and compressed size match the bytes since the data start and which a ZIP
  signature follows. Under encryption the CRC covers the plaintext, so only the size
  and the signature after the descriptor are matched. Unencrypted, a descriptor with
  one damaged field still ends the data (:func:`match_damaged_descriptor`), so one
  damaged byte fails that member alone.
- Bit 3 and any other method: the codec's own end. The walk cannot see it, so the
  caller decodes until the codec stream ends and hands :meth:`MemberData.settle` the
  decoded data's CRC; the walk finds the descriptor among the bytes it kept, one
  damaged field allowed, and puts what follows it back in front of the stream. A
  caller whose codec counts the bytes it used (DEFLATE) may pass that count
  instead. An encrypted one nobody reads is scanned for as a STORED one is
  (:meth:`LocalHeaderWalk.scan_member_data`), so no key is needed to pass it.

Like ``zip_parser``, this module decodes no name, runs no codec and emits no
diagnostic. Damage raises ``CorruptionError``, a stream that ends early
``TruncatedError``, a valid shape a forward read cannot follow
``UnsupportedFeatureError``. The caller stamps archive and member context.
"""

from __future__ import annotations

import io
import struct
import zlib
from collections import deque
from dataclasses import dataclass, replace
from typing import BinaryIO, NoReturn

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.zip_aes import iter_extra_fields
from archivey.internal.backends.zip_detect import (
    LOCAL_HEADER_SIGNATURE,
    LOCAL_HEADER_SIZE,
    validate_zip_local_header,
)
from archivey.internal.backends.zip_parser import (
    ARCHIVE_EXTRA_DATA_SIGNATURE,
    CENTRAL_HEADER_SIGNATURE,
    EOCD_SIGNATURE,
    EOCD_SIZE,
    STRONG_ENCRYPTED_DIRECTORY_MSG,
    ZIP64_EOCD_SIGNATURE,
    ZIP64_EOCD_SIZE,
    ZIP64_LOCATOR_SIGNATURE,
    EndRecord,
    LocalHeader,
    ReadAt,
    classic_record_saturated,
    find_end_record,
    local_header_from,
    local_header_variable_length,
    local_stored_sizes,
    local_zip64_sizes,
    locate_classic_record,
    read_local_header,
    read_zip64_locator,
    step_over_directory,
    zip64_record_matches,
)
from archivey.internal.overrides import override
from archivey.internal.sfx import SFX_MAX, VALIDATOR_PEEK_MAX, HitOutcome
from archivey.internal.streams.streamtools.base import ReadOnlyIOStream
from archivey.internal.streams.streamtools.binaryio import read_exact

DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"

_FLAG_ENCRYPTED = 0x01
_FLAG_DATA_DESCRIPTOR = 0x08
_METHOD_STORED = 0
_ZIP64_EXTRA_TAG = 0x0001
_ZIP64_RECORD = "ZIP64 end of central directory record"
_U16_MAX = 0xFFFF

# What may follow a member's data descriptor: the next member, the directory, the end
# records when the directory is empty or missing, or the record PKWARE Strong Encryption
# writes in front of an encrypted directory. Bytes before the directory that are
# neither (an APK signing block) are not a descriptor's successor.
_AFTER_MEMBER = frozenset(
    {
        LOCAL_HEADER_SIGNATURE,
        CENTRAL_HEADER_SIGNATURE,
        ZIP64_EOCD_SIGNATURE,
        EOCD_SIGNATURE,
        ARCHIVE_EXTRA_DATA_SIGNATURE,
    }
)
# What the bytes after the last member may start with: the directory, the end records
# of an archive with no entries, or the record PKWARE Strong Encryption writes in front
# of an encrypted directory. Anything else is no ZIP structure.
_DIRECTORY_STARTS = _AFTER_MEMBER - {LOCAL_HEADER_SIGNATURE}
# What the end record is stepped to from, right after the members
# (``step_over_directory``).
_STEPPED_OVER = frozenset(
    {
        CENTRAL_HEADER_SIGNATURE,
        ZIP64_EOCD_SIGNATURE,
        ZIP64_LOCATOR_SIGNATURE,
        EOCD_SIGNATURE,
    }
)
# What may open a stream without a stub in front: the same set as after a member.
_OPENS_STREAM = _AFTER_MEMBER
# The longest data descriptor, plus the signature after it: signature, CRC, two 8-byte
# sizes, next signature.
_DESCRIPTOR_LOOKAHEAD = 4 + 4 + 8 + 8 + 4
# Each descriptor shape's length (signature or none, 4- or 8-byte sizes), longest
# first: a scan that knows where one ends tries them from the earliest start. The
# order is policy: when two shapes fit, the member ends earlier, as a planted prefix
# descriptor ends it (see ``_CodecData._find_descriptor``), and the directory check
# at the end of the pass catches that.
_DESCRIPTOR_LENGTHS = (24, 20, 16, 12)
_DESCRIPTOR_LONGEST = _DESCRIPTOR_LENGTHS[0]
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1
# ``_ScannedData._size_fits``'s probes, as (offset from the shape's start, width):
# the compressed size without a signature, then with one (or a damaged one), each
# 4 then 8 bytes wide; then for STORED data the uncompressed size without a
# signature, and with one when one is there.
_ENCRYPTED_PROBES = ((4, 4), (4, 8))
_ENCRYPTED_PROBES_SIGNED = (*_ENCRYPTED_PROBES, (8, 4), (8, 8))
_STORED_PROBES = (*_ENCRYPTED_PROBES_SIGNED, (8, 4), (12, 8))
_STORED_PROBES_SIGNED = (*_STORED_PROBES, (12, 4), (16, 8))
# Forward reads are made in pieces of this size.
_READ_CHUNK = 1 << 16
# The first read ahead into a bit-3 member's data, whose end the walk does not know
# yet (``MemberData._read_ahead``). Small, since what a member reads past its end is
# read again for the next header, so a tiny member costs about its own bytes; large
# enough that the descriptor scan, which holds back ``_DESCRIPTOR_LOOKAHEAD`` bytes,
# hands most of a first step out. Each step that comes back full doubles the next, up
# to the size the caller asks for, ``_READ_CHUNK`` for the walk's own reads.
_READ_AHEAD_FIRST = 256
# How far past the bytes a codec member handed out its descriptor is searched for when
# it is not right after them (``_CodecData._find_descriptor``): junk up to about this
# long between the codec's end and the descriptor is passed over, whatever the
# member's size.
_DESCRIPTOR_SEARCH_PAST = _READ_CHUNK
# How much of what a codec member handed out is kept to put back. A codec member's
# layers read ahead by at most a few of their read sizes: DecompressorStream reads up
# to 1 MiB at once, and a decrypt stage in front of it a little more.
_CODEC_RETAIN = 4 << 20
# The end record and its comment, the longest tail a stream can end with after the
# directory: kept by the descriptor scan to tell a whole archive after the member
# (no descriptor matched, a shape a forward read cannot split) from a stream cut
# inside the member.
_TAIL_KEEP = (1 << 16) + EOCD_SIZE


class ForwardSource:
    """A stream read forward only, with bytes put back in front of it.

    :attr:`offset` is the position of the next byte :meth:`read` returns, counted from
    the start of the stream (``offset`` at construction): reading moves it forward,
    :meth:`unread` moves it back.
    """

    def __init__(self, stream: BinaryIO, *, offset: int = 0) -> None:
        self._stream = stream
        self._pending = bytearray()
        self.offset = offset

    def read(self, n: int) -> bytes:
        """Up to ``n`` bytes; fewer only at the end of the stream."""
        if n <= 0:
            return b""
        if self._pending:
            out = bytes(self._pending[:n])
            del self._pending[:n]
            if len(out) < n:
                out += read_exact(self._stream, n - len(out))
        else:
            out = read_exact(self._stream, n)
        self.offset += len(out)
        return out

    def unread(self, data: bytes | bytearray | memoryview) -> None:
        """Put ``data``, the bytes most recently read, back in front of the stream."""
        if data:
            self._pending[0:0] = data
            self.offset -= len(data)

    def peek(self, n: int) -> bytes:
        """Up to ``n`` bytes, left in front of the stream."""
        data = self.read(n)
        self.unread(data)
        return data

    def skip(self, n: int) -> int:
        """Move past ``n`` bytes; returns how many there were before the end.

        A stream that can seek is seeked; any other is read.
        """
        skipped = 0
        if self._pending:
            skipped = len(self.read(min(n, len(self._pending))))
        if skipped < n and self._stream.seekable():
            here = self._stream.tell()
            end = self._stream.seek(0, io.SEEK_END)
            target = min(here + n - skipped, end)
            self._stream.seek(target)
            skipped += max(target - here, 0)
            self.offset += max(target - here, 0)
            return skipped
        while skipped < n:
            got = len(self.read(min(n - skipped, _READ_CHUNK)))
            if not got:
                break
            skipped += got
        return skipped


@dataclass(frozen=True, slots=True)
class LocalEntry:
    """One local header met by the forward walk."""

    #: Position in file order, from 0.
    index: int
    #: Stream offset of the header's signature: what a central entry's offset names.
    offset: int
    #: The header. ``data_start`` is a stream offset, and the sizes have the ZIP64
    #: extra field applied.
    header: LocalHeader
    #: The header carries a ZIP64 extra field, so a data descriptor's sizes are 8
    #: bytes wide (APPNOTE 4.3.9.2).
    zip64: bool

    @property
    def deferred(self) -> bool:
        """Bit 3: the CRC and sizes are in a data descriptor after the data."""
        return bool(self.header.flags & _FLAG_DATA_DESCRIPTOR)


@dataclass(frozen=True, slots=True)
class DataDescriptor:
    """The CRC and sizes written after a bit-3 member's data."""

    crc: int
    #: The full compressed size: a 4-byte shape matched it modulo 2**32.
    compressed_size: int
    #: The full uncompressed size when the caller supplied it to match against;
    #: otherwise as stored, so modulo 2**32 for a 4-byte shape.
    file_size: int
    #: The bytes it occupies, the signature included when it has one.
    length: int


def _has_zip64_extra(extra: bytes) -> bool:
    return any(field.tag == _ZIP64_EXTRA_TAG for field in iter_extra_fields(extra))


def match_descriptor(
    buffer: bytes | bytearray,
    pos: int,
    *,
    compressed_size: int,
    crc: int | None,
    file_size: int | None,
    zip64: bool,
    at_end: bool,
) -> DataDescriptor | None:
    """The data descriptor at ``buffer[pos:]``, or ``None`` when none fits there.

    Four shapes are tried, signature or none, 4- or 8-byte sizes, those the local
    header promises first (8-byte when it has a ZIP64 extra field; Java writes 8-byte
    sizes for a member past 4 GiB without one). A shape fits when its compressed size
    is ``compressed_size`` (modulo 2**32 for 4-byte sizes), its CRC is ``crc`` and its
    uncompressed size ``file_size`` when those are known, and a ZIP signature follows
    it, or the end of the input when ``at_end``. ``buffer`` must hold the
    longest shape and the signature after it (``_DESCRIPTOR_LOOKAHEAD`` bytes) unless
    it ends there. :func:`match_damaged_descriptor` is the fallback for a shape with
    one damaged field.
    """
    widths = (8, 4) if zip64 else (4, 8)
    for width in widths:
        for signed in (True, False):
            at = pos
            if signed:
                if buffer[at : at + 4] != DATA_DESCRIPTOR_SIGNATURE:
                    continue
                at += 4
            body_len = 4 + 2 * width
            if len(buffer) < at + body_len:
                continue
            got_crc = int.from_bytes(buffer[at : at + 4], "little")
            got_csize = int.from_bytes(buffer[at + 4 : at + 4 + width], "little")
            got_usize = int.from_bytes(buffer[at + 4 + width : at + body_len], "little")
            mask = (1 << (8 * width)) - 1
            if got_csize != compressed_size & mask:
                continue
            if crc is not None and got_crc != crc:
                continue
            if file_size is not None and got_usize != file_size & mask:
                continue
            end = at + body_len
            following = bytes(buffer[end : end + 4])
            if following not in _AFTER_MEMBER and not (at_end and not following):
                continue
            # A 4-byte shape matched modulo 2**32: give back the full sizes the caller
            # supplied. An uncompressed size it did not supply stays as stored.
            return DataDescriptor(
                crc=got_crc,
                compressed_size=compressed_size if width == 4 else got_csize,
                file_size=file_size
                if width == 4 and file_size is not None
                else got_usize,
                length=end - pos,
            )
    return None


def match_damaged_descriptor(
    buffer: bytes | bytearray,
    pos: int,
    *,
    compressed_size: int,
    crc: int | None,
    file_size: int | None,
    zip64: bool,
    at_end: bool,
) -> DataDescriptor | None:
    """The data descriptor at ``buffer[pos:]`` when one damaged field is all that
    stops :func:`match_descriptor` from taking it, or ``None``.

    The shapes and the ZIP signature after them are those of :func:`match_descriptor`.
    A shape without its signature is taken when two of its three fields agree with
    what the caller knows (its compressed size is ``compressed_size``, its CRC
    ``crc``, its uncompressed size ``file_size``; an unknown one never agrees). One
    with its signature is taken when its compressed size agrees, or two of the
    fields do; and with its signature damaged, when all three do. So one damaged
    byte, in the data or in the descriptor, still ends the member where it ends, and
    the member fails alone: the caller checks the CRC and size it read against the
    descriptor's, and the directory checks the descriptor at the end of the pass.

    The thresholds keep the same amount of evidence for each shape. The signature is
    itself a 32-bit match, so with it one agreeing field places the shape; that arm
    is also the fallback ``_CodecData._find_descriptor`` applied alone before this
    function existed (a signed descriptor whose size fits, whatever its CRC), kept
    at its strength so a damaged codec member still ends where it did. Without a
    signature, two agreeing fields stand in for those 32 bits. Four bytes that are
    nearly the signature but not it are evidence against the shape, so then all
    three fields must agree.

    The fields are returned as stored, except that a 4-byte size that agrees gives
    back the full value the caller supplied.
    """
    widths = (8, 4) if zip64 else (4, 8)
    signed_here = buffer[pos : pos + 4] == DATA_DESCRIPTOR_SIGNATURE
    for width in widths:
        # How many bytes come before the fields: a signature, one damaged, or none.
        for lead in (4, 0):
            at = pos + lead
            end = at + 4 + 2 * width
            if len(buffer) < end:
                continue
            following = bytes(buffer[end : end + 4])
            if following not in _AFTER_MEMBER and not (at_end and not following):
                continue
            mask = (1 << (8 * width)) - 1
            got_crc = int.from_bytes(buffer[at : at + 4], "little")
            got_csize = int.from_bytes(buffer[at + 4 : at + 4 + width], "little")
            got_usize = int.from_bytes(buffer[at + 4 + width : end], "little")
            csize_ok = got_csize == compressed_size & mask
            crc_ok = crc is not None and got_crc == crc
            usize_ok = file_size is not None and got_usize == file_size & mask
            agree = csize_ok + crc_ok + usize_ok
            if not lead:
                taken = agree >= 2
            elif signed_here:
                taken = csize_ok or agree >= 2
            else:
                taken = agree == 3
            if not taken:
                continue
            return DataDescriptor(
                crc=got_crc,
                compressed_size=compressed_size if csize_ok else got_csize,
                file_size=file_size
                if usize_ok and file_size is not None
                else got_usize,
                length=end - pos,
            )
    return None


def descriptor_by_crc(
    buffer: bytes | bytearray,
    *,
    crc: int,
    file_size: int | None,
    base: int,
    zip64: bool,
    at_end: bool,
) -> tuple[int, DataDescriptor] | None:
    """The first data descriptor in ``buffer`` whose CRC is ``crc``, with its
    position: one that states ``file_size`` when given, a compressed size equal to
    its own offset from the data's start (``base`` bytes before ``buffer``), and a
    ZIP signature after it (see :func:`match_descriptor`). Found by its CRC's bytes,
    so a buffer costs one search and a check per occurrence.
    """
    needle = crc.to_bytes(4, "little")
    at = buffer.find(needle)
    while at >= 0:
        for pos in (at - len(DATA_DESCRIPTOR_SIGNATURE), at):
            if pos < 0:
                continue
            descriptor = match_descriptor(
                buffer,
                pos,
                compressed_size=base + pos,
                crc=crc,
                file_size=file_size,
                zip64=zip64,
                at_end=at_end,
            )
            if descriptor is not None:
                return pos, descriptor
        at = buffer.find(needle, at + 1)
    return None


def _next_signature(buf: bytes | bytearray, at: int) -> int:
    """Where the next signature that may follow a descriptor starts, or -1."""
    while (at := buf.find(b"PK", at)) >= 0:
        if bytes(buf[at : at + 4]) in _AFTER_MEMBER:
            return at
        at += 1
    return -1


def _damaged_descriptor_in(
    buffer: bytes | bytearray,
    *,
    base: int,
    crc: int,
    file_size: int | None,
    zip64: bool,
    at_end: bool,
) -> tuple[int, DataDescriptor] | None:
    """The first descriptor in ``buffer`` that :func:`match_damaged_descriptor`
    takes, with its position; ``base`` is as for :func:`descriptor_by_crc`.

    Each descriptor ends at a ZIP signature (or the end of the input when
    ``at_end``), so the search goes from one signature to the next and tries each
    shape ending there, the earliest start first."""
    at = 0
    while True:
        after = _next_signature(buffer, at)
        if after < 0:
            if not at_end:
                return None
            after = len(buffer)
        for length in _DESCRIPTOR_LENGTHS:
            pos = after - length
            if pos < 0:
                continue
            descriptor = match_damaged_descriptor(
                buffer,
                pos,
                compressed_size=base + pos,
                crc=crc,
                file_size=file_size,
                zip64=zip64,
                at_end=at_end,
            )
            if descriptor is not None:
                return pos, descriptor
        if after >= len(buffer):
            return None
        at = after + 1


class MemberData(ReadOnlyIOStream):
    """One member's compressed bytes, read forward from the walk's stream.

    Read it as far as the caller needs, then call :meth:`settle` exactly once: it
    reads past what is left of the data and the data descriptor, and leaves the stream
    at the next header.
    """

    def __init__(self, walk: LocalHeaderWalk, entry: LocalEntry) -> None:
        super().__init__()
        self._walk = walk
        self._source = walk.source
        self.entry = entry
        #: Bytes handed out so far. For a codec member that is past its data: what
        #: its compressed size is, the descriptor ``settle`` returns says.
        self.consumed = 0
        #: The data's bytes after the last one handed out, which :meth:`settle` read
        #: to find the descriptor (a codec member's bytes between its codec's end and
        #: its descriptor); empty until then and on any other member.
        self.passed_over = b""
        self._settled = False
        self._ahead = _READ_AHEAD_FIRST

    @override
    def read(self, n: int = -1, /) -> bytes:
        if self._settled:
            raise ValueError("member data read after settle()")
        if n < 0:
            chunks = []
            while chunk := self._read_some(_READ_CHUNK):
                chunks.append(chunk)
            return b"".join(chunks)
        return self._read_some(n)

    def _read_some(self, size: int) -> bytes:
        raise NotImplementedError

    def _read_ahead(self, size: int) -> bytes:
        """Up to ``size`` bytes more from the stream, for data whose end is not known.

        What is read past the data's end is put back for the next header and read
        again, so the first read asks for :data:`_READ_AHEAD_FIRST` bytes and each
        one that got all it asked for doubles the next. A member then reads past its
        end by about its own length at most, not by a whole read size: many small
        bit-3 members cost about their own bytes, not a read size each.
        """
        want = min(size, self._ahead)
        data = self._source.read(want)
        if want == self._ahead and len(data) == want:
            self._ahead *= 2
        return data

    @property
    def found_descriptor(self) -> DataDescriptor | None:
        """The data descriptor, once a read has found the data's end before
        :meth:`settle`; ``None`` until then, and on a member whose end the walk does
        not find itself (its codec's, or its stated size)."""
        return None

    @property
    def read_end_record(self) -> bool:
        """Whether the archive's end record is among the last bytes handed out: a
        stream that ended after it was not cut. Only a codec member's data, which
        runs on to the stream's end, can hand it out."""
        return False

    def settle(
        self,
        used: int | None = None,
        *,
        crc: int | None = None,
        file_size: int | None = None,
    ) -> DataDescriptor | None:
        """Finish the member: skip its unread data, read its data descriptor.

        ``used`` is how many compressed bytes the codec consumed. On a member whose
        end the walk knows it is optional and checked against that end: a sized
        member refuses one past its stated size, a scanned one any other than its
        length. A member whose end only its codec knows (:class:`_CodecData`) needs
        ``used`` or ``crc``: with ``used`` its descriptor is read right there, and
        with ``crc`` alone it is searched for after the codec's end (see
        :meth:`_CodecData._find_descriptor`). ``crc`` and ``file_size``, when the
        caller has computed them, pick the descriptor among the shapes that fit, so
        only a codec member reads them: a sized member has no descriptor and a
        scanned one matched its own. A descriptor that disagrees with them is the
        caller's to judge. Returns ``None`` for a member with no descriptor.
        """
        if self._settled:
            raise ValueError("settle() called twice")
        self._settled = True
        try:
            descriptor = self._finish(used, crc=crc, file_size=file_size)
        except ArchiveyError as exc:
            # Where the data ends is unknown, so no next header can be found.
            self._walk._member_failed(exc)
            raise
        self._walk._member_settled()
        return descriptor

    def _finish(
        self, used: int | None, *, crc: int | None, file_size: int | None
    ) -> DataDescriptor | None:
        raise NotImplementedError

    def _check_used(self, used: int | None) -> None:
        """Refuse a ``used`` that is not where the walk found the data's end."""
        if used is not None and used != self.consumed:
            raise ValueError(
                f"settle(used={used}) on member #{self.entry.index}, whose data "
                f"is {self.consumed} bytes"
            )


class _SizedData(MemberData):
    """Data whose size the local header states."""

    def __init__(self, walk: LocalHeaderWalk, entry: LocalEntry) -> None:
        super().__init__(walk, entry)
        self._size = entry.header.compressed_size

    @override
    def _read_some(self, size: int) -> bytes:
        want = min(size, self._size - self.consumed)
        if want <= 0:
            return b""
        data = self._source.read(want)
        self.consumed += len(data)
        if len(data) < want:
            raise TruncatedError(
                f"ZIP stream ends inside member #{self.entry.index}'s data "
                f"({self.consumed} of {self._size} bytes)"
            )
        return data

    @override
    def _finish(
        self, used: int | None, *, crc: int | None, file_size: int | None
    ) -> DataDescriptor | None:
        left = self._size - self.consumed
        if left > 0:
            skipped = self._source.skip(left)
            self.consumed += skipped
            if skipped < left:
                raise TruncatedError(
                    f"ZIP stream ends inside member #{self.entry.index}'s data "
                    f"({self.consumed} of {self._size} bytes)"
                )
        # The codec may stop short of the stated size (padding after its end), but
        # never past it.
        if used is not None and used > self._size:
            raise ValueError(
                f"settle(used={used}) on member #{self.entry.index}, whose data "
                f"is {self._size} bytes"
            )
        return None


class _CodecData(MemberData):
    """Bit-3 data whose end only the codec finds.

    Hands out the stream as it comes, keeping the last :data:`_CODEC_RETAIN` bytes
    so the ones the caller's layers read past the codec's end can be put back. Only
    that many can be: an unsized read would run to the end of the archive, so it is
    refused, and the caller reads in pieces.
    """

    def __init__(self, walk: LocalHeaderWalk, entry: LocalEntry) -> None:
        super().__init__(walk, entry)
        self._kept: deque[bytes] = deque()
        self._kept_len = 0

    @override
    def read(self, n: int = -1, /) -> bytes:
        if n < 0:
            raise ValueError(
                "a codec member's data has no known end, and only the last "
                f"{_CODEC_RETAIN} bytes read can be put back; read it in pieces"
            )
        return super().read(n)

    @override
    def readall(self) -> bytes:
        return self.read(-1)

    @property
    @override
    def read_end_record(self) -> bool:
        return EOCD_SIGNATURE in b"".join(self._kept)

    @override
    def _read_some(self, size: int) -> bytes:
        data = self._read_ahead(size)
        if data:
            self.consumed += len(data)
            self._kept.append(data)
            self._kept_len += len(data)
            while self._kept and self._kept_len - len(self._kept[0]) >= _CODEC_RETAIN:
                self._kept_len -= len(self._kept.popleft())
        return data

    @override
    def _finish(
        self, used: int | None, *, crc: int | None, file_size: int | None
    ) -> DataDescriptor | None:
        if used is None:
            if crc is None:
                raise ValueError(
                    "settle() needs `used` or `crc` for a member its codec ends"
                )
            return self._find_descriptor(crc, file_size)
        excess = self.consumed - used
        if excess < 0:
            raise ValueError(
                f"settle(used={used}) after only {self.consumed} bytes were read"
            )
        if excess > self._kept_len:
            raise ValueError(
                f"{excess} bytes were read past the codec's end, more than the "
                f"{self._kept_len} kept to put back"
            )
        if excess:
            tail = b"".join(self._kept)[-excess:]
            self._source.unread(tail)
        self._kept.clear()
        self._kept_len = 0
        return self._walk._read_descriptor(
            self.entry, compressed_size=used, crc=crc, file_size=file_size
        )

    def _find_descriptor(self, crc: int, file_size: int | None) -> DataDescriptor:
        """Find the descriptor among the bytes kept, and put back what follows it.

        A codec stream stops after its end without saying how far past it it read:
        its decoder takes input in chunks, and some (Deflate64, PPMd) cannot say how
        much of the last one they used. The descriptor holds the CRC of the decoded
        data, so it is found where that CRC is, with a compressed size equal to its
        own position and a ZIP signature after it. A descriptor with one damaged
        field (a CRC that differs because the data is damaged, or a damaged byte in
        the descriptor) is found by the fields that still agree
        (:func:`match_damaged_descriptor`); the caller and the directory judge the
        field that differs.

        The descriptor dates the data's end from its own position, so bytes between the
        codec's end and the descriptor count into its compressed size: the check a sized
        member gets, that nothing follows the codec's end (DR-3), is not available here,
        and such a member reads from a pipe where it fails from a file. A crafted shape
        only, so DR-5a lets the two reads differ. The mirror shape differs the same way:
        a stream whose last bytes are the descriptor's first ones is cut short at the
        stated size from a file (``TruncatedError``), and here the descriptor is found
        inside the bytes the codec used. Refusing it needs every codec to say exactly
        where its input ended (Deflate64 and PPMd cannot), through the decrypt stages.
        As with the stored scan, a planted descriptor for a prefix ends the member
        early, and the walk reads on from inside its data; the central entry's size and
        CRC catch it at the end of the pass.
        """
        handed = self._kept_len  # where the bytes handed out end in ``buffer``
        base = self.consumed - handed
        # Built once and extended: the kept bytes are up to 4 MiB.
        buffer = bytearray().join(self._kept)
        self._kept.clear()
        self._kept_len = 0
        zip64 = self.entry.zip64

        def search(at_end: bool) -> tuple[int, DataDescriptor] | None:
            found = descriptor_by_crc(
                buffer,
                crc=crc,
                file_size=file_size,
                base=base,
                zip64=zip64,
                at_end=at_end,
            )
            if found is None:
                found = _damaged_descriptor_in(
                    buffer,
                    base=base,
                    crc=crc,
                    file_size=file_size,
                    zip64=zip64,
                    at_end=at_end,
                )
            return found

        # The descriptor is usually right after the codec's end, in the bytes kept and
        # the few after them. Junk between the two is searched to
        # :data:`_DESCRIPTOR_SEARCH_PAST` bytes past what was handed out, however
        # little the codec's last read took, before the search gives up.
        ahead = self._source.read(_DESCRIPTOR_LOOKAHEAD)
        at_end = len(ahead) < _DESCRIPTOR_LOOKAHEAD
        buffer += ahead
        found = search(at_end)
        if found is None and not at_end:
            more = self._source.read(_DESCRIPTOR_SEARCH_PAST - len(ahead))
            ahead += more
            at_end = len(ahead) < _DESCRIPTOR_SEARCH_PAST
            buffer += more
            found = search(at_end)
        if found is None:
            self._source.unread(ahead)
            index = self.entry.index
            # Read to the end of the stream with no end record in sight: the archive
            # was cut, whatever else went wrong.
            if at_end and EOCD_SIGNATURE not in buffer:
                raise TruncatedError(
                    f"ZIP stream ends before member #{index}'s data descriptor"
                )
            raise CorruptionError(
                f"no data descriptor after member #{index}'s data: none in the "
                f"last {len(buffer)} bytes read matches its size and decoded CRC "
                f"{crc:08x}"
            )
        pos, descriptor = found
        self.passed_over = bytes(buffer[handed:pos])
        self._source.unread(buffer[pos + descriptor.length :])
        return descriptor


class _ScannedData(MemberData):
    """Bit-3 data ended by a scan for its data descriptor, on the bytes as stored.

    A STORED member's, or, from :meth:`LocalHeaderWalk.scan_member_data`, a codec
    member's that is encrypted and nobody read, or whose read failed. ``check_crc`` is
    false when the descriptor's CRC covers bytes other than these (the plaintext, the
    decoded data): the scan then matches the compressed size and the signature after
    the descriptor only.
    """

    def __init__(
        self, walk: LocalHeaderWalk, entry: LocalEntry, *, check_crc: bool
    ) -> None:
        super().__init__(walk, entry)
        self._check_crc = check_crc
        self._buf = bytearray()
        self._crc = 0  # of the bytes handed out
        # The CRC of the data's first ``_scan_crc_end`` bytes, as ``_find_end`` last
        # computed it.
        self._scan_crc = 0
        self._scan_crc_end = 0
        self._eof = False
        #: Where the data ends in ``_buf``, once the descriptor is found.
        self._end_at: int | None = None
        self._descriptor: DataDescriptor | None = None
        # Where the next search for a signature after a descriptor starts in ``_buf``.
        self._search_from = 0
        # The bytes read from the stream most recently, for the end-of-stream verdict.
        self._tail = bytearray()

    def _pull(self) -> bool:
        data = self._read_ahead(_READ_CHUNK)
        if not data:
            self._eof = True
            return False
        self._buf += data
        self._tail += data
        if len(self._tail) > _TAIL_KEEP:
            del self._tail[: len(self._tail) - _TAIL_KEEP]
        return True

    def _find_end(self) -> None:
        """Look for the descriptor in what ``_buf`` holds; set ``_end_at`` on a match.

        A descriptor is followed by a ZIP signature (or the end of the stream), so
        the scan looks for those and tries each descriptor shape ending there:
        signed or not (APPNOTE 4.3.9.3 makes ``PK\\x07\\x08`` optional), 4- or
        8-byte sizes. A shape is taken when its compressed size is the length of the
        data before it, and its CRC that data's when ``check_crc``; then, when no
        shape ending at that signature matches whole, one with a single damaged field
        (:func:`match_damaged_descriptor`), so damaged data or a damaged descriptor
        fails the member alone instead of hiding where it ends. That fallback runs
        under ``check_crc`` only: without the CRC and the uncompressed size, the
        compressed size is the only field left to agree, and "one damaged field"
        would place a descriptor on a single 32-bit coincidence. Without the CRC,
        a false match in ciphertext takes a planted signature and size; in a damaged
        codec member's stored bytes it can also come by accident, a signature and a
        size that happen to fit. Either way the member ends early and the walk reads on
        from inside its data, and the directory entry's size and CRC catch it at the
        end of the pass.

        The CRC runs on from one candidate to the next, so a buffer full of planted
        signatures costs one pass, and it is computed only for a candidate whose
        compressed size (or, under ``check_crc``, uncompressed size) already fits.
        """
        buf = self._buf
        # The CRC of the data up to ``buf[crc_at]``, carried over from the last call
        # while those bytes are still in ``buf``: the scan runs over bytes pulled in
        # small steps, and starting it again at ``buf[0]`` each step would cost a pass
        # over the whole buffer per step. It stays behind every later candidate: a
        # call that runs out leaves ``_search_from`` at ``len(buf) - 3``, and a
        # signature needs four bytes, so its last ``earliest`` is behind the start of
        # the next call's first candidate.
        crc = self._crc  # of the bytes handed out, then buf[:crc_at]
        crc_at = 0
        if self._scan_crc_end > self.consumed:
            crc = self._scan_crc
            crc_at = self._scan_crc_end - self.consumed
        at = self._search_from
        try:
            while True:
                after = _next_signature(buf, at)
                if after < 0:
                    # A signature can still start in the last three bytes.
                    self._search_from = max(len(buf) - 3, 0)
                    if not self._eof:
                        return
                    after = len(buf)  # the stream ends after the descriptor
                # This candidate's shapes and every later one's start at or past here.
                earliest = after - _DESCRIPTOR_LONGEST
                fitting: list[tuple[int, int | None]] = []
                for length in _DESCRIPTOR_LENGTHS:
                    pos = after - length
                    if pos < 0:
                        continue
                    size = self.consumed + pos
                    if not self._size_fits(buf, pos, size, stored=self._check_crc):
                        continue
                    expect_crc = None
                    if self._check_crc:
                        if earliest > crc_at:
                            crc = zlib.crc32(buf[crc_at:earliest], crc)
                            crc_at = earliest
                        # An empty slice would give a longer prefix's CRC.
                        assert crc_at <= pos
                        expect_crc = zlib.crc32(buf[crc_at:pos], crc)
                    fitting.append((pos, expect_crc))
                for pos, expect_crc in fitting:
                    size = self.consumed + pos
                    descriptor = match_descriptor(
                        buf,
                        pos,
                        compressed_size=size,
                        crc=expect_crc,
                        # STORED: both sizes are the data's length, unless encryption
                        # added its header to the compressed one.
                        file_size=size if self._check_crc else None,
                        zip64=self.entry.zip64,
                        at_end=self._eof,
                    )
                    if descriptor is not None:
                        self._end_at = pos
                        self._descriptor = descriptor
                        return
                for pos, expect_crc in fitting if self._check_crc else ():
                    # No shape here matches whole: one damaged field (a byte of the data
                    # changes the CRC) still ends the member here, and the caller's CRC
                    # check fails it alone. Only under ``check_crc``: see the docstring.
                    size = self.consumed + pos
                    descriptor = match_damaged_descriptor(
                        buf,
                        pos,
                        compressed_size=size,
                        crc=expect_crc,
                        file_size=size,
                        zip64=self.entry.zip64,
                        at_end=self._eof,
                    )
                    if descriptor is not None:
                        self._end_at = pos
                        self._descriptor = descriptor
                        return
                if after >= len(buf):
                    return
                at = after + 1
        finally:
            self._scan_crc = crc
            self._scan_crc_end = self.consumed + crc_at

    @property
    @override
    def found_descriptor(self) -> DataDescriptor | None:
        return self._descriptor

    @staticmethod
    def _size_fits(buf: bytearray, pos: int, length: int, *, stored: bool) -> bool:
        """A descriptor at ``pos`` could state ``length``: the cheap test that comes
        before a CRC, and the scan's cost per candidate on signature-dense data.

        Each shape fixes the offset and width of its two sizes, so this probes
        those, the compressed sizes first (all a scan without ``stored`` needs):
        without a signature, then with one or one damaged. For unencrypted STORED
        data (``stored``) the uncompressed size is the same length, so a descriptor
        whose compressed size is the damaged field is still a candidate: then the
        uncompressed sizes without a signature, and with one when it is there (a
        damaged one needs all three fields, so its compressed size fits). At most
        eight probes.
        """
        signed = buf[pos : pos + 4] == DATA_DESCRIPTOR_SIGNATURE
        if stored:
            probes = _STORED_PROBES_SIGNED if signed else _STORED_PROBES
        else:
            probes = _ENCRYPTED_PROBES_SIGNED if signed else _ENCRYPTED_PROBES
        as4 = (length & _U32_MAX).to_bytes(4, "little")
        as8 = (length & _U64_MAX).to_bytes(8, "little")
        for offset, width in probes:
            at = pos + offset
            if buf[at : at + width] == (as4 if width == 4 else as8):
                return True
        return False

    def _avail(self) -> int:
        """How many bytes of ``_buf`` can be handed out before the end is found: no
        descriptor starts in them, since the signature after it would be in."""
        return max(len(self._buf) - _DESCRIPTOR_LOOKAHEAD + 1, 0)

    @override
    def _read_some(self, size: int) -> bytes:
        while True:
            if self._end_at is None:
                self._find_end()
            if self._end_at is not None:
                avail = self._end_at
            elif self._eof:
                self._raise_no_descriptor()
            else:
                avail = self._avail()
            # ``size`` bytes, or fewer only at the data's end: for a STORED member this
            # is the caller's stream, whose short read means the end (ADR 0014), and
            # the steps it is pulled in are small.
            if avail >= size or self._end_at is not None:
                take = min(size, avail)
                out = bytes(self._buf[:take])
                del self._buf[:take]
                self._crc = zlib.crc32(out, self._crc)
                self.consumed += take
                self._search_from = max(self._search_from - take, 0)
                if self._end_at is not None:
                    self._end_at -= take
                return out
            self._pull()

    def _raise_no_descriptor(self) -> NoReturn:
        name = f"member #{self.entry.index}"
        if EOCD_SIGNATURE in self._tail:
            raise UnsupportedFeatureError(
                f"ZIP {name} defers its sizes to a data descriptor, and none matches "
                "its data with a ZIP signature after it, so a forward read cannot "
                "find where its data ends; read the archive from a seekable source"
            )
        raise TruncatedError(
            f"ZIP stream ends inside {name}'s data, before its data descriptor"
        )

    @override
    def _finish(
        self, used: int | None, *, crc: int | None, file_size: int | None
    ) -> DataDescriptor | None:
        while self._read_some(_READ_CHUNK):
            pass
        descriptor = self._descriptor
        assert descriptor is not None
        rest = self._buf[descriptor.length :]
        self._source.unread(rest)
        self._buf.clear()
        self._check_used(used)
        return descriptor


class LocalHeaderWalk:
    """Read a ZIP forward: local entries, their data, then the directory.

    ``stream`` is only read. ``offset`` is its position in the archive file, so the
    entry offsets compare with the directory's. ``find_start`` scans for the first
    local header when the stream starts with no ZIP record :meth:`next_entry`
    handles (a self-extractor stub nobody skipped), within :data:`~archivey.internal.sfx.SFX_MAX`
    bytes, with the detector's local-header validator. ``index`` is the number of
    the first local entry, for a walk started part way through the members.
    """

    def __init__(
        self,
        stream: BinaryIO,
        *,
        offset: int = 0,
        find_start: bool = True,
        index: int = 0,
    ) -> None:
        self.source = ForwardSource(stream, offset=offset)
        self._find_start = find_start
        self._started = False
        self._index = index
        # The entry :meth:`next_entry` returned last, until its data is settled.
        self._unsettled: LocalEntry | None = None
        #: What a member's ``settle`` raised: the walk cannot go past that member.
        self._failure: ArchiveyError | None = None
        self._open: MemberData | None = None
        #: Stream offset of the first local header, once found.
        self.first_offset: int | None = None

    # -- members -------------------------------------------------------------

    def next_entry(self) -> LocalEntry | None:
        """The next local entry, or ``None`` once something other than a local header
        follows: the directory, the end records, or bytes :meth:`read_rest` reads.

        The previous member's data must have been settled; if its ``settle`` raised,
        this raises the same error, as the next header cannot be found. Raises
        ``TruncatedError``
        when the stream ends where a header should be, ``CorruptionError`` for bytes
        that are no ZIP structure and lead to no directory.
        """
        if self._failure is not None:
            raise self._failure
        if self._unsettled is not None:
            raise ValueError("settle the previous member's data first")
        if not self._started:
            self._started = True
            self._start()
        sig = self.source.peek(4)
        if sig == LOCAL_HEADER_SIGNATURE:
            entry = self._read_local_header()
            if self.first_offset is None:
                self.first_offset = entry.offset
            self._unsettled = entry
            return entry
        if not sig:
            raise TruncatedError(
                f"ZIP stream ends after {self._index} members, before the central "
                "directory"
            )
        if len(sig) < 4:
            raise TruncatedError(
                f"ZIP stream ends {len(sig)} bytes {self.where()}, before the "
                "central directory"
            )
        # The directory, the end records, or bytes that are neither: what follows
        # the members is read whole by ``read_rest`` and parsed as a file's is.
        return None

    def where(self) -> str:
        """Where the walk is, for a message: after which member, if any."""
        if self._index == 0:
            return "before the first local header"
        return f"after member #{self._index - 1}"

    def _start(self) -> None:
        # Anything next_entry knows how to handle opens the stream: a local header, the
        # directory or end records of an archive whose members are gone, or the Strong
        # Encryption record it names. Only other bytes are a stub to scan past.
        sig = self.source.peek(4)
        if sig in _OPENS_STREAM or not self._find_start:
            return
        window = self._scan_for_local_header()
        if window is None:
            return
        # No local header, but the stream ends within the window and an end
        # record's signature lies where the end record of an archive ending it
        # would: in the last ``EOCD_SIZE`` bytes plus the longest comment. That is
        # an empty archive, or one whose members are gone, behind a stub; the stub
        # and the archive are read whole by ``read_rest``, as a file read finds the
        # end record behind the stub. A stub that runs past the window keeps the
        # error below, whatever signatures it holds.
        if (
            not self.source.peek(1)
            and window.rfind(EOCD_SIGNATURE, max(len(window) - EOCD_SIZE - _U16_MAX, 0))
            >= 0
        ):
            self.source.unread(window)
            return
        raise CorruptionError(
            f"no ZIP local header at the start of the stream or within its first "
            f"{SFX_MAX} bytes"
        )

    def _scan_for_local_header(self) -> bytearray | None:
        """Move to the first local header the detector's validator accepts, and
        return ``None``; with none in the window, return the bytes read.

        A candidate counts only when its signature lies wholly inside the first
        :data:`SFX_MAX` bytes, as ``sfx.scan_for_magic`` requires; one near the end
        is judged on its whole header, so up to :data:`VALIDATOR_PEEK_MAX` more are
        read. This is not ``scan_for_magic`` itself because the walk needs every
        byte it read back, to put the ones after the header found in front of the
        stream, and ``scan_for_magic`` does not hand them back.
        Every byte read is kept, so the ones after the header found can be put back.
        Rejected candidates are not capped, as for
        the seekable ZIP read (``sfx.MAX_VALIDATED_CANDIDATES`` covers RAR and 7z):
        the window bounds the work, and the validator reads only the header.
        """
        window = bytearray()
        searched = 0
        while True:
            pos = window.find(LOCAL_HEADER_SIGNATURE, searched, SFX_MAX)
            if pos >= 0:

                def peek_more(n: int, _pos: int = pos) -> bytes:
                    while (
                        len(window) < _pos + n
                        and len(window) < SFX_MAX + VALIDATOR_PEEK_MAX
                    ):
                        more = self.source.read(_READ_CHUNK)
                        if not more:
                            break
                        window.extend(more)
                    return bytes(window[_pos : _pos + n])

                if validate_zip_local_header(peek_more, None) is HitOutcome.VALID:
                    self.source.unread(window[pos:])
                    return None
                searched = pos + 1
                continue
            searched = max(len(window) - len(LOCAL_HEADER_SIGNATURE) + 1, 0)
            if len(window) >= SFX_MAX:
                return window
            more = self.source.read(min(_READ_CHUNK, SFX_MAX - len(window)))
            if not more:
                return window
            window.extend(more)

    def _read_local_header(self) -> LocalEntry:
        offset = self.source.offset
        fixed = self.source.read(LOCAL_HEADER_SIZE)
        if len(fixed) != LOCAL_HEADER_SIZE:
            raise TruncatedError(f"ZIP stream ends inside local header #{self._index}")
        variable_len = local_header_variable_length(fixed)
        variable = self.source.read(variable_len)
        if len(variable) != variable_len:
            raise TruncatedError(f"ZIP stream ends inside local header #{self._index}")
        header = local_header_from(
            fixed, variable, self.source.offset, zip64_sizes=True
        )
        entry = LocalEntry(
            index=self._index,
            offset=offset,
            header=header,
            zip64=_has_zip64_extra(header.extra),
        )
        if not entry.deferred:
            # Whether a field supplied each size, not its value: a field can hold all
            # ones as a real size. With no other source of sizes, a deferral no field
            # holds is refused rather than read as a size of 4 GiB.
            compressed, uncompressed = local_zip64_sizes(
                header.extra, *local_stored_sizes(fixed)
            )
            if compressed is None or uncompressed is None:
                which = "compressed" if compressed is None else "uncompressed"
                raise CorruptionError(
                    f"ZIP local header #{self._index} defers its {which} size to "
                    "a ZIP64 extra field that does not hold it"
                )
        self._index += 1
        return entry

    def member_data(
        self, entry: LocalEntry, *, encrypted: bool = False, stored: bool | None = None
    ) -> MemberData:
        """The reader for ``entry``'s compressed data (for an encrypted member, its
        ciphertext, encryption header included).

        ``stored`` says whether the data is STORED when the header's method does not
        (WinZip AES names the real method in an extra field); by default it is the
        header's. Must be called once for each entry :meth:`next_entry` returns, and
        settled before the next one.
        """
        if entry is not self._unsettled or self._open is not None:
            raise ValueError(
                "member_data() is for the entry next_entry() returned last"
            )
        if stored is None:
            stored = entry.header.method == _METHOD_STORED
        data: MemberData
        if not entry.deferred:
            data = _SizedData(self, entry)
        elif stored:
            data = _ScannedData(self, entry, check_crc=not encrypted)
        else:
            data = _CodecData(self, entry)
        self._open = data
        return data

    def skip_member(self, entry: LocalEntry) -> DataDescriptor | None:
        """Move past ``entry``'s data and data descriptor without decoding it: a bit-3
        codec member's end is found by the descriptor scan
        (:meth:`scan_member_data`), as for one nobody read. Returns the data
        descriptor of a bit-3 member, ``None`` for any other."""
        encrypted = bool(entry.header.flags & _FLAG_ENCRYPTED)
        data = self.member_data(entry, encrypted=encrypted)
        if isinstance(data, _CodecData):
            data = self.scan_member_data(data)
        return data.settle()

    def scan_starts_at_data_start(self, data: MemberData) -> bool:
        """Whether :meth:`scan_member_data` would start its scan of ``data`` at the
        data's start: every byte read from it so far is still kept."""
        return (
            data is self._open
            and isinstance(data, _CodecData)
            and data.consumed <= data._kept_len
        )

    def scan_member_data(self, data: MemberData) -> MemberData:
        """``data``'s member read as scanned data instead: its end found by a scan for
        its descriptor on its bytes as stored, not by its codec.

        For an encrypted bit-3 codec member nobody read, or any bit-3 codec member
        whose read failed, so the walk goes past it without decoding it. The bytes
        still kept of what a read took (the last :data:`_CODEC_RETAIN`) are put back
        and the ones before them counted, so the scan starts where the kept bytes
        do: at the data's start when :meth:`scan_starts_at_data_start`. A descriptor
        before that point is not found, which takes a codec that read more than
        :data:`_CODEC_RETAIN` past its data's end: the scan then runs to the end of
        the stream and raises. ``data`` is done with, and the returned reader is the
        one to read and settle.
        """
        if not isinstance(data, _CodecData) or data is not self._open:
            raise ValueError("scan_member_data() is for the open codec member's data")
        kept = min(data.consumed, data._kept_len)
        if kept:
            self.source.unread(b"".join(data._kept)[-kept:])
        data._settled = True
        scanned = _ScannedData(self, data.entry, check_crc=False)
        # The bytes before the kept ones count into the compressed size.
        scanned.consumed = data.consumed - kept
        self._open = scanned
        return scanned

    def _member_settled(self) -> None:
        self._open = None
        self._unsettled = None

    def _member_failed(self, exc: ArchiveyError) -> None:
        self._member_settled()
        self._failure = exc

    def _read_descriptor(
        self,
        entry: LocalEntry,
        *,
        compressed_size: int,
        crc: int | None,
        file_size: int | None,
    ) -> DataDescriptor:
        buffer = self.source.read(_DESCRIPTOR_LOOKAHEAD)
        at_end = len(buffer) < _DESCRIPTOR_LOOKAHEAD
        descriptor = match_descriptor(
            buffer,
            0,
            compressed_size=compressed_size,
            crc=crc,
            file_size=file_size,
            zip64=entry.zip64,
            at_end=at_end,
        )
        if descriptor is None and (crc is not None or file_size is not None):
            # The structure is there but the values disagree with the decoded data:
            # the caller judges that, so find the descriptor by its size alone.
            descriptor = match_descriptor(
                buffer,
                0,
                compressed_size=compressed_size,
                crc=None,
                file_size=None,
                zip64=entry.zip64,
                at_end=at_end,
            )
        if descriptor is None:
            self.source.unread(buffer)
            if at_end:
                raise TruncatedError(
                    f"ZIP stream ends before member #{entry.index}'s data descriptor"
                )
            raise CorruptionError(
                f"no data descriptor after member #{entry.index}'s data "
                f"({compressed_size} bytes)"
            )
        self.source.unread(buffer[descriptor.length :])
        return descriptor

    # -- after the members ----------------------------------------------------

    def read_rest(self, keep: int | None) -> ForwardTail:
        """Read the stream to its end once :meth:`next_entry` has returned ``None``.

        What follows the members (bytes before the directory, the directory, the end
        records, the comment and anything after it) is kept, so the caller parses it
        with the seekable read's own code (``find_end_record``,
        ``CentralDirectoryWalk``) and lists what that read lists, except where
        :meth:`ForwardTail.end_record` refuses a record in bytes not kept. ``keep``
        bounds what is held: past it the last ``keep`` bytes stay, where the end
        records of an archive that ends the stream are, and, when a directory or end
        record follows the members right away, the first ``keep`` too, where those
        are when other bytes follow the archive; ``None`` keeps everything. While the
        stream is read the chunks held come to at most twice ``keep`` plus one chunk;
        joining them at the end holds them and their copy for that moment.
        """
        if self._unsettled is not None:
            raise ValueError("settle the previous member's data first")
        members_end = self.source.offset
        head = bytearray()
        # At least the first four bytes, whatever ``keep`` is.
        head_cap = None if keep is None else max(keep, 4)
        chunks: deque[bytes] = deque()
        held = 0
        dropped = 0
        while chunk := self.source.read(_READ_CHUNK):
            if head_cap is not None and len(head) < head_cap:
                head += chunk[: head_cap - len(head)]
                # Past the first four bytes, the head is kept only for a directory or
                # end record right after the members, the one place the end record is
                # stepped to from: other bytes there cost a long stream nothing more.
                # The four stay for ``ForwardTail.end_record``'s message, so they
                # are held whenever any byte after them was dropped.
                if len(head) >= 4 and bytes(head[:4]) not in _STEPPED_OVER:
                    head_cap = 4
                    del head[4:]
            chunks.append(chunk)
            held += len(chunk)
            # A whole chunk goes once the ones after it hold ``keep`` bytes.
            while (
                keep is not None and len(chunks) > 1 and held - len(chunks[0]) >= keep
            ):
                gone = len(chunks.popleft())
                held -= gone
                dropped += gone
        if keep is not None and held > keep:
            cut = held - keep
            chunks[0] = chunks[0][cut:]
            dropped += cut
        data = b"".join(chunks)
        chunks.clear()
        return ForwardTail(
            after=self.where(),
            members_start=(
                members_end if self.first_offset is None else self.first_offset
            ),
            members_end=members_end,
            start=members_end + dropped,
            data=data,
            # Only needed when the tail does not reach back to the members.
            head=bytes(head) if dropped else b"",
        )


def missing_end_record_error(
    read_at: ReadAt,
    members_end: int,
    after: str,
    stopped: int,
    *,
    whole: bool,
    file_size: int,
) -> ArchiveyError | None:
    """Why no end record follows the members, from the first four bytes after them
    (at stream offset ``members_end``, ``after`` the walk's last member) and those
    where the step over the directory stopped (``stopped``, ``step_over_directory``).

    The stream ends inside the directory (only when ``whole``: every byte after the
    members was seen), a ZIP64 end record declares a size the stream does not hold,
    bytes that are no ZIP record follow the directory, the directory is encrypted,
    or no ZIP structure follows the members at all. ``None`` for bytes that start an
    end record: the end records' own fault, in the parser's words.
    """
    head = read_at(members_end, 4)
    if head == CENTRAL_HEADER_SIGNATURE:
        rest = read_at(stopped, 4)
        if rest == ZIP64_EOCD_SIGNATURE:
            header = read_at(stopped, 12)
            if len(header) == 12:
                declared = struct.unpack_from("<Q", header, 4)[0]
                # ``step_over_directory`` stops on this same bound. Twelve bytes were
                # read, so the stream holds at least those.
                room = file_size - stopped - 12
                assert room >= 0
                if declared > room:
                    return TruncatedError(
                        "ZIP64 end of central directory record at stream offset "
                        f"{stopped} declares {declared} bytes after its first twelve, "
                        "and the stream ends inside that record"
                    )
        if len(rest) == 4 and rest not in _STEPPED_OVER:
            return CorruptionError(
                f"bytes at stream offset {stopped} after the central directory are "
                "not a ZIP record, and no end of central directory record follows "
                "them"
            )
        if whole:
            return TruncatedError(
                "ZIP stream ends inside the central directory, before the end of "
                "central directory record"
            )
    if head == ARCHIVE_EXTRA_DATA_SIGNATURE:
        return UnsupportedFeatureError(STRONG_ENCRYPTED_DIRECTORY_MSG)
    if head not in _DIRECTORY_STARTS:
        return CorruptionError(
            f"bytes at stream offset {members_end} {after} are not a ZIP header, and "
            "no end of central directory record follows them"
        )
    return None


def local_entry_at(read_at: ReadAt, index: int, offset: int) -> LocalEntry:
    """The local entry at stream ``offset`` as the walk reads it, sizes from a ZIP64
    extra field included: for a file read listing the members a walk found."""
    header = read_local_header(read_at, offset, zip64_sizes=True)
    return LocalEntry(
        index=index,
        offset=offset,
        header=header,
        zip64=_has_zip64_extra(header.extra),
    )


class _HeldBytes(ReadOnlyIOStream):
    """Bytes already in memory, read once from the front without a copy of the
    whole (:meth:`ForwardTail.held_from`)."""

    def __init__(self, *parts: memoryview) -> None:
        super().__init__()
        self._parts = deque(part for part in parts if part)

    @override
    def read(self, n: int = -1, /) -> bytes:
        out = bytearray()
        while self._parts and (n < 0 or len(out) < n):
            part = self._parts[0]
            take = len(part) if n < 0 else min(len(part), n - len(out))
            out += part[:take]
            if take == len(part):
                self._parts.popleft()
            else:
                self._parts[0] = part[take:]
        return bytes(out)


@dataclass(frozen=True, slots=True)
class ForwardTail:
    """The bytes after a forward walk's last member, up to the end of the stream:
    all of them, or the first and the last ones."""

    #: Where the members ended, for a message: "after member #n" or "before the
    #: first local header".
    after: str
    #: Stream offset of the first local header (``members_end`` with none): how
    #: much data was prepended to the archive at most.
    members_start: int
    #: Stream offset where the members ended: the walk read no header after it.
    members_end: int
    #: Stream offset of ``data[0]``; past ``members_end`` when the bound dropped some.
    start: int
    data: bytes
    #: The bytes from ``members_end`` when the bound dropped some; empty otherwise.
    head: bytes = b""

    @property
    def dropped(self) -> int:
        """Bytes after the members that the tail does not start with: those the head
        holds and those the bound dropped."""
        return self.start - self.members_end

    @property
    def size(self) -> int:
        """The stream's length: the offset of its end."""
        return self.start + len(self.data)

    def holds(self, offset: int, n: int) -> bool:
        """Whether the ``n`` bytes at stream ``offset``, cut at the end of the stream,
        are all kept."""
        if offset < self.members_end:
            return False
        head_end = self.members_end + len(self.head)
        if offset >= self.start or head_end >= self.start:
            return True
        return min(offset + n, self.size) <= head_end

    def read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes at stream ``offset``, as a file read would read them.

        Bytes not kept (before the members' end, or between the head and the tail)
        read as zeros, which hold no ZIP record: the end-record search's window may
        reach back past the members' end, and a ZIP64 locator may name an offset there
        (a stub stdlib's check moves past). :meth:`end_record` refuses a directory that
        starts there."""
        if offset >= self.start:
            at = offset - self.start
            return self.data[at : at + n]
        end = min(offset + n, self.size)
        if offset >= end:
            return b""
        out = bytearray(end - offset)
        for at, kept in ((self.members_end, self.head), (self.start, self.data)):
            lo, hi = max(offset, at), min(end, at + len(kept))
            if lo < hi:
                out[lo - offset : hi - offset] = kept[lo - at : hi - at]
        return bytes(out)

    def held_from(self, offset: int) -> BinaryIO | None:
        """The bytes from stream ``offset`` to the end of the stream, read forward,
        or ``None`` when this tail does not hold all of them.

        For a local entry the directory places after the members (bytes between two
        members ended the walk, or a second archive follows the first): a walk
        started here reads it as the walk reads any other. Bytes before the
        members' end were passed, and the bound may have dropped some after it.
        """
        if offset < self.members_end or offset > self.size:
            return None
        view = memoryview(self.data)
        if offset >= self.start:
            return _HeldBytes(view[offset - self.start :])
        head_end = self.members_end + len(self.head)
        if offset >= head_end or head_end < self.start:
            return None
        return _HeldBytes(
            memoryview(self.head)[offset - self.members_end :],
            view[head_end - self.start :],
        )

    def end_record(self) -> EndRecord:
        """The end record the seekable read would use.

        ``find_end_record`` runs over :meth:`read_at`, so it picks the record a file
        read picks, decoy signatures in the comment included. A record that places
        a non-empty directory among the members' data, which the walk has read past,
        is refused, and so is a ZIP64 end record there, unless the classic record
        needs none of its fields and stands in for it as it does for a file read
        that finds the ZIP64 record damaged. Either one in bytes the bound dropped is
        a ``ResourceLimitError``, with no stand-in: higher listing limits keep those
        bytes, and the pass then reads the record a file read reads.

        Behind more bytes than the search window, the end record is stepped to from
        the directory right after the members while the step stays in the kept
        bytes; a step that runs past them is a ``ResourceLimitError``. A missing end
        record is described by :func:`missing_end_record_error`, as a file read
        describes it. Every other fault is ``find_end_record``'s, in the file read's
        words.
        """
        found = locate_classic_record(self.read_at, self.size)
        if found is None:
            # Behind more bytes than the search window: step over the directory
            # after the members, as the file read does after its own walk.
            found, stopped = step_over_directory(
                self.read_at, self.size, self.members_end
            )
            if found is None and not self.holds(stopped, 4):
                # The step left the bytes this tail holds: a file read would read
                # on there.
                raise ResourceLimitError(
                    "ZIP directory and end records run past the "
                    f"{len(self.head)} bytes after the members that a forward read "
                    "holds within the listing limits"
                )
            if found is None:
                # No end record at all. The head or the tail holds the first four
                # bytes after the members. With bytes dropped after a directory,
                # whatever follows it is unknown.
                error = missing_end_record_error(
                    self.read_at,
                    self.members_end,
                    self.after,
                    stopped,
                    whole=not self.dropped,
                    file_size=self.size,
                )
                if error is not None:
                    raise error
        unseen = None
        if found is not None:
            unseen = self._unseen_zip64_record(found[0])
            if unseen is not None and (
                unseen >= self.members_end or classic_record_saturated(found[1])
            ):
                self._refuse_unseen(_ZIP64_RECORD, unseen)
        # Any other failure is the record's own, in the file read's words.
        try:
            end = find_end_record(
                self.read_at, self.size, members_end=lambda: self.members_end
            )
        except CorruptionError:
            if unseen is not None:
                self._refuse_unseen(_ZIP64_RECORD, unseen)
            raise
        if unseen is not None:
            if end.zip64_damage is None:
                # A record right before the locator: the file read takes the one
                # the locator names, which this tail did not see.
                self._refuse_unseen(_ZIP64_RECORD, unseen)
            # The classic record stands in for a ZIP64 record among the members'
            # data, which a file read finds missing or not matching the locator
            # unless crafted member data holds one that matches.
            end = replace(end, zip64_damage=self._unseen_message(_ZIP64_RECORD, unseen))
        if end.cd_size and not self.holds(end.cd_start, end.cd_size):
            self._refuse_unseen("ZIP central directory", end.cd_start)
        return end

    def _unseen_zip64_record(self, eocd_offset: int) -> int | None:
        """Where a ZIP64 locator names a record in bytes this tail does not hold, or
        ``None``.

        ``find_end_record`` reads the record at the locator's offset, and falls back
        to one right before the locator when that offset holds none (data prepended
        to the archive moved it). The unkept bytes at the locator's offset decide
        that, so here the fallback is taken only for a record right before the
        locator that passes the parser's own checks (``zip64_record_matches``) and
        whose shift, from where the locator places it, fits before the first local
        header: no more than the data a stub could have prepended. A file read not
        told where the archive starts (``format=`` skips the detection that slices
        the stub off) would instead read a record the locator names in unkept bytes
        within that shift; that takes a stub longer than the tail keeps. Otherwise the
        record the locator names is unseen, not missing. A split set is refused as
        from a file (``read_zip64_locator``); a corrupt locator is left to
        ``find_end_record``, which reads past it when the classic record needs
        none of the ZIP64 fields."""
        try:
            located = read_zip64_locator(self.read_at, eocd_offset)
        except CorruptionError:
            return None
        if located is None:
            return None
        locator_at, record_at = located
        if self.holds(record_at, ZIP64_EOCD_SIZE):
            return None
        adjacent = locator_at - ZIP64_EOCD_SIZE
        if (
            self.holds(adjacent, ZIP64_EOCD_SIZE)
            and adjacent - record_at <= self.members_start
            and zip64_record_matches(
                self.read_at(adjacent, ZIP64_EOCD_SIZE), record_at, 0
            )
        ):
            return None
        return record_at

    def _refuse_unseen(self, what: str, offset: int) -> NoReturn:
        """Refuse ``what``, which an end record places at stream ``offset``, outside
        the bytes this tail holds: among the members' data, which the walk read past,
        or in bytes the bound dropped (``ResourceLimitError``)."""
        message = self._unseen_message(what, offset)
        if offset >= self.members_end:
            raise ResourceLimitError(message)
        raise CorruptionError(message)

    def _unseen_message(self, what: str, offset: int) -> str:
        """Why ``what`` at stream ``offset`` is outside the bytes this tail holds."""
        if offset >= self.members_end:
            return (
                f"{what} starts {offset - self.members_end} bytes after the members "
                f"and {self.size - offset} before the end of the stream, further from "
                "both than a forward read holds within the listing limits"
            )
        return (
            f"ZIP end records place the {what} at stream offset {offset}, inside the "
            "members' data, which a read from a source that cannot seek has passed"
        )


__all__ = [
    "DATA_DESCRIPTOR_SIGNATURE",
    "DataDescriptor",
    "ForwardSource",
    "ForwardTail",
    "LocalEntry",
    "LocalHeaderWalk",
    "MemberData",
    "local_entry_at",
    "match_descriptor",
    "missing_end_record_error",
]
