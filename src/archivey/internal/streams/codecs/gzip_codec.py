"""gzip: the codec, and the checks it adds around rapidgzip (the ISIZE truncation
backstop, the first header's CRC, the multi-member probe).
"""

from __future__ import annotations

import contextlib
import gzip
import io
import zlib
from collections.abc import Callable
from dataclasses import replace
from typing import BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    exception_detail,
)
from archivey.internal.config import StreamConfig
from archivey.internal.hashing import crc32_combine
from archivey.internal.streams.codecs.base import (
    GZIP_MAGIC,
    GZIP_WBITS,
    Codec,
    CodecParams,
    CodecSource,
    MetadataContext,
    _peeking,
    _source_tail,
)
from archivey.internal.streams.codecs.deflate_decoder import GzipDecompressorStream
from archivey.internal.streams.codecs.deflate_family_codec import _DeflateFamilyCodec
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives, natives_for
from archivey.internal.streams.codecs.stdlib_takeover import (
    _DRAIN_CHUNK,
    _drain_into,
    _seek_reached_end,
    _SourceViews,
    _StdlibOnAcceleratorError,
)
from archivey.internal.streams.decompressor_stream import gzip_error, release_decoder
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import DelegatingStream
from archivey.internal.timestamps import unix32_to_datetime
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    MagicSignature,
    StreamFormat,
)


def _gzip_isize_and_length(source: CodecSource) -> tuple[int | None, int | None]:
    """Capture ``(source_byte_length, ISIZE_trailer)`` for the truncation backstop in one pass.

    Preserves the **tri-state** the path-reopen backstop relied on, which a bare ``int | None``
    would collapse:

    - ``(length, isize)`` — a readable seekable source ≥ 18 bytes: compare ``isize``.
    - ``(length, None)`` with ``length < 18`` — too short for a complete gzip member: the
      backstop must **raise** on a non-empty soft EOF (an incomplete member).
    - ``(None, None)`` — non-seekable / unreadable: the backstop cannot verify, so it must
      **return** without raising (never invent a truncation it cannot prove).

    ISIZE is uncompressed size mod 2**32 and covers only the *last* member of a multi-member
    file; callers needing a hard bound still prefer a container-declared size. Restores the
    source position for a caller-owned stream.
    """
    length, trailer = _source_tail(source, size=4, min_length=18)
    if trailer is None:
        return length, None
    return length, int.from_bytes(trailer, "little")


def _gzip_header_refused(source: CodecSource, natives: Natives = IN_PROCESS) -> bool:
    """Whether zlib refuses the first gzip member's header, which rapidgzip accepts.

    rapidgzip 0.16 ignores a header CRC (FHCRC) that does not match and the reserved
    FLG bits that RFC 1952 says must make a decoder fail; zlib's gzip window, which
    the standard-library path uses, raises "header crc mismatch" and "unknown header
    flags set". The header is fed to zlib until the first byte of output, the end of
    the member, or an error. Any error counts, so a first member that zlib cannot
    start is left to the engine whose verdict the accelerator must keep. Restores the
    source position for a caller-owned stream. Only the first member's header is
    checked: the accelerator does not say where later members start.
    """

    def refused(view: BinaryIO) -> bool:
        decoder = natives.zlib_decompressobj(GZIP_WBITS)
        try:
            while chunk := view.read(1 << 16):
                try:
                    if decoder.decompress(chunk, 1) or decoder.eof:
                        return False
                except zlib.error:
                    return True
            return False
        finally:
            release_decoder(decoder)

    with _peeking(source) as f:
        f.seek(0)
        return refused(f)


def _gzip_isize_from_source(source: CodecSource) -> int | None:
    """The gzip ISIZE trailer when cheaply readable, else ``None`` (see the tri-state helper)."""
    return _gzip_isize_and_length(source)[1]


def _config_with_gzip_isize(source: CodecSource, config: StreamConfig) -> StreamConfig:
    """Mark gzip ISIZE as available for AUTO / the ISIZE truncation backstop.

    Does **not** set ``expected_decompressed_size`` from ISIZE: that field is an exact
    bound for ``VerifyingStream``, but ISIZE is mod 2**32 and multi-member gzip's
    trailer covers only the last member.
    """
    if config.gzip_isize_backstop or config.expected_decompressed_size is not None:
        return config
    if _gzip_isize_from_source(source) is None:
        return config
    return replace(config, gzip_isize_backstop=True)


def _stdlib_gzip(source: CodecSource, config: StreamConfig) -> BinaryIO:
    return GzipDecompressorStream(
        source,
        collector=config.collector,
        report_trailing_data=config.report_trailing_data,
        natives=natives_for(config.process_isolation),
        index=config.seekable,
    )


# How far before the earliest place a gzip trailer could start the backstop still looks
# for the output's CRC-32 (``_GzipTruncationCheckStream._member_ends_the_file``). The
# numbers stated for that lookup follow from it: with ``end`` the end of the non-zero data,
# the range is ``[end - 8 - 64, end + 12)``, so "72 bytes before" the end; a copy more than
# 64 - 8 = 56 bytes past the end of the real trailer is not excluded; and the first read is
# the last 64 + 32 = 96 bytes, which hold the range when padding is 24 bytes or fewer. The
# docstring, ``dev-docs/formats/gzip.md`` §2.3 and §5, and the ``compressed-streams`` and
# ``seekable-decompressor-streams`` specs state these numbers; change them together.
_TRAILER_LOOKBACK = 64
# How far before the end of the non-zero data the backstop looks for the header of an
# empty last member (``_GzipTruncationCheckStream._empty_member_ends_the_data``). bgzip's
# end-of-file member is 28 bytes; an empty member whose header fields take more goes to
# the standard library, which finds nothing wrong at the cost of a second decode.
# ``dev-docs/formats/gzip.md`` §2.3 and the ``compressed-streams`` and
# ``seekable-decompressor-streams`` specs state it; change them together.
_EMPTY_MEMBER_REACH = 1 << 10
# How far apart the backstop saves the running CRC-32 of the output
# (``_CheckpointedCrc``), and so the most output it reads back from rapidgzip to check one
# candidate for the last member's trailer in a file of several members
# (``_GzipTruncationCheckStream._last_member_ends_the_file``). A fixed spacing of our own,
# not rapidgzip's seek points: those are sparse (only the start and end at
# ``parallelization=0``), built ahead of the reader in the child, and a round trip to
# read, and a point the reader has passed has no CRC-32 saved for it.
# ``dev-docs/formats/gzip.md`` §2.3 and §5, ``docs/formats.md`` §"Limits and
# accelerators", and the ``compressed-streams`` and ``seekable-decompressor-streams``
# specs state it; change them together.
_CRC_CHECKPOINT_SPACING = 4 << 20
# How much skipped output in all the backstop reads back from rapidgzip to check the last
# member's trailer after a seek skipped output: the part of a candidate before the point
# where reading resumed, which no saved CRC-32 covers. A candidate past what is left of
# it hands the read to the standard library, which gives the right result at the cost of
# a second decode. ``dev-docs/formats/gzip.md`` §2.3 and §5, ``docs/formats.md``
# §"Limits and accelerators", and the ``compressed-streams`` and
# ``seekable-decompressor-streams`` specs state it; change them together.
_SKIPPED_READ_BACK = 64 << 20


class _CheckpointedCrc:
    """A running CRC-32 of the output from ``start`` up to a ``frontier``, saved every
    ``_CRC_CHECKPOINT_SPACING`` bytes: ``checkpoints[i]`` is the CRC-32 of the output from
    ``start`` to ``start + i * _CRC_CHECKPOINT_SPACING``.

    ``feed`` folds a piece of output in only where it continues the covered range, as
    ``_OutputChecksum`` does. With a checkpoint at or before ``s``, the CRC-32 of the
    output from ``s`` to the frontier costs a read-back shorter than the spacing, and no
    more (``_GzipTruncationCheckStream._crc_to_the_end``).
    """

    def __init__(self, start: int) -> None:
        self.start = start
        self.frontier = start
        self.value = 0
        self.checkpoints = [0]

    def feed(self, pos: int, data: bytes) -> None:
        """Fold in ``data``, the output at ``pos``, if it reaches past the frontier."""
        end = pos + len(data)
        view = memoryview(data)
        while pos <= self.frontier < end:
            boundary = self.start + len(self.checkpoints) * _CRC_CHECKPOINT_SPACING
            stop = min(end, boundary)
            self.value = zlib.crc32(view[self.frontier - pos : stop - pos], self.value)
            self.frontier = stop
            if stop == boundary:
                self.checkpoints.append(self.value)


class _GzipTruncationCheckStream(DelegatingStream):
    """Backstop truncation detection for the rapidgzip accelerator (any seekable source).

    Upstream rapidgzip treats many incomplete streams as soft EOF (by design): ``read()``
    may return empty or a short/full prefix with no exception.

    1. On EOF with **zero** bytes delivered, the ``_StdlibOnAcceleratorError`` inside
       hands the read to the stdlib gzip-window :func:`GzipDecompressorStream`
       (``empty_to_stdlib``, set by ``GzipCodec._empty_to_stdlib``), so truncation is
       loud and any recoverable prefix is streamed (valid empty gzip still succeeds with
       zero bytes). This wrapper sees only that decoder's reads, and its checks stand
       down after the switch. A seek that meets the end of an empty output reads
       nothing, so the takeover does not switch there; this wrapper makes the same
       switch for it (:meth:`_settle_end`). That decoder reads a seekable view of the
       source, so it is seekable too, and the ``seekable()`` that this wrapper and the
       ones above it cached from rapidgzip stays true
       (``_StdlibOnAcceleratorError._open_stdlib_at`` asserts it).
    2. On EOF after **non-empty** delivery — check that rapidgzip decoded to the end of
       the source (its compressed position), then look for the member's trailer: the CRC-32
       of the output, kept as it goes by, and its length (mod 2**32), as the eight bytes
       that end the file but for zero padding (single-member). A forged copy of those
       eight bytes is not one (:meth:`_member_ends_the_file` says how far that holds).
       When a seek short of the end skipped output and a read then meets the end, there
       is no CRC-32 of that output, and the length is compared to the ISIZE read at
       open, the file's last four bytes, instead. On a mismatch, a file with a further
       member that zlib confirms (:func:`gzip_has_additional_member`) is taken as
       multi-member, whose trailer is only the last member's; nothing is raised when
       that trailer holds the CRC-32 and length of the end of the output
       (:meth:`_last_member_ends_the_file`, which saved CRC-32 checkpoints make cheap).
       A decode that stopped short of the end, or any other mismatch, hands the read to
       the standard library. After a seek skipped output, that check reads back the
       skipped part of the last member, under a ceiling past which the standard library
       decides.

       The compressed position is what tells a cut member followed by a complete one
       from a multi-member file: the trailer is then the last member's, and the further
       member is real, but rapidgzip stopped at the cut and never decoded it (found by
       the accelerator fuzz targets). It also keeps a forged ISIZE that matches the
       bytes delivered before a soft end from passing.

    ISIZE and the source length are **captured up front** (``isize`` / ``source_len``) so no
    per-read reopen is needed and the tri-state is preserved: ``source_len < 18`` ⇒ a
    non-empty soft EOF is an incomplete member, handed to the standard library like a
    mismatch; a value ⇒ compare; ``source_len is None`` (unreadable) ⇒ return without
    raising. ``views`` gives the trailer lookup and the multi-member scan their own access
    to the source (:class:`_SourceViews`), so neither disturbs the live accelerator's
    cursor.

    Both checks run once, on the first read or seek that meets the end of rapidgzip's
    output, and are spent after it: no later read or seek runs them again. A seek short
    of the end leaves them armed. The length they compare is the position at the end,
    not a count of the bytes delivered: a read that meets the end is at that length
    whatever seeks came before (rapidgzip clamps a seek past the end to the end, and
    ``_StdlibSeekContract`` above keeps the caller's position).

    A seek that stops at the end of rapidgzip's output (a seek to the end, or one that
    rapidgzip clamped) runs the checks there before it returns a position, so that
    ``seek(0, SEEK_END)`` on a cut file does not return rapidgzip's short length with no
    error. It first reads the output from the CRC-32 frontier to the end
    (:meth:`_read_through`), so the trailer check finds the trailer by its CRC-32, not
    by the four-byte ISIZE comparison that a forged trailer can pass. A size query on a
    stream not yet read so pays for receiving and checksumming the whole output, the
    price of a size that has been checked. When the standard library takes over, at the
    check or during that read, it seeks to the caller's target: it raises as it does
    with the accelerator off, or holds the caller's position, so a read after a seek
    past the end of an empty rapidgzip output does not return the bytes at offset 0.
    After a takeover the standard library owns the end, and this check does not run.

    An ISIZE mismatch hands the read to the standard library
    (:meth:`_StdlibOnAcceleratorError.switch_to_stdlib`), which gives the verdict and keeps
    it, as it does after the empty-EOF switch. The switch always installs that engine:
    positioning it at the delivered offset defers any content fault to the next read
    (``DecompressorStream.seek``), so a later read cannot see a clean EOF.
    """

    # Side-effecting read() (byte-total + EOF truncation check); disable
    # passthrough so readinto does not skip it.
    readinto_passthrough = False

    def __init__(
        self,
        inner: _StdlibOnAcceleratorError,
        *,
        views: _SourceViews,
        isize: int | None,
        source_len: int | None,
        natives: Natives = IN_PROCESS,
    ) -> None:
        super().__init__(inner)
        self._natives = natives
        # The same object as ``_inner``, typed: the ISIZE check hands over through it.
        self._takeover = inner
        self._views = views
        self._isize = isize
        self._source_len = source_len
        # The position in the output: where the read that meets the end of rapidgzip's
        # output is, that output's length. It equals ``self._inner.tell()`` (read adds
        # what the inner returned, seek stores what the inner's seek returned) and is
        # kept here because that tell() can be a round trip to the rapidgzip child
        # (``_StdlibSeekContract``). The ISIZE comparison depends on the two agreeing.
        self._pos = 0
        # CRC-32 of the output from offset 0 up to its frontier; ``_trailer_hands_over``
        # needs it whole to find where the member's trailer is.
        self._crc = _CheckpointedCrc(0)
        # After a seek skipped output, the CRC-32 from where reading resumed, so that the
        # last member's trailer can still be checked when that range holds the member's
        # output (:meth:`_last_member_ends_the_file`). Restarted by each later skip.
        self._resumed: _CheckpointedCrc | None = None
        self._checked = False

    def _count(self, data: bytes) -> None:
        """Advance the position past ``data`` that rapidgzip returned, and fold it into
        the CRC-32 of the output while that prefix is still unbroken. A piece past a gap
        in that prefix (a seek skipped output) goes to the CRC-32 that resumes after the
        gap instead, so no byte is hashed twice."""
        if not self._checked:
            pos, end = self._pos, self._pos + len(data)
            self._crc.feed(pos, data)
            if self._crc.frontier < end:
                resumed = self._resumed
                if resumed is None or pos > resumed.frontier:
                    resumed = self._resumed = _CheckpointedCrc(pos)
                resumed.feed(pos, data)
        self._pos += len(data)

    def read(self, size: int = -1, /) -> bytes:
        if size == 0:
            return b""  # an explicit read(0) is not EOF; it must not trip the check
        data = self._inner.read(size)
        if data:
            self._count(data)
            if size < 0 and not self._checked:
                # Completing read (read/-1): observe soft EOF now and run ISIZE
                # before returning. Callers that do only ``s.read(); s.close()`` must
                # still get TruncatedError from the read — never from close (ADR 0014).
                buf = bytearray(data)
                _drain_into(self._inner, buf, self._count)
                if self._settle_end():
                    more = self._inner.read(-1)
                    self._pos += len(more)
                    buf += more
                return bytes(buf)
            return data
        if self._settle_end():
            data = self._inner.read(size)
            self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # A seek short of the end leaves the checks armed. A seek that stops at the end
        # of rapidgzip's output runs them there (class docstring).
        if whence == io.SEEK_CUR:
            # _StdlibSeekContract above resolves a relative seek. A caller that drives
            # this layer directly does not, and _seek_reached_end needs an absolute
            # target, so resolve it here too, as _ZlibAdlerCheckStream.seek does.
            offset, whence = self._pos + offset, io.SEEK_SET
        self._pos = super().seek(offset, whence)
        if not _seek_reached_end(offset, whence, self._pos):
            return self._pos
        read_through = not self._checked and not self._takeover.switched
        if read_through:
            try:
                self._read_through()
            except ArchiveyError:
                if not self._takeover.switched:
                    raise
                # The standard library took over on the way and met the fault. Its
                # seek below gives the verdict a seek gets with the accelerator off: a
                # seek past the end holds the target and the next read raises.
        if self._settle_end() or (read_through and self._takeover.switched):
            # The standard library decodes now: it seeks to the caller's place, or
            # raises as it does with the accelerator off. The second operand covers a
            # handover during _read_through, not at the check: _settle_end() then
            # returns False, as the trailer check defers to a stream already switched.
            self._pos = super().seek(offset, whence)
        return self._pos

    def _read_through(self) -> None:
        """Read rapidgzip's output from the CRC-32 frontier to its end, so that the
        trailer check finds the trailer by its CRC-32 and does not compare the length
        alone with the file's last four bytes (:meth:`_trailer_hands_over`).

        A cut or damaged stream can hand the read to the standard library on the way;
        it then raises as it does with the accelerator off, or reads on to its own end.
        """
        if self._crc.frontier >= self._pos:
            return
        self._pos = self._inner.seek(self._crc.frontier)
        while data := self._inner.read(_DRAIN_CHUNK):
            self._count(data)

    def nearest_resume_offset(self, target: int) -> int | None:
        # Sits on the decompressed chain (accelerator, then maybe stdlib fallback).
        return ask_resume_offset(self._inner, target)

    def _settle_end(self) -> bool:
        """Run the end checks, once, at the end of rapidgzip's output (at ``_pos``);
        return whether the standard library decodes from now on, so that the caller's
        read or seek goes to it.

        An end at offset 0 not yet switched is an empty rapidgzip output met by a seek
        (a read there is switched by the takeover itself, ``empty_to_stdlib``): it
        hands over as that read would. Any other end runs the trailer check
        (:meth:`_trailer_hands_over`)."""
        if self._checked:
            return False
        self._checked = True
        if self._pos == 0 and not self._takeover.switched:
            self._takeover.switch_to_stdlib()
            return True
        return self._trailer_hands_over()

    def _trailer_hands_over(self) -> bool:
        """Check the trailer at the end of the data; return whether the
        standard-library decoder took over to decide (no trailer found, or after a
        seek short of the end the ISIZE does not match; below), at the position
        delivered.

        The inner half of :meth:`_settle_end`, which guards it (armed, not yet run)
        and runs it once: call that, not this.
        """
        if self._takeover.switched:
            # The standard-library decoder finished the read; it owns truncation, and
            # bytes appended to the file are for it to report.
            return False
        if self._source_len is None:
            # Source length unreadable (non-seekable / I/O error at capture): cannot verify,
            # so never invent a truncation we can't prove.
            return False
        # Below 18 bytes no gzip member is complete, so the delivered bytes are a
        # truncation. So is a decode that stopped short of the end of the source: the
        # trailer there is not this output's. Otherwise no trailer found (or, after a
        # seek, an ISIZE mismatch) is one, unless this is a concatenated multi-member
        # gzip (then the trailer is only the last member's). A confirmed further member,
        # and a last member's trailer that matches the end of the output => do not
        # raise. The further member alone is not enough: rapidgzip ends a last member
        # cut right after its header with no error, at the end of the source.
        if self._source_len >= 18 and self._decoded_to_the_end():
            if self._isize is None:
                return False  # length known but ISIZE unread (should not happen here)
            whole_crc = self._crc.frontier == self._pos
            if whole_crc and self._member_ends_the_file():
                # Every byte went through the CRC-32, so the trailer is found rather
                # than assumed to be the file's last four bytes.
                return False
            if self._has_additional_gzip_member():
                # The trailer is only the last member's, so check that one.
                if self._last_member_ends_the_file():
                    return False
            elif not whole_crc and self._pos % (1 << 32) == self._isize:
                # A seek short of the end skipped output, then a read met the end, so
                # there is no CRC-32 to find the trailer with; in a file of one member
                # the file's last four bytes stand in. A seek that meets the end reads
                # through instead.
                return False
        # No trailer of this output ends the file: it was cut, its ISIZE is wrong, or
        # something was appended, and rapidgzip reads past all of these without a word.
        # The standard-library decoder tells them apart, and keeps its verdict on later
        # reads: it carries on from here, and raises the truncation or reports the bytes.
        self._takeover.switch_to_stdlib()
        return True

    def _member_ends_the_file(self) -> bool:
        """Whether the file ends with this output's own trailer: its CRC-32 and the
        length mod 2**32, then nothing but zero padding.

        The trailer starts where the deflate stream ends, which rapidgzip does not
        report, and zero padding looks like the length's own high zero bytes. What is
        known is that the real trailer starts with the output's CRC-32, because rapidgzip
        compares it there. A trailer that ends the non-zero data starts at most 8 bytes
        before its end. So the CRC-32 is looked for from ``_TRAILER_LOOKBACK`` bytes
        before that to 12 bytes past the end of the non-zero data, and the file ends with
        the trailer only when the CRC-32 occurs there once, followed by the length and
        then by nothing but zeros.

        A forged copy of the eight bytes is turned down wherever it sits, because the
        real CRC-32 is then a second occurrence in that range. Bytes appended after the
        real trailer, a copy that overlaps it, and a copy that reaches back into the
        compressed data (a stored block ends with the payload's own bytes) all leave the
        real CRC-32 within range. If the real trailer starts in the zeros after the copy,
        its CRC-32 is zero, and the four zeros right after the copy are a second
        occurrence. A forger sets the CRC-32 at will with four chosen payload bytes, so
        nothing here leans on it being unlikely to repeat. Not excluded: a copy more than
        56 bytes after the end of the real trailer. That needs rapidgzip to read past
        those bytes, which are not a further member, without an error, and rapidgzip
        0.16 raises on ten or more, which hands the read to the standard library.

        A real trailer turned down goes to the standard library, which finds nothing
        wrong. That takes the CRC-32 occurring a second time by chance, about one file
        in 2**25, or a CRC-32 of zero with zero padding after the trailer.

        The file is read from the end: the last 96 bytes, which hold the whole range in
        any file with 24 bytes of padding or fewer, and more only to get back over
        padding.
        """
        crc = self._crc.value.to_bytes(4, "little")
        size = (self._pos % (1 << 32)).to_bytes(4, "little")
        try:
            first, end, window = self._trailer_window()
        except OSError:
            return True  # cannot look -> do not invent a mismatch
        at = window.find(crc)
        if at < 0 or window.find(crc, at + 1) >= 0:
            return False  # absent, or a second occurrence: one of them is forged
        return window[at + 4 : at + 8] == size and first + at + 8 >= end

    def _trailer_window(self) -> tuple[int, int, bytes]:
        """``(first, end, window)``: ``end`` is the end of the non-zero data, and
        ``window`` the source bytes from ``first``, ``_TRAILER_LOOKBACK + 8`` bytes before
        ``end``, to 12 bytes past it (both clipped to the file), where a trailer that
        ends the data lies. Raises ``OSError`` when the source cannot be read.

        The file is read from the end: the last 96 bytes, which hold the whole range in
        any file with 24 bytes of padding or fewer, and more only to get back over
        padding.
        """
        length = self._source_len
        assert length is not None
        with self._views.view() as f:
            base = max(0, length - (_TRAILER_LOOKBACK + 32))
            f.seek(base)
            tail = f.read(length - base)
            stripped = tail.rstrip(b"\0")
            end = base + len(stripped)
            if not stripped:
                end, step = base, 1 << 16
                while end > 0:
                    start = max(0, end - step)
                    f.seek(start)
                    stripped = f.read(end - start).rstrip(b"\0")
                    if stripped:
                        end = start + len(stripped)
                        break
                    end = start
            # A trailer that ends the data starts 8 bytes before ``end`` at the
            # earliest and at ``end`` at the latest.
            first = max(0, end - 8 - _TRAILER_LOOKBACK)
            last = min(length, end + 12)
            if base <= first and last <= base + len(tail):
                return first, end, tail[first - base : last - base]
            f.seek(first)
            return first, end, f.read(last - first)

    def _last_member_ends_the_file(self) -> bool:
        """Whether the file ends with the trailer of a last member whose output ends the
        output: eight bytes, then nothing but zero padding, that hold the CRC-32 and the
        length mod 2**32 of the output's last ``n`` bytes, ``n`` being that length.

        In a file of several members the CRC-32 of the whole output finds no trailer
        (:meth:`_member_ends_the_file`), and a further member does not show that the last
        one is whole: rapidgzip ends a last member cut right after its header with no
        error, at the end of the source (found by the ``gzip_accel`` fuzz target). The
        last member's trailer says where its output starts, ``n`` bytes before the end,
        so its CRC-32 is checked against the output from there. That needs no member
        boundaries.

        The trailer's place is not known exactly: it ends at the end of the non-zero data
        or up to 3 bytes into the zeros after it, as its last bytes are the high bytes of
        ISIZE, which is not zero for any member this checks (an empty member is checked
        apart, below). Each of those four places is a candidate. They are tried shortest
        first, and the first that matches ends the search.

        A candidate's CRC-32 comes from the running CRC-32 of the output, not from a
        second decode of the member: with ``C(x)`` the CRC-32 of ``x``, ``C(B)`` is
        ``C(A + B) ^ crc32_combine(C(A), 0, len(B))``, and the CRC-32 at the candidate's
        start is the checkpoint saved at or before it, carried on by reading back at most
        ``_CRC_CHECKPOINT_SPACING`` bytes from rapidgzip (:meth:`_crc_to_the_end`). So a
        check costs at most four such read-backs, whatever the size of the last member
        or the length a forged trailer states, and a valid file of any size is decided
        here without the standard library. A last member of 4 GiB or more does not match,
        as its length is wrapped, and goes to the standard library.

        After a seek short of the end skipped output, the check still runs. A CRC-32 is
        kept from where reading resumed, so a candidate that starts after that point is
        checked as above. For one that starts before it, the skipped part, from the
        candidate's start to the resume point, is read back from rapidgzip and its
        CRC-32 combined with the one kept since. That read-back has a ceiling,
        ``_SKIPPED_READ_BACK`` in all: a candidate past what is left of it hands the read
        to the standard library, which gives the right result at the cost of a second
        decode. Nothing is accepted that was not checked.

        An empty last member (bgzip ends every file with one) has a trailer of eight
        zeros, which any run of zeros would match, so it counts only when zlib decodes
        an empty member with nothing but zeros after it
        (:meth:`_empty_member_ends_the_data`).

        A crafted cut can still match, if the last eight bytes of the cut file are made
        the CRC-32 and length of the end of the output, which takes setting four bytes
        of the content to choose that CRC-32.
        """
        length = self._source_len
        assert length is not None
        try:
            first, end, window = self._trailer_window()
        except OSError:
            return True  # cannot look -> do not invent a mismatch
        if length - end >= 8 and self._empty_member_ends_the_data(end):
            return True
        trailers: dict[int, int] = {}  # where the output's last member starts: CRC-32
        for stop in range(max(end, 8), min(length, end + 3) + 1):
            trailer = window[stop - 8 - first : stop - first]
            size = int.from_bytes(trailer[4:], "little")  # not 0: it holds end - 1
            if size <= self._pos:
                trailers.setdefault(
                    self._pos - size, int.from_bytes(trailer[:4], "little")
                )
        hasher = next(
            (
                h
                for h in (self._crc, self._resumed)
                if h is not None and h.frontier == self._pos
            ),
            None,
        )
        budget = _SKIPPED_READ_BACK
        for start in sorted(trailers, reverse=True):  # shortest first
            if hasher is not None and start >= hasher.start:
                crc = self._crc_to_the_end(hasher, start)
            else:
                # After a skip, no saved CRC-32 covers the output from ``start`` to where
                # reading resumed (the end, with no CRC-32 kept since): read it back.
                resume = self._pos if hasher is None else hasher.start
                if resume - start > budget:
                    return False  # past the ceiling: the standard library decides
                budget -= resume - start
                crc = self._output_crc(start, resume, 0)
                if crc is not None and hasher is not None:
                    crc = crc32_combine(crc, hasher.value, self._pos - resume)
            if crc == trailers[start]:
                return True
        return False

    def _crc_to_the_end(self, hasher: _CheckpointedCrc, start: int) -> int | None:
        """The CRC-32 of the output from ``start`` to its end (``_pos``), which
        ``hasher`` covers; ``None`` when the read-back ends short.

        The checkpoint at or before ``start`` is carried on to ``start`` by reading back
        from rapidgzip, less than ``_CRC_CHECKPOINT_SPACING`` bytes, then taken out of the
        running CRC-32 with :func:`crc32_combine`. When the output from ``start`` to the
        end is shorter than that read-back (a small last member), it is read back
        instead."""
        index = (start - hasher.start) // _CRC_CHECKPOINT_SPACING
        at = hasher.start + index * _CRC_CHECKPOINT_SPACING
        if self._pos - start <= start - at:
            return self._output_crc(start, self._pos, 0)
        crc = hasher.checkpoints[index]
        if at < start:
            carried = self._output_crc(at, start, crc)
            if carried is None:
                return None
            crc = carried
        return hasher.value ^ crc32_combine(crc, 0, self._pos - start)

    def _output_crc(self, start: int, stop: int, crc: int) -> int | None:
        """``crc`` carried on over the output from ``start`` to ``stop``, read back from
        rapidgzip; ``None`` when the read ends short. Leaves the stream at ``_pos``.

        An error from the read-back propagates on purpose: rapidgzip, or the standard
        library that took over from it on the way, met damage, and that is the verdict
        of the caller's read. The seek back to ``_pos`` is then tried, and its own error
        is dropped so that it cannot replace that verdict.
        """
        at = start
        try:
            self._inner.seek(start)
            while at < stop:
                data = self._inner.read(min(_DRAIN_CHUNK, stop - at))
                if not data:
                    break
                crc = zlib.crc32(data, crc)
                at += len(data)
        except BaseException:
            with contextlib.suppress(Exception):
                self._inner.seek(self._pos)
            raise
        self._inner.seek(self._pos)
        return crc if at == stop else None

    def _empty_member_ends_the_data(self, end: int) -> bool:
        """Whether an empty gzip member ends the data, which ends at ``end`` but for
        zero padding: zlib decodes one from a ``1f 8b 08`` in the
        ``_EMPTY_MEMBER_REACH`` bytes before ``end``, and only zeros follow it."""
        length = self._source_len
        assert length is not None
        start = max(0, end - _EMPTY_MEMBER_REACH)
        stop = min(length, end + 16)  # past the trailer; only zeros are left after it
        try:
            with self._views.view() as f:
                f.seek(start)
                data = f.read(stop - start)
        except OSError:
            return True  # cannot look -> do not invent a mismatch
        magic = GZIP_MAGIC + b"\x08"
        at = data.rfind(magic)
        while at >= 0:
            decoder = self._natives.zlib_decompressobj(GZIP_WBITS)
            try:
                if (
                    not decoder.decompress(data[at:], 1)
                    and decoder.eof
                    and not decoder.unused_data.strip(b"\0")
                ):
                    return True
            except zlib.error:
                pass
            finally:
                release_decoder(decoder)
            at = data.rfind(magic, 0, at)
        return False

    def _decoded_to_the_end(self) -> bool:
        """Whether rapidgzip's decode reached the end of the source; ``True`` when it
        cannot say, which leaves the checks after it as they were."""
        position = getattr(self._takeover.accelerator, "compressed_position", None)
        if position is None or self._source_len is None:
            return True
        end = position()
        return end is None or end >= self._source_len

    def _has_additional_gzip_member(self) -> bool:
        # Closed via the context manager: a real fd close for a path source, a no-op
        # mark for a shared view (see _SourceViews).
        try:
            with self._views.view() as f:
                return gzip_has_additional_member(f, self._natives)
        except OSError:
            return True  # cannot rule out a second member -> do not raise


# The bounds of ``gzip_has_additional_member``'s probe. They are not ``ArchiveyConfig``
# limits because they are structural, not policy: running out of any of them only hands
# the read to the standard library, which gives the verdict at the cost of a second
# decode. It never turns a valid file into an error the caller would have to accept.
#
# How much of a candidate member the probe decodes before it takes the candidate for a
# real member: compressed bytes read, and output produced. Random bytes after a chance
# ``1f 8b 08`` fail long before either (see that function).
_MEMBER_PROBE_INPUT = 1 << 16
_MEMBER_PROBE_OUTPUT = 1 << 20
# The compressed bytes all candidates together may decode: this much, plus one byte per
# sixteen scanned. A file that spends it is not taken for multi-member.
_MEMBER_PROBE_BUDGET = 1 << 20
# The compressed bytes one probe read takes. The budget is tested between reads, so this
# is what every candidate that passes the header check costs at least (about 256
# candidates per MiB of budget) and how far one probe can overspend the budget.
_MEMBER_PROBE_PIECE = 1 << 12


def gzip_has_additional_member(stream: BinaryIO, natives: Natives = IN_PROCESS) -> bool:
    """Whether ``stream`` contains a gzip member after the one starting at offset 0.

    A member starts with ``1f 8b 08``, and those three bytes turn up by chance in a
    compressed body about once per 16 MiB, so a match is only a candidate. A candidate
    with reserved ``FLG`` bits set is skipped; any other counts when zlib's gzip decoder
    takes it for a member (:func:`_gzip_member_at`).

    The decodes share a budget (``_MEMBER_PROBE_BUDGET``), so a file crafted with a
    candidate every few bytes, each decoding a long way before it fails, costs a bounded
    share of the scan. A scan that spends it answers ``False``: the caller then hands the
    read to the standard library, which gives the verdict at the cost of a second decode.

    Scans in fixed-size blocks (never reads the whole file into memory), carrying a small
    overlap so a header split across a block boundary is still found. Starts one byte in so
    this member's own header at offset 0 is not matched.

    **Side effect:** seeks the stream. Callers that need the prior position MUST restore
    it themselves (e.g. ``tell``/``seek`` around the call). Path-source callers typically
    open a fresh handle owned only for this scan.
    """
    magic = GZIP_MAGIC + b"\x08"  # CM 8: deflate, the only method
    block = 1 << 20
    offset = 1  # of buf[0] in the stream
    budget = _MEMBER_PROBE_BUDGET
    stream.seek(offset)
    buf = b""
    while chunk := stream.read(block):
        budget += len(chunk) // 16
        buf += chunk
        found = buf.find(magic)
        while found >= 0:
            # FLG, when this block holds it: reserved bits make zlib refuse the header.
            if found + 3 >= len(buf) or not buf[found + 3] & 0xE0:
                member, fed = _gzip_member_at(stream, offset + found, budget, natives)
                budget -= fed
                if member is not None:
                    return member
                if budget <= 0:
                    return False
            found = buf.find(magic, found + 1)
        keep = min(len(magic) - 1, len(buf))
        offset += len(buf) - keep
        buf = buf[len(buf) - keep :]
        stream.seek(offset + keep)
    return False


def _gzip_member_at(
    stream: BinaryIO, offset: int, budget: int, natives: Natives = IN_PROCESS
) -> tuple[bool | None, int]:
    """Whether a gzip member starts at ``offset`` of ``stream``, as far as a short decode
    can tell, and the compressed bytes read: ``True`` for a member, ``None`` for a
    candidate that is not one, ``False`` when ``budget`` ran out first. Seeks the stream.

    zlib's gzip decoder checks the header (method, reserved flags, header CRC) and
    decodes from it. The candidate counts when the decode reaches the member's end, where
    zlib checks the CRC-32 and ISIZE, or decodes ``_MEMBER_PROBE_INPUT`` compressed bytes
    or ``_MEMBER_PROBE_OUTPUT`` of output without an error. Random bytes after a chance
    match do neither: most fail the header, and DEFLATE decoded from random bits meets an
    invalid code or a distance past the output within a few hundred symbols. A candidate
    the source ends inside does not count: a real member cut there is a truncation, which
    the standard-library engine then reports.
    """
    stream.seek(offset)
    decoder = natives.zlib_decompressobj(GZIP_WBITS)
    fed = produced = 0
    try:
        while fed < _MEMBER_PROBE_INPUT:
            if fed >= budget:
                return False, fed
            pending = stream.read(min(_MEMBER_PROBE_PIECE, _MEMBER_PROBE_INPUT - fed))
            if not pending:
                return None, fed
            fed += len(pending)
            while pending:
                # Ask for no more than the output bound leaves, so the probe never
                # produces more than _MEMBER_PROBE_OUTPUT in total.
                produced += len(
                    decoder.decompress(pending, _MEMBER_PROBE_OUTPUT - produced)
                )
                if decoder.eof or produced >= _MEMBER_PROBE_OUTPUT:
                    return True, fed
                pending = decoder.unconsumed_tail
    except zlib.error:
        return None, fed
    finally:
        release_decoder(decoder)
    return True, fed


# How many gzip header bytes to peek for cheap metadata (FNAME/mtime). Longer stored names
# beyond this are simply not surfaced.
_GZIP_HEADER_PEEK = 512
# Header (10) + CRC-32 and ISIZE (8): a floor below which a file cannot hold a gzip
# trailer. Only the last 4 bytes (ISIZE) are used. The smallest real member is 20
# bytes, since a deflate stream is never empty.
_GZIP_MIN_MEMBER = 18


class GzipCodec(_DeflateFamilyCodec):
    codec = Codec.GZIP
    checks_content = True
    stream_format = StreamFormat.GZIP
    magic = (MagicSignature(0, GZIP_MAGIC, ArchiveFormat.GZ),)
    # gzip is only a standalone stream format, never a 7z or ZIP coder, so no container
    # declares a pack size to clip it to and no AES pad follows its data.
    _bounds_source = False
    # rapidgzip ends some cut members before any output, with no error; the standard
    # library gives the verdict there (``_GzipTruncationCheckStream``, item 1).
    _empty_to_stdlib = True

    def prepare_config(self, source: CodecSource, config: StreamConfig) -> StreamConfig:
        # gzip ISIZE makes truncation checkable → allows rapidgzip AUTO with the ISIZE
        # backstop. Do not promote ISIZE into expected_decompressed_size (mod 2**32 /
        # multi-member).
        return _config_with_gzip_isize(source, config)

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        # Prefer a container-declared size; otherwise note a readable ISIZE so AUTO can
        # still select rapidgzip with the dedicated ISIZE backstop (not VerifyingStream).
        return super().open(source, params, _config_with_gzip_isize(source, config))

    def _open_stdlib(self, source: CodecSource, config: StreamConfig) -> BinaryIO:
        # Stdlib path: gzip-window DecompressorStream (not gzip.GzipFile). CRC/ISIZE
        # outcomes come from zlib's gzip window; members with nothing between them
        # chain, and NULs end the data as in GNU gzip (GzipDecoder). With declared seek
        # demand, a backward seek resumes at the nearest member or BGZF block start.
        # Otherwise it decodes again from the start, and warns once the discarded
        # progress reaches REWIND_REDECODE_WARN_BYTES.
        return _stdlib_gzip(source, config)

    def _leaves_to_stdlib(self, source: CodecSource, config: StreamConfig) -> bool:
        # The standard-library engine raises zlib's own error on the first read, as
        # it does with the accelerator off.
        return _gzip_header_refused(source, natives_for(config.process_isolation))

    def _end_check(
        self,
        source: CodecSource,
        config: StreamConfig,
        accel_source: CodecSource,
        views: _SourceViews,
    ) -> Callable[[_StdlibOnAcceleratorError], BinaryIO] | None:
        # A declared size does not replace this check: the VerifyingStream outside
        # checks only the length, and rapidgzip ends a cut member with no error, so a
        # size equal to the output before the cut would pass (the raw DEFLATE case the
        # accelerator fuzz targets found). No container declares a gzip size today
        # (gzip is never a ZIP or 7z coder), so this only keeps the check from
        # depending on that staying true.
        # Truncation backstop for **any** seekable source (path or caller-owned stream):
        # single-member ISIZE (the empty→stdlib fallback is the takeover's,
        # ``_empty_to_stdlib``), with the multi-member scan on an
        # independent view: the check stands down only for a further member zlib's gzip
        # decoder confirms and a last member's trailer that matches the end of the
        # output, and a scan that spends its budget hands the read to the standard
        # library (the ISIZE of a member before the last is not checked). Capture the ISIZE
        # tri-state up front so no per-read reopen is needed and `size < 18` truncation
        # is preserved.
        source_len, isize = _gzip_isize_and_length(source)
        return lambda stream: _GzipTruncationCheckStream(
            stream,
            views=views,
            isize=isize,
            source_len=source_len,
            natives=natives_for(config.process_isolation),
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, gzip.BadGzipFile):
            return CorruptionError(
                f"Error reading gzip stream: {exception_detail(exc)}"
            )
        if isinstance(exc, zlib.error):
            # Corruption inside the deflate body (a valid gzip header, then bad data) is
            # raised by zlib's gzip window as a raw zlib.error. zlib does not flag
            # truncation distinctly here (a short stream surfaces as TruncatedError via
            # the decompressor engine), so any zlib.error at this point is corruption,
            # and a failed CRC-32/ISIZE check a whole-stream one; a member header gzip
            # refuses as unsupported stays unsupported (:func:`gzip_error`).
            return gzip_error(exc)
        return self._eof_truncation(exc, "gzip")

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """Surface gzip's stored filename (FNAME), mtime and trailer ISIZE.

        RFC 1952 specifies the FNAME field as ISO-8859-1 (Latin-1), so the decoded value in
        ``extra`` uses that encoding; ``raw_name`` keeps the verbatim stored bytes.

        **ISIZE goes in** ``extra["gzip.isize"]``, **never in** ``member.size``. It is
        the last four bytes of the file, read only where the end is cheap to reach. In a
        file of one gzip member with nothing after it, that is the size modulo 2**32. It
        is not the size of a file of several members (it covers the last one only: a
        bgzip file ends with an empty member, so it reads 0), nor of a file with bytes
        after its last member. Like the CRC below, nothing short of a scan of the whole
        file tells those cases apart. ``member.size`` comes from the first full read
        instead (the reader's late fill-in).

        **The trailer CRC-32 is deliberately never put in** ``member.hashes``. Maintainer
        decision (PR 441); the reasoning, so it is not re-litigated:

        - A digest is worth having for two things: skipping a decompression because an
          equal file was already processed (it must be known *before* the read), or
          verifying a read (it must come from somewhere the decoder does not already
          check).
        - The trailer CRC covers only the **last** member. It equals the digest of the
          whole content only when the file holds exactly one member, and nothing in the
          header says so.
        - Proving single-memberness at open means scanning the whole compressed file.
          That was the old behaviour: O(file size) on every open (a full download for a
          remote source), and on large files the 3-byte member magic ``1f 8b 08``
          matches by chance (about once per 16 MiB), so the scan usually concluded
          "multi-member" and dropped the CRC anyway.
        - Adding the CRC after a full read was implemented and removed: by then the
          decoder has already checked every member's CRC and raised on a mismatch, so
          the digest serves neither purpose. It also could not be made uniform, since
          the rapidgzip accelerator hides member boundaries.

        A caller that wants a digest of a gzip's content computes one while reading.
        """
        header = ctx.peek_header(_GZIP_HEADER_PEEK)
        if len(header) < 10 or not header.startswith(GZIP_MAGIC):
            return
        # A file shorter than header + trailer has no trailer to read.
        trailer = ctx.peek_trailer(_GZIP_MIN_MEMBER)
        if trailer is not None:
            member.extra["gzip.isize"] = int.from_bytes(trailer[-4:], "little")
        flg = header[3]
        mtime = int.from_bytes(header[4:8], "little")
        if mtime != 0:
            member.modified = unix32_to_datetime(mtime)

        pos = 10
        if flg & 0x04:  # FEXTRA: 2-byte length + data
            if pos + 2 <= len(header):
                xlen = int.from_bytes(header[pos : pos + 2], "little")
                pos += 2 + xlen
            else:
                pos = len(header) + 1  # stop optional-field walk
        if flg & 0x08 and pos <= len(header):
            # FNAME: null-terminated stored filename (Latin-1 per RFC 1952)
            end = header.find(b"\x00", pos)
            if end != -1:
                name_bytes = header[pos:end]
                member.raw_name = name_bytes
                member.extra["gzip.original_filename"] = name_bytes.decode("latin-1")
