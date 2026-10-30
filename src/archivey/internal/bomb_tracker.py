"""The decompression-bomb tracker: the byte, ratio and entry-count limits one extraction
enforces as it writes (``ExtractionLimits``), the archive-wide ratio a compressed
container's decode is held to in every use (:class:`DecodeRatioGuard`), and the ratio
member reads are held to outside extraction (:class:`MemberRatioGuard`)."""

from __future__ import annotations

import io
import math
import threading
from dataclasses import replace
from typing import TYPE_CHECKING, BinaryIO, cast

from archivey.config import (
    DecoderLimits,
    ExtractionLimits,
    ratio_field_is_set,
)
from archivey.exceptions import ResourceLimitError
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    read_blocking,
    source_byte_size,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from archivey.internal.base_reader import BaseArchiveReader
    from archivey.internal.streams.streamtools.readahead import _ReadsAhead
    from archivey.types import ArchiveMember


def ratio_limits(
    decoder: DecoderLimits, *overrides: ExtractionLimits | None
) -> DecoderLimits:
    """``decoder``, with each ratio field a deprecated ``ExtractionLimits`` sets in its
    place (a later override wins). The guards read the ratio fields from the result."""
    max_ratio = decoder.max_ratio
    floor = decoder.ratio_activation_threshold
    live_floor = decoder.live_ratio_activation_threshold
    for limits in overrides:
        if limits is None:
            continue
        if ratio_field_is_set(limits.max_ratio):
            max_ratio = limits.max_ratio
        if ratio_field_is_set(limits.ratio_activation_threshold):
            floor = limits.ratio_activation_threshold
        if ratio_field_is_set(limits.live_ratio_activation_threshold):
            live_floor = limits.live_ratio_activation_threshold
    if (max_ratio, floor, live_floor) == (
        decoder.max_ratio,
        decoder.ratio_activation_threshold,
        decoder.live_ratio_activation_threshold,
    ):
        return decoder
    return replace(
        decoder,
        max_ratio=max_ratio,
        ratio_activation_threshold=floor,
        live_ratio_activation_threshold=live_floor,
    )


def archive_ratio_refusal(
    output: int,
    *,
    max_ratio: float | None,
    floor: int,
    live_floor: int,
    static_size: int | None,
    consumed: Callable[[], int | None] | None,
) -> str | None:
    """Why ``output`` decoded bytes break the archive-wide ratio, or ``None``.

    The rule extraction's archive-wide check and a compressed container's decode
    (:class:`DecodeRatioGuard`) share. The denominator is the archive's size when it is
    cheaply known (``static_size``), otherwise the compressed bytes read so far
    (``consumed``, asked only when needed). Nothing is judged before ``floor`` bytes of
    output, and the live denominator not before ``live_floor`` either: it is what has
    been read so far, so a blank run at the start of the source reads far above the
    ratio it will end at once the data after it arrives. Waiting for the live floor lets
    such a start pass as it does when the whole size is known; once a pipe is read to
    its end, ``consumed`` is that whole size and the two checks agree (codec-layer
    re-reads elsewhere only make it larger).
    """
    if max_ratio is None or output <= floor:
        return None
    if static_size and static_size > 0:
        if output / static_size > max_ratio:
            return (
                f"Archive-wide decompression ratio {output / static_size:.0f}:1 "
                f"exceeds limit max_ratio={max_ratio:.0f}:1"
            )
        return None
    if consumed is None or output <= live_floor:
        return None
    read = consumed()
    if read and read > 0 and output / read > max_ratio:
        return (
            f"Live decompression ratio {output / read:.0f}:1 exceeds limit "
            f"max_ratio={max_ratio:.0f}:1"
        )
    return None


class AlwaysStopResourceLimitError(ResourceLimitError):
    """A cumulative/global bomb guard: halts extraction even under ``OnError.CONTINUE``.

    A subclass of ``ResourceLimitError`` so callers catching that type (or
    ``ArchiveyError``) still catch it; the coordinator uses the type to distinguish it
    from a *skippable* per-member ratio failure.
    """


class BombTracker:
    """Cumulative byte / per-member ratio / archive-wide ratio / entry-count guards.

    Constructed once per extraction call. ``start_member()`` is called (with the
    **original** member) before each member; ``count()`` is called with each chunk
    written.
    """

    def __init__(
        self,
        max_bytes: int | None,
        max_ratio: float | None,
        # The defaults come from ExtractionLimits, the one place the limits are set.
        ratio_activation_threshold: int = ExtractionLimits.ratio_activation_threshold,
        max_entries: int | None = ExtractionLimits.max_entries,
        *,
        source: BaseArchiveReader | None = None,
        live_ratio_activation_threshold: int = (
            ExtractionLimits.live_ratio_activation_threshold
        ),
    ) -> None:
        self._max_bytes = max_bytes
        self._max_ratio = max_ratio
        self._ratio_floor = ratio_activation_threshold
        self._live_ratio_floor = live_ratio_activation_threshold
        # Archive-wide ratio denominators, taken from the reader so the coordinator just
        # hands over the source: the static outer compressed size when it is cheaply known
        # (captured once), otherwise a LIVE sample of the compressed bytes consumed from the
        # source (read fresh on each count(), since it grows as extraction proceeds).
        self._source = source
        self._compressed_source_size = (
            source.compressed_source_size if source is not None else None
        )
        self._max_entries = max_entries
        self._entry_count = 0
        self._total_bytes = 0  # decoded output, cumulative across all members
        # Bytes copied from a file this run already wrote (the hardlink copy fallback).
        # They count toward the byte cap. The part copied at the filesystem's link-count
        # limit also counts toward the archive-wide ratio (``count_copy``).
        self._copied_bytes = 0
        self._link_limit_copied_bytes = 0
        self._member_bytes = 0  # output bytes for the current member
        self._member: ArchiveMember | None = None
        # Output of members a streaming pass wrote and then did not keep (see
        # ``refund``). Subtracted for the byte cap only.
        self._refunded_bytes = 0

    @property
    def total_bytes(self) -> int:
        """Every byte written to the destination, decoded or copied."""
        return self._total_bytes + self._copied_bytes

    @property
    def member_bytes(self) -> int:
        return self._member_bytes

    def start_member(self, member: ArchiveMember) -> None:
        # Called with the ORIGINAL member (not a filter copy), so compressed_size and any
        # late-bound fields are accurate. Increments the entry-count guard, which — like
        # the cumulative byte guard — halts even under OnError.CONTINUE.
        self._member = member
        self._member_bytes = 0
        self._entry_count += 1
        if self._max_entries is not None and self._entry_count > self._max_entries:
            raise AlwaysStopResourceLimitError(
                f"Entry-count limit reached: max_entries={self._max_entries} "
                f"(would write entry {self._entry_count})"
            )

    def refund(self, member_bytes: int, *, entry: bool = True) -> None:
        """Stop counting one member that a streaming pass wrote and then did not keep.

        Two passes do this. A streaming pass takes back a member as superseded: random
        access never writes a shadowed duplicate, so it never counts one
        (``safe-extraction``: no bomb-limit counting for the skip). A pass that stages
        its members (a ZIP from a pipe) removes the staged data of a member it does
        not place. Either way the entry is gone from the destination, so the entry
        count stops counting it, unless the member still has one (``entry=False``: a
        link placed without its staged data). Its bytes are gone too unless a hardlink
        made to it still holds them, so the caller passes ``member_bytes`` as 0 in that
        case and the byte cap keeps them. The archive-wide ratio counts them either
        way: those bytes were decoded, and a name repeated many times must not decode
        for free. ``total_bytes``, which progress reports, is not reduced: it counts
        what was written.
        """
        if entry:
            self._entry_count -= 1
        self._refunded_bytes += member_bytes

    def check_recorded_size(self) -> None:
        """Refuse the current member before its data is read, when its recorded size
        is over the per-member ratio.

        Called once the member is about to be decoded, after every check that could
        still skip it, so a member that would not be decoded is never refused here.
        A member's output never passes its recorded size: the member stream refuses
        a byte past it (``CorruptionError``). So a member whose recorded size is over
        the per-member ratio is one ``count()`` would refuse after decoding past the
        activation threshold, and it is refused now instead, with the same skippable
        error. The one difference is a member whose data stops short of its recorded
        size: ``count()`` might never refuse it, and the read would fail as damaged
        instead. Both fail that member alone.

        The archive-wide ratios are left to ``count()``. Refusing early on the archive's
        recorded sizes would stop the whole run on a size nothing has verified, losing
        the intact members after a damaged one; and ``count()`` already stops at the
        chunk that crosses the archive-wide limit, so an early check would save little.
        ``count()`` still runs on every chunk.
        """
        member = self._member
        if self._max_ratio is None or member is None:
            return
        size = member.size
        cs = member.compressed_size
        if size is None or not cs or cs <= 0:
            return
        if size > max(self._ratio_floor, self._max_ratio * cs):
            raise ResourceLimitError(
                f"Decompression ratio {size / cs:.0f}:1 exceeds limit "
                f"max_ratio={self._max_ratio:.0f}:1 (from recorded sizes: "
                f"{size} bytes from {cs} compressed)",
                member_name=member.name,
            )

    def count(self, chunk_bytes: int) -> None:
        """Count a chunk that is about to be written; raise instead if it may not be."""
        self._check_cumulative_bytes(chunk_bytes)
        self._total_bytes += chunk_bytes
        self._member_bytes += chunk_bytes

        # Per-member ratio: activates on THIS member's output; a per-member failure
        # (skippable under OnError.CONTINUE).
        member = self._member
        cs = member.compressed_size if member is not None else None
        if (
            self._max_ratio is not None
            and member is not None
            and self._member_bytes > self._ratio_floor
            and cs
            and cs > 0
        ):
            ratio = self._member_bytes / cs
            if ratio > self._max_ratio:
                raise ResourceLimitError(
                    f"Decompression ratio {ratio:.0f}:1 exceeds limit "
                    f"max_ratio={self._max_ratio:.0f}:1",
                    member_name=member.name,
                )
        self._check_archive_ratio()

    def count_copy(self, chunk_bytes: int, *, at_link_limit: bool) -> None:
        """Count bytes copied from a file this run already wrote, not decoded.

        A hard link that cannot be made writes a second full copy of content already
        on disk: across a device boundary, or past the filesystem's link-count limit.
        Those bytes land on the filesystem, so they count toward ``max_extracted_bytes``
        like any other write.

        A copy made at the link-count limit (``at_link_limit``) also counts toward the
        archive-wide ratio. The archive drives it: one that declares enough links to
        one member makes a copy per limit's worth of links, so a small archive could
        otherwise write far more than its size while staying under the byte cap, which
        is the case the ratio exists for. A cross-device copy does not: whether it
        happens depends on where the caller extracts to, not on the archive. Neither
        counts toward the per-member ratio, since a link member's compressed size says
        nothing about the copy's size.
        """
        self._check_cumulative_bytes(chunk_bytes)
        self._copied_bytes += chunk_bytes
        if at_link_limit:
            self._link_limit_copied_bytes += chunk_bytes
            self._check_archive_ratio()

    def _check_cumulative_bytes(self, chunk_bytes: int) -> None:
        """Cumulative byte guard (always-stop), checked before ``chunk_bytes`` is written.

        Both callers count a chunk before they write it, so a refused chunk never
        reaches the destination and is not counted. The message says what is on disk
        and what the refused write would have made it.
        """
        written = self.total_bytes - self._refunded_bytes
        would_be = written + chunk_bytes
        if self._max_bytes is not None and would_be > self._max_bytes:
            raise AlwaysStopResourceLimitError(
                f"Extraction limit reached: max_extracted_bytes={self._max_bytes} "
                f"(written {written} bytes; the next {chunk_bytes}-byte chunk would "
                f"make {would_be})"
            )

    def _check_archive_ratio(self) -> None:
        # Archive-wide ratio: activates on CUMULATIVE output; a whole-archive bomb signal
        # (always-stop). Uses the static outer compressed size when it is cheaply known,
        # otherwise a LIVE denominator — the compressed bytes consumed from the source so
        # far — which works for a streaming/pipe source whose total size is unknown. The two
        # are mutually exclusive (static when known, live otherwise), so the ratio is never
        # counted twice.
        css = self._compressed_source_size
        # Decoded output plus the copies made at the link-count limit (``count_copy``).
        output = self._total_bytes + self._link_limit_copied_bytes
        # Says which part was not decoded, so a trip on a store-only archive with many
        # hard links is not read as a decompression bomb.
        copies = self._link_limit_copied_bytes
        detail = (
            f" ({self._total_bytes} bytes decoded, plus {copies} bytes copied for hard "
            f"links past the filesystem's link-count limit)"
            if copies
            else ""
        )
        source = self._source
        refusal = archive_ratio_refusal(
            output,
            max_ratio=self._max_ratio,
            floor=self._ratio_floor,
            live_floor=self._live_ratio_floor,
            static_size=css,
            consumed=(
                (lambda: source.compressed_bytes_consumed)
                if source is not None
                else None
            ),
        )
        if refusal is not None:
            raise AlwaysStopResourceLimitError(refusal + detail)


# How far a forward seek moves the decoder before the guard checks again. A codec
# serves a forward seek by decoding the gap, so one seek over a huge member would
# decode all of it before a check after the seek could refuse.
_GUARD_STEP = 1 << 20


class _RatioGuard(DelegatingStream):
    """A decoded stream refused once the furthest offset it has decoded breaks a ratio
    rule (:meth:`_judge`).

    The measure is the furthest offset decoded, so a backward seek that decodes again
    costs nothing here. Reads and seeks forward go to the decoder in steps of at most
    1 MiB, a seek to the end included, so a refusal comes within a step of the limit,
    from the call that crosses it, whose bytes are withheld.
    """

    # Changes no bytes and no positions: verification and resume offsets look
    # through, and so do a cheap size and seek cost (``source_byte_size``,
    # ``seek_is_expensive``), which are the decoder's.
    forwards_verification = True
    peel_for_source_size = True
    readinto_passthrough = False
    # Whether the decoder's error after a whole step is held for the next call.
    _holds_errors = True

    def __init__(self, inner: BinaryIO, *, max_ratio: float | None) -> None:
        super().__init__(inner)
        self._max_ratio = max_ratio
        self._pos = 0  # over a decoder that has not started
        self._decoded = 0  # the furthest offset decoded
        # The decoder's error after a read that already returned bytes: raised by
        # the next read (a seek drops it), so the prefix a damaged stream decodes is not lost
        # (the hazard ReadAheadStream holds its error for).
        self._held: Exception | None = None
        # The decoded length when known, so a read to the end inside the room stays
        # one read; a subclass sets it.
        self._size: int | None = None

    def _judge(self, position: int) -> None:
        """Raise if ``position`` decoded bytes break the rule; called as it grows."""
        raise NotImplementedError

    def _room(self) -> float:
        """How far past the current position one call may decode before a check.

        At least a step; more where no position before it can break the rule, so a
        large read stays one read of the decoder (``math.inf``: the rest of it).
        """
        return _GUARD_STEP

    def _step(self, left: int) -> int:
        """The size of the next decoder read toward ``left`` bytes (``-1``: the end)."""
        room = self._room()
        if left < 0:
            size = self._size
            if room == math.inf or (size is not None and self._pos + room >= size):
                return -1
            return int(room)
        return int(min(left, room))

    def _check(self, position: int) -> None:
        if position <= self._decoded or self._max_ratio is None:
            return
        self._decoded = position
        self._judge(position)

    def _raise_held(self) -> None:
        if self._held is not None:
            err, self._held = self._held, None
            raise err

    def read(self, n: int = -1, /) -> bytes:
        self._raise_held()
        if n is not None and 0 <= n <= max(_GUARD_STEP, self._room()):
            data = read_blocking(self._inner, n)
            self._pos += len(data)
            self._check(self._pos)
            return data
        parts: list[bytes] = []
        left = -1 if n is None or n < 0 else n
        while left != 0:
            step = self._step(left)
            try:
                data = read_blocking(self._inner, step)
            except Exception as e:
                if not parts or not self._holds_errors:
                    raise
                self._held = e
                break
            if not data:
                break
            parts.append(data)
            self._pos += len(data)
            self._check(self._pos)
            if step < 0:
                break
            if left > 0 and len(data) < step:
                # A full-count decoder's short read is its end; its error, if any,
                # comes from the next read, as when the call went to it whole. A read
                # to the end goes on to that read.
                break
            if left > 0:
                left -= len(data)
        return b"".join(parts)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # A seek drops the held error, as ReadAheadStream's does: it describes the
        # position the caller is leaving, and a rewind re-decodes from a resume point.
        # Unlike there, a refused seek drops it too; a decoder that has raised
        # raises again on the next read.
        self._held = None
        if whence == io.SEEK_END:
            # The decoder serves this by decoding to its end in one call: find the
            # end from its cheap size, or by reading to it a step at a time.
            size = source_byte_size(self._inner)
            if size is None:
                if not self._inner.seekable():
                    # Refused before the drain, not after decoding it all.
                    raise io.UnsupportedOperation("seek")
                while True:
                    data = read_blocking(self._inner, _GUARD_STEP)
                    if not data:
                        break
                    self._pos += len(data)
                    self._check(self._pos)
                size = self._pos
            offset, whence = size + offset, io.SEEK_SET
        target = offset if whence == io.SEEK_SET else self._pos + offset
        while target - self._pos > _GUARD_STEP:
            step_to = self._pos + _GUARD_STEP
            self._pos = self._inner.seek(step_to)
            if self._pos < step_to:  # the stream ended inside the step
                return self._pos
            self._check(self._pos)
        self._pos = self._inner.seek(target)
        self._check(self._pos)
        return self._pos

    def tell(self, /) -> int:
        return self._pos

    def read_ahead(self, need: int, n: int, /) -> bytes:
        """The decoder's ``read_ahead`` (:class:`ReadAheadStream` with
        ``fill_arrived``): at least ``need`` bytes, up to ``n``, of what has arrived."""
        self._raise_held()
        data = cast("_ReadsAhead", self._inner).read_ahead(need, n)
        self._pos += len(data)
        self._check(self._pos)
        return data


class DecodeRatioGuard(_RatioGuard):
    """A compressed container's decoded stream (a ``.tar.gz``), refused once it has
    decoded past :attr:`~archivey.DecoderLimits.max_ratio` of the archive's size.

    Listing such an archive decodes all of it, member data included, before
    extraction counts a byte, so a few hundred bytes of bzip2 could keep ``members()``
    decoding for minutes. Extraction would refuse the same archive at the same ratio;
    this refuses it while listing, reading or extracting alike.
    """

    def __init__(
        self,
        inner: BinaryIO,
        *,
        limits: DecoderLimits,
        static_size: int | None,
        consumed: Callable[[], int | None] | None,
    ) -> None:
        super().__init__(inner, max_ratio=limits.max_ratio)
        self._limits = limits
        self._static_size = static_size
        self._consumed = consumed

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)

    def _judge(self, position: int) -> None:
        limits = self._limits
        refusal = archive_ratio_refusal(
            position,
            max_ratio=limits.max_ratio,
            floor=limits.ratio_activation_threshold,
            live_floor=limits.live_ratio_activation_threshold,
            static_size=self._static_size,
            consumed=self._consumed,
        )
        if refusal is not None:
            raise AlwaysStopResourceLimitError(
                f"{refusal} ({position} bytes of the archive decoded)"
            )


class ReadRatioTally:
    """The bytes a reader's member reads have decoded, for the archive-wide ratio.

    Each member counts once, at the furthest offset any read of it reached, so reading
    a member again or seeking back in it adds nothing; the total is then at most what
    one full pass decodes. Shared by every member stream of one reader, from any
    thread.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._furthest: dict[int, int] = {}
        self._total = 0

    def others(self, key: int) -> int:
        """The total, less member ``key``'s part of it. Read without the lock: it only
        sizes a step (``MemberRatioGuard._room``), and ``advance`` judges."""
        return self._total - self._furthest.get(key, 0)

    def advance(self, key: int, position: int) -> int:
        """Record that member ``key`` has decoded ``position`` bytes; the new total."""
        with self._lock:
            before = self._furthest.get(key, 0)
            if position > before:
                self._furthest[key] = position
                self._total += position - before
            return self._total


class MemberRatioGuard(_RatioGuard):
    """A member's decoded stream on ``open()`` or ``stream_members()``, held to
    :attr:`~archivey.DecoderLimits.max_ratio` as extraction holds what it writes.

    Two rules, the same two ``BombTracker`` applies on write. The member's own output
    against its recorded compressed size (where the archive records one) fails this
    member only: a plain :exc:`~archivey.exceptions.ResourceLimitError`, so a pass can
    go on to the next member. The output of all the reader's member reads together
    (:class:`ReadRatioTally`) against the archive's size raises
    ``AlwaysStopResourceLimitError``.

    The decoder's error raises from the call that meets it, as it did without the
    guard: a ``read()`` of the whole member that reaches damage raises rather than
    returning the steps before it.
    """

    _holds_errors = False

    def __init__(
        self,
        inner: BinaryIO,
        *,
        limits: DecoderLimits,
        member: ArchiveMember,
        tally: ReadRatioTally,
        static_size: int | None,
        consumed: Callable[[], int | None] | None,
    ) -> None:
        super().__init__(inner, max_ratio=limits.max_ratio)
        self._limits = limits
        self._member_name = member.name
        self._compressed_size = member.compressed_size
        # Never decoded past: the member's recorded size bounds a seek's gap.
        self._size = member.size
        assert member._member_id is not None, member.name
        self._key = member._member_id
        self._tally = tally
        self._static_size = static_size
        self._consumed = consumed
        # The furthest output each rule allows without a look (``_room``): the
        # member's own, and the archive-wide one, less what other members read.
        floor = limits.ratio_activation_threshold
        max_ratio = limits.max_ratio
        cs = member.compressed_size
        self._member_safe: float = math.inf
        self._archive_safe: float = math.inf
        if max_ratio is not None:
            if cs and cs > 0:
                self._member_safe = max(floor, max_ratio * cs)
            if static_size and static_size > 0:
                self._archive_safe = max(floor, max_ratio * static_size)
            elif consumed is not None:
                self._archive_safe = max(floor, limits.live_ratio_activation_threshold)

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)

    def try_get_size(self) -> int | None:
        """The inner stream's cheap size, as ``ArchiveStreamImpl.size`` asks it."""
        inner = self._inner
        try_get_size = getattr(inner, "try_get_size", None)
        if callable(try_get_size):
            result = try_get_size()
            return result if isinstance(result, int) else None
        size = getattr(inner, "size", None)
        return size if isinstance(size, int) and not isinstance(size, bool) else None

    def _room(self) -> float:
        # The first position either rule could refuse at, less the current one.
        safe = self._member_safe
        if self._archive_safe != math.inf:
            safe = min(safe, self._archive_safe - self._tally.others(self._key))
        return max(_GUARD_STEP, safe - self._pos)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # The decoder answers the seek itself, with its own clamping and end rules;
        # only a forward gap is decoded first, in steps, to the target the seek names.
        self._held = None
        if whence == io.SEEK_SET:
            target: int | None = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        else:
            size = self._size
            target = None if size is None else size + offset
        if target is not None and self._size is not None:
            # Past the member's end there is nothing to decode.
            target = min(target, self._size)
        if target is not None:
            while target - self._pos > self._room():
                step_to = self._pos + int(self._room())
                reached = self._inner.seek(step_to)
                if reached < step_to:  # the stream ended inside the step
                    break
                self._pos = reached
                self._check(reached)
        self._pos = self._inner.seek(offset, whence)
        self._check(self._pos)
        return self._pos

    def _judge(self, position: int) -> None:
        limits = self._limits
        max_ratio = limits.max_ratio
        assert max_ratio is not None  # _check returns first otherwise
        cs = self._compressed_size
        if self._size is not None:
            # A seek past the end decodes nothing there.
            position = min(position, self._size)
        if position > limits.ratio_activation_threshold and cs and cs > 0:
            ratio = position / cs
            if ratio > max_ratio:
                raise ResourceLimitError(
                    f"Decompression ratio {ratio:.0f}:1 exceeds limit "
                    f"max_ratio={max_ratio:.0f}:1",
                    member_name=self._member_name,
                )
        total = self._tally.advance(self._key, position)
        refusal = archive_ratio_refusal(
            total,
            max_ratio=max_ratio,
            floor=limits.ratio_activation_threshold,
            live_floor=limits.live_ratio_activation_threshold,
            static_size=self._static_size,
            consumed=self._consumed,
        )
        if refusal is not None:
            raise AlwaysStopResourceLimitError(
                f"{refusal} ({total} bytes of member data read)",
                member_name=self._member_name,
            )
