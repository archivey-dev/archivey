"""Detection-owned prefix workspace: one handle, one growing buffer, range views.

Every tier that reads from the front of a source does so through a
:class:`PrefixWorkspace`. Extending the window reads only the delta of the prefix;
bytes already in the buffer are not fetched again. :meth:`PrefixWorkspace.read_tail`
sits outside that buffer. It seeks to a fixed block at the end and restores the
handle, and it does not keep the bytes. A later tier that grows the prefix over
that range fetches them again. A seekable bzip2 or xz file larger than the prefix
does this: the trailer check runs when the near magic matches, and the inner-TAR
probe then reads the rest of the file. A file that already fits in the prefix has
the block in the buffer.

A seekable caller stream records its entry position and restores it on the way
out. The tail read adds one seek out and one seek back before that restore. A
non-seekable :class:`~archivey.internal.source.ArchiveSource` is peeked, so its
replay prefix holds the bytes and the backend reads them from the same object.

The access-shape rule and the seeks it allows: ``dev-docs/topics/detection.md`` §4.2.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Protocol, Self

from archivey.config import ProcessIsolation
from archivey.detection_cost import (
    DetectionBudget,
    DetectionCostReceipt,
    TierSkipReason,
)
from archivey.internal.detection_cost_receipt import MutableDetectionCostReceipt
from archivey.internal.source import ArchiveSource, seek_is_expensive
from archivey.internal.streams.streamtools import (
    is_seekable,
    read_arrived,
    read_exact,
    source_byte_size,
)

# Default amount detection peeks (``format-detection``'s DETECTION_LIMIT). A peek grows
# past it on demand — 32 774 bytes when the ISO probe is triggered — so this is the
# typical case, not a cap on what a non-seekable source's replay prefix may hold.
DETECTION_LIMIT = 4096

# Non-seekable ``read_at`` ceiling for content-probe chain walks: reaching offset N means
# buffering [0, N). 1 MiB covers a second link after a 4- or 5-nibble first block; a
# 6-nibble first block (up to 16 MiB) is declined (``None`` → cannot disprove).
PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE = 1 << 20


class CandidateView(Protocol):
    """The callable :meth:`PrefixWorkspace.candidate_view` returns.

    ``view(end)`` returns the candidate's first ``end`` bytes. ``view(end, start)``
    returns only bytes ``[start, end)``, so a reader that keeps what it got before asks
    for the new bytes alone. Without ``start``, a reader that grows its prefix one small
    read at a time copies the whole prefix on every read.
    """

    def __call__(self, end: int, start: int = 0, /) -> bytes: ...


class PrefixWorkspace:
    """Monotonically growing prefix buffer over a detection source.

    Consumers ask for ranges relative to the archive origin (the position detection
    started from). The workspace decides whether that is a buffer slice, a delta read, or
    (for a content probe on a random-access source) a seek that it undoes.
    """

    def __init__(
        self,
        source: str | Path | BinaryIO,
        budget: DetectionBudget,
        receipt: MutableDetectionCostReceipt | None = None,
        *,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> None:
        self._budget = budget
        # The caller's ``process_isolation``: where the probes' trial decodes run.
        self.isolation = isolation
        # A caller-supplied receipt accumulates across workspaces: ``detect_format``
        # passes one to both the stub pass and the sibling-volume pass.
        self._receipt = (
            receipt if receipt is not None else MutableDetectionCostReceipt()
        )
        self._buf = bytearray()
        self._closed = False
        # A random-access handle: a path's own (owned, closed on exit) or a seekable
        # caller stream (borrowed, restored to ``_entry_pos`` on exit). Until close,
        # ``_handle is not None`` exactly when ``_entry_pos is not None``; close drops
        # the handle and keeps ``_entry_pos`` for ``remaining_known``.
        self._handle: BinaryIO | None = None
        self._owns_handle = False
        self._entry_pos: int | None = None
        self._peekable: ArchiveSource | None = None
        self._raw_forward: BinaryIO | None = None
        self._source_exhausted = False
        # Set when a ``limit``-clamped ``candidate_view`` shortens a peek. Distinct
        # from source EOF: the scan records ``BUDGET_EXHAUSTED`` from this, because
        # the validator's ``NOT_THIS_FORMAT`` cannot tell the two apart.
        self._clamped_view_read = False
        self._owned_source: ArchiveSource | None = None
        if isinstance(source, (str, Path)):
            # Classify the path as ``open_archive`` does: a pipe, character device or
            # socket cannot seek, so it is read forward once through a source this
            # workspace owns instead of as a random-access file handle.
            path_source = ArchiveSource.for_path(Path(source))
            if not path_source.seekable():
                self._owned_source = path_source
                source = path_source
        if isinstance(source, ArchiveSource) and source.path is not None:
            # Detection keeps its own handle on a file and closes it on exit, so the
            # source's handle opens only when a backend reads, and a backend that never
            # does leaves nothing open on the archive: ``unrar`` over a path, and ZIP,
            # the single-file codecs and compressed TAR, which hand their parser the
            # path. Reading through the source here would open its handle before the
            # backend chose, and hold it for the reader's lifetime.
            source = source.path
        # Total size of the underlying object from its own offset 0, when cheap. For an
        # ``ArchiveSource`` that is its ``size_hint``, a caller's fsspec ``size`` included;
        # its ``size`` is the narrower fact, which is for clamping a read and would leave
        # a hint-sized stream with no known remaining length.
        self._total_size = (
            source.size_hint
            if isinstance(source, ArchiveSource)
            else source_byte_size(source)
        )

        if isinstance(source, (str, Path)):
            # The handle outlives this statement; its owner closes it.
            self._handle = open(source, "rb")  # noqa: SIM115
            self._owns_handle = True
            self._entry_pos = 0
        elif isinstance(source, ArchiveSource) and not source.seekable():
            self._peekable = source
            # The source's own replay prefix — the backend drains it, so never a copy.
        elif is_seekable(source):
            self._handle = source
            self._entry_pos = source.tell()
        else:
            self._raw_forward = source

    @property
    def budget(self) -> DetectionBudget:
        return self._budget

    @property
    def read_ceiling(self) -> int:
        """Most bytes from the origin any buffered tier may pull into the prefix.

        The largest of the prefix, far and scan limits: a tier that stays under it
        cannot fetch more than the budget allows any buffered tier to read.
        """
        b = self._budget
        return max(b.max_prefix_bytes, b.max_far_bytes, b.max_scan_bytes)

    @property
    def receipt(self) -> DetectionCostReceipt:
        return self._receipt.freeze()

    @property
    def skips(self) -> tuple:
        return tuple(self._receipt.skips)

    @property
    def forward_only(self) -> bool:
        """Whether the source is read forward once, with no handle to seek."""
        return self._peekable is not None or self._raw_forward is not None

    @property
    def buffered_length(self) -> int:
        return len(self._buf)

    def remaining_known(self) -> int | None:
        """Provable bytes from the archive origin, or ``None`` if not known.

        An overestimated total size never proves a later offset reachable — we only report
        a remaining length when it is measured from the entry position (or a short peek
        that hit EOF). The one unverified total is a caller's fsspec ``size`` attribute,
        which is taken at its word here.
        """
        if self._total_size is not None and self._entry_pos is not None:
            remaining = self._total_size - self._entry_pos
            return remaining if remaining >= 0 else None
        if self._source_exhausted:
            return len(self._buf)
        return None

    def ensure(self, end: int, *, arrived: bool = False) -> None:
        """Grow the prefix buffer to at least ``end`` bytes (or EOF).

        With ``arrived``, a forward-only source is read once, for what has arrived
        (:func:`~archivey.internal.streams.streamtools.binaryio.read_arrived`), so the
        buffer can stay short of ``end`` without the source having ended. It grows
        by at least one byte unless the source has ended. A random-access source
        cannot hold a reader back, so it is read to ``end`` either way.

        Does not materialise a ``bytes`` copy of the whole buffer — callers slice
        ``self._buf`` for the span they need.
        """
        if end < 0:
            raise ValueError("end must be non-negative")
        if end <= len(self._buf) or self._source_exhausted:
            return
        needed = end - len(self._buf)
        chunk, ended = self._fetch_forward(needed, arrived=arrived)
        if chunk:
            self._buf.extend(chunk)
            self._receipt.unique_bytes_read += len(chunk)
        if ended:
            self._source_exhausted = True

    def peek_range(self, origin: int, length: int, *, arrived: bool = False) -> bytes:
        """Return ``length`` bytes starting at archive-relative ``origin``.

        Extends the prefix buffer when the range lies in the forward-growing region.
        Does not re-fetch bytes already buffered. ``arrived`` is :meth:`ensure`'s: the
        result can then be short while the source has not ended.
        """
        if origin < 0 or length < 0:
            raise ValueError("origin and length must be non-negative")
        if length == 0:
            return b""
        end = origin + length
        self._receipt.prefix_bytes += length
        self.ensure(end, arrived=arrived)
        if origin >= len(self._buf):
            return b""
        return bytes(self._buf[origin:end])

    def peek_prefix(self, length: int) -> bytes:
        """Convenience: :meth:`peek_range` from archive origin 0."""
        return self.peek_range(0, length)

    def peek_prefix_until(self, length: int, settled: Callable[[bytes], bool]) -> bytes:
        """The first ``length`` bytes, or fewer once ``settled`` accepts what arrived.

        :meth:`peek_prefix` with an early stop. A forward-only source is read for
        what has arrived, one read at a time, and ``settled`` is asked about the
        prefix after each read. It returns ``True`` only when no later byte can
        change the caller's answer. This stops a pipe whose writer sent a short
        archive and keeps the pipe open from holding detection until the writer
        closes it. A random-access source is read to ``length`` in one read, as
        :meth:`peek_prefix` reads it. The receipt is charged one request of
        ``length``, as :meth:`peek_prefix` charges it.
        """
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        self._receipt.prefix_bytes += length
        while (
            len(self._buf) < length
            and not self._source_exhausted
            and not settled(bytes(self._buf))
        ):
            self.ensure(length, arrived=True)
        return bytes(self._buf[:length])

    def candidate_view(
        self,
        candidate_origin: int,
        *,
        limit: int | None = None,
        arrived: bool = False,
    ) -> CandidateView:
        """A ``peek_more(end)``-shaped callable relative to ``candidate_origin``.

        ``peek_more(end)`` returns the first ``end`` bytes of the *candidate*, which are
        the absolute range ``[candidate_origin, candidate_origin + end)``. Served from
        the shared buffer — never a second fetch of bytes already retrieved.
        ``peek_more(end, start)`` returns only the part from ``start``, and the receipt
        is charged for that part only (:class:`CandidateView`).

        With ``arrived``, a short result does not mean the source has ended: only a
        result no longer than the one before it does. A call that asks for more than
        the view last returned gets what the buffer already holds when that is more,
        and reads the source (:meth:`ensure`) only when it is not. So a probe that asks
        for a large block over a pipe gets the bytes that are there, and waits only
        when it has used all of them.

        ``limit`` is an exclusive archive-origin ceiling (the SFX scan passes
        ``scan_limit`` plus ``validator_allowance(budget)``, which every
        validator's peek fits under the presets).
        A validator that asks for more than remains gets a short read and must not
        grow the prefix past the cost gate. That short read is indistinguishable
        from source EOF inside the validator; the workspace notes the clamp so the
        scan can record ``BUDGET_EXHAUSTED``. ``None`` leaves the view unbounded.
        """
        if candidate_origin < 0:
            raise ValueError("candidate_origin must be non-negative")
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")

        returned = 0

        def peek_more(end: int, start: int = 0, /) -> bytes:
            nonlocal returned
            if start < 0:
                raise ValueError("start must be non-negative")
            if limit is not None:
                remaining = max(0, limit - candidate_origin)
                if end > remaining:
                    self._clamped_view_read = True
                end = min(end, remaining)
            wanted = max(0, end - start)
            if not arrived:
                return self.peek_range(candidate_origin + start, wanted)
            held = len(self._buf) - candidate_origin
            if held > returned or held >= end:
                # Enough is buffered, or more than last time: no read.
                self._receipt.prefix_bytes += wanted
                first = candidate_origin + start
                data = bytes(self._buf[first : first + wanted])
            else:
                data = self.peek_range(candidate_origin + start, wanted, arrived=True)
            # How far into the candidate this call's answer reaches, whatever
            # ``start`` was.
            returned = max(0, min(len(self._buf) - candidate_origin, end))
            return data

        return peek_more

    def take_clamped_view_read(self) -> bool:
        """Return and clear whether a limited view truncated a peek since last take."""
        flagged = self._clamped_view_read
        self._clamped_view_read = False
        return flagged

    def read_at(self, offset: int, length: int) -> bytes | None:
        """Absolute (archive-origin) range read for content-probe chain walks.

        Random-access sources (path, cheap seekable streams) seek to
        ``offset``, read ``length`` bytes, and restore the handle — they do **not** grow
        the prefix buffer through ``[0, offset)``. Non-seekable sources, and seekable
        streams whose seek is known to be expensive (:class:`~archivey.ArchiveStream`
        re-decode), grow the prefix under the smaller of
        :data:`PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE` and :attr:`read_ceiling`, and return
        ``None`` past that cap (recorded as ``BUDGET_EXHAUSTED``). Short/empty on EOF.
        A seek read that starts inside the prefix takes that part from the prefix, so
        the bytes are not fetched twice.
        """
        if offset < 0 or length < 0:
            return None
        if length == 0:
            return b""
        end = offset + length
        if end <= len(self._buf):
            self._receipt.prefix_bytes += length
            return bytes(self._buf[offset:end])

        handle = self._cheap_random_access_handle()
        if handle is not None:
            held = len(self._buf)
            if offset < held:
                self._receipt.prefix_bytes += held - offset
                rest = self._read_at_via_seek(handle, held, end - held)
                return bytes(self._buf[offset:held]) + rest
            return self._read_at_via_seek(handle, offset, length)

        if end > min(PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE, self.read_ceiling):
            self.record_skip("content_probe_read_at", TierSkipReason.BUDGET_EXHAUSTED)
            return None
        return self.peek_range(offset, length)

    def _cheap_random_access_handle(self) -> BinaryIO | None:
        """Handle for O(1) probe seeks, or ``None`` to fall back to capped buffering.

        A path's own handle and a bare seekable stream (``BytesIO``, file object)
        are treated as cheap. :class:`~archivey.ArchiveStream` is not, under any
        pass-through layer or in a volume list (``seek_is_expensive``): many codecs
        service a backward restore by re-decoding, so probes prefer the capped buffer
        path there. Richer "is this seek cheap?" pricing is
        an idea in ``dev-docs/IDEAS.md`` ("Price detection in round trips, not
        bytes").
        """
        if self._handle is None or seek_is_expensive(self._handle):
            return None
        return self._handle

    def _read_at_via_seek(self, handle: BinaryIO, offset: int, length: int) -> bytes:
        assert self._entry_pos is not None
        entry = self._entry_pos
        restore = entry + len(self._buf)
        handle.seek(entry + offset)
        try:
            data = read_exact(handle, length)
        finally:
            # The handle must leave the cursor at the end of the prefix buffer —
            # `_fetch_forward` assumes that; an interrupted probe must not splice the
            # next ensure from the probe offset.
            handle.seek(restore)
        self._receipt.unique_bytes_read += len(data)
        return data

    def read_tail(self, length: int) -> bytes | None:
        """The last ``length`` bytes, or ``None`` when that read is not cheap.

        A path or a plain seekable stream seeks to the end and restores the
        handle, the same way :meth:`read_at` does, and does not grow the prefix
        through the middle of the file. A non-seekable source, and an
        ``ArchiveStream`` whose backward seek may re-decode, returns ``None``
        rather than buffering the whole source to reach the end. Those declines
        record the trailer tier as ``CAPABILITY_UNAVAILABLE``: the source has a
        tail detection did not look at. A source shorter than ``length`` has no
        such block and returns ``None`` with nothing recorded.
        """
        if length < 0:
            return None
        if length == 0:
            return b""
        total = self.remaining_known()
        if total is None:
            self.record_skip("trailer", TierSkipReason.CAPABILITY_UNAVAILABLE)
            return None
        if total < length:
            return None
        origin = total - length
        if origin + length <= len(self._buf):
            return bytes(self._buf[origin : origin + length])
        handle = self._cheap_random_access_handle()
        if handle is None:
            self.record_skip("trailer", TierSkipReason.CAPABILITY_UNAVAILABLE)
            return None
        return self._read_at_via_seek(handle, origin, length)

    def charge_far(self, nbytes: int) -> None:
        self._receipt.far_bytes += nbytes

    def charge_scanned(self, nbytes: int) -> None:
        self._receipt.scanned_bytes += nbytes

    def charge_decode(self, *, input_bytes: int = 0, output_bytes: int = 0) -> None:
        self._receipt.decode_input += input_bytes
        self._receipt.decode_output += output_bytes

    @property
    def decode_input_left(self) -> int:
        """Compressed input detection may still decode before ``max_decode_input`` runs out.

        One allowance for the whole call: every decoding tier (content probes, their
        completion check, the inner-TAR probe) draws on it, so the number of tiers or
        candidates cannot multiply the input the budget allows decoded.
        """
        return max(0, self._budget.max_decode_input - self._receipt.decode_input)

    def record_skip(self, tier: str, reason: TierSkipReason) -> None:
        self._receipt.record_skip(tier, reason)

    def close(self) -> None:
        """Release an owned handle, or restore a borrowed one to its entry position."""
        if self._closed:
            return
        self._closed = True
        handle, self._handle = self._handle, None
        try:
            if handle is not None:
                assert self._entry_pos is not None
                if self._owns_handle:
                    handle.close()
                else:
                    handle.seek(self._entry_pos)
        finally:
            if self._owned_source is not None:
                self._owned_source.close()
                self._owned_source = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _fetch_forward(self, nbytes: int, *, arrived: bool) -> tuple[bytes, bool]:
        """The next bytes after the buffer, and whether the source has ended.

        Up to ``nbytes`` bytes. Without ``arrived``, or from a random-access handle,
        a short result is the end of the source. With ``arrived``, a forward-only
        source is read once for what has arrived, and only an empty result is the
        end.
        """
        if nbytes <= 0:
            return b"", False
        if self._peekable is not None:
            # Grow the source's replay prefix, and take only the bytes past the
            # buffer: the whole prefix on every read would make a source that
            # returns small reads cost the square of its length.
            start = len(self._buf)
            end = start + nbytes
            if arrived:
                delta = self._peekable.peek_arrived(end, start)
                return delta, not delta
            delta = self._peekable.peek(end, start)
            return delta, len(delta) < nbytes
        if self._handle is not None:
            assert self._entry_pos is not None
            # Sequential growth: seek only when the handle is not at the end of the
            # buffer. Never rewind to re-fetch bytes already in the buffer.
            expected = self._entry_pos + len(self._buf)
            if self._handle.tell() != expected:
                self._handle.seek(expected)
            data = read_exact(self._handle, nbytes)
            return data, len(data) < nbytes
        if self._raw_forward is not None:
            if arrived:
                data = read_arrived(self._raw_forward, nbytes)
                return data, not data
            data = read_exact(self._raw_forward, nbytes)
            return data, len(data) < nbytes
        return b"", True
