"""Keep the bytes a solid RAR pass decodes for the file copies that follow them.

A RAR5 file copy (``rar -oi``) has no data of its own; it reads as its source member.
``unrar p`` and ``unar`` emit nothing for it, so a solid pass used to serve each copy
from a named open of the source, and every such open decodes the solid stream again
from its start up to the source. Fifty copies of a 1 KiB file behind 100 MiB of solid
data decoded 5 GiB.

:class:`FileCopySources` sits between the pass's decompressor output and its
:class:`~archivey.internal.streams.streamtools.solid.SolidBlockReader` and keeps the
bytes of every member a later copy reads, as the pipe passes them, whether or not
the caller reads that member. Small sources stay in memory; a larger one goes to a
temporary file charged to the reader's spool budget (``SpoolLimits.max_bytes``). The
file is opened, and the source charged, only when the source's first byte arrives,
and :meth:`FileCopySources.close` gives the charge back. A source that fits neither
is not kept, and its copies fall back to the named open. So is a source the pass's
``keep`` callback declines when its first byte arrives: extraction declines a source it
is writing to disk, and copies the source's copies from the written file.
Kept bytes are served unverified; the caller wraps them in the source's digest
check, as it does the pipe's own bytes.
"""

from __future__ import annotations

import io
import tempfile
from collections.abc import Callable
from typing import BinaryIO, Literal

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import read_blocking
from archivey.internal.streams.streamtools.slice import SlicingStream

# Total bytes one pass keeps in memory. A source that would pass it goes to the
# temporary file instead. This is a tuning value, not a limit a caller needs to set: it
# never refuses anything and never changes which bytes a read returns. It only chooses
# where a kept source waits, and both places are bounded already. The bytes kept in
# memory are at most this much per live pass, and the file is charged to
# ``SpoolLimits.max_bytes``, which callers set. A source the file has no room for is not
# kept, and its copies decode it again with a named open. A caller reading from a path
# who wants no kept file sets ``max_bytes=0``; on a stream source that also refuses the
# archive copy ``unrar`` needs. ``format-rar``'s spec states the value.
_MEMORY_LIMIT = 8 << 20

_State = Literal["memory", "file", "dropped"]


class _Kept:
    """One source's range in the pipe and what has been kept of it."""

    __slots__ = ("data", "file_offset", "key", "received", "size", "start", "state")

    def __init__(self, key: int, start: int, size: int, state: _State) -> None:
        self.key = key
        self.start = start
        self.size = size
        self.received = 0
        # Set at registration. "file" is the temporary file, if the spool budget has
        # room when the first byte arrives; "dropped" is not kept, and its copies
        # use the fallback.
        self.state: _State = state
        self.data: bytearray | bytes = bytearray()
        # Where the source's span in the temporary file starts; ``None`` until its
        # first byte is written.
        self.file_offset: int | None = None

    @property
    def end(self) -> int:
        return self.start + self.size


class _TeeBlock(DelegatingStream):
    """The pass's decoded block, handing each chunk read to ``feed`` with its offset."""

    # Every byte must reach ``feed``, so readinto goes through read.
    readinto_passthrough = False

    def __init__(self, inner: BinaryIO, feed: Callable[[int, bytes], None]) -> None:
        super().__init__(inner)
        self._feed = feed
        self._at = 0

    @override
    def read(self, n: int = -1, /) -> bytes:
        data = read_blocking(self._inner, n)
        if data:
            self._feed(self._at, data)
            self._at += len(data)
        return data


class FileCopySources:
    """The sources of a solid pass's file copies, kept as the pipe passes them.

    A member is keyed by ``id()`` of its one ``ArchiveMember`` object, which the
    reader keeps alive; ``_member_id`` is not assigned yet when a streaming pass
    starts. ``source_ids`` are the keys of every member a copy in the pass reads.
    The pass calls :meth:`register` with each such member's pipe range as it reaches
    it, before any read can move the pipe past it, and builds its block reader over
    :meth:`tee`. ``try_spool(size)`` charges the spool budget and says whether
    ``size`` more bytes may go to the temporary file; ``release_spool(size)`` gives
    a charge back. Charging only when a source's first byte arrives means a pass that
    reads nothing writes nothing, and the pass has already made any copy of the
    archive source it needs (that copy comes before the decompressor that produces
    the byte), so a keep never takes the allowance that copy needed. ``keep(key)``,
    when given, is asked at that same first byte; ``False`` leaves the source unkept.
    """

    def __init__(
        self,
        source_ids: frozenset[int],
        try_spool: Callable[[int], bool],
        release_spool: Callable[[int], None],
        keep: Callable[[int], bool] | None = None,
    ) -> None:
        self._source_ids = source_ids
        self._keep = keep
        self._try_spool = try_spool
        self._release_spool = release_spool
        self._kept: dict[int, _Kept] = {}
        # Registered ranges the pipe has not finished, in pipe order.
        self._pending: list[_Kept] = []
        self._pipe_pos = 0
        self._memory = 0
        self._file: BinaryIO | None = None
        # Bytes of the file promised to sources, all of them charged to the spool
        # budget. Two sources can be pending at once (a caller that skips both), so
        # each gets its own span.
        self._file_size = 0

    def is_source(self, key: int) -> bool:
        return key in self._source_ids

    def register(self, key: int, start: int, size: int) -> None:
        """Keep ``[start, start + size)`` of the pipe for ``key``'s copies."""
        if start < self._pipe_pos:
            # The pipe has already passed it; never the case for a pass that
            # registers members in order, but a partial range would be wrong bytes.
            self._kept[key] = _Kept(key, start, size, "dropped")
            return
        if size == 0 or self._memory + size <= _MEMORY_LIMIT:
            kept = _Kept(key, start, size, "memory")
            self._memory += size
        else:
            kept = _Kept(key, start, size, "file")
        self._kept[key] = kept
        if kept.received < kept.size:
            self._pending.append(kept)

    def tee(self, block: BinaryIO) -> BinaryIO:
        """Wrap the pass's decoded block so every byte read passes through here."""
        return _TeeBlock(block, self._feed)

    def _place_in_file(self, kept: _Kept) -> bool:
        """Charge ``kept`` to the spool budget and give it a span of the file.

        ``False`` when the budget has no room: the source is then not kept.
        """
        if not self._try_spool(kept.size):
            kept.state = "dropped"
            return False
        # Counted before the file opens, so close() gives the charge back even if
        # opening it fails.
        kept.file_offset = self._file_size
        self._file_size += kept.size
        if self._file is None:
            self._file = tempfile.TemporaryFile()  # noqa: SIM115 - closed in close()
        return True

    def _wanted(self, kept: _Kept) -> bool:
        """Whether to keep ``kept``, asked as its first byte arrives; drops it if not."""
        if self._keep is None or self._keep(kept.key):
            return True
        if kept.state == "memory":
            self._memory -= kept.size
        kept.state = "dropped"
        return False

    def _feed(self, at: int, data: bytes) -> None:
        end = at + len(data)
        self._pipe_pos = end
        while self._pending:
            kept = self._pending[0]
            if kept.start >= end:
                return
            lo = max(kept.start + kept.received, at)
            hi = min(kept.end, end)
            if hi > lo:
                chunk = memoryview(data)[lo - at : hi - at]
                if kept.received == 0 and not self._wanted(kept):
                    self._pending.pop(0)
                    continue
                if kept.state == "memory":
                    assert isinstance(kept.data, bytearray)
                    kept.data += chunk
                elif kept.file_offset is not None or self._place_in_file(kept):
                    assert self._file is not None and kept.file_offset is not None
                    self._file.seek(kept.file_offset + kept.received)
                    self._file.write(chunk)
                else:
                    # No room in the spool: not kept, and the pipe moves on.
                    self._pending.pop(0)
                    continue
                kept.received += hi - lo
            if kept.received < kept.size:
                return
            if kept.state == "memory":
                # Immutable from here, so each copy's BytesIO shares it.
                kept.data = bytes(kept.data)
            self._pending.pop(0)

    def open(self, key: int, advance_past: Callable[[int], object]) -> BinaryIO | None:
        """The kept bytes of source ``key``, or ``None`` when they were not kept.

        ``advance_past(end)`` moves the pipe to ``end`` when the caller skipped the
        source and the pipe has not reached the end of it yet; the bytes are kept on
        the way. A pipe that ends early raises from there, as reading the source would.
        """
        kept = self._kept.get(key)
        if kept is None or kept.state == "dropped":
            return None
        if kept.received < kept.size:
            advance_past(kept.end)
            if kept.received < kept.size:
                return None
        if kept.state == "memory":
            return io.BytesIO(kept.data)
        assert self._file is not None and kept.file_offset is not None
        # Nothing writes to the file while a copy reads it: the pipe only moves for a
        # later member or another copy, and the pass closes this copy's stream first.
        return SlicingStream(self._file, kept.file_offset, kept.size)

    def close(self) -> None:
        """Delete the temporary file and give its spool charge back."""
        self._kept.clear()
        self._pending.clear()
        try:
            if self._file is not None:
                self._file.close()
                self._file = None
        finally:
            if self._file_size:
                self._release_spool(self._file_size)
                self._file_size = 0
