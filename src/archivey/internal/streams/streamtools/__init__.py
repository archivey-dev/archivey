"""Generic binary-stream plumbing — adapt, classify, and slice arbitrary ``BinaryIO``.

This subpackage is the codec- and format-agnostic core of the stream layer: it knows
nothing about archivey's error hierarchy or any codec, only about stdlib binary streams.
That independence is deliberate — it could be lifted out as a standalone library — so
nothing here may import from the rest of ``archivey``. The import rule is the half
tooling enforces; concept leaks count too. Do not put archivey types, the error
hierarchy, or codec internals in the *API* of this package (call-site examples in
"when to use" comments can stay).

Named exception: ``SlicingStream.nearest_resume_offset`` translates a
contiguous window into the inner's offset space, and ``ask_resume_offset`` in
``binaryio`` is the duck-typing helper it uses. That is generic offset
arithmetic, not the seek-point table — the table stays outside this package.
The method name is archivey-specific; this may move later if the package is
lifted out.

Module map:

- :mod:`.base` — ``ReadOnlyIOStream`` / ``DelegatingStream`` (wrapper bases)
- :mod:`.binaryio` — classify/coerce sources (``is_seekable``, ``ensure_binaryio``, …)
  plus ``ask_resume_offset`` (duck-typed resume query; see the named exception above)
  and ``resolve_seek`` / ``check_seek_args`` / ``check_read_size`` (``io.BytesIO``
  seek-target and argument rules)
- :mod:`.slice` — ``SlicingStream`` / ``SharedView`` bound views + ``fix_stream_start_position``
- :mod:`.shared` — ``SharedSource`` (concurrent independent views over one handle)
- :mod:`.fullcount` — ``FullCountStream`` (full-count reads with no buffer)
- :mod:`.locked` — ``LockedStream`` (whole-op lock wrapper)
- :mod:`.readahead` — ``ReadAheadStream`` (a read buffer over a full-count stream)
- :mod:`.solid` — ``SolidBlockReader`` (forward-only solid demux)
- :mod:`.sparse` — ``SparseStream`` (a sparse file's logical bytes, holes as zeros)

When to use which concurrency helper:

- ``LockedStream`` — one shared handle; hold a lock across each seek+read (TAR/ISO).
- ``SharedSource`` + ``SharedView`` — each consumer has its own logical
  position; a read seeks under the lock when the handle is not already there
  (ZIP-style shared file).
- ``SolidBlockReader`` — one forward decode; hand out consecutive member slices
  (7z folder / RAR pipe). Not seekable.

Import from this package root rather than the individual modules.
"""

from __future__ import annotations

from archivey.internal.streams.streamtools.base import (
    DelegatingStream,
    ReadOnlyIOStream,
)
from archivey.internal.streams.streamtools.binaryio import (
    DEFAULT_UNKNOWN_LENGTH_READ_STEP,
    BinaryIOWrapper,
    OneReadEachStream,
    ReadableStream,
    check_read_size,
    check_seek_args,
    ensure_binaryio,
    ensure_bufferedio,
    is_closed_file_error,
    is_filename,
    is_seekable,
    is_stream,
    raise_if_text_stream,
    raise_if_write_only_stream,
    read_arrived,
    read_exact,
    read_within_reach,
    readinto_via_read,
    reject_source,
    require_source,
    resolve_seek,
    source_byte_size,
    source_name,
    source_size_fact,
    underlying_stream,
)
from archivey.internal.streams.streamtools.fullcount import FullCountStream
from archivey.internal.streams.streamtools.locked import LockedStream
from archivey.internal.streams.streamtools.readahead import ReadAheadStream
from archivey.internal.streams.streamtools.shared import MemberDataView, SharedSource
from archivey.internal.streams.streamtools.slice import (
    SharedView,
    SlicingStream,
    fix_stream_start_position,
)
from archivey.internal.streams.streamtools.solid import (
    SolidBlockReader,
    skip_forward,
)
from archivey.internal.streams.streamtools.sparse import SparseStream

__all__ = [
    "DEFAULT_UNKNOWN_LENGTH_READ_STEP",
    "BinaryIOWrapper",
    "DelegatingStream",
    "FullCountStream",
    "LockedStream",
    "MemberDataView",
    "OneReadEachStream",
    "ReadAheadStream",
    "ReadOnlyIOStream",
    "ReadableStream",
    "SharedSource",
    "SharedView",
    "SlicingStream",
    "SolidBlockReader",
    "SparseStream",
    "check_read_size",
    "check_seek_args",
    "ensure_binaryio",
    "ensure_bufferedio",
    "fix_stream_start_position",
    "is_closed_file_error",
    "is_filename",
    "is_seekable",
    "is_stream",
    "raise_if_text_stream",
    "raise_if_write_only_stream",
    "read_arrived",
    "read_exact",
    "read_within_reach",
    "readinto_via_read",
    "reject_source",
    "require_source",
    "resolve_seek",
    "skip_forward",
    "source_byte_size",
    "source_name",
    "source_size_fact",
    "underlying_stream",
]
