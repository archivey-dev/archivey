"""TAR on the sequential plugin shape: a prototype, to measure what the shape costs.

The plugin-API change ports TAR onto :class:`~archivey.formats.SequentialReader` as the
test of that shape (tasks 2b), as ISO was the test of the indexed one. This module is
the port's first cut. It is not registered: the built-in TAR reader still serves every
TAR. A test or a benchmark registers :class:`TarSequentialHandler` in a
``registration_scope()`` and opens an archive with ``format=TAR_SEQUENTIAL``.

It reuses the built-in reader's parts as they are: :class:`TarWalker` parses the
headers, reading a :class:`ForwardStream` through :class:`_ForwardFile`, and the
member is typed by ``TarReader._to_member``'s own code (:class:`_MemberTyper`), its
diagnostics sent through ``ReaderContext.report``. A sparse member's data is handed
over decoded (``MemberSpan.data``). Not ported yet: the end-of-archive checks
(``TarReader._verify_tar_eof``: the second zero block, trailing data, a directory's
declared blocks) and the header budget.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, BinaryIO, ClassVar, cast

from archivey.diagnostics import DiagnosticCode, DiagnosticContext
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.formats import (
    ForwardStream,
    MemberSpan,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.backends import tar_reader
from archivey.internal.backends.tar_parser import (
    TarEnd,
    TarEndKind,
    TarEntry,
    TarWalker,
    validate_sparse_map,
)
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.streams.streamtools import ReadOnlyIOStream, check_read_size
from archivey.internal.streams.streamtools.sparse import SparseStream
from archivey.terminal import quoted
from archivey.types import ArchiveFormat, ArchiveMember, PluginContainer, StreamFormat


class TarSequentialContainer(PluginContainer):
    TAR_SEQUENTIAL = "tar-sequential"


TAR_SEQUENTIAL = ArchiveFormat(
    TarSequentialContainer.TAR_SEQUENTIAL, StreamFormat.UNCOMPRESSED
)


class _ForwardFile:
    """The walker's stream: a :class:`ForwardStream` read forward. The walker reads
    it with ``seekable=False``, so it only reads; archivey skips member data."""

    def __init__(self, forward: ForwardStream) -> None:
        self.forward = forward

    def read(self, n: int = -1, /) -> bytes:
        return self.forward.read(n)


class _Collector:
    """What ``TarReader._to_member`` emits through, sent to ``ReaderContext.report``.
    The contexts it builds name the archive and the member's index already."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def emit(
        self,
        *,
        code: DiagnosticCode,
        message: str,
        context: DiagnosticContext,
        member: ArchiveMember | None = None,
        **_: Any,
    ) -> None:
        self._context.report(code, message, context, member=member)


class _MemberTyper:
    """``TarReader._to_member`` and the helpers it calls, bound to a reader context in
    place of a ``TarReader``: the same code types the member on either shape."""

    _to_member = tar_reader.TarReader._to_member
    _decode_name = tar_reader.TarReader._decode_name
    _decode_not_utf8 = tar_reader.TarReader._decode_not_utf8
    _owner_name = tar_reader.TarReader._owner_name
    _extra_pax_headers = tar_reader.TarReader._extra_pax_headers
    _pax_headers_text = tar_reader.TarReader._pax_headers_text
    _emit_link_data_ignored = tar_reader.TarReader._emit_link_data_ignored
    _emit_member_type_unknown = tar_reader.TarReader._emit_member_type_unknown
    _emit_timestamp_invalid = BaseArchiveReader._emit_timestamp_invalid
    _emit_name_encoding_inferred = BaseArchiveReader._emit_name_encoding_inferred
    _emit_directory_data_ignored = BaseArchiveReader._emit_directory_data_ignored

    def __init__(self, context: ReaderContext) -> None:
        self._encoding = context.encoding
        self._codec = context.encoding or "utf-8"
        self._archive_name = context.archive_name
        self._diagnostics_collector = _Collector(context)
        self._shared_pax: Any = None


class _StoredChunks(ReadOnlyIOStream):
    """A sparse member's stored chunks: the next ``length`` bytes of the walk's
    stream, read while the walk is at them."""

    def __init__(self, forward: ForwardStream, length: int) -> None:
        super().__init__()
        self._forward = forward
        self._left = length

    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed member stream")
        n = check_read_size(n)
        want = self._left if n < 0 else min(n, self._left)
        data = self._forward.read(want)
        self._left -= len(data)
        return data

    @property
    def left(self) -> int:
        return self._left


class TarSequentialReader(SequentialReader):
    link_target_in_data = False

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        # A walk's state is its own (the walker, the typer's shared PAX cache): a
        # random access to a sparse member walks again while this walk is open.
        typer: Any = _MemberTyper(self._context)
        walker = TarWalker(cast(BinaryIO, _ForwardFile(stream)), seekable=False)
        index = 0
        while True:
            entry = walker.next_entry()
            if isinstance(entry, TarEnd):
                _check_end(entry, index)
                return
            member = typer._to_member(entry, index)
            # The walker read the header blocks: the stream is at the data, or past
            # it when the walker held the block after a link header.
            yield _span(member, entry, stream)
            # archivey read or skipped the data: the walker carries on from there.
            walker._stream_pos = stream.offset
            index += 1


def _span(member: ArchiveMember, entry: TarEntry, stream: ForwardStream) -> MemberSpan:
    sparse = entry.sparse
    if sparse is None:
        return MemberSpan(member, entry.stored_size)
    error = validate_sparse_map(
        sparse, entry.size, entry.stored_size, quoted(member.name)
    )
    if error is not None:
        raise error
    chunks = _StoredChunks(stream, entry.stored_size)
    data = SparseStream(
        chunks,  # type: ignore[arg-type]
        sparse.offsets,
        sparse.lengths,
        entry.size,
    )
    return MemberSpan(member, 0, data=data)


def _check_end(end: TarEnd, members: int) -> None:
    """The walk's end, as far as this prototype checks it."""
    if end.kind is TarEndKind.ZERO_BLOCK or (end.kind is TarEndKind.ABSENT and members):
        return
    if end.kind is TarEndKind.SHORT:
        raise TruncatedError(
            f"TAR archive is truncated: {end.observed_bytes} bytes of a header block "
            f"at offset {end.offset}"
        )
    raise CorruptionError(
        f"TAR archive has a block that is no header at offset {end.offset}"
        + (f" ({end.reason})" if end.reason else "")
    )


class TarSequentialHandler(SequentialFormatHandler):
    format: ClassVar[ArchiveFormat] = TAR_SEQUENTIAL

    def open_sequential(self, context: ReaderContext) -> TarSequentialReader:
        return TarSequentialReader(context)
