"""Note the working set a library-checked stream declares, for the reader's record.

liblzma (LZMA Alone) and libzstd read the dictionary or window a stream declares
themselves, and refuse one over ``max_decoder_memory`` before they allocate it, so
archivey never sees the number. A nest of archives (``ReaderContext.open_nested``)
needs it: its levels' decoders share ``max_decoder_memory``, and an archive inside
this stream's output gets the cap less what this decoder declared
(``_PluginAdapter._nested_config``). xz notes its block header in ``_XzState``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archivey.formats import Decompressor
    from archivey.internal.resource_usage import ResourceUsageRecorder


class NotingDecompressor:
    """``inner``, noting to ``usage`` what the first ``header_size`` bytes fed to it
    declare: ``declared(head)`` is the number, or ``None`` when ``head`` declares
    nothing it can read yet. ``what`` names it in the record.

    A stream shorter than ``header_size`` notes what ``declared`` finds in it at its
    end, or nothing.
    """

    def __init__(
        self,
        inner: Decompressor,
        usage: ResourceUsageRecorder,
        *,
        header_size: int,
        declared: Callable[[bytes], int | None],
        what: str,
    ) -> None:
        self._inner = inner
        self._usage = usage
        self._header_size = header_size
        self._declared = declared
        self._what = what
        # The bytes fed so far, up to ``header_size``; ``None`` once noted.
        self._head: bytearray | None = bytearray()

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        head = self._head
        if head is not None:
            head += data[: self._header_size - len(head)]
            full = len(head) >= self._header_size
            declared = self._declared(bytes(head))
            if declared is not None or full or not data:
                self._head = None
                if declared is not None:
                    self._usage.note_decoder_memory(declared, self._what)
        return self._inner.decompress(data, max_length)

    @property
    def eof(self) -> bool:
        return self._inner.eof

    @property
    def unused_data(self) -> bytes:
        return self._inner.unused_data

    @property
    def needs_input(self) -> bool:
        return self._inner.needs_input


def noting(
    inner: Decompressor,
    usage: ResourceUsageRecorder | None,
    *,
    header_size: int,
    declared: Callable[[bytes], int | None],
    what: str,
) -> Decompressor:
    """``inner`` in a :class:`NotingDecompressor`, or as it is with no ``usage``."""
    if usage is None:
        return inner
    return NotingDecompressor(
        inner, usage, header_size=header_size, declared=declared, what=what
    )
