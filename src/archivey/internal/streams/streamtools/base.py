"""Shared bases for archivey's read-only stream wrappers.

``io.RawIOBase``'s defaults are the wrong way round for a *wrapper*: ``readable``/``writable``/
``seekable`` default to ``False``, and ``read``/``readall`` are implemented in terms of
``readinto``. Every read-only wrapper would otherwise re-declare ``readable()->True`` /
``writable()->False`` and supply a ``readinto``. These bases invert that once:

- :class:`ReadOnlyIOStream` provides the read-only surface (``readable``/``writable``/``write``)
  and a single canonical ``readinto``/``readall`` built on the subclass's ``read``. A subclass
  implements ``read`` (+ whatever it actually changes); ``read`` is left abstract so a subclass
  that forgets it fails loudly instead of looping through ``RawIOBase``.
- :class:`DelegatingStream` additionally holds one inner ``BinaryIO`` and forwards
  ``read``/``readinto``/``seek``/``tell``/``seekable``/``close`` to it, so a wrapper that only
  changes one operation overrides just that method.

``close()`` also runs on a half-built instance: ``IOBase.__del__`` calls it on any
instance not marked closed, including one whose ``__init__`` raised. So a stream's
``__init__`` assigns everything ``close()`` reads before anything that can raise, or
releases what it holds and marks itself closed before re-raising. A class that breaks
this dies a second time at collection, as an ``AttributeError`` blamed on whatever runs
then. ``tests/test_refused_constructor_close.py`` keeps an inventory of every stream
class against this rule.

This module is part of the codec-/format-agnostic ``streamtools`` core: it imports only from
``streamtools`` itself (``is_seekable``), nothing from the rest of ``archivey``.
The source boundary's full-count guarantee lives outside this package, in
``archivey.internal.source``.
"""

from __future__ import annotations

import abc
import io
from typing import TYPE_CHECKING, BinaryIO, Never

from archivey.internal.streams.streamtools.binaryio import (
    is_seekable,
    read_blocking,
    readinto_via_read,
    source_name,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer


class ReadOnlyIOStream(io.RawIOBase, BinaryIO):
    """Base for a read-only ``BinaryIO``: subclasses implement ``read`` (and what they change).

    Deliberately defines only the *read-only surface* (``read``/``readinto``/``readall`` +
    ``readable``/``writable``/``write``). It does **not** define ``seek``/``tell``/``seekable``/
    ``close``: those genuinely vary per wrapper — sequential vs. seekable, owns-its-inner vs. a
    non-owning view — so subclasses declare them, or inherit ``RawIOBase``'s non-seekable
    defaults (``seekable()->False``, ``seek`` raising). :class:`DelegatingStream` supplies the
    forwarding versions for wrappers that do own one inner stream.
    """

    @abc.abstractmethod
    def read(self, n: int = -1, /) -> bytes:
        # The internal contract takes an int. ``read(None)`` (read to EOF, the ``io``
        # contract) is accepted at the public boundary, ``ArchiveStream.read``, which
        # passes ``-1`` inward; the streams that also accept ``None`` do so as a
        # convenience, and a new stream need not.
        # @abstractmethod marks the subclass contract. On Python 3.12+ ABCMeta already
        # rejects constructing a subclass that omits read(); on 3.11, io.RawIOBase's C
        # __new__ still allows construction, so this body is the runtime guard — a
        # forgotten read() fails loudly instead of looping via RawIOBase.
        raise NotImplementedError

    def readinto(self, b: WriteableBuffer, /) -> int:
        """Canonical ``readinto``: read into ``b`` via the subclass's ``read``."""
        return readinto_via_read(self, b)

    def readall(self) -> bytes:
        chunks = bytearray()
        while True:
            chunk = self.read(io.DEFAULT_BUFFER_SIZE)
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def write(self, b: object, /) -> int:
        raise io.UnsupportedOperation("write")

    @property
    def mode(self) -> str:
        """Always ``"rb"``: every stream here is read-only binary by construction.

        Like :meth:`name`, this override exists because ``typing.BinaryIO`` is in our
        MRO. ``typing.IO.mode`` is a real runtime property whose body returns ``None``,
        so a subclass that does not override it advertises ``mode = None`` rather than
        having no ``mode`` at all. Libraries that duck-type it break on that: pycdlib
        does ``'b' not in fp.mode``, which raises ``TypeError`` on ``None``.

        Unlike :meth:`name`, there is a correct answer for every stream in this module,
        so this one returns a value instead of raising.
        """
        return "rb"

    @property
    def name(self) -> Never:
        """Always raises :exc:`AttributeError`. The raise *is* the contract.

        Deleting this property does **not** remove the attribute. ``typing.BinaryIO``
        is in our MRO and ``typing.IO.name`` is a real runtime property returning
        ``None``, so a subclass that does not override it advertises ``name = None``
        to duck-typing consumers — worse than absence, because ``hasattr`` says yes
        and the value is unusable. pycdlib on Windows does
        ``fp.name.startswith(...)`` on a device path and raises ``AttributeError`` on
        exactly that.

        ``typing.IO`` declaring ``name`` at all is arguably a typing bug, because the
        stdlib treats it as optional: ``open(path, "rb").name`` is the path, while
        ``io.BytesIO()`` and ``io.BufferedReader(io.BytesIO())`` have no ``name``
        attribute whatsoever. Streams without a real path must match that duck-typing
        surface, so raising is how we opt back out of the declaration.

        We keep the ``BinaryIO`` base regardless — it is what makes these wrappers
        nominally ``BinaryIO`` for the checkers, which is the point of having it.
        Dropping it costs 64 errors on both pyrefly and ty (measured 2026-09-11) and
        would mean replacing ``typing.BinaryIO`` with a Protocol across the internal
        surface.

        ``Never`` is the honest return type: this returns nothing, ever. It is also
        why the subclasses that *do* have a path (:class:`DelegatingStream` here, and
        ``ArchiveSource`` and ``ArchiveStream`` outside this package) need
        ``# pyrefly: ignore[bad-override]`` and
        ``# ty: ignore[invalid-property-type-override]``: widening ``Never`` to
        ``str`` is a deliberate LSP exception, not an oversight.

        Do not "fix" this by returning a string or ``None``. See :meth:`mode`, which
        overrides the same ``typing.IO`` stub for the same reason.
        """
        raise AttributeError("name")


class DelegatingStream(ReadOnlyIOStream):
    """A read-only wrapper around one inner ``BinaryIO``, forwarding to it by default.

    Subclasses override only the method whose behavior they change (e.g. just ``seek`` to add a
    warning, or just ``close`` to add a cleanup guard).

    All three flags are a class default with a constructor override. Production
    subclasses set the class flag and omit the kwarg; ad-hoc construction may
    pass the kwarg. ``__init__`` uses the class value when the kwarg is omitted.
    ``peel_for_source_size`` reports the resolved instance value under the same
    public name, because code outside the class reads it by that name
    (:func:`source_byte_size` does a ``getattr``); ``readinto_passthrough`` shadows
    the same way. The close flag follows the constant form instead: the class
    default is ``_SUBCLASS_CLOSES_INNER`` and the resolved instance copy is
    ``_subclass_closes_inner``, so the constant only ever means the default.

    ``peel_for_source_size`` is an opt-in for pass-through wrappers whose cheap size
    *is* the inner's (a seek counter on ``ZipFile.fp``). :func:`source_byte_size`
    peels those and never every :class:`DelegatingStream` — a transforming wrapper
    (decrypt, BCJ, ``OutputCountingStream`` on a decompressor) must not report the
    underlying file's size as its own. Subclasses set ``peel_for_source_size = True``.
    Setting it also asserts that a seek on the wrapper costs what a seek on its inner
    costs: ``archivey.internal.source.seek_is_expensive`` peels the same layers to
    decide whether a seek may re-decode, so a wrapper that changes seek cost (a spool
    that makes it cheaper, a layer that makes it dearer) must not opt in.

    **Consistency caveat (``readinto_passthrough``).** By default ``readinto`` forwards straight
    to ``inner.readinto`` (zero-copy), which *bypasses this class's ``read``*. That is correct
    for a plain delegator, but a subclass that overrides ``read`` with a side effect (tracking
    bytes, hashing, a check at EOF) would have that side effect skipped on ``readinto``-driven
    reads. Such a subclass MUST set ``readinto_passthrough = False``, which routes ``readinto``
    through ``read`` (the :class:`ReadOnlyIOStream` implementation) so the override always runs.
    (We use an explicit flag rather than auto-detecting an overridden ``read``: a plain
    pass-through override of ``read`` should keep the zero-copy path, and silent auto-detection
    would make that choice invisible and bug-prone.)

    **Close ownership.** A :class:`DelegatingStream` *owns* its inner: ``close``
    closes ``inner`` and then marks this wrapper closed. That is the opposite of
    :class:`~archivey.internal.streams.streamtools.slice.SlicingStream` /
    :class:`~archivey.internal.streams.streamtools.slice.SharedView`, which borrow
    unless told otherwise. The owning default is load-bearing — every production
    subclass sits in a close chain that must reach the inner (a TAR sparse
    member's view, a ``PyCdlibIO``, a measured source, an accelerator). Flipping it to
    borrow would make a forgotten keyword a leak the leak oracle does not pin
    (it ignores default DelegatingStream constructors). A wrapper that must not
    close what it wraps is not a ``DelegatingStream``: the source boundary's
    :class:`~archivey.internal.source.ArchiveSource` borrows the caller's stream by
    being its own class. See ``dev-docs/topics/stream-ownership.md``.

    A subclass that must close ``inner`` itself (a finalize guard, reaping a
    subprocess) sets ``_SUBCLASS_CLOSES_INNER = True`` and calls
    ``super().close()`` afterwards to mark the wrapper closed without closing
    ``inner`` a second time. That flag is *who performs the close*, not whether
    the wrapper owns — both values own. Ad-hoc construction may pass
    ``subclass_closes_inner=True`` to override the class default. Subclasses
    that only need to hold a lock around close wrap ``super().close()`` in the
    lock instead.
    """

    # Opt-in class flag; :func:`source_byte_size` peels only when this is True.
    # Inventory test reads this; ``__init__`` uses it when the kwarg is omitted.
    peel_for_source_size: bool = False
    # Class-level readinto contract. False: route readinto through this class's
    # read() so a side-effecting override is not bypassed. Inventory test reads
    # this; ``__init__`` uses it when the kwarg is omitted.
    readinto_passthrough: bool = True
    # Class-level close contract. True: the subclass closes ``_inner`` itself.
    # Inventory test reads this; ``__init__`` uses it when the kwarg is omitted.
    _SUBCLASS_CLOSES_INNER: bool = False

    def __init__(
        self,
        inner: BinaryIO,
        *,
        peel_for_source_size: bool | None = None,
        readinto_passthrough: bool | None = None,
        subclass_closes_inner: bool | None = None,
    ) -> None:
        super().__init__()
        self._inner = inner
        if peel_for_source_size is None:
            peel_for_source_size = type(self).peel_for_source_size
        # Instance shadows the class flag so a constructor override is visible
        # to :func:`source_byte_size`'s ``getattr(..., "peel_for_source_size")``.
        self.peel_for_source_size = peel_for_source_size
        if readinto_passthrough is None:
            readinto_passthrough = type(self).readinto_passthrough
        # Instance shadows the class flag so a constructor override is the
        # value ``readinto`` and ``getattr`` see, matching peel.
        self.readinto_passthrough = readinto_passthrough
        # True when the subclass closes ``_inner`` itself (finalize guard, reap a
        # subprocess) and then calls ``super().close()`` only to mark this wrapper closed.
        # Not an ownership flag: the wrapper owns in both cases.
        if subclass_closes_inner is None:
            subclass_closes_inner = type(self)._SUBCLASS_CLOSES_INNER
        self._subclass_closes_inner = subclass_closes_inner
        # Cached at construction; a subclass that swaps ``_inner`` must go through
        # ``_replace_inner`` so seekable() tracks the new engine. Keep this last: the
        # inner's seekable() can raise, and the half-built stream's close() (from
        # __del__ or a subclass's cleanup) needs every field above.
        self._seekable = is_seekable(inner)

    def _replace_inner(self, inner: BinaryIO) -> None:
        """Swap the inner stream, recaching anything derived from it, and close the old
        one best-effort: the new one has taken over. A ``subclass_closes_inner`` stream
        closes the old one itself, as it does in ``close``; this method does not hand
        it back, so such a subclass captures ``self._inner`` before the call."""
        old, self._inner = self._inner, inner
        self._seekable = is_seekable(inner)
        if self._subclass_closes_inner:
            return
        try:
            old.close()
        except Exception:  # noqa: BLE001, S110 - best-effort; the new inner took over
            pass

    def read(self, n: int = -1, /) -> bytes:
        # A non-blocking inner's ``None`` ("nothing yet") is refused with
        # ``BlockingIOError``, as ``readinto`` already does via ``try_readinto``;
        # passing it on would hand callers a non-bytes they would take for EOF.
        return read_blocking(self._inner, n)

    def readinto(self, b: WriteableBuffer, /) -> int:
        # Zero-copy passthrough when allowed and the inner exposes a usable
        # readinto; otherwise route through self.read() so an overridden
        # read() is not bypassed. try_readinto treats a missing, refused, or
        # NotImplemented inner readinto as "not usable".
        if self.readinto_passthrough:
            n = try_readinto(self._inner, b)
            if n is not None:
                return n
        return super().readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._inner.seek(offset, whence)

    def tell(self, /) -> int:
        return self._inner.tell()

    def seekable(self) -> bool:
        # is_seekable() handles the edge cases a bare inner.seekable() misses (a BufferedReader
        # over a non-seekable raw; a pipe that reports seekable()=True but cannot reposition).
        # Cached at construction; a subclass that swaps ``_inner`` must go through
        # ``_replace_inner``.
        return self._seekable

    def close(self) -> None:
        if self.closed:
            return
        try:
            if not self._subclass_closes_inner:
                self._inner.close()
        finally:
            super().close()

    @property
    def name(self) -> str:  # pyrefly: ignore[bad-override]  # ty: ignore[invalid-property-type-override]  # base is Never; this returns a path when the inner has one
        """Path of the inner stream, or raise :exc:`AttributeError` if it has none.

        Raising keeps ``hasattr(..., "name")`` false when the inner is nameless
        (the :class:`ReadOnlyIOStream` contract). Returning ``None`` would make
        ``hasattr`` true and crash pycdlib's Windows ``fp.name.startswith(...)``.
        """
        resolved = source_name(self._inner)
        if resolved is not None:
            return resolved
        raise AttributeError("name")
