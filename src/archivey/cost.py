"""Access-cost types: the `CostReceipt` and its enums.

Access *mode* is not modelled here — it is the plain ``streaming: bool`` and
``pipe: bool`` parameters of ``open_archive`` (``streaming=False`` = random access;
``streaming=True`` = forward-only, single pass; ``pipe=True`` = a single pass read as a
pipe is read, the only mode that takes a non-seekable source). This module is only the
cost half of the ``access-mode-and-cost`` capability.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from enum import Enum


class ListingCost(Enum):
    """How expensive it is to *enumerate* all members (list names + metadata).

    The value names how the member list is read through the source the archive was
    opened on: from an index, by walking member headers, or by decompressing. It does
    not count the work of finding the index: a ZIP whose end record sits behind a long
    tail is walked to find its central directory and is still ``INDEXED``. Nor does it
    say when the work is paid: a backend may do it inside ``open_archive`` and serve
    ``members()`` from memory (RAR). One format can need different work on different
    sources: a ZIP read from a pipe is ``REQUIRES_SCANNING``. The value is set per
    backend and source, so a damaged archive listed by a fallback walk (a ZIP whose
    directory is gone) keeps its backend's value.
    """

    INDEXED = "indexed"
    """Members can be listed without scanning header-to-header or decompressing payload.

    Examples: ZIP central directory, 7z header, ISO directory tree at open, and a
    single-file compressed stream (gzip, xz, …), whose one member is known from the
    header without decompressing. A filesystem directory is **not** indexed (its walk
    is ``REQUIRES_SCANNING``).
    """

    REQUIRES_SCANNING = "requires_scanning"
    """No index, but members can be enumerated by seeking/scanning header-to-header
    without decompressing payload (e.g. an uncompressed tar, a RAR archive, or a
    filesystem directory walk).

    RAR walks its headers inside ``open_archive``, so ``members()`` then returns from
    memory.
    """

    REQUIRES_DECOMPRESSION = "requires_decompression"
    """The stream must be decompressed to reach the member headers (e.g. a compressed tar)."""


class AccessCost(Enum):
    """How expensive it is to *read* one member's data, given the format layout."""

    DIRECT = "direct"
    """Any member can be read without touching other members."""

    SOLID = "solid"
    """Reading member N may require decompressing earlier members in its solid block."""


@functools.total_ordering
class StreamCapability(Enum):
    """A property of the underlying *source* bytes, independent of the format layout.

    **Ordered by strength**, weakest first: ``FORWARD_ONLY < SEEKABLE``. There is only
    one possible direction — a seekable source can serve every read a forward-only one
    can — so the comparison means "is at least as strong as", not a preference. That is
    what lets a requirement stated as a capability (``FormatAvailability.required_source``)
    be tested against a source's actual capability (``CostReceipt.stream_capability``)
    with ``<=`` instead of a lookup table.

    ``ListingCost`` and ``AccessCost`` are deliberately *not* ordered: their members name
    kinds of work, not strengths of one resource.
    """

    SEEKABLE = "seekable"
    """The source supports arbitrary ``seek()``; positions can be revisited."""

    FORWARD_ONLY = "forward_only"
    """Non-seekable source (pipe/socket): it cannot be rewound at all. Re-reading any
    earlier position requires a brand-new stream."""

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, StreamCapability):
            return NotImplemented
        return _STREAM_CAPABILITY_ORDER.index(self) < _STREAM_CAPABILITY_ORDER.index(
            other
        )


# Weakest first. Declared after the class because the members do not exist until it is
# built; `total_ordering` fills in <=, > and >= from `__lt__` above.
_STREAM_CAPABILITY_ORDER: tuple[StreamCapability, ...] = (
    StreamCapability.FORWARD_ONLY,
    StreamCapability.SEEKABLE,
)


@dataclass(frozen=True)
class CostReceipt:
    """Machine-readable description of an opened archive's access costs.

    The three axes are **orthogonal** and must not be conflated: ``listing_cost`` is about
    enumeration, ``access_cost`` about the format layout, and ``stream_capability`` about
    the source bytes. See the ``access-mode-and-cost`` capability spec for the full model.
    """

    listing_cost: ListingCost
    """Cost of enumerating all members."""

    access_cost: AccessCost
    """Cost of reading one member's data, given the format layout."""

    stream_capability: StreamCapability
    """Seekability of the underlying source bytes."""

    solid_block_count: int | None = None
    """Number of distinct solid blocks (each one decompress pass), or ``None`` when not
    applicable / unknown. ``is_solid`` lives on ``ArchiveInfo``, not here, to avoid
    duplicating the flag."""

    notes: tuple[str, ...] = field(default_factory=tuple)
    """Human-readable caveats about the cost figures."""


#: The public names of this module. The most used of them are also re-exported at
#: the package root (see archivey.__all__).
__all__ = [
    "AccessCost",
    "CostReceipt",
    "ListingCost",
    "StreamCapability",
]
