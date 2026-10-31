"""UDIF disk images (``.dmg``): recognise the ``koly`` block, and refuse the image.

A compressed image stores its blocks as ordinary zlib, bzip2 or xz streams. The
first of those is a real stream, so a prefix read extracts one block and calls
the rest of the image trailing data. The image itself is the 512-byte ``koly``
block: at offset 0 on an old image, or at the end on every image the backup
scan found. Reading the blocks is a separate feature. This module exists so
detection can name the image and ``open_archive`` can refuse it.
"""

from __future__ import annotations

from archivey.config import ArchiveyConfig
from archivey.exceptions import UnsupportedFeatureError
from archivey.internal.base_reader import BaseArchiveReader, ReadBackend
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.open_site import OpenSite
from archivey.internal.overrides import override
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    MemberStreams,
    TrailerSignature,
)

# 7-Zip's ``IsKoly``: the four bytes ``koly``, then version 4 and a header size
# of 512, both big-endian. Version or size other than those is not this format.
_KOLY = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")
_TRAILER_LENGTH = 512

UDIF_UNSUPPORTED_MESSAGE = (
    "The file is a UDIF disk image (.dmg). Reading UDIF images is not supported."
)


class UdifBackend(ReadBackend):
    """Names a UDIF image so ``open_archive`` can refuse it. Does not read one."""

    FORMATS = (ArchiveFormat.DMG,)
    # No ``.dmg`` extension. A file with that name and no koly block is whatever
    # its bytes are (often a zip). The block is the claim, not the name.
    MAGIC = (MagicSignature(0, _KOLY, ArchiveFormat.DMG),)
    TRAILER = (
        TrailerSignature(
            _TRAILER_LENGTH,
            _KOLY,
            ArchiveFormat.DMG,
            # The first block of a compressed image is one of these streams.
            preempts=(ArchiveFormat.BZ2, ArchiveFormat.XZ),
        ),
    )
    READ_IMPLEMENTED = False
    UNSUPPORTED_MESSAGE = UDIF_UNSUPPORTED_MESSAGE
    # Nothing reads the image, and open refuses before the seekability check.
    # The flag only feeds ``required_source``. ``FORWARD_ONLY`` keeps the
    # published spool recipe from copying a file that is refused either way.
    SUPPORTS_STREAMING_NON_SEEKABLE = True

    @override
    def open_read(
        self,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        passwords: _PasswordCandidates | None,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
        start_offset: int = 0,
    ) -> BaseArchiveReader:
        # ``open_archive`` refuses before it asks the registry. This is the same
        # answer for a caller that reaches the backend anyway. The unused
        # parameters are the ``ReadBackend.open_read`` signature.
        raise UnsupportedFeatureError(
            UDIF_UNSUPPORTED_MESSAGE,
            source_format=format,
            archive_name=archive_name,
        )


register_reader(UdifBackend)
