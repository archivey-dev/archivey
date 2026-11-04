"""The StreamCodec object is the single source of truth for a single-stream codec.

Registering one synthetic StreamCodec subclass must make a new standalone codec detectable,
readable as a one-member archive, and availability-reported — without touching the detector,
the single-file reader, or the registry's availability logic (see ``compressed-streams``).
"""

from __future__ import annotations

import io
import os
from collections.abc import Generator
from contextlib import contextmanager

from archivey import open_archive
from archivey.internal.detection import DetectionConfidence, detect_format
from archivey.internal.format_adapter import registration_scope
from archivey.internal.registry import format_availability, get_registry
from archivey.internal.streams import codecs
from archivey.internal.streams.codecs.registry import add_stream_codec
from archivey.internal.streams.streamtools import ensure_binaryio
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    FormatSupport,
    MagicSignature,
    MissingComponent,
    PluginStream,
)

# The synthetic codec stores its payload verbatim behind a unique 6-byte magic, so detection
# matches on the magic and reading is a passthrough whose output equals the stored payload.
_MAGIC = b"SYNTH\x00"


class _SyntheticStream(PluginStream):
    SYNTHETIC = "syn"


# A bare ArchiveFormat (not one of the named singletons) for the synthetic standalone format.
_FORMAT = ArchiveFormat(ContainerFormat.RAW_STREAM, _SyntheticStream.SYNTHETIC)


@contextmanager
def _install_synthetic(
    *,
    requirement: MissingComponent | None,
    available: bool = True,
) -> Generator[ArchiveFormat, None, None]:
    """Add one synthetic StreamCodec subclass to the codec list, then restore on exit."""

    class SyntheticCodec(codecs.StreamCodec):
        codec = _SyntheticStream.SYNTHETIC
        stream_format = _SyntheticStream.SYNTHETIC
        # single_file_format (== _FORMAT) and extensions (".syn") are derived from
        # stream_format by the base class — no need to declare them.
        magic = (MagicSignature(0, _MAGIC, _FORMAT),)

        def open(self, source, params, config):  # type: ignore[no-untyped-def]
            if isinstance(source, (str, os.PathLike)):
                return open(os.fspath(source), "rb")
            return ensure_binaryio(source)

        def extract_metadata(self, ctx, member):  # type: ignore[no-untyped-def]
            # Prove the codec's metadata hook runs through the reader's context.
            member.extra["synthetic.header_len"] = len(ctx.peek_header(len(_MAGIC)))

        def _backend_present(self) -> bool:
            return available

    SyntheticCodec.requirement = requirement
    # The one call a codec takes: the detector, the single-file reader, the TAR pairs
    # and the registry read the codec list when asked.
    with registration_scope():
        add_stream_codec(SyntheticCodec())
        get_registry().codecs_changed()
        yield _FORMAT


def test_synthetic_descriptor_is_detectable_and_readable() -> None:
    payload = b"hello from a one-descriptor codec"
    data = _MAGIC + payload
    with _install_synthetic(requirement=None) as fmt:
        # 1. Detected by its codec's magic, no detector edits.
        info = detect_format(io.BytesIO(data))
        assert info.format == fmt
        assert info.confidence == DetectionConfidence.CERTAIN
        assert info.detected_by == "magic"

        # 2. Read as a one-member archive through the single-file reader, no reader edits.
        with open_archive(io.BytesIO(data)) as ar:
            assert ar.format == fmt
            members = ar.members()
            assert len(members) == 1
            assert members[0].is_file
            # The codec's metadata hook ran via the reader's context.
            assert members[0].extra["synthetic.header_len"] == len(_MAGIC)
            assert ar.read(members[0]) == data  # passthrough codec stores verbatim

        # 3. Availability reported FULL (no requirement -> always available).
        assert format_availability(fmt).support is FormatSupport.FULL


def test_synthetic_descriptor_availability_comes_from_requirement() -> None:
    requirement = MissingComponent(
        "synthlib", "pip install archivey[synth]", ("synthetic",)
    )
    with _install_synthetic(requirement=requirement, available=False) as fmt:
        # The (simulated) missing backend makes the single-codec format unreadable -> NONE,
        # with the install hint taken from the codec's requirement (no registry table).
        availability = format_availability(fmt)
        assert availability.support is FormatSupport.NONE
        assert availability.missing == (requirement,)
