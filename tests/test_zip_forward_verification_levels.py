"""Levels a streaming ZIP pass proves (``verification-level-redesign``, task 3.3b).

A forward pass over a ZIP checks each member it decodes against the CRC in its local
header or data descriptor, whether the caller reads the member or the pass decodes it
on its own. That check raises the member, and the central directory read at the end
of the pass does not undo it: a level never falls.
"""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from archivey import Verification, open_archive
from archivey.types import ArchiveMember
from tests.streams_util import NonSeekableBytesIO

_CHECKED = (Verification.CHECKSUM, Verification.CHECKSUM)
_FILES = {"a": b"first " * 1000, "b": b"second"}


class _Unseekable(io.RawIOBase):
    """A writer that cannot seek, so ``zipfile`` writes a data descriptor."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def _zip(method: int, *, descriptors: bool) -> bytes:
    out: io.RawIOBase | io.BytesIO = _Unseekable() if descriptors else io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as zf:
        for name, data in _FILES.items():
            zf.writestr(name, data)
    if isinstance(out, _Unseekable):
        return bytes(out.data)
    assert isinstance(out, io.BytesIO)
    return out.getvalue()


def _levels(members: list[ArchiveMember]) -> dict[str, tuple[Verification, ...]]:
    return {m.name: (m.verified, m.verifiable) for m in members}


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptor", "sized"])
@pytest.mark.parametrize(
    "method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED], ids=["deflate", "stored"]
)
def test_a_pass_read_reaches_checksum_and_keeps_it(
    method: int, descriptors: bool
) -> None:
    data = _zip(method, descriptors=descriptors)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == _FILES[member.name]
            assert (stream.verified, stream.verifiable) == _CHECKED
            seen.append(member)
    # The central directory, read after the last member, does not lower them.
    assert _levels(seen) == dict.fromkeys(_FILES, _CHECKED)


def test_a_member_the_pass_decodes_on_its_own_is_raised() -> None:
    # The pass decodes a short member it passes, to keep it in case the directory
    # makes it a link, and checks it against its descriptor's CRC.
    data = _zip(zipfile.ZIP_DEFLATED, descriptors=True)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        report = reader.members_report()
    assert report.error is None
    levels = _levels(list(report.members))
    assert levels["b"] == _CHECKED
    for verified, verifiable in levels.values():
        assert verified <= verifiable


def test_a_descriptor_crc_that_does_not_match_raises_nothing() -> None:
    raw = bytearray(_zip(zipfile.ZIP_DEFLATED, descriptors=True))
    # b's data descriptor: signature, then its CRC-32.
    at = raw.rindex(b"PK\x07\x08") + 4
    (crc,) = struct.unpack_from("<I", raw, at)
    struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    with open_archive(NonSeekableBytesIO(bytes(raw)), streaming=True) as reader:
        report = reader.members_report()
    levels = _levels(list(report.members))
    assert levels["b"][0] < Verification.LENGTH
