"""A cut CAB or XAR reads the same whether or not the source's size is known.

Both readers check a cut against the source's size. A seekable stream archivey does
not recognize (a socket wrapper, a user-written file object) has no size it can learn
cheaply, so the check was skipped. A CAB folder whose data blocks start past the end
then raised ``TruncatedError`` from a member read where a known-size source read the
member as empty. An XAR member cut inside its data reached the codec, which reported
``CorruptionError`` where a known-size source said ``TruncatedError``. And an offset
past what any file can hold, which a known size clamps to an empty read, was sought
and raised ``ValueError``. Found by the fuzz oracle that reads one input from a
``BytesIO`` and from a short-read source.
"""

from __future__ import annotations

import hashlib
import io
from collections.abc import Callable

import pytest

from archivey import ArchiveyError, open_archive
from archivey.internal.streams.streamtools.shared import SharedSource
from tests.atheris_fuzz import seeds
from tests.streams_util import ShortReadBytesIO


def _outcomes(source: io.RawIOBase | io.BytesIO) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        with open_archive(source) as reader:
            for member in reader:
                if not member.is_file:
                    continue
                try:
                    with reader.open(member) as stream:
                        result = hashlib.sha1(stream.read()).hexdigest()[:12]
                except ArchiveyError as exc:
                    result = type(exc).__name__
                out.append((member.name, result))
    except ArchiveyError as exc:
        out.append(("<open>", type(exc).__name__))
    return out


def _cuts(data: bytes) -> list[int]:
    # Every 7th length, plus the last 64: inside headers, data and the end.
    return sorted(
        {*range(64, len(data), 7), *range(max(64, len(data) - 64), len(data))}
    )


@pytest.mark.parametrize("make", [seeds.cab_seeds, seeds.xar_seeds], ids=["cab", "xar"])
def test_cut_archive_reads_the_same_with_and_without_a_known_size(
    make: Callable[[], list[bytes]],
) -> None:
    checked = 0
    for seed in make():
        if len(seed) > 16 * 1024:
            continue
        for cut in _cuts(seed):
            # Cut, and cut with a damaged byte before the cut: the size check must
            # come before the codec sees either.
            flip = cut * 7 // 8
            damaged = seed[:flip] + bytes([seed[flip] ^ 0xFF]) + seed[flip + 1 : cut]
            for data in (seed[:cut], damaged):
                known = _outcomes(io.BytesIO(data))
                unknown = _outcomes(ShortReadBytesIO(data, max_chunk=1 << 16))
                assert known == unknown, f"cut at {cut} of {len(seed)}"
                checked += 1
    assert checked > 50


def test_a_read_past_any_file_offset_is_empty_on_a_source_of_unknown_size() -> None:
    # A squashfs image named a fragment table at 2**64 - 31. With a known size the
    # read was clamped to nothing; with none, seeking there raised ValueError
    # ("cannot fit 'int' into an offset-sized integer"), outside archivey's errors.
    source = SharedSource(ShortReadBytesIO(b"abc"))
    assert source.size is None
    assert source.read_at(2**64 - 31, 4) == b""
    with source.view(2**64 - 31, 4) as view:
        assert view.read() == b""
    with source.view(2**63) as view:
        assert view.read() == b""
