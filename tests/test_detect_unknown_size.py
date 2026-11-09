"""A content probe judges the same bytes the same with and without a known size.

A content probe sees only the detection window, so detection runs it again over the
whole source (``_probe_completes``) when the source fits the completion window. That
needed the source's size. A seekable stream archivey does not recognize (a socket
wrapper, a user-written file object) has no size it can learn cheaply, so its bytes
were accepted on the window alone. Random bytes that a ``BytesIO`` left undetected
came back as Brotli, and an archive behind a few junk bytes as Brotli instead of the
archive. Found by the fuzz oracle that reads one input from a ``BytesIO`` and from a
short-read source.
"""

from __future__ import annotations

import io
import random
import zipfile

import pytest

from archivey import ArchiveFormat, ArchiveyConfig, ArchiveyError, detect_format
from tests.streams_util import ShortReadBytesIO

_CONFIG = ArchiveyConfig(always_probe_content=True)


def _detected(source: io.BytesIO | ShortReadBytesIO) -> ArchiveFormat | str:
    try:
        return detect_format(source, config=_CONFIG).format
    except ArchiveyError as exc:
        return type(exc).__name__


def _noise(seed: int) -> bytes:
    # A Brotli-looking first byte, then noise: some of these decode for the whole
    # detection window and fail only further on.
    rng = random.Random(seed)
    first = rng.choice(b"\x0b\x1b\x2b\x8b\xcb\x21\x00\xff")
    return bytes([first]) + rng.randbytes(rng.choice([5000, 9000, 20000]))


@pytest.mark.parametrize("seed", [3, 5, 8, 22, 30])
def test_noise_is_detected_the_same_without_a_known_size(seed: int) -> None:
    data = _noise(seed)
    known = _detected(io.BytesIO(data))
    assert known != ArchiveFormat.BROTLI
    assert _detected(ShortReadBytesIO(data, max_chunk=1 << 16)) == known


def test_an_archive_behind_noise_is_detected_the_same_without_a_known_size() -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "hello " * 100)
    data = _noise(22) + archive.getvalue()
    known = _detected(io.BytesIO(data))
    assert _detected(ShortReadBytesIO(data, max_chunk=7)) == known


def test_a_source_past_the_completion_window_is_not_read_to_its_end() -> None:
    # Over the window, the probe's verdict stands on the window, as with a known size:
    # detection does not read a long source of unknown size to its end.
    data = _noise(22) + bytes(1 << 20)
    source = ShortReadBytesIO(data, max_chunk=1 << 16)
    _detected(source)
    assert source.tell() < len(data)
