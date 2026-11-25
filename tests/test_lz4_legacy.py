"""The legacy LZ4 stream (``lz4 -l``, Linux kernel images): detected and decoded.

``lz4.frame`` does not read this format, so archivey decodes its blocks with
``lz4.block`` (``internal/streams/codecs/lz4_legacy.py``). The streams here are built the way
the ``lz4`` command builds them: the magic, then each block of at most 8 MiB of input
compressed on its own, after its little-endian compressed size.
"""

from __future__ import annotations

import io
import subprocess
import tarfile
from pathlib import Path

import pytest

from archivey import ArchiveFormat, detect_format, open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs.lz4_legacy import (
    LEGACY_BLOCK_BOUND,
    LEGACY_BLOCK_SIZE,
    LEGACY_MAGIC,
)
from tests.conftest import requires, requires_binary
from tests.streams_util import NonSeekableBytesIO

pytestmark = requires("lz4")


def _block(chunk: bytes) -> bytes:
    import lz4.block

    body = lz4.block.compress(chunk, store_size=False)
    return len(body).to_bytes(4, "little") + body


def _legacy(data: bytes, block_size: int = LEGACY_BLOCK_SIZE) -> bytes:
    blocks = (data[i : i + block_size] for i in range(0, len(data), block_size))
    return LEGACY_MAGIC + b"".join(_block(chunk) for chunk in blocks)


def _payload(size: int) -> bytes:
    # Compressible but not trivially so, and different in every block.
    return b"".join(b"line %d of the payload\n" % i for i in range(size // 20))[:size]


def _read(data: bytes) -> tuple[ArchiveFormat, bytes, list[DiagnosticCode]]:
    with open_archive(io.BytesIO(data)) as ar:
        out = ar.read(ar.members()[0])
        codes = [d.code for d in ar.diagnostics.retained]
        return ar.format, out, codes


def test_multi_block_stream_is_detected_and_read() -> None:
    data = _payload(LEGACY_BLOCK_SIZE * 2 + 12345)
    fmt, out, codes = _read(_legacy(data))
    assert fmt == ArchiveFormat.LZ4
    assert out == data
    assert codes == []


def test_small_reads_cross_block_boundaries() -> None:
    data = _payload(3000)
    with open_archive(io.BytesIO(_legacy(data, block_size=700))) as ar:
        stream = ar.open(ar.members()[0])
        pieces = []
        while piece := stream.read(333):
            pieces.append(piece)
    assert b"".join(pieces) == data


def test_named_file_and_non_seekable_source(tmp_path: Path) -> None:
    data = _payload(5000)
    path = tmp_path / "vmlinux.lz4"
    path.write_bytes(_legacy(data))
    with open_archive(path) as ar:
        assert ar.members()[0].name == "vmlinux"
        assert ar.read(ar.members()[0]) == data
    with open_archive(NonSeekableBytesIO(_legacy(data)), pipe=True) as ar:
        for _member, stream in ar.stream_members():
            assert stream is not None
            assert stream.read() == data


def test_legacy_and_frame_streams_concatenate() -> None:
    import lz4.frame

    a, b, c = _payload(4000), b"framed middle", _payload(900)
    data = _legacy(a) + lz4.frame.compress(b) + _legacy(c)
    fmt, out, codes = _read(data)
    assert (fmt, out, codes) == (ArchiveFormat.LZ4, a + b + c, [])


def test_two_legacy_streams_concatenate() -> None:
    # The second magic, read as a block size, is over the bound, so it ends the first
    # stream (``cat a.lz4 b.lz4`` of two ``lz4 -l`` outputs).
    a, b = _payload(4000), _payload(900)
    assert _read(_legacy(a) + _legacy(b))[1:] == (a + b, [])


def test_zero_padding_after_the_stream_is_not_trailing_data() -> None:
    data = _payload(2000)
    for padding in (b"\x00", b"\x00" * 3, b"\x00" * 512):
        assert _read(_legacy(data) + padding)[1:] == (data, [])


def test_bytes_after_the_stream_are_reported() -> None:
    data = _payload(2000)
    _fmt, out, codes = _read(_legacy(data) + b"junk after the stream")
    assert out == data
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


@pytest.mark.parametrize("declared", [LEGACY_BLOCK_BOUND + 1, 0xFFFFFFFF])
def test_a_block_larger_than_any_writer_emits_ends_the_stream(declared: int) -> None:
    """A size field over ``LZ4_COMPRESSBOUND(8 MiB)`` is never buffered as a block.

    The field is 32 bits, so a crafted stream can declare 4 GiB; believing it would
    mean holding that much input before decoding a byte. Like the ``lz4`` command, the
    decoder takes such a field as the end of the stream, and what follows is reported.
    """
    data = _payload(2000)
    stream = _legacy(data) + declared.to_bytes(4, "little") + b"\x01" * 64
    _fmt, out, codes = _read(stream)
    assert out == data
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


def test_a_block_at_the_bound_is_read_as_a_block() -> None:
    # Incompressible input compresses to just over its own size; 8 MiB of it is the
    # largest block a writer emits, and must still be taken as one.
    import os

    data = os.urandom(LEGACY_BLOCK_SIZE)
    stream = _legacy(data)
    assert int.from_bytes(stream[4:8], "little") <= LEGACY_BLOCK_BOUND
    assert _read(stream)[1] == data


def test_a_block_that_decodes_past_8_mib_is_corrupt() -> None:
    stream = LEGACY_MAGIC + _block(b"\x00" * (LEGACY_BLOCK_SIZE + 1))
    with pytest.raises(CorruptionError):
        _read(stream)


def test_a_damaged_block_is_corrupt() -> None:
    stream = bytearray(_legacy(_payload(4000)))
    stream[8] = 0xFF  # the first token: a literal run past the block's end
    stream[9:20] = b"\xff" * 11
    with pytest.raises(CorruptionError):
        _read(bytes(stream))


@pytest.mark.parametrize("cut", [5, 6, 30])
def test_a_cut_stream_is_truncated(cut: int) -> None:
    # 5 and 6: inside the first size field; 30: inside the first block.
    stream = _legacy(_payload(4000))
    with pytest.raises(TruncatedError):
        _read(stream[:cut])


def test_a_cut_between_blocks_reads_short_with_no_error() -> None:
    """The legacy stream has no end mark, so a cut on a block boundary is invisible.

    ``lz4 -dc`` reads such a file the same way; the handbook records it as a format
    limitation (``zstd-lz4.md`` §2.3, §5).
    """
    data = _payload(4000)
    stream = _legacy(data, block_size=2000)
    first_block_end = 4 + 4 + int.from_bytes(stream[4:8], "little")
    _fmt, out, codes = _read(stream[:first_block_end])
    assert (out, codes) == (data[:2000], [])


def test_legacy_tar_is_tar_lz4() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        payload = b"inside a legacy tar.lz4"
        info = tarfile.TarInfo("inner.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    with open_archive(io.BytesIO(_legacy(buf.getvalue()))) as ar:
        assert ar.format == ArchiveFormat.TAR_LZ4
        assert ar.read("inner.txt") == payload


def test_legacy_tar_with_a_first_block_over_the_probe_bound_is_not_upgraded() -> None:
    """Content detection sees a legacy ``.tar.lz4`` as bare LZ4 when its first block is big.

    A legacy block yields nothing until all of it is read, and the inner-TAR probe reads
    at most 1 MiB of compressed input, so a first block that compresses to more than
    that leaves the probe with no header to see. The name still resolves ``.tar.lz4``.
    """
    import os

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        payload = os.urandom(3 * 2**20)
        info = tarfile.TarInfo("noise.bin")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    stream = _legacy(buf.getvalue())
    assert int.from_bytes(stream[4:8], "little") > 2**20
    assert detect_format(io.BytesIO(stream)).format == ArchiveFormat.LZ4


@requires_binary("lz4")
def test_the_lz4_command_s_legacy_output(tmp_path: Path) -> None:
    data = _payload(LEGACY_BLOCK_SIZE + 4096)
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    subprocess.run(
        ["lz4", "-l", "-q", "-f", str(src), str(tmp_path / "in.bin.lz4")], check=True
    )
    with open_archive(tmp_path / "in.bin.lz4") as ar:
        assert ar.format == ArchiveFormat.LZ4
        assert ar.read(ar.members()[0]) == data
