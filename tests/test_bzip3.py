"""bzip3: the ``.bz3`` files the ``bzip3`` tool writes, read through the bzip3 codec."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ContainerFormat,
    CorruptionError,
    DecoderLimits,
    FormatDetectionError,
    FormatPolicy,
    PackageNotInstalledError,
    ProcessIsolation,
    ResourceLimitError,
    ResourceUnavailableError,
    StreamFormat,
    TruncatedError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.detection_cost import TierSkip, TierSkipReason
from archivey.internal.streams.codecs import bzip3_codec
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO

FIXTURES = Path(__file__).parent / "fixtures" / "external" / "bzip3"
LINES = b"".join(
    b"%07d the quick brown fox jumps over the lazy dog\n" % i for i in range(30000)
)
TAR_BZIP3 = ArchiveFormat(ContainerFormat.TAR, StreamFormat.BZIP3)
ISOLATIONS = list(ProcessIsolation)

needs_bzip3 = requires("bz3")


def _bz3(data: bytes, block_size: int = 1 << 20) -> bytes:
    """A ``.bz3`` file as the ``bzip3`` package's compressor writes it."""
    from bz3.backends import BZ3Compressor

    compressor = BZ3Compressor(block_size)
    return compressor.compress(data) + compressor.flush()


def _blocks(raw: bytes) -> list[tuple[int, int, int]]:
    """Each block's offset, compressed size and decoded size."""
    out, pos = [], 9
    while pos < len(raw):
        compressed, decoded = struct.unpack_from("<ii", raw, pos)
        out.append((pos, compressed, decoded))
        pos += 8 + compressed
    return out


def _read(source: object, **kwargs: object) -> bytes:
    with open_archive(source, **kwargs) as archive:  # type: ignore[arg-type]
        (member,) = archive.members()
        return archive.read(member)


def _config(isolation: ProcessIsolation = ProcessIsolation.NONE) -> ArchiveyConfig:
    return ArchiveyConfig(process_isolation=isolation)


# --- files the bzip3 tool wrote --------------------------------------------------


@needs_bzip3
@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
@pytest.mark.parametrize(
    ("name", "data"),
    [("tiny.txt", b"hi\n"), ("empty.txt", b""), ("lines.txt", LINES)],
    ids=["tiny", "empty", "lines"],
)
def test_files_the_tool_wrote(
    name: str, data: bytes, isolation: ProcessIsolation
) -> None:
    path = FIXTURES / f"{name}.bz3"
    assert detect_format(path).format == ArchiveFormat.BZIP3
    with open_archive(path, config=_config(isolation)) as archive:
        assert archive.format == ArchiveFormat.BZIP3
        for member, stream in archive.stream_members():
            assert member.name == name
            assert stream is not None
            assert stream.read() == data
            assert member.verified is Verification.CHECKSUM


@needs_bzip3
def test_a_tar_inside_is_found() -> None:
    path = FIXTURES / "files.tar.bz3"
    assert detect_format(path).format == TAR_BZIP3
    with open_archive(path) as archive:
        assert [m.name for m in archive.members()] == ["tiny.txt", "empty.txt"]
        assert archive.read("tiny.txt") == b"hi\n"


@needs_bzip3
def test_reads_from_a_pipe_in_small_pieces() -> None:
    source = NonSeekableBytesIO((FIXTURES / "lines.txt.bz3").read_bytes())
    with open_archive(source, streaming=True) as archive:
        for _member, stream in archive.stream_members():
            assert stream is not None
            pieces = []
            while piece := stream.read(1000):
                pieces.append(piece)
            assert b"".join(pieces) == LINES


@needs_bzip3
def test_a_seekable_member_seeks_back_and_forward() -> None:
    raw = (FIXTURES / "lines.txt.bz3").read_bytes()
    with (
        open_archive(io.BytesIO(raw), seekable_members=True) as archive,
        archive.open(archive.members()[0]) as stream,
    ):
        stream.seek(1_200_000)
        assert stream.read(50) == LINES[1_200_000:1_200_050]
        stream.seek(10)
        assert stream.read(5) == LINES[10:15]


@needs_bzip3
@pytest.mark.parametrize("block_size", [65 << 10, 1 << 20])
def test_files_the_package_writes(block_size: int) -> None:
    raw = _bz3(LINES, block_size)
    assert len(_blocks(raw)) > 1
    assert _read(io.BytesIO(raw)) == LINES


# --- damage ---------------------------------------------------------------------


def _with_block_header(raw: bytes, index: int, compressed: int, decoded: int) -> bytes:
    pos = _blocks(raw)[index][0]
    return raw[:pos] + struct.pack("<ii", compressed, decoded) + raw[pos + 8 :]


@needs_bzip3
@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
def test_a_flipped_byte_fails_the_block_crc(isolation: ProcessIsolation) -> None:
    raw = bytearray(_bz3(LINES))
    raw[9 + 8 + 2] ^= 0x01  # inside the first block's CRC-32
    with pytest.raises(CorruptionError, match="does not decode"):
        _read(io.BytesIO(bytes(raw)), config=_config(isolation))


@needs_bzip3
@pytest.mark.parametrize(
    ("compressed", "decoded", "message"),
    [
        # The binding would pass -8 to memcpy as a huge length.
        (-8, 10, "-8 compressed bytes"),
        (1 << 30, 10, "1073741824 compressed bytes"),
        # One past what a 1 MiB block can compress to.
        (bzip3_codec.bz3_bound(1 << 20) + 1, 10, "1069580 compressed bytes"),
        (100, (1 << 20) + 1, "1048577 decoded bytes"),
        (100, -1, "-1 decoded bytes"),
    ],
)
def test_block_sizes_outside_the_block_size_are_refused(
    compressed: int, decoded: int, message: str
) -> None:
    raw = _with_block_header(_bz3(LINES), 0, compressed, decoded)
    with pytest.raises(CorruptionError, match=message):
        _read(io.BytesIO(raw), format=ArchiveFormat.BZIP3, config=_config())


@needs_bzip3
def test_a_literal_block_must_decode_to_its_own_bytes() -> None:
    """The binding returns as many bytes of its buffer as the header says, whatever the
    literal block held: 100 for a 3-byte block would hand back 97 stale bytes."""
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    pos, compressed, _ = _blocks(raw)[0]
    forged = _with_block_header(raw, 0, compressed, 100)
    with pytest.raises(CorruptionError, match="literal block of 11 bytes declares 100"):
        _read(io.BytesIO(forged), format=ArchiveFormat.BZIP3, config=_config())
    assert pos == 9


@needs_bzip3
def test_a_literal_block_holds_at_most_64_bytes() -> None:
    raw = _bz3(LINES)
    pos, _, _ = _blocks(raw)[0]
    block = struct.pack("<Ii", 0, -1) + b"x" * 65
    forged = raw[:pos] + struct.pack("<ii", len(block), 65) + block
    with pytest.raises(CorruptionError, match="literal block of 73 bytes"):
        _read(io.BytesIO(forged), format=ArchiveFormat.BZIP3, config=_config())


@needs_bzip3
@pytest.mark.parametrize("model", [2, 4, 6], ids=["LZP", "RLE", "LZP and RLE"])
def test_a_block_shorter_than_its_own_header_is_refused(model: int) -> None:
    raw = _bz3(LINES)
    pos, _, decoded = _blocks(raw)[0]
    # CRC, BWT index 0, a model byte naming one or two sizes, and nothing more.
    block = struct.pack("<Iib", 0, 0, model)
    forged = raw[:pos] + struct.pack("<ii", len(block), decoded) + block
    with pytest.raises(CorruptionError, match="shorter than its own header"):
        _read(io.BytesIO(forged), format=ArchiveFormat.BZIP3, config=_config())


@needs_bzip3
def test_the_decoded_size_must_match_the_header() -> None:
    raw = _bz3(LINES)
    pos, compressed, decoded = _blocks(raw)[0]
    forged = _with_block_header(raw, 0, compressed, decoded - 1)
    with pytest.raises(CorruptionError):
        _read(io.BytesIO(forged), format=ArchiveFormat.BZIP3, config=_config())
    assert pos == 9


@needs_bzip3
@pytest.mark.parametrize(
    ("size", "message"),
    [((64 << 10), "65536 bytes"), ((512 << 20), "536870912 bytes"), (-1, "-1 bytes")],
)
def test_a_block_size_bzip3_does_not_allow_is_refused(size: int, message: str) -> None:
    raw = _bz3(b"x" * 100)
    forged = raw[:5] + struct.pack("<i", size) + raw[9:]
    with pytest.raises(CorruptionError, match=f"block size of {message}"):
        _read(io.BytesIO(forged), format=ArchiveFormat.BZIP3)


@needs_bzip3
def test_bad_magic_is_refused_when_forced() -> None:
    raw = b"BZ3v2" + _bz3(b"x")[5:]
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(raw))
    with pytest.raises(CorruptionError, match="bad magic"):
        _read(io.BytesIO(raw), format=ArchiveFormat.BZIP3)


@needs_bzip3
@pytest.mark.parametrize(
    ("cut", "where"),
    [(0, "header"), (3, "header"), (9 + 4, "block"), (9 + 8 + 100, "block")],
)
def test_a_file_cut_inside_a_header_or_block_is_truncated(cut: int, where: str) -> None:
    raw = _bz3(LINES)
    with pytest.raises(TruncatedError, match=f"inside (its|a) {where}"):
        _read(io.BytesIO(raw[:cut]), format=ArchiveFormat.BZIP3)


@needs_bzip3
def test_a_file_cut_at_a_block_boundary_reads_short() -> None:
    """The format has no end mark: a cut between blocks is a valid shorter file."""
    raw = (FIXTURES / "lines.txt.bz3").read_bytes()
    first, second = _blocks(raw)
    assert _read(io.BytesIO(raw[: second[0]])) == LINES[: first[2]]


@needs_bzip3
@pytest.mark.parametrize(
    "tail", [b"x", b"\0" * 8], ids=["one byte", "an empty block header"]
)
def test_bytes_after_the_last_block(tail: bytes) -> None:
    raw = _bz3(b"abc" * 100)
    if len(tail) == 8:
        # A zero-length block fails its own header check.
        with pytest.raises(CorruptionError, match="shorter than its own header"):
            _read(io.BytesIO(raw + tail))
    else:
        with pytest.raises(TruncatedError):
            _read(io.BytesIO(raw + tail))


@needs_bzip3
@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
@pytest.mark.parametrize("chunk", [4 << 10, 1 << 20], ids=["4KiB", "1MiB"])
@pytest.mark.parametrize(
    "tail", [b"\xff" * 16, "copy"], ids=["bad block header", "second file"]
)
def test_a_bad_block_header_comes_after_the_good_blocks_output(
    isolation: ProcessIsolation, chunk: int, tail: bytes | str
) -> None:
    """A block header that fails its checks raises only once every byte of the good
    blocks before it is read (spec ``compressed-streams``)."""
    raw = (FIXTURES / "lines.txt.bz3").read_bytes()
    raw += raw if tail == "copy" else tail
    got = bytearray()
    with open_archive(io.BytesIO(raw), config=_config(isolation)) as archive:
        (member,) = archive.members()
        with (
            archive.open(member) as stream,
            pytest.raises(CorruptionError, match="compressed bytes"),
        ):
            while piece := stream.read(chunk):
                got += piece
    assert bytes(got) == LINES


@needs_bzip3
def test_a_bad_block_in_one_call_keeps_the_output_before_it() -> None:
    """One unbounded call that decodes a good block and then meets a bad block header
    returns the good output, says it needs no input, and raises on the next call."""
    from bz3.backends import BZ3Decompressor

    raw = (FIXTURES / "lines.txt.bz3").read_bytes() + b"\xff" * 16
    decoder = bzip3_codec.Bzip3Decompressor(lambda size: None, BZ3Decompressor)
    assert decoder.decompress(raw) == LINES
    assert not decoder.needs_input
    assert not decoder.eof
    with pytest.raises(CorruptionError, match="compressed bytes"):
        decoder.decompress(b"")


@needs_bzip3
def test_a_second_file_after_the_first_is_refused() -> None:
    raw = _bz3(b"abc" * 100)
    with pytest.raises(CorruptionError, match="compressed bytes"):
        _read(io.BytesIO(raw + raw))


# --- limits ----------------------------------------------------------------------


@needs_bzip3
def test_the_block_size_is_checked_against_the_decoder_memory_cap() -> None:
    raw = (FIXTURES / "lines.txt.bz3").read_bytes()
    need = bzip3_codec.decoder_memory(1 << 20)
    under = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=need))
    assert _read(io.BytesIO(raw), config=under) == LINES
    over = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=need - 1))
    with pytest.raises(ResourceLimitError, match="1048576-byte block size"):
        _read(io.BytesIO(raw), config=over)


def test_the_largest_block_size_is_over_the_default_cap() -> None:
    """511 MiB blocks need about 5.7 GB; the default 2 GiB cap reads 16 MiB blocks."""
    assert bzip3_codec.decoder_memory(bzip3_codec.MAX_BLOCK_SIZE) > 2 << 30
    assert bzip3_codec.decoder_memory(16 << 20) < 200 << 20


@needs_bzip3
def test_detection_does_not_wait_for_a_long_first_block() -> None:
    """A first block over 1 MiB compressed is "can't tell": the open reads a bare
    ``.bz3``, and passing the format reads the tar."""
    import random
    import tarfile

    payload = random.Random(5).randbytes(1_500_000)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("random.bin")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    raw = _bz3(buffer.getvalue(), 16 << 20)
    info = detect_format(io.BytesIO(raw))
    assert info.format == ArchiveFormat.BZIP3
    assert info.unavailable_tiers == (
        TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE),
    )
    with open_archive(io.BytesIO(raw), format=TAR_BZIP3) as archive:
        assert archive.read("random.bin") == payload


@needs_bzip3
def test_a_probe_decodes_a_first_block_of_exactly_its_limit() -> None:
    from bz3.backends import BZ3Decompressor

    raw = _bz3(LINES[:5000])
    ((_, compressed, decoded),) = _blocks(raw)

    def decoder(limit: int) -> bzip3_codec.Bzip3Decompressor:
        return bzip3_codec.Bzip3Decompressor(
            lambda size: None, BZ3Decompressor, probe_block_max=limit
        )

    assert decoder(compressed).decompress(raw) == LINES[:decoded]
    with pytest.raises(ResourceLimitError):
        decoder(compressed - 1).decompress(raw)


@needs_bzip3
def test_detection_does_not_build_a_decoder_for_huge_blocks() -> None:
    raw = _bz3(b"x" * 100)
    forged = raw[:5] + struct.pack("<i", 17 << 20) + raw[9:]
    info = detect_format(io.BytesIO(forged))
    assert info.format == ArchiveFormat.BZIP3
    assert info.unavailable_tiers == (
        TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE),
    )


# --- the package and the child process ---------------------------------------------


def test_without_the_package_the_error_names_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.streams.codecs import deps

    monkeypatch.setattr(deps.bzip3, "_present", False)
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    with pytest.raises(PackageNotInstalledError, match=r"archivey\[bzip3\]"):
        _read(io.BytesIO(raw))


@needs_bzip3
def test_an_excluded_package_is_not_used() -> None:
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"bz3"}))
    with pytest.raises(PackageNotInstalledError, match="exclude"):
        _read(io.BytesIO(raw), config=config)


@needs_bzip3
@pytest.mark.parametrize(
    "isolation",
    [ProcessIsolation.KNOWN_CRASHES, ProcessIsolation.NATIVE_DECODERS],
    ids=lambda i: i.name,
)
def test_no_child_process_is_resource_unavailable(
    monkeypatch: pytest.MonkeyPatch, isolation: ProcessIsolation
) -> None:
    """bzip3 decodes only in a child unless NONE, so NONE is the advice."""
    from archivey.internal.streams.codecs import isolated

    monkeypatch.setattr(
        isolated, "decoder_child_unavailable_reason", lambda codec: "no children here"
    )
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    with pytest.raises(ResourceUnavailableError, match=r"ProcessIsolation\.NONE"):
        _read(io.BytesIO(raw), config=_config(isolation))
    assert _read(io.BytesIO(raw), config=_config(ProcessIsolation.NONE)) == b"hi\n"


@needs_bzip3
def test_the_package_is_imported_here_only_under_none() -> None:
    import subprocess
    import sys

    script = (
        "import sys, archivey\n"
        "from archivey import ArchiveyConfig, ProcessIsolation, open_archive\n"
        "for iso in (ProcessIsolation.KNOWN_CRASHES, ProcessIsolation.NONE):\n"
        "    with open_archive(sys.argv[1], config=ArchiveyConfig("
        "process_isolation=iso)) as a:\n"
        "        a.read(a.members()[0])\n"
        "    print(iso.name, 'bz3' in sys.modules)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(FIXTURES / "tiny.txt.bz3")],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.split() == ["KNOWN_CRASHES", "False", "NONE", "True"]


@needs_bzip3
def test_a_decoder_that_cannot_allocate_raises_memory_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.streams.codecs.isolated import Natives

    class _NoMemory:
        def decompress(self, data: bytes) -> bytes:
            raise MemoryError

    monkeypatch.setattr(
        Natives, "bzip3_decompressor", lambda self, setting: _NoMemory()
    )
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    # Not translated: running out of memory is never a damaged archive.
    with pytest.raises(MemoryError):
        _read(io.BytesIO(raw), format=ArchiveFormat.BZIP3)


@needs_bzip3
def test_a_decoder_that_returns_the_wrong_size_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.streams.codecs.isolated import Natives

    class _Short:
        def decompress(self, data: bytes) -> bytes:
            return b"h" if data[:5] != b"BZ3v1" else b""

    monkeypatch.setattr(Natives, "bzip3_decompressor", lambda self, setting: _Short())
    raw = (FIXTURES / "tiny.txt.bz3").read_bytes()
    with pytest.raises(CorruptionError, match="decoded to 1 bytes, not the 3"):
        _read(io.BytesIO(raw))
