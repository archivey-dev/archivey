"""Shared inputs and adapters for the codec-library investigation, never production code."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import struct
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

import archivey  # noqa: E402
from archivey.config import AcceleratorMode, ArchiveyConfig, DecoderLimits  # noqa: E402
from archivey.internal.config import StreamConfig, without_accelerators  # noqa: E402
from archivey.internal.streams.codecs.base import Codec  # noqa: E402
from archivey.internal.streams.codecs.registry import open_codec_stream  # noqa: E402

CHUNK = 65536
CONFIG = ArchiveyConfig(
    use_rapidgzip=AcceleratorMode.OFF,
    decoder_limits=DecoderLimits.UNLIMITED,
)
STREAM_CONFIG = replace(
    without_accelerators(StreamConfig()), decoder_limits=DecoderLimits.UNLIMITED
)
CRAMJAM = (
    "gzip",
    "zlib",
    "deflate",
    "bzip2",
    "xz",
    "lzma_alone",
    "zstd",
    "lz4",
    "brotli",
    "snappy",
    "snappy_raw",
    "lz4_block",
)
UNPACKIO = ("zstd", "lz4", "unix_compress")
CONTAINERS = (
    "zip_stored",
    "zip_deflate",
    "zip_bzip2",
    "zip_lzma",
    "7z",
    "7z_copy",
    "7z_lzma",
    "7z_deflate",
    "7z_bzip2",
    "7z_ppmd",
    "7z_brotli",
    "7z_zstd",
)


def payload(size: int) -> bytes:
    """Seeded mixed text and binary, identical on both sides and across interpreters."""
    rng = random.Random(81073)
    unit = b"archivey codec investigation\n" * 30 + rng.randbytes(256)
    if size <= 4096:
        return (unit * (size // len(unit) + 1))[:size]
    chunks = [
        b"archivey codec investigation\n" * 30 + rng.randbytes(256)
        for _ in range(size // len(unit) + 1)
    ]
    return b"".join(chunks)[:size]


def encode(kind: str, data: bytes) -> bytes:
    import cramjam

    if kind == "gzip":
        return gzip.compress(data, mtime=0)
    if kind in ("zlib", "deflate"):
        import zlib

        return zlib.compress(data, wbits=15 if kind == "zlib" else -15)
    if kind == "bzip2":
        return bz2.compress(data)
    if kind in ("xz", "lzma_alone"):
        return lzma.compress(
            data, format=lzma.FORMAT_XZ if kind == "xz" else lzma.FORMAT_ALONE
        )
    if kind == "zstd":
        from backports import zstd

        return zstd.compress(data)
    if kind == "lz4":
        import lz4.frame

        return lz4.frame.compress(data, content_checksum=True, block_checksum=True)
    if kind == "brotli":
        import brotli

        return brotli.compress(data)
    if kind == "unix_compress":
        import ncompress

        return ncompress.compress(data)
    if kind == "snappy_raw":
        return bytes(cramjam.snappy.compress_raw(data))
    if kind == "lz4_block":
        import lz4.block

        return lz4.block.compress(data)
    if kind == "snappy":
        return bytes(cramjam.snappy.compress(data))
    if kind.startswith("zip_"):
        methods = {"stored": 0, "deflate": 8, "bzip2": 12, "lzma": 14}
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", compression=methods[kind[4:]]) as out:
            info = zipfile.ZipInfo("sample.bin", date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = methods[kind[4:]]
            out.writestr(info, data)
        return target.getvalue()
    if kind.startswith("7z"):
        import py7zr

        target = io.BytesIO()
        method = kind.partition("_")[2]
        filters = (
            None if not method else [{"id": getattr(py7zr, "FILTER_" + method.upper())}]
        )
        from py7zr.helpers import ArchiveTimestamp

        timestamp = ArchiveTimestamp(
            132223104000000000
        )  # 2020-01-01 UTC, Windows FILETIME.
        with (
            patch.object(ArchiveTimestamp, "from_now", return_value=timestamp),
            py7zr.SevenZipFile(target, "w", filters=filters) as out,
        ):
            out.writestr(data, "sample.bin")
        return target.getvalue()
    raise ValueError(kind)


def fixture_cases() -> dict[str, tuple[str, bytes]]:
    """Real-producer archives already committed by archivey; do not copy their payloads."""
    cases = {}
    patterns = {
        "rpm": "rpm/payload-*.rpm",
        "deb": "deb/hello-*.deb",
        "cpio": "cpio/gnu-*.cpio",
        "arj": "external/arj_310/method*.arj",
        "7z": "sevenzip/*lzma2.7z",
    }
    for kind, pattern in patterns.items():
        for path in sorted((ROOT / "tests/fixtures").glob(pattern)):
            cases[f"{kind}_{path.stem}"] = kind, path.read_bytes()
    return cases


def baseline(
    kind: str,
    data: bytes,
    streaming: bool = False,
    *,
    include_hardlinks: bool = True,
    password: str | bytes | None = None,
) -> bytes:
    if kind in ("snappy", "snappy_raw"):
        raise NotImplementedError("archivey has no Snappy backend")
    if kind == "lz4_block":
        # The primitive used by archivey's mozlz4 decoder; no outer header here.
        import lz4.block

        return lz4.block.decompress(data)
    if kind in CRAMJAM or kind == "unix_compress":
        with open_codec_stream(
            Codec(kind), io.BytesIO(data), config=STREAM_CONFIG
        ) as stream:
            return drain(stream, streaming)
    fmt = (
        "zip" if kind.startswith("zip_") else ("7z" if kind.startswith("7z") else kind)
    )
    with archivey.open_archive(
        io.BytesIO(data), format=fmt, config=CONFIG, password=password
    ) as reader:
        outputs = []
        for member in reader.members():
            if member.type == archivey.MemberType.FILE or (
                include_hardlinks and member.type == archivey.MemberType.HARDLINK
            ):
                with reader.open(member) as stream:
                    outputs.append(drain(stream, streaming))
        return b"".join(outputs)


def drain(stream, streaming: bool) -> bytes:
    if not streaming:
        return stream.read()
    pieces = []
    while chunk := stream.read(CHUNK):
        pieces.append(chunk)
    return b"".join(pieces)


def candidate(
    library: str,
    kind: str,
    data: bytes,
    streaming: bool = False,
    *,
    password: str | bytes | None = None,
) -> bytes:
    if library == "cramjam":
        import cramjam

        module = getattr(cramjam, "xz" if kind == "lzma_alone" else kind.split("_")[0])
        if kind == "snappy_raw":
            return bytes(module.decompress_raw(data))
        if kind == "lz4_block":
            return bytes(module.decompress_block(data))
        if not streaming:
            return bytes(module.decompress(data))
        decoder = module.Decompressor()
        output = []
        for offset in range(0, len(data), CHUNK):
            decoder.decompress(data[offset : offset + CHUNK])
            output.append(bytes(decoder.flush()))
        output.append(bytes(decoder.finish()))
        return b"".join(output)
    import unpackio

    # Disable policy limits in parity/throughput tests. Memory tests use explicit
    # limits.
    limits = unpackio.Limits(
        max_dictionary_bytes=128 << 20,
        max_entry_output_bytes=128 << 20,
        max_total_output_bytes=256 << 20,
        max_total_input_bytes=256 << 20,
    )
    target = io.BytesIO()

    def receive(chunk):
        target.write(chunk)

    if kind in UNPACKIO:
        stream = unpackio.open_stream_bytes(
            data, format=kind.replace("unix_compress", "z"), limits=limits
        )
        if streaming:
            stream.stream(receive)
        else:
            stream.extract_to(target)
    else:
        fmt = (
            "zip"
            if kind.startswith("zip_")
            else ("7z" if kind.startswith("7z") else kind)
        )
        opener = (
            unpackio.open_bytes
            if fmt == "7z"
            else getattr(unpackio, f"open_{fmt}_bytes")
        )
        kwargs = {} if password is None else {"password": password}
        archive = opener(data, limits=limits, **kwargs)
        for entry in archive.entries():
            is_file = (
                not entry.is_directory and not entry.is_symlink
                if fmt == "zip"
                else entry.kind in ("file", "File", "binary", "text")
            )
            if fmt == "7z":
                is_file = entry.has_stream and entry.kind == "file"
            if is_file:
                if streaming:
                    archive.stream_entry(entry.index, receive)
                else:
                    archive.extract_entry_to(entry.index, target)
    return target.getvalue()


def mutations(data: bytes):
    yield "valid", data
    # Exhaust all short-input truncations; sample 64 evenly spaced offsets for large
    # inputs.
    offsets = (
        range(len(data))
        if len(data) <= 512
        else sorted({0, 1, len(data) - 1, *(i * len(data) // 64 for i in range(64))})
    )
    for offset in offsets:
        yield f"cut-{offset}", data[:offset]
    rng = random.Random(73)
    for i in range(64):
        changed = bytearray(data)
        pos = rng.randrange(len(changed))
        changed[pos] ^= 1 << rng.randrange(8)
        yield f"flip-{i}-{pos}", bytes(changed)
    yield "trailing", data + b"TRAILING"
    yield "padding", data + b"\0" * 4
    yield "concat", data + data
    if data[:4] in (b"\x04\x22\x4d\x18", b"\x28\xb5\x2f\xfd"):
        yield "skippable", struct.pack("<II", 0x184D2A50, 3) + b"abc" + data
