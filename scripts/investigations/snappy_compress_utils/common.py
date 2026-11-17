"""Inputs, archivey baselines and explicitly selected package APIs for this investigation."""

from __future__ import annotations

import bz2
import ctypes
import ctypes.util
import gzip
import io
import lzma
import os
import random
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from archivey.config import DecoderLimits  # noqa: E402
from archivey.internal.config import StreamConfig, without_accelerators  # noqa: E402
from archivey.internal.streams.codecs.base import (  # noqa: E402
    Codec,
    CodecParams,
)
from archivey.internal.streams.codecs.registry import (  # noqa: E402
    open_codec_stream,
    stream_codecs,
)

__all__ = ["CodecParams", "stream_codecs"]

CONFIG = replace(
    without_accelerators(StreamConfig()), decoder_limits=DecoderLimits.UNLIMITED
)
ALGORITHMS = {
    "gzip": "gzip",
    "zlib": "zlib",
    "deflate": "deflate",
    "bzip2": "bz2",
    "xz": "xz",
    "lzma_alone": "lzma",
    "zstd": "zstd",
    "lz4": "lz4",
    "brotli": "brotli",
    "lz4_raw": "lz4_raw",
    "lzo": "lzo",
    "raw": "snappy",
}
SNAPPY_PACKAGES = (
    "py-snappy",
    "python-snappy",
    "python-snappy-pure",
    "pysnappy",
    "compress-utils",
    "cramjam",
)
CHUNK = 65536


def payload(size: int) -> bytes:
    rng = random.Random(81073)
    text = b"archivey codec investigation\n" * 30
    unit = text + rng.randbytes(256)
    if size <= 4096:
        return (unit * (size // len(unit) + 1))[:size]
    return b"".join(text + rng.randbytes(256) for _ in range(size // len(unit) + 1))[
        :size
    ]


def encode(kind: str, raw: bytes) -> bytes:
    if kind == "lzo":
        # Independent producer only; archivey and the candidate decode this LZO1X block.
        name = os.environ.get("LZO_PRODUCER_LIBRARY") or ctypes.util.find_library(
            "lzo2"
        )
        if not name:
            raise RuntimeError("LZO benchmarks require system liblzo2 (producer only)")
        lib = ctypes.CDLL(name)
        lib.lzo1x_1_compress.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
        ]
        capacity = len(raw) + len(raw) // 16 + 128
        output = ctypes.create_string_buffer(capacity)
        n = ctypes.c_size_t(capacity)
        work = ctypes.create_string_buffer(1 << 20)
        status = lib.lzo1x_1_compress(raw, len(raw), output, ctypes.byref(n), work)
        if status:
            raise RuntimeError(f"LZO producer status {status}")
        return output.raw[: n.value]
    if kind == "raw":
        import pysnappy

        return pysnappy.compress(raw)
    if kind == "framed":
        from pysnappy.framing import Compressor

        return Compressor().compress(raw)
    if kind == "hadoop":
        from pysnappy.framing import HadoopCompressor

        return HadoopCompressor(buffer_size=1024).compress(raw)
    if kind == "gzip":
        return gzip.compress(raw, mtime=0)
    if kind in ("zlib", "deflate"):
        import zlib

        return zlib.compress(raw, wbits=15 if kind == "zlib" else -15)
    if kind == "bzip2":
        return bz2.compress(raw)
    if kind in ("xz", "lzma_alone"):
        return lzma.compress(
            raw, format=lzma.FORMAT_XZ if kind == "xz" else lzma.FORMAT_ALONE
        )
    if kind == "zstd":
        from backports import zstd

        return zstd.compress(raw, options={zstd.CompressionParameter.checksum_flag: 1})
    if kind in ("lz4", "lz4_raw"):
        import lz4.block
        import lz4.frame

        return (
            lz4.block.compress(raw, store_size=False)
            if kind == "lz4_raw"
            else lz4.frame.compress(raw, content_checksum=True, block_checksum=True)
        )
    if kind == "brotli":
        import brotli

        return brotli.compress(raw)
    raise ValueError(kind)


def archivey_decode(kind: str, data: bytes, streaming=False, size=None) -> bytes:
    if kind == "lz4_raw":
        import lz4.block

        # A SquashFS/mozlz4 block primitive, with the decoded length supplied by the
        # container.
        return lz4.block.decompress(data, uncompressed_size=size)
    if kind == "lzo":
        from archivey.internal.streams.codecs.lzo_decoder import lzo1x_decompress_python

        return lzo1x_decompress_python(data, size)
    with open_codec_stream(Codec(kind), io.BytesIO(data), config=CONFIG) as stream:
        if not streaming:
            return stream.read()
        pieces = []
        while block := stream.read(CHUNK):
            pieces.append(block)
        return b"".join(pieces)


def decode(package: str, kind: str, data: bytes, streaming=False, size=None) -> bytes:
    if package == "compress-utils":
        import compress_utils as cu

        algorithm = ALGORITHMS[kind]
        if not streaming:
            return cu.decompress(data, algorithm, expected_size=size)
        decoder = cu.DecompressStream(algorithm, max_output=size)
        return (
            b"".join(
                decoder.decompress(data[i : i + CHUNK])
                for i in range(0, len(data), CHUNK)
            )
            + decoder.finish()
        )
    if package == "python-snappy":
        import snappy

        if kind == "raw":
            return snappy.decompress(data)
        decoder = (
            snappy.StreamDecompressor()
            if kind == "framed"
            else snappy.HadoopStreamDecompressor()
        )
    elif package == "pysnappy":
        import pysnappy
        from pysnappy.framing import Decompressor, HadoopDecompressor

        if kind == "raw":
            return pysnappy.decompress(data)
        decoder = Decompressor() if kind == "framed" else HadoopDecompressor()
    elif package == "py-snappy":
        import py_snappy

        return py_snappy.decompress(data)
    elif package == "python-snappy-pure":
        import python_snappy

        return python_snappy.decompress(data)
    elif package == "cramjam":
        import cramjam

        return bytes(
            cramjam.snappy.decompress_raw(data)
            if kind == "raw"
            else cramjam.snappy.decompress(data)
        )
    else:
        raise ValueError(package)
    step = CHUNK if streaming else max(1, len(data))
    return (
        b"".join(
            decoder.decompress(data[i : i + step]) for i in range(0, len(data), step)
        )
        + decoder.flush()
    )


def google_raw(data: bytes) -> bytes:
    """Reference: system Google Snappy 1.2.2 C API; validate before allocation."""
    name = ctypes.util.find_library("snappy")
    if not name:
        raise RuntimeError("The independent raw oracle requires system libsnappy")
    library = ctypes.CDLL(name)
    library.snappy_validate_compressed_buffer.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    library.snappy_uncompressed_length.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.snappy_uncompress.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    if library.snappy_validate_compressed_buffer(data, len(data)):
        raise ValueError("Google Snappy rejects raw block")
    n = ctypes.c_size_t()
    if library.snappy_uncompressed_length(data, len(data), ctypes.byref(n)):
        raise ValueError("invalid raw length")
    if n.value > 64 << 20:
        raise MemoryError("reference experiment cap: 64 MiB")
    output = ctypes.create_string_buffer(max(1, n.value))
    if library.snappy_uncompress(data, len(data), output, ctypes.byref(n)):
        raise ValueError("Google Snappy decode failed")
    return output.raw[: n.value]


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xFFFFFFFF


def reference(kind: str, data: bytes) -> bytes:
    if kind == "raw":
        return google_raw(data)
    output, pos, identified = [], 0, False
    while pos < len(data):
        if kind == "hadoop":
            if len(data) - pos < 4:
                raise EOFError("partial Hadoop block length")
            total = int.from_bytes(data[pos : pos + 4], "big")
            pos += 4
            count = 0
            while count < total:
                if len(data) - pos < 4:
                    raise EOFError("partial Hadoop subblock length")
                n = int.from_bytes(data[pos : pos + 4], "big")
                pos += 4
                if n == 0 or pos + n > len(data):
                    raise EOFError("partial/empty Hadoop subblock")
                raw = google_raw(data[pos : pos + n])
                pos += n
                count += len(raw)
                if count > total:
                    raise ValueError("Hadoop block output exceeds declared size")
                output.append(raw)
            continue
        if len(data) - pos < 4:
            raise EOFError("partial Snappy frame header")
        tag = data[pos]
        n = int.from_bytes(data[pos + 1 : pos + 4], "little")
        pos += 4
        if pos + n > len(data):
            raise EOFError("partial Snappy frame payload")
        block = data[pos : pos + n]
        pos += n
        if tag == 255:
            if block != b"sNaPpY":
                raise ValueError("invalid stream identifier")
            identified = True
        elif not identified:
            raise ValueError("missing stream identifier")
        elif tag >= 128:
            continue
        elif tag in (0, 1):
            if n < 4:
                raise ValueError("missing CRC")
            raw = google_raw(block[4:]) if tag == 0 else block[4:]
            if len(raw) > 65536:
                raise ValueError("Snappy frame expands beyond 64 KiB")
            crc = crc32c(raw)
            masked = (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF
            if int.from_bytes(block[:4], "little") != masked:
                raise ValueError("CRC-32C mismatch")
            output.append(raw)
        else:
            raise ValueError("unknown mandatory chunk")
    if kind == "framed" and not identified:
        raise EOFError("no Snappy identifier")
    return b"".join(output)


def mutations(data: bytes):
    yield "valid", data
    offsets = (
        range(len(data))
        if len(data) <= 512
        else sorted({0, 1, len(data) - 1, *(i * len(data) // 64 for i in range(64))})
    )
    for i in offsets:
        yield f"cut-{i}", data[:i]
    rng = random.Random(73)
    for i in range(64):
        b = bytearray(data)
        pos = rng.randrange(len(b))
        b[pos] ^= 1 << rng.randrange(8)
        yield f"flip-{i}-{pos}", bytes(b)
    yield "trailing", data + b"TRAILING"
    yield "padding", data + b"\0" * 4
    yield "concat", data + data


def rss_kib():
    return int(
        next(
            s.split()[1]
            for s in Path("/proc/self/status").read_text().splitlines()
            if s.startswith("VmHWM:")
        )
    )
