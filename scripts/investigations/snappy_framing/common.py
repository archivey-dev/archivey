"""Shared pieces of the Snappy framing experiment: producers, oracles, the decoders
under test.

Oracles are independent of both backends: system Google Snappy (``libsnappy.so.1``,
through ctypes) for raw blocks, and a strict pure-Python raw decoder written from
``format_description.txt``. The framing reference is the study's
(``scripts/investigations/snappy_compress_utils/common.py``), restated here around the
Google raw decoder so that it shares no code with ``snappy_framed``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib
import io
import random
import zlib
from collections.abc import Callable

from archivey import ArchiveyConfig, FormatPolicy, open_stream
from archivey.internal.streams.codecs.snappy_framed import (
    MAX_CHUNK_DATA,
    NATIVE_DECODERS,
    STREAM_IDENTIFIER,
    LocalChunks,
    SnappyFormatError,
    SnappyFramedDecompressor,
    crc32c_python,
    decode_raw_chunk,
    decode_raw_python,
    masked_crc,
)
from archivey.types import OptionalLibrary

# Each backend's raw decoder alone, without the Python re-check archivey adds to a
# native refusal, so the comparison sees what the backend itself does.
_LIBRARIES = {
    "compress-utils": OptionalLibrary.COMPRESS_UTILS,
    "cramjam": OptionalLibrary.CRAMJAM,
}
_MODULES = {"compress-utils": "compress_utils", "cramjam": "cramjam"}
BACKEND_NAMES = ["compress-utils", "cramjam", "python"]
DECODERS: dict[str, Callable[[bytes, int], bytes]] = {
    name: NATIVE_DECODERS[_LIBRARIES[name]](importlib.import_module(_MODULES[name]))
    for name in _LIBRARIES
}
DECODERS["python"] = decode_raw_python
_SNAPPY_LIBRARIES = frozenset(
    {*_LIBRARIES.values(), OptionalLibrary.GOOGLE_CRC32C, OptionalLibrary.CRC32C}
)
_CRC_LIBRARIES = {
    "google-crc32c": OptionalLibrary.GOOGLE_CRC32C,
    "crc32c": OptionalLibrary.CRC32C,
}


# --- Google Snappy through ctypes ------------------------------------------------------

_lib = ctypes.CDLL(ctypes.util.find_library("snappy") or "libsnappy.so.1")
_lib.snappy_uncompressed_length.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.snappy_uncompress.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.snappy_compress.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.snappy_max_compressed_length.argtypes = [ctypes.c_size_t]
_lib.snappy_max_compressed_length.restype = ctypes.c_size_t


class OracleRefused(Exception):
    pass


def google_raw(block: bytes, cap: int = MAX_CHUNK_DATA) -> bytes:
    n = ctypes.c_size_t()
    if _lib.snappy_uncompressed_length(block, len(block), ctypes.byref(n)):
        raise OracleRefused("length")
    if n.value > cap:
        raise OracleRefused("over cap")
    out = ctypes.create_string_buffer(max(1, n.value))
    if _lib.snappy_uncompress(block, len(block), out, ctypes.byref(n)):
        raise OracleRefused("decode")
    return out.raw[: n.value]


def google_compress_raw(data: bytes) -> bytes:
    n = ctypes.c_size_t(_lib.snappy_max_compressed_length(len(data)))
    out = ctypes.create_string_buffer(max(1, n.value))
    if _lib.snappy_compress(data, len(data), out, ctypes.byref(n)):
        raise RuntimeError("compress failed")
    return out.raw[: n.value]


# --- strict pure-Python raw decoder ----------------------------------------------------


def python_raw(block: bytes, cap: int = MAX_CHUNK_DATA) -> bytes:
    """format_description.txt, strictly: a varint length, then elements until the
    input ends exactly at the declared length."""
    pos, size, shift = 0, 0, 0
    while True:
        if pos >= len(block) or pos >= 5:
            raise OracleRefused("varint")
        b = block[pos]
        pos += 1
        size |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    if size > 0xFFFFFFFF:
        raise OracleRefused("varint over 32 bits")
    if size > cap:
        raise OracleRefused("over cap")
    out = bytearray()
    while pos < len(block):
        tag = block[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:
            n = tag >> 2
            if n >= 60:
                extra = n - 59
                if pos + extra > len(block):
                    raise OracleRefused("literal length cut")
                n = int.from_bytes(block[pos : pos + extra], "little")
                pos += extra
            n += 1
            if pos + n > len(block):
                raise OracleRefused("literal cut")
            out += block[pos : pos + n]
            pos += n
        else:
            if kind == 1:
                if pos + 1 > len(block):
                    raise OracleRefused("copy1 cut")
                n = ((tag >> 2) & 7) + 4
                off = ((tag >> 5) << 8) | block[pos]
                pos += 1
            else:
                width = 2 if kind == 2 else 4
                if pos + width > len(block):
                    raise OracleRefused("copy cut")
                n = (tag >> 2) + 1
                off = int.from_bytes(block[pos : pos + width], "little")
                pos += width
            if off == 0 or off > len(out):
                raise OracleRefused("bad offset")
            for _ in range(n):
                out.append(out[-off])
        if len(out) > size:
            raise OracleRefused("output over declared length")
    if len(out) != size:
        raise OracleRefused("output short of declared length")
    return bytes(out)


# --- framing reference -----------------------------------------------------------------


def reference_framed(data: bytes, raw: Callable[[bytes], bytes] = google_raw) -> bytes:
    out, pos, identified = [], 0, False
    while pos < len(data):
        if len(data) - pos < 4:
            raise EOFError("partial header")
        tag = data[pos]
        n = int.from_bytes(data[pos + 1 : pos + 4], "little")
        pos += 4
        if not identified and tag != 0xFF:
            raise OracleRefused("missing identifier")
        most = 4 + (32 + 65536 + 65536 // 6 if tag == 0x00 else 65536)
        if tag in (0x00, 0x01) and not 4 <= n <= most:
            raise OracleRefused("data chunk length")  # refused before the bytes come
        if tag == 0xFF and n != 6:
            raise OracleRefused("identifier length")
        if 0x02 <= tag <= 0x7F:
            raise OracleRefused("unskippable")
        if pos + n > len(data):
            raise EOFError("partial payload")
        body = data[pos : pos + n]
        pos += n
        if tag == 0xFF:
            if body != b"sNaPpY":
                raise OracleRefused("identifier")
            identified = True
        elif tag >= 0x80:
            continue
        else:
            if tag == 0:
                chunk = raw(body[4:])
            else:
                chunk = body[4:]
                if len(chunk) > MAX_CHUNK_DATA:
                    raise OracleRefused("uncompressed over 64 KiB")
            if masked_crc(crc32c_python(chunk)) != int.from_bytes(body[:4], "little"):
                raise OracleRefused("crc")
            out.append(chunk)
    if not identified:
        raise EOFError("no identifier")
    return b"".join(out)


# --- producers -------------------------------------------------------------------------


def frame(
    chunks: list[bytes],
    raw: Callable[[bytes], bytes],
    uncompressed_if_larger: bool = True,
) -> bytes:
    """Our own framing writer around any raw compressor."""
    out = bytearray(STREAM_IDENTIFIER)
    for chunk in chunks:
        crc = masked_crc(crc32c_python(chunk)).to_bytes(4, "little")
        block = raw(chunk)
        if uncompressed_if_larger and len(block) >= len(chunk):
            kind, body = 0x01, crc + chunk
        else:
            kind, body = 0x00, crc + block
        out += bytes([kind]) + len(body).to_bytes(3, "little") + body
    return bytes(out)


def split(data: bytes, size: int = MAX_CHUNK_DATA) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)] or []


def producers() -> dict[str, Callable[[bytes], bytes]]:
    import compress_utils
    import cramjam

    return {
        "cramjam-framed": lambda d: bytes(cramjam.snappy.compress(d)),
        "google-raw+frame": lambda d: frame(split(d), google_compress_raw),
        "compress-utils-raw+frame": lambda d: frame(
            split(d), lambda c: compress_utils.compress(c, "snappy")
        ),
        "cramjam-raw+frame-small-chunks": lambda d: frame(
            split(d, 4093), lambda c: bytes(cramjam.snappy.compress_raw(c))
        ),
    }


def payloads(size: int, seed: int = 7) -> dict[str, bytes]:
    rng = random.Random(seed)
    words = [b"archive", b"member", b"snappy", b"chunk", b"\n", b" ", b"data", b"0123"]
    text = bytearray()
    while len(text) < size:
        text += rng.choice(words) if rng.random() < 0.9 else rng.randbytes(8)
    return {
        "text": bytes(text[:size]),
        "random": rng.randbytes(size),
        "zeros": bytes(size),
        "zlib-ish": zlib.compress(bytes(text[: size // 2]), 1)[: size // 2]
        + bytes(text[: size - size // 2]),
    }


# --- decoders under test ---------------------------------------------------------------


def decode_with(
    backend: str, data: bytes, step: int = 1 << 20, max_length: int = 1 << 16
) -> bytes:
    """The framed decompressor alone, driven like archivey's stream reader drives it."""
    d = SnappyFramedDecompressor(LocalChunks(DECODERS[backend], crc32c_python))
    out = bytearray()
    pos = 0
    while not d.eof:
        if d.needs_input:
            if pos >= len(data):
                d.end_input()
                if d.needs_input:
                    raise EOFError("stream ends early")
                continue
            out += d.decompress(data[pos : pos + step], max_length)
            pos += step
        else:
            out += d.decompress(b"", max_length)
    return bytes(out)


def snappy_config(backend: str, crc: str = "auto") -> ArchiveyConfig:
    """A config whose library policy leaves only ``backend`` and ``crc`` to the
    built-in codec. ``crc`` is ``"auto"``, ``"python"`` or a package name."""
    keep = {_LIBRARIES[backend]} if backend in _LIBRARIES else set()
    if crc == "auto":
        keep |= set(_CRC_LIBRARIES.values())
    elif crc != "python":
        keep.add(_CRC_LIBRARIES[crc])
    return ArchiveyConfig(
        formats=FormatPolicy(exclude_libraries=_SNAPPY_LIBRARIES - keep)
    )


def archivey_read(backend: str, data: bytes, crc: str = "auto") -> bytes:
    with open_stream(
        io.BytesIO(data), format="sz", config=snappy_config(backend, crc)
    ) as stream:
        return stream.read()


def outcome(fn: Callable[[], bytes]) -> tuple[str, object]:
    """("ok", bytes) or ("refused"/"truncated", reason class)."""
    try:
        return "ok", fn()
    except EOFError as exc:
        return "truncated", type(exc).__name__
    except (SnappyFormatError, OracleRefused) as exc:
        return "refused", type(exc).__name__


__all__ = [
    "BACKEND_NAMES",
    "DECODERS",
    "decode_raw_chunk",
]
