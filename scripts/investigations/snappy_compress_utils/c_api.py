"""Experimental bounded adapter to compress-utils' exported C API; not production code."""

from __future__ import annotations

import copy
import ctypes as C
import importlib
import io

from common import ALGORITHMS, CONFIG, Codec, CodecParams, stream_codecs

# Values from compress-utils 0.12.1, include/compress_utils.h: cu_algorithm_t,
# cu_status_t and CU_DSTREAM_SINGLE. Pin that release when running this prototype.
CU_ALGO_ZSTD = 0
CU_ALGO_BROTLI = 1
CU_ALGO_ZLIB = 2
CU_ALGO_BZ2 = 3
CU_ALGO_LZ4 = 4
CU_ALGO_XZ = 5
CU_ALGO_LZMA = 6
CU_ALGO_SNAPPY = 7
CU_ALGO_GZIP = 8
CU_ALGO_DEFLATE = 9
CU_ALGO_LZ4_RAW = 10
CU_ALGO_LZO = 11

CU_OK = 0
# Stream writes/finishes retain input on this status; drain with empty input.
CU_ERR_BUF_TOO_SMALL = 3
CU_ERR_TRUNCATED = 8
CU_DSTREAM_SINGLE = 0x1


class CoreError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(f"CU status {status}: {message}")


class BoundedDecoder:
    def __init__(self, kind, single=True, total_limit=None):
        self.ptr = C.c_void_p()
        module = importlib.import_module("compress_utils.compress_utils_py")
        self.lib = C.CDLL(module.__file__)
        ptr = C.c_void_p
        size = C.c_size_t
        self.lib.cu_decompress_stream_create_ex.argtypes = [
            C.c_int,
            C.c_uint32,
            C.POINTER(ptr),
        ]
        for name in ("write", "finish"):
            f = getattr(self.lib, "cu_decompress_stream_" + name)
            f.argtypes = (
                [ptr, ptr, size, ptr, C.POINTER(size)]
                if name == "write"
                else [ptr, ptr, C.POINTER(size)]
            )
        self.lib.cu_decompress_stream_destroy.argtypes = [ptr]
        self.lib.cu_decompress_stream_set_max_output.argtypes = [ptr, size]
        self.lib.cu_decompress_stream_eof.argtypes = [ptr]
        self.lib.cu_decompress_stream_unused.argtypes = [
            ptr,
            C.POINTER(ptr),
            C.POINTER(size),
        ]
        self.lib.cu_last_error.restype = C.c_char_p
        algorithms = {
            "zstd": CU_ALGO_ZSTD,
            "brotli": CU_ALGO_BROTLI,
            "zlib": CU_ALGO_ZLIB,
            "bz2": CU_ALGO_BZ2,
            "lz4": CU_ALGO_LZ4,
            "xz": CU_ALGO_XZ,
            "lzma": CU_ALGO_LZMA,
            "snappy": CU_ALGO_SNAPPY,
            "gzip": CU_ALGO_GZIP,
            "deflate": CU_ALGO_DEFLATE,
            "lz4_raw": CU_ALGO_LZ4_RAW,
            "lzo": CU_ALGO_LZO,
        }
        self.ptr = ptr()
        self.status = CU_OK
        self.finishing = False
        self.kind = kind
        s = self.lib.cu_decompress_stream_create_ex(
            algorithms[ALGORITHMS[kind]],
            CU_DSTREAM_SINGLE if single else 0,
            C.byref(self.ptr),
        )
        self.check(s)
        if total_limit is not None:
            self.check(
                self.lib.cu_decompress_stream_set_max_output(self.ptr, total_limit)
            )

    def check(self, status):
        if status not in (CU_OK, CU_ERR_BUF_TOO_SMALL):
            error = self.lib.cu_last_error()
            if status == CU_ERR_TRUNCATED:
                raise EOFError(error.decode(errors="replace") if error else "truncated")
            raise CoreError(status, error.decode(errors="replace") if error else "")

    def decompress(self, data, max_length=-1):
        capacity = 65536 if max_length < 0 else max_length
        if capacity == 0:
            if data:
                raise ValueError(
                    "zero-capacity input not supported by experimental adapter"
                )
            return b""
        output = C.create_string_buffer(capacity)
        n = C.c_size_t(capacity)
        if self.finishing:
            if data:
                raise ValueError("input after end_input")
            s = self.lib.cu_decompress_stream_finish(self.ptr, output, C.byref(n))
        else:
            source = C.create_string_buffer(data) if data else None
            s = self.lib.cu_decompress_stream_write(
                self.ptr, source, len(data), output, C.byref(n)
            )
        self.status = s
        self.check(s)
        if n.value > capacity:
            raise RuntimeError("C API wrote/reported beyond offered output capacity")
        return output.raw[: n.value]

    def end_input(self):
        self.finishing = True

    @property
    def eof(self):
        return bool(self.lib.cu_decompress_stream_eof(self.ptr))

    @property
    def needs_input(self):
        return self.status != CU_ERR_BUF_TOO_SMALL and not self.finishing

    @property
    def unused_data(self):
        data = C.c_void_p()
        n = C.c_size_t()
        self.check(
            self.lib.cu_decompress_stream_unused(self.ptr, C.byref(data), C.byref(n))
        )
        return C.string_at(data, n.value) if n.value else b""

    def close(self):
        if self.ptr:
            self.lib.cu_decompress_stream_destroy(self.ptr)
            self.ptr = C.c_void_p()

    def __del__(self):
        self.close()


def framed_decode(kind, data, streaming=False):
    """Keep archivey's stream-boundary policy, replacing only its per-stream decoder."""
    descriptor = copy.copy(next(x for x in stream_codecs() if x.codec == Codec(kind)))
    descriptor.decompressor = lambda params, config: BoundedDecoder(kind)
    with descriptor.open_framed(io.BytesIO(data), CodecParams(), CONFIG) as stream:
        if not streaming:
            return stream.read()
        output = []
        while block := stream.read(65536):
            output.append(block)
        return b"".join(output)


def bounded_raw(kind, data, size=65536, first_only=False, total_limit=None):
    decoder = BoundedDecoder(kind, single=False, total_limit=total_limit)
    output = []
    try:
        for offset in range(0, len(data), 65536):
            output.append(decoder.decompress(data[offset : offset + 65536], size))
            if first_only:
                return output[0]
            while not decoder.needs_input:
                output.append(decoder.decompress(b"", size))
        decoder.end_input()
        while True:
            output.append(decoder.decompress(b"", size))
            if decoder.status == CU_OK:
                break
        return b"".join(output)
    finally:
        decoder.close()
