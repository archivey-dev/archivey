"""The uniform, pull-based codec layer.

Format backends compose these stream backends instead of importing codec libraries
(the ``compressed-streams`` contract). Adding a standalone codec is "add one
:class:`StreamCodec` subclass" — not "edit the detector, single-file reader, and
registry separately". Instances live in :data:`STREAM_CODECS`.

Three names that are easy to mix up:

- :class:`Codec` — enum id (``Codec.GZIP``, ``Codec.DEFLATE``, …). What callers pass
  to :func:`open_codec_stream` / :func:`resolve_codec`.
- :class:`StreamCodec` — descriptor class per codec: ``open`` / ``translate`` /
  magic / content probe / optional ``requirement``. Looked up via ``STREAM_CODECS``.
- :class:`CodecBackend` — *resolved* open+translator for a given ``StreamConfig``
  (accelerator choice may change the translator). Returned by :func:`resolve_codec`.

AES decrypt lives in ``streams/crypto.py``; digest/length verify in
``streams/verify.py``. Both compose *around* these codec streams in a pipeline. The
seekable engine every decoder plugs into is ``streams/decompressor_stream.py``.

The package, one module per codec plus the shared pieces:

- ``base`` — :class:`Codec`, :class:`CodecParams`, :class:`StreamCodec`, source helpers.
- ``deps`` — the optional packages, read at call time (patch them there in tests).
- ``registry`` — :data:`STREAM_CODECS`, lookups, :func:`resolve_codec`,
  :func:`open_codec_stream`.
- ``rapidgzip_select`` / ``stdlib_takeover`` — the rapidgzip accelerator: choosing it,
  opening it in a child process, and handing a failed decode to the standard library.
  Checks that parse one format (the gzip ISIZE backstop, the zlib Adler-32 check, the
  bzip2 empty-stream check) live in that codec's module.
- ``<name>_codec`` — one module per codec family: its :class:`StreamCodec`.
- The engines beside them: ``<name>_decoder`` (``deflate``, ``brotli``, ``ppmd``,
  ``deflate64``, ``xz``, ``lzip``, ``unix_compress``, ``lzma_filter``), ``framed_decoder``
  for the one-shot decompressors, framing and resume helpers (``zstd_framing``,
  ``brotli_framing``, ``lz4_legacy``, ``bzip2_resume``, ``deflate_resume``), the 7z
  filters (``arm64_filter``, ``riscv_filter``, ``bcj2_filter``), and the child processes and worker
  scripts (``ppmd_child`` / ``ppmd_worker``, ``rapidgzip_child`` / ``rapidgzip_worker``).

This module re-exports the names other modules use.
"""

# Imported so ``codecs.deps`` and the rapidgzip modules are attributes of this package
# whatever the codec modules import: tests patch through them.
from archivey.internal.streams.codecs import (  # noqa: F401
    deflate_family_codec,
    deps,
    rapidgzip_select,
    stdlib_takeover,
)
from archivey.internal.streams.codecs.base import (
    LZMA_FILTER_IDS,
    Codec,
    CodecParams,
    CodecSource,
    MetadataContext,
    ProbeChargeDecode,
    ProbeReadAt,
    StreamCodec,
)
from archivey.internal.streams.codecs.brotli_codec import BrotliCodec
from archivey.internal.streams.codecs.bzip2_codec import Bzip2Codec
from archivey.internal.streams.codecs.deflate64_codec import Deflate64Codec
from archivey.internal.streams.codecs.gzip_codec import (
    GzipCodec,
    gzip_has_additional_member,
)
from archivey.internal.streams.codecs.lz4_codec import Lz4Codec
from archivey.internal.streams.codecs.lzma_codec import (
    LZMA_DICTIONARY_FILTERS,
    LzipCodec,
    Lzma2Codec,
    LzmaAloneCodec,
    LzmaCodec,
    XzCodec,
    decode_lzma_filter_properties,
)
from archivey.internal.streams.codecs.ppmd_codec import (
    PpmdCodec,
    parse_ppmd_var_h_properties,
)
from archivey.internal.streams.codecs.registry import (
    SINGLE_FILE_CODECS,
    STREAM_CODECS,
    CodecBackend,
    OpenedCodec,
    codec_for_stream_format,
    codec_requirement,
    is_codec_available,
    open_codec_raw,
    open_codec_stream,
    resolve_codec,
    stream_codec,
    stream_codec_for_format,
)
from archivey.internal.streams.codecs.stored_codec import StoredCodec
from archivey.internal.streams.codecs.unix_compress_codec import UnixCompressCodec
from archivey.internal.streams.codecs.zlib_codec import (
    DeflateCodec,
    ZlibCodec,
)
from archivey.internal.streams.codecs.zstd_codec import ZstdCodec

__all__ = [
    "LZMA_DICTIONARY_FILTERS",
    "LZMA_FILTER_IDS",
    "SINGLE_FILE_CODECS",
    "STREAM_CODECS",
    "BrotliCodec",
    "Bzip2Codec",
    "Codec",
    "CodecBackend",
    "CodecParams",
    "CodecSource",
    "Deflate64Codec",
    "DeflateCodec",
    "GzipCodec",
    "Lz4Codec",
    "LzipCodec",
    "Lzma2Codec",
    "LzmaAloneCodec",
    "LzmaCodec",
    "MetadataContext",
    "OpenedCodec",
    "PpmdCodec",
    "ProbeChargeDecode",
    "ProbeReadAt",
    "StoredCodec",
    "StreamCodec",
    "UnixCompressCodec",
    "XzCodec",
    "ZlibCodec",
    "ZstdCodec",
    "codec_for_stream_format",
    "codec_requirement",
    "decode_lzma_filter_properties",
    "gzip_has_additional_member",
    "is_codec_available",
    "open_codec_raw",
    "open_codec_stream",
    "parse_ppmd_var_h_properties",
    "resolve_codec",
    "stream_codec",
    "stream_codec_for_format",
]
