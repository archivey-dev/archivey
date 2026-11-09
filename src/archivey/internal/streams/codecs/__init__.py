"""The uniform, pull-based codec layer.

Format backends compose these stream backends instead of importing codec libraries
(the ``compressed-streams`` contract). Adding a standalone codec is "add one
:class:`StreamCodec` subclass" — not "edit the detector, single-file reader, and
registry separately". Instances live in the registry (:func:`stream_codecs`).

Three names that are easy to mix up:

- :class:`Codec` — enum id (``Codec.GZIP``, ``Codec.DEFLATE``, …). What callers pass
  to :func:`open_codec_stream` / :func:`resolve_codec`.
- :class:`StreamCodec` — descriptor class per codec: ``open`` / ``translate`` /
  magic / content probe / optional ``requirement``. Looked up via :func:`stream_codecs`.
- :class:`CodecBackend` — *resolved* open+translator for a given ``StreamConfig``
  (accelerator choice may change the translator). Returned by :func:`resolve_codec`.

AES decrypt lives in ``streams/crypto.py``; digest/length verify in
``streams/verify.py``. Both compose *around* these codec streams in a pipeline. The
seekable engine every decoder plugs into is ``streams/decompressor_stream.py``.

How an open goes, from :func:`open_codec_stream`:

1. **Choose the codec.** The caller names a :class:`Codec` (detection maps a file's
   magic or content probe to one); the registry holds one :class:`StreamCodec` per id.
2. **Prepare the config.** The registry notes whether the source can seek and how long
   it is, and the codec fills in what it reads from the source
   (:meth:`StreamCodec.prepare_config`).
3. **Pick the engine.** The DEFLATE family and bzip2 may decode through rapidgzip, an
   optional accelerator that builds a seek index as it reads, depending on the
   ``use_rapidgzip`` / ``use_indexed_bzip2`` settings, the source size and the seek
   demand. rapidgzip runs only in a child process, so ``process_isolation=NONE`` never
   uses it. Every other codec has one engine. :func:`resolve_codec` picks the
   exception translator that matches the engine.
4. **Isolate it.** ``process_isolation`` decides which native decoders run in a child
   process, so a crash on hostile input costs the member and not the caller. Under the
   default (``KNOWN_CRASHES``), rapidgzip, pyppmd and libbzip3 run in a child.
   ``NONE`` runs pyppmd and libbzip3 in this process and drops rapidgzip.
   ``NATIVE_DECODERS`` moves every native decoder into a child.
5. **Seek and recover.** A backward seek re-decodes from the nearest seek point the
   decoder knows: an index the format carries (xz, lzip, BGZF, the Seekable Zstandard
   table), block boundaries a decoder found, or rapidgzip's index. When rapidgzip fails
   on data, the standard library decodes again, from a block boundary rapidgzip passed
   where it can, so the accelerator changes speed and never the verdict.

The package, one module per codec plus the shared pieces:

- ``base`` — :class:`Codec`, :class:`CodecParams`, :class:`StreamCodec`, source helpers.
- ``deps`` — the optional packages, read at call time (patch them there in tests).
- ``registry`` — :func:`stream_codecs`, lookups, :func:`resolve_codec`,
  :func:`open_codec_stream`.
- ``<name>_codec`` — one module per codec family: its :class:`StreamCodec`.
- ``deflate_family_codec`` — the open path gzip, zlib and raw DEFLATE share: the
  standard library, or rapidgzip.
- ``rapidgzip_select`` / ``stdlib_takeover`` — the rapidgzip accelerator: choosing it,
  opening it in a child process, and handing a failed decode to the standard library.
  Checks that parse one format (the gzip ISIZE backstop, the zlib Adler-32 check, the
  bzip2 empty-stream check) live in that codec's module.
- Process isolation: ``isolated`` builds each native decoder in this process or as a
  proxy to a child; ``decoder_child`` / ``decoder_worker`` are the parent and child
  sides of that child, and ``ppmd_child`` is PPMd's use of it. ``rapidgzip_child`` /
  ``rapidgzip_worker`` are rapidgzip's own child: it starts from the same worker script
  and frame format, with messages of its own. ``callers_source`` marks an exception that
  the caller's own source raised, so no layer translates it.
- The engines: ``<name>_decoder`` (``deflate``, ``brotli``, ``ppmd``, ``deflate64``,
  ``xz``, ``lzip``, ``lzo``, ``unix_compress``, ``lzma_filter``, ``zip_legacy``, and
  ``lzx``, which only the CAB reader uses) and ``framed_decoder`` for the libraries
  that decode one stream at a time.
- Framing, seek indexes and resume helpers: ``zstd_framing``, ``brotli_framing``,
  ``lz4_legacy``, ``zstd_seek_table``, ``bgzf_index``, ``bzip2_resume``,
  ``deflate_resume``.
- The 7z filters: ``arm64_filter``, ``riscv_filter``, ``bcj2_filter``.

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
    AnyStreamFormat,
    Codec,
    CodecId,
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
    CodecBackend,
    OpenedCodec,
    codec_for_stream_format,
    codec_requirement,
    is_codec_available,
    open_codec_raw,
    open_codec_stream,
    resolve_codec,
    single_file_codec,
    single_file_codecs,
    stream_codec,
    stream_codec_for_format,
    stream_codecs,
)
from archivey.internal.streams.codecs.stored_codec import StoredCodec
from archivey.internal.streams.codecs.unix_compress_codec import UnixCompressCodec
from archivey.internal.streams.codecs.zip_legacy_codec import ImplodeCodec, ShrinkCodec
from archivey.internal.streams.codecs.zlib_codec import (
    DeflateCodec,
    ZlibCodec,
)
from archivey.internal.streams.codecs.zstd_codec import ZstdCodec

__all__ = [
    "LZMA_DICTIONARY_FILTERS",
    "LZMA_FILTER_IDS",
    "AnyStreamFormat",
    "BrotliCodec",
    "Bzip2Codec",
    "Codec",
    "CodecBackend",
    "CodecId",
    "CodecParams",
    "CodecSource",
    "Deflate64Codec",
    "DeflateCodec",
    "GzipCodec",
    "ImplodeCodec",
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
    "ShrinkCodec",
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
    "single_file_codec",
    "single_file_codecs",
    "stream_codec",
    "stream_codec_for_format",
    "stream_codecs",
]
