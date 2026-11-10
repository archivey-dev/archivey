# 6. Streams and codecs

**In one minute.** A member's bytes come out of a short stack of streams, each with one
job. At the bottom is the `ArchiveSource`. Above it, a *view* bounds the member's
compressed bytes (`streamtools/slice.py`, `shared.py`). Above that, an optional
decryption stage (`crypto.py`, or ZIP's own ciphers), then a *decoder* from the codec
registry, running inside one generic engine, `DecompressorStream`, which owns the buffer,
the position and every seek. At the top is `ArchiveStreamImpl`, the one public
`ArchiveStream`: it translates exceptions, counts bytes, holds the ratio limit, checks the
length and checksum when a read reaches the end, and reports how much was verified. Every
codec is written once and used by every format. Decoders that can crash run in a child
process. The accelerator, rapidgzip, can only change speed: when it fails, the standard
library takes over from where it was.

## The stack, for one ZIP member

```
  caller ── read(n) ──►  ArchiveStreamImpl            archive_stream.py
                           │  translate errors, stamp names; count; ratio guard;
                           │  MemberVerifier: length + CRC-32 at the end; verified level
                           ▼
                         DecompressorStream            decompressor_stream.py
                           │  buffer, position, seek points, rewinds
                           │  └─ Decoder strategy     codecs/deflate_decoder.py (zlib)
                           ▼
                         ZipCrypto / WinZip AES stage  backends/zipcrypto.py, zip_aes.py
                           │  (only for an encrypted member)
                           ▼
                         SharedView [start, end)       streamtools/slice.py, shared.py
                           │  the member's compressed bytes; own position, locked seek
                           ▼
                         ArchiveSource                 internal/source.py
                           │  full-count reads, bounded reads, never closes caller's object
                           ▼
                         the file, BytesIO, pipe, or remote range reads
```

Other formats build different middles (a 7z folder can have four input views feeding a
BCJ2 filter feeding LZMA; a TAR member is a slice of the *decoded* archive stream; a RAR
member is an `unrar` pipe) but the top and bottom are always the same two objects. That
is what makes every format behave the same at the edges.

Reads are pulled, never pushed: nothing below decodes more than the layer above asks for,
apart from bounded buffers.

## `streamtools/`: plain byte plumbing

These modules know nothing about archives and raise only standard-library exceptions.

- **`SlicingStream`** is a bounded view `[start, start+length)` of another stream, with
  its own position.
- **`SharedSource` and `SharedView`.** A file handle has one position, so two consumers
  that each `seek`+`read` the same handle clobber each other, even on one thread.
  `SharedSource` mints views that each keep their own position; a read seeks the handle
  under a lock only when it is somewhere else. This is the stdlib `zipfile._SharedFile`
  idea, and it is what makes `concurrent_operations=True` safe. Views are deliberately
  unbuffered: their consumers (decoders) already read in big chunks.
- **`SolidBlockReader`** (`solid.py`) takes one forward-only decoded stream (a 7z folder,
  an `unrar p` pipe of a solid archive) and hands out one member sub-stream at a time,
  skipping forward lazily.
- **`SparseStream`** presents a sparse TAR member's holes as zeros.
- **`binaryio.py`** classifies whatever the caller passed (path, file object, almost-a-file
  object) and adapts it to one `BinaryIO` shape.
- **`ReadAheadStream`** and **`FullCountStream`** handle the "a short read means the end"
  rule (below).

### The full-count rule

`io.RawIOBase.read(n)` may legally return fewer than `n` bytes before the end. Header
parsers (archivey's and the standard library's) issue one `read(n)` and treat a short
answer as the end. Mixing the two silently truncates. So archivey picks one rule and
enforces it at the boundary: **inside archivey, `read(n)` returns `n` bytes unless the
stream has ended**. The `ArchiveSource` supplies that guarantee for every caller source
(by passing through an already buffered object, adding its own buffer to a seekable raw
one, or asking again on a pipe), and every layer above can rely on it.

## The codec layer (`internal/streams/codecs/`)

One module per codec family, with its decoder beside it, plus a registry. Three names are
easy to mix up (from `codecs/__init__.py`):

- **`Codec`**: an enum id (`Codec.GZIP`, `Codec.DEFLATE`, `Codec.PPMD7`, …). What a
  backend asks for.
- **`StreamCodec`**: one descriptor class per codec: how to open it, how to translate its
  library's exceptions, its magic bytes, its content probe, the optional package it needs.
- **`CodecBackend`**: a codec *resolved* for one configuration. The accelerator choice can
  change which decoder runs and therefore which translator applies.

A backend calls `open_codec_stream(Codec.X, source, ...)` or `resolve_codec(...)` in
`codecs/registry.py`. It never imports `zlib` or `lzma`. Adding a single-file codec is
"add one `StreamCodec` subclass", and detection, the single-file reader, `.tar.<ext>`
and every sequential format pick it up from the registry.

Where the decoders come from:

- the **standard library**: zlib (gzip, zlib, raw DEFLATE), bz2, lzma (xz, lzip, LZMA
  Alone, 7z LZMA/LZMA2 and their filters), and zstd from Python 3.14;
- **optional packages** in the `[recommended]` extra: pyppmd, inflate64 (Deflate64),
  brotli, lz4, `backports.zstd` before 3.14, `cryptography` for AES;
- **archivey's own Python code**: Unix `.Z` (LZW), the 7z BCJ2, ARM64 and RISC-V filters,
  the legacy LZ4 frame, ZIP's Shrink and Implode, LZX for CAB, LZO, and the framing
  around each stream (the gzip, xz and lzip headers and trailers, zstd frames);
- **rapidgzip**, the one accelerator, in the `[seekable]` extra.

Choosing a library per codec is its own investigation, measured on damaged input, in
[`library-analysis.md`](../library-analysis.md). The core install has no third-party
dependency at all (ADR [0011](../decisions/0011-zero-dependency-core.md)).

## The decode engine: `DecompressorStream`

`DecompressorStream` (`streams/decompressor_stream.py`) is one stream class for every
codec. It owns the output buffer, the logical position, a table of seek points and the
seek algorithm. A codec plugs in through the small `Decoder` protocol: `feed(chunk)`,
`flush()` at the end of the input, `recreate(point, inner)` to start again from a seek
point, and optional index discovery. A codec does not subclass the stream.

Why this matters: every codec gets the same seeking, the same "data after the end"
detection, the same truncation rule (`flush()` is the only place that decides a stream
was cut, and it arms an error rather than raising, so the bytes before the cut are still
delivered first), and the same limits.

### How a seek works

1. **Forward seek:** decode and drop the bytes in between.
2. **Backward seek:** find the nearest seek point at or before the target, recreate the
   decoder there, decode forward. With no seek point but the start, that means
   decompressing again from the beginning. The first time that happens the stream
   records `STREAM_REWIND_REDECOMPRESSES`, so a caller who seeks backwards in a loop can
   find out why it is slow.
3. **Where seek points come from:**
   - the format's own index: the xz block index, a zstd seek table, a BGZF or mgzip
     block list, gzip member boundaries;
   - **snapshots** taken while reading: for zlib and DEFLATE with
     `seekable_members=True`, the decoder state is saved about every MiB of output;
   - **the accelerator**: rapidgzip builds its own index as it reads, for gzip and bzip2.

Seek points from an index are trusted: a crafted index that is consistent with itself
but places blocks wrongly makes a cold seek return wrong bytes. That is an accepted risk,
recorded as threat-model O17, because "verify the index first" would mean decompressing
everything, which is what the index exists to avoid (maintainer ruling, 2026-09-23). A
forward read never trusts the index.

Without `seekable_members=True`, the stream builds no index and takes no snapshots: the
default path pays for nothing it does not use (ADR [0003](../decisions/0003-member-streams-opt-in.md)).

## The public stream: `ArchiveStreamImpl`

`streams/archive_stream.py`. Every member stream archivey hands out is one of these, and
nested codec streams collapse into one, so a member is one Python layer at the top, not
three. It does four jobs in the same `read()`:

1. **Error translation.** Any exception from the layers below goes through the
   backend's or codec's translator, which returns an `ArchiveyError` or `None` (let it
   propagate). The result is stamped with the format, the archive name and the member
   name. There is no catch-all ([page 9](09-errors-and-diagnostics.md)).
2. **Verification** (the fused `MemberVerifier` from `streams/verify.py`). When a read
   reaches the member's end, it checks the length and every stored digest. The rules are
   precise, and they are ADR [0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md):
   a digest mismatch raises on the read that reaches the end and withholds that chunk; a
   cut member returns the bytes that exist, and the next read raises `TruncatedError`;
   `close()` never produces the first verdict. Seeks keep the check where they can: see
   [DR-4a](../design-rules.md#dr-4a-the-integrity-guarantee-is-for-a-start-to-end-read).
3. **Counting and limits.** Decoded bytes are counted for the cost receipt and for the
   ratio guard (`MemberRatioGuard` in `bomb_tracker.py`), which stops a member that
   expands far beyond its compressed size.
4. **The verification level** (`verified`, `verifiable`), asked of each layer through
   `streams/verification.py`. Each layer reports what *it* proved: the member's CRC, a
   codec's own checksum, the WinZip AES authentication code. A slice of a decoded TAR
   stream must not claim the whole stream's checksum as its member's, so a layer that does
   not know passes on only doubt. See [verification](../topics/verification.md).

## Accelerators: faster, never different

rapidgzip decodes gzip, zlib, raw DEFLATE and bzip2 in parallel and builds a seek index
as it goes. It is a C++ library, and it has known defects: it can abort the whole process
on a truncated stream, and it can terminate the process when its Python source raises
([`known-issues.md`](../known-issues.md#rapidgzip-accelerator-upstream-defects)). So:

- It runs in a **child process** (`codecs/rapidgzip_child.py` and its worker). A crash
  kills the child, not the caller.
- When it fails on data, **the standard library takes over** (`codecs/stdlib_takeover.py`)
  from its last checkpoint, not from the start, so a cut stream delivers exactly what the
  standard library would, about three times faster. Resuming a DEFLATE stream at a bit
  offset is done by prefixing empty DEFLATE blocks, because Python's zlib has no
  `inflatePrime` (`codecs/deflate_resume.py`).
- Checks the accelerator skips are done around it: the gzip size trailer, the first
  header's CRC, the zlib Adler-32, empty bzip2 streams. Each lives in that codec's module.
- It is fuzzed against the standard decoders, which must give the same result.

The rule is [DR-5](../design-rules.md#dr-5-same-input-same-outcome): an accelerator changes
speed, never the result or the error type, except for one crafted shape listed in DR-5a.

## Child processes

`ArchiveyConfig.process_isolation` chooses which native decoders run in a child
process. The default, `KNOWN_CRASHES`, isolates the ones that have been *seen* to crash
the process: rapidgzip (`use_rapidgzip`, `use_indexed_bzip2`), pyppmd (every PPMd member)
and, as a precaution, libbzip3 (every `.bz3` file, a young library). `NATIVE_DECODERS` isolates the standard-library decoders too; `NONE` starts no
child. Every native decoder object is built through `codecs/isolated.py`'s `Natives`, which
gives either the real object or a proxy with the same methods whose object lives in a
child. Only the native object moves; checksums, decryption and parsing stay in the caller.

A crash signal becomes `CorruptionError`; the out-of-memory killer's SIGKILL becomes
`ResourceUnavailableError`. The child is a crash boundary, not a sandbox: it runs as the
same user, and there is no timeout. All of it is on the
[process isolation](../topics/process-isolation.md) topic page.

## Who closes what

Every wrapper has to answer "when I am closed, do I close the stream under me?" The rule
([stream ownership](../topics/stream-ownership.md)): **a view or a decoder borrows unless
its type says otherwise**; a `DelegatingStream` (a one-to-one stand-in in a close chain)
owns. The exception is spelled `owns_inner=True` at the call site. The public promise
behind it: archivey never closes a stream the caller passed in. That promise is kept at the
source boundary rather than by every wrapper getting its flag right: every backend reads
an `ArchiveSource`, never the caller's object, and the `ArchiveSource` closes only what
archivey opened. `tests/leak_oracle.py` fails a test that leaks an owning stream or a
child.

## Encryption

AES (7z, RAR 5, WinZip AES in ZIP) runs through the `cryptography` package
(`streams/crypto.py`); ZipCrypto is archivey's own (`backends/zipcrypto.py`). Encryption
is a stage in the stack, below the decoder. Password handling is shared: candidates come
from `password.py`, and `password_confirm.py` has the ladder that decides whether a
candidate is right when a format's own check can accept a wrong password: a cheap key
check, then a stored CRC over a small decodable prefix, then "does the decoder reject
this as garbage?". Key derivation is costly by design, so its rounds are capped
(`DecoderLimits.max_key_derivation_rounds`) and derived keys are cached per reader.
