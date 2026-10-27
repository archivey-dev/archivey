# zstd and LZ4

Current maintainer truth for Zstandard (`.zst`) and the LZ4 frame format (`.lz4`) as
single-file formats and inside TAR, and for zstd as a ZIP method and LZ4 as a 7z coder.
They share a page because they share a shape: frames that can be concatenated, an optional
content size and an optional checksum in each frame, the same range of skippable frames,
and a decoder library archivey drives as a black box. What they share with the other
codecs, the one-member reader, the seek table and the truncation contract, is on
[`single-file.md`](single-file.md). Registers keep the status; this page states the
behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | zstd and LZ4 frames as one-member archives and inside `.tar.zst` / `.tar.lz4`, and the legacy LZ4 stream (`lz4 -l`) the same way; zstd as a ZIP method; LZ4 as a 7z coder |
| Write | **Not shipped** |
| Backends | zstd: the standard library's `compression.zstd` on Python 3.14 and later, `backports.zstd` from `[recommended]` before it. LZ4: `lz4.frame` from `[recommended]`, and `lz4.block` from the same package for the legacy stream |
| Seeking | zstd, on declared seek demand: from the frame before the target, and the seekable format's seek table gives every frame and the size without decoding (§2.3). LZ4: a backward seek decodes again from the start |
| Size | `None`, even when the frame header declares it |
| Digests | None listed. A frame's content checksum, when present, is checked on read; the legacy LZ4 stream has none |
| Metadata | None beyond the shared fields |
| Truncation | Raised, as `TruncatedError`, except for a legacy LZ4 stream cut exactly between blocks, which reads short with no error (§2.3) |
| Refuses | zstd: a frame whose window is over `DecoderLimits.max_decoder_memory`, as `ResourceLimitError`, or over libzstd's 2 GiB ceiling, as `UnsupportedFeatureError` (§4); a frame that needs a dictionary ("Dictionary mismatch"), as `UnsupportedFeatureError`. LZ4: a frame whose version bits are not `01` (`ERROR_headerVersion_wrong`), as `UnsupportedFeatureError` |

**Three things a reader might expect and will not find.** `member.size` is `None` for a
frame that records its content size. A zstd or LZ4 frame written without a checksum can
decode damaged data to wrong bytes with no error, and the legacy LZ4 stream that `lz4 -l`
writes, used for Linux kernel images, never has one.

## 1. Shape

Three properties generate most of this page.

```
zstd frame:   28 b5 2f fd  frame header (window, [dict id], [content size])
              blocks …  [content checksum: xxh64 low 32 bits]
LZ4 frame:    04 22 4d 18  FLG BD [content size(8)] [dict id(4)] HC
              blocks …  end mark 00 00 00 00  [content checksum: xxh32]
skippable:    50..5f 2a 4d 18  size(4)  payload      ← either format, any number, anywhere
legacy LZ4:   02 21 4c 18  size(4) block  size(4) block …  ← no frame header, no checksum, no end mark
```

**A file is a run of frames, and nothing counts them.** Each frame is complete in itself:
`pzstd` writes one frame per chunk, and `cat a.zst b.zst` is valid. Skippable frames can
sit before, between or after them; the seekable-zstd format stores its seek table in one.
So a size in one frame header is not the file's size, and no digest covers the whole file.

**The checksum is optional.** `zstd` writes one by default and `zstd --no-check` does not;
LZ4's content checksum is set by the writer too. Without it, a changed byte can decode to
different bytes of the same length and pass: measured by flipping one bit mid-file in a
`zstd --no-check` file, which read back with no error.

**The window is the writer's choice: up to 2 GiB from the `zstd` command.** A zstd frame header declares
its window, and the decoder needs that much memory. The `zstd` command sizes the window to
the input when it knows the input's size, so `zstd --long=31` on a file writes a small
window, and the same command reading standard input declares 2 GiB. LZ4 blocks are at most
4 MiB (8 MiB in the legacy stream), and matches reach back 64 KiB.

## 2. The pipeline here

### 2.1 Identify

zstd is the magic `28 b5 2f fd` at offset 0, and LZ4 `04 22 4d 18` or the legacy stream's
`02 21 4c 18`; each is `CERTAIN`. The inner-TAR probe then decodes 512 bytes and upgrades
a match to `TAR_ZST` or `TAR_LZ4` ([`single-file.md`](single-file.md) §2.1). It reads at
most 1 MiB of compressed input to get them, and a legacy block yields nothing until all
of it is read, so a legacy `.tar.lz4` whose first block compresses to more than 1 MiB
(incompressible data at the start of the tar) stays bare `LZ4` unless its name says
`.tar.lz4`. A frame's blocks decode as they arrive, so no frame file is affected.

For zstd, detection also walks a leading run of skippable frames
(`streams/codecs/zstd_framing.py`): each declares its size, so the next frame's offset is
arithmetic, with nothing decoded. A regular frame must follow. A source of only skippable
frames has no payload and is not claimed, since claiming it would open a fabricated empty
member. The walk stays inside the peeked prefix: a skippable frame larger than that ends it
with no answer rather than extending the read.

LZ4 has no such walk, so an LZ4 file that starts with a skippable frame is not detected by
content; named `.lz4`, it opens through the extension.

### 2.2 Open and list

The member has no metadata of its own: `size` is `None`, `modified` is `None`, and `hashes`
is empty. The content size an LZ4 frame (`lz4 --content-size`) or a zstd frame records is
not read, because it describes one frame and nothing says the file has one (§7).

### 2.3 Member data

Both codecs run in archivey's engine as `FramedDecompressorStream`
(`internal/streams/codecs/framed_decoder.py`): one library decompressor per frame, and a
new one only when the bytes right after a frame are a frame or skippable-frame magic.
Bytes there that hold one of those magics in at least half of its positions, but not
all, are a frame with a damaged magic and raise `CorruptionError`; a run of one to three
zeros counts as the magic's first bytes there, since a damaged byte can be a zero.
Anything else after a frame is trailing data, reported as `ARCHIVE_TRAILING_DATA` unless
it is zeros that run to the end of the file ([`single-file.md`](single-file.md) §2.3).
After zeros, any other byte ends the data, a further frame's magic too (§6). The
file-level readers the libraries offer (`compression.zstd.open`, `lz4.frame.open`)
cannot do that: they take any bytes after a frame for the next frame and fail on them.

**zstd.** The decompressor is `compression.zstd.ZstdDecompressor`, or `backports.zstd`'s
before Python 3.14, the same API (ADR 0009). It skips skippable frames and checks each
content checksum. A frame that ends early is `TruncatedError`; any `ZstdError` is
`CorruptionError`, except the window refusal, which is `ResourceLimitError` (§4).

**LZ4.** The decompressor is `lz4.frame.LZ4FrameDecompressor`, which checks the content
and block checksums when present. A frame that ends early is `TruncatedError`; a
`RuntimeError` whose message starts with "LZ4" is `CorruptionError`. Dependent blocks
(`lz4 -BD`) decode normally.

**Legacy LZ4.** `lz4.frame` does not read the legacy stream, so a stream that starts with
its magic decodes block by block with `lz4.block` instead
(`internal/streams/codecs/lz4_legacy.py`); the first four bytes of each stream pick the decoder, so
legacy and modern streams can follow each other in one file, as the `lz4` command allows.
Each block was compressed on its own from at most 8 MiB, so it decodes into an 8 MiB
buffer and nothing carries between blocks. The stream has no end mark: it ends where the
input does, at a zero size (zeros after it are padding), or at a size no writer could
produce (over `LZ4_COMPRESSBOUND(8 MiB)`, 8 421 520 bytes), which is how the `lz4`
command finds the next frame. Whatever follows is the next stream or trailing data. A
block that fails to decode, or decodes to more than 8 MiB, is `CorruptionError`; input
that ends inside a size field or a block is `TruncatedError`. Input that ends exactly
between two blocks cannot be told from the stream's real end, so a file cut there reads
short with no error; `lz4 -dc` reads it the same way.

**zstd seeks from frame starts.** Each zstd frame is decoded on its own, so on declared seek
demand every regular frame after the first is a resume point, recorded when a forward read
reaches it (`FramedDecoder` with a `StreamIndex`). A skippable frame holds no output and is
not one. A file in the *Seekable Zstandard* format (`contrib/seekable_format` in the zstd
repository) ends with a skippable frame (magic `0x184D2A5E`) that lists every frame's
compressed and decompressed size, under a 9-byte footer: frame count, a descriptor byte, and
the magic `0x8F92EAB1`. A forward seek past the known points, `SEEK_END` or a size query
reads that table (`codecs/zstd_seek_table.py`): every frame becomes a resume point and the
total is the stream's size, with nothing decoded. The table is trusted, like the xz and lzip
indexes (§5), until a decode finds a frame at another output offset than the table gives
it, or reaches the end with another total: the stream then drops the table's points and
size and reports `SEEK_INDEX_DEGRADED` (scan `decode_check`; threat-model O17). Its
optional per-frame checksums are the low 32 bits of XXH64, which the standard library
lacks, so they are not checked; a frame's own content checksum still is.
A table with reserved descriptor bits set, or whose frames do not end where the table
starts, emits `SEEK_INDEX_DEGRADED` (scan `zstd_seek_table`) and reads decode from the
start. The table must end the file: zeros after it hide it, and the file then seeks like
any other zstd file. A single-frame file, the default `zstd` output, has nothing to resume
from, so a backward seek decodes again from the start and the rewind report says so
([`single-file.md`](single-file.md) §2.3). LZ4 records no resume points, so every LZ4
backward seek does that too. A ZIP zstd member is read as a `.zst` file is, with the
same seek points and table.

### 2.4 Extract

Nothing here is specific to these formats ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with the tools listed on [`single-file.md`](single-file.md) §3.

| Producer | archivey |
| --- | --- |
| `zstd`, `zstd --no-check`, `pzstd`, two frames concatenated | Reads; `size=None` |
| A zstd frame behind a skippable frame | Detected and read |
| `zstd --long=31` on a file | Reads: the window is sized to the input |
| `zstd --long=31` from standard input (2 GiB window) | Reads under the default 2 GiB cap; `ResourceLimitError` under a smaller one |
| A zstd file followed by `junk` | Reads, then `ARCHIVE_TRAILING_DATA`; `zstd -t` refuses it |
| Two zstd or LZ4 frames, one byte of the second frame's magic damaged | `CorruptionError` on a read and a seek |
| One bit flipped mid-file, `zstd` / `zstd --no-check` | `CorruptionError` from the checksum / **read with no error** |
| `lz4`, `lz4 -BD`, two frames concatenated | Reads |
| `lz4 --content-size` | Reads; `size=None` |
| An LZ4 file followed by `junk` | Reads, then `ARCHIVE_TRAILING_DATA` |
| An LZ4 frame behind a skippable frame, no extension | Not detected |
| `lz4 -l` of a tar starting with 3 MiB of incompressible data, no extension | `LZ4`, not `TAR_LZ4`: the first block is over the inner-TAR probe's 1 MiB (§2.1) |
| `lz4 -l` (legacy frame, magic `02 21 4c 18`), one block and several | Detected and read |
| `lz4 -l` output, a modern frame and another `lz4 -l` output concatenated | Reads, as `lz4 -dc` does |
| `lz4 -l` output followed by `junk` / by three zero bytes | Reads, then `ARCHIVE_TRAILING_DATA` / reads clean; `lz4 -dc` accepts the first and refuses the second ("Error 40 : Unrecognized header", exit 40) |
| A frame, 4 zero bytes, a frame (crafted: no known writer emits this) | The first payload, then `ARCHIVE_TRAILING_DATA` at the second frame's first byte; `DiagnosticPolicy.STRICT` raises. `zstd -dc` 1.5.5 writes the first payload, then "unsupported format", exit 1; `lz4 -dc` 1.9.4 writes it and exits 1. `bsdcat` fails on the `.zst` ("Unknown frame descriptor") and writes the first payload of the `.lz4`; `lz4.frame.decompress` returns the first payload. 7-Zip 16.02 opens neither |
| A frame, then 4 zero bytes at the end of the file | Reads, with no diagnostic. `zstd -dc` and `lz4 -dc` write the payload and exit 1 on the zeros; archivey keeps them silent, as for every codec (§6) |

The legacy format is what Linux kernel images and initramfs files compressed with LZ4 use.

## 4. Threat surface

Specific to these formats; the shared items are [`single-file.md`](single-file.md) §4.

- **The window is an allocation.** `DecoderLimits.max_decoder_memory` bounds it: the cap
  replaces libzstd's own default of 128 MiB (a window log of 27) as the decoder's
  `window_log_max`, and libzstd refuses a larger window from the frame header, before it
  allocates. That refusal is `ResourceLimitError`. `window_log_max` is a power of two, so
  the cap is rounded down to one; a window between that power of two and the cap is
  refused too. libzstd accepts values from 2^10 to 2^31 on a 64-bit build, and the cap is
  clamped to that range, so a cap under 1 KiB acts as 1 KiB. A window over 2^31 is
  libzstd's own ceiling and is `UnsupportedFeatureError`, with no remedy named: the
  default cap is exactly 2^31, so under the default every refusal is this one. Every
  frame of the stream is checked, not only the first. LZ4's memory is fixed by the
  format.
- **The legacy block size is not believed past the format's bound.** Its size field is
  32 bits, so a crafted stream can declare a 4 GiB block, and a decoder that waited for
  it would hold that much input before decoding a byte. A size over
  `LZ4_COMPRESSBOUND(8 MiB)` ends the stream instead, so the input held for one block
  stays under about 8 MiB and each block decodes into an 8 MiB buffer. Both numbers are
  the format's, so `DecoderLimits` has nothing to cap here.
- **Detection lifts the cap, not the window.** The inner-TAR probe decodes with
  `DecoderLimits.UNLIMITED` (`_PROBE_STREAM_CONFIG` in `codecs/base.py`, the same rule as
  liblzma's dictionary), but with `window_log_max` at libzstd's default 27 (128 MiB),
  what `zstd -d` decodes without `--long`. libzstd reserves the declared window of a
  frame without a content size when it reads the header (measured: a 2 GiB window under
  a 256 MiB `RLIMIT_AS` fails with "Allocation error"), and a window cannot be shrunk to
  what the read needs the way an LZMA dictionary can. A frame over 128 MiB is "can't
  tell": detection reports a bare `.zst`, records `inner_tar` as
  `CAPABILITY_UNAVAILABLE`, and the open applies the caller's limit. The alternative was to
  keep libzstd's 2 GiB ceiling and let its own allocation refusal ("Allocation error", a
  `CorruptionError` to the probe) be the "can't tell" under memory pressure; that keeps
  `--long=28` and up detected where memory allows. The cap was chosen because a 2 GiB
  reservation per `detect_format` is a cost in itself (threat model O11) and `--long`
  frames are rare beside the 8 MiB window of `zstd -19`.
- **The decoders are native code.** Both run in the caller's process. `compression.zstd`
  is the standard library's; `lz4` is a C extension. Neither is fuzzed by archivey's own
  harness beyond the corpus.
- **No checksum, no detection.** A frame written without one gives wrong bytes for damaged
  input. The format allows it and nothing archivey can do finds the damage.
- **Skippable frames are walked without reading.** The walk is arithmetic over bytes
  already peeked; a 4 GiB skippable frame costs nothing.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| `ResourceLimitError` on a zstd file whose window is under the cap | **archivey** | The cap is rounded down to a power of two for zstd (§4) |
| `member.size` is `None` although the frame header has a content size | **archivey** | One frame's size is not the file's (§1, §7) |
| A damaged `lz4 -l` file can read with no error | **format** | The legacy stream has no checksum (§2.3) |
| An `lz4 -l` file cut between two blocks reads short with no error | **format** | The legacy stream has no end mark (§2.3) |
| An LZ4 file starting with a skippable frame is not detected by content | **archivey** | The skippable-frame walk is zstd's only |
| A damaged `--no-check` file reads with no error | **format** | No checksum (§1) |
| A file `zstd -t` refuses reads, with `ARCHIVE_TRAILING_DATA` | **archivey** | Bytes after the last frame are reported, not refused ([`single-file.md`](single-file.md) §6); `DiagnosticPolicy.STRICT` raises |
| A backward seek in a single-frame zstd file or any LZ4 file re-decodes from the start | **format** | Nothing in the stream to resume from (§2.3) |
| A cold seek into a seekable-zstd file trusts its seek table | **format** / **archivey** | Accepted as for xz and lzip: threat-model O17 |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| zstd through `compression.zstd`, with `backports.zstd` before Python 3.14 (PR #24, ADR 0009) | The standard library's API, so the backport disappears with 3.13; truncation raises; backward seeks work | `zstandard`, which returned a short read with no error on a cut frame and could not seek backward; `pyzstd`, whose API became `compression.zstd` |
| Walk skippable frames at detection, but require a regular frame (PR #270) | The seekable-zstd format puts a skippable frame first; a file of only skippable frames has no content | Registering the sixteen skippable magics as zstd, which would claim an empty file |
| Keep the walk inside the peeked prefix | A skippable frame can declare 4 GiB, and seeing past it is not worth a longer read | Extending the peek |
| LZ4 through `lz4.frame` | The maintained binding | Writing a frame decoder |
| The legacy LZ4 stream through `lz4.block`, framed in archivey | Its framing is a magic and a size per block, and `lz4.block` is in the package already installed | Refusing it with `UnsupportedFeatureError`, which would leave kernel images unreadable |
| One library decompressor per frame, framed by magic in archivey's engine | Finds where the last frame ends, so bytes after it are reported rather than failing the read | `compression.zstd.open` and `lz4.frame.open`, which fail on them |
| Zero bytes end the data unless they run to the end of the file; a frame after them is `ARCHIVE_TRAILING_DATA` (maintainer ruling, 2026-10-10) | Match the official tools (DR-6): `zstd` and `lz4` stop at zeros between frames and fail, and the same rule already holds for gzip and bzip2. Zeros at the end of the file stay silent although `zstd` and `lz4` refuse them too: one rule for every codec, as tape and block devices pad files with zeros ([`single-file.md`](single-file.md) §6) | Reading a frame after the zeros; refusing zeros at the end, as `zstd` and `lz4` do |
| Do not report a frame's content size | It covers one frame, and proving there is one frame means reading to the end | Reporting it when present |
| Seek with frame starts and the seekable format's table, natively | Frames are independent, so a frame start is an exact resume point, and the table lists them all from the end of the file; `indexed_zstd` bundles the native core ADR 0008 keeps out | `indexed_zstd`; checking the table's XXH64 checksums, which needs a dependency |

## 7. Open questions

- **Content size for a single-frame file.** A seekable source could confirm there is one
  frame by walking the frame headers and block sizes without decoding; that would give
  `size` for most files. Tracked internally.
- **Frame index without a seek table.** A multi-frame file with no seek table (`pzstd`)
  gets its frame points only as a forward read reaches them. Walking the frame and block
  headers would find them without decoding.

## 8. Verify

```bash
./scripts/test.sh tests/test_single_file.py tests/test_codecs.py tests/test_detection.py \
    tests/test_seekable_streams.py tests/test_zip_native_codecs.py -k "zstd or lz4 or zst"
```

| Claim |
| --- |
| Both read as one member |
| A cut zstd frame is `TruncatedError` |
| Skippable frames before a regular frame; alone they are not a claim; the walk stays in the prefix |
| Backward seeks re-decode and are reported |
| Frame starts and the seekable-zstd table give resume points and the size; a bad table degrades; the table is trusted |
| zstd as a ZIP method |
| The zstd window is capped by `max_decoder_memory`, on `.zst` and ZIP method 93 |
| A frame after zero bytes is trailing data, and strict refuses it; zeros at the end and frames with nothing between them stay silent |
| The legacy LZ4 stream: detection, blocks, concatenation, padding, the size bound, corruption and truncation |
| `pyzstd` is not a runtime dependency |

The LZ4 skippable-frame gap has no test; it was measured with the tools in §3.

**Building fixtures.** `compression.zstd` or `backports.zstd` and `lz4.frame` write both
formats; `tests/streams_util.py::make_seekable_zstd` adds a seek table. `zstd`, `pzstd` and `lz4` install from the distribution.

## 9. References

- RFC 8878 (Zstandard): §3.1.1 frame header and window descriptor, §3.1.2 skippable frames
- LZ4 frame format description (github.com/lz4/lz4, `doc/lz4_Frame_format.md`), including
  the legacy frame and skippable frames
- The seekable-zstd format (github.com/facebook/zstd, `contrib/seekable_format`)
- Decisions: [ADR 0009](../decisions/0009-zstd-stdlib-backports.md) ·
  [ADR 0008](../decisions/0008-single-accelerator-rapidgzip.md) ·
  [`library-analysis.md`](../library-analysis.md) §zstd, §lz4
- Code: `internal/streams/codecs/zstd_codec.py` (`ZstdCodec`), `lz4_codec.py` (`Lz4Codec`) ·
  `internal/streams/codecs/zstd_framing.py` · `internal/streams/codecs/zstd_seek_table.py` ·
  `internal/streams/codecs/lz4_legacy.py`
- Handbook: [`single-file.md`](single-file.md) · [`zip.md`](zip.md) (zstd method) ·
  [`7z.md`](7z.md) (LZ4 coder) · [`tar.md`](tar.md)
