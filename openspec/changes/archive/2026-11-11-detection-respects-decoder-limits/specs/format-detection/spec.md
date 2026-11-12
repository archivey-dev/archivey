## MODIFIED Requirements

### Requirement: Compressed streams are probed for an inner TAR

For single-file compressors (gzip, bzip2, xz, zstd, lz4, lzip, LZMA Alone, zlib,
brotli, unix-compress), detection SHALL decompress a bounded amount of *content*
and look for TAR `ustar` at offset 257, or a first header that passes the
self-checking header test (a v7 tar), reporting combined formats (`TAR_GZ`, …) when
present. Need ≥512 decompressed bytes.

Compressed input is supplied via a **bounded, non-consuming view** (up to
`_INNER_TAR_MAX_PROBE_BYTES`, ≥ largest bzip2 first-block compressed size):

- Stream codecs pull incrementally (first few KiB usually enough).
- Block-transform (bzip2) may pull a full first block before any output.

Seekable: read + restore position. Path: open/close. Non-seekable: buffer in the
`ArchiveSource`'s replay prefix. Use sequential decompression (not random-access
accelerators that reject bounded non-seekable views). Missing decompressor → bare
compressor format; open may refine. No TAR header within the bound → bare
compressor.

A detection decode (this probe and the content probes) SHALL be held to the caller's
`DecoderLimits.max_decoder_memory`, and SHALL NOT reserve decoder memory the source
declares beyond what its bounded read needs. Where the read needs less than the source
declares, the cap SHALL be checked against what the decoder reserves, so a probe the
read that follows would refuse still finds the format. An LZMA-family decoder (`.xz`,
`.lzma`, `.lz`) SHALL be built with a dictionary no larger than the read's output plus a
small allowance for a filter ahead of LZMA2 (64 bytes), and at least 4 KiB; that decodes
those bytes identically. The xz probe SHALL follow the file through stream padding into
later streams, as the reader does. An xz block whose filter chain cannot be decoded that
way is "can't tell" and its inner TAR is not claimed. A zstd frame whose window is over
2^27 bytes (libzstd's default limit) or over the cap is "can't tell", and so is any
decoder the cap refuses (`ResourceLimitError`); detection SHALL report that refusal
as `DETECTION_DECODER_LIMITED` (`diagnostics`) with the limit and its value, and the
open that follows reads the source as the bare compressed stream. A content probe the cap refuses is
"can't tell" too: it SHALL record `content_probe` as `CAPABILITY_UNAVAILABLE` and SHALL
NOT answer "not this format". A `MemoryError` from a probe's decoder is "can't tell";
it SHALL NOT escape detection. In the inner-TAR probe, "can't
tell" (an absent backend, or a decoder the probe cannot build) SHALL record `inner_tar`
in `unavailable_tiers` as `CAPABILITY_UNAVAILABLE`; a corrupt or truncated stream records
nothing, since it answers "no TAR". The probe SHALL record one reason, in this order: a
budget that turns the tier off records `NOT_ENABLED_BY_POLICY`, whether or not the
backend is present; then an absent backend records `CAPABILITY_UNAVAILABLE`, even under
a budget too small for the probe; then a budget too small for the probe records
`BUDGET_EXHAUSTED`.

#### Scenario: inner-TAR matrix

- **WHEN** a compressed source is detected
- **THEN** the inner-TAR probe answers as below

| Case | Expected |
| --- | --- |
| `.gz` → content with `ustar`@257 | `TAR_GZ` (not bare `GZIP`) |
| `.gz` → non-TAR content | `GZIP` |
| `.tar.bz2` with large first block (> peek prefix) | Read up to max block; `TAR_BZ2` |
| Large-block bare `.bz2`, no `ustar` | Bounded read; `BZ2` (no false promotion) |
| Non-seekable `.tar.bz2` needing full block | Buffered in the `ArchiveSource`'s replay prefix; `TAR_BZ2`; backend can still read all |
| Alone `.tar.lzma` / Alone `.tlz` with `ustar`@257 | `ArchiveFormat(TAR, LZMA_ALONE)` |
| Bare Alone `.lzma`, no `ustar` | `ArchiveFormat.LZMA_ALONE` |
| `.tar.xz`, `.tar.lzma` or `.tar.lz` declaring a 4 GiB (lzip: 512 MiB) dictionary | `TAR_*`, decoded with a 4 KiB dictionary |
| `.tar.xz` whose block chain has a filter Python's `lzma` cannot build raw (ARM64) | `XZ`; `inner_tar` skipped as `CAPABILITY_UNAVAILABLE` |
| Multi-stream `.tar.xz` whose first stream decodes to under 262 bytes (or is empty, with or without stream padding) | `TAR_XZ` |
| `.tar.zst` whose frame declares a window over 128 MiB (`zstd --long=28` and up) | `ZST`; `inner_tar` skipped as `CAPABILITY_UNAVAILABLE` |
| `.tar.zst` with an 8 MiB window, `max_decoder_memory=4 MiB` | `ZST`; `inner_tar` skipped as `CAPABILITY_UNAVAILABLE`; `DETECTION_DECODER_LIMITED` names `max_decoder_memory=4194304`; reading it raises `ResourceLimitError` |
| `.tar.xz` declaring a 64 MiB dictionary, `max_decoder_memory=32 MiB` | `TAR_XZ` (the probe reserves 4 KiB); opening it raises `ResourceLimitError` |
| `.tar.gz`, any cap | `TAR_GZ` (no cap applies to a 32 KiB window) |
