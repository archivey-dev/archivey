# Brotli

Current maintainer truth for Brotli (`.br`) as a single-file format and inside `.tar.br`.
Brotli is the one codec here with no magic number and no trailer, so most of this page is
about detection: how archivey decides a source is Brotli, how often that decision is
wrong, and what a caller sees when it is. What Brotli shares with the other codecs, the
one-member reader, the seek table and the truncation contract, is on
[`single-file.md`](single-file.md). Registers keep the status; this page states the
behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | Brotli as a one-member archive and inside `.tar.br` |
| Write | **Not shipped** |
| Backends | `brotli` 1.2.1 or later, from `[recommended]`, through its incremental `Decompressor` under `DecompressorStream` |
| Seeking | A backward seek decodes again from the start |
| Size | `None`. Brotli has no size field |
| Digests | None. Brotli has no checksum |
| Metadata | None beyond the shared fields |
| Truncation | Raised as `TruncatedError` when the decoder never reaches the last meta-block |
| Detection | By a content probe only, which runs for a `.br` name, under `open_stream`, or with `always_probe_content=True`; `PROBABLE` or `GUESS` (§2.1); a failed read of a probe-only match is stamped `format_unconfirmed` |

**Three things a reader might expect and will not find.** A Brotli file with no extension is
not found by `open_archive` or `detect_format` by default: the probe runs only for a `.br`,
`.brotli`, `.tar.br` or `.tar.brotli` name, or with `always_probe_content=True`, or under
`open_stream`. Where it runs, Brotli is found by decoding, not by a signature, and a small
share of non-Brotli files are still claimed (§3). Damaged Brotli data can decode to wrong bytes with no error, since there
is no checksum. And a read of a misidentified file can deliver up to 64 KiB of invented
bytes before it raises (§4).

## 1. Shape

Three properties generate most of this page.

```
stream:      WBITS (1 to 7 bits)
             meta-block:  ISLAST, MLEN, [ISUNCOMPRESSED]  data …   ← not byte-aligned
             meta-block:  …
             last meta-block (ISLAST=1)
```

**There is no signature.** A stream starts with a window-size field of 1 to 7 bits and goes
straight into a meta-block header. Most byte patterns parse as a valid start: before any
gate, 8.2% of random data and 3.5% of the files in a `/usr` tree decoded as the start of a
Brotli stream. So recognition has to be by decoding, and the question is how much evidence
is enough.

**Meta-blocks declare their own lengths.** Each header states how many bytes it produces;
an uncompressed or metadata meta-block then holds exactly that many raw bytes. That is what
detection can check cheaply: a block that claims more bytes than the source holds is not
Brotli, and the chain of such blocks can be walked without decoding (§2.1). The common
false positive is an uncompressed meta-block, because it asks almost nothing of the bytes
after its header.

**There is no trailer and no checksum.** The only end marker is the `ISLAST` flag. A stream
cut before it is detectable as incomplete; a stream with changed bytes that still parse
decodes to different output with no error.

## 2. The pipeline here

### 2.1 Identify

Brotli is the third content probe, after LZMA Alone and zlib, and runs only when no magic,
SFX scan or far magic has matched. Far magic running first is what keeps a bootable ISO,
whose system area can start like a Brotli stream, from being claimed. The probe is skipped
when `brotli` is not installed.

`BrotliCodec.content_probe` then applies, in order:

1. **The first-block gate**, when the source length is known: a first meta-block that
   declares more uncompressed or metadata bytes than the source holds is rejected
   (`brotli_framing.first_block_overruns_source`).
2. **The chain walk**, when the source length is known: byte-aligned self-describing
   meta-blocks after the first are followed, up to eight links, stopping at the first
   compressed block. A link that overruns the source, or bytes left over after a declared
   last block, reject the match (`walk_chain`). On a non-seekable source the walk
   reads at most 1 MiB ahead.
3. **The decode**: the whole 4 KiB detection window is decoded and must succeed. A shorter
   sample let text through: 7 of 800 Perl modules decoded as Brotli for 256 bytes, none for
   4 096.
4. **The chain decode**, when the walk stopped at a compressed block the window decode did
   not reach: the source is decoded from offset 0 to 4 KiB past that block's header
   (`CHAIN_DECODE_MARGIN`), and an error there rejects the match. This turns away data
   whose first bytes declare a long uncompressed or metadata block: CPython 3.11 and 3.14
   `.pyc` files over about 269 KiB, Type 1 fonts, 1.2 % of random data over 64 KiB. Each
   fails within 256 bytes of the compressed header. The decode is a sequential read, mostly
   a copy. It does not run when its end would pass 1 MiB or the budget's read ceiling, or
   when what is left of `max_decode_input` cannot cover it (most of these cases under
   `FAST`); the walk's verdict then stands and `content_probe_decode` is recorded.
5. **Completeness**: when the whole source is visible, it must decode to its end. A source
   no larger than `completion_window_bytes` (64 KiB under `BALANCED`, off under `FAST`) is
   decoded whole to check that.

A match is reported `PROBABLE` when the first meta-block is compressed or the name ends in
`.br` or `.tar.br`, and `GUESS` otherwise: an uncompressed or metadata first block with no
agreeing extension is the class where the remaining false positives live. Every error from
a probe-only match, at any confidence, is stamped `format_unconfirmed` and emits
`PROBE_FORMAT_UNCONFIRMED`, so a caller can tell a misread file from a damaged one. A match
the `.br` extension agrees with is corroborated and not stamped.

The inner-TAR probe then decodes 512 bytes and upgrades a match to TAR over Brotli
([`single-file.md`](single-file.md) §2.1).

### 2.2 Open and list

The member has no metadata of its own: `size` is `None`, `modified` is `None`, and `hashes`
is empty ([`single-file.md`](single-file.md) §2.2).

### 2.3 Member data

`BrotliDecompressorStream` is `DecompressorStream` over `BrotliDecoder`, which feeds
`brotli.Decompressor` incrementally. It asks for output with `output_buffer_limit` and
checks `can_accept_more_data()` before feeding more, so a `read(1)` does not make the
library materialise a whole meta-block of up to 16 MiB. The limit is per block, with a
floor around 32 KiB, not a byte cap. Those two calls exist from `brotli` 1.2.0: earlier
versions have no way to bound one call's output (CVE-2025-6176). The minimum is 1.2.1, which
also fixes a decoder buffer overflow (CVE-2026-111497).

A `brotli.error` is `CorruptionError`. A cut stream does not raise in the library: the
decompressor simply never reports that it finished, so the engine arms a `TruncatedError`
at the end of input ([`single-file.md`](single-file.md) §2.3). A backward seek decodes again
from the start, and the rewind report says so.

**Bytes after the end.** The library does not say where a stream ends. A `process()`
call whose input runs past the end fails with the same "decoder failed" as damage,
returns none of that call's output, and leaves the decompressor unusable. So
`BrotliDecoder` replays on any `brotli.error`. It keeps the input offset of the last
point where everything handed over had been decoded and returned. That point needs a
call that returned nothing: the library holds output back even from a call with no
limit, so input is handed over in 64 KiB pieces and each is drained until it settles. It
builds a fresh decompressor, brings it to that point by decoding the source from offset
0 with the output thrown away, and then hands over the bytes up to the failure one at a
time, draining output before each byte. If the stream finishes on one of them, the rest
is trailing data: the output lost with the failed call is delivered, skipping what the
caller already had, and the bytes after the end are reported as `ARCHIVE_TRAILING_DATA`
unless they are zeros. If not, the original error stands and is raised as
`CorruptionError`.

The replay reads the source a second time, so it needs a seekable source. From a pipe the
error is raised unchanged, and a Brotli stream with bytes after it is a `CorruptionError`
there. A pipe is read as its bytes arrive, so the bytes after the end can come in a later
feed than the end itself, after a call that finished the stream. `_bytes_after_end` then
raises the error the combined call would have raised, so the error is the same however
the bytes arrive. The bytes delivered before it are not: a call that fails loses its
output, and how much output that call held depends on where the feeds split. That holds
for a sized read of a bare file as much as for a compressed tar; a read of the whole file
drops them either way. A file with no bytes after it never replays. One with them pays
one more decode up to the failure, fed one byte at a time over at most one piece:
measured on a 14 MB `.br`, 0.29 s against 0.13 s for the clean file.

### 2.4 Extract

Nothing here is Brotli-specific ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with the tools listed on [`single-file.md`](single-file.md) §3, and from the
detection census in the investigation linked in §9.

| Source | archivey |
| --- | --- |
| `brotli` output, any size | Detected by the probe and read. A compressed first block is `PROBABLE` without an extension |
| A Brotli file named `.brotli` | Detected by the probe, corroborated by the name, like `.br` |
| A Brotli file followed by `junk` | Reads, then `ARCHIVE_TRAILING_DATA`; from a pipe, `CorruptionError` |
| A cut Brotli file | `TruncatedError` |
| A `/usr` tree of 150 623 files, none of them Brotli | 29 claimed as Brotli (0.019%), measured with the 256-byte sample before the 4 KiB window; each claim's read error is stamped `format_unconfirmed` |
| OLE files (`.msi`, old `.doc`, `Thumbs.db`) | Not probed: the OLE signature stops the content probes ([`detection.md`](../topics/detection.md) §2.5). `FormatDetectionError`, or the extension guess |
| COFF object files | Can be claimed by a probe, LZMA Alone or Brotli ([`xz.md`](xz.md) §3) |
| A 7z, ZIP or RAR behind a low-entropy stub | Found by the SFX scan, not claimed as Brotli |
| CPython 3.11 / 3.14 `.pyc` over ~269 KiB, a Type 1 font (`.pfb`), random data over 64 KiB | Not claimed under `BALANCED`: the chain decode rejects them (§2.1). Before it, these were the 5 non-OLE false claims in 148 255 local files, and 1.2 % of random blobs |
| Data whose compressed block sits past 1 MiB, or whose chain is longer than eight links | Can still be claimed at `GUESS`: nothing past the walk is checked there |

## 4. Threat surface

Brotli-specific only; the shared items are [`single-file.md`](single-file.md) §4.

- **The probe can fabricate a member (threat-model O10, narrowed).** A non-Brotli file that
  passes every gate lists as one `<name>.uncompressed` member. Three things remain true of
  such a file: the listing is wrong, a full read raises, and a read can already have
  delivered fabricated bytes before the raise (65 536 measured). The `GUESS` confidence and
  the `format_unconfirmed` stamp are how a caller finds out.
- **Detection decodes.** The probe decodes 4 KiB, the chain walk reads up to eight headers,
  the chain decode can decode up to 1 MiB from the start, and the completeness check can
  decode a whole source of up to 64 KiB. All of it is inside the detection budget
  (threat-model O11).
- **One call's output is bounded by the library** from `brotli` 1.2.0 (§2.3). A single
  meta-block can declare 16 MiB; without the bound, `read(1)` produced all of it.
- **No checksum.** Damaged data that still parses gives wrong bytes. That is the format.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| A non-Brotli file lists as one `.uncompressed` member | **format** | No magic (§1); the gates narrow it, and the claim is `GUESS` or stamped (§2.1) |
| A read delivers bytes, then raises | **format** | A fabricated claim decodes for a while before it fails (§4) |
| `member.size` is `None` | **format** | No size field |
| Damaged data reads with no error | **format** | No checksum |
| A backward seek re-decodes from the start | **format** | No restart points |
| From a pipe, bytes after a Brotli stream are `CorruptionError` | **library** / **archivey** | Telling them from damage needs a second read of the source (§2.3) |
| A flip near the end can read as a shorter stream plus trailing data | **format** | No checksum, and the damaged bytes may form a valid end (§2.3) |
| No Brotli support without `[recommended]`, and no detection either | **archivey** | The probe needs the decoder |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Detect Brotli by content at all | `.br` files arrive without names (pipes, HTTP bodies saved to disk) | Extension only, which never finds an unnamed stream |
| The first-block framing gate and the `GUESS` split (PR #261) | Rejects blocks that claim more than the source holds; marks the class that remains unsure | Decoding alone, which accepted 3.5% of real files |
| Completeness and the chain walk (PR #265) | A fully visible source must end where it says; later blocks must fit too | A larger sample alone |
| Stamp by provenance, not confidence (PR #267) | Any probe-only claim can be wrong; the caller needs the signal whatever the grade | Stamping `GUESS` only |
| Decode the whole 4 KiB window, and a small source whole (PR #466) | The 256-byte sample let text through | 256 bytes |
| Far magic before content probes (PR #270) | A bootable ISO's system area decoded as Brotli | Probes first |
| Decode to the compressed block the walk stops at | Every measured false claim over 64 KiB failed within 256 bytes of it; the read is sequential and mostly a copy | Stopping signatures for `.pyc` and PFB (the pyc magic changes per CPython version); parsing the block's Huffman tables without decoding |
| Require `brotli` 1.2.0 | `output_buffer_limit` bounds one call's output (CVE-2025-6176) | Older versions, which decoded a whole meta-block per call |
| Require `brotli` 1.2.1 | Fixes a decoder buffer overflow (CVE-2026-111497) present from 1.0.3 through 1.2.0. The floor binds an install of `[recommended]` only: a brotli that is already present is used whatever its version, so `docs/security.md` §Hardening tells users to upgrade it | Staying on 1.2.0, which left the overflow reachable from a crafted stream; a runtime version check, which no other Python codec has |
| Replay from the start to tell bytes after the end from damage | The library gives the same error for both and loses the call's output; a replay costs nothing on a clean file | Feeding one byte at a time always, which is slow on every file; refusing bytes after the end, unlike every other codec |
| `brotli`, not `brotlicffi` | `brotli` is the reference binding; `brotlicffi` helps only on PyPy | Supporting both |

## 7. Open questions

- **A re-measured census with the 4 KiB window.** The 0.019% residual predates it and is
  the baseline for the next count.

## 8. Verify

```bash
./scripts/test.sh tests/test_brotli_framing_gate.py tests/test_probe_completeness_gate.py \
    tests/test_codecs.py tests/test_detection.py tests/test_single_file.py -k "brotli or br_ or chain or completeness or guess"
```

| Claim |
| --- |
| Reads; the backend is optional |
| Cut is `TruncatedError`, damage `CorruptionError` |
| One call's output is bounded |
| No real Brotli file is rejected |
| The first-block gate |
| The chain walk and completeness |
| The 4 KiB sample |
| The chain decode |
| `PROBABLE` and `GUESS` |
| `format_unconfirmed` on a probe-only failure |
| Archives behind a stub are not Brotli |

**Building fixtures.** `brotli.compress` writes Brotli; the `brotli` command installs from
the distribution. `scripts/exploration/brotli_probe_field_survey.py` is the reference for
the meta-block header parser.

## 9. References

- RFC 7932 (Brotli): §9.1 stream header and WBITS, §9.2 meta-block header
- Investigation: [`brotli-content-probe-results.md`](../investigations/brotli-content-probe-results.md)
- Registers: [`threat-model.md`](../threat-model.md) O10, O11
- Decisions: [`library-analysis.md`](../library-analysis.md) §brotli
- Code: `internal/streams/codecs/` (`brotli_codec.py`: `BrotliCodec`;
  `brotli_framing.py`; `brotli_decoder.py`: `BrotliDecoder`) · `internal/detection.py`
  (`_brotli_probe_confidence`)
- Handbook: [`single-file.md`](single-file.md) · [`xz.md`](xz.md) (the LZMA Alone probe) ·
  [`tar.md`](tar.md)
