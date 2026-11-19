## MODIFIED Requirements

### Requirement: A content probe SHALL follow a format's self-describing block chain

A content probe SHALL check reachable block framing even without a known source length.

**Scope: formats whose blocks are byte-aligned and self-describing, so a successor's
offset is known without decompressing. Brotli is the only such format today.** For
those, a probe SHALL follow the chain to test the same framing invariant beyond the
first block, and SHALL reject a link that overruns the source or a declared end that
leaves trailing bytes. A format outside that scope is unaffected — this is not an
obligation on every probe. The chain SHALL also be walked when source length is unknown.
Short or empty full range reads prove EOF; a declined read (`None`) proves nothing.
An available-byte observation SHALL carry separate EOF evidence: a short arrival
on an open pipe SHALL NOT prove EOF. Optional end checks SHALL inspect buffered
bytes without waiting for a following byte or for the writer to close. A missing
successor, a truncated declared final block, or bytes after a declared end SHALL reject
the match when the range reads establish that fact. Prefix exhaustion without a known
length or an available range read SHALL NOT count as EOF.

The walk is mandatory rather than optional because the alternative is a probe whose
false-positive rate silently depends on whether an implementer felt like walking. What
is *bounded* is the work, not the obligation: the budgets below are the escape hatch,
and exhausting either is a defined outcome rather than a licence to skip the walk.

The walk exists because the first-block check goes **vacuous on large sources**:
Brotli's MLEN field tops out at 2²⁴, so past ~16 MiB every declared length fits
trivially. Measured on random blobs, the walk takes 16 MiB acceptance from 8.33% (where
the first-block check buys nothing) to 2.00%, and a `/usr` tree from 61 survivors to 14.

The walk SHALL be **bounded by a declared link count** (today: 8). Cheap random
access SHALL retain header seeks at any offset, without buffering literal bodies.
Sources requiring buffer growth SHALL retain the existing 1 MiB/read-ceiling limit.
On forward-only sources, additional buffering SHALL also obey
`max_probe_forward_bytes` (`detection-cost`); with a zero allowance, only bytes already
buffered may be inspected. Exhausting a limit means *cannot disprove*: the probe
SHALL keep the verdict the earlier rules reached and MUST NOT reject on that basis.
Absence of evidence is not evidence against, so budget exhaustion cannot manufacture
a false negative. The forward-only allowance SHALL NOT disable existing checks on
seekable expensive-seek sources, including remote sources and member streams.

The walk stops at the first compressed block, which carries no declared length to check.
On a real Brotli file whose first meta-block is compressed — 79 of 150 in the corpus —
it therefore terminates immediately, having read four bytes.

Following the chain requires bytes at offsets that may lie past the peeked prefix.
However a probe reaches them, the header reads SHALL stay within the declared bounds and
SHALL NOT decompress.

**When the walk stops at a compressed block the window decode did not reach, the probe
SHALL decode the source from offset 0 to a declared margin past that block's header
(today: 4 KiB), and SHALL reject on a decode error there.** The walk alone leaves a gap:
data whose first bytes declare a long uncompressed or metadata block passes the walk and
the 4 KiB window decode, and on a source over the completion window nothing else looks
at it. Measured: CPython 3.11/3.14 `.pyc` files over ~269 KiB, a Type 1 font, about 100
libmagic signature bodies, and 1.2–1.3 % of uniform random data over 64 KiB were claimed
this way, and a real decoder rejects each within 256 bytes of the compressed header. The
decode is a sequential read of `[0, end)`, mostly a copy of the declared bytes. It SHALL
stay within its own input cap (`end` at most 1 MiB, applied to every source),
independently of cheap header-seek offsets, and inside the detection budget: it is
charged to `max_decode_input` and SHALL NOT read past the budget's prefix/far/scan
ceiling (see `detection-cost`). When `end` is out of reach, the budget cannot cover it,
or the read is declined, the walk's verdict stands (*cannot disprove*). A real stream
decodes cleanly or runs out of input there, and both SHALL be accepted.

On a forward-only source, an enabled chain decode SHALL feed arrived bytes to one
incremental decoder until it fails, finishes, or reaches its input/output bound.
A short arrival SHALL NOT end the trial while the decoder still needs input within
the allowed range. A finished decoder SHALL NOT fetch optional following bytes.
The trial's input ceiling SHALL be charged before fetching its sample, even when
it finishes before reaching that ceiling.

#### Scenario: chain walk matrix

- **WHEN** a content probe encounters a case listed below
- **THEN** its framing verdict and bounded reads match the expected result.

| Case | Expected |
| --- | --- |
| Real `.br` file, first meta-block compressed | Walk stops at once; accepted |
| Real `.br` file, uncompressed first block, all links fit | Accepted — every declared length is honoured |
| Real stream over 64 KiB whose compressed block follows a long uncompressed or metadata run | Decoded to just past that block's header; accepted |
| Data whose declared chain fits, compressed header past the window, decode fails there (`.pyc`, random data) | **Rejected** |
| The same, compressed header past the 1 MiB reach, or the budget cannot cover the decode | Not decoded; verdict unchanged — **not** a rejection |
| Fabrication whose first block fits but whose second link overruns the source | **Rejected** |
| Fabrication whose chain reaches a declared end with bytes left over | **Rejected** |
| 16 MiB source whose first declared block fits trivially (MLEN ceiling) | Walk decides; first-block check alone would have accepted |
| Chain longer than the link bound | Verdict unchanged from the earlier rules; **not** a rejection |
| Non-seekable `read_at` past the 1 MiB offset ceiling | Declined → cannot disprove; earlier verdict stands |
| Invalid successor past 1 MiB on a path or cheap seekable stream | Rejected under every preset; the header seek does not buffer the literal body |
| Finite remote source or seekable decoded member, invalid successor within the existing buffer ceiling | Rejected under every preset, as from `BytesIO` |
| Complete Brotli stream larger than the completion window on a held-open pipe, including `THOROUGH` | Detection returns without waiting for optional framing bytes or pipe closure |
| Partial available header without EOF evidence | Cannot disprove; a short arrival is not truncation |
| Valid compressed header followed by corruption 64 bytes later, pipe with 7-byte or 64 KiB source chunks, `THOROUGH` | Rejected as from memory, within the chain-decode bounds |
| Complete compressed block before the trial's target input end, writer still open | Trial stops without fetching optional following bytes |
| OLE/CFB file ≥ 7425 bytes | Its constant magic yields a fitting chain that stops at a compressed header at 7 426; the decode there rejects it. Detection does not run the probe on it in any case (*A known non-archive signature stops the content probes*) |

| Unknown-size source, missing successor within reach, cheap seek or enabled forward reads | Rejected from EOF evidence |
| Unknown-size pipe under `FAST` or `BALANCED`, next header not buffered | Earlier verdict stands; forward read recorded as not enabled by policy |
| Valid reference-encoder literal block larger than 128 KiB | Not rejected by size; walk or decline under the same budgets |

### Requirement: A content probe SHALL NOT accept framing the source cannot hold

RFC 7932 lets a Brotli meta-block *declare* a length and then emit literal bytes: a
non-last uncompressed meta-block is a four-byte header after which the decoder copies.
A bounded-prefix decode therefore cannot distinguish a real stream from any data whose
first bytes happen to parse as such a header — measured at **8.2% of arbitrary binary
data** and **3.5% of a real `/usr` tree**, the latter dominated by files opening `/**\n`.

A **complete, valid** stream always satisfies
`header_bytes + declared_length <= source_length` for a declared (uncompressed or
metadata) meta-block, because those bytes must physically be present. When the source
length is known, the Brotli probe SHALL reject a prefix whose **first** declared
meta-block violates that invariant. Detection supplies that length via the existing
cheap size probe (`source_byte_size`); when the length is unknown the check is skipped,
not guessed. The chain walk may still use reachable EOF evidence without a known
length.

A stronger **chain walk** — following byte-aligned self-describing meta-blocks and
rejecting a later link that overruns, or a declared end with trailing bytes — is
required by its own requirement, *A content probe SHALL follow a format's self-describing
block chain*, which supersedes the deferral this paragraph used to record. This
requirement remains satisfied by the first-block check alone; the walk is what covers
sources large enough for the first-block check to go vacuous.

The same first-block principle SHALL apply to the **LZMA Alone** probe, whose only
measured real-world false positives are files that are *exactly* its 13-byte header: a
source no longer than the header carries no range-coder payload and cannot be an Alone
stream. Rejecting those removed 4 of 4 measured hits across 40 000 real files. This is
the same invariant, not a second heuristic — the framing a source declares must fit what
it holds.

No decompression beyond today's bounded prefix is required for the first-block check.

This requirement is about *soundness*, not tuning: it MUST NOT reject any complete valid
stream, so the real-stream corpus in `testing-contract` is the binding constraint.
Probe-parameter tuning (larger prefix, minimum decoded output, WBITS whitelists) SHALL
NOT be used in its place — each was measured to trade false positives for false negatives
roughly one-for-one, or to reject real `.br` files.

That distinction — a threshold traded against a false-positive rate, versus a check the
format's own framing already implies — is what *Executable-looking prefixes must not
silently become a wrong stream format* is stating when it forbids "tightening the Brotli
probe". The two requirements stand together; this one is the invariant, that one is the
prohibition on knobs.

#### Scenario: framing gate matrix

- **WHEN** the probe examines a case listed below
- **THEN** its framing gate follows the expected result.

| Case | Expected |
| --- | --- |
| Real `.br` file whose first meta-block is compressed | Accepted (no declared length to check) |
| Real `.br` file whose first meta-block is uncompressed (incompressible payload) | Accepted — declared length fits by construction |
| `MZ` + `\x90`×4094 (declares 2 171 061 bytes, file is 4096) | Rejected — declared framing overruns the source |
| A `/**\n…` C header (declares an uncompressed block past EOF) | Rejected |
| Arbitrary data whose first declared block happens to fit | Probe may still accept at *this* requirement's floor; the residual is then narrowed by *A content probe SHALL follow a format's self-describing block chain* below |
| OLE/CFB file (`D0 CF 11 E0 A1 B1 1A E1`, ≥ 7425 bytes) | Brotli first-block gate accepts (MLEN 7422 always fits); `BrotliCodec.content_probe` rejects it by decoding to the compressed block that follows (*A content probe SHALL follow a format's self-describing block chain*). End-to-end `detect_format` does not run the probes: the OLE signature stops them (*A known non-archive signature stops the content probes*) |
| COFF-shaped prefix (`64 86 …` with a fitting uncompressed trailer, then a compressed header) | Brotli gate accepts; the probe rejects it as for OLE. The Alone probe declines the header's zero uncompressed size, so detection fails |
| A 13-byte text file, LZMA Alone probe | **Rejected** — a source that is only the 13-byte header cannot be an Alone stream (removes the entire measured real-world Alone residual, 4 of 4) |
| Non-seekable source of unknown length (≥ `DETECTION_LIMIT` peek) | Gate skipped; today's behaviour |
| Non-seekable source shorter than the detection peek | Length inferred from the short peek; gate applies |
| Source length known to be shorter than the declared metadata skip | Rejected |
