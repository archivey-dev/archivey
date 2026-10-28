# Format Detection

## Purpose

Identify archive format of a path or binary stream without fully opening it.
Returns frozen `FormatInfo` (format, confidence, optional SFX offset, detection
diagnostics). Detection never discards bytes the opener still needs.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Auto-detect inside `open_archive`; caller sees events on `reader.diagnostics` |
| `diagnostics` | Collector/budget/policy; this spec owns the open handoff |
| `backend-registry` | Container `MAGIC` / `EXTENSIONS` / `CONTENT_PROBES` |
| `compressed-streams` | Codec descriptors supply stream-codec magic/probes |

## Requirements

### Requirement: detect_format() returns a FormatInfo

The system SHALL expose:

```python
archivey.detect_format(
    source: str | Path | BinaryIO,
    *,
    config: ArchiveyConfig | None = None,
) -> FormatInfo
```

```python
class DetectionConfidence(Enum):
    CERTAIN = "certain"
    PROBABLE = "probable"
    GUESS = "guess"

@dataclass(frozen=True)
class FormatInfo:
    format: ArchiveFormat
    confidence: DetectionConfidence
    detected_by: Literal["magic", "extension", "content_probe", "sfx_scan", "directory"]
    payload_offset: int = 0
    diagnostics: DiagnosticSummary = DiagnosticSummary.empty()
    cost_receipt: DetectionCostReceipt | None = None   # compare=False; see detection-cost
    unavailable_tiers: tuple[TierSkip, ...] = ()       # compare=False; see detection-cost
```

`config=None` → library default. `confidence` = magic / structural probe /
extension-guess. `payload_offset > 0` marks an SFX payload start. `cost_receipt` and
`unavailable_tiers` are part of this contract; `detection-cost` defines what they hold.
`FormatInfo` also carries a provisional `corroborated: bool` for `open_archive`'s own use,
which SHALL NOT be part of this contract: its `False` cannot tell an uncorroborated probe
from a result that was not a probe.

A **directory path** SHALL return `FormatInfo(format=DIRECTORY,
confidence=CERTAIN, detected_by="directory")` without reading anything, the same
format `open_archive` reads it as. Its `cost_receipt` SHALL be the zero receipt (one pass, no
bytes read). It SHALL NOT raise `IsADirectoryError` or any
other `OSError`. An empty string is not a directory path, although `Path("")` is
`Path(".")`: `detect_format("")` SHALL raise `ValueError` (`error-handling`).

A **path to a volume of a set** SHALL be detected on the source `open_archive` resolves
for it: any part of a numbered split set (`set.7z.002`, `set.zip.003`, `set.exe.002`) on
the parts joined in order, and a RAR continuation on volume 1. A middle part has no magic
at offset 0, so detecting the named file alone would refuse a path `open_archive` opens.
That resolution runs before detection reads a byte and MAY raise what `open_archive`
raises for the same path: a numbered set with a gap SHALL raise `TruncatedError` naming the
missing part. A lone first part (`set.zip.001` with no other part) SHALL be detected as the
format its bytes show; `open_archive` refuses it as an incomplete set.

**Collectors:**

| Path | Behavior |
| --- | --- |
| Standalone `detect_format` | One finite collector; policy/callback/logging/budget; final summary on `FormatInfo.diagnostics` |
| Inside `open_archive` | Open creates prospective-reader collector + detection watermark, passes that collector into detection. On success the reader owns it — no seed/merge/replay/copy; each retained occurrence charged once. Internal detection-range `FormatInfo.diagnostics` is not retained after handoff; same events remain on the reader's cumulative summary |

#### Scenario: detect / handoff matrix

| Case | Expected |
| --- | --- |
| Standalone detect with magic/extension conflict | `FormatInfo.diagnostics` has exact conflict count + retained detail under default budget |
| Auto-detect inside `open_archive` retains conflict, open succeeds | Reader continues same collector/order/budget; no copied aggregate |
| Magic match | `confidence=CERTAIN`, `detected_by="magic"` |
| Extension-only guess | `confidence=GUESS`, `detected_by="extension"` |
| Directory path | `format=DIRECTORY`, `confidence=CERTAIN`, `detected_by="directory"`; zero `cost_receipt`; no `OSError` |
| Empty string `""` | `ValueError`; the current directory is not detected |
| Any part of a numbered split set, or a RAR continuation | The format, `detected_by` and `payload_offset` `open_archive` reports for the same path |
| Numbered set with a gap (`set.zip.002`, no `set.zip.001`) | `TruncatedError` naming the missing part, from `detect_format` and `open_archive` alike |
| Lone first part (`set.zip.001`, no other part) | The format its bytes show; `open_archive` raises `TruncatedError` |
| Explicit `diagnostic_policy` on detect | IGNORE/COLLECT/RAISE applies to that finite detection |

### Requirement: Magic-first detection with extension fallback and confidence scoring

The system SHALL execute format detection with this algorithm:

1. Read up to `DETECTION_LIMIT` bytes (default 4096) from the source.
2. **Near magic** — the magic-byte table at exact offsets within that window. Match →
   `CERTAIN` / `detected_by="magic"`.
3. **Prefixed payload** — the tiers owned by *Self-extracting (SFX) archives are detected
   behind an executable stub*.
4. **Far magic** — signatures whose end offset lies outside the default window, today ISO
   9660's `CD001` at 32 769. Match → `CERTAIN` / `detected_by="magic"`. This SHALL be
   attempted **before** the content probes: it is exact magic at a known offset and they
   are the weakest signal available. It SHALL be skipped when the source size is known to
   be smaller than the extended window, and a source too short for it SHALL fall through
   rather than be rejected.
5. **Trailer magic** — exact magic at the start of a fixed-length block at the end of the
   source, today UDIF's `koly` block (512 bytes). Match → `CERTAIN` /
   `detected_by="magic"`. This SHALL run after far magic and before the content probes.
   It SHALL also outrank a near-magic hit whose format the trailer lists in `preempts`
   (today bzip2 and xz): that hit is one block of the image, and the replacement SHALL
   happen before an inner-TAR upgrade. The read SHALL be a cheap seek that restores the
   handle. A source that cannot seek cheaply SHALL skip it, except that a tail already
   held in the detection prefix still matches. A source shorter than the block SHALL NOT
   be read for it.
6. **Self-checking header** — a format with no magic whose first block proves itself,
   today a TAR header without `ustar` (a v7 tar): the first 512 bytes SHALL parse as a
   TAR header, so the stored checksum equals the unsigned or signed sum of the block with
   its checksum field as spaces and every numeric field is a number, and the name SHALL
   be non-empty. Match → `PROBABLE` / `detected_by="content_probe"`. This SHALL run on
   every source, whatever its name, after trailer magic and before the content probes.
7. **Content probes** — formats with no exact magic. Match → `detected_by="content_probe"`.
   Unless `ArchiveyConfig.always_probe_content` is set, only the probe of a stream format
   the source's extension names SHALL run (see *Magic-less formats are detected by a
   content probe*); `open_stream` SHALL run every probe.
8. **Extension** — `Path` with a known extension → `GUESS` / `detected_by="extension"`.
9. `FormatDetectionError` when nothing matched. When step 7 ran only the probes the
   extension allows, the message SHALL name the three ways to read a nameless
   probe-only stream: `format=`, `open_stream()` and `always_probe_content=True`.

Steps are ordered attempts, not alternatives: a step that produces no match falls through,
and attempting one never prevents a later one from running.

**Tie rule.** When more than one format could match, the earlier step wins, and within a
step the earlier entry in registry order wins. This is the documented rule, not an
accident of iteration: `confidence` is a provisional grade and `detected_by` an open set,
so a later release may grade evidence more finely without breaking a caller that treats
unknown values as possible. A source with no bytes left at its current position (empty,
or already read to its end) SHALL raise `FormatDetectionError` saying there are no bytes
to read, not that nothing matched. A non-blocking stream whose `read` returns `None` has
not run out of bytes; it SHALL raise `BlockingIOError`, whether nothing has arrived or only
part of the prefix has (`access-mode-and-cost`, "a non-blocking read is not end of file").

#### Scenario: unrecognised bytes, no path

| Case | Expected |
| --- | --- |
| Non-seekable `BinaryIO`, no filename, no magic | `FormatDetectionError` |

#### Scenario: far magic precedes the content probes

| Case | Expected |
| --- | --- |
| Bootable/hybrid ISO whose 32 KiB system area holds boot code a probe accepts | `ISO` / `CERTAIN` / `magic` — not a fabricated single-file member |
| ISO with a zeroed system area | `ISO` / `CERTAIN` / `magic`; unchanged |
| Source smaller than the extended window, size known | Step 4 skipped without an extended peek; falls through |
| Source too short for the window, size unknown | Short peek, no match, falls through — never an error for being short |
| Real Brotli stream larger than the window, no extension, `always_probe_content=True` | One bounded peek misses at step 4, then step 7 detects it |

### Requirement: Conflict resolution — magic wins and warning is emitted

Magic/content result wins per existing precedence. A genuine mismatch SHALL emit
`FORMAT_EXTENSION_CONFLICT` with typed context (source display name, extension
format, content format). Counted on `FormatInfo.diagnostics`; under
`COLLECT`/`RAISE` + budget, retained; logged via `archivey.detection` per policy.
SHALL NOT attach to `ArchiveInfo`. If a reader is created, the occurrence already
belongs to the transferred collector.

#### Scenario: conflict matrix

| Case | Expected |
| --- | --- |
| `archive.tar.gz` with 7z magic | `SEVEN_Z` + `FORMAT_EXTENSION_CONFLICT` on `FormatInfo`; default policy logs on `archivey.detection` |
| `open_archive` policy raises on conflict | `DiagnosticRaisedError` during detection; no reader |
| `open_archive(..., format=ZIP)` | No format-conflict diagnostic |

### Requirement: Magic/extension/probe tables are aggregated from backends and codec descriptors

Detector tables SHALL come from container backends (`ReadBackend.MAGIC` /
`EXTENSIONS` / `CONTENT_PROBES`) and stream-codec descriptors — no per-format
`detect()` logic. Stream-codec rows come from descriptors (not hand-listed on
`SingleFileBackend`). A content probe is the codec's `content_probe` function.
A codec's extensions are its canonical one, derived from its format, then its
`extension_aliases`; today `.zlib` for zlib and `.brotli` for Brotli, each with a `.tar.`
form. Both formats are found only by a probe, which runs only for a name that claims
the format, so a common alias is the difference between a file that opens and one
that is refused.
Detected formats and `detected_by` MUST match prior behavior. Confidence MUST also
match prior behavior **except** for an uncorroborated Brotli content-probe match,
which reports `GUESS` (see the magic-less-formats requirement).

#### Scenario: table sources matrix

| Case | Expected |
| --- | --- |
| `.gz` / `.zst` | Same result as before; magic from codec descriptors |
| zlib / LZMA Alone | `PROBABLE` / `content_probe` from descriptor functions — unchanged |
| Brotli, extension corroborates | `PROBABLE` / `content_probe` |
| Brotli, first meta-block compressed, no corroborating extension | `PROBABLE` / `content_probe` |
| Brotli, first meta-block uncompressed/metadata, no corroborating extension | `GUESS` / `content_probe` |
| ZIP / TAR / ISO | Container backend `MAGIC`, merged into the same table |
| `x.brotli` / `x.tar.brotli` holding Brotli | Brotli probe runs; `BROTLI` / `TAR` × `BROTLI`, corroborated |
| `x.zlib` / `x.tar.zlib` holding zlib | zlib probe runs; `ZLIB` / `TAR` × `ZLIB`, corroborated |

### Requirement: Magic-byte table

Exact matches only (no fuzzy/weak magic). Recognised:

| Format | Signature (summary) |
| --- | --- |
| ZIP | `50 4B 03 04` / `07 08` / `05 06` |
| GZip | `1F 8B` |
| BZip2 | `42 5A 68` |
| XZ | `FD 37 7A 58 5A 00` |
| Zstandard | `28 B5 2F FD`, optionally preceded by skippable frames |
| 7-Zip | `37 7A BC AF 27 1C` |
| RAR 4.x / 5.x | `52 61 72 21 1A 07 00` / `… 01 00` |
| ISO 9660 | `CD001` at 32769 |
| ISO 9660, raw CD sector image | `00 FF×10 00` sector sync at 0 (claimed so `format-iso` can refuse it by name) |
| UDIF | `6B 6F 6C 79 00 00 00 04 00 00 02 00` (`koly`, version 4, header size 512) at offset 0, or at the start of the last 512 bytes |
| TAR | `ustar` at 257 |
| LZ4 | `04 22 4D 18` (frame); `02 21 4C 18` (legacy stream, `lz4 -l`) |
| lzip | `LZIP` |
| unix-compress | `1F 9D` |

Formats without reliable exact magic (notably **zlib**) SHALL NOT appear here —
content probe only.

A zstd **skippable frame** — magic in `0x184D2A50 .. 0x184D2A5F` followed by a
little-endian `uint32` payload size — carries no compressed data and MAY precede the first
regular frame. Detection SHALL walk consecutive skippable frames by their declared sizes
within the peeked prefix and match the regular frame that follows. A source of skippable
frames alone, or one whose declared size runs past the prefix, SHALL NOT be claimed as
zstd: the walk is arithmetic over already-peeked bytes and never extends the read.

#### Scenario: magic matrix

| Case | Expected |
| --- | --- |
| Starts `50 4B 03 04` | ZIP, `CERTAIN`, `magic` |
| Magic table consulted for zlib | No zlib entry; CMF/FLG → zlib probe |
| `ustar` at 257, ≥512 bytes | TAR, `CERTAIN`, `magic` |
| No `ustar`; first 512 bytes a TAR header with a matching checksum and a name, from a path, a `BytesIO` or a pipe, named or not | TAR, `PROBABLE`, `content_probe` |
| The same block one byte off its checksum, or with an empty name, no extension | `FormatDetectionError` |
| gzip of such a v7 tar | `TAR_GZ`, `PROBABLE`, `content_probe` |
| Raw CD sector sync at 0 | ISO, `CERTAIN`, `magic`; opening it raises `UnsupportedFeatureError` |
| `koly` block at offset 0 | `DMG`, `CERTAIN`, `magic`; opening it raises `UnsupportedFeatureError` |
| `koly` trailer, and no earlier step matched | `DMG`, `CERTAIN`, `magic`; opening it raises `UnsupportedFeatureError` |
| `CD001` at 32 769 and a `koly` trailer, no `koly` at offset 0 | `ISO`, `CERTAIN`, `magic` — far magic already matched, so the trailer is not consulted |
| Starts `02 21 4C 18` (legacy LZ4) | LZ4, `CERTAIN`, `magic` |

#### Scenario: zstd frame prefix

| Case | Expected |
| --- | --- |
| Regular frame at offset 0 | `ZST`, `CERTAIN`, `magic` |
| One skippable frame, then a regular frame | `ZST`, `CERTAIN`, `magic` |
| Several chained skippable frames, then a regular frame | `ZST`, `CERTAIN`, `magic` |
| Skippable frames only, no regular frame | No zstd claim; falls through |
| Skippable frame whose declared size runs past the peeked prefix | No zstd claim; no extended read |

### Requirement: Magic-less formats are detected by a content probe

When the magic-byte table yields no match, the system SHALL run the registered content
probes on the peeked prefix (consumes nothing), except after a strong executable cue or a
known non-archive signature (see *A known non-archive signature stops the content
probes*).

**Which probes run.** A probe is the weakest evidence detection has, and on a source with
no name it is the only evidence: real binary files pass the LZMA Alone and Brotli probes
(a backup-drive scan: 435 of 437 Brotli hits and 51 of 55 Alone hits were other files;
26 681 zlib hits were git loose objects). So by default `open_archive` and
`detect_format` SHALL run only the probe of a stream format the source's extension
names: the extension map's format (`.br`, `.tar.br`, `.zz`, `.lzma`, …), plus LZMA Alone
for `.tlz` (see *Keep `.tlz` as TAR × LZIP*). Any other source SHALL run no probe.
Whenever the name leaves out at least one probe, whether or not another one runs, the
step SHALL be recorded in `unavailable_tiers` as `content_probe` /
`NOT_ENABLED_BY_POLICY`. `ArchiveyConfig.always_probe_content=True` SHALL run every
probe whatever the name. `open_stream` SHALL always run every probe: its caller says the
source is a compressed stream, so a probe only picks the codec. The internal detections
`open_archive` runs under `format=` (stub check, empty-listing rescan) SHALL follow the
caller's `always_probe_content`. This covers Brotli (no
signature), zlib (too-unspecific CMF/FLG), and LZMA Alone (13-byte header whose
properties byte is too weak for exact magic). Probes typically decode a bounded
prefix; MAY gate on cheap structural bytes first; and MAY consult the source length
when detection knows it (see the framing requirement below). Skip when the
decompressor backend is missing (fall through to extension). A probe the extension's
format does not name does not run, so the extension decides between them; a stream
named for another format falls through to that extension's `GUESS`.

A probe match SHALL report `detected_by="content_probe"`. For **Brotli specifically**,
confidence SHALL be `PROBABLE` when the file extension corroborates the format **or**
when the first meta-block is compressed, and `GUESS` when the only evidence is a
probe hit whose first meta-block is uncompressed or metadata. Brotli's probe is the
only one measured to accept ordinary files (3.5% of a real `/usr` tree before the
framing gate), and that false-positive mass concentrates in the uncompressed/metadata
first-block class — so those claims are weaker evidence than a compressed-first hit or
an extension-backed one. This does not change *what* is detected — only what the system
claims to know about it.

The zlib and LZMA Alone probes keep `PROBABLE` unconditionally. Both measured **0 false
positives in 20 000 random blobs**, so the confidence downgrade would cost honesty rather
than buy it. (Alone was additionally re-measured at 0 over 4 000 blobs of 64 KiB; its
real-world residual is a framing problem, not a confidence one — see the framing
requirement.) Random blobs never hold a zero run, so that measurement does not cover a
plausible Alone header followed by zeros, which decodes cleanly: before the zero-run rule
in the framing requirement, 356 of 3 143 libmagic signatures followed by zeros were
claimed, and ID3-tagged MP3s with tag padding; the libmagic scan found that refusing a
leading zero run removes all 356.

Within Brotli, a probe-only hit whose **first meta-block is compressed** SHALL keep
`PROBABLE`: measured on random data, that class is accepted 0.014% of the time against
~100% for an uncompressed first block, and 25 of 25 real streams found in the wild are
compressed-first. An uncompressed or metadata first block is the class every false
positive comes from, and takes `GUESS`. This split grades evidence strength only —
`format_unconfirmed` / `PROBE_FORMAT_UNCONFIRMED` key on probe-only provenance (and
`EXTENSION_FORMAT_UNCONFIRMED` on an extension-only guess), not on confidence (see
*Detection confidence SHALL NOT be the trigger for error provenance*).
Uncompressed-first remains a valid stream class (incompressible payloads); the framing
gate keeps those streams — they are not rejected for being uncompressed-first.

The **zlib** probe SHALL gate on the RFC 1950 header grammar — `CM == 8`, `CINFO <= 7`,
and `(CMF * 256 + FLG) % 31 == 0` — rather than an allow-list of common headers, and SHALL
accept a header with `FDICT` set. All seven legal window sizes are therefore recognised.
`FDICT` is accepted rather than rejected because a preset dictionary is valid zlib and the
decode, not the header, decides what archivey can read: today no dictionary is ever
supplied to the codec layer, so every `FDICT` stream fails that decode and falls through.
The gate does not encode that as a rejection — the day a dictionary can be supplied, the
grammar already admits the header.

The LZMA Alone probe SHALL attempt a bounded `FORMAT_ALONE` decode and MUST NOT
claim streams that already matched exact magic (notably lzip `LZIP` and xz
`FD 37 7A…`). It SHALL NOT reject a **dictionary size** of zero: every 32-bit value is
legal and decoders round values below 4 KiB up to 4 KiB. Rejecting zero was an ordering
workaround for a zero-filled ISO system area, which the far-magic step of the detection
algorithm now answers before any probe runs.

It SHALL, separately, refuse a header declaring an **uncompressed size** of exactly zero.
Any value but the all-ones "unknown" sentinel is the stream's exact output length, so zero
declares a stream carrying no payload — nothing that can be opened. This is the same rule
as the probe's existing refusal to claim an empty successful decode, stated at the header
because a bounded probe cannot reach it: 18 zero bytes are a *valid, complete, empty*
Alone stream (a legal 13-byte header plus a five-byte range-coder init), so zero-filled
padding decodes cleanly to nothing and the bounded read then reports truncation, which is
otherwise a match. This refuses nothing that was ever detected: an empty stream is not
claimed with or without the rule, because the probe already declines an empty decode, and
a `.lzma` name still opens one through the extension. It is a rule about *zero output*,
not about the sentinel — a header carrying a real uncompressed size, as the LZMA SDK's
encoder writes, is as welcome as one carrying the sentinel. The two header fields are
independent: a stream with a zero dictionary size and a real payload is still detected.

It SHALL refuse, before decoding, a header whose range-coder data holds a run of **16 zero
bytes starting in its first 32 bytes**. A range coder fed zeros decodes zero literals
without error, so any plausible header followed by a few hundred zero bytes, or by a zero
byte, a few other bytes and then zeros, decodes as a valid stream of zeros, and reading
it gives a member of zeros with no error. No measured encoder writes such a run: the longest zero
run measured anywhere in real payloads is 3 bytes from liblzma and 7 from the LZMA SDK
encoder (7-Zip), the 7 being a two-zero-byte input whose whole payload is zeros. The
measurement and its inputs are recorded at the rule in `lzma_codec.py`. Unlike the other
Alone rules this one rests on what encoders write, not on what the format allows: an
encoder that coded a long run of zero bytes as literals would write such a run, and
neither measured encoder does, because both code the third byte of a run as a match. A stream refused
here still opens through a `.lzma` name.

#### Scenario: content-probe matrix

| Case | Expected |
| --- | --- |
| No magic; bounded prefix decompresses as Brotli, name is `x.br` | `BROTLI`, `PROBABLE`, `content_probe` |
| No magic, no name, probe-only bytes, default config | No probe runs; `FormatDetectionError` naming `always_probe_content` |
| Same through `open_stream` | Every probe runs; the codec is detected |
| LZMA Alone bytes named `x.zz` | Only the zlib probe runs; it declines; `ZLIB` / `GUESS` / `extension` |
| zlib bytes named `x.gz` | No probe runs (`content_probe` / `NOT_ENABLED_BY_POLICY`); `GZ` / `GUESS` / `extension` |
| Any of the above with `always_probe_content=True` | Every probe runs, as listed in the rows below |
| `always_probe_content=True`; no magic; bounded prefix decompresses as Brotli, first meta-block compressed, no corroborating extension | `BROTLI`, `PROBABLE`, `content_probe` |
| `always_probe_content=True`; no magic; bounded prefix decompresses as Brotli, first meta-block uncompressed/metadata, no corroborating extension | `BROTLI`, `GUESS`, `content_probe` |
| zlib CMF/FLG + clean zlib decode | `ZLIB`, `PROBABLE`, `content_probe` — unchanged |
| zlib-looking header, decode fails | No zlib claim; fall through to extension / fail |
| `.br`, Brotli extra missing | Probe skipped; extension guess `BROTLI`/`GUESS` |
| No magic; bounded prefix decompresses as LZMA Alone | `LZMA_ALONE`, `PROBABLE`, `content_probe` — unchanged |
| Stream starts with `LZIP` | lzip magic wins; Alone probe not claimed |
| Alone-looking bytes that fail `FORMAT_ALONE` decode | No Alone claim; fall through |

#### Scenario: header grammars accept the full legal range

| Case | Expected |
| --- | --- |
| zlib stream at any window size 512 B – 32 KiB (`18 95`, `28 91`, `38 8d`, `48 89`, `58 85`, `68 81`, `78 9c`) | `ZLIB`, `content_probe` — all seven |
| zlib header with `FDICT` set | Header passes the grammar; the decode decides. Archivey supplies no preset dictionary today, so the decode fails and no zlib claim is made |
| Header failing `CM == 8`, `CINFO <= 7` or the mod-31 check (e.g. all-zero bytes) | No zlib claim; no decode attempted |
| LZMA Alone stream whose dictionary-size field is zero | `LZMA_ALONE`, `content_probe` |
| Alone header declaring an uncompressed size of exactly zero | No Alone claim; no payload to open |
| Alone header carrying a real uncompressed size rather than the sentinel | `LZMA_ALONE`, `content_probe` — unaffected |
| Zero-filled source of any length (padding, a sparse or zero-truncated file) | No Alone claim — the header declares zero output |
| Zero-filled source with `CD001` at 32 769 | `ISO` at the far-magic step; no Alone claim |
| Plausible Alone header (e.g. an ID3v2.3 tag) followed by a zero run, or by `00`, a few bytes and a zero run | No Alone claim — no measured encoder writes the run, though it decodes |
| Real Alone stream of an all-zero input (liblzma or LZMA SDK, any level) | `LZMA_ALONE`, `content_probe` — unaffected |

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

A detection decode (this probe and the content probes) SHALL NOT reserve decoder memory
the source declares beyond what its bounded read needs. An LZMA-family decoder (`.xz`,
`.lzma`, `.lz`) SHALL be built with a dictionary no larger than the read's output plus a
small allowance for a filter ahead of LZMA2 (64 bytes), and at least 4 KiB; that decodes
those bytes identically. The xz probe SHALL follow the file through stream padding into
later streams, as the reader does. An xz block whose filter chain cannot be decoded that
way is "can't tell" and its inner TAR is not claimed. A zstd frame whose window is over
2^27 bytes (libzstd's default limit) is "can't tell". A `MemoryError` from a probe's
decoder is "can't tell"; it SHALL NOT escape detection. In the inner-TAR probe, "can't
tell" (an absent backend, or a decoder the probe cannot build) SHALL record `inner_tar`
in `unavailable_tiers` as `CAPABILITY_UNAVAILABLE`; a corrupt or truncated stream records
nothing, since it answers "no TAR". The probe SHALL record one reason, in this order: a
budget that turns the tier off records `NOT_ENABLED_BY_POLICY`, whether or not the
backend is present; then an absent backend records `CAPABILITY_UNAVAILABLE`, even under
a budget too small for the probe; then a budget too small for the probe records
`BUDGET_EXHAUSTED`.

#### Scenario: inner-TAR matrix

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

### Requirement: Keep `.tlz` as TAR × LZIP; Alone content still wins

The system SHALL keep the TAR short alias `.tlz` mapped to
`ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)` (same family as `.lz` /
`.tar.lz`). Canonical Alone paths remain `.lzma` / `.tar.lzma`. Content detection
SHALL still win over the extension alias:

| Leading bytes | Detected format |
| --- | --- |
| Exact `LZIP` magic | LZIP (then inner-TAR probe may yield TAR × LZIP) |
| Alone content probe match | LZMA Alone (then inner-TAR probe may yield TAR × LZMA_ALONE) |

A `.tlz` whose content is LZMA Alone SHALL detect as TAR × LZMA_ALONE and emit
`FORMAT_EXTENSION_CONFLICT` against the lzip alias. A `.tlz` whose content is
lzip SHALL detect as TAR × LZIP with no Alone claim.

#### Scenario: `.tlz` / Alone extension matrix

| Case | Expected |
| --- | --- |
| `test_compat_lzip_1.tlz` (`LZIP` magic + TAR) | TAR × LZIP; no Alone claim |
| `test_compat_lzma_*.tlz` (Alone payload + TAR) | `ArchiveFormat(TAR, LZMA_ALONE)`; members readable; `FORMAT_EXTENSION_CONFLICT` retained under default budget |
| Extension-only `.tlz` with unreadable/empty content | GUESS `ArchiveFormat(TAR, LZIP)` |
| Bare `.lzma` Alone, no TAR | `ArchiveFormat.LZMA_ALONE` |
| `.tar.lzma` Alone + TAR | `ArchiveFormat(TAR, LZMA_ALONE)` |

### Requirement: Self-extracting (SFX) archives are detected behind an executable stub

SFX RAR/7z/ZIP: EXE stub precedes payload. If leading bytes look like executable
(`MZ` / ELF) rather than archive magic, the system SHALL scan for RAR
(`52 61 72 21 1A 07`), 7z (`37 7A BC AF 27 1C`), or ZIP local-header
(`50 4B 03 04`) magic within a bounded forward window equal to the shared
`SFX_MAX` constant (today 2 MiB; same binding as the RAR and 7z SFX scanners)
before running content probes. Match → embedded format
with `payload_offset` = payload start and `detected_by` indicating an SFX scan.
No match → fall through per the differentiation policy from the sibling
requirement, which is graded by cue strength: a strong cue suppresses the content
probes, a weak one does not. "No silent fabricated member" is therefore guaranteed for
a **strong** cue only — see that requirement for the measured reason.

Which magic the scan hunts for SHALL be **backend-declared data**, like every other
detection signal, rather than a table maintained inside the detector. A backend declares
only the magic that can legitimately begin an appended payload: ZIP declares its
local-file header and NOT the end-of-central-directory or spanned markers, which as
needles inside a 2 MiB stub window would claim any executable containing those four
bytes.

Native RAR/7z parsers SHALL accept a start offset (read in place, no copy). ZIP
already locates the EOCD from the tail, so a leading stub is tolerated without a
separate parser scan; detection still SHALL return `ZIP` with `payload_offset`
rather than a stream codec when the ZIP needle matches.

The scan takes the **earliest** matching needle in the window that its format's hit
validator accepts, and resumes past one it rejects. A 7z hit whose declared end falls
short of a known end of source (`HitOutcome.VALID_SHORT`) is kept only as a fallback: the
scan goes on, and a later 7z hit that ends exactly at end of source wins over it, so a
stub that embeds a whole small 7z archive does not hide the real payload after it. With no
such later hit the short one is used, which keeps a 7z followed by trailing data readable.
A held short hit SHALL be displaced only by a later `VALID` hit of the **same** format. A
`VALID` hit of another format SHALL end the scan, and the held short hit SHALL be the
answer: the exact-end preference is a tie-break within one format and never reorders
formats, so the earliest accepted needle still decides between them.

The window bounds where a magic may **start**, not how far its validator reads. A
candidate that starts inside the window SHALL be judged on its whole header, read up to
the smaller of `VALIDATOR_PEEK_MAX` and `max_scan_bytes` past the window end, so under the
presets the same bytes give the same answer at the window end, inside the window, and on
a non-seekable source. A header that does not fit that allowance SHALL be rejected and
`sfx_scan` recorded as *budget exhausted*.

The scan SHALL cap rejected candidates only for a format whose parser runs its own capped
scan (RAR and 7z), and SHALL count them per format, as each of those parsers counts its own
format's. Decoys of one format SHALL NOT spend another's allowance. A format whose reader
runs no such scan SHALL NOT be capped: ZIP already locates the end of central directory
from the tail, so a cap on ZIP candidates would refuse a file that forced `format=ZIP`
opens. With both rules, a file of decoys means the same thing to detection as to a forced
`format=`. After `MAX_VALIDATED_CANDIDATES` (256) rejected candidates of a capped format,
the scan SHALL stop searching for that format's needles, so its later candidates are not
judged, and SHALL record `sfx_scan` as *budget exhausted*, whether or not it answers.

#### Scenario: SFX matrix

| Case | Expected |
| --- | --- |
| `MZ` + 7z magic at offset N | `SEVEN_Z`, `payload_offset == N`; backend opens at N |
| `MZ` + RAR magic at offset N | `RAR`, `payload_offset == N`; backend opens at N |
| `MZ` + ZIP local magic (`PK\x03\x04`) at offset N | `ZIP`, `payload_offset == N`; real ZIP members listed |
| `MZ` + low-entropy filler + RAR/7z/ZIP magic in window | Same as above — **not** `BROTLI` / fabricated single-file member |
| **Strong** executable cue (validated PE / ELF), no RAR/7z/ZIP in window | No content probe runs; extension guess or `FormatDetectionError` — never a fabricated member |
| **Weak** executable cue (bare `MZ` / `\x7fELF`), no RAR/7z/ZIP in window | Content probes run unchanged, so a probe may still claim the stub — the accepted residual, per the sibling requirement and `dev-docs/topics/detection.md` |
| Stub containing a decoy needle the validator rejects | The scan resumes past it and finds the real payload |
| RAR decoy whose header (bad CRC) crosses the window end | Rejected, as at any offset inside the window and on a pipe |
| Real RAR whose main header crosses the window end | `RAR`, `payload_offset` at its marker; receipt within budget |
| A header that crosses the window end by more than a small `max_scan_bytes` allows | Rejected; `sfx_scan` recorded *budget exhausted*; the tier reads at most twice `max_scan_bytes` |
| 256 rejected RAR decoys before the real RAR payload | No `sfx_scan` answer; `sfx_scan` recorded *budget exhausted*; forced `format=RAR` raises `CorruptionError` naming the cap |
| 256 rejected ZIP decoys before a real RAR payload | `RAR` at its marker, as forced `format=RAR` opens it; nothing recorded as cut short |
| 256 rejected ZIP decoys before a real ZIP payload | `ZIP` at its local header, as forced `format=ZIP` opens it; nothing recorded as cut short |
| A window filled with one capped format's decoys | That format's needles are no longer searched after the 256th rejection; the scan does not walk the rest of its decoys |
| Whole valid 7z in the stub, then 256 rejected 7z decoys, then the real 7z | The embedded 7z, as the fallback forced `format=SEVEN_Z` also takes; `sfx_scan` recorded *budget exhausted* |
| Stub containing a whole valid 7z before the real 7z payload | The real payload, which ends at end of source; the embedded one is only a fallback |
| Whole valid 7z in the stub, then a real ZIP payload | `SEVEN_Z` at the stub's 7z: a `VALID` hit of another format does not displace a held short hit |
| A valid 7z followed by trailing bytes, nothing later | That 7z, at its offset |
| Bare brotli / non-executable stream | Unchanged content-probe behaviour |
| Strong cue, no archive in the stub, exactly one of `vol.exe.001` / `vol.7z.001` / `vol.zip.001` beside it | `detect_format` reports that volume's format; `open_archive` (including with `format=` matching that container) opens the set |
| Same stub, but it *does* contain archive magic | The embedded archive; sibling volumes are ignored |
| Two of those first-volume names beside the stub | `UnsupportedFeatureError` naming both |

### Requirement: Executable-looking prefixes must not silently become a wrong stream format

When a source's leading bytes look executable-shaped, detection SHALL NOT let a
content probe (notably Brotli) claim a stream codec and allow `open_archive` to
succeed with a fabricated single-file member (e.g. `*.uncompressed`). That is a
silent wrong answer.

This obligation is **outcome-shaped**, not "disable Brotli whenever the prefix is
`MZ`". A genuine Brotli (or other probe-matched) stream whose first bytes happen
to look executable MUST remain detectable.

The rule, settled by measurement in the archived `sfx-format-detection` design, grades the
evidence:

- A **weak** cue — a bare `MZ` or `\x7fELF` prefix — SHALL trigger the SFX scan and
  nothing else. When the scan finds no archive magic, content probes run unchanged. Two
  or four bytes are not proof, and refusing a probe on them would reject real streams.
- A **strong** cue — a DOS header whose `e_lfanew` points at a `PE\0\0` signature, or an
  ELF identification block with valid `EI_CLASS` / `EI_DATA` / `EI_VERSION` — with no
  archive magic in the window SHALL suppress content probes entirely; detection falls
  through to the extension guess or `FormatDetectionError`. A structurally confirmed
  executable is not a compressed stream.

The system SHALL NOT tighten the Brotli probe with a **threshold** to satisfy this
requirement: measured, a larger probe prefix does not reduce false positives (8.27% →
8.13% of random data at 16x the prefix) and requiring decoded output loses real streams
roughly one-for-one. That prohibition is about knobs traded against a false-positive rate,
and it does **not** reach a check derived from the format's own invariant, which costs no
real streams — see *A content probe SHALL NOT accept framing the source cannot hold*.

The residual — arbitrary non-archive data that the Brotli probe claims, which is a far
wider problem than executable prefixes — remains out of scope *here* and stays tracked
separately (`dev-docs/topics/detection.md`, `dev-docs/threat-model.md` O10). The
**first-block** framing check narrows it from 3.5% of a real `/usr` tree to ~0.15%
(61/39 859 measured); the deferred chain walk would cut further to ~0.035%. It does not
close the residual, and the registered wording needs three clauses, not one: the listing
is wrong, a full read raises, and a prefix of fabricated bytes may already have been
produced.

#### Scenario: no silent wrong answer on executable-shaped prefix

| Case | Expected |
| --- | --- |
| Low-entropy `MZ` stub + RAR/7z/ZIP payload in window | Detected as that archive — **not** `BROTLI` / fabricated member |
| Real Brotli stream with non-executable prefix, `.br` extension | Unchanged — `BROTLI` / `PROBABLE` via content probe |
| Real Brotli stream with non-executable prefix, compressed-first, no corroborating extension | Still `BROTLI` via content probe, at `PROBABLE` |
| Real Brotli stream with non-executable prefix, uncompressed/metadata-first, no corroborating extension | Still `BROTLI` via content probe, at `GUESS` |
| Real Brotli (or other probe format) whose prefix coincides with a **weak** executable cue | Still detected as that stream — **not** forced to `FormatDetectionError` solely because two bytes were `MZ` |
| **Strong** executable cue (validated PE / ELF), no archive needle in the window | No content probe runs; extension guess or `FormatDetectionError` — never a fabricated member |
| Executable-shaped prefix, no archive needle, probe correctly rejects | Extension guess or `FormatDetectionError` — not a fabricated member |

### Requirement: ISO 9660 requires an extended peek window

The system SHALL raise the peek window to 32774 bytes when `.iso` or ISO
detection is attempted (PVD at 32769). A stream shorter than that SHALL rule out
ISO and continue (other magic / extension) — never reject solely for being too
short for ISO. Long enough but no `CD001`@32769 → no ISO match, fall through.
`FormatDetectionError` only when **no** format matches.

#### Scenario: ISO peek matrix

| Case | Expected |
| --- | --- |
| `.iso`, ≥32774 bytes, `CD001`@32769 | ISO, `CERTAIN`, `magic` |
| Stream < 32774 bytes | ISO ruled out; fall through; error only if nothing else matches |
| 2 KiB file with ZIP magic | ZIP (despite short of ISO window) |

### Requirement: Detection never consumes or discards bytes

Bytes inspected during detection MUST remain available to the backend. Wrapping
non-seekable sources is the **opener's** job so one wrapper is shared:

| Source | Behavior |
| --- | --- |
| Path / seekable stream | Peek/read then restore entry `tell()`. Archive begins where the caller positioned. `open_archive` may wrap a mid-file seekable stream in a zero-origin view (`SlicingStream`) so absolute-offset backends (e.g. ISO/`pycdlib`) see origin 0. |
| Non-seekable | The `ArchiveSource` `open_archive` builds holds a replay prefix; detection and backend receive that **same** object. Detection uses `peek(n)` only, and the backend's reads drain the prefix before reaching the source. |

Standalone `detect_format` is non-consuming for paths/seekable streams. For a raw
non-seekable stream the peeked prefix is lost to the caller unless the caller buffers
it; `open_archive` and `open_stream` keep it in the `ArchiveSource`.

The replay prefix: buffers what detection peeks, `DETECTION_LIMIT` bytes by default (32774
when ISO triggered, up to 1 MiB for the inner-TAR probe and chain walks, up to `SFX_MAX`
for the self-extracting scan); `.peek(n)` without consume; reads drain the prefix, then
the underlying source.

Every tier that reads from the front SHALL do so through **one detection-owned prefix
workspace** that grows monotonically: extending the window reads only the delta, and bytes
already in the prefix buffer SHALL NOT be fetched again. The trailer read is outside that
buffer. It seeks to its block and restores the handle, and a later tier that grows the
prefix over those bytes fetches them again. A path keeps one detection handle; a seekable
caller stream records its entry position, reads forward, and restores it in an
exception-safe exit; a non-seekable source uses the same replay buffer the backend will
consume.

#### Scenario: non-consuming matrix

| Case | Expected |
| --- | --- |
| Seekable `BinaryIO` at position N | After detect, position is N again; backend can read full archive |
| `open_archive` on non-seekable | One `ArchiveSource` for detect + backend; peeked bytes replay then fall through |
| Standalone detect on raw non-seekable the caller will reread | Caller must buffer the stream itself |

#### Scenario: the workspace reads each byte once

| Case | Expected |
| --- | --- |
| Near magic then far magic on a seekable stream | 32 774 bytes fetched once, not 4 096 then 32 774 from zero |
| Five tiers peeking the same 30-byte head | One fetch, four buffer reads |
| Cued scan growing 64 KiB → 256 KiB → 1 MiB → 2 MiB | 2 MiB of unique source I/O, not 3.31 MiB of overlapping reads |

### Requirement: Detection's access shape is bounded, not only its byte count

Detection SHALL perform **one forward-only pass** over the prefix from the detection
origin. Bytes already in the prefix buffer SHALL NOT be fetched again. The trailer tier,
when it runs, SHALL add one seek towards the end, one read of its block, and one seek
back to the end of the prefix. Those bytes are not kept, so a later tier that reads
them as part of the prefix fetches them again. No other backward seek re-reads the
prefix. The exit restore of a seekable caller stream is the non-consumption contract.

This holds for every source kind. A network range reader pays for the prefix pass and,
when the trailer runs, one range for that block; a member stream (`ArchiveStream`) is
not asked for the trailer, because a rewind would re-decode, and it decodes the prefix
forward once. That holds whether the member stream reaches detection bare, under a
pass-through buffer, wrapped in the `ArchiveSource` that `open_archive` builds, or as a
volume in a list passed to `open_archive`. A source that is not asked records `trailer`
as *capability unavailable* (detection-cost), unless it is shorter than the 512-byte
block: then there is no block to miss and nothing is recorded. The rule is stated flatly rather than
derived from a cost model because `StreamCapability` cannot distinguish a cheap seek
from an expensive one.

Resolving an exact `payload_offset` through a central-directory walk does not fit this
shape — the directory is reached backwards from the end and points backwards again. Offset
resolution is therefore separable from identification, and no tier does it today.

#### Scenario: access-shape matrix

| Case | Forward reads | Seeks toward end | Backward seeks |
| --- | --- | --- | --- |
| gzip at offset 0, seekable stream | 1 pass | 0 | **0** |
| ISO far magic, seekable stream | 1 pass | 0 | **0** |
| Seekable bzip2 or xz larger than the prefix, no `koly` block | 1 pass, then the rest of the file for the inner-TAR probe, which fetches the trailer bytes again | 1 | 1, back to the end of the prefix |
| `koly` hit on a seekable image larger than the prefix | 1 prefix pass; the trailer bytes are fetched once | 1 | 1, back to the end of the prefix |
| Non-seekable source, any tier | 1 pass | 0 | **0** |
| Member stream (`ArchiveStream`), bare, buffered, through `open_archive`, or one volume of a list, any tier | 1 pass | 0 | **0** |

The backward-seek column does not count the exit restore of a seekable caller stream.

### Requirement: Structural checks receive a candidate-relative view

A needle declaration SHALL carry the offset at which its magic sits **within the candidate**,
and every validator and probe SHALL receive bytes positioned at the candidate origin rather
than at the source origin.

TAR's `ustar` sits at candidate offset 257, so a scan hit at absolute offset `H` denotes a
candidate origin of `H - 257`. A gzip needle begins at candidate offset zero. Without this,
a self-extracting archive's internal structure cannot be validated at all, because the only
available view starts at the source origin.

#### Scenario: candidate-relative reads

| Case | Expected |
| --- | --- |
| `ustar` found at absolute 100 257 | Candidate origin 100 000; the 512-byte header is validated from there |
| gzip needle found at absolute 4 096 | Candidate origin 4 096; the bounded decode reads from there |
| Candidate-relative read of length N at origin O | Same bytes as an absolute read at `O` for `N` — one is a view of the other, never a second fetch |
| Candidate origin computed as negative (`H` < declared needle offset) | Not a candidate; the hit is discarded |

### Requirement: An unconfirmed format choice is reported when the listing is empty

`detected_by="extension"` means every content signal declined: magic, the content
probes, and far magic all failed, and the extension was the only evidence left. That is
the same answer content detection gives when it **refuses** a file — so a format chosen
this way is not confirmed by the bytes, and no second detection pass is needed to know
it.

On its own that is fine and common (an empty `.br` with the Brotli extra missing, a
`.tlz` whose content is unreadable). Combined with a **listing that completes with zero
members**, it is the realistic form of the wrong-format problem: 32 KiB of zeros named
`z.tar` opens as an empty TAR, while `detect_format()` on the same bytes raises
`FormatDetectionError`.

When a listing completes without error and with zero members, the system SHALL therefore
emit `EXTENSION_FORMAT_UNCONFIRMED` if the format came from the extension fallback, and
SHALL NOT emit it otherwise. It SHALL NOT refuse the open: a zero-member archive is legal
and a zero-filled file is byte-identical to an empty one (see `diagnostics`).

The check SHALL cost nothing on a non-empty listing — it is a comparison of the recorded
`FormatInfo`, not a rescan.

#### Scenario: unconfirmed format matrix

| Case | Expected |
| --- | --- |
| 32 KiB of zeros named `z.tar` | Opens as TAR, 0 members, `EXTENSION_FORMAT_UNCONFIRMED` (+ `EMPTY_ARCHIVE`) |
| `detect_format()` on the same bytes with no name | `FormatDetectionError` — unchanged |
| Real one-member tar named `a.tar`, no magic window match | Non-empty listing → no diagnostic |
| A legitimately empty tar (all zeros, hence extension-only) | `EXTENSION_FORMAT_UNCONFIRMED` too — the bytes genuinely did not confirm it, and that is the honest answer, not a false positive |
| Empty archive opened with an explicit `format=` | `EXPLICIT_FORMAT_LISTED_EMPTY` instead — no extension fallback ran |

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
not guessed, and detection behaves as before.

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

### Requirement: A content probe SHALL NOT accept an incomplete stream it can see whole

A content probe decodes a bounded prefix and treats "the decoder wants more input" as a
match, because a real stream usually continues past the prefix. When the probe knows the
source length and that length does not exceed the bytes it was handed, there is no more
input: the probe is holding the entire file. A **complete valid stream that finishes within
a declared output drain terminates**, so a decode that still wants more input after that
bounded drain SHALL be a rejection rather than a match.

This is a **bounded** completeness check, not a full drain of the decoded output: the
implementation SHALL declare an output budget (today: 64 KiB) so a highly-compressible
fully-visible sample cannot expand into an unbounded decode. Streams whose expansion
exceeds that budget without the decoder signalling "needs more input" are not rejected
here. The check MUST NOT be implemented as a minimum source size. A 9-byte
`brotli.compress(b"hello")` finishes within the drain and SHALL still be accepted.

The rule SHALL apply to every probe that decodes, not to Brotli alone: it follows from
bounded decoding rather than from any one format's framing. Measured on 66 361 real files
(at the then-256-byte completeness drain; the drain is now 64 KiB, which only strengthens
the rule), it rejects **91 of 128** fabricated probe claims (71%) — 67 of them under
16 bytes — while costing **zero** genuine streams.

The check SHALL be skipped when the source length is unknown, exactly as the framing gate
is; detection then behaves as before.

A probe SHALL be handed the whole detection window (`DETECTION_LIMIT`, 4 096 bytes), not a
shorter sample of it. Text can decode as a Brotli meta-block for a few hundred bytes and
turn invalid only further in: with a 256-byte sample, 7 of the first 800 Perl modules under
`/usr/share/perl` detected as Brotli; with the whole window, none did.

When a probe accepts the window and the source is longer than the window but no longer
than the budget's `completion_window_bytes` (64 KiB under `BALANCED`), detection SHALL
peek the whole source and run the probe again on it, so the completeness check above
applies to it too. A source larger than that window, a budget with no completion window
(`FAST`), or a source of unknown length keeps the window's answer. The whole-source decode
is charged to the detection decode allowance; when the allowance cannot cover it, the
window's answer stands and `probe_completion` is recorded as *budget exhausted*.

#### Scenario: completeness matrix

| Case | Expected |
| --- | --- |
| 9-byte real Brotli stream, whole file in the prefix, decodes to completion | Accepted |
| 5-byte text file whose first meta-block parses as compressed, decode wants more input within the output drain | **Rejected** — the file is fully visible and does not terminate |
| Truncated high-ratio zlib (fully visible; expands past the old 256-byte probe read, within ~64 KiB) | **Rejected** within the declared output drain |
| Truncated high-ratio zlib whose expansion exceeds the output drain before signalling truncation | Not rejected here — bounded check cannot disprove |
| Real Brotli file larger than the prefix, decode wants more input | Accepted — there genuinely is more input |
| Real Brotli file exactly the size of the prefix, decodes to completion | Accepted |
| Source length unknown (non-seekable stream longer than the peek) | Rule skipped; today's behaviour |
| LZMA Alone: 51-byte low-entropy file, fully visible, does not terminate | **Rejected** — same rule, not a Brotli special case |
| Source larger than the prefix, within the completion window, stream truncated past the window | **Rejected** — the whole source is peeked and the probe re-run on it |
| Same source under `FAST` (no completion window) | Accepted on the window |
| Source larger than the completion window | Rule does not apply; other rules decide |
| Text whose first 256 bytes decode as a Brotli meta-block (Perl module opening) | **Rejected** — the probe decodes the whole 4 KiB window |

### Requirement: A content probe SHALL follow a format's self-describing block chain

**Scope: formats whose blocks are byte-aligned and self-describing, so a successor's offset
is known without decompressing. Brotli is the only such format today.** For those, a probe
SHALL follow the chain to test the same framing invariant beyond the first block, and SHALL
reject a link that overruns the source or a declared end that leaves trailing bytes. A
format outside that scope is unaffected — this is not an obligation on every probe.

The walk is mandatory rather than optional because the alternative is a probe whose
false-positive rate silently depends on whether an implementer felt like walking. What is
*bounded* is the work, not the obligation: the budgets below are the escape hatch, and
exhausting either is a defined outcome rather than a licence to skip the walk.

The walk exists because the first-block check goes **vacuous on large sources**: Brotli's
MLEN field tops out at 2²⁴, so past ~16 MiB every declared length fits trivially. Measured
on random blobs, the walk takes 16 MiB acceptance from 8.33% (where the first-block check
buys nothing) to 2.00%, and a `/usr` tree from 61 survivors to 14.

The walk SHALL be **bounded by a declared link count** (today: 8) and, on forward-only
sources, by a **declared maximum absolute offset** for probe reads (today: 1 MiB). Reaching
either means *cannot disprove*: the probe SHALL keep the verdict the earlier rules reached
and MUST NOT reject on that basis. This is the same discipline as an unknown source length
— absence of evidence is not evidence against, so budget exhaustion can never manufacture a
false negative. The 1 MiB figure is the memory-governing ceiling for a non-seekable
`read_at` (buffering `[0, offset)`); seekable sources and paths may seek past it.

The walk stops at the first compressed block, which carries no declared length to check.
On a real Brotli file whose first meta-block is compressed — 79 of 150 in the corpus — it
therefore terminates immediately, having read four bytes.

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
stay inside the reach of the walk's reads (`end` at most 1 MiB, the non-seekable
`read_at` ceiling, applied to every source) and inside the detection budget: it is
charged to `max_decode_input` and SHALL NOT read past the budget's prefix/far/scan
ceiling (see `detection-cost`). When `end` is out of reach, the budget cannot cover it,
or the read is declined, the walk's verdict stands (*cannot disprove*). A real stream
decodes cleanly or runs out of input there, and both SHALL be accepted.

#### Scenario: chain walk matrix

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
| OLE/CFB file ≥ 7425 bytes | Its constant magic yields a fitting chain that stops at a compressed header at 7 426; the decode there rejects it. Detection does not run the probe on it in any case (*A known non-archive signature stops the content probes*) |

### Requirement: A read failure on probe-only evidence names its provenance

When a single-file result's format came from a content probe with **no corroborating
evidence** (matching extension or inner-TAR upgrade) — at any `DetectionConfidence` — a
decode failure while reading the fabricated single member SHALL report that the format
identification was unconfirmed, rather than presenting as a plain truncation of a file
whose format is settled. See `error-handling` for the attribute, message, and diagnostic
contract.

The system SHALL NOT refuse the open on this basis — a genuine extensionless stream that
the probe correctly identified must still be readable, and a probe-only result that reads
cleanly is a success.

#### Scenario: unconfirmed-format read failure

| Case | Expected |
| --- | --- |
| Probe-only result at any confidence, read fails | Same exception type; `format_unconfirmed=True`; message names unconfirmed identification; `PROBE_FORMAT_UNCONFIRMED` diagnostic |
| Probe + `.br` extension, read fails | Ordinary truncation/corruption error — the format is corroborated; `format_unconfirmed=False` |
| Probe + `.tar.br` extension reported as bare `BROTLI`, read fails | Corroborated — the deferred inner-TAR case is agreement, not conflict; `format_unconfirmed=False` |
| Probe + an extension that **disagrees** (`.zip` over Brotli bytes), read fails | Not corroborated; `format_unconfirmed=True`, and a `FORMAT_EXTENSION_CONFLICT` is raised |
| Probe hit upgraded to `TAR_*` via inner-TAR, read fails | Corroborated; `format_unconfirmed=False` |
| Probe-only result, read succeeds | Success; no error, no downgrade |

### Requirement: An inner-TAR upgrade corroborates a content-probe identification

When a content-probe hit is upgraded to a `TAR_*` format because a TAR header was found in
the decompressed prefix (`_resolve_single_file_or_tar`), that upgrade SHALL count as
corroborating evidence for the underlying codec identification, equivalent to a matching
file extension.

The upgrade is not a second guess about the same bytes: reaching it required the probe's
decompression to actually produce output, and that output to contain a `ustar` signature
at the offset TAR specifies. Two independent things had to hold. A result reached that way
SHALL therefore report `PROBABLE` rather than `GUESS`, and SHALL NOT be stamped
`format_unconfirmed` on a later decode failure (see `error-handling`).

The population is small — a `.tar.br` with no filename to go on — but the alternative is
treating a stream that decompressed successfully into a recognisable TAR as no better
evidenced than four bytes that happened to parse as a block header.

#### Scenario: inner-TAR corroboration matrix

| Case | Expected |
| --- | --- |
| Extensionless stream, Brotli probe hits, decompressed prefix contains a TAR header | `TAR_BROTLI`, `PROBABLE`, `content_probe` — corroborated |
| Same, and a later read fails | Ordinary error; `format_unconfirmed is False` |
| Extensionless stream, Brotli probe hits, no TAR header in the decompressed prefix | Unchanged — the probe-only rules decide |
| `x.tar.br` (extension already corroborates) | Unchanged |

### Requirement: Detection confidence SHALL NOT be the trigger for error provenance

`DetectionConfidence` grades how strong the evidence for a format was.  Whether a caller
is told the identification may have been wrong is a **different** question — whether
anything corroborated a probe. The system SHALL keep these separate: no error-reporting
behaviour SHALL key on a `DetectionConfidence` value.

This exists because conflating them produced a measured blind spot and then bent a
detection decision around it. `format_unconfirmed` originally fired on
`detected_by == "content_probe" and confidence is GUESS`, which left 68 of 128 real-world
fabricated probe claims unsignalled: LZMA Alone reports `PROBABLE` unconditionally, and
Brotli's compressed-first class was moved to `PROBABLE` *in order to* route it away from
the flag. A confidence value chosen to steer exception behaviour is no longer reporting
confidence.

Detection MAY still grade probe-only hits by class where it has measured grounds to — the
compressed-first split stands on its own evidence — but the grade SHALL be a claim about
evidence strength only, with no error-reporting consequence attached.

#### Scenario: separation matrix

| Case | Expected |
| --- | --- |
| Probe-only hit at `PROBABLE`, read fails | Stamped — the stamp asks about corroboration, not confidence |
| Probe-only hit at `GUESS`, read fails | Stamped — same reason |
| Corroborated hit at `PROBABLE`, read fails | Not stamped |
| A future retune of Brotli's confidence split | Changes reported confidence only; no error behaviour moves |

### Requirement: Refuse a UDIF disk image by name

The system SHALL report a UDIF image as `ArchiveFormat.DMG` / `CERTAIN` / `magic`, and
`open_archive` SHALL raise `UnsupportedFeatureError` naming UDIF, when the `koly` block
is at offset 0, or at the start of the last 512 bytes and no earlier step matched.
Far magic runs first, so an uncompressed image whose disk is an ISO 9660 filesystem
(`CD001` at 32 769) SHALL be reported as `ISO` and read as one; the trailer is not
consulted. `format_availability(DMG)` SHALL be `NONE` with an empty `missing`: known,
not supported, nothing to install. The `.dmg` suffix SHALL NOT select the format.

#### Scenario: UDIF matrix

| Case | Expected |
| --- | --- |
| Seekable image, zlib, bzip2 or xz first block, `koly` trailer | `DMG` / `CERTAIN` / `magic`; `open_archive` raises `UnsupportedFeatureError` naming UDIF |
| `koly` block at offset 0 | `DMG` / `CERTAIN` / `magic`; the same refusal |
| `CD001` at 32 769 and a `koly` trailer, no `koly` at offset 0 | `ISO` / `CERTAIN` / `magic`; the image is read as an ISO |
| Real zlib, bzip2 or xz stream, no `koly` block | Unchanged |
| Version other than 4 | Not `DMG` |
| ZIP whose name ends in `.dmg` | `ZIP` |
| `format=ZLIB` on a zlib-first image | The first block is read; detection does not run |
| `format=DMG` or `format="dmg"` | `UnsupportedFeatureError` naming UDIF |
| Non-seekable source longer than the far-magic window, zlib first block, `koly` at the end | `ZLIB`; the trailer is not seeked to |
| `format_availability(DMG)` | `NONE`, `missing` empty; in `list_known_formats()`, absent from `list_supported_formats()` |

### Requirement: A known non-archive signature stops the content probes

When the source starts with a recognized **non-archive signature**, detection SHALL NOT run
the content probes or the SFX scan, whatever executable cue the bytes raise, and SHALL fall
through to the extension guess. The magic tiers run as before. With no extension, the
`FormatDetectionError` SHALL name the evidence that stopped the probes, as it SHALL after
a strong executable cue. Today the one signature is OLE / Compound File Binary,
`D0 CF 11 E0 A1 B1 1A E1` at offset 0.

#### Scenario: non-archive signature

Both the Brotli and the LZMA Alone probe accept an OLE header followed by zeros (`.doc`,
`.xls`, `.ppt`, `.msi`, `Thumbs.db`), and neither can reject it on its own framing: the
header is a fitting Brotli chain, and a range coder decodes zero bytes without error.
This is not the threshold that *Executable-looking prefixes must not silently become a
wrong stream format* forbids: it is positive evidence of another format, and an
eight-byte signature at offset 0 is as specific as an archive's exact magic. A two-byte
prefix such as `MZ` is not specific enough. The SFX scan is skipped because these files
are not stubs: an archive stored inside one is part of the document, not its payload.

The cases are pinned in `tests/test_audit_backup_scan.py`: an OLE header over zeros is
`FormatDetectionError` naming the OLE signature, not `BROTLI` or `LZMA_ALONE`; an OLE file
named `x.br` is `BROTLI` / `GUESS` / `extension`; a ZIP inside an OLE file is not
reported; and a signature whose bytes raise an executable cue does not start the SFX
scan. The measurement is in `dev-docs/investigations/2026-10-backup-scan.md` §3.2.
