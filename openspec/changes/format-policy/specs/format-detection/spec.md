# format-detection — format policy delta

## MODIFIED Requirements

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
6. **Content probes** — formats with no exact magic. Match → `detected_by="content_probe"`.
   Unless `ArchiveyConfig.always_probe_content` is set, only the probe of a stream format
   the source's extension names SHALL run (see *Magic-less formats are detected by a
   content probe*); `open_stream` SHALL run every probe.
7. **Extension** — `Path` with a known extension → `GUESS` / `detected_by="extension"`.
8. `FormatDetectionError` when nothing matched. When step 6 ran only the probes the
   extension allows, the message SHALL name the three ways to read a nameless
   probe-only stream: `format=`, `open_stream()` and `always_probe_content=True`. When
   the policy left a plugin out at any step, the message SHALL also name the policy
   and the plugin formats it turned off, since none of the three reaches a plugin that
   is off.

A plugin format that `ArchiveyConfig.formats` does not allow SHALL NOT be a candidate
at any step: its magic SHALL NOT match at steps 2 and 4, its probe SHALL NOT run at step
6, and its extensions SHALL NOT match at step 7, so that an off plugin neither runs code
nor claims a file an allowed plugin matches. Each step that leaves one out SHALL be
recorded in `unavailable_tiers` with `NOT_ENABLED_BY_POLICY`. Built-in formats SHALL be
candidates under every policy.

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
| Real Brotli stream larger than the window, no extension, `always_probe_content=True` | One bounded peek misses at step 4, then step 6 detects it |

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
source is a compressed stream, so a probe only picks the codec. Both rules stop at the
caller's format policy: the probe of a plugin format that `ArchiveyConfig.formats` does
not allow SHALL NOT run, under `always_probe_content=True` and in `open_stream` alike,
and the skip SHALL be recorded in `unavailable_tiers` as `content_probe` /
`NOT_ENABLED_BY_POLICY` (the off plugin's magic and extensions are left out too; see
*Magic-first detection*). Built-in probes are not affected by the policy.
The internal detections `open_archive` runs under `format=` (stub check, empty-listing
rescan) SHALL follow the caller's `always_probe_content`. This covers Brotli (no
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

#### Scenario: A plugin that is off runs no code, even when every probe is asked for

- **WHEN** a plugin with a content probe is registered and a caller runs
  `detect_format` with `ArchiveyConfig(always_probe_content=True,
  formats=FormatPolicy(plugins=False))` on a file only that probe recognises
- **THEN** the plugin's probe is not called
- **AND** `unavailable_tiers` records `content_probe` as `NOT_ENABLED_BY_POLICY`
- **AND** the `FormatDetectionError` message names the format policy

#### Scenario: A plugin that is off does not shadow an allowed one

- **WHEN** plugins `A` and `B` are registered in that order, both with magic that
  matches a file, and a caller opens the file with
  `FormatPolicy(exclude={A.format.container})`
- **THEN** detection reports `B`'s format and `B` reads the file
- **AND** `unavailable_tiers` records `near_magic` as `NOT_ENABLED_BY_POLICY`
