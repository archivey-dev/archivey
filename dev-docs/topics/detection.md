# Format detection

How `detect_format()` decides what a source is, and why it decides that way. `open_archive`
and `open_stream` run the same detection when the caller passes no `format=`, under the
same budget, so everything here applies to them too.

Three other pages own parts of this, and this page links them rather than repeating them:

- [`prefixed-archives.md`](prefixed-archives.md) owns the SFX scan: the cue, the window,
  the hit validators, and the tail probe that is not shipped.
- [`formats/single-file.md`](../formats/single-file.md) §2.1 owns the codec side of
  content probing: what each probe checks, its lifted memory limits, and the inner-TAR
  probe's per-codec detail. [`formats/brotli.md`](../formats/brotli.md) owns the Brotli
  probe, which is the one with a false-positive history.
- Each format page's §2.1 owns that format's magic and what the magic cannot tell.

## At a glance

- **Seven steps, strongest evidence first, and the first match wins.** Near magic → SFX
  scan → far magic → trailer magic → self-checking header → content probes → extension. The whole order is one
  function, `_detect_format_body` in `internal/detection.py`.
- **Detection reads the front of the source, and one fixed block at the end.** The block
  is the last 512 bytes, and only to look for a UDIF `koly` signature on a cheap seek
  (§2.4). No ZIP tail probe is shipped, and the budget has no field for one. An archive
  that is found only from its end, such as a ZIP appended to a JPEG, is not detected.
  `format=ZIP` still opens it.
- **Detection never consumes bytes the backend needs.** A path gets its own handle. A
  seekable stream is put back where the caller left it. A non-seekable stream is peeked
  through the replay prefix that the backend then reads first. A raw pipe handed straight
  to `detect_format` is the exception (§4.3).
- **Every read and decode is bounded**, almost entirely by
  `ArchiveyConfig.detection_budget` (`BALANCED` by default). The probes' positioned reads
  also have a fixed cap of their own (§4.1). The result carries a receipt of what was spent and a list of the steps that did
  not run, with the reason for each.
- **A filename never overrules the bytes.** When they disagree, the bytes win and
  `FORMAT_EXTENSION_CONFLICT` is emitted.
- **A content probe runs only for a name that claims its format**, unless
  `ArchiveyConfig.always_probe_content` is set or the caller is `open_stream` (§2.6). A
  nameless raw LZMA Alone, zlib or Brotli source is refused by default.
- **`confidence` is provisional and `detected_by` is an open set** (`docs/formats.md`
  §Detection). No behaviour in the library branches on `confidence`.
- **What you might expect and will not find:**
  - A graded evidence record: `FormatInfo` has one confidence and one `detected_by`, not a
    list of candidates.
  - An error on a polyglot: a file that is two formats gets one deterministic answer (§3.1).
  - More formats found under `THOROUGH`. It reads the same window as `BALANCED`, and the
    same 512-byte `koly` block. What changes in behaviour is only how large a source a
    probe hit is re-checked against (§4.1).
  - Any check that a magic hit is more than its bytes: two bytes `1f 8b` are `GZ` /
    `CERTAIN`, and the open fails.

## 1. Shape

Four facts about the problem produce most of the design.

**Evidence comes in strengths, and the strongest kinds are also the cheapest.** An exact
magic at the offset the format specifies costs a 4 KiB read and is rarely wrong. A magic
found by searching a window is weaker, because the search can land on the same bytes inside
something else, and it costs up to 2 MiB. A content probe is a decoder asked "does this
decode?", and a decoder given arbitrary bytes sometimes says yes. A filename is only what
someone called the file. So the steps run in a fixed order from strongest to weakest, and
each weak step sees only what the stronger ones declined. A fixed order is also easy to
read. The tie rule (§3.1) falls out of it, and it answers every source in at most one pass.

**Some formats have no magic worth trusting.** Brotli has none. zlib has a two-byte header
that matches too much text, and LZMA Alone has a properties byte and a dictionary size.
These three are found only by probes, so the probe step exists and gets the most guards
(§2.6). They are also why the far-magic step runs before the probes and not after (§2.3).

**Detection runs before a reader exists, on any source.** The source can be a path, a
seekable stream in the middle of a file, or a pipe that can be read once. So detection must
not consume what the backend needs, must work forward-only on a pipe, and must bound its
own work, because no reader limit applies yet. That gives the prefix workspace (§4.2),
the budget (§4.1), and one forward pass over the prefix. The seek toward the end is the
512-byte UDIF block, and only on a cheap seek (§2.4).

**Filenames are wrong often enough to matter.** A `.tar.gz` that is really a ZIP, a `.cbr`
that is a ZIP, and a `.tlz` that holds LZMA Alone instead of lzip are all common. So the
extension is the last step, and it is used only when every content signal declined.

## 2. The steps

| Step | Evidence | `confidence` | `detected_by` | Bound under `BALANCED` |
| --- | --- | --- | --- | --- |
| 1. Near magic | Exact magic inside the first 4 KiB (`DETECTION_LIMIT`) | `CERTAIN` | `magic` | 4 KiB read |
| 2. SFX scan | Leading bytes look like a prefix; a validated archive needle behind it | `PROBABLE` | `sfx_scan` | `min(size, 2 MiB)` read |
| 3. Far magic | Exact magic past 4 KiB (ISO `CD001` at 32 769) | `CERTAIN` | `magic` | 32 774 bytes, once |
| 4. Trailer magic | Exact magic at the start of a fixed block at EOF (UDIF `koly`, 512 bytes) | `CERTAIN` | `magic` | 512 bytes, on a cheap seek |
| 5. Self-checking header | A first block that proves its format with no magic (a v7 TAR header's checksum) | `PROBABLE` | `content_probe` | nothing more read |
| 6. Content probes | LZMA Alone, zlib, Brotli decoders accept the bytes; by default only the probe the extension names runs | `PROBABLE`, or `GUESS` for weak Brotli | `content_probe` | 1 MiB of decode input for the call |
| 7. Extension | Longest matching suffix in the aggregated map | `GUESS` | `extension` | nothing read |

A near-magic or content-probe match on a single-file compressor is then offered to the
**inner-TAR probe**, which decodes up to 512 bytes and looks for `ustar` at offset 257, or
a first header that passes the TAR header check (§2.5). A hit reports the TAR combination
(`TAR_GZ`, and so on) as `PROBABLE` / `content_probe`. It reads at most 1 MiB of
compressed input and draws on the same decode allowance as the content probes (§4.1). A
trailer hit is not a compressor, so it is not offered.

The tables that drive steps 1, 2, 4, 5 and 6 come from the backends and the codec
descriptors as data: `MAGIC`, `TRAILER`, `EXTENSIONS`, `SFX_MAGIC`, `SFX_HIT_VALIDATOR`,
`HEADER_CHECKS` and `CONTENT_PROBES`, aggregated by `internal/registry.py`. The detector has no per-format
code. A new format becomes detectable when its backend registers, and the detector cannot
disagree with the backend about what the format's magic is.

### 2.1 Near magic

The first 4 KiB is compared against every signature that ends inside it. TAR's `ustar` at
257 is in this set, so a plain tar is `CERTAIN`. zstd has a structural walk as well: it steps
over skippable frames by their declared sizes, but only inside the bytes already peeked, and
matches the regular frame behind them. A walk never triggers a larger read, so a skippable
frame bigger than the window is a decline, not a new read.

A near match is final, with one exception. A bzip2 or xz header can be the first block of
a UDIF image, and the trailer step outranks those two hits (§2.4). Everything else the
later steps could offer is weaker evidence than an exact magic at its specified offset.

The weak point is length: some magics are two bytes (gzip `1f 8b`, unix-compress `1f 9d`).
Two bytes at offset 0 are reported `CERTAIN`, and a file that is only those two bytes fails
at open with `TruncatedError`. §5 lists it.

### 2.2 The SFX scan

This step runs only when the first bytes carry a cue (`MZ`, ELF, a Mach-O header that
parses, or `#!`). It searches up to 2 MiB for a ZIP, 7z or RAR needle, and a hit counts
only once that format's validator passes it. The validator judges the candidate's whole
header, which may run past the window end (§4.1). RAR and 7z may each have 256 candidates
rejected, the cap their parsers' own scans stop at. Past that, the scan stops searching for
that format's needles, so its later candidates are not judged, and it records `sfx_scan` as
*budget exhausted* even when it answers. ZIP has no cap: the ZIP reader finds the end of
central directory from the tail and runs no scan, so a cap would refuse a file that
`format=ZIP` opens. A window carpeted with ZIP decoys therefore pays one validation per
decoy ([`prefixed-archives.md`](prefixed-archives.md) §7). The cue decides only whether to
spend the window. The validator decides whether a hit is real. A structurally confirmed
executable (a `STRONG` cue) with no hit also turns off the content probes. Without that, a
probe could claim the stub as a compressed stream and `open_archive` would return a
fabricated `installer.uncompressed` member. A known non-archive signature (§2.6) does not
start the scan, whatever cue its bytes raise. All of this is on
[`prefixed-archives.md`](prefixed-archives.md) §2 to §5.

One cost rule settled here belongs on this page because it is a budget question. **A 7z hit
whose declared end falls short of the end of the source is kept only as a fallback, and the
scan goes on reading to the end of the window** for a later 7z that does end there. The
scan cannot stop at the short hit's own end: a decoy inside the stub ends before the real
payload starts, so that bound would open the decoy. A 7z SFX with data after the archive
(an Authenticode signature, for example) therefore reads the whole window to detect, the
same as a miss. The cost stays inside `max_scan_bytes` plus the validator allowance of
§4.1. A tighter bound for PE stubs, the end of the stub's last section, is in
[`IDEAS.md`](../IDEAS.md).

### 2.3 Far magic

ISO 9660's `CD001` sits at 32 769, outside the 4 KiB window. The step peeks the extended
window once, through the same workspace, so the first 4 KiB is not read twice. A source
whose known size is smaller than the window never pays for the peek.

It runs **before** the content probes because a bootable or hybrid ISO keeps boot code in
its first 32 KiB, and boot code is the kind of data a probe accepts. If the probes ran first,
such an image would open as a single fabricated member, although an exact magic was at a
known offset the whole time.

A consequence worth knowing: a source that matches nothing in the first 4 KiB and is at
least 32 774 bytes long pays the far peek, whatever it turns out to be. A 40 000-byte file of
zeros named `backup.gz` reads 32 774 bytes before the extension guess.

### 2.4 Trailer magic

UDIF (a `.dmg`) keeps a 512-byte `koly` block at the end of the file, or at offset 0 on
an old image. The block starts with `koly`, version 4, and a header size of 512, all
big-endian: the same 12 bytes 7-Zip checks. Offset 0 is ordinary near magic. The block
at the end is this step.

It runs after far magic, so an ISO that already matched is not asked for a tail read.
An uncompressed image of an ISO 9660 disk is that case: `CD001` at 32 769 wins, and
the file is read as an ISO. It runs before the content probes, so a zlib-first image
is named as the image. What a compressed block contains, and why that is not a
signature detection can use, is on [`formats/dmg.md`](../formats/dmg.md) §1. The read is
one seek to the last 512 bytes on a path or a plain seekable stream, then a seek back to
the end of the prefix. A pipe and an `ArchiveStream` are not seeked to the end. When
the source is 512 bytes or more, the receipt records `trailer` as
`CAPABILITY_UNAVAILABLE`; a shorter source records nothing, as it has no block to
miss. When the length is unknown the
far-magic step has already read its window, so an image that fits in that window is
refused: the block is in the prefix. A longer zlib-first image still opens as zlib. A
source shorter than 512 bytes skips the read too.

A hit is `DMG` / `CERTAIN` / `magic`. Nothing reads the image. `open_archive` raises
`UnsupportedFeatureError` naming UDIF. `format_availability` reports `NONE` with an
empty `missing`: there is nothing to install. The `.dmg` suffix is not registered, so a
zip with that name stays a zip.

The step is not a ZIP tail probe. It looks at one fixed block for one signature, and a
ZIP appended to a JPEG is still not found (§5).

### 2.5 Self-checking headers

Some formats have no magic, but their first block checks itself. Today that is TAR without
`ustar`: a v7 tar (`tar --format=v7`), and the old bsdtar and star outputs that leave the
magic out. The backend declares the check as data (`HEADER_CHECKS`, aggregated as
`registry.header_checks()`), and TAR's is `tar_parser.starts_with_header`. Its first
512 bytes must parse as the walker parses a header: the checksum field parses as a number
equal to the unsigned or signed sum of the block, with the field itself counted as eight
spaces, every numeric field is octal or base-256, and the name is non-empty. A zero block
is not a header.

A hit is `PROBABLE` / `content_probe`, and it is its own corroboration (DR-7): a later
read failure is not stamped `format_unconfirmed`, as a probe-only choice would be. With
`max_prefix_bytes` under 512 the step cannot see a whole block, and `unavailable_tiers`
records `header_check` (§4.1). It runs on every source, named or not, unlike the
probes (§2.6):
- **The check is not a decoder.** It is arithmetic over the window already peeked, so it
  reads and decodes nothing.
- **Arbitrary bytes do not pass it.** The checksum must equal the block's byte sum, and
  the numeric fields must parse too.
  - A scan of 200 333 files on a development machine found 207 that pass. All 207 were
    real tars: 205 with `ustar`, and two v7 test files in Go's standard library.
  - The step comes after the trailer and ahead of the probes, so a v7 tar that a probe
    would also accept is named TAR.

It is what `tarfile.is_tarfile` and Commons Compress's detector check, and GNU tar reads
any input as a tar. The case for it came from a 2026-10-28 run of archivey over Apache
Commons Compress's test files: 6 of their 86 `.tar` files have no magic. Two of those
came from users' bug reports, one a pub.dev package. A `.tar` name had been the only way
to open them.

The inner-TAR probe accepts the same check, so a gzipped v7 tar is `TAR_GZ`.

### 2.6 Content probes

**Which probes run.** By default only the probe of a stream format the source's extension
names: `.lzma`, `.zz`, `.zlib`, `.br`, `.brotli`, their `.tar.` forms, and LZMA Alone for
`.tlz`, which lzma-utils used before lzip took the name. A plugin format's probe is keyed
by the format rather than its stream, because every plugin format shares `UNCOMPRESSED`
with ZIP, TAR and the rest: it runs only when the extension names that plugin format. A
source with no name or another extension runs no probe. Whenever the name leaves a probe
out, even if another one runs, the step is recorded as `content_probe` /
`NOT_ENABLED_BY_POLICY`. `ArchiveyConfig.always_probe_content=True` runs every probe, and
`open_stream` always does, because its caller already says the source is a compressed
stream; there a probe only picks the codec. The reason is evidence, not cost: on a
nameless source a probe is the only evidence, and real files pass it. A scan of a backup
drive
([`investigations/2026-10-backup-scan.md`](../investigations/2026-10-backup-scan.md))
found about 27 300 of its 57 390 "archives" through the probes: 26 681 git loose objects,
435 non-Brotli files claimed as Brotli and 51 non-LZMA files claimed as LZMA Alone. A raw
stream with no name is rare as a file and common as `open_stream` input. With a matching
name the probe can only confirm the name, so it adds no false claim, and its hit still
gets the inner-TAR check that an extension guess does not.

When probes run, they run in registry order (LZMA Alone, zlib, Brotli), and the first to accept wins.
Five guards keep a probe from claiming bytes that are not its format. The codec side of each
guard is on [`formats/single-file.md`](../formats/single-file.md) §2.1.

- **The probe decodes the whole 4 KiB window.** A shorter sample lets ordinary text pass:
  with a 256-byte sample, 7 of the first 800 Perl modules under `/usr/share/perl` decoded as
  a Brotli meta-block. With the whole window, none did.
- **A hit on a small source is re-checked against all of it.** When the source is longer
  than the window but no larger than `completion_window_bytes` (64 KiB under `BALANCED`),
  the whole source is peeked and the probe runs again. Its completeness check then rejects a
  decode that still asks for input at the end of the source. The window alone cannot tell a
  stream that goes on from one that turns invalid after 4 KiB.
- **A `STRONG` executable cue turns the step off** (§2.2).
- **A known non-archive signature turns the step off.** Today that is the OLE compound file
  signature `D0 CF 11 E0 A1 B1 1A E1` (`.doc`, `.xls`, `.ppt`, `.msi`, `Thumbs.db`). These
  files are a constant header followed by zero runs, which the Brotli and LZMA Alone probes
  both accept. A scan of a backup drive found 437 files claimed as Brotli, all but two of
  which failed to decode. OLE files were among them, but they were not counted separately,
  and the scan did not record what the two that decoded were. Brotli's own framing cannot
  reject these files, and the spec forbids a threshold there; the LZMA Alone probe now
  refuses a zero run after its header, so for it the signature is defence in depth. An
  eight-byte signature is as
  specific as archive magic. The signature also turns off the SFX scan (§2.2): an OLE file
  is not a stub, and a ZIP stored inside a document is not the document's payload. With no
  extension, the error names the signature, as it names a `STRONG` cue.
- **Framing that the source cannot hold is rejected** when the source length is known.
  This check is the Brotli probe's own, on [`formats/brotli.md`](../formats/brotli.md).

The guards reduce false claims. They do not remove them: some structured binary files
(COFF objects) still pass a probe. What bounds
the damage is provenance. A probe hit with nothing to corroborate it is stamped, and when
a read fails, the error has
`format_unconfirmed=True` and emits `PROBE_FORMAT_UNCONFIRMED`. The open is not refused on
that basis, because a real extensionless stream that the probe identified correctly must
still be readable. Status is in threat-model O10.

**Corroboration** is either a matching extension or an inner-TAR upgrade. The upgrade
counts because reaching it took two independent things: the decode produced output, and
the output had `ustar` where TAR puts it.

### 2.7 Extension

When every content step declined, the longest matching suffix decides (`.tar.gz` beats
`.gz`), as `GUESS` / `extension`. That is the same situation in which content detection
refuses a file, so the bytes did not confirm the choice. Two things follow from that:

- A read that fails on an extension-only format sets `format_unconfirmed=True`, names the
  extension in its message, and emits `EXTENSION_FORMAT_UNCONFIRMED`. Without the stamp, a
  zero-filled `backup.gz` would fail as an ordinary corrupt gzip, which tells the caller the
  wrong thing about the file.
- A listing that completes with zero members also emits `EXTENSION_FORMAT_UNCONFIRMED`. 32
  KiB of zeros named `z.tar` opens as an empty TAR, and without that diagnostic nothing
  would say that the bytes never confirmed it. The open is not refused, because an empty tar
  is byte-for-byte the same file.

When no step matches, `FormatDetectionError` says so. A source with no bytes left at its
current position gets a different message, saying it is empty or already at its end. The
general message would tell the caller that some magic byte was wrong.

### 2.8 Special sources

- **A directory** is `DIRECTORY` / `CERTAIN` / `directory`, decided without reading
  anything, with the zero receipt. `detect_format` and `open_archive` give the same answer
  from `directory_format_info()`, so the two cannot disagree about a directory.
- **A stub-only `.exe` or `.sfx`** (no archive inside) next to a 7-Zip split first volume
  is detected as that volume. `detect_format` follows the stub by default
  (`follow_stub_volumes=True`), so `detect_format("vol.exe")` agrees with `open_archive`.
  `open_archive` probes with the flag off and then replaces the source itself, because it
  must hand the backend the volume's bytes and not the stub's. The receipt covers both
  passes (§4.1).
- **A path to a volume of a set** goes through `resolve_source` first, as in
  `open_archive`. Any part of a numbered split set (`set.zip.002`) is detected on the
  joined parts, and a RAR continuation on volume 1. A middle part has no magic at offset
  0, so detecting that one file alone refused a path that `open_archive` opens.
  Resolution runs before detection reads a byte, and raises what `open_archive` raises
  for the same path: `TruncatedError` for a numbered set with a gap. A lone first part
  is detected as the format its bytes show, where `open_archive` refuses it as an
  incomplete set.

## 3. What the answer claims

### 3.1 Ties

**The earlier step wins; within a step, the earlier backend in registry order wins.** A
polyglot, one file that is valid as two formats, gets one deterministic answer. A caller who
wants the other reading passes `format=`. This is the documented rule, not an accident of
iteration (`docs/formats.md` §Detection).

A tie error (`AmbiguousFormatError`) would make a file that opens today fail, and the case
it serves is rare: a sweep of 33 947 real files found no file that two probes accepted, and
the only example of it (an executable holding both an end-anchored ZIP and a CRC-valid 7z)
is a hand-built file. `format=` already lets a caller choose.

### 3.2 `confidence`, `detected_by` and `corroborated`

- **`confidence` grades the evidence and does nothing else.** No error behaviour keys on
  it. `format_unconfirmed` asks whether anything corroborated the choice, which is a
  different question. When the two are tied together, a confidence value gets chosen to
  steer an exception and stops reporting confidence. LZMA Alone reports `PROBABLE`
  unconditionally, so a stamp keyed on `GUESS` would miss every fabricated LZMA Alone
  claim.
- **`confidence` is provisional in 0.2.x.** The grades are coarse: two bytes of gzip magic
  are `CERTAIN`. Calling the grade provisional lets a later release grade more finely
  without breaking a caller, which is why callers are told to branch on `format`.
- **`detected_by` is an open set.** A later step may add a value, so code that matches on
  it must handle an unknown one. `sfx_scan` covers every archive found behind a prefix,
  including a `#!` launcher, not only an executable stub.
- **`corroborated` is informational and provisional.** Its `False` means both "not
  corroborated" and "not a probe hit at all", so read it only together with
  `detected_by == "content_probe"`.

### 3.3 Conflicts

When the bytes and the extension disagree, the bytes win and `FORMAT_EXTENSION_CONFLICT`
is emitted, naming the evidence that won (magic, the stub scan, or content inspection). The
diagnostic lands on `FormatInfo.diagnostics`, or on the reader's collector when
`open_archive` detected. `STRICT` does not raise on it (the name lies outside the
archive, and the archive reads in full); a caller whose policy does, such as `PEDANTIC`,
gets `DiagnosticRaisedError` before any reader exists. A TAR-combination extension over a bare compressor (`foo.tar.gz`
reported as `GZ` because no `ustar` was found) is agreement, not a conflict, and is silent.

An explicit `format=` skips detection, so it never produces a conflict. The detection
inside `format=` stub checks and inside the empty-listing rescan runs under
`probe_config(config)`: the library default config with the caller's budget. Those
detections are internal, so their diagnostics must not reach the caller's `on_diagnostic`,
and a `STRICT` policy must not raise inside them.

## 4. Cost and source kinds

### 4.1 The budget

`DetectionBudget` (`archivey.detection_cost`) bounds each kind of work, and three presets
name common settings:

| Field | `BALANCED` (default) | `FAST` | `THOROUGH` |
| --- | --- | --- | --- |
| `max_prefix_bytes` | 4 KiB | 4 KiB | 4 KiB |
| `max_far_bytes` | 32 774 | 32 774 | 32 774 |
| `max_scan_bytes` | 2 MiB | 256 KiB | 2 MiB |
| `max_decode_input` / `max_decode_output` | 1 MiB | 64 KiB | 1 MiB |
| `completion_window_bytes` | 64 KiB | off | 1 MiB |

**The budget is set in one place, `ArchiveyConfig.detection_budget`.** `detect_format`,
`open_archive` and `open_stream` read it from there. With a second way to set it, such as a
`budget=` argument on `detect_format`, the same file could be detected under two budgets
and give two answers depending on the entry point.

**Decode input is one allowance for the whole call.** The content probes, the Brotli chain
decode, the completion re-check and the inner-TAR probe all draw on it, and a step the rest cannot cover does not
run. A per-candidate cap cannot bound the total: with 2 MiB of back-to-back gzip headers,
decoding each to a 64 KiB cap is hundreds of times more work than the input. Threat-model
O11 has the measurement. No step decodes scan candidates today, so that case is not
reachable yet. A step that does, such as compressor needles for makeself installers, must
draw on the same allowance. Decode output is charged only by the inner-TAR probe. A content
probe's output is bounded by the codec's own drain.

**Steps size their reads from the budget fields.** Each step in `detection.py` computes
its own request from the budget (`min(SFX_MAX, max_scan_bytes)`, the far window, what is
left of the decode allowance), and `PrefixWorkspace` meters what they read. A limit held
as a module constant somewhere else shadows the field meant to bound it: a `FAST`
detection overruns its own preset, and nothing in the receipt says why. The SFX hit
validators follow the same rule. A candidate that starts inside the scan window is judged
on its whole header, read up to `validator_allowance(budget)` past the window end: the
smaller of `VALIDATOR_PEEK_MAX` (132 KiB, the largest header any validator reads) and
`max_scan_bytes`. Under the presets that is the constant. Under a smaller scan budget a
header that does not fit is rejected, and the clamped view records `sfx_scan` as *budget
exhausted*, so the tier never reads more than twice `max_scan_bytes`.

**Probe reads at an offset are the one path whose cap is not tied to a budget field.** A
content probe can ask for a few bytes deep in the source through `PrefixWorkspace.read_at`,
which is how the Brotli chain walk checks later meta-block headers. On a path or a plain
seekable stream, `read_at` seeks to the offset, reads, and seeks back, without growing the
prefix. It is charged to `unique_bytes_read`. It is bounded by the walk's `CHAIN_MAX_LINKS`
(8 links of 24 bytes), not by a budget field. On a pipe, or on an `ArchiveStream` whose
rewind would re-decode, `read_at` grows the prefix instead, up to the smaller of
`PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE` (1 MiB) and the workspace's read ceiling (the
largest of the prefix, far and scan limits). Past that it returns nothing and records
`content_probe_read_at` as `BUDGET_EXHAUSTED`.

When the walk stops at a compressed block past the window, the Brotli probe reads and
decodes `[0, end)`, to 4 KiB past that block's header, through the same `read_at` (a seek
read takes the part the prefix already holds from the prefix). That decode is charged to
`max_decode_input` and runs only when `end` is within the read ceiling and 1 MiB;
otherwise `content_probe_decode` is recorded as `BUDGET_EXHAUSTED` and the probe keeps its
verdict.

**The receipt says what was spent and what did not run.** `FormatInfo.cost_receipt` counts
unique bytes read, far and scanned bytes, decode input and output, and passes.
`FormatInfo.unavailable_tiers` lists each step that did not run, as a `TierSkip` with one of
three reasons:

- `NOT_ENABLED_BY_POLICY`: the budget turned it off (`probe_completion` under `FAST`,
  or `header_check` with `max_prefix_bytes=0`).
  The search is still complete for what the policy asked.
- `CAPABILITY_UNAVAILABLE`: the step could not run here. The inner-TAR probe records it
  if the codec's backend is absent or its decoder cannot be built within the probe's
  reservation (an xz filter chain it cannot decode raw, a zstd window over 128 MiB, a
  `MemoryError`). The search is incomplete. The probe records one reason: a budget that
  turns it off gives `NOT_ENABLED_BY_POLICY` whatever the backend, and an absent backend
  gives `CAPABILITY_UNAVAILABLE` ahead of `BUDGET_EXHAUSTED`, since more budget would
  not help.
- `BUDGET_EXHAUSTED`: it started or would have started, and the budget cut it short. The
  search is incomplete.

The distinction matters to a caller deciding whether a miss means "not an archive" or "not
found within what I allowed". The invariant a test holds: a receipt over its budget always
names a step as cut short. The check lives in the tests; the library never asks it.

When `detect_format` follows a stub to its volume, one receipt sums both passes and
`passes` is 2. The stub's pass is usually the expensive one, a full SFX scan. A receipt
from the second pass alone would hide most of the cost.

The receipt is separate from `ArchiveInfo.cost`, and the two are never summed. Detection
runs before the reader, and a caller comparing sources wants each number on its own.

### 4.2 One forward pass

Every step that reads the front of the source does so through one `PrefixWorkspace`
that only grows. Extending the window reads only the new prefix bytes, so near magic,
then a 2 MiB scan, then the far peek fetch each of those bytes once. Detection makes
one forward pass from the origin and does not seek back to fetch bytes the buffer
already holds. That rule is stated flatly and not derived from a cost model, because
`StreamCapability` cannot tell a cheap seek from an expensive one. A network range
reader or a member stream inside a solid 7z block would pay heavily for a rewind.

The trailer read is not part of that buffer. It seeks to the last 512 bytes and seeks
back to the end of the prefix, and it does not keep the bytes. When a later tier grows
the prefix over that range, it fetches them again, and `unique_bytes_read` counts the
512 twice. A seekable bzip2 or xz file larger than the prefix does this: the
near-magic hit is in the trailer's `preempts` list, so the tail is read before the
inner-TAR probe reads the file. A file that already fits in the prefix has the block
in the buffer, and there is no second fetch. Gzip, ZIP and ISO return before that
step, so they still fetch
each byte once. A `koly` hit returns at the trailer, before the probe, so those 512
bytes are fetched once.

A backward seek puts the handle back. It does not re-read the prefix:

- On exit, a seekable stream is seeked back to the caller's entry position. That is the
  non-consumption contract, and it happens once.
- `read_at` on a cheap-seek source seeks back to the end of the prefix after its probe
  read (§4.1), so the next forward fetch continues where the prefix ends. `read_at` never
  takes that path on an `ArchiveStream`, where a rewind would re-decode.
- The UDIF trailer read seeks back to the end of the prefix after its 512-byte read
  (§2.4). On a source that reached the step, that is a second backward seek, ahead of
  the exit restore. A pipe and an `ArchiveStream` are not asked.

### 4.3 Source kinds

| Source | What detection does | What it cannot do |
| --- | --- | --- |
| Path | Resolved first, as `open_archive` resolves it (§2.8); then opens its own handle for detection. Resolution's listing and peeks run before the receipt starts, so `cost_receipt` does not count them | Nothing missing |
| Seekable stream | Reads forward from the caller's position, restores it; the archive is taken to start where the caller positioned it | Nothing missing |
| Non-seekable, through `open_archive` / `open_stream` | Peeks through the `ArchiveSource` replay prefix; the backend reads the same object and drains the prefix first | No tail, including the `koly` block (`trailer` is recorded as `CAPABILITY_UNAVAILABLE` when detection reaches that step and the source is 512 bytes or more). Length is unknown unless the source ends inside the peek, so the probes' length-based checks do not run |
| Non-seekable, raw, to `detect_format` | Reads what it peeks | The caller loses those bytes unless it buffers the stream itself |
| Member stream (`ArchiveStream`): bare, under a buffer, through `open_archive`, or one volume of a list | Reads forward from the caller's position and restores it, like any seekable stream | No tail, including the `koly` block (`trailer` is recorded as `CAPABILITY_UNAVAILABLE` when the source is 512 bytes or more), and probe reads at an offset grow the prefix (§4.2): a seek would re-decode. `seek_is_expensive` in `internal/source.py` looks through pass-through layers, an `ArchiveSource` keeps the answer for the stream it borrows, and a joined set answers for its volumes |
| Directory | Nothing | Nothing to do |

A non-seekable source is read for what has arrived, not to fill the window, and the near
step stops once no later byte can change its answer: every signature ahead of the match in
table order has either all of its bytes in hand or a byte that already differs
(`_near_magic_settled`). So a ZIP or a gzip stream of a few KiB sent down a pipe whose
writer keeps it open is detected without waiting for the writer to close. Detection is
not the whole read: §5 says where open and the reads still wait, per format. The inner-TAR
probe decodes what has arrived the same way. Three cases still wait for 4 KiB or the end of
the source, because the answer can depend on bytes not yet sent: a match whose
earlier-listed signatures are not settled yet (TAR's `ustar` row comes first and starts at
offset 257, so a source shorter than 258 bytes, or one whose bytes from offset 257 on are
still a prefix of `ustar`), a bzip2 or xz hit (the trailer step needs the source length,
§2.4), and every source with no near match (the later steps read the whole window, and a
short window is how they learn the length). The inner-TAR probe also waits while it has
fewer than 512 decoded bytes: its read is full-count, and the codec stream learns that
the data ended only from an empty read of the source or from bytes after the end. Another
member could follow (a concatenated `.gz` or `.zst`), and so could trailing bytes. So a bare
compressed stream that decodes to under 512 bytes, of any codec, also waits for the end of
the source.

Detection never spools a pipe to a temporary file. The one temporary copy the library makes
is RAR's, for `unrar`, bounded by `SpoolLimits` and made after detection.

## 5. Sharp edges

**format**: inherent. **library**: upstream's. **archivey**: ours.

| What you see | Where | More |
| --- | --- | --- |
| A two-byte file `1f 8b` detects as `GZ` / `CERTAIN`, then fails at open with `TruncatedError` | **archivey** | Magic hits are not graded by length (§2.1, §3.2). The open still fails loudly |
| A ZIP appended to a JPEG, or behind any prefix that raises no cue, is not detected | **archivey** | The one tail read is the 512-byte `koly` block (§2.4), not a ZIP trailer. `format=ZIP` reads it. [`prefixed-archives.md`](prefixed-archives.md) §6 |
| An uncompressed `.dmg` whose disk is ISO 9660 opens as `ISO` | **archivey** | Far magic runs before the trailer (§2.4). [`formats/dmg.md`](../formats/dmg.md) §2.1 |
| Some binary files (COFF) detect as LZMA Alone or Brotli and list one `.uncompressed` member | **format** | Three formats have no usable magic (§1). A failed read is stamped `format_unconfirmed` (§2.6). Threat-model O10 |
| A zero-filled `backup.gz` detects as `GZ` / `GUESS`; the read raises `CorruptionError` with `format_unconfirmed=True` | **format** | Extension was the only evidence (§2.7) |
| A 7z SFX with data after the archive reads the whole 2 MiB window to detect | **archivey** | By choice (§2.2) |
| A source of 32 774 bytes or more that matches nothing near pays the far peek | **archivey** | The price of running far magic before the probes (§2.3) |
| `detect_format` on a raw pipe leaves the caller without the bytes it read | **archivey** | By design: `open_archive` and `open_stream` keep them (§4.3) |
| A compressed TAR sent down a pipe the writer keeps open opens at once and yields its members, but its listing does not end until the writer closes the pipe. A short one waits in detection: under 258 bytes (§4.3 has the exact rule), and a `.tar.bz2` or `.tar.xz` under 4 KiB. bzip2 gives no output until a whole block has arrived, so a `.tar.bz2` waits for the end of its first block at open | **format** / **archivey** | Detection answers at once except in the cases §4.3 lists. Past detection, the codec reads what has arrived (`BaseArchiveReader._codec_input`: `arrived_view` under `OneReadEachStream`, one source read per feed), and the walk buffer fills through `read_ahead`, which decodes only as far as the bytes the walk needs. The end waits because another stream or trailing bytes could follow the last one; the trailing-data scan reads past the trailer ([`formats/tar.md`](../formats/tar.md) §2.2) |
| A bare compressed stream (`.gz`, `.zst`, `.lz4`, `.bz2`, `.xz`, `.lz`, `.lzma`, `.zz`, `.br`, `.Z`) sent down a pipe the writer keeps open opens at once, and its reads return the data whose compressed bytes have arrived, up to its last byte. The read past the last byte waits until the writer closes the pipe. A `.bz2` read waits for the end of the block it is in, and a detected `.bz2` of any size waits at open for the end of its first block, because the inner-TAR probe decodes it; with `format=` the open returns and the first read waits instead. A short stream waits at open: under 258 bytes (§4.3 has the exact rule), a `.bz2` or `.xz` under 4 KiB, and one that decodes to under 512 bytes. A `.gz` under 512 bytes waits at open too: the single-file reader peeks a 512-byte header for FNAME and mtime (`_GZIP_HEADER_PEEK`), and that peek is full-count | **format** / **archivey** | Only an empty read of the source tells the codec that its input ended, and another member or trailing bytes could follow the stream. A short feed is not the end: the decoder asks again. The same holds for `open_stream`. A seekable source and a path read as before, in full feeds |
| A ZIP of 258 bytes or more sent down a pipe the writer keeps open opens at once, and its members come at once, but the listing does not end until the writer closes the pipe. When the sizes come after each member's data (bit 3, which a writer to a pipe sets), the last member's data also ends only at the close; the earlier members read whole at once | **format** / **archivey** | The pipe pass reads to the end of the source before it reads the central directory, which is last in the file ([`formats/zip.md`](../formats/zip.md) §2.2.2). A ZIP whose local headers carry the sizes reads every member at once. Under 258 bytes, a ZIP waits at open: TAR's `ustar` row at offset 257 is ahead of the ZIP rows in the signature table, so the near step cannot settle until byte 257 has arrived and is not `u` (§4.3). Measured: 257 bytes waits, 258 opens at once. [`docs/formats.md`](../../docs/formats.md#zip) tells senders to close the pipe |
| A polyglot opens as whichever format comes first | **archivey** | The tie rule (§3.1); pass `format=` |
| A bzip2- or xz-compressed `.dmg` read from a pipe or as a member stream detects as `BZ2` / `XZ`, with `trailer` in `unavailable_tiers` | **archivey** | Its `koly` block is at the end, and those sources are not seeked there (§2.4, §4.3) |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| A fixed sequence of seven steps, first match wins | Every defect that motivated a scheduler had a fix of a few lines in the existing order. What a scheduler adds beyond that (graded evidence classes, a stopping proof, a per-candidate evidence record) had no measured demand, and it would regrade confidence and add a new failure on files that open today | An evidence ledger: graded evidence classes per candidate, a branch-and-bound scheduler, and `AmbiguousFormatError` on ties. The OpenSpec change is archived as decided against |
| Ties go to the earlier step, then registry order | A deterministic answer, and `format=` for the other reading. An ambiguity error would fail files that open today, for a case not seen in a 33 947-file sweep | `AmbiguousFormatError` |
| Exact magic, then SFX scan, then far magic, then the `koly` trailer, then self-checking headers, then probes | Strongest evidence first. A self-checking header is arithmetic, not a decode, and passes no arbitrary bytes, so it runs on every source ahead of the probes (§2.5). Far magic goes ahead of the probes because a bootable ISO's system area is the kind of data a probe accepts. The trailer goes ahead of the probes for the same reason a zlib-first disk image must not open as its first block | Probes before far magic; a general ZIP tail scan |
| Probes decode the full 4 KiB window | A shorter sample lets text through (7 of 800 Perl modules with 256 bytes) | A 256-byte sample |
| A probe hit on a source up to 64 KiB is re-checked whole | The window cannot tell a stream that goes on from one that turns invalid after it | Accepting every hit on the window; an evidence class system for "stored-only" decodes |
| One decode-input allowance per call | A per-candidate cap cannot bound the total (O11) | Per-candidate caps |
| The budget lives on `ArchiveyConfig`, and `detect_format` has no `budget=` | One place to set it, so the entry points cannot detect one file under two budgets. The argument had never shipped in a release, so removing it cost no caller anything | A deprecated `budget=` kept alongside the config field |
| `confidence` grades evidence only; `format_unconfirmed` keys on corroboration | A grade chosen to steer an exception stops being a grade (§3.2) | Stamping on `GUESS` |
| Extension-only read failures are stamped too | A filename is weaker evidence than a probe, so it gets at least the same warning | Stamping probe hits only |
| `confidence` provisional, `detected_by` an open set | Lets a later release grade more finely or add a step without breaking callers | Freezing the grades and values in 0.2.0; renaming `sfx_scan` to `prefixed_scan` |
| A short 7z hit keeps the scan going to the end of the window | The short hit's own end would stop before a real payload that follows a decoy | Stopping at the first hit; bounding at the PE overlay now (an idea in [`IDEAS.md`](../IDEAS.md)) |
| The reader keeps the `FormatInfo` its open detected (`reader.format_info`) | `archivey info` prints it instead of detecting a second time, and a second detection could differ from the first | Detecting again in the CLI |
| Content probes run only for a name that claims the format, unless `always_probe_content` is set; `open_stream` always probes | On a nameless source a probe is the only evidence, and the backup scan found it wrong more often than right outside git objects (§2.6). Fixing one false-positive shape at a time (an OLE veto, the libmagic sweep) does not end the class | Probes on by default with more vetoes; probes off with no extension exception, which would lose the `.br`-holds-a-tar check |
| Internal detections run under `probe_config(config)` | They spend what the caller allowed, but their diagnostics are not the caller's | Passing the caller's config through |

## 7. Open questions

- **Is one decode allowance enough once a step decodes scan candidates?** It would change
  whether makeself support needs its own cap. A measurement on a window packed with
  compressor needles, run with that step in place, would answer it. Threat-model O11 stays
  open until then.
- **What does a wasted tail read cost on a cold cache or over a network?** It decides
  whether the ZIP tail probe can ever be on by default.
  [`prefixed-archives.md`](prefixed-archives.md) §3 has the argument.
- **Should short magics be graded below `CERTAIN`?** It would change a label and nothing
  else, since no behaviour keys on `confidence`. A caller who asks to branch on confidence
  would be the reason to settle it.

## 8. Verify

```bash
./scripts/test.sh tests/test_detection.py tests/test_detection_workspace.py \
    tests/test_probe_completeness_gate.py tests/test_probe_provenance_unconfirmed.py \
    tests/test_sfx.py tests/test_sfx_scan.py tests/test_brotli_framing_gate.py \
    tests/test_udif.py tests/test_cli.py::test_info_detects_once \
    tests/test_tar_header_check.py
```

| Claim |
| --- |
| The bytes win over the extension, with a conflict that names the winning evidence (§3.3) |
| Extension-only detection is `GUESS` (§2.7) |
| An empty source says it is empty (§2.7) |
| zstd skippable frames are walked inside the peek only (§2.1) |
| Far magic runs before the probes, and a short source never pays for it (§2.3) |
| The probe sample is the whole window, and small hits are re-checked whole (§2.6) |
| Probe-only and extension-only failures are stamped; corroborated ones, and self-checking header hits, are not (§2.5, §2.6, §2.7) |
| One decode allowance, shared by every decoding step (§4.1) |
| The budget comes from the config, for every entry point and every internal detection (§4.1, §3.3) |
| A receipt over budget always names a step cut short, for one pass and two (§4.1) |
| A stub-volume detection's receipt keeps the stub pass (§2.8, §4.1) |
| A path to any volume of a set is detected on the set `open_archive` reads; a gapped set raises `TruncatedError` (§2.8) |
| The detection receipt is not merged into the reader's cost (§4.1) |
| One forward pass over the prefix. Gzip, ZIP and ISO fetch each byte once and seek backward only to restore the handle. A seekable bzip2 or xz file also reads the 512-byte trailer, then fetches those bytes again when a later tier reads the file (§4.2) |
| A zlib, bzip2 or xz first block with a `koly` trailer is the disk image (§2.4) |
| A v7 tar is TAR / `PROBABLE` from a path, a `BytesIO` or a pipe, gzipped it is `TAR_GZ`, and a block one byte off its checksum, with no name, or a bad number is not a tar (§2.5) |
| A short archive on a pipe the writer keeps open is detected without waiting for the close, and with the answer the whole source gives (§4.3) |
| Detection leaves a non-seekable stream readable by the backend (§4.3) |
| A directory is decided without reading, with the zero receipt (§2.8) |
| A short 7z hit costs up to the scan window (§2.2) |
| `archivey info` reads the open's detection instead of detecting again (§6) |

To see what a detection spent, print `info.cost_receipt` and `info.unavailable_tiers` from
`detect_format(path, config=ArchiveyConfig(detection_budget=FAST_BUDGET))`.

## 9. References

- Specs: [`format-detection`](../../openspec/specs/format-detection/spec.md) (the step
  order, the tie rule, the probe guards, provenance) ·
  [`detection-cost`](../../openspec/specs/detection-cost/spec.md) (budget, receipt,
  skips)
- User docs: `docs/formats.md` §Detection
- Decided against: `openspec/changes/archive/2026-09-25-detection-evidence-ledger/`
- Related pages: [`prefixed-archives.md`](prefixed-archives.md) ·
  [`formats/single-file.md`](../formats/single-file.md) ·
  [`formats/brotli.md`](../formats/brotli.md)
- Investigations:
  [`archive-format-detection-algorithm.md`](../investigations/archive-format-detection-algorithm.md)
  · [`brotli-content-probe-results.md`](../investigations/brotli-content-probe-results.md)
- Registers: [`threat-model.md`](../threat-model.md) O10, O11
- Code: `internal/detection.py` (the steps, `_detect_format_body`) ·
  `internal/detection_workspace.py` (`PrefixWorkspace`) · `detection_cost.py` (budget,
  presets, receipt) · `detection.py` (`FormatInfo`, `DetectionConfidence`) ·
  `internal/registry.py` (the aggregated tables) · `internal/sfx.py` (cue and scan)
