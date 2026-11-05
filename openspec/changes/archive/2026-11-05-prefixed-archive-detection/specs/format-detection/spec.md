## MODIFIED Requirements

### Requirement: Self-extracting (SFX) archives are detected behind an executable stub

An archive MAY begin after byte zero. The system SHALL look for that in **cost tiers**,
because what it costs to find depends on the format, not on how hard we are willing to
look. Detection SHALL try, in order:

1. **Exact magic at offset 0** — unchanged.
2. **Tail probe for self-locating containers** (see the ZIP requirement in `format-zip`).
   Needs no prefix cue — the format bounds the locator — but SHALL run only when the
   detection budget grants `TAIL` (`max_tail_bytes` / `max_seeks`). The default `BALANCED`
   budget does not. `#273` ships every preset at `max_tail_bytes = 0`; this change is what
   may raise `THOROUGH`.
3. **Prefix-cued forward scan** for containers that cannot locate themselves, within the
   shared `SFX_MAX` window (today 2 MiB; same binding as the RAR and 7z SFX scanners), run
   before content probes. **Container needles**, searched under every cue: RAR
   (`52 61 72 21 1A 07`), 7z (`37 7A BC AF 27 1C`), and ZIP's local-file
   header (`50 4B 03 04`). TAR's `ustar` is **not** a container needle in this change —
   claiming on five bytes without the ledger's checksum validator is the rework that
   change exists to avoid.
4. **Exhaustive scan**, only when the caller's `DetectionBudget` grants a scan past
   `SFX_MAX`. The budget is `ArchiveyConfig.detection_budget`, not a keyword on
   `detect_format` / `open_archive` and not a separate `exhaustive_prefix_scan` bool.

Which magic tier 3 hunts for SHALL remain **backend-declared data**, not a table inside the
detector, and a backend SHALL declare only magic that can legitimately *begin* an appended
payload — ZIP declares its local-file header and NOT the end-of-central-directory or
spanned markers, which as needles inside a 2 MiB window would claim any executable
containing those four bytes.

Hit validators and the ZIP tail locator SHALL live on the same side of that line: a named
function on the format module (or collected next to `SFX_MAGIC`), taking a
candidate-relative view. The generic detector SHALL call those functions; it SHALL NOT
inline ZIP / 7z / RAR / gzip parse, or ZIP EOCD search, inside `detection.py`.

Validators SHALL return a small internal `HitOutcome` (`NOT_THIS_FORMAT` / `VALID` /
`DAMAGED`), not a boolean. `DAMAGED` means identity holds and structure does not (a 7z
whose `StartHeaderCRC` fails). This change's first-match scan treats `NOT_THIS_FORMAT`
and `DAMAGED` the same — not reported; the scan continues. The later
`detection-evidence-ledger` scheduler MAY treat `DAMAGED` as a lower-evidence candidate
without changing the validator function or its signature.

This change SHALL NOT introduce `DetectionDeclaration`, `EvidenceClass`, competing-candidate
ranking **across formats**, or `AmbiguousFormatError`. Those belong to
`detection-evidence-ledger`. An intra-format tie-break inside one validator (7z preferring
an exact-EOF match among several validating hits) is not that ranking. Cue restriction for
compressor needles is a backend-declared collection consulted under a `#!` cue, not a
bitfield on `MagicSignature`. The ZIP tail probe is ZIP-named: `detected_by="zip_tail_probe"`,
and the ZIP backend owns the locator function the detector calls when the budget grants
`TAIL`. It is not a format-neutral locator registry — see `design.md` §Why the tail probe
does not generalise. Inner-TAR after a compressor hit stays the existing probe-at-offset
resolution (`TAR_GZ` versus bare `GZIP`), not a gzip-specific branch.

**Compressor needles are searched under a `#!` cue only.** A script stub followed by a bare
compressed stream — `#!/bin/sh` then a gzipped tar — is the makeself / NVIDIA / Anaconda
`.run` installer family, and it is the one place where a stub plus a *stream codec* rather
than a container is a real production shape. Under a `#!` cue the scan SHALL additionally
search for stream-codec magic; under `MZ`, ELF or Mach-O it SHALL NOT.

The restriction is a cost decision like the cue itself, and rests on needle length.
Compressor magic is short, so it collides: measured across 497 ELF binaries (176 MB), gzip's
2-byte `1f 8b` occurs **423** times — 0.85 per binary — while the 3-byte `1f 8b 08`, which
pins the compression method to deflate, occurs **3** times in the same 176 MB. A
stream-codec needle SHALL therefore include the method or equivalent discriminating byte
where the format has one, and SHALL be declared only when a hit can be confirmed by a
**cheap structural validator** — the same bar `detection-evidence-ledger` calls
`DISCRIMINATING_HEADER` — without running a content probe. Probes (zlib, Brotli, LZMA
Alone) SHALL NOT become needles. Makeself's `--bzip2` is a real production shape: the
needle is `BZh` plus ASCII `1`–`9`, confirmed by the first-block marker or empty-stream
EOS (ledger task 4.5), not by `bz2.decompress`. unix-compress `.Z` stays out.

This narrows, rather than reverses, the standing rule that stream codecs declare no SFX
magic. That rule's stated reason — that a stub plus a bare compressed stream is not a thing
anyone produces — is false for shebang stubs specifically and remains true for executable
ones, so the exception is scoped to where the counterexample actually lives.

A compressor hit SHALL be resolved through the existing inner-TAR probe at the hit offset,
so a script + gzipped tar reports `TAR_GZ` rather than `GZIP`, and SHALL be validated by
decoding a bounded prefix — the magic alone is not the evidence.

**Every needle SHALL declare the offset at which it sits inside its own format, and a hit
SHALL be converted to a candidate origin before any validator or probe runs.** This is not
a detail: TAR's `ustar` lives at offset **257** of a tar header, so a hit at absolute offset
`H` means the candidate begins at `H - 257`, not at `H`. A gzip needle begins at candidate
offset 0, and 7z's and RAR's markers likewise. Reporting `payload_offset = H` for a TAR hit
would be wrong by 257 bytes and would hand the backend a misaligned source.

Validators and probes therefore SHALL receive a view **relative to the candidate origin**,
not to the source origin. Today's `peek_more(length)` always returns the first `length`
bytes of the *source*, so it cannot express that view: with it alone, a scan hit at a
non-zero offset cannot be validated in place, and the inner-TAR probe cannot run at the hit.
A bounded candidate-relative read — `peek_range(origin, length)` or an equivalent view — is
therefore a **prerequisite** for the TAR and compressor needles, not an optimisation. The
existing 7z and RAR scanners avoid the problem only because their native parsers already
accept a start offset.

ZIP keeps its tier-3 needle even though tier 2 now finds prefixed ZIPs more cheaply,
because tier 2 needs a seekable source and tier 3 does not.

The tier-3 cue SHALL fire on `MZ`, `\x7fELF`, a **`#!` shebang**, or a **Mach-O header that
parses** (thin `cputype`/`filetype`, or a fat arch table). The weak/strong grading is
retained: a strong cue (a validated PE, a valid ELF ident block, or a parsing Mach-O header)
suppresses the content probes; a weak one does not. Mach-O magic that does not parse raises
**no** cue rather than a weak one — see the sibling requirement for why the shared
`ca fe ba be` forces that asymmetry.

A match SHALL report the embedded format with `payload_offset` = payload start and a
`detected_by` naming which tier found it. No match SHALL fall through to the content probes
and then the extension fallback, ending in `FormatDetectionError` — the complete order,
including where far magic sits, is fixed by *Magic-first detection with extension fallback
and confidence scoring* and is **not** restated here. Far magic has already run by this
point; it precedes the probes rather than following them. Native RAR/7z parsers SHALL accept a start offset
(read in place, no copy). A prefixed ZIP SHALL be reported as `ZIP` with a `payload_offset`
— never as a stream codec — whichever tier finds it; ZIP needs no separate parser scan,
since the reader already locates the central directory from the tail.

The cue at tier 3 is a **cost gate, not a correctness gate**: its purpose is to avoid
reading up to `SFX_MAX` from every source, not to prevent false matches — the validation
requirement below does that. Widening the cue is therefore a cost decision, and MUST NOT
be justified by, or traded against, false-positive rate.

**Earliest-match is replaced by earliest-*valid*-match.** The superseded requirement took
the earliest matching needle and accepted that a decoy inside the stub would send the
backend to the wrong offset, failing loudly; it deliberately deferred validating a hit and
resuming the scan. The validation requirement below closes that: a candidate that fails
its structural check SHALL NOT be reported and the scan SHALL continue past it.

#### Scenario: SFX matrix

| Case | Expected |
| --- | --- |
| `MZ` + 7z magic at offset N | `SEVEN_Z`, `payload_offset == N`; backend opens at N |
| `MZ` + RAR magic at offset N | `RAR`, `payload_offset == N` |
| `\x7fELF` + RAR magic at offset N (a `rar a -sfx` stub) | `RAR`, `payload_offset == N` |
| **Mach-O (thin 64-bit) + 7z magic at offset N** | `SEVEN_Z`, `payload_offset == N` — previously `BROTLI` with a fabricated member |
| `#!/bin/sh` + tar.gz (a makeself `.run`) | `TAR_GZ`, `payload_offset` at the gzip magic — compressor needle, reached only because the cue is `#!` |
| `#!/bin/sh` + a gzip stream that is not a tar | `GZIP` at that offset; the inner-TAR probe declines and the honest answer is the stream codec |
| `MZ` or ELF stub containing gzip magic | **No compressor needle is searched under an executable cue**; no claim from the scan |
| `#!` stub whose own text happens to contain `1f 8b 08` | Bounded decode fails; not reported; scan continues |
| `MZ` + ZIP local magic at offset N, non-seekable source | `ZIP`, `payload_offset == N` — tier 3, since tier 2 needs a seek |
| Prefix + ZIP, seekable source | Found at tier 2 by the tail probe, not by the scan |
| **Strong** cue, no needle in window | No content probe runs; extension guess or `FormatDetectionError` |
| **Weak** cue, no needle in window | Content probes run unchanged |
| Stub containing a decoy needle before the real payload | Decoy fails validation; scan resumes and finds the real payload |
| Archive magic beyond `SFX_MAX`, caller did not opt in | No match; `FormatDetectionError` rather than an unbounded read |
| Bare brotli / non-executable stream | Unchanged content-probe behaviour |

### Requirement: Executable-looking prefixes must not silently become a wrong stream format

When a source's leading bytes look executable-shaped, detection SHALL NOT let a
content probe (notably Brotli) claim a stream codec and allow `open_archive` to
succeed with a fabricated single-file member (e.g. `*.uncompressed`). That is a
silent wrong answer.

This obligation is **outcome-shaped**, not "disable Brotli whenever the prefix is
`MZ`". A genuine Brotli (or other probe-matched) stream whose first bytes happen
to look executable MUST remain detectable.

The rule, settled by measurement in the archived `sfx-format-detection` design and
extended by this change's, grades the evidence:

- A **weak** cue — a bare `MZ`, `\x7fELF`, or `#!` prefix — SHALL trigger the
  forward scan and nothing else. When the scan finds no archive magic, content probes run
  unchanged. Two or four bytes are not proof, and refusing a probe on them would reject real
  streams. **Mach-O magic alone is not a weak cue**: it raises no cue until its header
  parses, because `ca fe ba be` is shared with Java class files and a weak cue would still
  cost them the scan.
- A **strong** cue — a DOS header whose `e_lfanew` points at a `PE\0\0` signature, an
  ELF identification block with valid `EI_CLASS` / `EI_DATA` / `EI_VERSION`, or a Mach-O
  header whose `cputype` and `filetype` parse — with no archive magic in the window SHALL
  suppress content probes entirely; detection falls through to the extension guess or
  `FormatDetectionError`. A structurally confirmed executable is not a compressed stream.

The set of prefixes that raise a cue at all is a **cost** decision, governed by the sibling
requirement; the weak/strong grading above is what decides the *outcome* once a cue exists.
The two are independent: widening the cue set does not weaken this rule, and this rule does
not license reading `SFX_MAX` from sources the cost gate excludes.

**A prefix outside the cue set gets neither treatment, and that is where this obligation was
being broken.** Before this change the cue recognised `MZ` and ELF only, so a thin
little-endian Mach-O stub raised no cue — while `cf fa ed fe` is *structurally guaranteed*
to parse as an uncompressed Brotli meta-block header. Measured end to end: PE and ELF stubs
in front of a 7z opened the real members, and a Mach-O stub returned `BROTLI` with one
fabricated `.uncompressed` member. Adding Mach-O to the cue set is what closes it; the
grading above was already correct.

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
| **Thin little-endian Mach-O stub + 7z payload** | `SEVEN_Z` — previously `BROTLI` (or `LZMA_ALONE`) with a fabricated member |
| `#!/bin/sh` + tar.gz in window | Detected as that archive, not claimed by a probe |
| Real Brotli stream with non-executable prefix, `.br` extension | Unchanged — `BROTLI` / `PROBABLE` via content probe |
| Real Brotli stream with non-executable prefix, compressed-first, no corroborating extension | Still `BROTLI` via content probe, at `PROBABLE` |
| Real Brotli stream with non-executable prefix, uncompressed/metadata-first, no corroborating extension | Still `BROTLI` via content probe, at `GUESS` |
| Real Brotli (or other probe format) whose prefix coincides with a **weak** executable cue | Still detected as that stream — **not** forced to `FormatDetectionError` solely because two bytes were `MZ` |
| **Strong** executable cue (validated PE / ELF / Mach-O), no archive needle in the window | No content probe runs; extension guess or `FormatDetectionError` — never a fabricated member |
| Executable-shaped prefix, no archive needle, probe correctly rejects | Extension guess or `FormatDetectionError` — not a fabricated member |
| **Fat (universal) Mach-O stub + 7z payload** | `SEVEN_Z` — the fat header parses, so the cue fires, and it must not stop the scan before the payload |
| **Java `.class` file** (`ca fe ba be`, shared with the Mach-O fat magic) | **No cue at all.** The bytes after the magic do not parse as a fat header, so a `.class` file SHALL NOT pay the `SFX_MAX` scan, and its content-probe behaviour is unchanged |
| Mach-O magic whose `cputype` / `filetype` (or fat arch table) do not parse | **No cue** — not a weak one. Four bytes are not evidence for a magic this change is adding, and the probes still run |

**Mach-O is the one cue that requires a successful header parse to fire at all**, and the
rule differs from `MZ` / `\x7fELF` / `#!` deliberately. Those three raise a weak cue on their
leading bytes alone; Mach-O SHALL NOT. `ca fe ba be` is simultaneously the Java class-file
magic, so a bare-magic cue would put every `.class` file in a source tree through a 2 MiB
scan — and grading it *weak* would not help, because a weak cue still triggers the forward
scan. Only "no cue" actually spares it.

Nothing is lost by requiring the parse: a real Mach-O SFX stub is a real executable, so its
header parses by construction. So Mach-O has two states rather than three — parses (strong,
suppressing the content probes) or does not (no cue, probes run unchanged) — and the
fat/thin split matters within the first: a *fat* stub fails loudly today while a *thin* one
is the shape that fails silently, so both belong in the matrix rather than in tasks prose.

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

class PrefixKind(Enum):
    NONE = "none"
    EXECUTABLE = "executable"
    SCRIPT = "script"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class FormatInfo:
    format: ArchiveFormat
    confidence: DetectionConfidence
    detected_by: str
    payload_offset: int = 0
    diagnostics: DiagnosticSummary = DiagnosticSummary.empty()
    prefix_kind: PrefixKind = PrefixKind.NONE
```

`config=None` → library default. Detection's spend cap is `config.detection_budget`
(`None` → `BALANCED_BUDGET`). The budget types live in `archivey.detection_cost` until
`detection-result-surface` freezes the root surface; this change does not re-export them.
`detect_format` SHALL NOT grow a `budget=` / `detection_budget=` keyword — `#273`'s
`budget=` argument is removed when the config field lands. `confidence` = magic /
structural probe / extension-guess. `payload_offset > 0` marks an SFX payload start.

`prefix_kind` SHALL always be present, defaulting to `NONE`, so a caller may read it
without testing `payload_offset` first. `NONE` SHALL correspond exactly to
`payload_offset == 0`; the classification of a non-zero prefix is specified in *Detection
reports what precedes the payload*.

`detected_by` SHALL name the tier that produced the match, drawn from `"magic"`,
`"zip_tail_probe"`, `"sfx_scan"`, `"exhaustive_scan"`, `"content_probe"`, and
`"extension"`.

**The exhaustive-scan opt-in is `ArchiveyConfig.detection_budget`, not a keyword
argument.** `detect_format` and `open_archive` already take `config=`; a second
spend-cap argument would be two knobs most callers never set. `#273`'s
`detect_format(..., budget=)` is removed in the same PR that adds the field
(task 3.1). There is no `exhaustive_prefix_scan` bool.

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
| Explicit `diagnostic_policy` on detect | IGNORE/COLLECT/RAISE applies to that finite detection |
| Plain archive at offset 0 | `prefix_kind == NONE`, `payload_offset == 0` |
| Prefixed archive found by any tier | `prefix_kind` set, `payload_offset > 0`, `detected_by` naming the tier |
| Default `BALANCED` budget (`config.detection_budget is None`) | No unbounded read; a beyond-window archive stays undetected |
| `config=ArchiveyConfig(detection_budget=…)` with `max_scan_bytes` past `SFX_MAX` | Exhaustive scan may fire |

### Requirement: Magic-first detection with extension fallback and confidence scoring

The system SHALL execute format detection with this algorithm:

**The ordering principle is strength of evidence first, cost second.** A signal that proves
little must never be consulted before one that proves a lot, because the cheap weak signal
answers first and the strong one is never asked. Cost decides only between signals of
comparable strength. Ranked by what each actually establishes:

| evidence | what it proves | measured |
| --- | --- | --- |
| exact magic at a fixed offset — **near or far** | specific bytes in a specific place | ISO's 5-byte `CD001` collides by chance at ~2⁻⁴⁰ |
| a validated structural hit (tail probe, 7z/RAR scan) | magic **and** self-consistency | near-certain by construction |
| a content probe | a bounded decode did not fail | **weakest** — accepts 8.2% of arbitrary binary data, 3.5% of a real `/usr` tree, ~0.15% after the framing gate |
| an extension | what someone named the file | no evidence about content at all |

The content probe is the weakest signal in the system by a wide margin, so it SHALL run
after **every** form of exact magic and after every validated structural hit.

The steps below are **ordered attempts, not a chain of alternatives**: each step that does
not produce a match falls through to the next, and a step being *attempted* never prevents a
later step from running. In particular a seekable source whose tail probe finds nothing SHALL
still reach the forward scan, the content probes, and the extension fallback.

1. Read up to `DETECTION_LIMIT` bytes (default 4096) from the source.
2. **Near magic** — the magic-byte table at exact offsets within that window. Match →
   `CERTAIN` / `detected_by="magic"` (see the provisional note below: a uniform `CERTAIN`
   across signatures of wildly differing strength is known to be wrong, and is retained
   here only because changing it is a separate piece of work).
3. **Far magic** — signatures outside the default window, today ISO 9660's `CD001` at offset
   32 769. Match → `CERTAIN` / `detected_by="magic"`. This SHALL be attempted **before** the
   content probes, because it is exact magic and they are the weakest signal available. It
   SHALL be skipped when the source size is known to be smaller than the extended window,
   and a source too short for it SHALL fall through rather than be rejected.
4. **Tail probe** for self-locating containers (`format-zip`), when the source is seekable
   **and** the budget grants `TAIL`. A validated hit → `CERTAIN` / `detected_by="zip_tail_probe"`.
   This tier needs no prefix cue — the format bounds the *locator's* cost — so when it runs
   it runs even when nothing about the leading bytes looks executable. It is **off** under
   `BALANCED` (and, until this change raises them, under `THOROUGH` too: `#273` left
   `max_tail_bytes = 0` on every preset). See the cost note below.
5. **Bounded forward scan** within `SFX_MAX`, when a prefix cue fires. A validated hit →
   `detected_by="sfx_scan"`.
6. **Unbounded scan**, only when the budget's `max_scan_bytes` exceeds `SFX_MAX`. A validated hit →
   `detected_by="exhaustive_scan"`.
7. **Content probes** — formats with no exact magic (Brotli, zlib, LZMA Alone). Match →
   `detected_by="content_probe"`, at the confidence the magic-less-formats requirement
   specifies. Skipped entirely on a **strong** executable cue, per *Executable-looking
   prefixes must not silently become a wrong stream format*; a weak cue does not gate them.
8. **Extension** — `Path` with a known extension → `GUESS` / `detected_by="extension"`.
9. `FormatDetectionError` when nothing matched.

Steps 4–6 are the cost tiers specified in *Self-extracting (SFX) archives are detected
behind an executable stub*; this requirement is where their placement relative to the
content probes, far magic and the extension fallback is fixed.

> **Provisional: two parts of this requirement are known to be wrong and are scheduled to
> change.** The independent design analysis in
> `dev-docs/investigations/archive-format-detection-algorithm.md` (added by PR #263) was accepted as redesign
> input for this change, and it identifies two defects that this change deliberately does
> **not** fix, because fixing either is a larger piece of work than prefixed-archive
> detection:
>
> 1. **A uniform `CERTAIN` for all near magic is unsound.** gzip's two bytes and
>    `unix-compress`'s two bytes are not the same evidence as XZ's stream-flags CRC, 7z's
>    `StartHeaderCRC`, or TAR's header checksum. Signature length and the presence of a
>    structural validator should grade the result; flattening them to one confidence value
>    is the same failure mode that let a content probe outrank ISO's far magic.
> 2. **First-match-wins is not a sound selection rule.** Where several detectors can accept
>    the same bytes — notably the three magic-less probes, and genuine polyglots — returning
>    the first hit in registry order picks by accident. Selection should compare typed
>    evidence once every tier that could dominate has run.
>
> Until that redesign lands, this requirement states the **acquisition order**, which is
> what prefixed-archive detection needs and which the analysis endorses. It does not settle
> evidence strength or the selection rule, and an implementer SHALL NOT read the uniform
> `CERTAIN` above as a considered decision that those signatures are equally strong.

**The tail probe's cost is bounded for the locator, not for the whole tier.** Two separate
numbers, and conflating them overstates how cheap "format-bounded" is:

- **Locating** the EOCD reads at most `min(remaining, 65535 + 22)` bytes from the end, plus
  the positioning and restoration operations. That bound is real and comes from the format.
- **Validating** it, and computing an exact `payload_offset`, additionally reads the ZIP64
  record where present, central-directory bytes, and at least one local header. The earliest
  local-header offset may require walking the **entire** central directory, whose size is
  **not** bounded by 65,557 bytes.

So a cheap result may report ZIP after bounded geometry checks, while an exact
`payload_offset` charges the central-directory walk. A requirement that says "one seek and
64 KiB" is describing only the first of those.

Aggregate cost, measured over 71,983 files under `/usr`:

| | |
| --- | --- |
| files at least 65,557 B, which pay the locator in full | 3,195 — **4.4%** |
| median file size | 2,239 B |
| **actual aggregate locator bytes** | **0.61 GiB** |
| worst case if every file paid in full | 4.39 GiB |

The worst case overstates the real cost by roughly 7×, because the locator is also bounded
by the source and most files are small. But 0.61 GiB of reads — and, more importantly,
**one additional seek per file across the whole sweep** — is a real cost on the founding
backup-corpus workload, and seek latency rather than byte count is likely to dominate on a
network or spinning-disk source.

Therefore: this tier is **off** under `BALANCED`. Seek latency on the founding backup
workload, not byte count, is what would have to change that. The probe is specified and
available under a budget that grants `TAIL`; it is not an assumption inherited from
"format-bounded".

**Far magic ahead of the content probes closes a silent wrong answer.** ISO 9660 reserves
its first 32 KiB as a system area for a bootloader, so every bootable or hybrid image
carries real executable code exactly where detection peeks — and the Brotli probe accepts
such data at the rate above. Reproduced on a genuine `pycdlib`-built ISO: with a zeroed
system area it detects as `ISO` / `CERTAIN` and lists its members, and with that area
overwritten by boot-code-shaped bytes (the `isohybrid` shape, filesystem byte-identical) the
same image detects as `BROTLI` / `GUESS`, opens as a single fabricated
`*.uncompressed` member, and raises `CorruptionError` on read — while the ISO remains
readable by other tools. Exact magic at a known offset was available the whole time and was
never consulted.

The size precondition keeps the move cheap. `source_byte_size()` is already computed for the
framing gate at the probe step, so hoisting it costs nothing, and no ISO is smaller than the
extended window — so a small source never pays the extended peek, and the only sources that
do are ones nothing cheaper has identified.

**The extension fallback SHALL remain last, after the content probes.** *An unconfirmed
format choice is reported when the listing is empty* defines `detected_by="extension"` as
the state where magic, the content probes **and** far magic all declined, and the Brotli
confidence split in *Magic-less formats are detected by a content probe* only has meaning if
the probe runs before the extension can answer. Moving the extension earlier would silently
downgrade a real `.br` stream from a probe result to an extension guess, and change what
`format_unconfirmed` reports, without either requirement saying so.

**The extension is nonetheless read up front, and is a corroborator throughout, not only a
final tier.** Its value is available from the first step and SHALL be used to grade other
evidence — it decides the Brotli probe's `PROBABLE`-versus-`GUESS` split, and it is what a
`FORMAT_EXTENSION_CONFLICT` is raised against. Being *last to answer* and *available
throughout* are not in tension: the extension never outvotes evidence drawn from the bytes,
and it still sharpens what that evidence is worth.

> **Note for the archiver.** When this block was written, the live text of this requirement
> listed the extension fallback *before* the content probes and omitted far magic entirely —
> a pre-existing defect rather than one this change introduced. Because a MODIFIED
> requirement replaces its predecessor whole, restating the live order verbatim would have
> re-shipped that error, so this block states the order the implementation actually has.
>
> **`detection-format-gaps` has since fixed both halves of that defect in the live text**, and
> shipped the far-magic hoist itself. **Step 3 is therefore inherited here, not proposed by
> this change** — it is retained verbatim *because* the replacement is whole-requirement:
> deleting it would remove far magic from the live spec when this change archives, silently
> reverting a shipped behaviour fix. Nothing in step 3 is work for this change's implementer;
> its tasks (3.4a's reorder clause, 3.4b, 3.4c, 3.4d) are struck accordingly. What this change
> still proposes are the tail probe, the cued and exhaustive scans, and their placement — steps
> 4 to 6.
>
> Before archiving, re-check step 3 against the then-live text and carry over any wording
> `detection-format-gaps` settled, exactly as this block already did for
> `brotli-probe-framing-gate`. That carry-over has already happened once: when that change
> archived, `openspec validate` refused this delta for omitting its
> *far magic precedes the content probes* scenario, which is now inherited below with this
> requirement's step numbers. The tool enforces exactly the hazard this note describes —
> trust it over any assumption that the blocks are disjoint.

#### Scenario: unrecognised bytes, no path

| Case | Expected |
| --- | --- |
| Non-seekable `BinaryIO`, no filename, no magic | `FormatDetectionError` |

#### Scenario: far magic precedes the content probes

Inherited from `detection-format-gaps`, which shipped the hoist; carried here because a
MODIFIED requirement replaces the whole block, so omitting it would drop the scenario from
the live spec. Step numbers are this requirement's (far magic 3, probes 7), not that
change's (4 and 5). The rows overlap *tier ordering* below by design — that table places
far magic among the new tiers, this one is the shipped guarantee it must not break.

| Case | Expected |
| --- | --- |
| Bootable/hybrid ISO whose 32 KiB system area holds boot code a probe accepts | `ISO` / `CERTAIN` / `magic` — not a fabricated single-file member |
| ISO with a zeroed system area | `ISO` / `CERTAIN` / `magic`; unchanged |
| Source smaller than the extended window, size known | Step 3 skipped without an extended peek; falls through |
| Source too short for the window, size unknown | Short peek, no match, falls through — never an error for being short |
| Real Brotli stream larger than the window, no extension | One bounded peek misses at step 3, then step 7 detects it |

#### Scenario: tier ordering

| Case | Expected |
| --- | --- |
| Seekable non-archive file with no executable cue | Tail probe still runs; finds nothing; falls through |
| Prefixed ZIP, seekable, no executable cue (`#!` or otherwise) | Found at step 4, before any extension guess |
| Prefixed ZIP whose extension is also known (`.pyz`) | Step 4 wins; `CERTAIN`, not the `GUESS` an extension would give |
| Prefixed 7z behind an `MZ` stub | Not found at step 4 (7z cannot self-locate); found at step 5 |
| Archive beyond `SFX_MAX`, opt-in off | Steps 4–6 miss; probes and extension still run; source not read past the window |
| **Seekable source, tail probe finds nothing, `MZ` stub with a 7z inside** | Scan still runs — a tail-probe miss SHALL NOT short-circuit step 5 |
| **`x.br` holding a real Brotli stream, no cue** | `BROTLI` via the **content probe** at step 7, at the probe's confidence — **not** an extension `GUESS`; the extension never gets to answer first |
| **Extensionless file holding a real Brotli stream** | Still reaches step 7 and is detected; nothing about a missing extension skips the probes |
| **Bootable/hybrid ISO whose 32 KiB system area is boot code the Brotli probe accepts** | `ISO` / `CERTAIN` / `"magic"` at step 3 — **not** `BROTLI` with a fabricated member. This is the ordering's reason for existing |
| Plain ISO with a zeroed system area | `ISO` / `CERTAIN` / `"magic"`; unchanged from today |
| Source smaller than the extended window, size known | Step 3 skipped without an extended peek; falls through |
| Source too short for the ISO window, size unknown | Extended peek returns short; no match; falls through rather than erroring |
| **Real Brotli stream larger than 32 KiB, no extension** | Step 3 attempts the extended peek and misses, then step 7 detects it — the reorder costs one bounded peek, never a detection |
| Non-archive `.zip` (extension only, nothing matches) | `GUESS` / `"extension"` at step 8, reached only because 2–7 all declined — which is what makes `format_unconfirmed` meaningful |

## ADDED Requirements

### Requirement: A prefixed-container match is confirmed structurally, not by magic alone

A forward-scan hit SHALL be validated before it is reported, using evidence the candidate
carries about itself:

- **7z**: the 32-byte signature header self-checks. `StartHeaderCRC` is a CRC32 over the
  20-byte StartHeader that follows it, and `offset + 32 + NextHeaderOffset +
  NextHeaderSize` SHALL fall at or before the end of the source — landing exactly at the
  end is the strong form, and SHALL be preferred when several candidates validate. A
  trailing-data tolerance is required because some stubs append configuration after the
  archive.
- **RAR 5**: the 8-byte marker SHALL be followed by a main archive header whose CRC32
  matches.
- **RAR 4**: the 7-byte marker block SHALL be followed by a parseable main header.
- **ZIP**: a local-file-header hit SHALL pass a cheap structural check without a tail
  seek: `version_needed` within a sane maximum, the reserved GP-flag bits clear,
  `compression_method` in the known set, and `filename_length` / `extra_field_length`
  plausible and in-bounds against the remaining source. Four bytes of `PK\x03\x04` in a
  stub are not a ZIP. EOCD + central-directory confirmation (the `CERTAIN` bar the tail
  probe already requires) is the Block 2 tail helper's job, not a Block 1 requirement.
- **Stream codecs** (shebang cue only): the magic SHALL include the compression-method
  byte where the format has one. Identity is the cheap structural validator (gzip header
  checks; bzip2 block-size digit plus first-block / EOS marker; xz flags CRC; and the
  equivalents the ledger lists). A hit that identifies SHALL then be run through the
  existing inner-TAR probe, so a script-wrapped gzipped tar resolves to `TAR_GZ` rather
  than `GZIP`. The inner-TAR decode is a *resolution* step, not the format identity.

A candidate that fails validation SHALL NOT be reported, and the scan SHALL continue.
Validation exists so that a hit can be reported at high confidence and so a scan cannot
claim a file that merely contains the magic bytes; it does **not** license scanning more
sources than the cost gate allows.

#### Scenario: scan validation matrix

| Case | Expected |
| --- | --- |
| Stub + real 7z, CRC and end-offset agree | `SEVEN_Z` at that offset, `CERTAIN` |
| `#!` stub + gzipped tar, header identifies and inner-TAR resolves | `TAR_GZ` at the gzip offset |
| `#!` stub + gzip magic whose header bytes fail the structural check | Not reported; scan continues |
| `#!` stub + identifying gzip that is not a tar | `GZIP` at the gzip offset — inner-TAR is resolution, not identity |
| `#!` stub whose text contains `PK\x03\x04` but no valid local header | Not reported; scan continues |
| `#!` / ELF stub + local header that passes the cheap check, real ZIP follows | `ZIP` at that offset |
| The 6 magic bytes appear in unrelated data | CRC fails; not reported; scan continues |
| 7z whose declared end overruns the source | Not reported |
| 7z with trailing bytes appended after the archive | Still reported — declared end within the source |
| Stub + RAR5 whose main-header CRC fails | Not reported |

### Requirement: Detection reports what precedes the payload

`FormatInfo` SHALL always carry a `prefix_kind` describing what sits in front of the
payload, so a caller can distinguish an archive meant to be extracted from an archive that
merely happens to be embedded, and can read the field without first testing
`payload_offset`. archivey SHALL report what it observed and SHALL NOT infer the producer's
intent beyond that.

`prefix_kind == NONE` SHALL hold exactly when `payload_offset == 0`. The two are reported
together and cannot disagree: a prefix that detection could not classify is `UNKNOWN`, not
`NONE`. This is why `payload_offset` is defined in `format-zip` as the position of the
earliest local file header rather than as the ZIP's internal offset adjustment — under the
adjustment definition a `zipapp` file would report `0`, and the headline case for this
change would be indistinguishable from an unprefixed archive.

| `prefix_kind` | meaning |
| --- | --- |
| `NONE` | `payload_offset == 0` |
| `EXECUTABLE` | PE, ELF or Mach-O — a self-extracting archive |
| `SCRIPT` | a `#!` shebang — a self-extracting shell installer |
| `UNKNOWN` | a prefix that is neither executable nor shebang. How the offset was found is `detected_by`, not a kind. Archivey does not maintain a non-archive file-type list, so a JPEG prefix is `UNKNOWN` rather than a recognised other format |

`payload_offset is None` (origin not established — a forced `format=ZIP` whose reader
self-adjusted) is a different axis, for a later change on `ArchiveInfo`,
and SHALL NOT grow a fifth `PrefixKind` member.

#### Scenario: prefix kinds

| Case | Expected |
| --- | --- |
| Plain `.zip` | `prefix_kind == NONE` |
| `rar a -sfx` output | `EXECUTABLE` |
| `zipapp` `.pyz`, Spring Boot executable JAR | `SCRIPT` |
| JPEG with an appended ZIP (tail probe enabled) | `UNKNOWN` — not a new file-type |
| ZIP found by the opt-in scan behind unrecognised bytes | `UNKNOWN` |
