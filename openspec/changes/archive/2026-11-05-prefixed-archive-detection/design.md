> **Cut on 2026-09-25.** The ZIP tail probe (Block 2) and `prefix_kind` / `PrefixKind` are
> struck, the exhaustive scan is deferred unless asked, and `ArchiveyConfig.detection_budget`
> has landed. The spec deltas below still describe the struck parts and must be trimmed
> before this change is archived. See the note at the top of `tasks.md`.
>
> **Trimmed on 2026-09-27.** The ZIP-tail budget and receipt fields (`max_tail_bytes`,
> `max_seeks`, `tail_bytes`, `seeks`), `DetectionCapability` (`TAIL`, `SEEK`), the
> detection spool and the `zip_tail` skip were removed from the library before 0.2.0, and
> the `detection-cost` delta that would have put them back on archive is deleted. The
> `format-detection`, `format-zip` and `archive-reading` deltas and the tasks below still
> name them for the struck Block 2; a tail probe that is reopened adds its own fields as
> an additive change.

# Design — prefixed archive detection

## The idea, in one line

**What it costs to find an archive that starts late depends on the format, so tier the
search by cost instead of applying one rule to every format.**

## Why the old rule was shaped the way it was

The shipped requirement says: *if leading bytes look like executable (`MZ` / ELF), scan for
RAR or 7z magic within a bounded forward window.* The cue is easy to misread as a
false-positive defence — a reviewer of the sibling Brotli change read it that way — but it
is not. It exists so that opening an ordinary file does not read up to `SFX_MAX` (2 MiB)
looking for a stub that is not there. `sfx.py` makes that explicit: the window is stepped in
geometric peeks of 64 KiB → 256 KiB → 1 MiB → 2 MiB, and **each peek asks for the first
N bytes again** rather than continuing. A full miss therefore hands the scanner
64 + 256 + 1024 + 2048 KiB = 3392 KiB to cover a 2048 KiB window — **1.66×**, counted by
instrumenting the loop. (`sfx.py`'s comment says "a little over 2×"; that overstates it.)

Whether that 1.66× is real I/O depends on the source, and it is worth being precise
because the tiering argument leans on it:

| source | what a repeat peek costs |
| --- | --- |
| `Path` | `_peek_prefix` reopens the file and re-reads from byte 0 — **1.66× real reads**, mostly absorbed by the page cache |
| seekable stream | `tell` / `read_exact` / `seek` back — **1.66× reads** on the file object |
| `PeekableStream` | `_fill_to` reads only the delta, so **1× I/O**; the 1.66× is the repeated `bytes(buffer[:n])` copy, and the buffer grows to the full window |

The reason it re-requests rather than continuing is the **peek contract**: detection must
leave the source positioned where the caller left it, because the backend opens it next.
`peek_more(n)` means "the first n bytes, without consuming", so there is no cursor to
continue from — not having one is the point.

That is fixable for the seekable kinds (seek to `searched - overlap`, read only the
delta), and for `PeekableStream` the I/O is already optimal — handing the scanner a
`memoryview` over the buffer instead of a fresh copy would remove the rest. It is written
the current way because one uniform `peek_more` callable serves all four source kinds,
which is a genuine simplification, and the cost was believed to be bounded and small.

Worth noting for honesty: fixing it narrows the tail-probe-versus-scan gap from about 53×
to about 32×. The tiering argument survives that comfortably — it does not depend on the
inefficiency.

Getting the rationale right is what unlocks the design. If the cue were a correctness gate,
widening it would be dangerous — it would be trading away a defence. Because it is a cost
gate, widening it is a **cost** decision, and the honest way to state that cost is as a
*population*: the cue does not change what a matching file pays, it changes **which files
match**.

Today only `MZ` and ELF enter the `SFX_MAX` path. Adding Mach-O and `#!` enrolls every
shell and Python script a caller points at — including the ordinary non-archive scripts in
a backup corpus, which is VISION's founding use case. Counted on this container's `/usr`
tree, 72 100 files:

| prefix | files | share | status |
| --- | --- | --- | --- |
| `#!` shebang | 734 | 1.0% | **newly enrolled** |
| Mach-O | 8 | 0.01% | **newly enrolled** |
| ELF | 2 837 | 3.9% | already paying |
| `MZ` | 31 | 0.04% | already paying |

So the scanned population grows by 742 files against 2 868 — about **26% more files**
paying the scan. That is the real cost move, and it is not free.

What keeps it small is that the scan is bounded by the source as well as by `SFX_MAX`: a
2 KB shell script costs 2 KB, not 2 MiB. Across those 734 shebang files the median is
2 959 B, the mean 14 781 B, and exactly **one** file reaches `SFX_MAX` at all — a total of
**10.3 MiB** of additional reads to sweep the entire tree. The population grows by a
quarter; the bytes do not, because the newly enrolled population is made of small files.

Both halves belong in the argument. "Widening is free" is wrong, and "every `#!` file now
reads 2 MiB" is wrong by two orders of magnitude in the other direction. The claim that
survives is: *widening enrolls more files, each bounded by `min(size, SFX_MAX)`, and for
the shebang population that bound is small in practice.*

Two consequences for the implementation. A tier-2 hit SHOULD short-circuit tier 3 — a
`zipapp` or Spring Boot JAR is a seekable ZIP, so the tail probe answers it and it should
never reach the scan at all, which removes the most common shebang case from the new
population. And the cost regression (task 4.8) needs a shebang row: a `#!` non-archive
source must read no more than `min(size, SFX_MAX)`, so the bound is pinned by a test rather
than by this paragraph.

## The cost asymmetry

| tier | bound | who bounds it |
| --- | --- | --- |
| tail probe (ZIP) | 65535 + 22 bytes, one seek | **the format** — the EOCD comment length is a `uint16` |
| forward scan (7z/RAR/TAR) | `SFX_MAX` = 2 MiB window; 3392 KiB scanned on a miss (1.66×, fixable to ~1×) | a constant we chose |
| exhaustive scan | the whole source | nothing |

Tier 1 is not a tuning parameter. No valid EOCD can sit further back, so searching further
cannot find anything and searching less would reject legal archives. A bound the format
hands you can run unconditionally; a bound you invented needs a reason to run.

## What this fixes, measured on `main`

| file | `detect_format` today | `open_archive(format=ZIP)` today |
| --- | --- | --- |
| `zipapp` `.pyz` | `FormatDetectionError` | opens, both members, contents intact |
| Spring Boot executable JAR | `FormatDetectionError` | opens |
| JPEG + appended ZIP | `FormatDetectionError` | opens |
| makeself `.run` (script + tar.gz) | `FormatDetectionError` | fails — genuinely needs an offset |

The first three are pure detection bugs: the reader already works, and stdlib `zipfile`
opens all three, so archivey is currently worse than `zipfile` on a file the standard
library itself produces. The cue never fires because the prefix is `#!`, not `MZ`.

## Ordering: strength of evidence first, cost second

> Since this section was written, an independent design analysis
> (`dev-docs/investigations/archive-format-detection-algorithm.md`, added by PR #263) reviewed it and was
> accepted as redesign input. It **agrees** that far magic must precede the content probes
> and calls the bootable-ISO reproduction decisive. It **disagrees** with two things this
> change kept: that all near magic deserves one `CERTAIN`, and that first-match-wins is a
> sound selection rule. Both are now marked provisional in the spec rather than quietly
> retained. It also found an implementability gap nobody here had: needles carry an anchor
> offset inside their own format, so a TAR `ustar` hit is 257 bytes past its candidate
> origin, and the current peek primitive cannot express a candidate-relative view at all.

Writing the tiers down forced the question of where they sit relative to everything else,
and answering it surfaced a defect that has nothing to do with prefixes.

The rule has to be **evidence strength first, cost only as a tie-break between comparable
signals.** A weak signal placed early answers first, and the strong one is never asked — so
ordering by cost alone silently trades correctness for latency. Ranked by what each actually
establishes:

| evidence | proves | measured |
| --- | --- | --- |
| exact magic at a fixed offset, near **or far** | specific bytes in a specific place | ISO's 5-byte `CD001` collides at ~2⁻⁴⁰ |
| validated structural hit (tail probe, 7z/RAR scan) | magic **and** self-consistency | near-certain by construction |
| content probe | a bounded decode did not fail | **8.2%** of arbitrary binary data, **3.5%** of a real `/usr` tree, ~0.15% after the framing gate |
| extension | what someone named the file | nothing about the content |

The content probe is the weakest signal archivey has, by a wide margin and by measurement.
Shipped, it runs **fourth of five — ahead of far magic.** That inverts the rule, and ISO is
where it bites: ISO 9660 reserves its first 32 KiB as a system area for a bootloader, so
every bootable or hybrid image has real executable code sitting exactly where detection
peeks, and executable code is the data class the Brotli probe accepts.

Reproduced on a genuine `pycdlib`-built ISO, changing **only** the reserved area — the
filesystem stays byte-identical, and other tools keep reading it:

| system area | `detect_format` | `open_archive` |
| --- | --- | --- |
| zeroed | `ISO` / `CERTAIN` / `magic` | lists `README.`, reads correctly |
| boot-code-shaped | **`BROTLI` / `GUESS` / `content_probe`** | one fabricated `*.uncompressed`; read raises `CorruptionError` |

Exact magic was available at a known offset the entire time and was never consulted. This is
the same silent-wrong-answer shape as the Mach-O defect, reached from the other end — there
a missing cue let a probe claim a stub, here a late tier let a probe claim a whole
filesystem.

So far magic moves to second, right behind near magic. The cost is one bounded peek on
sources that nothing cheaper identified, and it is gated on the source being at least as
large as the window — `source_byte_size()` is already computed at the probe step for the
framing gate, so hoisting it is free, and no ISO is under 32 KiB. Small files pay nothing.

**A note on the extension, because "extension versus probes" is a false dichotomy.** The
extension is read up front and used as a *corroborator* throughout: it is what
`_brotli_probe_confidence` consults to split `PROBABLE` from `GUESS`, and what a format
conflict is raised against. It is last to *answer* and available *throughout*, and those two
facts are not in tension — it never outvotes evidence drawn from the bytes, but it does
sharpen what that evidence is worth. The live requirement's "magic → extension → probes"
reads as though the extension competes with the probes, which is what made it easy to
restate wrongly.

## Why the scan can trust itself

Not the reason to scan — cost decides that — but the reason a hit can be reported at
`CERTAIN` rather than hedged. Both scanned formats carry their own proof:

**7z.** The 32-byte signature header contains `StartHeaderCRC`, a CRC32 over the 20-byte
StartHeader that follows it, and that StartHeader gives `NextHeaderOffset` /
`NextHeaderSize`. Verified against a real archive behind stubs of 23 bytes, 4 KiB and
100 KB: CRC valid in every case, and `offset + 32 + NextHeaderOffset + NextHeaderSize`
landed exactly on EOF in every case. Combined, a false hit needs a 48-bit magic *and* a
32-bit CRC *and* a size agreement.

Use `<=` against the known source remaining from the candidate origin (not the
scan window / `SFX_MAX`) for the gate, and `==` as a later tie-break among several
CRC-valid hits. The slim follow-up after #277 landed the remaining-length gate
and rejects an empty next-header (`NextHeaderSize == 0`) behind a stub: nobody
ships a self-extractor with no files, and a genuine empty `.7z` is claimed by
near magic, never by the scan. Exact-EOF ranking has landed (task 2.3, done
2026-09-25): a hit whose declared end falls short of the source grades
`HitOutcome.VALID_SHORT` and the scan keeps looking for one that ends at EOF
(`internal/sfx.py`), pinned by `tests/test_sfx.py::test_inexact_7z_decoy_loses_to_a_later_exact_payload`
and recorded in `dev-docs/topics/prefixed-archives.md`. Appending 16 bytes to a 7z leaves it perfectly
readable while breaking the exact-EOF equality, and some SFX tools append
configuration after the payload — measured, not assumed. That is why the
tie-break is a preference among validated hits, not a filter.

**RAR 5.** The 8-byte marker is followed by a main archive header with its own CRC32,
which validated at every stub offset tried.

This is the same shape as `brotli-probe-framing-gate` (proposed in PR #255): *the thing declares
where it ends, so check that against the source.* Worth noting the recurrence — it is
becoming this codebase's standard way to make a cheap signal trustworthy.

## Why the tail probe does not generalise

It was tempting to make tier 2 "probe the last 64 KiB for anything". It only works for ZIP:

- **7z** puts its metadata at the end, but the *pointer* to it lives at offset 12, inside
  the signature header at the start. From the tail alone there is nothing to find — no
  magic, and no way to know where the header begins.
- **RAR** has no tail magic either. Its last records are service blocks — which is where
  quick-open caching lives — but RAR 5 encodes header sizes as variable-length integers, so
  the chain cannot be walked backwards. Quick-open exists to avoid re-reading *file*
  headers scattered through the archive, not to locate the archive.
- **tar and raw compressed streams** have neither a tail structure nor self-validation.
  These stay the genuinely hard case and are the reason the shebang cue matters.

Checked against archives produced here by `7z a`, `rar a`, and `rar a -qo+`; the plain and
quick-open RARs had byte-identical tails.

## Implementation decisions (2026-08-31)

Settled with the maintainer before the first implementation PR. Spec deltas that still
contradict these are revised in the same commit as the matching block, not in a
drive-by rewrite of the whole change.

**Split into four PRs** (see tasks.md §Implementation blocks). Do not land the 64-task
change as one review.

**Tail probe off by default.** JPEG+appended ZIP stays `FormatDetectionError` under
`BALANCED`. A `zipapp` is found by the shebang cue plus ZIP's existing local-header
needle, without the tail. `#273` already ships `DetectionBudget.max_tail_bytes = 0` on
every preset, including `THOROUGH`, with a comment that this change is what raises it.
Enabling the probe means raising `THOROUGH.max_tail_bytes` / `max_seeks` and charging
`tail_bytes` / `seeks` on a workspace tail helper — not a new `ArchiveyConfig` flag, and
not turning it on for `BALANCED` until a seek-cost measurement on the founding backup
workload exists.

**No `OTHER_FORMAT`.** Archivey is not a general file-type detector and will not grow a
JPEG/PNG/PDF magic list to classify prefixes. `PrefixKind` is `NONE` / `EXECUTABLE` /
`SCRIPT` / `UNKNOWN`. A prefix that is not an executable or a shebang is `UNKNOWN`,
whether the offset came from the tail probe, the cued scan, or the exhaustive scan —
those are `detected_by` values, not kinds. `archive-origin-reporting` (#274) listed
`OTHER_FORMAT` and also used `UNKNOWN` for *origin not established*
(`payload_offset is None`); the second meaning stays on the `int | None` axis, not on a
fifth enum member. That change was retired unimplemented on 2026-10-10
(`openspec/changes/archive/2026-10-10-archive-origin-reporting/`).

**Makeself / compressor needles are a later block, and opening them needs backend
work this change's tasks originally omitted.** TAR and the single-file codecs currently
`reject_start_offset`. Detection reporting `TAR_GZ` at offset N without the backends
honouring `start_offset` would be a footgun. That backend work ships in the same PR as
the needles. Uncompressed TAR-behind-stub (`ustar` as a container needle) waits for
`detection-evidence-ledger`'s TAR checksum validator rather than claiming on five
bytes.

**Scan needles are cheap structural validators, not content probes.** Do not invent a
parallel confidence scale here — `detection-evidence-ledger` already ranks signatures
into evidence classes. A shebang-cued compressor needle is allowed only when a hit can
reach `DISCRIMINATING_HEADER` (or stronger) without a decode probe. Gzip (`1f 8b 08` plus
the ledger's header checks) and bzip2 (`BZh` + ASCII `1`–`9` plus the first-block
marker / empty-stream EOS, ledger task 4.5) both qualify; xz/zstd/lz4/lzip do on their
existing headers. zlib / Brotli / LZMA Alone stay probes, never needles. unix-compress
`.Z` stays out (two-byte magic). Makeself's `--bzip2` is a real production shape, so
bzip2 is in the first needle set, not a later maybe.

The same bar applies to ZIP's `PK\x03\x04` scan needle, which Block 1 makes reachable
on every `#!` file. A local-header sanity check (version, reserved flags, method,
name/extra lengths in-bounds) is Block 1; EOCD + central-directory confirmation is
Block 2's tail helper. Shipping the widened cue without the cheap check would report
scripts that mention those four bytes as damaged ZIPs.

**Shebang cue searches only formats with a hit validator.** (#277 F3 A, F10.)
A script is text, so magics appear as literals. The scan filters
`entry.format in validators` rather than hardcoding ZIP — 7z `StartHeaderCRC`
and RAR main-header CRC (tasks 2.3–2.4) join automatically when they register
on `SFX_HIT_VALIDATOR`. Do not key this off `ExecutableCue.WEAK` alone: an
unconfirmed `MZ` / ELF stub is the live 7z/RAR SFX path and keeps the full
needle set. `PrefixKind.SCRIPT` (Block 3) can replace the `#!` byte check.
The rest of Block 3 (`prefix_kind`, `detection_budget`, exhaustive scan) is
independent of the 7z/RAR validators. **2.4 and the CRC / remaining-length half
of 2.3 landed as a slim follow-up after #277**; exact-EOF ranking stays `[~]`
on task 2.3.

**`ArchiveyConfig.detection_budget` is the spend cap.** Threading it needs a freeze
surface: *Explicit configuration object*. `None` selects `BALANCED_BUDGET`.
`format=` plus a non-default `detection_budget` is a silent unused knob (detection
never ran). The types stay in `archivey.detection_cost`; this change does not take
that freeze away from `detection-result-surface`. Exhaustive scan is a
larger `max_scan_bytes`, not a named preset — `THOROUGH.max_scan_bytes` stays at
`SFX_MAX`. Raising it would make every `THOROUGH` caller scan the whole source, which
is a different decision from enabling the ZIP tail.

`open_archive` and `detect_format` do **not** grow a `budget=` keyword. The name on
the config field is `detection_budget` because a bare `budget` could be a
decompression cap, and config already has other budget-shaped numbers. `#273`'s
`detect_format(..., budget=)` is removed when the field lands — keeping both would
be two knobs for one decision. Most callers never set a spend cap; they already skip
the `config=` argument.

A Makeself-aware locator that reads `SKIP` / `COMPRESS` out of the stub and seeks to the
payload, instead of scanning 2 MiB of script for magic, is a better installer-specific
follow-up than widening needles further — parked in `dev-docs/IDEAS.md`.

**`peek_range` is not this change's to invent.** `#273` shipped `PrefixWorkspace.peek_range`
/ `candidate_view`, `ScanNeedle`, and `MagicHit`. Task 2.5a is inherited plumbing.

**Format-owned hooks, ledger-shaped — not a second declaration type.** Q1 still lands
the four PRs on the current first-match detector. The shape of those PRs is chosen so
`detection-evidence-ledger` task 3.3 / group 4 **wraps** what they ship rather than
extracting parse logic out of `detection.py`.

What that means in code:

- **Validators** (ZIP local-header sanity, 7z `StartHeaderCRC`, RAR main-header CRC,
  gzip header identity, bzip2 first-block / EOS) are named functions on the format
  module, taking a candidate-relative view. They return an internal `HitOutcome`
  (`NOT_THIS_FORMAT` / `VALID` / `DAMAGED`), not a boolean. `detection.py` calls them.
  It does not inline the parse.
- **The ZIP tail locator** is a function on the ZIP backend. The detector calls it
  when the budget grants `TAIL`. The tier stays ZIP-named (`detected_by="zip_tail_probe"`,
  skip key `"zip_tail"` as #273 shipped). There is no locator registry — 7z / RAR / tar
  have nothing at the tail (see §Why the tail probe does not generalise), so a
  format-neutral slot would be speculative generality the ledger does not need. The
  format-owned function is what task 3.3 wraps.
- **Cue restriction** for compressor needles is a separate backend-declared
  collection consulted when the cue is `#!`, not a homegrown `cue_mask` bitfield on
  `MagicSignature`. Container needles stay on `SFX_MAGIC` as today.
- **Failure policy stays in the detector.** This change treats `NOT_THIS_FORMAT` and
  `DAMAGED` the same (scan continues). The ledger later treats `DAMAGED` as a
  still-identified candidate (its tasks 4.6 / 4.7) without changing the validator
  signature. A boolean would destroy that distinction at the return and force the
  rewrite 0.6 exists to avoid.

What this change does **not** invent: `DetectionDeclaration`, `EvidenceClass`,
competing-candidate ranking **across formats**, `AmbiguousFormatError`, or the
branch-and-bound `stop_now` scheduler. Those are the ledger (its tasks 3.1, 5.x, 6.x).
A parallel declaration type here would be the rework the four PRs exist to avoid.
An intra-format tie-break inside one validator is not that ranking.

## Open question this change does not settle

**Are there prefixed 7z/RAR files in the wild that are not self-extracting executables?**
Everything found so far says no — `7z.sfx` / `7zCon.sfx` are PE, `rar -sfx` produces PE on
Windows and ELF on Linux, and every non-executable prefix encountered was ZIP or tar. If
that holds, tier 3's cue is sufficient in practice and the exhaustive scan stays a rarity.

The known exception is script-wrapped payloads, which is why the cue gains `#!`. The
unknown is DOS/Windows-era installers and media images, which the maintainer plans to
survey. If that corpus turns up a shape the cue misses, the answer is to widen the cue
again — it is a cost gate, so widening is cheap — not to abandon the tiering.

**This is why there is no ADR yet.** Per `CONTRIBUTING.md`, a decision that still needs an
open-questions section is not an ADR. The load-bearing "why" here — *tier detection cost by
what the format guarantees* — is stable and should become one once this change is applied;
this file is written so that write-up is a summary rather than a re-derivation.

## Sequencing

`sfx-format-detection` (#254) had to land first — this change rewrites the requirement that
one modifies, and depends on its `payload_offset` plumbing through `open_archive` and the
backends. Both are done: #254 merged as `6e71eba` and #258 archived the change into the live
specs at `da427a0`, so the deltas here are written against shipped text.

The archive also promoted a second requirement, *Executable-looking prefixes must not
silently become a wrong stream format*, which this change now modifies too: it enumerates
the cue as `MZ` / `\x7fELF`, and widening that set is the fix for the macOS defect below.
`brotli-probe-framing-gate` (PR #255) also modifies that same executable-prefix
requirement — for its confidence rows and its probe-tightening paragraph, disjoint from the
cue enumeration this change rewrites. Since OpenSpec replaces a MODIFIED requirement whole,
the two are **not** archive-order independent: whichever lands second rebuilds on the
other's text.

**That order is now settled: the framing gate archived first, in #262 (`49d8b4a`), so this
change is the one that rebuilt.** The MODIFIED block below has been rebased onto the
resulting live text, and task 0.3 lists the five things it inherited — the narrowed
threshold prohibition, the three-clause residual paragraph with its figures, three
confidence rows in place of one, the changed attribution line, and the normalised quotes.

The rebuild was done at rebase time rather than at archive time on purpose. Doing it later
would land a wholesale rewrite of a requirement in the same PR as the implementation, where
a reviewer would have to separate "text inherited from a sibling change" from "behaviour
this PR is proposing" — and those read identically in a diff. Doing it now keeps this PR
proposal-only and leaves the implementation PR to contain only code.

Both changes edited **disjoint parts** of that requirement — the framing gate the
probe-tightening paragraph and the confidence rows, this change the cue enumeration and the
Mach-O defect — so the merge lost nothing. That was verified rather than assumed: the
rebuilt block was diffed against live, and every remaining difference is an edit this change
intends to make.

**The far-magic hoist has been taken out of this change and shipped by
`detection-format-gaps`.** That change removes the LZMA Alone zero-dictionary guard, which
is unsafe until far magic precedes the content probes, and it could not wait for this one
now that this is sequenced behind `detection-evidence-ledger`. Two in-flight changes
MODIFYing the same requirement is the archive-order conflict the investigation §14 warns
about, so this change no longer claims the move. **Done here rather than deferred to a
revision**, in the same PR that shipped the hoist:

- `proposal.md`'s far-magic Impact bullet is **dropped** — it claimed the move as this
  change's work.
- Tasks **3.4b, 3.4c, 3.4d and 4.9b are struck** as shipped there, and **3.4a keeps only its
  tier-insertion half**. **3.4e was not struck**: `detection-format-gaps` never touched
  `_warn_on_conflict`, whose message hardcoded "magic bytes indicate …" on every branch that
  calls it, so that defect stayed this change's to fix. (The hoist routes the ISO case to the
  far-magic branch, where the wording is accurate, so it fired less often.) It has since been
  **pulled forward as its own PR**, which the note above says such tasks may be: it depends on
  nothing else here, and leaving a wrong statement about our own evidence in a user-visible
  diagnostic until a large change lands is the wrong trade. The four branches now each name
  their own evidence; the task carries the wording and the two limits.
- **The far-magic step in the `Magic-first detection…` delta stays, deliberately.** An
  earlier draft of this paragraph said it would be dropped. That was wrong: OpenSpec
  replaces a MODIFIED requirement whole — the reason the archiver note in that delta exists
  at all — so a block omitting step 3 would delete far magic from the live spec the moment
  this change archives, reverting a shipped fix. It is retained as **inherited text rather
  than proposed work**, and the archiver note now says so and says to re-check it against
  the then-live wording.

The bootable-ISO reproduction above stays useful: it is the justification recorded in
`detection-format-gaps`'s design for making the move.

**`detection-prefix-workspace` (#273) has landed** (`64d2f6c`). Candidate-relative views,
`DetectionBudget` presets, and `max_tail_bytes = 0` are on `main`. This change no longer
carries a peek primitive. `#273` also added `detect_format(..., budget=)` — that keyword
is young debt: a bare `budget` is ambiguous with decompression, and most callers never
set one. This change puts the spend cap on `ArchiveyConfig.detection_budget` and removes
the keyword (task 3.1). There is no `exhaustive_prefix_scan` bool. Exhaustive scan and
the ZIP tail remain budget numbers (`max_scan_bytes`, `max_tail_bytes` / `max_seeks`).
`open_archive` already takes `config=`; detection reads the field from there.

**What a forced `format=ZIP` reports.** Under the default decided above it does not run
the tail probe to fill `payload_offset`: `UNKNOWN` + `payload_offset is None` stays the
honest forced-ZIP answer unless the caller opted into a budget that grants `TAIL`.

The follow-up that would have reused `PrefixKind` on `ArchiveInfo`,
`archive-origin-reporting`, was retired on 2026-10-10; its archived proposal lists what a
later change would still have to carry.
