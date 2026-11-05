> **Cut on 2026-09-25**, when `detection-evidence-ledger` was decided against. **Block 2
> (ZIP tail probe) is struck**: off under `BALANCED` by decision, no measured real appended
> ZIP, six false positives on a developer tree, and `open_archive(format=ZIP)` already opens
> one; reopen if a user asks. **`prefix_kind` / `PrefixKind` is struck**: `payload_offset > 0`
> already says "prefixed". `ArchiveyConfig.detection_budget` landed (3.1's config half) and
> task 2.3's exact-end tie-break landed. The exhaustive scan is **deferred unless asked**:
> the scan window is still clamped to `SFX_MAX` (`min(SFX_MAX, budget.max_scan_bytes)` in
> `internal/detection.py`), so a larger `max_scan_bytes` does not widen it today. Block 4
> (makeself) is the remaining block with user value, after 0.2.0.

> **Re-derive the `archive-reading` "Explicit configuration object" block before archiving.**
> `one-member-listing-per-reader` archived a version of that block adding
> `read_link_targets` (and the two fields the schema had missed). This change's MODIFIED
> block predates it and would delete those lines on archive.

## Implementation blocks

Four PRs, in order. Details and the decisions behind the split: `design.md`
§Implementation decisions. Every open implementation task is tagged `(Block N)` so an
implementor can pick up one block without re-deriving its scope. Prerequisite notes
use `(context)` / `(every block)` rather than a block number.

1. **Cue + zipapp** — `#!` / Mach-O cue, ZIP local-header needle **plus cheap
   local-header validator**, `.jar` / `.pyz` / `.whl` / `.apk` extensions, cost
   bound for shebang non-archives. A shebang scan searches only formats with a
   hit validator (`entry.format in validators`); 2.3–2.4 self-enable on that
   seam. No `prefix_kind`, no tail probe, no compressor needles.
   Tasks: **2.1, 2.1a, 2.1b, 2.1c, 2.2, 2.2a, 3.4, 4.1, 4.1a, 4.8a, 5.4.**
   **Slim follow-up after #277:** 7z `StartHeaderCRC` and RAR main-header CRC
   on `SFX_HIT_VALIDATOR` (tasks **2.3, 2.4, 4.4**). Not the rest of Block 3.
2. **ZIP tail probe** — budget-gated (`THOROUGH.max_tail_bytes`, not `BALANCED`).
   Workspace tail helper. Both ZIP offset conventions. JPEG+ZIP as an enabled-path
   test. EOCD + central-directory confirmation of a scan hit can fold in here.
   Tasks: **1.1–1.8, 3.5, 4.5, 4.8, 4.9.**
3. **`prefix_kind` + scan validation + exhaustive-via-budget** — public enum
   (`NONE`/`EXECUTABLE`/`SCRIPT`/`UNKNOWN`), 7z/RAR hit validation, conflict-diagnostic
   members, `ArchiveyConfig.detection_budget` (task 3.1 lands in *Explicit configuration
   object*; drop `#273`'s `detect_format(..., budget=)` in the same PR). Exhaustive scan
   is a larger `max_scan_bytes`, not a named preset and not a root re-export.
   Tasks: **2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.3a, 3.3b, 3.4a, 4.3, 4.4, 4.6, 4.7,
   4.9a, 4.11.**
4. **Makeself** — shebang-only compressor needles (gzip + bzip2 + xz/zstd/lz4/lzip),
   inner-TAR at the hit, and TAR/single-file `start_offset` (task 5.7) in the same PR.
   Tasks: **2.5b, 2.7, 2.8, 2.9, 4.2, 5.7.**

Every block runs **4.10** and obeys **0.6** (format-owned validators / ZIP locator /
`HitOutcome`; no second declaration type). **4.12** archives in the finishing PR.
**5.1** is the ADR after apply. **5.2** is maintainer corpus work. **5.8** stays in
`IDEAS.md`. **2.6** and **5.3** are decided-not-to-do (checked below). **4.3** needs
Block 1's cue already landed; it sits here because the 7z/RAR validators are this
block. **0.4** is `(context)` — a prerequisite note, not a block.

## 0. Prerequisite

- [x] 0.0 ~~**Implement this change third, after `probe-completeness-gate` and then `probe-provenance-unconfirmed`.**~~ Both archived. `#273` (`detection-prefix-workspace`) has also landed. Implement in the four blocks in `design.md` §Implementation decisions, not as one 64-task PR. Public API from this change is `prefix_kind` / `PrefixKind` and `ArchiveyConfig.detection_budget` — **not** `ArchiveyConfig.exhaustive_prefix_scan`, and **not** a `budget=` keyword on `open_archive` / `detect_format`. Tail and exhaustive scan are `DetectionBudget` numbers on that config field. `#273`'s `detect_format(..., budget=)` is removed when the field lands.

  **Prerequisite for makeself / TAR self-extracting needles (tasks 2.5a–2.8, 4.2):** ~~the
  candidate-relative range view lands in `detection-prefix-workspace`.~~ **Done in #273.**
  Use `PrefixWorkspace.peek_range` / `candidate_view`; do not invent a second peek
  primitive. **Still required in the same PR as the needles:** TAR and the single-file
  codecs currently `reject_start_offset`, so `detect_format` reporting `TAR_GZ` at N
  without the backends honouring `start_offset` would open wrong. That backend work is
  task 5.7, not optional follow-up.

  **Inherited from `detection-prefix-workspace` Decision 1B:** `PrefixWorkspace.read_tail`
  was deleted because nothing called it and the synced spec falsely claimed a THOROUGH ZIP
  tail. When task 1.1 adds the ZIP tail probe, reintroduce a single seek-toward-end helper
  on the workspace (or an equivalent owned by the declaration), charge `tail_bytes` /
  `seeks`, and only then raise `THOROUGH.max_tail_bytes` / `max_seeks` above zero. The
  intended EOCD+comment window is 65 557 bytes (22 + 65535). **Do not raise `BALANCED`.**
  Also: shebang (`#!`) is not an `executable_cue` today — `zipapp` detection is this
  change's cued-scan work (Block 1), not a shipping `detection-cost` scenario.

  **Two seams worth knowing before you start.** Both are now **closed by
  `detection-format-gaps`**, which shipped the far-magic hoist and the Alone guard
  replacement together. Tasks 3.4b, 3.4c, 3.4d and 4.9b are struck below, and 3.4a keeps
  only its tier-insertion half.

  **The far-magic step stays in the `Magic-first…` delta, and must.** An earlier note here
  said this change would "drop" it; that is wrong and would cause the harm it was meant to
  avoid. OpenSpec replaces a MODIFIED requirement **whole**, so a delta that omits step 3
  deletes far magic from the live spec the moment this change archives — silently reverting
  a shipped fix. The step is retained as **inherited text, not proposed work**; the delta's
  note-for-the-archiver now says so, and this change proposes only steps 4–6 (tail probe,
  cued scan, exhaustive scan). What is genuinely dropped is the far-magic bullet in
  `proposal.md`'s Impact, which claims the move as this change's.

  - ~~**Tasks 3.4c–3.4e can be pulled forward as their own PR.**~~ — 3.4c (the hoist) and
    3.4d (the bootable-ISO red–green, built with `pycdlib` exactly as described) are done
    by `detection-format-gaps`, which is where that live silent wrong answer — a bootable
    ISO detected as `BROTLI` with a fabricated `*.uncompressed` member — was actually
    fixed. **3.4e was not**, and *was* pulled forward as its own PR exactly as this note
    describes — see the task itself. `detection-format-gaps` never touched
    `_warn_on_conflict`, whose message hardcoded "magic bytes indicate …" on all four
    branches that call it. The hoist made the ISO case take the far-magic branch, where
    the wording is accurate, so it fired less often — but the defect was untouched, and
    fixing it needs nothing else from this change.
  - ~~**The LZMA Alone `dict_size != 0` guard must be removed *with* task 3.4c, not
    before.**~~ — done by `detection-format-gaps`, in the same change as the hoist. `src/archivey/internal/streams/codecs.py` `_alone_header_plausible` rejects a zero dictionary size, and the comment says why: it stops a zero-filled ISO system area decoding as an empty Alone stream **before far-magic ISO detection runs**. That guard is a false-negative bug — verified, a stream with that field zeroed still decodes, because the LZMA SDK clamps the value to `LZMA_DIC_MIN` rather than rejecting it — but it is load-bearing until far magic precedes the probes. Remove it in the same commit as 3.4c, never earlier

- [x] 0.1 ~~Land `sfx-format-detection` (#254) first~~ — merged as `6e71eba`. Its `payload_offset` hand-off is on `main`
- [x] 0.2 ~~**Archive `sfx-format-detection` before archiving this change.**~~ — done in #258 (`da427a0`). Both changes MODIFY the same SFX requirement, and this one's delta was written against #254's version rather than the then-shipped text, so the ordering mattered. Verified after the archive: the live requirement's three additions all survive in this delta — the ZIP local-header needle (tier 3), the backend-declared-needles rule (verbatim), and the weak/strong cue grading (in the sibling requirement below). Also restored the live spec's "a prefixed ZIP is reported as `ZIP` with a `payload_offset`, never as a stream codec" guarantee, which the tiering had left implicit
- [x] 0.3 ~~Rebuild the `Executable-looking prefixes must not silently become a wrong stream format` MODIFIED block once `brotli-probe-framing-gate` archives first~~ — **done.** #262 merged as `49d8b4a`, so that requirement's live text changed and this delta was rebuilt on it during the rebase. Both changes MODIFY it and OpenSpec replaces a requirement whole, so the second to archive had to inherit the first's edits; they touched **disjoint parts** — that change the probe-tightening paragraph and the confidence rows, this change the cue enumeration and the Mach-O defect. All four inherited items are now in the block, verified by diffing it against live so that nothing live was dropped:
  - the prohibition narrowed from "SHALL NOT tighten the Brotli probe" to "SHALL NOT tighten it with a **threshold**", plus the sentence explaining that a check derived from the format's own invariant is not a threshold
  - the residual paragraph now carries the 3.5% → ~0.15% (61/39 859) figures and the three-clause registered wording (the listing is wrong, a full read raises, fabricated bytes may already have been produced)
  - the single `Real Brotli stream with non-executable prefix` scenario row became **three**: `.br` extension → `PROBABLE`, compressed-first without a corroborating extension → `PROBABLE`, uncompressed/metadata-first without one → `GUESS`. The fourth variant this delta had been carrying (which dropped confidence entirely) is gone rather than appended
  - the attribution line now reads "settled by measurement in the archived `sfx-format-detection` design", extended to name this change's design too
  - straight quotes, which #262 normalised in the same requirement
  This change still MODIFIES the requirement, and must: it enumerates the cue as `MZ` / `\x7fELF` only, which this change widens to `#!` and a *parsing* Mach-O header, and it is where the macOS silent-wrong-answer defect is registered
- [ ] 0.4 **(context)** The framing gate's implementation has landed (#261, `bee7735`); two things it settled apply here.
  - **The shared helper already exists — use it.** Both changes need "is this source's end reachable, and where is it?" #261 did *not* invent a `_source_length`; it reused **`source_byte_size()`** (`streams/streamtools/binaryio.py`), which dispatches path `stat` → stream `.size` → `try_get_size()` → a cheap `SEEK_END` only when O(1). Build the ZIP tail probe on that same helper (task 1.1) rather than a second dispatch, and note it returns `None` for a non-seekable source — which is exactly the tier-2 skip condition in task 1.5
  - **Task 2.1a's premise has moved again.** Earlier notes here predicted the Mach-O fixture would raise `FormatDetectionError` after the framing gate. Measured on `bee7735`, that holds only for a realistic-entropy stub; a low-entropy one is claimed by **LZMA Alone** instead, with a fabricated member and no unconfirmed signal. 2.1a now carries the measured table — use it rather than re-deriving

- [x] 0.4a ~~`dev-docs/IDEAS.md` overlaps with #262~~ — **resolved by the rebase.** #262 merged the base *Extension-first detection ordering* entry, and rebasing this branch onto it left exactly one copy of that paragraph plus this branch's agreement-short-circuit variant attached beneath it. Verified after the rebase: one occurrence of the base entry, variant intact.
- [x] 0.5 **Read `dev-docs/investigations/archive-format-detection-algorithm.md` before implementing.** In the tree (PR #263). It endorses the acquisition order here and identifies two things this change deliberately does not fix, both marked provisional in the algorithm requirement: a uniform `CERTAIN` across near magic of wildly differing strength, and first-match-wins as the selection rule. Neither blocks the prefixed-archive work. The evidence-ledger model, `AmbiguousFormatError`, and budget presets belong to that redesign; `#273` already shipped the budget object this change now uses instead of `ArchiveyConfig.exhaustive_prefix_scan`.
- [ ] 0.6 **(every block)** Land validators and the ZIP tail locator as **format-owned
      functions** the generic first-match loop *calls*. Do not inline parse in
      `detection.py`. Do not invent `DetectionDeclaration` / `EvidenceClass` /
      competing-candidate ranking **across formats** / `AmbiguousFormatError` here —
      those are `detection-evidence-ledger` tasks 3.1, 5.x, 6.x. An intra-format
      tie-break inside one validator (task 2.3) is not that ranking.

      Validators return an internal `HitOutcome` (`NOT_THIS_FORMAT` / `VALID` /
      `DAMAGED`), not a boolean. This change treats `NOT_THIS_FORMAT` and `DAMAGED`
      the same (skip and continue). The ledger later changes only the policy that
      reads `DAMAGED` (its tasks 4.6 / 4.7), never the signature.

      The ZIP tail probe stays ZIP-named (`detected_by="zip_tail_probe"`; skip key
      `"zip_tail"`). The ZIP backend owns the locator; there is no locator registry.

      Compressor needles are a backend-declared shebang-only collection, not a
      `cue_mask` on `MagicSignature`. Details: `design.md` §Implementation decisions,
      last paragraph.

## 1. Tail probe for self-locating containers

- [x] 1.0 ~~**Settle whether the tail probe is on by default**~~ — **off.** JPEG+ZIP is a
  `THOROUGH` (once `max_tail_bytes` is raised) case, not a `BALANCED` one. `zipapp` is
  found by the shebang cue. Revisit `BALANCED` only after a seek-cost measurement on the
  founding backup workload; byte-count arguments do not reopen this.
- [ ] 1.1 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Add a ZIP tail probe, running after magic-at-0 and before the
      forward scan, only when the source is seekable **and** the budget grants `TAIL`.
      The locator lives on the ZIP backend; `detect_format` calls it. Do not inline
      EOCD search in `detection.py`. Keep the skip key `"zip_tail"` that #273 shipped
      and report `detected_by="zip_tail_probe"`.
- [ ] 1.2 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Bound the EOCD search at 65535 + 22 bytes and derive the constant in code from the `uint16` comment-length field, with a comment saying why it is not tunable
- [ ] 1.3 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Report `payload_offset` as **the absolute position of the earliest local file header** — `min(header_offset) + adjustment` over the central directory — when a prefix is present. Not the EOCD adjustment: ZIP has two write conventions and they store different numbers. Measured, a stdlib `zipapp` writes its offsets from byte 0 of the file (adjustment **0**, first local header at 23) while a concatenated ZIP writes them from the payload (adjustment **33**, first local header at 33). The earliest-local-header rule gives the prefix length under both; the adjustment rule would report the `zipapp` — this change's headline case — as unprefixed, and would make `prefix_kind` unreachable for it
- [ ] 1.3a ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Red–green **both** conventions, not just one: a `zipapp` fixture and a `cat`-style concatenation of the same entries must produce the same `(payload_offset, prefix_kind)` shape. Note that stdlib `zipfile` opens both whether handed the whole file or a view at the prefix — a five-member `zipapp` sliced at its first local header yields a *negative* adjustment and still reads every member — so a test that only asserts "it opens" will pass under either definition and pin nothing. Assert the reported offset
- [ ] 1.6 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Validate a tail-probe candidate before reporting it, per the `format-zip` validation requirement: record fits, `comment_length` exactly consumes the tail, derived CD position non-negative and in range, first CD entry is `PK\x01\x02`, entry count consistent, earliest adjusted `header_offset` lands on `PK\x03\x04`. Computing `payload_offset` and validating are the same read
- [ ] 1.7 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Continue the backward search past a candidate that fails validation instead of concluding the source is not a ZIP — member data can contain `PK\x05\x06`
- [ ] 1.8 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Follow a ZIP64 locator (`PK\x06\x07`) to the ZIP64 EOCD (`PK\x06\x06`) and apply the equivalent wide-field checks, rather than rejecting the archive for failing the 32-bit ones
- [ ] 1.4 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Confirm the ZIP backend needs no change — verified on `main` that a prefixed ZIP already opens with `format=ZIP`; the work is detection-side only
- [ ] 1.5 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Non-seekable sources skip the probe and fall through; no attempt to buffer the whole stream to fake a seek

## 2. Widen the cue, validate the scan

- [x] 2.1 **(Block 1)** Extend the prefix cue from `MZ`/ELF to also accept a `#!` shebang and a **Mach-O header that parses**; keep the same `SFX_MAX` window and peek schedule. Mach-O is asymmetric on purpose: `MZ` / ELF / `#!` raise a **weak** cue on their leading bytes, but Mach-O magic raises **no cue at all** until its header parses (thin `cputype`/`filetype`, or a fat arch table). `ca fe ba be` is shared with the Java class-file magic, and grading it weak would not spare a `.class` file — a weak cue still triggers the forward scan, so only `ExecutableCue.NONE` does. Nothing is lost: a real Mach-O SFX stub is a real executable and parses by construction. **#277 F3 (maintainer: A) / F10:** a `#!` scan searches only formats that have an `SFX_HIT_VALIDATOR` (`entry.format in validators`), so a script that mentions the 7z/RAR magics stays `FormatDetectionError` rather than a wrong-format `CorruptionError`. Do not key this off `ExecutableCue.WEAK` — unconfirmed `MZ` / ELF stubs keep the full needle set. Tasks 2.3–2.4 self-enable on that seam (slim follow-up after Block 1, not delayed for the rest of Block 3).
- [x] 2.1c **(Block 1)** Red–green the collision directly: a minimal `.class` file starting `ca fe ba be` must raise no cue, must not enter the `SFX_MAX` scan, and must keep today's content-probe behaviour; a fat Mach-O stub with a real 7z inside must still be found
- [x] 2.1a **(Block 1)** Red–green the Mach-O case specifically. **Re-measured on `main` at `bee7735`; the premise has moved twice, so take these numbers rather than the ones in older notes.** A thin 64-bit stub (`cf fa ed fe`) plus an appended 7z now behaves *differently depending on the stub's entropy*, because #261's framing gate rejects the Brotli claim but nothing replaced it:

  | stub | `detect_format` today | `open_archive` today | after this change |
  | --- | --- | --- | --- |
  | Mach-O, realistic entropy | `FormatDetectionError` | — | `SEVEN_Z`, real members |
  | Mach-O, low-entropy / zero-filled | `LZMA_ALONE` / `PROBABLE` | one fabricated `*.uncompressed` member; read raises `CorruptionError` with `format_unconfirmed=False` | `SEVEN_Z`, real members |

  So **both** need covering, and the second is still the silent-wrong-answer shape — the claimant moved from Brotli to LZMA Alone, which reports `PROBABLE` unconditionally and therefore gets no unconfirmed signal at all (that half is `probe-provenance-unconfirmed`'s subject, not this change's). Assert the real members, not merely that no error is raised. Watch the two traps: `0xcafebabe` is also the Java class-file magic (a weak match on it would gate probes on every `.class` file — `sfx-format-detection`'s `design.md` flags this too), and a *fat* stub fails loudly while a *thin* one can fail silently, so cover both
- [x] 2.1b **(Block 1)** Revisit the `e_lfanew` bound in `_is_pe` (`src/archivey/internal/sfx.py`) while the cue is already being rewritten — **scoped to SFX stubs**, per the maintainer ruling in results doc §7.3. 12 887 Windows PEs give a maximum of 11 648, from `tcblaunch.exe`, which is not and never will be a self-extracting archive; the general-PE counterexamples (the EFI kernel image at `e_lfanew` 130, unaligned; `.winmd` metadata assemblies) are bounds on the whole PE population, not on the stub population. If a bound is wanted for read-size reasons, exceeding it SHALL mean "cannot confirm cheaply" — i.e. fall back to a weak cue — never "not an executable". Do not require 4-byte alignment: the EFI image is valid and unaligned. Inherited from `brotli-probe-framing-gate` task 5.4
- [x] 2.2 **(Block 1)** Comment the cue as a **cost gate, not a correctness gate**, so the next reader does not re-derive it as a false-positive defence (a reviewer already did)
- [x] 2.2a **(Block 1)** Validate a ZIP scan hit with a cheap local-header sanity check
      before reporting it: `version_needed` within a sane maximum, reserved GP-flag bits
      clear, `compression_method` in the known set, `filename_length` /
      `extra_field_length` in-bounds against the remaining source. Four bytes of
      `PK\x03\x04` in a stub are not a ZIP. The check is a named function on the ZIP
      backend (candidate-relative view in, `HitOutcome` out); the scan calls it. A
      decoy of four `PK\x03\x04` bytes is `NOT_THIS_FORMAT`. Do **not** require an
      EOCD seek here — that is Block 2. Red–green alongside 4.1a.
- [x] 2.3 **Done 2026-09-25:** the exact-end tie-break landed as `HitOutcome.VALID_SHORT` — a hit whose declared end falls short of the known end of source is kept only as a fallback to a later `VALID` hit. Original text: **(Block 3, or a slim follow-up after Block 1)** Validate a 7z hit: `StartHeaderCRC` over the 20-byte StartHeader,
      and `offset + 32 + NextHeaderOffset + NextHeaderSize <= source length`, preferring
      an exact end match when several candidates validate — an intra-format tie-break
      inside this validator, not the cross-format ranking 0.6 defers. Named function on
      the 7z backend returning `HitOutcome`; the scan calls it. Failed CRC with a
      plausible header is `DAMAGED`; this change still skips it (scan continues). Ledger
      task 4.7 is the later policy that reports `SEVEN_Z` from that outcome.
      **Partially landed as the slim follow-up after #277 (F12).** CRC identity, the
      remaining-length overrun (`DAMAGED`), and `NextHeaderSize == 0` behind a stub
      (`NOT_THIS_FORMAT`) are in. The declared-end check compares against the known
      source length (`remaining` from the candidate origin), not the peek window /
      `scan_limit` / `SFX_MAX`. Exact-EOF ranking among several CRC-valid hits is
      **not**: first `VALID` still wins. Trailing bytes after a CRC-valid header stay
      `VALID` (task 4.4). Pin: `test_inexact_7z_decoy_loses_to_a_later_exact_payload`
      (`xfail(strict=True)` on the real payload winning). Recorded in
      `dev-docs/topics/prefixed-archives.md`. `[~]` so this change cannot archive until the
      tie-break lands (`scripts/checks/check_openspec_archived.py`).
- [x] 2.4 **(Block 3, or a slim follow-up after Block 1)** Validate a RAR 5 hit via the main header's CRC32; RAR 4 via a
      parseable main header. Named function on the RAR backend, same `HitOutcome` split
      as 2.3.
      **Landed as the slim follow-up after #277.** RAR 5 encrypted-headers archives
      start with a plaintext ENCRYPTION block; that CRC is the identity check.
- [x] 2.5 **(Block 3)** Continue scanning past a candidate that fails validation rather than giving up
      — detector path already did this (`iter_magic_in_prefix` + validators). Parser
      path (`scan_for_magic` + `HitValidator`) landed in #375: earliest VALID, else
      earliest identified (maintainer ruling on that PR, option A). The detector path
      applies the same `MAX_VALIDATED_CANDIDATES` cap, counted per format, only for the
      formats whose parser runs that capped scan (`ReadBackend.SFX_PARSER_SCANS`: RAR
      and 7z); a capped format's needles are no longer searched. ZIP candidates stay
      uncapped on purpose, so what is left of the superlinear cost threat-model O11
      cites is one ZIP validation per decoy (`dev-docs/topics/prefixed-archives.md` §7).
- [x] 2.5a ~~**Prerequisite for 2.6–2.8: a bounded candidate-relative read.**~~ — shipped by `#273` as `PrefixWorkspace.peek_range` / `candidate_view` and `ScanNeedle` / `MagicHit.candidate_origin`. Nothing to invent here.
- [ ] 2.5b **(Block 4)** Report `payload_offset` as the **candidate origin**, not the needle hit. A TAR hit reported at `H` rather than `H - 257` is wrong by 257 bytes and hands the backend a misaligned source; add a red–green for exactly that off-by-257. **Waits on 2.6**, which waits on the ledger.
- [x] 2.6 ~~**Deferred to `detection-evidence-ledger`.** Do not add TAR's `ustar` as a container needle here — five bytes with no checksum is a false-positive risk inside a PE/ELF stub, and that change already specifies the checksum validator that would make the needle safe.~~
- [ ] 2.7 **(Block 4)** Add **compressor needles under a `#!` cue only**, so the makeself /
      NVIDIA / Anaconda `.run` family resolves. Needle set: codecs whose hit can be
      confirmed by a cheap structural validator without a content probe (gzip `1f 8b 08`
      + header checks; bzip2 `BZh` + `1`–`9` + first-block / EOS marker; xz / zstd / lz4
      / lzip on their existing headers). Not zlib / Brotli / LZMA Alone (probes). Not
      `.Z`. Makeself `--bzip2` is in the first set, not a maybe. Needles and validators
      are backend-declared (a shebang-only collection the scan consults when the cue is
      `#!`); do not hard-code gzip in `detection.py`. Same PR as task 5.7. The gzip /
      bzip2 parse is what ledger tasks 4.1 / 4.5 wrap if this block lands first.
- [ ] 2.8 **(Block 4)** Resolve a compressor hit through the **existing inner-TAR probe** at the hit offset so a script-wrapped gzipped tar reports `TAR_GZ`, not `GZIP`. Identity is the structural validator; the decode is the TAR-vs-bare-stream resolution.
- [ ] 2.9 **(Block 4)** Update the policy comment in `registry.sfx_magic_entries()`
      (`src/archivey/internal/registry.py`), which currently reads "the stream codecs
      never do, since a stub plus a bare compressed stream is not a thing anyone
      produces". That premise is false for shebang stubs and true for executable ones;
      the comment should say so and name the cue restriction, rather than being quietly
      contradicted by the compressor-needle collection this block adds. Block 1 does
      not add stream-codec needles, so the existing comment stays true until this task.

## 3. Exhaustive scan and prefix reporting

- [ ] 3.1 **(Block 3)** **Config half done 2026-09-25:** `ArchiveyConfig.detection_budget` landed and `detect_format(..., budget=)` was removed. The field is a plain `DetectionBudget` defaulting to `BALANCED_BUDGET`, like `extraction_limits` beside it, so the `None` clause below is struck. The exhaustive half is deferred unless asked; the window is still clamped to `SFX_MAX`. Original text: Wire the opt-in exhaustive scan as a **`DetectionBudget` with `max_scan_bytes` past `SFX_MAX`**, defaulting to off (`BALANCED` stays at 2 MiB). Reuse the same validation. Land `ArchiveyConfig.detection_budget` on *Explicit configuration object* (the freeze surface). ~~`None` → `BALANCED_BUDGET`.~~ **Remove** `#273`'s `detect_format(..., budget=)` in this PR — do not keep both channels. Do **not** add `budget=` / `detection_budget=` keywords on `open_archive` or `detect_format`; do **not** add `ArchiveyConfig.exhaustive_prefix_scan`. `format=` plus a non-default `detection_budget` is a silent unused config knob. Restore `zip_unflagged_fallback_encoding` on the spec dataclass (already in `config.py`; live spec omitted it). Do **not** re-export the budget types; do **not** raise `THOROUGH.max_scan_bytes`. Migrate tests that pass `budget=` to `config=ArchiveyConfig(detection_budget=…)`.
- [ ] 3.2 **(Block 3)** Never enable it implicitly — no retry-after-failure, no extension-driven escalation
- [ ] 3.3 ~~**(Block 3)**~~ **Struck 2026-09-25** (`prefix_kind` dropped; `payload_offset > 0` already says prefixed). Add `prefix_kind` to `FormatInfo` with a `PrefixKind` enum (`NONE` / `EXECUTABLE` / `SCRIPT` / `UNKNOWN`), **always present, defaulting to `NONE`**. No `OTHER_FORMAT` — archivey will not maintain a non-archive file-type list; a JPEG prefix is `UNKNOWN`. `NONE` must hold exactly when `payload_offset == 0`. How the offset was found is `detected_by`, not a kind. `archive-origin-reporting` (#274), which would have reused this enum, was retired unimplemented on 2026-10-10; origin-not-established stays `payload_offset is None`.
- [ ] 3.3a **(Block 3)** Set `detected_by` to the tier that matched: `"zip_tail_probe"`, `"sfx_scan"`, `"exhaustive_scan"` alongside the existing `"magic"` / `"content_probe"` / `"extension"`
- [ ] 3.3b **(Block 3)** **Grow `_ConflictEvidence` with the new tiers, in the same commit as 3.3a.** `_warn_on_conflict` (`src/archivey/internal/detection.py`) names its evidence in the conflict diagnostic, and its `SFX_SCAN` member says *"archive magic behind an executable stub indicates"* — accurate only while that branch runs under an `MZ`/ELF cue alone. A shebang or Mach-O cue, a `zipapp` answered by the tail probe, or a ZIP appended to a JPEG all reach a conflict through wording that names an executable stub that is not there, which is the same class of overclaim task 3.4e removed for the content probes. Add members (script stub, tail probe, exhaustive scan) rather than widening `SFX_SCAN`'s phrase to something vague enough to cover them, and extend `tests/test_detection.py`'s per-branch message pins — `_assert_names_only` reads the enum, so a new member is excluded from the other branches' messages automatically, but each new branch still needs its own positive pin. Raised as F3 on the PR that landed 3.4e
- [ ] 3.4a **(Block 3)** Insert the new tiers into `_detect_format_body`. Target order is near magic → far magic → tail probe → cued scan → exhaustive scan → content probes → extension. The tail probe and exhaustive scan are what this task adds; **the far-magic hoist is already shipped** by `detection-format-gaps`, so insert the tiers around it rather than moving it (~~the far-magic move is a behaviour fix (3.4c)~~ — done). The extension fallback stays **last** — moving it earlier would downgrade a real `.br` stream from a probe result to an extension guess and change what `format_unconfirmed` reports. Each step falls through on a miss; a tail-probe miss must not skip the scan
- [x] 3.4b ~~**The live spec's algorithm requirement is wrong today**~~ — **fixed by `detection-format-gaps`**, which rewrote that requirement with far magic present and the extension fallback last. Nothing to do; the warning below is kept only so the old text is not "restored" by someone working from a stale copy. Original note: **the live spec's algorithm requirement is wrong today** and this change's MODIFIED block corrects it: it lists the extension fallback *before* the content probes and omits far magic entirely, while `detection.py` and the live *unconfirmed format choice* requirement both describe the shipped order. Nothing to implement — but do not "fix" the code to match the old text
- [x] 3.4c ~~**Move far magic ahead of the content probes, and gate it on size.**~~ — **done by `detection-format-gaps`**, size gate included; a source below the window takes no extended peek. Retained for its rationale: A content probe currently outranks exact magic at a fixed offset, which misdetects bootable ISOs: ISO 9660 reserves its first 32 KiB as a bootloader system area, so a hybrid image carries executable code exactly where detection peeks, and the Brotli probe accepts that class of data. Skip the extended peek when the source size is known to be below the window — `source_byte_size()` is already computed at the probe step for the framing gate, so hoisting it is free, and no ISO is smaller than 32 774 bytes. Keep the existing "too short simply falls through, never rejected" behaviour
- [x] 3.4d ~~Red–green the ISO case~~ — **done by `detection-format-gaps`**, built exactly as prescribed here (a real `pycdlib` ISO with only bytes 0–32767 overwritten by content the Brotli probe accepts, plus a zeroed-system-area pin). Original instruction: build the fixture the way the defect actually arises rather than by hand: create a real ISO with `pycdlib` (already a dependency), then overwrite **only** bytes 0–32767 with content the Brotli probe accepts, leaving the filesystem byte-identical. Measured on `main` at `dcb69d5`, the two shapes diverge:

  | fixture | `detect_format` today | `open_archive` today | after this change |
  | --- | --- | --- | --- |
  | ISO, zeroed system area | `ISO` / `CERTAIN` / `magic` | lists `README.`, reads correctly | unchanged |
  | ISO, boot-code-shaped system area | `BROTLI` / `GUESS` / `content_probe` | one fabricated `*.uncompressed`; read raises `CorruptionError` | `ISO` / `CERTAIN`, real members |

  Assert the members, not merely that no error is raised, and keep the zeroed row so a future reorder cannot regress the easy case while fixing the hard one
- [x] 3.4e ~~Fix the conflict diagnostic's wording in `_warn_on_conflict`~~ — **done, pulled forward as its own PR** (nothing else in this change is a prerequisite). `_warn_on_conflict` now takes a `_ConflictEvidence` naming the branch that won, and all four call sites pass their own: near magic and far magic *"magic bytes indicate"*, the SFX scan *"archive magic behind an executable stub indicates"*, the content probe *"content inspection indicates"*. Four tests pin one message per branch, so the wording cannot collapse back to a single hardcoded claim. Two deliberate limits: the evidence is **not** added to `FormatConflictContext`, because `detection-result-surface` renames two `detected_by` values and would have to respell the field immediately; and the tail now reads *"using that result over the extension"* rather than naming the winner twice. Review F3 on that PR turned the first limit into task **3.3b** above, and F1 corrected the reason given for it: an earlier draft said a caller wanting the evidence as data could read `detected_by` off the same `FormatInfo`, which is true only for `detect_format`. On the `open_archive` path — where a retained conflict diagnostic matters most — `FormatInfo` is dropped, `_format_provenance` collapses magic, far magic, the SFX scan and the probes to `chosen_by="content"` and is private anyway, and the reader exposes no evidence field at all (verified against the reader's public surface). So the message text is the *only* evidence channel there, which makes deferring the typed field a real cost rather than a free one, and makes the wording load-bearing until `detection-result-surface` grows the field. Original text: The message hardcodes *"but magic bytes indicate {X}; using the magic-byte result"*, yet the function is also called from the content-probe branch — so on the ISO fixture above it reports "magic bytes indicate BROTLI" while actually discarding a correct exact-magic answer for a probe guess. Name the evidence that actually won. The live *Conflict resolution* requirement already says "magic/content result", so this is the code catching up to the spec, not a contract change
- [ ] 3.5 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Short-circuit the cued scan when the tail probe already hit — only reachable
  under a budget that grants `TAIL`. Under `BALANCED` a seekable `zipapp` is answered by
  the shebang cue (Block 1) and never reaches the tail.
- [x] 3.4 **(Block 1)** Register the missing ZIP-family extensions (`.jar`, `.pyz`, `.whl`, `.apk`) — today not even the extension fallback rescues these

## 4. Verify

- [x] 4.1 **(Block 1)** Red–green: `zipapp` output and a Spring Boot-style `#!/bin/sh` + ZIP detect as `ZIP` and list their members under `BALANCED` (cued scan, no tail). JPEG + appended ZIP is a **tail-enabled** case (`THOROUGH` once `max_tail_bytes` is raised), not a default-budget assertion — it currently raises `FormatDetectionError` and that stays the `BALANCED` answer. Assert the members, not just the absence of an error.
- [x] 4.1a **(Block 1)** Red–green the ZIP scan validator: a `#!` stub whose text contains `PK\x03\x04` but whose following bytes fail local-header sanity SHALL raise `FormatDetectionError`, not report `ZIP` / `CorruptionError`. Pin the ELF-cued form of the same bytes too — today that path already claims a damaged ZIP, which is the live defect Block 1 must not widen.
- [ ] 4.2 **(Block 4)** Red–green: a makeself-style `#!/bin/sh` + tar.gz detects as `TAR_GZ` and opens its members. Cover the negatives that define the scoping too: an `MZ` stub containing the same gzip bytes yields no scan claim, a `#!` stub whose own text contains `1f 8b 08` is rejected by the **structural header check**, and a `#!` + non-tar gzip stream reports `GZIP` (inner-TAR is resolution, not identity)
- [ ] 4.3 **(Block 3)** SFX matrix across stub kinds: PE, ELF (a real `rar a -sfx`), Mach-O, and shebang, for 7z and RAR. Needs Block 1's cue already landed.
- [x] 4.4 **(Block 3)** Scan validation: the 6 magic bytes embedded in unrelated data are not claimed; a 7z whose declared end overruns the source is not claimed; a 7z with trailing bytes appended still is. **Landed with the 2.3–2.4 slim follow-up after #277.**
- [ ] 4.5 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Non-seekable prefixed ZIP falls through rather than crashing or buffering the stream
- [ ] 4.6 **(Block 3)** Exhaustive scan: off by default leaves a beyond-window archive undetected and unread past the window; on, it finds it with `prefix_kind == UNKNOWN`
- [ ] 4.7 ~~**(Block 3)**~~ **Struck 2026-09-25** (`prefix_kind` dropped; `payload_offset > 0` already says prefixed). `prefix_kind` values for each fixture in 4.1–4.3
- [ ] 4.8 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Cost regression: opening an ordinary non-archive file under `BALANCED` must not seek to the tail and must not read more than the detection prefix plus, if a cue fired, `min(size, SFX_MAX)`. The tail probe's 64 KiB is **not** part of the default bound.
- [x] 4.8a **(Block 1)** Cost regression for the **newly enrolled** population, which 4.8 does not cover: a `#!` non-archive source (an ordinary shell or Python script) must read no more than `min(size, SFX_MAX)`. Widening the cue adds 742 files per 2 868 already paying on a `/usr` tree — about 26% more files entering the scan — so the bound belongs in a test rather than only in `design.md`. Pair it with a seekable `#!` + ZIP asserting the **cued scan** answered it under `BALANCED` (task 2.1), and a separate assertion that the tail probe did not run.
- [ ] 4.9 ~~**(Block 2)**~~ **Struck 2026-09-25** (tail probe parked; reopen if a user asks). Tail-probe validation: planted `PK\x05\x06` with a CD offset past the end, with an overrunning `comment_length`, and pointing at non-`PK\x01\x02` bytes are each rejected; a decoy `PK\x05\x06` inside member data does not stop the search finding the real record; an empty ZIP (`total_entries == 0`) is accepted with `payload_offset` at the EOCD-derived base (the one documented exception to the earliest-local-header rule); a prefixed ZIP64 archive is followed via its locator
- [ ] 4.9a **(Block 3)** Ordering regressions, which the tier work is most likely to break: an `x.br` holding a real Brotli stream is detected by the **content probe** at its proper confidence rather than as an extension `GUESS`; an extensionless Brotli stream is still detected; a source whose tail probe misses still reaches the cued scan; and a **real Brotli stream larger than 32 KiB with no extension** is still detected after the hoisted far-magic peek misses — the reorder must cost one bounded peek, never a detection
- [x] 4.9b ~~Cost regression for the far-magic hoist~~ — **covered by `detection-format-gaps`** (`test_small_source_takes_no_extended_peek`): a source known to be smaller than the extended ISO window triggers no extended peek, so ordinary small files pay nothing. That change also measured the cost the hoist *does* add on a large content-probe success (~3% of `detect_format`), which its design §Risks records
- [ ] 4.10 **(every block)** `./scripts/test.sh --all-configs` and `openspec validate --strict prefixed-archive-detection`
- [ ] 4.11 **(Block 3)** Update `docs/formats.md` detection prose for the tiers, `prefix_kind`, and the budget-gated tail / exhaustive scan — the proposal's Impact claims this file, so it needs a checkbox rather than an implicit promise. Document the spend cap as `ArchiveyConfig.detection_budget` (a larger `max_scan_bytes` for exhaustive scan), not as a `budget=` keyword and not as a public import of `DetectionBudget`; the root-surface freeze belongs to `detection-result-surface`.
- [ ] 4.12 **(finishing PR)** Archive this change in the finishing PR

## 5. Follow-ups

- [ ] 5.1 **(finishing)** Write the ADR once this is applied: *detection cost is tiered by what the format guarantees* — stable, load-bearing, and currently blocked from ADR status only by the open question in `design.md`
- [ ] 5.2 **(maintainer)** **Build the SFX corpus** (maintainer legwork, absorbed from `brotli-probe-framing-gate` task 5.5), then settle the design's open question with it. Generate stubs with current *and* old tools — WinRAR, 7-Zip, installer-era self-extractors — and pull from old installation archives and media images. Two things ride on it: (a) are there prefixed 7z/RAR that are **not** self-extracting executables? If so, widen the cue rather than abandon the tiering. (b) What does a **16-bit NE/LE self-extractor** actually look like? Until such a corpus exists, the executable-header conclusions in results doc §3.1/§7.2 are bounds on the *general PE population*, not on the stub population — which is exactly the distinction the §7.3 scope ruling turns on, and what task 2.1b's `e_lfanew` decision would rest on
- [x] 5.3 ~~Dropped with `OTHER_FORMAT`. A caller who wants to notice polyglots inspects `prefix_kind == UNKNOWN` together with `payload_offset > 0`; a dedicated diagnostic is still the follow-up, tracked internally, if sweeping a directory without reading every `FormatInfo` turns out to matter.~~
- [x] 5.4 **(Block 1)** Fix the stale cost comment in `sfx.py` (from #254): it says the geometric peeks cap the worst case "at a little over 2× the window". Counted, a full miss scans 64 + 256 + 1024 + 2048 KiB = 3392 KiB for a 2048 KiB window — **1.66×**. Small, but it is the number the tiering argument rests on, so it should be right where an implementer will read it
- [x] 5.5 ~~Make the forward scan resume instead of re-requesting the prefix.~~ — **done by `#273`'s monotonically growing workspace.** I/O is already 1×; do not rebuild a per-source-kind resume path here.
- [x] 5.6 ~~Check the boxes in `brotli-probe-framing-gate` when this lands~~ — **done in #262, now merged (`49d8b4a`).** Its tasks **5.3** (the executable cue is blind on macOS) and **5.4** (the `e_lfanew` bound) are checked in the archive and redirected here, to tasks 2.1/2.1a and 2.1b, with their original text retained. The work is recorded once, in the archive, pointing this way; nothing needs ticking there when this lands.
- [ ] 5.7 **(Block 4)** **TAR / gzip / single-file `start_offset`**, same PR as 2.7/2.8/4.2. Those backends currently `reject_start_offset`. Makeself cannot open until they honour detection's `payload_offset` the way ZIP/RAR/7z already do (slice the source). Detection-only makeself is a footgun; do not ship 2.7 without this.
- [x] 5.8 ~~Makeself-aware locator (read `SKIP` / `COMPRESS` from the stub, seek to the payload) — **not this change.**~~ Parked in `dev-docs/IDEAS.md`; a better installer-specific follow-up than widening needles or scanning 2 MiB of script.
