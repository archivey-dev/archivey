> **Archive note:** Archived unimplemented on 2026-11-05 (maintainer decision). The makeself `.run` installer case stays tracked internally.

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

## Why

An archive does not have to start at byte zero, and archivey currently finds only one
shape of that: an executable stub in front of RAR or 7z. The shipped `format-detection`
requirement says so literally — *"If leading bytes look like executable (`MZ` / ELF)"*.

That misses formats that are neither rare nor exotic. Measured on `main`:

| file | `detect_format` | `open_archive(format=ZIP)` | stdlib `zipfile` |
| --- | --- | --- | --- |
| `zipapp` output (`#!/usr/bin/env python3` + ZIP) | `FormatDetectionError` | **opens, all members** | opens |
| Spring Boot executable JAR (`#!/bin/sh` + ZIP) | `FormatDetectionError` | **opens** | opens |
| JPEG with an appended ZIP | `FormatDetectionError` under `BALANCED`; opens with `format=ZIP` | opens |
| makeself `.run` (`#!/bin/sh` + tar.gz) | `FormatDetectionError` | fails — needs an offset | n/a |

The ZIP rows are the embarrassing ones: **the backend already reads these files**, and
`zipapp` is in the Python standard library. Only detection refuses, and archivey is
currently worse than `zipfile` on a `.pyz`. The cause is that the executable cue never
fires on a `#!` prefix.

The gap is not "we forgot to scan harder". Detection is deliberately cheap, and the
existing cue exists to avoid reading up to `SFX_MAX` (2 MiB) from every file someone opens.
The fix is to notice that **different formats make that cost wildly different**, and to
tier detection accordingly instead of applying one rule to all of them.

## What Changes

- **A ZIP tail probe, off under `BALANCED`.** ZIP records its central directory from the end
  and its offsets are relative to the ZIP's own start, so a prefixed ZIP needs no scan and
  no offset — only the willingness to look. The search is bounded *by the format*: the EOCD
  comment length is a `uint16`, so 65535 + 22 bytes is a hard ceiling, not a tuning choice.
  **Off under `BALANCED`** — the format bounds the locator, not the extra seek per file on a
  backup sweep. `zipapp` is found by the shebang cue without it; JPEG+appended ZIP is a
  `THOROUGH` case.
- **Keep the forward scan gated, but widen the gate** from "leading bytes look executable"
  to "leading bytes look like a *prefix*": `MZ`, ELF, **Mach-O**, or a `#!` shebang. Same
  window and the same per-file bound, but a **larger population** — counted on a `/usr`
  tree, 742 more files enter the scan against 2 868 already there, about 26% more. Each is
  still bounded by `min(size, SFX_MAX)`, and since the newly enrolled files are mostly small
  scripts (median 2 959 B, one file in 734 reaching the window at all) the whole tree costs
  10.3 MiB more. Not free, and not the 2 MiB-per-script the bound alone suggests;
  `design.md` carries both halves.

  What it buys is the `.run` installer family (makeself, NVIDIA, Anaconda) — the one case
  the ZIP tail probe cannot reach. Those wrap a *compressed stream*, not a container, so
  they need a compressor needle; that needle is searched **under the `#!` cue only**, since
  a stub plus a bare compressed stream is a real shape for script stubs and not for
  executable ones.

  **The Mach-O half is a live defect, not a tidy-up.** `sfx-format-detection` names `MZ`
  and ELF, so a macOS SFX stub matches no cue — and `cf fa ed fe` is *structurally
  guaranteed* to parse as a Brotli uncompressed meta-block header. Measured against that
  change's own HEAD (`34db1b0`): a PE stub and an ELF stub both open the real 7z members,
  while a Mach-O stub returns `BROTLI` with one fabricated `.uncompressed` member. The
  silent-wrong-answer defect #254 exists to close is therefore intact on macOS after it
  lands. That change records the gap and deliberately defers the fix, because widening the
  cue set is a spec change; **this is that spec change**.
- **Validate a scan hit instead of trusting the magic.** A 7z signature self-checks from
  its own 32 bytes (`StartHeaderCRC` over the 20-byte StartHeader, plus
  `offset + 32 + NextHeaderOffset + NextHeaderSize` landing at EOF); RAR5's 8-byte marker
  is followed by a CRC-checked main header. This does not change *when* we scan — cost
  still decides that — but it means a hit is essentially never wrong, so it can be reported
  at high confidence.
- **Add an opt-in exhaustive scan**, off by default, for callers who know they are holding
  a firmware image or a disk image.
- **Report what is in front of the payload**, so a caller can tell a self-extracting archive
  from an archive that merely happens to be embedded in something else.
- **Register the ZIP-family extensions that are missing** (`.jar`, `.pyz`, `.whl`, `.apk`),
  since today not even the extension fallback rescues these files.

## Capabilities

### New Capabilities

### Modified Capabilities

- `format-detection` — the SFX requirement is replaced by a tiered "the archive may start
  after byte zero" rule: a **budget-gated** tail probe for self-locating containers (off
  under `BALANCED`), a prefix-cued forward scan for the rest, an opt-in exhaustive scan
  via a larger `max_scan_bytes`, and a `prefix_kind` on `FormatInfo`.
- `format-zip` — a leading prefix is explicitly supported rather than incidental, and the
  EOCD search bound is stated as a format-derived constant. The tail probe runs only when
  the budget grants `TAIL`.
- `archive-reading` — `ArchiveyConfig` gains `detection_budget` (the freeze surface for
  the detection spend cap) and the exhaustive-scan requirement. Not a keyword on
  `open_archive` / `detect_format`, and not `exhaustive_prefix_scan`.

## Decisions

- **Cost tiers the design, not exhaustiveness.** The cue was never about false positives;
  it was about not reading 2 MiB from every file. Once that is the stated reason, the
  answer follows: a probe the *format* bounds (ZIP's 64 KiB tail) is cheap enough to
  *consider* always, but still a seek, so it stays off under `BALANCED` until a
  seek-cost measurement exists; a scan bounded only by a constant we picked needs a
  reason to run; an unbounded sweep is opt-in via `max_scan_bytes`. Recorded rather
  than assumed, because the previous cue looked like a false-positive defence and was
  reasoned about that way in review.
- **Opening an embedded archive is the right default.** A caller who opens a file has a
  reason to think it is an archive; if they are sweeping everything, the `prefix_kind`
  field lets them filter. archivey reports what it found rather than guessing intent.
- **Scan validation is not a licence to scan more.** The 7z/RAR self-checks make a hit
  trustworthy, not cheap. They justify high confidence on a hit, not removing the gate.
- **Four implementation PRs already move toward the ledger.** Validators and the ZIP
  tail locator land as format-owned functions the first-match loop calls. Validators
  return an internal `HitOutcome` so the ledger can later treat `DAMAGED` as still
  identified without a signature change. The tail probe stays ZIP-named
  (`detected_by="zip_tail_probe"`); there is no locator registry. No parallel
  `DetectionDeclaration`.
- **Detection spend lives on `ArchiveyConfig.detection_budget`.** Most callers never
  set a cap; they already skip `config=`. A bare `budget=` on `open_archive` /
  `detect_format` is easy to read as a decompression limit. `#273`'s `budget=`
  keyword is removed when the field lands. The earlier "not an ArchiveyConfig field"
  note was the `exhaustive_prefix_scan` bool, not this.

## Impact

- Modules: `src/archivey/internal/detection.py` (tier order, cue, `prefix_kind` — the
  generic loop), `src/archivey/internal/sfx.py` (cue), format modules for validators and
  the ZIP tail locator, `src/archivey/config.py` (`detection_budget` on `ArchiveyConfig`).
  The detector calls those functions rather than inlining parse. No `DetectionDeclaration`
  type here (that is `detection-evidence-ledger`).
- Public API: `FormatInfo` gains `prefix_kind` (always present, default `NONE`) and a
  `PrefixKind` enum (`NONE` / `EXECUTABLE` / `SCRIPT` / `UNKNOWN`). `ArchiveyConfig`
  gains `detection_budget` (`None` → BALANCED). Tail and exhaustive scan are
  `DetectionBudget` numbers on that field, not `exhaustive_prefix_scan` and not a
  `budget=` keyword. `#273`'s `detect_format(..., budget=)` is removed. Files that
  used to raise `FormatDetectionError` now open — a behaviour change, and the point
  of the change.
- ~~**Detection order changes once, deliberately: far magic moves ahead of the content
  probes.**~~ — **no longer this change's; shipped by `detection-format-gaps`.** Writing the
  tiers down here is what exposed it (exact magic at a fixed offset losing to the weakest
  signal archivey has, so a bootable ISO detected as `BROTLI` and opened as one fabricated
  `*.uncompressed` member), and the reproduction on a real `pycdlib` image is recorded in
  `design.md` §Ordering. But the LZMA Alone dictionary fix could not wait for a change
  sequenced behind `detection-evidence-ledger`, so the hoist — size gate, tests and all —
  landed there instead. The step remains in this change's algorithm delta as *inherited*
  text, because a MODIFIED requirement is replaced whole and omitting it would delete far
  magic from the live spec; see design §Sequencing.
- Tests: `zipapp` (offsets from byte 0) *and* a concatenated ZIP (offsets from the payload),
  Spring Boot exec JAR, polyglot, makeself, 7z/RAR SFX with PE, ELF, Mach-O and shebang
  stubs; tail-probe validation against planted EOCD records; non-seekable sources; the
  opt-in scan; the shebang cost bound.
- Docs: `docs/formats.md` detection prose — tracked as task 4.11, not left implicit.
- **Supersedes** the SFX requirement `sfx-format-detection` (#254) established, and modifies
  the *Executable-looking prefixes* requirement it added alongside — both now live, since
  #258 archived that change. The prerequisite is satisfied; see `design.md` §Sequencing.
