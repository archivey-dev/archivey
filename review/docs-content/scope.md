# Scope — pass 0 of Topic 8

Per-page job, explicit non-coverage, and every current block routed by
[`../archive/2026-10-06-docs/outline.md` D-f](../archive/2026-10-06-docs/outline.md).
Written before `claims.md`, because a claim on a block that is about to move is not worth verifying
([`brief.md` §Deliverables](brief.md)).

Measured against `main` @ `5d08f31` (`d4668c3` + the Topic 8/10 commission, which touched
no page under `docs/`). Guide today: **15 pages, 2 108 lines**; the sixteenth,
`how-it-works.md`, does not exist.

**This document routes; it does not write.** No guide prose is proposed here, and no line
of `docs/` is edited by this pass. Prose is step 6.

## The test, and how a ruling is written

D-f, for every block: *does the reader do something differently after reading it?*

| Answer | Destination | Written here as |
|---|---|---|
| Yes — it changes what they write, configure, or expect | the guide | **Keep** / **Trim** |
| No — it changes only how impressed they are | `dev-docs/threat-model.md`, or the spec / test that already proves it | **→ TM** |
| It is a lookup — a field, an enum member, a signature | the docstring, surfaced via `api.md` | **→ DS** |

Two rulings D-f does not name, both of which fall out of applying it across pages rather
than within one:

- **→ page** — the block is actionable, so it stays in the guide, but it is the *second*
  copy of a fact another page owns. One home, a link from the other. This is O-2's failure
  mode and the hard constraint "verify against code or spec, never against another page"
  is the reason it gets its own ruling rather than being folded into Keep.
- **Cut** — the block is a roadmap note, a duplicate with no surviving unique claim, or an
  argument with a reviewer. Nothing receives it. Every Cut below names what is lost; per
  the brief's hard constraint, a claim removed must land somewhere **or be recorded as
  dropped**, and these are the recorded drops.

Line references are `page:start-end` at `5d08f31`. Size estimates are *ceilings to
re-derive*, not targets — D-f's own instruction about the outline's table applies to this
one too.

## Precondition: the docstring leg does not work today

D-f routes lookups to "the docstring, surfaced through `api.md`". Checked before relying
on it, because several rulings below depend on it:

```
uv run --group docs python -c "griffe.load('archivey.internal.extraction_types', ...)"
  ExtractionStatus  class docstring 1 line — EXTRACTED, NOT_OVERWRITTEN, SUPERSEDED,
                    OVERWRITTEN, BLOCKED, FAILED: no docstring, all six
  AbortOn           class docstring 13 lines — BLOCKED_MEMBER, NAME_COLLISION,
                    NAME_SANITIZED: no docstring, all three
  ExtractionResult  class docstring 5 lines — all nine fields: no docstring
```

D-f's counts (1 / 3 / 5 / 6 / 13) are exact and unchanged. What the counts understate is
*where the missing depth already is*: `extraction_types.py` carries it as `#` comments
beside each member — `AbortOn.NAME_SANITIZED` has a six-line comment saying almost
exactly what `extracting.md:139-143` says, and `ExtractionResult.collided_with` has an
eleven-line one. **mkdocstrings renders none of it.** The enum table comes from
`scripts/docs/griffe_extensions.py` `EnumMembersAsTable`, which reads `m.docstring`
(`scripts/docs/griffe_extensions.py:125`); `griffe_fieldz` does the same for dataclass fields.
A `#` comment is not a docstring to griffe, so it reaches no reader.

Consequences for this pass:

1. **"→ DS" is a write task in `src/`, not a move.** Roughly: promote the existing
   comment to a docstring, then delete the guide copy. The prose mostly exists; it is in
   the wrong syntactic slot.
2. **It is a `src/` edit in a docs programme**, which the brief's "no library changes in a
   docs PR" rule does not obviously cover — a docstring changes no behaviour, but it does
   change `src/`. **Decided (Q1):** the constraint is about behaviour, so a docstring
   promotion rides with the page PR that drains the prose — under a stated carve-out that
   nothing but a docstring may change.
3. **§D gates part of it.** A block routed → DS is only *surfaced* if the type has an
   `api.md` entry. `ExtractionStatus`, `AbortOn`, `ExtractionResult`, `CostReceipt`,
   `ArchiveyConfig`, `DiagnosticCode` all have one, so those rulings are safe. The 21
   exception types do **not**, which is why `errors-and-diagnostics.md`'s exception table
   is ruled Keep below and not → DS.

This is a documentation-infrastructure fact, not a library defect. No `src/` file was
edited by this pass.

---

# The 16 pages

## 1. `index.md` — 93 lines

**Job.** Get a reader from "what is this" to a correct, safe call within one screen, and
name the page that owns each next step.

**Not on this page.** Any explanation of *why* a default is what it is (→ `philosophy.md`,
`how-it-works.md`); install detail beyond the pointer (→ `install.md`); behaviour of
anything the recipes call (→ the owning flow page); contributor material (→ the repo, D1/D3);
**a fifth recipe** — the block stays at four by maintainer decision (Q6).

| Block | Ruling | Note |
|---|---|---|
| `1-12` title, one-sentence pitch, open+list snippet | **Keep** | |
| `14-41` §Thirty seconds — four recipes | **Keep, frozen** | D-a rests on this block existing on the first screen. It is not available for trimming by a later pass without reopening D-a |
| `43-44` link row | **Keep** | |
| `46-61` §Highlights — eight bullets | **Keep, frozen at current size** | Mixed: "zero-dependency core" and "native 7z/RAR metadata" change what a reader installs; "one interface for every format" changes only how impressed they are. It stays because saying what the library *is* is this page's job, but it is Topic 7's material and must not grow here |
| `63-78` §User guide — numbered mirror of the nav | **Keep** | Becomes 15 entries when `how-it-works.md` lands; `check_docs_nav.py` is the guardrail |
| `80-93` §For contributors | **Keep** | D1/D3 shape: published page → repo links |

**Inbound.** None. I had routed one recipe here (~6 lines, cheap dedupe over
`member.hashes`) as the receiver for D-f's `formats.md` cut; **dropped by maintainer
decision** (Q6). The trimmed `formats.md` snippet is the guide's only dedupe example.

**Size.** 93 → 93.

---

## 2. `install.md` — 34 lines

**Job.** Answer "what do I have to install for the formats I need", completely, in one
screen.

**Not on this page.** Per-format quirks and the per-format capability matrix
(→ `formats.md`); which packages each extra actually pulls (→ `acknowledgements.md`
§Runtime dependencies); free-threading detail (→ `support-matrix.md`); the
`required_source` comparison (→ `opening-and-listing.md`, which already owns it).

| Block | Ruling | Note |
|---|---|---|
| `1-6` intro | **Keep** | |
| `8-13` four `pip install` lines | **Keep** | The page's deliverable |
| `15-18` four extras, no per-format ones; free-threaded pointer | **Keep** | |
| `20-21` RAR needs `unrar` | **Keep** | must-explain #14 |
| `23-28` §What each format needs | **Trim, then extend** | Today it is a pointer wearing a section heading. Receives both halves of the §B row: the `format_availability()` support-level query, and — **by maintainer decision (Q4)** — a four-row extra → formats re-index, capped at a re-index rather than a capability table |
| `30-34` §Free-threaded builds | **→ page (fold)** | Repeats `15-18` almost word for word, including the same link. One home; fold into the extras paragraph |

**Inbound, two.** (1) `format_availability()` as a runtime query — FULL / PARTIAL / NONE
and what `missing` gives you (must-explain #15), ~10 lines. Actionable: a caller checks it
before promising a user a format works. (2) The extra → formats re-index, ~12 lines,
restored by decision (Q4) after I had dissolved it; four rows, no capability columns,
`formats.md` still authoritative.

**Size.** 34 → ~52 (the Q4 re-index is most of the growth).

---

## 3. `opening-and-listing.md` — 203 lines

**Job.** Open a source of any shape — path, directory, stream, volume set, pipe — unlock it
if it needs a password, and find out what is inside.

**Not on this page.** Reading bytes out (→ `reading-members.md`); the damage contract, which
is `errors-and-diagnostics.md`'s by D-e — this page keeps the one-line honesty promise and a
link; per-format detail (→ `formats.md`); what an access pattern costs (→ `access-and-cost.md`).

| Block | Ruling | Note |
|---|---|---|
| `6-28` open+list, random access by default, streaming pointer | **Keep** | |
| `30-43` §`open_archive` or `open_stream`? | **Keep** | must-explain #21 |
| `45-56` §What you can open table; `format=` on a directory | **Keep** | must-explain #25 |
| `57-62` seekable stream read from `tell()` | **Keep** | must-explain #12. Actionable and invisible from the signature |
| `64-68` non-seekable stream, which formats | **Keep** | |
| `70-85` `required_source` comparison + `StreamCapability` ordering | **Keep — canonical home** | The one place this fact lives. `install.md` and `access-and-cost.md:48-53` link here |
| `87-107` §Multi-volume archives | **Keep** | The naming-scheme table is a lookup with no docstring home — a file-naming convention belongs to no type |
| `109-131` §Detection | **Keep — canonical home** | `formats.md:222-228` becomes a pointer |
| `133-151` §Passwords | **Trim** | Keep the shapes, the ordering cost, and the accepted-but-unused rule. The "keyring you are offering" justification is three lines arguing with a hypothetical objector — register pass, one line |
| `153-162` §Damaged archives | **Trim to D-e's one-liner + link** | D-e: the flow pages keep "the one-line honesty promise plus a link"; the contract is `errors-and-diagnostics.md`'s. Today this is ~6 lines of contract (`members_report()` semantics), duplicating `errors-and-diagnostics.md:114-132` |
| `164-188` §Duplicate names and `is_current` — rules + selector trap | **Keep** | must-explain #9. Highest-value block on the page |
| `189-203` two closing code blocks | **Trim to one** | The `is_current` filter earns its lines. The history-view loop below it demonstrates an f-string and a conditional — D-f's "the loop demonstrates that Python has `for`" ruling |

**Size.** 203 → ~185.

---

## 4. `reading-members.md` — 184 lines

**Job.** Get bytes out of a member, and know what each outcome means.

**Not on this page.** What is *in* the archive (→ `opening-and-listing.md`); the full damage
contract and the call × failure matrix (→ `errors-and-diagnostics.md`, D-e); what a pattern
costs (→ `access-and-cost.md`); writing files to disk (→ `extracting.md`).

| Block | Ruling | Note |
|---|---|---|
| `7-39` §Read a member; the two defaults + lift | **Keep** | must-explain #2 |
| `41-66` §Two ways to read; `access_cost` steering | **Keep** | |
| `67-77` three facts about yielded streams | **Keep** | must-explain #10. Lifetime, `None` for non-files, laziness — all three change loop shape |
| `79-84` data- vs header-encryption sub-note | **Trim** | Actionable (header-encrypted formats need the password at open), but it is written as a rebuttal. Two lines |
| `86-97` links are followed by `open()` but not by `stream_members()`; pass ownership | **Keep** | |
| `99-113` §What a read gives you back — the two bullets | **Keep** | D-e's named exception: the `read(member.size)` asymmetry is a footgun and stays in the flow |
| `114-126` the chunked-loop code block + closing note | **→ page** | Byte-identical to `errors-and-diagnostics.md:167-175`. Two copies of one recipe is the O-2 shape. D-e made errors the contract's home; the code goes there, this page keeps the bullets and the link it already has at `103-104` |
| `128-156` §Which members you can open | **Keep** | must-explain #19, #26, #20 |
| `158-171` §Streaming mode (pipes) | **Keep** | |
| `172-184` §One-shot extract | **Keep** | must-explain #4, #5 |

**Size.** 184 → ~170.

---

## 5. `gotchas.md` — 107 lines

**Job.** One line per trap, with a link to the page that owns the detail. A digest (D4:
"a footgun digest, not a format encyclopaedia").

**Not on this page.** Detail of any kind — every entry's second sentence is a link. Format
matrices, policy tables and unsupported-feature lists live on their owning pages, as the
page's own preamble says at `8-11`.

| Block | Ruling | Note |
|---|---|---|
| `13-52` §What you should and shouldn't do — 9 bullets | **Keep** | On contract: ≤4 lines each, each with a `→` link |
| `54-58` §What you should be aware of preamble | **Keep** | |
| `59-74` stdlib strictness, 7z password, 7z header residual, TAR residuals | **Keep** | On contract |
| `75-79` `strict_archive_eof` reads to EOF — 5 lines | **Trim to 1 + link** | Restates `formats.md:80-87` including the 10 KiB record argument. The digest's job is to say the flag is opt-in and costly, not to re-derive why |
| `80-90` rapidgzip truncation, `.Z` truncation, pycdlib patching | **Keep** | must-explain #29 |
| `91-104` empty listing — **14 lines** | **Trim to ~3 + link** | The page's largest entry, in the page whose contract is one line per trap. The `tar -b` blocking-factor derivation and the byte-identity argument are `errors-and-diagnostics.md`'s (which owns `EMPTY_ARCHIVE`) or the spec's. **Keep one clause of it**: Docker/OCI images carry a 1024-byte empty tar behind every metadata-only instruction — a reader who hits that acts on it |
| `105-107` prefer `reader.diagnostics` over logs | **Keep** | |

**Size.** 107 → ~80. The page is closer to its own stated contract than any other; the two
entries that broke it are the two trimmed.

---

## 6. `extracting.md` — 228 lines → **~120** (D-f's target: ~110–130)

**Job.** Extract an untrusted archive safely, and know what the defaults will do to your
files.

**Not on this page.** The enforcement inventory and the trust-boundary model
(→ `dev-docs/threat-model.md`); per-enum lookups (→ docstrings); the diagnostics and damage
contract (→ `errors-and-diagnostics.md`); the trap digest (→ `gotchas.md`); *why* the
defaults are these (→ `philosophy.md`).

This page is D-f's worked case, so the routing is given block by block.

| Block | Ruling | Note |
|---|---|---|
| `1-10` title, "you opt out, not in", one-shot | **Keep** | The contract, stated. Six lines is right |
| `12-27` §Trust boundaries — 4 bullets, 16 lines | **Trim to ~3 lines; rest → TM** | Mostly a threat model's §Scope rendered as user documentation — nobody writes different code after reading that other local processes are trusted, and the `O_NOFOLLOW`/`openat` future direction is roadmap. Two clauses do change behaviour and stay: *the archive is untrusted in every byte*, and *an earlier extracted member is untrusted input to every later one*. **Revised after #241**, which ruled the section "stays compact"; this is that reading, with the process/local-attacker and optional-dependency bullets still routed out |
| `29-33` path traversal, absolute, UNC, null bytes | **Trim → one clause** | D-f rules it verbatim: "**Guide, as one clause** in the contract sentence. Not three lines with module paths." Drop `internal/filters.py` |
| `34-37` extraction-root overwrite | **→ TM** | The caller does nothing differently; `PathTraversalError` already appears in the exception table |
| `38-41` symlink escapes, three layers | **→ TM** | D-f rules it verbatim: "Nobody acts on the layer count" |
| `42-43` hardlinks resolved positionally | **→ TM** | D-f rules it. The caller-visible half is already at `165-167` as an identity rule and stays there |
| `44-46` never write through a symlink; atomic temp writes | **Trim → one clause** | The temp-file mechanism is only interesting because of `80-84`, which is kept |
| `47-48` special files, NTFS junctions | **Trim → one clause** | |
| `49-58` deceptive names / bidi | **Keep, shorter** | D-f rules it: "**Guide, shorter.** Someone with those filenames acts on it." Overrides rejected, marks not, `فهرس.txt` fine, `MEMBER_NAME_BIDI_CONTROL` on read. ~5 lines. The `evil‮gnp.exe` example earns its line |
| `59-65` the `TRUSTED`-lifts-it justification | **→ DS + one line** | Already in `ExtractionPolicy.__doc__` (`extraction_types.py:48-56`), better written. Guide keeps "`TRUSTED` extracts it under the stored name" + link |
| `66-68` decompression bombs | **Trim → one clause** | §Limits at `185-206` is the detail |
| `69-70` permission hygiene | **Trim → one clause** | |
| `71-73` cross-platform name safety, ADR 0013 / PRs #109/#123 | **→ TM** | D-f rules it. The caller-visible consequences are already in §Names change on disk and the Need-to-know table |
| `74-75` error honesty | **→ page** | This *is* the translation contract, which is the §B row on `errors-and-diagnostics.md`. One home, and it is not this one |
| `76-78` accelerator `weakref.finalize` lifecycle | **→ TM** | The caller rule survives at `210-216` |
| `80-84` `.archivey-tmp-*` are safe to delete | **Keep** | D-f rules it: "Operational, actionable, surprising" |
| `86-106` §Policies code block | **Keep** | |
| `108-111` `OnError` failures vs policy blocks | **Keep** | must-explain #6. The distinction scripts get wrong |
| `113-121` `abort_on` exists; the `AbortOn.BLOCKED_MEMBER` example | **Keep** | D-f: "the guide naming that `abort_on` exists and linking" |
| `122-129` the three-member `abort_on` table | **→ DS** | D-f rules it. `AbortOn`'s members carry this as `#` comments today (§Precondition) |
| `130-133` abort is immediate, no report returned | **Keep, one line** | Changes how you call it — you handle an exception, not a return value. The rest is in `AbortOn.__doc__` (`extraction_types.py:105-108`) |
| `135-137` `NAME_COLLISION` fires on every collision | **→ DS** | Verbatim in the `NAME_COLLISION` comment already |
| `139-143` `NAME_SANITIZED` is a narrow escape hatch | **→ DS** | D-f rules it by name. Verbatim in the `NAME_SANITIZED` comment already |
| `145-149` the policy table | **Keep, fix** | Two rows for three enum members: `STANDARD` is absent from the table while the page's prose uses it four times (`51`, `71`, `173`, `175`). Recorded as an accuracy row for pass 1, not fixed here |
| `151-155` selective extract on an open reader | **Keep** | |
| `157-167` §Names change on disk — the four identity rules | **Keep** | Receives the hardlink rule from `42-43` |
| `169-183` the 14-row "Need to know" table | **Trim to ~6 rows** | A second gotchas digest living inside a flow page. Six rows are extraction-specific and stated nowhere else (STRICT rewrites names · collisions are first-class · `collided_with` · reserved names · hardlinks + filters · symlink-hostile filesystems). The other eight each have a home: nested archives → `gotchas.md:41-44` + §Limits; listing vs extract limits → §Limits; staging leftovers → `80-84`; `CONTINUE` ≠ ignore bombs → `gotchas.md`; `STOP` is failures-only → `108-111`; `TRUSTED` won't traverse → the policy table; safe ≠ unlimited → §Limits |
| `185-206` §Limits | **Keep, unchanged** | Including the per-archive bomb-tracker paragraph at `203-206`. The worked recursion recipe I had routed here is **dropped by maintainer decision** (Q5) — the pointer is the coverage |
| `208-216` accelerators off for untrusted input | **Trim** | Keep the rule and the reason. "Mutation and Atheris harnesses run with accelerators off for this reason" is evidence for the maintainer → TM |
| `218-223` external `unrar` is in your trust boundary; extract-then-promote | **Keep** | Both operational |
| `225-228` §Diagnostics pointer | **Keep** | |

**Where the lines go.** Summed from the per-block rulings above, ~**82** lines leave their
current form: ~32 → `dev-docs/threat-model.md` (verify each has a home there before
deleting — hard constraint); ~25 → docstrings; ~2 → `errors-and-diagnostics.md`; ~8 dropped
as duplicates with the receiving home named above; ~15 absorbed into the one-clause
rewrites that stay on the page. Nothing comes back — the recursion recipe I had routed
inbound is dropped by Q5.

**So routing alone lands the page at ~145, not inside D-f's ~110–130.** Said plainly rather
than rounded away: the band is reached once pass 3 runs O-17 on what survives, and this page
carries more promoted maintainer prose than any other. Pass 0 must not pre-spend that — the
same reasoning as §Arithmetic below, applied to the page D-f measured.

---

## 7. `access-and-cost.md` — 188 lines

**Job.** Predict what an access pattern will cost, and configure the reader so it costs
less.

**Not on this page.** What is *legal* (→ the flow pages — `reader.cost` describes price,
not permission, as `46` already says); per-format quirks (→ `formats.md`); safety limits
(→ `extracting.md`); benchmark methodology and the perf roadmap (→ `dev-docs/`, `IDEAS.md`).

| Block | Ruling | Note |
|---|---|---|
| `6-14` §Wall-time bands preamble + harness command | **Keep** | |
| `16-33` measured column, nightly run link, corpus, the L5 follow-up | **Trim to ~6** | Keep the aspirational band table and one sentence pointing at the nightly. A specific run id, a corpus description, an above-band admission and a deferred-optimization pointer are maintainer evidence. **Also**: the run link at `18` points at `github.com/davitf/archivey-**2**/actions` — recorded as an accuracy row for pass 1, not fixed here |
| `35-45` §Read `reader.cost` — the four-field table | **→ DS** | A field table is D-f's own example of a lookup. `CostReceipt` has an `api.md` entry, so it surfaces |
| `46-53` cost ≠ legality; `StreamCapability` is ordered; the other two are not | **Keep** | Actionable, and the "not ordered" clause prevents a real mistake |
| `55-63` §RAR listing cost | **Keep, trim** | **Revised after #241.** I had moved this to `formats.md`; that was wrong by my own rule — a cost fact's owner is the cost page, and moving an owner is what → page is not for. Keep "open-time cost scales with member count, `members()` is O(1) afterwards"; the Quick Open record and "not the primary source" are parser internals → `formats.md` §RAR or the spec |
| `64-87` §Solid archives: prefer one forward pass | **Keep** | The page's central claim; must-explain #11 |
| `88-107` §Seeking — flag semantics, the rewind rule, single-block `.xz` | **Keep, tighten** | The "what the seek costs, not the codec's name" rule changes expectations. The single-block `.xz` worked example is the shortest proof that the rule is not a codec whitelist — keep it, shorter |
| `109-111` fires on every qualifying seek, not only the first | **→ DS** | `DiagnosticCode.STREAM_REWIND_REDECOMPRESSES` |
| `113-123` the flag changes nothing else; the `AUTO` threshold | **Keep + one clause** | **Corrected after #241.** I had marked must-explain #16 closed; only half of it is. The page states the 1 MiB `AUTO` threshold but never says what happens when the package is *absent* — `ON` raises `PackageNotInstalledError`, `AUTO` falls back silently (`must-explain.md:212-214`, `config.py:19-31`). That is the half a caller acts on. ~2 lines |
| `125-137` §Concurrent member streams | **Keep** | must-explain #3 |
| `139-146` §Non-seekable sources | **→ page, 2 lines** | The rule is `opening-and-listing.md:64-68`'s. Here: what it costs you to spool |
| `148-152` §Streaming mode is one pass | **Trim to 2 + link** | Third copy (`reading-members.md:158-171`, `gotchas.md:25-27`). The unique claim here is `scan_members()` to drain — keep that one |
| `154-159` §Passwords and confirmation cost | **Keep** | must-explain #13; the ZipCrypto STORED niche is a real cost cliff |
| `161-172` §Accelerators — the contained fault | **Trim to ~4** | The `terminate()` boundary, the trap test's name and what it asserts are evidence, not instruction → TM. The caller rule ("closing a source under a live stream is a clean failure, still don't") stays |
| `174-177` the uncontained path-source residual | **Keep** | Round-2 finding 2 exists because this was once contradicted across pages. Both halves stay stated |
| `179-188` §Checklist | **Keep as-is** | And see §B row 3: the "config-at-a-glance screen" this row was supposed to become is a lookup and dissolves to `ArchiveyConfig.__doc__` |

**Inbound.** Measurement, ~8 lines: `enable_measurement()` is opt-in and open-scoped, and
`reader.io_stats()` returns `None` outside it (must-explain #28). Field meanings stay in
`IoStats.__doc__`, which is already written and already rendered.

**Size.** 188 → ~145.

---

## 8. `formats.md` — 228 lines

**Job.** Per format: what works, what it needs installed, and the quirks that surprise
callers.

**Not on this page.** Install lines (→ `install.md`); cost mechanics (→ `access-and-cost.md`);
extraction safety (→ `extracting.md`); which package each extra pulls (→ `acknowledgements.md`);
detection *behaviour* (→ `opening-and-listing.md`); codec-choice rationale
(→ `how-it-works.md`).

| Block | Ruling | Note |
|---|---|---|
| `6-27` §Quick matrix + `unrar` + install pointer | **Keep** | The page's index |
| `29-49` ZIP: backends, extended codecs, split rejection, timestamps, name encoding | **Keep** | The unflagged-UTF-8 sniff and `zip_unflagged_fallback_encoding` are configuration decisions |
| `50-54` a wrong bit-11 makes the whole archive unlistable | **Keep, 2 lines** | Rare and loud, but a caller who hits it needs to know it is archive-wide. "A native ZIP reader could recover the other entries; today it cannot" is roadmap → **Cut** |
| `55-59` ZipCrypto cost, WinZip AES, AE-2 has no `crc32` | **Keep** | |
| `61-71` TAR basics | **Keep** | |
| `72-89` mid-archive corruption; the three `strict_archive_eof` sub-bullets | **Keep, tighten** | must-explain #27. Each sub-bullet changes a config choice, so all three stay; the derivations shorten |
| `90-92` streaming caveat + "a future native TAR reader may close this gap" | **Keep / Cut** | Keep the caveat; cut the roadmap clause |
| `94-106` 7z: native parse, extras, BCJ2, solid folders, AES-without-anchor, header-encrypted wrong password | **Keep** | |
| `107-108` `NumCyclesPower` capped at ≤24 / the `0x3F` sentinel | **→ TM** | Impressed-only. Nobody chooses differently knowing 7-Zip's clamp value |
| `111-116` RAR: native metadata, `unrar` on `PATH`, password on stdin | **Keep** | |
| `117-119` BLAKE2sp needs no package; HASHMAC via `ConvertHashToMAC` | **Trim** | Keep "tweaked digests are not exposed as `member.hashes`" (actionable — you will not find the value you expect). The UnRAR function name → TM |
| `120-126` `-ver` history rows, solid RAR, read-only | **Keep** | Feeds `is_current` |
| `128-134` ISO 9660 | **Keep + one clause** | **Added after #241.** `gotchas.md:90` links "`import archivey` patches pycdlib process-globally" → `formats.md#iso-9660`, and the landing section does not mention it (must-explain #29 names both pages as owners). A link with no landing is round-2 finding 3's exact shape |
| `136-140` Directory | **Keep** | |
| `142-155` single-file: synthetic member, `FNAME`, gzip trailer CRC, the rapidgzip best-effort caveat | **Keep** | O-2's subject; the caveat is load-bearing |
| `156-160` `.lz` CRC-combine derivation | **Trim to the rule** | "Whenever the source can be seeked" is actionable; how the multi-member value is combined is provenance → TM or spec |
| `161-164` why zlib's Adler-32 is not surfaced | **Trim to the fact** | The parenthetical is an answer to a reviewer |
| `165-170` `.Z` truncation, `open_stream` seekability | **Keep** | |
| `172-189` §Stored digests intro + the format×keys matrix | **Keep** | D-f: "The *matrix* is archivey knowledge and stays" |
| `190-220` §Cheap dedupe — the 30-line `hashlib` loop | **Cut to ~8, floor raised** | D-f rules it: "the loop demonstrates that Python has `for`". Q6 declined the Home recipe that was to receive the use case, so this snippet is the guide's **only** dedupe example and must stand alone — keep the stored-vs-computed provenance idea in the ~8 lines, not just the `member.hashes` lookup |
| `222-228` §Detection | **→ page, 2 lines** | `opening-and-listing.md:109-131` owns detection. The SFX-stub line is unique — keep it here |

**Size.** 228 → ~185. §Stored digests: 49 → ~20, as D-f targets.

---

## 9. `errors-and-diagnostics.md` — 201 lines

**Job.** What is raised, what is recorded, and — when the archive is damaged — what you can
still get out of it. D-e makes it the damage contract's home.

**Not on this page.** Extraction policy semantics (→ `extracting.md`); per-code and
per-field lookups (→ docstrings, once §D is settled); the trap digest (→ `gotchas.md`).

| Block | Ruling | Note |
|---|---|---|
| `6-32` §The exception tree — the `except ArchiveyError` example + 7-row subtype table | **Keep** | It reads like a lookup, and §D is why it is not: 21 of the 26 exception types have **no `api.md` entry** (counted: 27 `*Error` names in `__all__`, less `OnError`, which is an enum; `api.md` lists five), so this table is the only reference that exists. **Coupled to §D** — if §D enumerates the exception tree in `api.md`, revisit this table then, and not before |
| `33-39` `ArchiveyUsageError` is outside the tree | **Keep** | must-explain #1. The single most consequential fact about the hierarchy |
| `41-46` §Diagnostics intro — queryable, not log-only | **Keep** | |
| `48-62` the 7-row "said with a diagnostic" table | **Keep the table; trim the cells** | **Softened after #241**, which ruled it Keep outright on the ground that each code changes whether a caller escalates or ignores. That is right about the *table* — it is the escalation decision surface, not a glossary — so it stays. What still leaves is the multi-sentence justification inside three cells (`EMPTY_ARCHIVE`'s tar-is-all-zeros argument is written in three places: here, `gotchas.md:91-104`, and the code); reference-grade wording for each code belongs on `DiagnosticCode`'s members, which `api.md` renders |
| `63-78` §What is *not* here: per-member outcomes | **Trim to ~6** | #235's admission rule. "Read `results`, not `report.diagnostics`" is the actionable sentence; "a fact has exactly one authoritative channel, and when a return value can carry it, the return value wins" is the design argument → the `diagnostics` spec, which already states it |
| `80-101` §Named policy presets; `strict()` / `pedantic()`; the five exclusions | **Keep, tighten** | Each exclusion changes whether a pipeline raises. The per-exclusion justification is one clause each, not one sentence each |
| `103-106` new codes may appear in minor releases | **Keep** | A version-stability rule a caller acts on |
| `108-113` §When an archive is damaged preamble | **Keep** | |
| `114-132` §Listing a damaged archive + `members_report()` recipe | **Keep — canonical home** | D-e. `opening-and-listing.md:153-162` shrinks to the one-liner + this link |
| `135-165` §The integrity guarantee — five bullets | **Keep** | D-f rules the whole section Keep. O-17's worked example lives here ("we can't tell which bytes are good") |
| `167-179` the chunked-loop code block + `VerificationMode.STRICT` | **Keep — canonical home** | Receives the duplicate from `reading-members.md:114-126` |
| `181-198` §What each call does — the call × failure matrix | **Keep** | D-e assigned it here explicitly. It is a table of *outcomes*, not of fields — the reader branches on it |
| `200-202` members with no declared size | **Keep** | |

**Inbound, two rows.**

1. **The error-translation narrative** (§B row 5), ~12 lines. `CONTRIBUTING.md:221-230` is
   a user-facing promise the guide never states: known third-party exceptions are
   translated to the `ArchiveyError` tree; unrecognized ones **propagate raw** rather than
   being swallowed by a catch-all; `OSError` / `KeyboardInterrupt` / `MemoryError` pass
   through unchanged except where a spec says otherwise; `ArchiveyUsageError` is
   deliberately outside the tree. A caller writing `except` clauses acts on every clause of
   that. Receives `extracting.md:74-75`.
2. **Messages are inert for terminal display** (#236), ~3 lines — new, not in the outline's
   worklist. `ArchiveyError` / `ArchiveyUsageError` escape archive-derived text at
   construction and `Diagnostic` escapes its `message`, so printing one to a terminal
   cannot be used to move the cursor or forge output. `error-handling` and `diagnostics`
   both require it; no page states it. Threat-model O9 is **closed**, so this is coverage,
   not a gap.

**Size.** 201 → ~195.

---

## 10. `cli.md` — 48 lines

**Job.** Run the `archivey` command, and know its defaults and exit codes — especially the
three places they deliberately differ from the library.

**Not on this page.** Library equivalents (→ the flow pages); output formats not yet shipped
(`--json` is `IDEAS.md`'s).

| Block | Ruling | Note |
|---|---|---|
| `1-4` install + `tqdm` note | **Keep** | |
| `6-13` verb table | **Keep** | |
| `16-37` §Safer extract demo | **Keep, restructure** | The CLI-vs-library divergence is currently a comment *inside* a bash block (`19-22`). See inbound |
| `39-48` §Notes — verb grammar, exit codes, reserved | **Keep** | Exit `3` is the one an automation author must handle |

**Inbound, three rows** (outline `§10 items 3 and 6`; never in the §B table, so easy to
lose):

1. **CLI defaults diverge from the library** as its own block, ~6 lines — `policy=strict`
   but `overwrite=rename` and `on_error=continue`, where the library defaults to `ERROR` /
   `STOP`. must-explain #23, and the outline's note is exact: *"it is what breaks scripts
   ported from one to the other"*.
2. **Passwords on argv are visible to `ps`**, ~2 lines. Operational, actionable, and stated
   nowhere.
3. **Terminal-safe output**, ~1 line + link — the CLI prints archive-derived names and
   messages; escaping happens at message construction (#236). This page is 48 lines against
   the largest recent change to CLI output.

**Size.** 48 → ~60. The only page that grows by more than it sheds.

---

## 11. `migrating.md` — 174 lines

**Job.** Replace `zipfile` / `tarfile` / `shutil` / `patool` / `py7zr` with the archivey
call, and know what changes in behaviour.

**Not on this page.** Full explanations of anything it names — every "what changes" bullet
ends in a link. Feature comparison as advocacy (→ Topic 7).

| Block | Ruling | Note |
|---|---|---|
| `10-21` cheat sheet | **Keep** | |
| `23-56` from `zipfile` | **Keep** | The `extractall`-was-never-safe bullet is the page's strongest claim and a safety claim — pass 1 verifies it, pass 0 keeps it |
| `57-92` from `tarfile` | **Keep** | The accidental-O(n²) bullet does real work |
| `93-114` from `shutil.unpack_archive` | **Keep** | |
| `115-136` from `patool` / shelling out | **Keep** | |
| `130-132` the RAR licensing paragraph | **Trim to 1 line** | "May not be reimplemented" is the actionable half; the rest is rationale → `how-it-works.md` §What is not ours |
| `137-155` from `py7zr` / `rarfile` | **Keep** | |
| `157-175` §Things that will bite you — 5 items | **Keep** | Overlaps `gotchas.md` by design: same traps, migrator's framing. Not a duplicate to collapse |

**Accuracy note for pass 1, not a routing change.** This page names `ExtractionStatus`
members (`48`) and the report shape (`112`); #235 removed four diagnostic codes and changed
that surface. §A's sweep covers it.

**Size.** 174 → ~170.

---

## 12. `support-matrix.md` — 152 lines

**Job.** What CI proves about platforms and threading, and — equally — what is deliberately
not claimed.

**Not on this page.** Performance (→ `access-and-cost.md`); install lines (→ `install.md`);
the concurrency *API* (→ `reading-members.md`, `access-and-cost.md`).

D-f flagged §Free-threaded Python (105 lines, the guide's largest section) as **"not ruled
here"** and handed it to this pass. **Ruling: it stays, at about 60% of its size.** The test
is whether a reader acts on it, not how many readers there are, and the extras table is the
only place that answers "which extras keep the GIL disabled on 3.13t" — an install decision,
derivable from no other page and from no docstring. What does not survive the test is the
~23 lines inside it that re-explain the single-stream default, which three other pages own.

| Block | Ruling | Note |
|---|---|---|
| `7-27` Python and OS table + the minimum-versions leg | **Keep** | |
| `29-33` non-CPython interpreters | **Keep** | An explicit non-claim; the page's job |
| `35-58` §What is claimed + the fan-out example | **Keep, tighten to ~12** | |
| `60-82` §Which extras are free-threaded + the package table | **Keep** | The actionable core. "Importing an undeclared C extension silently re-enables the GIL" is the fact the whole section exists for |
| `66-68` the second "Measured on CPython 3.13.7t" | **Cut** | Duplicated from `62`, four lines apart |
| `84-96` the two consequences + the CI assertion | **Keep** | `[recommended]` failing to install on 3.13t is actionable |
| `98-108` §What is *not* claimed | **Keep** | Four explicit non-claims. This is what an explicit non-coverage list looks like when a page does it well |
| `110-127` §The default is fail-fast, not racy | **Trim to ~4 + links** | Fourth copy of the one-live-stream default (`reading-members.md:22-28`, `access-and-cost.md:125-137`, `philosophy.md:39`). The unique claim here — capabilities are opt-in so a reader can hold one decode position — is one sentence |
| `128-132` `ConcurrentAccessError` is outside `ArchiveyError` | **→ page** | `errors-and-diagnostics.md:33-39` owns the two-root rule |
| `134-139` §One live-stream caveat — `close()` can block | **Keep** | Not stated anywhere else, and it bites under concurrency |
| `141-152` §Thread-safety summary table | **Keep** | The page's deliverable: one row per operation, each a yes/no a caller acts on |

**Size.** 152 → ~115; §Free-threaded 105 → ~65.

---

## 13. `philosophy.md` — 79 lines

**Job.** Why archivey exists and which defaults follow from it, in the end user's framing.

**Not on this page.** The maintainer vision — adoption strategy, quality scaffolding,
non-goals (→ `VISION.md`, as `3-5` already says); how anything works (→ `how-it-works.md`);
any behaviour a page owns (→ that page, via link).

| Block | Ruling | Note |
|---|---|---|
| `1-5` VISION pointer | **Keep** | |
| `7-29` one sentence, simple API, safe by design | **Keep** | `28` — "safety is a contract, not a marketing flag" — is the sentence D-d and D-f are both built on |
| `31-45` don't-shoot-yourself by design | **Keep** | |
| `47-56` escape-hatch table | **Keep** | Reads as a lookup, but it is this page's argument in table form: every hatch is explicit. Not → DS |
| `57-72` content-first; honest about damage and cost | **Keep** | |
| `74-79` what this is not | **Keep** | |

**No cuts.** The shortest narrative page and the one most on-job. D-f's pressure does not
apply to a page whose subject *is* rationale — but that is also why nothing may be
*added* here: an overflowing behaviour page must not drain into it.

**Overlap to watch, not to resolve here.** `index.md` §Highlights and this page make
adjacent claims. Topic 7 owns positioning; neither block moves in this pass.

**Size.** 79 → 79.

---

## 14. `api.md` — 91 lines

**Job.** The generated reference: every public name, with its signature and docstring.

**Not on this page.** Narrative, recipes, rationale. It is `::: archivey.X` lines and
section headers, and should stay that.

| Block | Ruling | Note |
|---|---|---|
| `3-5` "everything documented here is re-exported… and listed in `archivey.__all__`" | **Keep, reword — §D** | True, and reads as a completeness claim it does not make: 56 of 87 names have entries. The sentence is `QUESTIONS.md`'s, not a routing call |
| `7-91` twelve sections, 56 entries | **Keep** | |
| `40-41` the Diagnostics prose note | **Keep** | The one narrative sentence, and it earns its place |

**This page is the receiving end of every → DS ruling above**, which makes §D a *dependency*
of pass 6 rather than a standalone question: `ExtractionStatus`, `AbortOn`,
`ExtractionResult`, `CostReceipt`, `ArchiveyConfig`, `DiagnosticCode` all have entries, so
those moves are safe today. The 21 exception types do not, which is exactly why
`errors-and-diagnostics.md`'s table is ruled Keep.

**Size.** 91 → ~91, plus whatever §D decides.

---

## 15. `acknowledgements.md` — 98 lines

**Job.** Credit every project archivey depends on, learned from, was checked against, or
deliberately did not use — and say which of those four each one is.

**Not on this page.** Install guidance (→ `install.md`); codec-choice rationale
(→ `how-it-works.md` and `library-analysis.md`); per-format behaviour (→ `formats.md`).

| Block | Ruling | Note |
|---|---|---|
| `1-20` intro, license pointer, thanks | **Keep** | |
| `22-28` adapted source | **Keep** | License-bearing; not optional |
| `29-39` format references, oracles, corpora | **Keep** | |
| `41-57` seekable-stream design references | **Keep** | D-f's "changes only how impressed they are" is not the test for a credits page: crediting an evaluated-and-rejected library **is** the page's job. Stated so the ruling is not re-derived |
| `59-82` runtime dependencies per extra | **Keep** | Overlaps `install.md` and `formats.md`, and shouldn't collapse: this is the package-level enumeration (who wrote what), those are "what do I install" and "what does this format need". Three questions, three answers |
| `84-99` dev and test dependencies | **Keep** | |

**No cuts.** The one page where the D-f "no" leg does not bite, because attribution is the
deliverable rather than evidence for a claim.

**Size.** 98 → 98.

---

## 16. `how-it-works.md` — **does not exist**

**Job.** For a reader deciding whether to trust the library: how it is built, in six
paragraphs, each ending in a link out (D2). The nav's sixteenth entry, late, before the API
reference.

**Not on this page.** The raw ADR corpus (→ `dev-docs/decisions/`, D2); anything a reader
*acts* on — every such fact belongs on a flow page and is linked from here, not explained
here; threat-model depth; per-format quirks (→ `formats.md`); the problem catalogue, which
D2's six sources do not include and which this page does **not** wait for
([`brief.md` §Definition of done](brief.md) row 3).

**Sections** (D2, `../archive/2026-10-06-docs/DECISIONS.md:50-57`) — a paragraph plus a link each:

| Section | Sourced from | Also receives |
|---|---|---|
| Native-first parsing — why 7z/RAR headers are parsed in pure Python | `VISION.md:29-34`, ADRs 0001/0002 | |
| The uniform stream layer | `library-analysis.md:14-19`, `compressed-streams` spec | |
| Where the cost model comes from — why `CostReceipt` exists rather than silent heuristics | `access-mode-and-cost` spec, ADR 0003 | the *rationale* half of `access-and-cost.md:35-45` |
| Backends and the registry — how detection picks one, what an extra actually adds | `backend-registry` spec | |
| What is *not* ours — stdlib `zipfile`/`tarfile`, `unrar`, `pycdlib`, and why | ADRs 0006/0002, `formats.md` | `migrating.md:130-132`'s RAR licensing rationale |
| Decisions summary — one short entry per load-bearing ADR outcome | `dev-docs/decisions/` | |

**The D-f tension, ruled.** Every other page sheds "changes only how impressed they are" to
`dev-docs/threat-model.md`. This page's *job* is that register — which is why it can receive
**architecture** rationale (why the cost model exists, why `unrar` stays) that would
otherwise have no published home. It does **not** receive **adversarial** rationale: symlink
layers, casefold tracking and trust boundaries go to the threat model as D-f rules, not
here. The distinction is "how it is built" versus "what an attacker cannot do", and it is
the difference between a curated overview and a second threat model.

**Cap.** D2 says ~120–180 and `outline.md`'s worklist says ~150. Under D-f, re-derived as
six paragraphs plus links plus two inbound rationale blocks: **~110–120**. The cap is the
guardrail against it becoming the dumping ground for everything the other pages shed — if a
section wants more than ~20 lines, the excess is a `dev-docs/` link.

**Fix vehicle.** A `documentation` spec delta, not just a file:
`openspec/specs/documentation/spec.md:78-93` enumerates the narrative pages and requires
every file under `docs/` to carry a nav entry.

---

# §B worklist, re-derived under D-f

`outline.md` §"What merging cannot supply" estimated **~455 outstanding lines**. That
number predates +226/−27 lines of guide prose landed by `#225` / `#232` / `#235`, and D-f
converts several rows from prose tasks into docstring or threat-model tasks. Re-tallied
row by row against `5d08f31`:

| # | Outline row | Est. | State now | Routed | New est. |
|---|---|---:|---|---|---:|
| 1 | `how-it-works.md`, all six D2 sections | ~150 | Still absent — the only page in the outline with no file | **Guide** | ~110 |
| 2 | `install.md` — `format_availability()` section; matrix re-cut by extra | ~45 | 34 lines, two sections | **Both halves guide** — the re-cut restored by decision (Q4), capped as a four-row re-index | ~22 |
| 3 | `access-and-cost.md` — ON-vs-AUTO, measurement, config-at-a-glance | ~55 | AUTO *threshold* shipped (`118-123`); the ON-raises / AUTO-falls-back-silently half is **not** | **Splits: one half shipped, two guide, one → DS** | ~10 |
| 4 | `extracting.md` — bounded recursion, "what `TRUSTED` does not relax", the config ceiling | ~90 | `TRUSTED` covered (`59-65`); recursion is a pointer (`203-206`) | **Splits: one shipped, one dropped by decision (Q5), one guide** | ~3 |
| 5 | `errors-and-diagnostics.md` — translation, diagnostics-as-data, codes worth knowing, policy, limits vs filters | ~55 | Grew +61 in `#235` | **Splits: three shipped, one guide, one → DS** | ~15 |
| 6 | `opening-and-listing.md` / `reading-members.md` remainders | ~25 / ~35 | | **Dissolved — all shipped** | 0 |
| 7 | *(new)* `cli.md` — outline §10 items 3 and 6 | — | Never in the §B table | **Guide** | ~10 |
| 8 | *(new)* `index.md` — a dedupe recipe to receive the `formats.md` cut | — | | **Dropped by decision (Q6)** — recorded, not unwritten | 0 |
| 9 | *(new)* `errors-and-diagnostics.md` — messages are terminal-inert (`#236`) | — | No page states it | **Guide** | ~3 |
| 10 | *(new, from #241)* `formats.md` §ISO — state the process-global pycdlib patch | — | `gotchas.md:90` links here; the landing is silent | **Guide** | ~2 |
| | **Total new guide prose** | **~455** | | | **~174** |

## Which rows dissolved, and why

**Row 6 dissolves entirely — both pages.** Checked line by line rather than assumed, as the
row itself asks:

| Remainder | Where it landed |
|---|---|
| Sources | `opening-and-listing.md:45-107` — the What-you-can-open table, the mid-stream `tell()` rule, `required_source`, multi-volume |
| The named detection diagnostic | `opening-and-listing.md:119-123` — `FORMAT_EXTENSION_CONFLICT`, named, with both candidates |
| The errors callout | `opening-and-listing.md:153-162` — and round-2 finding 4 exists precisely because this was recorded as done before it was |
| `stream_members` lifetime | `reading-members.md:67-77` — all three facts: validity window, `None` for non-files, laziness |
| Identity and lifetime | `reading-members.md:128-156` — cross-reader members, `member in reader`, stream-outlives-reader |
| The `extract()` pipe note | `reading-members.md:172-184` — both halves, no `members=` and auto-streaming |

These two pages now need **cuts, not additions** (−14 and −14 above). A worklist row that
became negative is exactly the stale-worklist failure #223's round-2 finding 5 named.

**Row 2 half-dissolves.** The `format_availability()` work split in two when `#232` landed
`required_source`: the comparison recipe is written, on `opening-and-listing.md:70-85`, and
must not be written a second time here. What is left is the support level — FULL / PARTIAL /
NONE and `missing` (must-explain #15), ~10 lines.

The second half — "matrix not re-cut by extra" — **I had dissolved, and the maintainer
restored it** (Q4). My argument was that `formats.md:8-20` already carries Core?/Extra
columns and `acknowledgements.md:63-68` already carries extra→packages, so a third cut is
the O-2 shape: one fact in several places, stale in two. The decision accepts a **bounded**
version of that duplication because neither existing table is organised by what the reader
types, which is `install.md`'s whole job. **Outstanding work: a four-row extra → formats
re-index, ~12 lines**, with no capability columns and `formats.md` still authoritative.

**Row 3 splits three ways.** ON-vs-AUTO **shipped** (`access-and-cost.md:118-123`, the
`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` threshold). Measurement stays **guide**, ~8 lines,
because opt-in-and-open-scoped is a behaviour, while the counter meanings are already in
`IoStats.__doc__` and already render. The **config-at-a-glance screen dissolves to a
docstring row**: an enumeration of every `ArchiveyConfig` field with its default is D-f's
definition of a lookup, and `ArchiveyConfig` has an `api.md` entry. `#223`'s finding 4 asked
for "a configuration reference home"; under D-f that home is the class, not a screen in a
prose page. The situation→API checklist already on the page (`179-188`) is the actionable
half and stays.

**Row 4 loses two of its three sub-rows.** "What `TRUSTED` does not relax" is **written
twice** — `extracting.md:59-65` and, better, `ExtractionPolicy.__doc__:48-56` — so that
sub-row is closed. The bounded-recursion worked recipe is **dropped by decision** (Q5): the
paragraph at `203-206` plus `gotchas.md:41-44` is the guide's coverage, and the
amplification analysis stays threat-model O6's. **All that remains is the config-ceiling
rule** (must-explain #8: `extract_all(config=)` cannot raise the listing ceiling set at open
time), **~3 lines**. Note the asymmetry: `extracting.md` is the **largest cut** on the guide
(~−82) and still adds those three lines.

**Row 5 keeps one clause of five.** Diagnostics-as-data **shipped** (`41-46`); policy
**shipped** (`80-107`, `strict()` / `pedantic()` and the five exclusions); limits-vs-filters
**shipped** across `extracting.md:108-111` and the exception table. "The codes worth
knowing" **dissolves to → DS** — a per-code "what this means" table is a lookup and
`DiagnosticCode` renders. What survives is **translation**, the one genuinely absent
user-facing promise: `CONTRIBUTING.md:221-230`'s boundary contract appears in no published
sentence, and a caller writing `except` clauses acts on every part of it.

**Four rows are new**, and three of them were reachable only by doing this pass. Row 7 sits
in `outline.md` §10 but never reached the §B table, so a worklist-driven writer would have
missed it. Row 8 was proposed *because* D-f cuts the `formats.md` loop and names Home as the
receiver; **it is dropped by decision** (Q6) and stays in the table at zero rather than
disappearing, so the drop is visible rather than silent. Row 9 comes from §A's `#236` seed:
a caller-visible contract that two specs require and no page states. Row 10 came from the
second pass (#241): `gotchas.md:90` links to `formats.md#iso-9660` for the process-global
pycdlib patch, and the landing is silent.

## Arithmetic, stated honestly

Summed from the per-page rulings, not from a computed diff — every figure below is an
estimate carrying the tolerance of ~40 blocks ruled *trim* without a line count:

| | Lines |
|---|---:|
| Guide today | 2 108 |
| New prose (the re-derived worklist) | +174 |
| Routed out — → TM, → DS, → page, Cut | ≈ −275 |
| **After pass 0's routing** | **≈ 2 007** |

D-f projects the finished guide at **~1 600–1 800**. Routing alone does not get there, and
the gap is not a disagreement: those ~40 **Trim** blocks stay in the guide, shorter. That
shrink is O-17's 20–30% on promoted maintainer prose, and it is **pass 3's**, not pass 0's.
Counting it here would spend it twice and would put a size target on a pass whose output is
supposed to be routing decisions. Routing lands ~2 007; the register pass lands the band.

---

# Where the cuts concentrate

For the step-4 checkpoint, the short read:

1. **`extracting.md` carries about 30% of the total reduction** (~−82 of ~275), and ~52 of
   those lines are one ruling: §Trust boundaries plus §What is enforced are a threat-model
   inventory that was rendered as user documentation. This is D-f's own worked case and the
   routing agrees with it block for block, including both directions on the bidi paragraph.
   Routing alone leaves the page near ~145; D-f's ~110–130 band needs pass 3 as well.
2. **The docstring leg is a `src/` writing task, not a move** (§Precondition). The prose
   largely exists as `#` comments that mkdocstrings drops on the floor. This is the single
   most consequential thing this pass found, because six rulings depend on it and because
   "move it to the docstring" sounds free and is not. **Q1.**
3. **Four pages lose most of their cut to duplication, not to depth**: `gotchas.md` (−27,
   two entries that stopped being one-liners), `support-matrix.md` (−37, a fourth copy of
   the one-live-stream default), `access-and-cost.md` (−43, benchmark evidence plus two
   rules other pages own), `formats.md` (−43, of which 29 is D-f's `hashlib` loop). Every
   one of those is the O-2 shape, and none was found by reading a page against its
   neighbour — they were found by asking which page *owns* a fact.
4. **Two pages are net-zero and should be left alone**: `philosophy.md` and
   `acknowledgements.md`. Recorded so a later pass does not re-derive them. `philosophy.md`
   is rationale by job, and `acknowledgements.md` is attribution by job; D-f's "no" leg is
   not the test for either.
5. **Three pages grow**: `how-it-works.md` (0 → ~110), `install.md` (34 → ~52, mostly the
   Q4 re-index) and `cli.md` (48 → ~60, the thinnest page against the largest recent change
   to CLI output). Nothing else nets positive; `index.md` was going to, until Q6.
6. **The worklist shrank by 62%** (~455 → ~174), and the largest single reason is not D-f —
   it is that rows 6 and half of 2, 3, 4 and 5 had already shipped in `#224`/`#225`/`#232`/
   `#235`. D-f converts about 30 more lines to docstring and threat-model tasks. Both
   halves matter: planning against the stale number would have written six sections that
   already exist.

---

# Cross-check against the second pass (#241)

A second agent ran pass 0 independently (`cursor/docs-content-scope-07a9`, PR #241).
Recorded here because the brief warns that convergence between passes with shared priors
is weak evidence — both read the same brief and the same D-f, so agreement means "we made
the same reading", not "the reading is right". Divergence is the informative half.

**Converged, without contact** — treat as settled unless a question below reopens it:
`extracting.md` is the primary cut and §What is enforced is the bulk of it; the `abort_on`
member table and the `NAME_SANITIZED` essay go to docstrings; ADR/PR citations and the
symlink layer count leave the guide; the bidi paragraph stays, shorter; `formats.md`'s
`hashlib` loop cuts to ~8; **`support-matrix.md` §Free-threaded stays** (D-f left it
unruled and both passes kept it, for the same reason — the adopter acts on the narrowness);
the config-at-a-glance screen becomes an `ArchiveyConfig` docstring with a thin pointer
under D-c; the error-translation narrative and the measurement section are real writes;
§B row 6 dissolves entirely. Two findings were also found twice: `STANDARD` missing from
the policy table, and the stale `archivey-2` link.

**Taken from #241** (four corrections, applied above): the `archivey-2` link is **O-4**,
already open, not a new finding — my S-1 was a rediscovery; must-explain #16 is **half
open**, not closed, because the page never says `ON` raises while `AUTO` falls back
silently; `formats.md` §ISO must state the pycdlib patch, because `gotchas.md:90` links
there and the landing is silent; and §Trust boundaries keeps two clauses rather than
leaving whole. One further revision came from re-reading my own rule under their pressure:
§RAR listing cost stays on `access-and-cost.md`, because a cost fact's owner is the cost
page.

**Diverged, and now decided** — Q4–Q6, each a deliverable one pass had and the other did
not, so none of them merged. The maintainer settled all three on 2026-08-17, and they split
**two to one against this pass**: the `install.md` matrix re-cut is written after all (#241,
bounded to a four-row re-index), the bounded-recursion recipe is dropped for a pointer
(#241), and Home gets no fifth recipe (#241). Recorded in §Questions with the reasoning, so
the next pass inherits decisions rather than re-running the argument.

**In neither pass's favour, but only in this one:** the §Precondition finding. #241 routes
material to docstrings without noticing that the depth it is routing *to* currently lives
in `#` comments that mkdocstrings drops, so its docstring rows read as relocations. That is
the same class of error as recording a decision in the present tense before doing the work
it depends on — the trap the brief names three times.

# Questions for the maintainer

**All six are answered** (2026-08-17). Q1–Q3 were this pass's own; Q4–Q6 were the
divergences with #241. Kept here with their reasoning rather than compressed to a verdict
list, because a fresh container has no memory and the arguments are what stop them being
re-run. Nothing in pass 0 is now blocked.

**Q1 — Does the docstring leg ship inside a docs PR? — DECIDED 2026-08-17: it rides with
the page PR.** Six rulings route a block to a docstring, which means editing `src/`
(promoting an existing `#` comment to a `"""` docstring — no behaviour change, no signature
change) against the brief's "no library changes in a docs PR". **Maintainer: read that
constraint as being about behaviour.** Each page PR carries the docstring promotions its
own cuts depend on, so a page never merges linking to a docstring that does not exist yet
and a reviewer sees the fact *move* rather than vanish.

**The carve-out, stated so it is not re-argued per PR:** a docs PR may touch `src/` **only**
to add or reword a docstring or an attribute docstring, with no change to any statement,
signature, default, annotation or control flow. Anything else — including a one-character
behaviour fix noticed while writing the docstring — is still `#225`'s shape: a finding, a
repro, and its own red–green PR. Each page PR that carries a docstring change should say so
in its body and name the guide block it drains, so the pairing is visible in review.

**The six** (all have `api.md` entries, so all surface): `AbortOn` members ·
`ExtractionStatus` values · `ExtractionResult` fields where the guide's Need-to-know table
drains into them · `CostReceipt` fields · `DiagnosticCode.STREAM_REWIND_REDECOMPRESSES` ·
`ArchiveyConfig` (the config-at-a-glance screen).

**Q2 — `support-matrix.md` §Free-threaded — DECIDED 2026-08-17: keep at ~65 lines.** D-f
flagged the 105-line section as "not ruled here… it serves a small minority today" and
handed it to this pass; it is the one block D-f declined to decide. **Maintainer: keep at
~65** — section 105 → ~65, page 152 → ~115.

What that cuts is **cross-page duplication only**: §The default is fail-fast, not racy (a
fourth copy of the one-live-stream default, after `reading-members.md:22-28`,
`access-and-cost.md:125-137` and `philosophy.md:39`), the `ConcurrentAccessError`-outside-
the-tree paragraph (`errors-and-diagnostics.md:33-39` owns it), and the duplicated "Measured
on CPython 3.13.7t" line. **No free-threading fact is cut** — the measured extras table, the
CI-proves scope, the two install consequences, the GIL-still-disabled assertion, the
what-is-*not*-claimed list and the thread-safety summary all survive.

**The reasoning, recorded because "serves a small minority" will be re-raised:** D-f asks
whether a reader *acts*, not how many readers there are. The extras table answers "which
extras keep the GIL disabled on 3.13t", which is an install decision derivable from no other
page and no docstring. And the section is long *because* the claim is narrow — compressing
a deliberately scoped safety claim is how it starts sounding broader than CI proves, which
is O-16's failure mode on the page the outline calls "the most honest page on the site".
**D-f's open flag is now closed**, not deferred again.

**Q3 — §D's shape — DECIDED 2026-08-17 on *timing*, not on shape: settle §D before pass 6
writes `errors-and-diagnostics.md`.** The table at `6-32` is ruled Keep *because* 21 of the
exception types have no `api.md` entry, so it is currently the exception tree's only
reference; if §D adds those entries, the table becomes a genuine lookup and should shrink
in the same pass. **Maintainer: resolve the coupling before the prose, not after** — the
page gets written once, against a known reference surface.

**What is still open: which of the brief's three shapes** — enumerate all 87, enumerate a
documented subset with the opening sentence corrected, or generate the list. Pass 0 does
not take that; it is `QUESTIONS.md`'s, and it now carries a **deadline** rather than
sitting undated: it must be answered before the errors page is written, which puts it
between step 3 (claim inventory) and step 6 (prose).

**What would settle it**, so the decision is not taken on vibes: the claim inventory says
how much of the 7-row table is *accurate* and how many of the 21 types a reader is ever
told about. A tree that is mostly unreferenced argues for generate-the-list plus a
guardrail; one whose types are already named across four pages argues for enumerating them
deliberately with the opening sentence fixed. Either way `brief.md` §D requires it to end
as a test rather than a preference (Definition of done row 8).

*Q4–Q6 are the live disagreements with #241 (see §Cross-check). Each is a deliverable one
pass has and the other does not, so none of them merges — they are decisions.*

**Q4 — `install.md`: re-cut the format × extra matrix? — DECIDED 2026-08-17: write it, as a
four-row re-index.** I had dissolved the row as O-2-shaped duplication (`formats.md:8-20`
and `acknowledgements.md:63-68` each already carry a cut of this data); #241 kept it as a
write, on the ground that neither existing table is organised by *what the reader types*.
**Maintainer: write it, bounded.** One row per extra — core / `[recommended]` / `[seekable]`
/ `[free-threaded]` — naming which formats it unlocks and linking out, ~12 lines. It is a
**re-index, not a third source of truth**: `formats.md` stays authoritative on per-format
capability, and the row must not grow columns that duplicate it. The bounded duplication is
accepted deliberately so the page answers its own question; whoever writes it should expect
the guardrail conversation (§D's shape) to eventually cover it.

**Q5 — the bounded-recursion recipe: worked, or a pointer? — DECIDED 2026-08-17: pointer.**
`brief.md` §B listed it as still-open work ("the worked recipe stays Topic 8", round-2
finding 3) and I had routed ~12 lines to `extracting.md` §Limits; #241 ruled the opposite.
**Maintainer: keep the pointer, drop the row.** The paragraph already at
`extracting.md:203-206` plus `gotchas.md:41-44`'s one-liner is the guide's whole coverage;
the amplification analysis stays threat-model O6's, and a code block re-proving it would be
threat-model material wearing a recipe. This is a **decision that supersedes the §B row**
(`brief.md` §Definition of done row 2), not an unwritten row — recorded so no later pass
re-derives it as outstanding work.

**Q6 — does Home get a fifth recipe? — DECIDED 2026-08-17: no.** D-f's `formats.md` ruling
("keep the use case visible via a Home recipe") supports both readings; I read it as
requiring a receiver on Home, #241 read it as satisfied by the existing four.
**Maintainer: no fifth recipe.** `index.md` §Thirty seconds stays at four, and "any fifth
recipe" joins its non-coverage list.

**What this means for the cut, stated precisely** (hard constraint: a claim removed must
land or be recorded as dropped):

- **Dropped from Home:** the dedupe use case has no first-screen presence, by decision.
  VISION's founding use case is therefore not visible on `index.md`. Recorded, not
  accidental.
- **Not dropped from the guide:** D-f's "cut to ~8" leaves a short snippet on
  `formats.md` beside the stored-digest matrix, which D-b put there deliberately. That
  snippet is now the guide's **only** dedupe example, which raises its floor — it has to
  stand on its own rather than as a pointer to something on Home. Whoever writes the cut
  should keep the stored-vs-computed provenance idea in it, not just the lookup.
- **A consequence for Topic 7:** the adoption capstone asks whether the docs persuade, and
  the founding use case now appears on no landing surface. That is a legitimate thing for
  it to re-raise; it is not a rediscovery of this decision, it is a different question
  about the same fact.

---

# Findings

**No library defects found.** This pass read `docs/`, six `src/` docstring sites and the
mkdocstrings configuration; it edited nothing under `src/`.

Two non-defect items, recorded here so pass 1 does not re-derive them, and neither resolved:

| # | Where | Item |
|---|---|---|
| S-1 | `docs/access-and-cost.md:18` | The nightly-run link points at `github.com/davitf/archivey-**2**/actions/runs/29992136861`. **Already recorded — this is [O-4](../archive/2026-10-06-docs/observations.md), open**, from the IA audit: the repo was renamed 2026-07-25 and GitHub redirects, so it resolves but is stale. Cite O-4; do not file it again |
| S-2 | `docs/extracting.md:145-149` | The policy table has two rows for a three-member enum: `STANDARD` is absent while the page's prose uses it four times (`51`, `71`, `173`, `175`). An accuracy row, listed here because the block was ruled Keep and the gap would otherwise be inherited silently. Independently found by the second pass (#241) |

---

# What pass 0 did not do

- No guide prose written, and no file under `docs/` edited.
- **D-a–D-e untouched.** Page boundaries, nav order, the `reading.md` split, `extracting.md`'s
  name and the damage contract's home all stand. Every → page ruling above moves a *duplicate*
  to the page that already owns the fact; none moves an owner.
- **No claim verified.** Every "shipped" above is a statement that prose exists at a cited
  line, not that it is true. That is `claims.md`'s job, and the two rows in §Findings are
  the two places this pass tripped over something that looked wrong while routing.
- **`outline.md`'s projected-sizes table was not used as targets** — it carries a note saying
  it is not one, and it targets `extracting.md` at ~280 where D-f targets ~110–130.
