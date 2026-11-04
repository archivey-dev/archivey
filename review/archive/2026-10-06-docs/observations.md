# Observations — content problems noticed while auditing

**Recorded, not acted on.** Rewriting page content is out of scope for this review
(brief, *Out of scope*); it is Topic 8 (`review/backlog.md:162`). The audit reads
every file anyway, so recording these is free. Topic 8 should start here rather
than from zero.

Cited against `4f154b9` (`main` @ `ce674bf` plus this review's prompt commits).
Where a claim depends on something not verified, it says so.

---

## O-1 — `AGENTS.md` makes two statements that are false today

`AGENTS.md:11-16`:

> there is no server, web UI, or runnable CLI (the `archivey` command in
> `openspec/specs/cli/spec.md` is planned, not implemented) … Implemented backends
> are ZIP, TAR, ISO, directory, and single-file-compressed …; **7z and RAR readers
> are not implemented yet** despite their specs/extras existing.

Both are wrong:

- The CLI ships. `pyproject.toml:49-50` declares
  `archivey = "archivey.cli.main:main"`; `src/archivey/cli/` exists; it landed in
  #120 and has an archived product review (`review/archive/2026-07-20-cli-product/`).
- The native readers ship. `src/archivey/internal/backends/sevenzip_reader.py` and
  `rar_reader.py` exist; `CONTRIBUTING.md:96` describes the core as including
  "native 7z read + RAR metadata".

**Severity: high for an agent guide** — an agent that believes this will not run
the CLI, will not test 7z/RAR paths, and may re-propose work that is done. This is
also the strongest argument for the `AGENTS`/`CLAUDE` consolidation (Q5): the file
that is *not* the canonical one is the one that rotted.

---

## O-2 — The rapidgzip gzip-truncation caveat exists four times; two copies are stale against the spec

The authoritative text, `openspec/specs/seekable-decompressor-streams/spec.md:125-126`:

> … for **any declared-seekable source** — a path or a caller-owned `BinaryIO`
> alike — **not only path sources**.

| Copy | Says | Correct? |
|---|---|---|
| `docs/gotchas.md:87` | "Archivey backstops **any seekable source** — a path or a caller-owned `BinaryIO` alike" | ✅ |
| `docs/internal/known-issues.md:158-162` | "on **any seekable source** (path or caller-owned `BinaryIO`)" | ✅ |
| `docs/formats.md:132` | "With the `[seekable]` rapidgzip accelerator on a **path** `.gz`…" | ❌ narrower than the spec |
| `docs/internal/open-issues.md:132-133` | "(empty→stdlib + single-member ISIZE on **path sources**)" | ❌ narrower than the spec |

This is the concrete case that the duplication is not theoretical: the same fact,
written four times, has already drifted in two of them. Both stale copies
under-promise (they describe an older, narrower backstop), so no user is misled
into unsafety — but a user reading `formats.md` will needlessly set
`use_rapidgzip=OFF` for a `BinaryIO` source that is in fact covered.

**Not a pause-and-ask case.** The spec is unambiguous and the prose is simply
behind it; there is no decision to make. Topic 8 fixes the two copies; this
review's §3 of [`page-shape.md`](page-shape.md) removes the reason a fifth copy
would ever be written.

---

## O-3 — `rapidgzip-upstream-report.md` points at a path that moved to the archive

`docs/internal/rapidgzip-upstream-report.md:11`:

> `openspec/changes/rapidgzip-truncation-investigation/UPSTREAM_TRUNCATION_REPORT.md`

That change was archived; the file is now at
`openspec/changes/archive/2026-07-24-rapidgzip-truncation-investigation/UPSTREAM_TRUNCATION_REPORT.md`
(verified — the file exists there and not at the cited path). It is written as
inline code, not a Markdown link, so `mkdocs build --strict` does not catch it.
This is exactly the class the phase-4 link checker exists for.

---

## O-4 — A published user page links to the pre-rename repository

`docs/costs.md:17` links the nightly benchmark run at
`https://github.com/davitf/archivey-2/actions/runs/29992136861`. The repo was
renamed to `davitf/archivey` (`CHANGELOG.md:42`;
`docs/internal/release-repo-cutover.md:7` records the rename as done 2026-07-25).
GitHub redirects renamed repositories, so the link most likely still resolves — it
is the wrong name on a user-facing page either way, and
`release-repo-cutover.md:62` explicitly listed "fix references" as a cutover step
that this one escaped.

**Not verified:** whether the redirect actually resolves (no outbound check made).

---

## O-5 — Six pages are built and reachable but absent from the nav

Confirmed by running the build. `uv run --group docs mkdocs build --strict` at
`ce674bf` is **green** and prints:

```
INFO - The following pages exist in the docs directory, but are not included in the "nav" configuration:
  - decisions/0014-integrity-verdicts-from-reads-not-close.md
  - internal/ppmd-exit-after-green-exploration.md
  - internal/ppmd-native-investigation-brief.md
  - internal/ppmd-native-investigation-results.md
  - internal/pyppmd-upstream-report.md
  - internal/rapidgzip-upstream-report.md
```

`--strict` does not fail on this. 1,846 lines are published at a URL, indexed by
the site search, and unreachable by navigation. Phase-4 guardrail #1 is a
non-empty check on this exact line.

---

## O-6 — ADR 0014 is marked `Status: accepted` but has an `## Open questions` section

`docs/decisions/0014-integrity-verdicts-from-reads-not-close.md:3` says
`**Status:** accepted`; line 493 opens `## Open questions`. The other 13 ADRs have
no such section. Related: at 615 lines it is 59% of the whole ADR corpus and ~25×
the median (24 lines) — see Q4. The `## Open questions` content also overlaps the
open `verification-integrity-mode` proposal (PR #185), which is where open
questions normally live.

---

## O-7 — User-facing security prose lives in `SECURITY.md`, not the guide

`SECURITY.md:68-89` ("Hardening notes for callers") tells users to leave
accelerators off for untrusted input under a latency budget, that `unrar` is part
of their deployment's trust boundary, and to extract into a scratch directory
before promoting. That is guide content in a file GitHub renders for vulnerability
reporters. `docs/safe-extraction.md` says none of it.

`SECURITY.md` should keep the reporting policy and scope; the caller guidance
belongs in `safe-extraction.md` with a link back. Folded into the growth plan in
[`page-shape.md`](page-shape.md) §1.

---

## O-8 — `docs/internal/index.md` understates `known-issues.md` by an order of magnitude

`internal/index.md:10` describes it as "Accelerator lifecycle / macOS coexistence
notes". The file is 709 lines covering stdlib `tarfile` EOF leniency, the pycdlib
process-global monkeypatch, three rapidgzip bugs, two distinct pyppmd native-abort
families with a version matrix and valgrind evidence, and an open intermittent
full-suite heap corruption with CI bandages and a bisect recipe. A contributor
reading the index will not open it, which is the opposite of what an index is for.

---

## O-9 — `open-issues.md` is a dated snapshot that has aged

`docs/internal/open-issues.md:10` pins itself to "2026-07-18 against `main` @
`93dc28e`" with one 2026-07-25 amendment. Since then #149/#162/#183/#191/#206/#207
and the #209 extras work have landed. Item **P6** (line 83) cites "PR #101 (still
open) / `docs/internal/rar-unrar-piping-investigation.md` (when merged)" — that
file does not exist in the tree, so the reference is to a future state that has not
arrived (PR #101 is indeed still open — verified against the repo's open PR list).

The dated-snapshot format is honest and better than an undated one. The
observation is only that it needs a refresh pass, which Topic 8 or the release
checklist can own.

---

## O-10 — `docs/grab-bag/` prose has drifted, as its own index predicts

Declared non-normative, so this is **not a defect** — recorded because it is the
evidence for "unpublish, don't delete" (Q1) rather than for keeping it visible to
users:

- `ARCHITECTURE.md` §1 module layout lists `internal/streams/decompressor_stream.py`;
  the file is `internal/streams/decompress.py`. It also annotates the 7z/RAR
  backends as "Phase 7" — they are Phase 6 (`openspec/project.md:101`).
- `SPEC.md` §2 lists a `[7z-write]` optional extra. It does not exist;
  `openspec/project.md:44` says "7z writing is not shipped (no `[7z-write]`)".
- `COMPARISON.md` carries a decision it explicitly records as later reversed (the
  `Intent` enum), which is correct behaviour for a historical document.

A user searching the published site for "7z-write" today finds an extra that was
never shipped.

---

## O-11 — Minor: the brief's own per-home line counts are transposed

`brief.md:45-46` gives `docs/internal/` 3,968 lines and `docs/grab-bag/` 2,831.
Measured: **3,731** and **3,068** — the same 237 lines attributed to the wrong
home. File counts (12 and 6) and the totals (6,799 non-user of 8,281 published,
excluding `decisions/`) are correct, so the headline "≈82% non-user" stands
unchanged. `docs/` is byte-identical between the brief's `403e7ff` baseline and
`ce674bf`, so this is a transcription slip, not drift.

Also `brief.md:170`: the code comment to update is at
`src/archivey/internal/streams/decompress.py`, not `decompressor_stream.py` (that
filename exists only in the stale grab-bag module map — see O-10).

---

## O-12 — Two runtime error messages embed documentation paths

`src/archivey/internal/streams/decompress.py:453` and `:467` raise `ValueError`s
whose text ends `"… — see docs/internal/known-issues.md)"`. These are strings a
user can see. They are repo paths, not URLs, so they are only actionable for
someone with a checkout — which stays true after the proposed move to
`dev-docs/known-issues.md`, but the strings must be updated in the same commit.
Listed in [`inventory.md`](inventory.md) §Migration mechanics.

Whether an error message should cite a maintainer document at all is a Topic 8
question, not one this review takes.

---

## O-13 — Coordination: the in-flight extras change will move the install story

`openspec/changes/consolidate-optional-extras/` (landed after the brief's baseline,
#209) proposes changing the optional-extras set. `docs/usage.md:5-9`,
`docs/formats.md:8-24`, `docs/acknowledgements.md:57-73` and
`docs/support-matrix.md:60-80` all encode the current extras. The proposed new
`install.md` ([`page-shape.md`](page-shape.md) §2) is where that lands.

**Sequencing note, not a finding:** if the extras change ships before the docs
migration, `install.md` should be written against the new extras rather than
migrated and then rewritten.

---

## O-14 — Three published pages attribute BLAKE2sp to an extra; it is native and zero-dep

**Closed 2026-08-03** — verified fixed on `main` @ `d34489f`. All three copies now
state that BLAKE2sp needs no package: `docs/formats.md:16`, `docs/formats.md:105`,
`docs/acknowledgements.md:73`. `consolidate-optional-extras` (#212) fixed the
published pages alongside the `pyproject.toml` comment, which is what the last
paragraph below asked for. Recorded here rather than deleted, because the closing
argument still stands: a structural audit reading every file for *filing* did not
catch a factual error on a user page.

Added 2026-07-29 during maintainer review of this audit, so numbered after the fact.

`src/archivey/internal/hashing/blake2sp.py` implements BLAKE2sp on stdlib
`hashlib` — no third-party package, no extra. Three published lines disagree:

| Line | Says | Correct? |
|---|---|---|
| `docs/acknowledgements.md:64` | `[rar]` / `[crypto]` → cryptography "(Blake2sp backend still TBD)" | ❌ nothing is TBD; it shipped natively |
| `docs/formats.md:16` | RAR needs "`[rar]` for header crypto / Blake2sp" | ❌ conflates the two; only header crypto needs the extra |
| `docs/formats.md:101` | "`[rar]` / `[crypto]`: header-encrypted RAR5 **and Blake2sp verification**" | ❌ same conflation |

A user reading any of these installs an extra they do not need, or concludes RAR5
hash verification is unavailable to them when it is always available.

This is the published twin of `code-self-documentation.md` B1, which found the same
stale claim in `pyproject.toml:69-74`. B1 was scoped to the packaging comment; the
docs copies were not noticed by either pass. `consolidate-optional-extras` task 1.2
already deletes the `pyproject.toml` half, so **the two halves should be fixed in
the same change** rather than leaving the published pages behind — see that change's
task 4.4.

**Worth noting for Topic 8's framing:** this is a factual error on a user page that
a structural audit reading every file for *filing* did not catch. It is evidence
that the content pass has to be its own deliberate read, not a byproduct.

---

## O-15 — `known-issues.md` needs a triage pass after the IA move (D9)

Recorded with Q7 B. Phase 3 only moves the file to `dev-docs/known-issues.md`.
A **required follow-up** (Topic 8 accuracy pass, or a dedicated small change)
classifies every section: resolved (ours) / mitigated (ours) / upstream
unfixable / open we-can-fix / evidence-only — and routes items to IDEAS,
`open-issues`, threat-model register, or `investigations/` per
[`DECISIONS.md`](DECISIONS.md) D9. Also rewrite the Gotchas accelerator bullet
for `_TrappingSource` (Bug 3 is contained; “process dies” is stale).

---

## O-16 — The integrity guarantee overstated what a `CorruptionError` means

Raised by the maintainer 2026-08-04, reading the moved text on
`docs/reading-members.md`, and **fixed in `docs-ia-split-user-guide`** rather than
deferred: it is a factual error about a load-bearing safety claim on a published page.

The moved-in wording said a `CorruptionError` means *"discard everything read from this
member; none of it is trustworthy"*. The ADR it came from qualified that with "as a
complete intact member", but the bolding buried the qualifier and the sentence read as
the stronger claim.

What is actually true, and what the page now says:

| Claim | Correct version |
|---|---|
| Bytes read before a `CorruptionError` are worthless | **Unknown quality.** On a compressed member that fails mid-stream, some are probably fine — we cannot say which, or how much. Unverified, not known-bad. |
| `CorruptionError` vs `TruncatedError` tells you what happened | **A best-effort label, not a diagnosis.** Damage that decodes into a shorter stream is indistinguishable from real truncation. Don't branch on it. |
| Every error raises | **We try to raise on every error we can detect.** Some formats store no checksum; some damage decodes to something valid-looking. |

No spec had to change — `compressed-streams` specifies the *exception mapping*
(corrupt → `CorruptionError`, short → `TruncatedError`), not the reliability of the
distinction or the status of the prefix. `dev-docs/investigations/adr-0014-investigation.md`
carries a note recording the sharpened reading next to the original reasoning.

A third point was added the same day, and it is the reassuring half: **a chunked read
loop delivers every readable byte and then raises.** `read(member.size)` returns short
and quiet, but the next read raises — so `while chunk := stream.read(n)` cannot end
silently on a truncated member. Verified against
`tests/test_codecs.py::test_verify_expected_size_short_chunked_then_empty_raises`,
which asserts the loop collects the whole available prefix before the `TruncatedError`.
The page now shows that loop as the recover-the-prefix recipe.

**For Topic 8:** do not restore the stronger phrasing when tightening this section, and
keep the chunked-loop guarantee — it is the answer to "how do I get what is readable
out of a damaged member".

*(Correction 2026-08-04: an earlier draft called that a "VISION founding use case".
It is not. VISION's two load-bearing claims are safe-by-default and memory-safe
parsing of hostile input; the founding use case is indexing and deduplicating messy
backups, and "damaged input is a first-class citizen" is one of five priorities that
origin story implies — and that bullet is about not failing at open, i.e. the listing
side, not the read contract.)*

---

## O-17 — Dev-doc register leaked into the user guide

Raised by the maintainer 2026-08-04. Several pages read as too technical for their
audience, which is the predictable cost of the IA migration: `safe-extraction.md` took
its enforced-guarantees list from a threat model, `reading-members.md` took its
guarantee from an ADR, and `formats.md` was always written close to the specs. The
prose is accurate; the register is wrong for the reader.

**The audience, stated so the rewrite has a target:** a working developer who is not a
compression or archive-format specialist. They know Python and streams. They do not
know what a "solid folder", an "ISIZE trailer", a "check value" or a "terminal
boundary" is unless the page says.

**Rules for the Topic 8 rewrite:**

1. **Define or drop the jargon.** First use of a format term gets a half-sentence gloss,
   or the sentence gets rewritten without it.
2. **Lead with what the reader does, not with the mechanism.** "Don't close the source
   underneath a live stream" before the explanation of why the C++ layer objects.
3. **Cut the provenance voice.** "This is a deliberate idiom, not a trap", "the
   load-bearing asymmetry", "target contract; best-effort today on a few backends" are
   ADR register — they argue with a reviewer who is not present.
4. **Be shorter.** Most of these sections lose 20–30% with nothing of substance gone.
   The guarantee section on `reading-members.md` is the worked example: rewritten for
   O-16, it is both more accurate and shorter.
5. **Keep the honesty.** Plainer is not vaguer. "We can't tell which bytes are good"
   is plain *and* precise; "the prefix is best-effort salvageable" is neither.

---

## O-18 — Reader close vs escaped member streams: docs are right, but the design was questioned

Raised by the maintainer 2026-08-04 on the outline's must-explain #20 line ("closing
the reader does not invalidate already-open streams") — *"doesn't it? that surprised
me."*

**Checked, and the docs are correct.** It is specified
(`archive-reading/spec.md:543-580`, "Context-manager and close lifecycle"), tested
(`tests/test_member_streams.py::test_post_close_reader_ops_are_usage_errors`), and
**consistent across all seven backends** — zip, tar, tar.gz, bare gz, directory, 7z and
RAR all read fine after `reader.close()`, and `stream.close()` afterwards is clean. So
there is nothing for Topic 8 to fix in the prose.

One wording nuance worth keeping in mind when tightening: the spec requirement says a
stream **MAY** remain usable, while its own scenario table states it as an outcome. The
guide currently promises the stronger version. If the behaviour is ever revisited, the
guide is the thing that has to change first.

**What the check turned up is a product question, not a docs one**, and it is filed as
`dev-docs/open-issues.md` **P7**: an unclosed member stream leaks a file descriptor
that GC never reclaims (+1 on every backend measured), and `reader.close()` does not
release it. That is closer to the hazard the maintainer's instinct was pointing at than
the read-after-close behaviour itself.


---

## O-19 — Broken anchors ship silently; the guardrail now covers them

**Found while writing `opening-and-listing.md` (Topic 8, page 1).** Three links in
the published tree pointed at headings that do not exist:

| Link | Where | Why it broke |
|---|---|---|
| `gotchas.md#passwords-that-look-accepted` | `formats.md:98` | Section deleted by the Gotchas shrink |
| `gotchas.md#format-limitations` | `formats.md:148` | Same |
| `access-and-cost.md#accelerators-and-process-aborts` | `gotchas.md:47` | Heading is "Accelerators and source **lifetime**" |

All three were created by `docs-ia-split-user-guide` and shipped green. This is
finding **F5** in the flesh: `mkdocs build --strict` reports a missing anchor at INFO
level and then exits 0, exactly as it does for a page missing from the nav.

**Fixed, in both senses.** The two `formats.md` links were pointing *backwards* — the
digest rule (D4) says Gotchas links to the page that owns a fact, not the reverse, and
`formats.md` already stated both facts in full, so the link sentences are gone rather
than repointed. The third is repointed. And `scripts/checks/check_docs_nav.py` now resolves
every intra-`docs/` anchor, cross-page and same-page, deriving the ids by running each
file through Python-Markdown's own `toc` extension rather than reimplementing the slug
rule — so the check cannot drift from what the site serves. Verified against planted
failures of both kinds.

Worth having before the rewrite rather than after: moving a heading is the single most
common thing the remaining ~455 lines of prose will do.

**One register leak fixed in passing:** `formats.md` §7z said "See threat-model O8",
citing an unpublished maintainer document by internal item number. That is O-17's
failure mode with a dangling reference on top.

---

## O-20 — `open_archive` does not accept bytes

**Outline correction, not a docs bug.** `outline.md` §3 listed the sources as "paths,
file objects, directories, byte sequences". There is no `bytes` source:
`OpenSourceInput = SourceItem | SourceSequence` with `SourceItem = str | Path |
BinaryIO` (`internal/volumes.py:21-22`), and `_is_source_sequence` explicitly excludes
`bytes` so a bytestring is never mistaken for a sequence of sources. "Byte sequences"
was a misreading of the multi-volume sequence type. The written page says paths,
directories, streams, and ordered sequences of those.

---

## O-21 — Review round on `opening-and-listing.md`: what the register rules were missing

**14 maintainer comments on the first written page (#224).** Four were factual
corrections, and all four were right. Recording them because the pattern generalises
to the remaining fourteen pages.

**The four factual errors, all mine:**

1. **"The question is settled when you open the file"** (deferred inner-TAR) was
   simply wrong. `open_archive` calls the same `detect_format`, so it gets the same
   answer; when the codec is absent the *open* fails with a missing-package error.
   Nothing is resolved later.
2. **`.gz` was the example** for the missing-codec case, and `gzip` is stdlib — the
   case cannot arise for it. The optional codecs are zstd (below 3.14), lz4, brotli,
   ppmd and deflate64.
3. **"An embedded archive needs no slicing"** overstated it. `fix_stream_start_position`
   wraps a mid-positioned stream with a `start` and no `end`, so the archive is taken
   to run to EOF. Trailing data is the caller's problem.
4. **"A non-seekable stream is fine too"** was true for only half the formats.
   `SUPPORTS_STREAMING_NON_SEEKABLE` is `True` for TAR and single-file compressors,
   `False` for ZIP, 7z, RAR and ISO.

**And one thing I never wrote:** multi-volume sets are discovered from *any single
volume path* (`discover_volume_siblings`), across three naming schemes, with 7z sets
checked for completeness. I had documented only the explicit-sequence form — the
power-user path — and omitted the one nearly every caller will use.

**The generalisation.** The O-17 register rules are about *how* a sentence reads;
every one of these is about whether it is true, and four of five came from writing
confidently about a mechanism after reading only the function that names it. The
per-page procedure needs a step the first pass did not have: **for each behavioural
claim, find the line that implements it, and check the branch where it does not hold.**
Every error above lived in that branch — the codec that is absent, the stream that has
data after it, the backend whose flag is `False`.

**Three register findings worth carrying forward**, beyond O-17's list:

- **Say when a reader can skip something.** `detect_format` needed "most callers never
  need this: `open_archive` detects the format itself" more than it needed detail.
- **Informality can cost clarity.** "A pipe or anything else you cannot seek in" is
  worse than "a pipe or another non-seekable stream" — it sounds friendlier and is
  harder to parse.
- **Internal mechanism is not user-facing behaviour.** "Archivey buffers what it peeks
  at during detection and replays it" describes a correct implementation detail the
  reader can do nothing with; the behaviour is just "you can open a non-seekable
  stream".

**One product issue filed:** `dev-docs/open-issues.md` **P8** — a directory path
silently discards an explicit `format=`. The maintainer's instinct that it should
raise is right; it is the only case where an explicit format assertion is overruled
without a diagnostic.

**One gap the self-review caught, of the same class as O-19:** `gotchas.md` links to
`#duplicate-names-and-is_current` for the `get()` last-wins footgun, and the section
never stated it — a link landing on a page that does not carry the fact. Stating it
turned up an inaccuracy in the Gotchas line itself: it named
`extract_all(members=["x"])` as the hazard, but `extraction.py:364` hardwires the
`is_current` skip after the filter, so extraction is safe. `stream_members` has no
such skip, and is the real one. Both pages now say so.

---

## O-22 — Two more register rules, and the opening/reading boundary

**From the second review round on #224, plus writing `reading-members.md`.**

### Table cells stay short

Maintainer, generalising from a five-line cell in the "What you can open" table:
*"table cell contents should be succinct; if it grows too much, it's probably better
to add details to the text afterwards."* Adopted as a rule for every page. The failure
mode is easy to fall into, because a table looks like the tidy place to put a
conditional rule — but a cell has no room for the *why*, and the reader ends up
parsing a paragraph laid out as a column. The fix is mechanical: cell states the
answer, prose below carries the condition and the reason.

Applied: the non-seekable-stream row went from five lines to nine words, with the
format list and the "their index sits at the end" reason moved into prose.

### Rule: the boundary is the reader's question, not the call name

The maintainer asked whether the read-cost material on `opening-and-listing.md` should
move to the reading page, and where `stream_members()` belongs. Both resolve the same
way, and it is the rule the outline already stated for the split — *contract here,
consequences there* — applied to a case the outline did not name:

| Belongs to **Opening** | Belongs to **Reading** |
|---|---|
| The open-*time* decision: `streaming=`, what a source can be | The read-*time* strategy: `open()` vs one forward pass |
| What is in the archive: listing, detection, names, passwords | What comes out of a member: bytes, integrity, stream lifetime |

So the solid-archive cost argument moves to Reading, where it is the reason to choose
`stream_members()`, and `stream_members()` itself is a Reading topic — the outline had
already decided this ("its hard parts are stream lifetime and laziness, which are
stream contract, not enumeration"), and the confusion came from Opening having grown a
strategy section that was never its job. Opening keeps one sentence and a link.

The stronger form: **a page owns a decision if the reader makes it while doing that
page's job.** Choosing `streaming=True` happens with your hand on `open_archive`.
Choosing between `open()` and `stream_members()` happens when you want bytes.

### The new check earned its place immediately

O-21's procedural fix — for each behavioural claim, find the implementing line *and*
check the branch where it does not hold — caught an error in the first page written
after it. I wrote that Archivey warns (`STREAM_REWIND_REDECOMPRESSES`) when a solid
archive is read out of order. It does not: that code is emitted from one site
(`archive_stream.py:442`), for a backward **seek inside a member**, and no diagnostic
or log warning exists for the solid case at all. The page now says the cost is silent.

That turned up a **spec overstatement** rather than only a docs error:
`archive-reading/spec.md:476-477` promises that random `open()` on a solid archive
"may re-decode from block start **and warn** to prefer `stream_members()`". Filed in
`dev-docs/open-issues.md` under docs/specs drift — either the diagnostic gets added or
the spec drops the clause.

### One thing deliberately left undocumented

Must-explain **#20** ("closing the reader does not invalidate already-open streams")
is *not* stated on `reading-members.md`. It is true today and verified across all
seven backends (O-18), but the spec says a stream **MAY** remain usable, the
maintainer has said closing-on-reader-close seems safer, and **P7** may change it. The
page gives the advice that survives either decision — close streams before closing the
reader, which `with` does for you — plus the resource consequence, which is P7's
user-visible half. Documenting the permissive behaviour would be documenting something
there is active intent to remove.

---

## O-23 — Diagnostics describe the archive, not the caller

> **Retired by `extraction-results-authoritative`.** The rule this observation
> proposed is no longer the admission test for a `DiagnosticCode`. The taxonomy's
> ceiling now lives in `openspec/specs/diagnostics/spec.md` as two clauses —
> **admission** (report only what the caller could not have determined from the
> declared contract of the call, and can act on) and **placement** (when an operation
> returns a structured per-item report, that report is the sole carrier of per-item
> outcomes). The archive-versus-caller split below is **descriptive only**: it
> accurately characterises the shapes most codes happen to have, and it decides
> nothing. See `dev-docs/discussions/2026-08-diagnostics/diagnostics-archive-vs-usage.md`
> and the three reviewer opinions alongside it for why. The rest of this entry is kept as the
> record of what was ruled at the time.

**Maintainer ruling, deciding the solid-warning question from O-22.** The spec
promised a warning on solid out-of-order `open()` that no backend implements. The
resolution is not "add the diagnostic" but a boundary that was never written down:

> Diagnostics are archive-related, not usage-related.

Every existing code was taken to fit it — a normalized member name, an inferred
encoding, a format/extension conflict, a missing EOF marker, an invalid timestamp, an
unverifiable digest, a degraded seek index — each describing something true about the
bytes the caller was handed. "You opened members out of order" describes the program
doing the reading. It belongs in the API documentation, and it is now in the
`ArchiveReader.open()` and `.read()` docstrings, which render into `docs/api.md`.

That outcome still stands; the *reason* is now the admission clause rather than the
archive/usage cut. "You opened members out of order" is refused because it restates
advice the API surface already carries, not because it describes the caller.

`spec-drop-unimplemented-solid-warning` removes the clause from both places it
appeared. A plain `warnings.warn` was left explicitly undecided.

**One code sits awkwardly against the rule and is worth a later look:**
`STREAM_REWIND_REDECOMPRESSES` fires because the *caller* sought backwards. It is
defensible on the reading that its message states a property of the codec ("this codec
has no random-access index"), surfaced at the moment it costs something — but if the
rule is taken strictly, this is the one existing code that reports a usage pattern.
Not raised as a question because nothing depends on it: it ships, it is documented on
`gotchas.md` and `access-and-cost.md`, and renaming or recategorising it would be
churn. Flagged so the rule is not later read as inconsistent by accident.

*Resolved by the retirement above:* the code was never inconsistent, the rule was.
`STREAM_REWIND_REDECOMPRESSES` passes admission (a caller cannot know from the
declared contract that this particular backward seek will re-decompress) and has no
return-value home, so it keeps its place in the taxonomy. Its usage-pattern character
now decides only its *preset* membership — it is excluded from
`ARCHIVE_INTEGRITY_CODES`, and so from `DiagnosticPolicy.strict()`, as a deliberately
targeted tripwire rather than an archive-integrity fact.

**Process note.** This is the second finding in two pages where writing user-facing
prose caught a *spec* defect rather than a docs one. Both were invisible to
`openspec validate --strict`, which checks structure, not whether a requirement
describes shipped behaviour. Worth remembering when estimating the remaining pages:
the accuracy pass is finding things outside its own scope at a steady rate.

---

## O-24 — P7 resolved by re-reading the principle, not by weighing the options

**The maintainer chose option B** (close member streams on `reader.close()`), which the
P7 write-up had argued against. The deciding move was not a trade-off judgement but a
correction to what the governing sentence says:

> "never silently close/invalidate a held stream" (`archive-reading/spec.md:83`)

That sentence sits **inside the concurrency-gate paragraph**. It is the rule that makes
a second overlapping `open()` raise `ConcurrentAccessError` instead of quietly closing
the first — a rule about how *contention* is resolved, not about lifetime. P7 quoted it
as a general principle and built the escaped-stream contract on top of it. Checked, and
the maintainer is right: the paragraph is entirely about the gate.

**Two things in my own P7 analysis were wrong**, both found only by implementing it:

1. **"B routinely exercises the Bug 3 accelerator trap" — false.** Teardown was already
   deferred until the last lease dropped, so the source was never closed under a live
   stream. B closes the stream *first* and tears down after, which is the safe order.
   The hazard I warned about was the one the existing design already avoided, and B
   preserves.
2. **The fd leak was a plain bug, not a consequence of the design.** The safety-net
   finalizer could never fire: `_register_public_stream`'s callback captured the
   *stream*, and `weakref.finalize` keeps its callback alive until it fires — so the
   stream kept itself alive and the weakref never died. `ReaderState` only ever used
   `id(stream)`. The leak would have persisted under option A, which was the option I
   recommended *because* it fixed the leak.

The comment on `_attach_finalizer` says "Hold only the close hook; do not keep the
stream alive." The intent was right and a closure two files away defeated it — which is
why it survived: the file that states the invariant is not the file that breaks it.

**Process note, third in a row.** Each of the last three pages has produced a finding
outside the docs: a spec clause describing behaviour that never shipped (O-23), an API
silently discarding an argument (P8), and now a finalizer that could not run. None were
reachable by reading prose. All three came from the O-21 rule — check the branch where
the claim does not hold — applied to a sentence I was about to write for users.

**Cost note.** The estimate of ~455 lines of remaining prose is holding as prose, but
it is not the real cost: three of five decided items so far have turned into code
changes with spec deltas and tests. That is worth knowing before planning the rest.

**Docs consequence.** `docs/reading-members.md` can now state the behaviour instead of
the advice written to survive either outcome (O-22), and `support-matrix.md`'s
"one live-stream caveat" is rewritten — it described deferred teardown keeping escaped
streams readable, which is no longer true. Must-explain **#20** is closed.


---

## O-25 — Closed: the specs were right, the code and `formats.md` were wrong

**O-2 has been open since the audit** as "`formats.md` says path `.gz`, the spec says
any declared-seekable source". Investigating it found a third answer: **both specs
already say seekability**, and it was the *code* that required a filesystem path.

Measured, same bytes both ways, `seekable_members=True`:

| Source | `.lz` size | `.lz` crc32 | `.xz` size |
|---|---|---|---|
| `Path` | 3500 | present | 3500 |
| `BytesIO` | **`None`** | **absent** | **`None`** |

Two probes in `single_file_reader.py` gated on `isinstance(self._source, Path)`:

- `_probe_lzip_index` — gratuitously. It immediately calls `_with_seekable_source`,
  which already handles a seekable stream and returns `None` for a non-seekable one.
  The docstring said "Same gate as size historically", which is how a restriction
  outlives whatever once justified it.
- `_probe_decompressed_size` — for a stated reason: a path gives "a fresh handle the
  probe fully owns", so it "never disturbs a caller-provided stream's position or
  lifetime". Real concern, already-solved problem: `_with_seekable_source` restores the
  position, and a non-owning `SlicingStream` view means closing the probe's decompressor
  cannot close a stream the caller owns.

**What the specs actually say**, both checked rather than assumed:
`format-single-file-compressors` gates GZIP's CRC on "seekable/path", LZIP's on "when
the seekable lzip index is available", and the size matrix mentions no source shape at
all. `seekable-decompressor-streams:122-124` goes further and says the ISIZE backstop
applies to "any declared-seekable source — a path or a caller-owned `BinaryIO` alike —
**not only path sources**".

So there is **no spec delta**: this is a bug fix bringing code into line with a spec
that was already correct, plus two `formats.md` sentences that had copied the code's
restriction rather than the spec's rule. No OpenSpec change was raised for it.

**Guard.** `test_cheap_size_does_not_require_a_path_source` compares a `BytesIO`
against a file with identical bytes for `.lz` and `.xz`, and asserts the caller's
stream is neither closed nor disturbed. Verified failing before the fix.

**The lesson is about O-2's original framing, not the bug.** It was filed as a
docs-consistency note — two documents disagreeing — so for weeks the obvious action
looked like "pick the right sentence". Nobody asked which one the code implemented. A
disagreement between two descriptions of behaviour is evidence about the *behaviour*,
and the cheapest way to settle it is to run it.

---

## O-26 — A reviewer's correct counter-example is not automatically a docs bug

O-25's lesson, arrived at from the other direction. There, two documents disagreed and
nobody had asked which one the code implemented. Here a reviewer produced a *correct,
reproducible counter-example* to a sentence on `reading-members.md`:

> **Nothing is decompressed until you read.** A member you skip is never opened, and
> no password is requested for it.

True for ZIP and the default lazy path; false for solid 7z, where an encrypted archive
with a wrong password raised `EncryptionError` while iterating, before yielding a
single member. The suggested fix was to scope the claim to the formats where it holds
and invert the password-proof advice for solid archives.

**That would have documented a bug as a contract.** `archive-reading/spec.md` already
required what the page said — "unselected/unread members are not opened/decompressed
**and do not request passwords**", with a matrix row to match. The page was right and
two backends were wrong: 7z opened each folder's decode pipeline at yield time (which
for an encrypted folder runs the whole password confirmation), and solid RAR spawned
`unrar p` at pass start. Both now defer to the first read.

**The rule.** When a behavioural claim in the guide is shown to be false, check the
spec before rewriting the sentence. Three outcomes, and only one is a docs fix:

| Spec says | What is broken |
| --- | --- |
| The same thing the page says | The **code** — fix it; the sentence already stands |
| Nothing about it | The **spec** — decide the contract, then write both |
| Something else | The **page** — rewrite it |

This is the mirror of O-21, where the page over-claimed and the code was right. The
check is the same in both directions — find the line that implements the claim — but
the conclusion is not, and "a counter-example turned up, so soften the sentence" gets
it wrong half the time.

It was also the cheaper fix. Softening would have put a format-conditional into the one
paragraph a reader consults to decide whether iterating proves their password; fixing
the code removed the condition instead.

**Scope note.** The maintainer's framing drove the fix past the reported symptom:
passwords in 7z are per *folder*, so laziness is per folder too — reading one member of
a three-folder archive opens exactly one folder. Fixing only the reported case (the
first folder, at pass start) would have left the same class of surprise one folder in.
