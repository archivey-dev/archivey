# The problem catalogue — SUMMARY (Topic 10)

> Run 2026-08-17 against `main` @ `5d08f31`. Commissioned 2026-08-15 against `d4668c3`
> ([`brief.md`](brief.md)); §Sources' counts were verified mechanically at the start of the
> pass and not re-derived.
>
> **Every source group is mined**, except two files recorded with their reason (§Outstanding).
> [`sources.md`](sources.md) is the coverage proof, and the handoff — a fresh container keeps
> no memory of the session.

**146 entries**, one per non-trivial problem, each stated so that someone who has never seen
archivey could design against it.

## Headline

**The material was there; the vocabulary was the work.** Roughly 180 documents already state
these problems, and nothing collected them — so one problem was restated in a review finding,
an ADR context section and a change proposal, in three vocabularies, and could not be counted.
The dedupe is real and measurable: **FQ-01** (a member's true size is knowable only after its
bytes are read) was stated in four documents and an ADR, in four vocabularies, and is now one
row with five sources. Across the catalogue, the sources supply **489 entry-source
attributions for 146 entries** — an average of 3.3 documents per problem.

What was *not* already written down anywhere is the **neutral phrasing**. Every source
except `dev-docs/history/` describes problems in terms of the answer archivey built, and
translating each one back into what the format specifies, what the upstream library gets
wrong, what the platform refuses, and what an attacker can send was the slow, load-bearing
step — exactly as the brief predicted.

Two things the extraction produced that were not asked for and are worth keeping:

1. **The schema needed sharpening in two places** (§Two schema decisions below). Both are
   defects the brief's four fields would have permitted, and both would have silently
   destroyed the artifact's second use.
2. **Mechanical guardrails** in `tests/test_review_problem_catalogue.py`, one of which found
   twelve real neutrality leaks across two runs (§Guardrails).

## Entries by category

| Category | Entries | The shape of what is in it |
|---|---:|---|
| Format quirk | 31 | What the formats specify and cannot express: late-bound sizes, indexes at the end or absent, solid compression, names with no declared encoding, duplicate and superseded names, zeros as a valid archive |
| Security / hostile input | 27 | Traversal and link escape, bombs and their false positives, listing-time exhaustion, name deception on the terminal and in display order, formats with no password verifier, argument injection into an external tool |
| API and usage pattern | 30 | Where a uniform interface over unlike formats leaks: cost that varies by orders of magnitude, capabilities that are traps on some formats, verdicts delivered where nobody can act on them, partial failure |
| Upstream library defect | 22 | Silent truncation, infinite loops, process aborts, one broad exception type for unrelated conditions, a finalizer that can never run |
| Performance & memory | 12 | Solid re-decode, rewinds without an index, verification fused into the delivering read, bounded memory versus boundary-crossing cost, guards that measure the wrong quantity |
| Packaging & dependency | 11 | Optional native wheels, a codec's provider moving into the standard library, an external tool that may be a different program of the same name, a test corpus needing trialware |
| Platform & filesystem | 7 | A stream that lies about seekability, path resolution that raises, links that cannot be made, metadata with no portable form |
| Concurrency & lifetime | 6 | One byte source and two readers, one pipe carrying every member, streams outliving their reader, archive-wide limits versus workers |
| **Total** | **146** | |

## Coverage against §Sources

| Group | Documents | State |
|---|---:|---|
| `dev-docs/history/` | 5 | **complete** — read first, per the brief; the only pre-implementation source, so its statements were already neutral |
| Standing registers (threat-model, known-issues, library-analysis, open-issues) | 4 | **complete** |
| `dev-docs/decisions/` | 17 | **complete** |
| `review/archive/*/SUMMARY.md` | 11 | **complete** |
| Archived proposals (`## Why`) | 72 | **complete** |
| Unsettled / parked (`IDEAS.md`, `discussions/`) | 5 | **complete** |
| `dev-docs/investigations/` | 8 | **6 of 8** — two read selectively, two `unread — attributed` |
| `design.md` files | 57 | **complete** — read for *alternatives considered and why they lost* |
| Code residue (Topic 8's harvest) | — | **outstanding** (§Outstanding) |

[`sources.md`](sources.md) carries the per-document state and, for each document, the entry
ids it contributes — inverted mechanically from the catalogue's `Sources` lines, so the two
cannot drift.

**Source concentration.** `open-issues.md` (39 entries), `library-analysis.md` and
`known-issues.md` (16–17 each), `threat-model.md` (24), and the four `history/` files (40, 32,
27, 2) carry most of the catalogue. That is expected: they are themselves aggregations. The
prediction made before the proposals were read was that they would **yield more sources per
existing entry than new entries**, because much of what they state has already reached the
catalogue through a register that summarised them.

**It held for both proposal groups and broke for one other, informatively.** The full
per-group table is in [`sources.md`](sources.md) §Where this pass stopped; the shape of it:

| Group | New entries | Why |
|---|---:|---|
| `history/` (5) | ~40 | The only pre-implementation source; nothing had summarised it |
| Registers (4) | ~45 | The aggregations themselves |
| ADRs (17) | 4 | Context restates the registers; their value was *sharpening* existing entries with measurements |
| Reviews (11) | 23 | Findings are problem-shaped, and a register summarises only the ones that stayed open |
| Proposal `## Why` (72) | 12 | Predicted — mostly new *sources* on existing entries (41 of them) |
| Parked / unsettled (5) | 4 | **Broke the prediction**: a parked idea is a problem nobody has filed *as* a problem, so no register states it |
| `design.md` (57) | 2 | Downstream of the proposals' forces, as predicted. Its distinctive contribution was a *collision* between two requirements each already catalogued (**API-30**) |

The transferable lesson: read the documents nobody has summarised, and read the ones that
record a force **against** a decision. Those two shapes carry the problems a status-organized
register structurally cannot.

## What the sources turned out **not** to contain

- **No collected problem list of any kind.** Every register is organized by *status* — open
  gaps, known issues, decisions made, findings fixed — and none by problem. That is why the
  same problem appears in four of them.
- **No statement of the neutrality distinction.** No source separates "the world does X"
  from "we do Y about X"; `dev-docs/history/` reads neutrally by accident of having been
  written before the design existed, not by policy.
- **Very little without evidence.** The registers are unusually disciplined: nearly every
  claim carries a measurement, an upstream citation, a pinning test or a `file:line`. The
  **unverified list is empty** — no entry had to be excluded for want of evidence, and no
  recollection needed recording separately. This is the single most useful property the
  sources had, and it is why 146 entries could be admitted without a judgement call about
  any of them.
- **Cross-format comparison is rare.** Problems are almost always recorded per format. Four
  entries exist only because a source happened to measure across formats at once —
  **FQ-18** (a link's digest covers zero bytes in one format and the target string in three
  others, from a measured four-format table) is the clearest, and it was found only because
  a long-dormant test column was switched on.
- **Two documents state no problem**: `dev-docs/history/index.md` and
  `dev-docs/decisions/index.md` are routers. Recorded as such rather than left as gaps.
- **Five archived changes carry no `proposal.md`** (specs and tasks only). Outside §Sources'
  count of 72 and recorded with the reason.

## Two schema decisions

Both are written into [`catalogue.md`](catalogue.md)'s header, because both are defects the
brief's four fields would have permitted:

1. **Fields 2 and 3 carry the same neutrality obligation as field 1.** The experiment is
   handed all three. A symptom described as "`ArchiveReader.open()` raises
   `ConcurrentAccessError`" leaks the design as surely as a problem statement would, so
   symptoms are written as what an operator or caller *sees*.
2. **Field 3 cites the demonstration, not the implementation.** A pinning test, an upstream
   issue, a format spec section or a measurement proves the problem is real. The internal
   class that *answers* it is field 4 material, and citing it in field 3 would smuggle the
   solution into the redacted view. Where the only proof is archivey's own test, the test
   path is cited — `tests/test_iso.py:362` says a case exists and describes no architecture.

## Guardrails

`tests/test_review_problem_catalogue.py`, four tests:

- **The redacted view is derivable and current.** `catalogue-neutral.md` is generated by
  `scripts/derive_neutral_catalogue.py`; the test fails if the committed file is stale.
  Definition of done #4 wants it committed, and the hazard of committing a generated file is
  that it silently rots.
- **No entry's fields 1–3 name an archivey type, module or config field.** This found **ten
  real leaks on its first run and two more on the next batch**, every one of them inside a
  *quoted* line from a source document — the failure mode nobody would catch by reading,
  because the quote is accurate. All twelve were paraphrased with bracketed generic terms.
- **Every entry has all four fields**, field 4 given or explicitly unresolved.
- **The redacted view really is redacted** — no answer or source lines survive into it.

The name sweep checks the mechanical half only. Voice is a human pass, and
[`experiment.md`](experiment.md) §Pre-flight makes a ten-entry spot-read a precondition of
spending a run.

## Unresolved problems

Fifteen entries record their answer as unresolved or partly unresolved, per §Definition of
done #2. They are not new findings — each is already registered somewhere — but the catalogue
is the first place they are visible together:

| Entry | What is open |
|---|---|
| **SEC-18** | Native decoders can busy-loop on crafted input; no host-language guard can stop it. The resource-limited subprocess sandbox is not built |
| **UL-18** | Intermittent heap corruption in a long-lived process with many native extensions loaded. Process isolation is CI hygiene, explicitly "not a product fix" |
| **PERF-04**, **API-22** | Best-effort salvage of a damaged archive — the founding use case — is all-or-error. A library-level verify-everything primitive is deferred |
| **PLAT-04**, **PLAT-05** | Concurrent hostile modification of the destination, and extended-metadata fidelity: both declared out of scope |
| **SEC-11** | Nested-archive amplification: the documented stance and bounded-recursion recipe are still owed |
| **CONC-02** | The external tool's per-member-kind emission model is matched by hand; the shared emission table is not written |
| **PKG-05** | A format's test column depends on a tool that cannot be shipped; the licensing call is the maintainer's |
| **API-24** | The verify-everything primitive the library's own front-end hand-rolls |
| **PERF-10** | Per-open fixed cost at 5–8× the standard library; the member-model build is recorded as actionable |
| **PERF-12** | Holding a solid-block decoder open would turn a measured 4.5× walk into 1.0×, but two concurrent reads of one block mean two live decodes from its start. Direction agreed; the concurrency half is explicitly unbrainstormed |
| **FQ-30** | Legacy single-byte name encodings have no oracle — every candidate decodes every input. The honest garble is the default and detection stays post-1.0 opt-in |
| **PLAT-07** | How much space an extraction needs, and how much is available, are both unknowable enough that a pre-flight check can only ever be advisory |
| **FQ-31** | A multi-member compressed file's trailer describes only its last member, so a whole-file digest is deferred rather than summed |

## Outstanding

1. **Topic 8's harvest** — [`harvest/`](harvest/) holds only its `README.md`. It is filled by
   that topic's capability workers, which are downstream of its pass 0 and have not run
   ([§Definition of done #5](brief.md)). It is the **only** source for problems that never
   reached a register: a grep for `workaround|quirk` over `src/` finds four sites while 136
   comments name an upstream library, so the residue is not keyword-findable and is reachable
   only by someone already reading the subsystem. Nothing here gates Topic 8, and Topic 8
   does not gate this — but this catalogue is incomplete without that group, and the
   capabilities are named in the harvest README.
2. **Two primary documents**: `investigations/ppmd-native-investigation-brief.md` and
   `ppmd-exit-after-green-exploration.md`. Their headings were scanned and every problem they
   state is carried by `known-issues.md` §PPMd, so the entries exist (`UL-08`, `UL-10`,
   `FQ-23`) — but that is a summary's word, not the primary document's, and `sources.md`
   marks them as the gap they are.
3. **The experiment has not been run.** [`experiment.md`](experiment.md) is the protocol and
   the grading rubric, written whether or not it is ever run (Definition of done #6). Its
   §Cheaper variants names the two subsets worth running on their own — the coverage probe is
   the cheapest useful thing in it.

## Deliverables

| File | State |
|---|---|
| [`sources.md`](sources.md) | The inventory and coverage proof; the resumability record |
| [`catalogue.md`](catalogue.md) | 146 entries, all four fields |
| [`catalogue-neutral.md`](catalogue-neutral.md) | Fields 1–3, **derived** by `scripts/derive_neutral_catalogue.py` |
| [`experiment.md`](experiment.md) | The protocol and rubric; not run |
| [`harvest/`](harvest/) | Outstanding — README only |
| `SUMMARY.md` | This file |

## Hard constraints observed

No fixes, no refactors, no spec changes. Where the catalogue made a design look questionable,
the entry records the problem and points at the review that owns the area; nothing was acted
on. No entry was admitted without evidence, and the unverified list is empty because none was
needed. Severity is not editorialized — entries record that a problem exists and what it
does. One entry, N sources: every duplicate is a merge, and §Retired ids in the catalogue is
where a merged id would go (still empty — no two entries have needed merging after the fact,
because the merge happened during extraction rather than after it).
