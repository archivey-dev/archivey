# Design — bounded source spooling


> **Superseded on 2026-09-27:** `SpoolLimitExceededError` was folded into plain
> `ResourceLimitError` before 0.2.0 (see the amendment to
> `dev-docs/decisions/0012-usage-errors-outside-archiveyerror.md`). Where this file names
> the subclass, read `ResourceLimitError`.

Specs-first, following `seekable-gzip-and-block-writing`. This file carries the reasoning
and the questions the proposal does not settle; the deltas carry only what is decided.

## Decision 1 — one limit, not two kinds

**Superseded design, recorded because the reasoning is the useful part.** The first draft
split spooling in two:

- a **tool-tax** spool — materializing an already-seekable source because `unrar` accepts
  only a filesystem path — permitted by default;
- a **capability** spool — making a non-seekable source seekable — refused by default,
  on the argument that passing a pipe *is* the statement "stream this", so spooling it
  overrides a choice the caller made.

**The distinction is real inside the library and invisible outside it.** Both write the
same bytes to the same directory at the same cost. Both are avoided by the same remedy:
pass a path. Both are made safe by the same bound. The asymmetric-preference test is what
kills it — "I want RAR-from-stream but never pipe buffering" is answered by the *limit*,
not by a second switch, and the reverse preference ("pipes yes, RAR temp files no") is
incoherent.

What the split was actually doing was avoiding a breaking change to RAR-from-stream reads,
dressed as a user-facing taxonomy. Topic 9's brief rules that out directly:

> **Behaviour churn is free until the `0.2.0` tag** — "this would be a breaking change" is
> not a reason to prefer documenting a quirk over deleting it.

So: one number. `spool_limit` decides *whether and how much*; nothing in the public surface
records *why* a spool was needed.

## Decision 2 — a limit, not a boolean

`allow_temp_files: bool` was the next obvious shape and is still worse than a number, for
two reasons:

1. **It forces the default question to be all-or-nothing.** A modest default limit lets
   ordinary archives keep working from streams *and* pipes while a 40 GB one fails loudly.
   A boolean has to choose between "everything works, unbounded" and "nothing works".
2. **`None` already means what a boolean's `False` would**, and `UNLIMITED` already means
   what `True` would, so the boolean adds a second way to say things the number says.

`ExtractionLimits.UNLIMITED` and `ListingLimits.UNLIMITED` establish the sentinel pattern;
this reads as the third member of an existing family rather than a new concept.

## Decision 3 — `CostReceipt.notes`, not a diagnostic — **settled and shipped**

P11 left this open; it was answered the way this section argued, and it has since landed.
`format-rar` requires the disk-copy caveat in `ar.cost.notes` at open, and
`rar_reader.py:119` emits it. The reasoning is kept because it is the record of why the
note went where it did, not because anything here is still to decide.

The `diagnostics` capability settles it once the spool is *bounded*:

- The **admission** clause covers what a caller could not determine from the declared
  contract of the call. A spool inside a limit the caller set is declared.
- The **placement** clause prefers a structured field where one exists. `CostReceipt.notes`
  exists and is already the home for per-reader cost facts.

The reasoning inverted for the *unreported* behaviour P11 was filed against, which no
caller declared — which is why it was a defect and not a preference. With the note
shipped, what remains is the bound, and a bound is a configuration question rather than
an honesty one.

## Decision 4 — config, not a per-call argument

`ArchiveyConfig` already carries `extraction_limits` and `listing_limits`; `limits=` is a
per-call argument on extraction only. The dividing line the repo already uses is scope: a
per-call argument governs one operation, config governs the reader. Source handling affects
every read the reader performs.

## Decision 5 — the limit is the guard; free space is a heuristic

A pre-flight space check is worth having and worth not trusting:

- `TMPDIR` may be a different device than the working directory, sized independently.
- Free space is a race — another process can consume it between check and write.
- Containers frequently report the host's figures rather than the container's quota.
- **A memory-backed temporary directory turns "spool to disk" into "spool to RAM"** — ADR
  0010's unbounded memory use, reached through the door marked disk. Several distributions
  mount `/tmp` as `tmpfs` by default. (Checked on the development container while writing
  this: `/tmp` there is `ext4`, so this is a known risk rather than an observed one, and it
  is a property of the deployment rather than of archivey.)

So the **byte limit is the contract** — checked before the write when the size is known and
during the write when it is not. The space check only fails earlier and more legibly than
`ENOSPC` would. The caller can name the spool directory precisely so someone who knows
their `/tmp` is `tmpfs` can point elsewhere.

## Decision 6 — when the spool happens is documented, not configurable

The maintainer's one surviving objection to collapsing the kinds was *timing*: a spool for
an external binary happens at the first read that needs it, while a spool to make a source
seekable happens at open. That difference is real and caller-visible — an archive can be
listed without paying for it in one case but not the other — so it is **specified and
documented**, not turned into a knob. `CostReceipt.notes` records the spool when it
happens, which makes the timing observable rather than something to reason about.

## Out of scope — caching decompressed payloads

Writing *decompressed* member data to disk to make seeking cheap is a **caller-side**
concern: the natural shape is a wrapper stream around a member, which archivey might ship
or recommend later, but which does not belong in the source layer.

| | Source spool (this change) | Payload cache (not this change) |
|---|---|---|
| Bounded by | archive size, often known at open | uncompressed size — decompression-bomb territory |
| Motivated by | an external binary's API, and pipe sources | seek performance |
| Evidence needed | none; the behaviour already exists unbounded | hit rate, and which paths are actually `readinto`-bound |
| Natural home | the reader's source handling | a wrapper stream the caller composes |
| Overlaps | — | Topic 6, and the parked `stream-layering` **Q4** |

## Decisions the maintainer settled

The four questions this file left open were answered on 2026-09-17. They are recorded here
with the reasoning, because the reasoning is what a later reader needs; the deltas carry the
resulting contract.

### Q1 — the default limit is 1 GiB

A fixed byte count, not `UNLIMITED` and not none. It keeps essentially every archive that
works today working, while making the bound real for the case that motivated the change.

**The consequence is stated rather than hidden:** a RAR read from a stream whose archive
exceeds 1 GiB starts raising where it succeeds today. Nothing in the repository exercises
that boundary — the largest corpus RAR is 188 KiB — so **CI will not catch a badly chosen
default**. The implementation therefore owns a test that drives the boundary directly rather
than relying on the corpus to reach it.

### Q2 — a frozen `SpoolLimits` with an `UNLIMITED` classvar

Not two flat fields. It matches `ExtractionLimits` (`src/archivey/config.py:97`) and
`ListingLimits` (`src/archivey/config.py:119`) exactly, so the spool limit reads as the third
member of a family a caller has already met rather than a new shape to learn. The spool
directory travels on the same object.

### Q3 — a dedicated error, subclassing `ResourceLimitError`

Neither of the two candidates this file offered. `UnsupportedOperationError` is for what
*cannot* be done, and a limit the caller can raise is not that; `ArchiveyUsageError` sits
outside `ArchiveyError` (ADR 0012) and makes a configured bound look like a programming
mistake. So: a type of its own, `SpoolLimitExceededError`.

**It subclasses `ResourceLimitError`** (`src/archivey/exceptions.py:220`), which already
means "a configured limit was exceeded" — so `except ResourceLimitError` keeps catching every
configured-limit trip, and callers who want to distinguish the spool can. That error's
docstring currently scopes itself to `ExtractionLimits` and `ListingLimits`, and widens to
say so. Adding a third unrelated limit exception was the alternative, and it splits a
category that is already coherent.

One type covers both refusals, because they are the same refusal: a limit of none is a
limit of zero bytes, and any spool exceeds it. The alternative — a second exception for
"spooling is off" — would make a caller write two `except` clauses to express one intent.

The refusal for a **non-seekable source** stays `StreamNotSeekableError`, which is the
existing contract.

### Q4 — `streaming=True` streams from the spooled file

It does not switch to random access because the source happened to become seekable.

The reason is cross-format uniformity, and it is the part worth keeping: **if `streaming=True`
means something different per format, code that is wrong passes its tests on the format the
author happened to use and breaks in production when another appears.** A caller who wrote
`streaming=True` stated an intent, and spooling is an implementation detail of reading their
source, not a revision of that intent.

`openspec/specs/access-mode-and-cost/spec.md:28` is adjacent — under `streaming=True`
random-access APIs are disabled *uniformly*, independent of any loaded index — but it is
about disabling APIs regardless of index state, not about cross-format uniformity as such.
This change therefore **states the rule as contract** in its `access-mode-and-cost` delta
rather than citing that line as though it already said it.
