## Context

Two mechanisms bound work that spans more than one reader today:

- **Format nesting** (`ReaderContext.open_nested`, #1346, ruling 2026-11-08 "charge
  across the nesting"). The inner reader is built under `nesting.reading_inside(outer)`
  and finds its outer reader through `enclosing_reader()`
  (`BaseArchiveReader._nest_outer`). It shares `max_metadata_bytes` through the
  outermost `ListingLimitTracker`, gets the `max_decoder_memory` the outer levels left
  (`_PluginAdapter._nested_config`), and measures `max_ratio` against the outermost
  archive (`_trusted_source_size`, `_live_consumed`). This is sound because the levels
  run at once and every inner byte also passes through the outer reader's own ratio
  tally. Its members are yielded as the outer archive's members, so `max_members`,
  name checks and extraction count them once. It is streaming-only and gets no
  passwords. `MAX_NESTED_DEPTH` is 8.
- **`Budget`** (#1372, D1 on 11-11): a thread-safe pool of decoded bytes and members on
  `ArchiveyConfig.budget`, drawn by every reader whose config holds it. Its scope is the
  object, so a config reused across requests shares one pool that never refills (thread
  "Explain how the Budget is shared", 2026-11-13). PR 1541 moved it to
  `open_archive(budget=)`; this change supersedes that.

An archive the caller opens from a member of another archive (the nested-upload recipe
in `docs/recipes.md`) gets neither: it is a fresh top-level reader, judged against its
own size, so a nest of n levels can decode `max_ratio` to the n-th power of the upload.

Round 1 of the design review (Fable, PR 1541, FB1-FB11) showed that copying the
`open_nested` rules to caller-opened readers is wrong for most limits: a caller-opened
reader is a separate public reader whose bytes pass through no outer tally, whose
parent's decoder is usually idle (the inner archive was copied to a temporary file),
and whose siblings the parent cannot see. This revision keeps `open_nested` as it is
and gives `parent=` readers a smaller rule: their own limits, plus totals for the nest.

## Goals / Non-Goals

**Goals:**
- A nest (an upload and every archive read from inside it) is held to totals that scale
  with the upload: members, decoded bytes, and `max_ratio` against the upload's size.
- Linking a reader to its parent never weakens a limit it would have on its own.
- `Budget` is removed; what it counted moves to the nest.

**Non-Goals:**
- A shared total across unrelated archives of one request. The caller bounds that by the
  upload size, the number of archives, and a child process. `docs/security.md` offers
  `Budget` for "a batch of archives read on several threads" today; that advice goes.
- Sharing memory limits (`max_decoder_memory`, `max_metadata_bytes`) across `parent=`
  readers: the caller decides how many readers are open at once (Decision 4).
- Changing `ExtractionLimits` scope (Decision 8).
- `open_stream(parent=)`: a compressed file inside an archive is read through the outer
  member stream already; revisit if a caller needs it.

## Investigations

Each limit, sorted by what it protects, and its rule for each kind of child:

| Limit | Protects | `parent=` child | `open_nested` child (unchanged) |
| --- | --- | --- | --- |
| `max_ratio` | decode vs input | own size, and the nest rule (Decision 3) | against the outermost |
| `ListingLimits.max_members` | work and memory | own, and summed over the nest | counted as outer members |
| nest decoded bytes (Budget's counter) | CPU, total work | summed over the nest | summed over the nest |
| `max_decoder_memory` | memory held at once | own | what the open levels left |
| `max_metadata_bytes` | memory held at once | own | outermost tracker |
| `max_key_derivation_rounds` | CPU | own | n/a (no passwords) |
| `SpoolLimits.max_bytes` | temporary disk | own | n/a (no RAR inside) |
| `max_ppmd_held_input` | memory, one decoder | per decoder | per decoder |
| `ListingLimits.max_decoded_bytes` | one listing pass | per pass (ruling 11-11) | per pass |
| `ExtractionLimits.*` | disk, one extraction | per `extract_all` call | counted as outer members |

"Own" means what a top-level reader opened with the child's config gets today.

Measured in review round 1, building the child inside `reading_inside(outer)`: a 15 KB
`.tar.xz` of 100 MiB of zeros inside a 2.17 MB stored ZIP is refused after 11.5 MiB on
its own, and decodes all 100 MiB when judged against the outer archive's size. Five such
children each decode 100 MiB. A `DIRECTORY` parent has no size, so the rule switches
off. Hence Decision 3.

## Decisions

### 1. The caller names the parent: `open_archive(..., parent=reader)`
The link is explicit, so it survives the recipe's copy of a member to a temporary file
(needed so a 7z, RAR or ISO inside can seek), works from any thread, and costs nothing
for callers who do not nest. **Rejected:** inferring the parent from an archivey member
stream passed as `source` (lost through any copy; implicit; Resolved Questions); a
context-manager scope (a thread-local, silent on another thread, the trap K2 found in
`drawing_from`); keeping `Budget` alongside (opt-in, does nothing for the ratio, two
scopes to explain).

### 2. A nest-root account replaces `Budget`
The outermost reader owns one locked account. It holds the nest's member count and its
decoded-byte count. It is `Budget`'s implementation made private; the draw sites (base
reader, `StageDraws`, TAR holes, RAR solid prefix, CAB folder skip, 7z encoded header)
keep their shape and read `self._nest_account`. Every reader of a nest, of either kind,
draws decoded bytes from it; members are drawn per Decision 5.

The decoded-byte cap is `DecoderLimits.max_nest_decoded_bytes` (default `None`; see
Resolved Questions). The counter never refills, so on a long-lived reader (an
`ArchiveyFileSystem`, a server reader with `concurrent_operations=True`) any fixed cap
is a lifetime quota; the field's docs say so.

### 3. Ratio: each reader's own rule, plus one rule for the nest
A `parent=` reader keeps the ratio rule a top-level reader has: its own tally against
its own size. On top, the nest is held to `max_ratio` times the outermost archive's
trusted size, after the root's `ratio_activation_threshold`, on a sum defined as
follows. Each reader adds one number, the most it has decoded of its archive in one
pass: the largest of its container stream guard's position (`DecodeRatioGuard`), its
member read tally (`ReadRatioTally`) and its largest single extraction (`BombTracker`).
It adds only the growth of that number, so reading again, or extracting after reading,
adds nothing, and a long-lived reader carries no quota. Each of those counters is
already held to `max_ratio` times the reader's own size, so a nest of one is never
refused by the nest rule where the reader's own rules pass: a lone reader behaves
exactly as today. So the nest as a whole decodes at most `max_ratio` times the upload,
whatever its depth and breadth; a child alone can never decode more than it could
unlinked. Where the outermost reader has no size (a `DIRECTORY`, a stream of unknown
length), the nest rule does not apply and each reader's own rule still does.

`open_nested` readers keep today's rule (against the outermost size), which is sound
because their bytes also pass through the outer reader's tally; they add nothing to the
nest's sum, since their bytes are already in the outer reader's number (as they add no
members). The four existing ratio requirements in `safe-extraction` therefore
stand unchanged for a `parent=` reader, and the nest rule is a new requirement.

The nest ratio error is the always-stop `ResourceLimitError`, as the per-reader one is.

**Rejected:** judging a `parent=` child against the outermost size only (review FB1:
weaker than unlinked, multiplied by breadth, off under a `DIRECTORY` parent); summing
every counter of every reader, or every decoded byte (review FB12: the counters overlap,
so an honest `.tar.gz` at 476:1 listed and read sums to 953:1, and an honest `.deb` read
once to 2372:1; a sum of every decoded byte is a default-on lifetime quota; maintainer
card 2026-11-13).

### 4. Memory limits stay per reader for `parent=` children
`max_decoder_memory`, `max_metadata_bytes`, `max_key_derivation_rounds` and
`SpoolLimits.max_bytes` apply to a `parent=` reader as to any top-level reader.
`_nested_config` stays on the `open_nested` path, where the levels' decoders do run at
once. **Rejected:** applying `_nested_config` to `parent=` readers (review FB3: it
subtracts the parent's peak declared working set even when that decoder is idle, which
refuses an honest archive in the recipe's temporary-file case, and siblings do not see
each other); charging `parent=` members to the outermost metadata tracker (FB2: needs a
lock and a release on close, for a bound the caller already controls by how many
readers it keeps open, at most nine by depth); summing key derivation and spool (FB7:
per-archive defaults would refuse a nest of honest encrypted archives, and a child
opened from a temporary-file path never spools).

### 5. Members: each reader's own cap, plus a total for the nest
A `parent=` reader applies its own config's `max_members`, including the parse-time
checks in ZIP, 7z, RAR, ISO, RPM and plugins through `context.config`, exactly as today.
In addition each member it registers is drawn from the account, held to the nest's
`max_members`; the draw keeps the per-reader high-water mark `Budget` uses, so listing
again does not count again. A reader `open_nested` builds does not draw: its members
reach the root as the outer listing's members. Opening the same inner archive twice
counts its members twice; the docs say so. **Rejected:** parse-time checks against "what
the nest has left" (FB8: needs the reader's own draw added back on a re-walk, and misses
RPM and plugins).

### 6. Which config each rule reads
Every per-reader rule reads the child's own config (with `parent=` and no `config`, the
parent's). The nest rules (member total, decoded-byte total, nest ratio) read the root's
config, fixed when the root opened, and also the drawing reader's own config: a draw is
held to the stricter of the two values. So a child config that tightens a nest total
takes effect for that child's draws, and no value a caller passes is ever unread. A
child config cannot loosen a nest total; the field docs and `security.md` say so.
**Rejected:** dropping the child's value silently (FB6); refusing a differing value
(forces callers to rebuild configs to change a diagnostic policy); a diagnostic for a
differing value (FB13: fires for a tighter value that works as asked, re-fires for
inherited configs, and needs a new public code for what the docs can state once).

### 7. Depth and name checks are two things
A new nest depth, counted along `_nest_outer` across both kinds of nesting, drives both
depth checks. Today's `_nested_depth` keeps its other job alone, "the outer listing
checks my names", true only for `open_nested` readers; a `parent=` reader runs its own
duplicate-name and NUL checks. Counted in archives: nine levels, the outermost
included, open; the tenth raises `UnsupportedFeatureError`, as `open_nested` does today.

### 8. Extraction limits stay per `extract_all` call
`ExtractionLimits` is an operation's argument (`extract_all(limits=)`), and a caller
extracting a nest makes one call per level into destinations it chooses. Bytes written
are decoded bytes, so the nest total bounds the sum. **Rejected:** summing extraction
across the nest (an operation limit that depends on what other readers did).

### 9. Parent lifetime
`parent` must be an archivey reader (`ArchiveyUsageError` otherwise); it may be closed.
Extract-then-recurse (`extract_all`, leave the `with`, walk the destination, open each
inner archive with `parent=`) is a common shape and keeps the nest. A closed reader
still answers its trusted size, which the nest rule needs; the account outlives the
readers that hold it. Closing a parent does not close its children.

### 10. Plumbing
`_open_resolved` wraps only the `backend.open_read(...)` call in
`reading_inside(parent)`, the thread-local `open_nested` already uses, so no `open_read`
signature changes and detection, which runs before and emits diagnostics, never sees the
link. The child's base constructor consumes the thread-local value once, so a reader
that a password provider or an `on_diagnostic` callback opens later in the open does not
join the nest (FB11). After `open_read` returns, `_open_resolved` checks
`reader._nest_outer is parent` and raises an internal error otherwise, so a backend or a
plugin factory that builds a helper reader first fails a test rather than a limit
(FB16). The `drawing_from` thread-local from PR 1541 is not needed.

`ArchiveyFileSystem(budget=)` from PR 1541 is removed, and it takes no `parent=`: a
filesystem is one top-level nest.

## Risks / Trade-offs

- [A caller forgets `parent=`] → the inner archive is a fresh nest, as today: its own
  limits still hold, only the totals are lost. The recipe and `security.md` lead with
  `parent=`.
- [The nest member total refuses an upload of many archives that each fit] → intended;
  the error names the nest's total and the field.
- [Two rules for members and ratio] → each is the familiar per-archive rule plus one
  total; the error says which one was crossed.

## Resolved Questions (maintainer, 2026-11-13)

- **Name and home:** `DecoderLimits.max_nest_decoded_bytes`. "Nest", not "nested": the
  cap counts every level, the outermost included.
- **Default `None`.** The nest ratio total (Decision 3) is on by default and scales with
  the upload: it answers "is this a bomb?". `max_nest_decoded_bytes` is a fixed work
  budget per upload the caller sets: it answers "how much work will I do for one
  request?", and it is the only nest total when the outermost reader has no size. They
  count differently: the ratio total counts each reader's one-pass high-water mark
  (Decision 3), the fixed cap every byte decoded, again on every re-read. A 1 MB upload
  under a 1 GiB cap is stopped by the ratio at 800 MB; a 100 MB upload of 50:1 logs
  passes the ratio (80 GB) and is stopped by the cap at 1 GiB.
- **No parent inference.** A caller who knowingly handles nested archives passes
  `parent=`; archivey does not force it.
