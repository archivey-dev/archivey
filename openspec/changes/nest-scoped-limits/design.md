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
stream passed as `source` as the only mechanism (lost through any copy; see Open
Questions for inference as an addition); a context-manager scope (a thread-local,
silent on another thread, the trap K2 found in `drawing_from`); keeping `Budget`
alongside (opt-in, does nothing for the ratio, two scopes to explain).

### 2. A nest-root account replaces `Budget`
The outermost reader owns one locked account. It holds the nest's member count and its
decoded-byte count. It is `Budget`'s implementation made private; the draw sites (base
reader, `StageDraws`, TAR holes, RAR solid prefix, CAB folder skip, 7z encoded header)
keep their shape and read `self._nest_account`. Every reader of a nest, of either kind,
draws decoded bytes from it; members are drawn per Decision 5.

The decoded-byte cap is `DecoderLimits.max_nest_decoded_bytes` (default `None`; name and
default are Open Questions). The counter never refills, so on a long-lived reader (an
`ArchiveyFileSystem`, a server reader with `concurrent_operations=True`) any fixed cap
is a lifetime quota; the field's docs say so.

### 3. Ratio: each reader's own rule, plus one rule for the nest
A `parent=` reader keeps the ratio rule a top-level reader has: its own tally against
its own size. On top, the account sums every reader's archive-wide ratio tally, and the
nest is held to `max_ratio` times the outermost archive's trusted size, after the root's
`ratio_activation_threshold`. So the nest as a whole decodes at most `max_ratio` times
the upload, whatever its depth and breadth; a child alone can never decode more than it
could unlinked. Where the outermost reader has no size (a `DIRECTORY`, a stream of
unknown length), the nest rule does not apply and each reader's own rule still does.

`open_nested` readers keep today's rule (against the outermost size), which is sound
because their bytes also pass through the outer reader's tally; they add their tally to
the nest's too. The four existing ratio requirements in `safe-extraction` therefore
stand unchanged for a `parent=` reader, and the nest rule is a new requirement.

**Rejected:** judging a `parent=` child against the outermost size only (review FB1:
weaker than unlinked, multiplied by breadth, off under a `DIRECTORY` parent).

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
In addition each member it registers is drawn from the account, held to the root's
`max_members`; the draw keeps the per-reader high-water mark `Budget` uses, so listing
again does not count again. A reader `open_nested` builds does not draw: its members
reach the root as the outer listing's members. Opening the same inner archive twice
counts its members twice; the docs say so. **Rejected:** parse-time checks against "what
the nest has left" (FB8: needs the reader's own draw added back on a re-walk, and misses
RPM and plugins).

### 6. Which config each rule reads
Every per-reader rule reads the child's own config (with `parent=` and no `config`, the
parent's). The nest rules (member total, decoded-byte total, nest ratio) read the root's
config, fixed when the root opened. A child config whose value for one of those three
differs from the root's records `NEST_LIMIT_FROM_ROOT`, naming the field, at open: the
argument is a resource the nest cannot use, so the spec's permit-and-record rule
applies. **Rejected:** dropping it silently (FB6); refusing it (forces callers to
rebuild configs to change a diagnostic policy).

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
`_open_resolved` builds the reader inside `reading_inside(parent)`, the thread-local
`open_nested` already uses, so no `open_read` signature changes. The child's constructor
consumes the thread-local value once, so a reader that a password provider or an
`on_diagnostic` callback opens during the open does not join the nest (FB11). The
`drawing_from` thread-local from PR 1541 is not needed.

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

## Open Questions

- Name and home of the decoded-byte total. Recommendation:
  `DecoderLimits.max_nest_decoded_bytes`, the scope in the name, beside
  `ListingLimits.max_decoded_bytes` (one pass) and
  `ExtractionLimits.max_extracted_bytes` (one call). Alternative: a `NestLimits` class
  holding it, if more nest totals come.
- Its default. Recommendation: `None`. With the nest ratio rule the nest already has a
  default-on total that scales with the upload; a fixed number would be a lifetime quota
  on long-lived readers.
- Inferring `parent` when `source` is a member stream of an open archivey reader and
  `parent` is not given (FB11). Safer by default; the cost is a second way in and a
  changed result for callers who pass member streams today. Recommendation: not in this
  change; reconsider once `parent=` has users.
