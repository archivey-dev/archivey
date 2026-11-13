## Context

Two mechanisms bound work that spans more than one reader today:

- **Format nesting** (`ReaderContext.open_nested`, #1346, ruling 2026-11-08 "charge across
  the nesting"). The inner reader is built under `nesting.reading_inside(outer)` and finds
  its outer reader through `enclosing_reader()` (`BaseArchiveReader._nest_outer`). It
  then shares `max_metadata_bytes` through the outermost `ListingLimitTracker`, gets the
  `max_decoder_memory` the outer levels left (`_PluginAdapter._nested_config`), and
  measures `max_ratio` against the outermost archive (`_trusted_source_size`,
  `_live_consumed`). Its members are yielded as the outer archive's members, so
  `max_members` and extraction count them once. It is streaming-only and gets no
  passwords, so spool and key-derivation limits never come up. `MAX_NESTED_DEPTH` is 8.
- **`Budget`** (#1372, D1 on 11-11): a thread-safe pool of decoded bytes and members on
  `ArchiveyConfig.budget`, drawn by every reader whose config holds it. Its scope is the
  object, so a config reused across requests shares one pool that never refills (thread
  "Explain how the Budget is shared", 2026-11-13). PR 1541 moved it to
  `open_archive(budget=)`; this change supersedes that.

An archive the caller opens from a member of another archive (the nested-upload recipe
in `docs/recipes.md`) gets neither: it is a fresh top-level reader.

## Goals / Non-Goals

**Goals:**
- One meaning for the config's limits: per nest, where a nest is an archive and every
  archive read from inside it, whether a format or the caller opened it.
- Caller nesting gets the same rules `open_nested` already has.
- `Budget` is removed; nothing it counted is lost.

**Non-Goals:**
- A shared total across unrelated archives of one request. The caller bounds that by the
  upload size, the number of archives, and a child process; an opt-in account can be
  added later without breaking anything.
- Changing `ExtractionLimits` scope (Decision 7).
- `open_stream(parent=)`: a compressed file inside an archive is read through the outer
  member stream already; revisit if a caller needs it.

## Investigations

Each limit, sorted by what it protects (thread, 2026-11-13):

| Limit | Protects | Rule in a nest | `open_nested` today |
| --- | --- | --- | --- |
| `DecoderLimits.max_decoder_memory` | memory held at once | shared by the open levels | shared |
| `ListingLimits.max_metadata_bytes` | memory held at once | shared by the open levels | shared |
| `DecoderLimits.max_ppmd_held_input` | memory, one decoder | per decoder | per decoder |
| `DecoderLimits.max_ratio` | decode vs input | against the outermost input | yes |
| `ListingLimits.max_members` | work and memory | summed over the nest | counted as outer members |
| `DecoderLimits.max_key_derivation_rounds` | CPU | summed over the nest | n/a (no passwords) |
| `SpoolLimits.max_bytes` | temporary disk, cumulative | summed over the nest | n/a (no RAR inside) |
| decoded bytes (Budget's counter) | CPU, total work | summed over the nest | inherited Budget |
| `ListingLimits.max_decoded_bytes` | one listing pass | per pass (ruling 11-11) | per pass |
| `ExtractionLimits.*` | disk, one extraction | per `extract_all` call | counted as outer members |

## Decisions

### 1. The caller names the parent: `open_archive(..., parent=reader)`
The link is explicit, so it survives the recipe's copy of a member to a temporary file
(needed so a 7z, RAR or ISO inside can seek), works from any thread, and costs nothing
for callers who do not nest. **Rejected:** inferring the parent from an archivey member
stream passed as `source` (lost through any copy; implicit); a `Job`/session object that
opens archives (a second object to carry, the same scope problem `Budget` had); keeping
`Budget` alongside (two scopes to explain).

### 2. A nest-root account replaces `Budget`
The outermost reader owns one locked account holding the summed counters: decoded bytes,
members, key-derivation rounds and spool bytes. It is `Budget`'s implementation, made
private and extended with two counters; the draw sites (base reader, `StageDraws`, TAR
holes, RAR solid prefix, CAB folder skip, 7z encoded header) keep their shape and read
`self._nest_account`. `KeyDerivationBudget` and `SpoolBudget` take their cap from the
root's limits and charge the account instead of a per-reader counter.
**Rejected:** a separate object per limit (four locks, four places to forget).

### 3. Shared while open, as `open_nested` does
`max_metadata_bytes` keeps its outermost-tracker account; an inner level's charge comes
off when it closes. `max_decoder_memory`: the inner reader's cap is what the open levels'
largest declared working sets left, computed when it opens; `_nested_config` moves from
`_PluginAdapter` to the shared nest code so both kinds use it.

### 4. Ratio against the outermost archive
`_trusted_source_size` and `_live_consumed` already walk `_nest_outer`; `parent=` sets
`_nest_outer`, so a caller-opened level is held to `max_ratio` of the bytes the caller
handed to the outermost reader.

### 5. Limits come from the root
A reader opened with `parent=` and no `config` uses its parent's config. With a `config`,
its own non-limit settings apply (diagnostic policy, accelerators, formats), and so do
the per-reader-only limits (`ListingLimits.max_decoded_bytes`, `max_ppmd_held_input`);
every shared or summed limit is the root's. **Rejected:** refusing a child config whose
limits differ (forces callers to rebuild configs to change a diagnostic policy).

### 6. Members are counted once per nest
A reader opened with `parent=` adds its members to the root account; its parse-time
`max_members` check (ZIP, 7z, RAR, ISO) uses what the nest has left. A reader that
`open_nested` builds does not add its members: they reach the root as the outer
listing's members. Listing again does not count again (per reader, as today).

### 7. Extraction limits stay per `extract_all` call
`ExtractionLimits` is an operation's argument (`extract_all(limits=)`), and a caller
extracting a nest makes one call per level into destinations it chooses.
**Rejected:** summing extraction across the nest (an operation-level limit that depends
on what other readers did; surprising for a repeat extraction of one reader).

### 8. Parent lifetime
`parent` must be open when the child opens (`ArchiveyUsageError` otherwise) and must be
an archivey reader. Closing a parent does not close its children; they keep drawing from
the account, which outlives the readers that hold it. Depth counts both kinds of nesting;
past `MAX_NESTED_DEPTH` the open raises `UnsupportedFeatureError`, as `open_nested` does.

### 9. Plumbing
`_open_resolved` builds the reader inside `reading_inside(parent)`, the thread-local
`open_nested` already uses, so no `open_read` signature changes. The `drawing_from`
thread-local from PR 1541 is not needed.

## Risks / Trade-offs

- [A child opened on another thread while the parent's decoders run] → the account is
  locked; the decoder-memory snapshot may be one declaration stale, which can only
  refuse more, as `_nested_config` documents.
- [A caller forgets `parent=`] → the inner archive is a fresh nest, as today. The recipe
  and `security.md` lead with `parent=`.
- [`max_members` per nest refuses an upload of many archives that each fit] → intended;
  the error names the nest's total.

## Open Questions

- Default of `DecoderLimits.max_total_decoded_bytes`: `None` (no cap, as an unset
  `Budget` today), or a number. Recommendation: `None` for this change; measure real
  uploads before picking a default.
