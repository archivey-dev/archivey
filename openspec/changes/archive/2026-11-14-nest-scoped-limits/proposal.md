## Why

archivey bounds one archive well, but an archive a caller finds inside another and opens
with `open_archive` gets a fresh set of limits: its ratio is measured against its own
size, so the cap multiplies by 800 at every level, and its members are counted as if the
outer archive did not exist. `Budget` (PR 1372) was added to close that gap, but it is a
second concept with its own scope: a pool the caller must create per job and pass
around, which silently becomes a process-wide quota when it is kept on a reused config,
and which does nothing for the ratio. Naming the parent reader instead gives archivey
the nest's lineage (the upload's size, the depth), so the totals follow from the
config's defaults with no extra object.

## What Changes

- `open_archive(..., parent=reader)`: the new reader joins `reader`'s nest. `parent` may
  be closed, so extract-then-recurse keeps the nest.
- A `parent=` reader keeps every limit it would have on its own (its own ratio, decoder
  memory, metadata, key derivation, spool, members); its ratio cap is the stricter of
  its own `max_ratio` and the outermost reader's. Linking never weakens a limit.
- On top, an account the outermost reader owns holds three totals for the whole nest,
  every level counted, from the outermost reader's config: members (`max_members`),
  `max_ratio` times the outermost archive's size, and the new
  `DecoderLimits.max_nest_decoded_bytes` (default `None`). So a nest decodes at most
  `max_ratio` times the upload, whatever its depth and breadth.
- `ReaderContext.open_nested` keeps its sharing rules; its readers count toward the
  nest's totals. `MAX_NESTED_DEPTH` holds across both kinds of nesting.
- **BREAKING** `archivey.Budget`, `ArchiveyConfig.budget` and (on this branch)
  `open_archive(budget=)` / `ArchiveyFileSystem(budget=)` are removed. `Budget` has not
  been released (it came after 0.3.0), so no deprecation is owed.
- A request that opens several unrelated archives gets no shared total from archivey:
  the caller bounds it by the upload size, the number of archives, and a child process.

## Capabilities

### New Capabilities

### Modified Capabilities

- `archive-reading`: `open_archive` takes `parent=`; nest totals for members, ratio and
  decoded bytes; the new config field.
- `format-plugins`: `open_nested` readers join the nest; depth counts both kinds.
- `error-handling`: the argument table's `parent` row replaces `budget`.
- `safe-extraction`: the shared-budget requirement is replaced by a per-nest
  decoded-byte total under `DecoderLimits.max_nest_decoded_bytes`.

## Impact

- Public API: `open_archive(parent=)` and `DecoderLimits.max_nest_decoded_bytes` added;
  `Budget`, `ArchiveyConfig.budget` removed (`dev-docs/api-surface.txt`, `docs/api.md`).
- `src/archivey/core.py`, `config.py`, `internal/nesting.py`, `base_reader.py` (nest
  depth, account, nest ratio), `listing_limits.py`, `format_adapter.py` (depth check),
  `fsspec.py`, and the draw sites (base reader, TAR holes, RAR solid prefix, CAB folder
  skip, 7z encoded header).
- Docs: `docs/security.md`, the nested-upload recipe in `docs/recipes.md`,
  `dev-docs/threat-model.md`. The CHANGELOG line is written at release, not in the PR.
- Tests: `tests/test_budget.py` becomes the nest tests; `test_format_api_nested.py`,
  `test_argument_boundary.py` and the fsspec tests follow.
- Supersedes the `open_archive(budget=)` commits on PR 1541.
