## Why

archivey bounds one archive well, but an archive a caller finds inside another and opens
with `open_archive` gets a fresh set of limits: its ratio is measured against its own
size, so the cap multiplies by 800 at every level, and its members, decoder memory and
key derivations are counted as if the outer archive did not exist. `Budget` (PR 1372)
was added to close that gap, but it is a second concept with its own scope: a pool the
caller must create per job and pass around, which silently becomes a process-wide quota
when it is kept on a reused config. `ReaderContext.open_nested` already shows the better
shape: the inner reader "shares this archive's limits rather than getting its own".

## What Changes

- `open_archive(..., parent=reader)`: the new reader joins `reader`'s nest and shares
  its limits the way a reader `open_nested` builds does. A config's limits then mean
  "per nest" everywhere.
- Shared while the levels are open: `max_decoder_memory` (an inner level gets what the
  open levels left) and `max_metadata_bytes`. Measured against the outermost archive:
  `max_ratio`, so a nest of n levels decodes at most n times the ratio, not the ratio to
  the n-th power. Summed over the whole nest, closed levels included, in an account the
  outermost reader owns: `max_members`, `max_key_derivation_rounds`,
  `SpoolLimits.max_bytes`, and the new `DecoderLimits.max_total_decoded_bytes`.
- `MAX_NESTED_DEPTH` (8) holds for both kinds of nesting together.
- **BREAKING** `archivey.Budget` and `ArchiveyConfig.budget` are removed. Its byte
  counter becomes `DecoderLimits.max_total_decoded_bytes`, its member counter
  `ListingLimits.max_members`, both per nest. `Budget` has not been released (it came
  after 0.3.0), so no deprecation is owed.
- A request that opens several unrelated archives gets no shared total from archivey:
  the caller bounds it by the upload size, the number of archives, and a child process.

## Capabilities

### New Capabilities

### Modified Capabilities

- `archive-reading`: `open_archive` takes `parent=`; a reader in a nest shares its
  limits; `max_members` counts per nest.
- `safe-extraction`: the shared-budget requirement is replaced by a per-nest
  decoded-byte total under `DecoderLimits.max_total_decoded_bytes`.

## Impact

- Public API: `open_archive(parent=)` added; `DecoderLimits.max_total_decoded_bytes`
  added; `Budget`, `ArchiveyConfig.budget` removed (`dev-docs/api-surface.txt`).
- `src/archivey/core.py`, `src/archivey/config.py`, `src/archivey/internal/nesting.py`,
  `base_reader.py`, `listing_limits.py`, `format_adapter.py` (`_nested_config` moves to
  the shared path), `internal/config.py` (`KeyDerivationBudget`), `internal/spool.py`,
  and the four draw sites (base reader, TAR holes, RAR solid prefix, CAB folder skip).
- Docs: `docs/security.md`, the nested-upload recipe in `docs/recipes.md` (passes
  `parent=` instead of a budget), `dev-docs/threat-model.md`.
- Tests: `tests/test_budget.py` becomes the nest-account tests;
  `test_format_api_nested.py` and `test_argument_boundary.py` follow.
- Supersedes the unmerged PR 1541 (`open_archive(budget=)`).
