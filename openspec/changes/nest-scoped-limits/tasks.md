## 1. Nest account

- [ ] 1.1 Turn `Budget` into a private nest account (`internal/nesting.py`): decoded
  bytes, members, key-derivation rounds, spool bytes, one lock; caps from the root's
  config
- [ ] 1.2 `BaseArchiveReader`: the outermost reader creates the account; a nested reader
  takes its `_nest_outer`'s; replace every `config.budget` read and `StageDraws`' budget
  with it
- [ ] 1.3 Add `DecoderLimits.max_total_decoded_bytes` (default `None`, Open Question in
  design.md) and draw decoded bytes against it
- [ ] 1.4 `ListingLimitTracker`: count members in the account against
  `ListingLimits.max_members`; a reader `open_nested` builds does not add its members;
  parse-time checks (ZIP, 7z, RAR, ISO) use what the nest has left
- [ ] 1.5 `KeyDerivationBudget` and `SpoolBudget` charge the account instead of a
  per-reader counter
- [ ] 1.6 Remove `Budget`, `ArchiveyConfig.budget`, its export and `__all__` entry

## 2. `open_archive(parent=)`

- [ ] 2.1 Add `parent` to both overloads and the implementation; refuse a closed reader
  or a non-reader with `ArchiveyUsageError`; `config=None` takes the parent's config
- [ ] 2.2 Build the reader inside `reading_inside(parent)` in `_open_resolved`; set its
  depth from the parent; refuse past `MAX_NESTED_DEPTH` across both kinds of nesting
- [ ] 2.3 Move `_PluginAdapter._nested_config` (decoder memory the open levels left) to
  shared nest code and apply it to `parent=` readers
- [ ] 2.4 Check that `_trusted_source_size` and `_live_consumed` reach the outermost
  archive for `parent=` readers, including a child from a temporary-file copy

## 3. Docs

- [ ] 3.1 `docs/security.md`: limits are per nest; open inner archives with `parent=`;
  unrelated archives are the caller's to bound
- [ ] 3.2 `docs/recipes.md` nested-upload recipe: pass `parent=` instead of a budget;
  run it
- [ ] 3.3 `dev-docs/threat-model.md` nesting row; `ReaderContext.open_nested` docstring;
  `open_archive` docstring
- [ ] 3.4 Error-handling spec's argument table: add `parent` to the `open_archive()` row

## 4. Verify

- [ ] 4.1 Rewrite `tests/test_budget.py` as nest tests covering the archive-reading nest
  matrix and the safe-extraction decoded-bytes matrix
- [ ] 4.2 `tests/test_format_api_nested.py`, `tests/test_listing_decoded_bytes.py`,
  `tests/test_argument_boundary.py` (`parent=` row), fsspec tests without `budget=`
- [ ] 4.3 `./scripts/check.sh`, `./scripts/test.sh`
- [ ] 4.4 `openspec validate --strict nest-scoped-limits` (the two long-requirement
  warnings are the only accepted ones)
