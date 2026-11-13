## 1. Nest account and totals

- [ ] 1.1 Turn `Budget` into a private nest account (`internal/nesting.py`): member
  count, decoded-byte count, ratio tally, one lock; caps from the outermost reader's
  config
- [ ] 1.2 `BaseArchiveReader`: the outermost reader creates the account; a nested reader
  of either kind takes its `_nest_outer`'s; replace every `config.budget` read and
  `StageDraws`' budget with it
- [ ] 1.3 Add `DecoderLimits.max_nest_decoded_bytes` (default `None`) and draw decoded
  bytes against it; document that it never refills
- [ ] 1.4 Nest ratio: each outermost or `parent=` reader adds the growth of its one-pass
  high-water mark (largest of `DecodeRatioGuard` position, `ReadRatioTally`, largest
  single `BombTracker`); `open_nested` readers add nothing; hold the sum to `max_ratio`
  times the outermost trusted size after `ratio_activation_threshold`, always-stop; off
  when the outermost has no trusted size. A `parent=` reader keeps its own ratio rule
- [ ] 1.5 `ListingLimitTracker`: a `parent=` reader draws each member it registers from
  the account against the root's `max_members`, with a per-reader high-water mark; an
  `open_nested` reader does not draw; parse-time checks stay per reader
- [ ] 1.6 Hold each nest draw (members, ratio, decoded bytes) to the stricter of the
  root's and the drawing reader's config values
- [ ] 1.7 Remove `Budget`, `ArchiveyConfig.budget`, `open_archive(budget=)`,
  `ArchiveyFileSystem(budget=)`, `drawing_from`, exports and `__all__` entries

## 2. `open_archive(parent=)`

- [ ] 2.1 Add `parent` to both overloads and the implementation; refuse a non-reader
  with `ArchiveyUsageError` (closed readers allowed); `config=None` takes the parent's
  config
- [ ] 2.2 Wrap only `backend.open_read(...)` in `reading_inside(parent)`; the child's
  base constructor consumes the thread-local once; then check
  `reader._nest_outer is parent` (internal error otherwise). Test: a 7z with an
  encrypted header opened with `parent=` and a password provider that opens another
  archive; only the child joins the nest
- [ ] 2.3 Add a nest depth counted along `_nest_outer`, used by `open_nested`'s check
  and `parent=`'s; keep `_nested_depth` only for "the outer listing checks my names"
  (true for `open_nested` readers), so a `parent=` reader runs its own name checks
- [ ] 2.4 Leave `_nested_config` and the outermost metadata tracker on the `open_nested`
  path only; a `parent=` reader's decoder memory, metadata, key derivation and spool are
  its own

## 3. Docs

- [ ] 3.1 `docs/security.md`: nest totals; open inner archives with `parent=` (closed
  parents fine); unrelated archives are the caller's to bound; drop the batch `Budget`
  advice
- [ ] 3.2 `docs/recipes.md` nested-upload recipe: pass `parent=`; run it
- [ ] 3.3 `dev-docs/threat-model.md` nesting row; `ReaderContext.open_nested` docstring;
  `open_archive` docstring; `docs/api.md` (`::: archivey.Budget` out);
  `dev-docs/api-surface.txt`

## 4. Verify

- [ ] 4.1 Rewrite `tests/test_budget.py` as nest tests covering the archive-reading
  join and nest-limit matrices and the safe-extraction decoded-bytes matrix, including
  the review's ratio cases (small bomb in a large outer, breadth, `DIRECTORY` parent)
  and the no-refusal rows (honest `.tar.gz` listed, read and extracted; `.deb`; one
  member read 1000 times)
- [ ] 4.2 `tests/test_format_api_nested.py`, `tests/test_listing_decoded_bytes.py`,
  `tests/test_argument_boundary.py` (`parent=` row), fsspec tests without `budget=`
- [ ] 4.3 `./scripts/check.sh`, `./scripts/test.sh`
- [ ] 4.4 `openspec validate --strict nest-scoped-limits`
