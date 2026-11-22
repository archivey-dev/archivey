## 1. Library

- [x] 1.1 `OnError.KEEP_PARTIAL` and its `OnErrorStr` spellings
- [x] 1.2 `extraction.py`: a FILE copy that fails part-way lands its temp file (`_land_partial`) and records `FAILED` with the path; the run's bookkeeping counts the file as written
- [x] 1.3 ZIP from a pipe: the staged bytes are kept and written again at placement (`_PartialThenError`)

## 2. Tests and docs

- [x] 2.1 `tests/test_extraction_keep_partial.py`: check failure, cut `.tar.gz`, cut `.gz`, `ERROR` and `REPLACE` over an existing file, dry run, limit, both access modes
- [x] 2.2 `docs/extracting.md` "Damaged members" and the `on_error` table; `docs/gotchas.md`

## 3. Archive

- [x] 3.1 `openspec validate --strict keep-partial-on-error`, then `openspec archive keep-partial-on-error --yes`
