## 1. Data model

- [x] 1.1 `ArchiveMember.accessed_utc()`, `created_utc()` and `ctime_utc()` beside `modified_utc()`, all four on a shared private `_as_utc`

## 2. Tests and docs

- [x] 2.1 `tests/test_data_model.py` pins each helper: naive with and without `tz_for_naive`, aware, and that each reads only its own field
- [x] 2.2 `docs/migrating.md` names the three new helpers; `dev-docs/api-surface.txt` regenerated
- [x] 2.3 `openspec validate --strict timestamp-utc-helpers`, then archive
