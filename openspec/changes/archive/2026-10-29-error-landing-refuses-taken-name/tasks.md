## 1. Extraction

- [x] 1.1 `_swap_into_place` lands under ERROR on a free name with `_land_on_free_name`: `link()` + unlink on POSIX, `os.rename()` on Windows; `FileExistsError` is the ERROR clash; another `link()` failure falls back to `os.replace()`
- [x] 1.2 The same landing under SKIP (the member is skipped) and RENAME (the next free name, up to `_LANDING_ATTEMPTS`); a SYMLINK or DIRECTORY refused over a name taken since is skipped under SKIP

## 2. Tests and docs

- [x] 2.1 `tests/test_cross_os_extraction.py`: a writer taking the name right before the real landing call is the clash for FILE and HARDLINK (red on main); `EPERM` from `link()` falls back
- [x] 2.2 `docs/extracting.md` says what `"error"` guarantees against another writer
- [x] 2.3 `openspec validate --strict error-landing-refuses-taken-name`, then archive
