# Tasks — salvage mode (step 3)

## 0. Design

- [x] 0.1 Rulings carried from the salvage design §0 (2026-11-20), dated.
- [ ] 0.2 Maintainer review of this change (with the switch PR).

## 1. Switch (PR 1, davi merges)

- [x] 1.1 `salvage=` on both `open_archive` overloads; `ArchiveyUsageError` with
  `streaming=True`.
- [x] 1.2 `SalvageLimits`, `ArchiveyConfig.salvage_limits`, export, copy/validation like
  the other limits.
- [x] 1.3 Codes, contexts, `DiagnosticCodeStr`, catalogue row, API surface listing.
- [x] 1.4 Flag reaches every backend; `supports_salvage`; `SALVAGE_UNAVAILABLE` at open;
  nested readers inherit.
- [x] 1.5 `internal/salvage.py` driver: windows, overlap, budget, once-per-byte, claimed
  regions, region records and cap; unit tests with synthetic finders.
- [x] 1.6 `docs/security.md` note; `open_archive` docstring.

## 2. TAR (PR 2)

- [x] 2.1 `find_header` for TAR (magic + checksum; v7 headers on a plausibility check).
- [x] 2.2 Walk: start search where the default ends on damage; confirmed / unconfirmed;
  resume normal walk.
- [x] 2.3 Lost start via `format=` / extension (core, shared).
- [x] 2.4 Tests: damage corpus (cuts, zeroed regions, byte flips, lost start, 64 KiB
  gap), add-only prefix test, nested-tar case, compressed TAR, GNU tar oracle (skips
  without it).

## 3. CPIO and ar (PR 3)

- [ ] 3.1 CPIO `find_header` per variant; walk.
- [ ] 3.2 ar `find_header`; GNU/BSD names; walk.
- [ ] 3.3 Tests as 2.4.

## 4. CLI (PR 4, after #1715)

- [ ] 4.1 `--salvage` wiring; KEEP_PARTIAL on extract; `list` marks; pipe refusal.
- [ ] 4.2 CLI spec delta applied; tests.

## 5. Close

- [ ] 5.1 Sync specs, archive the change.
