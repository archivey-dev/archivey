# salvage-mode — opt-in salvage, first for TAR, CPIO and ar

**Status:** Proposed 2026-11-22. All design questions ruled by the maintainer on
2026-11-20 (salvage design §0, draft PR #1399). Target: 0.7.0. Effort: medium-large,
four PRs.

**Why it matters:** the default mode stops at damage no confirmed size crosses: a gap, a
zeroed region, a lost start. GNU tar searches past it; archivey loses every member after
it (657 vs 713 members in the salvage corpus).

**What it does:**

- `open_archive(path, salvage=True)`: lists every member the default lists, unchanged,
  then adds members found by searching past damage, each flagged `MEMBER_FOUND_BY_SCAN`.
  The pass still ends in the damage error. Needs a seekable file.
- A shared search driver with a budget (`SalvageLimits`, uncapped by default), used
  first by TAR, CPIO and ar. Each skipped range is reported (`ARCHIVE_REGION_SKIPPED`).
- Every other format reads as the default and says so (`SALVAGE_UNAVAILABLE`) until its
  step.
- Lost start: `format=` or the extension picks the format when detection fails.
- CLI `--salvage`, with partial files kept on extract.

**Decisions taken here (not in the rulings):** names `max_reported_regions`,
`SalvageScanContext.confirmed`/`unchecked`; v7 TAR headers searched only in all-v7
archives; a TAR clean end never starts a search (data after it is the hidden-content
step).
