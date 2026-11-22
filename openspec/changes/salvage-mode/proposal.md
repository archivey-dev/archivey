# Salvage mode: the switch, and header search for TAR, CPIO and ar

## Why

VISION's founding use case is decades of messy backups, with damaged input "a
first-class citizen". The default mode now follows a damaged RAR, TAR or ZIP header when
the next header confirms its sizes (`2026-11-21-salvage-step-1`, `-step-2-tar`,
`-step-2-zip`). What it cannot cross is damage that no size confirms: a gap of deleted
bytes, a zeroed region, a size field that is itself the damaged byte, a lost start. GNU
tar crosses all of these with a block search; archivey stops. In the salvage corpus
(salvage design, draft PR #1399, §3) that is the whole gap between archivey
(657 members) and GNU tar (713) on `plain.tar` and `pax.tar`.

The maintainer ruled every question of the salvage design on 2026-11-20 (design §0). The
main rules: salvage is an opt-in `salvage=True`; it only **adds** members, each flagged,
never changes or drops one the default lists; it lists every candidate that passes the
format's own check (**recall first**); it needs a **seekable** source; and the pass
still ends in the damage error.

This change is step 3 of the design (§11): the switch and everything later steps share,
and the first formats that use it.

## What Changes

- **`open_archive(..., salvage=False)`.** A new keyword. With `streaming=True` it raises
  `ArchiveyUsageError` at open ("save it to a file first"); random access already
  requires a seekable source. Not on `open_stream()`, not a config field.
- **`SalvageLimits`** on `ArchiveyConfig.salvage_limits`: `max_search_bytes` (default
  `None`, uncapped) and `max_reported_regions` (default 1 000, caps the
  `ARCHIVE_REGION_SKIPPED` diagnostics, not the walk). Each byte is searched at most
  once per layer.
- **Diagnostics:** `MEMBER_FOUND_BY_SCAN` (member found by a search past damage, with
  `confirmed`), `ARCHIVE_REGION_SKIPPED` (one per range the search stepped over), and
  `SALVAGE_UNAVAILABLE` (open, `salvage=True` on a format without salvage support,
  which then reads as the default). None is an integrity code.
- **A shared header-search driver** (`internal/salvage.py`): owns the forward search,
  the budget, the claimed regions, the diagnostics and the error kept for the end. A
  format supplies one function: where in this window does the first header start that
  passes my check?
- **TAR, CPIO, ar** use it. After damage that the default cannot cross (TAR: also after
  step 2's follow-size fails), the walk searches forward for the next header that passes
  the format's check, lists it flagged, and goes on. A confirmed header (the header
  after its data passes too) claims its data; an unconfirmed one does not, and the
  search goes on inside it.
- **Lost start:** with `salvage=True`, when detection finds no format, an explicit
  `format=` or the file name's extension picks the format, and the walk starts with a
  search from offset 0. `detect_format()` does not change.
- **CLI `--salvage`** on `list`, `test`, `extract` and `info` calls
  `open_archive(salvage=True)`; `extract --salvage` keeps partial files
  (`OnError.KEEP_PARTIAL`). `list` marks a member found by a search.
- **Every other format** records `SALVAGE_UNAVAILABLE` until its own step lands.

Not `needs-minor` for the default: `salvage=False` reads exactly as before. New public
names: the keyword, `SalvageLimits`, `ArchiveyConfig.salvage_limits`, three codes and
their contexts. Release note: **Added**.

Out of scope (later changes, `design.md` §Later steps): RAR CRC search, 7z cut
archives, stream segments (bzip2/xz/gzip members), hidden content of intact archives
(`MEMBER_HIDDEN`), ISO second trees, `MEMBER_NAME_UNKNOWN`, the plugin `find_header`
hook, DEFLATE restart, readable ranges, format conversion.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `archive-reading`: the `salvage=` keyword, its access-mode rule, `SalvageLimits`, the
  add-only rule, lost start.
- `diagnostics`: three codes and two contexts.
- `format-tar`, `format-cpio`, `format-ar`: the header search in salvage mode.
- `cli`: `--salvage` is implemented (replaces "reserved without behavior").

## Impact

- `src/archivey/core.py`, `src/archivey/reader.py`: the keyword, the usage check, the
  lost-start format choice.
- `src/archivey/config.py`: `SalvageLimits`, `ArchiveyConfig.salvage_limits`.
- `src/archivey/diagnostics.py`: codes, contexts, `DiagnosticCodeStr`.
- `src/archivey/internal/base_reader.py`, `internal/registry.py`: the flag reaches each
  backend; a backend declares salvage support.
- `src/archivey/internal/salvage.py` (new): the search driver.
- `src/archivey/internal/backends/tar_parser.py`, `tar_reader.py`, `cpio_reader.py`,
  `ar_reader.py`: the format checks and the walk.
- `src/archivey/cli/`: `--salvage`.
- `docs/security.md`: never use `salvage=True` to decide what an archive holds.
