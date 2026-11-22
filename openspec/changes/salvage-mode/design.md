# Design — salvage mode (step 3)

The salvage design is the design-draft PR #1399 (not merged; its §0 holds the
maintainer's rulings of 2026-11-20, Q1–Q18). This page carries the rulings this step
needs and decides what they left open. "Q*n*" below is a ruling of that design.

## Rulings this step implements

- **Q1** `salvage: bool = False` on `open_archive()` only; CLI `--salvage`.
- **Q2 add-only.** `salvage=True` never changes or drops a member the default lists. It
  only adds members, each flagged. (Hidden content of intact archives is a later step.)
- **Q3** the pass still ends in the damage error.
- **Q7** `SalvageLimits`, uncapped by default; each byte searched at most once per
  layer; the region count caps the diagnostics, not the walk; decoding limits apply
  unchanged.
- **Q8** `ARCHIVE_REGION_SKIPPED`, one per skipped range, salvage only.
- **Q9** salvage needs a seekable source; `streaming=True` raises at open.
- **Q10** a format without salvage reads as the default and records
  `SALVAGE_UNAVAILABLE`.
- **Q12 / Q16 recall first.** Every candidate that passes the format's own check is
  listed. A confirmed one claims its region; an unconfirmed one is listed with
  `confirmed=False` and the search goes on inside it.
- **Q14** lost start: when detection fails, `format=` or the extension picks the format.
- **Q6** CLI salvage extraction uses `OnError.KEEP_PARTIAL` (PR #1715).

## Decisions

1. **The keyword's shape.** `salvage: bool = False` on both `open_archive` overloads.
   `salvage=True, streaming=True` raises `ArchiveyUsageError` before the source is
   touched: "salvage needs random access to a seekable file; save the stream to a file
   first". Random access already refuses a non-seekable source at open, so no second
   check is needed. `stream_members()`, `extract_all()` and `verify_all()` on a
   random-access reader work as usual. A nested archive archivey opens itself
   (`ReaderContext.open_nested`: a deb's `data.tar`, a `.pkg` payload, a makeself
   payload) inherits the flag; `open_archive(parent=...)` takes it as given by the
   caller. An RPM's CPIO payload is not a nested reader: the RPM
   reader parses it itself, under its own salvage state.

2. **`SalvageLimits`.**

   ```python
   @dataclass(frozen=True)
   class SalvageLimits:
       max_search_bytes: int | None = None   # bytes a search examines, per reader, all layers
       max_reported_regions: int = 1_000     # ARCHIVE_REGION_SKIPPED records per reader
   ```

   `ArchiveyConfig.salvage_limits: SalvageLimits = SalvageLimits()`. When the search
   budget runs out, the search stops where it is: one `ARCHIVE_REGION_SKIPPED` with
   `length=None` and `reason="search_limit"`, nothing after it is listed, and the pass
   ends in the damage error, whose message adds that the search limit stopped salvage.
   Past `max_reported_regions`, the walk goes on and records one last
   `ARCHIVE_REGION_SKIPPED` with `reason="report_limit"` counting the rest (the
   `_MAX_DAMAGED_SERVICE_HEADERS` pattern).

3. **Diagnostics.** No new field on `ArchiveMember` (design §7.2).

   | Code | Context | When | Integrity code |
   | --- | --- | --- | --- |
   | `MEMBER_FOUND_BY_SCAN` | `SalvageScanContext` | once per member, at listing | no |
   | `ARCHIVE_REGION_SKIPPED` | `RegionSkippedContext` | once per skipped range, at listing | no |
   | `SALVAGE_UNAVAILABLE` | `SalvageUnavailableContext` | once, at open | no |

   ```python
   SalvageScanContext(kind="salvage_scan", archive_name, member_name, member_id,
                      format, method, offset, confirmed, unchecked)
   RegionSkippedContext(kind="region_skipped", archive_name, format, layer,
                        offset, length, reason)
   SalvageUnavailableContext(kind="salvage_unavailable", archive_name, format)
   ```

   - `method`: `"header_search"` in this step (later: `"second_copy"`,
     `"stream_segment"`, `"content"`).
   - `offset`: where the member's header starts in its layer.
   - `confirmed`: the header after the member's data passes its check too (or is the
     format's clean end). Q16.
   - `unchecked`: the fields no check covers. Always `("position",)`: nothing says the
     member belongs at this level (a nested archive's header passes too, Q12). TAR adds
     `"name"` when the found header has no long-name record before it and its name
     field is full (a long name may have been in the lost region).
   - `layer`: `"archive"` for the file; a codec name (`"gzip"`, ...) for a decoded
     stream.
   - `reason`: `"no_header"` (a range with no header that passes), `"search_limit"`,
     `"report_limit"`.
   - Default delivery: warning for `MEMBER_FOUND_BY_SCAN` and `ARCHIVE_REGION_SKIPPED`,
     info for `SALVAGE_UNAVAILABLE`. None is in `ARCHIVE_INTEGRITY_CODES`, so `STRICT`
     does not stop a salvage listing (design §8). The damage still raises at the end.
   - `MEMBER_NAME_UNKNOWN` and `MEMBER_HIDDEN` land with the first step that emits them
     (DR-13).

4. **The search driver** (`internal/salvage.py`). One forward loop, owned by archivey:

   ```text
   walk stops at damage D (default rules, follow-size included, already failed)
     search from D: finder(window, start) -> offset of first candidate | None
       none in the layer      -> REGION_SKIPPED(D, end-D), walk ends
       candidate at C         -> REGION_SKIPPED(D, C-D) when C > D
                                 parse it as the walk parses any header
                                 list it, MEMBER_FOUND_BY_SCAN(confirmed=?)
                                 confirmed   -> walk resumes after its data (normal walk)
                                 unconfirmed -> search resumes at C + step (inside its data)
   ```

   - The driver reads the layer forward in windows (1 MiB, with an overlap of the
     format's longest header so a header across a window edge is found once): through
     the backend's seekable view, or through a nested reader's forward-only stream. It
     counts every byte it examines against `max_search_bytes`, and never examines a
     byte twice in one layer of a walk: the search position only moves forward.
   - A confirmed member resumes the **normal** walk after it, so the default rules
     (follow-size, the end marker, every check) apply again from there, and a later
     damage starts a new search.
   - The first damage error is kept and raised at the end of the pass, as today. A
     search that finds nothing changes nothing about it.
   - The format supplies `find_header(window: bytes, start: int) -> int | None`, pure on
     bytes: the first offset at or after `start` where a header passes the format's own
     check. This is also the shape of the later plugin hook (design §7.7).

5. **Add-only, by construction.** The search starts only where the default walk stopped,
   so every default member comes first, unchanged, with the same diagnostics. The test
   for every format: for each damaged fixture, the default listing is a prefix of the
   salvage listing, member by member (name, sizes, offsets, data), and the default's
   diagnostics are a subset.

6. **TAR.**
   - **Where the search starts:** where the default walk ends on damage: a header that
     fails its checksum and that step 2 cannot follow, a block that is not a header
     (`_end_at_non_header`), a chain that does not confirm. The search starts at the
     damaged block. Not after a clean end (two zero blocks, then zeros or EOF): that is
     an intact end, and what follows it is hidden content (later step).
   - **What passes:** a 512-byte block whose checksum passes and whose magic is
     `ustar\0` or `ustar  \0` (POSIX, GNU, PAX), searched at **every 512-byte block**
     relative to the archive start. A v7 header (no magic) passes only when every header
     the walk listed before the damage was v7, and only at 512-byte blocks. The checksum
     is a byte sum (≈2⁻¹⁷); the magic adds 48 bits.
   - **Unaligned search** (any byte offset) runs only on a layer whose offsets are not
     known after a gap (stream segments, step 6). In this step every layer keeps its
     offsets, so the search is aligned. The driver takes the step as a parameter.
   - **Extended headers:** the walk parses a found PAX `x`/`g` or GNU `L`/`K` header and
     its chain as it parses any; the long name applies to the header after it. A found
     plain header whose name field is full and has no record before it gets `"name"` in
     `unchecked`.
   - **Confirmed:** the block after the found member's data (its chain's last header
     included) is a header that passes checksum and magic, or the clean end. Otherwise
     unconfirmed; the search resumes at the next block after the found header (its data
     is searched).
   - **Compressed TAR** (`.tar.gz` etc.): the search runs on the decoded stream, which
     the reader reads forward; a random-access TAR reader over a decoded stream already
     seeks forward by decoding. Damage in the codec itself stops the decode as today
     (stream segments are step 6).
   - Members after a found member are walked by the normal walk, so PAX globals, GNU
     sparse and every check apply.

7. **CPIO.** The search runs at the format's alignment (`newc`/`crc`: 4 bytes; `odc`:
   1 byte) for the variant the archive showed before the damage (the first header's
   variant; at a lost start, any of the three). A candidate passes when its magic
   matches, every field parses (hex or octal digits only), `namesize` is in 1..64 KiB,
   and the name ends with its NUL at `namesize`. `TRAILER!!!` found by the search ends
   the walk as an intact trailer does. Confirmed: the header after its data passes the
   same check, or is the trailer. The `crc` variant's data sum checks the data on read,
   as today.

8. **ar.** The search runs at 2-byte alignment. A candidate passes when its 60-byte
   header ends in `` `\n ``, the size and mode fields parse, and the date, uid and gid
   fields hold digits or spaces only. A found member whose name is a GNU `/123` long
   name whose table was lost keeps the raw `/123` name with `"name"` in `unchecked`; a
   found `//` table applies to the members after it. Confirmed: the header after its
   data (2-byte padded) passes, or the archive ends there.

9. **Lost start (Q14).** In `open_archive`, with `salvage=True`, when detection finds
   no format: the explicit `format=` (already honoured) or else the format the file
   name's extension names picks the reader, which then opens in "search from 0" mode:
   the first header is found by the search, not required at offset 0. The member found
   first is flagged like any found member, and `ARCHIVE_REGION_SKIPPED` covers the
   bytes before it. When the search finds no header, the open raises the error it
   raises today. Readers without salvage support raise as today. A compound extension
   (`.tar.gz`) whose outer codec is not detected either needs stream segments (step 6).
   `detect_format()` does not change.

10. **Formats without support.** Every backend declares `supports_salvage` (default
    `False`). `salvage=True` on one that does not records `SALVAGE_UNAVAILABLE` at open
    and reads exactly as the default. Plugins: unavailable until the `find_header` hook
    (step 11).

11. **CLI.** `--salvage` on `list`, `test`, `extract`, `info` (global or per verb, as
    reserved). `extract --salvage` uses `OnError.KEEP_PARTIAL` (the CLI already
    continues past a failed member). `list` marks a member with
    `MEMBER_FOUND_BY_SCAN` (a `found by search` note in the long listing and a column in
    JSON). The exit code is the damage error's, as today. Lands after PR #1715.

12. **Security note.** `docs/security.md`: salvage is a parser differential by design;
    never use `salvage=True` to decide what an archive holds or whether it is safe.
    Extraction safety is unchanged.

## Notes from the switch PR

Choices the decisions above left open, made while building PR 1:

- **The backend flag** is `ReadBackend.SUPPORTS_SALVAGE`, upper case like the other
  backend flags (`SUPPORTS_PASSWORD`), not `supports_salvage`.
- **How the flag reaches a reader.** The opener wraps the backend's `open_read` in
  `requesting_salvage(...)`, and `BaseArchiveReader.__init__` takes the request, as
  `parent=` is taken (`nesting.joining`). `open_archive` and `ReaderContext.open_nested`
  are the two openers; no `open_read` signature changed. A reader reads
  `self._salvage_mode` (`SalvageState`): `.enabled`, `.limits`.
- **Nested readers** are built forward-only (`streaming=True` over the member's
  stream). One search reads forward, so it can run there. Going back after it, into
  the data of an unconfirmed member, is the format's call: TAR holds up to 4 MiB of
  it, and CPIO and ar on a forward-only reader record `SALVAGE_UNAVAILABLE`.
- **Walks.** The reader's `SalvageState` holds the listing walk's budget, records and
  layer positions. A listing walk started over calls `restart()`. Another walk from
  the start (to reach a member's data, possibly beside the listing walk) searches with
  a `QuietSalvageState` of its own: the same cap, from zero, recording nothing, so it
  finds the same members and leaves the reader's state as it is.
- **One `SALVAGE_UNAVAILABLE` per reader**: a `.deb` opened with `salvage=True` records
  it for the package and for each inner tar while TAR has no search.
- **The budget** counts `step` bytes per candidate position examined (fewer at a
  layer's end). With `max_search_bytes=0` nothing is read or examined.
- **The `search_limit` record** has the `offset` where the stopped search started.
  **The `report_limit` record** has the `offset` of the first range not reported and
  `length=None`; its message gives the count, since the context has no count field. A
  format calls `SalvageState.finish()` at the end of its walk to record it, and
  `SalvageState.restart()` when its listing walk starts over.

## Notes from the CPIO and ar PR

Choices made while building PR 3, and where it departs from the decisions above:

- **Every member past the damage is flagged**, not only the one the search found: the
  ones walked on from a found member are not in the default listing either (the
  archive-reading delta: each added member carries `MEMBER_FOUND_BY_SCAN`). Each one
  is checked as a found one is, so a member whose next header fails is unconfirmed,
  and the search goes on inside its data (decision 4 resumed the normal walk; the
  next header's failure would start a search there anyway, after the member's data).
- **How a sequential reader reaches the driver.** `ReaderContext._salvage(stream)`
  (internal, set by the adapter) gives a `WalkSalvage` for the layer the walk reads:
  `search()`, `read_at()`, `seek()` (moves the walk's `ForwardStream` back to the
  found header), `holds()`, `found()` and `ending()` (finish, and the damage error,
  its message noting the search limit when that stopped the search). The CPIO and ar
  readers import `HeaderSearch` and `WalkSalvage` from `internal.salvage` until the
  plugin hook (step 11); `tests/public_names.py` allows those two names.
- **Forward-only layers do not search.** The walk moves back to the header the search
  found, which a reader built `streaming=True` over a member's data cannot do. A CPIO
  or ar reader inside another archive (a `.pkg` payload) records
  `SALVAGE_UNAVAILABLE`, saying it reads forward only, and reads as the default. A
  random-access `.cpio.gz` searches its decoded stream (`layer="gzip"`).
- **A found member whose data runs past the layer's end is not listed**: reading it
  would end the pass in `TruncatedError` instead of the first damage. A default
  member whose size runs past the end still ends the pass there, as the default does.
- **CPIO damage at the first header**: its magic still names the variant (detection
  needed it), so the search runs for that variant. Binary CPIO has no search.
- **Lost start (reader side).** `SalvageRequest.lost_start` / `SalvageState.lost_start`
  (`requesting_salvage(..., lost_start=True)`, the TAR PR's shape). With it, a CPIO
  whose first header fails searches all three ASCII magics at every byte; the first
  header found sets the alignment of later `newc`/`crc` searches. An ar whose magic is
  missing searches from 0 at **every byte** (not 2: the bytes lost may be odd), then
  at 2-byte steps from the first header found.
- **deb.** A damaged ar header after `debian-binary` starts the ar search; a found
  `control.tar*` or `data.tar*` is read as the walk reads one, each inner member
  flagged with the ar header's offset. A found header with another name is passed
  over. Damage to `debian-binary`'s own header is not searched: detection needs it.
- **ar** after damage takes a second `//` table (the later one names what follows),
  and a `/123` whose offset is past the table keeps its raw name like a lost table.

## Verification

Q18: a member found by a search has the `verifiable` level its own read can reach. For
TAR, CPIO (`newc`/`odc`) and ar that is `LENGTH`, as for any member of those formats;
CPIO `crc` is `CHECKSUM` as today. Nothing changes in this step.

## PRs

1. **Switch** (davi merges, public API): keyword, usage check, `SalvageLimits`, the
   three codes and contexts, backend flag, `SALVAGE_UNAVAILABLE`, the driver with unit
   tests on synthetic finders, security note.
2. **TAR** (stacked on 1): search, confirmation, lost start through `format=` /
   extension.
3. **CPIO and ar** (stacked on 1).
4. **CLI** (stacked on 1, after #1715).

## Later steps

Each its own OpenSpec change, in this order (design §11, with the 2026-11-20 rulings):

| Step | Change | Notes |
| --- | --- | --- |
| 4 | RAR CRC search, lost start, later volumes | CRC-32 (RAR5) confirms; RAR 1.5-4 CRC16 unconfirmed unless the next passes (Q16) |
| 5 | 7z: start-header repair (measure 7-Zip first, Q15); cut or lost end header as unnamed content | adds `MEMBER_NAME_UNKNOWN`, `__salvaged__/` names (Q4) |
| 5b | Hidden content of intact archives | adds `MEMBER_HIDDEN`; ZIP entries outside the central directory, TAR after the end marker, unclaimed regions, directory/link data (Q2) |
| 6 | Stream segments: bzip2, xz, multi-member gzip/BGZF, lzip, zstd, lz4; unaligned TAR on segments | `layer` = codec |
| 8 | ISO second trees, earlier sessions, path tables (Q17); RPM digests | native ISO reader only |
| 9 | 7z LZMA2 reset parts, CAB block skip, SquashFS inode walk, XAR heap | |
| 10 | DEFLATE restart (measure first, rapidgzip, Q11) | dropped if no gain |
| 11 | Plugin `find_header` hook | |
| late | Readable-ranges API (Q5) | when a caller needs it |
