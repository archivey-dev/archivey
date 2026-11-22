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
       max_search_bytes: int | None = None   # bytes a walk's searches examine, all layers
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
   SalvageUnavailableContext(kind="salvage_unavailable", archive_name, format, reason)
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
   - The format supplies
     `find_header(window: bytes, start: int, stop: int) -> int | None`, pure on bytes:
     the first candidate offset at or after `start` and before `stop` where a header
     passes the format's own check. It examines no offset at or after `stop`. This is
     also the shape of the later plugin hook (design §7.7).

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
- **Nested readers** are built forward-only (`streaming=True` over the member's stream),
  except a deb's tars on a plain file, which the TAR PR's second step reads with random
  access (see "the two-pass rule" below). One search reads forward, so it can run there.
  Going back after it, into the data of an unconfirmed member, is the format's call: TAR
  holds up to 4 MiB of it, and CPIO and ar on a forward-only reader record
  `SALVAGE_UNAVAILABLE` with `reason="forward_only_reader"` (a format with no search at
  all records `reason="no_salvage_search"`).
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

## Notes from the TAR PR

Choices made while building PR 2, where decisions 6 and 9 left them open:

- **Every added member is flagged.** The archive-reading delta says each member the
  default does not list carries `MEMBER_FOUND_BY_SCAN`. So a member the normal walk
  reaches after a confirmed found member is flagged too, with `offset` at its own chain
  and `confirmed` from the block after its data. Only a member the search found starts
  a search inside its data when it is unconfirmed; a walked member's next damage starts
  a search where that damage is, as for any walk.
- **The default's zero-block end starts no search**, even when non-zero bytes follow the
  marker. The default reads that end without an error, and the archive-reading delta
  says such an archive reads the same with `salvage=True` in this step. A run of zero
  blocks from a header's start (4 KiB zeroed at a header) therefore looks like an intact
  end with hidden content after it, which is step 5b. GNU tar stops there too ("A lone
  zero block"), unless `--ignore-zeros`. Past the default's damage, a zero-block end
  that is not the clean end (a nested tar's marker, with the outer members after it)
  does start a search.
- **The v7 rule needs a listed header.** A block with no magic passes only when at least
  one header was listed and every one listed was v7, so a lost start never accepts a v7
  block on its checksum alone. In v7 mode a v7 header confirms a found member.
- **A found header that makes no member** (its chain does not parse, or it raises
  `CorruptionError`) is passed over: the search goes on at the block after it. Past the
  default's end, `CorruptionError` inside a walked chain ends that chain as a rejected
  header does, and the search starts at the chain. Damage in the codec stream during a
  search ends the walk; the pass ends in the default's error.
- **The damage error's message** adds that salvage searched past it, and names the
  search limit when it stopped the search. Its code and context are the default's.
- **Lost start in core is a flag, not a format choice.** Detection already falls back
  to the name's extension (`detected_by="extension"`), and `format=` skips detection, so
  both already pick the reader. Core sets `SalvageRequest.lost_start` /
  `SalvageState.lost_start` (`core._start_may_be_lost`: salvage requested and the
  format came from `format=` or the extension), for a format whose search depends on
  it (CPIO's variant). TAR does not read it: a first header that does not parse is
  damage at offset 0 under salvage, whatever the detection said, and the search runs at
  open, so a file with no header still fails at open.
- **A forward-only walk** (a nested reader such as a makeself payload's TAR) reads
  through a window that, from the first search on, keeps the last 4 MiB (the pipe span)
  it read, so the search inside an unconfirmed member's data reads that data again and
  the walk goes back to the found header. Bytes it read past and no longer keeps (the
  damaged block itself, data read further than the span) read as zeros, which never
  pass. A compressed TAR's walk reads its codec stream through the same window from the
  first search on, because a seek back on a codec stream decodes again from a restart
  point.
- **Confirmation on a layer that is costly to go back on: the two-pass rule**
  (maintainer ruling, 2026-11-22, project thread). A plain file seeks, so any size is
  confirmed. A codec stream (`.tar.gz`, `.tar.xz`, ...) seeks back by decoding again
  from a restart point, so a salvage walk there makes two passes, not one restart per
  found member:
  - **Pass 1** reads the layer forward once. It trusts each found member's size and
    looks for a header where the size points; reading forward always reaches that
    block, so the look costs nothing, and the walk reads it through its window,
    which keeps the last 4 MiB before it. When the block confirms the member, the
    walk goes on from there. When it does not, the search goes on from the first
    byte the window still keeps, and the found member's data before that byte is a
    gap: pass 1 records it and does not search it.
  - **Pass 2** runs once pass 1 has ended, when pass 1 recorded a gap. It goes back
    to the first gap (one restart of the decode) and reads forward, searching only
    inside the gaps, in order, each search bounded by its gap's end. A member found
    there is checked as in pass 1 while the block after its data is inside the gap
    or within 4 MiB; a block past the gap and the hold is not decoded to: it
    confirms the member when pass 1 listed a member at that offset or found the
    clean end there. A search pass 2 would need behind where it stands searches the
    4 MiB window it keeps (option (b) of PR 1768), never a third pass.
  - **The listing** keeps archive order: the members pass 1 lists after its first
    gap are held until pass 2 has searched the gaps, then listed with pass 2's in
    order of their offsets. Each byte is examined once per layer: a gap is a range
    pass 1's search position stepped over without examining it, and pass 2 searches
    it under `SalvageState.revisiting`.
  - Total decode: two passes over the layer, whatever the member count (about
    1.1 to 2 times the compressed size on the test shapes: 40 found members that
    each claim 6 MiB, 20 that claim 12 MiB, 300 dense ones that claim 16 MiB). This
    replaces the per-look budget of PR 1768 (`_far_look_allowed` / `_far_spent`,
    review round 3, K5/K7). The look past the hold reads forward to the block
    (`_Window.skip_to`) and stops at the stream's end: a seek past the end counted
    as decoded bytes, and the ratio guard stopped a listing whose found member
    claimed 8 MiB past the end.
- **A reached member that nothing confirms.** A member the walk reaches after a
  found one is treated as a found member that nothing confirms, and the search goes
  inside its data, when its size points past the archive's end as far as the walk
  knows it (a file's size, or where a read of the stream came back short), or when
  the block at its claimed end is not a header (round 2 of PR 1774; the same on the
  base PR: `a, m0, liar` lost the members inside the liar's claim). The walk does
  not step to where its size points. In the second pass, a reached member that what
  pass 1 listed does not confirm is searched inside too. A search from an offset at
  or past the end finds nothing. A forward-only walk trusts a reached member's size
  past the hold as it trusts a found one's. The default walk does not change: this
  applies only past the default end.
- **How the window moves forward on a codec stream** (round 2 of PR 1774, K5/K6). Past
  what it holds, the window seeks the codec only when a restart point lies between where
  the stream stands and the offset (`RestartPoints.jumps`, answered by
  `_DecodeThroughSkips` from the decoder's own `nearest_resume_offset`): the seek then
  skips decoding the bytes in between and keeps none of them. Otherwise a seek would
  decode those bytes anyway, so the window reads through and keeps the 4 MiB hold. A
  seek back is cheap, and pass 1 records no gap, once a seek has jumped a restart point
  (`_Window.indexed`). Either move stops at the stream's end: `_DecodeThroughSkips.seek`
  reads to the restart point's offset or through, and returns where the stream ended
  rather than seeking past it, since a seek past the end counts bytes no decoder
  produced and the ratio guard refuses them. The default walk uses the same handle, so a
  `.tar.gz` whose last size points past the end now ends in `TruncatedError`, as the
  plain tar does, where it raised the ratio error before. A read right after a seek that
  comes back empty says the stream ends at or before that offset (`_Window.ended_by`).
  The decoder reads a file's own index (a BGZF scan, a Seekable Zstandard seek table)
  only on declared seek demand, and the plain resume query does not build it, so in a
  TAR walk the restart points ahead are the ones a decode already found: in pass 2,
  after pass 1 decoded the layer. The default walk asks the same question, so neither
  walk jumps more than base did.
- **A deb's tars on a plain file** read with random access. A deb opened with random
  access hands its control and data tars to `open_nested` as seekable views of the
  file (`ForwardStream._take_view`, internal: the public `take()` contract does not
  change), and the inner reader is built without `streaming=True`. The view is taken
  only when the file holds the bytes the ar header gives; a tar cut short is read
  through `take()`, which raises `TruncatedError` at the cut. A plain data.tar
  then confirms as the plain `.tar` does, so a deb's data.tar lists exactly what the
  same tar lists; a compressed one follows the two-pass rule. The inner reader's
  limits are the outer one's as before: its listing tracker charges outward, its
  decoders share `max_decoder_memory` (`_nested_config`), its codec stages charge
  `max_decoded_bytes`. The outer walk resumes after the view's bytes by its own
  position (`_end_take` skips them), not by where the inner reader left the file.
  The outer walk no longer drains such a member's data: the inner reader reads it
  by offset when asked, as a `data_on_demand` reader's (`_NestedData.on_demand`).
  So a plain data.tar's stored bytes are no longer drawn from `max_decoded_bytes`
  during the listing, as for the same plain `.tar`. A forward-only walk keeps the
  4 MiB hold (option (b)): a deb read with `streaming=True` or nested in another
  reader, a makeself payload (its bytes are hashed as they pass, so a view does not
  fit cheaply), a pkg payload. Such a walk trusts a found member's size past the
  span, as GNU tar reads a pipe: it is listed unconfirmed, its data reads in full
  through the walk, and the walk goes on from where the size points. When the
  block there does not confirm it, or the stream ends before it, the search goes
  back inside the member's data from the first byte the walk's window still keeps.
  So a real member bigger than the span reads whole and a tar stored in it is not
  listed, and a size that lies by more than the span loses the members whose
  headers are in all but the last 4 MiB of the read. The clean-end check reads each
  byte once per walk: an end more than the 1 MiB scan away answers without a read,
  and the zeros before the end are scanned once.
- **An unconfirmed found member's data, on a forward-only walk,** when the block
  after it is within the span and does not confirm it, is read from the window
  without moving the walk, and ends quietly where the stream ends: its size is not
  trusted. A deb's pass drains each member's data, so a
  lying size no longer runs the walk into the stream's end, and the bytes it hands
  out count once against `max_decoded_bytes`, however many found members cover them.

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
