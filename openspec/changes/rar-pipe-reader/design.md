## Context

`RarReader` parses every header at open (`rar_parser.parse_rar_volumes`), then reads
member data through `unrar p` on a synthetic archive built from stored headers re-read
at their offsets (`rar_synthetic.read_stored_header`). Both steps seek, so a
non-seekable source is refused (`rar_reader.py`, `_NON_SEEKABLE_REASON`), and
`SUPPORTS_STREAMING_NON_SEEKABLE` is `False`.

PR 1552 (this change builds on it) added rolling volumes: `RollingVolumes` writes a
synthetic archive as RAR volumes, one on disk at a time, taking its members from an
iterator only when the previous member's data is written, and `VolumeFeeder` answers
`unrar -vp`'s next-volume prompts from a thread. A RAR from a stream source is already
decoded in one `unrar` run that way for a large solid pass.

ZIP already reads a pipe: `ZipReadBackend.open_read` picks `ZipForwardReader`, a
subclass, when the source cannot seek (`_MEMBER_LIST_UPFRONT = False`, members yielded
by `_iter_members` as the walk reaches them, `_open_member` only for the member the
walk is at). The base reader's `_ProgressivePassIterator` registers members as they
come, and `members()` and `open()` raise on any streaming reader.

Request: davi, 2026-11-14 (tracked internally): read a RAR from a non-seekable source in
`stream_members()` through rolling synthetic volumes, after the rolling-volume PR's
review.

## Goals / Non-Goals

**Goals:**

- `stream_members()` and `extract_all()` over a single-volume RAR (RAR 1.5-4 and RAR5,
  solid or not, plain, `-p` or `-hp`) from a pipe, with the same member metadata and
  bytes as the seekable reader gives for the same archive.
- One `unrar` run per pass; one rolling volume on disk at a time, charged to
  `SpoolLimits.max_bytes` as in PR 1552.
- A refusal that names the reason for each shape this cannot read.

**Non-Goals:**

- Volume sets from a pipe: the other volumes are separate files.
- `streaming=False` on a pipe (random access stays refused, as for every format).
- Reads without RARLAB `unrar` 7.00 or later, including stored-only archives read
  natively. They could follow later; the pipe reader starts with one data path.
- Damage recovery past a member whose output does not line up (Decision 6).
- RAR5 file copies whose source the pass has not kept (Decision 7).

## Investigations

What the walk does that a forward-only source cannot serve (read 2026-11-14 in
`rar_parser.py`):

| Step | Seeks | Forward-only |
| --- | --- | --- |
| Skip a block's data (`_seek_after_packed`) | forward, to the next header | a skip, or the data is consumed first (Decision 2) |
| SFX stub (`_find_sfx_header`) | back to the start, scan up to 2 MiB | the opener passes `start_offset`; skip forward, as ZIP's forward reader does |
| Quick-open record (`_try_list_via_rar5_qo`) | far forward, then back | off: `use_qo=False` already exists |
| "Data past end" message (`_data_past_end`), comment span (`_span_in_file`) | to the end | a short read is the cut; the comment read is already bounded by `max_metadata_bytes` |
| Trailing scan after ENDARC, zeros after a damaged ENDARC (`_scan_after_end_block`, `_only_zeros_after`) | read up to 1 MiB, seek back | the walk ends there, so the read bytes need no replay |
| Header-password retry (`_parse_archive` re-parses per candidate) | back to the start | Decision 5 |

Damage recovery that scans for the next header does not exist in either walk: a bad
header CRC after `MAIN` ends the walk (`damaged`), as a cut does (`truncated`).

What the reader needs about the whole archive before the first member, and whether the
prefix is enough:

| Need | Whole list? |
| --- | --- |
| Solid flag, version, header encryption | `MAIN` / `ENCRYPTION`, before any member |
| Dictionary cost of a solid member | running peak (prefix) |
| File copy targets, hard links | backward only (existing ruling), prefix |
| Metadata budget (`_check_header_metadata_budget`) | total; becomes a running total |
| `-ver` for the demux | chosen at spawn; rolling runs already always pass it |
| Copy sources to keep (`_file_copy_sources`) | counts later copies: not known forward (Decision 7) |
| Data password (`_archive_data_password`) | searches every member (Decision 5) |

`RollingVolumes.write_next` asks its iterator for the next member only once the
current member's data is written, so a generator that yields a member before its data
and resumes the walk after it never has to skip data it has not copied.

## Decisions

### 1. A forward subclass, routed by the backend

`RarForwardReader(RarReader)` in `rar_forward_reader.py`, chosen by
`RarReadBackend.open_read` when the source cannot seek, as ZIP does.
`SUPPORTS_STREAMING_NON_SEEKABLE` becomes `True` for RAR, and the backend refuses at
open what the forward reader cannot read (`streaming=False` is refused by `core.py`
already). The subclass overrides the open sequence (no full parse), `_iter_with_data`,
and the listing hooks, and reuses the member building, verification and demultiplexing
code.

**Rejected:** reading the pipe into a temporary file first. It is what the spool limit
exists to bound, and it is not streaming. **Rejected:** a separate backend class. The
registry, detection and option handling are RAR's; only the open differs.

### 2. The walk becomes a generator over a forward view

`_Rar5Walk` and `_Rar3Walk` gain `blocks()`: the existing loop, yielding each member
(`RarMemberInfo`, its header bytes as read, data offset and packed size) before the
data skip. `run()` stays the seekable entry and drains `blocks()`. The forward source
is a view over the `ArchiveSource` that keeps its own position, serves `seek` to the
current position as a no-op and a forward `seek` as a skip, and raises on a backward
seek, so a missed case fails loudly in tests rather than reading wrong bytes. The walk
is created with `use_qo=False` and a `forward=True` switch for the steps in the table
above.

The consumer reads a member's packed bytes from the view (it is at the data offset when
the member is yielded), so the walk's skip after resuming is a no-op.

**Rejected:** a callback from inside the walk. The data must be copied when `unrar`
asks for the next volume, on the feeder thread, not when the walk reaches it.
**Rejected:** a second, forward-only parser. The two walks hold years of format cases.

### 3. One `unrar` run, members listed as their volume is written

The pass builds `RollingVolumes` over a generator that pulls the walk: for each member
with packed data it builds the synthetic member from the header bytes the walk read
(placeholder name, as `_synthetic_entry` does, without re-reading the source) and a
bounded view of the forward source for its data. `start_rolling_unrar` writes the first
volume; the feeder writes the rest on `unrar`'s prompts.

Each member the walk yields (with data or not) is put on a queue the pass iterator reads
on the caller's thread. A member is queued once the walk has read the next header, so a
RAR 1.5-4 `UOW` or `CMT` service header after it reaches it, or when the volume holding
its first part is written, whichever comes first: a member split across volumes must be
listed before `unrar` prints it. Such a member misses a `UOW` or `CMT` after it, and is
given `MEMBER_HEADER_RECORD_SKIPPED` when the walk reads one. The demultiplexing is the
solid pass's (`plan`, `pipe_offset`, per-member digest and size checks), fed from that
queue instead of `_listed_members()` of a full list. Stored members go through `unrar`
too: one data path, and `unrar` already prints them in order.

No deadlock: before it waits on the queue, the caller reads past `unrar`'s output of the
members it has been given (`SolidBlockReader.skip_to`), and every member whose output
`unrar` can print from a written volume is already queued, so `unrar` reaches its next
prompt.

**Rejected:** reading stored members natively between `unrar`'s members: the source is
one stream, and `unrar` would still need their bytes in its volumes to keep its own
offsets.

### 4. Open reads up to the first member

At open the reader walks `MAIN` (and `ENCRYPTION`) on the caller's thread, so the
solid flag, the version, the header password and the comment of a RAR 1.5-4 main header
are known, and a refusal (Decision 8) comes from `open_archive`. Nothing is spawned
until the pass reads its first member's data.

### 5. One password per pass

`unrar` gets one password at spawn.

- RAR5 `-hp`: the `ENCRYPTION` block's check value picks the candidate at open, with
  no re-parse.
- RAR5 data encryption: the candidate is chosen by the first encrypted member's
  PswCheck. `unrar` is spawned on the first data read, after the first volume is
  written, so a candidate list is judged when an encrypted member is in it. When the
  first encrypted member comes later and there are several candidates, the read raises
  `UnsupportedFeatureError`, naming one password as the fix. A later member whose
  PswCheck rejects that password is refused on its own (the existing mixed-password
  rule), and its output does not line up (Decision 6).
- RAR 1.5-4 `-p`: no check value, so with several candidates each encrypted member is
  refused on its first read (`UnsupportedFeatureError`, naming one password as the fix).
- `-hp`, either version: the walk is started again for each candidate. At open it has
  read only the first headers, which the forward source still holds (its last 4 MiB),
  so the retry needs no re-read of the stream.

**Rejected:** refusing several candidates for RAR 1.5-4 at open, as first planned. The
forward source already holds the bytes an `-hp` retry needs, and refusing an
unencrypted archive for an unused list would be a refusal with no cause.

### 6. A member whose output does not line up ends the pass

The seekable pass reads a nonsolid batch again member by member when a damaged member
makes the output stop lining up. A pipe cannot go back. The forward pass checks each
member's digest and length as today; the first member that fails raises its error, and
the pass ends there: the members after it cannot be placed in the output.

**Rejected:** one `unrar` run per member for nonsolid archives. It isolates damage, but
starts a process per member: thousands of small members would take tens of seconds.

### 7. File copies: kept only within a budget, else refused

A RAR5 file copy (`rar -oi`) reads an earlier member's bytes, which `unrar` does not
print for the copy. The seekable pass keeps exactly the sources later copies need,
counted from the full list. Forward, the counts are unknown, so a copy's stream raises
`UnsupportedFeatureError` on its first read ("the copied member was not kept"). Hard
links and symlinks need no bytes and behave as in the seekable pass.

**Rejected:** keeping every member's bytes in case a copy follows: a pass would hold the
whole archive.

### 8. Refusals at open

On a non-seekable source with `streaming=True`, `open_archive` raises:

| Shape | Error |
| --- | --- |
| Not RARLAB `unrar` 7.00 or later (`unar`, `NONE`, older, missing) | `StreamNotSeekableError`, naming a seekable source or `unrar` 7.00 as the fix |
| A volume of a set (`MAIN` volume flag) | `StreamNotSeekableError` |

The access-mode rule that a pipe refusal comes before the availability check is kept:
the refusal names the program as part of the reason, and is raised by the backend
before any program runs.

## Risks / Trade-offs

- [The walk refactor changes the seekable path] → `run()` drains the same generator;
  the full suite runs it, and the walk's tests stay unchanged.
- [A missed seek in a rare branch] → the forward view raises on a backward seek, and
  every committed RAR fixture is read from a pipe in the tests.
- [A damaged nonsolid member ends a pipe pass where the seekable pass continues] →
  documented as a forward-only difference (Decision 6).
- [Threads: the walk runs on the feeder thread] → the source view is used by that
  thread only once the pass starts; the caller's thread only reads `unrar`'s output and
  the member queue. A walk error is passed to the reader like a volume-write error
  (PR 1552's `VolumeFeeder.error`).

## Open Questions

- Whether a stored-only archive should be read without `unrar` (a later change).
