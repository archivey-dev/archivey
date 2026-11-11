# 7. Pipes, files and the compromises between them

**In one minute.** A file on disk can be read in any order. A pipe (`sys.stdin`, a socket,
a download in progress) can be read once, front to back. Remote objects sit in between:
you can seek, but each seek can cost a network round trip. Archive formats were designed
with different assumptions: ZIP puts its index at the end, 7z too, TAR has no index at all,
and compressed data cannot be entered in the middle. Archivey's answer is to make the
caller say what they will do (`streaming=`), to keep the expensive capabilities off until
asked for (`seekable_members=`, `concurrent_operations=`), to never buffer a pipe behind
the caller's back, and then to make each format do the best it honestly can in each mode.
This page explains the three switches, what each format can do from a pipe, and every
place where the code had to bend.

## The three switches, and why they exist

### `streaming` (ADR 0004)

`open_archive(source, streaming=False)` (the default) promises random access: list the
members, open any of them, in any order, as often as you like. That needs a source that
can seek. `streaming=True` is the caller's promise to read once, front to back, through
`stream_members()`, iteration or `extract_all()`; in exchange, archivey can read from a
pipe. `members()`, `get()`, `open()` and `read()` raise on a streaming reader, uniformly,
for every format. Even the types say so: `open_archive(..., streaming=True)` is annotated
to return a `ForwardArchiveReader`, which lacks those methods.

An earlier design had an `Intent` enum (`AUTO`, `SEQUENTIAL`, `RANDOM`). It was dropped:
`AUTO` never chose anything by itself, so there were really two modes, and a bool says
that (ADR [0004](../decisions/0004-streaming-bool-not-intent-enum.md)).

### `seekable_members` and `concurrent_operations` (ADR 0003)

Two traps hide behind innocent-looking code:

- **Seeking inside a compressed member.** `f.seek(0)` after reading a 1 GB `.gz` member
  means decompressing 1 GB again, unless there is an index.
- **Overlapping opens.** Two member streams open on a `.tar.gz` or a solid 7z fight over
  one decoder, and each switch can mean decoding again from the start.

A developer who tests on ZIP, where both are cheap, would ship code that is slow on TAR
and 7z. So both are **off by default**, uniformly for every format, the directory reader
included: member streams report `seekable() == False`, and a second live `open()` raises
`ArchiveyUsageError`. A caller turns each on by name, and then it is a guarantee: with
`seekable_members=True`, every format that can open a member must be able to seek in it,
slow rewinds included (amended in PR #299). Seek indexes and accelerators are built only
on demand. A `stream_members()` stream never seeks, with or without the flag (maintainer,
2026-09-26): a pass reads forward, and that is what keeps it cheap.

`concurrent_operations=True` makes every operation work as if it ran on a reader of its
own: several threads can open members, run passes and extract at once. Combined with
`streaming=True` it is refused, because a single forward pass cannot fan out.

### No silent buffering (ADR 0010)

With `streaming=False` and a pipe, archivey refuses at open. It does not quietly copy the
pipe to memory or a temp file "to make ZIP work". That copy has no bound, and a caller who
thought they were streaming would never see it. The error says what to do: open with
`streaming=True`, or buffer it yourself (ADR
[0010](../decisions/0010-no-silent-buffer-nonseekable.md)). The one place archivey does
copy a source to disk is RAR's `unrar`, which can only read files, and that copy is
bounded by `SpoolLimits` and declared ([below](#rar-an-external-program-that-wants-a-file)).

## What each format can do from a pipe

The backend declares it (`SUPPORTS_STREAMING_NON_SEEKABLE` and `NON_SEEKABLE_REASON` on
the `ReadBackend`; `non_seekable_reason` on an indexed handler):

| Format | From a pipe (`streaming=True`) | Why |
| --- | --- | --- |
| TAR, `.tar.gz` and every compressed TAR | Yes | Header, data, header, data: made for tapes |
| CPIO, ar, RPM, deb | Yes | The same shape (sequential readers) |
| Single compressed file (`.gz`, `.xz`, …) | Yes | One stream, decoded forward |
| ZIP | Yes, with compromises | Each member has a local header in front of it; the index at the end arrives last |
| 7z | No | Its index is at the end of the file |
| RAR | No | The header walk seeks past each member's data, and `unrar` reads members from a file on disk |
| ISO, SquashFS, CAB, XAR | No | Their directories point at data anywhere in the file |

For the "No" rows, `open_archive` refuses *before* checking optional packages, with a
message that names the only fix, so a piped ISO without `pycdlib` is told about the pipe
rather than sent to install a package that would not help.

## Detection on a pipe

Detection must look at the first bytes, but the backend needs those bytes too, and a
pipe cannot be rewound. So the `ArchiveSource` of a non-seekable source keeps a **replay
prefix**: `peek()` fills it without consuming, and the backend's first reads drain it
before reading the pipe. Detection and the backend read the same object; nothing is
swapped in between.

The compromises:

- The prefix can grow to 2 MiB (`SFX_MAX`), the window of the scan for an archive behind
  an executable stub, even though most detection needs 4 KiB. The cost receipt reports
  what was read.
- **Trailer magic is not checked on a pipe.** DMG's `koly` block is in the last 512
  bytes; a pipe cannot be read to its end and given back.
- **The size is unknown**, so checks that use it (the archive-wide ratio limit, the "is
  this ISO big enough" gate) fall back or wait.

## ZIP from a pipe

A ZIP is laid out like this:

```
[ local header · data · data descriptor? ] × n      member by member
[ central directory ] [ end record ]                 after the last member
```

From a file, archivey reads the end record and the central directory first (`zip_reader.py`).
From a pipe it must read front to back (`zip_forward_reader.py` over `zip_local_walk.py`),
and the central directory, which holds the authoritative metadata, arrives **after every
member**. The consequences:

- **Members are yielded before they are final.** The local header has the name, sizes and
  method, but the permissions, the host system, the comment, and the facts that decide the
  *type* (is this a symlink? a directory?) are only in the central directory. So members
  are yielded with `member_state_final=False` and updated in place at the end of the pass.
  A symlink is yielded looking like a file. The `stream_members()` docstring warns: do not
  act on those fields in a way you cannot take back until the flag is true.
- **Extraction stages, then places.** `extract_all()` from a pipe writes each member's data
  into a private staging directory under the destination, and only after the central
  directory has arrived places the members, in listing order, by rename
  (`ExtractionCoordinator._stage_then_place`, PR 920). A member that turned out to be a
  symlink is then created as a symlink, not left as a file.
- **Sizes can come after the data.** With bit 3 set, the sizes and CRC are in a data
  descriptor *after* the data. For a compressed member the decoder finds the end. For a
  STORED member nothing marks the end, so the walk scans for a descriptor whose CRC matches
  the bytes before it. A directory written that way gets no stream at all.
- **Passwords.** With several candidate passwords, the pass cannot go back to try another.
  The first candidate that passes the cheap key check is used, and the CRC or
  authentication code at the member's end reports a wrong pick. The maintainer chose
  this (2026-10-14) and recorded it as a choice that may change: spooling the encrypted
  data to try each candidate is the known alternative.
- **Damage shows late.** A truncated ZIP from a file fails at open (no end record). From a
  pipe it fails when the walk reaches the cut, after the members before it were delivered.

With a seekable source, `streaming=True` uses the index-first reader anyway: it reads the
central directory first, so members are final from the start.

## TAR, and solid archives in general

TAR has no index, so listing *is* reading. Two consequences show up everywhere:

- **Listing a `.tar.gz` decompresses it.** The cost receipt says so
  (`REQUIRES_SCANNING`), and random access over a compressed TAR is "solid": opening the
  last member decodes everything before it.
- **The pass reads through the walk.** In random access, before the walk has finished,
  `stream_members()` reads each member's data through the walk's own stream, so the
  archive is decoded once, not once to list and once to read
  ([page 4](04-readers-and-members.md#walks-and-passes)). If the caller holds on to a
  member while the walk moves on, the member's stream switches to its own view from where
  it stopped (`internal/walk_handoff.py`).

The same idea applies to every **solid** archive (7z folders, solid RAR): the cheap way to
read everything is one pass in archive order, `stream_members()`, which decodes each solid
block once. `open()` in an arbitrary order decodes each member's block from its start. The
first time an `open()` decodes again what an earlier open already decoded, the reader
records `SOLID_OPEN_REDECOMPRESSES` (logged at INFO), with the hint to use
`stream_members()`. A caller who asked for random access gets it, and gets told what it
costs; `reader.cost` says the same up front.

Links make streaming harder too: in a streaming pass, a symlink's target can be settled
only when the pass reaches it, and the end of the archive can still change `is_current`.

## RAR: an external program that wants a file

No good library decodes RAR, so member data comes from RARLAB `unrar p`, a separate
process writing to a pipe (ADR [0002](../decisions/0002-native-rar-metadata-unrar-data.md)).
`unrar` reads only seekable files on disk. The metadata is parsed by archivey's own
parser, so listing needs no program at all.

- **A path source** is handed to `unrar` directly. Members stored uncompressed and
  unencrypted are read by archivey itself, with no process.
- **A stream source** (a `BytesIO`, a remote object) has no path. Archivey writes a small
  **synthetic RAR** to a temp file for each read: a header it makes, the member's own
  stored header (with the name replaced by `m0`, `m1`, …), its packed bytes copied
  verbatim, and an end header (`rar_synthetic.py`). For a solid member, the chain from
  the start of its solid stream. Before this, the first read from a stream copied the
  whole archive to disk: 1,350 ms to read a 1.2 KB member of a 200 MiB archive from a
  `BytesIO`, against 7 ms from a path. The copies are bounded by `SpoolLimits.max_bytes`.
- **Seeking** in a member read from a pipe uses `RespawnStream`: a forward seek reads and
  drops, a backward seek starts `unrar` again from the start.

## Seeking inside a member

With `seekable_members=True`, a backward seek finds the nearest seek point and decodes
forward from there, or from the start when there is none
([page 6](06-streams-and-codecs.md#how-a-seek-works)). Seek points come from the format's
own index (xz, a zstd seek table, BGZF), from snapshots taken about every MiB for DEFLATE,
or from the accelerator. `ArchiveStream.nearest_resume_offset(target)` tells a caller where
a seek would resume. Which seeks need a full re-decode depends on the decoder, and is not
part of the API.

### What a seek does to the checksum (DR-4a)

The integrity promise is for a member read from start to end with no skipped bytes. A seek
keeps the digest when nothing is actually skipped: a seek back (the bytes were already
hashed), a forward seek whose gap is decoded anyway (the next read hashes the gap), a seek
to the end (the concluding read hashes the rest). A seek that jumps by an index or the
accelerator, then a read past it, *pauses* the check; a seek back to where the reads had
reached completes it. The maintainer's summary: "we'd only lose the check for indexed or
accelerated seeks" (PR 743). The rules are
[DR-4a](../design-rules.md#dr-4a-the-integrity-guarantee-is-for-a-start-to-end-read).

## Remote objects: seekable, but each seek costs

Archives are often read from object storage or HTTP. A seek there is a request. So
archivey treats cost in seeks and bytes read, not wall time
([DR-10a](../design-rules.md#dr-10a-read-sequentially-seek-only-when-the-format-needs-it)):
read forward, in few large reads, and only the parts the operation needs.

An `fsspec` `OpenFile` passed to `open_archive` is never entered. Every byte comes from
`fs.cat_file(path, start, end)` through archivey's own fetch planner (`internal/remote.py`):

- a run of sequential reads doubles its fetch size from the third fetch, so a header probe
  never pays for read-ahead but a long read gets big requests;
- a short forward gap is read through rather than starting a new request
  (`ArchiveyConfig.max_read_through`);
- a backend can say "I am about to read this span" (`MemberData.ranges`, `_will_read`),
  and the first read inside it fetches the whole span in one request;
- all windows of one reader share a bounded memory pool.

The size comes from one `fs.size()` call and is a fact. The benchmark harness counts seeks
and bytes read per operation, and a PR that adds a seek to a common path fails it.

## Limits that behave differently on a pipe

- **The archive-wide ratio limit** divides the bytes written by the archive's size. From a
  pipe the size is unknown, so it divides by the bytes read so far, and that is unfair at
  the start: a `.tar.gz` that begins with 64 MiB of zeros looked like a bomb from a pipe
  and passed from disk, which broke "same input, same outcome". The live check now waits
  for `live_ratio_activation_threshold` (default 256 MiB)
  before it applies; `max_extracted_bytes` still bounds the total (PR 775).
- **A hard link whose source the caller filtered out** can be recovered from a seekable
  source by a second pass. From a pipe the source's bytes are gone, so that link fails
  under the caller's `OnError` setting.
- **A same-name pair in a streaming TAR**: the later copy replaces the earlier one on disk
  and the earlier result is reported `SUPERSEDED`, exactly as in random access. The
  maintainer's rule: "both modes should always end up the same on disk unless there's a
  strong reason that makes it impossible" (2026-09-25).

## The compromises, in one list

| Compromise | Where | Why it is acceptable |
| --- | --- | --- |
| A pipe with `streaming=False` is refused | `core.py` | The alternative is an unbounded hidden copy (ADR 0010) |
| 7z, RAR, ISO, SquashFS, CAB, XAR cannot come from a pipe | backend declarations | Their layouts need seeks; the caller can buffer |
| Member streams do not seek by default | ADR 0003 | Seeking backwards in compressed data can be very costly; opting in is one keyword |
| One live member stream by default | ADR 0003 | Overlap on a solid archive thrashes the decoder |
| `stream_members()` streams never seek | ADR 0003 amendment | A pass reads forward; that is its whole point |
| Members from a ZIP pipe are not final until the end | `zip_forward_reader.py` | The central directory comes last; `member_state_final` says so, extraction waits |
| Pipe ZIP extraction stages its data | `extraction.py` | Placement needs the central directory's types |
| `open()` on a solid archive decodes the block again | 7z, RAR, compressed TAR | The caller asked for random access; the diagnostic and the cost receipt say what it costs |
| Index-based seeks trust the index | threat-model O17 | Checking it would mean decoding everything |
| A seek that jumps pauses the checksum | DR-4a | The skipped bytes were never decoded |
| RAR from a stream writes small temp files | `rar_synthetic.py` | `unrar` reads only files; copies are bounded by `SpoolLimits` |
| The live ratio check starts late on a pipe | `bomb_tracker.py` | Honest archives with a blank start must pass, as from disk |
| No trailer detection on a pipe | `detection.py` | The end of a pipe cannot be read and given back |
