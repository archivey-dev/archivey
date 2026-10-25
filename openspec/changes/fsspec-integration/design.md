# Design: fsspec integration

## Context

Two things are asked for, and they share one mechanism:

1. **Remote archives in few requests.** A caller has an archive on HTTP, S3 or GCS and
   wants to list it or read one member without downloading it. This is
   [scenario 9](../../../dev-docs/scenarios.md#9-loading-from-a-remote-file-object), and
   [DR-10a](../../../dev-docs/design-rules.md#dr-10a-read-sequentially-seek-only-when-the-format-needs-it)
   states the rule: read forward in few large reads, read only the index to list and only
   the member's bytes to read it.
2. **Archives as fsspec file systems.** A pandas, dask or pyarrow user writes
   `pd.read_csv("archivey://data.csv::s3://bucket/set.7z")` and gets archivey's formats,
   limits and checks behind fsspec's interface.

The second needs the first: an `archivey::s3://` URL opens a remote archive.

Constraints that bind the design:

- **ADR 0011, zero-dependency core.** fsspec is never a dependency of `archivey`.
- **ADR 0005, sync-only API.** fsspec runs its own event loop for async back ends; the
  archivey side stays synchronous.
- **ADR 0010, no silent buffering of a non-seekable source.** A remote file is seekable
  through range requests, so nothing here buffers a whole source. The RAR spool, which
  already exists and is bounded by `SpoolLimits`, is the one whole-archive copy.
- **Maintainer, 2026-10-09:** "Archivey does not need to accept a URL itself". A `str`
  passed to `open_archive()` stays a local path.
- **DR-9a, the upload-server test.** Read-ahead memory is a fixed bound that does not
  grow with the archive.

## Measurements

Taken on `main` at 8808382, 2026-10-21. Corpus: 300 files, 42 MB, every tenth file
random bytes and the rest text, archived eight ways. Each run opens the archive, lists
it, and for "one" also reads `tree/dir05/file004.txt` (148 KB, near the middle). A local
HTTP/1.1 server with `Range` support logs every request. The scripts and raw logs are
kept beside the project's earlier HTTP range-reading report (2026-09-29), which used
the same method on an older `main`.

Fetch policies:

- **naive**: one GET for exactly each read archivey makes. This shows archivey's own
  read pattern.
- **fsspec default**: `HTTPFileSystem().open(url)`, which is the `bytes` cache with 5 MiB
  blocks. This is what a caller gets today without choosing anything.
- **fsspec blockcache 256 KiB**: the better of fsspec's caches here.
- **doubling**: a read-ahead that doubles on each sequential read up to 8 MiB and resets
  on a jump (the `adaptive` policy of the September study).

GETs and bytes fetched; the HEAD that learns the size is left out of every column.

| Archive (size) | Op | naive | fsspec default | blockcache 256 KiB | doubling |
| --- | --- | --- | --- | --- | --- |
| ZIP deflate (26.5 MB) | list | 6, 37 KB | 4, 5.3 MB | 2, 332 KB | 3, 135 KB |
| | one | 9, 94 KB | 5, 10.5 MB | 3, 594 KB | 4, 266 KB |
| 7z non-solid (25.3 MB) | list | 3, 12 KB | 3, 5.3 MB | 2, 417 KB | 2, 89 KB |
| | one | 5, 70 KB | 4, 10.5 MB | 4, 941 KB | 3, 220 KB |
| 7z solid (24.1 MB) | list | 3, 12 KB | 3, 5.3 MB | 2, 492 KB | 2, 99 KB |
| | one | 52, 12.6 MB | 8, 31.5 MB | 50, 13.1 MB | 10, 19.0 MB |
| RAR5 (26.1 MB) | list | 11, 78 KB | 7, 25.0 MB | 7, 1.8 MB | 7, 518 KB |
| | one | 36, 26.2 MB | 13, 55.3 MB | 104, 27.1 MB | 26, 27.3 MB |
| RAR5 solid (24.8 MB) | list | 16, 118 KB | 8, 33.5 MB | 12, 3.1 MB | 12, 773 KB |
| | one | 40, 24.9 MB | 14, 62.5 MB | 103, 26.8 MB | 34, 25.1 MB |
| TAR (43.0 MB) | list | 297, 2.4 MB | 15, 68.2 MB | 132, 34.4 MB | 156, 28.1 MB |
| | one | 299, 2.6 MB | 16, 73.6 MB | 134, 34.9 MB | 157, 28.3 MB |
| tar.gz (26.0 MB) | list | 400, 27.0 MB | 8, 36.4 MB | 101, 26.0 MB | 12, 26.0 MB |
| | one | 417, 28.1 MB | 9, 41.7 MB | 106, 27.3 MB | 17, 28.0 MB |
| tar.xz (24.3 MB) | list | 373, 24.3 MB | 8, 34.7 MB | 94, 24.4 MB | 11, 24.3 MB |
| | one | 388, 25.3 MB | 9, 40.0 MB | 98, 25.5 MB | 15, 25.3 MB |

What the table says:

- **No single cache policy is right.** The fsspec default fetches 5 MiB per miss, so
  listing any archive costs at least 5 MB, and the RAR header walk and the TAR header
  hops fetch more than the whole archive. Small blocks fix the bytes and multiply the
  requests on sequential data. Doubling is best for sequential data and for listing, and
  still wrong for TAR, where every hop over member data resets it.
- **archivey's own read pattern is already close to the minimum in bytes** for ZIP and
  non-solid 7z (naive column). The native ZIP reader halved the bytes since September
  (37 KB to list, against 102 KB). What remains is request count: 6 GETs where 2 would do.
- **The waste is in the gap between archivey and the cache.** The cache cannot know
  that a ZIP open needs the last 64 KiB and nothing else, or that a TAR hop of 50 KB is
  cheaper to read through than to jump. The backend knows both.
- **RAR reading downloads the archive.** Listing is cheap; reading one compressed
  member spools the whole archive for `unrar`, in every policy.
- **Request latency dominates TAR.** 297 sequential requests took 13 s on localhost. On
  S3 or HTTP over a WAN, each request costs tens of milliseconds before its first byte.

## Decisions

### D1. How a caller hands archivey a remote archive

**Decision: `open_archive()`, `open_stream()` and `detect_format()` accept an
`fsspec.core.OpenFile`**, the object `fsspec.open(url, **storage_options)` returns before
it is entered. archivey never enters it and never opens a file object from it. It reads
the bytes through its own fetch planner (D2), which calls `fs.cat_file(path, start, end)`
on the `OpenFile`'s file system and path, so fsspec's file caches are never involved.
`source` sequences accept `OpenFile` items for an explicit volume list. All three entry
points take the same source types, so `open_archive(of).format_info == detect_format(of)`
keeps holding (`archive-reading` §Archive metadata access, DR-5).

**What archivey takes from the `OpenFile`, and what it refuses.** An `OpenFile` also
carries `mode`, `compression`, `encoding`, `errors` and `newline`, and two of them change
the bytes it would deliver. A raw range read ignores them, so archivey refuses the ones
it cannot honour rather than drop them in silence (DR-1, DR-15):

| Field | Handling |
| --- | --- |
| `fs`, `path` | Used: every range read and the size come from them |
| `mode` other than `"rb"` | `ArchiveyUsageError` (a `ValueError`) naming the mode |
| `compression` not `None` after fsspec resolves it (`"infer"` on `x.zip.gz` is `"gzip"`) | `ArchiveyUsageError` naming the compression and the fix: open without it, and archivey reads the compressed stream itself |
| `encoding`, `errors`, `newline` | Meaningless in binary mode; ignored, as fsspec ignores them for `"rb"` |

**The boundary row for an `OpenFile` source** (`access-mode-and-cost` §boundary table):

| Fact | Value |
| --- | --- |
| `size` | `fs.size(path)`, read once at open, as a **fact**: it clamps reads, the way `stat` does for a path. The archive is the object as it was at open; a later change is D7's to catch, not the clamp's |
| `size_hint` | The same value |
| `path`, `volume_paths` | `None`: there is no local file. A backend that needs a path (RAR's `unrar`) spools, under `SpoolLimits`, as it does for any stream |
| `name` | `of.path`. Detection's name checks and volume discovery (D4) read it |
| `seek_is_expensive` | `True` |
| Ownership | Nothing to close: the planner holds `(fs, path, size)` and its fetched windows, and `close()` drops the windows. The caller's file system object is never closed |

```python
import fsspec, archivey
with archivey.open_archive(fsspec.open("s3://bucket/set.7z", anon=True)) as ar:
    ar.read("data.csv")
```

Why this shape:

- **It keeps the maintainer's rule.** archivey still does not accept a URL. The caller
  builds the `OpenFile` and chooses the protocol, credentials and options; archivey
  never turns a string into a network request. A server that passes user-supplied file
  names to `open_archive()` cannot be made to fetch a URL.
- **DR-14: extend an existing option before adding a new one.** `source` already takes
  paths, streams and sequences. An `OpenFile` is one more kind of source.
- **It gives archivey what it needs and a file object does not:** the file system and
  the path. With those, archivey fetches ranges directly (`fs.cat_file(path, start,
  end)`), learns the size once (`fs.size(path)`), and lists the parent directory to find
  sibling volumes.
- **The check costs nothing without fsspec.** `open_archive()` tests for `OpenFile` only
  when `"fsspec" in sys.modules`. A caller who has not imported fsspec cannot be holding
  an `OpenFile`.

A caller who passes an already-open fsspec file (the object `fs.open(path)` returns)
keeps today's behaviour: archivey reads it as a seekable stream, through the caller's own
cache, and does not close it. archivey does not reach past the caller's object to its
file system: the caller chose that object and its cache, and a file object whose bytes
differ from `fs.cat_file` (a transforming subclass) would then read wrong data (DR-1).
The docs say which form to prefer and why.

Rejected:

- **URL strings in `open_archive()`.** Against the 2026-10-09 rule, and a server-side
  request forgery risk for every caller that passes untrusted names.
- **A separate `archivey.fsspec.open_url(url, storage_options=...)`.** It is
  `open_archive(fsspec.open(url, **opts))` under a second name (DR-14), and it would
  need its own copy of every `open_archive()` keyword.
- **Reading a caller's open fsspec file through its file system.** See above: it
  bypasses the caller's choice and can read the wrong bytes.

### D2. A fetch planner for remote sources

`ArchiveSource` gains one more way to supply its guarantees (`access-mode-and-cost`
§boundary table). For an `OpenFile` source, the raw stream is an internal
`RangeSource` over `(fs, path, size)`. Every byte reaches archivey through
`fs.cat_file(path, start, end)` (or `fs.cat_ranges` for D5). The planner decides each
fetch's start and length:

1. **Doubling read-ahead.** A read that continues where the last fetch ended doubles
   the next fetch, from 64 KiB up to `_MAX_FETCH` (8 MiB). A backward jump, or a forward
   jump past the read-through distance, resets it.
2. **Read through short forward gaps.** A forward seek of at most
   `ArchiveyConfig.max_read_through` bytes (public, default 1 MiB; maintainer,
   2026-10-25) does not end the sequential run: the
   planner keeps fetching through the gap. This is the TAR fix without any TAR code: a
   hop over a small member's data costs bytes, not a request, and a hop over a large one
   is a jump.
3. **Range hints from the backend.** A backend that knows what it will read next says
   so: `source.will_read(start, end)`. The planner fetches that span in one request, up
   to `_MAX_FETCH`, and then continues it as a sequential run. The hint never changes
   what bytes are returned, only how they are fetched. On a local source it does nothing.

   | Backend | Hint |
   | --- | --- |
   | ZIP, open | The last `min(size, 64 KiB + 22)` bytes: the end record, and the whole central directory when it fits |
   | ZIP, open, larger directory | The central directory's span, from the end record |
   | ZIP, member | `[local header, next local header or central directory)`: header, data and data descriptor in one request |
   | 7z, open | The next-header span named by the signature header |
   | 7z, member | The pack stream span, from pack info; for a solid folder, from the folder start |
   | ISO, member | The member's extent |
   | RAR, listing | The next header's position as each block is parsed (it lets the planner tell a header hop from a jump) |
   | TAR | None; rule 2 covers it |

4. **Bounded memory, per reader.** One reader has one window pool, shared by every
   `RangeSource` it opens, so every volume of a multi-volume set draws on the same pool.
   The pool holds at most `_POOL_BYTES` (32 MiB) of fetched data, least recently used
   first out, whatever the archive and however many volumes or streams it has. A volume's
   windows leave the pool by the same rule once nothing reads them. A hinted span longer
   than one fetch is fetched in steps as it is read, not at once.

   Each sequential run (one member stream, or the listing walk) owns at most one window.
   When more runs are active than `_POOL_BYTES / _MAX_FETCH` (4), the planner lowers the
   maximum fetch to `_POOL_BYTES / runs`, down to the 64 KiB minimum. Past 512 concurrent
   runs every fetch is the minimum, and the pool stays at 32 MiB. So eight threads reading
   eight members of one remote ZIP get 4 MiB fetches each, not evictions on every read. A
   remote benchmark case with more streams than windows pins this (`tasks.md` 1.3).

The constants are internal. They are fixed bounds per reader that do not grow with
input, so DR-9 does not ask for a new public limit. If the benchmark or a user shows that
a caller needs to change them, that is a new public field then, not now. The benchmark
sets them through a private seam to small values (64 KiB maximum fetch, 16 KiB
read-through), so that its PR-gated cases exercise every planner rule on the small
fixtures the structural gate already uses (§Benchmark).

What the planner should reach. The ceilings that follow from an index are in the spec;
the rest are what the benchmark baseline records. `F` is the maximum fetch and `G` the
read-through distance.

| Archive | List | List and read one member | Where it comes from |
| --- | --- | --- | --- |
| ZIP, directory within the last 64 KiB | 2 (head for detection, tail) | 3 | Spec ceiling |
| 7z, non-solid | 2 (head, next header) | 3 | Spec ceiling |
| 7z, solid | 2 | bytes fetched ≤ folder start to member end + F | Spec ceiling on bytes; the request count is the doubling ramp over that span |
| ISO | baseline only (directory records are scattered) | list + 1 | Spec ceiling on the member read |
| RAR5 | baseline only. The header walk reaches the last header near the end, so it fetches most of the archive's byte range in steps; on the measured corpus doubling took 7 requests | unchanged until D6 | Spec ceiling: bytes fetched ≤ archive size + F |
| TAR | baseline only; about size / F requests plus one per member larger than G | the same | Spec ceiling: bytes fetched ≤ archive size + F |
| tar.gz, tar.xz | about size / F | the same | Spec ceiling: bytes fetched ≤ archive size + F |

The "≤ archive size + F" ceiling is the one that matters for these formats: it is the
fsspec default cache's failure (68 MB fetched to list a 43 MB TAR) stated as a bound.
RAR5's quick-open record could bring its listing to a few requests; whether to read it
is an open question on the RAR handbook page and not part of this change.

Rejected:

- **Pick an fsspec cache per format.** The table shows every cache is wrong somewhere,
  and none of them can take a hint. The planner is about 200 lines and owns the policy.
- **A per-source memory bound.** Volumes and streams would multiply it, and the count
  of both comes from the archive.
- **A public `advise()` on archivey streams.** Callers never need to say this; backends
  do.

### D3. `ArchiveyFileSystem`

A subclass of `fsspec.archive.AbstractArchiveFileSystem`, protocol `archivey`,
registered through the base package's `fsspec.specs` entry point, so it exists for
fsspec as soon as archivey is installed, without an import.

```python
ArchiveyFileSystem(
    fo,                          # an fsspec URL, an OpenFile, a path, or a binary file object
    *,
    target_protocol=None,        # fsspec's chained-URL arguments, as zip:// takes them
    target_options=None,
    format=None, password=None, encoding=None, config=None,
    policy=ExtractionPolicy.STRICT,  # the name transform the tree uses; extract_all's default
    **kwargs,                    # passed to AbstractFileSystem
)
```

- **It opens the archive once,** with `seekable_members=True` and
  `concurrent_operations=True`, because fsspec consumers seek (pyarrow reads Parquet
  footers first) and open several files at once (dask). A string `fo` goes through
  `fsspec.open(fo, protocol=target_protocol, **target_options)` and then D1, so a chained
  URL gets the fetch planner.
- **A string `fo` reaches the network, unlike `open_archive(str)`.** This is what an
  fsspec protocol is for, and it is the first archivey API where a string can open a
  connection: `ArchiveyFileSystem(fo="https://…")` and every `archivey://…::…` URL reach
  whatever protocol the chain names. fsspec splits a chain on `::`, so a service that
  builds `archivey://{member}::{trusted_url}` from a caller's member name lets that name
  add a protocol of its own. The docs page and the threat model say so, and say that a
  member name from a caller is passed as the path argument of `fs.open()` on an
  `ArchiveyFileSystem` built from a trusted `fo`, never formatted into a URL.
- **The tree is the extraction view, for one named policy.** A path in the file system
  is the relative path `extract_all(dest, policy=policy)` would give that member: the
  policy's name transform (normalization, refusals, and re-rooting of absolute names
  under `STANDARD` and `TRUSTED`; refusal under the default `STRICT`) and directories
  implied by member paths. `policy` is a constructor argument because it is an
  `extract_all()` argument, not an `ArchiveyConfig` field. `STRICT` rewrites or refuses
  a name the same way on every OS, so dask workers on mixed platforms see one tree. A
  duplicate name shows its current entry (the reader's own last-entry-wins rule,
  `ArchiveMember.is_current`). A member the policy refuses is not in the tree, and the
  refusal is a diagnostic on the reader, readable as `fs.reader.diagnostics`.

  What the tree does not model: anything that depends on a destination directory
  (`overwrite=`, an existing file, a name collision on a case-insensitive disk) and the
  `filter=` callback. A caller who wants a filtered view filters the paths it reads.

  The reason for the extraction view is DR-5: the same archive gives one result. A pandas
  user must not see a file that `archivey extract` would not write, or the other way
  round.
- **Links.** A link whose target resolves to a member appears as that member's type,
  with `"islink": True` and `"destination"` in its info, and opens the target (archivey's
  transparent link following). A link that resolves to nothing is listed with type
  `"other"`; opening it raises `FileNotFoundError`.
- **`info()`** carries fsspec's `name`, `size` and `type`, plus `mtime` (POSIX seconds)
  when the member has a time, and `member`, the `ArchiveMember`. `size` is the member's
  declared size, or `None` when the format does not record one before the data.
- **Read-only.** Every write method and every non-read `open` mode raises
  `NotImplementedError`, as fsspec's other read-only file systems do.
- **Errors.** A missing path raises `FileNotFoundError` and a directory opened for
  reading raises `IsADirectoryError`. archivey's own errors pass through unchanged
  (DR-15a), so a damaged member still raises `CorruptionError` from `read()`.
- **Pickling.** dask sends file systems to worker processes. The file system pickles
  as its constructor arguments and opens the archive again on the other side. It
  pickles when `fo` is a URL or an `OpenFile` and the archivey arguments pickle; a file
  object `fo` raises `TypeError` naming the reason.
- **Lifetime: the file system owns its reader, and `cachable = False`.** fsspec's
  instance cache keeps a strong reference to every cached instance until
  `clear_instance_cache()`, so a cachable file system that holds an open reader would
  never be collected: every distinct archive opened through an `archivey://` URL would
  keep its listing, its source and any RAR spool (up to `SpoolLimits.max_bytes`) for the
  life of the process. That fails DR-9a. The cache would not even give sharing between
  dask threads, because fsspec puts the thread id in the cache key for a synchronous
  file system. So `cachable = False`, as `ZipFileSystem` has. The instance owns the
  reader: `fs.close()` (and leaving `with ArchiveyFileSystem(...) as fs:`) closes it, and
  a `weakref.finalize` closes it when the instance is collected, so a caller who drops
  every reference does not leak it. Member streams opened from the file system keep the
  instance alive until they close.

Nested archives need nothing extra: `archivey://a.csv::archivey://inner.zip::s3://b/outer.tar`
chains two file systems, and the inner one reads a seekable member stream of the outer.
A compressed outer member re-decodes on a backward seek, with archivey's usual
loud-slow-rewind warning.

Rejected:

- **Registering `zip`, `tar` or `7z` protocols.** fsspec owns the first two, and taking
  any of these names would change what other people's URLs mean.
- **Showing raw member names.** The tree would then contain `../x` and duplicate paths,
  which no file system can hold, and would differ from what extraction writes.

### D4. Sibling volumes over fsspec

For an `OpenFile` source, volume discovery lists the parent directory once
(`fs.ls(parent, detail=False)`) and applies the same naming rules as local discovery
(`archive-reading` §Multi-volume). `discover_volume_siblings` is split so that the rules
run on a list of names, and the local and fsspec callers each supply the list. Each
volume becomes its own `RangeSource`. A file system without listing (plain HTTP) finds no
siblings, and a multi-volume open then fails as it does today for a lone first volume;
an explicit sequence of `OpenFile` objects is the way to open those.

### D5. Batched fetches for whole-archive passes

`extract_all()` and `stream_members()` over a non-solid ZIP or 7z know every member span
before they start. With the spans as hints, the planner can coalesce adjacent spans
into one request and prefetch the next span while the current one decodes, through
`fs.cat_ranges`, which fsspec runs concurrently for async file systems. This is a later
stage: the planner of D2 already turns each member into one request, and the benchmark
will show whether the remaining latency matters.

### D6. RAR members over a remote source

Reading a compressed RAR member needs `unrar`, which needs a file. Today the whole
archive is spooled, bounded by `SpoolLimits.max_bytes` (1 GiB) and announced in
`CostReceipt.notes`. Over a remote source that copy is a full download.

A **sparse spool** could cut it: a temporary file of the archive's full length that holds
only the bytes `unrar` reads (every block header, whose offsets the native parser
already knows, and the target member's data; for a solid archive, the data of every
member before it), with holes elsewhere. Whether `unrar` reads anything else (a
recovery record, the quick-open data, the end-of-archive block) has to be measured
first, with a test that fills the holes with garbage and checks that the output and the
CRC verdict do not change. This is an investigation task, not a commitment. Until it
lands, the cost note stays as it is.

### D7. A changed remote object

An object can be replaced between two range requests (an S3 overwrite during a long
read). A ranged read then returns bytes of a different archive, and the CRC catches it
only for data that has a checksum. In order of strength:

1. **Pin a version** when the file system offers one: s3fs with `version_aware=True`,
   gcsfs generations. Every fetch then reads the object as it was at open.
2. **Make the server refuse a changed object** when the file system passes request
   headers through (`HTTPFileSystem` forwards `headers=` to each request): send
   `If-Match` with the `ETag` seen at open, so a replaced object answers 412 instead of
   other bytes.
3. **Otherwise nothing can see a same-length replacement.** Comparing the total size on
   each fetch catches a replacement of a different length only. This is an accepted
   non-guarantee, recorded in the threat model beside the others, and the reader says so
   at open with a diagnostic of the `DIGEST_UNVERIFIABLE` kind (advisory; §Decisions 3), so that silence never reads as "checked".

A change that is caught raises `SourceChangedError` (§Decisions 3).

## Benchmark: requests and bytes fetched

The structural gate counts seeks today. This change adds a remote axis.

- **`benchmarks/remote.py`** defines `CountingFileSystem`, an fsspec file system over
  local fixture files. It records each `cat_file` / `cat_ranges` range, each `info` /
  `size` call and each `ls`. It needs no network and is deterministic, so its counts are
  exact on every host.
- **Cases**, per format: open and list; read the first, a middle and the last member;
  `extract_all()`; one `stream_members()` pass under `streaming=True`; and one read
  through `ArchiveyFileSystem` (`fsspec.open("archivey://m::counting://fixture")`).
- **Recorded per case:** `range_requests`, `metadata_requests`, `bytes_fetched`, and
  `bytes_needed`, the least the operation can read (the index bytes plus the member's
  stored span, or the whole archive for a compressed TAR). `overfetch = bytes_fetched /
  bytes_needed` is the figure to watch.
- **Gate:** `range_requests` exact and `bytes_fetched` at most the baseline, in
  `benchmarks/baselines/remote.json`, updated with `--update-baselines` like
  `structural.json`. Both are structural invariants, so they block a PR.
- **Fixtures and scale.** The PR-gated cases run on the `ci` scale the structural gate
  already builds (`benchmarks/fixtures.py`), with the planner's constants set small
  through its private seam (64 KiB maximum fetch, 16 KiB read-through, 256 KiB pool), so
  each case still crosses windows, gaps and runs and no large archive is built on a PR.
  The generator stays seeded, so member spans and the exact counts are the same on every
  host. The production constants run on the `realistic` scale in the change-guarded
  nightly that already runs the wall job; those numbers are reported, not gated.
- **More streams than windows.** One case reads eight members of one ZIP from eight
  threads under `concurrent_operations=True`, so the shrinking-fetch rule of D2 is
  pinned.
- **Informational:** a modelled time, `range_requests x 30 ms + bytes_fetched / 50 MB/s`,
  printed beside each case so that a change that trades requests for bytes can be judged.
  Not gated.
- **A real-HTTP check, off the PR path.** `benchmarks/remote_http.py` runs the same cases
  against a local range server through fsspec's `HTTPFileSystem`. Its counts must equal
  the counting file system's; a difference means the model misses something the real
  path does. It also records the "caller's own fsspec file with the default cache"
  numbers, which the docs quote.

## Decisions by the maintainer (2026-10-25)

The open questions of the first draft, and the review's decision card:

1. **Remote listing of a format without an index (TAR, RAR5): a public knob.**
   `ArchiveyConfig.max_read_through` (bytes, default 1 MiB): a forward gap of at most this
   is read through, a longer one is a new request. The default sits just under the
   break-even of one request against its bytes (about 30 ms × 50 MB/s ≈ 1.5 MB), leaning
   toward fewer requests. `0` means "fetch only what is needed". It replaces the
   internal `_READ_THROUGH`; the benchmark still sets small values through it. It is the
   one public addition to the planner (D2's other constants stay internal).
2. **The CLI accepts URLs.** When fsspec is installed, an argument with a `scheme://`
   prefix fsspec knows, that is not an existing local path, is opened as
   `fsspec.open(arg)`.
3. **A detected change raises `SourceChangedError`**, a new subclass of `ReadError`, at
   open or later (D7). It is not damage, so not `CorruptionError`, and a distinct type
   lets a caller reopen and retry. Where no guard exists (no version pinning, no
   `If-Match`), the reader emits an advisory diagnostic at open saying that changes
   cannot be detected; like `DIGEST_UNVERIFIABLE`, `STRICT` does not refuse on it.
4. **No download-size cost figure.** If a user asks, the honest form is an
   after-the-fact count of bytes fetched, not a prediction.
