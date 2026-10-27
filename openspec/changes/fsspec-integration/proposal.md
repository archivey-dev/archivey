# fsspec integration: archives as file systems, and remote archives in few requests

> **Design only, after 0.2.0.** Nothing here is implemented. No feature code from this
> change merges before the `v0.2.0` tag. `tasks.md` gives the order of the work for when
> it starts.

## Why

Remote file objects (HTTP, S3, GCS) are an intended use, and the maintainer has said
what that means for the read pattern: read sequentially where possible, and seek as
little as possible. Today a caller can already pass an fsspec file to `open_archive()`,
and every format opens. But the number of requests depends on the cache the caller
happened to choose, and the defaults are poor for archives. Measured on `main` at
8808382 (`design.md` §Measurements):

- With fsspec's default HTTP cache (`readahead`, 5 MiB blocks), listing a 26 MB ZIP
  whose central directory is 28 KB fetches 5.3 MB in 4 requests. Reading one 64 KB
  member then fetches 10.5 MB.
- With no cache, listing a 43 MB TAR takes 297 requests, one per member header.
- Reading one compressed RAR member downloads the whole archive, because `unrar` needs a
  file on disk.

The other half is how most data users would meet archivey. pandas, dask and pyarrow open
files through fsspec URLs. fsspec ships `zip://`, `tar://` and `libarchive://` file
systems, but each covers one family of formats, and the libarchive one needs a seekable
source and has weak random access. None of them has archivey's limits, name checks or
damaged-input handling. An archivey file system would give those users one URL scheme
for every format archivey reads.

## What Changes

- **`open_archive()`, `open_stream()` and `detect_format()` accept an
  `fsspec.core.OpenFile`**, the object `fsspec.open(url, **options)` returns. archivey
  reads it by range through the `OpenFile`'s file system, with no fsspec file cache in
  between, and plans its own fetches (below). It refuses an `OpenFile` whose mode or
  compression it cannot honour. A plain string passed to `open_archive()` stays a local
  path: archivey still never turns a string into a network request.
- **New module `archivey.fsspec`**, importable only when fsspec is installed. `import
  archivey` never imports fsspec. There is no new extra: a caller who reads from S3 or
  GCS already installs `s3fs` or `gcsfs`, and those depend on fsspec.
- **A remote read policy inside `ArchiveSource`.** Read-ahead that grows on sequential
  reads and resets on a jump, a bounded buffer, and range hints from the backends: the
  index location for ZIP and 7z, a member's byte span for ZIP, 7z and ISO, and a gap rule
  for TAR header hops. The hints are internal. Local files ignore them.
- **`ArchiveyFileSystem`**, registered with fsspec as the `archivey` protocol through a
  package entry point, so `archivey://data/train.csv::s3://bucket/set.7z` works in
  `fsspec.open`, `pandas.read_csv` and `dask`. It is read-only, owns its reader and
  closes it, and its tree holds the names `extract_all()` would write under a policy the
  caller names (`STRICT` by default).
- **Sibling volumes over fsspec.** A multi-volume set opened by URL finds its other
  parts with one listing of the parent directory, by the same naming rules as local
  discovery.
- **A new benchmark axis: requests and bytes fetched.** A counting fsspec file system
  over local fixture files records every range request. The structural gate checks
  request and byte counts per format and operation, the same way it checks seek counts
  today.

## Capabilities

### New Capabilities

- `fsspec-integration`: `OpenFile` sources, the remote read policy and its bounds,
  `ArchiveyFileSystem`, and volume discovery over fsspec.

### Modified Capabilities

- `archive-reading`: the three entry points accept an `fsspec.core.OpenFile` (and
  `open_archive()` a sequence of them), with its source facts and refused fields.
- `testing-contract`: a remote-source axis (requests and bytes fetched) is added to the
  benchmark harness and gated as a structural invariant.
- `packaging-and-extras`: the base package declares the `fsspec.specs` entry point, and
  fsspec stays out of every extra.
- `access-mode-and-cost`: the source boundary gains the `OpenFile` read-ahead row and its
  size as a fact, and `detect_format` crosses the boundary for an `OpenFile`.
- `error-handling`: `SourceChangedError`, a `ReadError` subclass.
- `diagnostics`: the advisory code `SOURCE_CHANGE_UNDETECTABLE`, outside
  `ARCHIVE_INTEGRITY_CODES`.

Not here: the CLI's URL arguments (maintainer, 2026-10-25) change the `cli` contract
for which tokens are archive paths and can only be tested once `OpenFile` sources exist,
so they land as their own change after this one.

## Impact

- **Public surface:** one more accepted `source` type for `open_archive()`,
  `open_stream()` and `detect_format()`; one new public module (`archivey.fsspec`)
  holding `ArchiveyFileSystem`; one config field, `ArchiveyConfig.max_read_through`; one
  exception, `SourceChangedError`; and one diagnostic code, `SOURCE_CHANGE_UNDETECTABLE`.
  No new function and no new keyword argument.
- **Internal:** a fetch-planning layer in `ArchiveSource` for remote sources, and a
  small hint call that the ZIP, 7z, ISO and RAR backends make before they read.
- **Benchmarks:** a new structural baseline file for the remote axis.
- **Docs:** a "Remote archives and fsspec" page in `docs/`, and the cache advice for
  callers who keep passing their own fsspec file.
- **Not in scope:** an async API (ADR 0005 stands; fsspec runs its own event loop), writing
  through the file system, and caching decompressed member data.
