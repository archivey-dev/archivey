## Why

Reading an archive from a URL is silent until it ends, and one range request can take
seconds. A local `test` or `extract` of a large `.xz` or `.tar.gz` cannot show a
percentage either: the output size is not known in advance, so
`ExtractionProgress.total_bytes_estimated` is `None`. What a caller can measure in both
cases is how far archivey has read through the archive's own file. Nothing reports it:
`extract_all(on_progress=)` reports output written, and the request counters behind the
CLI's `--track-io` are internal.

The maintainer asked for a callback any caller can hook, and a CLI display built on it
(2026-11-20). He approved the names, one callback for local and remote sources, and
0.6.0 as the release.

## What Changes

- New `ArchiveyConfig.on_source_read: Callable[[SourceProgress], None] | None`, called
  as archivey reads the archive's own file.
- New public dataclass `SourceProgress`: the file's display name, its size, the bytes
  read from it so far, the current position, and for a URL source the request count and
  the current request's range, bytes received and whether it is done.
- A local file or stream reports about once per MiB read, from `ArchiveSource`
  (`ArchiveyConfig.source_read_step`; `0` reports every read, and `read_start` gives
  each read's range, a log of every region read). A URL
  (fsspec) source reports at the start and end of each range request, from
  `RangeSource`. Detection's reads count.
- Every reader reports to the callback in its own config. A reader opened with `parent=`
  reports with `SourceProgress.nest_level` one more than its parent's; each reader
  reports the bytes it reads from its own source, at its own level. A member stream
  opened without `parent=` is a source of its own, at level 0. Bytes an external program
  (`unrar`) or the RAR backend reads from volume paths directly are not seen.
- The callback runs on the thread that read. A read on a thread archivey started (the
  RAR volume feeder) does not call it: the latest such report is kept and delivered on
  the caller's next read of the archive or of the member being read. Reports in between
  are merged, so `requests` may skip numbers. An exception it raises propagates out of
  the read.
- Over HTTP, a request also reports about once per MiB of its answer as it comes in:
  the adapter reads the body one event-loop call per chunk, so the callback runs on the
  caller's thread between chunks.
- Later in this change: the CLI status line for URLs and the input-position bar for
  `test` and `extract` (tasks 3.x).

## Capabilities

### Modified Capabilities

- `archive-reading`: a requirement for `on_source_read`.
- `cli`: a requirement for the line that shows the reads of the archive's file.

## Impact

- Public: `ArchiveyConfig.on_source_read`, `archivey.SourceProgress`. A minor release
  (0.6.0).
- Internal: `internal/read_progress.py` (the reporter), hooks in
  `internal/source.py` and `internal/remote.py`, wiring in `core.py`.
- Cost when unset: one `is None` check per source read or request.
