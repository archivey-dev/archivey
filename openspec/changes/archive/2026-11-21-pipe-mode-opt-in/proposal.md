## Why

`streaming=True` is a promise about access (one pass), and until now it also read any
source that cannot seek. Pipe mode does not give what a file gives: a ZIP's
permissions, comments and symlink flag arrive only with its index at the end, extraction
stages members before the index, a `filter` rename cannot rescue a name the early path
checks refuse, damaged xz or zstd data loses up to 64 KiB more, a read waits for the
sender to close, and detection sees only the start of the stream. A caller who wrote
`open_archive(f, streaming=True)` for files, as the gotchas page recommends, got pipe
results without any signal as soon as `f` was an HTTP response, an S3 body, stdin, an
object with no `seekable()`, or a `stream_members()` stream.

Maintainer ruling (2026-11-21): pipe reading becomes an explicit, separate mode, "a
single forward read regardless of seekability".

## What Changes

- **Breaking:** `open_archive(pipe=True)` is the only mode that reads a source that
  cannot seek. Without it, `streaming=False` and `streaming=True` both raise
  `StreamNotSeekableError`, naming `pipe=True`.
- `pipe=True` implies `streaming=True` and reads every source as a pipe, a seekable one
  included (`ArchiveSource.read_as_pipe`), so the result depends on the flag, not on
  the object. A directory raises `ArchiveyUsageError`; `concurrent_operations=True`
  raises as with `streaming=True`.
- A format that cannot be read as a pipe keeps its one refusal; under `pipe=True` it
  says to open without the flag.
- A third `open_archive` overload returns `ForwardArchiveReader` for `pipe=`.
- The CLI passes `pipe=True` where it passed `streaming=True` for a read-once input. No
  CLI behaviour changes.

## Impact

- Public API: new keyword `pipe` on `open_archive`. Every caller that reads a pipe,
  socket or HTTP response must pass it.
- `open_stream`, `detect_format`, URL and fsspec reads are unchanged (a range source
  always seeks).
- Specs: `access-mode-and-cost` (the modes), `format-zip` (the pipe requirement), and
  wording in the format specs that named `streaming=True` for a pipe.
