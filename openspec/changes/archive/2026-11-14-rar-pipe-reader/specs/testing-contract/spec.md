## MODIFIED Requirements

### Requirement: Non-seekable stream coverage for streaming backends

The system SHALL test every backend that supports streaming with a **non-seekable
double** that raises `io.UnsupportedOperation` from `seek()` and reports `seekable()` as
`False`. A streaming-capable backend MUST read and iterate correctly without
repositioning the source.

The double SHALL be named in `tests/`, not in this spec. Naming a concrete class here is
what let the spec drift: it named `FakeNonSeekable` — a class that has never existed in
`tests/` — while the double actually used is `NonSeekableBytesIO`. It also described the
double as raising on *every* `seek` **and `tell`** call, which `NonSeekableBytesIO` does
not do: it answers `tell()` from its inner `BytesIO`. Answering `tell()` is load-bearing
rather than an oversight — `ConcatenatedFile.__init__` probes `tell()` then `seek()` on
`BinaryIO` volumes (Path volumes are sized with `stat()`), and
`fix_stream_start_position` needs a position for the mid-stream origin contract — so the
requirement is stated on `seek()` and `seekable()`, which is what the doubles enforce
and what backends branch on.

A backend that requires a seekable source, including ISO and 7z per
`access-mode-and-cost` and the format specs, SHALL fail fast at open time with
`StreamNotSeekableError`, and so SHALL RAR when no RARLAB `unrar` 7.00 or later is
found. So SHALL a backend that reads front to back (TAR, ZIP, the
single-file compressors) opened with `streaming=False`. No backend may implicitly
buffer the non-seekable source to make it seekable. The recovery path is to provide a
seekable source for seek-required formats, or `streaming=True` where the backend reads
front to back.

#### Scenario: non-seekable-source matrix

| Case | Expected |
| --- | --- |
| ZIP opened through a non-seekable double, `streaming=False` | `open_archive` raises `StreamNotSeekableError` at open, naming `streaming=True`; no member data read; never implicitly buffers |
| ZIP opened through a non-seekable double, `streaming=True` | Members are iterable and data is readable without seek/tell; the members after the pass equal those of the same archive read from a file |
| ISO opened through a non-seekable double | `StreamNotSeekableError` at open under the same seek-required rule |
| `.tar.gz` opened through a non-seekable double | Members are iterable and data is readable without seek/tell |
| Caller needs random access to a ZIP from non-seekable input | Use a seekable source; do not rely on Archivey buffering |
