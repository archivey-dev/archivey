## Context

A sequential plugin walk yields `MemberSpan`s; a span's data is either stored bytes
(`data_length`) or a decoded stream (`data`). archivey's built-in readers are
`BaseArchiveReader`s, built by a `ReadBackend` over an `ArchiveSource`.

## Decisions

### 1. A public hook, used by deb first

Maintainer, 2026-11-07 (decision card Q9), over two alternatives:

- **Internal composite reader for deb only.** No public name, but each later nested
  format (ipk, Alpine apk, XAR payloads) repeats the plumbing.
- **`archivey.open_archive` inside the walk.** No new name, but the inner reader has a
  collector of its own: copying its diagnostics over escapes their messages twice, and
  their member ids count from 0.

### 2. The inner reader is archivey's own, in streaming mode

`open_nested` builds the registered backend for the format (or the caller's
`FormatPolicy` replacement) over `ArchiveSource.for_stream(data)`, with `streaming=True`,
the outer reader's `encoding`, `archive_name`, `config` and diagnostic collector, and
iterates `stream_members()`. A backend that cannot read a non-seekable source
(`SUPPORTS_STREAMING_NON_SEEKABLE` false: 7z, RAR) is refused with
`UnsupportedFeatureError`. ZIP reads forward and is accepted.

### 3. Member ids: an offset on the collector

The inner reader numbers its members from 0. The outer listing gives them the ids after
the members yielded before, so the hook asks the walk to yield every span in order, and
shifts every `member_id` the inner reader reports by the outer walk index at the call
(`DiagnosticCollector.member_ids_from`, a per-thread offset, entered around each step of
the inner reader and each read of an inner member's data). An offset on the collector
touches one place; numbering inside the inner reader would touch every report site.

### 4. Copies, not the inner reader's member objects

The outer adapter keeps its own state on each member it lists (`_raw`, ids); TAR reads
its own state back from its members at the end of its walk. So the span carries a copy of
the public fields, with the reports attached to the member so far. A report the inner
reader attaches later, while the data is read, reaches the collector but not the copy.

### 5. Name checks once

A nested reader (`_nested_reader`) skips the presentation checks at registration
(deceptive names, duplicates, NUL); the outer listing makes them on the renamed member,
across all the inner archives. Each inner reader still applies the listing limits to
its own members.

### 6. `take()`

`take(n)` returns a buffered stream over the next `n` bytes, read through the
`ForwardStream`'s own read function, so it works on every layer: a pipe, a file and a
`decompress()`ed layer. The next `read`, `skip`, `take` or `decompress` skips what is
left; a read of the stream after that is a plugin bug (`ArchiveyUsageError`).

## Risks

- A walk that drops a span shifts the ids of later reports by one. Documented as part of
  the contract ("yield every span, in order").
- A walk started over to reach member data opens the inner archive again; what it
  reports then is reported again, as a plugin's own reports are.
