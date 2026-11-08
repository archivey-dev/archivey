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
reader attaches later, while the data is read, is passed on to the copy after each read
(`_NestedData`), so `member.diagnostics` holds it as it would for the inner format read
on its own.

### 5. Name checks once

A nested reader (`_nested_depth` above 0) skips the presentation checks at registration
(deceptive names, duplicates, NUL); the outer listing makes them on the renamed member,
across all the inner archives. Each inner reader still applies the listing limits to
its own members. The budgets are shared across the levels (§8).

### 6. `take()`

`take(n)` returns an unbuffered stream over the next `n` bytes, read through the
`ForwardStream`'s own read function, so it works on every layer: a pipe, a file and a
`decompress()`ed layer. A read fills what it asks for, as a buffered stream's does. The
next `read`, `skip`, `take` or `decompress` skips what is left; a read of the stream
after that is a plugin bug (`ArchiveyUsageError`). With no buffer in between, that read
raises even when an earlier read was a short one.

### 7. Depth

Each nested reader records its depth (`_nested_depth`), one more than the reader that
opened it, and `open_nested` refuses past `MAX_NESTED_DEPTH` (8) with
`UnsupportedFeatureError`. Formats that nest go one or two levels deep; a walk that
reads its inner format from its own bytes could otherwise recurse until Python's
recursion limit, a bare `RecursionError` on a 19 KB input. The iterators `open_nested`
returns are kept in a weak set and closed with the archive at the latest.

### 8. One budget for the nest

Maintainer ruling, 2026-11-08: "charge across the nesting". With `open_nested` the
library recurses, not the caller, so 8 levels must not get 8 times each cap. A reader
learns the reader it reads inside while it is built (`archivey.internal.nesting`).

- **`max_metadata_bytes`.** An inner reader's members reach the outermost listing as
  copies that share their strings, and the outermost tracker counts them there, so an
  inner tracker counts its members for itself only. What an inner level keeps beyond
  them (a held member, an archive comment, a link target weighed late, a TAR sparse map)
  is charged to the outermost tracker as well, whose checks count it until the inner
  reader closes (`ListingLimitTracker._charge_outward`).
- **`max_decoder_memory`.** The decoders of the levels run at once: the inner archive's
  bytes come out of the outer decoder. An inner reader gets the outer reader's config
  with `max_decoder_memory` less the largest working set the outer reader recorded
  (`_PluginAdapter._nested_config`). A level thus counts as one decoder holding its
  largest declaration, which over-counts a decoder that has ended and so can only refuse
  more. Inside one level the cap stays one decoder's, as for an archive that is not
  nested. The working sets liblzma and libzstd check themselves are recorded too: an xz
  stream's first block dictionary, an LZMA Alone header's dictionary, a zstd frame's
  window.
- **`max_ratio`.** An inner reader's ratio guards divide by the outermost archive's
  compressed size (or its live count of bytes taken), not by the bytes of the inner
  archive. Dividing by the inner archive's own bytes lets each level expand its input
  by the ratio again, so a nest of `n` levels decodes up to the ratio to the `n`-th
  power. With the outermost denominator each level decodes at most the ratio times
  what the caller handed over, and the nest at most `n` times that. The members the
  walk yields stay counted by the outermost reader's own guards as before.

## Risks

- A walk that drops a span shifts the ids of later reports by one. Documented as part of
  the contract ("yield every span, in order").
- A walk started over to reach member data opens the inner archive again; what it
  reports then is reported again, as a plugin's own reports are.
