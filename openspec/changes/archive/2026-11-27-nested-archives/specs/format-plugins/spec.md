## ADDED Requirements

### Requirement: A sequential walk reads an archive stored inside its archive

`ForwardStream.take(n)` SHALL return a stream of the next `n` bytes, read forward from
the archive, that ends after them and raises `TruncatedError` where the archive ends
first. The next `read`, `skip`, `take` or `decompress` on the `ForwardStream` SHALL skip
what the stream left unread; a read of the stream after that SHALL raise
`ArchiveyUsageError`.

`ReaderContext.open_nested(data, format)`, called from `SequentialReader.walk`, SHALL read
`data` with archivey's reader for `format` (or the caller's `FormatPolicy` replacement for
it) in one forward pass and yield one `MemberSpan` per inner member, in the inner
archive's order, its decoded data as `MemberSpan.data`. The inner reader SHALL use the
caller's config and `encoding`; what it reports SHALL go into the outer reader's
diagnostics with `member_id` as the outer listing numbers the member, when the walk
yields each span in order, and SHALL be attached to that member, while its data is read
too; its errors SHALL raise from the walk. Name checks SHALL run once, on the members the
outer listing lists. An archive nested more than 8 deep (`MAX_NESTED_DEPTH`) SHALL be
refused with `UnsupportedFeatureError`.

The levels of one nest SHALL share one budget for each limit, not one each. What an
inner reader keeps beyond the members it hands out (a member it holds back, bytes it
charges with `charge_metadata`, an archive comment, a link target) SHALL count against
`max_metadata_bytes` together with the outermost listing, until the inner reader closes.
The decoders of the levels SHALL share `max_decoder_memory`: an inner reader's decoders
SHALL get the cap less the largest working set each enclosing level declared by the time
the inner archive's first byte was decoded. Every level's decoded bytes SHALL be held to
`max_ratio` of the outermost archive's compressed size, or of the compressed bytes taken
from it so far when that size is unknown.

#### Scenario: nested reads

| Case | Expected |
| --- | --- |
| A walk yields the spans of a `.tar` and a `.tar.xz`, renamed, read from a pipe | The renamed members, their bytes, no diagnostics |
| The same with random access, members opened out of order | The same bytes |
| An inner TAR header with an unknown type, third member listed | One `MEMBER_TYPE_UNKNOWN`, `member_id` 2, attached to that member |
| The same name twice across two inner archives | One `MEMBER_NAME_DUPLICATE` |
| An inner archive shorter than its `take` | The walk resumes after the taken bytes |
| A ZIP inside, read from a pipe | Its members |
| A 7z inside | `UnsupportedFeatureError` |
| `open_nested` called outside `walk()` | `ArchiveyUsageError` |
| A format that names itself as its inner format, 9 levels deep | `UnsupportedFeatureError` |
| A `take` stream read after the walk moved on, one byte read before | `ArchiveyUsageError` |
| 3 levels each hold back a 400-byte member, `max_metadata_bytes=1000` | `ResourceLimitError`; with 1500, the members |
| 3 levels each charge 400 bytes with `charge_metadata`, `max_metadata_bytes=1000` | `ResourceLimitError`; with 1500, the members |
| 3 levels each decode with a 1 MiB LZMA or xz dictionary, `max_decoder_memory` 2.5 MiB | `ResourceLimitError`; with 3.5 MiB, the members |
| The same, each level's member decoded on its own with xz or LZMA Alone through `ReaderContext.decompress` | The same |
| An xz level holds a gzip level that skips 8 MiB of zeros, under 2000:1 to its own input and over 2000:1 to the outermost archive, `max_ratio=2000` | `ResourceLimitError`; with no ratio limit, the members |
