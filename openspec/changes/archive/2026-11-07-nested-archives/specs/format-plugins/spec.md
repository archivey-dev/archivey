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
