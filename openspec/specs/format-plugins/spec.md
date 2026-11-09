# format-plugins Specification

## Purpose
TBD - created by archiving change format-policy. Update Purpose after archive.
## Requirements
### Requirement: A replacement plugin declares a built-in format and no detection

An `IndexedFormatHandler` named in `FormatPolicy(replace=)` SHALL NOT be registered. Its `format`
SHALL be the built-in `ArchiveFormat(key, StreamFormat.UNCOMPRESSED)` of the container
it replaces, the key SHALL be `ZIP`, `SEVEN_Z`, `RAR` or `ISO`, the plugin SHALL be an
indexed one, and it SHALL declare no `extensions`, `magic` or `probe`. Building the
policy SHALL refuse any other plugin with `ArchiveyUsageError`, so a bad replacement
fails before any open.

#### Scenario: replacement refusals

| Case | Expected |
| --- | --- |
| `replace={ContainerFormat.ZIP: P}`, `P.format` is `ArchiveFormat.ZIP`, no signals | Accepted |
| `replace={ContainerFormat.TAR: P}` | `ArchiveyUsageError` naming `ContainerFormat.TAR` |
| `P.format` is a plugin format, or another built-in format | `ArchiveyUsageError` |
| `P` declares `extensions`, `magic` or `probe` | `ArchiveyUsageError` |
| `P` is a sequential plugin | `ArchiveyUsageError` |
| The value is not an `IndexedFormatHandler` subclass | `ArchiveyUsageError` |

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

