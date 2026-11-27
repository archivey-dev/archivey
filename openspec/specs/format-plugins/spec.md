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

`ReaderContext.open_nested(data, format)`, called from `SequentialReader.walk`, SHALL
read `data` with archivey's reader for `format` (or the caller's `FormatPolicy`
replacement for it) in one forward pass and yield one `MemberSpan` per inner member, in
the inner archive's order, its decoded data as `MemberSpan.data`. The inner reader SHALL
use the caller's config and `encoding`; what it reports SHALL go into the outer reader's
diagnostics with `member_id` as the outer listing numbers the member, when the walk
yields each span in order, and SHALL be attached to that member, while its data is read
too; its errors SHALL raise from the walk. Name checks SHALL run once, on the members
the outer listing lists. The inner reader SHALL join the outer reader's nest
(`archive-reading`, "A reader opened inside another joins its nest"): it shares
`max_metadata_bytes` through the outermost listing, charges what its listing decodes to
the enclosing listing's `max_decoded_bytes` while that listing runs, gets the
`max_decoder_memory` the open outer levels left, is held to `max_ratio` against the
outermost archive, and counts toward the nest's totals ("Limits apply per nest"). A
chain of more than nine archives, the outermost included and readers opened with
`open_archive(..., parent=)` counted too (`MAX_NESTED_DEPTH` is 8 levels below the
outermost), SHALL be refused with `UnsupportedFeatureError`.

#### Scenario: nested reads

- **WHEN** a call is made as each row says
- **THEN** it behaves as the row's Expected column says

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
| An `open_nested` archive inside a reader opened with `parent=` 8 levels below the outermost | `UnsupportedFeatureError` |
| A `take` stream read after the walk moved on, one byte read before | `ArchiveyUsageError` |

### Requirement: A reader names the borders between the trees it joins

`ReaderContext.open_nested(data, format, under=..., keep_out=...)` SHALL check each
inner member against the borders the call names before it yields the member's span,
and raise `CorruptionError` naming the member for one that crosses a border. With
`under="F/"` it SHALL list each inner member under `F/` (`.` as `F/` itself) and a hard
link's `link_target` with it, and refuse a member whose name, or a hard link whose
target, extracts outside `F/` under any policy or filter, compared spelled as `F` is.
With `keep_out=("K/", ...)` it SHALL refuse a member that can reach `K/` under any
spelling that extraction or a filesystem takes for `K` (`collision_key`): by its name,
by a hard link's target, by a symlink whose target lands there, read lexically or
through the inner archive's earlier symlinks, or through a later symlink that redirects
an earlier one. With either option it SHALL refuse a member under a symlink of the
inner archive, a symlink at the path of a directory or of another symlink, and a
directory at a symlink's path. With `keep_out`, the path steps taken inside symlink
targets and in re-resolving earlier targets SHALL count against
`ListingLimits.max_members` (`ResourceLimitError`); with `under` alone no target is
resolved. A rooted folder, one with `..`, an empty one, or a single `str` for
`keep_out` SHALL raise `ArchiveyUsageError`.

`ReaderContext.read_nested(span)` SHALL return the whole data of a span `open_nested`
yielded and the span with its data served from those bytes, which count once toward
`ListingLimits.max_decoded_bytes`. A span whose data `open_nested` did not make SHALL
raise `ArchiveyUsageError`.

#### Scenario: borders

- **WHEN** a walk calls `open_nested` as each row says
- **THEN** the listing behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| `under="Payload/"`, inner `.`, `a`, a hard link `h` to `a`, a symlink `l -> a` | `Payload/`, `Payload/a`, `Payload/h` linked to `Payload/a`, `Payload/l -> a` |
| `under="Payload/"`, inner `../Bom`, `a\..\..\Bom` or `../payload/x` | `CorruptionError` |
| `under="Payload/"`, inner `l -> ..`, then `l/Bom` | `CorruptionError` naming `l/Bom` |
| `under="Payload/"`, 20 chained symlinks, `max_members=100` | Lists |
| `keep_out=("DEBIAN/",)`, inner `debian/control`, `d -> .` then `d/DEBIAN/control`, `x -> y/DEBIAN/control` then `y -> .` | `CorruptionError` |
| `keep_out=("DEBIAN/",)`, inner `usr/share/DEBIAN`, `usr/lib/libfoo.so -> libfoo.so.1` | Lists |
| `under="/Payload"`, `under="a/../b"`, `keep_out="DEBIAN/"` | `ArchiveyUsageError` |
| `read_nested` of each span of a 50 kB `.tar.xz` file, `max_decoded_bytes` 80 000 | Lists; the same bytes in a `BytesIO` raise `ResourceLimitError` |

### Requirement: An indexed reader reads an archive stored inside its archive

`ReaderContext.open_nested(data, format)` SHALL also be callable from
`IndexedReader.iter_members`, with the behavior it has from a walk: the reader yields a
`MemberRecord` of each span's member at once, in order, and inner reports carry the
outer listing's `member_id`. Called from `IndexedReader.open_member` for a member listed
from an inner archive, over the same inner archive's bytes and format, it SHALL yield
one span, the member being opened, whose `data` is that member's data. Reading the inner
archive forward to that member SHALL report nothing the listing reported. When the
member's data stream is closed, the next member opened further on in the same inner
archive SHALL carry on from that point, so a pass over the members in order reads each
inner archive once. Called from `open_member` for any other member, it SHALL raise
`ArchiveyUsageError`.

#### Scenario: nested reads from an indexed reader

| Case | Expected |
| --- | --- |
| An indexed reader lists a `.tar` and a `.tar.xz` and opens their members out of order, and again | The bytes; a hard link names its prefixed target |
| An inner TAR header with an unknown type, then every member read | One `MEMBER_TYPE_UNKNOWN`, `member_id` 2 |
| `extract_all` of a package with two payloads | Each payload read once after the listing |
| `open_nested` from `open_member` of a member no inner archive holds | `ArchiveyUsageError` |
