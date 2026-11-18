## ADDED Requirements

### Requirement: An indexed reader reads an archive stored inside its archive

`ReaderContext.open_nested(data, format)` SHALL also be callable from
`IndexedReader.iter_members`, with the behavior it has from a walk: the reader yields a
`MemberRecord` of each span's member at once, in order, and inner reports carry the
outer listing's `member_id`. Called from `IndexedReader.open_member` for a member listed
from an inner archive, over the same inner archive's bytes and format, it SHALL yield one
span, the member being opened, whose `data` is that member's data. Reading the inner
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
