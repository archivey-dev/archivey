## ADDED Requirements

### Requirement: Streams and passes come from archivey

`ArchiveStream` and `MemberPass` SHALL stay public types for annotations and
`isinstance`, as base classes with no public constructor: every stream and pass
archivey hands out SHALL be an instance of an internal subclass, so how one is built
can change in any release. Until archivey 0.4.0, calling either base directly SHALL
still work, building that internal subclass, and SHALL emit a `DeprecationWarning`
(DR-12a).

#### Scenario: construction matrix

| Call | Result |
|---|---|
| `ArchiveStream(open_fn, translate=…)` | Working stream; `DeprecationWarning` naming `ArchiveReader.open()` |
| `MemberPass(generator)` | Working pass; `DeprecationWarning` naming `stream_members()` |
| `reader.open()`, `reader.read()`, `stream_members()`, iterating a reader, `open_stream()` | No `DeprecationWarning` |

#### Scenario: internal subclasses

`isinstance(stream, ArchiveStream)` and `isinstance(members, MemberPass)` hold for
everything archivey hands out. The subclasses' names and constructors are not public
API.

#### Scenario: no published constructor

`dev-docs/api-surface.txt` lists no `init` line for `archivey.ArchiveStream` or
`archivey.MemberPass`.
