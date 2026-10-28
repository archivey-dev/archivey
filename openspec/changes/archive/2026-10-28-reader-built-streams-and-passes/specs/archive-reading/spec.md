## ADDED Requirements

### Requirement: Streams and passes come from archivey

`ArchiveStream` and `MemberPass` SHALL stay public types for annotations and
`isinstance`, but their constructors SHALL NOT be public API: archivey builds them
through private factories, so their construction can change in any release. Until
archivey 0.4.0, a direct call SHALL still work and SHALL emit a `DeprecationWarning`
(DR-12a).

#### Scenario: construction matrix

| Call | Result |
|---|---|
| `ArchiveStream(open_fn, translate=…)` | Working stream; `DeprecationWarning` naming `ArchiveReader.open()` |
| `MemberPass(generator)` | Working pass; `DeprecationWarning` naming `stream_members()` |
| `reader.open()`, `reader.read()`, `stream_members()`, iterating a reader, `open_stream()` | No `DeprecationWarning` |

#### Scenario: private factories

Archivey builds both through private factories, whose names are not public API.

#### Scenario: the published constructor

`dev-docs/api-surface.txt` lists
`init archivey.ArchiveStream(*args: Any, **kwargs: Any) -> None`: the published
constructor carries no internal parameter types.
