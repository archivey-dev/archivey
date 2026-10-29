# format-plugins — format policy delta

## ADDED Requirements

### Requirement: A replacement plugin declares a built-in format and no detection

A `FormatHandler` named in `FormatPolicy(replace=)` SHALL NOT be registered. Its `format`
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
| The value is not a `FormatHandler` subclass | `ArchiveyUsageError` |
