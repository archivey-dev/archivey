## ADDED Requirements

### Requirement: A package adds a format through archivey.plugins

The system SHALL let a package outside archivey add a read-only format by subclassing
`archivey.plugins.FormatPlugin` and one of `archivey.plugins.IndexedReader` or
`archivey.plugins.SequentialReader`, and calling
`archivey.plugins.register_format()`. A plugin reader SHALL NOT subclass or see
`BaseArchiveReader`. An internal adapter SHALL present it as an ordinary
`ArchiveReader`.

#### Scenario: plugin format through the public API

| Case | Expected |
| --- | --- |
| A CPIO plugin is registered; `open_archive("a.cpio")` | Reader with `format.container` the plugin's `PluginContainer` member; `members()`, `open()`, `stream_members()`, `extract_all()` work |
| Same, `detect_format("a.cpio")` | The plugin format |
| Same, `format_availability("cpio")` | `FULL` |
| No plugin registered, `open_archive("a.cpio")` | `FormatDetectionError`, as today |

### Requirement: Plugin containers subclass PluginContainer

`ArchiveFormat.container` SHALL accept a member of a `PluginContainer` subclass and keep
it unchanged. `register_format()` SHALL refuse with `ArchiveyUsageError` a container
value equal to a built-in or registered one, and an extension a built-in format claims.

#### Scenario: registration refusals

| Case | Expected |
| --- | --- |
| Plugin container value `"zip"` | `ArchiveyUsageError` |
| Plugin extension `".tar"` | `ArchiveyUsageError` |
| Same plugin registered twice | `ArchiveyUsageError` |

### Requirement: Built-in detection signals outrank plugin signals

A plugin magic or probe match SHALL count only when no built-in format matched at the
same or a higher confidence. A plugin probe SHALL receive only the prefix detection
already read. A probe that raises SHALL count as no match, so one plugin cannot change
how unrelated input fails to be detected; `MemoryError` and `OSError` still propagate.

#### Scenario: plugin magic does not change built-in detection

| Case | Expected |
| --- | --- |
| A plugin declares magic `PK\x03\x04`; a ZIP is detected | `ArchiveFormat.ZIP` |

### Requirement: Plugin member data is checked like built-in member data

The adapter SHALL verify every plugin member stream against the listed size and the
digests the plugin returns, and SHALL apply the built-in name normalization, name checks,
listing limits and extraction limits to plugin members.

#### Scenario: plugin data checks

| Case | Expected |
| --- | --- |
| Plugin stream shorter than the listed size, read to the end | `TruncatedError` |
| Plugin returns a CRC-32 that does not match | `CorruptionError` |
| Plugin lists a member named `../x`; `extract_all` | Refused as for a built-in format |

### Requirement: Sequential plugins read forward-only sources

A `SequentialReader` plugin SHALL be readable from a non-seekable source in one forward
pass through `stream_members()`, iteration and `extract_all()`, with the listing limits
enforced as members arrive. The adapter SHALL own each member's data window and skip
what the caller leaves unread. On a seekable source the adapter SHALL serve random access
without an `open_member` from the plugin.

#### Scenario: sequential plugin sources

| Case | Expected |
| --- | --- |
| A CPIO archive piped to `open_archive(stream, streaming=True)`; `stream_members()` | Every member with its data, in one pass |
| `x.cpio.gz` from a file; `open(member)` on the third member | Its data |
| A caller reads half of a member's stream and advances | The next member's header and data are read correctly |

### Requirement: Sequential plugin formats are detected inside compression streams

Detection SHALL check registered sequential plugins' magic inside a gzip, bzip2, xz or
zstd stream after TAR, within the prefix and budget the inner-TAR probe uses today.

#### Scenario: compressed plugin format

| Case | Expected |
| --- | --- |
| `x.cpio.gz` from a file; `detect_format` | `ArchiveFormat(CpioContainer.CPIO, StreamFormat.GZIP)` |
| No plugin registered; `x.cpio.gz` | Detects as `GZ`, as today |

### Requirement: FormatInfo marks plugin formats

`FormatInfo` SHALL carry `from_plugin`, true for a format added by `register_format()`
and false for every built-in format.

#### Scenario: from_plugin

| Case | Expected |
| --- | --- |
| `format_availability` / `FormatInfo` for the registered CPIO plugin | `from_plugin` is `True` |
| The same for `ArchiveFormat.ZIP` | `from_plugin` is `False` |
