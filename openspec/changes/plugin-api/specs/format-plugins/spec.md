## ADDED Requirements

### Requirement: A package adds a format through archivey.formats

The system SHALL let a package outside archivey add a read-only format by subclassing
`archivey.formats.FormatHandler` and one of `archivey.formats.IndexedReader` or
`archivey.formats.SequentialReader`, and calling
`archivey.formats.register_format()`. A plugin reader SHALL NOT subclass or see
`BaseArchiveReader`. An internal adapter SHALL present it as an ordinary
`ArchiveReader`.

#### Scenario: plugin format through the public API

| Case | Expected |
| --- | --- |
| An LHA plugin is registered; `open_archive("a.lha")` | Reader with `format.container` the plugin's `PluginContainer` member; `members()`, `open()`, `stream_members()`, `extract_all()` work |
| Same, `detect_format("a.lha")` | The plugin format |
| Same, `format_availability("lha")` | `FULL` |
| No plugin registered, `open_archive("a.lha")` | `FormatDetectionError`, as today |

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
| An archive of a sequential plugin format piped to `open_archive(stream, streaming=True)`; `stream_members()` | Every member with its data, in one pass |
| `x.lha.gz` from a file; `open(member)` on the third member | Its data |
| A caller reads half of a member's stream and advances | The next member's header and data are read correctly |

### Requirement: Sequential plugins may hand over decoded member data

A `SequentialReader` whose library decodes each member SHALL be able to yield the
member's decoded bytes as `MemberSpan.data`, with `data_length` 0. The adapter SHALL read
the member through that stream with the checks stored data gets, drain what the caller
leaves (at most one byte past a listed size) before the walk moves on, and serve random
access by walking again from the start to the member, carrying on from the last such
walk when members are opened in archive order. A walk started again SHALL yield the same
members in the same order.

#### Scenario: decoded member data

| Case | Expected |
| --- | --- |
| A pipe; `stream_members()`, each member read part-way | Every member's start, in one walk |
| A file; `open()` on members in archive order | Their data, through one walk after the listing |
| A file; `open()` on a member before the last one opened | Its data, through a walk from the start |
| Decoded data longer than the listed size | `CorruptionError` |
| Decoded data shorter than the listed size | `TruncatedError` when read |
| A second walk yields another member at the opened member's place | `ValueError` (a plugin bug) |

### Requirement: Sequential plugin formats are detected inside compression streams

Detection SHALL check registered sequential plugins' magic inside any single-file
compression stream archivey decodes (gzip, bzip2, xz, zstd and the rest, the set a
compressed TAR has) after TAR, within the prefix and budget the inner-TAR probe uses
today. A plugin with no magic SHALL be found there by its probe, run on the same decoded
prefix under the rule its probe follows on an uncompressed source: where the extension
names the plugin's format inside the compressor (`x.lha.gz`), or `always_probe_content`
is set.

#### Scenario: compressed plugin format

| Case | Expected |
| --- | --- |
| `x.lha.gz` from a file, a sequential plugin for LHA registered; `detect_format` | `ArchiveFormat(LhaContainer.LHA, StreamFormat.GZIP)` |
| No plugin registered; `x.lha.gz` | Detects as `GZ`, as today |
| A sequential LHA plugin with a probe and no magic; gzip of an archive it matches, named `x.lha.gz` | `ArchiveFormat(LhaContainer.LHA, StreamFormat.GZIP)` |
| The same bytes named `x.gz`, default config | `GZ`: the name does not let the probe run |

### Requirement: FormatInfo marks plugin formats

`FormatInfo` SHALL carry `from_plugin`, true for a format added by `register_format()`
and false for every built-in format.

#### Scenario: from_plugin

| Case | Expected |
| --- | --- |
| `format_availability` / `FormatInfo` for a registered plugin | `from_plugin` is `True` |
| The same for `ArchiveFormat.ZIP` | `from_plugin` is `False` |

### Requirement: A package adds a compression format through register_codec

`archivey.formats` SHALL provide `CodecHandler`, `PluginStream` and `register_codec()`.
A handler declares a `PluginStream` member as its `stream_format`, and its
`decompressor(call)` returns a decoder with the interface of `bz2.BZ2Decompressor`.
The `CodecCall` it is given SHALL carry the `size` and `properties` a format reader
passed to `ReaderContext.decompress()`, the caller's `DecoderLimits`, and, during a
detection probe only, the probe's output bound.
After `register_codec()`, archivey SHALL read the format as a single compressed file,
around a TAR, around each sequential plugin format registered before or after it, in
`open_stream()` and in `ReaderContext.decompress()`, and `detect_format`,
`format_availability`, the format lists and `format=` SHALL know it. The decoder's
output SHALL be held to the decoder limits and the ratio guard, and its end of data
SHALL follow the rules of the built-in one-stream codecs (truncation, zero padding,
further streams by magic, trailing data). `FormatPolicy(plugins=False)` SHALL turn the
codec off, and `FormatInfo.from_plugin` SHALL be true for a format that uses it.

#### Scenario: a registered codec

| Case | Expected |
| --- | --- |
| `x.toy` with the codec's magic; `open_archive` | `ArchiveFormat(RAW_STREAM, ToyStream.TOY)`, one member, decoded bytes |
| A TAR inside the codec, no name | `ArchiveFormat(TAR, ToyStream.TOY)` by the inner probe |
| A sequential plugin registered after the codec; `x.cpio.toy` | `ArchiveFormat(CpioContainer.CPIO, ToyStream.TOY)` |
| The stream cut short | `TruncatedError` |
| `ReaderContext.decompress(data, ToyStream.TOY, size=n, properties=p)` | the decoder's `CodecCall` has `size=n`, `properties=p` and the caller's limits |
| The inner-TAR probe decodes the codec | `CodecCall.probe_bound` set; `None` on a read |
| A module in `requires` missing | `FormatSupport.NONE` with the handler's install hint |
| `stream_format = StreamFormat.GZIP`, or a value a built-in uses | `ArchiveyUsageError` at registration |
