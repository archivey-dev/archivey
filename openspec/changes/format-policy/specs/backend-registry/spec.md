# backend-registry — format policy delta

## ADDED Requirements

### Requirement: The caller's format policy decides whether a detected format opens

`ArchiveyConfig.formats` SHALL hold a `FormatPolicy`. After detection, or after an
explicit `format=`, `open_archive` and `open_stream` SHALL refuse a format the policy
does not allow, with `UnsupportedFeatureError` whose `source_format` is that format and
whose message names the policy entry that would allow it. The policy SHALL NOT change
which format detection reports (see `format-detection` for the one exception).

#### Scenario: A compression missing from an allow-list is refused

- **WHEN** a caller opens a gzip-compressed TAR with
  `FormatPolicy(only={ContainerFormat.TAR})`
- **THEN** the open raises `UnsupportedFeatureError` that names `StreamFormat.GZIP`
- **AND** `detect_format` on the same file still reports `ArchiveFormat.TAR_GZ`

### Requirement: A replacement plugin reads a built-in container

A `FormatPolicy(replace={container: plugin})` SHALL open that built-in container with
the plugin's reader. Detection SHALL stay the built-in's, `reader.format` SHALL be the
built-in format, and `format_info.from_plugin` SHALL stay false.

The replacement SHALL NOT be given a multi-volume set, an archive found behind an SFX
stub, or a read-once source. Each SHALL raise `UnsupportedFeatureError` that names the
replacement, before the plugin's `open` runs.

#### Scenario: A ZIP opens with the replacement

- **WHEN** a caller opens a ZIP file with `FormatPolicy(replace={ContainerFormat.ZIP: P})`
- **THEN** `P.open` reads it and `reader.format` is `ArchiveFormat.ZIP`

#### Scenario: A replacement is not given a volume set

- **WHEN** a caller opens the first part of a multi-volume ZIP set with
  `FormatPolicy(replace={ContainerFormat.ZIP: P})`
- **THEN** the open raises `UnsupportedFeatureError` that names `P`
- **AND** `P.open` is not called
