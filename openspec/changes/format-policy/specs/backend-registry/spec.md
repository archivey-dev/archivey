# backend-registry — format policy delta

## ADDED Requirements

### Requirement: The caller's format policy decides whether a detected format opens

`ArchiveyConfig.formats` SHALL hold a `FormatPolicy`. After detection, or after an
explicit `format=`, `open_archive` and `open_stream` SHALL refuse a format the policy
does not allow, with `UnsupportedFeatureError` whose `source_format` is that format and
whose message names the policy entry that would allow it. The policy SHALL NOT change
which format detection reports, except that the content probe of a plugin the policy
turns off SHALL NOT run.

#### Scenario: A compression missing from an allow-list is refused

- **WHEN** a caller opens a gzip-compressed TAR with
  `FormatPolicy(only={ContainerFormat.TAR})`
- **THEN** the open raises `UnsupportedFeatureError` that names `StreamFormat.GZIP`
- **AND** `detect_format` on the same file still reports `ArchiveFormat.TAR_GZ`

#### Scenario: A plugin that is off runs no code

- **WHEN** a plugin with a content probe is registered and a caller opens a file with
  `FormatPolicy(plugins=False)`
- **THEN** the plugin's probe is not called

### Requirement: A replacement plugin reads a built-in container

A `FormatPolicy(replace={container: plugin})` SHALL open that built-in container with
the plugin's reader. Detection SHALL stay the built-in's, and `reader.format` SHALL be
the built-in format.

#### Scenario: A ZIP opens with the replacement

- **WHEN** a caller opens a ZIP file with `FormatPolicy(replace={ContainerFormat.ZIP: P})`
- **THEN** `P.open` reads it and `reader.format` is `ArchiveFormat.ZIP`

### Requirement: An excluded optional library reads as not installed

When `FormatPolicy.exclude_libraries` names an optional package, archivey SHALL treat
that package as not installed for every call made with that config: an accelerator
under `AUTO` SHALL fall back, a member that needs it SHALL raise
`PackageNotInstalledError` when opened, and a format that needs it SHALL refuse at open.
The error SHALL name the policy as the reason. archivey SHALL NOT call into the package
during such a call.

#### Scenario: An excluded pyppmd refuses only the PPMd member

- **WHEN** a caller opens a 7z archive that holds a PPMd member and a LZMA2 member with
  `FormatPolicy(exclude_libraries={"pyppmd"})`, with `pyppmd` installed
- **THEN** both members are listed
- **AND** reading the PPMd member raises `PackageNotInstalledError` that names the policy
- **AND** the LZMA2 member reads
