# packaging-and-extras — format policy delta

## ADDED Requirements

### Requirement: An excluded optional library reads as not installed

When `FormatPolicy.exclude_libraries` names an optional package, archivey SHALL treat
that package as not installed for every call made with that config: an accelerator
under `AUTO` SHALL fall back, a member that needs it SHALL raise
`PackageNotInstalledError` when opened, and a format that needs it SHALL refuse at open.
The error SHALL name the policy as the reason. archivey SHALL NOT call into the package
during such a call. The exclusion SHALL apply only to calls made with that config:
another call in the same process, on any thread, SHALL see the package as it is.

`format_availability(fmt, config=...)` and `list_supported_formats(config=...)` SHALL
count an excluded package as absent, listing it in `missing` with the policy as its
`reason`. Without `config` they SHALL answer what the environment provides.

#### Scenario: An excluded pyppmd refuses only the PPMd member

- **WHEN** a caller opens a 7z archive that holds a PPMd member and a LZMA2 member with
  `FormatPolicy(exclude_libraries={"pyppmd"})`, with `pyppmd` installed
- **THEN** both members are listed
- **AND** reading the PPMd member raises `PackageNotInstalledError` that names the policy
- **AND** the LZMA2 member reads
- **AND** `format_availability(ArchiveFormat.SEVEN_Z, config=...)` with the same config
  reports `PARTIAL` with `pyppmd` in `missing`

#### Scenario: Excluding one zstd module falls through to the other

- **WHEN** both `compression.zstd` and `backports.zstd` import, and a caller opens a
  `.zst` file with `FormatPolicy(exclude_libraries={"compression.zstd"})`
- **THEN** the file decodes with `backports.zstd`
- **AND** with both names excluded the open raises `PackageNotInstalledError` that names
  the policy

