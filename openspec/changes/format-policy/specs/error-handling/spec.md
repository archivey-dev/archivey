# error-handling — format policy delta

## ADDED Requirements

### Requirement: PackageNotInstalledError carries its missing components

`PackageNotInstalledError` SHALL have a `missing: tuple[MissingComponent, ...]`
attribute holding the packages and programs the raise is about, set on every raise.
For an absent package or program it SHALL name that component; the `unrar` refusals
SHALL fill it from the same components `format_availability` reports. It SHALL be empty
only when the program is present but cannot start, where no component is missing. A
component that the caller's `FormatPolicy` excludes SHALL have the policy as its
`reason`, so a caller tells a policy refusal from a missing install by checking
whether a component's `name` is in its own `exclude_libraries`.

#### Scenario: A missing unrar is data on the exception

- **WHEN** a caller reads a compressed RAR member with no RARLAB `unrar` or `rar` on
  `PATH` and no other usable decompressor
- **THEN** the read raises `PackageNotInstalledError`
- **AND** its `missing` holds a component named `unrar`, the same one
  `format_availability(ArchiveFormat.RAR).missing` names
