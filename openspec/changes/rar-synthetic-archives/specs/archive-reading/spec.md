# archive-reading — synthetic archives for `unrar`

## ADDED Requirements

### Requirement: Deprecate the RAR glob concatenation switch

`ArchiveyConfig.rar_allow_glob_member_concatenation` SHALL stay a `bool` field that
defaults to `False`, and SHALL change no read: no RAR read refuses a member for a name
whose mask selects other members. A caller constructing a config with the field set to
`True` SHALL get a `DeprecationWarning` naming the field; the copies archivey makes of
that config for itself SHALL NOT warn again. The field SHALL be removed in a later
minor release.

#### Scenario: deprecated field matrix

| Case | Expected |
| --- | --- |
| `ArchiveyConfig()` | No warning |
| `ArchiveyConfig(rar_allow_glob_member_concatenation=True)` | `DeprecationWarning` naming the field; reads are the same as with `False` |
| `open_stream(src, config=cfg)` with `cfg` built with the field `True` | No second warning from archivey's own copy |
| `ArchiveyConfig(rar_allow_glob_member_concatenation="false")` | `ArchiveyUsageError` at construction, as before |
