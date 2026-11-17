## ADDED Requirements

### Requirement: An archive stored as a program resource

A PE program can hold an archive as one of its resources, inside its resource section,
with other resources, other sections and a certificate table after it (Squirrel's setup
program holds its ZIP this way). For a backend whose format can carry a stub (ZIP, 7z,
RAR), on a seekable source of known size, `open_archive` SHALL let the backend learn the
file extents of the resources of a PE program at the start of the source, read from its
headers and the start of its resource directory, whether the format was detected or
named. The ZIP, 7z and RAR (lone archive) readers SHALL NOT report
`ARCHIVE_TRAILING_DATA` for a non-zero byte that lies at or past the end of the resource
whose data holds the archive's end. A non-zero byte after the archive and before that
resource's end SHALL be reported as before. An archive whose end lies in no resource
SHALL be reported as before. The extents SHALL be read only when a reader has found a
non-zero byte after its archive, at most 4096 header bytes and 64 KiB of resource tables,
and they SHALL NOT change what the archive lists. LHA is not covered and reports as
before.

#### Scenario: archive stored as a program resource

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| ZIP, 7z or RAR filling one resource, other resources and `.reloc` after it, detected or forced | Nothing reported | Opens |
| The same, signed | Nothing reported | Opens |
| Zero padding after the archive inside its resource | Nothing reported | Opens |
| Non-zero bytes after the archive inside its resource | `ARCHIVE_TRAILING_DATA`, measured from the archive's end | Refused |
| Archive appended in the overlay of a program that has resources, bytes after it | `ARCHIVE_TRAILING_DATA` | Refused |
| GitHub Desktop's Squirrel installer | `ZIP` at 169 888, 5 members, nothing reported | Opens |
| No trailing bytes | The resource table is not read | Opens |
