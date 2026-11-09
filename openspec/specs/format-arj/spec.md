# ARJ Archive Support

## Purpose

ARJ archives (`.arj`; what ARJ for DOS, ARJ32 and ARJ for Unix write) are read through
the unified `ArchiveReader` API. The reader is a built-in written against
`archivey.formats` and registered with `register_builtin_format`; methods 1 to 4 are
decoded by archivey's own decoders, in Python. The format handbook is
`dev-docs/formats/arj.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Listing header by header, direct access, seekable source required |
| `format-detection` | `60 EA` at offset 0 |
| `format-plugins` | The handler and reader API the backend is written against; `FormatPolicy(replace=)` accepts `ContainerFormat.ARJ` |
| `archive-data-model` | `CompressionAlgorithm.LZH` and `ARJ_FAST` |
| `diagnostics` | `ARCHIVE_EOF_MARKER_MISSING` with `expected_marker="end_of_archive_header"` |
| `format-lha` | Shares the LZH decoder: ARJ methods 1 to 3 are its `"arj"` method |

## Requirements

### Requirement: Read an ARJ archive's members from a seekable source

The ARJ backend SHALL read the main header, then list one member per header, in archive
order, until the end header or the end of the file, checking the CRC-32 of each basic
and extended header. A member SHALL be named by its stored name, with `\` separators
turned into `/` when the host is MS-DOS, OS/2 or Windows. It SHALL carry the stored and
original sizes, the modification time (a Unix time in UTC when the host is Unix or NeXT,
a naive DOS time otherwise), `accessed` and `created` when the header has them, the Unix
mode (Unix hosts) or `windows_attrs` (other hosts), the host as `create_system`, and
`extra["arj.method"]` and `extra["arj.file_type"]`. File types 0 and 1 SHALL be files, 3
a `DIRECTORY`, and 6 with a `U` extended header a `SYMLINK` or `HARDLINK` with its
target, or `OTHER` for a FIFO or device; types 4, 5 and a type 6 without the header
SHALL be `OTHER`. The backend SHALL read stored members and decode methods 1 to 4, check
each member's CRC-32 and report a member read to its end as `Verification.CHECKSUM`. A
pipe SHALL be refused with `StreamNotSeekableError`.

#### Scenario: ARJ listings

| Case | Expected |
| --- | --- |
| ARJ 3.10's archives of each method | The same bytes the files had; `LZH` for methods 1 to 3, `ARJ_FAST` for 4 |
| ARJ 3.10 symlink, hard link, FIFO and directory | `SYMLINK`, `HARDLINK` to the first name, `OTHER`, `DIRECTORY` |
| Commons Compress's three ARJ archives | The same listing and bytes as Commons Compress |
| A DOS-host member with `\` separators | `/` separators; DOS time; `windows_attrs` |
| No end header after the last member | Every member listed; `ARCHIVE_EOF_MARKER_MISSING` |
| `0x00` or `0x1A` padding after the end header | No diagnostic |
| Other bytes within 64 KiB after the end header | `ARCHIVE_TRAILING_DATA` |

### Requirement: Refuse what the ARJ reader cannot read

The backend SHALL raise `CorruptionError` for a header without `60 EA`, a basic header
over 2600 bytes or under its fixed part, a basic or extended header that fails its
CRC-32, a name with no NUL, a second main header, a Unix special header cut short, more
than 1 MiB of extended headers on one member, and a member whose data fails its CRC-32.
It SHALL raise `TruncatedError` for a file that ends inside a header or a member's data.
A garbled member SHALL be listed with `is_encrypted` and raise `UnsupportedFeatureError`
when read, as SHALL a member split across volumes and a method past 4.

#### Scenario: ARJ refusals

| Case | Expected |
| --- | --- |
| A header byte changed | `CorruptionError` (CRC) |
| A member's data changed | `CorruptionError` |
| The file cut inside a member | `TruncatedError` |
| A garbled member | Listed, `is_encrypted`; `UnsupportedFeatureError` on read |
| Volume flag `0x04` or `0x08` | `UnsupportedFeatureError` on read |
| Method 9 | Listed as `UNKNOWN`; `UnsupportedFeatureError` on read |
