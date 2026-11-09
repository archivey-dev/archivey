# LHA Archive Support

## Purpose

LHA archives (`.lzh`, `.lha`, `.lzs`, `.pma`; what LHarc, LHA, UNLHA32, LHa for UNIX,
Amiga LhA, LHARK, LArc and PMarc write) are read through the unified `ArchiveReader`
API. The reader is a built-in written against `archivey.formats` and registered with
`register_builtin_format`; the LZH methods are decoded by archivey's own decoder, in
Python. The format handbook is `dev-docs/formats/lha.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Listing header by header, direct access, seekable source required |
| `format-detection` | A method id (`-lh0-` to `-pm2-`) at offset 2 |
| `format-plugins` | The handler and reader API the backend is written against; `FormatPolicy(replace=)` accepts `ContainerFormat.LHA` |
| `archive-data-model` | `CompressionAlgorithm.LZH` |
| `diagnostics` | `ARCHIVE_EOF_MARKER_MISSING` with `expected_marker="end_of_archive_byte"` |

## Requirements

### Requirement: Read an LHA archive's members from a seekable source

The LHA backend SHALL list one member per header, in archive order, reading header levels
0, 1, 2 and 3 and their extended headers, until a zero byte or the end of the file. A
member SHALL be named by its directory record and name joined with `/`, `0xFF` and `\`
separators turned into `/` (the `\` after decoding). It SHALL carry the stored size, the
Unix mtime (UTC) when the header has one and the DOS time (naive) otherwise, `created`
and `accessed` from a Windows timestamps record, the Unix mode, uid, gid, user and group
names when stored, and the OS id as `create_system` and `extra["lha.os_id"]`.
`extra["lha.method"]` SHALL name the method and `extra["lha.header_level"]` the level. A
`-lhd-` member SHALL be a `DIRECTORY`, or a `SYMLINK` when its mode is a symlink, its name
split at `|` into name and target. The backend SHALL read stored members (`-lh0-`,
`-lz4-`, `-pm0-`) and decode `-lh4-` to `-lh7-`, `-lhx-` and `-lk7-`, check each member's
CRC-16 and report a member read to its end as `Verification.CHECKSUM`. It SHALL follow
lhasa where writers disagree: a level-1 `-lh7-` member with OS id `' '` is `-lk7-`; an
Amiga `-lh0-` member with no name and size 0 is a directory; OS-9/68k's level-2 header is
two bytes longer than its size says; OS-9 permissions become a Unix mode. A pipe SHALL be
refused with `StreamNotSeekableError`.

#### Scenario: LHA listings

| Case | Expected |
| --- | --- |
| Members of each decoded method at each header level, written by the test writer | The same members and bytes; each `CHECKSUM`; lhasa extracts the same bytes |
| lhasa's test archives (LHa for UNIX, UNLHA32, LHA for OS/2, Amiga LhA, OS-9/68k LHA, LHARK, LArc, PMarc, MorphOS LhA) | The same members and bytes as lhasa extracts |
| Commons Compress's fifteen LHA archives | The same listing and bytes as Commons Compress |
| A Unix level-2 header with mode, owner and directory records | `mode`, `uid`, `gid`, names joined with `/` |
| A Unix symlink (`name|target`) | `SYMLINK` with that target |
| A `-lhd-` symlink with no `|` | `SYMLINK`, no target; `SYMLINK_TARGET_UNAVAILABLE` |
| Windows timestamps and 64-bit size records | `created`, `accessed`, the 64-bit sizes |
| An Amiga name with a NUL | The name before it; the note after it as `comment` |
| A cp932 name opened with `encoding="cp932"` | The Japanese name, whole |
| A level-2 header padded by a byte | Read, padding skipped |
| An invalid DOS time | `modified is None`; `MEMBER_TIMESTAMP_INVALID` |
| No zero byte after the last member | Every member listed; `ARCHIVE_EOF_MARKER_MISSING` |
| `0x00` or `0x1A` padding after the end byte | No diagnostic |
| Other bytes within 64 KiB after the end byte | `ARCHIVE_TRAILING_DATA` |

### Requirement: Refuse damaged and unsupported LHA archives

The backend SHALL list a member of a method it does not decode (`-lh1-`, `-lh2-`,
`-lh3-`, `-lzs-`, `-lz5-`, `-pm1-`, `-pm2-`, or another) and raise
`UnsupportedFeatureError` when it is read. It SHALL raise `CorruptionError` for a header
that fails its 8-bit sum or its common-record CRC-16, a level past 3, a name or extended
header past its header, a level-3 header over 1 MiB, level-1 extended headers longer than
the stored size, and a file that starts with the end byte; and, when reading, for a data
CRC-16 that does not match, a code length over 16 bits, a table that over- or underfills
its code space, a symbol past its table, or a match from further back than the window. A
member whose data runs past the file SHALL raise `TruncatedError` at listing, and a
stream that needs more than 32 zero bytes past its input SHALL raise `TruncatedError` when
read.

#### Scenario: LHA refusals

| Case | Expected |
| --- | --- |
| An `-lh1-` member | Listed; `UnsupportedFeatureError` on read |
| A flipped header byte at level 0 or 1 | `CorruptionError` at open |
| A changed name at level 2 or 3 | `CorruptionError` (header CRC) at open |
| A wrong data CRC | `CorruptionError` on read |
| Header level 4 | `CorruptionError` |
| An archive cut in half | `TruncatedError` |
| Random bit flips in an `-lh6-` member | An `ArchiveyError`, never another exception |
| A code length of 17 bits; an overfull table; a command past the table; a match past the window | `CorruptionError` |
| An `-lh5-` stream cut in half | `TruncatedError` |
