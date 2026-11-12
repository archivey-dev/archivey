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
| `format-detection` | A method id (`-lh0-` to `-pm2-`) at offset 2; the same ids behind a self-extracting stub |
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
`-lz4-`, `-pm0-`) and decode `-lh1-`, `-lh4-` to `-lh7-`, `-lhx-`, `-lk7-`, `-lzs-` and
`-lz5-`, check each member's
CRC-16 and report a member read to its end as `Verification.CHECKSUM`. It SHALL follow
lhasa where writers disagree: a level-1 `-lh7-` member with OS id `' '` is `-lk7-`; an
Amiga `-lh0-` member with no name and size 0 is a directory; OS-9/68k's level-2 header is
two bytes longer than its size says; OS-9 permissions become a Unix mode. A pipe SHALL be
refused with `StreamNotSeekableError`.

#### Scenario: LHA listings

| Case | Expected |
| --- | --- |
| Members of each decoded method at each header level, written by the test writer | The same members and bytes; each `CHECKSUM`; lhasa extracts the same bytes |
| lhasa's test archives (LHa for UNIX, UNLHA32, LHA for OS/2, Amiga LhA, OS-9/68k LHA, LHARK, LHarc, LArc, PMarc, MorphOS LhA) | The same members and bytes as lhasa extracts |
| `-lz5-` copying from its starting ring; `-lzs-` from its ring of spaces | The pattern's bytes; spaces |
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

### Requirement: Strip MacLHA's MacBinary wrapper

A file member with OS id `m` SHALL have its MacBinary wrapper stripped as lhasa's
`macbinary.c` does: when its first 128 decoded bytes have zero version and reserved
bytes, the member's own name, fork lengths that round up with the header to its size,
and a modification time within 14 hours of its own, it SHALL read as its data fork (its
resource fork when the data fork is empty), with that fork's `size` and the type and
creator as `extra["lha.mac_type"]` and `extra["lha.mac_creator"]`. The CRC-16 SHALL
still be checked over every decoded byte. Any other member SHALL read whole.

#### Scenario: MacLHA members

| Case | Expected |
| --- | --- |
| lhasa's MacLHA 2.24 archives, levels 1 and 2 | The data fork, the bytes lhasa extracts; `size` the fork's |
| A MacLHA level-0 archive | The member whole, wrapper included, as lhasa reads it |
| A MacBinary header whose name, time, version or sizes do not match the member | The member whole |
| A MacBinary member whose dropped bytes are damaged | `CorruptionError` (the CRC-16) |
| The same wrapper under another OS id | The member whole |

### Requirement: Read an LHA archive behind a self-extracting stub

The LHA backend SHALL declare its method ids at offset 2 as SFX magic, with a validator
that reads the header at the candidate and accepts it only when its level, layout and
8-bit sum or common-record CRC hold. The validator SHALL grade a candidate whose members
end with an end byte followed by more than padding, before the source ends, as
`VALID_SHORT`, so a later archive that ends the file is preferred. When byte 2 of the
source is not a method id, the reader SHALL run the same scan over the shared SFX window,
so a forced `format=LHA` opens the archive detection would. A built-in format that
declares SFX magic SHALL be opened on detection's `[payload_offset, payload_end)` region
as its whole source; a plugin, which cannot declare SFX magic, SHALL still refuse an
offset.

#### Scenario: LHA self-extractors

| Source | Result |
| --- | --- |
| A Windows PE stub, then an archive | Detected as LHA by the SFX scan, `payload_offset` at the archive; members read |
| A DOS `.COM`, Amiga hunk or Atari TOS stub, then an archive | Found by the leading-bytes scan; members read |
| The same, with `format=LHA` | The reader's own scan finds the same archive |
| A stub whose code names `-lh5-` with no valid header around it | The candidate is passed over |
| A small archive inside the stub, then the real one ending the file | The real one |
| Only the archive inside the stub | That archive, with `ARCHIVE_TRAILING_DATA` |
| A signed PE stub, then an archive | Read up to the certificate table, which is not trailing data |
| A stub and no archive, with `format=LHA` | `CorruptionError` ("Not an LHA archive") |

### Requirement: Refuse damaged and unsupported LHA archives

The backend SHALL list a member of a method it does not decode (`-lh2-`, `-lh3-`,
`-pm1-`, `-pm2-`, or another) and raise
`UnsupportedFeatureError` when it is read. It SHALL raise `CorruptionError` for a header
that fails its 8-bit sum or its common-record CRC-16, a level past 3, a name or extended
header past its header, a level-3 header over 1 MiB, level-1 extended headers over 1 MiB
or longer than the stored size, and a file that starts with the end byte; and, when reading, for a data
CRC-16 that does not match, a code length over 16 bits, a table that over- or underfills
its code space, a symbol past its table, or a match from further back than the window. A
member whose data runs past the file SHALL raise `TruncatedError` at listing, and a
stream that needs more than 32 zero bytes past its input SHALL raise `TruncatedError` when
read.

#### Scenario: LHA refusals

| Case | Expected |
| --- | --- |
| An `-lh2-` or `-pm1-` member | Listed; `UnsupportedFeatureError` on read |
| An `-lh1-`, `-lzs-` or `-lz5-` stream cut in half | `TruncatedError` |
| A flipped header byte at level 0 or 1 | `CorruptionError` at open |
| A changed name at level 2 or 3 | `CorruptionError` (header CRC) at open |
| A wrong data CRC | `CorruptionError` on read |
| Header level 4 | `CorruptionError` |
| An archive cut in half | `TruncatedError` |
| Random bit flips in an `-lh6-` member | An `ArchiveyError`, never another exception |
| A code length of 17 bits; an overfull table; a command past the table; a match past the window | `CorruptionError` |
| An `-lh5-` stream cut in half | `TruncatedError` |
