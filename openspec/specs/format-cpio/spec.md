# CPIO Archive Support

## Purpose

CPIO archives (initramfs images, RPM payloads, what `cpio` and `bsdcpio` write) are read
through the unified `ArchiveReader` API. The reader is a built-in written against
`archivey.formats` and registered with `register_builtin_format`; it reads every header
variant in one forward pass. The format handbook is `dev-docs/formats/cpio.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Scanned listing, direct or solid access |
| `format-detection` | ASCII magic at offset 0; content probe for the binary variant |
| `format-plugins` | The handler and reader API the backend is written against |
| `archive-data-model` | `ArchiveInfo.extra["cpio.variant"]` |
| `diagnostics` | `ARCHIVE_TRAILING_DATA`, `MEMBER_SPECIAL_FILE_HAS_DATA` |

## Requirements

### Requirement: Read every CPIO header variant in one pass

The CPIO backend SHALL read binary (either byte order), odc, newc and crc archives, and
afio's large header inside an odc archive, in one forward pass from a file, a seekable
stream, a pipe (`streaming=True`) or inside any single-file compression stream, up to
the `TRAILER!!!` member. It SHALL name the variant in `ArchiveInfo.extra["cpio.variant"]`
as GNU cpio's `-H` option does (`bin`, `bin-be`, `odc`, `newc`, `crc`).
`ArchiveInfo.format_version` SHALL be `None`: a header variant is not a version. A
variant that changes mid-archive SHALL raise `CorruptionError`. In a crc archive each
member's data SHALL be checked against the header's sum as it is read.

#### Scenario: CPIO variants

| Case | Expected |
| --- | --- |
| Archives written by GNU cpio with `-H bin`, `odc`, `newc`, `crc` | Same members and data; `extra["cpio.variant"]` names the variant |
| A newc header followed by a crc header | `CorruptionError` naming both variants |
| A crc member whose data does not match its sum | `CorruptionError` while it is read |
| The newc archive gzipped, opened with `format="cpio.gz"` | `ArchiveFormat(CPIO, GZIP)`; `format="cpio"` on those bytes raises `CorruptionError` |
| The binary archive gzipped, named `.cpio.gz`, or nameless with `always_probe_content=True` | `ArchiveFormat(CPIO, GZIP)` |
| A gzipped binary archive named `.cpio.gz` whose first name ends past the first 512 decoded bytes | `ArchiveFormat.GZ`: the probe sees only those bytes; `format="cpio.gz"` opens it |
| The same bytes nameless, or named `.tar.gz`, by default | `ArchiveFormat.GZ`: the binary probe runs only where the name or the config allows it |

### Requirement: Name an earlier member in every hard link

Members that share a device and inode number SHALL list as one `FILE` and `HARDLINK`
members to it, each naming an earlier member. binary and odc store the data with every
link: the first is the file and the later copies are skipped. newc and crc store it with
the last link only: the reader SHALL hold the empty links back until the link with the
data arrives, yield it as the `FILE` and then the held links. More held links than
`ListingLimits.max_members` SHALL raise `ResourceLimitError`.

#### Scenario: CPIO hard links

| Case | Expected |
| --- | --- |
| newc archive written by GNU cpio with a hard-linked pair, data on the second name | The second name is the `FILE`, listed first; the first name is a `HARDLINK` to it |
| The same pair in odc | The first name is the `FILE`, the second a `HARDLINK` to it |
| More held links than `max_members` | `ResourceLimitError` |

### Requirement: Bound a stored name to 64 KiB

A stored name longer than 64 KiB, or without its terminating NUL, SHALL raise
`CorruptionError` before it is read. This is a structural bound, not a policy limit: no
file system takes a path that long, and newc's 32-bit name size would otherwise let one
header ask for 4 GiB.

#### Scenario: CPIO name bound

| Case | Expected |
| --- | --- |
| newc header declaring a name of 65 537 bytes | `CorruptionError` naming the size |
| A name without its NUL | `CorruptionError` |

### Requirement: Report a missing trailer and data after it

An archive that ends before its `TRAILER!!!` member SHALL raise `TruncatedError`, with
the members before the cut readable in a pass. Bytes other than zeros within 1 MiB after
the trailer SHALL be reported as `ARCHIVE_TRAILING_DATA` with `format="cpio"`; zero
padding to a block boundary SHALL NOT.

#### Scenario: CPIO end of archive

| Case | Expected |
| --- | --- |
| The trailer member removed | `TruncatedError` naming the trailer |
| `junk` after the trailer | One `ARCHIVE_TRAILING_DATA` |
| 4096 zero bytes after the trailer | Nothing reported |
