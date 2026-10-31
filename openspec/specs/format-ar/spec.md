# ar Archive Support

## Purpose

Unix ar archives (static libraries `.a`, Windows `.lib`, the outer layer of a `.deb`)
are read through the unified `ArchiveReader` API. The reader is a built-in written
against `archivey.formats` and registered with `register_builtin_format`; it reads
both the GNU (System V) and the BSD (macOS) dialect in one forward pass. The format
handbook is `dev-docs/formats/ar.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Scanned listing, direct or solid access |
| `format-detection` | `!<arch>\n` and `!<thin>\n` magic at offset 0 |
| `format-plugins` | The handler and reader API the backend is written against |
| `archive-data-model` | `ArchiveInfo.extra` keys `ar.dialect` and `ar.symbol_table` |

## Requirements

### Requirement: Read ar archives of either dialect in one pass

The ar backend SHALL read an archive that starts with `!<arch>\n` in one forward pass,
from a file, a seekable stream, a pipe (`streaming=True`) or inside any single-file
compression stream. It SHALL list every member as a `FILE`, skip the symbol tables
(`/`, `/SYM64/`, `__.SYMDEF` and its `SORTED` and `_64` forms), and report the dialect
in `ArchiveInfo.extra["ar.dialect"]` (`"gnu"` or `"bsd"`) and whether a symbol table
was seen in `extra["ar.symbol_table"]`. During a streaming pass both keys say what the
walk has seen so far. `ArchiveInfo.format_version` SHALL be `None`: a dialect is not a
version.

#### Scenario: ar dialects

| Case | Expected |
| --- | --- |
| GNU archive with a `//` long-name table and a `/` symbol table | Members listed with their long names; `extra["ar.dialect"] == "gnu"`, `extra["ar.symbol_table"] is True` |
| BSD archive with a `#1/20` name in the data area | Member named by those 20 bytes, its data after them; `extra["ar.dialect"] == "bsd"` |
| `!<arch>\n` and nothing else | No members, no `ar.dialect` key, no error |
| The same archive gzipped, opened with `format="ar.gz"` | `ArchiveFormat(AR, GZIP)`; `format="ar"` on those bytes raises `CorruptionError` |
| `open_stream` of that file with `format="ar.gz"` | The uncompressed ar bytes |
| A plain archive, opened | `cost.listing_cost=REQUIRES_SCANNING`; `cost.access_cost=DIRECT` |
| The same archive gzipped, opened | `cost.listing_cost=REQUIRES_DECOMPRESSION`; `cost.access_cost=SOLID` |

### Requirement: Bound a BSD name to 64 KiB

A BSD name stored in the data area (`#1/N`) longer than 64 KiB, or longer than its
member, SHALL raise `CorruptionError` before any of it is read. This is a structural
bound, not a policy limit: no file system takes a path that long, and the check keeps a
damaged length from growing one buffer to the member's size. The GNU long-name table is
held for the whole walk instead, so it is charged to `ListingLimits.max_metadata_bytes`.

#### Scenario: ar name bounds

| Case | Expected |
| --- | --- |
| `#1/65537` in a member of 70 000 bytes | `CorruptionError` naming the header offset |
| `#1/99` in a member of 5 bytes | `CorruptionError` |
| `//` table larger than `max_metadata_bytes` | `ResourceLimitError` |

### Requirement: Refuse thin archives by name

An archive that starts with `!<thin>\n` stores only the names of files kept outside it.
The backend SHALL claim it by magic and refuse it with `UnsupportedFeatureError`, never
`FormatDetectionError`.

#### Scenario: thin archive

| Case | Expected |
| --- | --- |
| A file written by `ar --thin` | `UnsupportedFeatureError` at the open |
