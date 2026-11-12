# XAR Archive Support

## Purpose

XAR archives (macOS installer packages `.pkg`, `.xip` files, what Apple's `xar`,
`pkgbuild` and `bsdtar --format xar` write) are read through the unified `ArchiveReader`
API. The reader is a built-in written against `archivey.formats` and registered with
`register_builtin_format`. The format handbook is `dev-docs/formats/xar.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Indexed listing, direct access, seekable source required |
| `format-detection` | `xar!\0` magic at offset 0 |
| `format-plugins` | The handler and reader API the backend is written against; `FormatPolicy(replace=)` accepts `ContainerFormat.XAR` |
| `archive-data-model` | `HashAlgorithm.MD5`, `SHA1`, `SHA256` and `SHA512` |

## Requirements

### Requirement: Read a XAR archive's files from a seekable source

The XAR backend SHALL read the header, decode the zlib-compressed table of contents and
parse it with expat, and list one member per `<file>` element in document order, a
directory before the files inside it, each named by its enclosing directories' names and
its own joined with `/`. A `<name enctype="base64">` SHALL be decoded from base64 and then
as any stored name: UTF-8 first, then `encoding=`. Members SHALL carry the stored mode,
uid, gid, user and group names, and `mtime`, `atime` and `ctime` as UTC times. A file's
data SHALL be read from the heap, stored or decoded as zlib (`application/x-gzip`), bzip2,
LZMA Alone (`application/x-lzma`) or xz through archivey's decoder limits, and its
`<extracted-checksum>` (MD5, SHA-1, SHA-256 or SHA-512) SHALL be the member's hash, so a
member read to its end is at `Verification.CHECKSUM`. A `hardlink` with
`link="original"` SHALL be a `FILE`; another `hardlink` SHALL be a `HARDLINK` whose
`link_target` is the member whose id it names, listed after that member even when the
archive writes it first. `fifo`, device and socket entries SHALL be `OTHER`; a type
archivey does not know SHALL be a `FILE` when it has data and `OTHER` otherwise, with
`MEMBER_TYPE_UNKNOWN`. `ArchiveInfo.format_version` SHALL be `"1"`. A pipe SHALL be
refused with `StreamNotSeekableError`.

#### Scenario: XAR listings

| Case | Expected |
| --- | --- |
| bsdtar 3.7.2 archives with each `xar:compression` (none, gzip, bzip2, lzma, xz) | Same members and data; each file `CHECKSUM` |
| A hard link written before the entry holding its data | Listed after it; reads that entry's data |
| A base64 name of Latin-1 bytes with `encoding="latin-1"` | The decoded name; `raw_name` the bytes |
| A file checked with MD5, SHA-1, SHA-256 or SHA-512 | `member.hashes` holds that digest |
| A file checksum of another style (`sha224`), or with no style | No hash; `DIGEST_UNVERIFIABLE` (`reason="unknown_algorithm_or_backend"`) |
| A time with no `Z`, or not a date | `None`; `MEMBER_TIMESTAMP_INVALID` |
| A data encoding archivey does not know | Listed with `CompressionAlgorithm.UNKNOWN`; `UnsupportedFeatureError` on read |

### Requirement: Check and bound the table of contents

The backend SHALL refuse with `ResourceLimitError`, before decoding it, a table of
contents whose stored or decoded size, as the header gives them, is over
`ListingLimits.max_metadata_bytes`, and one that lists
more than `max_members` files, while it is parsed. It SHALL raise `CorruptionError` for a
table of contents that does not decode to the size its header gives, holds a NUL byte (so
is not UTF-8; checked before the XML is parsed), is not XML, declares
a document type (so no entity is ever expanded), has a tag of more than 65 536 pieces (a
character outside quotes, or one quoted value; checked before the XML is parsed), nests
more than 2048 elements, or fails
the checksum the header names (SHA-1 or MD5, or a named algorithm). It SHALL raise
`UnsupportedFeatureError` for a version other than 1 and for a named checksum algorithm
it does not compute. A hard link to an id no entry has, a name that is empty or not
base64, a file with two names, a directory whose children come before its name, a data
element without a length, offset or size, and a malformed file checksum SHALL raise
`CorruptionError`; data past the end of the archive SHALL raise `TruncatedError` when
read, and a file that fails its checksum SHALL fail `verify_all()`.

#### Scenario: XAR refusals

| Case | Expected |
| --- | --- |
| A stored or decoded TOC size over `max_metadata_bytes` | `ResourceLimitError` at open |
| A DOCTYPE with nested entities | `CorruptionError` at open |
| One `<file>` tag with 200 000 attributes | `CorruptionError` at open, before expat builds them |
| A 100 000-byte attribute value, or a `>` inside values | A long value is one piece and lists; `>` does not end the tag |
| A flipped bit in the TOC checksum | `CorruptionError` at open |
| A flipped bit in a stored file | `verify_all()` returns it with `CorruptionError` |
| Five files with `max_members=4` | `ResourceLimitError` at open |
