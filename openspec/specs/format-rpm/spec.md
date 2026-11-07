# RPM Package Support

## Purpose

RPM packages, binary and source, are read through the unified `ArchiveReader` API: their
files, with the metadata from the package header and the data from the CPIO payload.
The reader is a built-in written against `archivey.formats` and registered with
`register_builtin_format`; it reads a package in one forward pass. The format handbook
is `dev-docs/formats/rpm.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Listing needs decompression, solid access |
| `format-detection` | `ED AB EE DB` magic at offset 0 |
| `format-plugins` | The handler and reader API the backend is written against, and `ForwardStream.decompress` for the payload |
| `format-cpio` | The newc entries the payload holds |
| `archive-data-model` | `ArchiveInfo.extra` keys `rpm.name`, `rpm.version`, `rpm.release`, `rpm.epoch`, `rpm.arch`, `rpm.source`, `rpm.signed`, `rpm.payload_compressor` |

## Requirements

### Requirement: List a package's files from its header

The RPM backend SHALL read the lead, the signature header and the main header, then the
payload through the codec `PAYLOADCOMPRESSOR` names (none when the tag is absent). It
SHALL list one member per file of the header's list that is not a `%ghost`, with its
type, mode, size, modification time, owner names and link target from the header, named
as the payload stores it (`./usr/bin/x`, so `usr/bin/x`), with the header's name as
`raw_name`. It SHALL map a newc entry to its file by name and a stripped (`07070X`)
entry by index, and SHALL skip a ghost stored in the payload. In a hard-link set (regular
files sharing `FILEDEVICES` and `FILEINODES`) the file that carries the data SHALL be
the `FILE` and the others `HARDLINK` members to it, listed after it.

#### Scenario: RPM listings

| Case | Expected |
| --- | --- |
| An rpmbuild package with a gzip, xz, zstd, bzip2, LZMA or no payload compressor | The same members, the same bytes; `cost.listing_cost=REQUIRES_DECOMPRESSION`, `cost.access_cost=SOLID` |
| The same package from a pipe with `streaming=True` | The same members |
| A package whose payload is in the stripped form | The same members as its newc twin |
| A `%ghost` file | Not a member |
| A source package | Its spec file under its relative name; `extra["rpm.source"] is True` |
| A header that stores `RPMFORMAT` 6 | `format_version == "6"`; otherwise `"4"` |

### Requirement: Check each file's digest

A regular file's digest from `FILEDIGESTS`, in the algorithm `FILEDIGESTALGO` names (MD5
when absent), SHALL be checked as the file is read: a mismatch raises `CorruptionError`
and a match is `Verification.CHECKSUM`. An algorithm id rpm does not define SHALL leave
the file unchecked.

#### Scenario: RPM digests

| Case | Expected |
| --- | --- |
| A file read to its end, SHA-256 digest matches | `verified is CHECKSUM` |
| A file whose bytes do not match its digest | `CorruptionError` on the read |

### Requirement: Refuse damaged and unsupported packages

The backend SHALL raise `CorruptionError` for a header that does not parse (bad magic,
an entry outside the store, a repeated tag, a per-file array of the wrong length, a
string with no NUL), for a payload entry the header does not list, a stripped index past
the file list, a newc size that disagrees with the header, a file stored twice, or a
payload that ends without one of the header's files. A header larger than
`ListingLimits.max_metadata_bytes` SHALL raise `ResourceLimitError` before it is read. A
cut package SHALL raise `TruncatedError`. A lead version other than 3 or 4, a delta RPM
and a payload compressor archivey has no codec for SHALL raise `UnsupportedFeatureError`.

#### Scenario: RPM refusals

| Case | Expected |
| --- | --- |
| `PAYLOADFORMAT` `drpm` | `UnsupportedFeatureError` naming a delta RPM |
| `PAYLOADCOMPRESSOR` `lzip` | `UnsupportedFeatureError` |
| Payload missing one non-ghost file | `CorruptionError` |
| Non-zero bytes after the payload's trailer | `ARCHIVE_TRAILING_DATA` reported, not raised |
