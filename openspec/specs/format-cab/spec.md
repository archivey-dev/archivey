# Microsoft Cabinet Support

## Purpose

Microsoft cabinets (Windows updates, drivers, installer payloads, what `makecab` and
`gcab` write) are read through the unified `ArchiveReader` API. The reader is a built-in
written against `archivey.formats` and registered with `register_builtin_format`; LZX is
decoded by archivey's own decoder, in Python. The format handbook is
`dev-docs/formats/cab.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Indexed listing; solid access for compressed folders; seekable source required |
| `format-detection` | `MSCF\0\0\0\0` magic at offset 0 |
| `format-plugins` | The handler and reader API the backend is written against; `FormatPolicy(replace=)` accepts `ContainerFormat.CAB` |
| `archive-data-model` | `CompressionAlgorithm.LZX` and `QUANTUM` |

## Requirements

### Requirement: Read a cabinet's files from a seekable source

The CAB backend SHALL list one `FILE` member per `CFFILE` record, in table order, named
as stored with `\` turned into `/` after decoding, with its size, the DOS date and time
as a naive `modified`, its attributes as `windows_attrs` (without the cabinet-only bits
`0x40` and `0x80`), and its folder's method as
`compression`. It SHALL read stored, MSZIP and LZX folders (LZX windows 2^15 to 2^21),
check each data block's checksum when it is not 0, and report a member whose blocks from
the folder start through its end all carry one as `Verification.CHECKSUM` once read to the
end. `ArchiveInfo.format_version` SHALL be `major.minor` from the header, and
`ArchiveInfo.is_solid` SHALL be true when any folder is compressed. A pipe SHALL be refused
with `StreamNotSeekableError`.

#### Scenario: CAB listings

| Case | Expected |
| --- | --- |
| A cabinet with a stored, MSZIP or LZX folder (verbatim, aligned and uncompressed blocks, E8 translation, every window size) | The same members and bytes; each member `CHECKSUM` |
| `makecab.exe` cabinets, stored, MSZIP and LZX (libarchive's test files) | The same members and bytes |
| A cp932 name opened with `encoding="cp932"` | The Japanese name, whole |
| Members read in order from one LZX folder | Each 32 KiB frame decoded once |
| A member in the middle of a stored folder | The blocks before it not read |
| Header, folder and data reserve areas | Skipped |
| A block whose checksum is 0 | The member read, `LENGTH` |
| An invalid DOS date | `modified is None`; `MEMBER_TIMESTAMP_INVALID` |
| Attributes `0xE1` | `windows_attrs == 0x21` |

### Requirement: Refuse damaged and unsupported cabinets

The backend SHALL raise `UnsupportedFeatureError` at open for a cabinet that is part of a
set (flag `PREV` or `NEXT`), and when reading a Quantum member or one of an unknown
method. It SHALL raise `CorruptionError` for a folder index past the folders, a
"continued" folder index, a name with no NUL within 256 bytes or an empty name (as
libmspack's `cabd_read_string`), an LZX window outside 2^15 to 2^21, a block over 38 912
stored or 32 768 decoded bytes, a block of 0 decoded bytes (libmspack's mark for a block
split across cabinets), a block checksum that does not match, an MSZIP block that
does not start with `CK` or does not decode to its size, LZX that does not decode, and a
file past its folder's output. A cut cabinet SHALL raise `TruncatedError` for what it cuts
off, and still read the files before the cut. The block tables the backend keeps, one per
folder read, SHALL be weighed against `max_metadata_bytes` as they are read, 256 bytes a
block, and crossing it SHALL raise `ResourceLimitError`. An LZX window over
`DecoderLimits.max_decoder_memory` SHALL raise `ResourceLimitError` when a member of the
folder is read. A member of size 0 SHALL read as empty without decoding its folder.

#### Scenario: CAB refusals

| Case | Expected |
| --- | --- |
| Header flag 1 or 2 | `UnsupportedFeatureError` at open |
| A Quantum folder | Listed; `UnsupportedFeatureError` on read |
| A flipped bit in a block with a checksum | `CorruptionError` on read |
| Random bit flips in an LZX folder with no checksums | An `ArchiveyError`, never another exception |
| A cabinet cut inside its last folder | The earlier files read; `TruncatedError` for the cut one |
| An LZX match reaching before the stream start, or past the frame | `CorruptionError` |
| An LZX match past its block or the window, or from more than a window back; a tree that over- or underfills its code space, or a pretree, aligned or main tree with no codes | `CorruptionError` |
| A block of 0 decoded bytes, in any method | `CorruptionError` on read |
| A 2^21 LZX window under a 1 MiB `max_decoder_memory` | `ResourceLimitError` on read |
| An LZX stream that reads more than two bytes past its input | `TruncatedError` |
| Folders that all name one run of 20 000 blocks | `ResourceLimitError` once the kept tables pass `max_metadata_bytes` |
