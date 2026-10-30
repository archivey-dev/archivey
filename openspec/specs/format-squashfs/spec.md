# SquashFS Image Support

## Purpose

SquashFS 4.0 images (snap packages, live-system roots, what `mksquashfs` writes) are read
through the unified `ArchiveReader` API. The reader is a built-in written against
`archivey.formats` and registered with `register_builtin_format`. The format handbook is
`dev-docs/formats/squashfs.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and member metadata |
| `access-mode-and-cost` | Indexed listing, direct access, seekable source required |
| `format-detection` | `hsqs` magic at offset 0, and `sqsh` for the refusal |
| `format-plugins` | The handler and reader API the backend is written against |
| `archive-data-model` | `ArchiveInfo.extra` keys `squashfs.compressor` and `squashfs.block_size` |
| `packaging-and-extras` | `lz4` (`[recommended]`) for LZ4 images; `exclude_libraries` |

## Requirements

### Requirement: Read SquashFS 4.0 images from a seekable source

The SquashFS backend SHALL read little-endian SquashFS 4.0 images compressed with gzip,
LZMA, LZO, xz, LZ4 or Zstandard, or not compressed, from a file or a seekable stream. A
pipe SHALL be refused with `StreamNotSeekableError`: the directory and inode tables come
after the file data. `ArchiveInfo.format_version` SHALL be `"4.0"`, and
`extra["squashfs.compressor"]` and `extra["squashfs.block_size"]` SHALL name the
compressor and the data block size. Every compressed block SHALL be decoded through
archivey's decoder limits, or through a decoder capped at the block's size (LZ4, LZO).
LZ4 SHALL follow archivey's own `lz4` rules: process isolation, `exclude_libraries`, and
the PyPy rule. A big-endian image (SquashFS 3 and older, magic `sqsh`) or a version
other than 4.0 SHALL raise `UnsupportedFeatureError`.

#### Scenario: SquashFS images

| Case | Expected |
| --- | --- |
| Images written by `mksquashfs` 4.6.1 with each compressor | Same members and data; `format_version == "4.0"` |
| An LZ4 image with `FormatPolicy(exclude_libraries={OptionalLibrary.LZ4})` | `PackageNotInstalledError` naming `exclude_libraries` |
| Superblock magic `sqsh`, or version 3.0, from a stream with no name | `UnsupportedFeatureError` |
| A file with blocks stored with size 0, under a basic inode | `is_sparse` is true; the holes read as zeros |
| An unknown compressor id | `CorruptionError` naming the id |

### Requirement: Bound every size to what the format allows

The backend SHALL refuse with `CorruptionError`: a metadata block longer than 8 KiB, a
data block longer than the block size or shorter than its file needs, a fragment past
the fragment table, a name with a `/`, an entry whose inode has another type, a
directory reached twice, a symlink target longer than 65535 bytes, and files whose
block lists add up to more than the inode table holds. These are structural bounds, not
policy limits: 8 KiB is the format's metadata block size, the block size is in the
superblock, 65535 is the longest target the Linux kernel reads (`squashfs_read_inode`),
and in a valid image each file's block list lies in its own bytes of the inode table.
An image cut short SHALL raise `TruncatedError` naming the structure the cut falls in.

The backend SHALL keep at most 64 decoded metadata blocks and 4 decoded fragment blocks
for reuse, whatever the image declares. These are caches, not limits: a block that is
not kept is decoded again when it is needed.

#### Scenario: SquashFS damage

| Case | Expected |
| --- | --- |
| A metadata block header declaring 8193 bytes | `CorruptionError` |
| A data block declaring `0xFFFFFF` bytes | `CorruptionError` |
| A data block that decodes to 4000 bytes where the file needs 4096 | `CorruptionError` |
| A symlink target of 70000 bytes | `CorruptionError` |
| A directory listed inside itself | `CorruptionError`, "listed twice" |
| A file whose size needs a block list longer than the inode table | `CorruptionError`, before the list is read |
| An image cut in half | `TruncatedError` |
