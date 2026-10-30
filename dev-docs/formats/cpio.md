# CPIO

Current maintainer truth for CPIO archives: initramfs images, RPM payloads, and what
`cpio` and `bsdcpio` write. The format is one header after another up to a member named
`TRAILER!!!`, with no index, so archivey reads it in one forward pass, from a pipe and
inside a compression stream too. The reader is written against `archivey.formats`, the API
a format added from outside uses, and is registered as a built-in the way ISO and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/cpio_reader.py`, a `CpioHandler` (`SequentialFormatHandler`) and a `CpioReader` (`SequentialReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file, a stream that can seek, or a pipe (`streaming=True`). Inside any single-file compression stream (`.cpio.gz`, `.cpio.xz`, …), as TAR is |
| Listing cost | `REQUIRES_SCANNING`, header by header |
| Access cost | `DIRECT` from a source that can seek; inside a compression stream, solid, as a compressed TAR is |
| Core dependencies | None |
| Encryption | None |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Checksums | crc only: the header's 32-bit sum of the data bytes, checked as the data is read |

## 1. Variants and detection

Each member is a header, the NUL-terminated name, padding, the data, and padding. The
variants differ only in the header and the padding:

- **Binary** (`cpio -H bin`): 26 bytes of 16-bit words, in the writer's byte order, told
  apart by the magic `0o070707`. Name and data are padded to 2 bytes.
- **odc** (`-H odc`, POSIX.1 "portable"): 76 bytes of octal ASCII fields after `070707`.
  No padding.
- **afio's large header** (`070727`, 116 bytes of mostly hexadecimal fields, as libarchive
  reads it): afio writes it in an odc archive for a file over 2 GB, a uid or gid over
  65535, or an archive of more than 64K hard-linked files. It has odc's rules otherwise,
  so the archive is still `odc`.
- **newc** (`-H newc`, SVR4) and **crc** (`-H crc`): 110 bytes of hexadecimal ASCII fields
  after `070701` or `070702`. Name and data are padded to 4 bytes.

`ArchiveInfo.format_version` names the variant as GNU cpio's `-H` option does (`bin`,
`odc`, `newc`, `crc`), with `bin-be` for a binary archive in the other byte order. A
variant that changes mid-archive is `CorruptionError`.

The ASCII variants are found by their 6-byte magic. The binary variant's 2-byte magic is
too weak alone, so it has a content probe instead: the header must also hold a name of
the size it declares, ending in a NUL. Like every container's probe, it runs only when the
extension names CPIO (`.cpio`) or the config sets `always_probe_content`.

## 2. Member types and hard links

A symlink's target is its data. Device nodes, FIFOs and sockets are `OTHER` members, with
`extra["special_file_type"]`, as in every format; one that stores data reports
`MEMBER_SPECIAL_FILE_HAS_DATA`.

Hard links are members that share a device and inode number. binary and odc store the data
with every link: the reader lists the first as a `FILE` and the later ones as `HARDLINK`
members to it, and skips their copy of the data. newc and crc store the data with the
**last** link only, the earlier ones empty. archivey's hard links name an earlier member
only, so the reader holds the empty links back until the link with the data arrives,
yields that one as the `FILE`, then the held ones as `HARDLINK` members to it. The member
order is then not quite the archive's; libarchive lists the first name as the file instead
(a POLICY row in `tests/test_libarchive_corpus.py`). A group whose data never arrives (an
empty file) is yielded at the trailer. More held links than `ListingLimits.max_members`
raises `ResourceLimitError`.

## 3. Damage and limits

The reader refuses, with `CorruptionError`: a header whose fields are not numbers, a name
over 64 KiB or without its NUL, and a variant change. An archive that ends before its
`TRAILER!!!` member raises `TruncatedError`; the members before the cut stay readable in
a pass. An afio large header that declares extra bytes is `UnsupportedFeatureError`,
since nothing says where they go.

Bytes other than zeros within 1 MiB after the trailer are `ARCHIVE_TRAILING_DATA` with
`format="cpio"`. GNU cpio pads the archive to a 512-byte block, which passes. A second
archive concatenated after the first is such data: archivey lists the first archive's
members and not the second's, as its TAR reader stops at the first end marker.

## 4. Tests and fixtures

`tests/test_cpio.py`, against `tests/fixtures/cpio/`: archives written by GNU cpio 2.15
and bsdcpio 3.7.2. `tests/fixtures/cpio/make-archives.sh` writes them again (as root: the
tree has device nodes). The same test checks that the reader imports only archivey's
public names, apart from `register_builtin_format`. The Atheris target `cpio` fuzzes the
walk, plain and inside gzip. The libarchive and Commons Compress corpus harnesses compare
it with those libraries.
