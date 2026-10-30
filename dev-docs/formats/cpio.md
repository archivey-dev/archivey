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
| Refuses | An afio large header that declares extra bytes, with `UnsupportedFeatureError` |
| Spec | `openspec/specs/format-cpio/spec.md` |

Not here, though a reader might look for it: `ArchiveInfo.format_version` is always
`None` (the variant is in `extra["cpio.variant"]`, §6); an RPM package is not read (its
payload is a compressed CPIO after headers archivey does not parse); and a second archive
concatenated after the first, as in many initramfs images, is reported as trailing data
rather than listed (§6).

## 1. Shape

- **Headers back to back, up to a trailer member.** Each member is a header, the
  NUL-terminated name, padding, the data, and padding; the archive ends with a member
  named `TRAILER!!!`. With no index, listing is a walk and works on a pipe; the trailer
  is how a cut archive is told from a whole one.
- **Four header variants, which differ only in the header and the padding:**
  - **Binary** (`cpio -H bin`, GNU cpio's default): 26 bytes of 16-bit words, in the
    writer's byte order, told apart by the magic `0o070707`. Name and data are padded to
    2 bytes. Its 2-byte magic is the format's weak point for detection (§2.1).
  - **odc** (`-H odc`, POSIX.1 "portable"): 76 bytes of octal ASCII fields after
    `070707`. No padding.
  - **afio's large header** (`070727`, 116 bytes of mostly hexadecimal fields, as
    libarchive reads it): afio writes it in an odc archive for a file over 2 GB, a uid or
    gid over 65535, or an archive of more than 64K hard-linked files. It has odc's rules
    otherwise, so the archive is still `odc`.
  - **newc** (`-H newc`, SVR4) and **crc** (`-H crc`): 110 bytes of hexadecimal ASCII
    fields after `070701` or `070702`. Name and data are padded to 4 bytes. crc adds a
    32-bit sum of the data bytes.
- **Hard links are members that share a device and inode number,** and where the data
  goes depends on the variant: binary and odc store it with every link, newc and crc with
  the **last** link only, the earlier ones empty. That one fact drives the hard-link
  handling in §2.2.
- **A symlink's target is its data,** so the walk reads it before it lists the member.

## 2. The pipeline here

### 2.1 Identify

The ASCII variants are found by their 6-byte magic at offset 0. The binary variant's
2-byte magic is too weak alone, so it has a content probe instead: the header must also
hold a name of the size it declares, ending in a NUL. Like every container's probe, it
runs only when the extension names CPIO (`.cpio`) or the config sets
`always_probe_content`.

Inside a compressor, the inner-container probe decodes the first 512 bytes, matches the
ASCII magics there, and runs the binary probe on those bytes under the same rule: where
the name is `.cpio.gz` (or another compressed spelling), or `always_probe_content` is
set. A binary archive whose first name ends past those 512 bytes is not found inside a
compressor; `format="cpio.gz"` opens it.

### 2.2 Open and list

`ArchiveInfo.extra["cpio.variant"]` names the variant as GNU cpio's `-H` option does
(`bin`, `odc`, `newc`, `crc`), with `bin-be` for a binary archive in the other byte order,
and is absent until the walk reads the first header. A variant that changes mid-archive
is `CorruptionError`.

A modification time past what `datetime` holds, which only afio's 16-digit field can
reach, lists as `modified=None`.

Device nodes, FIFOs and sockets are `OTHER` members, with `extra["special_file_type"]`,
as in every format; one that stores data reports `MEMBER_SPECIAL_FILE_HAS_DATA`.

archivey's hard links name an earlier member only, so:

- binary and odc: the first name is the `FILE`, the later ones `HARDLINK` members to it,
  and their copy of the data is skipped.
- newc and crc: the reader holds the empty links back until the link with the data
  arrives, yields that one as the `FILE`, then the held ones as `HARDLINK` members to it.
  A group whose data never arrives (an empty file) is yielded at the trailer. More held
  links than `ListingLimits.max_members` raises `ResourceLimitError`.

### 2.3 Member data

Nothing here is format-specific apart from the crc sum, which is checked as the data is
read: a mismatch is `CorruptionError` on the read. archivey reads and skips member data
itself, checking each member's length, as for every format read through
`archivey.formats`.

### 2.4 Extract

Nothing here is format-specific. Members go through the same extraction rules as every
format's; `OTHER` members are not created.

### 2.5 Write

Not shipped.

## 3. In the wild

- **GNU cpio** writes binary by default, and pads the archive to a 512-byte block after
  the trailer, which is not reported.
- **bsdcpio** (libarchive) writes odc by default, and newc with `--format newc`.
- **The Linux kernel's initramfs** is newc, often several archives concatenated (an
  early microcode archive, then the main one), each compressed or not.
- **RPM payloads** are newc (or crc) inside a compressor, after the RPM lead and headers.
- **afio** writes odc, and switches a member to its large header when the fields do not
  fit (§1).
- **Corpus evidence.** On 2026-10-30, against libarchive 3.7.2, every CPIO fixture of
  libarchive's test suite that both read matched, the compressed ones included; the one
  difference is the newc and crc link order, recorded as POLICY (§5).

## 4. Threat surface

Names are archive-controlled bytes like any format's and go through the same extraction
rules ([`threat-model.md`](../threat-model.md)). The format-specific surface is memory a
header can ask for:

- A stored name is read into memory before the member, so it is bounded: over 64 KiB, or
  without its NUL, is `CorruptionError` before it is read. newc's 32-bit name size would
  otherwise let one header ask for 4 GiB.
- Held newc and crc links are bounded by `ListingLimits.max_members`, checked by the
  reader itself, because `max_members` counts yielded members and a held link is not yet
  one.
- The check for bytes after the trailer reads at most 1 MiB.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| In a newc or crc archive, a hard-linked file lists under its last name, where libarchive lists the first | **archivey** | Hard links name an earlier member, and the data comes with the last link (§2.2, §6) |
| A gzipped binary archive opens as a one-member `.gz` | **format** | Its magic is too weak to trust alone: name it `.cpio.gz`, or pass `format="cpio.gz"` (§2.1) |
| An initramfs lists only its first archive and reports `ARCHIVE_TRAILING_DATA` | **archivey** | The walk stops at the first trailer (§6) |
| An afio archive with extra header bytes raises `UnsupportedFeatureError` | **format** | Nothing says where the extra bytes go (§6) |
| `format_version` is `None` | **archivey** | The variant is in `extra["cpio.variant"]` (§6) |

## 6. Decisions

- **Built in, not a separate package.** The maintainer's call (2026-10-28), as for ar.
  The reader still imports only public names (apart from `register_builtin_format`).
- **The variant goes in `extra["cpio.variant"]`, not `format_version`.** A header
  variant is not a version; TAR and ar report `format_version=None` for the same reason.
- **In newc and crc, the link with the data is listed first, as the `FILE`.** Hard links
  name an earlier member everywhere in archivey, so a link cannot point forward to the
  data. Rejected: keeping the archive's order with the first name as the file, which
  would mean holding that member back until its data, the last link, arrives.
- **Stop at the first trailer.** A second concatenated archive is reported as trailing
  data, as archivey's TAR reader stops at its first end marker. Reading on would mean
  guessing whether bytes after a trailer are an archive or padding.
- **A 64 KiB cap on a stored name, as a module constant.** Structural, not policy (§4);
  it has its spec row (DR-9).
- **Refuse an afio large header that declares extra bytes.** Nothing says where those
  bytes go, so the next header could not be found.
- **The binary probe runs where the name allows, inside a compressor too.** The same
  rule as uncompressed, so a binary `.cpio.gz` opens and an unrelated `.gz` is not probed.

## 7. Open questions

None are open.

## 8. Verify

```bash
./scripts/test.sh tests/test_cpio.py
```

The fixtures in `tests/fixtures/cpio/` were written by GNU cpio 2.15 and bsdcpio 3.7.2;
`tests/fixtures/cpio/make-archives.sh` writes them again (as root: the tree has device
nodes). afio headers, damaged headers and link groups are built in the tests. The Atheris
target `cpio` fuzzes the walk, plain and inside gzip, with every probe on so the binary
variant is reached. The libarchive corpus harness (`ARCHIVEY_LIBARCHIVE_TEST_FILES`) and
the Commons Compress harness compare the reader with those libraries.

## 9. References

- POSIX.1-1988 `cpio` (odc); the binary, odc, newc and crc layouts in FreeBSD
  [`cpio(5)`](https://man.freebsd.org/cgi/man.cgi?query=cpio&sektion=5).
- The Linux kernel's
  [initramfs buffer format](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html).
- libarchive `archive_read_support_format_cpio.c` for afio's large header.
- `openspec/changes/plugin-api/tasks.md` §3, the reader's history as a plugin.
