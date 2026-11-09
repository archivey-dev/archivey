# RPM

Current maintainer truth for RPM packages, binary and source. A package is two headers
and then a CPIO payload inside a compressor, with no index of where each file's data
starts, so archivey reads it in one forward pass, from a pipe too. The reader is written
against `archivey.formats`, the API a format added from outside uses, and is registered
as a built-in the way ar and CPIO are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/rpm_reader.py`, an `RpmHandler` (`SequentialFormatHandler`) and an `RpmReader` (`SequentialReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file, a stream that can seek, or a pipe (`streaming=True`) |
| Listing cost | `REQUIRES_DECOMPRESSION`: the file list is in the header, but the payload is walked to find each file's data |
| Access cost | `SOLID`: one compression stream holds every file |
| Core dependencies | None. The payload is decoded by archivey's codecs (gzip, bzip2, xz, LZMA Alone, Zstandard) |
| Encryption | None |
| Checksums | Each regular file's digest from `FILEDIGESTS` (SHA-256 in current packages, MD5 in old ones), checked as it is read |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Refuses | Lead versions other than 3 and 4, delta RPMs, payload compressors archivey has no codec for |
| Spec | `openspec/specs/format-rpm/spec.md` |

Not here, though a reader might look for it: signatures are not checked (only reported),
the payload digests (`PAYLOADSHA256` and friends) are not checked, `%ghost` files are not
listed, and scriptlets, dependencies and the changelog are not exposed.

## 1. Shape

- **Lead, signature header, header, payload.** The lead is 96 bytes starting
  `ED AB EE DB`; apart from the magic it is historical (its version byte is 3 in v4
  packages and 4 in v6 ones). Both headers have one shape: `8E AD E8 01`, four reserved
  bytes, the entry count and the data size, then 16-byte entries (tag, type, offset,
  count) and the data store. The signature header is padded to 8 bytes; the main header
  is not. The payload runs to the end of the file.
- **The header is the file list.** Names (`DIRNAMES` + `BASENAMES` + `DIRINDEXES`, or
  `OLDFILENAMES` in old packages), modes, sizes (`FILESIZES`, or `LONGFILESIZES` when a
  file is 4 GiB or more), times, owner names, link targets, flags and digests, one array
  entry per file.
- **The payload is CPIO, in one of two forms.** newc (`070701`) entries named
  `./usr/bin/x`, or the *stripped* form (`07070X`, then the file's index in the header
  as 8 hexadecimal digits, and nothing else), which RPM 6 always uses and RPM 4 uses for
  a package with a file of 4 GiB or more. Entries are 4-byte aligned from the payload's
  start, and the payload ends with a newc `TRAILER!!!` entry. rpm also ends a stripped
  payload at an index of `ffffffff` (`rpmcpioHeaderRead`), which it does not write.
- **Ghost files are in the header only.** A `%ghost` file (flag bit 6) is never stored.
- **Hard links:** regular, non-ghost files that share `FILEDEVICES` and `FILEINODES`.
  rpm writes their entries together, and only the set's last file in header order
  carries the data.
- **A symlink's target is its entry's data**, and also in `FILELINKTOS`.

## 2. The pipeline here

### 2.1 Identify

By the lead's magic at offset 0, `.rpm` by extension. There is no content probe.

### 2.2 Open and list

The walk reads the lead and both headers, then hands the rest of the file to
`ForwardStream.decompress()` with the codec `PAYLOADCOMPRESSOR` names. With no such tag
the payload is read uncompressed: rpm's `ufdio` writes none. Each payload entry is mapped
to its file as `rpm` does (`lib/rpmfi.c`): a newc entry by its name, a stripped one by
its index. The member's metadata comes from the header, as `rpm` installs it; a newc
entry's own size is only checked against it.

Members are named as the payload stores them, `./usr/bin/x`, so `usr/bin/x` once
normalized: what `rpm2cpio | cpio -i` extracts, relative to the directory given. The
header's absolute name is `raw_name`. A source package's names are relative already.

Device nodes, FIFOs and sockets are `OTHER` members with `extra["special_file_type"]`, as
in every format. A type the header does not name is `OTHER` too, reported with
`MEMBER_TYPE_UNKNOWN` (DR-25): rpm reads no payload data for it. Neither may carry payload
bytes, nor may a directory: rpm takes a size of 0 for every type but a regular file and a
symlink (`iterReadArchiveNext` sets the expected size, whatever the newc entry says), so
the bytes would be read as the next entry's header and the package fails in rpm. A newc
size that disagrees with that 0 is `CorruptionError`, as any size that disagrees with the
header.

Hard links are handled as in newc CPIO: the earlier, empty entries are held
(`ReaderContext.hold()`, counted toward the listing's limits), and the set's last file,
which carries the data, is yielded as the `FILE` with the held ones as `HARDLINK`
members to it after it. An earlier link the payload stores after that file, which rpm
installs all the same, is yielded as a `HARDLINK` when its entry arrives. A symlink's
payload bytes are skipped; the target is the header's.

`ArchiveInfo`:

- `format_version`: `"6"` when the header stores `RPMFORMAT`, else `"4"` for a header
  with an immutable region (tag 63), else `"3"`: rpm's own rule.
- `is_solid` is true for a compressed payload and false for one with no compressor
  (`identity`, `ufdio` or no tag), which reads as a CPIO archive does. The header that
  says which is read by the open's first walk step, so the cost receipt is right from
  the open.
- `extra["rpm.name"]`, `rpm.version`, `rpm.release`, `rpm.arch` (strings), `rpm.epoch`
  (int, when set), `rpm.source` (no `SOURCERPM` tag), `rpm.signed` (the signature header
  holds an RSA, DSA, PGP, GPG or OpenPGP signature: tags 267, 268, 278, 1002, 1005 or
  1006, as rpm numbers them on disk) and `rpm.payload_compressor` (the tag's
  value, `"none"` when absent). Set once the walk has read the header, which the open
  does.

### 2.3 Member data

A regular file's digest from `FILEDIGESTS`, in the algorithm `FILEDIGESTALGO` names (MD5
when absent), is a `MemberDigest`, checked as the data is read; a mismatch is
`CorruptionError` and a match is `Verification.CHECKSUM`. An algorithm id rpm does not
define leaves the file unchecked. The digests are not in `ArchiveMember.hashes`, which
holds only `HashAlgorithm` names.

### 2.4 Extract

Nothing here is format-specific. `OTHER` members are not created; ghosts are not
members, so not created either.

### 2.5 Write

Not shipped.

## 3. In the wild

- **rpmbuild** (rpm 4.x) writes newc payloads compressed with zstd (Fedora since 31), xz
  (RHEL 8, openSUSE) or gzip, and the stripped form for a file of 4 GiB or more.
- **rpm 6.0** (2025) writes v6 packages: the stripped form always, `LONGFILESIZES`
  always, SHA-256 or stronger file digests, and `RPMFORMAT` = 6.
- **rpm < 4.11** sometimes stored a ghost file in the payload; rpm skips it, and so does
  archivey.
- **Source packages** hold the spec file and sources with relative names, and no
  `SOURCERPM` tag.
- `tests/fixtures/rpm/` holds rpm 4.18.2 packages, one per payload compressor; the
  stripped form was checked against a package rpm 4.18.2 wrote for a 4 GiB file (not
  committed: its payload decodes to 4 GiB), and is built in the tests.

## 4. Threat surface

Names and link targets are archive-controlled bytes like any format's, and go through
the same extraction rules ([`threat-model.md`](../threat-model.md)). The format-specific
surface is memory a header can ask for:

- A header's entry count and data size are bounded as rpm bounds them (65 535 entries,
  256 MiB), and both headers together by `ListingLimits.max_metadata_bytes`, before the
  index and the data are read.
- Every value read from the store is bounds-checked; a string must end inside it.
- Every per-file array must have one entry per file; a directory index must name a
  directory.
- A payload entry's name is bounded to 4096 bytes (rpm's own bound); a stripped entry's
  index must name a file.
- A header listing more files, or more directory names, than
  `ListingLimits.max_members` is refused before any per-file list is built. Below that a
  file costs about 400 bytes until the payload reaches it (about 100 MiB at the default
  262 144).
- Names stay split as the header stores them (directory, base) and members are made as
  the payload reaches each file, since `DIRINDEXES` lets every file share one long
  directory name: joined up front, the names grow with files times directory length.
  Each member's name is then weighed by the listing's limits as it is listed.
- A string array cannot declare more strings than its bytes can hold.
- A tag read for one value (NAME, VERSION, EPOCH, the payload tags and the like) reads
  only its first value, whatever count its entry declares.
- Held hard links are charged to the listing's limits as they are held.
- The check for bytes after the trailer reads at most 1 MiB.
- The payload is decoded by archivey's codecs, under the caller's decoder limits and the
  decompression-ratio guard.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| Names are relative (`usr/bin/x`) where `rpm -qpl` prints `/usr/bin/x` | **archivey** | What `rpm2cpio \| cpio -i` extracts; `raw_name` keeps the header's (§2.2, §6) |
| A hard-linked file lists under its last name | **format** | The data comes with the set's last file (§1, §2.2) |
| A `%ghost` file is not listed | **format** | It is never stored (§1) |
| A package whose payload has no compressor tag but is gzip raises `CorruptionError` | **archivey** | §7 |
| `rpm.signed` is true for a package whose signature does not verify | **archivey** | Signatures are reported, not checked (§6) |

## 6. Decisions

- **Built in, written against `archivey.formats`,** as ar and CPIO are.
- **The header is the truth, the payload only carries data.** That is how rpm installs a
  package, and the only way to read the stripped form, whose entries hold nothing but an
  index. A newc entry whose size disagrees with the header is `CorruptionError`.
- **Relative names, as the payload stores them.** An absolute name would be blocked by
  extraction's default policy; `rpm2cpio | cpio -i` extracts relative to the directory.
- **Ghosts are not members,** as `rpm2cpio` does not give them.
- **Signatures are reported, not checked.** Checking needs keys and an OpenPGP
  implementation; archivey is an archive reader, and `rpm -K` exists.
- **Every file must be found before the trailer,** as rpm requires
  (`RPMERR_MISSING_FILE`): a payload that ends early is `CorruptionError`.
- **No content probe:** the lead's magic is four bytes at offset 0.

## 7. Open questions

- **The payload digests.** `PAYLOADSHA256` (and the v6 SHA-512 and SHA3-256 tags) cover
  the compressed and the uncompressed payload as a whole, including bytes no member
  reads. Checking them needs a hook in `archivey.formats` for a check that spans the
  payload; tracked internally.
- **A payload with no compressor tag that is gzip.** rpm opens such a payload with
  `gzdio`, which reads plain bytes too; only packages from rpm 3 and older have it. The
  walk cannot look at the payload's first bytes and then hand them to a codec, so it reads
  it uncompressed.

## 8. Verify

```bash
./scripts/test.sh tests/test_rpm.py
```

`tests/fixtures/rpm/make-rpms.sh` writes the fixtures again with rpmbuild (as root: the
package has a device node). Stripped payloads, RPM 6 headers and damaged packages are
built in the tests.

## 9. References

- rpm.org [V4 package format](https://rpm.org/docs/6.0.x/manual/format_v4.html),
  [V6 package format](https://rpm.org/docs/6.0.x/manual/format_v6.html), the
  [header format](https://rpm.org/docs/6.0.x/manual/format_header.html) and the tag list.
- rpm 4.18.2 `lib/rpmfi.c` (payload entry to file mapping, hard links, ghosts) and
  `lib/cpio.c` (newc and stripped entries, padding, the trailer).
