# RPM

Current maintainer truth for RPM packages, binary and source. A package is two headers
and then a CPIO payload inside a compressor. The main header lists every file, so
archivey lists the package from the headers alone and decodes the payload only when a
member's data is read, in one forward pass, from a pipe too. The reader is written
against `archivey.formats`, the API a format added from outside uses, and is registered
as a built-in the way ar and CPIO are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/rpm_reader.py`, an `RpmHandler` (`SequentialFormatHandler`) and an `RpmReader` (`SequentialReader` with `data_on_demand`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file, a stream that can seek, or a pipe (`streaming=True`) |
| Listing cost | `INDEXED`: the file list is the header's, and listing decodes none of the payload |
| Access cost | `SOLID`: one compression stream holds every file (`DIRECT` for an uncompressed payload) |
| Core dependencies | None. The payload is decoded by archivey's codecs (gzip, bzip2, xz, LZMA Alone, Zstandard) |
| Encryption | None |
| Checksums | The main header's SHA-256 and SHA-1 digests from the signature header, each one stored checked as the header is read; each regular file's digest from `FILEDIGESTS` (SHA-256 in current packages, MD5 in old ones), checked as it is read |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Refuses | Lead versions other than 3 and 4, delta RPMs, payload compressors archivey has no codec for |
| Spec | `openspec/specs/format-rpm/spec.md` |

Not here, though a reader might look for it: signatures are not checked (only reported),
the payload digests (`PAYLOADSHA256` and friends) and the MD5 over header and payload
(signature tag 1004) are not checked, bytes after the payload's trailer are not read,
`%ghost` files are not listed, and scriptlets, dependencies and the changelog are not
exposed.

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
- **Entry order.** rpm writes every file that is not in a hard-link set in header order,
  then each set, ordered by its first file, with its files in header order: rpm 4.12 and
  later in `lib/rpmfi.c` (`iterWriteArchiveNextFile`), rpm 4.11 in `lib/fsm.c`
  (`writeLinks`). rpm reads the entries in any order.
- **A symlink's target is its entry's data**, and also in `FILELINKTOS`.

## 2. The pipeline here

### 2.1 Identify

By the lead's magic at offset 0, `.rpm` by extension. There is no content probe.

### 2.2 Open and list

The walk reads the lead and both headers. When the signature header stores a digest
of the main header, `RPMSIGTAG_SHA256` (tag 273), `RPMSIGTAG_SHA1` (269) or both, the
walk hashes the main header as it reads it, once for each digest stored, from its magic to the end of its data store,
and any mismatch is `CorruptionError` before any member is listed: in both access modes,
since both read the header the same way. The digest covers what only the header holds
(names, modes, owners, link targets, file digests), which no member read checks. A
package with neither tag is read unchecked.

The walk then hands the rest of the file to `ForwardStream.decompress()` with the codec
`PAYLOADCOMPRESSOR` names, which decodes nothing yet. With no such tag the payload is
read uncompressed: rpm's `ufdio` writes none. It then yields every member from the
header, in the order rpm writes the entries (§1), before any payload byte is read: the
reader sets `SequentialReader.data_on_demand`, and each `FILE` member's
`MemberSpan.data` finds the file's entry in the payload only when it is read (§2.3).
Listing an RPM is reading its two headers. The member's metadata comes from the header,
as `rpm` installs it.

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

Hard links: the set's earlier files are held (`ReaderContext.hold()`, counted toward
the listing's limits), and the set's last file, which carries the data, is yielded as
the `FILE` with the held ones as `HARDLINK` members to it after it. A symlink's target is
the header's; its payload copy is compared with it when a read passes the entry (§2.3).

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

Each walk has one cursor in the payload (`_Payload`), shared by the data streams of the
members it yields, which moves forward only. A file's data stream, read for the first
time, moves the cursor to the file's entry: it skips the entries on the way (directories,
symlinks, the empty entries of earlier hard links, files nobody read, ghosts rpm < 4.11
stored, a second entry for a file already passed), maps each entry to its file as `rpm`
does (`lib/rpmfi.c`: a newc entry by its name, a stripped one by its index), and checks
each entry's size against the header's. archivey reads a pass's members in the walk's
order, which is the payload's, so `stream_members()` and `extract_all` decode the payload
once. `open()` of one member walks again from the start of the archive with a cursor of
its own, as for any solid archive.

- **A file the payload lacks fails alone.** The search for it stops at the next entry
  that carries a later file's data (by rpm's order, §1), leaves that entry for that
  file, and raises `CorruptionError` for this one. The same holds for a payload whose
  data entries are in another order than rpm's: the file found out of place fails.
- **Damage to the payload's structure** (an entry that does not parse, a name the header
  does not list, a stripped index past the file list, an entry size other than the
  header's, which rpm reads by, a cut or a codec error) raises for the read that finds it
  and for every later read of that cursor: rpm would not get past it either.
- **A symlink's payload target that differs from the header's** is reported, once per
  reader, as `MEMBER_HEADER_AMBIGUOUS` with `ambiguity="copies_differ"` and
  `field="FILELINKTOS"`, when a read of a later file passes the entry. The member keeps
  the header's target. `STRICT` raises it, in the read that passed the entry. A
  symlink whose entry no read passes is not compared.
- **Nothing past the last file read is read.** Listing never reads the payload, and a
  pass stops after the last file's data, so the trailer, what follows it and the
  codec's own end check are not reached, and damage in the entries after the last file
  read is not reported.

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
  file costs about 400 bytes while the walk lists (about 100 MiB at the default
  262 144).
- Names stay split as the header stores them (directory, base) and each member is made
  as the walk yields it, since `DIRINDEXES` lets every file share one long directory
  name: joined up front, the names grow with files times directory length. Each
  member's name is weighed by the listing's limits as it is listed, so
  `max_metadata_bytes` stops a listing whose names grow that way.
- A string array cannot declare more strings than its bytes can hold.
- A tag read for one value (NAME, VERSION, EPOCH, the payload tags and the like) reads
  only its first value, whatever count its entry declares.
- Held hard links are charged to the listing's limits as they are held.
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
- **Every header digest stored is checked.** SHA-256 and SHA-1, as `rpm -K` checks
  every digest it finds; the first that differs is named. A package with neither (an
  old or rewritten one) is not damage. The digests are not signed, so they detect
  damage, not tampering: whoever changes the header can change them too. The
  member list comes from the header, so without this check a changed link target, mode
  or owner passed `archivey test`.
- **The listing is the header's; the payload is read only for data.** The header is
  what rpm installs and what the header digests cover, so listing needs nothing else,
  and `list` costs two headers. What this gives up, accepted by the maintainer: a file
  the payload lacks (rpm's `RPMERR_MISSING_FILE`) or a damaged payload is found only when
  data is read, and fails that read (§2.3), not the listing.
- **A symlink's two targets that differ are reported, not refused** (maintainer,
  2026-11-12). The member keeps `FILELINKTOS`, which rpm installs and the header
  digests cover; `rpm2cpio | cpio -i` makes the payload's. The report is
  `MEMBER_HEADER_AMBIGUOUS` (a shape no writer produces, which tools resolve
  differently), so `STRICT` raises it. It comes only when a read passes the entry,
  after the link is listed: extraction never reads a symlink's entry.
- **Members come in the order rpm writes the payload** (§1), so a pass reads it forward
  once. Header order would put a hard-link set's data before the files rpm writes ahead
  of it.
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
