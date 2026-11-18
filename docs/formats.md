# Formats and extras

What each format can do, what it needs installed, and what most often surprises callers. The
first sections cover what holds across formats; then each format has a section of its own, in
the same order: what it needs, how it lists and reads, and its quirks.

The maintainer handbook has more depth on
[7z](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/7z.md),
[ISO](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/iso.md),
[SquashFS](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/squashfs.md),
[CPIO](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cpio.md),
[ar](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/ar.md),
[Debian packages](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/deb.md),
[RAR](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rar.md),
[TAR](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/tar.md) and
[ZIP](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zip.md), and on the single-file
compressors: what they share in
[single-file.md](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/single-file.md), then
[gzip](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/gzip.md),
[bzip2](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/bzip2.md),
[bzip3](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/bzip3.md), [xz, lzip and LZMA
Alone](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xz.md), [zstd and
LZ4](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zstd-lz4.md),
[Brotli](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/brotli.md) and
[`.Z`](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/unix-compress.md), and on [disk
images](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/dmg.md) and
[directories](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/directory.md).

## Overview

"Core" means a plain `pip install archivey`, with no other packages. `archivey[recommended]` is
the usual choice ([Install](install.md)). At run time,
[`format_availability()`](api.md#archivey.format_availability) says what the current install can
read.

| Format | Install |
|---|---|
| ZIP (`.zip`, `.jar`, `.whl`, `.apk`) | Core. `[recommended]` adds Deflate64, PPMd, WinZip AES, and Zstandard before Python 3.14 |
| TAR (`.tar`) | Core |
| Compressed TAR (`.tar.gz` or `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, …) | What its compressor needs (below) |
| 7z (`.7z`) | Core. `[recommended]` adds PPMd, Deflate64, Brotli, LZ4, AES, and Zstandard before Python 3.14 |
| RAR (`.rar`, volume sets such as `.part1.rar` or `.r00`) | Core lists it and reads uncompressed members. Compressed members need the `unrar` program ([RAR](#rar)) |
| ISO 9660 (`.iso`, and CD images as `.bin` with `.cue`) | `[recommended]` |
| SquashFS (`.squashfs`, `.sqfs`, `.snap`) | Core. Zstandard images need `[recommended]` before Python 3.14, and LZ4 images need `[recommended]` |
| XAR (`.xar`, macOS `.pkg` and `.xip`) | Core |
| CAB (`.cab`) | Core |
| Debian packages (`.deb`, `.udeb`) | Core. Zstandard packages need `[recommended]` before Python 3.14 |
| RPM (`.rpm`) | Core. Zstandard payloads (Fedora's default) need `[recommended]` before Python 3.14 |
| makeself (`.run`) | Core. The payload needs what its compressor needs |
| LHA (`.lzh`, `.lha`), ARJ (`.arj`) | Core |
| CPIO (`.cpio`), ar (`.a`, `.lib`) | Core |
| gzip (`.gz`), bzip2 (`.bz2`), xz (`.xz`), lzip (`.lz`), LZMA Alone (`.lzma`), zlib (`.zz`), Unix compress (`.Z`), lzop (`.lzo`), Snappy (`.sz`) | Core. `[recommended]` makes `.lzo` and `.sz` faster |
| Zstandard (`.zst`) | Core on Python 3.14 and later, `[recommended]` before |
| LZ4 (`.lz4`), Firefox's mozlz4 (`.jsonlz4`, `.mozlz4`), Brotli (`.br`) | `[recommended]` |
| bzip3 (`.bz3`) | `[bzip3]` |
| uuencode (`.uu`, `.uue`), base64 (`.b64`) | Core |
| A directory on disk | Core |

A UDIF disk image (`.dmg`) is recognised and refused ([Disk images](#disk-images)).

The
[library analysis](https://github.com/archivey-dev/archivey/blob/main/dev-docs/library-analysis.md)
explains the choice of each compression library, and [Acknowledgements](acknowledgements.md)
credits them.

## Seeking in compressed files

A member stream can seek when you pass `seekable_members=True`
([Seeking inside a member](reading.md#seeking-inside-a-member)). A seek forward decodes the bytes
in between. A seek backward resumes from the last point before its target where decoding can
restart. If there is no such point, it decodes again from the start of the stream. Reading a
member of a `.tar.gz` or other compressed TAR by name uses the same points.

**Always near the target:**

- **gzip, zlib, and Deflate members of ZIP and 7z:** from a point archivey keeps about every MiB
  that a read has passed, except on PyPy ([PyPy](install.md#pypy)). `[seekable]` adds an
  accelerator that keeps its own points.
- **bzip2:** from the start of the block, which holds at most 900 kB of data.
- **bzip3:** from the start of the block. Its size is set by the writer, and is 16 MiB by default.
- **lzop:** from the start of the block, 256 KiB of data by default.
- **Snappy:** from the start of the chunk, which holds at most 64 KiB of data.
- **Legacy LZ4** (`lz4 -l`): from the start of the block, which holds 8 MiB of data.

**Near the target only if the file was written in pieces:**

- **xz:** from the start of a block, found from the file's index without decoding.
  Single-threaded `xz` writes one block. `xz -T0` writes one every 24 MiB at the default level.
- **lzip:** from the start of a member. `lzip` writes one, and `plzip` writes several for a large
  file.
- **LZ4:** from the start of a frame. `lz4` writes one frame per file.
- **Zstandard:** from the start of a frame. `zstd` writes one frame per file. Files in the
  Seekable Zstandard format have many frames, and archivey finds them without decoding.
- **Unix compress (`.Z`):** from a reset code (CLEAR), which the writer adds only when compression
  gets worse.

**Always from the start:** LZMA Alone, Brotli and mozlz4. Archivey keeps no restart points in
them.

If you'll seek backwards often in a file from the last two groups, extracting the member to a file
first is usually faster.


## Member fields across formats

### The `extra` bags

`ArchiveMember.extra` is a [`MemberExtra`](api.md#members-and-archive-details) and
`ArchiveInfo.extra` is an [`ArchiveInfoExtra`](api.md#members-and-archive-details). Both are
`dict[str, object]` subclasses, and both names are importable. Reading a known key
(`extra["zip.compress_type"]`) gives that key's type to a type checker, and an unknown key (from a
third party, or added later) stays legal and is typed as `object`. `.get()` returns `object` for
every key. The `EXTRA_*` constants in `archivey.types` name the keys that have constants.

Writes are not type-checked: a value of the wrong type for a known key is accepted, as an unknown
key is. To replace a bag, assign a `MemberExtra(...)` or `ArchiveInfoExtra(...)` rather than a bare
dict. Changing the existing bag in place works as before.

The format sections below mention a key only when it is part of that format's behaviour. The full
list is on the two classes.

### Time zones

A time has no zone when the format records local time: a ZIP with only the DOS time, and RAR 4.
Every other format records UTC or an offset, so its times have a zone, and so does a ZIP with a
UTC field beside its DOS time. Two such times from one archive can't be compared directly.
`member.modified_utc()`, `accessed_utc()`, `created_utc()` and `ctime_utc()` give each time in UTC.
A time with no zone is taken as your local time, or as the zone you pass (`tz_for_naive=`).

### Creation time and `ctime`

`ArchiveMember.created` is a birth time or `None`, never Unix `st_ctime` (the time of the last
inode change). Several writers store `st_ctime` where a reader might expect a creation time: a Rock
Ridge ISO, a Unix RAR, a PAX TAR, a 7z written on Unix, and a ZIP written on Unix by 7-Zip or
libarchive. That time is in `ArchiveMember.ctime` instead.

RAR, 7z and ZIP have one creation slot, so a member has at most one of the two. Rock Ridge, and a
PAX TAR from libarchive (`LIBARCHIVE.creationtime`), store both times and can have both. For ZIP
the writer's host decides: a creation time is `created` only from a FAT, OS/2, NTFS or VFAT host,
and `ctime` from any other host, an unknown one included. 7-Zip and libarchive on macOS store
`st_ctime` too. A writer that marks itself Unix while storing a birth time (libarchive on Windows)
gets `ctime`, so that `st_ctime` never lands in `created`.

### Fields that change after a member is returned

`ArchiveMember.member_state_final` is `False` while archivey can still update a member you hold
([Reading once](reading.md#reading-once)). It is always `False` during a `streaming=True` pass.
The fields that change, by format:

- **ZIP:** `link_target_member`. `is_current` from a pipe only: from a file, the pass reads the
  index first, so it is final when the member is yielded. The `size` of a large macOS member listed
  as `None` ([ZIP](#zip)), until a checked full read fills it in.
  From a pipe, `size`, `compressed_size` and the CRC-32 in `hashes` of a member whose sizes come
  after its data, until the pass gets past its data. Also from a pipe, until the pass reads the
  index, every field only the index holds: `type`, `name` (where a DOS host makes `\` a separator),
  `mode`, `create_system`, `comment`, and the times and owner ids from its extra fields.
- **TAR, 7z, ISO, SquashFS, CPIO:** `is_current` and `link_target_member`.
- **RAR:** `is_current` and `link_target_member`. Also the `size` of a RAR5 file whose headers
  never give it (no known archiver writes one), listed as `None` until a checked full read fills
  it in.
- **Directory:** `link_target_member`. Names never repeat, so `is_current` never changes.
- **Single compressed files:** `size`, when the format records none. A full read fills it in, and
  the flag stays `False` until then ([Single-file compressors](#single-file-compressors)).

A symlink whose target archivey has not read yet (`read_link_targets=False`) can also change:

- **ZIP and 7z:** `link_target`. A Windows reparse point whose data is not a link becomes a `FILE`.
- **RAR:** `link_target`, in RAR 4 only.
- **TAR, ISO, SquashFS, CPIO, directory, single compressed files:** nothing. The header,
  Rock Ridge, the inode, the member's data or the filesystem gives the target with the entry.

`members()`, `members_report()` and `get()` return members that read `True`, except unread
symlinks, and single-file, large macOS ZIP or unsized RAR5 members whose `size` a full read has
not filled in yet. Members report `False` until a call like those, or the end of a pass, has resolved the
listing's links. A `streaming=True` pass yields every member before that, in every format. A
`members_report_if_available()` peek resolves no links, so its members report `False` until a later
call or pass does. A random-access pass with no listing call before it may or may not yield before
that point, depending on how the format is listed, so read the flag rather than assume. A pass that
goes past `ListingLimits` stops updating members from that point: a member yielded after it reads
`True`, with `is_current` as yielded.

### Stored digests

`member.hashes` holds the digests the archive already stores, keyed by
[`HashAlgorithm`][archivey.HashAlgorithm]. They are readable without decompressing anything, and
they are not computed: a full read still checks the data the usual way. Values are always `bytes`.
A CRC-32 is four big-endian bytes, so a CRC you computed compares as
`zlib.crc32(data).to_bytes(4, "big")`.

- **ZIP:** `crc32`, for files and symlinks, and for a directory that declares data with a non-zero
  CRC. It comes from the index, or from the local header when listed without one. A WinZip AE-2
  member has none.
- **7z:** `crc32`, for files.
- **RAR5:** `crc32`, `blake2sp`, or both, for files that store them.
- **`.lz`:** `crc32`, from a source that can seek. A file of several lzip members gets one value,
  combined from each member's CRC, equal to the CRC-32 of the whole payload.
- **CPIO:** none. A crc archive stores a 32-bit sum of each file's data, which a full read
  checks, but it is not a digest `hashes` can hold.
- **LHA:** none. Each member stores a CRC-16 of its data, which a full read checks, but it
  is not a digest `hashes` can hold.
- **ARJ:** `crc32`, for files, from the member's header. A full read checks it.
- **Debian packages:** `md5`, for the files the package's `DEBIAN/md5sums` lists. It comes from
  the control tar, so it is known once listing has decompressed that, before the data tar.
- **TAR, SquashFS, ar, directory, and every other single compressed file:** none.

When a format stores none, compute a digest while reading. A first-pass dedupe index can take the
best one available:

```python
import hashlib
import archivey
from archivey import HashAlgorithm

def content_key(reader, member):
    """Best available digest for a first-pass dedupe index."""
    if HashAlgorithm.BLAKE2SP in member.hashes:
        return ("stored", "blake2sp", member.hashes[HashAlgorithm.BLAKE2SP])
    if HashAlgorithm.CRC32 in member.hashes:
        return ("stored", "crc32", member.hashes[HashAlgorithm.CRC32])
    # No stored digest (e.g. tar, bzip2): compute while reading.
    h = hashlib.sha256()
    with reader.open(member) as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return ("computed", "sha256", h.digest())

with archivey.open_archive("backups.zip") as reader:
    for member in reader:
        if member.is_file and member.is_current:
            print(member.name, content_key(reader, member))
```

A stored CRC-32 is weak, and each format stores its own kind; a computed digest is stronger but
costs a full decode. Keeping `stored` and `computed` apart in the key lets your index decide how
far to trust each.

## Behaviour shared by several formats

### Bytes after the end of an archive

TAR, ZIP, 7z, RAR, ISO, CPIO, LHA and ARJ archives, and single compressed files, all check for bytes
after the archive's end. A non-zero byte there is reported as `ARCHIVE_TRAILING_DATA`, with the format in
`format`: a warning under the default policy, raised under `DiagnosticPolicy.STRICT`. Zero bytes
are padding and pass. ZIP, TAR, 7z, RAR, ISO and CPIO look at most 1 MiB past the end, so a byte
further out goes unseen; LHA and ARJ look 64 KiB past their end, and take the DOS end-of-file
byte `0x1A` as padding too. Each format section says where its end is. Two exceptions, both for an
archive inside a Windows program: its signature, and the rest of the program after an archive
stored as one of its resources (see self-extracting stubs under [Detection](#detection)).

Inside a ZIP or 7z member, bytes after the compressed stream are corruption, not trailing bytes
([ZIP](#zip)).

### Device files, FIFOs and sockets

A ZIP, 7z, RAR, ISO, CPIO or SquashFS entry whose mode is a device, FIFO or socket, or a TAR entry
whose typeflag is a device or FIFO (TAR has no socket type), is listed as `MemberType.OTHER` when it
stores no data. Extraction does not create it: its result is `BLOCKED`, and the other members
are extracted. `extra["special_file_type"]` names the kind. In ZIP, 7z, RAR, ISO and CPIO, such
an entry that does store data is a `FILE`, with `MEMBER_SPECIAL_FILE_HAS_DATA` reported. Each
section for ZIP, 7z, RAR and ISO says when its mode is trusted; for TAR, archivey reads the typeflag instead
([TAR](#tar-and-compressed-tar)).

### Names with a NUL

ZIP and CPIO store a name's length, so a name can hold a NUL (`a\0b.txt`). Archivey lists the
whole name and reports `MEMBER_READERS_DISAGREE`; extraction skips the member under every policy,
since no filesystem takes the name, unless a filter such as `sanitize_names` rewrites it. unzip writes the name up to the NUL (`a`), and 7-Zip refuses
the archive.

### Names with an unpaired surrogate

A UTF-16 name (in 7z, in RAR 1.5-4, and in Joliet on an ISO) can hold a surrogate without its
partner, which NTFS allows. Archivey keeps that code unit in `member.name` (`'hi\ud800'`) and
lists every member, as 7-Zip does. The CLI shows the name escaped, as `hi\ud800`.
`member.raw_name` always holds the stored units.

Under the `STRICT` extraction policy, extraction refuses the member (`BLOCKED`), as it refuses
any name that is not portable. Under `STANDARD` it escapes the surrogate's UTF-8 bytes:
`hi\ud800` is written `hi%ED%A0%80` on every OS, and `presented_name` holds the stored name.
Under `TRUSTED` it writes what 7-Zip writes. On Linux and other POSIX systems that is the
three-byte UTF-8 form, `hi` followed by `ed a0 80`; a filesystem that accepts only valid UTF-8,
such as APFS, refuses those bytes, and the member fails with `ExtractionError`. On Windows it is the exact name. One exception: a unit from U+DC80 to
U+DCFF looks the same as an undecodable byte (see
[Names in other encodings](opening.md#names-in-other-encodings)), so extraction writes it as that
byte, where 7-Zip writes three bytes.

### macOS sidecar files

A ZIP or TAR made on a Mac often holds AppleDouble sidecars: a `._name` file with the extended
attributes and resource fork of `name`, next to it (macOS `tar`) or under `__MACOSX/` (Finder,
`ditto`). Archivey lists them as ordinary files, as `unzip` does. To leave them out, skip them by
name with `members=`:

```python
from archivey import open_archive

def is_macos_sidecar(member):
    base = member.name.rsplit("/", 1)[-1]
    return member.name.startswith("__MACOSX/") or base.startswith("._")

with open_archive("photos.zip") as reader:
    reader.extract_all("out", members=lambda m: not is_macos_sidecar(m))
```

The test goes by name only, so it also skips a file that was really called `._notes`, and anything
in a real folder named `__MACOSX`.

## ZIP

- **Reading:** archivey reads the index at the end of the file, so listing is quick and every
  member can be read directly.
- **From a pipe:** with `streaming=True`. A member's mode, comment and owner, and whether it is a
  symlink, are stored only in the index at the end, so they arrive when the pass gets there, and
  `member.member_state_final` turns `True` then. Extraction from a pipe keeps the files in a
  temporary folder inside the destination, and puts them in place once the index has been read.
- **Split sets:** a set split by 7-Zip (`name.zip.001`, `.002`, …), or spanned by `zip -s` or
  WinZip (`name.z01`, `.z02`, …, `name.zip`), opens from any part, when all parts are in one
  folder. A missing part raises `TruncatedError`.
- **Encryption:** ZipCrypto, and WinZip AES with `[recommended]`. ZipCrypto's password check lets
  about one wrong password in 256 through, so a wrong password and a damaged member fail with the
  same error, and its decryption is slow, a few MiB/s. PKWARE Strong Encryption is not supported.
- **Names:** a name not flagged as UTF-8 is still read as UTF-8 when it is valid UTF-8, because
  many tools write UTF-8 without setting the flag. Otherwise archivey uses `encoding=`, or cp437 by
  default. Unlike `zipfile`'s `metadata_encoding`, `encoding=` applies only to names that are not
  valid UTF-8.
- **Archives from macOS:** archivey reads a ZIP over 4 GiB that Finder wrote without ZIP64, which
  7-Zip and `zipfile` cannot. In such a file a member's size can be listed as `None` until a full
  read fills it in. Finder also adds `__MACOSX/` sidecar files
  ([macOS sidecar files](#macos-sidecar-files)).
- **Compression methods:** archivey reads every method in common use, the old PKZIP ones
  included. It does not read WinZip's JPEG, WavPack and MP3 methods or IBM's mainframe methods: a
  member that uses one is listed normally, and reading it raises `UnsupportedFeatureError`.

Damaged and unusual archives are read as far as they can be, and each problem is reported with a
diagnostic: a missing or damaged index, local headers that disagree with the index, bytes missing
from the middle, or data after a member's compressed stream. The
[ZIP handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zip.md)
describes each case and the error it raises.


## TAR (and compressed TAR)

- **Reading:** members of a plain `.tar` file are read directly. A compressed TAR is solid:
  reaching a member means decompressing everything before it, so a single `stream_members()` pass
  is the fast way to read many members. Reading one by name after listing resumes from the nearest
  restart point ([Seeking in compressed files](#seeking-in-compressed-files)).
- **From a pipe:** yes. Archivey reads up to 1 MiB past the end of the archive to check for
  trailing data, so close the sending side when the tar is done, or the listing waits.
- **Headers** are read the way GNU tar reads them, the same on every Python version. Where tools
  disagree on a member's name, link target or size, archivey gives GNU tar's answer and reports a
  diagnostic. Old v7 tars, which have no `ustar` signature, are recognised by their checksum.
- **Hard links** are extracted as hard links.
- **Sparse members** (`tar -S`) are extracted with their holes filled with zeros. That output
  counts towards the ratio limit, so a very sparse file can raise `ResourceLimitError`.
  `member.is_sparse` tells you which members are sparse. For an archive you trust, raise
  `DecoderLimits.max_ratio`.
- **A tar cut exactly between two members** looks complete, because a tar has no member count.
  Archivey reports the missing end blocks as `ARCHIVE_EOF_MARKER_MISSING`, which
  `DiagnosticPolicy.STRICT` raises, for when you need the listing proven complete. A cut inside a
  member always raises `TruncatedError`.
- A tar made by macOS `tar` can hold `._name` sidecar files
  ([macOS sidecar files](#macos-sidecar-files)).

Damaged headers, and header shapes no writer produces (a device or directory header that declares
data, PAX records set twice, a lone zero block), are refused or reported with a diagnostic. The
[TAR handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/tar.md)
describes each case.


## 7z

- **Reading:** archivey reads the index at the end of the file, so the archive needs a source
  that can seek: a pipe raises `StreamNotSeekableError`. Members are solid unless the archive was
  written without solid blocks (`7z -ms=off`). A `stream_members()` pass decodes each solid block
  once. Opening a member in the middle of a block may decode the block again from its start.
- **Compression methods:** the core install reads LZMA, LZMA2, Deflate, BZip2, Delta and the
  executable filters, including BCJ2, ARM64 and RISC-V, which archivey decodes in Python and so
  read more slowly. `[recommended]` adds PPMd, Deflate64, Brotli, LZ4, AES, and Zstandard before
  Python 3.14. One setting can't be read: LZMA with `lc + lp` over 4, which 7-Zip writes only when
  asked for it (for example `-mlc=8`). Such an archive can be listed, and reading its members
  raises `UnsupportedFeatureError`.
- **Encryption:** 7z stores no password check. A wrong password usually makes decompression fail,
  or else the data fails its CRC. Only a member stored without compression and without a CRC can
  come back as garbage, which archivey reports as unchecked data (`DIGEST_UNVERIFIABLE`). With
  encrypted headers, a wrong password raises `EncryptionError`.
- **Names** are stored as UTF-16, so `encoding=` has no effect.
- **Self-extracting `.exe` files** open like a `.7z`, a code-signed one included.

Damaged archives, and the details of confirming a password among several candidates, are covered
in the [7z handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/7z.md).


## RAR

Archivey reads the RAR structure itself, RAR 1.5 to RAR5, but no Python package decodes RAR
compression. Listing and reading uncompressed members need nothing extra. Compressed members are
decoded by running RARLAB's `unrar` (or `rar`) 6.0 or later, found on `PATH` or, on Windows, in a
WinRAR installation, or else The Unarchiver's `unar` 1.10 or later
([Getting unrar](install.md#getting-unrar)). `ArchiveyConfig.rar_decompressor` picks the program:

```python
ArchiveyConfig(rar_decompressor="auto")   # default: unrar when found, otherwise unar
ArchiveyConfig(rar_decompressor="unrar")  # only unrar; unar is never run
ArchiveyConfig(rar_decompressor="unar")   # only unar
ArchiveyConfig(rar_decompressor="none")   # run no program
```

- **`unar` exposes the password.** `unar` takes the password on its command line, where other
  users on the same machine can see it. On a shared machine, install `unrar`, or set
  `rar_decompressor="unrar"`. `unar` also gets some archives wrong, and archivey refuses those
  reads before running it.
- **Solid archives:** a `stream_members()` pass decodes the archive in one run. Opening members
  out of order decodes the solid stream again from its start each time.
- **Volume sets** (`.part1.rar`, or `.rar` with `.r00`) open from any volume when all are in one
  folder. If a volume is missing, the members in the remaining volumes are listed, and reading a
  member with data in the missing volume raises `TruncatedError`.
- **From a pipe:** with `streaming=True` and `unrar` 7.00 or later, for an archive in a single
  volume.
- **Encryption:** `[recommended]` adds archives with encrypted headers. RAR5 stores a password
  check, so a list of passwords is tried quickly. RAR 1.5-4 doesn't, so each wrong candidate costs
  a decode, and putting the likely password first is faster.
- **File versions** (`rar -ver`): older revisions are listed under names like `path;1`, as `unrar`
  names them, with the number in `extra["rar.file_version"]` and `is_current=False`. Extraction
  skips them by default.
- **Names** in RAR 1.5-4 that are stored only as 8-bit bytes are read as UTF-8 when they are valid
  UTF-8. Otherwise they're decoded with `encoding=`, or by default with cp437 for an archive from
  DOS or Windows and windows-1252 otherwise.
- **With `unrar` older than 7.00**, a large member or solid stream from an archive opened as a
  stream (not a path) is copied whole to a temporary file before `unrar` reads it.
  `SpoolLimits.max_bytes` (1 GiB by default) bounds the copy, and a read over it raises
  `ResourceLimitError`. `unrar` 7.00 or later avoids the copy.
- **No timeout:** a member read waits as long as `unrar` does. A solid archive can produce nothing
  for a long time while `unrar` decodes the members ahead of the one you asked for.

Damaged archives, and the details of how archivey runs `unrar` and `unar`, are covered in the
[RAR handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rar.md).

## ISO 9660

Reading an ISO image needs `[recommended]` (`pycdlib`) and a source that can seek, so not a pipe.
An image can carry several name trees over the same files. Archivey lists Rock Ridge first, then
Joliet, then plain ISO 9660, and says which in `ArchiveInfo.extra["iso.namespace"]`.

- **Names:** Rock Ridge and plain names are read as UTF-8, then with `encoding=` when you pass
  one. Without it, a name that isn't UTF-8 takes the matching Joliet name when the image has one,
  and is escaped otherwise. Joliet names are UTF-16.
- **File versions:** the `;1` at the end of a plain or Joliet file name is dropped, and the number
  is kept in `extra["iso.version"]`. When a folder holds several versions of one name, the highest
  takes the bare name, and older ones are listed as `FOO.;1` with `is_current=False`, as RAR file
  versions are.
- **Files in other trees:** a file that only an unlisted tree holds (such as Joliet or UDF, which
  Windows and 7-Zip read) is not a member. Archivey reports it with `MEMBER_READERS_DISAGREE`.
- **UDF** is not read. A DVD image that also has an ISO 9660 tree is listed from that tree, and
  a UDF-only image (such as a Blu-ray) is not recognised.
- **Contents:** zisofs compression (`mkzftree`, `genisoimage -z`, `xorriso --zisofs`) is read
  decoded; zisofs2 members are listed, and reading one raises `UnsupportedFeatureError`. Files of
  4 GiB or more, stored in several pieces, are one member. A bootable image's boot catalog is
  listed as an ordinary file, as a mounted image shows it.
- **CD images** (`.bin` with `.cue`): open the `.cue`, or the `.bin` by its path with its `.cue`
  beside it. Archivey reads the session an operating system would mount, from one track file or
  one per track. Mode 1 and Mode 2 Form 1 data can be read; a video or audio-only image raises
  `UnsupportedFeatureError`. A `.bin` opened without its `.cue` is read from its first session,
  and `ARCHIVE_UNREAD_SESSION` says when a later one exists.
- **Damage:** ISO 9660 stores no checksums, so damaged data comes back without an error. A
  truncated image still opens when its folders survive, and only the files the cut reaches raise
  `TruncatedError`. An image with UDF doesn't open once truncated, because the UDF anchor sits in
  its last block.
- **Hybrid installer images**, whose EFI partition sits after the ISO data, open without a
  trailing-data warning.

Archivey also refuses folder trees that loop back on themselves, survives Rock Ridge entries
`pycdlib` can't parse, and checks each CD sector's header as it reads. The details, and how
`.cue` sheets and multisession discs are read, are in the
[ISO handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/iso.md).

## SquashFS

gzip, xz, LZMA and LZO images need nothing extra. Zstandard images need `[recommended]` before
Python 3.14, and LZ4 images need `[recommended]`. Members are read directly, but the image needs a
source that can seek, so not a pipe. `ArchiveInfo.extra` names the compressor
(`"squashfs.compressor"`) and the block size (`"squashfs.block_size"`).

- **Members:** files, folders, symlinks, hard links, sparse files (`is_sparse`), and devices,
  FIFOs and sockets (`OTHER`). Extended attributes are not read.
- **SquashFS 3 and older** raise `UnsupportedFeatureError`. Only version 4.0, written since 2009,
  is read.
- **Damage:** SquashFS stores no checksums of its own. A damaged block is caught when it doesn't
  decode to its length, or when its compressor's own check fails (zlib's Adler-32, the xz CRC).

The [SquashFS
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/squashfs.md) covers
the layout and how damaged images are handled.

## XAR

The format of macOS installer packages (`.pkg`) and `.xip` files, written by Apple's `xar`,
`pkgbuild` and `productbuild`, and by `bsdtar --format xar`. It needs nothing extra. Members are
read directly, each compressed on its own, but the archive needs a source that can seek, so not a
pipe.

- **Installer packages** are listed as the files their XAR layer holds: `Distribution`, and for
  each component `PackageInfo`, `Bom`, `Scripts` and `Payload`. `Payload` is a compressed CPIO
  archive (or a `pbzx` stream in newer packages). Archivey reads it as one file and doesn't
  expand it.
- **Checksums:** the index's own checksum is checked at open. Each file stores a checksum of its
  data (SHA-1 by default), which is in `member.hashes` and checked when you read the member to
  its end.
- **Names** stored as base64, as writers do for bytes that aren't UTF-8, are decoded with
  `encoding=` like names in any other format.

The [XAR handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xar.md)
covers the index, its limits, hard links, and the shapes archivey refuses.

## CAB

Microsoft cabinets: Windows updates and drivers, the payloads inside many installers, and what
`makecab` and `gcab` write. Cabinets need nothing extra: MSZIP is read with Python's `zlib`, and
LZX is decoded by archivey itself, in Python, at a few megabytes a second. The cabinet needs a
source that can seek, so not a pipe.

- **Solid folders:** a cabinet groups its files into folders, each one compressed stream.
  Reaching a file decodes its folder from the start. Reading the files in listed order, as
  `stream_members()` does, decodes each folder once.
- **Names** are UTF-8 when valid, otherwise decoded with `encoding=`. A Japanese cabinet from
  `makecab` is usually `encoding="cp932"`. A cabinet stores paths, not folders, and `\` becomes
  `/`.
- **Checksums:** each data block stores a checksum, checked as it is read, so a member read to its
  end is checked when its blocks carry one (some writers store 0, meaning none).
- **Not read:** Quantum-compressed members are listed, and reading one raises
  `UnsupportedFeatureError`. A cabinet split across several files (`file.cab`, `file2.cab`) raises
  `UnsupportedFeatureError` at open.

Archivey also refuses a cabinet whose file table doesn't match its folders, and lists edited or
crafted cabinets in an order that decodes each folder once. The
[CAB handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cab.md) has the
details.

## LHA

LHA and LZH archives, from LHarc, LHA and their kin on DOS, the Amiga, OS/2, OS-9, the Atari
ST and Japanese PCs, and from LHa for UNIX.

- **Needs:** nothing. archivey decodes the methods itself, in Python, at about 4 to 8 MB a
  second.
- **Listing:** header by header: each member is a header and then its data, and the listing
  reads each header and seeks past the data to the next one.
- **Reading members:** each member is compressed on its own, so every member is direct.
- **From a pipe:** no, for now: the listing seeks past each member's data.
- Header levels 0 to 3 all read. Stored members (`-lh0-`, `-lz4-`, `-pm0-`) and the
  `-lh1-` and `-lh4-` to `-lh7-` methods, UNLHA32's `-lhx-`, LHARK's `-lk7-` and LArc's
  `-lzs-` and `-lz5-` decode; other methods (`-lh2-`, `-lh3-`, PMarc's `-pm1-` and `-pm2-`) are listed and
  raise `UnsupportedFeatureError` when read. `member.compression` is `LZH` for every
  `-lh?-` and `-lz?-` method, and `extra["lha.method"]` names the exact one.
- Each member stores a CRC-16 of its data, which a read checks, so a member read to its
  end is at `Verification.CHECKSUM`. A header's own checksum or CRC is checked when it is
  read: a damaged header is `CorruptionError`.
- `member.modified` is the Unix time a header stores, in UTC, or else its DOS time, with no
  time zone. A Windows timestamps record adds `created` and `accessed`. Unix mode, owner and
  group names come from LHa for UNIX's records; OS-9 permissions become a Unix mode as
  lhasa reads them. A directory is a member of its own; a Unix symlink is listed with its
  target. `create_system` comes from the header's OS id, and `extra["lha.os_id"]` keeps it.
- Names are UTF-8 when valid, otherwise decoded with `encoding=` (an archive from a
  Japanese PC is usually `encoding="cp932"`), as in every format. A name's `\` separators
  become `/`. An Amiga file note stored after the name is `member.comment`.
- An archive without the zero byte that ends it reports `ARCHIVE_EOF_MARKER_MISSING`, after
  listing every member.
- A self-extracting LHA program reads like an archive: the archive behind a DOS, Windows,
  Amiga, Atari or X68000 stub is found by its first header, as for ZIP, 7z and RAR (see
  [Detection](#detection)). An Amiga self-extractor's own usage text, a small archive inside
  the stub, is passed over for the archive that ends the file.
- A Mac file archived by MacLHA reads as its data fork (or its resource fork, when the
  data fork is empty), as lhasa reads it: MacLHA wraps the file in MacBinary, a 128-byte
  header that archivey strips when every field in it matches the LHA header (name, sizes,
  and a time within 14 hours). `member.size` is the fork's size, and
  `extra["lha.mac_type"]` and `extra["lha.mac_creator"]` keep the Finder's type and
  creator codes. The listing decodes the first 128 bytes of each such member to check.
  A level-0 member has no OS id to say it came from a Mac, so it reads with its wrapper,
  as in lhasa.

## ARJ

ARJ archives, from ARJ for DOS, ARJ32 and ARJ for Unix (the `arj` command on Linux).

- **Needs:** nothing. archivey decodes the methods itself, in Python, at about 10 to 30 MB a
  second.
- **Listing:** header by header: each member is a header and then its data, and the listing
  reads each header and seeks past the data to the next one.
- **Reading members:** each member is compressed on its own, so every member is direct.
- **From a pipe:** no, for now: the listing seeks past each member's data.
- Methods 0 (stored) to 4 all decode. `member.compression` is `LZH` for methods 1 to 3,
  which are the same as LHA's `-lh5-` to `-lh7-` with another dictionary size, and
  `ARJ_FAST` for method 4. `extra["arj.method"]` names the exact one.
- Each header has a CRC-32, checked when it is read: a damaged header is
  `CorruptionError`. Each member stores a CRC-32 of its data, which a read checks, so a
  member read to its end is at `Verification.CHECKSUM`.
- `member.modified` is a DOS time with no time zone, except from ARJ for Unix, which
  stores a Unix time, read in UTC. ARJ 2.62 and later also store `accessed` and `created`.
  From ARJ for Unix, `mode` is the Unix mode; from DOS and Windows, `windows_attrs` holds
  the attributes. A directory is a member of its own; ARJ for Unix's symlinks and hard
  links are listed with their targets, and FIFOs and devices as `OTHER`.
- Names are UTF-8 when valid, otherwise decoded with `encoding=` (DOS archives are usually
  `encoding="cp437"`, or `"cp866"` from Russian systems), as in every format. A DOS or
  Windows name's `\` separators become `/`.
- Garbled (password-protected) members are listed with `is_encrypted` and raise
  `UnsupportedFeatureError` when read, as do members split across the volumes of a
  multi-volume set. An archive without the end header reports
  `ARCHIVE_EOF_MARKER_MISSING`, after listing every member.
- Self-extracting ARJ programs (ARJ's DOS `.EXE` modules, or an ELF program from ARJ for
  Unix) are read: detection finds the main header behind the program by its CRC-32, and
  so does `format=ARJ`.
- An archive signed by a registered ARJ carries an ARJ-SECURITY envelope after its end
  header. The envelope is not checked, and is not reported as data after the archive.

## CPIO

- **Needs:** nothing.
- **Listing:** header by header, in one pass, up to the `TRAILER!!!` member; inside a compressor,
  it needs decompression, as in a compressed TAR.
- **Reading members:** direct; inside a compressor, solid, as in a compressed TAR.
- **From a pipe:** yes, with `streaming=True`.
- All four header variants read: binary (either byte order), odc, newc and crc, and afio's
  large header in an odc archive. `ArchiveInfo.extra["cpio.variant"]` names the variant as
  GNU cpio's `-H` option does (`bin`, `odc`, `newc`, `crc`), with `bin-be` for a binary
  archive in the other byte order. `ArchiveInfo.format_version` is `None`.
- A binary archive (GNU cpio's default) has only a 2-byte magic, so it is detected only when
  its name ends in `.cpio` or a compressed spelling of it (`.cpio.gz`, …), or with
  `always_probe_content=True`, or when you pass `format=` (`"cpio"`, `"cpio.gz"`, …). Inside a
  compressor the check reads the first 512 decompressed bytes, so an archive whose first name
  ends past them needs `format="cpio.gz"`.
- A symlink's target is its data. Devices, FIFOs and sockets are `OTHER`, as in every
  format.
- In crc, each file's checksum is checked as its data is read.
- **Hard links.** Names that share a device and inode number are one file. The first name
  listed is a `FILE`, the others `HARDLINK` members to it. newc and crc store the data with
  the **last** name only, so archivey lists that name first and the earlier, empty names
  right after it: the member order is then not quite the archive's. A file whose names are
  all empty is listed at the trailer.
- An archive that ends before its trailer raises `TruncatedError`. Non-zero bytes after the
  trailer are `ARCHIVE_TRAILING_DATA`, as for TAR; a second archive appended after the first
  is not listed.

## ar

- **Needs:** nothing.
- **Listing:** header by header, in one pass; inside a compressor, it needs decompression, as in a
  compressed TAR. Every member is a file: ar has no directories or links.
- **Reading members:** direct; inside a compressor, solid, as in a compressed TAR.
- **From a pipe:** yes, with `streaming=True`.
- Both dialects read. GNU (System V, also Windows `.lib`) keeps long names in a `//` member;
  BSD and macOS keep a long name at the start of the member's data (`#1/N`).
  `ArchiveInfo.extra["ar.dialect"]` is `"gnu"` or `"bsd"`, and absent for an archive with no
  members. `ArchiveInfo.format_version` is `None`: ar has no versions.
- The symbol table (`/`, `/SYM64/`, `__.SYMDEF`) is the linker's index, not a file. It is not
  listed, and `ArchiveInfo.extra["ar.symbol_table"]` says whether there was one. During a
  streaming pass both keys say what the walk has seen so far, and are final once it ends.
- macOS ar pads each member with newlines so the next header starts on 8 bytes, and counts the
  padding in the member's size. The padding is then part of the member, as llvm-ar and bsdtar
  extract it.
- A blank time, owner or mode field is `None`.
- A thin archive (`!<thin>`) only names files kept outside it, and raises
  `UnsupportedFeatureError`.
- The long-name table may be no larger than `ListingLimits.max_metadata_bytes`.

## Debian packages

- **Needs:** what the package's two tars are compressed with: nothing for xz, gzip, bzip2 and
  LZMA, which `dpkg-deb` also accepts, and what a `.zst` file needs for Zstandard.
- **Listing:** what `dpkg-deb -R` unpacks: the files the package installs under their own names,
  and the control files (`control`, `md5sums`, the maintainer scripts) under `DEBIAN/`. The
  listing starts with the control files, then `.`, the data tar's root, then the data files.
  Listing reads both tars, so it needs decompression.
- **Reading members:** solid: a member is reached by reading the package from the start, as in a
  compressed TAR.
- **From a pipe:** yes, with `streaming=True`.
- `format=ArchiveFormat.AR` lists the package's three ar members instead (`debian-binary`,
  `control.tar.xz`, `data.tar.xz`), to read a tar whole.
- `ArchiveInfo.format_version` is the `debian-binary` version (`"2.0"`), and
  `ArchiveInfo.extra` has `deb.package`, `deb.version` and `deb.architecture`, from the control
  file. They appear once the listing or iteration has read the control tar, on any source:
  `info.extra` is empty right after `open_archive`, until `members()` or the first members of
  `stream_members()`.
- Each file that `DEBIAN/md5sums` lists gets its MD5 in `member.hashes`, and a full read checks
  it: a file that does not match raises `CorruptionError`. A line of `md5sums` that is not an
  MD5 and a name is skipped, and a file it does not list has no digest.
- As `dpkg-deb` does, a package whose format version is not 2.x raises `UnsupportedFeatureError`,
  members whose names start with `_` (a signature, for example) are skipped, any other member
  before the data tar raises `CorruptionError`, and nothing after the data tar is read.
- A file of the data tar that would land in `DEBIAN/`, whatever its spelling, raises
  `CorruptionError`, and so does a symlink or hard link of the data tar that points there, or a
  file that reaches `DEBIAN/` through such a symlink. A later symlink that makes an earlier one
  point there (`x -> y/DEBIAN/control`, then `y -> .`) raises it too, and so does a symlink whose
  target reaches `DEBIAN/` once its `..` are taken literally (`x -> y/../DEBIAN/control`). The
  control files are always the control tar's.
- So that this holds whichever members you extract and whatever `overwrite` says, a data file
  under a data symlink (`y -> a/b`, then `y/z`) raises `CorruptionError`, and so does a data
  symlink at the path of a directory or of another symlink. Packages built by `dpkg-deb` have
  neither. A hard link to a data symlink is checked as the symlink extraction writes for it.
- Following one data symlink through another, and checking earlier symlinks again when a later
  symlink moves them, count against `ListingLimits.max_members`, one per path step, and raise
  `ResourceLimitError` past it. A symlink that follows no other costs nothing.
- The control file and `md5sums` are held whole while the package is read, and together may be
  no larger than `ListingLimits.max_metadata_bytes`.

## RPM

- **Needs:** nothing for gzip, bzip2, xz and LZMA payloads; a Zstandard payload (Fedora's
  default) needs what a `.zst` file needs.
- **Listing:** from the package header alone. Nothing is decompressed until you read a
  member's data.
- **Reading members:** solid: one compression stream holds every file, so opening a member
  out of order decodes the files before it again. Members are listed in the order `rpm`
  writes their data (hard-linked files last), so `stream_members()` and `extract_all` read
  the payload once, front to back. A package with an uncompressed payload, which `rpmbuild`
  writes only when asked, is not solid.
- **From a pipe:** yes, with `streaming=True`.
- Members are named as `rpm2cpio | cpio -i` extracts them: `usr/bin/tool` for the package's
  `/usr/bin/tool`, which is the member's `raw_name`. A source package's names are relative.
- Each member's type, mode, size, time and owner names come from the package header, as `rpm`
  installs them. Owners are names (`uname`, `gname`); `uid` and `gid` are `None`.
- Both payload forms read: newc CPIO, and the stripped form of RPM 6 packages and of RPM 4
  packages with a file of 4 GiB or more.
- The package header's own digests (SHA-256 and SHA-1, each one the package stores) are
  checked when the package is opened: a damaged name, mode, owner or link target raises
  `CorruptionError`. They detect damage, not tampering: they are not signed, and signatures
  are not checked. A package that stores no such digest is read unchecked.
- Each regular file's digest from the header (SHA-256 in current packages, MD5 in old ones)
  is checked as its data is read.
- `%ghost` files are listed in the package but never stored, and are not members.
- A symlink's target comes from the header, as `rpm` installs it. The payload stores the
  target again; when a read of a later file passes that copy and it differs,
  `MEMBER_HEADER_AMBIGUOUS` is reported for the link, which `STRICT` raises.
  `rpm2cpio | cpio` would make the payload's target.
- **Hard links.** Files that share an inode are one file. The package stores the data with
  the last of them, so archivey lists that one as the `FILE` and the others after it as
  `HARDLINK` members to it.
- `ArchiveInfo.format_version` is `"6"` for an RPM 6 package, `"4"` for an RPM 4 one, and
  `"3"` for an old header with no immutable region. `ArchiveInfo.extra` holds `rpm.name`,
  `rpm.version`, `rpm.release`, `rpm.arch`, `rpm.epoch` (when set), `rpm.source`,
  `rpm.signed` and `rpm.payload_compressor`. Signatures are reported, not checked: use
  `rpm -K` for that.
- Delta RPMs, and payloads compressed with something archivey cannot decode, raise
  `UnsupportedFeatureError`. Damage to the payload is found only when a member's data is
  read, since listing never reads it. A file the payload lacks raises `CorruptionError` when
  its data is read, and the files after it still read. A payload whose structure is damaged
  (an entry that does not parse, a file the header does not list, a size other than the
  header's) raises `CorruptionError` for the file being read and every file after it.

## makeself

A makeself archive is a `.run` installer: a shell script that unpacks the TARs stored after it.
NVIDIA's Linux drivers, VirtualBox extension packs and many vendor SDKs are shipped this way.
Archivey reads the TARs and never runs the script.

- **Needs:** nothing for gzip, bzip2, xz and uncompressed payloads; a Zstandard, LZ4, lzop or
  bzip3 payload needs what the same `.tar.zst`, `.tar.lz4`, `.tar.lzo` or `.tar.bz3` needs;
  an `--ssl-encrypt` payload needs `cryptography`.
- **Listing:** needs decompression. The members are the TAR's, named as makeself extracts them
  into its target folder.
- **Reading members:** solid.
- **From a pipe:** yes, with `streaming=True`.
- Archives from makeself 2.2.0 and later are read. They are found by their first two lines,
  whatever the file's name.
- **Several payloads.** makeself 2.2.0 to 2.4.0 add a TAR to the archive at each `--append`.
  Archivey lists each TAR's members after the previous one's, as makeself extracts them.
- **Checksums.** The header stores a CRC, an MD5 and, with `--sha256`, a SHA-256 of each
  payload. Archivey checks each one it finds when it reads to the end of the payload. They cover
  every file of the payload, so a match raises each to `Verification.CHECKSUM`, and a mismatch
  raises `CorruptionError` and makes `verify_all()` return each file of the payload.
- **Encryption.** A payload written with `--base64` is read. One written with `--ssl-encrypt`
  is read with `password=` and needs `cryptography`, as AES in a ZIP does. Without a password,
  opening the archive raises `EncryptionError`, and with a wrong one it raises `EncryptionError`
  saying the password is wrong. One written with `--gpg-encrypt` raises
  `UnsupportedFeatureError`.
- `ArchiveInfo.format_version` is the makeself version the header names (`"2.4.5"`).
  `ArchiveInfo.extra` holds `makeself.label`, `makeself.script` (the command run after
  extraction), `makeself.target_dir`, `makeself.compression` (`"gzip"`, `"xz"`, `"none"`, …),
  `makeself.encryption` (when there is one: `"base64"`, `"openssl"` or `"gpg"`),
  `makeself.payloads` and `makeself.signed` (the header has a gpg signature, which is not
  checked).
- `format=TAR_GZ` (or any other format) on a makeself archive fails as on any file that is not
  one, and the error says the file is a makeself archive.
- A header archivey cannot parse raises `CorruptionError`. Archivey weighs the header against
  `max_metadata_bytes` as it reads it, at open, and refuses a header that lists more payloads
  than `max_members`: either raises `ResourceLimitError`.

## Disk images

A UDIF image (`.dmg`) is recognised by its `koly` block, in its last 512 bytes, or its first 12 when
an old image puts the block at the start, and refused with `UnsupportedFeatureError`. A compressed
image stores its blocks as zlib, bzip2 or xz, so without this check, opening one would extract the
first block and treat the rest as trailing bytes. To get at the files, convert or mount the image
first (for example with `7z x`, `dmg2img`, or `hdiutil attach` on macOS).

- An uncompressed image whose disk is an ISO 9660 filesystem is read as that ISO: `CD001` at byte
  32 769 is checked first.
- The end is read from a file, an in-memory stream, an fsspec `OpenFile` (one more range request),
  and a stored ZIP entry or uncompressed TAR member opened with `seekable_members=True`.
- A pipe is not rewound to read the end. A short image from a pipe is still refused, because
  detection has already read through to its end. A longer one whose first block is bzip2 or xz
  opens as that stream. One whose first block is zlib fails with `FormatDetectionError`, because no
  content probe runs on a source with no name.

## Directory

- **Needs:** nothing. A filesystem tree is read as a pseudo-archive, with the same API, for tests
  and for code that handles directories and archives alike.
- **Listing:** walks the tree.
- **Reading members:** the same defaults as an archive: forward-only streams and one live stream,
  until you pass `seekable_members=True` or `concurrent_operations=True`.
- Hardlinks are listed as tar lists them. When several names inside the root share one file, the first
  name the walk reaches is a `FILE`, and each later name is a `HARDLINK` to it, with `size` `None`.
  The walk visits a directory's files by name, then its subdirectories, so which name keeps the
  data is fixed. With `streaming=True`, extracting a later name whose first name a filter left out
  fails, as for a streamed tar.
- Names come from the filesystem, so `encoding=` has no effect, and passing it reports
  `ENCODING_ARGUMENT_UNUSED`.
- Files on Linux's `/proc` and `/sys` filesystems report a size that isn't their content's
  (0 or 4096), so they are listed with `size` `None` and read to the end.

## Single-file compressors

- **Needs:** gzip, bzip2, xz, lzip, LZMA Alone, zlib, `.Z`, `.lzo` and `.sz` are in core (`.Z` with
  archivey's own LZW decoder). Zstandard is in core on Python 3.14 and later, and needs
  `[recommended]` before. LZ4, mozlz4 and Brotli need `[recommended]`. `.lzo`, the format `lzop`
  writes, decodes LZO1X with the `compress-utils` package, which `[recommended]` installs on CPython
  except on Intel macOS, and otherwise in Python, more than 20 times slower on text. Both refuse a
  block that ends with an end marker other than the one every LZO1X writer produces, which `lzop`
  itself accepts.
- **bzip3** (`.bz3`, the format the `bzip3` tool writes) needs `[bzip3]`, which is in neither
  `[recommended]` nor `[all]` and does not install on macOS, PyPy or Python 3.15
  ([Install](install.md#bzip3)). It decodes in a child process unless `process_isolation` is
  `NONE`. A file is a header and a run of blocks, each with its own CRC-32, which is checked as
  the block decodes. Nothing marks the end of the file: a file cut between two blocks reads
  short with no error. A cut inside the header or a block raises `TruncatedError`.
- **mozlz4** is the format Firefox keeps its session, add-on and search files in
  (`sessionstore.jsonlz4`, `search.json.mozlz4`, `recovery.baklz4`, `addonStartup.json.lz4`):
  one LZ4 block behind a `mozLz40` header that stores the decoded size. archivey finds it by that
  header, whatever the extension, so `addonStartup.json.lz4` reads as mozlz4, not LZ4. The block
  has no checksum, and it decodes only when the whole file has arrived, so the first byte from a
  pipe waits for the end of the input. The decoded size must match the header, or the read raises
  `CorruptionError`.
- **Snappy** (`.sz`) is Snappy's framing format, which `snzip`, python-snappy and the Snappy
  libraries write: chunks of at most 64 KiB, each with a CRC-32C of its decoded data, checked before
  the data is returned. With no other package installed, archivey decodes it and checks the CRC in
  Python, at about 10 MB/s. When `cramjam` or `compress-utils` is installed it decodes the raw
  blocks, and `google-crc32c` or `crc32c` computes the CRC; either kind alone reaches about 20 to 25
  MB/s, and both kinds together several hundred MB/s. `[recommended]` installs `compress-utils`
  (except on Intel macOS) and `google-crc32c` on CPython; `cramjam` and `crc32c` are in no extra.
  Which packages are installed changes only the speed: a block a package refuses is decoded again in
  Python, which decides. With `process_isolation=NATIVE_DECODERS` the packages run in a child
  process. Nothing marks the end of the file, so a file cut between two chunks reads short with no
  error; a cut inside a chunk raises `TruncatedError`. Hadoop's `.snappy` files and raw Snappy
  blocks have no signature, and archivey does not read them.
- **uuencode and base64** compress nothing, but they wrap a file as text the way a compressor
  wraps it, so archivey peels them the same way: `files.tar.uu` lists the tar.
  - **uuencode** (`.uu`, `.uue`): a `begin 644 name` line, encoded lines, then `end`; the
    `begin-base64` variant (`uuencode -m`) ends at `====`. A file is recognised by its `begin`
    line at the start, whatever its name. With a `.uu` or `.uue` name, text before `begin` (a
    mail or news post) is skipped, up to 64 KiB. A line over 4 096 bytes, before `begin` or
    after it, is an error. Only the first file is read, and text after its end line is
    reported as `ARCHIVE_TRAILING_DATA`. The stored name is
    `extra["uu.original_filename"]` and `raw_name`, and the stored mode is `mode`; the member
    keeps the name it gets from the file's own name, so the stored name never picks a path.
  - **base64** (`.b64`, `.base64`): bare base64 text, in lines of one length or one long line,
    with or without `=` padding. Base64 has no signature, and plain text is often made of base64
    characters, so without such a name a file is taken as base64 only when its first lines are
    of one length and decode to the start of a format archivey knows (a pasted ZIP, gzip or tar).
    Line breaks are skipped; any other character, a space included, is an error.
  - Neither is found by a signature, so a source recognised from its contents alone is reported
    as `PROBABLE`, not `CERTAIN`.
  - Neither has a checksum, so a damaged character changes the output with no error unless it is
    not a valid character. A missing `end` or `====` line raises `TruncatedError`.
- **Listing:** one synthetic member, named from the source path, or `data` for a source with no
  name. `.jsonlz4` and `.baklz4` become `.json` and `.bak` (`sessionstore.jsonlz4` holds
  `sessionstore.json`). `encoding=` has no effect, and passing it reports `ENCODING_ARGUMENT_UNUSED`.
- **Reading:** forward only, until you pass `seekable_members=True`
  ([Seeking inside a member](reading.md#seeking-inside-a-member)). `archivey.open_stream(...)`
  follows the same rule: not seekable unless `seekable=True`. `.Z` decodes forward from a pipe, and
  its CLEAR codes give seek points when the source can seek.
- **From a pipe:** yes, with the waits [below](#from-a-pipe-held-open).

### Size and stored values

- **`size` arrives with the first full read** when listing left it `None`: always for `.gz`,
  `.bz2`, `.zz`, `.br`, `.zst`, `.lz4`, `.bz3` and `.Z` (a zstd or LZ4 frame's content-size field is not
  used), and for `.xz`, `.lz` and `.lzma` when their size is absent or out of reach (an `.xz` from a
  pipe, an `.lzma` written with an unknown size). A read that reaches the end, having returned every
  byte from the start, which the decoder finishes without error, sets `member.size` on the member
  `members()` returned. Seeking back is fine, and so is seeking forward on these codecs: the seek
  decodes the bytes it skips anyway, and they count. A read that stops early or raises leaves it
  `None`, as does a copy made with `replace()`. The filled size is only as good as the codec's end
  check: for a `.Z` (no end marker or checksum) or an accelerated `.gz` (below), a cut the decoder
  cannot see fills in the size of the cut data. `member_state_final` reads `False` until the size
  is filled in, a `streaming=True` pass ends, or the reader closes.
- **`.xz` size and `.lz` CRC-32** come from the stream's index or the lzip trailer whenever the
  source can seek: a file path, an in-memory stream and an fsspec `OpenFile` (one more range
  request) qualify, a pipe does not. One exception, from an fsspec `OpenFile` only: a file of
  several `.xz` streams or `.lz` members reads only the last one's index or trailer, sees the
  earlier ones and stops, so `size` is `None` and the `.lz` CRC is absent. Walking every
  stream would cost the open a step per stream, and a read from the start never needs it.
  The same file from a path reports both. The same holds for a `.xz` from an `OpenFile` whose
  last 64 KiB are stream padding (zeros): the open does not scan back over it. A seek in that member still works: it walks the
  index then.
  `seekable_members=True` makes no difference, since reading the trailer is a bounded backward peek
  at open. A `.xz` or `.lz` opened from another archive's member stream gets both when the
  member stream is seekable and is a stored ZIP entry or an uncompressed TAR member, whose end is
  as cheap to reach as a file's. From a deflated member, a member of a compressed TAR whose decoder
  cannot resume near it, a member that cannot seek, or a standard-library `GzipFile`, `BZ2File`,
  `LZMAFile` or `ZipExtFile`, archivey reads neither: it does not report the CRC-32, and the size
  arrives only from a full read.
- `.gz` may expose `extra["gzip.original_filename"]` when the header carries a name (`FNAME`).
- `.lzo` exposes `extra["lzop.original_filename"]` when its header stores a name, and the
  modification time and permission bits the header stores.
- mozlz4 sets `member.size` at listing, from its header.
- `.gz` exposes `extra["gzip.isize"]`, the trailer's size field, when the file's end is cheap to
  reach (a path, an in-memory stream, an fsspec `OpenFile`, a seekable stored ZIP entry or
  uncompressed TAR member; not a
  pipe, a deflated member or a standard-library decompressor). It is the size
  modulo 2^32 only for a file of one gzip member with nothing after it. A file of several members
  stores the last member's size there (a bgzip file stores 0), so it never becomes `member.size`.
- `.gz` has no `member.hashes` entry, before or after a read. The trailer's CRC-32 covers the whole
  member only when the file holds one gzip member, and proving that at open would mean reading the
  whole file. The decoder still checks every gzip member's CRC as it reads.
- `.bz2`, `.xz`, zlib, Brotli and `.Z` have no whole-member digest that can be read without
  decoding. zlib's Adler-32 is still checked by the decompressor on read, but it is not put in
  `member.hashes`, because with possible concatenation or trailing bytes the end of the stream
  cannot be found from its fields.

### Checks on the data

- **No checksum:** Brotli, `.Z` and LZMA Alone files have none, so damaged data can decode to wrong
  bytes with no error. A `.zst` frame has one only when its writer adds it, as a modern `.lz4`
  frame usually does; archivey checks it when it is there. The legacy LZ4 format (`lz4 -l`, used
  for Linux kernel images) is read as `.lz4` and has no checksum either. Archivey does not report a
  diagnostic on each such file, because there is no check to skip.
- **No end mark:** a `.Z` file, a `.bz3` file and a legacy LZ4 file can be cut between two blocks and read short
  with no error. `.Z` truncation is best effort: leftover bits that are not zero after the last
  complete code raise `TruncatedError` on the next `read()` after the bytes that could be decoded;
  a cut that leaves no such bits goes unnoticed.
- **`open_archive` decodes the first byte** of a seekable source, so a file that is not the codec
  its name or detection claims (a `.gz` full of zeros, an empty `.bz2`) raises `CorruptionError` or
  `TruncatedError` from `open_archive` rather than from the first read. A valid empty stream still
  opens and is read as `b""`. The check goes one byte deep: damage further in still fails on the read.
  It costs one decoded block, which is noticeable only for `.bz2` (up to 900 KB of output; about
  30 ms on incompressible data). A pipe is checked at open only when archivey detected the
  format and read all of it while doing so (a short stream whose sender closed the pipe, and no
  `format=` given): the check then decodes a copy, so it gives the same answer as a file. Any
  other pipe isn't, because the check would consume bytes of its one pass; it fails on the
  first read instead.
- **A header the format's own tool calls unsupported** raises `UnsupportedFeatureError`, not
  `CorruptionError`: a gzip member with a method other than Deflate or a reserved flag bit set, an
  LZ4 frame in a version other than `01`, a zstd frame that needs a dictionary, and a `.Z` file
  with a code width over 16 bits. A damaged byte in one of those fields raises the same error,
  because nothing tells the two apart; the message says a damaged header reads the same way
  ([Damaged archives](errors-and-diagnostics.md#damaged-archives)).
- `.lz` is read in lzip format version 1, which every lzip since 1.0 writes. A member in version 0
  (lzip before 1.0) or a later version raises `UnsupportedFeatureError`, wherever it is in the
  file: a member that starts with the `LZIP` magic is never skipped as trailing bytes.

### Bytes after the compressed stream

Bytes after the stream (a signature or checksum appended to a download, a tool that pads its
output) do not stop the read. For gzip, zlib, bzip2, xz, lzip, LZMA Alone, Zstandard, LZ4 and
Brotli, archivey returns the whole payload, then reports one `ARCHIVE_TRAILING_DATA` whose
`observed_bytes` is the offset of the first appended byte
([Bytes after the end of an archive](#bytes-after-the-end-of-an-archive)). Under `STRICT`, the
read that reaches it raises `DiagnosticRaisedError`. The same check runs on a compressed tar.

- A second stream of the same codec (a concatenated `.gz`, `.bz2`, `.lzma`, `.zst` or `.lz4`) is
  more data, not trailing bytes.
- For every codec but `.xz`, zero bytes are padding only at the end of the file: a stream after
  them is reported as trailing bytes and not read, as GNU `gzip`, `bzip2`, `zstd` and `lz4` do.
  `.xz` defines padding between streams and reads past it.
- For `.xz`, `.lz`, `.zst`, `.lz4` and `.bz2`, bytes after a stream that hold at least half of the
  codec's magic, but not all of it, are a later stream with a damaged header: the read raises
  `CorruptionError` rather than return the first stream alone.
- `.xz` and `.lz` keep their size and seeks when the appended bytes are within 1 MiB, unless they
  are crafted to hold thousands of fake end markers. Further out, the index is not found and the
  size is reported as unknown. A damaged end marker on the last of several `.xz` streams or `.lz` members
  is corruption, not appended bytes: the size is reported as unknown, and the read or seek that reaches
  the damage raises `CorruptionError`.
- Brotli has no end marker the library reports, so archivey finds the end by decoding the source
  again, which needs a source that can seek. From a pipe, bytes after a Brotli stream raise
  `CorruptionError`, and how much data comes before that error depends on how the bytes arrive.
- `.Z` is not covered: it has no end marker, so appended bytes decode as more data.
- `.bz3` is not covered either: bytes after the last block are read as the next block, and
  raise `CorruptionError`, or `TruncatedError` when fewer than 8 bytes follow. A second `.bz3`
  file after the first raises `CorruptionError`, as the `bzip3` tool refuses it.

### From a pipe held open

A compressed file or a compressed tar from a pipe that the sender keeps open is decompressed from
what has arrived: a compressed tar opens and yields its members, and a read returns the data whose
compressed bytes have arrived. It waits for the sender to close the pipe in these places:

- `open_archive` of a short file, because archivey reads a fixed amount from the start before it
  decides:
    - Under 258 bytes. A tar header starts at offset 257, and until that byte has arrived the file
      could still be a tar, even a `.gz` whose first two bytes say gzip. A few files up to 261 bytes
      wait too, when their bytes from offset 257 spell the start of a tar header.
    - A `.gz` under 512 bytes, whose first 512 bytes are read for the stored name.
    - A `.bz2` or `.xz` under 4 KiB, and a `.tar.bz2` or `.tar.xz` too. These are checked for a
      disk image, which needs the length of the file.
    - A file that decompresses to under 512 bytes, the size of a tar header.
- A read past the last byte of data, and the end of a compressed tar's listing, since another
  stream or trailing bytes could still follow.

bzip2 and bzip3 are the exceptions to decoding what has arrived: they decompress nothing until a
whole block has arrived (up to 900 KB of original data for bzip2, 16 MiB by default for bzip3), at
any file size, so their reads wait for the end of each block. `open_archive` waits for the end of
the first block of a `.tar.bz2` or `.tar.bz3`, which it decodes for the first header, and of a
`.bz2` or `.bz3` when it detects the format, which decodes the start of the file; with `format=`,
they open at once. Close the sending side when the file is done.

### Limits and accelerators

- A `.zst` frame declares its window, and the decoder keeps that much memory.
  `DecoderLimits.max_decoder_memory` (2 GiB by default) caps it, so the 2 GiB window of
  `zstd --long=31` reading standard input reads. A window over the cap raises `ResourceLimitError`.
  The cap is rounded down to a power of two for zstd. A window over 2 GiB is beyond what libzstd
  decodes at any setting, and raises `UnsupportedFeatureError`. Detection decodes its sample with
  the window capped at 128 MiB (what `zstd -d` decodes without `--long`) or at
  `max_decoder_memory`, whichever is smaller. It does not look inside a frame over that, so a
  `.tar.zst` is reported as a bare `.zst`. When your cap is the reason, the diagnostic
  `DETECTION_DECODER_LIMITED` names it, and reading the file raises the same `ResourceLimitError`.
- A mozlz4 header declares the decoded size, and the decode holds twice that at its
  peak (the decode buffer and the copy returned). `DecoderLimits.max_decoder_memory` caps
  twice the size, and a size over the cap raises `ResourceLimitError`.
  A size larger than the block can decode to raises `CorruptionError` before anything is
  allocated, and so does a block longer than the declared size can encode to.
- A `.bz3` header declares a block size, from 65 KiB to 511 MiB, and the decoder needs about 10
  times that. `DecoderLimits.max_decoder_memory` caps it, so the 2 GiB default reads blocks up
  to about 200 MiB, the `bzip3` tool's 16 MiB default among them; a larger block size raises
  `ResourceLimitError` before the decoder is built. Each block's sizes are checked against the
  block size before the block is read. Detection does not build a decoder for blocks over
  16 MiB or wait for a first block over 1 MiB compressed: it reports the inner TAR test as
  skipped (`CAPABILITY_UNAVAILABLE`), and the file opens as a `.bz3` of one member. Pass
  `format=ArchiveFormat(ContainerFormat.TAR, StreamFormat.BZIP3)` to read such a `.tar.bz3` as
  a TAR.
- With the `[seekable]` rapidgzip accelerator on a seekable `.gz` (by default from 16 MiB, with
  `seekable_members=True`, or on Linux and macOS without it when the file compresses 3:1 or
  less), archivey adds its own checks, because rapidgzip can end a cut file with no error. If
  rapidgzip returns nothing, the standard library reads the file instead. Otherwise the trailer
  at the end of the file is checked: in a file of one gzip member, against the checksum and
  length of all the data read; in a file of several members, against the end of the data. For
  that, archivey saves the checksum every 4 MiB as it reads and reads back at most 4 MiB from
  rapidgzip per check, whatever the size of the last member. After a seek that skipped data, the
  check still runs, and also reads back the skipped part of the last member; past about 64 MiB
  of that, the standard library reads the whole file again instead, which gives the right result
  but takes longer. A wrong length in a member before the last is not caught, but every member's
  checksum still is, so the data is right. A cut file built on purpose can still read short with
  no error, if its last eight bytes are made to match the end of the data. So when you need
  certainty, set `ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)`. This applies to a bare
  `.gz` or `open_stream` (and bare zlib or raw Deflate), not to ZIP or 7z members, whose stored
  CRC and size catch short or wrong data.
- The `[seekable]` accelerator's bzip2 decoder reads input that is not bzip2 as an empty stream.
  When it yields nothing, archivey decodes the source again with the standard library, so a damaged
  `.bz2` raises the same error whether or not `seekable_members=True` engaged the accelerator.

## Detection

- **Strongest signal first**, and the file name last; wrong extensions are expected. In order:
  exact magic in the first 4 KiB, then an SFX scan behind an executable stub, then exact magic
  further in (ISO 9660's `CD001` at 32 769, on one extended peek that a source too small for it
  never pays for), then the 512-byte `koly` block at the end of a seekable source
  ([Disk images](#disk-images)), then a TAR header with no magic
  ([TAR](#tar-and-compressed-tar)), then content probes for the formats with no magic (next
  item), then the same 2 MiB scan for a ZIP, 7z or RAR behind leading bytes of any kind, then the
  extension. A bzip2 or xz header that is the first block of a disk image loses
  to its `koly` block. A step that matches nothing falls through to the next; nothing is rejected for
  failing an earlier one. When only the extension matched and the decode then fails, the error has
  `format_unconfirmed=True`, and archivey reports `EXTENSION_FORMAT_UNCONFIRMED`.
- **Content probes run only for a matching name by default.** LZMA Alone, zlib and Brotli have no
  magic, so a trial decode of the first bytes (a content probe) is the only thing that recognises
  them, and ordinary binary files sometimes pass one. By default `open_archive` and `detect_format`
  run a probe only when the name ends in one of that format's extensions: `.lzma` or `.tlz` for LZMA
  Alone, `.zz` or `.zlib` for zlib, `.br` or `.brotli` for Brotli, and the `.tar.` form of each
  except `.tlz`. A matching probe confirms the name and still finds a TAR inside. A source with no
  name, or another extension, runs no probe: a raw stream of these formats with no name raises
  `FormatDetectionError`, and one named for another format gets that format's guess. To read such
  sources, give the file its format's extension, pass `format=`, use `open_stream()` (which always
  runs every probe), or set `ArchiveyConfig(always_probe_content=True)` (`--probe-content` on the
  command line). No probe runs on a file that starts with a valid executable header or an OLE (old
  Office) header, even when it is named for one of these formats.
- **Brotli** detection adds framing checks to the probe when the source length is known (paths,
  `BytesIO`, and short non-seekable peeks): a first meta-block that declares more bytes than the
  source holds is rejected; when the source is 64 KiB or less, the whole of it is decoded, and a
  stream that still wants more input after a declared output drain is rejected; and a bounded walk
  of self-describing meta-blocks rejects a later link that overruns, or a declared end with bytes
  after it. On a non-seekable stream of unknown length those checks are skipped. When the decoded
  start is a TAR header, the format is `tar.br` with confidence `PROBABLE`. Otherwise, without a
  Brotli extension, the confidence is `PROBABLE` when the first meta-block is compressed and `GUESS`
  when it is not, and a later decode failure sets `ArchiveyError.format_unconfirmed` and reports
  `PROBE_FORMAT_UNCONFIRMED`: the bytes may never have been Brotli, and some made-up output may
  already have been returned before the error. A `tar.br` found this way is not flagged. With a
  Brotli extension (`.br`, `.brotli`, `.tar.br`) it is `PROBABLE`.
- **zstd skippable frames** (a magic from `0x184D2A50` to `0x184D2A5F` plus a declared payload
  size) may come before the first real frame, so detection walks past them by their declared sizes
  within the bytes it peeked, and matches the regular frame behind. Skippable frames alone are not
  a zstd claim: there is nothing to open.
- **zlib** is recognised by the RFC 1950 header rules (`CM == 8`, `CINFO <= 7`, and the mod-31
  check, `FDICT` included) rather than a list of common headers, so all seven legal window sizes are
  recognised. A preset dictionary archivey does not hold fails the decode, and detection moves on.
- **LZMA Alone** accepts any 32-bit dictionary size, zero included: the format allows every value,
  and decoders round anything below 4 KiB up to 4 KiB. It does not claim a header declaring an
  uncompressed size of exactly zero: that stream holds no payload, and 18 zero bytes are a valid
  empty one, so zero padding would otherwise be detected as `.lzma`. A real size and the all-ones
  "unknown" value are both accepted, and an empty `.lzma` still opens through its extension.
- **Self-extracting (SFX) stubs** are detected when the archive sits behind an executable header
  (Windows `MZ`/PE, Linux ELF, or a macOS Mach-O header that parses) or a `#!` launcher line (a
  zipapp `.pyz`, a Spring Boot jar). The 2 MiB scan behind the stub reports where the archive starts
  as `payload_offset`, and sets `prefixed`. For a code-signed Windows program, `payload_end` is
  where its signature starts: the ZIP, 7z, RAR, LHA and ARJ readers stop there, so the signature is not
  reported as data after the archive. Some installers (Squirrel's, used by GitHub Desktop, Slack
  and Discord) store the archive as a resource inside the program instead of after it. When the
  archive ends inside a resource, the ZIP, 7z and RAR readers stop the trailing-data check at the
  resource's end: other resources, sections and the signature follow it and are not reported.
  Bytes inside the resource after the archive still are. A ZIP further into a Windows installer than the scan
  reaches is found from its end, when the program's header shows that something was
  appended past the window. A launcher is text, so behind `#!` only formats with a structural check
  (ZIP, 7z, RAR, LHA, ARJ) are searched for, and so are gzip, bzip2, xz, zstd, LZ4 and lzip
  streams whose header fields pass their checks: a CPack `.sh` installer, or another shell
  installer, is a script followed by a compressed TAR. That stream is reported as the TAR inside
  it (`TAR_GZ`), or as the bare stream (`GZ`) when it holds nothing archivey recognizes, and is
  read from where it starts, from a pipe too. An uncompressed TAR behind a script is not found,
  and `format=TAR_GZ` on such a script fails, as on any file that does not start with the
  stream. Behind a Windows, Linux or macOS program whose header says
  where its own image ends, an archive that starts exactly there is taken first, ahead of
  anything else in the window. That holds under every detection budget: a smaller one, such as
  `FAST`, still looks there, with a seek. Read from a pipe, under a budget whose window ends before
  that point, detection gives up instead (`FormatDetectionError` when nothing else names the
  format), because answering from the program image could open a different archive. Raise
  `max_scan_bytes`, or pass `format=`. Otherwise,
  among several 7z candidates, one that ends exactly at the end of
  the file is preferred over an earlier one that ends short of it.
- **An archive behind any leading bytes** (an image, zeros, text) is found too, as 7-Zip, `unrar`
  and `unzip` find it: when no other step matched, the same 2 MiB scan runs without an executable
  cue, for ZIP, 7z, RAR, LHA and ARJ, each with its structural check (LHA's is its header sum or
  CRC, ARJ's its main header's CRC-32; a DOS `.COM`, Amiga or Atari self-extractor has no
  executable header to cue on). It is the last content step, so a file
  archivey recognizes pays nothing for it; a file it does not recognize pays a read of up to 2 MiB.
  On a source that cannot seek and whose length is not known yet, such as a pipe, the scan covers
  only the bytes detection has already read, and `sfx_scan` is listed in `unavailable_tiers` as
  `CAPABILITY_UNAVAILABLE`.
  A file whose name has a known extension skips it and gets the extension's guess; the ZIP, 7z,
  RAR, LHA and ARJ readers find an archive behind leading bytes themselves.
- **Ties go to the earlier step, then to registration order.** Detection stops at the first step
  that matches, and within a step the first backend registered wins. A file that is two formats at
  once (a polyglot) gets one fixed answer; pass `format=` to read it as the other.
- **`confidence` may change in 0.2.x**: what each step reports may be regraded later (a two-byte
  magic such as gzip's reported below `CERTAIN`, say). Branch on `format`, not on `confidence`.
  **`detected_by` is an open set**: new detection steps may add values, so handle an unknown one
  rather than matching every value.
- `detect_format` returns the confidence and evidence on `FormatInfo`; the
  [API reference](api.md#detection-budgets) lists what detection may read.

## What archivey does not do

- **Change an archive in place.** Archivey reads archives and extracts them. It does not add,
  remove or replace members in an existing archive, and it doesn't write archives yet.
- **Offer an async API.** The API is synchronous, and an async one is not planned before 1.0. In
  async code, run archivey calls in a worker thread, for example with `asyncio.to_thread`.
- **Make backups.** Archivey reads the members and metadata a backup tool needs, but it is not a
  backup engine by itself.
