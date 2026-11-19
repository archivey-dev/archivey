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
| XAR (`.xar`) | Core |
| macOS installer packages (`.pkg`, `.mpkg`, `.xip`) | Core |
| CAB (`.cab`) | Core |
| Debian packages (`.deb`, `.udeb`) | Core. Zstandard packages need `[recommended]` before Python 3.14 |
| RPM (`.rpm`) | Core. Zstandard payloads (Fedora's default) need `[recommended]` before Python 3.14 |
| makeself (`.run`) | Core. The payload needs what its compressor needs |
| LHA (`.lzh`, `.lha`), ARJ (`.arj`) | Core |
| CPIO (`.cpio`), ar (`.a`, `.lib`) | Core |
| gzip (`.gz`), bzip2 (`.bz2`), xz (`.xz`), lzip (`.lz`), LZMA Alone (`.lzma`), zlib (`.zz`), Unix compress (`.Z`), lzop (`.lzo`), Snappy (`.sz`), Apple's pbzx | Core. `[recommended]` makes `.lzo` and `.sz` faster |
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

Archivey reads the index at the end of the file, so listing is quick and every member can be read
directly.

- **Supported:** every compression method in common use, the old PKZIP ones included.
  ZipCrypto, and WinZip AES with `[recommended]`. Sets split by 7-Zip (`name.zip.001`, `.002`, …)
  or spanned by `zip -s` or WinZip (`name.z01`, `.z02`, …, `name.zip`), opened from any part when
  all parts are in one folder. Archives over 4 GiB that macOS Finder wrote without ZIP64.
- **Not supported:** WinZip's JPEG, WavPack and MP3 methods and IBM's mainframe methods. A member
  that uses one is listed normally, and reading it raises `UnsupportedFeatureError`. PKWARE Strong
  Encryption.
- **Split sets:** a missing part raises `TruncatedError`.
- **Encryption:** ZipCrypto's password check lets about one wrong password in 256 through, so a
  wrong password and a damaged member fail with the same error, and its decryption is slow, a few
  MiB/s.
- **Names:** a name not flagged as UTF-8 is still read as UTF-8 when it is valid UTF-8, because
  many tools write UTF-8 without setting the flag. Otherwise archivey uses `encoding=`, or cp437 by
  default. Unlike `zipfile`'s `metadata_encoding`, `encoding=` applies only to names that are not
  valid UTF-8.
- **Archives from macOS:** in a ZIP over 4 GiB that Finder wrote without ZIP64, which 7-Zip and
  `zipfile` can't read, a member's size can be listed as `None` until a full read fills it in.
  Finder also adds `__MACOSX/` sidecar files ([macOS sidecar files](#macos-sidecar-files)).

Damaged and unusual archives are read as far as they can be, and each problem is reported with a
diagnostic: a missing or damaged index, local headers that disagree with the index, bytes missing
from the middle, or data after a member's compressed stream. The
[ZIP handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zip.md)
describes each case and the error it raises.


## TAR (and compressed TAR)

Members of a plain `.tar` file are read directly. A compressed TAR is solid: reaching a member
means decompressing everything before it, so a single `stream_members()` pass is the fast way to
read many members. Reading one by name after listing resumes from the nearest restart point
([Seeking in compressed files](#seeking-in-compressed-files)).

- **Supported:** GNU, POSIX (pax), ustar and old v7 tars, which have no `ustar` signature and
  are recognised by their checksum. Hard links, extracted as hard links. Sparse members
  (`tar -S`). Every compressor in [Single-file compressors](#single-file-compressors).
- **Headers** are read the way GNU tar reads them, the same on every Python version. Where tools
  disagree on a member's name, link target or size, archivey gives GNU tar's answer and reports a
  diagnostic.
- **Sparse members** are extracted with their holes filled with zeros. That output
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

Archivey reads the index at the end of the file. Members are solid unless the archive was
written without solid blocks (`7z -ms=off`). A `stream_members()` pass decodes each solid block
once, and opening a member in the middle of a block may decode the block again from its start.

- **Supported:** LZMA, LZMA2, Deflate, BZip2, Delta and the executable filters, including BCJ2,
  ARM64 and RISC-V, in the core install (the filters are decoded in Python, so they're slower).
  PPMd, Deflate64, Brotli, LZ4, AES encryption, and Zstandard before Python 3.14, with
  `[recommended]`. Self-extracting `.exe` files, code-signed ones included.
- **Not supported:** LZMA with `lc + lp` over 4, which 7-Zip writes only when asked (for example
  `-mlc=8`). Such an archive can be listed, and reading its members raises
  `UnsupportedFeatureError`.
- **Encryption:** 7z stores no password check. A wrong password usually makes decompression fail,
  or else the data fails its CRC. Only a member stored without compression and without a CRC can
  come back as garbage, which archivey reports as unchecked data (`DIGEST_UNVERIFIABLE`). With
  encrypted headers, a wrong password raises `EncryptionError`.
- **Names** are stored as UTF-16, so `encoding=` has no effect.

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

- **Supported:** RAR 1.5 to RAR5, solid archives, volume sets (`.part1.rar`, or `.rar` with
  `.r00`) opened from any volume when all are in one folder, encryption (encrypted headers need
  `[recommended]`), and file versions (`rar -ver`).
- **`unar` exposes the password.** `unar` takes the password on its command line, where other
  users on the same machine can see it. On a shared machine, install `unrar`, or set
  `rar_decompressor="unrar"`. `unar` also gets some archives wrong, and archivey refuses those
  reads before running it.
- **Solid archives:** a `stream_members()` pass decodes the archive in one run. Opening members
  out of order decodes the solid stream again from its start each time.
- **Volume sets:** if a volume is missing, the members in the remaining volumes are listed, and
  reading a member with data in the missing volume raises `TruncatedError`.
- **Encryption:** RAR5 stores a password check, so a list of passwords is tried quickly. RAR 1.5-4
  doesn't, so each wrong candidate costs a decode, and putting the likely password first is faster.
- **File versions:** older revisions are listed under names like `path;1`, as `unrar`
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

Reading an ISO image needs `[recommended]` (`pycdlib`). An image can carry several name trees
over the same files. Archivey lists Rock Ridge first, then Joliet, then plain ISO 9660, and says
which in `ArchiveInfo.extra["iso.namespace"]`.

- **Supported:** Rock Ridge, Joliet and plain ISO 9660 names. zisofs compression (`mkzftree`,
  `genisoimage -z`, `xorriso --zisofs`). Files of 4 GiB or more, stored in several pieces, read as
  one member. Raw CD images (`.bin` with or without its `.cue`) in Mode 1 or Mode 2 Form 1,
  multisession discs included. Hybrid installer images, whose EFI partition sits after the ISO
  data, open without a trailing-data warning.
- **Not supported:** UDF: a DVD image that also has an ISO 9660 tree is listed from that tree,
  and a UDF-only image (such as a Blu-ray) is not recognised. zisofs2 members are listed, and
  reading one raises `UnsupportedFeatureError`. Video and audio-only CD images raise
  `UnsupportedFeatureError`.

- **Names:** Rock Ridge and plain names are read as UTF-8, then with `encoding=` when you pass
  one. Without it, a name that isn't UTF-8 takes the matching Joliet name when the image has one,
  and is escaped otherwise. Joliet names are UTF-16.
- **File versions:** the `;1` at the end of a plain or Joliet file name is dropped, and the number
  is kept in `extra["iso.version"]`. When a folder holds several versions of one name, the highest
  takes the bare name, and older ones are listed as `FOO.;1` with `is_current=False`, as RAR file
  versions are.
- **Files in other trees:** a file that only an unlisted tree holds (such as Joliet or UDF, which
  Windows and 7-Zip read) is not a member. Archivey reports it with `MEMBER_READERS_DISAGREE`.
- **Boot catalog:** a bootable image's boot catalog is listed as an ordinary file, as a mounted
  image shows it.
- **CD images:** archivey reads the session an operating system would mount, from one track file
  or one per track, with or without the `.cue`. When the sector addresses can't place a later
  session, it reads the first and reports `ARCHIVE_UNREAD_SESSION`.
- **Damage:** ISO 9660 stores no checksums, so damaged data comes back without an error. A
  truncated image still opens when its folders survive, and only the files the cut reaches raise
  `TruncatedError`. An image with UDF doesn't open once truncated, because the UDF anchor sits in
  its last block.

Archivey also refuses folder trees that loop back on themselves, survives Rock Ridge entries
`pycdlib` can't parse, and checks each CD sector's header as it reads. The details, and how
`.cue` sheets and multisession discs are read, are in the
[ISO handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/iso.md).

## SquashFS

gzip, xz, LZMA and LZO images need nothing extra. Zstandard images need `[recommended]` before
Python 3.14, and LZ4 images need `[recommended]`. Members are read directly. `ArchiveInfo.extra`
names the compressor (`"squashfs.compressor"`) and the block size (`"squashfs.block_size"`).

- **Supported:** SquashFS 4.0, written since 2009. Files, folders, symlinks, hard links, sparse
  files (`is_sparse`), and devices, FIFOs and sockets (`OTHER`).
- **Not supported:** SquashFS 3 and older, which raise `UnsupportedFeatureError`. Extended
  attributes are not read.
- **Damage:** SquashFS stores no checksums of its own. A damaged block is caught when it doesn't
  decode to its length, or when its compressor's own check fails (zlib's Adler-32, the xz CRC).

The [SquashFS
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/squashfs.md) covers
the layout and how damaged images are handled.

## XAR

The archive format written by Apple's `xar` and `bsdtar --format xar`. macOS installer packages
and `.xip` files are XAR archives too: archivey opens them as
[installer packages](#macos-installer-packages), and as XAR only with `format=ArchiveFormat.XAR`.
XAR needs nothing extra. Members are read directly, each compressed on its own.

- **Supported:** stored, gzip, bzip2, LZMA and xz data. MD5, SHA-1, SHA-224, SHA-256, SHA-384
  and SHA-512 checksums.
- **Checksums:** the index's own checksum is checked at open. Each file stores a checksum of its
  data (SHA-1 by default), which is in `member.hashes` and checked when you read the member to
  its end.
- **Names** stored as base64, as writers do for bytes that aren't UTF-8, are decoded with
  `encoding=` like names in any other format.

The [XAR handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xar.md)
covers the index, its limits, hard links, and the shapes archivey refuses.

## macOS installer packages

macOS installer packages (`.pkg`, `.mpkg`), written by Apple's `pkgbuild` and
`productbuild`, and Xcode's `.xip` archives. Each is a [XAR](#xar) archive whose payloads
are CPIO archives; archivey lists the files inside them, the way `pkgutil --expand-full`
unpacks a package. The format is `ArchiveFormat.PKG`.

- **Needs:** nothing. Payloads are gzip or pbzx (Apple's xz in chunks), read with Python's
  own modules.
- **Listing:** each `Payload` and `Scripts`, in a component package or in a component's
  folder of a product archive (`app.pkg/`), and the `Content` of a `.xip`, is listed as the
  files its CPIO holds, under a folder of its own name:
  `app.pkg/Payload/Applications/App.app/...`. `Distribution`, `PackageInfo`, `Bom` and the
  other files are listed as they are. Listing decodes every payload.
- **Reading members:** solid within a payload: reading a file decodes its payload up to it,
  and reading the files in order decodes each payload once.
- **Detection:** a XAR named `.pkg`, `.mpkg` or `.xip` is a package, and a `.xar` is not.
  Without either name, a XAR whose index lists `Distribution` or `PackageInfo`, or both
  `Content` and `Metadata`, is a package. `format=ArchiveFormat.XAR` opens a package as the
  XAR files it holds, and `FormatPolicy` allows or refuses packages as `ContainerFormat.PKG`.
- A payload's XAR checksum is checked as the listing reads it, and a payload that fails it
  raises `CorruptionError`. A payload that is not a CPIO, or whose first CPIO header cannot
  be read, is listed as the one file it is.
- A file in a payload, or a hard link's target, whose name would extract outside the
  payload's folder (`../Bom`) raises `CorruptionError`. A symlink in a payload is not
  checked at listing; extraction applies its usual link checks.

## CAB

Microsoft cabinets: Windows updates and drivers, the payloads inside many installers, and what
`makecab` and `gcab` write. Cabinets need nothing extra: MSZIP is read with Python's `zlib`, and
LZX is decoded by archivey itself, in Python, at a few megabytes a second.

- **Supported:** stored, MSZIP and LZX folders.
- **Not supported:** Quantum-compressed members are listed, and reading one raises
  `UnsupportedFeatureError`. A cabinet split across several files (`file.cab`, `file2.cab`) raises
  `UnsupportedFeatureError` at open.
- **Solid folders:** a cabinet groups its files into folders, each one compressed stream.
  Reaching a file decodes its folder from the start. Reading the files in listed order, as
  `stream_members()` does, decodes each folder once.
- **Names** are UTF-8 when valid, otherwise decoded with `encoding=`. A Japanese cabinet from
  `makecab` is usually `encoding="cp932"`. A cabinet stores paths, not folders, and `\` becomes
  `/`.
- **Checksums:** each data block stores a checksum, checked as it is read, so a member read to its
  end is checked when its blocks carry one (some writers store 0, meaning none).

Archivey also refuses a cabinet whose file table doesn't match its folders, and lists edited or
crafted cabinets in an order that decodes each folder once. The
[CAB handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cab.md) has the
details.

## LHA

LHA and LZH archives, from LHarc, LHA and their kin on DOS, the Amiga, OS/2, OS-9, the Atari ST
and Japanese PCs, and from LHa for UNIX. They need nothing extra: archivey decodes the methods
itself, in Python, at about 4 to 8 MB a second. Each member is compressed on its own and read
directly.

- **Supported:** header levels 0 to 3. Stored members and the `-lh1-`, `-lh4-` to `-lh7-`,
  `-lhx-`, `-lk7-`, `-lzs-` and `-lz5-` methods. Self-extracting programs for DOS, Windows, the
  Amiga, the Atari and the X68000 ([Self-extracting archives](#self-extracting-archives)). Mac
  files from MacLHA, read as their data fork, or their resource fork when the data fork is empty,
  as `lhasa` reads them.
- **Not supported:** `-lh2-`, `-lh3-`, `-pm1-` and `-pm2-` members. They are listed, and reading
  one raises `UnsupportedFeatureError`.
- **Checksums:** each member stores a CRC-16 of its data, checked when you read it to its end.
- **Names** are UTF-8 when valid, otherwise decoded with `encoding=`. An archive from a Japanese PC
  is usually `encoding="cp932"`.

The [LHA handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/lha.md)
covers header levels, the per-system fields, and how the MacLHA wrapper is recognised.

## ARJ

ARJ archives, from ARJ for DOS, ARJ32 and ARJ for Unix (the `arj` command on Linux). They need
nothing extra: archivey decodes methods 0 to 4 itself, in Python, at about 10 to 30 MB a second.
Each member is compressed on its own and read directly.

- **Supported:** methods 0 (stored) to 4. Self-extracting programs: ARJ's DOS `.EXE` modules and
  ARJ for Unix's ELF programs ([Self-extracting archives](#self-extracting-archives)).
- **Not supported:** garbled (password-protected) members are listed with `is_encrypted`, and
  reading one raises `UnsupportedFeatureError`, as does reading a member split across the volumes
  of a multi-volume set.
- **Checksums:** each member stores a CRC-32 of its data, checked when you read it to its end.
- **Names** are UTF-8 when valid, otherwise decoded with `encoding=`. DOS archives are usually
  `encoding="cp437"`, or `"cp866"` from Russian systems.

The [ARJ handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/arj.md)
covers the per-system fields and the ARJ-SECURITY envelope.

## CPIO

CPIO is the old Unix archive format still used inside RPM packages, Linux initramfs images and macOS
installer payloads. CPIO archives need nothing extra. Members are read directly, or inside a
compressor (`.cpio.gz`, …) one after another, as in a compressed TAR.

- **Supported:** the binary (either byte order), odc, newc and crc variants, plain or inside any
  compressor a TAR can be in. `ArchiveInfo.extra["cpio.variant"]` names the variant as GNU cpio's
  `-H` option does. In crc, each file's checksum is checked as it is read.
- **Detection:** a binary archive (GNU cpio's default) has only a 2-byte magic, so it is found
  only by a name ending in `.cpio` (or `.cpio.gz`, …), or with `format="cpio"` or
  `always_probe_content=True`.
- **Hard links:** names that share a device and inode are one file. newc and crc store the data
  with the last name, so archivey lists that name first and the others right after it as
  `HARDLINK` members.
- **Endings:** an archive cut before its trailer raises `TruncatedError`.

The [CPIO handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cpio.md)
covers afio's large headers, detection inside a compressor, and data after the trailer.

## ar

ar archives (static libraries, Windows `.lib` files) need nothing extra. Every member is a file,
read directly: ar has no folders or links.

- **Supported:** the GNU (System V, Windows `.lib`) and BSD (macOS) dialects.
  `ArchiveInfo.extra["ar.dialect"]` says which.
- **Not supported:** thin archives (`!<thin>`), which only name files kept outside them, raise
  `UnsupportedFeatureError`.
- **Symbol table:** the index a linker uses to find which member defines each symbol (`/`,
  `/SYM64/`, `__.SYMDEF`) is not listed as a member. `ArchiveInfo.extra["ar.symbol_table"]` is
  `True` when the archive has one; its contents are not read.
- **macOS padding:** macOS `ar` pads members with newlines and counts the padding in the size, so
  the padding is part of the member, as `llvm-ar` and `bsdtar` extract it.

The [ar handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/ar.md)
covers long names in each dialect and the streaming details.

## Debian packages

A `.deb` is an ar archive holding two tars: the control files and the files the package
installs. Archivey lists it as `dpkg-deb -R` unpacks it: the installed files under their own
names, and the control files (`control`, `md5sums`, the maintainer scripts) under `DEBIAN/`. xz,
gzip, bzip2 and LZMA packages need nothing extra, and Zstandard ones need `[recommended]` before
Python 3.14. Listing decompresses both tars, and members are read one after another, as in a
compressed TAR.

- **Package fields:** `ArchiveInfo.extra` has `deb.package`, `deb.version` and
  `deb.architecture` from the control file, once the listing or `stream_members()` has read it.
- **Checksums:** each file that `DEBIAN/md5sums` lists gets its MD5 in `member.hashes`, checked
  when you read it to its end.
- **The raw layout:** `format=ArchiveFormat.AR` lists the three ar members instead
  (`debian-binary`, `control.tar.xz`, `data.tar.xz`), to read a tar whole.

Archivey follows `dpkg-deb` on which members it reads, and refuses a package whose data files
or links would land in `DEBIAN/` or let one extraction write through another's symlink. The
[Debian handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/deb.md) has
the rules and their limits.

## RPM

An RPM package is a header listing every file, followed by a compressed CPIO payload. gzip,
bzip2, xz and LZMA payloads need nothing extra, and Zstandard ones (Fedora's default) need
`[recommended]` before Python 3.14.

- **Supported:** binary and source packages, RPM 3, 4 and 6.
- **Not supported:** delta RPMs, and payloads in a compression archivey can't decode, raise
  `UnsupportedFeatureError`.
- **Listing** comes from the header alone, so nothing is decompressed until you read a member.
  Members are named as `rpm2cpio | cpio -i` extracts them: `usr/bin/tool` for `/usr/bin/tool`.
- **Reading:** one compression stream holds every file. Members are listed in the order the
  payload stores them, so `stream_members()` and `extract_all()` read it once, front to back;
  opening members out of order decodes the files before them again.
- **Fields** come from the header, as `rpm` installs them. Owners are names (`uname`, `gname`),
  and `uid` and `gid` are `None`. `%ghost` files are not stored, and are not members.
  `ArchiveInfo.extra` holds `rpm.name`, `rpm.version`, `rpm.release`, `rpm.arch` and more.
- **Checksums:** the header's own digests are checked at open, and each file's digest as it is
  read. They catch damage, not tampering: signatures are not checked, so use `rpm -K` for that.

Damage to the payload is found only when a member is read, since listing never reads it. The
[RPM handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rpm.md) covers
payload forms, hard links, symlink targets and how damage is reported.

## makeself

A makeself archive is a `.run` installer: a shell script that unpacks the TARs stored after it.
NVIDIA's Linux drivers, VirtualBox extension packs and many vendor SDKs are shipped this way.
Archivey reads the TARs and never runs the script. It finds them by
the script's first lines, whatever the file is called. The payload needs what its compressor needs
(as for the same `.tar.gz`, `.tar.zst`, …). Listing decompresses it, and members are read one after
another.

- **Supported:** makeself 2.2.0 and later. Several payloads (makeself 2.2.0 to 2.4.0 add a TAR
  at each `--append`), listed in the order makeself extracts them. `--base64` payloads, and
  `--ssl-encrypt` ones with `password=` and `cryptography`.
- **Not supported:** `--gpg-encrypt` payloads raise `UnsupportedFeatureError`.
- **Checksums:** the CRC, MD5 and SHA-256 that the script stores for each payload are checked
  when the payload is read to its end. A mismatch raises `CorruptionError`.
- **Archive fields:** `ArchiveInfo.extra` holds the label, the command run after extraction
  (`makeself.script`), the target folder and the compression.

Since archivey doesn't run the script, a script that does more than unpack can leave a different
result than running the `.run` file would. The [makeself
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/makeself.md) covers
the header forms, the encryption schemes and the limits.

## Disk images

A macOS disk image (`.dmg`, UDIF) is recognised and refused with `UnsupportedFeatureError`, so it
isn't mistaken for the zlib, bzip2 or xz stream its first block happens to be. To get at the
files, convert or mount the image first, for example with `7z x`, `dmg2img`, or `hdiutil attach`
on macOS. An uncompressed image that holds an ISO 9660 filesystem is read as that ISO.

The [DMG handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/dmg.md) says
how the image is recognised.

## Directory

A folder on disk can be opened like an archive, with the same API, which helps tests and code that
handles folders and archives alike. It needs nothing extra. Member streams have the same defaults
as an archive's: forward-only, one at a time, until you pass `seekable_members=True` or
`concurrent_operations=True`.

- **Hard links:** when several names in the folder share one file, the first name the walk reaches
  is a `FILE` and the others are `HARDLINK` members to it, as `tar` lists them.
- **Names** come from the filesystem, so `encoding=` has no effect.
- **`/proc` and `/sys`** files report sizes that aren't their content's, so they are listed with
  `size` set to `None` and read to their end.

The [directory
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/directory.md) covers
the walk order and symlinks.

## Single-file compressors

A compressed file holds one file, so archivey lists it as one member, named after the source
without its compression extension (`notes.txt.gz` holds `notes.txt`, `sessionstore.jsonlz4` holds
`sessionstore.json`), or `data` for a source with no name. The [Overview](#overview) says what each
format needs. A member stream can seek only with `seekable_members=True` ([Seeking in compressed
files](#seeking-in-compressed-files)).

- **Not supported:** Hadoop's `.snappy` files and raw Snappy blocks, which have no signature,
  and lzip files from lzip before 1.0, which raise `UnsupportedFeatureError`.
- **Size:** most formats store no original size that can be read without decoding, so
  `member.size` is often `None` at listing and is filled in when a read reaches the end. `.xz` and
  `.lz` give it at open when the source can seek, and mozlz4 always does.
- **Checksums:** gzip, bzip2, xz, lzip, zlib, bzip3, lzop and Snappy files carry checksums, and so
  do the Zstandard and LZ4 files their command-line tools write. Each is checked as the data is
  read. Most cover a block or one stream rather than the whole file, so they don't appear in
  `member.hashes`. Brotli, `.Z`, LZMA Alone, mozlz4 and legacy LZ4 files have none, so damaged data
  can decode to wrong bytes with no error.
- **Cut files:** `.Z`, `.bz3`, Snappy and legacy LZ4 files have no end marker, so a file cut
  between two blocks reads short with no error. In the other formats a cut raises `TruncatedError`.
- **Concatenated files** (`cat a.gz b.gz > ab.gz`) are read as one payload in every format that
  allows it: gzip, bzip2, xz, lzip, LZMA Alone, Zstandard, LZ4 and Snappy. zlib and Brotli hold one
  stream each.
- **Bytes after the stream**, such as a signature appended to a download, don't stop the read.
  Archivey returns the whole payload, then reports `ARCHIVE_TRAILING_DATA`. `.Z` and `.bz3` have no
  end marker, so they can't tell where the data stops: `.Z` decodes appended bytes as data, and
  `.bz3` raises `CorruptionError` on them, as the `bzip3` tool does.
- **Memory:** a Zstandard window, a mozlz4 size and a bzip3 block size are declared by the file.
  `DecoderLimits.max_decoder_memory` (2 GiB by default) caps the memory they ask for, and a file
  over the cap raises `ResourceLimitError`.
- **The `[seekable]` gzip accelerator** can miss a cut made on purpose to fool it. When you need
  certainty, set `ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)`.

Some formats have more to know:

- **mozlz4** is the format Firefox keeps its session, add-on and search files in
  (`sessionstore.jsonlz4`, `search.json.mozlz4`). Archivey finds it by its header, whatever the
  extension. It decodes only once the whole file has arrived.
- **Snappy** (`.sz`) is the framing format that `snzip` and the Snappy libraries write.
- **pbzx** is Apple's framing of xz, used for the payloads of macOS installer packages. Archivey
  finds it by its `pbzx` signature.
- **lzop** (`.lzo`) and Snappy decode in Python, many times slower, unless `[recommended]` is
  installed.
- **bzip3** (`.bz3`) needs `[bzip3]`, which is in neither `[recommended]` nor `[all]` and doesn't
  install on macOS, PyPy or Python 3.15 ([Install](install.md#bzip3)).
- **uuencode and base64** compress nothing, but they wrap a file as text, so archivey peels them
  the same way: `files.tar.uu` lists the tar. A uuencoded file is found by its `begin` line, and a
  base64 one by a `.b64` or `.base64` name, or when its decoded start is a format archivey knows.
  Neither has a checksum.

The [single-file
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/single-file.md) covers
when the size arrives, how appended bytes are told apart from a damaged header, which pipe reads
wait and why, and the checks archivey adds around the accelerators.

## Detection

Archivey decides the format from the file's contents first and its name last, so a wrong extension
doesn't matter. `detect_format()` returns the answer without opening the archive
([Opening](opening.md)).

- **Magic first:** most formats start with a fixed signature, and archivey checks it before
  anything else. When only the name matched and decoding then fails, the error has
  `format_unconfirmed=True`.
- **Formats with no signature** (LZMA Alone, zlib and Brotli) can only be recognised by trying to
  decode them, and ordinary binary files sometimes pass that test. So archivey tries only when the
  name ends in one of their extensions (`.lzma`, `.zz`, `.br`, and their `.tar.` forms). To read
  one with no name or another name, pass `format=`, use `open_stream()`, or set
  `ArchiveyConfig(always_probe_content=True)`.
- **Archives behind a program or other bytes** are found too
  ([Self-extracting archives](#self-extracting-archives)).
- **A file that is two formats at once** gets one fixed answer. Pass `format=` to read it as the
  other.

The [detection
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/topics/detection.md) gives the
full order of the checks, each format's probe, and how signed and resource-packed installers are
handled.

## Reading from a pipe

A pipe, a socket or an HTTP response can be read once, from start to end, with `streaming=True`
([Reading once](reading.md#reading-once)). Whether a format can be read that way depends on where
it keeps what archivey needs.

- **Can be read from a pipe:** ZIP, TAR and compressed TAR, CPIO, ar, Debian packages, RPM,
  makeself, and every single-file compressor. RAR can too, for an archive in one volume, when
  `unrar` 7.00 or later is installed.
- **Need a source that can seek:** 7z, ISO 9660, SquashFS, XAR and macOS installer packages, CAB,
  LHA and ARJ. Opening one from a pipe raises `StreamNotSeekableError`. Copy it to a file or an
  `io.BytesIO` first.

Some formats behave differently from a pipe:

- **ZIP** keeps a member's mode, owner, comment and symlink flag only in the index at its end, so
  from a pipe they arrive when the pass gets there, and `member.member_state_final` turns `True`
  then. Extraction keeps the files in a temporary folder inside the destination until the index
  has been read.
- **TAR** reads up to 1 MiB past the end of the archive to check for trailing data, so the listing
  ends only when the sender closes the pipe.
- **Compressed files** are decoded from what has arrived. bzip2 and bzip3 decode only whole blocks
  (up to 900 kB, and 16 MiB by default), mozlz4 decodes only once the whole file has arrived, and
  `open_archive` on a file of a few KiB waits for the pipe to close. Close the sending side when
  the file is done.
- **Detection** sees only the start of a pipe. A `.dmg` isn't recognised, because its marker is at
  the end. LZMA Alone, zlib and Brotli have no name to go by, so they need `format=`. An archive
  behind other bytes is found only within the bytes that have arrived when detection runs.

## Self-extracting archives

A self-extracting archive is a program with an archive stored after it, or for some Windows
installers inside it. Archivey reads the archive and never runs the program. It finds:

- a ZIP, 7z, RAR, LHA or ARJ behind a Windows, Linux or macOS program;
- the DOS, Windows, Amiga, Atari and X68000 self-extractors of LHA, and ARJ's own;
- a ZIP, 7z, RAR, LHA or ARJ behind a `#!` launcher, such as a Python zipapp (`.pyz`), and a
  compressed TAR behind a shell-script installer, such as CMake's CPack `.sh`;
- a ZIP, 7z, RAR, LHA or ARJ behind any other bytes, such as an image, within the first 2 MiB.

`FormatInfo.prefixed` is `True`, and `payload_offset` says where the archive starts. A signed
Windows program's signature isn't reported as data after the archive. makeself `.run` installers
are their own format ([makeself](#makeself)).

The [prefixed-archives
handbook](https://github.com/archivey-dev/archivey/blob/main/dev-docs/topics/prefixed-archives.md)
covers how far the search goes and how installers that pack the archive as a resource are read.

## What archivey does not do

- **Change an archive in place.** Archivey reads archives and extracts them. It does not add,
  remove or replace members in an existing archive, and it doesn't write archives yet.
- **Offer an async API.** The API is synchronous, and an async one is not planned before 1.0. In
  async code, run archivey calls in a worker thread, for example with `asyncio.to_thread`.
- **Make backups.** Archivey reads the members and metadata a backup tool needs, but it is not a
  backup engine by itself.
