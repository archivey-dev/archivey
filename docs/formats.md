# Formats and extras

What each format can do, what it needs installed, and what most often surprises callers. The
first sections cover what holds across formats; then each format has a section of its own, in
the same order: what it needs, how it lists and reads, and its quirks.

The maintainer handbook has more depth on
[7z](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/7z.md),
[ISO](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/iso.md),
[ar](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/ar.md),
[RAR](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rar.md),
[TAR](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/tar.md) and
[ZIP](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zip.md), and on the single-file
compressors: what they share in
[single-file.md](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/single-file.md), then
[gzip](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/gzip.md),
[bzip2](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/bzip2.md), [xz, lzip and LZMA
Alone](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xz.md), [zstd and
LZ4](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zstd-lz4.md),
[Brotli](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/brotli.md) and
[`.Z`](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/unix-compress.md), and on [disk
images](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/dmg.md) and
[directories](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/directory.md).

## Quick matrix

"Core" means a plain `pip install archivey`, with no dependencies. *Listing* is what
`archive.cost.listing_cost` reports, and *members* is its `access_cost`: direct, or solid when
reaching a member means decompressing others first ([Solid archives](reading.md#solid-archives)).

- **ZIP:** core; `[recommended]` adds Deflate64, PPMd, WinZip AES, and Zstandard before Python
  3.14. Listing: from its index; from a pipe, header by header. Members: direct. Reads from a pipe.
- **TAR:** core. Listing: header by header. Members: direct. Reads from a pipe.
- **Compressed TAR** (`.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.lz`, `.tar.lzma`, `.tar.zz`,
  `.tar.Z`, `.tar.zst`, `.tar.lz4`, `.tar.br`): needs what its compressor needs (below).
  Listing: needs decompression. Members: solid. Reads from a pipe.
- **7z:** core for LZMA, LZMA2, Deflate, BZip2, Delta and the executable filters (BCJ, BCJ2,
  ARM64, RISC-V and the others); `[recommended]` adds PPMd, Deflate64, Brotli, LZ4, AES, and Zstandard
  before Python 3.14. Listing: from its index. Members: solid, unless written without solid
  blocks (`7z -ms=off`). Needs a source that can seek.
- **RAR:** listing and uncompressed members in core; compressed members need the `unrar`
  program ([below](#the-program-for-rar)); `[recommended]` adds encrypted headers and
  uncompressed encrypted members in one part. Listing: header by header. Members: solid when the archive is
  solid, otherwise direct. Needs a source that can seek.
- **ISO 9660:** `[recommended]` (`pycdlib`). Listing: from its index. Members: direct. Needs a
  source that can seek.
- **ar** (`.a`, `.lib`, the outer layer of a `.deb`): core. Listing: header by header. Members:
  direct. Reads from a pipe. Inside any compressor TAR reads inside (`.a.gz`, …), as a
  compressed TAR is: listing needs decompression, members are solid.
- **Directory:** core. Listing: walks the tree. Members: direct.
- **Single compressed files:** gzip, bzip2, xz, lzip, LZMA Alone, zlib and `.Z` in core;
  Zstandard in core on Python 3.14 and later, otherwise `[recommended]`; LZ4 and Brotli need
  `[recommended]`. One member. Members: direct. Reads from a pipe. Seeking inside the member
  needs `seekable_members=True` ([Seeking inside a member](reading.md#seeking-inside-a-member)).
- **UDIF disk images** (`.dmg`): recognised and refused ([Disk images](#disk-images)).

[Install](install.md) lists what each extra installs. `archivey[recommended]` is the usual choice,
and `archivey[all]` adds the `[seekable]` accelerator. At run time,
[`format_availability()`](api.md#archivey.format_availability) says what the current install can
read. The [library analysis](https://github.com/archivey-dev/archivey/blob/main/dev-docs/library-analysis.md)
explains the choice of each compression library, and
[Acknowledgements](acknowledgements.md) credits them.

### The program for RAR

No pip extra can read compressed RAR data. Archivey runs RARLAB's `unrar` or `rar`, version 6.0 or
later, from `PATH`, or else The Unarchiver's `unar` 1.10 or later. Without either, RAR archives
still list, uncompressed members read, and so does an uncompressed encrypted member in one part
when `cryptography` is installed. `7z` and `unrar-free` are never used.

`ArchiveyConfig.rar_decompressor` picks the program:

```python
ArchiveyConfig(rar_decompressor="auto")   # default: unrar when found, otherwise unar
ArchiveyConfig(rar_decompressor="unrar")  # only unrar; unar is never run
ArchiveyConfig(rar_decompressor="unar")   # only unar
ArchiveyConfig(rar_decompressor="none")   # run no program
```

`unar` reads less than `unrar`, and it takes the password on its command line, where other users
on the machine can see it ([`unar` instead of `unrar`](#unar-instead-of-unrar)).
`format_availability("rar")` reports `PARTIAL`, with `unrar` in `missing`, when no RARLAB program
of 6.0 or later is found, even when a usable `unar` is installed.
[Getting unrar](install.md#getting-unrar) says how to install it.

## Member fields across formats

### The `extra` bags

`ArchiveMember.extra` is a [`MemberExtra`](api.md#members-and-archive-details) and
`ArchiveInfo.extra` is an [`ArchiveInfoExtra`](api.md#members-and-archive-details). Both are
`dict[str, object]` subclasses, and both names are importable. Reading a known key
(`extra["zip.compress_type"]`) gives that key's type to a type checker, and an unknown key (from a
third party, or added later) stays legal and reads as `object`. `.get()` returns `object` for
every key. The `EXTRA_*` constants in `archivey.types` name the keys that have constants.

Writes are not type-checked: a value of the wrong type for a known key is accepted, as an unknown
key is. To replace a bag, assign a `MemberExtra(...)` or `ArchiveInfoExtra(...)` rather than a bare
dict. Changing the existing bag in place works as before.

The format sections below mention a key only when it is part of that format's behaviour. The full
list is on the two classes.

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
  as `None` ([Archives from macOS](#archives-from-macos)), until a checked full read fills it in.
  From a pipe, `size`, `compressed_size` and the CRC-32 in `hashes` of a member whose sizes come
  after its data, until the pass gets past its data. Also from a pipe, until the pass reads the
  index, every field only the index holds: `type`, `name` (where a DOS host makes `\` a separator),
  `mode`, `create_system`, `comment`, and the times and owner ids from its extra fields.
- **TAR, 7z, RAR, ISO:** `is_current` and `link_target_member`.
- **Directory:** `link_target_member`. Names never repeat, so `is_current` never changes.
- **Single compressed files:** `size`, when the format records none. A full read fills it in, and
  the flag stays `False` until then ([Single-file compressors](#single-file-compressors)).

A symlink whose target archivey has not read yet (`read_link_targets=False`) can also change:

- **ZIP and 7z:** `link_target`. A Windows reparse point whose data is not a link becomes a `FILE`.
- **RAR:** `link_target`, in RAR 4 only.
- **TAR, ISO, directory, single compressed files:** nothing. The header, Rock Ridge or the
  filesystem gives the target with the entry.

`members()`, `members_report()` and `get()` return members that read `True`, except unread
symlinks, and single-file or large macOS ZIP members whose `size` a full read has not filled in
yet. Members read `False` until a call like those, or the end of a pass, has resolved the
listing's links. A `streaming=True` pass yields every member before that, in every format. A
`members_report_if_available()` peek resolves no links, so its members read `False` until a later
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
- **TAR, ar, directory, and every other single compressed file:** none.

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

TAR, ZIP, 7z, RAR and ISO archives, and single compressed files, all check for bytes after the
archive's end. A non-zero byte there is reported as `ARCHIVE_TRAILING_DATA`, with the format in
`format`: a warning under the default policy, raised under `DiagnosticPolicy.STRICT`. Zero bytes
are padding and pass. ZIP, TAR, 7z, RAR and ISO look at most 1 MiB past the end, so a byte
further out goes unseen. Each format section says where its end is.

Inside a ZIP or 7z member, bytes after the compressed stream are corruption, not trailing bytes
([ZIP](#zip)).

### Device files, FIFOs and sockets

A ZIP, 7z, RAR or ISO entry whose mode is a device, FIFO or socket, or a TAR entry whose typeflag
is a device or FIFO (TAR has no socket type), lists as `MemberType.OTHER` when it stores no data. Extraction does not create it: its result is
`BLOCKED`, and the other members are extracted. `extra["special_file_type"]` names the kind. In ZIP, 7z, RAR and ISO, such
an entry that does store data is a `FILE`, with `MEMBER_SPECIAL_FILE_HAS_DATA` reported. Each
section for ZIP, 7z, RAR and ISO says when its mode is trusted; TAR reads the typeflag instead
([TAR](#tar-and-compressed-tar)).

### Names with an unpaired surrogate

A UTF-16 name (in 7z, in RAR 1.5-4, and in Joliet on an ISO) can hold a surrogate without its
partner, which NTFS allows. Archivey keeps that code unit in `member.name` (`'hi\ud800'`) and
lists every member, as 7-Zip does. The CLI shows the name escaped, as `hi\ud800`.
`member.raw_name` always holds the stored units.

Under the `STRICT` and `STANDARD` extraction policies, extraction escapes the surrogate's UTF-8
bytes as it escapes any name that is not portable: `hi\ud800` is written `hi%ED%A0%80` on every
OS, and `presented_name` holds the stored name. Under `TRUSTED` it writes what 7-Zip writes. On
Linux and other POSIX systems that is the three-byte UTF-8 form, `hi` followed by `ed a0 80`; a
filesystem that accepts only valid UTF-8, such as APFS, refuses those bytes, and the member fails
with `ExtractionError`. On Windows it is the exact name. One exception: a unit from U+DC80 to
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

- **Needs:** nothing for stored, Deflate, BZip2, LZMA and XZ members, the PKZIP 1.x methods Shrink
  and Implode, or ZipCrypto. `[recommended]`
  adds Deflate64 and PPMd (`inflate64`, `pyppmd`, the packages the 7z reader uses too), WinZip AES
  (`cryptography`), and Zstandard before Python 3.14 (`backports.zstd`). A missing package raises
  `PackageNotInstalledError` when you read such a member.
- **Listing:** archivey's own parser reads the central directory, the index at the end of the
  file. Stdlib `zipfile` is not used.
- **From a pipe:** with `streaming=True`, header by header ([below](#zip-from-a-pipe)).

### ZIP from a pipe

The pass finds each member by its local header, and reads the central directory after the last
one. A member is yielded with what its local header says. Until the pass reaches the directory, a
member's `mode`, `create_system`, `comment`, `uid` and `gid` are `None`, and a symlink is a `FILE`.
Then every member is updated in place, and `member_state_final` turns `True`.

A member whose sizes come after its data (general-purpose bit 3, which every writer to a pipe sets)
is yielded with `size`, `compressed_size` and its CRC-32 unknown. Its data descriptor fills them in
once the pass gets past its data.

Extraction keeps each member's data in a private `.archivey-tmp-` folder inside the destination,
and puts the members in place only once the pass has read the directory. It calls your `filter`
once on each member as the directory describes it, so the files on disk match a read from a file.
A member the directory does not list (an appended update, a planted entry) is still yielded when
the pass meets it. When the pass reaches the directory, that member is dropped from the listing and
reported as `ARCHIVE_UNLISTED_DATA`, and extraction does not keep it.

What a pipe cannot read:

- A bit-3 member compressed with LZMA without an end marker raises `UnsupportedFeatureError`,
  since nothing marks its end.
- A bit-3 PPMd member is fed to the decoder in pieces, since its size isn't known in advance.
- A directory written with a data descriptor gets no stream for the data it declares: its size
  comes after its data, so the pass cannot know the bytes are there, and the message says so.
- With several candidate passwords, a member is confirmed on its first 1 MiB. When more than one
  candidate is still possible after that, the first one is used.

Where a pipe and a file differ, on damaged archives or ones no writer produces:

- A data descriptor that disagrees with the central directory, or a local header the directory
  contradicts, makes the pass raise `CorruptionError` for that member once it reaches the
  directory. A read from a file reads it.
- Two members with the same name whose directory order reverses their order in the file list and
  stream as from a file. Extraction raises `CorruptionError` for that name, where extraction from
  a file writes the copy the directory lists last.
- A member whose local header holds a name the safety checks refuse fails extraction, even when
  the directory or your `filter` gives it a safe name, since its data was not kept.

From a pipe, the pass reads to the end of the stream after the last member, so a sender that keeps
the connection open after the ZIP ends makes the pass wait for the end of the stream. The members
are final only then. When the sizes come after each member's data, the wait also comes in the read
that ends the last member's data. A ZIP under 258 bytes waits at `open_archive` too: a tar header
starts at offset 257, and until that byte has arrived the file could still be a tar. Close the
sending side when the ZIP is done.

### Damaged and unusual endings

- **The end record is missing** (a download cut short): the members the local headers hold are
  listed, without the mode, host or comment that only the directory has. Then the listing raises
  `TruncatedError`, or `CorruptionError` when other bytes stand where the directory should be.
- **The central directory is damaged partway:** the members before the damage are listed, then the
  ones the local headers hold after it, and then the listing raises `CorruptionError`.
  `members_report()` gives you both ([Damaged archives](errors-and-diagnostics.md#damaged-archives)).
- **A ZIP64 end record is damaged:** archivey reads past it when the plain end record holds every
  value itself and the directory's end can be found, and reports `ARCHIVE_EOF_MARKER_MISSING`.
  Otherwise it lists the members the local headers hold, then raises `CorruptionError`.
- **The end record disagrees with the directory**, on the entry count or with an archive comment
  length past the end of the file: the members still list and read, and
  `ARCHIVE_EOF_MARKER_MISSING` is reported after the directory's last entry. From a file, the
  listing is complete before any member is handed out, so `DiagnosticPolicy.STRICT` raises before
  the first one. With `streaming=True`, the pass yields every member and then raises.
- **Bytes after the end record and its comment** are `ARCHIVE_TRAILING_DATA`
  ([Bytes after the end of an archive](#bytes-after-the-end-of-an-archive)).
- **The local header disagrees with the directory on the name, or stores a real CRC-32 where the
  directory stores 0:** the member is read, from a file and a pipe alike, as `unzip` reads it. The
  directory's name is used and `MEMBER_LOCAL_NAME_DIFFERS` is reported, which `STRICT` refuses. The
  data is checked against the local CRC-32 and `MEMBER_LOCAL_CRC_USED` is reported, which `STRICT`
  reads: Adobe AIR packages store `META-INF/AIR/hash` this way.
- **The local header names another compression method than the directory:** the member is
  decoded by the local header's method, from a file and a pipe alike. The local header sits next to
  the data and is all a pipe has, so both reads give the same bytes, still checked against the
  CRC-32. `MEMBER_LOCAL_METHOD_DIFFERS` is reported, which `STRICT` refuses, since a tool that
  trusts the directory reads the member differently. The member's `compression` still names the
  directory's method, as the listing comes from the directory; the diagnostic gives both. WinZip
  AES in the directory only is refused with `CorruptionError` from a file and `EncryptionError`
  from a pipe, where the local header alone says how the data is encrypted. WinZip AES in the
  local header only is refused with `CorruptionError` from both, from a pipe once the pass
  reaches the directory. WinZip AES in both headers with AES records that differ (version, key
  strength or method), or with one header's record missing, is refused with `CorruptionError`
  from a file. A pipe decrypts by the local record and refuses it too: where that decryption
  fails, with the error it meets (`EncryptionError` for another key strength), and where it
  succeeds, once the pass reaches the directory.
- **Both headers declare less than the data decodes to:** the member is refused with
  `CorruptionError`.
- **Bytes after a member's compressed stream:** a member's compressed data must hold its codec's
  data and nothing else, as 7-Zip checks. For most methods that is one stream. For Zstandard and
  XZ it is what their own formats define as the data, as in a `.zst` or `.xz` file: one or more
  Zstandard frames, or one or more xz streams with stream padding (groups of four zero bytes)
  between and after them. Junk, other zero bytes, or a second DEFLATE or BZip2 stream raise
  `CorruptionError` once the data before them has been read, for every method, whatever the
  declared size and CRC cover. So does an LZMA member without an end marker, or a PPMd member,
  whose declared size stops short of its data. One zero byte after LZMA data without an end
  marker reads, because 7-Zip's encoder sometimes writes it. Under ZipCrypto these read as the
  password-or-damage `EncryptionError` instead, caused by that `CorruptionError`, because the
  bytes are encrypted. With rapidgzip, one crafted shape may read instead: a long
  second DEFLATE stream, with a size and CRC that cover both streams. See
  [Where the guarantees stop](security.md#where-the-guarantees-stop).
- `ListingLimits.max_members` is checked at open against the entry count the end record declares,
  and again as the directory is read, in `stream_members()` too. From a pipe it is checked as the
  pass meets each local header, and again on the directory's entries.

### Archives from macOS

- **A ZIP over 4 GiB that macOS wrote without ZIP64** reads. Finder's Compress (Archive Utility,
  `ditto -c -k`) stores every offset past 4 GiB with its top bits cut off, so 7-Zip and Python's
  `zipfile` fail on such an archive. Archivey adds back the missing multiple of 4 GiB where an
  offset falls below the end of the members before it, but only when a local header with the
  member's name is at the corrected offset. The member's CRC-32 is still checked. Each correction
  reports `ARCHIVE_OFFSET_WRAPPED`, which `STRICT` does not raise on, since macOS writes such
  archives by default.
- A single member over 4 GiB has its sizes cut too. For entries carrying Archive Utility's marks,
  archivey corrects them with `MEMBER_SIZE_WRAPPED`: the compressed size from where the data really
  ends, and the size from that where Deflate's ratio leaves only one value (members under about
  4 MB compressed).
- **Archive Utility stores each member's size modulo 4 GiB**, so for a deflated member over about
  4 MB compressed, the listing cannot tell whether the size passed 4 GiB. This happens in a Mac ZIP
  of any length. Such a member lists `size=None`, with the stored value in
  `extra["size_mod_2_32"]` and `MEMBER_SIZE_WRAPPED` reported. A read to the end, checked against
  that value and the CRC-32, fills in `size`; the key stays.
- Finder and `ditto` add `__MACOSX/` sidecar files
  ([macOS sidecar files](#macos-sidecar-files)).

### Split and spanned sets

- A set split by 7-Zip's `-v` (`name.zip.001` to `name.zip.00N`) opens from any part, when every
  part is in the same directory. The parts are byte slices of one ordinary ZIP, and archivey joins
  them. A missing part raises `TruncatedError`.
- A spanned set written by `zip -s` (`.z01` to `.zip`) addresses its entries by disk number, and is
  refused with `UnsupportedFeatureError`. Join it with the tool that made it.

### Compression methods

- A method archivey cannot read lists normally, and reading the member raises
  `UnsupportedFeatureError`. So does an LZMA member with `lc + lp` over 4 (which 7-Zip writes with
  `-mm=LZMA:lc=8` and liblzma cannot decode), and a PPMd member with restore method 2. Under
  ZipCrypto both read as the password-or-damage `EncryptionError` instead, because those settings
  are encrypted.
- "Version needed to extract" never refuses a member: only a method or encryption archivey cannot
  read does.

### Encryption

- Encrypted members decode every compression method an unencrypted one does.
- **ZipCrypto** checks a password against one byte, so a wrong one passes about one time in 256.
  Its data then fails the CRC or the decompressor, and archivey raises `EncryptionError` saying the
  password may be wrong or the member damaged, since a damaged member read with the right password
  fails the same way. Decryption is pure Python and slow (a few MiB/s). A ZipCrypto member can seek,
  but a backward seek decrypts it again from the start. Confirming one of several passwords can be
  expensive on a stored member.
- **WinZip AES** (method 99, AE-1 and AE-2) needs `[recommended]`. Without it, an AES member is
  still listed as encrypted, and reading it raises `PackageNotInstalledError`. An AE-2 member has
  no CRC-32 in `hashes`: its HMAC checks the data. A failing HMAC raises `CorruptionError`, with one
  password or several: a wrong password gets past the two-byte check only once in 65 536 tries, so
  damage is by far the likelier cause.
- **PKWARE Strong Encryption** is not supported. Such members list as encrypted, and opening one
  raises `UnsupportedFeatureError`. An archive whose central directory is itself encrypted this way
  cannot be listed: archivey raises `UnsupportedFeatureError` when it recognises the layout, and
  `CorruptionError` otherwise.
- Both password checks admit some wrong passwords, so the CRC or HMAC at the end of the member is
  the real test. With several candidate passwords, each one that passes is checked further before
  it is used. Closing a member stream before its end reports `ENCRYPTED_MEMBER_UNVERIFIED` when
  only the short check accepted the password.

### Names and comments

- **Names flagged UTF-8** (general-purpose bit 11) decode as UTF-8 when the stored bytes are valid
  UTF-8.
- **Unflagged names** should be cp437, but many tools write UTF-8 without setting the flag. So
  archivey uses UTF-8 when the bytes are valid UTF-8, and otherwise the `encoding=` you passed to
  `open_archive`, or without one `ArchiveyConfig.zip_unflagged_fallback_encoding` (default
  `cp437`). When UTF-8 is inferred for an unflagged name, `member_name_encoding_inferred` records
  it, and `STRICT` refuses it. So `encoding=` decodes only the unflagged names that are not valid
  UTF-8, unlike `metadata_encoding` in Python's `zipfile` or `unzip -O`, which apply to every
  unflagged name.
- **A wrongly set UTF-8 flag is ignored.** When bit 11 claims UTF-8 but the bytes are not valid
  UTF-8, the name decodes as an unflagged name that is not UTF-8 does. A
  `member_name_encoding_inferred` diagnostic names the encoding used, with
  `declared_encoding="utf-8"`, and `STRICT` refuses the archive. `raw_name` keeps the stored bytes.
- **An Info-ZIP Unicode Path extra field** (`0x7075`) whose checksum matches the stored bytes
  outranks the guess and names the member in UTF-8. `raw_name` is then the field's UTF-8 bytes, and
  `extra["alternate_raw_name"]` holds the stored ones. A malformed field (too short, or matching
  with an empty, cut-short or non-UTF-8 name) is dropped with a `member_header_record_skipped`
  diagnostic, and the archive opens on every Python version. Python 3.12's `zipfile` refuses a
  too-short field or a non-UTF-8 name.
- **Comments** decode the same way. A member comment follows its name's flag (a flag the name's
  bytes refute counts as unset for the comment too), and the archive comment, which has no flag,
  decodes as an unflagged name. A byte the chosen encoding does not define stays in the comment as
  a surrogate escape, as in a name. An Info-ZIP Unicode Comment field (`0x6375`) whose checksum
  matches the stored comment gives a member comment whose bit 11 is clear in UTF-8, by the Unicode
  Path field's rules, as 7-Zip reads it.

### Times, owners and extra fields

- Times start from the DOS fields, then NTFS, then the Unix fields (`0x000d`, `0x5855`), then the
  Extended Timestamp field when present. The Unix fields are read as unzip 6.00 reads them. macOS
  `ditto` and Archive Utility write only `0x5855`, so their archives list `modified` and `accessed`
  in UTC.
- Owner ids: Info-ZIP `zip` on Unix records `uid` and `gid`, read as unzip 6.00 reads them.
  `uname` and `gname` stay `None`, and Windows writers store no owner.
- Extra fields archivey takes nothing from (a vendor's own, or a known one found malformed) stay
  readable as `extra["zip.extra_fields"]`, as `{tag: data}`.

### Member types

- A Unix mode is read only when "version made by" says Unix. A device, FIFO or socket follows
  [the shared rule](#device-files-fifos-and-sockets); `zip -FI` stores a named pipe's content as
  data, which makes it a `FILE`.
- **A directory entry that declares data** (APPNOTE gives a directory none) lists as a directory
  with that size, and `MEMBER_DIRECTORY_DATA_IGNORED` is reported; `STRICT` refuses the archive.
  Extraction creates the directory, as unzip and 7-Zip do. `read()` returns the bytes, checked
  against the stored CRC-32, and so does the stream `stream_members()` yields for it. A CRC of 0,
  the usual value for a directory, is no digest: when it was the entry's only check (unencrypted or
  ZipCrypto), `DIGEST_UNVERIFIABLE` says the bytes come back unchecked. A WinZip AES entry has its
  HMAC check them, so nothing is reported. A directory that declares size 0 over a body larger than
  an empty one of its method is reported too (`read()` has nothing to return for it). The Java
  `jar` tool's deflated empty directory body (compressed size 2, size 0) is not.

## TAR (and compressed TAR)

- **Needs:** nothing for a plain `.tar`. A compressed TAR needs what its compressor needs
  ([Single-file compressors](#single-file-compressors)).
- **Listing:** archivey parses the headers itself, the same way on every Python version.
- **Old tars with no magic:** a v7 tar (`tar --format=v7`, old bsdtar or star) has no `ustar`
  signature. archivey recognises it by its first header's checksum, from a file, a pipe or a
  `BytesIO`, with or without a `.tar` name, and inside a compressor (a gzipped one is `TAR_GZ`).
  It is reported as `PROBABLE`, not `CERTAIN`.
- **Reading members:** a plain TAR from a file reads each member straight from its place. A
  compressed TAR is solid: reaching a member means decompressing everything before it, so a
  single `stream_members()` pass is the fast way to read it.
- **From a pipe:** yes. The listing reads up to 1 MiB past the end-of-archive blocks, so a sender
  that keeps the connection open after the tar ends makes the listing wait for more bytes or for
  the end of the stream. Close the sending side when the tar is done. A compressed TAR from a held
  pipe can also wait at open ([Single-file compressors](#from-a-pipe-held-open)).
- With `concurrent_operations=True`, member reads share one file handle and take turns on it, so
  reads from several threads are safe but not parallel. ISO works the same way.
- Hardlinks are extracted as hardlinks. An `extract_all` with no filter resolves them in one pass.
- A tar from macOS `tar` can hold `._name` sidecar files
  ([macOS sidecar files](#macos-sidecar-files)).

### How the archive ends

A tar has no member count, so a damaged header after the first one could pass for the end of the
archive and shorten the listing without an error. Archivey checks how the archive ends:

- **A header that does not parse** where the walk stops raises `CorruptionError`, whatever the
  diagnostic policy, because a well-formed tar never ends that way. This holds in random-access and
  streaming reads, whatever follows the bad header: more members, nothing, or a block of zeros.
- **A clean end on a member boundary without the two zero blocks** is reported as
  `ARCHIVE_EOF_MARKER_MISSING`, not raised. A tar written without them, tars joined with `cat`, and
  a tar cut exactly at a member boundary look the same. When you need a listing proven complete,
  set that code to `RAISE` in the diagnostic policy (`DiagnosticPolicy.STRICT` does), which turns
  it into `DiagnosticRaisedError`.
- **A first zero block followed by a block that is not zero** is reported the same way, with
  `context.expected_marker="second_zero_block"`. The zero block ends the members, so every member
  is listed and reads normally, as GNU tar ("A lone zero block") and 7-Zip list them; `STRICT`
  raises it. The trailing-bytes check then starts from the block after the damaged one. At least
  one member must come before the zero block: a file that is only a zero block and other bytes is
  not shown to be a TAR, and raises `CorruptionError`.
- **Bytes after the end** are `ARCHIVE_TRAILING_DATA` (trailing junk, or a second archive joined
  on; [Bytes after the end of an archive](#bytes-after-the-end-of-an-archive)). Zero padding passes
  because `tar` writes 10 KiB records, so "nothing but zeros" is the strictest rule that does not
  flag what `tar` itself writes. On a compressed tar, the 1 MiB checked is decompressed to inspect
  it, and bytes after the compressed stream itself are reported the same way, with the codec's name
  as `format` ([Single-file compressors](#single-file-compressors)).
- **Truncation inside a member's data** always raises `TruncatedError`, whatever the policy: in a
  listing or a pass when the walk reaches the cut, and from a member stream on the read that
  reaches it. A read with a size returns the bytes before the cut first; `read()` with no size
  raises and returns nothing.

On a compressed tar, the stream's own checksum adds three cases:

- A stream cut inside its footer (a missing gzip CRC-32, say) does not fail the listing, since
  every member was read whole, but its checksum was never checked. That is `DIGEST_UNVERIFIABLE`,
  which `STRICT` refuses.
- A stream that fails to decompress past the end-of-archive blocks is `DIGEST_UNVERIFIABLE` too,
  worded as "whether the checksum passed cannot be told": the failing bytes may be another
  compressed member after the one holding the tar.
- The check stops at trailing bytes, and says nothing about the stream's checksum past them. In a
  concatenated `.tar.gz` they are a second gzip member, and the first one's checksum was already
  checked. Junk inside the same gzip member can leave that checksum unchecked, so treat
  `ARCHIVE_TRAILING_DATA` on a compressed tar as "the members may not have been checked" too.

### Headers that declare data they should not have

- **A device or FIFO header with data** (typeflag `3`, `4` or `6` with a non-zero size) raises
  `CorruptionError` at that header, before the end-of-archive checks run. Such an entry has no data,
  and GNU tar skips the header as damaged. Reading on from the next block, an all-zero payload would
  look like the end of the archive and drop every member after it.
- **A directory header (typeflag `5`) with data** has no data area either, so the next header is
  read straight after it. When that header parses, the directory lists with no size, as GNU tar,
  bsdtar and 7-Zip list it. When the walk ends instead on a zero block inside the declared span,
  the directory lists with no size and `MEMBER_DIRECTORY_DATA_IGNORED` is reported (`STRICT`
  refuses the archive). The declared blocks, if they are there, were read as the end-of-archive
  marker, and the members behind them are not listed, as GNU tar does. Nothing in the file tells
  that from an end marker after blocks that were never written, so the report says what the header
  declares, and the end checks above report the rest. `open()` refuses the directory, and
  `stream_members()` yields no stream for it, since its bytes cannot be told from the end marker. A
  block that is neither a header nor zero where the data would begin raises `CorruptionError`
  naming the directory header. A walk that gets past the declared span (extended headers filled it)
  has read all it could hide, and nothing is reported.
- **An old-style directory with data:** a regular-file header (typeflag NUL, `0` or contiguous `7`)
  whose name ends in `/` is a directory, as GNU tar reads it; 7-Zip agrees for NUL and `0`. When
  its size is not zero, the directory keeps that `size` and `MEMBER_DIRECTORY_DATA_IGNORED` is
  reported. Extraction creates the directory and skips the blocks, as GNU tar does, and `read()` on
  the directory returns them, as does the stream `stream_members()` yields for it, in both access
  modes. `STRICT` refuses the archive.
- **A symlink or hard link header (typeflag `2` or `1`) with data** has no data area either. When
  a member header follows it at once, the size names no data, and the link lists with nothing
  reported, as GNU tar and `tarfile` read it. Otherwise the declared blocks are skipped, so a zero
  block among them does not end the archive, and `MEMBER_LINK_DATA_IGNORED` reports the link
  (`STRICT` refuses the archive). GNU tar and `tarfile` skip nothing and stop at such a zero block,
  dropping the later members. When the declared blocks are all zeros and no member header follows
  them, they are also the end marker of a link whose blocks were never written: the end checks then
  read them as the end marker, as after a file, so an intact one gets no warning, and the link is
  reported the same way. Extraction creates the link.

### Member types and fields

- A device or FIFO follows [the shared rule](#device-files-fifos-and-sockets). A device keeps its
  numbers in `extra["tar.devmajor"]` and `extra["tar.devminor"]`. A device number field that is not
  a number is dropped and reported as `MEMBER_HEADER_RECORD_SKIPPED`, as GNU tar lists such a
  device too.
- **A member of an unknown type is a file when it has data.** A header whose type byte archivey
  does not know (such as `9`) and that declares data is a `FILE` of that size, which reads and
  extracts like any file, as GNU tar extracts it. One that declares no data is `OTHER`, and its
  extraction result is `BLOCKED`. Both are reported with `MEMBER_TYPE_UNKNOWN`, which `STRICT` does
  not refuse, and `extra["tar.type"]` keeps the byte.
- **Sparse members are extracted dense.** A GNU or PAX sparse member (`tar -S`) is written with its
  holes filled with zeros, so it takes its full size on disk. The zeros count as output for the
  [ratio limit](security.md#hardening), which a TAR checks across the whole archive because a
  member has no compressed size. A 10 MiB sparse file packs into a 10 KiB tar, 1024:1, and
  `extract_all`, or reading the member, raises `ResourceLimitError` against the default
  `max_ratio` of 800.
  `member.is_sparse` tells you which members are sparse before you extract. For a sparse archive
  you trust, raise the limit with
  `ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=...))`, or `max_ratio=None`.
- A PAX time record that does not parse leaves that time unset, and `MEMBER_TIMESTAMP_INVALID`
  reports it.

## 7z

- **Needs:** nothing for LZMA, LZMA2, Deflate, BZip2, Delta, stored data and the executable
  filters. `[recommended]` adds PPMd, Deflate64, Brotli, LZ4 and AES, and Zstandard before Python
  3.14 (3.14 has it in the standard library).
- **Listing:** archivey's own parser reads the header. `py7zr` is used only to check archivey in
  tests.
- **Reading members:** a solid block is decoded once by `stream_members()`. A random `open()` of a
  member in the middle of a block may decode again from the block's start.
- **From a pipe:** no. The index is at the end of the file, so `open_archive` raises
  `StreamNotSeekableError`.

### Compression methods

- **BCJ2** (which 7-Zip writes for x86 executables at `-mx9`) reads on a core install. An encrypted
  BCJ2 archive also needs AES, as any encrypted 7z does. Its decoder is pure Python, about half the
  speed of the same file under BCJ. It keeps no seek points, so a backward seek decodes again from
  the block start.
- **ARM64** (which 7-Zip 23 writes for AArch64 executables) reads on a core install. Python's
  `lzma` cannot build that filter, so archivey decodes it in pure Python. On real AArch64 code a
  read runs at roughly four fifths of the speed of the same file with no filter. The filter slows
  with branch density: on data where every word is a branch, it runs about 15 times slower than on
  real code.
- **RISC-V** (a filter 7-Zip 24 added for RISC-V executables) reads on a core install, decoded in
  pure Python like ARM64. On real RISC-V code a read runs at roughly half the speed of the same
  file with no filter. The filter slows with branch density: on data where every word is a branch,
  it runs about 15 times slower than on real code.
- Bytes after a coder's stream are corruption, as in a ZIP member ([ZIP](#damaged-and-unusual-endings)),
  except that a Zstandard or LZ4 coder reads concatenated frames as one stream, so a further frame is
  content that counts against the declared size.

### Encryption

- **AES with stored data, and neither a block digest nor a member CRC:** 7z has no password check
  value, so a wrong password can give garbage, as in 7-Zip. Archivey reports `DIGEST_UNVERIFIABLE`
  (`reason="no_integrity_anchor"`). Treat the data as unchecked.
- **Confirming a password on an encrypted block** decodes only until it can decide: the first
  member CRC covering at least 4 bytes, or 64 KiB of output for a compressed block, whose codec
  rejects a wrong key within a few bytes. Peak memory is one 64 KiB chunk. Time grows with the
  block's size only for stored-plus-AES (or PPMd) blocks whose only CRC is at the end, with several
  candidates, since nothing rejects a wrong key before that CRC. Give a single known password there
  when you can. `ExtractionLimits` do not apply to this step.
- **Partial reads after an unconfirmed password** report `ENCRYPTED_MEMBER_UNVERIFIED`. When
  confirmation stopped at its 64 KiB budget without reaching a CRC, the member's own CRC at its end
  is the only check, and a stream closed before the end skips it.
- **Encrypted headers with a wrong password:** a decoded header with no file records is rejected
  as `EncryptionError`, never returned as an empty listing. The header's CRC is what catches a
  wrong password. 7-Zip stores that CRC; `py7zr` does not, and for its archives a wrong password
  can, rarely, decode to a header that parses with members in it, and that garbage listing is
  returned.
- `NumCyclesPower` (the key derivation's cost) is capped at 24, or the `0x3F` no-hash value, as
  7-Zip clamps it. Values from 25 to 62 raise `UnsupportedFeatureError`.

### Names and comments

- **Member names** are UTF-16, so `encoding=` has no effect, and passing it reports
  `ENCODING_ARGUMENT_UNUSED`. A name can hold an
  [unpaired surrogate](#names-with-an-unpaired-surrogate).
- **The archive comment** is UTF-16 too. An unpaired surrogate stays in `ArchiveInfo.comment`, so
  be ready for it if you print the comment. Only a comment with an odd byte count raises
  `CorruptionError`.

### Endings and member types

- **Bytes after the archive's end** (its next header or its last packed stream, whichever is later)
  are `ARCHIVE_TRAILING_DATA` with `format="7z"`. Zero padding passes, although 7-Zip warns "There
  are data after the end of archive" for zeros too. A code-signed self-extracting `.exe` carries
  its signature after the archive, so it gets the warning, and `STRICT` refuses it.
- A device, FIFO or socket that 7-Zip or p7zip stored on Unix follows
  [the shared rule](#device-files-fifos-and-sockets). The mode is trusted for this only when the
  attribute's `0x8000` Unix-extension bit is set.

## RAR

- **Needs:** nothing to list, or to read an uncompressed member. `[recommended]` (`cryptography`)
  adds archives with encrypted headers, RAR 1.5-4 and RAR5 alike, and uncompressed encrypted
  members in one part (RAR 2.9 and later). Every other member needs `unrar` or `unar`
  ([The program for RAR](#the-program-for-rar)). BLAKE2sp checking needs no package.
- **Listing:** archivey's own parser reads RAR 1.5 to RAR5 headers, header by header. The one
  exception is a compressed RAR 1.5-4 comment, which the selected program decodes; without it, or
  when the decoded text fails its CRC, `comment` is `None`.
- **Reading members:** archivey reads uncompressed members itself. Everything else goes through
  the program. In a solid archive, `stream_members()` uses one `unrar p` run for the whole pass. A
  random `open()` out of order is a separate run that decodes from the start of the archive each
  time, so reading *n* members that way costs *n* full decodes. With `seekable_members=True`, a
  backward `seek()` on a compressed member costs the same: a new run from the start.
  `CostReceipt.access_cost` is `SOLID` to say so.
- **From a pipe:** no; RAR needs a source that can seek.
- Read only: archivey writes no RAR.

### Running `unrar`

- `unrar` is preferred when both `unrar` and `rar` are on `PATH`. Archivey refuses a 5.x `unrar`.
  Debian 12 and Ubuntu 22.04 package `unrar` 6.x, and Ubuntu 24.04 packages 7.00, all recent
  enough; on an older release with 5.x, build from RARLAB's source. RARLAB's RAR for macOS download
  also contains `unrar`. It is not notarized by Apple, so macOS may block it until you allow it in
  System Settings. The "UnRAR for Mac OS X 64 bit" link on the RARLAB add-ons page is a 2018 Intel
  build someone else contributed.
- `unrar` gets the password as a bare `-p`, with the secret on stdin, not in its arguments.
  `unrar` reads it as one line and would drop anything after a line break or a NUL character,
  so a password containing either raises `UnsupportedFeatureError` instead of being cut short
  ([Passwords](opening.md#passwords)).
- Archivey passes a password to `unrar` or `unar` only when the read needs it: the member is
  encrypted, the headers are, or an encrypted member comes before it in a solid archive.
- An uncompressed encrypted member split across volumes, and any member encrypted with the RAR 2.0
  cipher (archives from RAR 2.0 to 2.8), still need the program: each part of a split member has its
  own encryption record, and archivey does not implement the old cipher.
- **A stream source is copied to disk for `unrar`.** `unrar` reads only files, so a RAR opened from
  a `BytesIO` or a file object is copied whole to a temporary file (a volume set, to a temporary
  directory) on the first member read that needs the program, and removed on close. Members
  archivey reads itself are read in place and need no copy. `ArchiveyConfig.spool_limits`
  (`SpoolLimits.max_bytes`, default 1 GiB) bounds the copy: over it, the read raises
  `ResourceLimitError` before anything is written. Opening from a path avoids the copy.
- **A member read waits as long as `unrar` does.** `read()` on a RAR member stream has no time
  bound: archivey does not stop an `unrar` process that stalls. A solid archive can produce no bytes
  for a long time while `unrar` decodes the members ahead of the one you asked for, so no idle
  timeout would be safe.

### `unar` instead of `unrar`

Under `"auto"`, the program is chosen once, when the archive is opened, and a read `unar` refuses
is not retried with `unrar`. When `"auto"` picks `unar`, `archive.cost.notes` says so at open. With
`unrar` chosen, `"auto"` still reads a member that `unrar` cannot be pointed at by name with an
accepted `unar` ([Names unrar cannot select](#names-unrar-cannot-select)). With `"unrar"` or
`"unar"`, archivey never switches programs; with `"unar"` and no usable `unar`, a read raises
`PackageNotInstalledError`.

Archivey runs each `unar` once on a small RAR5 archive and does not use one that decodes it wrong,
as the Debian and Ubuntu packages before 1.10.8+ds1-10 do (Ubuntu 22.04 to 26.04 among them).
`"auto"` then treats `unar` as absent. `brew install unar` on macOS installs a version archivey
accepts.

**The password is visible to other local users.** `unar` accepts a password only on its command
line (`-p <password>`), so while it runs, any user on the same machine can read it from the process
list (`ps`, `/proc/<pid>/cmdline`). On a shared machine, install `unrar`, or set
`rar_decompressor="unrar"` so that `unar` is never used. A wrong password makes `unar` write nothing
and report success; archivey reports that as `EncryptionError`, and a RAR5 password check usually
rejects a wrong password before `unar` runs at all.

Archivey refuses these reads with `UnsupportedFeatureError` before `unar` runs, because `unar` gets
them wrong, sometimes with a success exit:

- encrypted data in a RAR 2.x-4.x archive, except an uncompressed encrypted member in one part,
  which archivey decrypts itself. RAR5 encryption is read.
- in a solid RAR 2.x-4.x archive, every compressed member after an encrypted one in the same solid
  stream. A `stream_members()` pass refuses the encrypted member and the compressed members its
  solid stream carries into, and reads the rest, those before the encrypted one included. With
  encrypted headers it refuses every member;
- a password that is not ASCII;
- a multi-volume RAR5 set with encrypted headers (Homebrew's `unar` 1.10.8 returns nothing for it);
- in a solid RAR5 archive, a member with data after an empty file, a directory or a link;
- a member compressed with the RAR 1.5 algorithm;
- an old-style volume set (`.rar`, `.r00`, ...) of more than 901 volumes: `unar` stops at `.z99`;
- a multi-volume set with data before the first volume (an SFX stub). A single file with such a
  prefix is copied to a temporary file first;
- in `stream_members()` over a solid archive that holds one of the members above, any readable
  member past the 4000th: that pass names each member it reads on the `unar` command line, which
  has a size limit. Such a member still opens on its own.

With `"none"`, archivey runs no program. Listing still works, and so does reading an uncompressed
member, also when it is split across volumes or sits in a solid archive, or when it is encrypted
and in one part (that one needs `cryptography`, and raises `PackageNotInstalledError` without it).
A compressed member, an encrypted one split across volumes, or a split one with a volume missing
raises `UnsupportedFeatureError` before anything runs, and `archive.cost.notes` says so at open.

### Names unrar cannot select

`unrar` is told which member to write with an include *mask* built from its name. Some names make
that mask select the wrong members, or none:

- **`*` or `?` in a name** also matches the member's siblings. Names like this are almost always
  constructed, so reading such a member raises `UnsupportedFeatureError`. On an archive that is not
  solid, the extra decode would also be unbounded: `ExtractionLimits` apply to extraction, not to
  `open()` or `read()`, and the error says how many bytes it would have cost. On a solid archive
  those bytes are already part of `AccessCost.SOLID`, so the error names the flag instead. Setting
  `ArchiveyConfig.rar_allow_glob_member_concatenation=True` reads it anyway. Two cases are not
  affected: a name that matches no other member (an accidental `report*.pdf` beside `report1.pdf`)
  reads with no flag, and a solid `stream_members()` pass reads everything, because it builds no
  mask at all.
- **`*` or `?` in a directory part of the name, or a backslash in it:** `unrar` cannot read the
  member, and the flag does not change that. The one exception is a backslash in a RAR5 name
  written on Windows, which `unrar` on Linux and macOS reads as `_`.
- **Several members under one name** (two members with the same name, or two names `unrar` reads
  the same way): `unrar` writes every member a name selects, in archive order, and archivey skips to
  the one you asked for, so each read returns that member's own bytes. A RAR5 name that is not valid
  UTF-8 is cut by `unrar` at its first invalid byte, and is read through that shorter name the same
  way.
- **A name `unrar` reads as empty** raises `UnsupportedFeatureError`, and so does a name `unrar`
  reads but that cannot be handed back to it as a mask.
- **A name ending in `.`, or with a `.` before a `\`:** `unrar` up to 7.30 beta 1 lets the mask
  `notes.` also select a member named `notes`, and 7.30 beta 2 does not. When that changes which
  members come before the one you asked for, archivey asks the `unrar` on `PATH` once, with a
  small test archive, which way it matches. If it gives no usable answer, the read raises
  `UnsupportedFeatureError`.
- **A non-ASCII name in an older RAR (1.5-4) archive on a system with no UTF-8 locale:** `unrar`
  reads such a name through the locale, so archivey cannot tell which bytes `unrar` sends before
  any later member, and a read of a later member raises `UnsupportedFeatureError`.
- **An unpaired surrogate in a RAR 1.5-4 name:** archivey selects the member with `?` in place of
  each such unit, and when that pattern also matches an earlier member, the read raises
  `UnsupportedFeatureError` unless you set `rar_allow_glob_member_concatenation`.

`unar` selects members by position, so none of these apply to it. Under the default `"auto"`,
archivey reads such a member with `unar` when one it accepts is installed. It does not use `unar`
when the read needs a password (`unar` takes it on its command line), when the archive is a stream
or has data before the RAR (`unar` would need its own copy of it), or when `unar` is known to
misread the archive.
`rar_decompressor="unar"` reads every member by position.

### Damage and endings

- **A RAR5 archive cut exactly between two blocks** is reported, not raised. RAR5 ends each volume
  with an end-of-archive block, so archivey lists the members before the cut and then reports
  `ARCHIVE_EOF_MARKER_MISSING` (`expected_marker="end_of_archive_block"`), which `STRICT` raises.
  RAR 1.5-4 archives may lack the end block, so a cut between their blocks lists as complete.
- **A cut inside a member's data or a header** lists the members before the cut, and the listing
  raises `TruncatedError`.
- **A damaged end-of-archive block keeps the listing.** When the block after the last member fails
  its header checksum, every member is listed and reads normally, and archivey reports
  `ARCHIVE_EOF_MARKER_MISSING` with `observed_kind="nonzero"` after them, which `STRICT` raises.
  This is what `unrar t` does: each member tests OK, then it reports one error. A damaged header
  counts as the end block only if it has an end block's shape and nothing but zeros follows it
  within 1 MiB (`rar` pads a volume cut at exactly the `-v` size with zeros). The damaged block's
  next-volume flag is not trusted, so a volume set goes on to the next volume only when a member's
  own header says its data continues there.
- **A damaged member header lists the members before it.** The members before it are listed and
  read normally, and then the listing raises `CorruptionError`. No later member of that volume is
  listed: the damaged header's size field cannot be trusted, so archivey does not know where the
  next header starts. `unrar` searches on and lists them. In a volume set, a member before the
  damage whose data continues is still followed into the next volume, whose members are listed
  before the error. A damaged main header raises `CorruptionError` at open.
- **Bytes after the end-of-archive block** are `ARCHIVE_TRAILING_DATA` with `format="rar"`, once
  for each volume that has them. Zero padding passes, because `rar` pads volumes with zeros.
  `unrar` says nothing about such bytes; 7-Zip warns "There are data after the end of archive", for
  zeros too.
- **A volume set with a volume missing lists what it has**, whether the missing volume is the
  first, one in the middle, or the last. The members whose headers are in the volumes present are
  listed, the set opens from any of them, and members wholly inside them read normally. A member
  with data in the missing volume raises `TruncatedError` when read, and so does every member past
  the gap in a solid archive. The listing then ends with `TruncatedError` naming the missing
  volumes, as for a cut file and as `unrar t` does. A later volume opened on its own by path is read
  the same way, as a set missing the rest. Opened as a stream, with no name to number it, it is
  refused with "Need first volume".
- **With encrypted headers**, telling damage from a wrong password needs the password proven
  first: by RAR5's password check value, or in RAR 1.5-4 by an encrypted header whose checksum
  matches, which in a volume set covers the later volumes too. Until then, a cut past a header's
  first 16-byte block, or a header whose checksum does not match, looks the same as a wrong
  password, so it raises `EncryptionError` ("wrong password?") at open and lists nothing, even with
  the right password. That happens inside the first encrypted header of a RAR 1.5-4 archive or
  volume set, and inside any header of a RAR5 archive whose encryption record has no password check
  value. Once the password is proven, damage is reported as above, and other damage to an encrypted
  header is `CorruptionError`.

### Encryption

- **Password lists:** RAR5 records a password check for each member, so a list is tried in order
  and the matching password is used. RAR 3-4 records none, so with several passwords archivey
  judges each by decoding the member: up to 64 KiB of `unrar` output, which a wrong password usually
  fails, and, when several passwords get that far, the whole member against its CRC. An
  uncompressed member in one part is checked by decrypting it in archivey and comparing its CRC,
  when `cryptography` is installed. The order of the list does not matter for the result, but every
  wrong password before the right one costs a decode, so putting the likely one first is faster.
- **Partial reads of RAR 3-4 encrypted data** report `ENCRYPTED_MEMBER_UNVERIFIED`. With no password
  check, only the member's CRC at its end catches a wrong password, and a wrong password can still
  produce bytes before that: always for an uncompressed member, and for some wrong passwords on a
  compressed one. Closing the stream before the end, or after a seek, skips the CRC. RAR5 members
  and archives with encrypted headers have checked the password already and never report it.
- RAR5 members with the HASHMAC flag check tweaked digests, as `unrar`'s `ConvertHashToMAC` does,
  when a password is available. The tweaked values are not in `member.hashes`.
- **Encrypted old-style comments are not decoded.** A RAR 1.5 or 2.x comment block with its
  password or salt flag set gives `comment` as `None`. No available tool writes such a comment, so
  there is nothing to test a decoder against.

### Names and comments

- RAR5 stores names as UTF-8, and RAR 1.5-4 usually as UTF-16 beside an 8-bit copy. A RAR 1.5-4
  name with only the 8-bit bytes does not say which code page they are in. Archivey tries UTF-8
  first. When the bytes are not valid UTF-8, it decodes them with `encoding=` when you pass one,
  and otherwise with cp437 for a member written on DOS or Windows (WinRAR writes the OEM code page)
  and windows-1252 for one written elsewhere. `raw_name` is always the stored bytes. `encoding=` has
  no effect on a RAR5 name.
- A RAR 1.5-4 UTF-16 name can hold an [unpaired surrogate](#names-with-an-unpaired-surrogate).
  `unrar` 7.00 on Linux extracts such a name cut at that unit, so `hi\ud800.txt` becomes `hi`.
- A RAR 1.5-4 comment is 8-bit text that does not say which code page it is in. Archivey reads it
  up to the first NUL, as UTF-8 if it is valid, otherwise with the `encoding=` you passed, and
  otherwise as windows-1252. A byte that code page does not define stays as a surrogate escape, as
  in a name. A RAR 2.9-4 comment flagged as Unicode is UTF-16LE, and an unpaired surrogate in it
  stays, as in a name. A RAR5 comment is UTF-8, and a byte in it that is not valid UTF-8 stays as a
  surrogate escape.

### Member types and fields

- **File versions (`rar -ver`):** older revisions list as names like `path;1`, with
  `extra["rar.file_version"]` and `is_current=False`; the live path is `is_current=True`.
  Extraction skips the older revisions by default.
- **Links and file copies.** A RAR5 hard link (`rar -oh`) is a `HARDLINK`. A RAR5 file copy
  (`rar -oi`, which `unrar` lists as "File reference") stores a duplicate file once and names the
  earlier member that holds the bytes. It is a `FILE` with `extra["is_file_copy"] = True`;
  `link_target` is the source's stored path and `link_target_member` the source member. Reading it
  gives the source's bytes, and extraction writes an independent file, as `unrar` does, by copying
  the source's file when it has just written it. A copy whose source is not an earlier file member
  raises `LinkTargetNotFoundError` when read. `stream_members(file_copy_streams=False)` yields `None`
  for each copy; its bytes and digests are its source's. A RAR5 redirect of a type archivey does
  not know (no RAR version writes one) is `OTHER` with no `size`, even with the directory
  flag, holds no data and is not extracted, as `unrar` skips it with "Unknown extra field".
  It is reported with `MEMBER_TYPE_UNKNOWN`. A redirect record of type 0 names no redirect,
  and the member is an ordinary file, as in `unrar`.
- **RAR 2.9-4 symlinks** store their target as member data. When that data is uncompressed and
  encrypted, archivey decrypts it while listing if you gave the password and `cryptography` is
  installed, and checks it against its CRC. Without either, `link_target` is unset, and a
  `SYMLINK_TARGET_UNAVAILABLE` diagnostic says why.
- **Compression:** method M0 is `STORED`. M1 to M5 are `CompressionAlgorithm.RAR` with `level` 1 to
  5. Any other method byte stays `UNKNOWN`, with no `level`. The unpack version is in
  `extra["rar.extract_version"]` on every member whose file header records one, stored members
  included: RAR 3 copies the `UNP_VER` byte as stored, and RAR5 reports `50`.
- **A compression version RAR does not know:** a RAR5 member whose compression version is newer
  than RAR 7's, or a RAR 1.5-4 member whose unpack version is outside 13-29, lists normally and
  raises `UnsupportedFeatureError` when read, where `unrar` says "Unknown method". An uncompressed
  member reads whatever version it declares.
- A device, FIFO or socket from a Unix host follows [the shared rule](#device-files-fifos-and-sockets).
  `rar` itself skips such files when archiving.
- **A directory entry that declares data** (`rar` never writes one) is reported with
  `MEMBER_DIRECTORY_DATA_IGNORED`, and extraction creates the directory, as `unrar` does. `read()`,
  and the stream `stream_members()` yields for the directory, return the bytes when they are stored
  and not encrypted. Compressed or encrypted directory data raises `UnsupportedFeatureError` (from
  the stream, on its first read), because `unrar` writes nothing for a directory entry.

## ISO 9660

- **Needs:** `[recommended]` (`pycdlib` 1.22 or later).
- **Listing:** from the image's directory records. The namespace is chosen automatically, Rock
  Ridge, then Joliet, then plain ISO 9660, and reported in `ArchiveInfo.extra["iso.namespace"]`.
- **Reading members:** direct. With `concurrent_operations=True`, reads share one file handle and
  take turns on it, as in TAR.
- **From a pipe:** no; an ISO needs a source that can seek.
- `ArchiveInfo.format_version` is `None`: ISO 9660 records no interchange level.
- `ArchiveInfo.comment` is the volume identifier (`-V`), decoded as a plain ISO 9660 name is:
  UTF-8 first, then `encoding=`, then escaped.

### Names

- Rock Ridge and plain ISO 9660 names, and Rock Ridge link targets, decode as UTF-8 first. Bytes
  that are not valid UTF-8 decode with `encoding=` when you pass one. Without it, a Rock Ridge name
  takes the Joliet name of the same file or directory when the image has a Joliet tree and the two
  line up, with a `member_name_encoding_inferred` diagnostic, and is escaped otherwise
  ([Names in other encodings](opening.md#names-in-other-encodings)).
- Joliet names are UTF-16 and ignore `encoding=`. They can hold an
  [unpaired surrogate](#names-with-an-unpaired-surrogate).
- Plain ISO 9660 file names lose their `;N` version suffix (and the `.` of an empty extension), and
  `extra["iso.version"]` keeps the number. When a directory holds several versions of one name, the
  highest takes the bare name, and the others list under their stored identifier (`FOO.;1`) with
  `is_current=False`, the same shape as RAR file versions. Plain directory names have no version
  and keep any `;N`.
- Two files stored with the same identifier both list, the later one current, as in ZIP and TAR.
  That includes a file and its associated file (such as the resource fork on a Mac hybrid image),
  which list as two members with one name and nothing to tell the fork apart. Entries in a directory
  list in the order of their records on the disc.

### Contents

- **zisofs** (Rock Ridge transparent compression: `mkzftree` with `genisoimage -z`, or `xorriso
  -set_filter_r --zisofs`) reads. The member lists the size its data decodes to, with
  `compression=(CompressionMethod(algo=DEFLATE),)`, and reads decoded, seeking by block. zisofs2
  (`xorriso -zisofs version_2=on -set_filter_r --zisofs /`, under the `ZF` or the `Z2` tag), and a
  zisofs entry too short to parse, list with `CompressionAlgorithm.UNKNOWN` and refuse to read with
  `UnsupportedFeatureError`.
- A file of 4 GiB or more, stored in several extents, lists and reads as one member, wherever
  its extents sit in the image. Extents that overlap each other are refused with
  `CorruptionError`.
- A bootable image lists its El Torito boot catalog (`boot.catalog`, `BOOT.CAT`) as an ordinary
  file, with the catalog's bytes as its data, as a mounted image shows it.
- A Rock Ridge device node, FIFO or socket over an empty extent follows
  [the shared rule](#device-files-fifos-and-sockets); over a non-empty extent it is a `FILE`.
- The `rr_moved` directory that holds relocated deep subtrees is not listed; those subtrees appear
  at their logical place.
- `import archivey` wraps pycdlib's Rock Ridge parser, but the wrapper acts only while archivey
  itself opens an image, so other code using pycdlib sees no change. Inside archivey, a System Use
  entry of a type pycdlib does not know is skipped, as the SUSP specification says, instead of
  failing the whole image. A malformed entry ends that record's Rock Ridge data: the member lists
  from the entries before it, with a `MEMBER_HEADER_RECORD_SKIPPED` diagnostic, and a symlink cut
  this way lists with `link_target` unset and a `SYMLINK_TARGET_UNAVAILABLE` diagnostic.
  genisoimage writes such an entry for a long symlink target (from about 400 bytes with genisoimage
  1.1.11).

### Damage and endings

- An image whose directory tree loops back on itself, in any of its trees (ISO 9660, Joliet or UDF),
  is refused at open with `CorruptionError`, even when the tree archivey lists from is intact.
  pycdlib finds the loop. No tool writes such an image; a damaged or crafted one can.
- A truncated image opens as long as its directories survive, and lists the sizes its records
  declare. A file the cut reaches reads the bytes that survive and then raises `TruncatedError`;
  files before the cut read normally. A file whose declared length cannot be recovered lists with
  `size` set to `None`. A cut that reaches the volume descriptors, path tables or directories makes
  `open_archive` raise `TruncatedError`.
- An image with UDF does not open once it is truncated at all, even when the files before the cut
  survive: `open_archive` raises `TruncatedError`, because the UDF anchor that pycdlib reads is in
  the image's last block.
- **Bytes after the image's end** are `ARCHIVE_TRAILING_DATA` with `format="iso"`. The end counts
  the partitions the image's MBR lists, and those of its GPT when the GPT's checksums match, so a
  hybrid installer image, whose EFI partition and GPT backup header sit after the ISO 9660 volume
  space, opens clean (7-Zip warns "There are data after the end of archive" on those images). A GPT
  damaged in transfer is not trusted, so the partition it lists is reported.
- Raw CD sector images (the `.bin` of a `.bin`/`.cue` pair) are recognised and refused with
  `UnsupportedFeatureError` naming the sector layout. Convert one to a plain `.iso` first (for
  example with `bchunk` or `bin2iso`).

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
- The long-name table counts against `ListingLimits.max_metadata_bytes`.

## Disk images

A UDIF image (`.dmg`) is recognised by its `koly` block, in its last 512 bytes, or its first 12 when
an old image puts the block at the start, and refused with `UnsupportedFeatureError`. A compressed
image stores its blocks as zlib, bzip2 or xz, so without this check, opening one would extract the
first block and treat the rest as trailing bytes. To get at the files, convert or mount the image
first (for example with `7z x`, `dmg2img`, or `hdiutil attach` on macOS).

- An uncompressed image whose disk is an ISO 9660 filesystem is read as that ISO: `CD001` at byte
  32 769 is checked first.
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
- Hardlinks list as a tar lists them. When several names inside the root share one file, the first
  name the walk reaches is a `FILE`, and each later name is a `HARDLINK` to it, with `size` `None`.
  The walk visits a directory's files by name, then its subdirectories, so which name keeps the
  data is fixed. With `streaming=True`, extracting a later name whose first name a filter left out
  fails, as for a streamed tar.
- Names come from the filesystem, so `encoding=` has no effect, and passing it reports
  `ENCODING_ARGUMENT_UNUSED`.

## Single-file compressors

- **Needs:** gzip, bzip2, xz, lzip, LZMA Alone, zlib and `.Z` are in core (`.Z` with archivey's own
  LZW decoder). Zstandard is in core on Python 3.14 and later, and needs `[recommended]` before.
  LZ4 and Brotli need `[recommended]`.
- **Listing:** one synthetic member, named from the source path, or `data` for a source with no
  name. `encoding=` has no effect, and passing it reports `ENCODING_ARGUMENT_UNUSED`.
- **Reading:** forward only, until you pass `seekable_members=True`
  ([Seeking inside a member](reading.md#seeking-inside-a-member)). `archivey.open_stream(...)`
  follows the same rule: not seekable unless `seekable=True`. `.Z` decodes forward from a pipe, and
  its CLEAR codes give seek points when the source can seek.
- **From a pipe:** yes, with the waits [below](#from-a-pipe-held-open).

### Size and stored values

- **`size` arrives with the first full read** when listing left it `None`: always for `.gz`,
  `.bz2`, `.zz`, `.br`, `.zst`, `.lz4` and `.Z` (a zstd or LZ4 frame's content-size field is not
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
  source can seek: a file path and an in-memory stream both qualify, a pipe does not.
  `seekable_members=True` makes no difference, since reading the trailer is a bounded backward peek
  at open. A `.xz` or `.lz` opened from another archive's member stream reads neither, seekable or
  not: it never reports the CRC-32, and its size arrives only from a full read.
- `.gz` may expose `extra["gzip.original_filename"]` when the header carries a name (`FNAME`).
- `.gz` exposes `extra["gzip.isize"]`, the trailer's size field, when the file's end is cheap to
  reach (a path or an in-memory stream; not a pipe or another archive's member). It is the size
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
  for Linux kernel images) reads as `.lz4` and has no checksum either. Archivey does not report a
  diagnostic on each such file, because there is no check to skip.
- **No end mark:** a `.Z` file, and a legacy LZ4 file, can be cut between two blocks and read short
  with no error. `.Z` truncation is best effort: leftover bits that are not zero after the last
  complete code raise `TruncatedError` on the next `read()` after the bytes that could be decoded;
  a cut that leaves no such bits goes unnoticed.
- **`open_archive` decodes the first byte** of a seekable source, so a file that is not the codec
  its name or detection claims (a `.gz` full of zeros, an empty `.bz2`) raises `CorruptionError` or
  `TruncatedError` from `open_archive` rather than from the first read. A valid empty stream still
  opens and reads as `b""`. The check goes one byte deep: damage further in still fails on the read.
  It costs one decoded block, which is noticeable only for `.bz2` (up to 900 KB of output; about
  30 ms on incompressible data). A pipe is not checked at open, because the check would consume
  bytes of its one pass; it fails on the first read instead.
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
  size reads as unknown. A damaged end marker on the last of several `.xz` streams or `.lz` members
  is corruption, not appended bytes: the size reads as unknown, and the read or seek that reaches
  the damage raises `CorruptionError`.
- Brotli has no end marker the library reports, so archivey finds the end by decoding the source
  again, which needs a source that can seek. From a pipe, bytes after a Brotli stream raise
  `CorruptionError`, and how much data comes before that error depends on how the bytes arrive.
- `.Z` is not covered: it has no end marker, so appended bytes decode as more data.

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

bzip2 is the exception to decoding what has arrived: it decompresses nothing until a whole block
has arrived (up to 900 KB of original data), at any file size, so its reads wait for the end of
each block. `open_archive` waits for the end of the first block of a `.tar.bz2`, which it decodes
for the first header, and of a `.bz2` when it detects the format, which decodes the start of the
file; with `format=`, a `.bz2` opens at once. Close the sending side when the file is done.

### Limits and accelerators

- A `.zst` frame declares its window, and the decoder keeps that much memory.
  `DecoderLimits.max_decoder_memory` (2 GiB by default) caps it, so the 2 GiB window of
  `zstd --long=31` reading standard input reads. A window over the cap raises `ResourceLimitError`.
  The cap is rounded down to a power of two for zstd. A window over 2 GiB is beyond what libzstd
  decodes at any setting, and raises `UnsupportedFeatureError`. Detection reads a sample of the
  stream with no cap, so a frame declaring 2 GiB has that much address space reserved while
  `open_archive` detects it, whatever the cap.
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
  as `payload_offset`. A launcher is text, so behind `#!` only formats with a structural check
  (ZIP, 7z, RAR) are searched for. Among several 7z candidates, one that ends exactly at the end of
  the file is preferred over an earlier one that ends short of it.
- **An archive behind any leading bytes** (an image, zeros, text) is found too, as 7-Zip, `unrar`
  and `unzip` find it: when no other step matched, the same 2 MiB scan runs without an executable
  cue, for ZIP, 7z and RAR, each with its structural check. It is the last content step, so a file
  archivey recognizes pays nothing for it; a file it does not recognize pays a read of up to 2 MiB.
  On a source that cannot seek and whose length is not known yet, such as a pipe, the scan covers
  only the bytes detection has already read, and `sfx_scan` is listed in `unavailable_tiers` as
  `CAPABILITY_UNAVAILABLE`.
  A file whose name has a known extension skips it and gets the extension's guess; the ZIP, 7z and
  RAR readers find an archive behind leading bytes themselves.
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
