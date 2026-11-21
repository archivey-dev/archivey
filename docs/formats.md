# Formats and extras

Which formats archivey reads, what each needs installed, and what to expect when listing and
reading it. The table below lists every format and its extra. Each format then has a section
that starts with what is supported and what isn't. It ends with a link to the format's
development docs, which explain how archivey parses it, which damaged or unusual archives it
refuses and why, and where it differs from the format's own tools. The last sections cover
what holds across formats: seeking in compressed files, detection, reading from a pipe,
and self-extracting archives.

## Overview

"Core" means a plain `pip install archivey`, with no other packages. `archivey[recommended]` is
the usual choice ([Install](install.md)). At run time,
[`format_availability()`](api.md#archivey.format_availability) says what the current install can
read.

| Format | Install |
|---|---|
| [ZIP](#zip) (`.zip`, `.jar`, `.whl`, `.apk`) | Core. `[recommended]` adds Deflate64, PPMd, WinZip AES, and Zstandard* |
| [TAR](#tar-and-compressed-tar) (`.tar`) | Core |
| [Compressed TAR](#tar-and-compressed-tar) (`.tar.gz` or `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, …) | What its compressor needs (below) |
| [7z](#7z) (`.7z`) | Core. `[recommended]` adds PPMd, Deflate64, Brotli, LZ4, AES, and Zstandard* |
| [RAR](#rar) (`.rar`) | Core lists it and reads uncompressed members. Compressed members need the `unrar` program, and encrypted headers need `[recommended]` |
| [gzip](#single-file-compressors) (`.gz`), bzip2 (`.bz2`), xz (`.xz`), lzip (`.lz`), LZMA Alone (`.lzma`), zlib (`.zz`), Unix compress (`.Z`), lzop (`.lzo`), Snappy (`.sz`) | Core. `[recommended]` makes `.lzo` and `.sz` faster |
| [Zstandard](#single-file-compressors) (`.zst`) | Core on Python 3.14 and later, `[recommended]` before |
| [LZ4](#single-file-compressors) (`.lz4`), Firefox's mozlz4 (`.jsonlz4`, `.mozlz4`), Brotli (`.br`) | `[recommended]` |
| [bzip3](#single-file-compressors) (`.bz3`) | `[bzip3]` |
| [uuencode](#single-file-compressors) (`.uu`, `.uue`), base64 (`.b64`) | Core |
| [ISO 9660 and UDF](#iso-9660) (`.iso`, and CD images as `.bin`, with or without `.cue`) | Core |
| [SquashFS](#squashfs) (`.squashfs`, `.sqfs`, `.snap`) | Core. Zstandard* and LZ4 images need `[recommended]` |
| [Debian packages](#debian-packages) (`.deb`, `.udeb`) | Core. Zstandard* packages need `[recommended]` |
| [RPM](#rpm) (`.rpm`) | Core. Zstandard* payloads (Fedora's default) need `[recommended]` |
| [XAR](#xar) (`.xar`) | Core |
| [macOS installer packages](#macos-installer-packages) (`.pkg`, `.mpkg`, `.xip`) | Core |
| [CAB](#cab) (`.cab`) | Core |
| [makeself](#makeself) (`.run`) | Core. The payload needs what its compressor needs, and `--ssl-encrypt` payloads need `[recommended]` |
| [LHA](#lha) (`.lzh`, `.lha`), [ARJ](#arj) (`.arj`) | Core |
| [CPIO](#cpio) (`.cpio`), [ar](#ar) (`.a`, `.lib`) | Core |
| [A directory on disk](#directory) | Core |

\* Only before Python 3.14, which has Zstandard built in.

A UDIF disk image (`.dmg`) is recognised and refused ([Disk images](#disk-images)). These are not
read at all, and opening one raises `FormatDetectionError`:

- Windows images and virtual disks: WIM and ESD (`.wim`, `.esd`), MSI (`.msi`), VHD and VHDX
  (`.vhd`, `.vhdx`), VMDK (`.vmdk`) and QCOW2 (`.qcow2`). 7-Zip reads them.
- Older archive formats: ACE (`.ace`), StuffIt (`.sit`), Zoo (`.zoo`) and ARC (`.arc`). The
  Unarchiver's `unar` reads them.
- ZPAQ (`.zpaq`), which the `zpaq` tool reads.

Where this page names a diagnostic, such as `ARCHIVE_TRAILING_DATA`, archivey records it on the
reader and carries on: it is a warning by default and an exception under `DiagnosticPolicy.STRICT`
([Diagnostics](errors-and-diagnostics.md#diagnostics)).

The
[library analysis](https://github.com/archivey-dev/archivey/blob/main/dev-docs/library-analysis.md)
explains the choice of each compression library, and [Acknowledgements](acknowledgements.md)
credits them.

## Everyday archives

### ZIP

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
  Finder also adds `__MACOSX/` sidecar files ([macOS sidecar
  files](opening.md#macos-sidecar-files)).

Damaged and unusual archives are read as far as they can be, and each problem is reported with a
diagnostic: a missing or damaged index, local headers that disagree with the index, bytes missing
from the middle, or data after a member's compressed stream. The
[ZIP development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/zip.md)
describes each case and the error it raises.

### TAR (and compressed TAR)

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
  ([macOS sidecar files](opening.md#macos-sidecar-files)).

Damaged headers, and header shapes no writer produces, are refused or reported with a diagnostic.
The [TAR development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/tar.md)
describes each case.

### 7z

Archivey reads the index at the end of the file. Members are solid, so reaching one decodes the ones
before it in its block, unless the archive was written without solid blocks (`7z -ms=off`). A
`stream_members()` pass decodes each solid block once, and opening a member in the middle of a block
may decode the block again from its start.

- **Supported:** LZMA, LZMA2, Deflate, BZip2, Delta and the executable filters, including BCJ2,
  ARM64 and RISC-V, in the core install (the filters are decoded in Python, so they're slower).
  PPMd, Deflate64, Brotli, LZ4, AES encryption, and Zstandard[\*](#overview), with
  `[recommended]`. Self-extracting `.exe` files, code-signed ones included.
- **Not supported:** rare LZMA settings that 7-Zip writes only when asked (for example
  `-mlc=8`). Such an archive can be listed, and reading its members raises
  `UnsupportedFeatureError`.
- **Encryption:** 7z stores no password check. A wrong password usually makes decompression fail,
  or else the data fails its CRC. Only a member stored without compression and without a CRC can
  come back as garbage, which archivey reports as unchecked data (`DIGEST_UNVERIFIABLE`). With
  encrypted headers, a wrong password raises `EncryptionError`, except in archives written by
  `py7zr`, which store no header checksum: there a wrong password can, rarely, list garbage
  members.
- **Names** are stored as UTF-16, so `encoding=` has no effect.

Damaged archives, and the details of confirming a password among several candidates, are covered
in the [7z development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/7z.md).

### RAR

Archivey reads the RAR structure itself, RAR 1.5 to RAR5, but no Python package decodes RAR
compression. Listing and reading uncompressed members need nothing extra. Compressed members are
decoded by running RARLAB's `unrar` (or `rar`) 6.0 or later, found on `PATH` or, on Windows, in a
WinRAR installation, or else The Unarchiver's `unar` 1.10 or later
([Getting unrar](install.md#getting-unrar)). With neither, reading a compressed member raises
`PackageNotInstalledError`. `ArchiveyConfig.rar_decompressor` picks the program:

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
- **Solid archives,** where reaching a member decodes every member before it: a
  `stream_members()` pass decodes the archive in one run. Opening members
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
[RAR development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rar.md).

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
  between two blocks reads short with no error. A cut mozlz4 file raises `CorruptionError`, and in
  the other formats a cut raises `TruncatedError`.
- **Concatenated files** (`cat a.gz b.gz > ab.gz`) are read as one payload in every format that
  allows it: gzip, bzip2, xz, lzip, LZMA Alone, Zstandard, LZ4 and Snappy. zlib and Brotli hold one
  stream each.
- **Bytes after the stream**, such as a signature appended to a download, don't stop the read in
  most formats. Archivey returns the whole payload, then reports `ARCHIVE_TRAILING_DATA`. `.Z`,
  `.bz3` and Snappy have no end marker, so they can't tell where the data stops: `.Z` decodes
  appended bytes as data, and `.bz3` and Snappy raise `CorruptionError` on them. mozlz4 decodes the
  whole file as one block, so it raises `CorruptionError` too. Snappy makes one exception, for zero
  bytes that run to the end of the file, such as the padding `dd` or a tape write adds: four or
  more are read past, and fewer may be a cut chunk header, so they raise `TruncatedError`.
- **Memory:** a Zstandard window, a mozlz4 size and a bzip3 block size are declared by the file.
  `DecoderLimits.max_decoder_memory` (2 GiB by default) caps the memory they ask for, and a file
  over the cap raises `ResourceLimitError`.

Some formats have more to know:

- **mozlz4** is the format Firefox keeps its session, add-on and search files in
  (`sessionstore.jsonlz4`, `search.json.mozlz4`). Archivey finds it by its header, whatever the
  extension. It decodes only once the whole file has arrived.
- **Snappy** (`.sz`) is the framing format that `snzip` and the Snappy libraries write.
- **lzop** (`.lzo`) and Snappy decode in Python, many times slower, unless `[recommended]` is
  installed. A `compress-utils` built from source that leaves out LZO1X or Snappy is skipped for
  that format.
- **bzip3** (`.bz3`) needs `[bzip3]`, which is in neither `[recommended]` nor `[all]` and doesn't
  install on macOS, PyPy or Python 3.15 ([Install](install.md#bzip3)).
- **uuencode and base64** compress nothing, but they wrap a file as text, so archivey peels them
  the same way: `files.tar.uu` lists the tar. A uuencoded file is found by its `begin` line, and a
  base64 one by a `.b64` or `.base64` name, or when its decoded start is a format archivey knows.
  Neither has a checksum.

The [single-file development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/single-file.md) cover when
the size arrives, how appended bytes are told apart from a damaged header, which pipe reads wait and
why, and the checks archivey adds around the accelerators.

## Disk and filesystem images

### ISO 9660

Reading an ISO image needs no extra. An image can carry several name trees over the same files.
Archivey lists Rock Ridge first, then UDF, then Joliet, then plain ISO 9660,
and says which in `ArchiveInfo.extra["iso.namespace"]`.

- **Supported:** Rock Ridge, UDF, Joliet and plain ISO 9660 names. Images with only UDF, as on
  most Blu-ray discs. zisofs compression (`mkzftree`,
  `genisoimage -z`, `xorriso --zisofs`). Files of 4 GiB or more, stored in several pieces, read as
  one member. Raw CD images (`.bin` with or without its `.cue`) in Mode 1 or Mode 2 Form 1,
  multisession discs included. Hybrid installer images, with an EFI partition after the ISO data.
- **Not supported:** UDF on a rewritable or incrementally written disc (a sparable or virtual
  partition), or with extended allocation descriptors: the image is listed from another tree when
  it has one, and otherwise raises `UnsupportedFeatureError`. zisofs2 members are listed, and
  reading one raises `UnsupportedFeatureError`. Video and audio-only CD images raise
  `UnsupportedFeatureError`.

- **Names:** Rock Ridge and plain names are read as UTF-8, then with `encoding=` when you pass
  one. Without it, a name that isn't UTF-8 takes the matching Joliet name when the image has one,
  and is escaped otherwise. Joliet names are UTF-16, and UDF names are Latin-1 or UTF-16, as each
  name says, so `encoding=` has no effect on them.
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
  `TruncatedError`. A cut that reaches the folders, or the UDF anchor at block 256, makes
  `open_archive` raise `TruncatedError`.

Archivey also refuses folder trees that loop back on themselves. The details, and how `.cue`
sheets and multisession discs are read, are in the
[ISO development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/iso.md).

### SquashFS

gzip, xz, LZMA and LZO images need nothing extra. Zstandard[\*](#overview) and LZ4 images need
`[recommended]`. Members are read directly. `ArchiveInfo.extra`
names the compressor (`"squashfs.compressor"`) and the block size (`"squashfs.block_size"`).

- **Supported:** SquashFS 4.0, written since 2009. Files, folders, symlinks, hard links, sparse
  files (`is_sparse`), and devices, FIFOs and sockets (`OTHER`).
- **Not supported:** SquashFS 3 and older, which raise `UnsupportedFeatureError`. Extended
  attributes are not read.
- **Damage:** SquashFS stores no checksums of its own. A damaged block is caught when it doesn't
  decode to its length, or when its compressor's own check fails (zlib's Adler-32, the xz CRC).

The [SquashFS
development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/squashfs.md)
cover the layout and how damaged images are handled.

### Disk images

A macOS disk image (`.dmg`, UDIF) is recognised and refused with `UnsupportedFeatureError`, so it
isn't mistaken for the zlib, bzip2 or xz stream its first block happens to be. To get at the
files, convert or mount the image first, for example with `7z x`, `dmg2img`, or `hdiutil attach`
on macOS. An uncompressed image that holds an ISO 9660 filesystem is read as that ISO.

The [DMG development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/dmg.md) say how the image
is recognised.

## Packages and installers

### Debian packages

A `.deb` is an ar archive holding two tars: the control files and the files the package
installs. Archivey lists it as `dpkg-deb -R` unpacks it: the installed files under their own
names, and the control files (`control`, `md5sums`, the maintainer scripts) under `DEBIAN/`. xz,
gzip, bzip2 and LZMA packages need nothing extra, and Zstandard[\*](#overview) ones need
`[recommended]`. Listing decompresses both tars, and members are read one after another, as in a
compressed TAR.

- **Package fields:** `ArchiveInfo.extra` has `deb.package`, `deb.version` and
  `deb.architecture` from the control file, once the listing or `stream_members()` has read it.
- **Checksums:** each file that `DEBIAN/md5sums` lists gets its MD5 in `member.hashes`, checked
  when you read it to its end.
- **The raw layout:** `format=ArchiveFormat.AR` lists the three ar members instead
  (`debian-binary`, `control.tar.xz`, `data.tar.xz`), to read a tar whole.

Archivey follows `dpkg-deb` on which members it reads, and refuses a package whose data files or
links would land in `DEBIAN/` or let one extraction write through another's symlink. The [Debian
development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/deb.md) have
the rules and their limits.

### RPM

An RPM package is a header listing every file, followed by a compressed CPIO payload. gzip,
bzip2, xz and LZMA payloads need nothing extra, and Zstandard[\*](#overview) ones (Fedora's default)
need `[recommended]`.

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
[RPM development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/rpm.md)
cover payload forms, hard links, symlink targets and how damage is reported.

### XAR

The archive format written by Apple's `xar` and `bsdtar --format xar`. macOS installer packages
and `.xip` files are XAR archives too: archivey opens them as
[installer packages](#macos-installer-packages), and as XAR only with `format=ArchiveFormat.XAR`.
XAR needs nothing extra. Members are read directly, each compressed on its own.

- **Supported:** stored, gzip, bzip2, LZMA and xz data. MD5, SHA-1, SHA-224, SHA-256, SHA-384
  and SHA-512 checksums.
- **Not supported:** signatures are not checked.
- **Checksums:** the index's own checksum is checked at open. Each file stores a checksum of its
  data (SHA-1 by default), which is in `member.hashes` and checked when you read the member to
  its end.
- **Names** stored as base64, as writers do for bytes that aren't UTF-8, are decoded with
  `encoding=` like names in any other format.

The [XAR development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xar.md) cover the index,
its limits, hard links, and the shapes archivey refuses.

### macOS installer packages

A macOS installer package (`.pkg`, `.mpkg`, written by `pkgbuild` and `productbuild`) or an
Xcode `.xip` is a [XAR](#xar) archive whose payloads are compressed CPIO archives. Archivey lists
the files inside the payloads, as `pkgutil --expand-full` unpacks them, under a folder named after
the payload: `app.pkg/Payload/Applications/App.app/...`. `Distribution`, `PackageInfo`, `Bom` and
the other files are listed as they are. Packages need nothing extra.

- **Supported:** component packages, product archives with one folder per component, and `.xip`.
  Payloads compressed with gzip or Apple's pbzx.
- **Not supported:** signatures are not checked, so use `pkgutil --check-signature` for that.
- **Listing** decodes every payload. Within one payload, reading a file decodes the payload up to
  it, so `stream_members()` and `extract_all()` decode each payload once.
- **Checksums:** each payload's XAR checksum is checked as the listing reads it, and a payload
  that fails raises `CorruptionError`. Files from a payload have nothing in `member.hashes`;
  `Distribution`, `Bom` and the other XAR files keep their XAR checksum there.
- **The raw layout:** `format=ArchiveFormat.XAR` lists the XAR files instead, with each payload
  as one file.

A payload that is not a CPIO, or that is stored with a XAR encoding archivey does not read or
`FormatPolicy` turns off, is listed as the one file it is. The
[XAR development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/xar.md)
cover packages too.

### CAB

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

Archivey also refuses a cabinet whose file table doesn't match its folders. The
[CAB development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cab.md)
have the details.

### makeself

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
development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/makeself.md)
cover the header forms, the encryption schemes and the limits.

## Older and Unix formats

### LHA

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

The [LHA development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/lha.md) cover header
levels, the per-system fields, and how the MacLHA wrapper is recognised.

### ARJ

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

The [ARJ development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/arj.md) cover the
per-system fields and the ARJ-SECURITY envelope.

### CPIO

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

The [CPIO development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/cpio.md) cover afio's
large headers, detection inside a compressor, and data after the trailer.

### ar

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

The [ar development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/ar.md)
cover long names in each dialect and the streaming details.

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
development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/formats/directory.md)
cover the walk order and symlinks.

## Seeking in compressed files

If you'll seek backwards often inside a compressed member, extracting it to a file first is
usually faster, unless its format keeps a restart point near every target (the first group below).
The same points decide how fast archivey opens one member of a `.tar.gz` or other compressed TAR by
name.

A member stream can seek when you pass `seekable_members=True`
([Seeking inside a member](reading.md#seeking-inside-a-member)). A seek forward decodes the bytes
in between. A seek backward resumes from the last point before its target where decoding can
restart, or from the start of the stream when there is none.

**Always near the target:**

- **gzip, zlib, and Deflate members of ZIP and 7z:** from a point archivey keeps about every MiB
  that a read has passed, except on PyPy ([PyPy](install.md#pypy)). `[seekable]` adds an
  accelerator that keeps its own points.
- **bzip2:** from the start of the block, which holds about 900 kB of data at the default level.
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
development docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/topics/detection.md)
give the full order of the checks, each format's probe, and how signed and resource-packed
installers are handled.

## Reading from a pipe

A pipe, a socket or an HTTP response can be read once, from start to end, with `pipe=True`
([Reading from a pipe](reading.md#reading-from-a-pipe)). `pipe=True` reads any source that way,
one that can seek included, so the lists below hold for the flag, not for the object you pass.
Whether a format can be read that way depends on where it keeps what archivey needs.

- **Can be read from a pipe:** ZIP, TAR and compressed TAR, CPIO, ar, Debian packages, RPM,
  makeself, and every single-file compressor. RAR can too, for an archive in one volume, when
  `unrar` 7.00 or later is installed.
- **Need a source that can seek:** 7z, ISO 9660, SquashFS, XAR and macOS installer packages, CAB,
  LHA and ARJ. Opening one with `pipe=True` raises `StreamNotSeekableError`. Copy it to a file or
  an `io.BytesIO` first, and open that without `pipe=True`.

Some formats behave differently from a pipe:

- **ZIP** keeps a member's mode, owner, comment and symlink flag only in the index at its end, so
  from a pipe they arrive when the pass gets there, and `member.member_state_final` turns `True`
  then. Extraction keeps the files in a temporary folder inside the destination until the index
  has been read.
- **RAR** writes what arrives into temporary volumes for `unrar`, 16 MiB each, one on disk at a
  time. `unrar` gets one password, so with several candidates an encrypted RAR 1.5-4 member raises
  `UnsupportedFeatureError`: pass the one password. A RAR5 file copy (`rar -oi`) raises
  `UnsupportedFeatureError`, since its bytes are an earlier member's. After a member cut short, a
  wrong password or a member with no size, that member and every later member with data raise.
  Closing the reader can leave a read of the source pending, so give a socket a timeout, or call
  `shutdown()` on it before you close it.
- **TAR** reads up to 1 MiB past the end of the archive to check for trailing data, so the listing
  ends only when the sender closes the pipe.
- **Compressed files** are decoded from what has arrived. bzip2 and bzip3 decode only whole blocks
  (about 900 kB, and 16 MiB by default), mozlz4 decodes only once the whole file has arrived, and
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
development
docs](https://github.com/archivey-dev/archivey/blob/main/dev-docs/topics/prefixed-archives.md) cover
how far the search goes and how installers that pack the archive as a resource are read.
