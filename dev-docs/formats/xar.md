# XAR

Current maintainer truth for XAR: macOS installer packages (`.pkg`), `.xip` files, and
what Apple's `xar` and `bsdtar --format xar` write. A XAR archive keeps an XML index at
the start and each file's data, compressed on its own, in a heap after it, so archivey
reads it from a source that can seek. The reader is written against `archivey.formats`
and registered as a built-in, as ISO, SquashFS and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/xar_reader.py`, a `XarHandler` (`IndexedFormatHandler`) and a `XarReader` (`IndexedReader`), registered from core's format table |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the index points at data anywhere after it |
| Listing cost | From the index, read whole at open |
| Access cost | `DIRECT`: each file's data is its own stream |
| Core dependencies | None. zlib, bz2 and lzma from the standard library; the XML through `xml.parsers.expat` |
| Encryption | None read. Apple's `xar` can sign the TOC (`<signature>`), which is not checked |
| Name encoding | UTF-8 text in the XML, or base64 of raw bytes (`enctype="base64"`), then UTF-8 first, `encoding=`, escaped |
| Checksums | The TOC's (SHA-1 by default, MD5, or a named algorithm), checked at open; each file's `extracted-checksum` as `member.hashes`, checked by the verifying stream. One whose style is not MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512, or that names no style, is not a hash: the file reads unchecked and reports `DIGEST_UNVERIFIABLE` (`reason="unknown_algorithm_or_backend"`, the style in `algorithm`) |
| Refuses | Version other than 1; a DOCTYPE in the TOC; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-xar/spec.md` |

A macOS installer package or `.xip` is read as `ArchiveFormat.PKG`, with its payloads
expanded (§4); `format=ArchiveFormat.XAR` keeps the XAR members as they are.

Not here, though a reader might look for it: the `archived-checksum` over the encoded
bytes is not checked, since the decoded bytes' checksum and the decoder's own check
already cover them; extended attributes (`<ea>`) and Finder info are not read;
signatures are not verified.

## 1. Shape

From Apple's `xar` sources (`include/xar.h.in`, `lib/archive.c`) and libarchive's
`archive_read_support_format_xar.c`:

- **Header**, big-endian, 28 bytes or more: `xar!`, its own size, version 1, the TOC's
  compressed and decoded sizes (64-bit each), and the checksum algorithm (0 none, 1
  SHA-1, 2 MD5, 3 named: the name follows the fixed header, NUL-padded).
- **TOC**, zlib-compressed XML: `<xar><toc>`, an optional `<creation-time>`, the TOC
  `<checksum style=…>` with the heap `<offset>` and `<size>` of the digest, and the
  `<file id=…>` elements, a directory's files nested inside it.
- **Heap**, right after the TOC: the TOC's digest (usually at offset 0), then file data.

Each `<file>` holds `<name>`, `<type>` (`file`, `directory`, `symlink`, `hardlink`,
`fifo`, `character special`, `block special`, `socket`), `<link>` for a symlink's target,
`<mode>` (octal), `<uid>`, `<gid>`, `<user>`, `<group>`, the times as
`YYYY-MM-DDTHH:MM:SS[.fff]Z`, and for one with data a `<data>` with `<length>` (stored),
`<offset>` (in the heap), `<size>` (decoded), `<encoding style=…>` and the two checksums.

Encodings: `application/octet-stream` (stored), `application/x-gzip` (a **zlib** stream,
not gzip), `application/x-bzip2`, `application/x-lzma` (LZMA Alone) and
`application/x-xz`.

## 2. Reading

- **Open.** The header's TOC sizes, stored and decoded, are checked against `max_metadata_bytes` before any byte
  is decoded; the TOC is decoded with a cap of that size plus one and must end exactly
  there. Before expat sees it, a TOC holding a NUL byte is refused with `CorruptionError`:
  expat switches to UTF-16 by itself at a BOM, a UTF-16 character can hold the bytes of
  `<`, `>` or a quote, and the scan below reads bytes, so a UTF-16 TOC could hide a long
  tag from it. Every UTF-16 document holds a NUL and no UTF-8 one does; Apple's xar and
  the other writers emit UTF-8. Then one regex pass (`_LONG_TAG`) refuses with `CorruptionError` any
  tag of more than 65 536 pieces, a piece being one character outside quotes or one whole
  quoted value: expat builds a tag's whole attribute dict before any handler runs, so a 13 MB
  TOC of one element with millions of attributes took 1.67 GB, beyond the TOC byte cap
  (maintainer ruling, 2026-11-11). The pass costs about a tenth of a listing. Expat parses
  it in one call with a `StartDoctypeDeclHandler` that raises: entity declarations only
  exist inside a document type, so none is expanded. The parser keeps
  one frame per open `<file>`, reserves the entry's slot when the element opens (so a
  directory is listed before its files) and computes its path when its `<name>` closes,
  from the enclosing frame's. A second `<name>` with the same text is the same name: Apple's
  productbuild writes each top-level file's name twice (seen in the Node.js, GitHub CLI and
  Miniconda installers), and bsdtar 3.7 joins the two into `DistributionDistribution`. A second
  name that differs raises `CorruptionError`. `max_members` is checked as each `<file>` opens. The TOC
  digest is then checked over the compressed TOC bytes, as Apple's `xar` computes it.
- **Hard links.** Apple's `xar` and bsdtar mark the entry that holds the data
  `<type link="original">hardlink</type>` (listed as a `FILE`) and every other name
  `<type link="ID">hardlink</type>`. bsdtar can write a link before its original, so a
  link whose id is not listed yet waits and is yielded right after it: hard links name an
  earlier member. A link to an id nothing holds raises `CorruptionError` at the end of
  the listing.
- **Data.** Stored data is a view of the heap and must be as long as its size; encoded
  data goes through archivey's codecs (`ReaderContext.decompress(..., one_stream=True)`)
  with the decoded size, so archivey's decoder limits and length checks apply. A
  member's data is one stream: any byte after its end, a second zlib stream, junk or
  zeros, raises `CorruptionError`, as in a ZIP member, where a `.zz` file only reports
  it as trailing data. The official readers disagree (§3): on macOS, Apple's `xar`
  writes the first stream and ignores the rest, and bsdtar hangs. On Linux, libarchive
  failed on a 24 MiB member ("XAR decompressor made no progress"). Under `rapidgzip`,
  which decodes every zlib stream as one, the Adler-32 at the end covers only the last
  stream, and the second decode that mismatch starts finds the first stream's end and
  raises; only a forged last trailer that matches every stream gets past (`gzip.md` §5).
  A bzip2 or LZMA Alone member is one stream too, as Apple's `xar` writes it and
  libarchive reads it (it ends its decoder at the first stream's end), so a further
  stream is refused, where a `.bz2` or `.lzma` file reads it on. xz keeps its further
  streams and stream padding, as in a ZIP xz member: the xz format defines its data as
  one or more streams. The extracted checksum is `member.hashes`, and the verifying
  stream checks it (`hashlib.new(..., usedforsecurity=False)`, so a FIPS OpenSSL still
  computes MD5 and SHA-1).
- **Shared heap data.** Several files may name one heap range: `xar --coalesce-heap`
  stores identical files once. Each is read as its own member, and each counts in the
  archive-wide ratio, so a TOC of many files over one range stops at `max_ratio` times
  the archive's size, on extraction and on `open()` reads. ZIP and CAB refuse
  overlapping members as damage; XAR cannot, since a writer makes them.
- **Unknown types.** A type the format does not define is a readable `FILE` when it has
  data and `OTHER` otherwise, with `MEMBER_TYPE_UNKNOWN` (DR-25).

## 3. Tests

`tests/test_xar.py` reads the five bsdtar archives in `tests/fixtures/external/xar_bsdtar`
(one per compression) and archives `tests/xar_util.py` writes for every encoding, file
checksum and TOC checksum, hard links in either order, base64 names, and each refusal.
The fuzz target `xar` (`tests/atheris_fuzz/targets.py`) opens mutated bsdtar archives.
7-Zip cannot list bsdtar's archives, so the test suite has no second reader to compare
against. `tests/test_pkg.py` reads packages `tests/xar_util.py` writes around CPIOs and
pbzx streams from `tests/pbzx_util.py`; `tests/test_pbzx.py` covers the codec. No real
`pkgbuild` package is committed yet.

Apple's `xar` and bsdtar are compared by hand:
`scripts/investigations/xar_multistream_oracle.py` writes one-file archives whose member
holds one stream, two streams, or a stream followed by junk or zeros, for each encoding,
and extracts them with all three readers. The manual
`xar-oracle` workflow runs it on macOS, which ships both tools. On 2026-11-11 (Apple `xar`
1.8dev, bsdtar 3.5.3 with libarchive 3.7.4):

- Apple `xar` decodes only the first gzip or bzip2 stream and ignores the rest without an
  error, even when the declared checksum covers both streams. It cannot read xz (it writes
  the raw bytes) or LZMA ("not compiled in").
- bsdtar reads every xz stream and the stream padding, as archivey does, and ignores junk
  after an xz stream. It hangs on any byte after a gzip stream and fails on any byte after
  a bzip2 or LZMA stream.
- archivey refuses every byte after a gzip, bzip2 or LZMA stream (§2), and junk after xz.

## 4. Installer packages (`PKG`)

`internal/backends/pkg_reader.py`: a `PkgHandler` and a `PkgReader` that subclasses
`XarReader`. Maintainer ruling 2026-11-18: list a package's payloads like a `.deb`'s
tars, as a new format, with `format=XAR` keeping the raw view (the deb-versus-ar
choice).

- **Layout.** A component package (`pkgbuild`) holds `Bom`, `PackageInfo`, `Payload` and
  often `Scripts`; a product archive (`productbuild`) holds a `Distribution` and one
  folder per component (`app.pkg/`) with those inside. A `.xip` holds `Content` and
  `Metadata`. `Payload` and `Scripts` are odc CPIOs, gzip-compressed (older packages,
  and `Scripts` today) or pbzx (`Payload` since about 10.10); `Content` is a pbzx CPIO.
- **Listing.** Each `Payload` and `Scripts` at the top or in a top-level folder, and a
  top-level `Content`, is replaced by its CPIO's files under a folder of its own name
  (`app.pkg/Payload/Applications/...`), the layout `pkgutil --expand-full` writes; the
  CPIO's `.` is that folder. The format is told from the payload's first bytes (gzip,
  `pbzx`, `0707`); anything else, a payload stored with a XAR encoding archivey does not
  read or the configuration turns off (a codec, or an xz filter such as BCJ, that
  `FormatPolicy` excludes; reading it raises `UnsupportedFeatureError`), or a payload
  whose first CPIO header cannot be read (`CorruptionError` before the first member), is
  listed as the file it is. A failure after the first member raises, since files are
  already listed. The CPIO is read through `ReaderContext.open_nested`, so listing
  decodes every payload. The payload's XAR checksum is computed as the listing reads it,
  the rest of the payload drained after the CPIO ends, and a mismatch raises
  `CorruptionError`. A payload file, or a hard link's target, that extracts outside its
  folder (`../Bom`, `a/../../Scripts/x`) is refused: it would replace another member of
  the package. Symlinks inside a payload are not followed for that check; extraction's
  own link checks apply.
- **Opening a file.** `open_member` opens the payload again and calls `open_nested`,
  which yields the one span asked for (`format-plugins`, "An indexed reader reads an
  archive stored inside its archive"). The adapter mutes the inner reader's reports on
  the way, since the listing delivered them, and parks the inner walk when the member's
  stream closes, so `extract_all` and `stream_members()` read each payload once more,
  not once per file.
- **Detection.** XAR magic is refined to `PKG` (`ReadBackend.MAGIC_REFINEMENTS`) when
  the name ends in `.pkg`, `.mpkg` or `.xip`, or, for a name that is not `.xar`, when
  the start of the table of contents names a `Distribution` or `PackageInfo`, or both
  `Content` and `Metadata`. On a source that can seek, detection reads up to the first
  64 KiB of the stored (compressed) table of contents for this, past the 4 KiB near
  window when the table is longer, and decodes at most 256 KiB of it. A forward-only
  source (a pipe) gives the check only what detection already holds, so a signed package
  there is answered `XAR`: waiting on the pipe could hold detection, and a package
  cannot be opened from a pipe in any case (`StreamNotSeekableError`). The extra read
  happens on XAR magic only: a signed package or `.xip` puts its certificate chain
  (`<signature>`, `<x-signature>`) before the first `<file>`, and base64 certificates
  hardly compress, so the names often lie past the near window.
- **pbzx** (`StreamFormat.PBZX`, `streams/codecs/pbzx_codec.py`). `pbzx`, a 64-bit chunk
  size (Apple writes 16 MiB), then per chunk a 64-bit decoded size, a 64-bit stored
  length and the bytes: stored when the two sizes are equal, else one xz stream. A chunk
  shorter than the chunk size is the last, as the `pbzx` tools read it; a stream whose
  size is a multiple of the chunk size ends with the input. Each xz chunk decodes under
  `max_decoder_memory` (`new_capped_decompressor`) and notes the dictionary its first
  block declares to the usage record (`declared_memory.noting`), as plain xz does, so
  an archive read inside pbzx output gets the cap less it. Nothing is held whole.
