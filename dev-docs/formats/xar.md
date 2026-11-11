# XAR

Current maintainer truth for XAR: macOS installer packages (`.pkg`), `.xip` files, and
what Apple's `xar` and `bsdtar --format xar` write. A XAR archive keeps an XML index at
the start and each file's data, compressed on its own, in a heap after it, so archivey
reads it from a source that can seek. The reader is written against `archivey.formats`
and registered as a built-in, as ISO, SquashFS and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/xar_reader.py`, a `XarHandler` (`IndexedFormatHandler`) and a `XarReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the index points at data anywhere after it |
| Listing cost | From the index, read whole at open |
| Access cost | `DIRECT`: each file's data is its own stream |
| Core dependencies | None. zlib, bz2 and lzma from the standard library; the XML through `xml.parsers.expat` |
| Encryption | None read. Apple's `xar` can sign the TOC (`<signature>`), which is not checked |
| Name encoding | UTF-8 text in the XML, or base64 of raw bytes (`enctype="base64"`), then UTF-8 first, `encoding=`, escaped |
| Checksums | The TOC's (SHA-1 by default, MD5, or a named algorithm), checked at open; each file's `extracted-checksum` as `member.hashes`, checked by the verifying stream. One whose style is not MD5, SHA-1, SHA-256 or SHA-512, or that names no style, is not a hash: the file reads unchecked and reports `DIGEST_UNVERIFIABLE` (`reason="unknown_algorithm_or_backend"`, the style in `algorithm`) |
| Refuses | Version other than 1; a DOCTYPE in the TOC; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-xar/spec.md` |

Not here, though a reader might look for it: a package's `Payload` (a gzip CPIO, or a
`pbzx` stream in newer packages) is not expanded: the reader lists the XAR members only,
for now; the `archived-checksum` over the encoded bytes is not
checked, since the decoded bytes' checksum and the decoder's own check already cover them;
extended attributes (`<ea>`) and Finder info are not read; signatures are not verified.

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
  there. Expat parses it in one call with a `StartDoctypeDeclHandler` that raises: entity
  declarations only exist inside a document type, so none is expanded. The parser keeps
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
  data goes through archivey's codecs (`ReaderContext._decompress_coder`) with the decoded
  size, so archivey's decoder limits and length checks apply. A member's data is one
  stream: any byte after its end, a second zlib stream, junk or zeros, raises
  `CorruptionError`, as in a ZIP member, where a `.zz` file only reports it as trailing
  data. libarchive fails on the same input ("XAR decompressor made no progress"), and
  Apple's `xar` loops on it until an allocation fails. Under `rapidgzip`, which decodes
  every zlib stream as one, the Adler-32 at the end covers only the last stream, and the
  second decode that mismatch starts finds the first stream's end and raises; only a
  forged last trailer that matches every stream gets past (`gzip.md` §5). A bzip2 or LZMA
  Alone member is one stream too, as Apple's `xar` writes it and libarchive reads it (it
  ends its decoder at the first stream's end), so a further stream is refused, where a
  `.bz2` or `.lzma` file reads it on. xz keeps its further streams and stream padding, as
  in a ZIP xz member: the xz format defines its data as one or more streams. The extracted checksum is `member.hashes`, and
  the verifying stream checks it (`hashlib.new(..., usedforsecurity=False)`, so a FIPS
  OpenSSL still computes MD5 and SHA-1).
- **Unknown types.** A type the format does not define is a readable `FILE` when it has
  data and `OTHER` otherwise, with `MEMBER_TYPE_UNKNOWN` (DR-25).

## 3. Tests

`tests/test_xar.py` reads the five bsdtar archives in `tests/fixtures/external/xar_bsdtar`
(one per compression) and archives `tests/xar_util.py` writes for every encoding, file
checksum and TOC checksum, hard links in either order, base64 names, and each refusal.
The fuzz target `xar` (`tests/atheris_fuzz/targets.py`) opens mutated bsdtar archives.
7-Zip cannot list bsdtar's archives, so there is no second reader to compare against.
