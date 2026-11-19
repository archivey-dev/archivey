# Acknowledgements

Archivey builds on the work of the people who designed these formats and wrote the libraries and
tools around them. This page credits the code archivey adapted, the projects it learned from and
checks itself against, and the packages it uses. If we missed a project that should be here, please
open an issue or a pull request.

## Code adapted from other projects

Two parts of archivey are adapted from other projects' code, and their licence notices are kept in
the files that hold it:

| Project | What archivey adapted | Licence |
| --- | --- | --- |
| [uncompresspy](https://github.com/kYwzor/uncompresspy) (Tiago Gomes) | The LZW decoder for `.Z` files ([notice](https://github.com/archivey-dev/archivey/blob/main/src/archivey/internal/streams/codecs/unix_compress_decoder.py)) | BSD-3-Clause |
| [rarfile](https://github.com/markokr/rarfile) (Marko Kreen) | RAR3 password key derivation and the RAR3 Unicode filename decoder ([notice](https://github.com/archivey-dev/archivey/blob/main/src/archivey/internal/backends/rar_parser.py)) | ISC |

Archivey's other decoders are its own code, but each follows a reference implementation
wherever the format leaves a choice, so that it reads what that tool reads:

- **LHA and LArc:** [lhasa](https://github.com/fragglet/lhasa) (Simon Howard), and Jason
  Summers' notes for LHARK's variant of `-lh7-`.
- **LZX in CAB files:** [libmspack](https://github.com/kyz/libmspack) (Stuart Caie), the
  library `cabextract` uses.
- **ARJ:** Robert Jung's UNARJ, for the headers and method 4. Methods 1 to 3 are LHA's format
  and use the LHA decoder.
- **Shrink, Implode and Reduce in ZIP:** [Info-ZIP](https://infozip.sourceforge.net/)'s
  `unzip`. DCL Implode follows Mark Adler's `blast`, in [zlib](https://github.com/madler/zlib)'s
  `contrib/`.
- **LZO1X, in `.lzo` files and SquashFS images:** the Linux kernel's LZO decoder, and Markus
  Oberhumer's [LZO](https://www.oberhumer.com/opensource/lzo/) library for how a block ends.
- **BCJ2 in 7z archives:** 7-Zip's.
- **The ARM64 and RISC-V branch filters in 7z archives:** liblzma, from the
  [xz](https://github.com/tukaani-project/xz) project. Both are checked against 7-Zip's.

## Projects archivey learned from

[py7zr](https://github.com/miurahr/py7zr) (Hiroshi Miura and contributors) and rarfile were the main
references for how 7z and RAR archives behave in practice. Archivey's 7z and RAR readers were
checked against them at every step and take ideas from them, though not code (apart from the rarfile
pieces above). Python's [`zipfile`](https://docs.python.org/3/library/zipfile.html) and
[`tarfile`](https://docs.python.org/3/library/tarfile.html) played the same part for ZIP and TAR:
archivey read both formats through them before it had its own readers, which still follow them in
places. [7-Zip](https://www.7-zip.org/)'s and [RARLAB](https://www.rarlab.com/)'s UnRAR sources were
the references for the formats themselves, and WinZip's AES specification for encrypted ZIP files.
[GNU tar](https://www.gnu.org/software/tar/) is the reference for how archivey reads TAR archives,
down to how extended headers combine. A comparison with
[Apache Commons Compress](https://commons.apache.org/proper/commons-compress/) showed formats and
checks worth adding, such as XZ-compressed ZIP members and finding TAR archives that have no
`ustar` magic. [Google Snappy](https://github.com/google/snappy)'s format and framing
descriptions are the reference for the Snappy reader, and its library was the oracle the reader
was fuzzed against.

The indexed and seekable decompressors ([python-xz](https://github.com/Rogdham/python-xz),
[indexed_bzip2](https://github.com/mxmlnkn/indexed_bzip2),
[indexed_gzip](https://github.com/pauldmccarthy/indexed_gzip),
[ratarmount](https://github.com/mxmlnkn/ratarmount) and
[indexed_zstd](https://github.com/martinellimarco/indexed_zstd)) shaped how archivey seeks inside
compressed streams, even though archivey doesn't depend on them.

## Packages archivey uses

Archivey itself needs no third-party package. Optional packages add formats and features, and
[Install](install.md) says which extra brings in which:

- **[pyppmd](https://github.com/miurahr/pyppmd):** PPMd compression in 7z and ZIP.
- **[inflate64](https://github.com/miurahr/inflate64):** Deflate64 in ZIP and 7z.
- **[brotli](https://github.com/google/brotli), [lz4](https://github.com/python-lz4/python-lz4) and
  [backports.zstd](https://github.com/Rogdham/backports.zstd):** Brotli, LZ4 and Zstandard, as
  single files and inside 7z archives (Zstandard also inside ZIP). Python 3.14 and later reads
  Zstandard without backports.zstd.
- **[cryptography](https://github.com/pyca/cryptography):** AES decryption for 7z, RAR and WinZip
  AES ZIP files.
- **[pycdlib](https://github.com/clalancette/pycdlib):** ISO images.
- **[bzip3](https://github.com/synodriver/python-bz3):** `.bz3` files, with the
  [bzip3](https://github.com/kspalaiologos/bzip3) library it bundles.
- **[cramjam](https://github.com/milesgranger/cramjam),
  [google-crc32c](https://github.com/googleapis/python-crc32c) and
  [crc32c](https://github.com/ICRAR/crc32c):** faster Snappy (`.sz`) reading: cramjam decodes raw
  Snappy blocks, and the other two compute the CRC-32C of each chunk.
- **[tqdm](https://github.com/tqdm/tqdm):** progress bars in the command-line tool.
- **[rapidgzip](https://github.com/mxmlnkn/rapidgzip):** faster seeking in large gzip, bzip2 and
  DEFLATE data, such as ZIP members, and faster reading of large DEFLATE data where it pays off.
- **[compress-utils](https://github.com/dupontcyborg/compress-utils):** faster
  LZO decoding in `.lzo` files and SquashFS images.

Compressed or encrypted RAR data is read with RARLAB's `unrar` (or `rar`), or with [The
Unarchiver](https://theunarchiver.com/)'s `unar`. [Install](install.md) says which one runs when.

## Projects archivey checks itself against

Tests compare what archivey reads with py7zr, rarfile, `zipfile` and `tarfile`, field by field, and
can also read [libarchive](https://github.com/libarchive/libarchive)'s own test archives through
[libarchive-c](https://github.com/Changaco/python-libarchive-c). Two outside collections check
archivey against other readers. The tests read them when they are given a copy:

- **[tar-minefield](https://github.com/haampie/tar-minefield)** (Harmen Stoppels): crafted TAR
  archives, each with the tree an extractor should write, and what GNU tar and Astral's tar-codec
  write from them.
- **[Apache Commons Compress](https://github.com/apache/commons-compress)'s test archives:** about
  410 files in many formats, read by archivey and by Commons Compress.

Where they are installed, the tests also compare archivey with `unar`, lhasa, `cabextract` and
Info-ZIP's `unzip` on the same archives, and with liblzo2, through
[python-lzo](https://github.com/jd-boyd/python-lzo), on LZO data.

7-Zip, RARLAB's `rar`, Info-ZIP's `zip`, `lzop`, the `bzip3` tool, libarchive's `bsdtar` and
`bsdcpio`, GNU `ar` and `cpio`, LLVM's `llvm-ar`, ARJ for Unix, makeself, CMake's CPack,
squashfs-tools, `rpmbuild`, `dpkg-deb`, xorriso, [ncompress](https://github.com/valgur/ncompress),
[pyzipper](https://github.com/danifus/pyzipper) and several of the libraries above write
archivey's test archives. Some archives come from other projects, because no tool at hand writes
them; each is credited in its folder's README:

- two old RAR archives from rarfile, and an LZ4 7z archive from py7zr;
- an encrypted solid RAR archive and four CAB files from libarchive's tests;
- twenty-nine LHA-family archives, written by many old tools, from lhasa's tests;
- two ARJ archives from Commons Compress's tests;
- two ZIP Reduce streams from the Rust [zip](https://github.com/zip-rs/zip2) crate's tests;
- three LZMA files attached to a CPython bug report.

You don't need any of them to use archivey.

## Tools archivey is built with

Archivey is built and tested with [pytest](https://github.com/pytest-dev/pytest),
[Hypothesis](https://github.com/HypothesisWorks/hypothesis),
[Atheris](https://github.com/google/atheris), [Ruff](https://github.com/astral-sh/ruff),
[Pyrefly](https://github.com/facebook/pyrefly), [ty](https://github.com/astral-sh/ty) and
[MkDocs](https://github.com/mkdocs/mkdocs), among others. Thanks to everyone who maintains them.
