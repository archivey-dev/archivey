# How it works

You don't need this page to use archivey. It's for when you want to know what's underneath. Maybe
you're deciding whether to trust archivey with archives from strangers and want to know which code
reads them. Maybe an error names a package or program you didn't expect, or a file was recognized
as a different format than you thought. The page follows what happens when you open an archive and
read from it: how archivey recognizes the format, reads the archive's structure, and decodes the
data. For why the defaults are the way they are, see [Philosophy](philosophy.md).

## Recognizing the format

Archivey decides the format from the file's contents first. Most formats start with a fixed
signature. Some keep it further in, as ISO images do at 32 KiB, or behind a program stub, as
self-extracting archives do. A single compressed file such as a `.gz` is also checked for a TAR
header inside, so a tarball named `.gz` opens as a `.tar.gz`. The name is used only when the
contents don't settle it.

A few formats, such as raw zlib, LZMA alone and Brotli, have no signature, or one too weak to
identify them. Archivey recognizes them by trying to decode the start of the data, which is called a
probe. A probe can mistake other data for one of these formats, because the start of an unrelated
file sometimes decodes without an error. So a probe runs only when the file's extension names that
format, when you set `always_probe_content=True`, or when you call `open_stream()`.
`detect_format()` runs the same steps without opening the archive.

## Reading the archive's structure

Once the format is known, a parser reads the archive's structure: the list of members, their names,
sizes and times, and where each one's data starts. Archivey has its own parsers for ZIP, TAR, 7z and
RAR, and uses pycdlib for ISO images. All of them are written in Python, so parsing a malicious
archive can result in wrong data but can't corrupt memory.

Its own parsers mean every format follows the same rules for metadata, and any archive, solid ones
included, can be read in a single forward pass with `stream_members()`.

In archivey's tests, the ZIP, TAR, 7z and RAR parsers are checked against zipfile, tarfile, py7zr,
rarfile and `unrar`, comparing both metadata and bytes. Archivey never imports zipfile, tarfile,
py7zr or rarfile at run time. For each format's details, see the [format
handbooks](https://github.com/archivey-dev/archivey/tree/main/dev-docs/formats) and the [library
analysis](https://github.com/archivey-dev/archivey/blob/main/dev-docs/library-analysis.md), both written
for people working on archivey itself.

## Decoding member data

Many formats share the same compression methods. LZMA appears in 7z, `.xz` and `.tar.xz`, and
DEFLATE in ZIP, 7z and gzip. Archivey implements each method once, as a stream that decodes another
stream, and each format reader stacks the streams a member needs. A method therefore behaves the
same, with the same limits and checks, whichever format it comes in. As the data passes, the stack
also computes the checksum the format recorded, where it records one, and compares it when the
member's last byte comes out.

The decoders come from three places. Python's standard library covers zlib, bzip2 and LZMA, and
Zstandard on Python 3.14 and later. The `[recommended]` extra includes third-party packages that add
support for PPMd, Deflate64, Brotli, LZ4, Zstandard on older Pythons, and AES encryption. Archivey's
own Python code handles `.Z` files, the 7z BCJ2, ARM64 and RISC-V filters, the legacy LZ4 frame, and the
wrapping around each compressed stream in formats such as gzip and xz. Some decoders written in C
can crash on bad data, so archivey runs those in a child process, and can run every decoder in one.
[Security](security.md#decoders-in-a-child-process) says which.

RAR is the exception. No good library decodes it, so archivey decompresses RAR data by running an
external program, `unrar`, `rar` or `unar`, and reading its output through a pipe, as the rarfile
library does. Archivey still reads the RAR structure with its own parser, and reads members stored
without compression or encryption itself. The [decision
record](https://github.com/archivey-dev/archivey/blob/main/dev-docs/decisions/0002-native-rar-metadata-unrar-data.md)
explains the choice.

Compressed data can't be read starting from the middle, so a seek inside a member takes one of three
routes. Without help, archivey decompresses the member again from its start, or from where it
already is if the target is ahead. Some formats record where they can be restarted: xz keeps an
index of its blocks, so a seek starts decoding at the nearest block before the target. For bzip2
data, and large DEFLATE data such as gzip files, the `seekable` extra adds an accelerator that marks
restart points as it reads, and later seeks resume from the nearest one. [Seeking inside a
member](reading.md#seeking-inside-a-member) says what decoding again from the start and the
accelerator mean for the checksum.
