# archivey

[![CI](https://github.com/archivey-dev/archivey/actions/workflows/ci.yml/badge.svg?branch=main&event=schedule)](https://github.com/archivey-dev/archivey/actions/workflows/ci.yml?query=branch%3Amain+event%3Aschedule)

Python library for reading, streaming, and safely extracting archives (ZIP, TAR, RAR, 7z, ISO, and more) through a unified interface.

## Features

- **One interface for every format:** ZIP, TAR (plain or compressed with any of the
  single-file formats below), 7z, RAR, ISO 9660, SquashFS, CPIO, ar (static libraries,
  `.deb`), RPM packages, makeself `.run` installers, Microsoft cabinets, XAR (macOS
  `.pkg`), LHA (`.lzh`), ARJ, plain directories, and single-file streams (gzip, bzip2,
  bzip3, xz, lzip, LZMA, zstd, lz4, Firefox's mozlz4, LZO, zlib, Brotli, Unix compress).
  List members, read one, or stream them all in one pass, the same way for each.
- **Automatic format detection** from the file's content, so a misnamed file still opens.
- **Safe extraction by default:** path traversal, symlink and hardlink escapes, special
  files and archive bombs are blocked unless you opt out.
- **Resource limits** on listing size, decoder memory, password key-derivation work and
  temporary files, so a hostile archive fails with `ResourceLimitError` instead of
  exhausting the machine.
- **Verified reads:** a member whose stored checksum fails raises `CorruptionError`,
  and the bad chunk is withheld. Reading past a truncation raises `TruncatedError`.
  Integrity errors come from reads, never from `close()`.
- **Built for streaming:** `stream_members()` hands out each member as a stream, in
  archive order and in one pass, so a solid 7z or RAR is decoded once and a large member
  is read in chunks rather than held in memory. TAR, ZIP, cpio, ar, deb, RPM, makeself
  and the single-file formats can also be read straight from a pipe.
- **Remote archives:** an archive on S3, an HTTP server or another store reached through
  [fsspec](https://filesystem-spec.readthedocs.io/) opens without a download. Listing a ZIP or 7z
  archive there, or reading a member of a ZIP, fetches little more than the bytes it needs. The
  `archivey://` protocol shows an archive's members as files to any fsspec user, such as pandas.
- **Encrypted archives:** ZipCrypto and WinZip AES in ZIP, AES in 7z, and RAR encryption.
- **Native 7z and RAR metadata readers.** 7z data decodes in-process; RAR data needs
  RARLAB `unrar` or `rar`, or `unar`.
- **Zero-dependency core** for ZIP, TAR, 7z with the common codecs, RAR listing,
  directories and the standard-library codecs,
  plus an `archivey` command for listing, testing and extracting from the shell.
- Tested on Python 3.11 to 3.15 on Linux, and on 3.11 and 3.15 on macOS and Windows.

The API is not frozen until 1.0, but no large changes are expected. Until then, a removed or
renamed name warns for one minor release before it goes ([versioning and
stability](https://archivey-dev.github.io/archivey/how-it-is-built/#versioning-and-stability)).

## Install and use

```bash
pip install archivey                 # zero-dependency core
pip install "archivey[recommended]"  # every format and codec that installs everywhere
```

```python
import archivey

# Extract safely: traversal, link escapes and bombs are blocked by default.
# A refused member isn't written; once the rest are, FilterRejectionError is
# raised with the full report. abort_on makes the first refusal raise at once.
with archivey.open_archive("untrusted.zip") as reader:
    reader.extract_all("out/", abort_on=["blocked_member"])

# List and read members, whatever the format.
with archivey.open_archive("photos.tar.gz") as reader:
    for member, stream in reader.stream_members():
        if member.is_file:
            print(member.name, len(stream.read()))
```

## Documentation

**<https://archivey-dev.github.io/archivey/>**

The [cheat sheet](https://archivey-dev.github.io/archivey/cheat-sheet/) has the main calls, their errors
and the zipfile and tarfile equivalents on one page.
Coding agents can read the docs as Markdown, starting from
[llms.txt](https://archivey-dev.github.io/archivey/llms.txt), or all in one file from
[llms-full.txt](https://archivey-dev.github.io/archivey/llms-full.txt).

[Install](https://archivey-dev.github.io/archivey/install/) ·
[Opening an archive](https://archivey-dev.github.io/archivey/opening/) ·
[Choosing how to read](https://archivey-dev.github.io/archivey/reading/) ·
[Remote archives](https://archivey-dev.github.io/archivey/remote/) ·
[Extracting](https://archivey-dev.github.io/archivey/extracting/) ·
[Security](https://archivey-dev.github.io/archivey/security/) ·
[Formats and extras](https://archivey-dev.github.io/archivey/formats/) ·
[Migrating from other libraries](https://archivey-dev.github.io/archivey/migrating/) ·
[API reference](https://archivey-dev.github.io/archivey/api/)

## How it is built

Almost all of archivey's code, tests and documentation are written by AI coding agents
(Claude Code and Cursor). The maintainer designs the library, makes the decisions,
directs the work and reviews the code, especially the architecture and the tricky parts.
Changes are tested on Linux, macOS and Windows and reviewed by a separate AI session
that reads them from zero, and several reviews of the whole codebase hunt for bugs,
unclear or dead code, and API problems. If you are wary of AI-written code, that is
reasonable: [How it is built](https://archivey-dev.github.io/archivey/how-it-is-built/) says
how changes are made and checked, and what the process does not promise.

## Contributing and security

- **[CONTRIBUTING.md](https://github.com/archivey-dev/archivey/blob/main/CONTRIBUTING.md)** — coding / testing standards
- **[VISION.md](https://github.com/archivey-dev/archivey/blob/main/VISION.md)** — priorities and trade-offs; authoritative contracts live in `openspec/specs/`
- **[SECURITY.md](https://github.com/archivey-dev/archivey/blob/main/SECURITY.md)** — private vulnerability reporting
- **[Issues](https://github.com/archivey-dev/archivey/issues/new/choose)** — bug reports and feature requests, each with its own form
