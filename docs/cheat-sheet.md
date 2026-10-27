# Cheat sheet

The calls most code needs, what each returns and raises, and how they map from `zipfile` and
`tarfile`. Each section links to the page with the details.

## The main calls

```python
import archivey

# Open any supported format. The format comes from the file's contents.
with archivey.open_archive("photos.zip") as archive:
    names = [member.name for member in archive]  # list, in archive order
    member = archive.get("notes.txt")            # ArchiveMember, or None
    data = archive.read("holiday/beach.jpg")     # bytes
    with archive.open("holiday/video.mp4") as stream:  # binary file object
        first_kb = stream.read(1024)

# Read every member in one pass, in archive order.
with archivey.open_archive("backup.tar.gz") as archive:
    for member, stream in archive.stream_members():
        if member.is_file:
            print(member.name, len(stream.read()))

# Extract safely.
with archivey.open_archive("download.zip") as archive:
    report = archive.extract_all("out/")

# Decompress a single file, such as a .gz.
with archivey.open_stream("notes.txt.gz") as stream:
    data = stream.read()  # bytes

# Identify the format without opening the archive.
info = archivey.detect_format("backup.tar.gz")
print(info.format)  # ArchiveFormat.TAR_GZ
```

What each call returns, and the errors you're most likely to meet. The
[next section](#exceptions) has all of them.

- **`open_archive(source)`** returns an [`ArchiveReader`][archivey.ArchiveReader], to use in a
  `with` block. `source` is a path, a binary file object or a folder. A missing file raises
  `FileNotFoundError`, and a file in no format archivey reads raises `FormatDetectionError`. A
  file object that can't seek, such as a pipe, raises `StreamNotSeekableError` unless you pass
  `streaming=True`, which reads TAR, ZIP and single compressed files from one.
  [Opening an archive](opening.md)
- **`for member in archive`** and **`archive.members()`** give
  [`ArchiveMember`][archivey.ArchiveMember] objects. A directory's name ends with `/` in every
  format.
- **`archive.get(name)`** returns the member with that name, or `None`.
- **`archive.read(name)`** returns the member's contents as `bytes`, and
  **`archive.open(name)`** a file object to read them in pieces. Both take a name or an
  `ArchiveMember`. A name the archive doesn't have raises `KeyError`, a directory raises
  `ArchiveyUsageError` unless the archive stored data in it, and a link whose target isn't in
  the archive raises `LinkTargetNotFoundError`. Only one stream from `open` can be open at a
  time, and it can't seek. [Choosing how to read](reading.md) has the options that change both.
- **`archive.stream_members()`** yields `(member, stream)` pairs in archive order. The stream is
  `None` for links and most directories, and works only until the loop moves on.
  [Read everything in one pass](index.md#read-everything-in-one-pass)
- **`archive.extract_all(dest)`** returns an [`ExtractionReport`][archivey.ExtractionReport]
  with one result per member. A refused member, such as `../evil.txt`, is skipped and recorded
  in the report with the status `BLOCKED`, without raising. By default the first member that
  fails raises and ends the extraction: `ExtractionError` for a file already at the destination,
  `CorruptionError` for damaged data. [Extracting](extracting.md)
- **`open_stream(source)`** returns a file object with the decompressed contents. On a
  `.tar.gz` you get the TAR's bytes. A ZIP, 7z, RAR, ISO or plain TAR raises
  `FormatDetectionError`. [Single compressed files](opening.md#single-compressed-files)
- **`detect_format(source)`** returns a [`FormatInfo`][archivey.FormatInfo] with the `format`
  and how sure archivey is about it. A file in no format archivey reads raises
  `FormatDetectionError`. [Format](opening.md#format)

`open_archive(source, streaming=True)` reads the archive once, from start to end, which also
works on a pipe. Its reader has no `members()`, `get()`, `read()` or `open()`: they raise
`ArchiveyUsageError`. [Reading once](reading.md#reading-once)

## Exceptions

```text
ArchiveyError                 problems with the archive or what reading it needs
├── OpenError                 reading could not start
│   ├── FormatDetectionError  not a format archivey reads
│   └── StreamNotSeekableError
├── ReadError
│   ├── CorruptionError       damaged data
│   │   └── TruncatedError    the data seems to end early
│   ├── EncryptionError       password missing or wrong
│   └── LinkTargetNotFoundError
├── ExtractionError           a member could not be written
│   ├── FilterRejectionError  a safety check refused a member
│   ├── NameCollisionError
│   └── NameRewrittenError
├── ResourceLimitError        a limit was reached, such as an archive bomb
├── UnsupportedFeatureError   a recognized format, with something archivey can't read
├── PackageNotInstalledError  an optional package or program is missing
└── DiagnosticRaisedError     a diagnostic turned into an error by DiagnosticPolicy

ArchiveyUsageError            a mistake in the calling code, not an ArchiveyError
```

An argument with a type or value the call can't use raises `ArchiveyUsageError` that is also a
`TypeError` or a `ValueError`. Errors
that aren't about the archive pass through as themselves: `FileNotFoundError`, `OSError` from the
disk, and `KeyError` for a missing name. [Errors and diagnostics](errors-and-diagnostics.md)

```python
try:
    with archivey.open_archive("download.zip") as archive:
        archive.extract_all("checked/")
except archivey.EncryptionError:
    print("Wrong or missing password")
except archivey.ArchiveyError as e:
    print("Could not extract:", e)
```

## Safe defaults

```python
with archivey.open_archive("download.zip") as archive:
    archive.extract_all(
        "defaults/",
        policy="strict",    # portable names; no setuid bits or group and other write
        overwrite="error",  # an existing file fails the member
        on_error="stop",    # the first failed member raises
        limits=archivey.ExtractionLimits(
            max_extracted_bytes=2 * 2**30,  # 2 GiB written in total
            max_ratio=1000.0,               # how much a member, or the archive, may expand
            max_entries=262_144,            # files, folders and links created
        ),
    )
```

These are the defaults. Under every policy, `extract_all` refuses `../` paths, links pointing
outside the destination, and device files. Going over a limit raises `ResourceLimitError`.
[Extracting](extracting.md#options) lists every policy, and
[Archives you trust](extracting.md#archives-you-trust) shows how to relax them.

Reading has limits too, with the same `ResourceLimitError`: a listing stops at 262,144 members,
and an archive can ask a decoder for at most 2 GiB of memory. [Hardening](security.md#hardening) lists them, and
`config=archivey.ArchiveyConfig(...)` changes them.

## From zipfile and tarfile

Each item gives the archivey call first, then the zipfile and tarfile calls it replaces.

- `open_archive(p)`: `ZipFile(p)`, `tarfile.open(p)`.
- `[m.name for m in archive]`: `zf.namelist()`, `tf.getnames()`.
- `archive.members()`: `zf.infolist()`, `tf.getmembers()`.
- `archive.get(n)`, which returns `None` for a missing name: `zf.getinfo(n)`,
  `tf.getmember(n)`.
- `archive.read(n)`: `zf.read(n)`, `tf.extractfile(n).read()`.
- `archive.open(n)`: `zf.open(n)`, `tf.extractfile(n)`.
- `archive.stream_members()`: a loop over `zf.open(info)`, or `for info in tf:` with
  `tf.extractfile(info)`.
- `archive.extract_all(d)`: `zf.extractall(d)`, `tf.extractall(d)`.
- `open_archive(p, password=pw)`: `zf.setpassword(pw)`.
- `detect_format(p)`: `is_zipfile(p)`, `is_tarfile(p)`.
- `CorruptionError` or `FormatDetectionError`: `BadZipFile`, `tarfile.ReadError`.
- `member.name`: `info.filename`, `info.name`.
- `member.size`: `info.file_size`, `info.size`.
- `member.is_dir`: `info.is_dir()`, `info.isdir()`.
- `member.modified`, a `datetime`: `info.date_time`, `info.mtime`.

For a single compressed file, `open_stream(p)` replaces `gzip.open(p)`, `bz2.open(p)` and
`lzma.open(p)`. [Migrating from other libraries](migrating.md) covers py7zr and rarfile, and what
behaves differently.
