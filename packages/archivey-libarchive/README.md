# archivey-libarchive

Formats that [archivey](https://pypi.org/project/archivey/) reads through the system
[libarchive](https://libarchive.org/), for archives archivey has no reader of its own for.
Today that is LHA (`.lzh`, `.lha`), the format of many old Japanese and Amiga archives.

```python
import archivey
import archivey_libarchive

archivey_libarchive.register()
with archivey.open_archive("old.lzh") as archive:
    for member in archive.members():
        print(member.name, member.size)
    archive.extract_all("out")
```

After `register()`, `open_archive`, `detect_format` and `format=` know the format in that
process, and archivey applies its usual name checks, limits, link handling and
safe extraction to what libarchive reads.

## Requirements

- libarchive 3.6 or later, installed on the system: `apt install libarchive13`,
  `dnf install libarchive`, `brew install libarchive`, or conda-forge's `libarchive`.
  This package does not bundle it. Set `LIBARCHIVE` to the library file to use another
  one.
- The same archivey version as this package's: it uses `archivey.formats`, which any
  archivey release may change.

## What to expect

- libarchive is C code reading untrusted bytes, so it runs in a child process, one per
  pass over an archive, unless you set `ArchiveyConfig(process_isolation=ProcessIsolation.NONE)`.
  A crash there raises `CorruptionError`; the child being killed (most often by the
  out-of-memory killer) raises `ResourceUnavailableError`.
- libarchive reads forward only, so a member read out of order walks the archive again
  from the start, as in a solid archive.
- libarchive checks each LHA member's CRC-16, and a mismatch raises `CorruptionError`.
  archivey never sees the checksum itself, so members carry no `hashes`.
- libarchive reports errors as messages, so whether one is a `TruncatedError`, a
  `CorruptionError` or an `UnsupportedFeatureError` is read from the message.
- `DecoderLimits` do not reach inside libarchive.
- LHA names: libarchive reads a name in an old header as UTF-8 when it is valid and as
  CP932 (Japanese) otherwise. Pass `encoding=` for any other charset, such as
  `encoding="latin-1"` for an Amiga archive; valid UTF-8 names still win.
- LHA times: old headers (levels 0 and 1) store a local time with no zone, which comes
  out as a naive `datetime`, as in ZIP. Newer headers store UTC.
- LHA owners and permissions: a header that stores none gives `mode`, `uid` and `gid`
  of `None`.
