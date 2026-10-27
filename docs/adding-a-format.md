# Adding a format

archivey reads a fixed set of formats, and a program can add one more of its own with
`archivey.plugins`. A format added this way works with `open_archive`, `detect_format`,
`format=`, `format_availability`, the format lists, extraction and the `archivey` command,
as the built-in formats do.

!!! warning "Provisional"
    `archivey.plugins` can change in a minor release until a plugin outside archivey has
    used it. Pin the archivey version your plugin is tested with.

This first version reads one kind of format: a format with an index, where the reader can
list every member first and then open any one of them, from a file or another source that
can seek. ISO 9660, SquashFS, CAB and WIM are this kind. Formats read as one pass from
start to end, such as CPIO or AR, and formats inside an outer compressor, such as a
`.cpio.gz`, come in a later version. [What is not supported yet](#what-is-not-supported-yet)
has the full list.

## What a plugin is

A plugin is two classes:

- A **`FormatPlugin`** subclass. Its class attributes say what the format is called and
  how to recognise it: an `ArchiveFormat`, file extensions, and magic bytes. Its `open()`
  method returns a reader.
- An **`IndexedReader`** subclass. It lists the members with `iter_members()`, and returns
  the data of one member with `open_member()`.

The plugin hands archivey members and bytes. archivey does everything after that the
same way it does for a built-in format: it normalizes member names, checks them, applies
the listing limits, resolves links, checks each member's size and checksum as it is read,
and extracts safely.

## A complete example

The example format here, TOYA, is small enough to read in full. A TOYA file starts with
the 8 bytes `TOYARC1\n` and a 4-byte member count. One index entry per member follows: the
name, a directory flag, the size, a CRC-32 and the offset of the data. The data of all
members comes after the index. All numbers are little-endian.

```python
import struct
from collections.abc import Iterator

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    HashAlgorithm,
    MemberType,
    PluginContainer,
    StreamFormat,
    TruncatedError,
)
from archivey.plugins import (
    FormatPlugin,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    PluginContext,
    PluginSource,
    register_format,
)


class ToyContainer(PluginContainer):
    TOYA = "toya"


TOYA = ArchiveFormat(ToyContainer.TOYA, StreamFormat.UNCOMPRESSED)

# Where a member's data is: (offset, length).
Locator = tuple[int, int]


class ToyReader(IndexedReader[Locator]):
    def __init__(self, source: PluginSource, context: PluginContext) -> None:
        self._source = source
        self._context = context
        head = source.read_at(0, 12)
        if len(head) < 12:
            raise TruncatedError("the TOYA index is cut short")
        (self._count,) = struct.unpack_from("<I", head, 8)

    def iter_members(self) -> Iterator[MemberRecord[Locator]]:
        pos = 12
        for _ in range(self._count):
            (name_len,) = struct.unpack("<H", self._source.read_at(pos, 2))
            raw_name = self._source.read_at(pos + 2, name_len)
            is_dir, size, crc, offset = struct.unpack(
                "<BIIQ", self._source.read_at(pos + 2 + name_len, 17)
            )
            pos += 2 + name_len + 17
            member = ArchiveMember(
                type=MemberType.DIRECTORY if is_dir else MemberType.FILE,
                name=self._context.decode_name(raw_name),
                raw_name=raw_name,
                size=0 if is_dir else size,
                hashes={} if is_dir else {HashAlgorithm.CRC32: crc.to_bytes(4)},
            )
            yield MemberRecord(member, locator=(offset, size))

    def open_member(self, member: ArchiveMember, locator: Locator) -> MemberData:
        offset, size = locator
        return MemberData(self._source.view(offset, size))


class ToyPlugin(FormatPlugin):
    format = TOYA
    extensions = (".toya",)
    magic = (Magic(0, b"TOYARC1\n"),)
    uses_encoding = True

    def open(self, source: PluginSource, context: PluginContext) -> ToyReader:
        return ToyReader(source, context)


register_format(ToyPlugin)
```

After `register_format`, a TOYA file opens like any other archive:

```python
import archivey

with archivey.open_archive("photos.toya") as archive:
    for member in archive.members():
        print(member.name, member.size)
    archive.extract_all("out/")
```

`detect_format("photos.toya").format` is `TOYA`, and `format="toya"` opens a TOYA file
whatever its name is.

## The format's identity

A format is an `ArchiveFormat`, a pair of a container and a stream. A plugin defines its
container as a member of its own `PluginContainer` subclass, and uses
`StreamFormat.UNCOMPRESSED` as the stream. The container's value and its member name are
the format's names in `format=` and on the command line, so neither may already name a
format: not a built-in one (`"zip"`, `"tar.gz"`, `"TAR_GZ"` and the others) and not
another plugin's. `register_format()` refuses a plugin whose name is taken.

Code that matches on `ArchiveFormat.container` needs a default case once a plugin is
registered, because the set of containers is no longer only `ContainerFormat`.

## Listing members

`iter_members()` yields one `MemberRecord` per member, in archive order, and must yield
the same members in the same order if archivey calls it again.

Each record holds an `ArchiveMember` and a locator. The member carries the public fields
your format stores: at least `type`, `name` and, for a file, `size`. The name is decoded
but not cleaned up. archivey normalizes it (`./a//b` becomes `a/b`) and reports
`MEMBER_NAME_NORMALIZED` when that changes it, as for a built-in format.
`PluginContext.decode_name()` decodes stored bytes the way the built-in formats do: valid
UTF-8 wins, then the caller's `encoding=`, then UTF-8 with no byte lost.

The locator is anything your reader needs to find the member's data again: an offset, a
tuple, or an object from the library you wrap. archivey keeps it and hands it back to
`open_member()` without looking inside. `IndexedReader[Locator]` tells a type checker what
it is, so `open_member()` gets a `tuple[int, int]` and not an `object`.

Set `member_list_upfront = False` on the reader when `iter_members()` reads headers from
all through the file, not from one index. archivey then reports the listing as needing a
scan in `archive.cost`.

## Reading member data

`open_member()` returns a `MemberData` with a stream of the member's bytes, decoded and
read from the start. archivey closes the stream.

The stream does not need to seek. When the caller opens the archive with
`seekable_members=True` and the stream cannot seek, archivey seeks for it: a forward seek
reads the bytes in between, and a backward seek calls `open_member()` again and reads
forward from the start, which is slow for a large member. When the listing gives no
`size`, a seek from the end reads to the end once to find it.

`PluginSource.view(start, length)` gives a stream over part of the archive with its own
position, so two members open at the same time do not move each other. A format that
stores members uncompressed returns a view directly, as TOYA does.

A format that compresses each member with a method archivey already decodes hands the
member's compressed bytes to `PluginContext.decompress()`, and returns what it gives:

```python
def open_member(self, member: ArchiveMember, locator: Locator) -> MemberData:
    offset, compressed_size = locator
    data = self._source.view(offset, compressed_size)
    return MemberData(
        self._context.decompress(data, CompressionAlgorithm.DEFLATE, size=member.size)
    )
```

It decodes raw Deflate, Deflate64, bzip2, Zstandard and LZ4 frames, Brotli, and raw
LZMA and LZMA2 (with the `properties` bytes the format stores). It uses the caller's
decoder limits, process isolation and accelerator settings, and turns the decoder's
errors into archivey's own. Bytes left after the end of the compressed data raise
`CorruptionError`. A method whose optional package is missing raises
`PackageNotInstalledError`.

A format whose methods archivey does not decode wraps the view in its own library's
decoder.

archivey checks every member stream against what the listing said:

- **Size.** A stream that ends before `member.size` raises `TruncatedError`, and one that
  runs past it raises `CorruptionError`. A file listed with no size is read to the end
  of its stream, and only its checksums are checked.
- **Checksums archivey can compute.** A CRC-32 or BLAKE2sp in `member.hashes`, or in
  `MemberData.expected_hashes`, is checked as the stream is read. A mismatch raises
  `CorruptionError`, and a full read with a match reaches `Verification.CONTENT`.
- **Checksums archivey has no hasher for.** For a CRC-16, a SHA-1 or any other
  checksum, put a `MemberDigest` in `MemberData.digests`: its name, the stored value,
  and a function that makes a fresh hasher, such as `hashlib.sha1`. A hasher is any
  object with `update(bytes)` and `digest()`. archivey feeds it the bytes as they are
  read, and checks the result the same way as a CRC-32:

  ```python
  return MemberData(
      self._source.view(offset, size),
      digests=(MemberDigest("sha1", stored_sha1, hashlib.sha1),),
  )
  ```

- **Checksums the stream checks itself.** If the stream your library returns checks
  its own checksum and raises when it does not match, set `checked=True` on the
  `MemberData`. A read to the end then counts as `Verification.CONTENT` too.

Whichever way a checksum archivey has no name for is checked, keep the stored value in
`member.extra` under a key named after your format, such as `"toya.sha1"`, so callers
can see it.

## Errors

When the archive is damaged, raise archivey's own exceptions from the reader:
`CorruptionError` for bytes that cannot be right, `TruncatedError` for an archive that
ends too early, and `UnsupportedFeatureError` for a feature your reader does not handle.

An exception from a library you wrap can go through `translate_exception()`. It is asked
about every exception raised while archivey calls the reader, and while a member stream
it returned is read. Errors from `PluginContext.decompress()` are archivey's own already
and never reach it. Return the
archivey exception to raise in its place, or `None` to let it propagate as it is:

```python
def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
    if isinstance(exc, somelib.BadArchive):
        return archivey.CorruptionError(str(exc))
    return None
```

## Archive details

`archive_info()` returns a `PluginArchiveInfo` with what archivey cannot work out itself:
whether members share one decode (`is_solid`), a format version, a comment, and extra
values under keys named after your format. A key a built-in format already defines,
such as `7z.volume_count`, is not yours to write. archivey fills in the rest of
`archive.info`.

## Detection

archivey recognises a plugin's format by its `magic`, its `extensions`, and an optional
`probe`:

- A **magic** is exact bytes at an offset. It counts only when no built-in format's magic
  matched, so registering a plugin never changes how a file archivey already reads is
  detected.
- An **extension** that a built-in format uses is refused at registration.
- A **probe** is a function that takes the first bytes of the source and returns `True`
  for your format. It gets only the bytes detection has already read, and runs after
  every built-in check. Like a built-in format's probe, it runs only when the source's
  name has one of your extensions, or when `ArchiveyConfig(always_probe_content=True)`
  is set. Use it only for a format with no fixed signature.

`FormatInfo.from_plugin` is `True` when detection chose a plugin's format.

## Optional dependencies

A plugin that wraps a library names its modules in `requires` and what to install in
`install_hint`:

```python
class SquashPlugin(FormatPlugin):
    requires = ("PySquashfsImage",)
    install_hint = "pip install PySquashfsImage"
```

When a module is missing, `format_availability()` reports the format as
`FormatSupport.NONE` with the hint, and opening a file of that format raises
`PackageNotInstalledError`, as for a built-in format whose extra is not installed.

A library that needs a file name rather than a stream can use `PluginSource.path`, which is
the path the archive was opened from, or `None` when it was opened from a stream.

## Registration and trust

`register_format()` is the only way to add a format: nothing is loaded automatically
because a package is installed. The program that calls it chooses which parsers read its
input.

A plugin's code runs in your process like any other import. archivey's limits cover what
the plugin hands over: listing limits, member names, extraction limits, and the size and
checksum checks on member data. They cannot cover the plugin's own parser, which could use
unbounded memory or crash on a crafted file. A program that reads untrusted archives can
refuse plugin formats by checking `FormatInfo.from_plugin`.

## What is not supported yet

- Formats read in one pass from start to end, and reading a plugin format from a pipe.
- A plugin format inside an outer compressor, such as `.cpio.gz`.
- Self-extracting archives, multi-volume sets and passwords.
- Diagnostics from the plugin, such as an invalid timestamp. A plugin cannot add new
  diagnostic codes.
- Writing archives.
