# Adding a format

archivey reads a fixed set of formats, and a program can add one more of its own with
`archivey.plugins`. A format added this way works with `open_archive`, `detect_format`,
`format=`, `format_availability`, the format lists, extraction and the `archivey` command,
as the built-in formats do.

!!! warning "Provisional"
    `archivey.plugins` can change in a minor release until a plugin outside archivey has
    used it. Pin the archivey version your plugin is tested with.

A plugin reads one of two kinds of format:

- **A format with an index**, where the reader can list every member first and then open
  any one of them, from a file or another source that can seek. ISO 9660, SquashFS, CAB
  and WIM are this kind.
- **A format read in one pass**, a header and then the member's data, again and again to
  the end. It can be read from a pipe. CPIO and AR are this kind. See
  [Formats read in one pass](#formats-read-in-one-pass).

A format read in one pass can also be read inside a compressor, such as a `.cpio.gz`,
with no extra code; see [Inside a compression stream](#inside-a-compression-stream).
[What is not supported yet](#what-is-not-supported-yet) lists what a plugin cannot do.

## What a plugin is

A plugin is two classes:

- A **`FormatPlugin`** subclass. Its class attributes say what the format is called and
  how to recognise it: an `ArchiveFormat`, file extensions, and magic bytes. Its `open()`
  method returns a reader.
- An **`IndexedReader`** subclass. It lists the members with `iter_members()`, and returns
  the data of one member with `open_member()`.

A format read in one pass uses a `SequentialFormatPlugin` and a `SequentialReader`
instead, described in [Formats read in one pass](#formats-read-in-one-pass). The rest of
this page applies to both kinds unless it says otherwise.

The plugin hands archivey members and bytes. archivey does everything after that the
same way it does for a built-in format: it normalizes member names, checks them, applies
the listing limits, resolves links, checks each member's size and checksum as it is read,
and extracts safely.

Three complete plugins outside archivey are in the repository:
[`packages/archivey-squashfs`](https://github.com/archivey-dev/archivey/tree/main/packages/archivey-squashfs)
for SquashFS images, a format with an index;
[`packages/archivey-cpio`](https://github.com/archivey-dev/archivey/tree/main/packages/archivey-cpio)
for CPIO archives and
[`packages/archivey-ar`](https://github.com/archivey-dev/archivey/tree/main/packages/archivey-ar)
for ar archives (static libraries), both read in one pass. None is published.

## A complete example

The example format here, TOYA, is small enough to read in full. A TOYA file starts with
the 8 bytes `TOYARC1\n` and a 4-byte member count. One index entry per member follows: the
name, a directory flag, the size, a CRC-32 and the offset of the data. The data of all
members comes after the index. All numbers are little-endian.

```python
from collections.abc import Iterator

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    HashAlgorithm,
    MemberType,
    PluginContainer,
    StreamFormat,
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
        # read_struct() and read_exact() raise TruncatedError when the archive ends
        # early, where struct.unpack() would fail on the short read with an error of
        # its own.
        (self._count,) = source.read_struct(8, "<I")

    def iter_members(self) -> Iterator[MemberRecord[Locator]]:
        pos = 12
        for _ in range(self._count):
            (name_len,) = self._source.read_struct(pos, "<H")
            raw_name = self._source.read_exact(pos + 2, name_len)
            is_dir, size, crc, offset = self._source.read_struct(
                pos + 2 + name_len, "<BIIQ"
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

`open_member()` returns a `MemberData`. Its `stream` holds the member's bytes, decoded
and read from the start. archivey closes the stream when the caller is done with it. The
other fields say how archivey can check those bytes, as described in
[What archivey checks](#what-archivey-checks).

### Where the bytes come from

There are four ways to build the stream. Pick the first one that fits your format.

**Stored bytes.** `PluginSource.view(start, length)` is a stream over part of the archive
with its own position, so two members open at the same time do not move each other. A
format that stores members uncompressed returns a view, as TOYA does.

**A compression method archivey decodes.** Hand the member's compressed bytes to
`PluginContext.decompress()` and return what it gives:

```python
def open_member(self, member: ArchiveMember, locator: Locator) -> MemberData:
    offset, compressed_size = locator
    data = self._source.view(offset, compressed_size)
    return MemberData(
        self._context.decompress(data, CompressionAlgorithm.DEFLATE, size=member.size)
    )
```

`decompress()` takes one of these methods:

- raw Deflate and Deflate64;
- bzip2;
- Zstandard and LZ4 frames;
- Brotli;
- raw LZMA and LZMA2, with the `properties` bytes the format stores;
- XZ, for `.xz` data kept inside a member, as ZIP method 95 keeps it;
- `STORED`, for data kept as is, so a format with a per-member method can pass every
  method through the same call.

It also takes a `StreamFormat` in place of a method. The data is then a whole stream with
its own framing, decoded the way a file of that format is: `StreamFormat.ZLIB` for
Deflate with the zlib header, and `GZIP`, `XZ`, `LZMA_ALONE`, `LZIP` and the rest.

The decoding uses the caller's decoder limits, process isolation and accelerator
settings. It turns the decoder's errors into archivey's own, so your
`translate_exception()` never sees them. A method whose optional package is missing
raises `PackageNotInstalledError`, and a method not in the list above raises
`UnsupportedFeatureError`.

Where the compressed data ends depends on the method:

- **Zstandard and LZ4** data may be several frames, and all of them are decoded.
- **XZ** data may be several xz streams, with stream padding (groups of four zero bytes)
  between and after them, and all of them are decoded.
- **bzip2** data is one stream, and a second stream after it raises `CorruptionError`.
- **LZMA and LZMA2** end at their end marker. Raw LZMA1, which may have none, then ends
  at `size`.
- For every method, bytes left after that end raise `CorruptionError`.
- A **stream format** ends where its format says. Bytes after that end are reported as
  `ARCHIVE_TRAILING_DATA`, as they are for a file of that format.

**A file in independent blocks.** Some formats store a file as fixed-size blocks, each
compressed on its own, so a reader can start at any block: SquashFS, CAB, WIM and CSO all
do this. Return `block_stream(size, block_size, read_block)`, where `read_block(i)` returns
block `i` decoded. archivey takes care of the rest:

- it calls `read_block` when a read first needs a block, and keeps only the current one;
- it handles reads that cross from one block into the next;
- a seek decodes only the block it lands in, not the file up to it;
- a block of the wrong length raises `CorruptionError`.

`read_block` may return the stream `decompress()` gives rather than bytes. archivey then
asks it for one byte more than the block's length and refuses the block if it gets it.
How much the stream decodes to answer is the stream's own: a decoder that buffers decodes
up to its buffer, so keep that buffer near the block size. The SquashFS package's `read_block`
is short: it reads the block list as far as it needs, returns zeros for a sparse block,
and decodes the rest. Its first branch returns the file's tail, which SquashFS keeps in a
fragment block shared with other files: `read_block` only has to return the right bytes
for each index, wherever the format stores them.

**Your own decoder.** For a method archivey does not decode, wrap the view in your
library's decoder, or one of your own. Such a decoder is outside archivey's decoder
limits, so it must stop at the size the format allows: pass the expected output size and
refuse anything longer. The SquashFS package does this for its LZ4 and LZO blocks, which
can never be larger than one block.

### Seeking and short reads

The stream does not need to seek. When the caller opens the archive with
`seekable_members=True` and the stream cannot seek, archivey seeks for it:

- a forward seek reads the bytes in between;
- a backward seek calls `open_member()` again and reads forward from the start, which
  is slow for a large member;
- when the listing gives no `size`, a seek from the end reads to the end once to find it.

A view and a `block_stream()` seek by themselves, and cheaply. A `decompress()` result
seeks by itself too, but a backward seek decodes again from the start, as the fallback
does.

A raw stream may also return fewer bytes than asked before it ends, as an `io.RawIOBase`
may. One that stops each read at the end of a block is an example. archivey asks it again
for the rest, and reads nothing ahead. An `io.BufferedIOBase` is taken at its word, as
that class promises full reads until the end, and so are the streams archivey hands out
(a view, a `decompress()` result, `block_stream()`). For a raw stream whose reads cost more than a
copy, such as one call into a library per read, return `buffered_stream(stream)`, which
puts an `io.BufferedReader` in front of it. Closing that also closes the stream it wraps.

### What archivey checks

archivey checks every member stream against what the listing said.

- **Size.**
    - A stream that ends before `member.size` raises `TruncatedError`, and one that runs
      past it raises `CorruptionError`.
    - A file listed with no size is read to the end of its stream, and only its
      checksums are checked.
    - To find out whether a stream runs past the size, archivey reads one more byte at
      the end. It skips that read for a view or a `block_stream()` no longer than the
      member, which cannot run past it. For another stream that cannot return more
      than `member.size` bytes, such as your own decoder that stops at the size, set
      `bounded=True` on the `MemberData`. The extra read is a measurable part of
      opening a small member.
- **Checksums in the index.** A CRC-32 or BLAKE2sp the index stores, known when
  listing, goes in `member.hashes`, where callers see it. It is checked as the stream is
  read. A mismatch raises `CorruptionError`, and a full read with a match reaches
  `Verification.CONTENT`.
- **Checksums you read when opening.** A checksum the member's own header stores goes in
  `MemberData.digests`, as a `MemberDigest` with its name and stored value. For a name
  archivey computes (`"crc32"`, `"blake2sp"`) that is all; for a CRC-16, a SHA-1 or any
  other checksum, also pass a function that makes a fresh hasher, such as
  `hashlib.sha1`. A hasher is any object with `update(bytes)` and `digest()`. archivey
  feeds it the bytes as they are read, and checks the result the same way as a CRC-32.
  A CRC-32 or BLAKE2sp given this way that the index does not already store is also
  added to `member.hashes` when the member is opened, so callers see it. For example,
  for a header that stores a CRC-32 and a SHA-1:

    ```python
    return MemberData(
        self._source.view(offset, size),
        digests=(
            MemberDigest("crc32", stored_crc),
            MemberDigest("sha1", stored_sha1, hashlib.sha1),
        ),
    )
    ```

    A name, ignoring case, appears once in `digests`, and one archivey does not compute
    needs a hasher; otherwise opening the member raises `ValueError`. When the index and
    the header both store a CRC-32, put each where it is read: archivey checks both, so
    a read fails when either does not match the data, rather than one replacing the
    other. A field the format leaves unset (a zero CRC in a header whose value comes
    later, say) is left out, not passed: archivey compares whatever value you give it.

- **Checksums the stream checks itself.** If the stream your library returns checks its
  own checksum and raises when it does not match, set `checked=True` on the
  `MemberData`. A read to the end then counts as `Verification.CONTENT` too.

Whichever way a checksum archivey has no name for gets checked, keep the stored value in
`member.extra` under a key named after your format, such as `"toya.sha1"`, so callers can
see it.

## Formats read in one pass

A format of header, data, header, data has no index to list from: the only way to find
the members is to read the archive from the start. Such a format can be read from a pipe,
and a plugin for it has two other classes:

- A **`SequentialFormatPlugin`** subclass. It declares the format as a `FormatPlugin`
  does, but implements `open_sequential(context)` instead of `open()`. There is no
  `PluginSource`, because the archive may be a pipe.
- A **`SequentialReader`** subclass. Its `walk(stream)` is a generator that reads headers
  from a `ForwardStream` and yields one `MemberSpan` per member.

The reader parses headers and archivey owns the data. A `MemberSpan` holds the member
and `data_length`, the number of bytes after the header that are the member's data,
stored as they are. archivey hands those bytes to the caller as the member's stream.
Before it resumes the walk, it skips whatever the caller did not read, so when `walk()`
continues after its `yield`, the stream is at the end of the member's data. The walk then
reads any padding and the next header:

```python
import struct
from collections.abc import Iterator

from archivey import ArchiveMember, CorruptionError, MemberType
from archivey.plugins import (
    ForwardStream,
    MemberDigest,
    MemberSpan,
    SequentialReader,
)

HEADER = struct.Struct("<2scHII")  # magic, type, name length, data length, CRC-32


class ToysReader(SequentialReader):
    link_target_in_data = True  # a symlink's data is its target

    def __init__(self, context):
        self._context = context

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        while True:
            at = stream.offset
            magic, code, name_len, length, crc = stream.read_struct(HEADER)
            if magic != b"TS":
                raise CorruptionError(f"no header at offset {at}")
            if code == b"E":  # the end-of-archive header
                return
            raw = stream.read_exact(name_len)
            kind = {b"F": MemberType.FILE, b"L": MemberType.SYMLINK}[code]
            member = ArchiveMember(
                type=kind, name=self._context.decode_name(raw), raw_name=raw
            )
            digest = MemberDigest("crc32", crc.to_bytes(4, "big"))
            yield MemberSpan(member, length, (digest,))
            stream.skip(-length % 4)  # padding to four bytes
```

A real reader also refuses an unknown type code with `CorruptionError` rather than a
`KeyError`.

`ForwardStream` reads forward only. `read(n)` returns fewer bytes only at the end of the
archive; `read_exact(n)`, `read_struct(fmt)` and `skip(n)` raise `TruncatedError` there
instead. `offset` is how far the archive has been read, for messages. A walk never reads
a member's data itself.

archivey takes the first step of the walk when it opens the archive, so a file that is
not your format fails to open, as a built-in one does. The end of the archive is
`walk()`'s to check: an end marker, a trailer, or bytes after it. Raise
`CorruptionError` or `TruncatedError` when they are wrong, and archivey keeps the members
the walk yielded before it.

What archivey does with the spans:

- **Pipes and passes.** Opened with `streaming=True`, the walk is the reader's one
  forward pass, so `stream_members()`, iteration and `extract_all()` each read the
  archive once, from a pipe too. The listing limits count members as they arrive.
- **Random access on a file.** Opened from a file or a seekable stream without
  `streaming=True`, archivey walks the archive once to list it and records where each
  member's data starts. `open()` and `read()` then read a member directly, in any order.
- **Sizes.** A `FILE`'s `size` is its `data_length`. Leave `size` unset and archivey
  fills it in; a different one raises `ValueError`, since the data is stored as it is.
- **Checksums.** `MemberSpan.digests` are checked as `MemberData.digests` are (see
  [What archivey checks](#what-archivey-checks)). A `HashAlgorithm` digest, such as the
  CRC-32 above, is also listed in `ArchiveMember.hashes`.
- **Link targets stored as data.** With `link_target_in_data = True`, a symlink's data is
  its target. archivey reads it while walking, up to 4096 bytes, as UTF-8. A longer one
  is reported with `SYMLINK_TARGET_UNAVAILABLE` and left unset.
- **Other members' data.** The data of a member that is not a file, a directory or such
  a symlink is skipped. A directory with data keeps it as its `size`: a read delivers
  the bytes, extraction creates the directory, and the listing reports
  `MEMBER_DIRECTORY_DATA_IGNORED`, as for a built-in format.

`SequentialFormatPlugin` takes the same class attributes as `FormatPlugin`. The format's
`archive.info.cost` says the listing needs a scan, and `format_availability()` reports
that it can be read from a source that cannot seek.

### Inside a compression stream

A format read in one pass is often compressed whole, as a `.tar.gz` is: `.cpio.gz`,
`.a.xz`. archivey reads these with no extra code. Registering the format also registers
it inside each compression stream archivey decodes, as
`ArchiveFormat(<your container>, StreamFormat.GZIP)` and so on, and adds your extensions
followed by the compressor's (`.cpio` gives `.cpio.gz`, `.cpio.xz`, `.cpio.zst`, …), as
`format=` spellings too. archivey decodes the stream and `walk()` reads the decoded
bytes, from a file or a pipe.

- **Detection.** A compressed file is first recognised as one gzip or xz member. archivey
  then decodes its first 512 bytes, the same bytes it decodes to find a TAR inside, and
  looks for your `magic` in them. So a sequential format's magic must end within the
  first 512 bytes, and registration refuses one that does not. A format found only by its
  `probe` is not found inside a compressor: name it with its extension or `format=`.
- **Cost.** One compression stream holds every member, so the archive is solid:
  `archive.info.is_solid` is `True`, the listing needs decompression, and with random
  access, reading a member before the last one read decodes again from the start.
- **Limits.** The decoder limits and the decompression-ratio guard apply as for a
  `.tar.gz`, and bytes after the compressed stream are reported with
  `ARCHIVE_TRAILING_DATA`.

### Compression that starts part-way

Some formats store headers and then compress the rest: an RPM package is a few headers
followed by a gzip, xz or zstd stream holding a CPIO archive. A walk reads the headers,
then calls `stream.decompress(StreamFormat.XZ)` and reads on from the stream it returns:

```python
def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
    read_rpm_headers(stream)
    stream = stream.decompress(payload_format)
    yield from walk_cpio(stream)
```

The returned stream holds the decoded bytes, and its `offset` counts them from 0. The
members the walk yields after the call are read from those bytes, from a pipe too, with
random access to them on a file. archivey decodes with its own codecs, under the
caller's decoder limits and the decompression-ratio guard. The stream the walk called
`decompress()` on refuses further reads. archivey cannot know the archive holds a
compression stream before the walk reaches it, so have `archive_info()` return
`PluginArchiveInfo(is_solid=True)`: the cost receipt then says members are read through
one stream, and that listing needs decompression, from the moment the archive opens.
The compressed stream is taken to run to the end of the archive: bytes after its end are
reported with `ARCHIVE_TRAILING_DATA`, not refused.

## Reading untrusted bytes

archivey cannot check how your reader parses the archive, only what it hands back.
These habits keep a crafted file from doing more than raising one of archivey's errors:
`CorruptionError`, `TruncatedError` or `UnsupportedFeatureError`.

- **Read with `PluginSource.read_struct()` and `read_exact()`** wherever the bytes must
  all be there, as the example does. They raise `TruncatedError` when the archive ends
  early. They and `read_at()` are the cheap way to parse: each is one read of the
  archive, with no stream built, and safe from any thread. Keep `view()` for a member's
  data.
- **Check every size and offset against what the format allows** before you allocate or
  read with it. Bound offsets by the format's own structures (a superblock's table
  offsets, an index's declared extent, the bytes a read returned), and also by
  `PluginSource.size` when it is not `None`: it is `None` for a stream whose length
  archivey cannot learn cheaply. Refuse a count or length larger than the format can
  hold, and bound a count the format leaves wide open by `config.listing_limits`.
- **Walk trees with a loop and a set of what you have seen**, not recursion. A directory
  that lists itself is then an error, not a hang.
- **Validate names** before you yield them. A name with `/` in a format that stores one
  path component per entry is damage. archivey checks the final path in any case.
- **Cap every decode** at the size the format allows, as
  [Where the bytes come from](#where-the-bytes-come-from) describes for a decoder of
  your own.
- **Raise archivey's exceptions** for damage, and let your own bugs propagate, as
  [Errors](#errors) describes.

The SquashFS package's tests show a way to test this. They take an image `mksquashfs`
wrote, change one field (a block size, a fragment index, a directory entry's type) and
check that each change raises `CorruptionError`, `TruncatedError` or
`UnsupportedFeatureError`.

## Errors

When the archive is damaged, raise archivey's own exceptions from the reader:
`CorruptionError` for bytes that cannot be right, `TruncatedError` for an archive that
ends too early, and `UnsupportedFeatureError` for a feature your reader does not handle.

An exception from a library you wrap can go through `translate_exception()`. It is asked
about every exception raised while archivey calls the reader, and while a member stream
it returned is read. Errors from `PluginContext.decompress()` are archivey's own already
and never reach it. Return the archivey exception to raise in its place, or `None` to
let it propagate as it is:

```python
def translate_exception(self, exc: Exception) -> archivey.ArchiveyError | None:
    if isinstance(exc, somelib.BadArchive):
        return archivey.CorruptionError(str(exc))
    return None
```

Define it on the `FormatPlugin` to cover `open()` too, where there is no reader yet. The
plugin's `translate_exception()` is also asked about anything the reader's returns
`None` for, so a translation that needs nothing from the open archive is written once,
on the plugin.

## Reporting problems that do not stop the read

Some damage is worth telling the caller about without refusing the archive: a date that
is not a date, a header field that had to be skipped, bytes after the end of the
archive. Report it with `PluginContext.report()`, using one of archivey's own diagnostic
codes and the context type that code takes:

```python
from archivey.diagnostics import DiagnosticCode, MemberTimestampContext

self._context.report(
    DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
    f"Invalid date for {member.name!r}: {raw!r}",
    MemberTimestampContext(
        member_name=member.name,
        field="modified",
        source="header",
        value_repr=repr(raw),
    ),
    member=member,
)
```

Leave `archive_name` and `member_id` unset: archivey fills them in. Pass `member` to
attach the report to a member, either while listing it (before it is yielded) or while
opening it. The caller's `DiagnosticPolicy` applies, so a code the caller raises on
raises from `report()`.

A report made while listing a member should name it as callers will see it, and
archivey normalizes names only after `iter_members()` yields them. So normalize the
name first with `PluginContext.normalize_name()`, set `member.name` to the result, and
yield the name you started from as `MemberRecord(member, locator, stored_name=...)`.
archivey then reports the change from that name, as it would have.

A symlink whose target cannot be read is reported with
`PluginContext.link_target_unavailable()`, which also leaves `link_target` unset and
tells extraction whether the archive holds a target the reader could not reach.

`PluginContext.config` is the caller's `ArchiveyConfig`. A reader that parses a large
index itself can bound that work by `config.listing_limits`. archivey applies those
limits to the members it is handed in any case.

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
  every built-in check. Like a built-in format's probe, it runs when the source's name
  has one of your extensions, when the source has no name at all (a stream passed to
  `open_stream()`), or when `ArchiveyConfig(always_probe_content=True)` is set. So it
  sees untrusted bytes that may not be your format at all. The prefix may be shorter
  than your format's header. A probe that raises counts as no match, and the first
  time it does archivey logs a warning on `archivey.detection`. `MemoryError` and
  `OSError` are the exception: they propagate, as everywhere else, so decide from the
  prefix alone and do not reach outside it. Use a probe only for a format with no fixed
  signature.

`FormatInfo.from_plugin` is `True` when detection chose a plugin's format.

## Optional dependencies

A plugin that wraps a library names its modules in `requires` and what to install in
`install_hint`:

```python
class CabPlugin(FormatPlugin):
    requires = ("cabarchive",)
    install_hint = "pip install cabarchive"
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
unbounded memory or crash on a crafted file; [Reading untrusted bytes](#reading-untrusted-bytes)
lists what a plugin's author can do about that. A program that reads untrusted archives
can refuse plugin formats by checking `FormatInfo.from_plugin`.

## What is not supported yet

- A format with an index inside an outer compressor. Only a format read in one pass can
  be.
- In a format read in one pass, member data that a library decodes, or that is
  compressed per member: `MemberSpan` describes bytes stored as they are.
- Self-extracting archives, multi-volume sets and passwords.
- New diagnostic codes. A plugin reports with archivey's existing codes.
- Writing archives.
