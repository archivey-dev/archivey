# Remote archives

Archivey can read an archive that lives on S3, Google Cloud Storage, Azure, an HTTP server that
answers range requests, or any other store that [fsspec](https://filesystem-spec.readthedocs.io/)
reaches, without downloading it first. Listing a ZIP or a 7z archive, or reading a member of a
ZIP, then fetches little more than the bytes it needs. Reading a member of a solid archive, as
most 7z archives are, also fetches the members before it ([What reading costs](#what-reading-costs)).

```python
import fsspec
import archivey

with archivey.open_archive(fsspec.open("s3://bucket/dataset.zip", anon=True)) as archive:
    for member in archive:
        print(member.name, member.size)
    data = archive.read("labels.csv")
```

`fsspec.open(url, **options)` returns an `OpenFile`: a description of the file, with the file
system that holds it and its path, which nothing has opened yet. Pass it to `open_archive`,
`open_stream` or `detect_format` as is, without a `with` block around it. Unless the `OpenFile`
has a `compression` ([below](#what-archivey-takes-from-an-openfile)), archivey never opens it as a
file. It asks the file system for the object's size once, at open, and then reads the bytes it
needs as ranges, which most stores serve as one request each. It doesn't list the folder that
holds the file or look for other files beside it, even when the name is one that a part of a
split archive could have ([Archives in several volumes](#archives-in-several-volumes)).

Archivey doesn't depend on fsspec, and no extra installs it. The package for your store, such as
`s3fs`, `gcsfs` or `adlfs`, installs it; HTTP needs `fsspec` and `aiohttp`. The URL and its
options (a region, credentials, `anon=True`) go to `fsspec.open` as they would anywhere else. Archivey reads
them from nowhere else: a string passed to `open_archive` is always a local path, so a URL there
raises `FileNotFoundError` and fetches nothing. A program that passes file names from its users to
`open_archive` can't be made to fetch a URL.

## What reading costs

Each request to a remote store takes time before the first byte comes back, so archivey tries to
make few requests and keep each one close to what it needs. How few depends on the format,
because some formats keep an index and others have to be walked from the start
([Quick matrix](formats.md#quick-matrix)):

- **A ZIP is listed in two requests**: one for the start of the file, to recognise the format, and
  one for the index at its end. Reading a member is one more request, for that member's bytes.
  7z is similar.
- **A TAR has no index**, so listing it reads each member's header, which sits just before that
  member's data. With small members, archivey fetches the data in between too, in a few large
  requests, rather than one small request per header (the next section has the setting for
  this).
- **A solid archive** has to be decompressed from the start of a block to reach a member in it,
  so reading a member near its end fetches everything before it
  ([Solid archives](reading.md#solid-archives)). Compressed TARs are solid this way.
- **A pass over every member**, with `stream_members()` or `extract_all()`, reads the archive
  from start to end. Archivey makes each request larger as the reads stay in order, up to 8 MiB,
  so a 40 MB ZIP is read in fewer than ten requests.

The fetched bytes are held in memory only until the reads move on, and never more than 32 MiB
for one reader, whatever the number of member streams open at once. Past that, more streams cost
more requests, not more memory.

Archivey learns the size at open and reads by range, so a source opened this way can seek:
`streaming=True` isn't needed, and ZIP, 7z, RAR, ISO and the other formats that need a seekable
source all work. [Choosing how to read](reading.md) applies unchanged. Reading in one pass, in
archive order, is still the cheapest way to read many members.

### Gaps between reads

`ArchiveyConfig.max_read_through` sets how far ahead a read may land and still continue the
current request, in bytes. A read at most that far past the end of the last fetch fetches the
gap too, and one further away starts a new request:

```python
ArchiveyConfig(max_read_through=1024 * 1024)  # default: read through gaps up to 1 MiB
ArchiveyConfig(max_read_through=0)            # fetch only the bytes each read needs
```

The default sits just under the point where fetching the gap costs about as much time as a new
request, on a typical object store. It matters most when listing an archive with no index. On a
40 MB TAR of 200 KB files, the default lists it in 12 requests that fetch the whole file, and
`max_read_through=0` lists it in about 200 requests that fetch 1.6 MB. A larger value suits a
store where each request is slow and bytes are cheap, and a smaller one a store that charges for
the bytes.

## What archivey takes from an `OpenFile`

An `OpenFile` carries some options that change the bytes it would give if it were opened.
Archivey reads ranges straight from the file system, so it can't apply them on the way. It
refuses or works around each one rather than drop it silently:

- **`mode`** must be `"rb"`, which is fsspec's default. Any other mode raises
  `ArchiveyUsageError`, which is also a `ValueError`.
- **`compression`** set to a codec, or `"infer"` on a name that ends in a compressed extension,
  makes fsspec decompress the file as it is read. Archivey then opens the `OpenFile`, reads
  fsspec's decompressed stream instead of ranges, and logs a warning. That works, but every seek
  back decompresses again from the start. If you leave `compression` unset, archivey decompresses
  the file itself and reads it by range. A `.tar.gz` lists the same either way, while
  `data.csv.gz` opens as an archive with one member, `data.csv`
  ([Single compressed files](opening.md#single-compressed-files)). `open_stream` refuses an
  `OpenFile` with a `compression`, because it decompresses the data itself and would be handed
  bytes already decompressed. A list of volumes refuses one too.
- **`encoding`, `errors` and `newline`** have no meaning for bytes, and fsspec ignores them in
  `"rb"` mode too, so archivey ignores them.

??? note "Why not pass a file opened with `fsspec.open(...).open()` or `fs.open(path)`?"
    That works too: archivey reads it like any other binary file object, through the cache that
    file was opened with, and leaves it open when the reader closes. But its cache decides what
    each request fetches, without knowing what archivey will read next: depending on the cache,
    listing a ZIP may fetch the whole file, or make a request for each small read. Given the
    `OpenFile`, archivey knows where the index is and how far each member's data runs, and asks
    for those bytes directly.

## Archives in several volumes

A 7z or RAR archive split into several files, or a ZIP split by 7-Zip (`.zip.001`,
`.zip.002`, …), opens from a list of `OpenFile` objects, one per part, in order:

```python
parts = [fsspec.open(f"s3://bucket/backup.7z.{n:03d}") for n in (1, 2, 3)]
with archivey.open_archive(parts) as archive:
    ...
```

`fsspec.open_files("s3://bucket/backup.7z.*")` builds that list from a pattern, if the store
lets you list the folder.

Unlike a local path ([What you can open](opening.md#what-you-can-open)), a single `OpenFile`
never makes archivey look for the other parts, whatever `ArchiveyConfig.discover_volumes` says:
archivey lists no folder and asks for no other file. If the part you pass turns out to need the
others, such as `backup.7z.001` or a RAR first volume whose header says more follow, opening it
or listing its members raises an error that says to pass the parts as a list. A `.rar` or
`.exe` that is a complete archive opens as usual. With `discover_volumes=False`, a numbered part
such as `backup.7z.001` is read alone, as a local one is: the error is whatever its format
reports for a cut archive, without that advice.

??? note "Why not find the other parts, as for a local path?"
    Listing a remote folder is unreliable. On S3 it depends on a permission that reading a file
    doesn't need, and many HTTP servers have no index page, or one archivey would have to parse
    from HTML. Nothing would bound what the search costs on a large folder either, and it would
    run for every `.rar` or `.exe` opened. You know which parts there are, so a list is both
    cheaper and certain.

## RAR archives

Compressed RAR members are decoded by the `unrar` program ([The program for RAR](formats.md#the-program-for-rar)),
which reads a local file. For each read, archivey fetches the member's packed bytes and writes
them to a temporary file for `unrar`, so reading one member of a large RAR archive doesn't
download the rest. A pass with `stream_members()` or `extract_all()` copies several small
members at a time. A solid RAR archive needs the members before the one read, as in any solid
archive. [Running `unrar`](formats.md#running-unrar) says what each temporary file holds.

`SpoolLimits.max_bytes` (default 1 GiB) caps each copy, and a remote archive has no way around
it: an archive opened from a local path reads a large member in place, but a remote one can't.
So a member whose packed bytes pass the limit, or in a solid archive the part of the stream up
to that member, raises `ResourceLimitError`. Raising the limit lets archivey read it.

## If the remote file changes

An object can be replaced while archivey reads it, such as a file uploaded again under the same
name in the middle of a long extraction. Later requests then return bytes of another file, while
archivey still reads them as the archive it opened.

If the new file is shorter, a request past its end comes back short, and archivey raises
`SourceChangedError`, a `ReadError`. It isn't damage, so it isn't a `CorruptionError`: opening the
archive again reads the new file. If the new file is the same length or longer, nothing in the
requests shows the change. Members with a checksum are still checked as they're read, so changed
bytes there most often raise `CorruptionError`, but bytes with no checksum, such as an index, may
be read from the new file with no error.

Archivey says so at open, with the diagnostic `SOURCE_CHANGE_UNDETECTABLE`. Its context names the
store's protocol and why the reads aren't guarded. It is advisory: it describes how the archive
arrives, not the archive, so `DiagnosticPolicy.STRICT` doesn't turn it into an error
([Diagnostics](errors-and-diagnostics.md#diagnostics)). If you need the guarantee, read from a
store or a URL that can't change under you, such as an object version, or copy the file before
opening it.
