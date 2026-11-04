# Migrating from other libraries

Archivey reads ZIP, TAR, 7z, RAR and ISO archives, and single compressed files, through one
interface, so code written for zipfile, tarfile or a `7z` subprocess becomes the same few calls.
This page gives the archivey version of each, then what behaves differently. Archivey puts
correctness and the same behaviour in every format ahead of matching any one library. The difference
you'll meet first is in extraction: archivey refuses some members that zipfile or tarfile would
write, and it stops an archive that expands past its limits.

## Equivalent calls

Each item gives the archivey call first, then the calls it replaces and what's different.

- **Open an archive:** `archivey.open_archive(p)`.
    - Standard library: `zipfile.ZipFile(p)`, `tarfile.open(p)`.
    - py7zr or rarfile: `py7zr.SevenZipFile(p)`, `rarfile.RarFile(p)`.
    - [Any format, identified from its contents, with options for how you'll read it](#opening-an-archive).
- **List the names:** `[m.name for m in reader]`.
    - Standard library: `zf.namelist()`, `tf.getnames()`.
    - py7zr or rarfile: `z.getnames()`, `rf.namelist()`.
    - [A name can appear more than once](#members-and-their-details).
- **Look up one member:** `reader.get(n)`.
    - Standard library: `zf.getinfo(n)`, `tf.getmember(n)`.
    - py7zr or rarfile: `z.getinfo(n)`, `rf.getinfo(n)`.
    - Returns an [`ArchiveMember`][archivey.ArchiveMember].
- **Read one member:** `reader.read(n)`.
    - Standard library: `zf.read(n)`, `tf.extractfile(n).read()`.
    - py7zr or rarfile: `z.extract(targets=[n], factory=f)`, `rf.read(n)`.
    - [A directory raises an error](#reading-members).
- **Open one member as a file object:** `reader.open(n)`.
    - Standard library: `zf.open(n)`, `tf.extractfile(n)`.
    - rarfile: `rf.open(n)`.
    - [One open at a time, and not seekable, by default](#reading-members).
- **Read every member, in order:** `for member, stream in reader.stream_members():`.
    - Standard library: `for info in tf: tf.extractfile(info)`.
    - py7zr: `z.extractall(factory=f)`.
    - [One pass over the archive, in every format](#reading-members).
- **Give a password:** `archivey.open_archive(p, password="...")`.
    - Standard library: `zf.read(n, pwd=b"...")`.
    - py7zr or rarfile: `SevenZipFile(p, password="...")`, `rf.setpassword("...")`.
    - [Given once, when opening, and can be a list](#opening-an-archive).
- **Extract everything:** `reader.extract_all(d)`.
    - Standard library: `zf.extractall(d)`, `tf.extractall(d)`.
    - py7zr or rarfile: `z.extractall(d)`, `rf.extractall(d)`.
    - [Unsafe members are refused, and policies and filters choose what's written](#extracting).
- **Unpack any supported format:** `open_archive(p)`, then `reader.extract_all(d)`.
    - Standard library: `shutil.unpack_archive(p, d)`.
    - [More formats, and a report of what was written](#extracting).
- **Decompress a single file:** `archivey.open_stream(p)`.
    - Standard library: `gzip.open(p)`, `bz2.open(p)`, `lzma.open(p)`.
    - [One call for every compression format](opening.md#single-compressed-files).
- **Identify the format:** `archivey.detect_format(p)`.
    - Standard library: `zipfile.is_zipfile(p)`, `tarfile.is_tarfile(p)`.
    - [Names the format, among all those archivey reads](opening.md#format).

## Opening an archive

`open_archive` opens every format archivey reads and identifies it from the file's contents, so a
TAR file named `backup.bin` opens too, where `shutil.unpack_archive` fails because of the extension.
If your code actually needs to handle only one format, you can pass `format="zip"` or
`format=archivey.ArchiveFormat.TAR_GZ` to skip detection. A file in another format then fails like a
damaged one ([Format](opening.md#format)).

A password is given once, when opening: one string, a list of candidates, or a function that
supplies them ([Passwords](opening.md#passwords)). zipfile takes one per read or through
`setpassword`, and only for the older ZIP encryption. With the `recommended` extra, archivey also
reads WinZip AES. py7zr takes the password when opening, like archivey, and rarfile takes it per
read or through `setpassword`.

Like rarfile, archivey reads files stored without compression in a RAR archive on its own, and needs
a program for compressed ones: RARLAB's `unrar` or `rar`, or `unar` when neither is installed.
rarfile can also use `7z` or `bsdtar`, and archivey can't.

Three options to `open_archive` allow ways of reading that are off by default:

- **Seek in a member:** `seekable_members=True`. With the [`seekable`
  extra](reading.md#seeking-inside-a-member), seeks in bzip2 and large DEFLATE data (gzip files and
  most ZIP members) restart near their target. zipfile, tarfile and rarfile allow it, and a seek back
  decompresses again from the start. py7zr has no member streams.
- **Keep several members open at once:** `concurrent_operations=True`. zipfile, tarfile and rarfile
  allow it. py7zr has no member streams.
- **Read from a pipe:** one pass, with `streaming=True`, for TAR, ZIP and single compressed files.
  tarfile reads one pass with mode `"r|*"`. zipfile, py7zr and rarfile can't read from a pipe.

Seeking and keeping several members open are cheap on some archives and slow on others, and nothing
in the calling code shows which. Archivey turns them off by default so that code tested on a ZIP
doesn't first turn slow on a `.tar.gz` in production. [Choosing how to read](reading.md) explains
each option and what it costs.

## Members and their details

Every format gives an [`ArchiveMember`][archivey.ArchiveMember] with the same fields. The
ones code using `ZipInfo` or `TarInfo` reads most map like this:

- `member.name`: `info.filename` in zipfile, py7zr and rarfile, `info.name` in tarfile.
- `member.size`: `info.file_size` in zipfile and rarfile, `info.size` in tarfile, `info.uncompressed`
  in py7zr.
- `member.compressed_size`: `info.compress_size` in zipfile and rarfile, `info.compressed` in py7zr.
- `member.modified`: `info.date_time` in zipfile, `info.mtime` in tarfile and rarfile,
  `info.creationtime` in py7zr.
- `member.mode`: `info.external_attr >> 16` in zipfile, `info.mode` in tarfile and rarfile.
- `member.is_dir`, `member.is_file`, `member.is_link`: `info.is_dir()` in zipfile; `info.isdir()`,
  `info.isfile()`, `info.issym()` in tarfile; `info.is_directory`, `info.is_file`,
  `info.is_symlink` in py7zr; `info.is_dir()`, `info.is_file()`, `info.is_symlink()` in rarfile.
- `member.created` or `member.ctime`: `info.ctime` in rarfile.
- `member.link_target`: `info.linkname` in tarfile.

zipfile doesn't recognize symbolic links: a ZIP entry that records one is a plain file to it, and
`extractall` writes the target's path as the file's contents. Archivey reports it as a link, with
`member.is_link` and `member.link_target`.

A field the archive doesn't record is `None`, such as `compressed_size` for a member of a
`.tar.gz`. A directory's name ends with `/` in every format, so a directory that tarfile lists as `docs`
is `docs/` in archivey. `reader.get` returns `None` for a name that isn't there, where `getinfo` and
`getmember` raise `KeyError`.

`member.modified` is a `datetime` with the time zone the archive records. Some ZIPs, such as those
made by the `zip` command, carry a UTC time beside the old local one. zipfile ignores it, and
archivey uses it, so `modified` is in UTC there. A ZIP without it, or a RAR 4 archive, records a
local time with no zone, and `modified` has no zone either. TAR, 7z and RAR 5 archives record UTC:
tarfile gives a number of seconds, and py7zr, rarfile and archivey give a UTC `datetime`. py7zr's
`creationtime` holds this modification time. `member.modified_utc()` gives UTC for every format, and
treats a time with no zone as your local time unless you pass another zone. `accessed_utc()`,
`created_utc()` and `ctime_utc()` do the same for the other three times.

RAR, 7z and ZIP archives have a slot for a creation time, and what goes in it depends on where the
archive was made. Tools on Windows store when the file was created, and tools on Linux and macOS
store when its metadata last changed, Unix's `ctime`. rarfile gives the slot as `ctime` whatever it
holds. Archivey puts a creation time in `member.created` and a change time in `member.ctime`, so
`created` never holds a change time.

When an archive holds a name twice, zipfile, tarfile and archivey all list it twice, and reading by
name gives the last copy. Going through the member list, `member.is_current` tells you which copy
that is ([Members with the same name](opening.md#members-with-the-same-name)).

## Reading members

`reader.read` and `reader.open` work like their zipfile and tarfile counterparts, in every format
archivey opens. For ZIP, the `recommended` extra adds compression methods zipfile can't read:
Deflate64, PPMd, and zstd before Python 3.14.

Calling `read` or `open` on a directory raises `ArchiveyUsageError`, where zipfile returns empty
bytes and tarfile's `extractfile` returns `None`. Reading a symbolic link gives its target's
contents, as tarfile does, and raises `LinkTargetNotFoundError` when the target isn't in the
archive, where tarfile raises `KeyError`. zipfile gives the link's own text, the target's path.

In a `.tar.gz`, in most 7z archives and in some RAR archives, members are compressed together, so
reading one member on its own means decompressing everything before it. tarfile avoids repeating
that work when you read each member while iterating over the archive, and py7zr when you pass all
the names to one `extract` call. rarfile has no way to avoid it. With archivey, use
`stream_members()` whenever you need several members and their order doesn't matter: it reads each
member once, in order, in every format ([Solid archives](reading.md#solid-archives)). `read` and
`open` cost more. In a `.tar.gz`, the first one lists the whole archive, which takes a pass of its
own, and reading members in the archive's order after that takes one more pass. Going back to an
earlier member starts again from the beginning. In 7z and RAR, each read decompresses again
everything before its member. If you want to make sure your code avoids these costs, open the
archive with `streaming=True`: `read` and `open` then always raise, and `stream_members()` is the
only way to read members.

## Extracting

`extract_all` never writes outside the destination folder, in any format or under any policy.
zipfile, tarfile with `filter="data"`, and archivey's `strict` (the default) and `standard`
policies treat the same members differently:

- **`/abs.txt`:** zipfile, tarfile and archivey's `standard` write it as `abs.txt`. Archivey's
  `strict` refuses it.
- **`../up.txt`:** zipfile writes it as `up.txt`. tarfile raises, ending the extraction. Archivey
  refuses it.
- **A link to `../../etc/passwd`:** zipfile writes a plain file holding the path. tarfile raises,
  ending the extraction. Archivey refuses it.
- **A file with mode 4755 (setuid):** tarfile and archivey write it as 755. zipfile doesn't keep the
  mode.
- **A file with mode 666:** tarfile and archivey's `strict` write it as 644, and archivey's
  `standard` as 666. zipfile doesn't keep the mode.
- **A file with mode 755:** tarfile and archivey write it as 755. zipfile doesn't keep the mode.

zipfile ignores the permissions an archive records, so each file gets the system's default for new
files, usually 644. py7zr raises on `../up.txt` and on a link pointing outside, and rarfile renames
`../up.txt` and `/abs.txt` as zipfile does and raises on the link. Both keep the recorded
permissions. The data filter is tarfile's default from Python 3.14. Before that, tarfile with
no filter writes every member as recorded, outside the destination too, and Python 3.12 and 3.13
warn about it. The Extracting page has [a longer
table](extracting.md#what-each-policy-does-with-unusual-members), with more kinds of member and
every policy.

When archivey refuses a member, it skips it and goes on with the others, where tarfile's data
filter raises and ends the whole extraction. `abort_on=["blocked_member"]` makes archivey stop too.
If you want zipfile's renaming, pass `filter=archivey.sanitize_names`. `filter=` also takes your own
function, which can rename, skip or change each member ([Extracting all or some
members](extracting.md#extracting-all-or-some-members)).

zipfile and tarfile write as much as the archive holds. Archivey stops at 2 GiB written, 262,144
members, or a member that expands more than 800 times, and all three can be changed ([Archives you
trust](extracting.md#archives-you-trust)). `extract_all` returns an `ExtractionReport` saying what
happened to each member, where `extractall` returns `None`.

`shutil.unpack_archive` picks the format from the extension, handles ZIP and TAR (with gzip, bzip2,
xz, and zstd from Python 3.14), and extracts them through zipfile and tarfile, so the comparison
above applies to it too.

## Errors

Every problem with the archive raises a subclass of `archivey.ArchiveyError`, so one `except` covers
what took several exception types before:

- **Not an archive:** archivey raises `FormatDetectionError`. zipfile raises `BadZipFile`, tarfile
  `ReadError`, py7zr `Bad7zFile` and rarfile `NotRarFile`.
- **Damaged or cut short:** archivey raises `CorruptionError`, or `TruncatedError` when cut short.
  zipfile raises `BadZipFile`, tarfile `ReadError` or `EOFError` from the decompressor, py7zr
  `Bad7zFile` or `CrcError`, and rarfile `BadRarFile`.
- **Wrong password:** archivey raises `EncryptionError`. zipfile raises `RuntimeError`, py7zr
  `LZMAError`, and rarfile `BadRarFile`, or `RarWrongPassword` when the names are encrypted too.
- **No member with that name:** archivey raises `KeyError`, as zipfile, tarfile and py7zr do.
  rarfile raises `NoRarEntry`.

A missing name raises `KeyError`, which isn't an `ArchiveyError`, because the mistake is in the
calling code, not the archive. [Errors and diagnostics](errors-and-diagnostics.md) explains each
exception, and the warnings archivey reports without raising.
