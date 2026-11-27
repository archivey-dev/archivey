# Opening an archive

## What you can open

`open_archive` takes a path, a binary file object or a folder. A folder opens like an archive of the
files inside it. For a 7z or RAR archive split into several volumes, the path of any one of them is
enough, and archivey finds the others. If it can't find them by name, such as volumes you hold as
open file objects, you can pass a list of them, in order. A ZIP split by 7-Zip into `.zip.001`,
`.zip.002` and so on opens the same way. If a part of a numbered set like that (`.7z.001`,
`.zip.001`) is missing, opening raises `TruncatedError` naming it, rather than reading a shorter
archive. A RAR set with a volume missing still opens, as `unrar` would, but `members()` raises
`TruncatedError` naming the missing volume, and so does reading a member with data in it. A part
archivey finds on its own that is a symbolic link is refused with `OpenError`; pass the parts as a
list to read it. If listing the folder fails with an `OSError`, such as no permission to list it,
archivey finds no other volumes: the path opens alone, and a missing part is reported as above.
Any other error from the listing is raised as is.
`ArchiveyConfig(discover_volumes=False)` turns the search off, so a path opens only the file it
names ([Security](security.md#hardening) says when that is worth it). A remote archive is never
searched: pass its volumes as a list ([Remote archives](remote.md#archives-in-several-volumes)).

A file object is read from its current position to its end, so an archive that starts partway
through a larger file opens as is. Bytes after the archive don't stop it opening. Any that aren't
zeros are recorded as `ARCHIVE_TRAILING_DATA`, which `DiagnosticPolicy.STRICT` turns into an
exception. Behind more than 64 KiB of trailing bytes, zeros included, a ZIP's index is found by
walking its members from the start, which takes longer. A file object that can't seek, such as a
pipe or an HTTP response, needs `pipe=True` and works only for some formats, which [Reading from a
pipe](formats.md#reading-from-a-pipe) lists. An archive on S3, an HTTP server or another remote
store opens from `fsspec.open(url)` without downloading it, and can seek ([Remote
archives](remote.md)).

??? note "Why not refuse bytes after the archive?"
    They aren't part of any member, so every member is still read correctly. GNU gzip and bzip2 also
    decompress such a file and only warn, though `xz` refuses it.

## Format

Archivey identifies the format from the file's contents, so a ZIP named `backup.bin` still
opens as a ZIP. It falls back to the file name only when the contents don't settle it. To skip
detection, pass `format=`, such as `format="zip"` or `format=archivey.ArchiveFormat.TAR_GZ`. If
the file isn't in the specified format, it fails like a damaged one.

`archivey.detect_format(path)` tells you the format without opening the archive. It returns a
`FormatInfo` with the format and how sure archivey is about it: `CERTAIN` when the format's
signature matched where the format puts it, `PROBABLE` when a test of its contents matched, and
`GUESS` when the evidence is weak, such as only the file name. `prefixed` is `True` for a
self-extracting archive, where the archive starts after a program, and for any other archive found
behind leading bytes; `payload_offset` says where reading starts. Test `prefixed`, not
`payload_offset > 0`, to ask whether the archive came after something else: a ZIP whose own
offsets count from the start of the file starts at 0 even behind a program. `prefixed` says what
detection found, so `False` is not proof that nothing comes first: a file named for its format
whose first bytes are neither an archive signature nor a program or `#!` header is taken at its
name's word, with no search for leading bytes. For a signed Windows
program, `payload_end` is where its signature starts, and archivey reads the archive only up to
there. A file in no format archivey knows raises `FormatDetectionError`. The confidence grade is
for a person reading it and may change between releases, so decide what to do from the format,
not the grade.

## Single compressed files

A file that's compressed but not an archive, such as `notes.txt.gz`, opens as an archive of one
member, named after the file without its extension (`notes.txt`). The member's `compression` names
the file's method, as a ZIP member compressed the same way does: `DEFLATE` for a `.gz`, `XZ` for a
`.xz`. It's empty for a format no method names, such as a uuencoded file. A `.tar.gz` is different:
there the gzip belongs to the archive, and each member is `STORED`. If you only want the contents,
`open_stream` returns them as a file object:

```python
with archivey.open_stream("notes.txt.gz") as stream:
    text = stream.read()
```

On a `.tar.gz` it removes only the compression, so you get the TAR's bytes. It refuses ZIP, 7z, RAR,
ISO and plain TAR files, which aren't compressed streams. It takes `seekable=`, which works like
`seekable_members` in [Seeking inside a member](reading.md#seeking-inside-a-member).

zlib, Brotli and `.lzma` files start with nothing that identifies them. By default `open_archive`
recognizes them only by their extension (`.zz`, `.br` or `.lzma`), and a file without one raises
`FormatDetectionError`. To open one anyway, pass `format=`, or set `always_probe_content=True` in the
config, which makes `open_archive` try decoding the start of the file. `open_stream` always tries.

??? note "Why doesn't `open_archive` try decoding?"
    These formats are rarely saved as files of their own. They usually come inside something else,
    such as an HTTP response compressed with Brotli or zlib, and that's what `open_stream` is for.
    `open_archive` is mostly handed files, of any kind. For these formats, decoding the start and
    seeing whether it works is the only test, and some files that aren't compressed at all pass it,
    such as encrypted or media files. `open_archive` would then open one of them as a compressed
    file and return garbage or a confusing error. On the streams `open_stream` gets, the test is
    worth that risk.

## Passwords

Pass the password as `password=`: one string, a list of candidates when you're not sure which one
the archive uses, or a function that supplies passwords as they're needed.

```python
archivey.open_archive("secret.7z", password="hunter2")
archivey.open_archive("secret.zip", password=["likely", "fallback"])
```

Archivey tries a list in order, and each wrong password costs some hashing work before it's
rejected, so the most likely one is best placed first. An archive can use different passwords for
different members, and archivey finds the right one from your list for each.

??? note "How does archivey know which password is right?"
    The archive can't simply say. A ZIP stores a check value of one byte, or two with AES, so about
    one wrong password in 256 (or in 65,536) passes it, and a 7z stores none. Archivey decrypts the
    start of the member and decompresses it: a wrong password gives random bytes, which most
    compression methods reject within a few hundred bytes. When more than one password gets through
    that, it reads the member to its end and checks its checksum.

You can also pass a function, such as one that asks the user. Archivey calls it only when a
password is needed and none tried so far works. It passes a `PasswordRequest` with the member being
opened and the attempt number. When the password is needed to read an encrypted members list,
which 7z and RAR support, `PasswordRequest.member` is `None`. Return a password to try, or `None` to
give up, which raises `EncryptionError`.

Archivey hands a RAR password to `unrar` only when the read needs one, and `unrar` would cut a
password at a line break or a NUL character. So when the password that reaches `unrar` contains
either, archivey raises `UnsupportedFeatureError` for the archive. It doesn't move on to the next
password in your list, because the one handed over is the first candidate (or the one already found
to be right). A password read from a file usually ends with a newline: remove it yourself, for
example with `password.removesuffix("\n")`. The [RAR section](formats.md#rar) has the details.

A password or list of passwords given for a format with no encryption, such as TAR, is ignored and
noted in the [diagnostics](errors-and-diagnostics.md), which log a warning for each such archive by
default. One list can then serve a whole batch of archives, and the diagnostics page shows how to
quiet the warning.

## Names in other encodings

Archives made by current tools either say which encoding their names use or store them as UTF-8, and
archivey decodes them that way. It has to guess only for older formats, or archives made by older
tools. Then it uses UTF-8 if the bytes are valid UTF-8, and otherwise the format's traditional
encoding, such as cp437 for ZIP. Where there isn't one, it keeps each byte it can't decode as an
escape, the way Python's `surrogateescape` does. An escape is a placeholder character between U+DC80
and U+DCFF.

If you know the encoding, set it as `ArchiveyConfig(fallback_encoding=...)`, and archivey uses it
in place of that default for names that aren't valid UTF-8: a Latin-1 `café.txt` in a TAR is listed
as `'caf\udce9.txt'` without it and `'café.txt'` with `fallback_encoding="latin-1"`. Archives opened
inside that one with `parent=` use it too. Only ZIP, TAR, ISO, RAR, CPIO, ar, RPM, makeself,
SquashFS, CAB, XAR, LHA and ARJ read it. The other formats decode names their own way.

```python
config = archivey.ArchiveyConfig(fallback_encoding="cp1252")
with archivey.open_archive("old.zip", config=config) as archive:
    ...
```

Each name a fallback decoded, the format's or yours, gets a `MEMBER_NAME_FALLBACK_ENCODING`
diagnostic on its member, whose context names the codec used. Those are the names another
`fallback_encoding` could change, so a program can look for them to decide whether to ask which
encoding the archive uses. `open_archive(encoding=)` did the same for one call before 0.6.0; it
still works with a `DeprecationWarning`.

??? note "Why does valid UTF-8 win over `fallback_encoding`?"
    Text in another encoding almost never happens to be valid UTF-8. `café`, `Müller` and `Größe`,
    written in Latin-1, all fail to decode as UTF-8. So a name that decodes as UTF-8 almost
    certainly is UTF-8, even in an archive whose other names use your encoding.

`member.name` is the decoded name, and `member.raw_name` is the bytes as stored. A name with an
escaped byte, like `'caf\udce9.txt'`, can't be encoded as UTF-8, so printing or logging it can raise
`UnicodeEncodeError`. `archivey.terminal.escape_control_chars(member.name)` gives a version that's
safe to show.

## Members with the same name

An archive can hold several members with the same name. Some tools update an archive by adding the
new version of a file at its end and leaving the old one in place, as `tar --append` does, and RAR
and ISO can keep old versions on purpose. All of them are listed. The last one is the current
version: its `member.is_current` is `True`, and the earlier ones have `False`. `get`, `open` and
`read` with a name use the current version, since that's the file the archive's own tool would give
you. `extract_all` writes only the current version and reports the others as
`ExtractionStatus.SUPERSEDED`.

A name passed in `members=`, to `extract_all` or `stream_members`, matches every member with that
name, so `stream_members(members=["a.txt"])` gives you each version. To pick one, pass the
`ArchiveMember` from the listing.

A `stream_members` loop can give you a member before archivey has seen the rest of the archive, so
it can't yet tell whether a later copy replaces it. Each member then has `is_current` set to `True`
until the loop ends, and the members you kept are updated then. `member.member_state_final` tells
you which case you have: it's `False` while a member's fields can still change.

## Times

A time has no zone when the format records local time: a ZIP with only the DOS time, RAR 4, CAB, and
LHA and ARJ archives from DOS or Windows. Other formats record UTC or an offset. To compare times
from different archives, use `member.modified_utc()`, `accessed_utc()`, `created_utc()` and
`ctime_utc()`. They take a time with no zone as your local time, or as the zone you pass
(`tz_for_naive=`).

`ArchiveMember.created` is a birth time or `None`, never Unix `st_ctime` (the time of the last
inode change). Several writers store `st_ctime` where a reader might expect a creation time, such
as a Rock Ridge ISO, a Unix RAR, a PAX TAR, and a 7z or ZIP written on Unix. That time is in
`ArchiveMember.ctime` instead.

## Stored digests

`member.hashes` holds the digests the archive already stores, so they can be read without
decompressing anything. A CRC-32 is four big-endian bytes, so one you computed compares as
`zlib.crc32(data).to_bytes(4, "big")`.

- **CRC-32** (`HashAlgorithm.CRC32`): ZIP, 7z and ARJ files, RAR5 files that store one, and `.lz`
  files read from a source that can seek.
- **BLAKE2sp**: RAR5 files that store one.
- **MD5**: Debian package files listed in `DEBIAN/md5sums`.
- **MD5, SHA-1 or a SHA-2 digest**: XAR files, and the files of a macOS installer package outside
  its payloads.
- **None:** TAR, SquashFS, CPIO, LHA, ar, RPM, the files in a macOS installer package's payloads,
  directories, and every other single compressed file. Many of them still check their data as it is
  read, with a checksum per block, or per file in a form `member.hashes` doesn't hold.

When a format stores none, compute one while reading. A dedupe index can key every member by its
CRC-32, read from the archive when it's stored and computed otherwise, so the same file in a ZIP
and in a TAR gets the same key:

```python
import zlib
import archivey
from archivey.types import HashAlgorithm

def crc32_of(reader, member):
    """The member's CRC-32: stored when the archive has one, computed otherwise."""
    if HashAlgorithm.CRC32 in member.hashes:
        return member.hashes[HashAlgorithm.CRC32]
    crc = 0
    with reader.open(member) as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            crc = zlib.crc32(chunk, crc)
    return crc.to_bytes(4, "big")

with archivey.open_archive("backups.zip") as reader:
    for member in reader:
        if member.is_file and member.is_current:
            print(member.name, crc32_of(reader, member).hex())
```

Two different files can share a CRC-32, so treat a match as a candidate, and compare a SHA-256 of
both members before counting them as the same file.

## Format-specific fields

`ArchiveMember.extra` and `ArchiveInfo.extra` hold what only some formats store, such as
`extra["gzip.original_filename"]` or `extra["deb.package"]`. Both are dicts, typed so that a type
checker knows each documented key's type. The format sections mention a key only when it matters
for that format. The full list is on [`MemberExtra` and
`ArchiveInfoExtra`](api.md#members-and-archive-details).

## macOS sidecar files

A ZIP or TAR made on a Mac often holds AppleDouble sidecars: a `._name` file with the extended
attributes and resource fork of `name`, next to it (macOS `tar`) or under `__MACOSX/` (Finder,
`ditto`). A folder archived on a Mac can also hold `.DS_Store` files, Finder's view settings.
Archivey lists them all as ordinary files, as `unzip` does. To leave them out, skip them by name
with `members=`:

```python
from archivey import open_archive

def is_macos_sidecar(member):
    base = member.name.rsplit("/", 1)[-1]
    return (
        member.name.startswith("__MACOSX/")
        or base.startswith("._")
        or base == ".DS_Store"
    )

with open_archive("photos.zip") as reader:
    reader.extract_all("out", members=lambda m: not is_macos_sidecar(m))
```

The test goes by name only, so it also skips a file that was really called `._notes`, and anything
in a real folder named `__MACOSX`.

## Configuration

Settings you'd keep the same across many archives live in `archivey.ArchiveyConfig`, passed as
`config=`. These include the [limits](security.md#hardening), which RAR program to use, the
[accelerators](reading.md#seeking-inside-a-member), and how [diagnostics](errors-and-diagnostics.md)
are reported. Without it, the defaults apply. The [reference][archivey.ArchiveyConfig] lists
every setting.

`ArchiveyConfig.formats` takes a [`FormatPolicy`][archivey.FormatPolicy], which decides which
formats a call opens. A format is a container and its compression, and both have to be allowed:

```python
from archivey import ArchiveyConfig, ContainerFormat as C, FormatPolicy, StreamFormat as S

# The formats people send today, for files you didn't make. See below.
UPLOADS = ArchiveyConfig(formats=FormatPolicy.COMMON)

# ZIP, and TAR with or without gzip or xz. Nothing else opens.
ZIP_OR_TAR = ArchiveyConfig(formats=FormatPolicy(only={C.ZIP, C.TAR, S.GZIP, S.XZ}))

# Everything except RAR, and no plugin formats.
NO_RAR = ArchiveyConfig(formats=FormatPolicy(exclude={C.RAR}, plugins=False))
```

A file in a format the policy turns off raises `UnsupportedFeatureError`, and the message says
which entry would let it open. `format=` doesn't get around it. `detect_format` still reports
what a file is, and `config.formats.allows(info.format)` tells you whether it would open. A plugin
format that's turned off isn't detected at all, so its code doesn't run.

`FormatPolicy.COMMON` is a preset for files you didn't make, such as uploads. It opens ZIP, TAR,
RAR and 7z, and gzip, bzip2, xz and zstd, as a whole file or around a TAR. It refuses ZIP members
compressed with Shrink, Implode, Reduce or DCL Implode, methods only PKZIP 1.x and earlier wrote.
Everything else is refused: disk images, packages, cabinets, the rarer compressions, plugin
formats, and any format a later release adds. Their readers and their pure-Python decoders then
never run on what you're sent. To add a format, build on it:
`FormatPolicy(only=FormatPolicy.COMMON.only | {S.LZ4}, exclude=FormatPolicy.COMMON.exclude)`.

`exclude_libraries=` turns off optional packages for the call, even when they're installed:

```python
from archivey.types import OptionalLibrary as L

NO_PPMD = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={L.PYPPMD, "inflate64"}))
```

archivey then reads as if those packages weren't there. A PPMd member raises
`PackageNotInstalledError` when you open it, while the other members can still be read; a `.lz4`
file with `lz4` excluded doesn't open; and an accelerator such as rapidgzip under `AUTO` falls back
to the standard library. The error's `missing` names the package, and its `reason` says the policy
turned it off. Each entry is an [`OptionalLibrary`][archivey.types.OptionalLibrary] member or its
value, and any other name is refused, so a typo can't leave a package on. The setting only affects
calls made with that config: other calls in the same program, on any thread, still use the package.
`format_availability(fmt, config=...)` and `list_supported_formats(config=...)` answer with the
excluded packages counted as missing. A plugin reader that imports a package itself honours the setting
only if it checks `config.formats.allows_library(name)` itself.

`only_libraries=` is the allowlist form, as `only=` is of `exclude=`: every optional package it
doesn't list is turned off, including any that a later archivey release adds. `only_libraries=set()`
runs with no optional package. On Python 3.14 that also turns off the standard library's
`compression.zstd`, which is listed as an optional package; list it to keep zstd:

```python
STDLIB_ONLY = ArchiveyConfig(formats=FormatPolicy(only_libraries=set()))
WITH_AES = ArchiveyConfig(formats=FormatPolicy(only_libraries={L.CRYPTOGRAPHY}))
```

It covers archivey's own optional packages, not a plugin's own modules: `plugins=False` turns
plugins off. Zstandard comes from `compression.zstd` on Python 3.14 and `backports.zstd` before
that, so list both to keep zstd on every version.

`only=` and `exclude=` check the file you open, not what's inside it. `S.XZ` there means a file
compressed with xz as a whole, such as a `.xz` or `.tar.xz` file, not the xz codec: a ZIP member
compressed with xz can still be read under `exclude={S.XZ}`, because the file is a ZIP.
A [`CompressionAlgorithm`][archivey.types.CompressionAlgorithm] in `exclude=` reaches further: it
turns that decoder off, for a file compressed with it as a whole and for every member compressed
with it. `exclude={CompressionAlgorithm.XZ}` refuses a `.xz` or `.tar.xz` file and still lists an
xz-compressed ZIP member, but opening, reading or extracting that member raises
`UnsupportedFeatureError` before anything is decoded. Every xz stream holds LZMA2 data, so
`exclude={CompressionAlgorithm.LZMA2}` refuses all of that too, and a 7z LZMA2 member as well;
`exclude={CompressionAlgorithm.XZ}` leaves the 7z member open. A format that compresses data inside
itself without naming the method on each member, such as a `.deb` with a `data.tar.xz`, an RPM
package or a SquashFS image, doesn't open at all when you exclude that method. An xz block can run
a BCJ or Delta filter ahead of LZMA2, and only its header says so, so
`exclude={CompressionAlgorithm.BCJ}` or `{CompressionAlgorithm.DELTA}` stops a read at the first
block that uses that filter, with `UnsupportedFeatureError`; xz data whose blocks don't use it reads
as usual. `only=` takes no
methods. `plugins=False`, `exclude_libraries=` and `only_libraries=` are different, since they turn
off the code that decodes, wherever it runs. Under `plugins=False`, no plugin codec or plugin format
runs in the call, even for a member or an archive inside an archive: reading a member that needs one
raises `UnsupportedFeatureError`.
