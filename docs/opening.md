# Opening an archive

## What you can open

`open_archive` takes a path, a binary file object or a folder. A folder opens like an archive of the
files inside it. For a 7z or RAR archive split into several volumes, the path of any one of them is
enough, and archivey finds the others. If it can't find them by name, such as volumes you hold as
open file objects, you can pass a list of them, in order. A ZIP split by 7-Zip into `.zip.001`,
`.zip.002` and so on opens the same way. If a part of a numbered set like that (`.7z.001`,
`.zip.001`) is missing, opening raises `TruncatedError` naming it, rather than reading a shorter
archive. A RAR set with a volume missing still opens, as `unrar` would, but `members()` raises
`TruncatedError` naming the missing volume, and so does reading a member with data in it.

A file object is read from its current position to its end, so an archive that starts partway
through a larger file opens as is. Bytes after the archive don't stop it opening. Any that aren't
zeros are recorded as `ARCHIVE_TRAILING_DATA`, which `DiagnosticPolicy.STRICT` turns into an
exception. Behind more than 64 KiB of trailing bytes, zeros included, a ZIP's index is found by
walking its members from the start, which takes longer. A file object that can't seek, such as a
pipe or an HTTP response, needs `streaming=True` and works only for some formats, which [Reading
once](reading.md#reading-once) lists.

??? note "Why not refuse bytes after the archive?"
    They aren't part of any member, so every member still reads correctly. GNU gzip and bzip2 also
    decompress such a file and only warn, though `xz` refuses it.

## Format

Archivey identifies the format from the file's contents, so a ZIP named `backup.bin` still
opens as a ZIP. It falls back to the file name only when the contents don't settle it. To skip
detection, pass `format=`, such as `format="zip"` or `format=archivey.ArchiveFormat.TAR_GZ`. If
the file isn't in the specified format, it fails like a damaged one.

`archivey.detect_format(path)` tells you the format without opening the archive. It returns a
`FormatInfo` with the format and how sure archivey is about it: `CERTAIN` when the format's
signature matched where the format puts it, `PROBABLE` when a test of its contents matched, and
`GUESS` when the evidence is weak, such as only the file name. `payload_offset` is more than 0 for a
self-extracting archive, where the archive starts after a program. A file in no format archivey
knows raises `FormatDetectionError`. The confidence grade is for a person reading it and may change
between releases, so decide what to do from the format, not the grade.

## Single compressed files

A file that's compressed but not an archive, such as `notes.txt.gz`, opens as an archive of one
member, named after the file without its extension (`notes.txt`). If you only want its contents,
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

If you know the encoding, pass it as `encoding=`, and archivey uses it in place of that default for
names that aren't valid UTF-8: a Latin-1 `café.txt` in a TAR lists as `'caf\udce9.txt'` without it
and `'café.txt'` with `encoding="latin-1"`. Only ZIP, TAR, ISO and RAR read `encoding=`. The other
formats decode names their own way, and a value passed to them is ignored and noted in the
diagnostics.

??? note "Why does valid UTF-8 win over `encoding=`?"
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

## Configuration

Settings you'd keep the same across many archives live in `archivey.ArchiveyConfig`, passed as
`config=`. These include the [limits](security.md#hardening), which RAR program to use, the
[accelerators](reading.md#seeking-inside-a-member), and how [diagnostics](errors-and-diagnostics.md)
are reported. Without it, the defaults apply. The [reference][archivey.ArchiveyConfig] lists
every setting.
