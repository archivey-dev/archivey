# LHA

Current maintainer truth for LHA (also called LZH): what LHarc, LHA for DOS, UNLHA32,
LHa for UNIX, Amiga LhA, LHARK, PMarc and LArc write. An LHA archive is a run of members,
each a header and then its data, ended by a zero byte. There is no index, and each member
is compressed on its own. The reader is written against `archivey.formats` and registered
as a built-in, as CAB, XAR and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/lha_reader.py`, a `LhaHandler` (`IndexedFormatHandler`) and a `LhaReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek, from its start or behind a self-extracting stub (§2.6). Not a pipe, for now: the listing seeks past each member's data to the next header |
| Listing cost | Header by header, one read per header and a seek past the data |
| Access cost | `DIRECT`: each member is its own stream |
| Core dependencies | None. The LZH methods through `internal/streams/codecs/lzh_decoder.py` and `lharc_decoder.py`, archivey's own, in Python |
| Encryption | None in the format |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Checksums | A CRC-16/ARC of each member's data, checked by the read; an 8-bit header sum (levels 0 and 1) or a header CRC-16 (the common record, levels 1 to 3), checked when the header is read |
| Refuses | Methods it does not decode, when read; a header level past 3; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-lha/spec.md` |

Not here, though a reader might look for it: PMarc's `-pm1-` and `-pm2-`
methods are not decoded; MacLHA's resource fork, when the member has a data fork too, is
dropped as lhasa drops it; multi-volume archives (a `0x39` record) are
not joined; OS/2 extended attributes and MorphOS LhA's comment record (`0x71`) are not
read, as lhasa does not read them.

## 1. Shape

From lhasa's `lha_file_header.c` and `ext_header.c` (the reference here) and the LHA
header notes in jca02266's LHa for UNIX:

- **Level 0** (LHarc, LHA 1.x): a 1-byte header size (counting from byte 2), an 8-bit sum
  of the header from byte 2, the method (`-lh5-`, five bytes at offset 2), stored and
  decoded sizes, a DOS date and time, an attribute byte, the level (byte 20), a
  length-prefixed name and the data's CRC-16. LHa for UNIX and OS-9/68k append a 12-byte
  area: OS id `U` or `K`, a zero, a Unix mtime, then mode, uid and gid in the last six
  bytes. OS-9's own LHA appends a 22-byte area with its permissions.
- **Level 1**: level 0, then an OS id and the size of the first extended header. The
  extended headers follow the base header, outside its sum, and count in the stored size.
- **Level 2**: a 2-byte size of the whole header, a Unix mtime in place of the DOS time,
  the CRC-16, the OS id and the extended headers, all inside the header. OS-9/68k LHA
  writes two bytes more than its size counts. A writer pads a header whose size has a
  zero low byte by one byte, so that it does not read as the end marker.
- **Level 3** (LHA for OS/2): level 2 with a 4 in the size field, a 4-byte header size and
  4-byte extended header sizes.

Each extended header is a type byte, a body and the next header's size (0 ends the
chain). The types read: `0x00` common (the header CRC-16), `0x01` name, `0x02` directory
(parts split by `0xFF`), `0x3F` comment, `0x41` Windows FILETIMEs (created, modified,
accessed), `0x42` 64-bit stored and decoded sizes, `0x50` Unix mode, `0x51` gid and uid,
`0x52` group name, `0x53` user name, `0x54` Unix mtime, `0xCC` OS-9 permissions. The
others are skipped, as lhasa skips them.

The methods: `-lhd-` a directory (or a symlink), `-lh0-`, `-lz4-` and `-pm0-` stored,
`-lh1-` LZHUF (adaptive Huffman, 4 KiB), `-lh2-` and `-lh3-` (experimental methods from LHA 2's
development), `-lh4-` to `-lh7-` the static-Huffman LZ77 of LHA 2 (windows of 4,
8, 32 and 64 KiB), `-lhx-` UNLHA32's 512 KiB window, `-lk7-` LHARK's (written as `-lh7-`
with OS id `' '`), `-lzs-` and `-lz5-` LArc's, `-pm1-` and `-pm2-` PMarc's.

## 2. The pipeline here

### 2.1 Identify

Magic is the method at offset 2: one of the sixteen methods above, `-lh0-` to `-pm2-`.
Five bytes, but a dash, two letters, a character and a dash at that offset rule out
nearly everything else. The extensions are `.lzh` and `.lha`; `.lzs` and `.pma` files
are found by the magic.

### 2.2 Open and list

`LhaReader.__init__` reads the first header, so a file that is not LHA fails at open; a
file that starts with the end byte is `CorruptionError` ("has no members"). Then
`iter_members` reads each header, yields the member and reads the next header after the
member's data, until a zero byte or the end of the file.

A header is checked as it is read: level 0 and 1 against their 8-bit sum, any level with
a common record against its CRC-16 (computed over the whole header, the CRC field
zeroed). A name past the header, an extended header past the header, a level-3 header
over 1 MiB, level-1 extended headers over 1 MiB or longer than the stored size, or a level past 3 is
`CorruptionError`. A member whose data runs past the file is `TruncatedError` at listing.

As lhasa does: a level-1 `-lh7-` member with OS id `' '` is LHARK's, read as `-lk7-`; an
Amiga `-lh0-` member with no name and size 0 is a directory, named by its directory
record; OS-9/68k's mode field and OS-9's permissions become a Unix mode (the owner's
`rwx` from OS-9's owner bits, group and others from its public bits, `0x80` a directory).

Names: the directory record and the name join with `/`, `0xFF` separators become `/`,
then the name is decoded and `\` becomes `/` (after decoding, so a cp932 second byte of
`0x5C` stays whole). Before level 2, a NUL in the name starts an Amiga file note, which
becomes `member.comment`. A `-lhd-` member whose mode is a symlink is a `SYMLINK`, its
stored name `name|target` (`raw_name` keeps the bytes before the `|`); one with no `|`
is listed with
`SYMLINK_TARGET_UNAVAILABLE`.

Times: the Unix mtime when the header has one (level 2 and 3, the `0x54` record, the
level-0 Unix area), in UTC; else the DOS time, naive. The `0x41` record adds `created`
and `accessed`. An invalid DOS time is `None` with `MEMBER_TIMESTAMP_INVALID`.

The end: no zero byte after the last member reports `ARCHIVE_EOF_MARKER_MISSING`
(`expected_marker="end_of_archive_byte"`); a byte other than `0x00` or `0x1A` in the
64 KiB after the end byte reports `ARCHIVE_TRAILING_DATA`.

`extra` holds `lha.method`, `lha.header_level` and, when the header has one,
`lha.os_id`; `create_system` maps the OS id (`M` FAT, `2` OS/2, `U` Unix, `A` Amiga, `m`
Macintosh, `w` VFAT, `W` NTFS, `C` CP/M, `a` Atari ST, `' '` LHARK on DOS; others
`UNKNOWN`).

MacBinary: MacLHA (OS id `m`) stores a Mac file as a MacBinary file, a 128-byte header
(name, Finder type and creator, fork lengths, Mac times) and then the data and resource
forks, padded to 128 bytes. The header has no magic, so the listing follows lhasa's
`macbinary.c`: for a `FILE` member with OS id `m` and a size of 128 or more, it decodes
the first 128 bytes and accepts them only when the version and reserved bytes are zero,
the name is the member's own name (its last part, zero-padded to 63 bytes), the fork
lengths plus 128, rounded up to 128, are the member's size, and the modification time is
within 14 hours (a time zone) of the header's (a DOS time is read as UTC here). A
member that passes reads as its data fork, or its resource fork when the data fork is
empty: `size` is that fork's length, and `lha.mac_type` and `lha.mac_creator` (4 bytes
each) join `extra`. A member that fails reads whole, so an archived MacBinary file, which
rarely matches the name and the time, keeps its wrapper. Level 0 has no OS id, so its
members keep their wrapper, as in lhasa. The check costs one decode of 128 bytes per
such member at listing; a member that fails to decode is left as it is, and its read
fails as before.

### 2.3 Read

A stored member is a view of its data. An LZH member is decoded by `LzhDecoder`, which
reads the data 64 KiB at a time. Both check the CRC-16 as the read reaches the end, so a
member read whole is `Verification.CHECKSUM`. A MacBinary member is read through
`_MacBinaryStream`: it drops the 128-byte header, returns the fork, and with the fork's
last byte decodes the rest and checks the CRC-16 itself (`checked=True`), since the CRC
covers bytes the caller never sees. A method archivey does not decode raises
`UnsupportedFeatureError` when read; it is listed like any other member, with
`compression` `LZH` for any `-lh?-` method and `UNKNOWN` for the rest.

### 2.4 The LZH decoder

`lzh_decoder.py` follows lhasa's `lh_new_decoder.c` wherever the format leaves a choice,
so the two agree on every stream lhasa reads; its docstring lists those choices (the
window starts as spaces, `-lh4-` uses `-lh5-`'s tables, a zero count is one symbol with
no bits, a count over the table is cut, decoding stops at the member's size). Where lhasa
decodes damage into bytes its CRC then refuses, the decoder raises `CorruptionError` at
once: a code length over 16 bits, a table that over- or underfills its code space, a
symbol past its table, a match from further back than the window. Past the end of the
input it reads zero bytes, at most 32, and refuses output that needed them
(`TruncatedError`).

Each table decodes through `huffman_table.py`'s two-level table, shared with LZX: a root
of at most 10 bits and sub-tables under it. A block can carry up to 65 535 commands and
three tables, so a run of blocks with no commands costs three table builds each, as in
LZX: with the fullest tables the format allows, about 2.2 µs an input byte (CPython
3.11), producing nothing (threat model, §No CPU or wall-clock bound).
The hot loop keeps the bit buffer and both tables in locals and reads a whole command
without a call: about 8 MB/s on text, 4 to 5 on random data (CPython 3.11).

### 2.5 The older methods

`lharc_decoder.py` holds `-lh1-` (LHarc's LZHUF: one adaptive Huffman tree of 314
symbols, rebuilt with halved counts when its root reaches 32 768, and a fixed code for
the high part of each distance), and LArc's `-lzs-` (a 2 KiB ring, bit commands) and
`-lz5-` (a 4 KiB ring that starts with a fixed pattern, flag bytes). They follow lhasa's
`lh1_decoder.c`, `lzs_decoder.c` and `lz5_decoder.c`. None of their codes can name a byte
outside its window, so the only damage they see before the CRC is input that ends
early. They share `LzhDecoder`'s input and output (`LhaBitDecoder` in
`lzh_decoder.py`): past the input they read zeros, at most 32 bytes, and refuse output
that needed them (`TruncatedError`). On lhasa's fixtures (the 18 092-byte GPL text,
CPython 3.11), `-lzs-` and `-lz5-` decode about 4.7 MB/s and `-lh1-` about 1.8 MB/s,
against 7 for `-lh5-` on the same text: `-lh1-` updates its tree after every symbol.

### 2.6 Self-extracting archives

An LHA self-extractor is a program with the archive after it: DOS `.COM` and `.EXE`
stubs (LHarc, LHA, LArc, PMarc), Windows (LHMelt's WinSFX, ExpLzh's DECLHA), the Amiga
(LhASFX), the Atari ST and the X68000. The archive is found by its first header, as
lhasa finds it, but with the shared SFX scan (`internal/sfx.py`): the method at offset 2
of a header is the needle (`SFX_MAGIC`, offset 2), and `_validate_header` reads the
header there and checks its sum or CRC, so a stub that names the methods in its code is
passed over. Detection runs it behind an executable cue, and as the leading-bytes scan
when nothing else matched: a `.COM`, Amiga hunk or Atari TOS stub has no cue.
`LhaReader` runs the same scan itself when byte 2 is not a method, so a forced
`format=LHA` reads what detection finds (`SFX_PARSER_SCANS`).

Where lhasa skips the first header after the names `LHA-SFX` and `LhASFX V1.2,`, the
validator walks the members after the first instead: an archive that ends, with more
than padding after its end byte, before the file does is `VALID_SHORT`, and the scan
looks on. Amiga LhASFX keeps its usage text as such an archive inside the stub. The walk
stops after `_WALK_MAX` (8) members and then grades the candidate `VALID`, so a decoy of
nine or more members is taken: a window of valid headers makes each one a candidate,
and an unbounded walk from each costs time quadratic in the window. A next header that
does not read grades the candidate `DAMAGED`, so a stub header that passes its 8-bit sum
by chance loses to the real archive; opening still falls back to it. ExpLzh's
DECLHA stubs carry no decoy, and lhasa's skip passes over their real archive (it lists
nothing); archivey reads it.

The format API gives a reader no start offset, so `register_builtin_format` sets
`SFX_MAGIC` for LHA and `IndexedReaderAdapter` reads detection's `[payload_offset,
payload_end)` as the reader's whole source (`ReadBackend.open_read`'s promise). A plugin
cannot declare `SFX_MAGIC`, and still refuses an offset.

Measured once (2026-11-09) on lhasa's 15 self-extractors: the 12 lhasa extracts read the
same, auto-detected and forced; PMarc's is listed and its `-pm2-` member refused; the two
DECLHA ones read the GPL text lhasa does not reach.

## 3. Tests

`tests/test_lha.py`. Archives are written at test time by `tests/lha_util.py`, which
writes headers of every level and holds an `-lh4-` to `-lh7-` encoder (no Linux tool
here writes LHA; lhasa only extracts). lhasa reads every archive the tests write (checked
whenever it is installed), so the decoder is not checked only against its own reading.
Twenty-two archives from lhasa's test suite, written by eleven tools and by hand, are in
`tests/fixtures/external/lha_lhasa/`: every decoded method, every header level, Unix and
OS-9 modes, symlinks, directories, LHARK, `-lh1-`, `-lzs-` and `-lz5-` (one crafted to
copy the whole starting ring). Commons Compress's fifteen
LHA archives match its listing (`tests/test_commons_compress_corpus.py`).

Measured once (2026-11-09) against lhasa 0.4.0 on lhasa's whole test suite and
libarchive's LHA tests, 247 files: every member lhasa extracts with a method archivey
decodes read byte for byte the same. The differences were the methods not decoded yet,
self-extracting programs, MacBinary members (read with their wrapper then; since
stripped, and lhasa's sixteen MacLHA 2.24 archives match its CRCs), and a few damaged
archives: where lhasa
stops quietly (a name past its header, a 4 GB level-3 header), archivey raises
`CorruptionError`, and where lhasa stops at an empty name, archivey lists the members
after it.
