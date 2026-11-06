# format-rar — synthetic archives for `unrar`

## ADDED Requirements

### Requirement: Read RAR member data through a synthetic archive

When `unrar` serves a member read, the system SHALL give `unrar` a single-volume
synthetic RAR file instead of the original archive, unless `Keep the original archive
for a large plainly named member of a path source` applies. The file SHALL hold the RAR
signature, a MAIN header made by archivey, the FILE header and packed data of each member
the read needs in archive order, and an ENDARC header made by archivey.

#### Scenario: members a read needs

| Read | Members in the synthetic file |
| --- | --- |
| A member of a nonsolid archive | The member |
| A member of a solid archive | Every header with packed data from the last member at or before it whose own solid flag is clear, up to the member |
| A member split across volumes | One member: the parts' data joined in order |
| Solid archive written with `rar -s<N>`, a member in a later group | Only that group's members up to it |
| Solid archive, its first member | The first member only; `unrar` exits after it |

#### Scenario: synthetic reads match the original

| Case | Expected |
| --- | --- |
| Compressed member, RAR 1.5-4 or RAR5, plain or `-p` | Bytes equal `unrar p` on the original |
| Same, `-hp` | Bytes equal; the synthetic file has plain headers and the data is still encrypted |
| Member split across three volumes, plain, `-p` or `-hp` | Bytes equal the source file |
| History row of `rar -ver` | Its own bytes |
| Member name with `*`, `?`, `\`, a NUL or invalid UTF-8 | Read; the name never reaches `unrar` |

### Requirement: Build synthetic FILE headers from the archive's own headers

Each FILE header in a synthetic file SHALL be the archive's stored header, decrypted when
the archive's headers are encrypted. The system SHALL change only the name (to `m<i>`,
its position in the file), the RAR 1.5-4 Unicode-name flag, the split flags and packed
size of a joined member, and the header size and CRC that follow. Before writing a
header the system SHALL check its CRC against the listing, and SHALL raise
`CorruptionError` without spawning `unrar` when they differ.

#### Scenario: header matrix

| Case | Expected |
| --- | --- |
| Any member | Every decode field (method, dictionary, solid flag, sizes, CRC, extra records, salt) as stored |
| Joined split member | The last part's header, split flags cleared, packed size = sum of the parts |
| MAIN header | Solid flag only when the file holds more than one member; never header encryption |
| Stored header changed on disk after `open()` | `CorruptionError`; no spawn |

### Requirement: Run unrar on a synthetic file with a placeholder mask

The system SHALL run `unrar p -inul -cfg- -ver (-p | -p-) [-n./m<k>] -- <file>` on a
synthetic file. The mask SHALL be present only when the file holds more than one member
and only the target is wanted. The password SHALL be written to stdin.

#### Scenario: argv matrix

| Case | Expected |
| --- | --- |
| One-member synthetic file | No `-n` |
| Solid chain | `-n./m<k>` for the target only |
| Any synthetic read | `-ver` present |

### Requirement: Bound and remove synthetic files

The bytes of a synthetic file SHALL count against `SpoolLimits.max_bytes` for every
source. A copy over the limit SHALL raise `ResourceLimitError` before any byte is written
and before `unrar` is spawned. The file SHALL have mode 0600, SHALL be reused when a
seekable member stream respawns `unrar`, and SHALL be removed when the member stream or
the reader closes. A synthetic read SHALL NOT copy a stream source whole.

#### Scenario: copy matrix

| Case | Expected |
| --- | --- |
| Stream source, one compressed member read | Only that member's header and packed bytes are written to disk |
| Copy over `SpoolLimits.max_bytes` | `ResourceLimitError` naming the field; no temp file; no spawn |
| `seekable_members=True`, backward seek | `unrar` runs again on the same file; nothing is copied again |
| Member stream closed | The file is removed |

### Requirement: Keep one growing synthetic file per solid stream

For a solid archive the reader SHALL keep one synthetic file per solid stream for its
lifetime. A read past the last member in the file SHALL append the missing members and a
new ENDARC; a read of a member already in the file SHALL copy nothing. Every byte of the
stream SHALL be copied at most once per reader.

#### Scenario: solid stream file matrix

| Case | Expected |
| --- | --- |
| `open()` of members 1, 2, … n of one solid stream in order | Total bytes written = the packed bytes up to member n, once |
| `open()` of member 5 after member 50 | Nothing written; `unrar` decodes from the stream start, at most to member 50 |
| Members in two `rar -s<N>` groups | Two files, one per group |

### Requirement: Keep the original archive for a large plainly named member of a path source

For an archive opened from a path, the system SHALL keep the `-n` include-mask read of
the original archive when the packed bytes a synthetic file would hold exceed an
implementation threshold (initially 64 MiB) and the member's name is plain. Every other
`unrar` read SHALL use a synthetic file. A read of the original SHALL select exactly one
member.

#### Scenario: plain names

| Case | Plain |
| --- | --- |
| Every name in the archive decodes cleanly (valid UTF-8 for RAR5, ASCII for an 8-bit RAR 1.5-4 name) and has no `\`, NUL, leading `/`, or empty, `.` or `..` component; the target has no `*` or `?` and no component ending in `.`, and is ASCII unless `unrar` reads a non-ASCII mask back as the same text (Windows, or a UTF-8 locale on POSIX); no other name equals it or starts with it plus `/`, compared without case | Yes |
| Any name in the archive that fails the archive-wide part | No, for every member |
| Target named `a*.txt` or `notes.` | No |
| Target named `café.txt` | Yes on Windows and under a UTF-8 locale; No on POSIX with none |

#### Scenario: route matrix

| Case | Expected |
| --- | --- |
| Path source, 2 KB member | Synthetic file |
| Path source, 500 MiB member with a plain name | Original archive, `-n./<name>` |
| Path source, 500 MiB member named `a*.txt` | Synthetic file within the spool limit |
| Path source, 2 GiB member named `a*.txt`, default spool limit | `ResourceLimitError` naming `SpoolLimits.max_bytes` |
| Stream source, any size | Synthetic file |

### Requirement: Batch a pass over a nonsolid archive into one unrar run

In a `stream_members()` pass over a nonsolid archive, the system SHALL put compressed
members into synthetic files of several members, run one `unrar p` without a mask per
file, and split the output by unpacked size. A batch SHALL hold only regular files with
a stored digest that need the same password, within an implementation size (initially
64 MiB packed) and the spool limit. After a failure in a batch, its later members SHALL
be read one at a time.

#### Scenario: batch matrix

| Case | Expected |
| --- | --- |
| `extract_all()` on a nonsolid archive of 4,000 small members | Few `unrar` runs, not 4,000 |
| A member with no stored digest | Its own synthetic file, outside any batch |
| A damaged member inside a batch | Its error is raised for it; the later members of the batch read one at a time |
| Members with different passwords | Different batches |

## MODIFIED Requirements

### Requirement: Decode RAR member names

A RAR5 name, and a RAR 1.5-4 name whose UTF-16 field decodes, SHALL be listed as that
text. A RAR5 name or redirect target that is not valid UTF-8 SHALL decode with
`surrogateescape`, so two names that differ only in such bytes stay two members and
extraction escapes the bytes by the portable-name rule, as for a TAR name. A RAR 1.5-4
name stored only as 8-bit bytes records no code page. The system SHALL try strict UTF-8
first, with or without the Unicode flag. When the bytes are not valid UTF-8 it SHALL
decode them with the caller's `encoding=` when one was passed, and without one with
cp437 (the OEM code page WinRAR writes) for a member whose host is MS-DOS, OS/2 or
Win32, and windows-1252 for any other host, with `surrogateescape` for the bytes the
codec leaves undefined. When a name without the Unicode flag decodes as UTF-8 and the
caller's `encoding=` would have given a different name, the system SHALL emit
`MEMBER_NAME_ENCODING_INFERRED` with `inferred_encoding="utf-8"` and `declared_encoding`
set to the caller's encoding, as ZIP does; the Unicode flag declares UTF-8, so a flagged
name emits none. The system MUST NOT decode an 8-bit name as UTF-16LE. `raw_name` SHALL be the
stored bytes in every case, and RAR SHALL NOT emit `ENCODING_ARGUMENT_UNUSED`. How a
name is decoded SHALL NOT change which member a read returns: a read gives `unrar` the
member through a synthetic archive under a placeholder name, or the stored name itself
only when it is plain (`Keep the original archive for a large plainly named member of a
path source`), never a mask built from the decoded text. A RAR 1.5-4
UTF-16 field SHALL decode with `surrogatepass`: a surrogate without its partner stays in
`name` as that code unit, and a valid pair decodes as one character. Extraction writes
such a name by `safe-extraction` "Lone surrogates in a member name". A name with a lone
surrogate is not plain, so the member reads through a synthetic archive like any other
name that is not plain.

#### Scenario: RAR name decoding matrix

| Case | Expected |
| --- | --- |
| 8-bit `caf\x82.txt` written on Windows or DOS | `café.txt` (cp437) |
| 8-bit `caf\xe9.txt` written on Unix | `café.txt` (windows-1252) |
| 8-bit name whose bytes are valid UTF-8 | Decoded as UTF-8 |
| 8-bit name that is not valid UTF-8, with `encoding="cp1251"` | Decoded with cp1251; still reads |
| 8-bit name whose bytes are valid UTF-8, `encoding=` passed, with or without the Unicode flag | UTF-8; one `MEMBER_NAME_ENCODING_INFERRED` without the flag, none with it |
| RAR5 name with `encoding=` passed | Unchanged; no `ENCODING_ARGUMENT_UNUSED` |
| Any 8-bit name | `raw_name` is the stored bytes |
| UTF-16 field holds a lone surrogate (`hi` U+D800) | `name == "hi\ud800"`; `raw_name` is the 8-bit field; the member reads |
| RAR5 `a\xffq.txt` and `a\xfeq.txt` | Two members, `a\udcffq.txt` and `a\udcfeq.txt`; each reads its own bytes through `unrar` |
| 8-bit `b\x81.txt` and `b\x8d.txt` written on Unix | `b\udc81.txt` and `b\udc8d.txt` |

## REMOVED Requirements

### Requirement: Support benchmark-gated small-member optimization

**Reason**: Replaced by `Read RAR member data through a synthetic archive`. The deferred
optimization was the same single-member temporary RAR. Benchmarks now justify it, and it
serves reads of every size, with the size rule in `Keep the original archive for a large
plainly named member of a path source`.

### Requirement: Return a named member's own bytes when its mask selects others

**Reason**: No read passes `unrar` a mask that selects more than one member any more.
A synthetic file names its members `m<i>`, and a read of the original archive uses a
plain name that selects exactly one member (`Keep the original archive for a large
plainly named member of a path source`). The name model and the skip it fed are gone.

### Requirement: Refuse a member name whose mask also selects earlier members

**Reason**: The refusal guarded the extra decode a shared mask cost `unrar`. A synthetic
read never builds a mask from a stored name, so a glob, a duplicate or a name `unrar`
reads like another one reads its own bytes with no extra decode. A member that can only
be read in place with a name that is not plain raises `UnsupportedFeatureError` instead.
`rar_allow_glob_member_concatenation` is deprecated and has no effect.

### Requirement: Under auto, read a member unrar cannot name with unar

**Reason**: Every member `unrar` could not name now reads through a synthetic file, so
`auto` never needs `unar` beside a RARLAB binary.
