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
| Every name in the archive decodes cleanly (valid UTF-8 for RAR5, ASCII for an 8-bit RAR 1.5-4 name) and has no `\`, NUL, leading `/`, or empty, `.` or `..` component; the target is ASCII with no `*` or `?` and no component ending in `.`; no other name equals it or starts with it plus `/`, compared without case | Yes |
| Any name in the archive that fails the archive-wide part | No, for every member |
| Target named `a*.txt`, `café.txt` or `notes.` | No |

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

## REMOVED Requirements

### Requirement: Support benchmark-gated small-member optimization

**Reason**: Replaced by `Read RAR member data through a synthetic archive`. The deferred
optimization was the same single-member temporary RAR. Benchmarks now justify it, and it
serves reads of every size, with the size rule in `Keep the original archive for a large
plainly named member of a path source`.
