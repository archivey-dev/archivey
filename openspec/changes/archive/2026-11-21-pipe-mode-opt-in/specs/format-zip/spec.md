## MODIFIED Requirements

### Requirement: Read a non-seekable ZIP source in one forward pass

A ZIP read from a non-seekable source SHALL be read under `pipe=True` in one
forward pass over the local headers, with the central directory read after the last
member. Without `pipe=True` (under `streaming=False` or `streaming=True`) it SHALL raise
`StreamNotSeekableError` at open, naming `pipe=True`. Under `pipe=True` a seekable source
SHALL be read the same way, by its local headers (`access-mode-and-cost`). The library MUST NOT buffer, spool, or copy the source into seekable
storage. The member data `extract_all` stages in the destination (`safe-extraction`) is
extraction output, not a copy of the source. What the pass keeps SHALL be bounded: the
directory and end records by the listing limits, and the member data it keeps (a
password-confirmation prefix, a short member that may turn out to be a link) by fixed
caps.

Each member's data ends where its local header says, or, when bit 3 defers the sizes to
a data descriptor, where its codec's end marker is (DEFLATE, Deflate64, bzip2,
Zstandard, LZMA with the end-of-stream marker, PPMd with its end mark), followed by the
descriptor; a STORED bit-3 member ends at a descriptor whose CRC and size match the
bytes before it and that a ZIP signature follows. A bit-3 codec member the pass reads
past (nobody read it to its end) SHALL be decoded no further than the byte past the
symlink target cap, then the reparse prefix a file read reads (a Windows reparse buffer
and one byte), and one byte past that prefix, since only a decode that returns nothing
tells bit-3 data it has ended there; the two reads stop at the same place. Where its
codec has not ended by then, it ends as a STORED one does, matched on its size and the
signature after the descriptor: decoding the rest costs what no limit bounds. A bit-3
member nobody reads that is encrypted under a codec ends the same way, so passing it
needs no key. A bit-3 LZMA member without the end-of-stream marker has no end its codec
can find: its read SHALL raise `UnsupportedFeatureError`. A bit-3 PPMd member without an
end mark fails its decode, as from a file. A bit-3 codec member whose decode fails or
cannot find its end SHALL be passed by the same scan for its descriptor on its stored
bytes, with no key. The scan starts at the last 4 MiB the decode read and counts the
bytes before them into the size it matches; a decode that read more than that past the
data's end leaves the descriptor behind the scan's start, and the pass SHALL then end
with the scan's error. A bit-3 PPMd member is decoded in a child process, like every
PPMd member, except under `process_isolation=NONE`, which SHALL decode it in-process,
fed in pieces. Several
password candidates SHALL be confirmed on a kept prefix of the member's data
(`archive-reading`, "A unit read once").

`stream_members()` SHALL yield each member with what its local header gives: `mode`,
`create_system` and `comment` are `None`, `uid` and `gid` are `None` even when the local
extra field carries them, the type is `FILE` or `DIRECTORY` from the name (a name ending
in `\` is a `DIRECTORY`), and `member_state_final` is `False` (`archive-data-model`).
Once the directory has been read, before the pass ends, each member SHALL be updated in
place from its directory entry, matched by offset, as the same archive read from a file
lists it, and `is_current` SHALL follow the directory order; member ids and listing
order stay those of the file. A local entry no directory entry points to SHALL be
dropped from the listing and reported as `ARCHIVE_UNLISTED_DATA`. The walk SHALL stop at
the first bytes after a member that are no local header and keep the rest of the stream;
a directory entry that points into the kept bytes (bytes a writer left between two
members, or a second archive appended with `cat`) SHALL be read from them at that offset
and yielded before the pass ends, and no other local header there SHALL be read. One
whose bytes the listing limits dropped SHALL end the pass with `ResourceLimitError`.
Every byte each attempt there consumes, a member read or a local header that fails to
parse, SHALL be counted, and an entry reached once the count equals the bytes the pass
holds SHALL end the pass with `CorruptionError` before it is read. A local header there
that does not parse SHALL fail its entry at the end of the pass with the parse error as
its cause. A stub with no local header within `SFX_MAX`, the stream ending there on an
end record, SHALL be read as the tail, so an archive with no local header behind a stub
lists as from a file. A file-shaped member flagged as a Windows reparse point whose
data is not a reparse buffer stays a file; a directory-shaped one stays a link with no
target, as from a file. The cost receipt SHALL be `REQUIRES_SCANNING`, `DIRECT`,
`FORWARD_ONLY`; `member_count` and `comment` SHALL be `None` and
`members_report_if_available()` SHALL return `None` until the directory has been read.

Four things SHALL fail the member they name once the directory has been read: a size or
CRC from a data descriptor that differs from the central entry; a local header whose
CRC, sizes or encryption flag the central entry contradicts (a central CRC-32 of 0 over
data against a non-zero local one is none: a file or link takes the local value, and a
directory keeps no digest, as from a file); two same-name members whose directory order
reverses their file order; and a directory entry with no local entry. `stream_members()`
SHALL raise `CorruptionError` at the end of the pass for each but the reversed pair,
which only updates the members. A local header that stores another name than the
directory entry SHALL NOT fail the member: the member takes the directory's name, and a
file or link reports `MEMBER_LOCAL_NAME_DIFFERS`, as a file read reports it (the
requirement on headers that disagree). Nor SHALL one that names another compression
method, unless one of the two is WinZip AES (99): the pass decoded by the local method,
as a file read decodes, and a file or link reports `MEMBER_LOCAL_METHOD_DIFFERS`, as a
file read reports it once the member's local header passes its checks, before the data
is decoded: so also when the data then fails on a CRC or size the directory contradicts
(a size the overlap guard refuses aside, below). Method 99 in both headers SHALL fail
the member when the two AES records differ in any field (version, strength, real method)
or one is missing or unparseable; the message names the fields, or the side that lacks a
record. `extract_all` settles them as `safe-extraction` states. A directory entry
pointing at a local header an earlier entry already took SHALL end the pass with
`CorruptionError`.

The pass MAY differ from a file read on crafted archives (DR-5a): the descriptor
mismatch (a STORED member's, or a descriptor planted in the data of a bit-3 codec member
the pass reads past) and the reversed pair fail a member the file read writes; bytes
between a bit-3 codec member's end and its descriptor, refused from a file, are counted
into the member; the first of several inconclusive password candidates wins; WinZip AES
in the directory over another local method fails with `EncryptionError` where a file
read raises `CorruptionError`; so does a local AES strength other than the directory's,
and an AE-1 local record over an AE-2 one fails on its CRC-32 and a missing local record
with `UnsupportedFeatureError`, each during the pass, where a file read raises
`CorruptionError` on the records; a member whose directory names another method and a
compressed size the file read's overlap guard refuses reports
`MEMBER_LOCAL_METHOD_DIFFERS` from the pass, which keeps no such bound, and nothing from
a file (both raise `CorruptionError`; under `STRICT` the pass raises the report). It MAY
also differ in these: a damaged bit-3 codec member can fail with another
`CorruptionError` subclass, and ends the pass, losing the members after it, if its
decode read more than 4 MiB past the data's end; a bit-3 codec member whose stream runs
on into its descriptor reads, where a file read raises `TruncatedError` at the stated
compressed size; a bit-3 LZMA member without the end-of-stream marker is refused where a
file read reads it; a bit-3 member followed by bytes that are no ZIP record ends the
pass (`UnsupportedFeatureError` when STORED) where a file read reads it; in
`extract_all`, a link member the pass wrote as a file keeps the error its data read gave
(no password: `EncryptionError`, where the file read reports `LinkTargetNotFoundError`);
and an archive-wide refusal the directory or end record makes is raised by a file read
before anything is written and by the pass after every member is written. A policy that
raises on `MEMBER_LOCAL_NAME_DIFFERS`, `MEMBER_LOCAL_METHOD_DIFFERS` or
`MEMBER_LOCAL_CRC_USED` is the same: a file read raises when it lists or opens the
member, the pass once it has read the directory. A run that stops before the end of the
pass, for these or any other reason, places no member (`safe-extraction`), so no link is
left on disk as a file holding its target.

The data the pass keeps of short members until the directory says which are links SHALL
NOT be charged to the listing limits: an archive a file read lists within them SHALL
list from a pipe too, however many small files it holds, except that a link whose own
data was dropped (below) is listed without its target. The pass SHALL hold at most
`max_metadata_bytes` of that data, dropping the longest first; a link whose data was
dropped SHALL be listed with `link_target` unset and `SYMLINK_TARGET_UNAVAILABLE` with
reason `"target_data_dropped"`, unless the member is flagged as a reparse point and its
dropped data is no buffer as a file read reads one, which is re-typed as from a file.
The rest of the listing SHALL stand, except under `DiagnosticPolicy.STRICT`, which
refuses the archive on that integrity code. This differs from a file read only for a
target at least as long as `max_metadata_bytes` of short members' data before it, and
for an encrypted reparse point nobody read, whose dropped ciphertext the pass does not
decrypt: it stays a link with no target where a file read with the password may
re-type it. The archive comment SHALL be weighed against
`max_metadata_bytes` once the pass reads the end record, as a file read weighs it.

#### Scenario: non-seekable read matrix

| Case | Expected |
| --- | --- |
| Non-seekable ZIP with default `streaming=False` | `StreamNotSeekableError` at open, naming `pipe=True`; no reader |
| Non-seekable ZIP with `pipe=True` | Opens; `stream_members()` and `extract_all()` read every member in one pass; after the pass the members equal the file read's |
| Implementation lacks seekable source | No implicit seekable-copy, temp-file, or spool fallback of the source; the member data `extract_all` stages is not one |
| `stream_members()` from a pipe, a Unix symlink member | Yielded as `FILE`, `member_state_final` false; after the pass `SYMLINK` with its target |
| A pipe, many small files whose data passes `max_metadata_bytes`, a symlink after them | Lists every member and the link's target, as a file read does |
| `extract_all()` from a pipe, a Unix symlink member | The link is made when the member is placed, after the directory is read; the filter sees it once, as a symlink |
| `extract_all()` from a pipe that stops before the end of the pass (`abort_on`, `on_error="stop"`, a limit, a `STRICT` refusal at the directory, or any other reason) | No member is placed; the destination holds nothing the run wrote |
| Bit-3 STORED members (stdlib `zipfile` writing to a pipe) | Each ends at its descriptor; contents as from a file |
| Bit-3 LZMA member without the end-of-stream marker | `UnsupportedFeatureError` at that member |
| Bit-3 PPMd member, `process_isolation=NONE` | Decoded in-process |
| Two same-name members whose directory order reverses their file order | `is_current` from the directory order; `stream_members()` raises nothing |
| A data descriptor that understates a STORED member, `stream_members()` | `CorruptionError` at the end of the pass |
| A local entry the directory does not list | Dropped from the listing; `ARCHIVE_UNLISTED_DATA` |
| Bytes between a sized member and the next | Every member read, as from a file |
| `cat first.zip second.zip` | The second archive's members, as from a file; the first's yielded, then dropped with `ARCHIVE_UNLISTED_DATA` |
| A member the directory places in bytes the listing limits dropped | `ResourceLimitError` |
| Entries placed in the kept bytes whose data or headers overlap, at any listing limits | `CorruptionError` once they have consumed the bytes held |
| A stub, then an archive with no local header (an empty one), `format=ZIP` | Opens with what the directory lists, as from a file |
| `reader.info` during the pass, then after it | `member_count` and `comment` `None`, then the directory's |
