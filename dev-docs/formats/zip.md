# ZIP

Current maintainer truth for the ZIP backend: what the format forces, who does which
part of the work, and where the sharp edges are. Registers keep the status — this page
states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | Yes |
| Write | **Not shipped**, for any format — no `archivey.create`, no writer module ([writing design](../investigations/archive-writing-design.md)) |
| Source | Seekable, in both access modes; a pipe under `streaming=True` only, read forward (§2.2.2) |
| Listing cost | `INDEXED`; `REQUIRES_SCANNING` from a pipe |
| Access cost | `DIRECT` |
| Stream capability | `SEEKABLE`; `FORWARD_ONLY` from a pipe |
| Core dependencies | None — ZIP reads on a zero-dependency install |
| Optional | `[recommended]`: Deflate64 (`inflate64`), PPMd (`pyppmd`), Zstd (`backports.zstd`, stdlib on 3.14+), WinZip AES (`cryptography`) |
| Refuses | A pipe under `streaming=False` · from a pipe, a bit-3 LZMA member without the end marker (§2.2.2) · Info-ZIP spanned sets (7-Zip `.zip.NNN` byte splits are joined, §2.2) · unknown compression methods, at read · LZMA with `lc + lp` over 4 and PPMd restore method 2, at read (§2.3) · AES without `cryptography` · PKWARE Strong Encryption, at read (§2.3) |

The extras are named for what they provide, not for ZIP, because every one of those
codecs is shared with 7z or TAR. See [`packaging-and-extras`](../../openspec/specs/packaging-and-extras/spec.md).

## 1. Shape

Four properties generate most of this page. Everything below is a consequence of one of
them.

```
[ prefix? ]  [ LFH · data · DD? ] × n   [ CDH ] × n   [ ZIP64 EOCD + locator ]?  [ EOCD ]
                  ▲                       │  ▲                                      │
                  └── header_offset ──────┘  └────── offset_cd ─────────────────────┤
                                                     search backwards ≤ 65 558 B ◄──┘
```

| Part | Signature | What it is |
| --- | --- | --- |
| **prefix** | — | Arbitrary leading bytes. **Not part of the ZIP structure**: no field records it or its length, and nothing inside the archive has to change for it to be there. See §3 |
| **LFH** — local file header | `PK\x03\x04` | One per member, immediately before that member's compressed bytes. Carries the name, extra fields, method and flags, and — unless bit 3 is set — the sizes and CRC. Its metadata is a *copy*; the CDH is authoritative |
| **DD** — data descriptor | `PK\x07\x08`, optional | Present only when general-purpose bit 3 is set: the CRC and both sizes, written *after* the data because a streaming writer did not know them in advance. The same signature at offset 0 means something else — the split-archive spanning marker |
| **CDH** — central directory header | `PK\x01\x02` | One per member, all of them together near the end; the run of CDHs is *the central directory*. Each points back at its LFH through `header_offset` and adds what the LFH has no room for: external attributes (mode), version made by (create system), the member comment, the starting disk |
| **ZIP64 EOCD** + locator | `PK\x06\x06`, `PK\x06\x07` | Wider versions of the EOCD fields, present when a count or an offset does not fit in 32 bits |
| **EOCD** — end of central directory | `PK\x05\x06` | 22 fixed bytes plus an optional comment: total entries, the size of the CDH run, `offset_cd` (where that run starts), the disk numbers, the comment length. The only record found by *position* rather than by a pointer |

archivey takes every member field from the CDH and reads the LFH only to locate the data
(§2.3). Three exceptions read the LFH for more. When the two copies of the name differ,
as bytes, the member keeps the CDH's name and reports `MEMBER_LOCAL_NAME_DIFFERS`;
stdlib refused it. When the two name different compression methods, the member is
decoded by the LFH's, which sits next to the data and is the only one a pipe has, so a
file and a pipe read the same bytes; it reports `MEMBER_LOCAL_METHOD_DIFFERS`. When the
CDH stores CRC-32 0 for a file or link that is not WinZip AE-2 and the LFH a real value,
the LFH's is the member's CRC-32, reported as `MEMBER_LOCAL_CRC_USED` (§5).

**The index is at the end.** The central directory is authoritative and is found by
scanning backwards from the last bytes for the EOCD. So:
reading the structure requires positioning at the end, which is why a non-seekable source
is read another way, forward over the local headers with the directory last, and only
under `streaming=True` (§2.2.2); a ZIP can be preceded by arbitrary bytes without any of
its own numbers changing meaning, which is why prefixed ZIPs work (§3); appending is
expressed by writing a new directory at the end, which is why in-place update is possible
in the format and refused here (§6); and a scan that lands on the wrong `PK\x03\x04` is
usually self-correcting, because the reader still finds the real EOCD from the tail
(§2.1).

The backwards search bound is not configurable. A valid record with no trailing bytes
begins at most 65535 + 22 bytes before the end, since `comment_length` is a `uint16`.
Archivey searches one byte further, 65 558 bytes, because that is stdlib's older window
(3.11 and early 3.12 releases; 3.13 and later 3.12 releases dropped the byte). Trailing
bytes are not comment bytes, so the extra byte does find a record: a maximal comment
followed by one junk byte. When the reader used stdlib, that archive opened or not
depending on the Python version; it now lists on every version, and the junk byte is
reported as trailing data.

**Bytes after the end are reported.** The archive ends where the end record's declared
comment ends. A non-zero byte after that is `ARCHIVE_TRAILING_DATA`
(`expected_marker="zeros_to_eof"`, `format="zip"`, `observed_bytes` counted from the
comment's end), found at open by the scan TAR, 7z, RAR and ISO share
(`internal/trailing_scan.py`), or from a pipe at the end of the pass; zero padding is
silent and `STRICT` refuses (DR-3). Bytes inside the declared comment are the comment,
whatever they look like. A tail longer than the search window hides the end record from
the search; the reader then walks the local headers from the start (the pipe's walk,
seeking over sized members and scanning bit-3 ones for their descriptor, decoding
nothing) and steps over the directory and the records after it to the end record
(`step_over_directory`). That open costs up to one read of the file, and each
local header counts toward `max_members`, as on a pipe. A pipe steps over the records
after its pass, from the bytes it keeps right after the members.

**Members are independent.** Each member has its own LFH and its own compressed byte range,
with no cross-member state. So reaching any member is a seek rather than a walk (`DIRECT`),
two members can be open at once because neither decoder depends on the other's state, and
there is no solid-block cost model. A solid 7z or RAR block gives you none of that.

Seeking *within* a member is a different question and the answer is no: a compressed member
decodes sequentially, so a backward seek re-decodes from the start of the member, or from the
nearest seek point when the deflate accelerator is in play. Only STORED members are random
access in the real sense. Past a megabyte of re-decoding the stream says so, with
`STREAM_REWIND_REDECOMPRESSES`. **Seekable member streams** and **concurrent member streams**
are both off by default even here — see §6.

**Sizes and the CRC may arrive after the data.** With general-purpose bit 3 set, the LFH
carries zeros and a DD follows the compressed bytes. The CDH carries the real values, so
a random-access read is unaffected; a forward-only reader sees them late, and has to find
where the data ends without them (§2.2.2). This is also why the ZipCrypto verification
byte is the high byte of the DOS time rather than of the CRC when bit 3 is set.

**Names are bytes plus one unreliable flag.** General-purpose bit 11 declares UTF-8;
unflagged names are nominally CP437. Producers set the flag on names that are not UTF-8
and omit it on names that are, and the flag alone does not recover the intent. The one
in-band oracle is optional: Info-ZIP's Unicode Path extra field (`0x7075`) stores the name
again as UTF-8 beside a CRC-32 of the header's bytes, so a renamed entry with a stale field
is detectable. Without it, decoding is a judgement (§2.2), `raw_name` keeps the stored
bytes so a wrong decode can be undone, and a flag the bytes contradict is overruled (§2.2).

## 2. The pipeline here

Each stage: who does the work, what is ZIP-specific rather than general, what is refused.

### 2.1 Identify

ZIP declares four magics at offset 0 — `PK\x03\x04` (local header), `PK\x05\x06` (empty
archive), `PK\x07\x08` (spanned marker) and `PK00PK\x03\x04` (APPNOTE 8.5.4's no-span
marker, which PKZIP may write before the first local header of a one-segment set) —
and six extensions: `.zip`, `.jar`, `.pyz`, `.whl`, `.apk`, `.cbz`. Comic-book aliases:
`.cbr` → RAR, `.cbz` → ZIP, `.cbt` → TAR, `.cb7` → 7z. Magic wins; a ZIP named `.cbr`
emits `FORMAT_EXTENSION_CONFLICT` (see [`rar.md`](rar.md) §2.1).

When searching a prefixed archive for a ZIP, archivey looks only for the local header
(`PK\x03\x04`). The no-span marker is just a local header with 4 bytes in front, so that
search finds it. The other two magics are not useful search targets: `PK\x05\x06` would
appear before a local header only for an empty archive, and `PK\x07\x08` is the spanning
marker — 7-Zip's own `-sfx -v` writes the stub as a standalone executable and the volumes
as separate `.zip.NNN` files, so a concatenated stub-plus-spanned-ZIP is not the shape that
tool produces. Measured: `7z a -tzip -sfx -v40k` left a 416 KB stub containing **no ZIP
signature at all** beside parts that join into an ordinary byte-split ZIP starting with
`PK\x03\x04` and carrying no spanning marker anywhere. Neither magic carries fields a cheap
check can validate the way a local header can, and the survey in
[`topics/prefixed-archives.md`](../topics/prefixed-archives.md) §4 found every `PK\x05\x06`
match in a binary to be a string constant parsing to nonsense.

A local-header hit is confirmed by `validate_zip_local_header` (`internal/backends/zip_detect.py`)
before it is reported: version-needed in range, no reserved general-purpose bits, a known
method id, a non-empty name, and name+extra within the source.

**The first of those does nearly all the work.** `PK\x03\x04` occurs 148 times across
3 332 ELF and PE files under `/usr/bin`, `/usr/lib`, `/usr/local` and `/opt`, and the
validator rejects every one on version-needed alone, which must fall in 10–99 and instead
reads as whatever the surrounding bytes happen to be. Twenty-three of the 148 are the magic
followed by a run of zeros — so that shape is real rather than a story about padding, and
it fails the same check, since 0 is below the floor. The name and name+extra checks never
fired on this corpus at all; they are there for shapes it does not contain, such as a
header truncated by the end of the file.

The validator's method table is deliberately **wider** than the set archivey can decode: a
member using a method we refuse to read is still a ZIP, and identity is not a support
claim.

Two things are ZIP-specific rather than general in the shared detector:

- Prefixed ZIPs are found only when the leading bytes look like an executable or script
  (`MZ`, ELF, or `#!` at offset 0). That gate is what keeps the forward search from reading
  up to 2 MiB of every file a caller opens. A hit is reported as `ZIP` with a
  `payload_offset`, ahead of the content probes (the tier that reports headerless stream
  codecs), so a stub with a ZIP behind it comes back as a ZIP rather than as a guess at the
  stub's own bytes. `THOROUGH` does not lift the gate today — `THOROUGH_BUDGET` raises probe
  links, index bytes and the completion window but keeps the same 2 MiB window, and the gate
  itself is unconditional (`detection.py:609`); a gate-free exhaustive scan is designed and
  not shipped. The cue set, the scan window, the budget tiers and why a hit is
  validated are shared with 7z and RAR —
  [`topics/prefixed-archives.md`](../topics/prefixed-archives.md). What is ZIP's alone: the
  local-header search and its validator above, the offset conventions in §3, and the fact
  that ZIP is the only format that can locate itself from the end.
- A **tail probe** — locating the EOCD directly instead of scanning forward — is designed and
  not shipped, and ZIP is the only format it can serve. Until it lands, a prefixed ZIP behind
  bytes that look like neither an executable nor a script (a JPEG polyglot, a plain
  concatenation) is not detected, though `open_archive(..., format=ZIP)` reads it. The probe
  cannot be gated the same way: a ZIP an executable cue would reach is already found. So it
  means one tail read on every source — free on a hit, since the backend reads the EOCD
  anyway, and pure waste on a miss, which is most files. Calling `open_archive` rather than
  `detect_format()` does not change that arithmetic; it runs the same detection and wastes
  the same read. What gates it is that nobody has measured what that wasted seek costs on a
  cold cache or a remote source — not false positives, which validation handles.

### 2.2 Open and list

archivey's own parser (`internal/backends/zip_parser.py`, ADR
[0020](../decisions/0020-native-zip-reader.md)) finds the end record at open and walks
the central directory (the CDH run) as members are listed. Open reads nothing else but
the trailing-data scan, unless the tail search finds no end record: then open walks the
local headers from the start (§1, and the "no end record" row below). Each listed member
keeps a small locator (`_ZipLocator`: offsets, sizes, CRC, flags, method, and what its
open needs), not the directory entry, so an entry's extra field is not kept alive.
`reader.get()` and name lookup are satisfied from the listing with no further archive
I/O.

The walk records each entry's local-header offset for the overlap guard (§4) and counts
the entries for `member_count`. Every member open comes after that walk has ended: a
streaming pass over a seekable source walks the whole directory before its first
member's data, so it reads the directory once and then moves forward only. Only
`info.member_count` read before the listing runs one index pass over the directory
instead. Both walks charge `ListingLimits.max_members` in every mode, because each keeps
an offset per entry; an end record that declares more entries than the limit, in a
directory large enough to hold them (46 bytes each), is refused at open. A count the
directory cannot hold is a wrong field: the walk charges the entries really there, and
the mismatch is reported below. Both walks stop at the same entry, at the limit as at
damage, and the members before the stop read with the overlap bounds of the entries
before it.

**A damaged directory lists up to the damage, then the local headers past it.** An entry
with a wrong signature, whose 46-byte fixed header the directory cuts short, or whose
lengths swallowed the entries after it (below), raises
`CorruptionError` after the members before it, as a cut TAR or RAR does (DR-2), and
after the members the local headers hold past it: the headers are walked once, as for a
ZIP with no end record, and a member the directory already listed (by offset) is not
listed again. Those keep what their local header holds and nothing the directory alone
has (mode, host, comment), as a read from a pipe lists them, so the two reads write the
same files (davi, 2026-10-14). `members_report()` carries both, iteration and
`extract_all()` deliver those members and then raise, and `member_count` is `None`. The
overlap guard keeps one bound per listed member: a directory entry before the damage
that points at no local header bounds nothing, and one over a real header the walk
stepped over (inside another member's stated data) still bounds its neighbours, so two
entries over it stay an overlap. A walk over the local headers that meets a listing
limit raises the limit instead. One that cannot get past a member's data lists that
member, whose read fails, never as `TruncatedError` (the end record follows it), and the
listing still raises the damage; the pass meets that error first and raises it.

A damaged name, extra or comment length can swallow the entries after it: the entry
then ends at a later entry, or past the directory's end. Stdlib cuts the field at the
directory's end and lists it: one member named `a.txtPK\x01\x02…`, the swallowed
members gone, and only the entry-count warning, while a pipe lists every member from
its local headers. Info-ZIP `unzip` stops with "expected central file header signature
not found" and 7-Zip with "Headers Error". So the walk treats three shapes as damage:

- an entry whose fields run past the directory's end;
- an entry whose name, extra field or comment holds a central header signature from
  which the headers chain exactly to the directory's end, when either the declared
  count fits that reading or the first of those headers points at a local header with
  its name. The count alone cannot decide: a swallow can leave it agreeing with the
  entries that remain (then `unzip` and 7-Zip list the swallowing name without an
  error; archivey takes DR-1's side), and a member comment can hold a whole
  well-formed entry, which chains too but points at another member's local header. A
  signature that does not chain so is part of the name, and a wrong count alone stays
  the count warning below;
- an entry no header follows whose local header holds another name: its name length
  was made shorter. A next entry with a damaged signature, where the local header
  agrees, leaves the entry listed from the directory with its mode, but without its
  comment: one of its lengths is wrong, and the comment, its last field, may be cut.

Whether the headers from a directory position chain to its end depends on the
directory's bytes alone, so the walk remembers each position a chain steps onto past its
first header, with the answer, and a later chain stops there. Each such header is
stepped over once per walk, and the reads past the walk's own go through one buffer: a
directory of crafted chains costs about one more pass over it, however many signatures
point into them. The memo holds at most 4096 positions (about 400 KiB), forgetting those
the walk has passed, since chains only step forward; a ladder longer than that costs
steps instead. Most signatures are settled before any following: the header one would
start steps past the directory's end, or onto bytes the walk holds that start no header.
A signature that is part of a name fails there and spends nothing. Two budgets bound
the rest: headers stepped over, as many as the directory could hold, and bytes read,
twice the directory. Past either, the walk fails closed: an entry holding a signature it
can no longer follow is damage, since a swallow cannot be ruled out. What stays is time:
a directory of nothing but signatures lists at about 155 ns a byte, an ordinary one at
about 5 ns ([threat model](../threat-model.md#no-cpu-or-wall-clock-bound)).

A local header that the file cuts short means the directory pointed at the wrong place
(the directory follows every local header), so it is `CorruptionError` too, never
`TruncatedError`.

**"Version needed to extract" decides nothing.** Stdlib refused an archive whose entry
said it needed more than 6.3; 7-Zip 23.01 reads such a stored member and Info-ZIP
`unzip` 6.0 skips it. archivey lists and reads it: what a member needs is named by its
method and flags, checked when it opens (DR-4).

**Split sets are settled before anything else, and the two conventions get opposite
answers.** 7-Zip's `.zip.NNN` parts (and SFX `.exe.NNN` slices of the same `-v` split)
are byte slices of one finished archive, so a
complete set is concatenated by `internal/volumes.py` and read as the ordinary
single-disk ZIP it is — the same code path and the same regex that already joined
`.7z.NNN`, because it is the same `-v` flag doing the same slicing. Path parts
are sized with `stat()` and the joiner keeps a small cache of Path handles
(size and miss cost: [stream-ownership](../topics/stream-ownership.md)). The stub
`name.exe` beside those parts is not a sibling; if it has no archive magic,
`open_archive` follows it to `name.exe.001` or `name.zip.001` (including under
`format=ZIP`). Info-ZIP's
`.z01 … .zip` is a genuinely spanned set whose entries are addressed by
`(disk, offset-within-disk)`, so it keeps refusing. §3 has the producer detail.

Two files with the same part number in different padding (`x.zip.002` and a stray
`x.zip.0002`), or in different case on a case-sensitive filesystem (`X.ZIP.002`), are one
part, not a repeat: discovery takes the name opened, then the one padded and spelled like
the name opened, as 7-Zip does when it predicts the next part's name, and falls back to
the lowest name, never listing order (measured, 7-Zip 23.01 opens `x.7z.001` beside a stray
`x.7z.0002` and reads `.002`; it refuses a set renamed to mixed widths, which archivey
still joins). The same rule picks RAR `.partN` volumes ([`rar.md`](rar.md) §2.2). An
explicit sequence naming both is still refused as a repeated part.

A lone numbered part (`.zip.NNN` / `.exe.NNN` / `.7z.NNN` with no siblings) is
`TruncatedError` naming the missing parts — the same incomplete-set error as a
gap, not the ZIP "not supported" message. A part that is not on disk itself is
`FileNotFoundError`, like any other missing path. Info-ZIP `.zNN` stays
`UnsupportedFeatureError` with the rejoin-first text. Both run in `open_archive`
before detection, because middle parts have no magic at offset 0 and detection
alone would raise `FormatDetectionError`. When the parser reads the end record:
non-zero EOCD disk fields (the ZIP64 end record's when there is one, else the
classic record's, with `0xFFFF` treated as the ZIP64 sentinel),
which is what catches Info-ZIP's final `.zip` part — it would list cleanly, because it
holds the central directory — and a ZIP64 locator claiming more than one disk. Both
raise `UnsupportedFeatureError` from the parser itself.

Two things narrow the filename refusals. A joined set keeps part one's name, so they key
off *whether the set was joined*, not off the name alone; otherwise they would fire on
the very set `open_archive` had just rejoined. And they defer to an explicit non-ZIP /
non-7z `format=`, which must be honoured or refused as a *format conflict* rather than as
a volume error. Nameless streams are out of scope for them entirely.

`ArchiveInfo.is_multivolume` is `True` for a joined set and
`ArchiveInfo.extra["zip.volume_count"]` carries the part count, matching what 7z reports
for `.7z.NNN`. Both live on `ArchiveInfo`, not on `ArchiveMember` — `member.extra` is the
more reachable of the two and stays empty here. They describe how the archive arrived,
not its ZIP structure, which is single-disk.

**Name decoding.** A set bit 11 is honoured as UTF-8 when the bytes are valid UTF-8. An
unflagged name is decoded as UTF-8 when the bytes are valid UTF-8, and otherwise with
the caller's `encoding=` when one was passed, else with
`ArchiveyConfig.zip_unflagged_fallback_encoding` (default `cp437`, which decodes every
byte, so no `UnicodeDecodeError` escapes). Both decode with `surrogateescape`. The
parser hands the reader the stored bytes, so nothing is decoded twice. A flagged name
that is not valid UTF-8 is decoded as an unflagged name that is not UTF-8 would be
(`encoding=`, else the fallback), with `MEMBER_NAME_ENCODING_INFERRED` naming that codec
and `declared_encoding="utf-8"`: the flag is the one claim the bytes can check, and they
refute it. The Unicode Path field is not consulted for it, as for any flagged name. This
departs from stdlib's `metadata_encoding` and from `unzip -O`, which apply the codec to
every unflagged name: a valid UTF-8 name wins over `encoding=` in every format (design
rules, ruled 2026-10-07), so a legacy `encoding=` fixes the legacy names in a mixed
archive without garbling its UTF-8 ones.

Choosing UTF-8 for an unflagged name emits `MEMBER_NAME_ENCODING_INFERRED`; a pure-ASCII
name does not, because ASCII decodes identically under both and nothing was overridden.
The sniff is validation rather than guessing: UTF-8 is self-checking, so a clean decode is
near-conclusive evidence. No equivalent is possible for the legacy tail — see §5.

Before any of that, an unflagged name with a Unicode Path extra field (`0x7075`) in its
central-directory entry is named by the field when the field is version 1, its CRC-32
matches the stored name bytes, and its name is non-empty valid UTF-8. It outranks the sniff
and an explicit `encoding=` alike, as in 7-Zip, which also consults it only for unflagged
names and before its code page switch. Info-ZIP `unzip` and stdlib `zipfile` 3.12+
(`ZipInfo.filename`) use it too. `raw_name` is then the field's UTF-8 bytes, so `name` stays
`raw_name` decoded, and the header's bytes go to `extra["alternate_raw_name"]`; no
diagnostic, since the field declares its encoding. A stale field (CRC mismatch) or an
unknown version is not about this name and is ignored like any unknown record. A
**malformed** field is dropped with `MEMBER_HEADER_RECORD_SKIPPED` (`record="unicode_path"`,
`record_id=0x7075`) and the name decoded as if it were absent: one shorter than its
version byte and CRC, or one whose CRC matches but whose name is empty, not UTF-8, or
runs past the end of the extra field. That
is the RAR5 extra-record ruling ([`rar.md`](rar.md) §6) applied to ZIP's one optional name
record: one bad record costs that record, not the archive. Only the field of an unflagged
name is consulted, so a flagged name's field is never read or reported. The local header's
copy is not read: the listing comes from the central directory, and the local header's
name is only compared with the central one.

Stdlib from 3.12 acts on the field while reading the central directory: it raises
`BadZipFile` over a field shorter than five bytes (whatever its CRC) or a CRC-matching
one that is not UTF-8, and calls `warnings.warn` on an empty one, outside the
diagnostics system; 3.11 ignores it, and so does 7-Zip. archivey's parser reads the
field itself, so the outcome is the same on every Python version and no warning filter
is touched.

Backslashes are normalised on `name` by origin, not globally: a DOS/FAT-origin entry's `\`
is treated as a path separator and rewritten to `/`; a Unix-origin entry keeps `\` as a
literal filename character. `raw_name` keeps the stored bytes unchanged: the header's,
or the Unicode Path field's when that named the member.

**Metadata mapping.** The parser hands the reader the central-directory fields
(`CentralEntry`, ZIP64 values already resolved) and the raw `extra` blob; the reader
classifies symlinks, parses the NTFS, Unix and Extended Timestamp extras into
datetime fields, reads the owner ids from the Unix extras, and keeps the fields it
took nothing from in `extra["zip.extra_fields"]`.

| `ArchiveMember` field | Source | Absent when |
| --- | --- | --- |
| `name` | CDH name bytes, decoded as above, or the CDH Unicode Path field's name; `\` → `/` only for DOS/FAT-origin entries | — |
| `raw_name` | The stored bytes `name` was decoded from, verbatim (no backslash rewrite) | — |
| `extra["alternate_raw_name"]` | The CDH name bytes, when the Unicode Path field named the member | No such field, or it does not match |
| `mode` | The permission bits of `external_attr >> 16` | The producer was not Unix-like, or the high word is 0 (a Unix host that stored DOS attribute bits at most, which unzip 6.00 also reads as no Unix mode) — then `None`, never a substituted default |
| `uid` / `gid` | The owner extra fields, read in blob order as unzip 6.00 reads them (§6): Info-ZIP new Unix `0x7875` (version 1, ids of 2, 4 or 8 bytes; Info-ZIP `zip` writes it on Unix by default, 4-byte ids) and Info-ZIP Unix type 2 `0x7855` (16-bit ids) each decide the owner afresh, readable or not, and a `0x7855` after a `0x7875` is ignored; PKWARE Unix `0x000d` and Info-ZIP old Unix `0x5855` (16-bit ids after two times) count only when neither came before, and then the last one that holds ids wins. The two 16-bit Info-ZIP fields hold the ids in local headers only (their central copies are empty, or the two times alone), so a file read finds them only from writers that copy the ids into the directory. A forward pass yields no owner, and takes the directory's at the end | No such field, or the deciding field holds none. A `0x7875` of another version and the central short copies are silent; a deciding field that is cut short, too short for its ids, a `0x7855` neither empty nor exactly 4 bytes, or a `0x7875` with an id size unzip does not read gives none and is dropped with `MEMBER_HEADER_RECORD_SKIPPED` (`record="unix_owner"`, `record_id` the tag). Writers on Windows store none |
| `uname` / `gname` | — | Always: no ZIP extra field records owner names |
| `modified` / `accessed` / `created` / `ctime` | CDH DOS date-time (naive local, 2-second granularity) ← NTFS extra `0x000A` (UTC) ← PKWARE Unix `0x000d` or Info-ZIP old Unix `0x5855` (access and modification time, UTC) ← Extended Timestamp `0x5455` (UTC), later overriding earlier — parsed by archivey. macOS `ditto` and Archive Utility write only `0x5855`, so without it a macOS archive would list naive local DOS times. The Unix fields' times follow unzip 6.00 (measured with `unzip` on crafted local headers): ignored in a blob that holds a `0x5455` with data, or after a `0x7855` or `0x7875` (the rule their ids follow), the last one long enough for both times winning. They sit above NTFS, which unzip on Unix does not read. The two "creation" slots (NTFS FILETIME, Extended Timestamp third time; the latter wins) mean what the writer's host says, not what the field says: on Linux and macOS, 7-Zip and p7zip fill the NTFS one from `st_ctime` and libarchive the UT one; Info-ZIP and `ditto` there store no creation time. From a FAT / OS2 / NTFS / VFAT host ("version made by", `_ZIP_BIRTH_TIME_HOSTS`) the time is a birth time and is `created`; from any other host, unknown included, it goes to `ctime` and `created` is `None`. libarchive on Windows stamps host 3 but stores the birth time, so its time lands in `ctime` too. Info-ZIP on Windows puts its birth time in the UT field of the local header only, which listing does not read. Per-writer measurements: [`writer-timestamp-slots.md`](../investigations/writer-timestamp-slots.md) | 1980 sentinel, or every layer invalid. Each invalid layer emits `MEMBER_TIMESTAMP_INVALID`, whose `field` is the member attribute that layer would have filled (the creation slot `created` or `ctime` by the same host rule), even when a lower layer still fills it |
| `type` | Symlink via the `FILE_ATTRIBUTE_REPARSE_POINT` bit in the low word of `external_attr` — provisionally, until the member's data confirms it (§2.2.1) — or via Unix mode bits in its high word; directory when the decoded name (the one `name` comes from) ends in `/`, or in `\` for a DOS/FAT-origin entry, the same on every host OS and Python version. A directory whose `file_size` is not 0 (APPNOTE 4.3.8 forbids it; unzip, 7-Zip and bsdtar create the directory and drop the bytes silently, Go's `archive/zip` refuses the archive) stays a directory, emits `MEMBER_DIRECTORY_DATA_IGNORED` with both sizes, carries its stored CRC-32 in `hashes` (the central directory's, or the local header's on a listing from local headers) (unless that field is 0, the conventional value for a directory: then no digest, and `DIGEST_UNVERIFIABLE` where the CRC was the only check, unencrypted or ZipCrypto; a WinZip AES entry, AE-1 with a zeroed field or AE-2 which stores 0 by design, is checked by its HMAC instead and reports nothing), and reads through `open()` like a file: `_open_with_link_follow` refuses a directory by data and a tombstone or special entry by type. `stream_members()` yields a stream for the same directories (`pass_has_data`), from a file and from a pipe, except a bit-3 directory from a pipe: its `size` is `None` until the descriptor, so the pass yields `None` and `ZipForwardReader._directory_data_reach` words the message to say so. The pipe pass checks the bytes against the CRC-32 by the same zero-field rule (`_PassData._crc_is_digest`). `file_size == 0` over a body larger than an empty one of its method (`_ZIP_EMPTY_BODY_SIZES`: 0 stored, 2 deflated, 14 bzip2, 19 LZMA) is reported too and not readable; `compress_size == 2` deflated is the Java `jar` tool's empty body and is silent. A Unix FIFO, device or socket mode makes `OTHER` only when `file_size` is 0; with data it is a `FILE` (`zip -FI` stores a named pipe's content so, and unzip, 7-Zip, bsdtar and `zipfile` all write it as a file) with `MEMBER_SPECIAL_FILE_HAS_DATA`, DR-25. Both carry `extra["special_file_type"]` | — |
| `link_target` | The member's **data**, not its metadata — a bare path for a Unix symlink, a `REPARSE_DATA_BUFFER` for a Windows one (§2.2.1) | The member is encrypted and no password is available, so there is nothing to read it from — `SYMLINK_TARGET_UNAVAILABLE(reason="password_required")`, whose context carries the member's identity and the reason and nothing out of the member; or the ZipCrypto data failed its integrity check under a password only the check byte vouched for, with `reason="password_or_damage"`; or the data failed its CRC, HMAC or decompressor under a password that was not in doubt (or no password at all), with `reason="target_data_damaged"` and the damage raised when the link is opened or extracted; or the data uses a method or flag this reader does not decode (`reason="target_data_unsupported"`) or needs an optional library that is not installed, a codec or `cryptography` for AES (`reason="package_not_installed"`), with that error raised when the link is opened or extracted; or the writer stored no usable reparse data, with `reason="reparse_data_absent"` (no data at all), `"reparse_data_unrecognized"` (data that is not a link buffer — a file-shaped member is re-typed to carry it, a directory-shaped one stays a targetless link, §2.2.1) or `"reparse_data_nameless"` (a link buffer that parsed but named no target); or, from a pipe only, the pass dropped the data to stay within its bound on what it keeps for link targets, with `reason="target_data_dropped"` (§2.2.2) |
| `compression` | CDH method → `CompressionMethod` | — |
| `is_encrypted` | general-purpose bit 0, or method 99: a WinZip AES member is encrypted even when a writer left bit 0 clear, and opening it asks for a password either way, so listing and opening share one predicate | — |
| `hashes["crc32"]` | CDH CRC (the local header's or data descriptor's on a listing from local headers; `_crc_is_digest` says which members carry one), as four big-endian bytes — present for AE-1 (and verified on read); omitted for AE-2, where the format zeroes the field and the HMAC is the integrity signal | WinZip AE-2 members |
| `comment` | CDH member comment. APPNOTE puts it under the name's bit 11, so it decodes as the name would: UTF-8 when flagged over a valid UTF-8 name; unflagged, or flagged over a name that is not UTF-8, the same sniff as an unflagged name (UTF-8 if valid, else `encoding=`, else `zip_unflagged_fallback_encoding`), with no diagnostic; a byte the codec leaves undefined survives as a lone surrogate. Before the sniff, an Info-ZIP Unicode Comment field (`0x6375`) gives the comment by the Unicode Path field's rules (above): version 1 with the CRC-32 of the stored comment, read as 7-Zip reads it (Info-ZIP `unzip` 6.00 prints the header bytes instead); a malformed one is dropped with `MEMBER_HEADER_RECORD_SKIPPED` (`record="unicode_comment"`). The field is read only when bit 11 is clear, as for a name, so a flag the name refutes leaves it unread, as in 7-Zip 23.01. When the field gives the comment, the header's comment bytes are not kept: unlike a name, a comment is never looked up, so there is no `alternate_raw_name` counterpart, and 7-Zip shows only the field's text too. `ArchiveInfo.comment` (the end record's, which has no flag) decodes as an unflagged one | The entry stores none, which is the common case |
| `create_system` | CDH "version made by", high byte | Never — an unrecognised value maps to `CreateSystem.UNKNOWN` rather than to nothing |
| `extra` | `zip.compress_type`, plus `zip.aes_vendor_version` / `zip.aes_strength` / `zip.aes_actual_method` on AE members, plus `is_reparse_point` from the attribute bit and `is_junction` when a stored reparse buffer says so (§2.2.1) | — |
| `extra["zip.extra_fields"]` | The CDH extra fields archivey took no value from, as `{tag: data}`: unknown tags (a vendor's field, the `jar` tool's empty `0xcafe`) and known ones that gave nothing (malformed, a Unicode Path field about another name, a `0x5855` under a `0x5455`). The first of several fields with one tag; a tag any copy of which gave a value is left out, and so are the structural ZIP64, WinZip AES and Strong Encryption fields. Charged to `max_metadata_bytes` at 72 bytes per field plus its data (an empty field retains about 70 bytes). A pipe pass sets it when it reaches the directory | Every field gave a value, or there are none: the usual case |

Raw extra-field blobs are not surfaced. Duplicate names are legal and are not merged:
members keep a positional `member_id`, name lookup is last-wins, and currency is computed
in the reader spine so ZIP behaves like every other format.

#### 2.2.1 Windows reparse points, and the junction that cannot be found

A Windows symlink and an NTFS junction are both *reparse points*, and the attribute that
marks them — `FILE_ATTRIBUTE_REPARSE_POINT`, `0x400` in the low (DOS) word of
`external_attr` — is the same for both. What tells them apart is the **reparse tag**
(`IO_REPARSE_TAG_MOUNT_POINT` `0xA0000003` against `IO_REPARSE_TAG_SYMLINK`
`0xA000000C`), and that tag is not in any header: it is the first field of the
`REPARSE_DATA_BUFFER`, which archivers store as the member's *content*. So archivey
reads it exactly where it already reads a symlink target, in `_ensure_link_target`,
and `extra["is_junction"]` is a listing-time flag whose source is read-time data. The 7z
backend has the same problem for the same reason and shares the whole path: the parsing
in `archivey.internal.windows_reparse`, and in `BaseArchiveReader` the capped read
(`_link_target_from_data`), the settle of a reparse point stored with no data
(`_settle_empty_reparse_point`) and the report when encryption blocks the read. Each
backend supplies only which members are reparse points and what type one reverts to.
A pass (`stream_members()`) under `read_link_targets` reads each symlink's data when it
reaches the member, before yielding it, so a reparse point whose data is not a link
buffer is yielded as a file with its content; a streaming pass used to decide only when
it ended, after yielding the member as a link with no stream. Under
`read_link_targets=False` such a link reads `member_state_final=False` until its data
is read.

Two things follow, both measured against archives built on a Windows runner
(`tests/fixtures/external/README.md` §`junction/`):

**7-Zip's `-snl` is the only common writer that records any of this**, and it records it
only for a **file** reparse point. bsdtar follows a junction outright and rewrites
Windows symlinks as Unix ones; `Compress-Archive` follows everything.

**A junction is always a directory reparse point, and 7-Zip stores no data for those.**
`junction_dir` and `symlink_dir` come out byte-identical: the reparse bit set, the
directory bit set, zero bytes of content, no extra field carrying the buffer. The tag is
simply not in the archive, so `is_junction` is not derivable from one, and 7-Zip cannot
restore the junction from its own output either. Such a member is surfaced as a symlink
with `link_target` unset and a `SYMLINK_TARGET_UNAVAILABLE(reason="reparse_data_absent")`
diagnostic — a link whose target the writer discarded, rather than a plain directory,
which is what it was before and which silently lost the fact that anything was there.
The trailing `/` the writer stores on that entry is dropped by `normalize_member_name`,
because the member is not a directory; the same member has always been spelled without
it in 7z. The ZIP backend passes `link_stored_as_directory` to
`emit_member_name_normalized` so that drop does not report a `MEMBER_NAME_NORMALIZED`
anomaly — the flag is explicit precisely because the suppression rules are shared, and a
TAR `SYMTYPE` entry named `link/` *is* an anomaly worth reporting.

`extra["is_reparse_point"]` records the bit itself, so it is available while listing and
stays set even when the data turns out not to be a link buffer and the member is
re-typed. `extra["is_junction"]` is the stronger claim and needs the tag out of the data,
which is why a 7-Zip-written junction carries the first key and not the second.

**The attribute bit is a candidate, not a verdict; the data decides.** `0x400` says the
entry was a reparse point on the source filesystem. It does not say the archive carries
the buffer, and it does not say the tag named a link — Windows sets the same bit for
deduplication stubs, cloud placeholders and WSL entries, whose data is ordinary content.
So a **file-shaped** member whose data is present but does not parse as a link buffer is
put back to the type it would otherwise have had and keeps that content, with
`SYMLINK_TARGET_UNAVAILABLE(reason="reparse_data_unrecognized")` recording the
reinterpretation. Presenting it the other way round would cost the caller a readable
member on the strength of a bit, and `open()` on it would raise.

**Data longer than the buffer is not the buffer** (maintainer decision, 2026-10-21).
Windows returns exactly the 8-byte header and `ReparseDataLength` bytes, so a member whose
data runs on past them is data that does not parse as a link buffer, and takes the
re-type above. The read stops one byte past the buffer, as before. Reading such a
member as a link used to leave the rest of its data and its CRC unread, so one changed
byte in the target listed as a different target with no error. As a `FILE`, the member's
CRC is checked when it is read. A read that meets a failed CRC at that one byte past the
buffer is damage (`target_data_damaged`), not a re-type. The 7z backend shares this
parse, and the pipe pass agrees (`ZipForwardReader._link_target_opener`). For a buffer
over the bound it keeps, it uses the size from the directory. For data within the target
cap, which it decodes to the end, a failed CRC past that one byte does not decide: it
keeps the data and gives the file read's answer, a `FILE` whose read raises the damage.
When the bound on what it keeps drops such data (§2.2.2), it keeps the verdict instead:
whether the data, read as far as a file read reads it, parses as no buffer.

Two members are left a link with no target. One has *no* data, so there is nothing to
reinterpret. The other is **directory-shaped** — stored with the trailing slash — where
the re-type would buy nothing: `open()` refuses a directory, so the data the re-type
exists to preserve stays unreachable regardless, and the entry has already lost its
trailing slash to name normalization (whose diagnostic the backend suppresses for a link
stored with the directory convention, §2.2.1). It keeps the `reparse_data_unrecognized`
reason, since that is still what happened; only the outcome differs.

**What the target looks like, and what extraction does with it.** The buffer holds a
Windows path, so the parser normalizes it (`normalize_windows_link_target`, shared with
7z and with RAR5 redirect types 2 and 3): every `\` becomes `/`, a leading `\??\` or
`\\?\` is dropped, and `UNC\` after it becomes `//`. So `\??\C:\Windows` lists as
`C:/Windows`, `\??\UNC\srv\share` as `//srv/share` and `..\up\x` as `../up/x`, in
all three formats. Extraction refuses a symlink target with a drive letter or a UNC root
at every policy and on every OS (maintainer ruling 2026-10-06, `safe-extraction`): on
POSIX `C:/Windows` would otherwise be created as a relative link into a directory named
`C:`, and on Windows the same archive is refused, so one archive would extract two ways.
`STRICT` and `STANDARD` also refuse a `:` or a Windows-reserved device name in a target
segment (`file:stream`, `sub/NUL`), as they do in a member name.

The junction path in the reader is therefore correct and unreachable from any archive
these tools produce. It is kept, and tested against an assembled buffer, because the
format permits a writer to store one and the `archive-data-model` spec promises the
flag.

**A symlink's digest covers the bytes the link is stored as.** ZIP stores a link's target
as the member's data, so `hashes["crc32"]` is a real digest — of a *path* for a Unix
symlink (9 bytes for `file1.txt`), and of the `REPARSE_DATA_BUFFER` for a Windows one
(§2.2.1), which is a Win32 structure rather than the path inside it. Either way it is not
a digest of whatever the link resolves to. Kept, because the value is genuine and 7z and RAR3/4 record
exactly the same thing; said out loud, because `hashes` otherwise reads as being about
content, and a caller de-duplicating by digest or checking content without decompressing
would take it that way. RAR5 is the instructive contrast: it stores links as header
redirects with no data stream, so its CRC32 field covers zero bytes and archivey surfaces
no digest at all rather than the constant `crc32(b"")` —
[`formats/rar.md`](rar.md) §2.2.

**The end record is checked against the directory the walk read.** The walk reads
directory entries until it has consumed the size the end record gives. After the last
member, the reader emits the walk's findings as `ARCHIVE_EOF_MARKER_MISSING`: an entry
count that differs from the entries read (the ZIP64 record's count when there is one; a
classic count modulo 65536, because old 7-Zip versions stored a larger count's low 16
bits without ZIP64 and current 7-Zip's `ZipIn.cpp` accepts that with a "16-bit overflow"
note), and an archive comment length past the end of the file. Info-ZIP unzip warns or
errors on each and 7-Zip says "Headers Error", after testing every member, so the
default policy lists and reads; `STRICT` refuses. The end record is the last signature
in the tail, so a decoy end-record signature inside the archive comment passes the
checks: the archive lists as empty (`EMPTY_ARCHIVE`), as with Info-ZIP unzip, where
7-Zip searches further back and lists the real members.

#### 2.2.2 From a pipe: the forward pass

A non-seekable source under `streaming=True` is read by `ZipForwardReader`
(`internal/backends/zip_forward_reader.py`) over `LocalHeaderWalk`
(`internal/backends/zip_local_walk.py`), which parses each local header and each central
header with the parser's own code and reads the source forward only. `streaming=False`
on a pipe raises `StreamNotSeekableError` naming `streaming=True`. Nothing is spooled
(ADR [0010](../decisions/0010-no-silent-buffer-nonseekable.md)). The receipt is
`REQUIRES_SCANNING`, `DIRECT`, `FORWARD_ONLY`; `member_count` and the archive comment
are `None`, and `members_report_if_available()` returns `None`, until the directory has
been read. The full design, row by row, is the `native-zip-reader` change's `design.md`
(§"Streaming: a forward walk over local headers").

**Where a member's data ends.** A sized local header gives it. With bit 3 set, a member
the caller reads to its end is decoded to the codec's end marker (DEFLATE, Deflate64,
bzip2, Zstandard, LZMA with the EOS bit, PPMd with its end mark), then the walk finds
the data descriptor by the decoded CRC; a STORED member ends at a descriptor whose CRC
and size match the bytes before it and that a ZIP signature follows, signed or not. When
none matches whole, one with a single damaged field still ends the member
(`match_damaged_descriptor`): without its signature, two of its CRC, compressed size and
uncompressed size agree; with it, its compressed size or two fields; with a damaged
signature, all three. So one damaged byte in a STORED member's data, or in the
descriptor of a member the walk ends by its CRC, fails that member alone, by its CRC or
size check or by the directory at the end of the pass, and the members after it are
read. A scan matched on the size alone (below) has one field to go on and takes no
damaged descriptor. A bit-3 codec member the pass reads past (nobody read it, or the
caller stopped early) is
decoded no further than the byte past the 4096-byte target cap, then the reparse prefix
a file read reads (the buffer and one byte, §2.2.1), and one byte past that prefix:
bit-3 data has no size, so only a decode that returns nothing says it ended there, and
the two reads stop at the same place. A member whose codec ends within that is checked
as a read to its end is. Past it the walk passes the member by the STORED member's scan
on its stored bytes, matched on the size and the signature after the descriptor, since
the CRC covers the decoded data: decoding the rest would cost what no limit bounds (a
900-byte bzip2 member decodes to 1 GiB). A descriptor planted in the data then ends the
member early, and the directory catches it at the end of the pass. An encrypted bit-3
member nobody reads is passed the same way on its ciphertext, so no key is needed. A
bit-3 LZMA member without EOS has no end its codec can find, and its read is
`UnsupportedFeatureError`. PPMd has no flag for a missing end mark: such a member fails
its decode, as from a file. A bit-3 codec member whose decode fails or finds no end is
passed by the same scan on its stored bytes. The scan starts at the bytes the walk kept
of what the decode read (`_CODEC_RETAIN`, 4 MiB) and counts the ones before them into
the size it matches, so the descriptor is found unless the decode read more than that
past the data's end; then the scan runs to the end of the stream and the pass ends with
its error. A bit-3 PPMd member is fed to pyppmd in pieces, in a child process unless
`process_isolation` is `NONE`. Several
password candidates are confirmed on the first 1 MiB, kept and replayed (§2.3).

**What the pass yields, and what changes at the end.** Each member is yielded with what
its local header gives: `mode`, `create_system` and `comment` are `None`, the type is
`FILE` or `DIRECTORY` from the name (a trailing `\` is a `DIRECTORY` until the host is
known), a `\` inside a name is a literal character, and `member_state_final` is `False`.
`uid` and `gid` are `None` as well, though a local header can carry them (§6). After the
last member the pass keeps what follows (bounded by the listing limits, see
`_tail_bound`) and parses it with `find_end_record` and `CentralDirectoryWalk`, so it
picks the end record and reads the directory exactly as a file read does. Each member is
then updated in place from the directory entry at its offset: type, name (a DOS host
makes `\` a separator), mode, host, comment, times and owner ids from the directory's
extra fields, and `is_current`, which follows the directory order. Member ids and listing
order stay the file's. A local entry no directory entry points to is dropped and reported
as `ARCHIVE_UNLISTED_DATA`. A reparse-flagged member whose data is not a reparse buffer
stays a file. `max_members` is charged on the local headers as they are yielded and again
on the directory's entries, whose text is weighed against `max_metadata_bytes` as it
arrives. The archive comment is weighed once the end record is read.

**What the pass keeps for link targets.** A symlink's target is its data, and only the
directory says which members are links, so the pass keeps the data of every member short
enough to be one (`MAX_LINK_TARGET_BYTES`, 4096 bytes decoded), the ciphertext of an
unread encrypted one (8 KiB), and a Windows reparse buffer's start of longer data
(§2.2.1). This is files' data, which a file read never keeps, so it is not charged to the
listing limits: an archive of 20 000 files of 4 KB lists from a pipe as from a file. It
is bounded on its own (`ZipForwardReader._hold`): the pass holds at most
`max_metadata_bytes` of it, on top of the listing, and drops the longest first, since a
link target is a path and shorter than most files. At the directory it keeps only the
links' data. A link whose data was dropped is listed without its target and reports
`SYMLINK_TARGET_UNAVAILABLE` with `reason="target_data_dropped"`, naming
`max_metadata_bytes`; the rest of the listing stands, and `extract_all` does not place
the link and fails that member alone. A drop keeps no bytes, but it does keep one
verdict: whether the data is no reparse buffer as a file read reads one
(`_NO_BUFFER_REASONS`). A Windows reparse point whose dropped data is no buffer is then
re-typed as from a file (§2.2.1), so the bound changes a target, never a type. The
verdict costs one parse of at most the dropped data, at the drop, and no bytes held.
Kept ciphertext is not decrypted to decide, so the dropped data of an encrypted reparse
point nobody read stays a link with no target.

**Bytes after a member that are no local header.** The walk stops at the first bytes
after a member that are not a local header and keeps the rest of the stream, as after
the last member. Bytes a writer left between two members (zeros, junk, a data descriptor
after a member whose sizes are in its header) and a second archive appended with `cat
first.zip second.zip` end the walk there (after a bit-3 member they end the pass
instead, below). Once the directory has been read, each member it places in the kept
bytes is read from them at the offset it names and yielded before the pass ends, as a
file read seeks to it. Only the offsets the directory names are read there, so the pass
yields no member the file read does not list. Of a `cat`, the first archive's members
are yielded as the walk meets them; the file read lists only the second's, so they are
dropped and reported as `ARCHIVE_UNLISTED_DATA`. A member the directory places in bytes
the listing limits dropped ends the pass with `ResourceLimitError`: higher limits keep
them. Overlapping entries are a different case, malformed input that no limit relieves.
Every byte an attempt there consumes is counted, a member read or a local header that
fails to parse, and once the count reaches the bytes held, the next entry ends the pass
with `CorruptionError` before it is read, so the kept bytes are consumed at most twice,
not once each. A local header that is there and does not parse fails its entry at the
end of the pass, with the parse error as the reason. A stub with no local header in the
scan's 2 MiB window, ending within it on an end record, is read the same way, so an
empty archive, or one whose members are gone, behind a stub opens as from a file.

**Extraction** stages, then places (`ExtractionCoordinator._stage_then_place`; the
`pipe-zip-stage-then-commit` change has the design). During the pass each member the
selection may take has its data written to one `.archivey-tmp-<random>` directory under
the destination, after the universal checks and the name policy pass on its local
header's name. Once the directory is read, the members are placed in listing order by the
same per-member code a file read uses: the selection made for good, the `filter` once,
the policy checks, the overwrite policy and collisions on the final member, and each staged
file landing by a rename. A run that stops before placement leaves nothing of its own in
the destination, so no link is ever written as a file holding its target.

**Failures found at the end of the pass** (`_failed_at_end`,
`_placement_data`): a data descriptor the directory contradicts, a local header
whose CRC, sizes or encryption flag the directory contradicts (not a central CRC-32 of
0 over data against a local value, §5), a same-name pair whose directory order reverses the
file order, and a directory entry with no local entry. Each fails its member
(`CorruptionError`; the reversed pair only updates the members in `stream_members()`),
and extraction does not place it. A directory entry pointing at a local
header an earlier entry took ends the pass with `CorruptionError`. Two headers storing
different names fail nothing: the member takes the directory's name, and a file or link
reports `MEMBER_LOCAL_NAME_DIFFERS` as a file read does when it opens the member (§5);
extraction places it under the directory's name. Two headers naming different compression
methods fail nothing either: the pass decoded by the local one, as a file read decodes,
and a file or link reports `MEMBER_LOCAL_METHOD_DIFFERS`, also when the member fails on
a CRC or size the directory contradicts: a file read reports once the local header
passes its checks, before it decodes, so it reports a member whose data then fails. A
member the file read's overlap guard refuses on its central compressed size reports
nothing from a file and still reports from the pass, which keeps no such bound
(§"Where the pass and a file read differ"). WinZip AES is the exception: method 99 in
one header only, or in both with AES records that differ in any field (version,
strength, real method) or with one side's record missing or unparseable
(`aes_record_differences`), is refused as a header disagreement, without the report. A
file read refuses it too, by the same error except where the pass fails it mid-pass
(§"Where the pass and a file read differ"). The listing keeps the directory's method in
`compression` and `extra["zip.compress_type"]`, as every listed field comes from the
directory (a CRC-32 of 0 aside, §5).

**Where the pass and a file read differ.** The first seven are shapes only crafted archives
have (DR-5a). The next five come from staging the
members before the directory is read, and DR-5a names each of them. The rest come from
damage, from the directory's refusals the file read is to drop, or, for the last one
only, from the bound the pass puts on the data it keeps for link targets, which an
ordinary archive can reach:

- A data descriptor that understates a STORED member, or a bit-3 codec member the pass
  reads past, and the reversed same-name pair, fail a member the file read writes.
- Junk between a bit-3 codec member's end and its descriptor counts into the member,
  where the file read refuses it (DR-3). The walk searches at least 64 KiB
  (`_DESCRIPTOR_SEARCH_PAST`) past the bytes the codec was handed for the descriptor,
  whatever the member's size; with more junk than that the pass can end there.
- The first of several inconclusive password candidates wins (§6).
- A local header without bit 3 whose size field holds all ones that no ZIP64 field
  holds is refused (`CorruptionError`); the file read takes the sizes from the directory
  and reads the member.
- WinZip AES (method 99) in the directory with another method in the local header: a
  file read refuses the member with `CorruptionError` (the AES record is the directory's,
  so the two headers disagree on the encryption). The pass has the local header alone, so
  it decodes by what that says, usually ZipCrypto, whose check byte the AES data fails:
  `EncryptionError`.
  Only a crafted archive has this shape (DR-5a). The other direction, method 99 in the
  local header only, raises `CorruptionError` from both reads (the pass at its end).
- Method 99 in both headers with AES records that differ: a file read refuses the member
  with `CorruptionError` naming the fields. The pass decodes by the local record, so it
  fails the member at the end on the records only where that decode succeeds (a real
  method that fits, AE-2 over AE-1, a missing central record). Otherwise it fails it
  during the pass: another strength gives the wrong key, so `EncryptionError`; AE-1 over
  AE-2 checks a CRC-32 the AE-2 entry leaves at 0, so a CRC-32 mismatch; a missing or
  unparseable local record, `UnsupportedFeatureError`. Only a crafted archive has this
  shape.
- A directory entry naming another compression method and a compressed size that runs
  into the next local header or the directory: a file read's overlap guard refuses the
  member while checking its local header, before `_with_local_method` reports, so it
  raises `CorruptionError` with no `MEMBER_LOCAL_METHOD_DIFFERS`. The pass keeps no such
  bound: it reports the method once it reads the directory and fails the member on the
  sizes, so under `STRICT` it raises `DiagnosticRaisedError` there. Matching it would
  mean rebuilding the guard's per-member bound (the next local header, or the
  directory's start) in the pass, for a crafted-only shape (DR-5a).
- Under `on_error="stop"`, a member whose data fails as the pass stages it stops the
  run, though the directory may then not list or select it. A refusal of the local
  header's name by the universal checks or the name policy stops the run the same way
  only under `abort_on` (`blocked_member` for a refusal, `name_sanitized` for a
  rewrite). `on_error="stop"` alone does not stop on it: the refusal blocks the member,
  as a refusal at placement does, and the run goes on, as from a file.
- A member refused on its local header's name and accepted on the directory's (a
  crafted pair of names, or a `filter` that renames an unsafe name such as
  `../evil.txt`) fails at placement, its data not staged, where the file read writes it.
- A member whose local name ends in a backslash is a folder to the pass, which stages no
  data for it. When the directory names a host that makes it a file with data (`d\`
  from a Unix host), it fails at placement (`ExtractionError`), where the file read
  writes it.
- The bomb limits count what the pass stages while it is staged, so a member staged and
  then not placed, a member the `filter` drops included, can still stop a run under
  `max_entries` or `max_extracted_bytes` that the file read completes.
- A run stopped before placement (`abort_on`, `on_error="stop"`, a limit, a `STRICT`
  refusal at the directory) leaves nothing of its own in the destination, where the
  file read keeps every member it wrote before the stop, links made.
- A bit-3 codec member whose data is damaged can fail with another error than from a
  file (`TruncatedError` where the file read says `DataAfterEndError`, for one): the
  file read knows its stored size, and the pass finds its end by the scan for its
  descriptor (§"Where a member's data ends"). The members after it read the same,
  unless its decode read more than 4 MiB past the data's end: then the pass ends there.
- A bit-3 member whose data descriptor has one damaged field fails at the end of the
  pass, as the directory contradicts the descriptor: the file read never reads the
  descriptor, and reads the member when its data is intact.
- A bit-3 codec member whose stream runs on into its descriptor (the stream's last
  byte is the descriptor's first) reads from a pipe. The file read is the right one:
  it stops at the compressed size the directory and the descriptor state, and raises
  `TruncatedError`. The pass does not know where the codec ended, so it finds the
  descriptor by the decoded CRC and size, and that CRC still checks the data (DR-1).
  To match the file read, every codec (Deflate64 and PPMd too) would have to say
  exactly where its input ended, through the decrypt stages (DR-5a). One flipped bit
  can make this shape; it is the mirror of the junk case above.
- A bit-3 LZMA member without the EOS bit is refused (`UnsupportedFeatureError`); a
  file read knows its size and reads it.
- A bit-3 member followed by bytes that are no ZIP record (a gap before the next
  member) ends the pass: its descriptor counts only when a ZIP signature follows it,
  which is what stops a descriptor planted inside its data. A STORED one is
  `UnsupportedFeatureError`, a codec one `CorruptionError`. A file read knows its size
  and reads every member. After a sized member the same bytes are read past
  (§"Bytes after a member that are no local header").
- A link member the pass staged as a file keeps the error its data read gave: under no
  password an encrypted link fails with `EncryptionError`, where the file read reports
  `LinkTargetNotFoundError`.
- A damaged directory lists the directory's entries before the damage and the local
  headers' past it in both reads, then raises; the two write the same files. The pass
  applies the directory to the members it describes before the damage and keeps the
  rest as their local headers say, without reporting them as unlisted.
- Damaged ZIP64 end records no longer refuse the archive in either read. When no
  field of the classic end record holds the ZIP64 sentinel and the directory's end can
  be placed, the classic record is used and `ARCHIVE_EOF_MARKER_MISSING` (marker
  `zip64_end_of_central_directory`, `observed_kind="absent"`) reports it. Otherwise
  the end records cannot be used: the file read walks the local headers, lists what
  they hold and raises the end records' error, as the pass does. A locator naming an
  offset among the members' data reads the same, though the two say why in different
  words: a file read checks the bytes there, the pass has passed them. One naming
  bytes the pass's listing limits dropped is a `ResourceLimitError` from a pipe, since
  higher limits keep those bytes.
- A symlink whose target is behind `max_metadata_bytes` of short members' data no
  shorter than it is listed without its target (`target_data_dropped`); the file read
  lists it (§"What the pass keeps for link targets"). A reparse point whose dropped data
  is no buffer is re-typed as from a file, except for an encrypted one nobody read, whose
  dropped ciphertext is not decrypted: it stays a link with no target where the file read may
  re-type it.

### 2.3 Member data

**`zipfile`'s own decoders were never used** — meaning `ZipExtFile`, not the standard library:
the codec layer still ends at `zlib`, `bz2` and `lzma` for the methods they cover. archivey
locates the member's raw compressed bytes with a bounded LFH parse (the fixed 30 bytes
plus the local name and extra lengths, with an absurd data-offset cap and a name
comparison with the CDH that reports a mismatch), slices the source, and dispatches on
the ZIP method id to the shared codec layer.

The reason is coverage and uniformity, in that order. `ZipExtFile` handles STORED, DEFLATE,
BZIP2 and LZMA; the codec layer adds Deflate64 (9), Zstd (93) and PPMd (98), which the
registry already advertised for ZIP, and XZ (95), which is core. It also puts ZIP member reads on the same
`VerifyingStream` and the same exception translation as every other backend, so a corrupt
body raises `CorruptionError` and a cut-short one raises `TruncatedError` through shared
code — and it is what lets a ZIP member use the accelerators when the caller turns them on,
since `use_rapidgzip` covers raw deflate.

**Codec settings 7-Zip names but this reader cannot decode are unsupported, not
corrupt.** An LZMA member's properties byte with `lc + lp` over 4 (7-Zip accepts up to
12 and writes it with `-mm=LZMA:lc=8`; liblzma stops at 4) raises
`UnsupportedFeatureError` through `decode_lzma_filter_properties`, the check the 7z
pipeline uses for the same byte; properties it cannot read at all (a byte past 224, a
blob of the wrong length) are `CorruptionError` from the same function. A PPMd member's
restore method 2 is `UnsupportedFeatureError` and 3 to 15 `CorruptionError`, as 7-Zip
reports "Unsupported Method" and "Data Error". Each of these errors names the member.
Under ZipCrypto those settings are decrypted with a key one byte vouched for, so both
stay `CorruptionError` there and count as the candidate failing.

A member's compressed data is its codec's data and nothing else, as 7-Zip, Info-ZIP and
`zipfile` read it. For most methods that is one stream; for Zstd and XZ it is the frames
or streams their formats define as the data (below). Each codec ends the member at the
end of that data (an LZMA member at its end marker; `lzma.LZMAFile` would start a second
raw stream on the bytes after it and read that as content). The reader opens every
member with `StreamConfig.refuse_input_after_end`, so any byte of the compressed data
the codec leaves after that end, a zero too, and a second stream where the format defines
one, are `DataAfterEndError` (a
`CorruptionError`), raised once the output before them has been read, whatever the
declared size and CRC cover. 7-Zip 23.01 `7z t` fails every such member ("Data Error",
or "There are some data after the end of the payload data"), and the bytes may be a side
channel (`design-rules.md` DR-3). Under ZipCrypto the read raises the `EncryptionError`
of an unconfirmed password instead, caused by that `CorruptionError`, as the verify
table below records. A Zstd member (method 93) reads every frame, skippable ones too, as
a `.zst` file and a 7z Zstd coder do: RFC 8878 defines Zstd data as one or more frames,
and the member's sizes and CRC check the whole output (maintainer, 2026-10-21). Bytes
after the last frame that start no frame are refused like any other input after the end. An
XZ member (method 95) reads the same way, for the same reason: the xz format (spec §2.2)
defines its data as one or more streams with stream padding (groups of four zero bytes)
between and after them, and 7-Zip 23.01 and 26.05 read such a member in full. Zero bytes that
do not fill a group of four, or any other byte after the last stream, are input after the
end; 7-Zip fails those members too. An LZMA member with bit 1 clear, and a PPMd member,
end at their declared size, and their input must end there too: right after it for LZMA
(or one zero byte later, which 7-Zip's encoder sometimes writes), after the end mark
PPMd8 must carry. So a declared size short
of the stream's data is `CorruptionError`, not `TruncatedError`: the input is too long,
not short. The 7z handbook (§ coders, *Input after the stream*) has how each codec finds
its end, and what it cannot see; `inflate64` drops input after a Deflate64 stream's end
and has no `unused_data`, so `Deflate64Decoder` holds back the last byte it is given,
and input follows the end when `eof` is already True as that byte goes in. The
accelerators read on into a second stream; at the bytes after the first they hand the
read over to the standard library, which refuses them, so the verdict does not depend on
the accelerator, with one exception. rapidgzip does not say where a DEFLATE stream ends,
so when its output ends zlib decodes only the tail, from the last point of rapidgzip's
complete index before the end, to find a final block and any input after it. The index
is taken whole, not from the points the stream kept as it read, so the result does not
depend on timing; it depends on the data and on how many threads rapidgzip runs, which
follows the core count (it places points every few hundred KiB to a few MiB of output on
Linux and macOS; on the windows-latest CI runner a ZIP member's index held none past 0,
so there the check decodes from the start). A second stream that holds that point is
then the stream whose end the check sees, and a member whose size and CRC cover both
streams reads as both under rapidgzip; with the accelerator off it is
`DataAfterEndError`, and 7-Zip and Info-ZIP read the first stream and fail the CRC. No
known writer makes such a member. Finding the first stream's end would take a zlib
decode from the start, which cost a full read under rapidgzip as much as the
standard-library read it replaces (maintainer decision, 2026-10-24; `design-rules.md`
DR-5a). A shorter second stream, junk, zeros and a cut stream keep the standard
library's verdict.

Encrypted members take the same route with a decrypt stage between the slice and the codec
layer, so they decode every method an unencrypted member does, and their CRC runs through
the same fused verifier:

| | Decrypt stage | Notes |
| --- | --- | --- |
| Traditional ZipCrypto | archivey (`zipcrypto.py`, `ZipCryptoDecryptStream`) | One-byte verifier, so ~1 in 256 wrong passwords passes it. Pure Python, byte by byte, at the speed of stdlib's own decrypter (~1.6 MiB/s here). The cipher state depends on every earlier byte, so a backward seek restarts from the saved post-header state and a forward seek decrypts what it skips; `AUTO` accelerators stay off over it, because they read out of order. A seek back, or a forward seek in a compressed member (whose next read decodes the gap), keeps the CRC; a forward seek in a STORED member jumps, and a read past it gives the CRC up. The CRC is ZipCrypto's only content check: after that, the rest of the member is checked for length only (ADR 0014). A 12-byte header the file cuts short is `TruncatedError` on every password path |
| WinZip AES (method 99, extra `0x9901`) | archivey (`zip_aes.py`) | AES-128, -192 or -256, as the extra's strength byte says · PBKDF2-HMAC-SHA1 at 1 000 iterations · AES-CTR · HMAC-SHA1 truncated to 10 bytes |
| PKWARE Strong Encryption (APPNOTE §7: bit 6, or extra `0x0017`) | refused | Listed as encrypted; opening it raises `UnsupportedFeatureError` naming Strong Encryption, with or without a password. A symlink of this kind lists with `link_target` unset (`target_data_encrypted`). When the central directory itself is encrypted (bit 13), it cannot be listed; an archive extra data record (`PK\x06\x08`) where the directory should start makes the open the same refusal instead of a `CorruptionError` from the listing. Best-effort: without that record the archive reads as corrupt |

Both cheap key checks admit some wrong passwords (ZipCrypto 2⁻⁸, WinZip AES 2⁻¹⁶), so
both schemes share one confirmation ladder (`password_confirm.py`). With **one** possible
password it is accepted on the cheap check, and the CRC or HMAC at EOF is the real test.
With **several**, each surviving candidate runs a bounded confirm before one is accepted:
for a DEFLATE, Deflate64, bzip2, LZMA or Zstandard member the decompressor rejects a wrong
key within a few bytes, so a bounded prefix decode is enough (`REJECTING_CODECS` in
`password_confirm.py`, re-measured by the tests). PPMd is not a measured rejecter, so a
PPMd member is decoded to its CRC once per surviving candidate. A WinZip AES member whose
CRC is out of reach (AE-2 has none) is read to its end instead when it fits the budget or
has no rejecting codec: the HMAC covers the whole member. A **STORED** ZipCrypto member
has no decompressor, so the only discriminator is the whole-stream CRC — all surviving
candidates are resolved in one shared ciphertext pass computing each candidate's CRC in
constant memory, earliest match winning. That cost is irreducible for the format.
The CRC each candidate is matched against is the member's CRC-32 digest, not the header
field (`_member_crc_anchor`). A member that lists none — AE-2, and a directory whose CRC
field is 0 over declared data (§2.2 `type` row) — has no CRC to match: a ZipCrypto one
skips the shared pass and takes the bounded confirm, a WinZip AES one is confirmed by its
HMAC. Matching the field's 0 failed every candidate, the right one included, where one
password read the member.

From a pipe the data goes by once, so there is no second walk. The pass keeps the first
`PASSWORD_CONFIRM_MAX_INPUT_BYTES` (1 MiB) of the member's data and runs each candidate's
bounded confirm on it; the winner reads those bytes, then the rest of the stream. A bit-3
member is confirmed only when it ends inside them, by its descriptor's CRC or the HMAC.
When several candidates are still inconclusive, the first wins, and its CRC or HMAC at
the end decides, as for one password (§6). The pass keeps the ciphertext of an unread
encrypted member short enough to be a link (8 KiB) and decrypts it only if the directory
makes it one. A member whose local header states a plaintext size that fits a link but
whose ciphertext is longer (only a padded codec stream) is decoded as the pass drains it
instead, only under `read_link_targets` (its default): that reads a target nobody asked
for, and may ask a password provider about a member that turns out to be no link. A
bit-3 member's sizes come after its data, so one that long is not kept or decoded, and
its target is lost where the file read has it (tracked for stage 3.4).

With one ZipCrypto password, a wrong password that passes the check byte fails where the
decrypted bytes first meet a check. `open()` parses an LZMA or PPMd member's codec
header, the first bytes decrypted, so an LZMA member usually fails there, and a PPMd
member does when its two-byte header decrypts to parameters out of range. Otherwise it
is the first read or forward seek the decoder objects to, and for a STORED member the
CRC at the end. Each raises the same `EncryptionError` that names both a wrong password
and damage (§5).

**A read that stops before the check is reported.** When nothing stronger than the cheap
check accepted the password (one password), or a confirm used up its budget without
reaching a CRC or HMAC, the member stream watches for the caller stopping short. Closing it
after reading some bytes and before the end emits `ENCRYPTED_MEMBER_UNVERIFIED`: those
bytes may have been decrypted with a wrong password. `check` says which of the two
accepted it (`weak_open_check`, `confirm_budget_exhausted`); `reason` is `partial_read`,
or `seek` for a ZipCrypto member whose seek jumped past its read position and so lost
its CRC (a STORED member's forward seek), even if it then read to the end. A WinZip AES
seek keeps the HMAC, so there only a read that reaches the end counts. Extraction reads
every member to the end and never emits it, and a candidate that a CRC confirmed has
nothing to report.

For AES, a wrong password fails fast on the 2-byte verification value with no bytes
returned; a tampered ciphertext fails on the HMAC at the terminal read, as
`CorruptionError` whether one password or several were tried. Every candidate that
reached the HMAC had passed the 16-bit check, so damage is the likelier cause. A partial
read then `close()` is quiet — HMAC is a content verdict, not teardown
([ADR 0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md)). AE-1
surfaces and verifies `crc32` alongside the HMAC; AE-2 surfaces neither. Under
`seekable_members=True` an AES member seeks by restarting CTR at the target's block. A
seek that jumps gives up the AE-1 CRC once a read passes it, but never the HMAC: the
read that returns the last byte reads the ciphertext the seeks skipped (no decryption)
and completes the HMAC.

An unknown method id lists fine and raises `UnsupportedFeatureError` on read — never
guessed output. A missing optional package raises `PackageNotInstalledError` naming the
extra.

### 2.4 Extract

Nothing here is ZIP-specific. Path traversal, symlink escape, name collisions,
cross-platform name safety and the byte/ratio/member caps are all the shared extraction
spine — see [`safe-extraction`](../../openspec/specs/safe-extraction/spec.md) and
[`threat-model.md`](../threat-model.md). A blocked member does not end the run; the rest of
the archive still extracts.

### 2.5 Write

Not shipped, and not ZIP-specific: no format has a writer. `format-zip` used to specify
streaming write via data descriptors and no longer does — the requirement went in
`2026-09-02-drop-unshipped-write-claims`, to be restored with the writing phase rather
than edited around. The format-level fact it rested on survives in §1: a ZIP records late
sizes in a DD, which is why bit 3 exists at all.

## 3. In the wild

**ZIP is the container other formats are built on.** JARs, wheels, APKs, zipapps, OOXML
and the ODF family are all ZIPs, and `open_archive` reads them as such with nothing to
distinguish them from a backup. A census of 643 readable ZIPs on one Linux image found 363
JARs (`META-INF/MANIFEST.MF`), 176 ODF-family (a `mimetype` entry stored first, 176/176,
none compressed), 11 wheels, and 91 with no marker at all — of which 85 were named `.zip`
and none was user data. Recognising the role is post-1.0 and, if built, must report "not
recognised" rather than "this is data"; the idea is in [`IDEAS.md`](../IDEAS.md)
§Detection. For ZIP the cheap tests are nearly free, because the first entry's name and
its `compress_type` are both already in the central directory.

**Prefixed ZIPs are an idiom, not an abuse** — `zipapp`, pex, shiv, Spring Boot executable
JARs, self-extracting installers, appended-ZIP polyglots. Two write conventions exist and
store different numbers:

| | Stored offsets count from | EOCD adjustment |
| --- | --- | --- |
| Written in place (`zipapp`: open one file, emit a stub, write entries through the same handle) | Byte 0 of the file, stub included | 0 |
| Concatenated (`cat stub payload.zip`) | The start of the ZIP data | The prefix length |

The difference is self-correcting: the EOCD's own position is known once it is found, so
`(eocd_pos - size_cd) - offset_cd` recovers the base under either convention and every
entry offset is read through it. Every member sits at the base plus a stored offset that
is not negative, so **the base is never after any member**.

`payload_offset` is where to start reading: **never after the archive's first member, and
exactly that member when the detection step saw it.** It is not only a label:
`open_archive` hands it to the reader, which cuts the source there, so a value after the
first member would cut members off. The forward scan meets the earliest local header and
reports it; an empty archive has no local header, so there it reports the base. A planned
step that finds the ZIP from its end record (the tail probe of the `pe-aware-sfx-location`
change) sees only the base, and will report that with no read to refine it.

**A base of 0 is a real answer, not a missing one.** For a ZIP written in place, the
stored offsets count from byte 0 of the file, stub included, so by the ZIP's own numbers
the archive starts at byte 0, and reading from there finds every member. The forward scan
reports the same ZIP at its first local header, after the stub; both are correct starts.
Today only the forward scan reports a prefixed ZIP, so `payload_offset > 0` still marks
one, as the `FormatInfo` docstring says. Once the tail probe ships it can report 0 for a
prefixed ZIP, and the test moves to a separate field (`FormatInfo.prefixed`, planned in the
same change).

**Producers disagree about encodings.** Info-ZIP and others write valid UTF-8 names without
setting bit 11, which is the case the sniff exists for; `tests/fixtures/external/encoding_infozip_jules.zip`
is a real sample.

**Producers disagree about split naming, and the disagreement is not cosmetic.** Info-ZIP
and WinZip write `name.z01 … name.zip` (and `name.z100+` once the set exceeds 99 parts);
7-Zip writes `name.zip.001 … name.zip.00N`. The two look alike and are different things:

| Family | Made by | Structure | Answer |
| --- | --- | --- | --- |
| `name.z01 … name.zip` | `zip -s` | true spanned set; entries addressed by (disk, offset), a `PK\x07\x08` spanning marker at the head of disk 1 | refuse |
| `name.zip.001 …` | `7z -v` | raw byte slices of one finished single-disk ZIP | join |

7-Zip's `-v` is a splitter, not an archive feature: it slices the finished output at a
fixed size with no awareness of what falls where, which is why the parts concatenate back
to the original and why the rejoined EOCD reads disk `(0, 0)`. That is the same thing it
does to `.7z`, so ZIP and 7z get the same answer for the same input.

Info-ZIP's do not, and a joined spanned set fails in a shape worth knowing: it **lists
correctly and then reads nothing.** The central directory survives intact on the final
disk, so enumeration works — but every entry's offset is relative to *its own* disk,
while the EOCD's `offset_cd` is relative to the last one. Reading a three-disk
`zip -s 64k` set joined by hand:

```
disk sizes [65536, 65536, 19117]      EOCD at 150167, size_cd=75, offset_cd=19020
stdlib's adjustment = eocd - size_cd - offset_cd = 131072   (= the two preceding disks)
first entry's header_offset after it = 131076 -> bytes there are b'\xaa\xff\x82\x12'
lists: ['p.bin']          read p.bin: BadZipFile: Bad magic number for file header
```

That constant is applied to every entry, and it is correct for exactly one disk — the
last. So a member whose local header sits on the final disk reads normally, and every
member before it lands in the middle of somebody else's data and raises `BadZipFile`.
Adding a small final member to the set above shows both halves at once:

```
big.bin    header_offset=131076   BadZipFile: Bad magic number for file header
last.txt   header_offset=150069   read OK, 17 bytes
```

Which members survive depends on where `zip -s` happened to cut, so a joined set is not
reliably unreadable — it is *partly* readable, which is worse. In sets without a small
tail member there is nothing to survive: 3, 5 and 12-disk sets all listed every member and
read none. The failures are at least loud — a wrong offset misses the `PK\x03\x04` magic
rather than returning plausible bytes. Refusing on the non-zero EOCD disk fields (§5)
refuses a set that cannot be read whole, not one that happened to work.

A possible later refinement for the refuse path — detect first, upgrade a failed detection
to rejoin-first when the name looks volume-shaped — is in [`IDEAS.md`](../IDEAS.md) until
someone takes it up; do not invent a ZIP-only half-step here.

**Producers disagree about encryption defaults.** 7-Zip's `-tzip` default is ZipCrypto and
`-mem=AES256` selects WinZip AES; stdlib `zipfile` writes neither. That is why the
encrypted corpus rows shell out to `7z` and skip silently without it. Reading is uneven
too: Info-ZIP `unzip` 6.00, still the default `unzip` on Debian, cannot read WinZip AES at
all and exits 81 ("unsupported compression method") on any method-99 member — an archive
archivey reads may be one the system CLI cannot.

**And about the AES vendor version.** AE-1 stores the plaintext CRC in the headers; AE-2
zeroes it, because for a very small file the CRC narrows the plaintext independently of the
cipher. 7-Zip writes AE-2, which is the modern default — but `pyzipper`, the
`zipfile` fork that adds WinZip AES to Python, wrote **AE-1 for every member regardless of
size** from 0.3.0 (2019-02) through 0.3.6 (2022-07), and 0.3.6 was the only release
available until 0.4.0 switched to AE-2 on 2026-05-14. Stdlib writes no encryption at all,
so a Python program emitting an AES ZIP in those four years was almost certainly emitting
AE-1. It is not a legacy branch kept for symmetry, and 0.4.0 still emits it under an opt-in
`conditionally_include_crc` for members of at least 20 bytes. `tests/fixtures/external/aes_ae1_pyzipper036.zip`
is a real sample; the CRC is verified on AE-1 and absent on AE-2 (§2.3).

ZIP64 is not exotic. A central directory of 70 000 entries lists correctly, through the
ZIP64 end record or, without one, as a classic count modulo 65 536 (§2.2).

**macOS writes ZIPs past 4 GiB without ZIP64.** Archive Utility (Finder's Compress,
`ditto -c -k`) keeps the classic records and stores every offset modulo 2³², the end
record's offset of the directory included; the producer markers are version made by
Unix 2.1, the old Info-ZIP `UX` extra field (`0x5855`) and data descriptors with
signatures. A backup in the scan had 261 of its 2 122 offsets off by exactly
2³², and 7-Zip and stdlib cannot open it
([`investigations/2026-10-backup-scan.md`](../investigations/2026-10-backup-scan.md)
§4). One rule recovers every offset, and `CentralDirectoryWalk` applies it: the
members lie in directory order, so an offset below the furthest end of the members
before it gets 2³² added until it is not. The wrapped directory offset shows up as a stub length
(`base`) 2³² too large, so the walk takes `base` modulo 2³². Each correction needs a
local header with the entry's name at the corrected offset, so a ZIP under 4 GiB
whose directory is out of file order is untouched (the corrected offset would be past
the directory, and nothing is read there). `ARCHIVE_OFFSET_WRAPPED` records each one.

**What Finder and `ditto` write besides sizes.** davi's tests on macOS (2026-10-16), a
folder with relative, absolute, dangling and directory symlinks, a hard link, an
executable, an xattr, a resource fork, an empty folder and an NFD name:

- Both write only stored directories and deflated files; `ditto
  --zlibCompressionLevel 0` still writes method 8, with stored blocks inside.
- Symlinks are Unix-mode entries whose data is the target; the hard link is a second
  copy. A FIFO hangs `ditto`.
- Names are UTF-8 without the UTF-8 flag (bit 11), NFD as the filesystem gives them,
  so every non-ASCII name reports `MEMBER_NAME_ENCODING_INFERRED`. davi chose to keep
  that diagnostic.
- Finder writes UTC into the DOS time field and `ditto` local time; both write the
  real UTC mtime in the `UX` field (`0x5855`).
- Both write `__MACOSX/<path>/._<name>` AppleDouble sidecars. `ditto` writes one for
  every entry, symlinks included, plus `__MACOSX/` directory entries, and drops the
  top folder unless given `--keepParent`. Finder keeps the top folder with its own
  sidecar and writes none for symlinks. archivey lists sidecars as plain files, like
  `unzip`; `ditto -x` folds them back into xattrs instead. §6 has why there is no
  marking key.

**A member over 4 GiB from macOS.** The same writer stores a member's sizes modulo 2³²
too, in the directory and the data descriptor alike. davi's tests on macOS (2026-10-15):
a Finder archive of five 1 GiB random files reads with the offset corrections; a
10 000 000 000-byte text file lists as 1 410 065 408 (10¹⁰ mod 2³²) and its read stopped
at that size with "Decompressed content exceeds its declared size". The archive records
the real size nowhere: the directory, the local header and the descriptor hold 32 bits,
the `UX` field (`0x5855`) holds only times and, in the local copy, owner ids, deflate
does not record its length, and the `__MACOSX/._name` sidecar is AppleDouble (Finder
info, extended attributes, resource fork; no data length).

- **The fingerprint** (`written_by_archive_utility` in `zip_parser.py`): version made by
  `0x0315` (Unix, 2.1), bit 3 set and bit 0 (encryption) clear (Archive Utility
  writes 16-byte descriptors with their signature, and never encrypts), and the
  central extra field is exactly one `UX` field. The reader also requires a classic
  end record, since the writer never writes ZIP64. The `__MACOSX` sidecars usually
  appear too, but are not required. Anyone can copy these fields, so
  the fingerprint only decides whether to try the corrections below. Each is checked
  against the archive's own bytes, and the CRC-32 is still checked on a read.
- **Compressed size, from the layout.** Only in a directory past 4 GiB can a compressed
  size have wrapped. There `CentralDirectoryWalk` holds each marked entry back until it
  has the next entry's offset, then measures the data from the local header's data
  start to the next local header (or the directory, for the last entry) less the
  16-byte descriptor. A length past the stored size by a positive multiple of 2³² is
  taken. The entry after a marked one looks for its header at its stored offset plus
  each multiple of 2³² in turn (from the first not below the members before it) and
  keeps the first with its name. The walk reads each local header once (its fixed
  part, then its name), and the data start comes from the same read, so the cost is
  one header read per member, only in a marked archive past 4 GiB. A pipe has the data
  starts of the `UX` local headers its pass met, and measures the same way.
- **Size, stored members:** the compressed size, when the two agree modulo 2³².
- **Size, deflated members: deflate's ratio bound.** The real size is the stored size
  plus some multiple of 2³², and the compressed size bounds it from above: a 258-byte
  match takes at least one bit of literal/length code and one of distance code, so a
  byte of deflate decodes to at most 1032 bytes. Nothing bounds it from below: empty
  stored blocks pad a valid stream without bound, so a large stream can decode to a few
  bytes.
  - **Only the stored value fits** (1032 times the compressed size is under the stored
    value plus 2³²): that is the size. Every member under about 4.16 MB compressed
    falls here (1032 × 4.16 MB ≈ 4 GiB), which is most members of a typical archive.
  - **Several fit:** the size is unknown. `size` is `None`, `extra["size_mod_2_32"]`
    holds the stored value, and `MEMBER_SIZE_WRAPPED` carries `size=None`. This covers
    every deflated member over about 4.16 MB compressed, whatever its real size, since
    only a read tells a member over 4 GiB from one under it. A file read decodes with
    no declared size (limits and the expansion ratio stay on); with no declared size,
    `AUTO` keeps rapidgzip off (it needs one to report a cut stream), so such a member
    reads through zlib unless the caller turns the accelerator `ON`. When a read
    reaches the end, the length must equal the stored value modulo 2³² and be at most
    1032 times the compressed size, then the CRC-32 must match, and only then does
    `member.size` take the length (`MemberVerifier`'s `end_check` / `fill_size`;
    `ArchiveMember` is mutable for late-bound fields, as digests are). Until then
    `member_state_final` reads `False` (the end of a `streaming=True` pass, or closing
    the reader, settles it).
    `extra["size_mod_2_32"]` stays after the fill-in, so the member still says the
    archive stored only the low bits. A pipe pass that decoded the member to its end
    with the directory's CRC-32 keeps the size it counted. For a bit-3 member nobody
    read, that is one whose codec ended within the symlink target cap; past it the
    pass decodes no further (§2.2 "Where a member's data ends") and `size` stays `None`,
    as from a file. davi chose this (option A,
    2026-10-15) over decoding such members while listing, which would read a whole
    archive of videos to list it. An entry with no CRC-32 (a directory carrying data)
    has nothing to check a read against, so it keeps the stored size instead of
    `None`; its compressed size, and a stored member's size, still come from the
    layout, which needs no digest.
  - **None fits:** the stored value is over 1032 times the compressed size, a damaged
    entry. The stored size stays and the read fails on it.
- Every member whose sizes were corrected or left unknown gets one `MEMBER_SIZE_WRAPPED`
  (`SizeWrapContext`: stored and corrected compressed size and size), advisory for the
  same reason as `ARCHIVE_OFFSET_WRAPPED`. Its message says the archive passed 4 GiB
  only when a size was corrected; an unknown one says only that the size may be past
  4 GiB. A member under about 4.16 MB compressed is untouched and reports nothing. A
  larger deflated member lists `size=None` and reports one even in an archive under
  4 GiB, since only a read tells.
- Archive Utility writes only stored and deflated members; another method under the
  fingerprint keeps its stored sizes.

## 4. Threat surface

ZIP-specific only. General extraction and name hazards are §2.4.

- **Listing is attacker-controlled work.** A small file can declare an enormous number of
  entries, or entries with enormous names and comments, with nothing decompressed. Capped
  by `ListingLimits`; see [`threat-model.md`](../threat-model.md) O1.
- **ZIP is the canonical bomb.** Declared sizes are attacker-controlled and so is the
  stored CRC, so neither bounds the output; the caps are enforced against bytes actually
  written, plus a live ratio measured from bytes consumed. Nesting is not tracked — a
  zip-of-zips amplifies one level at a time (O6).
- **Overlapping entries** are a distinct crafted shape, caught when a member opens by
  an overlap guard and raised as `CorruptionError`. The guard was stdlib's: each
  entry's data must end before the next local header in file order, or before the
  central directory. The bounds come from the offsets the listing walk records
  (`_DataBounds`, one sorted array), or from one index pass when `member_count` is
  read first (§2.2). Of two entries over one local header, the first in directory order reads
  and the later one is refused. stdlib raised on 3.11, on 3.12 before 3.12.10 and on
  3.13 before 3.13.3; 3.12.10+, 3.13.3+ and 3.14 warn and read both. archivey keeps
  refusing, because many entries over one local header is the overlapping-entry
  amplification shape (DR-9a). The guard runs before the local name is compared, so a
  refused entry reports only the overlap, under every policy, and no
  `MEMBER_LOCAL_NAME_DIFFERS`. The refusal is a per-member `CorruptionError`, never
  the always-stop `DiagnosticRaisedError`, so under `OnError.CONTINUE` the rest of the
  archive still extracts, `STRICT` included.
- **Confirming a ZipCrypto password costs time that depends on the archive, and that cost
  is observable**: the one-byte verifier cannot decide between candidates, so a STORED
  member is read through and its CRC compared. Timing the call, or watching how much is
  read, tells an observer that some candidate got past the byte check and that the member
  is stored — not which candidate, and never a password or a plaintext byte. Documented and
  deliberate; the alternative is accepting a wrong password one time in 256.
- The real-world case behind the cross-platform name policies arrived as a ZIP: a macOS
  archive containing a `stuff_etc.` folder, a trailing dot Win32 silently trims. Because
  the offending segment is a directory, rejecting it takes every member beneath it. See
  [ADR 0013](../decisions/0013-cross-platform-name-safety-policies.md) and O3.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — a
library archivey decodes with, fixable only upstream or by replacing it · **archivey** —
ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| A ZIP from a pipe opens only with `streaming=True`, and its members arrive without the fields only the directory holds: no mode, host or comment, and a symlink is a `FILE` until the pass reaches the directory | **format** | The index is at the end (§1). The pass updates the members in place from the directory and says so through `member_state_final`; extraction applies the same fields to disk at the end of the pass (§2.2.2) |
| From a pipe, a few crafted or damaged shapes fail a member, or leave files on disk, that a file read handles otherwise | **format** / **archivey** | The data goes by before the directory that would correct it arrives; matching the file read would mean buffering every member (ADR 0010). The list is in §2.2.2 |
| A name whose UTF-8 flag is set over bytes that are not UTF-8 decodes as an unflagged name, with `MEMBER_NAME_ENCODING_INFERRED`, and `DiagnosticPolicy.STRICT` refuses it | **archivey** | The bytes refute the flag, so it cannot be honoured; reading the name as unflagged keeps every other member and the name itself, where refusing cost at least the rest of the listing. The diagnostic's `declared_encoding` is `"utf-8"` and its `inferred_encoding` the codec used (§2.2) |
| A `.z01`…`.zip` split set is refused with "rejoin first", while a `.zip.001`…`.00N` set beside it opens | **archivey** | Not an inconsistency: the first is a true spanned set addressed by (disk, offset), which the format defines perfectly well and a native reader could follow, and which a linear join reconstructs only for whichever members happen to sit on the last disk (§3); the second is `7z -v` byte slices that rejoin into an ordinary ZIP (§3). The native ZIP reader exposes each entry's disk number but keeps spanned sets refused; reading them stays an idea ([`IDEAS.md`](../IDEAS.md)). Filename rules catch `.zNN`; EOCD disk fields catch Info-ZIP's final `.zip` part (`0xFFFF` is the ZIP64 sentinel, not a disk number). [`docs/formats.md`](../../docs/formats.md#zip) tells users |
| A single `.zip.001` handed over without its siblings is refused rather than read as a ZIP | **archivey** | Joining needs parts `1..N` beside it. The part opens with `PK\x03\x04`, so it looks like a ZIP to a detector, but the central directory is in the *last* part, so no end record is found and not even a listing is available. "Rejoin first" names the actual problem. A numbering gap is `TruncatedError` instead |
| An archive cut before its end record lists its members without mode, host or comment, then raises | **format** | Those fields live only in the directory. With no end record in the tail, the reader walks the local headers, lists what they hold as a pipe read does before its directory, then raises the walk's error (`TruncatedError` for a cut). A damaged *directory* lists the entries before the damage and the local headers' past it, then raises (§2.2) |
| A legacy name that is not valid UTF-8 renders garbled and no setting fixes it | **format** | Unless the writer added a Unicode Path field (§2.2), which Info-ZIP `zip` does and many writers do not, every candidate codepage decodes every byte, so there is no oracle, and a filename is far too short for a statistical detector. The garble is honest and `raw_name` round-trips; a wrong guess is neither. Opt-in detection is post-1.0 ([`IDEAS.md`](../IDEAS.md)) |
| A wrong ZipCrypto password can be accepted, and a damaged ZipCrypto member reads as a password error | **format** | One-byte verifier. With several candidates, confirmation narrows it; nothing eliminates it. Data that then fails its CRC or decompressor raises `EncryptionError` naming both causes, because a damaged member read with the right password fails the same way |
| A DEFLATE member that holds two streams, with a size and CRC that cover both, reads as both under rapidgzip and is `DataAfterEndError` without it | **library** / **archivey** | Only when the second stream holds the last point of rapidgzip's index, so a short second stream is refused either way. rapidgzip does not say where a stream ends, and finding the first one's end costs a decode from the start (§2.3, DR-5a). 7-Zip and Info-ZIP read the first stream and fail the CRC; no known writer makes such a member. `use_rapidgzip=OFF` refuses it |
| After a forward seek in a STORED ZipCrypto member, no CRC checks it, and a wrong password that passed the check byte goes unnoticed | **format** / **archivey** | The CRC is the only content check ZipCrypto has, and it covers the plaintext in order. A seek back keeps it, and so does a compressed member's forward seek, whose skipped bytes the verifier reads and hashes (ADR 0014, since 2026-10-10). A STORED member's forward seek jumps, so a read past it gives the CRC up and returns whatever the key produced. `ENCRYPTED_MEMBER_UNVERIFIED` (`reason="seek"`) says so on close when only the check byte vouched for the password (§2.3). WinZip AES keeps its HMAC across seeks |
| A ZIP over 4 GiB written without ZIP64 (macOS Archive Utility) reads, with an `ARCHIVE_OFFSET_WRAPPED` per corrected offset (advisory: macOS writes and reads them by default, so `STRICT` reads them too) | **format** | The writer stores offsets modulo 2³². The walk adds 2³² to an offset below the furthest end of the members before it and keeps it only when a local header with the member's name is there (§3) |
| A large deflated member of a macOS ZIP can list with `size=None` until it is read | **format** | Archive Utility stores sizes modulo 2³² and records the real size nowhere. Deflate's ratio settles it for members under about 4.16 MB compressed; for larger ones, `extra["size_mod_2_32"]` holds the stored one and a read to the end fills `size` in after the length and CRC-32 checks (§3). Members without the writer's fingerprint keep their stored sizes |
| A ZIP with a digital signature record (`PK\x05\x05`, APPNOTE 4.3.13) between its directory and its end record is refused with `CorruptionError` ("Bad magic number") | **archivey** | The end record's directory size and offset do not count the record, so its bytes shift where the directory is taken to start, the way prepended data does. stdlib `zipfile` refuses it the same way, and a read from a pipe matches the file read. Few writers produce the record; reading past it is not planned |
| A prefixed ZIP behind bytes that look like neither an executable nor a script is not detected, though it opens with `format=ZIP` | **archivey** | The tail probe is designed and unshipped (§2.1) |
| An LZMA member 7-Zip wrote with `-mm=LZMA:lc=8` (any `lc + lp` over 4) raises `UnsupportedFeatureError`, though 7-Zip reads it | **library** | The member is valid: the format allows `lc + lp` up to 12 and 7-Zip decodes it. liblzma, which stdlib `lzma` wraps, decodes `lc + lp` up to 4 only (`LZMA_LCLP_MAX`) and fails the rest with `LZMAError: Internal error`. Left unsupported by maintainer decision, 2026-10-08 (§6). 7z members behave the same ([`7z.md`](7z.md) §5) |
| A ZIP missing its first bytes lists every member, reads the members whose local headers survive, and raises `CorruptionError` for each member whose header was cut, saying how many bytes the archive seems to be missing | **format** | The central directory still names every member, but its offsets count from the lost start, so the first local headers fall before byte 0; the directory holds no copy of the lost bytes, so nothing recovers them. The number is `-EndRecord.base`, one for the whole archive. A directory offset or size field that is too large gives the same shape with nothing missing, so the message says "seems". Found in real files (a backup-drive scan, [§4](../investigations/2026-10-backup-scan.md)); `unzip` reports "missing N bytes in zipfile" and then fails every member |
| A member whose local header stores another name, or a real CRC-32 where the directory stores 0, reads with `MEMBER_LOCAL_NAME_DIFFERS` (which `STRICT` refuses) or `MEMBER_LOCAL_CRC_USED` (which `STRICT` reads); one whose two headers both understate its size is refused with `CorruptionError` | **archivey** | Found in real archives (a backup-drive scan, [§3.3-3.5](../investigations/2026-10-backup-scan.md)). `unzip` reads all three. The name case is another code page, or `\` against `/`; the directory's name is used, so the local one decides nothing. The CRC case is every Adobe AIR package's `META-INF/AIR/hash`; the data is checked against the local value. The size case is refused because the declared size is the bound that stops decoding (DR-9a). A file read sees the name only when it opens the member's data, and only a file or link reports it: extraction reads no directory's data, so neither read reports a directory's. A file read reads the local header of a zero-CRC file or link (not AE-2, whose HMAC checks it) when it lists it, one positioned read per such member; a directory's zero CRC keeps no digest from either read (`DIGEST_UNVERIFIABLE`). A local header naming another compression method is decoded by it and reports `MEMBER_LOCAL_METHOD_DIFFERS`, which `STRICT` refuses (§6). From a pipe, the pass reports these at the directory; under `STRICT` only the name and method cases raise there, after every member was staged and before any is placed, so nothing of the run is in the destination; the CRC case is recorded |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| archivey's own parser for the end record, central directory and local headers ([ADR 0020](../decisions/0020-native-zip-reader.md), superseding [0006](../decisions/0006-stdlib-zipfile.md)) | Zero-dependency still. Stdlib parsed the whole directory at open before `ListingLimits` saw a member, lost the archive over one damaged entry, varied by Python version and was reached through private names and exception text; the parser lists lazily, lists up to damage, and behaves the same everywhere | Stdlib `zipfile` (ADR 0006); `python-libarchive-c`, faster and broader at the cost of a native dependency |
| Under rapidgzip, check a DEFLATE member's end from the last point of rapidgzip's complete index (2026-10-24) | The check finds a cut stream and bytes after the last stream for the cost of the tail, where the index has a point before the end; where it has none (seen on the windows-latest CI runner) the check decodes from the start and costs what it did before. The complete index makes the result the same on every run on one machine, where the points a stream keeps as it reads depend on timing | A zlib decode from the start, which doubled a full read under rapidgzip (about 500 ms against 320 ms without it, 40 MiB member); a parallel zlib check of the stretches between resume points, prototyped at about 300 ms, which still costs as much as the read rapidgzip replaces |
| Report bytes after the end record as `ARCHIVE_TRAILING_DATA` | DR-3: the TAR, 7z, RAR and ISO rule. 7-Zip warns on any tail; zero padding stays silent here as there | Ignoring the tail, as Info-ZIP `unzip` and stdlib do |
| Refuse at open an end record declaring more entries than `max_members` | Every walk keeps an offset per entry for the overlap guard, so the count bounds memory in every mode (DR-15b); the directory must be 46 bytes per declared entry, so a wrong count field alone does not refuse a small archive | Charging only on `members()`, which left a streaming pass unbounded |
| A central entry whose fields run past the directory's end, hold the headers after it (they chain from a signature inside exactly to the end), or whose name is shorter than its local header's with no header after it, is damage (§2.2) | Cutting the field, as stdlib does, listed a member named after the swallowed entries' bytes and dropped those entries with only a count warning, where a pipe listed every member (DR-1, DR-5); `unzip` and 7-Zip both stop with an error. As damage, both reads list every member from the local headers and raise | Cutting at the directory's end (the native reader's first choice; superseded by davi's 2026-10-17 ruling, PR 860); treating a signature with a wrong count as damage, which refuses an intact directory over a name and a count field |
| Read members whatever "version needed" says | DR-4: the method and flags say what a member needs; 7-Zip reads such members | Stdlib's refusal of the whole archive above 6.3 |
| archivey's codec layer for member data | Stdlib decodes four methods; the codec layer decodes seven, and unifies CRC verification and error translation with the other backends | Staying on `ZipExtFile`, which left ZIP advertising codecs it could not decode |
| Read a non-seekable source forward over the local headers under `streaming=True`, and refuse it under `streaming=False`, rather than spool it | Silent buffering hides an unbounded memory or disk cost the caller did not ask for; the local headers make one forward pass possible (the maintainer, 2026-10-10) | Transparent `SpooledTemporaryFile`; still possible later as an explicit opt-in ([ADR 0010](../decisions/0010-no-silent-buffer-nonseekable.md)) |
| Apply the fields only the directory holds at the end of a forward pass (2026-10-02) | Matches the file read on disk without buffering anything (ADR 0010) | Treating every member as a regular file, as libarchive's streaming reader does (a symlink becomes a file: DR-1); spooling the archive to read the directory first |
| From a pipe, keep the files a directory-wide refusal finds after they were written (davi, 2026-10-14; the file read is to stop refusing these instead) | The pass learns of a mislabelled UTF-8 name only after every member is written; it raises the file read's error and leaves the files | Taking them back, as a member failure at the end of the pass does |
| Seeking and concurrent member streams off by default, on ZIP too | A rewind always re-decodes from the start of that member (or its nearest seek point), which is why both stay opt-in even here — not merely because TAR/7z can be worse. Concurrent opens also share one archive handle — `zip_reader.py` keeps a single `fp` behind its own re-entrant lock (a source whose read closes the archive re-enters it on the same thread), for a path source exactly as for a caller-supplied stream, so it is serialized seeks (multiplexing) either way rather than a second handle. ZIP's advantage is only the absence of cross-member decode dependency, plus a source that is always seekable for random access, because a pipe is read only by the forward pass, whose streams never seek. The strict default is reversible before 1.0; the permissive one is not | Enabling them where member access is `DIRECT` ([ADR 0003](../decisions/0003-member-streams-opt-in.md)) |
| Sniff unflagged names for UTF-8 validity; do not guess legacy codepages | Validation is near-conclusive; guessing has no oracle and a plausible wrong name is worse than a visible garble | An off-the-shelf charset detector, which can override a *valid* UTF-8 string with a legacy guess |
| Join `7z -v` byte slices; reject Info-ZIP spanned sets | The first are slices of one finished archive and rejoin exactly — archivey already rejoins the identical split for `.7z.NNN`, so refusing here answered the same input two ways. A linear join of the second lists correctly and then reads only the members that happen to sit on the last disk (§3) | Refusing both (the shape of the rule was the filename, not the structure); concatenating spanned segments and hoping |
| Extras named by capability, not by format | The codecs are shared, so `[7z]` told a ZIP reader to install support for a different format — the name lied, not the message | Per-format extras |
| Refuse PKWARE Strong Encryption at member open, not implement it | Without these checks, a member marked only by extra `0x0017` (no bit 6) was decrypted as ZipCrypto: a wrong-password or corruption error, or with the right password bytes handed back as plaintext. Checking bit 6 too gives a bit-6 member a message archivey owns (it used to reach stdlib's own `NotImplementedError`) and refuses a symlink's target before its data is read. Implementing it is out: patent-encumbered and rare outside PKZIP. No real archive of this kind is in the corpora, so the tests use re-flagged ZipCrypto members | Leaving the misleading error; implementing SES |
| Create-only writing, if and when writing lands | ZIP append is legal in the format and turns an interrupted write into a corrupt archive | In-place append (`history/ARCHITECTURE.md` §5.4) |
| Short ZipCrypto header is `TruncatedError` on both password paths; a declared size too small for the encryption header is `CorruptionError` for ZipCrypto and WinZip AES alike | A short read is physical EOF; callers matching `TruncatedError` vs `CorruptionError` would otherwise see a dispatch-dependent split. A declared size under 12 bytes (ZipCrypto) or under salt + verifier + HMAC (WinZip AES) is an impossible header in a file that did not end, so it is checked before the read and is damage, the same for both schemes; for WinZip AES it is also checked before the `cryptography` availability gate, so the type does not depend on the install (DR-5) | Mapping the confirm path's `BadZipFile` through the generic ZIP translator (`CorruptionError`); leaving the split |
| ZipCrypto decrypts in archivey, ahead of the codec layer, not in stdlib's `ZipExtFile` | One pipeline for every member: ZipCrypto members gain the three methods stdlib cannot decode, the fused verifier and the codec layer's seek, and share WinZip AES's password ladder. Stdlib's decrypter is pure Python too, so nothing is slower | Keeping `ZipExtFile` for ZipCrypto, which left it the one exception to the shared stream layer |
| Several WinZip AES candidates are confirmed like ZipCrypto ones | The first candidate to pass the 2-byte `pw_verify` used to win outright, so a colliding wrong password ahead of the right one failed the read on the HMAC. A confirm walk costs one extra read of a small or uncompressed member, only when there is more than one candidate | Accepting on `pw_verify` (2⁻¹⁶ per wrong candidate) |
| WinZip AES seeks by restarting CTR at the target's block, and keeps the HMAC | CTR decrypts from any offset (counter `1 + offset // 16`), so a seek costs one block. The HMAC covers the ciphertext, not the plaintext, so it survives seeks: the HMAC takes in ciphertext while reads continue its hashed prefix, and the read that returns the last byte reads the rest from the source, without decrypting, before it returns. That keeps the only check an AE-2 member has, and the candidate confirmation, under rapidgzip's own out-of-order reads too, so accelerators stay on | Refusing to seek, which broke the `seekable_members=True` guarantee; forfeiting the HMAC on a seek as a CRC is forfeited, which let an accelerator's seeks silently drop it; turning accelerators off over the AES stage |
| A WinZip AES member every candidate fails on the HMAC raises `CorruptionError`, as one password does | A wrong password passes `pw_verify` once in 65 536, so damage is far likelier, and one error type for both password paths means a symlink with a damaged target lists the same way under either (S28-K4, davi 2026-09-26) | ZipCrypto's ambiguous `EncryptionError`, which fits an 8-bit check but made the same damaged AES member raise two different types depending on how many passwords the caller passed |
| From a pipe, the first of several inconclusive password candidates wins (davi, 2026-10-14) | The walk to the end that tells them apart from a file needs the data twice. It only matters past the kept 1 MiB, for a STORED member or one under a codec that accepts random input, where a wrong candidate passed the cheap check (2⁻⁸ ZipCrypto, 2⁻¹⁶ AES). A wrong winner fails at its CRC or HMAC like one unconfirmed password. A choice that may change once spool limits are designed | Spooling the whole ciphertext, walking every survivor to its end and serving the winner from the spool; refusing several passwords from a pipe |
| A damaged symlink target leaves the link listed without a target | One member's damage says nothing about the others, and listing raised for the whole archive. The link is reported (`target_data_damaged`) and raises when opened or extracted; a strict policy still refuses the archive | Raising from `members()`, which took every other member with it |
| An undecodable symlink target leaves the link listed without a target | Same reasoning as damage (DR-2, and DR-5 for a missing library): an unknown method, bit 5, LZMA `lc + lp` over 4, method 99 without an AES record, or a missing optional library the data needs (a codec, or `cryptography` for AES) made `members()`, `stream_members()` and `extract_all()` fail for the whole archive. The link is reported (`target_data_unsupported` or `package_not_installed`) and raises that error when opened or extracted. A strict policy refuses the archive even when it is intact and only a library is missing, as it does for `password_required`. The handling is in the shared base hook, so 7z behaves the same | Raising from `members()`, which took every other member with it |
| WinZip AES HMAC from the completing read, not `close()` | ADR 0014: `close()` is teardown. STORED members used to drain the MAC on close and raise `CorruptionError` there; compressed members already skipped it because the decompressor borrows the decrypt stream (S1-F1). Removing the drain makes both match CRC members | Wiring compressed members to authenticate on close too (the S1-F1 "fix" that would add a behaviour the ADR already ruled out) |
| Owner ids read as unzip 6.00 reads the four fields | DR-6, the format's official tool. Measured with `unzip -X` 6.00 (the Ubuntu 24.04 package) as root on crafted local headers, 36 field orders, "none" meaning the file stayed owned by root: each `0x7875` or `0x7855` decides afresh (the last one wins, a damaged or unknown-version one leaves none, a `0x7855` after a `0x7875` is ignored, a PKWARE field before either is discarded); `0x000d` and `0x5855` count only with neither present, the last one with ids winning and a short one changing nothing; new Unix ids of 1 or 3 bytes leave the file root-owned. The madler/unzip source keeps PKWARE ids under a later short `0x7855` or `0x7875`; the released 6.00 does not, and 6.00 is what users run. The difference is one mask in `ef_scan_for_izux`: 6.00 (Debian's 6.0-28 source) has `flags &= 0x0ff`, which clears `EB_UX2_VALID` (`1 << 8`), where the mirror has `flags &= ~0x0ff`. For 3-byte ids 6.00 does not decline: `read_ux3_value` has no case for 3, returns true without writing, and unzip chowns to an uninitialised `z_uidgid`, which happened to read 0. Archivey reports `id_size` instead; do not "fix" it into a chown to 0. A damaged deciding field is reported as `MEMBER_HEADER_RECORD_SKIPPED`, the Unicode Path rule below; an unknown version is silent, as for that field | A fixed ranking where the highest field present decides (wrong for half the orders); falling through to the next readable field; dropping damage silently |
| Times from the PKWARE (`0x000d`) and Info-ZIP old (`0x5855`) Unix fields read as unzip 6.00 reads them: an Extended Timestamp with data anywhere wins, a `0x7855` or `0x7875` before the field hides it, the last field long enough for both times wins, and they sit above NTFS `0x000A` (2026-10-15) | DR-6, the format's official tool, and macOS `ditto` and Archive Utility write only `0x5855`, so without it a macOS archive lists naive local DOS times (Maccy.app.zip 8 hours off). Measured with `unzip -qo` 6.00 (Debian 6.0-28, the Ubuntu 24.04 package) on crafted local headers in eleven field orders, by the extracted file's `st_mtime` and `st_atime`. unzip on Unix does not read NTFS times at all, so a blob with both gives the Unix field's | A fixed ranking by tag, which gets the `0x7855`/`0x7875`-before case wrong; NTFS above the Unix fields, which no Unix tool does |
| Keep the central extra fields no value was taken from as `extra["zip.extra_fields"]`, `{tag: data}`, first copy per tag (davi, 2026-10-15, in the thread on common ZIP extras) | Archivey reads every field the surveyed archives carry, so most members keep nothing, and a caller with a vendor field still gets it. A field archivey knows but took nothing from stays in, so a caller sees what was ignored. A tag leaves the dict when a later version reads it; davi accepted that, to be weighed case by case and noted in the changelog. Reopen if callers need the local header's fields | The raw central blob for every member (+4-5% listing memory for fields archivey already reads); parsed `(tag, data)` pairs for every field (+12-23%); not exposing extras |
| A forward pass yields no owner; the directory's is applied when the member is placed, as the mode is | Extraction places a pipe ZIP's members only once the directory is read; an owner from the local header would be one the file read never applies, when the directory gives another owner or none (a `0x7855` the local header alone carries, or any field a writer leaves out of the directory). Waiting for the directory holds the file read's owner on disk under `TRUSTED` as root by construction, not by trusting which fields a writer copies | Yielding the local header's ids and replacing them at the end of the pass; reading only the tags a directory usually also carries (`0x7875`, `0x000d`), which rests on what writers do |
| A malformed Unicode Path field drops the field, not the archive, on every Python version | The RAR5 extra-record ruling ([`rar.md`](rar.md) §6): an optional record that cannot be parsed costs that record, reported as `MEMBER_HEADER_RECORD_SKIPPED`, and the name it would have given is absent, so the header's bytes name the member. Stdlib 3.12+ refused the archive over two of the shapes and warned outside the diagnostics system over the third, while 3.11 and 7-Zip open it; the native parser reads the field itself, so every version agrees | Keeping stdlib's refusal on 3.12+; silencing the warning with `warnings.catch_warnings`, which changes process-wide state and is not thread-safe; dropping the field silently |
| An unknown size past 4 GiB in a macOS ZIP is `None` with `extra["size_mod_2_32"]`, filled in after a verified full read (davi, 2026-10-15, project thread: option A; the extra's name is his proposal) | Nothing reported is wrong, and the unknowns are limited to deflated members over about 4.16 MB compressed in Mac archives; the fingerprint keeps other writers' sizes as stored. Smaller members, most of a typical archive, keep exact sizes | Decoding such members while listing (exact sizes, but listing an archive of videos reads all of it); listing the stored remainder with a diagnostic (a wrong number) |
| Size corrections report a new code, `MEMBER_SIZE_WRAPPED` with `SizeWrapContext` (davi, 2026-10-16, project thread decision card) | Sizes and offsets are different facts with different fields; one code per fact keeps each context simple to match on | Reusing `ARCHIVE_OFFSET_WRAPPED` with optional size fields on its context; no diagnostic, leaving `size=None` and the extra key as the only trace |
| No lower deflate bound: only the upper one, 1032 to 1, narrows the size (davi, 2026-10-16, project thread: a lower bound only settles members truly over 4 GiB, and those can as well be over 8 GiB) | Empty stored blocks pad a valid stream without bound, so any lower bound picks a size 4 GiB too large for a padded stream with a matching CRC-32 (seen in review). The upper bound is deflate's own and a read checks it | A lower bound of seven eighths of the compressed size, which holds for real encoders and kept more sizes exact, but reported a wrong size for valid data |
| `ARCHIVE_OFFSET_WRAPPED` is advisory, outside `ARCHIVE_INTEGRITY_CODES` (davi, 2026-10-15, project thread) | macOS Archive Utility writes a ZIP past 4 GiB this way by default and reads it back, so `STRICT` would refuse an ordinary Mac archive; a correction is kept only when a local header with the member's name is there, and the CRC-32 is still checked, the `MEMBER_SPECIAL_FILE_HAS_DATA` pattern (DR-25). Reopen if a writer other than macOS is found producing wrapped offsets that a correction misreads | The integrity set, under DR-3 (the stored offsets misdescribe where good data sits) |
| Read a member whose central and local headers disagree on the name, or whose central CRC is 0 while the local CRC is right; keep refusing one whose two headers both understate the size (davi, 2026-10-10) | The first two are found in real archives (another code page or `\` against `/` in the local name; every Adobe AIR package), `unzip` reads both, and archivey takes every field from the central directory, so the local name decides nothing; the data is still checked against the local CRC. The third is refused because the declared size is the bound that stops decoding (DR-9a). The name case reports `MEMBER_LOCAL_NAME_DIFFERS`, which strict refuses because another tool shows another name; the CRC case reports `MEMBER_LOCAL_CRC_USED`, which strict reads because the data is still checked (davi, 2026-10-15). Both carry `LocalHeaderContext`. Reopen if a real writer produces the third shape at scale. Shipped with stage 5 of the native ZIP reader | Refusing all three, which loses archives `unzip` reads; reading the third, which drops the size bound |
| Decode a member whose local header names another compression method than its directory entry by the local method, and report `MEMBER_LOCAL_METHOD_DIFFERS` (in `ARCHIVE_INTEGRITY_CODES`, so `STRICT` refuses it), from a file and a pipe (davi, 2026-10-21) | The local header sits next to the data, and a pipe has only it, so a file and a pipe read the same bytes; the CRC-32 still checks them. A tool that trusts the other header decodes other bytes or fails, so `STRICT` refuses it, as for the name. Measured on a one-member ZIP whose local method was set to stored over a deflated body: `unzip` 6.00 takes the local method and fails (exit 2), 7-Zip reports "Headers Error" and "CRC Failed", and stdlib `zipfile` reads it by the central method. No real archive in the backup-drive scan has the shape. WinZip AES (method 99) on one side only is refused: the AES record is read from the central extra field, so the headers disagree on the encryption; so is method 99 in both headers when the two AES records differ in any field (version, strength, real method) or one is missing or unparseable. A file read reports once the local header passes its checks, before it decodes, so a member whose data then fails on a CRC or size the directory contradicts reports from a file and a pipe; one the overlap guard refuses reports only from a pipe (§"Where the pass and a file read differ"). The listing keeps the directory's method in `compression` and `extra["zip.compress_type"]`, as every listed field comes from the directory (a CRC-32 of 0 aside, §5), and the diagnostic carries both methods | Refusing it with `CorruptionError`, as `unzip` and 7-Zip fail it (the first draft); decoding by the central method, which a pipe cannot do, so the two reads would deliver different bytes; reading it silently, as before |
| Two stored names that decode to the same name stay ordinary duplicates (davi, 2026-10-10) | Once each name decodes on its own, `c3 a9` (valid UTF-8) and `82` (cp437) can both become `é.txt`. The later member supersedes the earlier like any duplicate (`is_current=False`, `SUPERSEDED` on extraction) and the two `raw_name`s differ, so nothing is lost and no new public name is needed. Reopen if a real archive shows a collision a user needs both copies of | A dedicated diagnostic or a renaming rule |
| AppleDouble sidecars (`._name`, `__MACOSX/`) stay ordinary members with no marking key (davi, 2026-10-16, project thread) | Marked by name alone, a key adds nothing over the name filter in `docs/formats.md` and also marks a real file named `._x` | `extra["macos.resource_of"]` set from the name (#839, closed). Reopen with a mark that checks the AppleDouble magic in the data (`IDEAS.md`) |
| Leave LZMA1 `lc + lp` over 4 unsupported | 7-Zip writes it only when asked (`lc=8`). Decoding it needs an LZMA1 decoder other than liblzma | `pylzma` 0.6.1, which binds 7-Zip's own LZMA SDK and does decode these (an `lc=8` ZIP member read back byte-identical, one-shot and through `decompressobj`), but ships only an sdist (a C compiler for every install) under the LGPL, the reasons it was rejected for BCJ2 too; a pure-Python LZMA1 decoder (very slow); handing such members to the `7z` CLI (archivey has no 7z CLI backend). `backports.lzma` and libarchive both use liblzma |

## 7. Open questions

Gaps in what *we* know, not in what the format says — each would change something here if
answered, and none can be settled by reading more code. Distinct from §5, which is
behaviour a caller already sees.

None open. The heading stays so the section numbers after it, which briefs cite, do not
move.

## 8. Verify

```bash
./scripts/test.sh tests/test_zip.py tests/test_zip_aes.py \
    tests/test_zip_native_codecs.py tests/test_zip_multipassword.py \
    tests/test_volumes.py tests/test_volume_missing_part.py \
    tests/test_zip_extra_fields.py
```

| Claim |
| --- |
| Cost receipt, central-directory lookup without I/O |
| Non-seekable refused at open under `streaming=False`, naming `streaming=True`; read under `streaming=True` |
| From a pipe: the walk and where each member's data ends |
| From a pipe: members updated from the directory, `is_current` by directory order, unlisted local entries dropped, failures at the end of the pass, limits |
| A bit-3 codec stream that runs on into its descriptor: `TruncatedError` from a file, read from a pipe (§2.2.2) |
| From a pipe: encrypted members, one password, several, a provider |
| From a pipe: extraction settled at the end of the pass, selection made again, failures at the end |
| Every fixture read from a pipe and from a file gives the same members, data and files, except the recorded differences |
| Spanned set and unjoinable segment refused |
| A numbered part that is not on disk is `FileNotFoundError`, not an incomplete set |
| Split checks do not fire on single-volume archives |
| `7z -v` set joined, read across a part boundary, opened from any part |
| Numbered-part discovery, ordering and gap rejection, `.zNN` left alone |
| Joiner caches a few Path handles, cursor on sequential read |
| Timestamp precedence; an out-of-range NTFS time is an issue; the extended timestamp, a signed 32-bit field, is always a valid date (pre-1970 included) |
| A bad timestamp's diagnostic names the member field, the creation slot by host |
| Times from the PKWARE and Info-ZIP old Unix fields in each field order, from a file and a pipe, and against `unzip` where it is installed |
| `extra["zip.extra_fields"]`: unknown and unused known fields kept, first copy per tag, a field whose times were all replaced kept, absent when every field was read, set by a pipe pass at the directory, and charged per field against `max_metadata_bytes` |
| Encoding sniff, fallback, override, escalation |
| Owner ids from each of the four fields, their ranking, the central directory's short copies, and a damaged deciding field dropped with `MEMBER_HEADER_RECORD_SKIPPED` (strict refuses); a pass yields no owner and leaves the same owner on disk as a file read |
| Unicode Path field names the member over the sniff and `encoding=`; a stale, unknown-version or local-only field is ignored |
| Unicode Comment field (`0x6375`) gives an unflagged member comment over the sniff and `encoding=`; a stale or unknown-version field is ignored; a malformed one is dropped with `MEMBER_HEADER_RECORD_SKIPPED`; a trusted flag's comment does not consult it |
| A short, empty, cut-short or non-UTF-8 Unicode Path field is dropped with `MEMBER_HEADER_RECORD_SKIPPED` on every Python version, with no stdlib warning; strict refuses; a flagged name's field is not consulted |
| Backslash by origin |
| Symlink target from member data; encrypted target withheld |
| Windows reparse points: a file symlink's buffer decoded, a directory one's absent data, a stored junction buffer setting the flag |
| Duplicate names read independently |
| Overlapping-entry bomb; entries sharing a local header read once; a refused entry reports no name difference |
| A damaged directory lists up to the damage, then the local headers past it; version needed above 6.3 reads; trailing bytes reported; one walk for listing then opening, one index pass when `member_count` comes first, a seekable streaming pass reads the directory then forward only; a listed member keeps no extra field |
| `max_members` refused at open from the declared count, charged by the walk when the count lies |
| The parser against stdlib on every fixture, ZIP64, stubs, disk fields |
| A member's input ends with its stream: LZMA without an end marker and PPMd with junk or a declared size short of their data, DEFLATE and bzip2 with junk or a second stream, accelerators off and on, are `CorruptionError`; one zero byte after marker-less LZMA reads; a Zstd member reads every frame |
| AE-1/AE-2, wrong password, tampered ciphertext |
| Bytes after the codec's end inside a member (zero, zeros, junk) raise for DEFLATE, Deflate64, BZip2, PPMd (in process and in a child) and Zstd, also under the accelerators (for DEFLATE on a seek to the end too); `7z t` fails on the same members |
| A Zstd member's second frame reads as content and a skippable frame as nothing, and a seekable-format table gives its seek points; the shared framed decoder refuses a second stream where the codec is one stream |
| Bytes after the stream inside a ZipCrypto member (the `EncryptionError` of an unconfirmed password, caused by the `CorruptionError`) or a WinZip AES member raise |
| A PPMd member with no end mark is `CorruptionError`, in process and in a child; an end mark already decoded at the size is checked; a worker the end-mark probe parks is quiesced on close |
| A second bzip2 stream in a member is `DataAfterEndError`, whatever the size and CRC cover, where `zipfile` ends the member at the first |
| Tampered HMAC raises on a full read (STORED and DEFLATE); partial read then `close()` is quiet |
| AES decrypt stream `close()` still releases the source after a partial read; a source `OSError` still marks the wrapper closed |
| Our AE-1 fixtures cross-checked against an independent implementation |
| A third-party AE-1 archive reads, with the CRC exposed and verified |
| ZipCrypto candidate confirmation, STORED CRC pass; ZipCrypto over Zstd; ZipCrypto seeks; stage output equals stdlib's |
| The STORED CRC pass reads through the same validated local header as the open, so it never runs over a member the open refuses |
| From a pipe, short members' data and kept ciphertext are not charged to `max_metadata_bytes`; the longest is dropped first past it, and a dropped link lists targetless with `target_data_dropped` and leaves no file from `extract_all`, and a reparse point whose dropped data is no buffer is re-typed as from a file; the archive comment is weighed at the end record |
| A local name that differs from the directory's, and a central CRC-32 of 0 under a right local one, read from a file and a pipe, strict refusing the name case only; a wrong local CRC-32 and 0 in both still fail; both headers understating the size stays refused |
| WinZip AES seeks at every block phase and backward; the HMAC survives seeks, including over bytes a seek skipped and on a `read(n)` ending exactly at the end; a partial read after a seek has no verdict |
| A tampered AE-2 DEFLATE member still raises under rapidgzip's own seeks (`AUTO` and `ON`, one password and two) |
| A lone ZipCrypto password that passed the check byte: a partial read is reported unverified, a read to EOF and extraction are not; a forward seek on a compressed member raises the password-or-damage error, and a seek on a STORED one is reported as `seek` |
| A seek then a full read of a weakly accepted AES member is not reported unverified; a seek then a partial read is, as `partial_read` |
| A method-99 member with bit 0 clear lists as encrypted and asks for a password |
| WinZip AES candidates confirmed, not taken on `pw_verify` |
| A failing HMAC is `CorruptionError` with a candidate list too, including when only colliding wrong candidates reach it |
| A damaged symlink target (CRC, HMAC, declared size) lists the link targetless with `target_data_damaged`; open and extraction raise; strict refuses |
| An undecodable symlink target (unknown method, bit 5, missing codec or `cryptography`) lists the link targetless with `target_data_unsupported` or `package_not_installed`; open and extraction raise that error |
| PKWARE Strong Encryption refused at open, a symlink of it listed with the target unset; unrelated extra records still read; an encrypted central directory recognized where the directory starts, a damaged one (and a record at a stale declared offset) still `CorruptionError` |
| Truncated ZipCrypto header is `TruncatedError` on both password dispatch paths; a declared size too small for the ZipCrypto or WinZip AES header is `CorruptionError` naming the member; codec-path and member-read `IndexError` stay raw; CONCURRENT stamp releases the handle lock |
| Cross-format member equivalence, per-method decode, AE-2 CRC absence |

**Building fixtures.** Stdlib `zipfile` cannot write encryption, so encrypted fixtures shell
out to `7z` (`-mem=AES256` for WinZip AES, ZipCrypto by default) and skip when it is absent —
one of the ~109 tests that vanish quietly on an unprovisioned container. Nothing on the
image writes **AE-1**, so those fixtures are hand-built by `tests/zip_aes_fixture.py`; what
keeps that builder honest is `7z` accepting its output while rejecting the same bytes with
a corrupted CRC, plus one committed third-party sample
([`tests/fixtures/external/README.md`](../../tests/fixtures/external/README.md)). `-mm=Deflate64`,
`-mm=PPMd`, `-mm=BZip2` and `-mm=LZMA` produce the extended methods. The backslash fixtures
are committed rather than generated because `zipfile` rewrites `ZipInfo.filename` on Windows;
the reader uses `orig_filename` for the same reason.

The joined-set fixtures shell out to `7z a -tzip -mx0 -v40k` — a real split from the tool
whose behaviour is being matched, and cheap because `-mx0` stores. The Info-ZIP shapes are
**synthesised instead**: `zip` is not installed on CI, macOS or Windows, so a `zip -s`
fixture would skip on every machine that matters and prove nothing about the refuse path.

## 9. References

- [APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT): §4.3.6 overall format · §4.3.9 data descriptor · §4.3.16 EOCD · §4.4.4
  general-purpose flags (bits 0, 3, 6, 11 and 13) · §4.4.6 MS-DOS date/time · §4.4.15
  external file attributes · §4.5.5 extended timestamp · §4.5.12 strong encryption header
  (`0x0017`) · §4.3.11 archive extra data record · §6 traditional encryption · §7 strong
  encryption · §8 splitting and spanning · Appendix D CP437
- Specs: [`format-zip`](../../openspec/specs/format-zip/spec.md) ·
  [`compressed-streams`](../../openspec/specs/compressed-streams/spec.md) ·
  [`format-detection`](../../openspec/specs/format-detection/spec.md)
- Code: `internal/backends/zip_reader.py` · `internal/backends/zip_forward_reader.py` and
  `internal/backends/zip_local_walk.py` (the forward pass) · `internal/backends/zip_detect.py` ·
  `internal/backends/zipcrypto.py` · `internal/backends/zip_aes.py` · `internal/volumes.py` (numbered-part
  discovery and joining, shared with 7z)
- Investigations: [`archive-format-detection-algorithm.md`](../investigations/archive-format-detection-algorithm.md)
  (tail-tier design, corpus counts) ·
  [`rar-corpus-sweep-diagnosis.md`](../investigations/rar-corpus-sweep-diagnosis.md)
  (per-format symlink digest and size comparison)
- User-facing: [`docs/formats.md`](../../docs/formats.md#zip) ·
  [`docs/formats.md`](../../docs/formats.md)
