# ZIP Format Behavior

## Purpose

ZIP archives are read through the unified `ArchiveReader` API using archivey's
own parser for the end record, central directory and local headers
(`internal/backends/zip_parser.py`) and archivey's shared codec layer for
member data. ZIP listing is indexed, member access is direct, and a seekable
source is read through its central directory. A non-seekable source is read under
`streaming=True` in one forward pass over the local headers. Read-only: writing is
not shipped for any format.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API, password candidates, weak-check confirmation, bounded storage |
| `access-mode-and-cost` | Random-access vs streaming rules; non-seekable random-access failure; the forward pass's cost receipt |
| `diagnostics` | Timestamp and symlink-target diagnostic values / policy |
| `backend-registry` | `format_availability(ZIP)` FULL/PARTIAL from optional member codecs |
| `compressed-streams` | ZIP member-data decode path (method id → `StreamCodec`) |

## Requirements

### Requirement: Report ZIP format properties

The ZIP backend SHALL expose these properties for every opened ZIP archive:

| Property | Value |
| --- | --- |
| Backend dependency | None: archivey's parser for the structure (no `zipfile` import); shared codec layer for member data |
| Listing cost | `ListingCost.INDEXED` — end record read at open, central directory walked as members are listed; the local header of a file or link (not WinZip AE-2) whose central CRC-32 is 0 over data is read too (the requirement on headers that disagree) |
| Access cost | `AccessCost.DIRECT` — independent local file offsets |
| Stream capability | `StreamCapability.SEEKABLE`; `FORWARD_ONLY` for a non-seekable source |
| Read source | Seekable in both access modes; non-seekable under `streaming=True` only; no implicit buffering/spooling |
| Write support | No — writing is not shipped for any format (`dev-docs/investigations/archive-writing-design.md`) |

`reader.get()` and other name lookups SHALL use the central-directory-derived
member map without extra archive I/O. Unencrypted ZIP member data SHALL decode
through the shared `compressed-streams` codec layer (bounded local-header parse
+ slice + method-id dispatch), including XZ (method 95, `.xz` data, decoded in core
with stdlib `lzma`), and extended codecs when their backends are
installed: Deflate64 (method 9, via `[recommended]`/`inflate64`), ZSTD (method 93), PPMD
(method 98, ZIP PPMd8 framing via `[recommended]`/`pyppmd`). A missing optional backend
SHALL raise `PackageNotInstalledError`. An unknown/unsupported method id SHALL
raise `UnsupportedFeatureError`. `format_availability(ZIP)` SHALL report FULL
when every optional ZIP member codec is installed, else PARTIAL with the missing
components listed. Encrypted members (ZipCrypto / WinZip AE) SHALL decode the same
methods through the same codec layer, after a decrypt stage.

#### Scenario: ZIP property matrix

| Case | Expected |
| --- | --- |
| Open valid ZIP | `cost.listing_cost=INDEXED`, `cost.access_cost=DIRECT`, `cost.stream_capability=SEEKABLE` |
| `reader.get("some/member.txt")` | Satisfied from the in-memory central-directory name map; no additional archive I/O |
| Member uses unknown method id | Listing succeeds; reading raises `UnsupportedFeatureError` |
| Deflate64/Zstd/PPMd member, backend present | Decodes via the shared codec layer |
| Deflate64/Zstd/PPMd member, backend absent | `PackageNotInstalledError` |
| Optional ZIP codecs all installed | `format_availability(ZIP)` is FULL |

### Requirement: Decode ZIP member bodies through the shared codec layer

The ZIP backend SHALL decode unencrypted member data through the shared
`compressed-streams` codec layer rather than stdlib `zipfile`'s internal
decoders. It SHALL locate a member's raw compressed bytes via a bounded
local-file-header parse (fixed header + local name/extra lengths, with an
absurd data-offset cap) and a slice over the source, then dispatch by ZIP
method id to the codec's default backend.

Member reads SHALL verify `member.hashes["crc32"]` through the shared
`VerifyingStream` when a CRC is surfaced. A corrupt member body SHALL raise
`CorruptionError` (or `TruncatedError` when the payload is cut short) via the
shared translation. Traditional ZipCrypto and WinZip AES (method 99) members
SHALL decrypt natively (see below) and then feed the codec layer. A ZipCrypto
member SHALL seek under `seekable_members=True`: a backward seek restarts
decryption from the member's start, a forward seek decrypts what it skips, and
`AUTO` accelerators stay off over the decrypt stage. A WinZip AES member SHALL
seek too: CTR restarts at the target's block (counter `1 + offset // 16`). A
seek SHALL NOT give up the HMAC, whether the caller or an accelerator made it:
the HMAC covers the ciphertext, so the read that returns the member's last byte
SHALL complete it by reading, without decrypting, the ciphertext the seeks
skipped, and raise `CorruptionError` on a mismatch. A read that stops short of
the end gives no verdict.

Codec settings 7-Zip writes or names but this reader cannot decode SHALL raise
`UnsupportedFeatureError`, not `CorruptionError`. An LZMA (method 14) member whose
properties byte is a valid `lc`/`lp`/`pb` triple with `lc + lp` over 4 (`7z a -tzip
-mm=LZMA:lc=8`; liblzma decodes up to 4) is one, decided by the same check as a 7z LZMA
coder; a properties byte of 225 or more stays `CorruptionError`. A PPMd (method 98)
member with restore method 2 is another (7-Zip: "Unsupported Method"); a restore method
above 2 SHALL raise `CorruptionError` (7-Zip: "Data Error"). Under ZipCrypto these
settings are decrypted data, so both SHALL raise `CorruptionError` there, which the
password confirmation counts as the candidate failing (see below).

A member's compressed data SHALL be one stream of its codec and nothing else, as 7-Zip
23.01 reads it (DR-3). A byte of it the codec leaves after the stream's end, a zero byte
too, and a further stream there, SHALL raise `CorruptionError` (`DataAfterEndError`)
once the output before it is read, whatever the declared size and CRC cover, for every
method and for encrypted members too, with an accelerator on or off, except as
`compressed-streams` allows for rapidgzip on a DEFLATE member (a second stream that
holds the last point of rapidgzip's index, with a size and CRC that cover both, reads as
both); under ZipCrypto the password confirmation counts it as the candidate failing, as
above. The exception is a Zstd member: RFC 8878 defines Zstd data as one or more frames,
so every frame, skippable ones too, SHALL be read as a `.zst` file's are
(`compressed-streams`), and only bytes after the last frame that start no frame SHALL
raise. An LZMA member without the end-marker flag (general-purpose bit 1) and a PPMd
member end at their declared size: their input SHALL end there too (after an end marker
right at that size for LZMA, and after PPMd8's end mark, which a member SHALL carry), so
a declared size short of the stream's data SHALL raise `CorruptionError`, not
`TruncatedError`. One zero byte after LZMA data without an end marker reads, as 7-Zip's
encoder sometimes flushes it past the decoder's last read.

#### Scenario: ZIP codec-layer decoding

| Case | Expected |
| --- | --- |
| STORED / DEFLATE / BZIP2 / LZMA member, unencrypted | Decodes via the shared codec layer; CRC verified through `VerifyingStream` |
| LZMA member with compressed data after its end marker (a second stream, or one zero byte), whatever the declared size covers | `CorruptionError`, as 7-Zip reports "Data Error" |
| LZMA member without an end marker (bit 1 clear), with junk after its data or a declared size 1000 bytes short of it | `CorruptionError`, not `TruncatedError` (7-Zip: "Data Error") |
| PPMd member with junk or zero bytes after its end mark, a declared size 1000 bytes short of its data, or no end mark | `CorruptionError`, not `TruncatedError` (7-Zip: "Data Error") |
| DEFLATE, Deflate64, BZIP2 or Zstd member with junk or zero bytes after its stream (after its last frame for Zstd), or a DEFLATE, Deflate64 or BZIP2 member with a second stream, accelerator off or on | `CorruptionError` (7-Zip: "There are some data after the end of the payload data") |
| DEFLATE member with a second stream that holds the last rapidgzip index point, declared size and CRC covering both, `use_rapidgzip=ON` | Decodes both streams; with the accelerator off, `CorruptionError` |
| Zstd member with a second frame or a skippable frame after its first, declared size and CRC covering all of it | Decodes every frame, as a `.zst` file does; a declared size or CRC that stops at the first frame raises `CorruptionError` |
| DEFLATE64 (method 9) member, `inflate64` backend present | Decodes; absent backend → `PackageNotInstalledError` |
| ZSTD (method 93) / PPMD (method 98) member, backend present | Decodes; absent backend → `PackageNotInstalledError` |
| XZ (method 95) member, as 7-Zip writes it with `-mm=XZ` | Decodes in core; lists `CompressionAlgorithm.XZ` |
| XZ member with a second xz stream, or stream padding (groups of four zero bytes) between or after its streams, declared size and CRC covering all of it | Decodes every stream, as an `.xz` file does (7-Zip reads it too) |
| XZ member with junk, or zero bytes that do not fill a group of four, after its last stream | `CorruptionError` (7-Zip: "Data Error", or "There are some data after the end of the payload data") |
| Unsupported/unknown method id | `UnsupportedFeatureError`; no guessed output |
| Corrupt member body | `CorruptionError` / `TruncatedError` |
| LZMA member, `lc + lp` over 4 (`-mm=LZMA:lc=8`) | `UnsupportedFeatureError` naming `lc` and `lp` |
| PPMd member, restore method 2 / 3–15 | `UnsupportedFeatureError` / `CorruptionError` |
| Encrypted ZipCrypto member, any of the methods above | Decrypts natively, decodes via the codec layer; CRC verified through the fused verifier |
| ZipCrypto or WinZip AES member, `seekable_members=True` | Seeks backward and forward; content matches a sequential read |

### Requirement: Read WinZip AES-encrypted members

The ZIP backend SHALL read WinZip AES (AE-x) encrypted members: compression
method 99 with the AES extra field `0x9901` giving vendor version (AE-1/AE-2),
key strength (128/192/256), and the actual underlying compression method.
Decryption SHALL derive keys via PBKDF2-HMAC-SHA1 (1000 iterations) over the
password and per-member salt (strength/16 bytes) into encryption key ‖
authentication key ‖ 2-byte verification value, decrypt with AES-CTR
(little-endian counter), and authenticate the ciphertext with HMAC-SHA1
truncated to 10 bytes. Decrypted bytes SHALL be decompressed through the shared
codec layer for the actual method.

A wrong password SHALL fail fast on the 2-byte verification value with
`EncryptionError` (no bytes returned). A ciphertext HMAC mismatch SHALL raise
at the terminal read (`CorruptionError`), whether one password or several were
tried: a wrong password passes the verification value once in 65 536, so a member
that every candidate passing it fails is reported as damaged, with the type the
damage has on the one-password path (`TruncatedError` for data that ends before its
declared size, `CorruptionError` otherwise). AE-2 members SHALL surface no
`crc32` (the ZIP CRC is 0; integrity is the HMAC) and run no CRC check; AE-1
members SHALL surface and verify `crc32` in addition to the HMAC. AES
decryption requires `cryptography` (`[recommended]`); when it is absent an AE member SHALL raise
`PackageNotInstalledError` (detection still identifies the member as
AES-encrypted), except that a member no library can read, one whose declared size cannot
hold salt, verification value and HMAC, SHALL raise `CorruptionError` with or without
`cryptography`. With several possible passwords, WinZip AES candidates SHALL be
confirmed as "Confirm multi-candidate ZipCrypto passwords" describes, not accepted on
the verification value alone.

#### Scenario: WinZip AES matrix

| Case | Expected |
| --- | --- |
| AE-1 or AE-2 member, 128/192/256, correct password, `cryptography` present | Decrypts, decompresses via codec layer, HMAC verified at EOF |
| Wrong password | `EncryptionError` on the 2-byte verification value; no bytes |
| Tampered ciphertext, correct password | HMAC mismatch → `CorruptionError` at terminal read |
| Tampered ciphertext, several candidates including the correct one | `CorruptionError` naming the member as most likely damaged |
| Declared size past the stored data, one password or several | `TruncatedError` |
| Declared size too small for the encryption header | `CorruptionError` naming the member |
| Tampered ciphertext, partial read then `close()` | Quiet; `close()` is teardown, not a verdict (ADR 0014) |
| AE-2 member | `crc32` absent; no CRC check; HMAC is the integrity signal |
| AE-1 member | `crc32` present and verified alongside the HMAC |
| AES member without `cryptography` installed | `PackageNotInstalledError`; still reported as encrypted |
| Same, declared size too small for the encryption header | `CorruptionError` |
| Several candidates, a wrong one passing the verification value first | Wrong candidate rejected by the confirm; the right one reads |

### Requirement: Refuse PKWARE Strong Encryption

The ZIP backend SHALL NOT decrypt PKWARE Strong Encryption (APPNOTE §7). An
encrypted member (general-purpose bit 0) that also sets bit 6 or carries an extra
field `0x0017` SHALL list with `is_encrypted=True`, and opening it SHALL raise
`UnsupportedFeatureError` naming Strong Encryption, whatever passwords were given.
Listing a symlink of this kind SHALL leave `link_target` unset and emit
`SYMLINK_TARGET_UNAVAILABLE` with reason `"target_data_encrypted"`. When an archive
extra data record (`PK\x06\x08`) sits where the central directory starts (the position
of the end record that follows the directory, minus the directory size that record
gives; for a ZIP64 archive both come from the ZIP64 end record), opening the archive
SHALL raise `UnsupportedFeatureError` naming Strong Encryption rather than
`CorruptionError`.

#### Scenario: Damaged central directory without the record

- **WHEN** the central directory cannot be read and no archive extra data record sits
  where it starts
- **THEN** listing raises `CorruptionError`, not `UnsupportedFeatureError`, after the
  entries before the damage and the members the local headers hold past it

### Requirement: Read a non-seekable ZIP source in one forward pass

A ZIP read from a non-seekable source SHALL be read under `streaming=True` in one
forward pass over the local headers, with the central directory read after the last
member. Under `streaming=False` it SHALL raise `StreamNotSeekableError` at open, naming
`streaming=True`. The library MUST NOT buffer, spool, or copy the source into seekable
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
| Non-seekable ZIP with default `streaming=False` | `StreamNotSeekableError` at open, naming `streaming=True`; no reader |
| Non-seekable ZIP with `streaming=True` | Opens; `stream_members()` and `extract_all()` read every member in one pass; after the pass the members equal the file read's |
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

### Requirement: Map ZIP member metadata to ArchiveMember

The ZIP backend SHALL map each `ZipInfo` to `ArchiveMember` with these field
rules:

| Field | Mapping |
| --- | --- |
| `mode` | The permission bits of `external_attr >> 16`, only for Unix entries whose high word is non-zero; otherwise `None` (a Unix entry with DOS attribute bits only has no mode, as unzip 6.00 reads it) |
| timestamps | DOS `date_time` base (naive local wall-clock, 2s granularity, 1980 sentinel → `None`); NTFS extra `0x000A` UTC FILETIMEs override present fields; the access and modification times of a PKWARE Unix `0x000d` or Info-ZIP old Unix `0x5855` field override those, unless the blob holds an Extended Timestamp with data or the field follows a `0x7855` or `0x7875` (as unzip 6.00 reads them), the last such field winning; Extended Timestamp `0x5455` UTC Unix times override present fields |
| `type` | Infer from Unix mode when available (a device, FIFO or socket mode is `OTHER` when the entry stores no data, `FILE` with `MEMBER_SPECIAL_FILE_HAS_DATA` when it does, `extra["special_file_type"]` whatever the type, a directory-marked or reparse-flagged entry over such a mode included); otherwise directory marker and symlink hints. The directory marker is a trailing `/` on the decoded name that `name` comes from, or a trailing `\` when the entry is DOS/Windows-origin, so the type is the same on every host OS and Python version. A directory marker with `file_size > 0`, or with `file_size == 0` and a body larger than an empty one of its method (0 stored, 2 deflated, 14 bzip2, 19 LZMA; any body for another method), stays `DIRECTORY` and emits `MEMBER_DIRECTORY_DATA_IGNORED` with both sizes; one declaring data carries its stored CRC-32 in `hashes` (the central directory's, or the local header's on a listing from local headers) and `open()` on it, or the stream `stream_members()` yields for it (from a pipe too, unless the entry is bit 3: see "Two shapes read differently from a pipe"), decodes and verifies the data like a file's, unless the CRC field is 0, in which case it carries no digest: where that CRC was the entry's only check (unencrypted, ZipCrypto) `DIGEST_UNVERIFIABLE` (`reason="no_integrity_anchor"`) is reported and the bytes are delivered unchecked, while a WinZip AES entry (AE-1 with a zeroed field, or AE-2, which stores 0 by design) is verified by its HMAC, with no digest and no report |
| `uid`, `gid` | From the owner extra fields in blob order, as unzip 6.00 reads them: each `0x7875` (Info-ZIP new Unix, version 1, ids of 2, 4 or 8 bytes) or `0x7855` (Info-ZIP Unix type 2, exactly 4 bytes) decides afresh, readable or not, a `0x7855` after a `0x7875` being ignored; `0x000d` (PKWARE Unix) and `0x5855` (Info-ZIP old Unix) count only when neither came before, the last one holding ids winning. An empty `0x7855` or an 8-byte `0x000d` or `0x5855` holds no ids and is not damage. `stream_members()` yields `None` for both until the directory is read |
| `uname`, `gname` | Always `None`: no ZIP extra field records them |
| `compression` | `compress_type` mapped to `CompressionMethod` |
| `is_encrypted` | `flag_bits & 0x1 != 0`, or `compress_type == 99` (WinZip AES) whatever bit 0 says |
| `extra["zip.extra_fields"]` | The central directory extra fields no value was taken from, as `{tag: data}`, the first of several with one tag; a tag any copy of which gave a value, and the ZIP64, WinZip AES and Strong Encryption fields, are left out. Absent when nothing is left |

Invalid DOS or NTFS timestamp values SHALL fall through to the next valid
precedence layer or `None` and emit `MEMBER_TIMESTAMP_INVALID`, whose `field`
SHALL name the member attribute: `modified` for the DOS stamp and the NTFS
modification time, `accessed` for the NTFS access time, and `created` or `ctime`
for the NTFS creation time, by the same host rule that fills those fields. With
`read_link_targets=True` (the default), if listing cannot read an encrypted
symlink target because no correct password is available, `link_target` SHALL
remain unset and `SYMLINK_TARGET_UNAVAILABLE` SHALL be emitted with reason
`"password_required"`. When a ZipCrypto target's data fails its integrity check
under a password only the verification byte vouched for (the ambiguous
`EncryptionError` of "Confirm multi-candidate ZipCrypto passwords"), the reason
SHALL be `"password_or_damage"` and the message SHALL name both causes. With
`read_link_targets=False`, listing reads no symlink target and emits nothing for it
(`archive-reading`, "Link targets stored as member data are read only when
configured"). Diagnostic payloads SHALL not include passwords, candidates,
provider returns, key material, or decrypted target bytes. Under `RAISE`, listing
halts with `DiagnosticRaisedError`.

#### Scenario: ZIP metadata matrix

| Case | Expected |
| --- | --- |
| Unix entry with non-zero `external_attr >> 16` | `member.mode` is its permission bits (`0o644 << 16` gives `0o644`) |
| Unix entry whose `external_attr` holds only DOS bits (`0x20`) | `member.mode is None`, never `0` |
| Non-Unix entry or missing attrs | `member.mode is None` |
| Only an Info-ZIP old Unix `0x5855` field (macOS `ditto`) | `modified` and `accessed` are timezone-aware UTC from it |
| A vendor extra field archivey does not read | `extra["zip.extra_fields"]` maps its tag to its data |
| Extended Timestamp carries modification time | `member.modified` is timezone-aware UTC from `0x5455`, overriding DOS / NTFS |
| NTFS FILETIMEs present, no Extended Timestamp, DOS-attribute host | Present `modified` / `accessed` / `created` fields are timezone-aware UTC from `0x000A` |
| Creation time stored (NTFS or Extended Timestamp third time), FAT / OS2 / NTFS / VFAT host | `created` holds it (the Extended Timestamp wins); `ctime is None` |
| Creation time stored, Unix or any other host | `created is None`; `ctime` holds it (7-Zip and libarchive on Linux and macOS store `st_ctime`) |
| Written by Info-ZIP `zip` on Unix (extra field `0x7875`) | `uid` and `gid` are the file's owner ids; `uname` and `gname` are `None` |
| Owner field in the local header only, read from a pipe | The pass yields `uid` and `gid` `None`, as a file read lists them, and `TRUSTED` as root leaves the same owner on disk from both |
| `0x000d` with ids, then a `0x7855` of 2 bytes | `uid` and `gid` `None`, `MEMBER_HEADER_RECORD_SKIPPED` for the `0x7855`, as unzip 6.00 gives no owner |
| Deciding owner field cut short, too short for its ids, a `0x7855` neither empty nor exactly 4 bytes, or a `0x7875` with an id size other than 2, 4 or 8 bytes | `uid` and `gid` `None`; `MEMBER_HEADER_RECORD_SKIPPED` with `record="unix_owner"` and `record_id` the tag |
| `flag_bits & 0x1`, or method 99 with bit 0 clear | `member.is_encrypted is True` |
| Unix-origin entry named `a\` | `FILE` named `a\` on every host OS |
| DOS-origin entry named `a\` | `DIRECTORY` named `a/` on every host OS; any data it declares is not reachable (no `open()`, extraction writes an empty directory) and `size` still reports it |
| Header name without a trailing `/`, Unicode Path field `dir/` | `DIRECTORY` named `dir/` on every Python version |
| Out-of-range NTFS or DOS timestamp | Fallback value used; `MEMBER_TIMESTAMP_INVALID` counted and may attach to member |
| Timestamp diagnostic resolves to `RAISE` | Listing halts with `DiagnosticRaisedError` |
| Encrypted symlink target unavailable | Listing continues with `link_target=None`; `SYMLINK_TARGET_UNAVAILABLE` contains no secret |
| ZipCrypto symlink target fails its integrity check under an unconfirmed password | Listing continues with `link_target=None`; `SYMLINK_TARGET_UNAVAILABLE` with reason `"password_or_damage"` |
| Encrypted symlink, `read_link_targets=False` | Listing reads no target data; `link_target=None`; no diagnostic |

### Requirement: Join 7-Zip .zip.NNN sets; reject spanned ZIP cleanly

7-Zip's `-v` byte-splits one finished single-disk ZIP into
`name.zip.001 … name.zip.00N`, exactly as it splits `name.7z.NNN`. An SFX split
names the same slices `name.exe.001 … name.exe.00N` (stub `name.exe` is not a
sibling). Windows 7-Zip keeps the archive extension (`name.zip.001`) and writes
the stub as `name.exe`. With every
part `1..N` present beside the one named, `open_archive` SHALL concatenate them
and read the result as the ordinary ZIP it is, from any part **or from a
stub-only `name.exe` that has no archive magic** (including under an explicit
`format=ZIP`; a `format=` naming a different container is `ArchiveyUsageError`),
reporting
`ArchiveInfo.is_multivolume = True` and `ArchiveInfo.extra["zip.volume_count"] = N`
(not `ArchiveMember.extra`, which stays empty).
A gap in the numbering SHALL raise `TruncatedError`. A lone `.zip.NNN` (or
SFX `.exe.NNN`) part whose siblings are not on disk SHALL raise the same
`TruncatedError`, naming the missing parts — not a ZIP spanned-set refusal.
A named part that is not on disk itself SHALL raise `FileNotFoundError`, like
any other missing path.

Every other split/spanned signal SHALL raise `UnsupportedFeatureError` with a
rejoin-first message rather than mis-read data or raise `CorruptionError`:
Info-ZIP `.zNN` segment names, non-zero EOCD disk fields (the ZIP64 end record's
when there is one; a classic `0xFFFF` is the ZIP64 sentinel, not a disk number), and
ZIP64 locator `disks > 1`. Info-ZIP
`zip -s` writes a genuinely spanned
set addressed by `(disk, offset-within-disk)`; a linear join lists correctly and then
reads only whichever members happen to sit on the last disk. Reading such a set is not
planned.

#### Scenario: multi-volume ZIP join and refusal

`open_archive` on a complete 7-Zip `.zip.NNN` or SFX `.exe.NNN` set — named at any
part — lists and
reads its members, including data spanning a part boundary. An incomplete such set
raises `TruncatedError`; every other split/spanned signal raises
`UnsupportedFeatureError`. Neither surfaces `CorruptionError` or
`FormatDetectionError`.

### Requirement: Check the ZIP end record against the central directory

The central directory is walked entry by entry until the walk has consumed the
directory size the end record gives. The ZIP reader SHALL report, as
`ARCHIVE_EOF_MARKER_MISSING` with `format="zip"`, emitted after the listing's
last member so the listing completes, each of:

- the entry count the end record declares (the ZIP64 record's when there is one)
  differs from the number of entries the central directory holds
  (`expected_marker="end_of_central_directory"`, `observed_kind="nonzero"`). A classic
  record counts in 16 bits and old 7-Zip versions stored a larger count's low 16 bits
  there without ZIP64, which current 7-Zip accepts, so its count is compared modulo
  65536;
- the archive comment length runs past the end of the file
  (`expected_marker="end_of_central_directory"`, `observed_kind="short"`).

Neither SHALL raise under the default policy; `STRICT` refuses the archive.
Info-ZIP unzip warns or errors on each and 7-Zip reports "Headers Error", after testing
every member.

The checks compare the end record the reader selected, the last end-record signature
in the file's tail. An end-record signature inside the archive comment is therefore
compared with the empty directory it describes and agrees with it: the archive lists as
empty (`EMPTY_ARCHIVE`) with no end-record diagnostic, as Info-ZIP unzip also lists it,
while 7-Zip searches further back and lists the real members.

#### Scenario: end record mismatches

| Archive | Expected |
| --- | --- |
| Classic end record declares 2 or 4 entries, directory holds 3 | All 3 members listed and readable; one `ARCHIVE_EOF_MARKER_MISSING`, `expected_marker="end_of_central_directory"`, `observed_kind="nonzero"`, `observed_bytes` the record's offset |
| ZIP64 end record declares 5 entries, directory holds 3 | Same, the message naming the ZIP64 record |
| Comment length 5000, 8 comment bytes in the file | `observed_kind="short"`, `expected_bytes` 5022, `observed_bytes` 30 |
| Consistent classic or ZIP64 end record | No diagnostic |
| 65537 entries, classic record only, count 1 (65537 modulo 65536) | All 65537 members listed; no diagnostic |
| Archive comment holding an end-record signature followed by 30 zero bytes | No members listed; one `EMPTY_ARCHIVE` and no `ARCHIVE_EOF_MARKER_MISSING` |
| Any of the above under `STRICT` | `DiagnosticRaisedError` from the listing |

### Requirement: List a damaged ZIP central directory up to the damage

The central directory SHALL be walked as members are listed, so a damaged entry costs
the directory's fields from it on, not the archive (DR-2). An entry whose signature is
wrong, whose 46-byte fixed header the directory cuts short, or whose lengths are damaged
SHALL make the listing raise `CorruptionError` after the members before it and the
members the local headers hold past it, which a read from a pipe lists the same way:
those keep only what their local header holds (no mode, host or comment), and a member
the directory already listed, by offset, is not listed again. `members()` raises,
`members_report()` returns those members with the error, iteration yields them and then
raises, and `extract_all()` writes them and then raises. Every listed member SHALL read,
except one whose data the walk over the local headers could not get past: its read SHALL
raise that walk's error, a cut as `CorruptionError` and never `TruncatedError` (the end
record follows it). A listing limit that walk meets SHALL be raised instead of the
damage. A read from a pipe raises whatever stops it, as it meets that before the
directory, and raises the damage ahead of a check a member before it fails.
`ArchiveInfo.member_count` SHALL be `None` when the walk did not complete. A
local-header offset past the file's end SHALL raise `CorruptionError` when that member
opens, never `TruncatedError` (the directory follows every local header, so the offset
is wrong, not the file cut) and never an untyped error for an offset too large to seek
to. A local-header offset that falls before the file's start, as when the archive lost
its first bytes, SHALL raise `CorruptionError` when that member opens, and its message
SHALL say how many bytes the archive seems to be missing, not give the negative offset.

An entry's lengths are damaged when:

- its name, extra field or comment runs past the directory's end;
- its name, extra field or comment holds a central header signature from which the
  headers chain exactly to the directory's end, and either the end record's count fits
  that reading or the first of those headers points at a local header with its name:
  the lengths swallowed those entries. A member comment holding a whole well-formed
  entry chains too, but points at another member's local header and lists as it is;
- its name, extra field or comment holds a central header signature, and following
  such signatures has already stepped over as many headers as the directory could
  hold or read twice the directory past the walk's own reads, so the walk cannot rule
  out a swallow. The walk remembers the headers a chain steps onto past its first, up
  to a fixed number ahead of it, so following costs about one more pass over the
  directory however many signatures it holds, in bounded memory, and a signature that
  is part of a name fails at its first header and spends nothing;
- no central header follows it and the local header at its offset holds another name:
  its name length was made shorter.

Cutting the field, as `zipfile` does, would list a member under a cut name or one made
of other entries' bytes and drop the entries it swallowed (DR-1). A signature from which
the headers do not chain so is part of the name, and a wrong count alone stays the
end-record finding above. An entry no header follows whose local header holds the same
name, or none, is listed without its comment, which a wrong length may have cut, and the
next entry raises. This supersedes the earlier cut-and-warn rule, by davi's 2026-10-17
ruling (PR 860).

#### Scenario: damaged directory

| Archive | Expected |
| --- | --- |
| Third central header's signature overwritten | `a.txt`, `b.txt` listed from the directory, `c.txt` from its local header (no mode), then `CorruptionError` naming a bad magic number; all three read |
| A 10-byte header fragment after the second entry, inside the declared directory size | `a.txt`, `b.txt` listed (no third local header), then `CorruptionError` naming a truncated central directory |
| The first, through `for member in reader` or `extract_all()` | Three members yielded or written, then `CorruptionError` |
| Second central header's signature overwritten, from a file and from a pipe | The same listing, mode from the directory for the first member only, the same files written |
| First entry's name, extra or comment length grown by exactly the second entry's size, or by 0x8000, from a file and from a pipe | `m0.txt`, `m1.txt`, `m2.txt` listed from their local headers, the same files written, then `CorruptionError`; never a member named `m0.txtPK\x01\x02…` |
| Last entry's name, extra or comment length runs past the directory | The members before it from the directory, the last from its local header, then `CorruptionError` naming the field |
| A member named `a\x01PK\x01\x02.txt`, count agreeing | Listed as it is; no diagnostic |
| A member named `a\x01PK\x01\x02.txt`, end record declaring one entry too many, from a file and from a pipe | Both members listed with their mode; one `ARCHIVE_EOF_MARKER_MISSING` for the count |
| First entry's name length cut from 6 to 4 (`m0.t`), from a file and from a pipe | `m0.txt`, `m1.txt`, `m2.txt` from their local headers, then `CorruptionError`; never `m0.t` |
| First entry's name length grown by exactly the second entry, end record declaring the 2 entries that remain, from a file and from a pipe | `m0.txt`, `m1.txt`, `m2.txt` from their local headers, then `CorruptionError` |
| First entry's comment length cut from 13 to 8, from a file and from a pipe | Both members listed with comment `None`, never `hello-co`, then `CorruptionError` |
| 40 members, each with two signatures in its comment and one in its name, from a file and from a pipe | Every member listed with its mode and comment; no error and no diagnostic |
| Second entry's ZIP64 local-header offset 2^41, 2^63 − 1 or 2^64 − 1 | Both members listed; `a.txt` reads, `b.txt` raises `CorruptionError` when it opens |
| First 60 bytes of a three-member stored ZIP cut off | All three members listed; `a.txt` and `b.txt` raise `CorruptionError` saying the archive seems to be missing at least its first 60 bytes; `c.txt` reads |

### Requirement: Read ZIP members whatever version they say they need

"Version needed to extract" SHALL NOT refuse a member or the archive: what a member
needs is named by its method and flags, which are checked when it opens (DR-4). 7-Zip
23.01 reads a stored member marked 8.4.

#### Scenario: version needed above 6.3

| Archive | Expected |
| --- | --- |
| Stored member, both headers marking version 8.4 | Listed and read |
| The same with method 77 | Listed; reading it raises `UnsupportedFeatureError` naming method 77 |

### Requirement: Read ZIP members whose local header disagrees with the directory

The local header repeats most of a member's central directory entry. Three
disagreements SHALL NOT refuse the member (maintainer rulings 2026-10-10 and 2026-10-21)
and SHALL report a code with `LocalHeaderContext`:

- **The name** (`MEMBER_LOCAL_NAME_DIFFERS`, which `STRICT` refuses: a tool that trusts
  the local header shows another name). The local header stores other name bytes than
  the directory: another code page, or `\` where the directory has `/`. Every field
  comes from the directory, so the member keeps the directory's name. A file read reads
  a local header only when it opens a member's data, so the report comes then
  (`field="name"`, the local bytes in `local_raw_name_base64`), once per member; a
  policy that raises on the code raises on every open. Only a file or link reports it:
  extraction reads no directory's data, so a directory reports nothing, even after a
  `read()` of data it declares, and nor does the pass from a pipe, which reads every
  local header.
- **The compression method** (`MEMBER_LOCAL_METHOD_DIFFERS`, which `STRICT` refuses: a
  tool that trusts the other header decodes other bytes or fails). The member SHALL be
  decoded by the local header's method: it sits next to the data, and a read from a pipe
  has nothing else, so a file and a pipe read the same bytes, which the CRC-32 still
  checks. A file read reports when it opens the member (`field="method"`,
  `local_method`, `central_method`), once its local header passes its checks and before
  the data is decoded, once per member, a file or link only, as for the name; the pass
  reports once it has read the directory, also for a member whose data then fails on a
  CRC or size, as a file read does. A member the overlap guard refuses reports nothing
  from a file and still reports from the pass (DR-5a; the forward-pass requirement
  lists it). The listing
  keeps the directory's method: `compression` and `extra["zip.compress_type"]` name it,
  as every listed field comes from the directory (a CRC-32 of 0 aside, below), and the
  diagnostic carries both.
  WinZip AES (method 99) in one header only SHALL refuse the member, from a file and a
  pipe, without the report: its record is read from the directory's extra field, so the
  two headers disagree on the encryption. So SHALL method 99 in both headers when the
  two AES records differ in any field (version, strength, real method) or one side's is
  missing or unparseable: the pass would decode by the local record and a file read by
  the directory's.
- **A CRC-32 of 0** (`MEMBER_LOCAL_CRC_USED`, which `STRICT` reads: the data is still
  checked; maintainer ruling 2026-10-15). The directory stores 0 for a file or link of
  one byte or more, not WinZip AE-2 (whose HMAC checks the data, above), and the local
  header, with no data descriptor (bit 3 clear), a non-zero value. Adobe AIR's packager
  stores `META-INF/AIR/hash` this way. The member's `hashes` and every check of its data
  (the CRC, the ZipCrypto check byte) take the local value. A file read reads that local
  header when it lists the member, the only listing-time read of a local header, and
  reports then (`field="crc32"`, `local_crc32`); a crafted plaintext archive whose every
  entry stores 0 so costs one positioned read per member while listing. An AE-2 entry
  costs none and reports nothing. A directory that declares data under a CRC-32 of 0
  keeps no digest, from a file and a pipe alike (`DIGEST_UNVERIFIABLE`), and reports
  nothing more.

Both headers understating the size, with a CRC-32 over the longer output, SHALL stay
refused: the declared size is the bound that stops decoding (DR-9a). A read from a pipe
SHALL behave as a file read: the same members, data, reports and files on disk.

#### Scenario: headers that disagree

| Archive | Expected |
| --- | --- |
| Local name `Patag\x93nia.mp3`, directory `Patag\xf4nia.mp3` | Reads; the member's name from the directory; `MEMBER_LOCAL_NAME_DIFFERS` (`field="name"`) when its data is read |
| Local name `crack\`, directory `crack/`, with or without declared data | A directory, `crack/`; no report |
| Directory `crack/` declaring data, its CRC-32 0, the local CRC-32 right | `DIGEST_UNVERIFIABLE` and `MEMBER_DIRECTORY_DATA_IGNORED`, from a file and a pipe alike |
| Central CRC-32 0, local CRC-32 right | Listed with the local CRC-32 in `hashes`; reads; `MEMBER_LOCAL_CRC_USED` (`field="crc32"`) at listing, also under `DiagnosticPolicy.STRICT` |
| Central CRC-32 0, local CRC-32 wrong, or 0 in both | `CorruptionError` when read |
| The first under `DiagnosticPolicy.STRICT`, or the fourth under `DiagnosticPolicy.PEDANTIC` | `DiagnosticRaisedError` |
| Both headers declare 3.5% less than the data decodes to | `CorruptionError` ("exceeds its declared size") |
| Local method stored, directory method deflate, over stored data (or deflate against stored or bzip2), from a file and a pipe | Reads the data; `MEMBER_LOCAL_METHOD_DIFFERS` (`field="method"`); `DiagnosticRaisedError` under `DiagnosticPolicy.STRICT` |
| Local method stored over a deflated body, directory deflate | `CorruptionError` from a file and a pipe |
| Directory method 99 (WinZip AES), local method 8 | `CorruptionError` from a file; from a pipe the local header says ZipCrypto, so `EncryptionError` |
| Local method 99 (WinZip AES), directory method 8 | `CorruptionError` from a file, and from a pipe at the end of the pass |
| Method 99 in both, local AES record naming stored, the directory's deflate | `CorruptionError` from a file, and from a pipe at the end of the pass |
| Directory names stored over a deflated body the local header names | `compression` and `extra["zip.compress_type"]` say stored; the data reads deflated |

### Requirement: Report bytes after the end of a ZIP archive

A ZIP archive SHALL be taken to end at the end of its end-of-central-directory record
plus the comment length that record declares. At open, a non-zero byte after that end
SHALL emit one `ARCHIVE_TRAILING_DATA` with `format="zip"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"` and `observed_bytes` the
offset of that byte past the end. It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the end SHALL be silent. Bytes inside
the declared comment are the comment, whatever they hold. The end record is searched for
in the last 65 558 bytes of the file. When a longer tail hides it, the reader SHALL walk
the local headers from the start, without decoding any member, to where the members end,
and step over the directory and the ZIP64 end records there to the end record, which is
then read as one the search found. Each local header the walk meets SHALL count toward
`max_members` before its data is passed. A read from a pipe steps over the same records
after its pass. A stub before the archive moves nothing. 7-Zip 23.01 warns on any tail;
Info-ZIP `unzip` says nothing.

#### Scenario: ZIP trailing bytes

| Archive | Expected |
| --- | --- |
| Ends at its end record, with or without a comment | No diagnostic |
| 4096 zero bytes after the end record | No diagnostic; `STRICT` opens it |
| 0, 100 or 60 000 zero bytes then `JUNK` after the end record or its comment | One `ARCHIVE_TRAILING_DATA`, `observed_bytes` 0, 100 or 60 000; members list and read |
| A 1000-byte stub before the archive, 7 zero bytes and `JUNK` after it | `observed_bytes` 7 |
| `JUNK` after the end record under `STRICT` | `DiagnosticRaisedError` |
| 1 MiB of non-zero bytes after the end record, from a file or a pipe | One `ARCHIVE_TRAILING_DATA`, `observed_bytes` 0; members list and read |
| The same with the directory gone | Members listed from their local headers, then `CorruptionError` (see the next requirement) |

### Requirement: List a ZIP whose end record is missing

When neither the search nor the step over the directory finds an end record, the
reader SHALL list the members the local-header walk found and then raise the error the
walk met, in the words a read from a pipe uses for the same bytes, as a cut TAR lists
and raises: `members()` raises, `members_report()` returns the members with the error,
iteration yields them and then raises, and `extract_all()` writes them and then raises.
Each member SHALL be what its local header says, as a pipe read lists it before its
directory: no `mode`, `create_system` or comment; a bit-3 member takes its CRC and
sizes from its data descriptor, and a read checks the data against them. A member whose
data the file cuts, or whose descriptor the walk does not find, SHALL be listed last,
and reading it SHALL raise the walk's error. `ArchiveInfo.member_count` SHALL be
`None`. With no member before the walk's error, `open_archive` SHALL raise it. A walk
that meets more local headers than `max_members` SHALL stop there and the archive
SHALL open; the listing then raises `ResourceLimitError` as when the directory's
entries cross the limit: a streaming pass, from a file as from a pipe, yields the
members before it first, and a random-access listing lists none.
After that streaming pass, `members_report_if_available()` SHALL return `None`, as for
a pipe read.

Two shapes read differently from a pipe, which decodes each member as it passes:

- A deflated or encrypted bit-3 member whose descriptor states a size or CRC its data
  does not have. The file read decodes nothing at open, as it does not check a
  directory's sizes either, so it lists the member's size and CRC32 as the descriptor
  states them; the pipe read lists the size it measured, and no CRC32 when its data did
  not match the descriptor's. Both refuse the member's data, in different words: from
  a file by the size, digest or declared ratio check, from a pipe at the end of its
  data.
- A bit-3 directory that declares data. The pipe read reaches the directory before
  its data descriptor, so it has no size for it, and `stream_members()` yields `None`
  for it where the file read, and a pass over a seekable source, yield a stream of the
  bytes. Telling a bit-3 directory with data from an empty one would mean decoding its
  data before the pass yields it, which for an encrypted entry asks for a password the
  caller may never need; so the pass does not, and the data goes past unread.
  `MEMBER_DIRECTORY_DATA_IGNORED`, reported when the central directory arrives (on any
  listing, not only a pass), says that a pass over a source that cannot seek yields no
  stream for it and that `open()` from a seekable source delivers the bytes. In a ZIP
  with no central directory, the file read lists the CRC32 the data descriptor states,
  as for a file; the pipe read lists none for the directory.
- Junk after a bit-3 member: the two raise in different words.

Both write the same files.

#### Scenario: ZIP with no end record

| Archive, three members | Expected |
| --- | --- |
| Cut where the directory starts | Three members listed and read, then `TruncatedError` naming the end after 3 members |
| Cut inside the directory, or right before the end record | Three members, then `TruncatedError`: the stream ends inside the central directory |
| Cut inside the third member's data | Three members, then `TruncatedError` naming member #2, which its read raises too; the first two read |
| Cut inside the second local header | One member, then `TruncatedError` naming local header #1 |
| `JUNK` where the directory should start | Three members, then `CorruptionError`: the bytes after member #2 are not a ZIP header |
| `JUNK` after a whole directory, where the end record should be | Three members, then `CorruptionError` naming the bytes after the central directory |
| Cut inside the first local header | `TruncatedError` at open |
| Any of these with bit-3 members | The same members, each with its descriptor's CRC and sizes; a pipe read lists and extracts the same, and for a cut raises in the same words (junk after a member raises in different words, as above) |
| A deflated bit-3 member whose descriptor states an uncompressed size of 2^62 or 2^64 − 1, or a wrong CRC, cut inside the directory | Listed with that size and CRC32; its read and its extraction fail; from a pipe it is listed with the 11 bytes it holds, without the wrong CRC32, and its read fails; both listings raise the same `TruncatedError`; nothing is written |

### Requirement: Read past damaged ZIP64 end records

When the ZIP64 end record a locator announces cannot be used (no record where the
locator points or right before it, a record that does not match the locator, or a
locator naming an offset past itself), and no field of the classic end record holds the
ZIP64 sentinel, both reads SHALL use the classic record's values and report
`ARCHIVE_EOF_MARKER_MISSING` with `expected_marker="zip64_end_of_central_directory"` and
`observed_kind="absent"`. The directory SHALL end at the first of these that follows a
central header: where the locator names the record, right before the locator, at the
locator. When a classic field holds the sentinel, or no such place exists, a file read
SHALL list the members the local headers hold and then raise the end records' error,
as a read from a pipe does (Requirement: List a ZIP whose end record is missing). A
read from a pipe whose listing limits dropped the bytes the locator names SHALL raise
`ResourceLimitError` instead of using the classic record: higher limits keep those
bytes, and the pass then reads what a file read reads. A locator naming another disk
SHALL stay refused as a split set.

#### Scenario: damaged ZIP64 end records

| Archive, three members, ZIP64 records before the classic one | Expected, from a file and from a pipe |
| --- | --- |
| The ZIP64 record's signature damaged, classic fields unsaturated | Three members listed and read; `ARCHIVE_EOF_MARKER_MISSING` |
| The locator names an offset past itself, classic fields unsaturated | The same |
| The locator names an offset among the members' data, classic fields unsaturated | The same; the pass's message says it passed those bytes |
| A locator with no ZIP64 record, naming an offset among the members' data; the directory ends at the locator; classic fields unsaturated | The same |
| The ZIP64 record's signature damaged and the classic directory size one byte longer than the directory, so no place fits a directory; classic fields unsaturated | Three members as their local headers say, then `CorruptionError`, from a file and a pipe alike |
| A locator naming an offset in bytes a pipe's listing limits dropped, classic fields unsaturated | Members listed from a file with `ARCHIVE_EOF_MARKER_MISSING`; `ResourceLimitError` from a pipe |
| Any of the first three with the count, size and offset fields saturated | Three members as their local headers say, then `CorruptionError`; a pipe read gives the same error, except for the offset among the members' data, said in its own words |
| A bad directory offset (`cd_size` past the classic record) | Three members as their local headers say, then `CorruptionError: Bad offset for central directory` |

### Requirement: Read ZIPs written past 4 GiB without ZIP64

macOS Archive Utility (Finder's Compress, `ditto -c -k`) writes a classic ZIP past
4 GiB and stores every offset modulo 2³², the end record's offset of the central
directory too. When the end record is classic, a read from a file and a read from a
pipe SHALL correct such offsets as they walk the directory. The members lie in
directory order, so an entry whose stored local header offset falls below the end of
an entry before it (its corrected offset, the 30-byte fixed local header and its
compressed size; the furthest such end) SHALL get 2³² added until it no longer does.
The directory's own offset wraps the same way, which makes the stub length the end
record implies (`base`) a multiple of 2³² larger than the real one: the walk SHALL
take that length modulo 2³². A correction SHALL be kept only when a local header
whose name equals the entry's starts at the corrected offset before the directory (for
the directory's offset, the first entry's header at its offset with the smaller
length); otherwise the stored offset stays and the member fails as it would without
the correction. A read from a pipe checks the name against the local headers its pass
met. An offset from a ZIP64 extra field, and any offset under a ZIP64 end record,
SHALL NOT be corrected. Each kept correction SHALL emit `ARCHIVE_OFFSET_WRAPPED` with
`OffsetWrapContext`: one per member (`record="local_header"`), and one for the
directory (`record="central_directory"`, no member). The member's CRC-32 SHALL be
checked as for any member. A member whose own sizes pass 4 GiB wraps its sizes too;
the next requirement corrects them for the entries that writer marks. Without those
marks its read raises at the declared size, and when its compressed size wraps, its end
falls a multiple of 2³² short, so the members after it keep their stored offsets and
their reads fail too.

#### Scenario: offsets wrapped past 4 GiB

| Archive (a sparse layout, nothing stored past the headers and short members) | Expected, from a file and from a pipe |
| --- | --- |
| A member of 2³² − 16 bytes, then two short members and the directory past 4 GiB, every offset stored modulo 2³² | Three members listed; the two short ones read with matching CRCs; `ARCHIVE_OFFSET_WRAPPED` twice with `record="local_header"`, then once with `record="central_directory"` |
| Every member below 4 GiB, the last one ending past it, so only the directory's offset wraps | Members listed and read; one `ARCHIVE_OFFSET_WRAPPED` with `record="central_directory"` |
| The first case with the directory naming one short member differently from its local header | From a file: that member keeps its stored offset and its read raises `CorruptionError`; the other is corrected. From a pipe: the directory entry points at no local header the pass met, so the pass raises `CorruptionError` at the directory, as for any such entry, and reports the unmatched local header as `ARCHIVE_UNLISTED_DATA` |
| A member of 2³² + 2²⁹ bytes, sizes and offsets stored modulo 2³², then a short member, without Archive Utility's marks | Both listed and the directory's offset corrected; the short member after the large one keeps its stored offset and its read raises `CorruptionError` |
| A ZIP under 4 GiB whose directory lists members out of file order | No correction and no extra read: every corrected offset would be past the directory |
| The first case under `DiagnosticPolicy.STRICT` | Reads as above; the `ARCHIVE_OFFSET_WRAPPED` diagnostics are recorded, not raised |

### Requirement: Read members past 4 GiB of a macOS Archive Utility ZIP

The same writer stores a member's sizes modulo 2³² as well. An entry carries its marks
when its version made by is `0x0315` (Unix, 2.1), general-purpose bit 3 is set and
bit 0 (encryption) clear, and its central extra field is one old Info-ZIP Unix (`UX`,
`0x5855`) field and nothing else. Anyone can copy the marks, so they SHALL only gate
the corrections below, each checked against the archive's own bytes; under a ZIP64
end record nothing is corrected.

- **Compressed size.** When the directory starts past 4 GiB, the walk SHALL hold back
  each marked entry until it has corrected the next entry's offset, and SHALL measure
  the marked entry's data from its local header's data start to the next entry's
  local header, or to the directory for the last entry, less the 16-byte signed data
  descriptor. When that length exceeds the stored compressed size by a positive
  multiple of 2³², the entry SHALL take it. The entry after a marked one SHALL look
  for its local header at its stored offset plus each multiple of 2³² in turn, from the
  first not below the end of the members before it, and keep the first whose name
  matches; the data start SHALL come from the same local header read. A read from a
  pipe measures from the local headers its pass met.
- **Size, stored members.** The size SHALL be the compressed size when the two agree
  modulo 2³².
- **Size, deflated members.** The size is the stored size plus a multiple of 2³² that
  is at most 1032 times the compressed size (a 258-byte match takes two bits at the
  least). No lower bound applies, since empty stored blocks pad a valid stream without
  bound. When only the stored size fits, it SHALL be the member's size. When several
  fit, `size` SHALL be `None`, with `extra["size_mod_2_32"]` holding the stored size;
  the key SHALL stay after a read fills `size` in. An entry with no CRC-32 SHALL keep
  the stored size instead of `None`, since nothing can check a read against it. When none fits (a damaged entry),
  the stored size SHALL stay, and the read fails on it.
- A member whose sizes were corrected or left unknown SHALL emit `MEMBER_SIZE_WRAPPED`
  with `SizeWrapContext` (advisory, as `ARCHIVE_OFFSET_WRAPPED`). Its message SHALL say
  the archive was written past 4 GiB only for a corrected size, not an unknown one.
- **Reading a member of unknown size.** A read from a file SHALL decode the member
  with no declared size, under the usual limits. Once a read reaches the end, the
  length SHALL be refused with `CorruptionError` unless it equals the stored size
  modulo 2³² and is at most 1032 times the compressed size, then the CRC-32 SHALL be
  checked, and only then SHALL `member.size` take the length. A pipe pass that decoded
  the member to its end with the directory's CRC-32 SHALL keep the size it counted
  when the directory leaves it unknown; for a bit-3 member it reads past, that is one
  whose codec ended within the symlink target cap, and one whose data runs past the
  cap keeps `size` `None`, as from a file. Until its size is filled in, such a member's
  `member_state_final` SHALL be `False`; it SHALL be `True` once the size is filled
  in, once a `streaming=True` pass ends (no read can reach the member again), and
  once the reader closes (`archive-data-model`).

#### Scenario: members past 4 GiB with Archive Utility's marks

| Archive (a sparse layout; every entry marked) | Expected |
| --- | --- |
| A short member, a stored member of 2³² + 2²⁹ zero bytes, a short member | From a file and a pipe: the large member's size and compressed size are 2³² + 2²⁹, the members after it read, one `MEMBER_SIZE_WRAPPED` and the offset corrections |
| The same without the `UX` fields | The stored sizes stay and the last member's read fails, as in the previous requirement |
| A deflated member of 2³² + 100 zero bytes, about 4 MiB compressed | `size` is `None` and `extra["size_mod_2_32"]` 100 at listing; `DiagnosticPolicy.STRICT` lists it; a read to the end yields 2³² + 100 bytes and fills in `size`, and the key stays |
| A deflated member of 100 bytes padded with empty stored blocks to about 10 MB, stored size 100 | `size` is `None`, not 2³² + 100, and `member_state_final` `False`; a read yields 100 bytes and fills in `size`, and the flag reads `True`; with no read, it reads `True` once the reader closes |
| The same, `streaming=True` | After the pass the member reads `True`: from a pipe with the size the pass counted, from a seekable source the caller did not read with `size` `None` |
| The same with 5000 bytes, past the symlink target cap, `streaming=True` from a pipe, not read | After the pass the member reads `True` with `size` `None`, as from a file: the pass decoded it only to the byte past the cap |
| A deflated member whose stored size is over 1032 times its compressed size | The stored size stays; the read raises `TruncatedError` |
| A stream decoding to 101 bytes against a stored 100 | `size` is `None`; the read raises `CorruptionError` and `size` stays `None` |
| A stream of unknown size with a wrong CRC-32 | The read raises `CorruptionError` and `size` stays `None` |
| A stored entry `d/` with no CRC-32 and 2³² + 2²⁹ bytes of data | Its sizes come from the layout, with one `MEMBER_SIZE_WRAPPED`; the member after it reads |
| A small deflated member | Untouched: no diagnostic, no `size_mod_2_32` |

### Requirement: Apply max_members while reading a ZIP directory

`ListingLimits.max_members` SHALL be charged as the central directory is walked, in
every access mode and by every walk (the listing, and the index pass `member_count`
runs when it comes first), so `stream_members()` and iteration are not
an escape hatch. An end record that declares more entries than `max_members`, in a
directory at least 46 bytes per declared entry long, SHALL be refused at
`open_archive` with `ResourceLimitError`. A declared count the directory cannot hold is
a wrong field (reported as a count mismatch, see above), and the walk charges the
entries really there: past `max_members` it SHALL raise `ResourceLimitError`. The
members listed before the limit SHALL read, also when they are opened before the
listing reaches it.

A forward pass over a non-seekable source has no directory to read first: it SHALL
charge `max_members` on the local headers as it yields members, and again on the
directory's entries as it reads them, and SHALL weigh the directory's names, extra
fields and comments against `max_metadata_bytes` as they arrive, raising
`ResourceLimitError` past either.

#### Scenario: ZIP member limit

| Archive, `max_members=2` | Expected |
| --- | --- |
| Three entries, end record declares 3 | `ResourceLimitError` at open |
| Three entries, end record declares 1 | Opens; the listing, iteration or `stream_members()` raises `ResourceLimitError` at the third entry |
| The same, `streaming=True`, each stream read as `stream_members()` yields it | The first two members read in full, then `ResourceLimitError` |
| Three entries from a non-seekable source, `streaming=True` | The first two members yielded, then `ResourceLimitError` at the third local header |
| Three entries from a file, then 1 MiB of other bytes (the end record past the search window) | Opens without reading the third member's data or the tail; the listing raises `ResourceLimitError`, as at the third directory entry |

### Requirement: Confirm multi-candidate ZipCrypto passwords

For traditional ZipCrypto, the per-open verification byte is weak and the
authoritative check is CRC-32 plus decompressor completion. When another
distinct candidate may be tried, the ZIP reader SHALL confirm a candidate that
passes the byte check before accepting it, following `archive-reading` weak-check
confirmation and bounded-storage rules. With one distinct static candidate
(duplicates included), the reader SHALL keep the normal lazy stream path, with no
confirmation read. Because only the verification byte vouched for that password, a
candidate failure (defined below) on the caller's `read`, `readinto` or forward `seek`
SHALL raise `EncryptionError` explaining that the password may be wrong or the member
may be corrupt, not `CorruptionError`; for an `LZMA` or `PPMd` member, whose codec
header is read when the member opens, the open raises it. It SHALL NOT be marked as a
wrong-password verdict: nothing in the archive tells a colliding wrong password from a
damaged member. A STORED member's forward seek jumps, so a read after it pauses the CRC
until a seek back to the frontier (`compressed-streams`, ADR 0014) and that seek does
not raise; closing that stream emits `ENCRYPTED_MEMBER_UNVERIFIED`. A compressed
member's forward seek keeps the CRC, as `compressed-streams` describes.

ZIP's two per-open checks are the `archive-reading` ladder's **cheap key check** rung:
ZipCrypto's one header verification byte (2⁻⁸) and WinZip AES's two-byte `pw_verify`
(2⁻¹⁶). Neither reaches 2⁻³², so neither SHALL confirm on its own; both eliminate. Neither
cipher pads — ZipCrypto is a byte-wise stream cipher and WinZip AES is CTR, so ciphertext
length equals plaintext length in both — so ZIP has no tail-padding check to add.

A member stream whose password only one of those checks accepted, closed before EOF,
SHALL emit `ENCRYPTED_MEMBER_UNVERIFIED` (`check="weak_open_check"`): a wrong ZipCrypto
password that passes the byte check returns readable garbage from a partial read and
fails only at the CRC, and a WinZip AES member's HMAC runs only at EOF.

Compressed members SHALL confirm by decompressing a bounded plaintext prefix and
discarding it. If EOF is reached within the bound, the CRC check makes confirmation
exact. Confirmation SHALL run through `plan_password_confirm` /
`run_password_confirm_plan` as the probe under `_PasswordCandidates.attempt`, with the
member as the one substream. Only `DEFLATE`, `BZIP2` and `LZMA` count as rejecting
codecs; they are stream codecs, or bzip2, which produces output after one block, so the
compressed input a bounded prefix consumes is bounded by the format and needs no
separate cap. Any other method walks to the CRC. A compressed member larger than the
prefix yields an `INCONCLUSIVE` survivor: its stream, closed before EOF, SHALL emit
`ENCRYPTED_MEMBER_UNVERIFIED` (`check="confirm_budget_exhausted"`). The same probe
confirms WinZip AES candidates. Where an AES member's CRC is out of reach (AE-2 stores
none) and the member fits the prefix or its codec does not reject, the probe SHALL read
the member to its end, where the HMAC, which covers the whole ciphertext, confirms or
rejects the candidate. STORED members
SHALL disambiguate all surviving candidates in one shared ciphertext pass, computing each
candidate's plaintext CRC-32 in constant memory; if multiple candidates match, candidate
order wins. No candidate plaintext may be buffered. The STORED shared pass stays
ZIP-local, since running every candidate over one pass is a shape the per-candidate probe
does not model.

The CRC a candidate is confirmed against SHALL be the member's CRC-32 digest
(`hashes[CRC32]`, the one its read is verified against), not the header's CRC field. A
member with no CRC-32 digest (AE-2, which stores 0; a directory whose CRC field is 0 over
declared data) has no CRC anchor: a ZipCrypto one, STORED included, takes the bounded
confirm, and a WinZip AES one is confirmed by its HMAC. The member then reads with
several candidates as it does with the one right password.

After confirmation, the reader SHALL open a fresh caller stream with the accepted
password, promote it to known-good when confirmation reached the member's CRC, and retain
ordinary read-time integrity checking. An `INCONCLUSIVE` survivor is not promoted: this
path runs only for an ambiguous candidate set. Confirmation failure for all candidates
SHALL raise `EncryptionError` explaining that passwords may be wrong or the member may be
corrupt. For WinZip AES, where each failing candidate had passed the 16-bit `pw_verify`,
it SHALL raise the damage instead (`CorruptionError`, or `TruncatedError` for data that
ends before its declared size), as "Read WinZip AES-encrypted members" says.

Candidate failures SHALL be the `CorruptionError` a wrong key's garbage produces (a
codec rejection, a CRC or HMAC mismatch), and a codec's `TruncatedError` while the
member's whole payload is in the file. Local-header mismatch, bad local-header magic,
overlap and other structural failures raise before decryption starts and SHALL become
`CorruptionError` immediately, with no further password iteration; a payload the file
cuts short stays `TruncatedError`. `UnsupportedFeatureError`,
`PackageNotInstalledError`, `ResourceLimitError` and `OSError` values SHALL propagate
unchanged, with two exceptions. The LZMA `lc + lp` and PPMd restore-method settings a
ZipCrypto key decrypted raise `CorruptionError`, not `UnsupportedFeatureError` (see the
codec-layer requirement), so a wrong key's garbage there is a candidate failure. On a
ZipCrypto `LZMA` or `PPMd` member the codec settings (the LZMA properties, the PPMd
order and memory size) are part of the encrypted data, so a wrong password that passes
the one-byte check decrypts them to an arbitrary size. A `ResourceLimitError` those
settings raise SHALL count as that candidate's failure, and the next candidate SHALL be
tried. When no candidate succeeds and at least
one failed that way, the reader SHALL raise the first such `ResourceLimitError`, its
message noting that under ZipCrypto the password may be wrong. It stays a
`ResourceLimitError` so that a caller who raises `DecoderLimits.max_decoder_memory`
gets a working read when the size is real. A lone password raises the same noted
`ResourceLimitError`. WinZip AES members keep propagating `ResourceLimitError`
unchanged: a garbage size needs a wrong password that passes the 16-bit `pw_verify`.
Rejected-candidate streams SHALL be closed before trying the next candidate.

#### Scenario: ZipCrypto confirmation matrix

| Case | Expected |
| --- | --- |
| Wrong candidate passes verification byte before correct one (STORED / DEFLATE / BZIP2 / LZMA) | Wrong candidate rejected; fresh stream opened with correct candidate |
| One distinct static candidate | No confirmation read; member streams lazily |
| One distinct static candidate that passes the verification byte but is wrong, or right on a corrupt member | Caller `read`/`readinto`/forward `seek` of a compressed member raises `EncryptionError` saying the password may be wrong or the member corrupt (at open for `LZMA`/`PPMd`); no wrong-password mark |
| Same, `LZMA`/`PPMd` member whose decrypted codec settings exceed `max_decoder_memory` | Open raises `ResourceLimitError` whose message notes the ZipCrypto password may be wrong |
| Wrong candidate whose decrypted `LZMA`/`PPMd` settings exceed `max_decoder_memory`, before the correct one | Wrong candidate rejected; correct candidate reads |
| No candidate succeeds, and one failed on a decoder limit from its decrypted settings | The first such `ResourceLimitError`, message noting the ZipCrypto password may be wrong |
| Same, STORED member, caller seeks and closes | Seek does not raise; `ENCRYPTED_MEMBER_UNVERIFIED` on close |
| Large compressed member | At most bounded prefix decompressed per candidate; no proportional plaintext storage; caller stream still checks CRC at EOF |
| STORED member with several surviving candidates | One shared ciphertext pass computes every candidate CRC; matching candidate accepted and reopened |
| Multiple STORED CRC matches | Earliest matching candidate in order wins |
| Corruption beyond confirmed prefix | Caller read raises what the codec layer raises for the same damage unencrypted (`CorruptionError` or `TruncatedError`) |
| ZipCrypto candidates fail confirmation | `EncryptionError` says password may be wrong or member corrupt; no bytes returned |
| WinZip AES candidates all fail after passing `pw_verify` | `CorruptionError` (`TruncatedError` for a short member); no bytes returned |
| `OSError` from the source | Propagates unchanged; failed stream is closed |
| Structural local-header damage | `CorruptionError`; no further password iteration |
| Declared size too small for the encryption header | `CorruptionError` naming the member |
| One distinct static candidate, stream closed before EOF | Data returned; `ENCRYPTED_MEMBER_UNVERIFIED` (`check="weak_open_check"`) |
| Several candidates, STORED or compressed member within the prefix, stream closed before EOF | No diagnostic (the CRC confirmed the winner) |
| Several candidates, compressed member past the prefix, stream closed before EOF | `ENCRYPTED_MEMBER_UNVERIFIED` (`check="confirm_budget_exhausted"`); winner not added to known-good |
| WinZip AES member, wrong password | Rejected by `pw_verify`; HMAC remains the authoritative check |
| WinZip AES member, stream closed before EOF | `ENCRYPTED_MEMBER_UNVERIFIED` (`check="weak_open_check"`) |

### Requirement: Decode unflagged ZIP member names by UTF-8-validity sniff

The ZIP backend SHALL decode a member name whose general-purpose bit 11 (UTF-8/EFS flag) is
**clear** by first attempting UTF-8, and only when the bytes are not valid UTF-8 falling
back to the caller's `encoding=` when one was passed, else to a configurable legacy encoding
(default cp437, per APPNOTE). The caller's `encoding=` and the configured fallback SHALL
decode with `surrogateescape`; a codec that refuses that handler (`idna`) gives way to the
next one, and cp437 decodes every byte. This sniff SHALL apply only in the absence of an
authoritative encoding signal: a set bit 11 SHALL be honored as UTF-8 when the bytes are
valid UTF-8. A name whose bit 11 is set over bytes that are not valid UTF-8 SHALL decode
as an unflagged name that is not valid UTF-8 does (the caller's `encoding=`, else the
configured fallback, with no Unicode Path field consulted), and SHALL emit
`MEMBER_NAME_ENCODING_INFERRED` with `inferred_encoding` the codec used and
`declared_encoding="utf-8"`, whether or not the caller passed `encoding=`. When the sniff
selects an encoding archivey chose over the cp437 default — UTF-8, or a configured fallback
other than cp437 — the backend SHALL emit a `diagnostics` warning identifying the member,
the chosen encoding and the encoding it passed over (the caller's `encoding=` or the
configured fallback for a UTF-8 reading, cp437 for a configured fallback), so the decision
is observable and escalatable via `DiagnosticPolicy`. A name decoded with the caller's
`encoding=` emits no such warning. Decoding SHALL NOT raise a bare `UnicodeDecodeError`.

An Info-ZIP Unicode Path extra field (`0x7075`) in the central directory outranks both the
sniff and an explicit `encoding=` for an unflagged name: when the field is version 1, its
CRC-32 equals the CRC-32 of the stored name bytes, and its name is non-empty valid UTF-8,
the member name SHALL be that UTF-8 name, `raw_name` SHALL be its UTF-8 bytes, and
`extra["alternate_raw_name"]` SHALL hold the stored header bytes. No inference diagnostic
is emitted, since the field declares the encoding. A field whose CRC does not match or
whose version is not 1 SHALL be ignored, and the name decoded as above. A malformed field
SHALL be dropped, the name decoded as above, and `MEMBER_HEADER_RECORD_SKIPPED` emitted on
the member with `record="unicode_path"` and `record_id=0x7075`: a field shorter than its
version byte and CRC (5 bytes), whatever its first byte, since neither its version nor
its CRC can be read; or a version-1 field with a matching CRC whose name is
empty or not valid UTF-8. A version-1 field whose CRC matches but whose declared name runs
past the end of the extra field is malformed too. The outcome SHALL be the same on every
supported Python version: the archive SHALL open, and no Python `warnings` warning SHALL
be raised for the field. A
field in the local header only SHALL be ignored, and so SHALL the field of a name whose
UTF-8 flag is set. `name` is always `raw_name` decoded and normalized.

#### Scenario: UTF-8 bytes without the flag

- **WHEN** an archive stores a member name as valid UTF-8 bytes (e.g. `Español.txt`,
  `emoji_😀.txt`) with bit 11 **clear**, with or without an `encoding=` from the caller
- **THEN** the member name is decoded as UTF-8 (`Español.txt`, `emoji_😀.txt`), not cp437
  or `encoding=` mojibake, and a diagnostic records that UTF-8 was inferred for an
  unflagged name

#### Scenario: Legacy bytes without the flag

- **WHEN** an unflagged member name is not valid UTF-8
- **THEN** it is decoded with the caller's `encoding=` when one was passed, else with the
  configured legacy fallback (default cp437), and no bare `UnicodeDecodeError` escapes

#### Scenario: Authoritative signal disables the sniff

- **WHEN** bit 11 is set and the name is valid UTF-8
- **THEN** the name is decoded as UTF-8, with no sniff and no override diagnostic

#### Scenario: A set flag the bytes refute

- **WHEN** bit 11 is set and the name is not valid UTF-8 (`caf\xe9.txt`), from a file or
  from a pipe
- **THEN** the archive lists every member, the name decodes as `cafΘ.txt` (cp437), or
  as `café.txt` under `encoding="cp1252"`, `raw_name` keeps the stored bytes, and
  `MEMBER_NAME_ENCODING_INFERRED` records the codec used with
  `declared_encoding="utf-8"`; `DiagnosticPolicy.STRICT` refuses the archive

#### Scenario: Unicode Path extra field

| Case | Expected |
| --- | --- |
| Unflagged cp866 name `Привет.txt`, central `0x7075` version 1 with a matching CRC | `name == "Привет.txt"`; `raw_name` is its UTF-8 bytes; `extra["alternate_raw_name"]` is the cp866 bytes; no diagnostic |
| The same, `encoding="latin-1"` | The same: the field outranks `encoding=` |
| The field's CRC does not match the stored bytes, or its version is not 1 | Field ignored: cp437 decode (or `encoding=`), `raw_name` is the stored bytes, no `alternate_raw_name` |
| The field in the local header only | Field ignored |
| The field is 0 to 4 bytes long, whatever its first byte, or the CRC matches and the name is empty, not valid UTF-8, or cut short by the end of the extra field | The archive opens on every Python version; field dropped: the name decoded as above, no `alternate_raw_name`, `MEMBER_HEADER_RECORD_SKIPPED` attached to that member only, no Python warning; `DiagnosticPolicy.STRICT` refuses |
| The same malformed field on a name with the UTF-8 flag set | Field not consulted: no diagnostic |

### Requirement: Decode ZIP comments as unflagged names are decoded

APPNOTE puts a member comment under the same bit 11 as its name, and gives the archive
comment no flag. A member comment whose bit 11 is clear or set over a name that is not
valid UTF-8 (a flag the name's bytes refute), and the archive comment, SHALL decode as an
unflagged name does: UTF-8 when the bytes are valid UTF-8, else the caller's
`encoding=`, else `zip_unflagged_fallback_encoding` (default cp437). The `encoding=` and
fallback steps SHALL be the ones a name uses. A byte the chosen codec leaves undefined
SHALL survive as a lone surrogate, as it does in a name. Any other member comment whose
bit 11 is set SHALL decode as UTF-8, with cp437 for bytes that are not valid UTF-8, and
SHALL ignore `encoding=`. A comment is not a name, so decoding it SHALL NOT emit
`MEMBER_NAME_ENCODING_INFERRED`.

An Info-ZIP Unicode Comment extra field (`0x6375`) in the central directory SHALL be read
for a member comment whose bit 11 is clear, by the Unicode Path field's rules: when
the field is version 1, its CRC-32 equals the CRC-32 of the stored comment bytes, and its
text is non-empty valid UTF-8, the comment SHALL be that text, ahead of the sniff and of
`encoding=`, as 7-Zip reads it. A field whose CRC does not match or whose version is not
1 SHALL be ignored. A malformed field (shorter than 5 bytes, or with a matching CRC and
text that is empty, not valid UTF-8 or cut short by the end of the extra field) SHALL be
dropped, the comment decoded as above, and `MEMBER_HEADER_RECORD_SKIPPED` emitted on the
member with `record="unicode_comment"` and `record_id=0x6375`. As for a name, the field
SHALL be consulted only when bit 11 is clear: a comment under a set bit 11, trusted or
refuted by the name, SHALL NOT read it. A field the comment used SHALL NOT appear
in `extra["zip.extra_fields"]`.

#### Scenario: A Unicode Comment field gives the member comment

| Case | Expected |
| --- | --- |
| Comment `caf\x82` (cp437), field version 1 with its CRC and `café ü` | `comment == "café ü"`, with or without `encoding="cp1252"`; no diagnostic |
| The same field with the CRC of other bytes, or version 2 | Field ignored: `comment == "café"` (cp437) |
| Field of 3 bytes, or matching CRC and invalid UTF-8 text | `comment == "café"`; `MEMBER_HEADER_RECORD_SKIPPED`, `record="unicode_comment"`; `DiagnosticPolicy.STRICT` refuses |
| Bit 11 set over a valid UTF-8 name, malformed field | Field not consulted: no diagnostic |
| Bit 11 set over the name `caf\xe9.txt`, which refutes it, good or malformed field | Field not consulted: `comment == "café"`; only the name's `MEMBER_NAME_ENCODING_INFERRED` |

#### Scenario: A flagged member comment ignores `encoding=`

- **WHEN** a member with bit 11 set and a valid UTF-8 name has a comment whose bytes are
  not valid UTF-8, and the archive is opened with `encoding="cp1251"`
- **THEN** the comment is the cp437 reading of the bytes, not the cp1251 one

#### Scenario: A flag the name refutes does not cover the comment

- **WHEN** a member with bit 11 set has the name `caf\xe9.txt` and the comment
  `caf\xe9ine`, and the archive is opened with `encoding="cp1252"`
- **THEN** the name is `café.txt` and the comment `caféine`, both decoded as unflagged
