# RAR Archive Support

## Purpose

Archivey parses RAR metadata natively (RAR 1.5 / 2.x through RAR5) with no
`rarfile` dependency. Listing uses the native parser only (except a compressed
RAR 1.5-4 comment, which the data program decodes); reading compressed or
encrypted member data delegates to the system RARLAB `unrar` binary, or to `unar`
when selected. RAR is
read-only, and `rarfile` is only a test oracle.

This native-metadata/system-decompressor split follows the `archivey-dev`
`rar-native-metadata-reader` exploration. A full native RAR decompressor is out
of scope because RAR compression is proprietary and `unrar` is the reference
implementation.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Read API, multi-source input, passwords, link following, bounded storage |
| `access-mode-and-cost` | Seek requirement, cost receipt, solid access semantics |
| `compressed-streams` | Pass-through stored reads and checksum verification |
| `packaging-and-extras` | RARLAB `unrar` binary and `[recommended]` availability |
| `testing-contract` | Native parser coverage and `rarfile` oracle checks |

## Requirements

### Requirement: Declare RAR format properties

The RAR backend SHALL expose these properties:

| Property | Value |
| --- | --- |
| Read dependency (metadata) | None; native RAR 1.5–RAR5 header parser |
| Read dependency (data) | RARLAB `unrar` or `rar` binary on `PATH` (`unrar` preferred), for compressed members and encrypted members archivey does not decrypt itself; `cryptography` for stored, encrypted members in one part |
| Listing cost | `REQUIRES_SCANNING`: a header walk at open, parsed natively, no member-data decompression. Also with a quick-open record, which saves seeks but not the walk |
| Access cost | `SOLID` for solid archives; `DIRECT` otherwise |
| Supports write | No |
| Requires seek | Yes |

#### Scenario: format property matrix

| Case | Expected |
| --- | --- |
| Open non-header-encrypted RAR without `unrar`/`rar` | Listing and metadata still work through the native parser |
| Read a stored, encrypted member in one part without `unrar`/`rar`, `cryptography` installed | Decrypted and returned by archivey |
| Open from a non-seekable source | Open fails because RAR header parsing requires seek |

### Requirement: Parse RAR headers natively (RAR 1.5 through RAR5)

The system SHALL parse RAR archive headers natively — including RAR 1.5 / 2.x
archives that advertise extract version ≤ 20, RAR3/RAR4, and RAR5 — to produce
the full member list and per-member metadata: names, packed/unpacked sizes,
timestamps, mode, flags, solid state, RAR5 redirect (`file_redir`) records,
encryption flags, and integrity hashes. Listing SHALL not import `rarfile` or
invoke `unrar`. Extract version ≤ 20 MUST NOT by itself cause rejection: those
archives share the same header block layout the parser already understands, and
member data remains RARLAB `unrar`'s responsibility. When a RAR5 MAIN locator
points at a stored, unencrypted `QO` SERVICE, the parser SHALL parse those
FILE copies, seek back to after MAIN, and walk. FILE headers whose offsets
appear in `QO` SHALL be emitted from the copies and skipped; FILE headers
`QO` omitted SHALL still be parsed. `CMT` after MAIN SHALL be consumed as a
normal SERVICE on that walk. A copy whose offset the walk never lands on SHALL NOT
be listed. When the walk ends cleanly, at an end block read whole, and copies are
left unmatched, the `QO` header SHALL report `MEMBER_HEADER_RECORD_SKIPPED` saying
how many, with the listing unchanged; a walk that was cut, stopped at a damaged
header or ended at a damaged end block, or one that did not use `QO`, SHALL NOT
report it. The report SHALL NOT count toward the cap on damaged service headers. Extract SHALL use the
same table. Otherwise the parser SHALL walk FILE headers. A `QO` that is missing,
packed, split,
encrypted, CRC-invalid, or behind header encryption SHALL fall back to the
walk. Only the first MAIN header of a volume SHALL have its locator followed: a
repeated MAIN SHALL still be parsed for its flags, but SHALL NOT read the `QO`
payload again, so the payload is read at most once per volume however many MAIN
headers point at it. A RAR 1.5-4 FILE or SUB header's data area SHALL be skipped by
its PACK_SIZE (with HIGH_PACK_SIZE when set) whether or not LONG_BLOCK is set, as
`unrar` does, so a member's data is never parsed as further headers.

#### Scenario: native header matrix

| Case | Expected |
| --- | --- |
| Open RAR 1.5 / 2.x archive (extract version ≤ 20) | Members and metadata come from native headers; data via `unrar`; no `UnsupportedFeatureError` for extract version alone |
| Open RAR3/RAR4 archive whose members advertise extract version 20 | Listing and reads succeed (stored/small members often carry `unp_ver=20`) |
| Open RAR4 archive | Members and metadata come from native headers |
| Open RAR5 archive | Members, flags, hashes, and redirect metadata come from native headers |
| Open RAR5 with a stored unencrypted `QO` reachable from MAIN's locator | FILE headers in `QO` are emitted from the copies and skipped on the walk; omitted FILE headers and `CMT` after MAIN are parsed |
| Open RAR5 whose `QO` holds a copy no FILE header the walk reaches matches, walk ending at a whole end block | Members listed as the walk finds them; one `MEMBER_HEADER_RECORD_SKIPPED` on the `QO` header with the count |
| Same, but the walk is cut | Members before the cut listed; no unmatched-copy report |
| Same, but a FILE header the walk reads fails its CRC | Members before it listed; no unmatched-copy report |
| Same, but the end block fails its CRC and only zeros follow it | Members listed as the walk finds them; no unmatched-copy report |
| Open RAR5 with no `QO`, locator offset 0, packed/encrypted/`QO` CRC failure, or header encryption | Member table is filled by the FILE-header walk |
| Open RAR5 whose MAIN header is repeated, each copy's locator pointing at one `QO` | The `QO` payload is read once; later MAIN headers are parsed for their flags only |
| Open RAR4 whose FILE header has LONG_BLOCK clear and whose data holds another FILE header | Only the outer member is listed, as `unrar lb` lists it |
| `unrar` missing during listing | Listing succeeds unless header decryption needs unavailable crypto/password |
| Extract version ≤ 20 alone | No `UnsupportedFeatureError` |

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
name with no UTF-16 field is decoded SHALL NOT change which member a read returns: its
`unrar` mask is built from the stored name, not from the decoded text. A RAR 1.5-4
UTF-16 field SHALL decode with `surrogatepass`: a surrogate without its partner stays in
`name` as that code unit, and a valid pair decodes as one character. Extraction writes
such a name by `safe-extraction` "Lone surrogates in a member name". `unrar` matches the
field unit by unit (a valid pair is two units). On POSIX, where the mask goes out as
UTF-8 bytes that cannot carry a surrogate unit, a read through `unrar` SHALL send each
unit as `?` in the mask, and SHALL refuse with `UnsupportedFeatureError` naming `unar`
when a unit is in a directory component. On Windows the mask SHALL carry a valid pair's
units as they are, and a lone unit SHALL be refused naming `unar`, as it is in a RAR5
name.

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
| RAR5 `a\xffq.txt` and `a\xfeq.txt` | Two members, `a\udcffq.txt` and `a\udcfeq.txt`; each reads its own bytes through `unrar`, which reads both names as `a` |
| 8-bit `b\x81.txt` and `b\x8d.txt` written on Unix | `b\udc81.txt` and `b\udc8d.txt` |

### Requirement: Decode RAR 1.5-4 comments in the order names use

A RAR5 comment is UTF-8 by the format and SHALL ignore `encoding=`; a byte that is not
valid UTF-8 SHALL survive as a lone surrogate, as it does in a RAR5 name. A RAR 2.9-4
`CMT` SERVICE header with `SUBHEAD_FLAGS_CMT_UNICODE` set SHALL decode as UTF-16LE, a
surrogate unit without its partner kept as that unit, as in a RAR3 Unicode name. Every
other RAR 1.5-4 comment (an unflagged `CMT` or an old-style COMMENT subblock, each stored
or compressed) records no code page. It SHALL be cut at the first NUL, as `unrar` reads
it, and SHALL decode as strict UTF-8 when the bytes are valid UTF-8, else with the
caller's `encoding=` when one was passed, else as windows-1252. A byte the chosen code
page leaves undefined SHALL survive as a lone surrogate, as it does in a name. The system
MUST NOT decode an 8-bit comment as UTF-16LE. A comment is not a name, so decoding it
SHALL NOT emit `MEMBER_NAME_ENCODING_INFERRED`.

#### Scenario: An undecodable comment byte survives

- **WHEN** an 8-bit comment holds `b"a\x98b"` and the archive is opened with
  `encoding="cp1251"`, which leaves 0x98 undefined
- **THEN** the comment is `"a\udc98b"`, the same string a ZIP comment with those bytes gives

#### Scenario: A RAR5 comment byte that is not UTF-8 survives

- **WHEN** a RAR5 comment holds `b"caf\xe9 \xff ok"` and the archive is opened with
  `encoding="cp1252"`
- **THEN** the comment is `"caf\udce9 \udcff ok"`, never U+FFFD

### Requirement: Accept a non-zero archive start offset (SFX)

The RAR reader SHALL accept an archive whose marker (`Rar!\x1a\x07\x00` for RAR4
or `Rar!\x1a\x07\x01\x00` for RAR5) begins at a non-zero byte offset — whether
supplied as an explicit start offset from detection (`payload_offset`) or
discovered by a bounded forward scan when the marker is absent at the open
position (forced `format=RAR` on an SFX stub).

The forced-format scan bound SHALL be the shared `SFX_MAX` constant (same
binding as the 7z parser and `detect_format`; today 2 MiB). The scan SHALL use
the same hit validator the detector uses. It SHALL return the earliest VALID
match, or if none validate the earliest identified candidate, so a damaged
payload still reaches the parser. After `MAX_VALIDATED_CANDIDATES` (256)
rejected candidates the scan SHALL stop and raise `CorruptionError` naming the
cap. That bound is structural (a real SFX stub does not carry hundreds of
format magics, and the parser has no `DetectionBudget`) and is not a
`ListingLimits` knob. A miss with no candidate SHALL raise `CorruptionError`
naming that there was no match.

Scanning both markers rather than their shared `Rar!\x1a\x07` prefix SHALL
resolve the version by which marker matched first.

Member and header offsets SHALL be relative to the resolved origin. The system
SHALL read in place and SHALL NOT copy the archive to a temporary file solely
to strip a stub.

#### Scenario: RAR SFX / start-offset matrix

| Case | Expected |
| --- | --- |
| Marker at open origin (offset 0) | Unchanged success path; version from the marker read |
| Forced `format=RAR`, marker at N within `SFX_MAX`, header validates | Scan finds N; members listed |
| Forced `format=RAR`, marker at N, header does not validate, no later VALID hit | Scan falls back to N; the parser reports the damage |
| Forced `format=RAR`, decoy magic then a VALID payload within `SFX_MAX` | Earliest VALID wins |
| Forced `format=RAR`, no marker within `SFX_MAX` | `CorruptionError` naming that there was no match |
| Forced `format=RAR`, `MAX_VALIDATED_CANDIDATES` (256) candidates rejected, none VALID | `CorruptionError` naming that the candidate cap was reached |

### Requirement: Bound RAR parser member tables at open

The native RAR header walk SHALL refuse to retain more members than
`listing_limits.max_members` when that field is not `None`, and SHALL raise
`ResourceLimitError` at parse (`open_archive`) when the ceiling is crossed.
`None` (`ListingLimits.UNLIMITED`) disables the bound. The config value is the
bound at parse because the table is built then; there is no separate
parser-constant ceiling. `stream_members()` / `streaming=True` are not an
escape hatch.

RAR has no header-size analogue for member count (the walk is sequential), so
`UNLIMITED` can walk until memory is exhausted. The header walk SHALL also weigh
each member it keeps against `listing_limits.max_metadata_bytes` as it appends
it: the stored name (as `name` and as `raw_name`), a RAR5 redirection target, and
the member's comment (a stored one by its length; a compressed RAR 1.5-4 one by
the larger of its declared unpacked size and its packed bytes, which the listing
holds until the decode), by the weights of `archive-reading`. A RAR 1.5-4 `CMT`
service header attaches its comment to the member before it, after that member was
weighed, so the walk SHALL weigh that comment as it attaches. The running total
is kept per member list, the way `max_members` is: per volume, and again for the
merged list of a volume set, where a split member's later parts merge into its
first and are not weighed again. Crossing the cap SHALL raise `ResourceLimitError`
naming `max_metadata_bytes` at parse (`open_archive`). Compressed RAR 1.5-4
comments expand after the parse: before decoding any, the reader SHALL
weigh every member of the final list again, add the archive comment, and raise
`ResourceLimitError` naming `max_metadata_bytes` at `open_archive` when the sum exceeds
it. It recomputes the total rather than reusing the walk's, which is kept per list. Spine
`ListingLimits` still apply when members are registered into a materialized list.

#### Scenario: RAR parser bound matrix

| Case | Expected |
| --- | --- |
| Hostile or honest archive over `listing_limits.max_members` | `ResourceLimitError` at parse (`open_archive`), including `stream_members()` / `streaming=True` |
| `listing_limits.max_members is None` (`UNLIMITED`) | No member-count bound at parse; a large honest archive opens |
| Default limits, typical archive | Open and listing succeed |
| Compressed RAR 1.5-4 comments (old-style COMMENT subblocks or `CMT` service headers) whose weights (each the larger of its declared unpacked size and its packed bytes) sum past `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive`, before any comment is decoded, including `stream_members()` / `streaming=True` |
| RAR4 or RAR5 archive under `max_members` whose stored names weigh more than `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at parse (`open_archive`), including `stream_members()` / `streaming=True` |
| Volume set whose members are split across volumes, `max_metadata_bytes` at exactly what registration weighs | Opens and lists: a split member's name is weighed once |
| RAR 1.5-4 member whose stored `CMT` comment, attached after the member was weighed, takes the total past `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` from the header walk at parse (`open_archive`); at exactly the total, opens and lists the comment |
| RAR 1.5-4 or RAR5 `CMT` comment the walk reads (its bytes in the file, within the 256 KiB compressed cap, not encrypted or split) whose packed bytes alone are over `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at parse, before its bytes are read |
| Solid compressed `CMT` comments that each declare 1 byte over up to 256 KiB of packed data | Weighed by their packed bytes: `ResourceLimitError` naming `max_metadata_bytes` at parse once their sum passes it |

### Requirement: Expose RAR file-version history members

The system SHALL include RAR file-version history FILE blocks in the member list
instead of omitting them. RAR5 extra type `0x04` (and RAR3 `FILE_VERSION` when
present) identifies a prior revision. History members SHALL use the WinRAR /
`unrar` presented name `path;n` (version `n != 0`), set
`extra["rar.file_version"] = n`, and set `is_current=False`. The live revision of
the same archive path (no version extra, or version 0) SHALL keep the plain path
name and `is_current=True`.

`open` / `read` of a history `FILE` SHALL return that revision’s bytes. For
`unrar`-backed reads the backend SHALL request the exact presented member name
(`path;n`). Solid ALL-pipe demux SHALL pass `unrar`’s `-ver` switch when the
member list contains any versioned payload FILE so the pipe includes history
bytes in archive order; otherwise solid demux MAY omit `-ver`.

Default `extract` / `extract_all` SHALL skip history rows through the existing
`is_current=False` coordinator behavior (`safe-extraction`), recording each as
`ExtractionStatus.SUPERSEDED`. History rows have unique `path;n` presentation
names, so the shared last-entry-wins pass leaves their backend `is_current=False`
untouched. History rows SHALL count toward listing / parser member ceilings like
any other FILE.

#### Scenario: file-version matrix

| Case | Expected |
| --- | --- |
| RAR5 `-ver` archive with revisions 1..k then live path | Members include `path;1`…`path;k` (`is_current=False`) and `path` (`is_current=True`) |
| `read("path;1")` / `open` that member | Bytes of revision 1 |
| `read("path")` | Bytes of the live revision |
| `extract_all` default | Writes live `path` only; history rows `SUPERSEDED` |
| Solid archive that includes versioned payload FILEs | ALL-pipe demux uses `-ver`; stream order stays aligned |
| Nonsolid named `unrar p` of `path;n` | Exact member name; `-ver` not required |
| Hostile archive with many version rows | Rows count toward member caps |

### Requirement: Map RAR method bytes and unpack version

The RAR backend SHALL map the FILE-header method byte as follows:

| Method | `member.compression` |
| --- | --- |
| M0 (`0x30`) | `(CompressionMethod(algo=CompressionAlgorithm.STORED),)` |
| M1–M5 (`0x31`–`0x35`) | `(CompressionMethod(algo=CompressionAlgorithm.RAR, level=<1-5>),)` with `level` = method − `0x30` |
| Any other byte | `(CompressionMethod(algo=CompressionAlgorithm.UNKNOWN),)` — `level` omitted |

Ordinary RAR M1–M5 SHALL map to `CompressionAlgorithm.RAR`, not to any other
algorithm name. An unrecognized method byte SHALL not abort listing.

When the FILE header recorded an unpack version, every member — stored
included — SHALL set `extra["rar.extract_version"]` to that value. RAR3
copies the `UNP_VER` byte as stored, unvalidated. RAR5 members report `50`
(RAR5 records no per-file unpack version).

#### Scenario: RAR compression matrix

| Case | Expected |
| --- | --- |
| Stored member (M0) | `STORED`; `extra["rar.extract_version"]` present |
| Compressed member (M1–M5) | `RAR` with `level` 1–5; `extra["rar.extract_version"]` present |
| Method byte outside M0–M5 | `UNKNOWN`; `level` is `None`; listing succeeds |
| RAR3 FILE `UNP_VER` byte 200 | listing succeeds; `extra["rar.extract_version"]` is 200 |
| RAR5 member | `extra["rar.extract_version"]` is 50 |

### Requirement: Use RARLAB unrar only for member data that needs it

The system SHALL read stored, uncompressed, unencrypted members directly as raw bytes
through the shared pass-through backend, whatever the member's own solid flag says. A
member split across volumes SHALL be read by joining its parts in order. A stored,
encrypted member in one part SHALL be decrypted and read by archivey when
`cryptography` is installed: AES-128-CBC under the key and IV that the password and the
member's 8-byte salt give for RAR 2.9-4 (extract version 29 or later), AES-256-CBC
under the PBKDF2 key and the IV of the member's encryption record for RAR5. The
ciphertext is padded to whole 16-byte blocks; the read SHALL end at the member's
unpacked size and SHALL be checked against its stored digest, a RAR5 tweaked digest
included. The password SHALL be picked as for an `unrar` read: a RAR5 PswCheck rejects a
wrong one with `EncryptionError` before any byte is returned. Without `cryptography`
such a member SHALL be read by the selected program; when that program is missing too,
the `PackageNotInstalledError` SHALL name both `unrar` and `cryptography`. Each part of a
member split across volumes has its own encryption record, so a split encrypted member
is read by the program. All other
member data SHALL be read by invoking a system RARLAB decompressor: `unrar` if a usable
binary is on `PATH`, otherwise `rar`. A usable binary is identified by a RARLAB banner
(`Alexander Roshal` or `RARLAB`, plus a standalone `UNRAR` or `RAR` token that does not
match inside `UNRAR`) whose parsed major.minor is 6.0 or later. If a decompressor is
required and missing or incompatible, the system SHALL raise `PackageNotInstalledError`
naming RARLAB `unrar` or `rar`. Archivey MUST NOT use `unrar-free`, `bsdtar`, `7z`, or a
degraded backend. The spawn SHALL be the `p` (print to stdout) command only. This
requirement applies when `ArchiveyConfig.rar_decompressor` is `unrar`, or `auto` (the
default) with a usable RARLAB binary on `PATH`; `unar` is covered by `Read RAR member
data with unar`.

#### Scenario: unrar dependency matrix

| Case | Expected |
| --- | --- |
| Stored member, `unrar`/`rar` missing | Raw bytes are returned without invoking either |
| Stored member split across volumes, `unrar`/`rar` missing | Its parts are joined and returned, checked against the member's checksum |
| Stored member carrying its own solid flag (`rar -s -ms<ext>`), `unrar`/`rar` missing | Raw bytes are returned without invoking either |
| Stored, encrypted RAR 2.9-4 or RAR5 member in one part, `cryptography` installed | Decrypted by archivey, byte-identical to `unrar p`, seekable with `seekable_members=True`; no process starts |
| Same, RAR5, wrong password | `EncryptionError` from the PswCheck before any byte |
| Same, RAR 2.9-4, wrong password | Bytes end in a CRC mismatch (`CorruptionError`), as through `unrar`; an abandoned read emits `ENCRYPTED_MEMBER_UNVERIFIED` |
| Same, `cryptography` missing, `unrar` present | `unrar` reads it |
| Same, `cryptography` and `unrar` both missing | `PackageNotInstalledError` names `unrar` and `cryptography` |
| Stored, encrypted member split across volumes | Read by the program |
| Compressed member, both missing, and no `unar` (or `rar_decompressor="unrar"`) | `PackageNotInstalledError` names `unrar` or `rar` |
| PATH `unrar` is not RARLAB `unrar`, and no usable `rar` | `PackageNotInstalledError` names RARLAB `unrar` or `rar` |
| RARLAB `unrar` older than 6.0 and no usable `rar`, or a RARLAB banner with no parseable version | `PackageNotInstalledError` names the floor and the version found; refused at identification |
| RARLAB `rar` 6.0+ on `PATH`, `unrar` missing | Used for compressed member data and encrypted data archivey does not decrypt; spawn is `rar p` |
| RARLAB `unrar` 6.0+ and RARLAB `rar` both on `PATH` | `unrar` is used |
| Listing only, both missing | No data dependency is checked |
| Listing only, both missing, archive has a compressed RAR 1.5-4 comment | The comment is `None`; nothing else depends on a data program |

### Requirement: Constrain unrar argv by call site

The system SHALL invoke RARLAB `unrar` with member path arguments only as follows:

| Call site | Member path args after the archive |
| --- | --- |
| Solid `stream_members()` / solid `_iter_with_data` | none (unnamed `unrar p -inul <archive>`) |
| `_open_member` for a FILE member | exactly one archive-relative member path |
| Stored M0 unencrypted member | `unrar` not invoked |
| Stored M0 encrypted member in one part, `cryptography` installed | `unrar` not invoked |

The system MUST NOT pass multiple member paths, globs, or `@listfile` filters in this
capability’s initial implementation. Hardlink / file-copy members are never named on the
`unrar` command line; the shared link-following layer opens a hardlink's target FILE,
and the RAR reader opens a file copy's source FILE.

#### Scenario: unrar argv matrix

| Case | Expected |
| --- | --- |
| Solid full or filtered `stream_members()` | One `unrar p` with no member path args |
| Nonsolid `open()` / lazy stream of a FILE | `unrar p … <archive> <member>` |
| `open()` on hardlink / `FILE_COPY` | `unrar` receives the target (source) FILE path only, or equivalent target open |
| Symlink member | No `unrar` data read for the link payload |

### Requirement: Stream solid RAR archives through one unrar pipe

For solid-archive `stream_members()`, the system SHALL run one
`unrar p -inul <archive>` subprocess **with no member path arguments** and
demultiplex stdout into per-member streams using the unpacked sizes of
**payload FILE members only** (members whose content `unrar p` emits).
Symlinks, hardlinks, file-copies, and directories MUST NOT consume pipe bytes
even when native headers advertise a non-zero size. Demultiplexing SHALL use
`SolidBlockReader` (or equivalent forward-only slicing). The system SHALL
validate each payload member's CRC32 or Blake2sp hash incrementally via the
shared verification stage. This path MUST process the archive once, not spawn
one subprocess per member.

#### Scenario: solid streaming matrix

| Case | Expected |
| --- | --- |
| `stream_members()` on a solid RAR | Exactly one unnamed `unrar p` process |
| Solid archive with symlinks / hardlinks | Pipe length equals Σ payload FILE sizes only; link members yield `stream is None` |
| Member has CRC32/Blake2sp | Verification runs as bytes are read and raises on mismatch |
| A later member is selected in the same pass | Earlier payload bytes are drained through the single pipe, not separate member subprocesses |
| Filtered `stream_members(selector)` | Still one unnamed `unrar p`; unselected payload tails are skipped via the shared iterator close/`SolidBlockReader` lazy skip |

### Requirement: Serve random access and extraction with bounded explicit temp use

The system SHALL serve non-solid random reads by invoking `unrar` for the target
member **with that member's path as the sole path argument**, doing
O(member_size) data work. For solid random reads, the system SHALL decode from
archive start to the target member (named `unrar p … <member>`). Each such read
is its own decode: the reader SHALL NOT amortize repeated solid reads by
extracting members into a temporary directory and serving later reads from disk.
`extract_all()` SHALL be served by the same `stream_members()` pass as any other
caller, plus a second `stream_members()` pass when a selected hardlink's source
was excluded and has to be re-read; on a solid archive each pass is one unnamed
`unrar p` addressed at the whole archive, decoding only as far as the last
member it needs. Which members a pass names on the `unrar` command line — and
which need no spawn at all — is governed by `Constrain unrar argv by call site`.
Any temp materialization SHALL be a declared RAR strategy, not an implicit
in-memory buffer; the only one the reader implements is copying a non-path
archive *source* to disk so `unrar` can seek it, the deferred small-member
optimization being the other strategy this capability declares.

A non-path stream source SHALL NOT be copied to disk at open. Both stream shapes —
a single stream and an ordered set of stream volumes — SHALL defer the copy to the
first member read that `unrar` has to serve, and a caller that only lists SHALL
write nothing. An `open()` the reader refuses before spawning `unrar` — a name it
cannot address through an include mask, or one whose mask would pull in earlier
members — is not such a read and SHALL write nothing either. Listing SHALL be served from the source the caller supplied; for a
volume set the reader SHALL read each volume as its own bounded view over that
source rather than reopening or copying it.

When the copy does happen for a volume set it SHALL write the whole set, because
`unrar` resolves sibling volumes by name. The copies SHALL be named in the set's own
scheme: `name.partN.rar`, or `name.rar`, `name.r00`, … for a RAR 1.5-2.x set whose
main header lacks the new-numbering flag, because `unar` looks for the next volume
only under that scheme.

The copy SHALL be bounded by `ArchiveyConfig.spool_limits` (`archive-reading`), measured
across the whole volume set, file volumes of a mixed set included. The archive size is
known before the copy, so an archive over `SpoolLimits.max_bytes` SHALL raise
`ResourceLimitError` before any byte is written and before
`unrar` is spawned. Where the size is not known up front, the copy SHALL stop before its
total passes the limit and SHALL remove what it wrote. The limit SHALL hold for the
reader, not for each attempt: once a copy has been refused, a later read that needs it
SHALL raise the same refusal without writing again. With `max_bytes=0` a member that
cannot be read directly SHALL be refused, and a member that can SHALL still read.

When the archive is opened from a non-path stream source, `ar.cost.notes` SHALL
include a human-readable disk-copy caveat **at open** (path sources SHALL NOT, except
the prefixed file that `Read RAR member data with unar` copies): a single stream source
SHALL warn that reading a member the program has to read (such as a compressed one)
will copy the whole archive to disk; ordered stream volumes SHALL warn that reading
such a member will copy every volume to a temp directory. The caveat SHALL name the
spool limit in force (or say there is none), so the caller reads the worst case at
open. When the limit already rules the copy out — `max_bytes=0`, or a copy whose size
is known at open and is over the limit — the caveat SHALL say that such a read will be
refused, in place of the copy warning. The note is a
static open-time caveat, not an occurrence log:
it SHALL be present even if only stored members are read, and SHALL NOT appear
after materialization if it was absent at open. Mixed-password
nonsolid archives MUST NOT demultiplex one unnamed `unrar p` ALL pipe against the
full member list (wrong-password members are omitted from stdout and would
desynchronize sizes).

#### Scenario: random/extract matrix

| Case | Expected |
| --- | --- |
| Random `open()` in non-solid RAR | `unrar p … <archive> <member>`; work is O(member_size) |
| Repeated random opens in solid RAR | Each open is its own `unrar p` decode from archive start; no tempdir cache, and the re-decode is reported as `RewindWarning.min_redecode_bytes` |
| `extract_all()` | The same `stream_members()` pass as any other caller, plus a second pass when a selected hardlink's source was excluded and must be re-read; no `unrar x` |
| Mixed-password nonsolid stream/open | Per-member named `unrar` (or equivalent); no ALL-pipe demux |
| Single non-path stream, at open | `ar.cost.notes` warns a read the program serves (such as a compressed one) will copy to disk and names the spool limit; nothing is written yet |
| Ordered stream volumes, at open | `ar.cost.notes` warns a read the program serves will copy every volume and names the spool limit; nothing is written yet |
| Stream source at open, `max_bytes=0` or a known size over the limit | `ar.cost.notes` says a read the program serves will be refused and promises no copy |
| Ordered stream volumes, listing only | No temp directory is created |
| Solid `stream_members()` pass, no member read | Nothing is written, even from a stream source |
| Ordered stream volumes, first compressed read | The whole set is written once; later reads reuse it; close removes it |
| Stream source over `SpoolLimits.max_bytes` | `ResourceLimitError` naming the field; no temp file or directory; no `unrar` spawn |
| Volume set, each volume within the limit, total over it | `ResourceLimitError`; the limit weighs the total |
| Stream source of unknown size refused mid-copy, then another compressed read | The same refusal, with no second temp file |
| Stream source, `max_bytes=0` | Stored members read, unencrypted or decrypted by archivey; a member needing `unrar` is refused |
| `open()` on a directory-flagged header that declares data | Stored, unencrypted data is sliced by archivey and delivered; compressed or encrypted directory data raises `UnsupportedFeatureError` (`unrar p` emits nothing for a directory entry), never a spawn |
| `stream_members()` over the same header, solid or not | The stream yielded for the directory delivers what `open()` delivers, sliced from the archive and outside the `unrar p` pipe (it takes no offset there), or raises the same `UnsupportedFeatureError` on its first read |
| Stream source, `open()` refused before any spawn | Nothing is written; the refusal raises without materializing |
| Path source | `ar.cost.notes` has no disk-copy caveat (under `unrar`); the spool limit never refuses it |
| Prefixed path source under `unar`, copy over `SpoolLimits.max_bytes` | `ar.cost.notes` says a compressed read will be refused; the read raises `ResourceLimitError` naming `rar_decompressor='unrar'`; no temp file |

### Requirement: Support benchmark-gated small-member optimization

The reader SHALL allow an optional small-member optimization only when
benchmarks justify it. The optimization MAY build a temporary single-file RAR
containing the requested member and invoke `unrar` on that smaller archive when
the member is below a benchmark-derived threshold. Output MUST be byte-identical
to the direct `unrar` path. This optimization is **deferred**: the initial
native RAR reader MUST NOT implement it.

#### Scenario: small-member optimization matrix

| Case | Expected |
| --- | --- |
| Initial native RAR reader | Extract-hack / temp single-file RAR path is not used |
| Future enablement after benchmarks | Bytes match direct `unrar`; measured overhead is lower |
| Benchmark does not justify the threshold | Optimization is not used |

### Requirement: Report RAR cost and version-specific metadata

The system SHALL treat RAR solidity as a binary archive-level property because
RAR exposes no per-solid-block boundaries. `ArchiveInfo.is_solid` reflects the
native solid flag and `CostReceipt.solid_block_count` SHALL be `None`. Timestamp
mapping SHALL preserve RAR version semantics for `modified`, `accessed`, and
`created`: RAR4 local wall-clock timestamps become naive `datetime` values, and
RAR5 UTC/sub-second timestamps become timezone-aware UTC `datetime` values.
`accessed` and `created` come from the RAR5 `0x03` time extra (`HAS_ATIME` /
`HAS_CTIME`) or RAR3 EXTTIME; they SHALL be `None` when that extra or slot is
absent. `created` SHALL carry the creation slot only when `host_os` names a
birth-time host (Win32, or RAR3 MS-DOS / OS2 / Mac / BeOS); for a Unix host
(`host_os == 3`) or an unknown one it SHALL be `None` and `ctime` SHALL carry the
slot instead: a Unix RARLAB writer
stores `st_ctime` (inode change) in the creation slot, and `created` never
holds `st_ctime`. RAR5 Blake2sp-only members SHALL store the
digest bytes at `member.hashes["blake2sp"]` and omit `"crc32"`.

A RAR5 owner record (`rar -ow`) SHALL fill `uname`, `gname`, `uid` and `gid`, each
only when the record's flags announce it. A RAR 1.5-4 `UOW` service header SHALL fill
`uname` and `gname` of the file it follows. With no owner record all four SHALL be
`None`. A record too short for what its flags announce SHALL be dropped like any other
malformed optional record (`MEMBER_HEADER_RECORD_SKIPPED`). A `UOW` header whose data
holds no NUL SHALL give no owner and SHALL be reported the same way, once, on the file it
follows, unless another `UOW` header after that file names an owner; one with no file
before it SHALL be ignored.

A **RAR5 redirect** member — symlink, hard link, or file copy — SHALL surface **no**
stored digest. Such a member keeps its target in a header field and stores no data
stream, so its CRC32 field covers zero bytes and RARLAB writes `crc32(b"") == 0`. That
value is correct about nothing: it does not describe the member (`size` is the target's
length while the digest covers no bytes) and is identical for every redirect member in
every archive. Surfacing it would make `member.hashes` mean something different in RAR
than in every other format, and the value it would carry is the one a de-duplicating
caller reads.

**RAR3/4 is the opposite and is unaffected**: it stores a symlink's target *as the
member's data*, so the stored CRC32 is a genuine digest of the target string — the same
thing ZIP and 7z record. The rule therefore keys on the RAR5 redirect, never on the
member type.

#### Scenario: metadata matrix

| Case | Expected |
| --- | --- |
| Solid RAR | `ArchiveInfo.is_solid` true; `solid_block_count is None` |
| RAR4 timestamp | `ArchiveMember.modified` is naive local wall-clock time |
| RAR5 timestamp | `ArchiveMember.modified` is timezone-aware UTC |
| RAR5 `-tsmca` archive | `modified` / `accessed` / `ctime` are timezone-aware UTC |
| RAR4 `-tsmca` archive | `modified` / `accessed` / `ctime` are naive local wall-clock |
| mtime-only archive (no atime/ctime extra) | `accessed` / `created` / `ctime` are `None`; `modified` populated |
| Unix-written member with a creation slot | `created is None`; `ctime` holds the slot |
| Win32-written member with a creation slot | `created` holds the slot; `ctime is None` |
| Member with an unknown `host_os` | `created is None`; `ctime` holds the slot when present |
| RAR5 member with Blake2sp only | `"blake2sp"` present as bytes; `"crc32"` absent |
| RAR5 symlink / hard link / file copy | `member.hashes` empty — never `crc32 == 0` |
| RAR4 symlink (target stored as data) | `"crc32"` present, equal to the target string's CRC32 |
| RAR5 `-ow` member whose owner has names | `uname` / `gname` set; `uid` / `gid` `None` |
| RAR5 `-ow` member whose ids have no names | `uid` / `gid` set; `uname` / `gname` `None` |
| RAR4 `-ow` member (`UOW` header after it) | `uname` / `gname` set; `uid` / `gid` `None` |

### Requirement: Handle RAR5 redirect link types natively

The system SHALL read RAR5 link semantics from native `file_redir` metadata. Hardlinks
(`RAR5_XREDIR_HARD_LINK`) SHALL be exposed as `MemberType.HARDLINK` with `link_target`
set from the redirect, so `ArchiveReader` link following returns the target FILE's
data. A RAR hardlink SHALL resolve only to a member before it, in random access as in
a streaming pass, as `unrar` extracts it from what it has already written. A hardlink
whose only same-named member comes after it has no `link_target_member`; opening it
raises `LinkTargetNotFoundError`. File copies (`RAR5_XREDIR_FILE_COPY`, `rar -oi`)
SHALL be exposed as `MemberType.FILE` with `extra["is_file_copy"] == True`,
`link_target` set to the stored source path and `link_target_member` set to the
source: the latest earlier `FILE` member that path names. A path that `..`-escapes the
archive root names no source: extraction writes a copy from its source's bytes under
the copy's own name, and does not refuse a copy of a refused member as it refuses a
hard link. Reading a copy SHALL return the source's bytes, and extraction SHALL write
it as an independent file, as `unrar` does. A copy with no such source SHALL raise
`LinkTargetNotFoundError` when read. Unix symlinks and Windows symlinks/junctions
(`RAR5_XREDIR_UNIX_SYMLINK`, `RAR5_XREDIR_WINDOWS_SYMLINK`,
`RAR5_XREDIR_WINDOWS_JUNCTION`) SHALL be exposed as `MemberType.SYMLINK` with
`link_target` from the redirect and resolved by the format-independent link-following
layer. The target of a Windows symlink or junction SHALL be normalized as a ZIP or 7z
reparse buffer's is: `\` becomes `/`, a leading `\??\` or `/??/` is dropped, and
`UNC\` after it becomes `//`. A Unix symlink's target SHALL be kept as stored.
Redirect members MUST NOT appear in the solid `unrar p` demux size map.

#### Scenario: redirect matrix

| Case | Expected |
| --- | --- |
| RAR5 hardlink `open()` | Follows to target FILE data |
| RAR5 `FILE_COPY` | `type=FILE`, `extra["is_file_copy"]`; `open()`, `stream_members()` and extraction give the source's bytes; extracted as an independent file |
| RAR5 Unix/Windows symlink `open()` | Link following resolves target; symlink itself has no `unrar p` payload |
| Solid stream past a redirect member | Demux does not advance the pipe for that member |

### Requirement: Resolve RAR link targets when possible at list time

The system SHALL set `ArchiveMember.link_target` during member registration /
`_ensure_link_target` whenever the target is available without interactive input,
except an encrypted RAR 2.9-4 target (below), which uses the password, and so the
password provider, that a read of the member would use:

| Variant | Source of `link_target` |
| --- | --- |
| RAR5 symlink | native `file_redir` target string |
| RAR5 Windows symlink / junction | native `file_redir` target string, normalized as a reparse buffer's (`\??\C:\Windows` → `C:/Windows`, `..\up\x` → `../up/x`) |
| RAR5 hardlink / `FILE_COPY` | native `file_redir` target string (`MemberType.HARDLINK` / `MemberType.FILE`) |
| RAR4 Unix symlink | stored member bytes (direct read when M0 / readable without `unrar`), only while `read_link_targets` is `True` |

A RAR 2.9-4 symlink whose stored target is encrypted SHALL be decrypted at listing as
its member read would be (stored, in one part, `cryptography` installed), and its target
set when the password decrypts it to bytes its CRC32 matches. Without a password the
target SHALL stay unset with `SYMLINK_TARGET_UNAVAILABLE` (`reason="password_required"`);
a password that fails the CRC SHALL leave it unset with `reason="password_or_damage"`,
since RAR 2.9-4 records no password check and a wrong key looks like damage. A target
archivey cannot decrypt itself (compressed, split, RAR 2.0's cipher, or no
`cryptography`) SHALL stay unset with `reason="target_data_encrypted"`. Listing MUST
still succeed in every case. With
`read_link_targets=False`, listing reads no RAR4 member bytes for a link target and emits
nothing for it; RAR5 `file_redir` targets are set as before (`archive-reading`, "Link
targets stored as member data are read only when configured").

#### Scenario: link-target resolution matrix

| Case | Expected |
| --- | --- |
| RAR5 symlink | `type=SYMLINK`, `link_target` set from `file_redir` |
| RAR5 hardlink | `type=HARDLINK`, `link_target` set; `open()` follows to target data |
| RAR5 `FILE_COPY` | `type=FILE`, `link_target` and `link_target_member` name the source; `open()` reads the source's data |
| RAR4 stored symlink | `link_target` equals stored target bytes decoded as text |
| Encrypted stored RAR4 symlink, right password (one, or in a list) | `link_target` set; no program started |
| Encrypted stored RAR4 symlink, no password | `link_target=None`; `reason="password_required"`; listing succeeds |
| Encrypted stored RAR4 symlink, wrong password (one, or a list whose every entry fails) | `link_target=None`; `reason="password_or_damage"`; listing succeeds |
| Encrypted stored RAR4 symlink, no `cryptography` | `link_target=None`; `reason="target_data_encrypted"` |
| RAR4 stored symlink, `read_link_targets=False` | `link_target=None`; no member bytes read; RAR5 targets still set |

### Requirement: Decrypt RAR5 header-encrypted archives natively

The system SHALL decrypt RAR5 header-encrypted archives through the optional
crypto backend when a valid password is supplied. The native parser derives the
AES key and decrypts headers itself; `unrar` is not required for listing and
remains required only for member data. Header-encrypted listing without a
password SHALL raise `EncryptionError`; with a password but no `cryptography`
backend (`[recommended]`), it SHALL raise `PackageNotInstalledError`. Any encrypted RAR
SHALL set `ArchiveInfo.is_encrypted` to `True`.

#### Scenario: header encryption matrix

| Case | Expected |
| --- | --- |
| Header-encrypted RAR5, no password | `EncryptionError` |
| Header-encrypted RAR5, password but no crypto backend | `PackageNotInstalledError` |
| Header-encrypted RAR5, valid password + crypto | Headers decrypt natively; members list; `is_encrypted` true |
| Read member data from that archive | `unrar` is still required |

### Requirement: Reject unsupported RAR variants clearly

Multi-volume RAR sets SHALL be supported by the volume contract, not rejected as
an unsupported variant. A later volume opened as a stream, with nothing to number
it, SHALL raise `UnsupportedFeatureError` (or a truncated/out-of-order error) rather
than silently mis-joining members; one opened by path is numbered by its name and
read as a set with volumes missing (below). Legacy RAR 1.5 / 2.x archives MUST NOT be
rejected solely for extract version ≤ 20. Truly unreadable layouts (corrupt
headers, unknown required crypto without the extra) continue to raise typed
errors from their existing requirements.

A member compressed with a version `unrar` 7.00 does not decode SHALL list normally and
SHALL raise `UnsupportedFeatureError` when its data is read, before any decompressor
runs, with either decompressor and in a solid pass. The versions it decodes are RAR5
compression-info versions 0 and 1 and RAR 1.5-4 `UNP_VER` 13 to 29; outside them
`unrar` reports "Unknown method" and writes nothing, which is not a truncation. A stored
member reads whatever version it declares, as in `unrar`. A later compressed member of
the same solid stream (by the members' solid flags) SHALL raise `UnsupportedFeatureError`
naming the unknown member, in the same way and with either decompressor, since decoding it
means decoding that member first. With `unrar`, in an archive whose main header has the
solid bit, every later member that `unrar` would decode SHALL raise it too, a later solid
stream included: archivey addresses a member through an include mask, and with one
`unrar` decodes the archive from its start. That message SHALL say so, and SHALL NOT
say the archive needs the unknown member decoded. With `unar`, which reads a later stream
on its own, a member of a later stream SHALL be read.

#### Scenario: unsupported variant matrix

| Case | Expected |
| --- | --- |
| Multi-volume RAR4/RAR5 set is opened from volume 1 | Handled by the multi-volume requirement |
| Multi-volume set opened from a later volume, by path | Same listing as from volume 1 |
| Lone later volume opened as a stream | `UnsupportedFeatureError` or truncated/out-of-order error |
| RAR 1.5 / 2.x archive is opened | Listing succeeds; not rejected for extract version |
| Compressed RAR5 member with compression-info version 2 or more | Listing succeeds; read raises `UnsupportedFeatureError` |
| Compressed RAR 1.5-4 member with `UNP_VER` below 13 or above 29 | Listing succeeds; read raises `UnsupportedFeatureError` |
| Stored member declaring an unknown version | Reads normally |
| Solid archive, compressed member after one with an unknown version, same solid stream | Read raises `UnsupportedFeatureError` naming that member, with either decompressor |
| Solid archive, member of a later solid stream after one with an unknown version | `unrar`: read raises `UnsupportedFeatureError` naming that member and the include mask; `unar`: reads normally |

### Requirement: Support multi-volume RAR sets

The system SHALL support multi-volume RAR archives named `name.partN.rar`
(RAR5/newer RAR4), including an SFX first volume named `name.partN.sfx` or
`name.partN.exe` beside later `.partN.rar` parts, or `name.rar` + `name.r00`,
`name.r01`, ... (older RAR4), including an old-scheme SFX first volume named
`name.exe` or `name.sfx` beside those parts (prefer `.rar` when more than
one first-volume name exists). The native parser SHALL read volume headers in
order and stitch members that span
volume boundaries into one logical member using continuation flags.
`open_archive()` SHALL accept either a path inside the set, with sibling
discovery in order, or an explicit ordered source sequence, which SHALL be used as
given with no discovery. For a path inside the set, data reads point `unrar` at the
first volume so it can find later volumes. An explicit sequence of paths that `unrar`
would not find by name beside the first SHALL be linked into a temporary directory
under the set's own names (copied within `SpoolLimits` only where the filesystem
refuses a link) on the first data read that needs it. For
stream sources, data reads SHALL materialize ordered volumes for `unrar` when
needed. Out-of-order volumes SHALL raise `UnsupportedFeatureError` or a truncated
error instead of a partial result. A set with volumes missing, at its start, in the
middle or at its end, SHALL list the members of the volumes present and then raise
`TruncatedError` (the requirement below). A later volume is one whose RAR5 MAIN or RAR
3.0+ end block records a volume number above 0, or whose first member continues an
earlier volume; a RAR 1.5 / 2.x volume records neither, so one whose first member starts
on its boundary reads as volume 1, as in `unrar`.

#### Scenario: volume matrix

| Case | Expected |
| --- | --- |
| Open `name.part1.rar` with complete siblings | Headers across all volumes parse as one archive |
| Open `name.part1.sfx` with later `name.partN.rar` siblings | Same as partN: `.sfx` (or `.exe`) is volume 1; one logical archive |
| Open `name.rar` with `name.r00` / `name.r01` siblings | Same as partN: one logical archive; member data spans volumes |
| Open `name.exe` (or `name.sfx`) with `name.r00` siblings | Same as `.rar` + `.r00`: the SFX file is volume 1 |
| Read a member spanning volumes | Returned stream reassembles the member across boundaries |
| Open explicit ordered stream volumes | Metadata parses in order; data reads materialize volumes for `unrar` if needed |
| Out-of-order volume | Error instead of partial or garbled output |
| Missing volume (first, middle or last) | Members of the volumes present listed, then `TruncatedError` |

### Requirement: A set with volumes missing SHALL list what it has, then raise

A volume is missing when the last volume read says another follows (a member continues
into it, or the end block's next-volume flag) and none is supplied or discovered, or
when discovery numbers the volumes present by name and a number is absent: volume 1, or
one in the middle. The reader SHALL list every member whose header is in the volumes
present, opened from any of them, and then raise `TruncatedError` naming the missing
volumes, the same "list, then raise" channel as a file cut inside a header. Members
wholly inside the present volumes SHALL read normally, with either decompressor. A
member whose data runs into or out of a missing volume SHALL raise `TruncatedError` when
read, before any decompressor runs; nothing SHALL be joined across a gap. In a solid
archive every member past a missing volume SHALL raise `TruncatedError` too, since its
data depends on the solid stream through it. `extract_all` SHALL write the members it
can and raise at the first that cannot. This matches `unrar` 7.00: from before a gap,
`t` passes every complete member and stops at the gap with "Cannot find volume"; from
after it, it skips the member continued from the gap ("You need to start extraction
from a previous volume") and tests the rest. A lone volume 1, as a stream or a path, is
such a set, and so is a lone later volume opened by path. Archive-level data only
volume 1 carries (the archive comment, an SFX stub) is absent when volume 1 is.

#### Scenario: Missing middle or first volume

- **GIVEN** a five-volume RAR5 set of stored members with volume 3, or volume 1, deleted
- **WHEN** it is opened from any volume present
- **THEN** the listing SHALL be the same from each, every member with a header in a
  present volume, and SHALL end with `TruncatedError` naming the missing volume
- **AND** every member wholly inside present volumes SHALL read back its original
  bytes, and each member with data in the missing volume SHALL raise `TruncatedError`

#### Scenario: Missing last volume

- **GIVEN** a four-volume RAR5 set, stored or solid-compressed, with its fourth volume
  deleted
- **WHEN** it is opened from its first volume
- **THEN** `members_report()` SHALL list the members whose headers are in volumes 1-3,
  with `error` a `TruncatedError` naming volume 4 as missing, and `members()` SHALL
  raise it
- **AND** every member but the last listed SHALL read back its original bytes, and the
  last listed SHALL raise `TruncatedError` when read

### Requirement: A malformed optional RAR5 extra record SHALL NOT refuse the archive

The RAR5 extra area of a FILE header is a list of optional records, placed by its
declared size: it is the header's last `extra_size` bytes, as `unrar` reads it, whatever
lies between the end of the name and that point. Bytes in between SHALL be skipped, as
`unrar` skips them, and SHALL be reported as `MEMBER_HEADER_RECORD_SKIPPED`: no writer
leaves them, so they mean a damaged or crafted header. An extra size not smaller than the
whole header, its CRC and size field included, SHALL raise `CorruptionError` (`unrar`:
"Corrupt header"). An area that would
overlap the fields already read SHALL be left unread, as `unrar` ignores it, and the
member SHALL be reported as having had its header cut short (below). The reader already
ignores a record whose type it does not recognise. A record whose type it *does*
recognise but whose body it cannot parse SHALL be treated the same way: the record is
dropped, the member is listed, and the walk continues with the next record.

CRC-32 on the enclosing header is an integrity check, not an authenticity one. A
well-formed extra still drops only the one malformed record; a crafted extra that
CRC-matches can produce one skip per byte, which is why the walk is capped below.

A dropped record SHALL leave the field it would have populated **absent, never wrong**.
Each record's parse SHALL commit its value only once every byte it needs has been read,
so a failure part-way through cannot leave a half-written timestamp, redirect or digest
behind.

Dropping a record SHALL NOT be silent: the reader SHALL emit
`MEMBER_HEADER_RECORD_SKIPPED` (see `diagnostics`) naming the member, the record and the
parse failure, attached to the member. Because that code is in `ARCHIVE_INTEGRITY_CODES`,
a caller who wants the archive refused instead SHALL get that from
`DiagnosticPolicy.STRICT`.

A crafted extra area SHALL NOT retain one skipped record per attacker byte, nor cost one
parse per attacker byte. The number of dropped records retained per member is a structural
cap (a handful of extras is every well-formed FILE; more cannot be useful diagnostics).
After the cap the extra-area walk for that member stops, and stopping SHALL be reported: a
caller SHALL be able to tell a member whose records were all read from one whose header
was abandoned part-way, because how far to trust that member's metadata turns on it.

The line SHALL fall between a record's *framing* and its *body*, because that is where the
information is. A body the reader cannot parse costs one record and leaves the next
record's offset known, so the walk continues. A size vint the reader cannot use costs every
later record, so the walk stops and reports that it stopped. A size is unusable when it
cannot be read at all, when it runs past the header, or when it is below the minimum a
record can have: a record's body opens with its type vint, so **one byte is the smallest
legal record** — a type with no payload, which is what an unimplemented record looks like —
and a declared size of zero names nothing while still advancing the cursor, which is what
made one attacker byte cost one retained record.

`unrar` 7.00 does continue past a zero-size record, and is wrong for it: one such record in
front of an encrypted member's records makes `unrar l` lose both the encryption record and
the timestamp and list the member as plaintext. The oracle that justifies the leniency
above SHALL NOT be read as justifying this.

#### Scenario: The extra area is placed by its declared size

- **GIVEN** a RAR5 FILE header with a redirect record between its name and its declared
  extra area
- **WHEN** the archive is listed
- **THEN** the member SHALL list as a plain file, not as a link, as in `unrar`
- **AND** the member SHALL carry `MEMBER_HEADER_RECORD_SKIPPED` for the skipped bytes
- **AND** a header whose declared extra size is at least the whole header's size SHALL
  raise `CorruptionError`, and one byte less SHALL list the member

#### Scenario: A record whose size cannot be used stops the walk

- **GIVEN** a RAR5 FILE extra area whose first record declares a size of zero, or a size
  larger than what remains of the header, or whose size vint has no terminating byte, with
  a valid enclosing header CRC
- **WHEN** the archive is listed under the default diagnostic policy
- **THEN** the walk SHALL stop at that record rather than trying to resynchronise
- **AND** the member SHALL be reported as having had its header cut short, not listed as
  though its extra area had been read to the end

#### Scenario: A record whose body cannot name its type is dropped, not fatal

- **GIVEN** a RAR5 FILE extra record declaring a one-byte body that holds only a vint
  continuation byte, sitting in front of the member's `FHEXTRA_CRYPT` record
- **WHEN** the archive is listed under the default diagnostic policy
- **THEN** the member SHALL be listed with one `MEMBER_HEADER_RECORD_SKIPPED`
- **AND** the member SHALL still be reported as encrypted, because the record's size is
  usable and the walk goes on to reach the encryption record
- **AND** nothing SHALL report the header as cut short

#### Scenario: A one-byte-short checksum record lists the member without a digest

- **GIVEN** a RAR5 archive whose BLAKE2sp extra record declares a size too small for the
  32-byte digest it contains, with a valid enclosing header CRC
- **WHEN** the archive is listed under the default diagnostic policy
- **THEN** the member SHALL be listed
- **AND** its BLAKE2sp hash SHALL be absent rather than a truncated or guessed value
- **AND** exactly one `MEMBER_HEADER_RECORD_SKIPPED` SHALL be attached to that member,
  with `record="hash"` and the record's numeric type
- **AND** `unrar` lists the same archive, which is why refusing it was wrong

#### Scenario: An unrecognised record type stays silent

- **WHEN** the extra area carries a record whose type the reader does not implement
- **THEN** the member SHALL be listed and **no** diagnostic SHALL be emitted
- **AND** this leniency SHALL NOT turn the pre-existing tolerance for unknown records
  into a diagnostic, or every archive written by a newer RAR would report one

#### Scenario: A zero-filled extra area does not retain one skip per byte

- **GIVEN** a RAR5 FILE extra area filled with zero bytes and a valid enclosing header CRC
- **WHEN** the archive is listed under the default diagnostic policy
- **THEN** the member SHALL be listed
- **AND** the number of `MEMBER_HEADER_RECORD_SKIPPED` diagnostics attached to it SHALL
  be at most the structural skip cap
- **AND** this cap exists because `xsize == 0` is one attacker byte per skip, which
  `max_members` cannot see
- **AND** exactly one of those diagnostics SHALL report that the walk stopped with the
  extra area unread, distinguishing it from a member whose records were all read

### Requirement: A malformed RAR5 encryption record SHALL remain fatal

The `FHEXTRA_CRYPT` record is the sole exception to the rule above. Dropping it would
leave the member's encryption parameters unset, and a member with no encryption
parameters is presented as plaintext. That is a *wrong* answer rather than a missing one,
and this library treats silently wrong metadata as its worst failure class.

A member whose encryption record cannot be parsed SHALL therefore raise, as it does
today. It SHALL NOT be listed as unencrypted, and it SHALL NOT be listed as encrypted
with absent parameters.

A member whose extra-area walk stopped before the end of the area SHALL be reported as
**encrypted**, whether or not an encryption record was read. The walk may have stopped in
front of one, so reporting such a member as unencrypted is the same wrong answer reached
by omission rather than by dropping anything, and the diagnostic saying the header was cut
short does not change what the field says. This is the one place the sentence above gives
way and the member carries no parameters.

"Encrypted" and "we could not tell" SHALL nonetheless remain distinguishable inside the
backend, because they are acted on differently. The cut-short answer SHALL apply to the
member's own reported flag and SHALL NOT reach the archive-level one: `ArchiveInfo`
reports header-level encryption and the aggregate of members *known* to be encrypted, so
one damaged member SHALL NOT make a wholly plaintext archive report as encrypted, hand the
caller's password to `unrar`, or relabel an empty read as a wrong password.

The cost of failing closed falls on the member's direct read. A stored member is otherwise
sliced straight from the source; one whose header was cut short SHALL NOT be handed back
unchecked, because those bytes are ciphertext if the record the walk never reached was the
encryption record.

A checksum that survived the damage SHALL settle it. RAR5 keeps CRC32 in the fixed FILE
header and BLAKE2sp in the extra area, so which digest a cut leaves behind is the writer's
choice, not archivey's. Where one survives, the member's stored bytes SHALL be verified
against it **before** any byte is returned, and the member SHALL be readable when they
match — on any installation, with or without `unrar`. Where none survives, the member SHALL
NOT be readable. The refusal SHALL name the cut-short header rather than the missing
package: installing `unrar` is a way out, not the cause, and it is not a better-informed
one — measured on unrar 7.00 it reads the same damaged header and reaches the same wrong
conclusion, applying that same digest test and returning the bytes unverified when no
digest survived.

The check SHALL run before the first byte is returned rather than at end of stream, for the
reason the ZIP ZipCrypto stored path gives: nothing in a stored member's framing can reject
wrong bytes incrementally, so a caller that stops reading early would never reach an
end-of-stream verdict. Its cost is one extra pass over an already-damaged member and none
at all on an undamaged one.

**Both paragraphs above are scoped to the member archivey reads by slicing the source** —
stored, including one split across volumes or carrying its own solid flag. Every
other cut-short member is decoded by
`unrar`, which is handed the whole member and cannot be asked to check a digest first;
there any surviving digest is verified as it is for an undamaged member, at end of stream,
and a member with none is read with nothing checking it. That is unchanged behaviour and
not a guarantee this requirement makes. Such a member SHALL still be reported as encrypted
and SHALL still carry the cut-short diagnostic, so a strict policy refuses it.

The diagnostic reporting a cut-short header SHALL name the fault that ended the walk. Four
different faults end it — the skip cap, a size that cannot be read, a size that overruns
the area, and a size below the one-byte minimum — and they are not interchangeable: this
message is the only thing that explains why a member may be reported encrypted when
nothing else in its listing says so.

#### Scenario: A cut-short header never reports an encrypted member as plaintext

- **GIVEN** a RAR5 member whose `FHEXTRA_CRYPT` record is preceded by enough records to
  stop the walk — past the skip cap, or one whose size cannot be used
- **WHEN** the archive is listed under the default diagnostic policy
- **THEN** the member SHALL be reported as encrypted
- **AND** a member whose extra area *was* read to the end SHALL NOT be reported as
  encrypted merely for having dropped a record, because that question was asked and
  answered

#### Scenario: One cut-short member does not report the archive as encrypted

- **GIVEN** a RAR5 archive with nothing encrypted in it, one of whose members has a
  cut-short extra area
- **WHEN** the archive is listed
- **THEN** that member SHALL be reported as encrypted
- **AND** the archive SHALL NOT be reported as encrypted

#### Scenario: A surviving checksum settles a cut-short stored member

- **GIVEN** a stored, unencrypted RAR5 member whose extra-area walk stopped early, whose
  CRC32 is in the fixed FILE header and so survived the damage
- **WHEN** it is read on an installation with no RARLAB `unrar` or `rar` available
- **THEN** the member SHALL be read and its content returned
- **AND** the member SHALL still be reported as encrypted, its header having never settled
  the question

#### Scenario: A cut-short stored member whose bytes fail the surviving checksum

- **GIVEN** a stored, *encrypted* RAR5 member whose extra-area walk stopped before its
  `FHEXTRA_CRYPT` record, whose CRC32 survived the damage
- **WHEN** it is read
- **THEN** the read SHALL raise `CorruptionError` reporting that the stored bytes do not
  match the surviving checksum
- **AND** no ciphertext SHALL be returned as member content

#### Scenario: A cut-short stored member names the header, not the missing package

- **GIVEN** a stored RAR5 member whose extra-area walk stopped early and whose only digest
  was BLAKE2sp, which the same cut destroyed
- **WHEN** it is read on an installation with no RARLAB `unrar` or `rar` available
- **THEN** the read SHALL raise `CorruptionError` naming the cut-short header and the
  absence of a surviving checksum

#### Scenario: An unparseable encryption record refuses the archive

- **GIVEN** a RAR5 member whose `FHEXTRA_CRYPT` record is truncated
- **WHEN** the archive is listed
- **THEN** listing SHALL raise `CorruptionError`
- **AND** the member SHALL NOT appear in any listing as an unencrypted member

### Requirement: A cut-short SERVICE header SHALL be reported, and its payload SHALL NOT be sliced

`CMT` and `QO` are SERVICE headers with the same extra area as a FILE header, so the same
leniency applies to them. They are not members, so nothing lists them and no per-member
diagnostic describes them.

A SERVICE header whose extra-area walk dropped a record or gave up SHALL emit the same
diagnostics a member's header does, in every volume of a multi-volume set. The argument for
dropping a record rather than refusing the archive is that the diagnostic is emitted and a
strict policy can still refuse; a header that reported nothing was outside that argument.

Those diagnostics SHALL NOT describe the header as a member. It is in no listing, so naming
it as one sends the caller looking for something that is not there; the message SHALL name
the header and what the archive therefore does without — the comment, or the quick-open
index — and SHALL carry no member name.

How many such headers one archive retains SHALL be bounded, and the bound SHALL NOT depend
on the archive. A SERVICE header is not a member, so the listing bound never counts one, and
a small archive of nothing but damaged SERVICE headers would otherwise retain without limit.
Past the bound the headers SHALL be counted and the count reported, so reaching it is not
itself silent. Counting them against the listing bound instead is rejected: that refuses an
archive `unrar` lists, over headers that are optional metadata.

The gates that slice a SERVICE payload out of the archive — the stored-comment gate and the
quick-open gate — SHALL refuse a header that stopped before it could rule encryption out,
as they already refuse one known to be encrypted. The comment is decoded as text and the
quick-open payload is parsed as a member table, so slicing unsettled bytes would put
ciphertext in `ArchiveInfo.comment` or parse a member list out of it. Losing the comment, or
falling back to the header walk, is a missing answer; the alternative is a wrong one.
A stored comment SHALL be read only from the span the walk skips after its header, so no
byte is read both as comment data and as a header.

#### Scenario: A cut-short comment header is refused and reported

- **GIVEN** a RAR5 archive whose `CMT` SERVICE header has an extra area whose walk stops
- **WHEN** the archive is opened
- **THEN** `ArchiveInfo.comment` SHALL NOT be taken from that header's payload
- **AND** the walk's dropped record and its stop SHALL each emit
  `MEMBER_HEADER_RECORD_SKIPPED`
- **AND** a strict diagnostic policy SHALL refuse the archive
- **AND** the diagnostics SHALL carry no member name and SHALL say the archive comment was
  not used

#### Scenario: An archive of damaged service headers is reported under a bound

- **GIVEN** a RAR5 archive holding more damaged SERVICE headers than the bound retains
- **WHEN** the archive is opened
- **THEN** the number retained SHALL be the bound, whatever the archive holds
- **AND** one further `MEMBER_HEADER_RECORD_SKIPPED` SHALL report how many were not
  described individually

### Requirement: Return a named member's own bytes when its mask selects others

`unrar p` with an include mask emits every payload member the mask selects, in archive
order and with no headers between them. The system SHALL build the mask from the name as
`unrar` reads it from the header, SHALL compute which members that mask selects the way
`unrar` 7 does, and SHALL return only the target's bytes: it SHALL skip the unpacked size
of the selected members before the target and SHALL stop at the target's size. This
covers members with the same name, names `unrar` reads as the same text, a mask that
names a directory prefix of another member, and a RAR5 name that is not valid UTF-8,
which `unrar` reads only up to its first invalid byte.

The system MUST NOT return another member's bytes for a member. When the selection is not
known, the system SHALL raise `UnsupportedFeatureError` naming
`rar_decompressor='unar'` before `unrar` is spawned and before a stream source is
copied. That is the case when `unrar` reads the name as empty or as a path with no name,
when the name `unrar` reads cannot be passed back to it in argv, when the mask would not
select the target, and when an earlier member's name cannot be read the way `unrar`
reads it on this host. A stored name that contains a NUL SHALL be refused the same way.

A mask with no `*` or `?` that selects earlier members SHALL be read without
`rar_allow_glob_member_concatenation`.

#### Scenario: shared mask matrix

| Case | Expected |
| --- | --- |
| Two or three members with the same name, solid or not | Each read returns its own bytes |
| RAR5 `ab\xffcd.txt` after members `unrar` reads as `ab` | Its own bytes; the earlier ones are skipped |
| RAR5 name `\xff` beside a sibling named U+FFFD, no stored digest | `UnsupportedFeatureError`; never the sibling's bytes |
| A name `unrar` reads as empty (`\xc0\x80x`) | `UnsupportedFeatureError` |
| Earlier 8-bit RAR 1.5-4 name and no UTF-8 locale for `unrar` | A later member's read raises `UnsupportedFeatureError` |

### Requirement: Refuse a glob member name whose mask also matches earlier members

A RAR member's stored name may contain `*` or `?`. Because `unrar` is addressed by an
include mask, such a name can match other members, and `unrar` decompresses every match
and emits them concatenated ahead of the target.

When the mask built from a member's stored name also matches **earlier** payload
members, the system SHALL raise `UnsupportedFeatureError` rather than read the member.
The error SHALL name the configuration flag that allows the read. On a non-solid
archive it SHALL also name the number of bytes of earlier matching members that
`unrar` would decompress first. On a solid archive those members are already inside
the solid prefix the read pays, so the error SHALL NOT describe that count as an
avoidable extra decode.

`ArchiveyConfig.rar_allow_glob_member_concatenation` SHALL default to `False`. When set
to `True` the read SHALL proceed and return the member's own bytes, skipping the earlier
matches as before. The flag SHALL govern only whether the read is attempted; it SHALL
NOT change what a successful read returns.

A glob name whose mask matches **no** other member SHALL be unaffected and SHALL read
without the flag. A name with no `*` or `?` SHALL NOT be refused by this requirement,
whatever else its mask selects (`Return a named member's own bytes when its mask selects
others`), unless the mask built for it holds a `?` that the name does not: on POSIX a
RAR 1.5-4 UTF-16 name sends each surrogate unit as `?` (`Decode RAR member names`), and
that mask falls under this requirement like a stored glob.

A call site that builds no include mask SHALL be unaffected, whatever the member names
are. In particular a solid `stream_members()` pass uses one unnamed `unrar p` pipe
demultiplexed by size, so it SHALL read glob-named members without the flag.

The refusal exists because names like this are almost always constructed. On a
non-solid archive the extra decode is also unbounded and unreported: it is not
covered by `ExtractionLimits`, which do not reach `open()` / `read()`. On a solid
archive `AccessCost.SOLID` already advertises the prefix; the names are still
refused.

#### Scenario: glob member matrix

| Case | Expected |
| --- | --- |
| `a*.txt` with an earlier `subdir/aY.txt` match, default config, non-solid | `UnsupportedFeatureError` naming the byte count and the flag |
| The same member on a solid archive, default config | `UnsupportedFeatureError` naming the flag, not an avoidable extra decode |
| The same read with `rar_allow_glob_member_concatenation=True` | The member's own bytes, earlier matches skipped |
| `only*.dat`, whose mask matches nothing else, default config | Reads normally; no refusal |
| Solid `stream_members()` over glob-named members, default config | All members read; no mask is built |
| A name with no `*` or `?`, even one shared with an earlier member | Not refused in either configuration |
| POSIX: `hi` U+D800 `.txt` after `hiX.txt`, default config | `UnsupportedFeatureError` naming the flag; with the flag, the member's own bytes |

### Requirement: Under auto, read a member unrar cannot name with unar

`unar` selects members by index, so a name `unrar` cannot be given, or a glob name
whose mask also matches earlier members, costs it nothing. When
`ArchiveyConfig.rar_decompressor` is `auto` and resolved to `unrar`, a read that the
two requirements above would refuse SHALL instead be served by `unar -i <index>`, when
all of these hold: an accepted `unar` is installed (the same check `auto` uses), the
read needs no password (see "A spawn gets a password only when the read needs one";
`unar` takes it on its command line), the source
is a file with nothing before the RAR (`unar` would otherwise need its own copy: a
prefix has no open-time cost note under `unrar`, and a stream source would be copied a
second time against the same `SpoolLimits` budget; a file is linked into `unar`'s
private directory, copied only where the system allows no link), and `unar` itself would not refuse the member
or the archive (`Read RAR member data with unar`). Otherwise the `unrar` refusal SHALL be
raised unchanged. The dictionary memory check SHALL use `unar`'s rule for that read.
Every other member SHALL still be read with `unrar`. With `rar_decompressor='unrar'`
the refusals SHALL stand.

#### Scenario: auto routes unnameable members to unar

| Case | Expected |
| --- | --- |
| `a*.txt` with an earlier `subdir/aY.txt`, non-solid, `auto`, accepted `unar` installed | The member's own bytes, read with `unar`; other members read with `unrar` |
| `d*/x.txt` (glob in a directory component), `auto`, accepted `unar` installed | The member's own bytes, read with `unar` |
| The same reads with no accepted `unar` | The `unrar` refusals, unchanged |
| The same reads with `rar_decompressor='unrar'` | The `unrar` refusals, unchanged |
| RAR5 solid archive with data after a directory (`unar` refuses it) | The `unrar` refusal, unchanged |
| A read that needs a password, or a stream source, or a prefix before the RAR | The `unrar` refusal, unchanged; nothing is written to disk |
| A plaintext member of a non-solid archive whose last member is encrypted | Read with `unar`, which gets no password |

### Requirement: A spawn gets a password only when the read needs one

An `unrar` or `unar` process started to read one member SHALL receive a password only
when that read needs one: the archive's headers are encrypted, the member is encrypted
or its encryption is unknown, or the archive is solid and an encrypted member (or one
whose encryption is unknown) comes before it. Otherwise the process SHALL be started
with no password, whatever the caller supplied. A process that decodes the whole
archive (a solid `stream_members()` pass) SHALL receive one when any member is
encrypted.

#### Scenario: Passwords per read

| Case | Expected |
| --- | --- |
| Non-solid archive, caller password, plaintext member read with `unrar` | `unrar` gets no password |
| The same archive, its encrypted member | `unrar` gets the password |
| Header-encrypted archive, any member | The password |
| Solid archive, plaintext member after an encrypted one | The password |
| Solid archive, plaintext member before every encrypted one | No password |

### Requirement: Read RAR member data with unar

When `ArchiveyConfig.rar_decompressor` is `unar`, or `auto` with no usable RARLAB
`unrar` or `rar` on `PATH`, the system SHALL read compressed member data by invoking
`unar` 1.10 or later, identified on `PATH` by its `unar -h` banner with the same probe
timeout and stat-keyed cache as RARLAB `unrar`. An identified `unar` SHALL also decode a
small embedded RAR5 archive once, under the same timeout and cache, and SHALL NOT be
used unless it writes that archive's one member exactly and exits 0: Debian and Ubuntu
`unar` packages before 1.10.8+ds1-10 write nothing for such members, and their version
string does not tell them apart. A refused `unar` SHALL count as absent under `auto`,
and the refusal SHALL say what the check saw; it names the Debian patch only for exit 0
with a short member. Stored, unencrypted members SHALL still be read directly, whatever
their own solid flag, including a member split across volumes whose parts were all
found, and a stored, encrypted member in one part SHALL be decrypted by archivey as
under `unrar` (`Use RARLAB unrar only for member data that needs it`). The system MUST
NOT use `unrar` in that mode, and MUST NOT use `unar` in any other mode; a missing,
unidentified or refused `unar` SHALL raise
`PackageNotInstalledError` naming `unar`. `auto` SHALL choose once per reader, when the
archive opens; a read `unar` refuses MUST NOT be retried with `unrar`, and with neither
program present `auto` SHALL raise the `PackageNotInstalledError` that names RARLAB
`unrar` or `rar`. When `auto` chooses `unar`, `ar.cost.notes` SHALL say so at open,
naming the password exposure and the `unrar` setting that avoids it.

The argv SHALL be
`unar -o - -q -nr -k skip [-p <password>] [-i] -- <absolute path> [index …]`:
members named by decimal entry index in parse order, never by stored name. The
password is on the command line because `unar` takes it nowhere else, so other local
users can read it in the process list; the documentation SHALL say so. The native
RAR5 password check SHALL reject a wrong password before `unar` runs where the archive
stores one; otherwise, when `unar` produces no data for a non-empty encrypted member,
the read SHALL raise `EncryptionError`. The
system SHALL refuse with `UnsupportedFeatureError`, before spawning `unar`:

- an encrypted RAR 2.x-4.x member that archivey does not decrypt itself, and every
  member of a solid pass over such an archive (`unar` 1.10 returns no data for it, and
  exits 0, even with the right password);
- a member or solid pass that needs a password that is not ASCII, or contains NUL
  (`unar` 1.10 does not decrypt with it);
- every member of a multi-volume RAR5 set with encrypted headers (XADMaster 1.10.8
  returns no data for it, and exits 0);
- in a RAR5 solid archive, a member with data that follows an empty file, a
  directory or a link;
- a compressed member whose extract version is below 20 (RAR 1.5 algorithm);
- any member of a multi-volume set that has a prefix before the RAR.

A solid pass that includes a refused member SHALL name only the readable payload
members, so `unar` never decodes the refused one, and SHALL name at most 4000 of
them to stay inside `ARG_MAX`. A readable member past the 4000th SHALL be refused in
that pass with `UnsupportedFeatureError`; opening it on its own is not affected. A
single archive with a prefix SHALL be copied from the RAR's start before `unar`
reads it, bounded by `ArchiveyConfig.spool_limits` for a path source too, and
`ar.cost.notes` SHALL say so at open, naming the limit or the refusal as for a stream
source. Every
member read through `unar` SHALL be checked against its declared
size and stored digest, because `unar` exits 0 on some failures.

A compressed RAR 1.5-4 comment (a RAR 1.5/2.x old-style COMMENT subblock, or a
RAR 2.9-4 `CMT` SERVICE header that is not stored) SHALL be decoded by the selected
program, so with `unar` selected `unar` decodes it. The decoded text SHALL be used
only when its stored CRC matches (the CRC16 of a COMMENT subblock, the full CRC32 of a
`CMT` header); otherwise, or when the selected program is missing, the comment SHALL be
`None`, as it is with `unrar`. A compressed `CMT` that declares more than 256 KiB, the
most `rar` writes, SHALL be `None` and SHALL NOT be weighed or decoded.

#### Scenario: unar selection matrix

| Case | Expected |
| --- | --- |
| Default config (`auto`), RARLAB `unrar` present, compressed member | `unrar` is spawned; `unar` is not |
| Default config (`auto`), only a `unar` that passes the RAR5 check, compressed member | `unar` is spawned; `ar.cost.notes` says why at open |
| `rar_decompressor="unrar"`, only `unar` present | `PackageNotInstalledError` names RARLAB `unrar` or `rar`; `unar` is not used |
| `rar_decompressor="unar"`, `unar` missing, `unrar` present | `PackageNotInstalledError` names `unar`; `unrar` is not used |
| `rar_decompressor="auto"`, RARLAB `unrar` present | `unrar` is spawned; `unar` is not |
| `rar_decompressor="auto"`, only a `unar` that passes the RAR5 check | `unar` is spawned |
| Only a `unar` that fails the RAR5 check (`tests/test_unar_probe.py`), `auto` or `"unar"` | `auto`: as with neither present; `"unar"`: `PackageNotInstalledError` saying what the check saw |
| `rar_decompressor="auto"`, neither present | `PackageNotInstalledError` names RARLAB `unrar` or `rar` |
| `unar` selected, member name contains `*` | Read by index; no `rar_allow_glob_member_concatenation` needed |
| `unar` selected, encrypted RAR5 member, right password | Read correctly; the password is passed with `-p` |
| `unar` selected, encrypted RAR5 member, wrong password | `EncryptionError` |
| `unar` selected, encrypted RAR 2.x-4.x member, compressed or split | `UnsupportedFeatureError` naming the RAR 2.x-4.x reason |
| `unar` selected, stored encrypted RAR 2.9-4 member in one part, `open()` | Decrypted by archivey; `unar` is not spawned |
| `unar` selected, non-ASCII password | `UnsupportedFeatureError` naming the password reason |
| `unar` selected, RAR5 volume set with encrypted headers, right password | `UnsupportedFeatureError` |
| `unar` selected, RAR5 solid, empty file first | Members with data after it are refused; listing is not |
| `unar` selected, member before the first empty entry in a RAR5 solid pass | Read correctly from a run that names only readable members |
| `unar` selected, RAR 1.5 compressed member | `UnsupportedFeatureError` |
| `unar` selected, single archive after a 4 KiB prefix | Read from a copy that starts at the RAR; `ar.cost.notes` warns of the copy at open |
| `unar` selected, solid pass with a refused member and more than 4000 readable members | Members past the 4000th refused in the pass; each still opens on its own |
| `unar` selected, compressed RAR 1.5 archive comment | Decoded by `unar` and checked against its CRC16 |
| `unrar` present, RAR 2.9-4 archive comment in a compressed `CMT` SERVICE header | Decoded, checked against its CRC32, and UTF-16LE when `SUBHEAD_FLAGS_CMT_UNICODE` is set |

### Requirement: Count the RAR dictionary against the decoder memory cap

The reader SHALL refuse a member read with `ResourceLimitError` when the dictionary
memory the decompressing program would use is over
`DecoderLimits.max_decoder_memory`. The refusal SHALL come before `unrar` or `unar` is
spawned and before a stream source is copied to disk. The count SHALL follow the
program that will run, so under `rar_decompressor="auto"` it is the rule of the program
`auto` picked:

- `unar`: the largest dictionary declared in the member's solid stream, up to and
  including the member.
- `unrar`, nonsolid: for the member and for every earlier member its include mask also
  selects, the smaller of that member's declared dictionary and its unpacked size; the
  largest of these.
- `unrar`, solid: the smaller of the largest dictionary declared up to and including the
  member and the unpacked size of those members. "Solid" here is the MAIN header's solid
  flag, which is what `unrar` decides by; a member's own solid flag does not.

A stored member, a directory and a RAR5 redirect add nothing to either count. Under
`unar` and in a nonsolid archive they SHALL count 0; under `unrar` in a solid archive
they SHALL count the `unrar` solid count of the members before them, because `unrar`
decodes those members to reach them. A `stream_members()` pass that runs one process
over the archive SHALL count, for each member, the largest count of any member up to
and including it, and SHALL check it on that member's first read, so a pass that lists
or skips a member is not refused for it. The message SHALL name the member whose header
declared the dictionary behind the count when the member read does not declare it, and
SHALL give the declared size when the count is smaller.

#### Scenario: dictionary cap matrix

| Case | Expected |
| --- | --- |
| `unar`, a small member declaring 4 GiB, default cap | `ResourceLimitError`; `unar` not spawned |
| `unrar`, a small nonsolid member declaring 4 GiB, default cap | Reads |
| `unrar`, a nonsolid member declaring 4 GiB and 3 GiB unpacked, default cap | `ResourceLimitError` naming 3 GiB and the declared 4 GiB; `unrar` not spawned |
| `unrar`, a solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError`, for a named read and in a `stream_members()` pass |
| `unrar`, a stored solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError` naming the earlier member; `unar` counts it 0 |
| `unrar`, a duplicate name whose earlier entry declares 4 GiB and 3 GiB unpacked | `ResourceLimitError` when the later, small entry is read |
| `rar_decompressor="auto"` | The count of the program `auto` picked |

### Requirement: A RAR file cut inside a header SHALL list the members before the cut

When a RAR file ends after the first byte of a header and before its last, the archive
SHALL open and list the members whose headers precede that header. The cut SHALL then be
reported as `TruncatedError`: as `members_report().error`, and raised by `members()` and
`stream_members()` after the listed members. This SHALL hold for RAR 1.5-4 and RAR5, in
both access modes, and for a RAR5 header cut inside its CRC or its size field. It is the
same rule as a walk whose skip over packed data lands past the end of the file, and a
`CMT` comment whose data runs past the end, stored or compressed, is such packed data:
the comment SHALL be `None` and the members before it SHALL still list. In a multi-volume
set the message SHALL name the volume, because its byte offset is within that volume.

Only a file that ends before the bytes a header declares is a cut. A declared size that
is invalid while its bytes are present SHALL stay `CorruptionError` at open.

With encrypted headers (`-hp`), a cut inside a salt or IV, or before a header's first
whole cipher block, is a cut as above. A cut after that block is a cut only once the
password is proven: in RAR5 by the archive's password check value, in RAR 1.5-4 by an
earlier encrypted header whose CRC16 matched. Before that proof, a wrong key also
decrypts a size that reads to the end of the file, so the open SHALL raise
`EncryptionError`. When that header's read ran out of ciphertext, the message SHALL
also name a cut in that header, or damage to it, as the cause if the password is right,
and in a volume set SHALL name the volume its byte offset is in; a header whose read did
not run out of ciphertext SHALL NOT be named as a cut. That happens inside the first
encrypted header of a RAR 1.5-4 archive, and inside any header of a RAR5 archive whose
encryption record has no check value.

A file that ends exactly at a header boundary is not a cut: RAR 1.5-4 lists as complete,
and RAR5 lists and then emits `ARCHIVE_EOF_MARKER_MISSING`.

#### Scenario: header cut matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, cut inside any header | Members before it listed; `TruncatedError` after them |
| Plain, cut exactly at a header boundary | RAR 1.5-4: complete listing; RAR5: listing, then `ARCHIVE_EOF_MARKER_MISSING` |
| RAR3 size below 7, RAR5 size over 2 MiB, RAR5 size field over 10 bytes | `CorruptionError` at open |
| `-hp` RAR5 with a check value, cut inside any header | Members before it listed; `TruncatedError` after them |
| `-hp` RAR 1.5-4, cut inside a header after one whose CRC16 matched | Members before it listed; `TruncatedError` after them |
| `-hp` RAR 1.5-4, cut after the first encrypted header's first cipher block | `EncryptionError` at open, its message naming a cut in that header or damage to it as the cause if the password is right |
| `-hp` RAR5 without a check value, cut after a header's first cipher block | `EncryptionError` at open, its message naming a cut in that header or damage to it as the cause if the password is right |
| Later volume of a set cut inside a header | `TruncatedError` naming that volume |

### Requirement: A damaged end-of-archive block SHALL keep the listing

When a RAR end-of-archive block (`ENDARC`) fails its header CRC, the archive SHALL open
and list every member before it, and those members SHALL open and read as they would
with an intact block. The damage is after the last member, so it SHALL be reported as
`ARCHIVE_EOF_MARKER_MISSING` after the members, once per damaged volume (`format="rar"`,
`expected_marker="end_of_archive_block"`, `observed_kind="nonzero"`, `observed_bytes`
the offset where the block starts in its volume, `expected_bytes` 0).
`members_report().error` SHALL be `None`, and `DiagnosticPolicy.STRICT` SHALL refuse
the archive after the listing is delivered. This SHALL hold for RAR 1.5-4 and RAR5, in
both access modes. It matches `unrar` 7.00, which lists such an archive, tests each
member OK, and then reports one error.

The type of a header whose CRC failed is not proof either, since one flipped byte can
make a MAIN or FILE header's type read as `ENDARC`. A CRC-failed header SHALL be taken
as the end block only when its type reads as `ENDARC`, it has an end block's shape (no
data area, and a header no larger than an end block's), and nothing but zero bytes
follows it in the volume (the padding `rar` writes, as for an intact end block). That
check looks at most 1 MiB past the block, the bound of the trailing-data check: a
non-zero byte at 1 MiB or more past it goes unseen, and the block is then taken for the
end block with no `ARCHIVE_TRAILING_DATA`. Any other CRC-failed header SHALL be handled
as the next requirement says: the members before it list, then `CorruptionError`.

The walk SHALL NOT read the flags of a damaged block, so its next-volume flag SHALL NOT
chain the walk to another volume. In a multi-volume set the walk SHALL continue past
that volume only when a member header in it, whose CRC matched, marks its data as
continuing in the next volume, which is the rule for a volume with no end block. When no
member does, the set SHALL end at that volume: any later volumes the caller supplied are
not read, and the diagnostic names the damaged volume. When a member does continue and
no next volume is supplied, the listing SHALL end with `TruncatedError`, as for any
incomplete set.

With encrypted headers, the damage is reported this way only once the header password
is proven, as for a cut (see the previous requirement). Before that proof, a CRC
mismatch in the end block reads the same as a wrong key, so the open SHALL raise the
wrong-password `EncryptionError`. That happens when the end block is the first
encrypted header of a RAR 1.5-4 archive, and in any RAR5 archive whose encryption
record has no check value.

#### Scenario: damaged end-of-archive block matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, end block CRC mismatch | Full listing; members read; `ARCHIVE_EOF_MARKER_MISSING` after them; strict refuses |
| MAIN header whose type byte is flipped to the end block's, blocks after it | `CorruptionError` at open |
| MAIN header whose type byte is flipped to the end block's, nothing but zeros after it | Empty listing; `ARCHIVE_EOF_MARKER_MISSING` and `EMPTY_ARCHIVE` |
| FILE header whose type byte is flipped to the end block's | Members before it listed; `CorruptionError` after them |
| Damaged end block followed by a non-zero byte within 1 MiB | Members before it listed; `CorruptionError` after them |
| Damaged end block followed by 1 MiB of zeros, then a non-zero byte | Full listing; `ARCHIVE_EOF_MARKER_MISSING` only (past the scan bound) |
| Damaged end block followed by zero bytes only (a padded volume) | Full listing; `ARCHIVE_EOF_MARKER_MISSING` after them, as with nothing after it |
| Damaged last header typed as the end block but with a data area or an oversized header | Members before it listed; `CorruptionError` after them |
| Damaged end block with its next-volume flag set, no member continues | Set ends at that volume; later volumes not read |
| Volume 1 of a set damaged, its last member continues into volume 2 | Full set listing; one diagnostic naming volume 1 |
| `-hp` RAR5 with a check value, or `-hp` RAR 1.5-4 after a header whose CRC16 matched | Full listing; `ARCHIVE_EOF_MARKER_MISSING` |
| `-hp` RAR 1.5-4 whose end block is the first encrypted header | `EncryptionError` ("wrong password?") at open |
| `-hp` RAR5 without a check value | `EncryptionError` ("wrong password?") at open |

### Requirement: Report bytes after a RAR end-of-archive block

After an intact end-of-archive block and any data area it declares, the walk SHALL
look at most 1 MiB further in that volume, and a non-zero byte there SHALL emit one
`ARCHIVE_TRAILING_DATA` per volume after the members (`format="rar"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"`, `observed_bytes` the
offset of that byte past the end block). It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the block SHALL be silent, and a
byte at 1 MiB or more past it goes unseen. With encrypted headers the block ends after
its AES padding. In a set the message names the volume. A damaged end block is taken
for one only when nothing but zeros follows it (previous requirement), so this check
does not apply to it, and a RAR 1.5-4 archive with no end block has nothing after its
last header to check. `unrar` 7.00 says nothing about these bytes. 7-Zip 23.01 warns
"There are data after the end of archive" for any tail, zeros included; archivey keeps
an all-zero tail silent, because `rar` pads volumes with zeros.

#### Scenario: RAR trailing bytes

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| RAR 1.5-4 or RAR5, headers plain or encrypted, ending at the end block | Nothing | Opens |
| 4 KiB of zeros after the end block | Nothing | Opens |
| `b"JUNK"` after the end block, or after zeros within 1 MiB | `ARCHIVE_TRAILING_DATA`, `observed_bytes` = zeros skipped | `DiagnosticRaisedError` |
| `b"JUNK"` after volume 1 of a set | Full listing; one `ARCHIVE_TRAILING_DATA` naming volume 1 | `DiagnosticRaisedError` |
| Non-zero byte at 1 MiB or more past the end block | Nothing | Opens |

### Requirement: A damaged header after the main header SHALL list the members before it

When a header after the main header fails its CRC, and it is not taken as a damaged end
block (previous requirement), the archive SHALL open and list the members whose headers
precede it. The damage SHALL then be reported as `CorruptionError`, as
`members_report().error` and raised by `members()` and `stream_members()` after the listed
members; not as `TruncatedError` unless the set is also incomplete (below). This SHALL
hold for RAR 1.5-4 and RAR5, in both access modes (DR-2: TAR lists the members before a
damaged header and then raises). In a multi-volume set the message SHALL name the first
damaged volume. The walk SHALL go on to the next volume only when a member header before
the damage (CRC intact) says its data continues there, as for a damaged end block: the
next volume's first header is at its own offset 0, so the damaged header's size is not
needed to find it. That volume's members SHALL be listed, and the `CorruptionError` SHALL
follow the whole listing (DR-2, as for a missing middle volume). With no continuing member
the set ends at the damaged volume. When the next volume is missing, the open SHALL end
with the incomplete-set `TruncatedError`, whose message also names the damaged header.

The walk SHALL stop at the damaged header. Its size field is not data once the CRC
fails, so the position of the next header is unknown. `unrar` 7.00 searches past the
damage and lists the later members too, reporting "the file header is corrupt" and
exiting 3; archivey does not search.

A damaged main header SHALL still raise `CorruptionError` at open: nothing precedes it,
and its flags (solid, volume, header encryption) are needed to read anything after it.
In RAR 1.5-4 the fields of a FILE header are parsed before its CRC is checked, since they
give the bytes the CRC covers; a field that does not parse in a header whose CRC also
fails SHALL count as the same damage. A header whose CRC matches but whose fields are
invalid, and a declared header size that is invalid, SHALL stay `CorruptionError` at
open (see the cut requirement above).

With encrypted headers the damage is reported this way only once the header password is
proven, as for a cut. Before that proof a CRC mismatch reads the same as a wrong key, so
the open SHALL raise the wrong-password `EncryptionError`. When that header's read ran
out of ciphertext, its message also names a cut in that header or damage to it, under
the condition the cut requirement above sets.

#### Scenario: damaged header matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, one byte of the second FILE header flipped | First member listed and read; `CorruptionError` after it |
| Plain, one byte of the MAIN header flipped | `CorruptionError` at open |
| Plain two-volume set, volume 1's end block damaged and not taken as one, its last member continues into volume 2 | Full set listing; members read; `CorruptionError` naming volume 1 after them |
| The same set with volume 2 missing | Volume 1's members listed; `TruncatedError` naming volume 2 and the damaged header |
| `-hp` RAR 1.5-4, a FILE header damaged after one whose CRC16 matched | Members before it listed; `CorruptionError` after them |
| `-hp` RAR 1.5-4 set, volume 2's first header damaged after volume 1 proved the key | `CorruptionError` naming volume 2 |
| The same damage with a wrong password | `EncryptionError` ("wrong password?") at open; when the read ran out of ciphertext, its message also names a cut or damage, and the volume |

### Requirement: Serve a solid pass's file copies from the source it decoded

A solid `stream_members()` pass, and the extraction built on it, SHALL keep the bytes of
each member that a later RAR5 file copy (`rar -oi`) in the pass reads, as its pipe passes
them, whether the caller reads that member or skips it, under `unrar` and `unar`. It
SHALL serve the copies from the kept bytes, so a kept source is decoded once for all its
copies. Kept bytes SHALL pass the source's digest check and declared size as the pipe's
own bytes do, and SHALL count toward extraction limits once per copy.

The pass SHALL keep up to 8 MiB of sources in memory. This constant is a tuning value: it
SHALL NOT refuse a read or change the bytes a read returns, and it is not a field of
`ArchiveyConfig`. A source past it SHALL go to a temporary file charged to
`SpoolLimits.max_bytes` (`archive-reading`). The file SHALL be created, and the source
charged, only when the source's first byte is decoded, so a pass that reads nothing writes
nothing and any copy of the archive source the pass needs is charged before the kept
source. The charge SHALL be given back when the pass ends. A source the limit has no room
for SHALL NOT be kept, and its copies SHALL read the source with a named open, as
`open()` does; that SHALL NOT raise `ResourceLimitError`. A source that the pass does not
emit (a `unar` refusal) SHALL fall back the same way.

Extraction SHALL NOT have the pass keep a source that it is writing to disk from the
pass's stream. It SHALL write each later copy of that source by copying the file it
wrote, when that file is still the one it wrote (same device, inode, size and
modification time, checked on the opened file) and the copy declares the source's size.
Those bytes SHALL count toward extraction limits as the copy's own, as bytes read from
the pass do. They need no second digest check: the source's write passed them through
the source's digest and size checks, and a write that failed them records no identity for
the copy to check against, so the copy falls back to the pass. Otherwise (a selector or filter dropped the source, its write failed, a
later member took its path, or the file changed) the copy SHALL be read from the pass:
from the kept bytes when the extraction did not write the source, and with a named open
when it did. A dry run writes empty files, so it SHALL keep sources as `stream_members()`
does.

`stream_members(file_copy_streams=False)` SHALL yield every file copy with a `None`
stream, solid or not, and a solid pass SHALL then keep no source.

#### Scenario: kept file-copy source matrix

| Case | Expected |
| --- | --- |
| Solid pass, source read, copies read | One decompressor run; every copy reads the source's bytes |
| Solid pass, source skipped, copies read | One decompressor run; the pass moves through the source and keeps it |
| `extract_all()` with a filter that drops the source | One decompressor run; the copies are written |
| Source over 8 MiB, no member read, stream source | Nothing is written: no temporary file, no copy of the archive |
| Source over the memory constant, within `SpoolLimits.max_bytes` | Kept in the temporary file; one decompressor run |
| Two passes on one reader, room for the source once | Each pass keeps it; one decompressor run per pass |
| Stream source, first member a source; the archive copy and the source each fit the limit, not both | The archive copy is made; the source is not kept; each copy decodes it again; no `ResourceLimitError` |
| `SpoolLimits.max_bytes=0`, path source, source over the memory constant | Not kept; each copy decodes it again; nothing is refused |
| Kept bytes that do not match the source's digest | `CorruptionError` on the copy's read |
| `max_extracted_bytes` below the total with copies | `ResourceLimitError`; each copy counts its bytes |
| `extract_all()`, source written from the pass, `SpoolLimits.max_bytes=0`, source over the memory constant | One decompressor run; nothing kept; each copy copied from the source's file |
| `extract_all()`, `streaming=True`, source written | The same: one decompressor run; each copy copied from the source's file |
| `extract_all()`, the source's file replaced before its copies are written | Each copy gets the source's bytes from the archive, not the replacement's; it decodes the source again |
| `extract_all(dry_run=True)` | Sources kept; one decompressor run |
| `stream_members(file_copy_streams=False)`, solid, under `unrar` and `unar` | Copies yielded with `None`; nothing kept; one decompressor run |
| `stream_members(file_copy_streams=False)`, nonsolid | Copies yielded with `None` |

### Requirement: Read RAR without any external program

When `ArchiveyConfig.rar_decompressor` is `none`, the system MUST NOT start `unrar`,
`rar` or `unar` for that reader: not to identify them at open, not to decode a comment,
and not to read member data. Opening and listing SHALL work as with any other setting,
including header-encrypted archives given the right password. A stored member that is
not encrypted SHALL be read directly, as it is under every setting, when all of its
parts were found, and a stored, encrypted member in one part SHALL be decrypted by
archivey, as under every setting; without `cryptography` its read SHALL raise
`PackageNotInstalledError` naming `cryptography`. A member with a part in a missing
volume SHALL raise `TruncatedError`, as under every setting ("A set with volumes
missing SHALL list what it has, then
raise"): no program can read data that is not there. Every other member read SHALL raise
`UnsupportedFeatureError` before any process starts or any source is copied, naming why
the member cannot be read (compressed, or encrypted in a form archivey does not decrypt)
and the `unrar` setting that reads it. A compressed RAR 1.5-4 comment SHALL be `None`. When
the archive has a file member that this setting refuses, `ar.cost.notes` SHALL say so at
open.

#### Scenario: no external program matrix

| Case | Expected |
| --- | --- |
| Non-solid archive, stored plaintext members, path or stream source | Every member reads; no process starts; `ar.cost.notes` is empty |
| Compressed member | `UnsupportedFeatureError` naming "compressed"; no process starts |
| Compressed encrypted member | `UnsupportedFeatureError` naming "compressed" |
| Stored encrypted member in one part, right password | Decrypted and read; no process starts; `ar.cost.notes` is empty when nothing else is refused |
| Stored encrypted member in one part, `cryptography` missing | `PackageNotInstalledError` naming `cryptography`; `ar.cost.notes` says reads will be refused |
| Stored encrypted member split across volumes | `UnsupportedFeatureError` naming "encrypted" |
| Stored member split across volumes | Its parts are joined and read; no process starts |
| Stored member split across volumes, its first or a later part missing | `TruncatedError`, as under every setting; no process starts |
| Stored member with its own solid flag | Read directly; no process starts |
| Solid archive, `stream_members()` | Each member's read is refused on its own; no solid pass starts |
| Header-encrypted archive, right password | Lists; no process starts |
| Compressed RAR 1.5 archive comment, or a compressed RAR 2.9-4 `CMT` | `None` |

### Requirement: Password lists for data with no password check

RAR3/4 file data records no password check value, and neither does a RAR5 encryption
record without a usable PswCheck. When the caller gives more than one distinct password
(or a provider) for an archive whose headers are not encrypted, the reader SHALL judge
the candidates for such a member by decoding it, under the shared confirmation rule
(`archive-reading`, "Confirm candidates when a weak check permits retries"), before the
member's own read starts:

- the **bounded probe** reads at most `PASSWORD_CONFIRM_PREFIX_BYTES` of the member's
  output from the decompressor; a program error, a wrong-password exit or output that
  ends short SHALL reject the candidate. A member that fits the prefix is checked against
  its CRC, which confirms;
- the **full check** reads the whole member and compares its CRC;
- a **stored** RAR 2.9+ or RAR5 member in one part that records a CRC32 SHALL be judged
  by decrypting it natively (`Use RARLAB unrar only for member data that needs it`) and
  comparing its CRC, a RAR5 tweaked CRC after the same transform under the candidate's
  HashKey, with no external program: every wrong key decrypts a stored member to bytes
  of the right length, so only the CRC can tell. The member's own read is then also
  native.

In a non-solid archive each such member is judged on its own data. In a solid archive,
and for the pass over a whole archive, the candidates are judged once, on the first
encrypted member (solid) or the smallest one (non-solid). One distinct password, and the
header password of a header-encrypted archive, SHALL go to the decompressor unjudged, as
before. A member whose password was confirmed against its own CRC SHALL NOT emit
`ENCRYPTED_MEMBER_UNVERIFIED` when its read is abandoned.

#### Scenario: RAR3/4 password list matrix

| Case | Expected |
| --- | --- |
| Non-solid, compressed, `password=[wrong, right]`, member larger than the prefix | Every member reads correctly |
| Same, `wrong` survives the 64 KiB prefix | The full check rejects it; every member reads correctly |
| Solid, compressed, `password=[wrong, right]` | One resolution on the first encrypted member; every member reads, by `open()` and `stream_members()` |
| Stored encrypted member, `password=[wrong, right]` | Judged natively by CRC; no process started for the check |
| `password=[wrong1, wrong2]` | `EncryptionError` |
| One password | Handed to the decompressor unjudged, as before |
