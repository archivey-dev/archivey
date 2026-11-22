## ADDED Requirements

### Requirement: Read a UDIF image as a virtual disk

The system SHALL read a UDIF image (`ArchiveFormat.DMG`) through its `koly` block, its
XML property list and its `mish` run tables, and serve the virtual disk they describe.
The property list's length SHALL be checked before any byte of it is read: over 64 MiB
SHALL raise `ResourceLimitError`. It SHALL then be parsed with `plistlib`. A `mish`
table whose run count does not fit its data SHALL raise `CorruptionError`, and the runs
SHALL be charged as metadata before they are kept. A sector inside a table's range that
no run covers SHALL read as zeros. Runs of type zero fill, raw, ignore (free space),
ADC, zlib, bzip2, LZFSE and xz SHALL be read; a comment run SHALL be skipped and the
terminator SHALL end the table. Each compressed run SHALL decode to exactly its sector
count × 512 bytes. Before any byte of a run is read, a raw run whose stored length is
not its decoded size, SHALL raise `CorruptionError`, and a compressed run whose stored
length exceeds twice its decoded size plus 64 KiB SHALL raise `ResourceLimitError` (a
support limit, not a validity bound); no decoder pull SHALL return more than the decoded
size plus one byte. Runs SHALL be decoded through `ReaderContext.decompress` for zlib,
bzip2 and xz and through archivey's own pure-Python decoders for LZFSE, LZVN and ADC,
whose output is bounded by the run's size. A run that decodes to another length, runs
that overlap or leave their table's sector range, and stored ranges outside the data
fork SHALL raise `CorruptionError`; a file that ends inside a run or the property list
SHALL raise `TruncatedError`. An unknown run type, and a compressed run that declares
more than 16 MiB decoded, SHALL raise `UnsupportedFeatureError` from the read that needs
it, leaving other members readable. Every member read, on `open()` and on extraction,
SHALL count in the archive-wide ratio (`DecoderLimits.max_ratio` times the image's
size), as for ISO, whatever runs serve it, zero fill and the in-house decoders included.
The format SHALL require a seekable source. A run's stored range SHALL be
`data fork offset + mish data offset + compressed offset` for its compressed length,
inside the data fork. A code-signature blob declared in the `koly` block SHALL be
allowed and not verified; file bytes outside the declared structures SHALL be reported
as trailing data. Opening SHALL read only a fixed envelope: the `koly` block, the
property list and run tables, the partition map (a GPT entry array of at most 64 KiB, or
an Apple Partition Map of at most 64 entries, each size checked from its header before
the read; a larger valid map SHALL be reported and the `blkx` ranges used instead), and
for each of at most 128 candidate partitions (a 129th candidate from any source SHALL
raise `ResourceLimitError` at open, so no volume is silently skipped) a 4 KiB probe, the
HFS+ volume header and, when journaled, the journal info block and journal header (512
bytes each), or the APFS block 0 at its declared size (at most 64 KiB). Beyond the
property list, the physical bytes read and the bytes decoded at open SHALL together stay
within 64 MiB; more SHALL raise `ResourceLimitError` at open. No work SHALL be
proportional to the image.

#### Scenario: UDIF runs

| Case | Expected |
| --- | --- |
| `hdiutil` UDZO, UDBZ, ULFO, ULMO and UDRO images | Every file's bytes as macOS reads them |
| A run that decodes one sector short | `CorruptionError` naming the run's file offset, at the read of a member that needs it |
| Two runs covering the same sectors | `CorruptionError` |
| Run type `0x80000009` | `UnsupportedFeatureError` at the read that needs it; other members read |
| A listing | Decodes only the runs that hold filesystem metadata |
| A pipe | Refused or spooled as for `SEEKABLE` formats |
| Segment count over 1 | `UnsupportedFeatureError` naming segmented images |
| Data fork offset and mish data offset both non-zero | Runs read from their sum plus the run offset |
| A signed image (code-signature blob before the `koly` block) | Read; no trailing-data report |
| A 64 KiB image with one 1 TiB file whose extents lie on a zero-fill run | `open()` read and extraction stop at the archive-wide ratio with `ResourceLimitError`; listing is unaffected |
| 128 candidates each probing a different maximal compressed run | `ResourceLimitError` at open once the 64 MiB open budget is spent |
| A GPT entry array over 64 KiB | Diagnostic; candidates from the `blkx` ranges |
| An APM whose map count is far above 64 | No entry beyond the cap read; diagnostic; candidates from the `blkx` ranges |
| 129 candidates, the filesystem only in the last | `ResourceLimitError` at open, not an empty listing |
| A one-sector gap inside a table's range | That sector reads as zeros |
| A plist length over 64 MiB | `ResourceLimitError`; no byte of the plist requested from the source |
| A compressed run whose stored length is over the cap | `ResourceLimitError`; no byte of the run requested |
| A valid ADC run of one-byte literals (stored ≈ 2 × decoded) | The data |
| A run whose decoder yields more than its decoded size | `CorruptionError` after at most the decoded size plus one byte |
| A `mish` table that declares more runs than its data holds | `CorruptionError` before any run is kept |

### Requirement: Pick the filesystem partitions of a disk image

The system SHALL serve the disk from one index of all `mish` tables, refusing tables
whose sector ranges overlap with `CorruptionError`. Candidate partitions SHALL come from
a valid GPT or Apple Partition Map, else from the `blkx` ranges, else the whole disk.
The system SHALL read a candidate as HFS+ when offset 1024 holds `H+` (version 4) or
`HX` (version 5), and as APFS when offset 32 holds `NXSB`; partition names and type
values SHALL only describe, never decide. An image with no such partition SHALL raise
`UnsupportedFeatureError` naming the partitions found. With one filesystem volume, its
files SHALL be listed at the archive root; with several, each volume's files SHALL be
listed under a top-level directory named after the volume, with an empty name as
`Untitled` and a name already taken given the first free ` 1`, ` 2`, ... suffix, as
macOS mounts them. The volume name, filesystem, partition scheme, run codecs and
encryption SHALL be in `archive_info().extra` under `dmg.` keys.

#### Scenario: partitions

| Case | Expected |
| --- | --- |
| GPT, one `Apple_HFS` partition | Its files at the root; `dmg.partition_scheme` `GPT` |
| Apple Partition Map | Read the same way; `APM` |
| No partition map, one whole-disk volume | Read; `none` |
| Two HFS+ volumes | Each under its volume name |
| Two volumes both named `Data` | `Data/...` and `Data 1/...`, in partition order; links stay inside their volume |
| A GPT HFS+ partition with an unrecognised `blkx` name | Read |
| Only an MBR and free space | `UnsupportedFeatureError` |

### Requirement: List an HFS+ volume as the Mac mounts it

The system SHALL list an HFS+ or HFSX volume from its catalog B-tree: folders as
`DIRECTORY`, files as `FILE`, hard-link records (Finder `hlnk`/`hfs+`) as in the
hard-link rule below, then files whose BSD mode is `S_IFLNK` (or, with mode 0, whose
Finder type and creator are `slnk`/`rhap`) as `SYMLINK` with the data fork as target,
devices, FIFOs and sockets as `OTHER`. A `/` stored in a name SHALL be listed as `:`,
and names SHALL keep their stored Unicode form. The private hard-link folders
(`\0\0\0\0HFS+ Private Data`, `.HFS+ Private Directory Data\r`) and the journal files of
a journaled volume SHALL NOT be listed. A journaled volume with pending transactions or
an external journal SHALL raise `UnsupportedFeatureError` at open; a clean journal SHALL
be read. A file hard link SHALL list its first path in listing order as `FILE` with the
data, and each later path as `HARDLINK` to it. A directory hard link SHALL raise
`UnsupportedFeatureError` for that member. Mode, owner, modification time and birth time
SHALL come from the catalog record. A B-tree node or a folder reached twice, an extent
outside the volume, and a record outside its node SHALL raise `CorruptionError`; members
listed before the damage SHALL be delivered first. Extended attribute names, and values
up to 1 KiB, SHALL be listed in `ArchiveMember.extra` and SHALL NOT be written on
extraction.

#### Scenario: HFS+ listing

| Case | Expected |
| --- | --- |
| The `hdiutil` fixture tree | `Applications` → `/Applications`, `link-rel` → `hello.txt`, `sub dir/hardlink.txt` a `HARDLINK` to `hello.txt`, every file's SHA-256 as macOS lists it |
| The private hard-link folders | Not listed |
| `hello.txt` | `extra` lists `com.example.test` |
| A catalog leaf whose next link points back | `CorruptionError` after the members before it |
| A `/` in a stored name | Listed with `:` |
| A symlink set only in the BSD mode | `SYMLINK` |
| A journal with `start != end` | `UnsupportedFeatureError` naming the unreplayed journal |

### Requirement: Decode transparently compressed files

A file flagged `UF_COMPRESSED` with a `com.apple.decmpfs` attribute SHALL be read
through it: types 1 and 9 (stored inline), 3 and 4 (zlib inline or in the resource
fork), 7 and 8 (LZVN), 10 (stored in the resource fork), 11 and 12 (LZFSE). The member's
size SHALL be the size the attribute declares. Inline data SHALL decode to exactly that
size. Resource-fork data SHALL hold exactly `ceil(size / 64 KiB)` chunks, each decoding
to 64 KiB except the last, which decodes to the remainder. Any other length SHALL raise
`CorruptionError`. A flagged file whose attribute or resource fork is missing SHALL
list, and its read SHALL raise `CorruptionError`. Any other type SHALL raise
`UnsupportedFeatureError` for that member. The `com.apple.decmpfs` attribute and the
resource fork of such a file SHALL NOT be listed in `extra`. The same rules SHALL apply
on HFS+ and on APFS.

#### Scenario: decmpfs

| Case | Expected |
| --- | --- |
| `compressed.txt` in the fixtures (type 8, 360 000 bytes) | The bytes of `text.txt` |
| Each type built by the test writer | The data |
| Type 99 | `UnsupportedFeatureError` at that member; others read |
| A resource-fork file whose last chunk is short | The data |
| `UF_COMPRESSED` with no `com.apple.decmpfs` | Listed; read raises `CorruptionError` |

### Requirement: List an APFS volume

The system SHALL read an APFS container from the newest complete checkpoint (its
superblock and checkpoint-map blocks all valid; the checkpoint scan at first listing
SHALL count its physical and decoded bytes against a 64 MiB budget and raise
`ResourceLimitError` when the next block would exceed it), resolve objects through the
container and volume object maps, and check the Fletcher-64 checksum of every object it
reads. An object whose checksum fails SHALL NOT be used: the walk SHALL skip it, list
every member whose records are all intact, and then raise `CorruptionError`. It SHALL
list the live filesystem tree of each volume (not snapshots), with types from the inode
mode, symlink targets from `com.apple.fs.symlink`, hard links as for HFS+, sparse
extents and holes as zeros, and names as stored. A node or object-map node that is
skipped SHALL mark the key range its verified parent gives it as damaged: a member whose
inode record, naming directory record, or symlink or decmpfs xattr falls in a damaged
range SHALL NOT be listed; damage that touches only its extents SHALL NOT stop it
listing, and a read that needs extents or an object-map entry in a damaged range SHALL
raise `CorruptionError`, never serve zeros. Holes outside damaged ranges SHALL read as
zeros. Encrypted volumes, sealed volumes and Fusion containers SHALL raise
`UnsupportedFeatureError` naming the feature.

#### Scenario: APFS

| Case | Expected |
| --- | --- |
| The `hdiutil` APFS fixtures, each codec | The same members and hashes as the HFS+ fixtures; `café.txt` keeps its stored form, composed (U+00E9) on APFS and decomposed (`e` U+0301) on HFS+, as the two listing files show |
| A newer checkpoint with a bad checksum | The older valid one is read |
| A newer superblock with a good checksum but a missing checkpoint-map block | The older complete one is read |
| An object deleted at xid 11, live at 10 | Absent at 11; found at 10 |
| One flipped byte in a leaf of the filesystem tree | Every member outside that leaf lists, then `CorruptionError` |
| Three filesystem-tree leaves, the middle one damaged: a sparse file in leaf 1, a file whose extents are in leaf 2, a file in leaf 3 | The sparse file reads zeros in its hole; the second file lists and its read raises `CorruptionError`; the third reads normally; the listing ends with `CorruptionError` |
| A damaged object-map leaf | Lookups of the oids it mapped raise `CorruptionError` |
| An encrypted volume | `UnsupportedFeatureError` |

### Requirement: Open a password-encrypted DMG

An image that starts with `encrcdsa` SHALL be opened with the caller's `password=`: a
password key entry is unwrapped (PBKDF2-HMAC-SHA1, then AES or 3DES in CBC mode with
PKCS#7 padding, as the entry's cipher field says), the unwrapped key SHALL be confirmed
by decrypting the image's `koly` block (or, with none, by the `CKIE` mark that ends the
unwrapped key, after which an image with no `koly` block SHALL raise
`UnsupportedFeatureError` as a read-write image), and the image SHALL then be read as an
unencrypted one through AES-CBC blocks of the header's block size. With no password
`open_archive` SHALL raise `EncryptionError`; with no right password among the
candidates it SHALL raise the wrong-password `EncryptionError`. The key-derivation work
SHALL count against archivey's key-derivation budget. The image and its members SHALL
report `is_encrypted`, and `archive_info().extra["dmg.encryption"]` SHALL name the
cipher (`"AES-128"`, `"AES-192"`, `"AES-256"`). Every length in the encrypted header
(data block size, key-entry count and sizes, iteration count, salt, IV and wrapped-key
lengths) SHALL be checked before any read and before a password is asked for: a data
block size other than 512 or 4096 SHALL raise `UnsupportedFeatureError`, a length past
the header or its field `CorruptionError`, and a count or size over its cap (16 key
entries; 4 KiB for each key entry) `ResourceLimitError`. `cdsaencr` v1 images and images
with no password key entry SHALL raise `UnsupportedFeatureError`. Without
`cryptography`, `PackageNotInstalledError`.

#### Scenario: encrypted images

| Case | Expected |
| --- | --- |
| The four `-UDZO-AES-128.dmg` and `-AES-256.dmg` fixtures (HFS+ and APFS) with `password="archivey"` | The fixture tree |
| No password | `EncryptionError` asking for one |
| Wrong password | Wrong-password `EncryptionError` |
| An iteration count over the budget | `ResourceLimitError` |
| `cryptography` excluded | `PackageNotInstalledError` |

### Requirement: Image checksums raise members together

Before the partition CRC-32 spanning check exists (Part F), members of a DMG SHALL list
with `verifiable = LENGTH`. With it, `verifiable` SHALL be set at listing: `CHECKSUM`
for a file member whose partition is fully covered by `blkx` tables that each carry a
CRC-32, else `LENGTH`. Only `verified` SHALL change after the pass. A zero-fill run
SHALL be folded into the CRC in time logarithmic in its length, never walked byte by
byte or slice by slice. `verify_all()` SHALL run a separate pass over whole checked
tables: for each `blkx` table with a CRC-32 that overlaps a filesystem partition, it
SHALL decode every run of that table except "ignore" runs, in sector order, including
runs outside the partition when the table straddles its boundary, once per reader. A
member's `verified` SHALL reach `CHECKSUM` only when every table covering its partition
matches. Ordinary member reads SHALL NOT run it. A mismatch or a decode error in a table
SHALL fail every member of every partition that table overlaps. The checksum SHALL NOT
be computed at open.

#### Scenario: partition CRC

| Case | Expected |
| --- | --- |
| `verify_all()` on a fixture | Every file member `CHECKSUM` |
| One byte flipped inside a zlib run that still decodes | `verify_all()` fails the partition's members |
| One byte flipped in a run that only holds free space | `verify_all()` fails the partition's members |
| One CRC table covering two GPT partitions (straddling their boundary) | The whole table is checked; both partitions' members reach `CHECKSUM`; a flipped byte in either fails both |
