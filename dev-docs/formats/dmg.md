# DMG (UDIF disk images)

Current maintainer truth for Apple's disk images. archivey reads UDIF images that hold
HFS+, HFSX or APFS volumes, encrypted ones (`hdiutil -encryption`) included with their
password; the plan is `openspec/changes/archive/2026-11-27-dmg-reader/`. Detection's
trailer step is on [`topics/detection.md`](../topics/detection.md) §2.4. This page is
the format.

## At a glance

| | |
| --- | --- |
| Read | Yes: UDIF (`koly` version 4) with every run codec (zero fill, raw, ignore, ADC, zlib, bzip2, LZFSE, xz), GPT, Apple partition map or no map, HFS+, HFSX and APFS (unencrypted, unsealed volumes; the live tree, not snapshots), and those images encrypted with a password (`encrcdsa` v2, AES-128 or AES-256 as `hdiutil` writes them, and AES-192) |
| Write | **Not shipped** |
| Source | Seekable only (`required_source` is `SEEKABLE`): the run tables are at the end of the image and the filesystem metadata anywhere in the disk. A pipe is refused, or spooled by the caller |
| Listing cost | The open reads the `koly` block, the property list and its run tables, the partition map, a 4 KiB probe of each partition, each HFS+ volume header (plus two 512-byte journal reads) and each APFS container's block 0; the first listing walks each HFS+ catalog twice and the attributes tree once, and for APFS scans the checkpoint ring, reads the object maps whole and walks each filesystem tree once |
| Core dependencies | None. ADC, LZFSE and LZVN are decoded in Python, LZFSE and LZVN by the `archivey-speedups` kernels when that package is installed (in the decoder child under `NATIVE_DECODERS`; same bytes and errors); zlib, bzip2 and xz through `ReaderContext.decompress`. An encrypted image needs `cryptography` (the `[recommended]` extra) |
| Refuses | Version 1 encrypted images (`cdsaencr`), encrypted images locked only by a certificate or keychain key, encrypted read-write (raw disk) images, segmented images, images with no property list, HFS wrappers, HFS+ volumes whose journal may hold changes, APFS Fusion and prerelease-layout containers, encrypted and sealed APFS volumes, unknown run types (at read), directory hard links (at read) |
| `format=` | `format="dmg"` opens a file as UDIF; one with no `koly` block is `CorruptionError` |

The `.dmg` suffix is not registered: many files with that name are raw disks
(`hdiutil` UDRW) or renamed zips. The `koly` block is the claim.

## 1. Shape

Three layers, one module each:

```
udif.py             koly block (last 512 bytes, or the first in an old layout)
                    -> XML property list -> blkx: one mish table per piece of the disk
                    -> runs: (type, first sector, sectors, stored offset, stored length)
disk_partitions.py  the virtual disk: GPT (primary, then backup), Apple partition map,
                    or the run tables' own sector ranges; each range probed
hfsplus.py          HFS+ volume: header at 1024, forks of 8 extents plus the extents
                    overflow tree, catalog and attributes B-trees, hard-link inodes in
                    the private folder, decmpfs transparent compression
apfs.py             APFS container: block 0, the checkpoint ring, the container object
                    map -> volume superblocks -> each volume's object map -> its
                    filesystem tree (inodes, directory records, xattrs, extents)
```

`dmg_reader.py` ties them: `DmgReader` opens the image and each volume, and lists the
catalogs and filesystem trees. The decmpfs decoding (`hfsplus.decmpfs_reader`) is
shared: HFS+ hands it a resource fork, APFS its `com.apple.ResourceFork` attribute.

A run's stored bytes start at the data fork offset plus the table's data offset plus
the run's own offset. A raw run stores exactly its sectors; a compressed run decodes to
exactly its sectors. Zero-fill and ignore runs store nothing and read as zeros, and so
do sectors no table covers.

## 2. The pipeline here

### 2.1 Identify

Unchanged from the recognised-only era: the 12 bytes `koly`, version 4, header size
512 at offset 0, or at the start of the last 512 bytes as a trailer that outranks the
bzip2 or xz stream an image's first run is. Far magic runs first, so an uncompressed
image of an ISO 9660 disk is `ISO`. Two more signatures name encrypted images:
`encrcdsa` at offset 0 (v2) and `cdsaencr` in the last 8 bytes (v1). The trailer step
reads the longest trailer once and matches the shorter ones against its end, so its
receipt is still one 512-byte tail read.

### 2.1.1 Encrypted images

`dmg_encrypted.py`. `hdiutil -encryption` encrypts the whole UDIF image (data fork,
property list, `koly` block) and puts the `encrcdsa` header in front, so the handler's
`open` returns a `NeedsPassword` for "the disk image" and its `then` opens `DmgReader`
on `EncryptedDmgSource`, the decrypted image. Everything below then runs unchanged on
that source, and its offsets in errors are the decrypted image's (its origin is 0,
whatever the file's): a run's or a truncated read's message says "decrypted image
offset" where an unencrypted image's says "file offset". The image and every
member are `is_encrypted`.

The header, big-endian, as the four `hdiutil` fixtures (macOS 26) hold it:

| Offset | Size | Field | Fixtures |
| --- | --- | --- | --- |
| 0 | 8 | `encrcdsa` | |
| 8 | 4 | version | 2 |
| 12 | 4 | IV size | 16 |
| 16 | 4 | mode | 5 |
| 20 | 4 | cipher (CSSM id) | `0x80000001`, AES |
| 24 | 4 | key bits | 128 or 256 |
| 28 | 4 | PRNG algorithm | 91 |
| 32 | 4 | HMAC key bits | 160 |
| 36 | 16 | UUID | |
| 52 | 4 | block size | 512 |
| 56 | 8 | decrypted image size | the UDZO image's size |
| 64 | 8 | encrypted data offset | 122368 |
| 72 | 4 | key entries | 1 |
| 76 | 20 each | entry: type (u32), blob offset (u64), blob size (u64) | type 1 (password), at 96, 616 bytes |

A password blob: KDF (103 = PBKDF2) at 0, KDF PRNG at 4, iterations at 8 (370,370 to
454,545: macOS times them), salt size at 12 and a 32-byte salt field at 16 (20 used),
IV size at 48 and a 32-byte IV field at 52, wrapping key bits at 84 (192), wrapping
cipher at 88, padding at 92 (7, PKCS#7), mode at 96 (6, CBC), wrapped-key size at 100
and the wrapped key at 104.

The unlock: PBKDF2-HMAC-SHA1 of the password gives a 24-byte key, charged first with
`charge_key_derivation`. It decrypts the wrapped key in CBC mode. The fixtures wrap
with AES-192 (cipher `0x80000001`) and state an IV size of 8, but the IV is the
field's first 16 bytes (the 8 stated, then zeros); vfdecrypt and dmg2img describe 3DES
(cipher 17) with an 8-byte IV in older images, read too. The unwrapped bytes, after
their PKCS#7 padding, are the AES key, the 20-byte HMAC-SHA1 key and, on every
fixture, the mark `CKIE\0`. A password is `CONFIRMED` when the padding is right and
the decrypted image has a `koly` block in its last 512 bytes or, as an old layout
does, its first 512 (where the unencrypted reader looks), or, with no `koly`, when the
mark is there; a password that confirms by the mark alone unlocks a read-write
image, which is refused by name.

Block `n` of the image (block size bytes from `data offset + n * block size`) is
AES-CBC with the IV `HMAC-SHA1(hmac_key, n as a big-endian u32)[:16]`. The last block
is whole in the file; the bytes past the image size are padding. `EncryptedDmgSource`
decrypts a read's blocks in one CBC pass and then corrects the first 16 bytes of each
later block for its own IV. It keeps the first and last block of each read's span
in a cache of at most 16 blocks, so a later read that starts or ends in one of them
does not decrypt it again.

Every length is checked before the bytes it names are read: the version (2), cipher
(AES), block IV size (16 bytes), HMAC key size (160 bits), block size (512 or 4096)
and PBKDF2 iteration count (at most 2^31 - 1, `hashlib`'s limit) are
`UnsupportedFeatureError` otherwise; more than 16 key entries, or an entry over 4 KiB,
is `ResourceLimitError`; no key entries, an entry outside the header (between the entry
table and the encrypted data), 0 PBKDF2 iterations, a salt over 32 bytes, an IV over the
cipher's block, or a wrapped key that is not a whole number of blocks inside its entry
is `CorruptionError`; a file shorter than the encrypted data is `TruncatedError`. A
password entry that fails these checks is skipped when another password entry passes
them, and reported (`ARCHIVE_STRUCTURE_INCONSISTENT`, `structure="key_entry"`): a
password for it is rejected as wrong. With none left, the first entry's refusal is
raised. Non-zero bytes after the encrypted data are `ARCHIVE_TRAILING_DATA` (the first
MiB is looked at, as for an unencrypted image; `observed_bytes` counts from the end of
the last encrypted block). All of this runs before a password is asked for. Only the
blocks that hold the last and the first 512 bytes are decrypted to check a password.

### 2.2 Open and list

The open is a fixed amount of work (design §7), bounded on top by an open budget: the
physical bytes read plus the bytes decoded between the property list and the end of the
open stay within 64 MiB (`udif.OPEN_BUDGET`), else `ResourceLimitError`.

1. `koly` block: segmented images and images with no property list are refused by
   name; the data fork, property list and `koly` block must lie inside the file and not
   overlap. A code signature outside the file or overlapping another structure is
   `ARCHIVE_STRUCTURE_INCONSISTENT` (`structure="code_signature"`) and ignored. Non-zero
   bytes no structure covers are `ARCHIVE_TRAILING_DATA`.
2. Property list: at most 64 MiB, checked before a byte is read. Each `mish` table is
   checked (signature, version, run count against the `Data` length, every run inside
   the table and the data fork, a compressed run's stored length at most twice its
   decoded size plus 64 KiB, a decoded size at most 16 MiB) before its runs are kept,
   as packed arrays. Before they are allocated, they are weighed against
   `max_metadata_bytes`: 256 bytes per kept table (an empty table counts too) plus its
   name, and 36 bytes per declared run (terminators, comments and empty runs included).
   The weight is kept for the reader's life with what the listing holds, as APFS's
   trees are (`ReaderContext._keep_metadata`); a context without that hook holds the
   tables to the limit alone. Overlapping tables are `CorruptionError`.
3. Partitions: a GPT whose header and entry array pass their CRCs and whose geometry is
   sound (primary, else the backup at the last sector), else an Apple partition map
   whose entries all agree, else the run tables' ranges, else the whole disk. Either
   map is refused when two of its entries overlap. At most
   128 candidates. Each is probed: `H+`/`HX` at 1024 is HFS+/HFSX, `BD` an HFS volume,
   `NXSB` at 32 APFS. Names (GPT type, APM type, run table name) only describe; a
   disagreement is `ARCHIVE_STRUCTURE_INCONSISTENT`.
4. No HFS+ or APFS volume: an HFS wrapper is refused by name, anything else names the
   partitions found. Beside them, another partition with contents is
   `ARCHIVE_UNLISTED_DATA`.
5. Each HFS+ volume header is checked (block size, total blocks inside the partition),
   and a journaled volume's journal state: a pending or external journal is refused.
6. Each APFS container's block 0 is read at its declared block size (4 KiB to 64 KiB,
   a power of two) and its Fletcher-64 checked; the block count must fit the partition,
   the checkpoint ring the container, and Fusion and version 1 containers are refused.
   A damaged or refused container beside other volumes does not stop the open: a
   refused one is `ARCHIVE_UNLISTED_DATA`, a damaged one raises after the others are
   listed.

The first listing, per volume (`_VolumeWalk`):

- pass 1 (`read_catalog`): every folder's parent and name, the hard-link inodes in
  `\0\0\0\0HFS+ Private Data`, and the hidden folders, charged to
  `max_metadata_bytes`;
- the attributes tree (`read_attributes`), names and values up to 1 KiB kept (the
  decmpfs header whole), charged;
- pass 2 (`catalog_entries`): one member per folder and file record, in catalog order
  (parent id, then name), skipping the hidden folders' contents and the journal files.
  Each folder path it builds and caches is charged to `max_metadata_bytes`, so a deep
  chain inside a hidden folder is bounded too. A visible folder's path is charged
  again in its member's name, because both strings are kept.

Type precedence: hard-link Finder markers first (`hlnk`/`hfs+` file link,
`fdrp`/`MACS` directory link), then a non-zero BSD mode, then the Finder `slnk`/`rhap`
tags. The first path to an inode is the `FILE`; later ones are `HARDLINK` to it. With
several volumes, each volume's members sit under a top-level directory named after the
volume (D1), with `Untitled` and ` 1`, ` 2`, ... suffixes as macOS names mount points.

Damage in a catalog node stops that volume's listing: the members before it are
delivered, the other volumes are listed, then the error is raised. A record whose name
cannot be a path component (empty, `.`, `..`, or holding a NUL; a stored `/` is shown
as `:`) is left out with everything inside it when it is a folder, and the volume's
listing ends with `CorruptionError`, as for an orphan.

The first listing, per APFS container (`ApfsContainer.load`, also reached from
`archive_info()`):

- the checkpoint: every block of the descriptor ring is read (at most 65,536, and at
  most 64 MiB read and decoded, `apfs.SCAN_BUDGET`, counted by `UdifImage.budget`), and
  the newest container superblock with a good checksum whose checkpoint is complete is
  used: its span ends at itself, every checkpoint-map block before it has a good
  checksum and the superblock's transaction, and the last one is marked last. A newer
  incomplete one is `ARCHIVE_STRUCTURE_INCONSISTENT` (`structure="apfs_checkpoint"`);
- the container object map, read whole: for each object id the entry with the highest
  transaction at or before the checkpoint's, a deletion included (a deleted winner is
  absent);
- each volume superblock through it. An encrypted volume (no `APFS_FS_UNENCRYPTED`, or
  an encrypted object-map entry) or a sealed one is not listed
  (`ARCHIVE_UNLISTED_DATA` beside other volumes, `UnsupportedFeatureError` when it is
  the only kind); a lost one fails the listing after the others;
- each volume's object map, read whole. An entry there marked encrypted, in a volume
  whose flags say it is not, is damage to the node it maps (a damaged key range), not a
  refusal: the other volumes are still listed.

What APFS keeps for the life of the archive (the object maps and each filesystem tree,
which member reads need) is counted against `max_metadata_bytes` on the listing's own
tracker (`DmgReader._keep`, through the adapter's `ReaderContext._keep_metadata` and
`ListingLimitTracker.keep`), so it counts together with the members listed and, for an
archive inside another, with what the outer levels keep. Unlike `charge_metadata`, the
charge stays across listings.

Per APFS volume, at the first listing (`ApfsVolume.walk`, then `_ApfsWalk`): one walk of
the filesystem tree in key order keeps the inodes, directory records, extended
attributes and extents (as packed arrays). The listing starts at the root directory
(inode 2), a directory at a time, each directory's entries sorted by name; the private
directory (inode 3) is never reached. The mode decides the type (a directory record
whose type disagrees is `ARCHIVE_STRUCTURE_INCONSISTENT`, `structure="member_type"`).
The first path to an inode is the member, later ones `HARDLINK` to it. A symlink's
target is its `com.apple.fs.symlink` attribute. Names are passed through as stored
(APFS preserves normalization: `café.txt` is composed on the fixtures, decomposed on
HFS+). A name holding `/` or a NUL, an empty name, `.` or `..`, an entry naming an
inode the tree does not hold, and a directory reached twice are left out and fail the
listing after the others.

**Damaged nodes (D7).** Every object's Fletcher-64, type, own id and transaction are
checked. A node that fails, or does not parse, or whose keys are out of order, is
skipped whole: the walk records the range of keys its verified parent gave it
(`apfs.Damage`) and goes on with its siblings; a damaged root damages the whole range. A
leaf whose checksum passes but holds a record that does not parse is skipped the same
way: nothing from it is kept. The ranges are merged and kept sorted
(`apfs.DamageIndex`), so each lookup is a bisection, whatever the number of damaged
nodes, and each range counts against `max_metadata_bytes` as the walk finds it: an index
node whose entries all name a missing child stops at the cap. Keys are compared on
(object id, record type, extent offset) only: names are left out, since hashed directory
keys may collide, so a boundary counts as inside. Then:

- a member whose inode record, or whose symlink or decmpfs attribute, may be in a
  damaged range is not listed; other attributes in one leave it listed with
  `MEMBER_HEADER_RECORD_SKIPPED`;
- a file read that reaches a hole an extent from a damaged range could fill raises
  `CorruptionError`; holes elsewhere read as zeros;
- an object-map lookup whose newer entry may be in a damaged node raises
  `CorruptionError` ("mapped by a damaged node"), not "not found";
- the listing ends with `CorruptionError` naming the first damaged block.

With no damaged node, directory records in a directory the walk from the root does not
reach end the listing with `CorruptionError` naming their count, as HFS+ orphans do.
The parent of the root (id 1) and the private directory (id 3) are not reached by
design and are left out.

### 2.3 Member data

A file's data fork is a `block_stream` of 1 MiB pieces over its extents; each piece
reads the virtual disk through `UdifSource`, which decodes the runs it covers (eight
decoded runs are cached).

**Member order.** Members come in listing order (§2.2), one volume after another. The
one exception: when reading a volume's files in that order would decode a compressed run
a second time, its members come in data order. The check replays the eight-run cache
over each file's disk ranges (an HFS+ fork's eight extents in its record, an APFS
stream's extents), with nothing decoded (`UdifImage.decodes_twice`). The replay's work
is one step per range plus a budget of steps across run boundaries (4 × the run count +
1024). Disjoint ranges cross each boundary once at most, so they never run out, whatever
their count or order. Ranges that overlap over many runs can (a crafted image, or many
APFS clones of one file); the listing is then sorted, which changes only the order.
Then the order is: directories and the other members with no data ranges, in listing
order (a directory still comes before its contents); the files, by the disk offset of
their first byte; the hard links, in listing order (each after the member it names).
Every fixture and every builder image in the tests keeps listing order: `hdiutil` lays
files out as it copies them. A crafted layout, where each file would decode a whole run
again, is sorted (§4). The volume's walk is held whole to sort it, while it fits
`max_members` and `max_metadata_bytes`; past either, it comes in listing order and the
listing stops at the limit.

**Runs decoded again.** What data order cannot fix is still charged. Each decode of a
run that a member read already decoded adds its decoded size to one total per image,
held to `DecoderLimits.max_ratio` times the image file's size, past
`ratio_activation_threshold`, with the error the checksum pass raises
(`AlwaysStopResourceLimitError`, which stops an extraction). Against the input, not the
output: a run is up to 16 MiB, so extents of 21 KiB or more (16 MiB / 800), each costing
a whole run, would stay under any multiple of what they return. A run counts as decoded
again when:

- the same member stream decoded it before (a file whose extents cycle over more runs
  than the cache holds, or a read that seeks back over them);
- or the stream's pass decoded it before. Member streams opened in listing order
  (`stream_members()`, `extract_all`, or `open()`/`read()` in that order, skipped
  members allowed) are one pass. A stream opened for an earlier member starts a new
  pass, so reads in an order the caller picks are charged within each stream only.

Reading each member front to back, over a listing where each run decodes once, charges
nothing. The first decode of a run is never charged; §7 says what that leaves.

A compressed file (`UF_COMPRESSED` and `com.apple.decmpfs`)
decodes its 64 KiB chunks one at a time from the inline attribute or the resource fork.
Every member read counts in the archive-wide ratio, whatever runs serve the bytes.

Member-local refusals raise at read, and the other members stay readable: a missing
hard-link inode, a compressed flag without its attribute, an extent past the volume, a
directory hard link, an unknown decmpfs type, an unknown run type.

An APFS file's data stream is read through its extents in 1 MiB pieces
(`apfs.stream_reader`). Gaps between extents, extents at block 0 and the range past the
last extent read as zeros (the member is `is_sparse`), unless a damaged range could
hold the missing extent. Overlapping extents, an extent past the container and an
extent with an encryption id fail that file's read. Clones are extents that share
blocks and need nothing special. A compressed file (`UF_COMPRESSED`) reads through
`com.apple.decmpfs` and the `com.apple.ResourceFork` attribute.

### 2.4 Verify

Each `blkx` table stores a CRC-32 of its runs: every run but the ignore runs, decoded,
in sector order, zero fill included. That CRC covers the filesystem's metadata and free
space too, and members overlap (hard links, decmpfs), so member reads cannot stand in
for it. `verify_all()` runs a separate pass (`DmgReader._check_partitions`, registered
through `ReaderContext._spanning_pass`) after it has read the members:

- A file is `CHECKSUM` from the listing when its whole partition is covered by runs of
  tables that carry a CRC-32, with no gap; otherwise `LENGTH`, and the pass never runs
  for it. Plain reads do not run the pass, so they leave files at `LENGTH`.
- The unit is a whole table, never a partition range: one table that straddles two
  partitions is decoded whole, and a mismatch fails the files of both.
- The volumes of one APFS container share their partition's check: a mismatch fails
  the files of every volume in it.
- One run is in memory at a time, not cached, and raw runs go to the CRC in 1 MiB
  slices. A zero-fill run is folded in with the zero-extension operator
  (`udif.crc32_zeros`), so a 2^50-byte one costs a few dozen small matrix products.
- The `koly` block's data-fork CRC-32 (the stored bytes read once more) and master
  checksum (a CRC-32 of the tables' CRC-32s in property-list order) are checked in the
  same pass, and a mismatch fails every checked file.
- The runs the pass decodes or reads, raw ones included (runs may share stored bytes),
  are held to `DecoderLimits.max_ratio` against the file's size, on their own total.
  Past it, or on a codec the policy refuses, the pass stops and the files it did not
  prove are failures saying the check did not run.
- The pass runs once per reader; later `verify_all()` calls reuse its result.

### 2.5 Extract

Through the shared extraction path. Extended attributes and resource forks are listed in
`extra` (D2) and not written.

### 2.6 Write

Not shipped.

## 3. In the wild

`hdiutil` writes UDZO (zlib), UDBZ (bzip2), ULFO (LZFSE), ULMO (xz), UDRO (raw) and, in
old images, UDCO (ADC). UDRW is a raw disk with no `koly` block, which is not UDIF and
is not read (a raw GPT disk reader would reuse `disk_partitions.py` and `hfsplus.py`).
Every image measured holds one HFS+ or one APFS volume in a GPT; two of the 41 corpus
images had no partition map. `hdiutil` marks every file with `com.apple.provenance`.

## 4. Threat surface

The row in [`threat-model.md`](../threat-model.md). In short: every range and count is
checked before it is used (§2.2); zero-fill runs make large disks from tiny files, so
member reads are bounded by the archive-wide ratio and the extraction limits, and every
run a listing decodes, a cache miss included, counts toward
`ListingLimits.max_decoded_bytes`; files whose layout would decode runs again in listing
order are listed in data order, and a run a member stream or a pass in listing order
decodes again counts toward `max_ratio` (§2.3); the in-house ADC, LZFSE and LZVN
decoders are bounded by their output length; `verify_all()`'s checksum pass holds the
runs it decodes to the archive-wide ratio on its own total (§2.4); B-tree leaf chains,
folder parent chains and overflow extents are loop-checked; the open is bounded by the
open budget. APFS: every object's Fletcher-64 is checked and a bad node is skipped with
its key range remembered (§2.2), B-tree nodes reached twice, directories reached twice
and B-trees deeper than 32 levels are damage, the checkpoint scan has its own 64 MiB
budget, and what the trees keep counts against `max_metadata_bytes`; a file of 1 TiB of
holes stops at the ratio guard (`test_a_zero_extent_bomb_stops_at_the_ratio_guard`). The
fuzz targets are `dmg` (HFS+) and `dmg_apfs` in `tests/atheris_fuzz/`. Encrypted images:
the header's counts and lengths are checked before any read (§2.1.1), the iteration
count is charged to `max_key_derivation_rounds` before each derivation, and the image
is decrypted a read at a time, so its memory is the reads' own; the `dmg` seeds hold
one encrypted image.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A `.dmg` that opens as a zip or not at all | **format** | No `koly` block: a raw disk (UDRW) or another format renamed (§3) |
| `encrypted APFS volume` or `sealed APFS volume` | **archivey** | Native APFS encryption and sealed (system) volumes are not read |
| `café.txt` composed on APFS, decomposed on HFS+ | **format** | Both store the name as written; HFS+ stores it decomposed |
| `the disk image is encrypted: pass password= to read it` | **format** | An `hdiutil -encryption` image (§2.1.1); a wrong password is `Wrong password for the disk image` |
| `read-write (raw disk) image` after the right password | **archivey** | An encrypted UDRW image: the decrypted data is a raw disk, which is not read (§3) |
| `version 1 (cdsaencr)` | **archivey** | Pre-10.5 encrypted images are not read |
| A hard link lists as `HARDLINK`, not two files | **archivey** | Links point backward (§2.2); 7-Zip writes both as empty files |
| `com.apple.provenance` on every member's `extra["dmg.xattrs"]` | **format** | `hdiutil` adds it |
| A name with `:` | **format** | HFS+ stores `/` in names; the Mac and 7-Zip show it as `:` |

## 6. Decisions

The plan's decisions D1 to D8 are in
`openspec/changes/archive/2026-11-27-dmg-reader/design.md` §2. Choices made in Part B
that the plan left open:

- **One generic diagnostic for structure disagreements.**
  `ARCHIVE_STRUCTURE_INCONSISTENT` with `ArchiveStructureContext.structure` naming
  which, rather than a code per case.
- **The catalog walk is two passes**, so folder paths and hard-link inodes are known
  before any member is made; a damaged node returns what pass 1 found, so pass 2 can
  deliver the members before it.
- **Folder thread records only cross-check the paths.** The folder records decide
  them; a thread that is missing, unreadable, or names another parent or name is one
  `ARCHIVE_STRUCTURE_INCONSISTENT` per volume (`structure="folder_thread"`).
- **Run tables are bounded against `max_metadata_bytes` at open by the reader**, because
  `charge_metadata` is for listing only.
- **A decmpfs type 10 chunk is its raw block after a 0xCC byte.** The macOS check
  (section 8) found the kernel reads that layout and refuses the same offset table
  without the byte, so a chunk without it is `CorruptionError`.

Choices made in Part E:

- **APFS object maps and filesystem trees are read whole and kept**, counted against
  `max_metadata_bytes` for the life of the archive, rather than searched per lookup.
  Simpler, and the damaged-range rules need the whole walk anyway.
- **The listing order is a directory at a time from the root**, entries sorted by
  stored name, not the tree's key order (which on a hashed volume is hash order).
- **A damaged APFS container beside other volumes fails after them**, not at open.
- **Sibling-link records are cross-checked against `nlink`** for each listed file:
  a mismatch is `ARCHIVE_STRUCTURE_INCONSISTENT` (`structure="link_count"`), not a
  refusal (design §6A.5). Hashed-name hashes are not checked (optional in §6A.5).
- **Extents and names are compared on (object id, type, offset) for damaged ranges**,
  so a damaged range's boundary counts as inside (conservative).

Choices made in Part G:

- **The key wrap is read by its cipher field**, AES (what every fixture holds) or
  3DES (what older images hold, per vfdecrypt), where the plan named 3DES only.
- **Block sizes 512 and 4096 are read.** The fixtures use 512; the plan expected 4096
  only, as vfdecrypt describes.
- **A password is confirmed by the `koly` block, else by the `CKIE` mark**, so the
  right password on an encrypted read-write image gets its own refusal rather than
  "wrong password".

Choices made after the sweep:

- **Data order over listing order, only when listing order would decode a run twice.**
  The same rule as CAB folders ([CAB §6](cab.md#6-decisions)) and SquashFS fragments
  ([SquashFS §6](squashfs.md#6-decisions)), asked for by the maintainer (2026-11-23).
  The sweep's image of 40 files whose extents cycle over 9 runs of 16 MiB decoded
  5.35 GB for 1.3 MB of output in listing order; sorted, it decodes 15 runs (252 MB).
  Listing order is kept whenever the replay of the eight-run cache says each run
  decodes once, which is every fixture and builder image; the order changes for
  `members()` too, since there is one member order. Rejected: charging every cache miss
  against `max_ratio` times the file size (an honest image of 5,000 files of 200 bytes
  read in random order decoded 519 MB from a 649 KB image and was refused).
- **What sorting leaves is charged, against the image's file size, once per image.**
  A run decoded again by the same member stream or the same pass in listing order adds
  to one total, held to `max_ratio` times the file size like the checksum pass. A first
  charge against each member's size, then against the bytes a pass returned, let
  extents of 24 KiB through (6.25 GB decoded from a 190 KB image): a whole run per
  extent stays under any multiple of the output. Reads in an order the caller picks
  are charged within each stream only, so reading small files in any order is never
  charged. The 5,000-file image and every fixture read and extract with no run decoded
  again, in listing order and in random order.

## 7. Open questions

- A run decoded once is never charged. A file of one-block extents, each in its own
  16 MiB run, decodes up to 4,096 times its size, bounded by the run count (36 bytes a
  run against `max_metadata_bytes`). Reads in an order the caller picks are charged
  only within each stream, not across members: that work is the caller's choice.
  Recorded in [threat-model.md](../threat-model.md) §5.
- No fixture has a 3DES key wrap or 4096-byte blocks: both follow vfdecrypt and are
  checked only against the test writer.

- Journal replay (a volume with pending transactions is refused).
- Whether any current tool still writes `koly` at offset 0.
- APFS snapshots (only the live tree is listed), encrypted volumes, sealed volumes,
  Fusion containers.
- 7-Zip 23.01 differs on two APFS sparse shapes the reader treats as holes: a gap with
  no extent (7-Zip: Data Error) and an extent at block 0 (7-Zip reads the container's
  block 0). The Linux APFS driver reads both as holes. A real sample of either would
  settle what macOS writes.

## 8. Verify

```bash
./scripts/test.sh tests/test_dmg.py tests/test_dmg_apfs.py tests/test_udif.py \
    tests/test_dmg_build.py tests/test_detection_workspace.py tests/test_lzfse_decoder.py
```

On macOS, `scripts/investigations/dmg_macos_check.py` checks the test writer's images
with `hdiutil verify`, `fsck_hfs -n` and a read-only mount, and archivey against fresh
`hdiutil create` images in every format. The `dmg-macos` workflow runs it weekly and
after a merge that touches the DMG code; the table is its job summary.

| Claim |
| --- |
| Every unencrypted HFS+ `hdiutil` fixture lists and reads as macOS mounts it (`test_an_hdiutil_image_lists_and_reads_as_macos_mounts_it`) |
| Every run codec and partition layout reads (`test_every_codec_and_layout_reads`) |
| Every APFS `hdiutil` fixture lists and reads as macOS mounts it (`test_an_hdiutil_apfs_image_lists_and_reads_as_macos_mounts_it`) |
| APFS: plain and hashed keys, every layout and codec, sparse files and clones (`tests/test_dmg_apfs.py`) |
| APFS damage: a checksum failure in every object kind is `CorruptionError`; a lost leaf fails only what it held, and a hole never reads as zeros when its extent may be lost (`test_a_lost_extent_leaf_*`) |
| Every encrypted `hdiutil` fixture lists and reads as macOS mounts it with the password `archivey`, and asks for it without (`test_an_encrypted_hdiutil_image_asks_for_its_password`) |
| Encrypted test-writer images with each key size, key wrap and block size read as the plain image (`test_an_encrypted_builder_image_reads_as_the_plain_one`); a damaged header is refused before any password (`test_a_damaged_encrypted_header_is_refused_before_any_password`) |
| 7-Zip extracts the same bytes, with the listed differences (`test_7zip_*`) |
| dpp-py and libyal read the same bytes, with their gaps pinned so a fixed gap fails the test (`tests/test_dmg_oracles.py`) |
| Damage fails the member it touches, and a damaged catalog node delivers the members before it |
| `verify_all()` raises every file of an `hdiutil` image to `CHECKSUM`, decoding each table once (`test_verify_all_raises_every_file_of_an_hdiutil_image_to_checksum`) |
| A changed byte no member reads fails the files of its partition, and a table over two partitions fails both (`test_a_change_no_member_reads_is_caught_by_verify_all`, `test_one_table_over_two_partitions_is_checked_whole`) |
| A 2^50-byte zero-fill run is checked in under five seconds (`test_a_zero_fill_run_of_a_petabyte_is_checked_in_no_time`) |

## 9. References

- Apple TN1150, "HFS Plus Volume Format".
- Apple, *Apple File System Reference* (2020).
- 7-Zip `CPP/7zip/Archive/DmgHandler.cpp`, `HfsHandler.cpp`, `ApfsHandler.cpp`,
  `ApmHandler.cpp`, `GptHandler.cpp`.
- UEFI 2.10 §5 (GPT).
- The plan: `openspec/changes/archive/2026-11-27-dmg-reader/`.
- User docs: `docs/formats.md` §Disk images.
