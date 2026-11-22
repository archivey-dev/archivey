# DMG (UDIF disk images)

Current maintainer truth for Apple's disk images. archivey reads UDIF images that hold
HFS+, HFSX or APFS volumes; encrypted images are recognised and refused by name until
the plan's part G lands (`openspec/changes/dmg-reader/`). Detection's
trailer step is on [`topics/detection.md`](../topics/detection.md) §2.4. This page is
the format.

## At a glance

| | |
| --- | --- |
| Read | Yes: UDIF (`koly` version 4) with every run codec (zero fill, raw, ignore, ADC, zlib, bzip2, LZFSE, xz), GPT, Apple partition map or no map, HFS+, HFSX and APFS (unencrypted, unsealed volumes; the live tree, not snapshots) |
| Write | **Not shipped** |
| Source | Seekable only (`required_source` is `SEEKABLE`): the run tables are at the end of the image and the filesystem metadata anywhere in the disk. A pipe is refused, or spooled by the caller |
| Listing cost | The open reads the `koly` block, the property list and its run tables, the partition map, a 4 KiB probe of each partition, each HFS+ volume header (plus two 512-byte journal reads) and each APFS container's block 0; the first listing walks each HFS+ catalog twice and the attributes tree once, and for APFS scans the checkpoint ring, reads the object maps whole and walks each filesystem tree once |
| Core dependencies | None. ADC, LZFSE and LZVN are decoded in Python; zlib, bzip2 and xz through `ReaderContext.decompress` |
| Refuses | Encrypted images (`encrcdsa`, `cdsaencr`), segmented images, images with no property list, HFS wrappers, HFS+ volumes whose journal may hold changes, APFS Fusion and prerelease-layout containers, encrypted and sealed APFS volumes, unknown run types (at read), directory hard links (at read) |
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
   as packed arrays charged against `max_metadata_bytes`. Overlapping tables are
   `CorruptionError`.
3. Partitions: a GPT whose header and entry array pass their CRCs and whose geometry is
   sound (primary, else the backup at the last sector), else an Apple partition map
   whose entries all agree, else the run tables' ranges, else the whole disk. At most
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

Type precedence: hard-link Finder markers first (`hlnk`/`hfs+` file link,
`fdrp`/`MACS` directory link), then a non-zero BSD mode, then the Finder `slnk`/`rhap`
tags. The first path to an inode is the `FILE`; later ones are `HARDLINK` to it. With
several volumes, each volume's members sit under a top-level directory named after the
volume (D1), with `Untitled` and ` 1`, ` 2`, ... suffixes as macOS names mount points.

Damage in a catalog node stops that volume's listing: the members before it are
delivered, the other volumes are listed, then the error is raised.

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
- each volume's object map, read whole.

What APFS keeps for the life of the archive (the object maps and each filesystem tree,
which member reads need) is counted against `max_metadata_bytes` by the reader itself
(`DmgReader._keep`), since `charge_metadata` lasts only for a listing.

Per APFS volume, at the first listing (`ApfsVolume.walk`, then `_ApfsWalk`): one walk of
the filesystem tree in key order keeps the inodes, directory records, extended
attributes and extents (as packed arrays). The listing starts at the root directory
(inode 2), a directory at a time, each directory's entries sorted by name; the private
directory (inode 3) is never reached. The mode decides the type (a directory record
whose type disagrees is `ARCHIVE_STRUCTURE_INCONSISTENT`, `structure="member_type"`).
The first path to an inode is the member, later ones `HARDLINK` to it. A symlink's
target is its `com.apple.fs.symlink` attribute. Names are passed through as stored
(APFS preserves normalization: `café.txt` is composed on the fixtures, decomposed on
HFS+). A name holding `/`, an empty name, `.` or `..`, an entry naming an inode the
tree does not hold, and a directory reached twice are left out and fail the listing
after the others.

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
decoded runs are cached). A compressed file (`UF_COMPRESSED` and `com.apple.decmpfs`)
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

### 2.4 Extract

Through the shared extraction path. Extended attributes and resource forks are listed in
`extra` (D2) and not written.

### 2.5 Write

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
`ListingLimits.max_decoded_bytes`; the in-house ADC, LZFSE and LZVN decoders are bounded
by their output length; B-tree leaf chains, folder parent chains and overflow extents
are loop-checked; the open is bounded by the open budget. APFS: every object's
Fletcher-64 is checked and a bad node is skipped with its key range remembered (§2.2),
B-tree nodes reached twice, directories reached twice and B-trees deeper than 32 levels
are damage, the checkpoint scan has its own 64 MiB budget, and what the trees keep
counts against `max_metadata_bytes`; a file of 1 TiB of holes stops at the ratio guard
(`test_a_zero_extent_bomb_stops_at_the_ratio_guard`). The fuzz targets are `dmg` (HFS+)
and `dmg_apfs` in `tests/atheris_fuzz/`.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A `.dmg` that opens as a zip or not at all | **format** | No `koly` block: a raw disk (UDRW) or another format renamed (§3) |
| `encrypted APFS volume` or `sealed APFS volume` | **archivey** | Native APFS encryption and sealed (system) volumes are not read |
| `café.txt` composed on APFS, decomposed on HFS+ | **format** | Both store the name as written; HFS+ stores it decomposed |
| `encrypted DMG disk image` | **archivey** | Encryption is part G of the plan |
| A hard link lists as `HARDLINK`, not two files | **archivey** | Links point backward (§2.2); 7-Zip writes both as empty files |
| `com.apple.provenance` on every member's `extra["dmg.xattrs"]` | **format** | `hdiutil` adds it |
| A name with `:` | **format** | HFS+ stores `/` in names; the Mac and 7-Zip show it as `:` |

## 6. Decisions

The plan's decisions D1 to D8 are in `openspec/changes/dmg-reader/design.md` §2.
Choices made in Part B that the plan left open:

- **One generic diagnostic for structure disagreements.**
  `ARCHIVE_STRUCTURE_INCONSISTENT` with `ArchiveStructureContext.structure` naming
  which, rather than a code per case.
- **The catalog walk is two passes**, so folder paths and hard-link inodes are known
  before any member is made; a damaged node returns what pass 1 found, so pass 2 can
  deliver the members before it.
- **Folder thread records are not cross-checked yet** (deferred to Part D).
- **Run tables are bounded against `max_metadata_bytes` at open by the reader**, because
  `charge_metadata` is for listing only.

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

## 7. Open questions

- decmpfs type 10 (raw in the resource fork) has no real sample; it is read with the
  type 8 offset table.
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

| Claim |
| --- |
| Every unencrypted HFS+ `hdiutil` fixture lists and reads as macOS mounts it (`test_an_hdiutil_image_lists_and_reads_as_macos_mounts_it`) |
| Every run codec and partition layout reads (`test_every_codec_and_layout_reads`) |
| Every APFS `hdiutil` fixture lists and reads as macOS mounts it (`test_an_hdiutil_apfs_image_lists_and_reads_as_macos_mounts_it`) |
| APFS: plain and hashed keys, every layout and codec, sparse files and clones (`tests/test_dmg_apfs.py`) |
| APFS damage: a checksum failure in every object kind is `CorruptionError`; a lost leaf fails only what it held, and a hole never reads as zeros when its extent may be lost (`test_a_lost_extent_leaf_*`) |
| Encrypted images are refused by name |
| 7-Zip extracts the same bytes, with the listed differences (`test_7zip_*`) |
| Damage fails the member it touches, and a damaged catalog node delivers the members before it |

## 9. References

- Apple TN1150, "HFS Plus Volume Format".
- Apple, *Apple File System Reference* (2020).
- 7-Zip `CPP/7zip/Archive/DmgHandler.cpp`, `HfsHandler.cpp`, `ApfsHandler.cpp`,
  `ApmHandler.cpp`, `GptHandler.cpp`.
- UEFI 2.10 §5 (GPT).
- The plan: `openspec/changes/dmg-reader/`.
- User docs: `docs/formats.md` §Disk images.
