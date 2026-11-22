# DMG (UDIF disk images)

Current maintainer truth for Apple's disk images. archivey reads UDIF images that hold
HFS+ or HFSX volumes; APFS volumes and encrypted images are recognised and refused by
name until the plan's parts E and G land (`openspec/changes/dmg-reader/`). Detection's
trailer step is on [`topics/detection.md`](../topics/detection.md) §2.4. This page is
the format.

## At a glance

| | |
| --- | --- |
| Read | Yes: UDIF (`koly` version 4) with every run codec (zero fill, raw, ignore, ADC, zlib, bzip2, LZFSE, xz), GPT, Apple partition map or no map, HFS+ and HFSX |
| Write | **Not shipped** |
| Source | Seekable only (`required_source` is `SEEKABLE`): the run tables are at the end of the image and the filesystem metadata anywhere in the disk. A pipe is refused, or spooled by the caller |
| Listing cost | The open reads the `koly` block, the property list and its run tables, the partition map, a 4 KiB probe of each partition, and each HFS+ volume header (plus two 512-byte journal reads); the first listing walks each catalog twice and the attributes tree once |
| Core dependencies | None. ADC, LZFSE and LZVN are decoded in Python; zlib, bzip2 and xz through `ReaderContext.decompress` |
| Refuses | Encrypted images (`encrcdsa`, `cdsaencr`), APFS-only images, segmented images, images with no property list, HFS wrappers, HFS+ volumes whose journal may hold changes, unknown run types (at read), directory hard links (at read) |
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
```

`dmg_reader.py` ties them: `DmgReader` opens the image and each volume, and lists the
catalogs.

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
4. No HFS+ volume: an HFS wrapper or an APFS container is refused by name, anything
   else names the partitions found. Beside HFS+, another partition with contents is
   `ARCHIVE_UNLISTED_DATA`.
5. Each HFS+ volume header is checked (block size, total blocks inside the partition),
   and a journaled volume's journal state: a pending or external journal is refused.

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

### 2.3 Member data

A file's data fork is a `block_stream` of 1 MiB pieces over its extents; each piece
reads the virtual disk through `UdifSource`, which decodes the runs it covers (eight
decoded runs are cached). A compressed file (`UF_COMPRESSED` and `com.apple.decmpfs`)
decodes its 64 KiB chunks one at a time from the inline attribute or the resource fork.
Every member read counts in the archive-wide ratio, whatever runs serve the bytes.

Member-local refusals raise at read, and the other members stay readable: a missing
hard-link inode, a compressed flag without its attribute, an extent past the volume, a
directory hard link, an unknown decmpfs type, an unknown run type.

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
`ListingLimits.max_decoded_bytes`; the in-house ADC, LZFSE and LZVN decoders are bounded
by their output length; `verify_all()`'s checksum pass holds the runs it decodes to the
archive-wide ratio on its own total (§2.4); B-tree leaf chains, folder parent chains
and overflow extents are loop-checked; the open is bounded by the open budget. The fuzz
target is `dmg` in `tests/atheris_fuzz/`.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A `.dmg` that opens as a zip or not at all | **format** | No `koly` block: a raw disk (UDRW) or another format renamed (§3) |
| `UnsupportedFeatureError: APFS disk images are not supported yet` | **archivey** | APFS is part E of the plan |
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

## 7. Open questions

- decmpfs type 10 (raw in the resource fork) has no real sample; it is read with the
  type 8 offset table.
- Journal replay (a volume with pending transactions is refused).
- Whether any current tool still writes `koly` at offset 0.

## 8. Verify

```bash
./scripts/test.sh tests/test_dmg.py tests/test_udif.py tests/test_dmg_build.py \
    tests/test_detection_workspace.py tests/test_lzfse_decoder.py
```

| Claim |
| --- |
| Every unencrypted HFS+ `hdiutil` fixture lists and reads as macOS mounts it (`test_an_hdiutil_image_lists_and_reads_as_macos_mounts_it`) |
| Every run codec and partition layout reads (`test_every_codec_and_layout_reads`) |
| Encrypted and APFS images are refused by name |
| 7-Zip extracts the same bytes, with the listed differences (`test_7zip_*`) |
| Damage fails the member it touches, and a damaged catalog node delivers the members before it |
| `verify_all()` raises every file of an `hdiutil` image to `CHECKSUM`, decoding each table once (`test_verify_all_raises_every_file_of_an_hdiutil_image_to_checksum`) |
| A changed byte no member reads fails the files of its partition, and a table over two partitions fails both (`test_a_change_no_member_reads_is_caught_by_verify_all`, `test_one_table_over_two_partitions_is_checked_whole`) |
| A 2^50-byte zero-fill run is checked in under five seconds (`test_a_zero_fill_run_of_a_petabyte_is_checked_in_no_time`) |

## 9. References

- Apple TN1150, "HFS Plus Volume Format".
- 7-Zip `CPP/7zip/Archive/DmgHandler.cpp`, `HfsHandler.cpp`, `ApmHandler.cpp`,
  `GptHandler.cpp`.
- UEFI 2.10 §5 (GPT).
- The plan: `openspec/changes/dmg-reader/`.
- User docs: `docs/formats.md` §Disk images.
