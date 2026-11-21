## ADDED Requirements

### Requirement: Read a UDIF image as a virtual disk

The system SHALL read a UDIF image (`ArchiveFormat.DMG`) through its `koly` block, its
XML property list and its `mish` run tables, and serve the virtual disk they describe.
The property list SHALL be parsed with `plistlib` and refused over 64 MiB with
`ResourceLimitError`. Runs of type zero fill, raw, ignore (free space), ADC, zlib,
bzip2, LZFSE and xz SHALL be read; a comment run SHALL be skipped and the terminator
SHALL end the table. Each compressed run SHALL decode to exactly its sector count × 512
bytes, through `ReaderContext.decompress` for zlib, bzip2 and xz and through archivey's
own pure-Python decoders for LZFSE, LZVN and ADC, whose output is bounded by the run's
size. A run that decodes to another length, runs that overlap or leave their table's
sector range, and stored ranges outside the data fork SHALL raise `CorruptionError`; a
file that ends inside a run or the property list SHALL raise `TruncatedError`. An
unknown run type, and a compressed run that declares more than 16 MiB decoded, SHALL
raise `UnsupportedFeatureError` from the read that needs it, leaving other members
readable. The format SHALL require a seekable source. Opening SHALL read only the `koly`
block, the property list and the filesystem's first header: no work proportional to the
image.

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

### Requirement: Pick the filesystem partitions of a disk image

The system SHALL take each `blkx` entry as a partition, cross-checked with the disk's
GPT or Apple Partition Map when there is one, and SHALL read a partition as HFS+ when
offset 1024 holds `H+` (version 4) or `HX` (version 5), and as APFS when offset 32 holds
`NXSB`. An image with no such partition SHALL raise `UnsupportedFeatureError` naming the
partitions found. With one filesystem volume, its files SHALL be listed at the archive
root; with several, each volume's files SHALL be listed under a top-level directory
named after the volume. The volume name, filesystem, partition scheme, run codecs and
encryption SHALL be in `archive_info().extra` under `dmg.` keys.

#### Scenario: partitions

| Case | Expected |
| --- | --- |
| GPT, one `Apple_HFS` partition | Its files at the root; `dmg.partition_scheme` `GPT` |
| Apple Partition Map | Read the same way; `APM` |
| No partition map, one whole-disk volume | Read; `none` |
| Two HFS+ volumes | Each under its volume name |
| Only an MBR and free space | `UnsupportedFeatureError` |

### Requirement: List an HFS+ volume as the Mac mounts it

The system SHALL list an HFS+ or HFSX volume from its catalog B-tree: folders as
`DIRECTORY`, files as `FILE`, `slnk` files as `SYMLINK` with the data fork as target,
devices, FIFOs and sockets as `OTHER`. A `/` stored in a name SHALL be listed as `:`,
and names SHALL keep their stored Unicode form. The private hard-link folders
(`\0\0\0\0HFS+ Private Data`, `.HFS+ Private Directory Data\r`) and the journal files of
a journaled volume SHALL NOT be listed. A file hard link SHALL list its first path in
listing order as `FILE` with the data, and each later path as `HARDLINK` to it. A
directory hard link SHALL raise `UnsupportedFeatureError` for that member. Mode, owner,
modification time and birth time SHALL come from the catalog record. A B-tree node or a
folder reached twice, an extent outside the volume, and a record outside its node SHALL
raise `CorruptionError`; members listed before the damage SHALL be delivered first.
Extended attribute names, and values up to 1 KiB, SHALL be listed in
`ArchiveMember.extra` and SHALL NOT be written on extraction.

#### Scenario: HFS+ listing

| Case | Expected |
| --- | --- |
| The `hdiutil` fixture tree | `Applications` → `/Applications`, `link-rel` → `hello.txt`, `sub dir/hardlink.txt` a `HARDLINK` to `hello.txt`, every file's SHA-256 as macOS lists it |
| The private hard-link folders | Not listed |
| `hello.txt` | `extra` lists `com.example.test` |
| A catalog leaf whose next link points back | `CorruptionError` after the members before it |
| A `/` in a stored name | Listed with `:` |

### Requirement: Decode transparently compressed files

A file flagged `UF_COMPRESSED` with a `com.apple.decmpfs` attribute SHALL be read
through it: types 1 and 9 (stored inline), 3 and 4 (zlib inline or in the resource
fork), 7 and 8 (LZVN), 10 (stored in the resource fork), 11 and 12 (LZFSE). The member's
size SHALL be the size the attribute declares, the data SHALL be decoded 64 KiB block by
block, and a block or total of another length SHALL raise `CorruptionError`. Any other
type SHALL raise `UnsupportedFeatureError` for that member. The `com.apple.decmpfs`
attribute and the resource fork of such a file SHALL NOT be listed in `extra`. The same
rules SHALL apply on HFS+ and on APFS.

#### Scenario: decmpfs

| Case | Expected |
| --- | --- |
| `compressed.txt` in the fixtures (type 8, 360 000 bytes) | The bytes of `text.txt` |
| Each type built by the test writer | The data |
| Type 99 | `UnsupportedFeatureError` at that member; others read |

### Requirement: List an APFS volume

The system SHALL read an APFS container from the newest valid checkpoint superblock,
resolve objects through the container and volume object maps, and check the Fletcher-64
checksum of every object it reads, raising `CorruptionError` on a mismatch. It SHALL
list the live filesystem tree of each volume (not snapshots), with types from the inode
mode, symlink targets from `com.apple.fs.symlink`, hard links as for HFS+, sparse
extents and holes as zeros, and names as stored. Encrypted volumes, sealed volumes and
Fusion containers SHALL raise `UnsupportedFeatureError` naming the feature.

#### Scenario: APFS

| Case | Expected |
| --- | --- |
| The `hdiutil` APFS fixtures, each codec | The same tree and hashes as the HFS+ fixtures |
| A newer checkpoint with a bad checksum | The older valid one is read |
| One flipped byte in a directory node | `CorruptionError` |
| An encrypted volume | `UnsupportedFeatureError` |

### Requirement: Open a password-encrypted DMG

An image that starts with `encrcdsa` SHALL be opened with the caller's `password=`: the
password key entry is unwrapped (PBKDF2-HMAC-SHA1, 3DES-EDE-CBC with PKCS#7 padding),
the unwrapped key SHALL be confirmed by decrypting the image's `koly` block, and the
image SHALL then be read as an unencrypted one through 4 KiB AES-CBC blocks. With no
password `open_archive` SHALL raise `EncryptionError`; with no right password among the
candidates it SHALL raise the wrong-password `EncryptionError`. The key-derivation work
SHALL count against archivey's key-derivation budget. Members SHALL report `encrypted`.
`cdsaencr` v1 images and images with no password key entry SHALL raise
`UnsupportedFeatureError`. Without `cryptography`, `PackageNotInstalledError`.

#### Scenario: encrypted images

| Case | Expected |
| --- | --- |
| `hfs-UDZO-AES-128.dmg` and `-AES-256.dmg` with `password="archivey"` | The fixture tree |
| No password | `EncryptionError` asking for one |
| Wrong password | Wrong-password `EncryptionError` |
| An iteration count over the budget | `ResourceLimitError` |
| `cryptography` excluded | `PackageNotInstalledError` |

### Requirement: Image checksums raise members together

Members of a DMG SHALL list with `verifiable = LENGTH` until the partition CRC-32 is
checked as a spanning check: then each file member of a partition with a CRC-32 SHALL be
`CHECKSUM` in `verifiable`, and SHALL reach `CHECKSUM` when an in-order read of the
partition or `verify_all()` matches the CRC over every run's decoded bytes except
"ignore" runs. A mismatch SHALL fail every member the partition covers. The checksum
SHALL NOT be computed at open.

#### Scenario: partition CRC

| Case | Expected |
| --- | --- |
| `verify_all()` on a fixture | Every file member `CHECKSUM` |
| One byte flipped inside a zlib run that still decodes | `verify_all()` fails the partition's members |
