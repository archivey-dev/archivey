# UDIF (`.dmg`)

Current maintainer truth for Apple's UDIF disk image. archivey recognises one and
refuses it. Nothing reads the blocks. Detection's trailer step is on
[`topics/detection.md`](../topics/detection.md) §2.4. This page is the format.

## At a glance

| | |
| --- | --- |
| Read | No. Recognised, then `UnsupportedFeatureError` |
| Write | **Not shipped** |
| Source | The trailer is read on a cheap seek. A pipe is not rewound (§2.1) |
| Listing cost | None. Open refuses before a reader exists |
| Core dependencies | None. Recognition uses no optional library |
| Refuses | Every image it recognises as UDIF |
| `format=` | `format=DMG` raises the same error. `format=` naming a compressor reads that stream and does not look for the trailer |

**Two things a reader might expect and will not find.** The files inside the image.
And a signature inside the first compressed block that would identify the container:
that block is disk sectors (§1).

## 1. Shape

What `hdiutil` writes is three regions. On a current image the signature is the last one.

```
data fork     runs of the virtual disk, each compressed or stored on its own
XML plist     the blkx map: which file range is which sectors, and which codec
last 512 B    the koly block. magic, version 4, header size 512, big-endian
```

The `koly` block is what 7-Zip checks: the 12 bytes `koly`, then version 4, then a
header size of 512. It records where the data fork and the property list sit.
The property list holds one `mish` table per partition. Each run in that table is
40 bytes: a type, a start sector, a sector count, and the offset and length of the
bytes in the file. The sector count is shifted 9 bits, so the decompressed length
is a whole number of 512-byte sectors.

A bzip2 run (type `0x80000006`) and an xz run (type `0x80000008`) are ordinary
streams of those codecs. Decompressing one yields the sectors it covers, not
another UDIF structure. The `mish` table that names the run is in the property
list, after the data fork. The stream carries no container signature. When the
run covers sector 0, the sectors are the start of whatever disk was imaged:

- an Apple partition map starts with `ER` (a Driver Descriptor Map)
- a GPT disk starts with a protective MBR, and `EFI PART` is one sector later
- a raw HFS+ volume often has zeros in the boot blocks and `H+` or `HX` at offset 1024
- a raw APFS container starts with `NXSB`

Those bytes name the disk. A `.bz2` of a raw disk begins the same way, so they
do not identify UDIF. The first stored run is also often a zero-fill, which
stores nothing, or it starts later than sector 0. The images in the backup scan
that opened as zlib wrote 512 bytes because that first run was one sector (§3).

`koly` at offset 0 is a rare old layout. 7-Zip's opener says a usual image has
the block at the end, and an old image has it at the beginning. It treats the
block as front-placed when the data-fork offset inside it is 512, so the runs
start immediately after the block. A current image, including an uncompressed
one (`Copy`, type 1, what `hdiutil` calls UDRW), keeps the block at the end.
An uncompressed image starts with disk sectors. The literal `koly` bytes at
offset 0 are that old layout.

## 2. The pipeline here

### 2.1 Identify

Offset 0 is ordinary near magic. The block at the end is the trailer step
([`detection.md`](../topics/detection.md) §2.4). The step runs after far magic,
so an uncompressed image of an ISO 9660 disk — `CD001` at byte 32 769 — is
reported as `ISO` and read as one. The trailer is not consulted once far magic
has matched.

It runs before the content probes, so a zlib first block is the image. A
bzip2 or xz header is near magic, and the trailer lists both in `preempts`, so
that hit is replaced before the inner-TAR probe. The `.dmg` suffix is not
registered.

A pipe and an `ArchiveStream` are not seeked to the end. A short image is still
refused, because the far-magic peek has already read through to the block. A
longer zlib-first image on a pipe opens as zlib.

### 2.2 Open and list

`open_archive` raises `UnsupportedFeatureError` with the text in
`UDIF_UNSUPPORTED_MESSAGE`, and the exception carries `archive_name`.
`reader_for_format` raises the same text for a caller that reaches it, but it
takes no archive name, which is why the open path raises first. The open path
does not test for DMG: it raises for any format whose backend sets
`READ_IMPLEMENTED` false, with the text from the registry's
`unread_format_message`. `UdifBackend.open_read` raises the same text with the
archive name for a caller that reaches the backend directly. That is the
backend's own code: a recognised-only backend must write that refusal itself.

`format_availability` is `NONE` with an empty `missing`. `archivey --version -v`
prints `dmg: none — recognised, not readable`. `required_source` is
`FORWARD_ONLY`: nothing reads the image, and `SEEKABLE` would tell the
published spool recipe to copy the file first.

### 2.3 Member data

Refused before a reader exists.

### 2.4 Extract

Same refusal. `format=` naming zlib, bzip2 or xz does not detect, and reads
that first stream.

### 2.5 Write

Not shipped.

## 3. In the wild

`hdiutil` writes compressed runs as zlib (`UDZO`), bzip2 (`UDBZ`) or LZFSE
(`ULFO`), or stores them (`UDRW`). xz is run type `0x80000008` in 7-Zip. This
page does not name an `hdiutil` spelling for it.

A backup scan that prompted recognition found 138 `.dmg` files archivey opened
as the first compressed block. 111 of them extracted as 512 bytes and reported
success: one sector, then the rest of the image treated as trailing data.

7-Zip calls the front-placed `koly` block rare and old. The scan's images had
the block at the end. This repo has not measured a current producer that still
writes it at offset 0.

## 4. Threat surface

No format-specific row in [`threat-model.md`](../threat-model.md). The failure
this recognition stops was a wrong format: the first run decoded as a complete
zlib, bzip2 or xz member. There is no UDIF parser.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A `.dmg` used to extract as a few hundred bytes and report success | **archivey** | The first run is a real compressed stream (§1). Recognition refuses it |
| An uncompressed image of an ISO 9660 disk lists as an ISO | **archivey** | Far magic wins (§2.1). Reading that ISO is the behaviour recorded in §6 |
| `format=zlib` on a zlib-first image extracts the first run | **archivey** | `format=` skips detection (§2.4) |
| A long image on a pipe opens as its first block | **format** | The trailer is at the end, and a pipe is not rewound (§2.1) |
| `dmg: none` with no install hint | **archivey** | Known, and nothing to install. The verbose version line says so (§2.2) |

## 6. Decisions

- **Refuse, and do not read the blocks.** The scan's failure was the false
  extract. A reader is a separate feature.
- **Do not decompress the first run to look for a disk signature.** The bytes
  are the disk, a compressed raw disk has the same bytes, and the `koly` block
  already identifies the file without a decode (§1).
- **Leave far magic ahead of the trailer.** An ISO 9660 payload is read as an
  ISO. Moving the trailer first would refuse those images and would read the
  tail of every ISO. That alternative has not been taken.
- **`required_source` is `FORWARD_ONLY`.** The spool recipe copies when the
  answer is `SEEKABLE`. The copy would end in the same refusal.
- **The open path raises, rather than the registry alone.** The registry raise
  has no archive name. The tests assert the refusal has one.

## 7. Open questions

- Whether any current tool still writes `koly` at offset 0. 7-Zip still accepts
  it. A sample would say if the near-magic row is dead.
- Encrypted images (an `encrcdsa` header is described at offset 0) and
  LZFSE-first images were not in the measured scan. A seekable file whose last
  512 bytes are still the `koly` block is refused either way. Whether those
  producers keep that block is unchecked.

## 8. Verify

```bash
./scripts/test.sh tests/test_udif.py tests/test_detection_workspace.py \
    tests/test_cli.py::test_version_verbose_lists_formats \
    tests/test_registry.py::test_required_source_is_declared_for_every_known_format
```

| Claim |
| --- |
| A zlib, bzip2 or xz first run with a `koly` trailer is `DMG`, and open refuses it (§2.1, §2.2) |
| `CD001` at 32 769 with a `koly` trailer is `ISO` (§2.1) |
| A pipe longer than the far window is not rewound (§2.1) |
| `format_availability` is `NONE` with nothing missing, and `required_source` is `FORWARD_ONLY` (§2.2) |
| `reader_for_format(DMG)` raises the same text without an archive name (§2.2) |
| `--version -v` says recognised, not readable (§2.2) |

## 9. References

- 7-Zip `CPP/7zip/Archive/DmgHandler.cpp`. `IsKoly` is the 12 bytes. `Open2` says a
  usual image has the block at the end, an old image has it at the start, and the
  block is front-placed when the data-fork offset is 512. The run types run from
  `METHOD_ZLIB` through `METHOD_XZ`. The sector shift is `UnpPos = sector << 9`.
- User docs: `docs/formats.md` §Disk images.
