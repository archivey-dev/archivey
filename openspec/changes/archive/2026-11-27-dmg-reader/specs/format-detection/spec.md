## MODIFIED Requirements

### Requirement: Magic-byte table

Exact matches only (no fuzzy/weak magic). Recognised:

| Format | Signature (summary) |
| --- | --- |
| ZIP | `50 4B 03 04` / `07 08` / `05 06` |
| GZip | `1F 8B` |
| BZip2 | `42 5A 68` |
| XZ | `FD 37 7A 58 5A 00` |
| Zstandard | `28 B5 2F FD`, optionally preceded by skippable frames |
| 7-Zip | `37 7A BC AF 27 1C` |
| RAR 4.x / 5.x | `52 61 72 21 1A 07 00` / `… 01 00` |
| ISO 9660 | `CD001` at 32769 |
| UDF-only disc image (read as ISO) | `BEA01` at 32769 |
| SquashFS | `hsqs` at 0 (little-endian SquashFS 4); `sqsh` at 0 (big-endian SquashFS 3 and older, claimed so `format-squashfs` can refuse it by name) |
| ISO 9660, raw CD sector image | `00 FF×10 00` sector sync at 0 (`format-iso` reads Mode 1 and Mode 2 Form 1 and refuses other layouts by name) |
| UDIF | `6B 6F 6C 79 00 00 00 04 00 00 02 00` (`koly`, version 4, header size 512) at offset 0, or at the start of the last 512 bytes |
| Encrypted DMG | `encrcdsa` at offset 0 (v2); `cdsaencr` as the last 8 bytes (v1, claimed so `format-dmg` can refuse it by name) |
| TAR | `ustar` at 257 |
| ar | `!<arch>\n` at 0; `!<thin>\n` at 0 (claimed so `format-ar` can refuse it by name) |
| CPIO | `070707`, `070701`, `070702` or `070727` at 0 (odc, newc, crc, afio's large header). The binary variant's 2-byte magic `C7 71` / `71 C7` is too weak: a content probe that also checks the name, run only when the extension names CPIO |
| LZ4 | `04 22 4D 18` (frame); `02 21 4C 18` (legacy stream, `lz4 -l`) |
| lzip | `LZIP` |
| unix-compress | `1F 9D` |

Formats without reliable exact magic (notably **zlib**) SHALL NOT appear here —
content probe only.

A zstd **skippable frame** — magic in `0x184D2A50 .. 0x184D2A5F` followed by a
little-endian `uint32` payload size — carries no compressed data and MAY precede the
first regular frame. Detection SHALL walk consecutive skippable frames by their declared
sizes within the peeked prefix and match the regular frame that follows. A source of
skippable frames alone, or one whose declared size runs past the prefix, SHALL NOT be
claimed as zstd: the walk is arithmetic over already-peeked bytes and never extends the
read.

#### Scenario: magic matrix

| Case | Expected |
| --- | --- |
| Starts `50 4B 03 04` | ZIP, `CERTAIN`, `magic` |
| Magic table consulted for zlib | No zlib entry; CMF/FLG → zlib probe |
| `ustar` at 257, ≥512 bytes | TAR, `CERTAIN`, `magic` |
| No `ustar`; first 512 bytes a TAR header with a matching checksum and a name, from a path, a `BytesIO` or a pipe, named or not | TAR, `PROBABLE`, `content_probe` |
| The same block one byte off its checksum, or with an empty name, no extension | `FormatDetectionError` |
| gzip of such a v7 tar | `TAR_GZ`, `PROBABLE`, `content_probe` |
| gzip of a binary CPIO archive, named `.cpio.gz` or with `always_probe_content`; the same with no name | `(CPIO, GZIP)`, `PROBABLE`, `content_probe`: a container's content probe runs on the first 512 decoded bytes under the rule it follows on an uncompressed source; with no name, `GZ` |
| A plugin format's probe answers `GUESS`, no name, `always_probe_content` | The plugin format, `GUESS`, `content_probe` |
| The same, named with the plugin's extension | The plugin format, `PROBABLE`, `content_probe` |
| gzip of a plugin sequential format whose probe answers `GUESS`, no name, `always_probe_content`; the same named `.<ext>.gz` | `GZ`: a weak inner match does not switch formats; named, `(<plugin>, GZIP)`, `PROBABLE`, corroborated |
| A plugin probe answers `None`, `True`, `CERTAIN` or another non-verdict | No match; one WARNING on `archivey.detection` |
| Raw CD sector sync at 0 | ISO, `CERTAIN`, `magic`; a Mode 1 or Mode 2 Form 1 image opens, other layouts raise `UnsupportedFeatureError` |
| `koly` block at offset 0 | `DMG`, `CERTAIN`, `magic`; read by `format-dmg` |
| `koly` trailer, and no earlier step matched | `DMG`, `CERTAIN`, `magic`; read by `format-dmg` |
| `encrcdsa` at offset 0 | `DMG`, `CERTAIN`, `magic`; `format-dmg` asks for the password |
| `CD001` at 32 769 and a `koly` trailer, no `koly` at offset 0 | `ISO`, `CERTAIN`, `magic` — far magic already matched, so the trailer is not consulted |
| Starts `02 21 4C 18` (legacy LZ4) | LZ4, `CERTAIN`, `magic` |

#### Scenario: zstd frame prefix

| Case | Expected |
| --- | --- |
| Regular frame at offset 0 | `ZST`, `CERTAIN`, `magic` |
| One skippable frame, then a regular frame | `ZST`, `CERTAIN`, `magic` |
| Several chained skippable frames, then a regular frame | `ZST`, `CERTAIN`, `magic` |
| Skippable frames only, no regular frame | No zstd claim; falls through |
| Skippable frame whose declared size runs past the peeked prefix | No zstd claim; no extended read |

## ADDED Requirements

### Requirement: Detect a DMG disk image

The system SHALL report a UDIF image as `ArchiveFormat.DMG` / `CERTAIN` / `magic` when
the `koly` block is at offset 0, or at the start of the last 512 bytes and no earlier
step matched, and an encrypted image the same way when it starts with `encrcdsa` or ends
with `cdsaencr`. `open_archive` SHALL read it with the `format-dmg` reader. Far magic
runs first, so an uncompressed image whose disk is an ISO 9660 filesystem (`CD001` at
32 769) SHALL be reported as `ISO` and read as one; the trailer is not consulted. The
`.dmg` suffix SHALL NOT select the format: a file named `.dmg` with none of these
signatures (a raw `hdiutil` UDRW disk, a renamed ZIP) is detected by its own bytes, as
today. `format_availability(DMG)` SHALL be `FULL` with no optional package, with or
without `cryptography`, as for encrypted members of other formats; opening an encrypted
image without it SHALL raise `PackageNotInstalledError`.

#### Scenario: DMG detection matrix

| Case | Expected |
| --- | --- |
| Seekable image, zlib, bzip2, xz or LZFSE first block, `koly` trailer | `DMG` / `CERTAIN` / `magic`; opens and lists |
| `koly` block at offset 0 | `DMG` / `CERTAIN` / `magic` |
| `encrcdsa` at offset 0 | `DMG` / `CERTAIN` / `magic` |
| `CD001` at 32 769 and a `koly` trailer, no `koly` at offset 0 | `ISO` / `CERTAIN` / `magic`; the image is read as an ISO |
| Real zlib, bzip2 or xz stream, no `koly` block | Unchanged |
| Version other than 4 | Not `DMG` |
| ZIP whose name ends in `.dmg` | `ZIP` |
| Raw disk named `.dmg` (no `koly`, GPT backup header in the last sector) | Not `DMG`; behaviour unchanged |
| `format=ZLIB` on a zlib-first image | The first block is read; detection does not run |
| Non-seekable source longer than the far-magic window, zlib first block, `koly` at the end | `ZLIB`; the trailer is not seeked to |

## REMOVED Requirements

### Requirement: Refuse a UDIF disk image by name

**Reason**: DMG images are now read (`format-dmg`); "Detect a DMG disk image" replaces
it.

**Migration**: A caller that caught `UnsupportedFeatureError` for a `.dmg` now gets its
members. Encrypted, segmented and other unsupported variants still raise
`UnsupportedFeatureError` or `EncryptionError` from `format-dmg`.
