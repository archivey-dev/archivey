# What a scan of a real backup drive found

**Status:** six defects reproduced with synthetic inputs and pinned by tests in
`tests/test_audit_backup_scan.py`. Three of them needed a maintainer decision
(§3.3-§3.5): two are now read with a diagnostic and the third stays refused.
The other failures were checked against `unzip`, `unrar`, 7-Zip and `xz` on the original
files (§5). The scan script's decoder-memory column is fixed (§2).

## 1. The scan

`scripts/scan_archives.py` dry-ran every file that `detect_format` placed on a personal
backup drive: years of unsorted copies of home directories, music and downloads. It
produced **57 390 archive rows**. File paths and names are left out of this record; only
counts and file types are kept.

| Format | Rows | Format | Rows |
| --- | ---: | --- | ---: |
| `raw_stream.zz` (zlib) | 26 821 | `raw_stream.bz2` | 1 084 |
| `zip` | 12 734 | `rar` | 981 |
| `raw_stream.xz` | 5 550 | `raw_stream.br` | 437 |
| `tar.bz2` | 3 594 | `tar.gz` | 371 |
| `raw_stream.gz` | 2 672 | `7z` | 231 |
| `tar.xz` | 2 666 | `iso` | 144 |

The log was triaged by grouping messages into templates (numbers and quoted names
replaced), then sampling each group. **No bug flag was raised**: no exception other than
an `ArchiveyError` left the library across all 57 390 archives.

## 2. The decoder-memory column was measuring detection

The summary reported 24 083 archives near `max_decoder_memory` and 2 666 over it. **All of
them came from detection, not decoding.** The content probes open the LZMA Alone codec on
every file that no magic places, and the codec checks header bytes 1-4 as a dictionary
size. The script's probe counted each check as a declared allocation:

- 26 681 of the zlib rows are git loose objects (extensionless files under
  `.git/objects/`). Their zlib header and first deflate bytes read as 1.0-3.4 GB.
- OLE compound files (`Thumbs.db`, `.doc`, `.msi`) read `cf11e0a1` as 2.7 GB.

The script now ignores the check while `_detect_format_body` runs.
`test_detection_probes_do_not_count_as_decoder_memory` fails on the old script
(`'3385478044' == ''`) and passes on the new one. A real `.lzma` still reports its
8 MiB dictionary.

A rescan is needed to see the real decoder-memory distribution: the noise covered all of it.

## 3. Defects

### 3.1 The LZMA Alone probe accepts a header followed by a zero run (55 files)

55 files were detected as `raw_stream.lzma` with PROBABLE confidence. None decoded. They
were MP3s, plus some `.jar` and TensorFlow `.data` files. For the MP3s, the logged
dictionary sizes are the ID3 tag bytes: `209 732` is `44 33 03 00`, that is `D3` and
version 3.0, the bytes after `ID3`.

The mechanism: a range coder fed zero bytes decodes an endless run of zero literals
without error. Any 13-byte prefix that passes the header gate and is followed by zeros is
therefore accepted. An ID3v2.3 tag that begins with padding is such a prefix. So is the
OLE magic followed by zeros (`0xD0` is legal properties: lc=1, lp=3, pb=4).

The `format-detection` spec keeps the Alone probe at PROBABLE because it "measured **0
false positives in 20 000 random blobs**", and says that the probe's real-world residual
was 13-byte files only. Random blobs never contain zero runs, and real files often do.
That measurement does not cover this class.

Checked on the original files: 32 of the 55 are MP3s with an ID3 tag followed by zeros,
the shape of the reproducer. The others also start with a zero run. Four are true
positives: router firmware images (a Belkin LZMA kernel followed by other data), which
archivey decodes and reports with `archive_trailing_data`, as `xz --format=lzma` does.

Pinned: `test_id3_tagged_mp3_is_not_lzma_alone`,
`test_ole_magic_then_zeros_is_not_lzma_alone`, and the mechanism itself in
`test_zero_run_after_an_alone_header_decodes_without_error`. The OLE case is fixed by the
OLE signature check in §3.2. The ID3 case was fixed later: the probe now refuses a zero
run at the start of the range-coder data, which also covers the OLE case on its own.

### 3.2 Brotli on OLE files: the P12 residual (437 files)

437 files were detected as `raw_stream.br`, 429 of them at GUESS confidence. They were
`.doc`, `.db` (`Thumbs.db`), `.msi`, `.ppt`, `.xls`, AppleDouble `._*` files and some
images. All of them failed to decode except two. This is the residual
that threat-model O10 records. The scan adds a real-world measure of it, and a
reproducible input: the 32-byte header that every version-3 OLE file starts with,
followed by zeros, at 256 KiB.

Pinned: `test_ole_header_then_zeros_is_not_brotli`. P12 and the spec forbid fixing it with
a threshold. A fix needs a check that comes from Brotli's own framing, or a recognized
non-archive signature that stops the probes, as the executable cue does for MZ and ELF.

**Status: fixed for OLE files.** The OLE signature `D0 CF 11 E0 A1 B1 1A E1` now stops
the content probes, as a `STRONG` executable cue does (`format-detection`: "A known
non-archive signature stops the content probes"). It does not start the SFX scan. This
also fixes the OLE case of §3.1: `test_ole_magic_then_zeros_is_not_lzma_alone` passes.
The AppleDouble `._*` files and the images among the 437 are not OLE files, and the fix
does not cover them.

### 3.3-3.5 ZIP: the two copies of a member's header disagree (decisions)

A ZIP stores most of a member's header twice: in the central directory and in the local
header before the data. Archivey reads everything from the central directory. At scan
time it refused a member that `unzip` reads in the three cases below, because the two
copies, or the declared size and the data, disagree. Each case needed a decision rather
than a fix: each check also catches real corruption, and a header mismatch is a known
spoofing shape for tools that trust the local header.

| | Disagreement | Seen | `unzip` | 7-Zip | Pinned by |
| --- | --- | --- | --- | --- | --- |
| 3.3 | Name: other code page (`0xF4` vs `0x93`, no UTF-8 flag), or `crack\` vs `crack/` | 3 archives, 4 members | warns, uses central name, passes | passes | `test_local_name_in_another_codepage_still_reads` |
| 3.4 | CRC: central 0, local right | 6 Adobe AIR packages, `META-INF/AIR/hash` | passes (checks the local CRC) | headers error | `test_zero_central_crc_with_a_right_local_crc_reads` |
| 3.5 | Size: both headers about 3.5% under the decoded size; CRC matches the full output | 1 archive (two copies), 12 deflated MP3s | passes (ignores the size) | CRC errors | `test_understated_size_with_a_matching_crc_is_refused` |

At scan time 3.3 was refused by `ZipReader._local_data_region`, as stdlib `zipfile`
refuses it. In 3.4 the AIR packager writes the
hash file after its central entry was made. In 3.5 the declared size is the bound that
stops a member from decoding past it, so honouring the CRC means decoding past the
declared size first; the extraction limits (`max_ratio`, `max_extracted_bytes`) would
still apply.

**Status (maintainer ruling 2026-10-10; shipped with stage 5 of the `native-zip-reader`
change).** 3.3 and 3.4 are read, from a file and from a pipe alike. 3.3 reports
`MEMBER_LOCAL_NAME_DIFFERS`, which `DiagnosticPolicy.STRICT` refuses; 3.4 reports
`MEMBER_LOCAL_CRC_USED`, which `STRICT` reads (ruling 2026-10-15). In 3.3 the
member keeps the central directory's name; a `crack/` directory reports nothing, since
reading a directory never reads its local header. In 3.4 the local CRC-32 is the
member's digest and the data is checked against it. 3.5 stays refused with
`CorruptionError` ("exceeds its declared size"): the declared size is the bound that
stops decoding (DR-9a).

## 4. ZIP local headers not where the central directory says

**Status: the ZIP over 4 GiB is read** since stage 6 of the `native-zip-reader` OpenSpec
change, by the rule below, with `ARCHIVE_OFFSET_WRAPPED` reported per corrected offset
([`formats/zip.md`](../formats/zip.md) §3).

`ZipReader._local_data_region` refused 4 183 members with a stdlib-style `BadZipFile`. The
name mismatch of §3.3 accounts for 4 of them. The rest:

| Message | Members | Archives |
| --- | ---: | ---: |
| Bad magic number for file header | 3 999 | 7 |
| Overlapped entries (possible zip bomb) | 178 | 2 |
| Absurd local-header offset: **negative** | 2 | 2 |

**One ZIP over 4 GiB written without ZIP64** accounts for 4 158 of these failures: 2 122
members, in two copies of the archive. Its central-directory offsets are the true offsets
mod 2³², and so is the end record's central-directory offset. A wrapped offset lands in
the middle of other data (bad magic) or makes two entries appear to overlap. 7-Zip cannot
open it, and no tool the owner tried salvages it.

**It is fully recoverable.** Checked on the file:

- All members but one carry a data descriptor (flag bit 3), so the local headers hold zero
  sizes. With the central directory's compressed sizes, which are exact because each
  member is under 4 GiB, a walk from offset 0 meets all 2 122 local headers in
  central-directory order and ends exactly where the central directory starts. Each
  data descriptor is the 16-byte form with a signature.
- The first 1 861 offsets are exact. The last 261 are off by exactly 2³².
- So one rule recovers every offset: a member's offset cannot be below the previous
  member's end, and when it is, add 2³² until it is not. The central directory's own
  offset follows the same rule against the last member's end. Sampled members on both
  sides of the wrap decode with matching CRCs.

The producer markers are version made by Unix 2.1, version needed 2.0, the old Info-ZIP
`UX` extra field (`0x5855`), and data descriptors with signatures. That combination is
what macOS Archive Utility (`ditto -c -k`, Finder's Compress) writes. This is a strong
lead, not a confirmed reproduction; `java.util.zip` does not write `UX` extras.

A third copy shows what a recovery tool made of it: the tool wrote a new ZIP holding only
the 261 wrapped members over the first 572 MiB of the file, which destroyed the original
members stored there, and the file was cut at exactly 2³² bytes. 7-Zip reads that new
261-member ZIP and reports the remaining 3.7 GB as trailing data.

A test needs an archive over 4 GiB, or a small archive whose offsets are rewritten to
simulate the wrap; the second is enough to test the rule.

The others, checked on the files:

- **Negative offset (2 ZIPs):** the files are missing their first 316 008 and 12 150
  bytes. `unzip` reports "missing N bytes in zipfile" and then fails every member as
  overlapped. Archivey fails only the member whose data was cut and extracts the rest. Its
  message was "Absurd local-header offset: -316008". **Status: fixed.** The message now
  says the archive seems to be missing at least its first 316 008 bytes, the same number
  for every cut member (`tests/test_zip_native_reader.py`,
  `test_a_zip_missing_its_first_bytes_says_so`).
- **All 13 members bad magic (1 ZIP, 120 MB):** the central directory lists tracks 6-18
  at offsets that leave room for five earlier tracks. The file's local headers sit at
  other offsets, and the members found there are longer than declared. It looks like a
  badly reassembled download. `unzip` and 7-Zip fail as well.
- **Installer `.exe` and `.part` files:** damaged or partial; reference tools fail too.

## 5. Checked against reference tools

| Group | Archives | Result |
| --- | ---: | --- |
| ZIP "central directory unreadable" | 92 | 53 are not ZIPs: 17 AppleDouble `._*`, 21 executables (ELF, PE, Mach-O), 9 Java WebStart cache stubs, 6 text or empty. Of 12 sampled ZIPs, `unzip` listed none; 7-Zip listed 1-6 members in 6, each with "Unexpected end of archive" (truncated downloads). Local-header recovery would salvage those few members. |
| RAR "solid stream ended before the requested member" | 6 | encrypted; `unrar` asks for a password, 7-Zip "Unsupported Method" |
| Digest mismatch | 30 (5 tested) | the AIR packages of §3.4 pass `unzip`; the rest are encrypted RARs or fail `unzip` and 7-Zip too |
| "content ended after N of M bytes" | 21 (5 tested) | genuine: encrypted RARs, `unrar` checksum errors, `unzip` CRC errors |
| "exceeds its declared size" | 3 | §3.5 (two copies); the third is a damaged `.part` |
| RAR "last block's packed data ends past the end of the file" | 15 (5 tested) | genuine: `unrar` "Unexpected end of archive" |
| "Invalid RAR header size", "no signature within the SFX window" | 2, 6 | genuine: `unrar` "Corrupt header" / not RAR |
| XZ "Internal error" | 1 | genuine: `xz -t` "Compressed data is corrupt" |
| ISO errors | 13 | 7-Zip lists 8 (7 over 2 GB not tested); 4 are not ISO 9660 or are cut short |
| "Destination already exists" | 70 (15 sampled) | 1 441 case-only pairs (policy) and 23 pairs equal only after NFC (policy, same key); no exact duplicates |

## 6. Policy and detection observations (no defect)

- **Renaming.** 21 765 of 21 774 `member_name_normalized` warnings only strip `./`, a
  leading `/`, or a trailing `/`. The exception is a Google Takeout ZIP whose entries
  claim a DOS-family creating system and whose names use the `\o/` emoticon. Its
  backslash becomes a separator, as `zip_reader.py` intends for DOS-created entries.
- **Unflagged UTF-8 ZIP names.** 11 839 names were read as UTF-8 without the flag. None
  looked garbled.
- **Colons.** About 12 000 entries were blocked as NTFS alternate data streams. They came
  from `wget` mirrors (`?i=http:`) and freedesktop icon names (`mime-audio:x-wav.png`).
  All are valid names on POSIX.
- **Unicode normalization collisions.** 23 sampled pairs differ only in NFC/NFD form (a
  macOS-written tree). The collision key is `casefold(NFC(path))` on purpose; on Linux
  both names are distinct files.
- **DMG.** 138 `.dmg` files were detected as raw zlib. 111 of them write 512 bytes and
  report `ok`, because only the first compressed chunk of the UDIF image decodes. All 138
  carry `archive_trailing_data`. Recognizing UDIF by its `koly` trailer and reporting it
  as unsupported would be clearer.
- **mozlz4.** Firefox `addonStartup.json.lz4` is Mozilla's `mozLz40\0` framing around a
  raw LZ4 block, not an LZ4 frame. Archivey detects it by extension only and fails it as
  unconfirmed. Reading it would be a small feature.
- **ZIP methods 1 (Shrink) and 6 (Implode).** Two old DOS-era archives use them. `unzip`
  and 7-Zip read both; archivey does not support either method.
- **Raw exception reprs in messages.** The ISO reader, and some gzip, tar and bzip2
  paths, put `repr(exc)` in the `CorruptionError` text (`error('unpack_from requires a
  buffer of at least 16 bytes…')`, `IndexError(…)`). The ZIP path double-escapes a byte
  string (`b'…\\\\x93…'`). The exception types are correct; only the text is affected.
- **Correct detections that looked odd.** These were checked and are right: `RS_*.xz`
  Reddit dumps that are tar (80+ members each), and gzip under `.mail`, `.inn` and `.top`
  (about 1 650 files).
