# Design: reading DMG disk images

This design is the implementation plan written for the implementer, kept here so the
plan can be reviewed before any code. The prototype and the `hdiutil` fixtures are in
this change under `resources/` (§0). Decisions D1 to D8 (§2) were ruled by the
maintainer on 2026-11-21.


Written 2026-11-21 for an implementer who works on github.com/archivey-dev/archivey and
has not seen the earlier investigation. Self-contained: everything you need from that
work is in this file or in the attachments listed in §0.

This is the plan for the **full** feature: the UDIF container with every run codec,
partition maps, HFS+, APFS, and encrypted images. It is built in separable parts
(§11, Parts A to H). Each part is one PR (or a few) that leaves `main` working, so the
plan can be reviewed as a whole and implemented part by part.

Target release: 0.6.0 for Parts A to E at least (a needs-minor change: a format that was
refused becomes readable). Later parts may land in 0.6.0 or after.

**Status of this document:** a plan for review. Where it says "verify against the
fixtures", the field layout comes from public notes and has not been checked on our
images yet; the implementer checks it first.

---

## 0. Before you start

**Resources in this change** (`openspec/changes/dmg-reader/resources/`):

| File | What it is |
| --- | --- |
| `prototype/dmgproto/udif.py`, `hfsplus.py`, `apfs.py`, `lzfse.py`, `adc.py`, `dmg.py` | A working pure-Python prototype (stdlib only, 1,470 lines). It reads every file of 41 real DMGs (36 HFS+, 5 APFS) byte for byte the same as 7-Zip, and all 10 unencrypted UDIF images in the fixture set. **Use it as the reference for the on-disk layouts; do not copy it as production code.** It has none of archivey's limits, error types or diagnostics, it decodes whole files into memory, and it has no decryption. |
| `fixtures/` | Moved in Part B to `tests/fixtures/external/dmg_hdiutil/`: small real images made with `hdiutil` on macOS 26.7 (§9.1), with macOS's own listing, hashes and xattrs of the mounted volume. The two 16 MiB UDRW images (raw disks, no `koly`) are left out. |
| `make-dmg-fixtures.sh` | The script that made `fixtures/` on a Mac (Appendix A). |
| `dmgurls.txt` | The real-world corpus URL list, 54 URLs (Appendix B); 41 were measured in the investigation. |

**Read these in the repo first, in this order:**

1. `AGENTS.md` ("Every task" block), `CONTRIBUTING.md`, `dev-docs/design-rules.md`
   (index).
2. `dev-docs/formats/dmg.md`: what archivey does with a DMG today (recognise, refuse).
3. `src/archivey/formats.py`: the reader API (`IndexedFormatHandler`, `IndexedReader`,
   `ReaderSource`, `ReaderContext`, `MemberRecord`, `MemberData`, `block_stream`).
4. `src/archivey/internal/backends/squashfs_reader.py`: the closest model for the
   filesystem reader (block decode through `ReaderContext.decompress`, listing walk,
   loop and size checks, `charge_metadata`, hard links, `archive_info`).
5. `src/archivey/internal/backends/cd_sectors.py` (`CookedSource`) and `iso_reader.py`
   (`IsoHandler.open`): the model for a translated `ReaderSource` handed to a reader.
6. `src/archivey/internal/backends/udif.py`: today's recognise-and-refuse backend, which
   this work replaces.
7. `src/archivey/internal/streams/codecs/lzo_decoder.py` and `lzo_codec.py`: the model
   for a pure-Python decoder with an optional native package in a child process
   (`Natives`, `natives_for`, `deps`).
8. `src/archivey/internal/backends/cab_reader.py` + `streams/codecs/lzx_decoder.py`: a
   container reader that drives its own pure-Python decoder directly.
9. `openspec/changes/archive/2026-11-18-macos-installer-packages/` and
   `openspec/changes/native-iso-parser/`: how a format change is written up.

**Rules that bite here** (from `design-rules.md`): DR-1 (a wrong answer is the worst
failure), DR-2 (deliver every intact member, then raise), DR-4 (unsupported is not
corrupt), DR-6 (match the official tool), DR-9/9a (every cost bounded by a public limit;
no archive may cause unbounded memory, disk, hang or crash), DR-15b (fail at open but do
no work proportional to the archive there), DR-20 (parse in Python; native code that can
crash runs in a child), DR-21a (do not ship what cannot be tested), DR-24 (tests against
real producers). PRs open with the "For dummies" section from
`.github/pull_request_template.md`. Do not edit `CHANGELOG.md`.

---

## 1. Scope

**In this plan:**

- UDIF container: the `koly` trailer, the XML property list, `blkx`/`mish` run tables,
  and run types zero, raw, ignore, zlib, bzip2, xz, LZFSE, ADC (§4).
- Partition map: GPT, Apple Partition Map (APM), and none (whole image is one volume)
  (§5).
- HFS+ and HFSX (case-sensitive HFS+) volumes: files, directories, symlinks, file hard
  links, transparent compression (decmpfs), extended attributes listed (§6).
- APFS containers: unencrypted volumes, files, directories, symlinks, hard links,
  sparse files, clones, decmpfs compression, extended attributes (§6A).
- Encrypted DMGs (`encrcdsa` v2, AES-128 and AES-256, password): decrypted with
  `password=` (§6B). Until Part G lands they are recognised and refused by name.
- An optional native LZFSE accelerator (Part H).
- Partition CRC-32 verification as a spanning check (Part F).

**Not in this plan** (refuse with `UnsupportedFeatureError` and a message that names the
thing, or leave as today):

- Encrypted APFS volumes inside an unencrypted image (APFS native encryption, keybags),
  sealed APFS volumes, Fusion containers, APFS snapshots other than the live tree.
- `cdsaencr` v1 encrypted images (pre-10.5; recognise and refuse by name: no fixture,
  DR-21a). Certificate- or keychain-only encrypted images (no password key entry).
- Segmented images (`.dmgpart`; `koly` segment count > 1), sparse images
  (`.sparseimage`, magic `sprs`), sparse bundles (a directory), NDIF (Mac OS 9 `.img` /
  `.smi`), images with no XML property list (resource-fork-only, very old).
- **A `.dmg` with no `koly` block.** `hdiutil create` writes "UDRW" read/write images as
  a plain raw disk (in the fixtures, `hfs-UDRW.dmg` and `apfs-UDRW.dmg` are 16 MiB with
  a GPT backup header in the last sector, no `koly`). That is a raw disk image, not
  UDIF. Detection and behaviour for those stay as they are today; reading raw GPT/HFS+
  disk images is a possible later feature (the partition and HFS+ code here would serve
  it).
- Writing DMGs.

---

## 2. Decisions (ruled by the maintainer, 2026-11-21)

All eight are ruled. Build them as written. Mention in
the PR body which defaults you implemented.

| # | Question | Recommended default |
| --- | --- | --- |
| D1 | Listing when an image holds more than one readable filesystem | **Ruled by the maintainer 2026-11-21: this default.** One filesystem (every image seen so far): its files at the archive root, volume name in `archive_info().extra`. Several: each volume's files under a top-level directory named after the volume (as macOS mounts them). Do not read only the first and warn: that hides files (DR-1). |
| D2 | Extended attributes and resource forks | **Ruled by the maintainer 2026-11-21: this default.** List names (and values up to 1 KiB) in `ArchiveMember.extra`, as TAR's pax xattrs are; do not write them on extract. Resource fork size goes in `extra` too. Docs note: code signatures of non-Mach-O files inside an `.app` (`com.apple.cs.*` xattrs) will not verify after extraction. |
| D3 | LZFSE decoder | **Ruled by the maintainer 2026-11-21:** we already have a working pure-Python LZFSE/LZVN decoder (the prototype), so Part A ports it and it is always available. Part A0 evaluates the `lzfse` PyPI package (MIT, Apple's reference C, about 45x faster); if it passes, it becomes the optional fast path (Part H). In general the maintainer prefers an established package as an extra, and an extra being required is acceptable; our own decoder is kept here only because it exists already. **A0.2, ruled 2026-11-21:** the `lzfse` package has no output cap and accepts damage that no outside check can catch (`dev-docs/investigations/lzfse-package.md`), so the fast path is our own kernel in the `archivey-codecs` Rust package instead (Part H). |
| D4 | UDIF checksums | **Ruled by the maintainer 2026-11-21: this default.** Parts B to E: members are `verifiable = LENGTH`, like ISO and SquashFS (no per-file checksum in HFS+ or APFS file data). Part F adds the per-partition CRC-32 as a spanning check, a separate partition pass that `verify_all()` runs (§7.2), which lifts members to `CHECKSUM`. Never check it at open (it needs a full decode, DR-15b). |
| D5 | Several APFS volumes in one container (a container can hold up to 100) | **Ruled by the maintainer 2026-11-21: this default.** Same as D1: one volume at the root; several, each under its volume name. Volumes with a system role (Preboot, Recovery, VM, Update) are listed like any other; DMGs seen so far hold one data volume. |
| D6 | Encrypted image, password checks | **Ruled by the maintainer 2026-11-21: this default** (the whole image, listing included, is under one key, so the password is tried once, at open, as for a header-encrypted RAR or 7z). The key unwrap is a strong password check (3DES-CBC with PKCS#7 padding, then the decrypted `koly` block): a member of an encrypted image is `UNLOCKED` at open. No password: `EncryptionError` at open ("pass password="). Wrong: the wrong-password `EncryptionError` that `ReaderContext.unlock` raises (§6B.0); the reader writes neither error itself. |
| D8 | Public codec names | **Ruled by the maintainer 2026-11-21:** add `CompressionAlgorithm.LZFSE`, `LZVN` and `ADC` in Part A, refusable one by one through the codec policy (§4.3). |
| D7 | APFS metadata checksums (Fletcher-64 on every object) | **Ruled by the maintainer 2026-11-21:** always checked. In regular mode a block whose checksum fails is never used: the walk skips it (a bad leaf loses its records, a bad index node its subtree, a bad object-map node every object it maps), lists every member whose records are all intact, then raises `CorruptionError` at the end of the listing (DR-2). A member whose extents were partly in a skipped block lists but raises on read. Salvage mode (planned separately) will use bad blocks anyway, with a diagnostic, and show orphaned files. Metadata integrity only: it does not change `verifiable`. |

---

## 3. Where the code goes

| Module (new or changed) | Contents |
| --- | --- |
| `internal/backends/udif.py` (rewrite) | `koly` parse, property list parse, `mish` run tables, `UdifImage`, and `UdifSource(ReaderSource)`: a virtual-disk view that decodes runs on demand. Keep `UDIF_UNSUPPORTED_MESSAGE` only if something still refuses with it. |
| `internal/backends/disk_partitions.py` (new) | GPT and APM parsing, partition selection (§5). Pure functions over a `ReaderSource`. |
| `internal/backends/hfsplus.py` (new) | The HFS+ volume parser: volume header, fork extents, B-tree walk, catalog, extents overflow, attributes, hard links, decmpfs. Plays the role `iso9660.py` / `udf.py` play for ISO: no `ArchiveMember`s here, only parsed entries. |
| `internal/backends/apfs.py` (new, Part E) | The APFS container and volume parser (§6A), same role as `hfsplus.py`. |
| `internal/backends/dmg_crypto.py` (new, Part G) | `encrcdsa` v2 header parse, key unwrap, and `EncryptedDmgSource(ReaderSource)`: a decrypted view that `UdifImage` reads instead of the file (§6B). Uses `internal/streams/crypto.py` (`get_crypto_backend`, AES-CBC stages, `wrong_password_error` is not needed) and the caller's passwords through the **public password API of the plugin interface** (`archivey.formats`), which a separate change adds first (see §6B.0). Do not use the private `ReaderContext._passwords` hook. |
| `internal/backends/dmg_reader.py` (new) | `DmgReader(IndexedReader[...])` and `DmgHandler(IndexedFormatHandler)`, registered with `register_builtin_format`. Turns HFS+ entries into `MemberRecord`s. |
| `internal/streams/codecs/lzfse_decoder.py` (new) | Pure-Python LZFSE (`bvx1`, `bvx2`, `bvxn`, `bvx-`, `bvx$`) and LZVN decoders, bounded output (`max_length`), `CorruptionError` on any bad input. Part H adds the optional native path here. |
| `internal/streams/codecs/adc_decoder.py` (new) | Apple Data Compression decoder (tiny; see prototype `adc.py`). |
| `internal/format_adapter.py` | Add `ContainerFormat.DMG` to `REPLACEABLE_CONTAINERS` (it is now an indexed format a plugin could replace) and update the comment above it. |
| `core.py`, `internal/format_args.py` | Remove or update the DMG "recognised-only" comments and special case (`format_args.py` around line 150-160: check whether DMG must still be excluded from the extension list). |
| `dev-docs/formats/dmg.md` | Rewrite as the handbook page for a readable format, same section layout as `squashfs.md` (At a glance, Shape, Pipeline, In the wild, Threat surface, Sharp edges, Decisions, Open questions, Verify, References). |
| `docs/formats.md` §Disk images | User docs. **Leave the prose for the maintainer's docs session** (user docs are written by a specific reviewer model by rule DR-22b); put a short factual draft in the PR body instead. |
| `dev-docs/threat-model.md` | Add a DMG row (§8). |
| `openspec/changes/dmg-reader/` | proposal, design, tasks, and spec deltas: a new `specs/format-dmg/spec.md`, and deltas to `format-detection`, `backend-registry` and `testing-contract` where they say DMG is refused (`detection-cost` needs none: the trailer receipt stays one 512-byte read, §6B.1) (grep `openspec/specs` for `UDIF`/`DMG`). |
| `tests/` | §9. |

Detection: the handler API's `magic` holds only fixed-offset `Magic` entries. The `koly`
**trailer** signature (with `preempts=(BZ2, XZ)`) lives on the backend class today
(`UdifBackend.TRAILER`). Keep it by passing `TRAILER=` (and the offset-0 `MAGIC`)
through `register_builtin_format(DmgHandler, **overrides)`; check `_backend_class` in
`format_adapter.py` accepts those names, and extend it if not. Detection results for
every input must stay as they are now (the existing `tests/test_udif.py` detection cases
keep passing). Keep `extensions = ()`: the `.dmg` suffix stays unregistered, because
many files named `.dmg` are not UDIF (§1, raw disks; zips renamed).

`required_source` becomes `SEEKABLE` (set `non_seekable_reason`, e.g. "its run table is
at the end of the image and the filesystem metadata can be anywhere in it"), so a pipe
is spooled or refused like ISO.

---

## 4. Layer 1: UDIF

All integers are big-endian unless stated.

### 4.1 The `koly` block

The last 512 bytes of the file (an old layout puts it at offset 0, with data-fork offset
512; accept both, as 7-Zip does). `struct` layout (prototype `KOLY`):
`>4sIIIQQQQQII16sII128sQQ120sII128sIQ12s`

| Field | Use |
| --- | --- |
| magic `koly`, version 4, header size 512 | Required; anything else is not UDIF (detection already checks these 12 bytes). |
| flags | Ignore. |
| running data fork offset | Ignore. |
| data fork offset, length | Must lie inside the file. Stored runs are located from the data fork offset (formula in 4.3). |
| resource fork offset, length | Ignore (old images only). |
| segment number, segment count, segment id | Segment count > 1: refuse ("segmented DMG"). |
| data checksum (type u32, bits u32, 128 bytes) | Type 2, 32 bits = CRC-32 of the data fork bytes (D4: checked from Part F). |
| XML offset, XML length | Required. Length 0: refuse ("DMG without a property list"). Must lie inside the file. |
| master checksum (type, bits, 128 bytes) | CRC-32 of the partition checksums; checked from Part F if cheap. |
| image variant u32, sector count u64 | Sector count = virtual disk size / 512. Bounded only so offsets stay below 2^63; never an allocation length or loop count (see 4.4). |
| code signature offset u64, length u64 (at `koly + 0x128`, inside what the struct above calls the 120 reserved bytes; 7-Zip `DmgHandler.cpp` reads it there) | Optional (both 0 when absent). A signed image keeps its code-signature blob here. Not verified. In range: allowed, and `dmg.code_signature` is `True` in `archive_info().extra`. Outside the file or overlapping another structure: a diagnostic (no existing code fits; Part B adds one, e.g. `ARCHIVE_SIGNATURE_RANGE_INVALID`, to `DiagnosticCodeStr`), the blob is ignored, and the image is read. |

The image's extent is the union of the declared, validated ranges: data fork, property
list, code-signature blob (when valid) and the `koly` block, wherever each one is (for a
`koly` block at offset 0 the data and the property list follow it). Bytes of the file
outside that union are reported as `ARCHIVE_TRAILING_DATA` (DR-3), never refused. The
data fork, the property list, the blob and the `koly` block must not overlap (the blob
excepted as above: an overlapping blob is ignored, not an error). Test: the builder
writes a signed layout (a blob between the property list and the `koly` block, and with
`koly` at offset 0), and the corpus run (9.5) asserts no `ARCHIVE_TRAILING_DATA` on the
signed real images.

### 4.2 The property list

Check the plist length from the `koly` block before reading any byte of it: over 64 MiB
is `ResourceLimitError`, and a range outside the file is `CorruptionError`. Then charge
that length with `charge_metadata` and read it in one `read_exact` (always at open: it
is bounded and nothing about the image can be known without it; see §7 for the whole
open-time envelope). The parsed objects are dropped once the run tables are built; only
the compact tables of §4.3 are kept. Parse with stdlib `plistlib.loads` (it refuses
entity declarations, so no billion-laughs). Wrap parse errors as `CorruptionError`.

Structure: `resource-fork` → `blkx` → list of dicts, each with `Name` (or `CFName`),
`ID`, `Attributes`, and `Data` (bytes: one `mish` table). Other keys (`plst`, `cSum`,
`nsiz`, `size`) are ignored.

### 4.3 The `mish` table

Header, 204 bytes, `>4sIQQQII24sII128sI`: magic `mish`, version 1, first sector,
sector count, data offset, buffers needed, block descriptors, reserved, checksum type,
checksum bits, checksum (128 bytes), number of runs. Then that many runs of 40 bytes,
`>IIQQQQ`: type, comment, sector (relative to the table's first sector), sector count,
compressed offset, compressed length. A run's stored bytes are the half-open file range
`[start, start + compressed length)` with `start = data fork offset + mish data offset +
compressed offset` (7-Zip `DmgHandler.cpp` adds the same three, plus the image's start
in the file, which is 0 here). That range must lie inside
`[data fork offset, data fork offset + data fork length)`; outside is `CorruptionError`.
The prototype only ever saw a data fork offset of 0 and a mish data offset of 0, so the
builder must add a vector with both non-zero.

Run types:

| Type | Name | Decode |
| --- | --- | --- |
| `0x00000000` | zero fill | `sector count * 512` zero bytes, nothing stored |
| `0x00000001` | raw | the stored bytes; length must be exactly `count * 512` |
| `0x00000002` | ignore (free space) | zeros; excluded from the partition CRC |
| `0x80000004` | ADC | `adc_decoder` |
| `0x80000005` | zlib (UDZO) | `ReaderContext.decompress(view, StreamFormat.ZLIB)` |
| `0x80000006` | bzip2 (UDBZ) | `ReaderContext.decompress(view, CompressionAlgorithm.BZIP2)` |
| `0x80000007` | LZFSE (ULFO) | `lzfse_decoder` |
| `0x80000008` | xz (ULMO) | `ReaderContext.decompress(view, CompressionAlgorithm.XZ)` |
| `0x7FFFFFFE` | comment | skip |
| `0xFFFFFFFF` | terminator | ends the table; runs after it are an error |
| other | | `UnsupportedFeatureError` naming the type in hex, raised when a read needs that run (DR-2: other members stay readable) |

**Bounds before any byte of a run is read or allocated.** Let `decoded = count * 512`. A
compressed run whose `decoded` exceeds 16 MiB is `UnsupportedFeatureError` (§4.4). A raw
run whose stored length is not exactly `decoded` is `CorruptionError`. A compressed run
whose stored length exceeds `2 * decoded + 64 KiB` is `ResourceLimitError` ("a
compressed run stores more than archivey reads for one run"). This is a support limit,
not a validity bound: a valid encoding can be arbitrarily inefficient (zlib allows empty
stored blocks without end; ADC allows a one-byte literal per command, so a valid run can
store about twice its decoded size). The limit admits every such ADC run and every real
writer's output (hdiutil's runs are at most 1 MiB decoded and smaller stored), and caps
the largest read for one run at 32 MiB + 64 KiB. Tests tell the two apart: a valid ADC
run of one-byte literals reads; a valid zlib run padded with empty stored blocks past
the limit raises `ResourceLimitError`; a malformed run within the limit raises
`CorruptionError`. The cap bounds work as well as memory: the run cache holds only a few
runs, so without it, repeated metadata reads that miss the cache could each re-read a
huge run. If the external corpus run (§9.5) ever hits the cap, switch to a streaming
read under an explicit per-run input budget instead of raising it. These checks run when
the run table is parsed, so a bad run is known before any decode; the error is raised
from the read that needs the run (other members stay readable).

Then use the same block-decode pattern as `SquashfsReader._block_decoder`: read the
run's stored bytes in one `read_exact` (bounded by the check above), decode from memory,
pull from the decoder with `read(decoded + 1 - len(data))` until it ends or more than
`decoded` bytes have come out (so no pull can return more than `decoded + 1` bytes in
total), and require the decoded length to equal `count * 512` exactly (shorter or longer
is `CorruptionError` naming the run's sector and file offset; offsets in messages count
from the start of the file, a standing rule). A cut-off run is `TruncatedError`.
`ReaderContext.decompress` applies `DecoderLimits`, the ratio guard and process
isolation. For the in-house decoders (LZFSE, ADC), pass `max_length = count * 512 + 1`
so output is bounded.

Codec policy granularity: zlib, bzip2 and xz runs go through `ReaderContext.decompress`,
so `config.formats` codec refusals apply to them as to every format. Part A adds
`CompressionAlgorithm.LZFSE`, `CompressionAlgorithm.LZVN` and `CompressionAlgorithm.ADC`
(D8), like the other format-specific codecs (`LZX`, `QUANTUM`, `LZH`, `SHRINK`, ...).
The DMG reader asks `config.formats._codec_refusal(...)` before decoding an LZFSE, ADC
or LZVN run or decmpfs block, as SquashFS does for LZ4, and a refused codec raises
`UnsupportedFeatureError` at the read that needs it. An LZVN block inside an LZFSE
stream (`bvxn`) is part of LZFSE and is governed by the `LZFSE` entry; `LZVN` governs
decmpfs types 7 and 8. The values name the algorithm, not the implementation: the
pure-Python decoder, the `lzfse` extra (Part H) and any later Rust kernel serve the same
value, as `LZO` is served by archivey's decoder, python-lzo or compress-utils. Members
do not report a codec chain or a `compressed_size` (runs are shared across files, as in
SquashFS); `dmg.run_codecs` in `archive_info().extra` reports them at archive level.

**Checks on the run table** (each failure is `CorruptionError` at open or first
listing). Before any run is parsed: the header's run count must satisfy
`204 + 40 * runs <= len(Data)` (the `Data` bytes are already bounded by the plist
check), and the total run count over all tables is charged with `charge_metadata` before
the descriptors are kept. Keep the runs as compact arrays (`array('Q')` per field, or
one packed `bytes` searched with `struct.unpack_from`), never one Python object per run.
Then: runs sorted by sector and not overlapping; every run inside the table's sector
range; every table inside the disk's sector count; compressed ranges inside the data
fork; sector count per run bounded (see 4.4). Gaps between runs, inside the table's
sector range, read as zeros (the spec states this; 7-Zip does the same; hdiutil leaves
none). Two runs whose stored bytes overlap are allowed (no writer does it, but it costs
nothing): each decodes on its own.

### 4.4 `UdifSource`

A `ReaderSource` over the virtual disk (size = koly sector count * 512), built like
`CookedSource`: `view()` and `read_at()` find the runs a range covers (bisect on start
sectors) and serve bytes from decoded runs. Keep a small LRU cache of decoded runs
(4 to 8 runs is enough: hdiutil never writes a compressed run larger than 2,048 sectors,
1 MiB decoded). Bounds:

- A compressed run whose declared decoded size exceeds 16 MiB: `UnsupportedFeatureError`
  when read (document on the handbook page; no measured producer writes one). Zero,
  ignore and raw runs may be any size and are served without caching whole.
- Pass read hints to `source._will_read` for the stored ranges, as `iso_reader` does for
  a remote source (optional, but cheap).
- Disk size is what the `koly` block says; a filesystem that claims more is
  `CorruptionError`. The disk size is never an allocation length or a loop count: the
  sector count only has to keep `sector count × 512` below 2^63 (offsets stay in range;
  more is `CorruptionError`). Every loop is over runs or over bytes actually read: raw
  runs are bounded by the data fork, ignore runs and gaps are never walked, and
  zero-fill runs are folded into the CRC in O(log n) (§7.2), so listing a huge sparse
  disk and checking its CRC allocate nothing in proportion to its size and loop over
  none of its sectors. No public ceiling on the disk size is needed, because no loop
  over the sector count remains. Reading a member is different: every byte a member read
  returns, zero fill included, counts in the archive-wide ratio (§8), so reading a large
  zero-fill file from a small image stops with `ResourceLimitError`.

The cache is memory bounded by (cache slots * 16 MiB); state that in the handbook page
and make the slot count a constant.

---

## 5. Layer 2: partition selection

**Which evidence decides.** All `mish` tables together form one index of the virtual
disk (sector ranges to runs); two tables whose sector ranges overlap are
`CorruptionError` before the index is built. Bytes of the disk always come from that
index. Candidate partition ranges come from the first of these that is valid: (a) the
partition map read from the disk: a GPT whose header CRC and partition-entry array CRC
both match and whose geometry is valid (entry size 128 × 2^n and at most 512 bytes,
entry count ≤ 128, so the array is at most 64 KiB and its size is checked from the
header before it is read; a GPT that is valid by the UEFI rules but larger than this is
not used: a diagnostic, and candidates come from (b); entry array, first and last usable
LBA inside the disk, every entry inside the usable range, no two entries overlapping),
tried as the primary pair (header at sector 1 and its array) and then the backup pair
(header at the last sector and its array); or an APM whose entries all have the `PM`
signature, a consistent map count and ranges inside the disk, with the map count taken
from the first entry and capped at 64 before any further entry is read (a valid larger
map: a diagnostic, and candidates come from (b), as for an oversized GPT), (b) the
`blkx` tables' own sector ranges when there is no map or the map is damaged (a
diagnostic says which), (c) the whole disk. Each candidate is probed, and the filesystem
signature (step 3) alone decides what is read. `blkx` names (`Apple_HFS`, `Apple_APFS`)
and GPT/APM type values only describe: a disagreement with the signature is a
diagnostic, never a reason to skip or read a partition. So a GPT HFS+ entry with a
matching header and an unrecognised `blkx` name is read.

1. Each `blkx` entry is normally one partition, named like `disk image (Apple_HFS : 4)`,
   `Protective Master Boot Record (MBR : 0)`, `GPT Header (Primary GPT Header : 1)`,
   ` (Apple_Free : 3)`. The fixtures show the full GPT set.
2. The names show what to expect: `Apple_HFS` or `Apple_HFSX` (HFS+), `Apple_APFS`
   (read by §6A from Part E). The partition maps:
      - GPT: `EFI PART` at sector 1 (backup at the last sector); partition entries; HFS+
     type GUID `48465300-0000-11AA-AA11-00306543ECAC`, APFS
     `7C3457EF-0000-11AA-AA11-00306543ECAC`. Valid only as defined above (both CRCs and
     the geometry); a primary that fails is a diagnostic and the backup is tried; both
     failing falls back to (b). `blkx` names never make a GPT valid.
   - APM: Driver Descriptor Map `ER` at sector 0, entries with signature `PM`,
     type `Apple_HFS` / `Apple_HFSX`.
   - None (2 of 41 real images): a single `blkx` entry covering the whole disk; probe
     the volume signature.
3. Whatever the map says, a partition is HFS+ only if offset 1024 of it holds `H+`
   (version 4) or `HX` (version 5); APFS if offset 32 holds `NXSB`.
4. Each HFS+ partition is read by §6, each APFS container by §6A. Until Part E lands, an
   image whose only filesystem is APFS raises `UnsupportedFeatureError("APFS disk images
   are not supported yet")` at open. No filesystem at all: `UnsupportedFeatureError`
   naming the partition names found. A hybrid image with an ISO 9660 or other partition
   beside HFS+/APFS lists only the HFS+/APFS volumes and reports the other partition
   (`ARCHIVE_UNLISTED_DATA`), as nothing we have seen does this.
5. If a valid map and a `blkx` table disagree on where a partition starts, the map's
   range is probed (the bytes come from the disk index either way) and a diagnostic is
   reported. Tests: a GPT image whose `blkx` names are unrecognised; a valid primary
   header with a damaged entry array (falls to the backup pair); both pairs bad (falls
   back to the `blkx` ranges); two `mish` tables that overlap.

   Probe work is capped: at most 128 candidates from any source, the `blkx` fallback
      included (more is `ResourceLimitError` at open, naming the count; never a silent
   stop at 128, which could hide a volume, DR-1). Each probe reads
   the bounded amounts in §7.

Several HFS+ partitions: D1. Top-level names (D1, D5), in partition order and then
volume order inside a container: the volume name with `/` as `:`; an empty name, `.`
or `..` becomes `Untitled`; a name already taken (exact match, then case-insensitive
match, so the tree also extracts on a case-insensitive file system) gets ` 1`, ` 2`, ...
appended, the first number that gives a free name, as macOS does under `/Volumes`.
The names are fixed before any member is listed, so ordering is stable. The original
labels are in `archive_info().extra["dmg.volumes"]` in the same order. Hard links never
cross volumes; their targets carry the volume's top-level name. Test: an image with two
volumes named `Data`, each holding `readme.txt` and a hard link, lists `Data/...` and
`Data 1/...`, in partition order, with each link pointing back inside its own
volume.

---

## 6. Layer 3: HFS+

Reference: Apple TN1150 "HFS Plus Volume Format". The prototype `hfsplus.py` has every
layout below; this section lists what production must add.

### 6.1 Volume header (offset 1024 in the partition, 512 bytes)

Signature `H+`/`HX`, version 4/5, attributes, `blockSize` (power of two, 512 to 64 KiB
in practice; refuse others), `totalBlocks` (× blockSize must fit in the partition),
`journalInfoBlock`, and five fork records (allocation, extents, catalog, attributes,
startup), each `logicalSize`, `totalBlocks` and 8 extents (`startBlock`, `blockCount`).
An HFS wrapper (signature `BD` at 1024, embedded HFS+ volume) is rare: refuse by name.

**Journal state** (TN1150 "Journal": an implementation must replay a journal with
pending transactions or not mount the volume). If the volume is journaled (attributes
bit 13), read the journal info block at `journalInfoBlock`, then the journal header:

- `kJIJournalNeedInitMask` set: the journal is empty; read the volume.
- `kJIJournalOnOtherDeviceMask` set (external journal): its state cannot be checked;
  `UnsupportedFeatureError("HFS+ volume with an external journal")` at open.
- Journal in the volume (`kJIJournalInFSMask`): header magic `JNLx` and endian mark
  checked (bad is `CorruptionError`); `start == end` means clean, read the volume;
  `start != end` means pending transactions:
  `UnsupportedFeatureError("HFS+ volume with an unreplayed journal")` at open. Replay
  is later work (§12). A volume that `hdiutil` or a clean unmount wrote is clean.

Tests: the builder writes each case (clean, need-init, pending, external), and a layout
test checks each one's journal info block, journal header and (pending) block list header
field by field against Apple's `hfs_journal.h` / `hfs_journal.c` (`journal_header`,
`block_list_header`, `calc_checksum`, `JOURNAL_HEADER_CKSUM_SIZE`, `BLHDR_CHECKSUM_SIZE`).
A pending image made on a Mac would be the independent check, if one turns up.
`fsck.hfsplus -n` from `hfsprogs` cannot tell the states apart: on Linux it never reads
the journal header (its journal check compares the volume signature without swapping
bytes), so it exits 0 for all four states on 540.1.linux3-5 and fails every journaled
volume on 540.1.linux3-6, its own `mkfs.hfsplus -J` output included. It checks the
rest of the volume only.

### 6.2 Forks and extents

A fork is up to 8 extents in its record, then more in the extents-overflow B-tree, keyed
by (file id, fork type 0x00 data / 0xFF resource, start block), compared in that order
(Apple's `CompareExtentKeysPlus`). Production checks:
every extent inside `totalBlocks`; sum of extents ≥ `logicalSize`; overflow lookups
bounded (the fork cannot have more extents than its block count); bytes after
`logicalSize` are not part of the file. Two files sharing blocks read normally.

### 6.3 B-trees (catalog, extents overflow, attributes)

Node size from the header node (512 to 32 KiB, power of two). Walk the leaf chain from
`firstLeafNode` through `fLink`. Production checks: node kind and height as expected;
record offsets inside the node and increasing; a node visited twice ends the walk with
`CorruptionError` (loop); node count bounded by fork size / node size. Charge the bytes
the walk keeps (names, link tables) with `ReaderContext.charge_metadata`.

### 6.4 Catalog

Keys: parent CNID + name (`HFSUniStr255`, UTF-16BE, ≤ 255 units). Records: folder (1),
file (2), folder thread (3), file thread (4). Root folder CNID 2.

Members:

| HFS+ record | archivey member |
| --- | --- |
| folder | `DIRECTORY` |
| file, normal | `FILE`, size = data fork `logicalSize` (or decmpfs size, 6.6) |
| file whose BSD mode is `S_IFLNK`, or whose `fileType` is `slnk` with creator `rhap` | `SYMLINK`, target = data fork bytes (UTF-8, cap 1024 bytes as PATH_MAX; longer is `CorruptionError`) |
| file, `fileType` `hlnk` creator `hfs+` | file hard link (6.5) |
| file, `fileType` `fdrp` creator `MACS` | directory hard link: `UnsupportedFeatureError` for that member (no fixture exists; DR-21a). Other members stay readable. |
| file with BSD mode of a FIFO, socket, char/block device | `OTHER` (standing ruling: device, FIFO, socket = OTHER) |

Type precedence, in this order: (1) hard-link records first, by their Finder markers
(`hlnk`/`hfs+` for a file link, `fdrp`/`MACS` for a directory link), whatever the BSD
mode says: in the HFS+ fixture both `hello.txt` and `sub dir/hardlink.txt` are link
records with mode `0100444` and an empty data fork, so a mode-first rule would list two
empty files; the prototype checks the markers first. (2) For other records, a non-zero
BSD mode decides the type (`S_IFLNK`, `S_IFREG`, devices,
FIFOs, sockets), as the prototype does; TN1150 says macOS writes both the mode and the
Finder `slnk`/`rhap` tags. When the mode is 0 (not set), the Finder tags decide. When
both are set and disagree, the mode wins and a diagnostic is reported. Test: a
mode-only symlink (Finder info zero) lists as `SYMLINK`.

Paths: build from each catalog key's parent CNID and the folder records' own CNIDs, as
the prototype does (`build_paths`). Folder thread records are a separate cross-check: a
thread that disagrees is a diagnostic. Depth cap and loop check (a parent chain that
revisits a CNID is `CorruptionError`).

Names: decode UTF-16BE. A `/` in a stored name becomes `:` (the POSIX view macOS mounts
and 7-Zip show). Keep the decomposed Unicode form as stored (do not NFC-compose; that is
what the mount and 7-Zip give). Pass names through the same `ReaderContext` name
handling ISO and SquashFS use, so the standard name diagnostics apply. Invalid UTF-16
(lone surrogates) keeps `surrogateescape`-style handling as ISO does for undecodable
names. `uses_encoding = False` (names have a fixed encoding).

Metadata: BSD info (owner, group, mode; mode 0 means "not set": leave mode `None`),
`contentModDate` → mtime, `createDate` → `created` (birth time), HFS times are seconds
since 1904-01-01 UTC in the catalog (subtract 2,082,844,800 for Unix); 0 means unset.
Use `ReaderContext.set_unix_time` so bad values get `MEMBER_TIMESTAMP_INVALID`.

Hidden, not listed (macOS hides them when mounted; match the mount, DR-6):

- `\0\0\0\0HFS+ Private Data` (file hard-link targets) and everything under it,
- `.HFS+ Private Directory Data\r` (present in every fixture),
- `.journal` and `.journal_info_block` at the root when the volume is journaled
  (attributes bit 13) and they are the journal files the `journalInfoBlock` names.

Other dot-files (`.fseventsd`, `.Trashes`, `.background`, `.DS_Store`) are listed.

### 6.5 File hard links

A link record (`hlnk`) carries `linkID` in its BSD `special` field; its content lives in
the private-data folder as `iNode<linkID>`. Rule (standing ruling: hard links point
backward only): the first path to an inode in listing order is a `FILE` with the data;
every later path is `HARDLINK` to that first path. The listing order is catalog order
(parent CNID, then name), as the walk finds them. A link whose inode is missing:
`LINK_TARGET_UNAVAILABLE`-style handling as other readers do for a missing link target,
not a silent empty file (7-Zip writes empty files here, which is wrong: DR-1).
The fixture has `hello.txt` and `sub dir/hardlink.txt` as one inode.

### 6.6 Transparent compression (decmpfs)

A file with `UF_COMPRESSED` (0x20) in its BSD owner flags and a `com.apple.decmpfs`
attribute: header `<4sIQ` (magic `fpmc`, type, uncompressed size), then data.

| Type | Data | Notes |
| --- | --- | --- |
| 1 | uncompressed, inline | |
| 9 | uncompressed, inline, after a `0xCC` marker byte | 7-Zip (`HfsHandler.cpp`) reads type 9 only with the marker and refuses it without; the prototype ignores the marker. Follow 7-Zip; without the marker the file is `UnsupportedFeatureError` at read, since no sample shows it is damage. |
| 3 | zlib, inline (first byte `0x?F` = stored) | |
| 4 | zlib, in the resource fork (resource-map layout, 64 KiB blocks) | |
| 7 | LZVN inline (first byte `0x06` = stored) | |
| 8 | LZVN in resource fork (offset table, 64 KiB blocks) | **The fixture `compressed.txt` is type 8** (360,000 bytes), so this path has real data |
| 10 | raw in resource fork (type 8 offset table), each chunk after a `0xCC` byte | The macOS kernel reads only this layout and refuses the table without the byte (the macOS check, `tasks.md` §M), so a chunk without it is `CorruptionError`. 7-Zip refuses type 10. |
| 11 | LZFSE inline (`0xFF` = stored) | |
| 12 | LZFSE in resource fork | |
| other | | `UnsupportedFeatureError` at that member's read |

Inline types (1, 3, 7, 9, 11): the payload is the attribute's bytes after the 16-byte
header, one chunk. It decodes with output capped at the declared size + 1, and the
decoded length must equal the declared size exactly (else `CorruptionError`). A
declared size over 64 KiB for an inline type is `CorruptionError` (inline data is one
chunk).

Resource-fork types (4, 8, 10, 12): the fork holds `n = ceil(size / 64 KiB)` chunks,
located by the type's table (type 4: the resource-map layout, a 256-byte resource fork
header, then the `cmpf` resource with a count and (offset, length) pairs; types 8 and
12, and type 10: `n + 1` little-endian u32 offsets). The table must have exactly `n`
chunks and every chunk inside the fork (else `CorruptionError`). Each chunk must decode
to exactly 64 KiB, the last to `size - 64 KiB * (n - 1)`. A chunk that starts with its
type's stored marker (`0xFF` for types 4 and 12, `0x06` for type 8) is the raw block
after that byte, not encoded data: macOS stores a chunk that does not shrink that way,
and 7-Zip reads it. A type 10 chunk is always its raw block after a `0xCC` byte, and one
without it is `CorruptionError`: the macOS check (`tasks.md` §M) found the kernel reads
that layout and refuses the table without the byte. Decode chunk by chunk through
`block_stream`, not the whole file in memory like the prototype.

Missing pieces: a file with `UF_COMPRESSED` but no `com.apple.decmpfs` attribute, a
fork type whose resource fork is missing or empty, and an attribute shorter than its
header all list the member, and its read raises `CorruptionError`; never an empty file
that reads successfully. A `com.apple.decmpfs` attribute without `UF_COMPRESSED` is
ignored, as macOS does: the data fork is read, and the attribute lists in `extra`.
Tests: each inline type; a resource-fork file whose last chunk is short; a flagged file
with no attribute; a fork type with no resource fork. zlib blocks go through
`ReaderContext.decompress(..., StreamFormat.ZLIB)`. Member size is the decmpfs size; the
data fork is empty for these files. Hide `com.apple.decmpfs` and the resource fork of a
compressed file from the D2 listing (they are implementation, not content).

### 6.7 Attributes B-tree

Keys: file id, start block, name (UTF-16). Records: inline data (0x10), fork data
(0x20), extents (0x30). Collect names (and small values) for D2. Bound the total kept
with `charge_metadata`. An attribute record that fails to parse: report
`MEMBER_HEADER_RECORD_SKIPPED` and keep the member (standing pattern for RAR's bad
optional record), unless it is `com.apple.decmpfs` of a compressed file, in which case
that member's read raises `CorruptionError`.

---

## 6A. Layer 3: APFS (Part E)

Reference: Apple, *Apple File System Reference* (2020). The prototype `apfs.py` reads
the 5 real APFS images and the 5 unencrypted APFS fixtures. All integers little-endian.
Block size from the container superblock (4096 in every image seen; accept powers of two
from 4096 to 65536).

### 6A.1 Objects and checksums

Every object starts with `obj_phys_t` (`<QQQII`: Fletcher-64 checksum, oid, xid, type,
subtype). Check the checksum on every object read (D7; prototype `fletcher64`); a
failing block is skipped and remembered, and the listing raises `CorruptionError` after
every intact member. Type in the low 16 bits; check the expected type at every read.
Physical address 0 and addresses at or past the container block count are
`CorruptionError`.

### 6A.2 Container

1. Block 0 is a copy of the container superblock (`NXSB` at offset 32). Read the block
   size and the checkpoint descriptor area (`nx_xp_desc_blocks`, `nx_xp_desc_base`).
2. Scan the checkpoint descriptor area for `NXSB` objects with the right type and a good
   checksum, and take the newest usable one, by xid (prototype `_latest_superblock`,
   which checks only the superblock). Usable means the checkpoint is complete. Its
   descriptor span is `nx_xp_desc_len` blocks starting at ring index `nx_xp_desc_index`
   and wrapping modulo `nx_xp_desc_blocks` (both values must be inside the ring, and
   `desc_len` ≥ 2): the first `desc_len - 1` blocks are checkpoint-map objects (type
   checkpoint map), each with a good checksum and the superblock's xid, the last of them
   has `CHECKPOINT_MAP_LAST`, and the final block of the span is the candidate `NXSB`
   itself. In the APFS UDRO fixture each checkpoint has `desc_len = 2`, laid out as
   `[checkpoint map, NXSB]`; the newest has xid 4 and occupies ring indexes 6 and 7.
   That fixture is the positive test. An incomplete checkpoint is skipped for the next
   older one, with a diagnostic. The reader needs no ephemeral object (space manager,
   reaper), so it does not read them. Damage in physical objects reached from a complete
   checkpoint (object maps, trees) never triggers this fallback: it is D7 damage
   (§6A.6). Test: a newest superblock with a good checksum but a missing checkpoint-map
   block, beside a complete older checkpoint: the older one is read. Bound the area
   (refuse > 65,536 blocks), and bound the work: the scan counts the physical bytes it
   reads and the bytes it decodes against a 64 MiB budget (the same constant as the open
   budget, §7, counted separately because the scan runs at first listing), and raises
   `ResourceLimitError` when the next block would exceed it. Real checkpoint areas are a
   few blocks (the fixtures: `desc_len = 2`), so the budget only stops a hostile area,
   such as 65,536 blocks of 64 KiB covered by LZFSE runs (about 4 GiB of decode); a
   non-contiguous area (high bit of `desc_blocks` set) is `UnsupportedFeatureError`
   (never seen in a DMG).
3. Refuse Fusion containers (`incompatible_features & 0x100`).
4. Load the container object map (`nx_omap_oid`): an `omap_phys_t` whose B-tree maps
   (oid, xid) to physical address. Lookup of an oid at transaction `x`: take the entry
   with the highest xid ≤ `x`, tombstones (`OMAP_VAL_DELETED`, flag 1) included. If that
   winning entry is a tombstone, the object is absent; tombstones are never filtered out
   before the choice (the bundled prototype `apfs.py` filters them first, which is
   wrong: a live entry at xid 10 and a deletion at 11 would resolve to the old address
   at 11). The encrypted flag (4) is read from the winning live entry only; set there,
   the object is part of an encrypted volume: refuse that volume. Test: lookups at xid
   10 and 11 on both sides of a deletion.
5. Volumes: the non-zero oids in `nx_fs_oid[100]`, each looked up in the container omap,
   each an `apfs_superblock_t` (`APSB`).

### 6A.3 Volume

For each volume: refuse encrypted (`apfs_fs_flags & APFS_FS_UNENCRYPTED` not set;
message "encrypted APFS volume"), refuse sealed (`incompatible_features & 0x20`). Volume
name from `apfs_volname`. Case- or normalization-insensitive volumes
(`incompatible_features & 0x1` or `& 0x8`) use hashed directory keys (6A.5). Load the
volume object map and resolve `apfs_root_tree_oid` through it. Ignore snapshots
(`apfs_snap_meta_tree`): read the live tree only. Snapshots are not listed; a later
version may list them.

### 6A.4 B-trees

`btree_node_phys_t`: flags (root 1, leaf 2, fixed-size 4), level, key count, table of
contents (offset, length), then keys from the start and values from the end (minus the
40-byte `btree_info_t` in a root node). Fixed-size trees (object maps) use 4-byte TOC
entries and the key/value sizes from `btree_info_t`. Child pointers in the filesystem
tree are virtual oids resolved through the volume omap; object-map trees use physical
addresses. Checks: every record inside the node; key count fits the TOC; depth ≤ 32; a
node visited twice is `CorruptionError`; total nodes bounded by the container block
count. A child node that fails its checksum is skipped (D7) and the walk goes on with
its siblings. Walk in key order; the filesystem tree is sorted by (oid, type,
name/offset).

### 6A.5 Filesystem records

Key header `j_key_t`: `obj_id_and_type` (type in the top 4 bits). Records used:

| Type | Record | Use |
| --- | --- | --- |
| 3 | inode (`j_inode_val_t`) | parent id, private id (data stream id), create/mod/change/access times (ns since 1970 UTC), internal flags, nlink, BSD flags, uid, gid, mode, and extended fields (`xf_blob`): `INO_EXT_TYPE_DSTREAM` (8) gives the file size; `INO_EXT_TYPE_NAME` (4) the name for a hard link |
| 4 | xattr | name, flags (embedded 2 / stream 1), data or (stream oid, size) |
| 5 | sibling link | hard-link names; use to cross-check nlink (report, don't refuse, on mismatch) |
| 6 | dstream id | reference count (clones) |
| 8 | file extent | logical address in the key; length (low 56 bits), physical block, crypto id in the value; physical block 0 = sparse hole |
| 9 | directory record | name (plain key: `u16` length + name; hashed key: `u32` length-and-hash, low 10 bits length, then name), file id, date added, flags (DT_* type in low 4 bits) |
| others | snapshot, crypto state, sibling map, dir stats, purgeable, ... | skip |

Names are UTF-8 with a trailing NUL; strip one NUL, decode UTF-8, and handle invalid
bytes as ISO does. APFS keeps names as written (normalization-preserving), so pass them
through unchanged. On hashed volumes the hash is CRC-32C of the NFD, case-folded name;
checking it is optional (a mismatch is a diagnostic, not a refusal). `/` cannot occur in
an APFS name; one that does is `CorruptionError` for that entry.

### 6A.6 Members

- Directory tree from directory records, root directory inode 2. A directory reached
  twice is `CorruptionError` (loop). The private directory (inode 3) and the
  `private-dir` contents are not listed.
- Type from the inode's mode (`S_IFDIR`, `S_IFREG`, `S_IFLNK`, others → `OTHER`). A
  directory record whose DT_* type disagrees with the mode: mode wins, report it
  (DR-25).
- Symlink target: the `com.apple.fs.symlink` xattr (UTF-8, NUL-terminated; cap 1024
  bytes).
- Hard links: an inode reached from more than one directory record. First path in
  listing order is the `FILE`; later paths are `HARDLINK` to it (backward-only rule,
  same as §6.5).
- File data: the extents of the data stream (private id), sorted by logical address.
  Gaps and physical block 0 are zeros (sparse; mark the member sparse like SquashFS
  does). Overlapping extents are `CorruptionError` at that member's read. Bytes past the
  dstream size are ignored; a stream shorter than the size reads as zeros to the size
  (APFS allows a sparse tail). Zeros are served only where the records show a hole: a
  gap, or a range of the stream past its last extent, that falls inside a damaged key
  range (below) is `CorruptionError` at that member's read, never zeros. Clones share
  extents: just read them.
- decmpfs compression: `UF_COMPRESSED` BSD flag plus `com.apple.decmpfs` xattr, with
  the resource fork in the `com.apple.ResourceFork` xattr (usually a stream xattr). Same
  types and decoding as §6.6; share that code (DR-23a).
- Times: mtime = `mod_time`, `created` = `create_time`, ns precision kept if
  `ArchiveMember` supports it.
- Owner, group, mode from the inode.
- Xattrs per D2, hiding `com.apple.fs.symlink`, `com.apple.decmpfs`,
  `com.apple.ResourceFork` of a compressed file.
- An extent whose crypto id is non-zero on an unencrypted volume: `CorruptionError` for
  that member.

**Damaged key ranges (D7).** A skipped node is not the same as a missing record. When
a node fails its checksum, or cannot be read, the walk records the key range it covered,
taken from the parent index node, which was verified: from the parent record's key to
the next sibling record's key, or to the parent's own upper bound for the last child (a
bad root makes the whole tree's range damaged). A bad object-map node records its range
of oids the same way. Every later lookup checks these ranges:

- Extents of a data stream: the key range `(stream id, 8, *)`. If any part of it
  overlaps a damaged range, the member lists, and its read raises `CorruptionError`
  naming the damaged node's address at the first byte the extents can no longer show,
  instead of serving zeros.
- Listing a member depends on exact keys, not on an interval over the object id (the
  inode id and the data-stream id are often the same number, as in the APFS UDRO
  fixture's `random.bin`, id 22 for both, so an interval would also catch its extents):
  its inode record `(oid, 3)`; the directory record that names it, `(parent, 9, name)`;
  and the xattrs that change what it is, `(oid, 4, "com.apple.fs.symlink")` for a
  symlink and `(oid, 4, "com.apple.decmpfs")` for a file with `UF_COMPRESSED`. If any of
  those keys falls in a damaged range, the member is not listed (its type and size
  cannot be trusted), and the end-of-listing `CorruptionError` counts it. Other xattrs
  in a damaged range leave the member listed with those names missing from `extra`, and
  the listing still ends with `CorruptionError`. A directory whose own `(oid, 9, *)`
  range overlaps a damaged range lists the children that remain, then the same error.
  Extents (type 8) are handled only by the data-stream rule above, never by this one.
- An oid looked up in the object map that falls into a damaged oid range is
  `CorruptionError` ("mapped by a damaged object-map node"), not "not found".

Keys outside every damaged range are trusted as complete, so a valid sparse file still
reads zeros in its holes. The ranges are few (one per bad node) and kept as a sorted
list.

Data stream reads go through `block_stream` over `UdifSource`, block by block, never the
whole file in memory.

Bounds: the walk keeps per-inode records and directory names; charge them with
`charge_metadata`. A file's extent list can be long (one per fragment): keep extents as
a compact array and charge it.

---

## 6B. Encrypted images (Part G)

### 6B.0 Dependency: passwords in the plugin interface

The DMG reader is written against `archivey.formats`, the plugin interface, like
SquashFS. That interface has no public way for a reader to receive the caller's
`password=` today (its module docstring lists passwords among what it leaves out); only
a private hook exists, used by makeself. The maintainer ruled (2026-11-21) that password
support is added to the plugin interface first, as its own change, and that new formats
use the plugin interface. **Part G depends on that change** and uses its API for: trying
candidates, telling "no password" from "wrong password", and charging the key-derivation
budget. Where this section names an error or behaviour (D6), it is the outcome required;
the calls come from that API. Parts A to F do not depend on it.

An encrypted DMG is a different file: the whole UDIF image (data fork, plist, `koly`) is
encrypted inside it. There is no `koly` block in clear text; detection must find the
encryption header instead.

The API, as ruled by the maintainer in PR 1705 (`openspec/changes/plugin-passwords`, not
merged when this was written; follow the merged version if it differs):

- The handler sets `supports_password = True`.
- At open, the reader calls `ReaderContext.unlock("the disk image", check)`.
  `check(password)` returns `(unwrapped_key, PasswordConfirmVerdict.CONFIRMED)` when the
  key unwraps and the decrypted `koly` block checks out, or
  `(None, PasswordConfirmVerdict.REJECTED)` when the password is wrong. archivey writes
  both the missing-password and the wrong-password `EncryptionError`.
- Before each PBKDF2 derivation the reader calls
  `ReaderContext.charge_key_derivation(rounds)`.
- `ReaderArchiveInfo.is_encrypted` is `True` for an encrypted image, and members list
  with `is_encrypted=True`.
- Build order (ruled): the API PR, then makeself, then ARJ, then DMG Part G.

### 6B.1 Detection

- `encrcdsa` (8 bytes) at offset 0: v2 encrypted image (every fixture, macOS 10.5+).
- `cdsaencr` in the last 8 bytes: v1 (pre-10.5). Recognise, refuse by name.

Both map to `ArchiveFormat.DMG`. Add them as an offset-0 magic and a trailer signature
next to the `koly` ones, in Part B (not G), so the named refusal works from Part B on.
Detector precedence stays as today (far magic, then the `koly` trailer). The `encrcdsa`
check uses the head bytes detection already reads, and `cdsaencr` the last 8 bytes of
the same single 512-byte tail read, so the detection-cost receipt for the trailer tier
(`openspec/specs/detection-cost`, one 512-byte tail read on a cheap-seek source) is
unchanged; a test asserts that receipt. Until Part G lands, `DmgHandler.open` refuses
both with
`UnsupportedFeatureError("The file is an encrypted DMG disk image. Reading encrypted DMGs is not supported yet.")`
(DR-4: not corrupt, archivey just cannot read it).

### 6B.2 The v2 header (verify against the fixtures)

Big-endian. Layout as documented by vfdecrypt, dmg2img and the libyal notes on the
"encrypted disk image" format; the implementer confirms each offset on
`hfs-UDZO-AES-128.dmg` and `hfs-UDZO-AES-256.dmg` first and writes the confirmed layout
into the handbook page:

- signature `encrcdsa`, version (2), IV size, encryption mode/algorithm fields, key
  bits (128 or 256), PRNG/KDF fields, a UUID, **data block size** (4096 expected),
  **encrypted data size** and **data offset**.
- a table of **key entries** (count, then type, offset, size): each points at a key
  blob. A password key blob holds the KDF algorithm (PBKDF2), PRNG algorithm,
  **iteration count**, **salt** (length + bytes), the wrapping IV, wrapping key bits,
  wrapping algorithm (3DES-EDE), padding, mode (CBC), and the **wrapped key** (length +
  bytes). Other key entry types (public-key, keychain) are skipped; no password entry at
  all is `UnsupportedFeatureError` ("encrypted with a certificate, not a password").

### 6B.3 Unlocking

Inside the `check(password)` callback passed to `ReaderContext.unlock` (§6B.0):

1. `PBKDF2-HMAC-SHA1(password, salt, iterations, 24 bytes)` → a 3DES key. Charge the
   iterations first with `ReaderContext.charge_key_derivation(rounds)`. An
   iteration count over the cap is `ResourceLimitError`.
2. 3DES-EDE-CBC decrypt the wrapped key with the blob's IV. Check PKCS#7 padding; bad
   padding means a wrong password. The plaintext holds the AES key (16 or 32 bytes per
   key bits) followed by the 20-byte HMAC-SHA1 key (confirm on the fixtures).
3. **3DES:** use `cryptography`'s TripleDES, which encrypted images need anyway for
   AES. Import it from `cryptography.hazmat.decrepit.ciphers.algorithms` (there since
   cryptography 43; the old `primitives.ciphers.algorithms.TripleDES` warns and is due
   for removal). Add it to archivey's crypto backend beside AES-CBC, so the
   `exclude_libraries` and missing-package handling are shared. It only unwraps the key
   blob, never file data.
4. Confirm the key: decrypt the block that holds the last 512 bytes of the encrypted
   data; it must be a valid `koly` block. That, plus the padding check, gives a strong
   check (D6).

The missing-password and wrong-password `EncryptionError`s come from
`ReaderContext.unlock`; the reader writes neither.

### 6B.4 Decrypted view

`EncryptedDmgSource(ReaderSource)` serves the decrypted image of `encrypted data size`
bytes. Block `n` (4096 bytes at `data offset + n * 4096`) decrypts with AES-CBC (key
from 6B.3), IV = first 16 bytes of `HMAC-SHA1(hmac_key, n as big-endian u32)`. The last
block may be short in the file: confirm how the fixtures pad it. Cache a few decrypted
blocks. AES goes through archivey's crypto backend (`cryptography`, optional): when it
is missing, `PackageNotInstalledError` naming `cryptography`, as for ZIP AES. Then the
whole UDIF pipeline (§4 onward) runs on that source unchanged.

Header lengths are checked before any read (DR-21a for the block size): the data block
size must be 4096, the only size any fixture or producer shows (another is
`UnsupportedFeatureError`); the key-entry count is capped at 16, each entry's size and
the salt and wrapped-key lengths at 4 KiB; every offset + length must stay inside the
header (past it is `CorruptionError`; over a cap is `ResourceLimitError`), checked
before the bytes are read or allocated. With a fixed 4096-byte block, memory and work
per read are bounded; no part of the image is decrypted at open except the `koly`
block and the plist.

---

## 7. The reader

```python
class DmgHandler(IndexedFormatHandler):
    format = ArchiveFormat.DMG          # enum member already exists
    extensions = ()                     # see §3
    non_seekable_reason = "..."
    magic = ()                          # koly MAGIC/TRAILER via register_builtin_format overrides

    def open(self, source, context) -> DmgReader: ...

DmgReadBackend = register_builtin_format(DmgHandler, MAGIC=..., TRAILER=...)
```

- `open()`: a fixed envelope, nothing proportional to the image. It reads: the `koly`
  block; the property list (≤ 64 MiB, §4.2) and its run tables; the partition map (GPT
  header and entry array, at most 64 KiB as bounded in §5; or APM, at most 64 entries);
  and for each candidate partition (at most 128, §5): a 4 KiB prefix probe (signature at
  1024 for HFS+, at 32 for APFS); for HFS+, the 512-byte volume header and, when
  journaled, exactly two more reads: the journal info block at
  `journalInfoBlock × blockSize` (one 512-byte read) and the journal header at the
  offset that block gives (one 512-byte read), both checked inside the partition; for
  APFS, block 0 at its declared block size (4 KiB to 64 KiB), with its Fletcher-64
  checked at open. So open-time disk reads are at most 128 × (4 KiB + 3 × 512 bytes, or
  64 KiB for APFS) plus the map. The physical bytes behind them are bounded per run by
  the caps of §4.3, and in total by an **open budget**: beyond the property list, the
  physical bytes read plus the bytes decoded at open must stay within 64 MiB (a
  constant). Each probe usually touches one run of at most 1 MiB decoded, so real images
  use a few MiB; a hostile image whose 128 probes each land in a maximal run stops with
  `ResourceLimitError` at open when the budget is spent. The normative spec states this
  same envelope. Errors raised at open: encrypted (before Part G) and segmented
  refusals; `koly`, plist and run-table errors (§4); partition-map errors that leave no
  candidate; no filesystem found; APFS-only before Part E; HFS+ volume header errors,
  HFS wrapper, journal refusals (§6.1). Everything else is at first listing: the catalog
  and other B-trees, the APFS checkpoint scan, object maps and volume superblocks (so
  APFS volume names, and D1/D5 top-level names for APFS, are fixed at first listing).
  Work past this envelope at open is a bug, not a deferral. Tests count both the
  virtual-disk bytes requested and the physical source bytes read, on a compressed
  image, and assert the 64 MiB aggregate ceiling with 128 probes into maximal runs.
- `iter_members()`: walk the catalog, yield `MemberRecord`s. Respect `max_members` the
  way squashfs does.
- `open_member()`: `MemberData(stream, bounded=True)` over the data fork extents (a
  `block_stream` over `UdifSource`), or the decmpfs stream.
- `archive_info()`: `format_version="UDIF 4"`, `extra` keys prefixed `dmg.`:
  `dmg.filesystem` (`"HFS+"` / `"HFSX"`), `dmg.volume_name`, `dmg.partition_scheme`
  (`"GPT"`, `"APM"`, `"none"`), `dmg.run_codecs` (sorted list, e.g. `["zlib"]`).
- Encrypted images: §6B. `open()` checks for `encrcdsa` first; with Part G it unlocks
  and wraps the source, before Part G it refuses by name. Members of an encrypted image
  report `encrypted = True`, and `PASSWORD_ARGUMENT_UNUSED` behaviour for an unencrypted
  image follows the other formats.
- `archive_info().extra` also gets `dmg.encryption` (`"AES-128"` / `"AES-256"` / absent)
  and, for APFS, `dmg.apfs_volumes` (names).
- `archivey --version -v` must show DMG as readable (check the output test in
  `tests/test_cli.py::test_version_verbose_lists_formats`). The format needs no optional
  package: `format_availability(DMG)` is `FULL` without `cryptography`, as the
  backend-registry rule says for encrypted members of other formats; opening an
  encrypted image without it raises `PackageNotInstalledError` (Part G).

### 7.1 Error map

| Condition | Error |
| --- | --- |
| `koly` fields out of range, plist unparsable, run table inconsistent | `CorruptionError` |
| File ends inside the data fork, the plist, a run, a B-tree node | `TruncatedError` |
| Segmented, `cdsaencr` v1, certificate-only encryption, encrypted/sealed APFS volume, Fusion, HFS wrapper, unknown run type, directory hard link, decmpfs type unknown, run > 16 MiB | `UnsupportedFeatureError` (open-time for image-wide ones, read-time for member-local ones) |
| Encrypted image, no password or wrong password | `EncryptionError` (§6B.3) |
| APFS Fletcher-64 mismatch, omap entry missing, B-tree loop | `CorruptionError` |
| AES needed and `cryptography` missing or excluded | `PackageNotInstalledError` |
| Plist > 64 MiB, more than 128 partition candidates, the 64 MiB open budget or the checkpoint-scan budget spent, a compressed run's stored size over its cap, an encrypted-header length over its cap, too many members, metadata over `max_metadata_bytes` | `ResourceLimitError` |
| Decoder errors in zlib/bzip2/xz runs | already translated by `ReaderContext.decompress` |
| LZFSE/LZVN/ADC bad input | `CorruptionError` from the decoder, naming the run's file offset |

Damage in one file's extents or decmpfs data must not stop listing or other members
(DR-2). Damage in a run that holds catalog nodes stops the listing at that point:
deliver the members found before it, then raise.


### 7.2 Partition CRC pass (Part F)

The CRC covers disk bytes that no member stream reads (filesystem metadata, free
blocks, slack), and member streams overlap (hard links, clones, decmpfs), so member
reads are not a proxy for it. Part F therefore runs a separate pass:

- **Coverage:** the unit is a whole checked table, never a partition range (§5 lets GPT
  and `blkx` boundaries differ, and the CRC covers the table). For each `blkx` table
  with a CRC-32 (`checksum type 2`, 32 bits) that overlaps a filesystem partition, every
  run of that table except "ignore" runs, including runs outside the partition when the
  table straddles its boundary, zero-fill included, decoded in sector order,
  CRC over the decoded bytes. One run in memory at a time (bounded by §4.4). Raw runs
  are bounded by the data fork and are fed to the CRC in fixed 1 MiB slices, never as
  one whole buffer. A zero-fill run is never walked: `sector count × 512` zero bytes are
  folded into the running CRC-32 in O(log n) time with the zero-extension operator
  (the GF(2) matrix squaring that zlib's `crc32_combine` uses; Python's `zlib` does not
  expose it, so implement it, about 30 lines, tested against `zlib.crc32` on sizes up to
  a few MiB). Test: a builder image with one zero-fill run of 2^50 bytes; `verify_all()`
  returns a match within a short timeout (a few seconds). The builder (§9.2) computes
  that table's CRC-32 with the same fold, never by feeding the zero bytes to
  `zlib.crc32`.
- **`verifiable`:** set at listing and never raised later. A file member is
  `CHECKSUM` only when its whole partition range (which holds its data and every piece
  of filesystem metadata it relies on) is fully covered by `blkx` tables that each
  carry a CRC-32, with no gap in the disk index inside that range; otherwise `LENGTH`.
  A partition that is read partly from an unchecked table or a gap stays `LENGTH` for
  all its members. Directories and links as for other formats. The pass then advances
  only `verified`.
- **Trigger:** `verify_all()` only. An ordinary in-order read of members does not run
  it and does not raise members to `CHECKSUM` (it does not cover every run). The pass
  runs once per reader; its result is kept, so a second `verify_all()` does not decode
  again. No retry: decoding is deterministic.
- **Result:** a member's `verified` reaches `CHECKSUM` when every table covering its
  partition matched and its own read passed. Mismatch in a table: a `SpanningCheckError`
  that fails every member of every partition the table overlaps (one table covering two
  GPT partitions fails both); `verified` stays below `CHECKSUM`. A decode error during
  the pass fails those members the same way, naming the run.
- **Hook:** today's spanning-check hook (`archivey.formats`) publishes a result for
  members but does not schedule reads of disk ranges. Part F adds a reader-driven pass
  to it (the reader decodes its own ranges when `verify_all()` asks), as part of the
  plugin interface; that is why the maintainer merges it.
- **Tests:** `verify_all()` on a fixture raises every file to `CHECKSUM`; a flipped byte
  in a run that only holds free space or catalog nodes (no member reads it) is caught by
  `verify_all()`; a flipped byte in a zlib run that still decodes fails the partition's
  members; one CRC table straddling two GPT partitions is checked whole, and a flipped
  byte in it fails the members of both.

The data-fork CRC-32 and the master checksum in the `koly` block are checked in the same
pass when present.

---

## 8. Threat surface (for the threat-model row and the fuzz target)

- Zero-fill runs make a large disk from a tiny file; files whose extents point at
  zero-fill read as zeros. Output is bounded by member sizes and archivey's extraction
  limits, and every member read, on `open()` and on extraction, counts in the
  archive-wide ratio (`ReadRatioTally`, `DecoderLimits.max_ratio` times the image's
  size, default 800), exactly as ISO members do (`dev-docs/formats/iso.md`), whatever
  runs serve the bytes: zero fill, raw, or the in-house LZFSE/LZVN/ADC decoders, which
  do not pass through `ReaderContext.decompress`'s per-stream guard. So a 1 TiB file of
  zero fill in a 64 KiB image stops at about 50 MiB with `ResourceLimitError`;
  extraction also has `ExtractionLimits.max_extracted_bytes`. Only the partition CRC
  pass (§7.2) reads disk ranges outside member streams, which is why it folds zero fill
  instead; check the behaviour matches SquashFS's sparse blocks
  (`tests/fixtures/squashfs/large-sparse.sqfs` test in `tests/test_squashfs.py`).
- Many files sharing the same blocks (like overlapping ZIP entries).
- Loops: B-tree leaf chain, parent chains, overflow extents, APFS directory records
  that reach a directory twice, omap trees that point back up.
- APFS: a checkpoint area or object map that names thousands of superblocks or volumes;
  extents that claim huge lengths; long extent lists.
- Encryption: a huge PBKDF2 iteration count (bounded by the key-derivation budget);
  a key blob length that exceeds the header.
- Huge declared counts: runs per table, nodes, extents, xattrs, name lengths.
- Decompression bombs inside runs: covered by `ReaderContext.decompress` limits for
  zlib/bzip2/xz; the in-house LZFSE/LZVN/ADC decoders must be bounded by `max_length`
  and must never allocate from a declared size before checking it.

---

## 9. Tests

Test files: `tests/test_dmg.py` (reader), `tests/test_lzfse.py`, `tests/test_adc.py`,
updates to `tests/test_udif.py` (detection stays, refusal tests change), a builder
module `tests/dmg_build.py`, a fuzz target in `tests/atheris_fuzz/targets.py` + seeds.

### 9.1 Real fixtures from hdiutil (commit these)

From `resources/fixtures/` in this change (moved in Part B) under
`tests/fixtures/external/dmg_hdiutil/` with a README entry in
`tests/fixtures/external/README.md` (producer, macOS 26.7.1, the script below, what each
file is for). The content is our own test files, so there is no licence problem.
Suggested set:

| File | Run codec | Use |
| --- | --- | --- |
| `hfs-UDZO.dmg` | zlib (9 runs) + ignore (6) | main reader test |
| `hfs-UDBZ.dmg` | bzip2 | codec |
| `hfs-ULFO.dmg` | LZFSE | codec, pure-Python decoder |
| `hfs-ULMO.dmg` | xz | codec (7-Zip 23.01 cannot read xz DMGs) |
| `hfs-UDRO.dmg` | raw | codec |
| `hfs-UDZO-AES-128.dmg`, `hfs-UDZO-AES-256.dmg` | encrypted (`encrcdsa`), password `archivey`, zlib inside | Part G decrypt (refusal before it) |
| `apfs-UDZO.dmg`, `apfs-UDBZ.dmg`, `apfs-ULFO.dmg`, `apfs-ULMO.dmg`, `apfs-UDRO.dmg` | each codec, APFS partition | Part E (refusal before it) |
| `apfs-UDZO-AES-128.dmg`, `apfs-UDZO-AES-256.dmg` | encrypted, APFS inside | Part G with Part E |
| `hfs-sha256.txt`, `hfs-listing.txt`, `hfs-xattrs.txt`, and the `apfs-*.txt` set | macOS's own view of the mounted volume | expected values |

Committing all of them is about 5 MB. If that is too much, keep UDZO, ULFO, ULMO and
both AES-128 images for each filesystem (about 2.7 MB) and leave the rest to the
external run.

Every HFS+ and APFS image holds the same members with the same hashes (names keep their
stored Unicode form, so `café.txt` is decomposed, `cafe\u0301.txt`, in `hfs-listing.txt`
and composed, `caf\u00e9.txt`, in `apfs-listing.txt`; tests compare each fixture to its
own listing) (GPT, one `Apple_HFS` partition named `Fixture`):

```
Applications        -> /Applications   (absolute symlink)
compressed.txt      360,000 bytes, decmpfs type 8 (LZVN in resource fork)   sha256 e688dfc5…
hello.txt           "hello dmg\n", xattr com.example.test = "xattr value"  sha256 c6ced9f7…
link-rel            -> hello.txt
random.bin          300,000 random bytes                                    sha256 e24447be…
sub dir/            directory with a space
sub dir/café.txt    non-ASCII name                                          sha256 7b49b9e0…
sub dir/hardlink.txt  hard link to hello.txt                                sha256 c6ced9f7…
text.txt            same content as compressed.txt, not compressed         sha256 e688dfc5…
```

Full hashes are in `hfs-sha256.txt` / `apfs-sha256.txt`. The prototype reads all five
HFS+ and all five unencrypted APFS images and gives those hashes for every file (checked
2026-11-21). The encrypted images have not been decrypted by anything yet: Part G's
first task is to confirm §6B.2 on them, using `hdiutil` output if needed (the maintainer
has a Mac) or `dmg2img`/`vfdecrypt` as an oracle on Linux. macOS adds
`com.apple.provenance` xattrs (empty values) to every file; the test must accept them.
The fixture script that made the set is in Appendix A, so the maintainer can regenerate
or extend it on a Mac.

### 9.2 Test-side builders (generated at test time, not committed)

`tests/dmg_build.py`, in the style of `tests/cab_util.py` and `tests/tar_build.py`:

- `write_udif(disk: bytes, *, runs=..., codec=...) -> bytes`: split a raw disk into runs
  with any codec (zlib via `zlib`, bzip2 via `bz2`, xz via `lzma`, raw, zero-fill for
  all-zero runs, ignore, ADC as literal-only blocks, LZFSE as uncompressed `bvx-` blocks
  or LZVN literal-only blocks, or real LZFSE via the `lzfse` package when installed),
  with a correct `mish` table per partition, plist, CRC-32 checksums and `koly` block.
  A zero-fill run can also be given by its length alone, with no bytes in `disk`, so a
  test can build a disk of 2^50 bytes; the CRC-32 of such a run is computed with the
  §7.2 fold. Options to break each field.
- `write_gpt(partitions) -> bytes`, `write_apm(partitions) -> bytes`.
- `write_hfsplus(tree) -> bytes`: a minimal HFS+ writer: volume header, allocation file,
  one catalog B-tree (header node + leaf nodes, enough for a few hundred entries),
  optional extents-overflow and attributes B-trees, hard links via the private folder,
  symlinks, decmpfs files (each type in 6.6), and hooks to corrupt any structure (leaf
  loop, parent loop, extent past the volume, overlapping extents, bad node offsets,
  names with `/`, 255-unit names, invalid UTF-16). This is the main tool for the
  damage tests; there is no Linux tool that writes filled HFS+ volumes reliably
  (`hfsprogs` `mkfs.hfsplus` makes empty ones only, and the Linux userland write tools
  hang).
- `write_apfs(tree) -> bytes` (Part E): a minimal APFS container writer: one checkpoint
  with one `NXSB`, a container omap, one volume (`APSB`) with its omap and a filesystem
  tree of one or two levels, correct Fletcher-64 on every object, plain or hashed
  directory keys, hard links, sparse and cloned extents, decmpfs xattrs. Hooks to break
  each structure (stale checkpoint with a higher xid but a bad checksum, omap loop,
  missing omap entry, extent past the container, directory loop, encrypted/sealed
  flags). `apfsprogs` (`mkapfs`, apt) makes empty containers only, so it can serve as a
  check of the writer's container layer, not as the fixture source.
- `encrypt_dmg(image, password, key_bits)` (Part G): wraps a UDIF image in `encrcdsa` v2
  once §6B.2 is confirmed, for damage tests (bad padding, short blob, huge iteration
  count, cut last block). Checked against the real fixtures' layout.
- Check the builders against the real fixtures where possible: an image built from the
  same tree should list the same members as `hfs-UDZO.dmg` / `apfs-UDZO.dmg`.

### 9.3 Oracle: 7-Zip

7-Zip is installed in the dev environment (`scripts/setup-dev-env.sh`; tests skip when
it is missing, like the other 7-Zip oracle tests). For each fixture and builder output,
compare `7z l -slt` and `7z x` with archivey's listing and extraction: names, types,
sizes, content hashes. **Known, accepted 7-Zip differences** (write each as an explicit
exception in the test, with the reason):

| 7-Zip 23.01 | archivey | Why |
| --- | --- | --- |
| Skips absolute symlinks (`/Applications`) and symlinks that climb several levels | Lists them as symlinks | The mount shows them; DR-1 |
| Extracts file hard links as empty files | Second path is `HARDLINK` to the first, with the content | 7-Zip is wrong |
| Cannot open xz (ULMO) images (lists raw partitions) | Reads them | |
| Shows `.HFS+ Private Directory Data\r`, the private data folder, journal files | Hidden | Match the mount (macOS) |
| Writes xattrs as `name:attr` side files | Lists in `extra` only (D2) | |
| May list the partitions themselves as members when it cannot find a filesystem | Refuses | |

The macOS listing in `hfs-sha256.txt` / `hfs-listing.txt` is the primary truth; 7-Zip is
the secondary oracle for builder-made images.

### 9.4 LZFSE/LZVN/ADC decoder tests

- Real data: `hfs-ULFO.dmg` runs (LZFSE) and `compressed.txt` (LZVN).
- When the `lzfse` package is installed (test-only, skip otherwise): random inputs and
  binaries compressed by it, decoded by the pure-Python decoder, byte-identical (the
  prototype passed 3,000 random inputs). Cover every block kind: `bvx2` (compressed v2),
  `bvx1` (v1, uncompressed tables), `bvxn` (LZVN), `bvx-` (raw), `bvx$` (end).
- Damage: every truncation point of a small stream raises
  `CorruptionError`/`TruncatedError` and never more than `max_length` output; bad FSE
  table states; matches before the start.

### 9.5 External corpus run (not committed, not in CI)

Real DMGs from GitHub release pages (third-party apps, so not committable). The URL list
(Appendix B, `resources/dmgurls.txt`) has 54 URLs; the 2026-11-09 investigation measured
the 41 of them that downloaded and parsed then (the numbers elsewhere in this plan are
those 41). The script runs every URL, records which ones download, and compares those.
Provide a script (e.g. `scripts/dev/dmg_corpus.py`, or document the commands in the
handbook page §Verify) that downloads them to a cache directory and compares archivey
with 7-Zip file by file (SHA-256), applying the §9.3 exceptions. Expected from the
prototype: 36 HFS+ images identical except the macFUSE hard links (where 7-Zip is
wrong); the 5 APFS images (MacVim, VSCodium, Zed, dosbox-staging, Mumble) identical once
Part E lands. The maintainer runs it before merging Parts B and E. Optional extra
oracles from the investigation: `dpp-py` (Rust; fails on HFS+ hard links), libyal
`libfshfs`/`libfsapfs` (no xz runs in `libmodi`).

### 9.6 Behaviour tests to include

- Each run codec, each partition scheme (GPT, APM, none), HFS+ and HFSX.
- Listing touches only metadata runs (count decoded runs during listing; the prototype
  lists every real image in < 0.4 s).
- Random access: `seekable_members` reads inside a large file decode only the runs
  needed.
- Pipe input: refused or spooled per `required_source = SEEKABLE` (same tests as ISO).
- Every refusal in §1 and §7.1 has a test with its message.
- `DecoderLimits` / `ListingLimits` apply (a zlib run over the ratio guard, too many
  members, too much metadata).
- Damage tests from 9.2, each asserting DR-2 (members before the damage are delivered).
- Detection unchanged: every case in the current `tests/test_udif.py` still detects the
  same format; an uncompressed image with an ISO 9660 payload is still `ISO`.
- `tests/test_registry.py::test_required_source_is_declared_for_every_known_format`
  updated to `SEEKABLE`.
- APFS (Part E): every fixture; plain and hashed keys; a stale checkpoint is skipped for
  the newest valid one; every refusal in §6A; Fletcher-64 damage on each object kind.
- APFS damaged key ranges (Part E): a filesystem tree of three leaves from `write_apfs`
  holding a sparse file A (a hole between two extents, leaf 1), a file B whose inode id
  and data-stream id are the same number (as in the fixtures) and whose extents alone
  sit in leaf 2 (its inode and directory record in leaf 1), and a file C (leaf 3); leaf
  2's checksum is broken. Expected: A reads with zeros in its hole; B lists and its read
  raises `CorruptionError` (not zeros); C reads normally; the listing ends with
  `CorruptionError`. The same with a damaged object-map leaf: lookups of the oids it
  mapped raise `CorruptionError`.
- UDIF bounds, through a source that counts the bytes requested from it: a plist length
  over 64 MiB raises `ResourceLimitError` with no byte of the plist requested; a run
  whose stored length is over the cap raises `ResourceLimitError` with no byte of the
  run requested; a run whose decoder yields more than `count * 512` bytes raises
  `CorruptionError` after at most `count * 512 + 1` decoded bytes; a `mish` table that
  declares more runs than its `Data` holds raises `CorruptionError` before any run is
  kept; a member read never requests more bytes than the capped stored lengths of the
  runs it covers.
- Encryption (Part G): both key sizes open with `password="archivey"`; no password;
  wrong password; several candidates where only the last is right; iteration count over
  the budget; `cryptography` excluded through `exclude_libraries`; members report
  `encrypted`; random access inside a large file decrypts only the blocks it needs.
- Fuzz targets: open, list, read the first members of builder images (UDIF + HFS+,
  UDIF + APFS, encrypted wrapper); seeds from the builders and the committed fixtures.

---

## 10. Speed expectations

Measured with the prototype (same algorithms, stdlib decoders): within 1x to 2x of 7-Zip
end to end on zlib, bzip2 and xz images (Cutter 640 MB: 2.8 s vs 4.1 s). LZFSE in pure
Python: about 7 MB/s (VSCodium: 83 s vs 2 s for 7-Zip); Part H fixes that. Add a
benchmark only if the repo's benchmark gate expects one for new formats (check
`tests/test_benchmark_gate.py`).

---

## 11. Implementation parts

One plan, built in parts. Each part is one PR unless noted, merges on its own, and
leaves `main` with every test green and every DMG either read correctly or refused by
name. Part A0 decided that Part H does not use the `lzfse` package (A0.2); Parts B to E
depend on A; the order after B is flexible except where noted.

| Part | Contents | Depends on | Who merges |
| --- | --- | --- | --- |
| **A0. Evaluate the `lzfse` package** | An investigation PR (results under `dev-docs/investigations/`, scripts under `scripts/investigations/`, like the compress-utils LZO evaluation). Check: wheels for CPython 3.11 to 3.15, free-threaded 3.14t/3.15t, PyPy, Linux (glibc and musl), macOS (arm64 and x86) and Windows; licence and maintenance; whether a call can cap its output (a declared size must not drive the allocation); whether raw LZVN blocks (decmpfs types 7 and 8) can be decoded, directly or by wrapping them in a `bvxn` block header; behaviour under a fuzz run (no crash, hang or over-cap output, in a child process per DR-20); child-process cost per 1 MiB run; agreement with the prototype on the fixtures and random inputs. Ends with a recommendation on whether Part H uses it as the accelerator. | none | maintainer decides |
| **A. Decoders** | `lzfse_decoder.py` (LZFSE + LZVN) and `adc_decoder.py`, pure Python, §9.4 tests; `CompressionAlgorithm.LZFSE`, `LZVN`, `ADC` (D8). No reader. | none | maintainer (new public names) |
| **B. UDIF + partitions + HFS+** | §3 to §7 for HFS+: `udif.py` rewrite, `disk_partitions.py`, `hfsplus.py`, `dmg_reader.py`, detection kept, the `encrcdsa`/`cdsaencr` signatures registered (§6B.1), encrypted and APFS refused by name, HFS+ fixtures, `tests/dmg_build.py` (UDIF, GPT, APM, HFS+ writers), 7-Zip oracle tests, fuzz target, handbook page, threat-model row, OpenSpec change. The big one: the test builders may go first as their own PR. | A | maintainer (new readable format, needs-minor) |
| **C. User docs** | `docs/formats.md` §Disk images, the formats table, `--version -v` wording. Written in the maintainer's docs session (DR-22b). | B | maintainer |
| **D. Hidden-content and edge polish** | Anything Part B's review defers: journal hiding cases, directory hard links if a fixture appears, xattr value caps, extra checks found by the corpus run. May be empty. | B | agent |
| **E. APFS** | §6A: `apfs.py`, the reader using it, `write_apfs` builder, APFS fixtures, D5 multi-volume listing, Fletcher-64, refusals (encrypted volume, sealed, Fusion), fuzz target, handbook page section. | B | maintainer (new filesystem; davi decision D5) |
| **F. Partition CRC-32 spanning check** | D4, as a partition pass (details in §7.2). | B | maintainer (changes a verification guarantee) |
| **G. Encrypted images** | §6B: `dmg_crypto.py`, TripleDES key unwrap, password flow, `EncryptedDmgSource`, `encrypt_dmg` builder, AES fixtures. Starts by confirming §6B.2 on the fixtures and writing the confirmed layout into the handbook page. Works for HFS+ at once and for APFS once E is in. | B, and the plugin-interface password change (§6B.0); E for APFS images | maintainer (password handling, new crypto code) |
| **H. LZFSE accelerator** | D3 as ruled in A0.2: archivey's own LZFSE and LZVN kernel in the `archivey-codecs` Rust package, with a bounded output and the same checks as the Python decoder, so the result never changes. archivey uses it when the package is installed. Tests that both decoders agree on every fixture and on the A0 fuzz corpus; `--all-configs` run. | A, and the `archivey-codecs` package | maintainer (new dependency) |

Each part's PR body says which part of this plan it implements and lists any place it
departs from the plan, with the reason.

---

## 12. Later (outside this plan; list in the handbook page's open questions)

- Encrypted APFS volumes (native APFS encryption with keybags), sealed volumes, Fusion
  containers, snapshots.
- `cdsaencr` v1 encrypted images, certificate-encrypted images.
- Segmented images, sparse images and bundles, NDIF, resource-fork-only images.
- Raw `.dmg` disk images without `koly` (UDRW), raw GPT/HFS+/APFS disk images.
- Replaying an HFS+ journal with pending transactions (refused by name today, §6.1).
- Writing xattrs on extract (a cross-format feature).
- An LZFSE kernel in the parked Rust core.

---

## 13. Done when (whole plan)

- [ ] All HFS+ and APFS fixture images list exactly the members in §9.1 (no hidden
      folders), with the macOS hashes, types, link targets, and `hello.txt`'s xattr in
      `extra`; the encrypted ones do the same with `password="archivey"`.
- [ ] A no-`koly` UDRW image behaves as it does today; every refusal in §1 and §7.1 has
      its named message and a test.
- [ ] Every damage test delivers the members before the damage, then raises an archivey
      error; no test input causes unbounded memory, a hang or a native crash.
- [ ] `./scripts/check.sh` and `./scripts/test.sh` pass; `--all-configs` from Part H on.
- [ ] `dev-docs/formats/dmg.md`, `threat-model.md`, `docs/formats.md`, and the OpenSpec
      change are updated with each part.
- [ ] The external corpus run (9.5) matches 7-Zip on every image in the list that
  downloads (41 at the investigation), apart from the
      listed 7-Zip differences.
- [ ] After Part F, `verify_all()` on a fixture raises every file to `CHECKSUM`, and a
      flipped byte in any run is caught.

---

## Appendix A: fixture script (run on a Mac)

This made `dmg-fixtures-2026-11-10.tar.gz`. Commit it next to the fixtures as
`make-dmg-fixtures.sh`, like `tests/fixtures/squashfs/make-images.sh`.

```bash
#!/bin/bash
# Make small DMG fixtures for archivey on a Mac. Writes ~/dmg-fixtures.tar.gz.
set -uo pipefail
OUT="$HOME/dmg-fixtures"; rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"; SRC="$T/src"; mkdir -p "$SRC/sub dir"
printf 'hello dmg\n' > "$SRC/hello.txt"
printf 'caf\xc3\xa9\n' > "$SRC/sub dir/caf$(printf '\xc3\xa9').txt"
head -c 300000 /dev/urandom > "$SRC/random.bin"
yes 'compressible line' | head -n 20000 > "$SRC/text.txt"
ln -s hello.txt "$SRC/link-rel"; ln -s /Applications "$SRC/Applications"
ln "$SRC/hello.txt" "$SRC/sub dir/hardlink.txt"
xattr -w com.example.test 'xattr value' "$SRC/hello.txt"
sw_vers > "$OUT/macos-version.txt"
for FS in HFS+ APFS; do
  TAG=$( [ "$FS" = "HFS+" ] && echo hfs || echo apfs )
  RW="$T/rw-$TAG.dmg"; MNT="$T/mnt-$TAG"; mkdir -p "$MNT"
  hdiutil create -quiet -size 16m -fs "$FS" -volname Fixture -type UDIF "$RW" || { echo "create $FS failed"; continue; }
  hdiutil attach -quiet -nobrowse -noverify -mountpoint "$MNT" "$RW" || { echo "attach $FS failed"; continue; }
  ditto "$SRC" "$MNT"
  ditto --hfsCompression "$SRC/text.txt" "$MNT/compressed.txt"
  ( cd "$MNT" && ls -laRO . > "$OUT/$TAG-listing.txt"; find . -type f -exec shasum -a 256 {} + > "$OUT/$TAG-sha256.txt"; xattr -lr . > "$OUT/$TAG-xattrs.txt" 2>&1 )
  hdiutil detach -quiet "$MNT"
  cp "$RW" "$OUT/$TAG-UDRW.dmg"
  for F in UDZO UDBZ ULFO ULMO UDRO; do
    hdiutil convert -quiet "$RW" -format "$F" -o "$OUT/$TAG-$F.dmg" || echo "convert $TAG $F failed" >> "$OUT/skipped.txt"
  done
  for E in AES-128 AES-256; do
    printf 'archivey' | hdiutil convert -quiet "$RW" -format UDZO -encryption "$E" -stdinpass -o "$OUT/$TAG-UDZO-$E.dmg" \
      || echo "convert $TAG $E failed" >> "$OUT/skipped.txt"
  done
done
for D in "$OUT"/*.dmg; do echo "== $(basename "$D")"; head -c 8 "$D" | od -c | head -1; done > "$OUT/heads.txt"
tar czf "$HOME/dmg-fixtures.tar.gz" -C "$HOME" dmg-fixtures && ls -la "$HOME/dmg-fixtures.tar.gz"
rm -rf "$T"
```

## Appendix B: real-DMG corpus URLs (external run, §9.5)

GitHub release downloads, fetched 2026-11-09. Some links may have moved; the run should
skip missing ones and report them.

```
https://github.com/rxhanson/Rectangle/releases/download/v0.85/Rectangle0.85.dmg
https://github.com/keepassxreboot/keepassxc/releases/download/2.7.9/KeePassXC-2.7.9-arm64.dmg
https://github.com/exelban/stats/releases/latest/download/Stats.dmg
https://github.com/iina/iina/releases/download/v1.3.5/IINA.v1.3.5.dmg
https://github.com/MonitorControl/MonitorControl/releases/download/v4.3.2/MonitorControl.4.3.2.dmg
https://github.com/neovide/neovide/releases/latest/download/Neovide-aarch64-apple-darwin.dmg
https://github.com/alacritty/alacritty/releases/download/v0.13.2/Alacritty-v0.13.2.dmg
https://github.com/ollama/ollama/releases/latest/download/Ollama.dmg
https://github.com/objective-see/LuLu/releases/download/v2.6.3/LuLu_2.6.3.dmg
https://github.com/dwarvesf/hidden/releases/download/v1.9/Hidden.Bar.1.9.dmg
https://github.com/laurent22/joplin/releases/download/v3.0.15/Joplin-3.0.15.dmg
https://github.com/balena-io/etcher/releases/download/v1.19.21/balenaEtcher-1.19.21-arm64.dmg
https://github.com/telegramdesktop/tdesktop/releases/download/v5.5.5/tsetup.5.5.5.dmg
https://github.com/macvim-dev/macvim/releases/download/release-180/MacVim.dmg
https://github.com/Kong/insomnia/releases/download/core%409.3.3/Insomnia.Core-9.3.3.dmg
https://github.com/gnachman/iTerm2/releases/download/v3.5.0/iTerm2-3_5_0.dmg
https://github.com/transmission/transmission/releases/download/4.0.6/Transmission-4.0.6.dmg
https://github.com/audacity/audacity/releases/download/Audacity-3.6.4/audacity-macOS-3.6.4-arm64.dmg
https://github.com/keycastr/keycastr/releases/download/v0.10.1/KeyCastr.dmg
https://github.com/zed-industries/zed/releases/download/v0.150.4/Zed-aarch64.dmg
https://github.com/lapce/lapce/releases/download/v0.4.2/Lapce-macos.dmg
https://github.com/upscayl/upscayl/releases/download/v2.11.5/upscayl-2.11.5-mac.dmg
https://github.com/Eugeny/tabby/releases/download/v1.0.215/tabby-1.0.215-macos-arm64.dmg
https://github.com/FreeCAD/FreeCAD/releases/download/0.21.2/FreeCAD-0.21.2-macOS-arm64.dmg
https://github.com/Mortennn/Dozer/releases/download/v4.0.0/Dozer.4.0.0.dmg
https://github.com/pqrs-org/Karabiner-Elements/releases/download/v15.0.0/Karabiner-Elements-15.0.0.dmg
https://github.com/sindresorhus/caprine/releases/download/v2.60.1/Caprine-2.60.1.dmg
https://github.com/AppFlowy-IO/AppFlowy/releases/download/0.7.0/AppFlowy-0.7.0-macos-universal.dmg
https://github.com/brave/brave-browser/releases/download/v1.69.168/Brave-Browser-universal.dmg
https://github.com/VSCodium/vscodium/releases/download/1.92.2.24228/VSCodium.arm64.1.92.2.24228.dmg
https://github.com/rustdesk/rustdesk/releases/download/1.3.1/rustdesk-1.3.1-aarch64.dmg
https://github.com/localsend/localsend/releases/download/v1.15.4/LocalSend-1.15.4.dmg
https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v1.7.7/Clash.Verge_1.7.7_aarch64.dmg
https://github.com/pot-app/pot-desktop/releases/download/3.0.5/pot_3.0.5_aarch64.dmg
https://github.com/lencx/ChatGPT/releases/download/v1.1.0/ChatGPT_1.1.0_macos_aarch64.dmg
https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.26.14/VeraCrypt_1.26.14.dmg
https://github.com/macfuse/macfuse/releases/download/macfuse-4.8.0/macfuse-4.8.0.dmg
https://github.com/osxfuse/osxfuse/releases/download/osxfuse-3.11.2/osxfuse-3.11.2.dmg
https://github.com/xbarapp/xbar/releases/download/v2.1.7-beta/xbar.v2.1.7-beta.dmg
https://github.com/rizinorg/cutter/releases/download/v2.3.4/Cutter-v2.3.4-macOS-arm64.dmg
https://github.com/HandBrake/HandBrake/releases/download/1.8.2/HandBrake-1.8.2.dmg
https://github.com/mltframework/shotcut/releases/download/v24.08.29/shotcut-macos-24.08.29.dmg
https://github.com/OpenShot/openshot-qt/releases/download/v3.2.1/OpenShot-v3.2.1-x86_64.dmg
https://github.com/keeweb/keeweb/releases/download/v1.18.7/KeeWeb-1.18.7.mac.x64.dmg
https://github.com/tw93/Pake/releases/download/V2.3.0/WeRead.dmg
https://github.com/marktext/marktext/releases/download/v0.17.1/marktext-x64.dmg
https://github.com/Molunerfinn/PicGo/releases/download/v2.3.1/PicGo-2.3.1-arm64.dmg
https://github.com/LibreCAD/LibreCAD/releases/download/2.2.0.2/LibreCAD-2.2.0.2.dmg
https://github.com/mumble-voip/mumble/releases/download/v1.5.634/mumble_client-1.5.634.x64.dmg
https://github.com/dosbox-staging/dosbox-staging/releases/download/v0.81.2/dosbox-staging-macOS-v0.81.2.dmg
https://github.com/xournalpp/xournalpp/releases/download/v1.2.3/xournalpp-1.2.3-macOS-arm64.dmg
https://github.com/musescore/MuseScore/releases/download/v4.4.1/MuseScore-Studio-4.4.1.242490810.dmg
https://github.com/mgba-emu/mgba/releases/download/0.10.3/mGBA-0.10.3-macos.dmg
https://github.com/syncthing/syncthing-macos/releases/download/v1.27.11-1/Syncthing-1.27.11-1.dmg
```

## Appendix C: sources

- Apple, *Apple File System Reference* (2020); Technical Note TN1150, *HFS Plus Volume
  Format*.
- Apple LZFSE reference implementation, github.com/lzfse/lzfse (BSD-3):
  `lzfse_decode_base.c`, `lzfse_fse.h`, `lzvn_decode_base.c`.
- 7-Zip `CPP/7zip/Archive/DmgHandler.cpp`, `HfsHandler.cpp`, `ApfsHandler.cpp`.
- libyal format notes: libmodi (UDIF), libfshfs (HFS+), libfsapfs (APFS), and the
  encrypted disk image notes.
- vfdecrypt and dmg2img sources for the `encrcdsa` layout and decryption.
- Investigation report 2026-11-09 (prototype results, corpus, library comparison);
  summarised in this file.
