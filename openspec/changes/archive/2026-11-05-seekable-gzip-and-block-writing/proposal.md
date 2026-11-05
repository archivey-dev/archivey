# Seekable blocked-gzip reading + block-split writing

> **Archive note:** Archived on 2026-11-05 with the remaining tasks undone (maintainer decision). mgzip reading, an `indexed_gzip` backend and block-split writing are tracked internally as three separate items.

## Why

Random access inside a single gzip stream currently requires an accelerator: the
`[seekable]` extra ships `rapidgzip` (gzip) and `indexed_bzip2` (bzip2), and without one
gzip is forward-only — a backward seek re-decompresses from the start, which the stream
layer now *warns* about (`seekable-decompressor-streams`). That is the right default for
**arbitrary** gzip, where block boundaries can only be discovered by decoding.

But two widely used gzip **variants** are *self-describing* and need no decoding to index:

- **BGZF** (the bgzip format; ubiquitous in bioinformatics — BAM/VCF/tabix). The file is a
  sequence of independent ≤64 KiB gzip members; each member's gzip extra field carries a
  `BC` subfield holding the compressed block size (`BSIZE`). A 28-byte empty member marks
  EOF. A BGZF file is a **valid gzip file** — standard tools decompress it unchanged.
- **mgzip** (a multi-threaded gzip writer). Same idea: each block is a standalone gzip
  member whose extra field (`MZ` subfield, 4-byte body) stores that member's compressed
  size; no 64 KiB cap. Also a valid gzip file.

Both store the per-block compressed size in the header, so a block index can be built by
**walking members without decompressing** — exactly the shape we already parse natively
for XZ (stream/block index) and lzip (trailer scan). That means Archivey can give BGZF and
mgzip **random access with zero dependencies** (stdlib `zlib` only), matching the
native-first philosophy and **without** requiring `rapidgzip`.

Separately, `indexed_gzip` (a Cython wrapper over zlib's `zran.c`) is a lighter, more
portable accelerator than `rapidgzip` for *arbitrary* gzip, and it can **persist** its
index (`.gzidx` export/import). It is worth offering as an opt-in alternative gzip backend.

Finally, the **write** side is the mirror of all of this: compressing in independent blocks
of size *X* makes the output randomly seekable later (and parallel-compressible). For gzip
that means emitting **BGZF** — a standard, interoperable format, not a bespoke one — which
round-trips with the native reader above. For xz it means setting the `lzma` `block_size`
(already readable by our XZ index reader); for zstd, the **zstd seekable format**.

This change is **specs only**: it records the intended capability so the read/write
symmetry is designed in. No code lands here; implementation is sequenced under Impact.

## What Changes

> **Update (2026-10-20):** native BGZF reading shipped on its own, in the archived
> `gzip-member-seek-points` change. What is left here is mgzip, `indexed_gzip` and
> block-split writing; the blocked-gzip requirement in `specs/` now covers mgzip only.

- **`seekable-decompressor-streams`** — two added requirements:
  - **Native blocked-gzip random access (BGZF / mgzip):** recognize the blocked structure
    from the first member's extra field, build a `SeekPoint` index by walking members via
    the per-block compressed size (no decompression), and serve random reads by decoding
    only the needed member(s). Zero-dependency (stdlib `zlib`). Arbitrary (non-blocked)
    gzip is unaffected and still relies on the sequential/accelerator path.
  - **`indexed_gzip` as an alternative gzip accelerator:** an optional backend for
    *arbitrary* gzip random access, selected like the existing accelerators, with clean
    absence behavior; it may build and (optionally) import/export a persistent index.
- **`packaging-and-extras`** — note that `[seekable]` MAY include `indexed_gzip` as an
  alternative gzip accelerator alongside `rapidgzip` / `indexed_bzip2`.
- **`format-single-file-compressors`** — an added requirement for **block-split writing**:
  an optional `block_size` that produces independently-decompressible output — gzip→BGZF,
  xz→`lzma` block size, zstd→zstd seekable format — defaulting off (one solid stream), with
  output that remains readable by standard tools and by Archivey's native seekable readers.

Not changing **`format-detection`**: BGZF and mgzip are detected as `gzip` by magic
(`1f 8b`) exactly as today; the blocked structure is discovered by the seekable reader, not
by detection. No new magic, no new format enum.

## Specs

Proposed deltas (kept here, not applied to `openspec/specs/*` until accepted, per the
"propose in `changes/`, don't edit shipped specs ad hoc" rule). Requirement text is written
sync-ready.

### seekable-decompressor-streams — ADDED Requirement: Native random access for blocked gzip (BGZF / mgzip)

The system SHALL provide zero-dependency random access within **blocked gzip** streams —
BGZF and mgzip — by reading the per-block size recorded in each gzip member's extra field,
without decompressing to find block boundaries. Blocked gzip is a sequence of independent
standalone gzip members; the system SHALL build a seek-point index by walking the members
(each member's compressed size comes from its extra subfield; its uncompressed size from
its gzip `ISIZE` trailer) and SHALL serve a seek by decoding only the member(s) containing
the target offset. Recognition is by the member's extra subfield: BGZF's `BC` subfield
(`BSIZE`, ≤64 KiB blocks) or mgzip's `MZ` subfield (4-byte compressed-member-size body).
A gzip stream with **no** recognized blocked-gzip subfield is not treated as blocked; it
falls back to the sequential path (or an accelerator, if enabled). Because blocked gzip is
valid gzip, the same bytes remain decompressible by any gzip tool.

When the blocked-gzip index is available, the reader SHALL report random-access capability
in its cost (non-SOLID `access_cost` and a `seekable` flag), per
`format-single-file-compressors`.

#### Scenario: seeking within a BGZF file via the BC subfields

- **WHEN** a seekable source whose first gzip member carries a `BC` extra subfield is opened
- **THEN** the system walks the members using each block's `BSIZE` to build a block index without decompressing
- **AND** a subsequent seek to an arbitrary uncompressed offset decodes only the block(s) containing that offset

#### Scenario: seeking within an mgzip file via the MZ subfield

- **WHEN** a seekable source whose gzip members carry the mgzip `MZ` extra subfield is opened
- **THEN** the system builds the block index from the per-member compressed sizes and serves seeks by decoding only the needed member(s)

#### Scenario: a plain gzip stream is not treated as blocked

- **WHEN** a gzip stream has no recognized blocked-gzip extra subfield
- **THEN** the native blocked-gzip path does not engage; the stream is served sequentially (or by an accelerator, if enabled), exactly as today

### seekable-decompressor-streams — ADDED Requirement: indexed_gzip as an alternative gzip accelerator

The system MAY use `indexed_gzip` (a zlib `zran`-based backend) as an alternative to
`rapidgzip` for random access within **arbitrary** gzip streams, resolved by the same
access-mode-aware configuration as the other accelerators and gated by the `[seekable]`
extra. When enabled and installed it builds an index of seek points on demand; it MAY
support importing/exporting that index to a persistent file. When it is absent or disabled,
behavior is unchanged (sequential, with the rewind warning). `indexed_gzip` requires a
seekable source.

#### Scenario: gzip random access via indexed_gzip

- **WHEN** the `indexed_gzip` backend is enabled and installed and a seekable gzip source is opened
- **THEN** a seek to an arbitrary uncompressed offset is served without decompressing from the start

#### Scenario: indexed_gzip backend absent

- **WHEN** `indexed_gzip` is not installed or is disabled
- **THEN** gzip random access falls back to any other enabled accelerator, else to the sequential path (which warns once on a rewind)

### packaging-and-extras — MODIFIED Requirement: the `[seekable]` extra

The `[seekable]` extra MAY include `indexed_gzip` as an alternative gzip accelerator
alongside `rapidgzip` (gzip) and `indexed_bzip2` (bzip2). All remain optional: the core
reads these formats sequentially without them. (No change to the zero-dependency core: the
native blocked-gzip reader above adds **no** dependency — it uses stdlib `zlib`.)

#### Scenario: seekable extra provides the gzip accelerators

- **WHEN** `[seekable]` is installed
- **THEN** `rapidgzip` and/or `indexed_gzip` are available as gzip random-access backends, and `indexed_bzip2` as the bzip2 backend

### format-single-file-compressors — ADDED Requirement: block-split writing for seekable output

When writing a single-file compressed stream, the system MAY accept a `block_size` option
that produces **independently-decompressible blocks**, so the result supports later random
access (and parallel compression). The mechanism is per codec and SHALL use the format's
standard, interoperable blocking — never a bespoke container:

- **gzip → BGZF**: independent ≤64 KiB gzip members with the `BC` extra subfield (and the
  28-byte EOF marker). Output is valid gzip and is randomly seekable by the native
  blocked-gzip reader.
- **xz → multi-block**: set the `lzma` stream `block_size`; output is ordinary `.xz`,
  randomly seekable via the XZ block index the reader already parses.
- **zstd → zstd seekable format**: the skippable-frame seek table; output is ordinary
  `.zst`.

`block_size` SHALL default to off (a single solid stream — today's behavior). A codec with
no block mechanism SHALL ignore the option (or reject it) rather than silently writing a
non-seekable stream that claims to be blocked.

#### Scenario: writing gzip with a block size yields seekable BGZF

- **WHEN** a gzip single-file stream is written with `block_size` set
- **THEN** the output is a valid BGZF gzip file (standard tools decompress it) that the native blocked-gzip reader can randomly seek

#### Scenario: writing xz with a block size yields a seekable multi-block stream

- **WHEN** an xz single-file stream is written with `block_size` set
- **THEN** the output is an ordinary `.xz` whose block index lets the reader seek to an arbitrary offset by decoding only the relevant block(s)

#### Scenario: default writing stays solid

- **WHEN** no `block_size` is given
- **THEN** a single solid stream is written, exactly as today

## Impact

- **Depends on:** Phase 2 stream layer — the `DecompressorStream` / `SeekPoint` index
  machinery (reused by the blocked-gzip reader), the codec registry, and the `[seekable]`
  extra. The write side depends on the archive/single-file **writing** path (later phase).
- **Affected capabilities:** `seekable-decompressor-streams` (two new requirements),
  `packaging-and-extras` (optional `indexed_gzip`), `format-single-file-compressors`
  (`block_size` write option). No change to `format-detection` or the format enum.
- **Sequencing (implementation, not in this proposal):**
  - *Native blocked-gzip reading* fits alongside the other native seekable readers and can
    land with single-file compressors (Phase 3) or shortly after — it is pure-stdlib.
  - *`indexed_gzip`* is a small optional-backend addition; lowest priority, non-breaking.
  - *`block_size` writing* belongs to the writing phase (Phase 5+), designed to round-trip
    with the native readers.
- **Out of scope:** arbitrary (non-blocked) gzip random access without an accelerator
  remains unsupported by design; standalone mgzip support beyond recognizing its `MZ`
  subfield in the shared blocked-gzip reader is not pursued (too niche to warrant its own
  path); the bespoke `indexed_gzip` `.gzidx` on-disk index format is referenced as an
  optional capability, not mandated.
