# SquashFS

Current maintainer truth for SquashFS 4.0 images: snap packages, live-system roots, and
what `mksquashfs` writes. A SquashFS image is a compressed read-only filesystem with its
index after the data, so archivey reads it from a source that can seek. The reader is
written against `archivey.formats`, the API a format added from outside uses, and is
registered as a built-in the way ISO, CPIO and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/squashfs_reader.py`, a `SquashfsHandler` (`FormatHandler`) and a `SquashfsReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the directory and inode tables come after the data |
| Listing cost | From the index (the inode and directory tables) |
| Access cost | `DIRECT`. Small files share a fragment block, which is decoded once and kept (four at a time) |
| Core dependencies | None for gzip, xz, LZMA and LZO images. Zstandard images need what a `.zst` file needs; LZ4 images need `lz4` (`[recommended]`). LZO is decoded as a `.lzo` file is: liblzo2 through `python-lzo` in a child process when it is installed, otherwise Python |
| Encryption | None |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Checksums | None. A damaged block is found only when it does not decode to its length |
| Refuses | Big-endian images (SquashFS 3 and older, magic `sqsh`), with `UnsupportedFeatureError`; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-squashfs/spec.md` |

Not here, though a reader might look for it: extended attributes and the NFS export table
are not read, and the compressor options after the superblock are not exposed.

## 1. Shape

- **A superblock, the data, then the tables.** A 96-byte superblock, then data blocks and
  fragment blocks, then the inode, directory, fragment, id, export and xattr tables. The
  superblock says where each table starts and how many bytes the image uses.
- **Metadata blocks.** The inode table and the directory table are runs of blocks of a
  2-byte header, then up to 8 KiB, compressed or not. The fragment, id, export and xattr
  tables are each an array of 8-byte pointers to such blocks. An inode or a directory
  listing is addressed by the offset of its metadata block from the start of its table
  and an offset inside the decoded block.
- **File data in blocks of one size,** set when the image is written (128 KiB by
  default), each compressed alone or stored. A file's tail, or a whole small file, may go
  in a *fragment* block shared with other files' tails.
- **One compressor for the whole image:** gzip (zlib), LZMA (LZMA Alone), LZO, xz, LZ4 or
  Zstandard, named in the superblock.

## 2. The pipeline here

### 2.1 Identify

`hsqs` at offset 0 is exact magic (little-endian SquashFS 4). `sqsh` at 0 is claimed too,
so an older big-endian image is refused by name rather than with `FormatDetectionError`.
The extensions are `.squashfs`, `.sqfs` and `.snap`. Nothing here is a content probe.

### 2.2 Open and list

The reader reads the superblock, then walks the directory table from the root inode.
`ArchiveInfo.format_version` is `"4.0"`, `extra["squashfs.compressor"]` names the
compressor (`gzip`, `lzma`, `lzo`, `xz`, `lz4`, `zstd`) and `extra["squashfs.block_size"]`
the data block size.

Members are files, directories, symlinks, hard links (a second name for an inode is a
`HARDLINK` to the first), sparse files, and devices, FIFOs and sockets (`OTHER`, with
`extra["special_file_type"]`, as in every format). Owner ids come from the id table;
permissions and modification times from the inode.

A block stored with size 0 is a hole and reads as zeros. `is_sparse` is true for a file
whose block list holds one, read from the list at listing time: `mksquashfs` writes most
sparse files under a basic inode, which has no "bytes saved" field to go by.

Compressor options after the superblock are not read: the zlib, xz, LZMA Alone and
Zstandard streams carry their own parameters, and the LZ4 and LZO options only name a
level or variant the same decoder reads.

### 2.3 Member data

Every compressed block goes through `ReaderContext.decompress`, so archivey's decoder
limits apply, or, for LZ4, through `lz4.block` capped at the block's size. LZO blocks
are raw LZO1X (`CompressionAlgorithm.LZO`), decoded by the codec a `.lzo` file uses:
liblzo2 through `python-lzo` when it is installed, in a child process under
`NATIVE_DECODERS`, and otherwise archivey's port of the kernel's
`lzo1x_decompress_safe`. LZO1X stores no decoded length, so the block size is passed as
the most it may decode to (§6).

`FormatPolicy(exclude_libraries={OptionalLibrary.LZ4})` makes an LZ4 image read as if
`lz4` were missing. Under PyPy the reader does not use `lz4`, as the rest of archivey
does not.

### 2.4 Extract

Nothing here is format-specific. Members go through the same extraction rules as every
format's; `OTHER` members are not created.

### 2.5 Write

Not shipped.

## 3. In the wild

- **`mksquashfs`** (squashfs-tools) writes gzip by default; xz and Zstandard are common
  for distribution images.
- **Snap packages** are SquashFS images, xz by default, LZO when the publisher asks.
- **Live-system roots** (Ubuntu's `filesystem.squashfs`, many installers) are SquashFS,
  mostly xz or Zstandard.
- **Embedded firmware** often holds a SquashFS root, sometimes from vendor forks of
  squashfs-tools that change the magic or the compressor numbering; those are not read.
- **Corpus evidence.** The libarchive corpus has no SquashFS fixtures; on 2026-10-28 the
  reader matched PySquashfsImage on every image both read.

## 4. Threat surface

Names are archive-controlled bytes like any format's and go through the same extraction
rules ([`threat-model.md`](../threat-model.md)). The format-specific surface is sizes and
offsets the image declares:

- Every size is checked against what the format allows before it is used: a superblock
  that declares more bytes than the source holds, a metadata block longer than 8 KiB, a
  data block longer than the block size or shorter than the file needs, a fragment past
  the fragment table, and a symlink target longer than the kernel allows (65535 bytes)
  are `CorruptionError`. A cut image names the structure the cut falls in.
- A name with a `/`, and an entry whose inode has another type, are `CorruptionError`.
- The directory walk is a loop, not a recursion, and refuses a directory reached twice,
  so a directory listed inside itself does not walk forever.
- The block lists the listing scans for holes are bounded together: in a valid image
  each lies in its own bytes of the decoded inode table, at most 8 KiB per metadata
  block, so lists that add up to more are `CorruptionError`, before a list longer than
  the table is read. The table's size on disk is no bound: it is compressed, and a
  list of holes compresses to almost nothing.
- Every decoder is bounded by the block size, so a block cannot expand past it. The LZO
  decoder in Python refuses a stream that would read past its input, write past the
  block size, or copy from before the start of the output.
- Decoded blocks are kept in two bounded caches, 64 metadata blocks and four fragment
  blocks (about 4.5 MiB at the largest block size). They are caches, not limits: a block
  that is not kept is decoded again.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A pipe raises `StreamNotSeekableError`, also with `streaming=True` | **format** | The tables a listing needs come after the data (§1) |
| A SquashFS 3 image raises `UnsupportedFeatureError` | **archivey** | Only version 4 is read (§6) |
| An LZ4 image raises `PackageNotInstalledError` | **library** | Its blocks need `lz4` (`[recommended]`) |
| A firmware image does not open | **format** | Vendor forks change the magic or the compressors (§3) |
| A damaged block is found only when it does not decode | **format** | SquashFS stores no checksums |

## 6. Decisions

- **Built in, not a separate package.** The maintainer's call (2026-10-28), as for ar
  and CPIO. Unlike those two, the reader also imports archivey's internal lz4 handling
  (`deps`, `natives_for`, `as_reported`, `LZ4_REQUIREMENT`), so LZ4 blocks follow
  the PyPy rule, `exclude_libraries` and process isolation as every other lz4 use does.
  A test pins the internal names it imports.
- **SquashFS 4 only.** Big-endian images from SquashFS 3 and older have another layout;
  they are claimed by magic (`sqsh`) so the refusal names them, from a stream too.
- **LZO goes through archivey's LZO codec.** `python-lzo` is GPL, so it is never a
  dependency, and an LZO image opens without it. When it is installed it decodes in a
  child process under `NATIVE_DECODERS`, so `exclude_libraries` and process isolation
  reach it as they reach every native decoder. An earlier version of this reader kept
  its own Python-only decoder for that reason; the shared codec made it unnecessary.
  The tests read the LZO images with each decoder, and the `LZO against liblzo2` CI job
  and the session setup script install `python-lzo` so that both run.
- **Extended attributes are not read.** archivey's members have no field for them.
- **`is_sparse` comes from the block list.** Reading it costs a scan of each file's
  list during the listing; the list sits in the inode table next to the inode, which the
  listing decodes anyway. Rejected: leaving it false, which would make it mean
  something else for SquashFS than for TAR.

## 7. Open questions

None are open.

## 8. Verify

```bash
./scripts/test.sh tests/test_squashfs.py tests/test_lzo.py
```

The fixtures in `tests/fixtures/squashfs/` were written by `mksquashfs` 4.6.1, one per
compressor and a few layouts (no fragments, tail ends, uncompressed);
`tests/fixtures/squashfs/make-images.sh` writes them again. Damaged images are built in
the tests. The tests also pin the internal names the reader imports. The Atheris target `squashfs`
fuzzes the image walk and block reads.

## 9. References

- The SquashFS 4.0 layout: the Linux kernel's
  [`squashfs.rst`](https://docs.kernel.org/filesystems/squashfs.html) and `fs/squashfs/`,
  and squashfs-tools.
- The kernel's `lib/lzo/lzo1x_decompress_safe.c`, which archivey's LZO decoder follows.
- `openspec/changes/plugin-api/tasks.md` §3b, the reader's history as a plugin.
