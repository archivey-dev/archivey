# SquashFS

Current maintainer truth for SquashFS 4.0 images: snap packages, live-system roots, and
what `mksquashfs` writes. A SquashFS image is a compressed read-only filesystem with its
index after the data, so archivey reads it from a source that can seek. The reader is
written against `archivey.formats`, the API a format added from outside uses, and is
registered as a built-in the way ISO, CPIO and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/squashfs_reader.py`, a `SquashfsHandler` (`IndexedFormatHandler`) and a `SquashfsReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the directory and inode tables come after the data |
| Listing cost | From the index (the inode and directory tables) |
| Access cost | `DIRECT`. Small files share a fragment block, which is decoded once and kept (four at a time) |
| Core dependencies | None for gzip, xz, LZMA and LZO images. Zstandard images need what a `.zst` file needs; LZ4 images need `lz4` (`[recommended]`). LZO is decoded as a `.lzo` file is: liblzo2 through `python-lzo` in a child process when it is installed, otherwise Python |
| Encryption | None |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Checksums | None of its own. A damaged block is found when it does not decode to its length, when its codec's own check fails (zlib's Adler-32, the xz CRC), or when its stored size stops before its stream ends |
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

**Member order.** Members come in listing order: the directory walk's, depth first,
each directory's entries as stored, which every writer sorts by name. The one exception
is fragments. A file's tail is read from its fragment block, which is decoded whole, and
the reader keeps four. When reading the files in listing order would decode a fragment
block a second time, the files with a tail come sorted by where their block starts and
by offset, so each block decodes once. The check replays the four-block cache over the
blocks' starts and stored sizes (from the fragment table), with nothing decoded. Then the order is:
directories, files with no tail and other members, in listing order (so a directory
still comes before its contents); the files with a tail; the hard links, in listing
order (each after the member it names). mksquashfs and gensquashfs fill one fragment at
a time in name order, and mksquashfs `-tailends` two (small files and tail ends), so
their images keep listing order. sqfstar and tar2sqfs fill fragments in the tar's order:
the same when the tar is in name order, and when it is not they can need more and are
sorted, as is a crafted image, which in listing order would cost a whole block decode
per small file (§4). An image that lists one name twice in a directory keeps listing
order whatever its fragments, since that order says which entry is current.

The listing makes two passes and parses each inode once. The first walks the
directories, keeping each entry's name, parent and inode reference, then reads every
other inode once, in its order in the inode table, and with it the file's block list
for `is_sparse`. Of each inode it keeps a fixed-size record of 58 bytes (a 96-byte
object in CPython): its type, mode, owner, time, whether the file has holes, and a
regular file's location (size, first block, block count, where its block list is, and
its fragment and offset). A symlink's target is kept beside the record, since its
member holds the target anyway. Of an inode that did not read, or a block list that
did not scan, only the reference is kept. An error holds its traceback, which no limit
charges: keeping one for each took a 2.6 MB image of 260 000 entries that name bad
inodes to a peak RSS of 505 MiB, against 115 MiB for the references. That member reads
the inode and its list again and raises, which ends the listing, so this costs one
more read a listing. The second pass makes each member from its record, in the order
the first chose, and drops the record and the entry's name as it goes; a directory's
entry stays, for the path in a later member's message. A hard
link takes what it needs from the member it names, which keeps its type, mode, owner
and time next to its name. On a 120 000-file mksquashfs image this lists in the time
of a walk that reads each inode as it goes (2.06 s, against 2.77 s for reading the
inodes again in the second pass), with a peak RSS of 168 MiB against 170 and 194 MiB.

What the first pass holds before the members are made is charged to
`max_metadata_bytes` as it is held: each entry's path when the walk finds it (twice its
length, for the raw name and the name), and each symlink's target when the first pass
keeps it (its length). For names that are valid UTF-8 or decoded with a one-byte
`encoding=`, the charge is at most what those members weigh when they are made, so it
refuses only a listing that would cross the limit anyway, before making any member
(§4). A multibyte `encoding=` that decodes to fewer characters than the stored bytes
(UTF-16) weighs the names at less, so the charge can refuse such a listing up to about
twice early. The charge covers the paths' and targets' bytes only: what each entry
costs beyond them (about 170 bytes in the walk, and the 96-byte record until its
member is made) is bounded by `max_members` alone, as every member's fixed cost is.

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
`lzo1x_decompress_safe`. The port takes the end marker as liblzo2 does, whatever its
length field, so the two decoders agree (the kernel refuses a length other than 3). LZO1X
stores no decoded length, so the block size is passed as the most it may decode to (§6).

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
  the fragment table, a symlink target longer than the kernel allows (65535 bytes), and
  an entry name longer than the kernel and unsquashfs allow (256 bytes) are
  `CorruptionError`. A compressed block is decoded to its stream's end, so a stored size
  that cuts the stream, even only its check value, is `CorruptionError`: the image holds
  the whole stored block, so the image is not cut. A cut image names the structure the cut falls in.
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
  that is not kept is decoded again. A crafted layout cannot make that happen once per
  member for fragments or file inodes: files with a tail come in fragment order when
  listing order would thrash the fragment cache (§2.2), which took a 229 KB xz image of
  50 000 one-byte files cycling five 1 MiB fragments from 62 s to 4 s (4.1 s for the
  same files in one fragment). Inodes other than directories' are read once, in table
  order, and the members are made from the records that read keeps (§2.2), so the
  member order does not reach the metadata cache. In an image whose inodes do not
  overlap, each inode-table block then decodes about once in the listing: 20 480 empty
  files whose inodes cycle over 80 gzip inode blocks list in 0.31 s with 147 metadata
  decodes (1.9 s and 20 547 decodes if each inode were read in member order), and 300
  files each in its own block, stored in reverse, decode 303 metadata blocks in all. A
  hard link does not read its inode again, so the entries that name one inode cost one
  read of it, not one per entry: 100 entries naming a symlink whose 65 535-byte target
  is stored in 1-byte metadata blocks list in 0.2 s (19 s with a read per entry).
- Residual, as on main: one inode's read can run through up to 65 535 metadata blocks
  (a symlink target in 1-byte blocks), and distinct inodes can overlap, so entries
  whose inodes overlap each pay that read: 20 such entries decode 1.3 M blocks in
  4.0 s, the same as main. The listing reads each inode once, so nothing doubles that
  cost.
- The name and target bytes the listing holds before it makes the members are bounded
  by `max_metadata_bytes`, not by the image's size, which can be far smaller: several
  directory inodes may point at one listing, and overlapping symlink inodes may each
  name a 65 535-byte target made of the inodes after it. The walk charges each path,
  and the first pass each symlink target it keeps, as it holds them (§2.2), whether
  `max_members` is set or not. Within the encoding limits of §2.2 it refuses only a
  listing whose members would cross the limit. Measured peak RSS, refused with
  `ResourceLimitError` at the default limits (`max_members=None` for the shared
  listing): 60 000 overlapping symlink inodes (1.69 MB image) 3 841 MiB in 23 s before
  the charge, 109 MiB in 0.5 s after; 20 000 listed in an order that strides the table
  (668 KB) 1 313 MiB before, 102 MiB in 0.1 s after; 3 000 directories sharing a
  listing of 2 000 250-byte names (140 KB) 3 597 MiB in 46 s before, 87 MiB in 0.6 s
  after. A 120 000-file image lists in 2.06 s at 168 MiB, its charge 240 bytes under
  its members' weight.
  What each entry costs beyond its bytes is not charged, so short names in a shared
  listing reach the per-member residual of the threat model (§Listing limits) from a
  small image: with `max_members=None`, a 9 KB image of 250 directories sharing a
  listing of 7 000 one-byte names lists 1.75 M members at 1 588 MiB in 93 s under the
  default `max_metadata_bytes`, and holds 338 MiB when refused at 12 MB. `max_members`
  bounds it, as for 7z.
- Directory inodes and listings are still read as the walk reaches them, since each is
  needed to find the next. Directories whose inodes or listings stride across more than
  64 metadata blocks decode an 8 KiB block for each: 20 480 empty directories strided
  across 80 inode-table blocks list in 1.9 s, against 0.3 s in order. That is a bounded
  cost per member (about one metadata block per directory, for an inode and a few
  entries of the image), not the 1 MiB per member the fragment layout cost.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| A pipe raises `StreamNotSeekableError`, also with `streaming=True` | **format** | The tables a listing needs come after the data (§1) |
| A SquashFS 3 image raises `UnsupportedFeatureError` | **archivey** | Only version 4 is read (§6) |
| An LZ4 image raises `PackageNotInstalledError` | **library** | Its blocks need `lz4` (`[recommended]`) |
| A firmware image does not open | **format** | Vendor forks change the magic or the compressors (§3) |
| A damaged block is found only when it does not decode | **format** | SquashFS stores no checksums |
| Two fragment entries at one start read its bytes differently (one stored, one compressed), each file reading its own entry's | **format** | Nothing is cached by offset alone: the fragment cache and the order planner key a block by start and stored size (§6) |

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
  The tests read the LZO images with each decoder, and the CI benchmark job (its
  `LZO against liblzo2` step) and the session setup script install `python-lzo` so
  that both run.
- **Extended attributes are not read.** archivey's members have no field for them.
- **`is_sparse` comes from the block list.** Reading it costs a scan of each file's
  list during the listing; the list sits in the inode table next to the inode, which the
  listing decodes anyway. Rejected: leaving it false, which would make it mean
  something else for SquashFS than for TAR.

- **Fragment order over listing order, only when listing order would thrash.** The
  maintainer's call (2026-11-03), for a crafted layout that decoded a fragment block per
  small file. Listing order is kept whenever the four-block cache covers it, which is
  every image mksquashfs or gensquashfs writes from a directory; files with a
  tail are sorted only when the replayed cache would decode a block twice. The replay
  and the sort key a block by its start and stored size, as the cache does, not by the
  fragment-table entry, since two entries can name one block. The stored size is in the
  key because it carries the compressed bit: two entries can name one start and read
  its bytes differently (pre-0.3.0 sweep, 2026-11-04). Rejected: charging decoded block bytes to a per-reader budget
  (refuses an image instead of reading it), a larger cache (a crafted image cycles
  through one more block), and only recording the case in the threat model. File inodes
  are read once, in table order, for the same reason (next decision); the order of
  reads is internal.

- **Two passes, one parse per inode, a compact record between them.** The
  maintainer's call (2026-11-03), replacing an earlier one that kept only what the
  order needs and read each inode again in the second pass (2.77 s and 194 MiB on a
  120 000-file image, against 2.06 s and 170 MiB for a walk that reads each inode as it
  goes). The first pass keeps a fixed-size packed record per inode (§2.2), and a
  symlink's target beside it, charged; the second makes the members from the records
  and parses nothing: 2.06 s and 168 MiB on that image, with half the inode parses
  and two thirds of the metadata decodes. Since no inode is read in member order, the
  replay of the metadata cache over the member order, and the table read that kept
  every inode when it said the order would thrash, are gone. Rejected: holding every
  inode as parsed (about 450 bytes a file against 96), and reading again in any order
  (an inode table that strides against the member order decodes an 8 KiB block per
  member: 1.9 s against 0.31 s for 20 480 files over 80 blocks).

## 7. Open questions

None are open.

## 8. Verify

```bash
./scripts/test.sh tests/test_squashfs.py tests/test_lzo.py
```

The fixtures in `tests/fixtures/squashfs/` were written by `mksquashfs` 4.6.1, one per
compressor and a few layouts (no fragments, tail ends, uncompressed), plus
`tar-order.sqfs` from `sqfstar` (fragments filled in tar order, which the listing
sorts) and `tail-ends-two-streams.sqfs` (two fragments in progress, which it does not);
`tests/fixtures/squashfs/make-images.sh` writes them again. Damaged images are built in
the tests. The tests also pin the internal names the reader imports. The Atheris target `squashfs`
fuzzes the image walk and block reads.

## 9. References

- The SquashFS 4.0 layout: the Linux kernel's
  [`squashfs.rst`](https://docs.kernel.org/filesystems/squashfs.html) and `fs/squashfs/`,
  and squashfs-tools.
- The kernel's `lib/lzo/lzo1x_decompress_safe.c`, which archivey's LZO decoder follows,
  and liblzo2 2.10's `lzo1x_decompress_safe`, whose end-marker rule it takes.
- `openspec/changes/plugin-api/tasks.md` §3b, the reader's history as a plugin.
