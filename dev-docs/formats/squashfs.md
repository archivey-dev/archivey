# SquashFS

Current maintainer truth for SquashFS 4.0 images: snap packages, live-system roots, and
what `mksquashfs` writes. A SquashFS image is a compressed read-only filesystem with its
index after the data, so archivey reads it from a source that can seek. The reader is
written against `archivey.formats`, the API a format added from outside uses, and is
registered as a built-in the way ISO, CPIO and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/squashfs_reader.py`, a `SquashfsHandler` (`FormatHandler`) and a `SquashfsReader` (`IndexedReader`), registered with `register_builtin_format`; the LZO decoder is `internal/backends/squashfs_lzo.py` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the directory and inode tables come after the data |
| Listing cost | From the index (the inode and directory tables) |
| Access cost | `DIRECT`. Small files share a fragment block, which is decoded once and kept (four at a time) |
| Core dependencies | None for gzip, xz, LZMA and LZO images. Zstandard images need what a `.zst` file needs; LZ4 images need `lz4` (`[recommended]`). `python-lzo` is used when installed (GPL, never a dependency) |
| Encryption | None |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Checksums | None. A damaged block is found only when it does not decode to its length |
| Refuses | Big-endian images (SquashFS 3 and older, magic `sqsh`), with `UnsupportedFeatureError` |
| Spec | `openspec/specs/format-squashfs/spec.md` |

## 1. Layout

A 96-byte superblock, then data blocks and fragment blocks, then the tables. The inode
table and the directory table are runs of *metadata blocks* (a 2-byte header, then up to
8 KiB, compressed or not). The fragment, id, export and xattr tables are each an array of
8-byte pointers to such blocks. An inode or a directory listing is addressed by the offset
of its metadata block from the start of its table and an offset inside the decoded block.

`ArchiveInfo.format_version` is `"4.0"`. `ArchiveInfo.extra["squashfs.compressor"]` names
the compressor (`gzip`, `lzma`, `lzo`, `xz`, `lz4`, `zstd`) and
`extra["squashfs.block_size"]` the data block size. Compressor options after the superblock
are not read: the zlib, xz, LZMA Alone and Zstandard streams carry their own parameters,
and the LZ4 and LZO options only name a level or variant the same decoder reads.

## 2. Members

Files, directories, symlinks, hard links (a second name for an inode is a `HARDLINK` to
the first), sparse files (a block stored with size 0 reads as zeros), and devices, FIFOs
and sockets (`OTHER`, with `extra["special_file_type"]`). Owner ids come from the id table;
permissions and modification times from the inode. Extended attributes and the NFS export
table are not read.

## 3. Decoding and limits

Every compressed block goes through `ReaderContext.decompress`, so archivey's decoder
limits apply, or through a decoder capped at the block's size: `lz4.block` for LZ4, and
`squashfs_lzo` for LZO. `squashfs_lzo` follows the Linux kernel's
`lzo1x_decompress_safe`, without LZO-RLE, which SquashFS does not write; `python-lzo` is
used instead when it is installed. Both refuse a stream that would read past its input,
write past the block size, or copy from before the start of the output.

`FormatPolicy(exclude_libraries={OptionalLibrary.LZ4})` makes an LZ4 image read as if
`lz4` were missing. The reader keeps its own copy of the "turned off" reason, because it
imports only public names; `tests/test_squashfs.py` compares the two. Under PyPy the
reader does not use `lz4`, as the rest of archivey does not.

## 4. Damage

The reader checks every size against what the format allows: a superblock that declares
more bytes than the source holds, a metadata block longer than 8 KiB, a data block longer
than the block size or shorter than the file needs, a fragment past the fragment table, a
name with a `/`, an entry whose inode has another type, and a symlink target longer than
the kernel allows (65535 bytes). The directory walk is a loop that refuses a directory
reached twice. A cut image names the structure the cut falls in.

## 5. Tests and fixtures

`tests/test_squashfs.py` and `tests/test_squashfs_lzo.py`, against `tests/fixtures/squashfs/`:
images written by `mksquashfs` 4.6.1, one per compressor and a few layouts (no fragments,
tail ends, uncompressed). `tests/fixtures/squashfs/make-images.sh` writes them again. The
same test checks that the reader imports only archivey's public names, apart from
`register_builtin_format` and its own LZO module. The Atheris target `squashfs` fuzzes the
image walk and block reads. The libarchive corpus has no SquashFS fixtures; on 2026-10-28
the reader matched PySquashfsImage on every image both read.
