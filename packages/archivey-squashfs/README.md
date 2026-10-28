# archivey-squashfs

Reads SquashFS 4.0 images (`.squashfs`, `.sqfs`, snap packages) with
[archivey](https://github.com/archivey-dev/archivey), as a format plugin. It is written
against `archivey.formats` only, as a check that a format can be added from outside
archivey. It is not published.

```python
import archivey
from archivey.formats import register_format
from archivey_squashfs import SquashfsHandler

register_format(SquashfsHandler)

with archivey.open_archive("rootfs.sqfs") as archive:
    archive.extract_all("rootfs/")
```

## What it reads

- Images compressed with gzip, xz, LZMA, Zstandard (through archivey's decoders) and
  LZ4 (with the `lz4` package), and LZO, decoded by the package's own LZO1X decoder in
  Python, or by liblzo2 when `python-lzo` is installed.
- Files, directories, symlinks, hard links (a second name for an inode is listed as a
  `HARDLINK` to the first), sparse files, and devices, FIFOs and sockets (listed as
  `OTHER`, with `extra["special_file_type"]`).
- Owner ids, permissions and modification times.

Extended attributes, the NFS export table and big-endian images (SquashFS 3 and older)
are not read.

## Safety

The reader does not trust the image. It checks every size against what the format
allows, walks the directory tree in a loop that refuses a directory reached twice, and
decodes every block with a cap on its output: archivey's decoders apply the caller's
decoder limits, and an LZ4 block is decoded to at most one block. SquashFS stores no
checksums, so a damaged block is found only when it does not decode to its length.

## Tests

`tests/data/` holds images written by `mksquashfs` 4.6.1; `tests/data/make-images.sh`
writes them again. Run the tests with archivey's development environment:

```bash
uv run --with-editable packages/archivey-squashfs pytest packages/archivey-squashfs/tests
```
