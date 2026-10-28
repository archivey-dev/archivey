# archivey-cpio

Reads CPIO archives (`.cpio`) with [archivey](https://github.com/archivey-dev/archivey),
as a format plugin read in one forward pass, so from a pipe too. It is written against
`archivey.formats` only, as a check that such a format can be added from outside
archivey. It is not published.

```python
import sys

import archivey
from archivey.formats import register_format
from archivey_cpio import CpioHandler

register_format(CpioHandler)

with archivey.open_archive("initramfs.cpio") as archive:
    archive.extract_all("initramfs/")

# From a pipe: one forward pass.
with archivey.open_archive(sys.stdin.buffer, streaming=True) as archive:
    for member, stream in archive.stream_members():
        ...
```

## What it reads

- All four header variants: binary (either byte order), odc, newc and crc. In crc the
  header's checksum of each file's data is checked as the data is read (not a symlink's,
  whose target is read while listing).
- afio's large header (`070727`), which afio writes in an odc archive, as afio(1)
  says, for a file over 2 GB, a uid or gid over 65535, or an archive of more than 64K
  hard-linked files. The archive is still `odc`.
- Files, directories, symlinks (a symlink's target is its data), hard links, and
  devices, FIFOs and sockets (listed as `OTHER`, with `extra["special_file_type"]`).
- Owner ids, permissions and modification times.

`archive.info.format_version` names the variant as GNU cpio's `-H` option does (`bin`,
`odc`, `newc`, `crc`), with `bin-be` for a binary archive in the other byte order, which
`-H` has no name for.

## Hard links

A file with several names shares a device and inode number across headers. The first
name archivey lists is a `FILE`, and the others are `HARDLINK` members to it. binary and
odc store the data with every name, and the later copies are skipped. newc and crc store
it with the **last** name only, the earlier names empty. archivey's hard links may name
only an earlier member, so the reader holds the empty names back until the name with the
data arrives, and lists them right after it: the member order is then not quite the
archive's. A file whose names are all empty is listed at the trailer.

A newc archive with more names waiting for their data than `ListingLimits.max_members`
raises `ResourceLimitError`.

## Safety

The reader does not trust the archive. It refuses a header whose fields are not
numbers, a name over 64 KiB or without its NUL, a variant that changes mid-archive, and
an archive that ends before its `TRAILER!!!` member; and, as unsupported
(`UnsupportedFeatureError`) rather than damage, an afio large header that declares
extra bytes, since nothing says where they go. Bytes other than zeros within
1 MiB after the trailer are reported as `ARCHIVE_TRAILING_DATA`. A second archive
concatenated after the first is such data: archivey lists the first archive's members
and not the second's, as its TAR reader stops at the first trailer. archivey reads and
skips member data itself, and checks each file's length and, in crc, its checksum.

## Tests

`tests/data/` holds archives written by GNU cpio 2.15 and bsdcpio 3.7.2;
`tests/data/make-archives.sh` writes them again (as root: the tree has device nodes).
Run the tests with archivey's development environment:

```bash
uv run --with-editable packages/archivey-cpio pytest packages/archivey-cpio/tests
```
