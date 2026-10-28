# archivey-ar

Reads Unix ar archives (`.a` static libraries, `.lib`, and the outer layer of `.deb`
packages) with [archivey](https://github.com/archivey-dev/archivey), as a format plugin
read in one forward pass, so from a pipe too. It is written against `archivey.plugins`
only, as a second check (after archivey-cpio) that such a format can be added from
outside archivey. It is not published.

```python
import sys

import archivey
from archivey.plugins import register_format
from archivey_ar import ArPlugin

register_format(ArPlugin)

with archivey.open_archive("libfoo.a") as archive:
    for member in archive.members():
        print(member.name, member.size)

# From a pipe: one forward pass.
with archivey.open_archive(sys.stdin.buffer, streaming=True) as archive:
    for member, stream in archive.stream_members():
        ...
```

## What it reads

- Both dialects. **GNU** (System V, also Windows `.lib`): long names in a `//` table
  member. **BSD** (and macOS): a long name at the start of the member's data area
  (`#1/N`).
- Every member is a file, with its owner ids, permissions and modification time. A
  blank header field is `None`.
- The symbol table (`/`, `/SYM64/`, `__.SYMDEF`) is the linker's index, not a file: it
  is not listed, and `archive.info.extra["ar.symbol_table"]` says whether there was
  one.

macOS ar pads each member with newlines so the next header starts on 8 bytes, and
counts the padding in the member's size. The padding is then part of the member, as
llvm-ar and bsdtar extract it too.

`archive.info.format_version` names the dialect, `gnu` or `bsd`, from the first name
or symbol table spelled in a dialect's own way. It is `None` for an archive with no
members.

A thin archive (`!<thin>`), which only names files kept outside it, raises
`UnsupportedFeatureError`.

## Safety

The reader does not trust the archive. It refuses a header without its `` `\n `` end
or with a field that is not a number (spaces on either side are padding, as GNU ar
reads them; a sign is refused), a long-name reference before the table or past its
end, a second table, and a BSD name over 64 KiB or longer than its member. A long-name
table larger than `ListingLimits.max_metadata_bytes` raises `ResourceLimitError`. An
archive that ends inside a header or a member's data raises `TruncatedError`. archivey
reads and skips member data itself, and checks each file's length.

## Tests

`tests/data/` holds archives written by GNU ar 2.42, bsdtar 3.7.2 and llvm-ar 18;
`tests/data/make-archives.sh` writes them again. Run the tests with archivey's
development environment:

```bash
uv run --with-editable packages/archivey-ar pytest packages/archivey-ar/tests
```
