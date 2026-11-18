## Why

A macOS `.pkg` is a XAR whose files sit in a compressed CPIO, `Payload`; a `.xip` holds
one in `Content`. archivey listed those as single files, so a caller saw no installed
file. The maintainer asked (2026-11-18) to list them as their files, as a `.deb`'s tars
are, and chose a new format so that `format=XAR` keeps the raw view.

## What Changes

- New container `ContainerFormat.PKG` and `ArchiveFormat.PKG` (`.pkg`, `.mpkg`, `.xip`):
  `Payload`, `Scripts` and `Content` listed as their CPIO's files, under a folder of
  their name. `ArchiveFormat.XAR` now claims only `.xar` by name.
- New stream format `StreamFormat.PBZX` and `ArchiveFormat.PBZX`: Apple's chunked xz.
- `ReaderContext.open_nested` works from `IndexedReader.iter_members` and
  `open_member`, so an indexed format can read an archive inside it.
- Detection can name a narrower format behind another's magic
  (`ReadBackend.MAGIC_REFINEMENTS`).

## Impact

Public API: the enum members above, and `open_nested` from an indexed reader. A `.pkg`
opened without `format=` now lists its payloads' files.
