# Archives stored as a program resource

## Why

`pe-aware-sfx-location` taught the readers where a signed installer's certificate table
starts, so the table is no longer reported as data after the archive. One installer
family still warns: Squirrel, the Windows installer Electron apps use. Its `Setup.exe`
keeps the app's ZIP as a resource in the program's `.rsrc` section, not in the overlay.
In GitHub Desktop's installer the ZIP fills one resource exactly (169 888 to
269 198 388); about 135 KB of other resources, then `.reloc`, then the certificate
follow. Those bytes are the program's, and archivey reports them as
`ARCHIVE_TRAILING_DATA`, which `DiagnosticPolicy.STRICT` refuses.

## What Changes

- New internal `archivey.internal.pe_resources.ProgramResources`: the file extents of a
  PE program's resources, read from its headers and from the start of its resource
  directory (at most 64 KiB), once and only when first asked.
- `open_archive` builds one for every backend with `SFX_MAGIC` on a seekable source of
  known size, detected or forced alike, and passes it as a new internal
  `ReadBackend.open_read(program_resources=…)` argument. Backends without `SFX_MAGIC`
  reject it, as they reject `end_offset`.
- The ZIP, 7z and RAR (lone archive) trailing-data checks: when the archive ends inside
  one resource's data and the first non-zero byte after it lies at or past that
  resource's end, nothing is reported.
- `sfx.pe_headers` / `PeHeaders` / `PeSection` factor the header parse out of
  `pe_layout`, which now uses them; behaviour unchanged.
- RAR's `RarArchive.trailing_data_volumes` values become `TrailingData(archive_end,
  offset)`, so the reader knows where the archive ended.

## Not changed

- What an archive lists. The resources only decide whether bytes after the archive are
  reported.
- LHA. Its reader is written against the plugin API, whose `ReaderContext` would need a
  new public member to carry this. No LHA installer stores its archive as a resource.
- An archive in the overlay. It is in no resource, so bytes after it are reported as
  before.
- Detection. It already finds Squirrel's ZIP with the SFX scan.

## Impact

- `src/archivey/internal/pe_resources.py` (new), `sfx.py`, `core.py`,
  `base_reader.py`, every `open_read`, `zip_reader.py`, `sevenzip_reader.py`,
  `rar_reader.py`, `rar_parser.py`.
- Spec: `archive-reading` gains one requirement.
- Cost: none for a file with no trailing bytes. Otherwise, on a seekable source with an
  SFX backend, two reads (4 KiB of headers, up to 64 KiB of resource tables), and none
  when the file is not a PE with a resource directory past its headers.
