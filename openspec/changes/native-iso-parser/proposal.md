## Why

The ISO backend reads ISO 9660, Joliet and Rock Ridge through `pycdlib`, a library
built for writing images. Reading damaged or unusual images safely took about 1,500
lines around it: import-time hooks on six pycdlib methods (a System Use filter, record
and path-table counters, a UDF skip, a copied directory walk for padding tolerance), a
second parse of directories to recover what pycdlib changed in memory (multi-extent
flags, clamped lengths, record order), a probe for its swapped `TF` bit order, and a
broad exception net for the `struct.error`s it raises on bad bytes. UDF already has its
own parser (`udf.py`).

A native parser makes ISO part of the zero-dependency core, parses each tree once under
`ListingLimits` from the start, keeps what the disc says (on-disc order, declared
lengths, record offsets), and gives the later salvage work (other trees, older
sessions, dedupe by data location) one model to build on.

## What Changes

- New `internal/backends/iso9660.py`: volume descriptors, directory records, SUSP and
  Rock Ridge (`PX`, `NM`, `SL`, `TF`, `CE`, `CL`/`PL`/`RE`, `ZF`), multi-extent files
  joined from the records as written, cut-image detection, padding tolerance and the
  listing budget built in. Differential tests require the same trees pycdlib parses.
- `IsoReader` reads through it; the pycdlib hooks, the raw re-parse and the
  `PyCdlibIO`-era handle lock go.
- `pycdlib` leaves the `[recommended]` and `[free-threaded]` extras and stays in the dev
  group as the test-side image writer and differential oracle. ISO becomes a built-in
  format with no optional dependency.
- Behaviour on intact images is unchanged. Images pycdlib refused for reasons that are
  not damage to anything archivey reads now open, as Linux's isofs and 7-Zip open them:
  two directories (or a file then a directory) with one identifier, a path table that
  is damaged or lies past the image (path tables are not read to list), more than one
  primary or Joliet descriptor, and a System Use entry pycdlib cannot parse (now
  contained to its record, like the malformed headers already were). A Rock Ridge
  continuation area that runs past its block is dropped for that record instead of
  refusing the image.

## Impact

- Public API: none. `OptionalLibrary.PYCDLIB` stays a known name, no longer needed by a
  built-in format.
- Packaging: one fewer runtime dependency in `[recommended]` and `[free-threaded]`.
- Specs: `format-iso` (this change), and the `packaging-and-extras`,
  `backend-registry`, `error-handling` and `access-mode-and-cost` rows that use "ISO
  without pycdlib" as their example of a missing optional package.
