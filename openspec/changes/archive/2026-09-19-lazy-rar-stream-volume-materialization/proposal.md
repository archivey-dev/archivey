# Stream volumes are copied on first read, not at open

## Why

`RarReader.__init__` copied every volume of an ordered stream-volume set to a temp
directory before it had parsed a single header. `_open_shared_source` called
`_materialize_stream_volumes()` inline, and `_parse_archive` then read the *copies*
rather than the originals.

That copy exists for one reason: RARLAB `unrar` takes a filesystem path and resolves
sibling volumes by name, so member data cannot be served from Python objects. Listing
needs none of it — archivey's own header walk reads the bytes it is given.

Measured on `ad3c1b9`, two `BytesIO` volumes of the `tinyvol` fixture, listing only and
never calling `read()`:

```
members: ['payload.bin']
temp dirs after LIST ONLY: {'/tmp/archivey-rar-vol-iec1cn2t'}
    archive.part1.rar 917
    archive.part2.rar 840
   total bytes written: 1757
```

1757 of 1757 bytes, 100% of both volumes, written for a caller that read nothing. A
single stream source has never behaved this way: its copy waits for the first member
`unrar` has to serve (`_ensure_archive_path`). The two stream shapes reported their
disk cost at different times for no reason other than where the call sat.

Recorded as `dev-docs/formats/rar.md` §10 #21 when [#314](https://github.com/archivey-dev/archivey/pull/314)
was reviewed.

## What Changes

- An ordered stream-volume set is **not** copied at open. `_materialize_stream_volumes`
  moves onto `_ensure_archive_path`, the same lazy trigger the single-stream copy
  already uses, so a caller that only lists writes nothing.
- The header walk reads the originals. `parse_rar_volumes` needs each volume as its own
  stream positioned at its start, which the concatenation cannot be, so the reader mints
  one bounded `SharedSource` view per volume from `ConcatenatedFile.volume_ranges`.
  Views are non-owning and take the shared lock, so nothing here touches the caller's
  stream positions.
- The `cost.notes` caveat for stream volumes becomes predictive, matching the single
  stream: "Reading a compressed member will copy every volume to a temp directory so
  RARLAB unrar or rar can read them." It stays a static open-time note.
- When the copy does happen it still writes the **whole set**, because `unrar` resolves
  siblings by name. Only its timing changes, never its size.

Nothing changes for path sources, for path volumes, or for a single stream source.

## Impact

- `ConcatenatedFile` gains a `volume_ranges` property. Internal; no public name moves.
- A caller reading `ar.cost.notes` for the stream-volume wording sees new text. The note
  was never a documented string, and the requirement below is what pinned its tense.
- `bounded-source-spooling` task 3.2 routes this same copy through a spool limit. Lazy
  materialization is what makes that limit apply to callers who read, rather than to
  every caller who opens.
