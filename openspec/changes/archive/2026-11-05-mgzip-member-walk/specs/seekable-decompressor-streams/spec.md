# seekable-decompressor-streams — mgzip member walk delta

## ADDED Requirements

### Requirement: mgzip members are walked without decoding

When a gzip file's first member carries an `MZ` extra subfield with a 4-byte body (the
`mgzip` writer's), the walk that §"BGZF members are walked without decoding" describes
SHALL walk mgzip members instead, inflating nothing: each member's size SHALL be its
header parsed to its end (`FNAME`, `FCOMMENT`, `FHCRC`), the `MZ` value (the member's
DEFLATE data size) and the 8-byte trailer, and its ISIZE its output. The walk SHALL jump
from header to header, since mgzip members are large. It SHALL stop quietly at the first
member without an `MZ` subfield, keeping the points before it, and the size SHALL be known
only when it reaches the end of the file. The sizes are trusted like the BGZF ones until a
decode contradicts them. A walk over the seek-table cap SHALL report scan `mgzip_blocks`.

#### Scenario: mgzip walk matrix

| Case | Expected |
| --- | --- |
| `seek(0, SEEK_END)` on an mgzip file, with or without `FNAME` | Total from the walk; fewer bytes read than the file; nothing inflated |
| Seek into member N | Decoding resumes at member N's start |
| mgzip members, then a plain member | Points for the mgzip members; no size from the walk |
| The last member cut | Points for the whole members; no size |
| A header whose `FNAME` runs past 64 KiB | No points |
| Walk over the seek-table cap | `SEEK_INDEX_DEGRADED` (scan `mgzip_blocks`, `SeekTableThinned`) |
| A member's ISIZE claims one byte more; walk, then a read from the start | The read raises `CorruptionError` at that member's trailer |
