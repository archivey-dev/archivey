# archive-reading — salvage stream segments delta

## ADDED Requirements

### Requirement: Container walks cross stream segments and search at a proven phase only

With `salvage=True`, a container reader that walks a decoded stream (TAR, CPIO, ar, and
the readers nested in them) SHALL, where a segment ends on codec damage, go on with the
next segment (`compressed-streams`):

- when the segment's offset is known and the next expected header lies at or after the
  segment's start, the walk SHALL go on there as the normal walk;
- otherwise it SHALL search from the segment's first byte.

The **phase** (the container's header step from the archive's start: TAR 512, CPIO
`newc`/`crc` 4, ar 2, CPIO `odc` 1) SHALL count as proven on the file layer, and in a
decoded layer only when its codec fixes each unit's byte count before or when the
bytes are handed out (bzip2, xz) and either the segment's offset is known or a header
found earlier in the same segment passed. A search at a proven phase SHALL step at the
container's step. Any other search SHALL test every byte offset for headers that carry
magic, and the walk SHALL go on from the first header that passes at the container's
step. The step of a search SHALL be fixed before it starts, so no range is searched
twice. A member found in a later segment SHALL be read from that segment; a member
whose data spans a gap SHALL read to the hole and raise.

#### Scenario: walks over segments

| Case | Expected |
| --- | --- |
| `.tar.xz`, index intact, one block damaged in the middle of a member's data | The next header after the gap read by the normal walk; that member's read raises at the hole |
| `.tar.bz2`, one block damaged | Unaligned search in segment 2; aligned from the first header found |
| `.cpio.gz` (concatenated members), one member damaged | CPIO magic searched at every byte in segment 2 |
