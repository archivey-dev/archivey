# format-tar — salvage stream segments delta

## MODIFIED Requirements

### Requirement: Salvage mode searches past damage for the next TAR header

With `salvage=True`, where the default walk ends on damage (a header that fails its
checksum and is not followed, a block that is not a header, a chain that does not
confirm), the walk SHALL search forward from the damaged block, one 512-byte block at a
time relative to the start of the archive, for a block whose checksum passes and whose
magic is `ustar\0` or `ustar  \0`. A block without magic (v7) SHALL pass only when every
header listed before the damage was v7. A clean end (the end marker, then zeros or the
end of the source) SHALL NOT start a search.

A found header SHALL be parsed and walked as any header, extended headers and their
chain included, and its member listed with `MEMBER_FOUND_BY_SCAN`. It is **confirmed**
when the block after its data is a header that passes checksum and magic, or the clean
end; a confirmed member's walk SHALL go on as the normal walk, and later damage SHALL
start a new search. An unconfirmed member SHALL be listed with `confirmed=False`, and
the search SHALL go on at the block after its header. A found header with a full name
field and no long-name record before it SHALL list `"name"` in `unchecked`. Each range
with no passing header SHALL be one `ARCHIVE_REGION_SKIPPED`. The pass SHALL end in the
default's error.

On a compressed TAR the search SHALL run on the decoded stream, at the step that
"Salvage searches a decoded TAR layer by magic where its phase is not proven" gives, and
damage in the codec SHALL move the walk to the next stream segment (`archive-reading`,
`compressed-streams`).

#### Scenario: TAR header search

| Case | Expected |
| --- | --- |
| 4 KiB zeroed inside the header region | Every member after the zeroed region, flagged and confirmed; one `ARCHIVE_REGION_SKIPPED`; `CorruptionError` at the end |
| 64 KiB deleted from the middle | Every member whose header follows the gap, flagged; GNU tar's member set |
| Damaged size field, `salvage=False` | As today |
| Outer `.tar` member holding an inner `.tar`, outer header damaged and not followed | The inner members listed, flagged (Q12); the outer member after them listed |
| Intact archive with data after the end marker | Nothing added in this step |

## ADDED Requirements

### Requirement: Salvage searches a decoded TAR layer by magic where its phase is not proven

In a decoded layer whose phase is not proven (`archive-reading`: a segment with an
unknown offset before its first found header, or any position in a DEFLATE, LZMA1, zstd
or LZ4 layer), the TAR search SHALL test every byte offset for a block whose `ustar`
magic is at offset 257 and whose checksum passes, and SHALL NOT accept a v7 header. The
walk SHALL go on from the first header that passes, in 512-byte steps from it. This
SHALL hold at any damage the walk meets in such a layer, whether or not the codec has
reported a gap. A member found this way SHALL carry `MEMBER_FOUND_BY_SCAN` with
`method="header_search"`, its `segment`, and `decoded_offset_known`; a member the walk
reaches after a gap without a search SHALL carry it with `method="stream_segment"` and
empty `unchecked`.

#### Scenario: unaligned TAR search

| Case | Expected |
| --- | --- |
| `.tar.bz2`, one block damaged | Members after it found at unaligned offsets, flagged, `decoded_offset_known=False` |
| `.tar.gz`, one flipped byte that zlib decodes past with a shifted byte count | Members after the flip found by the unaligned search |
| `.tar.xz`, index intact, damage inside a member's data | The walk goes on at the next header (`method="stream_segment"`); no search |
| v7 TAR inside a `.tar.bz2`, one block damaged | No v7 header accepted before a proven phase |
