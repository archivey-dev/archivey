# format-tar — salvage mode delta

## ADDED Requirements

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

On a compressed TAR the search SHALL run on the decoded stream; damage in the codec
SHALL end the walk as today.

#### Scenario: TAR header search

| Case | Expected |
| --- | --- |
| 4 KiB zeroed inside the header region | Every member after the zeroed region, flagged and confirmed; one `ARCHIVE_REGION_SKIPPED`; `CorruptionError` at the end |
| 64 KiB deleted from the middle | Every member whose header follows the gap, flagged; GNU tar's member set |
| Damaged size field, `salvage=False` | As today |
| Outer `.tar` member holding an inner `.tar`, outer header damaged and not followed | The inner members listed, flagged (Q12); the outer member after them listed |
| Intact archive with data after the end marker | Nothing added in this step |
