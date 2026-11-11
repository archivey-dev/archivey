# Design: archives stored as a program resource

## 1. The rule

A PE resource's data entry gives an RVA and a size; the section table turns it into a
file extent `[start, end)`. When an archive's end `A` satisfies `start < A <= end` for
some resource, the trailing-data check looks only at `[A, end)`. Zero padding there is
silent as everywhere; a non-zero byte there is reported as before. A first non-zero byte
at or past `end` is the rest of the program and is not reported.

Implemented as a filter on the existing scan's answer, not as a shorter scan: the scan
finds the first non-zero byte after `A`; it is reported unless it lies at or past the
end of the resource holding `A`. Both say the same thing, and the filter needs no change
to how each reader scans.

Not "any byte inside the program image": an archive embedded in `.text` or `.data` is
not a deliberate container, and the resource rule says exactly which bytes are the
archive's.

## 2. Same answer for detected and forced opens

The archive's start is not needed, only its end, which every reader knows after parsing.
The resource table comes from the source's first bytes, the same for both paths. So
`open_archive` builds the object for every SFX backend without looking at detection's
answer, and a forced `format=` reports what auto-detect reports.

## 3. Cost and laziness

The object reads nothing when built. The first question reads the first
`LAYOUT_PREFIX` (4096) bytes and, for a PE with a resource directory, up to
`RESOURCE_TABLES_READ` (64 KiB) from the directory's start, where linkers put the
directory tables and data entries. A data entry outside that window is not seen and the
archive is reported as today. The walk is bounded: three levels, 4 096 entries. A table
that points at itself stops at the depth bound.

The question is asked only after a reader found a non-zero byte, and only during open:
ZIP and 7z ask in their open-time trailing check; RAR's walk records the bytes at open
and the reader asks right after the walk, before anything else reads the source. The
object seeks the source and restores its position, as `read_payload_end` does.

## 4. Why a new `open_read` argument

`open_read`'s promise is a view of `[start_offset, end_offset)`: a backend never reads
before its start. The resource table sits before the archive, so `open_archive` reads it,
as it reads the certificate end. The argument says so; a hidden attribute or a method on
the source would not.

## 5. LHA

`lha_reader` is written against the plugin API (`IndexedReaderAdapter`). Carrying the
resources would need a new public `ReaderContext` member, a public API decision for a
case no real installer has. Left out; LHA still reports, the same way detected and
forced.
