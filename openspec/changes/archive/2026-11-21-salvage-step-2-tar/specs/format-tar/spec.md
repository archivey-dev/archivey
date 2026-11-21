# format-tar — salvage step 2 delta

## ADDED Requirements

### Requirement: A damaged TAR header SHALL be followed when the block its size points at confirms it

When a header fails its checksum (the checksum does not match, or the checksum field is
not a number), the walk SHALL read it from its other fields when they parse as any
header's do and it has the `ustar` magic (POSIX or old GNU). It SHALL then take the
member's chain as for an intact header and go on from where the next header starts,
when the block there *confirms* it:

- a header that passes its checksum and has the `ustar` magic; or
- the end-of-archive marker with only zero bytes after it to the end of the archive,
  at least two blocks and no more than 1 MiB.

A damaged extended header (`x`, `g`, `L`, `K`) SHALL be confirmed by the block after
its data in the same way, or by a damaged member header that is itself confirmed. Up to
8 damaged headers in a row SHALL be followed; the run is confirmed by the block after its
last damaged header. A header with no magic, a field that does not parse, a block that
does not confirm, an error inside the damaged chain, or a ninth damaged header in a row
SHALL stop the walk at the chain's first damaged header, with the reason a walk that
never followed it gives (`Reject TAR headers that do not parse`). The walk SHALL NOT
search the bytes for a header: GNU tar's block scan is a deliberate DR-6 departure, left
to salvage mode.

A member listed from a damaged chain SHALL carry the damaged header's offset, and every
read of it SHALL emit `MEMBER_HEADER_DAMAGED` (`diagnostics`); listing it SHALL NOT. After
the last member, the pass SHALL end in `CorruptionError` naming each followed header.

On a forward-only source the walk SHALL read the damaged member's data and the block
after it ahead and replay them, holding no more than 4 MiB before that block (the RAR
pipe's span); a longer member SHALL stop the walk at the damage, and the error SHALL say
to save the archive to a file. The listing SHALL otherwise be the same in both access
modes and on compressed TARs.

#### Scenario: damaged header matrix

| Case | Expected |
| --- | --- |
| A name byte of the third of five headers flipped (GNU or ustar, any access mode) | Five listed, the third under the damaged name with `MEMBER_HEADER_DAMAGED` on its read; `CorruptionError` at the end |
| The checksum field of the third header damaged | The same, under its own name |
| The size field of the third header damaged | Two listed; `CorruptionError` naming the third header, as before |
| The magic of the third header damaged, or a v7 archive | Two listed, as before |
| The last header damaged, only the trailer after it | All listed, the last flagged |
| The last header damaged, bytes after the trailer | All but the last; `CorruptionError` |
| A damaged `L` or `x` header with an intact size | All listed, the member flagged, with its long name |
| Eight damaged headers in a row / nine | All listed / the walk stops at the first |
| A pipe, a damaged member over 4 MiB | The walk stops at it; the error says to save the archive to a file |
| `DiagnosticPolicy.STRICT` | The damaged member's read raises `DiagnosticRaisedError`; the others read |
