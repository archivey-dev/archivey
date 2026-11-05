## ADDED Requirements

### Requirement: A ZIP may be preceded by arbitrary bytes

ZIP locates its central directory from the **end** of the file. A leading prefix is
therefore not a special case to be tolerated — it is a property the format was designed
with, and it is why concatenating a stub with a ZIP has been a working idiom for decades
(`zipapp`, pex, shiv, Spring Boot executable JARs, self-extracting `.exe` installers, and
appended-ZIP polyglots).

**There are two write conventions, and they store different numbers.** A reader must not
assume either one:

- **Written in place** (`zipapp`, and any writer that opens one file, emits a stub, then
  writes entries through the same handle): the stored offsets count from **byte 0 of the
  file**, stub included, because the writer simply used its current file position.
- **Concatenated** (`cat stub payload.zip > out`): the payload was written as a standalone
  ZIP, so its stored offsets count from **the start of the ZIP data** and are short by the
  prefix length.

Measured on a stdlib `zipapp.create_archive(..., interpreter="/usr/bin/env python3")` and
on a `cat`-style concatenation of the same entries:

| | prefix | first local header | stored `offset_cd` | actual CD position | EOCD adjustment |
| --- | --- | --- | --- | --- | --- |
| `zipapp` `.pyz` | 23 B | 23 | 76 | 76 | **0** |
| concatenated | 33 B | 33 | 53 | 86 | **33** |

The difference is real but self-correcting: the EOCD record's own location is known once
found, so the adjustment `(eocd_pos - size_cd) - offset_cd` recovers the base under either
convention, and every entry offset is read through it. Both shapes therefore open, and both
open whether the reader is handed the whole file or a view starting at the prefix — verified
against the stdlib on a five-member `zipapp`, where the view produces a *negative*
adjustment and still lists and reads every member.

The system SHALL locate the End of Central Directory by searching backwards from the end of
a seekable source, and SHALL read such an archive without requiring a forward scan, a stub
cue, or a caller-supplied offset.

`payload_offset` SHALL report **the absolute position of the earliest local file header** —
equivalently `min(header_offset) + adjustment` over the central directory. This is the
prefix length under *both* conventions (23 and 33 above), which is what makes it a usable
number for a caller and consistent with the value the forward scan already reports for an
`MZ`-prefixed ZIP. It is deliberately **not** the EOCD adjustment, which is 0 for `zipapp`
and would report the motivating case as unprefixed.

**One exception, because the definition has no subject there.** An empty archive
(`total_entries == 0`) has no local file header to point at, so `min(header_offset)` is
undefined. There `payload_offset` SHALL be the **EOCD-derived base** — the position the
central directory occupies, `eocd_pos - size_cd`, which for an empty archive is where the
ZIP data ends and also where it began. This is the only case where the two definitions are
not interchangeable, and it is stated here rather than left to the validation matrix.

The search bound is **derived from the format, not chosen**: the EOCD comment length field
is a `uint16`, so the record cannot begin more than 65535 + 22 bytes before the end. The
system SHALL NOT search further back than that, and SHALL NOT make the bound configurable —
a larger value cannot find a valid EOCD, and a smaller one would reject legal archives.

A non-seekable source cannot be searched from the end. There the system SHALL fall back to
the ordinary tiers (forward scan when a prefix cue fires, then extension), and a prefixed
ZIP arriving as a pipe MAY therefore go undetected. That is a documented limitation of the
source, not a defect in the ZIP reader.

#### Scenario: prefixed ZIP matrix

| Case | Expected |
| --- | --- |
| `#!/usr/bin/env python3` + ZIP (a `zipapp` `.pyz`, **written in place**, EOCD adjustment 0) | `ZIP`; all members listed and readable; `payload_offset` = length of the shebang line, **not** 0; `prefix_kind == SCRIPT` |
| `#!/bin/sh` launcher + **concatenated** ZIP (Spring Boot executable JAR shape, adjustment > 0) | `ZIP`; members readable; `payload_offset` = prefix length; `prefix_kind == SCRIPT` |
| PE stub + ZIP (a self-extracting installer) | `ZIP`, `payload_offset` at the ZIP data; `prefix_kind == EXECUTABLE` |
| JPEG header + appended ZIP (tail probe enabled) | `ZIP`; the polyglot opens as the archive it also is; `prefix_kind == UNKNOWN` |
| Plain ZIP | Unchanged; `payload_offset == 0`; `prefix_kind == NONE` |
| Prefixed ZIP on a non-seekable stream | Not found by the tail probe; falls through to the other tiers |
| A file whose last 64 KiB contain `PK\x05\x06` but no valid central directory | No ZIP claim (see the validation requirement below) |

The first two rows are the point of the table: they are the same archive to a caller, they
store different offsets, and they MUST produce the same `payload_offset` semantics.

### Requirement: A tail-probe hit is validated before it is reported

The tail probe runs when the detection budget grants a tail read (`max_tail_bytes` and
`TAIL`), so a four-byte coincidence in the last 64 KiB of an unrelated file must not
produce a ZIP claim. Under the default `BALANCED` budget it does not run. `PK\x05\x06` alone is not
evidence; the system SHALL confirm the record before reporting a format.

A candidate End of Central Directory SHALL be rejected unless all of the following hold:

- The 22-byte fixed record fits entirely within the source.
- `comment_length` exactly matches the bytes remaining after the record; a record that
  claims a comment running past the end, or that leaves unclaimed trailing bytes, is not
  the EOCD.
- The derived adjustment `(eocd_pos - size_cd) - offset_cd` places the central directory
  at a non-negative position, and `size_cd` bytes starting there lie within the source.
- The first central-directory entry at that position begins with `PK\x01\x02`, and the
  entry count is consistent with `total_entries` (an empty archive, `total_entries == 0`
  with `size_cd == 0`, is valid and SHALL be accepted).
- The earliest `header_offset`, adjusted, points at a `PK\x03\x04` local file header
  within the source — this is also the value `payload_offset` reports, so validating it
  and computing it are the same read.

When the record is a ZIP64 locator (`PK\x06\x07`) the system SHALL follow it to the ZIP64
EOCD (`PK\x06\x06`) and apply the equivalent checks to its wider fields, rather than
rejecting the archive for failing the 32-bit ones.

Because scanning backwards can encounter a `PK\x05\x06` that is file data rather than a
record, the search SHALL continue past a candidate that fails validation instead of
concluding the source is not a ZIP.

#### Scenario: tail-probe validation matrix

| Case | Expected |
| --- | --- |
| Valid prefixed ZIP | `ZIP` at the validated offset |
| Random bytes containing `PK\x05\x06` in the last 64 KiB | No ZIP claim; search continues past it |
| Planted `PK\x05\x06` with a central-directory offset past the end of the source | Rejected |
| Planted `PK\x05\x06` whose `comment_length` overruns the source | Rejected |
| Planted EOCD pointing at bytes that are not `PK\x01\x02` | Rejected |
| Valid EOCD preceded by an earlier decoy `PK\x05\x06` in member data | The real record is found; the decoy does not end the search |
| Empty ZIP (`total_entries == 0`) | Accepted; `payload_offset` at the EOCD-derived base — the stated exception to the earliest-local-header definition, since there is no local header |
| ZIP64 archive behind a prefix | Followed via the locator and accepted |
