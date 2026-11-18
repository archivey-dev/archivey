## RENAMED Requirements

- FROM: `### Requirement: Join 7-Zip .zip.NNN sets; reject spanned ZIP cleanly`
- TO: `### Requirement: Join split and spanned ZIP sets`

## MODIFIED Requirements

### Requirement: Join split and spanned ZIP sets

7-Zip's `-v` byte-splits one finished single-disk ZIP into
`name.zip.001 … name.zip.00N`, exactly as it splits `name.7z.NNN`. An SFX split
names the same slices `name.exe.001 … name.exe.00N` (stub `name.exe` is not a
sibling). Windows 7-Zip keeps the archive extension (`name.zip.001`) and writes
the stub as `name.exe`. With every
part `1..N` present beside the one named, `open_archive` SHALL concatenate them
and read the result as the ordinary ZIP it is, from any part **or from a
stub-only `name.exe` that has no archive magic** (including under an explicit
`format=ZIP`; a `format=` naming a different container is `ArchiveyUsageError`),
reporting
`ArchiveInfo.is_multivolume = True` and `ArchiveInfo.extra["zip.volume_count"] = N`
(not `ArchiveMember.extra`, which stays empty).
A gap in the numbering SHALL raise `TruncatedError`. A lone `.zip.NNN` (or
SFX `.exe.NNN`) part whose siblings are not on disk SHALL raise the same
`TruncatedError`, naming the missing parts.
A named part that is not on disk itself SHALL raise `FileNotFoundError`, like
any other missing path.

Info-ZIP's `zip -s` (and WinZip) writes a spanned set, `name.z01 … name.zNN`
(`name.z100` and on past 99 parts) and last `name.zip`, whose end record names the
last disk and whose entries are addressed by `(disk, offset-within-disk)`. When
`name.zip`'s end record names more than one disk (the ZIP64 locator's disk count when
there is one) and every part it names is beside the one named, `open_archive` SHALL
join the parts in order, from any part, and read every `(disk, offset)` pair, the
directory's and the ZIP64 record's included, as that part's start in the join plus
the offset, reporting `is_multivolume` and `zip.volume_count` as for a split set. A
part it names that is missing SHALL raise `TruncatedError` naming it. A `name.zip`
whose end record names one disk SHALL be read alone, whatever `.zNN` sits beside it.

Every other split/spanned signal SHALL raise `TruncatedError` rather than mis-read
data: a `.zNN` or `.zip.NNN` name read alone (no set found beside it, or volume
discovery off), an end record or ZIP64 locator naming more disks than the parts given
(a `.zip` read alone, or an explicit list of the wrong length; a classic `0xFFFF` is
the ZIP64 sentinel, not a disk number). An end record placing the directory on a disk
after its own, or an entry on a disk the set does not have, SHALL raise
`CorruptionError`.

#### Scenario: multi-volume ZIP join and refusal

| Source | Expected |
| --- | --- |
| A complete 7-Zip `.zip.NNN` or SFX `.exe.NNN` set, named at any part | Lists and reads every member, data across a part boundary included |
| A complete `zip -s` set, named at the `.zip` or any `.zNN`, or listed in order | Lists and reads every member; `zip.volume_count` is the part count |
| A `zip -s` set with a ZIP64 end record and locator | Same |
| A `zip -s` set with a `.zNN` missing | `TruncatedError` naming it |
| The `.zip` of a `zip -s` set alone | `TruncatedError` saying how many parts the set has |
| A `.zNN` with no `.zip` beside it | `TruncatedError` |
| A `.zip` naming one disk beside a stray `.z01` | Read alone |
| An incomplete `.zip.NNN` set | `TruncatedError` |
