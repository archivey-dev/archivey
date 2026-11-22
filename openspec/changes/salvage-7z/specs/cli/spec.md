# cli — salvage step 5 delta

## MODIFIED Requirements

### Requirement: --salvage reads in salvage mode

`--salvage` on `list`, `test`, `extract` and `info` SHALL open the archive with
`open_archive(salvage=True)`. `extract --salvage` SHALL extract with
`OnError.KEEP_PARTIAL`. `list` SHALL mark each member with `MEMBER_FOUND_BY_SCAN` or
`MEMBER_NAME_UNKNOWN` (a note in the long listing, `found by search` or `name unknown`,
and a field in JSON output that holds the code). The exit code SHALL be the one the
damage error gives without `--salvage`. `--salvage` on a pipe (`-`) SHALL fail with a
usage error that says to save the input to a file first.

#### Scenario: salvage flag

| Case | Expected |
| --- | --- |
| `archivey list damaged.tar --salvage` | Members past the damage, marked; damage exit code |
| `archivey list cut.7z --salvage` | `__salvaged__/7z-stream-0001.bin` and so on, marked `name unknown`; truncation exit code |
| `archivey extract damaged.tar --salvage` | Found members written; a member whose read failed kept partial |
| `cat x.tar \| archivey list - --salvage` | Usage error |
