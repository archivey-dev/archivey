# testing-contract — a remote-source benchmark axis

## ADDED Requirements

### Requirement: Remote-source requests and bytes fetched are measured and gated

The benchmark harness SHALL measure, for every format the structural gate covers, the
range requests and bytes fetched when the archive is read through an fsspec `OpenFile`.
The counts SHALL come from a counting fsspec file system over local fixture files, which
records every range read, every size or info call and every directory listing, so the
counts are exact and host-independent.

Per case the harness SHALL record `range_requests`, `metadata_requests`,
`bytes_fetched` and `bytes_needed` (the least the operation can read: the index plus the
member's stored span, or the whole stream for a format with no index), and report
`bytes_fetched / bytes_needed`. `range_requests` SHALL be gated exactly and
`bytes_fetched` as at most its baseline, in a committed baseline file updated only by
`--update-baselines`, on every PR, as the seek counts are.

The PR-gated cases SHALL run on small seeded fixtures, with the planner's internal
constants set small enough through a private seam, and `ArchiveyConfig.max_read_through`
through the config field, that every case crosses fetch, gap and pool boundaries, so the
counts are exact on every host. The seam's maximum fetch SHALL stay above every fixed
backend hint the planner's ceilings rely on, so a gated case is held to the same ceilings
as the production constants. The
production constants SHALL run on the larger wall-job scale off the PR path, reported
and not gated.

A non-gated job SHALL run the same cases through fsspec's `HTTPFileSystem` against a
local range server and SHALL fail when its request count differs from the counting file
system's for the same case.

#### Scenario: remote benchmark cases

| Case, per format | Recorded |
| --- | --- |
| Open and list | All four counts |
| Read the first, a middle and the last member | All four counts |
| `extract_all()` | All four counts |
| One `stream_members()` pass, `streaming=True` | All four counts |
| Eight threads read eight members of one ZIP | All four counts; the pool bound holds |
| More member streams of one ZIP than the pool holds at the minimum fetch | All four counts; the pool bound holds |
| Read one member through `fsspec.open("archivey://<member>::<fixture URL>")` | All four counts |
| A change adds one range request to a ZIP open | The PR gate fails until the baseline diff is reviewed |
