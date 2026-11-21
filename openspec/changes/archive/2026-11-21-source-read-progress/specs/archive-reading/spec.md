## ADDED Requirements

### Requirement: Reading the archive's file reports progress

`ArchiveyConfig.on_source_read` SHALL, when set, be called with a `SourceProgress` as
`open_archive()` and `open_stream()` read the archive's own file, detection included.

For a source read by range requests (an `fsspec.core.OpenFile`, alone or in a volume
list) it SHALL be called once before each request, with `request_received == 0` and
`request_done` false, and once after the request returns, with `request_done` true. Over
HTTP it SHALL also be called as the answer comes in, about once per MiB of it, with
`request_received` the bytes so far and `request_done` false. A request sent again (an
ignored range, a short answer continued) counts as a request. `bytes_read` is then the
bytes those requests returned, the current one's so far included.

For any other source it SHALL be called at least once per `source_read_step` bytes
taken from the source (1 MiB by default), and the request fields SHALL be `None`.
`read_start` SHALL be where the latest read started, so `read_start` to `position` is
that read's range. With `source_read_step=0` it SHALL be called for every read, so
those ranges are every read of the file. `bytes_read` counts every byte taken from the
source, rereads included, so it may pass `size`.

It SHALL run on the thread that read (as every caller function does). A read on a thread
archivey started (the RAR volume feeder) SHALL NOT call it: the latest such report SHALL
be kept and delivered on the caller's next read of the archive or of the member being
read. Reports in between are merged, so `requests` may skip numbers and a request may
lack its pair of calls; the once-before, once-after rule and the calls as an HTTP answer
comes in apply to requests sent from a caller's thread. Bytes that an external program
(`unrar`) or the RAR backend reads from volume paths directly are outside this
requirement. An exception it raises SHALL propagate out of the read that called it,
unchanged; every later read of the file SHALL raise it again, bytes served from a cache
or a replay included, and an extraction or verification that goes on past a member's
error SHALL stop on it instead. A reader opened with `parent=` SHALL report to the
callback in its own config (its parent's unless given one) with `nest_level` one more
than its parent's; a member stream opened without `parent=` is a source of its own and
SHALL report at `nest_level` 0. A split set found beside a stub, and the track files of
a `.cue` sheet, SHALL report as the file they stand in for. `position` and `read_start`
SHALL count from the start of the file, also when a stream is opened where the caller
left it. In a volume list that mixes local parts and URLs, the local parts SHALL report
their reads and the URLs their requests, each byte once. With `on_source_read` unset, no
reporting work SHALL be done beyond checking that it is unset.

#### Scenario: a local file read start to end

- **WHEN** `on_source_read` is set and a 10 MiB `.xz` file is read start to end through
  `open_stream()`
- **THEN** the callback runs about ten times, `bytes_read` never decreases, and the last
  call has `position` at the end of the file (`bytes_read` may pass the size: the tail
  is read first and again at the end)

#### Scenario: every read of a local file

- **WHEN** `on_source_read` is set with `source_read_step=0` and every member of a ZIP
  is read
- **THEN** each call's `read_start` to `position` is one read, the lengths add up to
  `bytes_read`, and together they cover the directory and every member's data

#### Scenario: a nested reader

- **WHEN** `on_source_read` is set and an archive is opened from a member with
  `open_archive(member, parent=outer)` and no `config=`
- **THEN** the outer file's reads report at `nest_level` 0 and the nested reader's
  reads report to the same callback at `nest_level` 1

#### Scenario: a URL source

- **WHEN** `on_source_read` is set and an archive is listed from an `OpenFile`
- **THEN** every request gives one call before it and one after it, and the last call's
  `requests` and `bytes_read` equal the request count and bytes fetched

#### Scenario: a large HTTP answer

- **WHEN** `on_source_read` is set and one HTTP request returns several MiB
- **THEN** the callback runs about once per MiB while the answer comes in, on the
  caller's thread, with `request_received` growing and `request_done` false

#### Scenario: the callback raises

- **WHEN** the callback raises `KeyboardInterrupt` or any other exception
- **THEN** the call into archivey that read raises that exception, also under
  `extract_all(on_error="continue")`
