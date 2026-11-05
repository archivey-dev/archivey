## ADDED Requirements

### Requirement: open_archive and open_stream accept a detection result

`open_archive()` and `open_stream()` SHALL accept `detection=`, a `FormatInfo` produced by
`detect_format()`, and SHALL skip detection when given one. `format=` and `detection=`
SHALL NOT be supplied together: `format=` is the caller's assertion and suppresses
`format_unconfirmed`, while `detection=` replays archivey's own result, so the reader's
`format_info` and its `format_unconfirmed` behaviour match a self-detecting open exactly.
`open_stream()` SHALL expose the container it detected, not only the stream codec.

#### Scenario: handoff

| Case | Expected |
| --- | --- |
| `open_archive(source, detection=result)` | Detection does not run again; `reader.format_info` is `result` |
| `open_archive(source, format=ZIP, detection=result)` | Usage error |
| `open_archive(source, format=ZIP)` | No detection I/O of any kind; `reader.format_info` is `None` |
| `open_stream(path)` | The detected container is recoverable from the stream |
