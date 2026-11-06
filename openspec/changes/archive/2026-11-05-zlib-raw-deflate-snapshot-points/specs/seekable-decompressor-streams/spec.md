## ADDED Requirements

### Requirement: zlib and raw DEFLATE decodes record zlib snapshot points

On declared seek demand, the standard library engine SHALL record zlib snapshot points
in a zlib stream and in raw DEFLATE (such as a ZIP member's), as in a gzip member
(§"gzip decodes record zlib snapshot points"). A zlib stream resumed from one MUST still
check its Adler-32, which the copy carries.

#### Scenario: zlib and raw DEFLATE snapshot matrix

- **WHEN** a zlib or raw DEFLATE stream is read and seeks back
- **THEN** it behaves as below

| Case | Expected |
| --- | --- |
| zlib or raw DEFLATE stream, read forward with seek demand, then seek back | Resumes at the nearest snapshot before the target |
| ZIP DEFLATE member opened with `seekable_members=True`, rapidgzip off | Same |
| zlib Adler-32 damaged, seek back to a snapshot and read on | `CorruptionError` at the end of the stream |
