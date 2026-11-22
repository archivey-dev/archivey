# format-single-file-compressors — salvage stream segments delta

## ADDED Requirements

### Requirement: Salvage lists later segments of a single-file stream as members

With `salvage=True`, the single-file reader SHALL list its one default member first,
unchanged: name, fields, bytes, diagnostics and the error where its decode stops. For
each later segment (`compressed-streams`) it SHALL list one `FILE` member named
`<default member name>.segment-<n>`, where `n` is the segment's number with at least
four digits, the stream's start being segment 1, so the first such member is
`.segment-0002`. Its `size` SHALL come from the stream's structure when it gives every
unit's decoded size (xz index, lzip trailers, BGZF walk, zstd seek table), else be
`None`; it SHALL have no `mtime`, and a later gzip member's `FNAME` and `MTIME` SHALL
NOT be used.

Each such member SHALL carry `MEMBER_NAME_UNKNOWN` and no other salvage code, with
`method="stream_segment"`, `segment=n`, `offset` the decoded offset of its first byte
(0 with `decoded_offset_known=False` when unknown), and `unchecked` holding `"name"`,
plus `"position"` when the offset is unknown.

Opening SHALL decode nothing. The listing SHALL yield the default member before any
decode, and SHALL decode to the next damage only when the next member is asked for. A
`stream_members()` pass SHALL decode each segment once.

A segment member's `verifiable` SHALL be `CHECKSUM` when each of its units carries a
data check, `LENGTH` when each stores its decoded size without a check, else `UNLOCKED`.
Its read SHALL end where its codec ends it.

#### Scenario: segment members

| Case | Expected |
| --- | --- |
| `data.txt.bz2` with one damaged block, `salvage=True` | `data.txt` (as the default, raising at the damage), then `data.txt.segment-0002` with `MEMBER_NAME_UNKNOWN`, `verifiable=CHECKSUM`; then the default's error |
| Intact `data.txt.xz`, `salvage=True` | One member, as the default; the listing decodes the stream once |
| `data.txt.xz`, index intact, two damaged blocks apart | `data.txt`, `.segment-0002`, `.segment-0003`, each with a known offset and size |
| Same file, `salvage=False` | One member, as today |
