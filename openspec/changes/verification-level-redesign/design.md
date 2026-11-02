## Context

`verification-level` (PR 1032) shipped four ordered levels, renamed in PR 1212 to
`NONE`, `PASSWORD`, `LENGTH` and `CHECKSUM` and marked experimental in PR 1213.
`ArchiveStream.verify(level)` (PR 1211) raises a stream to a level: a seekable stream
is left as it was, and a non-seekable one is read to the end, after which reads raise
`ArchiveyUsageError`. The maintainer refined the meaning in the thread "Refine the
verification design". The proposal lists each ruling. This file records how each
rule maps onto the code.

## Decisions

### 1. One definition for the top level

`CHECKSUM` holds when every byte of the member's output passed at least one check that
a wrong byte fails, except by chance at the check's own odds. Where the check sits
does not matter. A file of frames qualifies only if every frame carried a check.

- **xz:** each block carries its check type in the stream flags (None, CRC32, CRC64,
  SHA-256). Check type None in any stream of the file keeps it at `LENGTH`.
- **zstd:** the frame header's Content_Checksum_flag. A frame without it keeps the
  file at `LENGTH`. Skippable frames carry no output and do not count either way.
- **lz4 frame:** either the content checksum or block checksums covering every block.
  Legacy-format frames have none.

Each decoder reports through the same private query the codec check uses today
(`checks_content` becomes per-stream: "content matched" is set only when the decoder
saw a check on every frame and all passed). The seek rule of `verification-level`
Decision 4 is unchanged.

### 2. Keys without proof stay `NONE`

This is unchanged, but now written down. A member whose password nothing can prove
(stored data under AES, or a 7z AES folder with no CRC) has `verified == verifiable ==
NONE`, even after a clean full read. Another member's matching CRC proves the key only
for members of the **same 7z folder**, because folders can use different passwords.
The tests cover both cases.

### 3. One-file 7z folders

When a 7z folder holds exactly one file and that file has no digest, the folder's
unpack digest covers the same bytes, so the reader hands it to the verifier as the
member digest. With several files and only a folder CRC, each file stays at `LENGTH`.

### 4. Surface

The surface stays `verified`, `verifiable` and `verify(level)`. The docs lead with
"`verified == verifiable` means nothing more can be checked".

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| A decoder binding hides whether a frame had a check | Report `LENGTH` for that codec until the binding exposes it: under-report, never over-report |
| A one-file folder CRC handed over twice (folder check plus member digest) | Hand it over only when the member has no digest of its own |
