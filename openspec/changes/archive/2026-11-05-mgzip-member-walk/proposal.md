# Walk mgzip members without decoding

## Why

mgzip (the `mgzip` Python package's multi-threaded writer) writes gzip as a run of
independent members and names each member's DEFLATE size in an `MZ` extra subfield. Like
BGZF, that gives random access without `rapidgzip`, from the headers alone. This was the
remaining reading item of the archived `seekable-gzip-and-block-writing` change; the
maintainer asked for it on 2026-11-05.

## What Changes

- The blocked-gzip walk (`codecs/bgzf_index.py`) recognises an `MZ` first member and walks
  mgzip members header to header: the member size is the parsed header, the `MZ` value
  and the trailer; each ISIZE gives the output. Same trust, stop and thinning rules as
  BGZF; the thinning scan is `mgzip_blocks`.

## Impact

- `seekable-decompressor-streams`: one added requirement.
- Code: `internal/streams/codecs/bgzf_index.py`. No public API.
