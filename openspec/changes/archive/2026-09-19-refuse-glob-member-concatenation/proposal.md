# A glob-named member that pulls in its siblings is refused, not silently paid for

## Why

A RAR member's *stored name* can contain `*` or `?`. `unrar` is addressed by an
include mask, so archivey passes such a name as `-n./<name>` — and `unrar` reads it as
a wildcard. It decompresses **every** member the mask matches and emits them
concatenated in archive order. `_unrar_glob_prefix` sizes the earlier matches and
`_bounded_member_pipe` skips them, so the caller gets the right bytes. The decode has
already happened.

Measured on `ad3c1b9`, a purpose-built two-member **non-solid** archive:

```
glob_prefix bytes unrar will emit-and-discard: 2000000
read 120000 in 0.014s
```

Reading a 120 KB member named `*.bin` decompresses 2,000,000 bytes of `data.bin`
first. A member named `*` would decompress the whole archive. Nothing tells the
caller: the archive is not solid, `AccessCost.DIRECT` says "read any member without
touching the others", and `ExtractionLimits` do not cover `open()` / `read()`
(threat-model O1). `_track_decompressed` records the bytes after the fact.

PR #371 substitutes `?` for `*` in the mask, which narrows this sharply — `?` matches
exactly one character, so only same-length names agreeing on every literal position
can still match. It does **not** bound the magnitude. Measured with real `unrar`, a
120 KB member named `*.bin` plus one 2 MB sibling:

| Sibling | mask `*.bin` | mask `?.bin` |
| --- | --- | --- |
| `data.bin` (8 chars) | 2,120,000 bytes | 120,000 — target only |
| `x.bin` (5 chars) | 2,120,000 bytes | 2,120,000 — unchanged |

One same-length sibling can be any size, so the worst case survives. What changes is
that reaching it needs a name a constructed archive is far more likely to carry than
an accident.

Recorded as `dev-docs/formats/rar.md` §10 #19, raised on
[#296](https://github.com/archivey-dev/archivey/pull/296).

## What Changes

- Opening a member whose mask also matches **earlier** members raises
  `UnsupportedFeatureError`. On a non-solid archive the error names the byte count
  and the flag; on a solid archive it names the flag and does not describe those
  bytes as an avoidable extra decode. The message is the whole escape route, so a
  caller who hits it does not have to read the source.
- `ArchiveyConfig.rar_allow_glob_member_concatenation` (default `False`) restores the
  previous behaviour. The skip machinery is unchanged and still correct; the flag only
  decides whether the read is attempted.
- A glob name matching **no** other member is untouched — `glob_prefix` is 0 and the
  refusal never triggers. That is the accidental `report*.pdf` case, and it still
  reads with no flag.
- A **solid** streaming pass is unaffected, because it builds no mask at all: one
  unnamed `unrar p` ALL-pipe, demuxed by size. The exemption falls out of where the
  check sits rather than being special-cased.

**Maintainer (davitf, 2026-09-19):** "archives with filenames like these are likely
malicious, not worth the DOS risk. config is an escape hatch."

## Impact

- Archives that read today start raising unless the caller opts in. The affected set
  is narrow and narrows further once #371 lands.
- A **non-solid** `stream_members()` pass takes the named route, so it is refused too.
  Measured: `_iter_with_data` falls through to per-member named opens for nonsolid, so
  a streaming pass builds the same mask a random `open()` does — and decodes the
  prefix member twice, once as itself and once inside the target's pipe.
  Maintainer (davitf, 2026-09-19), asked whether iteration should be exempted:
  "right now don't exempt iteration, it can fail as the other modes."
  `test_wildcard_nonsolid_stream_members_hits_the_refusal` pins that. The 2026-09-20
  ruling was about carving *solid* `open()`/`read()` out of the refusal, not this path.
- `UnsupportedFeatureError` is reused rather than a new type, matching the
  backslash/directory-glob refusal a few lines above it in `_open_member`: from the
  caller's side both mean "this member's stored name means archivey will not read it
  through unrar". `ResourceLimitError` was the alternative and is scoped by its own
  docstring to `ListingLimits` / `ExtractionLimits` trips.
