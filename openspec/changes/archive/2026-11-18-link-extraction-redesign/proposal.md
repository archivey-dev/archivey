## Why

Hard links whose source the caller excluded are held back and made after the pass. To
give the result a link made in place gives, the coordinator simulates the made link:
its name (#1371, #1598), its parents, pins and holders (#1616), and the case folding of
the filesystem. Each review round finds one more shape the simulation gets wrong. Writes
through the run's own symlinks add a second source of shapes: a later member re-points
or replaces a symlink that earlier members were written through. A random-archive
fuzzer (`evidence/linkfuzz.py`) still finds mismatches on #1616's head.

## What Changes

- A held-back hard link is an empty placeholder file at its place in archive order,
  made through the normal file path (collision, overwrite policy, parents). Later links
  to the same excluded source link to it. After the pass the source is read once and
  moved onto each name that still holds the placeholder. The reservation model and the
  ordering of the second pass are removed.
- **BREAKING (if D2 is accepted):** a member whose parent path reaches a symlink this
  run created is refused (`BLOCKED`, `FilterRejectionError`). Symlinks that were in the
  destination before the run are followed as before.
- The streaming exception is stated as one rule: a hard link whose source has no written
  copy on disk is recovered only from a re-readable source. A link to the earlier copy
  of its own name, still on disk when the link arrives, is made against it.
- A Hypothesis test compares held, made, streaming and dry runs of random archives.

## Capabilities

### Modified Capabilities

- `safe-extraction`: held-back hard links, writes under the run's own symlinks.

## Impact

`src/archivey/internal/extraction.py` (deep tier), `tests/test_extraction.py`,
`tests/test_symlink_recheck.py`, a new property test,
`openspec/specs/safe-extraction/spec.md`, `docs/extracting.md`,
`dev-docs/threat-model.md`. D2 needs a minor release.
