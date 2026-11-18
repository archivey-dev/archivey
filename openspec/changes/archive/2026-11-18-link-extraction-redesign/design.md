# Link extraction: remove the corner-case classes instead of closing cases one by one

**Archived 2026-11-18, for reference.** All three decisions in §6 were taken as
recommended. D1 shipped in #1620, D2 in #1622 (next minor release), with the DR-6 scope
rule it relies on in #1621, and D3 is the documented difference between the modes.
`openspec/specs/safe-extraction/spec.md` carries the result; this change's delta spec
was not applied on archive, because those PRs edited the spec directly. Where the
outcome differs from the text below, §8 says so.

## 1. Recommendation

1. **A held-back hard link becomes a real, empty file at its place in archive order** (a
   *placeholder*), and the second pass only fills in its bytes. GNU tar uses the same
   idea for its delayed links. Today the first pass *simulates* the made link: it holds
   the name in a side table (`reservations`), and since #1616 also its parents
   (`held_under`, `pinned_dest`, `parent_holder`, `_reserved_component`) and the case
   folding of the filesystem (`_folds_case`). Every new shape needs one more rule in the
   simulation. With a placeholder, the filesystem gives every later member the answer a
   made link would give, because a made hard link is also a regular file at that name.
   A 40-line prototype on `main` (`evidence/placeholder-prototype.diff`) removes the
   held-versus-made mismatches that a random-archive fuzzer finds: from 110 in 1,200
   runs on `main`, and 6 to 20 in 1,200 on #1616's head, to 1 in 6,400 (§3).
2. **A member is never written through a symlink that this run created.** Such a
   member is refused (`BLOCKED`). bsdtar refuses these writes by default, and the deb
   reader already refuses a member under one of its own data symlinks (#1607). GNU tar
   and Python's `tarfile` write through the link. This removes the class where a later
   member re-points or replaces a symlink that earlier members were written through. 10
   of the 21 held-link parity shapes in #1616's test and one of the two open supersede
   gaps have a symlink above the link.
3. **Make the random-archive fuzzer a standing test** (Hypothesis, small in CI, long on
   the nightly schedule). In under a minute it finds the shapes that #1616 fixes
   (`hard a/x -> src1`, then `file a`), and on #1616's head it finds held-link
   mismatches that four review rounds did not.
4. **Keep the streaming exception and name it exactly** (§6, D3): a hard link whose
   source has no written copy left on disk can only be recovered from a re-readable
   source. Fix the one sub-case where the copy is in fact still on disk.

Not recommended now: a full plan-then-write model as the implementation, extraction
through directory descriptors (`openat`), and deferring all symlinks to the end (§5).

## 2. Why the cases keep coming

The coordinator writes in archive order to the real filesystem and uses the real
filesystem to decide what a later member meets. Two features break that:

- **Held-back hard links.** A link whose source was excluded is not on disk when later
  members arrive, but it must act as if it were (maintainer ruling: the same archive
  gives the same contents, whatever the options). So the coordinator keeps a second,
  partial model of the tree for those links, and every disagreement between that model
  and the filesystem is a bug. The model has grown with each review round: names
  (#1371), names in archive order (#1598), parents, pins and holders (#1616). The
  fuzzer still finds mismatches on #1616's head (§3).
- **Writes through the run's own symlinks.** A member under `s/` lands wherever `s`
  points *now*. A later member can re-point or replace `s`, so the run needs the
  physical path of every claim (`_Claim.physical`, `_physical_rel`,
  `resolved_parents`), and every place that compares paths must choose between the
  spelled and the physical one. Each wrong choice is a bug.

Each review round closes the cases it names. The classes stay open, so the next round
finds the next case.

## 3. Evidence: a differential fuzzer

`evidence/linkfuzz.py` builds random TAR archives of 4 to 9 members over a small name
space (`a`, `b`, `c`, `A`, `a/x`, `b/x`, `a/x/y`): files, directories, symlinks with
targets such as `a`, `../x`, `a/..`, `.`, and hard links to `src1`, `src2` or an earlier
member. It extracts each archive under each overwrite policy, `OnError.CONTINUE`, in
four ways, and compares each to the first: statuses, result paths and the files on disk.

- **made**: everything selected, random access (the reference)
- **held**: `src1` and `src2` excluded, so links to them are held back
- **stream**: everything selected, `streaming=True`
- **dry**: `dry_run=True` (statuses and paths only)

A divergent archive is shrunk by removing members while it still diverges.

| Code | Runs | held differs | stream differs | dry differs |
| --- | --- | --- | --- | --- |
| `main` f05fc4d, STANDARD | 1,200 | 110 | 46 | n/a |
| #1616 head 219cbfe, STANDARD, two seeds | 2,400 | 26 | 89 | 0 |
| #1616 head, STRICT / TRUSTED / STANDARD | 800 each | 10 / 14 / 10 | 21 / 20 / 21 | 0 |
| Placeholder prototype, STANDARD, four seeds | 4,800 | 1 | 157 | n/a |
| Placeholder prototype, STRICT / TRUSTED | 800 each | 0 / 0 | 21 / 20 | 0 |

Each run takes 15 to 60 seconds. Examples still open on #1616's head (held run differs
from the made run):

- `dir c/`, `hard c -> src1`, `dir c/`, under `ERROR` and `SKIP`. This is the second
  supersede gap tracked internally.
- `sym a -> x`, `hard A -> src2`, `hard a -> src2`, under `ERROR` and `SKIP`.
- `file b/x`, `hard b -> src1`, `dir b/`, under `ERROR` and `SKIP`.
- `sym A -> b/x`, `hard a -> src1`, `file a`, under `REPLACE`: the result paths differ
  (`a` against `A`).

The prototype gives the made result on all four, and on #1616's own review finding C1.
The one remaining held mismatch in 6,400 prototype runs is the prototype looking up
the file to fill by its spelled path after a symlink above it was replaced; looking it
up by identity fixes it, and recommendation 2 removes the case.

Every stream mismatch has one cause (§4, class S): a hard link whose source has no
written copy on disk. Random access recovers the bytes from the archive, and a
streaming pass cannot.

The prototype skips what a real change must keep, and 11 of the 2,290 link tests fail
on it for that reason: the failure group when reading the source fails, the link's
metadata on the filled file, the recorded-size refusal, `OnError.STOP` ordering, and
three tests that reach into the reservation code (`_folds_case`, the orphan pass close).

The fuzzer compares runs with each other. It cannot see a mistake that all runs make.
The first open supersede gap (`sym s -> e`, `hard s/X`, `sym s -> f`, `hard s/X`)
is one: the made run leaves the superseded `e/X` on disk. That needs an oracle (§5.1).

## 4. The corner-case classes

| # | Class | State | What closes it |
| --- | --- | --- | --- |
| H1 | Hard-link target rules: earlier member only, chains, refused sources, links to symlinks | Closed (#632, #666, #1598) | |
| H2 | Held link keeps its name in archive order (ERROR/SKIP/RENAME/REPLACE, case variants, two held links of one name) | Closed for names (#1371, #1598); fuzzer still finds mismatches | Placeholders (rec. 1) |
| H3 | Held link's parents (a later member at a parent, a held link under a held link, REPLACE of a directory that holds only held links) | Open on `main`; #1616 in review; fuzzer still finds mismatches on its head | Placeholders |
| H4 | Held link meets a non-current (superseded) member of the same name | Open (second supersede gap) | Placeholders |
| H5 | Materialize failures: group when the source read fails, the link's own destination fails alone | Closed (#938) | Placeholders make it simpler: a destination fails in the first pass, at the link |
| L1 | Member written through the run's own symlink; the symlink later re-pointed, replaced or superseded | Partly closed (#1616 `_run_wrote`); first supersede gap open | Leaves (rec. 2) |
| L2 | Held link spelled through the run's own symlink (pins, physical keys) | Closed by #1616 | Leaves |
| L3 | Symlink made escaping by a later member (threat model O22) | Closed (#516, bounded by `max_entries`) | Unchanged: link targets still resolve through other links |
| L4 | Rooted targets under TRUSTED | Closed (#1521) | Leaves simplify the spec text: a member under such a link is refused for the same reason as under any run link |
| L5 | Windows: two link kinds, privilege, junctions | Closed (#778, `_settle_link_kinds`) | Not fuzzed (Linux) |
| O1 | Overwrite policy against links and directories (REPLACE of a non-empty directory, RENAME numbering) | Closed for made links | Placeholders reuse it for held links |
| O2 | Case folding and Unicode normalization of names | Closed (#109, #955); held links via `_folds_case` | Placeholders: the filesystem decides, as for a made link |
| S | Streaming: a hard link whose source has no written copy (excluded, failed, skipped, superseded, replaced) | Excluded: accepted exception. The rest: open, every streaming mismatch | D3 |
| S1 | Streaming: link to the earlier copy of its own name (`file c`, `hard c -> c`) | Open. The earlier copy is still on disk (parked) when the link arrives | Small fix: link against the parked copy |
| X1 | Cross-format link rules: ZIP data-stored targets, RAR file copies, CPIO data on the last link, RPM inode sets, deb symlink redirect | Closed per reader | Not fuzzed: the coordinator is shared, so the TAR fuzzer covers it; reader rules need their own generators |
| X2 | Dry run against a real run | Closed: 0 mismatches | |
| R1 | Work bounds: many links, many rechecks | Closed (#1361, recheck cap) | |

## 5. Approaches

### 5.1 Plan then write (a model of the tree)

Keep one in-memory model of every path the run touches: type, owner result, physical
identity. Decide every member against the model, then execute on disk. A held link is
then a model node that waits for its bytes, so held and made parity holds by
construction, and streaming builds the same model one member at a time.

**Against it as the implementation:** the model has to agree with the filesystem it
replaces: case folding and normalization (macOS, Windows, case-insensitive mounts),
names the filesystem refuses, and what the caller had there before. Each disagreement
would be a new class. Placeholders get the same parity with the filesystem as the model.

**For it as a test oracle:** a model of the spec of about 200 lines, case-sensitive and
POSIX only, would catch what differential fuzzing cannot: a mistake every run makes
(the first supersede gap). Recommended as a later step, written by a session that has
not read `extraction.py`, so it does not copy the implementation's reading of the spec.

### 5.2 Placeholders for held links (recommended)

At the link's place, the first pass runs the normal FILE path with empty data:
collision, overwrite policy, parents, claim, result `EXTRACTED`. Later links to the same
excluded source are hard links to the placeholder, as they would be to a written source.
After the pass, for each source with a placeholder that still has a name on disk, the
source is read once, written to a temp file, and moved onto each surviving name that
still has the placeholder's identity (device, inode); the link's metadata is applied
after.

- **Removes:** `reservations`, `_reserve_orphan`, `_meet_reservation`,
  `_reservation_at`, `_folds_case`, `_SecondPass.under`/`waiting_on`/`ready`/`by_key`,
  `_orphan_blocker`, the ordering backstop, and #1616's held-link additions. The second
  pass no longer needs an order: placeholders do not interact, because the first pass
  already settled every interaction.
- **Keeps:** the source refusal rules (H1), the recorded-size refusal, failure groups
  (one group per source read), the forward-only failure.
- **Costs:** an empty file at the link's name for the length of the run. A run that is
  killed leaves it empty (GNU tar has the same behaviour). A caller reading the tree
  during the run sees an empty file. A read-only mode is applied after the fill.
- **Atomicity:** each name is replaced by a rename, so no name holds half a file. Names
  are replaced one at a time, so a crash between two renames leaves some names filled
  and some empty.

### 5.3 The run's own symlinks are leaves (recommended)

A member whose parent path reaches a symlink created by this run is refused with
`FilterRejectionError`, under every policy, in both access modes. A symlink that was in
the destination before the run is followed as today (`tar -C`, `unzip -d`, a merged
`/usr`). A member at the symlink's own name meets the overwrite policy as today.

- **Who writes such archives:** an archive made from a real tree cannot have both
  `s -> e` and `s/x`: by default tar, zip (`-y`) and 7-Zip store the link and do not
  descend into it. The shape comes from appended or concatenated archives, from
  hand-built ones, and from attacks. Docker-style layers do this across archives, which
  is a different run.
- **Matches:** bsdtar (refuses by default), archivey's own deb reader (#1607).
  **Differs from:** GNU tar and Python `tarfile` with `filter="data"`, which write
  `s/x` into `e/x` (measured with GNU tar 1.35 and Python 3.13, 2026-11-17).
- **Removes:** the physical-versus-spelled split for the run's own links
  (`_Claim.physical` kept only for the caller's links, which the run never re-points),
  the invalidation of `resolved_parents` on every symlink change, `_run_wrote`'s
  physical comparison, and the L1/L2 rows. LinkWatch stays: a link's *target* can still
  resolve through other links, and a later link can still change that.
- **Needs:** a minor release (`needs-minor`), a CHANGELOG **Breaking:** line, the
  `safe-extraction` spec, `docs/extracting.md` and the threat model.

### 5.4 Directory descriptors (`openat`, `O_NOFOLLOW`)

Walk each path from a descriptor of the destination, one component at a time, with
`O_NOFOLLOW | O_DIRECTORY`, and create entries with `mkdirat`, `symlinkat`, `linkat`,
`renameat`. That makes rec. 2 a property of the system calls and removes the time
between check and write.

**Not now:** Windows has no `dir_fd` support in Python (`os.supports_dir_fd` is empty
there), so this means two code paths. The caller's own symlinks must still be followed,
so plain `O_NOFOLLOW` everywhere is wrong. The threat model puts a local process racing
the extraction out of scope and names this as the direction if that changes.

### 5.5 Defer all symlinks to the end of the run

GNU tar delays links with unsafe targets and puts a placeholder there. With rec. 2, no
member is written through a run link, so deferral adds no write safety. It would hold
a symlink's name with a placeholder (more of §5.2's costs) and move the escape check to
a model, because the targets are not on disk yet. It would let Windows choose the link
kind once instead of remaking links (`_settle_link_kinds`). **Not recommended.**

### 5.6 Planned single pass (an optimization, later)

When the listing is free (`members_report_if_available()`), find the excluded sources
of selected links before the pass, keep their bytes in the staging directory as the pass
reaches them, and fill each placeholder from there. That removes the second read of a
solid archive. It does not change any result, so it can come after the placeholders.

## 6. Decisions for the maintainer

**D1. Held hard links: placeholders instead of the reservation model?**
Recommended: yes. Build it on `main` as one deep-tier pull request and do not merge
#1616 or the follow-up for the two supersede gaps: the placeholder change closes the
second gap and #1616's held cases, and deletes #1616's code.
Other option: merge #1616 now for the patch release and replace it after.

**D2. Refuse a member under a symlink that this run created?** Recommended: yes,
`BLOCKED`, in the next minor release. It follows bsdtar and archivey's deb reader, not
GNU tar. Other option: keep writing through these links (GNU tar's behaviour), keep the
physical-path bookkeeping, and fix the first supersede gap on its own.

**D3. Streaming: a hard link whose source has no written copy left.**
Recommended: random access keeps recovering the bytes from the archive; a streaming pass
fails the link, as it already does for an excluded source. Name this exception in the
spec, and fix the sub-case where the earlier copy is still on disk (S1).
Other options: (a) a streaming pass keeps the bytes of every selected file that does not
land, in the staging directory, until the run ends. Then the two modes match, but under
`SKIP` over a full tree that writes the whole archive to staging. (b) Fail the link in
both modes, as GNU tar and bsdtar do ("Cannot hard link"). Then selecting the source
changes the result (the held run recovers it), against the ruling.

## 7. Order of work

1. The fuzzer as a Hypothesis test (no behaviour change; it fails on `main` today, so
   it lands with an `xfail` list that each later step shrinks).
2. Placeholders (D1), with the S1 fix.
3. Leaves (D2), in the next minor release.
4. The oracle (§5.1), then the planned single pass (§5.6) if a solid-archive benchmark
   shows the second read matters.

## 8. Outcome (2026-11-18)

- **D1** as recommended. The prototype's last mismatch was fixed too: held-back against
  made links gave 0 mismatches in 25,600 fuzz runs on #1620.
- **D2** under every policy, `TRUSTED` included. The scan of 82,635 release tarballs
  (tar-minefield, `tree.through-symlink`) found the shape in none. A run link is matched
  by device and inode, so a case variant or a name Windows trims is refused too. Only a
  member's own path is checked: a symlink's target may still go through a run link.
- **Physical-path bookkeeping stays** (§5.3 expected to drop it). A symlink the caller
  had in `dest` is still followed, and a later member can replace it with the archive's
  own link, so the superseded-copy take-back and the placeholder fill still need to know
  where a copy physically is.
- **The fuzzer did not become a standing test.** It was run by hand on #1620 and #1622
  and stays in `evidence/`.
- §5.1 (oracle) and §5.6 (single pass) were not started.
