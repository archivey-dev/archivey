# Second-round performance review

## Outcome (evaluated 2026-11-15)

Every idea was checked against the code and measured again on current `main` in a separate
container (CPython 3.11, callgrind instructions per member from warm runs with GC frozen,
three-run minus one-run). The three small changes keep every byte, level, diagnostic and
error, and are implemented as separate PRs, held until after 0.4.0.

| Idea | Outcome | Measured here |
| --- | --- | --- |
| 1. Shared verifier proof records | Implemented, #1570 | ZIP 600,981 to 574,640 instructions/member (-4.4%); wall -1 to -2 µs/member, within noise |
| 2. Ratio room short-circuit | Implemented, #1571 | ZIP 600,981 to 589,481 instructions/member (-1.9%); the two conditions are equal for every input |
| 3. CAB checksum-presence summary | Implemented, #1569 | Small corpus: noise. 40,000 members over 1,283 blocks: 4.19 s to 3.33 s (-21%). The old scan was O(members × blocks), so the real gain is on large folders, not the 0.5-1 µs the report estimated |
| Checked-read driver (architecture) | Maintainer chose 2026-11-15: prototype after 0.4.0, kept only if traces match and it is faster; tracked internally | Not measured; no prototype |
| "What is actually fine" items | Agreed, nothing to do | Not re-measured |

The broader `proofs-experiment.patch` (shared `doubt_only()` records) was not taken: its
path did not show in the profiles.


The three changes worth pursuing are reusable verifier proof records, a short-circuit in
ratio allowance calculation, and a summary of checksum presence in CAB block tables.
The proof change has the strongest wall-time signal. The other two remove measurable work,
but their small wall-time advantages need confirmation on a quieter host.

This is the report of measurements made against
`529d7fbbeabafac2edf28ccb00afb8ea8af09053`, cloned from `main`. The proposals are prototypes,
not production changes in this PR. The original task is summarized in [brief.md](brief.md).
Scripts, patch application and test commands are in [REPRODUCING.md](REPRODUCING.md).

## Environment and method

- CPython 3.12.14, Linux x86-64, AMD EPYC 9V74, two-CPU container quota.
- Python dependencies installed with the development group and all extras. rapidgzip
  0.16.0 was available; archivey used its default AUTO selection.
- Baselines are medians of seven warmed runs, with `PYTHONHASHSEED=0` and
  `gc.collect(); gc.freeze(); gc.disable()` after warm-up.
- Small files: exactly 4,000 files, without separate directory entries, containing
  deterministic random payloads of 20-600 bytes. Total payload: 1,265,734 bytes.
- TAR listing: 20,000 USTAR entries, each with 32 data bytes. Large archives: 64 files
  of 1 MiB each, half random bytes and half repeated bytes per file. Payload is 64 MiB;
  TAR headers and padding are additional.
- CAB used the repository's checked MSZIP fixture writer because `gcab` was unavailable.
  The 7z archive used py7zr. These are not byte-identical to the first-round corpus.
- cProfile covered every required case. py-spy sampled repeated ZIP reads at 500 Hz
  (5,318 samples) and the full workload matrix at 300 Hz (10,309 samples). Sampling was
  of the parent Python process, not native work in rapidgzip's child.
- Callgrind used separate one-run and three-run processes, with the same warm-up and GC
  procedure. Subtracting their instruction totals and dividing by 8,000 gives the
  incremental instructions per member for the 4,000-file workloads.
- Candidate wall comparisons used 15 interleaved pairs. Final timing runs followed the
  instruction profiling rather than running alongside it.

Absolute times cannot establish what individual merges improved since round one. The
interpreter, machine, archive shapes and extraction filesystem differ. In particular,
extraction here used `/workspace`, not the first round's RAM-backed destination.

## Baselines

Times include reader open and close. Reverse reads also include listing before opening
members in reverse order. Extraction excludes temporary-directory cleanup.

| Workload | Members | Median microseconds/member |
| --- | ---: | ---: |
| ZIP listing | 4,000 | 10.35 |
| ZIP stream and read | 4,000 | 59.79 |
| TAR listing | 20,000 | 20.02 |
| tar.gz path, stream and read | 4,000 | 62.90 |
| tar.gz pipe, stream and read | 4,000 | 59.46 |
| tar.xz path, stream and read | 4,000 | 74.18 |
| tar.xz pipe, stream and read | 4,000 | 67.04 |
| MSZIP CAB read all | 4,000 | 49.76 |
| Solid 7z read all | 4,000 | 54.50 |
| 64 MiB tar.gz reverse reads | 64 | 3,144 |
| 64 MiB tar.xz reverse reads | 64 | 93,413 |
| ZIP extraction, excluding cleanup | 4,000 | 375.5 |

The ZIP read baseline ranged from 57.86 to 63.60 microseconds/member. Extraction excluding
cleanup ranged from 349.2 to 400.5. These spreads matter when assessing small changes.
The primary baseline script includes temporary-directory cleanup in extraction; its median
was 410.4 microseconds/member. The separate extraction-only timer in `final_extra.py`
produced the 375.5 figure above. Do not subtract the two medians to estimate cleanup cost:
they were separate timing series.

Same-host, same-fixture stdlib comparisons:

| Operation | archivey microseconds/member | stdlib microseconds/member | Ratio |
| --- | ---: | ---: | ---: |
| ZIP listing | 10.35 | 2.17 | 4.8x |
| ZIP read all | 59.79 | 10.41 | 5.7x |
| TAR listing | 20.02 | 14.32 | 1.4x |

Raw data: [baseline](results/baseline.jsonl), [additional measurements](results/extra.jsonl),
[cProfile summary](results/cprofile.json) and [sampling summary](results/sampling.json).

## Priorities

These are performance opportunities, not correctness defects. Status is proposed for all
three. None removes a check, synchronization event, lock, diagnostic or recovery step.

| Rank | Proposal | Paired wall measurement, microseconds/member | Instructions/member |
| --- | --- | --- | --- |
| 1 | Reuse verifier proof records | ZIP 67.52 to 61.83; 7z 57.39 to 55.07 | ZIP 586,631 to 555,438 |
| 2 | Short-circuit ratio allowance calculation | ZIP 66.00 to 65.32 | ZIP 586,631 to 576,859 |
| 3 | Summarize CAB checksum presence | CAB 49.64 to 48.83 | CAB 534,964 to 518,940 |

The instruction reductions in that pass were 5.3%, 1.7% and 3.0%, respectively. The ZIP
control was not repeated, so nothing here measures run-to-run variation; the 1.7% ratio
figure in particular is not separated from it. Trust the removed work rather than the
decimal precision of these counts. (The evaluation's own counts, in the Outcome table, were
a separate run.)
The savings are independent measurements and must not be added into a combined prediction.

The proof change won 14/15 ZIP pairs and 12/15 7z pairs. The ratio change won 10/15 pairs;
CAB won 9/15. Conservative planning estimates are 2-3 microseconds/member for proofs,
0.5-1 for ratio calculation, and 0.5-1 for CAB on this small corpus. Only the proof change
has a convincing wall-time signal in these measurements.

Evidence: [paired timings](results/paired-patches.jsonl) and
[instruction totals](results/instructions.json). The prototype patch names and their
relationship to the measurements are described in [REPRODUCING.md](REPRODUCING.md).

### 1. Reuse the eight possible verifier proof records

Location: `src/archivey/internal/streams/verify.py`, `MemberVerifier.proofs`.

This differs from the merged `_proofs_over` composition change. The verifier still builds
a frozen seven-field record every time it projects three Boolean state fields:

```python
return VerificationProofs(
    ended=self._ended_clean,
    content=self._digest_matched,
    content_possible=bool(self._expected),
)
```

cProfile counted 12,000 calls per 4,000-file ZIP or 7z read. ZIP's instrumented cumulative
cost was 19.9 ms. A separate CPU-time microbenchmark measured approximately 0.925 to
0.114 microseconds/call. Instrumented cumulative time is not an uninstrumented saving.

Construct an immutable table once, then return:

```python
return _VERIFIER_PROOFS[self._ended_clean][self._digest_matched][
    bool(self._expected)
]
```

The table contains all eight combinations, built with the existing `VerificationProofs`
constructor. See [the proposed patch](patches/verifier-proofs.patch).

Every synchronization still reads the verifier's current state. Nothing is cached per
member or skipped at open, EOF or close. Hashing, the over-run probe and the rule that a
read landing at the declared size ends the member stay intact. The shared records are
immutable, so this adds no synchronization requirement for concurrent reads.

Equivalence test: compare complete records against the original constructor for all eight
states. Pin the proof field set, so adding a field requires reviewing the projection.
Retain seek, damaged-data, encryption and verification-level coverage. This applies DR-5
and DR-23a without creating another read or validation path.

Corner cost: 1,096 bytes of permanent table objects on this CPython. There is no additional
per-member memory or I/O. The change is approximately 25-30 lines in one file. Risk is low;
the main maintenance risk is a future proof field omitted from the table projection.

The measured `proof8` prototype also shared `doubt_only()` records. That path was not
reached in the ZIP and 7z profiles used for the table's gains. The recommended patch omits
that extra change; [the exact broader prototype](patches/proofs-experiment.patch) is
retained for reproducibility, not as an additional recommendation.

### 2. Avoid an unnecessary ratio allowance calculation

Location: `src/archivey/internal/bomb_tracker.py`, `_RatioGuard.read`.

Replace:

```python
if n is not None and 0 <= n <= max(_GUARD_STEP, self._room()):
```

with:

```python
if n is not None and 0 <= n and (
    n <= _GUARD_STEP or n <= self._room()
):
```

`_room()` promises at least `_GUARD_STEP`, currently 1 MiB. For a smaller request, its
answer cannot change the selected branch. ZIP produced 8,000 `_room()` calls, including
the one-byte probes, with 12.9 ms instrumented cumulative cost.

The change eliminates those calculations. It does not eliminate `_check`, tally updates,
nesting accounting, refusals or source synchronization. The inner read sizes and check
order are identical. No archive-supplied index is involved.

Equivalence coverage must include requests around zero, 1 MiB and the allowance boundary,
unsized reads, held errors, live denominators, concurrent reads and ratio refusals. The
invariant that `_room()` is an allowance calculation rather than a state-changing check
must remain explicit. This preserves DR-5 and DR-9.

Corner cost: no additional allocation, I/O or retained memory. Large requests still
calculate the allowance. An extra comparison replaces the old `max()` call on that path;
no expensive fallback or changed chunk size is introduced. This is one changed expression
in one file, with very low implementation risk. See [the patch](patches/ratio.patch).

### 3. Record the first CAB block without a checksum

Locations: `src/archivey/internal/backends/cab_reader.py`, `_BlockTable`,
`CabReader._block_table` and `CabReader.open_member`.

Every member open currently slices and scans the block prefix again:

```python
all(block.checksum for block in table.blocks[: last + 1])
```

The 39-block benchmark cabinet produced 82,952 generator resumptions. The `all()` and
generator work consumed 15.3 ms under cProfile. Even an early missing checksum leaves the
prefix tuple allocation proportional to the endpoint.

While building the immutable block table, retain the position of its first block without
a checksum, or `None` when there is none. Query it in constant time:

```python
table.first_unchecked is None or last < table.first_unchecked
```

See [the patch](patches/cab-prefix.patch). Repeated prefix work changes from potentially
O(members times blocks) to O(blocks plus members).

This summarizes checksum presence, not checksum validity. The decoder still checks every
present checksum. The table's existing bounds, malformed-header refusal, truncated-table
behavior and source locking remain intact. No stored offset, size or index gains authority
to skip decoding or verification. A missing checksum lowers capability at the same member
open as before. This follows DR-5, DR-9 and DR-23a.

Corner costs must stay visible: 8-36 extra retained bytes per touched folder, depending on
whether an integer index must be retained, plus one condition per accepted table header.
A synthetic 65,535-header table benchmark found no detectable CPU regression: about 39.5
to 38.9 ms with checksums absent and 37.4 to 37.3 ms with them present. These small timing
differences are noise, not savings claims. That microbenchmark isolates table construction
and is not an end-to-end archive read. Its legacy `index_size` output describes the last
timed table, which can be the old implementation; it is not evidence for the memory delta.
The memory delta follows the additional tuple slot and retained integer.

The patch adds nine lines and removes two in one file. Risk is low-to-moderate: a wrong
prefix boundary could misreport verification capability. Publication remains under the
existing lock, with each immutable table carrying its own summary. The implementation
(#1569) makes `first_unchecked` a required field: `None` means every block is checked, so a
table built without the field must fail rather than claim full coverage.

I checked all 256 eight-block checksum-presence vectors at every endpoint. I also compared
42 public-operation traces across 21 clean, checksum-absent, checksum-damaged and truncated
archive variants, in both access modes. Member information, returned-byte hashes,
verification levels, diagnostics and exception traces agreed. The CAB test file passed
189 tests with nine skipped. See [trace results](results/cab-differential.json).

## What is actually fine

### Restart recording does not explain the whole path/pipe difference

Holding path access constant and toggling only internal restart recording gave:

| Recording off to on | Microseconds/member | Open only, microseconds/archive |
| --- | ---: | ---: |
| gzip | 69.43 to 70.08 | 751 to 746 |
| xz | 72.45 to 73.36 | 840 to 865 |

These clean-input differences are small relative to host noise. The xz block walker's
`feed` accumulated about 1.1 ms under cProfile on this corpus. The toggle is an experiment,
not a proposal to change the default or to make options produce different diagnostics.

cProfile counted four zlib copies on the indexed path versus 551 on the pipe. The pipe
copies support partial-data recovery, not restart points. This review does not propose
changing that recovery mechanism or re-enabling copies on affected PyPy versions.

### Reverse xz reads are dominated by decoding this archive's single block

The large xz fixture contains one block. Of 6.35 seconds under cProfile, 5.44 seconds were
inside liblzma decompression. Block restart points do not substantially help seeks within
that one block. This result justifies neither trusting its stored index nor decoder copies.

### Some unused-feature overhead is already avoided

`_budget_drawn` omits a counting-only wrapper when no byte cap needs it. `_listing_work`
appeared only two to four times per archive, not once per member, in these profiles.
Neither was a useful target here. The mandatory accounting is not proposed for removal.

### Extraction syscall removal needs a proof this review did not find

An extraction-only profile counted 21,048 `lstat` and 605 `stat` calls, or 5.41/member.
`_makedirs` already has a one-`lstat` common path. Destination checks examine a namespace
another writer can change, and the hard-link landing preserves refusal when a name becomes
occupied. I did not find a syscall I could prove redundant. No check is proposed for removal.

## Architecture

Shared stream machinery remains the main limit on these small-member workloads. In the
ZIP sampling profile, `_sync_member_level` occupied about 14% inclusive. Generated
constructors accounted for about 7% of leaf samples collectively. Listing, opening,
wrapping, ratio accounting, reading and closing split the rest. Inclusive shares overlap.

A larger experiment could put existing verifier state and ratio state behind one internal
checked-read driver:

```text
ArchiveStreamImpl
    -> checked-read driver
        -> existing verifier operations
        -> existing ratio and budget operations
        -> source or decoder
```

It must preserve the current per-chunk ordering, held-error behavior, hashing frontier,
over-run probe, diagnostic scope and open/read/close synchronization events. Source locks
remain at the shared source. Both public access modes use the same driver. The public API
and eager listing results stay unchanged.

This could remove wrapper objects and forwarding calls while sharing the actual checks,
as DR-14 and DR-23a require. Validate a prototype with operation-by-operation traces,
including interleaved concurrent reads, every limit boundary and damage before/at/after
member end. This structure has not been measured and has no assigned savings percentage.
The three small changes above come first.

## Validation and limits of the conclusions

Focused runs recorded 1,177 passes and 20 skips in total:

- Shared verifier, ratio, TAR, diagnostics, nesting and full-count tests: 711 passed,
  11 skipped.
- Format API, remote planner, differential TAR and verification-level tests: 277 passed.
- CAB tests with its prototype applied: 189 passed, nine skipped.

The first two groups ran with the shared experimental changes. The CAB run also applied
its source patch. The pytest plugin additionally enabled the unranked ASCII checksum and
range-validation experiments preserved in `experiments.py`; these are not recommendations.
That distinction matters when reproducing the recorded tests. These runs were not a green
full-suite baseline before the investigation. The full suite, all dependency configurations
and cross-platform gates were not run during measurement. Do not treat the report as a
completed correctness audit or the patches as merge-ready implementations.

Raw logs are retained under [results](REPRODUCING.md#evidence). No runtime source changes
are included in the report PR; patches are review artifacts. New performance claims should
be rerun against the revision where an implementation lands.
