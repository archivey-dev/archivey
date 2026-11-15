# Second-round performance review

Review the current `main` of archivey after the first performance round. Profile the Python
implementation and propose new, concrete improvements. Do not repeat merged, rejected or
planned work from that round.

The measured revision is `529d7fbbeabafac2edf28ccb00afb8ea8af09053`. The review must preserve
member enumeration, metadata, bytes, diagnostic behavior, typed errors and their timing,
limits, end-of-member over-run detection, concurrent reads and recoverable partial data.
Stored archive indexes must not justify skipping default-path decoding or verification.
Read `dev-docs/design-rules.md` before proposing structural changes.

Required coverage:

- ZIP listing and streaming reads of 4,000 small files.
- TAR listing of 20,000 small files.
- Streaming reads of 4,000-file `.tar.gz` and `.tar.xz` archives from paths and pipes.
- CAB and solid 7z reads of 4,000 small files.
- Reverse member reads after opening/listing 64 MiB `.tar.gz` and `.tar.xz` archives.
- Extraction of the 4,000-file ZIP into a temporary directory.

Use cProfile and a sampling profiler. Use warmed, deterministic Callgrind comparisons for
small effects where practical. Report per-member costs, proposed changes, equivalence
tests, corner-case costs, implementation size, risk and priorities. Supply rerun scripts
and experimental patches. Assess whether stream architecture is the remaining limit.

This review is a measurement report, not a completed implementation or a full correctness
audit. Follow the conventions in [the review index](../README.md). Scope and validation
limits are explicit in [SUMMARY.md](SUMMARY.md).
