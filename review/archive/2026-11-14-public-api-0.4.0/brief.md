# Public Python API consistency before 0.4.0

Requested by the maintainer and reviewed with Codex on 2026-11-14. The review
examined `main` at `733a1b63577915f3796267c35f88af5266c21d8a`.
[`api-consistency.md`](api-consistency.md) preserves the findings reported in chat.
[`SUMMARY.md`](SUMMARY.md) indexes them; [`QUESTIONS.md`](QUESTIONS.md) lists the
design decisions. Adding this report does not adopt its proposals or fix the code.

## Requested scope

Review everything exported from `archivey`, as listed in
`src/archivey/__init__.py`, and the API documentation under `docs/`, before the
0.4.0 release. Include `open_archive()`, readers and members, configuration and
limits, nesting through `open_archive(parent=)`, `FormatPolicy`, diagnostics,
`Verification`, and the exception hierarchy. Ignore the internal API.

Look for inconsistent naming, parameter names/order/defaults/types,
positional versus keyword-only arguments, booleans versus enums, surprising
defaults, loose or missing public annotations, sentinel conventions, inconsistent
return types and exceptions, unused public exceptions, and documentation drift.
Also identify choices a careful user would find surprising or that would become
harder to change after release. Exclude style nits and formatting.

For every finding, provide file and line references, quote both sides, explain
the user impact, propose a concrete change, and mark whether fixing it breaks
compatibility. Rank by user impact and distinguish uncertainty from evidence.

## Evidence and limitations

This was a source/API review with small Python probes using standard-library
fixtures. It was not a full commissioned deep-review baseline: no green full-suite,
coverage, ruff, pyrefly, or ty baseline was captured. The full suite and optional
accelerators were not run, and no three-dependency-configuration comparison was
performed. Static constructor-typing conclusions come from the signatures and
their documented conversion rules, not from executing a type checker.

Runtime probes covered gzip ratio limits, generator-based format policies,
report truthiness and slicing, operation boolean arguments, contradictory
accelerator settings, public annotation resolution, external trusted symlinks,
public source-capability queries, and the nesting-depth boundary.

The report is a snapshot of the cited revision, not a claim that every finding
remains open on a later `main`. No library behavior was changed during review.
