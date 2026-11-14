# Decisions before accepting API changes

These are proposals for maintainer triage, not decisions made by this report.
The corresponding evidence and compatibility costs are in
[`api-consistency.md`](api-consistency.md).

Triage (2026-11-14): items 1 and 4 were settled by DR-9 and did not need the
maintainer. Item 1: `max_ratio` holds every decode, so `open_stream()` is guarded
(#1553). Item 4: the nesting depth is a structural bound with a comment and a spec
row, so it stays fixed and keeps `UnsupportedFeatureError`. Items 2 and 3 went to the
maintainer with a recommendation. davi chose: F3, raise on a truth test (#1559);
F7, widen the constructors with `Literal` lists of the spellings (#1560).

1. **F1:** Should `open_stream()` apply `DecoderLimits.max_ratio` like a member
   read, or should its exemption become an explicit documented contract? Applying
   the guard newly refuses some successful stream reads.
2. **F3:** Should all report objects reject implicit truth tests and expose explicit
   success/completeness helpers? Extraction and listing reports currently promise
   sequence behavior; changing their truthiness breaks callers using that behavior.
3. **F7:** Should constructor input types include every documented string/preset
   while fields keep their normalized types? The current narrower constructor
   annotations are intentional, as `config.py:1161` explains.
4. **F12:** Should nesting depth be a public, adjustable resource limit, and should
   reaching it raise `ResourceLimitError`? The current nine-reader bound and
   `UnsupportedFeatureError` are documented behavior. Adding a setting is additive;
   changing the documented exception is breaking.

F2, F4-F6, and F8-F11 propose contract corrections, documentation corrections, or
additive typing fixes. They still need implementation review and tests appropriate
to the eventual change. A finding being recorded here does not settle a conflict
with a specification or an existing design ruling.
