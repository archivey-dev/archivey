# Brief — pre-release bug sweep for 0.3.0

Commissioned 2026-11-04 against `main` @ `f3d1b616`. Conventions inherited from
[`../README.md`](../README.md). Not repeated here.

## The ask

Find real bugs and inconsistencies before the 0.3.0 release. Do not change library
code. Leave a test for each bug, marked `xfail(strict=True)`, that asserts the
correct behaviour. Leave a passing test for a behaviour that was checked, works,
and had no test.

The spec is `dev-docs/design-rules.md`, then the user docs under `docs/`. An
intentional, documented decision is not a bug. A decision that looks wrong is
listed under disagreement, with no test.

Look in this order:

1. Correctness: wrong data or member metadata, crashes or unexpected exception
   types on malformed input, resource leaks, wrong behaviour after a seek or a
   partial read.
2. Safety: path traversal on extract, symlink and hard-link escapes, resource
   limits applied differently across formats.
3. The same situation handled differently across format readers, or streaming
   extraction writing a different tree from a random-access extraction.
4. `verify()`, `verify_all()`, and `verifiable`, against what each format checks.
5. Documented parameters, defaults, exceptions, diagnostic codes, or behaviour
   the code does not match.
6. Diagnostic codes emitted but missing from `DiagnosticCodeStr`, or listed and
   never emitted.

Skip style, refactors, and performance unless the cost blows up.

## Out of scope

Fixing the library. Editing `CHANGELOG.md`. Filing a style or performance nit.
