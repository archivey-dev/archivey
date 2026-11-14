# Public API consistency review before 0.4.0

Reviewed `main` at `733a1b63577915f3796267c35f88af5266c21d8a` on 2026-11-14.
The review recommends resolving the ratio-protection discrepancy and the iterable
policy bug before release. Other findings cover error contracts, documentation,
typing, and deliberate design choices that deserve an explicit decision.

All findings remain proposals pending maintainer triage. Confidence in observed
behavior does not imply that a proposed API design is the only correct choice.
Full evidence and compatibility qualifications are in
[`api-consistency.md`](api-consistency.md).

| Rank | ID | Severity | Finding / where | Status | Compatibility of proposed fix |
| --- | --- | --- | --- | --- | --- |
| 1 | F1 | Important | Ratio protection differs between opening APIs; `core.py:1305` | Behavior confirmed; intent unclear | Breaking to fix |
| 2 | F2 | Important | Library-policy generators are consumed twice; `format_policy.py:152` | Confirmed bug | Non-breaking contract correction |
| 3 | F3 | Important | Report truthiness differs; `diagnostics.py:1782` | Confirmed behavior; design recommendation | Breaking to fix |
| 4 | F4 | Important | Operation booleans accept truthy strings; `core.py:593` | Confirmed for three opening flags | Non-breaking invalid-input rejection |
| 5 | F5 | Important | Policy reference overstates external-link rejection; `types.py:1895` | Confirmed documentation conflict | Non-breaking |
| 6 | F6 | Important | Config conflicts miss the ValueError contract; `config.py:1224` | Confirmed | Non-breaking |
| 7 | F7 | API friction | Documented constructor inputs fail the type contract; `config.py:844` | Intentional; reconsideration proposed | Non-breaking |
| 8 | F8 | Documentation | Pipe-capable format list is stale; `core.py:548` | Confirmed against public capability queries | Non-breaking |
| 9 | F9 | Documentation | Forward-only stream promises no accelerator; `core.py:1274` | Confirmed contradiction | Non-breaking |
| 10 | F10 | API friction | Public annotations fail runtime resolution; `format_policy.py:467` | Confirmed | Non-breaking |
| 11 | F11 | API friction | Report slicing works but is incorrectly typed; `diagnostics.py:1785` | Confirmed | Non-breaking |
| 12 | F12 | Design concern | Fixed nest depth and its exception category; `core.py:662` | Confirmed behavior; inferred concern | Breaking exception change |

Severity here ranks user impact rather than declaring release blockers. The
original request excluded style nits. Compatibility labels treat corrections to
documented input contracts as non-breaking, while noting migration-sensitive
behavior in each finding.

## Triage (2026-11-14)

Checked against `main` at `c3bfd214`. A cold review of this report (round 1 on #1550)
reproduced eleven findings; F9 needs rapidgzip absent, and the code path is plain from
`config.py`. Each finding's status is under its heading in
[`api-consistency.md`](api-consistency.md).

| ID | Outcome | Where | 0.4.0 |
| --- | --- | --- | --- |
| F1 | Fixed (DR-9 settles it) | #1553 | Yes: behaviour change |
| F2 | Fixed | #1554 | Yes |
| F3 | Maintainer decision | pending | If changed, yes: breaking |
| F4 | Fixed (reverses a spec sentence) | #1554 | Yes: behaviour change |
| F5 | Fixed (docs) | #1556 | Yes |
| F6 | Fixed | #1554 | Yes |
| F7 | Maintainer decision | pending | Either way, non-breaking |
| F8 | Fixed (docs) | #1556 | Yes |
| F9 | Fixed (docs) | #1556 | Yes |
| F10 | Fixed | #1555 | Yes |
| F11 | Fixed | #1555 | Yes |
| F12 | Won't fix (DR-9 structural bound) | — | — |

## What is actually fine

- The separate `ArchiveyUsageError` root is deliberate and documented. This review
  does not propose making it a subclass of `ArchiveyError`.
- `seekable_members` versus `open_stream(seekable=...)` reflects member streams
  versus the one returned stream. Concurrency has no single-stream counterpart.
- `FormatPolicy.only`/`exclude` and compression-algorithm exclusions have distinct,
  documented scopes. A whole-file compression and a member codec are not interchangeable.
- `Verification` and the verification methods/reports are explicitly experimental.
  The report preserves that qualification when discussing their consistency.
- `ExtractionLimits.max_entries` and `ListingLimits.max_members` bound different
  operations. This review does not propose merging them merely to align names.

## Validation

See [`brief.md`](brief.md) for the probes and the checks not performed. This report
does not assert a green test baseline or optional-backend parity. The source links
in the findings are pinned so later code changes do not invalidate their locations.
