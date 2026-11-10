# 0003 — Member streams opt-in (non-seekable, single live stream by default)

- **Status:** accepted
- **Date:** 2026-07-11
- **Provenance:** OpenSpec change `concurrent-member-streams` (proposal + design);
  PRs promoting `MemberStreams`; `docs/access-and-cost.md`

## Context

Seeking inside a compressed member and overlapping opens are format-dependent traps
(O(n) rewinds; decoder thrash on compressed TAR; solid re-decode). An unconditional
“always seekable / always concurrent” API lets developers test on ZIP and ship a footgun
on TAR/7z. Cost receipts alone are too passive (warnings deferred).

## Decision

Both capabilities are off by default:

- streams report `seekable() is False`; `seek()` → `io.UnsupportedOperation`
- at most one live member stream; a second overlapping `open()` → `ArchiveyUsageError`

Opt in with `open_archive(..., seekable_members=True, concurrent_operations=True)`. Same
rule for `open_stream(..., seekable=False)`. Seek indexes / accelerators are
**demand-driven**. Uniform across every format, including directory.

**Amended before `0.2.0`:** the opt-in was originally spelled
`member_streams=MemberStreams.SEEKABLE | MemberStreams.CONCURRENT`. The decision above
is unchanged — same defaults, same errors, same semantics — but the two entry points now
share one vocabulary (`seekable` means the same thing in `open_archive` and
`open_stream`) instead of splitting a flag enum against a bool. This is what ADR 0004
already chose in the analogous case: prefer a bool when the mode count is small, and
these are two specific traps rather than an open-ended set. `MemberStreams` remains
exported and is still the declared-capability value on `CostReceipt` and in diagnostics.

**Amended (PR #299):** `seekable_members=True` is a guarantee on random `open()`, not
"where the backend can provide it". A backend that can list a file member must seek it
when the flag is set; loud-slow-rewind is allowed. `stream_members()` stays a
single-pass decode — SEEKABLE does not require those handles to seek. The original
decision (off by default, demand-driven indexes) is unchanged.

**Amended (2026-09-26, davitf):** a `stream_members()` handle never seeks, on any
format, with or without `seekable_members=True`: `seekable()` is `False`, `seek()`
raises `io.UnsupportedOperation`, `tell()` works. Before, whether a pass handle could
seek depended on the backend. `seekable_members=True` is for random `open()` only.

**Amended (2026-10-17):** after the `member_streams=` flag enum gave way to the two
booleans, the second was spelled `concurrent_members`. It became `concurrent_operations`
once it covered more than member opens: under it every operation on the reader (open,
read, passes, `extract_all()`) works as if it ran on a reader of its own. Same default,
same semantics otherwise.

**Amended (2026-11-10, davitf, PR #1489):** the codec stream around a sequential
container (a compressed TAR, or a sequential format inside a compressor such as
`.cpio.xz`) opened for random access keeps restart points by default
(`StreamConfig.restart_points`): the reader itself seeks back in that stream for every
member read after the listing, so the table is never unused there. It costs about
40 KiB per MiB of gzip output, capped at 32 MiB. It declares no seek demand, so
accelerator `AUTO` resolves as before, and member streams stay as `seekable_members`
says. A streaming open keeps none.

## Consequences

- Default path: no shared-handle locks, no seek tables, no accelerators, except the
  restart points of a random-access compressed TAR's codec stream (amendment of
  2026-11-10).
- Strict default is reversible pre-1.0; permissive-then-gate would be a breaking change.
- Solid **open-order** cost remains the caller’s algorithm (`AccessCost` /
  `stream_members()`), not something `concurrent_operations=True` erases.
