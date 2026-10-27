# 0022 — Every PPMd member decodes in a child process

- **Status:** accepted (implementation pending, with the native-decoder isolation change)
- **Date:** 2026-10-20
- **Supersedes:** the in-process rule of the `ppmd-crash-isolation` change (2026-09-26,
  PR #481): members up to `DecoderLimits.max_ppmd_in_process_input` (16 MiB of compressed
  input) decoded in this process
- **Provenance:** `openspec/changes/archive/2026-09-26-ppmd-crash-isolation/proposal.md`;
  `dev-docs/known-issues.md` §"Intermittent `pyppmd` native aborts on PPMd streams";
  `dev-docs/investigations/ppmd-native-investigation-results.md` §I, §K.3, §K.4
- **Amended (2026-10-22, PR #1007):** `max_ppmd_in_process_input` is kept, renamed
  `max_ppmd_held_input` with no alias. It still bounds the member that is held and
  handed to pyppmd whole, under every `process_isolation` value, so the old name, which
  tied it to decoding in this process, no longer fit. The text below keeps the old
  spelling where it records what existed on 2026-10-20.

## Context

pyppmd, the only PPMd decoder for Python, corrupts its heap in ways that kill the whole
process: SIGSEGV or SIGABRT on Linux, `STATUS_HEAP_CORRUPTION` on Windows. Two routes are
known. A decode that asks for more output than the stream holds frees a buffer that its
worker thread still writes to. A model that has ended early, which random bytes reach (a
wrong password, a crafted member), segfaults when it is asked to decode again. Nothing in
pyppmd's Python interface separates "the model ended" from "the worker waits for more
input". Both set the same flags. Upstream has no fix.

## The previous decision (2026-09-26)

archivey kept PPMd in this process for members up to 16 MiB of compressed input and used a
child process only above that. Inside the process it followed a discipline meant to keep
pyppmd out of both routes: it held the whole member, handed it to pyppmd in one call,
bounded every output request by the remaining size, and stopped at the first short
return. Before freeing a decoder whose worker was still parked, it sent one single-symbol
decode to finish the worker (the "quiesce" step), because freeing a parked worker was the
use-after-free that valgrind pinned.

The reasons were:

- **The discipline looked complete.** Every shape measured at the time ran clean under it,
  and valgrind reported no errors on archivey's own call sequences.
- **A child per member was expensive.** The `max_ppmd_in_process_input` docstring
  (`src/archivey/config.py`, from PR #481) puts the PPMd child's start-up at about 75 ms
  and its pipe at about 450 MB/s, compressed input in and decoded output back. That
  start-up is small beside a 16 MiB member, which takes seconds at pyppmd's 2 to 8 MB/s,
  but it dominates a small one. Only for large members did the memory of holding the
  whole input outweigh it. A re-measurement on 2026-10-20 (the PPMd child on main, Linux,
  CPython 3.11; numbers in PR #905's description) gave the same picture: decoding every
  member in a fresh child was 70 to 154 times slower on archives of 1 KB and 30 KB
  members, and 1.1 times on two 20 MB members.
- **Isolation was reserved for crashes that could not be avoided.** The rapidgzip DEFLATE
  abort was one. Native code alone was not a reason to pay for a process boundary. In the
  terms of [DR-20](../design-rules.md#dr-20-parse-in-python-isolate-native-code-that-can-crash)
  ("a codec with known crashes runs in a child process or is designed around"), PPMd
  below 16 MiB took the "designed around" branch.
- **`multiprocessing` was ruled out.** Its spawn mode re-imports the caller's `__main__`,
  and it reports neither stderr nor the exit status. A child had to be a plain subprocess
  running a standalone worker script, which kept the child code small and per codec.

## What changed (2026-10-20)

- **The discipline holds only by measurement, and one call separates it from a crash.**
  A re-measurement on 2026-10-20 (`scripts/pyppmd_crash_repro.py` in PR #905) found no
  crash on archivey's own call order: crafted members with an overstated `unpack_size` ran
  clean in 860 fresh children and under valgrind, and archivey's teardown order crashed 0
  of 100 children. But the margin is thin. When a member ends early, the quiesce step is
  itself a decode after the end; a spy saw it on 183 of 200 hostile 7z members. It stays
  safe only because pyppmd happens to stop that call at once. One more decode after
  pyppmd has raised `ValueError` crashed 59 of 100 children for PPMd8 and 5 of 100 for
  PPMd7, and archivey avoids it only because `_quiesce_worker` returns early on the state
  pyppmd reports after the error. Leaving the quiesce step out brings back the
  use-after-free it exists to prevent. Two candidates for an in-process crash stay open:
  the quiesce decode after an early end, and empty drains on a member that is declared
  complete but corrupt. Since pyppmd does not expose the state that would make a call
  sequence safe by construction, the in-process path rests on test results, not on a
  rule that can be checked. `known-issues.md` describes the remaining risk as an
  oversized `unpack_size`; measured, that shape is the free-while-parked route, which
  quiescing already handles. PR #905 corrects that entry.
- **A child no longer costs a process start per member.** The native-decoder isolation
  design takes children from a pool of reused idle children. In its prototype (Linux,
  CPython 3.11, a child that imports only `struct` and `sys` until it is asked for a
  codec; the prototype report is tracked internally, and the figures are restated in the
  design of PR #904), a small member on a reused child cost about 30 µs, against 12 to
  18 ms to start a fresh one.
  The 75 ms figure above includes importing pyppmd and the older per-codec worker.
- **The protocol is no longer per codec.** One shared child protocol now serves every
  native decoder, so moving PPMd onto it adds no new copy of the child code.
- **One rule is easier to state than a threshold.** "PPMd always decodes in a child" needs
  no explanation of a 16 MiB split, of the memory held below it, or of when the split moves.

## Decision

By default every PPMd member decodes in a child process taken from the pool, whatever its
size. This is DR-20's "runs in a child process" branch, since "designed around" is not
reachable from Python for pyppmd. A crash costs that member and becomes an archivey
error, as above the threshold today.

Password confirmation follows the same rule. It decodes a PPMd member under each
candidate key, and a wrong key turns the member into exactly the random input that
reaches pyppmd's crash routes, so it is the path most likely to need the isolation.

The planned `ProcessIsolation.NONE` setting, whose name lands with the native-decoder
isolation change, keeps PPMd in this process as a risk the caller accepts: for speed, for
tests, or where processes cannot be started. The docs will discourage it.

Reuse must not move the blame. pyppmd's damage is heap corruption, which can surface
later, while the same child decodes another member. So a child goes back to the pool only
after a clean finish: its member decoded to the declared end, the stored CRC matched, and
the decoder closed normally. Any error, early end or refused member retires it, and so
does a read the caller stops early: freeing a worker that may be parked needs the quiesce
decode, which is itself one of the suspect calls. A crash in a child that had already
served other members is not charged to the current member while none of its output has
reached the caller: that member runs again once in a fresh child, and only a crash there
becomes its error. Once output has reached the caller, a rerun would have to restart the
stream; whether it does is settled with the isolation change (PR #904). A member that
crashes every time decodes twice before it reports. A crashed child is never reused, and
children are recycled after a fixed number of decoders.

## Consequences

- Each request to a pooled child is a pipe round trip. A small member takes three (open,
  decode, close), about 30 µs together in the prototype; a large member read in bounded
  chunks takes one more per chunk. On top of that comes the cost of copying data through
  the pipe. The prototype measured
  0.5 to 0.8 ms per MiB of decoded output alone; the PR #481 docstring's 450 MB/s (about
  2.2 ms per MiB) counts compressed input and decoded output together. The 30 µs is the
  round trips alone. Measured end to end on the shipped pool (2026-10-22,
  `scripts/bench_process_isolation.py`), a non-solid PPMd member costs about 1.4 to 2 ms
  more than in-process, so another term dominates. Part of it is the pool's own
  recycling: a child is retired every 64 decoders (`MAX_DECODERS_PER_CHILD`), about
  0.2 ms per decoder at the start cost below. The rest is not traced (decoder
  construction is the likely term). A solid folder is one decoder and pays that once.
  `ProcessIsolation`'s docstring carries the current figures.
- The pool saves a process start only after a clean finish. A password-confirmation probe
  stops at its budget (64 KiB of plaintext, 1 MiB of input) or on a wrong key, and a read
  the caller abandons stops early too, so each of these retires its child and the next
  member pays a fresh start: 12 to 18 ms, plus importing pyppmd. Confirming three
  candidate keys on a large PPMd member costs three fresh children.
- `max_ppmd_in_process_input` loses its role under the default. Whether it is removed,
  renamed or kept for `NONE` is a public-name change. It is decided with the isolation
  change, not here. `DecoderLimits.UNLIMITED` changes meaning with it: it sets the field to
  `None`, which today also guarantees that no child process starts, and under the new
  default a PPMd member starts one anyway.
- Every statement of the current rule changes with the implementation: the 16 MiB split,
  "a PPMd member over the threshold decodes in a child", and "a password check runs
  in-process", wherever it appears in `openspec/specs/`, `docs/`, `dev-docs/`, `src/` or
  `tests/`. Grepping `max_ppmd_in_process_input` finds them. Examples on 2026-10-20:
  - `openspec/specs/archive-reading/spec.md`: the `max_ppmd_in_process_input` SHALL rows
    (a member over it decodes in a child), its 16 MiB default and the matching scenario
    row;
  - `openspec/specs/format-zip/spec.md`: the bit-3 PPMd SHALL row and its scenario;
  - `docs/formats.md`, on the bit-3 PPMd member and the 1 MiB confirmation;
  - `dev-docs/threat-model.md`, the child-process list and its "Residual" paragraph;
  - the field docstring in `src/archivey/config.py`, including "a password check ... always
    runs in-process";
  - the "Why the split at 16 MiB?" note in `docs/security.md`;
  - `dev-docs/known-issues.md`, "What archivey does" under the pyppmd entry;
  - `dev-docs/formats/zip.md`, on the bit-3 PPMd member that always decodes in a child;
  - the test files and scripts that pin the threshold (nine files on 2026-10-20).
- An environment that cannot start a process, such as a frozen application, already gets
  `ResourceLimitError` for PPMd members over the threshold. Under the new default this
  applies to every PPMd member unless the caller picks `NONE`.

## What would reopen it

- **A pyppmd release that fixes both routes.** It must pass the verification checklist in
  `ppmd-native-investigation-results.md` §J, on Linux, Windows and a free-threaded build.
- **A way to tell the two worker states apart from Python.** With that, the quiesce step
  could run only when it is safe.
- **A pooled child that costs much more than measured.** For example, if per-member cost on
  Windows comes out near a fresh process start.
