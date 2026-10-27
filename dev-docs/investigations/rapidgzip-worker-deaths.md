# Silent xdist worker deaths in the rapidgzip cut-stream tests

**Status:** cause found and fixed in archivey (the rapidgzip child turns off its own core
dumps). Confirmed on the GitHub runners (§5).

## 1. What CI showed

The main CI step (`pytest tests/ … -q -n auto`, `PYTHONFAULTHANDLER=1`, 60 s thread-method
timeout) lost a pytest-xdist worker with no output, only
`[gwN] node down: Not properly terminated`:

| Date | Run | Job | Test |
| --- | --- | --- | --- |
| 2026-10-02 | — | ubuntu py3.11 `[all]` | `test_accelerator_truncation_abort.py::test_a_large_cut_stream_delivers_what_the_standard_library_delivers[DEFLATE]` |
| 2026-10-03 | 37095139139 | ubuntu py3.13 `[all]` | `test_rapidgzip_resume.py::test_a_cut_stream_delivers_what_the_standard_library_delivers[Codec.GZIP-0.999-path]` |
| 2026-10-03 | 37096645613 | ubuntu py3.13 `[all]` | `test_rapidgzip_resume.py::test_a_cut_stream_delivers_what_the_standard_library_delivers[Codec.GZIP-0.999-file]` |
| 2026-10-03 | 37122014346 | ubuntu py3.11 `[all]` | `test_rapidgzip_resume.py::test_a_cut_stream_delivers_what_the_standard_library_delivers[Codec.GZIP-0.999-file]` |
| 2026-10-03 | 37126688179 | ubuntu py3.11 `[all]` | `test_rapidgzip_resume.py::test_a_bytes_source_cut_stream_matches_too` |

None of the PRs touched the decoders. The deaths are not specific to one Python version.

**The stall happens on every run.** In every main-step log read (green and red, py3.11,
py3.12, py3.13, `all-lowest`), one progress line, at 61%→62%, takes 68 to 150 s, where
every other line takes under 30 s. That is where `test_rapidgzip_resume.py` runs, and it
holds 21 expected child aborts (rapidgzip Bug 4). xdist hands that module's tests to all
four workers at once, so the whole run slows down, not one worker. Every death above
happened inside that line. A line's timestamp is when it ended, so its count of results
says nothing about whether the other workers were still running; the earlier reading in
`known-issues.md` ("the other workers kept finishing tests") did not hold.

## 2. What a death looks like under xdist

Measured with a toy test module, `-n 2`, `PYTHONFAULTHANDLER=1`:

- a worker that gets SIGSEGV prints `Fatal Python error: Segmentation fault` and every
  thread's stack, then `node down`;
- a test that runs past pytest-timeout's thread-method limit prints nothing but
  `node down: Not properly terminated`. SIGKILL looks the same.

CI printed nothing, so it was a timeout or a SIGKILL, not a native crash in the worker
(hypothesis 4 of the brief).

## 3. The mechanism

rapidgzip 0.16 aborts the child (SIGABRT) on every stream that ends early; that is why it
runs in a child at all. On Linux an abort writes a core dump. When `core_pattern` starts
with `|` (apport on Ubuntu, systemd-coredump elsewhere), the kernel pipes the core to that
program **whatever `RLIMIT_CORE` says**, and the dying process stays alive, with its pipes
open, until the program has read it. The parent is blocked reading the child's stdout, so it
waits for the whole dump.

With every core decoding, the child's address space is large. Measured on a 4-core
container, py3.11, rapidgzip 0.16.0, with `core_pattern` set to a program that only counts
the bytes:

| | Value |
| --- | --- |
| core size per abort | 3.8 GB on average over 84 aborts, 6.0 GB the largest |
| time per abort, the program only draining the pipe | 2.2 s on average, 4.1 s the most |
| `test_rapidgzip_resume.py`, serial | 17–20 s without a dump, 62–66 s with it |
| the same, `-n auto` | 10–11 s without, 22–23 s with |
| a program that holds a lock and takes 3 s per dump, `-n auto` | 112 s, slowest test 23 s |
| a program that waits 70 s, `[Codec.GZIP-0.999-file]` under `-n 1`, 60 s thread timeout | `worker 'gw0' crashed`, no output, at 61.6 s: the CI signature |

A real handler does more than drain the pipe: apport is a Python program, and
systemd-coredump compresses and stores the core. So the 61% stall on CI is what dumping 21
cores of several GB costs, and a test whose dump waits behind others crosses 60 s.

## 4. The fix

`rapidgzip_worker.py` calls `disable_core_dumps()` before it imports rapidgzip: a core
limit of 0 (a core file) and, on Linux, `prctl(PR_SET_DUMPABLE, 0)`, which makes the kernel
skip the dump entirely, piped or not. The child still ends with SIGABRT, so the parent's
reporting is unchanged. With the same counting program installed, no core reached it
(0 of 84 before), the module ran in 11 s under `-n auto` and 17–18 s serially, and the
70 s case passed in 3 s. Pinned by
`tests/test_accelerator_truncation_abort.py::test_the_child_writes_no_core_dump`. On a
Python built without `ctypes` the `prctl` step is skipped and the child runs on
(`tests/test_worker_scripts.py`).

A side effect: a non-dumpable process cannot be attached to by `gdb` or `py-spy`, nor its
`/proc` stacks or `wchan` read, without root or `CAP_SYS_PTRACE`. Nothing in archivey does either;
the one place it bites is the stress harness's own stack capture of a stalled child
(§6).

**The PPMd child gets the same.** `ppmd_worker.py` also exists to crash on hostile input,
and its core is about the size of the model the archive declares plus about 20 MB:
measured with the same counting program, 28 MB for a 16 MiB model, 280 MB for 256 MiB and
1.1 GB (1.1 s) for 1 GiB. `max_decoder_memory` allows 2 GiB by default, so a hostile 7z
could have every crashed member hand about 2 GB to the user's crash handler. It now calls
the same `disable_core_dumps()` (a copy, since neither worker can import the other;
`tests/test_worker_scripts.py` keeps the two the same), and the
1 GiB crash ends at once. Pinned by
`tests/test_ppmd_crash_isolation.py::test_the_child_writes_no_core_dump`. `unrar` and
`unar` are left alone: they are third-party programs that are not expected to crash, and
`PR_SET_DUMPABLE` does not survive `exec`.

## 5. On the GitHub runners

**The handler.** `ubuntu-latest` (4 CPUs, 16 GB, 3 GB swap) pipes cores to
systemd-coredump, which compresses and stores them:

```
core_pattern: |/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d
ulimit -c: 0
```

The core limit it passes is the literal 2^63, not `%c`, so `ulimit -c 0` makes no
difference. `systemd-coredump.socket` is active; apport is installed but inactive.

**Before and after, main CI step** (`ci.yml`, "Run tests", ubuntu `[all]` jobs):

| | Before the fix (runs 37095139139 to 37126688179) | After (run 37129260930) |
| --- | --- | --- |
| the 61%→62% progress line | 68–150 s on every job read | 0.2–1.5 s |
| largest gap between two progress lines | 68–207 s | under 9 s |
| the whole step | 295–431 s | 106–144 s |
| worker deaths | 4 in the last 10 runs | none |

**Stress workflow with the fix** (runs 37129260952 and 37134373725, py3.11 and py3.14):
0 failures, stalls, worker deaths or timeouts in 226 iterations:

- `serial`, `xdist`, `xdist_2x`, `contended` (4 CPU burners) and `file_mode_only`: 0 in
  200 (20 per scenario per Python);
- `suite_neighbours`: 0 in 20 (10 per Python);
- `main_step`, the whole main CI step under the 60 s thread-method timeout, as CI runs
  it: 0 in 6 (3 per Python), with the slowest test 10.7 s.

`coredumpctl` listed no rapidgzip core after them, only small cores (24 KB to 48 MB) from
tests that crash other processes on purpose. (The first run's `suite_neighbours` and
`main_step` iterations had all failed on one unrelated test, `test_benchmark_structural_gate`,
which needs `unrar`; the workflow installs it since.)

**Locally** (4 CPUs), without a pipe handler (`core_pattern` `core`, limit 0, so no core
either way), 0 failures, stalls or worker deaths in every scenario: `xdist` 0 in 106 (17
before the fix, 89 after), `xdist_2x` 0 in 60, `contended` 0 in 60, `file_mode_only` 0 in
30 (each `-file` case 10 times a run: 1,800 cut-stream reads), `serial` 0 in 26.

On py3.14 a cut stream sometimes kills the child with SIGSEGV instead of SIGABRT (2 to 6
in 60 children). Without the abort message that death classifies as `CorruptionError`,
but it still counts as a crash on the data, so the standard library takes over and the
caller gets its bytes and its `TruncatedError`, as the tests check.

**The serial step is gone.** `test_accelerator_truncation_abort.py` had run in its own
serial CI step since the first death on 2026-10-02. With the cause fixed it is back in the
main `-n auto` step (davitf, PR #570 review, decision D2).

## 6. The harness

`scripts/rapidgzip_resume_stress.py` runs the module, or the whole main step, in a fresh
process group per iteration, under named scenarios (`serial`, `xdist`, `xdist_2x`,
`contended`, `suite_neighbours`, `file_mode_only`, `main_step`). A plugin logs each test's
start and finish and each child's spawn, death and return code. When a test runs past
`--stall` seconds, it captures the stacks of the worker and of every process under it
before anything is killed. The rapidgzip and PPMd children are not dumpable (§4), so for
them `wchan` (it reads `0`), the task stacks, `gdb` and `py-spy` all need root or
`CAP_SYS_PTRACE`; without either, only `/proc/<pid>/status` is left, whose `State` line
shows that a child sleeps, not where. `.github/workflows/rapidgzip-resume-stress.yml` runs it on ubuntu py3.11
and py3.14, monthly and on demand (its own scheduled workflow per davitf, PR #570 review,
decision D1); it is not a required check.
