# Finding the failing byte when a file is decoded again (2026-11-11)

On a source that can seek, a bounded read that meets a decoder error first hands back
every byte the decoder gives before it (`compressed-streams` §"A file gets every byte
before a decode error"). CPython's decoders drop the output of a call that raises, so
`DecompressorStream._redecode_to_error` restarts a decoder at the last seek point and
searches for the failing byte. Until this change the search asked for one output byte
per call over a window of up to 1 MiB. That costs about 1 µs per byte in process, and a
round trip per byte to a decoder child (PPMd, bzip3): about 0.1 ms here, and about 2 ms
under the fuzzing harness, where a damaged 7z took 2.3 s per read and a 1 MiB window
would take about 35 minutes.

Any search gives the same bytes: a probe of `k` bytes that gives all `k` moves the search
past them on the same decoder; one that raises says the error is in those `k` bytes, and
the decoder is then unusable, so the next probe needs a restart from the seek point and
a second decode up to where the search stands. A restart costs a child process start
(12 to 18 ms) and the decode from the seek point, which for a single-block xz or a
gzip without an index is the whole stream so far. So a failed probe is expensive and a
successful one is cheap, which is why halving is not the obvious best.

## What was measured

[`redecode-probe-strategies/bench.py`](redecode-probe-strategies/bench.py) builds a
damaged stream (16 random bytes written over the compressed data at a depth of 20 KB,
300 KB, 1.5 MB or 2.7 MB of output), reads it in loops of `read(4096)`, `read(65536)`
and `read(1 MiB)` through `open_codec_stream`, and swaps the probe-size function. It
reports the time over a run with the re-decode switched off, and the restarts and calls.
[`analyze.py`](redecode-probe-strategies/analyze.py) sums them. Codecs: gzip and xz (one
block and 256 KiB blocks) in process; PPMd8 and bzip3 (1 MiB blocks) in decoder children
under the default `ProcessIsolation.KNOWN_CRASHES`. Every strategy gave the same prefix
as one byte per call in every case. One Linux VM, 4 cores, CPython 3.11; repeat runs vary
by about 30% per case, so only large gaps mean anything.

Strategies: `rN` asks for `1/N` of the bracket the error is known to be in (`r2` is
halving), starting from the 1 MiB window; `gGrN` first grows the probe G-fold from one
byte until a probe raises, then splits at `1/N`; `L2048` asks for one byte per call over
the first 2 KiB and over any bracket no larger, then behaves as `g2r64`; `ski` steps one
byte per call while that has cost less than the last restart (timed), then `g2r64`.

## Results

Rounds 1 and 2, all three read sizes, total seconds over the 36 cases of each kind
(lower is better):

| strategy | in process | decoder child |
|---|---|---|
| r2 (halving) | 8.6 | 93.7 |
| r8 | 3.9 | 37.6 |
| r64 | 2.0 | 21.5 |
| g2r16 | 2.6 | 15.9 |
| g2r64 | 2.3 | 13.4 |

- Splitting well below the midpoint wins because it trades restarts for calls: halving
  restarted 376 times over the child cases, `r64` 85 times.
- Growing from one byte matters for bzip3: a damaged block fails as a whole, so the
  error is usually at the very start of the window. A one-byte probe that raises names
  the byte with no restart; `r64` paid four restarts there (0.5 s against 0.1 s).

Round 3 added the old search (`linear`, one byte per call) for the `read(4096)` and
`read(65536)` loops, where it finishes in reasonable time:

| strategy | in process | decoder child | worst case lost to the best, child |
|---|---|---|---|
| linear (before) | 0.80 | 13.2 | 4.6 s |
| g2r64 | 0.90 | 7.8 | 1.0 s |
| L2048 (chosen) | 0.69 | 6.8 | 0.4 s |
| ski | 0.73 | 6.2 | 0.15 s |

With `read(1 MiB)`, where the window is up to 1 MiB, `L2048` cost 0.03 to 0.13 s extra
in process against 0.16 to 0.32 s for one byte per call, and 0.2 to 2.4 s for PPMd and
bzip3, where one byte per call is one round trip per byte up to the error (tens of
seconds at 0.1 ms, about 35 minutes at 2 ms).

`L2048` was what `_redecode_probe` did until round 4 below.
`ski` was a little faster for the decoder children but chooses by the clock, so the
calls a read makes would vary from run to run; the gain is within the noise.

## Round 4: damage deep in the stream (2026-11-12)

A restart decodes from the seek point to where the search stands, so its cost grows
with how far the seek point lies behind the failing call: the whole stream so far for
PPMd, a one-block xz or a gzip with no index. The rounds above put the damage at most
2.7 MB deep. [`depth.py`](redecode-probe-strategies/depth.py) adds 3 MB, 30 MB and
100 MB, each at four offsets 260 KB apart so the damage falls at different places in a
read, with reads of 64 KiB and 1 MiB (24 runs per codec).

Strategies: `L2048` is round 3's choice. `K1024` widens its one-byte stretch to
max(2 KiB, restart bytes / 1024). Two outside derivations of the optimum for an error
spread evenly over the window agreed on `SQ`: one byte per call over a tail of
F + √(2F) bytes, F the restart cost counted in calls, probes of √(2n) for a bracket of
n otherwise, and one one-byte probe at the start for a decoder that fails a whole block.
`KSQ` adds a one-byte stretch of F at the start. F is 5 calls plus one per 1024 bytes
decoded again (150 calls plus one per 1024 for a decoder child); `KSQ-by-mode` uses one
per 100 bytes in process and one per 512 in a child, the costs measured here.

Extra seconds over a run with the re-decode switched off, summed over the 24 runs:

| codec | L2048 | K1024 | SQ | KSQ-by-mode | KSQ |
|---|---|---|---|---|---|
| xz, one block | 52.0 | 23.7 to 25.0 | 34.3 to 36.6 | 20.1 | 24.9 |
| gzip | 15.1 | 9.1 to 9.3 | 9.7 to 10.2 | 7.9 | 8.8 |
| PPMd (child) | 636 | 338 to 351 | 407 to 425 | 322 | 320 |

(Two runs; a range is the same strategy in both. `L2048` and `SQ`'s first figures are
from the first run, `KSQ` and `KSQ-by-mode` from the second.)

- The error is not spread evenly over the failing call's output: it sits in the first
  tens of kilobytes, as a call is fed at most 64 KiB of compressed input. That is why
  `SQ`, the optimum for an even spread, wins at 3 MB and 30 MB and loses at 100 MB,
  where its √(2n) probe past the error costs a 19 s restart for PPMd that `K1024`'s
  long first stretch avoids.
- `KSQ` keeps both: no worse than `K1024` anywhere by more than the noise, and about
  half of `L2048`. `KSQ-by-mode` is a little better in process but needs to know
  whether a decoder runs in a child; the gain did not justify that.

`KSQ` with 128 calls per restart for every decoder is what `_redecode_probe` does
(`_REDECODE_RESTART_CALLS`, `_REDECODE_BYTES_PER_CALL`). A third run of the same 72
cases with the library's own rule (`real` in `bench.py`) gave 25.3 s for xz, 9.2 s for
gzip and 313 s for PPMd, the same as `KSQ` in that run (25.7, 9.3, 314), with 40
restarts over the 24 PPMd runs against 50 for `K1024`. Every strategy returned the
same bytes in every run.

A decoder that hands out every byte before its error before raising it (bzip3, lzop,
`.Z`, the ZIP legacy methods: `Decoder.holds_back_errors`) is no longer decoded again
at all: the second decode found nothing more, and for bzip3 it decoded a whole block in
the child to learn it.

## Not done

- The gzip pipe path (`_KeepsOutputBeforeErrors`) still replays one byte per call from a
  `decompressobj.copy()`. Its window is at most 64 KiB in process, about 65 ms.
- A decoder child could run the search itself and answer in one round trip, which
  would make one-byte calls as cheap there as in process.
- A decoder snapshot at the failing call (zlib's `copy()`, a forked child) would make a
  restart free of the decode from the seek point.
