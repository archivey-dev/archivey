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

`L2048` is what `_redecode_probe` does (`_REDECODE_ONE_BYTE_SPAN`, `_REDECODE_SPLIT`).
`ski` was a little faster for the decoder children but chooses by the clock, so the
calls a read makes would vary from run to run; the gain is within the noise.

## Not done

- The gzip pipe path (`_KeepsOutputBeforeErrors`) still replays one byte per call from a
  `decompressobj.copy()`. Its window is at most 64 KiB in process, about 65 ms.
- A decoder child could run the search itself and answer in one round trip. With the
  search above, the round trips are no longer the cost; restarts are.
