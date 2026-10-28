# Benchmark gate — sample results

**Blocking PR gate = structural invariants only** (seek-count baselines + solid
decode-once). Wall-time / VISION ≤1.3× runs off the PR path as a **change-guarded
nightly** (`benchmark-wall.yml`): a daily schedule whose expensive realistic run
fires when the default branch changed recently **or** the last measurement is
older than ~30 days (runner / toolchain drift). Quiet days **re-publish** the
previous JSON (preserving `measured_at`, stamping `republished_at`) so dormant
successes still carry an artifact for the next drift compare. When the expensive
run fires it:

- records results (JSON + markdown report artifacts, job summary table) with
  `measured_at` / source provenance;
- hard-fails on the ~10× sanity ceiling **or** on **wall-ratio drift** vs the
  JSON of the last run that measured, pass or fail (relative regression gate —
  debt-ledger Q1 / perf Q2 option (a)). A case drifts when its ratio rises to
  more than 1.25× the baseline ratio **and** by at least +0.15 in absolute terms
  **and** the rise costs ≥1 ms of wall time at this run's stdlib speed, so
  sub-millisecond listing cases do not fail on timer noise. Because a failed run's
  JSON becomes the next baseline, a real regression fails the first night that
  measures it and not every night after;
- prints absolute VISION / Q1 listing bands as informational only.

**Maintainer decision (davitf, 2026-10-10, #655):** compare against the last
measured run, pass or fail, and add the 1 ms floor. This supersedes the
"previous successful nightly" baseline of performance review Q2 (decided
2026-07-20). Reasons: on 2026-09-07 one sub-millisecond case failed on timer noise
(`rar_open_list`, 1.0 ms vs a 0.2 ms peer, 2.60× → 5.71×). With a successful-only
baseline that one night froze the 2026-09-06 numbers until 2026-10-09, and every
later change added up against them until each measured night failed. The cost: a
real regression is red for one night, then becomes the baseline unless someone
acts on that night's failure. Reopen if a regression is accepted that way without
anyone seeing it, or if a sub-millisecond case shows a real regression the 1 ms
floor hides.

`workflow_dispatch` can pass `skip_drift=true` to accept the current ratios as a
new baseline after an intentional slowdown.

Re-run with:

```bash
# PR structural gate (small fixtures, fast)
uv run --extra all python -m benchmarks.harness --mode structural --scale ci

# Realistic wall-time vs stdlib (multi-MiB corpora; interleaved medians)
uv run --extra all python -m benchmarks.harness --mode full --scale realistic
```

## 0.2.0 release figures (2026-10-21)

The figures quoted in the 0.2.0 CHANGELOG entry. Source: `benchmark-wall.yml` run
39544292797 (`workflow_dispatch`), `measured_at` 2026-10-21T04:30:48Z, `source_sha`
`de8a65654e35`, GitHub `ubuntu-latest` (4 vCPUs), Python 3.11, `--mode full --scale
realistic --warmup`. Corpus: 64 × 256 KiB members, 32 MiB gzip; 7z listing 10 000 solid
tiny / 1 000 non-solid members; RAR listing 1 000 / 256 members, the committed ci-scale
fixtures, because the nightly has no `rar` writer. The `tarfile` peers for `.tar.gz` and
`.tar.bz2` read in one forward pass. The band column is the report's own label against
`VISION.md`.

| Case | archivey | peer | ratio | band |
| --- | ---: | ---: | ---: | --- |
| `zip_open_list` | 1.9 ms | 0.2 ms | 8.50× | above listing 3.0× |
| `zip_read_all` | 21.6 ms | 11.4 ms | 1.90× | above 1.3×, under 2.0× |
| `zip_extract` | 54.2 ms | 21.4 ms | 2.54× | above 2.0× safety |
| `tar_open_list` | 3.4 ms | 1.5 ms | 2.28× | within listing ≤3.0× |
| `tar_read_all` | 7.7 ms | 2.8 ms | 2.74× | above 2.0× safety |
| `gzip_read_all` | 56.7 ms | 52.1 ms | 1.09× | within ≤1.3× |
| `targz_read_all_accel_off` | 21.8 ms | 13.2 ms | 1.65× | above 1.3×, under 2.0× |
| `targz_read_all_accel_on` | 77.0 ms | 13.6 ms | 5.68× | above 2.0× safety |
| `tarbz2_read_all_accel_off` | 139.6 ms | 119.6 ms | 1.17× | within ≤1.3× |
| `tarbz2_read_all_accel_on` | 118.6 ms | 120.2 ms | 0.99× | within ≤1.3× |
| `sevenzip_open_list` | 1.9 ms | 0.8 ms | 2.32× | above native parity (~1.25×) |
| `sevenzip_many_open_list` | 150.5 ms | 103.0 ms | 1.46× | above native parity (~1.25×) |
| `sevenzip_nonsolid_open_list` | 22.1 ms | 14.0 ms | 1.58× | above native parity (~1.25×) |
| `rar_open_list` | 1.0 ms | 0.2 ms | 5.46× | above native parity (~1.25×) |
| `rar_many_open_list` | 27.1 ms | 14.4 ms | 1.89× | above native parity (~1.25×) |
| `rar_nonsolid_open_list` | 7.6 ms | 3.7 ms | 2.02× | above native parity (~1.25×) |

Cost model from the same run, as the report prints it: fitted from 2048 × 8 KiB and 64 ×
256 KiB, checked against 512 × 16 KiB, 16 × 1 MiB and 4 × 4 MiB
(`benchmarks/cost_model.py`). Reading is members per second through a `stream_members()`
pass, listing included, with the byte cost taken out; it is the per-member term, which
is why it shows a larger gap than `zip_read_all` above. Throughput is the data rate once
per-member costs are taken out, on data that compresses about 4:1. Uncompressed TAR
shows no throughput (no codec): its byte cost is a small remainder of the fit, and its
large check rungs are expected to miss. Both sides read the same files, so the
comparison between them holds even where the absolute numbers move between hosts. A row
marked \* has a check rung more than 25% and at least 0.5 ms off its fit. Not a gate.

| format | side | open | reading | throughput |
| --- | --- | ---: | ---: | ---: |
| zip | archivey | 0.39 ms | 6k members/s | 370 MiB/s |
| zip | zipfile | 0.03 ms | 51k members/s | 380 MiB/s |
| tar | archivey \* | 0.45 ms | 12k members/s | no codec |
| tar | tarfile | 0.05 ms | 38k members/s | no codec |

Check rung off the fit (the starred row; expected for uncompressed TAR at multi-MiB
members, so the TAR member rates describe small members):

- tar archivey read 4 × 4 MiB: measured 1.79 ms, predicted 2.68 ms (−49%)

Three published cases do not reproduce between runs, so read them as ranges.
`gzip_read_all` straddles parity: 0.86–0.89× in the nightlies of 2026-10-15, -16 and -18
and in the 07:04 run of 2026-10-20, then 1.14× four hours later on the same commit
(`b72df0b7`, run 39416281497) and 1.09× here. Both sides slowed in the slow runs, and
`z_zeros_read_all`, which has no peer, went from 93 ms to 246 ms with them, so the move
is the runner and not a 0.2.0 change to the gzip read path. `tar_open_list` gave
2.28–2.6× and `tar_read_all` 2.7–3.0× over the same runs; the 1.49× and 2.08× this file
once quoted from the 2026-10-19 run were one fast night.

The sections below were re-measured on 2026-10-22 on a different host, with all
extras and with RAR listing archives built by `rar`, so their ratios differ from these;
read both as directional. Both agree that forcing the gzip accelerator on at this corpus
size is slower than the plain codec, because rapidgzip now starts its own process
(see "`.tar.gz`, `.tar.bz2` and ZIP deflate with accelerators").

## Realistic scale

**Measurement host for the tables below:** 4-core Intel Xeon @ 2.80 GHz (KVM),
Linux x86_64, CPython 3.11.17. rapidgzip parallelises across cores, so its
speedups scale with core count. Treat the figures as directional, not portable.

**Measured:** 2026-10-22 at `1f2e12c5` (a branch merged with `main` @ `afd8125`
that changes nothing under `src/`), rapidgzip 0.16.0. Three runs of the
full-mode command above. Each cell is the median of the three per-run values, and
`range` gives the lowest and highest per-run ratio.

**Corpus:** 64 × 256 KiB members for ZIP, TAR, tar.gz, tar.bz2 and solid 7z/RAR
(about 16 MiB), a 32 MiB gzip file, and for 7z/RAR listing a 10 000-member solid
archive and a 1 000-member non-solid one. The payloads repeat a 4 KiB block, so
they compress far past real data. Two exceptions: `rar_open_list` lists the
committed `tests/fixtures/rar/basic_solid__.rar` (366 bytes, six entries) at every
scale, and the cost model below builds its own archives.

### Wall time against the standard library and the listing peers

The peer is `zipfile`, `tarfile` or `gzip` for those formats, `py7zr` for 7z
listing and `rarfile` for RAR listing. Ratio is archivey ÷ peer: below 1× archivey
is faster.

| Case | archivey | peer | ratio | range | VISION band |
| --- | ---: | ---: | ---: | ---: | --- |
| `zip_open_list` | 2.0 ms | 0.2 ms | 8.67× | 8.13–9.14× | above the 2–3× listing band |
| `zip_read_all` | 21.9 ms | 8.5 ms | 2.59× | 2.53–2.61× | above 2× |
| `zip_extract` | 136.8 ms | 106.2 ms | 1.29×\* | 1.27–1.37× | see note |
| `tar_open_list` | 3.9 ms | 1.7 ms | 2.24× | 2.13–2.26× | within the 2–3× listing band |
| `tar_read_all` | 10.7 ms | 4.7 ms | 2.24× | 2.19–2.37× | above 2× |
| `gzip_read_all` | 60.7 ms | 49.2 ms | 1.24× | 1.16–1.27× | within 1.3× |
| `targz_read_all_accel_off` | 20.4 ms | 10.7 ms | 1.92× | 1.86–1.94× | above 1.3×, under 2× |
| `tarbz2_read_all_accel_off` | 274.3 ms | 262.2 ms | 1.15× | 1.03–1.18× | within 1.3× |
| `sevenzip_open_list` | 1.9 ms | 0.9 ms | 2.23× | 2.10–2.29× | above ~1.25× |
| `sevenzip_many_open_list` | 164.1 ms | 116.8 ms | 1.35× | 1.34–1.41× | above ~1.25× |
| `sevenzip_nonsolid_open_list` | 26.5 ms | 26.1 ms | 1.21× | 1.01–1.37× | near ~1.25× |
| `rar_open_list` | 1.2 ms | 0.2 ms | 5.65× | 5.22–6.13× | above ~1.25× |
| `rar_many_open_list` | 311.4 ms | 162.3 ms | 1.92× | 1.88–2.02× | above ~1.25× |
| `rar_nonsolid_open_list` | 29.2 ms | 15.1 ms | 1.92× | 1.88–1.93× | above ~1.25× |

What the numbers show:

- **The ZIP gap is per member, not in decompression.** archivey reads ZIP with its
  own reader; `zipfile` is only the peer. On the cost model's own ladder (below),
  both sides decode at about the same rate (364 against 390 MiB/s), but archivey
  handles 6 000 members per second against `zipfile`'s 50 000. With 64 members of
  256 KiB that per-member cost is most of the 13 ms gap on `read_all`, and all of
  it on listing.
- **TAR follows the same pattern:** 13 000 members per second against `tarfile`'s
  38 000.
- **The small listing rows are loud.** `zip_open_list` and `sevenzip_open_list`
  list 64 members and `rar_open_list` six, and their peers finish in under 1 ms,
  so ratios of 2–9× are gaps of 1–2 ms. The 10 000-member rows show the
  per-member ratio.
- **`.tar.gz` pays for reading through archivey's stream layers.** The
  2026-10-20 diagnosis (not re-measured here): archivey feeds zlib about 1 600
  times for 16 MiB, roughly 10 KiB of output per call, through the slice and
  read-ahead layers, where `tarfile` makes a few large calls. The plain gzip row,
  one stream with no TAR on top, stays near the 1.3× target.
- **\* `zip_extract` has no reliable ratio on this host.** archivey's time held
  at 134–153 ms over six runs, but `zipfile`'s moved from 19 ms to 111 ms (the
  disk and page cache, not the code). Compare extraction against a peer only
  inside one run.

### Cost per member and per byte

From the first of the three runs (`benchmarks/cost_model.py`; not a gate). The
cost model does not use the corpus above: it builds its own archives, fitted from
2048 × 8 KiB and 64 × 256 KiB and checked against 512 × 16 KiB, 16 × 1 MiB and
4 × 4 MiB, on data that compresses about 4:1. So its throughput does not apply to
the 250:1 corpus rows above. Reading is members per second through one
`stream_members()` pass with the byte cost taken out. Throughput is the data rate
once the per-member costs are taken out.

| format | side | open | reading | throughput |
| --- | --- | ---: | ---: | ---: |
| zip | archivey | 0.55 ms | 6k members/s | 364 MiB/s |
| zip | zipfile | 0.10 ms | 50k members/s | 390 MiB/s |
| tar | archivey \* | 0.39 ms | 13k members/s | no codec |
| tar | tarfile \* | under 0.01 ms | 38k members/s | no codec |

\* The TAR rows miss some of their large check rungs (16 × 1 MiB and 4 × 4 MiB read
40–60% faster than the fit predicts) on both sides. With no codec, TAR's byte cost
is a small remainder, so its rungs are expected to miss.

### `.tar.gz`, `.tar.bz2` and ZIP deflate with accelerators

Archivey forces `use_rapidgzip` / `use_indexed_bzip2` ON or OFF; ON also sets
`MemberStreams.SEEKABLE`. The bzip2 accelerator is `rapidgzip.IndexedBzip2File`,
not the separate `indexed_bzip2` package. The stdlib peer reads in one forward pass.

| Case | accelerator off | accelerator on | stdlib | on ÷ off |
| --- | ---: | ---: | ---: | ---: |
| tar.gz | 20.4 ms | 143.5 ms | 10.7 ms | **7.0×** slower |
| tar.bz2 | 274.3 ms | 193.9 ms | 262.2 ms | 0.71× |
| ZIP deflate, 64 members | 21.1 ms | 2 767 ms | — | **131×** slower |

**These rows force the accelerator on below the size where it pays.** rapidgzip has
run in a child process, one per stream, since PR 493, and its bzip2 decoder since
PR 661 (PR 904 later made this part of the `ProcessIsolation.KNOWN_CRASHES` default
and kept it). Each child costs a fixed start-up, which `src/archivey/config.py` puts
at about 45 ms and a break-even near 13 MB of compressed DEFLATE input. The default
setting, `AUTO`, needs the caller to ask for seekable streams (`seekable_members=True`
on `open_archive`, `seekable=True` on `open_stream`), so a default call stays on the
stdlib whatever the size. When the compressed size is known, `AUTO` also needs it to
be at least 16 MiB for `use_rapidgzip` or 1 MiB for `use_indexed_bzip2`. The
`AcceleratorMode.AUTO` docstring in `src/archivey/config.py` gives the full
condition. These fixtures are far below the thresholds, and the ON rows show start-up
cost:

- The ZIP row opens 64 streams: (2 767 − 21) ms ÷ 64 is 43 ms per member.
- tar.gz is one stream, and its 123 ms over accelerator-off is that start-up plus
  the transfer.
- bzip2 decodes slowly enough that even this small input repays the start-up.

The figures this section quoted before (tar.gz 2.57× and tar.bz2 2.97× faster than
accelerator off) were measured in-process, before PR 493. None of these rows reaches
the size where `AUTO` turns the accelerator on. `benchmarks/accel_auto.py` measures that
case: it builds inputs above the thresholds from text-like data (about 3:1 under gzip)
and compares the default `AUTO`, with `seekable_members=True`, against `OFF`. It is
not part of the harness runs above. On 2026-10-26 (4-core KVM, CPython 3.11.17,
rapidgzip 0.16.0, main after PRs 1027 and 1042, 64 MiB of data, fastest of three
alternating runs after a warm-up):

| Case | compressed | `AUTO` | `OFF` | `AUTO` ÷ `OFF` |
| --- | ---: | ---: | ---: | ---: |
| single `.gz`, read to the end | 18.8 MiB | 212 ms | 247 ms | 0.86× |
| `.tar.gz`, 64 members of 1 MiB | 18.8 MiB | 280 ms | 538 ms | 0.52× |
| `.tar.bz2`, the same members | 13.2 MiB | 1 495 ms | 5 596 ms | 0.27× |
| ZIP, one DEFLATE member, read to the end | 18.9 MiB | 212 ms | 252 ms | 0.84× |
| ZIP, the same member, 20 random 64 KiB reads | 18.9 MiB | 216 ms | 1 562 ms | 0.14× |

**Where `AUTO` engages, it now wins in every case measured.** Two earlier findings no
longer hold:

- A single `.gz` or `.bz2` used to start two children, because the one-byte format check
  at open used an accelerated stream. The check now decodes with the standard library.
- An in-ZIP DEFLATE member read to the end used to be slower with `AUTO` (a 32 MiB
  member: 379 ms against 230 ms off, 2026-10-22). Most of that cost was the end-of-stream
  check decoding the whole member again with zlib. PR 1042 checks only the tail when
  the member holds one stream, so a full read is now faster with `AUTO` too.

**The documented command fails its sanity ceiling on this host.**
`targz_read_all_accel_on` measured 10.9–13.6× against its own stdlib pair, above
the harness's 10× `WALL_RATIO_BUDGET`, so all three runs exited non-zero on that
one case. The nightly on `main` measured the same case at 5.3× on 2026-10-21.

At **ci** scale (tiny fixtures) the accelerator was already slower before PR 493,
because indexing and thread-pool startup dominate.

### 7z BCJ branch filters — liblzma staging vs `pybcj`

This is an A/B between two commits, kept as the record of that change. The
harness's `sevenzip_bcj_*` cases time today's tree only, and their absolute times
differ from these.

`sevenzip_bcj_{lzma2,lzma1,copy}_read_all` were added with the change that moved
branch filters off `pybcj` and onto liblzma
(`dev-docs/investigations/pybcj-upstream-report.md`). liblzma refuses a raw chain whose only filter is a branch filter, so a BCJ stage standing
outside the folder's main chain reframes its input as LZMA2 *uncompressed* chunks;
these cases are what makes that reframing cost visible.

Corpus: 16×256 KiB of x86-like code (one `call rel32` and one `jmp rel32` per
16 bytes, so the filter converts about one branch per eight bytes) = 4 MiB.
Method: the harness's own A/B recipe — `--mode structural --scale realistic`,
sides alternated A,B,B,A,…, per-case minimum over 16 rounds each, sign test over
the per-round pairs, plus a null control (same SHA on both sides, 10 rounds).
Both sides ran the identical harness; only `src/` was swapped.

New = `a50f01a` (liblzma), old = `13ffd75` (`pybcj`). 4-core Intel Xeon (KVM).

| Case | new | old | new/old | rounds new was faster | sign p |
| --- | ---: | ---: | ---: | ---: | ---: |
| `sevenzip_bcj_copy_read_all` | 9.95 ms | 7.64 ms | **1.30×** | 0/16 | 0.000 |
| `sevenzip_bcj_lzma1_read_all` | 38.15 ms | 35.79 ms | **1.07×** | 0/16 | 0.000 |
| `sevenzip_bcj_lzma2_read_all` | 34.94 ms | 34.99 ms | 1.00× | 9/16 | 0.804 |

The null control puts the floor at 1% or better on all three (1.000, 0.995,
0.991; no case worse than 8/10 signs), and none of the other 25 harness cases
shows a consistent sign — so the two significant rows are the change, not the
host.

Reading them:

- **BCJ+Copy is the worst case by construction** — the branch filter is the whole
  decode, so the 1.30× is the reframing cost undiluted: ~420 MiB/s against
  ~550 MiB/s. Nothing else in the suite is that filter-dominated.
- **BCJ+LZMA1 is the shape that actually forces the staging** (the 7-Zip CLI
  writes LZMA1 without an end-of-stream marker, so BCJ cannot join the chain).
  Diluted by LZMA1 decode, the same cost is 1.07×.
- **BCJ+LZMA2 is the control and does not move**: liblzma already ran that whole
  chain itself before the change, `pybcj` was never on that path.

Framing overhead is 3 bytes per 64 KiB of payload (0.005%), so the cost is the
extra pass through liblzma's LZMA2 chunk layer, not the bytes.

### Structural / solid

| Check | Result |
| --- | --- |
| ZIP/TAR/gzip seek counts | within committed baseline bound (silent re-open churn) |
| ZIP/TAR/gzip `read_all` bytes decoded | at most 1.1× the unpacked size (over-decode guard); under-decode is an integrity check |
| solid 7z sequential | decode-once (also pinned in `test_measurement.py`) |
| solid 7z random `read()` | ~32.5× re-decode at realistic scale (520 MiB for 16 MiB, n=64), recorded only; at ci scale (16.5× in the committed baseline) PR CI gates it at 1.5× that baseline |
| solid RAR decode-once | structural gate on committed `basic_solid__.rar` + unit test (`unrar`) |
| encrypted RAR / ZIP AES / ZIP LZMA / in-ZIP accel | structural gate cases (T3); skip when `unrar` / `cryptography` / `[seekable]` absent |
| solid RAR random | smoke + seek baseline; byte re-decode not observable via unrar pipe (P9) |

ISO / directory: measurement is wired; harness cases are out of scope (ISO
lock baseline lives in `benchmarks/tar_iso_lock_baseline.py`).

### Gate policy

- **PR CI (blocking):** `--mode structural --scale ci` + unit decode-once tests.
- **Change-guarded nightly (off the PR path, `benchmark-wall.yml`):** `--mode full
  --scale realistic` with JSON + markdown report artifact upload (the markdown is also
  written to the Actions job summary so it is readable without downloading) — a daily
  schedule that skips its expensive run unless the default branch changed recently or
  `measured_at` is older than ~30 days; skips re-publish the previous artifact.
  `workflow_dispatch` forces a run (`skip_drift` re-seeds after intentional regressions).
- Wall timing: unmeasured archivey vs stdlib; absolute VISION bands informational;
  nightly hard-fails on wall-ratio *drift* vs the last measured artifact, pass or
  fail.

## Third-party peers: py7zr, rarfile, libarchive-c

The tables above compare against the stdlib only. `benchmarks/peers.py` times
archivey against the other Python readers on the same realistic corpus:

```bash
uv run --extra all python -m benchmarks.peers --scale realistic
```

It is a report, not a gate: none of these rows feeds the nightly drift check.
libarchive-c needs the system `libarchive` (Ubuntu package `libarchive13t64`); without
it, and without `py7zr`, `rarfile` or RARLAB `unrar`, the rows print as skipped.

**Host and versions:** 2026-10-22 at `1f2e12c5`, the same host as the tables
above. py7zr 1.1.4, rarfile 4.5 (with `unrar` 7.00), libarchive-c over libarchive
3.7.2. Three runs of the command above (9 alternating timed calls per side, the
default); each cell is the median of the three per-run medians. The script prints
the first six columns, one archive at a time; the table below regroups its rows by
peer, and the `range` column (the lowest and highest of the three per-run ratios)
was added by hand. Each row is an independent archivey/peer pair with its own
archivey timing, so archivey's time for one archive and operation differs between
the rows of different peers: by up to about 15% on the 3 ms RAR solid `list`
pair, 8–9% on RAR solid `read_all` and RAR 10 000 `list`, and 5% or less
elsewhere. The harness table above times the 7z and many / non-solid RAR listings
on the same archives with its own loop (warm-up, interleaved medians), so its
ratios differ from these: by up to about 0.25× (7z non-solid 1.21× there, 1.46×
here; 7z 10 000 members 1.35× and 1.53×). Its `rar_open_list` row lists a
different archive, the committed six-entry `basic_solid__.rar`, not the solid RAR
here.

**Read the method notes first:**

- The corpus is the harness corpus. Its payloads repeat a 4 KiB block, so they
  compress far past real data (16 MiB packs into 3.9 KB of 7z, 6.1 KB of RAR,
  93 KB of ZIP). `read_all` and `extract` measure per-member and output handling
  much more than codec speed.
- `list` reads names and metadata only. `read_all` reads every member into memory,
  and checks first that both sides return the same number of bytes. `extract`
  writes to an empty directory. archivey extracts with its default checks (path and
  link safety, atomic writes) and with all three extraction limits off (ratio,
  total bytes, entry count): these payloads exceed the default 1000:1 ratio, and
  the peers have no such limits. Only the ratio limit would have fired here.
- 7z fixtures: py7zr writes the solid LZMA2 archive (64×256 KiB) and the
  10 000-member solid Copy archive; the 7-Zip CLI writes the 1 000-member non-solid
  store archive (`-ms=off -mx=0`). RAR fixtures are RAR5, written by `rar` 7.00
  (solid `-m3` 64×256 KiB; 10 000 and 1 000 tiny store members).
- Which peer runs `unrar`: archivey and rarfile both send RAR member data through
  RARLAB `unrar`. archivey starts one process for the whole solid archive; rarfile
  starts `unrar p` once per member, and on a solid archive each process decodes
  from the start up to that member. libarchive decodes RAR in C, with no `unrar`.
- libarchive and solid RAR: libarchive reads solid **RAR5** with the RAR5 reader it
  has had since 3.4, which is what these fixtures are. Its older RAR 1.5–4 reader
  refuses solid archives ("RAR solid archive support unavailable" on the repo's
  `basic_solid__rar4.rar`), and even the RAR5 reader refuses some archives that
  `unrar` and archivey read (`basic_solid__.rar`: "Unsupported block header size").

Ratio is archivey ÷ peer: below 1× archivey is faster.

| Archive | Operation | Peer | archivey | peer | ratio | range |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 7z solid | list | py7zr | 2.0 ms | 0.9 ms | **2.21×** | 2.20–2.76× |
| 7z solid | read_all | py7zr | 29.7 ms | 39.0 ms | **0.77×** | 0.76–0.78× |
| 7z solid | extract | py7zr | 58.0 ms | 52.1 ms | 1.13× | 1.11–1.17× |
| 7z 10 000 members | list | py7zr | 165.3 ms | 106.8 ms | **1.53×** | 1.52–1.57× |
| 7z 1 000 non-solid | list | py7zr | 23.7 ms | 16.6 ms | 1.46× | 1.33–1.48× |
| RAR solid | list | rarfile | 2.7 ms | 1.1 ms | **2.41×** | 2.25–2.58× |
| RAR solid | read_all | rarfile | 46.8 ms | 853 ms | **0.05×** | 0.05–0.06× |
| RAR solid | extract | rarfile | 69.3 ms | 857 ms | 0.08× | 0.08–0.09× |
| RAR 10 000 members | list | rarfile | 319.5 ms | 165.4 ms | **1.94×** | 1.91–1.95× |
| RAR 1 000 non-solid | list | rarfile | 28.6 ms | 15.2 ms | 1.94× | 1.88–1.95× |
| ZIP | list | libarchive-c | 1.8 ms | 0.5 ms | 3.64× | 3.63–3.72× |
| ZIP | read_all | libarchive-c | 20.8 ms | 11.7 ms | 1.75× | 1.74–1.78× |
| ZIP | extract | libarchive-c | 48.4 ms | 12.3 ms | 3.90× | 3.89–4.00× |
| TAR | list | libarchive-c | 3.7 ms | 0.9 ms | 4.23× | 4.17–4.98× |
| TAR | read_all | libarchive-c | 10.4 ms | 8.1 ms | 1.28× | 1.27–1.29× |
| TAR | extract | libarchive-c | 37.2 ms | 11.0 ms | 3.35× | 3.30–3.52× |
| 7z solid | list | libarchive-c | 2.0 ms | 0.3 ms | 6.51× | 5.95–6.58× |
| 7z solid | read_all | libarchive-c | 30.6 ms | 25.8 ms | 1.19× | 1.19–1.19× |
| 7z solid | extract | libarchive-c | 55.8 ms | 27.2 ms | 2.03× | 2.01–2.15× |
| 7z 10 000 members | list | libarchive-c | 160.2 ms | 31.7 ms | 5.06× | 4.97–5.06× |
| 7z 1 000 non-solid | list | libarchive-c | 23.3 ms | 3.6 ms | 6.47× | 6.40–6.56× |
| RAR solid | list | libarchive-c | 3.1 ms | 19.2 ms | 0.16× | 0.16–0.16× |
| RAR solid | read_all | libarchive-c | 50.9 ms | 32.1 ms | 1.51× | 1.39–1.73× |
| RAR solid | extract | libarchive-c | 71.4 ms | 35.3 ms | 2.17× | 1.99–2.48× |
| RAR 10 000 members | list | libarchive-c | 295.2 ms | 34.9 ms | 8.41× | 8.40–8.50× |
| RAR 1 000 non-solid | list | libarchive-c | 28.6 ms | 3.7 ms | 7.75× | 7.74–8.14× |

What the numbers show:

- **Listing is not at parity with py7zr and rarfile.** VISION's target is about
  1.25×. Measured: about 1.5× on the many-member 7z archives, about 1.9× on the
  many-member RAR archives, and 2.2–2.4× on the 64-member solid archives (there
  the gap is under 2 ms in absolute terms). A cProfile of the 10 000-member
  archives (2026-10-21) put about 40% of 7z listing in `_to_member` (building
  `ArchiveMember`), and about 60% of RAR listing in RAR5 header parsing, with
  `_to_member` next.
- **Reading data, archivey is at or ahead of the pure-Python peers.** Solid 7z
  `read_all` is 0.77× py7zr. Solid RAR is about 18× faster than rarfile to read
  and 12× faster to extract, because rarfile decodes a solid archive again for
  every member.
- **libarchive is faster on nearly everything:** 3.6–8.4× on listing, 1.2–1.8× on
  `read_all`, 2–4× on `extract`. The exception is listing a solid RAR, where
  libarchive decodes the data to skip it (0.16×).
- **Extraction pays a fixed cost per member** on top of reading: ZIP extract is
  about 2.3× ZIP `read_all` for 64 members. Solid 7z goes from 0.77× py7zr on
  `read_all` to 1.13× on `extract`, so the cost is not specific to ZIP.

## Why the published guide no longer quotes numbers

The guide's old performance page, `docs/access-and-cost.md` (dropped when the
guide was rewritten in #884), used to carry a Measured column from the
`2026-07-23` nightly (`main` @ `89720de`). The column was removed: those
figures are the fastest-rotting claim on a published page, and re-running the same
harness at the same `--scale realistic` did not reproduce the ZIP rows.

| Workload | published (`89720de`, nightly) | re-run (`532ae21`, container) |
| --- | ---: | ---: |
| ZIP read-all | 1.87× | **2.57×** |
| ZIP open+list | 4.44× | **5.17×** |
| ZIP extract | 2.38× | **1.41×** |
| gzip read-all | 1.03× | 1.06× |
| tar.gz accel-off\* | 1.27× | 1.27× |
| tar.bz2 accel-off\* | 1.04× | 1.04× |

\* Measured against a `tarfile` peer that called `getmembers()` first and so
decompressed the stream twice. The absolute values are stale; the comparison
between the two columns still holds.

The codec-dominated rows land on the published values, so this is not simply a
slower host — only the ZIP wrapper rows move, and they move in **both**
directions. The ZIP ratio is dominated by per-member Python overhead against a
stdlib peer measured in milliseconds, which is exactly the shape that
does not survive a change of machine.

Both columns predate archivey's own ZIP reader, which replaced the `zipfile`-based
one, so neither describes ZIP today; the table stays as the evidence for the
decision. The guide now states the aspirational bands and the re-run command, and
points here for figures with a host and a commit attached. Absolute numbers belong
where their provenance travels with them.
