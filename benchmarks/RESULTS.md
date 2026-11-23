# Benchmark gate — sample results

**Blocking PR gate = structural invariants only** (seek-count baselines + solid
decode-once). Wall-time / VISION ≤1.3× runs off the PR path as a **change-guarded
nightly** (`benchmark-wall.yml`): a daily schedule whose expensive realistic run
fires when the default branch changed recently **or** the last measurement is
older than ~30 days (runner / toolchain drift). Quiet days **re-publish** the
previous JSON (preserving `measured_at` and `source_sha`) so the next run still
knows which commit was measured last. When the expensive run fires it:

- records results (JSON + markdown report artifacts, job summary table) with
  `measured_at` / source provenance;
- hard-fails on the ~13× sanity ceiling (when the time past it is at least 1 ms)
  **or** when a case is slower than on the
  commit the last measuring run timed, pass or fail. Both commits run in the same
  job on the same runner, alternating, three harness runs each, and
  `benchmarks/compare_refs.py --fail-on-slower` compares each side's fastest run:
  a case fails when it is more than 1.25× slower in wall time **and**, where it
  has a stdlib peer, against that peer, **and** by at least 1 ms. A case whose
  fixture changed between the commits is reported, not gated. Because a failed
  run's commit becomes the next baseline, a real regression fails the first night
  that measures it and not every night after;
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

**Maintainer decision (davitf, 2026-11-20):** run the last measured commit again
on the same runner instead of comparing with its stored times. Until then the
nightly compared ratios with the previous run's JSON, and the 1.25× drift gate
failed on runner noise: the same commit read `tar_open_list` 2.33× on one runner
and 2.86× on the next (#1686).

`workflow_dispatch` can pass `skip_drift=true` to measure `main` alone and make it
the new baseline after an intentional slowdown.

Re-run with:

```bash
# PR structural gate (small fixtures, fast)
uv run --extra all python -m benchmarks.harness --mode structural --scale ci

# Realistic wall-time vs stdlib (multi-MiB corpora; interleaved medians)
uv run --extra all python -m benchmarks.harness --mode full --scale realistic
```

## Release figures for 0.5.1, 0.5.0, 0.4.1, 0.4.0, 0.3.0 and 0.2.1

The figures quoted in the CHANGELOG entries for 0.5.1, 0.5.0, 0.4.1, 0.4.0, 0.3.0 and
0.2.1. Each comes from a `benchmark-compare.yml` dispatch on a GitHub `ubuntu-24.04`
runner (4 vCPUs, Python 3.11): the harness's `--mode full --scale realistic --warmup`
for each tree, alternating three rounds per side. A cell is the fastest of the three
rounds, for archivey and for its peer separately; ratio is archivey ÷ peer. The rows
forcing an accelerator on are left out, because the default does not use one at this
corpus size. The rows are the same cases as in [0.2.0 release
figures](#020-release-figures-2026-10-21).

### 0.5.1 against 0.5.0 (2026-11-20)

Run 44758019540, the 0.5.1 release branch at `7512aff1` as the candidate and the
`v0.5.0` tag (`145280ca`) as the baseline:

| Case | archivey 0.5.0 | ratio 0.5.0 | archivey 0.5.1 | ratio 0.5.1 |
| --- | ---: | ---: | ---: | ---: |
| `gzip_read_all` | 41.0 ms | 1.07× | 41.5 ms | 1.08× |
| `tar_read_all` | 11.0 ms | 3.57× | 11.0 ms | 3.46× |
| `tarbz2_read_all_accel_off` | 141.3 ms | 1.19× | 148.2 ms | 1.24× |
| `targz_read_all_accel_off` | 24.9 ms | 1.89× | 25.0 ms | 1.88× |
| `zip_extract` | 48.5 ms | 2.29× | 48.6 ms | 2.33× |
| `zip_read_all` | 25.8 ms | 2.25× | 26.2 ms | 2.29× |
| `rar_many_open_list` | 33.3 ms | 2.36× | 32.5 ms | 2.32× |
| `rar_nonsolid_open_list` | 9.5 ms | 2.60× | 9.4 ms | 2.59× |
| `rar_open_list` | 1.4 ms | 9.65× | 1.5 ms | 9.75× |
| `sevenzip_many_open_list` | 145.9 ms | 1.52× | 148.8 ms | 1.54× |
| `sevenzip_nonsolid_open_list` | 22.7 ms | 1.53× | 22.7 ms | 1.52× |
| `sevenzip_open_list` | 2.0 ms | 2.64× | 2.0 ms | 2.63× |
| `tar_open_list` | 4.2 ms | 2.92× | 4.1 ms | 2.88× |
| `zip_open_list` | 2.2 ms | 11.06× | 2.2 ms | 11.04× |

The release changes only reading from a URL, which no case here covers, and the
comparison flagged no case. Outside the table, `z_text_read_all` measured 3.78 s for
0.5.0 and 3.98 s for 0.5.1, and `tarbz2_read_all_accel_on` 113 ms on both sides.

### 0.5.0 against 0.4.1 (2026-11-19)

Run 44584589577, the 0.5.0 release branch at `b5c7a01a` as the candidate and the `v0.4.1`
tag (`054d04cd`) as the baseline:

| Case | archivey 0.4.1 | ratio 0.4.1 | archivey 0.5.0 | ratio 0.5.0 |
| --- | ---: | ---: | ---: | ---: |
| `gzip_read_all` | 41.2 ms | 1.07× | 41.9 ms | 1.08× |
| `tar_read_all` | 11.0 ms | 3.36× | 10.8 ms | 3.44× |
| `tarbz2_read_all_accel_off` | 147.2 ms | 1.24× | 144.7 ms | 1.22× |
| `targz_read_all_accel_off` | 25.4 ms | 1.92× | 25.5 ms | 1.92× |
| `zip_extract` | 49.3 ms | 2.32× | 48.9 ms | 2.32× |
| `zip_read_all` | 26.5 ms | 2.31× | 26.1 ms | 2.29× |
| `rar_many_open_list` | 34.4 ms | 2.39× | 33.6 ms | 2.34× |
| `rar_nonsolid_open_list` | 9.7 ms | 2.61× | 9.5 ms | 2.58× |
| `rar_open_list` | 1.5 ms | 10.46× | 1.5 ms | 9.50× |
| `sevenzip_many_open_list` | 164.1 ms | 1.68× | 148.2 ms | 1.54× |
| `sevenzip_nonsolid_open_list` | 23.7 ms | 1.55× | 23.1 ms | 1.55× |
| `sevenzip_open_list` | 2.1 ms | 2.64× | 2.0 ms | 2.64× |
| `tar_open_list` | 4.2 ms | 2.70× | 4.2 ms | 2.70× |
| `zip_open_list` | 2.1 ms | 11.51× | 2.2 ms | 10.93× |

`sevenzip_many_open_list` was 148 to 150 ms in all three candidate rounds and 164 to 170
ms in all three baseline rounds, but no 7z change explains it, and a local check (90
listings of each, the two trees alternating) measured 140.4 ms for 0.4.1 and 139.9 ms for
0.5.0, so it is runner noise. Outside the table,
`z_text_read_all` went from 4.14 to 3.85 s (#1649). `z_zeros_read_all` measured 129 to
170 ms for the baseline and 157 to 199 ms for the candidate, a spread too wide to call a
change. `tarbz2_read_all_accel_on` went from 118 to 114 ms (#1631).

### 0.4.1 against 0.4.0 and 0.3.0 (2026-11-18)

Two runs, each with the 0.4.1 release branch at `2f0db5d8` as the candidate. Each run
pairs its own baseline with the candidate on the same runner, so compare within a table,
not across them: the two runners differ in speed, by up to 1.6 times, and not by the same
factor for every case.

Run 44220708965, baseline the `v0.4.0` tag (`5baeb00c`):

| Case | archivey 0.4.0 | ratio 0.4.0 | archivey 0.4.1 | ratio 0.4.1 |
| --- | ---: | ---: | ---: | ---: |
| `gzip_read_all` | 28.6 ms | 1.12× | 26.6 ms | 1.03× |
| `tar_read_all` | 7.3 ms | 3.49× | 7.3 ms | 3.45× |
| `tarbz2_read_all_accel_off` | 218.5 ms | 1.07× | 222.9 ms | 1.12× |
| `targz_read_all_accel_off` | 16.5 ms | 1.86× | 17.5 ms | 1.97× |
| `zip_extract` | 34.4 ms | 2.70× | 35.0 ms | 2.75× |
| `zip_read_all` | 18.5 ms | 2.42× | 18.1 ms | 2.36× |
| `rar_many_open_list` | 22.9 ms | 2.20× | 22.7 ms | 2.20× |
| `rar_nonsolid_open_list` | 6.6 ms | 2.53× | 6.4 ms | 2.45× |
| `rar_open_list` | 1.0 ms | 11.01× | 0.9 ms | 10.71× |
| `sevenzip_many_open_list` | 129.0 ms | 1.92× | 115.3 ms | 1.75× |
| `sevenzip_nonsolid_open_list` | 16.8 ms | 1.14× | 18.7 ms | 1.59× |
| `sevenzip_open_list` | 1.7 ms | 3.23× | 1.5 ms | 3.00× |
| `tar_open_list` | 2.9 ms | 3.02× | 2.9 ms | 2.92× |
| `zip_open_list` | 1.6 ms | 12.41× | 1.4 ms | 11.37× |

Run 44220715975, baseline the `v0.3.0` tag (`f013eec9`):

| Case | archivey 0.3.0 | ratio 0.3.0 | archivey 0.4.1 | ratio 0.4.1 |
| --- | ---: | ---: | ---: | ---: |
| `gzip_read_all` | 37.4 ms | 0.98× | 40.9 ms | 1.07× |
| `tar_read_all` | 11.4 ms | 3.62× | 11.2 ms | 3.34× |
| `tarbz2_read_all_accel_off` | 140.6 ms | 1.19× | 153.0 ms | 1.29× |
| `targz_read_all_accel_off` | 23.9 ms | 1.79× | 25.5 ms | 1.91× |
| `zip_extract` | 50.0 ms | 2.35× | 49.0 ms | 2.31× |
| `zip_read_all` | 27.3 ms | 2.40× | 26.6 ms | 2.29× |
| `rar_many_open_list` | 29.7 ms | 2.09× | 33.6 ms | 2.36× |
| `rar_nonsolid_open_list` | 8.4 ms | 2.26× | 9.6 ms | 2.63× |
| `rar_open_list` | 1.2 ms | 6.34× | 1.5 ms | 10.91× |
| `sevenzip_many_open_list` | 155.3 ms | 1.54× | 163.6 ms | 1.70× |
| `sevenzip_nonsolid_open_list` | 22.7 ms | 1.50× | 23.4 ms | 1.54× |
| `sevenzip_open_list` | 1.9 ms | 2.37× | 2.1 ms | 2.66× |
| `tar_open_list` | 3.9 ms | 2.70× | 4.3 ms | 3.02× |
| `zip_open_list` | 2.0 ms | 9.15× | 2.2 ms | 11.97× |

Against 0.4.0, `gzip_read_all` is 7% faster in archivey's own time (#1627), and 7z
listing of many members 11% faster (#1580 and #1579). `sevenzip_nonsolid_open_list` measured
11% slower here, but its reference reader moved by as much between the two sides, and a
run on 2026-11-17 at `ed7e9313` measured it 19% faster, so it is noise. Outside the
tables, `z_zeros_read_all` went from 162 to 133 ms (#1574), and `tarbz2_read_all_accel_on`
from 106 to 117 ms (9% in the 2026-11-17 run too). Against 0.3.0, `gzip_read_all` is 9%
slower (37.4 against 40.9 ms), where the 2026-11-17 run, before #1627, measured 22%; 7z
listing is 3–7% slower (10–14% in 0.4.0); and RAR listing is still 13–19% slower. The
RAR listing slowdown came with 0.4.0.

### 0.4.0 and 0.3.0 (2026-11-15)

Run 43689017345. Baseline is the `v0.3.0` tag (`f013eec9`), candidate is the 0.4.0
release branch at `14a36e8a`.

| Case | archivey 0.3.0 | ratio 0.3.0 | archivey 0.4.0 | ratio 0.4.0 |
| --- | ---: | ---: | ---: | ---: |
| `gzip_read_all` | 29.5 ms | 1.01× | 32.7 ms | 1.12× |
| `tar_read_all` | 7.3 ms | 3.63× | 7.3 ms | 3.56× |
| `tarbz2_read_all_accel_off` | 210.2 ms | 1.07× | 210.1 ms | 1.06× |
| `targz_read_all_accel_off` | 16.2 ms | 1.82× | 16.8 ms | 1.89× |
| `zip_extract` | 35.1 ms | 2.72× | 34.7 ms | 2.68× |
| `zip_read_all` | 19.1 ms | 2.49× | 19.1 ms | 2.47× |
| `rar_many_open_list` | 19.6 ms | 1.90× | 23.3 ms | 2.19× |
| `rar_nonsolid_open_list` | 5.5 ms | 2.05× | 6.9 ms | 2.59× |
| `rar_open_list` | 0.8 ms | 6.37× | 1.0 ms | 10.95× |
| `sevenzip_many_open_list` | 112.6 ms | 1.64× | 128.7 ms | 1.91× |
| `sevenzip_nonsolid_open_list` | 15.6 ms | 1.53× | 17.1 ms | 1.17× |
| `sevenzip_open_list` | 1.5 ms | 2.58× | 1.7 ms | 3.25× |
| `tar_open_list` | 2.7 ms | 2.63× | 2.9 ms | 2.98× |
| `zip_open_list` | 1.4 ms | 9.36× | 1.6 ms | 12.56× |

Reading did not move beyond noise. Listing did: RAR listing is 19–27% slower and 7z
listing 10–14% slower in archivey's own time, with the peers unchanged (the one 7z row
whose ratio fell, `sevenzip_nonsolid_open_list`, has a peer that was slower in this
run's candidate rounds). Outside this table, `z_zeros_read_all` (no peer, 128 MiB of
`.Z` zeros) went from 125 to 177 ms. This round did not profile either change.

### 0.2.1 (2026-11-01)

Run 41262561901, baseline side: the `v0.2.1` tag (`5f28bde7`), measured a week after
the release.

| Case | archivey 0.2.1 | ratio 0.2.1 |
| --- | ---: | ---: |
| `gzip_read_all` | 37.1 ms | 1.10× |
| `tar_read_all` | 3.8 ms | 2.46× |
| `tarbz2_read_all_accel_off` | 84.0 ms | 1.19× |
| `targz_read_all_accel_off` | 10.7 ms | 1.60× |
| `zip_extract` | 27.2 ms | 2.46× |
| `zip_read_all` | 11.3 ms | 1.95× |
| `rar_many_open_list` | 13.9 ms | 1.83× |
| `rar_nonsolid_open_list` | 3.9 ms | 1.98× |
| `rar_open_list` | 0.6 ms | 5.57× |
| `sevenzip_many_open_list` | 79.9 ms | 1.43× |
| `sevenzip_nonsolid_open_list` | 10.8 ms | 1.38× |
| `sevenzip_open_list` | 1.0 ms | 2.27× |
| `tar_open_list` | 1.6 ms | 1.79× |
| `zip_open_list` | 0.9 ms | 7.56× |

## Since 0.3.0 (2026-11-09)

**Trees.** Before is the `v0.3.0` tag (`f013eec9`). After is `main` at `37e08c35`. Both
trees ran this branch's `benchmarks/` against their own `src/`, as the 2026-10-28 round
did, and shared one `ARCHIVEY_BENCH_CACHE`, so both read the same archive files. The
interval holds the per-member work of PRs 1359 (layer proofs asked once per member sync)
and 1373 (a small ZIP member read whole at open), plus the new formats and many fixes. The
attribution below is an inference from what those PRs change.

**Host and method.** A 4-vCPU Intel Xeon KVM container, Linux x86_64, CPython 3.11.18,
libarchive-c over libarchive 3.7.2, py7zr 1.1.4, rapidgzip 0.16.0. Each tree ran
`benchmarks.harness --mode full --scale realistic --warmup` and `benchmarks.peers --scale
realistic` twice, in the order before, after, before, after. Each cell is the mean of a
tree's two runs. Extraction wrote to `/dev/shm`. Ratio is archivey ÷ peer, against the
peer timed in the same run.

### Many small members

The 4 000-file corpus of [Many small members](#many-small-members). The table
lists the rows where archivey's own time fell by 10% or more. Every other row moved by
less than 10%, inside the noise band of the earlier rounds, except one ZIP `list` pair
discussed below.

| Archive | Operation | Peer | archivey 0.3.0 | ratio 0.3.0 | archivey main | ratio main |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| ZIP | read_all | zipfile | 691 ms | 15.3× | 340 ms | 7.7× |
| ZIP | extract | zipfile | 1 358 ms | 13.7× | 870 ms | 8.7× |
| ZIP | read_all | libarchive-c | 705 ms | 28.9× | 332 ms | 13.7× |
| ZIP | extract | libarchive-c | 1 394 ms | 23.0× | 876 ms | 14.3× |
| ZIP stored | read_all | zipfile | 437 ms | 11.2× | 328 ms | 8.5× |
| ZIP stored | extract | zipfile | 947 ms | 10.4× | 812 ms | 9.0× |
| 7z | read_all | py7zr | 354 ms | 1.05× | 306 ms | 0.93× |
| 7z | read_all | libarchive-c | 352 ms | 19.5× | 301 ms | 16.5× |

What the numbers show:

- **Reading a small ZIP member costs half what it did.** `read_all` over 4 000 DEFLATE
  members fell from 691 to 340 ms (about 170 to 85 µs a member), and extraction by a
  third. PR 1373 decodes a member of up to 64 KiB in one call at open and skips the
  codec layer stack when nothing in the member looks unusual. Stored members gain less
  (−25%), because they had no decoder to skip.
- **7z gains about 14% on reading.** PR 1359, which asks the layer proofs once per
  member sync in every format, is the likeliest cause. TAR does not show a gain, so the
  saving may show only where the rest of a member's cost is low; this round did not
  profile it.
- **TAR, tar.gz and listing did not move** beyond noise (−4% to +5%). The ZIP `list`
  row read +15% in one pair of runs; a re-run of 15 alternating calls per side gave
  55 ms, the 0.3.0 figure, and the ratio stayed at 6.3–6.5× throughout.
- **The harness corpus did not move either** (64 members of 256 KiB, decode-bound): every
  row's ratio stayed inside its run-to-run range. `zip_extract` again had no stable
  `zipfile` time (10–43 ms between runs).

### Large `.tar.bz2` under AUTO (PR 1369)

PR 1369, merged after this was measured, sends a large sequential bzip2 read from a
local file through the parallel accelerator under the default `AUTO`. Its tree
(`129d3347`) and `main` read a 9.1 MiB `.tar.bz2` of 32 text-like members of 1 MiB with
`stream_members()`, against a one-pass `tarfile` (median of 7 alternating calls):

| Tree | archivey | tarfile | ratio |
| --- | ---: | ---: | ---: |
| `main` | 1 800 ms | 1 747 ms | 1.03× |
| PR 1369 | 510 ms | 1 698 ms | 0.30× |

The harness's own `.tar.bz2` is 23 KB on disk, far below the rule's 1 MiB threshold, so its `AUTO`
time did not change (272 against 277 ms).

### New formats against libarchive

The same 4 000-file tree as an MSZIP cabinet written by `gcab` 1.6, and as a binary RPM
with a gzip payload written by `rpmbuild` 4.18 (both are skipped when the tool is
missing). One run of `main`, 9 timed calls per side.

| Archive | Operation | archivey | libarchive-c | ratio |
| --- | --- | ---: | ---: | ---: |
| CAB | list | 38 ms | 9 ms | 4.1× |
| CAB | read_all | 264 ms | 17 ms | 16.0× |
| CAB | extract | 785 ms | 52 ms | 15.0× |
| RPM | list | 127 ms | 14 ms | 9.1× |
| RPM | read_all | 377 ms | 20 ms | 18.6× |
| RPM | extract | 985 ms | 59 ms | 16.7× |

Both sit where TAR and 7z sit against libarchive on this corpus (15–24× on reading and
extraction): the cost is per member, not in the decoders. RPM listing is the slowest of
the new rows. A profile of it shows little decoding: most of the time goes to the forward
walk over the cpio payload, one entry at a time through the format-API adapter, where a
CAB lists from its file table.

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
archivey against the other Python readers on the same realistic corpus, and on a
second corpus of many small members against `zipfile`, `tarfile`, py7zr and
libarchive-c (see "Many small members" below):

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

The extraction rows above predate PRs 1071–1083, which made extraction 15–28% faster
per member. "Many small members" below has before and after figures. `1f2e12c5` is a
branch commit, not on `main`; its `src/` matched `main` at `afd8125`.

## Many small members

The harness corpus has 64 members of 256 KiB, so the work each member costs barely
shows in it. `benchmarks/peers.py` also builds a corpus where that cost dominates:
4 000 files of 20 to 600 random bytes in 40 directories of 7 subdirectories each (4 320
entries with the directories, `Scale.small_members`), as ZIP (DEFLATE, and stored),
TAR, tar.gz and 7z. `zipfile` writes the ZIPs and py7zr the 7z, from a fixed seed. Its
rows are labelled `4 000 small`.

**What each peer does per member, on `extract`:** archivey runs its default checks
(path and link safety, atomic writes) and sets mode and mtime. `tarfile` (with
`filter="data"`) sets mode and mtime too. `zipfile.extractall` writes the bytes only, and
restores neither. So part of the gap to `zipfile` is work `zipfile` skips, and the
`tarfile` and `zipfile` ratios are not on the same footing.

**Before and after the per-member speedup (2026-10-28).** Before is `8191bdd4`, the
`main` just before PR 1071. After is `5b2f2f71`, `main` after PR 1083. The interval
holds PRs 1071 and 1073–1076 and 1083, which target per-member cost, and also 1065, 1066,
1068, 1069, 1070 and 1072 (plugins, a 7z Delta fix, docs, the public `ArchiveStream`
base classes); the attribution to the first group is an inference from what they
change, backed by the callgrind counts in each PR. The `8191bdd4` tree has no
small-member corpus, so both trees ran this branch's `peers.py` (copied over the old
one) against their own `src/`, sharing one `ARCHIVEY_BENCH_CACHE` so both read the same
archive files. The same 4-core KVM host as the sections above, CPython 3.11.17,
libarchive-c over libarchive 3.7.2, py7zr 1.1.4. Each tree ran twice, in the order
before, after, before, after (9 alternating timed calls per side, the default); each
cell is the mean of a tree's two runs. Each ratio is against the peer timed in the
same run, so the peer column is given for each tree. Extraction wrote to `/dev/shm`
(`TMPDIR`), to keep the disk out of it. Ratio is archivey ÷ peer.

| Archive | Operation | Peer | archivey before | peer | ratio before | archivey after | peer | ratio after |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ZIP | list | zipfile | 94 ms | 13 ms | 7.29× | 107 ms | 14 ms | 7.63× |
| ZIP | read_all | zipfile | 815 ms | 63 ms | 13.04× | 728 ms | 68 ms | 10.73× |
| ZIP | extract | zipfile | 2 659 ms | 212 ms | 12.52× | 2 115 ms | 209 ms | 10.12× |
| ZIP | list | libarchive-c | 101 ms | 34 ms | 3.00× | 106 ms | 29 ms | 3.60× |
| ZIP | read_all | libarchive-c | 824 ms | 44 ms | 18.91× | 755 ms | 44 ms | 17.15× |
| ZIP | extract | libarchive-c | 2 757 ms | 135 ms | 20.52× | 2 145 ms | 121 ms | 17.72× |
| TAR | list | tarfile | 347 ms | 223 ms | 1.56× | 359 ms | 221 ms | 1.61× |
| TAR | read_all | tarfile | 534 ms | 284 ms | 1.88× | 541 ms | 269 ms | 2.01× |
| TAR | extract | tarfile | 2 236 ms | 793 ms | 2.82× | 1 763 ms | 812 ms | 2.18× |
| TAR | list | libarchive-c | 356 ms | 18 ms | 19.27× | 410 ms | 23 ms | 18.75× |
| TAR | read_all | libarchive-c | 498 ms | 31 ms | 16.14× | 559 ms | 40 ms | 13.82× |
| TAR | extract | libarchive-c | 2 146 ms | 114 ms | 18.85× | 1 831 ms | 119 ms | 15.51× |
| tar.gz | list | tarfile | 401 ms | 248 ms | 1.61× | 372 ms | 280 ms | 1.33× |
| tar.gz | read_all | tarfile | 538 ms | 300 ms | 1.79× | 563 ms | 313 ms | 1.79× |
| tar.gz | extract | tarfile | 2 288 ms | 815 ms | 2.80× | 1 796 ms | 781 ms | 2.30× |
| tar.gz | list | libarchive-c | 446 ms | 25 ms | 17.91× | 399 ms | 25 ms | 16.05× |
| tar.gz | read_all | libarchive-c | 547 ms | 40 ms | 13.88× | 578 ms | 37 ms | 15.76× |
| tar.gz | extract | libarchive-c | 2 347 ms | 115 ms | 20.46× | 1 808 ms | 121 ms | 14.98× |
| 7z | list | py7zr | 85 ms | 73 ms | 1.17× | 77 ms | 56 ms | 1.38× |
| 7z | read_all | py7zr | 298 ms | 544 ms | 0.55× | 313 ms | 542 ms | 0.57× |
| 7z | extract | py7zr | 1 890 ms | 1 183 ms | 1.60× | 1 366 ms | 1 105 ms | 1.24× |
| 7z | list | libarchive-c | 82 ms | 17 ms | 4.78× | 82 ms | 16 ms | 5.18× |
| 7z | read_all | libarchive-c | 312 ms | 33 ms | 9.50× | 314 ms | 39 ms | 8.51× |
| 7z | extract | libarchive-c | 1 848 ms | 106 ms | 17.52× | 1 322 ms | 108 ms | 12.24× |

Read the before/after claim from the archivey columns; a ratio also moves with its
peer. The 7z `list` row shows why: archivey went from 85 to 77 ms while the ratio rose,
because py7zr's time in those runs went from 73 to 56 ms.

What the numbers show:

- **Extraction is 15–28% faster in every format** (archivey's own time), and the
  ratios moved with it: ZIP 12.5× → 10.1× `zipfile`, TAR and tar.gz 2.8× → 2.2–2.3×
  `tarfile`, 7z 1.6× → 1.24× py7zr. That is where the speedup went (the extraction
  coordinator: path checks, name policy, landing, member copies).
- **ZIP `read_all` is 11% faster** (815 → 728 ms), mostly from one `ArchiveStream` per
  member (PR 1083).
- **Listing and the TAR, tar.gz and 7z `read_all` rows did not move beyond noise,**
  though some moved by 10–15%. The same operation timed against the other peer tells
  the two apart: TAR `list` is +15% in its libarchive-c pair and +3.5% in its
  `tarfile` pair, TAR `read_all` +12% and +1.3%. Code that changed would move both
  pairs alike; these disagree, so the spread is the host.
  PR 1083 also measured the TAR and 7z reads at +0.6% to +2% instructions per member
  under callgrind. Read single wall-time differences under about 15% here as noise.
- **archivey is still far from the C reader and from `zipfile` per member.** Against
  libarchive it is 3.6–19× on listing and 8.5–18× on reading and extraction. Against
  `tarfile` it is within 1.3–2.3×; against `zipfile` it is 7.6–10.7×, part of which is
  the mode and mtime work `zipfile` skips (above).
- **A DEFLATE member costs much more to read than a stored one.** On the `after` tree
  (two runs, `ZIP stored 4 000 small` against `ZIP 4 000 small`, `zipfile` the peer),
  `read_all` takes 398–406 ms stored and 732–741 ms deflated: about 85 µs more per
  member. `zipfile` reads the two in 54–55 and 61–66 ms. A profile puts the difference
  in the codec set-up for each member: three `dataclasses.replace` calls on config
  objects (`_with_local_method`, `_member_config`, `_decoder_config`), the decompressor
  stream's own layers, and four `rapidgzip` eligibility checks.

On the harness corpus (the earlier sections), the same before/after pair, two runs
each, moved only the extraction rows beyond noise: ZIP `extract` against libarchive-c
4.2× → 3.2×, TAR `extract` 3.6× → 2.8×, solid 7z `extract` against py7zr 1.24× →
1.05×. The harness's `zip_extract` against `zipfile` stays unreliable on this host (see
the note under "Realistic scale"); on the small-member corpus the `zipfile` extract time
held at 209–212 ms across the four runs, so that row's ratio is stable.

**Second round (2026-10-28, later).** Before is `5b2f2f71` (the "after" above). After is
`9b7cae69`, `main` after PRs 1086 (positional copies of each member and result), 1087
(DEFLATE set-up per member), 1088 (string fast paths in the extraction coordinator)
and 1090 (listing pulls in batches). The interval also holds PRs 1080 (ZIP XZ method)
and 1091 (plugin formats inside a compression stream), which add paths this corpus
does not take, and 1085 (this corpus and the first round's notes; benchmarks and docs
only). Same method as above: the same `peers.py`, one shared `ARCHIVEY_BENCH_CACHE`,
extraction to `/dev/shm`, CPython 3.11.17, py7zr 1.1.4, libarchive-c over libarchive
3.7.2, two runs per tree in the order before, after, before, after. Times are means of
the two runs, and each ratio comes from one run.

The host was not the first round's, and it changed within this round: the container
restarted between the two runs of each tree, and the same tree ran up to 30% faster
after the restart. `5b2f2f71` is also 23–30% faster here than in the first round's
"after" column on every row not bound by its peer (ZIP `read_all` 728 against 631 ms).
So read only ratios and the before/after differences within this round; absolute times
do not compare across rounds.

Wall time is too noisy here to show a 2–5% change, so the instruction counts come
first. They are callgrind's count per member on the same corpus (`PYTHONHASHSEED=0`,
the count for opening the archive taken out), for `members()`, reading every member
through `stream_members()`, and `extract_all()`:

| Archive | list before | list after | read before | read after | extract before | extract after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ZIP (DEFLATE) | 122 249 | 118 473 (−3.1%) | 837 614 | 725 383 (−13.4%) | 1 416 834 | 1 273 420 (−10.1%) |
| ZIP stored | 121 903 | 118 498 (−2.8%) | 481 111 | 466 804 (−3.0%) | 1 057 861 | 1 008 357 (−4.7%) |
| TAR | 344 283 | 337 775 (−1.9%) | 507 814 | 500 867 (−1.4%) | 1 086 562 | 1 055 722 (−2.8%) |
| tar.gz | 381 738 | 375 552 (−1.6%) | 539 777 | 536 780 (−0.6%) | 1 117 578 | 1 081 819 (−3.2%) |
| 7z | 133 202 | 129 998 (−2.4%) | 349 567 | 339 492 (−2.9%) | 922 358 | 875 972 (−5.0%) |

The wall-clock rows (ms; ratio is archivey ÷ peer):

| Archive | Operation | Peer | archivey before | peer | ratio before | archivey after | peer | ratio after |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ZIP | list | zipfile | 74 ms | 11 ms | 6.88× | 62 ms | 10 ms | 6.35× |
| ZIP | read_all | zipfile | 631 ms | 58 ms | 10.87× | 560 ms | 58 ms | 9.62× |
| ZIP | extract | zipfile | 1 633 ms | 146 ms | 11.21× | 1 474 ms | 129 ms | 11.45× |
| ZIP | list | libarchive-c | 74 ms | 23 ms | 3.19× | 68 ms | 22 ms | 3.07× |
| ZIP | read_all | libarchive-c | 642 ms | 36 ms | 17.82× | 576 ms | 36 ms | 15.97× |
| ZIP | extract | libarchive-c | 1 591 ms | 89 ms | 17.80× | 1 491 ms | 89 ms | 16.84× |
| ZIP stored | list | zipfile | 67 ms | 10 ms | 6.80× | 69 ms | 11 ms | 6.42× |
| ZIP stored | read_all | zipfile | 339 ms | 47 ms | 7.23× | 350 ms | 50 ms | 6.94× |
| ZIP stored | extract | zipfile | 1 076 ms | 120 ms | 8.98× | 1 134 ms | 140 ms | 8.09× |
| TAR | list | tarfile | 261 ms | 170 ms | 1.53× | 273 ms | 190 ms | 1.44× |
| TAR | read_all | tarfile | 448 ms | 229 ms | 1.96× | 453 ms | 234 ms | 1.94× |
| TAR | extract | tarfile | 1 348 ms | 568 ms | 2.37× | 1 206 ms | 545 ms | 2.21× |
| TAR | list | libarchive-c | 279 ms | 14 ms | 19.78× | 253 ms | 13 ms | 19.99× |
| TAR | read_all | libarchive-c | 440 ms | 25 ms | 17.34× | 423 ms | 23 ms | 18.46× |
| TAR | extract | libarchive-c | 1 270 ms | 79 ms | 16.04× | 1 187 ms | 70 ms | 16.86× |
| tar.gz | list | tarfile | 307 ms | 221 ms | 1.39× | 298 ms | 220 ms | 1.35× |
| tar.gz | read_all | tarfile | 455 ms | 252 ms | 1.81× | 476 ms | 261 ms | 1.83× |
| tar.gz | extract | tarfile | 1 404 ms | 632 ms | 2.22× | 1 342 ms | 618 ms | 2.17× |
| tar.gz | list | libarchive-c | 305 ms | 22 ms | 13.65× | 298 ms | 22 ms | 13.59× |
| tar.gz | read_all | libarchive-c | 419 ms | 32 ms | 12.92× | 477 ms | 34 ms | 14.10× |
| tar.gz | extract | libarchive-c | 1 346 ms | 86 ms | 15.64× | 1 377 ms | 91 ms | 15.19× |
| 7z | list | py7zr | 60 ms | 42 ms | 1.43× | 56 ms | 42 ms | 1.34× |
| 7z | read_all | py7zr | 206 ms | 385 ms | 0.53× | 205 ms | 416 ms | 0.49× |
| 7z | extract | py7zr | 1 014 ms | 829 ms | 1.22× | 957 ms | 839 ms | 1.14× |
| 7z | list | libarchive-c | 56 ms | 13 ms | 4.18× | 54 ms | 12 ms | 4.56× |
| 7z | read_all | libarchive-c | 225 ms | 26 ms | 8.62× | 227 ms | 25 ms | 9.16× |
| 7z | extract | libarchive-c | 990 ms | 80 ms | 12.31× | 972 ms | 80 ms | 12.17× |

What the second round shows:

- **Reading a DEFLATE ZIP member is 13% cheaper** in instructions, and ZIP (DEFLATE)
  `read_all` fell from 631 to 560 ms (10.9× → 9.6× `zipfile`). That is PR 1087: one
  decoder config per member instead of three copies, and fewer rapidgzip eligibility
  checks. Within this round, the extra cost of a deflated member over a stored one fell
  from about 73 µs ((631 − 339) ms ÷ 4 000) to about 52 µs ((560 − 350) ms ÷ 4 000), and
  from about 356 000 to 259 000 instructions. The first round's "about 85 µs" was
  measured on another host.
- **Extraction is 2.8–10.1% cheaper** in instructions (TAR least, ZIP (DEFLATE) most;
  PRs 1086, 1087 and 1088). The wall rows agree in direction for ZIP (DEFLATE), TAR and
  7z.
- **Listing is 1.6–3.1% cheaper** in instructions (tar.gz least, ZIP most; PR 1090 and
  the copies in 1086). Too small to read from the wall rows.
- **Some wall rows moved the other way, all inside the noise band.** The three ZIP
  stored rows rose 2–5% while their instruction counts fell 2.8–4.7%, and the tar.gz
  `read_all` pair against libarchive-c rose 14%. The ZIP `extract` ratio against
  `zipfile` rose (11.2× → 11.5×) though archivey's own time fell from 1 633 to 1 474 ms,
  because `zipfile` ran faster in the "after" runs (146 → 129 ms). Single wall
  differences under about 15% are still noise here.
- **Where archivey stands now:** 6.4× `zipfile` to list a ZIP and 9.6× to read one,
  1.3–2.2× `tarfile`, 0.5–1.3× py7zr; against libarchive-c 3–20× on listing and 9–18×
  on reading and extraction.

The harness corpus (64 members of 256 KiB) ran twice per tree alongside, before the
restart. Its rows are dominated by decoding, which these PRs do not touch, and they
moved by no more than their run-to-run noise. Leaving out one 132 ms `zip_extract` run
on the "before" tree (the other was 53 ms), the largest change in a row's mean was
`tar_open_list`, +19% (3.7 → 4.3 ms), while the two runs of one tree differed by up to
27% on the same rows (`targz_read_all_accel_on`, 115 against 91 ms).

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
