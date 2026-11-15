# Reproducing the review

Run from the repository root. Pin runtime code to
`529d7fbbeabafac2edf28ccb00afb8ea8af09053`; the scripts are retained in this report PR.
A later report-only commit does not change that runtime source. `cabexperiment.py` reads
its original method from the pinned revision, not a moving `HEAD`.

The scripts are preserved experiments, not installed library modules. Changes from the
original scratch copies make the fixture directory configurable and pin the original CAB
source. Formatting changes do not change their workloads. Keep source patches separate
from the report commit when implementing a proposal.

## Setup

The measurement used CPython 3.12.14. Install the development group and all extras. System
setup was attempted during measurement but could not install system binaries on the
read-only host. Python dependencies were installed in the workspace. The benchmark does
not require `gcab` or a 7z executable: it uses py7zr and `tests.cab_util`.

```bash
uv sync --python python3.12 --group dev --extra all
export PYTHONHASHSEED=0
export PYTHONPATH=.:review/archive/2026-11-15-performance-round-two/scripts
export ROUND2_DIR="${TMPDIR:-/tmp}/archivey-performance-round-two"  # outside the checkout
mkdir -p "$ROUND2_DIR"
R=review/archive/2026-11-15-performance-round-two
S="$R/scripts"
```

The original fixture directory was `/workspace/work/round2`. Changing the directory or
filesystem can affect extraction cost. Python version, optional dependencies, CPU quota,
rapidgzip availability and filesystem should accompany any new numbers.

## Baselines and profiles

```bash
.venv/bin/python "$S/round2.py" --build --profile --runs 7 > "$ROUND2_DIR/baseline.jsonl"
.venv/bin/python "$S/final_extra.py" extra > "$ROUND2_DIR/extra.jsonl"
```

`round2.py` makes exactly 4,000 files of 20-600 deterministic random bytes, a 20,000-entry
USTAR listing fixture and two 64 MiB payload fixtures. It checks repeated operation totals.
The archive library itself performs its normal integrity checks. Path readers use defaults;
pipe readers explicitly use `streaming=True` over a non-seekable wrapper.

The script's extraction timer includes temporary-directory cleanup. The extraction-only
timer and profile in `final_extra.py` exclude cleanup. Use that separate series for the
375.5 microseconds/member result. `final_extra.py` also measures stdlib peers and the
internal restart-recording toggle. The toggle is for clean-input cost isolation, not a
proposed user option or an equivalence proof for damaged archives.

Each selected case warms once and then calls `gc.collect(); gc.freeze(); gc.disable()`.
With `--profile`, a separate cProfile pass precedes the uninstrumented timing passes.
Profile files are written to `ROUND2_DIR`.

For sampling, install py-spy without changing the project lockfile, for example:

```bash
uv pip install --python .venv/bin/python py-spy
.venv/bin/py-spy record --rate 500 --format speedscope -o "$ROUND2_DIR/zip.json" -- \
  .venv/bin/python "$S/round2.py" --case zip_stream --runs 30
.venv/bin/py-spy record --rate 300 --format speedscope -o "$ROUND2_DIR/all.json" -- \
  .venv/bin/python "$S/round2.py" --runs 2
```

These commands sample the parent process. They do not attribute native rapidgzip child
work to Python functions. The operation wall timers include waiting for that work.

## Shared-state experiments

Run against unpatched runtime code:

```bash
.venv/bin/python "$S/experiments.py" proof8 zip_stream 7z_read
.venv/bin/python "$S/experiments.py" ratio zip_stream
.venv/bin/python "$S/micro.py"
```

`experiments.py` runs 15 interleaved pairs and prints all samples, medians and minima.
`proof8` includes the verifier table and shared doubt-only records. The latter were not
reached in the ZIP and 7z measurements. The proposed `verifier-proofs.patch` narrows the
change to the verifier table. `proofs-experiment.patch` retains the broader prototype.

The `proof` mode contains only the doubt-only experiment, which did not show a useful gain.
The `sum` and `hints` modes are unranked experiments: an ASCII TAR checksum branch and a
rewrite of range validation. They are retained as measurement provenance, not proposals.
The `all` mode enables them along with the shared proof and ratio changes. The fixture
writer's CAB path did not call the range-validation method, so its isolated microbenchmark
is not a CAB end-to-end saving.

## Callgrind

Install Valgrind separately, then run each mode in one-run and three-run processes:

```bash
for mode in none ratio proof8; do
  for count in 1 3; do
    valgrind --tool=callgrind \
      --callgrind-out-file="$ROUND2_DIR/$mode-$count.cg" \
      .venv/bin/python "$S/cg.py" "$mode" zip_stream "$count"
  done
done
```

`cg.py` performs one warm-up operation and then freezes/disables GC before the requested
number of operations. For each mode, take `(three.summary - one.summary) / 8000`.
Repeat the unchanged mode as a control. Report variability; do not treat small instruction
count differences as exact production percentages. The original run used Valgrind 3.24.0.

## CAB experiment

Apply only the CAB patch to the pinned source. The scripts capture its patched method and
compare it with the original method compiled from the pinned revision. Both variants use
the extended table construction; the comparison isolates elimination of repeated prefix
scans. The table-construction CPU experiment measures that added bookkeeping separately.

```bash
git apply "$R/patches/cab-prefix.patch"
.venv/bin/python "$S/final_extra.py" cab
.venv/bin/python "$S/cab_differential.py"
.venv/bin/python "$S/cabmicro.py"
for mode in old new; do
  for count in 1 3; do
    valgrind --tool=callgrind \
      --callgrind-out-file="$ROUND2_DIR/cab-$mode-$count.cg" \
      .venv/bin/python "$S/cabexperiment.py" "$mode" "$count"
  done
done
```

For CAB, use the same `/8000` instruction difference. The differential script checks 42
public-operation trace pairs and 256 checksum-presence vectors. Its extra checksum and
truncation variants are crafted intentionally. `cabmicro.py` uses synthetic block headers
to isolate table construction, rather than claiming a real-producer end-to-end measurement.
Its `index_size` printout is the last timed table's field, which can belong to the old
implementation; do not use that field to infer the memory delta. The additional tuple slot
is eight bytes on this interpreter, and retaining a non-shared integer can add 28 bytes.

Restore runtime code after measuring:

```bash
git apply -R "$R/patches/cab-prefix.patch"
```

## Focused validation

The plugin reproduces the shared `all` experiment, including the two unranked experiments.
The first two runs below were recorded before applying the CAB source patch. This is the
historical validation configuration, not a claim that tests have independently validated
each proposal or that the full matrix is complete.

```bash
./scripts/test.sh -n 2 --no-cov -p round2_plugin \
  tests/test_stream_verify.py tests/test_verifier_seek_paths.py \
  tests/test_verification_contract.py tests/test_member_read_ratio.py \
  tests/test_tar_parser.py tests/test_diagnostics.py tests/test_nest_limits.py \
  tests/test_member_reads_full_count.py
./scripts/test.sh -n 2 --no-cov -p round2_plugin \
  tests/test_format_api.py tests/test_remote_benchmark.py \
  tests/test_tar_parser_differential.py tests/test_sevenzip_verification_levels.py \
  tests/test_sequential_verification_levels.py tests/test_tar_verification_levels.py

git apply "$R/patches/cab-prefix.patch"
./scripts/test.sh -n 2 --no-cov -p round2_plugin tests/test_cab.py
git apply -R "$R/patches/cab-prefix.patch"
```

The recorded results were 711 passed/11 skipped, 277 passed, and 189 passed/9 skipped.
The remote tests included the pinned planner request ceilings. A production change still
needs its own regression tests, full required checks and review.

## Evidence

- [Primary timing samples](results/baseline.jsonl).
- [Restart toggles, stdlib peers and extraction-only samples](results/extra.jsonl).
- [Interleaved candidate timing samples](results/paired-patches.jsonl).
- [Callgrind totals and per-member differences](results/instructions.json).
- [cProfile summaries](results/cprofile.json) and [sampling summaries](results/sampling.json).
- [Isolated CPU measurements](results/micro.txt) and [CAB table CPU data](results/cab-table-cpu.jsonl).
- [CAB trace comparison](results/cab-differential.json).
- [Shared tests](results/tests-shared.log), [format/remote tests](results/tests-formats-remote.log)
  and [CAB tests](results/tests-cab.log).

Generated multi-megabyte Callgrind traces and Speedscope traces are not committed. Regenerate
them with the commands above. cProfile and sampling summaries retain the measured hotspots;
raw timing samples and instruction totals retain the quantitative comparisons.
