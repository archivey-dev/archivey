# Linux full-suite heap corruption: CI bandage and soak recipes

Lab notes for the [`known-issues.md`](../known-issues.md) entry "Intermittent Linux
full-suite heap corruption". The entry holds the symptom and the suspects; this page holds
how CI works around it, how to reproduce it, and the recorded red runs.

## CI bandage (not a root-cause fix)

The required `[all]` and `[all-lowest]` jobs in `.github/workflows/ci.yml` split the suite
into four steps, each with `PYTHONFAULTHANDLER=1`:

```text
# 1) Main suite on every core, without Hypothesis and the dedicated accelerator/PPMd
#    stream modules (--no-cov on every leg but ubuntu py3.14 [all])
pytest tests/ \
  --ignore=tests/test_property_safety.py \
  --ignore=tests/test_rapidgzip_deflate_zlib.py \
  --ignore=tests/test_accelerator_shutdown.py \
  --ignore=tests/test_accelerator_corruption.py \
  --ignore=tests/test_ppmd_raw_streams.py -q -n auto --no-cov

# 2) Accelerator stream modules, one fresh subprocess each (coverage off, breadcrumbs)
python scripts/ci/ci_run_native_modules.py

# 3) PPMd raw streams in their own subprocess (coverage off); soft-passes an
#    exit-after-green abort of the parent (see the pyppmd entry in `known-issues.md`)
python scripts/ci/ci_run_native_modules.py \
  --modules tests/test_ppmd_raw_streams.py \
  --allow-exit-after-green

# 4) Hypothesis property-safety
pytest tests/test_property_safety.py -q -n auto --no-cov
```

Steps 1 and 4 apart stop a corrupted main-suite heap from taking down Hypothesis, and the
reverse. Step 2 keeps the heaviest in-process accelerator paths out of the long suite; the
modules run one per child because a single multi-module process aborted on Ubuntu with
every test green, during `coverage.collector.flush_data` / GC (`corrupted size vs.
prev_size`, exit 134). Step 3 is covered in the `known-issues.md` exit-after-green entry. The main suite
still exercises natives (`AUTO` and `SEEKABLE` paths, the py7zr/PPMd corpus), so this is CI
hygiene, not a product fix.

## How to reproduce or bisect

Use a rate and A/B runs:

```bash
# Match CI (Linux preferred; uv's standalone CPython). The serial baseline below keeps
# pytest-cov on via addopts, as CI ran before 2026-10-02; the bandage shape matches CI now.
uv python install 3.11
uv sync --group dev --extra all

# 1) Baseline soak: expect a rare exit 139/134, not every run
for i in $(seq 1 20); do
  uv run --python 3.11 --no-sync pytest tests/ -q \
    || { echo "FAILED pass $i rc=$?"; break; }
done

# 2) The CI shape, not step 1's A/B partner: it differs from step 1 in the --ignore set
#    AND in running the main suite as four short-lived xdist workers without coverage.
#    A heap corruption that needs the whole suite in one long-lived process may not show
#    there at any rate, so a clean 20/20 does not credit the --ignore set. For the A/B,
#    run step 1 again with the same --ignore set (serial, coverage on).
for i in $(seq 1 20); do
  uv run --python 3.11 --no-sync pytest tests/ \
    --ignore=tests/test_property_safety.py \
    --ignore=tests/test_rapidgzip_deflate_zlib.py \
    --ignore=tests/test_accelerator_shutdown.py \
    --ignore=tests/test_accelerator_corruption.py \
    --ignore=tests/test_ppmd_raw_streams.py -q -n auto --no-cov \
    || { echo "main FAILED pass $i rc=$?"; break; }
  uv run --python 3.11 --no-sync python scripts/ci/ci_run_native_modules.py \
    || { echo "accelerators FAILED pass $i rc=$?"; break; }
  uv run --python 3.11 --no-sync python scripts/ci/ci_run_native_modules.py \
    --modules tests/test_ppmd_raw_streams.py \
    || { echo "ppmd-raw FAILED pass $i rc=$?"; break; }
  uv run --python 3.11 --no-sync pytest tests/test_property_safety.py -q -n auto \
    --no-cov || { echo "property FAILED pass $i rc=$?"; break; }
done

# 2b) Hard soak of the PPMd raw-streams exit abort (the stress workflow's step)
uv run --python 3.11 --no-sync python scripts/ci/ci_run_native_modules.py \
  --modules tests/test_ppmd_raw_streams.py --repeat 20

# 3) A/B without rapidgzip; if crashes vanish, rapidgzip is implicated
uv run --python 3.11 --no-sync pip uninstall -y rapidgzip
# re-run soak (1); restore with: uv sync --group dev --extra all

# 4) A/B without pyppmd
uv run --python 3.11 --no-sync pip uninstall -y pyppmd
# re-run soak (1)
```

Set `PYTHONFAULTHANDLER=1`, log the last few nodeids before death (the stacks are late),
and compare against a red job's `Fatal Python error` and `Extension modules:` lines.

## Recorded red runs

All during the gzip/zlib truncation-recovery work in 2026-07:

- `29829920415`: Ubuntu py3.11/3.12 `[all]` SIGSEGV in Hypothesis charmap GC.
- `29836095815`: Ubuntu py3.11 SIGSEGV and py3.13 SIGABRT, still in Hypothesis.
- `29836326565`: with property-safety split out, Ubuntu py3.11 SIGSEGV during RAR
  multi-volume `open_unrar_p` GC in the main suite, so Hypothesis isolation alone is not
  enough.
- `29969446114`: Ubuntu py3.11/3.14 `[all]` SIGSEGV at about 63% (GC during fixture setup,
  `test_rar_oracle` importing `rarfile`/`cryptography`), right after
  `test_ppmd_raw_streams` and `test_rapidgzip_deflate_zlib` in collection order. This one
  motivated the accelerator and PPMd-stream process split.

## Next steps

Get a soak rate under recipe (1), then A/B without rapidgzip (3). If
rapidgzip is implicated, shrink to a subprocess loop that uses it the way the suite does
(path or `BytesIO`, truncated members, close or GC), starting from
`scripts/investigations/dual_accelerator_repro.py` and `tests/test_accelerator_shutdown.py`. If only the
long mixed suite flakes, treat it as CI hygiene (more process isolation, or a coverage or
accelerator policy on Linux). Do not fold this into the PPMd stress workflow without a
rapidgzip and long-suite axis; that job would stay green while this stays open.
