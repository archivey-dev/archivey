# Snappy and compress-utils experiments

Read the
[report](../../../dev-docs/investigations/codec-libraries-snappy-compress-utils.md) for
recommendations, measured results and limits. These programs do not change archivey's
runtime registry. A completed differential run can contain failures of parity: its JSON
is the result, not a green integration test.

Use Linux for `resource`, `/proc` RSS and watchdog measurements. Start from an
archivey development checkout with the normal dependencies:

```sh
uv sync --group dev --extra all
```

The independent raw Snappy oracle needs system Google Snappy (`libsnappy.so.1`,
version 1.2.2 on the measured host). LZO benchmark input production needs liblzo2
2.10. Neither is used as a candidate implementation. If liblzo2 is outside the
system loader path, set `LZO_PRODUCER_LIBRARY` to its absolute shared-library path.
Install those system libraries with your platform's package manager. Avoid mixing
aff4-snappy and python-snappy in one environment: both import as `snappy`.

Use this shell function to keep the exact candidate versions in an ephemeral uv
environment, with optional canonical references present:

```sh
run_candidates() {
  uv run --no-sync --with cramjam==2.14.0 \
    --with compress-utils==0.12.1 --with python-snappy==0.7.3 \
    --with py-snappy==0.1.0a1 --with python-snappy-pure==0.2.0 \
    --with pysnappy==0.8.2 --with zstandard==0.25.0 --with hypothesis \
    "$@"
}

uv run python scripts/investigations/snappy_compress_utils/metadata.py \
  --output work/snappy-upstream --download-sources
run_candidates python scripts/investigations/snappy_compress_utils/differential.py \
  --output work/snappy-diff --sources work/snappy-upstream/compress_utils-0.12.1
run_candidates python scripts/investigations/snappy_compress_utils/bench.py \
  --output work/snappy-bench
run_candidates python scripts/investigations/snappy_compress_utils/probes.py \
  --output work/snappy-probes
run_candidates python scripts/investigations/snappy_compress_utils/upstream.py \
  --sources work/snappy-upstream --output work/snappy-upstream-results
run_candidates python scripts/investigations/snappy_compress_utils/archivey_corpus.py \
  --output work/archivey-candidate-corpus
```

The source test runner uses installed candidate modules, not an unbuilt extension
from a source tree. It captures successful compress-utils one-shot encodings and
cross-decodes them with archivey or Google Snappy. Its saved test log contains any
skips. It replays C fuzz payloads, not full C test binaries or sanitizer suites.
The archivey LZO runner returns the original decoder's result while recording the
candidate's result. Its observed baseline tests passing does not mean the candidate
passed; inspect `differences`.

The py-snappy sdist omits its tests and Google corpus. Read the pinned repository:

```sh
git clone https://github.com/ethereum/py-snappy work/py-snappy-repo
git -C work/py-snappy-repo checkout f91082fa1498ed919ef26bd853a4552675c9665a
run_candidates python scripts/investigations/snappy_compress_utils/corpus.py \
  --py-snappy-repo work/py-snappy-repo --output work/snappy-corpus
```

Each corpus decode has a 10-CPU-second budget and 15-second parent watchdog. A worker
termination is recorded separately from accepting or refusing data. The full upstream
py-snappy pytest run was also attempted with 160 CPU seconds and did not complete.
Its focused error-parity failure is recorded in `results/py-snappy-error-test.log`.
Do not change an upstream test to make a candidate pass.

To replay the committed repro collection without downloading source fixtures:

```sh
run_candidates python scripts/investigations/snappy_compress_utils/replay.py --all
```

A replay checks recorded acceptance, complete-output hashes and error classes.
Error messages can change across platform builds. It does not write extracted files
or replace any archivey decoder. `results/differences.zip` stores every matrix
parity break, including stricter refusal; the small targeted inputs are in `repros/`.
The four `lzo-*.bin` files exercise archivey's accepted alternate end markers.

The failed aff4-snappy build can be retried separately:

```sh
uv run --no-project --python 3.11 --with aff4-snappy==0.5.1 python -c 'import snappy'
```

The free-threaded probe uses the same four packages that have compatible artifacts:

```sh
uv run --no-project --python 3.14t --with compress-utils==0.12.1 \
  --with python-snappy==0.7.3 --with cramjam==2.14.0 \
  --with py-snappy==0.1.0a1 --with python-snappy-pure==0.2.0 \
  python scripts/investigations/snappy_compress_utils/runtime_probe.py
```

`collect.py --work work` copies completed run files into this directory and builds
the differential ZIP. It expects the recorded build/test logs and free-threaded JSON
as well as the program outputs. It does not rerun experiments. Use `--destination`
to collect another run without replacing the committed evidence.

Benchmark ratios include wrapping overhead and cache effects. The bounded C API
prototype uses ctypes and is Linux-wheel-tested only. It does not implement full
production exception mapping, decoder-memory preflight or process isolation.
The normal native one-shot/Python streaming APIs remain separate measurements.
