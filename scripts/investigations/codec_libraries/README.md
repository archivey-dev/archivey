# Codec library experiments

These scripts are investigation tools, not archivey backends or CI parity gates.
They import archivey from this checkout and need its development dependencies.

```sh
uv sync --group dev --extra all
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/differential.py --output work/codec-diff
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/bench.py --output work/codec-bench
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/probes.py --output work/codec-probes
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/replay.py --all
uv run python scripts/investigations/codec_libraries/metadata.py \
  --output work/codec-metadata
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/upstream_corpus.py --download \
  --sources work/upstream --output work/upstream-corpus
```

Run on Linux for `resource` limits and `/proc/self/status` RSS observations.
The differential parent watches each child for 60 seconds; children have a 1 GiB
address-space ceiling and 45 CPU seconds. Memory probes use a 1 GiB ceiling too.
Use the default `CRAMJAM_BACKEND=c`. Other runtimes and builds need their own results.
Run timings without other CPU-heavy work. No script runs an upstream build hook.

- `common.py`: deterministic payloads, compressed/archive producers and minimal
  adapters. It disables archivey accelerators. A callback adapter is push output over
  complete input, not incremental input. Hardlink resolution and metadata normalization
  are deliberately absent; the report distinguishes their differences from codec
  failures.
- `differential.py`: valid input, strict prefixes, seeded flips and framing cases.
  Every observed acceptance/output difference is saved with exact input bytes.
  Exit zero means the experiment completed, not that parity holds.
- `bench.py`: median of five valid decodes, 4 KiB and 8 MiB generated payloads, plus
  committed real-producer fixtures. Both whole-result and chunk/callback paths are
  measured. Failed incremental calls are results, not replaced by whole-buffer calls.
  `--memory-only` runs fresh-process 16 MiB zero-output probes without replacing
  timings.
- `probes.py`: half-input decoding, output sizing, actual checksum-field mutations,
  legacy LZ4, hostile ZIP names, valid 7z/Brotli and the valid PPMd refusal.
  `--sevenzip /path/to/7zz` independently checks the latter without filesystem
  extraction.
- `metadata.py`: pinned-release PyPI artifacts, hashes, release dates, all locked
  registry crate license declarations and the crates.io unpackio lookup. This inventory
  includes build/test/disabled-feature dependencies and is not a linked-object license
  audit.
- `upstream_corpus.py`: executes unpackio's 23 binding tests with input capture, then
  cross-reads the captured archives, four Rust ARJ fixtures, and cramjam integration and
  completed flush streams. `--download` fetches and verifies pinned sdists; it runs no
  build hooks but does execute upstream Python test code. Use trusted release sources.
- `runtime_probe.py`: interpreter, import time and GIL state, for example with
  `uv run --no-project --python 3.14t --with cramjam==2.14.0 python ... --library cramjam`.
- `replay.py`: reads the saved `results/differences.zip` directly, without extracting
  paths. `--match` selects a repro and `--all` checks every saved difference. Exit one
  means acceptance, output hash or exception class changed from the recorded result.

`results/` contains the measured snapshot. `differences.zip` holds every differing input
and a JSON record with both outcomes. Its paths name library, family, mutation and
offset. `repros/` contains small individual examples and explicit checksum/name probes.
A larger input uses sampled cuts; matching outcomes are not a full grammar proof. The
comparison includes only concatenated regular/hardlink payload bytes, not every metadata
field or extraction behavior.

Generated payloads and mutations are authored for this investigation. Fixture-derived
repros name their family and original fixture stem; the source archives and provenance
remain under `tests/fixtures/`. Additional upstream fixtures come only from the two
hash-pinned release sdists. `results/upstream-corpus.zip` preserves their exact input
bytes and license notices.

See the [report](../../../dev-docs/investigations/codec-libraries-cramjam-unpackio.md)
for recommendations, scope, caveats and interpretation.

For the support/refusal triage, pass `--cpio /path/to/cpio` to `upstream_corpus.py`. It
lists mixed, padded and uniform-newc controls with GNU cpio, without extracting names.
The saved support-triage observations are in `results/upstream-corpus.json`. The 7-Zip
oracle was built with `scripts/ci/install-7zip-from-source.sh` into a workspace tool
directory. It is not bundled with these scripts or added to archivey's dependencies.
