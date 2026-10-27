# Coverage-guided fuzz (Atheris)

Atheris lives in the PEP 735 `fuzz` dependency group (`atheris`) and runs via
`.github/workflows/atheris-fuzz.yml` — same shape as the benchmark wall split:

- **Every PR:** short partitioned budgets over all targets (blocks the PR; sharded
  across parallel jobs because each target pays a large Atheris cold-start).
- **Nightly schedule:** full partition, but only if default-branch HEAD moved in the
  last ~3 days (commit-recency guard; dormant stretches skip the expensive run).
- **`workflow_dispatch`:** force the full partition (optional `budget_scale`).

The four accelerator targets (`gzip_accel`, `zlib_accel`, `deflate_accel`,
`bzip2_accel`) get only 1 to 2 seconds each there on a pull request and 10 to 15 on the
nightly. `.github/workflows/accelerator-fuzz-soak.yml` runs them again once a week for 20
minutes each, one runner per target, and keeps each target's corpus in the Actions cache
so the next run starts from it (`workflow_dispatch` takes `seconds`). GitHub evicts a
cache entry unread for 7 days, and a weekly run reads it with only minutes to spare, so a
cold start from the seeds is common; the carry-forward is best effort.

Mutation fuzz (`tests/test_mutation_fuzz.py`) and `ARCHIVEY_FUZZ=1` /
`tests/fuzz_sevenzip_parser.py` / `tests/fuzz_rar_parser.py` stay as they are.

Local smoke (Linux; needs corpus fixture builders). Prefer Python 3.12 for current
Atheris wheels; on 3.11 `uv` resolves `atheris` 3.0.x:

```bash
uv sync --group fuzz --group dev --extra all
uv run --no-sync python -m tests.atheris_fuzz --smoke

# or explicitly:
uv sync --python 3.12 --group fuzz --group dev --extra all
uv run --python 3.12 --no-sync python -m tests.atheris_fuzz --smoke
```

Deepen one target (budget seconds via env, e.g. `ARCHIVEY_FUZZ_BUDGET_SEVENZIP_HEADER=60`,
`ARCHIVEY_FUZZ_BUDGET_ZIP=60`, `ARCHIVEY_FUZZ_BUDGET_OPEN_DETECTED=60`, or
`ARCHIVEY_FUZZ_BUDGET_FILTERS=60`):

```bash
uv run --no-sync python -m tests.atheris_fuzz --target sevenzip_header
uv run --no-sync python -m tests.atheris_fuzz --target zip
uv run --no-sync python -m tests.atheris_fuzz --target open_detected
uv run --no-sync python -m tests.atheris_fuzz --target filters
```

`open_detected` opens whatever `detect_format` names (SFX payload offset, single-file
readers, compressed tar, UDIF refusal). `filters` feeds BCJ2, ARM64, RISC-V, Delta and
the liblzma branch filters directly. The TAR target recomputes header checksums before
parsing. 7z, RAR and ISO open targets read a few member payloads, and the ZIP target
also opens the same bytes as a pipe.

On a crash the harness writes the input under `artifacts/atheris/` and prints a one-line
repro command.
