# Exploration scripts

## Alternative RAR decompressors

`rar_decompressor_matrix.py` compares `unar` / `7z` / `bsdtar` / `unrar-free` against
RARLAB `unrar p` on the committed RAR fixtures. Evidence for
`dev-docs/investigations/alternative-rar-decompressors.md`.

Stdlib-only. Missing tools are skipped. Subprocesses use `stdin=DEVNULL`, a
timeout, and a stdout byte cap (`bsdtar --to-stdout` on stored nonsolid is a
normal row: `output cap exceeded`, not a skip).

```bash
python3 scripts/exploration/rar_decompressor_matrix.py
python3 scripts/exploration/rar_decompressor_matrix.py --json /tmp/matrix.json
```

## Brotli content probe — field survey

`brotli_probe_field_survey.py` collects the evidence
`dev-docs/investigations/brotli-content-probe-results.md` is thinnest on: PE/DOS header
shapes across real toolchains (especially the `e_lfanew` maximum), the WBITS values real
Brotli streams use, and how often the content probe claims ordinary files.

Stdlib-only and Python 3.8+, so it runs on a bare system interpreter — no venv, no
archivey, on whatever machine you point it at. Read-only; it writes one JSON report and
uploads nothing. Names are basenames by default (`--no-names` / `--full-paths` to change
that).

```bash
python3 scripts/exploration/brotli_probe_field_survey.py --self-test
python3 scripts/exploration/brotli_probe_field_survey.py            # system roots
python3 scripts/exploration/brotli_probe_field_survey.py ~/Downloads --out report.json
```

Windows and macOS runs are the valuable ones — the results doc was measured entirely on
one Linux container.

## Brotli meta-block chains — consecutive uncompressed blocks

`brotli_block_chain_survey.py` supports
`dev-docs/investigations/brotli-uncompressed-block-runs.md`, which asked whether the
completeness gate's chain walk could collapse to a single fixed test ("the meta-block after
the first must be compressed"). It cannot: consecutive uncompressed meta-blocks are the
normal shape for incompressible input, and the shortest counterexample is a 13-byte stream.

The script rebuilds both halves of that trade — false negatives on valid streams, false
positives on random blobs — importing the real gate rather than a copy. It needs the
`Brotli` binding and archivey importable; the two comparison columns only appear on a
checkout that has the chain walk.

```bash
python3 scripts/exploration/brotli_block_chain_survey.py
python3 scripts/exploration/brotli_block_chain_survey.py --scan ~/fonts /usr/share
```

Pointing `--scan` at a machine with a different font or `.br` population is the useful
variation — the results doc's real-world corpus was 1717 WOFF2 streams from npm.

## Content-probe residual — census on a real tree

`probe_residual_census.py` measures what the framing, completeness and chain-walk gates
left behind: how often a content probe still claims a file that is not that format, which
probe claims it, at what confidence, whether anything corroborated the claim, and whether
a later decode failure would carry a `format_unconfirmed` signal. It is the source of the
residual numbers in `dev-docs/investigations/brotli-content-probe-results.md` and the
`0 of N carry no signal` line in `dev-docs/threat-model.md`.

Like the chain-walk survey, it **imports the real predicate rather than a copy** — the
stamp column comes from `archivey.core._format_provenance(...).probe_only`, not a local
restatement of the rule. That is the point of the script: the previous confidence-keyed
rule left 53% of fabrications unsignalled, and this census is what found it. It also
cross-checks the stamp against `FormatInfo.corroborated` and shouts if the two drift.

Read-only: it opens files, reads at most `DETECTION_LIMIT` bytes for the probe, and reads
whole files only to verify genuineness. Nothing is written.

```bash
uv run python scripts/exploration/probe_residual_census.py            # system roots
uv run python scripts/exploration/probe_residual_census.py ~/Downloads
```

`uv run` matters — the probes and the verification step both need the optional `brotli`
decoder importable. A tree with real `.br` assets (web caches, font directories) is the
useful variation; `/usr` has almost no genuine Brotli.

## ZipCrypto disambiguation — exploration notes

Scripts supporting
`openspec/changes/zip-multipassword-disambiguation` tasks 1.1 and 1.3.

| Script | Purpose |
|--------|---------|
| `zipcrypto_codec_rejection.py` | How quickly stdlib DEFLATE / BZIP2 / LZMA reject random and wrong-key ZipCrypto plaintext |
| `zipcrypto_compressibility_probe.py` | Historical calibration of a STORED compressibility probe (investigated, then **dropped** — see `design.md`) |

```bash
uv run --no-sync python scripts/exploration/zipcrypto_codec_rejection.py
uv run --no-sync python scripts/exploration/zipcrypto_compressibility_probe.py
```

Findings are recorded in
`openspec/changes/zip-multipassword-disambiguation/design.md`
(section **Investigation findings**). Runtime STORED confirmation uses a shared CRC
pass only; the compressibility script is kept as a record, not as a live dependency.

## Capability declaration vs behaviour

`capability_declaration_sweep.py` observes whether each corpus format delivers
what it declares (`member_streams`, `CostReceipt` vs `io_stats()`, `ArchiveInfo`,
stream lifetime). Evidence for
`dev-docs/investigations/capability-declaration-vs-behaviour.md`.

It imports the real corpus (`CORPUS` / `corpus_archive_path` /
`skip_unless_runnable`) rather than a third fixture list. Skips are
`UNTESTED`, never `OK`. `--compare` diffs verdicts against the committed
JSON snapshot; seek-count drift is printed, not a failure. Encrypted and
packed RAR rows, and zip-aes, are required to run (exit 3 if skipped) so
a stored-only RAR matrix cannot look green. Holes are not xfailed.

```bash
uv run --no-sync python scripts/exploration/capability_declaration_sweep.py
uv run --no-sync python scripts/exploration/capability_declaration_sweep.py --compare
uv run --no-sync python scripts/exploration/capability_declaration_sweep.py --write-snapshot
```

## Writer timestamp slots — ZIP and 7z creation times

`probe_writer_timestamps.py` archives one file with every ZIP/7z writer it finds
(7-Zip, p7zip, Info-ZIP, libarchive `bsdtar`, `ditto`, `Compress-Archive`, the Explorer
shell) and labels each stored time as the source file's birth, ctime, mtime or atime.
Evidence for `dev-docs/investigations/writer-timestamp-slots.md`. Needs archivey
importable (for the 7z header parser); missing writers are reported as skipped.

```bash
uv run python scripts/exploration/probe_writer_timestamps.py
uv run python scripts/exploration/probe_writer_timestamps.py --out /tmp/archives --json /tmp/probe.json
```

The Linux/macOS/Windows matrix runs in CI: the `Writer timestamp probe` workflow
(`.github/workflows/writer-timestamps.yml`) on demand from the Actions tab, and on PRs
that change the probe.

## rapidgzip on this platform

`rapidgzip_platform_probe.py` measures rapidgzip against zlib in process (from a path and
from a `BytesIO`, at several `parallelization` values, with the index point count), then a
full read through archivey with `use_rapidgzip` OFF, ON and AUTO. Evidence for where
`AUTO` takes a sequential read (`dev-docs/formats/gzip.md` §2.3, which has the Windows
run). Needs the dev environment; read-only apart from a temporary directory.

```bash
uv run python scripts/exploration/rapidgzip_platform_probe.py --json probe.json
```
