# `lzfse` package evaluation (DMG plan, Part A0)

Investigation tools, not archivey code or CI gates. The write-up is
[`dev-docs/investigations/lzfse-package.md`](../../../dev-docs/investigations/lzfse-package.md).
They need only an interpreter with `lzfse` installed; the prototype decoder comes from
`openspec/changes/archive/2026-11-27-dmg-reader/resources/prototype/`. Run on Linux
(`resource` limits).

- `common.py`: block walk, the capped and checked ways to call the package, the raw
  LZVN wrapper, and the import of the prototype.
- `probes.py`: API facts (empty stream, short inputs, raw LZVN, bombs, double decode),
  each risky one in a child under an address-space limit (`PROBE_LIMIT_GIB`, default 1).
- `agreement.py [IMAGE.dmg ...]`: the package against the prototype on every LZFSE run
  and LZVN decmpfs chunk of the fixtures, and on each LZFSE run of extra images.
- `bench.py IMAGE.dmg`: per-run cost in process and in a long-lived child over a pipe.
- `fuzz.py CASES [SHARDS] [OUT.json]`: differential fuzz in restartable shard processes;
  raw per-case records go to `results/fuzz-work/` (not committed).
- `classify.py`: sorts the fuzz run's differences by cause.

`results/` holds the output of the 2026-11-21 run.
