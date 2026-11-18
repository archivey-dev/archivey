# Snappy framing experiment

Programs behind [the comparison
report](../../../dev-docs/investigations/snappy-framing-backends.md). They exercise
archivey's own Snappy framing (`src/archivey/internal/streams/codecs/snappy_framed.py`)
with each raw-block backend.

Install the candidates and the fuzzer into the development environment; the system
Google Snappy library (`libsnappy.so.1`) is the independent raw oracle:

```sh
uv pip install cramjam==2.14.0 compress-utils==0.12.1 google-crc32c==1.9.0 "atheris>=3.0.0,<3.1"
```

```sh
uv run --no-sync python scripts/investigations/snappy_framing/compare.py all scripts/investigations/snappy_framing/results
scripts/investigations/snappy_framing/campaign.sh 25 work/snappy-fuzz raw framed
```

`compare.py` parts: `correctness` (four producers x four payloads x three sizes, read
through `open_stream`), `mutations` (cuts, bit flips, byte changes and tails, each
backend fed two ways, against a framing reference around Google Snappy), `speed`,
`memory` (peak RSS of a 64 MiB read in a child) and `stability` (RSS growth over 200,000
refused blocks, four threads decoding at once). Run `speed` on an idle host.

`fuzz.py` targets: `raw` compares both backends with Google Snappy and a strict Python
decoder on one raw block; `framed` compares both backends, each fed two ways, with the
reference framing. Disagreements go to `WORKDIR/findings/`; a native crash leaves
`crash-*` in `WORKDIR`, and `campaign.sh` restarts the target.
