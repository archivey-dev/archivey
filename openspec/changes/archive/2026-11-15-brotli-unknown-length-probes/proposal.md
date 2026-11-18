## Why

Brotli detection skips its framing walk on an unknown-size source. A 105,001-byte
fabrication declaring a 485,963-byte literal block is rejected from `BytesIO` but
accepted through an unknown-size wrapper. Pipes need a separate work policy:
reaching a distant header consumes the intervening bytes and can wait for input.

## What changes

- Walk unknown-size sources using EOF evidence from bounded range reads.
- Add `DetectionBudget.max_probe_forward_bytes`: 0 by default and under `FAST` /
  `BALANCED`, 1 MiB under `THOROUGH`. Already-buffered bytes stay available.
- Preserve existing seekable-source checks: cheap header seeks at any offset and
  bounded read-ahead on expensive-seek sources. Apply the new allowance only to
  forward-only sources. Preserve the verdict when checking is declined.
- Avoid waiting for optional bytes after a complete stream on a held-open pipe.

## Impact

`format-detection` and `detection-cost`. No codec dependency or decoder change.
The default pipe can retain an uncertain match that a cheap-seek source disproves.
Literal sizes and entropy are not rejection criteria.
