## 1. Implementation

- [x] 1.1 `PrefixWorkspace.decoder_limits` and `ContentProbe(decoder_limits=)` carry the caller's `DecoderLimits` into every detection decode; `probe_config` keeps them
- [x] 1.2 LZMA-family probes check the clamped dictionary; lzop and mozlz4 probes check the cap under their probe ceilings; zstd's probe window is the smaller of the cap and 2^27
- [x] 1.3 A refused probe is "can't tell", recorded and logged at INFO
- [x] 1.4 Tests in `tests/test_detection_decoder_limits.py`
- [x] 1.5 Handbooks, threat model and `DecoderLimits` docstring
- [ ] 1.6 `openspec validate --strict detection-respects-decoder-limits`, then `openspec archive detection-respects-decoder-limits --yes` once davi settles the diagnostic-or-log question
