## 1. Decoder

- [x] 1.1 `StreamConfig.excluded_methods` from `FormatPolicy.exclude`, and the detection workspace's copy
- [x] 1.2 `xz_decoder.py`: `_XzFilterGuard` reads every block header before liblzma is fed it, on the sequential and the block-resume engine; the probe's `_head_filter_chain` refuses the same filters

## 2. Tests

- [x] 2.1 `tests/test_format_policy_methods.py`: BCJ and Delta in a `.xz`, a later block, a later stream, a ZIP member, a `.tar.xz`, a `.deb`, a resume, the probe; the guard fed in pieces; hostile block headers

## 3. Archive

- [x] 3.1 `openspec validate xz-filter-exclude`, then `openspec archive xz-filter-exclude --yes`
