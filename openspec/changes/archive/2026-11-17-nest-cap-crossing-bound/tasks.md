## 1. Documentation

- [x] 1.1 `DecoderLimits.max_nest_decoded_bytes`, `NestDraws` and `BudgetDrawStream` state the bound across levels: the crossing read can pass the cap by the bytes the outer levels decode to fill it
- [x] 1.2 `docs/security.md` says the same for the nest cap

## 2. Tests

- [x] 2.1 `tests/test_nest_limits.py::test_a_nested_crossing_read_passes_the_cap_by_its_own_bytes`: a stored ZIP inside a deflated ZIP, read in 65 536-byte steps under a cap, raises and counts at most the cap plus one step plus one byte

## 3. Archive

- [x] 3.1 `openspec validate nest-cap-crossing-bound --strict`, then `openspec archive nest-cap-crossing-bound --yes`
