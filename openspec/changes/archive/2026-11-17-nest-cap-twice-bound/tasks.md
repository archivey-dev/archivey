## 1. Documentation

- [x] 1.1 `DecoderLimits.max_nest_decoded_bytes`, `NestDraws`, `BudgetDrawStream` and `docs/security.md` state the bound a caller can size by: on one thread, about twice the cap at any depth, and what a child's stricter cap does not hold

## 2. Tests

- [x] 2.1 `tests/test_nest_limits.py::test_a_nest_three_levels_deep_decodes_at_most_twice_its_cap`: three levels, one `read()`, at most twice the cap plus one byte counted

## 3. Archive

- [x] 3.1 `openspec validate nest-cap-twice-bound --strict`, then `openspec archive nest-cap-twice-bound --yes`
