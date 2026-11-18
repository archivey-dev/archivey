## 1. Reader

- [x] 1.1 `text_codecs.py`: refuse every uuencode line over `_MAX_LINE`, with or without its newline; `_find_header` stops at one
- [x] 1.2 A begin-line pattern with no lazy group, matched after trailing whitespace is stripped

## 2. Tests

- [x] 2.1 `tests/test_text_codecs.py`: a long line refused with its newline; no line over the cap reaches the regex; the names `begin` lines give

## 3. Archive

- [x] 3.1 `openspec validate uu-line-cap`, then `openspec archive uu-line-cap --yes`
