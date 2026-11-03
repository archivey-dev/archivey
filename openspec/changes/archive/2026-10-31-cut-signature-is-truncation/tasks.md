## 1. Readers

- [x] 1.1 `sfx.is_cut_signature` and `sfx.cut_signature_error`, shared by the three readers
- [x] 1.2 ZIP (`zip_local_walk`), 7z (`find_signature_offset`) and RAR (`_find_sfx_header`) raise it for a cut signature at the start

## 2. Tests

- [x] 2.1 `tests/test_sfx.py`: the two helpers; every cut length of each signature, an empty file included; the forward ZIP reader; bytes that are not a cut signature, a stub before one included, stay `CorruptionError`
