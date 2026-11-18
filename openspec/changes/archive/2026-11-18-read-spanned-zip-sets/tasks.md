## 1. Reader

- [x] 1.1 `zip_parser.py`: `read_end_record(disk_starts=)` moves the directory's, the ZIP64 record's and each entry's `(disk, offset)` into the join; `SpannedPartsError` when the part count differs; `spanned_disk_count` for discovery
- [x] 1.2 `zip_reader.py`: pass the joined source's part starts; a missing part is a plain `TruncatedError`, not damage the local headers list past
- [x] 1.3 `volumes.py`: discover a `zip -s` set from the `.zip` or any `.zNN`, name missing parts, join it
- [x] 1.4 `core.py`, `zip_detect.py`: a lone part is `TruncatedError`

## 2. Tests

- [x] 2.1 `tests/test_zip_spanned.py`: a real `zip -s` fixture against 7-Zip; synthesized sets cut anywhere, classic and ZIP64, past `.z99`; missing parts, a lone `.zip`, strays, damage

## 3. Docs

- [x] 3.1 `dev-docs/formats/zip.md`, `dev-docs/IDEAS.md`, the life-of-an-open guide

## 4. Archive

- [x] 4.1 `openspec validate read-spanned-zip-sets`, then `openspec archive read-spanned-zip-sets --yes`
