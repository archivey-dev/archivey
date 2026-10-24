## 1. Reader

- [x] 1.1 `_DeflateEndCheckStream` decodes the tail from the newest rapidgzip resume point under `refuse_input_after_end` too, not the whole stream from its start

## 2. Tests and docs

- [x] 2.1 ZIP and 7z tests pin both sides: a short second stream is refused under rapidgzip, a long one whose size and CRC cover both reads
- [x] 2.2 ZIP and 7z handbook pages, design rules DR-5 and DR-5a, and the user docs name the exception
- [x] 2.3 `openspec validate --strict rapidgzip-tail-end-check`, then archive
