## 1. Decoder stream

- [x] 1.1 `DecompressorStream.seek` records the target (`_seek_target`); `_settle` decodes to it at the next read or `readall`; `tell()` returns it
- [x] 1.2 Seeks within the buffer, to the decoder's position, or at or past a known size stay immediate
- [x] 1.3 `_end_offset` starts its scan to the end from the last seek point past the decoder
- [x] 1.4 A decode error while settling leaves the stream at the target with the error kept; any other error keeps the target for the next read

## 2. Tests

- [x] 2.1 `tests/test_lazy_decoder_seek.py`: a seek back after a full read decodes nothing; seeks no read follows cost nothing; `SEEK_CUR` from the target; truncation and damage in the gap raise at the read and keep the target
- [x] 2.2 Tests that expected the seek itself to raise, or to have walked an index, now check the read after it
