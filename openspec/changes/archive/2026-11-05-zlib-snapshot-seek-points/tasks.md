## 1. Implementation

- [x] 1.1 `ZlibSnapshot` state and snapshot points in `GzipDecoder` on declared seek demand
- [x] 1.2 `DecompressorStream` keeps snapshots apart, and caps their memory at `MAX_SNAPSHOT_BYTES`
- [x] 1.3 Tests in `tests/test_gzip_snapshot_seek.py`
- [x] 1.4 Handbook and user docs
- [x] 1.5 `openspec validate zlib-snapshot-seek-points` (strict flags only the unchanged matrix of the modified requirement)
