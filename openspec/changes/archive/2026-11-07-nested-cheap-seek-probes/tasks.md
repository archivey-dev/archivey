## 1. Implementation

- [x] 1.1 `ArchiveSource.nearest_resume_offset`: a pointer-move seek answers the target; a borrowed stream is asked
- [x] 1.2 `seeks_to_end_are_cheap`: the single-file tail probes and the codec tail read ask it
- [x] 1.3 `seek_is_expensive` covers the standard library's decompressing file objects
- [x] 1.4 Tests in `tests/test_single_file.py`, `tests/test_single_file_size_fill.py` and `tests/test_archive_source.py`
- [x] 1.5 Handbook pages
- [x] 1.6 `openspec validate nested-cheap-seek-probes` (strict flags only the unchanged digest matrix of a modified requirement)
