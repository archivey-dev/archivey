# Tasks — salvage step 2 (ZIP)

- [x] 1.1 `zip_local_walk.py`: follow a local header whose signature alone is damaged,
      confirmed by the ZIP signature where its data ends, within 4 MiB.
- [x] 1.2 `zip_forward_reader.py`: refuse that member's read as a file read does.
- [x] 1.3 Tests: `tests/test_zip_damaged_local_signature.py` (file and pipe agree,
      STORED and DEFLATE; small listing limits; bit 3 not followed).
