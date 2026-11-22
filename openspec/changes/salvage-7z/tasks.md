# Tasks — salvage step 5 (7z)

Three PRs. PR 1 is `needs-minor` (the default opens an archive it refused). PRs 2 and 3
stack on step 3's switch PR (`salvage-mode`).

## 0. Design

- [x] 0.1 Q15 measured against 7-Zip 26.05 and 23.01 (`design.md` §Measurements).
- [x] 0.2 Raw-decode, header-copy, repair and search prototypes run and timed.
- [ ] 0.3 Maintainer review of this change, the open questions included.

## 1. Default: zeroed start header (PR 1)

- [x] 1.1 Fixtures: generate damaged copies in the test from 7-Zip archives written by
      the test (solid, non-solid, LZMA1, plain header of 150 and 594 bytes, BCJ, Delta,
      AES): bytes 8–31 zeroed; plus a non-zero byte; plus 16 zero bytes. Pin `7zz t` and
      `7z t` exit codes in a test that skips without them (DR-24).
- [x] 1.2 `read_signature_and_next_header`: the 512-byte rule, nearest pair only.
- [x] 1.3 `ARCHIVE_STRUCTURE_INCONSISTENT` with `structure="start_header"`; context
      docstring; `STRICT` test.
- [x] 1.4 `dev-docs/formats/7z.md` §2.1: the zeroed rule and why.

## 2. Salvage: header repair (PR 2)

- [x] 2.1 `supports_salvage` for 7z; `method` values `"header_repair"` and
      `"header_search"`.
- [x] 2.2 R1, R2, R3 (a, b, c), R4 in `sevenzip_parser.py`, pure on bytes; search bytes
      counted through the step 3 driver.
- [x] 2.3 A next header that fails its CRC: parse anyway, accept under the folder CRC.
- [ ] 2.4 Lost start (decision 11): R4 search, the lost-byte count, folders after it.
- [x] 2.5 Tests: every Q15 damage row; add-only (default raises, salvage lists all, the
      pass ends in the default's error); `max_search_bytes=0`; the R2 candidate count.

## 3. Salvage: content (PR 3)

- [ ] 3.1 `sevenzip_salvage.py`: LZMA2 chunk-chain walk (no decode), the stream search,
      the LZMA1 trial at offset 32, the header-copy check (parse to `kEnd`, pack layout
      agreement) and its tail search.
- [ ] 3.2 A header parse that stops at `kEnd` and reports where (for the copy).
- [x] 3.3 Content members: names, sizes, synthetic one-coder folders, dictionary from
      the unpacked size; feed the decoder so a failing piece keeps the bytes before it.
- [x] 3.4 `MEMBER_NAME_UNKNOWN`: code, `DiagnosticCodeStr`, catalogue row, API surface,
      docstring; `"content"` method; not an integrity code.
- [ ] 3.5 CLI `list` mark `name unknown`.
- [ ] 3.6 Tests: cuts at 25/50/75/95 % and 100 bytes short of solid, non-solid,
      multi-threaded, LZMA1, BCJ, BCJ2, Delta, AES archives; header copy; 4 KiB zeroed
      then cut; search false-positive test on random bytes (no candidate from
      uncompressed-only chains); `max_ratio` on a crafted chunk chain; names stable
      across runs.
- [ ] 3.7 `dev-docs/formats/7z.md`: salvage section (what is recovered, filters caveat,
      LZMA1 end caveat); `docs/` salvage page row for 7z.

## 4. Close

- [ ] 4.1 Sync specs, archive the change.
