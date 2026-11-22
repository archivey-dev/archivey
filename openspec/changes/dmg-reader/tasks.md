## A0. Evaluate the lzfse package

- [x] A0.1 Investigation PR: wheels, licence, output cap, raw LZVN, fuzz in a child
  process, per-run cost, agreement with the prototype
- [x] A0.2 Maintainer decides: library only, Python only, or Python plus the library as
  an accelerator

## A. Decoders

- [x] A.1 `lzfse_decoder.py`: LZFSE (`bvx2`, `bvxn`, `bvx-`, `bvx$` ported from the
  prototype; `bvx1` written from Apple's `lzfse_decode_base.c`, since the prototype
  raises on it) and LZVN, bounded output
- [x] A.2 `adc_decoder.py`
- [x] A.2b `CompressionAlgorithm.LZFSE`, `LZVN`, `ADC`; codec-policy refusal tests
- [x] A.3 Tests: real runs from the fixtures, agreement with the `lzfse` package when
  installed, damage and truncation

## B. UDIF, partitions and HFS+

- [x] B.1 Test writers in `tests/dmg_build.py`: UDIF, GPT, APM, HFS+ (may be its own PR)
- [x] B.2 `udif.py` rewrite: `koly`, property list, run tables, `UdifSource`;
  stored-length and run-count bounds checked before any read or allocation (design §4.2,
  §4.3)
- [x] B.3 `disk_partitions.py`: GPT, APM, none; one disk index; signature decides
  (design §5); volume top-level names
- [x] B.4 `hfsplus.py`: volume header, journal state (§6.1), forks, B-trees, catalog,
  hard links, decmpfs, attributes
- [x] B.5 `dmg_reader.py`: handler, reader, detection signatures kept through
  `register_builtin_format`, `SEEKABLE`
- [x] B.6 APFS-only and encrypted images refused by name until parts E and G
- [x] B.7 Committed `hdiutil` fixtures and their README entry; fixture script
- [x] B.8 7-Zip oracle tests with the listed differences; fuzz target
- [x] B.9 Handbook page `dev-docs/formats/dmg.md`, threat-model row, remove
  recognised-only special cases
- [x] B.10 External corpus run over the 54-URL list, which gave the 41 measured images
  (maintainer, before merge): `scripts/investigations/dmg_corpus.py`. Run 2026-11-21
  with 7-Zip 23.01: 48 of the 54 URLs downloaded; 40 images extract the same files as
  7-Zip, 6 are APFS (refused by name), and 2 use xz runs, which that 7-Zip cannot
  decode (archivey lists 1 and 509 files from them)

## M. macOS CI check with Apple's own tools

The macOS runners have `hdiutil` and `fsck_hfs`, the tools that write and read DMGs
on a Mac. A workflow on a macOS runner checks archivey against them. Like the other side
workflows, it runs after a merge to `main` and on a schedule, never on pull requests,
and the maintainer merges the PR that adds it (it adds triggers).

- [x] M.1 Writer images through Apple's tools (early: it checks `tests/dmg_build.py`):
  each builder image passes `hdiutil verify` and `hdiutil attach -readonly`, the mounted
  volume holds the files the writer put there, and each HFS+ volume passes `fsck_hfs -n`
- [x] M.2 Reader against fresh `hdiutil` images (with B.8): `hdiutil create` in every
  format (UDZO, UDBZ, ULFO, ULMO, UDRO, UDCO; HFS+, HFSX, APFS from Part E), then
  archivey's listing and file hashes match the mounted volume's

Both are `scripts/investigations/dmg_macos_check.py`, run by `dmg-macos.yml`. They
were ticked after its first green run on `main` (2026-11-22, run 45021023296, after
decmpfs type 10 was fixed); APFS joins M.2 with Part E.

## C. User docs

- [ ] C.1 `docs/formats.md` §Disk images and the formats table (maintainer's docs
  session)

## D. Polish

- [x] D.1 Anything part B's review defers: the folder thread cross-check (one
  `folder_thread` diagnostic per volume)

## E. APFS

- [x] E.1 `apfs.py`: checkpoint, object maps, B-trees, Fletcher-64, filesystem records;
  damaged key ranges of skipped nodes (design §6A.6)
- [x] E.2 Reader integration; several volumes per container
- [x] E.3 `write_apfs` test writer; APFS fixtures; refusals; fuzz target
- [x] E.4 Handbook page section

## F. Partition CRC-32

- [x] F.1 Spanning check over whole CRC-bearing `blkx` tables that overlap a filesystem
  partition (ignore runs excluded, runs outside the partition included, zero fill folded
  in O(log n)); one table straddling two partitions fails both; `verify_all()`
- [x] F.2 Data-fork and master checksums if cheap

## G. Encrypted images

- [ ] G.0 Wait for the plugin-interface password change; use its public API

- [ ] G.1 Confirm the `encrcdsa` v2 layout on the AES-128 and AES-256 fixtures; write it
  in the handbook page
- [ ] G.2 TripleDES from cryptography's decrepit module in the crypto backend; key
  unwrap; password flow; key-derivation budget
- [ ] G.3 `EncryptedDmgSource`; `encrypt_dmg` test writer; damage tests

## H. LZFSE accelerator

Ruled 2026-11-21 (A0.2): the fast path is archivey's own LZFSE and LZVN kernel in the
`archivey-codecs` Rust package, with the same checks as the Python decoder, not the
`lzfse` PyPI package.

- [ ] H.1 LZFSE and LZVN kernel in `archivey-codecs` with a bounded output and the
  Python decoder's checks; archivey uses it when the package is installed
- [ ] H.2 Tests that both decoders agree on every fixture and on the A0 fuzz corpus;
  `--all-configs`

## On archive

- [ ] Z.1 The `testing-contract` delta in this change moves the UDIF-refusal examples
  (auto-detect open target, detection-then-bounded-read matrix) to a segmented UDIF
  image (`segment count` 2), which stays refused with `UnsupportedFeatureError`, and
  adds an unencrypted UDIF image that opens and reads its first member. Apply it on
  archive
