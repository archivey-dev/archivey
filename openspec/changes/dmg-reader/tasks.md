## A0. Evaluate the lzfse package

- [ ] A0.1 Investigation PR: wheels, licence, output cap, raw LZVN, fuzz in a child
  process, per-run cost, agreement with the prototype
- [ ] A0.2 Maintainer decides: library only, Python only, or Python plus the library as
  an accelerator

## A. Decoders

- [ ] A.1 `lzfse_decoder.py` (ported from the prototype): LZFSE (`bvx1`, `bvx2`, `bvxn`,
  `bvx-`, `bvx$`) and LZVN, bounded output
- [ ] A.2 `adc_decoder.py`
- [ ] A.3 Tests: real runs from the fixtures, agreement with the `lzfse` package when
  installed, damage and truncation

## B. UDIF, partitions and HFS+

- [ ] B.1 Test writers in `tests/dmg_build.py`: UDIF, GPT, APM, HFS+ (may be its own PR)
- [ ] B.2 `udif.py` rewrite: `koly`, property list, run tables, `UdifSource`
- [ ] B.3 `disk_partitions.py`: GPT, APM, none
- [ ] B.4 `hfsplus.py`: volume header, forks, B-trees, catalog, hard links, decmpfs,
  attributes
- [ ] B.5 `dmg_reader.py`: handler, reader, detection signatures kept through
  `register_builtin_format`, `SEEKABLE`
- [ ] B.6 APFS-only and encrypted images refused by name until parts E and G
- [ ] B.7 Committed `hdiutil` fixtures and their README entry; fixture script
- [ ] B.8 7-Zip oracle tests with the listed differences; fuzz target
- [ ] B.9 Handbook page `dev-docs/formats/dmg.md`, threat-model row, remove
  recognised-only special cases
- [ ] B.10 External corpus run on the 41 real images (maintainer, before merge)

## C. User docs

- [ ] C.1 `docs/formats.md` §Disk images and the formats table (maintainer's docs
  session)

## D. Polish

- [ ] D.1 Anything part B's review defers

## E. APFS

- [ ] E.1 `apfs.py`: checkpoint, object maps, B-trees, Fletcher-64, filesystem records
- [ ] E.2 Reader integration; several volumes per container
- [ ] E.3 `write_apfs` test writer; APFS fixtures; refusals; fuzz target
- [ ] E.4 Handbook page section

## F. Partition CRC-32

- [ ] F.1 Spanning check over each partition's runs (ignore runs excluded);
  `verify_all()`
- [ ] F.2 Data-fork and master checksums if cheap

## G. Encrypted images

- [ ] G.0 Wait for the plugin-interface password change; use its public API

- [ ] G.1 Confirm the `encrcdsa` v2 layout on the AES-128 and AES-256 fixtures; write it
  in the handbook page
- [ ] G.2 TripleDES from cryptography's decrepit module in the crypto backend; key
  unwrap; password flow; key-derivation budget
- [ ] G.3 `EncryptedDmgSource`; `encrypt_dmg` test writer; damage tests

## H. LZFSE accelerator

- [ ] H.1 Optional `lzfse` package in a child process; `OptionalLibrary.LZFSE`; extra;
  `exclude_libraries`; `--version -v`
- [ ] H.2 Tests that both decoders agree on every fixture; `--all-configs`

## On archive

- [ ] Z.1 The `testing-contract` examples that use the UDIF refusal (auto-detect open
  target, bounded member read) move to an encrypted or segmented image, or to a read
