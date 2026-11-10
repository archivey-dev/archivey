## 1. Reader

- [x] 1.1 `ContainerFormat.MAKESELF`, `ArchiveFormat.MAKESELF`, the extra keys
- [x] 1.2 Header parse: variable block, `skip` (both forms), payload command, digests
- [x] 1.3 Payloads through `open_nested`; base64; trailing bytes reported
- [x] 1.4 Payload digests as a check over several members (`SpanningCheck`)
- [x] 1.5 Forced other format names makeself in its error

## 2. Tests and fixtures

- [x] 2.1 `tests/fixtures/makeself/make-runs.sh` with makeself 2.2.0, 2.4.0, 2.4.5, 2.7.1
- [x] 2.2 `tests/test_makeself.py`: each compressor, two payloads, damage, forced format
- [x] 2.3 Fuzz target and seeds

## 3. Docs

- [x] 3.1 `dev-docs/formats/makeself.md`, `docs/formats.md`, lists of formats
- [x] 3.2 Threat model: the parser, and the accepted SFX gap

## 4. Follow-ups (their own changes)

- [ ] 4.1 openssl decryption with `password=`
- [ ] 4.2 Generic `#!` compressor-needle scan, with TAR and single-file start offsets
