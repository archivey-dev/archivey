## 1. Reader

- [x] 1.1 `_archive_refusal` refuses a RAR 2.x-4.x solid pass only for encrypted headers; an encrypted member refuses itself and what its solid stream carries into (`member_refusal`)
- [x] 1.2 The pass treats an empty run as a wrong password only when the run holds data known to be encrypted (`solid_pass_needs_password`, not `encryption_unknown`)

## 2. Tests and docs

- [x] 2.1 `tests/test_rar_unar.py`: the pass's refusals equal `member_refusal`; with `unar` installed the members before the encrypted one read and the refusal names unar and `rar_decompressor='unrar'`; an `encryption_unknown` member does not make the run need a password
- [x] 2.2 `docs/formats.md` unar refusal list
- [x] 2.3 `openspec validate --strict unar-rar4-solid-pass-serves-before-encrypted`, then archive
