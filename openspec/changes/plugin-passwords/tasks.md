## 1. API (one PR, maintainer merges: public names)

- [ ] 1.1 `FormatHandler.supports_password`; `register_builtin_format` reads it instead
  of the `SUPPORTS_PASSWORD=` override
- [ ] 1.2 `ReaderContext.unlock`, `PasswordConfirmVerdict`, `charge_key_derivation` over
  `internal/password.py` and `KeyDerivationBudget`
- [ ] 1.3 `ReaderArchiveInfo.is_encrypted`; member verification starts at `NONE` for
  `is_encrypted` members until an unlock confirms them
- [ ] 1.4 Unconfirmed passwords: a member checksum failure becomes the unverified-data
  `EncryptionError`; the password is not promoted
- [ ] 1.5 Replacement readers get `password=` when they set `supports_password`
- [ ] 1.6 Tests: a toy XOR-with-check plugin and a toy no-check plugin in `tests/`,
  covering every row of the spec tables; provider repeats and reentry through `unlock`
- [ ] 1.7 Docs: `adding-a-format.md` passwords section, `formats.py` docstring (docs
  session)

## 2. Users (separate PRs)

- [ ] 2.1 makeself: `unlock` + `charge_key_derivation`; mark payload members
  `is_encrypted`; drop `ReaderContext._passwords`
- [ ] 2.2 ARJ: decrypt garbled members (`INCONCLUSIVE` + `full_check` on the CRC-32)
- [ ] 2.3 DMG spec §6B: point at `unlock`
