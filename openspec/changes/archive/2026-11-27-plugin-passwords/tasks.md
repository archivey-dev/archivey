> **Archived 2026-11-27.** The API, makeself, ARJ and DMG users have landed (2.3:
> `dmg_reader.py` returns `NeedsPassword` from `open`). Most 1.6b cases have tests in
> `tests/test_format_api_passwords.py`, `tests/test_arj.py` and `tests/test_makeself.py`;
> the cases with no test found are tracked internally: an interleaved nested-member
> reopen while another thread waits on the provider, a request reached below listing
> finalization, two overlapping requests on one shared handle, and a late makeself
> rewalk that reuses the saved winner.

## 1. API (one PR, maintainer merges: public names)

- [x] 1.1 `FormatHandler.supports_password`; `register_builtin_format` reads it instead
  of the `SUPPORTS_PASSWORD=` override
- [x] 1.2 `NeedsPassword` resolution for returned and yielded requests,
  `PasswordConfirmVerdict`, `charge_key_derivation` over
  `internal/password.py` and `KeyDerivationBudget`
- [x] 1.3 `ReaderArchiveInfo.is_encrypted`; `unlocked` on MemberRecord, MemberSpan,
  MemberData (D7); verification starts at `NONE` for `is_encrypted` members until an
  unlock confirms them
- [x] 1.4 Unconfirmed passwords: a member checksum failure becomes the unverified-data
  `EncryptionError`; the password is not promoted
- [x] 1.5 Replacement readers get `password=` when they set `supports_password`
- [x] 1.6 Tests: a toy XOR-with-check plugin and a toy no-check plugin in `tests/`,
  covering every row of the spec tables; provider repeats and reentry while a request is
  resolved
- [x] 1.6a Tests: provider reentry from `open_member` and after a stream is materialized
  under `CONCURRENT`; two workers waiting on one provider; callback exceptions through
  `translate_exception`; strength-rule cases
- [ ] 1.6b Tests (D8): reentry during first-touch listing and during a paused walk;
  another thread waiting on a paused walk; interleaved nested-member reopen while
  another thread waits on the provider; `open_member` and `then` called once per
  request; generator closed on failure; copied-context `close()` during a returned
  request; a request reached below listing finalization; two overlapping requests on one
  shared handle; late makeself rewalk reusing the saved winner; two-key `open_member`
  chain then seek-to-zero with an exhausted provider; provider-only first read through a
  fresh `stream_members()` pass and `extract_all()`, skipped members never prompting;
  indexed seek-to-zero where the original and replacement verdicts differ; ARJ short
  source vs wrong-key exhaustion
- [x] 1.7 Docs: `adding-a-format.md` passwords section, `formats.py` docstring (docs
  session)

## 2. Users (separate PRs)

- [x] 2.1 makeself: yield `NeedsPassword` + `charge_key_derivation`; mark payload
  members `is_encrypted`; drop `ReaderContext._passwords`
- [x] 2.2 ARJ: decrypt garbled members (`INCONCLUSIVE` + `full_check` on the CRC-32)
- [x] 2.3 DMG spec §6B: return `NeedsPassword` from the handler's `open`
