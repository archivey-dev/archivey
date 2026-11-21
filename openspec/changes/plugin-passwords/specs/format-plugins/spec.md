## ADDED Requirements

### Requirement: A plugin unlocks an encrypted unit through ReaderContext.unlock

A plugin whose handler sets `supports_password = True` SHALL read the caller's
`password=` only through `ReaderContext.unlock(what, check, *, full_check=None,
member=None)`, where `check` and `full_check` take one password and return
`(data, PasswordConfirmVerdict)`. archivey SHALL call `check` with one candidate at a time, in the
order the built-in readers use (the password that last unlocked a unit of this archive
first, then the static candidates, then the provider's answers, skipping any already
tried for this unit), SHALL return the data of the first `CONFIRMED` result, and when
several static candidates come back `INCONCLUSIVE` SHALL run `full_check` on each in order
until one is `CONFIRMED`. A plugin whose handler does not set
`supports_password` SHALL get `ArchiveyUsageError` from `unlock`, and a `password=`
value given for its format SHALL be reported with `PASSWORD_ARGUMENT_UNUSED`.

#### Scenario: unlock outcomes

| Case | Expected |
| --- | --- |
| `check` returns `(x, CONFIRMED)` for the first candidate | `x`; later candidates are not tried; the password is tried first for the next unit |
| `password=None` | `EncryptionError`: "{what} is encrypted: pass password= to read it" |
| Provider's first answer is `None` | Same as `password=None` |
| `check` returns `REJECTED` for every candidate and provider answer | `EncryptionError` from the wrong-password path: "Wrong password for {what}" |
| `check` raises `CorruptionError` | That `CorruptionError`; no further candidate is tried |
| Static list `["a", "b"]`, `a` `INCONCLUSIVE`, `b` `CONFIRMED` | `b`'s data |
| Static list `["a", "b"]`, `a` `INCONCLUSIVE`, `b` `REJECTED` | `a`'s data; `full_check` not called |
| Static list `["a", "b"]`, both `INCONCLUSIVE`, `full_check`: `a` `REJECTED`, `b` `CONFIRMED` | `b`'s data |
| Static list `["a", "b"]`, both `INCONCLUSIVE`, no `full_check` | `a`'s data; `a` is not promoted |
| Handler without `supports_password` calls `unlock` | `ArchiveyUsageError` |

### Requirement: Data that fails its checksum under an unconfirmed password reports both causes

When a member's data was decrypted under a password that `unlock` accepted only as
`INCONCLUSIVE`, and the member's checksum then fails, archivey SHALL raise
`EncryptionError` marked as unverified data (a wrong password or damaged data), not
`CorruptionError`.

#### Scenario: unconfirmed then checksum mismatch

| Case | Expected |
| --- | --- |
| Unconfirmed password, CRC-32 mismatch at the end of the member | `EncryptionError`; the link-target report gives `password_or_damage` |
| Confirmed password, CRC-32 mismatch | `CorruptionError` |

### Requirement: Plugin key derivation is charged to max_key_derivation_rounds

`ReaderContext.charge_key_derivation(rounds)` SHALL add `rounds` to the open archive's
key-derivation total and SHALL raise `ResourceLimitError` before returning when the
total would pass `DecoderLimits.max_key_derivation_rounds`. The total SHALL be the one
the built-in readers charge.

#### Scenario: budget

| Case | Expected |
| --- | --- |
| Cap `2**25`, plugin charges `10_000` per try, 3 tries | Returns each time; resource usage shows 30 000 rounds |
| Cap `20_000`, third charge of `10_000` | `ResourceLimitError` before the third derivation |
| Cap `None` | Never raises |

### Requirement: A plugin reports encryption as built-in formats do

`ReaderArchiveInfo.is_encrypted` SHALL become `ArchiveInfo.is_encrypted`. A member the
plugin lists with `is_encrypted=True` SHALL have `verified` `NONE` until a `CONFIRMED`
`unlock` for it (or a `CONFIRMED` archive-level `unlock` made before it was listed), and
`UNLOCKED` after it.

#### Scenario: verification of encrypted members

| Case | `verified` after listing |
| --- | --- |
| `is_encrypted=False` | `UNLOCKED` |
| `is_encrypted=True`, no unlock yet | `NONE` |
| `is_encrypted=True`, archive-level confirmed unlock at open | `UNLOCKED` |
| `is_encrypted=True`, member unlock won `INCONCLUSIVE` | `NONE` until its checksum passes |

### Requirement: A replacement reader receives password= when it supports passwords

A replacement plugin (`FormatPolicy(replace=)`) whose handler sets `supports_password`
SHALL receive the caller's `password=` through `unlock` like any plugin.

#### Scenario: replaced ZIP with an encrypted member

| Case | Expected |
| --- | --- |
| Replacement sets `supports_password`, correct `password=` | Member reads |
| Replacement does not set it, `password=` given | `PASSWORD_ARGUMENT_UNUSED`; member raises the plugin's own error |
