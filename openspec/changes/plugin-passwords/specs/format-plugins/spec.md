## ADDED Requirements

### Requirement: A plugin unlocks an encrypted unit through ReaderContext.unlock

A plugin whose handler sets `supports_password = True` SHALL read the caller's
`password=` only through
`ReaderContext.unlock(what, check, *, full_check=None, member=None)`, where `check` and
`full_check` take one password and return `(data, PasswordConfirmVerdict)`. archivey
SHALL call `check` with one candidate at a time, in the order the built-in readers use
(the password that last unlocked a unit of this reader first, then the static
candidates, then the provider's answers, skipping any already tried for this unit),
SHALL return the data of the first `CONFIRMED` result, and when several static
candidates come back `INCONCLUSIVE` SHALL run `full_check` on each in order until one is
`CONFIRMED`. A provider answer that `check` calls `INCONCLUSIVE` SHALL go through
`full_check` when one is given, and a `REJECTED` answer SHALL lead to the next provider
call. An exception from either callback SHALL stop resolution and then go through the
plugin's `translate_exception`. A plugin whose handler does not set `supports_password`
SHALL get `ArchiveyUsageError` from `unlock`, and a `password=` value given for its
format SHALL be reported with `PASSWORD_ARGUMENT_UNUSED`.

#### Scenario: unlock outcomes

| Case | Expected |
| --- | --- |
| `check` returns `(x, CONFIRMED)` for the first candidate | `x`; later candidates are not tried; the password is tried first for the next unit |
| `password=None` | `EncryptionError`: "{what} is encrypted: pass password= to read it" |
| Provider's first answer is `None` | Same as `password=None` |
| `check` returns `REJECTED` for every candidate and provider answer | `EncryptionError` from the wrong-password path: "Wrong password for {what}" |
| Every candidate reached `full_check` and came back `REJECTED` there only | Unverified-data `EncryptionError` (wrong password or damaged data) |
| `check` raises `CorruptionError` | Resolution stops; that error, after `translate_exception` |
| `check` raises `EncryptionError` | Resolution stops; that error, not a wrong-password exhaustion |
| `check` raises a library exception the plugin translates | The translated error |
| A callback returns a non-tuple, or `None` data with `CONFIRMED` | Plugin bug |
| Static `["a", "b"]`, `a` `INCONCLUSIVE`, `b` `CONFIRMED` | `b`'s data |
| Static `["a", "b"]`, `a` `INCONCLUSIVE`, `b` `REJECTED` | `a`'s data; `full_check` not called |
| Static `["a", "b"]`, both `INCONCLUSIVE`, `full_check`: `a` `REJECTED`, `b` `CONFIRMED` | `b`'s data |
| Static `["a", "b"]`, both `INCONCLUSIVE`, no `full_check` | `a`'s data; `a` is not promoted |
| Provider answers wrong then right, `check` always `INCONCLUSIVE`, `full_check` given | Second answer's data; `full_check` rejected the first |
| Handler without `supports_password` calls `unlock` | `ArchiveyUsageError` |

### Requirement: CONFIRMED needs evidence of at least CRC-32 strength

A plugin SHALL return `CONFIRMED` only on evidence at least as strong as a CRC-32 over 4
or more decoded bytes, or a cryptographic check of that strength. Weaker evidence (a
magic number, padding, a CRC over fewer than 4 bytes) SHALL give `INCONCLUSIVE` or
`REJECTED`. The toy test plugins and the built-in plugins SHALL follow it.

#### Scenario: strength

| Evidence | Verdict |
| --- | --- |
| gzip magic in the first decrypted block (about 2^-24) | `INCONCLUSIVE` |
| Weak pass in `check`, then CRC-32 over the whole member in `full_check` | `CONFIRMED` |
| ARJ member of 3 bytes, CRC-32 matches | `INCONCLUSIVE` |
| AES key unwrap with integrity check, decrypted `koly` block valid | `CONFIRMED` |

### Requirement: The verdict is attached to the data it covers

`MemberRecord`, `MemberSpan` and `MemberData` SHALL carry
`unlocked: PasswordConfirmVerdict | None = None`. An `is_encrypted` member SHALL be
`verified` `UNLOCKED` when listed only if its `MemberRecord` or `MemberSpan` says
`CONFIRMED`, and `NONE` otherwise until a stream of it proves more. A stream's
`MemberData.unlocked` SHALL be kept on that stream's own verification proof. Under
`INCONCLUSIVE`, a digest mismatch at the end of the stream SHALL raise the
unverified-data `EncryptionError`, and a stream closed after delivering bytes but before
its digest SHALL emit `ENCRYPTED_MEMBER_UNVERIFIED`.

#### Scenario: verification of encrypted members

| Case | Expected |
| --- | --- |
| `is_encrypted=False` | `UNLOCKED` at listing |
| `is_encrypted=True`, `unlocked=None` on the record | `NONE` at listing |
| DMG member, record `unlocked=CONFIRMED` | `UNLOCKED` at listing |
| Replaced RAR: headers confirmed, member data not yet unlocked | `NONE` at listing |
| Stream `unlocked=INCONCLUSIVE`, CRC-32 mismatch at the end | Unverified-data `EncryptionError`; link-target report `password_or_damage` |
| Stream `unlocked=INCONCLUSIVE`, CRC-32 matches | `verified` rises past `UNLOCKED` |
| Stream `unlocked=INCONCLUSIVE`, closed after 10 bytes | `ENCRYPTED_MEMBER_UNVERIFIED` |
| Stream `unlocked=INCONCLUSIVE`, `checked=True` plugin stream raises `CorruptionError` | Unverified-data `EncryptionError` |
| Stream `unlocked=CONFIRMED`, CRC-32 mismatch | `CorruptionError` |
| Two concurrent streams of one member, one `CONFIRMED`, one `INCONCLUSIVE` | Each keeps its own verdict |

### Requirement: Plugin key derivation is charged to the reader's budget

`ReaderContext.charge_key_derivation(rounds)` SHALL add `rounds` to the reader's one
key-derivation budget, the same `max_key_derivation_rounds` total the built-in readers
charge, built before the plugin's `open` runs. It SHALL raise `ResourceLimitError`
before returning when the total would pass the cap, leaving the total unchanged.
`rounds` SHALL be an `int` of 0 or more.

#### Scenario: budget

| Case | Expected |
| --- | --- |
| Cap `2**25`, plugin charges `10_000` per try, 3 tries | Returns each time; resource usage shows 30 000 rounds |
| Cap `20_000`, third charge of `10_000` | `ResourceLimitError` before the third derivation; total stays 20 000 |
| Charge at `open` (DMG) | Counted on the same total |
| `rounds=0` | Returns; total unchanged |
| `rounds=-1` or `1.5` | Plugin bug; total unchanged |
| Cap `None` | Never raises |
| A nested archive inside the plugin's archive | Its own reader and budget |

### Requirement: The provider runs outside the reader's handle lock

`unlock` SHALL release the adapter's handle guard for every provider call and take it
again before calling `check`. A provider that reenters the same reader from its own
thread or a copied context SHALL get `ArchiveyUsageError`, and two workers needing the
provider at once SHALL be served one after the other.

#### Scenario: concurrency

| Case | Expected |
| --- | --- |
| `MemberStreams.CONCURRENT`, provider calls `reader.open(other_encrypted_member)` from inside `open_member`'s unlock | `ArchiveyUsageError`, no deadlock |
| Same, after the member's stream was materialized | `ArchiveyUsageError`, no deadlock |
| Two threads open two encrypted members, provider sleeps | Provider called once at a time; both members read |

### Requirement: A replacement reader receives password= when it supports passwords

A replacement plugin (`FormatPolicy(replace=)`) whose handler sets `supports_password`
SHALL receive the caller's `password=` through `unlock` like any plugin.

#### Scenario: replaced ZIP with an encrypted member

| Case | Expected |
| --- | --- |
| Replacement sets `supports_password`, correct `password=` | Member reads |
| Replacement does not set it, `password=` given | `PASSWORD_ARGUMENT_UNUSED`; member raises the plugin's own error |
