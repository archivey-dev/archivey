## ADDED Requirements

### Requirement: A plugin unlocks an encrypted unit through ReaderContext.unlock

A plugin whose handler sets `supports_password = True` SHALL read the caller's
`password=` only through
`ReaderContext.unlock(what, check, *, full_check=None, member=None)`, where `check` and
`full_check` take one password and return `(data, PasswordConfirmVerdict)`. archivey
SHALL call `check` with one candidate at a time, in the order the built-in readers use
(the password that last unlocked a unit of this reader first, then the static
candidates, then the provider's answers, skipping any already tried for this unit),
SHALL return the winning data with the verdict it won with (`unlock` returns
`(data, verdict)`), the first `CONFIRMED` result winning at once, and when several
static candidates come back `INCONCLUSIVE` SHALL run `full_check` on each in order until
one is `CONFIRMED`. A provider answer that `check` calls `INCONCLUSIVE` SHALL go through
`full_check` when one is given, and a `REJECTED` answer SHALL lead to the next provider
call. An exception from either callback SHALL stop resolution and then go through the
plugin's `translate_exception`. A plugin whose handler does not set `supports_password`
SHALL get `ArchiveyUsageError` from `unlock`, and a concrete `password=` (a value or a
list) given for its format SHALL be reported with `PASSWORD_ARGUMENT_UNUSED`; a provider
callable SHALL stay uncalled and unreported.

#### Scenario: unlock outcomes

| Case | Expected |
| --- | --- |
| `check` returns `(x, CONFIRMED)` for the first candidate | `(x, CONFIRMED)`; later candidates are not tried; the password is tried first for the next unit |
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
| Static `["a", "b"]`, both `INCONCLUSIVE`, `full_check`: `a` `REJECTED`, `b` `CONFIRMED` | `(b's data, CONFIRMED)` |
| Static `["a", "b"]`, both `INCONCLUSIVE`, `full_check` `INCONCLUSIVE` for both | `(a's data, INCONCLUSIVE)` (fallback to the first survivor) |
| No static candidates; provider answers `a` (`REJECTED` at `check`), then `b` (`INCONCLUSIVE`, `full_check` CRC fails), then `None` | Unverified-data `EncryptionError` (password or damage) |
| Two member-less `unlock("encrypted payload", ...)` calls in one walk, needing different keys | Each has its own rejected set and provider attempt count |
| Listing recreated, same unit unlocked again on a fresh member object | Same unit: answers already rejected for it are skipped |
| ARJ trial: source ends early inside a decoder pull | `TruncatedError` propagates (source-side), next password not tried |
| Static `["a", "b"]`, both `INCONCLUSIVE`, no `full_check` | `a`'s data; `a` is not promoted |
| Provider answers wrong then right, `check` always `INCONCLUSIVE`, `full_check` given | Second answer's data; `full_check` rejected the first |
| Handler without `supports_password` calls `unlock` | `ArchiveyUsageError` |
| Handler without `supports_password`, `password="x"` | `PASSWORD_ARGUMENT_UNUSED` |
| Handler without `supports_password`, `password=provider` | No diagnostic; provider never called |

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
| Stream `unlocked=INCONCLUSIVE`, digest in `MemberData.digests` mismatches | Unverified-data `EncryptionError` |
| Stream `unlocked=INCONCLUSIVE`, `checked=True` stream raises `CorruptionError` | That error, through ordinary translation (not remapped) |
| Stream `unlocked=INCONCLUSIVE`, source ends early | `TruncatedError` (not remapped) |
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

### Requirement: The provider is called outside plugin calls where the step can repeat

Where nothing has reached the caller yet (the handler's `open`, `open_member` before its
stream is returned, an indexed listing before its first member is published), `unlock`
SHALL NOT call the password provider inside the plugin call: it SHALL end the call, and
archivey SHALL call the provider with no archivey lock held, then repeat that step,
which tries the new answer. A walk that already yielded a member SHALL call the provider
in place, with the handle guard released, as the built-in streaming readers do. A
provider that reenters the same reader from its own thread or a copied context SHALL get
`ArchiveyUsageError` before any lock or listing wait where the step repeats, and two
workers needing the provider at once SHALL be served one after the other. Retry state
SHALL be keyed by an internal identity of the unit within the pending step, not by
`what` or `member`.

#### Scenario: concurrency and repeats

| Case | Expected |
| --- | --- |
| `MemberStreams.CONCURRENT`, provider calls `reader.open(other_encrypted_member)` | `ArchiveyUsageError`, no deadlock |
| Same, after another member's stream was materialized | `ArchiveyUsageError`, no deadlock |
| Provider waits on a copied-context worker that calls `reader.open()` during first-touch listing | `ArchiveyUsageError` in the worker, no deadlock |
| Two threads open two encrypted members, provider sleeps | Provider called once at a time; both members read |
| Thread A waits on the provider for a nested member while thread B reopens another nested member | Both read; neither sees the other's reopen state |
| Provider answers wrong then right for one `open_member` | `open_member` called three times; rounds charged once per answer |
| makeself on a pipe, payload 2 needs a provider answer after payload 1's members were yielded | Provider called in place; payload 1 is not yielded again |
| DMG `open` needs a provider answer | Handler `open` repeated; no reader returned before |

#### Scenario: ARJ trial decode failures

| Case | Expected |
| --- | --- |
| Source ends inside the packed span | `TruncatedError` propagates; no next password |
| Complete span, decoder runs out of input under a wrong key | `REJECTED`; next password tried |

### Requirement: A replacement reader receives password= when it supports passwords

A replacement plugin (`FormatPolicy(replace=)`) whose handler sets `supports_password`
SHALL receive the caller's `password=` through `unlock` like any plugin.

#### Scenario: replaced ZIP with an encrypted member

| Case | Expected |
| --- | --- |
| Replacement sets `supports_password`, correct `password=` | Member reads |
| Replacement does not set it, `password="x"` | `PASSWORD_ARGUMENT_UNUSED` with the replacement reason; member raises the plugin's own error |
