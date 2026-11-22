## ADDED Requirements

### Requirement: A plugin unlocks an encrypted unit by handing archivey a NeedsPassword request

A plugin whose handler sets `supports_password = True` SHALL read the caller's
`password=` only through a `NeedsPassword(what, check, *, full_check=None, member=None,
then=None)` request, where `check` and `full_check` take one password and return
`(data, PasswordConfirmVerdict)`. The handler's `open` and `open_member` SHALL hand it
over by returning it with `then`; `iter_members` and `walk` SHALL hand it over by
yielding it without `then`, and archivey SHALL send `(data, verdict)` back into the
generator. archivey SHALL call `then(data, verdict)` for a returned request, and `then`
MAY return another request. archivey SHALL call `check` with one candidate at a time, in
the order the built-in readers use (the password that last unlocked a unit of this
reader first, then the static candidates, then the provider's answers, skipping any
already tried for this request), SHALL pass on the winning data with the verdict it won
with, the first `CONFIRMED` result winning at once, and when several static candidates
come back `INCONCLUSIVE` SHALL run `full_check` on each in order until one is
`CONFIRMED`. A provider answer that `check` calls `INCONCLUSIVE` SHALL go through
`full_check` when one is given, and a `REJECTED` answer SHALL lead to the next provider
call. An exception from either callback SHALL stop resolution and then go through the
plugin's `translate_exception`. A request handed over by a plugin whose handler does not
set `supports_password` SHALL be a plugin bug (`ArchiveyUsageError`), and a concrete
`password=` (a value or a list) given for its format SHALL be reported with
`PASSWORD_ARGUMENT_UNUSED`; a provider callable SHALL stay uncalled and unreported.

#### Scenario: request outcomes

| Case | Expected |
| --- | --- |
| `check` returns `(x, CONFIRMED)` for the first candidate | `then(x, CONFIRMED)` (or `(x, CONFIRMED)` sent into the walk); later candidates are not tried; the password is tried first for the next unit |
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
| Two member-less requests yielded in one walk, needing different keys | Each has its own rejected set and provider attempt count |
| ARJ trial: source ends early inside a decoder pull | `TruncatedError` propagates (source-side), next password not tried |
| Static `["a", "b"]`, both `INCONCLUSIVE`, no `full_check` | `a`'s data; `a` is not promoted |
| Provider answers wrong then right, `check` always `INCONCLUSIVE`, `full_check` given | Second answer's data; `full_check` rejected the first |
| Handler without `supports_password` returns or yields a request | `ArchiveyUsageError` |
| `open_member` returns a request without `then` | Plugin bug |
| `walk` yields a request with `then` | Plugin bug |
| `then` returns a second request (headers, then data) | Resolved in turn; its `then` returns the `MemberData` |
| `then` raises | That error, after `translate_exception` |
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

### Requirement: The provider runs while no plugin code is in progress

archivey SHALL run `check`, `full_check` and `then` under the same scoped handle guard
and adapter state as the plugin call that handed over the request, entered and left
around each callback. Before each provider call archivey SHALL leave the handle guard it
holds for the request and take it again after the answer, putting back the adapter state
the request's step had set. A lock that orders the request against other work on the
reader (the walk lock a listing or a paused walk holds, an outer frame's, such as
listing finalization reading link targets) SHALL stay held: the request's owner is then
the thread holding it, the active worker for a returned request or the paused walk for a
yielded one. Every same-reader entry that would wait on that owner (listing, iteration,
member `open()`, `stream_members()`, `close()`, link-target reads) SHALL raise
`ArchiveyUsageError` at once when called from the provider's own thread or a context
copied from it, and SHALL wait for the answer when called from any other thread. No
plugin call SHALL be repeated to try a provider answer. Retry state SHALL live on the
request. When the adapter calls a hook again on its own (a data walk, a respawn, a
rewalk), it SHALL try first the saved winner of each request, keyed by the plugin call
plus the request's index in that call's chain. A replacement open SHALL try first the
winners the stream it replaces was unlocked with, even when another open has since
saved a different winner for the same request, and SHALL keep that password when
`check` does not reject it; a random-access data walk left idle SHALL be taken for a
replacement open only when it unlocked the requests it passed with those same winners.
On a fresh open a saved winner that `check` does not confirm SHALL compete with the
other passwords as the first `INCONCLUSIVE` survivor, so a password confirmed since by
another unit can win. archivey SHALL call the provider only on
the first unlock of a unit: a request from the handler's `open` (with `member=None`), a
listing walk's request, or a first open of a member (the caller's `open()`, a data walk
it starts, the first open of a lazy `stream_members()` or extraction handle). It SHALL
never call it on a replacement open of an already unlocked stream, and SHALL give a
replacement stream the new `unlocked` verdict (a respawn's `MemberData`, a data walk's
span). A replacement whose `digests`, `checked` or `bounded` differ from the first
open's SHALL be refused as a plugin bug. When resolution fails for a yielded request,
archivey SHALL close the generator and the error SHALL end the walk. Two workers needing
the provider at once SHALL be served one after the other.

#### Scenario: concurrency

| Case | Expected |
| --- | --- |
| `MemberStreams.CONCURRENT`, provider calls `reader.open(other_encrypted_member)` | Provider's own thread: `ArchiveyUsageError`, no deadlock |
| Same, after another member's stream was materialized | `ArchiveyUsageError`, no deadlock |
| Provider waits on a copied-context worker that calls `reader.open()` during first-touch listing | `ArchiveyUsageError` in the worker, no deadlock |
| Two threads open two encrypted members, provider sleeps | Provider called once at a time; both members read |
| Thread A waits on the provider for a nested member while thread B reopens another nested member | Both read; neither sees the other's reopen state |
| Provider answers wrong then right for one `open_member` | `open_member` called once, `then` once; rounds charged once per answer |
| makeself on a pipe, payload 2 needs a provider answer after payload 1's members were yielded | Walk paused at the request, provider called, walk resumed; payload 1 is not yielded again |
| makeself payload 2: every password wrong | Generator closed; wrong-password `EncryptionError` ends the walk |
| Another thread calls `reader.members()` while the walk waits on the provider | Waits, then gets the full list |
| DMG `open` returns a request | Handler `open` called once; `then` returns the reader |
| Provider calls `reader.close()` from a copied context while an `open_member` request waits on it | `ArchiveyUsageError` in the helper, no deadlock |
| Listing finalization reads an encrypted link target whose request needs the provider | Listing lock stays held for the provider call; provider's own-context `reader.members()` raises `ArchiveyUsageError`; another thread's waits |
| Toy plugin with one shared handle, two overlapping requests, `full_check` decoding on the handle | Callbacks serialized by the handle guard; provider runs with the guard released |
| Provider's own thread calls `reader.read(member)` during a paused walk | `ArchiveyUsageError`, no deadlock |

#### Scenario: calls archivey makes again

| Case | Expected |
| --- | --- |
| makeself, payload 1 unlocked by a provider answer at listing; a member of it opened later through a random-access data walk | The saved winner is tried first and unlocks it; the provider is not asked again |
| Indexed member opened `INCONCLUSIVE`; backward seek respawns it and the toy plugin's `then` now reports `CONFIRMED` | The replacement stream is checked as `CONFIRMED` |
| Same with the original `CONFIRMED` and the replacement `INCONCLUSIVE` | A digest mismatch on the replacement raises the unverified-data `EncryptionError` |
| Respawn (replacement open) inside `read()` where the saved winner no longer unlocks the unit | D2 exhaustion error from that `read()`; provider not called |
| Handle A unlocked a member with an `INCONCLUSIVE` provider answer; handle B, a fresh open of the same member, then won a different, confirmed password; A seeks back to a nonzero offset | A's respawn or data walk unlocks with A's own password and returns the bytes it returned before; B's winner and B's idle data walk are not used for it |
| Reader closed, then reopened with `open_archive` | No saved winners carried over |
| `open_member` chain: header request then data request, each won by a different provider answer; then seek to zero, provider has no more answers | Both saved winners reused; replacement stream reads |
| Fresh reader, provider only, ARJ garbled member read through `stream_members()` | Provider asked on the handle's first `read()`; member reads |
| Same pass, caller skips two garbled members and reads a third | Provider asked only for the third |
| `extract_all()` with provider only, two ARJ garbled members sharing one key, each over 4 bytes (CRC-32 confirms) | Provider called once, for the first; the confirmed password is promoted and the second reads with no prompt; both extract |

#### Scenario: ARJ trial decode failures

| Case | Expected |
| --- | --- |
| Source ends inside the packed span | `TruncatedError` propagates; no next password |
| Complete span, decoder runs out of input under a wrong key | `REJECTED`; next password tried |

### Requirement: A replacement reader receives password= when it supports passwords

A replacement plugin (`FormatPolicy(replace=)`) whose handler sets `supports_password`
SHALL receive the caller's `password=` through `NeedsPassword` like any plugin.

#### Scenario: replaced ZIP with an encrypted member

| Case | Expected |
| --- | --- |
| Replacement sets `supports_password`, correct `password=` | Member reads |
| Replacement does not set it, `password="x"` | `PASSWORD_ARGUMENT_UNUSED` with the replacement reason; member raises the plugin's own error |
