## Context

The built-in password machinery is `internal/password.py`. `_PasswordCandidates` holds
the caller's `password=` (one value, a list, or a provider callable) for one open
archive, and `attempt(member, decrypt)` tries the passwords on one encrypted unit:
static candidates first (the one that last worked leads), then the provider, skipping
answers already tried and stopping a provider stuck on one answer. It guards provider
reentry and serializes provider calls across threads. `wrong_password_error` marks the
`EncryptionError` that a failed check raises, so exhaustion keeps its message;
`unverified_data_error` marks a checksum failure under a password nothing confirmed
(ZipCrypto, RAR 2.9-4).

makeself is the one plugin-shaped reader that uses it (`makeself_reader.py`
`MakeselfReader._decrypt`), through the private `ReaderContext._passwords`. It also
rebuilds the "required" versus "wrong" messages itself from
`_PasswordCandidatesExhausted.last_error`, and charges PBKDF2 to a `KeyDerivationBudget`
it builds and registers with `context._usage.watch_key_derivation`. A public API should
make each of those three steps one call.

The units differ by format:

| Reader | Unit | Password check | Cost per try |
| --- | --- | --- | --- |
| makeself (openssl) | one payload, while walking | compressor magic in the first block (about 1 in 2^24 false accept), PKCS#7 padding at the end | PBKDF2-SHA256 10 000 rounds, or one MD5/SHA-256 |
| DMG (`encrcdsa` v2) | the whole image, at open | key unwrap: 3DES-CBC padding, then the decrypted `koly` block | PBKDF2-SHA1, rounds stated by the image |
| ARJ garble | one member | none: each byte is XORed with the password; only the CRC-32 after the whole member tells | nothing |
| A ZIP/7z/RAR replacement | per member, per folder, or headers | the format's own | the format's own |

## Goals / Non-Goals

**Goals:** one public way for a plugin to try the caller's passwords on a unit, with the
same candidate order, provider rules and error messages as the built-in readers; key
derivation inside the existing budget; encryption reported in `ArchiveInfo` and
`ArchiveMember` as built-in formats report it.

**Non-goals:** the plugin seeing the password list or the provider (it gets one password
per `check` call); new exception classes; asymmetric or keychain encryption; ciphers in
archivey's API (a plugin brings its own, or uses its library's).

## Decisions (recommended; each is an open question below until ruled)

### D1. archivey runs the loop; the plugin writes `check` (RULED: davi 11-21, card)

```python
T = TypeVar("T")

class PasswordConfirmVerdict(Enum):   # today internal/password_confirm.py; made public
    REJECTED = "rejected"           # this password is not the one
    INCONCLUSIVE = "inconclusive"   # passed every check run so far, could still be wrong
    CONFIRMED = "confirmed"         # the format's check proves it

Check = Callable[[bytes], tuple[T | None, PasswordConfirmVerdict]]

class ReaderContext:
    def unlock(
        self,
        what: str,
        check: Check[T],
        *,
        full_check: Check[T] | None = None,
        member: ArchiveMember | None = None,
    ) -> tuple[T, PasswordConfirmVerdict]: ...
```

`check(password)` tries one password and returns what that password unlocked (whatever
the plugin needs to decrypt later: a derived key, a cipher state, a decrypted header),
with how sure it is. archivey never looks inside the value; `unlock` returns it together
with the verdict it won with (the full check's when one ran, or an earlier survivor's
`INCONCLUSIVE` when archivey fell back to it), which the plugin puts on
`MemberData.unlocked` or `MemberSpan.unlocked` (D7). Data is
`None` only with `REJECTED`. An exception from `check` or `full_check` ends the loop
(D2). `member` is what the provider's `PasswordRequest.member` shows (`None` for an
archive-level unit). `what` names the unit in archivey's messages ("makeself payload 2",
"the disk image").

This is the public form of the internal `password_confirm.attempt_with_confirm` (probe +
full check), which the ZIP, 7z and RAR readers already use. The enum is the one they
use, moved to `archivey.formats` and imported from there by the built-in readers, so
plugins and built-ins share one set of levels (davi 11-21).

**Strength rule** (the one `archive-reading` already states for the built-ins): a
verdict is `CONFIRMED` only on evidence at least as strong as a CRC-32 over 4 or more
decoded bytes (a false match no more often than 1 in 2^32), or a cryptographic check
(an AES key wrap, an HMAC, a validated decrypted structure of that strength). Anything
weaker (a magic number, padding, a CRC over fewer than 4 bytes) is a rejection filter:
it may return `REJECTED`, and otherwise `INCONCLUSIVE`.

One change for the built-ins: a probe may now return `REJECTED`, where today it raises
the wrong-password `EncryptionError` instead; both stay accepted inside archivey.

Example, makeself (openssl, AES-256-CBC). `unlock` returns the AES key and IV of the
password that worked:

```python
def check(password: bytes) -> tuple[AesParams | None, PasswordConfirmVerdict]:
    context.charge_key_derivation(10_000)        # PBKDF2 rounds, before the work
    params = derive_key(password, salt)          # AES key + IV
    first = aes_cbc_decrypt(params, first_block)
    if not first.startswith(GZIP_MAGIC):         # the payload must start with gzip
        return None, PasswordConfirmVerdict.REJECTED
    # A magic match is wrong about 1 time in 2**24 (2**19 for Unix compress): below the
    # strength rule, so a filter, not a proof. The payload digests in the header hash
    # the stored (encrypted) bytes, so they cannot confirm the password either.
    return params, PasswordConfirmVerdict.INCONCLUSIVE

params, verdict = context.unlock("makeself payload 1", check)
# each span of this payload: MemberSpan(..., unlocked=verdict)
```

makeself has no `full_check`: it is a forward walk with no replay, so with several
candidates that pass the magic the first one wins, unpromoted, as today. Its members
stay `NONE` until a read ends with the decoded TAR and compressor checks passing.

Example, ARJ garble (each byte XORed with the password; only the member's CRC-32 tells):

```python
def check(password):
    return password, PasswordConfirmVerdict.INCONCLUSIVE   # nothing to test before the data

def full_check(password):
    crc, size = 0, 0
    with open_packed_span(member) as packed:     # a short source read raises
        decoder = degarble_and_decode(packed, password)  # TruncatedError here: propagates
        try:
            while chunk := decoder.read(64 * 1024):   # bounded memory, never the
                crc = zlib.crc32(chunk, crc)          # whole member
                size += len(chunk)
        except CorruptionError:                  # from the decoder over a complete span,
            return None, PasswordConfirmVerdict.REJECTED  # TruncatedError included:
                                                 # a wrong key, not a cut
    if crc != stored_crc:
        return None, PasswordConfirmVerdict.REJECTED
    if size < 4:                                 # below the strength rule
        return password, PasswordConfirmVerdict.INCONCLUSIVE
    return password, PasswordConfirmVerdict.CONFIRMED

key, verdict = context.unlock(member_label, check, full_check=full_check, member=member)
return MemberData(degarbled_stream(key), unlocked=verdict)  # decoded again for the caller
```

The plugin decides which of its own failures depend on the password (return `REJECTED`)
and lets the rest propagate (source errors, a short read of the source itself, resource
limits). It tells them apart by where the error arose, not by class: `TruncatedError` is
a `CorruptionError`, and a decoder fed a complete span under a wrong key can raise it.
`full_check` decodes the whole member in bounded chunks (never holding it in memory, as
the built-in full check does), and the caller's read decodes it again; both are charged
where the decode limits measure them. It exists only where the plugin can replay the
unit: an indexed reader, or a sequential one that reads its unit into a bounded buffer
first.

For DMG, `check` returns the unwrapped disk key, `CONFIRMED` once the key unwrap and the
decrypted `koly` block (a 512-byte structure with magic, version and sizes) check out.

Alternative: hand the plugin an iterator of candidates. Rejected (davi chose the loop in
archivey): the provider's rules (skip repeats, stop after three own repeats, no reentry,
one call at a time) and promotion would be each plugin's job.

### D2. archivey builds both errors (RULED: davi 11-21, card)

| Outcome | archivey raises |
| --- | --- |
| No password given, or the provider's first answer is `None` | `EncryptionError("{what} is encrypted: pass password= to read it")` |
| Every password tried came back `REJECTED` | wrong-password `EncryptionError("Wrong password for {what}")` |
| `full_check` came back `REJECTED` for every candidate it ran on, and nothing stronger than the data checksum rejected them | unverified-data `EncryptionError` ("wrong password or damaged data"): a damaged member fails every CRC too |
| `check` or `full_check` raised (any exception, `EncryptionError` included) | Resolution stops; no further candidate or provider call. The exception then goes through the plugin's `translate_exception` like any other plugin exception |
| A callback returned something other than a 2-tuple of data and `PasswordConfirmVerdict`, or `None` data with a verdict other than `REJECTED` | Plugin bug (`_plugin_bug`, as for a bad `open_member` return) |

Same class as today for both (`EncryptionError`); the error-handling spec has no
subclasses for them, and callers already tell them apart only by message. The
built-ins keep their path, where a probe's wrong-password `EncryptionError` means
`REJECTED`; the plugin path rejects only through the returned verdict.

### D3. How several passwords are decided

The loop is the one the built-in readers run (`_PasswordCandidates.attempt` with
`settled`/`settle`):

1. Each static candidate in order goes through `check`. The first `CONFIRMED` wins at
   once, so no expensive derivation runs for the candidates after it. `REJECTED` is
   dropped. `INCONCLUSIVE` is set aside and the next candidate is tried.
2. When the candidates run out with **one** set aside, it wins; `full_check` does not
   run for it (every other candidate was `REJECTED`).
3. With **several** set aside, `full_check` runs on each in order. The first `CONFIRMED`
   wins; `REJECTED` is dropped. If none confirms (or there is no `full_check`), the
   first still `INCONCLUSIVE` wins.
4. With none left, the provider is asked, one answer at a time. An answer `check` calls
   `INCONCLUSIVE` goes through `full_check` when the plugin gives one; `REJECTED` from
   either asks the provider again. The first `CONFIRMED` answer wins, and an
   `INCONCLUSIVE` one wins only when there is no `full_check` (or it also came back
   `INCONCLUSIVE`), since a person at a prompt answers one at a time and there is
   nothing to compare it with.

A password that wins as `INCONCLUSIVE` is not promoted to be tried first for later units
(unless it was the only password given), and a checksum failure of that member's data
becomes the unverified-data `EncryptionError` ("wrong password or damaged data"), as for
ZipCrypto, so the link-target report says `password_or_damage`.

`PasswordConfirmVerdict` is an enum, not a score: the loop only needs "confirmed wins,
wrong is dropped, the rest wait", and new levels can be added to an enum later. A
numeric score would ask every plugin to calibrate numbers nothing compares across
formats.

### D4. Key derivation: `ReaderContext.charge_key_derivation(rounds)` (RULED: davi 11-21)

Charges `rounds` to the reader's one `KeyDerivationBudget` for
`DecoderLimits.max_key_derivation_rounds`. The budget is per reader, as
`archive-reading` scopes it: the adapter builds it and registers it with resource usage
before the plugin's `open` runs, so DMG can charge at open and makeself across payloads
and rewalks. A nested archive is its own reader with its own budget (and gets no
`password=`, as today). It raises `ResourceLimitError` before the work when the total
would pass the cap, and the total is then unchanged. `rounds` is an `int` of 0 or more
(0 for a mode with no iterations); anything else is a plugin bug and changes nothing.
The plugin calls it inside `check`, before each derivation it does not have cached.
Alternative: the plugin reads the limit from `config` and counts itself; rejected
because the total would not show in resource usage or cover the other derivations on the
same reader.

### D5. Declaring and reporting encryption

```python
class FormatHandler:
    supports_password: ClassVar[bool] = False

class ReaderArchiveInfo(NamedTuple):
    is_encrypted: bool = False
```

- `supports_password = False`: a concrete `password=` (a value or a list, not a
  provider, which stays uncalled and unreported, as today) is reported unused, with the
  replacement-specific reason for a replacement reader, (`PASSWORD_ARGUMENT_UNUSED`) and
  `unlock` raises `ArchiveyUsageError` (a plugin bug). The shared backend-class builder
  maps it next to `uses_encoding`, so registration and replacement agree, and makeself
  declares it in the API PR. This replaces the internal
  `register_builtin_format(..., SUPPORTS_PASSWORD=True)` override.
- How an encrypted member's `verified` level rises is D7.
- `ReaderArchiveInfo.is_encrypted` is per archive and becomes `ArchiveInfo.is_encrypted`
  (today the adapter always writes `False`). As for 7z and RAR5, it means the member
  list itself is encrypted (a password is needed to list): `True` for a DMG encrypted
  image and an openssl makeself payload, `False` for ARJ, whose garble covers member
  data only. Per-member encryption is the existing public `ArchiveMember.is_encrypted`,
  which the plugin sets on the member it lists (ARJ garbled members, and every member of
  an encrypted DMG or makeself payload).

### D6. Replacement readers

A replacement plugin for ZIP, 7z or RAR whose handler sets `supports_password` gets the
caller's `password=` through `unlock`, as any plugin does. The sentence in
`adding-a-format.md` saying a replaced ZIP cannot read encrypted members goes.

### D7. The verdict travels with the data it covers (RULED: davi 11-21, card)

Call order proves nothing: makeself unlocks one payload at a time and may walk again, a
replaced RAR can confirm its encrypted headers and still meet member data under another
key, and two streams of one member can be opened under different passwords. So the
plugin states what each verdict covers, on the object that carries the data:

```python
class MemberRecord(NamedTuple):   # indexed listing
    ...
    unlocked: PasswordConfirmVerdict | None = None
class MemberSpan(NamedTuple):     # sequential walk
    ...
    unlocked: PasswordConfirmVerdict | None = None
class MemberData(NamedTuple):     # one open of a member
    ...
    unlocked: PasswordConfirmVerdict | None = None
```

- `None`: no claim (a member that is not encrypted, or one whose data is still locked).
- On `MemberRecord`/`MemberSpan`: the listing step already unlocked this member's data
  with that verdict (DMG: every member `CONFIRMED` at listing; makeself: each payload's
  members `INCONCLUSIVE`). A `CONFIRMED` one makes the member `UNLOCKED` when listed. A
  header-only unlock sets nothing here: it proved only that the listing could be read.
- On `MemberData`: the verdict for this one stream. archivey keeps it on that stream's
  own verification proof (the per-stream proof and read watch the built-ins use), so two
  concurrent or respawned streams of a member never share it. A walk again (rewalk)
  reports its own spans, so the verdict is re-stated each time.
- `INCONCLUSIVE` on a stream: a mismatch of a digest archivey checks itself
  (`ArchiveMember.hashes`, `MemberData.digests`) at its end becomes the unverified-data
  `EncryptionError`. A `checked=True` stream's own errors are not remapped: archivey
  cannot tell its digest mismatch from a cut or a decoder fault (`TruncatedError` is a
  `CorruptionError`), so they go through ordinary translation. A plugin that wants the
  password-or-damage error declares the digest in `MemberData.digests` instead; a stream
  closed after delivering bytes but before its digest emits
  `ENCRYPTED_MEMBER_UNVERIFIED`, as for ZipCrypto; a digest that passes raises the
  member past `UNLOCKED` as usual.

Alternative: one member-wide flag set by the latest `unlock`. Rejected for the cases
above.

### D8. The provider is called only between plugin calls, never inside one

Inside a plugin call archivey may hold locks and per-call state: the handle guard around
`open_member` and stream reads under `MemberStreams.CONCURRENT`, the listing lock and
the materialization owner around `iter_members` and `walk`, and adapter scratch state
such as the nested-reopen marker around `open_member`. Releasing one of them around a
provider call leaves the others held, and releasing all of them would let another thread
change state the suspended call still uses. So `unlock` never calls the provider itself:

1. Inside the plugin call, `unlock` tries only what needs no provider call: the static
   candidates, and provider answers already given for this unit (by `what` and
   `member`), skipping any already rejected for it.
2. When it would need a new provider answer, it raises an internal signal (not an
   `ArchiveyError`, not visible to the plugin's `translate_exception`). The plugin call
   unwinds, and every lock and per-call state goes with it.
3. At the reader's public boundary (the caller's `open()`, iteration, `verify_all()` and
   so on), with no archivey lock held and the listing not mid-walk, archivey runs the
   provider call: the existing reentry check (own thread or copied context raises
   `ArchiveyUsageError`) and the existing one-at-a-time serialization, both before any
   lock or listing wait.
4. archivey then repeats the public operation from the start. The new answer is now in
   step 1's set, so the repeated call reaches the same `unlock` and tries it.

Cost: each new provider answer repeats the plugin's work up to that `unlock`. For
`open_member` that is a header read; for a first-touch listing it is the walk up to the
encrypted unit (a makeself payload), and for DMG the image header at `open`. Provider
answers are typed by a person or read from a keyring, so they are few; static candidates
never cause a repeat. Key derivation already charged for a rejected answer is not
charged again (the answer is skipped), and a plugin's own key cache survives the repeat.

The plugin may call `unlock` from `open`, `iter_members`, `walk` and `open_member`, and
from nowhere else (not from inside a stream's `read`). Its calls must be repeatable
(they already are: archivey rewalks and reopens today). A sequential walk that cannot be
repeated (a pipe with no spool) gets no provider answers: `unlock` there behaves as if
the provider returned `None` after the static candidates, and the missing-password
message says so.

Alternative: release the locks around an in-place provider call. Rejected for the
reasons above (listing lock, materialization wait, reopen marker).

## Risks / Trade-offs

- `unlock` is per call: a format that tries one password against many units must cache
  derived keys itself (makeself's `_keys` dict); archivey only orders the candidates.
- `what` is free text from the plugin and goes into an error message. Plain text is
  fine: error messages are not parsed, and archivey already quotes member names it
  inserts.
- A plugin can still decrypt without `unlock` by reading the password some other way
  (an environment variable). Nothing stops that, and nothing needs to.

## Open questions (all ruled by the maintainer, 2026-11-21)

1. D1: archivey runs the loop and the plugin writes only `check`? RULED yes (davi
   11-21).
2. D1/D3: `check` returns `(data, PasswordConfirmVerdict)` (davi 11-21: reuse the
   built-in enum and its levels; built-ins and plugins share it), with an optional
   `full_check` to decide between several unconfirmed passwords? RULED yes (davi 11-21).
3. D2: archivey writes both messages? RULED yes (davi 11-21, card).
4. D4: `charge_key_derivation(rounds)` on the context? RULED yes (davi 11-21, card).
5. D5: names `supports_password`, `ReaderArchiveInfo.is_encrypted`, `unlock`,
   `charge_key_derivation`, `PasswordConfirmVerdict` (`REJECTED`, `INCONCLUSIVE`,
   `CONFIRMED`). RULED keep all (davi 11-21, card).
6. Order: this API PR first, then makeself, ARJ and DMG on it? RULED yes (davi 11-21,
   card).
7. D7: the new public field `unlocked: PasswordConfirmVerdict | None` on `MemberRecord`,
   `MemberSpan` and `MemberData`? RULED yes (davi 11-21, card).
