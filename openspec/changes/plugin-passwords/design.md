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
    ) -> T: ...
```

`check(password)` tries one password and returns what that password unlocked (whatever
the plugin needs to decrypt later: a derived key, a cipher state, a decrypted header),
with how sure it is. archivey never looks inside the value; `unlock` returns it. Data is
`None` only with `REJECTED`. Any exception `check` raises ends the loop and reaches the caller
unchanged. `member` is what the provider's `PasswordRequest.member` shows (`None` for an
archive-level unit). `what` names the unit in archivey's messages ("makeself payload 2",
"the disk image").

This is the public form of the internal `password_confirm.attempt_with_confirm`
(probe + full check), which the ZIP, 7z and RAR readers already use. The enum is the one
they use, moved to `archivey.formats` and imported from there by the built-in readers, so
plugins and built-ins share one set of levels (davi 11-21). One change for the built-ins:
a probe may now return `REJECTED`, where today it raises the wrong-password
`EncryptionError` instead; both stay accepted inside archivey.

Example, makeself (openssl, AES-256-CBC). `unlock` returns the AES key and IV of the
password that worked:

```python
def check(password: bytes) -> tuple[AesParams | None, PasswordConfirmVerdict]:
    context.charge_key_derivation(10_000)        # PBKDF2 rounds, before the work
    params = derive_key(password, salt)          # AES key + IV
    first = aes_cbc_decrypt(params, first_block)
    if not first.startswith(GZIP_MAGIC):         # the payload must start with gzip
        return None, PasswordConfirmVerdict.REJECTED
    return params, PasswordConfirmVerdict.CONFIRMED       # a false match is about 1 in 2**24

params = context.unlock("makeself payload 1", check)
```

Example, ARJ garble (each byte XORed with the password; only the member's CRC-32 tells):

```python
def check(password):
    return password, PasswordConfirmVerdict.INCONCLUSIVE   # nothing to test before the data

def full_check(password):
    crc = crc32_of(degarble_and_decode(member_data, password))
    if crc != stored_crc:
        return None, PasswordConfirmVerdict.REJECTED
    return password, PasswordConfirmVerdict.CONFIRMED

key = context.unlock(member_label, check, full_check=full_check, member=member)
```

For DMG, `check` returns the unwrapped disk key, `CONFIRMED` once the 3DES padding and the
decrypted `koly` block check out.

Alternative: hand the plugin an iterator of candidates. Rejected (davi chose the loop in
archivey): the provider's rules (skip repeats, stop after three own repeats, no reentry,
one call at a time) and promotion would be each plugin's job.

### D2. archivey builds both errors

| Outcome | archivey raises |
| --- | --- |
| No password given, or the provider's first answer is `None` | `EncryptionError("{what} is encrypted: pass password= to read it")` |
| Every password tried came back `REJECTED` | wrong-password `EncryptionError("Wrong password for {what}")` |
| `check` or `full_check` raised | That exception, unchanged |

Same class as today for both (`EncryptionError`); the error-handling spec has no
subclasses for them, and callers already tell them apart only by message.

### D3. How several passwords are decided

The loop is the one the built-in readers run (`_PasswordCandidates.attempt` with
`settled`/`settle`):

1. Each static candidate in order goes through `check`. The first `CONFIRMED` wins at
   once, so no expensive derivation runs for the candidates after it. `REJECTED` is dropped.
   `INCONCLUSIVE` is set aside and the next candidate is tried.
2. When the candidates run out with **one** set aside, it wins; `full_check` does not
   run for it (every other candidate was `REJECTED`).
3. With **several** set aside, `full_check` runs on each in order. The first `CONFIRMED`
   wins; `REJECTED` is dropped. If none confirms (or there is no `full_check`), the first
   still `INCONCLUSIVE` wins.
4. With none left, the provider is asked, one answer at a time; its first answer that is
   not `REJECTED` wins (a person at a prompt answers one at a time, so there is nothing to
   compare it with).

A password that wins as `INCONCLUSIVE` is not promoted to be tried first for later units
(unless it was the only password given), and a checksum failure of that member's data
becomes the unverified-data `EncryptionError` ("wrong password or damaged data"), as for
ZipCrypto, so the link-target report says `password_or_damage`.

`PasswordConfirmVerdict` is an enum, not a score: the loop only needs "confirmed wins, wrong is
dropped, the rest wait", and new levels can be added to an enum later. A numeric score
would ask every plugin to calibrate numbers nothing compares across formats.

### D4. Key derivation: `ReaderContext.charge_key_derivation(rounds)`

Charges `rounds` to the open archive's `DecoderLimits.max_key_derivation_rounds` (shared
with every other derivation on that archive and visible in resource usage) and raises
`ResourceLimitError` before the work when it would pass the cap. The plugin calls it
inside `check`, before each derivation it does not have cached. Alternative: the plugin
reads the limit from `config` and counts itself; rejected because it would not share the
total with nested archives or show in resource usage.

### D5. Declaring and reporting encryption

```python
class FormatHandler:
    supports_password: ClassVar[bool] = False

class ReaderArchiveInfo(NamedTuple):
    is_encrypted: bool = False
```

- `supports_password = False`: `password=` is reported unused
  (`PASSWORD_ARGUMENT_UNUSED`) and `unlock` raises `ArchiveyUsageError` (a plugin bug).
  This replaces the internal `register_builtin_format(..., SUPPORTS_PASSWORD=True)`
  override.
- A member the plugin lists with `is_encrypted=True` is `Verification.NONE` until a
  `CONFIRMED` `unlock(member=that_member)`, or an archive-level `CONFIRMED` `unlock` made
  before the member was listed (DMG at open). An `INCONCLUSIVE` win leaves it at `NONE`
  until its checksum passes.
- `ReaderArchiveInfo.is_encrypted` becomes `ArchiveInfo.is_encrypted` (today the adapter
  always writes `False`).

### D6. Replacement readers

A replacement plugin for ZIP, 7z or RAR whose handler sets `supports_password` gets the
caller's `password=` through `unlock`, as any plugin does. The sentence in
`adding-a-format.md` saying a replaced ZIP cannot read encrypted members goes.

## Risks / Trade-offs

- `unlock` is per call: a format that tries one password against many units must cache
  derived keys itself (makeself's `_keys` dict); archivey only orders the candidates.
- `what` is free text from the plugin and goes into an error message. Plain text is
  fine: error messages are not parsed, and archivey already quotes member names it
  inserts.
- A plugin can still decrypt without `unlock` by reading the password some other way
  (an environment variable). Nothing stops that, and nothing needs to.

## Open questions (for the maintainer, one at a time)

1. D1: archivey runs the loop and the plugin writes only `check`? RULED yes (davi 11-21).
2. D1/D3: `check` returns `(data, PasswordConfirmVerdict)` (davi 11-21: reuse the built-in
   enum and its levels; built-ins and plugins share it), with an optional
   `full_check` to decide between several unconfirmed passwords? (Recommended: yes.)
3. D2: archivey writes both messages? (Recommended: yes.)
4. D4: `charge_key_derivation(rounds)` on the context? (Recommended: yes.)
5. D5: names `supports_password`, `ReaderArchiveInfo.is_encrypted`, `unlock`,
   `PasswordConfirmVerdict` (`REJECTED`, `INCONCLUSIVE`, `CONFIRMED`).
6. Order: this API PR first, then makeself, ARJ and DMG on it? (Recommended: yes.)
