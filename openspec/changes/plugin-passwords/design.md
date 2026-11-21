## Context

The built-in password machinery is `internal/password.py`. `_PasswordCandidates` holds the
caller's `password=` (one value, a list, or a provider callable) for one open archive, and
`attempt(member, decrypt)` tries the passwords on one encrypted unit: static candidates
first (the one that last worked leads), then the provider, skipping answers already tried
and stopping a provider stuck on one answer. It guards provider reentry and serializes
provider calls across threads. `wrong_password_error` marks the `EncryptionError` that a
failed check raises, so exhaustion keeps its message; `unverified_data_error` marks a
checksum failure under a password nothing confirmed (ZipCrypto, RAR 2.9-4).

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

### D1. archivey runs the loop; the plugin writes `check`

```python
T = TypeVar("T")

class ReaderContext:
    def unlock(
        self,
        what: str,
        check: Callable[[bytes], T | None],
        *,
        member: ArchiveMember | None = None,
    ) -> T: ...
```

`check(password)` returns what the password unlocked (a key, a cipher state, a decrypted
header) or `None` when the password is wrong. Any exception it raises ends the loop and
reaches the caller unchanged. `member` is what the provider's `PasswordRequest.member`
shows (`None` for an archive-level unit). `what` names the unit in archivey's messages
("makeself payload 2", "the disk image").

Alternative: hand the plugin an iterator of candidates. Rejected because the provider's
rules (skip repeats, stop after three own repeats, no reentry, one call at a time) and
promotion would then be each plugin's job, and a mistake asks a person to type a password
again or loops forever.

### D2. `None` means wrong; archivey builds both errors

| Outcome | archivey raises |
| --- | --- |
| No password given, or the provider's first answer is `None` | `EncryptionError("{what} is encrypted: pass password= to read it")` |
| Every password tried, `check` returned `None` for each | wrong-password `EncryptionError("Wrong password for {what}")` |
| `check` raised | That exception, unchanged |

Same class as today for both (`EncryptionError`); the error-handling spec has no
subclasses for them, and callers already tell them apart only by message. Alternative: a
public `WrongPasswordError` the plugin raises; rejected as a new public exception for no
caller benefit.

### D3. Weak and absent checks: `unconfirmed(result)`

```python
def unconfirmed(result: T) -> Unconfirmed[T]: ...
```

`check` returns `unconfirmed(x)` when the password passed every check the format has but
could still be wrong (ARJ garble: always; a one-byte check). archivey then:

- keeps trying the other static candidates; one confirmed result wins, else the first
  unconfirmed one does (the internal `attempt(settled=...)` rule);
- does not promote it to be tried first for later units;
- turns a checksum failure of that member's data into the unverified-data
  `EncryptionError` ("wrong password or damaged data"), as for ZipCrypto, so the
  link-target report says `password_or_damage`.

Alternative: leave weak checks out of v1. Rejected because ARJ garble needs it now, and
adding it later would change what `check` may return.

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

- `supports_password = False`: `password=` is reported unused (`PASSWORD_ARGUMENT_UNUSED`)
  and `unlock` raises `ArchiveyUsageError` (a plugin bug). This replaces the internal
  `register_builtin_format(..., SUPPORTS_PASSWORD=True)` override.
- A member the plugin lists with `is_encrypted=True` is `Verification.NONE` until a
  confirmed `unlock(member=that_member)`, or an archive-level confirmed `unlock` made
  before the member was listed (DMG at open). An unconfirmed unlock leaves it at `NONE`
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
- `what` is free text from the plugin and goes into an error message. Plain text is fine:
  error messages are not parsed, and archivey already quotes member names it inserts.
- A plugin can still decrypt without `unlock` by reading the password some other way
  (an environment variable). Nothing stops that, and nothing needs to.

## Open questions (for the maintainer, one at a time)

1. D1: archivey runs the loop and the plugin writes only `check`? (Recommended: yes.)
2. D2: `check` returns `None` for wrong, and archivey writes both messages? (Recommended: yes.)
3. D3: weak checks in v1 through `unconfirmed()`? (Recommended: yes, for ARJ.)
4. D4: `charge_key_derivation(rounds)` on the context? (Recommended: yes.)
5. D5: names `supports_password`, `ReaderArchiveInfo.is_encrypted`, `unlock`, `unconfirmed`.
6. Order: this API PR first, then makeself, ARJ and DMG on it? (Recommended: yes.)
