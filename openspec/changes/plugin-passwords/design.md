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

### D1. archivey runs the loop; the plugin hands it a `NeedsPassword` request (RULED: davi 11-21, cards for questions 1 and 9)

```python
T = TypeVar("T")   # what one password unlocks: a derived key, a cipher state, a header
R = TypeVar("R")   # what the plugin call returns once the unit is unlocked

class PasswordConfirmVerdict(Enum):   # today internal/password_confirm.py; made public
    REJECTED = "rejected"           # this password is not the one
    INCONCLUSIVE = "inconclusive"   # passed every check run so far, could still be wrong
    CONFIRMED = "confirmed"         # the format's check proves it

Check = Callable[[bytes], tuple[T | None, PasswordConfirmVerdict]]

@dataclass(frozen=True)
class NeedsPassword(Generic[T, R]):
    what: str                                   # names the unit in archivey's messages
    check: Check[T]
    full_check: Check[T] | None = None
    member: ArchiveMember | None = None         # shown to the provider
    then: Callable[[T, PasswordConfirmVerdict], R] | None = None
```

The plugin never calls into archivey to unlock. It hands archivey a request and archivey
calls back with the result, so the password loop and the provider always run while no
plugin code is in progress (D8):

| Plugin call | How the plugin hands over the request | What archivey does with it |
| --- | --- | --- |
| `FormatHandler.open` (DMG) | Returns `NeedsPassword(..., then=...)` instead of the reader | Runs the loop, then calls `then(data, verdict)`, which returns the reader |
| `IndexedReader.open_member` (ARJ, a replaced ZIP) | Returns `NeedsPassword(..., then=...)` instead of `MemberData` | Runs the loop, then calls `then(data, verdict)`, which returns the `MemberData` |
| `IndexedReader.iter_members`, `SequentialReader.walk` (makeself, encrypted headers) | `data, verdict = yield NeedsPassword(...)`, with no `then` | Runs the loop while the generator is paused, then sends `(data, verdict)` into it |

`then` may itself return another `NeedsPassword` (headers under one key, then data under
another). A returned request without `then`, a yielded one with `then`, and a request
yielded by an iterator that is not a generator are plugin bugs.

`check(password)` tries one password and returns what that password unlocked (whatever
the plugin needs to decrypt later), with how sure it is. archivey never looks inside the
value; it passes the value on with the verdict it won with (the full check's when one
ran, or an earlier survivor's `INCONCLUSIVE` when archivey fell back to it), and the
plugin puts that verdict on `MemberData.unlocked` or `MemberSpan.unlocked` (D7). Data is
`None` only with `REJECTED`. An exception from `check` or `full_check` ends the loop
(D2). `member` is what the provider's existing `PasswordRequest.member` shows (`None`
for an archive-level unit); the new type is not called `PasswordRequest` because that
name is already the provider's argument. `what` names the unit in archivey's messages
("makeself payload 2", "the disk image").

The loop is the public form of the internal `password_confirm.attempt_with_confirm`
(probe + full check), which the ZIP, 7z and RAR readers already use. The enum is the one
they use, moved to `archivey.formats` and imported from there by the built-in readers,
so plugins and built-ins share one set of levels (davi 11-21).

**Strength rule** (the one `archive-reading` already states for the built-ins): a
verdict is `CONFIRMED` only on evidence at least as strong as a CRC-32 over 4 or more
decoded bytes (a false match no more often than 1 in 2^32), or a cryptographic check
(an AES key wrap, an HMAC, a validated decrypted structure of that strength). Anything
weaker (a magic number, padding, a CRC over fewer than 4 bytes) is a rejection filter:
it may return `REJECTED`, and otherwise `INCONCLUSIVE`.

One change for the built-ins: a probe may now return `REJECTED`, where today it raises
the wrong-password `EncryptionError` instead; both stay accepted inside archivey.

Example, makeself (openssl, AES-256-CBC). The walk pauses at each encrypted payload:

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

def walk(self, stream):
    ...
    params, verdict = yield NeedsPassword(f"makeself payload {n}", check)
    for span in self._tar_spans(decrypting(stream, params)):
        yield span._replace(unlocked=verdict)
```

makeself has no `full_check`: it is a forward walk with no replay, so with several
candidates that pass the magic the first one wins, unpromoted, as today. Its members
stay `NONE` until a read ends with the decoded TAR and compressor checks passing.

Example, ARJ garble (each byte XORed with the password; only the member's CRC-32 tells).
Garbled members are listed normally; only opening one needs the password:

```python
def check(password):
    return password, PasswordConfirmVerdict.INCONCLUSIVE   # nothing to test before the data

def full_check(password):
    crc, size = 0, 0
    packed = ExactSource(source.view(start, stored))  # counts bytes; records a short read
    decoder = degarble_and_decode(packed, password)
    try:
        while chunk := decoder.read(64 * 1024):       # bounded memory, never the
            crc = zlib.crc32(chunk, crc)              # whole member
            size += len(chunk)
    except CorruptionError:
        if packed.source_failed:                      # the source itself ended or failed
            raise                                     # inside a pull: propagate
        return None, PasswordConfirmVerdict.REJECTED  # the decoder over complete input
                                                      # (TruncatedError too): a wrong key
    if packed.consumed != stored:                     # decoder stopped early: wrong key
        return None, PasswordConfirmVerdict.REJECTED
    if crc != stored_crc:
        return None, PasswordConfirmVerdict.REJECTED
    if size < 4:                                      # below the strength rule
        return password, PasswordConfirmVerdict.INCONCLUSIVE
    return password, PasswordConfirmVerdict.CONFIRMED

def open_member(self, member, locator):
    if not locator.garbled:
        return MemberData(...)
    return NeedsPassword(
        member_label, check, full_check=full_check, member=member,
        then=lambda key, verdict: MemberData(degarbled_stream(key), unlocked=verdict),
    )                                                 # decoded again for the caller
```

The plugin decides which of its own failures depend on the password (return `REJECTED`)
and lets the rest propagate (source errors, a short read of the source itself, resource
limits). It tells them apart by where the error arose, not by class: `TruncatedError` is
a `CorruptionError`, and a decoder fed a complete span under a wrong key can raise it.
`ExactSource` is a small plugin-side wrapper over the view: it counts the bytes the
decoder pulls and sets `source_failed` when the view itself raises or returns short
before the declared extent, so a source failure inside a decoder pull is told apart
from the decoder's own error without pre-reading the span.
`full_check` decodes the whole member in bounded chunks (never holding it in memory, as
the built-in full check does), and the caller's read decodes it again; both are charged
where the decode limits measure them. It exists only where the plugin can replay the
unit: an indexed reader, or a sequential one that reads its unit into a bounded buffer
first.

For DMG, the handler's `open` reads the `encrcdsa` header and returns a request whose
`check` returns the unwrapped disk key, `CONFIRMED` once the key unwrap and the
decrypted `koly` block (a 512-byte structure with magic, version and sizes) check out;
its `then` builds the reader over the decrypting source.

Alternatives:

- Hand the plugin an iterator of candidates. Rejected (davi chose the loop in archivey):
  the provider's rules (skip repeats, stop after three own repeats, no reentry, one call
  at a time) and promotion would be each plugin's job.
- `ReaderContext.unlock(...)`, called from inside the plugin (this design's first
  version). Replaced (davi 11-21, question 9): archivey could not call the provider
  while the plugin's call held its locks, so `unlock` had to raise a hidden internal
  signal through plugin code and repeat the plugin call once per provider answer, with
  retry state keyed by call order, and a walk that had already yielded still called the
  provider with the listing lock held.

### D2. archivey builds both errors (RULED: davi 11-21, card)

| Outcome | archivey raises |
| --- | --- |
| No password given, or the provider's first answer is `None` | `EncryptionError("{what} is encrypted: pass password= to read it")` |
| Every password tried came back `REJECTED` | wrong-password `EncryptionError("Wrong password for {what}")` |
| `full_check` came back `REJECTED` for every candidate it ran on, and nothing stronger than the data checksum rejected them | unverified-data `EncryptionError` ("wrong password or damaged data"): a damaged member fails every CRC too |
| `check` or `full_check` raised (any exception, `EncryptionError` included) | Resolution stops; no further candidate or provider call. The exception then goes through the plugin's `translate_exception` like any other plugin exception |
| A callback returned something other than a 2-tuple of data and `PasswordConfirmVerdict`, or `None` data with a verdict other than `REJECTED` | Plugin bug (`_plugin_bug`, as for a bad `open_member` return) |
| A request misused (D1: `then` missing or present in the wrong place, yielded by a non-generator, handed over by a handler without `supports_password`) | Plugin bug |
| `then` raised | An ordinary plugin exception, through `translate_exception` |

Same class as today for both (`EncryptionError`); the error-handling spec has no
subclasses for them, and callers already tell them apart only by message. The
built-ins keep their path, where a probe's wrong-password `EncryptionError` means
`REJECTED`; the plugin path rejects only through the returned verdict.

### D3. How several passwords are decided

The loop is the one the built-in readers run (`_PasswordCandidates.attempt` with
`settled`/`settle`); `plugin_passwords.resolve_request` only adapts the plugin's
`(data, verdict)` callbacks to it and builds the errors (maintainer decision, 11-21:
one loop, not two). The steps below hold for built-in units and plugin requests alike:

1. Each static candidate in order goes through `check`. The first `CONFIRMED` wins at
   once, so no expensive derivation runs for the candidates after it. `REJECTED` is
   dropped. `INCONCLUSIVE` is set aside and the next candidate is tried.
2. When the candidates run out with **one** set aside, it wins without `full_check` when
   no provider can be asked or there is no `full_check`: every other candidate was
   `REJECTED`, and the read's own check reports a wrong one. While a provider can be
   asked and there is a `full_check`, it runs (maintainer decision, 11-21): the survivor
   may be a known-good password from another unit. `CONFIRMED` or `INCONCLUSIVE` wins,
   and `REJECTED` leads to step 4.
3. With **several** set aside, `full_check` runs on each in order. The first `CONFIRMED`
   wins; `REJECTED` is dropped. If none confirms (or there is no `full_check`), the
   first still `INCONCLUSIVE` wins.
4. With none left, the provider is asked, one answer at a time. An answer `check` calls
   `INCONCLUSIVE` goes through `full_check` when there is one; `REJECTED` from
   either asks the provider again. The first `CONFIRMED` answer wins, and an
   `INCONCLUSIVE` one wins only when there is no `full_check` (or it also came back
   `INCONCLUSIVE`), since a person at a prompt answers one at a time and there is
   nothing to compare it with. Before the merge into one loop the built-in readers
   accepted an `INCONCLUSIVE` provider answer without its full check; they now run it
   too, which costs one more decode of that unit only when a provider answered and the
   bounded check could not confirm the answer.

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
  a `NeedsPassword` it hands over is a plugin bug (`ArchiveyUsageError`). The shared
  backend-class builder maps it next to `uses_encoding`, so registration and replacement
  agree, and makeself declares it in the API PR. This replaces the internal
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
caller's `password=` through `NeedsPassword`, as any plugin does. The sentence in
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

Alternative: one member-wide flag set by the latest request. Rejected for the cases
above.

### D8. The provider runs while no plugin code is in progress (RULED: davi 11-21, question 9)

Inside a plugin call archivey holds locks and per-call state: the handle guard around
`open_member` and stream reads under `MemberStreams.CONCURRENT`, the listing lock and
the materialization owner around `iter_members` and `walk`, and adapter scratch state
such as the nested-reopen marker around `open_member`. Because the plugin hands over a
request instead of calling in (D1), archivey resolves it at a point where it chooses
what is held. Two rules decide it:

1. **Plugin code runs under the plugin's guards.** `check`, `full_check` and `then` are
   plugin code: ARJ's full check decodes a stream, and a third-party plugin may run them
   on a shared library handle. archivey enters the same scoped handle guard and adapter
   state as the call that handed over the request (the handle guard for `open_member`,
   the walk's own state for a yielded request) around each callback, and leaves it after
   each one. Two overlapping requests on one shared handle are therefore serialized
   like any two member opens.
2. **The provider runs outside the plugin's guards.** Before each provider call
   archivey leaves the handle guard it took for the request, and takes it again after
   the answer, before the next callback, putting back the adapter state the step had
   set (another thread's step may set and clear it meanwhile). The walk lock a listing
   or a paused walk holds, and an outer frame's lock on the same stack, stay held: they
   are the ownership record below. A wait on one of them is refused, not blocked, when
   it comes from the provider's thread or a context copied from it
   (`ProviderAwareRLock`, and the same check before the materialization wait and in
   `close()`), and any other thread waits its turn, as it would for the walk.

Logical ownership is kept apart from the physical locks:

- **A returned request** (`open`, `open_member`) is owned by the worker that runs it,
  and that worker stays registered as active while the provider runs. `then` uses only
  what its closure captured and the reader's own state, as `open_member` already must
  under `CONCURRENT`.
- **A yielded request** (`walk`, `iter_members`): the generator is paused at its
  `yield`. archivey records the walk as paused on the provider (its listing ownership
  and materialization ownership stay with the paused walk, so no other thread may
  advance it) and releases the handle guard. The walk lock stays held, and records
  that ownership.
- **A request reached below an outer archivey frame** that holds a lock, such as
  listing finalization, which holds the listing lock while it reads link targets
  (`_finalize_and_publish`): that frame's lock stays held for the provider call, and
  is its ownership record, so its state stays reserved for it.

Every same-reader entry that would wait on a request's owner checks the provider context
first: listing and iteration (`members()`, `iter_members()`, the materialization wait),
`open()` and `read()` of members that need the listing, `stream_members()`, `close()`
(its wait for active workers), and link-target reads. From the provider's own thread or
a context copied from it (the existing `_PROVIDER_CALL` check), each raises
`ArchiveyUsageError` at once instead of waiting. From any other thread it waits on the
ownership record until the provider has answered, as it waits for the walk or the worker
today.

In both cases the request object is the unit. Its rejected answers and the provider's
attempt count for it live on the request and end with it, so no identity by call order
is needed, and no plugin call is ever repeated. Promotion of a known-good password
across units stays per reader, as today. The provider's reentry check and one-at-a-time
serialization run before any lock or listing wait, as today.

When resolution fails (no password, every password wrong, or a callback raised), a
returned request raises that error from the public call. For a yielded request archivey
closes the generator and the error ends the walk, as any walk error does: a streaming
walk that already yielded members is poisoned, as today, and an indexed listing that
failed before its first member publishes nothing.

A plugin hands over requests from `open`, `iter_members`, `walk` and `open_member`
(and from a `then` it was given), and from nowhere else: not from inside a stream's
`read`.

**Calls archivey makes again on its own.** The adapter calls the same hooks again
without a new public call: a random-access data walk over a sequential plugin (makeself
read out of order), a respawn of a forward-only indexed stream on a backward seek
(`RespawnStream` calling `open_member` once more), and a rewalk after the listing.
Requests met there are resolved too, under these rules:

- **The last winner is tried first.** The reader keeps, for its lifetime (dropped at
  `close()`), the password that won each request, and whether its resolution needed
  `full_check`, keyed by the request's place: the plugin call (the member for
  `open_member`, the handler for `open`, the k-th yielded request for a walk; a walk is
  deterministic over the same source, as rewalks already assume) plus the request's
  index in that call's chain (0 for the first request, 1 for the one its `then`
  returned, and so on). A member whose header and data need different passwords
  therefore keeps both. A repeat tries the saved password first and still runs `check`
  (and `full_check` when the first resolution needed it). So a late makeself rewalk
  does not ask the provider again for payload 1, although its `INCONCLUSIVE` winner is
  not promoted for other units (D3). On a fresh open (not a replacement of a stream
  already unlocked) an unconfirmed saved winner is not taken at once: it is the first
  survivor, and the other passwords are probed as usual, so a password another unit
  has confirmed since can win. That winner becomes the reader's saved winner, but a
  stream already open keeps its own: each member handle, and each walk, records the
  winners its data was unlocked with, and its replacement opens try those first. A
  respawn that took the reader's latest winner instead would hand the caller bytes
  decrypted with another password at the same offsets, and the checksum state the
  verifier carries over would mix the two. For the same reason a replacement open
  goes on with an idle data walk only when that walk unlocked the requests it passed
  with the handle's winners; otherwise it walks again from the start.
- **The provider only at a first open.** A first open of a member may ask the provider:
  the caller's `open()`, a data walk it starts, and the first open of a lazy pass handle
  from `stream_members()` or extraction, which calls `open_member` on the handle's
  first `read()`. So a member that `reader.open(name)` can read with a provider alone,
  `stream_members()` and extraction can read too, and a member the caller skips is
  never opened and never prompts. A replacement open of a stream that was already
  unlocked (a respawn on a backward seek, a data walk stepped again inside that
  stream's `read`) never asks: there the saved winners and the static candidates are
  tried, and if none unlocks a request in the chain the read raises the D2 exhaustion
  error for it.
- **The verdict follows the replacement.** The replacement stream's watch takes the new
  `unlocked` verdict, from a respawn's `MemberData` or a data walk's span, so a
  replacement unlocked as `INCONCLUSIVE` after a `CONFIRMED` original is checked as
  `INCONCLUSIVE` from then on, and the reverse. Its checks (`digests`, `checked`,
  `bounded`; a span's `checked` and `digests`) must match the first open's, because the
  verifier over the caller's stream was built from those: a replacement that changes
  them is refused as a plugin bug.


Remaining limit: a provider that waits for a separate thread (not a copied context) that
needs the same request's owner waits forever. That is the provider's own deadlock, the
same as a provider that waits for any lock its own caller holds, and the docs say so.

## Risks / Trade-offs

- Each request is one unit: a format that tries one password against many units must
  cache derived keys itself (makeself's `_keys` dict); archivey only orders the
  candidates.
- `what` is free text from the plugin and goes into an error message. Plain text is
  fine: error messages are not parsed, and archivey already quotes member names it
  inserts.
- A plugin can still decrypt without `NeedsPassword` by reading the password some other
  way (an environment variable). Nothing stops that, and nothing needs to.

## Open questions

1. D1: archivey runs the loop and the plugin writes only `check`? RULED yes (davi
   11-21).
2. D1/D3: `check` returns `(data, PasswordConfirmVerdict)` (davi 11-21: reuse the
   built-in enum and its levels; built-ins and plugins share it), with an optional
   `full_check` to decide between several unconfirmed passwords? RULED yes (davi 11-21).
3. D2: archivey writes both messages? RULED yes (davi 11-21, card).
4. D4: `charge_key_derivation(rounds)` on the context? RULED yes (davi 11-21, card).
5. D5: names `supports_password`, `ReaderArchiveInfo.is_encrypted`, `unlock`,
   `charge_key_derivation`, `PasswordConfirmVerdict` (`REJECTED`, `INCONCLUSIVE`,
   `CONFIRMED`). RULED keep all (davi 11-21, card); `unlock` later replaced by
   question 9.
6. Order: this API PR first, then makeself, ARJ and DMG on it? RULED yes (davi 11-21,
   card).
7. D7: the new public field `unlocked: PasswordConfirmVerdict | None` on `MemberRecord`,
   `MemberSpan` and `MemberData`? RULED yes (davi 11-21, card).
8. D8: a walk that already yielded members calls the provider in place? RULED yes (davi
   11-21, card); superseded by question 9, which removes the in-place call.
9. D1/D8: instead of calling `context.unlock`, the plugin returns or yields a request
   and archivey calls back with the key? RULED yes (davi 11-21, card).
10. D1: the request's name, `NeedsPassword`. RULED yes (davi 11-21, card).
11. D8: a member's first lazy open (first `read()` of a `stream_members()` or
    extraction handle) may ask the provider, like `open()`; replacement opens never do?
    RULED yes (davi 11-21, card).
    (`PasswordRequest` is already the provider's argument type.)
12. D8: the walk lock and an outer frame's lock stay held while the provider runs, with
    provider-context waits refused, rather than released with ownership records only?
    RULED keep them held (davi 11-21, card). The `reader-concurrency` delta amends "no
    Archivey lock held" to match.
13. D3: one password loop for built-in units and plugin requests, as the archive-reading
    spec requires, instead of a second loop kept in step by tests? RULED one loop (davi
    11-21, card).
