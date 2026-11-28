# format-plugins Specification

## Purpose
TBD - created by archiving change format-policy. Update Purpose after archive.

## Requirements

### Requirement: A replacement plugin declares a built-in format and no detection

An `IndexedFormatHandler` named in `FormatPolicy(replace=)` SHALL NOT be registered. Its `format`
SHALL be the built-in `ArchiveFormat(key, StreamFormat.UNCOMPRESSED)` of the container
it replaces, the key SHALL be `ZIP`, `SEVEN_Z`, `RAR` or `ISO`, the plugin SHALL be an
indexed one, and it SHALL declare no `extensions`, `magic` or `probe`. Building the
policy SHALL refuse any other plugin with `ArchiveyUsageError`, so a bad replacement
fails before any open.

#### Scenario: replacement refusals

| Case | Expected |
| --- | --- |
| `replace={ContainerFormat.ZIP: P}`, `P.format` is `ArchiveFormat.ZIP`, no signals | Accepted |
| `replace={ContainerFormat.TAR: P}` | `ArchiveyUsageError` naming `ContainerFormat.TAR` |
| `P.format` is a plugin format, or another built-in format | `ArchiveyUsageError` |
| `P` declares `extensions`, `magic` or `probe` | `ArchiveyUsageError` |
| `P` is a sequential plugin | `ArchiveyUsageError` |
| The value is not an `IndexedFormatHandler` subclass | `ArchiveyUsageError` |

### Requirement: A sequential walk reads an archive stored inside its archive

`ForwardStream.take(n)` SHALL return a stream of the next `n` bytes, read forward from
the archive, that ends after them and raises `TruncatedError` where the archive ends
first. The next `read`, `skip`, `take` or `decompress` on the `ForwardStream` SHALL skip
what the stream left unread; a read of the stream after that SHALL raise
`ArchiveyUsageError`.

`ReaderContext.open_nested(data, format)`, called from `SequentialReader.walk`, SHALL
read `data` with archivey's reader for `format` (or the caller's `FormatPolicy`
replacement for it) in one forward pass and yield one `MemberSpan` per inner member, in
the inner archive's order, its decoded data as `MemberSpan.data`. The inner reader SHALL
use the caller's config and `encoding`; what it reports SHALL go into the outer reader's
diagnostics with `member_id` as the outer listing numbers the member, when the walk
yields each span in order, and SHALL be attached to that member, while its data is read
too; its errors SHALL raise from the walk. Name checks SHALL run once, on the members
the outer listing lists. The inner reader SHALL join the outer reader's nest
(`archive-reading`, "A reader opened inside another joins its nest"): it shares
`max_metadata_bytes` through the outermost listing, charges what its listing decodes to
the enclosing listing's `max_decoded_bytes` while that listing runs, gets the
`max_decoder_memory` the open outer levels left, is held to `max_ratio` against the
outermost archive, and counts toward the nest's totals ("Limits apply per nest"). A
chain of more than nine archives, the outermost included and readers opened with
`open_archive(..., parent=)` counted too (`MAX_NESTED_DEPTH` is 8 levels below the
outermost), SHALL be refused with `UnsupportedFeatureError`.

#### Scenario: nested reads

- **WHEN** a call is made as each row says
- **THEN** it behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| A walk yields the spans of a `.tar` and a `.tar.xz`, renamed, read from a pipe | The renamed members, their bytes, no diagnostics |
| The same with random access, members opened out of order | The same bytes |
| An inner TAR header with an unknown type, third member listed | One `MEMBER_TYPE_UNKNOWN`, `member_id` 2, attached to that member |
| The same name twice across two inner archives | One `MEMBER_NAME_DUPLICATE` |
| An inner archive shorter than its `take` | The walk resumes after the taken bytes |
| A ZIP inside, read from a pipe | Its members |
| A 7z inside | `UnsupportedFeatureError` |
| `open_nested` called outside `walk()` | `ArchiveyUsageError` |
| A format that names itself as its inner format, 9 levels deep | `UnsupportedFeatureError` |
| An `open_nested` archive inside a reader opened with `parent=` 8 levels below the outermost | `UnsupportedFeatureError` |
| A `take` stream read after the walk moved on, one byte read before | `ArchiveyUsageError` |

### Requirement: An indexed reader reads an archive stored inside its archive

`ReaderContext.open_nested(data, format)` SHALL also be callable from
`IndexedReader.iter_members`, with the behavior it has from a walk: the reader yields a
`MemberRecord` of each span's member at once, in order, and inner reports carry the
outer listing's `member_id`. Called from `IndexedReader.open_member` for a member listed
from an inner archive, over the same inner archive's bytes and format, it SHALL yield
one span, the member being opened, whose `data` is that member's data. Reading the inner
archive forward to that member SHALL report nothing the listing reported. When the
member's data stream is closed, the next member opened further on in the same inner
archive SHALL carry on from that point, so a pass over the members in order reads each
inner archive once. Called from `open_member` for any other member, it SHALL raise
`ArchiveyUsageError`.

#### Scenario: nested reads from an indexed reader

| Case | Expected |
| --- | --- |
| An indexed reader lists a `.tar` and a `.tar.xz` and opens their members out of order, and again | The bytes; a hard link names its prefixed target |
| An inner TAR header with an unknown type, then every member read | One `MEMBER_TYPE_UNKNOWN`, `member_id` 2 |
| `extract_all` of a package with two payloads | Each payload read once after the listing |
| `open_nested` from `open_member` of a member no inner archive holds | `ArchiveyUsageError` |

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
| Respawn (replacement open) inside `read()` where the saved winner no longer unlocks the unit | The wrong-password-or-unverified-data `EncryptionError` for an exhausted provider (`archive-reading`, "Confirm candidates when a weak check permits retries") from that `read()`; provider not called |
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

### Requirement: A package adds a format through archivey.formats

The system SHALL let a package outside archivey add a read-only format by subclassing
`archivey.formats.FormatHandler` and one of `archivey.formats.IndexedReader` or
`archivey.formats.SequentialReader`, and calling
`archivey.formats.register_format()`. A plugin reader SHALL NOT subclass or see
`BaseArchiveReader`. An internal adapter SHALL present it as an ordinary
`ArchiveReader`.

#### Scenario: plugin format through the public API

| Case | Expected |
| --- | --- |
| An LHA plugin is registered; `open_archive("a.lha")` | Reader with `format.container` the plugin's `PluginContainer` member; `members()`, `open()`, `stream_members()`, `extract_all()` work |
| Same, `detect_format("a.lha")` | The plugin format |
| Same, `format_availability("lha")` | `FULL` |
| No plugin registered, `open_archive("a.lha")` | `FormatDetectionError`, as today |

### Requirement: Plugin containers subclass PluginContainer

`ArchiveFormat.container` SHALL accept a member of a `PluginContainer` subclass and keep
it unchanged. `register_format()` SHALL refuse with `ArchiveyUsageError` a container
value equal to a built-in or registered one, and an extension a built-in format claims.

#### Scenario: registration refusals

| Case | Expected |
| --- | --- |
| Plugin container value `"zip"` | `ArchiveyUsageError` |
| Plugin extension `".tar"` | `ArchiveyUsageError` |
| Same plugin registered twice | `ArchiveyUsageError` |

### Requirement: Built-in detection signals outrank plugin signals

A plugin magic or probe match SHALL count only when no built-in format matched at the
same or a higher confidence. A plugin probe SHALL receive only the prefix detection
already read. A probe that raises SHALL count as no match, so one plugin cannot change
how unrelated input fails to be detected; `MemoryError` and `OSError` still propagate.
In the same way, a plugin codec's decoder that raises an exception its
`translate_exception` does not map, while detection decodes the start of the stream to
look for a container inside it, SHALL count as no container there; the open still
raises it.

#### Scenario: plugin magic does not change built-in detection

| Case | Expected |
| --- | --- |
| A plugin declares magic `PK\x03\x04`; a ZIP is detected | `ArchiveFormat.ZIP` |
| A plugin declares magic `55 AA` at 510; an isohybrid ISO is detected | `ArchiveFormat.ISO` (far magic is a built-in signal) |
| A plugin declares magic `MZ` at 0; a ZIP behind a PE stub is detected | `ArchiveFormat.ZIP` (the SFX scan is a built-in signal) |

### Requirement: Plugin member data is checked like built-in member data

The adapter SHALL verify every plugin member stream against the listed size and the
digests the plugin returns, and SHALL apply the built-in name normalization, name
checks, listing limits and extraction limits to plugin members. A member a plugin keeps
back to yield later and passes to `ReaderContext.hold()` SHALL count toward the listing
limits with the members already listed while it is held, and once in all after it is
yielded.

#### Scenario: plugin data checks

| Case | Expected |
| --- | --- |
| Plugin stream shorter than the listed size, read to the end | `TruncatedError` |
| Plugin returns a CRC-32 that does not match | `CorruptionError` |
| Plugin lists a member named `../x`; `extract_all` | Refused as for a built-in format |
| Three members listed, then two held with `hold()`, under `max_members=4` | `ResourceLimitError` at the second `hold()` |

### Requirement: Sequential plugins read forward-only sources

A `SequentialReader` plugin SHALL be readable from a non-seekable source in one forward
pass through `stream_members()`, iteration and `extract_all()`, with the listing limits
enforced as members arrive. The adapter SHALL own each member's data window and skip
what the caller leaves unread. On a seekable source the adapter SHALL serve random
access without an `open_member` from the plugin.

#### Scenario: sequential plugin sources

| Case | Expected |
| --- | --- |
| An archive of a sequential plugin format piped to `open_archive(stream, pipe=True)`; `stream_members()` | Every member with its data, in one pass |
| `x.lha.gz` from a file; `open(member)` on the third member | Its data |
| A caller reads half of a member's stream and advances | The next member's header and data are read correctly |

### Requirement: Sequential plugins may hand over decoded member data

A `SequentialReader` whose library decodes each member SHALL be able to yield the
member's decoded bytes as `MemberSpan.data`, with `data_length` 0. The adapter SHALL
read the member through that stream with the checks stored data gets, drain what the
caller leaves (at most one byte past a listed size) before the walk moves on, and serve
random access by walking again from the start to the member, carrying on from the last
such walk when members are opened in archive order. A walk started again SHALL yield the
same members in the same order.

#### Scenario: decoded member data

| Case | Expected |
| --- | --- |
| A pipe; `stream_members()`, each member read part-way | Every member's start, in one walk |
| A file; `open()` on members in archive order | Their data, through one walk after the listing |
| A file; `open()` on a member before the last one opened | Its data, through a walk from the start |
| Decoded data longer than the listed size | `CorruptionError` |
| Decoded data shorter than the listed size | `TruncatedError` when read |
| A second walk yields another member at the opened member's place | `ValueError` (a plugin bug) |

### Requirement: A sequential plugin may list from a header and read data on demand

A `SequentialReader` that sets `data_on_demand` lists every member from a header at the
start of the archive and hands each member's data as a `MemberSpan.data` stream that
reads the rest of the archive only when it is read. The adapter SHALL close such a
stream unread when the walk moves on instead of draining it, SHALL report the listing
as `ListingCost.INDEXED`, and SHALL drop the reports a walk started over to reach member
data makes, since the listing walk made them already.

#### Scenario: data on demand

| Case | Expected |
| --- | --- |
| An RPM whose payload does not decode; `members()` | Every member; `CorruptionError` only when a member's data is read |
| An RPM; `info.cost.listing_cost` | `INDEXED` |
| An RPM with a member reported at listing; `read()` of another member | The report once |

### Requirement: Sequential plugin formats are detected inside compression streams

Detection SHALL check registered sequential plugins' magic inside any single-file
compression stream archivey decodes (gzip, bzip2, xz, zstd and the rest, the set a
compressed TAR has) after TAR, within the prefix and budget the inner-TAR probe uses
today. A plugin with no magic SHALL be found there by its probe, run on the same decoded
prefix under the rule its probe follows on an uncompressed source: where the extension
names the plugin's format inside the compressor (`x.lha.gz`), or `always_probe_content`
is set.

#### Scenario: compressed plugin format

| Case | Expected |
| --- | --- |
| `x.lha.gz` from a file, a sequential plugin for LHA registered; `detect_format` | `ArchiveFormat(LhaContainer.LHA, StreamFormat.GZIP)` |
| No plugin registered; `x.lha.gz` | Detects as `GZ`, as today |
| A sequential LHA plugin with a probe and no magic; gzip of an archive it matches, named `x.lha.gz` | `ArchiveFormat(LhaContainer.LHA, StreamFormat.GZIP)` |
| The same bytes named `x.gz`, default config | `GZ`: the name does not let the probe run |

### Requirement: FormatInfo marks plugin formats

`FormatInfo` SHALL carry `from_plugin`, true for a format added by `register_format()`
and false for every built-in format.

#### Scenario: from_plugin

| Case | Expected |
| --- | --- |
| `format_availability` / `FormatInfo` for a registered plugin | `from_plugin` is `True` |
| The same for `ArchiveFormat.ZIP` | `from_plugin` is `False` |

### Requirement: A package adds a compression format through register_codec

`archivey.formats` SHALL provide `CodecHandler`, `PluginStream` and `register_codec()`.
A handler declares a `PluginStream` member as its `stream_format`, and its
`decompressor(call)` returns a decoder with the interface of `bz2.BZ2Decompressor`.
The `CodecCall` it is given SHALL carry the `size` and `properties` a format reader
passed to `ReaderContext.decompress()`, the caller's `DecoderLimits`, and, during a
detection probe only, the probe's output bound.
After `register_codec()`, archivey SHALL read the format as a single compressed file,
around a TAR, around each sequential plugin format registered before or after it, in
`open_stream()` and in `ReaderContext.decompress()`, and `detect_format`,
`format_availability`, the format lists and `format=` SHALL know it. The decoder's
output SHALL be held to the decoder limits and the ratio guard, and its end of data
SHALL follow the rules of the built-in one-stream codecs (truncation, zero padding,
further streams by magic, trailing data). `FormatPolicy(plugins=False)` SHALL turn the
codec off, and `FormatInfo.from_plugin` SHALL be true for a format that uses it.

#### Scenario: a registered codec

| Case | Expected |
| --- | --- |
| `x.toy` with the codec's magic; `open_archive` | `ArchiveFormat(RAW_STREAM, ToyStream.TOY)`, one member, decoded bytes |
| A TAR inside the codec, no name | `ArchiveFormat(TAR, ToyStream.TOY)` by the inner probe |
| The same, `FormatPolicy(only={TAR, ToyStream.TOY})` | `ArchiveFormat(TAR, ToyStream.TOY)`: the policy allows a pair with the codec, so its magic stays |
| A sequential plugin registered after the codec; `x.lha.toy` | `ArchiveFormat(LhaContainer.LHA, ToyStream.TOY)` |
| The stream cut short | `TruncatedError` |
| `ReaderContext.decompress(data, ToyStream.TOY, size=n, properties=p)` | the decoder's `CodecCall` has `size=n`, `properties=p` and the caller's limits |
| The inner-TAR probe decodes the codec | `CodecCall.probe_bound` set; `None` on a read |
| A module in `requires` missing | `FormatSupport.NONE` with the handler's install hint |
| `open_stream(format=ToyStream.TOY)` before `register_codec()` | `UnsupportedFeatureError` naming `register_codec`, as `open_archive` refuses an unregistered format |
| `stream_format = StreamFormat.GZIP`, or a value a built-in uses | `ArchiveyUsageError` at registration |

### Requirement: A plugin asks for an archivey-speedups fast decoder by name

`ReaderContext.speedup(name)` and `CodecCall.speedup(name)` SHALL return the named fast
decoder of archivey-speedups when it can run: the package is installed and recent
enough, the caller's library policy allows it, and, for the five decoders, under
`ProcessIsolation.NATIVE_DECODERS`, a decoder child can run it. The `"crc16_arc"`
checksum SHALL follow the in-process checksum rule under every isolation setting.
Otherwise they SHALL return `None`. A name that is not a speedup SHALL raise
`ArchiveyUsageError`. `archivey.speedups` SHALL name the interface of each speedup.
archivey SHALL give back the decoder child of each object it handed out when the member
stream (for a codec) or the reader closes, and when the codec's `decompressor()` or the
reader's open raises. Each decompressor SHALL own what its call handed out, whatever its
equality or hash. `CodecCall` SHALL pickle, resolve its type hints and convert as a
plain dataclass, and a call copied with `dataclasses.replace` SHALL ask with the
caller's policy. The lookup SHALL check what can run; under `NATIVE_DECODERS`, making a
decoder or decoding a block SHALL raise `ResourceUnavailableError` when no decoder child
can start then.

#### Scenario: asking for a speedup

| Case | Expected |
| --- | --- |
| archivey-speedups installed, default config | each name returns a callable |
| `FormatPolicy(exclude_libraries={"archivey-speedups"})` | each name returns `None` |
| `ProcessIsolation.NATIVE_DECODERS` | a decoder is asked to run in a decoder child |
| the same, no decoder child can run | `"crc16_arc"` returns a callable; the decoders return `None` |
| two live decompressors that compare equal; the first stream closes | only the first one's child is given back |
| `decompressor()` or the reader's open raises after making an LZW decompressor | the child is given back before the error reaches the caller |
| `speedup("bcj2")` | `ArchiveyUsageError` |
| a reader made an LZW decompressor in a decoder child; the reader closes | the child is given back |
| the same, the object is in this process | it is closed, which does nothing: it keeps decoding |
| a reader closes its LZW decompressor when the member is done | the child is given back then, and closing again at reader close is harmless |
