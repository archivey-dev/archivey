# Diagnostics

## Purpose

Advisory library events as immutable, policy-controlled data: stable codes, typed
JSON-safe context, bounded retention, and lifecycle-aware aggregation across
detection, readers, streams, and extraction.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | `reader.diagnostics` / stream-filtered views (observables) |
| `format-detection` | Standalone `FormatInfo.diagnostics`; open handoff of one collector |
| `safe-extraction` | Extraction report ranges over the shared collector |
| `access-mode-and-cost` | Runtime events must not mutate `CostReceipt` |
| `logging` | Log-record projection (WARNING, or INFO for the codes `_INFO_LOG_CODES` names); handlers run unlocked |
| `reader-concurrency` | Callbacks / providers hold no Archivey locks |

## Requirements

### Requirement: Immutable diagnostic values with stable codes and safe typed context

Every advisory event SHALL be an immutable `Diagnostic`: opaque process-local
`occurrence_id`, stable `DiagnosticCode`, human `message`,
and code-specific frozen `DiagnosticContext`. Codes are the machine contract;
messages are not stable.

Contexts are a closed typed union of JSON-safe immutable scalar/tuple values.
Raw bytes use an explicitly named base64 field. `to_dict()` on diagnostic and
context SHALL be `json.dumps`-safe without a custom encoder.

| Code | Variant and required fields |
| --- | --- |
| `MEMBER_NAME_NORMALIZED` | `NameNormalizationContext`: `kind="name_normalization"`, `archive_name`, `member_name`, `member_id`, `raw_name_base64`, `presented_name`, `normalized_name` |
| `MEMBER_NAME_ENCODING_INFERRED` | `NameEncodingContext`: `kind="name_encoding"`, `archive_name`, `member_name`, `member_id`, `raw_name_base64`, `inferred_encoding`, `declared_encoding` |
| `MEMBER_NAME_BIDI_CONTROL` | `MemberNameControlsContext`: `kind="member_name_controls"`, `archive_name`, `member_name`, `member_id`, `raw_name_base64`, `controls`, `field` (`"name"` or `"link_target"`: which text carries the controls; emitted once per member for each), `category="bidi"` |
| `MEMBER_NAME_ZERO_WIDTH_CHARACTER` | `MemberNameControlsContext` as for `MEMBER_NAME_BIDI_CONTROL`, with `category="zero_width"`: `controls` lists the occurrences of U+200B, U+2060 and U+FEFF |
| `MEMBER_NAME_INVISIBLE_CHARACTER` | `MemberNameControlsContext` as for `MEMBER_NAME_BIDI_CONTROL`, with `category="invisible"`: `controls` lists the other characters of Unicode category Cf that are not bidi controls (for example U+00AD, U+200C, U+200D, the tag characters) |
| `FORMAT_EXTENSION_CONFLICT` | `FormatConflictContext`: `kind="format_conflict"`, `source_name`, `extension`, `extension_format`, `detected_format` |
| `EXPLICIT_FORMAT_LISTED_EMPTY` | `UnconfirmedFormatContext`: `kind="unconfirmed_format"`, `archive_name`, `format`, `chosen_by="argument"`, `detected_format` |
| `EXTENSION_FORMAT_UNCONFIRMED` | `UnconfirmedFormatContext`: `kind="unconfirmed_format"`, `archive_name`, `format`, `chosen_by="extension"`, `detected_format=None` |
| `PROBE_FORMAT_UNCONFIRMED` | `UnconfirmedFormatContext`: `kind="unconfirmed_format"`, `archive_name`, `format`, `chosen_by="content_probe"`, `detected_format` |
| `EMPTY_ARCHIVE` | `EmptyArchiveContext`: `kind="empty_archive"`, `archive_name`, `format` |
| `ENCODING_ARGUMENT_UNUSED` | `UnusedArgumentContext`: `kind="unused_argument"`, `archive_name`, `argument="encoding"`, `format`, `reason` |
| `PASSWORD_ARGUMENT_UNUSED` | `UnusedArgumentContext`: `kind="unused_argument"`, `archive_name`, `argument="password"`, `format`, `reason` |
| `SCAN_DIRECTORY_VANISHED` | `ScanRaceContext`: `kind="scan_race"`, `archive_name`, `relative_path`, `entry_kind="directory"` |
| `SCAN_ENTRY_VANISHED` | `ScanRaceContext`: `kind="scan_race"`, `archive_name`, `relative_path`, `entry_kind="entry"` |
| `ARCHIVE_EOF_MARKER_MISSING` | `ArchiveEofContext`: `kind="archive_eof"`, `archive_name`, `format`, `expected_marker` ∈ `{"two_zero_blocks","second_zero_block","end_of_archive_block","end_of_central_directory","zip64_end_of_central_directory"}`, `expected_bytes`, `observed_bytes`, `observed_kind` |
| `ARCHIVE_TRAILING_DATA` | `ArchiveEofContext`: `kind="archive_eof"`, `archive_name`, `format`, `expected_marker` ∈ `{"zeros_to_eof","end_of_stream"}`, `expected_bytes=0`, `observed_bytes`, `observed_kind="nonzero"` |
| `ARCHIVE_UNLISTED_DATA` | `UnlistedDataContext`: `kind="unlisted_data"`, `archive_name`, `format`, `member_name`, `member_id` (the name and id the pass gave the entry before dropping it), `offset` (of its local header), `compressed_size` |
| `MEMBER_TIMESTAMP_INVALID` | `MemberTimestampContext`: `kind="member_timestamp"`, `archive_name`, `member_name`, `member_id`, `field` ∈ `{"modified","accessed","created","ctime"}` (the `ArchiveMember` attribute the value would have filled, in every format), `source`, `value_repr` |
| `MEMBER_HEADER_RECORD_SKIPPED` | `MemberHeaderRecordContext`: `kind="member_header_record"`, `archive_name`, `member_name`, `member_id`, `record`, `record_id`, `reason`, `list_truncated` |
| `SYMLINK_TARGET_UNAVAILABLE` | `SymlinkTargetContext`: `kind="symlink_target"`, `archive_name`, `member_name`, `member_id`, `reason` |
| `DIGEST_UNVERIFIABLE` | `DigestContext`: `kind="digest"`, `archive_name`, `member_name`, `member_id`, `algorithm`, `reason` |
| `MEMBER_DIRECTORY_DATA_IGNORED` | `DirectoryDataContext`: `kind="directory_data"`, `archive_name`, `member_name`, `member_id`, `size` (declared; 0 when none is declared and the body is larger than an empty one of its method), `compressed_size` |
| `MEMBER_LINK_DATA_IGNORED` | `LinkDataContext`: `kind="link_data"`, `archive_name`, `member_name`, `member_id`, `size` (declared) |
| `MEMBER_SPECIAL_FILE_HAS_DATA` | `SpecialFileDataContext`: `kind="special_file_data"`, `archive_name`, `member_name`, `member_id`, `special_file_type` ∈ `{"fifo","char_device","block_device","socket","unknown"}`, `size` |
| `MEMBER_LOCAL_NAME_DIFFERS`, `MEMBER_LOCAL_METHOD_DIFFERS`, `MEMBER_LOCAL_CRC_USED` | `LocalHeaderContext`: `kind="local_header"`, `archive_name`, `member_name`, `member_id`, `field` (`"name"`, `"method"` and `"crc32"` in that order), `local_raw_name_base64` (the local header's name bytes, `field="name"` only), `local_method` and `central_method` (`field="method"` only), `local_crc32` (`field="crc32"` only) |
| `ARCHIVE_OFFSET_WRAPPED` | `OffsetWrapContext`: `kind="offset_wrap"`, `archive_name`, `format`, `member_name`, `member_id` (empty and `None` for the directory), `record` ∈ `{"local_header","central_directory"}`, `stored_offset`, `corrected_offset` |
| `MEMBER_SIZE_WRAPPED` | `SizeWrapContext`: `kind="size_wrap"`, `archive_name`, `format`, `member_name`, `member_id`, `stored_compressed_size`, `compressed_size`, `stored_size`, `size` (`None` when only a read can tell) |
| `MEMBER_TYPE_UNKNOWN` | `UnknownMemberTypeContext`: `kind="unknown_member_type"`, `archive_name`, `member_name`, `member_id`, `stored_type` (the TAR typeflag byte as a one-character string, the byte read as Latin-1), `size` (the member's `size`; `None` for an `OTHER` member) |
| `ENCRYPTED_MEMBER_UNVERIFIED` | `EncryptedVerificationContext`: `kind="encrypted_verification"`, `archive_name`, `member_name`, `member_id`, `check`, `reason` |
| `SEEK_INDEX_DEGRADED` | `SeekIndexContext`: `kind="seek_index"`, `archive_name`, `member_name`, `member_id`, `codec`, `scan`, `error_type` |
| `STREAM_REWIND_REDECOMPRESSES` | `StreamRewindContext`: `kind="stream_rewind"`, `archive_name`, `member_name`, `member_id`, `codec`, `from_offset`, `to_offset`, `accelerator` |

(`str | None` / `int | None` as in the typed variants.) `DiagnosticContext` is
exactly this union — no backend-defined variants. `observed_kind` ∈
`{"absent","short","nonzero"}`. `expected_marker` is symbolic (`"two_zero_blocks"`
for the trailer check; `"second_zero_block"` for a TAR trailer whose first block is
zero and ends the members and whose second block is full and non-null, with
`observed_kind="nonzero"` and both byte counts 512, where every member is listed;
`"end_of_archive_block"` for a RAR5 archive or volume that ends without its end-of-archive
block, with `format="rar"`, `observed_kind="absent"` and both byte counts 0, or whose
end-of-archive block fails its header CRC, with `observed_kind="nonzero"` (a block is
there, but it is not a valid end block), `observed_bytes` the offset where that block
starts in its volume (counted from that volume's first byte, unlike member offsets,
which count across the whole set; the message names the volume), and `expected_bytes` 0;
`"end_of_central_directory"` for a ZIP end record that does not match the archive, with
`format="zip"`: `observed_kind="nonzero"` when its entry count differs from the central
directory's (`observed_bytes` the record's offset, `expected_bytes` 0), or
`observed_kind="short"` when its comment length runs past the end of the file
(`expected_bytes` 22 plus the declared comment length, `observed_bytes` the bytes from
the record to the end of the file); `"zip64_end_of_central_directory"` for a ZIP64 end
record a locator announces that is missing or does not match it, the classic record
used instead (`observed_kind="absent"`, `observed_bytes` the locator's offset,
`expected_bytes` 0);
`"zeros_to_eof"` for the trailing-bytes check after an archive's end (a TAR
trailer, a 7z next header or last packed stream, whichever is later, a RAR
end-of-archive block, an ISO image's volume space and partitions, or a ZIP end record
and its declared comment), whose `format`
names the archive format and whose `observed_bytes` is the offset of the first non-zero
byte past that end;
`"end_of_stream"` for bytes after a compressed stream's end, whose `format` is the
codec name, such as `"gzip"`, and whose `observed_bytes` is the offset of the first
non-zero byte after that end).
`member_id` MAY be `None` only before registration.
`controls` SHALL be the comma-joined `U+XXXX` spellings of the bidi codepoints
found, in the order they occur, so a caller can tell an override from a mark
without re-scanning the name. `chosen_by` ∈ `{"argument","extension","content_probe"}`;
`detected_format` is `None` when detection refuses the bytes outright.

`PROBE_FORMAT_UNCONFIRMED` is a **separate code**, not a widening of
`EXTENSION_FORMAT_UNCONFIRMED`. The two describe different provenance and fire on
different events: the extension code keys on `detected_by="extension"` **and an empty
listing or a decode failure** (see `error-handling`, *A decode failure on an
extension-only format names its provenance*); the probe code keys on **probe-only
provenance** — `detected_by="content_probe"` with nothing corroborating the claim (no
matching extension, no inner-TAR upgrade) — **and a decode failure**. A probe-only read
failure MUST NOT double-report under the extension code.

**Confidence is not part of that trigger.** The probe code fires on a probe-only failure at
*any* `DetectionConfidence`, so an LZMA Alone hit (always `PROBABLE`) and a compressed-first
Brotli hit (`PROBABLE`) are stamped exactly as an uncorroborated `GUESS` hit is. Confidence
grades how strong the evidence looked; this code answers whether anything independent
corroborated it. Keying the diagnostic on confidence left 53% of measured fabrications
unsignalled, and made a probe's confidence value double as a switch for error behaviour.
This matches `error-handling`'s `format_unconfirmed`, and the two SHALL agree by
construction: the diagnostic is emitted while stamping that attribute, never on a separate
test.

`ExtractionOutcomeContext`, `NameCollisionContext` and `NameSanitizedContext` SHALL
NOT exist: per-member extraction outcomes are carried by `ExtractionResult` (see
`safe-extraction`), not by this channel.

No diagnostic surface SHALL contain passwords, candidates, provider returns, keys,
KDF material, or decrypted secrets. `PASSWORD_ARGUMENT_UNUSED` therefore records
that a password argument was supplied and unused — never how many candidates, and
never any candidate value.

Copies on multiple surfaces MAY share `occurrence_id` by value; object identity
and cross-run id stability are not promised.

`ENCRYPTED_MEMBER_UNVERIFIED` SHALL be emitted when a member of an encrypted unit is
closed before its declared digest was reached **and** the password behind those bytes was
accepted on a check weaker than that digest. `check` names what accepted the password
(`"weak_open_check"`, `"confirm_budget_exhausted"`); `reason` names why the digest was
not reached (`"partial_read"`, or `"seek"` when a seek left it unreached: a read skipped
bytes past the hashing frontier and no read from it reached the end, or the stream was
closed while parked past it; a WinZip AES
HMAC survives seeks, so there `"seek"` means only that a failed seek left the position
unknown). It SHALL NOT be emitted for a partial read whose password was confirmed
against an integrity anchor — that restates what the caller already knows, which the
admission clause refuses. Nor SHALL it be emitted for a stream closed before any read
returned bytes, since nothing unchecked was delivered.

#### Scenario: value-model matrix

| Case | Expected |
| --- | --- |
| Name normalization | `MEMBER_NAME_NORMALIZED` + typed JSON-safe context; no backend/mutable mapping |
| Same occurrence on aggregate + member | Same `occurrence_id`; value equality; no object-identity promise |
| Encrypted symlink unavailable | May use reason `"password_required"` (or `"password_or_damage"` when a ZIP or RAR 2.9-4 target's data failed its check under an unconfirmed password) + member name; no secret material |
| Member blocked by a universal/policy check | No diagnostic; a `BLOCKED` `ExtractionResult` is the whole record |
| `password=["a","b"]` on a format with no encryption | `PASSWORD_ARGUMENT_UNUSED`; context carries no candidate value and no count |
| Non-zero byte within 1 MiB past a complete TAR trailer | `ARCHIVE_TRAILING_DATA` sharing `ArchiveEofContext`; distinguished by `expected_marker` |
| Non-zero byte within 1 MiB past a 7z archive's end (next header or last packed stream) | `ARCHIVE_TRAILING_DATA` with `expected_marker="zeros_to_eof"` and `format="7z"` |
| Non-zero byte within 1 MiB past a RAR volume's end-of-archive block | `ARCHIVE_TRAILING_DATA` with `expected_marker="zeros_to_eof"` and `format="rar"`, once per volume |
| Non-zero byte within 1 MiB past an ISO image's volume space and listed partitions | `ARCHIVE_TRAILING_DATA` with `expected_marker="zeros_to_eof"` and `format="iso"` |
| Non-zero byte past a ZIP end record and its declared comment | `ARCHIVE_TRAILING_DATA` with `expected_marker="zeros_to_eof"` and `format="zip"` |
| A ZIP read from a pipe holds a local entry its central directory does not list | `ARCHIVE_UNLISTED_DATA` naming the entry; the entry is dropped from the listing, as the seekable read never sees it |
| Non-zero bytes after a single-file codec's stream | `ARCHIVE_TRAILING_DATA` with `expected_marker="end_of_stream"` and the codec name as `format` |
| Probe-only single-file read raises, uncorroborated `GUESS` | `PROBE_FORMAT_UNCONFIRMED` with `chosen_by="content_probe"` |
| Probe-only single-file read raises, uncorroborated **`PROBABLE`** (compressed-first Brotli) | `PROBE_FORMAT_UNCONFIRMED` too — **changed**; confidence is not the trigger |
| Probe-only **LZMA Alone** read raises (always `PROBABLE`) | `PROBE_FORMAT_UNCONFIRMED` — **changed**; previously unsignalled |
| Extension-only empty listing | Still `EXTENSION_FORMAT_UNCONFIRMED` only — unchanged |
| Extension-only read raises (zeros named `backup.gz`) | `EXTENSION_FORMAT_UNCONFIRMED` with `chosen_by="extension"`, `detected_format=None`; no `PROBE_FORMAT_UNCONFIRMED` |
| Probe + `.br` (`PROBABLE`) read raises | No `PROBE_FORMAT_UNCONFIRMED` — the format was corroborated, and corroboration is still what matters |
| Probe hit upgraded to `TAR_*` by the inner-TAR probe, read raises | No `PROBE_FORMAT_UNCONFIRMED` — the upgrade is independent corroboration |
| Probe-only read succeeds | No diagnostic |

#### Scenario: encrypted-member verification matrix

| Case | Expected |
| --- | --- |
| ZipCrypto member, candidate accepted on the header check byte, stream closed before EOF | `ENCRYPTED_MEMBER_UNVERIFIED` (`check="weak_open_check"`, `reason="partial_read"`) |
| 7z LZMA2, CRC at 200 MiB, correct password, stream closed before EOF | `ENCRYPTED_MEMBER_UNVERIFIED` (`check="confirm_budget_exhausted"`) |
| 7z store+AES, CRC at 200 MiB, correct password, stream closed before EOF | No diagnostic (walked to the CRC) |
| 7z store+AES, no CRC, single candidate, stream closed before EOF | `ENCRYPTED_MEMBER_UNVERIFIED` (`check="confirm_budget_exhausted"`) |
| Encrypted member whose password was confirmed against an integrity anchor, stream closed before EOF | No diagnostic |
| Encrypted member read to EOF | No diagnostic; the digest decides |
| Unencrypted member, stream closed before EOF | No diagnostic |

#### Scenario: A malformed optional member-header record is reported, not raised

- **WHEN** a backend drops an optional metadata record inside a member header, or in a
  header that belongs to one member (a RAR 1.5-4 `UOW` owner header), because it could
  not be parsed, and lists the member without it
- **THEN** it SHALL emit `MEMBER_HEADER_RECORD_SKIPPED` with `MemberHeaderRecordContext`,
  attached to that member
- **AND** `record` SHALL name the record as the format names it, and `record_id` SHALL
  carry the format's numeric type where it has one, so a record the backend cannot name is
  still identifiable
- **AND** the field the record would have populated SHALL be absent rather than partially
  written: a dropped record never changes a value, it only fails to set one

### Requirement: Exact bounded diagnostic summaries

`DiagnosticSummary` snapshots SHALL expose `total_count`, exact per-code `counts`,
retained occurrences in emission order, and `dropped_count`. Counts include every
emitted event regardless of disposition/retention. `dropped_count` = aggregate
occurrences not retained.

Each standalone detection, reader lifetime, top-level extraction, or standalone
stream SHALL enforce one `ArchiveyConfig.max_retained_diagnostic_references`
budget (default 256) across every library-retained reference for that collector.
Aggregate retention = one slot; one eligible object attachment = another.
Order: aggregate first, then most-specific attachment. No attachment without a
retained aggregate. Exact counters do not consume slots.

Snapshots are freshly created, bounded, never mutated. Caller-retained snapshots
and caller-created member copies are outside the library budget, and so is the record
a random-access member walk keeps until it ends so that a walk started over can
replay its diagnostics (`archive-reading` §Each member is listed once per reader).

**Watermark and scope (implementer):** an internal operation watermark consumes no
slot and copies no occurrence; a ranged summary computes counter deltas and selects
from already-retained aggregate entries. A scope does the same for the emits made on
one thread while it is entered: it keeps its own exact counters, and its summary
selects the retained aggregate entries tagged with it. A call whose result reports
its own diagnostics on a reader that other threads use at the same time uses a
scope, so their emits stay out of its report: `extract_all()` enters one for the
whole call, and a reader-owned member stream enters its own on every `read`, `seek`
and `close`, on whichever thread makes the call. `stream.diagnostics` is therefore
that stream's own reads, not everything the reader emitted after it opened.

#### Scenario: retention matrix

| Case | Expected |
| --- | --- |
| Member diagnostic, ≥2 slots left | Aggregate + member attachment; 1 slot → aggregate only |
| Budget exhausted, more events | No further detail/attachment; counts stay exact |
| `before = reader.diagnostics`, more events, `after = …` | `before` unchanged; `after` includes later counts in order |

### Requirement: Lifecycle-aware aggregation and attachment

The system SHALL own diagnostic aggregation per lifetime as follows:

| Lifetime | Collector ownership |
| --- | --- |
| Standalone `detect_format` | One collector; final summary on `FormatInfo` |
| `open_archive` + auto-detect | Prospective-reader collector created before detection, passed in, owned by successful reader — no seed/merge/replay/copy. Same counters, retained tuple, ids, order, one-time budget charges |
| Reader-owned stream | Operation-filtered view over the reader collector (no second aggregate retain) |
| Standalone stream | Own stream-lifetime collector |

Attachment rules:

- Natural member-metadata diagnostics MAY attach to `ArchiveMember.diagnostics`
  under the shared budget.
- `ExtractionResult` has **no** diagnostics field, and no per-member extraction
  outcome is emitted as a diagnostic at all: `status`, `error`, `requested_path`,
  `presented_name` and the failure-group fields are the whole record.
- Detection conflict attaches to `FormatInfo`.
- Runtime rewind, seek-index degradation, scan race, archive EOF: aggregate-only —
  never attached to frozen `CostReceipt` or `ArchiveInfo`.

`ExtractionReport.diagnostics` SHALL remain a real summary: reading an archive during
extraction still emits reading diagnostics (invalid timestamps, unresolvable symlinks,
unverifiable digests, rewinds), and those stay in the aggregate. What leaves the
channel is the per-member *extraction outcome*, not everything observed while
extracting.

#### Scenario: lifetime matrix

| Case | Expected |
| --- | --- |
| `open_archive` detects conflict, opens reader | One collector/budget; conflict one aggregate slot; visible on reader summary; no copy |
| `open_archive` then `extract_all()` | Report is that call's own emits (its scope); detection and open diagnostics, and other threads' emits meanwhile, stay on `reader.diagnostics` |
| Reader-owned stream rewinds | On stream op snapshot + cumulative reader; `CostReceipt`/`ArchiveInfo` unchanged |
| Extraction hits a member with an invalid timestamp and a blocked member | Timestamp diagnostic in the report summary; the block appears only as a `BLOCKED` result |

### Requirement: Complete per-code policy and delivery contract

The system SHALL provide a frozen `DiagnosticPolicy` with two keyword-only code sets,
`ignore` and `raise_on`. A code in `raise_on` resolves to `RAISE`, a code in `ignore` to
`IGNORE`, and every other code to `COLLECT`. The only dispositions SHALL be `IGNORE`,
`COLLECT`, and `RAISE` (no logger matching). The dispositions are the contract's
vocabulary, not a public type: a caller reads a policy through its two sets, and the
policy SHALL NOT expose a resolve method or a disposition enum.

```python
DiagnosticPolicy(*, ignore: Iterable[DiagnosticCode | DiagnosticCodeStr] | None = None,
                 raise_on: Iterable[DiagnosticCode | DiagnosticCodeStr] | None = None)
policy.ignore: frozenset[DiagnosticCode]
policy.raise_on: frozenset[DiagnosticCode]
```

`DiagnosticCodeStr` SHALL be a `Literal` of every code's value and its dash form, as the
other enum arguments' aliases are, so a type checker rejects a misspelled code. The test
suite SHALL fail when a code is added without its spellings.

Each argument SHALL accept any iterable of codes, a code's name or value as a string
included, and the field SHALL hold a `frozenset` of members, so a caller builds a policy
with set operations on the public code sets. A code in both sets SHALL raise
`ArchiveyUsageError`: keyword arguments have no order, so neither can win, and keeping
either silently drops what the other asked for. A bare string SHALL raise
`ArchiveyUsageError` rather than be read as a set of characters, and so SHALL a mapping
(it iterates as its keys, so the removed `{code: disposition}` shape would drop every
disposition) and a single code where a set was meant. There SHALL be no
default disposition other than `COLLECT`: "raise on everything but X" is
`raise_on=frozenset(DiagnosticCode) - {X}`.

| Disposition | Counts | Retain/attach | Log record | Callback | Raise |
| --- | --- | --- | --- | --- | --- |
| `IGNORE` | yes | no | no | no | no |
| `COLLECT` | yes | budget permitting | yes | if configured | no |
| `RAISE` | yes | budget permitting | yes | if configured | `DiagnosticRaisedError` |

Per event: validate typed payload → resolve policy → under collector lock allocate
id, build immutable value, update counts/retention → **release all locks** → log →
synchronous callback on calling thread → escalate. Logs/callbacks see
already-updated state, in emission order. The log record is WARNING, except for the codes
in `archivey.diagnostics._INFO_LOG_CODES`, which log at INFO: they report the caller's
access pattern rather than the archive (`logging` spec).

| Failure | Behavior |
| --- | --- |
| Logging-handler exception | Propagates; blocks later callback/escalation |
| Callback exception | Propagates unchanged; not under `OnError.CONTINUE`; blocks later `DiagnosticRaisedError`; operation still halted |

No collector/reader/stream/backend/registry lock while calling handlers/callbacks.
Callbacks MAY read snapshots; same-emitting-reader/stream operational reentry is
rejected: the reader's operation gate raises `ArchiveyUsageError` (reader-concurrency),
and a re-entrant call that gets as far as emitting a diagnostic of its own raises
`ArchiveyUsageError` from the collector; other readers OK.

**Deduplication is a presentation concern; escalation is not.** Where a code is
documented as recorded *at most once* per stream or per reader, that bound SHALL apply to
counting, retention, logging and callbacks only. The configured policy SHALL be evaluated
on **every** occurrence, so a `RAISE` disposition raises on the second and later
occurrences as well as the first: a report reader wants bounded, readable output, while a
caller who asked to be stopped wants to be stopped, and a guard that disarms after firing
once is not a guard.

This SHALL be the rule for **every** once-per-stream code, not a per-code exception, so
that a future deduplicated code inherits an answer rather than the question. The
collector SHALL expose a way to evaluate a code's policy without recording an occurrence;
the deduplication bookkeeping itself lives with the emitter, which is what knows the scope
("this stream").

**An operation that cannot unwind raises once, when it can.** A stream operation that
emits from inside a decode or an index scan (a read, seek or size query on a
decompressing stream) SHALL hold what an emit or an escalation-only evaluation would
raise, a callback's exception included, and raise the first error it held once its own
state is consistent. Each occurrence is still evaluated and delivered as above. The
operation raises at most once: a later occurrence in the same operation that would also
raise is evaluated, and delivered if it is recorded, but not raised. The next operation
evaluates afresh.

#### Scenario: policy / delivery matrix

| Case | Expected |
| --- | --- |
| Code → `IGNORE` | Count++; no retain/attach/log/callback/raise |
| Same code in `ignore` and `raise_on` | `ArchiveyUsageError` at construction |
| `ignore="archive_trailing_data"` (bare string) | `ArchiveyUsageError` at construction |
| `ignore={ARCHIVE_TRAILING_DATA: RAISE}` (a mapping) | `ArchiveyUsageError` at construction, naming both sets |
| `raise_on=STRICT.raise_on - {ARCHIVE_TRAILING_DATA}` | Same as built from `ARCHIVE_INTEGRITY_CODES`; the field is a `frozenset` |
| `raise_on=ARCHIVE_INTEGRITY_CODES - {ARCHIVE_TRAILING_DATA}` | `STRICT` except that code, which is collected |
| Callback reads `reader.diagnostics` | Sees current event counted/retained; no lock held |
| Callback raises during `RAISE` | Callback error propagates; no replacement `DiagnosticRaisedError`; no `OnError.CONTINUE` |
| Callback starts op on same emitting reader | `ArchiveyUsageError` from the reader's operation gate |

#### Scenario: deduplicated code policy matrix

| Case | Expected |
| --- | --- |
| Once-per-stream code, second qualifying occurrence, policy `COLLECT` | No second count, retention, log or callback |
| Once-per-stream code, second qualifying occurrence, policy `RAISE` | `DiagnosticRaisedError` raised again; still no second record |
| Once-per-stream code, second qualifying occurrence, policy `IGNORE` | Nothing happens |
| Two occurrences inside one deferring stream operation, policy `RAISE` | The operation raises once, with the first error held; the second is delivered if recorded, not raised |
| Escalation-only evaluation | Never appears in `retained`, never changes `counts`, never logs or calls back. The raised `DiagnosticRaisedError` still carries a full `Diagnostic` describing *this* occurrence — the caller being stopped should see the event that stopped them, not the first one |

### Requirement: Complete initial warning taxonomy

The initial `DiagnosticCode` set SHALL cover the library's advisory emissions via
the codes in the closed table above. Multiple call sites share a code only with the
same machine meaning; typed context distinguishes variants.

**No advisory SHALL be log-only.** Every condition the library reports as advice to
the caller SHALL be emitted through the central diagnostic path with a code, so it is
queryable on `reader.diagnostics` and escalatable by `DiagnosticPolicy`; the log
record is the projection of that emission, never a substitute for it.

That rule is a floor. The following two clauses are its ceiling, and a proposed code
SHALL satisfy both.

**Admission.** A `DiagnosticCode` SHALL report something the caller could not have
determined from the declared contract of the call, and can act on. It MAY describe a
property of the archive, or an outcome of the caller's request meeting the archive —
the archive-versus-caller distinction is descriptive and SHALL NOT be used as an
admission test. It SHALL NOT restate advice the API surface already carries.

**Placement.** When an operation returns a structured per-item report, that report
SHALL be the authoritative and sole carrier of per-item outcomes; the diagnostics
channel carries only facts with no return-value home. A fact SHALL have exactly one
authoritative channel. Where a fact would otherwise be reported twice, the return
value wins and the code SHALL NOT exist.

Where relocating a fact out of this channel would remove a caller's ability to be
stopped by it, the owning capability SHALL provide a named opt-in rather than
retaining the code for its escalation alone (see `safe-extraction`'s `AbortOn`).

No unused future codes reserved.

#### Scenario: taxonomy coverage

| Case | Expected |
| --- | --- |
| Advisory path that formerly logged only | Emits one of the initial codes through the central path |
| Member name containing a bidi formatting control | `MEMBER_NAME_BIDI_CONTROL` on the aggregate, not only a `logger.warning` |
| Member name containing a zero-width space, so `invoice.pdf` and `invoice<U+200B>.pdf` extract side by side | `MEMBER_NAME_ZERO_WIDTH_CHARACTER` naming U+200B; `STRICT` raises it, the default policy extracts both |
| Member name containing a zero-width joiner, as in an emoji sequence | `MEMBER_NAME_INVISIBLE_CHARACTER` naming U+200D; `STRICT` does not raise it |
| Member name containing a bidi control, a zero-width space and a zero-width joiner | One diagnostic of each of the three codes, each naming only its own characters; no character is reported under two codes |
| Proposed code restating a `CostReceipt` fact already returned at open time | Refused by the admission clause |
| Proposed code for a per-member outcome of an operation that returns a per-item report | Refused by the placement clause; the fact belongs in the result |
| A caller wants to be stopped by a fact that placement moved into a return value | A named opt-in on the owning capability, not a retained code |

### Requirement: Report unused explicit arguments as diagnostics

When an explicit argument is a **resource offered for use if needed** rather than an
assertion about the archive (see `archive-reading`), `open_archive()` SHALL accept it
and, when the resolved backend cannot act on it, SHALL emit one diagnostic naming the
argument. It MUST NOT raise.

| Condition | Code | `reason` |
| --- | --- | --- |
| Caller passed `encoding=` and `ReadBackend.USES_ENCODING` is `False` | `ENCODING_ARGUMENT_UNUSED` | why the backend decodes names another way |
| Caller passed a concrete `password=` (a single value or a sequence) and `ReadBackend.SUPPORTS_PASSWORD` is `False` | `PASSWORD_ARGUMENT_UNUSED` | that the format carries no encryption |

Each SHALL be emitted **at most once per `open_archive()` call**, before the reader is
returned, so a caller can inspect `reader.diagnostics` without listing anything.

`password=` SHALL open identically in all three forms (a single value, a sequence of
candidates, a provider callable) on a format with no encryption: accepted, never
consulted. A single value or a sequence SHALL record one diagnostic. A provider callable
SHALL record none: it offers a password only if asked, and a format with no encryption
never asks, so no password was supplied. (The CLI passes a provider on every run.) A
wrong password on an *encrypted* archive is unaffected and still raises.

#### Scenario: unused argument matrix

| Case | Expected |
| --- | --- |
| `open_archive(sevenzip, encoding="cp500")` | Opens; one `ENCODING_ARGUMENT_UNUSED`; names unchanged |
| `open_archive(iso, encoding="cp500")` | No diagnostic; UTF-8 names unchanged, and the encoding applies to a Rock Ridge or plain name that is not valid UTF-8 |
| `open_archive(zip, encoding="cp500")` | No diagnostic; UTF-8 names unchanged, and the encoding applies to an unflagged name that is not valid UTF-8 |
| Auto-detected open with no `encoding=` on a backend that ignores encoding | No diagnostic |
| `open_archive(tar, password="p")` / `password=["a","b"]` | Both open; one `PASSWORD_ARGUMENT_UNUSED` each; no `ArchiveyUsageError` |
| `open_archive(tar \| gz \| directory, password=lambda r: "p")` | Opens; no `PASSWORD_ARGUMENT_UNUSED`; the provider is never called |
| Wrong password on an encrypted ZIP | Unchanged: `EncryptionError` |

### Requirement: Report an empty listing as a diagnostic

When a member listing completes **without error** and contains **zero members**, the
system SHALL emit `EMPTY_ARCHIVE` exactly once per reader, whatever the format. It MUST
NOT raise: an empty tar is *all zeros*, so no predicate over the bytes separates one from
a zero-filled junk file and any "zero members is an error" rule rejects a file `tar(1)`
itself produces.

The system SHALL NOT restrict the accepted lengths to the canonical ones either. GNU
tar's `-b` blocking factor makes **every** block-aligned zero length a legitimate empty
archive — `tar -b 64 -cf e.tar --files-from /dev/null` emits 32768 zero bytes,
byte-identical to a 32 KiB junk file and listed by `tar -tvf` without error. The two
sizes seen in practice are 1024 (Go `archive/tar`, hence the Docker/OCI empty layer) and
10240 (GNU tar default, Python `tarfile`); a rule admitting only those would emit a false
advisory against valid `-b` output while still being unable to refuse anything.
See `dev-docs/decisions/0015-zero-filled-files-are-valid-empty-tars.md`.

An incomplete listing (one published with an error) SHALL NOT emit it — the member count
is not the archive's.

On an empty listing the system SHALL additionally report **how the format was chosen**,
when that choice was not confirmed against the bytes:

| How the format was chosen | Additional code |
| --- | --- |
| Explicit `format=` argument, and detection now reports a different format or refuses the bytes | `EXPLICIT_FORMAT_LISTED_EMPTY` |
| Extension fallback (`FormatInfo.detected_by == "extension"`), i.e. no magic, probe or far-magic match | `EXTENSION_FORMAT_UNCONFIRMED` |
| Magic, content probe, far magic, or a directory path | none — the bytes confirmed the format |

`format=` SHALL remain an override: neither code refuses the open. The
`EXPLICIT_FORMAT_LISTED_EMPTY` re-detection SHALL run **only** on an empty listing, and
only when the source is a filesystem path, where reopening it cannot disturb the reader;
for a stream source the check is skipped rather than reaching into a live source's
position. The path re-detected is the source as resolution left it — the first volume
of a multi-volume set, the volume a self-extracting stub was followed to — not the name
the caller passed; a joined set has no single path and skips the check. A directory
path opened with `format=DIRECTORY` counts as chosen by the filesystem, not by argument.

#### Scenario: empty listing matrix

| Case | Expected |
| --- | --- |
| `tar cf empty.tar --files-from /dev/null` | Opens, 0 members, `EMPTY_ARCHIVE`, no error |
| 32 KiB of zeros named `z.tar` | Opens, 0 members, `EMPTY_ARCHIVE` **and** `EXTENSION_FORMAT_UNCONFIRMED` |
| `open_archive(iso_path, format=TAR)` | Opens, 0 members, `EMPTY_ARCHIVE` **and** `EXPLICIT_FORMAT_LISTED_EMPTY` with `detected_format="ISO"` |
| `open_archive(tar_path, format=TAR)` on a real one-member tar | No diagnostic |
| Empty directory opened with `format=DIRECTORY` | `EMPTY_ARCHIVE` only |
| Empty ZIP / empty 7z | `EMPTY_ARCHIVE`; no format code (magic confirmed the bytes) |
| A legitimately empty tar (all zeros, so no magic) | `EMPTY_ARCHIVE` **and** `EXTENSION_FORMAT_UNCONFIRMED` — truthful: the bytes really did not confirm it |
| Listing published with an error and zero members | No `EMPTY_ARCHIVE` |

### Requirement: Named diagnostic policy presets and taxonomy-growth contract

The system SHALL provide named `DiagnosticPolicy` instances, as class attributes, so a
caller can express a coarse strictness without enumerating the taxonomy:

```python
ARCHIVE_INTEGRITY_CODES: frozenset[DiagnosticCode]

DiagnosticPolicy.STRICT    # DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES)
DiagnosticPolicy.PEDANTIC  # DiagnosticPolicy(raise_on=frozenset(DiagnosticCode))
```

`ARCHIVE_INTEGRITY_CODES` SHALL be a public frozen set covering the codes that report
the archive's own bytes or metadata as anomalous:

| In `ARCHIVE_INTEGRITY_CODES` | Excluded |
| --- | --- |
| `MEMBER_NAME_NORMALIZED`, `MEMBER_NAME_ENCODING_INFERRED`, `MEMBER_NAME_BIDI_CONTROL`, `MEMBER_NAME_ZERO_WIDTH_CHARACTER`, `EXTENSION_FORMAT_UNCONFIRMED`, `SCAN_DIRECTORY_VANISHED`, `SCAN_ENTRY_VANISHED`, `ARCHIVE_EOF_MARKER_MISSING`, `ARCHIVE_TRAILING_DATA`, `ARCHIVE_UNLISTED_DATA`, `MEMBER_TIMESTAMP_INVALID`, `MEMBER_HEADER_RECORD_SKIPPED`, `SYMLINK_TARGET_UNAVAILABLE`, `DIGEST_UNVERIFIABLE`, `MEMBER_DIRECTORY_DATA_IGNORED`, `MEMBER_LINK_DATA_IGNORED`, `SEEK_INDEX_DEGRADED`, `MEMBER_LOCAL_NAME_DIFFERS`, `MEMBER_LOCAL_METHOD_DIFFERS` | `EMPTY_ARCHIVE` (an empty archive is legitimate), `EXPLICIT_FORMAT_LISTED_EMPTY`, `ENCODING_ARGUMENT_UNUSED`, `PASSWORD_ARGUMENT_UNUSED`, `STREAM_REWIND_REDECOMPRESSES`, `PROBE_FORMAT_UNCONFIRMED`, `ENCRYPTED_MEMBER_UNVERIFIED`, `MEMBER_SELECTOR_UNMATCHED`, `MEMBER_SPECIAL_FILE_HAS_DATA`, `MEMBER_NAME_INVISIBLE_CHARACTER`, `FORMAT_EXTENSION_CONFLICT` (the name is wrong, not the bytes), `MEMBER_LOCAL_CRC_USED` (Adobe AIR writes it; the data is checked against the local CRC-32), `ARCHIVE_OFFSET_WRAPPED` and `MEMBER_SIZE_WRAPPED` (macOS writes the shape by default), `MEMBER_TYPE_UNKNOWN` (GNU tar extracts the member as a file) |

Each exclusion is deliberate, and the reason SHALL be recorded so the boundary is not
rediscovered: `EMPTY_ARCHIVE` because an empty archive is legitimate and this spec
forbids treating zero members as an error; `ENCODING_ARGUMENT_UNUSED` and
`PASSWORD_ARGUMENT_UNUSED` because they report argument hygiene, and a pipeline that
speculatively passes a password to every call would otherwise raise on every
unencrypted archive; `EXPLICIT_FORMAT_LISTED_EMPTY` because `format=` is an override
and an override that halts the caller is not an override;
`STREAM_REWIND_REDECOMPRESSES` because it reports the caller's access pattern rather
than the archive, and is most useful as a deliberately targeted tripwire;
`ENCRYPTED_MEMBER_UNVERIFIED` because the trigger is the caller abandoning the stream
before EOF (extract never fires it), and putting it in `STRICT` would turn a ZipCrypto
peek into `DiagnosticRaisedError` (revisit when `stream.verified` lands and this code
is retired); and
`PROBE_FORMAT_UNCONFIRMED` because a probe-only identification is an advisory about
what the file *is* (its bytes did pass that format's content check), not a finding
about the archive's own bytes, and the code only ever accompanies a read that has
already failed with a typed error, so `STRICT` would have nothing further to stop
(the emit keeps that typed error through `escalate_as` when a policy does resolve the
code to RAISE, so the exclusion is not what protects it);
`MEMBER_SPECIAL_FILE_HAS_DATA` because a documented writer option produces the
shape it reports (Info-ZIP's `zip -FI` stores a named pipe's content under the FIFO
mode) and every official extractor writes the bytes out, so the member is well-formed
and `STRICT` refusing it would hide data rather than damage;
`MEMBER_NAME_INVISIBLE_CHARACTER` because a zero-width joiner is part of ordinary emoji
sequences and a non-joiner of Persian and Indic spelling, so `STRICT` would refuse
archives of legitimately named files; `ARCHIVE_OFFSET_WRAPPED` because macOS Archive
Utility writes a ZIP past 4 GiB with its offsets cut to 32 bits by default and reads
it back, and each correction is kept only when a local header with the member's name
is there, with the CRC-32 still checked, so `STRICT` would refuse an ordinary Mac
archive; `MEMBER_SIZE_WRAPPED` for the same archives with a member past 4 GiB or a
deflated member over about 4 MB compressed in an archive of any length, whose sizes
are corrected only where the layout or deflate's ratio forces a value, with the length
and CRC-32 checked on a read; `MEMBER_TYPE_UNKNOWN` because GNU tar extracts a TAR
member of a typeflag it does not know as a regular file, with a warning, and archivey
lists its data as a `FILE`, so nothing is hidden and `STRICT` would refuse an archive
the reference tool extracts; and `FORMAT_EXTENSION_CONFLICT` because it
reports the file's name, which lies outside the archive, not the archive's bytes: the
bytes win and the archive reads in full, so `STRICT` would refuse a well-formed tarball
saved as `b.gz`. The code is still recorded, and a caller who wants the refusal adds it
to `raise_on`. Its sibling `MEMBER_NAME_ZERO_WIDTH_CHARACTER` is **in** the set: U+200B,
U+2060 and U+FEFF have no use inside a filename.
`EXTENSION_FORMAT_UNCONFIRMED`, its sibling, is **in** the set because it also fires
on a successful open: an extension-only empty listing, where no byte confirmed the
format at all, is exactly the case a `STRICT` caller wants stopped.

Presets SHALL be ordinary frozen `DiagnosticPolicy` values — no new resolution axis,
and no field on `Diagnostic`. A caller adjusts a preset by building another policy from
the same sets, for example
`DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES, ignore={PASSWORD_ARGUMENT_UNUSED})`.

**Taxonomy growth.** New `DiagnosticCode` members MAY be added in minor releases.
`PEDANTIC`, and any policy built from `frozenset(DiagnosticCode)`, takes every code of
the installed version, and therefore SHALL NOT be described as version-stable: a
caller running it starts raising on events their working program never produced. The
documentation SHALL state this, and SHALL present `STRICT` — whose membership is
versioned alongside the taxonomy — as the recommended strict mode. Removing a code
remains a breaking change.

#### Scenario: preset matrix

| Case | Expected |
| --- | --- |
| `STRICT`, archive with a truncated TAR trailer | `DiagnosticRaisedError` on `ARCHIVE_EOF_MARKER_MISSING` |
| `STRICT`, unencrypted archive opened with `password=` | No raise; `PASSWORD_ARGUMENT_UNUSED` is collected |
| `PEDANTIC`, same call | `DiagnosticRaisedError` on `PASSWORD_ARGUMENT_UNUSED` |
| `STRICT`, legitimately empty tar | No raise; `EMPTY_ARCHIVE` collected |
| Preset value compared to an equivalent hand-built policy | Equal; presets add no resolution axis |
| A new code added in a later minor release | `STRICT` membership is explicit; `PEDANTIC` silently gains it |
| `ENCRYPTED_MEMBER_UNVERIFIED in ARCHIVE_INTEGRITY_CODES` | False |
| `STRICT`, ZipCrypto member, `read(1)`, close | No raise; `ENCRYPTED_MEMBER_UNVERIFIED` collected |
| `PEDANTIC`, same call | `DiagnosticRaisedError` |

#### Scenario: probe code stays out of strict

| Case | Expected |
| --- | --- |
| `PROBE_FORMAT_UNCONFIRMED in ARCHIVE_INTEGRITY_CODES` | False |
| `DiagnosticPolicy.STRICT` disposition for that code | COLLECT (in neither set) |

#### Scenario: Strictness keeps the refuse-the-archive behaviour a lenient parse gives up

- **GIVEN** a backend that drops a malformed optional member-header record and lists the
  member, emitting `MEMBER_HEADER_RECORD_SKIPPED`
- **WHEN** the caller passes `DiagnosticPolicy.STRICT`
- **THEN** the listing SHALL raise, because the code is in `ARCHIVE_INTEGRITY_CODES`
- **AND** this is why a backend MAY become lenient about such a record without removing
  the strict outcome: leniency moves the default, the policy keeps the choice

### Requirement: Diagnostic messages are inert for terminal display

`Diagnostic.message` interpolates archive-derived values and is logged verbatim to the
CLI's stderr (`log.warning("%s", message)`), which makes it a terminal-display channel as
much as an exception message is. The system SHALL escape `Diagnostic.message` at
construction, losslessly, on the same terms as an exception message.

`Diagnostic.context` SHALL remain **raw**. It is the structured channel — `member_name`
and its siblings, surfaced through `to_dict()` — and a caller routing diagnostics to a
JSON sink needs the real values, not a display rendering.

Escaping SHALL NOT be left to the sites that build diagnostic messages. Every one of
them interpolates through `quoted()` today, so the text would be inert either way — but
that is a property of the current call sites, not of the type: a future message written
as `f"...{name}"` would look exactly like its neighbours and emit raw control bytes, and
only for a hostile archive.

`Diagnostic.message` is subject to the escape-exactly-once rule in `error-handling`:
values interpolated into it SHALL be raw, via `quoted()` rather than `!r`.

#### Scenario: a diagnostic message cannot spoof a terminal line

| Case | Expected |
| --- | --- |
| A diagnostic whose message embeds `ev\x1b[2Kil\rSPOOF.txt` | `message` carries `\x1b` as four literal characters; the logged line cannot be erased and rewritten |
| `context.member_name` for the same diagnostic | The raw name, unescaped |
| `to_dict()["context"]` | Raw values, suitable for a structured sink |
| A message with no control bytes | Unchanged |

### Requirement: A probe-only decode failure is filterable as unconfirmed

When a single-file decode fails and `ArchiveyError.format_unconfirmed` is true (see
`error-handling`), the system SHALL also emit `PROBE_FORMAT_UNCONFIRMED` so callers
that filter diagnostics — without inspecting exception attributes — see the same
fact. The exception attribute and the diagnostic are two views of one provenance;
neither replaces the other.

`PROBE_FORMAT_UNCONFIRMED` SHALL NOT be a member of the `ARCHIVE_INTEGRITY_CODES`
strict set: a probe-only identification is an advisory about what the file is, not a
finding about the archive's own bytes, and the code only accompanies a read that has
already failed with a typed `TruncatedError` / `CorruptionError`.
Default disposition is COLLECT. When a caller's policy resolves this code to RAISE
(notably `DiagnosticPolicy.PEDANTIC`), the emit SHALL surface the same typed error
via `escalate_as` (carrying `format_unconfirmed=True`) rather than
`DiagnosticRaisedError`. The diagnostic is emitted at most once per reader.

That once-per-reader bound SHALL hold under **every** policy, RAISE included: an
escalating emit MUST NOT leave a second count, retention, log line or callback behind on
a later occurrence.

The per-code policy contract's deduplication rule (*"deduplication is a presentation
concern; escalation is not"*) is what makes that safe to state. Its guarantee is that no
qualifying occurrence passes **silently** under RAISE — a guard that disarms after firing
once is not a guard. For this code the raise does not come from the diagnostic: every
qualifying occurrence re-raises the stamped typed error with `format_unconfirmed=True`
whether or not the diagnostic fires again, so the second and later reads stop the caller
exactly as the first did. The escalation obligation is therefore met by the read path
itself, and re-emitting would buy a duplicate record rather than a stop.

#### Scenario: dual channel

| Case | Expected |
| --- | --- |
| Probe-only decode failure | `exc.format_unconfirmed is True` **and** a `PROBE_FORMAT_UNCONFIRMED` diagnostic |
| Corroborated decode failure | `exc.format_unconfirmed is False`; no probe-unconfirmed diagnostic |
| `PEDANTIC`, probe-only decode failure | Same typed `TruncatedError`/`CorruptionError` with `format_unconfirmed=True` — not `DiagnosticRaisedError` |
| Three retried reads on one probe-only member | Diagnostic count stays 1; each exception still has `format_unconfirmed=True` |
| `PEDANTIC`, three retried reads on one probe-only member | Count and retention stay 1; every read still raises the typed error with `format_unconfirmed=True` |

### Requirement: Report a selector entry that matched no member

The system SHALL emit `MEMBER_SELECTOR_UNMATCHED` once for each entry of a `members=`
collection that matched no member, at the points that `archive-reading` "Collection
form of MemberSelector" names. `SelectorUnmatchedContext` is part of the
`DiagnosticContext` union:

| Code | Variant and required fields |
| --- | --- |
| `MEMBER_SELECTOR_UNMATCHED` | `SelectorUnmatchedContext`: `kind="selector_unmatched"`, `archive_name`, `entry`, `entry_kind` |

`entry_kind` ∈ `{"name","member"}`. For a `str` entry, `entry` is the entry as the
caller wrote it. For an `ArchiveMember` entry, `entry` is that member's name; a member
entry is unmatched when it belongs to another reader or carries no identity. An entry
that the caller repeated is reported once: a name by its text, a member by its identity.

`MEMBER_SELECTOR_UNMATCHED` SHALL NOT be in `ARCHIVE_INTEGRITY_CODES`: it reports the
caller's argument, not the archive, and a job that passes one list of names to many
archives would otherwise raise on each archive that lacks one of them. Its default
disposition is `COLLECT`.

#### Scenario: unmatched selector entries

| Case | Expected |
| --- | --- |
| `extract_all(members=["a.txt", "typo.txt"])` on an archive holding `a.txt` | `a.txt` extracted; the report carries one `MEMBER_SELECTOR_UNMATCHED` with `entry="typo.txt"`, `entry_kind="name"` |
| Same call under `DiagnosticPolicy.STRICT` | No raise; the diagnostic is collected |
| `stream_members(members=lambda m: False)` | No `MEMBER_SELECTOR_UNMATCHED` |
