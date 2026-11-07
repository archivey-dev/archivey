# diagnostics — salvage step 1 delta

## ADDED Requirements

### Requirement: Report every read of a member listed from a damaged header

When a member walk lists a member from a header that failed its own check and resumes
past it on a position the format's checks confirm (`format-rar`), every read, open,
stream or extraction of that member SHALL emit `MEMBER_HEADER_DAMAGED` before any of its
bytes are returned. Listing the member SHALL NOT emit it, so that a policy that raises on
the code refuses that member's read and no other: the listing, the other members and the
`CorruptionError` that ends the pass are unchanged. Its default delivery SHALL be a
warning. The message SHALL say which fields nothing checked (the name, type, mode, times
and flags) and that the member's data is still checked by its own digest. The code is
format-neutral, for every walk that lists a member from a damaged header the same way.

#### Scenario: member header damaged

| Case | Expected |
| --- | --- |
| RAR with one damaged, confirmed FILE header, default policy, `members()` | Every member listed, the damaged one included; no `MEMBER_HEADER_DAMAGED` yet; `CorruptionError` at the end |
| The same, read the damaged member | One `MEMBER_HEADER_DAMAGED`; its bytes, checked by its digest |
| The same under `DiagnosticPolicy.STRICT`, `stream_members()` | The damaged member's read raises `DiagnosticRaisedError`; every other member reads; `CorruptionError` at the end |
| `extract_all()` under the default policy | Every member written, the damaged one under its stored name; one `MEMBER_HEADER_DAMAGED`; then `CorruptionError` |
| A damaged header the walk cannot resume past | No `MEMBER_HEADER_DAMAGED`; `CorruptionError` after the members before it |

## MODIFIED Requirements

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
| `MEMBER_HEADER_DAMAGED` | `MemberHeaderDamageContext`: `kind="member_header_damage"`, `archive_name`, `member_name`, `member_id`, `format`, `volume_index` (0-based position in a multi-volume set, not the format's volume number; `None` for a single file), `header_offset` (offset of the damaged header in its volume) |
| `SYMLINK_TARGET_UNAVAILABLE` | `SymlinkTargetContext`: `kind="symlink_target"`, `archive_name`, `member_name`, `member_id`, `reason` |
| `DIGEST_UNVERIFIABLE` | `DigestContext`: `kind="digest"`, `archive_name`, `member_name`, `member_id`, `algorithm`, `reason` |
| `MEMBER_DIRECTORY_DATA_IGNORED` | `DirectoryDataContext`: `kind="directory_data"`, `archive_name`, `member_name`, `member_id`, `size` (declared; 0 when none is declared and the body is larger than an empty one of its method), `compressed_size` |
| `MEMBER_LINK_DATA_IGNORED` | `LinkDataContext`: `kind="link_data"`, `archive_name`, `member_name`, `member_id`, `size` (declared) |
| `MEMBER_HEADER_AMBIGUOUS` | `HeaderAmbiguityContext`: `kind="header_ambiguity"`, `archive_name`, `member_name`, `member_id`, `ambiguity` (`"both_families"`, `"repeated"`, `"global_member_field"`, `"nul_in_value"`, `"global_replaced"`, `"mixed_chain"`, `"global_in_chain"`, `"empty_value"`, `"leading_zero"`, `"field_tail"`, `"size_on_no_data"`, `"signed_checksum"`, `"magic_version"` or `"newline_in_value"`), `field` (the PAX keyword, or the header field for `"field_tail"`, `"chksum"` for `"signed_checksum"`, `"version"` for `"magic_version"`, `"x size"`, `"g size"`, `"L size"` or `"K size"` for an extended header's own size field; `"path"` or `"linkpath"` for a GNU long name or long link header, `"x"` for a repeated `x` header and for `"mixed_chain"`, `"g"` for `"global_in_chain"`), `more_fields` (how many other fields the same shape holds for on the member; one report covers them) |
| `MEMBER_SPECIAL_FILE_HAS_DATA` | `SpecialFileDataContext`: `kind="special_file_data"`, `archive_name`, `member_name`, `member_id`, `special_file_type` ∈ `{"fifo","char_device","block_device","socket","unknown"}`, `size` |
| `MEMBER_LOCAL_NAME_DIFFERS`, `MEMBER_LOCAL_METHOD_DIFFERS`, `MEMBER_LOCAL_CRC_USED` | `LocalHeaderContext`: `kind="local_header"`, `archive_name`, `member_name`, `member_id`, `field` (`"name"`, `"method"` and `"crc32"` in that order), `local_raw_name_base64` (the local header's name bytes, `field="name"` only), `local_method` and `central_method` (`field="method"` only), `local_crc32` (`field="crc32"` only) |
| `ARCHIVE_OFFSET_WRAPPED` | `OffsetWrapContext`: `kind="offset_wrap"`, `archive_name`, `format`, `member_name`, `member_id` (empty and `None` for the directory), `record` ∈ `{"local_header","central_directory"}`, `stored_offset`, `corrected_offset` |
| `MEMBER_SIZE_WRAPPED` | `SizeWrapContext`: `kind="size_wrap"`, `archive_name`, `format`, `member_name`, `member_id`, `stored_compressed_size`, `compressed_size`, `stored_size`, `size` (`None` when only a read can tell) |
| `MEMBER_TYPE_UNKNOWN` | `UnknownMemberTypeContext`: `kind="unknown_member_type"`, `archive_name`, `member_name`, `member_id`, `stored_type` (the TAR typeflag byte as a one-character string, the byte read as Latin-1; for a RAR5 redirect, the type number in decimal), `size` (the member's `size`; `None` for an `OTHER` member) |
| `MEMBER_NAME_DUPLICATE` | `NameDuplicateContext`: `kind="name_duplicate"`, `archive_name`, `member_name`, `member_id`, `earlier_member_id` (the latest earlier member under the name, or under it with or without a final `/`), `earlier_type` and `member_type` (`MemberType` values). Emitted at listing, in every format, when a current member has the name of an earlier current one and the two are not both directories. Names are compared as the listing presents them: a ZIP read from a pipe compares the central directory's names, once it has read the directory |
| `MEMBER_READERS_DISAGREE` | `ReaderDisagreementContext`: `kind="reader_disagreement"`, `archive_name`, `member_name`, `member_id`, `shape` (`"file_named_as_directory"`, `"link_name_on_file"` (the header's field or a PAX `linkpath` on a regular file), `"star_prefix"` or `"gnu_prefix_bytes"` for a TAR header; `"hardlink_to_symlink"` in every format with hard links; `"nul_in_name"` in every format; `"directory_attribute_without_slash"` for a ZIP entry; `"file_only_in_joliet"`, `"file_only_in_iso9660"` or `"file_only_in_udf"` for a file an ISO image's Joliet, plain ISO 9660 or UDF tree holds and its listed tree does not, with `member_name` its path in that tree and `member_id` `None`) |
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
matching extension, no inner-TAR upgrade, no self-checking header) — **and a decode
failure**. A probe-only read
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
| `MEMBER_NAME_NORMALIZED`, `MEMBER_NAME_ENCODING_INFERRED`, `MEMBER_NAME_BIDI_CONTROL`, `MEMBER_NAME_ZERO_WIDTH_CHARACTER`, `EXTENSION_FORMAT_UNCONFIRMED`, `SCAN_DIRECTORY_VANISHED`, `SCAN_ENTRY_VANISHED`, `ARCHIVE_EOF_MARKER_MISSING`, `ARCHIVE_TRAILING_DATA`, `ARCHIVE_UNLISTED_DATA`, `MEMBER_TIMESTAMP_INVALID`, `MEMBER_HEADER_RECORD_SKIPPED`, `SYMLINK_TARGET_UNAVAILABLE`, `DIGEST_UNVERIFIABLE`, `MEMBER_DIRECTORY_DATA_IGNORED`, `MEMBER_LINK_DATA_IGNORED`, `MEMBER_HEADER_AMBIGUOUS`, `MEMBER_HEADER_DAMAGED`, `SEEK_INDEX_DEGRADED`, `MEMBER_LOCAL_NAME_DIFFERS`, `MEMBER_LOCAL_METHOD_DIFFERS` | `EMPTY_ARCHIVE` (an empty archive is legitimate), `EXPLICIT_FORMAT_LISTED_EMPTY`, `ENCODING_ARGUMENT_UNUSED`, `PASSWORD_ARGUMENT_UNUSED`, `STREAM_REWIND_REDECOMPRESSES`, `PROBE_FORMAT_UNCONFIRMED`, `ENCRYPTED_MEMBER_UNVERIFIED`, `MEMBER_SELECTOR_UNMATCHED`, `MEMBER_SPECIAL_FILE_HAS_DATA`, `MEMBER_NAME_INVISIBLE_CHARACTER`, `FORMAT_EXTENSION_CONFLICT` (the name is wrong, not the bytes), `MEMBER_LOCAL_CRC_USED` (Adobe AIR writes it; the data is checked against the local CRC-32), `ARCHIVE_OFFSET_WRAPPED` and `MEMBER_SIZE_WRAPPED` (macOS writes the shape by default), `MEMBER_TYPE_UNKNOWN` (GNU tar extracts the member as a file), `MEMBER_NAME_DUPLICATE` and `MEMBER_READERS_DISAGREE` (real archives have the shapes, read as the format's tool reads them) |

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
the reference tool extracts; `MEMBER_NAME_DUPLICATE` and `MEMBER_READERS_DISAGREE`
because real archives have those shapes (`tar -r` appends, cabal sdists, v7
directories, star and GNU incremental headers) and archivey reads them as the
format's own tool does, so `STRICT` would refuse archives that tool extracts: they are
for a caller who checks an archive another tool will extract, through
`DiagnosticPolicy(raise_on=...)` or `PEDANTIC`; and `FORMAT_EXTENSION_CONFLICT` because it
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
| `MEMBER_HEADER_DAMAGED in ARCHIVE_INTEGRITY_CODES` | True; `STRICT` refuses only that member's read, at the read |
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
