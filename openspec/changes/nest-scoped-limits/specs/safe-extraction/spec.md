## ADDED Requirements

### Requirement: A nest's decoded bytes are held to one total

`DecoderLimits.max_nest_decoded_bytes: int | None` SHALL cap the bytes every reader of
a nest (archive-reading, "A reader opened inside another joins its nest")
decodes, summed across its levels and its threads; `None` disables it.

- **Bytes.** Every byte a member stream delivers (a read, `stream_members()`, an
  extraction's writes) SHALL count, and so SHALL the gap a forward seek skips past the
  furthest offset reached, and the byte a compressed single file's open-time check
  decodes. A seek whose target is known SHALL be refused before the decoder moves when
  the gap does not fit; a seek to an end the stream cannot size SHALL read to it,
  counted. A read that would cross the cap SHALL decode at most one byte past what is
  left, then raise the always-stop `ResourceLimitError`, so an extraction stops at that
  member. Readers on several threads MAY each overshoot by one read. Once spent, the
  nest SHALL refuse every later read before it decodes.
- **Skipped bytes.** Bytes a decoder produces to get past a member nobody reads SHALL
  count where they are decoded, in every format: a compressed TAR's, cpio's or RPM
  payload's skipped members and headers, a CAB folder's output before the member read,
  the part of a streaming ZIP member the pass decodes, the solid prefix `unrar` or
  `unar` decodes and does not emit, and a 7z header stored compressed. A member that is
  read SHALL count once. A step that decodes all at once (a RAR prefix, a 7z header)
  SHALL be counted before it runs, and refused, counting nothing, when it does not fit.
  A sparse TAR member's holes SHALL count as they are read.
- A byte decoded again (a member read twice, a backward seek in compressed data, the
  same archive opened twice in one nest) SHALL count again.
- The counter SHALL NOT refill while the nest lives, so on a reader kept open for long
  (an `ArchiveyFileSystem`, a reader shared by a server) the cap bounds every read it
  ever serves; the field's documentation SHALL say so.

#### Scenario: decoded-bytes matrix

- **WHEN** a nest decodes as each row says
- **THEN** the total is counted and held as the row's Expected column says

| Case | Expected |
| --- | --- |
| `max_nest_decoded_bytes=350_000`, ZIP of five 100 000-byte members, two read by the outer reader and two by an inner reader opened with `parent=` | The fourth read raises `ResourceLimitError` naming `max_nest_decoded_bytes=350000`; 350 001 bytes counted |
| Unlimited, `.tar.gz` of three 100 000-byte members, `stream_members()` reads only the third | At least 300 000 bytes counted; reading all three counts no more than the decoded tar's size |
| `max_nest_decoded_bytes=2 * 100_000 + 10`, `extract_all` on the ZIP | Raises; two members written whole, no later member opened |
| One config, two separate `open_archive` calls with no `parent=` | Each counts from zero |

## REMOVED Requirements

### Requirement: A shared budget holds many readers to one total

**Reason**: Its scope was the `Budget` object, so a reused config shared one pool across
unrelated requests and it never refilled. A nest now defines the scope of the totals:
the byte counter moves to `DecoderLimits.max_nest_decoded_bytes`, the member counter to
the nest's `max_members` total, and the nest's ratio total (archive-reading, "Limits
apply per nest") bounds a nest by default.

**Migration**: Replace `ArchiveyConfig(budget=Budget(max_decoded_bytes=N,
max_members=M))` with `DecoderLimits(max_nest_decoded_bytes=N)` and
`ListingLimits(max_members=M)`, and open each inner archive with
`open_archive(..., parent=outer_reader)`. A total across unrelated archives of one
request is the caller's: bound the upload size and the number of archives, and run the
request in a child process.
