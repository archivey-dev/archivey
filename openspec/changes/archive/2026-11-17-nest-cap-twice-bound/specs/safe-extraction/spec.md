## MODIFIED Requirements

### Requirement: A nest's decoded bytes are held to one total

`DecoderLimits.max_nest_decoded_bytes: int | None` SHALL cap the bytes every reader of
a nest (archive-reading, "A reader opened inside another joins its nest")
decodes, summed across its levels and its threads; `None` disables it.

- **Bytes.** Every byte a member stream delivers (a read, `stream_members()`, an
  extraction's writes) SHALL count, and so SHALL the gap a forward seek skips past the
  furthest offset reached, and the byte a compressed single file's open-time check
  decodes. A seek whose target is known SHALL be refused before the decoder moves when
  the gap does not fit; a seek to an end the stream cannot size SHALL read to it,
  counted. A read that would cross the cap SHALL ask its decoder for at most one byte
  past what is left, then raise the always-stop `ResourceLimitError`, so an extraction
  stops at that member. A buffer's read-ahead over a source that cannot seek SHALL be
  capped the same way. In a nest of one level, the crossing read SHALL decode at most
  one byte past the cap. In a deeper nest, the bytes an outer level decodes to fill an
  inner read count too, after the inner read has sized itself, so the crossing read
  MAY pass the cap by those bytes. Every read SHALL be sized against what is left when
  it starts, so on one thread the count SHALL stay at or under about twice the cap at
  any depth. That cap is the one the outer readers size their reads against: a child
  that sets a stricter cap SHALL stop its own reads at it, and the bytes its outer
  readers decode for it MAY reach their own cap. Readers on several threads MAY each
  overshoot by one read. Once spent, the nest SHALL refuse every later read before it
  decodes.
- **Skipped bytes.** Bytes a decoder produces to get past a member nobody reads SHALL
  count where they are decoded, in every format (a compressed TAR's listing included): a
  compressed TAR's, cpio's or RPM payload's skipped members and headers, a CAB folder's
  output before the member read, the part of a streaming ZIP member the pass decodes,
  the solid prefix `unrar` or `unar` decodes and does not emit, and a 7z header stored
  compressed. A member that is read SHALL count once. A step that decodes all at once (a
  RAR prefix, a 7z header) SHALL be counted before it runs, and refused, counting
  nothing, when it does not fit. A sparse TAR member's holes SHALL count as they are
  read. Other metadata a format decodes into memory (SquashFS metadata blocks, XAR's
  table of contents) is held by the listing limits, not by this total.
- A byte decoded again (a member read twice, a backward seek in compressed data, the
  same archive opened twice in one nest) SHALL count again.
- A reader whose cap, the stricter of its own and the outermost reader's, is `None`
  SHALL count nothing, so its reads pay for no counting: a child that sets a cap the
  outermost reader does not set counts only the bytes of the readers that set one.
- The counter SHALL NOT refill while the nest lives, so on a reader kept open for long
  (an `ArchiveyFileSystem`, a reader shared by a server) the cap bounds every read it
  ever serves; the field's documentation SHALL say so.

#### Scenario: decoded-bytes matrix

- **WHEN** a nest decodes as each row says
- **THEN** the total is counted and held as the row's Expected column says

| Case | Expected |
| --- | --- |
| `max_nest_decoded_bytes=350_000`, ZIP of five 100 000-byte members, two read by the outer reader and two by the same ZIP opened a second time with `parent=outer` | The fourth read raises `ResourceLimitError` naming `max_nest_decoded_bytes=350000`; 350 001 bytes counted |
| `max_nest_decoded_bytes=10**12`, `.tar.gz` of three 100 000-byte members, `stream_members()` reads only the third | At least 300 000 bytes counted; reading all three counts no more than the decoded tar's size |
| `max_nest_decoded_bytes=2 * 100_000 + 10`, `extract_all` on the ZIP | Raises; two members written whole, no later member opened |
| One config, two separate `open_archive` calls with no `parent=` | Each counts from zero |
| `max_nest_decoded_bytes=500_000`, a deflated ZIP holding a stored ZIP of one 4 000 000-byte member, the inner member read in 65 536-byte steps with `parent=outer` | Raises `ResourceLimitError` naming `max_nest_decoded_bytes=500000`; more than 500 000 and at most 500 000 + 65 536 + 1 bytes counted |
| `max_nest_decoded_bytes=500_000`, a deflated ZIP holding a stored ZIP holding a stored ZIP of one 8 000 000-byte member, each opened with `parent=` and `streaming=True`, the innermost member read with one `read()` | Raises `ResourceLimitError`; more than 500 000 and at most 2 × 500 000 + 1 bytes counted |
