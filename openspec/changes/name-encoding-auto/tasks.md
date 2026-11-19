## 1. Guesser

- [ ] 1.1 Add `src/archivey/internal/name_encoding.py` with `guess_cjk()` (design
  decision 2): strict decode per candidate, a name cut inside its last character, the
  frequency score, the 0.5 threshold, the 0.15 margin, the 2-character minimum, the
  Latin-word guard and the rival guard
- [ ] 1.2 Commit the frequency tables as package data, plus the script that rebuilds
  them (decisions 5 and 9): Wikipedia titles, from a pinned dump date, with a one-line
  provenance note next to the data
- [ ] 1.3 Add `NameDecoder`: evidence in meeting order, frozen after 256 evidence names,
  a memo of the names met before the freeze, one text per directory prefix (split on
  `/`, and on `\` only at a character boundary of the codec used), a lock until the
  freeze (decision 3)
- [ ] 1.4 Unit tests on committed name sets: each CJK codec guessed;
  cp437/cp850/cp1252/cp852 names never guessed; the `M\x81ller` and `Élève` cases
  abstain; a cp932 archive with one name cut inside its last character still guesses
  cp932; a frozen guess stays frozen; the memo returns one text per byte string; in a
  format that separates with `\`, a cp932 name holding `ソ` (`83 5C`) or `表` (`95 5C`)
  is not split at that byte

## 2. Wire it in

- [ ] 2.1 `check_encoding` accepts `"auto"`; `open_archive` and fsspec pass it through
- [ ] 2.2 ZIP, TAR, RAR and ISO decode legacy names through `NameDecoder`; only the
  decode that gives a member's `name` adds evidence: the central name in a seekable ZIP,
  the local name in a forward walk (decision 4)
- [ ] 2.3 ISO under `"auto"`: UTF-8, then the Joliet twin, then the guess (decision 7)
- [ ] 2.4 `ReaderContext.decode_name()` uses the reader's `NameDecoder` and adds
  evidence; add `ReaderContext.decode_text()`, which adds none; `ReaderContext.encoding`
  is `None` under `"auto"`; the adapter emits `MEMBER_NAME_ENCODING_INFERRED` for the
  member whose `raw_name` was guessed
- [ ] 2.5 Switch the built-in callers that decode text other than member names to
  `decode_text`: ARJ link targets and comments (archive comment included), LHA comments
  and user and group names, SquashFS and RPM link targets
- [ ] 2.6 A nested reader inherits `"auto"` and starts its own `NameDecoder`
- [ ] 2.7 `MEMBER_NAME_ENCODING_INFERRED` with `declared_encoding` set to the codec the
  name would otherwise have had (decision 8)

## 3. Docs

- [ ] 3.1 `docs/opening.md` §"Names in other encodings": `encoding="auto"`, what it
  guesses, what it never guesses, the diagnostic (written by Opus, DR-22b)
- [ ] 3.2 The name sections of the format pages that read `encoding=`
- [ ] 3.3 `docs/adding-a-format.md`: `decode_name` for member names, `decode_text` for
  everything else

## 4. Verify

- [ ] 4.1 One fixture per CJK codec through ZIP, TAR, cpio and LHA: the same names under
  `streaming=True` and `streaming=False`, and under `max_members`
- [ ] 4.2 A Big5 ZIP and TAR whose first entry is a short directory that abstains alone,
  followed by its children: one tree, no directory without its children (red-green
  against a decoder with no directory rule)
- [ ] 4.3 A ZIP whose central directory lists entries in another order than its local
  headers: the documented exception, pinned
- [ ] 4.4 ARJ with an archive comment: `info` read before and after the listing gives
  the same member names
- [ ] 4.5 Concurrency: two threads listing the same reader under
  `concurrent_operations=True` get the same names
- [ ] 4.6 libarchive's cp932, EUC-JP, cp866 and KOI8-R fixtures: the cp932 ones are
  guessed, the others abstain
- [ ] 4.7 `./scripts/check.sh --fix` and the targeted tests
- [ ] 4.8 `openspec validate --strict name-encoding-auto`
