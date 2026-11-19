## 1. Guesser

- [ ] 1.1 Add `src/archivey/internal/name_encoding.py` with `guess_cjk()` (design
  decision 2): strict decode per candidate, frequency score, the 0.5 threshold, the 0.15
  margin, the 2-character minimum, the Latin-word guard and the rival guard
- [ ] 1.2 Commit the frequency tables as package data, plus the script that rebuilds
  them (decision 5; open question 1 decides the source)
- [ ] 1.3 Add `NameDecoder`: evidence in meeting order, frozen after 256 evidence names,
  a memo per distinct byte string, a lock (decision 3)
- [ ] 1.4 Unit tests on committed name sets: each CJK codec guessed,
  cp437/cp850/cp1252/cp852 names never guessed, the `M\x81ller` and `Élève` cases
  abstain, a frozen guess stays frozen, the memo returns one text per byte string

## 2. Wire it in

- [ ] 2.1 `check_encoding` accepts `"auto"`; `open_archive` and fsspec pass it through
- [ ] 2.2 ZIP, TAR, RAR and ISO decode legacy names through `NameDecoder`; only the
  decode that gives a member's `name` adds evidence (decision 4)
- [ ] 2.3 `ReaderContext.decode_name()` uses the reader's `NameDecoder`;
  `ReaderContext.encoding` is `None` under `"auto"`; the adapter emits
  `MEMBER_NAME_ENCODING_INFERRED` for the member whose `raw_name` was guessed
- [ ] 2.4 A nested reader inherits `"auto"` and starts its own `NameDecoder`
- [ ] 2.5 `MEMBER_NAME_ENCODING_INFERRED` with `declared_encoding` set to the codec the
  name would otherwise have had (decision 7)

## 3. Docs

- [ ] 3.1 `docs/opening.md` §"Names in other encodings": `encoding="auto"`, what it
  guesses, what it never guesses, the diagnostic (written by Opus, DR-22b)
- [ ] 3.2 The name sections of the format pages that read `encoding=`

## 4. Verify

- [ ] 4.1 One fixture per CJK codec through ZIP, TAR, cpio and LHA: the same names under
  `streaming=True` and `streaming=False`, and under `max_members`
- [ ] 4.2 Concurrency: two threads listing the same reader under
  `concurrent_operations=True` get the same names
- [ ] 4.3 libarchive's cp932, EUC-JP, cp866 and KOI8-R fixtures: the cp932 ones are
  guessed, the others abstain
- [ ] 4.4 `./scripts/check.sh --fix` and the targeted tests
- [ ] 4.5 `openspec validate --strict name-encoding-auto`
