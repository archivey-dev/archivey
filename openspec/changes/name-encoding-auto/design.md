## Context

A name stored without an encoding signal decodes today as follows. Valid UTF-8 wins
(DR-7). Otherwise the caller's `encoding=` applies, or else the format's default: cp437
for ZIP (`zip_unflagged_fallback_encoding`), and UTF-8 with `surrogateescape` for most
others. ZIP, TAR, RAR and ISO decode in their own readers, each holding
`self._encoding`. The plugin-shaped built-ins (cpio, ar, RPM, deb, makeself, SquashFS,
CAB, XAR, LHA, ARJ) and third-party plugins call `ReaderContext.decode_name()`
(`src/archivey/formats.py`). ZIP and RAR already report a codec archivey chose itself
with `MEMBER_NAME_ENCODING_INFERRED`, which is in `ARCHIVE_INTEGRITY_CODES`, so STRICT
refuses it.

davi asked (2026-11-18) whether archivey could guess non-Western encodings from the
bytes. The investigation measured a hand-written check against chardet,
charset-normalizer and uchardet. Its scripts, full tables and report are in the project
files under `investigations/encoding-guess-2026-11-18/`, and are summarised under
Investigations.

## Goals / Non-Goals

**Goals:**

- An opt-in guess for CJK legacy names, with no new dependency, that almost never
  guesses wrong and abstains when it cannot tell.
- The same archive bytes give the same names in streaming and random access, under any
  `max_members`, and in any order of calls (DR-5).
- One decoder shared by every format that reads `encoding=`, built-in or plugin.

**Non-Goals:**

- Guessing Latin code pages (cp437, cp850, cp1252, cp852, cp1250, cp857). Every guesser
  measured is often wrong where today's default is right.
- Cyrillic, Greek and Hebrew code pages: a follow-up change (decision 6).
- Re-decoding names that are valid UTF-8. A valid UTF-8 name stays out of the guess,
  even in an archive confidently guessed as EUC-JP or GBK (DR-7; davi, 2026-11-19).
- A CLI `--encoding` option.
- Guessing as the default. `"auto"` is opt-in.

## Investigations

The name sets are Wikipedia article titles turned into file names: 40k random titles per
language, an optional folder, and an extension. There are 300 archives per cell. The
guesser sees only the names that are not valid UTF-8, because archivey already reads the
rest as UTF-8. Each cell is correct % / wrong %, and the rest abstained. Abstaining
keeps today's behaviour.

| Names | built-in check, N=1 | N=3 | N=10 | 1-4 character names, N=3 | chardet N=3 | charset-normalizer N=3 |
| --- | --- | --- | --- | --- | --- | --- |
| Japanese cp932 | 94/0 | 100/0 | 100/0 | 97/0 | 92/8 | 96/3 |
| Japanese EUC-JP | 92/0 | 100/0 | 100/0 | 86/0 | 91/9 | 95/4 |
| Chinese GBK | 81/0 | 99/0 | 100/0 | 80/1 | 91/9 | 88/11 |
| Chinese Big5 | 61/1 | 92/0 | 100/0 | 76/0 | 95/5 | 70/30 |
| Korean cp949 | 91/0 | 99/0 | 100/0 | 91/0 | 100/0 | 98/1 |
| German cp437 (should abstain) | 0/0 | 0/0 | 0/0 | 0/0 | 82/18 | 12/88 |
| French cp850 (should abstain) | 0/1 | 0/0 | 0/0 | 0/0 | 73/27 | 13/87 |

- Over every Latin-script target (de, fr, es, pt, sv, pl and cs, each with its code
  pages), the built-in check guessed a CJK codec in 0.1% of realistic archives and in
  0.0% of archives with 1-4 character names. Unrestricted chardet was wrong in 9-33% of
  them.
- Real archives (libarchive's encoded-name fixtures, plus archivey's own cp932 CAB): the
  check was right on the cp932 ZIP, CAB and LHA archives. It abstained on one EUC-JP
  cpio archive with a single two-character name (`漢字.txt`), where chardet said gb18030
  and charset-normalizer said utf-16-le.
- A table-free version uses each standard's "frequently used" block (GB2312 level 1,
  Big5 frequent, JIS level 1 and kana, KS X 1001 hangul). It cannot separate EUC-JP, GBK
  and EUC-KR, which share one byte layout: Korean came out 0-5% right. Frequency tables
  are needed.
- Cost: 0.03 ms per archive for the built-in check, against 0.6-0.9 ms for chardet or
  charset-normalizer.
- Today's per-name UTF-8 check decodes 0.53% of EUC-JP names and 0.21% of GBK names as
  UTF-8, because those bytes happen to be valid UTF-8. They stay out of the guess
  (Non-Goals).

## Decisions

### 1. The spelling is `encoding="auto"`

The value `"auto"` goes through the existing argument. No codec is registered under that
name, so it cannot collide with one. `check_encoding` accepts it before the codec
lookup. **Rejected:** a separate `guess_encoding=True` flag. It would need rules for how
it combines with an explicit codec, and DR-14 asks for one mechanism per job.
**Rejected:** a candidate list (`encoding=("cp932", "gbk")`). It could come later as its
own change if a caller needs it.

### 2. The guesser: strict decode, frequency score, guards, abstain

For each candidate in (cp932, euc_jp, gbk, big5, cp949), every evidence name must decode
strictly, or the candidate drops out. Score = the share of non-ASCII characters that are
among that language's 1000 most frequent, or are CJK punctuation (U+3000-303F and
full-width ASCII punctuation, but not full-width letters or digits). The guess is the
best candidate, but only when all of these hold:

- its score is at least 0.5;
- it beats every other candidate by at least 0.15;
- the evidence holds at least 2 non-ASCII characters;
- the Latin-word guard passes: abstain when the matches of `[A-Za-z][\x80-\xff][a-z]` in
  the bytes number at least a quarter of the CJK characters. This catches `M\x81ller`
  and `\x90l` from `Élève`, where 0x90 0x6C is 人 in cp932;
- the rival guard passes: with fewer than 4 CJK characters, abstain when the bytes also
  read as clean lower-case or capitalised words in cp866, cp1251, KOI8-R, cp737 or
  cp1253.

Each guard was added after it removed a measured false positive without costing CJK
accuracy. They are all in the investigation's `detectors.cjk_freq`. A guess that a name
cannot strictly decode under is never applied to that name: the name falls back as it
does today. The counts are additive, so the score updates per name in constant time.

**Rejected:** chardet, charset-normalizer and uchardet for CJK. Each is a dependency,
and each is weaker on 1-3 names (table above). chardet restricted to its CJK answers
still had about 0.5% false positives.

### 3. Evidence: the legacy names met so far, in archive order, capped at 256

The two open choices from the investigation are which names the guess sees, and how it
works on formats that walk without an index. One rule settles both. The codec for a name
is guessed from the evidence collected up to and including that name:

- **Evidence** is the distinct stored names that are not valid UTF-8, in the order the
  reader meets them as member names.
- After 256 evidence names the guess is **frozen**, and later names neither add to it
  nor change it.
- **Memo:** each distinct stored byte string is decoded once per reader, and every later
  decode of the same bytes returns the same text.

Why this rule:

- **Streaming matches random access** (DR-5). A forward walk and an indexed listing meet
  the same names in the same order. TAR, cpio, ar, LHA and ARJ write names in walk
  order, and the ZIP central directory lists entries in local-header order. So both
  reads give the same names. No reader needs lookahead, which a TAR stream can't have
  without buffering member data.
- **`max_members` and damage can't change a name.** A cut-short walk stops adding
  evidence after the cut, and names before the cut already have their final decode.
- **Order of calls doesn't matter.** Thanks to the memo, a re-walk, a `get()`, or a
  second `members()` never sees a different decode for bytes it already decoded.
- **Bounded cost.** Evidence stops at 256 names. Accuracy plateaus by about 10 names.

The cost: early names get less evidence than a whole-archive guess would give them. The
first legacy name is decoded on its own evidence (the N=1 column: right 61-94%,
otherwise abstains, wrong at most 1%). By the third name the guess matches the
whole-archive guess in 92-100% of archives.

**Rejected:**

- **(A) A whole-archive guess for indexed formats, refused or per-name for sequential
  ones.** A ZIP read from a pipe (forward walk) would then name members differently from
  the same ZIP read from a file. That breaks DR-5's access-mode rule, with no
  "impossible" reason behind it.
- **(B) A whole-archive guess from the first K names, with lookahead.** Fine for indexed
  formats. A TAR or cpio stream would have to buffer up to K members' data before
  yielding the first one, which breaks the streaming memory bound.
- **(C) Each name on its own evidence only.** Simple and consistent, but it throws away
  the evidence of the other names: N=1 accuracy for every name, instead of N=3 or better
  from the third name on.
- **A sticky first guess.** Once a codec is chosen, it would never change. It is
  simpler, but an early wrong guess (at most 1-3% at N=1) would then stick for the rest
  of the archive. The frozen running guess corrects itself as evidence grows.

### 4. Which decodes feed the evidence

Only the decode that produces a member's `name` adds evidence. Some decodes only compare
or annotate:

- ZIP's local-header name, read for `MEMBER_LOCAL_NAME_DIFFERS`;
- TAR's link targets;
- comments;
- RAR's alternate names.

These use the current guess and the memo, and add no evidence. So the listing alone
fixes the guess, and a read that skips the local headers or the link targets gives the
same names. A plugin's `ReaderContext.decode_name()` can't say which kind of decode it
is, so every call to it counts as a member name. The memo still keeps each byte string's
text fixed. **Rejected:** feeding link targets too. They would give more evidence, but a
TAR stream meets a link target at a different point than the listing does in some
readers, which reopens the question decision 3 settles.

### 5. One decoder per reader, shared by built-ins and plugins

A new module, `internal/name_encoding.py`, holds:

- `guess_cjk(evidence)`, a pure function;
- `NameDecoder(encoding, fallback)`, which holds the evidence, the memo and a lock.
  Readers under `concurrent_operations=True` decode from several threads.
- The frequency tables, as package data of about 12 KB. A committed script rebuilds them
  from the source corpus (open question 1).

`NameDecoder.decode(raw)` returns the text and the codec it used when that codec was
inferred. ZIP, TAR, RAR and ISO replace their `self._encoding` branches with it. ZIP
keeps its own steps around it: bit 11, the Unicode Path field and
`zip_unflagged_fallback_encoding`. `ReaderContext.decode_name()` calls it, and
`ReaderContext.encoding` returns `None` under `"auto"`, so a plugin that decodes with
`ctx.encoding` gets today's no-hint behaviour instead of a `LookupError`. A nested
reader inherits `"auto"` and starts its own decoder: an inner archive is another
archive, with its own evidence. **Rejected:** a guesser per format. Every format would
then need the same tests, and DR-23a says what must agree is shared.

### 6. Cyrillic, Greek and Hebrew: a follow-up, behind an optional extra

These need statistics. With chardet 7, kept only when it names one of those code pages
and the names hold at least 8 non-ASCII bytes, `"auto"` gets 91-100% right on 3
realistic names and 0% wrong on Latin names. On 1-4 letter names it is much weaker:
26-57% right, with up to 17% wrong for Greek and Hebrew. That runs against DR-1 (a wrong
answer is the worst failure), and it needs a dependency decision: chardet 7 is 0BSD, 3.3
MB, and needs Python 3.10 or later. As far as I recall, its relicensing in 7.0 was
publicly disputed. All of that belongs in its own change, after this one ships.
**Rejected:** a hand-written single-byte rule (letters plus casing). It was right on
Cyrillic, but it was 0-100% wrong on Hebrew and Turkish.

### 7. Reporting

Each name decoded with a guessed codec reports `MEMBER_NAME_ENCODING_INFERRED`, with
`inferred_encoding` set to the guess. `declared_encoding` is the codec the name would
otherwise have had: the format's default, or for ZIP the configured fallback. The code
stays in `ARCHIVE_INTEGRITY_CODES`, so STRICT refuses an archive whose names needed a
guess. This is the same rule as for the UTF-8 sniff today, and "STRICT" means no
guessing. A caller who wants both STRICT and CJK names passes the codec. No new code and
no new context field are needed.

## Risks / Trade-offs

- [The tables come from Wikipedia titles, which lean towards proper nouns] → Accuracy is
  measured on held-out titles. Real file names use more everyday characters, which
  should only help. Open question 1 covers swapping in public standard lists.
- [A wrong guess gives a wrong name, which DR-1 ranks worst] → The guess abstains unless
  one codec wins clearly. Measured wrong rates are at most 1% on CJK at N=1 and 0.1% on
  Latin archives. The diagnostic names the guess and keeps `raw_name`, so a caller can
  re-decode.
- [Early names decode on less evidence than later ones] → Accepted for DR-5 (decision
  3). A caller who knows the codec passes it.
- [A ZIP whose central directory lists entries in a different order from its local
  headers] → Then a forward walk and a listing meet the names in different orders, and
  may guess differently for the first few names. Such an archive already reports
  `MEMBER_LOCAL_*` diagnostics. Tests pin the common case, where the order is the same.
- [Thread safety] → The `NameDecoder` lock covers the evidence and the memo. A decode
  costs microseconds, so contention is negligible.

## Open Questions

1. **Table source (question for the reviewer).** The measured tables are the top-1000
   characters of Wikipedia titles per language, built by a committed script. The
   alternative is public standard lists: Jōyō kanji for Japanese, 通用规范汉字表 level 1
   for Simplified Chinese, 常用國字標準字體表 for Traditional Chinese, and a frequency
   ranking of the KS X 1001 hangul for Korean. The trade-offs:
   - Wikipedia titles: measured as above. Reproducible from a public dump. They lean
     towards proper nouns. A ranking of characters is data, not text, so licensing
     should not apply, but it comes from a CC BY-SA corpus.
   - Standard lists: an authority, and no corpus provenance. But they are unranked sets
     of 2000-3500 characters, not top-1000 rankings. The Korean one still needs a
     frequency source, and they would have to be re-measured, because a larger set
     lowers the margin between codecs.

   The author's recommendation is Wikipedia. davi asked for the reviewer's view before
   deciding.
