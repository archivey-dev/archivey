## Context

A name stored without an encoding signal decodes today as follows. Valid UTF-8 wins
(DR-7). Otherwise the caller's `encoding=` applies, or else the format's default: cp437
for ZIP (`zip_unflagged_fallback_encoding`), and UTF-8 with `surrogateescape` for most
others. ZIP, TAR, RAR and ISO decode in their own readers, each holding
`self._encoding`. The plugin-shaped built-ins (cpio, ar, RPM, deb, makeself, SquashFS,
CAB, XAR, LHA, ARJ) and third-party plugins call `ReaderContext.decode_name()`
(`src/archivey/formats.py`). ZIP, RAR and TAR already report a codec archivey chose
itself with `MEMBER_NAME_ENCODING_INFERRED`. ISO reports it, with empty
`inferred_encoding` and `declared_encoding`, for a Rock Ridge name taken from the Joliet
tree. The code is in `ARCHIVE_INTEGRITY_CODES`, so STRICT refuses it.

davi asked (2026-11-18) whether archivey could guess non-Western encodings from the
bytes. The investigation measured a hand-written check against chardet,
charset-normalizer and uchardet. Its scripts, full tables and report are in the project
files under `investigations/encoding-guess-2026-11-18/`, and are summarised under
Investigations.

## Goals / Non-Goals

**Goals:**

- An opt-in guess for CJK legacy names, with no new dependency, that almost never
  guesses wrong and abstains when it cannot tell.
- The same archive bytes give the same names in streaming and random access, and in
  any order of calls (DR-5). Damage and listing caps never change a name already
  listed.
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
strictly, or the candidate drops out. A name cut inside its last character is the
exception (a 100-byte ustar field, a tool that truncates by bytes, a damaged header):
when no candidate decodes the name but some candidate decodes it without its last byte,
the name gives evidence from all but that byte. Any other name that no candidate decodes
still rules every candidate out, because it is evidence that the archive is not CJK.
Keeping such names out of the evidence instead raised the false positives on short cp866
and cp862 names from 0% to 2-6%, so they stay in. Score = the share of non-ASCII
characters that are among that language's 1000 most frequent, or are CJK punctuation
(U+3000-303F and full-width ASCII punctuation, but not full-width letters or digits).
The guess is the best candidate, but only when all of these hold:

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
accuracy. They are all in the investigation's `detectors.cjk_freq_cut`, which measures
the same as `cjk_freq` on every set. A guess is applied to a name only when the name
decodes strictly under it, or is cut inside its last character: then the cut byte
decodes as a `surrogateescape` escape. Any other name falls back as it does today. The
counts are additive, so the score updates per name in constant time.

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
- **Memo:** each distinct stored byte string met before the freeze is decoded once per
  reader, and every later decode of the same bytes returns the same text. The one
  exception is a plugin directory that waits (below): from its listing on, its bytes
  decode to its listed text. After the freeze a decode depends only on the bytes, so the
  memo stops growing: it holds at most the names met before the freeze, and lookups
  after it need no lock.
- **Directories keep one text.** A directory's path decodes to one text per reader, and
  every name under it reuses that text for the directory part. Only the rest of the name
  is decoded with the current guess. The memo is keyed on each byte prefix that ends
  just before a `/` or a `\`, in every format, when that byte falls at a character
  boundary of the codec used for the prefix. So the trail byte of `ソ` (`83 5C`) or `表`
  (`95 5C`) never splits a name. Keying on `\` in a format where it is not a separator
  (TAR) only makes a prefix's text more consistent: a decode split at character
  boundaries gives the same text as a whole decode. So the decoder needs no per-format
  flag. This also works in the other order: a directory entry met after its children
  takes the text its children gave it.
- **A directory waits for the next entry that is not a directory.** A directory entry
  is decoded only once the reader has met the next member that is not a directory. Its
  decode uses the evidence up to that member. A directory is told by the member's own
  header in every mode: a ZIP name ending in `/`, a TAR or cpio directory type, and so
  on. An empty file or a link does not wait, because a streamed ZIP (flag bit 3) writes
  no sizes in its local headers, and a pipe walk learns that a member is a link only
  from the central directory at the end. Waiting on "no data" would end the wait at
  different members in the two modes. The single-root measurements below have no empty
  files, so this narrowing doesn't move them. Both modes can
  do this without buffering data: a forward walk reads only headers in between, and an
  indexed read looks ahead in its index. The lookahead ends early, and the waiting
  entries decode with the evidence met so far, at the first of:
  - the end of the archive, or damage that ends the walk;
  - the freeze;
  - 64 waiting directories, whether or not their names are valid UTF-8. Only names
    that are not valid UTF-8 count towards the freeze, so without this bound a
    legacy-named directory followed by a million ASCII directories would hold a million
    headers;
  - a listing cap (`ListingLimits`). Every member the lookahead reads is charged to the
    listing tracker as it is today, including the waiting ones. When the next member
    would cross a cap, the waiting entries are decoded and listed, and then the cap
    raises `ResourceLimitError` at that member, as it does now. So the lookahead never
    parses a header that today's walk wouldn't parse: a TAR walk with `max_members=5`
    still reads at most 6 headers.

  ZIP, TAR, RAR and ISO do the wait in their own readers. For the plugin-shaped formats
  (cpio, ar, LHA, ARJ, CAB and the rest) and third-party plugins, the adapter does it,
  so no plugin has to:
  - `decode_name` writes the whole-name memo at the first decode, as everywhere else,
    so a plugin that compares names before it yields them (CAB's repeated-name check)
    sees one text per byte string. It also records the guess each name was decoded
    with. Only the directory-prefix memo waits: a prefix's text is written when a
    member under it is listed. Until then, a decode reads the prefix memo and decodes
    what it lacks with the current guess.
  - When a plugin yields a directory member whose `name` is the text `decode_name`
    returned for its `raw_name`, or that text with `\` turned into `/` (what CAB and LHA
    do), the adapter holds it. It charges it to the listing tracker, as `hold()` does,
    and keeps the plugin's walk going.
  - When the wait ends, the directory agrees with the member that ended it. If that
    member's `raw_name` lies under the directory's, the directory takes the text that
    member's `name` gives that prefix, so the two stay one tree even when the plugin
    joined the child's path from the directory's first text (XAR builds its table
    before it yields anything). Otherwise the adapter decodes `raw_name` again with the
    guess recorded for that member's name, and makes the same `\` change if the plugin
    made it. The listed text replaces the directory's whole-name memo entry. At the
    freeze, at 64 waiting directories or at the end, the current guess is used. At a
    cap, the adapter lists the waiting directories first, and then raises as it does
    now.
  - A directory whose name the plugin built in some other way (joined from parts, or
    normalised) doesn't wait. It keeps the text `decode_name` gave, as with the
    directory rule alone.

  `decode_text` keeps the guess as of the last `decode_name` call, so a directory's own
  text, such as a comment, uses the evidence up to its header, as before. A plugin calls
  nothing new, and `hold()` keeps its current meaning.

  In TAR and the other formats that list by walking, the end and damage come at the
  same point in both modes. In ZIP they don't: a seekable read lists from the central
  directory and keeps a member whose local header is damaged, while a pipe walk loses
  it. Then a waiting directory can take its evidence from different members in the two
  modes, and every name after the damage can differ too, because the pipe's evidence
  lacks the lost name. The spec states this as an exception, under DR-5a: malformed
  corner cases may differ a little. A cap can come before the next entry that is not a
  directory, and then the directories just before it decode with less evidence than in
  an unlimited listing. The spec states this as an exception too.

Why this rule:

- **Streaming matches random access** (DR-5). A forward walk and an indexed listing meet
  the same names in the same order. TAR, cpio, ar, LHA and ARJ write names in walk
  order, and the ZIP central directory lists entries in local-header order. So both
  reads give the same names. The only lookahead is over directory entries, which have
  no data, so no reader buffers member data, which a TAR stream can't do within its
  memory bound.
- **Damage and caps change no name already final.** A walk that ends early, by damage
  or by a listing cap, stops adding evidence there, and a cap raises as it does today.
  The directories waiting at that point decode with the evidence met before it, so
  their names can differ from a whole, unlimited listing. Every other name listed
  before that point is final. The spec states this as one exception. A damaged ZIP
  local header is another.
- **Order of calls doesn't matter.** Thanks to the memo, a re-walk, a `get()`, or a
  second `members()` never sees a different decode for bytes it already decoded. A
  plugin directory that waited is listed once, with its final text, before any caller
  sees it.
- **Bounded cost.** Evidence stops at 256 names, and the wait at 64 entries and at the
  listing caps. Accuracy plateaus by about 10 names.

The cost: early names get less evidence than a whole-archive guess would give them. The
first legacy name is decoded on its own evidence (the N=1 column: right 61-94%,
otherwise abstains, wrong at most 1%). By the third name the guess matches the
whole-archive guess in 92-100% of archives.

Early names are mostly directories, the parents of later names, because TAR, 7-Zip,
WinRAR and most ZIP writers put `資料/` before `資料/報告書.txt`. Without the directory rule,
an abstaining first guess would list a folder `╕Ω«╞/` with no children, next to children
under a `資料/` that has no entry. The tree would split in two on extraction. With the
directory rule alone, the tree stays whole, but the root folder of a single-folder
archive, the most common layout, keeps the text of a guess made from its own name. A
one-character root (`新/`) always abstains, because of the 2-character minimum. The wait
for the next entry that is not a directory fixes most of that. It gives the root the
evidence of its first file too. Measured on single-root archives (a root folder entry
first, then 3 or 10 files under it; `single_root.py` in the investigation), as the share
of archives whose every path comes out right:

| Codec | Root name | Whole-archive guess | Directory rule alone | With the wait |
| --- | --- | --- | --- | --- |
| cp932 | realistic | 100 | 89-91 | 98 |
| cp932 | 1-4 characters | 100 | 47-48 | 95-97 |
| EUC-JP | realistic | 100 | 83-89 | 93-98 |
| EUC-JP | 1-4 characters | 100 | 19-22 | 90-94 |
| GBK | realistic | 99-100 | 73-78 | 91-94 |
| GBK | 1-4 characters | 99-100 | 26-32 | 86-87 |
| Big5 | realistic | 92-93 | 51-52 | 82-85 |
| Big5 | 1-4 characters | 90-93 | 21-24 | 76-78 |
| cp949 | realistic | 100 | 83-85 | 99-100 |
| cp949 | 1-4 characters | 100 | 15 | 95-96 |

The rest of the gap to the whole-archive guess is the price of DR-5: getting it would
mean buffering member data on a stream. In the archives that don't come out right, the
path either keeps today's text (an abstention) or, rarely, has one wrong component. A
caller who knows the codec passes it.

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
- **The directory rule without the wait.** It needs no lookahead at all, but the table
  above shows the root folder decoding wrong or as today in up to 85% of single-root
  archives with short root names.

### 4. Which decodes feed the evidence

Only the decode that produces a member's `name` adds evidence. Some decodes only compare
or annotate:

- the name read only for comparison: ZIP's local-header name in a seekable read
  (`MEMBER_LOCAL_NAME_DIFFERS`), and the central directory's names that a forward walk
  meets at the end of a pipe;
- link targets;
- comments, including the archive comment, which `ArchiveReader.info` may decode before
  or after the listing;
- user and group names, and RAR's alternate names.

These read the memo, including the directory-prefix memo. They add no evidence and write
nothing to the memo. Their guess is fixed by the text's place in the archive, not by the
time of the call: it is the guess as of the member whose header holds the text, the
evidence up to and including that member's name. A plugin decodes a member's text while
it parses that member, as every built-in does. Text that belongs to no member, such as
ARJ's main-header archive comment, which `info` decodes whenever the caller reads it,
uses no guess and decodes as without `"auto"`. So the listing alone fixes the guess and
the memo, and the order of calls changes neither a member name nor a text: an ARJ
archive comment reads the same before and after the listing. The cost is that an
archive comment is never guessed, even in an archive whose names are. Which name
is the member name depends on the read. In a seekable ZIP it is the central directory's
name. In a forward walk (a pipe) it is the local header's name, because that walk builds
each member from its local header. The two give the same evidence when the central
directory lists the entries in local-header order, which is how every writer measured
writes them.

Link targets need one more rule. Reading the memo makes a link target that names a
member met earlier decode to that member's text, whole or by directory prefix. TAR hard
links only point backwards, so they always resolve. A symbolic link met before the
freeze that names a member met after it gets the guess at the link's position, and the
member gets the guess at its own. If the guess changed between the two, the link
doesn't resolve, and a member that names a missing target reports what it reports
today. Measured, the guess matches the whole-archive guess from the third legacy name
on in 92-100% of archives, so this needs a forward link among the first few names.
**Rejected:** resolving links by their stored bytes. Link targets are normalised as
text (relative paths, `..`), so every resolver would need a second, byte-level path for
one rare case. The case is pinned by a test (task 4.7).

ZIP stores a symbolic link's target as the member's data, and reads it today as UTF-8
with `surrogateescape` (`base_reader.py`, the ZIP link-target read), outside the name
decoder. This change sends it through `decode_text` under every `encoding=`. Valid UTF-8
still wins, so a target that reads today as UTF-8 doesn't change. A cp932 target in a
cp932 ZIP then resolves to its cp932-named member, under `"auto"` and under an explicit
`encoding="cp932"` alike. Today it resolves under neither.

Plugins tell the two kinds apart through two methods (format-plugins spec):
`ReaderContext.decode_name(raw)` decodes a member name and adds evidence, and
`ReaderContext.decode_text(raw)` decodes any other stored text with the same guess and
memo, and adds none. The built-in callers that decode link targets, comments, and user
and group names switch to `decode_text`: ARJ, LHA, SquashFS and RPM. Without `"auto"`
the two methods decode the same way.

LHA stores a symbolic link as one field, `name|target`, and splits it after decoding.
The bytes can't be split on `|` first, because 0x7C is also a trail byte: `ポ` is
`83 7C` in cp932, and `倒`, `培`, `弓` (cp932) and `四`, `咽` (Big5) end in it too. So
a third method, `ReaderContext.decode_name_and_target(raw, separator)`, decodes such a
field. It splits at the first separator that falls at a character boundary of the codec
the field decodes with, and returns the name and the target, or `None` for the target
when there is no separator. Only the name part adds evidence. Each candidate codec
finds its own split when the guesser scores it, so the evidence is never a name with a
target attached.

**Rejected:** a keyword, `decode_name(raw, *, evidence=False)`. It is easy to leave out,
and the default would then be the wrong kind for every comment. **Rejected:** feeding
link targets too. They would give more evidence, but a TAR stream meets a link target at
a different point than the listing does in some readers, which reopens the question
decision 3 settles.

### 5. One decoder per reader, shared by built-ins and plugins

A new module, `internal/name_encoding.py`, holds:

- `guess_cjk(evidence)`, a pure function;
- `NameDecoder(encoding, fallback)`, which holds the evidence, the memo and a lock.
  Readers under `concurrent_operations=True` decode from several threads.
- The frequency tables, as package data of about 12 KB. A committed script rebuilds them
  from Wikipedia titles (decision 9).

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
answer is the worst failure), and it needs a dependency decision. chardet 7.7.0's
package metadata says 0BSD and Python 3.10 or later, and it installs as 3.3 MB. The
follow-up change checks its licence history with sources before adding it. All of that
belongs in its own change, after this one ships. **Rejected:** a hand-written
single-byte rule (letters plus casing). It was right on Cyrillic, but it was 0-100%
wrong on Hebrew and Turkish.

### 7. ISO: the Joliet name comes before the guess

ISO falls back from a Rock Ridge name that is not UTF-8 in this order: UTF-8, then
`encoding=`, then the Joliet twin's name, then UTF-8 with `surrogateescape`
(`iso_reader._decode_bytes_name`). Under `"auto"` the order is UTF-8, the Joliet twin,
the guess, and then today's fallback. The Joliet name is text the image's writer
converted from the same name. That is evidence from the archive itself, which outranks a
statistical guess (DR-7, DR-1). An explicit codec keeps its place before Joliet, because
it is the caller's knowledge, not a guess. A name taken from Joliet adds no evidence,
because the guess never decoded its bytes. **Rejected:** the guess before Joliet, in the
place of `encoding=` today. It would replace a converted name with a guess, and the
`_ascii_runs_match` check that pairs the two names does not catch a twin that differs in
its non-ASCII part.

### 8. Reporting

Each name decoded with a guessed codec reports `MEMBER_NAME_ENCODING_INFERRED`, with
`inferred_encoding` set to the guess. `declared_encoding` is the codec the name would
otherwise have had: for ZIP the configured fallback, and for the formats whose fallback
is UTF-8 with `surrogateescape` (TAR, ISO, the plugin-shaped formats), `"utf-8"`. The
code stays in `ARCHIVE_INTEGRITY_CODES`, so STRICT refuses an archive whose names needed
a guess. This is the same rule as for the UTF-8 sniff today, and "STRICT" means no
guessing. A caller who wants both STRICT and CJK names passes the codec. No new code and
no new context field are needed.

## Risks / Trade-offs

- [The tables come from Wikipedia titles, which lean towards proper nouns] → Accuracy is
  measured on held-out titles. Real file names use more everyday characters, which
  should only help. Article text is the fallback if real false positives appear
  (decision 9).
- [A wrong guess gives a wrong name, which DR-1 ranks worst] → The guess abstains unless
  one codec wins clearly. Measured wrong rates are at most 1% on CJK at N=1 and 0.1% on
  Latin archives. The diagnostic names the guess and keeps `raw_name`, so a caller can
  re-decode.
- [Early names decode on less evidence than later ones, and a root folder's text holds
  for the whole archive] → The wait for the next entry that is not a directory gives the
  root the evidence of its first file: 76-100% of single-root archives come out right on
  every path, against 90-100% for a whole-archive guess (decision 3). The rest is
  accepted for DR-5. A caller who knows the codec passes it.
- [A symbolic link met before the freeze that names a later member may not resolve] →
  Accepted and pinned (decision 4).
- [An archive comment is never guessed] → It belongs to no member, so it has no place
  in the evidence order. Guessing it at the time of the call would make it depend on
  whether `info` is read before or after the listing (decision 4).
- [A ZIP whose central directory lists entries in a different order from its local
  headers] → Then a forward walk and a listing meet the names in different orders. The
  names met before the freeze may decode differently, and so may every name under a
  directory first met before the freeze, because the directory keeps the text it got
  then. The spec states this as the one exception to equal names in both modes. Tests
  pin both the common case and the exception.
- [Thread safety] → The `NameDecoder` lock covers the evidence and the memo until the
  freeze. After it, a decode reads only the frozen guess and the memo, which no longer
  change, so it takes no lock.

### 9. The frequency tables come from Wikipedia titles

The tables are the top-1000 characters per language from Wikipedia article titles, as
measured. A committed script rebuilds them from a pinned dump date, and a one-line
provenance note sits next to the data (task 1.2). davi chose this on 2026-11-19, after
the round-1 reviewer recommended it. It is the only source with measurements behind it,
and Korean needs a frequency corpus either way. **Rejected:** national standard lists
(Jōyō kanji, 通用规范汉字表 level 1, 常用國字標準字體表, KS X 1001 hangul). They are
unranked sets of 2000-3500 characters, and a larger set narrows the margin between the
codecs that share the EUC byte layout. Every number in this design would have to be
measured again. **Deferred:** Wikipedia article text instead of titles. It is worth
trying only if real-world false positives appear.
