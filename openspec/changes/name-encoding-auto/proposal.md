## Why

Older tools stored member names in the local code page and recorded no encoding. Today
archivey decodes such a name as UTF-8 when the bytes are valid UTF-8. Otherwise it uses
`encoding=` or the format's default, such as cp437 for ZIP. A caller who doesn't know
the encoding gets mojibake for every Japanese, Chinese, Korean or Russian name.
Measurements show that the bytes identify CJK encodings reliably, and that a check
written in archivey can do it with no dependency (see design.md, Investigations).

## What Changes

- `open_archive(encoding="auto")` asks archivey to guess the codec of names that are not
  valid UTF-8. It applies wherever a format reads `encoding=` today. Valid UTF-8 still
  wins, and an explicit codec name keeps its current meaning.
- The guess covers cp932 (Shift_JIS), EUC-JP, GBK, Big5 and cp949 (EUC-KR / UHC). It is
  built in (zero-dependency core) and uses small character-frequency tables, about 12
  KB. If no codec wins clearly, the guess abstains and the name decodes as it does
  without `encoding=`. Latin code pages are never guessed.
- A guess is made from the legacy names met so far, in archive order, up to the
  first 256. Each distinct stored name is decoded once per reader. So the same bytes
  give the same names in streaming and non-streaming reads (design.md, decisions 3 and
  4). A directory waits for the next member that is not a directory before it is
  decoded, within the listing caps.
- Each name decoded with a guessed codec reports `MEMBER_NAME_ENCODING_INFERRED`. The
  `inferred_encoding` field holds the guess, and `declared_encoding` holds the codec the
  name would otherwise have had. STRICT refuses it, as it refuses every inferred name
  today.
- Plugins: `ReaderContext.decode_name()` applies the guess and adds the name to its
  evidence. A new `ReaderContext.decode_text()` decodes other stored text (link targets,
  comments, user names) with the same guess, adds nothing and fixes no text. A new
  `ReaderContext.decode_name_and_target()` splits a field that holds both, such as
  LHA's `name|target`, at a character boundary. `ReaderContext.encoding`
  is `None` under `"auto"`, so a plugin that decodes with it never sees `"auto"`.
- A directory's path keeps one text per reader, so a directory and its children never
  split into two trees. ISO takes a Rock Ridge name's Joliet twin before the guess.
- Not in this change: guessing Cyrillic, Greek or Hebrew code pages. That needs
  statistics (an optional `chardet` extra) and is a follow-up change (design.md,
  decision 6).

## Capabilities

### New Capabilities

### Modified Capabilities

- `archive-reading`: `encoding=` accepts `"auto"`.
- `format-plugins`: `ReaderContext.decode_name()`, the new `ReaderContext.decode_text()`
  and `ReaderContext.decode_name_and_target()`, and `ReaderContext.encoding` under
  `"auto"`.

## Impact

- New module `src/archivey/internal/name_encoding.py`: the guesser and the per-reader
  name decoder, plus the frequency tables as package data.
- The name decoding of ZIP, TAR, RAR and ISO (each holds `self._encoding`) moves to the
  shared decoder. Plugin-shaped built-ins (cpio, ar, RPM, deb, makeself, SquashFS, CAB,
  XAR, LHA, ARJ) get it through `ReaderContext.decode_name()`.
- `check_encoding` accepts `"auto"`. fsspec passes `encoding=` through unchanged. The
  CLI has no `--encoding` option today, and this change doesn't add one.
- Docs: `docs/opening.md` §"Names in other encodings", the format pages' name sections.
- Tests: guesser unit tests on committed name sets, plus one fixture per CJK codec
  through the formats that read `encoding=`.
