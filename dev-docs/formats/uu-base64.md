# uuencode and base64

Code: `src/archivey/internal/streams/codecs/text_codecs.py` (its module docstring holds the
format details). Tests: `tests/test_text_codecs.py`.

## What they are here

Text wrappers, not compressors, presented as single-file stream formats (`StreamFormat.UU`,
`StreamFormat.BASE64`) so they nest like one: `x.tar.uu` lists the tar. libarchive reads the
same two as its `uu` filter. yEnc, BinHex and quoted-printable were weighed and left out: yEnc
posts are split across many articles, BinHex carries a Mac resource fork, and quoted-printable
encodes mail text, not files.

## Detection, and why it is shaped this way

Neither has magic, so the checks run as `magic_behind_prefix` walks (on every source, inside
the first window) and as content probes (only for a name that claims the format):

- **uuencode by magic:** `begin` at offset 0, a mode of 3 to 6 octal digits, a name, and a next
  line that is a valid encoded line. A `begin` line followed by prose does not pass.
- **uuencode by name:** the same, but the `begin` line may come after other text (mail and news
  headers). Without the name, leading text is not searched: a README that shows a `begin` line
  as an example must not become a uuencoded file.
- **base64 by magic:** at least four full lines of one length (40 or more, a multiple of 4), all
  alphabet characters, whose decoded bytes hold a known format's exact magic. Hex digits and
  plain identifiers are base64 characters, so the line shape alone would claim hex dumps and
  ID lists; the decoded magic is what makes it safe. gzip's magic is two bytes, so base64 of
  random bytes passes about once in ten thousand files, and such a file is still base64.
  Detection reports this as magic (`CERTAIN`), like the zstd skippable-frame walk.
- **base64 by name:** the line shape alone, or one long line (`base64 -w0`) that mixes letter
  cases or digits.

## Limits

- Only the first uuencoded file of a source is read; a second `begin` after the first `end` is
  trailing data.
- Neither format has a checksum.
- A zero-byte `.b64` file is the encoding of an empty file and reads as one.
