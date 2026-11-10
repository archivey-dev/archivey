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

Neither has magic, so the checks run as `StreamCodec.header_check` (on every source, inside the
first window, reported as `PROBABLE` from a content test, like the v7 tar header check) and as
content probes (only for a name that claims the format):

- **uuencode by magic:** `begin` at offset 0, a mode of 3 to 6 octal digits, a name, and a next
  line that is a valid encoded line. For `begin-base64`, that line must also be at least 40
  characters, end in `=`, or be followed by `====`, since one short word is base64 characters
  too. A `begin` line followed by prose does not pass.
- **uuencode by name:** the same, but the `begin` line may come after other text (mail and news
  headers). Without the name, leading text is not searched: a README that shows a `begin` line
  as an example must not become a uuencoded file.
- **base64 by magic:** at least four full lines of one length (40 or more, a multiple of 4), all
  alphabet characters, whose decoded bytes hold a known format's exact magic. Hex digits and
  plain identifiers are base64 characters, so the line shape alone would claim hex dumps and
  ID lists; the decoded magic is what makes it safe. gzip's and `.Z`'s magics are two bytes
  each, so base64 of random bytes passes about once in 32 768 files, and such a file is still
  base64. Neither check is a signature, so neither is reported as `CERTAIN`.
- **base64 by name:** the line shape alone, or one long line (`base64 -w0`) that mixes letter
  cases or digits.

## Limits

- Only the first uuencoded file of a source is read; a second `begin` after the first `end` is
  trailing data.
- Neither format has a checksum.
- The base64 decoder skips line breaks only, so a line of prose (with a space) after unpadded
  base64 fails. A single trailing word with no space cannot be told from data and decodes as
  more of the file.
- A uuencoded line is decoded only as far as its length character declares, so the checksum
  character some old encoders add after it is ignored, as libarchive does.
- A zero-byte `.b64` file is the encoding of an empty file and reads as one.
