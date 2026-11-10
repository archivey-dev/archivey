# Design: makeself

## Maintainer rulings (2026-11-08)

The thread "Support shell-script self-extracting archives" asked these one at a time.

| # | Question | Ruling |
| --- | --- | --- |
| 1 | What a `.run` opens as | Its own format, `MAKESELF`, like RPM and deb. First answered "as other SFX do" (the inner `TAR_GZ` with `prefixed=True`), then reversed for the appended payloads and the checksums, which only a format of its own can use |
| 2 | How the payload is found | Parse the header (`skip`, `filesizes`); no magic scan. A file that does not parse is not opened as makeself |
| 3 | Appended payloads | List every payload's files, in order |
| 4 | `format=TAR_GZ` on a `.run` | Refuse, and name `MAKESELF` in the error. A refusal lists nothing, so it cannot list other contents than detection (the 2026-11-07 parity ruling) |
| 5 | Which header checksums | Every one the header states, as makeself's own check does; a check over several members, like a `.tar.gz` trailer |
| 6 | Other shell installers | The generic `#!` compressor-needle fallback, as its own change after this one; shar stays out (its files are shell text) |
| 7 | Encrypted payloads | Decrypt openssl with `password=`; gpg refuses listing; base64 is read |
| 8 | Versions | makeself 2.2.0 and later |
| — | Threat model | A self-extracting archive's program is not run: an accepted gap |

Settled without a question, stated in the thread: detection at byte 0 from the header;
the header is charged to `max_metadata_bytes`; pipes work; `prefixed=False` and no
`payload_end`.

## What the header looks like

From `makeself-header.sh` at each tag. Line 1 is `#!/bin/sh` and line 2
`# This script was generated using Makeself <version>` in every release since 2.2.0,
which is the magic. The variables come next, before the first function (`MS_Printf()`):

| Variable | Since | Meaning |
| --- | --- | --- |
| `CRCsum` | 2.2.0 | POSIX `cksum` CRC per payload, decimal; `0000000000` for none |
| `MD5` | 2.2.0 | MD5 per payload; 32 zeros for none |
| `SHA` | 2.4.0 | SHA-256 per payload; 64 zeros for none |
| `filesizes` | 2.2.0 | Payload sizes in bytes, space-separated |
| `totalsize` | 2.4.x | Their sum |
| `decrypt_cmd` | 2.4.2 | `openssl enc -aes-256-cbc -d [-salt] [-pbkdf2] [-md sha256]`, `gpg ... -d`, `base64 --decode`, or empty |
| `skip` | 2.4.2 | The header's line count |
| `SIGNATURE` | 2.4.x | A gpg detached signature, base64, when `--sign` was used |

Before 2.4.2 the line count is written into each `offset=`head -n N "$0" | wc -c | tr -d " "``
line instead; they must all agree. The compressor is the command the script pipes a
payload through, `eval "gzip -cd"`, after a `|` or alone in `MS_Decompress`. Every
occurrence must agree.

Several payloads occur only in 2.2.0 to 2.4.0 archives made with `--append`; from 2.4.2
`--append` decompresses the old payload, adds the files with `tar r`, and recompresses.
In 2.2.0 to 2.4.0, base64, gpg and openssl were compressors over the plain TAR; from
2.4.2 they run over the compressed bytes. The digests are over the stored payload
either way, so they can be checked without a password. `-pbkdf2` arrived in 2.6.0.

## Parsing without running

Only the variable block is read as shell: an assignment `NAME="..."` at the start of a
line, its value read as a double-quoted word (backslash escapes, may span lines). That
is what keeps a license text (which makeself escapes) or a help header from faking a
`skip=` line inside it. Text after a value's closing quote may not hold a quote. A
variable assigned twice is damage. After the block, only whole-line patterns are
matched. The header is read in 16 KiB chunks until `skip` lines are in; the bytes read
past it start the first payload.

## The check over several members

A payload digest covers the stored bytes of every file in its TAR, so it is checked the
way a 7z folder CRC or a `.tar.gz` trailer is: the covered files' `verifiable` is
`CHECKSUM` from listing; a pass raises them all; a mismatch raises from the walk and
makes them failures of every later `verify_all()`, until a walk passes it; a walk that
stops before the payload's end leaves them as failures too. A reader written against
`archivey.formats` had no way to say this, so the adapter gives built-in readers a
`SpanningCheck` through `ReaderContext._spanning_check`. It stays internal until a
plugin needs one.

## Alternatives not taken

- Reporting the inner `TAR_GZ` with `prefixed=True`, as for a 7z SFX (ruling 1).
- Scanning for compressor magic after `#!` (ruling 2): it can hit gzip bytes in the
  script, decodes candidates, and cannot name an encrypted payload.
- Claiming `.run` as an extension: other installers use it, and the magic finds every
  makeself archive.
