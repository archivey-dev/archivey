# makeself

Current maintainer truth for makeself archives, the `.run` installers. A makeself
archive is a shell script that states where its payloads start, followed by those
payloads: one or more compressed TARs. archivey parses the script and never runs it,
then reads each TAR in one forward pass, from a pipe too. The reader is written against
`archivey.formats` and registered as a built-in the way RPM is; it uses one internal
hook, for the payload digests (§3).

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/makeself_reader.py`, a `MakeselfHandler` (`SequentialFormatHandler`) and a `MakeselfReader` (`SequentialReader`), registered from core's format table |
| Versions | makeself 2.2.0 and later (fixtures from 2.2.0, 2.4.0, 2.4.5 and 2.7.1) |
| Source | A file, a stream that can seek, or a pipe (`pipe=True`) |
| Listing cost | `REQUIRES_DECOMPRESSION`: each payload is a compressed TAR |
| Access cost | `SOLID` |
| Compressors | gzip, bzip2, xz, zstd, lz4, lzop, bzip3, Unix compress, none; base64 over any of them |
| Encryption | openssl AES-256-CBC read with `password=` (PBKDF2 since 2.6.0, `EVP_BytesToKey` before; `cryptography`); gpg refused by name |
| Checksums | The header's CRC (POSIX `cksum`), MD5 and SHA-256 of each payload's stored bytes, all that are stated, as a check over the payload's files |
| Name encoding | The TAR's: UTF-8 first, then `encoding=`, then escaped |
| Spec | `openspec/specs/format-makeself/`; rulings in `openspec/changes/archive/2026-11-17-makeself-format/design.md` |

Not here: the startup script is reported (`makeself.script`), never run; the gpg
signature (`--sign`) is reported (`makeself.signed`), not checked; the license text and
help header are not exposed.

## 1. Shape

From `makeself-header.sh` at each release tag:

- **Line 1** `#!/bin/sh`, **line 2** `# This script was generated using Makeself
  <version>`: the magic, the same since 2.2.0. 2.6.0's header says `2.5.0`.
- **The variable block**, before the first function (`MS_Printf()`): `CRCsum`, `MD5`,
  `SHA` (2.4.0+), `label`, `script`, `licensetxt`, `targetdir`, `filesizes`,
  `totalsize` (2.4.x+), `decrypt_cmd` (2.4.2+), `skip` (2.4.2+), `SIGNATURE`. Values
  are double-quoted; `licensetxt` is escaped by makeself and may span lines; `label`
  and `scriptargs` are not escaped.
- **The header is `skip` lines.** 2.4.2+ state `skip="N"`; 2.2.0 to 2.4.0 write N into
  each ``offset=`head -n N "$0" | wc -c | tr -d " "` `` line of the script.
- **The payload command** is the one the script pipes each payload through:
  `| eval "gzip -cd" |` before 2.4.2, `MS_Decompress()` after (`eval "$decrypt_cmd"`
  then the compressor).
- **Payloads** follow back to back, sizes in `filesizes`. Several payloads only from
  2.2.0 to 2.4.0, one per `--append`; 2.4.2+ `--append` rewrites the one payload.
- **Digests** list one value per payload, over the payload's stored bytes (after
  encryption or encoding): `CRCsum` decimal (`0000000000` for none), `MD5` and `SHA`
  hexadecimal (all zeros for none).
- **Encryption.** 2.2.0 to 2.4.0 had base64 (`base64 -d -i`), gpg (`gpg -d`) and openssl
  (`openssl aes-256-cbc -d -a`) as compressors over the plain TAR. 2.4.2+ apply them
  after compression and name the command in `decrypt_cmd`; `-pbkdf2` since 2.6.0.
  openssl's output is `Salted__`, an 8-byte salt, then AES-256-CBC with PKCS#7 padding.
  The key and IV come from PBKDF2-HMAC-SHA256 (10 000 rounds) with `-pbkdf2`, else from
  one round of `EVP_BytesToKey` with `-md`'s digest; with no `-md` (2.4.2 to 2.5.0
  `--ssl-no-md`) the digest was openssl's default, MD5 before openssl 1.1.0 and SHA-256
  after, so both are tried. The old `openssl aes-256-cbc -d -a` compressor is the
  EVP form, base64-armored, over the plain TAR. The digests cover the ciphertext.
  A password is taken when the first decrypted bytes start the compressor's stream
  (its magic) or, uncompressed, a TAR header whose checksum matches; the padding is
  checked when the walk reaches the payload's end.

## 2. The pipeline here

### 2.1 Identify

By the magic at offset 0, nothing else: no extension (other installers use `.run`) and
no scan. A forced other format on a makeself file fails at byte 0 as on any non-archive,
and `core._name_makeself` adds to its `CorruptionError` that the file is a makeself
archive (a seekable source only: a pipe's first bytes are gone).

### 2.2 Parse the header

The header is read in 16 KiB chunks until `skip` lines are in, bounded by
`max_metadata_bytes` alone; what was read past it starts the first payload.
`_VariableParser` reads the block as shell double-quoted assignments only, so text
inside a value (a license holding `skip="3"`) is never taken for a variable. It goes on
from where the last chunk stopped (`_LineCounter` likewise for the `skip` lines), so a
hostile header costs time linear in its length, and it keeps only the variables in
`_USED`, so memory does not grow with it. Its patterns repeat possessively (`*+`), since
a repeated alternation keeps about 150 bytes of backtracking state per byte of a value.
A used variable assigned twice, or given a plain `NAME=` where the parse does not read
assignments (an indented line, after a `;` or `export`, after another value on its
line), text with a quote after a value, numbers that are not numbers, digests of the
wrong length or count, `totalsize` not the sum of `filesizes`, old offset lines
that disagree, and payload commands that differ are `CorruptionError`. A command
archivey does not know is `UnsupportedFeatureError` naming it. More payloads than
`max_members` is `ResourceLimitError`, counted before the list of sizes is built: each
payload builds a TAR reader, which costs far more than the bytes of header that list it,
and an empty one adds no member to count. The `NAME=` check catches a header edited by
hand or by a careless tool. It is not every way the shell sets a variable (`for`,
`read`, `eval`, `${NAME:=…}`), so the script can still read its payloads another way
than archivey does: §4, first row.

### 2.3 Read the payloads

Each payload is a `_Payload` stream (left-over header bytes, then `ForwardStream.take`),
which feeds the digests as it is read, base64-decoded by `_Base64Reader` when the header
says so (text after a padded group decodes on, as GNU `base64 -d -i` does), and handed
to `ReaderContext.open_nested` as a TAR in the payload's compressor. After the TAR's
last member the rest of the payload is read for the digests. Bytes after the last
payload that are not zero are `ARCHIVE_TRAILING_DATA`.

## 3. The payload digests

Each digest covers the stored bytes of every file in its payload's TAR: a check over
several members, as a 7z folder CRC or a `.tar.gz` trailer is. The reader asks the
adapter for a `SpanningCheck` (`ReaderContext._spanning_check`, internal) per payload
with a stated digest, `cover()`s each member before yielding it, and calls `passed()`
or raises `failed()` at the payload's end. Covered files have `verifiable=CHECKSUM` from
listing; a pass raises them all; a failure is kept in `_spanning_unreachable` under the
payload's key, so every later `verify_all()` returns each covered file with it until a
walk passes the check. An encrypted payload's files are covered with
`proves_data=False`: the digests are over the ciphertext, and the key is only
`INCONCLUSIVE`, so a mismatch still makes them failures, but a pass sets no
`CHECKSUM` level. The POSIX `cksum` CRC is CRC-32 MSB first, computed with
`binascii.crc32` over bit-reversed bytes (`_Cksum`).

## 4. Sharp edges

**format** — inherent · **library** — upstream's · **archivey** — ours.

| What you see | Where | More |
| --- | --- | --- |
| The listing is what the TARs hold, not what running the script does | **format** | Threat model §4 "A self-extracting archive's stub is not run" |
| An old archive lists `.` as a directory member | **format** | makeself before 2.4.2 tars `.` itself |
| A 2.4.x header whose `--help-header` text holds `NAME=` for a variable the reader uses (`label=`, `skip=`) is refused | **archivey** | That makeself writes `helpheader='…'` single-quoted, which the parse does not read as a value, so its lines are checked for a hidden `NAME=` (§2.2) |
| gpg payloads are refused | **archivey** | Decided 2026-11-08: no OpenPGP implementation here |
| A wrong password is told from the first decrypted bytes; damaged padding only at the payload's end | **format** | §1 "Encryption" |
| The first password whose first block passes is taken, with no later check among candidates; a wrong one passes about once in 2^24 (2^19 for a Unix compress payload) and then fails as damage | **archivey** | The magic check is the only one before the walk |
| A member is `CHECKSUM` only after the walk reaches its payload's end | **format** | The digest is over the whole payload |

## 5. Decisions

The maintainer's rulings of 2026-11-08 are in
`openspec/changes/archive/2026-11-17-makeself-format/design.md`: a format of its own
rather than the inner `TAR_GZ` with `prefixed=True`; the header parsed, not scanned;
every payload listed; a forced other format refused, naming makeself; every stated
digest checked; makeself 2.2.0 and later.
