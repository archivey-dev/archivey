## MODIFIED Requirements

### Requirement: Decode ZIP member bodies through the shared codec layer

The ZIP backend SHALL decode unencrypted member data through the shared
`compressed-streams` codec layer rather than stdlib `zipfile`'s internal
decoders. It SHALL locate a member's raw compressed bytes via a bounded
local-file-header parse (fixed header + local name/extra lengths, with an
absurd data-offset cap) and a slice over the source, then dispatch by ZIP
method id to the codec's default backend.

Member reads SHALL verify `member.hashes["crc32"]` through the shared
`VerifyingStream` when a CRC is surfaced. A corrupt member body SHALL raise
`CorruptionError` (or `TruncatedError` when the payload is cut short) via the
shared translation. Traditional ZipCrypto and WinZip AES (method 99) members
SHALL decrypt natively (see below) and then feed the codec layer. A ZipCrypto
member SHALL seek under `seekable_members=True`: a backward seek restarts
decryption from the member's start, a forward seek decrypts what it skips, and
`AUTO` accelerators stay off over the decrypt stage. A WinZip AES member SHALL
seek too: CTR restarts at the target's block (counter `1 + offset // 16`). A
seek SHALL NOT give up the HMAC, whether the caller or an accelerator made it:
the HMAC covers the ciphertext, so the read that returns the member's last byte
SHALL complete it by reading, without decrypting, the ciphertext the seeks
skipped, and raise `CorruptionError` on a mismatch. A read that stops short of
the end gives no verdict.

Codec settings 7-Zip writes or names but this reader cannot decode SHALL raise
`UnsupportedFeatureError`, not `CorruptionError`. An LZMA (method 14) member whose
properties byte is a valid `lc`/`lp`/`pb` triple with `lc + lp` over 4 (`7z a -tzip
-mm=LZMA:lc=8`; liblzma decodes up to 4) is one, decided by the same check as a 7z LZMA
coder; a properties byte of 225 or more stays `CorruptionError`. A PPMd (method 98)
member with restore method 2 is another (7-Zip: "Unsupported Method"); a restore method
above 2 SHALL raise `CorruptionError` (7-Zip: "Data Error"). Under ZipCrypto these
settings are decrypted data, so both SHALL raise `CorruptionError` there, which the
password confirmation counts as the candidate failing (see below).

A member's compressed data SHALL be one stream of its codec and nothing else, as 7-Zip
23.01 reads it (DR-3). A byte of it the codec leaves after the stream's end, a zero
byte too, and a further stream there, SHALL raise `CorruptionError`
(`DataAfterEndError`) once the output before it is read, whatever the declared size and
CRC cover, for every method and for encrypted members too, with an accelerator on or
off, except as `compressed-streams` allows for rapidgzip on a DEFLATE member (a second
stream that holds the last point of rapidgzip's index, with a size and CRC that cover both, reads as
both); under ZipCrypto the password confirmation counts it as the candidate failing, as
above. The exception is a Zstd member: RFC 8878 defines Zstd data as one or more
frames, so every frame, skippable ones too, SHALL be read as a `.zst` file's are
(`compressed-streams`), and only bytes after the last frame that start no frame SHALL
raise. An LZMA member without the end-marker flag (general-purpose bit 1) and a PPMd
member end at their declared size: their input SHALL end there too (after an end marker
right at that size for LZMA, and after PPMd8's end mark, which a member SHALL carry),
so a declared size short of the stream's data SHALL raise `CorruptionError`, not
`TruncatedError`. One zero byte after LZMA data without an end marker reads, as 7-Zip's
encoder sometimes flushes it past the decoder's last read.

#### Scenario: ZIP codec-layer decoding

| Case | Expected |
| --- | --- |
| STORED / DEFLATE / BZIP2 / LZMA member, unencrypted | Decodes via the shared codec layer; CRC verified through `VerifyingStream` |
| LZMA member with compressed data after its end marker (a second stream, or one zero byte), whatever the declared size covers | `CorruptionError`, as 7-Zip reports "Data Error" |
| LZMA member without an end marker (bit 1 clear), with junk after its data or a declared size 1000 bytes short of it | `CorruptionError`, not `TruncatedError` (7-Zip: "Data Error") |
| PPMd member with junk or zero bytes after its end mark, a declared size 1000 bytes short of its data, or no end mark | `CorruptionError`, not `TruncatedError` (7-Zip: "Data Error") |
| DEFLATE, Deflate64, BZIP2 or Zstd member with junk or zero bytes after its stream (after its last frame for Zstd), or a DEFLATE, Deflate64 or BZIP2 member with a second stream, accelerator off or on | `CorruptionError` (7-Zip: "There are some data after the end of the payload data") |
| DEFLATE member with a second stream that holds the last rapidgzip index point, declared size and CRC covering both, `use_rapidgzip=ON` | Decodes both streams; with the accelerator off, `CorruptionError` |
| Zstd member with a second frame or a skippable frame after its first, declared size and CRC covering all of it | Decodes every frame, as a `.zst` file does; a declared size or CRC that stops at the first frame raises `CorruptionError` |
| DEFLATE64 (method 9) member, `inflate64` backend present | Decodes; absent backend → `PackageNotInstalledError` |
| ZSTD (method 93) / PPMD (method 98) member, backend present | Decodes; absent backend → `PackageNotInstalledError` |
| Unsupported/unknown method id | `UnsupportedFeatureError`; no guessed output |
| Corrupt member body | `CorruptionError` / `TruncatedError` |
| LZMA member, `lc + lp` over 4 (`-mm=LZMA:lc=8`) | `UnsupportedFeatureError` naming `lc` and `lp` |
| PPMd member, restore method 2 / 3–15 | `UnsupportedFeatureError` / `CorruptionError` |
| Encrypted ZipCrypto member, any of the methods above | Decrypts natively, decodes via the codec layer; CRC verified through the fused verifier |
| ZipCrypto or WinZip AES member, `seekable_members=True` | Seeks backward and forward; content matches a sequential read |

