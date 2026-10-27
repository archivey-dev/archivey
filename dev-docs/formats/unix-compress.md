# Unix compress (`.Z`)

Current maintainer truth for the `compress` format (`.Z`, LZW) as a single-file format and
inside `.tar.Z`. archivey decodes it with its own LZW decoder, adapted from `uncompresspy`,
with no dependency. The format has no end marker, no size and no checksum, so the main
thing to know is what archivey can and cannot say about a damaged or cut file. What `.Z`
shares with the other codecs, the one-member reader, the seek table and the truncation
contract, is on [`single-file.md`](single-file.md). Registers keep the status; this page
states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | `.Z` as a one-member archive and inside `.tar.Z` |
| Write | **Not shipped** |
| Backends | Native: `internal/streams/codecs/unix_compress_decoder.py`, always available |
| Seeking | From the nearest CLEAR code, when the source is seekable. A file with no CLEAR code re-decodes from the start |
| Size | `None`. The format has no size field |
| Digests | None. The format has no checksum |
| Metadata | None beyond the shared fields |
| Truncation | **Best-effort.** About half of the cuts measured on a 16-bit file read as a shorter complete file with no error (§1) |
| Refuses | A header with reserved flag bits set (`UnsupportedFeatureError`); a maximum code width over 16 (`UnsupportedFeatureError`, as gzip and ncompress say "can only handle 16 bits") or under 9 (`CorruptionError`) |

**Three things a reader might expect and will not find.** A cut `.Z` file is not always
reported: the format has nothing that would show the cut. Damaged data decodes to wrong
bytes unless the damage produces an impossible code. And bytes after the data are not
reported as `ARCHIVE_TRAILING_DATA`, as they are for every other codec: with no end
marker they decode as more codes, and usually end in `TruncatedError` (§3).

## 1. Shape

Three properties generate most of this page.

```
header:  1f 9d  flags: block_mode(0x80) reserved(0x60) max_bits(0x1f)
codes:   9-bit codes …, widening by one bit each time the table fills, up to max_bits
         CLEAR (256) in block mode: reset the table to 9 bits, then pad to a group
         boundary
         …                                       ← no end marker, no trailer
```

**The stream ends where the file ends.** There is no end-of-data code, no length and no
checksum. The decoder stops when input runs out. A cut that falls on a code boundary leaves
a shorter file that is exactly as valid as a complete one. The only evidence of a cut is a
partial code left over at the end: bits that do not make a whole code and are not zero.
Once codes are 16 bits wide, every other byte is a code boundary, so about half of all cuts
leave no evidence; measured on a 3.7 MB file of 16-bit codes, 100 of 200 evenly spaced cuts
read with no error, and on a 12-bit file (`compress -b12`), 69 of 200.

**Only CLEAR codes are restart points.** In block mode the writer emits a CLEAR code when
compression gets worse, which resets the table. Decoding can restart at a CLEAR without
anything before it. How many there are depends on the data; a file can have none.

**Codes are packed in groups.** The original `compress` reads codes in groups of eight, so
after a CLEAR, or a width change, the writer pads to the end of the current group. A decoder
that does not skip the same padding reads garbage after the first CLEAR. In block mode a
width lasts a whole number of groups, so only a CLEAR leaves padding. Without block mode
(`compress -C`) the first free code is 256, not 257, so the first width lasts 257 codes and
the widening to 10 bits pads too. The padding after a CLEAR is also where a cut can be
detected even at a code boundary: a source that ends while it is still owed is cut. The
padding at a widening is written only when another code follows, so a stream may end
there with none of it; a stream that ends partway into it is cut.

## 2. The pipeline here

### 2.1 Identify

`.Z` is the magic `1f 9d` at offset 0, reported `CERTAIN`. The inner-TAR probe then decodes
512 bytes and upgrades a match to TAR over `.Z` ([`single-file.md`](single-file.md) §2.1).
`.Z` and `.tar.Z` are the registered extensions.

### 2.2 Open and list

The member has no metadata of its own: `size` is `None`, `modified` is `None`, and `hashes`
is empty ([`single-file.md`](single-file.md) §2.2).

### 2.3 Member data

`UnixCompressDecompressorStream` is `DecompressorStream` over the native LZW decoder
(`LzwState`). The header is checked first: reserved flag bits (`0x60`) are
`UnsupportedFeatureError`, since a writer that set them meant something archivey does not
know; a maximum code width above 16 is `UnsupportedFeatureError` (gzip and ncompress:
"compressed with 17 bits, can only handle 16 bits"), and one below 9 is `CorruptionError`.
Then codes are decoded
forward, with no need to seek, so a pipe reads too (in streaming mode, per
[`single-file.md`](single-file.md) §2.2).

When the source is seekable, each CLEAR code becomes a seek point, and a backward seek
resumes at the nearest one. Consecutive CLEAR codes with nothing between them produce one
point, not several at the same offset.

The decoder raises archivey's errors itself; there is no library exception to translate. An
impossible code (one past the next table entry) is `CorruptionError`. At the end of input,
`TruncatedError` is armed when any of these holds:

- the source ended inside the three-byte header, including a zero-byte source;
- the source ended while CLEAR padding was still owed, or after part of a widening's
  padding;
- bits were left over after the last whole code, and they are not all zero.

Otherwise the data ends there, with no error. As with every codec, sized reads return the
prefix before the error ([`single-file.md`](single-file.md) §2.3).

### 2.4 Extract

Nothing here is `.Z`-specific ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with `ncompress` 5.0, as listed on [`single-file.md`](single-file.md) §3.

| Producer | archivey |
| --- | --- |
| `compress` | Reads |
| `compress -b12` | Reads |
| A file followed by `junk` | `TruncatedError`: the junk decodes as codes and leaves a partial code |
| A 16-bit file cut at 200 even points | 100 `TruncatedError`, 100 read short with no error |
| A 12-bit file cut at 200 even points | 131 `TruncatedError`, 69 read short with no error |
| A zero-byte `.Z` | `TruncatedError` |
| `compress -b9` | Reads, unless the file hit a bug in ncompress 5.0 that writes a code that does not fit in 9 bits. Such a file reads without error but returns wrong bytes, as in `7z` and `unar`; see below |

**9-bit files from ncompress 5.0 can be damaged.** When `compress -b9` fills the table
partway through a string, ncompress 5.0 adds one entry too many, code 512, and can later
write it in 9 bits. Its low 9 bits read as the literal byte 0, and its tenth bit lands in
the next code. Nothing marks the damage, so every decoder reads on: archivey, `7z` and
`unar` return the same wrong bytes. Whether a file is hit depends on the data. The bug
is in the oldest version in ncompress's repository, 4.2.3 (commit `4b59db4`, 1992), which
already sets the 9-bit limit one too high. It was fixed in its repository in February
2021 (commit `3303f31`, "fixed nine bits processing"), after the 5.0 release, and no
release carries the fix yet. A build of that commit writes 9-bit files that archivey,
`7z` and `unar` read back to their input.

ncompress 5.0 and GNU gzip 1.12 refuse every 9-bit file, damaged or not. Their decoders
move to 10-bit codes when the table fills, even when the header says 9, which is the other
half of the same ncompress fix. So their refusal is not evidence against a file.

Without block mode (`compress -C`) no installed tool writes files, so the tests carry
their own encoder, which writes both modes. GNU gzip 1.12 reads its output like archivey at 10 to 16 bits. The
Apple gzip on macOS returned different bytes for the long zero runs, so the tests use
only GNU gzip as the reference.

## 4. Threat surface

`.Z`-specific only; the shared items are [`single-file.md`](single-file.md) §4.

- **Native code, but Python.** The decoder is archivey's own, in Python, and covered by the
  fuzzers; there is no native library to crash.
- **Memory is bounded by the decoder.** The table holds at most 2¹⁶ entries and no header
  field sizes an allocation, but an entry can be up to about 64 KiB long, so storing each
  entry as its full expansion would reach about 2 GiB. A zero run builds that shape, and
  130 KB of crafted input fills it. The decoder stores an entry of up to 256 bytes flat.
  A longer entry is a link to an earlier code plus a tail of up to 128 bytes, rebuilt on
  use by walking the links (about one step per 128 bytes of output). The table stays under
  about 19 MiB in the worst case (18.5 to 18.8 MiB measured on CPython 3.11 to 3.14; up to
  20.3 MiB on a free-threaded build, whose object headers are larger). That is well under
  the `DecoderLimits.max_decoder_memory` default, so that limit is not consulted.
- **Expansion.** Each code emits at most the longest string in the table, so one read's
  output is bounded per call like every codec's ([`single-file.md`](single-file.md) §4).
- **A cut or damaged file can pass.** The format carries no length or checksum (§1). A
  caller that needs to know a `.Z` file is whole must get the length or a digest from
  somewhere else.
- **CLEAR codes make seek points.** A file of back-to-back CLEAR codes would put several
  points at one offset, which the seek table does not allow; empty points are merged, and
  the table is capped like every codec's.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| A cut `.Z` file reads as complete, with no error | **format** | No end marker (§1). Detection is best-effort |
| Damaged data reads with no error | **format** | No checksum |
| Trailing bytes after the data give `TruncatedError` | **format** | They decode as codes (§3) |
| `UnsupportedFeatureError` naming reserved flags | **archivey** | A header bit this decoder does not know; no known writer sets it |
| A backward seek re-decodes from the start | **format** | No CLEAR codes in this file, or a non-seekable source |
| `member.size` is `None` | **format** | No size field |
| A `compress -b9` file reads with no error but returns wrong bytes | **format** | No checksum to show the damage; ncompress 5.0 writes such files (§3) |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Decode with a native LZW kernel adapted from `uncompresspy` (PR #89) | No dependency; forward decoding from a pipe; CLEAR codes as seek points | `uncompresspy` as an extra, which needed a seekable source |
| Refuse reserved flags as unsupported, not corrupt | A writer that set them may have meant a variant; the file is not shown to be damaged | Ignoring them |
| Refuse a maximum width above 16 (PR #128) | 16 is the format's ceiling in `compress` and `ncompress`; a larger width sizes a table no writer makes | Accepting it |
| Report a cut only where there is evidence | Calling every file that ends on a code boundary truncated would refuse every valid file | Guessing |
| A zero-byte source is `TruncatedError` (PR #420) | Every other codec raises on an empty source, and a `.Z` without its header is cut | An empty member |
| Merge consecutive empty CLEAR points (PR #116) | Several points at one offset broke the seek table's invariant | Asserting |

## 7. Open questions

None.

The truncation gap is the format's, not an open question;
[`docs/formats.md`](../../docs/formats.md) tells users it is best-effort.

## 8. Verify

```bash
./scripts/test.sh tests/test_codecs.py tests/test_single_file.py tests/test_detection.py \
    tests/test_audit_tar_streams.py -k "unix_compress or _z_"
```

| Claim |
| --- |
| Reads, from a pipe too |
| Header checks |
| The three kinds of truncation evidence |
| Truncation keeps raising, after a rewind too |
| CLEAR codes are seek points, merged when empty |
| One call's output is bounded |
| The table stays under about 19 MiB, 21 MiB on a free-threaded build (§4) |
| Files written without block mode decode like GNU `gzip -d` at 10 to 16 bits |
| 9-bit files, in block mode with and without CLEAR codes and without block mode, decode to their input like `7z` |
| A 9-bit file with ncompress 5.0's damage reads with no error to the same wrong bytes as `7z` |
| Linked long entries decode exactly |
| `.tar.Z` is found; a bare `.Z` stays bare |

**Building fixtures.** No Python library writes `.Z`. The `ncompress` package installs
`compress`; it is a development tool only.

## 9. References

- The `compress` format has no formal specification; `ncompress` 5.0's source is the
  reference implementation, including the code-group padding after CLEAR
- [`uncompresspy`](https://github.com/kYwzor/uncompresspy), BSD 3-Clause, the origin of the
  LZW kernel (notice at the end of `unix_compress_decoder.py`)
- Decisions: [`library-analysis.md`](../library-analysis.md) §unix-compress
- Code: `internal/streams/codecs/` (`unix_compress_decoder.py`: `LzwState`,
  `UnixCompressDecoder`, `UnixCompressDecompressorStream`; `unix_compress_codec.py`:
  `UnixCompressCodec`)
- Handbook: [`single-file.md`](single-file.md) · [`tar.md`](tar.md)
