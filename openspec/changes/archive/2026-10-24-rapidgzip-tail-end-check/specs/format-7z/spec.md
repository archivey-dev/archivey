## MODIFIED Requirements

### Requirement: Decode folder coder chains through compressed-streams

The system SHALL decode each folder by composing shared `compressed-streams`
backends in decoding order. A coder list such as `AES -> LZMA2` decrypts, then
decompresses. Files in a folder are yielded by reading exactly `member.size`
bytes in archive order from the decompressed folder stream. Per-member CRC32
values SHALL appear in `hashes["crc32"]` and SHALL be verified by the shared
verification stage as data is read.

| 7z codec | Method ID | Backend | Availability |
| --- | --- | --- | --- |
| STORED | `0x00` | pass-through | core |
| LZMA1 / LZMA2 | `0x030101` / `0x21` | `lzma` `FORMAT_RAW` | core |
| Delta | `0x03` | `lzma.FILTER_DELTA` | core |
| BCJ x86/ARM/ARMT/PPC/SPARC/IA64 | `0x04`-`0x09`, `0x03030103`... | `lzma` BCJ filters | core |
| BCJ ARM64 | `0x0A` | archivey's own decoder (pure Python) | core |
| BCJ RISC-V | `0x0B` | archivey's own decoder (pure Python) | core |
| Deflate | `0x040108` | raw `zlib` | core |
| BZip2 | `0x040202` | `bz2` | core |
| Zstd | `0x04f71101` | stdlib `compression.zstd` / `backports.zstd` | core on 3.14+; otherwise `[recommended]` |
| Brotli | `0x04f71102` | `brotli` | `[recommended]` |
| LZ4 | `0x04f71104` | `lz4` frame decoder (same backend as standalone / `.tar.lz4`) | `[recommended]` |
| PPMd (var.H) | `0x030401` | `pyppmd` | `[recommended]` |
| Deflate64 | `0x040109` | `inflate64` | `[recommended]` |
| AES-256 / SHA-256 | `0x06f10701` | crypto backend | `[recommended]` |
| BCJ2 | `0x0303011B` | archivey's own decoder (pure Python) | core |

The `[recommended]` extra SHALL provide PPMd, Deflate64, Zstd on Python versions without
stdlib zstd, Brotli, LZ4, and AES support in one install.

LZMA1+BCJ folders SHALL NOT be decoded via a single combined `lzma` `FORMAT_RAW`
filter chain: liblzma can silently truncate the final BCJ look-ahead bytes when
LZMA1 lacks an end-of-stream marker. The reader MUST stage LZMA1 (and any non-BCJ
`lzma` filters such as Delta) through stdlib `lzma`, then apply each BCJ stage
separately. LZMA2+BCJ remains a single stdlib filter chain.

A folder SHALL be decoded when its coder graph is a **tree**: exactly one coder
output is left unbound (the folder's output), every other output feeds exactly one
input, every input is either bound or a packed stream, and no coder feeds itself.
Each input is decoded as its own branch — a linear chain planned by the rules
above, ending at one packed stream — so a four-input BCJ2 coder over four
branches, each with its own AES coder when the folder is encrypted, is one tree.
Every packed stream SHALL be read through its own view of the archive, with its
own position. A graph that cannot be a valid folder SHALL raise `CorruptionError`:
an input that is neither bound nor packed, an output bound to two inputs, or a
cycle. A valid graph the reader does not run SHALL raise `UnsupportedFeatureError`:
more than one unbound output, or a multi-input coder other than BCJ2. A branch's
coders SHALL be planned with that branch's own sizes, so a coder's input length is
the output length of the coder before it in the same branch.

A folder SHALL hold at most 64 coders and at most 64 coder in-streams and
out-streams, the limits 7-Zip applies (`k_Scan_NumCoders_MAX` and
`k_Scan_NumCodersStreams_in_Folder_MAX` in 7-Zip's `7zIn.cpp`). A larger folder SHALL
raise `UnsupportedFeatureError` at header parse, as 7-Zip reports it unsupported.

An LZMA1 or LZMA2 coder SHALL share a liblzma raw chain only with the Delta and BCJ
filters decoded after it, ARM64 and RISC-V excepted: stdlib `lzma` does not build
those filters, so ARM64 or RISC-V, and every filter decoded after it in its run, SHALL
be decoded as its own stage. An ARM64 coder whose start offset is not a multiple of 4,
or a RISC-V coder whose start offset is not a multiple of 2, SHALL raise
`UnsupportedFeatureError` when the folder is planned, as 7-Zip refuses it. A filter decoded before any LZMA1/LZMA2 coder, and a second LZMA1/LZMA2 coder
in the same run, SHALL be decoded as its own stage, because a liblzma raw chain must
end, in encode order, in its only LZMA1/LZMA2 filter.

Every decoder of a folder runs at once: the stages of a chain are stacked streams, and
a BCJ2 folder's branches run side by side. When a folder has more than one decoder
that declares memory (LZMA dictionary sizes, PPMd memory sizes, and the window of a zstd
frame read directly from a pack stream), their sum SHALL be
checked against `DecoderLimits.max_decoder_memory` before any of them is built, and
exceeding it SHALL raise `ResourceLimitError`.

A coder whose codec ends its own stream (LZMA2, Deflate, Deflate64, BZip2, Zstd, LZ4
and Brotli) that decodes more bytes than its declared unpack size SHALL raise
`CorruptionError`, as 7-Zip reports a data error. In an encrypted folder the password
check can decode the folder before the caller's read does; when it meets the surplus
there, the raised error SHALL be `EncryptionError` ("wrong password or corrupt"), with
the surplus `CorruptionError` in its cause chain, as for any damage the check decodes.
The check SHALL count the coder's decoded output, so AES padding in the coder's input
is not surplus, and the output of concatenated Zstd or LZ4 frames in one coder counts
together. The check SHALL ask the decoder for at most one
byte of output past the declared size, and SHALL NOT decode the folder a second time.
The decoder MAY read the rest of the coder's packed input to produce that byte (a tail
of streams that decode to nothing), so the check's input cost is bounded by the coder's
packed size, the same bound as decoding the folder. A decoder error on that one byte
is not surplus output, except input left after the stream's end (below). LZMA1 and PPMd
coders, which 7-Zip writes without an end marker, SHALL stop at their declared size
and decode nothing past it; the check's read past the size is where they report input
left after that size.

A coder's data SHALL be one stream, as 7-Zip reads it: the decoder SHALL end at the
first stream's end and SHALL NOT decode a further stream after it as output. Any byte
of the coder's input after that end, a zero byte included, and a further stream there,
SHALL raise `CorruptionError` once the output before it is read, whatever the unpack
size and CRC count, as 7-Zip 23.01 reports a data error ("Data Error", or "There are
some data after the end of the payload data"). The exception is Zstd and LZ4, whose
decoders read concatenated frames as one stream: a further frame is output that counts
against the unpack size (below), and only bytes after the last frame that start no
frame SHALL raise. rapidgzip on a Deflate coder is the other exception
(`compressed-streams`): a second Deflate stream long enough to hold a resume point, with
an unpack size and CRC that cover both, reads as both. The coder's input is its declared input
size (its pack size, or the size the coder before it declares), so AES padding past it
is not such a byte. An LZMA1 or PPMd coder ends at its declared size: its input SHALL
end there too, or after an end marker right at that size, and a declared size short of
the data the stream holds SHALL raise `CorruptionError`, not `TruncatedError`, since
the input is too long rather than short. One zero byte after an LZMA1 stream without an
end marker reads: 7-Zip's encoder sometimes flushes it past the decoder's last read.
What cannot be told from a valid stream is a declared size that cuts off only zero
bytes of LZMA1 data, or the last few symbols of PPMd data where pyppmd's end flag has
already risen: there the hidden data is zeros, or a few bits. Under the rapidgzip
accelerator, a Deflate or BZip2 coder SHALL hand over to the standard-library decoder
where a further stream starts, so the verdict is the standard library's.

#### Scenario: coder-chain matrix

| Case | Expected |
| --- | --- |
| BCJ + LZMA2 folder | Shared `lzma` raw filter chain returns original bytes |
| BCJ + LZMA1 folder | Staged LZMA1 then a staged liblzma BCJ returns original bytes |
| ARM64 + LZMA2 folder (7-Zip 23's default for an AArch64 executable), with or without a start offset | LZMA2 chain, then a staged ARM64 filter, returns original bytes |
| RISC-V + LZMA2 folder written by 7-Zip 24+ (`-mf=RISCV`), with or without a start offset | LZMA2 chain, then a staged RISC-V filter, returns original bytes; the member CRC32 verifies |
| RISC-V coder with an odd start offset | `UnsupportedFeatureError` when the folder is planned |
| Member with stored CRC32 | Terminal verification raises `CorruptionError` on mismatch |
| PPMd without `pyppmd` | `PackageNotInstalledError` names `pyppmd` and the `[recommended]` extra |
| AES + LZMA2 folder | Crypto stage decrypts before LZMA2 decompression |
| LZ4 folder (`0x04f71104`) with `lz4` installed | Shared `Codec.LZ4` returns original bytes |
| LZ4 folder without `lz4` | `PackageNotInstalledError` names `lz4` and the `[recommended]` extra |
| 7-Zip `-mx9` folder: `BCJ2` over `LZMA2`, `LZMA`, `LZMA` and one raw pack stream | Four branches over four packed streams return the original bytes |
| Same folder, encrypted: an AES coder on each of the four branches | Each branch decrypts, then decodes; the original bytes return |
| Coder output bound to two inputs, or a coder bound to itself | `CorruptionError`; no output bytes |
| Same malformed graph in an encrypted folder | `CorruptionError` on the first attempt; not reported as a wrong password |
| BCJ2 folder whose `main` branch is `AES` then `BZip2` | The BZip2 stage's input length is the AES coder's output, not a sibling branch's |
| Folder of 64 Delta coders | Decodes; no `RecursionError` |
| Folder of 65 coders, or a coder graph with more than 64 in-streams | `UnsupportedFeatureError` at open |
| Delta, BCJ or LZMA2 decoded before LZMA2 (`7z a -m0=LZMA2 -m1=BCJ`) | Staged separately; the original bytes return |
| LZMA2, Copy, LZMA2 whose dictionaries each fit `max_decoder_memory` but together do not | `ResourceLimitError` before a decoder is built |
| LZMA2 coder decodes past the folder's declared unpack size | `CorruptionError` |
| Deflate, Deflate64, BZip2, Zstd, LZ4 or Brotli coder decodes past its declared unpack size, also before a Delta or BCJ filter or in a BCJ2 branch | `CorruptionError` |
| Same, behind AES, in a folder the password check decodes whole (one inside its 64 KiB prefix) | `EncryptionError`, with the surplus `CorruptionError` in its cause chain |
| Same, behind AES, in a folder the password check does not decode whole | `CorruptionError` |
| LZMA1 or PPMd coder whose data decodes 1000 bytes past its declared unpack size | `CorruptionError`, not `TruncatedError` (`7z t`: Data Error) |
| LZMA1 or PPMd coder with junk, zero bytes or a further stream after its data | `CorruptionError` (`7z t`: Data Error) |
| AES then Deflate, Deflate64, BZip2, Zstd, LZ4 or Brotli, decrypted input ending in AES padding | Original bytes return; the padding is not surplus |
| Two Zstd frames or LZ4 frames in one coder | Original bytes when the unpack size counts both; `CorruptionError` when it stops after the first |
| Two BZip2 or Deflate streams in one coder, whatever the unpack size and CRC count | `CorruptionError` (`7z t`: data after the end of the payload data) |
| BZip2, Deflate or Deflate64 coder with junk or zero bytes after its stream | `CorruptionError` (`7z t`: data after the end of the payload data) |
| Two LZMA (end-marked) or LZMA2 streams in one coder, whatever the unpack size counts | `CorruptionError` (`7z t`: Data Error) |
| LZMA (end-marked) or LZMA2 coder whose input has one more byte after the end marker, a zero too | `CorruptionError` (`7z t`: Data Error) |
| AES then LZMA or LZMA2, decrypted input ending in AES padding | Original bytes; the pad is past the coder's input size |
| LZMA1 coder without an end marker, with input after its data | `CorruptionError` (`7z t`: Data Error), except one zero byte |
| 7-Zip's own LZMA, LZMA:eos, LZMA2, PPMd, `-mhe=on`, solid, `-ms=off` and BCJ2 archives | Read clean |
| Two BZip2 streams under rapidgzip (`use_indexed_bzip2` `ON`), whatever the size and CRC count | `CorruptionError`, as with the accelerator off |
| Two Deflate streams under `use_rapidgzip=ON`, the unpack size covering the first only, or no resume point in the second | `CorruptionError`, as with the accelerator off |
| Two Deflate streams under `use_rapidgzip=ON`, a resume point in the second, the unpack size covering both | Decodes both streams |

