## MODIFIED Requirements

### Requirement: An accelerator preserves the error contract of the path it replaces

When an optional accelerator backend (today rapidgzip, including its bundled bzip2
decoder) replaces a codec's default decoder, the accelerated stream SHALL raise the same
class of translated error, on the same inputs, as the non-accelerated path. An accelerator
SHALL NOT convert a decode failure into a successful empty read.

Specifically, a decoder that ends a stream having produced no output, without consuming its
input and without reaching a valid end-of-stream marker, SHALL raise rather than report
end-of-file. Where the accelerator cannot report enough to tell that apart from a genuine
empty stream (rapidgzip's bundled bzip2 decoder cannot), the first empty read before any
output SHALL be re-decoded by the non-accelerated decoder over a fresh view of the
source, which raises or confirms the empty stream. A seek before that first read does not
bypass the check: on such a stream the accelerator clamps the seek to 0. Accelerator mode
is a performance choice and SHALL NOT be observable as a difference in whether a corrupt
source raises, with two exceptions. First, where every byte of output is covered by
checks the data itself declares, those checks give the verdict, and an accelerator MAY
differ from the standard-library decoder on a stream-boundary malformation they cannot
see: for a standalone multi-member gzip, a wrong ISIZE on a member other than the last,
when every member's CRC-32 is still checked. Second, rapidgzip on a container member's
raw DEFLATE data MAY read a second stream as content (below).

A container member's compressed data (a ZIP member's, a 7z coder's declared input) is
one stream of its codec and nothing else. A byte of it the codec leaves after the
stream's end, a zero byte too, and a second stream there SHALL raise `CorruptionError`,
after the output before that end has been delivered, whatever the declared size and CRC
cover, with the accelerator on or off: an accelerator that reads on past the first
stream hands the read to the standard-library decoder there, which refuses it. 7-Zip
23.01 fails such a member ("There are some data after the end of the payload data", or
"Data Error"), and the bytes may hide a second payload. The exception is a ZIP Zstd
member and a 7z Zstd or LZ4 coder, whose concatenated frames are read as one stream, as
RFC 8878 defines Zstd data as one or more frames and the LZ4 frame format lets frames be
appended: a further frame is content that counts against the declared size and CRC, and
only bytes after the last frame that start no frame SHALL raise. A codec that stops at a
declared output size (LZMA1 without an end marker, PPMd) SHALL raise the same way when
its input goes on past that size; such a cut leaves input over, so it is not a
`TruncatedError`. A standalone compressed file keeps reporting the bytes after its
streams as `ARCHIVE_TRAILING_DATA` instead.

rapidgzip on a container member's raw DEFLATE data is the second exception, to that
rule and to the parity above. rapidgzip does not report where a stream ends, and it
reads on into a second stream. When its output ends, zlib SHALL decode only the tail,
from the last point of rapidgzip's complete index before the end (or from the start
when there is none), to find a final block and any input after it. A decode from the
start would cost as much as the standard-library read that the accelerator replaces. So
when a second DEFLATE stream holds that point, the check sees only that stream's end,
and the member SHALL read as both streams when its declared size and CRC cover both.
With the accelerator off it raises `CorruptionError`, and 7-Zip and Info-ZIP read the
first stream and fail the CRC. No known writer makes such a member. Which stream holds
the point depends on the data and on how many threads rapidgzip runs, which follows the
core count: it places points every few hundred KiB to a few MiB of output, closer
together with more threads. A second stream that does not hold it, junk, zero bytes and
a cut stream keep the standard library's verdict. zlib parses only the tail: the output
before the point is rapidgzip's, checked by the member's CRC where the container
declares one.

A wrong ISIZE on the last member of a one-member gzip is not among the stream-boundary
malformations of the first exception, whatever follows
the member. The accelerator reads the output through a CRC-32 and finds the trailer as the
one place near the end of the file where that CRC-32 occurs: it looks from 72 bytes before
the end of the non-zero data to 12 bytes after it, and takes the file as ending with the
trailer only when the CRC-32 occurs there once, followed by the length and then by nothing
but zero padding. A forged copy of those eight bytes, whether appended after a wrong
trailer, overlapping it or reaching back into the compressed data, leaves the real CRC-32
as a second occurrence, so it does not stand in for the trailer. Not excluded: a copy more
than 56 bytes after the end of the real trailer, which needs rapidgzip to read past that
many bytes that are not a further member without an error; rapidgzip 0.16 raises on ten or
more. In a file of several members the CRC-32 of the whole output is not the last
member's, so it finds no trailer there. A further member that zlib confirms says only that
the file has several members, not that the last one is whole: rapidgzip ends a last member
cut right after its header with no error, at the end of the file. So the accelerator SHALL
also find the last member's trailer, the eight bytes that end the file but for zero
padding, and SHALL accept the file only when they hold the CRC-32 and the length mod 2**32
of the last that-many bytes of the output. A wrong ISIZE or a cut on the last member,
after any number of members before it and whatever its size, then gives the standard
library's error. An empty last member (bgzip's end-of-file member) counts when zlib
decodes it from a header in the 1 KiB before the end of the non-zero data, with only
zeros after it. That CRC-32 SHALL come from the running CRC-32 of the output, saved every
4 MiB of output, as `C(A + B) ^ crc32_combine(C(A), 0, len(B))` for the last `len(B)`
bytes `B`, with `C(A)` carried on from the checkpoint before it by a read-back from the
accelerator: at most four candidates, tried shortest first, each a read-back of at most
4 MiB, whatever the size of the last member or the length a forged trailer states. A
valid file of any size is so decided with no handover to the standard-library decoder.
Not excluded: a crafted cut whose last eight bytes are made the CRC-32 and length of the
end of the output, which takes choosing four bytes of the content. A last member of 4 GiB
or more of output does not match, as its length is wrapped, and is read by the
standard-library decoder, at the cost of a second decode.

When a seek short of the end has skipped output, there is no CRC-32 of the whole output,
and the last four bytes of the file stand in as the ISIZE of a file with no further
member. In a file with a further member, the last member's trailer SHALL still be checked
as above whatever the last four bytes say, and no candidate SHALL be accepted unchecked: a
CRC-32 kept from where reading resumed covers a candidate that starts after that point,
and for one that starts before it the skipped part is read back from the accelerator.
That read-back SHALL be bounded, at most 64 MiB of output in all; a candidate past it
hands the read to the standard-library decoder, which gives the right result at the cost
of a second decode.

#### Scenario: accelerator error parity

| Source | Accelerator `OFF` | Accelerator `AUTO` |
| --- | --- | --- |
| Valid bzip2 stream | Content | Content |
| Valid **empty** bzip2 stream | `b""` | `b""` |
| bzip2 source of 40 000 zero bytes | `CorruptionError` | `CorruptionError` — not `b""` |
| Zero-byte bzip2 source | `TruncatedError` | `TruncatedError` — not `b""` |
| Corrupt gzip source | `CorruptionError` | `CorruptionError` |

#### Scenario: the parity holds through the public reader

| Case | Expected |
| --- | --- |
| `open_archive(corrupt.bz2, seekable_members=True).read(member)` | Raises, matching `seekable_members=False` |
| A capability flag (`seekable_members`) | Never changes whether a corrupt source raises, except through the accelerator on the stream-boundary malformations listed above |

#### Scenario: a container member with input after its stream

| Member | Accelerator `OFF` | Accelerator `ON` |
| --- | --- | --- |
| Two bzip2 streams; declared size and CRC cover both, or the first only | `CorruptionError` | `CorruptionError` |
| Two DEFLATE streams; declared size and CRC cover the first only | `CorruptionError` | `CorruptionError` |
| Two DEFLATE streams; declared size and CRC cover both, the last rapidgzip index point in the first | `CorruptionError` | `CorruptionError` |
| Two DEFLATE streams; declared size and CRC cover both, the last rapidgzip index point in the second | `CorruptionError` | Decodes both |
| One DEFLATE or bzip2 stream, then junk or zero bytes | `CorruptionError` | `CorruptionError` |
| ZIP Zstd member with two frames; declared size and CRC cover both | Decodes both | — |
| ZIP Zstd member with two frames; declared size and CRC cover the first only, or junk after the last | `CorruptionError` | — |
| ZIP LZMA without an end marker, or 7z LZMA1, whose declared size is 1000 bytes short of its data | `CorruptionError` (not `TruncatedError`) | — |
| ZIP PPMd8 or 7z PPMd, then junk, or a declared size 1000 bytes short of its data | `CorruptionError` (not `TruncatedError`) | — |
| A `.bz2` file with junk after its stream | Content, and `ARCHIVE_TRAILING_DATA` | Content, and `ARCHIVE_TRAILING_DATA` |

