# CAB

Current maintainer truth for Microsoft cabinets: what `makecab`, `gcab` and the Windows
packaging tools write. A cabinet keeps its file table at the start and its data in
folders, each one compressed stream, so archivey reads it from a source that can seek.
The reader is written against `archivey.formats` and registered as a built-in, as ISO,
SquashFS and ar are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/cab_reader.py`, a `CabHandler` (`IndexedFormatHandler`) and a `CabReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek. Not a pipe: the file table points at folders anywhere in the file |
| Listing cost | From the index (the `CFFILE` table) |
| Access cost | `SOLID` when any folder is compressed, else `DIRECT` |
| Core dependencies | None. MSZIP through stdlib `zlib`; LZX through `internal/streams/codecs/lzx_decoder.py`, archivey's own, in Python |
| Encryption | None in the format |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format. The `_A_NAME_IS_UTF` attribute adds nothing: valid UTF-8 already wins |
| Checksums | A 32-bit XOR checksum per data block, over its stored bytes and two size fields; 0 means none |
| Refuses | Cabinet sets (a `PREV`/`NEXT` flag) at open; Quantum folders and unknown methods when a member is read; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-cab/spec.md` |

Not here, though a reader might look for it: the header reserve area (where Authenticode
signatures of signed cabinets live) is skipped, not read; bytes after `cbCabinet` are not
looked at; a cabinet embedded in an executable is not searched for.

## 1. Shape

From the Microsoft Cabinet Format specification (MS-CAB) and libmspack's `cabd.c`:

- **`CFHEADER`**, 36 bytes: `MSCF`, four reserved zero bytes, the cabinet size, the offset
  of the first `CFFILE`, version 1.3, the folder and file counts, flags and set fields.
  With flag 4, three reserve sizes and a header reserve area follow; with flags 1 and 2,
  the names of the previous and next cabinets in a set.
- **`CFFOLDER`** per folder: where its first data block starts, how many blocks, and the
  compression type (low nibble the method, bits 8-12 the LZX window or Quantum level),
  then the folder reserve.
- **`CFFILE`** per file, at `coffFiles`: size, offset in its folder's output, folder index
  (`0xFFFD`-`0xFFFF` continue a file across cabinets), DOS date and time, attributes, then
  a NUL-terminated name with `\` separators. `windows_attrs` drops the cabinet-only
  attributes `_A_EXEC` (`0x40`) and `_A_NAME_IS_UTF` (`0x80`): in a Windows attribute mask
  those bits are `FILE_ATTRIBUTE_DEVICE` and `FILE_ATTRIBUTE_NORMAL`.
- **`CFDATA`** blocks per folder: checksum, stored size, decoded size (at most 32 KiB),
  the data reserve, then the stored bytes.

The methods are 0 stored, 1 MSZIP, 2 Quantum and 3 LZX.

- **MSZIP:** each block is `CK` and a complete raw deflate stream, which may reference the
  previous block's output as its dictionary (`zlib.decompressobj(-15, zdict=…)`).
- **LZX:** one bit stream across all the folder's blocks (16-bit little-endian words, most
  significant bit first), in 32 KiB frames that realign to a word; Huffman trees whose code
  lengths are sent as deltas from the previous block's; three repeated offsets; verbatim,
  aligned-offset and uncompressed blocks; an optional x86 `E8` call translation. The
  window is 2^15 to 2^21 bytes; no reset interval in a cabinet.

## 2. The pipeline here

### 2.1 Identify

`MSCF\0\0\0\0` at offset 0 is exact magic (`file` uses the same eight bytes). The
extension is `.cab`.

### 2.2 Open and list

`CabReader.__init__` reads the header, refuses a set, skips the reserve area and reads the
folder records. `iter_members` then reads the file table from `coffFiles`, 64 KiB at a
time: each record, then a name that must end within 256 bytes and not be empty, as
`cabd.c`'s `cabd_read_string` requires. A folder index past the folders, or one of the
"continued" values in a cabinet that is not in a set, is `CorruptionError`. The name's
`\` become `/` after decoding, so a code page whose second byte can be `0x5C` (cp932)
stays whole. `modified` is the DOS date and time, naive; an invalid one is `None` with
`MEMBER_TIMESTAMP_INVALID`. `compression` is `STORED`, `DEFLATE` (MSZIP), `LZX` or
`QUANTUM`. `ArchiveInfo.format_version` is `major.minor`.

### 2.3 Read

The first open of a member in a folder reads that folder's `CFDATA` headers (one 8-byte
read per block, seeking past the data) into a block table: where each block's bytes are
and where its output starts. A block over 38 912 stored or 32 768 decoded bytes
(`CAB_INPUTMAX`, `CAB_BLOCKMAX`) is `CorruptionError`. A cabinet cut before the last header
keeps the blocks it has, so a file in them still reads. The tables are kept for the
reader's life and weighed against `max_metadata_bytes` as they are read (256 bytes a
block, about twice what one measures): folders may all name the same run of block
headers, so without the weighing a 2.5 MB cabinet could ask for hundreds of GiB of them.

A member's stream reads its folder's output from its offset. Stored folders start at the
block holding the offset and skip whole blocks unread. MSZIP and LZX start at the folder's
first block. Each block's checksum, when not 0, is checked as the block is read. MSZIP
must end its deflate stream with exactly the decoded size. LZX decodes 32 KiB frames,
the last one up to the folder's total, whatever size each block says.

When a member stream closes, the reader keeps its folder decoder; the next member of the
same folder at a later offset continues from it. So `stream_members()` and members read
in order decode each folder once. Only one decoder is kept: memory stays at one LZX window
(at most 2 MiB).

A member is `checked` (`Verification.CHECKSUM` once read to the end) when every block
from the folder's start through its last byte has a checksum. LZX history means an
earlier block's damage reaches the member, so the earlier blocks count too.

### 2.4 The LZX decoder

`lzx_decoder.py` follows libmspack's `lzxd.c` wherever the format leaves a choice, so the
two agree on every stream; its docstring lists those choices (code-length runs that spill
past their range, empty trees, matches that cross a frame or reach before the start, the
E8 limits). Each tree decodes through a two-level table: a root as wide as the longest
code, at most 10 bits, and a sub-table under each root entry whose codes are longer. A
block may be empty and still carry up to six trees, so a table's cost follows its tree:
a stream of nothing but block headers, with the deepest pretrees the format allows,
decodes at about 2 µs an input byte (0.5 MB/s, CPython 3.11), against 12 µs with one
65 536-entry table per tree. No byte comes out, so `ExtractionLimits` does not see it
(threat model, §No CPU or wall-clock bound).
Past the end of the input it reads zero bytes, as `lzxd.c` does for two bytes, and refuses
a stream that uses more than two of them (`TruncatedError`). It runs at about 5-10 MB/s.

## 3. Tests

`tests/test_cab.py`. Cabinets are written at test time by `tests/cab_util.py`, which holds
the only LZX encoder available here (no Linux tool writes LZX): greedy matching, the
repeated offsets, all three block types, the E8 translation, and code-length runs.
`cabextract` reads every cabinet the tests write (checked whenever it is installed), so the
decoder is not checked only against its own reading. Four cabinets from libarchive's test
suite, written by `makecab.exe`, are in `tests/fixtures/external/cab_libarchive/`: stored,
MSZIP, LZX and a cp932 name.
