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
  the data reserve, then the stored bytes. A decoded size of 0 marks a block split across
  cabinets; libmspack fails it when there is no next cabinet. archivey refuses cabinet
  sets, so it raises `CorruptionError` for such a block, and for one over the size
  limits. As in libmspack, which reads each header only when it needs that block, the
  error comes when a read reaches the block: the members before it still read.

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

The members come in table order, unless reading them in that order would decode a block
twice (§2.3); then they come sorted by folder and offset, the order of their bytes. To
decide, `iter_members` reads the whole table before the first member comes (at most
65 535 records, each read once from the table: about 6 MiB more at the peak for 65 535
files) and replays the kept decoder over it (`_decodes_twice`). A cabinet that lists one
name twice keeps table order, since the entry listed last is the current one. A damaged
table yields the members before the damage, sorted by the same rule, then the error: one
bad record at the end of a crafted table does not turn the sort off.

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
same folder, at or after where that one stopped, continues from it. Any other member of a
compressed folder decodes the folder again from its first block. Writers list files in
data order, so `stream_members()` and `extract_all` decode each folder once; a table in
an order that would decode a block twice is sorted into data order first (§2.2, §6).
Members whose bytes overlap still decode their folder again in any order. Only one
decoder is kept: memory stays at one LZX window (at most 2 MiB), and the window is
checked against `max_decoder_memory` before a member of the folder opens. A member of
size 0 reads as empty and decodes nothing.

A member is `checked` (`Verification.CHECKSUM` once read to the end) when every block
from the folder's start through its last byte has a checksum. LZX history means an
earlier block's damage reaches the member, so the earlier blocks count too.

### 2.4 The LZX decoder

`lzx_decoder.py` follows libmspack's `lzxd.c` wherever the format leaves a choice, so the
two agree on every stream; its docstring lists those choices (code-length runs that spill
past their range, code lengths a delta wraps out of range, which trees may be empty,
matches that cross a frame or reach before the start, the
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

## 6. Decisions

(Numbered as in the handbook template, so citations stay valid when the missing sections
are added.)

- **Data order over table order, only when table order would decode a block twice.**
  The maintainer's call (2026-11-08), the same rule as for SquashFS fragments
  ([SquashFS §6](squashfs.md#6-decisions)). A file table in reverse data order made
  `stream_members()` and `extract_all` decode the folder from its start for each
  member, so the cost grew with the square of the member count: 400 files of 32 KiB in
  one LZX folder streamed in 12.6 s reversed against 0.1 s forward (MSZIP 2.0 s against
  0.05 s); sorted, the reversed table takes 0.1 s. Table order is kept whenever the
  replay of the one kept decoder says each block decodes once, which is every cabinet
  whose writer lists files in data order, and any table whose members of each folder
  are in order, whatever the order of the folders. Like SquashFS, the order changes for
  `members()` too: there is one member order, and it is the one the stream pass reads.
  A cabinet that lists a name twice keeps table order. Rejected: keeping more than one
  decoder (a crafted table interleaves one folder more), and sorting every table (it
  changes the order of cabinets that read well as they are). 7z needs no such rule:
  its parser assigns a folder's members in data order. Reopen if a writer is found
  whose table order matters to its users and still decodes a block twice, or if
  overlapping members, which decode their folder again in any order, turn up outside
  crafted input.
