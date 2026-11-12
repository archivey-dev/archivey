# ARJ

Current maintainer truth for ARJ: what ARJ for DOS (Robert Jung, 1990 to 2002), ARJ32 and
ARJ for Unix (open-source ARJ 3.x, the `arj` package in Debian and Ubuntu) write. An ARJ
archive is a run of headers, each followed by its member's data, ended by an empty
header. There is no index, and each member is compressed on its own. The reader is
written against `archivey.formats` and registered as a built-in, as LHA and CAB are.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/arj_reader.py`, an `ArjHandler` (`IndexedFormatHandler`) and an `ArjReader` (`IndexedReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file or a stream that can seek, from its start or behind a self-extracting stub (§4). Not a pipe, for now: the listing seeks past each member's data to the next header |
| Listing cost | Header by header, one read per header and a seek past the data |
| Access cost | `DIRECT`: each member is its own stream |
| Core dependencies | None. Methods 1 to 3 through `lzh_decoder.py` (LHA's decoder), method 4 through `arj_fast_decoder.py`, both archivey's own, in Python |
| Encryption | "Garbling" (`-g`): listed with `is_encrypted`, refused when read |
| Name encoding | Bytes. UTF-8 first, then `encoding=` (DOS archives are usually cp437 or cp866), then escaped, as in every format |
| Checksums | A CRC-32 of each basic header and each extended header, checked when it is read; a CRC-32 of each member's data, checked by the read |
| Refuses | Garbled members and members split across volumes, when read; methods past 4, when read; a pipe, with `StreamNotSeekableError` |
| Spec | `openspec/specs/format-arj/spec.md` |

Not here, though a reader might look for it: multi-volume sets (`.arj`, `.a01`, ...) are
not joined (tracked internally, after 0.4.0); ARJ's security envelope is not checked, only
skipped (§3); chapter archives (backups that keep several
versions of a file) get no special handling, and their chapter labels list as `OTHER`.

## 1. Shape

From the ARJ 2.x technical notes (`TECHNOTE.DOC`), Robert Jung's public UNARJ 2.43 and
open-source ARJ 3.10:

- Every header starts with `60 EA` and a 2-byte size. A size of 0 is the end header. Up
  to 2600 bytes of *basic header* follow (UNARJ's `HEADERSIZE_MAX`), then its CRC-32,
  then *extended headers*: a 2-byte size, the bytes, their CRC-32, until a size of 0.
- The basic header opens with a fixed part whose first byte is its size: 30 bytes in
  ARJ 1, 34 with the position a split member starts at, 46 with access and creation
  times (ARJ 2.62 and later). Then the name and a comment, each ended by a NUL.
- The fixed part holds the host OS, flags (`0x01` garbled, `0x04` continues in the next
  volume, `0x08` continued from the last one), the method, the file type, the garble
  modifier, the modification time, the stored and original sizes, the data's CRC-32, and
  the file mode (DOS attributes, or a Unix mode when the host is Unix).
- The first header is the archive's main header (file type 2); it has no data.

**Times.** A DOS time (local, no zone), except when the host is Unix or NeXT: ARJ for
Unix stores a Unix time there (UTC). The `7z` on the test image (p7zip) reads every time as DOS and shows
ARJ for Unix's times in 2033; archivey follows ARJ.

**Names.** DOS, OS/2 and Windows hosts write `\` separators, which become `/`. Unix hosts
write `/`; a `\` from them is kept, as in every format.

**File types.** 0 (binary) and 1 (text) are files, 3 a directory, 6 a Unix special file,
4 a volume label and 5 a chapter label (both listed as `OTHER`). A text member's bytes
are stored as the writer read them; archivey does not change line ends.

**Unix special files.** ARJ for Unix writes a type-6 member with a `U` extended header:
a flags byte, then a byte whose top three bits say what it is (0 FIFO, 1 hard link, 2
symlink, 3 character device, 4 block device) and whose low five bits are the length of
the data that follows, 31 meaning a 2-byte length comes next. A symlink's data is its
target, and a hard link's the name of the earlier member that holds the data (ARJ stores
the data once, under the first name it meets).

## 2. Methods

- **0**, stored.
- **1 to 3**: the static-Huffman LZ77 of Haruhiko Okumura's `ar002`, which LHA's `-lh5-`
  to `-lh7-` also use. ARJ's dictionary is 26 624 bytes and its offset table has up to 17
  codes (UNARJ's `NP`), so `lzh_decoder.py` reads it as the method `"arj"`: a 32 KiB
  window and 5-bit offset counts, like `-lh6-`. The three methods differ only in how hard
  the encoder searches.
- **4**, "fastest": LZ77 with no tables, `arj_fast_decoder.py`, after UNARJ's `decode_f`.
  A length is a unary width (0 to 7) and that many bits, 0 meaning a literal byte follows;
  a distance is a unary width (9 to 13) and that many bits.

Both decoders stop at the member's size and ignore input after it, as UNARJ does. A copy
from before the first byte of output reads ARJ's uninitialised buffer; method 4 refuses it
as `CorruptionError`, and methods 1 to 3 copy the spaces LHA's window starts with. No ARJ
writer makes one, and the CRC-32 then fails. Speed: about 10 to 30 MB/s for methods 1 to 3
and 8 to 11 MB/s for method 4, on text.

## 3. Ends

The end header (`60 EA 00 00`) ends the listing. A file that ends right after the last
member's data reports `ARCHIVE_EOF_MARKER_MISSING` (`expected_marker="end_of_archive_header"`)
after listing every member. Up to 64 KiB after the end header is scanned for non-zero
bytes (`ARCHIVE_TRAILING_DATA`); `0x00` and the DOS end-of-file byte `0x1A` are padding.

**ARJ-SECURITY envelope.** A registered ARJ can sign an archive (`-hk`): main-header flag
`0x40`, and the envelope right after the end header. The main header's size field (offset
16, the archive's size) is then where the envelope starts, and its mode field (offset 26)
the envelope's length. When the flag is set and the size field is the end header's end,
the trailing-data check starts past the envelope. The envelope is not checked: ARJ 3.10
for Unix cannot check ARJ 2.41a's own (it reports it damaged), and 7-Zip ignores it with
a warning. Nothing in it changes what the members hold.

## 4. Detection

The two magic bytes at offset 0. That is weak, as for `.Z`; the main header's size, CRC-32
and file type then confirm it at open, so another file that starts with `60 EA` fails as
`CorruptionError`.

**Self-extracting archives.** ARJ's `-je` writes a program with the archive after it:
ARJSFX, ARJSFXV or ARJSFXJR, DOS `MZ` programs (no PE header) from ARJ for DOS, ELF ones
from ARJ for Unix. No DOS ARJ module is a `.COM`. The backend declares `60 EA` at offset 0
as SFX magic (`SFX_PARSER_SCANS`), with `_validate_main_header`: the header there must
pass its size bounds, its CRC-32, its layout and its extended headers' CRC-32s, and be
file type 2. The CRC-32 leaves a stub's stray `60 EA` a chance of 1 in 2^32, so, unlike
LHA, the validator does not walk on to the members. A main header the source ends inside
is `DAMAGED`. When byte 0 is not `60 EA`, `_payload` runs the same scan (overlay start
first), so `format=ARJ` opens what detection finds; a scan that finds only decoys falls
back to the first, as RAR and 7z do, and the error names what is wrong there.

Measured once (2026-11-11): ARJ 2.41a's own distribution, `arj241a.exe` (a DOS ARJSFX
stub, the archive at byte 16 959, an ARJ-SECURITY envelope after it, from the IF Archive),
lists its 25 members, detected and forced, with no diagnostic, and each member's bytes
match 7-Zip's. ARJ for Unix's `-je` and `-je1` programs (ELF) read the same way.

## 5. Tests and fixtures

- `tests/test_arj.py`: `tests/fixtures/external/arj_310` (ARJ 3.10 for Linux: each method,
  links, a FIFO, a directory, a garbled member, a `-je1` self-extractor) and two of Commons Compress's archives
  (one from ARJ for Windows); damaged archives from a test-only writer of stored members.
- The Commons Compress corpus test matches CC on its three ARJ archives.
- Fuzz target `arj` (`tests/atheris_fuzz`).
