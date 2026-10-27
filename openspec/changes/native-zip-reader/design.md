# Design — native ZIP reader

## Context

`zip_reader.py` (2 615 lines) uses `zipfile.ZipFile` for one job: find the end record and
turn the central directory into `ZipInfo` objects. Member data already bypasses
`ZipExtFile`: the reader parses the local header itself (`_local_data_region`), slices
the payload with a `SharedView`, runs its own ZipCrypto and WinZip AES stages and decodes
through the shared codec layer. So the native reader replaces the directory parse and the
glue around it, and leaves the member data path as it is.

The ZIP fix PRs from the October code sweep (trailing bytes after a codec's end, the
Unicode Path field, comment decoding) change the same file. Coding starts after they
merge, and their tests become acceptance tests for the native reader.

## Layout

### `internal/backends/zip_parser.py` (new)

Structure only, like `sevenzip_parser.py`: no `ArchiveMember`, no passwords, no codecs,
no diagnostics collector. It raises `CorruptionError`, `TruncatedError` and
`UnsupportedFeatureError` and returns plain data.

```python
@dataclass(frozen=True, slots=True)
class EndRecord:
    eocd_offset: int          # absolute position of PK\x05\x06
    zip64: bool               # a ZIP64 end record supplied the fields below
    entries_declared: int
    cd_size: int
    cd_offset: int            # as stored
    base: int                 # added to every stored offset (stub before the archive)
    comment: bytes            # cut at end of file
    comment_declared: int     # the stored length, for the "comment cut short" finding
    trailing: int | None      # bytes after the record and its declared comment; None from a forward walk

ReadAt = Callable[[int, int], bytes]   # read_at(offset, n); the caller owns handle and lock

def find_end_record(read_at: ReadAt, file_size: int) -> EndRecord: ...

@dataclass(frozen=True, slots=True)
class CentralEntry:
    index: int                # position in the directory
    version_made_by: int      # create system in the high byte
    version_needed: int
    flags: int
    method: int
    dos_time: int             # raw, for the ZipCrypto check byte under bit 3
    dos_date: int
    crc: int
    compressed_size: int      # after ZIP64 extra resolution
    file_size: int
    header_offset: int        # absolute: stored offset + EndRecord.base
    disk_start: int
    internal_attr: int
    external_attr: int
    name: bytes               # stored bytes, never decoded here
    extra: bytes
    comment: bytes

class CentralDirectoryWalk:
    def __init__(self, read_at: ReadAt, end: EndRecord) -> None: ...
    def __iter__(self) -> Iterator[CentralEntry]: ...
    findings: list[EndRecordFinding]   # complete once iteration ends

@dataclass(frozen=True, slots=True)
class LocalHeader:
    flags: int
    crc: int                  # 0 under bit 3
    compressed_size: int
    file_size: int
    name: bytes
    extra: bytes
    data_start: int           # absolute

def read_local_header(read_at: ReadAt, header_offset: int) -> LocalHeader: ...
```

`find_end_record` does what four helpers in `zip_reader.py` and stdlib's `_EndRecData`
do today, in one place:

- The search is stdlib's, so prefixed and commented archives resolve to the same record:
  a comment-less record ending at end of file first, then the last `PK\x05\x06` in the
  final 65 558 bytes (stdlib's older `1 << 16` plus the record, one byte more than the
  format needs; 3.13 and later 3.12 releases shrank it by that byte, and the wider window reads
  everything either one reads).
- The ZIP64 locator 20 bytes before it, then the ZIP64 record it points to.
- A disk field naming another disk (`0xFFFF` is the ZIP64 sentinel; the ZIP64 record's
  fields replace the classic ones when it is present, as in stdlib), or a ZIP64 locator
  with more than one disk, is `UnsupportedFeatureError` with `ZIP_MULTI_VOLUME_MSG`. No
  exception text is matched.
- An archive extra data record (`PK\x06\x08`) where the directory should start is the
  Strong Encryption refusal, checked before the walk rather than guessed after a failure.
  ZIP64 archives are covered too, which today they are not.
- `base` is stdlib's `concat`: `eocd_offset - cd_size - cd_offset` (minus the ZIP64
  records when present). A self-extractor stub whose writer did not adjust the offsets
  keeps reading. With `start_offset` the reader already slices the source, so `base` is
  computed inside the slice as today.

`CentralDirectoryWalk` reads the directory forward in 1 MiB pieces, one entry at a
time. The piece size trades memory (one piece plus one entry) against the number of
reads, each a seek and a read on the shared handle: a directory of 1 MiB or less is one
read, and a 46 MB one is 46. It is an implementation constant (DR-9). Every read goes
through `read_at`, which the reader implements as a seek and a read under its lock, so
the parser knows nothing of locking; it leaves the handle where the read ended, since
every other reader of the handle (`SharedView`) seeks before it reads. Each entry applies every
ZIP64 extra field (`0x0001`) in turn, as stdlib does, reading values in the order
APPNOTE gives: a value still all ones after one field is read again from the next (an
uncompressed size of `0xFFFFFFFF` or 64-bit all ones, a compressed size or header
offset of `0xFFFFFFFF`), and the disk number is read once, from the first field with
four bytes left after the other values. It stops at `cd_size` bytes, as stdlib does.
A name, extra or comment that runs past that point is damage, not cut as stdlib cuts
it, and so are fields that hold the entries after them and a name made shorter
(`dev-docs/formats/zip.md` §2.2).

The walk takes no limit and no charge callback. An entry's variable fields are three
16-bit lengths, so the most one entry can make the parser hold is 46 + 3 × 65 535 bytes,
plus the piece it is reading: the format bounds it, not the archive. The reader charges
each member it builds against `max_members` and `max_metadata_bytes` before it asks the
walk for the next entry, so the listing limits apply entry by entry. TAR differs here:
a header declares the size of the record after it, so the TAR parser charges that size
before reading it.

`read_local_header` is today's `_local_data_region` without the name decode: it compares
the local name **bytes** with the central name bytes, so a name that is not valid UTF-8
can no longer raise `UnicodeDecodeError` there.

### `zip_reader.py`

- The member is built from the `CentralEntry`; every `info.X` read maps to an entry
  field: `orig_filename` to `name` (no cp437 round trip), `_raw_time` to `dos_time`,
  `date_time` to a decode of `dos_date`/`dos_time`, `is_dir()` to "name ends in `/`".
  `member._raw` then keeps only a small frozen locator with what is read after listing
  (header offset, both sizes, CRC, flags, method, DOS time for the ZipCrypto check byte,
  and the WinZip AES strength and real method), not the entry: the entry's extra and
  comment bytes would otherwise stay alive per member. The raw-member-info measurement
  (2026-10-13, `reports/raw-member-info-2026-10-13.md` in the project files) puts
  today's `ZipInfo` at about 400 B per member, a quarter of listing memory. The
  later stages that need the directory entry (the end-of-pass update in stage 3, the
  header comparison in stage 5) use it while it is in hand, or the locator's fields.
- The handle is `self._source` (or the seek-counting and slicing wrappers over it), for a
  path source too. stdlib opened its own file for a path; the reader now opens nothing
  itself, and the path-or-handle branch in `__init__` goes.
- A reader-owned `threading.RLock` replaces `ZipFile._lock`, re-entrant as that one
  was: a source whose read closes the archive re-enters the lock on the same thread.
  `SharedView`, the local header read, `_payload_is_complete` and `_close_archive` take
  it, as they took the stdlib lock.
- `_iter_members` drives a `CentralDirectoryWalk` and yields each member as its entry is
  parsed. `ListingLimits` therefore see members as they are read, not after the whole
  directory has been built. The end-record findings are emitted after the last member, as
  today.
- `_get_archive_info`: `member_count` is the number of entries a complete walk read. A
  walk that fails, or stops at `max_members`, reports `None`, following DR-1 (absence
  over a wrong value). The count comes from the listing walk when that has run to the
  end, and otherwise from the index pass below; the directory is never walked a third
  time. The cost receipt stays `INDEXED`, `DIRECT`, `SEEKABLE` for a seekable source;
  §"What the caller sees in a forward pass" has the forward-pass values.
- At open, an archive whose end record declares more entries than `max_members` raises
  `ResourceLimitError`, when the directory is large enough to hold that many (`cd_size`
  at least 46 bytes per declared entry). That is the cheap check at open (DR-15b). It
  applies under `streaming=True` too, for a seekable source, which reads the directory
  first (question C). A declared count the directory cannot hold is a wrong
  field, not a breach: it stays the count-mismatch finding, and the walk charges what is
  really there.

### The overlap guard

stdlib refuses a member whose payload runs into the next local header ("Overlapped
entries", the zip-bomb shape). The bound for a member is the smallest header offset above
its own, or the directory start. That needs every offset, and the walk is lazy.

The listing walk records each entry's header offset as it goes (8 bytes per entry, in an
`array('Q')`), so after a listing that ran to the end the offsets and the count are
already known. A member open always comes after that walk: random access lists first,
and a streaming pass walks the directory before the first member's data (question C).
Only when `member_count` is asked for before the listing has finished does the reader
run an **index pass**: one more pass over the fixed 46-byte fields that builds no
members and keeps only the offsets and the count. Both collections charge `max_members`:
the index pass stops past it. Once it has stopped, **every** member open raises the
listing's `ResourceLimitError`, not only one above the stop, because the bound of a
member below it could come from an incomplete set of offsets. Listing alone never pays
for the array beyond the offsets of the members it listed.

`max_members` bounds the array in every mode, so ZIP charges it even under
`streaming=True`, where listing limits are otherwise off. That moves ZIP into the list
of formats that apply `max_members` while parsing (7z, RAR and ISO, `archive-reading`;
a stage 3 spec edit). A seekable source under `streaming=True` walks the directory
first, so the walk charges it there. A forward pass has no offset array (it reads data
in order), but it keeps every member it yielded until the end of the pass to update it
in place, so it charges `max_members` twice: on the local headers as members are
yielded, and on the directory's entries as it reads them, since a directory can list
more entries than the stream held members. The entries wait for the end record, which
says where their offsets count from, so their names, extra fields and comments are
weighed against `max_metadata_bytes` as they arrive, and past it the pass raises
`ResourceLimitError`, as every pass does at a cap. The seekable read weighs the members
it builds rather than the raw entries, so a directory whose extra fields alone pass the
cap is refused from a pipe only (DR-5a: a crafted shape). The fields the directory adds
(a comment above all) are weighed again when the members are updated, and the pass
raises when it is published if they took it over.

### Trailing bytes

ZIP reports bytes after its end record as TAR reports bytes after its trailer
(`format-tar`, the 1 MiB scan), so the one ruling gives one behaviour:

- The scan starts at the end of the declared comment and reads at most 1 MiB, in
  bounded chunks, in both modes. The first non-zero byte is reported as
  `ARCHIVE_TRAILING_DATA` with `observed_bytes` its offset past the comment; zeros are
  silent; past the bound the scan stops and reports nothing. The bound is TAR's
  `_MAX_TRAILING_SCAN` (measured there at about 5 ms), shared, not a second constant.
  No backend imports another format's module, so stage 2 moves the constant, its
  measured note and the zero-byte loop to a new `internal/trailing_scan.py` that TAR and
  ZIP both import; 7z, RAR and ISO use the same module when they take the ruling. TAR's
  codec-checksum handling around the loop stays in `tar_reader.py`.
- A seekable source skips the scan when `EndRecord.trailing` is 0, which is free from
  the file size. A forward pass has no size, so it reads; a pipe held open after the
  ZIP ends blocks there until more bytes or end of file, as a TAR pipe does today
  (`docs/gotchas.md` says so for TAR and gains ZIP).
- `expected_marker` is the existing `"zeros_to_eof"`, with `format="zip"`. Its meaning
  is the same (only zeros may follow the end marker, to end of file), so no new public
  value is added; the `diagnostics` spec row and the `ArchiveEofContext` docstring
  change from naming the TAR trailer to naming each format's end marker. 7z, RAR and
  ISO can share it under the same ruling; their thread decides, and this design does
  not need them to.

## Streaming: a forward walk over local headers

A ZIP can be read start to end with no seek, from a pipe, a socket or a remote object
read once: each member's local header sits right before its data, and the central
directory follows the last member. The parser supports this walk, and the reader uses it
for `streaming=True` on a non-seekable source, which ZIP refuses today. ZIP then sets
`SUPPORTS_STREAMING_NON_SEEKABLE`.

### Parser support

The forward walk is `internal/backends/zip_local_walk.py`, beside `zip_parser.py`. It
parses each central header with the parser's own `_unpack_central` and `_central_entry`,
and each local header with the same struct `read_local_header` uses. It takes the
source as a `BinaryIO` that it only reads, never seeks, and counts the bytes it has
consumed, which is the offset every local entry is matched by. That is the shape
`TarWalker` uses for a forward-only stream. Bytes a member's reader took past the
member's end are put back in front of the stream (`ForwardSource.unread`).

```python
class LocalEntry:                 # what one local header says, plus where it was
    index: int                    # position in file order
    offset: int                   # stream offset of its signature
    header: LocalHeader           # data_start a stream offset; ZIP64 extra applied
    zip64: bool                   # a ZIP64 extra field: 8-byte descriptor sizes
    deferred: bool                # bit 3: the data descriptor has the CRC and sizes

class LocalHeaderWalk:
    def __init__(self, stream: BinaryIO, *, offset=0, find_start=True) -> None: ...
    def next_entry(self) -> LocalEntry | None: ...    # None once the directory follows
    def member_data(self, entry, *, encrypted=False) -> MemberData: ...
    def directory(self) -> Iterator[CentralEntry]: ... # after the last member
    end: EndRecord | None           # set once the end record has been read
    gap: tuple[int, int] | None     # bytes read past before the directory

class MemberData(BinaryIO):         # the member's compressed bytes, read forward
    consumed: int                   # bytes handed out
    def settle(self, used=None, *, crc=None, file_size=None) -> DataDescriptor | None: ...
```

`settle` reads past the data the caller left and the data descriptor. For a member only
its codec can end, the caller passes the decoded data's `crc`, and the walk finds the
descriptor among the bytes it kept (§"Where a member's data ends"). A caller whose codec
counts its input (DEFLATE) may pass that count as `used` instead. Either way the bytes
the caller's layers read past the descriptor are put back. A central entry's offset is
the stored one (`base` 0) until the end record gives the stub offset.

The walk stops at the first `PK\x01\x02`, `PK\x06\x06` or `PK\x05\x06` after a member;
the directory is then read forward from the same stream with the same entry parser.

### Where a member's data ends

| Member | How the walk finds its end |
| --- | --- |
| Sizes in the local header (bit 3 clear) | `compressed_size` bytes |
| Bit 3, a codec with an end marker (DEFLATE, Deflate64, bzip2, Zstandard, LZMA with the EOS bit, PPMd with its end mark) | The codec's own end, then the data descriptor: signature optional, 8-byte sizes when the local header has a ZIP64 extra field, else 4-byte. Its CRC and sizes are checked against what was read. A member the pass reads past (nobody read it to its end) is decoded no further than the byte past the link target cap, then the reparse prefix a file read reads (the buffer and one byte) and one byte past it; if its codec has not ended there, the STORED scan below passes it on its stored bytes, matched on the compressed size and the signature after it, since decoding the rest costs what no limit bounds. If the decode fails, the walk's scan finds the descriptor on the stored bytes, with no key, starting at the last 4 MiB the decode read (the walk's put-back window) and counting the bytes before them; the members after it are read unless the decode ran more than that past the data's end |
| Bit 3, STORED (stdlib `zipfile` writes this to a pipe: measured, every member) | Scan forward for a local header, central header or end record signature (or the end of the stream), and take a descriptor ending right before it whose CRC and compressed size match the bytes since the data start. Its own `PK\x07\x08` is optional (APPNOTE 4.3.9.3; early PKZIP left it out), so both shapes are tried; libarchive finds only the signed one. When none matches whole, a descriptor with one damaged field ends the member: without its signature, two of its CRC and two sizes agree; with it, its compressed size or two fields; with a damaged signature, all three. The member then fails its CRC or size check when read, or the directory check at the end of the pass, and the members after it are read (DR-2). None matching by the end record (more damage, or bytes between the descriptor and the next header): `UnsupportedFeatureError` |
| Bit 3, STORED under ZipCrypto or WinZip AES | The same scan, on the ciphertext. The descriptor's CRC covers the plaintext, so the scan matches on the compressed size and the signature after it only; the CRC (ZipCrypto, AE-1) or the HMAC (AES) then checks the plaintext as for any member |
| Bit 3, LZMA without the EOS bit | The codec cannot find the end, so the member's read is `UnsupportedFeatureError` in this mode, naming the reason. The walk's scan on the stored bytes then passes it as it does a failed decode, under the same 4 MiB window. A seekable source reads it. (PPMd has no flag for a missing end mark: such a member fails its decode, from a file too, and the scan passes it.) |
| Bit 3, encrypted, any method but STORED, nobody reads it | The STORED scan, on the ciphertext, matching the compressed size and the signature after it: no key is needed to pass the member, and a short one keeps its ciphertext for a link target as a sized one does. A false match in ciphertext takes a planted signature and size (about 2^-64 per position by chance); a crafted one is the planted-prefix case, caught against the directory |
| Bit 3, encrypted, any method but STORED, read | Only the decrypted codec finds the end, so the walk decrypts and decodes it. When the read fails (no password, a wrong one, a key that passed its check byte and decodes garbage, damaged data), the walk puts back what the read took and passes the member by the scan above, so the member fails alone, as from a file. The scan starts at the last 4 MiB the read took (the walk's put-back window), so only a read that ran more than that past the data's end leaves the descriptor behind it and ends the walk there. The descriptor is found by the decoded CRC (zero under AE-2). Under WinZip AES the code follows the ciphertext, so the stage keeps the last bytes it read out of the HMAC until the descriptor says where the data ended (the walk's put-back window and one read more), and the bytes the descriptor search read past the stage's last read complete it |

The STORED scan can be fooled on purpose: a member that carries, inside its own data, a
descriptor for a prefix of itself followed by a local header signature ends early, and
its CRC matches. The central entry is the check that catches it: a size or CRC that came
from a data descriptor and differs from the central entry is a failure of that member at
the end of the pass (§"Failures found at the end of the pass"). This is not question A,
which is about two headers that state the same field differently; here the local header
stated no size at all.

Several possible passwords (a list, or a provider) are confirmed as the file read
confirms them (`password_confirm.attempt_with_confirm`), on the first 1 MiB of the
member's data, which the pass keeps and replays to the winner: a candidate is decrypted
and decoded over those bytes, a CRC or WinZip AES code reached in them confirms it, and a
codec's rejection or a mismatch rejects it. A bit-3 member's CRC follows its data, so it
is confirmed only when it ends inside the kept bytes: by the descriptor the STORED scan
found there, or after a codec's end by a descriptor in them that states the decoded CRC
and size. The file read walks each candidate that is still inconclusive to the member's
end to tell them apart; the data goes by once here, so the first of them wins and its
CRC or code at the end is the test, failing as one unconfirmed password does (davi
2026-10-14, "First survivor"). A lone survivor over a codec is the only key the data can
be under, so a failure past the kept bytes is the codec's or the CRC's, as from a file;
a STORED member's stays ambiguous, as the file read's CRC pass leaves it. A WinZip AES
member whose data ends before its declared size is `TruncatedError` whichever candidate
read it, as from a file. It only matters for a member over the kept bytes, stored
or under a codec that accepts random input, where a wrong candidate passes the cheap
check (1 in 256 under ZipCrypto, 1 in 65 536 under AES). A choice that may change: the
pass could spool the whole ciphertext, walk every survivor to its end and serve the
winner from the spool, once spool limits are designed. The pass decodes as it drains only
an unread sized member whose plaintext fits a link and whose ciphertext is over what it
keeps, and only under `read_link_targets`: that reads a target nobody asked for, and may
ask a provider about a member that turns out to be no link. With it off nothing reads a
target on its own. A kept one is decrypted only once the directory makes it a link,
provider or not, as from a file. A bit-3 one that long is neither kept nor decoded.

A codec stream stops after its end without saying how far past it it read: its
decoder takes input in chunks of up to 1 MiB, and Deflate64 and PPMd cannot say how much
of the last one they used. So the codec half does not count bytes. The reader decodes
until the codec stream ends (a `refuse_input_after_end` stream raises
`DataAfterEndError` at the first byte after the end, which here means "the member is
over": the descriptor itself is input after the codec's end on every valid member),
then the walk looks for the descriptor in the last 4 MiB it handed out: the
four bytes of the decoded data's CRC, with a compressed size equal to their own
position and a ZIP signature after them. A descriptor with one damaged field is found
as the STORED scan finds one, with the decoded CRC and size as the fields it checks
(`match_damaged_descriptor`): a signed one by its signature and compressed size, an
unsigned one by two of its three fields. The reader then reports the CRC or size
mismatch, or the directory contradicts the descriptor at the end of the pass, and the
members after it are read. Only a descriptor with more damage than that stops the walk,
with `CorruptionError`.

Because the descriptor dates the end from its own position, bytes between the codec's
end and the descriptor count into its compressed size. DR-3's check that nothing
follows the codec's end, which a sized member gets, is not available for these members:
a member with junk there fails from a file and reads from a pipe. Only a crafted
archive has that shape, so DR-5a lets the two reads differ.

PPMd holds its input until the whole member is in, and hands it to pyppmd whole: fed in
pieces, pyppmd can crash the process on corrupt input. A bit-3 PPMd member has no size
to wait for, and holding until the source ends would hold the rest of the archive, so it
is fed in pieces and always in a child process; `max_ppmd_held_input=None`, which
rules children out, refuses it with `ResourceLimitError`. pyppmd stops at the end mark
and reports what it did not use (measured, in-process and in the child).

### What only the central directory says

The external attributes (Unix mode, symlink and special-file bits, the DOS reparse
bit), "version made by" (the host, which decides `created` against `ctime`, and how a
backslash reads) and the member comment are in the central directory only. In a forward
read they arrive after every member. Measured: libarchive's streaming reader (`bsdtar
-xf - < x.zip`) never reads them, and writes an Info-ZIP symlink as a 5-byte regular
file with mode 0664.

archivey reads them and applies them at the end of the pass, so that streaming and
seekable extraction end up the same on disk (the 2026-10-02 ruling):

- `stream_members()` yields each member with what its local header gives (name, flags,
  method, sizes, times from the local extra fields). `mode`, `create_system` and
  `comment` are `None` until the directory has been read, not guessed. The type cannot
  be `None`: it is `FILE` or `DIRECTORY` from the name until then. A name ending in
  `\` is a `DIRECTORY` until then, because a DOS or Windows writer marks its folders
  that way, and a folder written as a file would stop every member inside it from being
  written. A Unix host makes it a file: an empty one is written at the end of the pass,
  and one with data fails there, its bytes passed (only a crafted archive has one).
  Then the members already yielded are updated in place (`ArchiveMember` is mutable,
  ADR 0007), before the pass ends. Each such member has `member_state_final` false
  until then (question D), so a caller sees the gap on the member before reading
  anything (DR-8).
- *The extraction side of the four bullets that follow is replaced by the
  `pipe-zip-stage-then-commit` change:* extraction now stages each member's data in a
  private directory under the destination during the pass and places the members only
  once the directory is read, so nothing below is written, revised, moved aside or taken
  back in the destination. The reader side stands as written.
- Extraction writes each member as it arrives, then at the end of the pass applies modes,
  turns a member the directory types as a symlink into a link (its target is the data
  just written, at most the link-target cap), and removes what it wrote for a member the
  directory types `OTHER`. A folder it wrote for a member the directory makes a link goes
  too, with the parent folders it made for that member alone, while they are empty. For a
  Windows reparse point the target is in a buffer up to 64 KiB long, and a tag that names
  no link makes the member a file again, so of data over the link-target cap the pass
  keeps the start a reparse buffer's parse reads (the 8-byte header, the payload a link
  tag declares, and one byte), decoding that much of a member nobody read, whatever
  `read_link_targets` says (no key or provider is involved). When that byte reaches the
  data's end, as it does for an unpadded buffer, the data's CRC is checked, as the file
  read's byte past the buffer checks it. An encrypted member nobody read is the
  exception: no key is derived for it and the pass keeps no ciphertext of data that
  decodes past the cap, so its target read fails from a pipe, saying so, where a file
  read decrypts it. It keeps none of a buffer longer than a symlink's with both names at
  the target cap (16 408 bytes), which Windows does not write: the read of such a link's target fails
  as a damaged one's does (`SYMLINK_TARGET_UNAVAILABLE` at listing, a failed member in
  extraction) where a file read reads up to 64 KiB of it. Each such member costs a
  decoder (about 0.1 ms, more for PPMd), which a file read does not spend on a member it
  does not read. A member the directory renames (a DOS host makes `\` a separator) is
  written again under its name, from the bytes already on disk. It only touches what it
  created (DR-18). This is the same end-of-pass step that already resolves links in a
  streaming pass.
- A member whose type the directory changes goes through the caller's `filter` and the
  extraction policy's checks **again**, on the updated member (name, type, link
  target), before the link is made, exactly as `extract_all` already calls the filter
  again for a link target it reads after the filter ran (`safe-extraction`, the
  `read_link_targets` paragraph). If either refuses it, the regular file written for it
  is removed and the refusal is reported as for any refused member. A symlink that
  escapes the destination is therefore refused from a pipe as from a file. Links are
  made only after the last member has been written, so no member is ever written
  through one.
- The selection is made again too, on what each member became. A `members=` list is
  matched during the pass against every name a member can end with (with `\` as a
  separator or not, with or without a folder's trailing `/`), so the data of any
  member it may select is written while the stream holds it; at the end the list
  selects for good, and what it no longer takes is removed with no result, and
  nothing is recorded as matched before then. A member a `members=` predicate or the
  filter left out during the pass is asked about again at the end; if it is taken
  then, it is written when it needs no bytes the stream has passed (a link, whose
  target the reader kept, a folder or an empty file) and fails otherwise. That
  failure is the one place a forward pass cannot match the seekable one: a filter
  that selects by a name only the directory gives (a DOS name, `docs/` against a
  stored `docs\r.txt`) sees the stored name during the pass on POSIX (on Windows
  it already sees `docs/r.txt`). The member fails with `ExtractionError`, as a
  hard link whose source a forward pass has passed does: the archive is sound. A
  `members=` predicate is called twice for every member, and the filter twice for
  one it left out; both read `member_state_final` as `False` on the first call, so
  either can tell the two apart. A member first handled at the end of the pass is
  reported to `on_progress` then. A member the pass writes is reported when it is
  written, so progress moves while the stream is read; one the end of the pass then
  leaves out was reported all the same, and from a pipe `members_done` can count a
  member the report does not hold. Holding every tick until the directory is read
  would leave a pipe extraction with no member progress at all until its end.
- What the pass writes before the end of it decides must be undone without loss. An
  entry the caller had at a destination the pass replaces (`overwrite="replace"`) is
  moved aside and put back at the end of the run unless the member still lands there
  (on Windows a read-only entry is not moved, so the member fails as it does from a
  file). A run that stops before the end of the pass (`abort_on`, `on_error="stop"`, a
  limit) never learns which members it keeps, so a write over a caller's entry is
  taken back and the entry returns. It never learns which members are links either,
  and a link the pass wrote holds its target as a file's content, so every file it
  wrote whose data could be a link's is taken back: one within the 4096-byte target
  cap, or one that starts with a Windows symlink or junction reparse tag. The longer
  files it wrote stay, as a stopped run's do, without the modes only the directory
  gives. One that stops while the end of the pass settles keeps what it settled, and
  takes back the files of the members it had not settled yet that could be links.
  Two effects outlive the take-back. `abort_on` fires before a write begins, which for
  such a member is before the end decides, so a run can stop for a member that would
  not have been selected; deferring it would mean writing the member it exists to
  stop. And the bomb limits: what the pass writes is on disk while the pass runs, so
  it is counted then and given back when it is taken back. A member the selection
  takes only provisionally (a Unix `x\y` that a list naming `x/y` may take) can
  therefore stop a run under `max_entries` or `max_extracted_bytes` that the same
  bytes from a file complete. Not counting it would let an archive write unbounded
  data the run then deletes.
  So does `on_error="stop"`: a member whose data fails as the pass writes it stops
  the run, though the directory may then not list it (an unlisted local entry, which
  random access never reads).
- The directory is authoritative. Each local entry is matched to its directory entry by
  offset. A local entry no directory entry points to (an appended update, a planted
  member) is removed from disk and reported: data outside any member is a warning
  (DR-3), and the seekable read never sees it. A name, CRC or size that differs
  between the two follows the answer to question A, as in seekable mode. A directory
  entry with no local entry in the stream is a failure of that member at the end of the
  pass (DR-2; next section).

### Other shapes the walk meets

- A stub before the first local header (self-extractors): when the detector reports
  `payload_offset`, the walk starts there. The detector finds it only within its scan
  budget (2 MiB, or 256 KiB under `FAST`), and a caller can name the format and skip
  detection. When the stream does not start with a local header or an end record and no
  offset was given, the walk scans forward for a local header that the detector's ZIP
  hit validator (`validate_zip_local_header`) accepts, within the same 2 MiB window
  (`SFX_MAX`), and starts there. Nothing found in the window is `CorruptionError`
  naming the reason, unless the stream ends within the window on an end record: then
  the stub and what follows go to the tail, as for an archive whose members are gone,
  and an empty archive behind a stub opens as from a file. In the seekable read a
  missed stub costs nothing, because `base` recovers the offsets; the forward walk
  has no end record to recover them from until the end.
- Everything after the last member is kept and parsed by the seekable read's own code:
  bytes before the directory (an APK signing block, for one), the directory, the end
  records, the comment and anything after it. `find_end_record` runs over them, then
  `CentralDirectoryWalk` over the directory the record places, so the pass picks the
  end record a file read picks (a decoy in the comment included), reads exactly the
  bytes the declared directory size covers, and raises on an entry that runs past them
  as the file read does. What the pass keeps is bounded by the
  listing limits: each entry's 46-byte header and its text, plus four end-record
  search windows (`_tail_bound` in `zip_forward_reader.py` says what each is for).
  While reading it holds that plus one 64 KiB chunk, and joining the kept chunks at
  the end holds them twice for that moment. Past the bound it keeps the last as many
  bytes, for an archive that ends the stream, and, when a directory or end record
  follows the members right away, the first as many too, read by stepping over the
  directory to the end record when more than the search window follows the archive. A
  directory or ZIP64 end record further from both is `ResourceLimitError`. End records
  that place the directory or the ZIP64 end record among the members' data, which the
  pass has read past, are `CorruptionError`; a file read would read them there. A
  ZIP64 end record right before its locator that passes the file read's checks,
  shifted from where the locator places it by no more than the bytes before the first
  local header, is read instead, as a file read reads it behind a self-extractor stub.
  Two cases a forward read cannot take, where the seekable read can: a stub longer
  than the kept bytes, which could hide a record at the locator's own offset that a
  file read not told where the archive starts (`format=` skips the detection that
  slices the stub off) would take instead; and a gap after a last member with bit 3
  set (a descriptor counts only when a ZIP signature follows it, which is what stops a
  planted one inside STORED data). Recognising an APK signing block by its own size
  fields would cover the second; it is not done.
- Bytes after a member that are no local header, before the next member: a gap a
  writer left, a data descriptor after a member whose sizes are in its header, or the
  directory and end record of a first archive with a second appended (`cat`). The walk
  stops there and keeps the rest as the tail. Once the directory has been read, each
  entry pointing into the kept tail is read from it at that offset, a walk of one
  local entry each, and yielded before the pass ends; only offsets the directory names
  are read, so the pass yields nothing there the file read does not list. An entry
  whose bytes the bound dropped is `ResourceLimitError`, as a directory there is.
  Every byte each attempt consumes is counted, a member read or a local header that
  fails to parse, and an entry reached once that count equals the bytes held is
  `CorruptionError` before it is read: the entries overlap, which no writer lays out
  and no limit relieves, so the kept bytes are consumed at most twice, not once each.
  A local header that does not parse fails its entry, with that reason. A bit-3 member
  before such bytes still ends the pass: its descriptor counts only with a ZIP
  signature after it (the table above).
- An empty archive: the stream starts with the end record.
- Order: members come in file order. A seekable read lists them in directory order.
  Writers put both in the same order; when they differ, `is_current` follows the
  directory once it has been read: of two members with the same name, the current one
  is the later in the directory, in both modes. Member ids and the order of the listing
  stay those of the file: the pass handed the ids out as it went. A streaming
  extraction writes copies in file order, so when the directory order of two same-name
  members is the reverse of their file order, the file on disk holds the copy the
  directory supersedes. That is a failure of the current member at the end of the pass
  (§"Failures found at the end of the pass"). Writers do not produce this; a crafted or
  hand-edited archive does. `stream_members()` raises nothing for it: the members are
  updated in place, `is_current` included, and `member_state_final` said so.

### Failures found at the end of the pass

Five things are known only once the directory has been read: a size or CRC from a data
descriptor that differs from the central entry, a local header the central entry
contradicts in its CRC, sizes or encryption flag, two same-name members whose directory
order reverses their file order, a directory entry with no local entry, and a member
whose directory entry and local header store different names (question A, case 3: the
seekable read refuses it when it reads the local header, and a forward pass has both
names only now). The pass reads and checks a member's data as its local header describes
it, and the file read as the directory does, so where the two headers differ the file
read reads other data or fails the member. The method does not count, nor the CRC of a
WinZip AE-2 member, which no read checks: data that matched the CRC and size the
directory gives is the data it describes, and a file read decodes by the local method
too, reporting `MEMBER_LOCAL_METHOD_DIFFERS` as the pass does (2026-10-21). A local name
that is not UTF-8 under the UTF-8 flag is read as unflagged for the pass, and the name
check fails the member, as the file read fails it. Each is a member-scoped failure of the
member it names, handled as `safe-extraction` handles any other (the `OnError`
requirement):

- In `extract_all`, the end of the pass settles every member the directory changes
  (its `is_current`, type or sizes), and every path such a member was written to:
  - **The member's own result** becomes the one the seekable extraction of the same
    archive gives it, revised in place as the `OVERWRITTEN` rows revise a result. Where
    that result needs bytes the stream has already passed (the member is now current
    but its data was not written, or its data failed the descriptor check), it becomes
    `FAILED` with `CorruptionError` instead. For a member now current, the overwrite
    policy decides first, as in random access, and the member fails only where the
    write reads the data that is not there: under `overwrite="skip"` over an existing
    entry it is `NOT_OVERWRITTEN`, and under `"error"` it carries the collision's
    `ExtractionError`. A refusal by the filter or a policy check, which random access
    makes on every copy, stands on a member now not current. A directory entry with no
    local entry never had a result, so one is added: it is handled as any member, and
    the overwrite policy decides first, so it is `FAILED` where the write reads its
    data. Its name counts for which copy is current, as in the seekable listing, so a
    listed copy it follows is not current and is taken back. Results stay in
    member-processing order.
  - **The path.** After the revisions, an entry this run wrote stays only if the member
    whose result names it is `EXTRACTED`. Any other entry archivey wrote there is
    removed (DR-18), and the path is left empty: the bytes the seekable extraction
    would put there are behind in the stream.
  - For the reversed pair (file order `M1`, `M2`; the directory makes `M1` current):
    during the pass `M1` was `SUPERSEDED` and `M2` `EXTRACTED` at the path. At the end
    `M2` becomes `SUPERSEDED` (non-current, never written in seekable mode), `M1`
    becomes `FAILED` (unless the overwrite policy would not write it, as above), and
    `M2`'s entry is removed. For a descriptor mismatch the member
    is `FAILED` and its entry removed.
  - Under `OnError.CONTINUE` the report completes. Under `OnError.STOP` the first such
    failure raises `CorruptionError` naming the member, at the end of the pass, which is
    the earliest point it is known; the revisions and removals above are made first.
- In `stream_members()`, which has no results and no `OnError`, the descriptor mismatch,
  the contradicted local header, the missing local entry and the differing names raise
  `CorruptionError` from the iterator at the end of the pass. The reversed pair raises
  nothing: the members are updated in place and `member_state_final` said they might be.
  Nothing is on disk to settle.

The descriptor mismatch and the reversed pair make a streaming extraction fail a member
that the seekable extraction of the same archive writes, and the contradicted local
header one that it writes differently or fails too. Those three are the only places the
two access modes differ on disk for one member; a member whose two names differ fails in
both, as the seekable read refuses it too. All three come only from crafted or
hand-edited archives, which DR-5a allows to differ a little; matching them would mean
buffering every member until the directory arrives (ADR 0010). The archive-wide refusal
below is the other difference on disk.

One more thing is known only once the directory has been read, and is not a member
failure. A directory entry pointing at a local header an earlier entry already took ends
the pass with its own `CorruptionError`: the seekable read lists both, and a forward
pass reads that data once, for one member. A directory whose entries fill a different
size than the end record declares is a warning (`ARCHIVE_EOF_MARKER_MISSING`, marker
`central_directory`), and every entry stays listed.

Two more differences are recorded (`tests/test_zip_pipe_parity.py`, `_DIFFERS`):

- In `extract_all`, a link member the pass wrote as a file keeps the error its data
  read gave: under no password an encrypted link fails with `EncryptionError`, where
  the file read reports `LinkTargetNotFoundError`; the files on disk are the same.
- What the directory refused as a whole is now read past (davi, 2026-10-14: the file
  read stops refusing what the pass writes). A missing end record makes the file read
  walk the local headers (task 3.0b), and so do end records it cannot use (task 3.0c1,
  §"Damaged ZIP64 end records") and a directory damaged part way (task 3.0c2,
  §"A damaged directory"); a name flagged UTF-8 that is not valid UTF-8 decodes as an
  unflagged one (task 4.1). The two reads write the same files.
  A split set and an encrypted central directory stay refused: no member of either can
  be read.

### Damaged ZIP64 end records

Some writers add ZIP64 end records whether a value needs them or not, so a classic
record often holds every value itself. When the ZIP64 record a locator announces cannot
be used (missing, not matching the locator, or named past the locator) and no classic
field holds the ZIP64 sentinel, both reads use the classic record and report
`ARCHIVE_EOF_MARKER_MISSING` (marker `zip64_end_of_central_directory`, `observed_kind`
`"absent"`, `observed_bytes` the locator's offset); `STRICT` refuses it. Without a ZIP64
record the directory's end is not known from the records, so the parser takes the first
place, of where the locator names the record, right before the locator and the locator
itself, that sits `cd_size` bytes after a central header.

When a classic field holds the sentinel, or no place fits, the end records cannot be
used, and the parser raises as before. The file read then walks the local headers and
lists what they hold, then raises that error, as the pass does when it reaches the end
records (§"A seekable source whose end record is not in the tail"); a directory offset
before the start of the file is read the same way. A locator naming an offset among
the members' data, which the pass has passed, reads the same on both sides: with the
classic record standing in, the pass takes it as the file read does, which differs
only when crafted member data holds a ZIP64 record that matches the locator; with a
saturated classic record, both raise, the pass in its own words. A locator naming bytes
the pass's listing limits dropped stays a `ResourceLimitError` from a pipe, where a file
read lets the classic record stand in: higher limits keep those bytes, and the pass then
reads what the file read reads. A locator naming another disk is still a split set.

### A damaged directory

An entry the directory walk cannot read (a wrong signature, a cut fixed header) ends the
directory's part of the listing. The file read then walks the local headers once
(`ZipReader._past_damage`, the walk a ZIP with no end record gets) and lists every
member whose offset the directory did not already list, from its local header, then
raises the damage, so the listing's error stays a `CorruptionError` and keeps its
members; only a listing limit the walk meets is raised instead. A member whose data the
walk could not get past is listed, and its read raises the walk's error, a cut as
`CorruptionError` since the end record follows it. The walk is made once per reader
(`_local_walk`, the tail search's walk when it made one), and each caller builds the
offsets past the damage from what it listed itself; the index pass and the listing stop
at the same entry, so both list the same members past the damage. The overlap guard
keeps one bound per member, aligned with the ids: -1, which bounds nothing, for a
directory entry before the damage that points at no local header, and the entry's offset
when a local header starts there, whether or not the walk reached it (a header inside
another member's stated data is real, and two entries over it stay an overlap). The
members past the damage take part in which copy of a name is current. The pass gets the
same result from the other side: it applies the directory to the members described
before the damage, keeps the rest as their local headers say without reporting them as
unlisted, and raises the damage at the end, ahead of a check a member before it fails,
which fails only that member.

A stored directory offset larger than the directory's position gives a negative `base`.
That is not damage: a stub sliced off the source (`start_offset`, a zipapp whose
offsets count from the file's start) gives the same shift. When the offsets it moves
land on no local header, every read fails from a file and the pass lists none, so
neither read writes anything, as Info-ZIP unzip and 7-Zip extract nothing.

### What the caller sees in a forward pass

| Field | During the pass | After the end record |
| --- | --- | --- |
| `cost.listing_cost` | `REQUIRES_SCANNING`: members are found by walking local headers | same |
| `cost.access_cost` | `DIRECT`: each member's data is independent | same |
| `cost.stream_capability` | from the source (`FORWARD_ONLY`), as TAR does | same |
| `member_count` | `None` (DR-1): the count is in the end record | the number of directory entries |
| `comment` | `None` | the archive comment |
| `members_report_if_available()` | `None`, as `access-mode-and-cost` already states for a trailing index on a non-seekable source | the complete report, as for TAR after a completed pass |

`get_archive_info()` builds a new `ArchiveInfo` on each call, so a call after the pass
returns the count and the comment.

### Seekable sources under `streaming=True`

A seekable source in streaming mode reads the directory first: one read at the tail,
then forward reads only, and every member is complete when yielded (question C,
answered). The local-header walk is for non-seekable sources, and for a seekable one
whose end record the tail search does not find (next section).

### A seekable source whose end record is not in the tail

The tail search reads the last 65 558 bytes. An archive followed by more trailing data
than that, or one whose end record and directory are missing (a download cut short, a
copy that stopped early), has no end record there, while the same bytes from a pipe
read through the walk above. The maintainer's ruling (2026-10-12): when the end record
is missing or buried, scan the local headers anyway, return the members, then raise as
an incomplete TAR does; when the scan reaches the end record, update the members from
the directory, as a streaming pass does.

When the tail search finds nothing, the reader runs the local-header walk over the
seekable source from its start (past the stub the detector found, which the reader
slices off). The walk seeks over a member's data when its local header states the size,
so in the common case it reads only the headers; a bit-3 member's data is scanned for
its descriptor, as from a pipe, and nothing is decoded. The walk keeps each member's
header offset and, for a bit-3 member, its descriptor's CRC and sizes. Where the walk
ends decides the result, in the words a pipe read uses for the same bytes:

| The walk ends at | Result |
| --- | --- |
| A central directory and a valid end record | The archive is whole and is read through its directory, as when the tail search finds the record. The bytes after the end record go through §"Trailing bytes": `ARCHIVE_TRAILING_DATA`, a warning by default. No error (the maintainer, 2026-10-12) |
| End of file on a member boundary, inside a local header, or inside the directory or end record | Every member found is listed or extracted first, then `TruncatedError`: the directory is required, so its absence is an archive cut short |
| End of file inside a member's data, or a bit-3 member whose descriptor the scan does not find | That member is listed last, as a pipe read lists it, and the listing then raises the walk's error naming it (`TruncatedError` for a cut); reading it raises the same error |
| Bytes that are neither a local header, a directory header nor an end record, after a member | The members before them are listed, then `CorruptionError`, as for a rejected TAR header |
| Bytes that are no ZIP record after a whole directory | The members are listed, then `CorruptionError`: the directory is there, so the archive is damaged rather than cut |
| Any of these before the first member (no local header at the start, or one cut short) | The walk's error at open, as the pipe read raises it at open |

Members come from their local headers as a pipe read builds them before its directory
arrives (§"What only the central directory says"): no mode, `create_system` or
comment, and a bit-3 member's CRC and sizes from its descriptor, which a read checks
the data against. No directory comes, so they are final: `member_state_final` is true.
A deflated or encrypted bit-3 member's descriptor is not checked at open (the walk
decodes nothing), so a descriptor that lies is listed with the size and CRC32 it
states, as a directory entry would be, and its read and extraction fail by the size,
digest or declared ratio check; a pipe read lists the size it measured, and no CRC32
when the data does not match the descriptor's, and fails the member at the end of its
data, in different words. Junk after a bit-3 member makes the two reads raise in
different words: the pipe decodes the member and looks for a descriptor with its CRC,
the file read for one followed by a ZIP signature.

`members()` is complete-or-raise; `members_report()` returns the members found and the
error; `__iter__` yields them, then raises; `extract_all` writes them, then raises. This
is the `partial-members-and-errors` model TAR already uses. The listing limits charge
each member as it arrives, and the walk charges `max_members` on each local header.
`member_count` is `None`. The fallback runs only when the tail search fails, so a
normal archive pays nothing for it.

A walk that meets more local headers than `max_members` stops there and the archive
opens. The listing then raises the limit as when the directory's entries cross it:
a streaming pass, from a file as from a pipe, yields the members before it first, and
a random-access listing lists none, since there only damage keeps the members before
it. After that streaming pass `members_report_if_available()` returns `None`, as for a
pipe read; it is the general rule for a streaming pass that raised a limit, which a
whole ZIP crossing the limit in its directory follows too.

## What the parser removes

| Workaround today | Where | Replaced by |
| --- | --- | --- |
| `_zipfile_private("_EndRecData")` and six `_ECD_*` indices | `zip_reader.py:246-263` | `EndRecord` |
| `_find_classic_eocd`, a second end-record search | `:2257` | `find_end_record` |
| `_central_directory_overrun`, a second directory parse | `:2399` | walk findings |
| `_end_record_findings` re-reading the record stdlib read | `:2296` | walk findings |
| `_classic_eocd_declares_split` after stdlib listed a spanned part | `:2431` | disk fields in `find_end_record` |
| `_looks_like_multivolume`, matching `BadZipFile` text | `:2545` | the same |
| `_central_directory_looks_encrypted` after stdlib failed | `:2496` | checked before the walk |
| `ZipInfo._raw_time` for the ZipCrypto check byte | `:1161` | `CentralEntry.dos_time` |
| `ZipFile._lock` | `:1180` | reader-owned re-entrant lock |
| `ZipInfo._end_offset` for the overlap guard | `:1266` | offset array |
| cp437 round trip of `orig_filename` to get the stored bytes | `:1013-1018` | `CentralEntry.name` |
| The `ZipFile` subclass overriding `_RealGetContents` (Unicode Path PR) | open PR | nothing: stdlib never sees the field |
| `UnicodeError` at open for a flagged name that is not UTF-8 | `:817` | per-name decode (stage 3) |
| `NotImplementedError` at open for version needed above 6.3 | `:826` | nothing at listing (below) |
| `BadZipFile` / `ValueError` / `NotImplementedError` arms in `_translate_exception` | `:863` | the parser raises typed errors |
| `_ZIP_MEMBER_READ_ERRORS` entries for stdlib's exceptions | `:326` | shrinks to the codec-side ones |

## Behaviour that changes

Each row lands in the stage PR that causes it, with the spec and handbook edits (DR-22).

| Input | Today | Native | Rule |
| --- | --- | --- | --- |
| A name flagged UTF-8 that is not valid UTF-8 | `CorruptionError` at open, nothing listed | The flag is wrong for that name: it decodes as an unflagged name does (UTF-8 is already ruled out, so `encoding=`, else the configured fallback) and `MEMBER_NAME_ENCODING_INFERRED` names the codec used, with `declared_encoding="utf-8"`. 7-Zip and `unzip` read the rest too | DR-2; the 2026-10-07 ruling that `encoding=` only replaces the fallback |
| A directory entry with a bad signature, or a directory the file cuts short | `CorruptionError` at open | The entries before it list; the walk then raises `CorruptionError` or `TruncatedError` at that entry | DR-2, as a cut RAR already does (list, then raise) |
| Version needed above 6.3 | `UnsupportedFeatureError` at open, nothing listed | Listed; a member raises `UnsupportedFeatureError` only when its method or a flag is one archivey cannot read | DR-4, DR-2. Measured on a STORED member marked 8.4: 7-Zip 23.01 ignores the field and reads it; `unzip` 6.0 skips that member and reads the rest. Both read the other members |
| Malformed Unicode Path field | Depends on the Python version until the Unicode Path PR merges | Same as that PR, on every version, without the subclass | DR-5 |
| `streaming=True` on a non-seekable source | `StreamNotSeekableError` at open | Read forward (§"Streaming") | The maintainer's request, 2026-10-10 |
| A ZIP64 archive whose directory is Strong-Encrypted | `CorruptionError` | `UnsupportedFeatureError` | DR-4 |
| Bytes after the end record and its comment | Nothing reported | `ARCHIVE_TRAILING_DATA` warning; strict refuses; zero padding stays silent. 7-Zip 23.01 warns on the same input, `unzip` says nothing. Examined as TAR's tail is, in both modes: at most 1 MiB past the comment's end, first non-zero byte reported, `expected_marker="zeros_to_eof"` (§"Trailing bytes") | The 2026-10-07 ruling (davi): report trailing data after ZIP, 7z, RAR and ISO, as TAR and the codecs already do. Stage 2 |
| A ZIP from a pipe whose data descriptor understates a STORED member, or whose directory lists two same-name members in the reverse of their file order | Not readable at all (non-seekable source refused) | That member fails at the end of the pass (`FAILED` under `OnError.CONTINUE`, a raise under `STOP`); the seekable read of the same archive writes it. Of the shapes no writer produces, the only on-disk difference between the two modes; damage adds one, a bit-3 member whose data descriptor has one damaged field (`dev-docs/formats/zip.md` §2.2.2) | DR-5a: only crafted archives have these shapes, and matching would mean buffering every member (ADR 0010). Stage 3 |
| A member flagged as a Windows reparse point whose data is not a reparse buffer, in a `stream_members()` pass | Yielded as a SYMLINK with no stream, retyped to FILE after the pass: its content is lost | Typed when the pass reaches it, by reading the bounded reparse header ahead and handing back a stream of the whole member, as 7z already does; `members()` already lists it as FILE. From a pipe the reparse bit arrives with the directory, so such a member is written as a file and stays one, and only a real reparse buffer becomes a link (§"What only the central directory says") | DR-5, DR-1. Stage 3 |
| An end record whose comment and trailing bytes total exactly 65 536 bytes (a maximal comment and one junk byte), on Python 3.13 and later 3.12 releases | `BadZipFile`, so `CorruptionError` at open | Listed; the junk is trailing data. Where stdlib keeps the older window (3.11, early 3.12) it already reads it | The wider window reads everything either stdlib window reads (§"Layout"). Stage 2 |
| A damaged ZIP64 end record or locator | `CorruptionError` at open, nothing listed | The classic record's values when none is saturated, with `ARCHIVE_EOF_MARKER_MISSING`; otherwise the local-header walk lists the members, then raises the same `CorruptionError`, as a pipe read does | The maintainer's ruling, 2026-10-14. Stage 3 |
| A ZIP followed by more than 64 KiB of other bytes, or with its directory and end record missing, from a seekable source | `CorruptionError` at open, nothing listed | Read by the local-header walk (§"A seekable source whose end record is not in the tail"): a whole archive opens with `ARCHIVE_TRAILING_DATA`; a missing directory lists or extracts the members found, then raises the walk's error (`TruncatedError` for a cut), in the words a pipe read uses | The maintainer's ruling, 2026-10-12. Stage 3 |
| Open of an archive with a huge declared directory | All `ZipInfo` built at open | Members built as listed; `ListingLimits` stop the walk | DR-9a, DR-15b |

Nothing else may change. The acceptance bar is the full suite as it stands once the
three ZIP fix PRs have merged, plus a differential test: for every ZIP under
`tests/fixtures/`, every archive `tests/create_adversarial.py` builds and the sample
corpus, the parser's entries match `zipfile.infolist()` wherever `zipfile` opens the
archive.

- **Compared, per entry:** the stored name bytes, header offset, both sizes, CRC, flags,
  method, create system, both version bytes, both attribute fields, extra, comment,
  `date_time`, the raw DOS time and whether the name ends in `/`. The disk number is
  compared unless stdlib holds the ZIP64 sentinel `0xFFFF`. Per archive: the directory
  start and the archive comment.
- **Not compared, and why:** the decoded name (the parser returns bytes; stdlib's
  `orig_filename` is re-encoded with the codec the flag names, which recovers the stored
  bytes exactly); `filename`, which 3.12+ replaces from the Unicode Path field; and
  `_end_offset`, which is not a stored field.
- **Where the parser parts from stdlib on purpose**, each its own test rather than the
  comparison: a cut or overrunning extra field (stdlib refuses the archive, the parser
  keeps it), a ZIP64 extra field that is absent although a value is deferred (both
  keep the 32-bit value), the decoy end record in a comment, and one byte of junk after
  a maximal comment (the search keeps stdlib's older window, which 3.13 and later 3.12
  releases shrank by one byte, so there stdlib refuses that archive and the parser
  reads it).
- **Interpreters:** the comparison runs on every Python in the CI matrix. stdlib's
  version differences (the Unicode Path field from 3.12, the end-record search window
  one byte shorter from 3.13 and in later 3.12 releases) change only whether it opens an archive, never a
  compared field, so on each version the test compares what that
  version opens and a floor on the count of compared archives stops it comparing
  nothing.
- **Shown to fail** against three mutants: the header offset without `base`, the ZIP64
  sizes read compressed-first (caught only by a test with both sizes deferred and
  different, added for this), and the two attribute fields swapped.

## Stages

One PR each, in order; every PR goes through the review label.

1. **Parser.** `zip_parser.py` and its tests: unit tests on hand-built records, the
   differential test above, ZIP64 (sizes, offsets, entry count), stub prefixes. No reader
   change.
2. **Switch the reader.** `zip_reader.py` reads through the parser; every row of the
   removal table except the name decode. Damaged-directory and version-needed rows of the
   behaviour table, and trailing bytes reported (§"Trailing bytes"). ADR 0006 is
   superseded by a new ADR; format-zip spec, the `diagnostics` spec row and the
   `ArchiveEofContext` docstring for `"zeros_to_eof"`, `docs/gotchas.md` (trailing data
   and the open-pipe note), handbook §2.2, §5 and §6 updated.
3. **Streaming**, in three PRs: 3a the forward walk in the parser layer
   (`zip_local_walk.py`, no reader change); 3b the reader over a non-seekable source and
   the end-of-pass reconciliation; 3c a seekable source under `streaming=True` and the
   fallback when the tail search finds no end record. Together: the forward
   local-header walk and the end-of-pass reconciliation, for non-seekable sources
   (seekable ones read the directory first, question C), and for a seekable source
   whose end record the tail search does not find (§"A seekable source whose end
   record is not in the tail"). `stream_members()` and
   `extract_all()` over a pipe, tested against the same archives read seekably: the
   files on disk must match. This stage changes a public declaration: ZIP's
   `SUPPORTS_STREAMING_NON_SEEKABLE` becomes true, so `required_source` for ZIP moves
   from `SEEKABLE` to `FORWARD_ONLY`. Specs and docs that move with it: format-zip,
   `backend-registry` (the `required_source` table), `access-mode-and-cost` (the
   trailing-index row), `safe-extraction` if the filter re-run needs a sentence there,
   `docs/access-and-cost.md` (the checklist tells users to buffer ZIP),
   `archive-data-model` (the new `member_state_final` field, every format),
   `archive-reading` (ZIP applies `max_members` at parse, in every mode) and the
   `ListingLimits` docstring in `config.py` that restates it, `docs/formats.md`, handbook
   §1, §2.2, §5, §6, and the TAR, 7z and RAR handbook pages for which of their fields
   `member_state_final` covers. The user docs, threat model and docstrings that restate
   either contract ("7z, RAR and ISO" apply `max_members`; "ZIP, 7z, RAR and ISO" have
   to seek) are listed in task 3.5a, found by that grep, which stage 3 reruns.
4. **Names.** The lying UTF-8 flag. Name collisions stay ordinary duplicates
   (question B, answered). Format-zip spec, handbook §2.2 and §5, `docs/formats.md`,
   and the DR-21 ruling in `design-rules.md`, which says the refusal lasts until this
   rewrite.
5. **Header disagreement.** Cases 1 and 2 read with a new diagnostic code (its name goes
   to the maintainer in the PR); case 3 stays refused (question A, answered).
   Format-zip spec, `docs/errors-and-diagnostics.md`, handbook §5, and
   the backup-scan investigation's §3.3-3.4 status.
6. **ZIPs over 4 GiB without ZIP64.** macOS Finder writes a classic ZIP past 4 GiB and
   stores every offset modulo 2³². The rule recorded in `IDEAS.md`: offsets must
   increase, so when one falls below the furthest end of the members before it, add
   2³² until it does not; the end record's directory offset follows the same rule. It applies only when a
   local header with the entry's name sits at the corrected offset, the CRC check stays,
   and a diagnostic records the correction. A single member over 4 GiB wraps its sizes
   too. davi's tests on a current Mac (2026-10-15) settled it, as stage 6b: under the
   writer's fingerprint the compressed size comes from the layout and the size from
   deflate's ratio bound, or stays unknown (`None`, `extra["size_mod_2_32"]`) until a
   verified read fills it in (handbook §3). The diagnostic may
   need a new code, which goes to the maintainer. Format-zip spec, handbook §3 and §5,
   `docs/formats.md`, and the `IDEAS.md` item, which this stage closes.
7. **Methods 1 (Shrink) and 6 (Implode). Deferred until after 0.2.0** (the maintainer,
   2026-10-13): the decoders are small, but no current writer produces these methods, so
   fixtures mean old archives or a test-only encoder, and the algorithm names are new
   public values. Until then such a member lists and its open raises
   `UnsupportedFeatureError`. The plan when it is picked up: two small pure-Python
   decoders under `internal/streams/codecs/`, registered with the codec layer like the
   others (DR-20: no native code). Only DOS-era archives use them, so speed does not
   matter. They need `CompressionAlgorithm` members, which are public names and go to
   the maintainer. Format-zip spec, `docs/formats.md`, handbook §2.3.

Stage 6 is independent of 3 to 5 and can run beside them; stage 7 is deferred.

## Questions for the maintainer

A, B and C were answered by the maintainer (davi) on 2026-10-10 in the thread that
commissioned this change. The format-specific rulings (A, B) are recorded in
`dev-docs/formats/zip.md` §6 and C, which is not ZIP-specific, under DR-8 in
`dev-docs/design-rules.md`; the text below keeps the reasoning they were asked with.

**A. Central and local headers that disagree.** Answered (davi, 2026-10-10): read cases
1 and 2 with a new diagnostic (strict refuses), keep refusing case 3, as recommended
below. Archivey refuses a member in three cases that `unzip` reads, found by the
backup-drive scan (`dev-docs/investigations/2026-10-backup-scan.md` §3.3-3.5; each
pinned by an `xfail(strict)` test in `tests/test_audit_backup_scan.py`). ZIP has no
single official tool (design rules, Open gaps), so DR-6 does not settle it.

| Case | `unzip` | 7-Zip | Recommendation |
| --- | --- | --- | --- |
| 1. Name differs (another code page, or `\` against `/`) | warns, reads | reads | Read, with a diagnostic. archivey takes every field from the central directory, so the local name decides nothing; the spoofing risk is for tools that trust the local header |
| 2. Central CRC 0, local CRC right (every Adobe AIR package) | reads (checks the local CRC) | headers error | Read, verified against the local CRC, with a diagnostic. The data is still checked |
| 3. Both headers understate the size, CRC matches the full output | reads | fails | Keep refusing. The declared size is the bound that stops decoding (DR-9a), and one archive in the scan has it |

Reading cases 1 and 2 needs a new diagnostic code (a public name). Strict refuses both.

**B. Two stored names that decode to the same name.** Answered (davi, 2026-10-10): keep.
The per-name decode can turn `c3 a9` (valid UTF-8) and `82` (cp437) into the same
`é.txt`; the later member supersedes the earlier one like any duplicate
(`is_current=False`, `SUPERSEDED` on extraction, the two `raw_name`s differ). No new
public name.

**C. A seekable source under `streaming=True`.** Answered (davi, 2026-10-10): directory
first. One read at the tail, then forward reads only; every member is complete when
yielded (DR-8), and nothing needs fixing at the end. The local-header walk is for
non-seekable sources only.

**D. How a caller sees that a forward pass fills some fields only at the end.**
Answered (davi, 2026-10-10): a per-member field saying the member's state will not
change again, named `member_state_final` (davi chose an explicit name over
`is_final`, which reads like `is_current` and `is_dir`, and kept it on 2026-10-13).
The cost receipt was rejected: it describes what listing and reading cost, not whether
a member's fields are settled. The field is not ZIP-specific. It is false wherever
archivey can still update a member in place: a ZIP member yielded in a forward pass
until the directory has been read; any member of a forward-only pass in any format
(TAR included) until the pass ends, because a later member with the same name can still
make it `is_current=False`; and a link whose target is stored as member data until that
target has been read (`read_link_targets=False`, or a listing from the index alone). It
is true everywhere else, so a caller checks it on each member before reading anything.
Its documented meaning is "any field of this member may still change"; each format's
handbook page and `docs/formats.md` name which fields that is in practice (for a ZIP
forward pass, any field the directory builds: above all type, name, where a DOS host
makes `\` a separator, mode, host, comment, times from the directory's extra fields,
and `is_current`; for a data-stored link: the target).

## Out of scope

- Listing an archive whose directory is lost, by walking local headers forward. The
  walk above is the tool for it; it stays an idea for later (`IDEAS.md`).
- Info-ZIP spanned sets (`.z01`…`.zip`). The parser exposes `disk_start`, which is what a
  later reader would follow; they stay refused.
- Writing.
- Spooling a pipe (the open `bounded-source-spooling` change). Its proposal says ZIP,
  7z, RAR and ISO refuse a pipe under both `streaming` values; after stage 3 that holds
  for ZIP under `streaming=False` only, and whichever change lands second updates the
  other's text. Stage 3 edits that proposal's sentence if it is still open then.

## Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Parse lazily, member by member | `ListingLimits` see each member as it is read; open does no work proportional to the archive (DR-15b); a damaged entry costs only the entries after it (DR-2) | Parsing the whole directory at open, as stdlib does |
| Parser returns bytes; the reader decodes | Name decoding is policy (`encoding=`, fallback, diagnostics) that already lives in the reader and is shared in shape with RAR and TAR | Decoding in the parser, which is how stdlib ended up refusing whole archives |
| Keep stdlib's end-record search and `concat` rule | Prefixed archives and decoy signatures in comments resolve exactly as today (on newer Pythons one more archive opens, below), and the differential test can compare against stdlib | 7-Zip's search, which differs on crafted inputs and would change detection results |
| Stop the walk at `cd_size`; an entry whose fields run past it, or hold the entries after it, is damage | Cutting the field listed a member named after the swallowed entries' bytes and dropped those entries, with only a count warning, where a pipe listed them all (DR-1, DR-5); as damage, both reads list every member from the local headers and raise | Cutting the field at `cd_size` as stdlib does (the earlier choice; superseded by davi's 2026-10-17 ruling, PR 860); reading the field from past the directory, which changes names on crafted input |
| Apply central-only fields at the end of a forward pass | Matches seekable extraction on disk without buffering anything (ADR 0010) | Treating every member as a regular file, as libarchive does (a symlink becomes a file: DR-1); spooling the archive to find the directory first |
| Positioned reads through a `read_at(offset, n)` callable for the directory walk | The walk is lazy, so it runs between reads of member data on the same handle; a positioned read under the reader's lock leaves the handle where the member stream needs it, and the parser stays free of locking | A `LockedStream` over the handle, which serialises each call but shares one position, so every walk read would need a seek and a read as one locked step, which is `read_at` |
| The forward walk reads a `BinaryIO` and counts what it consumed | The same shape as `TarWalker` on a forward-only stream; no new reader type | A separate `ForwardReader` class |
| No charge callback into the ZIP parser | One entry is at most 46 + 3 × 65 535 bytes by the format, and the reader charges each member against the listing limits before asking for the next | Passing `Charge` as the TAR parser does, which it needs because a TAR header declares the size of the record after it |
| Keep `zipfile` in the tests | It writes most fixtures and is the oracle for the differential test | Dropping it, which loses the cheapest independent check of the parser |
