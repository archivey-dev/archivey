# Archive Data Model

## Purpose

Archivey shares one public data model across readers, writers, backends, and
callers: compositional `ArchiveFormat`, member and compression taxonomies,
mutable `ArchiveMember` records, and frozen archive-level `ArchiveInfo`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader methods that return and mutate members in place |
| `diagnostics` | Diagnostic values, budgets, and member attachment rules |
| `safe-extraction` | Path safety and rejection of special files |
| `access-mode-and-cost` | `CostReceipt` carried by `ArchiveInfo` |
| `format-detection` | `ArchiveFormat` detection and detection diagnostics |

## Requirements

### Requirement: Archive format identity is compositional

The system SHALL model archive format as a frozen `(container, stream)` pair:
`ContainerFormat` names the member layout (`zip`, `tar`, `7z`, raw stream, ...),
and `StreamFormat` names the outer single-stream codec (`gz`, `xz`, ... or
`UNCOMPRESSED`). Predefined constants such as `ArchiveFormat.ZIP`,
`ArchiveFormat.TAR_GZ`, `ArchiveFormat.SEVEN_Z`, and standalone
`ArchiveFormat.LZIP` SHALL be class-var instances of that pair.

`StreamFormat` SHALL cover every standalone outer codec Archivey can read:
`UNCOMPRESSED`, `GZIP`, `BZIP2`, `XZ`, `ZSTD`, `LZ4`, `LZIP`, `LZMA_ALONE`,
`ZLIB`, `BROTLI`, and `UNIX_COMPRESS`. Standalone raw-stream constants SHALL
exist for `GZ`, `BZ2`, `XZ`, `ZST`, `LZ4`, `LZIP`, `LZMA_ALONE`, `ZLIB`,
`BROTLI`, and `Z`. Uncommon container-codec pairs such as `tar.lz` and
`tar.lzma` SHALL be constructed on demand as `ArchiveFormat(container, stream)`
rather than receiving named constants; their `display_name` SHALL be derived as
`CONTAINER_STREAM` from the two enum member names (for example `TAR_LZIP`), so
messages never print the constructor form. `file_extension()` SHALL derive from the
stream for raw streams and from `container.codec` for containers.

Constructing `ArchiveFormat` SHALL convert string fields to the enum members,
accepting the same spellings as the other public enum arguments (value or member
name, any case, `-` and `_` interchangeable), so the constructed value holds
members and behaves as the matching named format everywhere, including where
code compares with `is`. An unknown spelling SHALL raise `ArchiveyUsageError`
at construction.

`StreamFormat.LZMA_ALONE` SHALL name the legacy LZMA Alone file format
(`lzma.FORMAT_ALONE`: 13-byte header with properties, dictionary size, and
uncompressed size — not raw LZMA). Its enum value SHALL be `"lzma"` so
`file_extension()` yields `lzma` / `tar.lzma`. It MUST NOT be confused with raw
7z/ZIP `FORMAT_RAW` LZMA1/LZMA2 (`Codec.LZMA` / `Codec.LZMA2`).

#### Scenario: format identity matrix

| Case | Expected |
| --- | --- |
| Compare `ar.format` to `ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP)` | Equal to `ArchiveFormat.TAR_GZ` |
| Open a `.lz` standalone lzip stream | `ArchiveFormat.LZIP`; container `RAW_STREAM`; stream `LZIP` |
| Open `tar.lz` | Equal to `ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)`; `file_extension() == "tar.lz"` |
| Open a `.lzma` Alone stream | `ArchiveFormat.LZMA_ALONE`; container `RAW_STREAM`; stream `LZMA_ALONE` |
| Open `tar.lzma` | Equal to `ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)`; `file_extension() == "tar.lzma"` |
| `ArchiveFormat("raw_stream", "gz")` | `container is ContainerFormat.RAW_STREAM`, `stream is StreamFormat.GZIP`; equal to `ArchiveFormat.GZ` |
| `ArchiveFormat("nope", StreamFormat.GZIP)` | `ArchiveyUsageError` at construction, naming `ContainerFormat` |

### Requirement: MemberType describes filesystem object kind

The system SHALL define:

```python
class MemberType(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    OTHER = "other"
    ANTI = "anti"
```

Windows NTFS junctions SHALL surface as `MemberType.SYMLINK` with
`extra["is_junction"] == True`. `MemberType.OTHER` SHALL always be rejected by
extraction regardless of policy. A device, FIFO, socket or unknown file type that
stores no data SHALL be `MemberType.OTHER` in every format that can record one: TAR by
its typeflag, ISO when a Rock Ridge PX mode is not a regular file (its symlink and
directory records decide first) and the extent is empty, and ZIP from a Unix creator,
7z with `0x8000` and the mode in the attribute's high word, and RAR from a Unix host by
the file-type bits of the stored mode (a mode with no file-type bits is not special)
when the entry has no data stream, even where the format's own tool writes it as an
empty regular file (unzip, 7-Zip): an empty file in its place would hide what the
archive said it was. An entry whose mode names a special file but that owns a data
stream (ZIP, 7z, RAR, ISO) SHALL be `MemberType.FILE` with
`MEMBER_SPECIAL_FILE_HAS_DATA` reported: the stream is the structure and the mode an
attribute, and `OTHER` would hide bytes every official tool writes out (design rule
DR-25). In TAR the typeflag is the structure and GNU tar ignores the size field of a
device or FIFO header, so a header of typeflag `3`, `4` or `6` with a non-zero size
SHALL be refused as `CorruptionError`. A TAR typeflag the reader does not know is not a
special file: with a non-zero size it SHALL be `MemberType.FILE`, as GNU tar extracts it,
and with none `MemberType.OTHER`, both reported with `MEMBER_TYPE_UNKNOWN` (DR-25; the
`format-tar` spec has the rule). Every member whose stored mode's file-type bits
(or TAR typeflag `3`/`4`/`6`) named a device, FIFO, socket or unknown file type SHALL
carry `extra["special_file_type"]` ∈ `{"fifo","char_device","block_device","socket",
"unknown"}`, whatever type the member ends up with (a RAR file copy is `FILE` by its
redirect record; a ZIP directory marker, an ISO directory record or a reparse-point bit
over such a mode makes a `DIRECTORY` or `SYMLINK` that keeps the key), so the stored
kind is never lost; a member that recorded no such mode (a GNU dumpdir, which is a
`DIRECTORY`; an ISO file record with a directory's `S_IFDIR` mode, which is `OTHER`)
has no key. `MemberType.ANTI` SHALL be a
deletion/tombstone marker (`is_file` false, no payload); it SHALL NOT be treated as
`OTHER`.

A directory entry whose header declares data (ZIP, TAR, RAR; no format gives a
directory content) SHALL stay `MemberType.DIRECTORY` with `size` as declared, SHALL
be reported with `MEMBER_DIRECTORY_DATA_IGNORED` (in `ARCHIVE_INTEGRITY_CODES`) once
per member at listing, and SHALL be created as a directory by extraction, as every
official tool does. The one exception is GNU tar's dumpdir (`D`, from `tar -G`): its
data is the directory's contents list at dump time, structure that GNU tar defines and
reads itself, so it is a `DIRECTORY` with no `size` and no report, and `open()`
refuses it for declaring no data.
`open()` SHALL refuse a directory for declaring no data, and a tombstone or a special
entry for its type (a special entry that stores data is a `FILE`): `ANTI`, `OTHER` and a
directory declaring no size raise `ArchiveyUsageError`, while a directory declaring data
opens and delivers the bytes where the backend can decode them (ZIP decodes any method;
TAR reads the blocks of an old-style `d/` regular-file header; RAR delivers stored,
unencrypted directory data and raises `UnsupportedFeatureError` for the rest, since
`unrar` emits nothing for a directory entry), checked against the stored digest like a
file's when the header carries one. A ZIP directory entry whose CRC-32 field is 0, the
conventional value for a directory, carries no digest; `DIGEST_UNVERIFIABLE`
(`reason="no_integrity_anchor"`) SHALL say so instead of refusing the bytes as damaged
when that CRC was the entry's only check (unencrypted or ZipCrypto), and when the entry
is WinZip AES (AE-1 or AE-2) its HMAC checks the bytes as it checks a file's, so nothing
is reported. `stream_members()` SHALL yield a stream for the same directories, with the
same bytes and checks, in both access modes, so a forward-only reader reaches them too,
except a ZIP directory written with a data descriptor and read from a source that cannot
seek (`archive-reading`, "stream_members yields a stream for exactly the members open()
reads"). A directory whose declared size is zero SHALL also be reported when its body is
larger than an empty one of its method takes (ZIP: 0 stored, 2 deflated, 14 bzip2, 19
LZMA, any body for a method not in that table; RAR: any body), so a payload cannot hide
one field away; the Java `jar` tool's deflated empty directory body (compressed size 2,
size 0) is not reported. Such a member has no declared data, so `open()` still refuses
it and `stream_members()` yields `None` for it.

A link the source filesystem held as a Windows reparse point — a junction, a Windows
directory symlink or a Windows file symlink — SHALL additionally carry
`extra["is_reparse_point"] == True`, exposed as `ArchiveMember.is_reparse_point`. It
answers the question `is_junction` cannot: whether a `MemberType.SYMLINK` is a POSIX
symlink or a Windows reparse point, which decides whether its target is a Windows path
and whether recreating it on Windows needs a reparse point rather than a symlink.
`is_junction` SHALL remain the narrower claim and SHALL imply `is_reparse_point`.

Unlike `is_junction`, `is_reparse_point` SHALL NOT be gated on `type`: it records what
the archive said about the entry, and a member whose reparse data turns out not to be a
link keeps the flag alongside its re-typed `MemberType`.

`ArchiveMember.link_target_unrecorded` SHALL be `True` exactly for a link
(`SYMLINK` or `HARDLINK`) with `link_target is None` whose archive records no target:
the case extraction records as `LINK_TARGET_UNAVAILABLE` (`safe-extraction`). It SHALL
be `False` for a link whose recorded target this read could not produce, and for one
whose data-stored target has not been read yet (`read_link_targets=False`).

#### Scenario: member type matrix

| Case | Expected |
| --- | --- |
| TAR contains a device node or FIFO † | `member.type == MemberType.OTHER`; `extra["special_file_type"]` names the kind |
| TAR header with an unknown typeflag (`9`) and 5 bytes of data; the same with none | `FILE` with `size == 5` that reads and extracts; `OTHER` with no `size`. Both report `MEMBER_TYPE_UNKNOWN`; neither has `extra["special_file_type"]` |
| ZIP (Unix creator) or RAR (Unix host) entry whose mode is a device, FIFO or socket †, or a 7z one (`0x8000` set), with no data | `member.type == MemberType.OTHER`; `extra["special_file_type"]` names the kind |
| The same entry storing data (`zip -FI` on a named pipe), or an ISO Rock Ridge special mode over a non-empty extent | `member.type == MemberType.FILE`; `size` is the stored size; `extra["special_file_type"]` set; `MEMBER_SPECIAL_FILE_HAS_DATA` with `SpecialFileDataContext`; `STRICT` does not raise |
| ZIP or RAR directory entry declaring 12 bytes of data | `member.type == MemberType.DIRECTORY`, `size == 12`; `MEMBER_DIRECTORY_DATA_IGNORED`; `read()` returns the 12 bytes, and so does the stream `stream_members()` yields for it; extraction creates the directory; `STRICT` raises |
| ZIP directory entry declaring 12 bytes whose stored body was altered | `read()` raises `CorruptionError` (CRC-32 mismatch), as for a file |
| ZIP directory entry declaring 12 bytes with a CRC-32 field of 0 | `hashes` empty; `MEMBER_DIRECTORY_DATA_IGNORED` and `DIGEST_UNVERIFIABLE`; `read()` returns the 12 bytes |
| ZIP directory entry with compressed size 2 and size 0 (the `jar` shape) | `DIRECTORY`; no diagnostic; `read()` → `ArchiveyUsageError` |
| ZIP or RAR directory entry with size 0 over a 2000-byte stored body | `DIRECTORY`, `size == 0`, `compressed_size == 2000`; `MEMBER_DIRECTORY_DATA_IGNORED` with both sizes; `read()` → `ArchiveyUsageError`; `STRICT` raises |
| RAR directory entry with compressed or encrypted data | `MEMBER_DIRECTORY_DATA_IGNORED`; `read()` → `UnsupportedFeatureError`, and so does the first read of the stream `stream_members()` yields for it |
| ZIP whose member carries a junction's reparse data † | `member.type == MemberType.SYMLINK`; `member.extra["is_junction"] is True`; `link_target` is the buffer's substitute name |
| ZIP whose member has the reparse bit and no reparse data | `member.type == MemberType.SYMLINK`; `link_target is None`; `is_junction` unset, the tag that would establish it being in the data that was not written |
| 7z ANTI-bit entry † | `member.type == MemberType.ANTI`; `member.is_anti`; not `is_file` |
| ZIP entry with `FILE_ATTRIBUTE_REPARSE_POINT` | `member.is_reparse_point`; the bit lives in the DOS attribute word, so it SHALL be read only from a DOS/Windows `create_system` |
| 7z entry with `FILE_ATTRIBUTE_REPARSE_POINT` | `member.is_reparse_point`, unless the attribute word's high half already says `S_IFLNK` † — a POSIX symlink is not a reparse point |
| RAR5 redirect type 2 (Windows symlink) or 3 (junction) † | `member.is_reparse_point`; type 3 also sets `is_junction` |
| RAR5 redirect type 1 (Unix symlink) †, or a TAR/ISO symlink | `member.is_reparse_point` is False |
| Directory source read on Windows | `member.is_reparse_point` for every symlink †; on POSIX, never |

A case marked † is not pinned by another tool's output: no producer available to this
project writes that shape, so the test builds it — an assembled archive, a hand-built
header record, or a member constructed directly. The row still states what the system
guarantees for an archive that does carry the shape, but whether any writer in the wild
produces it is untested, and so is the behaviour a real one would get.

- **A TAR device node or FIFO.** Built with `tarfile` in the test.
- **A ZIP or RAR device, FIFO or socket.** Info-ZIP's zip and rar skip them, so the
  tests set the mode in a `ZipInfo` (ZIP) or a rewritten fixture header (RAR); the
  data-bearing ZIP shape is also made by `zip -FI` on a named pipe when `zip` is
  installed. The 7z case is not here: 7-Zip and p7zip store a FIFO, and a test archives
  one with the CLI; the data-bearing 7z record is constructed in the test.
- **A junction's reparse data in a ZIP.** A junction is always a directory reparse
  point, and the writers measured here store no reparse data for a directory (the row
  below it is what they write instead), so the only ZIPs carrying a junction buffer are
  assembled ones. `is_junction` from an archive therefore rests on the format allowing
  the shape rather than on any tool producing it.
- **A 7z ANTI-bit entry.** The test that builds one with the 7z CLI skips wherever the
  installed version cannot write an anti-item update archive, which is the case on the
  development image; what runs everywhere assembles the header itself.
- **The `S_IFLNK` exception in the 7z row.** No writer sets both the POSIX link mode and
  the reparse bit, so the guard against reading one as the other has no case to run on.
- **The RAR5 redirect types.** No RAR in the corpus carries a Windows redirect; the
  three redirect types are pinned against a hand-built header record.
- **Every symlink from a Windows directory source.** A junction scanned from a live
  Windows filesystem is covered on the Windows CI leg, but creating a symlink there
  needs privileges the runner does not have, so the symlink half is exercised by
  simulating the platform.

### Requirement: Compression methods model codec chains

The system SHALL define `CompressionAlgorithm`, frozen `CompressionMethod`, and
`tuple[CompressionMethod, ...]` for filter chains:

```python
class CompressionAlgorithm(Enum):
    STORED = "stored"
    DEFLATE = "deflate"
    DEFLATE64 = "deflate64"
    BZIP2 = "bzip2"
    LZMA = "lzma"
    LZMA2 = "lzma2"
    ZSTD = "zstd"
    LZ4 = "lz4"
    BROTLI = "brotli"
    PPMD = "ppmd"
    BCJ = "bcj"
    BCJ2 = "bcj2"
    DELTA = "delta"
    RAR = "rar"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class CompressionMethod:
    algo: CompressionAlgorithm
    level: int | None = None
    properties: bytes | None = None
```

The enum SHALL be open-ended by appending new members over time. Unrecognized
codec IDs SHALL map to `UNKNOWN` rather than raising. Ordinary RAR M1–M5 SHALL
map to `RAR`, not `UNKNOWN`.

#### Scenario: compression matrix

| Case | Expected |
| --- | --- |
| ZIP member stored with DEFLATE | `(CompressionMethod(algo=CompressionAlgorithm.DEFLATE),)` |
| 7z member uses BCJ2 + LZMA2 | `(CompressionMethod(BCJ2), CompressionMethod(LZMA2))` |
| Compressed RAR member (M1–M5) | `(CompressionMethod(algo=CompressionAlgorithm.RAR, level=<1-5>),)`; `extra["rar.extract_version"]` is the RAR3 `UNP_VER` byte as stored (unvalidated), or `50` for RAR5 |
| Archive contains an unknown codec ID | `CompressionAlgorithm.UNKNOWN`; no exception |

### Requirement: ArchiveMember exposes the complete mutable member record

The system SHALL define `ArchiveMember` as a mutable, unhashable dataclass that
callers treat as read-only:

```python
@dataclass
class ArchiveMember:
    type: MemberType
    name: str
    raw_name: bytes | None
    size: int | None
    compressed_size: int | None
    modified: datetime | None
    accessed: datetime | None
    created: datetime | None
    ctime: datetime | None
    mode: int | None
    uid: int | None
    gid: int | None
    uname: str | None
    gname: str | None
    link_target: str | None
    link_target_member: "ArchiveMember | None"
    compression: tuple[CompressionMethod, ...] = ()
    is_encrypted: bool = False
    is_current: bool = True
    is_sparse: bool = False
    comment: str | None = None
    create_system: "CreateSystem | None" = None
    windows_attrs: int | None = None
    hashes: Mapping[HashAlgorithm, bytes] = field(default_factory=dict, compare=False)
    diagnostics: tuple[Diagnostic, ...] = field(default=(), compare=False)
    extra: MemberExtra = field(default_factory=MemberExtra, compare=False)

    @property
    def member_id(self) -> int: ...
    @property
    def is_file(self) -> bool: ...
    @property
    def is_dir(self) -> bool: ...
    @property
    def is_link(self) -> bool: ...
    @property
    def is_other(self) -> bool: ...
    @property
    def is_anti(self) -> bool: ...
    @property
    def is_junction(self) -> bool: ...
    @property
    def is_reparse_point(self) -> bool: ...
    @property
    def member_state_final(self) -> bool: ...

    def modified_utc(self, tz_for_naive: tzinfo | None = None) -> datetime | None: ...
    def accessed_utc(self, tz_for_naive: tzinfo | None = None) -> datetime | None: ...
    def created_utc(self, tz_for_naive: tzinfo | None = None) -> datetime | None: ...
    def ctime_utc(self, tz_for_naive: tzinfo | None = None) -> datetime | None: ...
    def replace(self, **kwargs: object) -> "ArchiveMember": ...
```

`created` SHALL be a birth time or `None`, in every format, and SHALL NOT hold Unix
`st_ctime` (inode change). Where a writer stores `st_ctime`, in a creation slot or a
field of its own, or may, the time SHALL go to `ctime` instead. A format with one
creation slot (RAR, 7z, ZIP) SHALL fill at most one of `created` and `ctime`. Rock
Ridge ISO and libarchive's PAX TAR (`LIBARCHIVE.creationtime` beside `ctime`) store a
creation time and a change time separately and SHALL report each; a directory listing
reports both where the OS has them (`ctime` from `st_ctime`, except on Windows). Each
format spec says which writers store which.

`is_anti` SHALL be derived (`type == MemberType.ANTI`); there is no `is_anti` field.
`is_current` SHALL mean “live for default extract / path identity”: last-entry-wins
semantics apply uniformly across ALL container formats (ZIP, TAR, 7z, RAR, ISO,
directory); when the same name appears more than once in an archive, the **last** entry
in archive order has `is_current=True` and all earlier same-name entries have
`is_current=False`. RAR file-version history rows (`format-rar`) use the `;N` suffix
convention (unique presentation names) and MUST still set `is_current=False` on those
rows, as plain ISO 9660 does on an older file version (`format-iso`); the shared
last-entry-wins pass MUST NOT overwrite a backend's `is_current=False`, and counts
only the remaining rows, so it leaves a name that appears once among them
unchanged. Anti entries (7z delete markers)
supersede their targets per `format-7z`. Unavailable values SHALL be `None`;
`name` follows normalization while `raw_name` preserves stored bytes; timestamp
timezone semantics are preserved; digest keys name their real algorithms; there
is no `crc32` alias. Sizes, link targets, hashes, and diagnostics MAY be
completed in place during streaming. `member_id` and the reader that listed the
member preserve source identity (`member in reader`), convenience properties are
derived, and `replace()` creates an edited copy. `hashes`, `diagnostics`, and
`extra` SHALL be excluded from equality.
`extra` SHALL be a `MemberExtra`: a `dict[str, object]` subclass whose
`__getitem__` is overloaded once per known key, with a `str → object` fallback.
Known keys carry their declared types on a subscript read; unknown keys
(third-party or future) remain legal and read as `object`. Writes and `.get()`
are not narrowed. The `EXTRA_*` constants remain the names for the keys they
cover. A caller that uses an unknown key narrows it.

`ArchiveMember` SHALL remain unhashable and non-frozen. The `diagnostics` tuple
itself is immutable, but the library MAY replace it in place for later
member-specific events; previously returned members are live objects, not
point-in-time snapshots.

#### Scenario: member record matrix

| Case | Expected |
| --- | --- |
| Format cannot provide a field | Field is `None`, not a default |
| Streaming later learns `size` / `link_target` | Same yielded object is updated in place |
| Caller needs a renamed member | Uses `member.replace(name=...)`; original unchanged |
| `ArchiveMember` used as set item/dict key | Fails because the type is unhashable |
| Naive and aware `modified` / `accessed` / `created` / `ctime` through their `*_utc()` helpers | Returned values are aware UTC; the stored fields are unchanged; each helper reads only its own field |
| ZIP CRC32 and RAR5 Blake2sp hashes | Stored under `HashAlgorithm.CRC32` / `BLAKE2SP` with `bytes` values |
| Extraction report holds a member later completed in place | Report's result tuple is immutable; member object reflects late field update |
| `type == MemberType.ANTI` | `is_anti` true; `is_file` false |
| Content superseded by later same-name / anti (7z) | Earlier member `is_current` false |
| RAR `-ver` history row `path;n` | `is_current` false; live `path` remains true |
| Two rows with one name, both marked not current by the backend (plain ISO `FOO.;1` twice) | Both stay `is_current` false |

### Requirement: ArchiveMember says whether its fields can still change

`ArchiveMember.member_state_final` SHALL be `False` while the library can still update
the member in place, and `True` from the point it cannot. It SHALL be `False`, in every
format, in these cases:

- A member of a listing whose links have not been resolved yet, in either access mode.
  The listing is complete, and its members settled, when a call that resolves links to
  members returns (`members()`, `members_report()`, `get()`, the end of a
  `stream_members()` pass or of iterating the reader). Before that a later member with
  the same name can still make it `is_current=False` (except in a streaming pass over
  a seekable ZIP, which reads the whole central directory first), and links get
  `link_target_member`. A `streaming=True` pass yields every member before that point,
  in every format. A `members_report_if_available()` peek resolves no links, so the
  members it returns read `False` until a later call or pass does. Whether a
  random-access pass yields before that point depends on whether the backend has
  resolved the listing before the pass starts; the flag reports which. A ZIP read
  from a non-seekable source is one such pass with more to change: its central
  directory follows the last member, so until the pass has read it any field the
  directory gives can still change (type, the name where a DOS host makes `\` a
  separator, `mode`, `create_system`, `comment`, `uid` and `gid`, times from the
  directory's extra fields, and `is_current`; `format-zip`).
- A symlink whose target is stored as member data (ZIP, 7z, a RAR 4 symlink) until the
  library has read that data, whatever the read found. Reading it sets `link_target`,
  and a reparse point whose data is not a link buffer becomes a `FILE`. `open()` and
  `extract_all()` read it on the member object they are given, a copy included.
- A single-file member whose `size` is `None` after listing, until a read from the
  start to the end that skips no byte fills it in (`format-single-file-compressors`).
  Likewise a ZIP member whose size is unknown because a macOS writer stored it modulo
  2³², until a full read whose length and CRC-32 check out fills it in (`format-zip`).
  A `streaming=True` pass settles both when it ends: no read can reach them again.

It SHALL be `True` everywhere else. A walk that fails and cannot be resumed settles the
members it handed out, and closing the reader settles every member it listed. A copy
made with `replace()` belongs to no listing: it is never stamped, so it reads `False`
only while it is a symlink whose data-stored target is unread, and no settle reaches
it, so a copy whose target is never read reads `False` after the reader closes too.
Attached `diagnostics` are not covered and MAY still grow. The documented meaning is
"no field of this member will change"; each format's user documentation names the
fields that change in practice.

#### Scenario: member_state_final matrix

| Case | Expected |
| --- | --- |
| Streaming pass over a TAR holding `a.txt` twice, from a file or a pipe | Each member reads `False` when yielded; all read `True` after the pass, and the first `a.txt` reads `is_current=False` |
| `members()`, `members_report()`, or `stream_members()` after either | Every member reads `True`, except an unread symlink or a member whose `size` a read has not filled in yet (rows below) |
| Random-access `stream_members()` with no listing call first | 7z (walks as it goes): `False` when yielded, `True` after the pass. ZIP (listing resolved first): `True` when yielded, except a macOS member whose `size` is unknown (row below) |
| Peek (`members_report_if_available()`), either access mode | `False` until a later call or pass resolves links to members, then `True` |
| Pass left early, then the reader closed | `True`: a closed reader updates nothing |
| Copy made with `replace()` | `True`, unless it is a symlink whose data-stored target is unread: `False` until `open()` reads the target into the copy; one never read stays `False`, after the reader closes too |
| TAR symlink, either `read_link_targets` | `True`: the header carries the target |
| ZIP symlink under `read_link_targets=False` | `False` until `open()` or `extract_all()` reads its target, then `True` |
| ZIP symlink under the default | `True` once listed |
| `.gz` / `.bz2` after `members()` | `False` until a read from the start to EOF that skips no byte sets `size`, then `True`; `True` after the reader closes |
| `.xz` with a readable index, after `members()` | `True`: the index records the size |
| macOS ZIP member whose size is unknown (stored modulo 2³²), after `members()` | `False` until a read whose length and CRC-32 check out sets `size`, then `True`; `True` after the reader closes |
| A `.gz` member, or that ZIP member, `streaming=True`, after the pass | `True`, whether or not a read filled the size |
| ZIP from a non-seekable source, `streaming=True`, `stream_members()` | Each member reads `False` when yielded, with `mode`, `create_system`, `comment`, `uid` and `gid` `None`; after the pass every member reads `True`, with the directory's fields |

### Requirement: Member diagnostics attach under the shared budget

The system SHALL attach only retained, member-specific diagnostics to
`ArchiveMember.diagnostics` under the collector budget described by `diagnostics`.
Eligible initial codes are `MEMBER_NAME_NORMALIZED`,
`MEMBER_TIMESTAMP_INVALID`, `SYMLINK_TARGET_UNAVAILABLE`, and
`DIGEST_UNVERIFIABLE`. Attachment SHALL require both retained aggregate
occurrence and an additional attachment slot; aggregate and member copies share
the same occurrence id by value but not object identity.

`member.replace()` SHALL copy the tuple's current value without consuming another
library-retention slot. `ArchiveInfo` MUST NOT carry runtime diagnostics; those
live on `FormatInfo`, reader summaries, stream summaries, or extraction reports.

#### Scenario: member diagnostic matrix

| Case | Expected |
| --- | --- |
| Normalization emits retained member diagnostic and attachment slot remains | `member.diagnostics` exposes it with aggregate occurrence id |
| One collector budget slot remains | Aggregate retains; member attachment omitted; exact counts include event |
| Already-yielded stream discovers `DIGEST_UNVERIFIABLE` | Diagnostic may append in place, budget permitting |
| Rewind or missing EOF marker occurs after open | Reader/stream summary changes; frozen `ArchiveInfo` remains unchanged |

### Requirement: ArchiveMember name normalization is meaning-preserving only

The system SHALL normalize `ArchiveMember.name` using only meaning-preserving
rules and SHALL preserve verbatim stored bytes in `raw_name`. It MUST NOT strip a
leading `/` or collapse `..` components, because those rewrites hide unsafe
stored names. Such names are rejected by `safe-extraction`, not re-rooted at read
time. When normalization changes the presented path, Archivey SHALL emit the
documented normalization diagnostic/log event, except when the only changes are
dropping a leading `./` and appending a directory's `/`: `tar czf a.tar.gz .`
writes that on every member, every reader strips it, and reporting it would make
`DiagnosticPolicy.STRICT` refuse ordinary archives (maintainer ruling 2026-10-31).

Normalization SHALL apply in order:

1. Replace `\` with `/` only when the backend says backslash is a separator
   (RAR; ZIP from DOS/Windows create systems). TAR/POSIX keeps `\` literal.
2. Strip leading `./` and collapse interior `/./`.
3. Collapse repeated `//`.
4. Append `/` for directory members.
5. Never produce an empty string; empty/root becomes `"."`.

#### Scenario: normalization matrix

| Case | Expected |
| --- | --- |
| Windows-origin bytes `b"foo\\bar\\baz.txt"` | `name == "foo/bar/baz.txt"`; `raw_name` unchanged |
| TAR bytes `b"weird\\name.txt"` | Backslash preserved as a literal |
| `"foo/../bar"` | `..` retained; not collapsed |
| `"/etc/passwd"` | Leading `/` retained; extraction rejects later |
| `"../../etc/passwd"` | Traversal retained; extraction rejects later |
| `"a//b/./c"` | `name == "a/b/c"`; `MEMBER_NAME_NORMALIZED` |
| `"./a.txt"`, directory `"./d"`, or the bare root `"./"` | `name` is `"a.txt"`, `"d/"`, `"."`; nothing reported |
| `".//a.txt"` | `name == "a.txt"`; `MEMBER_NAME_NORMALIZED` (the `//` is reported) |
| Directory stored as `"mydir"` | `name == "mydir/"` |

### Requirement: ArchiveInfo carries open-time archive metadata

The system SHALL define frozen `ArchiveInfo` for metadata available immediately
after `open_archive()` without a full member scan:

```python
@dataclass(frozen=True)
class ArchiveInfo:
    format: ArchiveFormat
    format_version: str | None
    is_solid: bool
    member_count: int | None
    comment: str | None
    is_encrypted: bool
    is_multivolume: bool
    cost: CostReceipt
    extra: ArchiveInfoExtra = field(default_factory=ArchiveInfoExtra, compare=False)
```

`extra` keys SHALL be namespaced strings and excluded from equality.
`extra` SHALL be an `ArchiveInfoExtra`: a `dict[str, object]` subclass of the
same shape as `MemberExtra` over a separate key set, not merged with it. Known
keys carry their declared types on a subscript read; unknown keys remain legal
and read as `object`. Writes and `.get()` are not narrowed.
`member_count` SHALL be `None` when computing it requires a full scan, and when the
archive cannot supply a count: a ZIP whose central directory walk met damage or
stopped at `ListingLimits.max_members`. A ZIP reads its count from that walk, an index
read rather than a scan of member data; reading `member_count` before the listing has
walked the directory runs the walk.

#### Scenario: archive info matrix

| Case | Expected |
| --- | --- |
| TAR archive opens without central directory | `ar.info.member_count is None` |
| ZIP whose central directory is damaged at its third entry, or holds more entries than `max_members` | `ar.info.member_count is None`; `members()` raises |
| ISO 9660 image richest namespace is Joliet | `ar.info.extra["iso.namespace"] == "joliet"` |
