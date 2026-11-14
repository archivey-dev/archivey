## ADDED Requirements

### Requirement: Read a RAR archive forward from a non-seekable source

For a non-seekable source opened with `streaming=True`, the RAR backend SHALL read a
single-volume archive front to back: each member is listed once its header and data are
in the pass and the next header has been read, or once the volume holding its first part
is written, and every member with packed data is decoded by one RARLAB `unrar` (7.00 or
later) run fed rolling synthetic volumes, one on disk at a time and one charged to
`SpoolLimits.max_bytes`. Members and bytes SHALL match the seekable reader's for the
same archive, except for the forward-only rules in the scenario. A refusal the archive's
start decides SHALL be raised at open; a member's own refusal SHALL be raised on its
first read.

#### Scenario: forward-only matrix

| Case | Expected |
| --- | --- |
| RAR 1.5-4 or RAR5, solid or not, plain, `-p` or `-hp`, one password | Every member and its bytes as from a seekable source |
| A volume of a set | `StreamNotSeekableError` at open |
| `-hp`, several password candidates | The candidate that decrypts the headers |
| RAR5 data encryption, several candidates | The candidate the first listed member's PswCheck accepts when `unrar` starts; an encrypted member it does not fit raises `UnsupportedFeatureError` on its first read |
| RAR 1.5-4 data encryption, several candidates | Each encrypted member raises `UnsupportedFeatureError` on its first read |
| A member whose output does not line up (cut short, wrong password, no size, RAR 1.5-4 past 4 GiB, unknown version in a solid archive) | That member raises; every later member with data raises too |
| A member that fails its digest | That member raises; the later members read as from a seekable source |
| A member cut short past the 4 MiB the source reads ahead | `CorruptionError` instead of `TruncatedError` |
| A RAR 1.5-4 `UOW` or `CMT` after a member split across two volumes | The member is listed without it, and carries `MEMBER_HEADER_RECORD_SKIPPED` once the next member is listed or the pass ends |
| The caller closes while the source has stopped sending | `close()` returns within about a second; a read of the source may still be pending, so the source's own close or read waits for it; the thread removes the volumes when that read returns |
| `unar`, no `unrar` 7.00 or later | `StreamNotSeekableError` at open |
| Listing only (`members_report()`) | No volume written |
| RAR5 file copy | Its stream raises `UnsupportedFeatureError` on its first read |
| Hard link, symlink, directory | As in the seekable pass |
| Quick-open record | Not read |
| `members()`, `open()`, a second pass | Raise as for any streaming reader |

## MODIFIED Requirements

### Requirement: Declare RAR format properties

The RAR backend SHALL expose these properties:

| Property | Value |
| --- | --- |
| Read dependency (metadata) | None; native RAR 1.5–RAR5 header parser |
| Read dependency (data) | RARLAB `unrar` or `rar` binary on `PATH` (`unrar` preferred), for compressed members and encrypted members archivey does not decrypt itself; `cryptography` for stored, encrypted members in one part |
| Listing cost | `REQUIRES_SCANNING`: a header walk at open, parsed natively, no member-data decompression. Also with a quick-open record, which saves seeks but not the walk |
| Access cost | `SOLID` for solid archives; `DIRECT` otherwise |
| Supports write | No |
| Requires seek | Yes, except a streaming pass over a single-volume archive with RARLAB `unrar` 7.00 or later |

#### Scenario: format property matrix

| Case | Expected |
| --- | --- |
| Open non-header-encrypted RAR without `unrar`/`rar` | Listing and metadata still work through the native parser |
| Read a stored, encrypted member in one part without `unrar`/`rar`, `cryptography` installed | Decrypted and returned by archivey |
| Open from a non-seekable source, `streaming=False` | Open fails: random access needs seek |
| Open from a non-seekable source, `streaming=True`, `unrar` 7.00 or later | Opens a forward reader (requirement below) |
| Open from a non-seekable source, `streaming=True`, no `unrar` 7.00 or later | `StreamNotSeekableError` naming a seekable source or `unrar` 7.00 as the fix |
