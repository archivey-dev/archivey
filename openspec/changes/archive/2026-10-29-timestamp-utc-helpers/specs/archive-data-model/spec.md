## MODIFIED Requirements

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
| Naive and aware `modified` values pass through `modified_utc()` | Returned values are aware UTC; original `modified` fields unchanged |
| Naive and aware `accessed` / `created` / `ctime` pass through `accessed_utc()` / `created_utc()` / `ctime_utc()` | Converted as `modified_utc()` converts `modified`; each reads only its own field |
| ZIP CRC32 and RAR5 Blake2sp hashes | Stored under `HashAlgorithm.CRC32` / `BLAKE2SP` with `bytes` values |
| Extraction report holds a member later completed in place | Report's result tuple is immutable; member object reflects late field update |
| `type == MemberType.ANTI` | `is_anti` true; `is_file` false |
| Content superseded by later same-name / anti (7z) | Earlier member `is_current` false |
| RAR `-ver` history row `path;n` | `is_current` false; live `path` remains true |
| Two rows with one name, both marked not current by the backend (plain ISO `FOO.;1` twice) | Both stay `is_current` false |
