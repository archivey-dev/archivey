## Context

Measured on `main` at `446cb26`.

### What a backend is today

A format is two classes in `archivey.internal.backends`:

- A `ReadBackend` subclass (`internal/base_reader.py:336`). It is a stateless factory. It
  declares the formats it reads and its detection signals as class data (`FORMATS`,
  `EXTENSIONS`, `MAGIC`, `SFX_MAGIC`, `SFX_HIT_VALIDATOR`, `CONTENT_PROBES`, `TRAILER`),
  flags (`SUPPORTS_STREAMING_NON_SEEKABLE`, `SUPPORTS_PASSWORD`, `USES_ENCODING`,
  `READ_IMPLEMENTED`), an optional dependency, and one method, `open_read()`.
- A `BaseArchiveReader` subclass. It must implement four abstract methods:
  `_iter_members`, `_open_member`, `_get_archive_info`, `_close_archive`.

`internal/registry.py` collects the backends at import time. Detection reads the
signals through the registry, and `open_archive` asks the registry for the backend of the
detected format.

### What each reader overrides beyond the four methods

Counted from the class dictionaries (base-class names a reader redefines), and from the
base-class helpers each module calls:

| Reader | Extra hooks overridden | Base helpers called |
| --- | --- | --- |
| Single-file | `_validate_at_open` | 6, including `_codec_input`, `_wrap_compressed_input`, `_seek_handle_wrapper` |
| Directory | `_check_extraction_dest` | `_wrap_member_stream` |
| ISO | `_translate_exception` | 7: `_wrap_member_stream`, `_handle_guard`, `_translated_errors`, `_track_source_seeks`, three `_emit_*` |
| TAR | `_iter_with_data`, `_pull_member`, `_register_member`, `_list_before_extraction`, `_translate_exception` | 13 |
| ZIP | `_iter_with_data`, `_ensure_link_target`, `_archive_comment`, `_cost_receipt`, `_translate_exception` | 17 |
| ZIP (forward) | the ZIP set, plus `_listed_in_index_order`, `_account_archive_comment` | — |
| RAR | `_iter_with_data`, `_ensure_link_target`, `_translate_exception` | 20 |
| 7z | `_iter_with_data`, `_ensure_link_target`, `_prepare_link_target_reads`, `_translate_exception` | 16 |

TAR, ZIP, RAR and 7z need hooks into the member walk, the streaming pass and link-target
reads. These are the parts of the base class that change most often. A narrow public
interface cannot include them without freezing them.

ISO is the one dependency-backed reader that needs only the four methods plus an
exception translator. The three `_emit_*` helpers it calls (timestamp out of range,
special file with data, link target unavailable) are member-level diagnostics that any
format can meet.

### Where the format set is closed

- `ContainerFormat` is a `StrEnum`, and `ArchiveFormat.__post_init__` coerces the
  container to it, so `ArchiveFormat("cpio", ...)` raises `ArchiveyUsageError`.
  The stream half is already open: a member of another `Enum` is kept as it is, for
  codecs registered from outside (`tests/test_codec_descriptor.py`).
- About 20 lines outside the backends branch on a specific container: `core.py`
  (volume joining, the ISO raw-sector refusal, the directory source), `detection.py`
  (the inner-TAR probe), `format_args.py` (spellings), `cli/common.py` and
  `cli/extract_cmd.py` (single-file output names). Each branch tests for one named
  container, so a container they do not know takes the default branch. That default must
  be checked for each site (task 2.4).
- `DiagnosticCodeStr` is a closed `Literal` (PR 761). `CompressionAlgorithm` and
  `HashAlgorithm` are closed enums; `CompressionAlgorithm.UNKNOWN` exists.

## Goals / Non-Goals

**Goals**

- A package outside archivey can add a read-only format by implementing one small,
  documented interface, and the new format works with every public reader method,
  `detect_format`, `format_availability`, `list_known_formats`, and the CLI.
- A plugin format gets the same safety as a built-in one for everything archivey does
  after the plugin hands over a member: name normalization, the name-control and
  path checks, listing limits, link resolution, safe extraction, and the extraction
  byte, ratio and entry limits.
- The interface does not expose `BaseArchiveReader`. Internal changes to the walk, the
  streaming pass or link handling stay internal.
- One existing format (ISO) uses the interface, so the full ISO test suite tests it.

**Non-goals for the first version** (each is additive later)

- An indexed format read from a pipe (the ZIP-from-a-pipe problem, where the index
  comes last; see PR 893). An indexed plugin needs a seekable source. A sequential
  plugin reads pipes from the first version (maintainer, 2026-10-25).
- An indexed format inside an outer compression stream. Outer compression is for
  sequential plugins only (`cpio.gz`, `cpio.xz`).
- Member data that is not one contiguous span of the (decompressed) source: per-member
  compression or encryption inside a sequential format. A later `MemberSpan.codec`
  field would add it without breaking plugins.
- Solid formats, multi-volume sets, self-extracting stubs and trailer signatures.
- Passwords and encryption.
- New diagnostic codes from a plugin.
- Writing archives.
- Automatic loading of installed plugins (call 2).

## Decisions

### 1. Composition, not a public base class

A plugin reader does **not** subclass `BaseArchiveReader`. It implements one of two
small abstract classes with no internal state, `IndexedReader` or `SequentialReader`
(§2). An internal adapter, `PluginReaderAdapter(BaseArchiveReader)`, holds the plugin
reader and implements the four abstract methods by calling it. For a sequential reader
it also implements the forward-pass hooks TAR uses (`_iter_with_data`,
`_list_before_extraction`, `_pull_member`), once, for every sequential plugin. The
indexed case is sketched here:

```python
class PluginReaderAdapter(BaseArchiveReader):
    def _iter_members(self):
        for record in self._plugin.iter_members():
            member = record.member
            member._raw = record.locator          # the plugin's handle to its data
            member.name = normalize_member_name(member.name, ...)
            yield member

    def _open_member(self, member):
        data = self._plugin.open_member(member, member._raw)
        return self._wrap_member_stream(
            data.stream, member.name,
            size=member.size,
            expected_size=member.size,            # a short read always raises
            expected_hashes=data.expected_hashes, # verified as built-ins are
            fill_size=member.size is None, verify_member=member,
        )
```

**Why.** A subclass sees and can override every one of about 150 methods. Each one
would become public under the stability policy, and the stability of the internals is
what lets the readers keep agreeing (DR-5, DR-23a). With composition, the public surface
is what `archivey.plugins` exports, and nothing else.

**Rejected: export `BaseArchiveReader` and `ReadBackend` as they are.** It is the
smallest change, but it freezes the internals, and a plugin that overrides an internal
hook can break the guarantees for its format without any error.

### 2. The public interface

All in `archivey.plugins`. Names are proposals.

```python
class PluginContainer(StrEnum):            # re-exported at the root as archivey.PluginContainer
    """Base class for a plugin's container enum."""

class FormatPlugin(ABC):
    """One format: detection data, flags, and open(). Stateless."""

    format: ClassVar[ArchiveFormat]        # ArchiveFormat(MyContainer.CPIO, StreamFormat.UNCOMPRESSED)
    extensions: ClassVar[tuple[str, ...]] = ()       # (".cpio",)
    magic: ClassVar[tuple[Magic, ...]] = ()          # Magic(offset=0, data=b"070701")
    probe: ClassVar[Callable[[bytes], bool] | None] = None   # sees only the prefix detection peeked
    uses_encoding: ClassVar[bool] = False
    requires: ClassVar[tuple[str, ...]] = ()         # importable module names
    install_hint: ClassVar[str | None] = None
    # Sequential plugins only: outer streams this format may sit inside (§4).
    compressed_extensions: ClassVar[Mapping[str, StreamFormat]] = {}  # {".cpgz": GZIP}

    @abstractmethod
    def open(self, source: PluginSource | None, context: PluginContext) -> PluginReader: ...

class PluginReader(ABC):
    """One open archive. Subclass IndexedReader or SequentialReader, not this."""

    def archive_info(self) -> PluginArchiveInfo: return PluginArchiveInfo()
    def translate_exception(self, exc: Exception) -> ArchiveyError | None: return None
    def close(self) -> None: ...

class IndexedReader(PluginReader):
    """A format with an index: list first, then open any member. Seekable source."""

    member_list_upfront: ClassVar[bool] = True   # False = listing walks headers

    @abstractmethod
    def iter_members(self) -> Iterator[MemberRecord]: ...
    @abstractmethod
    def open_member(self, member: ArchiveMember, locator: object) -> MemberData: ...

class SequentialReader(PluginReader):
    """A format of header, data, header, data. Any source, including a pipe."""

    link_target_in_data: ClassVar[bool] = False  # a symlink's target is its data (CPIO)

    @abstractmethod
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]: ...

class MemberRecord(NamedTuple):
    member: ArchiveMember      # public fields only; name decoded, not yet normalized
    locator: object = None     # anything; handed back to open_member

class MemberSpan(NamedTuple):
    member: ArchiveMember
    data_length: int | None = None  # raw: the next data_length bytes of the stream
    data: BinaryIO | None = None    # decoded: a stream the plugin's library decodes
    expected_hashes: Mapping[HashAlgorithm, bytes] = {}
    checked: bool = False           # the library verified the data when read to the end

class MemberData(NamedTuple):
    stream: BinaryIO
    expected_hashes: Mapping[HashAlgorithm, bytes] = {}
    checked: bool = False

class ForwardStream:
    """The archive bytes (decompressed, if there is an outer stream), read forward."""
    offset: int                              # bytes consumed so far
    def read(self, n: int) -> bytes: ...     # short only at the end
    def read_exact(self, n: int) -> bytes: ...   # TruncatedError if short
    def skip(self, n: int) -> None: ...
    def decompress(self, stream: StreamFormat) -> ForwardStream: ...  # from here on (RPM)

class PluginSource:
    """The archive bytes for an indexed reader. Always seekable."""
    size: int | None
    path: Path | None                       # for a library that needs a file name
    def read_at(self, offset: int, n: int) -> bytes: ...
    def view(self, start: int, length: int | None = None) -> BinaryIO: ...  # own position

class PluginContext:
    """What the open archive needs from archivey."""
    encoding: str | None
    archive_name: str | None
    def decode_name(self, raw: bytes) -> str: ...      # archivey's rule: valid UTF-8 wins
    def timestamp_invalid(self, member_name: str, field: str, raw: object) -> None: ...
    def special_file_has_data(self, member_name: str, size: int) -> None: ...
    def link_target_unavailable(self, member_name: str, why: str) -> None: ...

class PluginArchiveInfo(NamedTuple):
    is_solid: bool = False                  # members share one decode (ACE, CAB folders)
    format_version: str | None = None
    comment: str | None = None
    extra: Mapping[str, object] = {}

def register_format(plugin: type[FormatPlugin]) -> None: ...
```

Points that matter:

- **The locator.** `ArchiveMember._raw` is private. A plugin needs somewhere to keep "where
  the data of this member is". `MemberRecord.locator` is that place, and the adapter
  stores it on the member. The plugin never sees `_raw`.
- **Member data is verified the way a built-in's is.** The adapter always passes the
  listed size, so a short stream raises `TruncatedError` (principle 1). A plugin that
  knows a checksum returns it in `expected_hashes`. A plugin that knows none gets the
  `DIGEST_UNVERIFIABLE` behaviour that a built-in format without a checksum gets.
- **Checksums the enum cannot name (maintainer, 2026-10-25).** `HashAlgorithm` holds
  CRC32 and BLAKE2SP only, and stays closed. When the plugin's library verifies a digest
  archivey cannot (LHA's CRC-16, WIM's SHA-1, XAR's SHA-1 or MD5), the plugin sets
  `checked=True`: "the library verified this data when it was read to the end, and
  raised if it did not match". archivey counts the member as verified, as it trusts
  plugin code (§5). The stored value is still exposed: a digest the enum names goes in
  `ArchiveMember.hashes` (archivey verifies it), and any other goes in
  `ArchiveMember.extra` under a namespaced key such as `extra["xar.sha1"]`, which
  `MemberExtra` already allows.
- **Plugin-supplied hashers (maintainer, 2026-10-26 23:11Z, project thread "Implement
  the plugin API": "yes, in memberdata. please add it").** This adds to the ruling
  above rather than replacing it. A plugin that parses the format itself and returns a
  raw stream can still have a checksum the enum cannot name checked: it returns
  `MemberData(stream, digests=(MemberDigest(name, expected, new),))`, where `new` makes
  a hashlib-shaped hasher (`update`, `digest`). archivey's member verifier feeds it as
  the stream is read, with the same seek handling, `CorruptionError` on a mismatch and
  `Verification.CONTENT` on a match as its own CRC-32. The hashers live on `MemberData`,
  not on `ArchiveMember`, because a member is public data callers copy and compare. A
  digest name is refused when it is a `HashAlgorithm` value or repeats another digest's
  name, so it can never replace archivey's own check. `checked=True` stays for a stream
  that checks itself (a library's own decoder), and the stored value still goes in
  `extra` either way. What would reopen it: a checksum a hasher cannot compute
  incrementally.
- **Sources are views, not a shared handle.** `PluginSource.view()` returns a stream with
  its own position over the shared source (the `SharedSource` views the built-ins use).
  Two member streams open at the same time, or a `CONCURRENT` reader, cannot move each
  other's position. A plugin that holds its own handle (an external library) sets nothing
  and the adapter serializes its calls with the reader's handle lock, as ISO does today
  with `_handle_guard`.
- **Diagnostics are three named methods, not `emit(code)`.** They are the member-level
  conditions that every format can meet, and they reuse the existing codes. A plugin
  cannot add a code, so `DiagnosticCodeStr` stays closed. A real need for a new
  code comes to archivey as a request.
- **Errors.** A plugin raises archivey's public exceptions (`CorruptionError`,
  `TruncatedError`, `UnsupportedFeatureError`). Any other exception goes through
  `translate_exception`, and an untranslated one propagates unchanged, as for a built-in
  (DR-15a).
- **Archive info.** The adapter builds `ArchiveInfo` and `CostReceipt` itself:
  `is_solid` from the plugin, `is_multivolume=False`, `is_encrypted=False`, access `DIRECT`, listing
  cost from `member_list_upfront`, stream capability from the source. The plugin
  supplies only what the adapter cannot know.
- **No password, volume or SFX parameters.** Each would be a field on `PluginContext`
  or a flag on `FormatPlugin` when it is added. Adding them breaks no plugin.

### 2a. The sequential shape

Added in the 2026-10-25 revision: the maintainer asked for an architecture that carries
streaming formats from the first version, since CPIO is mostly read from pipes.

TAR's overrides of the base class (§Context) are almost all one thing: the member walk
and the member data share one forward pass. The base class already runs such a pass
generically (`_begin_forward_pass`, `_drive_pass_streams`). What a plugin lacks is a
public way to feed it. `SequentialReader.walk()` is that way.

- **The plugin parses headers; the adapter owns the data.** `walk()` reads a header
  from the `ForwardStream`, and yields a `MemberSpan` that says "the next
  `data_length` bytes are this member's data". The adapter cuts that window, hands it
  to the caller as the member stream, and before it resumes `walk()` it skips whatever
  the caller left unread. The plugin then reads its padding and the next header. A
  plugin never holds a member stream, so it cannot read data the caller is still
  reading or leave the position wrong.
- **Pipes, passes and extraction come from the adapter.** On a non-seekable source the
  adapter runs the walk as the reader's one forward pass, so `stream_members()`,
  `__iter__` and `extract_all()` each work in one pass, with listing limits counted as
  members arrive (TAR's `_list_before_extraction` behaviour, written once). A member
  that crosses a limit raises before the caller gets it.
- **Random access is free on a seekable source.** The adapter records each span's
  offset as it walks, so `open(member)` and `members()` work without an `open_member`
  from the plugin. On a compressed source a random read seeks the codec stream, which
  re-decodes or uses the accelerator index, as for a compressed TAR.
- **Link targets stored as data** (`link_target_in_data`, CPIO's symlinks): the adapter
  reads the span as the target, bounded by `ListingLimits`, with the existing
  `_LINK_TARGETS_IN_DATA` machinery. Hard links stay backward-only (they may name only
  an earlier member), as in every format.
- **Format-specific checks stay in the plugin.** End markers, trailing data and
  checksums of the archive's own structure are the plugin's `walk()` to verify. It
  raises `CorruptionError` or `TruncatedError` like any reader. The adapter keeps the
  members listed before the damage, as a TAR walk does.
- **Data a library decodes (maintainer, 2026-10-25).** Formats that compress each
  member (LHA, ARJ, ACE read in order, anything through libarchive) give the plugin no
  raw window to describe. Such a plugin yields `MemberSpan(member, data=stream)`: a
  decoded stream that stays valid until the next member. The adapter wraps it as it
  wraps a window (size check against `member.size`, extraction limits, digest or
  `checked`), and drains what the caller left unread before it resumes `walk()`. Random
  access to such a member walks again from the start, as a solid archive does, unless
  the reader also implements `open_member`.
- **Compression that starts mid-stream** (RPM: headers, then a gzip, xz or zstd CPIO
  payload): `ForwardStream.decompress(fmt)` returns a forward stream through archivey's
  own codecs, with the decoder limits and the live ratio guard.
- **`open()` for a sequential format** gets `source=None`. The bytes reach `walk()`
  only, because on a pipe or a compressed source there is no seekable source to give.

The shared-pass locking (a `CONCURRENT` reader whose walk has a live member stream) is
TAR's `_pull_member` hand-off, moved into the adapter. It is the risky part of the
adapter, and the cross-format pass tests cover it.

### 2b. Checked against real libraries

The maintainer asked (2026-10-25) to check the interface against existing third-party
readers before building it. From the libraries' source distributions on PyPI (read,
not run):

| Format | Library (PyPI) | How it reads | Shape it fits | What it needs that the design lacks |
| --- | --- | --- | --- | --- |
| AR / .deb outer | arpy 2.4.0, unix-ar 0.2.1 | header + raw data, GNU/BSD long names | Sequential, as designed | Nothing. (.deb's inner data.tar.xz is a nested archive: out of scope) |
| CPIO | (our proof) | header + raw data | Sequential, as designed | newc hard links carry data on the last link |
| RPM | rpmfile 2.2.1 | lead + headers, then a gzip/xz/zstd/bzip2 CPIO payload | Sequential | **Compression that starts mid-stream** (after the RPM headers), not at byte 0 |
| LHA / LZH | lhafile 0.3.1 | header + per-member compressed data; library decodes, checks CRC-16 | Indexed today (it seeks); sequential possible | **Library-decoded member data**; **CRC-16** (not a HashAlgorithm) |
| ACE 1.0/2.0 | acefile 0.6.14 | seekable file or path; solid archives, multi-volume, passwords; `readblocks()` streams output | Indexed (library keeps solid state; out-of-order is slow) | **is_solid** in archive info; passwords; volumes (library finds siblings from a path) |
| ARJ | none found on PyPI; libarchive has no ARJ; 7-Zip reads it | header + per-member compressed data | Sequential or indexed via a decoder, or a 7z CLI wrapper (path) | Library-decoded data; CRC-32 fits; passwords ("garble") later |
| CAB | cabarchive 0.2.5 (MSZIP only, no LZX/Quantum; whole file as bytes, decodes all at parse) | index (CFFOLDER/CFFILE) + folders compressed as one stream | Indexed | Solid-like folders (**is_solid**); multi-cabinet sets later; library memory is unbounded (plugin's own risk) |
| SquashFS | PySquashfsImage 0.9.0, dissect.squashfs 1.12 | file object + offset; inode table, hard links by inode, devices, xattrs | Indexed, as designed | Nothing new (hard links: plugin picks the first name) |
| WIM | dissect.archive 1.8 | file object; several images per file; SHA-1 per resource; reparse points | Indexed | **SHA-1**; a naming rule for several images (plugin's choice, e.g. `1/...`) |
| XAR | libarchive only (no pure-Python reader found) | zlib XML TOC first, per-file checksums (SHA-1/MD5) | Indexed | **SHA-1 / MD5** |
| many (cab, lha, xar, iso, 7z, rar, warc, mtree) | libarchive-c 5.3 | forward only: next header, read data blocks; library owns I/O and decoding | Sequential | **Library-decoded member data**; it reads a path or file object itself |

What the survey changed: decoded data in the sequential shape, the `checked` flag and
the `extra` rule for digests, `ForwardStream.decompress`, and `PluginArchiveInfo.is_solid`
(all in §2 and §2a). What it confirmed stays out of the first version: passwords (ACE,
ARJ), multi-volume sets (ACE, ARJ, CAB; a library that finds its own volumes from
`PluginSource.path` works already) and nested archives (`.deb`). No ARJ reader exists in
Python, and libarchive has none, so an ARJ plugin needs its own decoder or a 7-Zip wrapper
through `PluginSource.path`.

### 3. Format identity: `PluginContainer`

The plugin defines its container enum as a subclass of a new public `StrEnum` base:

```python
class CpioContainer(PluginContainer):
    CPIO = "cpio"

CPIO = ArchiveFormat(CpioContainer.CPIO, StreamFormat.UNCOMPRESSED)
```

- `ArchiveFormat.container` is typed `ContainerFormat | PluginContainer`.
  `__post_init__` keeps a `PluginContainer` member as it is, as it already keeps a
  stream from another enum.
- `display_name` for a pair with no named constant and an `UNCOMPRESSED` stream becomes
  the container name alone (`"CPIO"`, not `"CPIO_UNCOMPRESSED"`).
- `register_format` refuses a container value that equals a built-in value or another
  plugin's, and a format that is already registered.
- `format="cpio"` resolves through the registry once the plugin is registered.
  `format_args.py` asks the registry for plugin spellings after the built-in ones.

**Rejected: add `ContainerFormat.OTHER` plus a name field.** Two formats would then
compare by a string field next to the enum, and `ArchiveFormat` would get a third field
every caller sees. **Rejected: extend `ContainerFormat` at run time.** `Enum` does not
support it, and the hacks that do break type checkers.

A caller's `match fmt.container:` over `ContainerFormat` needs a default case once a
plugin is registered. That is true of any open set, and the docs say so.

### 4. Detection

- Plugin magic, extensions and probes go into the registry tables the detector already
  reads (`magic_entries`, `extension_map`, `content_probes`).
- **Built-in signals win.** A plugin magic or probe match counts only when no built-in
  format matched at the same or a higher confidence. A plugin extension that a built-in
  format already claims is refused at registration. So registering a plugin never
  changes how an archive that archivey reads today is detected.
- **Probes see the prefix only.** A plugin probe gets at most the bytes detection has
  already peeked, with no `read_at` and no decode allowance, so it cannot make detection
  read more of an untrusted source.
- **Outer compression (maintainer, 2026-10-25).** Today a gzip, xz, bzip2 or zstd stream
  is checked for a TAR inside (`_probe_inner_tar`, `ustar` at offset 257 of the first
  512 decoded bytes). That probe becomes an inner-container probe: it decodes the same
  bounded prefix, under the same budget, and checks TAR first, then the magic of each
  registered sequential plugin. A plugin's magic for this check must end within the
  first 512 bytes, which `register_format` enforces. So `x.cpio.gz` detects as
  `ArchiveFormat(CpioContainer.CPIO, StreamFormat.GZIP)`, not as one gz member, and a
  plugin cannot make detection decode more than it does today.
- **Opening a compressed plugin format.** The adapter opens the codec stream the way
  TAR does (`TarReader._open_byte_stream`: path-only accelerators, the counted input
  for the live ratio guard, trailing-data reports), so that code moves to a shared
  helper both use. The plugin's `walk()` sees decompressed bytes only.

### 5. Registration and trust

`register_format(MyPlugin)` is the only way in. The registry already invalidates its
extension cache on registration. There is no `unregister`. Tests use the registry's
private copy-and-restore fixture, as `tests/test_codec_descriptor.py` does.

**No automatic loading (call 2).** Entry points would let any installed package claim
files for every program in that environment that uses archivey. On an upload server
(DR-9a) that means `pip install` of an unrelated package can change which parser reads
an untrusted upload. With explicit registration, the program that calls
`register_format` chose the plugin.

**Plugin code is trusted code.** It runs in the caller's process, like any import.
archivey's firm guarantees (bounded memory, no crash, DR-9a) cover archivey's code and
what it enforces after the plugin hands over members and bytes: listing limits, name
checks, extraction limits, and the size and digest checks on member data. They cannot
cover the plugin's own parser. The docs say this on the "Adding a format" page, and
`format_availability` and `FormatInfo` do not hide that a format came from a plugin
(task 2.6).

### 6. The CLI

The CLI uses only public API (DR-13), so it lists, tests and extracts a plugin format
once the plugin is registered. Nothing loads a plugin into the `archivey` command today.
This version adds nothing for that. The obvious later option is a repeatable
`--plugin MODULE` that imports a module before the command runs. It is left out until a
plugin user asks.

### 7. Which existing formats move

**ISO moves.** `IsoReader` becomes an `IndexedReader`, and `IsoReadBackend` becomes a
`FormatPlugin` registered through the same call a third party uses. Its parsing and
pycdlib hardening do not change. The work is in the class frame: `self._emit_*` calls
become `context` calls, `_handle_guard` goes to the adapter, and the raw-sector-image
refusal moves from `core.py` into `open`. The ISO test suite then tests the
interface, including an optional dependency (`requires=("pycdlib",)`) and a translator.

**Single-file stays internal.** It is not a container. It is a codec stream presented
as one member, and it depends on the codec registry, the accelerator selection
(rapidgzip) and the compressed-input counter that gives the live ratio guard its
denominator. Moving it would put all three into the public interface.

**Directory stays internal** (maintainer, 2026-10-25). Its reading part would fit the indexed shape, since it calls
one base helper. But three things it needs no other plugin would: a source that is a
folder path, not bytes; routing before detection (`core.py` sends a folder path to it
before any magic or extension check); and `_check_extraction_dest`, which refuses
extraction into the source tree. Each would become public, provisional surface used by
one in-repo reader, and ISO and CPIO already test both shapes. If an outside plugin
needs a path source (a mounted image), the hooks come then, and directory moves with
them.

**TAR, ZIP, RAR and 7z stay internal** (Context). They keep the internal hooks. The
adapter is one more `BaseArchiveReader` subclass next to them.

**CPIO is the outside proof of the sequential shape** (maintainer, 2026-10-25: in
this repo, unpublished). `packages/archivey-cpio/` (next to `packages/archivey-cli/`)
is a `SequentialReader` for the four CPIO variants (binary, odc, newc, newc with CRC)
with only `archivey.plugins` and the root API. Its tests run fixtures written by GNU
`cpio` and `bsdcpio`, including symlinks (target as data), hard links (CPIO links by
inode), the newc checksum, and `.cpio.gz` / `.cpio.xz`, each read from a file and from
a pipe. A test fails if the package imports from `archivey.internal`.

One CPIO detail the interface does not solve: newc stores a hard-linked file's data with
the **last** of its links, and the earlier ones are empty. Backward-only hard links
cannot name a later member, so the plugin reports the earlier names as empty files
with a member-level note until a forward pass can tell. This is the plugin's call, not
the interface's, and the CPIO package documents it.

### 8. Will the code be cleaner?

Only a little. What changes:

- **Cleaner:** the reader contract is written in one public module, with a test reader
  that cannot reach the internals. Today the contract is the docstring of a 3,900-line
  class. ISO stops calling base-class helpers by name.
- **Not cleaner:** `BaseArchiveReader` does not get smaller. TAR, ZIP, RAR and 7z do
  not change. The `ContainerFormat` branches in `core.py`, detection and the CLI stay,
  with a default branch checked for plugin containers.
- **New code:** about 1,300 lines. The public module and the adapter about 750 (the
  sequential pass is most of the growth), the registry, detection (inner-container
  probe) and format-identity changes about 250, the shared codec-stream helper moved
  out of TAR, and the CPIO package about 350.
  Plus a docs page and the spec.

The reason to build it is extensibility after the quota drops (2026-11-09): a new
format can come from someone else without the maintainer writing it.

## Risks / Trade-offs

- **A frozen surface.** Under the stability policy, a later change to
  `archivey.plugins` costs a deprecation cycle. Mitigation: call 1, provisional
  status until a real third-party plugin has used it.
- **Guarantees a plugin can break.** A plugin's parser can use unbounded memory or
  crash. Mitigation: documented scope (§5), built-in signals win (§4), explicit
  registration only, and `FormatInfo.from_plugin` so a caller can refuse plugin formats.
- **The sequential pass is shared state.** A `CONCURRENT` reader whose walk has a live
  member stream must hand that stream off before another caller pulls (TAR's
  `_pull_member`). Mitigation: the hand-off is written once in the adapter and CPIO
  runs the cross-format pass and concurrency tests.
- **The adapter drifts from the internals.** A base-class change that the four built-in
  families absorb can break the adapter. Mitigation: ISO and CPIO run in the normal
  suite and in the cross-format matrix tests, so a break fails CI.
- **Locator stored in `_raw`.** A member that a caller copies with `dataclasses.replace`
  keeps the locator. That is what built-in backends do already, so it is not new.
- **No strict end for a whole stream.** `decompress()` of a `StreamFormat` reports bytes
  after the stream's end (`ARCHIVE_TRAILING_DATA`) and never refuses them, as archivey
  reads a `.gz` or `.xz` file. A container that bounds the stream exactly, as a
  SquashFS block does, could treat those bytes as damage; it has no way to ask for that
  in this version. A `strict_end=` keyword on `decompress()` is the addition if a
  plugin needs it.

## Migration Plan

Additive, no migration. Order of PRs, each reviewed on its own:

1. `PluginContainer`, the `ArchiveFormat` change, spellings, registry and detection
   support (with the inner-container probe), the adapter for both shapes,
   `archivey.plugins`, `FormatInfo.from_plugin`, and minimal in-test plugins of each
   shape.
2. ISO onto the interface.
3. `packages/archivey-cpio/` with fixtures and CI.
4. User docs page "Adding a format" (written by Opus), API page entry, spec
   `format-plugins` and the deltas.

No PR merges before the 0.2.0 tag. The target is 0.3.0.

## Open Questions

The maintainer decided the brief's calls on 2026-10-25 (`brief.md`): provisional status,
explicit registration, both reader shapes with pipes, outer compression for sequential
formats, `FormatInfo.from_plugin` (one boolean), ISO onto the interface, CPIO in
`packages/archivey-cpio/`, the directory reader stays internal, decoded data in the
sequential shape, and the `checked` flag with stored digests in `hashes` or `extra`.
On 2026-10-26 the maintainer added plugin-supplied hashers (`MemberData.digests`), and
asked for seekable members over a forward-only plugin stream ("if the user says they
need seeking, we must support it") and for `PluginContext.decompress`.
No question is open.
