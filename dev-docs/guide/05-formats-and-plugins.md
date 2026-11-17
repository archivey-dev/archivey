# 5. Formats and plugins

**In one minute.** A format is written in one of two ways. The **internal tier** (ZIP,
TAR, 7z, RAR, the single compressed file, the directory reader, DMG recognition)
subclasses `BaseArchiveReader` directly and can use every internal feature: passwords,
volumes, self-extractor stubs, accelerators, hand-tuned fast paths. The
**`archivey.formats` tier** (ISO, SquashFS, CAB, XAR, CPIO, ar, RPM, deb) is written
against the small public interface an outside plugin would use: a *handler* that declares
the format and a *reader* that yields members and bytes. One adapter class turns such a
reader into a full `BaseArchiveReader`, so names, limits, links, extraction and checksums
behave exactly as for the internal tier. The same interface lets a program register a
new format or codec at run time (`register_format`, `register_codec`), and
`FormatPolicy` lets a caller turn readers and optional libraries off per call. The
interface is **experimental**: any release may change it.

The user-facing guide is [`docs/adding-a-format.md`](../../docs/adding-a-format.md). This
page covers archivey's side of it.

## The registry: which code reads which format

`internal/registry.py` maps an `ArchiveFormat` to a `ReadBackend` class. Every backend
module ends with a registration call, and `import archivey` imports them all, so the
registry is full before the first open.

Registration is **unconditional**. ISO registers even when `pycdlib` is not installed.
Availability is worked out separately, from whether the optional module imports, so the
registry can answer three ways (`FormatSupport.FULL`, `PARTIAL`, `NONE`) and raise
`PackageNotInstalledError` with an install hint, instead of acting as if the format did
not exist. `PARTIAL` is for a format that lists without its helper: RAR without `unrar`
lists members but can read only the stored ones.

The registry also makes the **pairs** on demand. A backend that sets `STREAM_PAIRS` (TAR,
and every sequential format) is registered for its container inside *every* single-file
codec: `.tar.gz`, `.tar.zst`, `.cpio.xz`, `.ar.lz4`. Because the pairs are made when asked,
a codec registered later by a plugin reaches all of them too.

Detection reads its tables from the same registry: each backend's `MAGIC`, `EXTENSIONS`,
`SFX_MAGIC` and probes. The detector has no per-format code.

## Tier 1: the internal readers

These formats subclass `BaseArchiveReader` directly (page 4 lists the four methods). They
are the formats that need something the public interface does not offer:

| Format | What it needs from the internal tier |
| --- | --- |
| ZIP | Two readers (index-first from a file, front-to-back from a pipe), passwords with a shared confirmation ladder, ZipCrypto and WinZip AES, self-extractor stubs, 7-Zip split volumes, a hand-tuned listing fast path |
| TAR | Its own walk over every compression stream, reading data through the walk, sparse files, the accelerator and its seek points |
| 7z | Solid folders and their coder graphs, encrypted headers, AES key derivation with a cost limit, multi-volume sets, stubs |
| RAR | An external program for data, spooling, synthetic archives, multi-volume sets with gaps, file copies inside solid archives |
| Single compressed file | One member whose metadata comes from the codec's own header, `open_stream()` |
| Directory | No bytes at all: a folder on disk, read with `os.scandir` |
| DMG (`udif.py`) | Nothing to read: it is registered so detection can name a disk image and refuse it with a clear message (`READ_IMPLEMENTED = False`) |

## Tier 2: the `archivey.formats` interface

### The shape of a format

A format that fits is two classes (`src/archivey/formats.py`):

- a **handler** declares the format: its `ArchiveFormat`, extensions, magic, optional
  probe, the modules it needs, and whether it uses `encoding=`. It opens a reader.
- a **reader** yields members and gives their bytes.

There are two reader shapes, because archive formats come in two shapes:

| | `IndexedReader` | `SequentialReader` |
| --- | --- | --- |
| Layout | An index somewhere (often at the end) says where each member is | Header, data, header, data, … from start to end |
| Examples | ISO, SquashFS, CAB, XAR | CPIO, ar, RPM, deb |
| Source | Always seekable (`ReaderSource`, with `view()`, `read_at()`) | A forward-only `ForwardStream`, so a pipe works |
| Methods | `iter_members()` yields `MemberRecord(member, locator)`; `open_member(member, locator)` returns `MemberData` | `walk(stream)` yields `MemberSpan(member, data_length)` |
| Who reads member data | The reader opens a stream from its locator | **archivey**: the span says "the next N bytes are the data", and archivey reads or skips them |
| From a pipe | Refused before `open()` is called (`non_seekable_reason` says why) | Yes |
| Inside a compressor (`.cpio.gz`) | No | Yes, automatically |

The `locator` is anything the reader needs to find a member again (an offset pair, a
directory record). archivey stores it and hands it back; it never looks inside.

A concrete example is the ar reader, `internal/backends/ar_reader.py`, about 250 lines.
Its `walk()` reads the magic, then loops: read a 60-byte header, work out the name (two
dialects store long names differently), skip the symbol table, and
`yield MemberSpan(member, size)`. That is all it does. It never reads a member's data,
never checks a name for `..`, never counts members against a limit, never resolves a hard
link. archivey does all of that, the same way as for TAR.

### What the reader gets from archivey: `ReaderContext`

Every reader gets a `ReaderContext`, its only door into archivey:

- `decode_name(raw)` applies `encoding=` and the UTF-8 rule; `normalize_name()` is
  available too, though archivey normalizes what the reader yields anyway.
- `report(...)` records a diagnostic, from a fixed set of codes (a plugin cannot invent
  new codes yet).
- `charge_metadata(n, what=...)` counts bytes the reader keeps beyond its members (ar's
  long-name table) against `max_metadata_bytes`, so a plugin cannot hold unbounded memory
  through the back door.
- `decompress(stream, format)` decodes with archivey's own codecs, with the caller's
  limits and process isolation.
- `open_nested(data, format)` reads a member that is itself an archive (a `.deb`'s
  `data.tar.xz`) with archivey's reader, reporting into the outer reader's diagnostics.
- `hold(...)` and `link_target_unavailable(...)` for the rarer cases.

And `ForwardStream` has `take(n)` (the next n bytes as a stream, for a nested archive) and
`decompress(format)` (the rest of the archive is compressed from here, as in RPM, whose
payload follows its headers).

### What archivey does with a member: the promises in `MemberData`

`open_member` returns a `MemberData`, and each field is a promise the reader makes:

- `stream`: the decoded bytes. archivey closes it.
- `checked=True`: the stream checks its own checksum and raises on a mismatch. A read to
  the end then counts as `Verification.CHECKSUM`.
- `digests`: checksums the archive stores, which archivey computes and compares as the
  bytes go by, exactly as for a ZIP member's CRC-32.
- `bounded=True`: the stream never returns more than `member.size` bytes, so archivey can
  skip the one-byte read past the end that looks for extra data (measurable on small
  members).
- `ranges`: the archive spans the stream reads, so a remote source can fetch each one in
  a single request.

### The adapter (`internal/format_adapter.py`)

A format written this way does not subclass `BaseArchiveReader`. Two adapter classes do,
once, for every such format:

- **`IndexedReaderAdapter`** implements `_iter_members` by calling `iter_members()` and
  `_open_member` by calling `open_member()`. It hands the reader a `ReaderSource` built
  on a `SharedSource`, so every `view()` has its own position and two member streams open
  at once cannot move each other.
- **`SequentialReaderAdapter`** runs the reader's `walk()` as the member walk. In a
  streaming pass, a member's stream is a window of the walk's stream, and whatever the
  caller leaves unread is skipped before the walk resumes. In random access on a seekable
  source, the adapter records where each member's data starts, so
  `open_archive(path).open(name)` reads it directly with no walk.

The adapter also translates exceptions (the reader's `translate_exception`, then the
handler's), wraps a member stream that cannot seek in a `RespawnStream`, and declares
the backend flags (`SUPPORTS_STREAMING_NON_SEEKABLE` is true for a sequential format).

`register_builtin_format(Handler)` builds a `ReadBackend` subclass for a built-in format,
in the built-in group. `register_format(Handler)`, the public function, calls
`register_plugin`, which builds the same kind of class and registers it **after** all
built-in backends.

### Why some built-in formats use the public interface

The interface was designed after the maintainer asked for an architecture that carries
streaming formats like TAR from the first version, not an indexed-only one (2026-10-25,
`openspec/changes/plugin-api/design.md` §2a), and asked for it
to be checked against real third-party format libraries (ARJ, CAB and others) before it was
built. ISO moved onto it first, with a benchmark to catch regressions; then CPIO, ar and
SquashFS; then the new formats (RPM, CAB, XAR, deb) were written on it from the start.
Writing built-in formats against the public interface keeps the interface honest: if
something is missing, a built-in format notices first. The ar and CPIO readers import only
public names plus `register_builtin_format`, and their tests check that.

The formats that stay internal are the ones whose features are outside the interface's
first version: passwords, multi-volume sets, self-extractor stubs, member data decoded by
an external program, or a hand-tuned hot path. The directory reader stays internal because
it has no bytes to describe (maintainer, 2026-10-25).

### What the first version leaves out

From the `formats.py` docstring: an indexed format inside a compression stream, member
data decoded by a library in a sequential format (now partly covered by
`MemberSpan.data`), self-extractor stubs, multi-volume sets, passwords, and new diagnostic
codes.

## Plugins from outside

A program calls `archivey.formats.register_format(MyHandler)` before other threads open
archives. Nothing is loaded automatically (no entry points); the maintainer chose explicit
registration (2026-10-25). After the call, `open_archive`, `detect_format`,
`format_availability`, the format lists and `format="<ext>"` all know the format.

A plugin's format is a `PluginContainer` value rather than a `ContainerFormat`, so
`ArchiveFormat.container` can hold either. `FormatInfo.from_plugin` says which.

Three safety rules apply to plugins:

- **Built-in signals win.** A plugin's magic counts only when no built-in signature
  matched, and its probe runs after every built-in probe. Registering a plugin never
  changes the answer for a file a built-in format reads. A plugin may not claim a built-in
  extension.
- **Plugin code is trusted code.** It runs in the caller's process. archivey's limits
  cover what the reader hands over (members, names, bytes), not the reader's own parser.
- **No stability promise.** The interface, `PluginContainer`, `PluginStream`,
  `FormatPolicy.replace` and `FormatInfo.from_plugin` may change in any release, a patch
  release included. Pin the exact version.

### Codecs from outside

A compression format is one `CodecHandler` subclass whose `decompressor(call)` returns an
object shaped like `zlib.decompressobj` (`decompress`, `eof`, `unused_data`,
`needs_input`). `register_codec` wraps it as a `PluginCodec` (`internal/codec_adapter.py`)
in the codec registry. From then on archivey reads it as a single compressed file, as
`.tar.<ext>`, around each sequential format, through `open_stream()` and through
`ReaderContext.decompress`. The generic `framed_decoder.py` drives it, with the same
limits and end-of-stream checks as the built-in codecs.

## Turning readers on and off: `FormatPolicy`

`ArchiveyConfig(formats=FormatPolicy(...))` is per call, like the diagnostic policy
(`format_policy.py`). The maintainer chose a per-call policy over process-wide switches
(2026-10-27). It can:

- **`only=` / `exclude=`** restrict which containers and stream formats may open.
  Detection still reports the true built-in format; the policy then refuses it, with a
  message that names the setting.
- **`plugins=False`** turns plugin formats off. An off plugin is left out of detection
  altogether (magic, extensions, probe), so its code does not run and its signals cannot
  shadow another plugin's (maintainer, 2026-10-28).
- **`replace=`** swaps a built-in reader (ZIP, 7z, RAR, ISO, SquashFS, CAB or XAR) for an indexed plugin
  handler. The replacement gets the archive from its start in one file: no volumes, no
  stub.
- **`exclude_libraries=`** makes optional packages read as not installed for the call.
  The maintainer chose to restrict by *library*, not by algorithm, because a library
  installed system-wide could not otherwise be avoided (2026-10-27), and to take an enum
  (`OptionalLibrary`) so a typo cannot silently leave a library on (2026-10-28).

The design is in `openspec/changes/archive/2026-10-28-format-policy/`.
