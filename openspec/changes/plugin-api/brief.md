# plugin-api — let other packages add archive formats

**Status:** Design only. Revised 2026-10-25 after the maintainer's review; the calls below
are the maintainer's. No code until the maintainer approves this revision. Additive: no current call changes.
Target: 0.3.0. Effort: large (four PRs, about 1,300 new lines).

**Why it matters:** Today every format lives in `archivey.internal`. A rare format (CPIO,
CAB, SquashFS, WIM, XAR) can only be added by changing archivey. A public interface lets
another package add one, and that package gets archivey's listing checks, name rules,
safe extraction and extraction limits without writing them.

**Why not make `BaseArchiveReader` public instead:** for a format in this repo, extending
the base class stays the right way (TAR, ZIP, RAR and 7z keep doing it). The interface
is for code outside the repo. A subclass of the 4,000-line base class sees about 150
methods, so every internal refactor would break plugins, and a subclass can override a
hook and lose a guarantee without an error. The interface is about ten names, and the
checks run in an adapter the plugin cannot skip.

**What it does:**

- A public submodule, `archivey.plugins`. A plugin subclasses `FormatPlugin` (detection
  data and `open`) and one of two reader shapes, then calls `register_format()`:
  - **Indexed** (`IndexedReader`: ZIP, ISO, CAB shape): list the members, then open any
    member by a locator.
  - **Sequential** (`SequentialReader`: TAR, CPIO, AR shape): one `walk()` that reads
    headers forward and says where each member's data is. Works from a pipe, and gets
    random access on a seekable file for free.
- **Outer compression for sequential formats:** `x.cpio.gz` detects as CPIO over gzip,
  as `x.tar.gz` detects as TAR over gzip. The adapter owns the codec stream.
- An internal adapter turns a plugin reader into an ordinary `BaseArchiveReader`, so
  every public method, limit and diagnostic works the same for a plugin format.
- A plugin names its format with its own `StrEnum` that subclasses a new public
  `PluginContainer`. `FormatInfo.from_plugin` lets a caller refuse plugin formats.
- ISO moves onto the indexed shape. A CPIO plugin in `packages/archivey-cpio/`
  (unpublished) proves the sequential shape, piped and compressed.

**Decided by the maintainer (2026-10-25):**

1. `archivey.plugins` is **provisional**: it may change in a minor release without the
   deprecation step until the maintainer marks it stable.
2. Registration only by an explicit `register_format()` call. No automatic loading from
   installed packages.
3. The first version must carry streaming formats: both reader shapes, pipes included.
4. `cpio.gz` and the other compressed forms detect as the plugin format over the codec.
5. `FormatInfo.from_plugin`: yes.
6. ISO moves onto the interface.
7. The CPIO proof lives in `packages/archivey-cpio/`, unpublished.
8. The directory reader stays internal.
9. A sequential plugin may hand over data its library decoded (LHA, ARJ, ACE, libarchive).
10. Digests the enum cannot name: a `checked=True` flag; the stored value goes in
    `member.extra` (`HashAlgorithm` stays closed).

The interface was checked against eleven formats and their existing libraries
(`design.md` §2b).

**Still open:** nothing.
