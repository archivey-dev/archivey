# Ideas

This page lists what we are thinking about for archivey beyond the work already in
progress. It is here so that users can see where the library may go, and so that
contributors can find something to work on.

**An idea is not a commitment.** Nothing here is scheduled unless its status says so.
Work that is committed has an OpenSpec change under `openspec/changes/`. Decided
out-of-scope items for v1 (async, in-place modification, and others) are in
`openspec/project.md` §"Deferred / out of scope (v1)".

**To pick one up**, open a GitHub issue that names the idea and says how you would
approach it, before you write code. Most ideas here touch a contract, so the shape is
worth agreeing first. **To propose a new idea**, open an issue too. If it is accepted, it
is added here.

Each idea carries a status:

- *Planned for 0.2.0* — committed for the first public release; the OpenSpec change
  named with it carries the work.
- *Planned after 0.2.0* — we intend to do it, after the first public release.
- *Needs design* — we want it, but the shape is not settled. Start with a proposal.
- *Open idea* — worth doing if someone needs it. Not planned.

**Good first contribution** marks an idea that is small and self-contained.

## Formats

- **List a ZIP whose central directory is lost, and read spanned ZIP sets.** *Needs
  design.* The native ZIP reader (the `native-zip-reader` OpenSpec change) already
  lists a damaged central directory up to the damage and the local headers past it. It
  reads a ZIP from a pipe or socket by walking the local headers forward, and walks them
  when the end record is not in the file's tail (which lists a ZIP cut before its
  directory). Its parser's per-entry disk number is what reading spanned
  `.z01`…`.zip` sets would follow (by resolving each (disk, offset) pair). See
  [`formats/zip.md`](formats/zip.md) §5.
- **Read raw CD sector images (`.bin`).** *Open idea.* 0.2.0 recognizes a raw image and
  refuses it (`iso_reader.refuse_raw_sector_image`). Mode 1 and Mode 2 Form 1 images
  strip to a byte-identical `.iso`, so a slicing stream that skips the sector headers
  would let the ISO reader read them. Out of scope: multi-track images that need the
  `.cue`, and EDC/ECC verification (which the docs must then say is skipped).
- **UU and Base64 wrappers as single-file formats.** *Open idea.* **Good first
  contribution.** `uuencode` files (`.uu`, `.uue`, including `begin-base64`) turn up in
  old mail and Usenet drops. They fit the one-member single-file backend: peel one
  wrapper and yield the payload. The decoder is trivial; the work is in weak detection
  (`begin `), in trusting the embedded name and mode, and in a ratio guard that expects
  data to shrink. Bare single-file only, not transparent `uu → gz → tar`.
- **Opt-in legacy name-encoding detection.** *Needs design (post-1.0).* Names with no
  Unicode marker that are not valid UTF-8 decode via `surrogateescape` today: honest and
  lossless, but garbled. Codepages have no oracle and filenames are too short for a
  statistical detector, so a wrong guess would be plausible and silently wrong. If built:
  off by default, behind an extra, one guess per archive over all such names, with a
  diagnostic. **The first step is a good first contribution**: a way for users to report
  names archivey could not decode (a docs note, a one-line CLI hint, or a helper that
  prints the raw-name samples), with no guessing. That is how we would collect the corpus
  a detector needs.
- **`unar` for formats archivey does not decode.** *Open idea.* `unar` reads StuffIt,
  LHA, ARJ, ACE, CAB, old Mac archives and codecs that have no Python library. The process
  layer (`internal/external/unar.py`) is already format-agnostic, so a backend would add
  its own refusals and entry mapping, as `rar_unar.py` does for RAR.
- **libarchive backend.** *Open idea.* `python-libarchive-c` as an additional backend for
  several formats, behind its own extra. It brings a native C dependency and weak random
  access.
- **Decode RAR without `unrar`.** *Open idea (research).* Build a minimal synthetic
  one-file RAR stream and feed it to libarchive's RAR decoder, as `rarfile` does. It could
  drop the `unrar` requirement for common cases, but RAR decode correctness is hard, and
  `unrar` stays the reference.
- **Subprocess decompressor streams.** *Open idea.* One reusable stream that pipes data
  through a system binary (`zstd`, `xz`, `brotli`, `lz4`), for environments where C
  extensions will not install but the CLI tools are on `PATH`. Forward-only, the same
  pattern archivey already uses for `unrar`.
- **Lift the directory-glob and backslash refusals on the `unrar` path.** *Open idea (low
  priority).* A RAR member name is passed to `unrar` as a mask, so archivey predicts which
  other members it matches. A glob in a directory component and a literal backslash are
  still refused ([`formats/rar.md`](formats/rar.md) §2.3). Lifting them means measuring
  those shapes in `tests/test_rar_unrar_names.py`, on Windows too. The names involved are
  adversarial, and a wrong model returns the wrong member's bytes.

## Detection

- **Extension-first detection, and stopping early on agreement.** *Needs design.* Try the
  formats a filename suggests first, then fall back to the full sweep, so a misnamed file
  is still found. Content probes already follow the name: by default only the probe the
  extension names runs ([`topics/detection.md`](topics/detection.md) §2.5). A second step is to stop as soon as the extension and the content agree, which
  saves the later scan tiers; the sound version may skip the expensive tiers but never a
  cheap exact-magic check. On `/usr`, near magic already settles almost every file, so the
  saving needs a Brotli-heavy corpus to show (the detection-algorithm
  [investigation](investigations/archive-format-detection-algorithm.md)).
- **Archive role: tell the caller whether to look inside.** *Needs design (post-1.0).*
  `open_archive()` reads a photo backup, a `.docx`, a `.jar` and a wheel the same way.
  A recognizer for container markers (`META-INF/MANIFEST.MF`, a stored `mimetype` first
  entry, `*.dist-info/WHEEL`) would let a backup indexer skip packaging files. It must
  say "not recognized" rather than "this is data", and rules need an order (an APK is
  also a JAR). See [`formats/zip.md`](formats/zip.md) §3.
- **Volume-shaped names: detect first, then explain.** *Open idea.* Today a `.zNN` name is
  refused before detection runs. Running detection first, and only turning a failure into
  "rejoin first" when the name looks like a volume, would keep odd but valid archives
  openable. It should replace the early refusal, not sit on top of it
  ([`formats/zip.md`](formats/zip.md) §3).
- **Raise on a tie instead of choosing by registry order.** *Needs design.* When two
  formats are equally well supported by the evidence, detection should raise a dedicated
  error. Later, opening could try each tied candidate; that needs limits on cumulative
  work and a rule for when several succeed.
- **Makeself-aware payload location.** *Open idea.* A makeself `.run` stub states where
  its payload starts (`SKIP`) and how it is compressed (`COMPRESS`). Reading that would
  replace a 2 MiB scan with one seek and would name compressors archivey does not read.
  It needs a corpus of current and old installers first
  ([`topics/prefixed-archives.md`](topics/prefixed-archives.md)).
- **Bound the SFX search at the PE overlay.** *Open idea.* **Good first contribution.**
  A 7z SFX with data after the archive reads the whole scan window today. For a PE stub,
  the end of its last section is a safe bound, because a decoy inside the stub cannot pass
  it. The current cost is pinned by
  `test_short_7z_hit_scan_cost_is_bounded_by_the_window`
  ([`topics/detection.md`](topics/detection.md) §2.2).
- **Price detection in round trips, not bytes.** *Needs design.* A range-request source
  and a local file look the same to detection, so its byte budgets are in the wrong
  currency for remote sources. Needs a measurement on a real range-request source.

## Reading and verification

- **Raise a stream's verification level on demand.** *Open idea.* A member stream
  reports `verified` and `verifiable` (`Verification`: `NONE`, `KEY`, `STRUCTURE`,
  `CONTENT`). A `verify(at_least=…)` method could read what is left to reach a level,
  and a `reader.verify(member)` could check a member without handing out its bytes.
  Retiring `ENCRYPTED_MEMBER_UNVERIFIED` in favour of the level is a separate call.
- **Count the xz, zstd and LZ4 checksums in the level.** *Open idea.* These formats
  carry a checksum per stream or frame only when the writer added one, so their
  streams stop at `STRUCTURE` today. Each decoder would report, per frame, that a check
  was present and passed.
- **Say when a WinZip AES seek re-reads the ciphertext.** *Open idea.* **Good first
  contribution.** To keep the HMAC across seeks, the read that returns an AES member's last
  byte first reads the ciphertext the seeks skipped. The user docs don't state this, and
  nothing reports it at run time. A diagnostic past about a megabyte would match
  `STREAM_REWIND_REDECOMPRESSES`.
- **Confirm a stored encrypted 7z folder from its smallest member.** *Open idea.* For a
  `Copy` chain, any member's bytes are addressable, so the cheapest member of at least 4
  bytes with a CRC could confirm a password instead of the earliest one.
- **Tell a real LZMA dictionary size from decrypted garbage.** *Open idea.* A wrong
  ZipCrypto password that passes the check byte can decrypt LZMA properties to a huge
  dictionary, which surfaces as a resource limit. Real encoders write only a few sizes, so
  an off-grid size could be reported as a wrong password. Measure what real writers emit
  first.
- **Salvage mode.** *Needs design.* Backups are full of truncated and corrupt archives.
  Reads already return the readable prefix and then raise, and a member's data error
  already leaves `stream_members()` running wherever the next member is reachable (ZIP,
  7z, RAR, ISO, plain TAR; `archive-reading` spec). What is left is damage to the
  archive's structure, which ends the pass: nothing resyncs past it. A salvage mode would
  walk ZIP local headers when the central directory is gone or a pipe's local-header walk
  loses its place, resync a TAR or compressed TAR stream on the next valid header, and
  return every recoverable member with its error.

## Performance

- **Hold the solid-block decoder across `open()` calls.** *Needs design.* Each random
  `open()` on a solid 7z rebuilds the folder decoder from the start, so opening every
  member costs about 4.5× one pass. Keeping one decoder and reusing it when the next target
  is ahead would remove that. The open question is what to keep under
  `concurrent_operations=True`, where several decoders can be live at once.
- **Batch small members into one `unrar` call.** *Open idea.* A non-solid
  `stream_members()` pass spawns one `unrar` per member, about 5 ms each. Small adjacent
  members could share a process and be split by size, as the solid path already does.
  This needs a measured threshold and a spec change, because `format-rar` forbids
  multiple member paths per call today.
- **zstd frame index from frame headers.** *Open idea.* zstd seeks from frame starts a
  forward read has reached, and from the seekable format's seek table. A multi-frame file
  with no table (`pzstd`) could have its frames found by walking frame and block headers,
  without decoding. It helps only multi-frame files, so measure how common they are first
  ([`formats/zstd-lz4.md`](formats/zstd-lz4.md) §7).
- **Lazy `ArchiveMember` derivation.** *Needs design.* The one known lever for faster ZIP
  open-and-list (`benchmarks/RESULTS.md`), and for the per-member memory that
  `max_members` has to account for (about 1 KB per 7z member).
- **Parallel extraction.** *Open idea.* Extract independent members, or independent
  solid blocks of a 7z, in parallel. The concurrent member stream seam exists; any speed
  claim needs measurement. Pairs with independent file handles per view (below) and with
  a position on free-threaded Python.
- **Independent handles for a file source.** *Open idea.* A path source reaches the codecs
  by being turned back into a path in three places, because a path is what gives a fresh
  descriptor. `ArchiveSource.open_independent()` would remove those branches and let
  concurrent views avoid sharing one locked handle. Measure the lock contention first.

## API and usability

- **A stricter `DecoderLimits` preset for untrusted input.** *Needs design.* A preset for
  servers: 256 MiB decoder memory (enough for every 7-Zip preset), `2**24` key-derivation
  rounds, and possibly a lower `max_members`. The name is open (`UNTRUSTED` is the
  suggestion). It may also want to be a mode, for example refusing a decode that could
  take the process down.
- **Resource usage against the limits, as data.** *Open idea.* A caller cannot ask how
  close an archive came to each limit. A usage record on the reader and on the extraction
  report would help tune limits against a real corpus. `scripts/scan_archives.py` shows
  what can be read from public results today.
- **Opt-in free-space check before extraction.** *Open idea.* **Good first contribution.**
  Sum the declared sizes of the selected members and compare against
  `shutil.disk_usage(dest).free`, failing before anything is written. Advisory only: it
  trusts declared sizes, so it is a convenience against honest mistakes, not a bomb
  defense. Skip it when the total cannot be known.
- **`SANITIZE` extraction policy.** *Needs design (post-v1).* An opt-in policy that rewrites
  names instead of refusing them: unsafe paths, and names the destination file system
  cannot represent.
- **Configurable symlink extraction.** *Open idea.* What to do when a symlink member cannot
  be created as a symlink (FAT, Windows without the privilege). Today it fails that member.
  An option such as `copy` must not reintroduce a path escape.
- **Mark macOS AppleDouble sidecars.** *Open idea.* Set a key such as
  `extra["macos.resource_of"]` on a `._name` file (next to `name` in a macOS TAR, under
  `__MACOSX/` in a Finder or `ditto` ZIP) so callers can skip them. Marking by name
  alone was tried and dropped: it adds nothing over a name filter (`docs/formats.md`)
  and also marks a real file called `._x`. A version worth having checks the AppleDouble
  magic (`00 05 16 07`) at the start of the data. That costs a read of the first bytes
  of each `._` file: buffered before a forward pass yields it, and an extra member open
  per `._` file in a listing that otherwise reads no data (a seekable ZIP). Also requiring the
  described file to exist costs more in a TAR, where the sidecar comes before its file:
  the pass would hold the small sidecar back until it has seen the next member.
- **Pathlib-like navigation.** *Open idea.* An `ArchivePath` with `/`, `iterdir()`,
  `glob()` and `read_bytes()`, as `zipfile.Path` does.
- **fsspec integration.** *Open idea.* Expose an opened archive as an fsspec file system,
  so pandas, dask and pyarrow read members by path. Opening from a URL could follow, with
  fsspec's listing used to find sibling volumes.
- **Best available digest without decompression.** *Open idea.* **Good first
  contribution.** A helper that returns the strongest digest an archive already stores
  for a member, and says whether it was stored or computed. The recipe is in
  `docs/formats.md`.
- **A library `verify()` primitive.** *Open idea.* `archivey test` writes its own loop
  today. Decide whether callers verify without extracting often enough for a public API.
- **Public backend API.** *Needs design.* Export the backend base class and registry so
  rare formats (CAB, CPIO, SquashFS, WIM, XAR) can be third-party plugins. It constrains
  how freely the backend contract can change, so decide before 1.0.
- **A lifecycle rule: a refused `open()` leaves nothing behind.** *Open idea.* Today this
  is specified for one case only. Before writing the general rule, audit each backend for
  the gap between creating a resource and the object that owns it.

## CLI

- **Read the archive from stdin.** *Open idea.* A piped archive is already read through
  `/dev/stdin` on Linux and macOS. What is still open is wiring the reserved `-` archive
  argument to it.
- **`--json` output.** *Needs design.* Waits for a designed member schema. The flag name
  is `--json`.
- **`--raw` names.** *Open idea.* An escape hatch that prints exact names, for scripts that
  need them before `--json` exists.

## Writing

- **Writing, designed in from the start.** *Open idea (possibly post-1.0).* Writing comes
  after reading. When it is specified, two things belong in the first version:
  reproducible output (`SOURCE_DATE_EPOCH`, stable ordering, normalized metadata) and the
  metadata-fidelity boundary (xattrs, ACLs, owners), because both shape the writer API
  ([`investigations/archive-writing-design.md`](investigations/archive-writing-design.md)).
- **Copy compressed data through without recompressing.** *Open idea.* When the source
  and destination use the same codec and parameters (deflate to deflate), copy the
  compressed bytes instead of decoding and encoding again.

## Tooling and CI

- **Commit the remaining live `rar a` fixtures.** *Open idea.* Four tests still run the
  `rar` writer at test time and skip on every CI leg. Generate their archives once and
  commit them, as ADR 0016 did for the corpus. Inventory: `tests/fixtures/rar/README.md`
  §"Tests that still need the `rar` writer at runtime".
- **Check that the Windows `unrar` download is rarlab's.** *Open idea.* The Windows CI leg
  downloads `unrarw64.exe` from an unversioned URL, so a pinned digest would go stale. An
  Authenticode check for the win.rar GmbH signature is the likely answer
  (`scripts/install-rarlab-unrar.ps1`).
- **Move the `unrar` finder onto `CliToolFinder`.** *Open idea.* `find_rarlab_unrar` repeats
  the policy in `internal/external/cli.py`, so a probe or cache fix lands twice. About
  sixty test sites patch the finder's internals, so do it as its own change, with those
  tests rewritten against the finder object.
- **Join RAR sets at the source boundary.** *Open idea.* Numbered parts are joined in
  `resolve_source`, but a RAR set is rediscovered and joined inside `RarReader`. Joining it
  at the source boundary would delete the RAR branch in `core.py` and the double
  discovery. Check the SFX stub follower and explicit part lists first.
