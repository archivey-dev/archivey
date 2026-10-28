No task starts until the maintainer approves the 2026-10-25 revision of `design.md`. Each numbered group is one PR, except group 1, which lands in stages, in this order: **1a**, the indexed shape with tests and the user page; **#1052**, asked for while 1a was in review: `ReaderContext.decompress`, seekable members over a plugin stream that reads forward only, and plugin-supplied digests (1.2d to 1.2f); the ISO port (group 2); then **1b**, the sequential shape: 1.2a, 1.2b, the rest of 1.2c, 1.3, 1.4 and 1.6. Only 1b waits for the ISO port. `ForwardStream.decompress` (1.2c) is the sequential shape's decoder, not `ReaderContext.decompress`. No spec delta lands before group 4 (4.2).

## 1. Format identity, registry, detection and the adapter

- [x] 1.1 Add `PluginContainer` (`StrEnum` base) to `types.py`; type
      `ArchiveFormat.container` as `ContainerFormat | PluginContainer`; keep a
      `PluginContainer` member in `__post_init__`; `display_name` drops `_UNCOMPRESSED`
      for a pair with no named constant.
- [x] 1.2 `internal/format_adapter.py`: `PluginBackend(ReadBackend)` and
      `IndexedReaderAdapter(BaseArchiveReader)` (locator on `_raw`, name normalization,
      size and digest verification, `ArchiveInfo` and `CostReceipt` built by the adapter,
      handle lock for plugins that keep their own handle).
- [x] 1.2a Sequential shape in the adapter: the forward pass over `walk()`
      (`_iter_with_data`, `_list_before_extraction`, the `_before_pull_locked`
      hand-off), span windows with skip-on-advance, recorded offsets for random access
      on a seekable source, link targets read from data. *`SequentialReaderAdapter`
      serves the walk as the member walk, through the base class's passes; link targets
      are read while walking (design §2a, "As built"). TAR's one-pass random-access read
      waits for outer compression.*
- [ ] 1.2c Decoded `MemberSpan.data` (drain on advance, re-walk for random access),
      `ForwardStream.decompress`, `checked` members counted as verified,
      `ReaderArchiveInfo.is_solid`. *1a landed `checked` and `is_solid`;
      `ForwardStream.decompress` landed after outer compression; decoded data is
      left.*
- [x] 1.2d `ReaderContext.decompress(data, method, *, size, properties)`: a member's
      compressed bytes through archivey's codec layer, with the caller's config and
      the member's sizes, for raw Deflate, Deflate64, bzip2, Zstandard, LZ4 frames,
      Brotli, raw LZMA and LZMA2 (maintainer, 2026-10-26).
- [x] 1.2e Seekable members over a plugin stream that reads forward only: a forward
      seek reads through, a backward one calls `open_member()` again
      (`internal/streams/respawn.py`, shared with RAR's `unrar` pipe), including a
      member listed with no size (maintainer, 2026-10-26).
- [x] 1.2f `MemberData.digests`, `MemberDigest` and `Hasher`: checksums the plugin reads
      when opening a member, computed by archivey for a `HashAlgorithm` name and by a
      hasher the plugin supplies for any other (a listed name archivey can hash keeps
      archivey's hasher) (maintainer, 2026-10-26 and 2026-10-27;
      see design.md).
- [x] 1.2b Move TAR's codec-stream opening (`_open_byte_stream`) to a helper shared
      with the adapter, for compressed sequential plugins.
      *`BaseArchiveReader._open_outer_codec_stream`. A sequential plugin is registered
      for each single-file codec's pair and compound extensions (`.cpio.gz`); its walk
      reads the decoded stream through a buffer (streaming) or views of it (random
      access), costed as a compressed TAR is.*
- [x] 1.3 `archivey/formats.py`: `FormatHandler`, `FormatReader`, `IndexedReader`,
      `SequentialReader`, `MemberRecord`, `MemberSpan`, `MemberData`, `MemberDigest`,
      `Hasher`, `ForwardStream`, `ReaderSource`, `ReaderContext`, `ReaderArchiveInfo`, `Magic`,
      `register_format`. Registration refuses clashing container values, already
      registered formats, and extensions a built-in format claims. *1a landed all but
      `SequentialReader`, `MemberSpan` and `ForwardStream`, and also refuses a
      container value or name that is already a `format=` spelling. The sequential
      stage added those three and `SequentialFormatHandler`; a stage after outer
      compression added `ForwardStream.decompress`, each call a new layer of the walk
      (a codec over the rest of the walk's buffer when streaming, over a view of the
      parent layer for random access, kept by where it starts so a second walk
      reuses it).*
- [x] 1.4 Detection: plugin signals counted only when no built-in signal matched at the
      same or a higher confidence; probes get the peeked prefix only. `_probe_inner_tar`
      becomes an inner-container probe (TAR first, then sequential plugin magic ending
      within 512 bytes), under the same budget. *1a landed the ranking and the probe;
      1b the inner-container probe (`_probe_inner_container` over
      `ReadBackend.INNER_MAGIC`; the tier keeps its name, `inner_tar`).*
- [x] 1.5 `format_args.py`: plugin spellings after built-in ones. Check the default
      branch of each `ContainerFormat` test in `core.py`, `detection.py`,
      `cli/common.py`, `cli/extract_cmd.py` for a plugin container.
- [x] 1.6 Tests: a minimal in-test plugin through `open_archive`, `stream_members`,
      `extract_all`, `detect_format`, `format_availability`, the CLI; a short member
      stream raises `TruncatedError`; a wrong digest raises; a member named `../x` is
      refused like a built-in's; a plugin magic never outranks a built-in one. A
      sequential test plugin read from a pipe, gzip-compressed, under
      `stream_members`, `extract_all` and a `CONCURRENT` reader. *1a landed the
      indexed tests. The sequential test plugin (`tests/test_format_api_sequential.py`)
      reads from a file, a non-seekable stream and an OS pipe, plain and inside gzip,
      bzip2 and xz.*
- [x] 1.7 `FormatInfo.from_plugin` (maintainer, 2026-10-25).

## 2b. TAR onto the sequential shape (after stages 3 and 4)

The test of the sequential shape, as the ISO port is of the indexed one (maintainer,
2026-10-28): it may stay internal for speed afterwards.

- [ ] 2b.1 `ForwardStream.peek(n)`: TAR looks at the block after a link with a size, and
      replays blocks at its end checks. On a pipe the peeked bytes are buffered and
      served to the next read (maintainer, 2026-10-28).
- [ ] 2b.2 Port `TarWalker` to `walk()` after outer compression (stage 3) and decoded
      member data for sparse files (stage 4); benchmark against the built-in reader.

## 2. ISO onto the interface

- [x] 2.1 `IsoReader` implements `IndexedReader`; `IsoReadBackend` becomes a
      `FormatHandler` registered with `register_format`. *Registered instead with the
      internal `register_builtin_format()`, so ISO keeps its built-in container, its
      place among the built-in backends and `from_plugin == False`.*
- [x] 2.2 `self._emit_*` calls go through `ReaderContext`; `_handle_guard` moves to the
      adapter; the raw-sector-image refusal moves from `core.py` into `open`. *The
      refusal stays in `core.py`: it runs before the availability check, so an image
      named `.bin` is refused the same with or without pycdlib.*
- [ ] 2.3 The ISO suite passes unchanged; `--all-configs` without pycdlib still reports
      ISO as known with `NONE` support and the install hint.
      *The suite passes; tests that reached into the old reader's internals were
      repointed, and the multi-extent gap test now reads the gap. The
      `--all-configs` check is not run yet.*
- [x] 2.4 Gaps the port found, added to the interface: `FormatHandler.translate_exception`
      (errors in `open()`), `ReaderContext.report`, `.link_target_unavailable`, `.config`
      and `.normalize_name` with `MemberRecord.stored_name`, and `MemberData.bounded`.
      ISO also reads member data through source views, joining the extents of a
      multi-extent file wherever they sit (maintainer, 2026-10-27).

## 3. CPIO package

- [x] 3.1 `packages/archivey-cpio/` (unpublished): a `SequentialReader` for binary, odc,
      newc, newc-with-CRC; `.cpio.gz` / `.cpio.xz`; read from a file and a pipe.
      *`.cpio.gz` / `.cpio.xz` came with outer compression (stage 3), and `.a.gz` too.*
- [x] 3.2 Fixtures written by GNU `cpio` and `bsdcpio`: files, directories, symlinks,
      hard links, device nodes (listed as `OTHER`), a damaged checksum, a truncated
      member. *GNU cpio 2.15 writes all four variants, bsdcpio 3.7.2 odc and newc (its
      binary writer refuses a FIFO); the damaged and truncated cases are cut from them
      in the tests.*
- [x] 3.3 A test that fails if the package imports `archivey.internal`.
- [x] 3.4 CI job that installs the package and runs its tests.

## 3a. ar package

A second sequential format, written from outside the library (the maintainer asked for
one more one-pass format to test the interface, 2026-10-28).

- [x] 3a.1 `packages/archivey-ar/` (unpublished): a `SequentialReader` for the GNU
      (System V, Windows `.lib`) and BSD (macOS) dialects; long-name tables carried
      across the walk, BSD names read from the data area; symbol tables skipped; thin
      archives refused.
- [x] 3a.2 Fixtures written by GNU ar 2.42, bsdtar 3.7.2 and llvm-ar 18
      (`--format=darwin`); Windows long names, blank fields and damaged headers are
      built in the tests.
- [x] 3a.3 The same import check, and a CI job.

## 3b. SquashFS package

A second indexed format, written from outside the library (the maintainer asked for one
more indexed plugin, 2026-10-27).

- [x] 3b.1 `packages/archivey-squashfs/` (unpublished): an `IndexedReader` for
      SquashFS 4.0 with gzip, xz, LZMA, LZ4 (with `lz4`), LZO, Zstandard and
      uncompressed images; files with fragments and sparse blocks, directories, symlinks, hard links
      and device nodes, FIFOs and sockets (listed as `OTHER`).
- [x] 3b.2 Images written by `mksquashfs` (`tests/data/make-images.sh`), and damaged
      copies of one: a truncated image, a bad superblock, a directory cycle, a bad name,
      a fragment past its table, a short data block, an oversized metadata block.
- [x] 3b.3 A test that fails if the package imports `archivey.internal`; a CI job that
      installs the package and runs its tests.
- [x] 3b.4 Gaps the package found, added to the interface: `ReaderContext.decompress`
      takes a `StreamFormat` (SquashFS stores zlib, xz and LZMA Alone streams; bytes
      after such a stream are reported as for a file of that format), and a
      member stream whose reads may be short before the end is read whole: the adapter
      puts streamtools' `FullCountStream` (no buffer) in front of any stream that is not
      buffered or archivey's own, and `buffered_stream()` (`ensure_bufferedio`) is
      public for a plugin that wants a buffer (maintainer, 2026-10-27).
      `block_stream()` (`internal/streams/blocks.py`): a file stored as fixed-size
      blocks that decode on their own, read and seeked by archivey from the plugin's
      `read_block(i)` (maintainer asked for shared infrastructure, 2026-10-27).
- [x] 3b.5 LZO, which archivey does not decode: the package's own LZO1X decoder in
      Python (from the kernel's `lzo1x_decompress_safe`), or liblzo2 through
      `python-lzo` when installed; tests cross-check the two (maintainer, 2026-10-27).
- [ ] 3b.6 Still outside the interface: the LZ4 block format (the package calls
      `lz4.block` itself) and LZO, each capped at the block size by the package rather
      than by archivey's decoder limits. Extended attributes and the export table are
      not read.

## 4. Docs and specs

- [x] 4.1 User page "Adding a format" (Opus), with the trust section; API page entry.
      *Landed with 1a so the API could be read as a plugin author sees it; its
      "later version" lines are rewritten as 1b and the ISO port land.*
- [ ] 4.2 New spec `format-plugins`; deltas to `backend-registry`, `format-detection`,
      `archive-data-model`, `format-iso`. The `format-iso` delta owes two changes the
      ISO port (group 2) made false in the spec: member data is read through source
      views, not `PyCdlibIO` under the handle lock ("Serialize shared pycdlib handle
      operations"), and two file records sharing one extent raise `CorruptionError`,
      not `UnsupportedFeatureError` (the record matrix). A `diagnostics` delta too,
      since a plugin emits archivey's codes: `UnknownMemberTypeContext.stored_type` is
      the format's own spelling of the type, not only the TAR typeflag byte; and the
      `zeros_to_eof` format list and `MEMBER_TYPE_UNKNOWN`'s STRICT-exemption rationale
      read as examples, not as the set of emitters.
- [ ] 4.3 `dev-docs/IDEAS.md` and `VISION.md`: the public backend API item points here.

## 5. Later: decoders that compound (maintainer, 2026-10-28)

- [ ] 5.1 A public `register_codec()`, the decoder twin of `register_format()`: a codec
      registered once is read by `open_stream`, as a single-file archive, inside TAR and
      sequential plugin pairs, by the inner-container probe and by
      `ReaderContext.decompress`. The pair, extension and codec tables become
      computed on demand instead of at import.
- [ ] 5.2 LZO as a built-in codec (the lzop stream and raw LZO1X as a member method),
      python-lzo optional with the pure-Python decoder as the fallback, when SquashFS
      becomes built-in.

## 6. Names

- [x] 6.1 Rename for the framing that built-in formats use these structures too and
      plugins reuse them (maintainer, 2026-10-28): `archivey.plugins` is
      `archivey.formats`; `FormatPlugin` and `SequentialFormatPlugin` are
      `FormatHandler` and `SequentialFormatHandler`; `PluginReader` is `FormatReader`;
      `PluginArchiveInfo`, `PluginSource` and `PluginContext` are `ReaderArchiveInfo`,
      `ReaderSource` and `ReaderContext`; `internal/plugin_adapter.py` is
      `internal/format_adapter.py`; `register_format(plugin)` takes `handler`. `PluginContainer` keeps its name: only a format
      from outside archivey defines a container. `brief.md`, `proposal.md` and
      `design.md` keep the old names as written.
