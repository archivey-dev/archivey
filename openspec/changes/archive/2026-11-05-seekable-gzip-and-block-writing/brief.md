# seekable-gzip-and-block-writing — zero-dependency random access for blocked gzip

**Status:** Exploration — specs only, no code lands in this change. BGZF reading shipped separately (2026-10-20, `gzip-member-seek-points`); mgzip, indexed_gzip and writing remain. Depends on the Phase 2 stream layer; the write half also depends on the later writing phase. Not breaking. Effort: large overall, but splittable.

**Why it matters:** random access inside a plain gzip stream needs an accelerator, because block boundaries can only be found by decoding. But two widely used gzip variants — BGZF, ubiquitous in bioinformatics, and mgzip from multi-threaded writers — are self-describing: each stores its per-block compressed size in the gzip header, so a seek index can be built by walking members without decompressing, exactly like we already do for xz and lzip. That means archivey can give these random access with no dependency at all, matching the native-first philosophy.

**What it does:** proposes three things. First, native zero-dependency random access for blocked gzip, recognized by the block subfield and served by decoding only the needed member. Second, indexed_gzip as an optional lighter, more portable accelerator for arbitrary gzip, able to persist its index. Third, on the write side, an optional block size that produces independently-decompressible output using each format's standard blocking — gzip becomes BGZF, xz sets its block size, zstd uses its seekable format — so the output stays readable by ordinary tools and round-trips with the native readers.

**Decided:** plain gzip detection is unchanged — the blocked structure is discovered by the seekable reader, not by format detection, so there is no new magic or format enum. Arbitrary gzip without an accelerator stays unsupported by design. The three parts are sequenced separately: native blocked-gzip reading is pure standard library and can land early, indexed_gzip is a small low-priority optional backend, and block-split writing belongs to the writing phase.

**Your call later:** mainly sequencing and appetite — how much of this you want before the first release versus after; the reading half is cheap and independent, the writing half is entangled with writing.

**Bottom line:** a well-shaped specs-only proposal; the zero-dependency blocked-gzip reader is the appealing near-term piece, the rest can follow with writing.
