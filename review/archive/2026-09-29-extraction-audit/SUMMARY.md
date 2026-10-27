# Extraction and backend security audit (2026-09-28/29) — summary

PR [#512](https://github.com/archivey-dev/archivey/pull/512). The brief was the maintainer's own:
find bugs and untested corner cases in extraction and the backends, including protections
one format has and another lacks. Try to make the library raise an untyped exception,
crash, return wrong data, use large memory, or skip a limit or a rate check, and compare
the code against `VISION.md` and `dev-docs/threat-model.md`. Write reproducers first,
triage and fix later.

## How it ran

Six agents audited in parallel: extraction, ZIP, TAR and compressed streams, 7z, RAR/ISO/
directory, and cross-format parity. The extraction agent was stopped by a safety
classifier partway through, so the coordinator covered that area by hand. It was the
narrowest pass of the six, and the first place to look again.

Every finding got a reproducer in `tests/test_audit_*.py`, marked `xfail(strict=True)`
with the defect in `reason`. A fix makes the test XPASS, which fails CI until the marker
is removed. Fixes removed the marker, so the files are now regression tests. The seven
tests still xfail are the reproducers for the deferred items below.

Useful helpers in those files:
- RAR5 and RAR3 header rewriting with CRC fix-up: `test_audit_rar_iso_dir.py`,
  `_rar5_parse` / `_rar5_build` / `_rar3_parse` / `_rar3_build`.
- A TAR builder: `test_audit_extraction.py::_build_tar`.
- 7z coder-graph construction: `test_audit_sevenzip.py`.
- A counting non-seekable source for laziness checks:
  `tests/test_tar.py::test_a_pass_reads_no_member_data_the_consumer_does_not_reach`.

## Findings and dispositions

"Fixed" means fixed in #512, with the audit test as the regression test.

### Extraction coordinator
| # | Finding | Disposition |
|---|---|---|
| E1 | **High.** `l -> a/../secret`, then `a -> .`: `l` is left on disk resolving outside the destination. Writes through it are still blocked. | **Deferred:** threat-model **O22** |
| E2 | Hardlink to a directory member: misleading error | Fixed |
| E3 | Empty symlink target reached `os.symlink('')`; the raw `FileNotFoundError` aborted `extract()` | Fixed: `LINK_TARGET_UNAVAILABLE`, `reason="target_empty"` |
| E4 | File `d`, then `d/f`: raw `FileExistsError` aborted `extract()` | Fixed: typed per-member `ExtractionError` when this run wrote the blocking file. A blocking file already in the destination stays an `OSError` |

### ZIP
| # | Finding | Disposition |
|---|---|---|
| Z1 | LZMA with GP bit 1 clear (no end marker) not stopped at the declared size | Fixed. Output past the size is ignored, as stdlib does |
| Z2 | A colliding wrong ZipCrypto candidate decrypts LZMA/PPMd settings over `max_decoder_memory`, and the `ResourceLimitError` ends the candidate search | Fixed: decision **D3** |
| Z3 | GP bit 5 (patched data) served as content | Fixed: `UnsupportedFeatureError` |
| Z4 | `encoding="idna"`: raw `UnicodeError` from `members()` | Fixed: `raw_name=None` when the codec cannot re-encode, as ISO and TAR do |

### TAR and compressed streams
| # | Finding | Disposition |
|---|---|---|
| T1 | **High.** A streaming skip loops for `declared_size // bufsize` iterations in `tarfile._Stream.seek`; a 2 KiB tar declaring 2**38 bytes takes 43 s | Fixed: decision **D4**. The skip is lazy, pinned by a test |
| T2 | About 1000 chained `L`/`K`/`x` headers: raw `RecursionError` | Fixed (translated) |
| T3 | Sizes of 2**63 or more: `OverflowError` / `ValueError` / `OSError(EINVAL)` | Fixed |
| T4 | Sparse PAX / 1.0 map parse errors: raw `ValueError`; backward sparse seek: `StreamError` | Fixed |
| T5 | Out-of-range base-256 mode: `OverflowError` | Fixed (masked `& 0o7777`) |
| T6 | Codec checksum failures after the tar trailer were swallowed; past 1 MiB the checksum was never reached | Fixed: decisions **D6** / **D6b**, extended in review (K2, K5) |
| T7 | PAX sparse 1.0 map not weighed against `max_metadata_bytes` | Fixed (24 bytes per entry) |
| T8 | `.Z` LZW dictionary holds full expansions: 130 KB of input reaches about 2.1 GiB | Fixed in #519 (decision **D7**): entries past 256 bytes are stored as links, so the table stays under about 19 MiB (`formats/unix-compress.md` §4) |
| T9 | bzip2 accelerator: raw `ValueError` / `UnicodeDecodeError` | Fixed |
| T10 | Sparse map running past the stored data served the next header as content | Fixed. Up to 511 bytes of the member's own zero padding can still be served |
| T11 | **High** (found by the cross-format agent). A compressed PAX header was allocated before the metadata cap; a 185-byte `.tar.bz2` peaked at 160 MB | Fixed: decision **D5** |
| T12 | `stream_members()` / `extract_all()` decoded a compressed TAR twice in random-access mode | Fixed: decisions **D8** / **D8b** |
| T13 | Random-access TAR resolved a hardlink *forward* to a later member (found while fixing T12) | Fixed: backward only in both modes, as stdlib `tarfile` does |

### 7z
| # | Finding | Disposition |
|---|---|---|
| S1 | 7-Zip's LZMA2+Delta / +BCJ / +LZMA2 chains were refused | Fixed |
| S2 | Decoder-memory sum checked only for BCJ2 folders | Fixed (every folder) |
| S3 | A rejecting codec *upstream* of AES was taken as evidence the password was right | Fixed |
| S4 | 200+ filters or 400 nested BCJ2 coders: raw `RecursionError` | Fixed: 64 coders per folder. The 7-Zip constants were cited from memory; see open item 6 |
| S5 | Surplus LZMA2 output past the declared size was accepted silently | Fixed for LZMA2; the other end-marked codecs closed by #518. See residuals |
| S6 | `raw_name` had backslashes rewritten | Fixed |
| S7 | Unknown size-prefixed `FILES_INFO` properties refused the archive | Fixed (skipped, as 7-Zip does) |
| S8 | Member-pass streams bypassed the one-live-stream guard | Fixed |

### RAR, ISO, directory
| # | Finding | Disposition |
|---|---|---|
| R1 | **Medium/high.** A RAR5 name that is not valid UTF-8 can serve a *sibling's* bytes on the `unrar` path | **Deferred:** `dev-docs/formats/rar.md` §7 |
| R2 | Two same-named members: both unreadable | **Deferred:** same entry |
| R3 | Non-ASCII names unreadable under `LC_ALL=C` | Fixed: the child runs under a UTF-8 locale |
| R4 | 8-bit RAR3 names unreadable | Fixed: the mask is the stored bytes; on Windows, `unrar`'s own OEM→ANSI conversion (review K1) |
| R5 | 8-bit RAR3 names *listed* as UTF-16 garbage | **Deferred:** same entry |
| R6 | RAR3 `;²` or a suffix of more than 4300 digits: bare `ValueError` | Fixed |
| R7 | NUL in a name: raw `ValueError` from `read()` | Fixed (typed refusal) |
| R8 | NUL in a password cut by `unrar`, so a wrong password opens RAR4 | Fixed (refused) |
| R9 | A password larger than the pipe buffer deadlocked the spawn | Fixed (sends what the native path hashes: 127 UTF-16 units) |
| R10 | An explicit volume sequence was ignored (siblings rediscovered) | Fixed |
| R11 | Invalid RAR/ISO timestamps fabricated or dropped silently | Fixed: `MEMBER_TIMESTAMP_INVALID` |
| R12 | Solid-RAR pass streams bypassed the one-live-stream guard | Fixed |
| R13 | RAR dictionary size never checked against `DecoderLimits` | **Deferred:** decision **D9**, `rar.md` §7 |
| R14 | The `unar` copy of a prefixed (SFX) RAR *path* had no bound | Fixed: decision **D10a**, `SpoolLimits` |

### CLI, diagnostics, docs
| # | Finding | Disposition |
|---|---|---|
| X1 | `archivey test` skipped symlinks, so a damaged data-stored target reported OK | Fixed |
| X2 | Bidi controls in a link target got no listing diagnostic | Fixed: decision **D10b**; `MEMBER_NAME_BIDI_CONTROL` with `field="link_target"` |
| X3 | The byte-cap message counted a refused chunk as written | Fixed (wording; nothing was ever written past the cap) |

### Found after #512's fixes, not yet homed elsewhere
| # | Finding | Status |
|---|---|---|
| P1 | A `.tar.bz2` whose last bzip2 stream is *empty* (`bzip2 -c a; bzip2 -c /dev/null`) reports `ARCHIVE_TRAILING_DATA` with the bzip2 accelerator on, so `DiagnosticPolicy.strict()` refuses it. The same file is clean with the accelerator off. `pbzip2`-style files whose streams all carry data are clean both ways. Already on `main` before #512 | **Open.** Recorded in `IDEAS.md` |

## Maintainer decisions (2026-09-28/29)

| # | Question | Decision |
|---|---|---|
| D1 | E1: how to stop a later member turning a link into an escape | Deferred to a separate exploration. Refusing `a/../x` rejects legitimate archives; an end-of-run sweep leaves the escape live on disk for an unbounded time; a full pre-analysis is impossible for streaming. Preferred direction: recheck only the links a new link affects. See O22 |
| D2 | R1–R5: RAR names `unrar` cannot address | Fix the easy cases now: stored-bytes masks and a UTF-8 locale. Defer invalid-UTF-8 names, duplicates and 8-bit listing to a separate PR. Maintainer: "`auto` is exactly picking the best tool for each job" (a per-member `unar` fallback is on the table), and the C1 rule that `auto` decides once "is not something I remember choosing" |
| D3 | Z2: ZipCrypto + decoder limit, where the spec contradicted itself | A: a failed candidate while others remain; the first `ResourceLimitError` surfaces with a "password may be wrong" note; a lone password gets the same. Idea recorded: tell real dictionary sizes from garbage by the sizes encoders actually write (`IDEAS.md`) |
| D4 | T1: streaming skip | A: archivey reads the skipped data itself, lazily, only when the next member is requested |
| D5 | T11: PAX header over the cap | A: pre-read check against the configured budget (remaining budget in random access, the whole cap in streaming) |
| D6 | T6: checksum past 1 MiB of padding | A: keep the 1 MiB bound and report `DIGEST_UNVERIFIABLE` |
| D6b | Should `strict()` refuse that clean-but-unverified case? | Yes: "every integrity check the archive offers must have run" |
| D7 | T8: `.Z` memory | A hybrid dictionary, in its own PR with benchmarks |
| D8 | T12: double decode | One forward pass. Maintainer correction: a TAR hardlink always refers to an *earlier* member (stdlib `tarfile._find_link_target`), so forward links are not a concern |
| D8b | One-pass extraction gives up fail-closed-on-damage, list-first duplicate outcomes, and listing limits before any write | A: accept, for all TAR. Checked: a valid archive extracts to an identical tree on 20 cases |
| D9 | R13: RAR dictionary vs `DecoderLimits` | Measure `unrar`/`unar` peak memory first; the docs meanwhile say RAR is not covered |
| D10a | R14: SFX copy | Apply `SpoolLimits` |
| D10b | X2: bidi in link targets | Emit the diagnostic for targets too |
| — | R5 listing | Deferred with the RAR name PR |

## Residuals of the fixes (known limits, accepted or noted)

- **7z (S5):** ~~the past-size check covers LZMA2 only. Deflate, BZip2, Zstd, LZ4 and
  Brotli stages can also decode past a coder's declared size. The fix agent did not risk
  probing them, because AES padding and multi-stream handling in those wrappers were
  unclear.~~ **Closed by #518:** Deflate, Deflate64, BZip2, Zstd, LZ4 and Brotli are
  checked too (`dev-docs/formats/7z.md` §2.3). Still open: LZMA1 (and PPMd) is capped at
  its size, so surplus LZMA1 output is truncated rather than detected: without an end
  marker it cannot be told from valid data.
- **ZIP (Z1):** with bit 1 clear, decoder output past the declared size is not read or
  reported.
- **TAR (T7, T11):** old-GNU sparse extension blocks and the PAX sparse 1.0 map have no
  declared size to check before parsing, so they are weighed after parsing at an
  estimated 24 bytes per entry. Python retains about 60–100.
- **TAR (T6):** for `.tar.bz2` / `.tar.xz`, a failed last-block check surfaces either as
  `CorruptionError` from the member read or as `DIGEST_UNVERIFIABLE` from the scan.
  Which one depends on the codec's read-ahead, not on the archive. It is never silent
  (review K5).
- **RAR (R3):** the UTF-8 locale probe (`rar_unrar._probe_utf8_locale`, `ctypes`
  `newlocale`) is unverified on macOS/BSD. If it fails there, non-ASCII names are refused
  rather than misread.
- **RAR (R4), Windows:** the glob skip is sized on the presented text. That matches
  Windows `unrar`'s own reading only under a single-byte OEM code page, so a glob-named
  8-bit member under a DBCS OEM code page (such as cp932) can mis-size it.
- **Specs:** fixes edited the main `openspec/specs/*` files directly, not through change
  proposals (format-tar, format-zip, format-7z, format-rar, archive-reading,
  safe-extraction, cli, diagnostics).

## Open items and where each lives

1. **E1 / D1:** `dev-docs/threat-model.md` **O22**.
2. **R1, R2, R5 / D2:** `dev-docs/formats/rar.md` §7, "members `unrar` cannot address by
   name".
3. **R13 / D9:** `dev-docs/formats/rar.md` §7, "should a RAR dictionary size count
   against `DecoderLimits`?".
4. **T8 / D7:** closed by #519; the bound is described in `dev-docs/formats/unix-compress.md`
   §4.
5. **P1:** `dev-docs/IDEAS.md`, "Empty trailing bzip2 stream under the accelerator".
6. **S4 constants:** confirm 7-Zip's `k_Scan_NumCoders_MAX` /
   `k_Scan_NumCodersStreams_in_Folder_MAX` (64) against `CPP/7zip/Archive/7z/7zIn.cpp`.
   `sevenzip_parser.py` cites them from memory.

## Suspicions not reproduced (seeds for the next audit)

None of these became a test. Each was either not reproducible or too contrived to spend
on.

- **ZIP:** the overlapping-entry guard reads stdlib's private `ZipInfo._end_offset` with
  `getattr(..., None)` (`zip_reader.py`). On 3.11 patch releases from before the
  gh-109858 backport the attribute is absent, so the guard is silently skipped and the
  overlapping-file bomb is not refused. Not testable on the 3.11.15 in the dev image.
- **ZIP:** `_find_classic_eocd` always uses `rfind`. An end-of-central-directory record
  whose own disk fields spell `PK\x05\x06` makes the split check read the wrong fields.
- **ZIP:** PPMd restore-method values 2–15 are accepted, where 7-Zip rejects values
  above 2. They decoded as cut-off in a subprocess, with no crash. A flipped bit in a
  PPMd body is reported as `TruncatedError` rather than `CorruptionError`.
- **ZIP:** bytes after a DEFLATE or bzip2 stream's end but inside `compress_size` are
  ignored without any report.
- **ZIP:** listing 20k/40k/80k same-name entries took 0.6/1.8/5.6 s. Profiling found no
  quadratic code in archivey; it looks like GC.
- **7z:** PPMd order and memory size go to pyppmd unchecked (ZIP checks order 2–64).
  pyppmd clamps order, and invalid settings surface as a misleading `TruncatedError`.
- **7z:** the folder-wide decoder-memory sum counts only LZMA dictionaries and PPMd
  memory, not zstd windows.
- **7z:** a folder CRC on a multi-substream folder with no per-member CRCs is checked only
  by password confirmation, never on the data path. 7-Zip is believed to behave the same.
- **RAR:** an unknown RAR5 redirect type is treated as payload by `is_payload_file()`, but
  `unrar p` emits nothing for it, so a solid-pass demux could shift. This is the
  documented residual in `rar.md` §4 (P6).
- **RAR:** the RAR5 "unknown unpacked size" flag (0x0008) on a stored member is ignored by
  the parser. `rar -si` rewrites the size, so no fixture could be made.
- **RAR:** `unrar vb` lists `emoji_😀.txt` from `tests/fixtures/rar/encoding__rar4.rar` as
  `emoji_.txt`, yet archivey reads the member correctly with both tools, probably
  through the unnamed solid path. Unexplained.
- **TAR:** a random-access listing of a compressed tar decodes all member data, and no
  limit bounds that work. bzip2 compresses zeros about 400 000:1, so a few KB can cost
  about a TB of decode at `members()`. `dev-docs/formats/tar.md` documents it as a
  format cost.
- **ISO:** pycdlib walks the whole tree at open, and `ListingLimits` are not applied there
  the way 7z and RAR apply them at open. Memory is linear in image size, not amplified.
- **ISO:** Joliet names decode with `errors="replace"`, so distinct invalid UTF-16 names
  can collapse into one name full of U+FFFD.
- **Streams:** the rapidgzip C++ code prints "[Warning] Trailing garbage after EOF
  ignored!" straight to stderr.
