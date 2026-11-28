# Assessment: cleanup and trim plan from four direction reviews

Written by Claude for the maintainer on 2026-11-24, after reading the four reviews in this
directory. "You" in the text is the maintainer. Copied from the working document it was
written in; internal tracker numbers are replaced by a description. The decisions taken on
it are in [What was decided](#what-was-decided) at the end.

Sources: PRs 1821, 1822, 1823 and 1824 (report PRs, not for merge). Every number below
was re-measured on main at 281298c unless it says otherwise.

| PR   | Review                                     |
|------|--------------------------------------------|
| 1821 | [OpenAI Codex](openai-codex.md)            |
| 1822 | [Cursor](cursor.md)                        |
| 1823 | [Google Gemini](google-gemini.md)          |
| 1824 | [Anthropic Claude](anthropic-claude.md)    |

## Recommendation

Stop adding, and spend the next stretch on a trim pass in the order of the ranked list
below. The first three items change nothing a caller sees except speed and clarity, so
they can start now. Items 4 to 7 remove or merge public names, which is cheapest before
0.6.0 ships. Five decisions at the end are yours.

The four reports agree more than they disagree. All four say the same thing in different
words: the foundations (safety contract, pure-Python container parsing, problems as data,
honest damaged-input handling) are right, and the cost now is how much a caller and a
maintainer must hold in their heads. None of them asks for a new format.

## What all four reports say

| Theme | 1821 | 1822 | 1823 | 1824 | Checked |
|-------|------|------|------|------|---------|
| Public surface too big (97 root names, 11 open_archive keywords, 25 config fields, 49 diagnostic codes) | yes | yes | yes | yes | All counts confirmed |
| Extraction outcome is hard to act on (three error knobs, README needs abort_on, upload recipe leaves its temp dir on failure) | yes | yes | yes | yes | Confirmed: on_error, on_blocked, abort_on; recipe uses mkdtemp with no cleanup |
| Plugin API is only half proven, and not stable enough for an ecosystem (exact-version pin, no outside conformance kit) | yes | yes | yes | yes | Confirmed: only ar, cpio and rpm use public imports only (plus the built-in register call); 11 other plugin-shape readers import archivey.internal |
| Everyday ZIP is slow per member, and import is heavy | partly | yes | yes | yes | import archivey loads 210 modules, 0.27 s warm here; RESULTS.md shows ZIP list 7.3x and read_all 7.7x to 13x zipfile |
| Scope has spread (disk images, installers, retro formats) while writing is missing; pick the pitch | yes | yes | yes | yes | Disk images (DMG, APFS, HFS+, UDIF) are about 8,300 lines; ISO, UDF and CD about 5,900 |
| Nothing caps total complexity; process checks correctness, not size | no | yes | yes | yes | 26 workflows; 7 OpenSpec changes still unarchived, several already implemented |
| Bounded memory is not bounded time; say so on the first screen | no | yes | yes | yes | security.md says it, README does not |

## Where they disagree

- **The mode flags.** 1822 keeps streaming, pipe and seekable_members on the signature
  (ADR 0004) and moves only concurrent_operations and salvage away. 1823 and 1824 want one
  mode enum. 1821, as a clean-slate idea, wants two entry points (open_archive and
  scan_archive). pipe=True only merged on 11-23, so the enum ideas reopen a fresh
  decision. I side with 1822.
- **Defaults.** 1824 wants ZIP to allow seeking and two open streams by default because it
  is cheap there. 1822 defends today's rule. You ruled that these checks apply to every
  format so code tested on one archive does not fail on another (docs page 2, "why these
  aren't on by default"). 1824 is re-arguing that ruling; I would not reopen it.
- **Where formats live.** 1823 and 1824 want disk images, installers and retro formats in
  a separate first-party package. 1822 says keep the plugin API as "how we write
  built-ins" and hold the ecosystem claim. You chose built-in on 10-28, partly because
  registration is explicit only (your 10-25 ruling), so a separate package means an
  install plus a register call. Splitting adds release work and is not a trim.
- **Porting ZIP, 7z and TAR onto the plugin API.** 1824 wants it. 1822 says ZIP, 7z and
  RAR should stay internal. The 10-30 survey (draft PRs 1102 and 1145) found little
  generic code to move and listed seven missing API features. Not a cleanup.
- **Member objects.** 1821 and 1824 want immutable members before a writer exists. 1822
  wants one mutable type with lazy fields. For a trim, lazy fields on the existing type is
  the smaller change.
- **Writing.** 1823 and 1824 lean toward a minimal ZIP and TAR writer before 1.0; 1821 and
  1822 defer it. Under "stop building", defer it and change the pitch to "reader".

## Claims that are wrong or already handled

- **1823: "PyPy is explicitly not supported."** Wrong. docs/install.md says archivey works
  on PyPy 3.11 and every main change must pass there. The cost point (merge-queue stalls)
  stands; the premise does not.
- **1823: "move rapidgzip out of core."** It is already an optional extra ([seekable]) and
  out of [recommended]. What is ours is about 3,000 lines of glue: rapidgzip_child.py
  (1,355), rapidgzip_worker.py, rapidgzip_select.py, deflate_resume.py. That glue is the
  real trim question (item 9).
- **1824: "bring rar-synthetic-archives forward, it deletes the mask code and the flag."**
  Already landed: rar_synthetic.py exists and rar_allow_glob_member_concatenation now
  warns that it has no effect. What is left is deleting the flag, deleting any dead mask
  helpers, and archiving the OpenSpec change.
- **1824: "until plugin-passwords lands".** Landed in PR 1711 on 11-22.
- **1823: "replace NeedsPassword's two protocols with one call".** You ruled this design
  on 11-21 and it merged on 11-22. Reopening it is churn.
- **1823 and 1824: entry-point plugin discovery and CLI plugin loading.** Your 10-25
  ruling is explicit registration only. Not a gap. (Superseded on 11-24; see below.)
- **1823: "\"name\" in reader raises TypeError".** True, but on purpose: the message tells
  the caller to use reader.get(name). Cheap to change if you want zipfile-like behaviour.
- **1823: import 500 to 635 ms.** I measured 0.27 s warm and 210 modules. Same shape,
  smaller number.
- **1823 and 1824: trusted and untrusted presets.** Not wrong, and you already asked for
  one (IDEAS.md, "a stricter DecoderLimits preset", 2**24 KDF rounds).

## Ranked cleanup and trim plan

Ranked by impact on a first-day user and on maintenance, against cost and risk.

1. **Write the freeze down and park what is still growing.** No new formats, codecs, Rust
   kernels, config fields, flags or diagnostic codes unless the same PR removes one. Park
   the four planned Rust-kernel ports (tracked internally) and the encoding auto draft.
   Add counts to the API-surface check (root names, config fields, codes, open_archive
   keywords) so growth shows in the diff. Close the never-merge drafts that no longer
   teach anything (1102, 1145, 1318, 1395, 1399, 1416). Zero code risk.
2. **Lazy backend imports.** Replace the import-everything registration with a small
   static table (format, extensions, magic, entry point) and import a backend only when an
   archive matches it. Three reports ask for it, no API change, and every CLI call and
   test run benefits. Add an import-time and module-count gate.
3. **Archive or delete stale process files.** Archive the implemented OpenSpec changes
   (nested-archives, plugin-api, plugin-passwords, rar-synthetic-archives,
   rust-codecs-package, and whatever of dmg-reader and salvage-mode is done). Trim the
   189-line open_archive docstring and the 1,134-line plugin guide to contracts, with
   rationale moved to reference pages.
4. **One extraction error control, and a correct upload recipe.** Merge on_error,
   on_blocked and abort_on into one setting with a few named values. Rewrite the upload
   recipe to extract into a private staging directory and publish only on success, and run
   it as a test. All four reports land here, and it is the first thing a newcomer hits.
5. **Tier the root namespace.** Keep about 25 names at archivey (open_archive,
   open_stream, detect_format, the reader, member, format, report and config types, and
   the error tree). Everything else stays importable from its submodule. This is a
   re-export change, not a removal of features.
6. **Shrink ArchiveyConfig.** Remove rar_allow_glob_member_concatenation (no effect
   today). Merge use_rapidgzip and use_indexed_bzip2 (one package backs both). Move
   per-format knobs (zip_unflagged_fallback_encoding, rar_decompressor, unrar_path,
   unar_path) under one per-format group. Ship the UNTRUSTED preset you already asked for,
   so the upload recipe stops building five objects by hand.
7. **Audit the 49 diagnostic codes and the mode flags against DR-13.** Merge codes no
   caller would branch on differently. Move concurrent_operations off open_archive, or
   drop it if no real caller needs overlapping reads (1821, 1822 and 1824 all question it,
   and it drives much of reader_state.py). Keep the typed contexts; 1823's switch to a
   free-form dict is a redesign, not a trim.
8. **Lazy ArchiveMember fields.** VISION already names this as the listing fix. Fill
   identity at listing; compute costly fields on first read; keep one member type. This is
   the biggest everyday speed gap and also trims per-member wrapper objects.
9. **Decide on the accelerator glue.** rapidgzip brings about 3,000 lines of our own code,
   a child process, bit-level DEFLATE resume and its own stress workflows, for an extra
   outside [recommended]. Ask whether anyone uses it. If not, deprecate it. This makes a
   corner case slower, so it is your call by the standing rule.
10. **Tier the formats instead of moving them.** Mark ZIP, TAR, 7z, RAR, ISO, single-file
    and directories as the full-guarantee tier, and the rest (DMG stack, UDF and CD
    sectors, makeself, LHA, ARJ, base64 and uuencode as formats) as best effort. If you
    want real deletion, the DMG stack is the largest and newest candidate.
11. **Say what the library is on the first screen.** "The default way to read archives".
    Then three sentences next to "zero dependencies": it does not create archives;
    compressed RAR members need unrar or unar; memory is bounded, time is not. Drop the
    ecosystem sentence from VISION until the plugin API has a stability promise, and say at
    the top of the plugin guide that readers which import archivey.internal are internal.

## Not recommended now

A writer, a time limit (deadline=), async support, a pathlib-style ArchivePath, a public
test kit for plugins, separate format packages, porting ZIP, 7z or TAR onto the plugin
API, a second member type, cost-gated defaults, and an independent audit. Each is either
new building, a reopened ruling, or something to do after the trim when there are outside
users. The plugin test kit and the time limit are the two I would revisit first.

## Decisions for the maintainer

1. **Freeze and park list.** Accept item 1 as written, including parking the Rust-kernel
   ports? And what happens to the salvage work still open: land the coded PRs (1767, 1768,
   1774) and park the design-only steps (1758, 1760, 1765) with the PRs that depend on
   them (1769, 1770)?
2. **Pitch.** "Default reader" now, writing revisited after 1.0?
3. **Breaking trims before 0.6.0.** Items 4, 5, 6 and 7 change public names. Do them
   before 0.6.0, so one release carries all the breaks?
4. **rapidgzip.** Keep, or deprecate its glue (item 9)?
5. **Formats.** Tier only, or also deprecate the DMG stack or other best-effort formats
   (item 10)?

## What was decided

The maintainer answered on 2026-11-24:

- **Stop building and trim.** Agreed. Finish the PRs and features already started; do the
  cleanup at a deliberate pace.
- **Writing** is future work, after the cleanups, possibly after 1.0.
- **Trims:** yes, especially of anything being added now.
- **rapidgzip:** keep for now. The seeking reason is gone, but faster decoding is still
  useful.
- **Formats:** do not remove support; tier them. Instead of one package, split the
  best-effort formats into a few plugin packages (for example disk images and legacy
  formats), with the core keeping the main formats. That needs plugin-architecture work
  first, so that every format is written against the public plugin API.

Work that followed from it:

- A plugin-architecture proposal, approved on 11-24, which replaces the 10-25
  explicit-registration ruling: plugins load through entry points, split into three
  packages, with open string format names and a codec registry.
- The `archivey-codecs` public API was cut to what archivey calls or a planned feature
  needs (PR 1825).
- Concurrent operations were cut down (plan PR 1830, then PRs 1833, 1834 and 1837).
