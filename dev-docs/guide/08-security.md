# 8. Security

**In one minute.** Every byte of an archive is attacker-controlled: names, link targets,
declared sizes, indexes, key-derivation costs and the compressed data itself. Archivey
defends in layers. **Parse in Python**, so a hostile header can produce wrong data but not
memory corruption. **Run crash-prone native decoders in a child process**, so a crash is an
exception. **Bound every cost with a public limit checked before the cost is paid**, so no
upload can eat all memory or disk. **Check every path before writing**, under every policy,
and recheck symlinks after creating them and when a later member changes the tree, so
nothing lands outside the destination. **Escape archive text** before it reaches a terminal.
And write down what is *not* defended. The authoritative document is the
[threat model](../threat-model.md); the user's version is
[`docs/security.md`](../../docs/security.md). This page is a map of where each layer
lives in the code.

## Who the attacker is

From the [threat model §1](../threat-model.md#1-scope-and-attackers):

- **Whoever wrote the archive.** Every field, every stream. Files that are not archives
  at all are in scope too, because detection runs on anything.
- **A process changing a directory source while archivey reads it** (an upload folder
  someone else can write to).

Trusted: the caller's own process and configuration (a caller who sets a limit to
`UNLIMITED` gets what they asked for); the extraction destination as it was before the
run (but *not* what earlier members of the same archive wrote there); and the optional
libraries and external programs, which are trusted not to be malicious but **not** trusted
to be robust on hostile input.

The test the maintainer applies to resource questions, [DR-9a](../design-rules.md#dr-9a-the-upload-server-test):
imagine a server where anyone can upload an archive to be listed, tested or hashed. Could
one upload bring it down, with unbounded memory or disk, an unbounded hang, or a crash?

## Layer 1: parsers are pure Python

ZIP, TAR, 7z and RAR headers are parsed by archivey's own Python code, and the
`archivey.formats` readers are Python too. A crafted header can make a parser compute a
wrong value or raise, but it cannot overwrite memory. Native code is for codecs only
([DR-20](../design-rules.md#dr-20-parse-in-python-isolate-native-code-that-can-crash)).
This is one reason archivey replaced `zipfile`, `tarfile`, `py7zr` and `rarfile` with its
own parsers ([page 10](10-decisions.md#native-parsers-for-every-format)).

Parsing in Python still needs care in three places:

- **Allocations sized by a header field.** A 7z header that says "ten billion entries"
  must not allocate a ten-billion-entry list. Reads sized by a header go through a
  bounded source (`ArchiveSource` never reads more than the source can supply), and
  counts are checked against `ListingLimits` while they are parsed.
- **Recursion and nesting.** Deep directory trees, chains of links and nested archives are
  meant to be walked with loops or explicit depth checks, not unbounded recursion. The
  standard library does not always do the same: a review on 2026-11-08 found that a tree
  of about 1,000 levels raises `RecursionError` inside `os.makedirs` and the dry run's
  cleanup (fix in review: PR 1355).
- **Quadratic shapes.** A loop that is fine for a thousand members can be a bomb at a
  quarter of a million (the default `max_members`). The 2026-11-09 reviews found one in
  the RPM reader, where every file of a hard-link set kept its own copy of the set, so
  4,000 files sharing one inode take 129 MiB to list (fix in review: PR 1392).

## Layer 2: native decoders in a child process

Some native decoders crash the process on bad input: pyppmd segfaults after the model ends
on hostile data; rapidgzip aborts on a truncated stream. Nothing at the Python level can
prevent that in every case, so those decoders run in a child process
([page 6](06-streams-and-codecs.md#child-processes),
[process isolation](../topics/process-isolation.md)). A crash becomes `CorruptionError`.
The rule is "observed crashes", not "native code", with one precaution: libbzip3, a young
library with memory-safety fixes in its recent releases, is isolated too. The standard
library's decoders are native and stay in-process unless the caller asks for
`NATIVE_DECODERS`.

The child is a crash boundary, not a sandbox. It has the caller's user and filesystem,
and no timeout.

## Layer 3: every cost has a public limit

[DR-9](../design-rules.md#dr-9-every-cost-is-bounded-by-a-public-raisable-limit): every
resource bound is a public field the caller can raise, checked *before* the cost is
paid. The limits live in `config.py`, grouped by when they apply:

| Limit group | Guards | Where it is enforced |
| --- | --- | --- |
| `ListingLimits` (`max_members` 262,144; `max_metadata_bytes` 64 MiB) | A hostile index or a header walk that never ends | `_register_member` in `base_reader.py`, `internal/listing_limits.py`, and the parsers while they read counts |
| `DecoderLimits.max_decoder_memory` (2 GiB) | A codec told to allocate a huge window (LZMA dictionary, zstd window, RAR dictionary, PPMd model) | Checked from the stream's header before the decoder is built; detection probes are held to it too |
| `DecoderLimits.max_key_derivation_rounds` (2^25) | An encrypted archive that chooses how much work each password attempt costs | The 7z and RAR key derivation |
| `DecoderLimits.max_ratio` (800:1) and its thresholds | A small member that decodes to an enormous one | `MemberRatioGuard`, `DecodeRatioGuard` in `bomb_tracker.py`, on every decode, not only extraction |
| `ExtractionLimits` (`max_extracted_bytes` 2 GiB, `max_entries`) | Filling the disk | `BombTracker` in `bomb_tracker.py`, as bytes are written |
| `SpoolLimits.max_bytes` (1 GiB) | A temp-file copy for `unrar` | `SpoolBudget` in `internal/spool.py` |
| `DetectionBudget` | Detection reading too much of a file that is not an archive | `internal/detection.py` |

A few choices behind these numbers:

- **The ratio default is 800, not 1000**, so that gzip of zeros (about 1,030:1) is refused
  every time rather than by chance (maintainer, 2026-10-30). The ratio holds on every
  read, not only on extraction, and its fields moved to `DecoderLimits` then (PR 1143).
- **A member is refused from its recorded size before it is decoded**, when the archive
  itself says it will expand past the ratio (PR 784). An archive-wide check from recorded
  sizes was rejected: a forged size would stop the run and lose the intact members after
  it ([DR-2](../design-rules.md#dr-2-deliver-everything-recoverable-then-raise)).
- **A pipe has no size**, so the archive-wide ratio there waits for 256 MiB of output
  ([page 7](07-pipes-and-files.md#limits-that-behave-differently-on-a-pipe)).

What is *not* bounded, on purpose: CPU and wall-clock time. A decoder that loops loops
for ever, as it would in other libraries; the caller bounds time, for example by running
archivey in a process they can stop ([threat model §4](../threat-model.md#4-accepted-non-guarantees)).

## Layer 4: extraction stays in the destination

`extract_all(dest)` is the most dangerous call: it turns attacker-chosen names into
filesystem operations. There is no single-member `extract()`
(ADR [0019](../decisions/0019-no-top-level-extract.md)): an older version had one that
skipped the checks `extractall()` ran, and that was a real vulnerability report
([page 11](11-bugs-and-lessons.md#a-single-member-extract-skipped-the-checks)).

What runs for each member, in order (`internal/extraction.py`, `internal/filters.py`):

1. **The policy transform** on a copy of the member (`POLICY_TRANSFORMS` in `filters.py`):
   `STRICT` drops ownership and strips setuid, setgid, sticky and group or other write
   bits; `STANDARD`, the default, strips setuid, setgid and sticky and keeps the rest;
   `TRUSTED` applies the stored metadata as it is. Under
   `STANDARD` and `TRUSTED`, an absolute name is re-rooted inside the destination
   (`reroot_absolute`), as tar, unzip and 7-Zip do (PR 524).
2. **The caller's filter**, if any. It can rename or skip a member.
3. **`check_universal`**, which runs under **every** policy, `TRUSTED` included, on the
   *final* name, so a filter cannot rename a member into an unsafe one. It refuses `..`
   components, absolute and drive-relative names, NUL bytes, device files, a member that
   would replace the destination root, and a parent path that resolves outside the
   destination. It resolves paths with its own walk, one link at a time, because
   `os.path.realpath` gives up on long link chains and keeps going lexically (the bug
   behind CVE-2025-4517 in `tarfile`).
4. **The write**, atomic for files: data goes to a temporary name and is renamed into place,
   so a failure never leaves half a file under the real name (`_write_file_atomic`).
   Extraction never changes or removes what it did not create
   ([DR-18](../design-rules.md#dr-18-extraction-never-damages-what-it-did-not-create)):
   collisions with existing files follow the caller's `OverwritePolicy`.
5. **After a symlink is created**, it is resolved again through the real filesystem and
   removed if it escapes (`_write_symlink`). An earlier member's symlink on the path
   (`sub -> /tmp/evil`, then `sub/link -> x`) is caught here.
6. **When a later member changes a path that an earlier link resolved through**, the link
   is checked again (`internal/link_watch.py`). `l -> a/../secret` resolves inside while
   `a` does not exist; once a later member creates `a -> .`, it resolves outside
   (threat-model O22, PR 516). `LinkWatch` records every path each link's resolution
   looked at, and rechecks the links that depend on a changed one.
7. **Hard links** must name an earlier member that was not refused, and they are created
   from the file this run wrote, never from a path outside.

Names also have to be safe on the *target* filesystem: Windows reserved names (`CON`,
`NUL`), characters Windows forbids, case-insensitive collisions, Unicode normalization
collisions on macOS, names past `MAX_PATH` (`internal/long_paths.py`), and bidi
override characters that make a name display differently from what it is
(ADR [0013](../decisions/0013-cross-platform-name-safety-policies.md),
[0017](../decisions/0017-bidi-override-rejection-is-policy-keyed.md)). These rules are keyed
on the policy: `STRICT` makes names portable to every system, `STANDARD` is portable but
not paranoid, and `TRUSTED` leaves names to the local system. The aim is the same outcome
on every operating system, or the same refusal
([DR-5](../design-rules.md#dr-5-same-input-same-outcome)).

### The dry run

`extract_all(dest, dry_run=True)` really extracts, into a private scratch copy of the
destination, and reports every path as if it were under `dest` (`internal/dry_run.py`). It
was built for scanning backups without writing anything; extracting for real into scratch
was the only way to make a dry run agree with a real run on collisions, links and limits.

## Layer 5: external programs get a fixed command line

`unrar` and `unar` run with a fixed argument list (`rar_unrar.py`, `external/unar.py`).
The password goes on stdin, not the command line (except for `unar`, which has no other
way: an accepted risk). A member name reaches `unrar` only inside an include-mask switch
`-n./name`, and, since synthetic archives, usually not at all: members are named `m0`,
`m1`, … in the synthetic file. Names containing `*` used to trigger catastrophic
backtracking in `unrar`'s own mask matcher. PR 371 first narrowed `*` to `?`; today a name
holding `*` or `?` never reaches `unrar` as a mask at all, and that member is read through
a synthetic archive ([page 11](11-bugs-and-lessons.md#unrars-own-mask-matcher-backtracked)). A `unar`
build that drops RAR5 members silently is detected and refused.

## Layer 6: archive text reaching a terminal is inert

A member name can contain ANSI escape sequences that move the cursor, rewrite the screen
or change a terminal's title. Every `ArchiveyError`, `ArchiveyUsageError` and
`Diagnostic` escapes its message when it is built (`escape_control_chars` in
`terminal.py`), not in a log formatter, because the likeliest way to a terminal is an
uncaught exception's traceback, which no formatter sees. Message sites put names in
`quoted()`, so text is escaped exactly once. `archivey.terminal` is public, so front ends
can print names the same way, and the CLI does.

## Layer 7: honest errors

Every archive problem becomes a typed `ArchiveyError`; an I/O problem passes through as
`OSError`; a programming mistake is `ArchiveyUsageError`. A wrong answer is the worst
failure ([DR-1](../design-rules.md#dr-1-a-wrong-answer-is-the-worst-failure)): a reported
absence is better than a refusal, a refusal is better than silent loss, and a wrong value
is the worst of all. [Page 9](09-errors-and-diagnostics.md) has the details.

## Where the guarantees stop

The [threat model §4](../threat-model.md#4-accepted-non-guarantees) lists every accepted
non-guarantee with its reason. The ones to know:

- **No CPU or wall-clock bound.** Use a process you can stop.
- **A seek trusts the format's own index** (O17): a crafted index can make a cold seek
  return wrong bytes. A full read never trusts it.
- **Nested archives multiply limits.** The limits measure one archive, so a zip of zips
  can pass them one level at a time. Recursing into members is the caller's choice, and
  the caller bounds the depth and the total.
- **Reads have no byte cap** beyond the ratio: `max_extracted_bytes` is for extraction,
  and `read()` of an honest 1 GiB member holds 1 GiB.
- **Volume discovery trusts the folder.** `x.7z.002` beside `x.7z.001` is taken as part
  of the set. A part that is a symlink is refused, but a part swapped after the check is
  not caught.
- **A probe can be wrong**: a file that happens to decode as zlib can be listed as one
  fabricated member, which a full read then refuses. That is why probes run only when the
  extension names the format, and the result carries `PROBE_FORMAT_UNCONFIRMED`.
- **Plugin code is trusted.**

## How security work is organized

- The [threat model](../threat-model.md) is a model, not a bug list: defended properties
  with their mechanisms and tests, accepted non-guarantees with reasons, open design gaps.
  Accepting a new residual risk is the maintainer's call.
- Hostile fixtures are built in code, and property tests (Hypothesis) generate names and
  link shapes (`tests/risky_text.py`).
- Atheris fuzzes every parser and decoder briefly in the merge queue and for longer
  nightly ([fuzzing](../fuzzing.md)); pull request pushes do not fuzz. Every test archive is also cut, bit-flipped, zeroed and padded,
  and must either read or raise an `ArchiveyError`.
- Whole-codebase audits run from time to time, each with one goal; their reports and
  reproducers are kept outside the repo, and their fixes land as normal PRs.
- Vulnerability reports go through [`SECURITY.md`](../../SECURITY.md) and
  [maintenance](../maintenance.md).
