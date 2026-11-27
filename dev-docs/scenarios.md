# Usage scenarios

Who we imagine using archivey, what code they write, and what would hurt them. The design
rules ([`design-rules.md`](design-rules.md)) get tested against these. When a question
asks "would this surprise a caller?" or "is this easy to use?", pick the scenarios it
touches and walk through them.

Scenario 1 is the founding use case (VISION). Scenario 2 is the maintainer's
upload-server test, and scenario 9 is his too. Claude proposed scenarios 3 to 8; the
maintainer accepted them all on 2026-10-09.

Each scenario lists:
- **Caller:** who it is.
- **Code:** what the code looks like.
- **Needs:** what it relies on.
- **Hurts:** what would hurt it.

## 1. Backup indexer (the founding use case)

**Caller:** a person or a script walking decades of old backups to index and deduplicate
them.
**Code:** `detect_format` on every file, then `open_archive(p, streaming=True)`, then
`stream_members()` to hash every member. Runs unattended for hours.
**Needs:**
- Detection by content, since extensions are wrong.
- One pass over solid archives.
- Stored hashes used without decoding.
- Damaged files yield what they can, then a typed error, and the scan moves on.
- `CorruptionError` and `UnsupportedFeatureError` are told apart.
**Hurts:**
- A crash or a hang on one file, which stops the whole run.
- Quadratic re-decompression.
- A truncated member reported as fine.
- An error type that can't separate "damaged" from "needs a newer tool".

## 2. Upload scanning service

**Caller:** a web service that accepts archives from anyone and tests them, lists them
or hashes their members, with default limits.
**Code:** `open_archive` on an upload, then iterate, read and hash. No extraction.
**Needs:**
- Bounded memory, disk, CPU and key-derivation work for any input.
- Errors, never crashes.
- External programs that can be turned off (`RarOptions(decompressor=RarDecompressor.NONE)`).
**Hurts:** any archive that exhausts memory, kills the process, or runs without bound.
This is the maintainer's test (design rules, principle 2).

## 3. Agent-written one-off script

**Caller:** a coding agent asked to "unpack this and summarise what's inside", writing
code from the README and docstrings in one try.
**Code:** `open_archive(path)`, then `extract_all(dest)` or a loop reading text members.
**Needs:**
- The obvious call is the right one.
- Errors say what to change: a misuse names the option to set.
- Names are guessable.
- Results are the same whatever the format, so code tested on a ZIP works on a 7z.
**Hurts:**
- A second near-identical API.
- An option the agent must know about before the first call works.
- A silent difference between formats.
- A diagnostic it never reads that hides missing data.

## 4. Safe extraction of untrusted archives

**Caller:** a server or desktop tool that extracts user archives into a folder, such as
mail attachments or a plugin installer.
**Code:** `open_archive(p).extract_all(dest)` with the default policy, maybe a filter.
**Needs:**
- Nothing written outside `dest`, with any link shape, on any OS.
- Limits on total size, ratio and entry count.
- A report of what was refused and why.
**Hurts:**
- An escape.
- A bomb.
- An extraction that differs between Linux and Windows.
- Refusing an ordinary archive, which pushes the caller to TRUSTED.

## 5. Data pipeline over archived datasets

**Caller:** a training or ETL job reading many members from large tar or zip shards,
often from a pipe or object storage.
**Code:** `open_archive(stream, pipe=True)` for a pipe, `streaming=True` for a file or
object storage, then `stream_members()`. Sometimes
random access with `seekable_members=True` and concurrent readers.
**Needs:**
- Throughput close to the standard library.
- Honest cost signals.
- Accelerators that only change speed.
- Clear rules on which streams seek.
**Hurts:**
- Hidden whole-file buffering.
- A random read that silently re-decodes the solid block.
- A result that depends on whether an accelerator is installed.

## 6. Forensics and triage

**Caller:** an analyst inspecting suspicious or damaged files without trusting them.
**Code:** `members_report()`, `detect_format` with its evidence, raw names, stored
hashes and diagnostics. Rarely extracts.
**Needs:**
- Exact metadata.
- `raw_name` alongside the decoded name.
- Trailing data and hidden bytes reported.
- Damaged structure listed as far as it goes.
**Hurts:**
- A guessed value presented as fact.
- A silently normalised name.
- Data after the archive end that goes unreported.

## 7. Command-line inspection

**Caller:** a person at a terminal, and the maintainer's own tool.
**Code:** `archivey list`, `archivey extract --dry-run`, `archivey test`.
**Needs:**
- Terminal-safe output for hostile names.
- Exit codes that separate "damaged" from "unsupported".
- The same behaviour as the library, since the CLI uses public API (apart from one
  allowlisted import).
**Hurts:**
- A name that rewrites the terminal.
- A CLI-only behaviour the library can't reproduce.

## 8. Tool or library built on archivey

**Caller:** another package that handles many archive formats through archivey, such as
a packaging tool, a backup program or a file manager.
**Code:** the public API only, across versions.
**Needs:**
- A stable, small public surface.
- Exceptions that are only added, never removed.
- Documented diagnostics codes.
**Hurts:**
- Removed or renamed names after a release.
- Behaviour that changes with no CHANGELOG line.

## 9. Loading from a remote file object

**Caller:** a model server loading artifacts straight from a URL or a storage bucket. It
passes archivey a file object that reads from the remote on demand, such as an HTTP
range-request file or an S3 client's file. Archivey does not need to accept a URL itself
(maintainer, 2026-10-09).
**Code:** `open_archive(remote_file)`, then read one or a few members. Sometimes it reads
the whole archive once.
**Needs:**
- Few seeks and few jumps around the file.
- Sequential reads wherever the format allows.
- Small reads near each other merged into one.
- Listing that touches only the index where the format has one.
**Hurts:**
- A tail read larger than needed. A September 2026 study found two extra requests per
  ZIP open.
- One request per TAR member just to list.
- Re-reading a solid block once per member.
- Spooling a whole RAR to disk before extracting one member.
The study's measurements are in the project's HTTP range-reading report (2026-09-29).

## Planned after 0.2.0

- **Salvage and recovery.** Resync past damage, for example by walking ZIP local headers
  or resyncing a TAR stream, to recover members after a defect that today ends the
  listing. Scenario 1 and 6 callers need this most.
- **Converting between formats.** In scope once writing exists: read one format, write
  another, keeping the metadata both formats can hold.

## Not designed for (yet)

- Writing or modifying archives. Writing comes after reading is complete (VISION).
- Async callers, which wrap archivey with `asyncio.to_thread` (ADR 0005).
- Accepting a URL directly. Callers pass a file object instead (scenario 9).
