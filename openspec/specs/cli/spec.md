# Command-Line Interface

## Purpose

Shell interface for inspecting, verifying, and extracting archives with glob member
filters and optional I/O instrumentation; CLI-only deps stay out of core.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Listing, member filtering, digest verification reads |
| `safe-extraction` | Default safe extraction policy used by `extract` |
| `packaging-and-extras` | `[recommended]` extra supplies `tqdm`; core remains importable without it |
| `access-mode-and-cost` | Optional I/O instrumentation/cost reporting |

## Requirements

### Requirement: archivey command with list, test, and extract subcommands

The system SHALL provide an `archivey` command whose verbs are **subcommands**:
each verb is a bare word (never dash-prefixed), and a verb that has an alias
uses a single-letter bare word for it. When no verb is present the verb SHALL default to `list`. Verb dispatch
SHALL be **known-verb-wins**: if the first positional token is a registered verb
or alias (including reserved verbs `hash` / `create` / `convert`), the
system SHALL dispatch that verb; otherwise it SHALL treat the token as an
archive path and run `list`. Every token after a `--` separator is a
positional, so a verb-shaped word there is an archive path: with no verb before
the separator, the system SHALL insert `list` ahead of the `--` (`archivey --
-weird.zip` lists `-weird.zip`; `archivey -- list` opens a file named `list`).
The verb test SHALL be an exact match on the whole token: a bare
verb word is a verb, and any path-qualified token (`./x`, `dir/x`, `/abs/x`)
is an archive path and is listed. A file whose name equals a verb word SHALL be
reachable by naming the verb explicitly (e.g. `archivey list x`) or by
qualifying its path (`archivey ./x`). New verbs MAY
be added later and take precedence over same-named files; the `list <path>`
escape hatch is permanent. Verbs MUST NOT be selectable via a
dash-prefixed option form (e.g. `-x` SHALL NOT mean `extract`); options always
take a dash, verbs never do. Progress output SHALL use
`tqdm` from `[recommended]` when available; core MUST NOT depend on `tqdm`. The console
script and `python -m archivey` MUST be importable/runnable without installing
`[recommended]` (progress suppressed if `tqdm` is absent).

Supported verbs in this capability:

| Verb | Alias | Role |
| --- | --- | --- |
| `list` | `l` | Inspect members (default verb) |
| `test` | `t` | Full-read integrity check |
| `extract` | `x` | Safe extraction |
| `info` | `i`, `detect` | Format detection + archive identity |

`list`, `test`, and `extract` SHALL support glob member filters. Positional
patterns after the archive path SHALL act as **include** filters (a member is
selected when it matches any positional, or when no positional is given).
A pattern SHALL match as `archivey.paths.match_glob(pattern, with_contents=True)`
does: `*` stays inside one folder, `**` matches any depth, and a pattern that matches
a folder also selects every member under it, so `docs` and `docs/` select the
directory `docs/` and its contents, as `tar` does, but `*.md` selects only top-level
`.md` files. On Windows a `\` in a pattern SHALL be read as `/` first; elsewhere it
SHALL stay a literal character. A pattern `match_glob` refuses SHALL be a usage error
(exit `2`). Includes, `--exclude` and the unmatched-pattern warning SHALL all use this
matching. The library's own `members=` still matches names exactly.
`--exclude PATTERN` (repeatable, long-form only — no short flag) SHALL remove
matching members; a member SHALL be processed when it matches an include (or none
is given) AND matches no `--exclude`. The system SHALL NOT provide a redundant
`--include` flag. When one or more include patterns are given, each pattern that
matches no member SHALL produce a stderr warning
(`warning: pattern matched no members: '…'`). When the includes match members but
`--exclude` removes every one of them, or when there is no include and `--exclude`
removes every member, the system SHALL warn
`warning: no members selected: --exclude removed every member…` instead. When the
patterns select no member in either way on `extract` or `test`, the command SHALL
exit `1` after the warning(s) and SHALL write nothing, not even the destination
directory; an archive with no members and only `--exclude` patterns is not such a
case. On `list`, the same warnings SHALL be emitted but the exit code SHALL remain
`0` when the archive otherwise listed successfully. On `extract` and `test`, the
patterns SHALL be checked against a member index when the archive has a complete
one without a scan, before anything is read or written. Otherwise they SHALL be
checked in the same pass that tests or extracts the members, with the warnings
after that pass, and SHALL NOT cost a separate pass: on a compressed TAR such a
pass decompresses the whole archive. An index that ends in damage holds only the
members before the damage, so it is not complete; and a pass that ends early SHALL
NOT report its patterns, while a pass that reaches its end SHALL, whatever members
failed in it. A pass that ends early SHALL exit `1` and SHALL NOT claim that the
patterns matched nothing. The "write nothing" rule above does not apply to it: an
`extract` that aborts this way MAY leave the destination directory it created, as
an aborted `extract` with no patterns does. On `list`, the patterns SHALL be
checked against the member listing the command reads anyway, with the warnings
before the member lines. A listing that ends in damage SHALL produce no pattern
warning on `list`, because the members after the damage are unknown; `list` SHALL
print the listing error and exit `1` instead. On `extract`, when there is exactly
one unmatched include that names an existing directory or ends with `/`, the
warning SHALL include a hint `(did you mean -d PATTERN?)`. Each invocation SHALL
accept exactly **one** archive positional (multi-archive is out of scope for this
capability). `--password` SHALL be accepted for encrypted archives; when an
encrypted archive is opened, no `--password` was supplied, and stdin is a TTY, the
system SHALL prompt for the password without echoing it.

Command data output (member listings, info summaries) SHALL be written to
**stdout**; progress bars, human summaries, prompts, and diagnostics SHALL be
written to **stderr**. The line that reports the fault which ended the run,
including the uncounted error that ends `test`'s read pass after a member already
failed, SHALL start with `archivey: `. A counted failure (`test`'s `FAIL …` lines),
a line about one member (`extract`'s per-member warnings), the notices and counts
that follow the fault line (stop notices, `N member(s) extracted before the stop`,
`files left in <dir>/`) and `interrupted` keep their own shape.

`--probe-content` SHALL open the archive with
`ArchiveyConfig(always_probe_content=True)` in every verb, so a raw LZMA Alone, zlib or
Brotli stream is recognised by its content whatever the file is named. Without it the
CLI detects as the library does by default; when detection then fails with a message
naming `always_probe_content`, the CLI SHALL add a line naming `--probe-content`.

`--track-io` SHALL report I/O accounting for the operation using the internal
measurement hook (decode/seek counters), without patching `builtins.open`. It is
a maintainer/debug affordance and MUST NOT add a public library performance API.

`list` SHALL obtain its member set via `ArchiveReader.members_report()` (or an
equivalent report path). It SHALL print a human layer-1 member view by default
(type, size, mtime, mode, encrypted flag, name; link target for links) for every
recovered member in the report. The default view MUST NOT show digests unless
`--digests` is set (stored `member.hashes` only; no body read). `--long` SHALL
instead print a header line and one line per member that adds packed size, space
saved, the compression method chain and the stored CRC-32, each column as wide as
its widest cell; `--digests` and `-v` add the same suffixes as in the default
view. `--details` SHALL instead print one `key: value` block per member,
blank-line separated, naming every field the member carries (`raw_name` when it
is not the UTF-8 spelling of the name, times, owner, host OS, Windows attributes,
every stored digest, comment, each `extra` key, attached diagnostics) and leaving
out fields the format does not record; `bytes` values print as `hex:<digits>`, as
in `info`. Neither reads a member body; the two flags are mutually exclusive.
When the report’s `error` is set, `list` SHALL still print the recovered members,
SHALL emit a short stderr message naming the terminal archive error, and SHALL
exit nonzero (`1`). `-v` / `--verbose` SHALL surface diagnostics when present.

`test` SHALL fully read selected file members and verify stored digests through
the shared verification stage (including CRC32 and Blake2sp where supported). A
directory member that declares data (`MEMBER_DIRECTORY_DATA_IGNORED`) and for which
`stream_members()` yields a stream SHALL be read and counted like a file member, so
damage in its hidden bytes fails the test, except that when archivey cannot decode
such a directory's data (`UnsupportedFeatureError` or `PackageNotInstalledError`),
`test` SHALL print `skip <name>: <reason>` by default and count it as not tested. A
file member archivey cannot decode, and a directory whose data needs a password, still
fail. `cat` SHALL skip such a directory.
Members with no stored digest SHALL count as OK when fully readable without
error. `test` MUST NOT require emitting computed content hashes. By default
`test` SHALL be quiet — printing only failures, the `skip` lines above, the stop
notice when the read pass ends early, and a one-line summary (`N OK, M failed`) to stderr — and SHALL
exit non-zero if any member fails;
`-v` / `--verbose` SHALL add a per-member OK/FAIL line. When a cheap member
index is available and the stream ends before every selected file member has
been counted OK or failed (an archive-wide error, such as damage to the archive's
structure: a TAR cut inside a member, a compressed TAR whose stream fails; a member's
data error, solid archives included, fails that member and does not end the stream), the
summary SHALL append `, K not tested` where `K` is the untested remainder. A
directory skipped as above counts in `K` whether or not an index was available and
whether or not the pass reached its end.
When the stream ends on an error right after a member read failed, that member's
failure SHALL be counted once: `test` SHALL print
`test stopped; remaining members were not tested`, SHALL print the stream's error
(prefixed `archivey: `) only when it differs from the member's, and SHALL NOT count
it as a second failure.
When the run emits `DIGEST_UNVERIFIABLE` or `ENCRYPTED_MEMBER_UNVERIFIED` (a member
or archive-level digest that went unchecked), the summary SHALL append
`, V not verified` where `V` counts those diagnostics. `test` SHALL exit `1` when
the summary reports anything as not tested or not verified, even if no member failed.

`extract` SHALL use safe-extraction defaults and SHALL expose `--policy
{strict,standard,trusted}` mapping to `ExtractionPolicy` (CLI default `strict`).
Destination SHALL be selected with `-d` / `--dest`; remaining positionals after the
archive path SHALL be member filters only (no bare positional destination). When `-d` is
given, extraction SHALL write into that directory verbatim (`-d .` reproduces classic
splatter-into-cwd behavior). When `-d` is omitted, the destination SHALL default to a
smart enclosing directory to avoid tarbombs. When a cheap member index is available
without a streaming scan (ZIP / 7z / RAR central directory, etc.), tops SHALL be
computed on the **filtered** member set: extract into `./<archive-stem>/` when that set
has multiple top-level entries; extract into `.` when it already has a single top-level
directory (no redundant nesting) or the archive is a single-file/single-stream archive.
When the index gives a single top-level entry whose name already exists in the cwd, or
may be written under another spelling that does (a trailing dot or space stripped, a
character Windows refuses or a non-printable character escaped), the system SHALL
instead extract into `./<archive-stem>/` and hoist, as below, so the hoist's rules
decide what happens to the operator's entry and `--overwrite` never replaces it. A
single-file/single-stream archive keeps writing into the cwd under `--overwrite`: its
one output name comes from the archive name the operator typed, and there is no wrapper
to hoist out of. When no cheap index is available (plain TAR, an archive read from a
pipe, …), the destination SHALL initially be `./<archive-stem>/` (always wrap — no
pre-extract metadata pass); after a successful extract, if that wrapper contains exactly
one top-level entry, the system SHALL hoist it to the cwd and remove the wrapper.
Whether the hoist runs SHALL depend only on what the run extracted, never on what was at
the wrapper's name before; what the hoist does (flatten in place, or merge under the
overwrite policy) can still depend on it, as described below. The hoist SHALL NOT run
when the only entry is a symlink (the move changes the directory its target is read
from), or when a symlink in the entry leaves the entry on the way to its target or part
of the entry could not be listed (it may hold such a link). Extraction checked those
links against the wrapper, and a path that climbs above the hoisted entry and back down
through the wrapper's name (`top/k -> ../../.ssh/authorized_keys`, from `.ssh.tar`)
climbs out of the cwd after the move. The check SHALL follow the path one component at a
time, through every symlink on the way, so a chain cannot hide a climb; an absolute
target always blocks. A path that stays inside the entry (`pkg/bin/a -> ../lib/a.so`)
means the same thing after the move, and does not block it. In each of these cases a
line says the content was kept in the wrapper and why. When it runs, directories merge
into existing directories, and under `rename` the hoist SHALL produce the same final
layout as extracting directly into the cwd. To move a root whose name differs from the
wrapper's, the hoist first renames the wrapper to an aside name `<wrapper> (N)/`, and
that aside directory SHALL NOT be the entry at the root's destination: with nothing at
`./foo`, `foo.tar` holding `foo (1)/` (or `FOO (1)/` on a case-insensitive filesystem)
lands at `./foo (1)/` (`./FOO (1)/` for that spelling), as a direct extraction puts it,
and not in the wrapper. The hoist is a convenience, not a guarantee: with no `-d`, the
operator accepts wherever the content lands, and the hoist SHALL NOT replace or delete
anything in the cwd under any `--overwrite` value. Before it moves anything, the hoist
SHALL check the whole merge for a collision the policy does not resolve. The wrapper
itself is not the operator's data: where the root's destination is the wrapper (`FILE`
in `file/` on a case-insensitive filesystem), the check SHALL NOT count it, since the
wrapper moves aside before the merge. Only `rename` resolves a collision, writing the
archive's entry under the library's `name (N)` spelling; `error`, `skip` and `replace`
resolve none, so any collision under them keeps the content in the wrapper. When the
check finds a collision the policy does not resolve, the hoist SHALL move nothing, print
a line naming the first such path, `kept in <wrapper>/: <path> already exists`, and
leave the whole root in the wrapper; the run counts as successful (exit `0`) and the
closing summary names the wrapper. So `replace` and `skip` are not reproduced as a
direct extraction applies them: the hoist neither replaces the operator's file nor
throws away the archive's copy. atool's `aunpack` keeps the content in its
`Unpack-NNNN/` directory the same way. A collision that appears after that check (the
cwd changed during the move) SHALL stop the hoist, leave the unmoved remainder under the
wrapper (or under the wrapper's aside name `<wrapper> (N)/` when the wrapper's name
could not be taken back), and exit nonzero; a filesystem error during the move does the
same. When the container got the plain stem name, a sole root sharing the wrapper's own
name, spelled the same (`src.tar.gz` containing `src/`), SHALL be flattened in place,
not treated as a collision, and the wrapper SHALL then take that root's mode and times.
A root whose name differs from the wrapper's only in case (`plain.tar` containing
`PLAIN/`) SHALL be moved like any other root, so it keeps its own spelling (`./PLAIN/`)
on every platform. When `./<archive-stem>` already existed, the container is
`./<archive-stem> (N)/`, the sole root no longer shares its name, and the hoist merges
the root into the existing `./<archive-stem>/` under the overwrite policy like any other
root. A directory stored without owner write permission (`0o555`) SHALL still be moved:
the hoist gives it owner read, write and search permission for the move and then puts
its mode back, as a direct extraction into the cwd would have succeeded. After a hoist,
the per-member lines (`renamed:`, `name rewritten:`, `not overwritten:`, `kept existing
directory's mode` and the others) SHALL name each member where it is after the move, as
a direct extraction into the cwd names it, never a path inside the removed wrapper: a
member the merge renamed is named under its new name. The lines the merge itself prints
(`renamed:` for its own collisions, and `kept existing directory's mode`) come before
the per-member lines, where a direct extraction prints every line in member order: the
hoist prints the same lines, not in the same order. `kept existing directory's mode` is
printed when the archive's directory mode, as the platform stores it, differs from the
operator's directory's mode, on both paths. Windows stores only a read-only attribute,
so there the line is printed only when that attribute differs. When the hoist stops, a
member left behind is named inside the directory that holds it: the wrapper, or the
wrapper's aside name `<wrapper> (N)/` when the wrapper's name could not be taken back,
because the merge gave that name to a member or the rename back failed. The container
(`./<archive-stem>/`) SHALL always be a new directory that the run creates. When
anything exists at the container name (a directory, a regular file, or a symlink,
dangling or live), the name SHALL be treated as taken under every overwrite policy and
the next free `<stem> (N)` used, because the CLI chose that name rather than the
operator. An existing directory SHALL NOT be reused as the container. The overwrite
policy SHALL apply where the content lands: inside the new container, or, after a hoist,
in the cwd. `-d` remains the way to extract into an existing directory or through a link
deliberately: `-d backup --overwrite replace` re-extracts a multi-root archive into an
existing `backup/`. Overwrite SHALL default to `rename` once `OverwritePolicy.RENAME`
exists (`--overwrite` may select `error` / `skip` / `replace` / `rename`). `extract`
SHALL pass `OnError.CONTINUE` by default so policy rejections and per-member read
failures are recorded (`blocked:` / `failed:` lines plus the closing summary) and
remaining members are still extracted where the stream allows. `--stop-on-error` SHALL
restore `OnError.STOP` for that invocation — stopping on member **failures** only.
Policy `BLOCKED` outcomes are always reported-and-continued (library `OnError` does not
halt on blocks; see `stop-on-failure-not-policy`). On an early stop (STOP-path failure
or always-stop limit), the system SHALL still report how many members were **extracted**
and how many were **blocked** before the stop (separate counts; other processed statuses
are omitted from that line).

#### Scenario: CLI behavior matrix

| Case | Expected |
| --- | --- |
| `archivey <archive>` | Same as `archivey list <archive>` (first token is not a known verb → list) |
| `archivey x <archive>` where `x` is also a file in the cwd | Dispatches `extract` (a bare verb word is a verb) |
| `archivey ./x`, `archivey dir/x`, `archivey /abs/x` where the basename is a verb word | Lists that file (a path-qualified token is a path, never a verb) |
| `archivey create <archive>` (reserved, unimplemented) | Usage error "not yet"; does not fall through to `list` |
| `archivey cat <archive>` | Writes the file members' contents to stdout (see the `cat` requirement); does not fall through to `list` |
| `archivey list <archive>` / `archivey l <archive>` | Layer-1 member listing |
| `archivey list <archive>` with recoverable prefix + terminal archive error | Prints recovered members on stdout; stderr names the error; exit `1` |
| `archivey list <archive> --digests` | Listing includes stored digests; no member body read for digests alone |
| `archivey list <archive> --long` | Header plus one line per member with packed size, space saved, method and CRC-32 |
| `archivey list <archive> --details` | One `key: value` block per member with every stored field |
| `archivey test <archive>` / `archivey t <archive>` | Fully reads members, verifies stored digests, reports failures |
| `archivey extract <archive>` / `archivey x …` | Extracts under `--policy` default `strict`, overwrite default `rename`, into the smart default dest |
| `archivey extract <archive>` where archive has many top-level entries | Extracts into `./<archive-stem>/` (no cwd splatter) |
| `archivey extract <indexed-archive>` where archive has a single top-level dir | Extracts into `.`; reuses the archive's root dir (no redundant `foo/foo/`) |
| `archivey extract one.zip --overwrite replace\|skip\|error` holding only `top/f`, with the operator's FILE `top` in the cwd | Extracts into `one/`, prints `kept in one/: top already exists`; the file `top` is untouched; exit `0`. Under `rename` the root moves to `top (1)/` |
| `archivey extract <indexed-archive> 'b/*'` where filtered set has single root `b/` | Extracts into `.` (tops on filtered set); lands as `./b/…` |
| `archivey extract <no-index-archive>` (e.g. plain TAR) with a single top-level dir | Extracts into `./<stem>/` then hoists the single root to cwd |
| `archivey extract foo.tar` holding only `foo`, with the operator's `foo` in the cwd | Wraps in `foo (1)/`, then hoists the root to `foo (1)`, as `-d .` does; prints `renamed: foo -> foo (1)` |
| `archivey extract foo.tar --overwrite skip\|replace\|error` holding `foo/x.txt` (with or without a `foo/` entry), with the operator's FILE `foo` in the cwd | Prints `kept in foo (1)/: foo already exists`; the content is at `foo (1)/foo/x.txt`; the file `foo` is untouched; exit `0`. Under `rename` the root moves to `foo (1)/x.txt` |
| `archivey extract <no-index-archive>` with a single root `top/` holding `c\x02` | Prints `name rewritten: top/c\x02 -> top/c%02`, the path after the hoist |
| As above, with the operator's `top/c%02` in the cwd | Prints `name rewritten: top/c\x02 -> top/c%02 (1)`, as `-d .` does |
| `archivey extract c.tar --overwrite skip` holding `c\x02`, with the operator's `c%02` | Prints `kept in c/: c%02 already exists`; the operator's `c%02` is untouched |
| `archivey extract <no-index-archive>` with multiple top-level entries | Extracts into `./<archive-stem>/` (no hoist) |
| `archivey extract <archive>` needing a wrapper when `./<archive-stem>` is a symlink (dangling or to a directory), any `--overwrite` | Wraps in the next free `./<archive-stem> (N)/`; nothing is written through the link |
| `archivey extract <archive>` needing a wrapper when `./<archive-stem>` is a regular file (for example the archive itself, when it has no extension), any `--overwrite` | Wraps in the next free `./<archive-stem> (N)/`; the file is untouched |
| `archivey extract <archive>` needing a wrapper when `./<archive-stem>/` is an existing directory, any `--overwrite` | Wraps in the next free `./<archive-stem> (N)/`; nothing is written into the existing directory |
| `archivey extract <no-index-archive>` with a single top-level dir `root/` when `./<archive-stem>/` is an existing directory, any `--overwrite` | Extracts into `./<archive-stem> (N)/`, then hoists `root/` to the cwd and removes the wrapper; the existing directory is untouched |
| `archivey extract <no-index-archive>` whose single top-level dir is named like the stem (`src.tar` holding `src/`) when `./src/` is an existing directory | Extracts into `./src (N)/`, then hoists `src/` into the existing `./src/`: `rename` writes `name (N)` beside colliding files; under `--overwrite error`, `skip` or `replace` a colliding file anywhere in the root keeps the whole root under `./src (N)/src/` with nothing moved, prints `kept in src (N)/: src/<file> already exists`, and the exit code is `0` |
| `archivey extract <archive> -d out/ '*.py'` | Dest is `out/` verbatim; `*.py` is a member filter |
| `archivey extract <archive> -d .` | Extracts into cwd verbatim (classic splatter, opt-in) |
| `archivey extract <archive> --policy trusted` | Maps to `ExtractionPolicy.TRUSTED` |
| `archivey extract <archive-with-traversal-and-safe-members>` | Safe members extracted; `blocked:` lines; exit `3` |
| `archivey extract --stop-on-error <archive-with-bad-member>` | Stops at first **failure**; reports extracted/blocked counts before stop; policy blocks alone do not stop |
| Subcommand includes glob pattern(s) after the archive | Operation limited to matching member names (positional = include) |
| `archivey extract <archive> out` where `out/` exists and matches no member | stderr warning with `(did you mean -d out?)`; exit `1` |
| `archivey extract <archive> docs` with members `docs/`, `docs/a.txt`, `docs.txt` | Extracts `docs/` and `docs/a.txt`, not `docs.txt`; no warning |
| `archivey extract <archive> '*.missing'` | stderr warning; exit `1` |
| `archivey list <archive> '*.missing'` | stderr warning; exit `0` |
| `archivey extract <archive> '**/*.py' --exclude '**/*_test.py'` | Includes `**/*.py` minus `**/*_test.py`; exclude wins over include |
| `archivey list <archive> '*.md'` with members `README.md`, `docs/a.md` | Lists `README.md` only: `*` does not cross `/` |
| `archivey list <archive> '**/*.md'` with members `README.md`, `docs/a.md` | Lists both: `**` matches any depth |
| `archivey list <archive> 'a//b'` or `archivey list <archive> '[z-a]'` | stderr `archivey: invalid member pattern: …` with the reason; exit `2` |
| `archivey test <archive> 'a*' --exclude 'a*'` or `archivey extract <archive> --exclude '*'` | stderr `warning: no members selected: …`; exit `1`; `extract` creates no directory |
| `archivey test <archive.tar.gz> a.txt` | The archive is decompressed once; no backward-seek warning |
| `archivey <verb> <archive> --include …` | Usage error — `--include` is not provided (use a positional) |
| `[recommended]` extra absent / `tqdm` missing | Progress suppressed; command and library API remain functional |
| `archivey list data.bi5` (a raw LZMA Alone stream) | stderr names the detection failure and `--probe-content`; exit `1` |
| `archivey --probe-content list data.bi5`, or the flag after any verb | Lists the one decompressed member; exit `0` |
| `--track-io` supplied | Reports decode/seek accounting (bytes decompressed, compressed bytes consumed, source seeks) via the measurement hook; no `builtins` patching |
| `archivey -- -weird.zip` | Lists `-weird.zip` (default `list` inserted ahead of `--`) |
| `archivey -- list` | Opens a file named `list`; a verb word after `--` is an archive path |
| `archivey -x <archive>` (dash-prefixed verb) | Usage error — verbs are bare words (`x`), not options; `-x` is not a mode selector |
| `archivey --policy strict x <archive>` or `archivey list <archive> --policy strict` (a verb's flag before the verb, or after a verb that does not take it) | Usage error naming the flag and the verb(s) it belongs to; a verb's own flags follow a verb that owns them |

### Requirement: Archive-derived text is escaped before terminal display

Archive member names are attacker-controlled. Archive-derived text SHALL NOT reach a
terminal stream carrying control sequences that rewrite, erase, or spoof the output line
reporting it. Escaping SHALL be lossless (a backslash form that names the escaped byte),
not elision.

Escaping SHALL happen where archive-derived text **becomes a message**, not where a
message is displayed:

- **Exception and diagnostic messages** escape themselves at construction
  (`error-handling`, `diagnostics`). This is the only placement that also covers a
  message the CLI never prints itself — an uncaught exception whose traceback the
  interpreter writes to stderr, whose final line is the exception's message.
- **Print sites** escape the member names and member-derived paths they format
  themselves — listings, report lines, summaries — and every archive-level value they
  print, of which the archive comment `archivey info` shows is the widest: arbitrary
  bytes, and on **stdout**, so redirecting stderr does not hide it.

The CLI's log handler SHALL NOT escape the records it renders. Escaping a message that
already escaped itself would double every backslash in it, and the library's own log
call sites interpolate member names through `%r`, which escapes. Records the library
emits SHALL NOT be altered, so a handler installed by an embedding application or a test
receives them verbatim.

When rendering an exception it did not construct — an `OSError` carrying a destination
filename, a third-party error — the CLI SHALL escape it, since only archivey's own
exceptions escape themselves.

A member-derived **path** formatted by a print site SHALL be rendered relative to the
operation's root, with `/` separators, before escaping. A native path would otherwise
have every separator doubled by the backslash escape on Windows. Any other path a print
site formats — the wrapper directory named after the archive file, the destination a
single root was hoisted to, the archive path `info` echoes — SHALL be rendered with `/`
separators before escaping, for the same reason.

Escaping is a **display** concern and SHALL NOT change the bytes written to disk, the
member names the library reports, or any value on `ExtractionResult`.

#### Scenario: control sequences cannot spoof CLI output

| Case | Expected |
| --- | --- |
| Member named `ev\x1b[2Kil\rSUCCESS.txt` in a report line | Printed as `ev\x1b[2Kil\rSUCCESS.txt` — no raw ESC or CR reaches the stream |
| The same member named in a library WARNING record | Escaped identically; the log line cannot be erased and rewritten |
| The same member in the error detail appended to `failed:` / `blocked:` | Escaped |
| `archivey test` failure detail, and the abort / top-level error notices | Escaped — these print the exception, not a report line |
| An `ArchiveyError` propagating uncaught out of the CLI | Traceback's final line is the escaped message; no raw control byte reaches stderr |
| A record carrying `exc_info` | Traceback stays multi-line and readable, and its exception-message line is escaped |
| An `OSError` naming a member-derived path | Escaped by the CLI, which does not assume the exception escaped itself |
| A handler installed by an embedding app or `caplog` | Receives the record unescaped and unmodified |
| An ordinary member name with no control bytes | Printed unchanged |
| A Windows destination path in a report line | Separators not doubled (rendered relative, `/`-separated, before escaping) |
| The same name as the single top-level directory, in the closing summary and the hoist's `moved to` line | Escaped — the summary is the last line the operator reads |
| An archive whose filename carries a non-printable character, extracted into a wrapper named after it | `extracting into` and the summary print the wrapper escaped |
| A ZIP comment carrying `\x1b[2K` + `\r`, shown by `archivey info` | Printed on stdout as `\x1b[2K` / `\r` text; no raw ESC or CR |
| Any other `archivey info` value (format version, `-v` extra entries) | Escaped the same way |
| An archivey exception `info` prints as its `open:` line | Not escaped a second time |

### Requirement: info and detect summarize archive identity

The system SHALL provide `archivey info` (alias `detect`) that reports detected
and/or opened format identity for a path without listing every member. It SHALL
be suitable for answering "what does archivey think this file is?" including
failure cases with a typed/clear error. After a successful open, `info` SHALL
print an `access:` line summarizing the archive's `CostReceipt` (listing /
member-access / stream axes) in human prose. With `-v` / `--verbose`, it SHALL
also print the raw cost axes (`listing`, `access_cost`, `stream`,
`solid_blocks`).

`info` SHALL detect once: the identity lines come from the reader's
`format_info`, not from a separate `detect_format` call before the open. Only
when the open fails does it call `detect_format`, to print what it can, and not
when the path is a pipe, a character device or a socket. Detection opens the path
again, and those are read once, so a second open gets different bytes or waits for
a writer that never comes; on those `info` prints the open error alone.

#### Scenario: info vs list

| Case | Expected |
| --- | --- |
| `archivey info <archive>` / `archivey detect <archive>` | Prints format/identity summary including `access:`; does not dump full member listing |
| `archivey info -v <indexed-zip>` | Includes `access: random (indexed)` and raw cost axes |
| `archivey info <directory>` | Exit `0`; reports format `directory` (the answer `detect_format` gives); no "cannot open" error |
| Unreadable/unknown file | Non-zero exit; clear error (no stack trace by default) |
| `archivey info <archive>` that opens | Detection runs once, inside the open |
| `archivey info <fifo>` whose open fails (a 7z, say) | Exit `1`; prints the open error; does not open the FIFO again, so it does not block |
| `archivey list <archive>` | Member listing; not a substitute for info's format summary |

### Requirement: version reports package identity and optional format matrix

`--version` SHALL print `archivey <version>` and exit. With `-v` / `--verbose`,
it SHALL also print a `formats:` matrix from the registry availability API
(`list_known_formats` / `format_availability`), including missing-component
install hints when support is not full.

#### Scenario: version

| Case | Expected |
| --- | --- |
| `archivey --version` | One line: `archivey <version>`; exit `0` |
| `archivey --version -v` / `archivey -v --version` | Version line plus `formats:` availability matrix |

### Requirement: salvage flag reserved without behavior

The system SHALL accept `--salvage` on `list`, `test`, and `extract` (and on
future `hash` / `convert` when those verbs exist) but MUST NOT implement salvage
semantics. Passing `--salvage` SHALL fail fast with a clear
not-implemented message so callers cannot assume best-effort reads.

#### Scenario: salvage reserved

| Case | Expected |
| --- | --- |
| `archivey list <archive> --salvage` | Non-zero exit; message indicates salvage is not implemented |
| `archivey extract <archive> --salvage` | Same |

### Requirement: reserved verbs do not collide with future write/hash UX

The system SHALL NOT reuse a verb letter that commonly means create/compress for
integrity checking (in particular `c` MUST NOT mean "check"; leave it for a
future `create`). Help text MAY mention `hash`, `create` and `convert` as
forthcoming without implementing them.

#### Scenario: flag hygiene

| Case | Expected |
| --- | --- |
| `t` | Means `test` (integrity), not create |
| Unknown verb `hash` / `create` / `convert` before implementation | Usage error naming the verb as unavailable (not a silent fallthrough to `list`) |

### Requirement: exit codes are argparse-aligned with a policy-refusal code

The system SHALL exit `0` on success and `2` on CLI usage errors (unknown
verb/flag or bad arguments — the argparse default), unless the output or message
could not be delivered (see the codes `128` and above below). Operational failures
(unreadable, unsupported, or corrupt archive; read/integrity failure; member
extraction `FAILED`; incomplete listing whose `MemberListReport.error` is set;
an early abort under `--stop-on-error` on a member **failure**, or any
always-stop / hoist failure) SHALL exit `1`. When `extract` **completes**
(under CONTINUE or STOP) with one or more members `BLOCKED` by safety policy
and no member `FAILED`, the system SHALL exit `3` (refused by safety policy —
safe members are on disk). Because `OnError.STOP` / `--stop-on-error` never
halts on a policy block, a STOP+policy abort cannot occur; exit `3` MUST NOT
be used for an aborted STOP-path failure. Exit codes `4` to `127` SHALL remain
reserved.
Codes `128` and above follow the shell's `128 + N` convention for signal `N`
and are not in the reserved range: a command interrupted by Ctrl-C (SIGINT)
SHALL print `interrupted` and exit `130`. A command whose stdout or stderr pipe
is closed by its reader SHALL stop without a message or traceback and exit `141`
(128 + SIGPIPE), on every platform, Windows included. That holds for help and
usage text and for error messages as well as for a verb's output: a usage error
whose message cannot be delivered SHALL exit `141`, not `2`, because the output
was lost.
Documentation SHALL direct callers to treat any nonzero code other than `2` as
a failure and MUST NOT assume `1` is the only failure code.

#### Scenario: exit codes

| Case | Expected |
| --- | --- |
| `archivey list <valid-archive>` | Exit `0` |
| `archivey --badflag` / unknown verb | Exit `2` (usage) |
| `archivey list <corrupt-or-unreadable>` | Exit `1` |
| `archivey list <archive-with-recoverable-prefix-and-terminal-error>` | Exit `1` (after printing recovered members) |
| `archivey test <archive-with-failing-member>` | Exit `1` |
| `archivey test <archive>` with a symlink whose target is stored as data (ZIP, 7z, RAR4) and fails its check | That link is reported `FAIL`; exit `1`. A link for which the archive records no target is not a failure |
| `archivey test <indexed-archive>` when the member stream aborts early | Summary includes `K not tested` for the untested remainder; exit `1` |
| `archivey test <truncated-tar>` (plain or compressed) whose stream ends on the error a member read already reported | One `FAIL <member>:` line, then `test stopped; remaining members were not tested`; the summary counts that member once; exit `1` |
| `archivey test <archive>` when a digest goes unchecked (`DIGEST_UNVERIFIABLE` / `ENCRYPTED_MEMBER_UNVERIFIED`) | Summary includes `V not verified`; exit `1` |
| `archivey extract <archive-with-traversal-and-safe-members>` | Extracts safe members; prints `blocked:`; exit `3` |
| `archivey extract --stop-on-error <archive-with-traversal-and-safe-members>` | Extracts safe members; prints `blocked:`; exit `3` (blocks always continue) |
| `archivey extract <archive-with-corrupt-member>` | Extracts recoverable members; prints `failed:`; exit `1` |
| `archivey extract --stop-on-error <archive-with-corrupt-member>` | Stops at first failure; exit `1` |
| `archivey extract <archive>` with a blocked or failed member | One line for each `BLOCKED` / `FAILED` result in the report (`blocked:` / `failed:`); the library's `Skipping …` warning is not printed too |
| `archivey extract <streamed archive>` where a later copy of a name supersedes an earlier copy that failed | The earlier copy's error is dropped with it, as the library's report drops it and as a random-access run never meets it; only the later copy's outcome is reported |
| `archivey extract --stop-on-error <archive>` that blocks a member, then stops on a failure | No report is returned, so the `WARNING: Skipping …` line for the blocked member is printed before the stop line |
| Ctrl-C during `archivey test` or `archivey extract`, including between members of the read pass | Prints `interrupted`; exit `130` |
| Any verb whose stdout or stderr pipe closes while it writes (`archivey t big.zip 2>&1 \| head -1`) | Stops without a message or traceback; exit `141`, so a `test` that had not finished verifying does not report success |
| `archivey --help \| true`, or a usage error whose stderr pipe is closed | No message or traceback; exit `141` (not `0` or `2`) |

### Requirement: read-once paths open in streaming mode

When the archive path is a pipe (FIFO), a character device or a socket, which can be
read only once, every verb that opens the archive (`list`, `test`, `extract`, `info`)
SHALL open it in streaming mode, because the user has no option to choose the mode.
`list` SHALL list the members in one pass, `test` SHALL verify them in one pass and
`extract` SHALL extract them in one pass; TAR, ZIP and the single-file formats read
so. When the format cannot be read in one forward pass (7z, RAR, ISO), the verb SHALL
exit `1` with a message that names the format by its file extension (`7z`, `rar`,
`iso`) and tells the user to copy the input to a regular file first. The message MUST
NOT suggest `streaming=True` or a `BytesIO`, which a CLI user cannot pass. A block
device rereads the same bytes and opens as a regular file does.

A read-once path includes `/dev/stdin` and `/proc/self/fd/N` when that descriptor is a
pipe, so an archive piped on stdin is read through this requirement. The `-` token is
separate: `cat` reads it from stdin, and every other verb refuses it (below).

#### Scenario: read-once paths

| Case | Expected |
| --- | --- |
| `archivey list <tar-fifo>` (also `<zip-fifo>`) | Lists every member; exit `0` |
| `archivey test <tar-fifo>` (also `<zip-fifo>`) | Verifies every file member in one pass; exit `0` |
| `archivey extract <tar-fifo> -d out` (also `<zip-fifo>`) | Extracts every member into `out`; exit `0` |
| `archivey info <tar-fifo>` | Prints the identity and an `access:` line that says the source is forward-only; exit `0` |
| `archivey list <7z-fifo>` (also `test`, `extract`, `info`; also RAR, ISO) | Exit `1`; message names the format as `7z` (`rar`, `iso`) and says to copy the input to a regular file first |
| `cat a.tar \| archivey list /dev/stdin` | Lists every member; exit `0` |

### Requirement: the stdin token `-` is reserved outside `cat`

For every verb except `cat`, which reads the archive from stdin when given `-` (see the
`cat` requirement), the system SHALL treat `-` as a reserved token meaning "read archive
from stdin" and SHALL fail fast with a clear "not supported yet" message rather than opening a
filesystem entry literally named `-`. Outside Windows, the message SHALL name
`/dev/stdin`, through which a piped archive is read as a read-once path (above). On
Windows, which has no `/dev/stdin`, the message SHALL tell the user to copy the archive
to a regular file instead.

#### Scenario: stdin reserved

| Case | Expected |
| --- | --- |
| `archivey list -` | Non-zero exit; message says the `-` token is not supported yet and names `/dev/stdin` (on Windows: says to copy the archive to a regular file) |
| `archivey extract -` | Same |
| `archivey cat -` | Reads the archive from stdin (see the `cat` requirement) |

### Requirement: cat writes member contents, or the decompressed outer stream, to stdout

`archivey cat ARCHIVE [pattern...] [--exclude PATTERN]` SHALL write the contents of the
selected file members to stdout as raw bytes, one after another in archive order, in a
single forward pass, as `unzip -p`, `tar -xO` and `unar -o -` do. Patterns SHALL select
members as they do for `list`, `test` and `extract`. Directories, links and other
entries have no body of their own and SHALL be skipped; under `-v` each written member's
name SHALL go to stderr, and each skipped one as `skip NAME`. A pass reads forward
only, so a link's target, an earlier member, is not read again for it.

`ARCHIVE` `-` SHALL read the archive from stdin in streaming mode. When stdin is a pipe,
a format that needs to seek SHALL be refused with the read-once message, naming the
source as `stdin`; a redirect from a regular file can seek, so every format reads.

Bytes reach stdout as they are decoded, so a member that fails its read or its digest
check may already have written part or all of its bytes. The system SHALL then print the
error on stderr, naming the member, stop without writing later members, and exit `1`,
as `zcat` does. When the archive has a free index, the patterns SHALL be judged before
any byte is written, so a selection that matches nothing exits `1` with nothing on
stdout; otherwise they are judged after the pass, as for `test`.

`--outer` SHALL write the source with only its compression layer removed: the tar
inside a `.tar.gz`, the file inside a `.gz`, as `zcat` or `zstdcat` would, detected
by content whatever the file is named. For a single compressed file both modes write
the same bytes. `--outer` on a container with no compression layer (ZIP, 7z, RAR, ISO,
an uncompressed tar) SHALL exit `1` with a message that names the format and says to
leave out `--outer`; on a directory it SHALL be a usage error. `--outer` with member
patterns, `--exclude` or `--track-io` SHALL be a usage error.

A stdout the reader closed SHALL exit `141`, as for the other verbs.

#### Scenario: cat refusals

The worked cases (selection, `-v`, stdin, `--outer` output) are in
`tests/test_cli_cat.py`; the refusals and their exit codes are the contract.

| Case | Expected |
| --- | --- |
| `archivey cat a.zip nomatch` | Warning names the pattern; nothing on stdout; exit `1` |
| `curl …/a.rar \| archivey cat -` | Exit `1`; read-once message naming `stdin` and `rar` |
| `archivey cat bad-crc.gz` | Error naming the member on stderr; exit `1` |
| `archivey cat a.zip --outer` | Exit `1`; message names `zip` and says to leave out `--outer` |
| `archivey cat a.tar.xz --outer a.txt` | Usage error, exit `2` |
| `archivey cat big.gz \| head -c 5` | Exit `141` |

### Requirement: extract and test --outer work on the compression layer alone

`archivey extract ARCHIVE --outer` SHALL write the source with only its compression
layer removed, as one file, as `gunzip -k` and `unxz -k` do: the tar of a `.tar.gz` or
`.tgz` as `data.tar`, the file of a `.gz` under the single-file member name
(`format-single-file-compressors`). It SHALL open the source as that single compressed
file, so `-d`, the default destination, `--overwrite`, `--policy`, `--dry-run` and the
report behave as for any single-file archive. `archivey test ARCHIVE --outer` SHALL read
the whole decompressed stream, check the codec's end-of-stream check where it has one
(Brotli and `.Z` have none), as `gzip -t` and `xz -t` do, and report it as one member.

As for `cat --outer`, the layer SHALL be found by content whatever the file is named;
on a container with no compression layer the run SHALL exit `1` with a message that
names the format and says to leave out `--outer`; a directory, member patterns or
`--exclude` SHALL be a usage error. A read-once path SHALL be a usage error that names
`archivey cat --outer`, since finding the layer reads the start of the pipe.

#### Scenario: outer refusals

The worked cases are in `tests/test_cli_outer.py`.

| Case | Expected |
| --- | --- |
| `archivey x data.tgz --outer` | Writes `data.tar` |
| `archivey t weird.name --outer` on zlib bytes | Found by content; `1 OK` |
| `archivey t a.tar --outer` | Exit `1`; message names `tar` and says to leave out `--outer` |
| `archivey x a.tar.gz --outer a.txt` | Usage error, exit `2` |

### Requirement: an empty path argument is a usage error

The system SHALL refuse an empty string given as the archive argument of any verb, or
as `extract --dest`, with a usage error (exit `2`) and a message, before anything is
read or written. `Path("")` is `Path(".")`, so an unset shell variable
(`"$ARCHIVE"`, `-d "$OUT"`) would otherwise read or extract into the working
directory; `.` remains the way to name it.

#### Scenario: empty path

| Case | Expected |
| --- | --- |
| `archivey list ""`, `test ""`, `info ""`, `extract ""` | Exit `2`; message names the empty path; no traceback |
| `archivey extract a.zip -d ""` | Exit `2`; nothing is written to the working directory |

### Requirement: The CLI uses only public API

The `archivey.cli` package SHALL import nothing from `archivey.internal`, with one
exception. `--track-io` imports `archivey.internal.measurement`, because the CLI is
also a debugging tool for the library and IO measurement is not public API. What it
needs beyond `archivey.__all__` SHALL otherwise come from a public module, such as
`archivey.terminal` for terminal-safe display and `archivey.paths` for the `name (N)`
spelling its single-root hoist shares with extraction. The CLI is the example other
front ends copy, and an internal import would let an internal refactor break it
without touching any public name. `extract --dry-run` also reads four private fields,
`ExtractionReport._dry_run_top_level`, `ExtractionReport._dry_run_links`,
`ExtractionReport._dry_run_entries` and `ExtractionReport._resource_usage`: the entries
the dry run left at the top of its scratch copy of the destination, the symlinks in that
copy, every entry in it, and the reader's peak use of its limits. A dry run writes
nothing the CLI could look at instead, and the usage record stays private until a scan
shows which of its numbers are worth a public name. Renaming any of these fields breaks
the dry run's hoist line, usage line and summary. Apart from those four fields, the CLI
SHALL NOT read a private attribute of a library object, and SHALL NOT decide anything
from a library exception's message: `extract` tells a re-root from a portable rewrite
by `ExtractionResult.rewrites`, and `test` tells a link the archive left without a
target by `ArchiveMember.link_target_unrecorded`, and an error about where a link
points by its type (`LinkTargetNotFoundError`) or its marker
(`ArchiveyUsageError.refused_member_type`). Argparse's own attributes and messages are
not the library's, and the CLI's parser reads both.

#### Scenario: CLI import boundary

| Case | Expected |
| --- | --- |
| Any module under `src/archivey/cli/` | No `import archivey.internal…` or `from archivey.internal… import`, except the allowlisted measurement import |
| One is added | `tests/test_cli_uses_public_api.py` fails, naming the file and line |
| The allowlisted import is removed | The same test fails until the allowlist entry goes too |

### Requirement: extract --dry-run reports without writing

`archivey extract --dry-run` SHALL run the extraction with `dry_run=True`. It SHALL
print the same per-member lines and return the same exit code as the same command
without `--dry-run` would against the same destination, and its closing summary SHALL
say that nothing was written. With no `-d`, it SHALL name the smart default destination
it would use, and SHALL NOT move anything. Where a real run would move a single
top-level entry out of that destination, it SHALL name where that entry would land,
and use that place in the closing summary. Where a real run would keep that entry in
the destination (the entry is a symlink, a symlink in it leaves it, or part of the
entry could not be listed, which here means part of the scratch tree could not be
read), it SHALL print `would keep in <stem>/:` with the same reason, judged from the
symlinks the dry run created. Where the real run would keep the entry because its merge
meets a collision the overwrite policy cannot resolve, it SHALL print
`would keep in <stem>/: <path> already exists`, judged from the entries the dry run
created against what is on disk. It SHALL NOT list the collisions the policy resolves,
nor check whether an existing directory there can be written into: a real run whose
hoist is refused by that directory's permissions fails where the dry run predicted the
move.

Just before its closing summary, `extract --dry-run` SHALL print one line beginning
`peak use of the reader limits:` with the parts that are not zero: the largest decoder
allocation archivey checked and what it was for, the key-derivation rounds, the spool
peak and the listing's member count and metadata bytes, each in the unit its limit
field uses. When every part is zero, or the run ends before its summary, there is no
line. A run without `--dry-run` SHALL NOT print it.

#### Scenario: extract dry-run matrix

| Case | Expected |
| --- | --- |
| `archivey extract <archive> --dry-run` | stderr names `would extract into <stem>/`; summary begins `dry run, nothing written:`; nothing created in the cwd |
| `archivey extract <archive-with-traversal> --dry-run` | `blocked:` line; exit `3` |
| `archivey extract <archive> -d out --dry-run` | `out` is not created |
| `archivey extract <7z-with-an-LZMA2-folder> --dry-run` | a `peak use of the reader limits:` line names `decoder memory` and `LZMA2 dictionary size`; without `--dry-run`, no such line |
| `archivey extract <tar-with-single-root-src> --dry-run` | stderr names `would move to src/`; summary ends `→ src/`; nothing created in the cwd |
| `archivey extract <tar-whose-single-root-has-a-link-leaving-it> --dry-run` | stderr names `would keep in <stem>/:` and the reason the real run prints; no `would move` |
| `archivey extract foo.tar --dry-run --overwrite error` holding `foo/x.txt`, with the operator's file `foo` | stderr names `would keep in foo (1)/: foo already exists`; summary ends `→ foo (1)/` |
