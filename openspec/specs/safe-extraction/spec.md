# Safe Extraction

## Purpose

Safe extraction writes archive members to a destination directory while enforcing
non-bypassable path safety, link safety, overwrite rules, permission transforms,
decompression-bomb limits, progress callbacks, diagnostics, and per-member
results. It is the caller-facing path for putting archive contents on disk.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | `open_archive()`, `ArchiveReader`, selectors, reader diagnostics, access methods |
| `access-mode-and-cost` | `extract_all()` as a forward-pass method and streaming legality |
| `diagnostics` | Diagnostic values, retention budgets, watermarks, extraction outcome codes |
| `error-handling` | Exception classes and ordered diagnostic/exception behavior |
| `format-tar` | TAR hardlink ordering, link recovery, and TAR-specific extraction constraints |

## Requirements

### Requirement: Per-Reader Extract-All Helper

`ArchiveReader.extract_all()` SHALL expose per-reader extraction with optional
member selection and filtering:

```python
def extract_all(
    dest: str | Path,
    *,
    members: MemberSelector | None = None,
    filter: MemberFilter | None = None,
    policy: ExtractionPolicy = ExtractionPolicy.STRICT,
    overwrite: OverwritePolicy = OverwritePolicy.ERROR,
    on_error: OnError = OnError.STOP,
    on_progress: Callable[[ExtractionProgress], None] | None = None,
    limits: ExtractionLimits | None = None,
) -> ExtractionReport: ...
```

The helper SHALL count the diagnostics its own call emits, on its own thread, and
return a report whose summary contains exact counts and retained entries for this
extraction call only, even when other threads use the reader meanwhile.
`reader.diagnostics` remains cumulative. The call SHALL run under the reader's
open config — its collector, diagnostic policy, callback and retention maximum —
and SHALL NOT take a `config=`; `limits=` overrides only the extraction limits.

Selection, filter ordering, one-pass selected extraction, reader-config
inheritance, and per-call limits precedence retain their existing contracts.
There is no single-member `reader.extract()` method, and no top-level
`archivey.extract()`: opening the archive and calling `extract_all()` is the one way to
extract (ADR 0019).

#### Scenario: extract_all matrix

| Case | Expected |
| --- | --- |
| Reader emitted a diagnostic before `extract_all()` and another during extraction | Report summary includes only the extraction occurrence; `reader.diagnostics` includes both |
| `reader.extract_all(dest, members=["a", "b"])` on a solid archive | Only selected members are extracted in one decompression pass |
| Caller wants one file | Uses `reader.extract_all(dest, members=[name])`; no separate single-member API |

### Requirement: Extraction reads limits and strictness from the configuration object

`ArchiveReader.extract_all()` SHALL accept `limits: ExtractionLimits | None`. Per-call
`limits` takes precedence over the reader's `config.extraction_limits`, then the
library default. `ExtractionLimits.UNLIMITED` disables byte, ratio,
archive-wide ratio/live-ratio, and entry-count guards. Policy, overwrite,
`on_error`, progress, and member-selection/filter arguments remain operational
arguments outside config.

`extract_all()` always returns `ExtractionReport` with an accumulated immutable result
tuple on success; there is no no-tracking mode.

#### Scenario: limits/config matrix

| Case | Expected |
| --- | --- |
| `extract_all(limits=...)` on an existing reader | Limits apply to this extraction; the report holds only this call's own diagnostics, from the existing collector |
| `open_archive(..., config=ArchiveyConfig(extraction_limits=ExtractionLimits(max_extracted_bytes=10 * 2**30)))` then `extract_all(dest)` | Cumulative byte limit is 10 GiB |
| Reader config has limits, call passes `limits=ExtractionLimits(max_extracted_bytes=50 * 2**20)` | 50 MiB governs this run; later calls without `limits` revert to reader config |
| `limits=ExtractionLimits.UNLIMITED` | Archives that would trip default guards complete without bomb-guard error |
| Reader opened with custom config and `extract_all(dest)` | Reader config, including extraction limits, governs the run |

### Requirement: Non-Bypassable Universal Path-Safety Constraints

The system SHALL run universal safety checks on the member about to be written:
after the policy transform, the absolute-name re-root below, and the user `filter`,
and before any filesystem write. `ExtractionPolicy.TRUSTED` does not bypass them. The
filter therefore sees every selected member, unsafe ones included, and can rename one
to a safe name; the checks run on whatever it returns. The default path-safety behavior
is reject/raise, with one rewrite:

- **Absolute names are re-rooted under `STANDARD` and `TRUSTED`.** Before the filter
  runs, a rooted name (a leading `/` or `\`, which covers UNC, or a drive letter
  followed by `/` or `\`) loses that root, repeatedly (`/etc/x` → `etc/x`, `C:\x` →
  `x`), and the member extracts inside `dest`. A drive-relative name (`C:x`) is not
  rooted: it is also an ordinary POSIX name (`a:b`), so it is not rewritten and the
  check below refuses it. Link targets are not re-rooted: a SYMLINK target is a
  filesystem path, and a HARDLINK target names a member, which is re-rooted on its own
  turn (see "Hardlink Two-Pass Extraction"). `STRICT` does not re-root, so the check
  below refuses the member. This
  matches GNU tar, bsdtar, unzip, 7-Zip and Python's `tarfile` `data` filter, which
  all strip the root. A re-root is a name rewrite: `AbortOn.NAME_SANITIZED` raises
  `NameRewrittenError` on it and `presented_name` records it, unless the filter
  dropped the member or renamed it.
- **`archivey.sanitize_names`** is a public `MemberFilter` that rewrites instead of
  refusing, at any policy: it strips a root, resolves `..` against the segment before
  it and drops a `..` with nothing to climb out of (`a/../b` → `b`, `../x` → `x`),
  removes bidi override/isolate characters, appends `_` to a Windows-reserved stem
  (`CON.txt` → `CON_.txt`), and replaces `:` and NUL with `_`. It leaves a HARDLINK
  target as stored: the target is a member name, and rewriting it would name another
  member. A SYMLINK target gets the character and segment rewrites only (`file:stream` →
  `file_stream`); its root and its `..` components are kept, and one with a drive or
  UNC root stays refused. A SYMLINK target read only after the filter ran (see
  `archive-reading`, "Link targets stored as member data are read only when
  configured") gets the same rewrite, because `extract_all` calls the filter again once
  the target is read. It returns the member unchanged when nothing needs rewriting.

The implementation SHALL enforce defense in depth: first a string check rejects
absolute paths, Windows drive/UNC roots, any `..` component split on `/` or `\`,
null bytes, and names/symlink targets the platform filesystem encoding cannot represent;
then `(dest / member.name).parent.resolve()` must remain within `dest.resolve()` to
catch symlinked intermediate components without following a final-component symlink;
symlink targets are rechecked as described in the symlink requirement. A HARDLINK
target string gets none of these checks; the hardlink requirement says when a link is
refused. These
string checks SHALL raise `FilterRejectionError`, never a raw
`UnicodeEncodeError`/`ValueError`.

| Constraint | Violation type | Condition |
| --- | --- | --- |
| Path traversal | `FilterRejectionError` | Any `..` component, escaping or internal |
| Absolute path | `FilterRejectionError` | Leading `/`, Windows drive path, or UNC path |
| Null byte | `FilterRejectionError` | `member.name` contains `\x00` |
| Unrepresentable name | `FilterRejectionError` | `member.name` cannot be encoded by the platform filesystem encoding |
| Link-target NUL / unrepresentable | `FilterRejectionError` | SYMLINK `link_target` contains `\x00` or cannot be encoded by the platform filesystem encoding |
| Symlink escape | `FilterRejectionError` | SYMLINK whose fully resolved target escapes `dest` |
| Link-target Windows root | `FilterRejectionError` | SYMLINK whose `link_target` starts with a drive letter (`C:`, `C:/x`, `C:x`) or a UNC root (two separators, `//server/share`), on every OS. Named exception: a target rooted by a single `\` (`\foo`) |
| Refused hardlink source | `FilterRejectionError` | HARDLINK whose source (`link_target_member`, the end of its chain) was refused (see "Hardlink Two-Pass Extraction") |
| Special file | `FilterRejectionError` | `MemberType.OTHER` device/FIFO/socket/etc. |

**A symlink target with a Windows root is refused on every OS.** Windows resolves a
drive or UNC target outside `dest` and refuses it as an escape; POSIX would create it as
a relative link into a directory named `C:`. The maintainer ruled on 2026-10-06 to
refuse it on POSIX too, for the portability rule: the same archive SHALL give the same
outcome on any OS, and Windows already refuses drive paths. The rule applies to every
format, because it reads the target string. It is a SYMLINK rule: a HARDLINK target is
a member name, never a path, so a link to the member `C:/x` or `C:x` gets what that
member gets (see "Hardlink Two-Pass Extraction").

The rule has one named exception. A SYMLINK target rooted by a single `\` (`\foo`)
SHALL extract on POSIX, where it is a relative link to a file named `\foo`, although
Windows resolves it to the drive root and refuses it as an escape. On POSIX a backslash
is an ordinary filename character, so refusing the target would block an archive that
is valid there, and ADR 0013 rules that extracting beats refusing. The exception holds
only where the `\` stays literal: `STRICT` and `STANDARD` write a TAR `\` as `/` (see
Portable-name enforcement), so there `\foo` is the rooted `/foo` and is refused as an
escape, as `..\x` is; `TRUSTED` keeps it. A HARDLINK target rooted by a single `\`
names a member, so it gets what that member gets. A Windows symlink or junction's
target is normalized before this check in ZIP, 7z and RAR5 alike (`\` to `/`, the
`\??\` prefix dropped, `UNC\` to `//`), so `\??\C:\Windows` is checked as
`C:/Windows`.

**Bidi overrides are rejected by the *policy*, not universally.** Every other
constraint in this requirement meets one of two criteria: the **write itself** is
dangerous or impossible — it escapes the destination, carries a NUL the OS truncates on,
or names a device — or the **outcome would differ by OS**, as for a link target with a
Windows root. A bidi override meets neither: the member lands inside `dest` under
exactly its stored bytes, and what is compromised is the name a person **reads back
afterwards**. That is a presentation property, and presentation is the axis
`ExtractionPolicy` owns.

The rejection therefore lives in the portable-name policy below, which means
`ExtractionPolicy.TRUSTED` — defined as *faithful bytes, no name rejection or rewrite* —
SHALL extract such a member unchanged, while `STRICT` (the default) and `STANDARD` SHALL
reject it with `FilterRejectionError`. Running after the caller filter also means a filter
that renames the member rescues it, which is the natural remedy for a name that is a lie.

Without this split a caller who wants the bytes — a mirroring tool, a format converter, a
forensic extract — has no route at *any* policy. That is the outcome ADR 0013 rejected for
unrepresentable names ("extracting beats refusing"), and it would couple two unrelated
axes. See ADR 0017.

**The rejected set is the reordering controls only.** Unicode bidi controls are not one
category, and the difference is load-bearing:

| Subset | Codepoints | Extraction |
| --- | --- | --- |
| Overrides and isolates — reorder *surrounding* text; what a `…gnp.exe` disguise requires | U+202A–U+202E, U+2066–U+2069 | **Rejected** |
| Directional marks — set the direction of one neutral character, reorder nothing, and occur in legitimate Arabic and Hebrew filenames | U+061C, U+200E, U+200F | **Accepted**; `MEMBER_NAME_BIDI_CONTROL` already reported it at listing |

The reject set SHALL be defined by enumerating those two ranges, and MUST NOT be derived
by subtracting from the library's broader advisory set: a subtraction leaves the three
marks one editing mistake away from rejecting legitimate RTL filenames.

Right-to-left **script** is unaffected: an Arabic or Hebrew filename takes its direction
from its own letters' properties, and contains no bidi control at all.

Listing and reading SHALL continue to present the name exactly as stored. Rejection
belongs to extraction, which is where a name becomes a filesystem path a person will
read back.

#### Scenario: universal safety matrix

| Case | Expected |
| --- | --- |
| `"../evil"` or `"../../etc/passwd"` | `FilterRejectionError`; no write; all policies |
| `"foo/../bar"` | `FilterRejectionError` under reject/raise behavior even if it would stay in root |
| Leading `/`, Windows drive, UNC path under `STRICT` | `FilterRejectionError`; no write |
| `"/etc/x"` or `"C:/etc/x"` under `STANDARD` / `TRUSTED` | Extracted at `dest/etc/x`; `result.member.name` keeps the stored name |
| HARDLINK `"/b"` → `"/a"` under `STANDARD` / `TRUSTED` | Both members re-rooted; `b` linked to the extracted `a` |
| Absolute name, `abort_on={NAME_SANITIZED}`, `STANDARD` | `NameRewrittenError`; no report |
| The same, with a filter that drops or renames the member | No error; the filter's outcome stands |
| `"/etc/x"` under `STANDARD` | `presented_name="/etc/x"`; `rewrites == {REROOTED}` |
| `"/a/what?.txt"` under `STANDARD` | Written `a/what%3F.txt`; `presented_name="/a/what?.txt"`; `rewrites == {REROOTED, PORTABLE_NAME}` |
| `"a:b"` (drive-relative) at any policy | `FilterRejectionError`; never re-rooted to `b` |
| Caller filter returns an absolute or `..` name | `FilterRejectionError`; the check runs on the filter's output |
| `"../evil"` with `filter=sanitize_names` | Extracted at `dest/evil`, all policies |
| `"a/../b"` with `filter=sanitize_names` | Extracted at `dest/b`, all policies |
| Earlier member creates symlink `foo` outside `dest`; later member writes `foo/x` | Parent resolution rejects `foo/x` with `FilterRejectionError` |
| Name with a lone surrogate outside U+DC80–U+DCFF (`hi\ud800`) | Extracts: `hi%ED%A0%80` under `STRICT`/`STANDARD`; under `TRUSTED` POSIX writes `hi` + `ed a0 80`, Windows the exact name; never raw `UnicodeEncodeError` |
| SYMLINK `link_target` with `\x00` | `FilterRejectionError`; never raw `ValueError` |
| SYMLINK `link_target` `C:/Windows`, `C:/abs/y`, `t:stream` or `//srv/share`, any policy, any OS | `FilterRejectionError` ("Symlink target is a Windows drive or UNC path"); no link written |
| SYMLINK `link_target` `\foo`, any policy, POSIX | Extracted: a link to the file `\foo` beside it |
| HARDLINK `hl` → `\x`, `C:/x` or `/x` beside a member of that name, any OS | `STRICT`: both `FilterRejectionError` (`hl`: "Hardlink target was refused"); `STANDARD`/`TRUSTED`: the member re-rooted, `hl` linked to it |
| HARDLINK `hl` → `C:x` beside a member `C:x`, any policy, any OS | Both `FilterRejectionError` (`hl`: "Hardlink target was refused") |
| SYMLINK `link_target` `file:stream` or `sub/NUL` with `filter=sanitize_names`, `STANDARD` | Extracted, pointing at `file_stream` or `sub/NUL_`; `C:/x` is still refused; the same with `read_link_targets=False` on a ZIP |
| Windows symlink or junction stored as `\??\C:\Windows`, `\??\UNC\srv\share` or `..\up\x` (ZIP, 7z, RAR5) | Lists as `C:/Windows`, `//srv/share`, `../up/x`; the first two refused as above, the third as an escape |
| Name using only `surrogateescape` round-trip low surrogates (`\udc80`–`\udcff`) | Accepted when otherwise safe (representable on disk) |
| `MemberType.OTHER` | `FilterRejectionError`; all policies |

#### Scenario: bidi name matrix

| Case | Expected |
| --- | --- |
| `"invoice‮cod.exe"` extracted under `STRICT` / `STANDARD` | `apply_name_policy` raises `FilterRejectionError`; a `BLOCKED` result and no write |
| The same member extracted under `TRUSTED` | **Extracts**, under the stored name, unmodified — faithful bytes |
| `"a⁦b⁩.txt"` (isolates) extracted | Same split |
| Symlink whose `link_target` contains U+202E | Same split |
| A caller filter renames it to a clean name | Extracts at every policy — the check runs on the final name, after the filter |
| `"‏דוח.pdf"` (RLM, a directional mark) extracted | Extracts; `MEMBER_NAME_BIDI_CONTROL` was reported at listing |
| `"فهرس.txt"` (Arabic script, no controls) extracted | Extracts; no diagnostic, no rejection |
| Any of the above listed rather than extracted | Name presented exactly as stored |
| Bidi-override rejection under either `OnError` | `BLOCKED` result, like any other `FilterRejectionError`; extraction proceeds unless `AbortOn.BLOCKED_MEMBER` is set |

### Requirement: Filesystem refusal of a member name is a typed error

A member name can pass `check_universal` (it encodes via `os.fsencode`, e.g. undecodable
archive bytes carried as `surrogateescape` low surrogates) and still be refused by the
destination filesystem at write time — a UTF-8-enforcing filesystem (APFS) rejects the
byte sequence with `EILSEQ`, and any filesystem rejects a component, whole path or
symlink target longer than it allows with `ENAMETOOLONG`. Extraction SHALL translate
either refusal into a typed
`ExtractionError` (carrying the member name and the original `OSError` as cause) rather
than letting the raw `OSError` escape. Under `OnError.CONTINUE` it is an ordinary
per-member failure result. On filesystems that accept arbitrary bytes (typical Linux),
the member extracts normally; the refusal is an environment outcome, not a property of
the archive.

Windows reports the same two refusals as `winerror` 123 (`ERROR_INVALID_NAME`) and 206
(`ERROR_FILENAME_EXCED_RANGE`); extraction SHALL type those the same way. Windows also
refuses to create a symlink with `winerror` 1314 (`ERROR_PRIVILEGE_NOT_HELD`) when the
process lacks the privilege; that SHALL be a typed `ExtractionError` as well, with its own
message naming the missing privilege.

**Paths past `MAX_PATH`.** Win32 refuses a path of 260 characters or more unless the
machine enables long paths, and reports it as a missing path. On Windows, extraction SHALL
pass each path under the destination that is that long to the filesystem in the extended
form (`\\?\C:\...`, `\\?\UNC\server\share\...`), so a deep member is written as it is
on POSIX. The extended form SHALL NOT appear in results, errors, diagnostics or CLI
output: they name the path as the caller would write it. The path-safety checks SHALL
resolve a long path through the extended form and compare the result without the
prefix, so a symlink deep in the tree is followed as for a short path. A path that a
call still takes without the prefix and that fails as missing (`winerror` 3) while being
at least `MAX_PATH` long SHALL be typed as too long, like `winerror` 206; a component
longer than the filesystem allows stays the typed error above.

`EINVAL` is deliberately not auto-translated: it is a broad errno that can arise from
unrelated syscalls during extraction. The Windows codes are matched on `winerror`, not
on the errno CPython maps them to (`EINVAL`, `ENOENT`).

Renaming the member to a representable name instead of failing is deliberately not part
of this requirement — it belongs to the future opt-in `SANITIZE` extraction policy
(post-v1, see `dev-docs/IDEAS.md`), not to a bespoke option.

#### Scenario: UTF-8-enforcing filesystem refuses a surrogateescape name

- **WHEN** a member whose name carries undecodable bytes (`surrogateescape`) is extracted
  to a filesystem that enforces valid UTF-8 names
- **THEN** extraction raises a typed `ExtractionError` whose cause is the filesystem's
  `OSError` with `EILSEQ` (never a raw `OSError`), or records a failure result under
  `OnError.CONTINUE`

#### Scenario: byte-preserving filesystem extracts the same member

- **WHEN** the same member is extracted on a filesystem that accepts arbitrary name bytes
- **THEN** the member extracts successfully with its bytes preserved

### Requirement: Lone surrogates in a member name

A member name or link target can hold a surrogate without its partner (U+D800–U+DFFF):
7z names, RAR 1.5-4 UTF-16 names and Joliet names are UTF-16 code units, and NTFS allows
any unit in a name. Listing and reading keep the unit in the name under every policy, and
the rule below is the same for every format.

Under `STRICT` and `STANDARD` such a name is not portable, and the portable-name rule
(O7) SHALL escape it as it escapes undecodable bytes: each lone surrogate outside
U+DC80–U+DCFF is taken as its three UTF-8 bytes (`surrogatepass`) and each byte is
written `%XX`, so `hi\ud800` is written `hi%ED%A0%80` on every OS and
`presented_name` records the stored name. Under `TRUSTED` extraction SHALL write the
name as 7-Zip 23.01 does: on POSIX each such surrogate as its three-byte UTF-8 form
(U+D800 becomes the bytes `ed a0 80`), on Windows the exact name. That on-disk spelling
is not a rename, so `presented_name` stays unset for it. A link target is written the
`TRUSTED` way under every policy, as O7 does not rewrite link targets. Under `STRICT`
and `STANDARD` a link to a member whose name was escaped therefore points at the
unescaped spelling and dangles, as it already does for undecodable bytes; on a
filesystem that accepts only UTF-8, such as APFS, creating that link fails.

U+DC80–U+DCFF SHALL keep its `surrogateescape` meaning, one undecodable byte, for every
format: it is written as that byte, or percent-escaped by the portable-name rule. The
path checks run on the name the disk spelling gives, before the portable-name rule, and
a rejection by them names the stored member name. An error raised while writing the
member, a deferred hardlink included, names the name from before the disk spelling:
the stored name under `TRUSTED`, the escaped one under `STRICT` and `STANDARD`. Every
error names a link target as stored, never in its disk spelling. The collision key and
the overwrite policy see the spelling that reaches disk. Under every policy a lone
U+D800 and a name whose undecodable bytes are `ed a0 80` are therefore one file: both
are `hi%ED%A0%80` under `STRICT` and `STANDARD`, and both are the bytes under
`TRUSTED`. A name that cannot be encoded even so is a `FilterRejectionError`, never a
raw `UnicodeEncodeError`.

#### Scenario: lone surrogate matrix

`tests/test_sevenzip_surrogate_names.py` compares both policies with the `7z` tool;
`tests/test_utf16_surrogate_names.py` checks that RAR 1.5-4 and Joliet names extract to
the same tree.

| Case | Expected |
| --- | --- |
| `hi\ud800.txt` under `STRICT` / `STANDARD`, any OS | Written `hi%ED%A0%80.txt`; `EXTRACTED`; `presented_name == "hi\ud800.txt"` |
| `hi\ud800.txt` under `TRUSTED` on POSIX | Written as `hi` + `ed a0 80` + `.txt`, as 7-Zip writes it; `presented_name` unset |
| `hi\ud800.txt` under `TRUSTED` on Windows | Written under the exact name |
| `hi\ud800` and `hi\udced\udca0\udc80` in one archive, any policy | One file; the second goes through the `OverwritePolicy` |
| `lo\udc80.txt` | `lo%80.txt` under `STRICT` / `STANDARD`; the byte `0x80` under `TRUSTED`, where 7-Zip writes `ed b2 80` |
| `\ud800/../x` | `FilterRejectionError` whose `member_name` is `\ud800/../x` |

### Requirement: Skip non-current members by default

`extract` / `extract_all` SHALL skip members with `is_current is False` by default
(`ExtractionStatus.SUPERSEDED`; no write; no bomb-limit counting for the skip). This
is **hardwired coordinator behavior**, not the policy `filter` / `MemberFilter`
pipeline: the skip happens after the optional user `filter` runs so callers can
inspect or rewrite non-current members, then the coordinator still skips writing
them unless a future explicit opt-in lands. `SUPERSEDED` is distinct from
`ExtractionStatus.NOT_OVERWRITTEN` (an existing destination left in place under
`OverwritePolicy.SKIP`).

How surfaces interact:

| Surface | Non-current members |
| --- | --- |
| `members()` / `__iter__` / `get` | Visible (metadata + `is_current=False`) |
| `members=` selector | May select them; they still participate in the extract walk |
| User `filter` (`MemberFilter`) | **Invoked** on them (same as current members) |
| Default extract write | Skipped after filter; `SUPERSEDED` result |
| `open`/`read` on superseded `FILE` | Still allowed (payload exists); not gated by `is_current` |

There is no extract-all flag to force writing non-current revisions; callers that need those bytes use `open`/`read` (or a future opt-in).

A streaming pass learns that a member is shadowed only when the later same-name member
arrives. So does a random-access TAR extraction, which is one forward pass too
(`format-tar`); everything below about a streaming pass holds for it, except that it can
read a hardlink's source again. At that point it SHALL report the earlier member `SUPERSEDED`, before the later
member reaches the filter, and stop counting it against `max_entries` and
`max_extracted_bytes`. Its bytes stay counted while a hardlink written in between still
holds them, and the archive-wide ratio still counts its decoded bytes. What the
earlier member wrote in this run SHALL stay in place until the later member is done, so
a later member that lands at the same path replaces it atomically under any overwrite
policy; if the later member does not land there, the earlier member's entry SHALL then be
removed. If the filesystem refuses that removal, a warning is logged and the entry stays
the run's own: other names still collide with it, and the next member of the same name
may replace it. A directory that other members were written into stays, as their parent.

Results and the tree on disk then match random access, except where something that
happened before the later member arrived depended on the earlier member. A streaming pass
cannot undo that:

- A selection that excludes the later member: the pass never sees it, so the earlier
  member stays `EXTRACTED`.
- An entry of the caller's that the earlier member replaced under `REPLACE`: it is not
  restored when the later member does not land.
- A member between the two that met the earlier member's write: a different name that
  collides with it (a case variant outside `TRUSTED`), a member written under it as a
  directory, or a hardlink to it when it was not written (random access reads that
  source again; a streaming pass cannot).

#### Scenario: non-current skip matrix

| Case | Expected |
| --- | --- |
| Content superseded by later same-name or anti | `SUPERSEDED` on extract; path absent on fresh dest |
| Streaming TAR holding `a.txt` twice, default overwrite policy | `SUPERSEDED`, then `EXTRACTED`; `a.txt` holds the later bytes, as in random access |
| User `filter` receives non-current member | Filter is called; returning the member does not force a write |
| `open` superseded content `FILE` | Bytes returned (random access still works) |

### Requirement: Anti-item extraction is delete-only-if-written

For `is_anti` members, extraction SHALL NOT write payload. It SHALL delete the
destination only if this same extraction wrote that path (file or empty dir via
`lstat`/`unlink`); otherwise it is a success no-op. Pre-existing, populated, or
out-of-root paths MUST NOT be deleted. `MemberType.ANTI` SHALL NOT raise
`FilterRejectionError` (only `OTHER` does).

A delete SHALL also release the destination's collision claim, so a later member
resolving to the same key does not collide against content that no longer exists.
The claim and the on-disk entry are two records of the same fact and SHALL be
cleared together; a stale claim would otherwise abort under `AbortOn.NAME_COLLISION`
with the destination empty, or revise an already-deleted member to `OVERWRITTEN`.

#### Scenario: anti extraction matrix

| Case | Expected |
| --- | --- |
| Anti path missing / pre-existing not written this run | Success no-op; pre-existing untouched |
| Earlier member this run wrote the path, then anti | Just-created file/empty dir removed |
| Same case, then a later member with the same collision key | No collision: the delete released the claim |
| Anti no-op (nothing written this run at that path) | Unrelated claims untouched |
| `check_universal` on `ANTI` | No `FilterRejectionError` for type alone |
| `MemberType.OTHER` | Still `FilterRejectionError` under all policies |

### Requirement: Symlink Escape Re-Validated at Extraction Time

The system SHALL validate a SYMLINK member after `os.symlink(link_target,
dest_path)` creates the link on disk. It resolves the created link target through
the real filesystem and, if the resolved path escapes `dest`, immediately unlinks the
new link and raises `FilterRejectionError`. Any failure to resolve the created link
(`OSError`, such as `ELOOP` or its platform equivalent) SHALL fail safe the same way:
unlink the just-created link and reject the member. A symlink loop SHALL be detected
on every supported Python version.

This post-creation check SHALL catch chained symlink attacks where earlier archive
members influence later target resolution, without allowing writes through an
escaping link.

A *later* member can change what an earlier link resolves to (`l -> a/../x`, then
`a -> .`). The system SHALL record which destination paths each created link's
resolution depended on and, before the next member is handled, recheck every link
whose dependency a member created as a symlink, or removed or replaced as a symlink or
directory. A link that now escapes SHALL be unlinked and its result revised in place to
`BLOCKED` with a `FilterRejectionError`. A `..` target that stays inside `dest` SHALL
NOT be refused. Rechecks count against `max_entries`; once it is spent, the links still
waiting are removed unresolved and the run stops with `ResourceLimitError`. Tests:
`tests/test_symlink_recheck.py`; rationale: `dev-docs/threat-model.md` O22.

#### Scenario: symlink revalidation matrix

| Case | Expected |
| --- | --- |
| Created symlink resolves outside `dest` | Link is unlinked; `FilterRejectionError`; no later data written through it |
| Chained symlink attack through earlier member | Post-creation resolution catches the escape and raises `FilterRejectionError` |
| Cyclic links (`d -> d`; `a -> b`, `b -> a`; longer loops) | The link that closes the loop is unlinked; `FilterRejectionError` with the message "Symlink target is part of a symlink loop", not the escape message; no uncaught OS/runtime error; same on every Python version |

### Requirement: Hardlink Two-Pass Extraction

The system SHALL support TAR-style hardlinks through the extraction coordinator as
a pull-based sink over reader streams. Ordinary FILE/DIR/SYMLINK members are
written as reached; each written FILE path is recorded under its source. A
HARDLINK whose source already has recorded paths tries `os.link()` against them,
newest first. If all fail with cross-device `EXDEV`, or one fails with `EMLINK` at the
filesystem's link-count limit, the coordinator falls back to a copy and records the copy
for later links. The search stops at the first path at the limit, so the cost of a link
does not grow with the number of links before it.

When a selected HARDLINK's source was excluded by `members` or `filter`, the
system MUST NOT materialize the excluded source at its own destination. It SHALL
make the source content available only through selected link destinations: write
the bytes to the first selected link path allowed by `OverwritePolicy`, record
`NOT_OVERWRITTEN` links under `SKIP`, link further selected links to the
materialized path, and write nothing if no selected link takes the bytes (each is
skipped or fails on its own, as below). The
materialized file gets the selected link's transformed metadata. An equivalent
hidden temp inside `dest` is permitted.

Two kinds of failure are the source's: the refusal of the source's recorded size
under the per-member ratio limit, which every link would meet, and any failure once
the copy of the source's bytes into the link's temp file begins (reading or decoding
the source, a bomb limit, writing or placing the file). The bytes cannot then be
offered to another link, so that link and every later one fail as one group; links
before it keep their own results. Every other failure is the link's own: a destination
that `ERROR` refuses, one that `REPLACE` cannot remove (a directory with entries), or a
directory that refuses the temp file fails that link alone, governed by `OnError`, and
under `CONTINUE` the content moves to the next selected link.

Recovering orphaned links SHALL take at most one extra pass and no speculative upfront
scan to find them: a seekable source gets one conditional second pass after the main
pass, and a forward-only source makes the orphaned link unrecoverable and therefore a
per-member failure governed by `OnError`. When a free member list exists
(`members_report_if_available()`), the coordinator MAY plan recovery into the first
pass instead, as `format-tar` describes; archivey does not, so recovering an orphan in
a solid archive decodes the solid stream a second time. A hardlink that merely precedes
its selected source is linked after the source is written, with one read and one
bomb-limit count for the source bytes.

**A HARDLINK's target SHALL name an earlier member, and the member the link gets its
bytes from SHALL NOT have been refused** (maintainer decision, 2026-10-07). That is the
whole rule for the target: the target string is a member name, never a path, so it
gets no path check (no containment join, no drive, UNC or rooted-`\` refusal, no NUL or
encoding check), and the link is made to the file its source was written to. A caller
filter that changes a HARDLINK's `link_target` changes nothing; the link follows the
stored name. A link whose source was refused SHALL be refused with
`FilterRejectionError` ("Hardlink target was refused"), so `BLOCKED`, in both access
modes, at every policy and on every OS: otherwise the second pass would write the
refused member's bytes under the link's name.

Which member counts is the source, `link_target_member`: the end of the link chain, the
member the link is made to or whose bytes the second pass reads. A link in the middle of
the chain that was refused for its own name does not refuse the links after it, since
they do not use that name: `h2` → `../h1` → `a` links to `a` when `a` was written. A
refused source refuses every link whose chain ends at it, whatever the names in between.
A HARDLINK whose chain ends at a SYMLINK is written as that symlink (a second name for
it, as GNU tar makes) and copies no bytes, so it gets the SYMLINK checks on its own name
and the symlink's target instead of this rule. A symlink with no target (a TAR symlink
with an empty `linkname`) cannot be written that way, and copies no bytes either: the
link fails, whether or not the symlink was refused for its own name. Only TAR, RAR5 and
a directory list hard links, and all three carry a symlink's target in the header or the
filesystem, so `read_link_targets` does not change these outcomes. When the run recorded
a result for the source, the result decides: `BLOCKED` is a refusal, anything else is
not, after the caller's filter. A filter that renames the source to an unsafe name
therefore refuses its links as well, and one that renames an unsafe source to a safe one
lets them through. A source the `members` selector or the `filter` excluded has no
result; for it the policy's own steps (the absolute-name re-root, the universal checks
and the name policy) run on the source as listed, without the filter. A refused one
refuses its links; any other is recovered as above.

#### Scenario: hardlink matrix

| Case | Expected |
| --- | --- |
| HARDLINK reached after its source was extracted | Try `os.link()` against recorded source paths; fallback to copy on all-`EXDEV` or all-`EMLINK` |
| Selected hardlink source was excluded but recoverable | Source content appears at selected link path(s); excluded source path is never created |
| First selected link destination exists under `OverwritePolicy.SKIP` | That link result is `NOT_OVERWRITTEN`; content moves to the next allowed link; all skipped means no write |
| First selected link destination refused under `OverwritePolicy.ERROR`, or a directory with entries under `REPLACE`, with `OnError.CONTINUE` | That link alone is `FAILED`, with no failure group; content moves to the next allowed link |
| Every selected link destination refused under `OverwritePolicy.ERROR`, with `OnError.CONTINUE` | Each link is `FAILED` on its own, with no failure group; nothing is written |
| The directory of the first selected link refuses the temp file, with `OnError.CONTINUE` | That link alone is `FAILED`, with no failure group; content moves to the next allowed link |
| Reading the excluded source fails while writing it at a later link, an earlier link skipped | The skipped link stays `NOT_OVERWRITTEN`; that link and the ones after it are `FAILED` as one failure group |
| Excluded source on a forward-only stream | Per-member failure: `STOP` raises; `CONTINUE` records `FAILED` and proceeds |
| HARDLINK appears before its also-selected source | After the pass it links to the extracted source inode; source bytes read and counted once |
| HARDLINK whose resolved source is not a FILE (e.g. a DIRECTORY member) | Per-member `ExtractionError` naming the source's type (for a directory: a hard link to one cannot be created); the source itself still extracts |
| HARDLINK to a member refused by the policy (`../x` at any policy, `/x` under `STRICT`), selected or excluded, either mode | `BLOCKED` with `FilterRejectionError` ("Hardlink target was refused"); nothing written for the link |
| HARDLINK `h` → `m` → `../x`: a safe middle name, a refused source, selected or excluded | `h` (and `m`, when selected) `BLOCKED` ("Hardlink target was refused") |
| HARDLINK `h2` → `../h1` → `a`, `a` extracted | `../h1` `BLOCKED` for its own name; `h2` linked to `a` |
| HARDLINK `hl` → SYMLINK `/s` → `t`, `STRICT` | `/s` `BLOCKED` for its own name; `hl` written as a symlink to `t` |
| HARDLINK `hl` → SYMLINK with no target (`/s` under `STRICT`, or `s`) | `hl` `FAILED`, not refused for `/s`'s name: `ExtractionError` naming the source's type when the listing was read first, else `LinkTargetNotFoundError` |
| HARDLINK whose target names no earlier member (`../x`, `C:x`, `/abs` with no such member) | `LinkTargetNotFoundError`, a failure; the target string is never refused as a path |
| Caller filter rewrites a HARDLINK's `link_target` | Ignored; the link is made to the member the stored target names |
| `REPLACE` routes a HARDLINK onto a path that holds its own source's content: `a`, then `A` → `a` under `STRICT`/`STANDARD`, either mode; or, in the seekable second pass, two links `L`, `l` whose source was excluded | The earlier member `OVERWRITTEN`, the link `EXTRACTED` at that path; the file is left as it is, content intact. On a forward-only stream the `L`, `l` links fail as the "Excluded source on a forward-only stream" row says |

### Requirement: Policy-Specific Metadata Transforms

The system SHALL apply policy-specific permission and ownership transforms to one
transient `ArchiveMember` copy before the universal checks and I/O. The
copy receives the policy transform, the absolute-name re-root (`STANDARD` /
`TRUSTED`) and the user `filter` in that order and supplies
the on-disk identity (`name`, mode, timestamps, destination path). The original
mutable member is used for `BombTracker.start_member()` and recorded in
`ExtractionResult`, so late-bound size/CRC/source metadata remain accurate.

```python
class ExtractionPolicy(Enum):
    STRICT = "strict"
    STANDARD = "standard"
    TRUSTED = "trusted"
```

Policies SHALL parallel Python `tarfile`'s `data` / `tar` / `fully_trusted`
mental model while applying uniformly to all formats and retaining Archivey's
non-bypassable safety checks.

| Behavior | `STRICT` default | `STANDARD` | `TRUSTED` |
| --- | --- | --- | --- |
| Path, absolute-path, link-escape, special-file rejection | Always | Always | Always |
| Missing file/dir mode | File `0o644`, dir `0o755` | File `0o644`, dir `0o755` | Apply as stored |
| Permission normalization | Files masked with `0o755` (execute kept when the owner has it; without owner execute, group/other execute are cleared too; group/other write stripped); dirs `0o755` | Preserve ordinary execute bits | Apply as stored |
| setuid/setgid/sticky | Strip all | Strip all | Preserve |
| uid/gid/uname/gname on the transformed member (what a `filter` sees) | Cleared to `None` | Kept as stored | Kept as stored |
| Ownership applied on disk (`chown`) | Never | Never | Only when running as root; otherwise skipped silently |

A DIRECTORY member's ownership, mode and times SHALL be applied after the last member of
the run is written, and not when the directory is created, in the same way in streaming
and random-access mode. Directories SHALL be done deepest first, so a parent's mode never
stops the run from reaching a directory inside it. This SHALL also happen when the run
stops early (`OnError.STOP`, an `abort_on` trigger, a limit), for the directories written
before it stopped. A directory is changed only when the entry at its path is still the
directory the member wrote: a symlink, or another entry, that a later member put there
SHALL NOT be changed, and the change SHALL NOT follow a symlink. A directory that a
member reaches through a directory symlink the archive created SHALL be taken by where it
physically is, with its parents resolved: that place sets its depth, and the change
reaches it from the root through that place only. Where several members reach one
directory, the one written last SHALL be applied last. A later member that removes the
directory SHALL drop its pending metadata under any spelling that reaches it, under
every policy: through such a symlink, or a case variant on a case-insensitive
filesystem. GNU tar, bsdtar and Python's `tarfile` order these changes the same way.
With the mode applied at once, a stored mode without owner write or search permission
refused every member inside the directory to a non-root user, and each member written
inside changed the directory's modification time. One consequence, which GNU tar shares:
under `TRUSTED`, the only policy that keeps setgid, a setgid directory gets the bit only
after its members are written, so a non-root run does not give them the directory's
group.

#### Scenario: metadata policy matrix

| Case | Expected |
| --- | --- |
| FILE `mode=0o755` under `STRICT` | Written as `0o755` |
| FILE `mode=0o777` or `0o4755` under `STRICT` | Written as `0o755` |
| FILE `mode=0o660` under `STRICT` | Written as `0o640`: a bit the file did not store is never added |
| FILE `mode=0o011` or `0o655` under `STRICT` | Written as `0o000` / `0o644`: without the owner execute bit, group and other execute are cleared too, as `tarfile`'s `data` filter does |
| FILE `mode=0o755` under `STANDARD` | Execute bits preserved; setuid/setgid/sticky stripped |
| FILE with uid/gid under `TRUSTED` as root | uid/gid applied |
| FILE with uid/gid under `STANDARD` | A `filter` sees the stored uid/gid; nothing is chowned |
| Any policy, unsafe path/link/special file | Universal safety rejection still applies |
| DIRECTORY `d/` stored `0o555` or `0o644` under `STANDARD`, then `d/f`, non-root user | `d/f` `EXTRACTED`; `d` ends with the stored mode |
| DIRECTORY `d/` with a stored mtime, then `d/f` | `d` ends with the stored mtime |
| DIRECTORY `d/`, then `d/f`, then a member that stops the run | `d` ends with its stored mode and mtime |
| DIRECTORY `d/` replaced under `REPLACE` by a symlink `d -> t` | `t` keeps its own mode and mtime |
| `s -> .`, DIRECTORY `s/d/` `0o700`, then `REPLACE` removes `d` for a refused symlink `d -> d`, then `d/x` | `d` is a plain parent: it does not get `0o700` or the stored mtime |
| DIRECTORY `t/`, DIRECTORY `a/b/c/` `0o000`, `a/b/c/s -> ../../../t`, DIRECTORY `a/b/c/s/u/` `0o750`, non-root user | `t/u` ends with `0o750` and its stored mtime |
| `s -> .`, FILE `s/d/f`, then DIRECTORY `d/` `0o700` | `d` ends with `0o700` and the stored mtime; `kept_mode` is `None` |
| `s -> .`, DIRECTORY `d/` `0o700`, then DIRECTORY `s/d/` `0o750` | `d` ends with `0o750`, the member written last |

### Requirement: Overwrite Policy

The system SHALL enforce `OverwritePolicy` whenever a destination entry already
exists at the transformed member path:

```python
class OverwritePolicy(Enum):
    ERROR = "error"
    SKIP = "skip"
    REPLACE = "replace"
    RENAME = "rename"
```

`ERROR` raises a per-member `ExtractionError` governed by `OnError`; `SKIP`
records a `NOT_OVERWRITTEN` result and is not a failure. Existence checks SHALL use
`lstat` semantics so dangling symlinks count as existing entries. `REPLACE` SHALL
be atomic wherever the platform permits, and SHALL never write through a symlink.

FILE and HARDLINK replacement SHALL be atomic: the new entry is built beside the
destination (a temp file for FILE data, a temp link for HARDLINK), metadata is
applied to it, and `os.replace()` moves it onto the destination. A failure part-way
through preserves the existing entry and discards only the temp. `os.replace()`
moves the entry itself, so a destination symlink is replaced rather than followed.

SYMLINK and DIRECTORY replacement SHALL remove the existing entry and create fresh,
because neither can be staged: a symlink MUST be created at its final name for the
escape re-validation's cycle check to resolve, and a directory cannot be renamed
over a non-directory at all. `RENAME` is the exception for a DIRECTORY member: when its
destination holds a file or a symlink (a symlink to a directory included, as it is never
written through), that entry SHALL NOT be removed, and the directory SHALL be written
under a derived name (see the cross-platform name-safety requirement). Every later member
whose destination lies inside the directory's requested path SHALL follow it: `dd/f` is
written at `dd (1)/f`, and reports `requested_path` `dd/f` and `path` `dd (1)/f`. A later
DIRECTORY member with the directory's own name merges into `dd (1)/`, as directories
merge. A non-directory member with that name is not inside the directory: it resolves its
own collision from the name it asked for (`dd (2)`, not `dd (1) (1)`).

A member also implies a directory for each parent of its destination, whether or not the
archive lists a directory entry for it. Where such a parent holds an entry that was there
before the run and is not a directory (a file, a dangling symlink, or a symlink to a
non-directory), that parent SHALL meet `OverwritePolicy` as an explicit DIRECTORY entry
at that path would, and the member SHALL get the outcome that entry would get: `ERROR`
fails the member with an `ExtractionError` naming the parent ("Destination already
exists"), governed by `OnError`; `SKIP` records `NOT_OVERWRITTEN` and leaves the entry;
`REPLACE` removes the entry and writes the member under a new directory there; `RENAME`
leaves the entry and writes the member under a derived name for the parent (`foo/x` at
`foo (1)/x`, `requested_path` `foo/x`), which later members inside it follow as above.
The entry already there SHALL NOT cause a raw `OSError` to leave the library; a
filesystem failure creating the parent (no space, no permission) still propagates as an
`OSError`, recorded as `FAILED` under `OnError.CONTINUE`. The same applies to the
members inside an explicit DIRECTORY entry that `ERROR` or `SKIP` left out. The entry is
not a collision event, so `collided_with` stays `None`. A symlink of the caller's that
resolves to a directory is a directory here and is followed, subject to the parent
resolution check. A parent that is a non-directory this run wrote is not covered: the
member fails as the `OnError` matrix states.

Replacing an existing directory with any member type removes the directory first, and
only an **empty** one: a directory that holds entries SHALL NOT be removed, and the
replacing member SHALL fail with an `ExtractionError` governed by `OnError` (as GNU tar
does without `--recursive-unlink`). Removing a tree would take the members this run wrote
into it, which would still report `EXTRACTED`, and the caller's own files when the
directory was already there. When a member of this run wrote the removed directory, under
any spelling that reaches it (through a directory symlink the archive created, under every
policy, or a case variant on a case-insensitive filesystem, under `STRICT` and `STANDARD`),
that member's result SHALL be revised to `OVERWRITTEN`. Under `TRUSTED` the coordinator keys
on the exact path and defers to the local OS (see the O2 collision requirement), so a case
variant there is not recognized and the earlier result is not revised. Outside
`TRUSTED`, the replacing member collided with that directory (see the O2 collision
requirement), so its `collided_with` names it and `AbortOn.NAME_COLLISION` fires before
the directory is removed. Under `TRUSTED` there is no collision event: `collided_with`
stays `None` and the abort does not fire, while the earlier result is still revised when
the replacing member spells the directory's path exactly.

A DIRECTORY member whose destination is a directory that was there before the run (the
destination root, for a `./` member, when the call did not create it, or any directory
this run neither wrote nor created as a parent) SHALL leave that directory's mode,
ownership and times unchanged. When the member's effective mode differs from the
directory's, the result SHALL carry the mode the directory kept in
`ExtractionResult.kept_mode`; otherwise `kept_mode` is `None`, and the times were still
left alone. On Windows a mode sets only the read-only attribute, so the member's mode is
compared as Windows would store it (`0o777`, or `0o555` without owner write): a `0o755`
member over a writable directory reports no `kept_mode`. A directory this run wrote or
created is recognized under any spelling that reaches it, under every policy: through a
directory symlink the archive created, and a case variant on a case-insensitive
filesystem. A case variant on a filesystem that reports inode 0 for every entry cannot be
told from another directory, and is taken for one that was there before the run.

A HARDLINK is made against the path its source member was written to only while that
path still holds the source's content. Once a later member replaces that path, the path
SHALL no longer serve as the source: a re-readable source is re-read by the second pass,
as an excluded one is, and a forward-only one fails the link. A source path that is not
a regular file when the link is made (a symlink put there) SHALL NOT be linked.

A HARDLINK whose target member is a SYMLINK, directly or through other hard links, SHALL
be written as a symlink with that member's target, read from the hardlink's own
directory, and checked like any symlink: it is a second name for the symlink, as GNU tar
creates it. When that member has no target, the HARDLINK SHALL fail instead, and SHALL
NOT be refused because the symlink was. The caller's filter SHALL see the HARDLINK as
listed, and the member on its `ExtractionResult` stays that HARDLINK; only what is
written is a symlink.

A HARDLINK SHALL resolve only to a member listed before it, in every format and in both
modes: a link whose only target comes later fails in random access as in a streaming
pass. This matches the format's own tool: `tar(1)` and `unrar` link to what they have
already written, and `unrar` refuses a link whose target comes later. ZIP, 7z and ISO
store no hard-link record (7-Zip writes two full copies to a `.7z`), so their readers
list no HARDLINK.

Where `REPLACE` removes an existing entry that a **member of this same run** wrote,
and the replacing write then fails, that earlier member's content is gone. Its
`ExtractionResult` SHALL be revised to `ExtractionStatus.OVERWRITTEN` even though no
member ended up holding the destination — a result SHALL NOT report `EXTRACTED` for
content that no longer exists.

`RENAME` writes a colliding entry under a deterministic derived name (`name (1)`,
inserted before the final suffix) rather than overwriting — see the cross-platform
name-safety requirement.

#### Scenario: overwrite matrix

| Case | Expected |
| --- | --- |
| Existing path under `ERROR` | `ExtractionError`; existing entry unmodified |
| Existing path under `SKIP` | `ExtractionResult.status == NOT_OVERWRITTEN`, `path=None`, no exception |
| Symlink for which the archive records no target | `ExtractionResult.status == LINK_TARGET_UNAVAILABLE`, `path=None`, no exception, under either `OnError` |
| Existing file under `REPLACE` | Fresh file is written via temp file + `os.replace()` |
| Existing entry replaced by a HARDLINK under `REPLACE` | Link is built at a temp sibling and `os.replace()`d in; a failure leaves the existing entry intact |
| Existing symlink under `REPLACE` | Symlink entry itself is replaced; bytes never follow the old link |
| `REPLACE` fails mid-stream | Existing file remains unchanged; temp is discarded |
| `REPLACE` clears a this-run destination and then fails | The earlier member is revised to `OVERWRITTEN`; no result claims `EXTRACTED` at the emptied path |
| `REPLACE` removes an empty directory this run wrote | The directory member is revised to `OVERWRITTEN`; outside `TRUSTED` the replacing member's `collided_with` names the directory, and under `TRUSTED` it is `None` |
| Dangling symlink under `ERROR` or `SKIP` | Treated as existing; no write-through to target |
| `foo/x` with no `foo/` entry, the caller's file at `foo`, under `ERROR` | `foo/x` `FAILED` with `ExtractionError` ("Destination already exists"); the file is kept |
| The same under `SKIP` | `foo/x` `NOT_OVERWRITTEN`; the file is kept |
| The same under `REPLACE` | The file is removed; `foo/x` `EXTRACTED` under a new directory `foo/` |
| The same under `RENAME` | The file is kept; `foo/x` `EXTRACTED` at `foo (1)/x`, and later members under `foo/` follow it there |

### Requirement: Extraction as a Composable Module

The system SHALL implement safe extraction in a dedicated coordinator module
separate from reader backends and format detection. `ArchiveReader.extract_all()`
delegates to `ExtractionCoordinator`, which drives one unified forward pass over
`(member, stream)` pairs in streaming and random-access modes.

The coordinator SHALL own member selection, transient metadata transforms, user
filter application, `BombTracker` calls, progress callbacks, result accumulation,
and extraction diagnostics. Reader generators yield original mutable members so
backend late-bound updates remain visible; copy-producing transforms/filters do
not detach streamed members from backend updates.

#### Scenario: coordinator matrix

| Case | Expected |
| --- | --- |
| `extract_all()` in random-access mode | Uses `ExtractionCoordinator.run()` forward pass |
| `extract_all()` in streaming mode | Uses the same coordinator pass and consumes the streaming pass per `access-mode-and-cost` |
| Backend fills late-bound fields while streaming | Original member in `ExtractionResult` and `BombTracker` sees the final source metadata |

### Requirement: Enforce Cumulative Max-Extracted-Bytes Limit

The system SHALL track total bytes written across a single
`extract_all()` call and raise `ResourceLimitError` at the chunk boundary where
the total exceeds `max_extracted_bytes`. The default is 2 GiB
(2,147,483,648 bytes). Callers override it through `ExtractionLimits`; `None` via
`ExtractionLimits.UNLIMITED` disables this guard.

The limit SHALL be tracked by one `BombTracker` per extraction call. It is a
global resource guard: when it trips, extraction halts and no later members are
processed regardless of `OnError`.

Bytes a hard link writes as a copy (across a device boundary, or past the filesystem's
link-count limit) SHALL count toward the limit. A declared link count can drive real
writes, one copy per limit's worth of links, so the bytes copied past the link-count
limit SHALL also count toward the archive-wide `max_ratio` guard: a small archive must
not write far more than its size by declaring many links to one member. A cross-device
copy SHALL NOT count toward either ratio, because it depends on where the caller extracts
to, not on the archive, and neither copy counts toward the per-member ratio.

A copy that a streaming pass takes back as superseded SHALL stop counting toward the
limit once no entry on disk holds its bytes ("Skip non-current members by default"). The
written-byte total that progress reports still includes it.

#### Scenario: cumulative byte limit matrix

| Case | Expected |
| --- | --- |
| Running written-byte total crosses `max_extracted_bytes` | Immediate `ResourceLimitError`; extraction halts |
| `ExtractionLimits(max_extracted_bytes=10 * 2**30)` | Enforced cumulative limit is 10 GiB |
| `ExtractionLimits.UNLIMITED` | Cumulative byte guard is disabled |

### Requirement: Enforce Per-ArchiveMember Max Decompression Ratio

The system SHALL raise `ResourceLimitError` when a single member's output exceeds
`max_ratio * member.compressed_size` after that member's output crosses
`ratio_activation_threshold`. Defaults are `max_ratio=1000.0` and threshold
5 MiB. The ratio is per-member output, not cumulative output, and is checked only
when `member.compressed_size` is known and greater than zero. The original member
is used so late-bound compressed-size metadata remains accurate.

This guard SHALL be independent of cumulative bytes and archive-wide ratio
guards. A ratio violation for one member is member-scoped and may be continued
under `OnError.CONTINUE`; global guards remain always-stop.

#### Scenario: per-member ratio matrix

| Case | Expected |
| --- | --- |
| Member output exceeds ratio after threshold | `ResourceLimitError` while processing that member |
| Tiny highly-compressible member stays below threshold | No ratio error; threshold prevents false positive |
| `compressed_size is None` or `0` | Per-member ratio skipped; cumulative/global guards still apply |
| `ExtractionLimits(max_ratio=100)` | Members over 100:1 trip this guard |

### Requirement: A recorded size decides the per-member ratio before decoding

A member stream never yields more than the member's recorded `size` (a byte past it
is `CorruptionError`), so a recorded size bounds the member's output. When a FILE
member is about to be decoded (`BombTracker.check_recorded_size()`, called at the
start of every FILE write, after the selector, the filter, the policy checks and the
overwrite policy have accepted it), the system SHALL refuse it with the per-member
`ResourceLimitError` when its `size` exceeds both `ratio_activation_threshold` and
`max_ratio * compressed_size` (only when both are known and `compressed_size` is
greater than zero). The refusal is member-scoped, as the measured per-member check's
is, and the member has no temp file and adds no bytes to any counter. When the orphan pass
writes an excluded hard-link source's content at a link's path, the source's sizes are
the ones checked.

For a member that delivers its whole recorded `size`, this is the verdict the measured
check would reach after decoding past the threshold. A member whose data stops short
of its recorded `size` is refused here as over the ratio, where the measured check
might not trip and the read would fail as damaged instead; either way only that member
fails.

The archive-wide ratios SHALL NOT be checked from recorded sizes. A recorded size is
unverified until the member is decoded, and refusing the archive-wide (always-stop)
ratio on it would stop the run on one damaged member and lose the intact members after
it. The measured archive-wide checks stop at the chunk that crosses the limit, so an
earlier check would save little. Members without a recorded `size` or
`compressed_size` are left to the measured checks, which still run on every chunk.

#### Scenario: recorded-size ratio matrix

| Case | Expected |
| --- | --- |
| Member whose recorded sizes are over the per-member ratio after the threshold | Per-member `ResourceLimitError` before any byte of it is written; under `OnError.CONTINUE` the rest are extracted |
| Member whose recorded sizes overstate its data | Only that member fails, whichever error names it |

### Requirement: Bomb Protection Scope Limited to Extraction Paths

The system SHALL apply `ExtractionLimits` bomb guards only during
`ArchiveReader.extract_all()`. `ArchiveReader.read()`
and `ArchiveReader.open()` return decompressed data/streams without byte, ratio,
or entry-count enforcement; callers are responsible for guarding direct reads.
Listing materialization caps are separate (`ListingLimits` in `archive-reading`)
and do not apply to `read()` / `open()` either.

#### Scenario: bomb-scope matrix

| Case | Expected |
| --- | --- |
| `reader.read(member)` on extreme-ratio data | Raw decompressed bytes returned or normal read error; no extraction bomb guard |
| `reader.open(member)` | Stream delivers decompressed data without extraction limits |
| `reader.members()` on a metadata bomb | `ListingLimits` / `ResourceLimitError` per `archive-reading`, not `ExtractionLimits` |

### Requirement: Progress Reporting via on_progress Callback

The system SHALL accept optional `on_progress` callbacks on both extraction APIs
and report progress with `ExtractionProgress`:

```python
@dataclass
class ExtractionProgress:
    member: ArchiveMember
    bytes_written: int
    total_bytes_estimated: int | None
    members_done: int
    members_total: int | None
    member_bytes_written: int
    members_extracted: int
    members_blocked: int
```

`bytes_written` is cumulative for the operation. `member_bytes_written` is the
output bytes written for the **current** member so far. `total_bytes_estimated`
is `None` when the format lacks uncompressed size information; `members_total` is
`None` when the attempted member count cannot be known without a scan. When a
free member list exists and a `members` selector is provided, totals SHALL cover
only selected members. `members_done` counts every selected member processed,
including user-filter skips and failures, so it reaches `members_total`;
selector-excluded members are invisible. `members_extracted` / `members_blocked`
are completed-outcome tallies of `EXTRACTED` / `BLOCKED` results so far (on
intra-member reports they exclude the in-flight member); other statuses advance
`members_done` without incrementing either. Predicate selectors evaluated against
an upfront index MUST be pure functions of the member.

For a ZIP read from a non-seekable source ("A ZIP extracted from a non-seekable source
is settled at the end of the pass"), a member's reports SHALL be made while its data is
staged, its intra-member reports and terminal report together, so `members_done` counts
the members staged and can count one that is then not placed. `members_extracted` and
`members_blocked` count placed outcomes: they stay 0 during the pass, and placement
SHALL make one more report when it ends, naming the last member it handled, with the
final tallies.

For a FILE member with a streamed body, the callback MAY be invoked **more than
once** as bytes are written: intra-member reports carry `member` = the current
member, `members_done` = the number of members fully completed *before* this one,
and a non-decreasing `member_bytes_written` that has not yet reached the member's
size. Each processed member SHALL additionally produce a terminal report in which
`member_bytes_written` equals the member's `size` (or, when `size` is unknown,
the final observed byte count), so a consumer can always complete a per-member
progress bar. Members without a streamed body (directories, symlinks, hardlinks)
SHALL produce a single report with `member_bytes_written == 0`. The reporting
frequency is bounded by the extraction copy chunk size; when `on_progress` is
`None`, no additional per-chunk work is performed beyond existing byte counting.

#### Scenario: progress matrix

| Case | Expected |
| --- | --- |
| `extract_all(..., on_progress=cb)` | `cb` called with cumulative bytes, per-member bytes, and counters |
| Large FILE member streamed | `cb` invoked multiple times with non-decreasing `member_bytes_written`, ending at the member `size` |
| FILE member smaller than one copy chunk | `cb` invoked once with `member_bytes_written == size` |
| Directory / symlink / hardlink member | Single report with `member_bytes_written == 0` |
| Member with unknown `size` (late-bound / streaming) | `member_bytes_written` still reported; terminal report equals final observed byte count |
| Format cannot provide uncompressed sizes | `total_bytes_estimated is None` |
| Free list + selector | Totals cover selected members only; filter skips/failures still advance `members_done` |
| Terminal report after `EXTRACTED` / `BLOCKED` | `members_extracted` / `members_blocked` match completed outcome tallies |
| `on_progress is None` | No callback; no extra per-chunk work beyond byte counting |
| ZIP from a pipe, three members, the directory drops the second | Each member's reports made in order while staged; one more report after placement with the final tallies |

### Requirement: Per-ArchiveMember ExtractionResult with Status

`ExtractionReport.results` SHALL contain one `ExtractionResult` for every
selected member the coordinator processes when the operation completes, including
members blocked by universal/policy checks. Selector
exclusions are outside the operation and have no result; a user `filter` that
returns `None` likewise drops the member with **no** `ExtractionResult` (it is a
caller-elected exclusion, not an extraction outcome).

```python
@dataclass(frozen=True)
class ExtractionResult:
    member: ArchiveMember
    path: Path | None
    status: ExtractionStatus
    error: ArchiveyError | OSError | None = None
    requested_path: Path | None = None
    presented_name: str | None = None
    rewrites: frozenset[NameRewrite] = frozenset()
    failure_group_id: str | None = None
    failure_group_size: int | None = None
    collided_with: Path | None = None

class ExtractionStatus(StrEnum):
    EXTRACTED = "extracted"
    NOT_OVERWRITTEN = "not_overwritten"
    SUPERSEDED = "superseded"
    OVERWRITTEN = "overwritten"
    BLOCKED = "blocked"
    FAILED = "failed"
    LINK_TARGET_UNAVAILABLE = "link_target_unavailable"

class NameRewrite(StrEnum):
    REROOTED = "rerooted"
    PORTABLE_NAME = "portable_name"
```

`ExtractionReport.results` SHALL be the **sole authoritative record** of per-member
extraction outcomes. No per-member extraction fact SHALL additionally be reported
through the diagnostics channel.

Statuses SHALL mean: `EXTRACTED` created an entry (`path` set, `error=None`);
`NOT_OVERWRITTEN` left an existing destination in place because
`OverwritePolicy.SKIP` found one (`path=None`, `error=None`); `SUPERSEDED` is a
non-current duplicate skipped by the hardwired last-entry-wins rule (`path=None`,
`error=None`); `OVERWRITTEN` was written and then had its destination replaced by a
later member under `OverwritePolicy.REPLACE` (`path=None`, `error=None`);
`BLOCKED` is a continued `FilterRejectionError` (a universal path-safety check or a
policy filter blocked the member); `FAILED` is a continued non-rejection per-member
`ArchiveyError` or permitted filesystem `OSError`; `LINK_TARGET_UNAVAILABLE` is a member the archive
describes but does not carry enough information to write — a symlink for which it
records no target at all (`path=None`, `error=None`, `requested_path` set). `NOT_OVERWRITTEN`,
`SUPERSEDED`, `OVERWRITTEN` and `LINK_TARGET_UNAVAILABLE` are not failures.

A symlink for which **the archive records no target** SHALL be recorded
`LINK_TARGET_UNAVAILABLE` rather than raised as a per-member failure, under either `OnError`
value, and SHALL NOT disturb an existing destination: the check happens before overwrite resolution, so `OverwritePolicy.REPLACE`
does not unlink an entry for a member that is not going to be written. The archive's
omission is reported through the diagnostics channel
(`SYMLINK_TARGET_UNAVAILABLE`, an archive-integrity code), which is where an anomaly in
the archive's own metadata belongs; the extraction result records only what extraction
did about it. This is not confined to one cause: a writer that discarded the target
(7-Zip records none for a directory reparse point), a reparse buffer that names nothing,
a member carrying no data at all and a stored target that is the empty string leave
extraction with the same nothing to write. No filesystem accepts an empty link target, so
the reader SHALL list such a link with `link_target=None` and report it as it reports the
other causes, rather than presenting `""`.

What the archive records is the condition, not whether this read produced a target.
An unset `link_target` has two other causes, and in both the archive carries a target
this read could not produce: **not resolved yet** — a ZIP, 7z or RAR 4 link carries its
target in the member's data, which a streaming pass under `read_link_targets=False`, or
a RAR pass, has already passed when it reads the target — and
**resolved but out of reach**, where the reader looked and the bytes were compressed,
split across volumes or encrypted. Recording either `LINK_TARGET_UNAVAILABLE` would
report success while dropping a member the archive describes in full, so both SHALL
stay a per-member failure. The reader SHALL therefore report which of the two an empty
lookup was, rather than leaving extraction to infer it from the lookup having run.

"Not resolved yet" is about the target's *bytes*, so it SHALL NOT be reached for a
member whose absent target the header already states. Where a reader can tell from
metadata alone that the archive records no target — a reparse point a writer stored no
data for is the case that exists — it SHALL settle that while typing the member, not in
a lookup that reads data. Otherwise the two paragraphs above disagree in a streaming
pass whose lookup runs late (at EOF, or only when extraction reads the link): the
member the first one names would take the second one's per-member failure, and the
library default would abort the archive on exactly the entry this outcome was added
for.

That is also the bound on the read modes. `LINK_TARGET_UNAVAILABLE` holds in a
streaming pass exactly for the members a reader settles from metadata; where the
archive's omission is legible only in the member's *data* — a reparse buffer that names
nothing, bytes that are not a link buffer at all, a RAR3/4 link carrying none — a
streaming pass that reads targets late (a RAR pass, or any pass under
`read_link_targets=False`) does not learn it until the member has already been written
or not. Those SHALL take the per-member failure that an unresolved target
takes, and the library default aborts the archive there. Settling them in a streaming
pass would mean holding a reparse point's data until the member is written, which is a
different guarantee and is not required here. ZIP and 7z passes do learn it at the
member: under `read_link_targets=True` each reads a reparse-flagged member's data as it reaches
it, so a member whose bytes are not a link buffer is a file by the time extraction sees
it, and is written as one. A directory-shaped entry is the exception: it stays a link
with no target (`archive-reading`, "Link targets stored as member data are read only
when configured").

`requested_path` carries the destination the coordinator intended before
overwrite/rename resolution; it equals `path` for an ordinary write, and
`requested_path != path and status == EXTRACTED` marks a member that
`OverwritePolicy.RENAME` moved (see the cross-platform name-safety requirement): either
the member was renamed itself, or it lies inside a DIRECTORY member that was, and kept
its path relative to that directory. An anti-item inside a renamed directory reports the
same pair. Its `path` is where it deleted, not a rename. On an `OVERWRITTEN` result it
retains the destination the member did write to, so a caller can join it to the
replacing member's `path`.

`presented_name` SHALL carry the member's full relative name **before** a safety
rewrite, and SHALL be `None` when no safety rewrite reached disk. The safety rewrites
are the portable-name rewrite and the absolute-name re-root. After a re-root it is the
stored name, even if a portable rewrite followed. A re-root the caller's `filter`
replaced with a name of its own is not a rewrite. `presented_name` is distinct from
`path` (the final on-disk spelling) and, except after a re-root, from `member.name`
(the archive's spelling): a caller `filter` rename followed by a portable rewrite
produces three spellings, and only `presented_name` records the middle one.

`rewrites` SHALL name each safety rewrite that reached disk, one `NameRewrite` value per
source: `REROOTED` for the absolute-name re-root and `PORTABLE_NAME` for the
portable-name rewrite. It SHALL be empty exactly when `presented_name` is `None`, and
SHALL hold both values when a re-root and a portable rewrite both ran. A caller reads
the kind of rewrite from it, not from the shape of `presented_name`.

`collided_with` SHALL carry the already-written destination this member collided
with, and SHALL be `None` when nothing this run held the name. It SHALL be set under
exactly the condition that constitutes a collision *event* — a destination claimed by
a member of this same run, under a non-`TRUSTED` policy — and therefore for **every**
resolution: `SKIP`, `ERROR`, a `REPLACE` merge, and `RENAME` alike. An obstacle that
was already on disk before extraction started is not a collision event and SHALL
leave the field `None`; the destination is recorded in `requested_path` regardless.

This is what makes the collision *cause* a property of the result rather than an
inference over the report: without it, a member blocked by another member of this run
and a member blocked by a pre-existing file produce identical results under every
policy. Callers MAY join to the blocking member by plain path equality against another
result's `path`, or its `requested_path` when that member was itself later revised to
`OVERWRITTEN` and no longer holds a live path.

`failure_group_id` / `failure_group_size` SHALL both be set only when one failed
hardlink source causes `N` `FAILED` link results, which SHALL share one group id and
`failure_group_size=N`; otherwise both are `None`. The id SHALL be a `str` generated
as `uuid.uuid4().hex` — the shape and generation the field carried on the diagnostics
channel before it moved here; relocating it did not change its type. It is opaque:
callers MAY compare ids for equality to join a group, and SHALL NOT rely on ordering,
format, or cross-run stability.

`ExtractionResult` has no diagnostics field; `status`, `error` and the fields above
are the per-result outcome.

#### Scenario: collision cause is recorded on the result

| Case | `collided_with` |
| --- | --- |
| Blocked by a member of this run (`SKIP` / `ERROR` / `REPLACE` / `RENAME`) | the prior member's written path |
| A non-directory member blocked by a directory this run wrote, or created as a parent of an earlier member | that directory's path |
| Blocked by an entry already on disk before extraction | `None` |
| No collision at all | `None` |
| Any collision under `ExtractionPolicy.TRUSTED` | `None` (no collision event) |

#### Scenario: result/status matrix

| Case | Expected |
| --- | --- |
| User filter returns `None` | No `ExtractionResult`; no result-count impact (like a selector exclusion) |
| User filter returns anything but an `ArchiveMember` or `None` | `TypeError` naming what it returned; the call ends (a caller bug, not a member outcome) |
| `extract_all()` on a directory source with `dest` inside that directory | `ExtractionError` before anything is created (the pass would read its own output) |
| `extract_all()` with `dest` under a symlink loop, any format | `OSError` (`ELOOP`), as `mkdir` raises it, before anything is created |
| `extract_all()` with `dest` itself a symlink loop, any format | `ExtractionError`, as for any `dest` that exists and is not a directory; nothing created |
| Selector excludes member | No `ExtractionResult`; no result-count impact |
| Member blocked by `FilterRejectionError` under `CONTINUE` | Result is `BLOCKED` with matching error; no diagnostic emitted |
| Member write raises `OSError` under `CONTINUE` | Result is `FAILED` with matching error; no diagnostic emitted |
| Member written successfully | Result is `EXTRACTED`, `path` points to created entry |
| Existing destination under `OverwritePolicy.SKIP` | Result is `NOT_OVERWRITTEN`, `path=None` |
| One failed source causes three hardlink results to fail | Three `FAILED` results sharing one `failure_group_id` with `failure_group_size=3` |

#### Scenario: replaced-member matrix

| Case | Expected |
| --- | --- |
| `A.txt` then `a.txt` under `REPLACE` (non-`TRUSTED`) | `A.txt` revised to `OVERWRITTEN` (`path=None`, `requested_path` kept); `a.txt` is `EXTRACTED` at that path |
| Same pair under `SKIP` | `A.txt` stays `EXTRACTED`; `a.txt` is `NOT_OVERWRITTEN` with `requested_path` set |
| Same pair under `RENAME` | Both `EXTRACTED`; second has `requested_path != path` |
| Same pair under `ERROR` | `A.txt` stays `EXTRACTED`; `a.txt` is `FAILED` with the error |
| Same pair under `TRUSTED` | No collision event; local OS behavior; no `OVERWRITTEN` |
| Result ordering after a retroactive revision | Results stay in member-processing order; only the revised member's fields change |

### Requirement: Error Policy (OnError) for extraction failures

`OnError.STOP` and `OnError.CONTINUE` SHALL govern per-member **failures** only — a
non-rejection member-scoped `ArchiveyError`, a permitted read/write `OSError`, or a
per-member ratio violation. A policy **block** (a `FilterRejectionError` from a universal
path-safety check or a policy filter) is NOT a failure: it SHALL always be recorded as a
`BLOCKED` `ExtractionResult`, have its partial output removed, and let extraction
proceed — under **either** `OnError.STOP` or `OnError.CONTINUE`. `OnError.STOP`
therefore never raises on a blocked member; a STOP run can complete and return an
`ExtractionReport` whose results include `BLOCKED`. Aborting the whole extraction on the
first unsafe member (fail-closed strict security) SHALL be expressed through
`AbortOn.BLOCKED_MEMBER`, not through `OnError`.

Under `CONTINUE`, a member-scoped failure records `FAILED`, removes partial output,
and proceeds.

Under `STOP`, a genuine member failure raises immediately and is not converted to a
continued result. Logging-handler and diagnostic-callback exceptions propagate
unchanged.

Diagnostic disposition SHALL remain authoritative for the diagnostics that still fire
during extraction. Per-member extraction *outcomes* are no longer diagnostics, but
reading an archive while extracting still emits reading diagnostics (invalid
timestamps, unresolvable symlinks, unverifiable digests, stream rewinds); a `RAISE`
disposition on any of those SHALL emit `DiagnosticRaisedError` and halt immediately,
even under `OnError.CONTINUE`, returning no report. Global resource guards (`ResourceLimitError` for cumulative bytes,
archive-wide/live ratio, and max entries), `KeyboardInterrupt`, `MemoryError`, and
unexpected programming exceptions are always-stop and are not swallowed.

#### Scenario: OnError matrix

| Case | Expected |
| --- | --- |
| Member blocked by policy/path-safety under `STOP` | `BLOCKED` result; partial output removed; extraction does **not** halt; later members continue |
| Member blocked by policy/path-safety under `CONTINUE` | `BLOCKED` result; partial output removed; later members continue |
| First member blocked, remaining members extractable, under `STOP` | Run completes; report contains `BLOCKED` + later `EXTRACTED`; no exception escapes |
| Corrupt member under `CONTINUE` | Partial output removed; `FAILED` result; later members continue |
| Default `STOP` member failure (e.g. `CorruptionError`) | Original error propagates immediately; failing partial file removed; earlier outputs remain (from a ZIP read from a pipe, less the files that could still be links: `format-zip`) |
| Filesystem `OSError` while writing under `CONTINUE` | Partial output removed; `FAILED` result; extraction proceeds |
| A member under a non-directory this run extracted (file `d`, then `d/f` or directory `d/y`) | Per-member `ExtractionError` naming `d`, not a raw `OSError`, under every `OverwritePolicy` |
| A member under a non-directory already in `dest` before the run (`d/f` over the caller's file `d`) | `d` meets `OverwritePolicy` as an explicit `d/` entry would (see the overwrite requirement); under `ERROR` a per-member `ExtractionError`, not a raw `OSError` |
| Cumulative bytes/live ratio/max entries exceed limit under any `OnError` | `ResourceLimitError` propagates and halts; no later member processed |
| Mixed good/corrupt/blocked archive under `CONTINUE` | Extractable members written; report includes `EXTRACTED` plus `FAILED`/`BLOCKED`; no per-member exception escapes |
| Reading diagnostic resolves to `RAISE` under `CONTINUE` (e.g. `MEMBER_TIMESTAMP_INVALID`) | `DiagnosticRaisedError` halts; no report returned |

### Requirement: A ZIP extracted from a non-seekable source is settled at the end of the pass

A ZIP read from a non-seekable source (`streaming=True`) gives each member's type, mode,
host and comment, and the order that decides `is_current`, only in its central
directory, after the last member. During the pass, `extract_all` SHALL write the data of
each member the selection may take into one staging directory, named `.archivey-tmp-`
and a random suffix, directly under the destination root, and SHALL write nothing else
into the destination. Once the directory has been read, it SHALL place the members in
listing order, as the extraction of the same archive from a file places them, each read
from its staged data:

- The selection, the caller's `filter`, the policy's checks, the overwrite policy, name
  collisions and `abort_on` SHALL each act on the member as the directory describes
  it, when the member is placed. A symlink that escapes the destination is therefore
  refused from a pipe as from a file, and nothing is written through a link before
  every member is known.
- During the pass, the universal path-safety checks and the name policy SHALL also run
  on each member as its local header names it, before its data is staged. A member
  they refuse SHALL NOT be staged, and `AbortOn.BLOCKED_MEMBER` and
  `AbortOn.NAME_SANITIZED` SHALL act on that refusal at once, as on a refusal at
  placement. A refusal blocks the member, so under `OnError.STOP` alone the run goes
  on, as at placement. A member's data failure while it is staged SHALL stop an
  `OnError.STOP` run at once. So a hostile archive is refused under `abort_on`, and a
  damaged one under `OnError.STOP`, without decoding the rest of it.
- Five things are known only once the directory has been read, and each SHALL fail
  the member it names, under "Error Policy (OnError)" above: a size or CRC from a
  data descriptor that differs from the central entry; a local header whose CRC, sizes
  or encryption flag the central entry contradicts; two same-name members whose
  directory order reverses their file order (the current one fails, the other becomes
  `SUPERSEDED`); a directory entry with no local entry; and a local header and
  directory entry that store different names. The member's result SHALL be the one
  the extraction from a file gives it, or `FAILED` with `CorruptionError` where that
  result needs bytes the pass did not stage; the overwrite policy decides first. Under
  `OnError.STOP` the first such failure SHALL raise `CorruptionError` when placement
  reaches it.
- A local entry no directory entry points to SHALL NOT be placed, and SHALL be reported
  as `ARCHIVE_UNLISTED_DATA`.
- A run that stops before placement begins SHALL leave nothing it wrote in the
  destination. One that stops during placement SHALL keep the members already placed,
  as an extraction from a file keeps the members before its stop. The staging directory
  SHALL be removed when the run ends, whatever the outcome; one the filesystem refuses
  to remove stays, with a warning.
- The bomb limits SHALL count staged data as decoded output, and each staged file
  toward `max_entries`, when it is staged: a staged file is an entry on disk. A staged
  member that is not placed SHALL stop counting toward `max_extracted_bytes` and
  `max_entries`, and SHALL still count toward the archive-wide ratio. Placing a staged
  member adds nothing to any count; a member placed with no staged data (a directory, a
  link, an empty file) SHALL count toward `max_entries` when it is placed.

Where the two reads MAY differ (DR-5a, shapes only crafted archives have): the
descriptor mismatch and the reversed pair fail a member the extraction from a file
writes; a refusal on the local header's name, or a data failure, can stop a run for a
member the directory then does not select or does not list; a member refused on the
local header's name and accepted on the directory's fails, its data not staged; so
does a member whose local name ends in a backslash, which the pass takes for a folder,
when the directory makes it a file with data; and the bomb limits count what the pass
stages, so a member staged and then not placed can still stop a run under
`max_entries` or `max_extracted_bytes`, a member the filter skips included.

#### Scenario: ZIP from a pipe, settled at the end of the pass

| Case | Expected |
| --- | --- |
| The directory types a member staged as a file as a symlink to `../../etc/passwd` | Refused when placed, as from a file; nothing of it reaches the destination |
| Two same-name members `M1`, `M2` in file order, the directory makes `M1` current, `OnError.CONTINUE` | `M1` `FAILED` with `CorruptionError`, `M2` `SUPERSEDED`; the path is empty |
| A STORED bit-3 member whose data embeds a descriptor for a prefix of itself | `FAILED` with `CorruptionError`; nothing placed for it; under `OnError.STOP` raised when placement reaches it |
| A directory entry with no local entry, selected | A `FAILED` result is added for it |
| A local entry the directory does not list | Not placed; `ARCHIVE_UNLISTED_DATA` |
| The run stops before the directory is read (`abort_on`, `on_error="stop"`, a limit) | The destination holds nothing the run wrote; the caller's entries are as they were |
| First member `../../etc/passwd`, `abort_on={BLOCKED_MEMBER}` | `FilterRejectionError` at that member, before any later member is decoded |
| `overwrite="replace"` over a caller's file, for a member the selection drops once the directory is read | The caller's file is untouched |
| The staging directory cannot be removed at the end of the run | It stays, named `.archivey-tmp-…`, with a warning |

### Requirement: A listing that ends in damage extracts its prefix, then raises

When an archive's listing ends in terminal damage (`CorruptionError` / `TruncatedError`
after a recovered prefix, per `archive-reading`), `extract_all()` SHALL
write the members listed before the damage, in either access mode and for every format,
and then raise the listing's own error, under either `OnError`. No report is returned, so
the members after the damage, which were never listed, have no result. This is the order
`stream_members()` gives (the prefix, then the error), and what unrar and 7-Zip do.
Ruled by the maintainer (davitf, 2026-10-03); the rationale and the rejected
alternatives are in `dev-docs/formats/rar.md` §6.

The listing limits SHALL still be checked before anything is written. A hardlink in the
prefix whose source was not selected SHALL still be completed by the second pass before
the raise; a hardlink only points back, so its source is in the prefix. A member
selection that the prefix satisfies SHALL NOT stop the pass before the damage, and its
entries that match nothing in the prefix SHALL NOT be reported unmatched.

#### Scenario: damaged listing matrix

Pinned by `tests/test_extraction_damaged_listing.py`. A 7z or ZIP listing is one index
read at open, so damage there fails the open.

| Case | Expected |
| --- | --- |
| RAR4 / RAR5 / TAR listing cut or corrupt after N members, random access or streaming, listed first or not | The N members written, then the listing's error; no report |
| Same, `members=` naming one prefix member | That member written, then the listing's error |
| Same, `members=` naming a prefix hardlink whose source is not selected | The link written with the source's bytes, then the listing's error |
| Same, `members=` naming a prefix member and an entry that matches nothing, `MEMBER_SELECTOR_UNMATCHED` set to `RAISE` | The prefix member written, then the listing's error; no `MEMBER_SELECTOR_UNMATCHED` |
| Same, prefix over a listing limit | `ResourceLimitError`; nothing written |

### Requirement: ExtractionReport is an immutable operation result

The system SHALL define:

```python
@dataclass(frozen=True)
class ExtractionReport:
    results: tuple[ExtractionResult, ...]
    diagnostics: DiagnosticSummary
```

The report SHALL preserve fixed result outcomes and a point-in-time diagnostic
summary with exact operation counts after retention is exhausted. It does not
duplicate the cumulative reader collector or retain beyond the shared budget.
Immutability is structural, not deep: `ExtractionResult.member` is the original
mutable, caller-read-only `ArchiveMember`, whose documented late-bound metadata
and diagnostics may still change; `error` may be an ordinary exception object.

#### Scenario: report immutability matrix

| Case | Expected |
| --- | --- |
| Caller keeps a report and reader later does more work | Result tuple/outcomes and diagnostic summary stay unchanged; referenced member may receive documented late-bound updates |

### Requirement: Archive-wide decompression ratio for solid containers

The system SHALL evaluate a static archive-wide ratio during extraction when a
member's `compressed_size` is unknown/zero and the reader exposes a cheap
`compressed_source_size`. The denominator is the archive source byte size: path
`stat`, trusted integer `size`, `try_get_size()` from Archivey streams, or an
O(1)-safe `SEEK_END`/restore probe for real files, `BytesIO`, and `mmap`.
Anything that would decompress or scan payload to answer (for example foreign
decompressor streams) yields `None`. A `size` is taken on a seekable source and
on an Archivey member stream, seekable or not. On a caller's non-seekable stream a
`size` attribute is an unchecked claim, and an inflated one would disable both
archive-wide guards, so it yields `None` and the live ratio applies. A member
stream's `size` is the length its container declares, and that declaration is
unchecked too: the container is untrusted input, and a member shorter than its
declaration is refused (`TruncatedError`) by the container's end-of-member check
only after its payload is decoded. An inflated declaration therefore disables
both archive-wide guards for a nested archive, and `max_extracted_bytes` is the
bound that holds there. For compressed containers this is compressed
size; for uncompressed containers the resulting ratio is about 1:1 and harmless.

The ratio SHALL be `archive_output / compressed_source_size`, where
`archive_output` is the decoded output plus the bytes a hard link writes as a
copy past the filesystem's link-count limit ("Enforce Cumulative
Max-Extracted-Bytes Limit"); a cross-device copy is not part of it. It is
checked in `BombTracker.count()` and, for those copies, in
`BombTracker.count_copy()`, using the same `max_ratio` and cumulative
`ratio_activation_threshold` as other ratio guards. When copies are part of it,
the error message gives the decoded and copied bytes separately. If `compressed_source_size`
is absent, the static archive-wide check is skipped. Per-member and archive-wide
ratios are independent; either may trip first. A tripped archive-wide ratio
SHALL raise `ResourceLimitError`.

#### Scenario: static archive-wide ratio matrix

| Case | Expected |
| --- | --- |
| Small `.tar.gz` file with known source size expands past `max_ratio` after threshold | `ResourceLimitError` during extraction |
| Compressed tar from non-seekable pipe, with or without a `size` attribute | Static archive-wide ratio skipped; live ratio and cumulative byte limit still apply |
| Plain `.tar` from a path or a seekable stream with a cheap size | No meaningful compressed denominator; archive-wide ratio does not trip, except on copies of a hard-link source written past the filesystem's link-count limit |
| Plain tar from a non-seekable stream, with or without a `size` attribute | No archive-wide denominator; the cumulative byte limit applies |
| ZIP member has known `compressed_size` | Per-member ratio applies; archive-wide ratio does not replace it |
| Nested archive opened from an Archivey member/codec stream with cheap size | Cheap source size may serve as archive-wide denominator; it is the container's unchecked declaration, so `max_extracted_bytes` is the bound that holds |

### Requirement: Enforce Maximum Entry Count

The system SHALL count members actually written to disk during one extraction call
and raise `ResourceLimitError` once the count exceeds `max_entries`. The default is
`262_144`; callers override through `ExtractionLimits`, and `None` disables the
guard. The counter protects against inode/per-directory/syscall bombs made of many
tiny entries and is independent of byte and ratio limits.

Only members that will create disk entries SHALL count: selector exclusions, user
filter skips, and members dropped before writing do not increment the counter. The
exception is a ZIP read from a pipe, whose pass stages a file for each member the
selection may take before the filter runs ("A ZIP extracted from a non-seekable source
is settled at the end of the pass"): each staged file counts while it is on disk, and
stops counting if its member is not placed.
Every written FILE, DIR, SYMLINK, and HARDLINK counts. This is a global resource
guard and halts even under `OnError.CONTINUE`. The same limit separately bounds the
symlink rechecks of "Symlink Escape Re-Validated at Extraction Time".

#### Scenario: entry-count matrix

| Case | Expected |
| --- | --- |
| More than `max_entries` members are written | `ResourceLimitError` once the count crosses the limit; extraction halts under any `OnError` |
| `ExtractionLimits(max_entries=100)` | Error after the 100th written member when the 101st would be written |
| Selector chooses one member from many | Extraction can complete with `max_entries=1` because only selected written entries count; every member the pass walks still counts against `ListingLimits` (`archive-reading`), in both access modes |
| Many tiny files stay below byte/ratio limits but exceed entry count | Entry-count guard still raises |

### Requirement: Symlink extraction is target-independent and fails safe on unsupported filesystems

The system SHALL create SYMLINK members as symbolic references via
`os.symlink()` without requiring the target to exist, to be selected, or to be
inside the archive. A symlink may dangle and no target data is copied; the
universal resolved-target escape check remains the only safety constraint on the
link target.

If the platform or destination filesystem cannot create symlinks and
`os.symlink()` raises `OSError` or `NotImplementedError`, the member SHALL be a
per-member failure governed by `OnError`. Archivey does not silently copy target
data as Python `tarfile` may do on symlink-unsupported platforms.

#### Scenario: symlink extraction matrix

| Case | Expected |
| --- | --- |
| SYMLINK target member is excluded by selector/filter and resolved target stays in `dest` | Symlink is created and may dangle; target data is not copied |
| SYMLINK target appears later or outside the archive but stays in `dest` | Symlink is created as stored; no target materialization |
| `os.symlink` unsupported raises `OSError`/`NotImplementedError` | `STOP` raises; `CONTINUE` records `FAILED`; no copy fallback |
| On Windows, a SYMLINK whose target is a directory when the link is created, or that the archive's listing shows is a directory (a directory member, or a name other members are inside) | Created as a directory link (`target_is_directory=True`) |
| On Windows, a SYMLINK whose target is not known when the link is created (a later member with no listing up front, as in a TAR or a streaming pass) | Created as a file link; at the end of the run, a link still in place whose target is then a directory is remade as a directory link, and a directory link whose target is not a directory is remade as a file link |
| On POSIX | One kind of link; no flag and no end-of-run pass |

### Requirement: Live archive-wide decompression ratio for unknown-size streams

The system SHALL evaluate a live archive-wide ratio during extraction when no
per-member `compressed_size` and no cheap static `compressed_source_size` is
available, but the compressed backend can expose `compressed_bytes_consumed`.
This covers compressed archives from non-seekable pipes, a pipe that carries a
`size` attribute included, and seekable opaque streams whose size is not cheaply
knowable. Backends wrap the stream source in
the counting reader exactly when the static denominator is absent.

The ratio SHALL be `archive_output / compressed_bytes_consumed`, with
`archive_output` as in the static archive-wide requirement (decoded output plus
link-count-limit copies), checked after it crosses both `ratio_activation_threshold`
and `live_ratio_activation_threshold` (default 256 MiB), using the same `max_ratio`.
The second, larger floor exists because the live denominator is only what has been
read so far: an honest archive whose data starts with a long blank run (a disk image,
a preallocated file) reads far above `max_ratio` until the data after that run
arrives, while the same archive from a file passes the static check. A blank start
shorter than the live floor therefore gives the same outcome from a pipe as from a
file; a longer one can still be refused from a pipe, and a bomb from a pipe can write
up to the live floor before this guard stops it. Once a pipe has been read to
its end, `compressed_bytes_consumed` is the whole compressed size and the live ratio
equals the static one; on a seekable source, codec-layer re-reads can only make the
live denominator larger. `max_extracted_bytes` stays the absolute bound. It is a
cumulative global guard: if it trips, extraction halts even
under `OnError.CONTINUE` with `ResourceLimitError`. The live path complements
static checks and is not used when member compressed sizes or a cheap outer
source size provide a denominator; whichever available guard trips first wins.
Codec-layer seeks may re-read counted bytes, inflating the denominator and
weakening the guard, but never causing a false positive.

#### Scenario: live archive-wide ratio matrix

| Case | Expected |
| --- | --- |
| Highly compressible `.tar.gz` from non-seekable pipe has no static denominator | Live ratio raises `ResourceLimitError` after both floors, before absolute byte cap |
| `.tar.gz` from a pipe whose member is 64 MiB of zeros then 8 MiB of data, default limits | Extracts, as it does from a file; the blank start is under `live_ratio_activation_threshold` |
| Same shape with a blank start longer than `live_ratio_activation_threshold` | Live ratio may raise `ResourceLimitError` from a pipe though the file passes; the documented trade-off |
| Live ratio exceeded under `OnError.CONTINUE` | `ResourceLimitError` propagates and extraction halts |
| Plain uncompressed `.tar` from a pipe | No counter is installed, so no live ratio applies; byte limit still applies |
| `.tar.gz` has cheap `compressed_source_size` | Static archive-wide ratio is used; live path is not engaged/double-counted |
| Seekable opaque compressed stream has no cheap size/`size`/`try_get_size()`/O(1) end seek | Source is counted live; archive is not left with only the byte cap |

### Requirement: Cross-platform name safety is deterministic across policy levels

Extraction SHALL handle destination-name hazards deterministically on every platform,
keyed off `ExtractionPolicy`, so the same archive yields the same logical outcome
(collision events, rejections, normalized spellings) regardless of the runner OS. These
rules compose with — and never bypass — the non-bypassable path-safety constraints.

**Collision determinism (O2).** Under `STRICT` and `STANDARD`, the coordinator SHALL track
a `casefold(NFC(path))` key per written destination, with a trailing dot or space dropped
from each segment that has other characters (Win32 trims it, so `foo.` and `foo` are one
file there), and treat a second member resolving to the same key as an existing
destination on **all** platforms. The key is taken on where
the entry physically lands (its parent resolved), so a member written through a
directory symlink the archive created (`s/f` with `s -> d`) collides with `d/f`. A
member whose destination holds an entry that no member of this run claimed by key, but that
is the same file (`st_dev`, `st_ino`) as a file this run claimed, collides with that member
as a case variant does: on Windows this is an 8.3 short name (`LONGFI~1.TXT` after
`longfilename.txt`) on a volume that makes them. This does not apply under `TRUSTED`, and
not on a filesystem that reports inode 0. The key
and the location are fixed when the earlier member is written, and a collision SHALL be
resolved at that location, so repointing `s` later does not move it. Such a collision
SHALL apply `OverwritePolicy` deliberately and record the outcome on both members'
`ExtractionResult`. DIRECTORY members are not claimed in the map, as a directory merges
into one already there. The coordinator looks a DIRECTORY member up in the map when its
destination holds a non-directory entry. If a member of this run claimed that entry, the
DIRECTORY member collides with it under every `OverwritePolicy`, as a file member
would: `collided_with`, `AbortOn.NAME_COLLISION` and the `REPLACE` revision of the
earlier member to `OVERWRITTEN` all apply. The same holds the other way: a non-directory
member whose destination is a directory this run wrote, or created as the parent of an
earlier member (`x/f` and then `x`), collides with that directory under every
`OverwritePolicy`. `collided_with` names the directory (the directory member's `path`
when one wrote it), `AbortOn.NAME_COLLISION` fires, and the policy then meets the
directory where it is: `ERROR` fails the member, `SKIP` records `NOT_OVERWRITTEN`,
`REPLACE` removes it only when it is empty, and `RENAME` writes the member under a
derived name. A directory that was there before the run is not a collision event, even
when a DIRECTORY member of this run merged into it. On a
case-sensitive filesystem a file `Foo` and a
directory `foo/` do not share an entry, so they do not collide. `REPLACE`
SHALL NOT silently merge distinct members on case-insensitive filesystems: the earlier
member's result SHALL be revised to `ExtractionStatus.OVERWRITTEN` so the merge is
observable in `results`. Under `TRUSTED` the coordinator SHALL key on the exact `Path`
and defer to the local OS (today's behavior), so genuinely distinct files on a
case-sensitive filesystem both extract.

`OverwritePolicy` SHALL add a `RENAME` member that extracts a colliding entry under a
deterministic derived name, using the same collision key, for archives with intentional
duplicates. The derived name SHALL insert ` (N)` (`N` = 1, 2, …) **before the final suffix**
(`Path.stem` + `Path.suffix` semantics): `photo.jpg` → `photo (1).jpg`; a name with no
suffix → `photo (1)`; a leading-dot dotfile (`.bashrc`) → `.bashrc (1)` (the leading dot is
not treated as a suffix); a multi-suffix name (`archive.tar.gz`) → `archive.tar (1).gz`
(single final suffix); a directory appends to the whole segment. `N` SHALL increment to the
first name free **both on disk and in the collision map**, in member-processing order.

**Portable-name enforcement (O3/O4).** Windows-reserved device names (`CON`, `PRN`, `AUX`,
`NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `COM¹`–`COM³`, `LPT¹`–`LPT³`, `CONIN$`, `CONOUT$`;
case-insensitive, with or without extension) and `:` within a segment are **unsafe**
(device capture / NTFS alternate data stream) and SHALL be rejected under `STRICT` and
`STANDARD` on **every** platform, in each segment of the member name and in each segment
of a SYMLINK's `link_target` (on Windows a link to `file:stream` names an alternate data
stream, and one to `NUL` the device). `TRUSTED` checks neither. A trailing dot or space
is a legitimate macOS/Linux name that Win32 merely trims; rejecting it would halt a
legitimate archive, so under `STRICT` each path segment's trailing dot/space SHALL be
**stripped** to its portable spelling (`stuff_etc.` → `stuff_etc`) deterministically on
every platform,
collision-tracked as above, and recorded as `ExtractionResult.presented_name`; a
segment that is entirely dots/spaces (e.g. `...`) has no portable spelling and SHALL be
rejected under `STRICT` and `STANDARD` (Win32 would merge `a/.../b` into `a/b`).
`STANDARD` and `TRUSTED` SHALL otherwise keep the trailing dot/space faithful (written if
the OS allows).

**Separators.** Under `STRICT` and `STANDARD`, a `\` that a member name keeps as a
literal character (TAR) SHALL be written as `/` on every platform, as Windows writes it, and
recorded as `ExtractionResult.presented_name`. A link target gets the same rewrite, so a
symlink to another member names the path that member was written at, and a target such as
`..\x` is checked as the `../x` it becomes. A hard link still resolves to the member the
reader matched to its stored target; the rewrite does not change which member that is. The
path-safety checks SHALL run again on a member the policy rewrote, so a rewrite that changes
the directories a path passes through cannot bypass them. `TRUSTED` writes the `\` as the
local OS does. On Windows, under every policy, a symlink's target SHALL be created with
each `/` written as `\`, so a relative target such as `sub/file` resolves there as it does
on POSIX; errors still name the target as stored.

**Read-only files.** A member whose stored mode has no write permission leaves a file
Windows will not replace or delete, or a directory it will not remove. On Windows, when a
later member of the run replaces or an anti-item removes a regular file or an empty
directory this run wrote read-only, extraction SHALL clear the read-only attribute first,
so `REPLACE` gives the result it gives on POSIX. The attribute is put back on a file's other
hard links. A read-only entry that was in the destination before the run is not changed.

**Portable-name representability (O7).** Under `STRICT` and `STANDARD`, a name carrying
bytes that cannot be represented portably on the destination filesystem SHALL be normalized
to a deterministic, reversible portable spelling — each non-UTF-8 byte (a surrogateescape
char U+DC80–U+DCFF mapping to raw byte 0x80–0xFF) percent-escaped as `%XX` (uppercase hex),
and a literal `%` escaped as `%25` — applied on **every** platform, collision-tracked as
above, and recorded as `ExtractionResult.presented_name`. The characters Win32 refuses in a
name, `<`, `>`, `"`, `|`, `?`, `*` and the controls 0x01–0x1F, SHALL be escaped the same
way, as `%XX` of their code point (`a?b` → `a%3Fb`), so a name POSIX could store gives the
tree Windows gives. A `%` is escaped only in a name the scheme rewrites. The scheme SHALL
touch nothing else; valid-but-non-portable Unicode (NFC/NFD forms) SHALL NOT be rewritten
(its cross-platform folding is the O2 collision concern). `TRUSTED` SHALL attempt the
faithful bytes and let the OS decide. The reversibility SHALL be a documented property; a
public un-escape API is out of scope. Either way the outcome SHALL be deterministic and
typed (never a bare `OSError`). A lone surrogate outside U+DC80–U+DCFF is escaped as
its three UTF-8 bytes (`hi\ud800` → `hi%ED%A0%80`); "Lone surrogates in a member name"
has the detail and the `TRUSTED` spelling.

`ExtractionResult.requested_path` carries the destination the coordinator intended before
overwrite/rename resolution. A rename SHALL be observable as `requested_path != path and
status == EXTRACTED`; a collision resolved by `SKIP`/`ERROR` SHALL set `requested_path`
with `path=None`. `presented_name` SHALL NOT be expressed through `requested_path`: the
two signals are independent, and a member MAY carry both (a portable rewrite whose
rewritten name then collides and is renamed).

#### Scenario: cross-platform name matrix

| Case | `STRICT` / `STANDARD` | `TRUSTED` |
| --- | --- | --- |
| `README` and `readme` in one archive | Second is a collision event on all platforms; `OverwritePolicy` applied; `requested_path` recorded | Local OS behavior (both extract on a case-sensitive FS) |
| `longfilename.txt`, then `LONGFI~1.TXT`, on a Windows volume with 8.3 names | Second is a collision event with the first (same file identity); under `REPLACE` the first is revised to `OVERWRITTEN` | Local OS behavior (the second meets a file already there) |
| NFC `café` and NFD `café` | Treated as a collision on all platforms | Local OS behavior |
| Member named `NUL` / `COM1` / `COM¹` / `CONIN$` | Rejected on all platforms (typed error) | Written if the OS allows |
| Trailing dot/space (`foo.`, `foo `) | `STRICT` strips to portable spelling (`foo`), `presented_name="foo."`, `rewrites == {PORTABLE_NAME}`; `STANDARD` keeps faithful; either way `foo.` beside `foo` is a collision event on all platforms | Written if the OS allows |
| Segment of only dots/spaces (`.../x`) | Rejected on all platforms (no portable spelling) | Written if the OS allows |
| Name containing `:` (`file:hidden`) | Rejected on all platforms | Local OS behavior (NTFS ADS) |
| TAR name `a\b` | Written as directory `a` and file `b`; `presented_name="a\b"` | Local OS behavior (a file `a\b` on POSIX) |
| SYMLINK whose `link_target` has a segment with `:` (`file:stream`) or a reserved name (`sub/NUL`) | Rejected on all platforms | Local OS behavior |
| Surrogateescape `caf\udce9.txt` | Sanitized to `caf%E9.txt`; `presented_name` keeps the pre-rewrite spelling; collision-tracked | Faithful bytes attempted; OS decides |
| `what?.txt`, `a*b`, a name with a control byte | Written as `what%3F.txt`, `a%2Ab`, `%XX` per control; `presented_name` keeps the stored name | Written if the OS allows (refused on Windows) |
| Symlink `l -> sub/file` (on Windows) | Created with target `sub\file`; resolves as on POSIX | Same |
| A member stored `0o444`, then a later member of the same name under `REPLACE` | Replaced on every OS | Same |
| `REPLACE` with a casefold collision | Not a silent merge; earlier member revised to `OVERWRITTEN` | Local OS behavior |
| `RENAME` with a collision (case/NFC or exact) | Second entry written as `name (1)` before the suffix; `requested_path` = intended name | Same |
| Filter rename, then a portable rewrite | `member.name`, `presented_name`, and `path.name` are all three spellings | Faithful bytes attempted |

### Requirement: Abort-on-event opt-in for extraction

`extract_all()` SHALL accept `abort_on: Collection[AbortOn] = ()`,
halting the whole extraction the first time a named event occurs.

```python
class AbortOn(StrEnum):
    BLOCKED_MEMBER = "blocked_member"
    NAME_COLLISION = "name_collision"
    NAME_SANITIZED = "name_sanitized"
```

| Member | Fires when | Raises |
| --- | --- | --- |
| `BLOCKED_MEMBER` | a member is blocked by a universal path-safety check or a policy filter | the underlying `FilterRejectionError` |
| `NAME_COLLISION` | a second member resolves to an already-written collision key (non-`TRUSTED`) | `NameCollisionError` |
| `NAME_SANITIZED` | a name is rewritten to its portable spelling, or an absolute name is re-rooted | `NameRewrittenError` |

`NAME_SANITIZED` is deliberately unlike the other two: it fires on a **successful**
safety rewrite rather than on a refusal or an ambiguity. It SHALL be documented as a
narrow escape hatch for callers who refuse any on-disk name differing from the archive's — mirroring tools, forensic extracts, byte-fidelity
checks — and SHALL NOT be presented as part of ordinary strict extraction or implied
by any preset or policy level. A caller wanting to *audit* rewrites reads
`presented_name`; only a caller who wants them to be **fatal** sets this.

`NAME_COLLISION` SHALL fire on **every** non-`TRUSTED` collision event, whatever
`OverwritePolicy` resolution follows — replaced, skipped, errored or renamed. The
trigger is the collision itself, not its outcome. `TRUSTED` keys on the exact path and
produces no collision event, so it never aborts.

`NameCollisionError` and `NameRewrittenError` SHALL subclass `ExtractionError`.
`BLOCKED_MEMBER` SHALL propagate the original rejection unchanged, matching
`OnError.STOP`'s propagate-the-original behaviour.

Abort SHALL be immediate: partial output for the triggering member is removed, no
later member is processed, and no `ExtractionReport` is returned. `abort_on` SHALL be
independent of `OnError` and of `DiagnosticPolicy` — a blocked member aborts under
either `OnError` value when `BLOCKED_MEMBER` is set, and never aborts when it is not.

Output written for **earlier** members SHALL remain on disk, matching `OnError.STOP`:
abort stops the run, it does not roll it back. For a collision abort this means the
first member's bytes are typically still present at the contested path, since that
member completed normally before the collision was detected. A ZIP read from a pipe
places its members only once the central directory has been read ("A ZIP extracted
from a non-seekable source is settled at the end of the pass"): an abort during its
pass leaves nothing in the destination, and an abort during placement keeps the members
placed before it, in listing order, as above.

Because no report is returned, an abort SHALL have no observable result-side effect:
in particular the earlier member is not revised to `OVERWRITTEN` anywhere the caller
can see. `OVERWRITTEN` is a property of a completed report, and `abort_on` and
`OVERWRITTEN` are therefore mutually exclusive for the same collision.

`AbortOn` SHALL NOT carry a member for extraction *failures*: `OnError.STOP` already
expresses "raise on the first failure".

#### Scenario: abort-on matrix

| Case | Expected |
| --- | --- |
| Absolute-path member, `abort_on={BLOCKED_MEMBER}`, `OnError.CONTINUE` | `FilterRejectionError` raised at that member; no report; later members untouched |
| Same archive, `abort_on=()` | `BLOCKED` result; extraction completes; report returned |
| `REPLACE` collision, `abort_on={NAME_COLLISION}` | `NameCollisionError` at the second member; no report; first member's bytes remain on disk |
| `SKIP` collision, `abort_on={NAME_COLLISION}` | Aborts — the trigger is the collision, not the resolution |
| `RENAME` collision, `abort_on={NAME_COLLISION}` | Aborts, even though the rename loses nothing; parity with the escalation this replaces |
| `ERROR` collision, `abort_on={NAME_COLLISION}` | Aborts with `NameCollisionError`, not the overwrite error |
| Any aborted collision | No result is observable; the earlier member is never seen as `OVERWRITTEN` |
| Trailing-dot name under `STRICT`, `abort_on={NAME_SANITIZED}` | `NameRewrittenError` at that member; no report |
| Collision under `TRUSTED`, `abort_on={NAME_COLLISION}` | No collision event, so no abort |
| `abort_on={BLOCKED_MEMBER}` with `OnError.STOP` and a corrupt member | Failure still raises via `OnError`; abort applies only to blocks |
| ZIP from a pipe, `abort_on={NAME_COLLISION}`, two members colliding | `NameCollisionError` when the second is placed; the first stays placed |

### Requirement: Dry-run extraction

`extract_all()` SHALL accept `dry_run: bool = False`, read for its
truthiness like the other boolean flags.

With `dry_run=True`, the extraction SHALL run the same pass as a real extraction into
a private scratch directory, and SHALL NOT create or change anything under `dest`.
Directories, symlinks and hardlinks SHALL be created in the scratch directory, so every
check that consults the filesystem behaves as in a real extraction. Every FILE body
SHALL be read, decompressed, verified and counted against the extraction limits; its
bytes SHALL be discarded and the file created empty. What `dest` already holds SHALL
be copied into the scratch directory before the pass looks at it: the entry at each
component of a member's path, link target or hardlink source, the names a RENAME would
try in its place, and one entry of a directory the path names. A file SHALL be copied
as an empty file with its mode, a directory with its mode and a symlink with its
target, so the overwrite policy and an entry in the way meet them as in `dest`. The
dry run SHALL NOT copy every entry of a directory it enters: it reads the directory's
listing once and copies the entries the pass names.

The returned report SHALL equal the report of a real extraction with the same
arguments into the same `dest`, with every path in it (`path`, `requested_path`,
`collided_with`) under `dest`. An absolute link target that names a path under `dest`
SHALL be checked as naming the same path under the scratch directory. Two cases are
exempt, because the scratch directory cannot reproduce them: a link target that leaves
`dest` and comes back into it through a symlink outside `dest`, or by climbing above
the directory that holds `dest`, MAY be refused where a real extraction accepts it; and
bytes a real extraction counts for copying a hardlink across a filesystem boundary
inside `dest` are not counted. And a directory of `dest` gains its owner's read,
write and search bits in the scratch directory, so a refusal that comes from its
permissions MAY appear only in a real extraction; a symlink of `dest` that the OS will
not create there is copied as an empty file; an entry that cannot be copied (the
scratch filesystem is full, or the name is too long there) is left out; and a path
whose links expand past `PATH_MAX` cannot be resolved and is refused, so where the
scratch directory's path and `dest`'s differ in length, a member whose resolution
passes that limit in only one of them MAY be refused in only one of the two runs. A
`dest` that exists and is not a directory SHALL be refused as a real extraction
refuses it. A `dest` that does not exist SHALL be refused with the error a real
extraction gets creating it when the nearest part of its path that exists cannot be
resolved, is not a directory, or cannot be written to. Whether it can be written to is a
prediction made with `access(2)`, which checks the real user and group ids rather than
the effective ones, and on Windows it is not made; so a refusal that comes from a
process whose real and effective ids differ, from a change after the check, or on
Windows, MAY appear only in a real extraction. File names in errors raised, recorded or
logged SHALL be the ones a real extraction's errors give, spelled from `dest` as given,
as `os.path.abspath` spells it, or resolved (a symlink loop already in `dest`), and
never the scratch directory's, except in the warning that the scratch directory itself
could not be removed. The scratch directory SHALL be removed before the call returns or
raises, including when the archive stored modes that make its directories unwritable or
its files read-only.

#### Scenario: dry-run matrix

| Case | Expected |
| --- | --- |
| Any archive, any policy, overwrite and access mode | Report equals that of a real extraction into the same `dest`, empty or not |
| A member whose data fails its digest | `FAILED`, as in a real extraction |
| Output over `max_extracted_bytes` | `ResourceLimitError`, as in a real extraction |
| `dest` holds a file of the same name as a member | The overwrite policy's outcome, as in a real extraction (`FAILED` under `ERROR`); the existing file is unchanged |
| `dest` holds a symlink where a member lands, or on a member's path | Replaced, renamed around, written through or refused as in a real extraction; the symlink is unchanged |
| `dest` is a regular file | `ExtractionError`; nothing created |
| `dest`'s parent is a regular file | `OSError`, as in a real extraction; nothing created |
| `dest`'s parent is a directory the caller cannot write to, or a symlink loop | The `OSError` a real extraction raises; nothing created |
| `dest` is relative, or reached through a symlink, or spelled with `..`, and a member fails with an `OSError` | Its file names match a real extraction's, spelled as those are |
| A symlink whose absolute target names a file under `dest` | `EXTRACTED`, as in a real extraction |
| A symlink at the top of `dest` whose target is `../<dest name>/<file>` | `EXTRACTED`, as in a real extraction |
| `dest` does not exist | Not created |
| Archive stores a directory with mode `0o555` or `0o000` under `TRUSTED` | Scratch directory still removed |
| `abort_on` fires | The error names paths under `dest`; scratch directory removed |
