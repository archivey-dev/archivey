# Outside review 1: triage

Verdict from the reviewer: **adopt with caveats**. Every task worked on ZIP, tar.gz, 7z and ISO.
No malicious fixture escaped extraction, the ratio guard and the extraction limits stopped the
bomb, wrong passwords gave clear errors, and a 1 GiB stream used about 34 MiB of memory. For a
ZIP/TAR-only program, the reviewer saw little gain over the standard library.

Each finding below was checked against `main` (4fce0ed).

## Fixed in the pull request that adds this directory

| Finding | What was wrong | Fix |
| --- | --- | --- |
| F9 | `docs/cli.md` said `--dry-run` behaves like an extraction into an empty folder. It looks at what is already in the destination, as `docs/extracting.md` says. | The CLI page now says the dry run reports what extracting into the destination as it is now would do. |
| F5 (part) | A bad gzip trailer raised `_StreamChecksumError`. It is a `CorruptionError`, but the user saw a private-looking name. | Renamed to `StreamChecksumError`. It is still not exported. |
| F2 | The README and the docs home page call `extract_all("out/")` and drop the report. A refused member does not raise, so a reader who copies the example can take a partial extraction for a full one. | The home page checks the report and names `abort_on=["blocked_member"]`; the README example passes `abort_on`. |

## Works as documented; the reviewer still tripped over it

- **F5:** `verify_all()` returned no failures on a truncated ZIP; the truncation was only in
  `members_report().error`. The errors page documents this, and marks `verify_all()` experimental.
- **F4:** `read()` has no byte cap, and `ExtractionLimits.max_extracted_bytes` does not apply to it.
  The security page says so.
- **F7:** ZIP gives naive datetimes and TAR gives aware ones, so comparing them raises
  `TypeError`. `modified_utc()` is the documented answer.
- **F6:** half of a very small `.tar.gz` lists as one gzip member, because the cut leaves less
  than one TAR header. Expected.
- **F10:** streaming used 34 MiB peak RSS against 14 MiB for `tarfile`, and was about 6 % slower.
- **F11:** the deprecated ratio fields of `ExtractionLimits` warn, as documented.
- **F1, F3, F8:** positive results, nothing to do.

## Design objections, for the maintainer

The reviewer offers each fix as an addition that keeps existing callers working.

1. **O1:** no single stable "is this archive acceptable" answer. It proposes a `validate()` that
   returns one report with `raise_for_failure()`. This overlaps with F2 and F5, and is the
   strongest of the five.
2. **O2:** during streaming, a yielded member can change later (a file becomes a symlink,
   `is_current` flips). It proposes separate provisional events.
3. **O3:** named reads on solid archives can re-decode a growing prefix; it wants that opt-in or
   louder.
4. **O4:** no shared resource budget across reads, nested archives and concurrent decoders.
5. **O5:** behaviour depends on which optional packages and external tools are installed; it
   proposes a deterministic profile with an explicit backend allowlist.
