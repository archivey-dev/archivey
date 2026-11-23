## For dummies

<!-- Goes first, and is written for someone who uses archives but has not read this code,
the issue or the review. Plain words: no function, class or file names, no finding IDs,
no internal jargon. A short paragraph or a few bullets that answer:
- What the thing is: the format, feature or part of archivey the change touches, in one
  sentence ("pbzx is the compression wrapper inside macOS .pkg installers").
- The bug or the gap, with a concrete example: an archive, a call, and what happened
  ("listing a CD image whose second session was burned in another mode showed only the
  first session's files").
- What the change does about it, in one sentence.
- Who notices, and what they see now. "Nobody: internal only" is a fine answer.
A pull request with several fixes gets one short block per fix. The sections below keep
the precise, technical record. -->

## What changes

<!-- What the diff does, in a few sentences. Link the issue it fixes, if there is one. -->

## Why

<!-- The problem it solves, or the decision it follows. -->

## Risk

<!-- What could break, and for whom, if this change is wrong.
Tier: the "tier:" line that `python3 scripts/review/review_prep.py tier` prints (light,
standard or deep), and the paths behind it. When the change is tricky in a way the paths
do not show (architecture, concurrency, crypto, resumable state, limits), end a commit
message with the trailer `Review-Tier: deep (why)`: its own line in the last paragraph,
after a blank line. The script then prints deep; the same words inside prose do not count.
Public API: "none" when the script's "public API:" line says unchanged, or the names
added, changed or removed (the diff of dev-docs/api-surface.txt or of an archivey-codecs
.pyi stub lists them). Removing or renaming a public name is the
maintainer's call.
Security: "yes" or "no", and the rule behind it. Yes when the change, on any path:
allocates, loops or recurses on a size, count or offset read from the archive; adds
or changes a decoder or codec; adds a call into native code or an external program;
touches a limit or a bomb check; or adds a format. Also yes when the tier command
prints "security pass: yes". When unsure, yes: the review runs a security pass
(code-review-skill §1). The reviewer applies these rules whatever the line says, so a
"no" can be raised but a "yes" is never lowered.
Merge: the "merge:" line the tier command prints. It names the decisions in the diff
that are the maintainer's call (a public name, parameter or fixed value removed, or a
top-level name added; a config default; a defended property dropped or cut down, or a
non-guarantee accepted; a new ADR, runtime dependency, workflow or workflow action; a
workflow's permissions, secrets, triggers or event text; the release path or the merge
gate). Add any it cannot see: a new subsystem, a reversed ruling. -->

## Tests

<!-- The tests that cover the change, and the gates you ran: ./scripts/check.sh,
./scripts/test.sh, ./scripts/test.sh --all-configs. If you skipped a leg, say why. -->

## Checklist

- [ ] The change follows [CONTRIBUTING.md](https://github.com/archivey-dev/archivey/blob/main/CONTRIBUTING.md): its coding and testing rules and its gates.
- [ ] A bug fix comes with a test that fails without the fix.
- [ ] The user docs (`docs/`) and the specs (`openspec/`) match the new behaviour, or the change does not touch them.
- [ ] A `CHANGELOG.md` edit is under `## [Unreleased]`, fits its sections, and merges into the line on the same topic when one exists, or the change has none. A plain bug fix needs no line: the release counts it in the shared Fixed line.
- [ ] A change in behaviour that needs a minor release (see "Versioning and stability" in [How it is built](https://archivey-dev.github.io/archivey/how-it-is-built/)) has the `needs-minor` label, or the change has none.
