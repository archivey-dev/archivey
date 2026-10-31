## What changes

<!-- What the diff does, in a few sentences. Link the issue it fixes, if there is one. -->

## Why

<!-- The problem it solves, or the decision it follows. -->

## Risk

<!-- What could break, and for whom, if this change is wrong.
Tier: the "tier:" line that `python3 scripts/review_prep.py tier` prints (light,
standard or deep), and the paths behind it.
Public API: "none", or the names added, changed or removed (the diff of
dev-docs/api-surface.txt lists them). Removing or renaming a public name is the
maintainer's call.
Security: "yes" or "no", and the rule behind it. Yes when the change, on any path:
allocates, loops or recurses on a size, count or offset read from the archive; adds
or changes a decoder or codec; adds a call into native code or an external program;
touches a limit or a bomb check; or adds a format. Also yes when the tier command
prints "security pass: yes". When unsure, yes: the review runs a security pass
(code-review-skill §1). The reviewer applies these rules whatever the line says, so a
"no" can be raised but a "yes" is never lowered.
Merge: the "merge:" line the tier command prints. It names the decisions in the diff
that are the maintainer's call (a public name removed or added at the top level, a
config default, a defended property dropped or a non-guarantee accepted, a new ADR or
runtime dependency, a workflow's permissions, secrets or triggers, the release path or
the merge gate). Add any it cannot see: a new subsystem, a reversed ruling. -->

## Tests

<!-- The tests that cover the change, and the gates you ran: ./scripts/check.sh,
./scripts/test.sh, ./scripts/test.sh --all-configs. If you skipped a leg, say why. -->

## Checklist

- [ ] The change follows [CONTRIBUTING.md](https://github.com/archivey-dev/archivey/blob/main/CONTRIBUTING.md): its coding and testing rules and its gates.
- [ ] A bug fix comes with a test that fails without the fix.
- [ ] The user docs (`docs/`) and the specs (`openspec/`) match the new behaviour, or the change does not touch them.
- [ ] `CHANGELOG.md` is unchanged. The release PR writes it.
- [ ] A change in behaviour that needs a minor release (see "Versioning and stability" in [How it is built](https://archivey-dev.github.io/archivey/how-it-is-built/)) has the `needs-minor` label, or the change has none.
