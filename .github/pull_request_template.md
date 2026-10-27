## What changes

<!-- What the diff does, in a few sentences. Link the issue it fixes, if there is one. -->

## Why

<!-- The problem it solves, or the decision it follows. -->

## Tests

<!-- The tests that cover the change, and the gates you ran: ./scripts/check.sh,
./scripts/test.sh, ./scripts/test.sh --all-configs. If you skipped a leg, say why. -->

## Checklist

- [ ] The change follows [CONTRIBUTING.md](https://github.com/archivey-dev/archivey/blob/main/CONTRIBUTING.md): its coding and testing rules and its gates.
- [ ] A bug fix comes with a test that fails without the fix.
- [ ] The user docs (`docs/`) and the specs (`openspec/`) match the new behaviour, or the change does not touch them.
- [ ] `CHANGELOG.md` is unchanged. The release PR writes it.
- [ ] A change in behaviour that needs a minor release (see "Versioning and stability" in [How it is built](https://archivey-dev.github.io/archivey/how-it-is-built/)) has the `needs-minor` label, or the change has none.
