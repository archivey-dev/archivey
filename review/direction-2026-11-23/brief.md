# Direction review, 23 November 2026

A direction note for the maintainer. It is not a defect review.
[`review/README.md`](../README.md) asks a commissioned review for a green baseline, a
findings table, theme files, and file-and-line evidence. Those do not fit this ask, and
this brief does not pretend they were done. The test suite was not run. Nothing under
`src/` or `tests/` changes. `./scripts/check.sh` was run on the prose.

## The ask

Look at the library with fresh eyes, as a candidate for the default way to deal with
archives: easy to use, safe, broadly compatible, and easier to extend with a plugin than
by writing another library. Say what is missing, what is too complicated in the API and
in the internal architecture, whether the project has gone too far, what else to ask,
and which unknowns the current work will not surface. Stay at the level that shapes
direction. Do not search for bugs. Write the analysis under `review/` and open a pull
request. Ignore other open pull requests.

## What was read

`VISION.md`, `docs/philosophy.md`, `docs/cheat-sheet.md` (the opening), `README.md`,
`dev-docs/scenarios.md`, the index and principles of `dev-docs/design-rules.md`,
`dev-docs/guide/README.md` and pages 2, 5, and 12, `docs/adding-a-format.md` (the
opening and "What is not supported yet"), `dev-docs/IDEAS.md` (formats and detection;
salvage status was checked against `open_archive` and the ideas page was not used for
it), `openspec/project.md` on deferred work,
`dev-docs/investigations/archive-writing-design.md` (status only),
`dev-docs/threat-model.md` section 4's opening, ADRs 0001, 0002, 0004, 0007, 0010, 0011,
and 0019, `review/outside-newcomer-2026-11-08/SUMMARY.md`, and the public signatures in
`src/archivey/__init__.py`, `core.py`, `reader.py`, `formats.py`, and `config.py`.

Counts (modules, lines, `__all__`, diagnostic codes, which readers import
`archivey.internal`) were taken at `183e3911`.

## What was not done

No bug hunt, no handbook pass, no benchmark, no comparison with other open pull
requests, and no measurement of downloads, dependents, or agent behavior. Where the note
says an agent trial or a backup corpus was not run, that is the gap.

## Deliverable

- [`SUMMARY.md`](SUMMARY.md) is the analysis, including what to leave alone and an order
  of work.
- [`QUESTIONS.md`](QUESTIONS.md) is the decision list and the unknowns.

There is no findings table and no theme file. Nothing here is a live TODO for the code.
A decision that comes out of it belongs in `VISION.md`, `dev-docs/design-rules.md`, or
the plugin guide, in the change that carries it.
