# scripts/

The commands people run sit at the top: `check.sh` (every fast gate), `test.sh` (the
library's test suite), `setup-dev-env.sh` (provision a machine) and
`install-git-hooks.sh`. Everything else is in a folder by kind, because each kind needs
a different sort of attention.

| Folder | What is in it | A change to it runs |
|---|---|---|
| `ci/` | What `ci.yml` and `atheris-fuzz.yml` run to test the library: the queue scope rule, the native-module runner, the JUnit summaries, the unrar, unar and 7-Zip installers | every leg |
| `fixtures/` | Generators of the committed test fixtures and the pins library tests read | every leg |
| `checks/` | Repository gates `check.sh` runs: the API surface, the docs tree and links, OpenSpec, tracker URLs, line width | every leg (a library test runs `api_surface.py`) |
| `investigations/` | Benchmarks, stress runs, sweeps, one-off repros and `exploration/`; several are run by scheduled workflows or by library tests | every leg |
| `review/` | The review loop and the review tooling around it | the reduced run (below) |
| `release/` | `release.py` | the reduced run (below) |
| `docs/` | Hooks the docs build loads (mkdocstrings, llms.txt) | the reduced run (below) |
| `tests/` | The tests of everything here; they never import `archivey` | the reduced run (below); the lint job runs them |

"Every leg" means the full run: all of the pull request set on a pull request push,
and the whole matrix in the merge queue. A diff that stays in the last four folders (or
on other paths off `FULL`, such as most docs) gets the reduced run instead. On a pull
request push that is the lint job alone, which runs `scripts/tests/`. In the merge
queue it is the pull request set, on the merged tree, without the queue-only legs.
`ci/ci_scope.py` holds the rule:
`NOT_FULL` lists the last four folders, and everything else under `scripts/` counts as
a full-run path, a new folder included. `tests/test_ci_scope.py` fails when a library
test reads, or `ci.yml` runs, a file in one of the four.

A new script goes in the folder that matches its kind. If a library test reads it, or
`ci.yml` runs it, it cannot go in a folder that skips legs. Its test goes in `tests/`.
