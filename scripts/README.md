# scripts/

The commands people run sit at the top: `check.sh` (every fast gate), `test.sh` (the
library's test suite), `setup-dev-env.sh` (provision a machine) and
`install-git-hooks.sh`. Everything else is in a folder by kind, because each kind needs
a different sort of attention.

| Folder | What is in it | A change to it runs |
|---|---|---|
| `ci/` | What `ci.yml` and `atheris-fuzz.yml` run to test the library: the queue scope rule, the native-module runner, the JUnit summaries, the unrar, unar and 7-Zip installers | every leg |
| `fixtures/` | Generators of the committed test fixtures and the pins library tests read | every leg |
| `checks/` | Repository gates `check.sh` runs: the API surface, the docs tree and links, OpenSpec, tracker URLs | every leg (a library test runs `api_surface.py`) |
| `investigations/` | Benchmarks, stress runs, sweeps, one-off repros and `exploration/`; several are run by scheduled workflows or by library tests | every leg |
| `review/` | The review loop and the review tooling around it | the pull request set |
| `release/` | `release.py` | the pull request set |
| `docs/` | Hooks the docs build loads (mkdocstrings, llms.txt) | the pull request set |
| `tests/` | The tests of everything here; they never import `archivey` | the pull request set (in the lint job) |

"Every leg" means the merge queue runs the whole matrix. "The pull request set" means
it runs only what a pull request push runs. `ci/ci_scope.py` holds the rule:
`NOT_FULL` lists the last four folders, and everything else under `scripts/` counts as
a full-run path, a new folder included. `tests/test_ci_scope.py` fails when a library
test reads, or `ci.yml` runs, a file in one of the four.

A new script goes in the folder that matches its kind. If a library test reads it, or
`ci.yml` runs it, it cannot go in a folder that skips legs. Its test goes in `tests/`.
