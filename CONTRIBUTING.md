# Contributing to Archivey (v2)

Thanks for working on Archivey! This file is the **coding and testing standards**, the
gates, and the OpenSpec mechanics. The *design* is authoritative elsewhere: the
capability specs under `openspec/specs/`, the handbook under `dev-docs/`, and
`VISION.md`. [`dev-docs/index.md`](dev-docs/index.md) maps where everything lives.

## Getting started

Python **3.11+**. Tooling runs through [`uv`](https://docs.astral.sh/uv/).
`scripts/setup-dev-env.sh` provisions everything — the `unrar` and `7z` binaries, the
`openspec` CLI, the dev environment and the format-on-commit git hook — and agent
environments run it at session start. By hand:

```bash
scripts/setup-dev-env.sh          # idempotent; prints anything still missing at the end
# or, for the Python side only:
uv sync --group dev --extra all   # create/refresh the dev environment
./scripts/install-git-hooks.sh    # required: auto ruff fix+format on commit
```

RAR *data* tests need the system `unrar` binary, and encrypted-ZIP fixtures need `7z`
(`p7zip-full`). Without them those tests skip cleanly — which is the problem: the suite
still reports green while running about a hundred fewer tests. Read the setup script's
last lines. On macOS, Homebrew no longer ships RARLAB `unrar`; the setup script compiles
the same pin CI uses (`scripts/install-rarlab-unrar.sh`).

Then two scripts cover the gates, split by how long they take and how often you run them:

```bash
./scripts/check.sh --fix   # seconds — every fast gate; --fix applies ruff first
./scripts/test.sh          # minutes — the everyday [all] test leg
```

Before asking for review, also run `uv run python scripts/review_prep.py`. It is not a CI
gate; it lists docs still naming what your branch removed or moved, fails on lines left
far wider than their file, and its `red-on-base` subcommand checks a "fails on `main`"
claim (`.claude/skills/address-review-findings/SKILL.md` §5).

`check.sh` mirrors CI's `lint`, `docs` and `openspec` jobs: ruff, **`pyrefly`**,
**`ty`**, the OpenSpec checks, the docs-tree and link checks, the strict docs build and
the check on what that build rendered. The script itself is the list. It runs every gate
even after one fails and lists what failed at the end, so a single run tells you
everything that is wrong. Without `--fix` it writes nothing and answers "will CI pass?".

`test.sh` passes extra arguments through to pytest (`./scripts/test.sh tests/test_zip.py
-k roundtrip`), and `--all-configs` runs the full before-pushing gate described below.

Run the underlying commands directly when you want one in isolation (`--no-sync` avoids a
redundant re-resolve):

```bash
uv run pytest                      # test suite
uv run ruff check                  # lint
uv run ruff format                 # format (apply; CI uses `ruff format --check`)
uv run pyrefly check               # type-check (Pyrefly)
uv run ty check                    # type-check (ty)
uv run pre-commit run --all-files  # optional: framework hooks over the whole tree
```

Pyrefly and ty are scoped to `src/`, `packages/archivey-squashfs/src/` and
`packages/archivey-cpio/src/` (the library and the in-repo plugin packages), so every
command above runs clean with no extra path arguments. **Both type checkers must stay
green** — `ruff` passing is not the gate, and running it alone is the most common
self-inflicted CI failure here.

**Format before you commit.** CI runs `ruff format --check` (and `ruff check`) over
`src/ tests/ scripts/ benchmarks/ packages/archivey-squashfs/ packages/archivey-cpio/`
and will fail on drift. Installing the git hook
(`./scripts/install-git-hooks.sh`) makes this automatic: staged `*.py` under those
paths are `ruff check --fix`'d and `ruff format`'d on commit. If you skip the hook,
run `uv run ruff format` yourself before committing — `ruff format --check` only
reports problems; it does not rewrite files. Prefer the script over
`uv run pre-commit install`: Cursor remaps `core.hooksPath`, and the script installs into
the chained original hooks directory so the hook still runs.

**From a `git worktree`,** both scripts work unchanged. A worktree starts without a
`.venv`, so they create one for it (about a second; uv hardlinks from its cache), and the
tree gets its own environment. One trap if you bypass the scripts: a bare
`uv run --no-sync` in a worktree creates an *empty* `.venv`, after which `pyrefly` and
`ty` report `missing-import` for every optional extra. That output is a missing
environment, not real findings; `./scripts/check.sh` fixes it.

If a gate cannot be run for environment reasons, **say it was not run** rather than
reporting its output. A phantom failure passed off as a result costs the next reader more
than a skipped gate honestly labelled.

**Before pushing a change whose behaviour could depend on which optional libraries are
installed, run the suite in all three dependency configurations CI runs** — optional
libraries change behaviour by their presence *and* their version, so a change that passes
one way can break another (a codec that's absent, a floor-version library bug, an
accelerator that's only installed at current versions):

```bash
./scripts/check.sh && ./scripts/test.sh --all-configs
```

Judge it by what the change can reach, not by its size. A change to a comment, to prose,
or to a test that only reads files off disk cannot vary by dependency configuration, and
`./scripts/check.sh && ./scripts/test.sh` is enough for it; CI runs the other two legs
regardless. Anything touching a codec, a backend, an import, or a version check gets all
three before it is pushed. When you skip the legs, say so and why in the pull request,
so a reviewer is not left guessing whether the gate was run or forgotten.

The three legs, which `--all-configs` runs in order:

```bash
# 1. Current versions, all extras — the everyday leg.
uv sync --group dev --extra all && uv run --no-sync pytest -n auto

# 2. Minimum supported versions — every declared dependency pinned to its floor
#    (`pycdlib 1.22`, `backports.zstd 1.0`, …), so version-specific library bugs in the
#    supported range surface. --no-sync keeps the lowest resolution for the test run.
uv sync --group dev --extra all --resolution lowest-direct && uv run --no-sync pytest -n auto --no-cov

# 3. Zero-dependency core — no extras, no dev group; proves tests needing an optional
#    library skip/xfail cleanly (see the `requires` helper in tests/conftest.py) and the
#    core imports nothing third-party.
uv sync --no-dev && uv run --no-sync python tests/check_zero_dep_core.py \
  && uv run --no-sync --with pytest --with pytest-timeout --with pytest-cov --with pytest-xdist \
     pytest tests/ -q -n auto --no-cov
```

These mirror CI's `[all]`, `[all-lowest]`, and `[core-only]` legs; all three must stay
green. `-n auto` (pytest-xdist) runs the suite on every core; it is not in `addopts`, so
a plain `uv run pytest tests/test_zip.py` stays one process.

CI also matrixes supported **Python versions** (3.11–3.14 on Linux; 3.11/3.14 on
macOS/Windows). Repo `.python-version` pins the default local env to 3.11, so a matrix
job must pin its Python on every `uv sync` / `uv run`, or newer-version legs silently
re-test 3.11. Today the `ci.yml` test matrix sets `UV_PYTHON` and passes `--python`; the
free-threaded job and the stress workflows pin each call with `--python` or `UV_PYTHON`.
Keep that when you add a step.

> **`--resolution lowest-direct` rewrites `uv.lock`**, and every later `uv sync --frozen`
> / `uv run --no-sync` keeps the downgraded set. `./scripts/test.sh --all-configs`
> restores `uv.lock` and the everyday environment on exit. Running the legs by hand,
> restore with `git checkout -- uv.lock && uv sync --frozen --group dev --extra all`. The
> lint and type checkers are pinned exactly in `pyproject.toml` so that leg 2 cannot
> change what the gates report.

A pull request that changes only documentation does not start `ci.yml` (none of its
jobs: lint, test legs, unar and free-threaded legs, benchmark gate) or `atheris-fuzz.yml`.
The docs build and the OpenSpec checks live in `docs-checks.yml`, which always runs. The
list of documentation paths is the `pull_request: paths:` filter in those two workflows;
if a test starts reading a doc file, re-include that file there, as `docs/api.md` is, or
a change to it will skip the test that reads it. `tests/test_ci_doc_paths.py` checks that
the two lists match and
that the re-includes come after every `!` entry. Branch protection on `main` requires no
status checks today. If one is added, it must come from a workflow that runs on every
pull request, because a filtered workflow reports no check at all and the PR would wait
on it forever.

## Cutting a release

See [`dev-docs/release-checklist.md`](dev-docs/release-checklist.md)
(CHANGELOG triage, perf vs previous tag, docs, three-config tests, version bump,
tag, publish). One-time repo rename / PyPI setup:
[`dev-docs/release-repo-cutover.md`](dev-docs/release-repo-cutover.md).
User-facing history lives in [`CHANGELOG.md`](CHANGELOG.md). Pull requests do not edit
it: the release PR writes each version's entry (new features, public API changes and
security fixes one line each, other bug fixes summarized in one line).

Whether a release can be a patch follows
[`docs/how-it-is-built.md`](docs/how-it-is-built.md) §Versioning and stability, and
`scripts/release.py notes` answers it from two sources:

- **`dev-docs/api-surface.txt`** lists the public API one line per item: the public
  submodules, names, signatures, fields, enum values, `ARCHIVE_INTEGRITY_CODES`, and
  the command's verbs, options and exit codes. A pull request that changes any of them runs
  `uv run python scripts/api_surface.py --write` and commits the result;
  `tests/test_api_surface.py` fails until it does.
- **The `needs-minor` label** marks a merged pull request that needs a minor release for
  a reason the file cannot show, such as a call that now gives a different result.

## Tooling decisions

- **Type-checking is Pyrefly + ty** — the library is kept clean on **both**. We do
  **not** use mypy or pyright. What gives *users* correct checks and IDE autocompletion
  is the typed public API plus the `py.typed` marker (PEP 561), independent of which
  checker CI runs; keeping two modern checkers green guards us against either one's
  blind spots. That guarantee holds only while the source also *parses* under the
  checkers CI does not run — a comment whose first token is `type:` is a type comment
  to mypy, and prose there makes the file unparseable in the consumer's own run.
  `tests/test_no_stray_type_comments.py` is what keeps that true.
- **Coverage is reported, never gated.** `pytest-cov` produces a report you can eyeball;
  there is no `fail_under` threshold. CI measures it on one leg only (ubuntu, py3.14, the
  `coverage: true` row in `ci.yml`); the others pass `--no-cov`, because tracing doubles
  the run on 3.11. Aim for meaningful coverage through the tests
  below, not a number.
- **Zero-dependency core.** The core (incl. native 7z read + RAR metadata) imports no
  third-party packages. Everything else is an optional extra (see
  `openspec/specs/packaging-and-extras/spec.md`). Don't add a runtime dependency to the
  core.

## Coding standards

Design questions (what a default should be, what a damaged archive should do, whether
two formats should agree) are settled by
[`dev-docs/design-rules.md`](dev-docs/design-rules.md) before anyone asks the
maintainer.

- **Keep it simple and well typed.** Prefer straightforward code over cleverness; type
  everything that's part of, or feeds, the public API.
- **Share code that must agree; copy code that agrees by coincidence** (DR-23a). Before
  factoring out duplicated code, ask whether a change to one copy must reach the other.
- **Don't accumulate debt — clean as you go** (DR-23). When you touch something, leave it
  in the shape it *should* have: a rename, a moved file, an updated doc or spec, or a small
  refactor goes in this change. Renaming a type or changing a contract updates the prose
  docs and the `openspec/specs/` that describe it in the same change. The exception is a
  cleanup that would resolve a genuine design discrepancy: surface it (see "Working with
  the specs") instead of silently picking a direction.
- **A pre-existing bug in the mechanism this change is already editing is fixed here,
  when the fix is proportionate.** Finding one mid-change is not a reason to open a ticket
  and move on: it lands in this PR, where the reviewer can see it against the code it
  belongs to. Being in a file the change touches is not enough on its own — the test is
  the mechanism under change, not the file. What does *not* land here is a
  **sweep**: the same mistake across files this change does not touch, or a rename that
  ripples through specs and archived changes. That is its own PR; anything not yet
  picked up is tracked internally, not parked in a file in the repo. The line is whether
  you are still in the code under review, not whether the bug is old.
- **Leave the code self-explanatory.** The *resulting* tree — names, structure, and
  nearby comments — must make sense to a future editor who never saw the PR. They will
  read the current code, not the diff or the OpenSpec change / `design.md` / PR body
  that motivated it. Those docs are for approach and contract; they are not a
  substitute for local clarity. Reviews in this repo cold-read the changed code before
  loading design narrative and treat non-obvious logic that only makes sense after
  external prose as important documentation debt (see `code-review-skill`'s `reference/code-pr.md`).
- **Comments explain *why*, not *what*.** Match the comment density and style of the
  surrounding code. Don't narrate what the code obviously does; do explain non-obvious
  decisions, format quirks, and edge cases (these archives are full of them). For a
  complex decision, a comment **may point** at a spec, `dev-docs/decisions/`, architecture
  note, exploration, or OpenSpec change — but **summarize the reason inline whenever
  possible** so the pointer is optional depth, not the only explanation.
- **Write the comment so it has one reading.** Sentence shape for comments, like all
  prose here, follows [`AGENTS.md`](AGENTS.md) §Writing English. It decides how you
  write a comment; the two rules above decide whether to write one and what it says,
  and they win where the two ever pull apart.
- **Cross-references in docstrings use Sphinx roles**, such as
  ``:class:`~archivey.ArchiveMember` ``. The roles accepted are `:class:`, `:meth:`,
  `:func:`, `:attr:`, `:data:`, `:const:`, `:exc:`, `:mod:`, `:obj:` and `:any:`, each
  with an optional `py:` domain. `SphinxRolesToAutorefs` in `scripts/griffe_extensions.py`
  turns them into links on the API page, and `scripts/check_docs_rendered.py` fails the
  docs build when one leaks as text, or when its target does not resolve and is not on
  the check's list of targets known to have no anchor. Pages under `docs/` are Markdown
  that nothing rewrites, so there use mkdocstrings syntax:
  ``[`ArchiveMember`][archivey.ArchiveMember]``.
- **Comments describe the code as it is, not how it got there.** A comment in `src/` is
  read by someone who never saw the change that produced it, so it must not depend on
  that change being remembered. Three things this rules out:
  - **History.** "Previously", "the old implementation", "this change", "we used to", a
    PR number, an OpenSpec change name, the name of the work batch a change belonged to
    (`Parcel B`, `Wave 1`), or a correction of an
    argument nobody else can see. If the
    superseded approach is worth recording, it goes in `dev-docs/decisions/` or the
    format handbook, not in a comment next to the code that replaced it.
  - **Claims stronger than the code.** A comment that states a bound, a ratio, or an
    invariant asserts something a reader will rely on. Say what is actually guaranteed,
    or measure it — "roughly 1:1 with the header" where the proven bound is 4× is a
    defect, not a rounding.
  - **References to what you just removed.** After an edit, re-read the comments in the
    files you touched: a comment naming a deleted call site, or explaining a case the
    change made unreachable, is now wrong. This is the single most common finding in
    this repo's reviews, and it is cheapest to catch before pushing.
- **A `readinto` releases every view of the caller's buffer before it returns**
  (`with memoryview(b) as view:`), test doubles included. The caller may resize the
  buffer next, and PyPy frees a dropped view only at a collection; the full contract is
  in `try_readinto`'s docstring.
- **Read a flag from a C extension by its truth, not its type.** PyPy can read a C `bool`
  member as the int 1 (dev-docs/known-issues.md, "PyPy: a C `bool` member reads as an
  int"), so `isinstance(value, bool)` drops it.
- **Match the surrounding code.** Naming, structure, and idiom should read like the file
  you're editing.
- **A `str` regex matches ASCII unless it means Unicode.** On a `str` pattern `\d`,
  `\w`, `\s` and `\b` match Unicode digits, letters and spaces, and `re.IGNORECASE`
  folds `ı`, `İ`, `ſ` and the Kelvin sign into ASCII letters: `0.7z.٠00` read as a
  volume name. Write `[0-9]`, `[A-Za-z0-9_]` or `[ \t]`, or pass `re.ASCII`.
  `tests/test_src_regex_ascii.py` enforces it.
- **Type-checker suppressions must be justified, and are a last resort.** A bare
  `# type: ignore` that hides a *fixable* error is not allowed — it lets a real bug
  through and silently rots. Before suppressing, fix the type model (e.g. declaring the
  named `ArchiveFormat` instances as `ClassVar`s removed ~20 `# type: ignore`s *and* the
  errors they were masking). When a suppression is genuinely unavoidable (a checker bug,
  or a third-party stub gap), it MUST:
  - be **specific to the checker that errors**, in that checker's native form:
    `# pyrefly: ignore[<code>]` or `# ty: ignore[<code>]`. Those bracketed codes
    are validated — a wrong or invented code restores the error. `# type: ignore[attr-defined]`
    is **not** specific here: Pyrefly does not check the bracketed code, so that form
    silences every future error on the line. Never a bare `# type: ignore`. Use only
    the directive of the checker that actually reports the error (they disagree).
  - carry an **inline reason** on the same line or just above, saying *why* it's needed
    and ideally linking the upstream issue.

  An unjustified or non-specific suppression should be treated as a review blocker. The
  library is kept clean on **both** Pyrefly and ty precisely so neither checker's blind
  spot can hide an error the other would catch — don't defeat that with a suppression.
- **Every resource bound is reachable from the public config** (DR-9). Guards against
  hostile input belong on the limits objects of `ArchiveyConfig`, where a user who needs a
  bigger archive can raise them, including to `UNLIMITED`. Do **not** add a second ceiling
  as a module constant inside a parser or reader: it cannot be lifted. A bound that is
  structural rather than policy says why in a comment at the constant and gets a spec row,
  not a quiet `_MAX_…`.
- **Never silently drop or clamp data.** Truncating an over-long read, clamping a seek
  past a boundary, or discarding a consumed count desynchronizes the stream for every
  later caller and turns a detectable error into wrong bytes. Raise, with a message that
  says which invariant was violated. Where `streamtools` cannot raise an `ArchiveyError`,
  `ValueError` is the right type (maintainer decision on #326).
- **Subprocess calls pass an argument list.** `unrar`, the fixture `7z`, and anything
  else spawned from this codebase take a list of arguments, never a single string with
  `shell=True`. Archive member names are attacker-controlled: a name is a value passed to
  the process, never text interpolated into a command line.
- **Secrets stay out of logs, `repr` and exception messages.** A password or key is
  handled, never displayed. An exception raised on a wrong password says that the password
  was wrong, not what was tried — the message ends up in a caller's log.
- **The public / `internal/` boundary is a contract, not a layout.** Code outside
  `internal/` is frozen surface; `__all__` is grown deliberately, one export at a time,
  with the reason in the PR. A public class is *defined* in a public module
  (`archivey/types.py`, `archivey/detection.py`, …), not under `internal/` and
  re-exported: its `__module__` is what `pickle` records. `tests/test_public_api.py`
  enforces this; `ArchiveStream` is the one listed exception.
- **The CLI uses only public API.** Nothing under `src/archivey/cli/` imports from
  `archivey.internal`; `tests/test_cli_uses_public_api.py` fails on one that does. One
  import is allowlisted in that test: `--track-io` imports
  `archivey.internal.measurement`, because the CLI is also a debugging tool for the
  library, and IO measurement is deliberately not public API. Otherwise, the CLI
  needing something internal means the public API has a gap. That includes a private
  attribute of a library object it would read, or a library exception's message it
  would match (argparse's attributes and messages are not the library's). The same
  test's second allowlist holds the two `ExtractionReport` dry-run fields, for the
  reason the `cli` spec records. Close the gap through the ordinary `__all__` decision
  above, or in a public module that is not re-exported (`archivey.terminal` holds the
  display helpers any front end needs, and `archivey.paths` the `name (N)` rename
  spelling), or do without: the library's enum-spelling helpers are internal, so the
  CLI derives its option choices from the enums and maps a parsed choice back to its
  member itself (`src/archivey/cli/choices.py`).
- **Report from what the run left behind, not a re-derivation of it.** When code has to
  report what an operation did or would do (a dry run, a preview, a summary line), read
  the answer from what the operation left behind, such as the tree it wrote, rather than
  re-deriving it from its per-item results. Where the operation tears that state down,
  capture it before it does and hand it to whatever reports. That hand-off is a
  public-surface question: a public field, a public module, or an exception recorded in
  the spec, per "The CLI uses only public API" above. A re-derivation is a second
  implementation, and it drifts: the CLI's dry-run line naming where a single top-level
  folder would land was re-derived from per-member results and broke in a new way in
  four review rounds running, until it read the top-level entries the dry run recorded
  before removing its scratch tree (#531). Where nothing usable is left behind, the
  re-derivation needs the comparison test in "A parity promise gets its comparison test
  first" below.
- **Cost signals stay honest, and nothing silently re-decompresses.** `ListingCost` and
  `AccessCost` are promises a caller plans against, so a change that makes a path more
  expensive updates them. Reading two members out of one solid block must not decode the
  block twice without the cost signal saying so: a tiny fixture hides it, and the caller
  pays in production. Claims about speed cite bytes decompressed and seeks, or an existing
  `benchmarks/` run — not wall time on one machine.
- **Picking an exception type means checking what catches it.** In this codebase an
  exception type is control flow: `TruncatedError` from the wrong layer aborts
  password-candidate iteration, and a `CorruptionError` where a wrong-password error was
  expected ends the same iteration early. Before choosing or changing a type, grep for
  what catches it upstream and say in the PR what you found.
- **Exception translation is specific.** All errors caused by archive problems must
  surface as `ArchiveyError` subclasses, via each reader's per-library translator:
  - Map *known* third-party exceptions to the right `ArchiveyError`
    (`CorruptionError`, `TruncatedError`, `EncryptionError`, …).
  - **Never** add a catch-all that converts *any* `Exception` — that hides bugs. If an
    exception is unrecognized, let it propagate (return `None` from the translator) so we
    learn about it and can map it deliberately.
  - Genuine `OSError` / `KeyboardInterrupt` / `MemoryError` propagate unchanged, except
    where a spec says otherwise (e.g. safe-extraction catches a per-member filesystem
    `OSError` under `OnError.CONTINUE` — see `openspec/specs/safe-extraction/spec.md`).

## Testing standards

- **Test behaviour, not internal implementation.** Assert on what a public API returns
  and does, so refactors don't break tests gratuitously. *Narrow exception:* the
  low-level building blocks — stream primitives/helpers, format parsers, the codec
  layer — should also get focused **unit** tests of their internals, because they're
  shared foundations and their corner cases are exactly what break formats downstream.
- **Leaked OS resources fail the test.** `tests/leak_oracle.py` is an autouse oracle
  (disable with `ARCHIVEY_LEAK_ORACLE=0`) that fails a test which leaves a child process
  running or an owning stream unclosed. Close an owning stream in the test that
  constructed it; `@pytest.mark.allow_resource_leaks` skips the fail, not the reap. The
  module docstring has what it detects and what it deliberately does not.
- **Measure a memory peak with `tests/memory_util.traced_peak`.** Do not start and stop
  `tracemalloc` by hand for a peak. On free-threaded 3.13 a garbage collection that runs
  inside the window adds memory in proportion to every live object in the process, so a
  peak bound fails in the full serial suite and never alone. The helper collects first
  and keeps the collector off while it measures; its module docstring has the numbers.
  A test that bounds retained memory (`test_audit_tar_streams.py`, `test_codecs.py`) is
  unaffected: the collector's working memory is freed by the time the collection ends.
- **Hit the corner cases.** Especially corrupt, truncated, and encrypted archives;
  wrong passwords; empty/zero-length members; unusual names and metadata; non-seekable
  sources. When porting or writing a reader, deliberately trigger each error path so the
  exception translator is exercised.
- **Use the declarative corpus.** Tests are driven by API-agnostic archive specs +
  expected data (generated on demand and cached); cross-validate against the `py7zr` /
  `rarfile` / frozen-DEV oracles where applicable (see
  `openspec/specs/testing-contract/spec.md`).
- **Fixing a bug? Red–green TDD.** First write a test that **reproduces** the bug and
  **fails**; then make it pass with the fix. The failing test is the proof the bug
  existed and that you fixed *that* bug.
- **A guard test must be shown to fail.** Red–green is not only for bug fixes. A new
  property test, inventory test, static guard, or assertion added to defend an invariant
  is done only once you have broken the thing it names and watched it fail. Write down in
  the PR which mutation you applied. A test that passes against the unfixed or
  un-guarded code is worse than no test, because it reports coverage that does not
  exist — this repo has shipped a property test that passed a `return block_start`
  mutant, an inventory test that passed vacuously, and a test whose fixture could not
  reach the path it named. For a test the PR says fails on `main`,
  `uv run python scripts/review_prep.py red-on-base <test ids>` runs it against the
  merge base's `src/` and prints a table for the PR body.
- **A test you move or refactor still tests what it did.** When a change moves tests
  between files or swaps their setup for a shared helper, run the suite before it (twice,
  for the coverage baseline) and after it, and compare the runs with
  `scripts/compare_test_runs.py` (its docstring has the commands). It fails when a test
  is missing, new or has a different outcome, and when a test lost a large share of the
  `src/` lines it ran: a test whose body no longer reaches the library still passes, so
  only this catches it. Per-test coverage varies a little between runs, so smaller
  losses do not fail; they are listed, and a reviewer reads them. Neither check reads
  test code: a test that makes the same calls and has lost an assertion reports `same`
  on both, so the moved tests still get read. Paste both results into the PR.
- **A parity promise gets its comparison test first.** When a feature promises to behave
  like another archivey path (a dry run like a real extraction), write the test that
  runs both and compares them first, before the feature itself. This generalises the
  oracle cross-validation above from third-party libraries to archivey's own paths. Run
  it over every surface the promise covers: each entry point, the CLI as well as the
  library, and each spelling of the inputs (a relative path, one through a symlink, one
  with `..`). Where the promise has stated exceptions, the test asserts each one
  explicitly rather than skipping the case. Like any guard test, the comparison has to
  be shown to fail, and the environment is one of its surfaces: two runs that agree
  because both took another path (a missing symlink privilege, a skipped backend, an
  absent extra) compare nothing. A surface you don't compare is where a divergence
  ships, and in practice where review finds it.

### Cross-platform traps (you develop on Linux; CI runs Windows and macOS)

The test matrix covers Linux, macOS and Windows, but your container is Linux — so this
class of failure lands *after* you push, and it has repeatedly cost a review round. Check
new tests and new message-formatting code for each of these:

- **`read_text()` / `open()` without `encoding="utf-8"`.** Python's default encoding on
  Windows is the ANSI code page (cp1252), not UTF-8. Any test that reads a repo source
  file — static/AST guards especially — will raise `UnicodeDecodeError` there the moment a
  source file contains a curly quote or an accented character. Always pass
  `encoding="utf-8"` explicitly.
- **Control characters and `:*?"<>|` in on-disk filenames.** Windows rejects them with
  `WinError 123` at *creation* time, so a test that writes a hostile member name to disk
  fails before it reaches the behaviour it meant to assert. Use a Windows-legal spoof
  (U+2028 and friends) for the portable case, and mark the ANSI variant with the repo's
  existing `_ANSI_ONLY` marker.
- **Path separators in compared strings.** A native `Path` interpolated into a message
  renders `C:\Users\…` on Windows, and backslashes double once the text is escaped for
  terminal display. Render paths through `terminal.display_path()` before they enter a
  message, and compare against `as_posix()` rather than `str(path)`.
- **Filesystem case-insensitivity.** macOS and Windows collapse `A.txt` / `a.txt`, which
  changes name-collision behaviour. If a test depends on two members differing only by
  case, it is testing something different on each platform.
- **Path comparison folds case on Windows.** `WindowsPath("FILE") == WindowsPath("file")`
  is `True` whatever the filesystem, and `in` and `sorted()` on paths fold case too. When
  a comparison is about the *spelling*, compare `str(path)` or `path.name`. Only Windows
  CI catches this: on a case-insensitive macOS volume `PosixPath` comparison stays exact.
- **`os.kill(pid, 0)` is not a liveness probe on Windows.** There `os.kill` calls
  `TerminateProcess`, so the "probe" kills the process. And a pid is free for reuse as
  soon as the last handle to it closes, so a bare pid you no longer hold may name an
  unrelated process. Check a child you own through its `Popen` (`poll()`), never
  through its pid.

### Fuzzing

Atheris coverage-guided fuzz runs on every PR (short sharded budgets) and nightly; the
workflow, local smoke runs and per-target budgets are in
[`dev-docs/fuzzing.md`](dev-docs/fuzzing.md). Mutation fuzz
(`tests/test_mutation_fuzz.py`) and the `ARCHIVEY_FUZZ=1` parser harnesses run in the
ordinary suite.

## OpenSpec changes

Committed work is an OpenSpec change under `openspec/changes/<change>/` — propose
changes there, don't edit shipped specs ad hoc. The default schema is `library`
(proposal → compact specs + design → tasks): specs stay dense (signatures, matrices) and
`design.md` holds investigations and decisions. Use `--schema minimalist` for tiny
changes. See `openspec/schemas/library/README.md` and `openspec/config.yaml`.

The setup script installs the `openspec` CLI. By hand, install the scoped package into a
prefix that is writable and already on `PATH` (the bare `openspec` package on npm is an
unrelated stub; a plain `npm install -g` fails with `EACCES` on the cloud images):

```bash
npm install -g --prefix "$HOME/.local" @fission-ai/openspec   # known-good: 1.4.1
openspec list                     # in-flight changes + task progress
openspec validate --all           # validate all specs and changes
openspec validate --strict <item-name>
openspec archive <change> --yes   # apply the deltas to openspec/specs/
```

### Archiving an OpenSpec change

**Merging a change does not apply it.** A proposal's deltas reach the authoritative specs
only when someone runs `openspec archive <change> --yes` and commits the resulting
`openspec/specs/` updates.

**Archive in the PR that finishes the change.** Most changes here are proposed,
implemented, and finished in one PR, and that PR is where the archive belongs — the
deltas are what make `openspec/specs/` describe what actually ships. Deferring it left
`main` with the wrong authority three times running. CI enforces this on pull requests
and on `main` (`scripts/check_openspec_archived.py`).

Practically, make the archive the change's **last task**, so checking the final box and
applying the deltas are the same act. Most of the archived corpus is already written this
way.

**When the change genuinely is not finished, leave the trailing task unchecked.** That is
the escape hatch, and it costs one character. Use it when the design is still moving under
review (archiving early is what turns a review round into a revert-and-rework), or when an
archive is deliberately batched with a sibling change. The gate reads finished-ness from
the checkboxes: an unchecked box is an honest "not done yet", while a checked one is a
claim that the change has landed in the specs. Do not check the last box to make a
progress report look tidy.

**`openspec validate --strict` does not check that a `MODIFIED` header names a
requirement that actually exists** in the parent spec, so a mis-targeted delta can
validate green and silently do nothing on archive. For a non-trivial delta, verify with
a dry-run archive (apply on a scratch tree, diff `openspec/specs/`, then reset).

**Retiring a whole capability has no delta form.** Removing every requirement leaves a
spec with none, which `openspec archive` refuses to write; deleting the directory first
makes archive read the same delta as a request to *create* the capability. Delete
`openspec/specs/<capability>/` by hand, keep only the deltas that modify surviving specs,
and record the retired requirements and their reasons in the change's `README.md` so the
archived change still explains itself. Worked example:
`openspec/changes/archive/2026-09-02-retire-archive-writing-specs/`.

### Writing a delta requirement body

**Do not write "this change" in a requirement body or its scenarios.** It is unambiguous
while you are writing it and meaningless the moment `openspec archive` folds that body
into `openspec/specs/`: the change has moved to `openspec/changes/archive/` and a reader
of the authoritative spec cannot tell which one you meant. Ten such phrases had
accumulated across five capabilities before anyone counted, and most were not worth
naming even then — they were pre-merge arguments ("this change is a strict increase in
what is stamped", "it SHALL ship anyway because…") whose other referents, the prior
behaviour and the pre-change tree, had gone too.

State the contract as it stands. The reasoning behind it goes in the change's
`design.md`, which `openspec/config.yaml` rules.specs already asks for. Naming the change
id is the last resort, for a cross-reference a reader of the archived spec would follow.
`scripts/check_openspec_self_reference.py` enforces this over `openspec/specs/` and over
in-flight deltas; the two changes that predate it are grandfathered in its `PENDING` set,
and it fails if an entry there goes stale, so the list can only shrink.

## Working with the specs (please read)

When you hit a **discrepancy** — specs disagreeing with the prose docs, or the specs
disagreeing with each other — **pause and ask the maintainer** rather than silently
picking an interpretation. A conflict usually means a decision hasn't been made yet, and
guessing bakes the wrong one into the code. Surface it (an issue, a PR comment, or an
`openspec/changes/` proposal) and let it be decided explicitly. When the design simply
does not cover your case, check
[`dev-docs/design-rules.md`](dev-docs/design-rules.md) first: if a rule settles it, do
what it says and name the rule in the PR; ask only when no rule does.

**Thin as you go.** Specs stay the authoritative *machine* contract for now (DP1 = C in the
specs-to-handbook discussion below), but we are migrating executable detail into
**tests** and human truth into **handbook** pages — see
[`dev-docs/discussions/2026-09-specs-to-handbook-and-tests.md`](dev-docs/discussions/2026-09-specs-to-handbook-and-tests.md).
On every PR that touches `openspec/specs/` or a change delta:

- Prefer a **pytest** over a new WHEN/THEN scenario.
- When you touch a requirement that is already covered by tests, **collapse or delete**
  redundant scenarios rather than adding siblings “for completeness”.
- Leave that capability **no denser than you found it** (preferably thinner).
- Keep in the spec only what tests cannot say well (signatures, non-goals, MUST refuse,
  packaging / threat posture).

## Where does a new doc go?

Five questions, in order. The first `yes` wins.

1. **Would someone who only *uses* the library need it?** → `docs/`, **and add it to
   `mkdocs.yml`'s nav in the same commit**. Curated "why we chose X" one-liners for
   curious users belong inline on the page that raises the question, not as a new
   page per decision. Use
   [`write-user-docs`](.claude/skills/write-user-docs/SKILL.md) for structure and voice,
   which outranks STE on user docs. The standing prose rules are [`AGENTS.md`](AGENTS.md)
   §Writing English.
2. **Is it current maintainer truth about a format or cross-cutting topic?** → a
   living handbook page `dev-docs/formats/<format>.md` or `dev-docs/topics/<topic>.md`
   (rewrite in place; light decision bullets, not a new ADR). **Create the file in the
   same PR that needs it** — do not add empty `formats/` / `topics/` trees. Format pages
   follow the shape (At a glance, then sections 1–9) in
   [`dev-docs/formats/README.md`](dev-docs/formats/README.md) §Format page structure, with
   [`dev-docs/formats/zip.md`](dev-docs/formats/zip.md) as the worked example.
3. **Is it rare repo-wide policy that will not fit a handbook page?** → a new ADR in
   `dev-docs/decisions/`, ADR-shaped (Context / Decision / Consequences, tens of
   lines). If it needs an `## Open questions` section, it is not an ADR yet — grill
   first (`/grill-with-handbook`).
4. **Does a contributor need a live register or runbook *today*?** → `dev-docs/`
   (e.g. threat model, known issues, release checklist).
5. **Is it finished evidence — an investigation, a superseded design, a lab
   notebook?** → `dev-docs/investigations/`, or `dev-docs/history/` for prose that a
   newer document replaced.

If it is a *review*, it belongs to the `review/` lifecycle. If it is a *proposed
behaviour / contract change*, it belongs to `openspec/changes/` so the authoritative
main specs stay in sync (prefer `--schema minimalist` when proposal/design would only
be agent bus). Scenario-row widenings that do not change a requirement's SHALL
(extra producer names, the same error type) may edit `openspec/specs/` directly
when the maintainer says so — do not open a change folder just to add a matrix
row. Human conclusions still land on handbook pages — specs are the binding
contract, not the primary reading surface
([`dev-docs/pair-workflow.md`](dev-docs/pair-workflow.md)).

**Same PR as code:** when a change falsifies a handbook or published-doc claim, update
that page in the same PR.

**Lessons.** When a fix or a review round teaches something, ask: if nothing wrote it
down, would a future engineer reading the final code still be likely to repeat the
mistake or redo substantial investigation? Effort and diff size do not count. If no,
write nothing. If yes, write it in the same PR, in the home that already exists for it:
a format trap in that format's handbook page (`dev-docs/formats/<format>.md` §5 Sharp
edges, or §6 Decisions for a choice), a coding trap here, a live defect in
[`dev-docs/known-issues.md`](dev-docs/known-issues.md), the evidence in
`dev-docs/investigations/`. A ruling that generalises across formats belongs in
[`dev-docs/design-rules.md`](dev-docs/design-rules.md), but an agent only proposes one
there; the maintainer writes it. (The test is adapted from the `ce-compound` skill of
EveryInc/compound-engineering-plugin, MIT.)

**The invariant:** everything under `docs/` is published and is for users; nothing
else lives under `docs/`. That is why maintainer material sits in `dev-docs/` rather
than under `docs/` behind an exclusion list — an exclusion list needs a second list
to keep in sync with the first, and drift between the two is what left six pages
published, URL-reachable and absent from every menu.

`scripts/check_docs_nav.py` enforces it, along with the rule that a published page
must not link into unpublished material: prefer inlining the fact, and where the
depth is genuinely worth keeping, link the file on GitHub with an absolute
`https://github.com/archivey-dev/archivey/blob/main/…` URL.
