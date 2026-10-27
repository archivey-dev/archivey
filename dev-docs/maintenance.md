# Maintenance runbook

How to keep archivey healthy with little time and a small AI budget. Each section starts
from something that happened and gives the smallest useful action. Most of them fit one
short agent session; a few need only you.

The default answer to most events is "wait and batch". A red scheduled job, a dependency
warning or a new feature request can usually wait for the next patch release. Two things
cannot wait: a security report, and a bug that writes wrong data or writes outside the
destination without an error.

## Cost of each recurring job

GitHub Actions minutes are free on a public repository. So most jobs cost only
attention: a red run is something to read. Two workflows start a Claude session, and
those use the AI plan's quota.

| Workflow | When it runs | Uses AI quota | What a red run means |
| --- | --- | --- | --- |
| `review-loop.yml` | each time the `review` label is added | **yes**, one Opus session per round: up to 5 rounds an agent can ask for, 8 if a person keeps adding the label ([Review loop](review-loop.md)) | the review itself failed to post; re-add the label once |
| `claude.yml` | an `@claude` mention by a person on an issue or PR | **yes**, one session per mention | nothing, unless you asked for something |
| `ci.yml` | each PR push (except documentation-only PRs), each merge-queue group and each push to `main`; its `CI gate` job is the queue's required check; PyPy's core-only suite runs only on pushes to `main` and dispatched runs | no | see [CI is red](#ci-is-red-on-main-or-on-a-pr); it also holds a release until a dispatched run is green on the release PR ([release gate](release-checklist.md#6-version-bump-and-tag)) |
| `docs-checks.yml` | each PR, each merge-queue group and each push to `main` | no | a docs build or OpenSpec gate broke |
| `pr-gate.yml` | each PR | no | never red: it reports `CI gate` as passed so any PR can join the merge queue, where the real `CI gate` in `ci.yml` runs |
| `docs-deploy.yml` | each push to `main` | no | the Pages deploy failed; the site keeps the previous version |
| `ppmd-native-stress.yml` | weekly (Wednesday 05:29 UTC), on demand, and on PRs that change the PPMd code, its child process, its tests or the dependency pins | no | not a required check; see [Known issues](known-issues.md), pyppmd sections |
| `atheris-fuzz.yml` | each PR except documentation-only PRs (short), nightly when `main` moved in the last 3 days | no | a fuzz target found an input; see [A fuzz job found a crash](#a-fuzz-job-found-a-crash); it also holds a release until it is green on the release PR ([release gate](release-checklist.md#6-version-bump-and-tag)) |
| `benchmark-wall.yml` | daily, with a change guard | no | a wall-time ratio moved; see [The benchmark went red](#the-benchmark-went-red) |
| `accelerator-crash-search.yml` | monthly (the 1st) | no | a new rapidgzip crash signature; it also holds a release until it is green on the release PR ([release gate](release-checklist.md#6-version-bump-and-tag)) |
| `accelerator-fuzz-soak.yml` | weekly (Tuesday) | no | accelerated and plain decode disagree; it also holds a release until it is green on the release PR ([release gate](release-checklist.md#6-version-bump-and-tag)) |
| `rapidgzip-resume-stress.yml` | monthly (the 1st) | no | the rapidgzip child process stalled or lost a worker; it also holds a release until it is green on the release PR ([release gate](release-checklist.md#6-version-bump-and-tag)) |
| `conflict-notice.yml` | each push to `main`, and hourly | no | its own script failed; it only comments on PRs |
| `rapidgzip-truncation-sweep.yml`, `writer-timestamps.yml` | only when their own files change, or on demand | no | investigation probes; ignore unless you are working on them |
| `publish.yml` | a `v*` tag, or on demand | no | see [Release checklist](release-checklist.md) §6 |

At the lower budget, review rounds are the cost to control. The implementing agent adds
the `review` label when its PR is ready ([Review loop](review-loop.md)). To refuse a round
on a docs, test or CI PR, add `no-review` to it: a PR with that label gets no round,
whoever asks. Then read the diff yourself.

## CI is red on main or on a PR

1. Open the failed job and read the first error, not the last one.
2. Decide which of these it is:
   - **The PR's own change.** Fix it in the PR.
   - **A flaky test** (passes on re-run, fails in code the PR does not touch). Re-run the
     job once. If it fails again on another PR in the same week, record it in the internal
     tracker and let it wait for a batch. Do not skip or quarantine the test to get green.
   - **A dependency changed** (a new release of a library, a runner image, a Python
     build). Check whether `main` fails the same way. If it does, see
     [A dependency broke](#a-dependency-broke-or-stopped-shipping-wheels).
   - **The `3.15` prerelease leg or `3.15t`** (allowed to fail). Read it, but it blocks
     nothing; see [A new CPython](#a-new-cpython-release).
3. For an agent: "CI failed on PR N in archivey-dev/archivey. Read the failed job log, decide
   whether the PR caused it, and fix it or say why not. Follow `.claude/skills/steward`."

## A fuzz job found a crash

Atheris writes the crashing input as an artifact of the run.

1. Download the artifact. Reproduce it locally: [`fuzzing.md`](fuzzing.md) shows how to
   run one target on one input.
2. If the failure is a Python exception that escapes as something other than an
   `ArchiveyError`, it is an archivey bug: add the input as a regression test and fix
   it. This is a normal small PR.
3. If it is a native crash inside a dependency (rapidgzip, pyppmd, inflate64, brotli,
   lz4, zstd), first check [Known issues](known-issues.md). A known signature needs
   nothing. A new one is an archivey bug, not a vulnerability: [`SECURITY.md`](../SECURITY.md)
   §Scope lists a crash inside an in-process native decoder as a documented limit. Record
   the signature in Known issues and report it upstream. If the crash is in a decoder
   that runs in the caller's process, the usual fix is to run that decoder in the child
   process too (`ProcessIsolation.NATIVE_DECODERS`, `internal/streams/codecs/isolated.py`).
   Use [A security report arrives](#a-security-report-arrives) only when the crash goes
   further than `SECURITY.md` §Scope says, for example memory corruption that the input
   can steer.

## The benchmark went red

`benchmark-wall.yml` fails when a wall-time ratio drifts against the last measured
night, or a case exceeds the 10x sanity ceiling. Shared runners are noisy.

1. Compare the failing case against the merges since the last green run. If nothing in
   that code path changed, it is probably noise. The failing night becomes the new
   baseline, but the job measures again only on a night after a push to `main` (or when
   the last measurement is 30 days old). On a quiet week, run it by hand
   (`workflow_dispatch`, with `skip_drift` to re-seed the baseline).
2. If a merge did change it, decide whether the cost is worth what the merge bought.
   Most of the time it is; write one line in the next CHANGELOG entry.

## A dependency broke or stopped shipping wheels

The core has no dependencies. Every optional package is behind an extra, and archivey
raises `PackageNotInstalledError` (naming what to install) when a member or format needs
one that is absent. So at **run time** a missing package makes some members unreadable,
or, for a few formats, the whole archive (see the table).

The serious case is at **install time**: if one package in `[recommended]` has no wheel
for a new Python and its source build fails, then `pip install archivey[recommended]`
fails for everyone on that Python. The fast fix for that case is an environment marker
that leaves the package out on the Python that has no wheel, for example
`"pyppmd>=1.3.1; python_version < '3.16'"`, in a patch release. The members it decodes
then raise `PackageNotInstalledError` on that Python until the package catches up. The
same PR updates the other places that list `[recommended]`: the table in
`openspec/specs/packaging-and-extras/spec.md`, and `docs/formats.md` and
`docs/install.md` where they say what `[recommended]` reads. The CHANGELOG entry gets a
line for it.

What to do per package if its upstream stops for good:

| Package | Extra | Used for | Users see, if it is absent | If upstream stops |
| --- | --- | --- | --- | --- |
| `pyppmd` | recommended | PPMd in 7z and ZIP; runs in a child process (known native crashes) | PPMd members raise `PackageNotInstalledError` | Leave it out of `[recommended]` on the Pythons it has no wheel for. PPMd is rare; no replacement needed |
| `inflate64` | recommended | Deflate64 in ZIP (Windows Explorer writes it for files over 2 GiB) | Deflate64 members raise `PackageNotInstalledError` | Same marker fix. A pure-Python Deflate64 decoder is possible but slow; only if users ask |
| `backports.zstd` | recommended, Python < 3.14 | Zstandard on 3.11 to 3.13 | zstd members raise on those Pythons | Nothing: 3.14+ has `compression.zstd` in the stdlib, and 3.13 reaches end of life in 2029 |
| `brotli` | recommended | Brotli single files and 7z Brotli | Brotli members raise | Marker fix; `brotlicffi` has the same API and could replace it |
| `lz4` | recommended | LZ4 single files and 7z LZ4 | LZ4 members raise | Marker fix |
| `cryptography` | recommended | AES for 7z, RAR and WinZip AES | AES-encrypted members raise; a header-encrypted RAR or 7z cannot be opened at all; ZipCrypto still works (pure Python) | Very unlikely to stop. If it did: `pycryptodome` covers AES-CBC and AES-CTR |
| `pycdlib` | recommended | ISO 9660 / Joliet / Rock Ridge / UDF | opening an ISO raises `PackageNotInstalledError` | It is pure Python, so it cannot lose wheels. If it stops getting fixes, vendor the version we test against |
| `tqdm` | recommended | CLI progress bars | no progress bars | Drop it; the CLI already works without it |
| `rapidgzip` | seekable (not in recommended) | faster gzip, zlib, DEFLATE and bzip2 with random access; runs in a child process | nothing breaks: archivey uses the stdlib decoders and seeks get slower | Remove the accelerator, or leave the extra in place and let it go stale. Nothing depends on it for correctness |
| `unrar` (external program) | none | compressed RAR members | `PackageNotInstalledError` naming `unrar` (or `unar`) | `unar` is the fallback backend. RAR listing and stored members do not need either program |

When a new major version of one of these breaks a test, pin below it with a comment
(`brotli>=1.2.0,<2`) in a patch release, then lift the pin when there is time.

## A new CPython release

- **A new alpha or beta** (for example 3.16a1): nothing to do. When the `uv` toolchain
  offers it, change the prerelease leg in `ci.yml` to the new version.
- **A release candidate**: the prerelease leg should be on it already. Read the leg once.
  Failures there are usually a dependency without a wheel yet; see above.
- **A final release**: in one small PR, drop `prerelease: true` from both prerelease rows
  in `ci.yml` (the test matrix leg and the `free-threaded-concurrency` `3.Xt` leg), add
  the `Programming Language :: Python :: 3.X` classifier to the root `pyproject.toml`
  (the `archivey-cli` package has no per-version classifiers), and move the "max Python"
  legs (macOS, Windows, core-only, coverage) to the new version.
- **A Python reaches end of life** (3.11 in October 2027): drop it in a minor release,
  not a patch release. Move the "min Python" legs and the `all-lowest` leg to the next
  version, raise `requires-python` in both `pyproject.toml` files, and update
  `.python-version`.

## unrar or unar changes

- CI builds RARLAB unrar from source at a pinned version
  (`scripts/install-rarlab-unrar.sh`, `UNRAR_VERSION`). A new unrar release changes
  nothing until you bump that pin. Bump it when convenient, and read
  `tests/` failures that mention unrar's output format: archivey parses unrar's listing
  and error text.
- The `unar-distro-packages` job in `ci.yml` runs the unar packaged by Debian stable,
  Debian unstable and Fedora. When a distribution updates unar and that job goes red,
  check the two unar entries in [Known issues](known-issues.md) first: a fixed
  upstream bug changes the `expect:` value, not the code.

## A security report arrives

[`SECURITY.md`](../SECURITY.md) is the public policy. The steps:

1. Reports come in through GitHub private vulnerability reporting, which opens a draft
   advisory only you and the reporter can see. Reply within a few days, even if only to
   say you have it.
2. Reproduce it. For an agent, start a session on a **private fork** or in the advisory's
   temporary private fork (the advisory page has a button for it), never in a public PR:
   "Reproduce the vulnerability described in this report against main. Write a failing
   test and the smallest fix. Do not push to a public branch."
3. Fix it in the advisory's private fork, then merge, release a patch version
   ([Release checklist](release-checklist.md)), and publish the advisory. Ask GitHub to
   assign a CVE from the advisory page; GitHub is the CNA, so there is no separate
   request.
4. Write one **Security** line in the CHANGELOG entry.

A native decoder crash is a documented limit, not a vulnerability (`SECURITY.md` §Scope,
and [A fuzz job found a crash](#a-fuzz-job-found-a-crash) for what to do). A report about
one gets a link to [Known issues](known-issues.md), unless it goes further than that
limit.

## A stranger files an issue

1. Label it within a week (bug, feature request, question, or upstream problem). A label
   is enough of an answer at first.
2. For a bug, ask for what the bug-report form asks for if it is missing (version,
   `archivey info`, Python, OS, the archive or how to make it). Without a file that
   reproduces it, most archive bugs cannot be fixed.
3. For a bug with a file: "Reproduce GitHub issue N in archivey-dev/archivey, add the archive
   (or a generated equivalent) as a test fixture, and fix it in a draft PR." Follow
   `.claude/skills/address-linear-issue` for the shape of the work.
4. For a feature request, point at [`IDEAS.md`](IDEAS.md). If it is already there, add
   the issue link to that idea; demand from users is what ranks ideas now.
5. Close an issue you will not act on with a sentence that says why. An open issue
   with no answer for months looks worse than a closed one.

## A patch release

See [Release checklist](release-checklist.md). It says which steps a patch release can
skip.

## Where the rest lives

- [Known issues](known-issues.md): upstream bugs archivey works around, and what to
  check when one gets fixed.
- [Fuzzing](fuzzing.md): running and deepening the fuzz targets.
- [Review loop](review-loop.md): what the `review` label does and what it costs.
- [`AGENTS.md`](../AGENTS.md): the rules an agent session follows here.
