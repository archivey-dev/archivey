# How it is built

Almost all of archivey's code, tests and documentation are written by AI coding agents, mostly
Claude Code and Cursor. The maintainer designs the library, makes the decisions, directs the work
and reviews it. If you're deciding whether to trust a library built this way, this page explains
who decides what, how a change gets made and tested, and what that does and doesn't promise.
Archivey is a work in progress, and so is the process described here.

## Who decides what

The maintainer designed the building blocks and the public API: one opener, one reader and one
member model for every format; reading as a stream, with a member's bytes decoded as you read them;
and the modes you choose at open, such as `streaming=True` for a pipe, `seekable_members=True` and
`concurrent_operations=True`. [Philosophy](philosophy.md) explains the thinking behind them.

The maintainer also sets the scope, the architecture and the
[design rules](https://github.com/archivey-dev/archivey/blob/main/dev-docs/design-rules.md) the agents
follow, and rules on the trade-offs they can't settle from the code. Two examples:

- **When formats disagree.** Archivey weighs following each format's official tool, such as `unrar`
  for RAR and GNU tar for TAR, against being the same across formats. Neither wins automatically.
  Device files that store no data are one case where being the same won: every format lists them as
  "other".
- **What counts as damage.** Some problems refuse the archive, and others, which are only unusual,
  are reported as diagnostics.

Decisions are recorded in the repository as
[architecture decision records](https://github.com/archivey-dev/archivey/tree/main/dev-docs/decisions),
[behaviour specs](https://github.com/archivey-dev/archivey/tree/main/openspec/specs) and
[archived change proposals](https://github.com/archivey-dev/archivey/tree/main/openspec/changes/archive).
The agents do the rest: they write the code and the tests, build the test archives, run
investigations and review each other's work. They also draft the docs you're reading, which the
maintainer reviews paragraph by paragraph.

## How a change gets made

AI makes mistakes, so every change is reviewed before it's merged.

1. An agent writes the change, with tests.
2. A separate AI session reviews it, starting from the diff and the repository alone, not from the
   session that wrote the code. Each finding gets a fix or a stated reason, and the fixes are
   reviewed too. The
   [review workflow](https://github.com/archivey-dev/archivey/blob/main/dev-docs/review-loop.md) and the
   instructions the agents follow to
   [review](https://github.com/archivey-dev/archivey/blob/main/.claude/skills/code-review-skill/SKILL.md)
   and to
   [address findings](https://github.com/archivey-dev/archivey/blob/main/.claude/skills/address-review-findings/SKILL.md)
   are in the repository.
3. Anything the agents can't settle from the code or the design rules goes to the maintainer as a
   decision.
4. Sometimes the maintainer reviews the change directly.
5. The change is merged only when review and CI pass. The maintainer merges anything tricky, and an
   agent may merge a straightforward change once its review approves it and CI is green.

Even then, problems and cases nobody thought of creep in. So agents also review the whole codebase
rather than one change, each time with one goal, such as finding bugs, finding dead, redundant or
unclear code, or evaluating the public API. One full review of the codebase ([PR
315](https://github.com/archivey-dev/archivey/pull/315)) produced nearly 700 comments, and a bug hunt ([PR
512](https://github.com/archivey-dev/archivey/pull/512)) found about 40 bugs, each reproduced with a test
and later fixed.

## How it is tested

Review catches mistakes in the reasoning. These checks catch the rest, and each one finds things the
others miss.

- **Thousands of tests on every pull request.** They run on Linux with Python 3.11 to 3.14, on macOS
  and Windows with 3.11 and 3.14, on a free-threaded build, with no optional packages installed,
  with the oldest dependency versions archivey allows, and on PyPy.
- **A test for every fix.** Every bug that has been fixed has a test, and so do many corner cases
  that were only worried about, so a fixed problem can't quietly come back.
- **One set of test archives, built in every format.** Each test archive is described once and then
  written in every format that can hold it, never by archivey itself: by other libraries (`zipfile`,
  `tarfile`, py7zr and pycdlib) and, for RAR and encrypted ZIP, by the `rar` and `7z` programs.
  Every copy must open, list, read back and extract safely. Hand-built hostile archives sit beside
  them: path traversal, links that point outside the destination, decompression bombs, and forged
  sizes and counts.
- **Other libraries as a reference.** Tests check what archivey reads against zipfile, tarfile,
  py7zr, rarfile and `unrar`. Archivey never imports zipfile, tarfile, py7zr or rarfile when it
  runs; `unrar` is also the program it uses to decompress RAR data.
- **Fuzzing.** Every test archive is cut short, bit-flipped, zeroed and padded, and reading it must
  either succeed or raise an `ArchiveyError`. A coverage-guided fuzzer (Atheris) runs over every
  format's parser and every decoder, briefly on each pull request and for longer every night. It
  fixes up checksums so its changes reach the code behind them, and it checks that the optional fast
  decoders give the same result as the standard ones. Property-based tests cover name handling,
  extraction safety and link resolution.
- **Benchmarks.** Each pull request checks numbers that shouldn't change by accident, such as how
  many seeks a read takes and that a solid archive is decoded only once. A daily run measures time
  and fails if things get noticeably slower.
- **A threat model.** Known attacks and gaps are written down with their status, including the
  limits archivey accepts rather than fixes. [Security](security.md) covers what you need to know as
  a user, and the [full threat
  model](https://github.com/archivey-dev/archivey/blob/main/dev-docs/threat-model.md) has the rest.
- **Bugs found in other libraries.** Comparing decoders turned up a use-after-free in pyppmd, three
  decoder bugs in pybcj and a hang in py7zr. Archivey avoids or works around each one.

## What this makes practical

AI lets the maintainer build a better library, faster. It changes what is practical to do.

- **Breadth.** Archivey reads ZIP, TAR, 7z, RAR and ISO archives and ten single-file compression
  formats. That includes encrypted archives, multi-volume sets, self-extracting executables and
  archives inside archives. Each of these has corner cases that libraries usually leave unsupported.
  Here most of them have a test.
- **Hostile input.** Agents are good at the tedious question "what if this field is wrong?", asked
  of every field in every format. Many entries in the threat model are attacks the maintainer
  wouldn't have thought of alone. Two examples are a 7z archive that sizes a memory allocation from
  a count nobody checked, and a password check where the archive chooses how much work each attempt
  costs.
- **Review as routine.** Reviewing every change from zero, and reading the whole codebase again and
  again, would take a team of people. With agents, both are part of the normal workflow.
- **Measurement over memory.** Claims about speed, memory use and seeks are measured, and the
  benchmarks above catch a change that makes them worse.

## Versioning and stability

Archivey follows [semantic versioning](https://semver.org/). Before 1.0, this is what each kind
of release may change:

- **A patch release (0.2.1)** fixes bugs and makes improvements that need no change in your
  code. It may read archives it used to refuse, report a new
  [diagnostic code](errors-and-diagnostics.md), or add a value to an enum that says it is
  open-ended, such as `CompressionAlgorithm`. It doesn't add, remove or change a function,
  class, parameter or attribute. A new code that `DiagnosticPolicy.STRICT` raises waits for a
  minor release, unless it reports damage archivey should already have caught.
- **A minor release (0.3.0)** may change it. A removed or renamed name keeps working for one more
  minor release first and emits a `DeprecationWarning` that names its replacement. A change that
  can't be phased in that way, such as a different result for the same call, has a line starting
  with **Breaking:** in that release's entry in the
  [changelog](https://github.com/archivey-dev/archivey/blob/main/CHANGELOG.md).

Python shows a `DeprecationWarning` by default only when the deprecated call is in your
top-level script, so the changelog's "Deprecated" section is the place to look before upgrading.
To find deprecated calls anywhere in your code, run your tests with
`pytest -W error::DeprecationWarning`.

The public API is what `archivey` and its public submodules export, as listed on the
[API page](api.md). Anything under `archivey.internal` can change in any release.

The same promise covers the `archivey` command's verbs, options and exit codes, as listed on
the [command-line page](cli.md): a removed or renamed one keeps working for one more minor
release and prints a deprecation warning. The text it prints for people to read, such as
messages and summaries, may change in any minor release, so a script should rely on the exit
code and the options rather than on that text. A patch release may add a line of that text, but
it doesn't change or remove one. A minor release may also add a verb, and from
then on that word runs the verb rather than naming a file. A script that passes a path should
write `archivey list <path>` or `./<path>`, which always reach the file.

1.0 comes once early users have run archivey for a while and the API has held up. After that,
breaking changes wait for 2.0. The larger open questions, such as a plugin interface for new
formats, writing archives and an async API, would each add to the API rather than change the
reading API that exists today.

## What this does not promise

- The maintainer doesn't read every line. Agents do the line-by-line reading, and the maintainer
  reads designs, decisions, the tricky parts and review findings.
- AI reviews find a lot, but their blind spots overlap: two sessions of similar models can miss the
  same thing.
- The fuzzing doesn't run at OSS-Fuzz scale. That waits until archivey has more users.
- Nobody can promise that archivey has no security bugs. If you process untrusted archives, take the
  precautions you would with any other library, such as running it with limited privileges or [in a
  process you can stop](security.md#where-the-guarantees-stop).

## Checking it yourself

You don't have to take this page's word for it. The history is public: every [pull
request](https://github.com/archivey-dev/archivey/pulls?q=is%3Apr), its review threads and the decisions
behind it are on GitHub, next to the decision records, specs and threat model linked above.

Reviews are welcome, whether you read the code yourself or point an agent at it. So are bug reports,
questions and pull requests; see
[CONTRIBUTING.md](https://github.com/archivey-dev/archivey/blob/main/CONTRIBUTING.md). If you find a
security problem, please report it privately as [Security](security.md#reporting-a-vulnerability)
describes, not in a public issue.
