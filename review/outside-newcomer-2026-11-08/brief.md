# Outside review 1: a newcomer evaluates archivey 0.3.0

Run 2026-11-08 outside this repository's tooling, with ChatGPT in agent mode (a non-Claude
model with a terminal and a browser). It installed archivey 0.3.0 from PyPI and read only the
published docs and `llms-full.txt`: no repository source, design notes, issues or pull requests.
Prompt A produced [`newcomer-review.md`](newcomer-review.md); prompt B, sent in the same chat,
produced [`hostile-objections.md`](hostile-objections.md). Both reports are kept as returned,
except for one link to a private file store. [`SUMMARY.md`](SUMMARY.md) has the triage.

## Prompt A

```
You are a senior Python developer deciding whether to adopt a library called "archivey" for a real project. You have never seen it before and nobody from the project will answer questions. Be skeptical: your job is to find out whether it is worth depending on, not to be nice about it.

What archivey claims to be: one Python library that reads many archive formats (ZIP, TAR and its compressed variants, 7z, RAR, ISO and others) through a single API, with safe extraction.

Rules
- Use only what a real newcomer would use: the PyPI package, its published docs at https://archivey-dev.github.io/archivey/ and the single-file docs at https://archivey-dev.github.io/archivey/llms-full.txt. Do not read the GitHub repository's source, design notes, issues or pull requests. You may read the installed package's code only to confirm a bug you already hit, and say when you did.
- Run everything you claim. Every finding must say whether you ran it or only read it in the docs.
- Where a task needs test archives, create them yourself (zipfile, tarfile, the 7z or rar command line tools if you can install them, py7zr, etc.). Include a few malicious or broken ones (path traversal names, symlinks pointing outside, truncated files, a wrong password, a zip bomb with a high ratio).

Steps
1. Install: create a fresh virtualenv, then `pip install archivey` and, separately, `pip install "archivey[recommended]"`. Note the time it takes, what gets pulled in, any warnings, and how clear it is which extra you need for which format.
2. First 15 minutes: from the docs home page only, try to get a ZIP and a .tar.gz listed and extracted. Record where you got stuck or had to guess.
3. Real tasks. For each, write the shortest correct code with archivey AND with the best alternative (zipfile, tarfile, shutil.unpack_archive, py7zr, rarfile, libarchive-c, whichever fits). Install the alternatives as needed.
   a. List every member of an archive of unknown format with name, size, type and modification time.
   b. Extract an untrusted archive safely into a directory (traversal, absolute paths, symlinks, special files, size limits).
   c. Read one member's bytes without extracting the rest.
   d. Stream through a large archive (generate a 1 GB+ tar.gz or 7z) and hash every file, checking memory use and time.
   e. Open an encrypted ZIP or 7z, with the right password and with a wrong one.
   f. Detect and report a corrupted or truncated archive.
   g. Use the command line tool `archivey` (pip install archivey-cli) for listing and extracting.
4. Errors: for each failure you provoked, quote the exception type and message and judge whether a user could act on it.
5. Docs: note anything missing, wrong, contradicted by behaviour, or that you had to find by trial and error.

Output: reply with one Markdown report in exactly this shape, nothing before or after it.

# archivey newcomer review
## Environment
OS, Python version, archivey version, alternatives and versions used.
## Verdict
Would you adopt it? One paragraph, then: Adopt / Adopt with caveats / Don't adopt.
## Task results
A table: task | archivey lines | alternative used | alternative lines | worked? | notes.
## Findings
Numbered. For each:
### F<n>: <one-line title>
- Kind: bug / API friction / docs gap / docs wrong / install / performance / security / error message
- Severity: blocker / major / minor / nit
- Evidence: ran it / docs only
- What I did: the code (short) and the input.
- What happened: exact output or exception.
- What I expected, and why.
## Where archivey is better than the alternatives
Bullets, each with the task it showed up in.
## Where the alternatives are better
Bullets, same.
## Scripts
Every script you wrote, each in its own code block, so the results can be rerun.
```

## Prompt B (same chat, after A's report)

```
Now drop the evaluator role and argue against archivey as hard as you honestly can, using what you learned above plus a fresh read of the docs (same rules: no GitHub source, design notes, issues or PRs).

Give the 5 strongest objections to the library's design or public API, the ones that would make an experienced engineer choose something else or stop using it a year from now. Prefer objections about the shape of the API, the abstraction, the error model, defaults and long-term maintenance over small bugs already listed.

Output exactly this, nothing else:

# archivey hostile objections
For each, ranked strongest first:
## O<n>: <one-line claim>
- Argument: why this is a real problem, in a short paragraph.
- Evidence: what you ran or which doc page/section, quoted.
- Who it hurts: which kind of user and when.
- Fix: what you would change in the public API or docs.
- Cost to change: low / medium / high, and whether it breaks existing callers.
- Strongest counter-argument the maintainers could make, and why you still hold the objection.
## What I would keep
The 3 design choices you would not change, one line each.
```
