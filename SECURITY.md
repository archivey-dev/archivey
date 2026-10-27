# Security Policy

## Supported Versions

Security fixes go into the latest minor release line of `archivey` on PyPI (0.2.x,
from the 0.2.0 release) and into `main`. A fix ships as a new patch release of that line.

| Version | Gets security fixes |
| --- | --- |
| Latest minor release (0.2.x) | Yes |
| Older minor releases | No |
| Pre-releases (`rc`, `a`, `b`) | Yes until the final release of that line is out, then no |

We do not backport fixes to older 0.x lines: the fix for an older line is to update to
the latest release. When 1.0 is out, this policy will be looked at again.

If you are on an older release, please try to reproduce against the latest
before reporting. Older-version reports are still useful for impact assessment;
fixes normally land on current `main` first.

This policy applies to **this** repository (`archivey-dev/archivey`, the v2 library).
The previous implementation lives at [`davitf/archivey-old`](https://github.com/davitf/archivey-old)
and is not covered here.

## Reporting a Vulnerability

Please report security vulnerabilities **privately**. Do **not** open a public
GitHub issue for exploitable bugs, malicious archives, or proof-of-concept
payloads.

**Preferred path:** use
[GitHub private vulnerability reporting](https://github.com/archivey-dev/archivey/security/advisories/new)
(Security → Advisories → Report a vulnerability).

If that flow is unavailable, email the maintainer at
[archivey@davitf.com](mailto:archivey@davitf.com).

Include as much of the following as you can:

- A clear description of the vulnerability and its impact
- Affected `archivey` version and/or commit
- OS and Python version used for testing
- Minimal reproduction steps (or a crafted archive attached privately)
- Expected vs actual behaviour
- Known impact class (path traversal, symlink/hardlink escape, arbitrary write
  outside the destination, DoS/hang, information disclosure, unexpected use of
  an external tool, etc.)
- Suggested fix or patch, if you have one

Please coordinate disclosure: allow time for investigation and a fix before
publishing exploit details.

## Scope

In scope (non-exhaustive):

- Extraction path traversal and destination escape
- Symlink / hardlink traversal during extraction
- Arbitrary overwrite outside the requested extraction directory
- Unsafe handling of archive metadata or member names
- Unexpected command execution through external extractors (e.g. `unrar`)
- Denial of service from malformed or malicious archives (including hangs that
  a caller cannot interrupt)
- Information disclosure via unsafe file access
- Failure to translate corrupt/truncated input into typed `ArchiveyError`s on
  the defended (non-accelerator) parse path

The [known and accepted limits](https://archivey-dev.github.io/archivey/security/#where-the-guarantees-stop)
(a crash inside an in-process native decoder, untranslated `MemoryError`, no CPU or
time bound, accelerators on by default, a crafted `.xz`/`.lz` index after a seek, and
the Windows directory-source gap) are documented trade-offs, not vulnerabilities. A
report that one of them reaches further than the page says is in scope.

Out of scope for private security reports (use ordinary GitHub issues):

- Feature requests, docs typos, and non-security compatibility bugs
- Performance complaints that are not DoS
- Issues that only reproduce with optional accelerators left on when the
  caller’s threat model requires them off (see below) — still welcome as
  ordinary bugs; escalate privately if they enable escape/RCE on the default
  path

## Hardening notes for callers

Guidance for processing untrusted archives — the optional accelerators, the external
RAR program (`unrar`, `rar` or `unar`, and the password `unar` takes on its command
line) in your deployment's trust boundary, and extracting to a
scratch directory before promoting — lives in the user guide, next to the policies it
qualifies:

- [Security](https://archivey-dev.github.io/archivey/security/) — what archivey relies on,
  where its guarantees stop, the limits, and hardening
- [`dev-docs/threat-model.md`](dev-docs/threat-model.md) — the threat model:
  attackers, trust boundaries, defended properties and accepted non-guarantees

## Response Process

A private report on GitHub opens a draft security advisory that only you and the
maintainer can see. The report then goes through these steps:

1. The maintainer confirms receipt in the advisory.
2. The maintainer reproduces the problem and assesses the severity and the affected
   versions with you. The draft advisory records them.
3. If the problem is a vulnerability, the maintainer requests a CVE ID from the
   draft advisory. GitHub is a CVE Numbering Authority and assigns the ID.
4. The fix is prepared in the advisory's temporary private fork of the repository, so it
   stays hidden until release. Collaborators on the advisory can open that fork. A
   report filed through GitHub makes you one, so you can review the fix there.
5. The fix ships as a new patch release on PyPI.
6. The maintainer publishes the advisory, with the CVE ID and the fixed version. It
   then appears in the GitHub Advisory Database, and Dependabot tells users of
   affected versions. Reporters who agree to it get credit in the advisory.

A report by email goes through the same steps. The maintainer opens the draft advisory
for it. If you have a GitHub account and want to review the fix, say so, and the
maintainer adds you to the advisory as a collaborator.

archivey has one maintainer, who works on it in their free time. These times are aims,
not guarantees:

- **Acknowledge** a report within 7 days.
- **Assess** it (accepted or not, and the severity) within 14 days.
- **Fix** a high or critical severity problem within 30 days of the assessment. A lower
  severity fix ships in a later regular release.

If an aim slips, the advisory says so and gives a new date. Please do not publish
details before the fix is released, or before a date we agree in the advisory.
