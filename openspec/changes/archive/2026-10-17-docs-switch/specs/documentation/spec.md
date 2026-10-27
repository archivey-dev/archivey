## MODIFIED Requirements

### Requirement: End-user guide is separate from internal reference

The MkDocs site SHALL publish end-user material only. Every file under `docs/` MUST
be an end-user page carrying a nav entry; maintainer material — decision log, threat
model, codec analysis, known issues, finished investigations,
and superseded historical prose — SHALL live under `dev-docs/`, outside the site,
rather than under `docs/` behind an exclusion list. The user narrative covers,
in this navigation order: install (including Python versions, platforms and
free-threaded Python), opening an archive, choosing how to read, extracting, security,
errors and diagnostics, the command line, formats/extras, migration, philosophy, how
the library works and how it is built (`how-it-works.md` and `how-it-is-built.md`,
after philosophy), the API reference, and acknowledgements. Each page SHALL do one
job, stated in its opening lines. A published page SHALL NOT link to a path outside `docs/`;
where maintainer depth is worth preserving the link MUST be an absolute
`https://github.com/archivey-dev/archivey/blob/main/…` URL.

#### Scenario: docs information architecture

| Case | Expected |
| --- | --- |
| User opens the docs home | Every nav entry is an end-user page; no internal, grab-bag, or decision-log section exists |
| User finishes choosing how to read | Next page in the navigation is Extracting |
| User wants to know what to install | `install.md` answers it, including formats needing an external binary |
| Contributor looks up “why not py7zr” | The full record is in `dev-docs/decisions/` in the repository; `how-it-works.md` gives the reasons in a paragraph and links the maintainer handbook |
| User wants to know how the library is built | `how-it-works.md` explains the design philosophy, the architecture and how the library is tested, linking to maintainer depth on GitHub |
| Published page needs maintainer depth | Absolute `github.com/archivey-dev/archivey/blob/main/dev-docs/…` URL, never a site-relative path into unpublished material |

### Requirement: Document complete-or-raise listing vs MemberListReport

The end-user guide SHALL document the dual listing contract on
`docs/errors-and-diagnostics.md`:

- `members()` — complete listing or raise (assert completeness); on a streaming
  reader, `members_report()` and raise its `error`.
- `members_report()` → `MemberListReport` — recovered members plus `error` when the
  archive ends in a terminal listing failure (VISION damaged-input recipe).
- `__iter__` / `stream_members` — yield recovered members then raise on the same
  failures (either access mode).
- `extract_all` / `extract` — write the members listed before the damage, then raise
  the same failure (either access mode; no report is returned).

The docs SHALL state that diagnostics alone are not the primary signal for these
failures, that an incomplete pass does not publish a complete member cache, and
that extraction from a listing that ends in damage leaves the prefix's members on
disk when it raises (per `safe-extraction`). Salvage / `--salvage` remains out of
scope and separately reserved.

#### Scenario: listing honesty documentation

| Case | Expected |
| --- | --- |
| Reader wants inventory of a possibly damaged tar | Reaches the `members_report()` recipe (check `error`, use report `.members`) — recipe on `errors-and-diagnostics.md` |
| Reader wants “fail if not complete” | Directed to `members()`, or to raising `members_report().error` on a streaming reader |
| Reader only wants to read a healthy archive | Meets the one-line "we raise rather than return short data" promise in the flow, and is not made to read the contract |
| Reader looks for salvage/best-effort | Pointed to reserved/future salvage — not `members_report` |

### Requirement: Document TAR EOF honesty and its diagnostic codes

End-user documentation SHALL state that:

- Stdlib-backed TAR may silently shorten a listing when a member header after the
  first is corrupt; archivey’s backstop is its end-of-archive check.
- By default archivey raises `CorruptionError` when the stopped scan lands on a
  rejected header — which a well-formed tar never produces — in both access modes,
  including when that header is the archive's final block. A merely
  trailer-less or `cat`-joined tar (ended cleanly on a member boundary) is warned about
  via `ARCHIVE_EOF_MARKER_MISSING`, not raised, because it is indistinguishable from a
  tar truncated at a member boundary.
- Setting `ARCHIVE_EOF_MARKER_MISSING` to `RAISE` (or using
  `DiagnosticPolicy.STRICT`) makes that ambiguous residual raise
  `DiagnosticRaisedError`, for inventory / dedupe / validators that need a provably
  complete listing. Docs SHALL NOT describe this as "the only way archivey catches
  corruption" — a rejected header is caught by default.
- A non-zero byte after the trailer is reported as `ARCHIVE_TRAILING_DATA` only within
  1 MiB of it; docs SHALL state the bound, and that zero padding passes.

This SHALL appear in the formats guide. Internal
threat-model / known-issues material MUST NOT be the only place this is written.

#### Scenario: TAR EOF documentation matrix

| Case | Expected |
| --- | --- |
| Reader opens the formats guide for TAR quirks | Finds silent-shorten + diagnostic + the rejected-header-raises-by-default vs missing-trailer-warns split |
| Inventory / dedupe guidance | Shows a `RAISE` disposition on `ARCHIVE_EOF_MARKER_MISSING` as the escalation for the ambiguous residual, not as the only corruption backstop |
| Trailing data | Documented as reported within 1 MiB of the trailer, and not beyond |
| Rejected final header | Documented as raising `CorruptionError` in both access modes |

## REMOVED Requirements

### Requirement: Gotchas page is a footgun digest, not a format encyclopaedia

**Reason**: The rewritten user guide has no Gotchas page. Each caution sits on the page
that owns the topic: seeking and solid archives on `reading.md`, extraction limits,
name collisions and nested archives on `extracting.md` and `security.md`, format
caveats on `formats.md`.

**Migration**: Link to the owning page's section instead of a Gotchas entry.
