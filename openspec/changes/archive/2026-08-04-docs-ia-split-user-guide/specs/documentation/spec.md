## MODIFIED Requirements

### Requirement: End-user guide is separate from internal reference

The MkDocs site SHALL publish end-user material only. Every file under `docs/` MUST
be an end-user page carrying a nav entry; maintainer material — decision log, threat
model, codec analysis, known issues, open-issues triage, finished investigations,
and superseded historical prose — SHALL live under `dev-docs/`, outside the site,
rather than under `docs/` behind an exclusion list. The user narrative covers
install, opening and listing, reading members, gotchas, extracting, access
costs/pitfalls, formats/extras, errors and diagnostics, the command line, migration,
platforms, philosophy, and the API reference. Each page SHALL do one job, stated in
its opening lines. Gotchas SHALL sit immediately after `reading-members.md` in
primary navigation. A published page SHALL NOT link to a path outside `docs/`;
where maintainer depth is worth preserving the link MUST be an absolute
`https://github.com/archivey-dev/archivey/blob/main/…` URL.

#### Scenario: docs information architecture

| Case | Expected |
| --- | --- |
| User opens the docs home | Every nav entry is an end-user page; no internal, grab-bag, or decision-log section exists |
| User finishes reading members | Next recommended page is Gotchas |
| User wants to know what to install | `install.md` answers it, including formats needing an external binary |
| Contributor looks up “why not py7zr” | Answer is in `dev-docs/decisions/` in the repository, not on the site |
| Published page needs maintainer depth | Absolute `github.com/archivey-dev/archivey/blob/main/dev-docs/…` URL, never a site-relative path into unpublished material |

### Requirement: Document complete-or-raise listing vs MemberListReport

The end-user guide SHALL document the dual listing contract on
`docs/errors-and-diagnostics.md`, with `docs/opening-and-listing.md` carrying a
short pointer to it:

- `members()` / `scan_members()` — complete listing or raise (assert completeness).
- `members_report()` → `MemberListReport` — recovered members plus `error` when the
  archive ends in a terminal listing failure (VISION damaged-input recipe).
- `__iter__` / `stream_members` — yield recovered members then raise on the same
  failures (either access mode).

The docs SHALL state that diagnostics alone are not the primary signal for these
failures, that an incomplete pass does not publish a complete member cache, and
that RA extract-prep remains fail-closed (no partial writes from a corrupt
archive). Salvage / `--salvage` remains out of scope and separately reserved.

#### Scenario: listing honesty documentation

| Case | Expected |
| --- | --- |
| Reader wants inventory of a possibly damaged tar | Reaches the `members_report()` recipe (check `error`, use report `.members`) — pointer on `opening-and-listing.md`, recipe on `errors-and-diagnostics.md` |
| Reader wants “fail if not complete” | Directed to `members()` / `scan_members()` |
| Reader only wants to read a healthy archive | Meets the one-line "we raise rather than return short data" promise in the flow, and is not made to read the contract |
| Reader looks for salvage/best-effort | Pointed to reserved/future salvage — not `members_report` |

## ADDED Requirements

### Requirement: Gotchas page is a footgun digest, not a format encyclopaedia

The Gotchas page SHALL carry two sections — **what you should / shouldn't do**
(caller choices that cause mistakes) and **what you should be aware of** (places
where Archivey cannot fully fail loudly or verify) — with each entry one line plus a
link to the page that owns the detail.

A topic belongs on Gotchas only if (a) a caller choice is likely to cause a mistake
or a footgun, or (b) Archivey cannot fulfil its intention of failing loudly and
verifying. Format encyclopaedia, unsupported-feature lists, full policy tables, and
"plan around this limitation" rows SHALL live on the owning page (`formats.md`,
`extracting.md`, `access-and-cost.md`) and MUST NOT be restated here.

The page SHALL carry the user-mitigable threat-model residuals: nested-archive
amplification (the bomb tracker is not nesting-aware), the unguarded paths
(`stream_members()` outside `ListingLimits`, unbounded `read()`), the 7z
header-encryption residual, and name-collision behaviour.

#### Scenario: Gotchas inclusion matrix

| Case | Expected |
| --- | --- |
| Seeking re-decompresses; solid open order; streaming is one pass | Present, one line each, linking `access-and-cost.md` |
| Multi-volume ZIP; ZIP/ISO needing seek; UTF-8 bit-11 | **Absent** — loud errors or normal format requirements; `formats.md` owns them |
| Full extraction policy table | **Absent** — `extracting.md` owns it |
| Nested-archive amplification | Present as a one-liner; the bounded-recursion recipe lives on `extracting.md` |
| A fact stated on Gotchas and on its owning page | Digest line links out rather than restating, so the two cannot drift |

## REMOVED Requirements

### Requirement: Gotchas page covers post-v1-fixable limitations as current behavior

**Reason**: Reversed by maintainer triage (`review/docs/DECISIONS.md` D4). The
requirement mandated four rows on Gotchas — multi-volume ZIP rejection, ZIP/ISO seek,
UTF-8 bit-11 unlistable archives, TAR mid-corrupt silent shorten. Three of those are
loud errors or ordinary format requirements rather than footguns, and listing them
made Gotchas a third copy of `formats.md`: four of its seven sections had a
same-titled section on another page, and the rapidgzip caveat had already drifted
across four copies. The replacement requirement above states what Gotchas *is* and
gives it an inclusion rule, which is the durable version of the same intent.

**Migration**: The multi-volume and ZIP/ISO-need-seek rows already existed on
`formats.md` and in `access-and-cost.md` §Non-seekable sources. The UTF-8 bit-11 row
did **not** — it lived only on Gotchas — and is added to `formats.md` §ZIP as part of
this change, next to the member-name encoding rules it belongs with. The TAR silent-shorten row stays covered —
"Document TAR EOF honesty and the strict_archive_eof opt-in" independently requires
it in the formats guide *and* on the Gotchas page, and D4 keeps TAR honesty residuals
under "what you should be aware of". No user-facing fact is dropped by this removal.
