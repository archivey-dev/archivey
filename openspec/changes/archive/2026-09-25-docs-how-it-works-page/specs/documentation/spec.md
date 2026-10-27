# documentation — How it works page delta

## MODIFIED Requirements

### Requirement: End-user guide is separate from internal reference

The MkDocs site SHALL publish end-user material only. Every file under `docs/` MUST
be an end-user page carrying a nav entry; maintainer material — decision log, threat
model, codec analysis, known issues, open-issues triage, finished investigations,
and superseded historical prose — SHALL live under `dev-docs/`, outside the site,
rather than under `docs/` behind an exclusion list. The user narrative covers
install, opening and listing, reading members, gotchas, extracting, access
costs/pitfalls, formats/extras, errors and diagnostics, the command line, migration,
platforms, philosophy, how the library is built (`how-it-works.md`, after philosophy),
and the API reference. Each page SHALL do one job, stated in
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
| Contributor looks up “why not py7zr” | The full record is in `dev-docs/decisions/` in the repository; `how-it-works.md` gives the reasons in a paragraph and links the maintainer handbook |
| User wants to know how the library is built | `how-it-works.md` explains the design philosophy, the architecture and how the library is tested, linking to maintainer depth on GitHub |
| Published page needs maintainer depth | Absolute `github.com/archivey-dev/archivey/blob/main/dev-docs/…` URL, never a site-relative path into unpublished material |
