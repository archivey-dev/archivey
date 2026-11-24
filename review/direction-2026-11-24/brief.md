# Direction review, 2026-11-24 — brief

**Asked by:** the maintainer, in a chat session.

**The question, as asked:** archivey should become the default library for every kind of
archive: the one you reach for without thinking. It should be easy to use, safe and
broadly compatible, and easy to extend, so that writing a plugin for a new format is
easier than writing a separate library. What is missing? What is too complicated, in the
API and in the internal architecture, and how can it be fixed? Has the project gone
overboard? What other questions should the maintainer ask, and what are the unknown
unknowns?

**Scope:** the high-level view, to shape direction. Not a bug hunt.

**Constraint:** a fresh view. The reviewer did not read the earlier reviews in `review/`
or `review/archive/`, so some points may repeat settled ground; where one does, the
recorded decision is the place to start, and this review says only how it looks from
outside.

**What was read:** `VISION.md`, `README.md`, `AGENTS.md`, the user docs (`docs/`,
especially the cheat sheet, reading, security, philosophy and adding-a-format pages), the
generated API surface (`dev-docs/api-surface.txt`), `dev-docs/code-map.md`, the index of
`dev-docs/design-rules.md`, the ADR titles and ADR 0019, `dev-docs/IDEAS.md`, and the
briefs of the open OpenSpec changes. The source was read for shape (module sizes, class
and method counts, which backends use which reader route), not line by line.

**What was run:** a few flows by hand on Linux with `[all]` installed (import time,
listing and reading a 5,000-member ZIP against `zipfile`, extracting a hostile ZIP,
opening a nested ZIP, opening two members at once). The numbers come from one container
and are order-of-magnitude only.

**Deliverable:** [`SUMMARY.md`](SUMMARY.md).
