"""Assert every Sphinx cross-reference role in the docstrings renders as intended.

The docstrings use Sphinx roles (``:class:`~archivey.ArchiveMember```), and
mkdocstrings does not understand them. ``scripts/docs/griffe_extensions.py`` rewrites them
into links at build time; before it did, 129 of them reached the published API page as
literal text (``:class:~archivey.ArchiveMember``), and ``mkdocs build --strict`` was
green the whole time. It has nothing to warn about: to Markdown a role is just text.

Two checks over the built site:

**No role leaks as text.** The HTML and the search index (which is what search results
show) must hold no role: a new docstring spelling the extension does not match, a role
written into a page under ``docs/``, or the extension dropped from ``mkdocs.yml``.

**Every role resolves, or is known not to.** The extension emits *optional* autorefs,
and an optional reference that finds no anchor falls back to plain code at DEBUG level,
so ``--strict`` never reports it. A renamed public symbol, or a broken mapping from
defining module to public path, would otherwise turn links into plain code silently.
The extension marks the code it emits with ``class="sphinx-role"``; one that renders
inside ``<span title="target">`` rather than a link did not resolve. Its target must be
in ``UNRESOLVED_OK`` below, and every entry there must still occur, so the list cannot
go stale.

Run after a build:

    uv run --group docs mkdocs build --strict
    python3 scripts/checks/check_docs_rendered.py [site-dir]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The role name, then what follows it once Markdown has turned the target's backticks
# into ``<code>`` (``\u003c`` or ``&lt;`` in escaped text), or the target itself. A role
# name standing alone, with a space or closing tag after it, is not a leak.
LEAKED_ROLE_RE = re.compile(
    r":(?:py:)?(?:class|func|meth|attr|data|const|exc|mod|obj|any):(?:[`~\w<&]|\\u003c)"
)


# autorefs renders an optional reference with no anchor as <span title="identifier">.
UNRESOLVED_RE = re.compile(r'<span title="([^"]*)"><code class="sphinx-role">')
ROLE_MARKER = 'class="sphinx-role"'

# Role targets that exist but have no anchor on the site, so they render as plain code.
# Outside the group marked NOT a decision, adding to this list is a decision that the
# reference is fine unlinked. Removing an entry is required once the target gains an
# anchor or its last role goes away.
UNRESOLVED_OK = {
    # Not on the API page: outside `archivey.__all__` (the two AUTO thresholds live in
    # `archivey.config` and are not re-exported at the root), or reachable only through
    # an internal module path.
    "archivey.config.INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE",
    "archivey.config.RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE",
    "archivey.exceptions.exception_detail",
    "archivey.exceptions.raw_message_of",
    # Members the page shows in a list or not at all, so they get no heading anchor.
    "archivey.ArchiveFormat.DIRECTORY",
    "archivey.ArchiveyError.__str__",
    "archivey.DecoderLimits.UNLIMITED",
    "archivey.Diagnostic.to_dict",
    "archivey.ExtractionLimits.UNLIMITED",
    "archivey.ListingLimits.UNLIMITED",
    "archivey.SpoolLimits.UNLIMITED",
    # Standard library: the site has no inventory for Python's own docs.
    "OSError",
    "ValueError",
    "ascii",
    "io.UnsupportedOperation",
    "repr",
    # ArchiveMember properties: folded into the class's field list
    # (PropertyFieldExtension), so a bare name no longer resolves against the class.
    "is_junction",
    "is_reparse_point",
}


def main(argv: list[str]) -> int:
    site = Path(argv[1] if len(argv) > 1 else "site")
    if not (site / "index.html").is_file():
        print(f"error: no built site at {site}/ (run `mkdocs build` first)")
        return 2
    leaks: list[str] = []
    files = [*site.rglob("*.html"), *site.glob("search/*.json")]
    for path in sorted(files):
        text = path.read_text(encoding="utf-8")
        for match in LEAKED_ROLE_RE.finditer(text):
            start = max(match.start() - 40, 0)
            context = " ".join(text[start : match.end() + 40].split())
            leaks.append(f"{path.relative_to(site)}: ...{context}...")
    if leaks:
        print(f"{len(leaks)} Sphinx role(s) leaked into the built site:")
        for leak in leaks:
            print(f"  {leak}")
        print(
            "\nWrite the reference as a mkdocstrings cross-reference "
            "([`Name`][archivey.Name]) or teach SphinxRolesToAutorefs in "
            "scripts/docs/griffe_extensions.py the new spelling."
        )
        return 1

    html_files = [path for path in files if path.suffix == ".html"]
    html = [path.read_text(encoding="utf-8") for path in html_files]
    total = sum(text.count(ROLE_MARKER) for text in html)
    if total == 0:
        print(
            f"error: no {ROLE_MARKER} in the built site; the resolution check would "
            "pass vacuously (is SphinxRolesToAutorefs still in mkdocs.yml?)"
        )
        return 1
    unresolved = [target for text in html for target in UNRESOLVED_RE.findall(text)]
    unexpected = sorted(set(unresolved) - UNRESOLVED_OK)
    stale = sorted(UNRESOLVED_OK - set(unresolved))
    if unexpected or stale:
        for target in unexpected:
            print(f"role target did not resolve to a link: {target}")
        for target in stale:
            print(f"UNRESOLVED_OK entry no longer occurs, remove it: {target}")
        print(
            "\nFix the docstring's target, or record it in UNRESOLVED_OK in "
            "scripts/checks/check_docs_rendered.py if it genuinely has no anchor."
        )
        return 1
    print(
        f"ok: no Sphinx roles in {len(files)} built files; "
        f"{total - len(unresolved)} of {total} role references link, "
        f"{len(unresolved)} are known to have no anchor"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
