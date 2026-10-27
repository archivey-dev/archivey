"""Keep links with an anchor inside the Markdown copies the `llmstxt` plugin writes.

The plugin (mkdocs.yml, `preprocess:`) calls :func:`preprocess` on each page's HTML
before it makes links absolute and converts the page to Markdown. Its own rewrite
points a link at a page's Markdown copy only when the link ends with `/`, so
`../reading/#reading-once` kept pointing at the HTML page and sent an agent reading
the Markdown copies back to HTML. This rewrites it to `../reading/index.md#reading-once`
first. A link to an anchor on the same page (`#name`), an absolute link and an
external URL are left as they are.

Only :func:`markdown_href` holds logic, and it needs nothing outside the standard
library, so `tests/test_llmstxt_preprocess.py` runs it without the docs group.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def markdown_href(href: str) -> str:
    """Return ``href`` pointed at the Markdown copy, for a relative page link with an anchor."""
    path, sep, fragment = href.partition("#")
    if not sep or not path or path.startswith("/") or urlsplit(href).scheme:
        return href
    if not path.endswith("/"):
        return href
    return f"{path}index.md#{fragment}"


def preprocess(soup: Any, output: str) -> None:
    """Rewrite every link in ``soup`` with :func:`markdown_href`."""
    for link in soup.find_all("a", href=True):
        href = link.get("href")
        if isinstance(href, str):
            link["href"] = markdown_href(href)
