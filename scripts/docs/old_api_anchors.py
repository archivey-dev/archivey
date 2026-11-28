"""Keep the API page's pre-0.6 anchors, so an old `api/#archivey.DecoderLimits` link lands.

Until 0.6.0 the API page documented 67 names under the package root, so mkdocstrings
gave each entry, field and method an id such as `archivey.DecoderLimits.max_ratio`.
Those entries are now documented under their submodule (`archivey.config.DecoderLimits`),
which changes every id. This mkdocs hook (mkdocs.yml, `hooks:`) puts an empty span with
the old id in front of each element whose id has a moved name's new prefix, so the old
links still scroll to the entry.

Only :func:`add_old_anchors` holds logic, and it needs nothing outside the standard
library, so `scripts/tests/test_old_api_anchors.py` runs it without the docs group.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

#: The experimental names that left the root at once (no ``archivey.<name>`` shim), and
#: so are not in ``archivey._MOVED_IN_0_6``; their old links should still land.
EXPERIMENTAL_MOVED = {
    "PluginContainer": "archivey.types",
    "PluginStream": "archivey.types",
}

_ID = re.compile(r'<[a-zA-Z][^<>]*?\sid="(archivey\.[\w.]+)"')


def add_old_anchors(html: str, moved: Mapping[str, str]) -> str:
    """Return ``html`` with an old-id span before each element of a moved name.

    ``moved`` maps a name that left the root to its new module. An element whose id is
    ``<module>.<name>`` or starts with ``<module>.<name>.`` gets a span with the id
    ``archivey.<name>`` plus the same suffix, unless the page already has that id.
    """
    present = set(re.findall(r'\sid="([^"]+)"', html))
    prefixes = {
        f"{module}.{name}": f"archivey.{name}" for name, module in moved.items()
    }
    out: list[str] = []
    last = 0
    for m in _ID.finditer(html):
        new_id = m.group(1)
        old = None
        for new_prefix, old_prefix in prefixes.items():
            if new_id == new_prefix or new_id.startswith(new_prefix + "."):
                old = old_prefix + new_id[len(new_prefix) :]
                break
        if old is None or old in present:
            continue
        present.add(old)
        out.append(html[last : m.start()])
        out.append(f'<span id="{old}"></span>')
        last = m.start()
    out.append(html[last:])
    return "".join(out)


def on_page_content(html: str, page: Any, **_: Any) -> str:
    """mkdocs hook: add the old anchors to the API page only."""
    if page.file.src_uri != "api.md":
        return html
    import archivey

    return add_old_anchors(html, {**archivey._MOVED_IN_0_6, **EXPERIMENTAL_MOVED})
