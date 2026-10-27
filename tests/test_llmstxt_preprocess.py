"""The link rewrite the docs build applies before writing the Markdown page copies.

`scripts/llmstxt_preprocess.py` points a relative page link with an anchor at the
page's Markdown copy, so an agent reading `llms.txt` copies stays in Markdown. A wrong
rewrite breaks links in every copy, and no docs gate reads the copies, so the cases
are pinned here.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "llmstxt_preprocess.py"

_spec = importlib.util.spec_from_file_location("llmstxt_preprocess", SCRIPT)
assert _spec is not None and _spec.loader is not None
pre = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pre)


@pytest.mark.parametrize(
    ("href", "expected"),
    [
        ("../reading/#reading-once", "../reading/index.md#reading-once"),
        ("../#read-everything-in-one-pass", "../index.md#read-everything-in-one-pass"),
        ("./#options", "./index.md#options"),
        # Left alone: no anchor (the plugin already handles a trailing `/`), an anchor
        # on the same page, a file link, an absolute path, an external URL.
        ("../reading/", "../reading/"),
        ("#exceptions", "#exceptions"),
        ("../api/objects.inv#x", "../api/objects.inv#x"),
        ("/archivey/reading/#x", "/archivey/reading/#x"),
        ("https://example.com/docs/#x", "https://example.com/docs/#x"),
    ],
)
def test_markdown_href(href: str, expected: str) -> None:
    assert pre.markdown_href(href) == expected


def test_preprocess_rewrites_links_in_place() -> None:
    class Link(dict):
        pass

    links = [Link(href="../reading/#reading-once"), Link(href="#top")]

    class Soup:
        def find_all(self, name: str, href: bool) -> list[Link]:
            assert (name, href) == ("a", True)
            return links

    pre.preprocess(Soup(), "out.md")
    assert [link["href"] for link in links] == [
        "../reading/index.md#reading-once",
        "#top",
    ]
