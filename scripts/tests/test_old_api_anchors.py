"""The old-anchor rewrite the docs build applies to the API page.

`scripts/docs/old_api_anchors.py` puts the pre-0.6 id of a moved name in front of each
element of its entry, so `api/#archivey.DecoderLimits.max_ratio` still lands. No docs
gate reads old links, so the cases are pinned here.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "docs" / "old_api_anchors.py"

_spec = importlib.util.spec_from_file_location("old_api_anchors", SCRIPT)
assert _spec is not None and _spec.loader is not None
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)

MOVED = {"DecoderLimits": "archivey.config", "PluginStream": "archivey.types"}


def test_an_entry_and_its_members_get_their_old_ids() -> None:
    html = (
        '<div class="doc"><h3 id="archivey.config.DecoderLimits">DecoderLimits</h3>'
        '<h4 id="archivey.config.DecoderLimits.max_ratio">max_ratio</h4></div>'
        '<h3 id="archivey.types.PluginStream">PluginStream</h3>'
    )
    out = hook.add_old_anchors(html, MOVED)
    assert out == (
        '<div class="doc"><span id="archivey.DecoderLimits"></span>'
        '<h3 id="archivey.config.DecoderLimits">DecoderLimits</h3>'
        '<span id="archivey.DecoderLimits.max_ratio"></span>'
        '<h4 id="archivey.config.DecoderLimits.max_ratio">max_ratio</h4></div>'
        '<span id="archivey.PluginStream"></span>'
        '<h3 id="archivey.types.PluginStream">PluginStream</h3>'
    )


def test_a_name_that_only_shares_a_prefix_is_left_alone() -> None:
    html = '<h3 id="archivey.config.DecoderLimitsExtra">x</h3>'
    assert hook.add_old_anchors(html, MOVED) == html


def test_an_id_already_on_the_page_is_not_added_again() -> None:
    html = (
        '<h3 id="archivey.config.DecoderLimits">a</h3>'
        '<h3 id="archivey.config.DecoderLimits">b</h3>'
    )
    out = hook.add_old_anchors(html, MOVED)
    assert out.count('id="archivey.DecoderLimits"') == 1


# Deprecated in 0.6.0 for ``on_problem=``, so the page no longer documents them and an
# old link to one opens the page at its top.
_DEPRECATED_OFF_THE_PAGE = frozenset({"AbortOn", "OnBlocked", "OnError"})


def test_the_hook_covers_every_name_that_left_the_root() -> None:
    """The hook's table is the root shim's plus the two experimental names, which is
    every name ``archivey.__all__`` listed in 0.5 and no longer lists, and the API page
    documents each one that is not deprecated under the module the table gives, where
    the hook looks."""
    import archivey

    covered = {**vars(archivey)["_MOVED_IN_0_6"], **hook.EXPERIMENTAL_MOVED}
    assert len(covered) == 67
    assert not set(covered) & set(archivey.__all__)
    page = (ROOT / "docs" / "api.md").read_text(encoding="utf-8").splitlines()
    for name, module in covered.items():
        assert hasattr(importlib.import_module(module), name), (module, name)
        documented = f"::: {module}.{name}" in page
        assert documented is (name not in _DEPRECATED_OFF_THE_PAGE), (module, name)
