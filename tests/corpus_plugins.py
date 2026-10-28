"""The format plugins in ``packages/``, for the corpus harnesses that compare archivey
with another library (``test_libarchive_corpus.py``, ``test_commons_compress_corpus.py``).
"""

from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Iterator
from contextlib import contextmanager

from archivey.internal.plugin_adapter import registration_scope
from archivey.internal.registry import get_registry
from archivey.plugins import register_format

# Module and class of each plugin in packages/. A new plugin goes here.
PLUGINS = (
    ("archivey_cpio", "CpioPlugin"),
    ("archivey_ar", "ArPlugin"),
    ("archivey_squashfs", "SquashfsPlugin"),
)


@contextmanager
def installed_plugins() -> Iterator[frozenset[str]]:
    """Register the plugins that are installed, until the block ends; yield their
    modules. Not installed: left out. Installed and failing to import: an error."""
    installed: set[str] = set()
    with registration_scope():
        for module, name in PLUGINS:
            if importlib.util.find_spec(module) is None:
                continue
            plugin = getattr(importlib.import_module(module), name)
            # A plugin's own tests may have registered it in this process already.
            if get_registry().registered_reader(plugin.format) is None:
                register_format(plugin)
            installed.add(module)
        yield frozenset(installed)
