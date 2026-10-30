"""The optional packages a call's ``FormatPolicy.exclude_libraries`` turns off.

An excluded package reads as not installed for that call only. Nothing process-wide
changes: every availability check takes the call's excluded set, carried on the reader's
``ArchiveyConfig`` and on the ``StreamConfig`` a codec opens with, and answers "absent"
for an excluded name before it looks the package up. So another call, on any thread,
sees the package as it is.
"""

from __future__ import annotations

import dataclasses

from archivey.types import MissingComponent, OptionalLibrary

NO_EXCLUSIONS: frozenset[OptionalLibrary] = frozenset()
"""The excluded set of a call whose policy excludes nothing: every check as without one."""

EXCLUDED_REASON = "ArchiveyConfig.formats.exclude_libraries turns it off"
"""``MissingComponent.reason`` for an excluded package: installing it would not help.

The SquashFS reader keeps a copy, since it is written against the public API only;
``tests/test_squashfs.py`` compares the two, so a reword here must reach it."""


def as_excluded(component: MissingComponent) -> MissingComponent:
    """``component`` as reported when the caller's policy turns it off."""
    return dataclasses.replace(component, reason=EXCLUDED_REASON)


def as_reported(
    component: MissingComponent, excluded: frozenset[OptionalLibrary]
) -> MissingComponent:
    """``component`` with the policy as its reason when ``excluded`` names it."""
    return as_excluded(component) if component.name in excluded else component


def is_excluded_module(module: str, excluded: frozenset[OptionalLibrary]) -> bool:
    """Whether ``module`` is an excluded package or part of one: ``lz4.block`` is off
    when ``excluded`` holds ``lz4``. A plugin's ``requires`` names modules, not
    packages."""
    return any(module == lib or module.startswith(f"{lib}.") for lib in excluded)
