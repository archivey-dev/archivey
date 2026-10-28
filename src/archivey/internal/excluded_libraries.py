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
"""``MissingComponent.reason`` for an excluded package: installing it would not help."""


def as_excluded(component: MissingComponent) -> MissingComponent:
    """``component`` as reported when the caller's policy turns it off."""
    return dataclasses.replace(component, reason=EXCLUDED_REASON)


def as_reported(
    component: MissingComponent, excluded: frozenset[OptionalLibrary]
) -> MissingComponent:
    """``component`` with the policy as its reason when ``excluded`` names it."""
    return as_excluded(component) if component.name in excluded else component
