"""Helpers for tests that run a decoding kernel both ways."""

from __future__ import annotations

from typing import Any

import pytest

from archivey.internal import kernels
from archivey.types import OptionalLibrary

_OFF = frozenset({OptionalLibrary.ARCHIVEY_CODECS})


def use_python_twin(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make the switch ``kernels.<name>`` give the Python twin, as if archivey-codecs
    were turned off for every call."""
    real = getattr(kernels, name)

    def twin(excluded: frozenset[OptionalLibrary], *args: Any, **kwargs: Any) -> Any:
        return real(excluded | _OFF, *args, **kwargs)

    monkeypatch.setattr(kernels, name, twin)
