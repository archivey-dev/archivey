"""``use_rapidgzip`` decides bzip2 too; ``use_indexed_bzip2`` is deprecated.

rapidgzip's bundled bzip2 decoder and its gzip decoder come from one package and run
in one kind of child process, so one switch covers both. The maintainer chose on
2026-11-27 that the breaking trims of the 0.6.0 API review go into 0.6.0; this is part
of shrinking ``ArchiveyConfig``.
"""

from __future__ import annotations

import dataclasses
import warnings

import pytest

from archivey import ArchiveyConfig
from archivey.config import AcceleratorMode
from archivey.internal.config import stream_config_from_archivey


def _bzip2_mode(config: ArchiveyConfig) -> AcceleratorMode:
    return stream_config_from_archivey(config, streaming=False).use_indexed_bzip2


@pytest.mark.parametrize("mode", list(AcceleratorMode))
def test_use_rapidgzip_decides_bzip2(mode: AcceleratorMode) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config = ArchiveyConfig(use_rapidgzip=mode)
    assert config.use_indexed_bzip2 is None
    assert _bzip2_mode(config) is mode


def test_the_default_leaves_the_old_field_unset() -> None:
    assert ArchiveyConfig().use_indexed_bzip2 is None
    assert _bzip2_mode(ArchiveyConfig()) is AcceleratorMode.AUTO


def test_the_old_field_warns_and_still_decides_bzip2_alone() -> None:
    with pytest.warns(DeprecationWarning, match="use_rapidgzip") as caught:
        config = ArchiveyConfig(use_rapidgzip="on", use_indexed_bzip2="off")
    assert caught[0].filename == __file__
    assert config.use_indexed_bzip2 is AcceleratorMode.OFF
    assert config.use_rapidgzip is AcceleratorMode.ON
    assert _bzip2_mode(config) is AcceleratorMode.OFF


def test_a_copy_of_a_config_without_it_does_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        dataclasses.replace(ArchiveyConfig(), use_rapidgzip="off")


def test_a_bad_spelling_of_the_old_field_is_still_a_usage_error() -> None:
    from archivey import ArchiveyUsageError

    with (
        pytest.warns(DeprecationWarning),
        pytest.raises(ArchiveyUsageError, match="use_indexed_bzip2"),
    ):
        ArchiveyConfig(use_indexed_bzip2="sometimes")  # type: ignore[arg-type]
