"""``ArchiveyConfig.UNTRUSTED``: the settings for files you did not make, ready-made.

The upload recipes build these by hand; the preset holds them in one place, and the
recipes start from it. The maintainer chose on 2026-11-27 that the 0.6.0 API trims,
this preset among them, go into 0.6.0.
"""

from __future__ import annotations

import dataclasses
import warnings

import archivey
from archivey import ArchiveyConfig, DiagnosticPolicy, FormatPolicy
from archivey.config import AcceleratorMode, ProcessIsolation


def test_the_preset_holds_the_upload_settings() -> None:
    config = ArchiveyConfig.UNTRUSTED
    assert config.formats == FormatPolicy.COMMON
    assert config.diagnostic_policy == DiagnosticPolicy.STRICT
    assert config.process_isolation is ProcessIsolation.NATIVE_DECODERS
    assert config.listing_limits.max_members == 10_000
    assert config.listing_limits.max_metadata_bytes == 4 * 2**20
    assert config.decoder_limits.max_decoder_memory == 256 * 2**20
    assert config.decoder_limits.max_key_derivation_rounds == 2**24
    assert config.extraction_limits.max_extracted_bytes == 500 * 2**20
    assert config.extraction_limits.max_entries == 10_000
    assert config.use_rapidgzip is AcceleratorMode.OFF


def test_everything_else_is_the_default() -> None:
    changed = {
        "formats",
        "diagnostic_policy",
        "process_isolation",
        "listing_limits",
        "decoder_limits",
        "extraction_limits",
        "use_rapidgzip",
    }
    default = ArchiveyConfig()
    for f in dataclasses.fields(ArchiveyConfig):
        if f.name not in changed:
            assert getattr(ArchiveyConfig.UNTRUSTED, f.name) == getattr(
                default, f.name
            ), f.name
    for name in ("listing_limits", "decoder_limits", "extraction_limits"):
        group = getattr(ArchiveyConfig.UNTRUSTED, name)
        base = type(group)()
        moved = {
            g.name
            for g in dataclasses.fields(group)
            if getattr(group, g.name) != getattr(base, g.name)
        }
        assert moved <= {
            "max_members",
            "max_metadata_bytes",
            "max_decoder_memory",
            "max_key_derivation_rounds",
            "max_extracted_bytes",
            "max_entries",
        }, (name, moved)


def test_a_caller_adjusts_it_with_replace_without_a_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config = dataclasses.replace(ArchiveyConfig.UNTRUSTED, read_link_targets=False)
    assert config.formats == FormatPolicy.COMMON
    assert config.read_link_targets is False


def test_it_is_not_a_root_name() -> None:
    assert "UNTRUSTED" not in archivey.__all__
