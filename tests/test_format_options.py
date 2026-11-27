"""``ArchiveyConfig(format_options=[...])``: the settings of one format, in its own class.

The maintainer ruled on 2026-11-27 (plugin plan R24) that a format's settings live in
one frozen options class per format, passed in ``format_options`` with at most one
object per class, and that ZIP and RAR use the same shape as plugins. The four
top-level fields they replace keep working through 0.6 with a ``DeprecationWarning``.
"""

from __future__ import annotations

import dataclasses
import io
import os
import warnings
import zipfile

import pytest

import archivey
from archivey import ArchiveyConfig, ArchiveyUsageError
from archivey.config import RarDecompressor, RarOptions, ZipOptions
from archivey.internal.config import format_options_of

_ABS = os.path.abspath("unrar-here")


def test_a_config_without_options_gives_each_class_its_defaults() -> None:
    config = ArchiveyConfig()
    assert config.format_options == ()
    assert format_options_of(config, ZipOptions) == ZipOptions()
    assert format_options_of(config, RarOptions) == RarOptions()
    assert ZipOptions().fallback_encoding == "cp437"
    assert RarOptions().decompressor is RarDecompressor.AUTO
    assert RarOptions().unrar_path is None
    assert RarOptions().unar_path is None


def test_the_callers_object_is_the_one_a_reader_gets() -> None:
    rar = RarOptions(decompressor="unar", unar_path=_ABS)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config = ArchiveyConfig(format_options=[rar, ZipOptions("cp1252")])
    assert config.format_options == (rar, ZipOptions("cp1252"))
    assert format_options_of(config, RarOptions) is rar
    assert rar.decompressor is RarDecompressor.UNAR
    assert format_options_of(config, ZipOptions).fallback_encoding == "cp1252"


def test_two_objects_of_one_class_are_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="RarOptions"):
        ArchiveyConfig(format_options=[RarOptions(), RarOptions(decompressor="unar")])


def test_an_object_that_is_not_an_options_class_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="format_options"):
        ArchiveyConfig(format_options=[{"decompressor": "unar"}])  # type: ignore[list-item]


def test_the_options_classes_check_their_fields() -> None:
    with pytest.raises(ArchiveyUsageError, match="decompressor"):
        RarOptions(decompressor="sometimes")  # type: ignore[arg-type]
    with pytest.raises(ArchiveyUsageError, match="unrar_path"):
        RarOptions(unrar_path="relative/unrar")
    with pytest.raises(ArchiveyUsageError, match="fallback_encoding"):
        ZipOptions(fallback_encoding="no-such-codec")


@pytest.mark.parametrize(
    ("old", "value", "cls", "new"),
    [
        ("zip_unflagged_fallback_encoding", "cp1252", ZipOptions, "fallback_encoding"),
        ("rar_decompressor", "unar", RarOptions, "decompressor"),
        ("unrar_path", _ABS, RarOptions, "unrar_path"),
        ("unar_path", _ABS, RarOptions, "unar_path"),
    ],
)
def test_an_old_field_warns_and_still_decides(
    old: str, value: str, cls: type, new: str
) -> None:
    with pytest.warns(DeprecationWarning, match=cls.__name__) as caught:
        config = ArchiveyConfig(**{old: value})
    assert caught[0].filename == __file__
    got = getattr(format_options_of(config, cls), new)
    assert got == value or got == RarDecompressor(value)


def test_an_old_field_beside_its_options_object_is_refused() -> None:
    with (
        pytest.warns(DeprecationWarning),
        pytest.raises(ArchiveyUsageError, match="RarOptions"),
    ):
        ArchiveyConfig(rar_decompressor="unar", format_options=[RarOptions()])


def test_a_copy_of_a_config_with_options_does_not_warn() -> None:
    config = ArchiveyConfig(format_options=[RarOptions(decompressor="unar")])
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        copy = dataclasses.replace(config, read_link_targets=False)
    assert format_options_of(copy, RarOptions).decompressor is RarDecompressor.UNAR


def test_the_zip_fallback_encoding_decodes_an_unflagged_name() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("x")
        zf.writestr(info, b"data")
    raw = bytearray(buf.getvalue())
    # Replace the one-byte name "x" (in both headers) with 0xE9, not valid UTF-8.
    for marker in (b"PK\x03\x04", b"PK\x01\x02"):
        start = raw.find(marker)
        name_at = start + (30 if marker == b"PK\x03\x04" else 46)
        assert raw[name_at : name_at + 1] == b"x"
        raw[name_at] = 0xE9
    config = ArchiveyConfig(format_options=[ZipOptions(fallback_encoding="cp1252")])
    with archivey.open_archive(io.BytesIO(bytes(raw)), config=config) as reader:
        assert [m.name for m in reader.members()] == ["é"]


def test_a_copy_decides_only_with_the_options_it_passes() -> None:
    """An old field decides only on the construction that names it: it reads back as
    ``None``, so a ``dataclasses.replace`` copy that sets ``format_options`` gets
    exactly those options, neither refused nor overridden by the old field."""
    with pytest.warns(DeprecationWarning):
        base = ArchiveyConfig(rar_decompressor="unrar", unrar_path=_ABS)
    assert base.rar_decompressor is None
    assert base.unrar_path is None
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        other = dataclasses.replace(
            base, format_options=[RarOptions(decompressor="unar")]
        )
        cleared = dataclasses.replace(base, format_options=[])
    assert other.format_options == (RarOptions(decompressor="unar"),)
    assert cleared.format_options == ()


@dataclasses.dataclass
class _MutableOptions:
    x: int = 1


@dataclasses.dataclass(frozen=True)
class _PluginOptions:
    x: int = 1


class _RarOptionsSubclass(RarOptions):
    pass


@pytest.mark.parametrize(
    "item",
    [
        archivey.config.ListingLimits(max_members=5),
        _MutableOptions(),
        _RarOptionsSubclass(decompressor="unar"),
    ],
    ids=["archivey-config-class", "mutable-dataclass", "options-subclass"],
)
def test_an_object_no_reader_would_read_is_refused(item: object) -> None:
    with pytest.raises(ArchiveyUsageError, match="format_options"):
        ArchiveyConfig(format_options=[item])


def test_a_plugins_frozen_options_class_is_taken_and_hashable() -> None:
    config = ArchiveyConfig(format_options=[_PluginOptions(x=2)])
    hash(config)
    assert format_options_of(config, _PluginOptions) == _PluginOptions(x=2)
