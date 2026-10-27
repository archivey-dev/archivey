"""Archive-data-model contract tests (phase-5 task 6.3 audit).

Pure data-type behaviours required by ``archive-data-model`` that the per-format tests
don't exercise directly: ``ArchiveFormat`` identity (compositional round-trip, on-demand
construction of uncommon container×codec pairs, ``file_extension``) and the
``ArchiveMember`` value-object contract (unhashable, copy-on-edit via ``replace``,
``None`` defaults, equality excluding hashes/extra, and the type helpers).
"""

from __future__ import annotations

import copy
import json
import pickle
from collections.abc import Hashable
from datetime import UTC

import pytest

from archivey.internal.hashing import crc32_digest
from archivey.types import (
    EXTRA_IS_JUNCTION,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    ContainerFormat,
    HashAlgorithm,
    MemberExtra,
    MemberType,
    StreamFormat,
)

# ---------------------------------------------------------------------------
# ArchiveFormat identity (compositional (container, stream) model)
# ---------------------------------------------------------------------------


def test_format_identity_round_trips_through_pair() -> None:
    assert ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP) == ArchiveFormat.TAR_GZ


def test_standalone_lzip_has_named_format() -> None:
    assert ArchiveFormat.LZIP.container == ContainerFormat.RAW_STREAM
    assert ArchiveFormat.LZIP.stream == StreamFormat.LZIP


def test_standalone_lzma_alone_has_named_format() -> None:
    assert ArchiveFormat.LZMA_ALONE.container == ContainerFormat.RAW_STREAM
    assert ArchiveFormat.LZMA_ALONE.stream == StreamFormat.LZMA_ALONE
    assert ArchiveFormat.LZMA_ALONE.file_extension() == "lzma"
    assert StreamFormat.LZMA_ALONE.value == "lzma"


def test_uncommon_container_codec_built_on_demand() -> None:
    # tar.lz has no predefined TAR_LZIP constant, but is constructed on demand and compares
    # equal to any other instance with the same (container, stream) pair.
    fmt = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)
    assert fmt == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)
    assert fmt.file_extension() == "tar.lz"


def test_tar_lzma_alone_built_on_demand() -> None:
    fmt = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)
    assert fmt.file_extension() == "tar.lzma"


def test_file_extension_examples() -> None:
    assert ArchiveFormat.ZIP.file_extension() == "zip"
    assert ArchiveFormat.TAR_GZ.file_extension() == "tar.gz"
    assert ArchiveFormat.GZ.file_extension() == "gz"
    # Formats with no on-disk file representation return "".
    assert ArchiveFormat.DIRECTORY.file_extension() == ""
    assert ArchiveFormat.UNKNOWN.file_extension() == ""


# ---------------------------------------------------------------------------
# ArchiveMember value-object contract
# ---------------------------------------------------------------------------


def test_member_is_unhashable() -> None:
    m = ArchiveMember(type=MemberType.FILE, name="a.txt")
    # ``None``, not a method that raises: only then does ``Hashable`` report it.
    assert ArchiveMember.__hash__ is None
    assert not isinstance(m, Hashable)
    with pytest.raises(TypeError, match="unhashable type: 'ArchiveMember'"):
        hash(m)
    with pytest.raises(TypeError):
        _ = {m}  # set membership needs hashing → unhashable


def test_replace_returns_copy_without_mutating_original() -> None:
    m = ArchiveMember(type=MemberType.FILE, name="a.txt", mode=0o644)
    copy = m.replace(name="b.txt")
    assert copy is not m
    assert copy.name == "b.txt"
    assert copy.mode == 0o644  # untouched fields carried over
    assert m.name == "a.txt"  # original never mutated


def test_unavailable_fields_default_to_none() -> None:
    # The library must not substitute silent defaults for fields a format cannot provide.
    m = ArchiveMember(type=MemberType.FILE, name="a.txt")
    assert m.size is None
    assert m.compressed_size is None
    assert m.mode is None
    assert m.modified is None
    assert m.link_target is None
    assert m.link_target_member is None
    assert m.compression == ()


def test_equality_excludes_hashes_and_extra() -> None:
    # hashes vary by format and extra is format-specific overflow; neither affects logical
    # identity, so both are excluded from __eq__.
    a = ArchiveMember(
        type=MemberType.FILE,
        name="a.txt",
        hashes={HashAlgorithm.CRC32: crc32_digest(1)},
        extra=MemberExtra({"third.party": 1}),
    )
    b = ArchiveMember(
        type=MemberType.FILE,
        name="a.txt",
        hashes={HashAlgorithm.CRC32: crc32_digest(2)},
        extra=MemberExtra({"third.party": 2}),
    )
    assert a == b


def test_anti_and_current_defaults_and_equality() -> None:
    # Defaults: ordinary members are non-anti and current.
    default = ArchiveMember(type=MemberType.FILE, name="a.txt")
    assert default.is_anti is False
    assert default.is_current is True

    # is_anti is derived from type; is_current remains a field in equality.
    anti = ArchiveMember(type=MemberType.ANTI, name="a.txt")
    assert anti.is_anti is True
    assert anti.is_file is False
    assert anti != default
    superseded = ArchiveMember(type=MemberType.FILE, name="a.txt", is_current=False)
    assert superseded != default
    assert anti == ArchiveMember(type=MemberType.ANTI, name="a.txt")


def test_single_codec_member_compression_shape() -> None:
    m = ArchiveMember(
        type=MemberType.FILE,
        name="a",
        compression=(CompressionMethod(CompressionAlgorithm.DEFLATE),),
    )
    assert m.compression == (CompressionMethod(algo=CompressionAlgorithm.DEFLATE),)


def test_type_helpers() -> None:
    assert ArchiveMember(type=MemberType.FILE, name="f").is_file
    assert ArchiveMember(type=MemberType.DIRECTORY, name="d/").is_dir
    assert ArchiveMember(type=MemberType.SYMLINK, name="s").is_link
    assert ArchiveMember(type=MemberType.HARDLINK, name="h").is_link
    assert ArchiveMember(type=MemberType.OTHER, name="o").is_other
    assert ArchiveMember(type=MemberType.ANTI, name="a").is_anti
    assert not ArchiveMember(type=MemberType.ANTI, name="a").is_file


def test_junction_helper() -> None:
    junction = ArchiveMember(
        type=MemberType.SYMLINK, name="j", extra=MemberExtra({EXTRA_IS_JUNCTION: True})
    )
    assert junction.is_junction
    assert not ArchiveMember(type=MemberType.SYMLINK, name="s").is_junction


def test_extra_is_an_open_mapping() -> None:
    # The names are importable at runtime.
    assert ArchiveMember.__annotations__["extra"] == "MemberExtra"
    assert ArchiveInfo.__annotations__["extra"] == "ArchiveInfoExtra"
    assert issubclass(MemberExtra, dict)
    assert issubclass(ArchiveInfoExtra, dict)
    # ``__slots__ = ()`` drops the per-instance ``__dict__``; the contract is the
    # key space, so an attribute write must not silently succeed.
    with pytest.raises(AttributeError):
        MemberExtra().not_a_key = True
    with pytest.raises(AttributeError):
        ArchiveInfoExtra().not_a_key = True

    m = ArchiveMember(
        type=MemberType.FILE, name="a", extra=MemberExtra({"third.party": 1})
    )
    assert isinstance(m.extra, MemberExtra)
    assert m.extra["third.party"] == 1
    assert m.extra == {"third.party": 1}

    empty = ArchiveMember(type=MemberType.FILE, name="b")
    assert isinstance(empty.extra, MemberExtra)
    assert empty.extra == {}
    empty.extra["third.party"] = 1
    assert empty.extra["third.party"] == 1

    bag = MemberExtra({"is_junction": True, "third.party": 1})
    assert bag == {"is_junction": True, "third.party": 1}
    assert json.loads(json.dumps(bag)) == {"is_junction": True, "third.party": 1}

    # Equality alone would pass on a plain dict, so assert the class survives too:
    # a round trip that degraded to dict would keep the data and silently lose the
    # declared key types for anything re-annotating the result.
    for roundtripped in (
        copy.copy(bag),
        copy.deepcopy(bag),
        pickle.loads(pickle.dumps(bag)),
    ):
        assert roundtripped == bag
        assert isinstance(roundtripped, MemberExtra)


def test_modified_utc_normalizes_mixed_timestamps() -> None:
    from datetime import datetime, timedelta, timezone

    # Aware (e.g. an NTFS-extra UTC time): converted to UTC.
    aware = ArchiveMember(
        type=MemberType.FILE,
        name="aware",
        modified=datetime(2020, 6, 1, 14, 0, tzinfo=timezone(timedelta(hours=2))),
    )
    assert aware.modified_utc() == datetime(2020, 6, 1, 12, 0, tzinfo=UTC)

    # Naive (a wall-clock DOS time): tz_for_naive supplies the caller's assumption.
    naive = ArchiveMember(
        type=MemberType.FILE, name="naive", modified=datetime(2020, 6, 1, 14, 0)
    )
    as_utc = naive.modified_utc(tz_for_naive=timezone(timedelta(hours=-3)))
    assert as_utc == datetime(2020, 6, 1, 17, 0, tzinfo=UTC)

    # Default: naive is interpreted in the local timezone; the result is aware UTC and
    # comparable with the aware member's (mixed naive/aware raises TypeError directly).
    local_utc = naive.modified_utc()
    assert local_utc is not None and local_utc.tzinfo == UTC
    assert (local_utc < aware.modified_utc()) in (
        True,
        False,
    )  # comparable, no TypeError

    # The stored field is untouched: provenance stays checkable.
    assert naive.modified is not None and naive.modified.tzinfo is None
    assert ArchiveMember(type=MemberType.FILE, name="none").modified_utc() is None
