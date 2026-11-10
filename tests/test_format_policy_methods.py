"""``FormatPolicy(exclude=)`` with :class:`~archivey.CompressionAlgorithm` entries: member
compression methods a call may not decode.

The ZIP archives come from the test-only encoders in ``tests/zip_legacy_build.py``. The
legacy decoders are replaced with one that fails the test, so every path here shows the
refusal comes before the decoder starts, not only that the read fails.
"""

from __future__ import annotations

import io
import lzma
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    CompressionAlgorithm,
    ContainerFormat,
    DiagnosticCode,
    FormatPolicy,
    MemberType,
    StreamFormat,
    UnsupportedFeatureError,
    open_archive,
)
from archivey.internal.streams.codecs import zip_legacy_codec
from tests.streams_util import NonSeekableBytesIO
from tests.zip_legacy_build import (
    LegacyEntry,
    build_zip,
    implode_entry,
    shrink_entry,
)

A = CompressionAlgorithm
_FIXTURES = Path(__file__).parent / "fixtures"
_DATA = b"a legacy member, " * 300
_NO_LEGACY = ArchiveyConfig(formats=FormatPolicy(exclude={A.SHRINK, A.IMPLODE}))


@pytest.fixture
def no_legacy_decoders(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if a Shrink or Implode decoder is built."""

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an excluded method's decoder was started")

    monkeypatch.setattr(zip_legacy_codec, "ShrinkDecompressor", _fail)
    monkeypatch.setattr(zip_legacy_codec, "ImplodeDecompressor", _fail)


def _legacy_zip(*, descriptor: bool = False) -> bytes:
    return build_zip(
        [
            shrink_entry("shrunk.txt", _DATA),
            implode_entry(
                "imploded.txt", _DATA, large_window=False, literal_tree=False
            ),
            LegacyEntry("stored.txt", _DATA, 0, _DATA),
        ],
        descriptor=descriptor,
    )


# -- construction --------------------------------------------------------------------


def test_exclude_takes_compression_methods() -> None:
    policy = FormatPolicy(exclude={A.IMPLODE, ContainerFormat.ISO})
    assert policy.exclude == frozenset({A.IMPLODE, ContainerFormat.ISO})
    # A method is about members, not the file opened.
    assert policy.allows(ArchiveFormat.ZIP)
    assert not policy.allows(ArchiveFormat.ISO)


@pytest.mark.parametrize(
    ("kwargs", "error", "match"),
    [
        pytest.param(
            {"only": {ContainerFormat.ZIP, A.DEFLATE}},
            TypeError,
            r"CompressionAlgorithm\.DEFLATE in only=.*refused with exclude=",
            id="only-takes-no-methods",
        ),
        pytest.param(
            {"exclude": {A.STORED}},
            ValueError,
            r"CompressionAlgorithm\.STORED in exclude=",
            id="stored",
        ),
        pytest.param(
            {"exclude": {A.UNKNOWN}},
            ValueError,
            r"CompressionAlgorithm\.UNKNOWN in exclude=",
            id="unknown",
        ),
        pytest.param(
            {"exclude": {"implode"}},
            TypeError,
            r"CompressionAlgorithm members for exclude=",
            id="string-spelling",
        ),
    ],
)
def test_method_entry_refusals(
    kwargs: dict[str, object], error: type[Exception], match: str
) -> None:
    with pytest.raises(ArchiveyUsageError, match=match) as info:
        FormatPolicy(**kwargs)  # type: ignore[arg-type]
    assert isinstance(info.value, error)


def test_a_method_and_a_stream_format_of_the_same_name_are_different_entries() -> None:
    policy = FormatPolicy(exclude={A.XZ})
    assert StreamFormat.XZ not in policy.exclude
    # A .xz file still opens: the method entry refuses xz members only.
    assert policy.allows(ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.XZ))


# -- ZIP -----------------------------------------------------------------------------


@pytest.mark.usefixtures("no_legacy_decoders")
def test_an_excluded_member_lists_but_does_not_open() -> None:
    with open_archive(io.BytesIO(_legacy_zip()), config=_NO_LEGACY) as reader:
        methods = {m.name: m.compression[0].algo for m in reader.members()}
        assert methods == {
            "shrunk.txt": A.SHRINK,
            "imploded.txt": A.IMPLODE,
            "stored.txt": A.STORED,
        }
        for name, method in (("shrunk.txt", "SHRINK"), ("imploded.txt", "IMPLODE")):
            with pytest.raises(
                UnsupportedFeatureError,
                match=rf"CompressionAlgorithm\.{method}.*exclude= lists it",
            ) as info:
                reader.read(name)
            assert info.value.member_name == name
        assert reader.read("stored.txt") == _DATA


@pytest.mark.usefixtures("no_legacy_decoders")
@pytest.mark.parametrize("descriptor", [False, True], ids=["sizes", "descriptor"])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_data_pass_refuses_an_excluded_member_without_decoding_it(
    pipe: bool, descriptor: bool
) -> None:
    """A pass hands out a stream that raises the refusal; from a pipe, the walk skips
    the member's data undecoded, data descriptor or not."""
    data = _legacy_zip(descriptor=descriptor)
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    seen: dict[str, bytes | str] = {}
    with open_archive(source, config=_NO_LEGACY, streaming=pipe) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            try:
                seen[member.name] = stream.read()
            except UnsupportedFeatureError as exc:
                seen[member.name] = type(exc).__name__
    assert seen == {
        "shrunk.txt": "UnsupportedFeatureError",
        "imploded.txt": "UnsupportedFeatureError",
        "stored.txt": _DATA,
    }


@pytest.mark.usefixtures("no_legacy_decoders")
def test_a_skipped_excluded_member_raises_nothing() -> None:
    with open_archive(io.BytesIO(_legacy_zip()), config=_NO_LEGACY) as reader:
        read = {
            m.name: s.read()
            for m, s in reader.stream_members(lambda m: m.name == "stored.txt")
            if s is not None
        }
    assert read == {"stored.txt": _DATA}


@pytest.mark.usefixtures("no_legacy_decoders")
def test_extraction_refuses_an_excluded_member(tmp_path: Path) -> None:
    with (
        open_archive(io.BytesIO(_legacy_zip()), config=_NO_LEGACY) as reader,
        pytest.raises(UnsupportedFeatureError, match=r"exclude= lists it"),
    ):
        reader.extract_all(tmp_path)


def test_the_default_policy_still_decodes_legacy_methods() -> None:
    with open_archive(io.BytesIO(_legacy_zip())) as reader:
        assert reader.read("shrunk.txt") == _DATA
        assert reader.read("imploded.txt") == _DATA


# -- other formats -------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_a_solid_7z_block_refuses_each_member(streaming: bool) -> None:
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.LZMA2}))
    path = _FIXTURES / "sevenzip" / "solid_three_members.7z"
    with open_archive(path, config=config, streaming=streaming) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(UnsupportedFeatureError, match="LZMA2"):
                stream.read()


@pytest.mark.parametrize("streaming", [False, True])
def test_a_link_whose_target_is_excluded_data_lists_without_a_target(
    streaming: bool,
) -> None:
    """A 7z symlink stores its target as data: with the method off it lists with no
    target and the diagnostic an undecodable target gets."""
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.LZMA2}))
    path = _FIXTURES / "sevenzip" / "links_mid_folder_solid.7z"
    with open_archive(path, config=config, streaming=streaming) as reader:
        links = [m for m, _s in reader.stream_members() if m.type is MemberType.SYMLINK]
        diagnostics = reader.diagnostics.retained
    assert links
    assert all(link.link_target is None for link in links)
    reasons = [
        d.context.reason  # type: ignore[union-attr]
        for d in diagnostics
        if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    ]
    assert reasons == ["target_data_unsupported"] * len(links)


def test_rar_members_follow_the_method_not_the_container() -> None:
    """Excluding RAR's own method leaves its stored members readable."""
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.RAR}))
    path = _FIXTURES / "rar" / "basic_nonsolid__.rar"
    with open_archive(path, config=config) as reader:
        assert reader.read("file1.txt")
    path = _FIXTURES / "rar" / "basic_solid__.rar"
    with (
        open_archive(path, config=config) as reader,
        pytest.raises(UnsupportedFeatureError, match=r"CompressionAlgorithm\.RAR"),
    ):
        reader.read("file1.txt")


# -- the COMMON preset ---------------------------------------------------------------


def test_the_common_preset_is_pinned() -> None:
    """Each entry is a decision: a change here is a changelog line, not a refactor."""
    C, S = ContainerFormat, StreamFormat
    assert FormatPolicy.COMMON.only == frozenset(
        {C.ZIP, C.TAR, C.RAR, C.SEVEN_Z, C.RAW_STREAM} | {S.GZIP, S.BZIP2, S.XZ, S.ZSTD}
    )
    assert FormatPolicy.COMMON.exclude == frozenset(
        {A.SHRINK, A.IMPLODE, A.REDUCE, A.DCL_IMPLODE}
    )
    assert FormatPolicy.COMMON.plugins
    assert not FormatPolicy.COMMON.replace
    assert not FormatPolicy.COMMON.exclude_libraries


@pytest.mark.parametrize(
    ("fmt", "allowed"),
    [
        (ArchiveFormat.ZIP, True),
        (ArchiveFormat.TAR_GZ, True),
        (ArchiveFormat(ContainerFormat.TAR, StreamFormat.ZSTD), True),
        (ArchiveFormat.SEVEN_Z, True),
        (ArchiveFormat.RAR, True),
        (ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.BZIP2), True),
        (ArchiveFormat.ISO, False),
        (ArchiveFormat(ContainerFormat.CAB, StreamFormat.UNCOMPRESSED), False),
        (ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.UNIX_COMPRESS), False),
        (ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZ4), False),
        (ArchiveFormat(ContainerFormat.DIRECTORY, StreamFormat.UNCOMPRESSED), False),
    ],
    ids=lambda v: v.display_name if isinstance(v, ArchiveFormat) else None,
)
def test_what_the_common_preset_opens(fmt: ArchiveFormat, allowed: bool) -> None:
    assert FormatPolicy.COMMON.allows(fmt) is allowed


@pytest.mark.usefixtures("no_legacy_decoders")
def test_the_common_preset_refuses_legacy_zip_members() -> None:
    config = ArchiveyConfig(formats=FormatPolicy.COMMON)
    with open_archive(io.BytesIO(_legacy_zip()), config=config) as reader:
        with pytest.raises(UnsupportedFeatureError, match="SHRINK"):
            reader.read("shrunk.txt")
        assert reader.read("stored.txt") == _DATA


def test_a_method_entry_does_not_refuse_a_compressed_file() -> None:
    """A bare ``.xz`` file is a compression stream, not a member compressed with xz."""
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.XZ, A.LZMA2}))
    with open_archive(io.BytesIO(lzma.compress(_DATA)), config=config) as reader:
        (member,) = reader.members()
        assert reader.read(member) == _DATA
