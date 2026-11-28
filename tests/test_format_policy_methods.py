"""``FormatPolicy(exclude=)`` with :class:`~archivey.types.CompressionAlgorithm` entries: member
compression methods a call may not decode.

The ZIP archives come from the test-only encoders in ``tests/zip_legacy_build.py``. The
legacy decoders are replaced with one that fails the test, so every path here shows the
refusal comes before the decoder starts, not only that the read fails.
"""

from __future__ import annotations

import io
import lzma
import re
import tarfile
import zlib
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    ArchiveyUsageError,
    ContainerFormat,
    CorruptionError,
    DiagnosticCode,
    FormatPolicy,
    MemberType,
    StreamFormat,
    UnsupportedFeatureError,
    open_archive,
)
from archivey.format_policy import excluded_method_refusal
from archivey.internal.streams.codecs import lzma_codec, xz_decoder, zip_legacy_codec
from archivey.types import CompressionAlgorithm, CompressionMethod
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
    policy = FormatPolicy(exclude={StreamFormat.XZ})
    assert A.XZ not in policy.exclude
    # The stream format entry is about the file only: it does not reach members.
    assert policy._excluded_methods((CompressionMethod(A.XZ),)) == ()


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
    with open_archive(source, config=_NO_LEGACY, pipe=pipe) as reader:
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


@pytest.mark.parametrize(
    ("method", "fmt"),
    [
        (A.XZ, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.XZ)),
        (A.XZ, ArchiveFormat(ContainerFormat.TAR, StreamFormat.XZ)),
        # Every xz stream is LZMA2 inside, so turning LZMA2 off refuses xz too.
        (A.LZMA2, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.XZ)),
        (A.LZMA2, ArchiveFormat(ContainerFormat.TAR, StreamFormat.XZ)),
        (A.DEFLATE, ArchiveFormat.TAR_GZ),
        (A.DEFLATE, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.ZLIB)),
        (A.LZMA, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.LZIP)),
        (A.LZ4, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.MOZLZ4)),
        (A.LZO, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.LZOP)),
        (A.LZW, ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.UNIX_COMPRESS)),
        (A.BZIP3, ArchiveFormat(ContainerFormat.TAR, StreamFormat.BZIP3)),
    ],
    ids=lambda v: v.display_name if isinstance(v, ArchiveFormat) else v.name,
)
def test_a_method_entry_refuses_a_file_compressed_with_it(
    method: CompressionAlgorithm, fmt: ArchiveFormat
) -> None:
    policy = FormatPolicy(exclude={method})
    assert not policy.allows(fmt)
    assert policy._refusal(fmt) == (
        f"ArchiveyConfig.formats does not allow {fmt.display_name}: exclude= lists "
        f"CompressionAlgorithm.{method.name}, which StreamFormat.{fmt.stream.name} "
        "decodes with."
    )


def test_a_method_entry_leaves_other_compressions_open() -> None:
    policy = FormatPolicy(exclude={A.XZ})
    assert policy.allows(ArchiveFormat.TAR_GZ)
    # LZMA2 inside 7z is its own method.
    assert policy.allows(ArchiveFormat.SEVEN_Z)


@pytest.mark.parametrize("method", [A.XZ, A.LZMA2])
def test_opening_a_file_compressed_with_an_excluded_method_is_refused(
    method: CompressionAlgorithm,
) -> None:
    config = ArchiveyConfig(formats=FormatPolicy(exclude={method}))
    with pytest.raises(
        UnsupportedFeatureError, match=rf"CompressionAlgorithm\.{method.name}"
    ):
        open_archive(io.BytesIO(lzma.compress(_DATA)), config=config)


def test_lzma2_off_refuses_an_xz_member() -> None:
    """A ZIP member compressed with xz (method 95) decodes LZMA2 too."""
    xz = LegacyEntry("x.txt", _DATA, 95, lzma.compress(_DATA))
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.LZMA2}))
    with open_archive(io.BytesIO(build_zip([xz])), config=config) as reader:
        assert reader.members()[0].compression[0].algo is A.XZ
        with pytest.raises(
            UnsupportedFeatureError,
            match=(
                r"'x\.txt' is compressed with CompressionAlgorithm\.XZ, which decodes "
                r"with CompressionAlgorithm\.LZMA2; exclude= lists it\."
            ),
        ):
            reader.read("x.txt")
    with open_archive(io.BytesIO(build_zip([xz]))) as reader:
        assert reader.read("x.txt") == _DATA


# -- review round 1: data decoded elsewhere than the member's own chain ----------------


@pytest.mark.parametrize("streaming", [False, True])
def test_a_rar_file_copy_is_refused_by_its_sources_method(streaming: bool) -> None:
    """A RAR5 file copy lists STORED but decodes its source's data."""
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.RAR}))
    path = _FIXTURES / "rar" / "links_before_data_solid__.rar"
    with open_archive(path, config=config, streaming=streaming) as reader:
        for member, stream in reader.stream_members():
            if member.name != "copy.txt":
                continue
            assert member.compression[0].algo is A.STORED
            assert stream is not None
            with pytest.raises(UnsupportedFeatureError, match=r"copies 'a\.txt'"):
                stream.read()
    with (
        open_archive(path, config=config) as reader,
        pytest.raises(UnsupportedFeatureError, match=r"CompressionAlgorithm\.RAR"),
    ):
        reader.read("copy.txt")


def test_a_compressed_rar3_comment_is_not_decoded_when_rar_is_excluded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.backends import rar_reader

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the RAR decoder was started for the comment")

    monkeypatch.setattr(rar_reader, "open_unrar_p", _fail)
    monkeypatch.setattr(rar_reader, "_open_unar_blob_pipe", _fail)
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.RAR}))
    path = _FIXTURES / "rar" / "comment_compressed__rar4.rar"
    with open_archive(path, config=config) as reader:
        assert reader.info.comment is None


@pytest.mark.parametrize(
    ("fixture", "method"),
    [
        ("rpm/payload-gzip.rpm", A.DEFLATE),
        ("rpm/payload-bzip2.rpm", A.BZIP2),
        ("rpm/payload-lzma.rpm", A.LZMA),
        ("rpm/payload-xz.rpm", A.XZ),
        ("rpm/payload-xz.rpm", A.LZMA2),
        ("squashfs/gzip.sqfs", A.DEFLATE),
        ("squashfs/lz4.sqfs", A.LZ4),
        ("squashfs/xz.sqfs", A.XZ),
        ("squashfs/xz.sqfs", A.LZMA2),
        ("deb/hello-gzip.deb", A.DEFLATE),
        ("deb/hello-xz.deb", A.XZ),
        ("deb/hello-xz.deb", A.LZMA2),
        ("makeself/xz-2.7.1.run", A.XZ),
        ("makeself/xz-2.7.1.run", A.LZMA2),
    ],
)
def test_a_format_compressing_inside_itself_is_refused_at_open(
    fixture: str, method: CompressionAlgorithm
) -> None:
    """Pinned per backend: a format that decodes its own payload or blocks with an
    excluded method does not open, whichever way it reaches the decoder
    (``ForwardStream.decompress``, ``ReaderContext.decompress``, ``open_nested`` or
    its own block decoder)."""
    config = ArchiveyConfig(formats=FormatPolicy(exclude={method}))
    with (
        pytest.raises(UnsupportedFeatureError, match=method.name),
        open_archive(_FIXTURES / fixture, config=config) as reader,
    ):
        for member in reader.members():
            if member.is_file:
                reader.read(member)


# -- xz filters: a BCJ or Delta filter inside an xz block ------------------------------

_X86 = [{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}]
_DELTA = [{"id": lzma.FILTER_DELTA, "dist": 4}, {"id": lzma.FILTER_LZMA2}]


def _xz(data: bytes, filters: list[dict[str, int]] | None = None) -> bytes:
    # An explicit check: PyPy's lzma raises "Internal error" for a filter chain with the
    # default check. CRC64 is the default, so CPython writes the same bytes either way.
    return lzma.compress(
        data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, filters=filters
    )


def _vli(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _one_stream(*streams: bytes) -> bytes:
    """The single-block xz ``streams`` (CRC64 checks) as the blocks of one stream, in
    order: each block keeps its own filter chain, as ``xz --block-list`` with
    ``--filters1`` writes them."""
    blocks, records = b"", b""
    for stream in streams:
        index_size = (int.from_bytes(stream[-8:-4], "little") + 1) * 4
        blocks += stream[12 : len(stream) - 12 - index_size]
        index = stream[len(stream) - 12 - index_size :]
        assert index[:2] == b"\x00\x01"  # one record
        unpadded, n = _vli_at(index, 2)
        uncompressed, m = _vli_at(index, 2 + n)
        records += _vli(unpadded) + _vli(uncompressed)
        assert 2 + n + m <= len(index)
    index = b"\x00" + _vli(len(streams)) + records
    index += b"\x00" * (-len(index) % 4)
    index += zlib.crc32(index).to_bytes(4, "little")
    flags = streams[0][6:8]
    backward = (len(index) // 4 - 1).to_bytes(4, "little")
    footer = zlib.crc32(backward + flags).to_bytes(4, "little") + backward + flags
    return streams[0][:12] + blocks + index + footer + b"YZ"


def _vli_at(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for i in range(9):
        byte = data[pos + i]
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value, i + 1
    raise AssertionError("VLI too long")


def _ar_file(*members: tuple[bytes, bytes]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
        out += b"100644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n" + data
        out += b"\n" * (len(data) & 1)
    return bytes(out)


def _tar_of(name: str, data: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _read_all(source: Path | bytes, config: ArchiveyConfig) -> None:
    with open_archive(
        source if isinstance(source, Path) else io.BytesIO(source), config=config
    ) as reader:
        for member in reader.members():
            if member.is_file:
                reader.read(member)


_FILTERED_XZ = [
    pytest.param(A.BCJ, _xz(_DATA, _X86), 1, id="bcj"),
    pytest.param(A.DELTA, _xz(_DATA, _DELTA), 1, id="delta"),
    # Only a later block of the stream uses the filter.
    pytest.param(
        A.BCJ, _one_stream(_xz(_DATA), _xz(_DATA, _X86)), 2, id="second-block"
    ),
    # Only the second of two streams uses it.
    pytest.param(A.DELTA, _xz(_DATA) + _xz(_DATA, _DELTA), 2, id="second-stream"),
]


@pytest.mark.parametrize(("method", "data", "copies"), _FILTERED_XZ)
def test_an_excluded_xz_filter_is_refused_before_it_decodes(
    method: CompressionAlgorithm, data: bytes, copies: int
) -> None:
    """The filters an xz block runs ahead of LZMA2 are in its header, not in the
    member's ``compression``: the decoder refuses an excluded one at the block."""
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read(reader.members()[0]) == _DATA * copies
    config = ArchiveyConfig(formats=FormatPolicy(exclude={method}))
    with pytest.raises(
        UnsupportedFeatureError, match=rf"CompressionAlgorithm\.{method.name}"
    ):
        _read_all(data, config)


@pytest.mark.parametrize("exclude", [A.BCJ, A.DELTA], ids=["bcj-off", "delta-off"])
def test_an_xz_stream_without_the_excluded_filter_still_reads(
    exclude: CompressionAlgorithm,
) -> None:
    """Not every xz stream is refused: only a block that uses the filter."""
    other = _X86 if exclude is A.DELTA else _DELTA
    config = ArchiveyConfig(formats=FormatPolicy(exclude={exclude}))
    for data in (_xz(_DATA), _xz(_DATA, other)):
        with open_archive(io.BytesIO(data), config=config) as reader:
            assert reader.read(reader.members()[0]) == _DATA


def test_the_blocks_before_an_excluded_xz_block_still_read() -> None:
    """The stream stops at the block that runs the filter, not before: the block
    ahead of it reads whole, however the input arrives."""
    data = _one_stream(_xz(_DATA), _xz(_DATA, _X86))
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.BCJ}))
    for pipe in (False, True):
        source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
        got = b""
        with open_archive(source, config=config, pipe=pipe) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                with pytest.raises(UnsupportedFeatureError, match=r"BCJ"):
                    while chunk := stream.read(1000):
                        got += chunk
        assert got == _DATA


def test_a_seek_into_an_excluded_xz_block_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read that resumes at the filtered block from the stream's index is refused
    there, and the refusal does not cast doubt on the index."""
    resumed: list[int] = []
    resume = xz_decoder._XzBlockResume

    def spy(start: object, *args: object, **kwargs: object) -> object:
        resumed.append(start.compressed_start)
        return resume(start, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(xz_decoder, "_XzBlockResume", spy)
    data = _one_stream(_xz(_DATA), _xz(_DATA, _X86))
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.BCJ}))
    with open_archive(io.BytesIO(data), config=config, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.seek(len(_DATA) + 10)
            with pytest.raises(UnsupportedFeatureError, match=r"BCJ"):
                stream.read()
        assert resumed
        codes = {d.code for d in reader.diagnostics.retained}
        assert DiagnosticCode.SEEK_INDEX_DEGRADED not in codes


def test_an_xz_zip_member_with_an_excluded_filter_is_refused() -> None:
    packed = _xz(_DATA, _X86)
    member = LegacyEntry("x.bin", _DATA, 95, packed)
    raw = build_zip([member, LegacyEntry("stored.txt", _DATA, 0, _DATA)])
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.BCJ}))
    with open_archive(io.BytesIO(raw), config=config) as reader:
        assert reader.read("stored.txt") == _DATA
        with pytest.raises(UnsupportedFeatureError, match=r"CompressionAlgorithm\.BCJ"):
            reader.read("x.bin")


@pytest.mark.parametrize("method", [A.BCJ, A.DELTA])
def test_a_tar_xz_or_deb_with_an_excluded_filter_is_refused(
    method: CompressionAlgorithm,
) -> None:
    filters = _X86 if method is A.BCJ else _DELTA
    tar_xz = _xz(_tar_of("payload.bin", _DATA), filters)
    deb = _ar_file(
        (b"debian-binary", b"2.0\n"),
        (b"control.tar", _tar_of("./control", b"Package: p\n")),
        (b"data.tar.xz", tar_xz),
    )
    config = ArchiveyConfig(formats=FormatPolicy(exclude={method}))
    # The policy's own refusal text, as every other excluded method gets.
    refusal = re.escape(excluded_method_refusal(method))
    for data in (tar_xz, deb):
        _read_all(data, ArchiveyConfig())
        with pytest.raises(UnsupportedFeatureError, match=refusal):
            _read_all(data, config)


def test_squashfs_xz_blocks_are_checked_for_excluded_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SquashFS decodes each xz block through the xz codec, which gets the filters to
    refuse. ``xz-bcj.sqfs`` was written with ``-Xbcj x86``, but mksquashfs kept the
    plain LZMA2 result for every block (its data is not x86 code), so no block runs
    BCJ and the image reads under ``exclude={BCJ}``."""
    seen: list[frozenset[int]] = []
    stream = lzma_codec.XzDecompressorStream

    def spy(*args: object, filters_off: frozenset[int], **kwargs: object) -> object:
        seen.append(filters_off)
        return stream(*args, filters_off=filters_off, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(lzma_codec, "XzDecompressorStream", spy)
    fixture = _FIXTURES / "squashfs" / "xz-bcj.sqfs"
    _read_all(fixture, ArchiveyConfig(formats=FormatPolicy(exclude={A.BCJ})))
    assert seen
    assert all(lzma.FILTER_X86 in off for off in seen)


def test_the_xz_detection_probe_does_not_run_an_excluded_filter() -> None:
    """The inner-format probe decodes a block raw with the chain its header declares;
    an excluded filter is "can't tell" there, raised before a decoder is built."""
    data = _xz(_tar_of("payload.bin", _DATA), _X86)
    off = xz_decoder.xz_filters_off(frozenset({A.BCJ}))
    assert xz_decoder._decode_xz_head(io.BytesIO(data).read, 512)
    with pytest.raises(UnsupportedFeatureError, match=r"CompressionAlgorithm\.BCJ"):
        xz_decoder._decode_xz_head(io.BytesIO(data).read, 512, filters_off=off)


@pytest.mark.parametrize("piece", [1, 3, 7, 64, 1 << 20])
def test_the_xz_filter_guard_stops_at_the_refused_header_however_fed(
    piece: int,
) -> None:
    """Fed in pieces of any size, the guard lets liblzma have every byte before the
    refused block's header and never the whole header: at most the part of it that
    earlier pieces held, which liblzma cannot act on."""
    first = _xz(_DATA)
    data = _one_stream(first, _xz(_DATA, _X86))
    header_at = len(first) - 12 - (int.from_bytes(first[-8:-4], "little") + 1) * 4
    off = xz_decoder.xz_filters_off(frozenset({A.BCJ}))
    guard = xz_decoder._XzFilterGuard(off, data[7], pos=12)
    allowed = 0
    for at in range(12, len(data), piece):
        chunk = data[at : at + piece]
        allowed += guard.feed(chunk)
        if guard.error is not None:
            break
    assert isinstance(guard.error, UnsupportedFeatureError)
    header_size = (data[header_at] + 1) * 4
    start = header_at - 12
    assert start <= allowed < start + header_size
    if piece >= len(data):
        assert allowed == start


def _block_header(body: bytes) -> bytes:
    """A block header around ``body`` (flags onward), padded and with its CRC32."""
    size = -(-(len(body) + 1 + 4) // 4) * 4
    head = bytes([size // 4 - 1]) + body
    head += b"\x00" * (size - 4 - len(head))
    return head + zlib.crc32(head).to_bytes(4, "little")


@pytest.mark.parametrize(
    ("header", "error", "message"),
    [
        # Reserved flag bits: liblzma reads them as options it does not know.
        (_block_header(b"\x04\x21\x01\x16"), UnsupportedFeatureError, "reserved"),
        # A VLI that runs past the header.
        (
            _block_header(b"\x00" + b"\xff" * 3),
            CorruptionError,
            "block header MBI",
        ),
        # A filter ID that is not minimally encoded (0x21 as 0xA1 0x00).
        (
            _block_header(b"\x00\xa1\x00\x01\x16"),
            CorruptionError,
            "block header MBI is not minimally encoded",
        ),
        # Properties longer than the header.
        (_block_header(b"\x00\x21\x7f"), CorruptionError, "properties"),
        # Four filters, the header holds one.
        (
            _block_header(b"\x03\x21\x01\x16"),
            CorruptionError,
            "block header MBI truncated",
        ),
        # A size field that never ends.
        (
            _block_header(b"\x40" + b"\x80" * 9 + b"\x00"),
            CorruptionError,
            "block header MBI exceeds 9 bytes",
        ),
        # Padding that is not zero.
        (_block_header(b"\x00\x21\x01\x16\x00\x01"), CorruptionError, "padding"),
    ],
)
def test_a_hostile_xz_block_header_does_not_parse(
    header: bytes, error: type[Exception], message: str
) -> None:
    """Each field is bounds-checked against the header's own size, and an error names
    the block header. The guard and the detection probe both read a header through
    this one parser."""
    with pytest.raises(error, match=message):
        xz_decoder._block_filters(header)


def test_an_xz_block_header_lists_its_filters() -> None:
    assert xz_decoder._block_filters(_block_header(b"\x01\x04\x00\x21\x01\x16")) == [
        (0x04, b""),
        (0x21, b"\x16"),
    ]


def _with_first_header(body: bytes) -> bytes:
    """A one-block xz of ``_DATA`` whose 12-byte block header holds ``body`` (flags
    onward, seven bytes) under a matching CRC32; the block's data is unchanged."""
    data = _xz(_DATA)
    assert data[12] == 0x02  # a 12-byte header
    head = b"\x02" + body
    return data[:12] + head + zlib.crc32(head).to_bytes(4, "little") + data[24:]


_DICT = _xz(_DATA)[16]  # the LZMA2 properties byte lzma.compress writes

_HOSTILE_XZ = [
    pytest.param(
        _with_first_header(bytes([0x04, 0x21, 0x01, _DICT, 0, 0, 0])),
        id="reserved-flags",
    ),
    pytest.param(
        _with_first_header(bytes([0x05, 0x04, 0x00, 0x21, 0x01, _DICT, 0])),
        id="reserved-flags-bcj",
    ),
    pytest.param(
        _with_first_header(bytes([0x00, 0x21, 0x01, _DICT, 0, 1, 0])),
        id="padding",
    ),
    pytest.param(
        _with_first_header(bytes([0x00, 0x21, 0x7F, 0, 0, 0, 0])), id="properties"
    ),
    pytest.param(
        _with_first_header(bytes([0x03, 0x21, 0x01, _DICT, 0, 0, 0])),
        id="four-filters",
    ),
    pytest.param(_with_first_header(b"\x00" + b"\xff" * 6), id="vli-past-header"),
    pytest.param(
        _with_first_header(bytes([0x00, 0xA1, 0x00, 0x01, _DICT, 0, 0])),
        id="vli-not-minimal",
    ),
    pytest.param(
        _xz(_DATA)[:20] + bytes([_xz(_DATA)[20] ^ 1]) + _xz(_DATA)[21:],
        id="header-crc",
    ),
    pytest.param(_xz(_DATA)[:24] + b"\x03" + _xz(_DATA)[25:], id="chunk-control"),
]


@pytest.mark.parametrize("piece", [1, 5, 1 << 20])
def test_the_xz_filter_guard_gives_liblzma_an_unread_header_and_nothing_after(
    piece: int,
) -> None:
    """A header the guard cannot read (reserved flag bits here) goes to liblzma whole,
    so liblzma's own error stands. Nothing past it does: a liblzma that accepted the
    header would get the guard's error before any of the block, so no later block
    runs unchecked."""
    data = _HOSTILE_XZ[0].values[0]
    assert isinstance(data, bytes)
    off = xz_decoder.xz_filters_off(frozenset({A.BCJ}))
    guard = xz_decoder._XzFilterGuard(off, data[7], pos=12)
    allowed = 0
    for at in range(12, len(data), piece):
        allowed += guard.feed(data[at : at + piece])
        if guard.error is not None:
            break
    assert isinstance(guard.error, UnsupportedFeatureError)
    assert "CompressionAlgorithm" not in str(guard.error)
    assert allowed == 12  # the 12-byte block header, whole
    assert guard.feed(data[24:]) == 0


@pytest.mark.parametrize("data", _HOSTILE_XZ)
@pytest.mark.parametrize("method", [A.BCJ, A.DELTA])
def test_the_policy_does_not_change_the_error_for_a_hostile_xz(
    data: bytes, method: CompressionAlgorithm
) -> None:
    """A policy that names BCJ or Delta refuses only a block that runs the filter. A
    block header it cannot read is liblzma's to refuse, with the exception type it
    gets without the policy."""
    with pytest.raises(ArchiveyError) as plain:
        _read_all(data, ArchiveyConfig())
    with pytest.raises(ArchiveyError) as policed:
        _read_all(data, ArchiveyConfig(formats=FormatPolicy(exclude={method})))
    assert type(policed.value) is type(plain.value)
    assert "CompressionAlgorithm" not in str(policed.value)


def test_detection_does_not_probe_through_an_excluded_xz_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``open_archive`` probes an xz file for an inner TAR; under ``exclude={BCJ}``
    that probe is given the filter to refuse."""
    seen: list[frozenset[int]] = []
    head = lzma_codec.open_xz_head

    def spy(*args: object, filters_off: frozenset[int], **kwargs: object) -> object:
        seen.append(filters_off)
        return head(*args, filters_off=filters_off, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(lzma_codec, "open_xz_head", spy)
    data = _xz(_tar_of("payload.bin", _DATA), _X86)
    config = ArchiveyConfig(formats=FormatPolicy(exclude={A.BCJ}))
    with pytest.raises(UnsupportedFeatureError, match=r"CompressionAlgorithm\.BCJ"):
        _read_all(data, config)
    assert seen
    assert all(lzma.FILTER_X86 in off for off in seen)
