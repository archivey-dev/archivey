"""Malformed 7z folder structures are refused at parse time, with the right error class.

One hand-built header per finding from the S2 sweep of the native 7z parser (tracked
internally): coder-graph checks, substream accounting, pack-index overruns, a short
next-header read, Delta-only folders, BCJ start offsets. Plus the ``max_members``
keyword contract the RAR parser already follows.
"""

from __future__ import annotations

import ast
import inspect
import io
import lzma
import struct
import subprocess
import sys
import zlib
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from archivey.config import ListingLimits
from archivey.exceptions import (
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import (
    sevenzip_parser,
    sevenzip_pipeline,
    sevenzip_reader,
)
from archivey.internal.backends.sevenzip_parser import (
    MAGIC_7Z,
    PlainHeader,
    SevenZipArchive,
    SevenZipCoder,
    materialize_archive,
    parse_header_block,
    read_signature_and_next_header,
)
from archivey.internal.backends.sevenzip_pipeline import plan_folder
from archivey.internal.backends.sevenzip_reader import load_sevenzip_archive
from tests.conftest import requires_binary
from tests.corruption_util import raises_corruption_not_truncation

_COPY = b"\x00"
_DELTA = b"\x03"
_BCJ_X86 = b"\x04"
_BCJ_ARM = b"\x07"
_LZMA = b"\x03\x01\x01"
_LZMA2 = b"\x21"

# ---------------------------------------------------------------------------
# Header builder
# ---------------------------------------------------------------------------


def _num(value: int) -> bytes:
    """7z ``NUMBER``: leading 1-bits of the first byte count the extra LE bytes."""
    for extra in range(8):
        if value < 1 << (8 * extra + 7 - extra):
            first = (0xFF << (8 - extra)) & 0xFF | (value >> (8 * extra))
            return bytes([first]) + (value & ((1 << 8 * extra) - 1)).to_bytes(
                extra, "little"
            )
    return b"\xff" + value.to_bytes(8, "little")


def _coder(
    method: bytes,
    *,
    num_in: int | None = None,
    num_out: int | None = None,
    props: bytes | None = None,
) -> bytes:
    flags = len(method)
    tail = b""
    if num_in is not None or num_out is not None:
        flags |= 0x10
        tail += _num(1 if num_in is None else num_in)
        tail += _num(1 if num_out is None else num_out)
    if props is not None:
        flags |= 0x20
        tail += _num(len(props)) + props
    return bytes([flags]) + method + tail


def _folder(
    coders: list[bytes],
    *,
    bind_pairs: Sequence[tuple[int, int]] = (),
    packed: Sequence[int] = (),
) -> bytes:
    out = _num(len(coders)) + b"".join(coders)
    for in_index, out_index in bind_pairs:
        out += _num(in_index) + _num(out_index)
    for index in packed:
        out += _num(index)
    return out


def _linear(coders: list[bytes]) -> bytes:
    """A linear chain: coder i+1 reads coder i's output, coder 0 reads the pack."""
    return _folder(coders, bind_pairs=[(i + 1, i) for i in range(len(coders) - 1)])


def _header(
    *,
    folders: list[bytes],
    coder_unpack_sizes: list[list[int]],
    pack_sizes: list[int] | None,
    names: list[str],
    folder_crcs: list[int] | None = None,
    substreams: bytes | None = None,
    file_props: bytes = b"",
) -> bytes:
    streams = b""
    if pack_sizes is not None:
        streams += b"\x06" + _num(0) + _num(len(pack_sizes))
        streams += b"\x09" + b"".join(_num(size) for size in pack_sizes) + b"\x00"
    streams += b"\x07\x0b" + _num(len(folders)) + b"\x00" + b"".join(folders)
    streams += b"\x0c" + b"".join(
        _num(size) for sizes in coder_unpack_sizes for size in sizes
    )
    if folder_crcs is not None:
        streams += b"\x0a\x01" + b"".join(struct.pack("<I", c) for c in folder_crcs)
    streams += b"\x00"
    if substreams is not None:
        streams += b"\x08" + substreams + b"\x00"
    names_blob = b"\x00" + b"".join(n.encode("utf-16le") + b"\x00\x00" for n in names)
    files = b"\x05" + _num(len(names))
    files += b"\x11" + _num(len(names_blob)) + names_blob + file_props + b"\x00"
    return b"\x01\x04" + streams + b"\x00" + files + b"\x00"


def _signature(*, next_offset: int, next_size: int, next_crc: int) -> bytes:
    start_header = struct.pack("<QQI", next_offset, next_size, next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return MAGIC_7Z + bytes([0, 4]) + struct.pack("<I", start_crc) + start_header


def _archive(packed: bytes, header: bytes) -> bytes:
    sig = _signature(
        next_offset=len(packed),
        next_size=len(header),
        next_crc=zlib.crc32(header) & 0xFFFFFFFF,
    )
    return sig + packed + header


def _single_folder_archive(
    coders: list[bytes], packed: bytes, payload: bytes, coder_sizes: list[int]
) -> bytes:
    header = _header(
        folders=[_linear(coders)],
        coder_unpack_sizes=[coder_sizes],
        pack_sizes=[len(packed)],
        names=["payload.bin"],
        folder_crcs=[zlib.crc32(payload) & 0xFFFFFFFF],
    )
    return _archive(packed, header)


def _read_only_member(data: bytes) -> bytes:
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            return stream.read()


def _materialize(header: bytes) -> SevenZipArchive:
    block = parse_header_block(header)
    assert isinstance(block, PlainHeader)
    signature = sevenzip_parser.SignatureInfo(0, 4, header, end_offset=0)
    return materialize_archive(signature, block)


# ---------------------------------------------------------------------------
# Coder graph (S2-F4)
# ---------------------------------------------------------------------------


def _one_folder_header(folder: bytes, sizes: list[int]) -> bytes:
    return _header(
        folders=[folder], coder_unpack_sizes=[sizes], pack_sizes=[1], names=["a"]
    )


@pytest.mark.parametrize(
    ("folder", "sizes", "match"),
    [
        pytest.param(_num(0), [], "no coders", id="zero-coders"),
        pytest.param(
            _folder([_coder(_COPY, num_in=1, num_out=0)]),
            [],
            "no coder out-streams",
            id="zero-out-streams",
        ),
        pytest.param(
            # Two out-streams need one bind pair, but there are no in-streams to bind.
            _folder([_coder(_COPY, num_in=0, num_out=2)], bind_pairs=[(0, 0)]),
            [1, 1],
            "only 0 coder in-streams",
            id="more-binds-than-in-streams",
        ),
        pytest.param(
            _folder([_coder(_COPY), _coder(_COPY)], bind_pairs=[(99, 99)]),
            [1, 1],
            "invalid coder bind pair",
            id="bind-out-of-range",
        ),
        pytest.param(
            # Packed index 0 is also the in-stream the bind pair feeds.
            _folder(
                [_coder(_COPY, num_in=2, num_out=1), _coder(_COPY, num_in=1)],
                bind_pairs=[(0, 1)],
                packed=[0, 2],
            ),
            [1, 1],
            "invalid packed-stream index",
            id="packed-index-is-bound",
        ),
        pytest.param(
            _folder([_coder(_COPY, num_in=2, num_out=1)], packed=[0, 5]),
            [1],
            "invalid packed-stream index",
            id="packed-index-out-of-range",
        ),
        pytest.param(
            _folder([_coder(_COPY, num_in=2, num_out=1)], packed=[1, 1]),
            [1],
            "invalid packed-stream index",
            id="packed-index-repeated",
        ),
    ],
)
def test_malformed_coder_graph_is_corruption_at_parse(
    folder: bytes, sizes: list[int], match: str
) -> None:
    with raises_corruption_not_truncation(match=match):
        parse_header_block(_one_folder_header(folder, sizes))


def test_bind_pair_reusing_an_out_stream_is_corruption() -> None:
    # Three coders, two bind pairs both consuming out-stream 0: out-stream 1 and 2
    # are then both unbound, so the folder has no single output.
    folder = _folder(
        [_coder(_COPY), _coder(_COPY), _coder(_COPY)], bind_pairs=[(1, 0), (2, 0)]
    )
    with raises_corruption_not_truncation(match="invalid coder bind pair"):
        parse_header_block(_one_folder_header(folder, [1, 1, 1]))


def test_well_formed_linear_chain_still_parses() -> None:
    block = parse_header_block(
        _one_folder_header(_linear([_coder(_COPY), _coder(_COPY)]), [4, 4])
    )
    assert isinstance(block, PlainHeader)
    (folder,) = block.streams.folders or []
    assert folder.bind_pairs == [(1, 0)]
    assert folder.packed_indices == [0]


# ---------------------------------------------------------------------------
# Substream accounting (S2-F3)
# ---------------------------------------------------------------------------


def test_leftover_substream_is_corruption() -> None:
    # One COPY folder of 10 bytes split 3 + 7, but only one file: 7 bytes belong to
    # no member, and the one-file folder would have been reported solid.
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[10]],
        pack_sizes=[10],
        names=["a"],
        substreams=b"\x0d" + _num(2) + b"\x09" + _num(3),
    )
    with raises_corruption_not_truncation(match="declares 2 unpack streams .* only 1"):
        _materialize(header)


def test_multi_stream_folder_without_sizes_is_corruption() -> None:
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[10]],
        pack_sizes=[10],
        names=["a", "b"],
        substreams=b"\x0d" + _num(2),
    )
    with raises_corruption_not_truncation(match="2 unpack streams but no substream"):
        parse_header_block(header)


def test_zero_stream_folder_is_skipped_when_mapping_files() -> None:
    # Folder 0 declares no unpack streams; the one file lives in folder 1.
    header = _header(
        folders=[_linear([_coder(_COPY)]), _linear([_coder(_COPY)])],
        coder_unpack_sizes=[[4], [6]],
        pack_sizes=[4, 6],
        names=["a"],
        substreams=b"\x0d" + _num(0) + _num(1),
    )
    archive = _materialize(header)
    (record,) = archive.files
    assert record.folder_index == 1
    assert record.uncompressed_size == 6
    assert record.compressed_size == 6


# ---------------------------------------------------------------------------
# Pack-index overrun (S2-F5)
# ---------------------------------------------------------------------------


def test_folder_overrunning_pack_sizes_is_corruption() -> None:
    # UNPACK_INFO with no PACK_INFO: the folder names a pack stream that is not there.
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[5]],
        pack_sizes=None,
        names=["a"],
    )
    with raises_corruption_not_truncation(match="missing pack stream"):
        _materialize(header)


# ---------------------------------------------------------------------------
# Short next-header read (S2-F6)
# ---------------------------------------------------------------------------


def test_short_next_header_is_truncation() -> None:
    data = _signature(next_offset=0, next_size=50, next_crc=0) + b"\x01\x04\x06\x00"
    with pytest.raises(TruncatedError, match="expected 50 bytes"):
        read_signature_and_next_header(io.BytesIO(data))


def test_short_signature_header_is_truncation() -> None:
    with pytest.raises(TruncatedError, match="7z signature header"):
        read_signature_and_next_header(io.BytesIO(MAGIC_7Z + b"\x00\x04"))


def test_full_next_header_with_bad_crc_stays_corruption() -> None:
    header = b"\x01\x00"
    data = _signature(next_offset=0, next_size=len(header), next_crc=0) + header
    with raises_corruption_not_truncation(match="next header CRC mismatch"):
        read_signature_and_next_header(io.BytesIO(data))


# ---------------------------------------------------------------------------
# Filter-only folders (S2-F8) and BCJ start offsets (S2-F7)
# ---------------------------------------------------------------------------


def _delta_encode(data: bytes, dist: int) -> bytes:
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        prev = data[i - dist] if i >= dist else 0
        out[i] = (byte - prev) & 0xFF
    return bytes(out)


def _x86_encode(data: bytes, start_offset: int = 0) -> bytes:
    """liblzma's x86 BCJ encoding of ``data``, with no compression around it."""
    bcj: dict[str, int] = {"id": lzma.FILTER_X86}
    if start_offset:
        bcj["start_offset"] = start_offset
    lzma2 = {"id": lzma.FILTER_LZMA2, "preset": 0}
    packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[bcj, lzma2])
    return lzma.decompress(packed, format=lzma.FORMAT_RAW, filters=[lzma2])


# x86-looking bytes: CALL rel32 opcodes every few bytes, so the filter changes them.
_X86_PAYLOAD = b"".join(
    b"\xe8" + (i * 7919 & 0xFFFFFF).to_bytes(4, "little") + b"\x90\x90\x90"
    for i in range(512)
)


def test_delta_only_folder_reads() -> None:
    payload = bytes(range(256)) * 16
    packed = _delta_encode(payload, 4)
    data = _single_folder_archive(
        [_coder(_DELTA, props=bytes([4 - 1]))], packed, payload, [len(payload)]
    )
    assert _read_only_member(data) == payload


def test_delta_then_bcj_without_lzma_reads() -> None:
    # Decode order: pack → Delta → BCJ. Previously refused as a non-LZMA coder in
    # a BCJ run; each filter-only coder is now its own stage.
    payload = _X86_PAYLOAD
    packed = _delta_encode(_x86_encode(payload), 2)
    data = _single_folder_archive(
        [_coder(_DELTA, props=b"\x01"), _coder(_BCJ_X86)],
        packed,
        payload,
        [len(payload), len(payload)],
    )
    assert _read_only_member(data) == payload


def test_filter_only_run_is_never_planned_as_an_lzma_chain() -> None:
    folder = sevenzip_parser.SevenZipFolder(
        coders=[SevenZipCoder(_DELTA, 1, 1, b"\x00")],
        bind_pairs=[],
        packed_indices=[0],
        unpack_sizes=[8],
        crc=None,
        digest_defined=False,
    )
    (stage,) = plan_folder(folder).stages
    assert isinstance(stage, sevenzip_pipeline._FilterStage)
    assert stage.lzma_filter == {"id": lzma.FILTER_DELTA, "dist": 1}
    with pytest.raises(UnsupportedFeatureError, match="filter-only coder run"):
        sevenzip_pipeline._lzma_chain_stage(folder.coders, cap_size=None)


@requires_binary("7z")
def test_7z_cli_delta_copy_archive_reads(tmp_path: Path) -> None:
    payload = b"delta parity with 7-Zip\n" * 64
    (tmp_path / "small.txt").write_bytes(payload)
    archive = tmp_path / "delta.7z"
    subprocess.run(
        ["7z", "a", "-mhc=off", "-m0=Delta:4", "-m1=Copy", str(archive), "small.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    assert _read_only_member(archive.read_bytes()) == payload


def test_bcj_start_offset_is_honoured_in_a_filter_stage() -> None:
    start = 0x1000
    packed = _x86_encode(_X86_PAYLOAD, start)
    # The offset matters: decoding without it gives different bytes.
    assert _x86_encode(_X86_PAYLOAD) != packed
    data = _single_folder_archive(
        [_coder(_BCJ_X86, props=start.to_bytes(4, "little"))],
        packed,
        _X86_PAYLOAD,
        [len(_X86_PAYLOAD)],
    )
    assert _read_only_member(data) == _X86_PAYLOAD


def test_bcj_start_offset_is_honoured_in_an_lzma2_chain() -> None:
    start = 0x2000
    lzma2 = {"id": lzma.FILTER_LZMA2, "preset": 1}
    packed = lzma.compress(
        _X86_PAYLOAD,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_X86, "start_offset": start}, lzma2],
    )
    lzma2_props = lzma._encode_filter_properties(lzma2)
    data = _single_folder_archive(
        [
            _coder(_LZMA2, props=lzma2_props),
            _coder(_BCJ_X86, props=start.to_bytes(4, "little")),
        ],
        packed,
        _X86_PAYLOAD,
        [len(_X86_PAYLOAD), len(_X86_PAYLOAD)],
    )
    assert _read_only_member(data) == _X86_PAYLOAD


def _bcj_folder(method: bytes, props: bytes) -> sevenzip_parser.SevenZipFolder:
    return sevenzip_parser.SevenZipFolder(
        coders=[SevenZipCoder(method, 1, 1, props)],
        bind_pairs=[],
        packed_indices=[0],
        unpack_sizes=[16],
        crc=None,
        digest_defined=False,
    )


def test_bcj_properties_of_the_wrong_length_are_corruption() -> None:
    with raises_corruption_not_truncation(match="Malformed 7z BCJ coder properties"):
        plan_folder(_bcj_folder(_BCJ_X86, b"\x00\x10\x00"))


@pytest.mark.parametrize(
    ("method", "props", "method_hex"),
    [
        pytest.param(_LZMA, b"\x5d\x00", "0x030101", id="lzma1-wrong-length"),
        # 225 and above is not an lc/lp/pb byte at all.
        pytest.param(
            _LZMA,
            bytes([225]) + (1 << 16).to_bytes(4, "little"),
            "0x030101",
            id="lzma1-byte-225",
        ),
        # LZMA2 dictionary codes stop at 40.
        pytest.param(_LZMA2, b"\x29", "0x21", id="lzma2-dict-code-41"),
    ],
)
def test_malformed_lzma_properties_are_corruption(
    method: bytes, props: bytes, method_hex: str
) -> None:
    """Properties liblzma refuses, other than an lc + lp over 4, are malformed; the
    message names the coder's method id."""
    with raises_corruption_not_truncation(
        match=f"Malformed 7z LZMA coder {method_hex} properties"
    ):
        plan_folder(_bcj_folder(method, props))


def test_lzma1_lc_lp_over_four_is_unsupported_at_plan_time() -> None:
    # lc=8, lp=0, pb=2: what ``7z a -m0=LZMA:lc=8`` writes; liblzma stops at lc + lp 4.
    props = bytes([8 + 9 * (0 + 5 * 2)]) + (1 << 16).to_bytes(4, "little")
    with pytest.raises(
        UnsupportedFeatureError, match="7z LZMA coder 0x030101 with lc=8, lp=0"
    ):
        plan_folder(_bcj_folder(_LZMA, props))


def test_misaligned_bcj_start_offset_is_refused_at_plan_time() -> None:
    with pytest.raises(UnsupportedFeatureError, match="start offset 3"):
        plan_folder(_bcj_folder(_BCJ_ARM, (3).to_bytes(4, "little")))


def test_zero_bcj_start_offset_needs_no_option() -> None:
    (stage,) = plan_folder(_bcj_folder(_BCJ_X86, bytes(4))).stages
    assert isinstance(stage, sevenzip_pipeline._FilterStage)
    assert stage.lzma_filter == {"id": lzma.FILTER_X86}


# ---------------------------------------------------------------------------
# Module contracts: detect imports (S2-F12), max_members keyword
# ---------------------------------------------------------------------------


def test_sevenzip_detect_imports_no_private_parser_names() -> None:
    from archivey.internal.backends import sevenzip_detect

    tree = ast.parse(Path(sevenzip_detect.__file__).read_text(encoding="utf-8"))
    imported = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and "sevenzip_parser" in node.module
        for alias in node.names
    ]
    assert imported
    assert not [name for name in imported if name.startswith("_")]


@pytest.mark.parametrize(
    "helper",
    [
        "_parse_plain_header",
        "_read_streams_info",
        "_read_unpack_info",
        "_read_substreams_info",
        "_read_files_info",
    ],
)
def test_internal_helpers_require_max_members(helper: str) -> None:
    param = inspect.signature(getattr(sevenzip_parser, helper)).parameters[
        "max_members"
    ]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is inspect.Parameter.empty


def test_archive_entry_point_applies_the_default_listing_limit() -> None:
    # A header large enough to pass the header-size bound, declaring one unpack
    # stream more than the default max_members. The count is refused before any
    # size is read, so the rest of the header is padding.
    count = ListingLimits().max_members + 1
    header = bytes.fromhex("0104070b010001000c0a00080d") + _num(count) + b"\x00" * count
    data = _signature(
        next_offset=0,
        next_size=len(header),
        next_crc=zlib.crc32(header) & 0xFFFFFFFF,
    )
    with pytest.raises(ResourceLimitError, match="max_members"):
        load_sevenzip_archive(io.BytesIO(data + header))
    with pytest.raises(ResourceLimitError, match="max_members"):
        parse_header_block(header)


@pytest.mark.parametrize("entry", [parse_header_block, load_sevenzip_archive])
def test_entry_points_default_to_the_listing_limit(
    entry: Callable[..., object],
) -> None:
    param = inspect.signature(entry).parameters["max_members"]
    assert param.default == ListingLimits().max_members
    assert param.default is not None


@pytest.mark.parametrize(
    "helper",
    [
        sevenzip_parser.parse_decoded_header,
        sevenzip_reader._decode_encoded_header_block,
    ],
)
def test_decoded_header_helpers_require_max_members(
    helper: Callable[..., object],
) -> None:
    param = inspect.signature(helper).parameters["max_members"]
    assert param.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# A record with a data stream is a file
# ---------------------------------------------------------------------------

_EMPTY_STREAM = 0x0E
_EMPTY_FILE = 0x0F
_ANTI = 0x10
_ATTRIBUTES = 0x15
_FILE_DATA = b"hello world"


def _file_prop(prop_id: int, payload: bytes) -> bytes:
    return bytes([prop_id]) + _num(len(payload)) + payload


def _bits(values: list[bool]) -> bytes:
    """A 7z bit vector, most significant bit first."""
    out = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            out[index // 8] |= 0x80 >> (index % 8)
    return bytes(out)


def _attributes(values: list[int]) -> bytes:
    """``kAttributes`` with every value defined."""
    return _file_prop(
        _ATTRIBUTES,
        b"\x01\x00" + b"".join(struct.pack("<I", value) for value in values),
    )


def _copy_archive(names: list[str], file_props: bytes) -> bytes:
    """One COPY folder holding ``_FILE_DATA`` as its only stream."""
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[len(_FILE_DATA)]],
        pack_sizes=[len(_FILE_DATA)],
        names=names,
        folder_crcs=[zlib.crc32(_FILE_DATA) & 0xFFFFFFFF],
        file_props=file_props,
    )
    return _archive(_FILE_DATA, header)


@pytest.mark.parametrize(
    "attributes",
    [
        pytest.param(0x8000 | (0o040755 << 16), id="unix-directory-mode"),
        pytest.param(0x8000 | 0x400 | (0o040755 << 16), id="with-reparse-bit"),
    ],
)
def test_a_member_with_data_and_a_directory_mode_is_a_file(
    attributes: int, tmp_path: Path
) -> None:
    """7-Zip never makes a directory of an entry that has a stream, and extracts it as
    a file. A directory type would skip the data on every read without an error."""
    data = _copy_archive(["a"], _attributes([attributes]))
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        assert (member.name, member.type) == ("a", MemberType.FILE)
        assert reader.read(member) == _FILE_DATA
    with open_archive(io.BytesIO(data)) as reader:
        reader.extract_all(tmp_path)
    assert (tmp_path / "a").read_bytes() == _FILE_DATA


def test_an_anti_bit_left_on_a_member_with_data_is_dropped() -> None:
    """``kEmptyStream`` repeated after ``kAnti`` moves the stream to the anti entry.

    7-Zip 23.01 refuses a header that repeats ``kEmptyStream`` (``E_INVALIDARG``), which
    is the evidence that no real producer writes this shape (DR-5a). Archivey keeps
    listing the recoverable members and types the entry that has the stream as a file
    (DR-2, DR-17): ``a`` must not be an anti item whose data is skipped. Each
    ``kEmptyStream`` clears the anti and empty-file bits, which is what 7-Zip's
    ``7zIn.cpp`` would do if it got that far.
    """
    props = (
        _file_prop(_EMPTY_STREAM, _bits([True, False]))
        + _file_prop(_ANTI, _bits([True]))
        + _file_prop(_EMPTY_STREAM, _bits([False, True]))
    )
    data = _copy_archive(["a", "b"], props)
    with open_archive(io.BytesIO(data)) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["a"].type is MemberType.FILE
        assert reader.read(members["a"]) == _FILE_DATA
        assert members["b/"].type is MemberType.DIRECTORY


def test_a_stale_anti_bit_on_a_stream_less_member_is_dropped() -> None:
    """A bit survives only the ``kEmptyStream`` vector it was supplied under.

    The first vector's ``kAnti`` marks ``a``. The second vector supplies no ``kAnti``,
    so the bit is dropped, not carried: ``a`` is still stream-less, and it is a
    directory, not an anti item (deletion marker).
    """
    props = (
        _file_prop(_EMPTY_STREAM, _bits([True, False, False]))
        + _file_prop(_ANTI, _bits([True]))
        + _file_prop(_EMPTY_STREAM, _bits([True, True, False]))
    )
    data = _copy_archive(["a", "b", "c"], props)
    with open_archive(io.BytesIO(data)) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["a/"].type is MemberType.DIRECTORY
        assert members["b/"].type is MemberType.DIRECTORY
        assert members["c"].type is MemberType.FILE
        assert reader.read(members["c"]) == _FILE_DATA


def test_a_stale_empty_file_bit_on_a_stream_less_member_is_dropped() -> None:
    """``kEmptyFile`` follows the same rule as ``kAnti``.

    The first vector's ``kEmptyFile`` marks ``a`` as an empty file. The second vector
    supplies no ``kEmptyFile``, so the bit is dropped: ``a`` is a directory, not a
    zero-byte file.
    """
    props = (
        _file_prop(_EMPTY_STREAM, _bits([True, False, False]))
        + _file_prop(_EMPTY_FILE, _bits([True]))
        + _file_prop(_EMPTY_STREAM, _bits([True, True, False]))
    )
    data = _copy_archive(["a", "b", "c"], props)
    with open_archive(io.BytesIO(data)) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["a/"].type is MemberType.DIRECTORY
        assert members["b/"].type is MemberType.DIRECTORY
        assert members["c"].type is MemberType.FILE
        assert reader.read(members["c"]) == _FILE_DATA


# ---------------------------------------------------------------------------
# Unknown property IDs inside streams info
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("context", ["pack", "unpack", "substreams"])
def test_unknown_streams_info_property_is_skipped(context: str) -> None:
    """7-Zip skips an unknown ID by its size in PackInfo, UnpackInfo and SubStreamsInfo.

    The unknown property (ID 0x30, size 1) sits before a property archivey must still
    read, so a skip of the wrong length corrupts the header.
    """
    payload = b"hello"
    crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    unknown = b"\x30\x01\xff"

    def extra(name: str) -> bytes:
        return unknown if name == context else b""

    pack_info = b"\x06" + _num(0) + _num(1) + b"\x09" + _num(len(payload))
    pack_info += extra("pack") + b"\x00"
    unpack_info = b"\x07\x0b" + _num(1) + b"\x00" + _linear([_coder(_COPY)])
    unpack_info += b"\x0c" + _num(len(payload)) + extra("unpack") + b"\x00"
    substreams = b"\x08" + extra("substreams") + b"\x0a\x01" + crc + b"\x00"
    streams = b"\x04" + pack_info + unpack_info + substreams + b"\x00"
    names_blob = b"\x00" + "a".encode("utf-16le") + b"\x00\x00"
    files = b"\x05" + _num(1) + b"\x11" + _num(len(names_blob)) + names_blob + b"\x00"
    header = b"\x01" + streams + files + b"\x00"

    assert _read_only_member(_archive(payload, header)) == payload


# ---------------------------------------------------------------------------
# Solid folder data pass cost
# ---------------------------------------------------------------------------


def _solid_copy_archive(count: int) -> tuple[bytes, bytes]:
    """One COPY folder holding ``count`` one-byte members, and its payload."""
    payload = bytes(index % 251 for index in range(count))
    header = _header(
        folders=[_linear([_coder(_COPY)])],
        coder_unpack_sizes=[[count]],
        pack_sizes=[count],
        names=[str(index) for index in range(count)],
        substreams=b"\x0d"
        + _num(count)
        + b"\x09"
        + b"".join(_num(1) for _ in range(count - 1)),
    )
    return _archive(payload, header), payload


def _python_calls_for_both_passes(count: int) -> int:
    """Python function calls made by a streaming pass plus an ``open()`` per member."""
    data, payload = _solid_copy_archive(count)
    calls = 0

    def profile(_frame: object, event: str, _arg: object) -> None:
        nonlocal calls
        if event == "call":
            calls += 1

    with open_archive(io.BytesIO(data)) as reader:
        members = reader.members()
        streamed = bytearray()
        opened = bytearray()
        sys.setprofile(profile)
        try:
            for _, stream in reader.stream_members():
                assert stream is not None
                streamed += stream.read()
            for member in members:
                with reader.open(member) as stream:
                    opened += stream.read()
        finally:
            sys.setprofile(None)
    assert streamed == payload
    assert opened == payload
    return calls


def test_solid_folder_data_pass_cost_grows_linearly_with_member_count() -> None:
    # Each member's offset in its folder is the sum of the earlier members' sizes.
    # Recomputing that sum for every member makes a pass over a solid folder
    # quadratic: doubling the member count then triples the work or more. Counting
    # Python calls instead of timing keeps the check deterministic.
    small = _python_calls_for_both_passes(200)
    large = _python_calls_for_both_passes(400)
    assert large / small < 2.5, (small, large)
