"""BCJ2 7z folders: the decoder stream, the tree planner, and archives the 7z CLI writes.

BCJ2 (``0x0303011B``) splits x86 code into four pack streams (``main``, ``call``,
``jump``, ``rc``). ``py7zr`` cannot read it, so the ``7z`` CLI is the only oracle
here: it writes the fixtures, and each member must read back equal to its input.
"""

from __future__ import annotations

import io
import random
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest

import archivey.internal.backends.sevenzip_reader as sevenzip_reader_mod
from archivey import open_archive
from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.sevenzip_parser import (
    SevenZipCoder,
    SevenZipFolder,
    encoded_header_slice,
)
from archivey.internal.backends.sevenzip_pipeline import (
    _Bcj2Stage,
    plan_folder,
)
from archivey.internal.backends.sevenzip_reader import load_sevenzip_archive
from archivey.internal.password import _PasswordCandidates
from archivey.internal.streams.codecs import bcj2_filter as bcj2_mod
from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream
from archivey.types import CompressionAlgorithm
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import (
    assert_non_integer_seek_is_type_error,
    assert_seek_underflow_matches_bytesio,
)

_BCJ2 = b"\x03\x03\x01\x1b"
_COPY = b"\x00"
_DELTA = b"\x03"
_PASSWORD = "Secret"
# 7-Zip picks BCJ2 at -mx9 only for an executable; these switches force it onto any
# input, with main through LZMA2 and call/jump through LZMA, as -mx9 does.
_FORCED = [
    "-m0=BCJ2",
    "-m1=LZMA2",
    "-m2=LZMA",
    "-m3=LZMA",
    "-mb0s0:1",
    "-mb0s1:2",
    "-mb0s2:3",
]


def _x86_like(seed: int, size: int) -> bytes:
    """Bytes dense in E8/E9/Jcc opcodes whose rel32 targets land inside the data.

    7-Zip converts a branch only when its target is plausible, so random bytes alone
    exercise the ``rc`` bit but rarely the ``call``/``jump`` streams.
    """
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        out += rnd.randbytes(rnd.randrange(0, 40))
        opcode = rnd.choice([b"\xe8", b"\xe9", b"\x0f\x84", b"\x0f\x85", b"\x0f\x8f"])
        out += opcode
        here = len(out) + 4
        out += (rnd.randrange(0, size) - here).to_bytes(4, "little", signed=True)
    return bytes(out[:size])


def _seven_zip(archive: Path, switches: list[str], inputs: list[Path]) -> None:
    result = subprocess.run(
        ["7z", "a", "-t7z", *switches, str(archive), *(p.name for p in inputs)],
        cwd=inputs[0].parent,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write {switches}: {result.stderr!r}")


def _bcj2_folder_count(archive: Path, password: str | None = None) -> int:
    passwords = _PasswordCandidates.from_input(password)
    with archive.open("rb") as fh:
        parsed = load_sevenzip_archive(fh, passwords=passwords)
    return sum(
        1
        for folder in parsed.folders
        if any(coder.method == _BCJ2 for coder in folder.coders)
    )


@pytest.fixture(scope="module")
def inputs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    work = tmp_path_factory.mktemp("bcj2-inputs")
    data = _x86_like(0, 200_000)
    files = {
        "code.bin": data,
        "code2.bin": _x86_like(1, 120_000),
        # The output ends on an opcode, so no bit may be decoded after it; and on half
        # a Jcc, so the last 0F starts nothing.
        "ends_e8.bin": data[:150_000] + b"\xe8",
        "ends_0f.bin": data[:150_000] + b"\x0f",
        "random.bin": random.Random(2).randbytes(100_000),
    }
    paths = {}
    for name, content in files.items():
        paths[name] = work / name
        paths[name].write_bytes(content)
    return paths


def _read_all_ways(archive: Path, expected: dict[str, bytes], **open_kwargs) -> None:
    """Every member reads equal to its input via open(), stream_members() and extract."""
    with open_archive(archive, **open_kwargs) as reader:
        members = [m for m in reader.members() if m.is_file]
        assert sorted(m.name for m in members) == sorted(expected)
        for member in reversed(members):  # a later member first: decoded from start
            with reader.open(member) as stream:
                assert stream.read() == expected[member.name]
    with open_archive(archive, **open_kwargs) as reader:
        seen = {}
        for member, stream in reader.stream_members():
            if stream is not None:
                seen[member.name] = stream.read()
        assert seen == expected
    dest = archive.parent / f"{archive.stem}-out"
    with open_archive(archive, **open_kwargs) as reader:
        reader.extract_all(dest)
    for name, content in expected.items():
        assert (dest / name).read_bytes() == content


# ---------------------------------------------------------------------------
# Archives the 7z CLI writes
# ---------------------------------------------------------------------------


@requires_binary("7z")
@pytest.mark.parametrize(
    ("label", "switches", "names"),
    [
        pytest.param("forced", _FORCED, ["code.bin"], id="forced"),
        pytest.param(
            "solid", _FORCED, ["code.bin", "code2.bin", "ends_e8.bin"], id="solid"
        ),
        pytest.param(
            "nonsolid", [*_FORCED, "-ms=off"], ["code.bin", "code2.bin"], id="nonsolid"
        ),
        pytest.param("ends-e8", _FORCED, ["ends_e8.bin"], id="ends-on-e8"),
        pytest.param("ends-0f", _FORCED, ["ends_0f.bin"], id="ends-on-0f"),
        pytest.param("random", _FORCED, ["random.bin"], id="random-data"),
        # D1 step 3: main's BZip2 stage takes its input size from its own branch.
        pytest.param(
            "bzip2-main",
            ["-m0=BCJ2", "-m1=BZip2", "-m2=LZMA", "-m3=LZMA", "-mb0s0:1", "-mb0s1:2",
             "-mb0s2:3"],
            ["code.bin"],
            id="bzip2-main-branch",
        ),
    ],
)  # fmt: skip
def test_cli_bcj2_folder_reads(
    tmp_path: Path,
    inputs: dict[str, Path],
    label: str,
    switches: list[str],
    names: list[str],
) -> None:
    archive = tmp_path / f"{label}.7z"
    _seven_zip(archive, switches, [inputs[n] for n in names])
    assert _bcj2_folder_count(archive) >= 1
    _read_all_ways(archive, {n: inputs[n].read_bytes() for n in names})


@requires("cryptography")
@requires_binary("7z")
@pytest.mark.parametrize(
    "switches",
    [
        pytest.param(_FORCED, id="lzma2-main"),
        pytest.param(
            ["-m0=BCJ2", "-m1=BZip2", "-m2=LZMA", "-m3=LZMA", "-mb0s0:1", "-mb0s1:2",
             "-mb0s2:3"],
            id="bzip2-main",
        ),
    ],
)  # fmt: skip
def test_encrypted_bcj2_folder_reads(
    tmp_path: Path, inputs: dict[str, Path], switches: list[str]
) -> None:
    """Header-encrypted: every pack stream gets its own 7zAES coder (eight coders)."""
    archive = tmp_path / "encrypted.7z"
    names = ["code.bin", "code2.bin"]
    _seven_zip(
        archive, [*switches, f"-p{_PASSWORD}", "-mhe=on"], [inputs[n] for n in names]
    )
    assert _bcj2_folder_count(archive, _PASSWORD) == 1
    _read_all_ways(
        archive, {n: inputs[n].read_bytes() for n in names}, password=_PASSWORD
    )


@requires_binary("7z")
def test_mx9_executable_picks_bcj2_and_reads(tmp_path: Path) -> None:
    """The case BCJ2 exists for: 7-Zip's own choice at -mx9 on an x86 executable.

    7-Zip picks BCJ2 only for a file it takes to be an executable; on Linux the
    execute bit is part of that test, so the copy is ``chmod +x``.
    """
    candidates = [shutil.which("ls"), shutil.which("cat"), sys.executable]
    source = next((Path(c).resolve() for c in candidates if c), None)
    if source is None:
        pytest.skip("no executable to archive")
    exe = tmp_path / "prog"
    exe.write_bytes(source.read_bytes())
    exe.chmod(0o755)
    archive = tmp_path / "mx9.7z"
    _seven_zip(archive, ["-mx9"], [exe])
    if not _bcj2_folder_count(archive):
        pytest.skip(f"7-Zip did not pick BCJ2 for {source} (not an x86 executable?)")
    with open_archive(archive) as reader:
        (member,) = reader.members()
        # D9: the root, then its main branch, in the pack direction; the side
        # streams' LZMA coders are part of BCJ2, not listed.
        assert tuple(m.algo for m in member.compression) == (
            CompressionAlgorithm.BCJ2,
            CompressionAlgorithm.LZMA2,
        )
        assert reader.read(member) == exe.read_bytes()


@requires_binary("7z")
def test_stream_members_opens_each_folder_once(
    tmp_path: Path, inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sequential pass decodes a solid BCJ2 folder once, not once per member."""
    names = ["code.bin", "code2.bin", "ends_e8.bin"]
    archive = tmp_path / "solid.7z"
    _seven_zip(archive, _FORCED, [inputs[n] for n in names])
    calls: list[int] = []
    original = sevenzip_reader_mod.SevenZipReader._folder_pack_views

    def counting(self: object, folder_index: int) -> list[BinaryIO]:
        calls.append(folder_index)
        return original(self, folder_index)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sevenzip_reader_mod.SevenZipReader, "_folder_pack_views", counting
    )
    with open_archive(archive) as reader:
        read = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert read == {n: inputs[n].read_bytes() for n in names}
    assert calls == [0]


@requires_binary("7z")
def test_seekable_members_seek_a_bcj2_member(
    tmp_path: Path, inputs: dict[str, Path]
) -> None:
    """The archive-reading guarantee holds for BCJ2: seek works, backward included."""
    names = ["code.bin", "code2.bin"]
    archive = tmp_path / "seek.7z"
    _seven_zip(archive, _FORCED, [inputs[n] for n in names])
    expected = inputs["code2.bin"].read_bytes()
    with open_archive(archive, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.name == "code2.bin")
        with reader.open(member) as stream:
            assert stream.seekable()
            assert stream.read(70_000) == expected[:70_000]
            stream.seek(1000)
            assert stream.read(5000) == expected[1000:6000]
            stream.seek(-10, io.SEEK_END)
            assert stream.read() == expected[-10:]
            stream.seek(0)
            assert stream.read() == expected


# ---------------------------------------------------------------------------
# The decoder stream on its own
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def branches(inputs: dict[str, Path]) -> tuple[list[bytes], int, bytes]:
    """The four decoded branches of a CLI-written BCJ2 folder, and its output."""
    if shutil.which("7z") is None:
        pytest.skip("requires external binary(ies): 7z")
    import lzma

    work = inputs["code.bin"].parent
    archive = work / "branches.7z"
    if not archive.exists():
        _seven_zip(archive, _FORCED, [inputs["code.bin"]])
    with archive.open("rb") as fh:
        parsed = load_sevenzip_archive(fh)
        raw = fh.seek(0) or fh.read()
    (folder,) = parsed.folders
    plan = plan_folder(folder)
    assert isinstance(plan.source, _Bcj2Stage)
    packs, pos = [], parsed.pack_pos
    for size in parsed.pack_sizes:
        packs.append(raw[pos : pos + size])
        pos += size
    decoded = []
    for branch in plan.source.branches:
        pack = packs[branch.source]  # type: ignore[index]
        if not branch.stages:
            decoded.append(pack)
            continue
        (stage,) = branch.stages
        decoder = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=stage.filters)  # type: ignore[union-attr]
        decoded.append(decoder.decompress(pack, branch.unpack_size))
    return decoded, plan.source.unpack_size, inputs["code.bin"].read_bytes()


def _decode(streams: list[bytes], size: int) -> bytes:
    return Bcj2DecoderStream(*map(io.BytesIO, streams), unpack_size=size).read(size)


def test_branches_decode_and_convert_targets(
    branches: tuple[list[bytes], int, bytes],
) -> None:
    streams, size, expected = branches
    main, call, jump, _ = streams
    # The fixture has to exercise both target streams, or the test proves little.
    assert len(call) >= 400 and len(jump) >= 400
    assert len(main) < size
    assert _decode(streams, size) == expected


@pytest.mark.parametrize(
    ("block", "read_size"),
    [
        (1, 4096),
        (7, 13),
        (7, None),
        (64 * 1024, 1),
        (64 * 1024, 4096),
        (64 * 1024, None),
    ],
)
def test_input_block_and_read_sizes_do_not_change_the_output(
    branches: tuple[list[bytes], int, bytes],
    monkeypatch: pytest.MonkeyPatch,
    block: int,
    read_size: int | None,
) -> None:
    streams, size, expected = branches
    monkeypatch.setattr(bcj2_mod, "_BLOCK", block)
    stream = Bcj2DecoderStream(*map(io.BytesIO, streams), unpack_size=size)
    if read_size is None:
        out = stream.read()
    else:
        parts = []
        while chunk := stream.read(read_size):
            parts.append(chunk)
        out = b"".join(parts)
    assert out == expected


@pytest.mark.parametrize(
    ("index", "label"), [(0, "main"), (1, "call"), (2, "jump"), (3, "range coder")]
)
def test_an_input_one_byte_short_is_truncation(
    branches: tuple[list[bytes], int, bytes], index: int, label: str
) -> None:
    streams, size, _ = branches
    streams = list(streams)
    if index == 3:
        # The encoder flushes rc, so its last byte may never be needed; cut it to
        # less than the five bytes the range coder starts from instead.
        streams[3] = streams[3][:4]
    else:
        streams[index] = streams[index][:-1]
    with pytest.raises(TruncatedError, match=f"BCJ2 {label} stream ended early"):
        _decode(streams, size)


@pytest.mark.parametrize(("index", "label"), [(0, "main"), (1, "call"), (2, "jump")])
def test_a_byte_left_over_in_an_input_is_corruption(
    branches: tuple[list[bytes], int, bytes], index: int, label: str
) -> None:
    streams, size, _ = branches
    streams = list(streams)
    streams[index] += b"\x00"
    with raises_corruption_not_truncation(match=f"BCJ2 {label} stream has bytes past"):
        _decode(streams, size)


class _ReadCounter(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.handed_out = 0

    def read(self, n: int | None = -1, /) -> bytes:
        chunk = super().read(n)
        self.handed_out += len(chunk)
        return chunk


def test_leftover_check_reads_one_byte_and_does_not_drain(
    branches: tuple[list[bytes], int, bytes],
) -> None:
    """D5: a hostile main tail is refused after one byte, not decoded in full."""
    streams, size, _ = branches
    main = _ReadCounter(streams[0] + b"\x00" * (8 * 1024 * 1024))
    stream = Bcj2DecoderStream(main, *map(io.BytesIO, streams[1:]), unpack_size=size)
    with raises_corruption_not_truncation():
        stream.read(size)
    # Whole blocks already buffered count too; the check itself reads one byte.
    assert main.handed_out - len(streams[0]) <= bcj2_mod._BLOCK + 1


def test_empty_output_reads_no_input() -> None:
    stream = Bcj2DecoderStream(*(io.BytesIO() for _ in range(4)), unpack_size=0)
    assert stream.read() == b""


def test_close_closes_owned_inputs_only() -> None:
    inputs = [io.BytesIO(b"") for _ in range(4)]
    stream = Bcj2DecoderStream(
        *inputs, unpack_size=0, owns_inputs=[True, True, True, False]
    )
    stream.close()
    assert [s.closed for s in inputs] == [True, True, True, False]


def test_hostile_all_candidates_main_decodes() -> None:
    """Every main byte an opcode, every bit 0: the worst case still decodes exactly."""
    main = b"\xe8" * 50_000 + b"\x0f\x80" * 25_000
    rc = b"\x00" * 100_000  # code 0 is below every bound: every bit decodes as 0
    assert _decode([main, b"", b"", rc], len(main)) == main


# A range-coder stream whose first bit decodes as 1 (convert), with no encoder: the
# code 0xFFFFFFFE is above the first bound, ``(0xFFFFFFFF >> 11) * 1024``. The second
# bit is a 1 too. (0xFFFFFFFF itself is a start 7-Zip refuses.)
_RC_CONVERT = b"\x00" + b"\xff" * 3 + b"\xfe"
_T1, _T2 = 0x12345678, 0x0ABBCCDD


@pytest.mark.parametrize(
    "rc",
    [b"\xff" + b"\x00" * 4, b"\x00" + b"\xff" * 4],
    ids=["nonzero-first-byte", "code-all-ones"],
)
def test_invalid_range_coder_start_is_refused(rc: bytes) -> None:
    """The two starts 7-Zip 23.01 refuses are corruption, not a guess (sweep S29-K10)."""
    main = b"\x90\xe8\x90\x90"
    with pytest.raises(
        CorruptionError, match="range coder stream has an invalid start"
    ):
        _decode([main, b"", b"", rc], len(main))


def _le(target: int, position: int) -> bytes:
    """A converted target as it is emitted: relative to the end of its 4 bytes."""
    return ((target - (position + 4)) & 0xFFFFFFFF).to_bytes(4, "little")


def _be(*targets: int) -> bytes:
    return b"".join(t.to_bytes(4, "big") for t in targets)


@pytest.mark.parametrize(
    ("main", "call", "jump", "expected"),
    [
        pytest.param(b"\xe8", _be(_T1), b"", b"\xe8" + _le(_T1, 1), id="call"),
        pytest.param(b"\xe9", b"", _be(_T1), b"\xe9" + _le(_T1, 1), id="jmp"),
        pytest.param(b"\x0f\x85", b"", _be(_T1), b"\x0f\x85" + _le(_T1, 2), id="jcc"),
        # The second E8's context is the top byte of the first converted target.
        pytest.param(
            b"\xe8\xe8",
            _be(_T1, _T2),
            b"",
            b"\xe8" + _le(_T1, 1) + b"\xe8" + _le(_T2, 6),
            id="call-after-converted-target",
        ),
    ],
)
def test_converted_target_without_the_cli(
    main: bytes, call: bytes, jump: bytes, expected: bytes
) -> None:
    """The conversion arithmetic, pinned on a core install with no 7z oracle."""
    assert _decode([main, call, jump, _RC_CONVERT], len(expected)) == expected


@pytest.mark.parametrize("size", [2, 3, 4])
def test_target_past_the_output_is_truncated(size: int) -> None:
    """A converted target that runs past the declared size is cut, as 7-Zip does."""
    expected = (b"\xe8" + _le(_T1, 1))[:size]
    assert _decode([b"\xe8", _be(_T1), b"", _RC_CONVERT], size) == expected


def test_call_stream_cut_short_without_the_cli() -> None:
    with pytest.raises(TruncatedError, match="call"):
        _decode([b"\xe8", b"\x12\x34", b"", _RC_CONVERT], 5)


def test_decoder_seeks_backward_and_forward() -> None:
    main, call = b"\xe8\xe8", _be(_T1, _T2)
    expected = b"\xe8" + _le(_T1, 1) + b"\xe8" + _le(_T2, 6)
    stream = Bcj2DecoderStream(
        *map(io.BytesIO, [main, call, b"", _RC_CONVERT]), unpack_size=len(expected)
    )
    assert stream.seekable()
    assert stream.read(7) == expected[:7]
    assert stream.seek(2) == 2
    assert stream.read(3) == expected[2:5]
    assert stream.seek(3, io.SEEK_CUR) == 8
    assert stream.tell() == 8
    assert stream.read() == expected[8:]
    assert stream.seek(-4, io.SEEK_END) == 6
    assert stream.read() == expected[6:]
    assert stream.seek(50) == 50
    assert stream.read(1) == b""
    assert stream.seek(0) == 0
    assert stream.read() == expected
    with pytest.raises(ValueError):
        stream.seek(-1)


def _seekable_decoder() -> tuple[Bcj2DecoderStream, bytes]:
    main, call = b"\xe8\xe8", _be(_T1, _T2)
    expected = b"\xe8" + _le(_T1, 1) + b"\xe8" + _le(_T2, 6)
    stream = Bcj2DecoderStream(
        *map(io.BytesIO, [main, call, b"", _RC_CONVERT]), unpack_size=len(expected)
    )
    return stream, expected


def test_decoder_seeks_before_the_start_as_bytesio() -> None:
    """The member-stream seek convention (archive-reading spec): a relative seek that
    lands before the start goes to 0, and only a negative ``SEEK_SET`` is refused."""
    stream, _ = _seekable_decoder()
    assert_seek_underflow_matches_bytesio(stream)


def test_decoder_refuses_a_non_integer_seek_as_bytesio() -> None:
    stream, expected = _seekable_decoder()
    assert_non_integer_seek_is_type_error(stream, expected)


def test_decoder_over_a_non_seekable_input_does_not_seek() -> None:
    class _Forward(io.BytesIO):
        def seekable(self) -> bool:
            return False

    stream = Bcj2DecoderStream(
        _Forward(b"\xe8"), *map(io.BytesIO, [_be(_T1), b"", _RC_CONVERT]),
        unpack_size=5,
    )  # fmt: skip
    assert not stream.seekable()
    with pytest.raises(io.UnsupportedOperation):
        stream.seek(0)


# ---------------------------------------------------------------------------
# The planner
# ---------------------------------------------------------------------------


def _coder(method: bytes, num_in: int = 1) -> SevenZipCoder:
    return SevenZipCoder(method, num_in, 1, None)


def _graph(
    coders: list[SevenZipCoder],
    bind_pairs: list[tuple[int, int]],
    packed: list[int],
) -> SevenZipFolder:
    return SevenZipFolder(
        coders=coders,
        bind_pairs=bind_pairs,
        packed_indices=packed,
        unpack_sizes=[3] * len(coders),
        crc=None,
        digest_defined=False,
    )


def test_seven_zip_layout_plans_a_bcj2_tree() -> None:
    """7-Zip's layout: LZMA, LZMA, LZMA2, then BCJ2 fed by all three plus a raw rc."""
    lzma1, lzma2 = b"\x03\x01\x01", b"\x21"
    folder = _graph(
        [_coder(lzma1), _coder(lzma1), _coder(lzma2), _coder(_BCJ2, 4)],
        [(5, 0), (4, 1), (3, 2)],
        [2, 6, 1, 0],
    )
    plan = plan_folder(folder)
    assert plan.stages == []
    assert isinstance(plan.source, _Bcj2Stage)
    # main, call, jump, rc read pack streams 0, 2, 3 and 1 of packed_indices.
    assert [b.source for b in plan.source.branches] == [0, 2, 3, 1]
    assert [len(b.stages) for b in plan.source.branches] == [1, 1, 1, 0]
    assert plan.pack_count() == 4


def test_linear_chain_in_any_list_order_plans_the_same() -> None:
    delta = _coder(_DELTA)
    folder = _graph([_coder(_COPY), delta], [(0, 1)], [1])
    plan = plan_folder(folder)
    assert plan.source == 0
    assert len(plan.stages) == 1


def test_coder_graph_cycle_is_corruption() -> None:
    # Coder 0 reads the pack; coders 1 and 2 feed each other and reach no output.
    folder = _graph(
        [_coder(_COPY), _coder(_COPY), _coder(_COPY)], [(1, 2), (2, 1)], [0]
    )
    with raises_corruption_not_truncation(match="cycle"):
        plan_folder(folder)


def test_output_bound_twice_is_corruption() -> None:
    folder = _graph([_coder(_COPY), _coder(_BCJ2, 4)], [(1, 0), (2, 0), (3, 0)], [0, 4])
    with raises_corruption_not_truncation(match="invalid coder bind pair"):
        plan_folder(folder)


def test_bind_pair_to_a_missing_in_stream_is_corruption() -> None:
    folder = _graph([_coder(_COPY), _coder(_COPY)], [(5, 0)], [1])
    with raises_corruption_not_truncation(match="invalid coder bind pair"):
        plan_folder(folder)


@pytest.mark.parametrize(
    "packed",
    [
        pytest.param([0, 2], id="extra-out-of-range"),
        pytest.param([0, 0], id="duplicate"),
    ],
)
def test_packed_indices_that_do_not_partition_the_inputs_are_corruption(
    packed: list[int],
) -> None:
    # Coder 1 reads coder 0's output; in-stream 0 is the only packed one.
    folder = _graph([_coder(_COPY), _coder(_COPY)], [(1, 0)], packed)
    with raises_corruption_not_truncation(match="invalid packed-stream index"):
        plan_folder(folder)


def test_multi_input_coder_other_than_bcj2_is_unsupported() -> None:
    folder = _graph([_coder(_COPY, 2)], [], [0, 1])
    with pytest.raises(UnsupportedFeatureError, match="0x00 with 2 inputs"):
        plan_folder(folder)


@pytest.mark.parametrize(
    ("coder", "message"),
    [
        pytest.param(SevenZipCoder(_COPY, 1, 0, None), "no out-stream", id="no-output"),
        pytest.param(SevenZipCoder(_COPY, 0, 1, None), "no in-stream", id="no-input"),
    ],
)
def test_coder_with_no_stream_is_corruption(coder: SevenZipCoder, message: str) -> None:
    with raises_corruption_not_truncation(match=message):
        plan_folder(_graph([coder], [], [0]))


def test_folder_with_no_coders_is_corruption() -> None:
    with raises_corruption_not_truncation(match="no coders"):
        plan_folder(_graph([], [], []))


def test_bcj2_with_one_input_is_unsupported() -> None:
    with pytest.raises(UnsupportedFeatureError, match="BCJ2"):
        plan_folder(_graph([_coder(_BCJ2)], [], [0]))


def test_encoded_header_stays_linear_only() -> None:
    """D7: no writer puts BCJ2 on a header, so a multi-pack header folder is refused."""
    folder = _graph([_coder(_BCJ2, 4)], [], [0, 1, 2, 3])
    encoded = SimpleNamespace(
        streams=SimpleNamespace(
            folders=[folder], pack_sizes=[1, 1, 1, 1], pack_positions=None, pack_pos=0
        )
    )
    with pytest.raises(UnsupportedFeatureError, match="multi-pack"):
        encoded_header_slice(encoded)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Hand-built archives
# ---------------------------------------------------------------------------


def _bare_bcj2_archive(payload: bytes) -> bytes:
    """A BCJ2 folder whose four branches are raw pack streams: no coder but BCJ2."""
    from tests.test_sevenzip_parser_hardening import (
        _archive,
        _coder as _raw_coder,
        _folder,
        _header,
    )

    assert not any(b in payload for b in (0xE8, 0xE9, 0x0F))
    rc = b"\x00" * 5
    header = _header(
        folders=[
            _folder([_raw_coder(_BCJ2, num_in=4, num_out=1)], packed=[0, 1, 2, 3])
        ],
        coder_unpack_sizes=[[len(payload)]],
        pack_sizes=[len(payload), 0, 0, len(rc)],
        names=["payload.bin"],
    )
    return _archive(payload + rc, header)


def test_bare_bcj2_folder_reads() -> None:
    payload = b"plain bytes with no branch opcodes"
    with open_archive(io.BytesIO(_bare_bcj2_archive(payload))) as reader:
        (member,) = reader.members()
        assert tuple(m.algo for m in member.compression) == (CompressionAlgorithm.BCJ2,)
        assert reader.read(member) == payload


def test_bare_bcj2_member_seeks_with_seekable_members() -> None:
    """The seek guarantee without the 7z CLI: a hand-built BCJ2 folder."""
    payload = b"plain bytes with no branch opcodes"
    archive = io.BytesIO(_bare_bcj2_archive(payload))
    with open_archive(archive, seekable_members=True) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.seekable()
            assert stream.read() == payload
            stream.seek(6)
            assert stream.read(5) == payload[6:11]
            stream.seek(0)
            assert stream.read() == payload
        # The decoder's own seek, reached through the archive's member stream.
        with reader.open(member) as stream:
            assert_seek_underflow_matches_bytesio(stream)
        with reader.open(member) as stream:
            assert_non_integer_seek_is_type_error(stream, payload)


def test_encrypted_folder_with_a_cycle_is_corruption_not_a_password_error() -> None:
    """Planning runs before the password check's error mapping (D1)."""
    from tests.test_sevenzip_parser_hardening import (
        _archive,
        _coder as _raw_coder,
        _folder,
        _header,
    )

    aes = b"\x06\xf1\x07\x01"
    props = bytes([0x13, 0x00])  # NumCyclesPower 19, no salt, no IV
    header = _header(
        folders=[
            _folder(
                [
                    _raw_coder(aes, props=props),
                    _raw_coder(_COPY),
                    _raw_coder(_COPY),
                ],
                bind_pairs=[(1, 2), (2, 1)],
            )
        ],
        coder_unpack_sizes=[[16, 16, 16]],
        pack_sizes=[16],
        names=["a"],
    )
    data = _archive(b"\x00" * 16, header)
    with open_archive(io.BytesIO(data), password="first") as reader:
        (member,) = reader.members()
        with raises_corruption_not_truncation(match="cycle"):
            reader.read(member)


@requires_binary("7z")
def test_bcj2_folder_dictionaries_count_together_against_the_decoder_cap(
    tmp_path: Path, inputs: dict[str, Path]
) -> None:
    """Design D6: the unit of the LZMA dictionary guard is the folder, not the branch."""
    import lzma

    from archivey import ArchiveyConfig, DecoderLimits
    from archivey.exceptions import ResourceLimitError

    archive = tmp_path / "forced.7z"
    _seven_zip(archive, _FORCED, [inputs["code.bin"]])
    with archive.open("rb") as fh:
        (folder,) = load_sevenzip_archive(fh).folders
    plan = plan_folder(folder)
    assert isinstance(plan.source, _Bcj2Stage)
    sizes = [
        spec["dict_size"]
        for branch in plan.source.branches
        for stage in branch.stages
        for spec in getattr(stage, "filters", [])
        if spec["id"] in (lzma.FILTER_LZMA1, lzma.FILTER_LZMA2)
    ]
    assert len(sizes) == 3
    # Every decoder fits on its own; the three together do not.
    cap = sum(sizes) - 1
    assert max(sizes) <= cap
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=cap))
    with open_archive(archive, config=config) as reader:
        (member,) = reader.members()
        with pytest.raises(ResourceLimitError, match="BCJ2 folder"):
            reader.read(member)
    roomy = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=sum(sizes)))
    with open_archive(archive, config=roomy) as reader:
        (member,) = reader.members()
        assert reader.read(member) == inputs["code.bin"].read_bytes()


def test_ppmd_branches_count_toward_the_folder_sum() -> None:
    """D6 covers PPMd too: three branches that each fit, together over the cap."""
    from archivey import DecoderLimits
    from archivey.exceptions import ResourceLimitError
    from archivey.internal.backends.sevenzip_aes import SevenZipKeyCache
    from archivey.internal.backends.sevenzip_pipeline import open_folder_pipeline
    from archivey.internal.config import StreamConfig

    mib = 1 << 20
    ppmd = SevenZipCoder(
        b"\x03\x04\x01", 1, 1, bytes([6]) + (64 * mib).to_bytes(4, "little")
    )
    folder = _graph(
        [ppmd, ppmd, ppmd, _coder(_BCJ2, 4)], [(5, 0), (4, 1), (3, 2)], [2, 6, 1, 0]
    )
    config = StreamConfig(decoder_limits=DecoderLimits(max_decoder_memory=128 * mib))
    with pytest.raises(ResourceLimitError, match="BCJ2 folder"):
        open_folder_pipeline(
            [io.BytesIO() for _ in range(4)],
            folder,
            password=None,
            key_cache=SevenZipKeyCache(),
            stream_config=config,
        )


@requires("cryptography")
@requires_binary("7z")
def test_wrong_password_on_an_encrypted_bcj2_folder_is_rejected(
    tmp_path: Path, inputs: dict[str, Path]
) -> None:
    from archivey.exceptions import EncryptionError

    archive = tmp_path / "encrypted-data.7z"
    _seven_zip(archive, [*_FORCED, f"-p{_PASSWORD}"], [inputs["code.bin"]])
    with open_archive(archive, password="not the password") as reader:
        (member,) = reader.members()
        with pytest.raises(EncryptionError):
            reader.read(member)
