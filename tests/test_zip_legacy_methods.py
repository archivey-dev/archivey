"""ZIP methods 1 (Shrink) and 6 (Implode), the PKZIP 1.x methods.

The archives come from the test-only encoders in ``tests/zip_legacy_build.py``. Where
Info-ZIP ``unzip`` and 7-Zip are installed, each archive is first checked with them, so
the encoders stand for a real writer. Commons Compress's archives from real PKZIP
writers are read by ``tests/test_commons_compress_corpus.py`` when its clone is given.
"""

from __future__ import annotations

import io
import random
import shutil
import struct
import subprocess
import tracemalloc
from pathlib import Path

import pytest

from archivey import CompressionAlgorithm, open_archive
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from tests.conftest import run_7z
from tests.streams_util import NonSeekableBytesIO
from tests.zip_legacy_build import (
    LegacyEntry,
    build_zip,
    implode,
    implode_entry,
    shrink,
    shrink_entry,
)

_README = (Path(__file__).parent.parent / "README.md").read_bytes()

_DATA = {
    "empty": b"",
    "one-byte": b"x",
    "text": _README * 3,
    "zeros": bytes(20_000),
    "random": random.Random(1).randbytes(5_000),
    # A small alphabet fills the Shrink table, so it widens to 13 bits and clears.
    "letters": bytes(random.Random(1).choices(b"abcd", k=80_000)),
}

_IMPLODE_VARIANTS = [
    pytest.param(False, False, id="4k-2trees"),
    pytest.param(False, True, id="4k-3trees"),
    pytest.param(True, False, id="8k-2trees"),
    pytest.param(True, True, id="8k-3trees"),
]


def _entries() -> list[LegacyEntry]:
    entries = []
    for key, data in _DATA.items():
        entries.append(shrink_entry(f"shrink/{key}", data))
        for large in (False, True):
            for literal in (False, True):
                entries.append(
                    implode_entry(
                        f"implode-{int(large)}{int(literal)}/{key}",
                        data,
                        large_window=large,
                        literal_tree=literal,
                    )
                )
    return entries


@pytest.fixture(scope="module")
def legacy_zip(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    entries = _entries()
    path = tmp_path_factory.mktemp("legacy") / "legacy.zip"
    path.write_bytes(build_zip(entries))
    return path, {e.name: e.data for e in entries}


def test_the_encoders_exercise_every_feature() -> None:
    """The fixtures reach what the decoders must handle, so the tests below cover it."""
    _, stats = shrink(_DATA["letters"])
    assert stats.max_width == 13
    assert stats.partial_clears >= 2
    assert stats.orphans >= 1
    for large in (False, True):
        for literal in (False, True):
            _, istats = implode(
                _DATA["zeros"], large_window=large, literal_tree=literal
            )
            assert istats.long_lengths > 0
            assert istats.before_start > 0


@pytest.mark.skipif(shutil.which("unzip") is None, reason="needs Info-ZIP unzip")
def test_unzip_reads_the_fixtures(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    for name, data in expected.items():
        out = subprocess.run(
            ["unzip", "-p", str(path), name], capture_output=True, check=True
        ).stdout
        assert out == data, name


_SEVEN_ZIP = next((p for p in ("7zz", "7z") if shutil.which(p)), None)


@pytest.mark.skipif(_SEVEN_ZIP is None, reason="needs the 7-Zip CLI")
def test_7zip_reads_the_fixtures(legacy_zip: tuple[Path, dict]) -> None:
    path, _ = legacy_zip
    assert _SEVEN_ZIP is not None
    result = run_7z(["t", str(path)], text=True, program=_SEVEN_ZIP)
    assert "Everything is Ok" in result.stdout, result.stdout


def test_members_decode_from_a_file(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    seen = {}
    with open_archive(path) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
            algo = member.compression[0].algo
            if member.name.startswith("shrink/"):
                assert algo is CompressionAlgorithm.SHRINK
            else:
                assert algo is CompressionAlgorithm.IMPLODE
    assert seen == expected


def test_members_decode_from_a_pipe(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    seen = {}
    with open_archive(NonSeekableBytesIO(path.read_bytes()), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    assert seen == expected


def test_random_access_and_small_reads(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    with open_archive(path) as reader:
        for name in ("implode-11/text", "shrink/letters", "implode-00/zeros"):
            with reader.open(reader.get(name)) as stream:
                parts = []
                while chunk := stream.read(7):
                    parts.append(chunk)
            assert b"".join(parts) == expected[name]


def _read_one(entry: LegacyEntry, compressed: bytes) -> bytes:
    data = build_zip(
        [LegacyEntry(entry.name, entry.data, entry.method, compressed, entry.flags)]
    )
    with open_archive(io.BytesIO(data)) as reader:
        return reader.read(reader.get(entry.name))


def _one_of_each() -> list:
    data = _README
    return [
        pytest.param(shrink_entry("x", data), id="shrink"),
        *(
            pytest.param(
                implode_entry("x", data, large_window=large, literal_tree=literal),
                id=f"implode-{int(large)}{int(literal)}",
            )
            for large in (False, True)
            for literal in (False, True)
        ),
    ]


@pytest.mark.parametrize("entry", _one_of_each())
def test_cut_data_is_truncated(entry: LegacyEntry) -> None:
    with pytest.raises(TruncatedError):
        _read_one(entry, entry.compressed[:-10])


@pytest.mark.parametrize("entry", _one_of_each())
@pytest.mark.parametrize("extra", [b"\x00", b"\x01\x02"], ids=["zero", "junk"])
def test_bytes_after_the_end_are_refused(entry: LegacyEntry, extra: bytes) -> None:
    """The member's size ends the data; a whole byte after it is not padding (DR-3)."""
    with pytest.raises(CorruptionError, match="left after its end"):
        _read_one(entry, entry.compressed + extra)


def test_a_full_shrink_table_that_is_not_cleared_is_refused() -> None:
    """unzip ("invalid compressed data to unshrink") and 7-Zip 26.05 refuse it too."""
    data = _DATA["letters"]
    compressed, stats = shrink(data, clear=False)
    assert stats.full_table_codes > 0
    with pytest.raises(CorruptionError, match="table is full"):
        _read_one(LegacyEntry("x", data, 1, compressed), compressed)


def test_an_unknown_shrink_control_code_is_refused() -> None:
    from tests.zip_legacy_build import BitWriter

    out = BitWriter()
    for code in (ord("a"), 256, 3, ord("b")):
        out.write(code, 9)
    with pytest.raises(CorruptionError, match="unknown control code 3"):
        _read_one(LegacyEntry("x", b"ab", 1, b""), out.getvalue())


def test_an_implode_tree_with_the_wrong_number_of_lengths_is_refused() -> None:
    # Two trees of one run of 16 lengths each (64 expected).
    bad = bytes([0, 0xF5, 0, 0xF5]) + bytes(8)
    with pytest.raises(CorruptionError, match="expected 64"):
        _read_one(LegacyEntry("x", b"abc", 6, b""), bad)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        pytest.param(shrink_entry("x", _README), "Shrink", id="shrink"),
        pytest.param(
            implode_entry("x", _README, large_window=True, literal_tree=True),
            "Implode",
            id="implode",
        ),
    ],
)
def test_a_pipe_member_with_a_data_descriptor_is_refused(
    entry: LegacyEntry, message: str
) -> None:
    """With bit 3 the size is only after the data, and neither method marks its end,
    so a pipe cannot find where the data stops. From a file, the central directory
    gives the size and the member reads."""
    data = build_zip([entry], descriptor=True)
    with (
        open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
        pytest.raises(UnsupportedFeatureError, match=message),
    ):
        for _, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read(reader.get("x")) == _README


def _zip64_entry(method: int, flags: int, payload: bytes, size: int) -> bytes:
    """One member whose ZIP64 extra field declares ``size`` over ``payload``."""
    name = b"a.txt"
    extra = struct.pack("<HHQQ", 1, 16, size, len(payload))
    fields = struct.pack(
        "<HHHHHIIIHH", 45, flags, method, 0, 0x21, 0, 0xFFFFFFFF, 0xFFFFFFFF,
        len(name), len(extra),
    )  # fmt: skip
    local = b"PK\x03\x04" + fields + name + extra + payload
    central = (
        b"PK\x01\x02" + struct.pack("<H", 45) + fields
        + struct.pack("<HHHII", 0, 0, 0, 0, 0) + name + extra
    )  # fmt: skip
    eocd = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0
    )
    return local + central + eocd


@pytest.mark.parametrize(
    ("method", "flags"),
    [
        pytest.param(1, 0, id="shrink"),
        pytest.param(6, 0, id="implode-4k-2trees"),
        pytest.param(6, 6, id="implode-8k-3trees"),
    ],
)
def test_a_huge_declared_size_allocates_nothing(
    method: int, flags: int, tmp_path: Path
) -> None:
    """GHSA-9hj8-73fh-9963 (Rust ``zip`` before 9.0.0): a Shrink member whose ZIP64
    size is 2**64 - 1 over a one-byte payload made the decoder reserve the declared
    size up front and abort; the advisory says Implode had the same pattern. Here
    the size only says where the data ends: a read finds the data cut short, and
    extraction refuses the ratio before decoding."""
    data = _zip64_entry(method, flags, b"\x41", 2**64 - 1)
    tracemalloc.start()
    try:
        with open_archive(io.BytesIO(data)) as reader:
            with pytest.raises(TruncatedError):
                reader.read(reader.get("a.txt"))
            with pytest.raises(ResourceLimitError, match="ratio"):
                reader.extract_all(tmp_path / "out")
        with (
            open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
            pytest.raises(TruncatedError),
        ):
            for _, stream in reader.stream_members():
                assert stream is not None
                stream.read()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 32 * 2**20
