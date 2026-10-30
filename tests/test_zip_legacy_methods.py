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
import time
from pathlib import Path

import pytest

from archivey import CompressionAlgorithm, open_archive
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.streams.codecs.zip_legacy_decoder import ShrinkDecoder
from tests.conftest import run_7z
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO
from tests.zip_legacy_build import (
    BitWriter,
    LegacyEntry,
    build_zip,
    implode,
    implode_entry,
    shrink,
    shrink_entry,
)
from tests.zipcrypto import build_zipcrypto_zip

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


def _codes(*pairs: tuple[int, int]) -> bytes:
    """Shrink codes as (code, width) pairs."""
    out = BitWriter()
    for code, width in pairs:
        out.write(code, width)
    return out.getvalue()


_A, _B, _X = ord("a"), ord("b"), ord("x")


@pytest.mark.parametrize(
    ("compressed", "message"),
    [
        pytest.param(
            _codes((_A, 9), (256, 9), (3, 9), (_B, 9)),
            "unknown control code 3",
            id="unknown-control",
        ),
        pytest.param(
            _codes((256, 9), (1, 9)), "starts with a control code", id="control-first"
        ),
        pytest.param(_codes((300, 9)), "starts with an undefined code", id="undefined"),
        # One literal, then a widening at each width from 9: the one at 13 goes past.
        pytest.param(
            _codes((_A, 9), *((c, w) for w in range(9, 14) for c in (256, 1))),
            "past 13 bits",
            id="widen-past-13",
        ),
        pytest.param(_codes((_A, 9), (300, 9)), "names the free code 300", id="free"),
        # 257 and 258 are leaves when the clear frees them, so the next entry takes
        # slot 257 with the freed 257 (the previous code) as its parent: a loop.
        pytest.param(
            _codes((_A, 9), (_B, 9), (257, 9), (256, 9), (2, 9), (_X, 9), (257, 9)),
            "links to a free code or loops",
            id="loop",
        ),
    ],
)
def test_bad_shrink_codes_are_refused(compressed: bytes, message: str) -> None:
    with pytest.raises(CorruptionError, match=message):
        _read_one(LegacyEntry("x", bytes(100), 1, b""), compressed)


def test_shrink_input_that_ends_inside_a_control_code_is_truncated() -> None:
    with pytest.raises(TruncatedError, match="inside a control code"):
        _read_one(LegacyEntry("x", b"ab", 1, b""), _codes((_A, 9), (256, 9)))


def test_a_shrink_entry_past_the_declared_size_is_refused() -> None:
    """Shrink stops after the code that reaches the size, so its last entry can run
    past it; the member's size check refuses the surplus."""
    # "a", "b", then 257 ("ab"): four bytes against a declared three.
    compressed = _codes((_A, 9), (_B, 9), (257, 9))
    with pytest.raises(CorruptionError, match="exceeds its declared size"):
        _read_one(LegacyEntry("x", b"aba", 1, b""), compressed)


def _all_16_bit_tree() -> bytes:
    """64 lengths of 16 bits: only codes 0 to 63 of 65536 are defined."""
    return bytes([3]) + bytes([0xFF]) * 4


def _undefined_implode_code() -> bytes:
    out = BitWriter()
    for byte in _all_16_bit_tree() * 2:
        out.write(byte, 8)
    out.write(0, 1)  # a copy
    out.write(0, 6)  # its low distance bits
    out.write(0xFFFF, 16)  # a distance code past the defined ones
    return out.getvalue()


@pytest.mark.parametrize(
    ("compressed", "message"),
    [
        # Two trees of one run of 16 lengths each (64 expected).
        pytest.param(bytes([0, 0xF5, 0, 0xF5]) + bytes(8), "expected 64", id="count"),
        # 64 lengths of one bit.
        pytest.param(
            bytes([3, 0xF0, 0xF0, 0xF0, 0xF0]) + bytes(8),
            "over-subscribe",
            id="over-subscribed",
        ),
        pytest.param(
            _undefined_implode_code(), "code its tree does not define", id="undefined"
        ),
    ],
)
def test_bad_implode_trees_and_codes_are_refused(
    compressed: bytes, message: str
) -> None:
    with pytest.raises(CorruptionError, match=message):
        _read_one(LegacyEntry("x", b"abc", 6, b""), compressed)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(shrink_entry("a.txt", _README), id="shrink"),
        pytest.param(
            implode_entry("a.txt", _README, large_window=True, literal_tree=True),
            id="implode",
        ),
    ],
)
def test_an_encrypted_member_reads(entry: LegacyEntry) -> None:
    """ZipCrypto around either method, with the right and a wrong password."""
    data = build_zipcrypto_zip(
        b"pw",
        b"a.txt",
        entry.data,
        compression=entry.method,
        extra_flags=entry.flags,
        compressed=entry.compressed,
    )
    with open_archive(io.BytesIO(data), password=b"pw") as reader:
        assert reader.read(reader.get("a.txt")) == _README
    with (
        open_archive(io.BytesIO(data), password=b"wrong") as reader,
        pytest.raises(EncryptionError),
    ):
        reader.read(reader.get("a.txt"))


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

    def reads() -> None:
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

    # About 1.5 MB measured.
    assert traced_peak(reads) < 4 << 20


def test_a_run_of_partial_clears_costs_little() -> None:
    """A clear makes no output, so neither the ratio guard nor a read budget sees it.
    Each costs the slots it frees, not a walk over the 8k-slot table: 60,000 clears
    (135 KB) took about 28 s with the walk."""
    out = BitWriter()
    out.write(ord("A"), 9)
    for _ in range(60_000):
        out.write(256, 9)
        out.write(2, 9)
    data = out.getvalue()
    decoder = ShrinkDecoder(10**9)
    start = time.perf_counter()
    assert decoder.feed(data).data == b"A"
    elapsed = time.perf_counter() - start
    assert elapsed < 5, (
        f"60,000 partial clears took {elapsed:.1f}s: a clear is walking the table again"
    )


def test_long_shrink_entries_are_stored_not_walked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Long entries are looked up, not rebuilt by walking their parents.

    KwKwK codes grow a chain of zeros to 1,791 bytes at 11 bits; then two of its longest
    codes alternate until the table is full, 6,144 codes of about 1,790 bytes each: 11
    MB from 11 KB. Each of those is a stored link, rebuilt by ``_expand`` (the count
    below; restoring the parent walk makes it 0). Stored flat, the strings would hold
    the whole output; as links the table stays small.
    """
    from archivey.internal.streams.codecs import zip_legacy_decoder

    expands = 0
    real_expand = zip_legacy_decoder._expand

    def counting_expand(*args: object) -> bytes:
        nonlocal expands
        expands += 1
        return real_expand(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(zip_legacy_decoder, "_expand", counting_expand)
    out = BitWriter()
    width = 9
    total = 0

    def write(code: int, length: int) -> None:
        nonlocal width, total
        if code >= 1 << width:
            out.write(256, width)
            out.write(1, width)
            width += 1
        out.write(code, width)
        total += length

    write(0, 1)
    for code in range(257, 2048):
        write(code, code - 255)
    for i in range(8192 - 2048):
        write(2046 + i % 2, 2047 - 255 - 1 + i % 2)
    data = out.getvalue()

    def decode() -> None:
        decoder = ShrinkDecoder(total)
        got = 0
        chunk = decoder.feed(data, 1 << 16).data
        while chunk:
            assert not chunk.strip(b"\0")
            got += len(chunk)
            chunk = decoder.feed(b"", 1 << 16).data
        assert got == total
        assert not decoder.flush().data

    decode()
    assert expands >= 8192 - 2048 - 1, "long entries were walked, not looked up"
    # About 2.3 MB measured; stored flat, about 13 MB.
    assert traced_peak(decode) < 4 << 20
