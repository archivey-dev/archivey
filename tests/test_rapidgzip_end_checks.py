"""The rapidgzip accelerator's end-of-data checks for gzip and zlib give the verdict the
standard library gives with the accelerator off.

rapidgzip checks neither a gzip file's length against its ISIZE trailer nor a zlib
stream's Adler-32, and reads a cut stream as a shorter whole one. archivey's checks
(``_GzipTruncationCheckStream``, ``_ZlibAdlerCheckStream``) and the takeover by the
standard library (``_StdlibOnAcceleratorError``) make up for that. Each test forces the
accelerator ``ON`` (``AUTO`` engages only from 16 MiB) and compares with ``OFF``:

- a seek, even back to the start, leaves the gzip check armed;
- ``1f 8b 08`` inside a compressed body is not taken for a further gzip member, so a cut
  or damaged one-member gzip still raises;
- a seek that meets bytes after the data (NUL padding) or damage is handed to the
  standard library, as a read is;
- a second zlib stream is trailing data, not content;
- a raw DEFLATE or gzip stream cut where rapidgzip ends it with no error raises, also
  when a declared size equals the output before the cut.
"""

from __future__ import annotations

import base64
import functools
import gzip
import io
import random
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import TruncatedError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.hashing import crc32_combine
from archivey.internal.streams import codecs
from archivey.internal.streams.codecs import (
    Codec,
    gzip_has_additional_member,
    open_codec_stream,
)
from archivey.internal.streams.codecs.rapidgzip_child import (
    rapidgzip_child_unavailable_reason,
)
from archivey.internal.streams.codecs.rapidgzip_select import (
    _deflate_family_uses_accelerator,
)
from archivey.types import ArchiveFormat
from tests.conftest import requires
from tests.streams_util import rapidgzip_soft_end
from tests.test_zip_native_codecs import _build_minimal_zip

_OFF = AcceleratorMode.OFF
_ON = AcceleratorMode.ON
# A gzip header with valid flags, as it can turn up by chance in a compressed body.
_FAKE_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"


@functools.cache
def _payload() -> bytes:
    """About 1 MB of words and noise: several DEFLATE blocks, and compressible."""
    rng = random.Random(11)
    words = [b"alpha ", b"beta ", b"gamma\n", b"delta "]
    return b"".join(
        rng.choice(words) if rng.random() < 0.8 else bytes([rng.randrange(256)])
        for _ in range(200_000)
    )


@functools.cache
def _noise() -> bytes:
    rng = random.Random(5)
    return bytes(rng.randrange(256) for _ in range(300_000))


@functools.cache
def _gzip_with_magic_in_body() -> bytes:
    """A one-member gzip whose body holds ``1f 8b 08`` and a whole header after it.

    Level 0 stores the payload verbatim, so the bytes are in the compressed file as
    they are in a large file by chance (about once per 16 MiB)."""
    payload = _noise()[:100_000] + _FAKE_HEADER + _noise()[100_000:]
    blob = gzip.compress(payload, compresslevel=0, mtime=0)
    assert _FAKE_HEADER in blob[1:]
    return blob


def _flip(blob: bytes, at: int) -> bytes:
    out = bytearray(blob)
    out[at] ^= 0x55
    return bytes(out)


def _config(mode: AcceleratorMode) -> StreamConfig:
    return StreamConfig(seekable=True, use_rapidgzip=mode)


Outcome = tuple[bytes, "type[Exception] | None"]


def _outcome(
    codec: Codec,
    blob: bytes,
    mode: AcceleratorMode,
    steps: Callable[[BinaryIO], None],
    chunk: int = -1,
) -> Outcome:
    """Run ``steps``, then read to the end in ``chunk`` reads: the bytes that last read
    got and the type of the exception, if any."""
    got = bytearray()
    try:
        with open_codec_stream(codec, io.BytesIO(blob), config=_config(mode)) as s:
            steps(s)
            while block := s.read(chunk):
                got += block
                if chunk < 0:
                    break
    except Exception as exc:  # noqa: BLE001 - compared below
        return bytes(got), type(exc)
    return bytes(got), None


def _no_seek(s: BinaryIO) -> None:
    pass


def _read_then_rewind(s: BinaryIO) -> None:
    s.read(1000)
    s.seek(0)


def _seek_then_rewind(s: BinaryIO) -> None:
    s.seek(5000)
    s.seek(0)


def _end_then_rewind(s: BinaryIO) -> None:
    s.seek(0, io.SEEK_END)
    s.seek(0)


def _skip_forward(s: BinaryIO) -> None:
    s.read(100)
    s.seek(200_000)


_SEEKS = {
    "no-seek": _no_seek,
    "read-then-rewind": _read_then_rewind,
    "seek-then-rewind": _seek_then_rewind,
    "end-then-rewind": _end_then_rewind,
    "skip-forward": _skip_forward,
}


def _assert_same(on: Outcome, off: Outcome) -> None:
    assert (len(on[0]), on[1]) == (len(off[0]), off[1])
    assert on[0] == off[0]


# --- the gzip check survives a seek ----------------------------------------------------


def _gzip_damage(kind: str) -> bytes:
    blob = gzip.compress(_payload(), mtime=0)
    if kind == "cut":
        return blob[: len(blob) * 3 // 4]
    if kind == "wrong-isize":
        return _flip(blob, len(blob) - 2)
    if kind == "intact":
        return blob
    raise AssertionError(kind)


@requires("rapidgzip")
@pytest.mark.parametrize("seek", sorted(_SEEKS))
@pytest.mark.parametrize("kind", ["cut", "wrong-isize", "intact"])
def test_a_seek_leaves_the_gzip_length_check_armed(kind: str, seek: str) -> None:
    """A seek used to turn the ISIZE check off for good: a cut file then read short
    with no error after ``read(1000); seek(0)``."""
    blob = _gzip_damage(kind)
    off = _outcome(Codec.GZIP, blob, _OFF, _SEEKS[seek])
    assert (off[1] is None) == (kind == "intact")
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _SEEKS[seek]), off)


# --- a chance 1f 8b 08 is not a further member -----------------------------------------


def _magic_case(kind: str) -> bytes:
    blob = _gzip_with_magic_in_body()
    if kind == "cut":
        return blob[: len(blob) * 3 // 4]
    if kind == "wrong-isize":
        return _flip(blob, len(blob) - 2)
    if kind == "appended":
        return blob + b"JUNKJUNK"
    if kind == "intact":
        return blob
    if kind == "second-member":
        return blob + gzip.compress(b"tail " * 100, mtime=0)
    if kind == "second-member-cut":
        return blob + gzip.compress(_noise(), mtime=0)[:5000]
    raise AssertionError(kind)


@requires("rapidgzip")
@pytest.mark.parametrize("chunk", [-1, 1 << 16])
@pytest.mark.parametrize(
    "kind",
    [
        "cut",
        "wrong-isize",
        "appended",
        "intact",
        "second-member",
        "second-member-cut",
    ],
)
def test_gzip_magic_in_the_body_does_not_silence_the_length_check(
    kind: str, chunk: int
) -> None:
    blob = _magic_case(kind)
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek, chunk)
    on = _outcome(Codec.GZIP, blob, _ON, _no_seek, chunk)
    assert on[1] is off[1]
    assert (off[1] is None) == (kind in ("appended", "intact", "second-member"))
    if kind == "wrong-isize" and chunk > 0:
        # Not this test's subject: the standard library raises on the chunk that
        # holds the trailer, rapidgzip's check after the last chunk.
        assert on[0].startswith(off[0])
        return
    _assert_same(on, off)


@requires("rapidgzip")
def test_gzip_bytes_after_the_data_are_reported_with_the_accelerator(tmp_path) -> None:
    path = tmp_path / "magic.gz"
    path.write_bytes(_magic_case("appended"))
    for mode in (_OFF, _ON):
        config = ArchiveyConfig(use_rapidgzip=mode)
        with open_archive(path, config=config, seekable_members=True) as reader:
            reader.read(reader.members()[0])
            assert reader.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


@requires("rapidgzip")
def test_appended_length_bytes_do_not_hide_a_wrong_gzip_isize() -> None:
    """Four bytes after a wrong ISIZE are not the trailer, even when they equal the length.

    The backstop compares the decoded length with the last four bytes of the file.
    Appending the real length there makes that comparison succeed, and the accelerator
    returns the payload. The standard library still raises on the real trailer. Those
    four bytes are not a trailer: the backstop finds it by the CRC-32 of the output.
    The ``gzip_accel`` fuzz target found this shape.
    """
    payload = b"atheris seed payload\n" * 8
    blob = bytearray(gzip.compress(payload, mtime=0))
    blob[-1] ^= 0x01
    blob += len(payload).to_bytes(4, "little")
    off = _outcome(Codec.GZIP, bytes(blob), _OFF, _no_seek)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, bytes(blob), _ON, _no_seek), off)


@requires("rapidgzip")
@pytest.mark.parametrize(
    ("wrong_isize", "after"),
    [
        (False, b""),
        (False, bytes(4)),
        (False, bytes(100_000)),
        (True, b""),
        (True, bytes(4)),
        (True, bytes(100_000)),
        (True, bytes(5) + (168).to_bytes(4, "little")),
        (False, b"junk"),
    ],
    ids=[
        "valid",
        "valid-padded",
        "valid-long-padding",
        "wrong-isize",
        "wrong-isize-padded",
        "wrong-isize-long-padding",
        "wrong-isize-padding-then-length",
        "valid-then-junk",
    ],
)
def test_gzip_last_isize_is_judged_as_with_the_accelerator_off(
    wrong_isize: bool, after: bytes
) -> None:
    """A wrong ISIZE on the last member raises whatever follows it; a right one reads
    with or without zero padding. The trailer is found by its CRC-32, so neither the
    padding nor the bytes after a wrong trailer decide."""
    payload = b"atheris seed payload\n" * 8
    blob = bytearray(gzip.compress(payload, mtime=0))
    if wrong_isize:
        blob[-1] ^= 0x01
    blob = bytes(blob) + after
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
    if wrong_isize:
        assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek), off)


@requires("rapidgzip")
@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "valid-padded",
        "last-wrong-isize",
        "last-wrong-isize-then-length",
        "cut-last",
    ],
)
def test_gzip_concatenated_members_are_judged_as_with_the_accelerator_off(
    case: str,
) -> None:
    """The output's CRC-32 is not the last member's, so it never finds a trailer in a
    concatenated file; the further-member scan and the last member's trailer decide. A
    wrong ISIZE or a cut on the last member raises as with the accelerator off (see
    ``test_gzip_wrong_last_isize_in_a_concatenated_file_raises`` for more members)."""
    first, second = b"first member payload\n" * 5, b"second member payload\n" * 7
    member1 = gzip.compress(first, mtime=0)
    member2 = bytearray(gzip.compress(second, mtime=0))
    after = b""
    if case == "valid-padded":
        after = bytes(9)
    elif case.startswith("last-wrong-isize"):
        member2[-1] ^= 0x01
        if case.endswith("length"):
            after = len(second).to_bytes(4, "little")
    elif case == "cut-last":
        del member2[-6:]
    blob = member1 + bytes(member2) + after
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
    assert (off[1] is not None) == (case not in ("valid", "valid-padded"))
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek), off)


def _require_the_accelerator_in_use() -> None:
    """Skip where ``ON`` would decode with the standard library: a comparison of the two
    modes then compares nothing."""
    if not _deflate_family_uses_accelerator(_config(_ON)):
        pytest.skip("the accelerator is not selected here")
    reason = rapidgzip_child_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)


@requires("rapidgzip")
@pytest.mark.parametrize(
    ("case", "flip"),
    [
        ("three-members", 1 << 24),
        ("large-last-member", 1 << 24),
        ("three-members", 1),
        ("large-last-member", 1),
    ],
    ids=[
        "three-members-high-byte",
        "large-last-member-high-byte",
        "three-members-low-byte",
        "large-last-member-low-byte",
    ],
)
def test_gzip_wrong_last_isize_in_a_concatenated_file_raises(
    case: str, flip: int
) -> None:
    """The further-member scan stands down at the first further member it confirms, and a
    candidate counts once zlib has decoded 64 KiB of its input, so with three or more
    members, or a large last one, it says nothing about the last member. Its trailer is
    checked against the end of the output instead, so a wrong ISIZE there raises as with
    the accelerator off. A flipped high byte makes the length larger than the output, so
    no candidate is checked; a flipped low byte keeps a length inside the output, and the
    CRC-32 of the output from there, from the running CRC-32 and a read-back of at most
    one checkpoint spacing, is what turns it down."""
    contents = [b"first member payload\n" * 5]
    if case == "three-members":
        contents += [b"middle member payload\n" * 7, b"last member payload\n" * 3]
    else:
        contents += [random.Random(1).randbytes(300_000)]
    members = [bytearray(gzip.compress(c, mtime=0)) for c in contents]
    isize = int.from_bytes(members[-1][-4:], "little") ^ flip
    members[-1][-4:] = isize.to_bytes(4, "little")
    blob = b"".join(members)
    assert (isize <= len(b"".join(contents))) == (flip == 1)
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek), off)


def _with_crc(prefix: bytes, target: int, suffix: bytes = b"") -> bytes:
    """``prefix``, four chosen bytes and ``suffix``, with the CRC-32 ``target``.

    The CRC-32 is affine in the four bytes over GF(2) and the map is invertible, so the
    bytes come out of a 32-by-32 elimination. A forger picks the CRC-32 this way, which is
    why no rule here may lean on a CRC-32 being unlikely to repeat itself."""

    def crc(x: int) -> int:
        return zlib.crc32(prefix + x.to_bytes(4, "little") + suffix)

    zero = crc(0)
    basis: dict[int, tuple[int, int]] = {}  # pivot bit -> (vector, bits of x behind it)

    def reduce(vector: int, combo: int) -> tuple[int, int]:
        for pivot in sorted(basis, reverse=True):
            if vector >> pivot & 1:
                vector ^= basis[pivot][0]
                combo ^= basis[pivot][1]
        return vector, combo

    for bit in range(32):
        vector, combo = reduce(crc(1 << bit) ^ zero, 1 << bit)
        if vector:
            basis[vector.bit_length() - 1] = (vector, combo)
    rest, x = reduce(target ^ zero, 0)
    assert rest == 0
    out = prefix + x.to_bytes(4, "little") + suffix
    assert zlib.crc32(out) == target
    return out


def _gzip_with_a_forged_trailer_after_the_real_one(shift: int) -> bytes:
    """A one-member gzip whose ISIZE is wrong, and whose last eight bytes are exactly the
    output's CRC-32 and length, starting ``shift`` bytes after the real trailer.

    Below 4 the copy overlaps the real CRC-32, which then has to repeat itself at that
    distance, so the payload is forced to a CRC-32 that does. From 4 to 8 the copy starts
    in the ISIZE field, and the field's leading bytes are free. Past 8 the copy is wholly
    appended, after ``shift - 8`` other bytes. The CRC-32 and the free bytes are chosen so
    that the CRC-32 occurs nowhere else by accident."""
    target = {1: 0x5A5A5A5A, 2: 0x3C5A3C5A, 3: 0x5A12345A}.get(shift, 0x12345678)
    payload = _with_crc(random.Random(shift).randbytes(2000), target)
    crc = zlib.crc32(payload).to_bytes(4, "little")
    want = crc + len(payload).to_bytes(4, "little")
    blob = bytearray(gzip.compress(payload, mtime=0))
    if shift < 4:
        assert crc[shift:] == want[: 4 - shift]
        blob[-4:] = want[4 - shift : 8 - shift]
        blob += want[8 - shift :]
    elif shift <= 8:
        blob[-4:] = b"\xa5" * (shift - 4) + want[: 8 - shift]
        blob += want[8 - shift :]
    else:
        blob[-1] ^= 0x01
        blob += b"\xa5" * (shift - 8) + want
    assert blob[-8:] == want
    return bytes(blob)


@requires("rapidgzip")
@pytest.mark.parametrize("shift", [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 70])
def test_gzip_forged_trailer_after_the_real_one_is_not_a_trailer(shift: int) -> None:
    """The eight bytes CRC-32 + length may be built out of the real trailer's tail, its
    ISIZE field and appended bytes. Up to 56 bytes past the end of the real trailer (shift
    64 for a length with no trailing zero byte), the real CRC-32 is a second occurrence in
    the range the lookup searches, and the candidate is turned down. Past that the lookup
    does not exclude the copy; only rapidgzip's own error does. Ten or more appended bytes
    (shifts past 9) never reach the lookup on rapidgzip 0.16, which raises on them. Shift
    12 is within the lookup's range; shift 70 is past it, a tripwire for that rapidgzip
    error: a rapidgzip that stops raising would make it read clean, and this test fail."""
    _require_the_accelerator_in_use()
    blob = _gzip_with_a_forged_trailer_after_the_real_one(shift)
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek), off)


@requires("rapidgzip")
def test_gzip_forged_trailer_reaching_back_into_the_compressed_data_is_not_one() -> (
    None
):
    """The copy may also sit before the real trailer, inside the compressed data. A
    stored deflate block ends with the payload's own bytes, so a payload that ends with
    CRC-32 + length, with the CRC-32 forced to zero, puts the copy there; the real
    trailer after it then holds a zero CRC-32 and a zero ISIZE, which is wrong, and the
    file ends in zeros. The real CRC-32 is a second occurrence, so this is turned down."""
    _require_the_accelerator_in_use()
    size = 40 * 21 + 12
    payload = _with_crc(
        b"atheris seed payload\n" * 40, 0, bytes(4) + size.to_bytes(4, "little")
    )
    assert len(payload) == size
    compressor = zlib.compressobj(0, zlib.DEFLATED, 31)
    blob = bytearray(compressor.compress(payload) + compressor.flush())
    assert blob[-16:-8] == bytes(4) + size.to_bytes(4, "little")
    blob[-4:] = bytes(4)  # ISIZE 0: wrong
    off = _outcome(Codec.GZIP, bytes(blob), _OFF, _no_seek)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, bytes(blob), _ON, _no_seek), off)


def test_the_gzip_accel_oracle_excuses_a_wrong_isize_only_where_the_spec_accepts_it() -> (
    None
):
    """The ``gzip_accel`` fuzz target excuses a clean accelerated read of a file the
    standard library rejects for its length only as far as the spec accepts it: a member
    another member follows. Never the last member, which the backstop checks against the
    end of the output however many members come before it and however large it is, and
    never a single member, padded or not."""
    from tests.atheris_fuzz.targets import _gzip_ignoring_lengths

    def member(content: bytes, *, wrong_isize: bool = False) -> bytes:
        blob = bytearray(gzip.compress(content, mtime=0))
        if wrong_isize:
            blob[-1] ^= 0x01
        return bytes(blob)

    a, b, c = b"a" * 50, b"b" * 70, b"c" * 30
    large = random.Random(3).randbytes(70_000)
    one = member(a, wrong_isize=True)
    assert _gzip_ignoring_lengths(one) is None
    assert _gzip_ignoring_lengths(one + bytes(4)) is None
    assert _gzip_ignoring_lengths(one + len(a).to_bytes(4, "little")) is None
    assert _gzip_ignoring_lengths(member(a, wrong_isize=True) + member(b)) == a + b
    middle_wrong = member(a) + member(b, wrong_isize=True) + member(c)
    assert _gzip_ignoring_lengths(middle_wrong) == a + b + c
    assert _gzip_ignoring_lengths(middle_wrong + bytes(7)) == a + b + c
    assert _gzip_ignoring_lengths(member(a) + member(b, wrong_isize=True)) is None
    three_wrong_last = member(a) + member(b) + member(c, wrong_isize=True)
    assert _gzip_ignoring_lengths(three_wrong_last) is None
    assert _gzip_ignoring_lengths(member(a) + member(large, wrong_isize=True)) is None


@requires("rapidgzip")
def test_gzip_wrong_isize_after_a_seek_that_skipped_output_is_still_caught() -> None:
    """With bytes skipped there is no CRC-32 of the output; the last four bytes of the
    file stand in for the ISIZE, which still catches a plain wrong ISIZE."""
    payload = b"atheris seed payload\n" * 8
    blob = bytearray(gzip.compress(payload, mtime=0))
    blob[-1] ^= 0x01

    def skip(s: BinaryIO) -> None:
        s.seek(len(payload) - 1)

    off = _outcome(Codec.GZIP, bytes(blob), _OFF, skip)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, bytes(blob), _ON, skip), off)


def _valid_concatenation(kind: str) -> bytes:
    """A whole file of several gzip members, whose last trailer the backstop checks
    against the end of the output (``_last_member_ends_the_file``)."""
    from tests.streams_util import make_bgzf

    first = gzip.compress(b"first member payload\n" * 4000, mtime=0)
    middle = gzip.compress(b"middle member payload\n" * 7, mtime=0)
    if kind == "three-members":
        return first + middle + gzip.compress(b"last\n" * 3, mtime=0)
    if kind == "large-last":
        return first + gzip.compress(random.Random(4).randbytes(300_000), mtime=0)
    if kind == "empty-last":
        return first + middle + gzip.compress(b"", mtime=0)
    assert kind == "bgzf", kind
    return make_bgzf([bytes([i]) * 70_000 for i in range(1, 4)])


@requires("rapidgzip")
@pytest.mark.parametrize(
    "blob",
    [
        pytest.param(_magic_case("second-member"), id="second-member"),
        pytest.param(gzip.compress(bytes(range(256)) * 800, mtime=0), id="one-member"),
        pytest.param(_valid_concatenation("three-members"), id="three-members"),
        pytest.param(_valid_concatenation("large-last"), id="large-last-member"),
        pytest.param(_valid_concatenation("empty-last"), id="empty-last-member"),
        pytest.param(_valid_concatenation("bgzf"), id="bgzf"),
    ],
)
def test_a_real_further_gzip_member_needs_no_stdlib_handover(
    monkeypatch: pytest.MonkeyPatch, blob: bytes
) -> None:
    """A multi-member file's trailer is only its last member's: the mismatch with the
    whole output is expected, and a confirmed further member with a last member's
    trailer that matches keeps the standard library out of it. A healthy one-member file
    matches its trailer, and its decode reaches the end of the source. The last-member
    check takes the candidate's CRC-32 from the running CRC-32 and a read-back of at most
    one checkpoint spacing; this pins only that the standard library does not take
    over."""
    handovers = _handovers(monkeypatch)
    got, error = _outcome(Codec.GZIP, blob, _ON, _no_seek)
    assert error is None
    assert got == gzip.decompress(blob)
    assert handovers == []


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        pytest.param(b"", False, id="none"),
        pytest.param(_FAKE_HEADER + b"\xff" * 4000, False, id="header-then-noise"),
        pytest.param(b"\x1f\x8b\x08\xe0" + b"\0" * 20, False, id="reserved-flags"),
        pytest.param(gzip.compress(b"x", mtime=0), True, id="member"),
        pytest.param(gzip.compress(b"", mtime=0), True, id="empty-member"),
        pytest.param(gzip.compress(b"abc" * 9000)[:30], False, id="cut-member"),
    ],
)
def test_gzip_has_additional_member_confirms_the_candidate(
    tail: bytes, expected: bool
) -> None:
    blob = gzip.compress(_noise()[:50_000], compresslevel=0, mtime=0)
    assert gzip_has_additional_member(io.BytesIO(blob + tail)) is expected


def test_gzip_has_additional_member_finds_a_header_split_across_blocks() -> None:
    member = gzip.compress(b"x" * 100, mtime=0)
    head = b"\0" * ((1 << 20) - 1)  # the magic starts on the last byte of block one
    assert gzip_has_additional_member(io.BytesIO(head + member))


def test_gzip_has_additional_member_reads_a_member_header_with_every_field() -> None:
    body = zlib.compressobj(6, zlib.DEFLATED, -15)
    deflated = body.compress(b"payload") + body.flush()
    # FHCRC | FEXTRA | FNAME | FCOMMENT
    header = b"\x1f\x8b\x08\x1e" + b"\0" * 4 + b"\x00\x03"
    header += b"\x02\x00ab" + b"name\0" + b"comment\0"
    header += (zlib.crc32(header) & 0xFFFF).to_bytes(2, "little")
    trailer = zlib.crc32(b"payload").to_bytes(4, "little") + (7).to_bytes(4, "little")
    member = header + deflated + trailer
    assert gzip.decompress(member) == b"payload"
    assert gzip_has_additional_member(io.BytesIO(b"\0" + member))
    bad_crc = header[:-2] + b"\0\0" + deflated + trailer
    assert not gzip_has_additional_member(io.BytesIO(b"\0" + bad_crc))


def _costly_fake_member() -> bytes:
    """A header zlib accepts, a 4000-byte stored block, then a reserved block type: a
    candidate that decodes a whole probe piece before it fails."""
    stored = (
        b"\x00" + (4000).to_bytes(2, "little") + (0xFFFF ^ 4000).to_bytes(2, "little")
    )
    return _FAKE_HEADER + stored + b"\0" * 4000 + b"\x07"


@pytest.mark.parametrize(("fakes", "expected"), [(10, True), (400, False)])
def test_gzip_member_scan_has_a_budget(fakes: int, expected: bool) -> None:
    """Candidates that each decode a long way before failing spend a shared budget;
    once it is spent the scan answers no, and the standard library decides."""
    blob = b"\0" + _costly_fake_member() * fakes + gzip.compress(b"x", mtime=0)
    assert gzip_has_additional_member(io.BytesIO(blob)) is expected


def test_gzip_member_probe_output_stays_within_its_bound(monkeypatch) -> None:
    """One candidate decodes at most ``_MEMBER_PROBE_OUTPUT`` of output in total, also
    when no single probe read reaches the bound and the last one would pass it."""
    rng = random.Random(3)
    # About 72:1, so each 4 KiB probe read expands by about 0.3 MiB.
    raw = b"".join(bytes([rng.randrange(256)]) + b"\0" * 200 for _ in range(10_000))
    member = gzip.compress(raw, mtime=0)
    produced = 0
    real = zlib.decompressobj

    class _Counting:
        def __init__(self, wbits: int) -> None:
            self._decoder = real(wbits)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            nonlocal produced
            out = self._decoder.decompress(data, max_length)
            produced += len(out)
            return out

        def __getattr__(self, name: str) -> object:
            return getattr(self._decoder, name)

    monkeypatch.setattr(codecs.gzip_codec.zlib, "decompressobj", _Counting)
    assert codecs.gzip_codec._gzip_member_at(io.BytesIO(member), 0, 1 << 20)[0] is True
    assert produced == codecs.gzip_codec._MEMBER_PROBE_OUTPUT


# --- the last member of a concatenated gzip is checked ---------------------------------

# The shape the gzip_accel fuzz target found, minimized: two whole members of b"a", then
# a third member cut right after its 10-byte header. rapidgzip reads the header, meets
# the end of the file, and ends with no error, at the end of the source. The further-member
# scan confirmed the second member, so the cut third one read clean.
_FUZZ_CUT_AFTER_A_HEADER = base64.b64decode(
    "H4sIAAAAAAACA0sEAEO+t+gBAAAAH4sIAAAAAAACA0sEAEO+t+gBAAAAH4sIAAAAAAACAw=="
)


def _gzip_member(content: bytes, *, name: bytes | None = None) -> bytes:
    out = io.BytesIO()
    filename = name.decode("latin-1") if name is not None else ""
    with gzip.GzipFile(fileobj=out, mode="wb", filename=filename, mtime=0) as gz:
        gz.write(content)
    return out.getvalue()


@functools.cache
def _cut_last_members() -> dict[str, bytes]:
    from tests.streams_util import BGZF_EOF, make_bgzf, make_bgzf_block

    first = _gzip_member(b"first member payload\n" * 4000)
    middle = _gzip_member(b"middle member payload\n" * 7)
    last = _gzip_member(b"last member payload\n" * 3, name=b"last.txt")
    large = _gzip_member(random.Random(2).randbytes(300_000))
    parts = [bytes([i]) * 70_000 for i in range(1, 4)]
    return {
        "fuzz-input": _FUZZ_CUT_AFTER_A_HEADER,
        "three-cut-after-the-header": first + middle + last[:10],
        "three-cut-after-the-name": first + middle + last[: 10 + len(b"last.txt\0")],
        "three-cut-in-the-data": first + middle + last[:-12],
        "three-cut-in-the-trailer": first + middle + last[:-3],
        "large-last-cut": first + large[:200_000],
        "bgzf-cut-after-a-block-header": make_bgzf(parts, eof=False)
        + make_bgzf_block(b"tail" * 100)[:18],
        "bgzf-eof-block-cut": make_bgzf(parts)[: -28 + 18],
        "bgzf-eof-block-cut-in-the-trailer": make_bgzf(parts, eof=False)
        + BGZF_EOF[:-4],
        "bgzf-cut-block-then-the-eof-block": make_bgzf(parts, eof=False)
        + make_bgzf_block(b"tail" * 100)[:18]
        + BGZF_EOF,
        "three-cut-after-the-header-then-zeros": first + middle + last[:10] + bytes(20),
    }


@requires("rapidgzip")
@pytest.mark.parametrize("case", sorted(_cut_last_members()))
@pytest.mark.parametrize("chunk", [-1, 1 << 16])
def test_a_cut_last_member_of_a_concatenated_gzip_raises(case: str, chunk: int) -> None:
    """A concatenated file's trailer is its last member's, which the CRC-32 of the whole
    output does not find; a further member used to stand the check down, so a last member
    cut where rapidgzip ends with no error (right after its header) read clean. The
    last member's trailer is now checked against the end of the output."""
    blob = _cut_last_members()[case]
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek, chunk)
    assert off[1] is not None
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek, chunk), off)


@requires("rapidgzip")
def test_every_cut_of_the_last_of_three_gzip_members_raises() -> None:
    """Every cut point of the last member, from its first byte to its last, gives the
    standard library's verdict with the accelerator on."""
    _require_the_accelerator_in_use()
    head = _gzip_member(b"first\n" * 50) + _gzip_member(b"middle\n" * 7)
    last = _gzip_member(b"last member payload\n" * 3, name=b"n")
    differ = []
    for cut in range(1, len(last)):
        blob = head + last[:cut]
        off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
        on = _outcome(Codec.GZIP, blob, _ON, _no_seek)
        if (len(on[0]), on[1]) != (len(off[0]), off[1]) or on[0] != off[0]:
            differ.append((cut, on[1], off[1]))
    assert differ == []


def _cut_after_two_members(forged: int) -> bytes:
    """Two members, then a third cut after its header, with its last four bytes forged
    to ``forged``."""
    first = random.Random(6).randbytes(100_000)
    second = b"second member payload\n" * 45 + b"0123456789"
    assert len(second) == 1000
    blob = bytearray(
        gzip.compress(first, mtime=0)
        + gzip.compress(second, mtime=0)
        + gzip.compress(b"third", mtime=0)[:10]
    )
    blob[-4:] = forged.to_bytes(4, "little")
    return bytes(blob)


def _skip_to_50000(s: BinaryIO) -> None:
    s.seek(50_000)


def _require_a_soft_end(blob: bytes, tmp_path: Path) -> None:
    """Skip where this rapidgzip build does not end the cut in ``blob`` with no error
    after decoding to the end of the file, as the Linux wheels do on a member cut after
    its header. A build that raises there (the macOS wheels), or stops short of the end,
    gets the standard library's verdict at once, so the last-member check whose
    internals a test spies on never runs; the verdict tests above hold there too."""
    path = tmp_path / "cut.gz"
    path.write_bytes(blob)
    end = rapidgzip_soft_end(str(path))
    if end is None or end[1] < len(blob):
        pytest.skip("this rapidgzip build does not end softly at the end of this cut")


@requires("rapidgzip")
@pytest.mark.parametrize("chunk", [-1, 100])
def test_a_forged_last_trailer_hashed_since_a_skip_raises(chunk: int) -> None:
    """After a seek that skipped output there is no CRC-32 of the whole output, but the
    one kept since reading resumed still covers a last member that starts after the
    seek target, however many reads it took. Four bytes that give a length must not
    stand in for that member: its trailer is checked, and a cut file raises."""
    blob = _cut_after_two_members(1000)  # the second member's length
    off = _outcome(Codec.GZIP, blob, _OFF, _skip_to_50000, chunk)
    assert off[1] is TruncatedError
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _skip_to_50000, chunk), off)


@requires("rapidgzip")
def test_the_crc_kept_since_a_skip_spans_every_read_after_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Read in 100-byte pieces after the skip, the CRC-32 kept since it still starts at
    the skip, so the last member's 1,000 bytes are read back themselves and nothing
    before them is."""
    _require_the_accelerator_in_use()
    blob = _cut_after_two_members(1000)
    _require_a_soft_end(blob, tmp_path)
    read_back = _read_backs(monkeypatch)
    assert _outcome(Codec.GZIP, blob, _ON, _skip_to_50000, 100)[1] is TruncatedError
    assert read_back == [1000]


@requires("rapidgzip")
@pytest.mark.parametrize("chunk", [-1, 100])
def test_a_forged_last_trailer_reaching_before_a_skip_raises(chunk: int) -> None:
    """After a seek that skipped output, a last-member trailer whose length reaches back
    before the seek target has no saved CRC-32 for the skipped part. That part is read
    back from rapidgzip, so a cut file forged so still raises as with the accelerator
    off."""
    blob = _cut_after_two_members(101_000)  # the length of the whole output
    off = _outcome(Codec.GZIP, blob, _OFF, _skip_to_50000, chunk)
    assert off[1] is TruncatedError
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _skip_to_50000, chunk), off)


@requires("rapidgzip")
def test_a_skip_reads_back_only_the_skipped_part_of_the_last_member(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The part of a candidate after the point where reading resumed comes from the CRC-32
    kept since; only the part before it is read back."""
    _require_the_accelerator_in_use()
    blob = _cut_after_two_members(101_000)
    _require_a_soft_end(blob, tmp_path)
    read_back = _read_backs(monkeypatch)
    assert _outcome(Codec.GZIP, blob, _ON, _skip_to_50000)[1] is TruncatedError
    assert read_back == [50_000]


def _skip_into_the_last_member(s: BinaryIO) -> None:
    s.seek(200_000)  # the "large-last" fixture's last member holds 84_000..384_000


@requires("rapidgzip")
@pytest.mark.parametrize("ceiling", [100_000, 64 << 20])
def test_a_skipped_read_back_past_its_ceiling_goes_to_the_stdlib(
    monkeypatch: pytest.MonkeyPatch, ceiling: int
) -> None:
    """After a skip into the last member, the 116,000 skipped bytes of it are read back
    under the ceiling; past it, the standard library reads the valid file instead, with
    the same bytes and no error."""
    _require_the_accelerator_in_use()
    monkeypatch.setattr(codecs.gzip_codec, "_SKIPPED_READ_BACK", ceiling)
    blob = _valid_concatenation("large-last")
    handovers = _handovers(monkeypatch)
    read_back = _read_backs(monkeypatch)
    got, error = _outcome(Codec.GZIP, blob, _ON, _skip_into_the_last_member)
    assert (got, error) == (gzip.decompress(blob)[200_000:], None)
    assert (handovers != [], 116_000 in read_back) == (
        ceiling < 116_000,
        ceiling > 116_000,
    )


@requires("rapidgzip")
@pytest.mark.parametrize("valid", [True, False])
def test_a_seek_to_exactly_the_end_then_a_read_is_checked(valid: bool) -> None:
    """``seek(n)`` to exactly the length of the output is not clamped, so it does not
    count as meeting the end (``_seek_reached_end``) and reads nothing through. The read
    after it meets the end and runs the check, with no CRC-32 of the output at all: the
    candidate is read back from its start. A cut file raises as with the accelerator off,
    and a valid one reads nothing more, with no error."""
    blob = (
        _valid_concatenation("three-members")
        if valid
        else _cut_after_two_members(101_000)
    )
    size = len(gzip.decompress(blob)) if valid else 101_000

    def seek_to_the_end(s: BinaryIO) -> None:
        assert s.seek(size) == size

    off = _outcome(Codec.GZIP, blob, _OFF, seek_to_the_end)
    assert off == (b"", None if valid else TruncatedError)
    _assert_same(_outcome(Codec.GZIP, blob, _ON, seek_to_the_end), off)


@requires("rapidgzip")
@pytest.mark.parametrize("target", [50_000, 84_160])
def test_a_valid_concatenation_after_a_skip_needs_no_stdlib_handover(
    monkeypatch: pytest.MonkeyPatch, target: int
) -> None:
    """A skip before the last member (its trailer checked against the CRC-32 kept since
    the skip), or into it (the skipped part read back), reads a valid file with no
    handover."""
    _require_the_accelerator_in_use()
    blob = _valid_concatenation("three-members")
    output = gzip.decompress(blob)
    assert target < len(output)

    def skip(s: BinaryIO) -> None:
        s.seek(target)

    handovers = _handovers(monkeypatch)
    got, error = _outcome(Codec.GZIP, blob, _ON, skip)
    assert (got, error) == (output[target:], None)
    assert handovers == []


def _handovers(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record each switch to the standard library (``switch_to_stdlib``)."""
    handovers: list[object] = []
    takeover = codecs.stdlib_takeover._StdlibOnAcceleratorError
    original = takeover.switch_to_stdlib

    def spy(
        self: codecs.stdlib_takeover._StdlibOnAcceleratorError, *args: object
    ) -> None:
        handovers.append(args)
        original(self, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(takeover, "switch_to_stdlib", spy)
    return handovers


def _read_backs(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the length of each read-back of the last-member check."""
    read_back: list[int] = []
    check = codecs.gzip_codec._GzipTruncationCheckStream
    original = check._output_crc

    def spy(self: object, start: int, stop: int, crc: int) -> int | None:
        read_back.append(stop - start)
        return original(self, start, stop, crc)  # type: ignore[arg-type]

    monkeypatch.setattr(check, "_output_crc", spy)
    return read_back


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (b"", b""),
        (b"", b"tail"),
        (b"head", b""),
        (b"x", b"y"),
        (random.Random(11).randbytes(1000), random.Random(12).randbytes(4097)),
    ],
    ids=["both-empty", "empty-a", "empty-b", "one-byte-each", "random"],
)
def test_the_crc_of_a_suffix_comes_from_the_running_crc(a: bytes, b: bytes) -> None:
    """The identity the last-member check rests on: the CRC-32 of the end ``B`` of the
    output ``A + B`` from the CRC-32 of the whole and of ``A``, with no read of ``B``."""
    assert zlib.crc32(b) == zlib.crc32(a + b) ^ crc32_combine(zlib.crc32(a), 0, len(b))


@pytest.mark.parametrize("piece", [1, 7, 100, 1 << 12])
def test_crc_checkpoints_hold_the_crc_of_each_prefix(
    monkeypatch: pytest.MonkeyPatch, piece: int
) -> None:
    """Fed in pieces of any size, a re-read behind the frontier and a piece past a gap
    included, the checkpoints hold the CRC-32 from ``start`` to each multiple of the
    spacing, and the value the CRC-32 to the frontier."""
    spacing = 64
    monkeypatch.setattr(codecs.gzip_codec, "_CRC_CHECKPOINT_SPACING", spacing)
    data = random.Random(13).randbytes(1000)
    crc = codecs.gzip_codec._CheckpointedCrc(10)
    for at in range(10, len(data), piece):
        crc.feed(at, data[at : at + piece])
        crc.feed(10, data[10:at])  # behind the frontier: counts nothing
    crc.feed(len(data) + 5, b"past a gap")  # leaves the frontier where it was
    assert (crc.frontier, crc.value) == (len(data), zlib.crc32(data[10:]))
    assert crc.checkpoints == [
        zlib.crc32(data[10:stop]) for stop in range(10, len(data) + 1, spacing)
    ]


@requires("rapidgzip")
@pytest.mark.parametrize("last_size", [50, 1000])
def test_the_last_member_check_reads_back_little_more_than_the_last_member(
    monkeypatch: pytest.MonkeyPatch, last_size: int
) -> None:
    """The trailer's place is not known exactly, so several candidates give a length.
    They are tried shortest first, and the first match ends the search. A last member
    shorter than the way back to its checkpoint is read back itself: the read-back is
    the last member's output and at most the shorter candidates before it."""
    _require_the_accelerator_in_use()
    first = random.Random(7).randbytes(300_000)
    last = bytes(range(256)) * (last_size // 256) + bytes(last_size % 256)
    blob = (
        gzip.compress(first, mtime=0)
        + gzip.compress(b"middle\n" * 9, mtime=0)
        + gzip.compress(last, mtime=0)
    )
    read_back = _read_backs(monkeypatch)
    got, error = _outcome(Codec.GZIP, blob, _ON, _no_seek)
    assert error is None
    assert got == gzip.decompress(blob)
    assert read_back[-1] == last_size
    assert all(size < last_size for size in read_back[:-1])


@requires("rapidgzip")
def test_a_forged_last_trailer_reads_back_no_more_than_the_checkpoint_spacing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A candidate's length comes from the file. A cut file whose last four bytes are
    forged to a length just under the output's would once have had the whole output
    read back before the standard library decodes it again; with saved CRC-32s each
    candidate costs a read-back shorter than their spacing, and the cut file raises."""
    _require_the_accelerator_in_use()
    spacing = 1 << 16
    monkeypatch.setattr(codecs.gzip_codec, "_CRC_CHECKPOINT_SPACING", spacing)
    first = random.Random(8).randbytes(300_000)
    blob = bytearray(
        gzip.compress(first, mtime=0)
        + gzip.compress(b"middle\n" * 9, mtime=0)
        + gzip.compress(b"third", mtime=0)[:10]
    )
    blob[-4:] = (len(first) - 1000).to_bytes(4, "little")
    _require_a_soft_end(bytes(blob), tmp_path)
    read_back = _read_backs(monkeypatch)
    off = _outcome(Codec.GZIP, bytes(blob), _OFF, _no_seek)
    assert off[1] is TruncatedError
    _assert_same(_outcome(Codec.GZIP, bytes(blob), _ON, _no_seek), off)
    assert 1 <= len(read_back) <= 4
    assert all(size < spacing for size in read_back)


@requires("rapidgzip")
def test_a_last_member_of_several_checkpoints_needs_no_stdlib_handover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A last member longer than many checkpoint spacings is checked from the saved
    CRC-32s, not handed to the standard library, and reads back less than one spacing."""
    _require_the_accelerator_in_use()
    spacing = 1 << 12
    monkeypatch.setattr(codecs.gzip_codec, "_CRC_CHECKPOINT_SPACING", spacing)
    blob = _valid_concatenation("large-last")
    handovers = _handovers(monkeypatch)
    read_back = _read_backs(monkeypatch)
    got, error = _outcome(Codec.GZIP, blob, _ON, _no_seek)
    assert (got, error) == (gzip.decompress(blob), None)
    assert handovers == []
    assert all(size < spacing for size in read_back)


def _gzip_of_zeros(size: int, crc: int) -> tuple[bytes, int]:
    """A gzip member of ``size`` zero bytes, written 1 MiB at a time so that no buffer of
    ``size`` bytes is ever live, and ``crc`` carried on over its content."""
    out, chunk = io.BytesIO(), bytes(1 << 20)
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as f:
        for _ in range(size // len(chunk)):
            f.write(chunk)
            crc = zlib.crc32(chunk, crc)
    return out.getvalue(), crc


@requires("rapidgzip")
def test_a_last_member_over_64_mib_needs_no_stdlib_handover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid last member of more than 64 MiB, at the real checkpoint spacing, is
    decided from the saved CRC-32s with no handover to the standard library."""
    _require_the_accelerator_in_use()
    head = b"first\n" * 1000
    last, expected = _gzip_of_zeros(65 << 20, zlib.crc32(head))
    blob = gzip.compress(head, mtime=0) + last
    handovers = _handovers(monkeypatch)
    read_back = _read_backs(monkeypatch)
    crc, size = 0, 0
    with open_codec_stream(Codec.GZIP, io.BytesIO(blob), config=_config(_ON)) as s:
        while data := s.read(1 << 20):
            crc, size = zlib.crc32(data, crc), size + len(data)
    assert (crc, size) == (expected, len(head) + (65 << 20))
    assert handovers == []
    assert read_back != []
    assert all(n < codecs.gzip_codec._CRC_CHECKPOINT_SPACING for n in read_back)


@requires("rapidgzip")
def test_an_empty_last_member_with_a_long_name_reads_as_with_the_accelerator_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty last member whose header starts further back than the check looks for it
    (``_EMPTY_MEMBER_REACH``: a long ``FNAME``) is not confirmed, so the read goes to the
    standard library, which reads it whole: the same bytes, and no error."""
    _require_the_accelerator_in_use()
    from archivey.internal.streams.codecs.gzip_codec import _EMPTY_MEMBER_REACH

    name = b"n" * (_EMPTY_MEMBER_REACH + 100)
    blob = (
        _gzip_member(b"first member payload\n" * 4000)
        + _gzip_member(b"middle member payload\n" * 7)
        + _gzip_member(b"", name=name)
    )
    off = _outcome(Codec.GZIP, blob, _OFF, _no_seek)
    assert off[1] is None
    handovers = _handovers(monkeypatch)
    _assert_same(_outcome(Codec.GZIP, blob, _ON, _no_seek), off)
    assert handovers != []


# --- a seek that meets a data error is handed over -------------------------------------


@requires("rapidgzip")
def test_a_seek_in_a_nul_padded_gzip_reads_the_data() -> None:
    """``gzip -t`` and the standard library accept NUL padding after the last member;
    rapidgzip's seek used to raise on it."""
    payload = _payload()
    blob = gzip.compress(payload, mtime=0) + b"\0" * 1024
    for mode in (_OFF, _ON):
        with open_codec_stream(Codec.GZIP, io.BytesIO(blob), config=_config(mode)) as s:
            target = len(payload) - 5000
            assert s.seek(target) == target
            assert s.read() == payload[-5000:]
            assert s.seek(0) == 0
            assert s.read() == payload


@requires("rapidgzip")
@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB])
def test_a_seek_into_damage_gives_the_verdict_of_the_accelerator_off(
    codec: Codec,
) -> None:
    compress = gzip.compress if codec is Codec.GZIP else zlib.compress
    blob = compress(_payload())
    damaged = _flip(blob, len(blob) // 2)

    def seek_far(s: BinaryIO) -> None:
        s.seek(len(_payload()) - 100)

    off = _outcome(codec, damaged, _OFF, seek_far)
    assert off[1] is not None
    on = _outcome(codec, damaged, _ON, seek_far)
    assert on[1] is off[1]


# --- a second zlib stream is trailing data ---------------------------------------------


@functools.cache
def _two_zlib_streams() -> bytes:
    return zlib.compress(_payload()) + zlib.compress(b"second " * 1000)


def _read_one_then_all(s: BinaryIO) -> None:
    s.read(1)


def _end_and_back(s: BinaryIO) -> None:
    assert s.seek(0, io.SEEK_END) == len(_payload())
    s.seek(10)


def _past_the_first_stream(s: BinaryIO) -> None:
    target = len(_payload()) + 100
    assert s.seek(target) == target
    assert s.tell() == target


@requires("rapidgzip")
@pytest.mark.parametrize(
    "steps",
    [_no_seek, _read_one_then_all, _end_and_back, _past_the_first_stream],
    ids=["read", "read-one-then-all", "end-and-back", "past-the-first-stream"],
)
def test_a_second_zlib_stream_is_not_content(steps: Callable[[BinaryIO], None]) -> None:
    blob = _two_zlib_streams()
    off = _outcome(Codec.ZLIB, blob, _OFF, steps)
    assert off[1] is None
    _assert_same(_outcome(Codec.ZLIB, blob, _ON, steps), off)


@requires("rapidgzip")
def test_a_second_zlib_stream_is_reported_as_trailing_data(tmp_path) -> None:
    path = tmp_path / "two.zz"
    path.write_bytes(_two_zlib_streams())
    for mode in (_OFF, _ON):
        config = ArchiveyConfig(use_rapidgzip=mode)
        with open_archive(
            path, format=ArchiveFormat.ZLIB, config=config, seekable_members=True
        ) as reader:
            assert reader.read(reader.members()[0]) == _payload()
            assert reader.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


# --- a cut raw DEFLATE or gzip stream with a declared size -----------------------------

# The input the deflate_accel fuzz target found, without its four-byte size prefix: one
# non-final block of 168 bytes, and no final block. rapidgzip reads it as a whole stream.
_FUZZ_CUT_DEFLATE = base64.b64decode("4izJSE5WLMotKE1NUShIrMzJT0zhShx8ggA=")


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


@functools.cache
def _cut_streams() -> dict[str, tuple[Codec, bytes]]:
    deflate = _raw_deflate(_payload())
    whole_blocks = zlib.compressobj(6, zlib.DEFLATED, -15)
    return {
        "fuzz-input": (Codec.DEFLATE, _FUZZ_CUT_DEFLATE),
        "deflate-after-a-block": (
            Codec.DEFLATE,
            whole_blocks.compress(_payload()) + whole_blocks.flush(zlib.Z_FULL_FLUSH),
        ),
        "deflate-in-the-last-block": (Codec.DEFLATE, deflate[:-3]),
        "gzip-in-the-last-block": (
            Codec.GZIP,
            gzip.compress(_payload(), mtime=0)[:-20],
        ),
    }


def _output_before_the_cut(codec: Codec, blob: bytes) -> bytes:
    return zlib.decompressobj(-15 if codec is Codec.DEFLATE else 31).decompress(blob)


def _sized_outcome(
    codec: Codec, blob: bytes, mode: AcceleratorMode, size: int
) -> Outcome:
    config = StreamConfig(
        seekable=True, use_rapidgzip=mode, expected_decompressed_size=size
    )
    try:
        with open_codec_stream(codec, io.BytesIO(blob), config=config) as s:
            return s.read(), None
    except Exception as exc:  # noqa: BLE001 - compared below
        return b"", type(exc)


@requires("rapidgzip")
@pytest.mark.parametrize("case", sorted(_cut_streams()))
@pytest.mark.parametrize("declared", ["output-before-the-cut", "none"])
def test_a_cut_stream_rapidgzip_ends_quietly_raises(case: str, declared: str) -> None:
    codec, blob = _cut_streams()[case]
    if declared == "none":
        off = _outcome(codec, blob, _OFF, _no_seek)
        assert off[1] is TruncatedError
        _assert_same(_outcome(codec, blob, _ON, _no_seek), off)
        return
    size = len(_output_before_the_cut(codec, blob))
    assert _sized_outcome(codec, blob, _OFF, size)[1] is TruncatedError
    assert _sized_outcome(codec, blob, _ON, size)[1] is TruncatedError


@requires("rapidgzip")
@pytest.mark.parametrize("chunk", [-1, 1 << 16])
def test_an_intact_raw_deflate_stream_reads_whole(chunk: int) -> None:
    blob = _raw_deflate(_payload())
    config = StreamConfig(
        seekable=True, use_rapidgzip=_ON, expected_decompressed_size=len(_payload())
    )
    got = bytearray()
    with open_codec_stream(Codec.DEFLATE, io.BytesIO(blob), config=config) as s:
        while block := s.read(chunk):
            got += block
    assert got == _payload()


@requires("rapidgzip")
@pytest.mark.parametrize(
    "case", ["fuzz-input", "deflate-after-a-block", "deflate-in-the-last-block"]
)
def test_a_zip_member_cut_where_its_size_and_crc_end_raises(case: str) -> None:
    """The size and CRC-32 cover the output before the cut, so only the missing final
    block shows the member is cut; that is what a crafted member looks like."""
    _, blob = _cut_streams()[case]
    archive = _build_minimal_zip(
        b"a", blob, _output_before_the_cut(Codec.DEFLATE, blob), method=8
    )
    for mode in (_OFF, _ON):
        config = ArchiveyConfig(use_rapidgzip=mode)
        with (
            open_archive(io.BytesIO(archive), config=config) as reader,
            pytest.raises(TruncatedError),
        ):
            reader.read(reader.members()[0])
