"""archivey-codecs' public API on its own: no archivey import, so it also runs where
archivey is not installed."""

from __future__ import annotations

import io
import os
import random

import pytest

if os.environ.get("CODECS_REQUIRED") == "1":
    import archivey_codecs  # CI: a missing build must fail, not skip
else:
    archivey_codecs = pytest.importorskip("archivey_codecs")

from archivey_codecs import (
    KERNELS,
    CodecError,
    CorruptDataError,
    Crc16Arc,
    TruncatedDataError,
    UnsupportedDataError,
    bcj2,
    crc16_arc,
    filters,
    lzo1x,
    lzw,
    lzx,
    zipcrypto,
)

# ── Errors and revisions ───────────────────────────────────────────────────────────


def test_error_family() -> None:
    for cls in (CorruptDataError, TruncatedDataError, UnsupportedDataError):
        assert issubclass(cls, CodecError)
    assert issubclass(CodecError, ValueError)


def test_kernels_table() -> None:
    assert KERNELS == {
        "arm64": 1,
        "bcj2": 1,
        "crc16_arc": 1,
        "lzo1x": 1,
        "lzw": 1,
        "lzx": 1,
        "riscv": 1,
        "zipcrypto": 1,
    }


# ── CRC-16/ARC ─────────────────────────────────────────────────────────────────────


def test_crc16_check_value() -> None:
    # The CRC catalogue's check value.
    assert crc16_arc(b"123456789") == 0xBB3D


def test_crc16_hash_interface() -> None:
    a, b = b"hello ", b"world" * 50_000
    h = Crc16Arc()
    h.update(a)
    h.update(bytearray(b))
    assert h.digest() == Crc16Arc(a + b).digest()
    assert h.digest() == crc16_arc(a + b).to_bytes(2, "big")
    assert h.hexdigest() == h.digest().hex()
    assert (h.name, h.digest_size, h.block_size) == ("crc16_arc", 2, 1)
    copy = h.copy()
    copy.update(b"more")
    assert h.digest() == Crc16Arc(a + b).digest()
    assert crc16_arc(b, crc16_arc(a)) == crc16_arc(a + b)
    assert crc16_arc(memoryview(a)) == crc16_arc(a)


def test_crc16_value_out_of_range() -> None:
    for value in (0x10000, -1, 2**63, 2**64):
        with pytest.raises(ValueError, match="outside 0 to 0xFFFF"):
            crc16_arc(b"", value)


def test_crc16_reads_any_buffer() -> None:
    import array

    words = array.array("I", [1, 2])
    assert crc16_arc(words) == crc16_arc(words.tobytes())


# ── LZO1X ──────────────────────────────────────────────────────────────────────────

# An LZO1X block for b"abc": a 3-byte literal run, then the end marker.
_LZO_ABC = bytes([17 + 3]) + b"abc" + bytes([17, 0, 0])


def test_lzo_exact_size() -> None:
    assert lzo1x.decompress(_LZO_ABC, out_size=3) == b"abc"
    with pytest.raises(CorruptDataError, match="decodes to 3 bytes, not 4"):
        lzo1x.decompress(_LZO_ABC, out_size=4)
    with pytest.raises(CorruptDataError, match="more than 2 bytes"):
        lzo1x.decompress(_LZO_ABC, out_size=2)
    with pytest.raises(CorruptDataError, match="follow the end marker"):
        lzo1x.decompress(_LZO_ABC + b"x", out_size=3)


def test_lzo_max_size_is_a_bound() -> None:
    """SquashFS gives only the most a block may decode to: ``max_size=`` returns
    the block's bytes when they fit, and refuses one that decodes to more."""
    assert lzo1x.decompress(_LZO_ABC, max_size=3) == b"abc"
    assert lzo1x.decompress(_LZO_ABC, max_size=4096) == b"abc"
    with pytest.raises(CorruptDataError, match="more than 2 bytes"):
        lzo1x.decompress(_LZO_ABC, max_size=2)
    for kwargs in ({}, {"out_size": 3, "max_size": 3}):
        with pytest.raises(TypeError, match="exactly one of out_size= and max_size="):
            lzo1x.decompress(_LZO_ABC, **kwargs)


# ── Branch filters ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("make", [filters.Arm64Decoder, filters.RiscvDecoder])
def test_filter_holds_back_and_flushes(make: type) -> None:
    data = bytes(range(256)) * 40
    whole = make(100)
    expected = whole.decode(data) + whole.flush()
    assert len(expected) == len(data)
    d = make(100)
    out = d.decode(data[:6])
    assert len(out) <= 6
    out += d.decode(data[6:]) + d.flush()
    assert out == expected
    assert (d.total_in, d.total_out) == (len(data), len(data))


def test_arm64_holds_cut_word() -> None:
    d = filters.Arm64Decoder()
    assert len(d.decode(b"\0" * 6)) == 4
    assert d.flush() == b"\0\0"


@pytest.mark.parametrize("make", [filters.Arm64Decoder, filters.RiscvDecoder])
def test_filter_state_resume(make: type) -> None:
    data = bytes((i * 37) & 0xFF for i in range(20_000))
    straight = make(4)
    expected = straight.decode(data) + straight.flush()
    for cut in (0, 1, 3, 4, 4097, 19_999):
        d = make(4)
        first = d.decode(data[:cut])
        resumed = make.from_state(d.getstate())
        assert (resumed.total_in, resumed.total_out) == (d.total_in, d.total_out)
        rest = resumed.decode(data[resumed.total_in :]) + resumed.flush()
        assert first + rest == expected, cut
        copy = d.copy()
        assert copy.decode(data[cut:]) == d.decode(data[cut:])


def test_state_from_another_kernel_is_refused() -> None:
    state = filters.Arm64Decoder().getstate()
    with pytest.raises(UnsupportedDataError, match="arm64 revision 1, not riscv"):
        filters.RiscvDecoder.from_state(state)
    with pytest.raises(UnsupportedDataError):
        zipcrypto.Decryptor.from_state(state)


@pytest.mark.parametrize("cut", [0, 1, 5, 20])
def test_cut_state_is_corrupt(cut: int) -> None:
    state = filters.RiscvDecoder(8).getstate()
    with pytest.raises(CorruptDataError, match="cut off"):
        filters.RiscvDecoder.from_state(state[:cut])


def test_damaged_state_is_corrupt() -> None:
    state = bytearray(filters.Arm64Decoder().getstate())
    state[-1] = 200  # claims 200 held-back bytes
    with pytest.raises(CorruptDataError, match="holds back 200 bytes"):
        filters.Arm64Decoder.from_state(bytes(state))
    with pytest.raises(CorruptDataError, match="follow"):
        filters.Arm64Decoder.from_state(filters.Arm64Decoder().getstate() + b"x")


# ── ZipCrypto ──────────────────────────────────────────────────────────────────────


def test_zipcrypto_state() -> None:
    data = bytes(range(256)) * 10
    straight = zipcrypto.Decryptor(b"secret").decrypt(data)
    d = zipcrypto.Decryptor(bytearray(b"secret"))
    first = d.decrypt(data[:1000])
    assert len(first) == 1000
    state = d.getstate()
    assert state.endswith((1000).to_bytes(8, "little"))
    resumed = zipcrypto.Decryptor.from_state(state)
    assert resumed.total_in == 1000
    assert first + resumed.decrypt(data[1000:]) == straight
    assert d.copy().decrypt(data[1000:]) == straight[1000:]


# ── Unix compress ──────────────────────────────────────────────────────────────────

# ``compress`` of b"ab" (block mode, 16-bit): the header, then codes 97 and 98 in
# 9 bits each, zero-padded to a byte.
_Z_AB = bytes([0x1F, 0x9D, 0x90, 0x61, 0xC4, 0x00])


def test_lzw_decompress_and_flush() -> None:
    d = lzw.Decompressor()
    assert d.decompress(_Z_AB) + d.flush() == b"ab"
    assert d.eof
    assert d.truncation is None
    assert d.header_params == (16, True)
    assert d.unused_data == b""
    assert (d.total_in, d.total_out) == (len(_Z_AB), 2)
    with pytest.raises(EOFError):
        d.decompress(b"")


def test_lzw_output_cap() -> None:
    d = lzw.Decompressor()
    out = d.decompress(_Z_AB, 1)
    assert len(out) <= 1
    while not d.eof:
        out += d.flush(1) if d.needs_input else d.decompress(b"", 1)
    assert out == b"ab"


def test_lzw_empty_decompress_only_drains() -> None:
    d = lzw.Decompressor()
    d.decompress(_Z_AB[:4])
    d.decompress(b"")
    assert not d.eof


def test_lzw_max_width_needs_block_mode() -> None:
    with pytest.raises(ValueError, match="give block_mode with max_width"):
        lzw.Decompressor(max_width=16)


def test_lzw_copy_is_independent() -> None:
    d = lzw.Decompressor()
    d.decompress(_Z_AB[:4])
    copy = d.copy()
    assert (
        copy.decompress(_Z_AB[4:]) + copy.flush() == d.decompress(_Z_AB[4:]) + d.flush()
    )


# ── LZX ────────────────────────────────────────────────────────────────────────────

# "hello world, hello lzx!" as one uncompressed LZX block, window 2**15.
_LZX_HELLO = bytes.fromhex(
    "0030700101000000010000000100000068656c6c6f20776f726c642c2068656c6c6f206c7a782100"
)
_HELLO = b"hello world, hello lzx!"
# A block of type 7, which LZX does not have.
_LZX_BAD = bytes.fromhex("007000000000")


def test_lzx_one_call() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.decompress(_LZX_HELLO + b"tail") == _HELLO
    assert d.eof
    assert not d.needs_input
    assert d.unused_data.endswith(b"tail")
    assert d.total_out == len(_HELLO)
    with pytest.raises(EOFError):
        d.decompress(b"x")


def test_lzx_byte_at_a_time_waits_for_the_frame() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.needs_input
    out = b""
    for i in range(len(_LZX_HELLO)):
        out += d.decompress(_LZX_HELLO[i : i + 1])
        if i < len(_LZX_HELLO) - 2:
            assert out == b""
            assert d.needs_input
    assert out + d.flush() == _HELLO
    assert d.eof


def test_lzx_max_length_slices_the_frame() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.decompress(_LZX_HELLO, 5) == b"hello"
    assert not d.needs_input
    assert d.decompress(b"", 7) == b" world,"
    assert d.decompress(b"") == b" hello lzx!"
    assert d.eof


def test_lzx_output_size_given_late() -> None:
    d = lzx.Decompressor(15)
    assert d.decompress(_LZX_HELLO) == b""
    assert d.needs_input
    d.set_output_size(len(_HELLO))
    assert d.output_size == len(_HELLO)
    assert d.decompress(b"") == _HELLO
    assert d.eof
    with pytest.raises(ValueError, match="below"):
        d.set_output_size(3)


def test_lzx_without_output_size() -> None:
    # Every frame is 32 KiB, so a shorter stream runs into the zero padding after it
    # (read as a block of type 0), as in the Python decoder...
    d = lzx.Decompressor(15)
    d.decompress(_LZX_HELLO)
    with pytest.raises(CodecError):
        d.flush()
    # ...and no input at all is an empty stream.
    d = lzx.Decompressor(15)
    assert d.flush() == b""
    assert d.eof


def test_lzx_cut_stream() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.decompress(_LZX_HELLO[:-10]) == b""
    with pytest.raises(archivey_codecs.TruncatedDataError):
        d.flush()


def test_lzx_damage_raises_again() -> None:
    d = lzx.Decompressor(15, output_size=100)
    for _ in range(2):
        with pytest.raises(archivey_codecs.CorruptDataError, match="block type 7"):
            d.decompress(_LZX_BAD)


def test_lzx_error_in_says_how_far_the_failed_frame_read() -> None:
    """The bad block header is in the first word after the 1-bit E8 flag: the frame
    fails having read two words, and padding past the input does not count."""
    d = lzx.Decompressor(15, output_size=100)
    assert d.error_in is None
    with pytest.raises(archivey_codecs.CorruptDataError):
        d.decompress(_LZX_BAD + bytes(100_000))
    assert d.error_in is not None
    assert 2 <= d.error_in <= 8
    assert d.total_in == 0  # the failed frame is undone


def test_lzx_window_range() -> None:
    with pytest.raises(archivey_codecs.CorruptDataError, match="window"):
        lzx.Decompressor(14)


def test_lzx_reset_and_copy() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.decompress(_LZX_HELLO, 5) == b"hello"
    c = d.copy()
    assert d.decompress(b"") == _HELLO[5:]
    assert c.decompress(b"") == _HELLO[5:]
    d.reset(len(_HELLO))
    assert (d.total_in, d.total_out, d.eof) == (0, 0, False)
    assert d.decompress(_LZX_HELLO) == _HELLO


def test_lzx_state_resumes_from_total_in() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    start = lzx.Decompressor.from_state(d.getstate())
    assert start.decompress(_LZX_HELLO) == _HELLO
    assert d.decompress(_LZX_HELLO, 5) == b"hello"
    state, total_in = d.getstate(), d.total_in
    r = lzx.Decompressor.from_state(state)
    assert (r.total_in, r.total_out, r.window_bits) == (total_in, 5, 15)
    assert r.decompress(_LZX_HELLO[total_in:]) == _HELLO[5:]
    assert r.eof


def test_lzx_state_refusals() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    state = d.getstate()
    with pytest.raises(archivey_codecs.CorruptDataError, match="cut off"):
        lzx.Decompressor.from_state(state[:-1])
    with pytest.raises(archivey_codecs.CorruptDataError, match="follow"):
        lzx.Decompressor.from_state(state + b"\0")
    bad = bytearray(state)
    bad[1 + len("lzx") + 4] = 22  # the window bits
    with pytest.raises(archivey_codecs.CorruptDataError, match="window"):
        lzx.Decompressor.from_state(bytes(bad))
    other = archivey_codecs.zipcrypto.Decryptor(b"pw").getstate()
    with pytest.raises(archivey_codecs.UnsupportedDataError):
        lzx.Decompressor.from_state(other)
    with pytest.raises(CodecError):
        d.flush()


def test_lzx_one_call_unused_data_is_exact() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    assert d.decompress(_LZX_HELLO + b"tail") == _HELLO
    assert d.unused_data == b"tail"
    assert d.total_in == len(_LZX_HELLO)


def test_lzx_state_after_a_capped_flush() -> None:
    """A state saved after ``flush(1)`` resumes with the rest. The restored decoder
    is one before ``flush()``: it takes the input from ``total_in``, then flushes."""
    for at in range(len(_HELLO)):
        d = lzx.Decompressor(15, output_size=len(_HELLO))
        assert d.decompress(_LZX_HELLO, 0) == b""
        out = d.flush(1)
        while len(out) < at:
            out += d.flush(1)
        r = lzx.Decompressor.from_state(d.getstate())
        assert (r.total_out, r.total_in) == (d.total_out, d.total_in)
        out += r.decompress(_LZX_HELLO[r.total_in :] + b"tail", 1)
        while not r.eof:
            out += r.flush(1)
        assert out == _HELLO, at
        assert r.unused_data == b"tail"
        assert d.flush() == _HELLO[max(at, 1) :]


def test_lzx_state_after_a_failed_flush_raises_again() -> None:
    d = lzx.Decompressor(15, output_size=len(_HELLO))
    d.decompress(_LZX_HELLO[:-10])
    with pytest.raises(archivey_codecs.TruncatedDataError):
        d.flush()
    r = lzx.Decompressor.from_state(d.getstate())
    r.decompress(_LZX_HELLO[r.total_in : -10])
    with pytest.raises(archivey_codecs.TruncatedDataError):
        r.flush()


def test_lzw_flush_keeps_its_cap(tmp_path) -> None:
    """``flush(max_length)`` decodes at most about ``max_length`` bytes a call: a
    49 KB stream of 400 MB of zeros must not be decoded at once. Run in a fresh
    process, so its resident memory says what the decoder holds (Linux only: it reads
    ``/proc/self/statm``)."""
    import subprocess
    import sys

    if not sys.platform.startswith("linux"):
        pytest.skip("reads /proc/self/statm")
    ncompress = pytest.importorskip("ncompress")
    z = ncompress.compress(bytes(400_000_000))
    path = tmp_path / "zeros.Z"
    path.write_bytes(z)
    del z
    probe = (
        "import sys\n"
        "from archivey_codecs import lzw\n"
        "z = open(sys.argv[1], 'rb').read()\n"
        "rss = lambda: int(open('/proc/self/statm').read().split()[1]) * 4096\n"
        "before = rss()\n"
        "d = lzw.Decompressor()\n"
        "assert len(d.decompress(z, 1)) == 1\n"
        "for _ in range(100):\n"
        "    assert len(d.flush(65536)) == 65536\n"
        "print((rss() - before) >> 20)\n"
    )
    got = subprocess.run(
        [sys.executable, "-c", probe, str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert int(got.stdout) < 50, f"flush grew the process by {got.stdout.strip()} MB"


def test_filter_state_hold_bounds() -> None:
    # A RISC-V decoder holds at most 7 bytes and an ARM64 one at most 3.
    for cls, most in ((filters.RiscvDecoder, 7), (filters.Arm64Decoder, 3)):
        state = cls().getstate()
        assert state[-1] == 0
        ok = state[:-1] + bytes([most]) + bytes(most)
        assert cls.from_state(ok).flush() == bytes(most)
        bad = state[:-1] + bytes([most + 1]) + bytes(most + 1)
        with pytest.raises(CorruptDataError, match="holds back"):
            cls.from_state(bad)


def test_filter_offset_wraps() -> None:
    d = filters.Arm64Decoder(start_offset=2**64 - 4)
    assert len(d.decode(bytes(64))) == 64


def test_lzw_error_on_new_input_keeps_counts() -> None:
    """A call that fails on its new input still counts that input: ``total_in``
    stays within what was passed in."""
    d = lzw.Decompressor()
    with pytest.raises(CorruptDataError, match="invalid code"):
        d.decompress(b"\x1f\x9d\x90\xff\xff\xff")
    assert d.total_in <= 6


def test_lzw_error_on_new_input_returns_held_output_first() -> None:
    """Output decoded before a bad code comes out before the error, also when a cap
    left part of an entry held: capped calls give what one uncapped call gives."""
    ncompress = pytest.importorskip("ncompress")
    rng = random.Random(3)
    raw = bytes(rng.choice(b"ab") for _ in range(20_000))
    buf = io.BytesIO()
    ncompress.compress(io.BytesIO(raw), buf)
    z = buf.getvalue()
    garbage = b"\xff\xff\xff\xff"

    for cut in range(8, 120):
        # One uncapped call holds nothing back: the reference.
        whole = lzw.Decompressor()
        expected = bytearray(whole.decompress(z[:cut]))
        try:
            expected += whole.decompress(garbage)
            for _ in range(4):
                expected += whole.decompress(b"")
        except CorruptDataError:
            pass
        else:
            raise AssertionError(cut)
        d = lzw.Decompressor()
        got = bytearray(d.decompress(z[:cut], 1))
        try:
            while d.total_in < cut and not d.needs_input:
                got += d.decompress(b"", 1)
            got += d.decompress(garbage, 1)
            for _ in range(100_000):
                got += d.decompress(b"", 1)
        except CorruptDataError:
            pass
        else:
            raise AssertionError(cut)
        assert got == expected, cut


# ── Saved states: refusals ─────────────────────────────────────────────────────────


def _patched(state: bytes, at: int, value: bytes) -> bytes:
    return state[:at] + value + state[at + len(value) :]


def _u32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def _u64(v: int) -> bytes:
    return v.to_bytes(8, "little")


# BCJ2 streams with no branch candidate: the output is ``main``, and the range coder
# reads only its 5 start bytes.
_BCJ2_MAIN = bytes(range(0x10, 0x70)) * 3000  # 288,000 bytes, no E8, E9 or 0F 8x
_BCJ2_RC = b"\0" * 5


def _bcj2(main: bytes = _BCJ2_MAIN, rc: bytes = _BCJ2_RC) -> bcj2.Decompressor:
    return bcj2.Decompressor(
        io.BytesIO(main), io.BytesIO(), io.BytesIO(), io.BytesIO(rc), out_size=len(main)
    )


def _bcj2_restore(state: bytes, at: tuple[int, ...] = (0, 0, 0, 0)):
    streams = [io.BytesIO(s) for s in (_BCJ2_MAIN, b"", b"", _BCJ2_RC)]
    for f, pos in zip(streams, at, strict=True):
        f.seek(pos)
    return bcj2.Decompressor.from_state(state, *streams)


# The BCJ2 state: header (9 bytes), 258 probabilities, prev, range, code (flag and
# value), out_pos; then out_size, checked, the pending output, total_in x 4.
_P0 = 9
_RANGE = _P0 + 516 + 1
_CODE = _RANGE + 4 + 1
_OUT_POS = _CODE + 4
_OUT_SIZE = _OUT_POS + 8
_CHECKED = _OUT_SIZE + 8
_PENDING = _CHECKED + 1


def test_bcj2_state_refusals() -> None:
    d = _bcj2()
    d.read(1000)
    state = d.getstate()
    assert state[_CODE - 1] == 1  # the range coder has started
    cases = [
        # Bcj2::load's probability check.
        (_patched(state, _P0, b"\0\0"), "a probability of 0"),
        (_patched(state, _P0 + 2, (2048).to_bytes(2, "little")), "probability of 2048"),
        # Bcj2::load's code < range check.
        (_patched(state, _CODE, state[_RANGE : _RANGE + 4]), "not below its range"),
        # from_state's size checks: decoded past out_size, pending past decoded, and
        # the end check passed before the end.
        (_patched(state, _OUT_SIZE, _u64(10)), "sizes that do not agree"),
        (_patched(state, _OUT_POS, _u64(10)), "sizes that do not agree"),
        (_patched(state, _CHECKED, b"\x01"), "sizes that do not agree"),
        # The pending cap: no read leaves more than one block's output.
        (_patched(state, _PENDING, _u32(5 * 65536 + 1)), "more than 327680"),
        (state[:-1], "cut off"),
        (state + b"\0", "follow"),
    ]
    for bad, message in cases:
        with pytest.raises(CorruptDataError, match=message):
            _bcj2_restore(bad)
    other = zipcrypto.Decryptor(b"pw").getstate()
    with pytest.raises(UnsupportedDataError):
        _bcj2_restore(other)


def test_bcj2_getstate_refused_after_an_error() -> None:
    # A main stream one byte short: the bytes before the error come first.
    d = bcj2.Decompressor(
        io.BytesIO(b"abc"), io.BytesIO(), io.BytesIO(), io.BytesIO(_BCJ2_RC), out_size=4
    )
    assert d.read() == b"abc"
    with pytest.raises(ValueError, match="after an error"):
        d.getstate()
    with pytest.raises(TruncatedDataError, match="main stream ended early"):
        d.read()


def test_bcj2_stream_returning_too_much_is_refused() -> None:
    class Greedy(io.BytesIO):
        def read(self, n: int | None = -1, /) -> bytes:
            return b"x" * (n + 1)

    d = bcj2.Decompressor(
        Greedy(b"abc"), io.BytesIO(), io.BytesIO(), io.BytesIO(_BCJ2_RC), out_size=3
    )
    with pytest.raises(ValueError, match=r"read\(65536\) returned"):
        d.read()


def test_bcj2_total_in_is_a_tuple() -> None:
    d = _bcj2()
    d.read(10)
    assert type(d.total_in) is tuple
    assert len({d.total_in: None}) == 1  # hashable, so it can key a seek index


def test_bcj2_exact_read_runs_the_end_check() -> None:
    """The read that returns the last byte runs the end check: ``eof`` is true after
    it, and surplus bytes in ``main`` raise on the next call."""
    d = _bcj2(b"abc")
    assert d.read(3) == b"abc"
    assert d.eof
    assert d.read() == b""
    d = bcj2.Decompressor(
        io.BytesIO(b"abcd"),
        io.BytesIO(),
        io.BytesIO(),
        io.BytesIO(_BCJ2_RC),
        out_size=3,
    )
    assert d.read(3) == b"abc"
    assert not d.eof
    with pytest.raises(CorruptDataError, match="main stream has bytes past the end"):
        d.read()


def test_bcj2_restored_twice_reads_independently() -> None:
    """Two decoders restored from one state, each on its own streams, read interleaved
    past their buffers, both give the straight decode."""
    d = _bcj2()
    head = d.read(1000)
    state, at = d.getstate(), d.total_in
    a, b = _bcj2_restore(state, at), _bcj2_restore(state, at)
    out_a, out_b = bytearray(head), bytearray(head)
    while not (a.eof and b.eof):
        out_a += a.read(70_000)
        out_b += b.read(30_000)
    assert out_a == out_b == _BCJ2_MAIN
    assert not hasattr(bcj2.Decompressor, "copy")


# The LZW state after ``_Z_AB`` without its flush: header (8 bytes), finished, the
# truncation flag (no message), nine-bit setting, at-fill, need-header, four segment and
# skip counters, the skip reason, the maximum width and block mode, the dictionary size
# and next code, one entry (prefix, suffix), the code reader; then the held output,
# header-in-stream, the CLEAR offsets, total_in and total_out.
_NINE_BIT = 10
_PENDING_SKIP = 13 + 16
_REASON = 13 + 32
_WIDTH = _REASON + 1
_DICT_LEN = _WIDTH + 2
_ENTRY = _DICT_LEN + 8
_BITS = _ENTRY + 5 + 8


def _lzw_state() -> bytes:
    d = lzw.Decompressor()
    assert d.decompress(_Z_AB) == b"ab"
    return d.getstate()


def test_lzw_state_refusals() -> None:
    state = _lzw_state()
    tail = len(state) - 33  # the five fields after the held output
    assert state[tail - 4 : tail] == _u32(0)  # nothing held
    dict_len = int.from_bytes(state[_DICT_LEN : _DICT_LEN + 4], "little")
    assert dict_len == 258  # one entry, 257
    cases = [
        (_patched(state, _NINE_BIT, b"\x03"), "a nine-bit setting of 3"),
        (_patched(state, _PENDING_SKIP, _u64(17)), "a segment or skip out of range"),
        (_patched(state, _REASON, b"\x02"), "a skip reason of 2"),
        (_patched(state, _WIDTH, b"\x11"), "a maximum code width of 17"),
        (_patched(state, _DICT_LEN, _u32(dict_len + 5)), "a dictionary size"),
        (_patched(state, _ENTRY, _u32(300)), "points forward"),
        (_patched(state, _BITS, b"\xff"), "a code reader out of range"),
        # The held-output cap.
        (_patched(state, tail - 4, _u32((1 << 16) + 1)), "more than 65536"),
        # The CLEAR offsets must lie within the input and output so far, without
        # overflow.
        (_patched(state, tail + 1, _u64(1 << 40)), "offsets that do not agree"),
        (_patched(state, tail + 9, _u64(1 << 40)), "offsets that do not agree"),
        (state[:-1], "cut off"),
        (state + b"\0", "follow"),
    ]
    for bad, message in cases:
        with pytest.raises(CorruptDataError, match=message):
            lzw.Decompressor.from_state(bad)
    with pytest.raises(UnsupportedDataError):
        lzw.Decompressor.from_state(zipcrypto.Decryptor(b"pw").getstate())


def test_lzw_held_output_offset_check_does_not_overflow() -> None:
    """``total_out`` plus the held output is compared without overflow: a state whose
    ``total_out`` is near 2**64 is refused, not wrapped (or a panic in debug)."""
    ncompress = pytest.importorskip("ncompress")
    raw = b"a" * 5000
    z = ncompress.compress(raw)
    d = lzw.Decompressor()
    d.decompress(z, 3)
    for _ in range(40):
        d.decompress(b"", 3)
        state, done = d.getstate(), d.total_out
        tail = len(state) - 33
        held = [
            n
            for n in range(1, 200)
            if state[tail - n - 4 : tail - n] == _u32(n)
            and state[tail - n : tail] == raw[done : done + n]
        ]
        if held:
            break
    else:
        pytest.fail("no state held output")
    bad = _patched(state, len(state) - 8, _u64(2**64 - 1))  # total_out
    # A wrapped sum would let any CLEAR output offset pass: 0 tests the overflow alone.
    bad = _patched(bad, tail + 9, _u64(0))
    with pytest.raises(CorruptDataError, match="offsets that do not agree"):
        lzw.Decompressor.from_state(bad)


def test_lzw_state_after_a_capped_flush() -> None:
    """A state saved during ``flush(1)`` resumes: the restored decoder is one before
    ``flush()``, so it takes the input from ``total_in``, then flushes."""
    for restore_after in range(3):
        d = lzw.Decompressor()
        assert d.decompress(_Z_AB, 0) == b""
        out = b""
        for _ in range(restore_after):
            out += d.flush(1)
        if restore_after:
            r = lzw.Decompressor.from_state(d.getstate())
            assert (r.total_in, r.total_out) == (d.total_in, d.total_out)
            assert not r.eof
            r.decompress(_Z_AB[r.total_in :], 0)
            d = r
        while not d.eof:
            out += d.flush(1)
        assert out == b"ab", restore_after
        assert d.truncation is None


def test_lzw_state_after_the_final_pass_keeps_truncation() -> None:
    cut = _Z_AB[:-1]  # the second code loses its last bit
    straight = lzw.Decompressor()
    want = straight.decompress(cut) + straight.flush()
    assert straight.truncation is not None
    d = lzw.Decompressor()
    d.decompress(cut, 0)
    out = d.flush(1)
    r = lzw.Decompressor.from_state(d.getstate())
    r.decompress(cut[r.total_in :], 0)
    while not r.eof:
        out += r.flush(1)
    assert out == want
    assert r.truncation == straight.truncation


def test_lzw_state_after_a_final_pass_on_a_partial_header() -> None:
    """A two-byte prefix of the header: restored after the final pass and given the
    input again, the decoder ends with the original's ``total_in`` and truncation."""
    straight = lzw.Decompressor()
    straight.decompress(_Z_AB[:2])
    assert straight.flush() == b""
    d = lzw.Decompressor()
    d.decompress(_Z_AB[:2])
    d.flush(1)
    r = lzw.Decompressor.from_state(d.getstate())
    r.decompress(_Z_AB[r.total_in : 2])
    assert r.flush() == b""
    assert r.eof
    assert (r.total_in, r.truncation) == (straight.total_in, straight.truncation)


def test_lzw_getstate_refused_after_an_error() -> None:
    d = lzw.Decompressor()
    with pytest.raises(CorruptDataError):
        d.decompress(b"\x1f\x9d\x90\xff\xff\xff")
    with pytest.raises(ValueError, match="after an error"):
        d.getstate()


def test_lzw_new_input_waits_while_output_is_owed() -> None:
    """While a cap leaves decoded output owed, new input is queued, not decoded: the
    held output stays within one dictionary entry however many capped calls bring
    more input."""
    ncompress = pytest.importorskip("ncompress")
    z = ncompress.compress(bytes(10_000_000))  # zeros: entries 1, 2, 3, ... bytes long
    d = lzw.Decompressor()
    out = bytearray(d.decompress(z[:8], 1))
    calls = 3000
    for i in range(8, 8 + calls):
        out += d.decompress(z[i : i + 1], 1)
    assert out == bytes(len(out))
    # Emitting ~3000 bytes takes ~80 entries of growing length, about 100 bytes of
    # input; decoding one entry per call would have used nearly all 3000.
    assert d.total_in < 400, d.total_in
    out += d.decompress(z[8 + calls :]) + d.flush()
    assert out == bytes(10_000_000)


def test_mutable_inputs_are_copied() -> None:
    """A ``bytearray``, a ``memoryview`` of one (also a slice) and an ``array`` give
    the same result as ``bytes``: each is copied, a ``bytearray`` under its lock."""
    import array

    data = bytes(range(256)) * 4
    want = crc16_arc(data)
    ba = bytearray(data)
    words = array.array("I", data)
    assert crc16_arc(ba) == want
    assert crc16_arc(memoryview(ba)) == want
    assert crc16_arc(memoryview(bytearray(b"x" + data))[1:]) == want
    assert crc16_arc(words) == want
