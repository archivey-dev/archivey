"""Differential tests: every Rust kernel against its Python twin, through one API.

archivey's Python twins (:mod:`archivey.internal.kernels.python`) have the package's
API, so each test drives ``PYTHON`` and ``RUST`` with the same code: same input, same
output bytes; on damage, the same error kind and the same message. The state methods
(``getstate``, ``from_state``, ``copy``), ``unused_data`` and LZX's ``total_in`` are
the package's only, and are exercised on its side alone. Run from the archivey
checkout with archivey-codecs installed: ``uv run pytest packages/archivey-codecs/tests``.
"""

from __future__ import annotations

import gc
import io
import os
import random
import struct
import sys
import types
import weakref
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

if os.environ.get("CODECS_REQUIRED") == "1":
    import archivey_codecs  # CI: a missing build must fail, not skip
else:
    archivey_codecs = pytest.importorskip("archivey_codecs")

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
    raw_message_of,
)
from archivey.internal.kernels import python as twins
from archivey.internal.kernels.python import (
    bcj2 as bcj2_twin,
    filters as filters_twin,
    lzfse as lzfse_twin,
    lzo1x as lzo1x_twin,
    lzvn as lzvn_twin,
    lzw as lzw_twin,
    lzx as lzx_twin,
    zipcrypto as zipcrypto_twin,
)
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder

SEEDS = int(os.environ.get("CODECS_PARITY_CASES", "300"))
# The DMG plan's A0 fuzz run had 200,000 cases; the default replays its first ones.
LZFSE_FUZZ_CASES = int(os.environ.get("CODECS_LZFSE_FUZZ_CASES", str(SEEDS * 20)))

# The two sides, each with the ``archivey_codecs`` API.
PYTHON = types.SimpleNamespace(
    crc16_arc=twins.crc16_arc,
    zipcrypto=zipcrypto_twin,
    filters=filters_twin,
    lzo1x=lzo1x_twin,
    lzw=lzw_twin,
    lzx=lzx_twin,
    bcj2=bcj2_twin,
    lzfse=lzfse_twin,
    lzvn=lzvn_twin,
)
RUST = archivey_codecs
BOTH = pytest.mark.parametrize("codecs", [PYTHON, RUST], ids=["python", "rust"])


def has_state(codecs: object) -> bool:
    """Whether ``codecs`` is the package, whose objects save and restore their state."""
    return codecs is RUST


def outcome(fn: Callable[[], object]) -> tuple[str, object]:
    """What ``fn`` returned, or the kind and message of what it raised."""
    try:
        return ("ok", fn())
    # raw_message_of: the text as the decoder wrote it, before archivey's exceptions
    # escape it (a backslash in an LZFSE block magic's repr, for one).
    except (TruncatedError, archivey_codecs.TruncatedDataError) as exc:
        return ("truncated", raw_message_of(exc))
    except (CorruptionError, archivey_codecs.CorruptDataError) as exc:
        return ("corrupt", raw_message_of(exc))
    except (UnsupportedFeatureError, archivey_codecs.UnsupportedDataError) as exc:
        return ("unsupported", raw_message_of(exc))
    except (IndexError, ValueError, EOFError) as exc:
        return (type(exc).__name__, str(exc))


def sample_data(rng: random.Random, size: int) -> bytes:
    """Compressible bytes: runs, repeats and some noise."""
    words = [rng.randbytes(rng.randint(1, 12)) for _ in range(40)]
    out = bytearray()
    while len(out) < size:
        pick = rng.random()
        if pick < 0.6:
            out += rng.choice(words)
        elif pick < 0.8:
            out += bytes([rng.randrange(256)]) * rng.randint(1, 300)
        else:
            out += rng.randbytes(rng.randint(1, 64))
    return bytes(out[:size])


def damage(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return data
    buf = bytearray(data)
    kind = rng.random()
    if kind < 0.4:
        for _ in range(rng.randint(1, 4)):
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
    elif kind < 0.7:
        del buf[rng.randrange(len(buf)) :]
    else:
        at = rng.randrange(len(buf))
        buf[at:at] = rng.randbytes(rng.randint(1, 8))
    return bytes(buf)


# ── LZO1X ──────────────────────────────────────────────────────────────────────────


def _lzo_compressor() -> Callable[[bytes, int], bytes]:
    """An LZO1X compressor: python-lzo, else compress-utils when its build can
    compress LZO1X (0.12.1's wheels decode it only); the test skips without either."""
    try:
        import lzo

        return lambda data, level: lzo.compress(data, level, False)
    except ImportError:
        pass
    try:
        import compress_utils

        compress_utils.compress(b"probe", "lzo", 1)
    except Exception:  # noqa: BLE001 - not installed, or built without LZO1X
        pytest.skip("no LZO1X compressor: install python-lzo")
    return lambda data, level: compress_utils.compress(data, "lzo", level)


def test_lzo_parity() -> None:
    compress = _lzo_compressor()
    rng = random.Random(1)
    for case in range(SEEDS):
        data = sample_data(rng, rng.randint(0, 200_000))
        block = compress(data, rng.choice((1, 9)))
        if case % 2:
            block = damage(rng, block)
        limit = rng.choice((len(data), len(data) // 2 + 1, 1 << 20))
        for size in ("out_size", "max_size"):
            got = lzo(PYTHON, block, size, limit)
            assert got == lzo(RUST, block, size, limit), (case, size)
    for case in range(SEEDS):
        block = rng.randbytes(rng.randint(0, 64))
        for size in ("out_size", "max_size"):
            got = lzo(PYTHON, block, size, 4096)
            assert got == lzo(RUST, block, size, 4096), (case, size)


def lzo(codecs: object, block: bytes, size: str, limit: int) -> tuple[str, object]:
    """``lzo1x.decompress`` with ``out_size`` (exactly ``limit`` bytes) or
    ``max_size`` (at most ``limit``)."""
    return outcome(lambda: codecs.lzo1x.decompress(block, **{size: limit}))


@BOTH
def test_lzo_takes_one_size(codecs: object) -> None:
    for sizes in ({}, {"out_size": 1, "max_size": 1}):
        with pytest.raises(TypeError):
            codecs.lzo1x.decompress(b"\x11\0\0", **sizes)


# ── Branch filters ─────────────────────────────────────────────────────────────────


def filter_input(rng: random.Random, size: int, hot: bytes) -> bytes:
    """Random bytes thick with the bytes that start a converted instruction."""
    return bytes(
        rng.choice(hot) if rng.random() < 0.3 else rng.randrange(256)
        for _ in range(size)
    )


def filter_chunks(data: bytes, rng: random.Random) -> list[bytes]:
    cuts = sorted(rng.randrange(len(data) + 1) for _ in range(rng.randint(0, 6)))
    return [data[a:b] for a, b in zip([0, *cuts], [*cuts, len(data)], strict=True)]


def filter_run(make: Callable, chunks: list[bytes], pc: int) -> list:
    """Each call's output: one ``decode()`` per chunk, then ``flush()``."""
    decoder = make(pc)
    out = []
    fed = 0
    for chunk in chunks:
        out.append(decoder.decode(chunk))
        fed += len(chunk)
        assert decoder.total_in == fed
    out.append(decoder.flush())
    assert decoder.total_out == fed
    return out


def test_arm64_parity() -> None:
    rng = random.Random(2)
    hot = bytes([0x94, 0x95, 0x96, 0x97, 0x90, 0xB0, 0xD0, 0xF0])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 4 * rng.randrange(1 << 20), (1 << 32) - 4, 1 << 40))
        chunks = filter_chunks(data, rng)
        assert filter_run(PYTHON.filters.Arm64Decoder, chunks, pc) == filter_run(
            RUST.filters.Arm64Decoder, chunks, pc
        )


def test_riscv_parity() -> None:
    rng = random.Random(3)
    hot = bytes([0xEF, 0x17, 0x97, 0x13, 0x67])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 2 * rng.randrange(1 << 20), (1 << 32) - 2))
        chunks = filter_chunks(data, rng)
        assert filter_run(PYTHON.filters.RiscvDecoder, chunks, pc) == filter_run(
            RUST.filters.RiscvDecoder, chunks, pc
        )


# ── CRC-16 ─────────────────────────────────────────────────────────────────────────


def _views(data: bytes) -> list[tuple[str, memoryview, bytes]]:
    """Views the package takes, and the bytes each holds: one of 4-byte items, one
    with a stride, one with both, and one of signed bytes with a stride."""
    doubled = bytes(b for pair in zip(data, data[::-1], strict=True) for b in pair)
    words = [data[i : i + 4] for i in range(0, len(data), 4)]
    interleaved = b"".join(w + w[::-1] for w in words)
    return [
        ("wide", memoryview(data).cast("I"), data),
        ("strided", memoryview(doubled)[::2], data),
        ("wide-strided", memoryview(interleaved).cast("I")[::2], data),
        ("signed-strided", memoryview(doubled).cast("b")[::2], data),
    ]


@BOTH
@pytest.mark.parametrize("kind", ["wide", "strided", "wide-strided", "signed-strided"])
def test_a_view_is_read_as_its_bytes(codecs: object, kind: str) -> None:
    """Every kernel takes a view as its bytes, never its items: a view of 4-byte
    items or with a stride gives the result of the same bytes, and counts them."""
    rng = random.Random(3)
    data = sample_data(rng, 4096)
    view, same = next((v, b) for k, v, b in _views(data) if k == kind)
    k = codecs  # type: ignore[assignment]
    assert k.crc16_arc(view, 7) == k.crc16_arc(same, 7)
    a, b = k.zipcrypto.Decryptor(b"pw"), k.zipcrypto.Decryptor(b"pw")
    assert (a.decrypt(view), a.total_in) == (b.decrypt(same), len(same))
    password = data[:8]
    pv = next(v for k2, v, _ in _views(password) if k2 == kind)
    a, b = k.zipcrypto.Decryptor(pv), k.zipcrypto.Decryptor(password)
    assert a.decrypt(data[:64]) == b.decrypt(data[:64])
    for make in (k.filters.Arm64Decoder, k.filters.RiscvDecoder):
        # A first feed of odd length leaves bytes held back, to join to the view.
        a, b = make(), make()
        head = data[:5]
        got = a.decode(head) + a.decode(view) + a.flush()
        want = b.decode(head) + b.decode(same) + b.flush()
        assert (got, a.total_in) == (want, len(head) + len(same))
    z = pack_lzw(rng, 12, True, False, 2000)
    z = z[: len(z) // 4 * 4]
    zv = next(v for k2, v, _ in _views(z) if k2 == kind)
    a, b = k.lzw.Decompressor(), k.lzw.Decompressor()
    assert (a.decompress(zv), a.total_in) == (b.decompress(z), b.total_in)


class _ReadsAs(io.BytesIO):
    """A stream whose ``read()`` returns each chunk as a view of ``kind``."""

    def __init__(self, data: bytes, kind: str) -> None:
        super().__init__(data)
        self._kind = kind

    def read(self, n: int | None = -1, /) -> memoryview:  # type: ignore[override]
        chunk = super().read(n if n is None or n < 0 else n // 4 * 4 or 4)
        if len(chunk) % 4:
            return memoryview(chunk)
        return next(v for k, v, _ in _views(chunk) if k == self._kind)


@BOTH
@pytest.mark.parametrize("kind", ["wide", "strided", "wide-strided", "signed-strided"])
def test_bcj2_reads_a_view_from_its_streams_as_its_bytes(
    codecs: object, kind: str
) -> None:
    """A BCJ2 input stream whose ``read()`` returns a view of wider or strided items
    gives the output its bytes give."""
    from bcj2_util import bcj2_encode

    streams = bcj2_encode(random.Random(5), 20_000)
    bcj2 = codecs.bcj2
    want = PYTHON.bcj2.Decompressor(
        *(io.BytesIO(s) for s in streams), out_size=20_000
    ).read()
    d = bcj2.Decompressor(*(_ReadsAs(s, kind) for s in streams), out_size=20_000)
    assert d.read() == want


class _OtherBytes(bytes):
    """A ``bytes`` whose ``__bytes__`` gives other bytes than its buffer."""

    def __bytes__(self) -> bytes:
        return b"other"


@BOTH
def test_a_bytes_subclass_is_read_as_its_buffer(codecs: object) -> None:
    data = _OtherBytes(b"abc")
    assert codecs.crc16_arc(data) == PYTHON.crc16_arc(b"abc")
    assert codecs.zipcrypto.Decryptor(b"k").decrypt(data) == (
        PYTHON.zipcrypto.Decryptor(b"k").decrypt(b"abc")
    )


@BOTH
@pytest.mark.parametrize("value", [3, "abc", [0]])
def test_bcj2_refuses_a_read_that_returns_no_buffer(
    codecs: object, value: object
) -> None:
    main = types.SimpleNamespace(read=lambda n: value)
    d = codecs.bcj2.Decompressor(
        main, io.BytesIO(), io.BytesIO(), io.BytesIO(bytes(5)), out_size=4
    )
    name = type(value).__name__
    with pytest.raises(
        TypeError, match=f"a bytes-like object is required, not '{name}'"
    ):
        d.read()


@BOTH
def test_crc16_refuses_a_value_outside_16_bits(codecs: object) -> None:
    for data in (b"", b"x"):
        for value in (-1, 1 << 16):
            with pytest.raises(ValueError, match="outside 0 to 0xFFFF"):
                codecs.crc16_arc(data, value)
        assert codecs.crc16_arc(data, 0xFFFF) == PYTHON.crc16_arc(data, 0xFFFF)


def test_crc16_parity() -> None:
    rng = random.Random(7)
    for _ in range(SEEDS // 3):
        data = rng.randbytes(rng.randint(0, 5000))
        start = rng.randrange(1 << 16)
        assert PYTHON.crc16_arc(data, start) == RUST.crc16_arc(data, start)
        running = archivey_codecs.Crc16Arc()
        expected = 0
        for chunk in filter_chunks(data, rng):
            running.update(chunk)
            expected = PYTHON.crc16_arc(chunk, expected)
        assert running.digest() == expected.to_bytes(2, "big")


# ── ZipCrypto ──────────────────────────────────────────────────────────────────────


def test_zipcrypto_parity() -> None:
    rng = random.Random(4)
    for _ in range(SEEDS // 3):
        password = rng.randbytes(rng.randint(0, 40))
        py = PYTHON.zipcrypto.Decryptor(password)
        rs = RUST.zipcrypto.Decryptor(password)
        for _ in range(rng.randint(1, 5)):
            chunk = rng.randbytes(rng.randint(0, 40_000))
            assert py.decrypt(chunk) == rs.decrypt(bytearray(chunk))
            assert py.total_in == rs.total_in
        for d in (py, rs):
            clone = d.copy()
            assert clone.total_in == d.total_in
            assert clone.decrypt(b"abc") == d.decrypt(b"abc")
        assert py.decrypt(b"xyz") == rs.decrypt(b"xyz")


# ── LZX ────────────────────────────────────────────────────────────────────────────


def lzx_state(d) -> bytes | None:
    """``d.getstate()``, or ``None`` once a decode error was found (the bytes before
    it were returned, and the next call raises it): no state is saved then."""
    try:
        return d.getstate()
    except ValueError as exc:
        assert "after a decode error" in str(exc)
        return None


def lzx_run(
    codecs: object,
    chunks: list[bytes],
    output_size: int,
    window: int,
    rng: random.Random,
) -> tuple[bytes, tuple[str, object]]:
    """``lzx.Decompressor``'s output, fed ``chunks`` in random pieces with random
    ``max_length`` caps; the package's is also saved and restored (or copied) at
    random points."""
    lzx = codecs.lzx
    state_ops = has_state(codecs)
    out = bytearray()
    data = b"".join(chunks)
    try:
        d = lzx.Decompressor(window, output_size=output_size)
    except Exception as exc:  # noqa: BLE001
        return b"", outcome(lambda e=exc: (_ for _ in ()).throw(e))
    at = 0

    def step() -> None:
        nonlocal d, at
        cap = rng.choice((-1, -1, 1, 5000, 40_000))
        if at < len(data) and (d.needs_input or rng.random() < 0.3):
            n = rng.choice((1, 100, 5000, 40_000, len(data)))
            piece, at = data[at : at + n], at + n
            out.extend(d.decompress(piece, cap))
        else:
            out.extend(d.decompress(b"", cap))
        pick = rng.random()
        if not state_ops:
            return
        if pick < 0.1 and (state := lzx_state(d)) is not None:
            restored = lzx.Decompressor.from_state(state)
            assert restored.total_out == d.total_out
            assert restored.total_in == d.total_in
            at = d.total_in
            d = restored
        elif pick < 0.15:
            d = d.copy()

    try:
        for _ in range(10_000):
            if d.eof or (at >= len(data) and d.needs_input):
                break
            step()
        while not d.eof:
            got = d.flush(rng.choice((-1, 1, 7000)))
            out += got
            if not got:
                break
            if (
                state_ops
                and not d.eof
                and rng.random() < 0.3
                and (state := lzx_state(d)) is not None
            ):
                # Saved during flush(): the restored decoder is not flushed, so it
                # takes the input from its total_in again, then flushes on.
                restored = lzx.Decompressor.from_state(state)
                assert restored.total_out == d.total_out
                assert restored.total_in == d.total_in
                assert restored.decompress(data[restored.total_in :], 0) == b""
                d = restored
    except Exception as exc:  # noqa: BLE001
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return bytes(out), ("ok", None)


def lzx_streams(rng: random.Random):
    from cab_util import FRAME, LzxEncoder

    layouts = [
        ("verbatim",),
        ("aligned",),
        ("uncompressed",),
        ("verbatim", "uncompressed", "aligned"),
    ]
    for case in range(max(8, SEEDS // 10)):
        window = rng.choice((15, 16, 17, 21))
        size = rng.randint(1, 5 * FRAME)
        data = sample_data(rng, size)
        if case % 3 == 0:
            # x86-looking code, for the E8 translation.
            data = bytes(b if rng.random() > 0.05 else 0xE8 for b in data)
        enc = LzxEncoder(
            window_bits=window,
            blocks=rng.choice(layouts),
            block_size=rng.choice((FRAME, 10_000, 70_000)),
            e8_file_size=rng.choice((0, 0, size, 12_000_000)),
        )
        frames = enc.encode(data)
        sizes = [min(FRAME, size - i) for i in range(0, size, FRAME)]
        yield case, window, frames, sizes, data


def test_lzx_eof_counts_stop_where_the_stream_does() -> None:
    """The package only. At ``eof``, ``total_in`` and ``unused_data`` split the input where the LZX
    stream ends: words the bit buffer fetched ahead belong to what follows."""
    from cab_util import LzxEncoder

    rng = random.Random(11)
    for blocks in (("verbatim",), ("aligned",), ("uncompressed",)):
        for size in (1, 100, 5000, 40_000):
            data = sample_data(rng, size)
            stream = b"".join(LzxEncoder(window_bits=15, blocks=blocks).encode(data))
            for cap in (-1, 1):
                d = archivey_codecs.lzx.Decompressor(15, output_size=size)
                out = bytearray(d.decompress(stream + b"appendix", cap))
                while not d.eof:
                    out += d.flush(cap)
                assert out == data, (blocks, size)
                assert d.unused_data == b"appendix", (blocks, size, d.unused_data)
                assert d.total_in == len(stream), (blocks, size)
                # Restored at eof, it ends where this one does, with nothing after.
                r = archivey_codecs.lzx.Decompressor.from_state(d.getstate())
                assert r.eof
                assert r.total_in == len(stream)
                assert r.unused_data == b""


def _odd_stored_lzx() -> bytes:
    from cab_util import LzxEncoder

    return b"".join(
        LzxEncoder(window_bits=15, blocks=("uncompressed",)).encode(b"hello")
    )


@BOTH
def test_lzx_waits_for_an_owed_pad_byte(codecs: object) -> None:
    """An odd final uncompressed block owes a pad byte: until it arrives the stream
    has not ended and needs input, and the byte fed in a later call is taken; with no
    more input, ``flush()`` ends the stream without it."""
    stream = _odd_stored_lzx()
    lzx = codecs.lzx
    d = lzx.Decompressor(15, output_size=5)
    assert d.decompress(stream[:-1]) == b"hello"
    assert (d.eof, d.needs_input) == (False, True)
    assert d.decompress(stream[-1:] + b"trailer") == b""
    assert d.eof
    cut = lzx.Decompressor(15, output_size=5)
    assert cut.decompress(stream[:-1]) == b"hello"
    assert cut.flush() == b""
    assert cut.eof


@BOTH
def test_lzx_refuses_to_grow_a_stream_past_a_short_frame(codecs: object) -> None:
    """Only the last frame is short: once a stream has ended with one, a larger
    output size is refused, and the next frame never starts off a frame boundary."""
    stream = _odd_stored_lzx()
    d = codecs.lzx.Decompressor(15, output_size=5)
    assert d.decompress(stream) == b"hello"
    d.set_output_size(5)
    with pytest.raises(ValueError, match="last frame ended short at 5 bytes"):
        d.set_output_size(5 + 32768)


@BOTH
def test_lzx_input_queued_without_decoding_is_not_needed_again(codecs: object) -> None:
    """``decompress(data, 0)`` queues ``data`` and decodes nothing: the decoder holds
    unread input, so it does not ask for more."""
    from cab_util import LzxEncoder

    data = sample_data(random.Random(6), 70_000)
    stream = b"".join(LzxEncoder(window_bits=15).encode(data))
    d = codecs.lzx.Decompressor(15, output_size=len(data))
    out = d.decompress(stream[:10])
    assert d.needs_input
    out += d.decompress(stream[10:], 0)
    assert not d.needs_input
    out += d.decompress(b"") + d.flush()
    assert out == data


def test_lzx_state_whose_input_count_is_below_what_it_holds() -> None:
    """The package only: a state's input count covers the bytes its bit buffer
    holds; a smaller one is refused, not wrapped below zero."""
    from cab_util import LzxEncoder

    data = sample_data(random.Random(6), 3000)
    stream = b"".join(LzxEncoder(window_bits=15).encode(data))
    lzx = archivey_codecs.lzx
    d = lzx.Decompressor(15, output_size=len(data))
    # Bytes after the stream let the bit reader fetch ahead, as a CAB folder's do.
    assert d.decompress(stream + bytes(8)) == data
    assert d.eof
    state = d.getstate()
    assert lzx.Decompressor.from_state(state).total_in == d.total_in
    bad = state[:-9] + b"\0" + (0).to_bytes(8, "little")
    with pytest.raises(archivey_codecs.CorruptDataError, match="do not agree"):
        lzx.Decompressor.from_state(bad)


def test_lzx_owed_pad_byte_in_a_later_call() -> None:
    """The package only: the counts and the input after the stream. An odd final
    uncompressed block owes a pad byte: fed in a later call, it still belongs to the
    stream, so the split matches the one-call decode; with no more input, ``flush()``
    ends the stream without it."""
    stream = _odd_stored_lzx()
    lzx = archivey_codecs.lzx
    whole = lzx.Decompressor(15, output_size=5)
    assert whole.decompress(stream + b"trailer") == b"hello"
    assert (whole.total_in, whole.unused_data) == (len(stream), b"trailer")
    d = lzx.Decompressor(15, output_size=5)
    assert d.decompress(stream[:-1]) == b"hello"
    assert not d.eof
    assert d.needs_input
    r = lzx.Decompressor.from_state(d.getstate())
    for dec in (d, r):
        assert dec.decompress(stream[dec.total_in :] + b"trailer") == b""
        assert dec.eof
        assert (dec.total_in, dec.unused_data) == (len(stream), b"trailer")
    cut = lzx.Decompressor(15, output_size=5)
    assert cut.decompress(stream[:-1]) == b"hello"
    assert cut.flush() == b""
    assert cut.eof
    assert (cut.total_in, cut.unused_data) == (len(stream) - 1, b"")


def test_lzx_parity_clean_and_damaged() -> None:
    rng = random.Random(5)
    for case, window, frames, sizes, data in lzx_streams(rng):
        seed = rng.random()
        py = lzx_run(PYTHON, frames, sum(sizes), window, random.Random(seed))
        rs = lzx_run(RUST, frames, sum(sizes), window, random.Random(seed))
        assert py == (data, ("ok", None)), case
        assert rs == py, case
        for trial in range(6):
            bad = list(frames)
            k = rng.randrange(len(bad))
            bad[k] = damage(rng, bad[k])
            if trial % 3 == 0:
                bad = bad[: rng.randrange(len(bad) + 1)]
            seed = rng.random()
            py = lzx_run(PYTHON, bad, sum(sizes), window, random.Random(seed))
            rs = lzx_run(RUST, bad, sum(sizes), window, random.Random(seed))
            # Both stop at the declared size, so what follows the last frame is not
            # compared.
            assert py == rs, (case, trial)


def lzx_python_pulls(chunks: list[bytes], sizes: list[int], window: int) -> list[int]:
    """For the Python decoder fed one chunk per ``more()``: the output it had given
    each time it asked for a chunk."""
    out = 0
    asked: list[int] = []
    feed = iter(chunks)

    def more() -> bytes | None:
        asked.append(out)
        return next(feed, None)

    decoder = LzxDecoder(window, more)
    try:
        for size in sizes:
            out += len(decoder.decode_frame(size))
    except Exception:  # noqa: BLE001, S110 - only the pulls are compared
        pass
    return asked


@BOTH
def test_lzx_push_takes_input_when_the_python_decoder_pulls_it(codecs: object) -> None:
    """Fed one chunk (one cabinet data block) at a time, ``lzx.Decompressor`` gives
    the output the pull decoder (``LzxDecoder``) had given when it asked for the next
    chunk: it needs no input early, so a damaged block is fetched, and its checksum
    checked, at the same frame with either decoder."""
    rng = random.Random(7)
    for case, window, frames, sizes, _data in lzx_streams(rng):
        for trial in range(3):
            chunks = list(frames)
            if trial:
                k = rng.randrange(len(chunks))
                chunks[k] = damage(rng, chunks[k])
            asked = lzx_python_pulls(chunks, sizes, window)
            d = codecs.lzx.Decompressor(window, output_size=sum(sizes))
            out = 0
            given = []
            try:
                for chunk in chunks:
                    if not d.needs_input:
                        break
                    given.append(out)
                    out += len(d.decompress(chunk))
            except (archivey_codecs.CodecError, CorruptionError, TruncatedError):
                pass
            # The push decoder is given a chunk only when it needs one; the Python
            # decoder asks once more at the end of the input.
            assert given == asked[: len(given)], (case, trial)
            assert len(given) in (len(asked), len(asked) - 1), (case, trial)


@BOTH
def test_lzx_short_e8_last_frame_in_one_byte_slices(codecs: object) -> None:
    """A short last frame with E8 translation on, fed and read one byte at a time:
    the translation must see the frame's real length, not a full frame."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(9)
    size = FRAME + 700
    data = bytes(0xE8 if i % 9 == 0 else rng.randrange(256) for i in range(size))
    frames = LzxEncoder(window_bits=16, e8_file_size=size).encode(data)
    stream = b"".join(frames)
    d = codecs.lzx.Decompressor(16, output_size=size)
    out = bytearray()
    for i in range(len(stream)):
        out += d.decompress(stream[i : i + 1], 1)
    while not d.eof:
        got = d.flush(1)
        if not got:
            break
        out += got
    assert bytes(out) == data


def test_lzx_random_input() -> None:
    rng = random.Random(6)
    for case in range(SEEDS):
        window = rng.randint(14, 22)
        chunks = [rng.randbytes(rng.randint(0, 3000)) for _ in range(rng.randint(0, 3))]
        sizes = [32768] * rng.randint(0, 3) + [rng.randint(1, 32768)]
        seed = rng.random()
        py = lzx_run(PYTHON, chunks, sum(sizes), window, random.Random(seed))
        rs = lzx_run(RUST, chunks, sum(sizes), window, random.Random(seed))
        assert py == rs, case


# ── BCJ2 ───────────────────────────────────────────────────────────────────────────


def bcj2_run(codecs: object, streams: tuple[bytes, ...], size: int, rng: random.Random):
    """``bcj2.Decompressor``'s output, read in random amounts, with the bytes decoded
    before an error; the package's is also saved and restored (onto new streams placed
    at ``total_in``) at random points."""
    bcj2 = codecs.bcj2
    out = bytearray()
    try:
        d = bcj2.Decompressor(*(io.BytesIO(s) for s in streams), out_size=size)
        for _ in range(100_000):
            if d.eof:
                break
            got = d.read(rng.choice((1, 7, 4096, 70_000, -1)))
            out += got
            assert d.total_out == len(out)
            if rng.random() < 0.1 and has_state(codecs):
                try:
                    state = d.getstate()
                except ValueError:
                    continue  # an error waits for the next read()
                total_in, total_out = d.total_in, d.total_out
                fresh = [io.BytesIO(s) for s in streams]
                for f, at in zip(fresh, total_in, strict=True):
                    f.seek(at)
                d = bcj2.Decompressor.from_state(state, *fresh)
                assert (d.total_in, d.total_out) == (total_in, total_out)
    except Exception as exc:  # noqa: BLE001
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    assert d.read() == b""
    return bytes(out), ("ok", None)


def test_bcj2_parity() -> None:
    from bcj2_util import bcj2_encode

    rng = random.Random(8)
    clean = 0
    for case in range(max(20, SEEDS // 5)):
        size = rng.randint(0, 200_000)
        if case % 2 == 0:
            # Valid streams, then one of: untouched, a stream cut short, a stream
            # with bytes added, or a changed range coder byte.
            streams = list(bcj2_encode(rng, size))
            out_size = size
            which, how = rng.randrange(4), rng.randrange(4)
            s = streams[which]
            if how == 1 and s:
                streams[which] = s[: rng.randrange(len(s))]
            elif how == 2:
                streams[which] = s + rng.randbytes(rng.randint(1, 5))
            elif how == 3 and len(streams[3]) > 5:
                k = rng.randrange(5, len(streams[3]))
                rc = bytearray(streams[3])
                rc[k] ^= 1 << rng.randrange(8)
                streams[3] = bytes(rc)
            streams = tuple(streams)
        else:
            main = bytes(
                rng.choice(b"\xe8\xe9\x0f\x85\x80")
                if rng.random() < 0.2
                else rng.randrange(256)
                for _ in range(size)
            )
            call = rng.randbytes(rng.randint(0, 4000) * 4 + rng.choice((0, 0, 1, 3)))
            jump = rng.randbytes(rng.randint(0, 4000) * 4)
            rc = b"\0" + rng.randbytes(rng.randint(0, 20_000))
            if case % 4 == 1:
                rc = rng.randbytes(rng.randint(0, 6))
            elif case % 4 == 3:
                # A start 7-Zip refuses: a non-zero first byte, five bytes or more.
                rc = bytes([rng.randint(1, 255)]) + rng.randbytes(rng.randint(4, 50))
            out_size = rng.choice((size, size + 1000, max(0, size - 50), size * 2))
            streams = (main, call, jump, rc)
        seed = rng.random()
        py = bcj2_run(PYTHON, streams, out_size, random.Random(seed))
        clean += py[1] == ("ok", None)
        assert bcj2_run(RUST, streams, out_size, random.Random(seed)) == py, case
    # The success path (all four streams used up exactly) must be compared too.
    assert clean >= 3, clean


def test_bcj2_clean_decode_matches() -> None:
    """Valid streams decode to the same bytes on both sides, the first bit of the
    range coder a convert (the start 7-Zip writes when the first branch converts)."""
    rc_convert = b"\x00" + b"\xff" * 3 + b"\xfe"
    streams = (b"\xe8", (0x12345678).to_bytes(4, "big"), b"", rc_convert)
    py = bcj2_run(PYTHON, streams, 5, random.Random(0))
    assert py[1] == ("ok", None)
    assert len(py[0]) == 5
    assert bcj2_run(RUST, streams, 5, random.Random(0)) == py


# ── Unix compress (.Z) LZW ─────────────────────────────────────────────────────────


def pack_lzw(
    rng: random.Random, max_width: int, block_mode: bool, widen9: bool, n: int
) -> bytes:
    """A .Z stream of ``n`` random codes that a decoder can follow: valid codes, with
    CLEARs, width increases and the writer's group padding. Not compressed data."""
    out = bytearray([0x1F, 0x9D, (0x80 if block_mode else 0) | max_width])
    width, next_code, prev = 9, (257 if block_mode else 256), None
    era: list[int] = []

    def flush_era(pad: bool) -> None:
        acc = nbits = 0
        chunk = bytearray()
        for code in era:
            acc |= code << nbits
            nbits += width
            while nbits >= 8:
                chunk.append(acc & 0xFF)
                acc >>= 8
                nbits -= 8
        if nbits:
            chunk.append(acc & 0xFF)
        if pad:
            chunk += bytes(-len(chunk) % width)
        out.extend(chunk)
        era.clear()

    for _ in range(n):
        if block_mode and prev is not None and rng.random() < 0.002:
            era.append(256)
            flush_era(True)
            width, next_code, prev = 9, 257, None
            continue
        if prev is None:
            code = rng.randrange(256)
        else:
            code = rng.randrange(
                min(
                    next_code + 1,
                    1 << width,
                    512 if width == 10 and max_width == 9 else 1 << 16,
                )
            )
            if block_mode and code == 256:
                code = 255
        era.append(code)
        mask = (1 << width) - 1
        if prev is not None and next_code <= mask:
            next_code += 1
        prev = code
        if next_code > mask and width < max_width:
            flush_era(True)
            width += 1
        elif max_width == 9 and widen9 and width == 9 and next_code > 511:
            flush_era(True)
            width = 10
    flush_era(False)
    return bytes(out)


def lzw_run(codecs: object, data: bytes, rng: random.Random, kwargs: dict):
    """``lzw.Decompressor`` fed ``data`` in random chunks with random ``max_length``
    caps that every call must keep: all output before the first error, the error, the
    end report and the CLEAR offsets. The package's is also saved and restored (then
    fed from ``total_in``) at random points."""
    out = bytearray()
    offsets: list[tuple[int, int]] = []
    try:
        d = codecs.lzw.Decompressor(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return ("init", type(exc).__name__)

    def take(got: bytes, cap: int) -> None:
        assert cap < 0 or len(got) <= cap
        out.extend(got)
        offsets.extend(d.clear_offsets)

    end: tuple = ("ok", None)
    try:
        pos = 0
        while pos < len(data):
            step = rng.randint(0, 3000)
            cap = rng.choice((-1, 0, 1, 100, 5000))
            take(d.decompress(memoryview(data[pos : pos + step]), cap), cap)
            pos += step
            assert d.total_in <= pos
            if rng.random() < 0.1 and has_state(codecs):
                try:
                    state = d.getstate()
                except ValueError:
                    continue  # an error waits for the next call
                totals = (d.total_in, d.total_out)
                d = archivey_codecs.lzw.Decompressor.from_state(state)
                assert (d.total_in, d.total_out) == totals
                pos = d.total_in
        while not d.needs_input:
            cap = rng.choice((-1, 1, 7000))
            take(d.decompress(b"", cap), cap)
        while not d.eof:
            cap = rng.choice((-1, 1, 7000))
            take(d.flush(cap), cap)
    except Exception as exc:  # noqa: BLE001
        end = outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return (bytes(out), end, d.truncation, d.header_params, offsets)


def test_lzw_parity() -> None:
    rng = random.Random(7)
    cases = []
    try:
        import ncompress

        for _ in range(20):
            raw = sample_data(rng, rng.randint(0, 300_000))
            buf = io.BytesIO()
            ncompress.compress(io.BytesIO(raw), buf)
            cases.append(buf.getvalue())
    except ImportError:
        pass
    for _ in range(SEEDS):
        cases.append(
            pack_lzw(
                rng,
                rng.choice((9, 9, 10, 12, 16)),
                rng.random() < 0.8,
                rng.random() < 0.5,
                rng.randint(0, 4000),
            )
        )
    for case, data in enumerate(cases):
        for variant in range(3):
            d = data if variant == 0 else damage(rng, data)
            kwargs: dict = {}
            if variant == 2 and len(d) > 3 and rng.random() < 0.5:
                kwargs = {
                    "max_width": max(9, d[2] & 0x1F),
                    "block_mode": bool(d[2] & 0x80),
                    "nine_bit_widens": rng.choice((None, True, False)),
                }
                if kwargs["max_width"] > 16:
                    continue
                d = d[3:]
            seed = rng.random()
            py = lzw_run(PYTHON, d, random.Random(seed), kwargs)
            rs = lzw_run(RUST, d, random.Random(seed), kwargs)
            if py[0] != "init" and py[1][0] != "ok":
                # A step that fails drops its own CLEARs (both decoders), so on
                # damage which CLEARs are reported depends on how input is split: one
                # list is a prefix of the other.
                short, long = sorted((py[4], rs[4]), key=len)
                assert long[: len(short)] == short, (case, variant)
                py, rs = py[:4], rs[:4]
            assert py == rs, (case, variant)


# ── Bindings ───────────────────────────────────────────────────────────────────────


def test_callback_cycles_are_collected() -> None:
    """The package only. A decoder held by the object its input streams are bound to is freed by the
    garbage collector. (The LZX decoder takes pushed input, so it holds no callback.)"""

    class Bcj2Holder:
        def __init__(self) -> None:
            self.d = archivey_codecs.bcj2.Decompressor(
                self, self, self, self, out_size=1
            )

        def read(self, n: int) -> bytes:
            return b""

    class FailingBcj2Holder(Bcj2Holder):
        """Its streams raise, so the decoder keeps the error, whose traceback holds
        the frame that holds this object."""

        def read(self, n: int) -> bytes:
            raise OSError("disk gone")

    def fail_once() -> weakref.ref:
        holder = FailingBcj2Holder()
        with pytest.raises(OSError):
            holder.d.read()
        return weakref.ref(holder)

    for make in (Bcj2Holder,):
        holder = make()
        ref = weakref.ref(holder)
        del holder
        gc.collect()
        assert ref() is None, make
    ref = fail_once()
    gc.collect()
    assert ref() is None, "a stored error kept the decoder alive"


@BOTH
def test_lzw_width_is_checked(codecs: object) -> None:
    with pytest.raises(ValueError, match="outside 9 to 16"):
        codecs.lzw.Decompressor(max_width=30, block_mode=True)
    with pytest.raises(ValueError, match="give block_mode with max_width"):
        codecs.lzw.Decompressor(max_width=12)
    # A lone block_mode is ignored: the header decides.
    d = codecs.lzw.Decompressor(block_mode=False)
    d.decompress(b"\x1f\x9d\x90")  # 16 bits, block mode
    assert d.header_params == (16, True)


# ── LZFSE and LZVN ─────────────────────────────────────────────────────────────────


def _dmg_helpers():
    """archivey's LZFSE test helpers: the fixture runs, the block walk, the ``bvx1``
    rewrite and the ``lzfse`` package as encoder, run in a subprocess."""
    import test_lzfse_decoder

    return test_lzfse_decoder


def lzfse_both(
    data: bytes, limit: int
) -> tuple[tuple[str, object], tuple[str, object]]:
    """The Python twin and the kernel (``max_size``, the Python contract) on one input."""
    return (
        outcome(lambda: PYTHON.lzfse.decompress(data, max_size=limit)),
        outcome(lambda: archivey_codecs.lzfse.decompress(data, max_size=limit)),
    )


def lzvn_both(data: bytes, limit: int) -> tuple[tuple[str, object], tuple[str, object]]:
    return (
        outcome(lambda: PYTHON.lzvn.decompress(data, max_size=limit)),
        outcome(lambda: archivey_codecs.lzvn.decompress(data, max_size=limit)),
    )


def test_lzfse_fixture_runs_parity() -> None:
    """Every LZFSE run of the hdiutil fixtures, whole, at each limit around its size,
    cut at many points and damaged."""
    helpers = _dmg_helpers()
    runs = helpers._lzfse_runs()
    assert runs
    rng = random.Random(11)
    for stream, size in runs:
        for limit in (size, size - 1, size + 1, 0):
            python, rust = lzfse_both(stream, limit)
            assert python == rust, limit
        assert lzfse_both(stream, size)[1][0] == "ok"
        cuts = sorted({rng.randrange(len(stream)) for _ in range(40)} | {0, 4, 11, 31})
        for cut in cuts:
            python, rust = lzfse_both(stream[:cut], size)
            assert python == rust, cut
        for case in range(SEEDS // 10 + 1):
            bad = damage(rng, stream)
            python, rust = lzfse_both(bad, size)
            assert python == rust, case


def _a0_seeds(helpers) -> list[tuple[bytes, bytes]]:
    """The A0 fuzz seeds (``scripts/investigations/lzfse_package/fuzz.py``): the
    ``lzfse`` package's encoder output for text, random, mixed and zero inputs from 0
    to 64 KiB, plus one stream of two blocks, in ``fuzz.py``'s order."""
    rnd = random.Random(7)
    words = [
        bytes(rnd.choice(b"abcdefghijklmnop \n") for _ in range(rnd.randint(1, 9)))
        for _ in range(80)
    ]
    items = []
    for n in (0, 1, 7, 100, 1000, 3000, 4095, 4096, 5000, 20000, 65536):
        text = b"".join(rnd.choice(words) for _ in range(n))[:n]
        rand = rnd.randbytes(n)
        mixed = bytes(b if i % 7 else 0 for i, b in enumerate(text))
        items += [text, rand, mixed, bytes(n)]
    streams = helpers._oracle("compress", items)
    seeds = list(zip(items, streams, strict=True))
    (a, za), (b, zb) = seeds[-4], seeds[-3]
    seeds.append((a + b, za[:-4] + zb))
    return seeds


def _a0_mutate(
    rnd: random.Random, seeds: list[tuple[bytes, bytes]], *, v1: bool = False
) -> tuple[bytes, int]:
    """One fuzz case: bit flips, byte overwrites, truncation, trailing bytes, splices,
    header size fields and packed ``bvx2`` fields, with the seed's size as the limit
    or near it. Without ``v1`` it is the case ``fuzz.py``'s ``mutate`` makes from the
    same generator; ``v1`` adds a flip in the ``bvx1`` fields."""
    data, z = rnd.choice(seeds)
    z = bytearray(z)
    op = rnd.randrange(9 if v1 else 8)
    if op == 0 and z:
        for _ in range(rnd.randint(1, 4)):
            z[rnd.randrange(len(z))] ^= 1 << rnd.randrange(8)
    elif op == 1 and z:
        for _ in range(rnd.randint(1, 4)):
            z[rnd.randrange(len(z))] = rnd.randrange(256)
    elif op == 2:
        z = z[: rnd.randrange(len(z) + 1)]
    elif op == 3:
        z += rnd.randbytes(rnd.randint(1, 64))
    elif op == 4:
        other = rnd.choice(seeds)[1]
        i, j = rnd.randrange(len(z) + 1), rnd.randrange(len(other) + 1)
        z = z[:i] + other[j:]
    elif op == 5 and len(z) >= 8:
        off = rnd.choice((4, 8)) if len(z) >= 12 else 4
        (v,) = struct.unpack_from("<I", z, off)
        step = rnd.choice((-1, 1, -16, 16, 1 << 20, -(1 << 20), 1 << 31))
        struct.pack_into("<I", z, off, max(0, min(0xFFFFFFFF, v + step)))
    elif op == 6 and len(z) >= 32 and z[:4] == b"bvx2":
        z[12 + rnd.randrange(24)] ^= 1 << rnd.randrange(8)
    elif v1 and op == 7 and len(z) >= 772 and z[:4] == b"bvx1":
        # one bit of the v1 fields before the frequencies (counts, bits, states)
        z[4 + rnd.randrange(46)] ^= 1 << rnd.randrange(8)
    else:
        for _ in range(rnd.randint(5, 40)):
            z[rnd.randrange(len(z))] = rnd.randrange(256) if z else 0
    limit = (
        len(data)
        if rnd.random() < 0.9
        else max(0, len(data) + rnd.choice((-1, 1, 4096)))
    )
    return bytes(z), limit


def _fuzz_parity(seeds: list[tuple[bytes, bytes]], seed: str, *, v1: bool) -> None:
    """``LZFSE_FUZZ_CASES`` cases from ``seeds``, case ``k`` generated from
    ``random.Random(f"{seed}:{k}")``: the same bytes or the same error, case by case."""
    verdicts: dict[str, int] = {}
    for k in range(LZFSE_FUZZ_CASES):
        src, limit = _a0_mutate(random.Random(f"{seed}:{k}"), seeds, v1=v1)
        python, rust = lzfse_both(src, limit)
        assert python == rust, (k, src[:64].hex(), limit)
        verdicts[python[0]] = verdicts.get(python[0], 0) + 1
    if LZFSE_FUZZ_CASES >= 1000:
        assert set(verdicts) == {"ok", "corrupt", "truncated"}, verdicts


def test_lzfse_a0_fuzz_parity() -> None:
    """The A0 fuzz cases themselves: ``fuzz.py``'s seeds, generator and run seed
    ``a0``, so case ``k`` is the A0 run's case ``k``. ``CODECS_LZFSE_FUZZ_CASES=200000``
    replays the whole A0 run."""
    helpers = _dmg_helpers()
    if not helpers._have_lzfse():
        pytest.skip("the lzfse package (the seeds' encoder) is not installed")
    seeds = _a0_seeds(helpers)
    assert {z[:4] for _data, z in seeds} >= {b"bvx-", b"bvxn", b"bvx2"}
    _fuzz_parity(seeds, "a0", v1=False)


def test_lzfse_v1_fuzz_parity() -> None:
    """Fuzz cases the A0 run had none of: the A0 seeds plus each with its ``bvx2``
    blocks rewritten as ``bvx1``, and a flip in the ``bvx1`` fields."""
    helpers = _dmg_helpers()
    if not helpers._have_lzfse():
        pytest.skip("the lzfse package (the seeds' encoder) is not installed")
    seeds = _a0_seeds(helpers)
    seeds += [(data, helpers._to_v1(z)) for data, z in seeds if b"bvx2" in z]
    assert b"bvx1" in {z[:4] for _data, z in seeds}
    _fuzz_parity(seeds, "v1", v1=True)


def test_lzvn_parity() -> None:
    """Raw LZVN, as decmpfs stores it: each ``bvxn`` payload of the fixtures and of
    random data, clean, cut and damaged, and random opcodes."""
    helpers = _dmg_helpers()
    payloads = []
    for stream, _size in helpers._lzfse_runs():
        for magic, pos, length in helpers._blocks(stream):
            if magic == b"bvxn":
                (n_raw,) = struct.unpack_from("<I", stream, pos + 4)
                payloads.append((stream[pos + 12 : pos + length], n_raw))
    assert len(payloads) >= 4
    rng = random.Random(12)
    for payload, n_raw in payloads:
        for limit in (n_raw, n_raw - 1, n_raw + 1):
            python, rust = lzvn_both(payload, limit)
            assert python == rust, limit
        assert lzvn_both(payload, n_raw)[0][0] == "ok"
        for case in range(SEEDS // 4 + 1):
            bad = damage(rng, payload)
            python, rust = lzvn_both(bad, n_raw)
            assert python == rust, case
    for case in range(SEEDS * 4):
        ops = rng.randbytes(rng.randint(0, 40))
        if rng.random() < 0.5:
            ops += bytes([0x06]) + bytes(7)
        python, rust = lzvn_both(ops, rng.choice((0, 50, 4096)))
        assert python == rust, (case, ops.hex())


def test_lzfse_random_blocks_parity() -> None:
    """Random bytes behind each block magic: the header checks and the table builds."""
    rng = random.Random(13)
    for case in range(SEEDS * 4):
        magic = rng.choice((b"bvx-", b"bvxn", b"bvx1", b"bvx2", b"bvx$", b"bvxx"))
        size = rng.choice((rng.randint(0, 40), rng.randint(0, 900)))
        data = magic + rng.randbytes(size) + (b"bvx$" if rng.random() < 0.5 else b"")
        python, rust = lzfse_both(data, rng.choice((0, 100, 1 << 20)))
        assert python == rust, (case, data[:64].hex())


@BOTH
def test_lzx_without_output_size_flush_finishes_the_frame_in_progress(
    codecs: object,
) -> None:
    """Without an output size, a frame whose input sits whole in the bit buffer is
    still in progress at ``flush()``: it is decoded, not taken for the end."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(11)
    for layout in (("verbatim",), ("aligned",)):
        data = sample_data(rng, 2 * FRAME)
        blocks = LzxEncoder(window_bits=15, blocks=layout).encode(data)
        d = codecs.lzx.Decompressor(15)
        # The first data block only: the frame's last symbols look past it.
        assert d.decompress(blocks[0]) == b"", layout
        assert d.flush(FRAME) == data[:FRAME], layout


@BOTH
def test_lzx_stored_stream_ending_on_a_frame_boundary(codecs: object) -> None:
    """An uncompressed block reads no bits past its end, so the next frame runs out
    of input at its first block header, having read nothing: it is not started.
    So ``flush()`` without an output size sees the end, and a late
    ``set_output_size()`` of the bytes decoded is accepted."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(12)
    lzx = codecs.lzx
    for frames in (1, 2):
        data = bytes(rng.randrange(4) + 97 for _ in range(frames * FRAME))
        s = b"".join(LzxEncoder(window_bits=15, blocks=("uncompressed",)).encode(data))
        d = lzx.Decompressor(15)
        assert d.decompress(s) + d.flush() == data, frames
        assert d.eof, frames
        d = lzx.Decompressor(15)
        assert d.decompress(s) == data, frames
        d.set_output_size(len(data))
        assert d.eof, frames


def test_lzx_input_fed_byte_by_byte_resumes_where_it_stopped() -> None:
    """The package only (``total_in``). Fed one byte at a time, the decoder keeps its
    place at the start of the symbol it ran out in, also inside a block header's
    trees: ``total_in`` stays within a few bytes of the input given, and a header is
    not read again from its
    start each time (which kept it up to a whole header behind)."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(13)
    for layout in (("verbatim",), ("aligned",)):
        data = sample_data(rng, 2 * FRAME)
        s = b"".join(
            LzxEncoder(window_bits=17, blocks=layout, block_size=1000).encode(data)
        )
        d = archivey_codecs.lzx.Decompressor(17, output_size=len(data))
        out = bytearray()
        for i in range(len(s)):
            out += d.decompress(s[i : i + 1])
            assert i + 1 - d.total_in <= 12, (layout, i)
        assert bytes(out + d.flush()) == data, layout


@BOTH
def test_lzx_output_size_given_late_gives_back_what_follows_the_stream(
    codecs: object,
) -> None:
    """A stream that ends on a frame boundary, followed by other bytes: without an
    output size the decoder starts the next frame and reads them as a block header
    (and may fail on them). A late ``set_output_size()`` that ends the output there
    gives them back: they are unused data (in the package's ``unused_data``), and no
    error is left for them."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(14)
    lzx = codecs.lzx
    data = bytes(rng.randrange(4) + 97 for _ in range(FRAME))
    stream = b"".join(LzxEncoder(window_bits=15, blocks=("uncompressed",)).encode(data))
    for tail in (bytes(8), bytes.fromhex("20000080") + bytes(range(39))):
        d = lzx.Decompressor(15)
        out = d.decompress(stream + tail)
        try:
            out += d.decompress(b"")
        except (archivey_codecs.CorruptDataError, CorruptionError):
            pass
        d.set_output_size(FRAME)
        assert out == data, tail
        assert d.eof, tail
        assert d.flush() == b"", tail
        if not has_state(codecs):
            continue
        assert d.unused_data == tail, tail
        assert d.total_in == len(stream), tail
        restored = lzx.Decompressor.from_state(d.getstate())
        assert restored.total_in == len(stream), tail


def test_lzw_state_restores_with_clear_padding_still_to_come() -> None:
    """The package only. A CLEAR's segment ends after its group padding: saved when
    the CLEAR is decoded but its padding has not all arrived, the state's last CLEAR
    offset is past ``total_in``, and it restores."""
    rng = random.Random(21)
    data = pack_lzw(rng, 16, True, False, 4000)
    lzw = archivey_codecs.lzw
    restored = 0
    for cut in range(3, len(data)):
        d = lzw.Decompressor()
        out = d.decompress(data[:cut])
        if not d.clear_offsets or d.clear_offsets[-1][0] <= d.total_in:
            continue
        r = lzw.Decompressor.from_state(d.getstate())
        out += r.decompress(data[r.total_in :]) + r.flush()
        whole = lzw.Decompressor()
        assert out == whole.decompress(data) + whole.flush(), cut
        restored += 1
    assert restored > 0


# ── Bad arguments ──────────────────────────────────────────────────────────────────

_BIG = 2**64
_EMPTY = io.BytesIO


class _Index:
    """An int as a NumPy integer is one: ``__index__`` only."""

    def __init__(self, value: int) -> None:
        self._value = value

    def __index__(self) -> int:
        return self._value


def _bcj2(codecs: object, *, out_size: object = 4, main: object = None) -> object:
    """A BCJ2 decoder whose main stream reads as ``main`` gives, if given."""
    first = types.SimpleNamespace(read=lambda n: main) if main is not None else _EMPTY()
    return codecs.bcj2.Decompressor(
        first, _EMPTY(), _EMPTY(), _EMPTY(bytes(5)), out_size=out_size
    )


# Each call gives an argument of the wrong type, or an int outside what the argument
# takes. Bytes inputs take any buffer and nothing else; int arguments take any int
# (``operator.index``), so a float is refused; ``max_length`` takes any int.
_BAD_ARGUMENTS: dict[str, Callable[[object], object]] = {
    "crc16 data list": lambda c: c.crc16_arc([1, 2]),
    "crc16 data int": lambda c: c.crc16_arc(3),
    "crc16 data str": lambda c: c.crc16_arc("ab"),
    "crc16 value float": lambda c: c.crc16_arc(b"a", 1.0),
    "crc16 value big": lambda c: c.crc16_arc(b"a", _BIG),
    "crc16 value __index__ big": lambda c: c.crc16_arc(b"a", _Index(70000)),
    "crc16 value __index__ negative": lambda c: c.crc16_arc(b"a", _Index(-1)),
    "zipcrypto password list": lambda c: c.zipcrypto.Decryptor([1, 2]),
    "zipcrypto password int": lambda c: c.zipcrypto.Decryptor(3),
    "zipcrypto password str": lambda c: c.zipcrypto.Decryptor("ab"),
    "zipcrypto data list": lambda c: c.zipcrypto.Decryptor(b"a").decrypt([1]),
    "arm64 start_offset negative": lambda c: c.filters.Arm64Decoder(-1),
    "arm64 start_offset big": lambda c: c.filters.Arm64Decoder(_BIG),
    "arm64 start_offset float": lambda c: c.filters.Arm64Decoder(1.0),
    "arm64 start_offset None": lambda c: c.filters.Arm64Decoder(None),
    "riscv start_offset negative": lambda c: c.filters.RiscvDecoder(-1),
    "arm64 data list": lambda c: c.filters.Arm64Decoder().decode([1, 2, 3, 4]),
    "lzo1x block list": lambda c: c.lzo1x.decompress([0x11, 0, 0], max_size=9),
    "lzo1x max_size negative": lambda c: c.lzo1x.decompress(b"\x11\0\0", max_size=-1),
    "lzo1x max_size big": lambda c: c.lzo1x.decompress(b"\x11\0\0", max_size=_BIG),
    "lzo1x out_size negative": lambda c: c.lzo1x.decompress(b"\x11\0\0", out_size=-1),
    "lzo1x out_size float": lambda c: c.lzo1x.decompress(b"\x11\0\0", out_size=1.0),
    "lzfse data list": lambda c: c.lzfse.decompress([1], max_size=9),
    "lzfse max_size negative": lambda c: c.lzfse.decompress(b"bvx$", max_size=-1),
    "lzfse out_size big": lambda c: c.lzfse.decompress(b"bvx$", out_size=_BIG),
    "lzfse out_size float": lambda c: c.lzfse.decompress(b"bvx$", out_size=0.0),
    "lzvn max_size big": lambda c: c.lzvn.decompress(b"\x06" + bytes(7), max_size=_BIG),
    "lzvn out_size negative": lambda c: c.lzvn.decompress(b"\x06", out_size=-1),
    "lzw max_width negative": lambda c: c.lzw.Decompressor(
        max_width=-1, block_mode=True
    ),
    "lzw max_width big": lambda c: c.lzw.Decompressor(max_width=_BIG, block_mode=True),
    "lzw max_width float": lambda c: c.lzw.Decompressor(
        max_width=12.0, block_mode=True
    ),
    "lzw block_mode int": lambda c: c.lzw.Decompressor(max_width=12, block_mode=1),
    "lzw nine_bit_widens int": lambda c: c.lzw.Decompressor(nine_bit_widens=1),
    "lzw data list": lambda c: c.lzw.Decompressor().decompress([1, 2]),
    "lzw max_length float": lambda c: c.lzw.Decompressor().decompress(b"", 1.0),
    "lzw flush max_length float": lambda c: c.lzw.Decompressor().flush(1.0),
    "lzx window_bits negative": lambda c: c.lzx.Decompressor(-1),
    "lzx window_bits big": lambda c: c.lzx.Decompressor(_BIG),
    "lzx window_bits float": lambda c: c.lzx.Decompressor(15.0),
    "lzx output_size negative": lambda c: c.lzx.Decompressor(15, output_size=-1),
    "lzx output_size big": lambda c: c.lzx.Decompressor(15, output_size=_BIG),
    "lzx set_output_size negative": lambda c: c.lzx.Decompressor(15).set_output_size(
        -1
    ),
    "lzx set_output_size big": lambda c: c.lzx.Decompressor(15).set_output_size(_BIG),
    "lzx set_output_size None": lambda c: c.lzx.Decompressor(15).set_output_size(None),
    "lzx reset negative": lambda c: c.lzx.Decompressor(15).reset(-1),
    "lzx reset big": lambda c: c.lzx.Decompressor(15).reset(_BIG),
    "lzx reset float": lambda c: c.lzx.Decompressor(15).reset(1.0),
    "lzx data str": lambda c: c.lzx.Decompressor(15).decompress("a"),
    "lzx max_length float": lambda c: c.lzx.Decompressor(15).decompress(b"", 1.0),
    "lzx flush max_length float": lambda c: c.lzx.Decompressor(15).flush(1.0),
    "bcj2 out_size negative": lambda c: _bcj2(c, out_size=-1),
    "bcj2 out_size big": lambda c: _bcj2(c, out_size=_BIG),
    "bcj2 out_size float": lambda c: _bcj2(c, out_size=1.0),
    "bcj2 max_length float": lambda c: _bcj2(c).read(1.0),
    "bcj2 stream reads a list": lambda c: _bcj2(c, main=[0]).read(),
    "bcj2 stream reads a str": lambda c: _bcj2(c, main="a").read(),
}


def _raised(fn: Callable[[], object]) -> tuple[str, object]:
    """:func:`outcome`, with ``TypeError`` too."""
    try:
        return outcome(fn)
    except TypeError as exc:
        return ("TypeError", str(exc))


@pytest.mark.parametrize("call", _BAD_ARGUMENTS.values(), ids=_BAD_ARGUMENTS.keys())
def test_a_bad_argument_raises_the_same_error_on_both_sides(
    call: Callable[[object], object],
) -> None:
    # The messages are fixed, not PyO3's ``OverflowError`` ones, which differ by
    # platform: the twins give the same everywhere.
    got = _raised(lambda: call(PYTHON))
    assert got[0] != "ok", got
    assert _raised(lambda: call(RUST)) == got


@BOTH
@pytest.mark.parametrize(
    ("max_length", "expected"), [(-_BIG, b"abc"), (_BIG, b"abc"), (-2, b"abc")]
)
def test_any_int_is_a_max_length(
    codecs: object, max_length: int, expected: bytes
) -> None:
    # Negative is no limit, and one past 2**63 - 1 is no limit in practice.
    bcj2 = _bcj2(codecs, out_size=3, main=b"abc")
    assert bcj2.read(max_length) == expected


@BOTH
def test_none_is_a_crc16_value_of_0(codecs: object) -> None:
    assert codecs.crc16_arc(b"abc", None) == codecs.crc16_arc(b"abc")


@BOTH
def test_lzx_reset_starts_a_new_stream(codecs: object) -> None:
    decoder = codecs.lzx.Decompressor(15, output_size=5)
    decoder.reset(0)
    assert decoder.output_size == 0
    assert decoder.eof
    decoder.reset()
    assert decoder.output_size is None
    assert not decoder.eof
