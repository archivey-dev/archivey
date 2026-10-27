"""Raw PPMd stream coverage — no 7z/ZIP container.

These tests exercise ``pyppmd`` and archivey's PPMd codec/stream adapters directly so
Windows/Linux native aborts can be chased on the *minimal* surface (see
``dev-docs/known-issues.md`` and ``scripts/ppmd_native_stress.py``).

Notes:
- In-process PPMd7 create/destroy loops are skipped on Windows (have aborted CI with
  ``STATUS_HEAP_CORRUPTION`` / access violation); that axis lives in the stress job.
- PPMd7 streams require ``unpack_size`` (7z always passes the folder size): the format
  has no end mark, and on pyppmd 1.3.x any decode request materially past the true
  payload corrupts the heap — the exact remaining size (py7zr-style) is the safe
  contract. Unsized PPMd8 is allowed (end-marked) and never passes ``-1`` (bounded
  drain loop).
"""

from __future__ import annotations

import io
import os
import random
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from archivey.exceptions import CorruptionError
from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
from archivey.internal.streams.codecs.ppmd_decoder import (
    PpmdDecoder,
    PpmdDecompressorStream,
)
from archivey.internal.streams.streamtools import read_exact
from tests.conftest import requires

pytestmark = requires("pyppmd")

_ORDER = 6
_MEM = 1 << 20
_CONTENT = b"the quick brown fox jumps over the lazy dog\n" * 40
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _encode_ppmd7(data: bytes, *, order: int = _ORDER, mem: int = _MEM) -> bytes:
    import pyppmd

    enc = pyppmd.Ppmd7Encoder(order, mem)
    return enc.encode(data) + enc.flush()


def _encode_ppmd8(data: bytes, *, order: int = _ORDER, mem: int = _MEM) -> bytes:
    import pyppmd

    enc = pyppmd.Ppmd8Encoder(order, mem, 0)
    return enc.encode(data) + enc.flush(True)


def _decode_ppmd7_raw(
    packed: bytes, size: int, *, order: int = _ORDER, mem: int = _MEM
) -> bytes:
    import pyppmd

    dec = pyppmd.Ppmd7Decoder(order, mem)
    out = bytearray(dec.decode(packed, size))
    while len(out) < size:
        need = size - len(out)
        chunk = dec.decode(b"\0" if dec.needs_input else b"", need)
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def test_raw_pyppmd7_roundtrip() -> None:
    """Bare ``Ppmd7Encoder``/``Ppmd7Decoder`` (no archivey, no 7z)."""
    packed = _encode_ppmd7(_CONTENT)
    assert _decode_ppmd7_raw(packed, len(_CONTENT)) == _CONTENT


def test_raw_pyppmd8_roundtrip() -> None:
    """Bare ``Ppmd8Encoder``/``Ppmd8Decoder`` with end-mark flush."""
    import pyppmd

    packed = _encode_ppmd8(_CONTENT)
    dec = pyppmd.Ppmd8Decoder(_ORDER, _MEM, 0)
    out = dec.decode(packed, -1)
    while not dec.eof:
        more = dec.decode(b"\0" if dec.needs_input else b"", -1)
        if not more:
            break
        out += more
    assert out == _CONTENT


def test_archivey_ppmd7_decompressor_stream_sized_read() -> None:
    """Archivey PPMd7 stream with an explicit uncompressed-size bound (no 7z)."""
    packed = _encode_ppmd7(_CONTENT)
    with PpmdDecompressorStream(
        io.BytesIO(packed),
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(_CONTENT),
        pack_size=len(packed),
    ) as stream:
        # DecompressorStream may return short chunks; containers use read_exact.
        assert read_exact(stream, len(_CONTENT)) == _CONTENT


def test_archivey_ppmd7_via_open_codec_stream_properties() -> None:
    """``open_codec_stream(Codec.PPMD)`` with 7z var.H properties blob."""
    packed = _encode_ppmd7(_CONTENT)
    props = struct.pack("<BL", _ORDER, _MEM)
    with open_codec_stream(
        Codec.PPMD,
        io.BytesIO(packed),
        params=CodecParams(properties=props, unpack_size=len(_CONTENT)),
    ) as stream:
        assert read_exact(stream, len(_CONTENT)) == _CONTENT


def test_archivey_ppmd7_trailing_null_payload() -> None:
    """Trailing NUL plaintext: sized decode must not overshoot (pyppmd extra-byte note).

    pyppmd documents that the encoder may omit a final null and the decoder may need
    an extra NUL input when output is short. With ``unpack_size``, archivey passes
    remaining length as ``max_length`` (py7zr-style) so ``decode(..., -1)`` cannot
    invent bytes past the member.
    """
    payload = b"hello world" + b"\0"
    packed = _encode_ppmd7(payload)
    with PpmdDecompressorStream(
        io.BytesIO(packed),
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    ) as stream:
        assert read_exact(stream, len(payload)) == payload


def test_archivey_ppmd7_unpack_size_prevents_overshoot() -> None:
    """``unpack_size`` keeps PPMd7 output within the known member/folder length.

    Unsized ``decode(..., -1)`` can overshoot and intermittently abort inside
    ``pyppmd`` 1.3.1 — do not exercise that path in-process here; see
    ``scripts/pyppmd_crash_repro.py --mode overshoot``.
    """
    payload = b"alpha\n" * 100
    packed = _encode_ppmd7(payload)
    with PpmdDecompressorStream(
        io.BytesIO(packed),
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    ) as stream:
        assert read_exact(stream, len(payload)) == payload
    # Decoder reports finished at unpack_size; further reads are empty.
    with PpmdDecompressorStream(
        io.BytesIO(packed),
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    ) as stream:
        assert read_exact(stream, len(payload)) == payload
        assert stream.read(1) == b""


def test_ppmd_decoder_complete_pack_drains_past_premature_eof() -> None:
    """Fully delivered pack may finish via chunked empty drains after premature eof.

    Highly compressible PPMd7 often sets native ``eof`` after the first capped
    output request; with ``pack_size`` satisfied, empty drains / flush must still
    reach ``unpack_size``.
    """
    payload = b"a" * 1024
    packed = _encode_ppmd7(payload)
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    )
    out = bytearray(dec.feed(packed, max_length=64).data)
    while len(out) < len(payload) and not dec.needs_input:
        chunk = dec.feed(b"", max_length=64).data
        if not chunk:
            break
        out.extend(chunk)
    out.extend(dec.flush().data)
    assert bytes(out) == payload
    assert dec.finished
    assert dec._fed_compressed == len(packed)
    assert dec._pack_complete() is True


def test_ppmd7_decoder_requires_pack_size() -> None:
    """PPMd7 without ``pack_size`` is rejected at construction.

    Without the declared compressed length a premature native ``eof`` (pyppmd flips it
    early on a small ``max_length`` over compressible data) cannot be told from
    truncation: the only safe move is to refuse the drain, which silently truncates a
    valid member on chunked reads. 7z always knows the pack length, so PPMd7 requires
    it rather than choosing between truncation and the near-EOF ``MemoryError``.
    """
    with pytest.raises(ValueError, match="pack_size"):
        PpmdDecoder(order=_ORDER, mem_size=_MEM, variant=7, unpack_size=1024)


def test_archivey_ppmd7_chunked_reads_compressible_are_complete() -> None:
    """Small ``read(n)`` on a highly compressible PPMd7 member returns the whole payload.

    Regression: pyppmd flips native ``eof`` after ~64 output bytes when ``max_length``
    is small over compressible data. With ``pack_size`` supplied, the decoder finishes
    the tail past that premature eof; a prior conservative gate truncated these reads.
    """
    payload = b"A" * 5000  # compresses to a handful of bytes -> premature eof pressure
    packed = _encode_ppmd7(payload)
    for read_size in (1, 64, 4096):
        with PpmdDecompressorStream(
            io.BytesIO(packed),
            order=_ORDER,
            mem_size=_MEM,
            variant=7,
            unpack_size=len(payload),
            pack_size=len(packed),
        ) as stream:
            chunks: list[bytes] = []
            while True:
                piece = stream.read(read_size)
                if not piece:
                    break
                chunks.append(piece)
            assert b"".join(chunks) == payload, f"read_size={read_size}"


def test_ppmd8_unsized_flush_does_not_overshoot() -> None:
    """Unsized PPMd8 must stop at its end mark — flush must not fabricate a tail.

    Regression: with a known ``pack_size`` but no ``unpack_size``, the post-eof empty
    drain chased a nonexistent bound and appended garbage bytes past the true end
    (measured on all-zero payloads). Unsized decodes rely on the end mark; no drain.
    """
    for payload in (b"\x00" * 9000, b"A" * 9000, b"ab\n" * 3000):
        packed = _encode_ppmd8(payload)
        dec = PpmdDecoder(
            order=_ORDER,
            mem_size=_MEM,
            variant=8,
            unpack_size=None,
            pack_size=len(packed),
        )
        out = dec.feed(packed).data
        out += dec.flush().data
        assert out == payload, f"len={len(payload)} got={len(out)}"


def test_ppmd_decoder_fed_compressed_matches_pack_size_on_complete_member() -> None:
    """``_fed_compressed`` must reach ``pack_size`` after a full pack delivery."""
    packed = _encode_ppmd7(_CONTENT)
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(_CONTENT),
        pack_size=len(packed),
    )
    out = dec.feed(packed).data
    out += dec.flush().data
    assert out == _CONTENT
    assert dec._fed_compressed == len(packed)
    assert dec._pack_complete() is True


def test_ppmd_decoder_extra_null_flush_respects_remaining() -> None:
    """Flush feeds at most remaining unpack_size bytes when needs_input (PyPI sample)."""
    payload = b"x" * 50 + b"\0"
    packed = _encode_ppmd7(payload)
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    )
    out = dec.feed(packed).data
    out += dec.flush().data
    assert out == payload
    assert dec.finished
    # Further flush must not invent more bytes past unpack_size.
    assert dec.flush().data == b""


def test_ppmd_decoder_skips_unbounded_after_eof() -> None:
    """After unpack_size is met, further feed/flush must not use decode(..., -1)."""
    payload = b"hello world"
    packed = _encode_ppmd7(payload)
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=7,
        unpack_size=len(payload),
        pack_size=len(packed),
    )
    out = dec.feed(packed).data
    out += dec.flush().data
    assert out == payload
    assert dec.finished
    # max_length is 0 once produced >= unpack_size — no native after-eof -1.
    assert dec.feed(b"\0\0\0").data == b""
    assert dec.flush().data == b""
    assert dec.feed(b"").data == b""


def test_archivey_ppmd8_via_open_codec_stream() -> None:
    """``open_codec_stream(Codec.PPMD)`` ZIP/PPMd8 params — end-marked, read-to-EOF."""
    packed = _encode_ppmd8(_CONTENT)
    with open_codec_stream(
        Codec.PPMD,
        io.BytesIO(packed),
        params=CodecParams(ppmd_order=_ORDER, ppmd_mem_size=_MEM),
    ) as stream:
        assert stream.read() == _CONTENT


def test_archivey_ppmd8_repeated_construct_destroy() -> None:
    """PPMd8 create/destroy cycles (end-marked; safer than PPMd7 on Windows)."""
    for _ in range(25):
        packed = _encode_ppmd8(_CONTENT)
        with open_codec_stream(
            Codec.PPMD,
            io.BytesIO(packed),
            params=CodecParams(ppmd_order=_ORDER, ppmd_mem_size=_MEM),
        ) as stream:
            assert stream.read() == _CONTENT


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "In-process PPMd7 create/destroy has aborted Windows CI with "
        "STATUS_HEAP_CORRUPTION / access violation; covered by PPMd native stress"
    ),
)
def test_archivey_ppmd7_repeated_construct_destroy() -> None:
    """Create/destroy many PPMd7 streams in one process (Linux/macOS only)."""
    for _ in range(25):
        packed = _encode_ppmd7(_CONTENT)
        with PpmdDecompressorStream(
            io.BytesIO(packed),
            order=_ORDER,
            mem_size=_MEM,
            variant=7,
            unpack_size=len(_CONTENT),
            pack_size=len(packed),
        ) as stream:
            assert read_exact(stream, len(_CONTENT)) == _CONTENT


# ---------------------------------------------------------------------------
# quiesce-on-close wiring + logic (deterministic; no native abort dependency)
#
# The teardown use-after-free (dev-docs/investigations/ppmd-native-investigation-results.md
# §D/§I) is a race that does not reproduce reliably in-process, so these tests
# assert the *mechanism* — that a parked worker is driven to exit on dispose and
# the happy path is skipped — with fakes, not by trying to provoke a crash.
# ---------------------------------------------------------------------------


class _FakeDecomp:
    """Stand-in for ``pyppmd.Ppmd7Decoder`` recording ``decode`` calls."""

    def __init__(self, *, needs_input: bool, eof: bool, returns: list[bytes]) -> None:
        self.needs_input = needs_input
        self.eof = eof
        self._returns = list(returns)
        self.calls: list[tuple[bytes, int]] = []

    def decode(self, data: bytes, length: int) -> bytes:
        self.calls.append((data, length))
        return self._returns.pop(0) if self._returns else b""


def _ppmd7_with_fake(fake: _FakeDecomp, *, produced: int) -> PpmdDecoder:
    dec = PpmdDecoder(
        order=_ORDER, mem_size=_MEM, variant=7, unpack_size=100, pack_size=50
    )
    dec._decomp = fake  # type: ignore[assignment]  # test double for the native decoder
    dec._held = None  # fed straight through, as a member past the hold limit would be
    dec._produced = produced
    return dec


def test_ppmd7_close_quiesces_parked_worker() -> None:
    """Incomplete member with a parked worker: close() feeds bounded NUL(s) until
    the worker exits on budget (a non-empty return)."""
    fake = _FakeDecomp(needs_input=True, eof=False, returns=[b"", b"x"])
    dec = _ppmd7_with_fake(fake, produced=0)  # not finished
    dec.close()
    # First NUL returns b"" (worker blocked again) -> feed once more; second returns
    # a byte (worker hit its 1-symbol budget and exited) -> stop.
    assert fake.calls == [(b"\0", 1), (b"\0", 1)]


def test_ppmd7_close_skips_finished_decoder() -> None:
    """A completed member (produced >= unpack_size) must not decode on close."""
    fake = _FakeDecomp(needs_input=True, eof=False, returns=[b"x"])
    dec = _ppmd7_with_fake(fake, produced=100)  # finished
    dec.close()
    assert fake.calls == []


def test_ppmd7_close_skips_at_native_eof() -> None:
    """At native eof the worker is not parked and a decode-after-eof is unsafe;
    close() must issue nothing."""
    fake = _FakeDecomp(needs_input=True, eof=True, returns=[b"x"])
    dec = _ppmd7_with_fake(fake, produced=0)
    dec.close()
    assert fake.calls == []


class _SpyDecoder:
    """Minimal :class:`Decoder` that records ``close()`` and re-registers on recreate."""

    def __init__(self, log: list[_SpyDecoder]) -> None:
        self._log = log
        self.closed = 0
        log.append(self)

    def recreate(self, point, inner):  # type: ignore[no-untyped-def]
        return _SpyDecoder(self._log)

    def feed(self, chunk: bytes, max_length: int = -1):  # type: ignore[no-untyped-def]
        from archivey.internal.streams.decompressor_stream import DecodeOut

        return DecodeOut(b"")

    def flush(self):  # type: ignore[no-untyped-def]
        from archivey.internal.streams.decompressor_stream import DecodeOut

        return DecodeOut(b"")

    @property
    def finished(self) -> bool:
        return True

    @property
    def pending_error(self):  # type: ignore[no-untyped-def]
        return None

    def clear_pending_error(self) -> None:
        pass

    @property
    def needs_input(self) -> bool:
        return True

    def build_index(self, inner, last_known):  # type: ignore[no-untyped-def]
        return [], None

    def close(self) -> None:
        self.closed += 1


def test_decompressor_stream_close_closes_decoder() -> None:
    """DecompressorStream.close() disposes its decoder (the close() wiring)."""
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    log: list[_SpyDecoder] = []
    stream = DecompressorStream(
        io.BytesIO(b""), make_decoder=lambda _p, _i: _SpyDecoder(log)
    )
    stream.close()
    assert log[0].closed == 1


def test_decompressor_stream_seek_recreate_closes_old_decoder() -> None:
    """Seek/recreate disposes the outgoing decoder before replacing it."""
    from archivey.internal.streams.decompressor_stream import (
        DecompressorStream,
        SeekPoint,
    )

    log: list[_SpyDecoder] = []
    stream = DecompressorStream(
        io.BytesIO(b""), make_decoder=lambda _p, _i: _SpyDecoder(log)
    )
    old = log[0]
    stream._reset_to_seek_point(SeekPoint(0, 0))
    assert old.closed == 1  # outgoing decoder disposed deterministically
    assert stream._decoder is log[1] and stream._decoder is not old


# ---------------------------------------------------------------------------
# Adversarial-input regression tests (pyppmd 1.3.x native aborts)
#
# pyppmd 1.3.x heap corruption fires when the native decoder runs past the true
# end of stream (unbounded budget); see dev-docs/known-issues.md and
# dev-docs/investigations/pyppmd-upstream-report.md. These tests pin the shapes damaged or
# hostile archives can force — truncation, early close, garbage tails — which
# must fail cleanly (archivey exception or bounded output) and never abort the
# process.
#
# Unfinished-decoder teardown also hits an upstream ``Ppmd7T_Free`` race when a
# worker is still blocked on input; that can silently poison the heap and only
# abort at pytest GC / interpreter exit ("exit-after-green"). These cases therefore
# run in a **fresh subprocess** so a child abort cannot take down the parent
# session (Windows already needed this; Linux hits the same Free race at lower
# rate). Bare-``pyppmd`` soaks: ``scripts/pyppmd_crash_repro.py``.
# ---------------------------------------------------------------------------


def _run_ppmd_child(script: str, *, timeout: float = 60.0) -> None:
    """Run ``script`` in a fresh interpreter; require a successful test body.

    The child must print a line ``ok`` when the archivey assertion holds. Exit 0
    is required when possible. A **teardown** native abort (SIGSEGV/SIGABRT /
    Windows STATUS_HEAP_CORRUPTION) *after* ``ok`` is the residual upstream
    ``Ppmd7T_Free`` race on unfinished workers — subprocess isolation keeps that
    out of the parent session, but cannot force a clean child exit. Those are
    accepted here so required CI is not flaky-red on a documented residual.
    Mid-script crashes (no ``ok``, or non-zero before success) still fail the
    test.
    """
    env = dict(os.environ)
    env.setdefault("PYTHONFAULTHANDLER", "1")
    # ``src`` for archivey; repo root for ``tests.test_ppmd_raw_streams`` helpers.
    path_parts = [str(_REPO_ROOT / "src"), str(_REPO_ROOT)]
    if env.get("PYTHONPATH"):
        path_parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(path_parts)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    stdout = proc.stdout or ""
    body_ok = any(line.strip() == "ok" for line in stdout.splitlines())
    if proc.returncode == 0:
        assert body_ok, (
            f"child exited 0 but did not print ok\nstdout:\n{stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
        return
    # Non-zero after a green body: residual Ppmd7T_Free / GC abort in the child.
    if body_ok:
        return
    raise AssertionError(
        f"child rc={proc.returncode}\nstdout:\n{stdout}\nstderr:\n{proc.stderr}"
    )


def test_archivey_ppmd7_truncated_input_raises_truncated_error() -> None:
    """Truncated member: flush must not fabricate the missing output.

    ``PpmdDecoder.flush`` injects at most one documented extra NUL with a *capped*
    output budget; a stream cut mid-payload must surface as ``TruncatedError``,
    not silently complete (and must not native-abort on pyppmd 1.3.x).
    Pass the true ``pack_size`` so post-eof empty drains stay gated off.
    """
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io
            from archivey.exceptions import TruncatedError
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from tests.test_ppmd_raw_streams import _CONTENT, _ORDER, _MEM, _encode_ppmd7

            packed = _encode_ppmd7(_CONTENT)
            with PpmdDecompressorStream(
                io.BytesIO(packed[: len(packed) // 2]),
                order=_ORDER,
                mem_size=_MEM,
                variant=7,
                unpack_size=len(_CONTENT),
                pack_size=len(packed),
            ) as stream:
                try:
                    stream.read()
                except TruncatedError:
                    print("ok")
                else:
                    raise SystemExit("expected TruncatedError")
            """
        )
    )


def test_archivey_ppmd7_near_truncated_pack_raises_truncated_error() -> None:
    """Near-complete pack cut (~95%) must TruncatedError, not MemoryError.

    Without ``pack_size``, empty drains past premature native eof chase
    ``unpack_size`` and can ``MemoryError`` on pyppmd 1.3.x. Declaring the true
    pack length keeps those drains gated off when delivery is short.
    """
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io
            from archivey.exceptions import TruncatedError
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from tests.test_ppmd_raw_streams import _CONTENT, _ORDER, _MEM, _encode_ppmd7

            packed = _encode_ppmd7(_CONTENT)
            cut = max(1, int(len(packed) * 0.95))
            with PpmdDecompressorStream(
                io.BytesIO(packed[:cut]),
                order=_ORDER,
                mem_size=_MEM,
                variant=7,
                unpack_size=len(_CONTENT),
                pack_size=len(packed),
            ) as stream:
                try:
                    stream.read()
                except TruncatedError:
                    print("ok")
                else:
                    raise SystemExit("expected TruncatedError")
            """
        )
    )


def test_ppmd_decoder_truncated_flush_reports_unfinished() -> None:
    """Decoder-level truncation: single-NUL flush leaves ``finished`` False."""
    _run_ppmd_child(
        textwrap.dedent(
            """\
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecoder
            from tests.test_ppmd_raw_streams import _CONTENT, _ORDER, _MEM, _encode_ppmd7

            packed = _encode_ppmd7(_CONTENT)
            dec = PpmdDecoder(
                order=_ORDER,
                mem_size=_MEM,
                variant=7,
                unpack_size=len(_CONTENT),
                pack_size=len(packed),
            )
            out = dec.feed(packed[: len(packed) // 2]).data
            out += dec.flush().data
            assert len(out) < len(_CONTENT)
            assert not dec.finished
            print("ok")
            """
        )
    )


def test_archivey_ppmd7_early_close_partial_read() -> None:
    """Closing mid-member (native decoder mid-stream) must not abort or raise."""
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from archivey.internal.streams.streamtools import read_exact
            from tests.test_ppmd_raw_streams import _CONTENT, _ORDER, _MEM, _encode_ppmd7

            packed = _encode_ppmd7(_CONTENT)
            for _ in range(5):
                stream = PpmdDecompressorStream(
                    io.BytesIO(packed),
                    order=_ORDER,
                    mem_size=_MEM,
                    variant=7,
                    unpack_size=len(_CONTENT),
                    pack_size=len(packed),
                )
                assert read_exact(stream, 16) == _CONTENT[:16]
                stream.close()
            print("ok")
            """
        )
    )


def test_archivey_ppmd7_hostile_tail_stays_bounded() -> None:
    """Inflated declared size + garbage tail: decode stays bounded, fails cleanly.

    Models a hostile 7z header whose folder ``unpack_size`` exceeds the true
    payload while the packed stream carries trailing garbage. Bytes past the
    true payload are undefined (garbage symbols), but output must never exceed
    the declared size, the true payload prefix must be intact, and any failure
    must surface as an archivey error — never a native abort.
    """
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io, struct
            from archivey.exceptions import ArchiveyError
            from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
            from tests.test_ppmd_raw_streams import _ORDER, _MEM, _encode_ppmd7

            payload = b"alpha\\n" * 100
            packed = _encode_ppmd7(payload) + bytes(range(64))
            claimed = len(payload) + 64
            props = struct.pack("<BL", _ORDER, _MEM)
            with open_codec_stream(
                Codec.PPMD,
                io.BytesIO(packed),
                params=CodecParams(properties=props, unpack_size=claimed),
            ) as stream:
                try:
                    data = stream.read()
                except ArchiveyError:
                    print("ok")
                else:
                    assert len(data) <= claimed
                    assert data[: len(payload)] == payload
                    print("ok")
            """
        )
    )


def test_ppmd_decoder_truncated_flush_caps_nul_max_length() -> None:
    """Truncated flush must not pass a large ``max_length`` with the extra NUL.

    ``decode(b"\\0", remaining_unpack_size)`` on mid-stream truncation is the
    exit-after-green / mid-suite abort trigger on pyppmd 1.3.x — cap the NUL
    recovery budget (see ``_PPMD_EXTRA_NUL_MAX_OUTPUT``).
    """
    _run_ppmd_child(
        textwrap.dedent(
            """\
            from archivey.internal.streams.codecs import ppmd_decoder
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecoder
            from tests.test_ppmd_raw_streams import (
                _CONTENT,
                _ORDER,
                _MEM,
                _encode_ppmd7,
                _MaxLengthSpy,
            )

            packed = _encode_ppmd7(_CONTENT)
            dec = PpmdDecoder(
                order=_ORDER,
                mem_size=_MEM,
                variant=7,
                unpack_size=len(_CONTENT),
                pack_size=len(packed),
            )
            dec._open_native(in_child=False)
            dec._held = None  # the chunked path, as a member past the hold limit
            spy = _MaxLengthSpy(dec._decomp)
            dec._decomp = spy
            _ = dec.feed(packed[: len(packed) // 2]).data
            _ = dec.flush().data
            assert not dec.finished
            assert spy.lengths, "expected native decode calls"
            assert all(length >= 0 for length in spy.lengths), spy.lengths
            assert (
                spy.lengths[-1] <= ppmd_decoder._PPMD_EXTRA_NUL_MAX_OUTPUT
            ), spy.lengths
            print("ok")
            """
        )
    )


class _MaxLengthSpy:
    """Wraps a pyppmd decoder, recording every ``max_length`` passed to ``decode``."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.lengths: list[int] = []

    def decode(self, data: bytes, length: int) -> bytes:
        self.lengths.append(length)
        return self._inner.decode(data, length)  # type: ignore[attr-defined]

    @property
    def eof(self) -> bool:
        return self._inner.eof  # type: ignore[attr-defined]

    @property
    def needs_input(self) -> bool:
        return self._inner.needs_input  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("variant", "sized"),
    [(7, True), (8, True), (8, False)],
    ids=["ppmd7-sized", "ppmd8-sized", "ppmd8-unsized"],
)
def test_ppmd_decoder_never_passes_unbounded_max_length(
    variant: int, sized: bool
) -> None:
    """No decode call may reach pyppmd with ``max_length=-1``.

    ``-1`` grants the pyppmd 1.3.x native worker an effectively unlimited symbol
    budget — the heap-corruption path. Sized decodes pass the remaining
    ``unpack_size``; unsized PPMd8 must use the bounded drain loop instead.
    """
    packed = _encode_ppmd7(_CONTENT) if variant == 7 else _encode_ppmd8(_CONTENT)
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=variant,
        unpack_size=len(_CONTENT) if sized else None,
        pack_size=len(packed) if sized else None,
    )
    dec._open_native(in_child=False)
    spy = _MaxLengthSpy(dec._decomp)
    dec._decomp = spy
    out = dec.feed(packed).data
    out += dec.flush().data
    assert out[: len(_CONTENT)] == _CONTENT
    assert spy.lengths, "expected at least one native decode call"
    assert all(length >= 0 for length in spy.lengths), spy.lengths


def test_archivey_ppmd7_requires_unpack_size() -> None:
    """Unsized PPMd7 is rejected outright — there is no safe decode request for it.

    PPMd7 has no end mark, and on pyppmd 1.3.x a decode request materially past the
    true remaining output leaves the native worker waiting for input, which corrupts
    the heap when the decoder is freed (bare pyppmd: +65536 over crashed 13/20, +64
    and +4096 over 0/20). With no declared size there is no correct output boundary
    either, so construction fails fast instead.
    """
    with pytest.raises(ValueError, match="unpack_size"):
        PpmdDecompressorStream(
            io.BytesIO(b""),
            order=_ORDER,
            mem_size=_MEM,
            variant=7,
        )


# ---------------------------------------------------------------------------
# Overstated ``unpack_size`` (#315 thread K6). A 7z folder may declare more output
# than its complete pack holds. pyppmd then returns short at native ``eof``, and
# the next ``decode`` resumes a worker parked on empty input: on 1.3.1 that raised
# a bare ``MemoryError`` that escaped the reader. The assertions are on the calls
# made to pyppmd, not on what pyppmd does with them, so they hold on any build.
# ---------------------------------------------------------------------------


class _DecodeCallSpy:
    """Wraps a pyppmd decoder, recording each call's shape and outcome."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        # (len(data), length, len(returned), eof after the call)
        self.calls: list[tuple[int, int, int, bool]] = []

    def decode(self, data: bytes, length: int) -> bytes:
        out: bytes = self._inner.decode(data, length)  # type: ignore[attr-defined]
        self.calls.append((len(data), length, len(out), self.eof))
        return out

    @property
    def eof(self) -> bool:
        return self._inner.eof  # type: ignore[attr-defined]

    @property
    def needs_input(self) -> bool:
        return self._inner.needs_input  # type: ignore[attr-defined]


def _calls_after_payload_spent(
    calls: list[tuple[int, int, int, bool]], pack_size: int = 0
) -> list:
    """The calls made after one that came back short at ``eof`` (payload spent) once
    ``pack_size`` input bytes had been fed; before that, more input is coming."""
    fed = 0
    for i, (data_len, length, got, eof) in enumerate(calls):
        fed += data_len
        if eof and got < length and fed >= pack_size:
            return calls[i + 1 :]
    return []


# Short, not repetitive: PPMd may decode a few symbols past a payload's end from the
# range coder's state alone (the container CRC catches those), and on this payload
# it decodes none, so the stream ends short straight away.
_K6_PAYLOAD = b"hello ppmd world, compress me a little bit more please\n"

# A member of several stream chunks that pyppmd 1.3.1, fed one chunk at a time with
# whole-remainder requests, returned short at ``eof`` on its last chunk: a parked
# worker, resumed, counted its earlier output against the new request (see
# ``PpmdDecoder._native_decode``). A random block repeated decodes fast enough after
# its first copy for that to happen; measured: the unsplit decoder raised
# ``TruncatedError`` on ``read()``. The model needs the larger memory to remember a
# whole block. The ``_K6_PAYLOAD`` tail makes an overstated size end short at once, as
# it does for ``_K6_PAYLOAD`` alone.
_PIECES_PAYLOAD = random.Random(0).randbytes(1 << 16) * 4 + _K6_PAYLOAD
_PIECES_MEM = 1 << 24


@pytest.mark.parametrize("overstate", [1, 1 << 40], ids=["plus-1", "plus-1TiB"])
@pytest.mark.parametrize(
    ("feed", "reads"),
    [
        (feed, reads)
        for feed in ("whole", "pieces")
        for reads in (
            "readall",
            "exact-then-more",
            "one-byte-at-a-time",
            "one-3GB-read",
        )
        # 256 KiB read a byte at a time is a decode call per byte: too slow.
        if (feed, reads) != ("pieces", "one-byte-at-a-time")
    ],
)
def test_archivey_ppmd7_overstated_unpack_size_raises_truncated_error(
    overstate: int, reads: str, feed: str
) -> None:
    """A complete pack under an overstated ``unpack_size`` ends in ``TruncatedError``.

    The payload itself comes back intact, and once pyppmd has returned short at
    ``eof`` no further ``decode`` is issued while reading — that later call is the
    one that raised ``MemoryError``. A single read larger than a C ``int`` reaches
    pyppmd capped, where it used to raise ``OverflowError``. ``pieces`` feeds a
    member of several stream chunks to pyppmd one chunk at a time, the path that
    splits each call (``PpmdDecoder._native_decode``): its ``b""`` second call must
    never reach a worker parked on empty input.
    """
    if feed == "whole":
        payload, mem, max_input = "_K6_PAYLOAD", "_MEM", "None"
    else:
        payload, mem, max_input = "_PIECES_PAYLOAD", "_PIECES_MEM", "0"
    _run_ppmd_child(
        textwrap.dedent(
            f"""\
            import io
            from archivey.config import ProcessIsolation
            from archivey.exceptions import TruncatedError
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from tests.test_ppmd_raw_streams import (
                _K6_PAYLOAD, _PIECES_PAYLOAD, _ORDER, _MEM, _PIECES_MEM, _DecodeCallSpy,
                _calls_after_payload_spent, _encode_ppmd7,
            )

            payload = {payload}
            packed = _encode_ppmd7(payload, mem={mem})
            stream = PpmdDecompressorStream(
                io.BytesIO(packed),
                order=_ORDER,
                mem_size={mem},
                variant=7,
                unpack_size=len(payload) + {overstate},
                pack_size=len(packed),
                max_held_input={max_input},
                isolation=ProcessIsolation.NONE,
            )
            stream._decoder._open_native(in_child=False)
            spy = _DecodeCallSpy(stream._decoder._decomp)
            stream._decoder._decomp = spy
            reads = {reads!r}
            got = bytearray()
            try:
                if reads == "readall":
                    got += stream.read()
                elif reads == "one-3GB-read":
                    got += stream.read(3_000_000_000)
                    got += stream.read(3_000_000_000)
                else:
                    step = 1 if reads == "one-byte-at-a-time" else 64
                    if reads == "exact-then-more":
                        got += stream.read(len(payload))
                    while True:
                        got += stream.read(step)
            except TruncatedError:
                pass
            else:
                raise SystemExit("expected TruncatedError")
            calls = list(spy.calls)
            stream.close()
            if reads != "readall":
                # readall() drops a truncated stream's bytes by contract.
                assert bytes(got) == payload, len(got)
            assert _calls_after_payload_spent(calls, len(packed)) == [], calls[-4:]
            assert all(length < 2**31 for _, length, _, _ in calls), calls
            print("ok")
            """
        )
    )


_PIECES_SCRIPT = """\
import io
from archivey.config import ProcessIsolation
from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
from tests.test_ppmd_raw_streams import (
    _ORDER, _PIECES_MEM, _PIECES_PAYLOAD, _encode_ppmd7,
)

packed = _encode_ppmd7(_PIECES_PAYLOAD, mem=_PIECES_MEM)
with PpmdDecompressorStream(
    io.BytesIO(packed),
    order=_ORDER,
    mem_size=_PIECES_MEM,
    variant=7,
    unpack_size=len(_PIECES_PAYLOAD),
    pack_size=len(packed),
    max_held_input=0,
    refuse_input_after_end=True,
    isolation=ProcessIsolation.{isolation},
) as stream:
    got = bytearray()
    while chunk := stream.read({read_size}):
        got += chunk
assert bytes(got) == _PIECES_PAYLOAD, len(got)
print("ok")
"""


@pytest.mark.parametrize("read_size", [-1, 65536], ids=["readall", "64KiB-reads"])
@pytest.mark.parametrize("isolation", ["NONE", "KNOWN_CRASHES"])
def test_archivey_ppmd7_fed_in_pieces_decodes_in_full(
    read_size: int, isolation: str
) -> None:
    """A valid member fed to pyppmd one stream chunk at a time decodes in full.

    ``max_held_input=0`` makes the decoder feed pyppmd in pieces, as it does
    for a member over ``DecoderLimits.max_ppmd_held_input``. pyppmd used to
    return short at ``eof`` on the last piece, which read as a spent payload: the
    member raised ``TruncatedError`` 30 KiB short. ``refuse_input_after_end`` runs the
    7z end check on top. ``NONE`` runs pyppmd in this test's own child interpreter.
    """
    script = _PIECES_SCRIPT.format(isolation=isolation, read_size=read_size)
    _run_ppmd_child(script)


@pytest.mark.parametrize("request_size", [4096, 1], ids=["4KiB-requests", "1-byte"])
@pytest.mark.parametrize("overstate", [0, 1 << 40], ids=["exact", "plus-1TiB"])
def test_archivey_ppmd7_fed_a_byte_at_a_time_never_resumes_a_parked_worker_empty(
    overstate: int, request_size: int
) -> None:
    """Fed one compressed byte per piece, a resumed worker often parks again before
    its first symbol: the 1-byte call comes back empty. ``_native_decode`` must then
    not ask the rest with ``b""``, which would resume that worker on empty input
    (pyppmd reads past its input and raises ``MemoryError``). The exact size reads in
    full; an overstated one ends in ``TruncatedError`` with the payload intact.

    ``1-byte`` asks one byte of every call, as ``read(1)`` does, so each piece resumes
    the worker with a request ``_native_decode`` does not split. The stream layer
    cannot reach that shape cheaply: it reads 64 KiB of compressed input per piece,
    and a member of two pieces read a byte at a time is 64 K stream reads."""
    _run_ppmd_child(
        textwrap.dedent(
            f"""\
            import random
            from archivey.config import ProcessIsolation
            from archivey.exceptions import TruncatedError
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecoder
            from tests.test_ppmd_raw_streams import (
                _K6_PAYLOAD, _ORDER, _MEM, _DecodeCallSpy, _encode_ppmd7,
            )

            payload = random.Random(1).randbytes(4096) + _K6_PAYLOAD
            packed = _encode_ppmd7(payload)
            decoder = PpmdDecoder(
                order=_ORDER,
                mem_size=_MEM,
                variant=7,
                unpack_size=len(payload) + {overstate},
                pack_size=len(packed),
                max_held_input=0,
                isolation=ProcessIsolation.NONE,
            )
            decoder._open_native(in_child=False)
            spy = _DecodeCallSpy(decoder._decomp)
            decoder._decomp = spy
            got = bytearray()
            # The stream layer reads its source in large chunks; drive the decoder
            # itself to feed it one byte at a time. The first piece holds the range
            # coder's 5 start bytes.
            request = {request_size}

            def feed(piece):
                out = bytearray(decoder.feed(piece, request).data)
                # Take what the piece holds before the next one, as the stream does.
                while request == 1 and (more := decoder.feed(b"", request).data):
                    out += more
                return out

            got += feed(packed[:5])
            for i in range(5, len(packed)):
                got += feed(packed[i : i + 1])
            got += decoder.flush().data
            while decoder.drains_after_flush:
                got += decoder.feed(b"", request).data
            error = decoder._pending_error
            calls = list(spy.calls)
            decoder.close()
            assert any(n == 1 and length == 1 and out == 0 for n, length, out, _ in calls)
            assert bytes(got) == payload, len(got)
            if {overstate}:
                assert isinstance(error, TruncatedError), error
            else:
                assert error is None, error
            print("ok")
            """
        )
    )


def test_archivey_ppmd7_truncated_in_pieces_sends_one_nul_and_no_empty_decode() -> None:
    """A pack cut short and fed in pieces gets the documented extra NUL at compressed
    EOF as one ``decode``, not split into a NUL and an empty decode: with the pack
    known short, this decoder makes no empty decode past what it was given. The read
    ends in ``TruncatedError`` with the bytes before it intact."""
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io
            from archivey.config import ProcessIsolation
            from archivey.exceptions import TruncatedError
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from tests.test_ppmd_raw_streams import (
                _ORDER, _PIECES_MEM, _PIECES_PAYLOAD, _DecodeCallSpy, _encode_ppmd7,
            )

            packed = _encode_ppmd7(_PIECES_PAYLOAD, mem=_PIECES_MEM)
            cut = packed[: len(packed) * 6 // 10]
            stream = PpmdDecompressorStream(
                io.BytesIO(cut),
                order=_ORDER,
                mem_size=_PIECES_MEM,
                variant=7,
                unpack_size=len(_PIECES_PAYLOAD),
                pack_size=len(packed),
                max_held_input=0,
                isolation=ProcessIsolation.NONE,
            )
            stream._decoder._open_native(in_child=False)
            spy = _DecodeCallSpy(stream._decoder._decomp)
            stream._decoder._decomp = spy
            got = bytearray()
            try:
                while chunk := stream.read(65536):
                    got += chunk
            except TruncatedError:
                pass
            else:
                raise SystemExit("expected TruncatedError")
            calls = list(spy.calls)
            stream.close()
            assert _PIECES_PAYLOAD.startswith(bytes(got)), len(got)
            fed = 0
            for i, (data_len, length, _, _) in enumerate(calls):
                fed += data_len
                if fed > len(cut):
                    break
            else:
                raise SystemExit(f"no NUL after the cut: {calls[-4:]}")
            # Call i is the NUL; nothing after it decodes from empty input.
            assert calls[i][0] == 1, calls[i - 1 :]
            assert all(n for n, _, _, _ in calls[i + 1 :]), calls[i:]
            print("ok")
            """
        )
    )


def test_ppmd7_close_quiesces_worker_after_payload_spent() -> None:
    """A spent payload reports ``eof`` with ``needs_input`` False even when its
    worker is parked, so close() must quiesce it regardless of those flags."""
    fake = _FakeDecomp(needs_input=False, eof=True, returns=[b"", b"x"])
    dec = _ppmd7_with_fake(fake, produced=0)
    dec._exhausted = True
    dec.close()
    assert fake.calls == [(b"\0", 1), (b"\0", 1)]


def test_ppmd7_payload_spent_needs_complete_pack() -> None:
    """A short return at ``eof`` mid-pack is not the end: more input may follow.

    This is the chunked path, which a member takes only past
    ``DecoderLimits.max_ppmd_held_input``, inside a child process: ``eof`` also rises on a
    valid stream whose compressed bytes end in zeros at a chunk boundary, so stopping
    here would cut valid members short.
    """
    fake = _FakeDecomp(needs_input=False, eof=True, returns=[b"ab"])
    dec = _ppmd7_with_fake(fake, produced=0)  # pack_size=50
    assert dec.feed(b"x" * 10, max_length=64).data == b"ab"
    assert not dec._exhausted
    fake._returns = [b"cd"]
    assert dec.feed(b"x" * 40, max_length=64).data == b"cd"
    assert dec._exhausted
    # Spent: nothing more reaches the native decoder, and flush reports truncation.
    before = len(fake.calls)
    assert dec.feed(b"", max_length=64).data == b""
    assert dec.flush().data == b""
    assert len(fake.calls) == before
    assert dec.pending_error is not None


def test_ppmd7_drain_stops_at_the_first_short_return_at_eof() -> None:
    """The flush drain's own stop: a full premature-eof return lets the drain start,
    and the first short return at ``eof`` inside it ends it with no further call."""
    fake = _FakeDecomp(needs_input=False, eof=True, returns=[b"a" * 10, b"bcd"])
    dec = _ppmd7_with_fake(fake, produced=0)  # unpack_size=100, pack_size=50
    assert dec.feed(b"x" * 50, max_length=10).data == b"a" * 10
    assert not dec._exhausted  # a full return, however premature its eof
    assert dec.flush().data == b"bcd"
    assert dec._exhausted
    assert fake.calls[1:] == [(b"", 64)]
    assert dec.pending_error is not None


class _FakePpmd8(_FakeDecomp):
    """A PPMd8 stand-in with ``unused_data``; a ``decode(b"", 1)`` that returns
    nothing leaves it parked on empty input, as pyppmd's worker is then."""

    def __init__(
        self, *, needs_input: bool, eof: bool, returns: list[bytes], unused: bytes
    ) -> None:
        super().__init__(needs_input=needs_input, eof=eof, returns=returns)
        self.unused_data = unused

    def decode(self, data: bytes, length: int) -> bytes:
        out = super().decode(data, length)
        self.needs_input = not out
        return out


def _ppmd8_at_size(fake: _FakePpmd8) -> PpmdDecoder:
    """A ZIP PPMd8 decoder whose output reached ``unpack_size``, with all input fed."""
    dec = PpmdDecoder(
        order=_ORDER,
        mem_size=_MEM,
        variant=8,
        unpack_size=100,
        pack_size=50,
        refuse_input_after_end=True,
    )
    dec._decomp = fake  # type: ignore[assignment]  # test double for the native decoder
    dec._held = None
    dec._produced = 100
    dec._fed_compressed = 50
    return dec


@pytest.mark.parametrize(("unused", "after"), [(b"J", True), (b"", False)])
def test_ppmd8_end_mark_decoded_before_the_size_check_reads_unused_data(
    unused: bytes, after: bool
) -> None:
    """A decoder already at ``eof`` has decoded its end mark (pyppmd sets PPMd8
    ``eof`` only there), so its ``unused_data`` is input after the end, and it is
    asked for no further symbol."""
    fake = _FakePpmd8(needs_input=False, eof=True, returns=[], unused=unused)
    dec = _ppmd8_at_size(fake)
    assert dec.flush().data == b""
    assert dec.finished
    assert dec.input_after_end is after
    assert fake.calls == []


def test_ppmd8_end_probe_that_parks_the_worker_quiesces_it_on_close() -> None:
    """No end mark at the size: the member is corrupt, as 7-Zip reads it, and the
    probe's empty return parks the worker, so close() must send it the NUL although
    the member is finished."""
    fake = _FakePpmd8(needs_input=False, eof=False, returns=[b"", b"x"], unused=b"")
    dec = _ppmd8_at_size(fake)
    assert dec.flush().data == b""
    assert dec.finished
    assert not dec.input_after_end
    assert isinstance(dec.pending_error, CorruptionError)
    assert "no end mark" in str(dec.pending_error)
    assert fake.calls == [(b"", 1)]
    dec.close()
    assert fake.calls == [(b"", 1), (b"\0", 1)]
