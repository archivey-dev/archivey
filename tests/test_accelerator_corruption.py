"""Corrupt/truncated-input handling for the random-access accelerators.

`test_codecs.py` only exercises the *stdlib* decompressor paths; these cover the optional
`rapidgzip` accelerator, which backs both gzip (`RapidgzipFile`) and bzip2 (its bundled
`IndexedBzip2File`) and whose exception taxonomy differs from the stdlib decoders'. The
accelerators are forced ON (and skipped when `rapidgzip` is absent). Truncation: rapidgzip
often soft-EOFs by design; Archivey backstops with empty→stdlib fallback and a single-member
ISIZE compare on path sources (see OpenSpec `rapidgzip-truncation-investigation`).
"""

from __future__ import annotations

import base64
import bz2
import gc
import gzip
import io
import random
import weakref
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from archivey.exceptions import CorruptionError, ReadError, TruncatedError
from archivey.internal.config import (
    DEFAULT_STREAM_CONFIG,
    AcceleratorMode,
    StreamConfig,
)
from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
from archivey.internal.streams.codecs.gzip_codec import (
    _GzipTruncationCheckStream,
    _stdlib_gzip,
)
from archivey.internal.streams.codecs.stdlib_takeover import (
    _SourceViews,
    _StdlibOnAcceleratorError,
)
from archivey.internal.streams.decompressor_stream import DataAfterEndError
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)
from tests.streams_util import rapidgzip_soft_end_length

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

    from archivey.internal.streams.codecs import CodecSource

_GZ_ON = StreamConfig(use_rapidgzip=AcceleratorMode.ON)
_BZ_ON = StreamConfig(use_indexed_bzip2=AcceleratorMode.ON)


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# --- rapidgzip -------------------------------------------------------------------------


def test_rapidgzip_corrupt_translates_to_corruption() -> None:
    pytest.importorskip("rapidgzip")
    corrupt = bytearray(gzip.compress(b"payload " * 200))
    corrupt[15:35] = b"\x00" * 20  # clobber the deflate body past the 10-byte header
    # An in-memory source exercises the "Failed to parse gzip/zlib header" path that was
    # previously left untranslated (leaking a raw RuntimeError).
    with (
        open_codec_stream(Codec.GZIP, io.BytesIO(bytes(corrupt)), config=_GZ_ON) as s,
        raises_corruption_not_truncation(),
    ):
        s.read()


@pytest.mark.parametrize(
    "message",
    [
        # Classic non-ISA-L (macOS) body-corruption wording.
        (
            "Failed to decode deflate block at 10 B 0 b because of: "
            "The backreferenced distance lies outside the window buffer!"
        ),
        # Observed on macOS CI for a clobbered zlib body (Huffman tables invalid):
        # "Failed to read deflate block header … The Huffman coding is not optimal!"
        (
            "Failed to read deflate block header at offset 2 B 0 b "
            "(position after trying: 10 B 7 b: The Huffman coding is not optimal!"
        ),
        # Bare Huffman phrasing — keep covered even if the prefix changes.
        "The Huffman coding is not optimal!",
    ],
    ids=["decode-block", "read-block-header-huffman", "huffman-only"],
)
def test_rapidgzip_macos_deflate_corruption_messages_are_translated(
    message: str,
) -> None:
    # Non-ISA-L rapidgzip (macOS) reports corrupt deflate as ValueError with several
    # message shapes; Linux ISA-L uses RuntimeError/IsalInflateWrapper instead. Assert
    # every known shape maps to CorruptionError so a raw ValueError never leaks —
    # platform-independently, without needing the macOS backend installed.
    from archivey.internal.streams.codecs import DeflateCodec, GzipCodec, ZlibCodec

    exc = ValueError(message)
    assert is_corruption_not_truncation(GzipCodec()._translate_accelerator(exc))
    assert is_corruption_not_truncation(DeflateCodec()._translate_accelerator(exc))
    assert is_corruption_not_truncation(ZlibCodec()._translate_accelerator(exc))


@pytest.mark.parametrize(
    "message",
    [
        "std::exception",
        "std::exception: x",
        "Unknown exception",
        "Unknown exception: x",
    ],
)
def test_rapidgzip_catch_all_translates_the_same_for_deflate_and_bzip2(
    message: str,
) -> None:
    # rapidgzip's C++ catch-all can carry detail after its fixed text. The DEFLATE
    # family and bzip2 translators share the arm, so both map it to CorruptionError.
    # The test builds an unmarked RuntimeError by hand because the child cannot produce
    # one: a RuntimeError it reports is marked, and the reported_by_child arm gives it
    # the same verdict. Unmarked, only the catch-all arm can map it.
    from archivey.internal.streams.codecs import Bzip2Codec, GzipCodec

    exc = RuntimeError(message)
    assert is_corruption_not_truncation(GzipCodec()._translate_accelerator(exc))
    assert is_corruption_not_truncation(Bzip2Codec()._translate_accelerator(exc))


def test_rapidgzip_truncation_is_reported(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    full = gzip.compress(b"the quick brown fox " * 5000)
    path = _write(tmp_path, "truncated.gz", full[: len(full) // 2])
    # Truncation must surface as a read/close error (testing-contract: "CorruptionError or
    # TruncatedError"). Linux often soft-EOFs then empty→stdlib / ISIZE → TruncatedError;
    # macOS often raises from rapidgzip itself (CorruptionError). Either satisfies.
    with (
        pytest.raises(CorruptionError),
        open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s,
    ):
        s.read()


def test_rapidgzip_header_only_truncation_raises(tmp_path: Path) -> None:
    """Bare 10-byte gzip header: rapidgzip silent-empty; empty→stdlib must raise."""
    pytest.importorskip("rapidgzip")
    path = _write(tmp_path, "header.gz", bytes.fromhex("1f8b08000000000000ff"))
    with (
        pytest.raises(CorruptionError),
        open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s,
    ):
        s.read()


def test_rapidgzip_empty_payload_still_ok(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    path = _write(tmp_path, "empty.gz", gzip.compress(b""))
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        assert s.read() == b""


def test_rapidgzip_silent_empty_fallback_recovers_prefix(tmp_path: Path) -> None:
    """When rapidgzip returns empty, stdlib fallback streams a correct prefix then errors.

    Uses a large bounded ``read(n)`` (not ``read()`` / ``readall``): after #183 the
    gzip-window engine recovers the prefix on sized reads and raises without returning
    bytes on ``read(-1)``. The ``if recovered:`` soft-assert is intentionally gone — a
    silent-empty Linux cut must deliver a non-empty correct prefix.
    """
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox jumps over the lazy dog.\n" * 800
    full = gzip.compress(payload)
    # Mid-body cut: Linux rapidgzip typically silent-empty; macOS may raise instead.
    path = _write(tmp_path, "mid.gz", full[: max(18, len(full) // 2)])
    recovered = bytearray()
    raised: BaseException | None = None
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        try:
            # Large chunk is safe on GzipDecompressorStream (#183); must not silently
            # drop the recoverable prefix the way GzipFile.read(large) could.
            while True:
                chunk = s.read(65536)
                if not chunk:
                    break
                recovered.extend(chunk)
        except CorruptionError as exc:
            raised = exc
    if raised is None:
        pytest.fail("expected TruncatedError or CorruptionError on truncated gzip")
    if is_corruption_not_truncation(raised):
        # macOS / rapidgzip raised before empty→stdlib fallback — no prefix contract.
        return
    assert recovered
    assert bytes(recovered) == payload[: len(recovered)]
    assert len(recovered) < len(payload)


def test_rapidgzip_silent_empty_fallback_tell_tracks_bytes(tmp_path: Path) -> None:
    """After empty→stdlib switch, tell() must track delivered bytes (not stay at 0)."""
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox jumps over the lazy dog.\n" * 800
    full = gzip.compress(payload)
    path = _write(tmp_path, "mid-tell.gz", full[: max(18, len(full) // 2)])
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        try:
            chunk = s.read(1024)
        except CorruptionError:
            return  # rapidgzip raised before fallback; nothing to assert on tell
        if not chunk:
            return  # unexpected empty without raise — not the soft-empty path
        assert s.tell() == len(chunk)


def test_rapidgzip_truncation_close_is_teardown_only(tmp_path: Path) -> None:
    """ADR 0014: TruncatedError / CorruptionError must raise from read, never close().

    Covers (1) completing ``read()`` that raises, then ``close()`` during ``with`` exit;
    (2) early-stop after a recovered prefix — ``close()`` stays quiet on content.
    """
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox jumps over the lazy dog.\n" * 800
    full = gzip.compress(payload)
    path = _write(tmp_path, "adr-close.gz", full[: max(18, len(full) // 2)])

    read_err: BaseException | None = None
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        try:
            s.read()
        except CorruptionError as exc:
            read_err = exc
        # __exit__ → close(); a content fault here would fail the test / leak past read.
    assert read_err is not None, "completing read must surface truncation/corruption"

    # Early stop: deliver a prefix via sized read, then close without draining.
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        try:
            prefix = s.read(256)
        except CorruptionError:
            return  # accelerator raised before any prefix — close path still quiet above
        if prefix:
            assert s.tell() == len(prefix)
        # close via __exit__ must not raise TruncatedError (early stop = no verdict)


def test_rapidgzip_isize_soft_short_raises_on_readall(tmp_path: Path) -> None:
    """Silent-short (non-empty soft EOF): read(-1) must raise, not return then close-quiet.

    Concatenated gzip truncated mid-second-member often yields a non-empty soft EOF of
    the first member on Linux; a further member zlib confirms skips ISIZE — still must
    not raise from close(). When ISIZE does fire (single-member soft-short), it raises here.
    """
    pytest.importorskip("rapidgzip")
    # Single-member mid-body is soft-empty on Linux; build a cut that can soft-short by
    # taking a valid small file and stripping the trailer only when rapidgzip returns
    # non-empty without raising (platform-dependent). Fall back to asserting close-quiet.
    payload = b"Z" * 50_000
    full = gzip.compress(payload)
    # Near-end cuts: may soft-short, raise, or soft-empty depending on rapidgzip build.
    cut = full[: max(18, len(full) - 6)]
    path = _write(tmp_path, "soft-short.gz", cut)
    close_raised = False
    read_outcome: str
    s = open_codec_stream(Codec.GZIP, path, config=_GZ_ON)
    try:
        try:
            data = s.read()
            read_outcome = f"ok:{len(data)}"
        except TruncatedError:
            read_outcome = "TruncatedError"
        except CorruptionError:
            read_outcome = "CorruptionError"
        try:
            s.close()
        except CorruptionError:
            close_raised = True
            raise
    finally:
        if not s.closed:
            try:
                s.close()
            except Exception:  # noqa: BLE001, S110 - test cleanup
                pass
    assert not close_raised
    # Completing read must not silently accept a truncated single-member stream.
    # Soft-empty → stdlib raises TruncatedError; accelerator may CorruptionError;
    # a clean ok:N with N == len(payload) would mean the cut was not truncating enough.
    if read_outcome.startswith("ok:"):
        n = int(read_outcome.split(":")[1])
        assert n < len(payload) or cut == full
        # size-unknown: ok with short N without exception is only tolerable for
        # multi-member bailout / incomplete characterization — single-member trailer
        # strip should have raised. If we got a short silent success, ISIZE failed.
        if n < len(payload) and n > 0:
            # Soft-short without raise: deferred multi-member-style hole or missing
            # EOS observe — treat as failure of the ADR completing-read guarantee.
            pytest.fail(
                f"read(-1) returned {n} of {len(payload)} without TruncatedError "
                "(ADR 0014 completing-read must raise on truncation)"
            )


def test_rapidgzip_intact_single_member_reads_clean(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox " * 5000
    path = _write(tmp_path, "ok.gz", gzip.compress(payload))
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        assert s.read() == payload


def test_rapidgzip_multimember_not_flagged(tmp_path: Path) -> None:
    # The ISIZE backstop must not false-flag a valid concatenated gzip (its trailer is only
    # the last member's size). Multi-member ISIZE summing is deferred: a further member that
    # zlib's gzip decoder confirms stands the check down.
    pytest.importorskip("rapidgzip")
    data = gzip.compress(b"A" * 4000) + gzip.compress(b"B" * 2500)
    path = _write(tmp_path, "multi.gz", data)
    with open_codec_stream(Codec.GZIP, path, config=_GZ_ON) as s:
        assert s.read() == b"A" * 4000 + b"B" * 2500


# A cut member and then a complete one: the trailer is the last member's ISIZE and the
# further member is real, but rapidgzip stops at the cut and never decodes it. Found by
# the accelerator fuzz targets.
_GZ_CUT_THEN_MEMBER = gzip.compress(
    random.Random(7).randbytes(60_000) + b"x" * 120_000, mtime=0
)[:40_000] + gzip.compress(b"tail member\n" * 20, mtime=0)


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
@pytest.mark.parametrize("mode", [AcceleratorMode.ON, AcceleratorMode.OFF])
def test_gzip_cut_member_before_a_complete_one_raises(
    tmp_path: Path, source_kind: str, mode: AcceleratorMode
) -> None:
    if mode is AcceleratorMode.ON:
        pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _GZ_CUT_THEN_MEMBER
    source = (
        _write(tmp_path, "cut.gz", data) if source_kind == "path" else io.BytesIO(data)
    )
    config = StreamConfig(use_rapidgzip=mode, seekable=True)
    with (
        open_codec_stream(Codec.GZIP, source, config=config) as s,
        pytest.raises(TruncatedError),
    ):
        s.read()


@pytest.fixture(scope="module")
def forged_cut_gzip(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    """A gzip cut short, its trailer set to the length rapidgzip delivers before its soft
    end; skips where this rapidgzip build does not end softly on the cut. The probe
    depends on the installed build and a fixed blob only, so it runs once per module."""
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    cut = bytearray(
        gzip.compress(random.Random(1).randbytes(300_000) + b"x" * 600_000, mtime=0)[
            :200_000
        ]
    )
    path = tmp_path_factory.mktemp("forged_cut") / "cut.gz"
    path.write_bytes(cut)
    delivered = rapidgzip_soft_end_length(str(path))
    if delivered is None:
        # Some builds raise or abort on the cut instead of ending softly (macOS raises;
        # Linux wheels abort on other cuts). Archivey then reports the truncation without
        # a soft end, and there is no soft end to forge a trailer for.
        pytest.skip("this rapidgzip build does not end softly on this cut")
    cut[-4:] = delivered.to_bytes(4, "little")
    return bytes(cut)


def _seek_to_the_end(s: BinaryIO) -> None:
    s.seek(0, io.SEEK_END)


def _seek_to_the_end_then_read_from_the_start(s: BinaryIO) -> None:
    s.seek(0, io.SEEK_END)
    s.seek(0)
    s.read()


@pytest.mark.parametrize(
    "action",
    [
        pytest.param(lambda s: s.read(), id="read"),
        pytest.param(_seek_to_the_end, id="seek-end"),
        pytest.param(
            _seek_to_the_end_then_read_from_the_start, id="seek-end-rewind-read"
        ),
    ],
)
@pytest.mark.parametrize("position_known", [True, False])
def test_gzip_cut_member_with_a_forged_isize_raises(
    forged_cut_gzip: bytes,
    monkeypatch: pytest.MonkeyPatch,
    action: Callable[[BinaryIO], object],
    position_known: bool,
) -> None:
    # The trailer of a cut file is whatever bytes the cut left there. Set to the length
    # rapidgzip delivers before its soft end, it matched, and the short read passed.
    # rapidgzip's compressed position shows the cut here, but it is a measured
    # behaviour that the check accepts as unknown (None): the CRC-32 must find the
    # forgery without it. A seek to the end skips the output, so it must read it
    # through for the CRC-32, not compare the forged length.
    if not position_known:
        from archivey.internal.streams.codecs.rapidgzip_child import (
            RapidgzipChildStream,
        )

        monkeypatch.setattr(RapidgzipChildStream, "compressed_position", lambda _: None)
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(use_rapidgzip=mode, seekable=True)
        with (
            open_codec_stream(
                Codec.GZIP, io.BytesIO(forged_cut_gzip), config=config
            ) as s,
            pytest.raises(TruncatedError),
        ):
            action(s)


# --- rapidgzip truncation backstop on non-path (caller-owned) seekable sources ---------
# The backstop was path-only; these assert parity for a caller-owned BinaryIO (BytesIO or a
# real file object), where the accelerator + multi-member scan coordinate through a
# SharedSource view and the caller's source is never closed (see OpenSpec
# `gzip-truncation-backstop-any-seekable`).


def test_rapidgzip_stream_truncation_is_reported() -> None:
    pytest.importorskip("rapidgzip")
    full = gzip.compress(b"the quick brown fox\n" * 800)
    src = io.BytesIO(full[: max(18, len(full) // 2)])  # mid-body cut
    with (
        pytest.raises(CorruptionError),
        open_codec_stream(Codec.GZIP, src, config=_GZ_ON) as s,
    ):
        s.read()


def test_rapidgzip_stream_header_only_truncation_raises() -> None:
    # A source too short for a complete member (< 18 bytes) must still raise — the up-front
    # ISIZE capture preserves the too-short tri-state that a path source raised on.
    pytest.importorskip("rapidgzip")
    src = io.BytesIO(bytes.fromhex("1f8b08000000000000ff"))  # 10-byte header only
    with (
        pytest.raises(CorruptionError),
        open_codec_stream(Codec.GZIP, src, config=_GZ_ON) as s,
    ):
        s.read()


def test_rapidgzip_stream_empty_payload_still_ok() -> None:
    pytest.importorskip("rapidgzip")
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(gzip.compress(b"")), config=_GZ_ON
    ) as s:
        assert s.read() == b""


def test_rapidgzip_stream_multimember_not_flagged() -> None:
    # A valid concatenated multi-member gzip from a stream must not be false-flagged: the
    # multi-member scan runs on an independent SharedSource view of the same source.
    pytest.importorskip("rapidgzip")
    data = gzip.compress(b"A" * 4000) + gzip.compress(b"B" * 2500)
    with open_codec_stream(Codec.GZIP, io.BytesIO(data), config=_GZ_ON) as s:
        assert s.read() == b"A" * 4000 + b"B" * 2500


def test_rapidgzip_stream_intact_roundtrip() -> None:
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox " * 5000
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(gzip.compress(payload)), config=_GZ_ON
    ) as s:
        assert s.read() == payload


def test_rapidgzip_stream_source_left_open_after_close() -> None:
    # archivey must never close a caller-owned source. After the archivey stream closes, the
    # caller's BytesIO stays open and re-readable (the SharedSource view is non-owning).
    pytest.importorskip("rapidgzip")
    payload = b"the quick brown fox " * 5000
    src = io.BytesIO(gzip.compress(payload))
    with open_codec_stream(Codec.GZIP, src, config=_GZ_ON) as s:
        assert s.read() == payload
    assert not src.closed
    src.seek(0)
    assert src.read(2) == b"\x1f\x8b"  # still a readable gzip source


def test_rapidgzip_caller_file_object_truncation(tmp_path: Path) -> None:
    # A real caller-opened file object (has a valid fileno) of a truncated gzip must raise,
    # and archivey must leave the caller's file object open.
    pytest.importorskip("rapidgzip")
    full = gzip.compress(b"the quick brown fox\n" * 800)
    p = _write(tmp_path, "trunc-fileobj.gz", full[: max(18, len(full) // 2)])
    fh = open(p, "rb")  # noqa: SIM115 - the handle outlives this statement; its owner closes it
    try:
        with (
            pytest.raises(CorruptionError),
            open_codec_stream(Codec.GZIP, fh, config=_GZ_ON) as s,
        ):
            s.read()
        assert not fh.closed  # caller still owns and can close it
    finally:
        fh.close()


# --- bzip2 (via rapidgzip's bundled IndexedBzip2File) ----------------------------------


def test_indexed_bzip2_corrupt_translates_to_corruption(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    corrupt = bytearray(bz2.compress(b"payload " * 400))
    corrupt[20:45] = b"\x00" * 25  # clobber block data/header
    path = _write(tmp_path, "corrupt.bz2", bytes(corrupt))
    with (
        open_codec_stream(Codec.BZIP2, path, config=_BZ_ON) as s,
        raises_corruption_not_truncation(),
    ):
        s.read()


def test_indexed_bzip2_intact_reads_clean(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    payload = b"payload " * 400
    path = _write(tmp_path, "ok.bz2", bz2.compress(payload))
    with open_codec_stream(Codec.BZIP2, path, config=_BZ_ON) as s:
        assert s.read() == payload


class _Source(io.BytesIO):
    """A ``BytesIO`` a weak reference can point at."""


@pytest.mark.parametrize("closed", [True, False], ids=["closed", "dropped"])
@pytest.mark.parametrize("damaged", [False, True], ids=["intact", "damaged"])
def test_indexed_bzip2_frees_a_stream_source_after_close(
    damaged: bool, closed: bool
) -> None:
    """rapidgzip 0.16 keeps the Python file object it reads from after ``close()``. The
    decoder runs in a child process, which reads the caller's source through this
    process, so an ``io.BytesIO`` and its buffer are freed once the stream is closed or
    dropped."""
    pytest.importorskip("rapidgzip")
    data = bytearray(bz2.compress(b"payload " * 400))
    if damaged:
        data[len(data) // 2] ^= 0xFF
    source = _Source(bytes(data))
    alive = weakref.ref(source)
    s = open_codec_stream(Codec.BZIP2, source, config=_BZ_ON)
    if damaged:
        with pytest.raises(ReadError):
            s.read()
    else:
        s.read()
    if closed:
        s.close()
    del source, s
    gc.collect()
    assert alive() is None


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
@pytest.mark.parametrize("mode", [AcceleratorMode.ON, AcceleratorMode.OFF])
def test_bzip2_failed_read_keeps_tell_at_the_bytes_delivered(
    tmp_path: Path, source_kind: str, mode: AcceleratorMode
) -> None:
    """A read that fails at damage returns nothing, so ``tell()`` stays at the bytes the
    caller received. The accelerator's decoder had moved on by the chunks it decoded
    before the failure (measured: 1 799 957 against 1 048 576 delivered), and so did the
    position it reported. After the error, reading on raises again and a seek back to
    the start rereads the good bytes, as on the stdlib path.

    The payload is base64 text so that it compresses. With the raw random bytes the
    accelerated decoder raises on its first read with nothing delivered (measured on
    rapidgzip 0.16), and there would be no good prefix to check."""
    if mode is AcceleratorMode.ON:
        pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    payload = base64.encodebytes(random.Random(1).randbytes(3_000_000))
    damaged = bytearray(bz2.compress(payload))
    middle = len(damaged) // 2
    damaged[middle : middle + 4000] = b"\xff" * 4000
    source = (
        _write(tmp_path, "damaged.bz2", bytes(damaged))
        if source_kind == "path"
        else io.BytesIO(bytes(damaged))
    )
    config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
    got = bytearray()
    with open_codec_stream(Codec.BZIP2, source, config=config) as s:
        with raises_corruption_not_truncation():
            while block := s.read(65536):
                got += block
        assert got and payload.startswith(got)
        assert s.tell() == len(got)
        with raises_corruption_not_truncation():
            s.read(100)
        assert s.tell() == len(got)
        assert s.seek(0) == 0
        assert s.read(1000) == payload[:1000]


# The bundled bzip2 decoder ends the stream with no output and no error when the input is
# not bzip2 at all: its offsets, ``tell_compressed()`` and ``size()`` read the same for
# garbage as for a valid empty stream. The accelerated path must still raise what the
# stdlib path raises (compressed-streams: an accelerator preserves the error contract).
_BZ2_EMPTY = bz2.compress(b"")

_BZ2_NOT_A_STREAM = {
    "zeros": (b"\x00" * 40_000, CorruptionError),
    "zero-byte": (b"", TruncatedError),
    "magic-only": (b"BZh9", TruncatedError),
    "magic-then-zeros": (b"BZh9" + b"\x00" * 100, CorruptionError),
}


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
@pytest.mark.parametrize("case", sorted(_BZ2_NOT_A_STREAM))
@pytest.mark.parametrize("mode", [AcceleratorMode.ON, AcceleratorMode.OFF])
def test_bzip2_not_a_stream_raises_in_every_accelerator_mode(
    tmp_path: Path, case: str, source_kind: str, mode: AcceleratorMode
) -> None:
    if mode is AcceleratorMode.ON:
        pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data, expected = _BZ2_NOT_A_STREAM[case]
    source = (
        _write(tmp_path, "bad.bz2", data) if source_kind == "path" else io.BytesIO(data)
    )
    config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
    with open_codec_stream(Codec.BZIP2, source, config=config) as s:
        with pytest.raises(expected):
            s.read(1)
        # A seek back to the start, where the failed read left the stream, restarts
        # the decoder: the read raises the same verdict, not the spent decoder's
        # ValueError (found by the accelerator fuzz targets).
        assert s.seek(0) == 0
        with pytest.raises(expected):
            s.read(1)


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
@pytest.mark.parametrize("streams", [1, 2], ids=["one-empty", "two-empty"])
def test_indexed_bzip2_valid_empty_stream_reads_empty(
    tmp_path: Path, source_kind: str, streams: int
) -> None:
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _BZ2_EMPTY * streams
    source = (
        _write(tmp_path, "empty.bz2", data)
        if source_kind == "path"
        else io.BytesIO(data)
    )
    with open_codec_stream(Codec.BZIP2, source, config=_BZ_ON) as s:
        assert s.read(1) == b""
        assert s.read() == b""


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
def test_indexed_bzip2_seek_before_read_still_raises(
    tmp_path: Path, source_kind: str
) -> None:
    # A seek before the first read disarms the empty-stream check only when it lands off
    # 0. The accelerator clamps a seek on input it reads as empty, so the seek reached its
    # end, and the standard library decides there: it raises at the seek, as with the
    # accelerator off.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = b"\x00" * 40_000
    source = (
        _write(tmp_path, "bad.bz2", data) if source_kind == "path" else io.BytesIO(data)
    )
    with (
        open_codec_stream(Codec.BZIP2, source, config=_BZ_ON) as s,
        raises_corruption_not_truncation(),
    ):
        s.seek(100)
        s.read()


def _soft_short_backstop() -> tuple[_GzipTruncationCheckStream, bytes]:
    """The gzip backstop, as ``GzipCodec.open`` builds it, over a cut file and an inner
    that ends early without raising, as rapidgzip does on some cuts: a prefix, then a
    clean EOF."""
    payload = b"".join(f"line {i:05d} of the payload\n".encode() for i in range(4000))
    whole = gzip.compress(payload)
    cut = whole[: len(whole) // 2]
    prefix = payload[: len(payload) // 8]
    views = _SourceViews(lambda: io.BytesIO(cut))

    def open_stdlib(fallback: CodecSource) -> BinaryIO:
        return _stdlib_gzip(fallback, DEFAULT_STREAM_CONFIG)

    stream = _GzipTruncationCheckStream(
        _StdlibOnAcceleratorError(
            io.BytesIO(prefix),
            views=views,
            open_stdlib=open_stdlib,
            label="gzip",
            empty_to_stdlib=True,
        ),
        views=views,
        isize=int.from_bytes(cut[-4:], "little"),
        source_len=len(cut),
    )
    return stream, prefix


def _drain(stream: _GzipTruncationCheckStream, read_all: bool, got: bytearray) -> None:
    if read_all:
        got += stream.read()
        return
    while block := stream.read(4096):
        got += block


@pytest.mark.parametrize("read_all", [True, False], ids=["read_all", "chunked"])
def test_gzip_backstop_keeps_raising_after_its_own_truncation(read_all: bool) -> None:
    """The ISIZE backstop hands a soft EOF on a cut file to the standard library, which
    raises the truncation; a later read raises the same error instead of reading as a
    clean, empty end, and a seek back re-reads the prefix to the same error, not to a
    clean EOF."""
    stream, prefix = _soft_short_backstop()
    got = bytearray()
    with pytest.raises(TruncatedError) as first:
        _drain(stream, read_all, got)
    with pytest.raises(TruncatedError) as again:
        stream.read(4096)
    assert again.value is first.value
    assert stream.seek(0) == 0
    reread = bytearray()
    with pytest.raises(TruncatedError) as second:
        _drain(stream, read_all, reread)
    # The seek restarts the standard library's decoder, which reaches the same error
    # again at the same place: a new instance, of the same type, with the same message.
    assert type(second.value) is type(first.value)
    assert str(second.value) == str(first.value)
    # A chunked read delivers what the standard library decodes before the cut, past
    # the accelerator's prefix, and the re-read delivers it again before the error;
    # read() raises without returning it, both times.
    if read_all:
        assert got == reread == b""
    else:
        assert bytes(got).startswith(prefix) and len(got) > len(prefix)
        assert reread == got


class _SourceFailingMidway(io.BytesIO):
    """The caller's own stream, failing on a read that starts past its first 64 KiB."""

    def __init__(self, data: bytes, exc: Exception) -> None:
        super().__init__(data)
        self._exc = exc

    def read(self, size: int | None = -1, /) -> bytes:
        if self.tell() > 64 * 1024:
            raise self._exc
        return super().read(size)


@pytest.mark.parametrize("error", [OSError, EOFError])
def test_bzip2_callers_source_exception_reaches_the_caller_unchanged(
    error: type[Exception],
) -> None:
    """The bzip2 decoder process reads a caller's stream through this process, which
    keeps the stream's exception and raises it when the call ends. That exception is
    the caller's, not a verdict on the data: an ``EOFError`` (a dropped network file
    object) must not be translated to ``TruncatedError`` as bzip2's own ``EOFError``
    would be."""
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    payload = bytes(random.Random(1).randbytes(3_000_000))
    failure = error("caller source failed")
    source = _SourceFailingMidway(bz2.compress(payload), failure)
    config = StreamConfig(use_indexed_bzip2=AcceleratorMode.ON, seekable=True)
    with open_codec_stream(Codec.BZIP2, source, config=config) as stream:
        with pytest.raises(error) as info:
            while stream.read(1 << 16):
                pass
        # The decoder read ahead of what it delivered, over a source that just faulted:
        # the stream is given up rather than read on from an unknown position.
        with pytest.raises(ReadError, match="cannot continue"):
            stream.read(1 << 16)
    assert info.value is failure


# What rapidgzip's bzip2 decoder skips between streams (``_Bzip2Layout``) and where it
# stops short (the end handover in ``_Bzip2EmptyStreamCheck``). Each source must read
# the same with the accelerator on as off: the bytes, and the error type if any. Found
# by the accelerator fuzz targets.
def _bz2_stream(fill: bytes) -> bytes:
    return bz2.compress(fill * 1000)


def _bz2_without_markers(fill: bytes) -> bytes:
    """A stream with one byte flipped in its block magic and one in its end marker."""
    damaged = bytearray(_bz2_stream(fill))
    damaged[4] ^= 0xFF  # the block magic starts right after the 4-byte header
    damaged[-10] ^= 0xFF  # inside the end-of-stream marker
    return bytes(damaged)


_BZ2_LAYOUT_CASES = {
    "junk-before-the-first-stream": b"BZh9" + bytes(40) + _bz2_stream(b"A"),
    # Zero bytes before the first stream, or after an empty one, end the data with the
    # accelerator off. rapidgzip 0.16 fails its header check on the first and stops at
    # the zeros on the second, so the layout walk's zero rejection is not what decides
    # either; these pin the result, whichever path gives it.
    "zeros-before-the-first-stream": bytes(40) + _bz2_stream(b"A"),
    "empty-stream-then-zeros-then-stream": _BZ2_EMPTY + bytes(4) + _bz2_stream(b"A"),
    "junk-stream-between-streams": _bz2_stream(b"A")
    + b"BZh9"
    + bytes(40)
    + _bz2_stream(b"C"),
    "stream-without-markers-between": _bz2_stream(b"A")
    + _bz2_without_markers(b"B")
    + _bz2_stream(b"C"),
    "zero-padding-between-streams": _bz2_stream(b"A") + bytes(16) + _bz2_stream(b"C"),
    "empty-streams-and-padding-between": _bz2_stream(b"A")
    + _BZ2_EMPTY
    + bytes(3)
    + _BZ2_EMPTY
    + _bz2_stream(b"C"),
    "junk-after-the-last-stream": _bz2_stream(b"A") + b"junkjunk",
    "junk-stream-after-the-last-stream": _bz2_stream(b"A") + b"BZh9" + bytes(40),
}


def _bz2_intact_prefix(data: bytes) -> bytes:
    """The output of the whole streams at the start of ``data``, up to the first
    damage or zero byte between them."""
    out = bytearray()
    while data:
        decompressor = bz2.BZ2Decompressor()
        try:
            chunk = decompressor.decompress(data)
        except OSError:
            break
        if not decompressor.eof:
            break
        out += chunk
        data = decompressor.unused_data
        if data.startswith(b"\0"):
            break
    return bytes(out)


def _read_bz2(
    data: bytes, mode: AcceleratorMode, *, chunk: int
) -> tuple[bytes, object]:
    out = bytearray()
    config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
    try:
        with open_codec_stream(Codec.BZIP2, io.BytesIO(data), config=config) as s:
            if chunk < 0:
                out += s.read()
            else:
                while block := s.read(chunk):
                    out += block
    except (CorruptionError, TruncatedError) as exc:
        return bytes(out), type(exc)
    return bytes(out), None


@pytest.mark.parametrize("chunk", [-1, 333], ids=["read_all", "chunked"])
@pytest.mark.parametrize("case", sorted(_BZ2_LAYOUT_CASES))
def test_bzip2_accelerator_reads_stream_gaps_as_the_standard_library_does(
    case: str, chunk: int
) -> None:
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _BZ2_LAYOUT_CASES[case]
    got, got_error = _read_bz2(data, AcceleratorMode.ON, chunk=chunk)
    want, want_error = _read_bz2(data, AcceleratorMode.OFF, chunk=chunk)
    assert got_error is want_error
    if want_error is None:
        assert got == want
    else:
        # Before an error, how much each engine delivers depends on how far it read
        # ahead; what both delivered must agree, and neither may go past the output
        # of the streams before the damage: more would be bytes from past it.
        assert got[: len(want)] == want[: len(got)]
        intact = _bz2_intact_prefix(data)
        assert len(got) <= len(intact)
        assert got == intact[: len(got)]


def test_bzip2_accelerator_stops_at_a_skipped_stream_after_a_seek_past_it() -> None:
    # A seek into the stream after the skipped one lands where the decoder's output
    # already went on past the damage; the seek raises, as with the accelerator off,
    # instead of handing out a position past it.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _BZ2_LAYOUT_CASES["stream-without-markers-between"]
    # 1500 lands inside the stream after the damage; 2000 is the end of the output the
    # decoder produced, where the read comes back empty and is still checked.
    for target, whence in ((1500, io.SEEK_SET), (2000, io.SEEK_SET), (0, io.SEEK_END)):
        with (
            open_codec_stream(Codec.BZIP2, io.BytesIO(data), config=_BZ_ON) as s,
            pytest.raises(CorruptionError),
        ):
            s.seek(target, whence)


@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(lambda c: c, id="valid"),
        pytest.param(lambda c: c[:-20], id="cut"),
        pytest.param(lambda c: b"BZh9" + bytes(40), id="bare-header"),
    ],
)
@pytest.mark.parametrize(
    ("target", "whence"),
    # SEEK_CUR covers the outer layer's resolution: _StdlibSeekContract passes it down
    # as SEEK_SET.
    [(0, io.SEEK_END), (1500, io.SEEK_SET), (2500, io.SEEK_SET), (1500, io.SEEK_CUR)],
)
def test_bzip2_accelerator_seek_to_its_end_reports_what_follows_padding(
    tail: Callable[[bytes], bytes], target: int, whence: int
) -> None:
    # Both engines end the data at zero padding, whatever follows it: a valid stream, a
    # cut one or a bare header. A seek that reaches the decoder's end runs the end
    # check, which reports what follows the padding as trailing data. It does not hand
    # the end to the standard library, as it does for a stream header right after the
    # data with no zeros before it. The 1500 and 2500 targets land past the end.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    # Every offset of the second stream holds a different byte from its neighbours, so
    # a read from the wrong place does not pass.
    c = bz2.compress(bytes(range(200)) * 5)
    data = _bz2_stream(b"A") + bytes(16) + tail(c)
    outcomes = []
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
        with open_codec_stream(Codec.BZIP2, io.BytesIO(data), config=config) as s:
            outcome: list[object] = []
            try:
                outcome.append(s.seek(target, whence))
                outcome += [s.read(20), s.tell()]
            except (CorruptionError, TruncatedError) as exc:
                outcome.append(type(exc))
            outcomes.append(outcome)
    assert outcomes[1] == outcomes[0]
    if (target, whence) == (0, io.SEEK_END):
        assert outcomes[0][0] == 1000


_BZ2_SEEK_CASES = {
    **{f"layout-{name}": data for name, data in _BZ2_LAYOUT_CASES.items()},
    "header-and-zeros": b"BZh9" + bytes(40),
    "zeros": bytes(64),
    "empty-stream-then-header": _BZ2_EMPTY + b"BZh9" + bytes(40),
}


@pytest.mark.parametrize(
    ("target", "whence"),
    [(0, io.SEEK_END), (-10, io.SEEK_END), (1500, io.SEEK_SET), (2500, io.SEEK_SET)],
)
@pytest.mark.parametrize("case", sorted(_BZ2_SEEK_CASES))
def test_bzip2_accelerator_seeks_into_damage_as_off(
    case: str, target: int, whence: int
) -> None:
    # A seek gets the verdict a read would, as with the accelerator off, by three
    # paths: past a skipped region it hands over there; at the decoder's end it runs
    # the end check (empty streams after the last stream, padding, trailing data); at the
    # end of a stream the decoder read as empty it falls back. A caller sizing the
    # stream with seek(0, SEEK_END) gets the error, not a plausible size.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _BZ2_SEEK_CASES[case]
    outcomes = []
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
        with open_codec_stream(Codec.BZIP2, io.BytesIO(data), config=config) as s:
            outcome: list[object] = []
            try:
                outcome.append(s.seek(target, whence))
                outcome += [s.read(20), s.tell()]
            except (CorruptionError, TruncatedError) as exc:
                outcome.append(type(exc))
            outcomes.append(outcome)
    assert outcomes[1] == outcomes[0]


@pytest.mark.parametrize(
    "between",
    [
        pytest.param(bytes(16), id="zero-padding"),
        pytest.param(b"junkjunk", id="junk"),
        pytest.param(b"BZh9" + bytes(40), id="header-and-zeros"),
        pytest.param(_bz2_without_markers(b"B"), id="damaged-stream"),
    ],
)
def test_bzip2_accelerator_reads_a_container_coders_single_stream_as_off(
    between: bytes,
) -> None:
    # A ZIP or 7z coder's data is one stream (CodecParams.single_stream); the standard
    # library stops at its end. The accelerator stops at the padding too, and the end
    # check must not hand a following stream to a standard library that reads it. At
    # a damaged stretch the standard library takes over with the single-stream rule,
    # so it stops at the first stream's end as well.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _bz2_stream(b"X") + between + _bz2_stream(b"Y")
    params = CodecParams(single_stream=True)
    results = []
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(use_indexed_bzip2=mode, seekable=True)
        with open_codec_stream(
            Codec.BZIP2, io.BytesIO(data), config=config, params=params
        ) as s:
            results.append(s.read())
    assert results == [b"X" * 1000, b"X" * 1000]


@pytest.mark.parametrize(
    "between",
    [
        pytest.param(b"", id="adjacent"),
        pytest.param(_BZ2_EMPTY, id="empty-stream"),
        pytest.param(b"BZh9" + bytes(40), id="header-and-zeros"),
        pytest.param(_bz2_without_markers(b"B"), id="damaged-stream"),
    ],
)
@pytest.mark.parametrize(
    "refuse_input_after_end", [False, True], ids=["bounded", "exact"]
)
def test_bzip2_accelerator_ends_a_container_coders_single_stream_as_off(
    between: bytes, refuse_input_after_end: bool
) -> None:
    # A container coder's data is one stream: the accelerator hands over where a
    # further stream starts, so both modes read the first alone. With
    # refuse_input_after_end (a ZIP member, a 7z coder), both refuse what follows it.
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    data = _bz2_stream(b"X") + between + _bz2_stream(b"Y")
    params = CodecParams(single_stream=True)
    results: list[int | type[Exception]] = []
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(
            use_indexed_bzip2=mode,
            seekable=True,
            refuse_input_after_end=refuse_input_after_end,
        )
        try:
            with open_codec_stream(
                Codec.BZIP2, io.BytesIO(data), config=config, params=params
            ) as s:
                results.append(len(s.read()))
        except CorruptionError as exc:
            results.append(type(exc))
    expected = DataAfterEndError if refuse_input_after_end else 1000
    assert results == [expected, expected]


@pytest.mark.parametrize("single_stream", [True, False])
def test_bzip2_read_as_empty_fallback_keeps_the_single_stream_rule(
    single_stream: bool,
) -> None:
    # The standard library that an empty first accelerator read hands over to decodes
    # as the accelerator-off path does: after a container coder's single stream (7z),
    # a second stream is trailing data, not content.
    from archivey.internal.streams.codecs.bzip2_codec import _Bzip2EmptyStreamCheck

    data = bz2.compress(b"first") + bz2.compress(b"second")
    stream = _Bzip2EmptyStreamCheck(
        io.BytesIO(b""),  # an accelerator that read the stream as empty
        views=_SourceViews(lambda: io.BytesIO(data)),
        config=DEFAULT_STREAM_CONFIG,
        single_stream=single_stream,
    )
    assert stream.read() == (b"first" if single_stream else b"firstsecond")
