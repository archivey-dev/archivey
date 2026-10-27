"""The rapidgzip child's memory is capped by ``DecoderLimits.max_decoder_memory``.

rapidgzip keeps decoded chunks in memory, and a chunk is as large as its output, so a
small gzip file that decodes to a lot of zeros made the child hold memory in proportion
to the output: 285 MB for a 255 KB file, and the out-of-memory killer for a 1 MB one.
The child now stops when its memory grows past the limit, and the standard library
reads the rest of the stream.

The tests prove the bound with a small input and a small limit: 64 MiB of zeros (a
65 KB file), which takes the child about 70 MB over its start-up memory, against a
limit of 8 MiB.
"""

from __future__ import annotations

import bz2
import functools
import io
import subprocess
import sys
import textwrap
import time
import zlib
from collections.abc import Callable

import pytest

from archivey.config import DecoderLimits
from archivey.exceptions import ResourceLimitError, ResourceUnavailableError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import (
    Codec,
    open_codec_stream,
    rapidgzip_worker,
)
from archivey.internal.streams.codecs.rapidgzip_child import (
    RapidgzipChildStream,
    crashed_on_data,
)
from archivey.internal.streams.codecs.stdlib_takeover import _StdlibOnAcceleratorError
from tests.conftest import requires

pytestmark = requires("rapidgzip")

_OUTPUT_SIZE = 64 << 20
_SMALL_LIMIT = 8 << 20


@functools.cache
def _zeros(wbits: int) -> bytes:
    """``_OUTPUT_SIZE`` zero bytes, compressed at level 9 in the format ``wbits`` names."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, wbits)
    block = bytes(1 << 20)
    parts = [compressor.compress(block) for _ in range(_OUTPUT_SIZE >> 20)]
    return b"".join([*parts, compressor.flush()])


def _read_in_chunks(read: Callable[[int], bytes]) -> int:
    """Call ``read`` in 1 MiB reads to the end; check every byte is zero; return the
    count."""
    total = 0
    while True:
        data = read(1 << 20)
        if not data:
            return total
        assert data.count(0) == len(data)
        total += len(data)


def _read_until_stopped(child: RapidgzipChildStream) -> ResourceLimitError:
    """Read ``child`` from the start, again and again, until a read raises
    ``ResourceLimitError``; fail after 20 seconds, well inside the suite's 60-second
    ``--timeout``, which would end the whole worker and hide this message.

    The child checks its memory from a thread every millisecond. On a busy machine
    that thread can wait long enough for the whole stream to be decoded first, but the
    peak stays over the limit, so the child stops at the thread's next check.
    """
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            _read_in_chunks(child.read)
            child.seek(0)
        except ResourceLimitError as exc:
            return exc
        time.sleep(0.05)
    pytest.fail("the child was not stopped at its memory limit")


def test_a_child_over_its_memory_limit_is_stopped() -> None:
    """The child is stopped, and the error names the limit. It is marked so that the
    codec hands the stream to the standard library."""
    with RapidgzipChildStream(
        io.BytesIO(_zeros(31)), label="gzip", max_memory=_SMALL_LIMIT
    ) as child:
        error = _read_until_stopped(child)
        assert "max_decoder_memory" in str(error)
        assert crashed_on_data(error)
        # A configured limit, not a shortage of the system.
        assert not isinstance(error, ResourceUnavailableError)
        # Every later call raises the same error.
        with pytest.raises(ResourceLimitError):
            child.read(1)


@functools.cache
def _bzip2_zeros() -> bytes:
    """``_OUTPUT_SIZE`` zero bytes, compressed with bzip2."""
    compressor = bz2.BZ2Compressor(9)
    block = bytes(1 << 20)
    parts = [compressor.compress(block) for _ in range(_OUTPUT_SIZE >> 20)]
    return b"".join([*parts, compressor.flush()])


def test_a_bzip2_child_names_its_own_setting() -> None:
    """The bzip2 decoder is turned off by ``use_indexed_bzip2``, so that is the setting
    the error suggests; ``use_rapidgzip`` would change nothing for this stream."""
    with RapidgzipChildStream(
        io.BytesIO(_bzip2_zeros()), label="bzip2", bzip2=True, max_memory=_SMALL_LIMIT
    ) as child:
        error = _read_until_stopped(child)
        assert "use_indexed_bzip2=AcceleratorMode.OFF" in str(error)
        assert "use_rapidgzip" not in str(error)


# A parent whose peak resident memory is far above what the child decodes to. Run in
# its own process, so the peak it raises is not the test worker's.
_STOPPED_UNDER_A_LARGE_PARENT = textwrap.dedent(
    """
    import io, sys, zlib
    from archivey.exceptions import ResourceLimitError
    from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream

    # Touch every page, then free them: the peak stays, the memory does not.
    ballast = bytearray(int(sys.argv[1]))
    for i in range(0, len(ballast), 4096):
        ballast[i] = 1
    del ballast

    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    block = bytes(1 << 20)
    data = b"".join([*(compressor.compress(block) for _ in range(64)), compressor.flush()])
    with RapidgzipChildStream(io.BytesIO(data), label="gzip", max_memory=8 << 20) as child:
        try:
            while child.read(1 << 20):
                pass
        except ResourceLimitError:
            print("stopped")
        else:
            print("not stopped")
    """
)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux carries the parent's peak memory into the child's getrusage",
)
def test_the_limit_counts_from_the_childs_own_memory_not_the_parents_peak() -> None:
    """On Linux, a child's ``getrusage`` peak starts at its parent's peak: ``exec``
    keeps the high-water mark of the memory it replaces, which is the parent's. With
    that as the start, a child in a parent that once held more than the child's
    decode plus the limit was never stopped. The parent here raises its peak to 256
    MiB, more than the 64 MiB the child decodes to, and frees it again."""
    result = subprocess.run(
        [sys.executable, "-c", _STOPPED_UNDER_A_LARGE_PARENT, str(256 << 20)],
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "stopped"


def test_a_child_under_its_memory_limit_reads_the_whole_stream() -> None:
    with RapidgzipChildStream(
        io.BytesIO(_zeros(31)), label="gzip", max_memory=1 << 30
    ) as child:
        assert _read_in_chunks(child.read) == _OUTPUT_SIZE


def test_a_limit_past_what_the_open_frame_holds_reads_the_whole_stream() -> None:
    """``DecoderLimits`` puts no upper bound on ``max_decoder_memory``, but the ``OPEN``
    frame carries a signed 64-bit integer. A larger cap, such as ``10**20`` written to
    mean "effectively unlimited", raised ``struct.error`` out of the open. It is now
    sent as the largest value the frame holds, which is still a cap and not "none"."""
    with RapidgzipChildStream(
        io.BytesIO(_zeros(31)), label="gzip", max_memory=1 << 63
    ) as child:
        assert _read_in_chunks(child.read) == _OUTPUT_SIZE


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the /proc fallback is Linux only"
)
def test_on_linux_an_unreadable_proc_reports_no_peak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Where ``/proc/self/status`` cannot be read (``/proc`` not mounted, ``hidepid``,
    a sandbox), the child reports no peak, so no cap applies. It does not fall back to
    ``getrusage``, whose peak on Linux starts at the parent's (see the test above), so
    a cap counted from it would leave the child as much extra room as the parent once
    held."""

    def refuse(*args: object, **kwargs: object) -> object:
        raise PermissionError(13, "Permission denied", "/proc/self/status")

    monkeypatch.setattr(rapidgzip_worker, "open", refuse, raising=False)
    assert rapidgzip_worker._peak_memory() is None


_CODECS = pytest.mark.parametrize(
    ("codec", "wbits"),
    [(Codec.GZIP, 31), (Codec.ZLIB, 15), (Codec.DEFLATE, -15)],
    ids=["gzip", "zlib", "deflate"],
)


def _takeover(stream: object) -> _StdlibOnAcceleratorError:
    """The ``_StdlibOnAcceleratorError`` under ``stream``, whose ``switched`` says
    whether the standard library took over from the child."""
    inner = stream
    while inner is not None and not isinstance(inner, _StdlibOnAcceleratorError):
        inner = getattr(inner, "_inner", None)
    assert isinstance(inner, _StdlibOnAcceleratorError), stream
    assert isinstance(inner._inner, RapidgzipChildStream)
    return inner


@_CODECS
def test_the_standard_library_reads_on_after_the_limit(
    codec: Codec, wbits: int
) -> None:
    """With the accelerator ON and a small limit, the child is stopped and the
    standard library takes over, the whole output is still delivered, and a seek back
    to the start works after the takeover.

    The child checks its memory before each read reply, so a second pass over the
    stream trips the limit even when the first one finished before any check saw the
    peak; the loop allows for more passes on a busy machine, up to 20 seconds.
    """
    config = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.ON,
        decoder_limits=DecoderLimits(max_decoder_memory=_SMALL_LIMIT),
    )
    with open_codec_stream(codec, io.BytesIO(_zeros(wbits)), config=config) as stream:
        takeover = _takeover(stream)
        deadline = time.monotonic() + 20
        while True:
            assert _read_in_chunks(stream.read) == _OUTPUT_SIZE
            assert stream.seek(0) == 0
            if takeover.switched or time.monotonic() > deadline:
                break
        assert takeover.switched, "the child was not stopped at its memory limit"
        assert stream.read(4) == bytes(4)
        assert _read_in_chunks(stream.read) == _OUTPUT_SIZE - 4


@_CODECS
def test_no_limit_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch, codec: Codec, wbits: int
) -> None:
    """With ``DecoderLimits.UNLIMITED`` the child decodes the whole stream, whatever
    the caller's environment holds: the limit travels in the child's ``OPEN`` frame,
    and no environment variable can set one. A limit of 0 read from the variable set
    here would stop the child at once."""
    monkeypatch.setenv("ARCHIVEY_RAPIDGZIP_MAX_MEMORY", "0")
    config = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.ON,
        decoder_limits=DecoderLimits.UNLIMITED,
    )
    with open_codec_stream(codec, io.BytesIO(_zeros(wbits)), config=config) as stream:
        takeover = _takeover(stream)
        for _ in range(2):
            assert _read_in_chunks(stream.read) == _OUTPUT_SIZE
            assert stream.seek(0) == 0
        assert not takeover.switched
