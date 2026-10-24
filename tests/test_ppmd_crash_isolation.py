"""PPMd on corrupt input fails cleanly, and valid input decodes the same on both paths.

pyppmd (1.3.1, and 1.2.0) segfaults when asked to decode after a corrupt stream has
hit its end early. Every PPMd member therefore decodes in a child process
(``ppmd_child``, on the shared decoder worker), unless ``process_isolation`` is
``NONE``; there ``PpmdDecoder`` hands pyppmd a member whole when it is at most
``DecoderLimits.max_ppmd_held_input`` of compressed input. The hostile-input
tests run in a fresh interpreter so that a regression fails the test instead of
killing the session.
"""

from __future__ import annotations

import contextlib
import io
import marshal
import os
import random
import signal
import struct
import subprocess
import sys
import textwrap
import time
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import DecoderLimits, ProcessIsolation
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    ReadError,
    ResourceUnavailableError,
    TruncatedError,
)
from archivey.internal.config import StreamConfig
from archivey.internal.streams.child_process import is_crash
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    PpmdCodec,
    decoder_child,
    deps,
    open_codec_stream,
    ppmd_decoder,
)
from archivey.internal.streams.codecs.decoder_child import (
    POOL,
    DecoderChildReportedError,
    DecoderChildStartError,
    start_error,
)
from archivey.internal.streams.codecs.decoder_worker import CALL
from archivey.internal.streams.codecs.isolated import PPMD_ERRORS, ChildPpmdDecoder
from archivey.internal.streams.codecs.ppmd_child import (
    PpmdChildAllocationError,
    _PpmdChild,
    open_ppmd_child,
    ppmd_child_unavailable_reason,
)
from tests.conftest import requires, requires_binary, run_7z
from tests.corruption_util import raises_corruption_not_truncation
from tests.test_ppmd_raw_streams import (
    _MEM,
    _ORDER,
    _encode_ppmd7,
    _run_ppmd_child,
)

pytestmark = requires("pyppmd")

# Paths: "whole" is ``NONE``'s in-process hold; "child" is the default.
_PATHS = ["whole", "child"]


def _config(path: str) -> StreamConfig:
    if path == "child":
        return StreamConfig()
    return StreamConfig(process_isolation=ProcessIsolation.NONE)


def _params(variant: int, packed_len: int, unpack_size: int | None) -> CodecParams:
    if variant == 7:
        return CodecParams(
            properties=struct.pack("<BL", _ORDER, _MEM),
            unpack_size=unpack_size,
            pack_size=packed_len,
        )
    return CodecParams(
        ppmd_order=_ORDER,
        ppmd_mem_size=_MEM,
        unpack_size=unpack_size,
        pack_size=packed_len,
    )


@pytest.fixture(autouse=True)
def _empty_pool() -> Iterator[None]:
    POOL.close_idle()
    yield
    POOL.close_idle()


def _count_child_starts(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    started: list[bool] = []
    real = ppmd_decoder.open_ppmd_child

    def counting(**kwargs: int) -> ChildPpmdDecoder:
        started.append(True)
        return real(**kwargs)

    monkeypatch.setattr(ppmd_decoder, "open_ppmd_child", counting)
    return started


@pytest.fixture
def ppmd_config(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[StreamConfig]:
    """The config for one path; afterwards, check that it was the path taken."""
    path = request.param
    started = _count_child_starts(monkeypatch)
    yield _config(path)
    assert bool(started) == (path == "child"), started


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("variant", [7, 8])
def test_random_input_raises_and_never_crashes(variant: int, path: str) -> None:
    """Random bytes (a wrong key, a hostile member) raise an archivey error.

    Every input starts with a zero byte, so PPMd7's range decoder accepts it and the
    model decodes garbage until it reaches an end. Before the hold, archivey then fed
    pyppmd the rest of the member, and every child of 100 such inputs segfaulted
    (7z and ZIP alike). Reads alternate between ``read()`` and 4 KiB ``read(n)``.
    """
    _run_ppmd_child(
        textwrap.dedent(
            f"""\
            import io, random
            from archivey.exceptions import ArchiveyError
            from archivey.internal.streams.codecs import Codec, open_codec_stream
            from tests.test_ppmd_crash_isolation import _config, _params

            config = _config({path!r})
            decoded_cleanly = 0
            for seed in range(40):
                data = b"\\\\0" + random.Random(seed).randbytes(128 * 1024 - 1)
                params = _params({variant}, len(data), 2 * len(data))
                try:
                    with open_codec_stream(
                        Codec.PPMD, io.BytesIO(data), params=params, config=config
                    ) as stream:
                        if seed % 2:
                            stream.read()
                        else:
                            while stream.read(4096):
                                pass
                except ArchiveyError:
                    pass
                else:
                    decoded_cleanly += 1
            # Twice the input's size is never what random bytes decode to.
            assert decoded_cleanly == 0, decoded_cleanly
            print("ok")
            """
        ),
        timeout=180.0,
    )


# A long run of one byte compresses to a long run of zero bytes, and a chunk boundary
# inside it raises pyppmd's ``eof`` on a valid stream (it never clears). A decoder that
# took "short at eof" as the end mid-member cut this member short.
# Its compressed size, about 200 KB, is past one 64 KiB read, so the child path is
# really taken when the hold limit is lowered.
_ZERO_RUN = (
    random.Random(7).randbytes(100_000)
    + bytes(600_000)
    + random.Random(8).randbytes(100_000)
)


@pytest.mark.parametrize("ppmd_config", _PATHS, indirect=True)
@pytest.mark.parametrize("read_size", [-1, 1000, 65536])
def test_valid_member_with_zero_runs_decodes_on_both_paths(
    ppmd_config: StreamConfig, read_size: int
) -> None:
    """PPMd7 only: pyppmd's own PPMd8 encoder cannot round-trip this payload (its
    decoder reports corruption on the encoder's output), while a 7-Zip-written ZIP
    PPMd member of it reads back intact."""
    packed = _encode_ppmd7(_ZERO_RUN)
    params = _params(7, len(packed), len(_ZERO_RUN))
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(packed), params=params, config=ppmd_config
    ) as stream:
        if read_size < 0:
            got = stream.read()
        else:
            parts = []
            while chunk := stream.read(read_size):
                parts.append(chunk)
            got = b"".join(parts)
    assert got == _ZERO_RUN


@pytest.mark.parametrize("ppmd_config", _PATHS, indirect=True)
def test_truncated_member_returns_its_prefix_then_raises(
    ppmd_config: StreamConfig,
) -> None:
    """A member cut short is handed over whole at compressed EOF, in this process.

    ``flush`` returns the first 64 KiB of output and the stream drains the rest, so a
    chunked reader still gets everything the truncated input decodes to (well past
    64 KiB here) before ``TruncatedError``.
    """
    payload, packed, cut = _truncated_text_member()
    params = _params(7, len(packed), len(payload))
    got = bytearray()
    with (
        open_codec_stream(
            Codec.PPMD, io.BytesIO(cut), params=params, config=ppmd_config
        ) as stream,
        pytest.raises(TruncatedError),
    ):
        while chunk := stream.read(4096):
            got += chunk
    assert len(got) > 65536
    assert bytes(got) == payload[: len(got)]


def _truncated_text_member() -> tuple[bytes, bytes, bytes]:
    """``(payload, packed, cut)``: a text member and its first three quarters."""
    rng = random.Random(9)
    words = [rng.randbytes(6).hex().encode() for _ in range(20_000)]
    payload = b" ".join(rng.choice(words) for _ in range(60_000))  # ~780 KB of text
    packed = _encode_ppmd7(payload)
    return payload, packed, packed[: len(packed) * 3 // 4]


def test_truncated_member_read_whole_asks_bounded_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``read()`` on a truncated member: after the handover at compressed EOF, no
    request asks pyppmd for more than one 64 KiB chunk, and nothing is asked after a
    short return (the member has ended)."""
    import pyppmd

    calls: list[tuple[int, int, int]] = []
    real = pyppmd.Ppmd7Decoder

    class Spy:
        def __init__(self, *args: int) -> None:
            self._real = real(*args)

        def decode(self, data: bytes, length: int) -> bytes:
            out = self._real.decode(data, length)
            calls.append((len(data), length, len(out)))
            return out

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

    monkeypatch.setattr(pyppmd, "Ppmd7Decoder", Spy)
    payload, packed, cut = _truncated_text_member()
    params = _params(7, len(packed), len(payload))
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(cut), params=params, config=_config("whole")
    ) as stream:
        got = bytearray()
        with pytest.raises(TruncatedError):
            got += stream.read()
    assert calls, calls
    handover = next(i for i, (size, _, _) in enumerate(calls) if size)
    after = calls[handover:]
    assert all(length <= 65536 for _, length, _ in after), after
    first_short = next(i for i, (_, length, out) in enumerate(after) if out < length)
    # At most the one documented extra NUL follows the short return, bounded at 64.
    assert all(length <= 64 for _, length, _ in after[first_short + 1 :]), after


@pytest.mark.parametrize(
    "isolation",
    [ProcessIsolation.KNOWN_CRASHES, ProcessIsolation.NATIVE_DECODERS],
    ids=lambda i: i.name,
)
def test_without_a_child_process_a_member_is_refused(
    monkeypatch: pytest.MonkeyPatch, isolation: ProcessIsolation
) -> None:
    """A frozen app cannot start a child: ``ResourceUnavailableError`` naming the setting
    that would decode it here. That is ``NONE`` under every other setting, since
    ``KNOWN_CRASHES`` isolates PPMd too."""
    monkeypatch.setattr(
        ppmd_decoder, "ppmd_child_unavailable_reason", lambda: "no child here"
    )
    packed = _encode_ppmd7(b"small member " * 10)
    params = _params(7, len(packed), 130)
    config = StreamConfig(process_isolation=isolation)
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(packed), params=params, config=config
    ) as stream:
        with pytest.raises(ResourceUnavailableError, match="none can be started") as e:
            stream.read(10)
        # The refusal names why no child can start, and the way out.
        assert "(no child here)" in str(e.value)
        assert f"process_isolation={isolation.name}" in str(e.value)
        assert "ProcessIsolation.NONE" in str(e.value)
        assert "use ProcessIsolation.KNOWN_CRASHES" not in str(e.value)
        # The refusal sticks: a second read says the same, never a stray error.
        with pytest.raises(ResourceUnavailableError, match="none can be started"):
            stream.read(10)


def test_a_fresh_child_that_cannot_start_part_way_names_none() -> None:
    """A fresh child needed part-way through a member (the re-run after a reused
    child failed) that cannot start gives the advice the open gives: ``NONE``, under
    ``NATIVE_DECODERS`` too, since ``KNOWN_CRASHES`` isolates PPMd as well."""
    child = object.__new__(_PpmdChild)
    child._mem_size = _MEM
    child._setting = "NATIVE_DECODERS"
    error = child._fresh_child_error(start_error("no child here"))
    assert isinstance(error, ResourceUnavailableError)
    assert "process_isolation=NATIVE_DECODERS" in str(error)
    assert "ProcessIsolation.NONE" in str(error)
    assert "use ProcessIsolation.KNOWN_CRASHES" not in str(error)


@pytest.mark.parametrize("failure", ["spawn", "handshake"])
def test_a_child_that_cannot_start_is_a_resource_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    """A spawn refused by the OS, or a child that dies before its decoder is ready
    (it cannot import pyppmd), is the same ``ResourceUnavailableError`` as no child."""
    if failure == "spawn":

        def refuse(*args: object, **kwargs: object) -> None:
            raise PermissionError("fork refused by policy")

        monkeypatch.setattr(subprocess, "Popen", refuse)
    else:
        worker = tmp_path / "worker.py"
        worker.write_text("raise SystemExit(3)\n")
        monkeypatch.setattr(decoder_child, "WORKER", worker)
    packed = _encode_ppmd7(_ZERO_RUN)
    params = _params(7, len(packed), len(_ZERO_RUN))
    with (
        open_codec_stream(Codec.PPMD, io.BytesIO(packed), params=params) as stream,
        pytest.raises(ResourceUnavailableError, match="none can be started"),
    ):
        stream.read(10)


@pytest.mark.parametrize(
    "limits",
    [
        DecoderLimits(),
        DecoderLimits(max_ppmd_held_input=1024),
        DecoderLimits.UNLIMITED,
    ],
    ids=["held", "in-pieces", "unlimited"],
)
def test_none_decodes_in_process_and_never_starts_a_child(
    monkeypatch: pytest.MonkeyPatch, limits: DecoderLimits
) -> None:
    """Under ``NONE`` any member decodes here: held whole up to the limit, fed in
    pieces past it. No child process is started."""

    def no_child(**kwargs: object) -> None:
        raise AssertionError("no child process may be started")

    monkeypatch.setattr(ppmd_decoder, "open_ppmd_child", no_child)
    packed = _encode_ppmd7(_ZERO_RUN)
    params = _params(7, len(packed), len(_ZERO_RUN))
    config = StreamConfig(
        decoder_limits=limits, process_isolation=ProcessIsolation.NONE
    )
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(packed), params=params, config=config
    ) as stream:
        assert stream.read(10) == _ZERO_RUN[:10]
        assert stream.read() == _ZERO_RUN[10:]


def test_a_child_is_reused_after_a_clean_member_and_not_after_a_cut_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid members share a child; a member that ends early retires its child, since
    pyppmd may have damaged its memory there without crashing."""
    data = b"clean member " * 100
    packed = _encode_ppmd7(data)
    for _ in range(3):
        with open_codec_stream(
            Codec.PPMD, io.BytesIO(packed), params=_params(7, len(packed), len(data))
        ) as stream:
            assert stream.read() == data
    assert POOL.idle_count() == 1
    payload, full, cut = _truncated_text_member()
    POOL.close_idle()
    with (
        open_codec_stream(
            Codec.PPMD, io.BytesIO(cut), params=_params(7, len(full), len(payload))
        ) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()
    assert POOL.idle_count() == 0


def test_a_read_stopped_part_way_retires_its_child() -> None:
    """Closing a member before its end sends the quiesce decode, so its child is not
    reused (a confirmation probe pays a fresh child for this)."""
    data = b"clean member " * 10_000
    packed = _encode_ppmd7(data)
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(packed), params=_params(7, len(packed), len(data))
    ) as stream:
        assert stream.read(100) == data[:100]
    assert POOL.idle_count() == 0


def test_a_failed_check_above_the_decoder_retires_its_child() -> None:
    """A digest mismatch reported by the layer above (``spoil_child``) ends the child
    at close, even though the decode itself ended cleanly."""
    data = b"clean member " * 100
    packed = _encode_ppmd7(data)
    decoder = ppmd_decoder.PpmdDecoder(
        order=_ORDER, mem_size=_MEM, unpack_size=len(data), pack_size=len(packed)
    )
    out = decoder.feed(packed).data + decoder.flush().data
    assert out == data
    decoder.spoil_child()
    decoder.close()
    assert POOL.idle_count() == 0


def test_child_decoder_round_trip_and_errors() -> None:
    """The child answers like pyppmd, re-raises its errors, and dies cleanly."""
    packed = _encode_ppmd7(b"hello child " * 50)
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        assert child.decode(packed, 600) == b"hello child " * 50
    finally:
        child.close()
    child.close()  # idempotent

    bad = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        with pytest.raises(ValueError):
            bad.decode(b"\x00\x01", 10)  # under the 5 bytes pyppmd needs to start
    finally:
        bad.close()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        bad.decode(b"\x00" * 16, 10)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl and /proc")
def test_the_child_writes_no_core_dump() -> None:
    """The child crashes by design on hostile input, and its core is about the model
    the archive declared (up to 2 GiB by default). A crash handler that
    ``core_pattern`` pipes to gets it whatever ``RLIMIT_CORE`` says, while the parent
    waits. The child turns its dumps off: a core limit of 0, and not dumpable, which
    is what stops a piped dump."""
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        limits = Path(f"/proc/{_pid(child)}/limits").read_text()
    finally:
        child.close()
    core = next(line for line in limits.splitlines() if line.startswith("Max core"))
    assert core.split()[4:6] == ["0", "0"], core
    # Whether a process is dumpable shows only to itself (PR_GET_DUMPABLE), so the
    # worker's function is run in a fresh interpreter.
    probe = textwrap.dedent(
        """
        import ctypes
        from archivey.internal.streams.codecs.decoder_worker import disable_core_dumps
        disable_core_dumps()
        print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))  # PR_GET_DUMPABLE
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_sigint_to_the_child_does_not_stop_it() -> None:
    """A terminal's Ctrl-C signals the whole foreground process group, the decoder child
    included. The child ignores it: the parent decides what an interrupt means."""
    data = b"hello child " * 50
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        assert child.decode(_encode_ppmd7(data), 100) == data[:100]
        os.kill(_pid(child), signal.SIGINT)
        with pytest.raises(subprocess.TimeoutExpired):
            _process(child).proc.wait(timeout=0.5)
        assert child.decode(b"", len(data) - 100) == data[100:]
    finally:
        child.close()


def test_a_decode_after_close_is_not_a_corruption_verdict() -> None:
    """A closed decoder raises a usage error, which ``translate`` leaves alone."""
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    child.close()
    with pytest.raises(ArchiveyUsageError) as caught:
        child.decode(b"\x00" * 16, 10)
    assert PpmdCodec().translate(caught.value) is None


def test_child_error_of_unknown_type_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception the child reports with no mapping is not called corruption."""
    monkeypatch.setattr(decoder_child, "_BUILTIN_ERRORS", {})
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        with pytest.raises(DecoderChildReportedError, match="^builtins.ValueError: "):
            child.decode(b"\x00\x01", 10)
    finally:
        child.close()


def test_child_crash_surfaces_as_corruption_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crashed child is ``CorruptionError`` to the caller, and the caller lives on.
    ``faulthandler._sigsegv`` faults for real on every platform: on Windows ``os.kill``
    ends the process with a plain exit status, and ctypes turns a read of address 0
    into ``OSError``."""
    with raises_corruption_not_truncation(match="crashed"):
        _read_child_member(
            monkeypatch, tmp_path, "__import__('faulthandler')._sigsegv()"
        )


def _pid(child: ChildPpmdDecoder) -> int:
    return _process(child).proc.pid


def _process(child: ChildPpmdDecoder) -> decoder_child._Process:
    process = child._child._lease.process
    assert process is not None
    return process


# A stand-in worker: the shared decoder worker with its PPMd7 decoder replaced by one
# whose ``decode`` runs ``decode`` and whose constructor runs ``build``. The real frame
# and serve loop answer, so a protocol change reaches the fake too.
_STAND_IN = """\
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("decoder_worker", {worker!r})
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
class Fake:
    eof = False
    needs_input = True
    def __init__(self, *args):
        {build}
    def decode(self, data, length):
        {decode}
worker.LOADERS["ppmd7"] = lambda: Fake
worker.main()
"""


def _stand_in_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    decode: str = "return b''",
    build: str = "pass",
) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text(
        _STAND_IN.format(worker=str(decoder_child.WORKER), decode=decode, build=build),
        encoding="utf-8",
    )
    monkeypatch.setattr(decoder_child, "WORKER", worker)


def _read_child_member(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    decode: str = "return b''",
    build: str = "pass",
) -> None:
    """Decode a member on the child path through a stand-in worker."""
    _stand_in_worker(monkeypatch, tmp_path, decode, build)
    packed = _encode_ppmd7(_ZERO_RUN)
    params = _params(7, len(packed), len(_ZERO_RUN))
    with open_codec_stream(Codec.PPMD, io.BytesIO(packed), params=params) as stream:
        stream.read()


def test_a_child_that_dies_allocating_its_model_is_not_sent_in_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A child that imports pyppmd and dies constructing the decoder is refused.

    pyppmd aborts the process when the model's ``mem_size`` cannot be allocated. The
    message names ``mem_size`` and does not suggest decoding in-process, where the
    same allocation would abort the caller.
    """
    with pytest.raises(ResourceUnavailableError, match="mem_size=") as caught:
        _read_child_member(monkeypatch, tmp_path, build="os.abort()")
    assert "ProcessIsolation.NONE" not in str(caught.value)
    assert "none can be started" not in str(caught.value)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced on Linux"
)
def test_an_address_space_cap_below_mem_size_is_a_shortage_on_the_child_path() -> None:
    """The measured case: under ``RLIMIT_AS``, pyppmd's constructor aborts the child."""
    _run_ppmd_child(
        textwrap.dedent(
            """\
            import io, resource, struct
            from archivey.exceptions import ResourceUnavailableError
            from archivey.internal.config import StreamConfig
            from archivey.internal.streams.codecs import (
                Codec, CodecParams, open_codec_stream,
            )
            from tests.test_ppmd_crash_isolation import _ZERO_RUN
            from tests.test_ppmd_raw_streams import _ORDER, _encode_ppmd7

            # Past one read, so the member goes to the child before it is whole; the
            # declared 1 GiB model is what the child cannot allocate.
            data = _ZERO_RUN
            packed = _encode_ppmd7(data)
            params = CodecParams(
                properties=struct.pack("<BL", _ORDER, 1 << 30),
                unpack_size=len(data),
                pack_size=len(packed),
            )
            config = StreamConfig()
            resource.setrlimit(resource.RLIMIT_AS, (700 << 20, 700 << 20))
            try:
                with open_codec_stream(
                    Codec.PPMD, io.BytesIO(packed), params=params, config=config
                ) as stream:
                    stream.read(10)
            except ResourceUnavailableError as exc:
                assert "mem_size=1073741824" in str(exc), exc
                assert "in-process would fail" in str(exc), exc
                print("ok")
            """
        )
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize(
    ("sig", "expected", "match"),
    [
        ("SIGSEGV", CorruptionError, "crashed.*killed by SIGSEGV"),
        ("SIGABRT", CorruptionError, "crashed.*killed by SIGABRT"),
        ("SIGBUS", CorruptionError, "crashed.*killed by SIGBUS"),
        ("SIGKILL", ResourceUnavailableError, "killed by SIGKILL.*out-of-memory"),
        ("SIGTERM", ReadError, "killed by SIGTERM.*did not crash"),
        ("SIGHUP", ReadError, "killed by SIGHUP.*did not crash"),
    ],
)
def test_a_child_death_names_its_signal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sig: str,
    expected: type[Exception],
    match: str,
) -> None:
    """A crash signal is corruption; a signal from outside the decoder is not."""
    decode = f"os.kill(os.getpid(), signal.{sig})"
    with pytest.raises(expected, match=match) as caught:
        _read_child_member(monkeypatch, tmp_path, decode)
    assert type(caught.value) is expected


def test_a_child_death_names_its_exit_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A plain non-zero exit is not a crash, so not a verdict on the data."""
    with pytest.raises(ReadError, match="exit status 7.*did not crash") as caught:
        _read_child_member(monkeypatch, tmp_path, "os._exit(7)")
    assert not isinstance(caught.value, CorruptionError)


def test_is_crash_reads_fault_signals_and_ntstatus_as_crashes() -> None:
    assert is_crash(0xC0000005)  # Windows access violation
    assert not is_crash(7)
    assert not is_crash(None)
    if sys.platform != "win32":
        assert is_crash(-signal.SIGSEGV)
        assert not is_crash(-signal.SIGTERM)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize(
    ("decode", "expected"),
    [
        ("os.kill(os.getpid(), signal.SIGKILL)", ResourceUnavailableError),
        ("os._exit(7)", ReadError),
        ("os.kill(os.getpid(), signal.SIGSEGV)", CorruptionError),
    ],
)
def test_a_decode_after_a_child_death_raises_the_same_error_again(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    decode: str,
    expected: type[Exception],
) -> None:
    """Every later ``decode`` repeats the first death's verdict."""
    _stand_in_worker(monkeypatch, tmp_path, decode)
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    try:
        errors = []
        for _ in range(2):
            with pytest.raises(expected) as caught:
                child.decode(b"\x00" * 16, 10)
            errors.append(caught.value)
    finally:
        child.close()
    assert type(errors[0]) is type(errors[1]) is expected
    assert str(errors[0]) == str(errors[1])


def test_without_sys_executable_a_member_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An embedded interpreter may not know its path: no child, a clean refusal."""
    monkeypatch.setattr(sys, "executable", None)
    assert ppmd_child_unavailable_reason() is not None
    with pytest.raises(DecoderChildStartError, match="sys.executable"):
        open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    packed = _encode_ppmd7(_ZERO_RUN)
    params = _params(7, len(packed), len(_ZERO_RUN))
    with (
        open_codec_stream(Codec.PPMD, io.BytesIO(packed), params=params) as stream,
        pytest.raises(ResourceUnavailableError, match="sys.executable is not set"),
    ):
        stream.read(10)


def test_close_with_an_unread_reply_does_not_wait_for_the_timeout() -> None:
    """A child blocked writing a reply nobody reads is ended at once by ``close``."""
    data = b"hello child " * 200_000
    packed = _encode_ppmd7(data)
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    header = marshal.dumps(("decode", (len(data),), {}, True))
    _process(child).send(CALL, len(header), header, packed)
    # A request is never left in flight but by an interrupt, which retires the child.
    child.spoil()
    started = time.monotonic()
    child.close()
    assert time.monotonic() - started < 2.0


def test_an_interrupted_reply_leaves_the_decoder_unusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reply cut short by an interrupt is not followed by a read of stale bytes."""
    data = b"hello child " * 50
    packed = _encode_ppmd7(data)
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    real_read_exact = decoder_child.read_exact_or_none
    calls: list[int] = []

    def interrupt_payload(stream: io.BufferedReader, size: int) -> bytes | None:
        calls.append(size)
        if len(calls) == 2:  # the state, after the reply header
            raise KeyboardInterrupt
        return real_read_exact(stream, size)

    try:
        monkeypatch.setattr(decoder_child, "read_exact_or_none", interrupt_payload)
        with pytest.raises(KeyboardInterrupt):
            child.decode(packed, len(data))
        monkeypatch.setattr(decoder_child, "read_exact_or_none", real_read_exact)
        with pytest.raises(ArchiveyUsageError, match="interrupted in the middle of a"):
            child.decode(packed, len(data))
    finally:
        child.close()


def test_every_error_the_child_reports_translates_as_it_would_in_process() -> None:
    """The stand-ins and ``PpmdCodec.translate`` agree with the real types."""
    pyppmd = deps.pyppmd.load()  # translate knows the real type once it is loaded

    codec = PpmdCodec()
    for (_module, name), stand_in in PPMD_ERRORS.items():
        assert name == "PpmdError"
        native = codec.translate(pyppmd.PpmdError("x"))
        reported = codec.translate(stand_in("x"))
        assert type(native) is type(reported) is CorruptionError
    for cls in decoder_child._BUILTIN_ERRORS.values():
        # Rebuilt as themselves, so translated as in-process.
        assert (
            decoder_child.rebuild_error(
                f"builtins\n{cls.__qualname__}\n\nx".encode(), {}
            ).__class__
            is cls
        )


def _ppmd_archive_with_crc(tmp_path: Path, archive_type: str, *, wrong: bool) -> Path:
    """A one-member PPMd archive written by ``7z``, its stored CRC flipped when
    ``wrong``: the decode ends cleanly, and only the digest check above it fails."""
    data = b"clean member with a stored crc\n" * 2000
    (tmp_path / "member.txt").write_bytes(data)
    archive = tmp_path / f"out.{archive_type}"
    method = "-mm=PPMd" if archive_type == "zip" else "-m0=PPMd"
    switches = [] if archive_type == "zip" else ["-mhc=off"]
    result = run_7z(
        ["a", f"-t{archive_type}", method, *switches, str(archive), "member.txt"],
        cwd=tmp_path,
    )
    if result.returncode != 0:
        pytest.skip(f"7z cannot write PPMd {archive_type}")
    if wrong:
        crc = struct.pack("<I", zlib.crc32(data))
        raw = archive.read_bytes()
        assert crc in raw
        raw = bytearray(raw.replace(crc, struct.pack("<I", zlib.crc32(data) ^ 1)))
        if archive_type == "7z":
            # Re-seal the header: its own CRC, then the start header's over that.
            offset, size = struct.unpack_from("<QQ", raw, 12)
            header = raw[32 + offset : 32 + offset + size]
            struct.pack_into("<I", raw, 28, zlib.crc32(header))
            struct.pack_into("<I", raw, 8, zlib.crc32(raw[12:32]))
        archive.write_bytes(raw)
    return archive


@requires_binary("7z")
@pytest.mark.parametrize("archive_type", ["zip", "7z"])
@pytest.mark.parametrize("wrong", [False, True], ids=["crc-ok", "crc-wrong"])
def test_a_member_whose_crc_does_not_match_retires_its_child(
    tmp_path: Path, archive_type: str, wrong: bool
) -> None:
    """The mismatch is raised by the member stream, above the decoder, after a decode
    that ended cleanly; the child must still not serve another member."""
    archive = _ppmd_archive_with_crc(tmp_path, archive_type, wrong=wrong)
    POOL.close_idle()
    with open_archive(archive) as ar:
        (member,) = ar.members()
        if wrong:
            with raises_corruption_not_truncation():
                ar.read(member)
        else:
            ar.read(member)
    assert POOL.idle_count() == (0 if wrong else 1)


def test_a_model_a_fresh_child_cannot_allocate_part_way_is_a_shortage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The move to a fresh child part-way through a member builds the model again;
    if that child cannot allocate it, the caller gets the ``ResourceUnavailableError``
    the same failure gives when the member opens, not a bare internal error."""
    packed = _encode_ppmd7(b"hello child " * 50)
    first = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    assert first.decode(packed, 600) == b"hello child " * 50
    first.close()
    child = open_ppmd_child(variant=7, order=_ORDER, mem_size=_MEM)
    inner = child._child
    assert inner.served_before

    def cannot_allocate() -> None:
        raise PpmdChildAllocationError("fake: the model does not fit")

    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 0)
    monkeypatch.setattr(inner, "_open", cannot_allocate)
    try:
        with pytest.raises(
            ResourceUnavailableError, match="the model does not fit"
        ) as info:
            child.decode(packed, 600)
        assert "Decoder limit reached" not in str(info.value)
    finally:
        child.close()


def _solid_ppmd_7z(tmp_path: Path, *, wrong: bool) -> Path:
    """Two members in one solid PPMd folder, the second's stored CRC flipped and the
    header re-sealed when ``wrong``."""
    second = b"second member of the folder\n" * 2000
    (tmp_path / "a.txt").write_bytes(b"first member of the folder\n" * 2000)
    (tmp_path / "b.txt").write_bytes(second)
    archive = tmp_path / "solid.7z"
    result = run_7z(
        ["a", "-t7z", "-m0=PPMd", "-mhc=off", "-ms=on", str(archive)]
        + ["a.txt", "b.txt"],
        cwd=tmp_path,
    )
    if result.returncode != 0:
        pytest.skip("7z cannot write PPMd")
    if not wrong:
        return archive
    raw = bytearray(archive.read_bytes())
    crc = struct.pack("<I", zlib.crc32(second))
    assert raw.count(crc) == 1
    raw = bytearray(raw.replace(crc, struct.pack("<I", zlib.crc32(second) ^ 1)))
    offset, size = struct.unpack_from("<QQ", raw, 12)
    struct.pack_into("<I", raw, 28, zlib.crc32(raw[32 + offset : 32 + offset + size]))
    struct.pack_into("<I", raw, 8, zlib.crc32(raw[12:32]))
    archive.write_bytes(raw)
    return archive


@requires_binary("7z")
@pytest.mark.parametrize("how", ["read", "stream_members", "extract_all"])
@pytest.mark.parametrize("wrong", [False, True], ids=["crc-ok", "crc-wrong"])
def test_a_solid_member_whose_crc_does_not_match_retires_the_folder_child(
    tmp_path: Path, how: str, wrong: bool
) -> None:
    """A solid folder's members share one decoder; each way of reading the bad member
    reaches it (the data pass hands out slices of the folder, not of a decode). The
    intact archive gives its child back, so 0 means retired, not never taken."""
    archive = _solid_ppmd_7z(tmp_path, wrong=wrong)
    POOL.close_idle()
    expect = raises_corruption_not_truncation() if wrong else contextlib.nullcontext()
    with open_archive(archive) as ar, expect:
        if how == "read":
            ar.read(next(m for m in ar.members() if m.name == "b.txt"))
        elif how == "stream_members":
            for _member, stream in ar.stream_members():
                if stream is not None:
                    stream.read()
        else:
            ar.extract_all(tmp_path / "out")
    assert POOL.idle_count() == (0 if wrong else 1)
