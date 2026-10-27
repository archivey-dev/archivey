"""rapidgzip aborts the process on a truncated DEFLATE stream; archivey must not.

rapidgzip 0.16 calls ``std::terminate`` (SIGABRT, "The bit buffer should not contain more
data than have been read from the file!") when it decodes a gzip, zlib or raw DEFLATE stream
that ends early. The throw comes from a destructor in its chunk decoder, so it happens for a
path, a real file object and an in-memory buffer alike, and no ``try/except`` in Python can
catch it. So archivey runs rapidgzip in a child process (``rapidgzip_child.py``), and the
abort becomes an archivey error.

Every case that could abort runs in a child interpreter as well, so a regression fails the
test and does not kill pytest.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import importlib.metadata
import io
import logging
import os
import random
import signal
import subprocess
import sys
import textwrap
import threading
import zlib
from pathlib import Path
from typing import NoReturn

import pytest

from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    ReadError,
    ResourceUnavailableError,
    TruncatedError,
)
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import codecs as codecs_module
from archivey.internal.streams.child_process import outside_death
from archivey.internal.streams.codecs import Codec, open_codec_stream, rapidgzip_child
from archivey.internal.streams.codecs.rapidgzip_child import (
    RapidgzipChildReportedError,
    RapidgzipChildStream,
)
from archivey.internal.streams.codecs.rapidgzip_worker import ERR, READ, SEEK
from tests.conftest import requires
from tests.corruption_util import is_corruption_not_truncation

pytestmark = requires("rapidgzip")

# Cut sizes from the original report. The canary test below checks that each one aborts
# raw rapidgzip on this payload.
_CUTS = [500, 1500, 3000]

_ON = StreamConfig(
    seekable=True,
    use_rapidgzip=AcceleratorMode.ON,
    use_indexed_bzip2=AcceleratorMode.ON,
)
_OFF = StreamConfig(
    seekable=True,
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
)
# Every codec rapidgzip decodes in a child process.
_CHILD_CODECS = [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE, Codec.BZIP2]
_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

# On Linux the truncation detail survives, in the child's abort message or in the
# exception rapidgzip raises instead ("Unexpected end of file", from a build that does
# not abort), so it maps to TruncatedError either way. Elsewhere the detail can be lost
# (Windows aborts without the message), and a truncation reported without it maps to
# CorruptionError (see ``_translate_rapidgzip``).
_TRUNCATION_ERRORS = (
    {"archivey.exceptions TruncatedError"}
    if sys.platform.startswith("linux")
    else {"archivey.exceptions TruncatedError", "archivey.exceptions CorruptionError"}
)


def _payload() -> bytes:
    """About 2.2 MB of base64 text, which compresses to about 1.6 MB: over the 1 MiB
    AUTO threshold the ``open_archive`` harness sets (the shipped one is 16 MiB)."""
    return base64.encodebytes(random.Random(0).randbytes(1_600_000))


def _compress(codec: Codec, data: bytes) -> bytes:
    if codec is Codec.BZIP2:
        return bz2.compress(data)
    if codec is Codec.GZIP:
        return gzip.compress(data)
    if codec is Codec.ZLIB:
        return zlib.compress(data)
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    # faulthandler on, as CI runs and as a user may: the decoder child inherits it, and
    # on SIGABRT it writes a stack dump (from 3.14 with the C stack, several KiB) after
    # rapidgzip's abort message.
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONFAULTHANDLER": "1"},
        check=False,
    )


def _assert_clean_exit(
    proc: subprocess.CompletedProcess[str], expected: str | set[str]
) -> None:
    # An abort kills the child before it prints its result line: a negative return code
    # (SIGABRT is -6) on POSIX, exit code 3 on Windows.
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr[-2000:])
    allowed = {expected} if isinstance(expected, str) else expected
    assert proc.stdout.strip().splitlines()[-1] in allowed, proc.stdout


_RAW_RAPIDGZIP = """
import sys, rapidgzip
stream = rapidgzip.open(sys.argv[1], parallelization=0)
outcome = "CLEAN"
try:
    while stream.read(1 << 20):
        pass
except Exception as exc:
    outcome = "RAISED " + type(exc).__name__
stream.close()
print(outcome)
"""


def _is_prebuilt_linux_wheel(wheel_metadata: str) -> bool:
    """True if a ``WHEEL`` file's tags name a PyPI Linux wheel (manylinux or musllinux).

    A build from source carries a plain ``linux_x86_64`` tag instead.
    """
    return any(
        line.startswith("Tag:") and ("manylinux" in line or "musllinux" in line)
        for line in wheel_metadata.splitlines()
    )


def _rapidgzip_is_prebuilt_linux_wheel() -> bool:
    """True if the installed rapidgzip came from one of its prebuilt Linux wheels."""
    wheel = importlib.metadata.distribution("rapidgzip").read_text("WHEEL")
    if wheel is None:
        raise AssertionError(
            "rapidgzip has no WHEEL metadata, so the canary cannot tell which build "
            "it is testing"
        )
    return _is_prebuilt_linux_wheel(wheel)


@pytest.mark.parametrize(
    ("tags", "prebuilt"),
    [
        (
            "Tag: cp311-cp311-manylinux_2_27_x86_64\nTag: cp311-cp311-manylinux_2_28_x86_64",
            True,
        ),
        ("Tag: cp312-cp312-musllinux_1_2_x86_64", True),
        ("Tag: cp315-cp315-linux_x86_64", False),
        ("Tag: cp314-cp314-macosx_11_0_arm64", False),
    ],
)
def test_prebuilt_linux_wheel_tags(tags: str, prebuilt: bool) -> None:
    wheel = f"Wheel-Version: 1.0\nGenerator: setuptools (71.1.0)\nRoot-Is-Purelib: false\n{tags}\n"
    assert _is_prebuilt_linux_wheel(wheel) is prebuilt


@pytest.mark.parametrize("cut", _CUTS)
def test_raw_rapidgzip_aborts_on_truncated_gzip(tmp_path: Path, cut: int) -> None:
    """Canary: the upstream hazard the child process guards against still exists.

    rapidgzip 0.16's prebuilt Linux wheels (manylinux and musllinux) abort on each of
    these inputs. The macOS build raises an exception on them instead ("Unexpected end
    of file when getting block ..."), and so can a build from source: on CPython 3.15,
    which has no wheel yet, the build on the GitHub runner raised and a local one
    aborted. So only a prebuilt Linux wheel must abort; any other build may abort or
    raise. Every build must not decode the truncated input without an error. If a later
    Linux wheel stops aborting, this test fails: the signal that rapidgzip may be safe
    to run in-process again.
    """
    path = _write(tmp_path, "cut.gz", gzip.compress(_payload())[:-cut])
    proc = _run(_RAW_RAPIDGZIP, str(path))
    if proc.returncode != 0:
        return  # aborted: the hazard is present
    assert not _rapidgzip_is_prebuilt_linux_wheel(), (
        "no abort",
        proc.stdout,
        proc.stderr,
    )
    assert proc.stdout.strip().startswith("RAISED "), (proc.stdout, proc.stderr)


# Each access pattern a caller can use on a member: read straight through; read part,
# seek back and read again; read to the end first, then seek back; seek to the end; read
# on past a caught error, then seek back. Each must raise an archivey error, and must not
# abort. After the child has died, every later call raises the same error.
_PATTERNS = """
def straight(stream):
    while stream.read(1 << 20):
        pass

def back(stream):
    stream.read(1 << 20)
    stream.seek(0)
    straight(stream)

def end_then_back(stream):
    try:
        straight(stream)
    except Exception:
        pass
    stream.seek(1000)
    straight(stream)

def to_end(stream):
    stream.seek(-100, 2)
    straight(stream)

def past_error_then_back(stream):
    for _ in range(2):
        try:
            straight(stream)
        except Exception:
            pass
    stream.seek(0)
    straight(stream)

def read_all_past_error_then_back(stream):
    for _ in range(2):
        try:
            stream.read()
        except Exception:
            pass
    stream.seek(0)
    stream.read()

PATTERNS = {
    "straight": straight,
    "back": back,
    "end_then_back": end_then_back,
    "to_end": to_end,
    "past_error_then_back": past_error_then_back,
    "read_all_past_error_then_back": read_all_past_error_then_back,
}
"""

_ACCESS = [
    "straight",
    "back",
    "end_then_back",
    "to_end",
    "past_error_then_back",
    "read_all_past_error_then_back",
]

_OPEN_ARCHIVE = (
    _PATTERNS
    + """
import sys
import archivey
from archivey.internal.streams import codecs

# The shipped AUTO threshold is 16 MiB; lowered so AUTO takes these inputs to the child.
codecs.RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE = 1 << 20

path, mode, pattern = sys.argv[1], sys.argv[2], PATTERNS[sys.argv[3]]
source = path if mode == "path" else open(path, "rb")
try:
    with archivey.open_archive(source, seekable_members=True) as reader:
        for member in reader.members():
            with reader.open(member) as stream:
                pattern(stream)
    print("OK")
except Exception as exc:
    print(type(exc).__module__, type(exc).__name__)
finally:
    if mode != "path":
        source.close()
"""
)


@pytest.mark.parametrize("access", _ACCESS)
@pytest.mark.parametrize("mode", ["path", "stream"])
@pytest.mark.parametrize("cut", _CUTS)
def test_truncated_gzip_with_seekable_members_raises_truncated(
    tmp_path: Path, cut: int, mode: str, access: str
) -> None:
    """The reported case: ``seekable_members=True`` on a truncated ``.gz`` killed Python.

    The accelerator is AUTO here, as in the report, with the AUTO threshold lowered to
    the 1 MiB it had then, so these inputs still reach rapidgzip.
    """
    path = _write(tmp_path, "cut.gz", gzip.compress(_payload())[:-cut])
    proc = _run(_OPEN_ARCHIVE, str(path), mode, access)
    _assert_clean_exit(proc, _TRUNCATION_ERRORS)


_OPEN_CODEC = (
    _PATTERNS
    + """
import io, sys
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream

path, codec, mode = sys.argv[1], Codec(sys.argv[2]), sys.argv[3]
pattern = PATTERNS[sys.argv[4]]
config = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.ON)
if mode == "path":
    source = path
elif mode == "file":
    source = open(path, "rb")
else:
    source = io.BytesIO(open(path, "rb").read())
try:
    with open_codec_stream(codec, source, config=config) as stream:
        pattern(stream)
    print("OK")
except Exception as exc:
    print(type(exc).__module__, type(exc).__name__)
finally:
    if mode != "path":
        source.close()
"""
)


@pytest.mark.parametrize("access", _ACCESS)
@pytest.mark.parametrize("mode", ["path", "file", "bytesio"])
@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE])
def test_truncated_deflate_family_with_accelerator_on_raises_truncated(
    tmp_path: Path, codec: Codec, mode: str, access: str
) -> None:
    """Every rapidgzip codec, forced ON: the abort is in DEFLATE decoding, not in gzip.

    A ZIP or 7z member reaches the deflate and zlib codecs through a bounded view, so a
    member whose data is cut short is this case.
    """
    data = _compress(codec, _payload())[:-1500]
    path = _write(tmp_path, f"cut.{codec.value}", data)
    proc = _run(_OPEN_CODEC, str(path), codec.value, mode, access)
    _assert_clean_exit(proc, _TRUNCATION_ERRORS)


# --- the child stream serves the codec layer --------------------------------------------


@pytest.mark.parametrize("chunk", [4096, 1 << 20])
@pytest.mark.parametrize("cut", _CUTS)
@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE])
def test_what_a_cut_stream_delivers_before_the_abort_is_a_correct_prefix(
    tmp_path: Path, codec: Codec, cut: int, chunk: int
) -> None:
    """The bytes read before the error are the payload's own: neither the read-ahead
    buffer nor the standard library's takeover after the abort serves data from past
    the cut or out of order. The test below compares a large cut stream with the
    standard library byte for byte."""
    payload = _payload()
    path = _write(tmp_path, f"cut.{codec.value}", _compress(codec, payload)[:-cut])
    got = bytearray()
    with (
        open_codec_stream(codec, str(path), config=_ON) as stream,
        pytest.raises(CorruptionError),
    ):
        while block := stream.read(chunk):
            got += block
    assert len(got) < len(payload)
    assert payload.startswith(got)


@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE])
def test_a_large_cut_stream_delivers_what_the_standard_library_delivers(
    tmp_path: Path, codec: Codec
) -> None:
    """About 32 MB cut near the end. How much the child returns before it aborts is a
    race between rapidgzip's decoder threads (it returned nothing on some runs), and
    after the abort the standard library takes over from what the child delivered. So
    the caller always gets the standard library's bytes. Any byte the read-ahead buffer
    served wrongly, or a takeover from the wrong place, shows up as a difference. Two
    read sizes split the buffer both ways: 4096 uses up each power-of-two refill
    exactly, and 10,000 straddles refills."""
    payload = base64.encodebytes(random.Random(32).randbytes(24_000_000))
    cut = _compress(codec, payload)[:-500]
    path = _write(tmp_path, f"cut.{codec.value}", cut)
    wbits = {Codec.GZIP: 31, Codec.ZLIB: 15, Codec.DEFLATE: -15}[codec]
    expected = zlib.decompressobj(wbits).decompress(cut)
    got = bytearray()
    with open_codec_stream(codec, str(path), config=_ON) as stream:
        assert _has_child_stream(stream)
        with pytest.raises(TruncatedError):
            while block := stream.read(4096 if codec is Codec.GZIP else 10_000):
                got += block
    assert len(got) == len(expected)
    assert got == expected


@pytest.mark.parametrize("codec", _CHILD_CODECS)
@pytest.mark.parametrize("mode", ["path", "bytesio"])
def test_the_child_stream_reads_and_seeks_like_stdlib(
    tmp_path: Path, codec: Codec, mode: str
) -> None:
    payload = _payload()
    compressed = _compress(codec, payload)
    path = _write(tmp_path, "valid.bin", compressed)
    source = str(path) if mode == "path" else io.BytesIO(compressed)
    with open_codec_stream(codec, source, config=_ON) as stream:
        assert stream.read(1000) == payload[:1000]
        assert stream.tell() == 1000
        middle = len(payload) // 2
        assert stream.seek(middle) == middle
        assert stream.read(64) == payload[middle : middle + 64]
        assert stream.seek(-10, io.SEEK_END) == len(payload) - 10
        assert stream.read() == payload[-10:]
        assert stream.seek(5) == 5
        assert stream.read() == payload[5:]
        assert stream.tell() == len(payload)


def _child_stream(stream: object) -> RapidgzipChildStream:
    inner = stream
    while not isinstance(inner, RapidgzipChildStream):
        inner = inner._inner
    return inner


def _has_child_stream(stream: object) -> bool:
    inner: object = stream
    while inner is not None:
        if isinstance(inner, RapidgzipChildStream):
            return True
        inner = getattr(inner, "_inner", None)
    return False


def test_rewind_offset_comes_from_the_childs_index() -> None:
    payload = _payload()
    with open_codec_stream(
        Codec.ZLIB, io.BytesIO(zlib.compress(payload)), config=_ON
    ) as stream:
        child = _child_stream(stream)
        stream.read()
        offset = child.nearest_resume_offset(len(payload) // 2)
        assert offset is not None and 0 <= offset <= len(payload) // 2


def test_bzip2_runs_in_a_child_process() -> None:
    """rapidgzip's bzip2 decoder has not been seen to abort, but it runs in a child
    process too, as a precaution, since it comes from the same library as the DEFLATE
    decoder. This process never imports rapidgzip for it."""
    code = """
        import bz2, io, sys
        from archivey.internal.config import AcceleratorMode, StreamConfig
        from archivey.internal.streams.codecs import Codec, open_codec_stream
        from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
        config = StreamConfig(seekable=True, use_indexed_bzip2=AcceleratorMode.ON)
        source = io.BytesIO(bz2.compress(b"x" * 1000))
        with open_codec_stream(Codec.BZIP2, source, config=config) as stream:
            inner = stream
            while not isinstance(inner, RapidgzipChildStream):
                inner = getattr(inner, "_inner")
            assert stream.read() == b"x" * 1000
        print("rapidgzip" in sys.modules)
    """
    proc = _run(code)
    _assert_clean_exit(proc, "False")


# --- the caller's source ----------------------------------------------------------------


class _FailingSource(io.BytesIO):
    """The caller's own stream, failing on a read that starts past its first 64 KiB.

    Reads near the end still work, for the gzip ISIZE probe at open.
    """

    def __init__(self, data: bytes, exc: BaseException) -> None:
        super().__init__(data)
        self._exc = exc

    def read(self, size: int | None = -1, /) -> bytes:
        if 64 * 1024 < self.tell() < len(self.getbuffer()) - 64 * 1024:
            raise self._exc
        return super().read(size)


@pytest.mark.parametrize("error", [RuntimeError, EOFError])
@pytest.mark.parametrize("codec", _CHILD_CODECS)
def test_an_exception_from_the_callers_source_reaches_the_caller_unchanged(
    codec: Codec, error: type[Exception]
) -> None:
    """The child's reads of a stream source are served here; the caller's own exception
    from that source is raised as itself, not as a verdict on the data.

    ``EOFError`` is a type the codecs' stdlib translation maps to ``TruncatedError``
    (and a type a network file object raises on a dropped connection), so it shows the
    source's exception bypasses that translation too."""
    failure = error("caller source failed")
    source = _FailingSource(_compress(codec, _payload()), failure)
    with open_codec_stream(codec, source, config=_ON) as stream:
        with pytest.raises(error) as info:
            while stream.read(1 << 16):
                pass
        assert info.value is failure
        # The child was told its input ended where the source failed. Whatever it does
        # with that, it is not reported as a verdict on the data.
        with pytest.raises((error, ReadError)) as later:
            while stream.read(1 << 16):
                pass
        assert not isinstance(later.value, CorruptionError)


class _OverReadingSource(io.BytesIO):
    """A caller's stream that breaks the read contract: it returns more than asked."""

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        if size is not None and size > 0 and len(data) == size:
            return data + b"!"
        return data


def test_a_fault_archivey_raises_about_the_source_is_not_marked_as_the_sources() -> (
    None
):
    """Only what the caller's source itself raised is marked as the caller's (and so
    left untranslated): archivey's own guard against an over-long read is not."""
    source = _OverReadingSource(zlib.compress(_payload()))
    with (
        open_codec_stream(Codec.ZLIB, source, config=_ON) as stream,
        pytest.raises(ValueError, match="the excess is already consumed") as info,
    ):
        while stream.read(1 << 16):
            pass
    assert not rapidgzip_child.from_callers_source(info.value)


class _FailingOnceSource(io.BytesIO):
    """The caller's stream, failing once, on the first read past its middle; every
    other read works, so nothing but the stream's own state can stop a later read."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.failed = False

    def read(self, size: int | None = -1, /) -> bytes:
        size_ = len(self.getbuffer())
        if not self.failed and size_ // 2 < self.tell() < size_ - 64 * 1024:
            self.failed = True
            raise OSError("transient source fault")
        return super().read(size)


@pytest.mark.parametrize("codec", _CHILD_CODECS)
def test_after_a_source_fault_every_later_call_raises(codec: Codec) -> None:
    """The child was told its input ended where the source failed, so what it decodes
    after that is not the stream: no later call may return a clean end or a verdict on
    the data."""
    source = _FailingOnceSource(_compress(codec, _payload()))
    with open_codec_stream(codec, source, config=_ON) as stream:
        with pytest.raises(OSError, match="transient source fault") as first:
            while stream.read(1 << 16):
                pass
        assert rapidgzip_child.from_callers_source(first.value)
        messages = set()
        for call in (
            lambda: stream.read(1 << 16),
            lambda: stream.read(),
            lambda: stream.seek(0),
            lambda: stream.read(1),
        ):
            with pytest.raises(ReadError) as later:
                call()
            assert not isinstance(later.value, (CorruptionError, TruncatedError))
            assert "source" in str(later.value)
            messages.add(str(later.value))
        assert len(messages) == 1
        assert _child_stream(stream)._proc is None  # the child is stopped


# The caller's source can be a member stream of an outer archive, so the fault it raises
# can be one of archivey's own, whose text is already escaped once.
_ESCAPED_FAULT = "outer member n\x1bme is damaged"


def _assert_escaped_once(message: str) -> None:
    assert "n\\x1bme" in message  # the escape the outer error wrote, once
    assert "\\\\" not in message  # no backslash escaped a second time
    assert "CorruptionError(" not in message


def test_a_stopped_stream_escapes_a_source_fault_of_ours_once() -> None:
    with open_codec_stream(
        Codec.ZLIB, io.BytesIO(_compress(Codec.ZLIB, _payload())), config=_ON
    ) as stream:
        stream.read(1)
        child = _child_stream(stream)
        child._poison(CorruptionError(_ESCAPED_FAULT))
        with pytest.raises(ReadError) as later:
            child.read(1)
    _assert_escaped_once(str(later.value))


def test_a_child_death_after_a_source_fault_of_ours_is_escaped_once() -> None:
    with open_codec_stream(
        Codec.ZLIB, io.BytesIO(_compress(Codec.ZLIB, _payload())), config=_ON
    ) as stream:
        stream.read(1)
        death = _child_stream(stream)._child_died(
            caused_by_source=CorruptionError(_ESCAPED_FAULT)
        )
    assert isinstance(death, ReadError)
    _assert_escaped_once(str(death))


def test_an_interrupt_from_the_callers_source_leaves_the_stream_unusable() -> None:
    source = _FailingSource(_compress(Codec.ZLIB, _payload()), KeyboardInterrupt())
    with open_codec_stream(Codec.ZLIB, source, config=_ON) as stream:
        with pytest.raises(KeyboardInterrupt):
            while stream.read(1 << 16):
                pass
        with pytest.raises(ArchiveyUsageError, match="interrupted"):
            stream.read(1)


# --- how a child death is reported ------------------------------------------------------


@_POSIX
@pytest.mark.parametrize(
    ("sig", "expected"),
    [
        ("SIGKILL", ResourceUnavailableError),
        ("SIGTERM", ReadError),
        ("SIGSEGV", CorruptionError),
        ("SIGABRT", CorruptionError),
    ],
)
def test_a_child_death_is_reported_by_how_it_ended(
    tmp_path: Path, sig: str, expected: type[Exception]
) -> None:
    """Only a crash is a verdict on the data; SIGKILL is most often the OOM killer."""
    payload = _payload()
    path = _write(tmp_path, "valid.gz", gzip.compress(payload))
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child_stream(stream)
        assert stream.read(10) == payload[:10]
        assert child._proc is not None
        os.kill(child._proc.pid, getattr(signal, sig))
        child._proc.wait()
        with pytest.raises(expected) as first:
            child.seek(0)
        assert type(first.value) is expected
        assert sig in str(first.value)
        assert rapidgzip_child.crashed_on_data(first.value) is (
            expected is CorruptionError
        )
        # Every later call raises the same error again.
        with pytest.raises(expected) as second:
            child.read(1)
        assert type(second.value) is expected
        assert str(second.value) == str(first.value)


@_POSIX
@pytest.mark.parametrize(
    ("sig", "expected"),
    [("SIGKILL", ResourceUnavailableError), ("SIGTERM", ReadError)],
)
def test_a_child_killed_from_outside_ends_the_stream(
    tmp_path: Path, sig: str, expected: type[Exception]
) -> None:
    """A death that is no verdict on the data reaches the caller, every time."""
    payload = _payload()
    path = _write(tmp_path, "valid.gz", gzip.compress(payload))
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child_stream(stream)
        assert stream.read(10) == payload[:10]
        assert child._proc is not None
        os.kill(child._proc.pid, getattr(signal, sig))
        child._proc.wait()
        with pytest.raises(expected) as first:
            stream.seek(0)
        assert type(first.value) is expected
        with pytest.raises(expected) as second:
            stream.read(1)
        assert str(second.value) == str(first.value)


@pytest.mark.parametrize("returncode", [-9, -15, 1])
def test_an_outside_death_message_is_escaped_once(returncode: int) -> None:
    """``outside_death`` gives the unescaped message, so the exception the caller
    builds from it escapes a backslash or a control character once, not twice."""
    what = "ended C:\\path\x1b"
    cls, message = outside_death(returncode, what)
    exc = cls(message)
    assert exc.raw_message.startswith(what)
    assert str(exc).startswith("ended C:\\\\path\\x1b")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl and /proc")
def test_the_child_writes_no_core_dump(tmp_path: Path) -> None:
    """The child aborts on every cut stream, and a crash handler that ``core_pattern``
    pipes to (apport, systemd-coredump) gets the whole core whatever ``RLIMIT_CORE``
    says: several GB, for which the parent waits. That made the cut-stream tests stall
    for minutes on CI, and a worker died at the 60 s timeout. The child turns its dumps
    off: a core limit of 0, and not dumpable, which is what stops a piped dump."""
    path = _write(tmp_path, "valid.gz", gzip.compress(_payload()))
    with RapidgzipChildStream(str(path), label="gzip", max_memory=None) as stream:
        assert stream._proc is not None
        limits = Path(f"/proc/{stream._proc.pid}/limits").read_text()
    core = next(line for line in limits.splitlines() if line.startswith("Max core"))
    assert core.split()[4:6] == ["0", "0"], core
    # Whether a process is dumpable shows only to itself (PR_GET_DUMPABLE), so the
    # worker's function is run in a fresh interpreter.
    probe = """
        import ctypes
        from archivey.internal.streams.codecs.decoder_worker import disable_core_dumps
        disable_core_dumps()
        print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))  # PR_GET_DUMPABLE
    """
    proc = _run(probe)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0"


@_POSIX
@pytest.mark.parametrize("sig", ["SIGSEGV", "SIGABRT"])
@pytest.mark.parametrize("then", ["read", "seek"])
@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.BZIP2])
def test_after_a_child_crash_the_standard_library_reads_on(
    tmp_path: Path, sig: str, then: str, codec: Codec
) -> None:
    """A crash is a verdict on the data, and the standard library gives it: on a valid
    stream it reads on from where the caller was, so the caller loses nothing."""
    payload = _payload()
    path = _write(tmp_path, f"valid.{codec.value}", _compress(codec, payload))
    with open_codec_stream(codec, str(path), config=_ON) as stream:
        child = _child_stream(stream)
        assert stream.read(10) == payload[:10]
        assert child._proc is not None
        os.kill(child._proc.pid, getattr(signal, sig))
        child._proc.wait()
        if then == "seek":
            assert stream.seek(5) == 5
            assert stream.read() == payload[5:]
        else:
            assert stream.read() == payload[10:]
        assert not _has_child_stream(stream)


@pytest.mark.parametrize("where", ["before", "after"])
def test_the_abort_message_is_found_among_other_output(
    tmp_path: Path, where: str
) -> None:
    """Output before or after the abort message does not hide it.

    With ``PYTHONFAULTHANDLER`` set, Python 3.14 wrote about 6.5 KiB of thread and C
    stacks after rapidgzip's ``what():`` line, and a search of the last 4 KiB missed
    it: every truncation read as ``CorruptionError``. A window at the start of the file
    would miss it the same way behind earlier output, so both sides get more than a
    MiB.
    """
    abort = (
        b"terminate called after throwing an instance of 'std::logic_error'\n"
        b"  what():  The bit buffer should not contain more data than have been read "
        b"from the file!\nFatal Python error: Aborted\n\n"
    )
    other = b'  Binary file "/lib/x86_64-linux-gnu/libc.so.6", at +0x9caa4\n' * 40_000
    assert len(other) > 2 << 20
    content = abort + other if where == "after" else other + abort
    with (tmp_path / "stderr").open("w+b") as stderr:
        stderr.write(content)
        truncated, reason = rapidgzip_child._scan_stderr(stderr)
    assert truncated
    assert reason.startswith(": The bit buffer")


@pytest.mark.parametrize("inside", [1, 30, 62])
def test_the_abort_message_is_found_across_a_split_long_line(
    tmp_path: Path, inside: int
) -> None:
    """A line longer than the scan's line cap is read in pieces; the abort message that
    straddles a split, with ``inside`` of its bytes in the first piece, is still found."""
    marker = rapidgzip_child._TRUNCATION_ABORT
    filler = b"x" * (rapidgzip_child._STDERR_LINE_LIMIT - inside)
    with (tmp_path / "stderr").open("w+b") as stderr:
        stderr.write(filler + marker + b" from the file!\n")
        truncated, _ = rapidgzip_child._scan_stderr(stderr)
    assert truncated


def test_the_last_what_line_gives_the_reason(tmp_path: Path) -> None:
    """Earlier output holding ``what():`` does not stand in for the abort's own line."""
    content = (
        b"  what():  an earlier message\n"
        b"terminate called after throwing an instance of 'std::logic_error'\n"
        b"  what():  The bit buffer should not contain more data than have been read "
        b"from the file!\n"
    )
    with (tmp_path / "stderr").open("w+b") as stderr:
        stderr.write(content)
        truncated, reason = rapidgzip_child._scan_stderr(stderr)
    assert truncated
    assert reason.startswith(": The bit buffer")


@pytest.mark.parametrize(
    "message",
    [
        # Leaked untranslated from the open-time probe of a truncated gzip.
        "Next block offset index is out of sync!",
        "an internal message no allowlist entry names",
    ],
)
def test_any_runtime_error_rapidgzip_raised_is_translated(message: str) -> None:
    """A RuntimeError the child reported maps to CorruptionError; the same RuntimeError
    from anywhere else (the caller's source) is left alone."""
    for codec in (
        codecs_module.GzipCodec(),
        codecs_module.DeflateCodec(),
        codecs_module.ZlibCodec(),
    ):
        reported = rapidgzip_child._reported_error(
            f"builtins\nRuntimeError\n\n{message}".encode()
        )
        assert is_corruption_not_truncation(codec._translate_accelerator(reported))
        assert codec._translate_accelerator(RuntimeError(message)) is None


def test_an_eof_error_the_child_reported_is_still_translated() -> None:
    """The mark that keeps the caller's source exception unchanged is on that exception
    only: an ``EOFError`` rapidgzip raised in the child is still a truncation."""
    for codec in (
        codecs_module.GzipCodec(),
        codecs_module.DeflateCodec(),
        codecs_module.ZlibCodec(),
    ):
        reported = rapidgzip_child._reported_error(
            b"builtins\nEOFError\n\nend of stream"
        )
        assert isinstance(codec._translate_accelerator(reported), TruncatedError)


def test_an_unknown_exception_from_the_child_propagates_unmapped() -> None:
    exc = rapidgzip_child._reported_error(b"builtins\nKeyError\n\n'x'")
    assert isinstance(exc, RapidgzipChildReportedError)
    assert codecs_module.GzipCodec()._translate_accelerator(exc) is None
    missing = rapidgzip_child._reported_error(
        b"builtins\nFileNotFoundError\n2\nno such file"
    )
    assert isinstance(missing, FileNotFoundError) and missing.errno == 2


def test_close_reaps_the_child_and_later_calls_raise(tmp_path: Path) -> None:
    path = _write(tmp_path, "valid.gz", gzip.compress(_payload()))
    stream = open_codec_stream(Codec.GZIP, str(path), config=_ON)
    child = _child_stream(stream)
    proc = child._proc
    assert proc is not None
    # Two sequential reads: the second fills the read-ahead buffer, so a read after
    # close() could be answered from it without reaching the child.
    child.read(10)
    child.read(10)
    assert child._buffer_at < len(child._buffer)
    stream.close()
    assert proc.returncode is not None
    for call in (lambda: child.read(1), lambda: child.read(), child.tell):
        with pytest.raises(ValueError, match="closed file"):
            call()


@pytest.mark.parametrize("offset", [2**63, -(2**63) - 1])
def test_an_offset_past_the_frame_range_is_refused_and_the_stream_survives(
    offset: int,
) -> None:
    """A seek the protocol cannot carry is refused before anything is sent, so the
    child is still in step and the stream goes on reading."""
    payload = _payload()
    child = RapidgzipChildStream(
        io.BytesIO(gzip.compress(payload)), label="gzip", max_memory=None
    )
    try:
        assert child.read(10) == payload[:10]
        with pytest.raises(OverflowError):
            child.seek(offset)
        assert child.seek(0) == 0
        assert child.read() == payload
        # An offset that fits, from a position that takes the target past the range.
        with pytest.raises(OverflowError):
            child.seek(2**63 - 1, io.SEEK_CUR)
        assert child.seek(5) == 5
        assert child.read(10) == payload[5:15]
        # A second sequential read fills the read-ahead buffer; a refused seek keeps
        # it and the position, so the next read goes on from where the caller was.
        assert child.read(10) == payload[15:25]
        with pytest.raises(OverflowError):
            child.seek(offset)
        assert child.tell() == 25
        assert child.read(10) == payload[25:35]
    finally:
        child.close()


@pytest.mark.parametrize(
    ("offset", "whence"),
    [(-1, io.SEEK_SET), (-100, io.SEEK_CUR), (0, 3), (0, 256)],
    ids=["negative", "negative-relative", "bad-whence-child", "bad-whence-byte"],
)
def test_a_refused_seek_keeps_the_position_and_buffer(offset: int, whence: int) -> None:
    """A seek refused before the child moves, here or by the child itself, leaves the
    read-ahead buffer and the position as they were (review round 2, K8)."""
    payload = _payload()
    child = RapidgzipChildStream(
        io.BytesIO(gzip.compress(payload)), label="gzip", max_memory=None
    )
    try:
        assert child.read(10) == payload[:10]
        assert child.read(10) == payload[10:20]  # fills the read-ahead buffer
        with pytest.raises(ValueError):
            child.seek(offset, whence)
        assert child.tell() == 20
        assert child.read(10) == payload[20:30]
    finally:
        child.close()


def _fail_the_nth_read(
    child: RapidgzipChildStream, n: int, *, fail_seeks: bool = False
) -> None:
    """Make the child answer its ``n``-th READ from now with a reported error, as it
    does for a corrupt (not truncated) stream; the child itself stays usable. With
    ``fail_seeks``, every SEEK after that is refused the same way."""
    exchange = child._exchange
    reads = 0

    def failing(tag: int, arg: int, payload: bytes) -> tuple[int, int, bytes] | None:
        nonlocal reads
        if tag == READ:
            reads += 1
            if reads == n:
                return ERR, 0, b"builtins\nRuntimeError\n\ncorrupt block"
        if tag == SEEK and fail_seeks and reads >= n:
            return ERR, 0, b"builtins\nRuntimeError\n\nseek refused"
        return exchange(tag, arg, payload)

    child._exchange = failing  # type: ignore[method-assign]


@pytest.mark.parametrize("failing_read", [1, 2], ids=["first-chunk", "part-way"])
def test_a_failed_read_leaves_the_position_where_it_started(failing_read: int) -> None:
    """A read that fails returns nothing, even when it had already taken a chunk from
    the child. The stream goes back to where the read started, so ``tell`` does not
    count bytes the caller never got and the next read returns them (round 3, K15)."""
    payload = _payload()
    assert len(payload) > rapidgzip_child._CHUNK  # read() takes two chunks
    child = RapidgzipChildStream(
        io.BytesIO(gzip.compress(payload)), label="gzip", max_memory=None
    )
    try:
        assert child.read(10) == payload[:10]
        _fail_the_nth_read(child, failing_read)
        with pytest.raises(RuntimeError, match="corrupt block"):
            child.read()
        assert child.tell() == 10
        assert child.read(100) == payload[10:110]
        assert child.read() == payload[110:]
    finally:
        child.close()


def test_a_failed_read_that_cannot_move_back_leaves_the_stream_unusable() -> None:
    """When the seek back to where a failed read started fails too, nobody knows the
    position: the read raises its own error, the child is stopped, and every later
    call raises ``ReadError`` (round 4, K18)."""
    payload = _payload()
    child = RapidgzipChildStream(
        io.BytesIO(gzip.compress(payload)), label="gzip", max_memory=None
    )
    try:
        assert child.read(10) == payload[:10]
        _fail_the_nth_read(child, 1, fail_seeks=True)
        with pytest.raises(RuntimeError, match="corrupt block"):
            child.read()
        assert child._proc is None
        for call in (lambda: child.read(1), child.tell, lambda: child.seek(0)):
            with pytest.raises(ReadError, match="moving back to where it started"):
                call()
    finally:
        child.close()


def test_a_negative_seek_after_a_failed_read_is_refused() -> None:
    """The sign of an absolute target is checked whatever the stream knows of its
    position, so a failed read cannot let ``seek(-1)`` reach the child, which would
    clamp it to 0 (round 3, K13)."""
    payload = _payload()
    child = RapidgzipChildStream(
        io.BytesIO(gzip.compress(payload)), label="gzip", max_memory=None
    )
    try:
        assert child.read(10) == payload[:10]
        _fail_the_nth_read(child, 1)
        with pytest.raises(RuntimeError, match="corrupt block"):
            child.read(10)
        child._pos = None  # as a failed read leaves it before the rewind
        with pytest.raises(ValueError, match="negative seek position"):
            child.seek(-1)
        assert child.tell() == 10
        assert child.read(10) == payload[10:20]
    finally:
        child.close()


@_POSIX
def test_a_sigint_to_the_child_does_not_stop_it(tmp_path: Path) -> None:
    """A terminal's Ctrl-C signals the whole foreground process group, the decoder child
    included. The child ignores it: the parent decides what an interrupt means."""
    payload = _payload()
    path = _write(tmp_path, "valid.gz", gzip.compress(payload))
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child_stream(stream)
        assert stream.read(10) == payload[:10]
        assert child._proc is not None
        os.kill(child._proc.pid, signal.SIGINT)
        with pytest.raises(subprocess.TimeoutExpired):
            child._proc.wait(timeout=0.5)
        assert stream.read() == payload[10:]


def test_an_interrupted_request_leaves_the_stream_unusable(tmp_path: Path) -> None:
    path = _write(tmp_path, "valid.gz", gzip.compress(_payload()))
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child_stream(stream)
        real = child._read_frame

        def interrupted() -> tuple[int, int, bytes] | None:
            raise KeyboardInterrupt

        child._read_frame = interrupted
        with pytest.raises(KeyboardInterrupt):
            stream.read(10)
        child._read_frame = real
        with pytest.raises(ArchiveyUsageError):
            stream.read(10)


# --- where no child can run -------------------------------------------------------------


@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.BZIP2])
def test_without_a_child_auto_uses_stdlib_and_on_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, codec: Codec
) -> None:
    """A frozen application has no interpreter to run the worker. AUTO decodes with the
    standard library; ON, which asked for rapidgzip, is refused rather than run in-process."""
    for module in (codecs_module.rapidgzip_select, codecs_module.bzip2_codec):
        monkeypatch.setattr(
            module, "rapidgzip_child_unavailable_reason", lambda: "no child here"
        )
    # Low enough that AUTO would otherwise pick rapidgzip for this input.
    monkeypatch.setattr(
        codecs_module.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    payload = _payload()
    path = _write(tmp_path, f"valid.{codec.value}", _compress(codec, payload))
    auto = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.AUTO,
        use_indexed_bzip2=AcceleratorMode.AUTO,
    )
    with open_codec_stream(codec, str(path), config=auto) as stream:
        assert not _has_child_stream(stream)
        assert stream.read() == payload
    field = "use_indexed_bzip2" if codec is Codec.BZIP2 else "use_rapidgzip"
    with pytest.raises(ResourceUnavailableError, match=rf"{field}.*\(no child here\)"):
        open_codec_stream(codec, str(path), config=_ON)


def test_under_pypy_on_is_refused_with_the_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """rapidgzip misreads valid streams under PyPy, so no child runs it there and ON
    says why. Under PyPy ``deps.rapidgzip`` already reads as absent, so ON raises
    PackageNotInstalledError first (tests/test_codecs.py); this pins the backstop for a
    rapidgzip that reads as present."""
    monkeypatch.setattr(codecs_module.deps, "UNDER_PYPY", True)
    assert rapidgzip_child.rapidgzip_child_unavailable_reason() == (
        "archivey does not use rapidgzip under PyPy, where it misreads valid streams"
    )
    path = _write(tmp_path, "valid.gz", gzip.compress(_payload()))
    with pytest.raises(
        ResourceUnavailableError, match=r"\(archivey does not use rapidgzip under PyPy"
    ):
        open_codec_stream(Codec.GZIP, str(path), config=_ON)


def _refuse(*args: object, **kwargs: object) -> NoReturn:
    raise OSError(11, "Resource temporarily unavailable")


# What can refuse a child at open: the spawn itself (a process cap, RLIMIT_NPROC, EMFILE)
# and the temporary file its stderr goes to (no writable temporary directory).
_START_FAILURES = {
    "popen": ("subprocess", "Popen"),
    "tempfile": ("tempfile", "TemporaryFile"),
    "no-interpreter": None,
}


def _break_child_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, how: str
) -> None:
    target = _START_FAILURES[how]
    if target is None:
        monkeypatch.setattr(sys, "executable", str(tmp_path / "no-such-python"))
    else:
        module, name = target
        monkeypatch.setattr(getattr(rapidgzip_child, module), name, _refuse)


@pytest.mark.parametrize("how", sorted(_START_FAILURES))
def test_a_child_that_cannot_start_is_a_resource_limit_under_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, how: str
) -> None:
    """ON asked for rapidgzip, so a refused child is an error, not a quiet fallback."""
    path = _write(tmp_path, "valid.gz", gzip.compress(_payload()))
    _break_child_start(monkeypatch, tmp_path, how)
    with pytest.raises(ResourceUnavailableError, match="cannot start"):
        open_codec_stream(Codec.GZIP, str(path), config=_ON)


@pytest.mark.parametrize("mode", ["path", "bytesio"])
@pytest.mark.parametrize("codec", _CHILD_CODECS)
@pytest.mark.parametrize("how", sorted(_START_FAILURES))
def test_a_child_that_cannot_start_falls_back_to_stdlib_under_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, how: str, codec: Codec, mode: str
) -> None:
    """AUTO decodes with the standard library when no child starts, as it does when
    rapidgzip is absent: valid data reads, and cut or damaged data raises as the stdlib
    backend reports it (translated, from the original start of the source)."""
    monkeypatch.setattr(
        codecs_module.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    payload = _payload()
    data = _compress(codec, payload)
    damaged = bytearray(data)
    damaged[len(data) // 2 : len(data) // 2 + 64] = bytes(64)
    cases: list[tuple[bytes, type[Exception] | None]] = [
        (data, None),
        (data[:-1500], TruncatedError),
    ]
    if codec is not Codec.DEFLATE:
        # Raw deflate carries no checksum: the stdlib can decode damage it cannot see.
        cases.append((bytes(damaged), CorruptionError))
    _break_child_start(monkeypatch, tmp_path, how)
    for i, (content, error) in enumerate(cases):
        path = _write(tmp_path, f"{i}.{codec.value}", content)
        source: str | io.BytesIO = str(path) if mode == "path" else io.BytesIO(content)
        config = StreamConfig(
            seekable=True,
            use_rapidgzip=AcceleratorMode.AUTO,
            use_indexed_bzip2=AcceleratorMode.AUTO,
            compressed_input_size=len(content),
            expected_decompressed_size=(None if codec is Codec.GZIP else len(payload)),
        )
        with open_codec_stream(codec, source, config=config) as stream:
            assert not _has_child_stream(stream)
            if error is None:
                assert stream.read() == payload
            else:
                with pytest.raises(error):
                    stream.read()


def _fallback_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    messages = (r.getMessage() for r in caplog.records if r.name == "archivey.streams")
    return [m for m in messages if "use_rapidgzip=AcceleratorMode.OFF" in m]


# How each way of having no child is set up, and what the warning and the ON error say.
_NO_CHILD_REASONS = {
    "popen": "Resource temporarily unavailable",
    "tempfile": "Resource temporarily unavailable",
    "frozen": "frozen application",
    "zip-import": "not a file on disk",
}


def _take_the_child_away(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, how: str
) -> None:
    if how == "frozen":
        monkeypatch.setattr(sys, "frozen", True, raising=False)
    elif how == "zip-import":
        monkeypatch.setattr(
            rapidgzip_child, "_WORKER", tmp_path / "rapidgzip_worker.py"
        )
    else:
        _break_child_start(monkeypatch, tmp_path, how)


@pytest.mark.parametrize("how", sorted(_NO_CHILD_REASONS))
def test_an_auto_fallback_warns_once_per_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    how: str,
) -> None:
    """A child that cannot start is a fact about the environment: AUTO logs it once,
    naming why, however many streams fall back. A normal open, and ON (which raises),
    log nothing."""
    monkeypatch.setattr(codecs_module.rapidgzip_select, "_child_fallback_warned", set())
    monkeypatch.setattr(
        codecs_module.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    caplog.set_level(logging.WARNING, logger="archivey.streams")
    payload = _payload()
    path = _write(tmp_path, "valid.gz", gzip.compress(payload))
    auto = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.AUTO,
        compressed_input_size=path.stat().st_size,
    )
    with open_codec_stream(Codec.GZIP, str(path), config=auto) as stream:
        assert _has_child_stream(stream)
    assert _fallback_warnings(caplog) == []

    why = _NO_CHILD_REASONS[how]
    _take_the_child_away(monkeypatch, tmp_path, how)
    with pytest.raises(ResourceUnavailableError, match=why):
        open_codec_stream(Codec.GZIP, str(path), config=_ON)
    assert _fallback_warnings(caplog) == []

    for _ in range(2):
        with open_codec_stream(Codec.GZIP, str(path), config=auto) as stream:
            assert not _has_child_stream(stream)
            assert stream.read() == payload
    (message,) = _fallback_warnings(caplog)
    assert "standard library decoder" in message
    assert why in message


def test_the_bzip2_fallback_warns_once_and_names_its_own_setting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The bzip2 fallback is logged once too, apart from the DEFLATE family's, and names
    the setting that silences it."""
    monkeypatch.setattr(codecs_module.rapidgzip_select, "_child_fallback_warned", set())
    caplog.set_level(logging.WARNING, logger="archivey.streams")
    payload = _payload()
    path = _write(tmp_path, "valid.bz2", bz2.compress(payload))
    auto = StreamConfig(
        seekable=True,
        use_indexed_bzip2=AcceleratorMode.AUTO,
        compressed_input_size=path.stat().st_size,
    )
    _take_the_child_away(monkeypatch, tmp_path, "frozen")
    for _ in range(2):
        with open_codec_stream(Codec.BZIP2, str(path), config=auto) as stream:
            assert not _has_child_stream(stream)
            assert stream.read() == payload
    messages = [r.getMessage() for r in caplog.records if r.name == "archivey.streams"]
    (message,) = [m for m in messages if "use_indexed_bzip2=AcceleratorMode.OFF" in m]
    assert "bzip2 streams are read with the standard library decoder" in message
    assert _fallback_warnings(caplog) == []


@pytest.mark.parametrize("how", ["frozen", "zip-import"])
def test_resolving_a_codec_does_not_warn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    how: str,
) -> None:
    """``resolve_codec`` is a query that opens nothing, so it logs nothing; the open
    that then reads with the stdlib is what warns."""
    monkeypatch.setattr(codecs_module.rapidgzip_select, "_child_fallback_warned", set())
    monkeypatch.setattr(
        codecs_module.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    caplog.set_level(logging.WARNING, logger="archivey.streams")
    payload = _payload()
    data = zlib.compress(payload)
    auto = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.AUTO,
        compressed_input_size=len(data),
        expected_decompressed_size=len(payload),
    )
    _take_the_child_away(monkeypatch, tmp_path, how)
    codecs_module.resolve_codec(Codec.ZLIB, auto)
    assert _fallback_warnings(caplog) == []
    with open_codec_stream(Codec.ZLIB, io.BytesIO(data), config=auto) as stream:
        assert stream.read() == payload
    (message,) = _fallback_warnings(caplog)
    assert _NO_CHILD_REASONS[how] in message


def test_no_fallback_warning_when_rapidgzip_is_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Without rapidgzip, AUTO reads with the stdlib as it always has, quietly: there is
    no child to fail."""
    monkeypatch.setattr(codecs_module.rapidgzip_select, "_child_fallback_warned", set())
    monkeypatch.setattr(
        codecs_module.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    monkeypatch.setattr(
        codecs_module.deps,
        "rapidgzip",
        codecs_module.deps.LazyOptional("rapidgzip", present=False),
    )
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    caplog.set_level(logging.WARNING, logger="archivey.streams")
    payload = _payload()
    path = _write(tmp_path, "valid.gz", gzip.compress(payload))
    auto = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.AUTO,
        compressed_input_size=path.stat().st_size,
    )
    with open_codec_stream(Codec.GZIP, str(path), config=auto) as stream:
        assert stream.read() == payload
    assert _fallback_warnings(caplog) == []


def test_background_reads_of_a_stream_source_are_served(tmp_path: Path) -> None:
    """rapidgzip's own threads read the source ahead; those reads arrive between
    requests and must be served by the next one, not deadlock."""
    payload = os.urandom(6 * 1024 * 1024)  # incompressible: many source reads
    compressed = gzip.compress(payload, compresslevel=1)
    done = threading.Event()
    result: list[bytes] = []

    def run() -> None:
        with open_codec_stream(Codec.GZIP, io.BytesIO(compressed), config=_ON) as s:
            parts = []
            while chunk := s.read(4096 * 7):
                parts.append(chunk)
            result.append(b"".join(parts))
        done.set()

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    assert done.wait(60), "reading through the child stalled"
    assert result == [payload]


@pytest.mark.parametrize("seed", range(6))
def test_reads_and_seeks_in_any_order_match_the_payload(seed: int) -> None:
    """The read-ahead buffer and the kept position agree with the data for any mix of
    small reads, large reads, and seeks inside and outside the buffer."""
    payload = _payload()
    rng = random.Random(seed)
    with open_codec_stream(
        Codec.ZLIB, io.BytesIO(zlib.compress(payload)), config=_ON
    ) as stream:
        pos = 0
        for _ in range(300):
            action = rng.random()
            if action < 0.5:
                size = rng.choice([1, 17, 512, 4096, 70_000, 1_500_000])
                data = stream.read(size)
                assert data == payload[pos : pos + size]
                pos += len(data)
            elif action < 0.7:
                delta = rng.randint(-5000, 5000)
                pos = min(max(pos + delta, 0), len(payload))
                assert stream.seek(pos - stream.tell(), io.SEEK_CUR) == pos
            elif action < 0.9:
                pos = rng.randrange(len(payload))
                assert stream.seek(pos) == pos
            else:
                back = rng.randint(0, 100)
                pos = len(payload) - back
                assert stream.seek(-back, io.SEEK_END) == pos
            assert stream.tell() == pos
