"""Pins from the review of blind ``except`` handlers in ``src/``.

Each test names the handler it pins and the exception a caller now sees. The review
record is ``review/archive/2026-09-25-exception-catchalls/``; the house rules it produced
are ``dev-docs/topics/exception-handlers.md``.
"""

from __future__ import annotations

import io
import itertools
import struct
import subprocess
import sys
import textwrap
import zipfile
import zlib

import pytest

import archivey
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.reader_state import LifecycleState
from archivey.internal.streams.verify import VerifyingStream
from tests.conftest import requires


def _zip_with_corrupt_deflate_body() -> bytes:
    """A one-member ZIP whose deflate body fails to decode (zlib error -3)."""
    data = b"".join(b"line %d of text, some words here\n" % i for i in range(20000))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", data)
    raw = bytearray(buf.getvalue())
    raw[30 + len("a.txt") + 38] ^= 0xFF  # inside the first block's Huffman tables
    return bytes(raw)


@pytest.mark.parametrize("how", ["read()", "read(n)"])
def test_corrupt_member_reads_as_corrupt_through_either_read(how: str) -> None:
    """verify.py ``_read_sized_all``: a raw decoder error is no longer relabelled.

    It used to become ``TruncatedError`` on ``read()`` while the same member raised
    ``CorruptionError`` on ``read(n)``, because only the bounded path let the
    translator see the decoder's error.
    """
    blob = _zip_with_corrupt_deflate_body()
    with (
        archivey.open_archive(io.BytesIO(blob)) as reader,
        reader.open(reader.get("a.txt")) as stream,
        pytest.raises(CorruptionError) as info,
    ):
        if how == "read()":
            stream.read()
        else:
            while stream.read(4096):
                pass
    assert not isinstance(info.value, TruncatedError)


class _ExactThenFails(io.BytesIO):
    """Delivers its bytes, then raises ``error`` on the read that probes past them."""

    def __init__(self, data: bytes, error: BaseException) -> None:
        super().__init__(data)
        self._size = len(data)
        self._error = error

    def read(self, n: int | None = -1) -> bytes:
        if self.tell() >= self._size:
            raise self._error
        return super().read(n)


@pytest.mark.parametrize("error", [OSError("disk gone"), MemoryError()])
def test_overrun_probe_lets_resource_errors_through(error: BaseException) -> None:
    """verify.py ``_probe_past_declared``: an I/O or memory failure is not "no more data"."""
    stream = VerifyingStream(_ExactThenFails(b"x" * 10, error), {}, expected_size=10)
    with pytest.raises(type(error)):
        stream.read()
    stream.close()


@pytest.mark.parametrize("n", [-1, 10])
def test_overrun_probe_reads_a_closed_source_as_the_end(n: int) -> None:
    """verify.py ``_probe_past_declared``: a closed source past the end is "no more data".

    The digests still judge the declared bytes: a wrong CRC raises.
    """
    closed = ValueError("I/O operation on closed file.")
    good = zlib.crc32(b"x" * 10).to_bytes(4, "big")
    with VerifyingStream(
        _ExactThenFails(b"x" * 10, closed), {"crc32": good}, expected_size=10
    ) as stream:
        assert stream.read(n) == b"x" * 10
    bad = (zlib.crc32(b"x" * 10) ^ 1).to_bytes(4, "big")
    with (
        VerifyingStream(
            _ExactThenFails(b"x" * 10, closed), {"crc32": bad}, expected_size=10
        ) as stream,
        pytest.raises(CorruptionError),
    ):
        stream.read(n)


@pytest.mark.parametrize("n", [-1, 10])
def test_overrun_probe_raises_a_decoder_error_past_the_end(n: int) -> None:
    """verify.py ``_probe_past_declared``: a decoder error past the declared size raises.

    It used to read as "the member ends here", so the read that reached the declared
    size returned its bytes as verified and only a later read raised.
    """
    inner = _ExactThenFails(b"x" * 10, zlib.error("invalid block type"))
    with (
        VerifyingStream(inner, {}, expected_size=10) as stream,
        pytest.raises(zlib.error),
    ):
        stream.read(n)


def _stored_block(data: bytes) -> bytes:
    """A non-final stored DEFLATE block holding ``data``."""
    return b"\x00" + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data


def _zip_with_bad_block_after_declared_size() -> tuple[bytes, int]:
    """A ZIP deflate member whose declared size and CRC match its first blocks.

    The body is ``size`` bytes in non-final stored blocks ending exactly at compressed
    offset 4 x 64 KiB, then a block of the reserved type 11. zlib and 7-Zip reject it.
    """
    blocks, compressed_len = 5, 4 * 65536
    size = compressed_len - 5 * blocks
    payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    step = size // blocks
    bounds = [i * step for i in range(blocks)] + [size]
    raw = b"".join(_stored_block(payload[a:b]) for a, b in itertools.pairwise(bounds))
    assert len(raw) == compressed_len
    raw += b"\x07\x00\x00"
    crc = zlib.crc32(payload)
    name = b"m"
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, crc, len(raw), size, len(name), 0
    )
    body = local + name + raw
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            8,
            0,
            0,
            crc,
            len(raw),
            size,
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(body), 0)
    return body + central + end, size


@pytest.mark.parametrize("n", [-1, 65536, 262119])
def test_read_reaching_declared_size_raises_when_the_body_goes_on_corrupt(
    n: int,
) -> None:
    """A read that reaches ``member.size`` does not hand over a member zlib rejects.

    With ``read(65536)`` the four reads ended at the declared size with no error, so a
    caller that stops at ``member.size`` took a damaged member as verified. The verdict
    is corruption, not truncation, and the reaching read withholds its chunk: only the
    reads before it deliver bytes.
    """
    blob, size = _zip_with_bad_block_after_declared_size()
    with pytest.raises(zlib.error):
        zipfile.ZipFile(io.BytesIO(blob)).read("m")
    got = 0
    with (
        archivey.open_archive(io.BytesIO(blob)) as reader,
        reader.open("m") as stream,
        pytest.raises(CorruptionError) as info,
    ):
        while got < size:
            chunk = stream.read(n)
            if not chunk:
                break
            got += len(chunk)
    assert not isinstance(info.value, TruncatedError)
    assert got == (0 if n < 0 else (size - 1) // n * n)


def _zip_declared_empty_with_garbage_body() -> bytes:
    """A one-member ZIP: DEFLATE, declared size 0 and CRC 0, and a 64-byte body that is
    not DEFLATE."""
    name, body = b"a.txt", b"\xff" * 64
    fields = struct.pack("<HHHHHIII", 20, 0, 8, 0, 0, 0, len(body), 0)
    local = b"PK\x03\x04" + fields + struct.pack("<HH", len(name), 0) + name
    central = (
        b"PK\x01\x02"
        + struct.pack("<H", 20)
        + fields
        + struct.pack("<HHHHHII", len(name), 0, 0, 0, 0, 0, 0)
        + name
    )
    offset = len(local) + len(body)
    end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), offset, 0)
    return local + body + central + end


def test_overrun_probe_raises_a_typed_decoder_error() -> None:
    """verify.py ``_probe_past_declared``: the standard-library DEFLATE decoder raises
    a typed ``CorruptionError`` past the declared size, and the probe lets it through.
    A garbage body behind a member declared empty is not read as an empty member. A valid
    DEFLATE body there: test_audit2_zip.py
    ::test_zero_declared_size_with_data_raises_rather_than_serving_it."""
    blob = _zip_declared_empty_with_garbage_body()
    with (
        archivey.open_archive(io.BytesIO(blob)) as reader,
        reader.open(reader.get("a.txt")) as stream,
        pytest.raises(CorruptionError, match="deflate stream") as info,
    ):
        stream.read()
    assert not isinstance(info.value, TruncatedError)


@requires("rapidgzip")
def test_bzip2_accelerator_traps_a_failing_caller_source() -> None:
    """codecs/bzip2_codec.py: the bzip2 accelerator reads a caller's stream through the trap too.

    Without it, the caller's ``OSError`` crossed into rapidgzip's C++ callback and
    aborted the interpreter (``std::invalid_argument``), so this runs in a child.
    """
    code = textwrap.dedent(
        """
        import bz2, io, random
        import archivey
        random.seed(0)
        blob = bz2.compress(random.randbytes(3_000_000))

        class Flaky(io.BytesIO):
            armed = False
            def read(self, n=-1):
                if self.armed and self.tell() > len(blob) // 2:
                    raise OSError("disk gone")
                return super().read(n)

        source = Flaky(blob)
        stream = archivey.open_stream(source, seekable=True)
        source.armed = True
        try:
            stream.read()
        except OSError as exc:
            print("raised", exc)
        stream.close()
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "raised disk gone" in proc.stdout


def test_interrupted_teardown_still_marks_the_lifecycle_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base_reader.py ``_maybe_teardown``: teardown is never retried, so an interrupt
    in the backend's close still leaves the lifecycle at TEARDOWN_COMPLETE.

    The lifecycle assertion is on internal state on purpose: the fix is bookkeeping with
    no external effect today (the retry is refused by the claim flag either way), so
    the state is the only thing that can pin it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"a")
    reader = archivey.open_archive(io.BytesIO(buf.getvalue()))

    calls = 0

    def _interrupted() -> None:
        nonlocal calls
        calls += 1
        raise KeyboardInterrupt

    monkeypatch.setattr(reader, "_close_archive", _interrupted)
    with pytest.raises(KeyboardInterrupt):
        reader.close()
    reader.close()  # quiet; the claim flag, not the lifecycle, refuses a second run
    assert calls == 1
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
