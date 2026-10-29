"""A stream that keeps an error and raises it again frees itself without the garbage
collector: no raise ties the stream to a traceback that holds the stream."""

from __future__ import annotations

import gc
import io
import os
import traceback
import weakref
import zipfile
from collections.abc import Iterator

import pytest

from archivey import open_archive
from archivey.exceptions import CorruptionError
from archivey.internal.streams.decompressor_stream import DecompressorStream
from archivey.internal.streams.kept_errors import EarlierRaise, KeptError
from tests.test_decompressor_stream_read import _FailsOnFeed


@pytest.fixture
def no_gc() -> Iterator[None]:
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


def test_a_raise_again_shows_both_raises_and_keeps_the_type() -> None:
    def first() -> None:
        raise OSError(5, "boom")

    with pytest.raises(OSError) as caught:
        first()
    kept = KeptError.of(caught.value)
    with pytest.raises(OSError) as again:
        kept.raise_again()
    assert again.value is not caught.value
    assert again.value.args == caught.value.args
    assert isinstance(again.value.__cause__, EarlierRaise)
    text = "".join(traceback.format_exception(again.value))
    assert "in first" in text  # the first raise, as text
    assert "in raise_again" in text  # and the raise the caller caught


def test_a_spent_decompressor_stream_is_freed_without_the_collector(
    no_gc: None,
) -> None:
    stream = DecompressorStream(
        io.BytesIO(os.urandom(1000)), make_decoder=lambda point, inner: _FailsOnFeed(2)
    )
    for _ in range(3):
        try:  # not pytest.raises, whose ExceptionInfo keeps the traceback
            while stream.read(100):
                pass
        except OSError:
            pass
        else:
            pytest.fail("the failing decoder read clean")
    alive = weakref.ref(stream)
    del stream
    assert alive() is None


def test_a_member_stream_with_a_verdict_is_freed_without_the_collector(
    no_gc: None,
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", os.urandom(10_000))
    blob = bytearray(buf.getvalue())
    for sig, off in ((b"PK\x01\x02", 16), (b"PK\x03\x04", 14)):
        blob[blob.index(sig) + off] ^= 0x01
    with open_archive(io.BytesIO(bytes(blob)), seekable_members=True) as ar:
        stream = ar.open("a.bin")
        for _ in range(3):
            try:  # not pytest.raises, whose ExceptionInfo keeps the traceback
                stream.read()
            except CorruptionError:
                pass
            else:
                pytest.fail("the damaged member read clean")
        stream.close()
        alive = weakref.ref(stream)
        del stream
        assert alive() is None
