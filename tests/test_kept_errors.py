"""A stream that keeps an error and raises it again frees itself without the garbage
collector: no raise ties the stream to a traceback that holds the stream."""

from __future__ import annotations

import gc
import gzip
import io
import os
import traceback
import weakref
import zipfile
from collections.abc import Iterator

import pytest

from archivey import open_archive
from archivey.exceptions import CorruptionError, TruncatedError
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


def test_a_truncated_member_stream_is_freed_without_the_collector(
    no_gc: None,
) -> None:
    """The deferred end error (a stream cut short) takes another route than a decoder
    failure: no frame on it may keep the error it raises."""
    cut = gzip.compress(os.urandom(10_000))[:-6]
    with open_archive(io.BytesIO(cut)) as ar:
        stream = ar.open(ar.members()[0])
        for _ in range(3):
            try:  # not pytest.raises, whose ExceptionInfo keeps the traceback
                stream.read()
            except TruncatedError:
                pass
            else:
                pytest.fail("the cut member read clean")
        stream.close()
        alive = weakref.ref(stream)
        del stream
        assert alive() is None


def test_a_member_stream_whose_close_fails_is_freed_without_the_collector(
    no_gc: None,
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", os.urandom(10_000))

    def fail() -> None:
        raise OSError("teardown failed")

    with open_archive(io.BytesIO(buf.getvalue()), seekable_members=True) as ar:
        stream = ar.open("a.bin")
        stream.read()
        stream._on_close = fail
        try:  # not pytest.raises, whose ExceptionInfo keeps the traceback
            stream.close()
        except OSError:
            pass
        else:
            pytest.fail("the failing teardown closed clean")
        alive = weakref.ref(stream)
        del stream
        assert alive() is None


class _NotCopyable(Exception):
    def __init__(self, message: str, *, code: int) -> None:
        super().__init__(message)
        self.code = code


def test_an_error_copy_cannot_rebuild_is_raised_with_a_bounded_traceback() -> None:
    try:
        raise _NotCopyable("boom", code=1)
    except _NotCopyable as exc:
        kept = KeptError.of(exc)
    depths = []
    for _ in range(4):
        try:
            kept.raise_again()
        except _NotCopyable as again:
            depths.append(len(traceback.extract_tb(again.__traceback__)))
            assert isinstance(again.__cause__, EarlierRaise)
    assert len(set(depths)) == 1


def test_keeping_an_error_copy_cannot_rebuild_leaves_its_first_raise_whole() -> None:
    """The first raise is the one the caller reads: keeping the error must not strip
    its traceback or cause, nor the first-raise text it keeps."""

    def boundary() -> None:
        try:
            try:
                raise ValueError("the real cause")
            except ValueError as cause:
                raise _NotCopyable("boom", code=1) from cause
        except _NotCopyable as exc:
            kept.append(KeptError.of(exc))
            raise

    kept: list[KeptError] = []
    try:
        boundary()
    except _NotCopyable as out:
        assert isinstance(out.__cause__, ValueError)
        assert traceback.extract_tb(out.__traceback__)
    assert "Traceback" in kept[0].first_raise
    assert "the real cause" in kept[0].first_raise
