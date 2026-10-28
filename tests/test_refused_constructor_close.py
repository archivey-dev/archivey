"""A stream whose constructor refused its input must still close cleanly.

``IOBase.__del__`` calls ``close()`` on every instance not marked closed, including
one whose ``__init__`` raised. So ``close()`` must work on whatever ``__init__`` got
through before the raise. When it does not, the refusal dies a second time in the
finalizer, as an ``AttributeError`` reported at an arbitrary later moment.

A GIL build without ``-X dev`` drops that second error silently, so these tests do not
wait for the collector. They take the half-built object out of the ``__init__`` frame
in the traceback and call ``close()`` on it. That is stricter than the finalizer, which
skips an instance already marked closed: ``close()`` must not raise either way.
"""

from __future__ import annotations

import inspect
import io
from pathlib import Path
from typing import BinaryIO, TypeVar

import pytest

from archivey.diagnostics import DiagnosticPolicy
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    DiagnosticRaisedError,
    OpenError,
    PackageNotInstalledError,
    StreamNotSeekableError,
)
from archivey.internal.backends import zip_aes
from archivey.internal.backends.zip_aes import WinZipAesDecryptStream
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.decompressor_stream import (
    DecompressorStream,
    SeekPoint,
)
from archivey.internal.streams.verify import VerifyingStream
from archivey.internal.volumes import ConcatenatedFile
from tests.streams_util import ShortReadNonSeekable

T = TypeVar("T")


def _refused(
    cls: type[T],
    exc_info: pytest.ExceptionInfo[BaseException],
    method: str = "__init__",
) -> T:
    """The ``cls`` instance whose ``method`` (its constructor by default) raised
    ``exc_info``."""
    tb = exc_info.tb
    while tb is not None:
        frame = tb.tb_frame
        candidate = frame.f_locals.get("self")
        if frame.f_code.co_name == method and isinstance(candidate, cls):
            return candidate
        tb = tb.tb_next
    raise AssertionError(f"no {cls.__name__}.{method} frame in the traceback")


def _assert_closes_cleanly(obj: io.IOBase) -> None:
    obj.close()
    assert obj.closed
    obj.close()  # and again, as an idempotent close must


@pytest.mark.parametrize(
    ("sources", "error"),
    [
        pytest.param(lambda _tmp: [], ArchiveyUsageError, id="no-volumes"),
        pytest.param(lambda tmp: [tmp / "gone.bin"], OpenError, id="missing-path"),
        pytest.param(lambda tmp: [tmp], OpenError, id="directory"),
        pytest.param(
            lambda _tmp: [ShortReadNonSeekable(b"abc", 1)],
            StreamNotSeekableError,
            id="non-seekable-stream",
        ),
    ],
)
def test_concatenated_file_refusal_closes_cleanly(
    tmp_path: Path, sources: object, error: type[ArchiveyError]
) -> None:
    with pytest.raises(error) as caught:
        ConcatenatedFile(sources(tmp_path))  # type: ignore[operator]
    _assert_closes_cleanly(_refused(ConcatenatedFile, caught))


class _DecoderRefused(Exception):
    pass


def _refusing_decoder(_point: SeekPoint, _inner: BinaryIO) -> object:
    raise _DecoderRefused("declared parameters refused")


def test_decompressor_stream_refused_decoder_closes_the_file_it_opened(
    tmp_path: Path,
) -> None:
    path = tmp_path / "member.bin"
    path.write_bytes(b"payload")
    with pytest.raises(_DecoderRefused) as caught:
        DecompressorStream(path, make_decoder=_refusing_decoder)  # type: ignore[arg-type]
    stream = _refused(DecompressorStream, caught)
    # Released by the constructor itself, not left for the collector.
    assert stream.closed
    assert stream._inner.closed
    _assert_closes_cleanly(stream)


@pytest.mark.parametrize("owns_inner", [True, False])
def test_decompressor_stream_refused_decoder_respects_ownership(
    owns_inner: bool,
) -> None:
    inner = io.BytesIO(b"payload")
    with pytest.raises(_DecoderRefused) as caught:
        DecompressorStream(
            inner,
            make_decoder=_refusing_decoder,  # type: ignore[arg-type]
            owns_inner=owns_inner,
        )
    _assert_closes_cleanly(_refused(DecompressorStream, caught))
    assert inner.closed is owns_inner


class _CloseFails(io.BytesIO):
    def close(self) -> None:
        super().close()
        raise OSError("teardown failed")


@pytest.mark.parametrize(
    "construct",
    [
        pytest.param(
            lambda inner: DecompressorStream(
                inner,
                make_decoder=_refusing_decoder,  # type: ignore[arg-type]
                owns_inner=True,
            ),
            id="decompressor-stream",
        ),
        pytest.param(
            lambda inner: VerifyingStream(
                inner,
                {"no-such-digest": b"\x00"},  # type: ignore[dict-item]
                collector=DiagnosticCollector(policy=DiagnosticPolicy.STRICT),
            ),
            id="verifying-stream",
        ),
    ],
)
def test_refusal_outlives_a_failing_owned_inner_close(construct: object) -> None:
    """The refusal is the diagnosis; a teardown error must not replace it."""
    inner = _CloseFails(b"payload")
    with pytest.raises((_DecoderRefused, DiagnosticRaisedError)):
        construct(inner)  # type: ignore[operator]
    assert inner.closed


def test_verifying_stream_refused_by_verifier_diagnostic_closes_cleanly() -> None:
    inner = io.BytesIO(b"payload")
    collector = DiagnosticCollector(policy=DiagnosticPolicy.STRICT)
    with pytest.raises(DiagnosticRaisedError) as caught:
        VerifyingStream(
            inner,
            {"no-such-digest": b"\x00"},  # type: ignore[dict-item]
            collector=collector,
        )
    _assert_closes_cleanly(_refused(VerifyingStream, caught))
    assert inner.closed  # the wrapper owns its inner, as close() does


def test_decompressor_stream_missing_path_closes_cleanly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError) as caught:
        DecompressorStream(tmp_path / "gone.bin", make_decoder=_refusing_decoder)  # type: ignore[arg-type]
    _assert_closes_cleanly(_refused(DecompressorStream, caught))


def test_archive_stream_refused_by_verifier_diagnostic_closes_cleanly() -> None:
    """Under the strict policy an unverifiable digest raises while the verifier is built."""
    opened: list[io.BytesIO] = []

    def open_fn() -> BinaryIO:
        opened.append(io.BytesIO(b"payload"))
        return opened[-1]

    collector = DiagnosticCollector(policy=DiagnosticPolicy.STRICT)
    with pytest.raises(DiagnosticRaisedError) as caught:
        ArchiveStream._blank()._setup(
            open_fn,
            translate=lambda _e: None,
            collector=collector,
            expected_hashes={"no-such-digest": b"\x00"},  # type: ignore[dict-item]
        )
    _assert_closes_cleanly(_refused(ArchiveStream, caught, "_setup"))
    assert opened == []  # refused before the member was opened


@pytest.mark.parametrize(
    ("cipher_len", "crypto_present", "refusal"),
    [
        pytest.param(-1, True, ValueError, id="negative-cipher-len"),
        pytest.param(0, False, PackageNotInstalledError, id="cryptography-missing"),
    ],
)
def test_winzip_aes_stream_refusals_close_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    cipher_len: int,
    crypto_present: bool,
    refusal: type[Exception],
) -> None:
    monkeypatch.setattr(zip_aes, "_crypto_available", lambda: crypto_present)
    source = io.BytesIO(b"")
    with pytest.raises(refusal) as caught:
        WinZipAesDecryptStream(
            source, enc_key=b"\0" * 32, auth_key=b"\0" * 32, cipher_len=cipher_len
        )
    _assert_closes_cleanly(_refused(WinZipAesDecryptStream, caught))
    assert source.closed  # close always owns the member payload slice


# The inventory. ``close()`` on an instance built by ``__new__`` alone is the worst case: an
# ``__init__`` that raised on its first line. A class that survives it needs no entry. Every
# other ``IOBase`` subclass in ``src/`` is listed below, either because a test above covers
# its refusals or with the reason its ``__init__`` cannot raise before it assigns what
# ``close()`` reads. A new stream class fails here until someone makes that call.
_REFUSALS_TESTED_ABOVE = {
    "archivey.internal.volumes.ConcatenatedFile",
    "archivey.ArchiveStream",  # its __module__ is pinned to the public package
    "archivey.internal.streams.decompressor_stream.DecompressorStream",
    "archivey.internal.streams.verify.VerifyingStream",
    "archivey.internal.backends.zip_aes.WinZipAesDecryptStream",
}
_CLOSE_STATE_FIRST = {
    "archivey.internal.streams.streamtools.base.DelegatingStream": (
        "assigns _inner and _subclass_closes_inner before is_seekable()"
    ),
    "archivey.internal.streams.streamtools.locked.LockedStream": (
        "DelegatingStream.__init__, then a plain _lock assignment"
    ),
    "archivey.internal.backends.tar_reader._WalkHandoffStream": (
        "assigns _data and _view, all close() reads, before ReadOnlyIOStream.__init__"
    ),
    "archivey.internal.backends.tar_reader._MemberDataView": (
        "DelegatingStream.__init__ first; close() reads nothing assigned after it"
    ),
    "archivey.internal.streams.streamtools.fullcount.FullCountStream": (
        "no __init__ of its own: DelegatingStream's"
    ),
    "archivey.internal.streams.streamtools.readahead.ReadAheadStream": (
        "assigns every field close() reads before DelegatingStream.__init__"
    ),
    "archivey.internal.streams.streamtools.sparse.SparseStream": (
        "DelegatingStream.__init__ first; close() reads nothing assigned after it"
    ),
    "archivey.internal.streams.counting.CountingReader": "plain assignments only",
    "archivey.internal.streams.counting.OutputCountingStream": "plain assignments only",
    "archivey.internal.streams.counting.SeekCountingStream": "plain assignments only",
    "archivey.internal.streams.codecs.zlib_codec._DeflateEndCheckStream": (
        "plain assignments only"
    ),
    "archivey.internal.streams.codecs.gzip_codec._GzipTruncationCheckStream": (
        "plain assignments only"
    ),
    "archivey.internal.streams.codecs.bzip2_codec._Bzip2EmptyStreamCheck": (
        "plain assignments only"
    ),
    "archivey.internal.streams.codecs.zlib_codec._ZlibAdlerCheckStream": (
        "plain assignments only"
    ),
    "archivey.internal.streams.codecs.stdlib_takeover._StdlibOnAcceleratorError": (
        "plain assignments only"
    ),
    "archivey.internal.streams.codecs.rapidgzip_select._StdlibSeekContract": "plain assignments only",
    "archivey.internal.volumes.JoinedViews": (
        "assigns _views, then ConcatenatedFile.__init__, which sets its close state "
        "first; its views come from SharedSource.view, which has already checked them"
    ),
    "archivey.internal.backends.zip_reader._UnconfirmedZipCryptoStream": (
        "assigns _payload_complete, then DelegatingStream.__init__"
    ),
    "archivey.internal.backends.zipcrypto.ZipCryptoDecryptStream": (
        "assigns _source before RawIOBase.__init__; nothing after it can raise"
    ),
    "archivey.internal.backends.zip_aes.WinZipAesForwardStream": (
        "assigns _source, all close() reads, before ReadOnlyIOStream.__init__"
    ),
    "archivey.internal.password_confirm.UnverifiedPasswordReadWatch": (
        "assigns every field close() reads before DelegatingStream.__init__"
    ),
    "archivey.internal.backends.rar_reader._UnrarOwnedStream": (
        "assigns every field close() reads before DelegatingStream.__init__"
    ),
    "archivey.internal.streams.respawn.RespawnStream": "plain assignments only",
    "archivey.internal.backends.rar_copy_sources._TeeBlock": "plain assignments only",
    "archivey.internal.backends.sevenzip_pipeline._DecodedPastSizeCheck": (
        "plain assignments only"
    ),
    "archivey.internal.backends.sevenzip_reader._ReadAheadStream": (
        "plain assignments only"
    ),
    "archivey.internal.external.unar.UnarOutputStream": (
        "assigns every field close() reads before DelegatingStream.__init__"
    ),
    "archivey.internal.streams.streamtools.slice.SlicingStream": (
        "_init_from_source assigns _stream and _owns_inner before any check"
    ),
    "archivey.internal.streams.streamtools.slice.SharedView": (
        "_init_from_source assigns _stream and _owns_inner before any check"
    ),
    "archivey.internal.streams.crypto.AesDecryptStream": (
        "assigns _source and _owns_inner before source.tell() and the stage build"
    ),
}


def _archivey_iobase_classes() -> dict[str, type]:
    from tests.test_stream_bases import _import_all_archivey_modules

    _import_all_archivey_modules()
    found: dict[str, type] = {}
    stack: list[type] = [io.IOBase]
    while stack:
        for sub in stack.pop().__subclasses__():
            name = f"{sub.__module__}.{sub.__qualname__}"
            if name not in found:
                found[name] = sub
                stack.append(sub)
    return {name: cls for name, cls in found.items() if name.startswith("archivey.")}


def _survives_close_before_init(cls: type) -> bool:
    if inspect.isabstract(cls):
        # No instance can exist to be half-built. Python 3.12+ refuses the __new__
        # below outright; 3.11's io.RawIOBase __new__ still allows it.
        return True
    try:
        obj = cls.__new__(cls)
    except TypeError:
        return False
    try:
        obj.close()
    except AttributeError:
        return False
    finally:
        # Keep the finalizer from repeating the attempt at collection time.
        io.IOBase.close(obj)
    return True


def test_refused_constructor_close_inventory() -> None:
    classes = _archivey_iobase_classes()
    listed = _REFUSALS_TESTED_ABOVE | set(_CLOSE_STATE_FIRST)
    assert not (_REFUSALS_TESTED_ABOVE & set(_CLOSE_STATE_FIRST))
    assert not listed - set(classes), "listed classes that no longer exist"

    unclassified = sorted(
        name
        for name, cls in classes.items()
        if name not in listed and not _survives_close_before_init(cls)
    )
    assert not unclassified, (
        "these stream classes' close() fails on an instance whose __init__ raised "
        "early; assign what close() reads before anything that can raise, then list "
        "the class here with the reason, or cover its refusals with a test above: "
        f"{unclassified}"
    )
    stale = sorted(
        name
        for name in _CLOSE_STATE_FIRST
        if _survives_close_before_init(classes[name])
    )
    assert not stale, f"these need no entry any more: {stale}"
