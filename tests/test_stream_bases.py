"""The shared read-only stream bases (`ReadOnlyIOStream`, `DelegatingStream`)."""

from __future__ import annotations

import ast
import inspect
import io
import textwrap
from pathlib import Path
from typing import Never, get_type_hints

import pytest

from archivey.internal.streams.streamtools import (
    DelegatingStream,
    OneReadEachStream,
    ReadOnlyIOStream,
    ensure_bufferedio,
)
from tests.streams_util import NonSeekableBytesIO


class _FixedReader(ReadOnlyIOStream):
    """Minimal subclass: only implements read(), to exercise the base's derived methods."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._buf = io.BytesIO(data)

    def read(self, n: int = -1, /) -> bytes:
        return self._buf.read(n)


def test_readonly_base_derives_readinto_readall_and_flags() -> None:
    s = _FixedReader(b"hello world")
    # readinto is derived from read()
    buf = bytearray(5)
    assert s.readinto(buf) == 5
    assert bytes(buf) == b"hello"
    # readall reads the rest via the read-loop
    assert s.readall() == b" world"
    assert s.readable() is True
    assert s.writable() is False
    with pytest.raises(io.UnsupportedOperation):
        s.write(b"x")


def test_readonly_readinto_raises_on_overlong_read() -> None:
    """A misbehaving read() that ignores n is a contract violation, not silent truncation."""

    class _OverRead(ReadOnlyIOStream):
        def read(self, n: int = -1, /) -> bytes:
            return b"abcdef"

    buf = bytearray(4)
    with pytest.raises(ValueError, match=r"read\(4\) returned 6 bytes"):
        _OverRead().readinto(buf)


def test_readonly_base_read_is_the_runtime_guard() -> None:
    # read() is @abstractmethod. On Python 3.12+ ABCMeta rejects construction of a
    # subclass that omits it (TypeError). On 3.11, io.RawIOBase's C __new__ still lets
    # the instance form, so the NotImplementedError body in read() is the runtime guard.
    class _ForgotRead(ReadOnlyIOStream):
        pass

    with pytest.raises((TypeError, NotImplementedError)):
        _ForgotRead().read()


def test_readonly_base_name_is_absent() -> None:
    """Nameless streams must not expose ``name`` (pycdlib Windows + reopen-by-name)."""
    s = _FixedReader(b"x")
    assert not hasattr(s, "name")


def test_readonly_base_name_annotation_does_not_claim_str() -> None:
    """The getter always raises; annotating ``str`` lets a checker accept ``.name.upper()``."""
    getter = ReadOnlyIOStream.name.fget
    assert getter is not None
    assert get_type_hints(getter).get("return") is Never


def test_delegating_base_name_absent_without_inner_path() -> None:
    s = DelegatingStream(io.BytesIO(b"x"))
    assert not hasattr(s, "name")


def test_delegating_base_forwards_name_from_inner_file(tmp_path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"x")
    with open(path, "rb") as inner:
        s = DelegatingStream(inner)
        assert s.name == str(path)


def test_delegating_base_forwards_to_inner() -> None:
    inner = io.BytesIO(b"abcdefgh")
    s = DelegatingStream(inner)
    assert s.read(3) == b"abc"
    assert s.tell() == 3
    assert s.seekable() is True
    assert s.seek(0) == 0
    assert s.read(2) == b"ab"
    # zero-copy readinto passthrough to the inner
    buf = bytearray(4)
    assert s.readinto(buf) == 4
    assert bytes(buf) == b"cdef"
    assert s.readable() is True and s.writable() is False


def test_delegating_seekable_is_fixed_at_construction() -> None:
    class _Flip(io.BytesIO):
        def __init__(self) -> None:
            super().__init__(b"x")
            self.flag = True

        def seekable(self) -> bool:
            return self.flag

    inner = _Flip()
    s = DelegatingStream(inner)
    assert s.seekable() is True
    inner.flag = False
    assert s.seekable() is True


def test_replace_inner_recaches_seekable() -> None:
    s = DelegatingStream(io.BytesIO(b"x"))
    assert s.seekable() is True
    s._replace_inner(NonSeekableBytesIO(b"y"))
    assert s.seekable() is False


def test_replace_inner_closes_the_old_inner() -> None:
    old = io.BytesIO(b"x")
    s = DelegatingStream(old)
    s._replace_inner(io.BytesIO(b"y"))
    assert old.closed
    assert s.read() == b"y"


def test_replace_inner_survives_an_old_inner_that_fails_to_close() -> None:
    class _FailingClose(io.BytesIO):
        def close(self) -> None:
            raise OSError("close failed")

    s = DelegatingStream(_FailingClose(b"x"))
    new = io.BytesIO(b"y")
    s._replace_inner(new)
    assert s._inner is new
    assert s.read() == b"y"


def test_replace_inner_leaves_the_old_inner_to_a_subclass_that_closes_it() -> None:
    old = io.BytesIO(b"x")
    s = DelegatingStream(old, subclass_closes_inner=True)
    s._replace_inner(io.BytesIO(b"y"))
    assert not old.closed
    s.close()


def test_delegating_base_close_closes_inner() -> None:
    inner = io.BytesIO(b"data")
    s = DelegatingStream(inner)
    s.close()
    assert inner.closed
    assert s.closed
    s.close()  # idempotent


def test_delegating_close_marks_closed_when_inner_close_fails() -> None:
    class _FailingClose(io.BytesIO):
        def close(self) -> None:
            raise OSError("boom")

    s = DelegatingStream(_FailingClose(b"x"))
    with pytest.raises(OSError, match="boom"):
        s.close()
    assert s.closed
    s.close()  # idempotent after the failed inner close


def test_delegating_subclass_closes_inner_skips_inner() -> None:
    inner = io.BytesIO(b"data")
    s = DelegatingStream(inner, subclass_closes_inner=True)
    s.close()
    assert s.closed
    assert not inner.closed
    inner.close()


def test_delegating_base_readinto_falls_back_without_inner_readinto() -> None:
    class _NoReadinto:
        def __init__(self, data: bytes) -> None:
            self._b = io.BytesIO(data)

        def read(self, n: int = -1, /) -> bytes:
            return self._b.read(n)

        # Without this, the wrapper's finalizer raises an unraisable AttributeError
        # when it closes the inner stream, in whichever test runs the collection.
        def close(self) -> None:
            self._b.close()

    s = DelegatingStream(_NoReadinto(b"xyz"))  # type: ignore[arg-type]
    buf = bytearray(2)
    assert s.readinto(buf) == 2
    assert bytes(buf) == b"xy"
    s.close()


class _RawIOWithoutReadinto(io.RawIOBase):
    """``io.RawIOBase`` advertises ``readinto`` but the default raises ``NotImplementedError``."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._b = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return self._b.read(n)


def test_delegating_readinto_falls_back_when_inner_readinto_unimplemented() -> None:
    s = DelegatingStream(_RawIOWithoutReadinto(b"xyz"))
    buf = bytearray(2)
    assert s.readinto(buf) == 2
    assert bytes(buf) == b"xy"


def test_delegating_readinto_none_raises_blocking() -> None:
    class _NonBlockingReadinto(io.BytesIO):
        def readinto(self, b):  # type: ignore[no-untyped-def]
            return None

    with pytest.raises(BlockingIOError):
        DelegatingStream(_NonBlockingReadinto(b"x")).readinto(bytearray(4))


def test_delegating_readinto_passthrough_false_routes_through_read() -> None:
    """With readinto_passthrough=False, readinto goes through the subclass's read() (so a
    side-effecting read override is not bypassed) — even when the inner has its own readinto."""
    reads: list[int] = []

    class _Tracking(DelegatingStream):
        def __init__(self, inner: io.BytesIO) -> None:
            super().__init__(inner, readinto_passthrough=False)

        def read(self, n: int = -1, /) -> bytes:
            data = self._inner.read(n)
            reads.append(len(data))  # side effect that must run on readinto too
            return data

    s = _Tracking(io.BytesIO(b"abcdef"))
    assert s.readinto_passthrough is False
    buf = bytearray(4)
    assert s.readinto(buf) == 4
    assert bytes(buf) == b"abcd"
    assert reads == [4]  # read() ran (passthrough would have left this empty)


def test_delegating_readinto_passthrough_class_flag_routes_through_read() -> None:
    """The production path: class flag False, constructor kwarg omitted."""
    reads: list[int] = []

    class _Tracking(DelegatingStream):
        readinto_passthrough = False

        def read(self, n: int = -1, /) -> bytes:
            data = self._inner.read(n)
            reads.append(len(data))
            return data

    s = _Tracking(io.BytesIO(b"abcdef"))
    assert s.readinto_passthrough is False
    buf = bytearray(4)
    assert s.readinto(buf) == 4
    assert bytes(buf) == b"abcd"
    assert reads == [4]


def test_delegating_peel_for_source_size_constructor_override() -> None:
    """Ad-hoc construction can opt a plain DelegatingStream into peeling."""
    from archivey.internal.streams.streamtools import source_byte_size

    opaque = DelegatingStream(io.BytesIO(b"0123456789"))
    assert source_byte_size(opaque) is None
    peeled = DelegatingStream(io.BytesIO(b"0123456789"), peel_for_source_size=True)
    assert source_byte_size(peeled) == 10


def test_delegating_stream_does_not_forward_resume_offset() -> None:
    class _Inner(io.BytesIO):
        def nearest_resume_offset(self, target: int) -> int:
            return 0

    s = DelegatingStream(_Inner(b"x"))
    assert not hasattr(s, "nearest_resume_offset")


def test_ask_resume_offset_helper() -> None:
    from archivey.internal.streams.resume import ask_resume_offset
    from archivey.internal.streams.streamtools.binaryio import (
        ask_resume_offset as from_binaryio,
    )

    class _Inner:
        def nearest_resume_offset(self, target: int) -> int:
            return target // 2

    assert ask_resume_offset is from_binaryio
    assert ask_resume_offset(_Inner(), 10) == 5
    assert ask_resume_offset(io.BytesIO(b"x"), 10) is None
    assert ask_resume_offset(None, 10) is None


def test_verifying_stream_forwards_resume_offset() -> None:
    from archivey.internal.streams.verify import VerifyingStream

    class _Inner(io.BytesIO):
        def nearest_resume_offset(self, target: int) -> int:
            return 7

    s = VerifyingStream(_Inner(b"x"), {})
    assert s.nearest_resume_offset(1) == 7


def _import_all_archivey_modules() -> None:
    """Import every archivey module so ``__subclasses__()`` is not collection-order-blind.

    ``archivey.__main__`` calls ``main()`` at import, so it is skipped.

    This walk also proves every ``archivey.*`` module imports with no extras
    (the ``[core-only]`` lazy-optional-import boundary). A top-level extra
    import fails here, not as an unrelated ``ImportError`` later in the suite.
    """
    import importlib
    import pkgutil

    import archivey

    for module in pkgutil.walk_packages(archivey.__path__, prefix="archivey."):
        if module.name.endswith("__main__"):
            continue
        try:
            importlib.import_module(module.name)
        except Exception as exc:  # any import-time failure is this check
            raise ImportError(
                f"{module.name} failed to import while walking archivey modules "
                "for the ReadOnlyIOStream resume-offset inventory. This walk also "
                "proves every archivey module imports with no extras ([core-only]); "
                "a top-level extra import fails here."
            ) from exc


def _is_archivey_class(cls: type) -> bool:
    # ``archivey`` itself counts: public classes defined under ``internal`` report the
    # package root as their module (``archivey/__init__.py`` pins it for pickling).
    module = getattr(cls, "__module__", "")
    return module == "archivey" or module.startswith("archivey.")


def _readonly_stream_subclasses() -> set[type]:
    found: set[type] = set()
    stack = [ReadOnlyIOStream]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            if sub not in found:
                found.add(sub)
                stack.append(sub)
    found = {cls for cls in found if _is_archivey_class(cls)}
    # Seed is ReadOnlyIOStream; subclasses include DelegatingStream. Discard both
    # bases so the inventory is the wrappers that need a resume-offset decision.
    found.discard(ReadOnlyIOStream)
    found.discard(DelegatingStream)
    return found


def test_readonly_stream_resume_offset_inventory() -> None:
    """Every ReadOnlyIOStream subclass is classified: forwards/owns, inherits a
    contiguous-window translation, or remaps / is not on the decompressed chain.

    Forwarding is opt-in. A new wrapper that sits between ArchiveStream and a
    seek-point table and forgets nearest_resume_offset becomes a silent
    diagnostic hole (None → resume 0). Walking only ``DelegatingStream`` misses
    ``VerifyingStream``-shaped holes; importing five modules by hand misses
    subclasses in modules this test never imported.

    Importing the package first also proves every ``archivey.*`` module imports
    with no extras (see ``_import_all_archivey_modules``).
    """
    _import_all_archivey_modules()

    import archivey.internal.source as source_mod
    import archivey.internal.streams.codecs.bcj2_filter as bcj2
    import archivey.internal.streams.streamtools.slice as slice_mod
    from archivey.internal import detection, password_confirm
    from archivey.internal.backends import (
        rar_copy_sources,
        rar_reader,
        sevenzip_pipeline,
        sevenzip_reader,
        tar_parser,
        tar_reader,
        zip_aes,
        zip_forward_reader,
        zip_local_walk,
        zip_reader,
        zipcrypto,
    )
    from archivey.internal.external import cli, unar
    from archivey.internal.streams import (
        archive_stream,
        blocks,
        codecs,
        counting,
        crypto,
        decompressor_stream,
        respawn,
        verify,
    )
    from archivey.internal.streams.codecs import rapidgzip_child
    from archivey.internal.streams.streamtools import (
        fullcount,
        locked,
        readahead,
        solid,
        sparse,
    )

    forwards_or_owns = {
        archive_stream.ArchiveStream,
        blocks.BlockStream,  # owns its resume points: every block start
        bcj2.Bcj2DecoderStream,  # owns its one resume point: the folder start
        rapidgzip_child.RapidgzipChildStream,  # asks the child's rapidgzip index
        codecs.zlib_codec._DeflateEndCheckStream,
        codecs.gzip_codec._GzipTruncationCheckStream,
        codecs.zlib_codec._ZlibAdlerCheckStream,
        codecs.bzip2_codec._Bzip2EmptyStreamCheck,
        codecs.stdlib_takeover._StdlibOnAcceleratorError,
        codecs.rapidgzip_select._StdlibSeekContract,
        counting.OutputCountingStream,
        readahead.ReadAheadStream,  # the inner's offsets
        decompressor_stream.DecompressorStream,
        crypto.AesDecryptStream,  # dense CBC restart; compose with inner
        sevenzip_pipeline._DecodedPastSizeCheck,  # same offsets as the codec it wraps
        slice_mod.SlicingStream,  # translates remapped offset space; clamp at 0
        verify.VerifyingStream,
    }
    # SharedView's window is the same contiguous shift as SlicingStream, so
    # inheriting that translation is correct. A future SlicingStream subclass
    # whose window is not a contiguous shift must decline or override — it
    # must not park here, and leftover will fail until it is classified.
    inherits_contiguous_translation = {
        slice_mod.SharedView,
    }
    remaps_or_not_on_chain = {
        locked.LockedStream,
        # Over a format plugin's own member stream, which has no table below it.
        fullcount.FullCountStream,
        counting.CountingReader,
        counting.SeekCountingStream,
        rar_reader._UnrarOwnedStream,
        respawn.RespawnStream,
        # Subprocess stdout, like the unrar pipe: nothing below it has a table.
        unar.UnarOutputStream,
        cli.ProcessOutputStream,  # the base of the two subprocess stdout streams
        solid._MemberSlice,
        # A table below it (gzip under a .tar.gz) is in stored offsets, and the map
        # from logical to stored offsets is not a contiguous shift, so a slice's
        # translation does not carry over. Declining costs this: ArchiveStream takes
        # None as a resume at 0, so where a rewind warning applies (a .tar.gz), a
        # backward seek reports its whole read position as re-decoded work, more
        # than it costs when the member is mostly holes.
        sparse.SparseStream,
        # The source boundary: it wraps the archive source, and every seek-point
        # table is above it.
        source_mod.ArchiveSource,
        # A raw view of the source for a plain tar's streaming buffer: below every
        # seek-point table, like the source it reads.
        source_mod._ArrivedView,
        # Decrypt stages below the codec: compressed-side offsets, no table.
        zip_aes.WinZipAesDecryptStream,
        zip_aes.WinZipAesForwardStream,
        zipcrypto.ZipCryptoDecryptStream,
        # Translates errors between the reader's unverified-read watch and the
        # member's verifier; like the watch, nothing above it asks it for a resume
        # offset.
        zip_reader._UnconfirmedZipCryptoStream,
        # Wraps an encrypted member's decoded stream to watch for an abandoned read;
        # nothing above it asks it for a resume offset.
        password_confirm.UnverifiedPasswordReadWatch,
        detection._BoundedPeekReader,
        # Under a solid RAR pass's SolidBlockReader, which only reads forward.
        rar_copy_sources._TeeBlock,
        # A member's stored bytes, read forward from the walk's stream (for .tar.gz,
        # the decompressed stream) in one pass. TAR stores member data as is, so no
        # codec above it has a table, and a pass's member streams are forward-only.
        tar_parser._ForwardSlice,
        # A random-access pass's member data: the slice above, or a member view from
        # where the slice stopped once the walk moves on. Forward-only, stored bytes.
        tar_reader._WalkHandoffStream,
        # A random-access member's data view: the view's offsets, forwarded.
        tar_reader._MemberDataView,
        # A ZIP member's compressed bytes, read forward from the local-header walk's
        # stream in one pass, below any codec: compressed offsets, no table.
        zip_local_walk.MemberData,
        zip_local_walk._SizedData,
        zip_local_walk._CodecData,
        zip_local_walk._ScannedData,
        # The bytes a pipe ZIP pass kept after its members, read forward once by a
        # walk over a member the directory places there: the stream under the
        # walk, archive offsets, no table.
        zip_local_walk._HeldBytes,
        # A pipe ZIP pass's member stream, over the codec stream the pass reads
        # once: forward-only, so nothing seeks it or asks it for a resume offset.
        zip_forward_reader._PassStream,
        # The member's data under a pipe pass's decrypt stage: compressed offsets,
        # read forward once.
        zip_forward_reader._CutShortWatch,
        # Kept ciphertext, read once from the start for a link target.
        zip_forward_reader._KeptData,
        # A password candidate's view of the spooled member data, and the winner's
        # replay of that spool before the rest of the data: compressed offsets,
        # read forward once, below any codec.
        zip_forward_reader._SpoolView,
        zip_forward_reader._Replay,
        # A 7z pass's member stream, forward-only like the folder decode under it:
        # nothing seeks it, so nothing asks it for a resume offset.
        sevenzip_reader._ReadAheadStream,
    }

    found = _readonly_stream_subclasses()
    leftover = (
        found
        - forwards_or_owns
        - remaps_or_not_on_chain
        - inherits_contiguous_translation
    )
    assert leftover == set(), (
        "new ReadOnlyIOStream subclass needs a nearest_resume_offset decision "
        f"(forwards/owns a table, inherits a contiguous-window translation, "
        f"or remaps / not on the decompressed chain): {leftover}"
    )
    extra_classified = (
        forwards_or_owns | remaps_or_not_on_chain | inherits_contiguous_translation
    ) - found
    assert extra_classified == set(), (
        "classified a class the walk did not find (typo or it is no longer "
        f"a ReadOnlyIOStream): {extra_classified}"
    )
    missing_method = [
        cls.__name__
        for cls in forwards_or_owns
        if "nearest_resume_offset" not in cls.__dict__
    ]
    assert missing_method == [], (
        "classified as forwards/owns but does not define nearest_resume_offset: "
        f"{missing_method}"
    )
    wrong_inherit = [
        cls.__name__
        for cls in inherits_contiguous_translation
        if cls.__dict__.get("nearest_resume_offset") is not None
        or getattr(cls, "nearest_resume_offset", None)
        is not slice_mod.SlicingStream.nearest_resume_offset
    ]
    assert wrong_inherit == [], (
        "classified as inheriting SlicingStream's contiguous-window translation "
        f"but overrides it or does not inherit that method: {wrong_inherit}"
    )
    wrong_remap = [
        cls.__name__
        for cls in remaps_or_not_on_chain
        if getattr(cls, "nearest_resume_offset", None)
        is slice_mod.SlicingStream.nearest_resume_offset
    ]
    assert wrong_remap == [], (
        "classified as remaps / not on the chain but inherits "
        "SlicingStream.nearest_resume_offset (a contiguous-window translation; "
        f"that class belongs in inherits_contiguous_translation): {wrong_remap}"
    )


def _delegating_stream_subclasses() -> set[type]:
    found: set[type] = set()
    stack = [DelegatingStream]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            if sub not in found:
                found.add(sub)
                stack.append(sub)
    return {cls for cls in found if _is_archivey_class(cls)}


_INIT_KWARG_MISSING = object()


def _init_keyword(cls: type, name: str) -> object:
    """Literal value of ``name=`` in *this class's* ``__init__`` source, or missing.

    Walks AST of the constructor, not a substring: a comment can mention the
    keyword; ``test_init_keyword_ignores_comments`` pins that. Only
    ``cls.__dict__`` counts — a subclass that inherits ``__init__`` is not
    charged with the parent's kwarg. Inventories use this only for the
    "no production kwarg" assert; the flag value itself is read off the
    class, so inheritance is not this helper's problem.
    """
    if "__init__" not in cls.__dict__:
        return _INIT_KWARG_MISSING
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls.__init__)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "__init__"):
            continue
        for kw in node.keywords:
            if kw.arg != name:
                continue
            if isinstance(kw.value, ast.Constant):
                return kw.value.value
            return ast.dump(kw.value)
    return _INIT_KWARG_MISSING


def test_delegating_stream_close_inventory() -> None:
    """Every DelegatingStream subclass has a recorded close contract.

    DelegatingStream owns its inner. A subclass that closes inner itself
    (reap a subprocess, a finalize guard) sets ``_SUBCLASS_CLOSES_INNER = True``
    on the class and omits the constructor kwarg; every other subclass rides
    the owning default. The walk asserts the class flag. A production
    ``__init__`` that still passes ``subclass_closes_inner=True`` while leaving
    the flag False used to evade that check (the kwarg overrides the flag at
    runtime). The constructor kwarg stays for ad-hoc construction in tests;
    that path is not inventory-checked. The "no production kwarg" check uses
    ``_init_keyword`` (AST, not a substring) so a comment mentioning the
    flag cannot trip it. Same grain as
    ``test_readonly_stream_resume_offset_inventory``.
    """
    _import_all_archivey_modules()

    from archivey.internal import password_confirm
    from archivey.internal.backends import (
        rar_copy_sources,
        rar_reader,
        sevenzip_pipeline,
        tar_reader,
        zip_reader,
    )
    from archivey.internal.external import cli, unar
    from archivey.internal.streams import codecs, counting
    from archivey.internal.streams.streamtools import (
        fullcount,
        locked,
        readahead,
        sparse,
    )

    owns_via_base = {
        locked.LockedStream,
        fullcount.FullCountStream,
        counting.CountingReader,
        counting.OutputCountingStream,
        counting.SeekCountingStream,
        codecs.zlib_codec._DeflateEndCheckStream,
        codecs.gzip_codec._GzipTruncationCheckStream,
        codecs.zlib_codec._ZlibAdlerCheckStream,
        codecs.bzip2_codec._Bzip2EmptyStreamCheck,
        codecs.stdlib_takeover._StdlibOnAcceleratorError,
        codecs.rapidgzip_select._StdlibSeekContract,
        sevenzip_pipeline._DecodedPastSizeCheck,
        zip_reader._UnconfirmedZipCryptoStream,
        password_confirm.UnverifiedPasswordReadWatch,
        rar_copy_sources._TeeBlock,
        sparse.SparseStream,
        readahead.ReadAheadStream,
        tar_reader._MemberDataView,
    }
    subclass_closes_inner = {
        cli.ProcessOutputStream,
        rar_reader._UnrarOwnedStream,
        unar.UnarOutputStream,
    }
    found = _delegating_stream_subclasses()
    leftover = found - owns_via_base - subclass_closes_inner
    assert leftover == set(), (
        "new DelegatingStream subclass needs a close-ownership decision "
        "(rides the owning default, or _SUBCLASS_CLOSES_INNER = True): "
        f"{leftover}"
    )
    extra_classified = (owns_via_base | subclass_closes_inner) - found
    assert extra_classified == set(), (
        "classified a class the walk did not find (typo or it is no longer "
        f"a DelegatingStream): {extra_classified}"
    )
    wrong_flag = {
        cls
        for cls in found
        if cls._SUBCLASS_CLOSES_INNER is not (cls in subclass_closes_inner)
    }
    assert wrong_flag == set(), (
        "DelegatingStream subclass _SUBCLASS_CLOSES_INNER does not match "
        f"its inventory group: {wrong_flag}"
    )
    passed_kwarg = {
        cls
        for cls in found
        if _init_keyword(cls, "subclass_closes_inner") is not _INIT_KWARG_MISSING
    }
    assert passed_kwarg == set(), (
        "production DelegatingStream subclass __init__ must set "
        "_SUBCLASS_CLOSES_INNER on the class and omit the constructor kwarg "
        f"(kwarg is for ad-hoc tests): {passed_kwarg}"
    )


def test_delegating_stream_readinto_passthrough_inventory() -> None:
    """A read override without a readinto override must disable passthrough.

    ``DelegatingStream.readinto`` zero-copies to ``inner.readinto`` by default,
    which bypasses this class's ``read``. The production cases that override
    ``read`` only (``_GzipTruncationCheckStream``, ``_Bzip2EmptyStreamCheck``,
    and ``ProcessOutputStream`` with its two subclasses) set
    ``readinto_passthrough = False`` on the class and omit the constructor
    kwarg so the side effect still runs. Deleting those class flags leaves the
    rest of the suite green; this test is the gate that does not.

    The dangerous set is computed from each class's MRO below
    ``DelegatingStream``, not a hand-maintained list: overrides ``read``
    (itself or through a base), does not override ``readinto``. Runtime
    auto-detection of an overridden ``read`` is still rejected (base
    docstring) — a plain forward of ``read`` should keep the zero-copy path,
    and silent auto-detection would hide that choice. No such forward exists
    today (the five classes that override ``read`` also override
    ``readinto``). A later one needs a declared exemption here, not a silent
    ``True``.

    Mandatory-explicit ``True`` on the other eight would record a decision
    that was never made: three never override ``read``, five already
    implement ``readinto``. Those must leave the class flag at the default.

    The walk asserts the class flag. A production ``__init__`` that still
    passes ``readinto_passthrough=False`` while leaving the flag True used
    to be the only way to set it, and would now evade a flag-only check
    (the kwarg overrides the flag at runtime). The constructor kwarg stays
    for ad-hoc construction in tests; that path is not inventory-checked.
    Same grain as ``test_delegating_stream_close_inventory``.

    Mutants this test must catch:

    - ``readinto_passthrough=False`` restored on ``ProcessOutputStream.__init__``'s
      ``super()`` while the class flag stays False → ``passed_kwarg``

    Reuses ``_delegating_stream_subclasses`` (archivey modules only); test-file
    subclasses do not trip it.
    """
    _import_all_archivey_modules()
    found = _delegating_stream_subclasses()

    def defines(cls: type, name: str) -> bool:
        # Inherited overrides count: ProcessOutputStream's read serves both subclasses.
        mro = cls.__mro__
        return any(name in c.__dict__ for c in mro[: mro.index(DelegatingStream)])

    needs_via_read = {
        cls for cls in found if defines(cls, "read") and not defines(cls, "readinto")
    }
    missing = {cls for cls in needs_via_read if cls.readinto_passthrough is not False}
    assert missing == set(), (
        "DelegatingStream subclass overrides read but not readinto; "
        "must set readinto_passthrough = False on the class so readinto "
        f"does not skip the read side effect: {missing}"
    )
    unexpected = {
        cls
        for cls in found
        if cls not in needs_via_read and cls.readinto_passthrough is not True
    }
    assert unexpected == set(), (
        "readinto_passthrough is irrelevant when the class does not override "
        "read, or already implements readinto. Leave the class flag at the "
        f"default: {unexpected}"
    )
    passed_kwarg = {
        cls
        for cls in found
        if _init_keyword(cls, "readinto_passthrough") is not _INIT_KWARG_MISSING
    }
    assert passed_kwarg == set(), (
        "production DelegatingStream subclass __init__ must set "
        "readinto_passthrough on the class and omit the constructor kwarg "
        f"(kwarg is for ad-hoc tests): {passed_kwarg}"
    )


def test_delegating_stream_peel_inventory() -> None:
    """Production peel is a class flag; the constructor kwarg is tests-only.

    ``source_byte_size`` peels on the resolved instance value, so
    ``super().__init__(inner, peel_for_source_size=True)`` peels even when
    the class flag stays False. Close and readinto already reject that
    production kwarg. Mutants this test must catch:

    - ``peel_for_source_size=True`` on ``SeekCountingStream.__init__``'s
      ``super()`` → ``passed_kwarg``
    - ``OutputCountingStream.peel_for_source_size = True`` → True-set

    ``ArchiveSource`` is a ``ReadOnlyIOStream`` and is not in this walk; it answers
    ``source_byte_size`` from its own ``size`` rather than by being peeled.
    """
    _import_all_archivey_modules()
    from archivey.internal.streams import counting

    found = _delegating_stream_subclasses()
    peels = {cls for cls in found if cls.peel_for_source_size is True}
    assert peels == {
        counting.SeekCountingStream,
    }, (
        "DelegatingStream subclass peel_for_source_size does not match "
        "the inventory (only a pass-through wrapper whose size is the "
        f"inner's may peel): {peels}"
    )
    passed_kwarg = {
        cls
        for cls in found
        if _init_keyword(cls, "peel_for_source_size") is not _INIT_KWARG_MISSING
    }
    assert passed_kwarg == set(), (
        "production DelegatingStream subclass __init__ must set "
        "peel_for_source_size on the class and omit the constructor kwarg "
        f"(kwarg is for ad-hoc tests): {passed_kwarg}"
    )


def test_init_keyword_ignores_comments() -> None:
    """AST lookup must not treat a comment mentioning the flag as passing it."""

    class _Commented(DelegatingStream):
        def __init__(self, inner: io.BytesIO) -> None:
            # readinto_passthrough=False and subclass_closes_inner=True in a
            # comment must not count
            super().__init__(inner)

    assert _init_keyword(_Commented, "readinto_passthrough") is _INIT_KWARG_MISSING
    assert _init_keyword(_Commented, "subclass_closes_inner") is _INIT_KWARG_MISSING


def test_init_keyword_does_not_attribute_parent_kwarg() -> None:
    """A subclass that writes no __init__ is not charged with the parent's kwarg."""

    class _Parent(DelegatingStream):
        def __init__(self, inner: io.BytesIO) -> None:
            super().__init__(inner, readinto_passthrough=False)

        def read(self, n: int = -1, /) -> bytes:
            return self._inner.read(n)

    class _Child(_Parent):
        pass

    assert _init_keyword(_Parent, "readinto_passthrough") is False
    assert _init_keyword(_Child, "readinto_passthrough") is _INIT_KWARG_MISSING


def test_delegating_read_none_raises_blocking() -> None:
    """A non-blocking inner's ``None`` is refused, not passed on as if it were bytes."""

    class _NonBlockingRead(io.BytesIO):
        def read(self, n: int | None = -1, /) -> bytes:
            return None  # type: ignore[return-value]

    with pytest.raises(BlockingIOError):
        DelegatingStream(_NonBlockingRead(b"x")).read(4)


def test_one_read_each_stream_passes_short_reads_and_answers_mode_and_name(
    tmp_path: Path,
) -> None:
    """``OneReadEachStream`` is buffered, so ``ensure_bufferedio`` keeps it and its
    source's short reads reach the reader; ``mode`` and ``name`` are not ``None``."""

    class Steps(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def read(self, n: int = -1, /) -> bytes:  # type: ignore[override]
            return b"ab"[: max(n, 0)] if n else b""

    stream = OneReadEachStream(Steps())
    assert ensure_bufferedio(stream) is stream
    assert stream.read(100) == b"ab"
    assert stream.mode == "rb"
    assert not hasattr(OneReadEachStream(io.BytesIO(b"abc")), "name")
    path = tmp_path / "named.bin"
    path.write_bytes(b"abc")
    with path.open("rb") as named:
        assert OneReadEachStream(named).name == str(path)
