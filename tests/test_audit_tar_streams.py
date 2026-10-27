"""Audit reproducers: TAR and single-file compressed streams.

Each test reproduces a bug an audit found and asserts the promised behaviour, now that
the fix has landed; they are kept as ordinary regression tests. The promise each test
checks is named in its docstring.
"""

from __future__ import annotations

import io
import random
import signal
import sys
import tarfile
import tracemalloc
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveFormat,
    ArchiveyConfig,
    ContainerFormat,
    DiagnosticPolicy,
    DiagnosticRaisedError,
    ListingLimits,
    StreamFormat,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from tests.conftest import requires, requires_zstd
from tests.memory_util import traced_peak

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _octal(value: int, width: int) -> bytes:
    return b"%0*o\0" % (width - 1, value)


def _base256(value: int, width: int) -> bytes:
    """GNU base-256: two's complement big-endian, top bit of the first byte set."""
    raw = bytearray((value % (1 << (8 * width))).to_bytes(width, "big"))
    raw[0] = 0x80 if value >= 0 else 0xFF
    return bytes(raw)


def _numeric(value: int, width: int) -> bytes:
    if 0 <= value < 8 ** (width - 1):
        return _octal(value, width)
    return _base256(value, width)


def _fix_checksum(header: bytearray) -> bytearray:
    block = bytes(header[:512])
    total = sum(block[:148]) + 8 * 32 + sum(block[156:512])
    header[148:156] = b"%06o\0 " % total
    return header


def _member(name: str, data: bytes, **fields: object) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in fields.items():
        setattr(info, key, value)
    fmt = tarfile.PAX_FORMAT if info.pax_headers else tarfile.GNU_FORMAT
    return info.tobuf(format=fmt) + data + b"\0" * (-len(data) % 512)


def _patched(member: bytes, offset: int, value: bytes) -> bytes:
    """``member`` (one header + data) with a raw header field overwritten."""
    header = bytearray(member[:512])
    header[offset : offset + len(value)] = value
    return bytes(_fix_checksum(header)) + member[512:]


_TRAILER = b"\0" * 1024


def _gnu_sparse(
    name: str, entries: list[tuple[int, int]], realsize: int, packed: bytes
) -> bytes:
    """An old-GNU ``S`` member: up to four ``(offset, numbytes)`` map entries in the
    header, ``realsize`` as the logical size and ``packed`` as the stored data."""
    info = tarfile.TarInfo(name)
    info.size = len(packed)
    info.type = tarfile.GNUTYPE_SPARSE
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    for i, (offset, numbytes) in enumerate(entries):
        pos = 386 + 24 * i
        header[pos : pos + 12] = _numeric(offset, 12)
        header[pos + 12 : pos + 24] = _numeric(numbytes, 12)
    header[483:495] = _numeric(realsize, 12)
    return bytes(_fix_checksum(header)) + packed + b"\0" * (-len(packed) % 512)


class _OverBudget(BaseException):
    """Raised by the watchdog; a BaseException so no library catch can swallow it."""


@contextmanager
def _watchdog(seconds: float) -> Generator[None, None, None]:
    """Interrupt the body after ``seconds`` of wall time (POSIX only)."""

    def _fire(signum: int, frame: object) -> None:
        raise _OverBudget(f"did not finish within {seconds} s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _drain(ar) -> None:
    for _member, stream in ar.stream_members():
        if stream is not None:
            stream.read()


# ---------------------------------------------------------------------------
# TAR: a size field the archive picks drives the streaming skip loop
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="SIGALRM watchdog")
def test_streaming_tar_huge_declared_size_fails_fast() -> None:
    """A forward-only walk must not do work proportional to a size the archive
    declares but does not contain (``streaming=True`` is the O(1) escape hatch in
    threat-model O1; the archive holds ~2 KiB). tarfile's ``_Stream.seek`` loops
    ``size // bufsize`` times reading empty chunks at EOF. Measured: a legal ustar
    octal size of 8 GiB costs 1.4 s (5.6 s as .tar.gz), 2**38 costs 43 s (180 s)."""
    first = _patched(_member("a", b"x" * 10), 124, _base256(2**45, 12))
    data = first + _member("b", b"y") + _TRAILER
    with (
        _watchdog(1.5),
        pytest.raises(ArchiveyError),
        open_archive(io.BytesIO(data), streaming=True) as ar,
    ):
        # List without reading: a consumer that skips a member is what makes
        # tarfile seek over it. (Reading it hits EOF at once and is typed.)
        for _member_, _stream in ar.stream_members():
            pass


# ---------------------------------------------------------------------------
# TAR: a huge size field in random-access mode leaks the seek's own error
# ---------------------------------------------------------------------------


def _huge_size_tar() -> bytes:
    first = _member("a", b"x" * 10, pax_headers={"size": str(2**63)})
    return first + _member("b", b"y") + _TRAILER


@pytest.mark.parametrize("source_kind", ["bytesio", "path", "tar.xz"])
def test_random_access_tar_huge_declared_size_is_typed(
    source_kind: str, tmp_path: Path
) -> None:
    """error-handling: 'Single rooted archive exception hierarchy' — archive content
    must not surface as a builtin exception."""
    import lzma

    data = _huge_size_tar()
    fmt = None
    source: object = io.BytesIO(data)
    if source_kind == "path":
        path = tmp_path / "huge.tar"
        path.write_bytes(data)
        source = path
    elif source_kind == "tar.xz":
        source = io.BytesIO(lzma.compress(data))
        fmt = ArchiveFormat.TAR_XZ
    with pytest.raises(ArchiveyError), open_archive(source, format=fmt) as ar:
        ar.members()


# ---------------------------------------------------------------------------
# TAR: GNU sparse PAX records tarfile parses with a bare int()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "pax",
    [
        {"GNU.sparse.map": "0,x"},  # PAX sparse 0.1
        {"GNU.sparse.size": "1e3"},  # PAX sparse 0.0 / 0.1 size
        {"GNU.sparse.realsize": "nan"},  # PAX sparse 1.0 size
    ],
    ids=["map", "size", "realsize"],
)
def test_gnu_sparse_pax_record_not_an_integer_is_corruption(
    pax: dict[str, str], streaming: bool
) -> None:
    """error-handling: a malformed header value is CorruptionError, not ValueError."""
    data = _member("a", b"x" * 10, pax_headers=pax) + _TRAILER
    with (
        pytest.raises(CorruptionError),
        open_archive(io.BytesIO(data), streaming=streaming) as ar,
    ):
        _drain(ar)


@pytest.mark.parametrize("streaming", [False, True])
def test_gnu_sparse_1_0_map_without_newline_is_corruption(streaming: bool) -> None:
    """error-handling: a malformed sparse map is CorruptionError, not ValueError."""
    pax = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "f",
        "GNU.sparse.realsize": "10",
    }
    data = _member("GNUSparseFile.0/f", b"no newline here", pax_headers=pax) + _TRAILER
    with (
        pytest.raises(CorruptionError),
        open_archive(io.BytesIO(data), streaming=streaming) as ar,
    ):
        _drain(ar)


# ---------------------------------------------------------------------------
# TAR: mode field outside what stat.S_IMODE accepts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("mode", [-1, 2**40], ids=["negative", "over-32-bit"])
def test_tar_mode_out_of_range_does_not_escape(mode: int, streaming: bool) -> None:
    """error-handling: listing never raises a builtin for a header value; the
    mtime field already degrades a hostile value (MEMBER_TIMESTAMP_INVALID)."""
    data = _patched(_member("a", b"x"), 100, _base256(mode, 8)) + _TRAILER
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            _drain(ar)
    except ArchiveyError:
        pass


# ---------------------------------------------------------------------------
# TAR: sparse maps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    ["negative-numbytes", "map-past-packed-data"],
)
def test_streaming_sparse_map_backward_seek_is_typed(case: str) -> None:
    """error-handling: tarfile.StreamError is a tarfile error about the archive's
    layout and must surface as an ArchiveyError (TarReader._translate_exception maps
    only ReadError and EOFError)."""
    if case == "negative-numbytes":
        sparse = _gnu_sparse("a", [(0, 10), (100, -5), (200, 10)], 300, b"A" * 30)
    else:
        sparse = _gnu_sparse("a", [(0, 1024)], 1024, b"A" * 512)
    data = sparse + _member("b", b"SECRET") + _TRAILER
    with (
        pytest.raises(ArchiveyError),
        open_archive(io.BytesIO(data), streaming=True) as ar,
    ):
        _drain(ar)


def test_sparse_map_past_packed_data_is_not_served_silently() -> None:
    """A member's bytes come from its own data area; reading past it into the next
    header is damage (tar(1) refuses such a map). Random access returns 1024 bytes
    of which the last 512 are member ``b``'s header."""
    data = (
        _gnu_sparse("a", [(0, 1024)], 1024, b"A" * 512)
        + _member("b", b"SECRET")
        + _TRAILER
    )
    with (
        open_archive(io.BytesIO(data)) as ar,
        pytest.raises(CorruptionError),
        ar.open("a") as stream,
    ):
        stream.read()


def _pax_sparse(
    version: str, entries: list[tuple[int, int]], realsize: int, packed: bytes
) -> bytes:
    """A PAX sparse member in encoding ``version`` 0.0, 0.1 or 1.0.

    0.0 repeats the ``GNU.sparse.offset`` / ``GNU.sparse.numbytes`` keys, which
    tarfile's ``pax_headers`` dict cannot hold, so the 0.x extended headers are
    written by hand. 1.0 stores the map as text at the head of the data.

    The 0.x data member's header has GNU magic (``_member`` writes
    ``tarfile.GNU_FORMAT``). tarfile applies the ``GNU.sparse.*`` records whatever
    the magic, so the tests are sound. GNU tar applies them only on a ustar header:
    it does not read these 0.x fixtures ("Unexpected EOF in archive", even for a
    valid map). To compare against GNU tar, write the data member with
    ``tarfile.USTAR_FORMAT``."""
    if version == "1.0":
        body = b"%d\n" % len(entries)
        body += b"".join(b"%d\n%d\n" % entry for entry in entries)
        body = body.ljust(-(-len(body) // 512) * 512, b"\0") + packed
        pax = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "a",
            "GNU.sparse.realsize": str(realsize),
        }
        return _member("GNUSparseFile.0/a", body, pax_headers=pax)
    fields = [("GNU.sparse.size", str(realsize))]
    fields.append(("GNU.sparse.numblocks", str(len(entries))))
    if version == "0.0":
        for offset, numbytes in entries:
            fields += [
                ("GNU.sparse.offset", str(offset)),
                ("GNU.sparse.numbytes", str(numbytes)),
            ]
    else:
        flat = ",".join(f"{offset},{numbytes}" for offset, numbytes in entries)
        fields.append(("GNU.sparse.map", flat))
    records = b""
    for key, value in fields:
        text = f" {key}={value}\n".encode()
        length = len(text) + len(str(len(text) + 1))
        records += str(length).encode() + text
    xhdr = tarfile.TarInfo("./PaxHeaders/a")
    xhdr.type = tarfile.XHDTYPE
    xhdr.size = len(records)
    return (
        xhdr.tobuf(format=tarfile.USTAR_FORMAT)
        + records
        + b"\0" * (-len(records) % 512)
        + _member("a", packed)
    )


def _sparse_member(
    encoding: str, entries: list[tuple[int, int]], realsize: int, packed: bytes
) -> bytes:
    if encoding == "gnu-old":
        return _gnu_sparse("a", entries, realsize, packed)
    return _pax_sparse(encoding.removeprefix("pax-"), entries, realsize, packed)


_SPARSE_ENCODINGS = ["gnu-old", "pax-0.0", "pax-0.1", "pax-1.0"]
_PACKED = b"A" * 512 + b"B" * 512


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
@pytest.mark.parametrize(
    ("entries", "realsize", "error", "match"),
    [
        (
            [(4096, 512), (0, 512)],
            8192,
            UnsupportedFeatureError,
            "out of order or overlapping",
        ),
        (
            [(0, 512), (256, 512)],
            2048,
            UnsupportedFeatureError,
            "out of order or overlapping",
        ),
        (
            [(0, 512), (4096, 512)],
            1024,
            CorruptionError,
            "ends past the member's size",
        ),
        (
            [(0, 512), (4096, 512), (8193, 0)],
            8192,
            CorruptionError,
            "ends past the member's size",
        ),
        ([(0, 512)], 8192, CorruptionError, "accounts for 512 bytes"),
    ],
    ids=[
        "out-of-order",
        "overlapping",
        "past-the-end",
        "empty-entry-past-the-end",
        "under-stored",
    ],
)
def test_sparse_map_damaged_or_out_of_order_is_refused(
    entries: list[tuple[int, int]],
    realsize: int,
    error: type[ArchiveyError],
    match: str,
    encoding: str,
    streaming: bool,
) -> None:
    """tarfile serves each of these maps with no error. Archivey refuses each one.

    tarfile stitches out-of-order or overlapping chunks into one run, where GNU tar
    1.35 places each chunk at its own offset: the map is valid data that archivey
    cannot serve, so ``UnsupportedFeatureError`` (DR-4).

    tarfile drops the stored bytes of a non-empty chunk past the logical size, and
    stored bytes that no chunk accounts for (``B`` in the last case): that is
    damage, ``CorruptionError`` (DR-3). An empty entry past the logical size loses
    no bytes in tarfile. It is ``CorruptionError`` because the map contradicts its
    own declared size, and because tarfile and GNU tar disagree on the extracted
    length (DR-1).

    GNU tar 1.35 refuses a chunk past the logical size in old GNU and PAX 1.0, and
    reads it in PAX 0.0 and 0.1. It extracts the under-stored member without the
    leftover bytes."""
    data = (
        _sparse_member(encoding, entries, realsize, _PACKED)
        + _member("b", b"SECRET")
        + _TRAILER
    )
    with (
        open_archive(io.BytesIO(data), streaming=streaming) as ar,
        pytest.raises(error, match=match),
    ):
        if streaming:
            _drain(ar)
        else:
            with ar.open("a") as stream:
                stream.read()


_IN_ORDER_ENTRIES = [(0, 512), (4096, 512), (8192, 0)]
_IN_ORDER_EXPECTED = b"A" * 512 + bytes(3584) + b"B" * 512 + bytes(3584)


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
def test_sparse_map_in_order_with_trailing_empty_entry_is_read(
    encoding: str, streaming: bool
) -> None:
    """The same chunks in order are a valid map. GNU tar ends a map with an empty
    ``(realsize, 0)`` entry when the file ends in a hole, and the old GNU header pads
    its unused slots with ``(0, 0)``; neither is out of order."""
    data = (
        _sparse_member(encoding, _IN_ORDER_ENTRIES, 8192, _PACKED)
        + _member("b", b"SECRET")
        + _TRAILER
    )
    with open_archive(io.BytesIO(data), streaming=streaming) as ar:
        got = {m.name: s.read() for m, s in ar.stream_members() if s is not None}
    assert got == {"a": _IN_ORDER_EXPECTED, "b": b"SECRET"}


@pytest.mark.parametrize("encoding", _SPARSE_ENCODINGS)
def test_sparse_map_in_order_is_read_through_open(encoding: str) -> None:
    """Random access by name serves the valid map too, the entry point the refusal
    tests use."""
    data = (
        _sparse_member(encoding, _IN_ORDER_ENTRIES, 8192, _PACKED)
        + _member("b", b"SECRET")
        + _TRAILER
    )
    with open_archive(io.BytesIO(data)) as ar, ar.open("a") as stream:
        assert stream.read() == _IN_ORDER_EXPECTED


def _sparse_1_0_tar(entries: int) -> bytes:
    body = b"%d\n" % entries + b"0\n0\n" * entries
    pax = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "f",
        "GNU.sparse.realsize": "0",
    }
    return _member("GNUSparseFile.0/f", body, pax_headers=pax) + _TRAILER


def test_sparse_1_0_map_is_weighed_against_max_metadata_bytes() -> None:
    """threat-model O1: listing-time retained metadata is budgeted by
    ``max_metadata_bytes``. Here 30 000 map entries (120 KB of tar, ~200 bytes of
    .tar.gz) are retained as ~2 MB of tuples against a 64 KiB cap. At a million
    entries a 4 KB .tar.gz retains 64 MB and takes ~2.5 s per member to list.

    The map is weighed as it is parsed, and the first member's headers are parsed as
    the archive opens, so the refusal may come from ``open_archive``."""
    data = _sparse_1_0_tar(30_000)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=64 * 1024))
    tracemalloc.start()
    try:
        try:
            with open_archive(io.BytesIO(data), config=config) as ar:
                members = ar.members()
                retained, _peak = tracemalloc.get_traced_memory()
                assert members[0].is_sparse
        except ResourceLimitError:
            return
    finally:
        tracemalloc.stop()
    assert retained < 1_000_000, f"listing retained {retained} bytes past a 64 KiB cap"


# ---------------------------------------------------------------------------
# bzip2 accelerator: untranslated rapidgzip errors
# ---------------------------------------------------------------------------


@requires("rapidgzip")
@pytest.mark.parametrize(
    "prefix",
    [b"BZh\x00", b"\xf26oUW"],
    ids=["bad-blocksize-byte", "junk-before-magic"],
)
def test_bzip2_accelerator_header_errors_are_typed(prefix: bytes) -> None:
    """compressed-streams: 'Returned streams translate decompression errors' and
    'An accelerator preserves the error contract of the path it replaces' (the
    stdlib path raises CorruptionError/TruncatedError on the same bytes)."""
    import bz2

    good = bz2.compress(bytes(range(256)) * 64)
    # Either the block-size byte replaced, or five junk bytes before the magic.
    data = prefix + good[4:] if prefix.startswith(b"BZh") else prefix + good
    config = ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)
    with (
        pytest.raises(ArchiveyError),
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.BZ2,
            seekable_members=True,
            config=config,
        ) as ar,
        ar.open(ar.members()[0]) as stream,
    ):
        stream.read()


# ---------------------------------------------------------------------------
# unix-compress: dictionary memory proportional to output
# ---------------------------------------------------------------------------


def _lzw_run_bomb(codes: int) -> bytes:
    """A ``.Z`` stream (16-bit, block mode) whose every code is the KwKwK case,
    so dictionary entry ``k`` is ``k`` bytes of ``a``: ``codes`` codes decode to
    ``codes * (codes + 1) / 2`` bytes. ``gzip -d`` decodes it to the same bytes."""
    out = bytearray(b"\x1f\x9d\x90")
    width, in_era, bits, nbits = 9, 0, 0, 0
    for code in [97] + [256 + i for i in range(1, codes)]:
        bits |= code << nbits
        nbits += width
        in_era += 1
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8
        if in_era >= 1 << (width - 1) and width < 16:
            width, in_era = width + 1, 0
    if nbits:
        out.append(bits & 0xFF)
    return bytes(out)


def test_unix_compress_dictionary_memory_is_bounded() -> None:
    """A chunked read of a stream must not retain memory proportional to the output
    (DecoderLimits: a decoder's working set is what the cap is for; LZW's needs only
    a 64 Ki-entry prefix/suffix table). 6 000 codes (~8 KB) decode 18 MB of ``a``;
    a dictionary that stored every entry as its full expansion would hold all of it
    while 64 KiB reads are served."""
    codes = 6_000
    data = _lzw_run_bomb(codes)
    total = 0

    def read_all() -> None:
        nonlocal total
        with (
            open_archive(io.BytesIO(data), format=ArchiveFormat.Z) as ar,
            ar.open(ar.members()[0]) as stream,
        ):
            while chunk := stream.read(65536):
                total += len(chunk)

    peak = traced_peak(read_all)
    assert total == codes * (codes + 1) // 2
    assert peak < 8_000_000, f"peak {peak} bytes for 64 KiB reads"


# ---------------------------------------------------------------------------
# TAR: extended-header chains recurse in tarfile
# ---------------------------------------------------------------------------


def _extended_header_chain(kind: bytes, count: int) -> bytes:
    """``count`` back-to-back GNU long-name (``L`` / ``K``) or PAX (``x``) headers
    ahead of one ordinary member. tarfile handles each by calling ``fromtarfile``
    again from inside the previous one, so the chain is a recursion."""
    out = bytearray()
    for i in range(count):
        if kind == tarfile.XHDTYPE:
            record = b"path=p%03d\n" % (i % 1000)
            body = b"%d %s" % (len(record) + 3, record)
            info = tarfile.TarInfo("pax")
            fmt = tarfile.USTAR_FORMAT
        else:
            body = b"n%d\0" % i
            info = tarfile.TarInfo("././@LongLink")
            fmt = tarfile.GNU_FORMAT
        info.type = kind
        info.size = len(body)
        out += info.tobuf(format=fmt) + body + b"\0" * (-len(body) % 512)
    return bytes(out) + _member("f", b"data") + _TRAILER


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "kind",
    [tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE],
    ids=["L", "K", "x"],
)
def test_extended_header_chain_does_not_raise_recursion_error(
    kind: bytes, streaming: bool
) -> None:
    """error-handling: archive content must not surface as a builtin exception. A
    1 000-header chain is 1 MB of tar and about 3 KB as .tar.gz."""
    data = _extended_header_chain(kind, 1000)
    escaped: str | None = None
    try:
        with open_archive(io.BytesIO(data), streaming=streaming) as ar:
            _drain(ar)
    except ArchiveyError:
        pass
    except RecursionError as exc:
        # Reported without the exception attached: pytest rendering a
        # thousand-frame traceback takes the better part of a minute.
        escaped = repr(exc)
    assert escaped is None, f"raw exception escaped: {escaped}"


# ---------------------------------------------------------------------------
# Compressed TAR: a stream checksum reached in the post-trailer scan is dropped
# ---------------------------------------------------------------------------


def _one_member_tar(payload: bytes) -> bytes:
    """An uncompressed tar holding one member ``a`` with ``payload`` as its body."""
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as t:
        info = tarfile.TarInfo("a")
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
    return tar.getvalue()


def _stored_codec(codec: str, raw: bytes) -> bytes:
    """``raw`` compressed so that incompressible bytes are stored verbatim, with the
    codec's whole-stream checksum on."""
    if codec == "gz":
        import gzip

        return gzip.compress(raw, compresslevel=0)
    if codec == "zst":
        from tests.conftest import zstd_backend

        zstd = zstd_backend()
        return zstd.compress(raw, options={zstd.CompressionParameter.checksum_flag: 1})
    import lz4.frame

    return lz4.frame.compress(raw, content_checksum=True)


_CODEC_FORMATS = {
    "gz": ArchiveFormat.TAR_GZ,
    "zst": ArchiveFormat.TAR_ZST,
    "lz4": ArchiveFormat.TAR_LZ4,
}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("padding", [64 * 1024, 2 * 2**20], ids=["64KiB", "2MiB"])
@pytest.mark.parametrize(
    "codec",
    [
        "gz",
        pytest.param("zst", marks=requires_zstd()),
        pytest.param("lz4", marks=requires("lz4")),
    ],
)
def test_compressed_tar_stream_checksum_after_trailer_is_not_dropped(
    codec: str, padding: int, streaming: bool
) -> None:
    """compressed-streams: 'Decompressed output digests are verified at clean EOF'.
    One flipped byte in a stored member body decodes cleanly, so only the stream
    checksum can see it. With a ``tar -b128`` record (64 KiB of zero padding after
    the trailer) the checksum is reached inside the trailing scan, which must raise
    it (_StreamChecksumError) rather than take it for a tail that failed to decode.
    Past the scan's 1 MiB bound it is never reached, and DIGEST_UNVERIFIABLE says so;
    the same archive without the flipped byte reports the same, and raises nothing."""
    import random

    payload = random.Random(1).randbytes(20_000)
    clean = _stored_codec(codec, _one_member_tar(payload) + b"\0" * padding)
    compressed = bytearray(clean)
    at = compressed.find(payload[1000:1100])
    assert at >= 0, "fixture premise: the member body is stored verbatim"
    compressed[at + 50] ^= 0x01

    def _drained(data: bytes) -> set[DiagnosticCode]:
        with open_archive(
            io.BytesIO(data), format=_CODEC_FORMATS[codec], streaming=streaming
        ) as ar:
            _drain(ar)
            return set(ar.diagnostics.counts)

    if padding <= 1 * 2**20:
        with pytest.raises(CorruptionError):
            _drained(bytes(compressed))
        assert DiagnosticCode.DIGEST_UNVERIFIABLE not in _drained(clean)
    else:
        assert DiagnosticCode.DIGEST_UNVERIFIABLE in _drained(bytes(compressed))
        assert DiagnosticCode.DIGEST_UNVERIFIABLE in _drained(clean)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("codec", "cut"),
    [
        # gzip's footer is 8 bytes; zstd's and lz4's content checksums are 4.
        ("gz", 1),
        ("gz", 4),
        ("gz", 8),
        pytest.param("zst", 1, marks=requires_zstd()),
        pytest.param("zst", 4, marks=requires_zstd()),
        pytest.param("lz4", 1, marks=requires("lz4")),
        pytest.param("lz4", 4, marks=requires("lz4")),
    ],
)
def test_compressed_tar_cut_after_trailer_is_unverifiable(
    codec: str, cut: int, streaming: bool
) -> None:
    """format-tar: a compressed stream cut after the tar trailer never reaches its
    checksum, so the members already read are unchecked, and DIGEST_UNVERIFIABLE
    (``reason="trailing_stream_truncated"``) says so, as it does on bzip2 and xz.

    The cut lands in the footer (gzip CRC-32 and ISIZE, the zstd and lz4 content
    checksums; a longer cut reaches the data and raises ``TruncatedError``), so every
    member decodes whole and still reads under the default
    policy; ``DiagnosticPolicy.STRICT`` refuses the archive. A plain ``.gz`` with the
    same cut raises ``TruncatedError`` on its read.
    """
    payload = random.Random(1).randbytes(20_000)
    data = _stored_codec(codec, _one_member_tar(payload))[:-cut]
    fmt = _CODEC_FORMATS[codec]
    with open_archive(io.BytesIO(data), format=fmt, streaming=streaming) as ar:
        read = [
            stream.read()
            for _member, stream in ar.stream_members()
            if stream is not None
        ]
        assert read == [payload]
        reasons = [
            d.context.reason  # type: ignore[union-attr]
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.DIGEST_UNVERIFIABLE
        ]
        assert reasons == ["trailing_stream_truncated"]
        assert set(ar.diagnostics.counts) == {DiagnosticCode.DIGEST_UNVERIFIABLE}

    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(
            io.BytesIO(data), format=fmt, streaming=streaming, config=strict
        ) as ar,
    ):
        _drain(ar)


@pytest.mark.parametrize("streaming", [False, True])
def test_concatenated_tar_gz_claims_nothing_about_the_checksum(
    streaming: bool,
) -> None:
    """format-tar: ``cat a.tar.gz b.tar.gz`` lists ``a.tar`` and reports ``b.tar`` as
    ``ARCHIVE_TRAILING_DATA``, and nothing else.

    The trailing bytes are a second gzip member. The first member's CRC-32, the one
    over the listed members, was checked on the way into it, so a
    ``DIGEST_UNVERIFIABLE`` here would be false; and the second member's checksum
    covers no listed member. The scan stops at the first non-zero byte, so a second
    archive larger than the 1 MiB bound adds no ``trailing_scan_limit`` report, and
    random access does not rewind across a megabyte of it either. The second archive
    is intact here; a damaged one is the next test.
    """
    import gzip

    first = gzip.compress(_one_member_tar(b"abc"), mtime=0)
    second = gzip.compress(
        _one_member_tar(random.Random(3).randbytes(2 * 2**20)), mtime=0
    )
    with open_archive(
        io.BytesIO(first + second), format=ArchiveFormat.TAR_GZ, streaming=streaming
    ) as ar:
        if streaming:
            read = [s.read() for _m, s in ar.stream_members() if s is not None]
        else:
            read = [ar.read(m) for m in ar.members()]
        assert read == [b"abc"]
        assert dict(ar.diagnostics.counts) == {DiagnosticCode.ARCHIVE_TRAILING_DATA: 1}


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("size", [200, 256 * 1024], ids=["small", "256KiB"])
def test_damaged_further_gzip_member_is_not_called_unreached(
    size: int, streaming: bool
) -> None:
    """format-tar: ``cat a.tar.gz b.gz``, ``b.gz`` with BFINAL cleared on its only
    deflate block, so it decodes and then fails on its own footer.

    ``a.tar.gz``'s CRC-32, over the listed members, is checked on the way into
    ``b.gz`` (flipping it raises), so a report must not say that checksum was never
    reached. The scan cannot tell this failure from one in the members' own stream,
    so it reports ``DIGEST_UNVERIFIABLE`` (``trailing_decode_failed``) worded as
    "cannot be told". Which report comes out depends on ``b.gz``'s size: the codec
    loses the output of a feed that fails, so a small member gives the digest report,
    and one decoding past a scan chunk first gives ``ARCHIVE_TRAILING_DATA``
    (``dev-docs/formats/tar.md`` §6). Neither is silent, and the listing stands.
    Random access checks the listing only: a later ``read()`` of ``a`` decodes from
    the start and its read-ahead reaches ``b.gz``'s failure, which raises
    ``CorruptionError`` on ``main`` too.
    """
    import gzip

    from archivey.internal.backends.tar_reader import _TRAILING_SCAN_CHUNK

    second = bytearray(gzip.compress(b"S" * size, mtime=0))
    assert second[10] & 1, "fixture premise: the first deflate block is final"
    second[10] &= 0xFE
    first = gzip.compress(_one_member_tar(b"abc"), mtime=0)
    with open_archive(
        io.BytesIO(first + bytes(second)),
        format=ArchiveFormat.TAR_GZ,
        streaming=streaming,
    ) as ar:
        if streaming:
            read = [s.read() for _m, s in ar.stream_members() if s is not None]
            assert read == [b"abc"]
        else:
            assert [m.name for m in ar.members()] == ["a"]
        found = {d.code: d for d in ar.diagnostics.retained}
    if size < _TRAILING_SCAN_CHUNK:
        assert set(found) == {DiagnosticCode.DIGEST_UNVERIFIABLE}
        digest = found[DiagnosticCode.DIGEST_UNVERIFIABLE]
        assert getattr(digest.context, "reason", None) == "trailing_decode_failed"
        assert "cannot be told" in digest.message
        assert "never reached" not in digest.message
    else:
        assert set(found) == {DiagnosticCode.ARCHIVE_TRAILING_DATA}


def test_gzip_decode_failure_after_trailer_is_not_silent() -> None:
    """format-tar: a deflate stream that fails past the tar trailer never reaches the
    gzip CRC-32, so the scan reports ``DIGEST_UNVERIFIABLE``
    (``reason="trailing_decode_failed"``), as it does on bzip2 and xz. The fixture
    clears BFINAL on the only deflate block: every tar byte decodes, then the decoder
    reads the gzip footer as a block header and fails. ``gzip -t`` fails on it.

    In a stream pass the member is delivered before the failure, so only the scan
    reports it. In random access the listing's scan reports it too, and the member
    read, which re-decodes from the start, reaches the failure through the codec's
    read-ahead and raises ``CorruptionError``.
    """
    import gzip

    data = bytearray(gzip.compress(_one_member_tar(b"EVIL DATA\n"), mtime=0))
    assert data[10] & 1, "fixture premise: the first deflate block is final"
    data[10] &= 0xFE

    def _reasons(ar) -> list[str | None]:
        return [
            getattr(d.context, "reason", None)
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.DIGEST_UNVERIFIABLE
        ]

    with open_archive(
        io.BytesIO(bytes(data)), format=ArchiveFormat.TAR_GZ, streaming=True
    ) as ar:
        read = [s.read() for _m, s in ar.stream_members() if s is not None]
        assert read == [b"EVIL DATA\n"]
        assert _reasons(ar) == ["trailing_decode_failed"]

    with open_archive(io.BytesIO(bytes(data)), format=ArchiveFormat.TAR_GZ) as ar:
        (member,) = ar.members()
        assert _reasons(ar) == ["trailing_decode_failed"]
        with pytest.raises(CorruptionError):
            ar.read(member)


def _bad_last_block_check(codec: str, raw: bytes) -> tuple[bytes, bytes]:
    """``raw`` compressed clean, and again with the last block's check flipped.

    The members still decode byte for byte; only the check disagrees, and bzip2 and
    xz report that the same way as any other decode failure.
    """
    if codec == "bz2":
        import bz2

        clean = bz2.compress(raw)
        # "BZh9", then the block magic (6 bytes), then the block CRC.
        at = 4 + 6
    else:
        import lzma

        clean = lzma.compress(raw, check=lzma.CHECK_CRC64)
        backward_size = (int.from_bytes(clean[-8:-4], "little") + 1) * 4
        # The block's CRC64 is the last 8 bytes before the index.
        at = len(clean) - 12 - backward_size - 1
    damaged = bytearray(clean)
    damaged[at] ^= 0x01
    return clean, bytes(damaged)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("codec", ["bz2", "xz"])
def test_untyped_block_check_after_trailer_is_reported(
    codec: str, streaming: bool
) -> None:
    """format-tar: bzip2 and xz cannot tell a failed check from junk after the stream.

    The last block's check is reached in the trailing scan (64 KiB of padding), so the
    failure there must be ``DIGEST_UNVERIFIABLE``, not silence: the same damage in a
    ``.tar.gz`` raises (the test above).
    """
    import random

    payload = random.Random(1).randbytes(200_000)
    clean, damaged = _bad_last_block_check(
        codec, _one_member_tar(payload) + b"\0" * 64 * 1024
    )
    fmt = ArchiveFormat.TAR_BZ2 if codec == "bz2" else ArchiveFormat.TAR_XZ

    def _drained(data: bytes) -> dict[DiagnosticCode, int]:
        with open_archive(io.BytesIO(data), format=fmt, streaming=streaming) as ar:
            read = [
                stream.read()
                for _member, stream in ar.stream_members()
                if stream is not None
            ]
            assert read == [payload]
            return dict(ar.diagnostics.counts)

    assert DiagnosticCode.DIGEST_UNVERIFIABLE in _drained(damaged)
    assert DiagnosticCode.DIGEST_UNVERIFIABLE not in _drained(clean)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("codec", ["bz2", "xz"])
def test_untyped_block_check_is_never_silent(codec: str, streaming: bool) -> None:
    """format-tar: the same failed bzip2/xz check has two outcomes, never silence.

    With only ``tarfile``'s own record padding, whether the check is reached while
    the member is read (``CorruptionError`` from ``read()``) or in the trailing scan
    (``DIGEST_UNVERIFIABLE``) depends on where the codec's input chunking lands, so
    the member size (and the codec backend) decides it. Neither arm is silent.
    """
    fmt = ArchiveFormat.TAR_BZ2 if codec == "bz2" else ArchiveFormat.TAR_XZ
    outcomes: set[str] = set()
    for size in range(1000, 25_000, 1000):
        payload = random.Random(7).randbytes(size)
        _clean, damaged = _bad_last_block_check(codec, _one_member_tar(payload))
        try:
            with open_archive(
                io.BytesIO(damaged), format=fmt, streaming=streaming
            ) as ar:
                _drain_closing(ar)
                counts = ar.diagnostics.counts
        except CorruptionError:
            outcomes.add("raised")
            continue
        assert DiagnosticCode.DIGEST_UNVERIFIABLE in counts, f"silent at {size}"
        outcomes.add("reported")
    # Which sizes land in which arm depends on the installed codec backends; the
    # reporting arm is pinned by the 64 KiB-padding test above.
    assert "raised" in outcomes


def _checksumless_codec(codec: str, raw: bytes) -> bytes:
    """``raw`` compressed with a codec whose stream carries no checksum at all."""
    if codec == "br":
        import brotli

        return brotli.compress(raw)
    if codec == "Z":
        from tests.streams_util import make_unix_compress

        return make_unix_compress(raw)
    import lzma

    return lzma.compress(raw, format=lzma.FORMAT_ALONE)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "codec",
    [
        pytest.param("br", marks=requires("brotli")),
        pytest.param("Z", marks=requires("ncompress")),
        "lzma",
    ],
)
def test_checksumless_stream_past_scan_bound_is_not_unverifiable(
    codec: str, streaming: bool
) -> None:
    """format-tar: the trailing-scan bound reports only for a codec that can carry a
    whole-stream checksum (DR-1). Brotli, ``.Z`` and LZMA Alone carry none.

    The same 2 MiB of padding that makes a ``.tar.gz`` report DIGEST_UNVERIFIABLE (the
    scan stops before the stream's checksum) reports nothing here: the docs say once
    that these codecs carry no check, and a diagnostic on every archive would add
    nothing.
    """
    payload = random.Random(1).randbytes(20_000)
    data = _checksumless_codec(codec, _one_member_tar(payload) + b"\0" * 2 * 2**20)
    fmt = ArchiveFormat(ContainerFormat.TAR, StreamFormat(codec))
    with open_archive(io.BytesIO(data), format=fmt, streaming=streaming) as ar:
        read = [
            stream.read()
            for _member, stream in ar.stream_members()
            if stream is not None
        ]
        assert read == [payload]
        assert DiagnosticCode.DIGEST_UNVERIFIABLE not in ar.diagnostics.counts


def _drain_closing(ar) -> None:
    """``_drain``, closing the pass even when a read raises."""
    members = ar.stream_members()
    try:
        for _member, stream in members:
            if stream is not None:
                stream.read()
    finally:
        members.close()
