"""Published vulnerabilities in other 7z and RAR readers, replayed against archivey.

Each test rebuilds, by hand, the archive structure a CVE or advisory for py7zr,
rarfile, 7-Zip, unrar, WinRAR or Apache Commons Compress describes, and checks that
archivey keeps the property the other reader lost: nothing lands outside the
destination, hostile structure ends in a typed error and does not hang or exhaust
memory, and a name cannot drive the terminal. A test names the CVE it replays, so a
failure points at the published write-up of the attack.

``tests/test_extraction.py`` already covers traversal and link chains over TAR. The
tests here add the 7z and RAR5 encodings of the same attacks, which reach extraction
through different records (7z ``S_IFLNK`` attributes, RAR5 redirect records), under
every policy, random and streaming.

Only logic-class bugs are replayed. Memory-safety bugs in C decoders (7-Zip's own
decoders, unrar's) do not run here: archivey reads 7z and RAR headers in Python, and
``unrar`` and ``unar`` only ever write member bytes to a pipe.
"""

from __future__ import annotations

import gc
import io
import os
import struct
import time
import zlib
from pathlib import Path
from typing import TypeVar

import pytest

from archivey import (
    ExtractionPolicy,
    ExtractionResult,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
    open_archive,
)
from archivey.cli.exit_codes import EXIT_OK, EXIT_POLICY
from archivey.cli.main import main
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    FilterRejectionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from tests.extract_util import open_and_extract
from tests.memory_util import traced_peak

# The hand-built archive writers come from the audit modules that already own them,
# so a fix to a writer reaches every test that builds archives with it.
from tests.test_audit_extraction_reaudit import _rar5_with
from tests.test_audit_rar_iso_dir import _vint
from tests.test_audit_sevenzip import (
    _COPY,
    _LZMA2,
    _archive,
    _coder,
    _crc,
    _folder,
    _header,
    _lzma2,
    _num,
)

_POSIX_LINKS = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
_POLICIES = pytest.mark.parametrize(
    "policy", list(ExtractionPolicy), ids=lambda p: p.name
)
_MODES = pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
_S_IFREG = 0o100644
_S_IFLNK = 0o120777
_UNIX_EXTENSION = 0x8000
_K = TypeVar("_K")


def _sevenzip(entries: list[tuple[str, int, bytes]]) -> bytes:
    """A 7z of ``(name, unix mode, data)`` entries, each stored in its own COPY folder.

    A symlink is ``S_IFLNK`` with its target as the data, as 7-Zip writes one."""
    attrs = b"\x01\x00" + b"".join(
        struct.pack("<I", _UNIX_EXTENSION | (mode << 16)) for _, mode, _ in entries
    )
    header = _header(
        folders=[_folder([_coder(_COPY)]) for _ in entries],
        coder_unpack_sizes=[[len(data)] for _, _, data in entries],
        pack_sizes=[len(data) for _, _, data in entries],
        names=[name for name, _, _ in entries],
        folder_crcs=[_crc(data) for _, _, data in entries],
        extra_file_props=b"\x15" + _num(len(attrs)) + attrs,
    )
    return _archive(b"".join(data for _, _, data in entries), header)


def _outside_layout(tmp_path: Path) -> tuple[Path, Path]:
    """``tmp_path/dest``, empty, and ``tmp_path/outside`` holding ``victim``."""
    dest = tmp_path / "dest"
    dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim").write_bytes(b"original")
    return dest, outside


def _assert_outside_untouched(tmp_path: Path, outside: Path) -> None:
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest", "outside"]
    assert [p.name for p in outside.iterdir()] == ["victim"]
    assert (outside / "victim").read_bytes() == b"original"


def _assert_no_link_leaves(dest: Path) -> None:
    """Every symlink under ``dest`` resolves inside it."""
    root = dest.resolve()
    for parent, dirnames, filenames in os.walk(dest):
        for name in dirnames + filenames:
            path = Path(parent, name)
            if path.is_symlink():
                assert path.resolve().is_relative_to(root), path


def _extract(
    data: bytes, dest: Path, policy: ExtractionPolicy, streaming: bool
) -> dict[str, ExtractionResult]:
    """Extract ``data`` into ``dest`` and return the results by member name, after
    checking that every result's paths are inside ``dest``. A path check catches an
    escape that lands outside ``tmp_path``, such as at the filesystem root."""
    report = open_and_extract(
        io.BytesIO(data),
        dest,
        streaming=streaming,
        policy=policy,
        on_error=OnError.CONTINUE,
        overwrite=OverwritePolicy.REPLACE,
    )
    root = Path(os.path.abspath(dest))
    for result in report:
        for path in (result.path, result.requested_path):
            if path is not None:
                assert Path(os.path.abspath(path)).is_relative_to(root), result
    return {result.member.name: result for result in report}


def _assert_blocked(results: dict[str, ExtractionResult], names: list[str]) -> None:
    for name in names:
        assert results[name].status is ExtractionStatus.BLOCKED, results[name]
        assert isinstance(results[name].error, FilterRejectionError), results[name]


# ---------------------------------------------------------------------------
# Traversal and links
# ---------------------------------------------------------------------------

# Names that leave the destination on POSIX or on Windows. The last three use the
# Windows spellings: a drive-relative name (the WinRAR ACE bug, CVE-2018-20250), and
# segments that Win32 trims to ``..`` (WinRAR CVE-2025-6218 is a traversal through
# crafted path segments in the Windows build only).
_ESCAPING_NAMES = [
    "../outside/victim",
    "a/../../outside/victim",
    "/outside-abs/victim",
    "C:../outside/victim",
    ".. /outside/victim",
    "a/... /.. ./outside/victim",
]
# Refused under every policy. STRICT also refuses the other three. STANDARD refuses the
# dot-and-space segments too: Win32 trims them to ``..``, so they are refused on every
# platform alike (``safe-extraction`` spec, name matrix). STANDARD and TRUSTED re-root the
# absolute name inside the destination. TRUSTED keeps the dot-and-space segments as
# literal names: on POSIX those are ordinary directory names, and on Windows the
# parent-containment check resolves the path through the OS and refuses the member. The
# Windows statuses are not pinned here; ``_assert_outside_untouched`` and the path check
# cover them.
_ALWAYS_BLOCKED = ["../outside/victim", "a/../../outside/victim", "C:../outside/victim"]
_DOT_SPACE_SEGMENTS = [".. /outside/victim", "a/... /.. ./outside/victim"]


def _assert_traversal_contained(
    results: dict[str, ExtractionResult], policy: ExtractionPolicy
) -> None:
    assert sorted(results) == sorted(_ESCAPING_NAMES)
    if policy is ExtractionPolicy.STRICT:
        _assert_blocked(results, _ESCAPING_NAMES)
        return
    _assert_blocked(results, _ALWAYS_BLOCKED)
    kept = ["/outside-abs/victim"]
    if policy is ExtractionPolicy.STANDARD:
        _assert_blocked(results, _DOT_SPACE_SEGMENTS)
    elif os.name != "nt":
        kept += _DOT_SPACE_SEGMENTS
    for name in kept:
        assert results[name].status is ExtractionStatus.EXTRACTED, results[name]


@_POLICIES
@_MODES
def test_py7zr_cve_2022_44900_traversal_names(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    # py7zr before 0.20.1 joined a member name to the destination without checking
    # that the result stayed inside it.
    dest, outside = _outside_layout(tmp_path)
    data = _sevenzip([(name, _S_IFREG, b"overwritten") for name in _ESCAPING_NAMES])
    _assert_traversal_contained(_extract(data, dest, policy, streaming), policy)
    _assert_outside_untouched(tmp_path, outside)


@_POLICIES
@_MODES
def test_winrar_cve_2025_6218_and_cve_2018_20250_traversal_names(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    # The same names in a RAR5 archive. RAR stores ``/`` on every host, and a reader
    # on Windows must still not write through a segment the OS reads as ``..``.
    dest, outside = _outside_layout(tmp_path)
    data = _rar5_with([(name, "file", b"overwritten") for name in _ESCAPING_NAMES])
    _assert_traversal_contained(_extract(data, dest, policy, streaming), policy)
    _assert_outside_untouched(tmp_path, outside)


def _link_chain(kind_link: _K, kind_file: _K) -> list[tuple[str, _K, str | bytes]]:
    """``l1 -> .``, then ``l2 -> l1/..``: lexically ``l2`` stays in the destination,
    but the kernel follows ``l1`` first and ``..`` then leaves it. A file written
    through ``l2`` lands in the destination's parent."""
    return [
        ("l1", kind_link, "."),
        ("l2", kind_link, "l1/.."),
        ("l2/outside/victim", kind_file, b"overwritten"),
        ("l2/outside/new", kind_file, b"new"),
    ]


def _assert_chain_contained(results: dict[str, ExtractionResult], dest: Path) -> None:
    """``l2`` is refused, so the files that would have gone through it are written
    as ordinary files under ``dest/l2/``."""
    assert results["l1"].status is ExtractionStatus.EXTRACTED
    _assert_blocked(results, ["l2"])
    for name in ("l2/outside/victim", "l2/outside/new"):
        assert results[name].status is ExtractionStatus.EXTRACTED, results[name]
    assert not (dest / "l2").is_symlink()


@_POSIX_LINKS
@_POLICIES
@_MODES
def test_py7zr_cve_2026_23879_symlink_chain(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    # py7zr 1.1.2 and earlier checked only where a link was placed and never resolved
    # the chain of links it went through, so regular files written after the links
    # went outside the destination.
    dest, outside = _outside_layout(tmp_path)
    entries = [
        (name, mode, value.encode() if isinstance(value, str) else value)
        for name, mode, value in _link_chain(_S_IFLNK, _S_IFREG)
    ]
    _assert_chain_contained(_extract(_sevenzip(entries), dest, policy, streaming), dest)
    _assert_outside_untouched(tmp_path, outside)
    _assert_no_link_leaves(dest)


@_POSIX_LINKS
@_POLICIES
@_MODES
def test_rar5_symlink_chain_like_py7zr_cve_2026_23879(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    # The same chain as RAR5 redirect records, which unrar CVE-2022-48579 also used.
    dest, outside = _outside_layout(tmp_path)
    data = _rar5_with(_link_chain("sym", "file"))
    _assert_chain_contained(_extract(data, dest, policy, streaming), dest)
    _assert_outside_untouched(tmp_path, outside)
    _assert_no_link_leaves(dest)


# ---------------------------------------------------------------------------
# Bombs, loops and counts
# ---------------------------------------------------------------------------


@_MODES
def test_py7zr_cve_2026_55195_decompression_bomb(
    tmp_path: Path, streaming: bool
) -> None:
    # py7zr before 1.1.3 tracked no total output size, so a small archive extracted to
    # any size. A 7z records every member's size, so archivey refuses this one from the
    # recorded ratio (16 MiB from about 2.5 KiB, past max_ratio=1000) before it
    # decodes a byte, and writes nothing.
    size = 16 << 20
    packed = _lzma2(bytes(size), dict_size=1 << 20)
    header = _header(
        folders=[_folder([_coder(_LZMA2, props=b"\x10")])],
        coder_unpack_sizes=[[size]],
        pack_sizes=[len(packed)],
        names=["bomb"],
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    report = open_and_extract(
        io.BytesIO(_archive(packed, header)),
        dest,
        streaming=streaming,
        on_error=OnError.CONTINUE,
    )
    (result,) = list(report)
    assert result.status is ExtractionStatus.FAILED
    assert isinstance(result.error, ResourceLimitError)
    assert "from recorded sizes" in str(result.error)
    assert list(dest.iterdir()) == []


def _many_folders(count: int) -> bytes:
    """``count`` one-byte members, each in its own folder and pack stream."""
    header = _header(
        folders=[_folder([_coder(_COPY)])] * count,
        coder_unpack_sizes=[[1]] * count,
        pack_sizes=[1] * count,
        names=[f"m{i}" for i in range(count)],
    )
    return _archive(bytes(count), header)


def test_py7zr_cve_2026_55206_pack_stream_count_is_linear() -> None:
    # py7zr 1.1.2 and earlier re-summed the pack sizes from the start for every pack
    # stream, so opening an archive with tens of thousands of them took seconds of CPU
    # per 50 KiB of header. Here eight times as many members cost about eight times as
    # long to list; a cost that grew with the square would cost sixty-four times. The
    # bound of 24 leaves room for runner noise (a Windows runner once measured 10.9x
    # at four times the members), and the collector is off so its passes over a
    # growing heap are not timed.
    def listing_seconds(count: int) -> float:
        data = _many_folders(count)
        gc.collect()
        gc.disable()
        try:
            start = time.perf_counter()
            with open_archive(io.BytesIO(data)) as reader:
                assert len(reader.members()) == count
            return time.perf_counter() - start
        finally:
            gc.enable()

    small = min(listing_seconds(4_000) for _ in range(3))
    large = min(listing_seconds(32_000) for _ in range(3))
    assert large < 24 * max(small, 0.005), f"{large:.3f}s vs {small:.3f}s"


def test_7zip_cve_2024_11612_copy_coder_short_of_its_size() -> None:
    # 7-Zip 24.06 and 24.07 looped for ever in the COPY coder. Here a COPY folder
    # that says it unpacks to far more than its pack stream holds must end in a
    # truncation error, not a loop that waits for bytes that never come.
    header = _header(
        folders=[_folder([_coder(_COPY)])],
        coder_unpack_sizes=[[1 << 40]],
        pack_sizes=[4],
        names=["short"],
    )
    data = _archive(b"abcd", header)
    with (
        pytest.raises(TruncatedError, match="ended after 4 of"),
        open_archive(io.BytesIO(data)) as reader,
    ):
        (member,) = reader.members()
        with reader.open(member) as stream:
            while stream.read(1 << 16):
                pass


def _three_copy_coders(bind_pairs: list[tuple[int, int]]) -> bytes:
    """One folder of three COPY coders with these two bind pairs ``(in, out)``. The
    one in-stream left unbound reads the pack stream; 7z stores no index for it."""
    header = _header(
        folders=[_folder([_coder(_COPY)] * 3, bind_pairs=bind_pairs)],
        coder_unpack_sizes=[[1, 1, 1]],
        pack_sizes=[1],
        names=["loop"],
    )
    return _archive(b"x", header)


def _read_the_member(data: bytes) -> bytes:
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            return stream.read()


def test_commons_compress_cve_2021_35515_coder_cycle_is_corruption() -> None:
    # Commons Compress 1.6 to 1.20 looped for ever building the coder list when the
    # bind pairs of a folder formed a cycle. Here coders 0 and 1 feed each other and
    # coder 2 alone reads the pack stream and gives the output, so a walk back from
    # the output never reaches 0 or 1.
    assert _read_the_member(_three_copy_coders([(1, 2), (0, 1)])) == b"x"  # a chain
    with pytest.raises(CorruptionError, match="cycle"):
        _read_the_member(_three_copy_coders([(0, 1), (1, 0)]))


def _huge_count_headers() -> list[tuple[str, bytes, type[ArchiveyError]]]:
    huge = 1 << 60
    files = b"\x05" + _num(huge) + b"\x00"
    pack = b"\x06" + _num(0) + _num(huge) + b"\x00"
    unpack = b"\x07\x0b" + _num(huge) + b"\x00"
    coders = b"\x07\x0b" + _num(1) + b"\x00" + _num(huge)
    return [
        # A count of items that cannot fit in the header is corrupt; the coder count
        # has a fixed limit (64, as in 7-Zip) and is checked against that instead.
        ("files", b"\x01" + files + b"\x00", CorruptionError),
        ("pack_streams", b"\x01\x04" + pack + b"\x00\x00", CorruptionError),
        ("folders", b"\x01\x04" + unpack + b"\x00\x00", CorruptionError),
        ("coders", b"\x01\x04" + coders + b"\x00\x00", UnsupportedFeatureError),
    ]


@pytest.mark.parametrize(
    ("header", "error"),
    [pytest.param(h, e, id=name) for name, h, e in _huge_count_headers()],
)
def test_commons_compress_cve_2021_35516_huge_declared_counts(
    header: bytes, error: type[ArchiveyError]
) -> None:
    # Commons Compress 1.6 to 1.20 allocated what a 7z header said it held, so a
    # few bytes declaring 2^60 files, folders or streams ran it out of memory. Here
    # the count is refused before anything is sized from it.
    def open_and_list() -> None:
        with (
            pytest.raises(error, match="exceeds"),
            open_archive(io.BytesIO(_archive(b"", header))) as reader,
        ):
            reader.members()

    open_and_list()  # imports and caches stay out of the measured peak
    assert traced_peak(open_and_list) < 4 << 20


def _rar5_short_header(body: bytes) -> bytes:
    """A RAR5 archive of one block whose header is ``body``, with a valid CRC, then
    16 zero bytes. A reader that read the block's fields past its declared size would
    decode those zeros as valid fields of 0 and go on; one that keeps to the declared
    size fails on the field the header does not hold."""
    sized = _vint(len(body)) + body
    signature = _rar5_with([])[:8]
    return signature + struct.pack("<I", zlib.crc32(sized)) + sized + bytes(16)


def _rar4_short_header(size: int) -> bytes:
    body = struct.pack("<BHH", 0x73, 0, size)
    crc = zlib.crc32(body) & 0xFFFF
    return b"Rar!\x1a\x07\x00" + struct.pack("<H", crc) + body + bytes(16)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        # No type at all; a main header with no archive flags; a file header that
        # ends after its type and flags.
        *(
            pytest.param(
                _rar5_short_header(body), "variable-length integer", id=f"rar5-{i}"
            )
            for i, body in enumerate((b"", b"\x01\x00", b"\x02\x00"))
        ),
        *(
            pytest.param(
                _rar4_short_header(s), "Invalid RAR3 header size", id=f"rar4-{s}"
            )
            for s in (0, 3, 6)
        ),
    ],
)
def test_rar_header_too_small_to_advance_is_an_error(data: bytes, message: str) -> None:
    # A block whose header size does not cover its own fields is the shape behind
    # header-walk loops in several readers (rarfile fixed one in a RAR3 subblock).
    # The CRC is valid, so the size itself must end the walk: RAR5 fields are read
    # only from inside the declared header, and RAR4 checks the size against the
    # seven bytes every block needs.
    with (
        pytest.raises(CorruptionError, match=message),
        open_archive(io.BytesIO(data)) as reader,
    ):
        reader.members()


# ---------------------------------------------------------------------------
# Names that drive the terminal
# ---------------------------------------------------------------------------


def test_unrar_cve_2024_33899_escape_sequences_in_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # unrar before 7.00 on Linux and Unix printed member names as they were, so ANSI
    # escape sequences in a name could rewrite the screen. archivey's CLI escapes
    # them in every listing and report; it also runs unrar with -inul, so unrar
    # itself prints nothing to the terminal.
    names = [
        "\x1b[2J\x1b[Hclean.txt",
        "ok\x1b]0;title\x07.txt",
        "cr\rover.txt",
        "../\x1b[1Aup.txt",
    ]
    archive = tmp_path / "hostile.rar"
    archive.write_bytes(_rar5_with([(n, "file", b"x") for n in names]))
    dest = tmp_path / "dest"
    # ``test`` prints member names only with ``-v``. ``extract`` exits with EXIT_POLICY because it blocks the ``../`` member, and
    # rewrites the other names for the disk, so its report shows a ``%1B`` spelling.
    for argv, code, shown in (
        (["list", str(archive)], EXIT_OK, ["\\x1b[2J", "\\x07", "\\r", "\\x1b[1A"]),
        (["test", "-v", str(archive)], EXIT_OK, ["\\x1b[2J", "\\x07", "\\r"]),
        (
            ["extract", str(archive), "-d", str(dest)],
            EXIT_POLICY,
            ["%1B[2J", "\\x1b[1A"],
        ),
    ):
        assert main(argv) == code, argv
        output = "".join(capsys.readouterr())
        for raw in ("\x1b", "\x07", "\r"):
            assert raw not in output, (argv, raw)
        for spelling in shown:
            assert spelling in output, (argv, spelling)
