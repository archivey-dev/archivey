"""Cross-format contract for an opened member stream (``reader.open(member)``).

The per-format test files each check their backend's metadata mapping; this suite instead
asserts the *uniform* behaviour every backend's member stream must share, exercised against
a small **real** archive of each implemented format. It is the v2 stand-in for the kind of
all-formats consistency the frozen DEV oracle used to provide, scoped to the member-read
contract.

The payload is deliberately small (well under a 2 KiB ISO sector and not block-aligned), so
a backend that over-reads — e.g. a ``readinto`` that walks past the logical end into a
container's padding — is caught rather than masked by alignment.
"""

from __future__ import annotations

import gzip
import io
import os
import tarfile
import traceback
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveStream,
    ArchiveyConfig,
    ArchiveyUsageError,
    StreamNotSeekableError,
    list_known_formats,
    open_archive,
)
from archivey.cost import StreamCapability
from archivey.exceptions import TruncatedError
from archivey.types import (
    ArchiveFormat,
    CompressionAlgorithm,
    ContainerFormat,
    MemberType,
    StreamFormat,
)
from tests.conftest import requires
from tests.corruption_util import raises_corruption_not_truncation
from tests.sample_archives import (
    CORPUS,
    FORMAT_KEYS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)
from tests.streams_util import (
    assert_non_integer_read_is_type_error,
    assert_non_integer_seek_is_type_error,
    assert_oversized_read_is_overflow_error,
    assert_seek_underflow_matches_bytesio,
    assert_unknown_whence_is_value_error,
)

CONTENT = b"The quick brown fox jumps over.\n"  # 32 bytes; < one ISO sector
MEMBER = "data.txt"

# Seek tests declare SEEKABLE; other contract tests use the default forward-only streams.

# A builder makes a small archive holding one ``MEMBER`` with ``CONTENT`` and returns the
# (source, member-name) pair to open. Source may be a path or directory.
Builder = Callable[[Path], tuple[Path, str]]


def _directory(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "dir"
    root.mkdir()
    (root / MEMBER).write_bytes(CONTENT)
    return root, MEMBER


def _zip_deflated(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(MEMBER, CONTENT)
    return path, MEMBER


def _zip_stored(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr(MEMBER, CONTENT)
    return path, MEMBER


def _tar(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as t:
        info = tarfile.TarInfo(MEMBER)
        info.size = len(CONTENT)
        t.addfile(info, io.BytesIO(CONTENT))
    return path, MEMBER


def _tar_gz(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo(MEMBER)
        info.size = len(CONTENT)
        t.addfile(info, io.BytesIO(CONTENT))
    return path, MEMBER


def _gzip(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "data.txt.gz"
    with gzip.open(path, "wb") as f:
        f.write(CONTENT)
    return path, MEMBER  # single-file member name inferred from the source filename


def _sevenzip(tmp_path: Path) -> tuple[Path, str]:
    import py7zr

    path = tmp_path / "a.7z"
    with py7zr.SevenZipFile(path, "w") as z:
        z.writestr(CONTENT, MEMBER)
    return path, MEMBER


def _iso(tmp_path: Path) -> tuple[Path, str]:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(CONTENT), len(CONTENT), "/DATA.TXT;1", rr_name=MEMBER)
    path = tmp_path / "a.iso"
    iso.write(str(path))
    iso.close()
    return path, MEMBER


@pytest.fixture(
    params=[
        pytest.param(_directory, id="directory"),
        pytest.param(_zip_deflated, id="zip_deflated"),
        pytest.param(_zip_stored, id="zip_stored"),
        pytest.param(_tar, id="tar"),
        pytest.param(_tar_gz, id="tar_gz"),
        pytest.param(_gzip, id="gzip"),
        pytest.param(_sevenzip, id="sevenzip", marks=requires("py7zr")),
        pytest.param(_iso, id="iso", marks=requires("pycdlib")),
    ]
)
def member(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[Path, str]:
    builder: Builder = request.param
    return builder(tmp_path)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_read_more_than_available_returns_all(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        # A read size far beyond the member length returns exactly the member's bytes.
        assert f.read(10_000) == CONTENT


def test_read_at_eof_returns_empty(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        assert f.read() == CONTENT
        assert f.read() == b""
        assert f.read(64) == b""


def test_read_none_reads_to_eof(member: tuple[Path, str]) -> None:
    # ``None`` means "to EOF" on every ``io`` stream (S28-K3); it used to raise TypeError.
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        assert f.read(None) == CONTENT
        assert f.read(None) == b""


@pytest.mark.parametrize(
    "compression",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED],
    ids=["stored", "deflated"],
)
def test_content_verdict_keeps_raising_after_a_seek_back(compression: int) -> None:
    """A stream that raised a content verdict raises it again until the caller seeks,
    and after a seek the read that reaches the end raises it again.

    It used to raise once: a caller who caught the CRC mismatch and seeked back read
    the whole damaged member with no error (S28-K1). A seek still restarts the decode,
    so the prefix reads again, as for a truncated stream.
    """
    payload = os.urandom(3000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        zf.writestr("a.bin", payload)
    blob = bytearray(buf.getvalue())
    # Flip the stored CRC (central directory and local header), so the data decodes
    # cleanly and only the digest at the end objects.
    for sig, off in ((b"PK\x01\x02", 16), (b"PK\x03\x04", 14)):
        at = blob.index(sig) + off
        blob[at] ^= 0x01
    with open_archive(io.BytesIO(bytes(blob)), seekable_members=True) as ar:
        stream = ar.open("a.bin")
        with raises_corruption_not_truncation() as first:
            stream.read()
        with raises_corruption_not_truncation() as again:
            stream.read(10)
        assert again.value is first.value
        stream.seek(0)
        assert stream.read(10) == payload[:10]
        with raises_corruption_not_truncation() as after:
            stream.read()
        assert after.value is first.value
        stream.seek(0)
        with raises_corruption_not_truncation():
            while stream.read(1000):
                pass
        # A read that asks for exactly what is left returns in full, and still reaches
        # the damage: the seek gave up the digest check, so this gate is all there is.
        stream.seek(0)
        with raises_corruption_not_truncation() as whole:
            stream.read(len(payload))
        assert whole.value is first.value
        stream.seek(0)
        with raises_corruption_not_truncation():
            stream.readinto(bytearray(len(payload)))
        # Each raise resets the traceback to where the damage was found, so a retry
        # loop does not grow it (and the frames it keeps alive) without bound.
        depths = []
        for _ in range(20):
            with raises_corruption_not_truncation() as retry:
                stream.read()
            depths.append(len(traceback.extract_tb(retry.value.__traceback__)))
        assert len(set(depths)) == 1
        stream.close()


def test_a_cut_tar_gz_member_keeps_raising_after_a_seek_back(tmp_path: Path) -> None:
    """The rule above holds for a cut .tar.gz member, whose archive-level codec stream
    does not repeat its own verdict: the member stream does."""
    payload = os.urandom(200_000)
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("a")
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
    path.write_bytes(path.read_bytes()[:10_000])
    with (
        open_archive(path, seekable_members=True) as ar,
        ar.open("a") as stream,
    ):
        got = bytearray()
        with pytest.raises(TruncatedError) as first:
            while block := stream.read(1024):
                got += block
        assert got and bytes(got) == payload[: len(got)]
        with pytest.raises(TruncatedError) as again:
            stream.read(10)
        assert again.value is first.value
        stream.seek(0)
        assert stream.read(10) == payload[:10]
        with pytest.raises(TruncatedError) as after:
            while stream.read(1024):
                pass
        assert after.value is first.value


@pytest.mark.parametrize("first_read", ["read", "read-size", "readinto-size"])
def test_a_kept_verdict_does_not_keep_the_withheld_member_alive(
    first_read: str,
) -> None:
    """The verdict keeps its first traceback, and that must not pin the member's bytes.

    Every read shape that reaches the end holds the member in a local when the digest
    check raises; the frame it raised from stays reachable from the kept traceback
    (S28-K17, S28-K21).
    """
    payload = os.urandom(1 << 20)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.bin", payload)
    blob = bytearray(buf.getvalue())
    for sig, off in ((b"PK\x01\x02", 16), (b"PK\x03\x04", 14)):
        blob[blob.index(sig) + off] ^= 0x01
    with open_archive(io.BytesIO(bytes(blob)), seekable_members=True) as ar:
        stream = ar.open("a.bin")
        # The caller's own readinto buffer is in the frames as an argument, as in any
        # traceback; it is theirs, not the withheld member.
        buffer = bytearray(len(payload))
        with raises_corruption_not_truncation() as caught:
            if first_read == "read":
                stream.read()
            elif first_read == "read-size":
                stream.read(len(payload))
            else:
                stream.readinto(buffer)
        tb = caught.value.__traceback__
        biggest = 0
        while tb is not None:
            if "tests" in Path(tb.tb_frame.f_code.co_filename).parts:
                tb = tb.tb_next  # this test's own frame holds the payload, rightly
                continue
            for value in tb.tb_frame.f_locals.values():
                if value is buffer:
                    continue
                if isinstance(value, (bytes, bytearray)):
                    biggest = max(biggest, len(value))
                elif isinstance(value, list):
                    biggest = max(
                        biggest,
                        sum(len(v) for v in value if isinstance(v, (bytes, bytearray))),
                    )
            tb = tb.tb_next
        assert biggest < len(payload) // 2
        stream.close()


def test_readinto_oversized_buffer_truncates_at_eof(member: tuple[Path, str]) -> None:
    # readinto into a buffer larger than the remaining data must return the actual byte
    # count (not the buffer size) and fill only those bytes — never reading into a
    # container's sector/block padding past the member's logical end.
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        buf = bytearray(10_000)
        n = f.readinto(buf)
        assert n == len(CONTENT)
        assert bytes(buf[:n]) == CONTENT
        # A second readinto at EOF fills nothing.
        assert f.readinto(bytearray(64)) == 0


def test_piecewise_read_then_eof(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        first = f.read(5)
        assert first == CONTENT[:5]
        assert first + f.read() == CONTENT
        assert f.read(1) == b""


# ---------------------------------------------------------------------------
# Seekability capability: off by default, on (and working) with MemberStreams.SEEKABLE
# ---------------------------------------------------------------------------


def test_default_open_is_not_seekable(member: tuple[Path, str]) -> None:
    # Without the SEEKABLE capability every backend hands out a forward-only stream.
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        assert f.seekable() is False
        with pytest.raises((io.UnsupportedOperation, ValueError)):
            f.seek(0)


def test_seekable_flag_enables_forward_and_backward_seek(
    member: tuple[Path, str],
) -> None:
    # With the capability the stream reports seekable and seeking actually works both
    # ways (backward seeks may re-decode from the start; the caller accepted that cost).
    source, name = member
    with open_archive(source, seekable_members=True) as ar, ar.open(name) as f:
        assert f.seekable() is True
        assert f.read() == CONTENT
        f.seek(0)  # backward to the start
        assert f.read() == CONTENT
        f.seek(10)  # forward into the middle
        assert f.read() == CONTENT[10:]
        assert f.tell() == len(CONTENT)


def test_seek_past_end_then_read_returns_empty(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source, seekable_members=True) as ar, ar.open(name) as f:
        if not f.seekable():
            pytest.skip("member stream is not seekable")
        f.seek(len(CONTENT) + 100)
        assert f.read() == b""
        assert f.read(64) == b""


def test_seek_to_start_rereads(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source, seekable_members=True) as ar, ar.open(name) as f:
        if not f.seekable():
            pytest.skip("member stream is not seekable")
        assert f.read(5) == CONTENT[:5]
        f.seek(0)
        assert f.read() == CONTENT


def test_seek_underflow_matches_bytesio(member: tuple[Path, str]) -> None:
    source, name = member
    with open_archive(source, seekable_members=True) as ar, ar.open(name) as f:
        if not f.seekable():
            pytest.skip("member stream is not seekable")
        if source.is_dir():
            # A directory member is the file itself, opened with open(): a relative seek
            # before its start raises OSError(EINVAL) as it does on any file.
            with pytest.raises(OSError):
                f.seek(-1, io.SEEK_CUR)
            # A negative SEEK_SET is refused before the file handle, as on every
            # other format.
            with pytest.raises(ValueError) as excinfo:
                f.seek(-1)
            assert type(excinfo.value) is ValueError
            assert_unknown_whence_is_value_error(f)
            return
        assert_seek_underflow_matches_bytesio(f)


_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("archive", "member_name"),
    [
        pytest.param(
            "zipcrypto/check_byte_collision.zip", "deflated.txt", id="zipcrypto"
        ),
        pytest.param(
            "zipcrypto/check_byte_collision.zip", "stored.txt", id="zipcrypto_stored"
        ),
        pytest.param(
            "external/aes_ae1_pyzipper036.zip",
            "secret.txt",
            id="aes",
            marks=requires("cryptography"),
        ),
    ],
)
def test_encrypted_zip_seek_underflow_matches_bytesio(
    archive: str, member_name: str
) -> None:
    with (
        open_archive(
            _FIXTURES / archive, password="secret", seekable_members=True
        ) as ar,
        ar.open(member_name) as f,
    ):
        assert_seek_underflow_matches_bytesio(f)


# ---------------------------------------------------------------------------
# Corpus enrollment: MemberStreams.SEEKABLE is a guarantee, not a request mask
# ---------------------------------------------------------------------------
#
# The small `member` fixture above never included RAR, AES ZIP, or encrypted 7z,
# which is how the original holes survived. These rows come from CORPUS.

_BY_ID: dict[str, CorpusEntry] = {e.id: e for e in CORPUS}


@dataclass(frozen=True)
class _SeekSpec:
    """One corpus archive enrolled in the seekability matrix.

    ``packing``:
      stored — fail if the member is not only STORED (RAR urandom trap).
      compressed — fail if the member is only STORED (or packed size >= size).
      None — no packing assertion.
    """

    entry_id: str
    key: str
    packing: str | None = None


_SEEK_ARCHIVES: tuple[_SeekSpec, ...] = (
    # ZIP store / deflate / bzip2 / lzma
    _SeekSpec("zip-compression-methods", "zip"),
    # ZipCrypto (the decrypt stage rewinds, or decrypts what it skips)
    _SeekSpec("encrypted", "zip"),
    _SeekSpec("encrypted-mixed", "zip"),
    # WinZip AES (CTR restarts at the target block; the mixed archive's
    # plaintext member is per-file and seeks as an unencrypted one)
    _SeekSpec("encrypted", "zip-aes"),
    _SeekSpec("encrypted-mixed", "zip-aes"),
    # 7z solid LZMA2 (`basic`), stored COPY, encrypted (now seeks).
    # Mixed 7z is archive-wide encryption: the corpus-plain file is encrypted too.
    _SeekSpec("basic", "7z"),
    _SeekSpec("sevenzip-stored", "7z", packing="stored"),
    _SeekSpec("encrypted", "7z"),
    _SeekSpec("encrypted-mixed", "7z"),
    _SeekSpec("encrypted-header", "7z"),
    # RAR stored (existing corpus is urandom/`basic` tiny files — both store)
    _SeekSpec("basic", "rar", packing="stored"),
    _SeekSpec("large", "rar", packing="stored"),
    # RAR genuinely compressed (new corpus row; not the stored slice path)
    _SeekSpec("compressed", "rar", packing="compressed"),
    # RAR encrypted goes through unrar, not an archivey decrypt wrapper.
    # Mixed RAR keeps a real plaintext member (per-member passwords).
    _SeekSpec("encrypted", "rar"),
    _SeekSpec("encrypted-mixed", "rar"),
    # TAR + compressed TAR + the original contract formats the hand list covered
    _SeekSpec("basic", "tar"),
    _SeekSpec("basic", "tar.gz"),
    _SeekSpec("basic", "tar.bz2"),
    _SeekSpec("basic", "tar.xz"),
    _SeekSpec("basic", "tar.zst"),
    _SeekSpec("basic", "tar.lz4"),
    _SeekSpec("basic", "tar.lz"),
    _SeekSpec("basic", "tar.zz"),
    _SeekSpec("basic", "tar.br"),
    _SeekSpec("basic", "dir"),
    _SeekSpec("basic", "iso"),
    _SeekSpec("basic", "iso-joliet"),
    _SeekSpec("single-file", "gz"),
    _SeekSpec("single-file", "bz2"),
    _SeekSpec("single-file", "xz"),
    _SeekSpec("single-file", "zst"),
    _SeekSpec("single-file", "lz4"),
    _SeekSpec("single-file", "lz"),
    _SeekSpec("single-file", "zz"),
    _SeekSpec("single-file", "br"),
    _SeekSpec("single-file-meta", "gz-meta"),
)


def _is_only_stored(member) -> bool:
    chain = member.compression
    return bool(chain) and all(c.algo is CompressionAlgorithm.STORED for c in chain)


def _seek_member_params() -> list:
    params = []
    for spec in _SEEK_ARCHIVES:
        entry = _BY_ID[spec.entry_id]
        if spec.key not in entry.formats:
            raise AssertionError(
                f"seek matrix names {spec.entry_id}/{spec.key} but that entry "
                f"is built as {entry.formats}"
            )
        for member in entry.members:
            if member.type is not MemberType.FILE:
                continue
            params.append(
                pytest.param(
                    spec,
                    member.name,
                    id=f"{spec.entry_id}/{spec.key}/{member.name}",
                )
            )
    return params


def _open_enrolled(
    spec: _SeekSpec, tmp_path: Path, *, seekable_members: bool, streaming: bool = False
):
    entry = _BY_ID[spec.entry_id]
    skip_unless_runnable(entry, spec.key)
    source = corpus_archive_path(entry, spec.key, tmp_path)
    return open_archive(
        source,
        seekable_members=seekable_members,
        streaming=streaming,
        password=list(entry.passwords) or None,
    )


def _resolve_file_member(ar, name: str):
    files = [m for m in ar.members() if m.is_file]
    matches = [m for m in files if m.name == name]
    if len(matches) == 1:
        return matches[0]
    # Single-file compressors infer the member name from the archive filename.
    if len(files) == 1:
        return files[0]
    pytest.fail(
        f"could not resolve file member {name!r}; have {[m.name for m in files]}"
    )


def _assert_packing(spec: _SeekSpec, member, *, name: str) -> None:
    if spec.packing is None:
        return
    algos = "+".join(c.algo.value for c in member.compression) or "(none)"
    if spec.packing == "stored":
        assert _is_only_stored(member), (
            f"{spec.entry_id}/{spec.key} {name!r} must be STORED for this row "
            f"(codec={algos}, packed={member.compressed_size}, size={member.size})"
        )
        return
    if spec.packing != "compressed":
        raise AssertionError(f"unknown packing {spec.packing!r}")
    packed_not_smaller = (
        member.compressed_size is not None
        and member.size is not None
        and member.size > 0
        and member.compressed_size >= member.size
    )
    if _is_only_stored(member) or packed_not_smaller:
        pytest.fail(
            f"{spec.entry_id}/{spec.key} {name!r} was stored; the compressed-RAR "
            f"row must not silently take the direct-slice path "
            f"(codec={algos}, packed={member.compressed_size}, size={member.size})"
        )


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_default_member_stream_is_not_seekable(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    with _open_enrolled(spec, tmp_path, seekable_members=False) as ar:
        member = _resolve_file_member(ar, member_name)
        _assert_packing(spec, member, name=member_name)
        with ar.open(member) as f:
            assert f.seekable() is False
            with pytest.raises((io.UnsupportedOperation, ValueError)):
                f.seek(0)


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_seekable_members_seek_and_reread(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    with _open_enrolled(spec, tmp_path, seekable_members=True) as ar:
        member = _resolve_file_member(ar, member_name)
        _assert_packing(spec, member, name=member_name)
        with ar.open(member) as f:
            assert f.seekable() is True
            data = f.read()
            f.seek(0)
            assert f.read() == data
            if not data:
                return
            mid = min(10, len(data) - 1)
            f.seek(mid)
            assert f.read() == data[mid:]
            assert f.tell() == len(data)


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_seek_underflow_matches_bytesio(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    # The same seek-before-start contract as the hand-built fixture above, over every
    # enrolled backend and codec path (RAR through unrar, 7z, encrypted ZIP, ...).
    with _open_enrolled(spec, tmp_path, seekable_members=True) as ar:
        member = _resolve_file_member(ar, member_name)
        with ar.open(member) as f:
            if spec.key == "dir":
                # A directory member is a real file: relative underflow is its OSError.
                # A negative SEEK_SET or unknown whence is refused before the file.
                with pytest.raises(OSError):
                    f.seek(-1, io.SEEK_CUR)
                with pytest.raises(ValueError) as excinfo:
                    f.seek(-1)
                assert type(excinfo.value) is ValueError
                assert_unknown_whence_is_value_error(f)
                return
            assert_seek_underflow_matches_bytesio(f)


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_non_integer_seek_is_type_error(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    """``seek(1.5)`` is the caller's ``TypeError`` on every enrolled backend and codec,
    raised before the stream moves, and the stream reads correctly afterwards."""
    with _open_enrolled(spec, tmp_path, seekable_members=True) as ar:
        member = _resolve_file_member(ar, member_name)
        with ar.open(member) as f:
            content = f.read()
        with ar.open(member) as f:
            assert_non_integer_seek_is_type_error(f, content)


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_non_integer_read_is_type_error(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    """``read(1.5)`` is the caller's ``TypeError`` on every enrolled backend and codec,
    raised before anything is read, and the stream reads correctly afterwards."""
    with _open_enrolled(spec, tmp_path, seekable_members=True) as ar:
        member = _resolve_file_member(ar, member_name)
        with ar.open(member) as f:
            content = f.read()
        with ar.open(member) as f:
            assert_non_integer_read_is_type_error(f, content)


@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_oversized_read_is_overflow_error(
    spec: _SeekSpec, member_name: str, tmp_path: Path
) -> None:
    """``read(2**70)`` is the caller's ``OverflowError`` on every enrolled backend and
    codec, raised before anything is read, and the stream reads correctly afterwards."""
    with _open_enrolled(spec, tmp_path, seekable_members=True) as ar:
        member = _resolve_file_member(ar, member_name)
        with ar.open(member) as f:
            content = f.read()
        with ar.open(member) as f:
            assert_oversized_read_is_overflow_error(f, content)


@pytest.mark.parametrize("kind", ["gz", "zip-deflate"])
def test_stream_members_non_integer_read_is_type_error(
    kind: str, tmp_path: Path
) -> None:
    """A forward-only ``stream_members()`` handle refuses ``read(1.5)`` and
    ``read(2**70)`` the same way, and the next read still returns the member: no seek
    can recover it there."""
    content = os.urandom(60) + b"text " * 40
    if kind == "gz":
        path = tmp_path / "data.bin.gz"
        path.write_bytes(gzip.compress(content))
    else:
        path = tmp_path / "data.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.bin", content)
    # Untyped handle: the argument is wrong on purpose.
    with open_archive(path, streaming=True) as ar:
        for member, f in ar.stream_members():
            assert member.is_file and f is not None
            read: Callable[..., bytes] = f.read
            with pytest.raises(TypeError):
                read(1.5)
            with pytest.raises(OverflowError):
                f.read(2**70)
            assert f.read() == content


def test_rapidgzip_non_integer_seek_is_type_error(tmp_path: Path) -> None:
    """The accelerated gzip path: a float offset reached the child and raised a raw
    ``struct.error``, losing the child."""
    pytest.importorskip("rapidgzip", reason="needs the [seekable] extra")
    content = os.urandom(200_000) + b"text " * 200_000
    path = tmp_path / "data.bin.gz"
    path.write_bytes(gzip.compress(content))
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)
    with open_archive(path, seekable_members=True, config=config) as ar:
        (member,) = [m for m in ar.members() if m.is_file]
        with ar.open(member) as f:
            assert_non_integer_seek_is_type_error(f, content)


def _assert_forward_only(f) -> None:
    assert f.seekable() is False
    head = f.read(1)
    assert f.tell() == len(head)
    with pytest.raises(io.UnsupportedOperation):
        f.seek(0)
    # The refused seek did not move the stream.
    assert f.tell() == len(head)


# (seekable_members, streaming, API) -> does the handle seek. Only random open() under
# seekable_members=True seeks: a stream_members() pass is single-pass on every format,
# whatever the source or the declaration.
_SEEKABILITY_CASES = (
    pytest.param(False, False, "open", False, id="default-open"),
    pytest.param(False, False, "stream_members", False, id="default-pass"),
    pytest.param(True, False, "open", True, id="seekable-open"),
    pytest.param(True, False, "stream_members", False, id="seekable-pass"),
    pytest.param(True, True, "stream_members", False, id="seekable-streaming-pass"),
)


@pytest.mark.parametrize(
    "spec",
    [pytest.param(s, id=f"{s.entry_id}/{s.key}") for s in _SEEK_ARCHIVES],
)
@pytest.mark.parametrize(
    ("seekable_members", "streaming", "api", "expect_seekable"), _SEEKABILITY_CASES
)
def test_member_stream_seekability_matrix(
    spec: _SeekSpec,
    seekable_members: bool,
    streaming: bool,
    api: str,
    expect_seekable: bool,
    tmp_path: Path,
) -> None:
    with _open_enrolled(
        spec, tmp_path, seekable_members=seekable_members, streaming=streaming
    ) as ar:
        if api == "open":
            for member in ar.members():
                if not member.is_file:
                    continue
                _assert_packing(spec, member, name=member.name)
                with ar.open(member) as f:
                    if expect_seekable:
                        assert f.seekable() is True
                        f.read(1)
                        assert f.seek(0) == 0
                    else:
                        _assert_forward_only(f)
            return
        seen = 0
        for member, stream in ar.stream_members():
            if stream is None:
                continue
            assert member.is_file
            # Streaming readers cannot list before the pass; the member is known here.
            _assert_packing(spec, member, name=member.name)
            seen += 1
            _assert_forward_only(stream)
        assert seen, "archive yielded no file member streams"


def _nested_params() -> list:
    params = []
    for entry_id in ("basic", "single-file"):
        for key in _BY_ID[entry_id].formats:
            if key == "dir":
                continue
            params.append(pytest.param(entry_id, key, id=f"{entry_id}/{key}"))
    return params


# Formats open_archive() reads from a non-seekable source (streaming=True only).
_STREAMS_FROM_PIPE = (
    frozenset(k for k in FORMAT_KEYS if k.startswith("tar"))
    | {"zip"}
    | set(_BY_ID["single-file"].formats)
)


@pytest.mark.parametrize(("entry_id", "key"), _nested_params())
def test_nested_archive_from_a_pass_handle_is_a_non_seekable_source(
    entry_id: str, key: str, tmp_path: Path
) -> None:
    """A ``stream_members()`` handle handed to ``open_archive()`` is a pipe to it.

    The pass handle never seeks, even under ``seekable_members=True``, so a nested
    archive read from it gets no random access: the default open raises
    ``StreamNotSeekableError``, ``streaming=True`` works only for formats that stream
    from a non-seekable source, and the formats that need their index (7z, RAR, ISO)
    refuse in either mode. ``open()`` on the same member still gives a seekable
    source, which is the documented way to read a nested archive at random.
    """
    entry = _BY_ID[entry_id]
    skip_unless_runnable(entry, key)
    inner_path = corpus_archive_path(entry, key, tmp_path / "inner")
    outer_path = tmp_path / "outer.tar"
    inner_name = f"inner.{key}"
    with tarfile.open(outer_path, "w") as tf:
        tf.add(inner_path, inner_name)
    file_count = sum(1 for m in entry.members if m.type is MemberType.FILE)

    def pass_handle() -> Iterator[ArchiveStream]:
        # A fresh outer pass per attempt: a refused open has already read the head.
        with open_archive(outer_path, seekable_members=True) as outer:
            handles = 0
            for member, stream in outer.stream_members():
                if stream is not None:
                    handles += 1
                    assert member.name == inner_name
                    assert stream.seekable() is False
                    yield stream
            assert handles == 1

    for stream in pass_handle():
        with pytest.raises(StreamNotSeekableError):
            open_archive(stream)
    for stream in pass_handle():
        if key in _STREAMS_FROM_PIPE:
            with open_archive(stream, streaming=True) as inner:
                assert inner.cost.stream_capability is StreamCapability.FORWARD_ONLY
                streams = [s for _, s in inner.stream_members() if s is not None]
                assert len(streams) == file_count
        else:
            with pytest.raises(StreamNotSeekableError):
                open_archive(stream, streaming=True)

    with (
        open_archive(outer_path, seekable_members=True) as outer,
        outer.open(inner_name) as f,
    ):
        assert f.seekable() is True
        with open_archive(f) as inner:
            assert inner.cost.stream_capability is StreamCapability.SEEKABLE
            assert sum(1 for m in inner.members() if m.is_file) == file_count


# Formats / mechanisms this contract should cover but cannot construct here.
# Skip (not pass): a missing row would look like the format was certified.
_UNTESTED: tuple[tuple[str, str], ...] = (
    ("unix-compress", "no corpus builder for unix compress (.Z)"),
    ("lzma-alone", "no corpus builder for LZMA Alone"),
    ("zip-deflate64", "no corpus builder for ZIP Deflate64"),
    ("zip-ppmd", "no corpus builder for ZIP PPMd"),
    ("zip-zstd", "no corpus builder for ZIP Zstd"),
    ("7z-ppmd", "no corpus builder for 7z PPMd"),
    ("7z-deflate64", "no corpus builder for 7z Deflate64"),
    ("7z-bcj2", "no corpus builder for 7z BCJ2 (py7zr cannot write it)"),
    (
        "7z-compressed-nonsolid",
        "py7zr multi-file writes are solid LZMA2; sevenzip-stored is a single COPY file (non-solid stored)",
    ),
    (
        "rar4",
        "corpus RAR fixtures are RAR5; RAR4 lives in targeted reader fixtures",
    ),
    ("multi-volume", "no corpus builder for split/multi-volume archives"),
    ("tar-lzma-alone", "no corpus builder for tar + LZMA Alone"),
    ("tar-unix-compress", "no corpus builder for tar + unix compress (.tar.Z)"),
    ("udif", "UDIF is recognised and refused; there is no reader"),
)

_UNTESTED_FORMATS = {
    ArchiveFormat.Z: "unix-compress",
    ArchiveFormat.LZMA_ALONE: "lzma-alone",
    ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE): "tar-lzma-alone",
    ArchiveFormat(ContainerFormat.TAR, StreamFormat.UNIX_COMPRESS): "tar-unix-compress",
    ArchiveFormat.DMG: "udif",
}


@pytest.mark.parametrize(
    ("label", "reason"),
    [pytest.param(label, reason, id=label) for label, reason in _UNTESTED],
)
def test_seekability_untested_mechanism(label: str, reason: str) -> None:
    pytest.skip(f"untested: {reason}")


def test_seekability_enrollment_covers_corpus_format_keys() -> None:
    enrolled = {spec.key for spec in _SEEK_ARCHIVES}
    missing = set(FORMAT_KEYS) - enrolled
    assert not missing, f"FORMAT_KEYS not enrolled in seek matrix: {sorted(missing)}"


def test_seekability_enrollment_covers_known_formats() -> None:
    enrolled = {FORMAT_KEYS[spec.key] for spec in _SEEK_ARCHIVES}
    untested = set(_UNTESTED_FORMATS)
    missing = set(list_known_formats()) - enrolled - untested - {ArchiveFormat.UNKNOWN}
    assert not missing, (
        f"known formats absent from seek matrix: {sorted(missing, key=str)}"
    )


# ---------------------------------------------------------------------------
# Reader close and the streams it handed out
# ---------------------------------------------------------------------------
#
# The pass-stream half of this rule lives in tests/test_concurrent_cooperative.py,
# over RAR, solid 7z and the streaming readers (_SUSPENDED_SOURCES).


@pytest.mark.parametrize("seekable", [False, True], ids=["forward", "seekable"])
@pytest.mark.parametrize(("spec", "member_name"), _seek_member_params())
def test_corpus_reader_close_mid_read_closes_the_member_stream(
    spec: _SeekSpec, member_name: str, seekable: bool, tmp_path: Path
) -> None:
    """``reader.close()`` after a member's first byte is read closes that stream, on
    every enrolled backend and codec path.

    The ``archive-reading`` lifecycle rule: a member stream does not outlive its
    reader, and a read after the close raises as for any closed stream (``ValueError``,
    as ``zipfile`` and ``tarfile`` give). With ``zipfile`` underneath, a stored ZIP
    member had kept serving bytes from its own handle while a deflated one refused.
    The matrix keeps the corpus's zero-byte members: those are at EOF after the read,
    not part-read, and still show the close reaching the stream.
    """
    with _open_enrolled(spec, tmp_path, seekable_members=seekable) as ar:
        member = _resolve_file_member(ar, member_name)
        f = ar.open(member)
        f.read(1)
        ar.close()
        assert f.closed
        with pytest.raises(ValueError, match="closed file"):
            f.read(1)
        with pytest.raises(ArchiveyUsageError, match="closed"):
            ar.open(member)
        f.close()  # idempotent


# ---------------------------------------------------------------------------
# Uniform handle type
# ---------------------------------------------------------------------------


def test_member_streams_are_archive_streams(member: tuple[Path, str]) -> None:
    # Every member handle the library hands out — from open() and from
    # stream_members() alike — is an ArchiveStream, regardless of backend (even the
    # directory backend, which has nothing to decompress): uniform error
    # translation/stamping, the `size` advertisement, and one place to grow shared
    # handle features.
    from archivey.internal.streams.archive_stream import ArchiveStream

    source, name = member
    with open_archive(source) as ar:
        with ar.open(name) as f:
            assert isinstance(f, ArchiveStream)
        for m, stream in ar.stream_members():
            if m.is_file:
                assert isinstance(stream, ArchiveStream)
            if stream is not None:
                stream.close()


def test_stream_members_do_not_nest_archive_streams(tmp_path: Path) -> None:
    """``stream_members`` must hand out a single ArchiveStream, not wrap-over-wrap.

    Regression for the lazy-open double wrap (``_lazy_member_stream`` over
    ``_wrap_member_stream``): after first read, the public handle's inner must not
    itself be an ``ArchiveStream``.
    """
    from archivey.internal.streams.archive_stream import ArchiveStream

    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"payload")
    with open_archive(path) as ar:
        for member, stream in ar.stream_members():
            if not member.is_file or stream is None:
                continue
            assert isinstance(stream, ArchiveStream)
            assert stream.read() == b"payload"
            inner = stream._inner
            assert inner is not None
            assert not isinstance(inner, ArchiveStream)
            break
        else:
            pytest.fail("expected a file member")


def test_zip_member_fuses_verify_no_verifying_stream_layer(tmp_path: Path) -> None:
    """STORED ZIP: public ArchiveStream verifies directly over SlicingStream.

    After verify-fusion, the codec ArchiveStream collapses through and there is
    no VerifyingStream in the chain (review/archive/2026-07-19-stream-layering/collapse-design.md).
    """
    from archivey.internal.streams.archive_stream import ArchiveStream
    from archivey.internal.streams.streamtools.slice import SlicingStream
    from archivey.internal.streams.verify import VerifyingStream

    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.bin", b"hello-verify-fuse")
    with open_archive(path) as ar, ar.open("a.bin") as f:
        assert isinstance(f, ArchiveStream)
        assert f._verifier is not None
        assert not isinstance(f._inner, ArchiveStream)
        assert not isinstance(f._inner, VerifyingStream)
        assert isinstance(f._inner, SlicingStream)
        assert f.read() == b"hello-verify-fuse"


def test_member_stream_advertises_size(member: tuple[Path, str]) -> None:
    # The fsspec-style `size` attribute carries the decompressed length when the
    # archive metadata knows it (feeds nested-archive sizing and the bomb tracker).
    source, name = member
    with open_archive(source) as ar, ar.open(name) as f:
        size = getattr(f, "size", None)
        assert size is None or size == len(CONTENT)
