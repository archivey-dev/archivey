"""An archive cut short raises ``TruncatedError`` in every container format.

A caller handling partial downloads catches one type, whatever the format (DR-5).
Each archive is cut at offsets spread over its whole length and read through every
public path: the listing and ``open()``, ``stream_members()`` and ``extract_all()``
from a file and, for the formats that read forward, from a pipe. Every cut must either
raise ``TruncatedError``, or open and read with nothing lost but what the format reports
as a missing end marker (TAR and RAR5 cut at a header boundary, a ZIP cut inside its
archive comment), trailing zeros (ISO padding), or whole RAR4 members after a header
boundary, which no reader can detect. Any other exception fails the test: a plain
``CorruptionError`` is for bytes that are present and wrong.

The cuts start after the format's signature. A file that ends inside the signature is
not recognisably that format: 7-Zip and unrar answer "cannot open the file as archive"
for it, not "unexpected end", so archivey keeps ``CorruptionError`` there (DR-6).
"""

from __future__ import annotations

import io
import struct
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveFormat, open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import TruncatedError
from archivey.internal.backends.rar_parser import RarMemberInfo
from archivey.reader import ArchiveReader
from tests.conftest import requires_binary
from tests.sample_archives import CORPUS, corpus_archive_path, skip_unless_runnable
from tests.streams_util import NonSeekableBytesIO

# Bytes a cut must keep before the file is recognisably the format (see the module
# docstring): the ZIP local header signature, the 7z signature without its version,
# the RAR5 signature. TAR and ISO carry no signature at offset 0.
_SIGNATURE_LENGTH = {"zip": 4, "zip-aes": 4, "7z": 6, "rar": 8}
# The formats that read from a source that cannot seek.
_FORWARD_ONLY = {"zip", "zip-aes", "tar"}
_RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
_PIPE_FORMAT = {".zip": ArchiveFormat.ZIP, ".tar": ArchiveFormat.TAR}
_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

_CASES = [
    ("basic", "zip"),
    ("basic", "tar"),
    ("basic", "7z"),
    ("basic", "rar"),
    ("basic", "iso"),
    ("basic", "iso-joliet"),
    ("comments", "zip"),
    ("comments", "rar"),
    ("zip-compression-methods", "zip"),
    ("encrypted", "zip"),
    ("encrypted", "zip-aes"),
    ("encrypted", "7z"),
    ("encrypted", "rar"),
    ("large", "zip"),
    ("large", "7z"),
    ("large", "rar"),
]


def _with_zip64_end_record(data: bytes) -> bytes:
    """A ZIP with no archive comment rewritten to end in a ZIP64 end record and locator,
    with the classic record's fields set to their ZIP64 sentinels."""
    eocd = len(data) - 22
    assert data[eocd : eocd + 4] == b"PK\x05\x06"
    count, cd_size, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    body = data[:eocd]
    record = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        cd_size,
        cd_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, len(body), 1)
    classic = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0
    )
    return body + record + locator + classic


def _cuts(start: int, length: int, count: int) -> list[int]:
    """About ``count`` cuts spread over ``[start, length)``, plus the last bytes, where
    the end records sit."""
    spread = range(start, length, max(1, (length - start) // count))
    tail = (length - k for k in (1, 22, 30))
    return sorted({*spread, *(cut for cut in tail if cut >= start)})


def _read_all(reader: ArchiveReader) -> None:
    for member in reader.members():
        if member.is_file:
            with reader.open(member) as stream:
                stream.read()


def _stream_all(reader: ArchiveReader) -> None:
    for _member, stream in reader.stream_members():
        if stream is not None:
            stream.read()


def _mode_random(cut: Path, data: bytes, scratch: Path, pw: list[str] | None) -> bool:
    with open_archive(cut, password=pw) as reader:
        _read_all(reader)
        return _marker_missing(reader)


def _mode_stream(cut: Path, data: bytes, scratch: Path, pw: list[str] | None) -> bool:
    with open_archive(cut, password=pw, streaming=True) as reader:
        _stream_all(reader)
        return _marker_missing(reader)


def _open_pipe(cut: Path, data: bytes, pw: list[str] | None) -> ArchiveReader:
    # A pipe has no name to detect from, and a TAR cut before its ``ustar`` magic at
    # byte 257 has no magic either, so the caller names the format.
    source = NonSeekableBytesIO(data)
    fmt = _PIPE_FORMAT[cut.suffix]
    return open_archive(source, password=pw, streaming=True, format=fmt)


def _mode_pipe(cut: Path, data: bytes, scratch: Path, pw: list[str] | None) -> bool:
    with _open_pipe(cut, data, pw) as reader:
        _stream_all(reader)
        return _marker_missing(reader)


def _fresh_dest(scratch: Path) -> Path:
    """A new empty directory to extract into, one for each read.

    A directory is not reused: an ISO with Rock Ridge extracts its files read-only
    (mode 0o444), and on Windows ``shutil.rmtree`` cannot delete a read-only file, so
    the next extraction into the same place found the earlier files there.
    """
    return Path(tempfile.mkdtemp(prefix="out", dir=scratch))


def _mode_pipe_extract(
    cut: Path, data: bytes, scratch: Path, pw: list[str] | None
) -> bool:
    with _open_pipe(cut, data, pw) as reader:
        reader.extract_all(_fresh_dest(scratch))
        return _marker_missing(reader)


def _mode_extract(cut: Path, data: bytes, scratch: Path, pw: list[str] | None) -> bool:
    with open_archive(cut, password=pw) as reader:
        reader.extract_all(_fresh_dest(scratch))
        return _marker_missing(reader)


def _marker_missing(reader: ArchiveReader) -> bool:
    counts = reader.diagnostics.counts
    return counts.get(DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING, 0) > 0


def _silent_read_allowed(
    data: bytes, password: list[str] | None, scratch_file: Path
) -> Callable[[int], bool]:
    """Whether a cut at an offset may read whole with nothing reported.

    A cut past the last nonzero byte loses only zeros: ISO padding, the TAR end
    blocks, which those formats may accept without a word. RAR 1.5-4 writers may
    omit the end block, so a RAR4 cut between two members' blocks leaves an archive
    no reader can tell from a complete one; unrar lists it and exits 0
    (dev-docs/formats/rar.md). A RAR4 cut inside a member's header or packed data
    is not that case, and must be reported.
    """
    if not data.startswith(_RAR4_SIGNATURE):
        content_end = len(data.rstrip(b"\0"))
        return lambda cut: cut >= content_end
    scratch_file.write_bytes(data)
    with open_archive(scratch_file, password=password) as reader:
        spans = [
            (raw.header_offset, raw.data_offset + raw.compress_size)
            for member in reader.members()
            if isinstance(raw := member._raw, RarMemberInfo)
        ]
    assert spans
    return lambda cut: not any(start < cut < end for start, end in spans)


def _check_every_cut(
    data: bytes,
    key: str,
    suffix: str,
    password: list[str] | None,
    tmp_path: Path,
    *,
    count: int = 24,
) -> None:
    modes: dict[str, Callable[[Path, bytes, Path, list[str] | None], bool]] = {
        "random access": _mode_random,
        "stream_members": _mode_stream,
        "extract_all": _mode_extract,
    }
    if key in _FORWARD_ONLY:
        modes["stream_members from a pipe"] = _mode_pipe
        modes["extract_all from a pipe"] = _mode_pipe_extract
    cut_path = tmp_path / f"cut{suffix}"
    silent_ok = _silent_read_allowed(data, password, cut_path)
    failures: list[str] = []
    truncated = 0
    for cut in _cuts(_SIGNATURE_LENGTH.get(key, 1), len(data), count):
        cut_path.write_bytes(data[:cut])
        for name, mode in modes.items():
            try:
                reported = mode(cut_path, data[:cut], tmp_path, password)
            except TruncatedError:
                truncated += 1
                continue
            except Exception as exc:  # noqa: BLE001  # the failure names any type
                failures.append(f"cut {cut}, {name}: {type(exc).__name__}: {exc}")
                continue
            if not reported and not silent_ok(cut):
                failures.append(f"cut {cut}, {name}: read whole, nothing reported")
    assert not failures, "\n".join(failures)
    assert truncated > 0


@pytest.mark.parametrize(
    ("entry_id", "key"), _CASES, ids=[f"{e}-{k}" for e, k in _CASES]
)
def test_a_cut_archive_raises_truncated_in_every_format(
    entry_id: str, key: str, tmp_path: Path
) -> None:
    entry = next(e for e in CORPUS if e.id == entry_id)
    skip_unless_runnable(entry, key)
    source = corpus_archive_path(entry, key, tmp_path)
    password = list(entry.passwords) or None
    # Each open of an encrypted archive derives a key, so those get fewer cuts.
    count = 6 if password else 24
    _check_every_cut(
        source.read_bytes(), key, source.suffix, password, tmp_path, count=count
    )


def test_a_cut_zip64_archive_raises_truncated(tmp_path: Path) -> None:
    entry = next(e for e in CORPUS if e.id == "basic")
    skip_unless_runnable(entry, "zip")
    data = _with_zip64_end_record(
        corpus_archive_path(entry, "zip", tmp_path).read_bytes()
    )
    with open_archive(io.BytesIO(data)) as reader:  # precondition: the rewrite reads
        assert len(reader.members()) == len(entry.members)
    _check_every_cut(data, "zip", ".zip", None, tmp_path)


@requires_binary("unrar")
@pytest.mark.parametrize(
    "name",
    [
        "encryption__.rar",
        "encryption__rar4.rar",
        "encryption_solid__.rar",
        "encryption_large__rar4.rar",
        "basic_solid__.rar",
        "basic_solid__rar4.rar",
        "encryption_stored__.rar",
        "encryption_large_stored__rar4.rar",
    ],
)
def test_a_cut_rar_read_through_unrar_is_truncated(name: str, tmp_path: Path) -> None:
    """``unrar`` exits 3 for a member whose packed data the file cuts. With no output
    that is also what RAR4 gives for a wrong password, and the bytes it writes for the
    gap can fail the digest first. The listing knows the data runs past the end of the
    file, so the right password reads as a cut, in random access and in a pass: not
    ``EncryptionError``, and not a digest mismatch. The plain solid and the stored
    encrypted fixtures are controls: they already raised ``TruncatedError``, the
    stored ones because archivey decrypts and slices them itself. The committed
    fixtures run where the ``rar`` builder is absent."""
    data = (_RAR_FIXTURES / name).read_bytes()
    _check_every_cut(data, "rar", ".rar", ["password"], tmp_path, count=4)


@requires_binary("unrar")
def test_a_cut_rar4_member_does_not_judge_the_password_candidates(
    tmp_path: Path,
) -> None:
    """A RAR4 candidate list is judged by decoding one encrypted member for the whole
    archive, in a nonsolid archive the smallest. A member whose data the file cuts
    fails to decode with every candidate, so it is not chosen; the intact member
    still reads with two candidates, and the cut one raises ``TruncatedError``.

    Built from ``encryption__rar4.rar`` with its two member blocks swapped, so the
    smaller member is last and the cut lands inside its packed data."""
    data = (_RAR_FIXTURES / "encryption__rar4.rar").read_bytes()
    source = tmp_path / "source.rar"
    source.write_bytes(data)
    with open_archive(source, password="password") as reader:
        first, second = (member._raw for member in reader.members())
    assert isinstance(first, RarMemberInfo) and isinstance(second, RarMemberInfo)

    def block(raw: RarMemberInfo) -> bytes:
        return data[raw.header_offset : raw.data_offset + raw.compress_size]

    swapped = (
        data[: first.header_offset]
        + block(second)
        + block(first)
        + data[second.data_offset + second.compress_size :]
    )
    cut_at = swapped.index(block(first)) + (first.data_offset - first.header_offset)
    cut = tmp_path / "cut.rar"
    cut.write_bytes(swapped[: cut_at + first.compress_size // 2])

    with open_archive(cut, password=["wrong", "password"]) as reader:
        intact, short = reader.members_report().members
        assert short.size < intact.size  # the smallest, as the judge is chosen
        reference = reader._unchecked_reference_member()
        assert reference is not None and reference.name == intact.name
        with reader.open(intact) as stream:
            assert stream.read() == b"This is also secret"
        with pytest.raises(TruncatedError), reader.open(short) as stream:
            stream.read()
