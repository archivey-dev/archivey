"""Security advisories of the Rust ``zip`` crate (zip-rs/zip2), replayed against
archivey's ZIP reader.

Each test rebuilds the archive an advisory describes and checks that archivey keeps
the property the crate lost: every way of reading an archive agrees on what it holds,
an authenticated member is authenticated, and a declared size buys no allocation. A
test names the advisory it replays (GHSA id), so a failure points at the write-up.
The advisories about symlinks are replayed in ``test_cve_regressions``, next to the
other link escapes, apart from the one that needs the destination's own path.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
from pathlib import Path

import pytest

from archivey import (
    DiagnosticCode,
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
    open_archive,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    FilterRejectionError,
    TruncatedError,
)
from tests.conftest import requires
from tests.extract_util import open_and_extract
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO
from tests.test_cve_regressions import _outside_layout, _zip as _zip_entries

# ``pipe`` reads a stream that cannot seek, so a ZIP is read by its local headers.
_MODES = pytest.mark.parametrize("mode", ["random", "stream", "pipe"])


def _open(data: bytes, mode: str, **kwargs):
    source = NonSeekableBytesIO(data) if mode == "pipe" else io.BytesIO(data)
    return open_archive(source, streaming=mode != "random", **kwargs)


def _zip(*members: tuple[str, bytes], extra: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in members:
            info = zipfile.ZipInfo(name)
            info.extra = extra
            zf.writestr(info, payload)
    return buf.getvalue()


def _eocd(data: bytes | bytearray) -> int:
    return bytes(data).rindex(b"PK\x05\x06")


def _central_offsets(data: bytes | bytearray) -> list[int]:
    """Where each central directory header starts."""
    eocd = _eocd(data)
    count, _size, start = struct.unpack_from("<HLL", data, eocd + 10)
    out = []
    pos = start
    for _ in range(count):
        out.append(pos)
        n, m, k = struct.unpack_from("<HHH", data, pos + 28)
        pos += 46 + n + m + k
    return out


def _moved(data: bytes, by: int) -> bytearray:
    """``data``, a whole ZIP, with every offset in it moved by ``by``: the ZIP as it
    reads when ``by`` bytes come before it, as when one ZIP is appended to another."""
    out = bytearray(data)
    for pos in _central_offsets(out):
        struct.pack_into(
            "<L", out, pos + 42, struct.unpack_from("<L", out, pos + 42)[0] + by
        )
    eocd = _eocd(out)
    struct.pack_into(
        "<L", out, eocd + 16, struct.unpack_from("<L", out, eocd + 16)[0] + by
    )
    return out


def _drain(data: bytes, mode: str) -> None:
    """Read every member of ``data`` to its end."""
    with _open(data, mode) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


def _extracted(data: bytes, mode: str, dest: Path) -> list[str]:
    """What ``data`` extracts to, as paths under ``dest``."""
    with _open(data, mode) as reader:
        reader.extract_all(dest)
    return sorted(
        os.path.relpath(os.path.join(parent, name), dest)
        for parent, _, names in os.walk(dest)
        for name in names
    )


# --- Which archive a reader sees ------------------------------------------------------


def _two_archives(*, malformed_ntfs: bool) -> bytes:
    """``benign.txt`` in one ZIP, then ``payload.sh`` in a second appended after it,
    its offsets counted from the start of the file. With ``malformed_ntfs``, the
    second member carries an NTFS extra field (0x000a) of a length that holds no
    attribute, which the crate refused."""
    benign = _zip(("benign.txt", b"benign"))
    extra = struct.pack("<HH", 0x000A, 7) + bytes(7) if malformed_ntfs else b""
    payload = _moved(_zip(("payload.sh", b"evil"), extra=extra), len(benign))
    return benign + bytes(payload)


@_MODES
def test_ghsa_wjr6_mhvj_cjvm_last_end_record_wins(mode: str, tmp_path: Path) -> None:
    # The crate went back to an earlier end-of-central-directory record when the
    # last one's directory held a field it refused, so it listed the first archive
    # and every other reader the second. The last end record is the archive here, as
    # for zipfile, unzip and bsdtar, and its odd extra field is kept unparsed.
    data = _two_archives(malformed_ntfs=True)
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["payload.sh"]
    assert _extracted(data, mode, tmp_path) == ["payload.sh"]
    if mode != "pipe":
        # A pipe meets ``benign.txt`` first and yields it; the directory then drops
        # it (``ARCHIVE_UNLISTED_DATA``, docs/formats.md), and extraction above
        # kept only what the directory lists.
        with _open(data, mode) as reader:
            assert [m.name for m, _ in reader.stream_members()] == ["payload.sh"]


@_MODES
def test_ghsa_wjr6_mhvj_cjvm_directory_offset_naming_another_directory(
    mode: str, tmp_path: Path
) -> None:
    # The same advisory's second input: the last end record's directory offset names
    # the first archive's directory, while its directory size (counted back from the
    # end record) gives the second. The crate took the offset and listed
    # ``benign.txt``; zipfile, unzip and bsdtar take the size and list
    # ``payload.sh``. The payload's local-header offset is moved by the same
    # distance, so the size-based reading still finds it.
    data = bytearray(_two_archives(malformed_ntfs=False))
    eocd = _eocd(data)
    benign_cd = data.index(b"PK\x01\x02")
    real_cd = struct.unpack_from("<L", data, eocd + 16)[0]
    struct.pack_into("<L", data, eocd + 16, benign_cd)
    local = struct.unpack_from("<L", data, real_cd + 42)[0]
    struct.pack_into("<L", data, real_cd + 42, local - (real_cd - benign_cd))
    archive = bytes(data)
    assert zipfile.ZipFile(io.BytesIO(archive)).namelist() == ["payload.sh"]
    assert _extracted(archive, mode, tmp_path) == ["payload.sh"]


@_MODES
def test_ghsa_m665_v7pm_7grj_local_name_differs(mode: str, tmp_path: Path) -> None:
    # "ZIP cloaking": a local header named ``cron_worker.sh`` under a directory entry
    # named ``doc_report.pdf``. The crate's random-access reader listed the
    # directory's name and its stream extractor wrote the local one, so a scanner
    # and an extractor saw different files. Every mode extracts the directory's name
    # here and reports the difference (which ``STRICT`` raises).
    data = bytearray(_zip(("cron_worker.sh", b"payload")))
    entry = _central_offsets(data)[0]
    data[entry + 46 : entry + 46 + 14] = b"doc_report.pdf"
    archive = bytes(data)
    assert _extracted(archive, mode, tmp_path) == ["doc_report.pdf"]
    with _open(archive, mode) as reader:
        seen = [(m.name, s.read() if s else None) for m, s in reader.stream_members()]
        counts = reader.diagnostics.counts
    # A pipe yields each member as its local header names it, before the directory
    # (read last) gives the name the extraction above used (docs/formats.md).
    name = "cron_worker.sh" if mode == "pipe" else "doc_report.pdf"
    assert seen == [(name, b"payload")]
    assert counts[DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS] == 1


@_MODES
def test_ghsa_gmfj_vffv_32pw_missing_end_record(mode: str) -> None:
    # The crate's validating stream reader finished without error on a ZIP cut just
    # before its end-of-central-directory record. Here every mode raises: a pipe
    # reads the directory and then needs the end record after it.
    data = _zip(("a", b"aaa"), ("b", b"bbb"))
    with pytest.raises(TruncatedError, match="end of central directory"):
        _drain(data[: _eocd(data)], mode)


@_MODES
@pytest.mark.parametrize("which", ["one", "all"])
def test_ghsa_gmfj_vffv_32pw_shifted_local_offsets(mode: str, which: str) -> None:
    # The same advisory: the crate measured local-header offsets from the first one,
    # which hid a directory whose offsets were all moved by the same amount. A
    # directory offset that names no local header is damage in every mode, whether
    # one entry or every entry is moved.
    data = bytearray(_zip(("a", b"aaa"), ("b", b"bbb")))
    entries = _central_offsets(data)
    for pos in entries[1:] if which == "one" else entries:
        struct.pack_into(
            "<L", data, pos + 42, struct.unpack_from("<L", data, pos + 42)[0] + 3
        )
    with pytest.raises(CorruptionError, match="(?i)magic number|no local header"):
        _drain(bytes(data), mode)


# --- Overlapping entries --------------------------------------------------------------


def _with_extra_entries(data: bytes, extra: list[bytes]) -> bytes:
    """``data`` with ``extra`` central directory entries appended to its directory."""
    cd_start = _central_offsets(data)[0]
    eocd = _eocd(data)
    directory = data[cd_start:eocd] + b"".join(extra)
    end = bytearray(data[eocd:])
    count = len(_central_offsets(data)) + len(extra)
    struct.pack_into("<HHLL", end, 8, count, count, len(directory), cd_start)
    return data[:cd_start] + directory + bytes(end)


def _alias(entry: bytes, name: bytes, local_offset: int) -> bytes:
    """A copy of the central directory entry ``entry`` (no extra, no comment) under
    ``name``, pointing at ``local_offset``."""
    out = bytearray(entry[:46]) + name
    struct.pack_into("<H", out, 28, len(name))
    struct.pack_into("<L", out, 42, local_offset)
    return bytes(out)


@_MODES
def test_ghsa_8p9w_4prr_vvqh_empty_entries_inside_another(mode: str) -> None:
    # The crate's overlap check skipped entries of no compressed data and did not
    # count local headers, so two empty entries over one local header placed inside
    # another member's stored data passed it. That header lies inside ``outer.bin``'s
    # data here, so the read refuses the overlap; a pass that cannot seek reads the
    # data whole and finds no local header where the directory says.
    inner = _zip(("a", b""))
    inner_local = inner[: inner.index(b"PK\x01\x02")]
    inner_entry = inner[inner.index(b"PK\x01\x02") : inner.index(b"PK\x05\x06")]
    outer = _zip(("outer.bin", inner_local))
    at = outer.index(inner_local)
    data = _with_extra_entries(
        outer,
        [_alias(inner_entry, b"inner_1", at), _alias(inner_entry, b"inner_2", at)],
    )
    with pytest.raises(CorruptionError, match="(?i)overlap|no local header"):
        _drain(data, mode)


@_MODES
def test_ghsa_8p9w_4prr_vvqh_empty_entries_sharing_one_header(mode: str) -> None:
    # The same check's other blind spot: two empty entries over one local header.
    # ``test_cve_parsing`` replays the non-empty form (CVE-2024-0450).
    data = _zip(("a", b""))
    entry = data[_central_offsets(data)[0] : _eocd(data)]
    archive = _with_extra_entries(data, [_alias(entry, b"b", 0)])
    with pytest.raises(CorruptionError, match="(?i)overlap|already describes"):
        _drain(archive, mode)


# --- WinZip AES authentication --------------------------------------------------------


def _read_all(data: bytes, mode: str) -> list[bytes]:
    with _open(data, mode, password=b"pw") as reader:
        return [s.read() for _, s in reader.stream_members() if s is not None]


@requires("cryptography")
@_MODES
@pytest.mark.parametrize("vendor_version", [1, 2], ids=["AE-1", "AE-2"])
def test_ghsa_c9rm_qm35_rhqf_ciphertext_after_the_compressed_stream(
    mode: str, vendor_version: int
) -> None:
    # The crate checked the authentication code only when the decompressor had read
    # all the ciphertext. A deflate stream that ends early, with 64 KiB of ciphertext
    # after it (more than the crate's 8 KiB buffer), returned the forged output with
    # no check. Ciphertext left after the stream's end is damage here, before any
    # verdict on the code.
    from tests.zip_aes_fixture import build_aes_zip

    data = build_aes_zip(
        [(b"a.bin", b"hello" * 10)],
        password=b"pw",
        vendor_version=vendor_version,
        compressed_tail=bytes(65536),
    )
    with pytest.raises(CorruptionError, match="left after its end"):
        _read_all(data, mode)


@requires("cryptography")
@_MODES
def test_ghsa_8hxf_qr8p_62x4_empty_member_is_authenticated(mode: str) -> None:
    # The crate returned early for an AES member of no data, before it read the
    # authentication code, so a tampered code passed. An empty member's code is
    # checked like any other here.
    from tests.zip_aes_fixture import build_aes_zip

    good = build_aes_zip([(b"empty", b"")], password=b"pw", method=0)
    assert _read_all(good, mode) == [b""]
    bad = build_aes_zip([(b"empty", b"")], password=b"pw", method=0, tamper_hmac=True)
    with pytest.raises(CorruptionError, match="HMAC mismatch"):
        _read_all(bad, mode)


@requires("cryptography")
@_MODES
def test_ghsa_8hxf_qr8p_62x4_member_declaring_past_the_end(mode: str) -> None:
    # The advisory's other input: an AES member whose declared size runs past the
    # end of the file, so the crate's reader met the end before its count reached
    # zero and skipped the code. A member cut short is truncated here, in every mode.
    from tests.zip_aes_fixture import build_aes_zip

    data = bytearray(
        build_aes_zip([(b"a.bin", b"hello" * 10)], password=b"pw", method=0)
    )
    # Keep the member and drop the directory: the declared size now runs past the
    # end, and a pass that cannot seek meets the end inside the member too.
    cut = bytes(data[: data.index(b"PK\x01\x02") - 4])
    with pytest.raises(TruncatedError):
        _read_all(cut, mode)


# --- Symlinks ----------------------------------------------------------------------


def _symlink_declaring(size: int) -> bytes:
    """A stored ZIP symlink ``l`` to ``target`` whose directory entry declares
    ``size`` bytes of data in a ZIP64 extra field (and the local header 0)."""
    data = bytearray(_zip_entries([("sym", "l", "target")]))
    struct.pack_into("<L", data, 22, 0)
    entry = _central_offsets(data)[0]
    n, m, _k = struct.unpack_from("<HHH", data, entry + 28)
    extra = struct.pack("<HHQ", 0x0001, 8, size)
    struct.pack_into("<L", data, entry + 24, 0xFFFFFFFF)
    struct.pack_into("<H", data, entry + 30, m + len(extra))
    at = entry + 46 + n + m
    out = bytearray(data[:at] + extra + data[at:])
    eocd = _eocd(out)
    struct.pack_into(
        "<L", out, eocd + 12, struct.unpack_from("<L", out, eocd + 12)[0] + len(extra)
    )
    return bytes(out)


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@_MODES
def test_ghsa_q7v9_x93c_xqv3_symlink_declaring_a_huge_target(
    mode: str, tmp_path: Path
) -> None:
    # The crate sized a buffer for a symlink's target from the member's declared
    # size before reading any of it, and 2**62 bytes aborted the process. A target
    # longer than 4096 bytes is refused here before anything is read for it, and the
    # extraction goes on without the link.
    data = _symlink_declaring(1 << 62)

    def extract() -> None:
        dest = tmp_path / f"d{len(list(tmp_path.iterdir()))}"
        with _open(data, mode) as reader:
            report = reader.extract_all(dest, on_error=OnError.CONTINUE)
        ((outcome,),) = [list(report)]
        assert outcome.status is ExtractionStatus.FAILED
        assert isinstance(outcome.error, ArchiveyError)
        assert not os.path.lexists(dest / "l")

    extract()
    assert traced_peak(extract) < 16 << 20


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
def test_ghsa_hjqx_j4rw_g7xv_absolute_link_into_the_destination(
    tmp_path: Path, policy: ExtractionPolicy, streaming: bool
) -> None:
    # The crate checked symlink targets lexically and never again: ``b`` pointing
    # outside, then ``a`` pointing at ``<dest>/b/sub`` (inside, by its spelling), then
    # ``a/pwned.txt`` written through both. ``b`` is refused here, and nothing is
    # written through a link this run created.
    dest, outside = _outside_layout(tmp_path)
    entries = [
        ("sym", "b", str(outside)),
        ("sym", "a", f"{dest}/b/sub"),
        ("file", "a/pwned.txt", b"overwritten"),
    ]
    report = open_and_extract(
        io.BytesIO(_zip_entries(entries)),
        dest,
        streaming=streaming,
        policy=policy,
        on_error=OnError.CONTINUE,
        overwrite=OverwritePolicy.REPLACE,
    )
    outcomes = {r.member.name: r for r in report}
    assert outcomes["b"].status is ExtractionStatus.BLOCKED
    assert isinstance(outcomes["b"].error, FilterRejectionError)
    assert outcomes["a/pwned.txt"].status is not ExtractionStatus.EXTRACTED
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest", "outside"]
    assert [p.name for p in outside.iterdir()] == ["victim"]
    assert not any(p.name == "pwned.txt" for p in tmp_path.rglob("*"))
