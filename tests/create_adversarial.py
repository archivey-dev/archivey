"""Build hostile string archives deterministically and entirely in memory.

Writer libraries correctly reject several byte sequences this corpus needs, so each case
starts from a clean stdlib-generated ZIP or TAR and performs a length-preserving,
field-targeted mutation.  No generated archive is committed or written into the source
tree.

The case names describe what the format actually says:

* invalid/WTF-8/overlong ZIP names have general-purpose bit 11 set in *both* headers, so
  the flag claims UTF-8 and the bytes are not: they decode as an unflagged name would;
* an unflagged high-byte ZIP name and comment are explicitly CP437 fallback cases, not
  mislabeled "invalid UTF-8";
* TAR invalid bytes exercise tarfile's documented UTF-8+surrogateescape path;
* no regular TAR name-field NUL case is claimed, because a NUL there is the field
  terminator rather than a character in the path.

ZIP entries are deliberately STORED.  That makes a symlink target a directly addressable
payload; mutating it also updates the CRC-32 in the local and central headers.
"""

from __future__ import annotations

import io
import stat
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

# Distinctive, equal-per-field-length ASCII placeholders spliced over at test time.
_NAME = b"NAME_ZZZZZZZZ.txt"  # 17 bytes
_LINK = b"LINKTARGET_ZZZZZ"  # 16 bytes
_COMMENT = b"COMMENT_ZZZZZZZZ"  # 16 bytes


# --- hostile tokens ---------------------------------------------------------------

# Each hostile byte sequence, padded with a benign filler to the field's placeholder
# length so the splice is length-preserving.
_HOSTILE: dict[str, bytes] = {
    "nul": b"\x00",
    "lone_surrogate": b"\xed\xa0\x80",  # WTF-8 encoding of U+D800 (invalid UTF-8)
    "invalid_utf8": b"\xff\xfe",
    "rtl_override": b"\xe2\x80\xae",  # U+202E RIGHT-TO-LEFT OVERRIDE (valid UTF-8)
    # U+200F RIGHT-TO-LEFT MARK. Also a bidi control, also warned about — but a
    # *directional mark*, which reorders nothing and occurs in legitimate Arabic and
    # Hebrew filenames. It must extract, which is what proves the extraction rejection
    # covers the override/isolate subset and not the whole advisory set.
    "rtl_mark": b"\xe2\x80\x8f",
    "overlong": b"\xc0\xaf",  # overlong encoding of "/" (invalid UTF-8)
}


def _padded(token: bytes, length: int) -> bytes:
    body = token + b"x" * (length - len(token))
    assert len(body) == length, f"{token!r} does not fit in {length} bytes"
    return body


# --- clean bases (generated on demand) --------------------------------------------


def build_base_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        info = zipfile.ZipInfo(_NAME.decode())
        info.create_system = 3
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.comment = _COMMENT
        zf.writestr(info, b"payload for the adversarial name member\n")
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.compress_type = zipfile.ZIP_STORED
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, _LINK)
    return buf.getvalue()


def build_base_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo(_NAME.decode())
        payload = b"payload for the adversarial name member\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = _LINK.decode()
        tf.addfile(link)
    return buf.getvalue()


# --- ZIP field mutation -----------------------------------------------------------


def _find_zip_header(
    base: bytes, signature: bytes, fixed_size: int, name: bytes
) -> int:
    """Find the unique ZIP header with ``name`` and return its start offset."""
    matches: list[int] = []
    start = base.find(signature)
    while start >= 0:
        name_length_offset = start + (26 if fixed_size == 30 else 28)
        if name_length_offset + 2 <= len(base):
            name_length = struct.unpack_from("<H", base, name_length_offset)[0]
            name_start = start + fixed_size
            if base[name_start : name_start + name_length] == name:
                matches.append(start)
        start = base.find(signature, start + 1)
    assert len(matches) == 1, (
        f"expected one {signature!r} header for {name!r}, found {len(matches)}"
    )
    return matches[0]


def _zip_headers_for_name(base: bytes, name: bytes) -> tuple[int, int]:
    return (
        _find_zip_header(base, b"PK\x03\x04", 30, name),
        _find_zip_header(base, b"PK\x01\x02", 46, name),
    )


def _zip_name_splice(base: bytes, replacement: bytes, *, utf8: bool) -> bytes:
    """Replace the name in both headers, optionally first setting both UTF-8 flags.

    Header offsets are found while the placeholder is still present.  In particular,
    bit 11 is set *before* either name copy is replaced; looking for ``_NAME`` after the
    splice would silently mutate neither header.
    """
    assert len(replacement) == len(_NAME)
    local, central = _zip_headers_for_name(base, _NAME)
    data = bytearray(base)
    if utf8:
        for flag_offset in (local + 6, central + 8):
            flags = struct.unpack_from("<H", data, flag_offset)[0] | 0x0800
            struct.pack_into("<H", data, flag_offset, flags)
    data[local + 30 : local + 30 + len(_NAME)] = replacement
    data[central + 46 : central + 46 + len(_NAME)] = replacement
    return bytes(data)


def _zip_stored_data_splice(
    base: bytes, name: bytes, token: bytes, replacement: bytes
) -> bytes:
    """Mutate one STORED member payload and repair both CRC fields."""
    assert len(token) == len(replacement)
    local, central = _zip_headers_for_name(base, name)
    local_flags, local_method = struct.unpack_from("<HH", base, local + 6)
    central_method = struct.unpack_from("<H", base, central + 10)[0]
    assert not local_flags & 0x0008, "test base must not use a data descriptor"
    assert local_method == central_method == zipfile.ZIP_STORED

    local_crc, compressed_size, uncompressed_size = struct.unpack_from(
        "<III", base, local + 14
    )
    central_crc, central_compressed, central_uncompressed = struct.unpack_from(
        "<III", base, central + 16
    )
    assert compressed_size == uncompressed_size == len(token)
    assert central_compressed == central_uncompressed == len(token)
    assert local_crc == central_crc == zlib.crc32(token)

    name_length, extra_length = struct.unpack_from("<HH", base, local + 26)
    payload_start = local + 30 + name_length + extra_length
    assert base[payload_start : payload_start + len(token)] == token

    data = bytearray(base)
    data[payload_start : payload_start + len(token)] = replacement
    replacement_crc = zlib.crc32(replacement)
    struct.pack_into("<I", data, local + 14, replacement_crc)
    struct.pack_into("<I", data, central + 16, replacement_crc)
    return bytes(data)


def _zip_comment_splice(base: bytes, token: bytes, replacement: bytes) -> bytes:
    """Mutate the first member's central-directory comment."""
    assert len(token) == len(replacement)
    _, central = _zip_headers_for_name(base, _NAME)
    name_length, extra_length, comment_length = struct.unpack_from(
        "<HHH", base, central + 28
    )
    comment_start = central + 46 + name_length + extra_length
    assert comment_length == len(token)
    assert base[comment_start : comment_start + comment_length] == token
    data = bytearray(base)
    data[comment_start : comment_start + comment_length] = replacement
    return bytes(data)


# --- TAR field mutation -----------------------------------------------------------


def _tar_recompute_checksum(data: bytearray, block_start: int) -> None:
    header = data[block_start : block_start + 512]
    header[148:156] = b" " * 8  # checksum field is spaces while summing
    chksum = sum(header)
    data[block_start + 148 : block_start + 156] = b"%06o\x00 " % chksum


def _tar_splice(base: bytes, token: bytes, replacement: bytes) -> bytes:
    """Replace one fixed TAR header field and repair that header's checksum."""
    assert len(token) == len(replacement)
    assert base.count(token) == 1
    idx = base.index(token)
    assert idx % 512 + len(token) <= 512, "token is not wholly inside a TAR header"
    data = bytearray(base)
    data[idx : idx + len(token)] = replacement
    _tar_recompute_checksum(data, (idx // 512) * 512)
    return bytes(data)


# --- corpus manifest --------------------------------------------------------------


ExtractOutcome = Literal[
    "success",
    "path_traversal",
    "symlink_escape",
    "filesystem_name_refusal",
    "deceptive_name",
]


@dataclass(frozen=True)
class Adversarial:
    id: str
    fmt: str  # "zip" | "tar"
    build: Callable[[bytes], bytes]  # (base_bytes) -> spliced_bytes
    field: Literal["name", "link_target", "comment"]
    stored_name: bytes
    expected_name: str | None
    expected_raw_name: bytes | None
    expected_link_target: str | None = None
    expected_comment: str | None = None
    utf8_flag: bool = False
    extract_outcome: ExtractOutcome = "success"
    warning_text: str | None = None


def _is_utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _zip_name_case(
    case_id: str,
    key: str,
    *,
    utf8: bool,
    extract_outcome: ExtractOutcome = "success",
    warning_text: str | None = None,
) -> Adversarial:
    raw = _padded(_HOSTILE[key], len(_NAME))
    decoded = raw.decode("utf-8" if utf8 and _is_utf8(raw) else "cp437")
    return Adversarial(
        id=case_id,
        fmt="zip",
        build=lambda base, replacement=raw, flagged=utf8: _zip_name_splice(
            base, replacement, utf8=flagged
        ),
        field="name",
        stored_name=raw,
        expected_name=decoded,
        expected_raw_name=raw,
        utf8_flag=utf8,
        extract_outcome=extract_outcome,
        warning_text=warning_text,
    )


def _tar_name_case(
    case_id: str,
    key: str,
    *,
    extract_outcome: ExtractOutcome,
    warning_text: str | None = None,
) -> Adversarial:
    raw = _padded(_HOSTILE[key], len(_NAME))
    return Adversarial(
        id=case_id,
        fmt="tar",
        build=lambda base, replacement=raw: _tar_splice(base, _NAME, replacement),
        field="name",
        stored_name=raw,
        expected_name=raw.decode("utf-8", errors="surrogateescape"),
        expected_raw_name=raw,
        extract_outcome=extract_outcome,
        warning_text=warning_text,
    )


CORPUS: tuple[Adversarial, ...] = (
    _zip_name_case(
        "zip-name-nul",
        "nul",
        utf8=False,
        extract_outcome="path_traversal",
    ),
    _zip_name_case("zip-name-cp437-high-bytes", "invalid_utf8", utf8=False),
    _zip_name_case(
        "zip-name-wtf8-flagged",
        "lone_surrogate",
        utf8=True,
        warning_text="decoded as an unflagged name",
    ),
    _zip_name_case(
        "zip-name-invalid-utf8-flagged",
        "invalid_utf8",
        utf8=True,
        warning_text="decoded as an unflagged name",
    ),
    _zip_name_case(
        "zip-name-overlong-utf8-flagged",
        "overlong",
        utf8=True,
        warning_text="decoded as an unflagged name",
    ),
    _zip_name_case(
        "zip-name-rtl-override",
        "rtl_override",
        utf8=True,
        extract_outcome="deceptive_name",
        warning_text="bidirectional control",
    ),
    _zip_name_case(
        "zip-name-rtl-mark",
        "rtl_mark",
        utf8=True,
        warning_text="bidirectional control",
    ),
    _tar_name_case(
        "tar-name-invalid-utf8-surrogateescape",
        "invalid_utf8",
        extract_outcome="filesystem_name_refusal",
    ),
    _tar_name_case(
        "tar-name-rtl-override",
        "rtl_override",
        extract_outcome="deceptive_name",
        warning_text="bidirectional control",
    ),
    _tar_name_case(
        "tar-name-rtl-mark",
        "rtl_mark",
        extract_outcome="success",
        warning_text="bidirectional control",
    ),
    Adversarial(
        id="zip-link-nul",
        fmt="zip",
        build=lambda base: _zip_stored_data_splice(
            base, b"link", _LINK, _padded(_HOSTILE["nul"], len(_LINK))
        ),
        field="link_target",
        stored_name=b"link",
        expected_name="link",
        expected_raw_name=b"link",
        expected_link_target=_padded(_HOSTILE["nul"], len(_LINK)).decode("utf-8"),
        extract_outcome="symlink_escape",
    ),
    Adversarial(
        id="zip-comment-cp437-high-bytes",
        fmt="zip",
        build=lambda base: _zip_comment_splice(
            base, _COMMENT, _padded(_HOSTILE["invalid_utf8"], len(_COMMENT))
        ),
        field="comment",
        stored_name=_NAME,
        expected_name=_NAME.decode(),
        expected_raw_name=_NAME,
        expected_comment=_padded(_HOSTILE["invalid_utf8"], len(_COMMENT)).decode(
            "cp437"
        ),
    ),
)


def clean_base_archives() -> dict[str, bytes]:
    """Fresh deterministic bases; generated on demand, never persisted."""
    return {"zip": build_base_zip(), "tar": build_base_tar()}


def adversarial_archives() -> list[tuple[Adversarial, bytes]]:
    """Every corpus entry as ``(entry, spliced_archive_bytes)``, built in memory."""
    bases = clean_base_archives()
    return [(entry, entry.build(bases[entry.fmt])) for entry in CORPUS]
