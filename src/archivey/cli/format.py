"""Shared formatting helpers for CLI output."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from datetime import datetime

from archivey.cli.sources import http_error_text, redact
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.exceptions import ArchiveyError, ArchiveyUsageError
from archivey.terminal import display_path, escape_control_chars
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionMethod,
    HashAlgorithm,
    MemberType,
)

_TYPE_MARK = {
    MemberType.FILE: "f",
    MemberType.DIRECTORY: "d",
    MemberType.SYMLINK: "l",
    MemberType.HARDLINK: "h",
    MemberType.ANTI: "A",
    MemberType.OTHER: "?",
}


def format_format_label(fmt: ArchiveFormat) -> str:
    """Human format name (``zip``, ``7z``, ``tar.gz``) rather than enum spellings."""
    ext = fmt.file_extension()
    if ext:
        return ext
    return fmt.display_name.lower().replace("_", "-")


def escape_member_name(name: str) -> str:
    """Backslash-escape control bytes in a member name for safe terminal display.

    A thin alias over :func:`archivey.terminal.escape_control_chars`, kept because
    every CLI call site is escaping a member name (or a path built from one) and
    reads better for saying so. Exception messages escape themselves; the CLI does
    not escape them again, or the backslashes would double.
    """
    return escape_control_chars(name)


def escape_path(path: str | os.PathLike[str]) -> str:
    """Render a path for terminal display: ``/``-separated, then escaped.

    For every path the CLI prints that is not already relative to an extraction root —
    the wrapper directory, the hoist destination, a collision's destination, the
    closing summary. Most are built from a member's top-level name or from the archive's
    own filename, and either can carry control bytes. Rendering ``/``-separated first
    keeps a native Windows path from having every separator doubled by the escape
    (:func:`archivey.terminal.display_path`).
    """
    return escape_control_chars(display_path(path))


def format_error_detail(exc: BaseException) -> str:
    """Render an exception for terminal display, escaping only what has not been.

    Archivey's own exceptions escape their message at construction, so escaping them
    again here would double every backslash they wrote. Anything else — an ``OSError``
    carrying a destination filename, a third-party error — has had nothing done to it
    and still needs escaping.

    Call sites should not have to know which of the two they are holding; several hold
    a union (``ExtractionResult.error`` is ``ArchiveyError | OSError``). This is the
    one place that decides.

    A URL the CLI resolved is replaced by its sanitized label first, so a signed URL's
    query or a password in its authority is not printed
    (:func:`~archivey.cli.sources.redact`). An aiohttp error gets a message the CLI
    builds itself (:func:`~archivey.cli.sources.http_error_text`).
    """
    if isinstance(exc, (ArchiveyError, ArchiveyUsageError)):
        return redact(str(exc))
    http_text = http_error_text(exc)
    if http_text is not None:
        return escape_control_chars(http_text)
    return escape_control_chars(redact(str(exc)))


def format_mode(mode: int | None) -> str:
    if mode is None:
        return "---------"
    bits = mode & 0o777
    perms = ""
    for who in (6, 3, 0):
        tri = (bits >> who) & 0o7
        perms += "r" if tri & 0o4 else "-"
        perms += "w" if tri & 0o2 else "-"
        perms += "x" if tri & 0o1 else "-"
    return perms


def format_mtime(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    # Naive wall-clock as stored; drop tz for compact display when aware.
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M")


def format_size(size: int | None) -> str:
    if size is None:
        return "-"
    return str(size)


def format_hash_value(value: bytes | int) -> str:
    """Format a stored digest for CLI display (values are ``bytes``; ``int`` accepted)."""
    if isinstance(value, int):
        return f"{value:08x}" if value <= 0xFFFFFFFF else hex(value)
    return value.hex()


def _member_status(member: ArchiveMember) -> str:
    """The two-character type and status mark that starts every listing line."""
    mark = _TYPE_MARK.get(member.type, "?")
    if member.is_encrypted:
        status = "E"
    elif not member.is_current:
        status = "~"  # superseded / non-current revision
    else:
        status = "-"
    return f"{mark}{status}"


def _member_label(member: ArchiveMember) -> str:
    """The escaped name, with ``-> target`` for a link."""
    name = escape_member_name(member.name)
    if member.is_link and member.link_target is not None:
        name = f"{name} -> {escape_member_name(member.link_target)}"
    return name


def _listing_suffix(member: ArchiveMember, *, digests: bool, verbose: bool) -> str:
    """The ``[digests]`` and ``(diagnostics)`` a listing line ends with, when asked."""
    suffix = ""
    if digests and member.hashes:
        digest_bits = " ".join(
            f"{algo.value}={format_hash_value(val)}"
            for algo, val in sorted(member.hashes.items())
        )
        suffix += f"  [{digest_bits}]"
    if verbose and member.diagnostics:
        # Messages are stored escaped (see format_member_details).
        diag = "; ".join(
            d.message for d in member.diagnostics if getattr(d, "message", None)
        )
        if diag:
            suffix += f"  ({diag})"
    return suffix


def format_member_line(
    member: ArchiveMember,
    *,
    digests: bool = False,
    verbose: bool = False,
) -> str:
    """Layer-1 listing line; optional stored digests and verbose extras."""
    parts = [
        _member_status(member),
        format_mode(member.mode),
        f"{format_size(member.size):>10}",
        format_mtime(member.modified),
        _member_label(member),
    ]
    return "  ".join(parts) + _listing_suffix(member, digests=digests, verbose=verbose)


def format_compression(methods: tuple[CompressionMethod, ...]) -> str:
    """The member's codec chain, pre-filters first: ``deflate``, ``bcj2+lzma2``.

    A RAR method level shows after a colon (``rar:3``). ``-`` when the member's
    entry records no method at all: a directory or a link, or a format that leaves
    the field empty.
    """
    if not methods:
        return "-"
    return "+".join(
        m.algo.value if m.level is None else f"{m.algo.value}:{m.level}"
        for m in methods
    )


def format_saved(member: ArchiveMember) -> str:
    """Space saved, as ``unzip -v`` prints it: ``75%`` for a member packed to a quarter.

    Negative when the packed data is larger (a tiny member under encryption overhead).
    """
    size, packed = member.size, member.compressed_size
    if size is None or packed is None:
        return "-"
    if size == 0:
        return "0%"
    return f"{round(100 * (size - packed) / size)}%"


def _crc_column(member: ArchiveMember) -> str:
    crc = member.hashes.get(HashAlgorithm.CRC32)
    return format_hash_value(crc) if crc is not None else "-"


# ``list --long`` columns between the status mark and the name: title, alignment, and
# the cell for one member. Each column is as wide as its widest cell in the listing.
_LONG_COLUMNS: tuple[tuple[str, str, Callable[[ArchiveMember], str]], ...] = (
    ("mode", "<", lambda m: format_mode(m.mode)),
    ("size", ">", lambda m: format_size(m.size)),
    ("packed", ">", lambda m: format_size(m.compressed_size)),
    ("saved", ">", format_saved),
    ("method", "<", lambda m: escape_control_chars(format_compression(m.compression))),
    ("crc32", ">", _crc_column),
    ("modified", "<", lambda m: format_mtime(m.modified)),
)


def format_long_listing(
    members: Sequence[ArchiveMember], *, digests: bool, verbose: bool
) -> list[str]:
    """``list --long``: a header line, then one line per member.

    The default line's columns plus packed size, space saved, method and stored
    CRC-32, each column sized to its widest cell so the names line up under their
    header. ``digests`` and ``verbose`` add the same suffixes as the default line.
    Empty for no members (no header without rows).
    """
    if not members:
        return []
    cells = [[cell(m) for _, _, cell in _LONG_COLUMNS] for m in members]
    widths = [
        max(len(title), *(len(row[i]) for row in cells))
        for i, (title, _, _) in enumerate(_LONG_COLUMNS)
    ]

    def join(status: str, row: list[str], name: str) -> str:
        padded = [
            f"{text:{align}{width}}"
            for text, (_, align, _), width in zip(
                row, _LONG_COLUMNS, widths, strict=True
            )
        ]
        return "  ".join([status, *padded, name])

    lines = [join("ts", [title for title, _, _ in _LONG_COLUMNS], "name")]
    for member, row in zip(members, cells, strict=True):
        lines.append(
            join(_member_status(member), row, _member_label(member))
            + _listing_suffix(member, digests=digests, verbose=verbose)
        )
    return lines


def format_field_value(value: object) -> str:
    """One ``key: value`` value for the terminal, escaped.

    Shared by ``info`` and ``list --details``, so a value prints the same in both.
    ``bytes`` print as ``hex:<digits>``: bare hex digits read as a number (a TAR
    typeflag ``b"0"`` would show as ``30``).
    """
    if isinstance(value, bytes):
        return f"hex:{value.hex()}"
    return escape_control_chars(str(value))


def _format_time_detail(dt: datetime | None) -> str | None:
    return None if dt is None else dt.isoformat(sep=" ")


def format_member_details(member: ArchiveMember) -> list[str]:
    """``list --details`` block: one ``key: value`` line per field the member has.

    Fields the format does not record are left out rather than printed as ``-``, so
    the block shows what this archive actually stores. ``raw_name`` shows only when
    it is not the UTF-8 spelling of ``name``. Every value from the archive is escaped
    (:func:`format_field_value`); a diagnostic's message arrives escaped and is not
    escaped again (see below).
    """
    fields: list[tuple[str, object]] = [
        ("name", member.name),
    ]
    if member.raw_name is not None and member.raw_name != member.name.encode(
        "utf-8", "surrogateescape"
    ):
        fields.append(("raw_name", member.raw_name))
    fields.append(("type", member.type.value))
    if member.is_link and member.link_target is not None:
        fields.append(("link_target", member.link_target))
    fields += [
        ("size", member.size),
        ("packed_size", member.compressed_size),
    ]
    if member.size is not None and member.compressed_size is not None:
        fields.append(("saved", format_saved(member)))
    if member.compression:
        fields.append(("method", format_compression(member.compression)))
    fields.append(("encrypted", "yes" if member.is_encrypted else "no"))
    if not member.is_current:
        fields.append(("current", "no"))
    if member.is_sparse:
        fields.append(("sparse", "yes"))
    fields += [
        ("modified", _format_time_detail(member.modified)),
        ("accessed", _format_time_detail(member.accessed)),
        ("created", _format_time_detail(member.created)),
        ("ctime", _format_time_detail(member.ctime)),
    ]
    if member.mode is not None:
        fields.append(("mode", f"{member.mode:04o} ({format_mode(member.mode)})"))
    fields += [
        ("uid", member.uid),
        ("gid", member.gid),
        ("owner", member.uname),
        ("group", member.gname),
    ]
    if member.create_system is not None:
        fields.append(("host_os", member.create_system.name.lower()))
    if member.windows_attrs is not None:
        fields.append(("windows_attrs", f"0x{member.windows_attrs:08x}"))
    for algo, val in sorted(member.hashes.items()):
        fields.append((algo.value, format_hash_value(val)))
    fields.append(("comment", member.comment))
    for key, value in sorted(member.extra.items()):
        fields.append((f"extra.{key}", value))

    shown = [
        (escape_control_chars(k), format_field_value(v))
        for k, v in fields
        if v is not None
    ]
    # A diagnostic's message is stored escaped already; escaping it again would
    # double its backslashes.
    shown += [
        ("diagnostic", f"{d.code.value}: {d.message}") for d in member.diagnostics
    ]
    width = max(len(k) for k, _ in shown) + 1
    return [f"{key + ':':<{width}} {text}" for key, text in shown]


def format_access_summary(cost: CostReceipt) -> str:
    """One-line human summary of ``CostReceipt`` for ``archivey info`` (Q5 / P14).

    Derived from the public open-time axes only — not accelerator install state
    (that lives in config / diagnostics, not the frozen receipt).
    """
    if cost.access_cost is AccessCost.SOLID:
        bits: list[str] = []
        if cost.listing_cost is ListingCost.REQUIRES_DECOMPRESSION:
            bits.append("listing requires decompression")
        elif cost.listing_cost is ListingCost.REQUIRES_SCANNING:
            bits.append("listing requires scan")
        bits.append("reading one member may decode earlier members in its block")
        if cost.solid_block_count is not None:
            n = cost.solid_block_count
            bits.append(f"{n} solid block{'s' if n != 1 else ''}")
        if cost.stream_capability is StreamCapability.FORWARD_ONLY:
            bits.append("forward-only source")
        return f"solid ({'; '.join(bits)})"

    if cost.listing_cost is ListingCost.INDEXED:
        head = "random (indexed)"
    elif cost.listing_cost is ListingCost.REQUIRES_SCANNING:
        head = "random (listing requires scan)"
    else:
        head = "random (listing requires decompression)"

    if cost.stream_capability is StreamCapability.FORWARD_ONLY:
        return f"{head}; forward-only source"
    return head
