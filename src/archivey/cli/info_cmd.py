"""``info`` / ``i`` / ``detect`` verb — format detection + archive identity."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from archivey import FormatInfo, detect_format, open_archive
from archivey.cli.common import is_read_once, read_once_refusal, reject_stdin_token
from archivey.cli.format import (
    escape_path,
    format_access_summary,
    format_error_detail,
    format_field_value,
    format_format_label,
)
from archivey.cli.password import resolve_password
from archivey.config import ArchiveyConfig, PasswordInput
from archivey.cost import CostReceipt
from archivey.exceptions import ArchiveyError
from archivey.terminal import escape_control_chars
from archivey.types import ArchiveFormat


def _format_label(fmt: ArchiveFormat) -> str:
    return format_format_label(fmt)


def _field(key: str, text: str, out: TextIO) -> None:
    """Print one ``key: value`` line; ``text`` must already be terminal-safe."""
    print(f"{key + ':':<12} {text}", file=out)


def _line(key: str, value: object, out: TextIO) -> None:
    """Print one ``key: value`` line, escaping the value.

    Every value is escaped, not only the ones known to come from the archive today.
    The comment is the obvious one — arbitrary bytes, up to 64 KiB in a ZIP — but the
    version string and the ``extra`` bag are archive- or backend-derived too, and an
    escape costs nothing on the enums, booleans and integers that make up the rest.
    The value goes through :func:`~archivey.cli.format.format_field_value`, which
    ``list --details`` uses too, so ``bytes`` print as ``hex:<digits>`` in both.
    The key is escaped as well: ``extra.<key>`` names come from the open ``extra`` bag.

    Two values do not go through here. The archive path goes through
    :func:`~archivey.cli.format.escape_path`, which renders it ``/``-separated
    first so a Windows path's separators are not doubled; and an exception goes
    through :func:`~archivey.cli.format.format_error_detail`, because archivey's own
    exceptions have already escaped their message.
    """
    _field(escape_control_chars(key), format_field_value(value), out)


def _print_cost_axes(cost: CostReceipt, out: TextIO) -> None:
    """Verbose breakdown of the three CostReceipt axes (plus solid_block_count)."""
    _line("listing", cost.listing_cost.value, out)
    _line("access_cost", cost.access_cost.value, out)
    _line("stream", cost.stream_capability.value, out)
    blocks = cost.solid_block_count
    _line("solid_blocks", blocks if blocks is not None else "-", out)
    for note in cost.notes:
        _line("cost_note", note, out)


def _print_identity(archive: str, detected: FormatInfo, out: TextIO) -> None:
    _field("path", escape_path(archive), out)
    _line("format", _format_label(detected.format), out)
    _line("confidence", detected.confidence.value, out)
    _line("detected_by", detected.detected_by, out)
    if detected.payload_offset:
        # Printed under its older name, which output parsers may match on: any
        # prefix, not only a self-extractor's stub (FormatInfo.payload_offset).
        _line("sfx_offset", detected.payload_offset, out)


def _can_reread(path: str) -> bool:
    """Whether opening ``path`` again reads the same bytes.

    False for a FIFO, a character device or a socket, the same set that
    ``ArchiveSource.for_path`` treats as non-seekable; a block device rereads fine.
    Also false for a path that cannot be stat'ed, which the existence check is for:
    ``is_read_once`` reports ``False`` for such a path, so without the check it would
    count as rereadable and detection would run on a path the open already failed on.
    """
    return os.path.exists(path) and not is_read_once(path)


def run_info(
    *,
    archive: str,
    password: str | None,
    track_io: bool,
    verbose: bool,
    config: ArchiveyConfig | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    reject_stdin_token(archive)
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    if track_io:
        print("track-io: n/a for info (no member-body decode)", file=err)

    pwd: PasswordInput = resolve_password(password)
    identity_printed = False
    # A read-once path opens in streaming mode, as in the other verbs: nothing below
    # needs random access, and a random-access open of a pipe always fails.
    streaming = is_read_once(archive)
    try:
        with open_archive(
            archive, password=pwd, streaming=streaming, config=config
        ) as reader:
            # The open already detected the format; print what it found rather than
            # detecting a second time. No format= is passed, so it is never None.
            detected = reader.format_info
            assert detected is not None
            _print_identity(archive, detected, out)
            identity_printed = True
            info = reader.info
            _line("version", info.format_version or "-", out)
            _line("solid", info.is_solid, out)
            _line("access", format_access_summary(info.cost), out)
            if verbose:
                _print_cost_axes(info.cost, out)
            _line("encrypted", info.is_encrypted, out)
            _line("multivolume", info.is_multivolume, out)
            _line(
                "members",
                info.member_count if info.member_count is not None else "-",
                out,
            )
            if info.comment:
                _line("comment", info.comment, out)
            if verbose and info.extra:
                for key, value in sorted(info.extra.items()):
                    _line(f"extra.{key}", value, out)
    except ArchiveyError as exc:
        # When the open itself failed, identity comes from detection alone: printed
        # when the format was recognised (the open error is still a failure), and when
        # it was not, detection's own error is the one to report. Detection opens the
        # path again, so it is skipped for a pipe, a character device or a socket: those
        # are read once, so a second open gets different bytes or waits for a writer
        # that never comes.
        if not identity_printed and _can_reread(archive):
            _print_identity(archive, detect_format(archive, config=config), out)
        refusal = read_once_refusal(archive, exc, streaming=streaming)
        if refusal is not None:
            _field("open", escape_control_chars(refusal), err)
        else:
            _field("open", format_error_detail(exc), err)
        return 1
    return 0
