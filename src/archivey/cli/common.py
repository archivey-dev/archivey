"""Shared open / track-io helpers for CLI verbs."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO, TextIO

from archivey import detect_format, open_archive
from archivey.cli.errors import CliError
from archivey.cli.exit_codes import EXIT_USAGE
from archivey.cli.format import format_format_label
from archivey.config import DEFAULT_ARCHIVEY_CONFIG, ArchiveyConfig, PasswordInput
from archivey.exceptions import StreamNotSeekableError

# The one internal import in the CLI, allowlisted in tests/test_cli_uses_public_api.py:
# --track-io is a debugging aid for the library, and IO measurement is not public API.
from archivey.internal.measurement import enable_measurement, io_stats
from archivey.reader import ForwardArchiveReader
from archivey.terminal import display_path
from archivey.types import ArchiveFormat, ContainerFormat, StreamFormat


def reject_stdin_token(archive: str) -> None:
    """Fail fast when ``-`` is used: the token is reserved for every verb but ``cat``.

    A pipe on stdin is still readable through its path, ``/dev/stdin``, which
    :func:`is_read_once` treats as any other pipe, so the message names that path.
    Windows has no such path, so there the message says to copy the archive to a file.

    Also refuses the empty string, through :func:`reject_empty_path`. Call it on the
    string the user typed, before any ``Path()``: ``Path("")`` is ``Path(".")``.
    """
    reject_empty_path(archive, arg="archive")
    if archive == "-":
        # Grammar-level "not available yet" → usage exit (D7), matching reserved verbs.
        if sys.platform == "win32":
            hint = "copy the archive to a regular file and pass its path"
        else:
            hint = "to read an archive piped on stdin, pass /dev/stdin instead"
        raise CliError(
            f"the '-' token for stdin is reserved and not supported yet; {hint}",
            code=EXIT_USAGE,
        )


def outer_format(
    archive: str, *, config: ArchiveyConfig | None, verb: str
) -> ArchiveFormat:
    """The format that opens only ``archive``'s compression layer, for ``--outer``.

    A compressed tar gives its single-file format (``.tar.gz`` → GZ), so the reader
    presents the tar itself as its one member; a single compressed file is returned
    unchanged. ``verb`` completes the "leave out --outer to …" advice.
    """
    reject_stdin_token(archive)
    shown = display_path(archive)
    if os.path.isdir(archive):
        raise outer_directory_error(shown)
    if is_read_once(archive):
        # Detecting the format reads the start of the pipe, and the open after it
        # would not see those bytes again.
        raise CliError(
            f"--outer: {shown} can be read only once; use "
            f"'archivey cat --outer' to decompress a pipe",
            code=EXIT_USAGE,
        )
    # Every content probe runs, as open_stream's detection does for cat --outer: the
    # flag says the source is a compressed stream, so a probe only says which codec.
    probing = replace(config or DEFAULT_ARCHIVEY_CONFIG, always_probe_content=True)
    fmt = detect_format(archive, config=probing).format
    outer = outer_layer_format(fmt)
    if outer is None:
        raise no_compression_layer(shown, fmt, verb=verb)
    return outer


def outer_layer_format(fmt: ArchiveFormat) -> ArchiveFormat | None:
    """The single-file format of ``fmt``'s compression layer, or ``None``.

    The same rule as the library's ``outer_stream_format``, which decides what
    ``open_stream`` (and so ``cat --outer``) accepts; it is internal, so the CLI keeps
    this copy, and ``tests/test_cli_outer.py`` pins the two to the same answer for
    every ``ArchiveFormat``.
    """
    if fmt.container is ContainerFormat.RAW_STREAM:
        return fmt
    if (
        fmt.container is ContainerFormat.TAR
        and fmt.stream is not StreamFormat.UNCOMPRESSED
    ):
        return ArchiveFormat(ContainerFormat.RAW_STREAM, fmt.stream)
    return None


def refuse_outer_selection(
    patterns: list[str], exclude: list[str], *, verb: str
) -> None:
    """``--outer`` takes the whole stream: member patterns or ``--exclude`` are usage
    errors. ``verb`` is what the verb does with the stream (``writes``, ``tests``)."""
    if patterns or exclude:
        raise CliError(
            f"--outer {verb} the whole decompressed stream; it takes no member "
            "patterns or --exclude",
            code=EXIT_USAGE,
        )


def outer_format_for(
    archive: str,
    patterns: list[str],
    exclude: list[str],
    *,
    config: ArchiveyConfig | None,
    verb: str,
) -> ArchiveFormat:
    """:func:`outer_format` for ``extract`` and ``test``, which take patterns too."""
    refuse_outer_selection(patterns, exclude, verb=f"{verb}s")
    return outer_format(archive, config=config, verb=verb)


def outer_directory_error(shown: str) -> CliError:
    """The usage error for ``--outer`` on a directory, naming the CLI's view of it."""
    return CliError(
        f"--outer: {shown} is a directory, which has no compression layer",
        code=EXIT_USAGE,
    )


def no_compression_layer(shown: str, fmt: ArchiveFormat, *, verb: str) -> CliError:
    """The error for ``--outer`` on a container with nothing to decompress."""
    return CliError(
        f"--outer: {shown} is a {format_format_label(fmt)} archive, which has no "
        f"compression layer to remove; leave out --outer to {verb} its members"
    )


def reject_empty_path(value: str, *, arg: str) -> None:
    """Refuse an empty path argument as a usage error.

    ``Path("")`` is ``Path(".")``, so an unset shell variable (``"$ARCHIVE"``,
    ``-d "$OUT"``) would otherwise read or extract into the working directory. The
    library refuses an empty string too (an ``ArchiveyUsageError`` that is also a
    ``ValueError``), and the CLI turns the path into a ``Path`` before the library sees
    it; ``.`` names the cwd on purpose.
    """
    if value == "":
        raise CliError(
            f"{arg} is an empty path; pass '.' to mean the current directory",
            code=EXIT_USAGE,
        )


@contextmanager
def open_for_cli(
    archive: str | Path,
    *,
    password: PasswordInput = None,
    track_io: bool = False,
    config: ArchiveyConfig | None = None,
    stdin: BinaryIO | None = None,
    err: TextIO | None = None,
    format: ArchiveFormat | None = None,
) -> Generator[ForwardArchiveReader, None, None]:
    """Open an archive, optionally wrapping the call in measurement for ``--track-io``.

    A path that can be read only once (see :func:`is_read_once`) opens in streaming
    mode: the user cannot choose the mode, so the CLI chooses the one that can work.
    Each verb then reads the archive in one forward pass. A verb that reads ``-`` from
    stdin passes the stream as ``stdin``, which opens in streaming mode as well; for
    every other verb ``-`` is refused. ``format`` skips detection, as
    ``open_archive(format=)`` does.
    """
    source: str | Path | BinaryIO
    if archive == "-" and stdin is not None:
        source, streaming = stdin, True
    else:
        reject_stdin_token(str(archive))
        source, streaming = archive, is_read_once(archive)
    err = err if err is not None else sys.stderr
    if track_io:
        with (
            enable_measurement(),
            _open(
                source,
                password=password,
                streaming=streaming,
                config=config,
                format=format,
            ) as reader,
        ):
            yield reader
            _report_track_io(reader, err)
    else:
        with _open(
            source,
            password=password,
            streaming=streaming,
            config=config,
            format=format,
        ) as reader:
            yield reader


def _open(
    archive: str | Path | BinaryIO,
    *,
    password: PasswordInput,
    streaming: bool,
    config: ArchiveyConfig | None,
    format: ArchiveFormat | None,
) -> ForwardArchiveReader:
    try:
        return open_archive(
            archive,
            format=format,
            password=password,
            streaming=streaming,
            config=config,
        )
    except StreamNotSeekableError as exc:
        shown = archive if isinstance(archive, (str, Path)) else "stdin"
        message = read_once_refusal(shown, exc, streaming=streaming)
        if message is None:
            raise
        raise CliError(message) from exc


def is_read_once(archive: str | Path) -> bool:
    """Whether ``archive`` is a FIFO, a character device or a socket.

    These are the paths that ``ArchiveSource.for_path`` treats as non-seekable: a
    second open reads different bytes, or waits for a writer that never comes. They
    include ``/dev/stdin`` and ``/proc/self/fd/N`` when that descriptor is a pipe. A
    block device rereads fine. A path that cannot be stat'ed is not read-once; the open
    reports its error.
    """
    try:
        mode = os.stat(archive).st_mode
    except OSError:
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISSOCK(mode)


def read_once_refusal(
    archive: str | Path, exc: BaseException, *, streaming: bool
) -> str | None:
    """The CLI message for a read-once path whose format needs to seek, or ``None``.

    ``None`` unless the open was in streaming mode and raised
    ``StreamNotSeekableError``: any other failure keeps its own message. The library's
    message suggests ``streaming=True`` or a ``BytesIO``, which a CLI user cannot pass;
    this one names what the user can do. The one place that makes this decision:
    ``open_for_cli`` raises the message as a ``CliError``, and ``info`` prints it as its
    ``open:`` field.

    The path is ``/``-separated here, because the caller escapes the whole message and
    an escaped native Windows path would have every separator doubled.
    """
    if not streaming or not isinstance(exc, StreamNotSeekableError):
        return None
    fmt = exc.source_format
    subject = (
        f"the {format_format_label(fmt)} format"
        if fmt is not None
        else "this archive's format"
    )
    return (
        f"{display_path(archive)}: {subject} cannot be read from a pipe or device. "
        f"It needs to seek, and a pipe or device can be read only once. Copy the "
        f"archive to a regular file first, then run archivey on that file."
    )


def _report_track_io(reader: ForwardArchiveReader, err: TextIO) -> None:
    stats = io_stats(reader)
    if stats is None:
        print("track-io: counters unavailable for this reader", file=err)
        return
    consumed_s = (
        "-"
        if stats.compressed_bytes_consumed is None
        else str(stats.compressed_bytes_consumed)
    )
    print(
        "track-io:"
        f" bytes_decompressed={stats.bytes_decompressed}"
        f" compressed_bytes_consumed={consumed_s}"
        f" source_seek_count={stats.source_seek_count}",
        file=err,
    )
