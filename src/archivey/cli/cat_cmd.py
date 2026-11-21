"""``cat`` verb — member contents, or the decompressed outer stream, to stdout."""

from __future__ import annotations

import os
import sys
from typing import Any, BinaryIO, TextIO

from archivey import open_stream
from archivey.cli.common import (
    no_compression_layer,
    open_for_cli,
    outer_directory_error,
    refuse_outer_selection,
    reject_stdin_token,
    with_source_progress,
)
from archivey.cli.errors import CliError
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK, EXIT_USAGE
from archivey.cli.filters import MemberSelection
from archivey.cli.format import (
    escape_member_name,
    format_error_detail,
)
from archivey.cli.password import resolve_password
from archivey.cli.progress import ProgressCallback, make_progress_callback
from archivey.cli.sources import (
    http_error_type,
    is_remote,
    resolve_archive,
    shown_archive,
)
from archivey.config import ArchiveyConfig, PasswordInput
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    FormatDetectionError,
)

# Bytes copied per read: large enough that the copy costs little per call, small
# enough that one chunk held in memory does not matter.
_CHUNK = 1 << 20


class _SinkWriteError(Exception):
    """A write to stdout failed: the output's fault, not the member's.

    Carries the ``OSError`` past the member-error arm in :func:`_cat_members`, which
    re-raises it for ``main()`` to report as it reports any other output error.
    """

    def __init__(self, error: OSError) -> None:
        super().__init__(error)
        self.error = error


def run_cat(
    *,
    archive: str,
    patterns: list[str],
    exclude: list[str],
    outer: bool,
    verbose: bool,
    password: str | None,
    track_io: bool,
    sink: BinaryIO,
    stdin: BinaryIO | None = None,
    hide_progress: bool = False,
    config: ArchiveyConfig | None = None,
    err: TextIO | None = None,
) -> int:
    """Write member contents, or with ``outer`` the decompressed stream, to ``sink``.

    A status line on ``err`` shows the reads of the archive's file until the first
    member byte is written, so it never mixes with the output on a terminal or under a
    pager. ``archive`` ``-`` reads from ``stdin``. Bytes reach ``sink`` as they are read, so
    some or all of a member's bytes may already have been written when a digest
    mismatch is found: the run then exits ``1`` with the error on ``err``, as ``zcat``
    does.
    """
    err = err if err is not None else sys.stderr
    if archive == "-" and stdin is None:
        # fd 0 closed or detached: the other verbs' "pass /dev/stdin" hint would not
        # help, since there is no standard input behind that path either.
        raise CliError("no standard input to read the archive from", code=EXIT_USAGE)
    if outer:
        refuse_outer_selection(patterns, exclude, verb="writes")
        if track_io:
            raise CliError(
                "--track-io counts member reads; it does not apply with --outer",
                code=EXIT_USAGE,
            )
    progress = make_progress_callback(hide_progress=hide_progress, stream=err)
    if progress is not None:
        # Every stderr line, log lines included, clears the status line first.
        err = progress.guard(err)
    if outer:
        return _cat_outer(
            archive, sink=sink, stdin=stdin, config=config, progress=progress
        )
    return _cat_members(
        archive,
        patterns=patterns,
        exclude=exclude,
        verbose=verbose,
        password=password,
        track_io=track_io,
        sink=sink,
        stdin=stdin,
        config=config,
        err=err,
        progress=progress,
    )


def _cat_outer(
    archive: str,
    *,
    sink: BinaryIO,
    stdin: BinaryIO | None,
    config: ArchiveyConfig | None,
    progress: ProgressCallback | None,
) -> int:
    if archive == "-" and stdin is not None:
        source: Any = stdin
        shown = "stdin"
    else:
        reject_stdin_token(archive)
        source = resolve_archive(archive)
        shown = shown_archive(archive)
        if not is_remote(archive) and os.path.isdir(archive):
            # The library refuses a directory too (caught below), but its message
            # points at open_archive(); this one names the CLI's view of it.
            raise outer_directory_error(shown)
    try:
        try:
            stream = open_stream(source, config=with_source_progress(config, progress))
        finally:
            # Before the first byte goes out.
            if progress is not None:
                progress.close()
    except ArchiveyUsageError as exc:
        # Not an ArchiveyError, so main() would not catch it: a usage exit instead.
        raise CliError(f"--outer: {exc}", code=EXIT_USAGE) from exc
    except FormatDetectionError as exc:
        fmt = exc.source_format
        if fmt is None:
            raise
        # Detection found a container (ZIP, 7z, a plain tar): the library's message
        # names open_archive, which a CLI user reaches by leaving the flag out.
        raise no_compression_layer(shown, fmt, verb="write") from exc
    try:
        with stream:
            _copy(stream, sink)
    except _SinkWriteError as exc:
        raise exc.error from None
    return EXIT_OK


def _cat_members(
    archive: str,
    *,
    patterns: list[str],
    exclude: list[str],
    verbose: bool,
    password: str | None,
    track_io: bool,
    sink: BinaryIO,
    stdin: BinaryIO | None,
    config: ArchiveyConfig | None,
    err: TextIO,
    progress: ProgressCallback | None,
) -> int:
    pwd: PasswordInput = resolve_password(password)
    selection = MemberSelection(patterns, exclude)
    with open_for_cli(
        archive,
        password=pwd,
        track_io=track_io,
        config=config,
        stdin=stdin,
        err=err,
        progress=progress,
    ) as reader:
        indexed = reader.members_report_if_available()
        if indexed is not None:
            # Judge the patterns before writing anything when the index is free, so
            # a pattern that matches nothing fails before any bytes reach stdout.
            if progress is not None:
                progress.close()
            selection.settle_from(indexed, err=err)
            if selection.settled and selection.selects_nothing:
                return EXIT_FAIL
        # The ``with`` ends the pass here, whatever leaves the loop (a member error,
        # a closed stdout), rather than leaving it suspended for ``reader.close()``.
        with reader.stream_members(selection.predicate) as it:
            for member, stream in it:
                if progress is not None:
                    # Before the first line or byte goes out.
                    progress.close()
                if stream is None or member.is_dir:
                    # Directories, links and other entries have no body of their
                    # own. A pass reads forward only, so a link's target, an earlier
                    # member, cannot be read again for it. A directory that declares
                    # data gets a stream, but its bytes are not file content: the
                    # pass closes the stream unread when it advances.
                    if verbose:
                        print(f"skip {escape_member_name(member.name)}", file=err)
                    continue
                if verbose:
                    print(escape_member_name(member.name), file=err)
                try:
                    with stream:
                        _copy(stream, sink)
                except _SinkWriteError as exc:
                    # stdout failed (a closed pipe, a full disk): main() reports it,
                    # and exits 141 for a closed pipe.
                    raise exc.error from None
                except (ArchiveyError, OSError, http_error_type()) as exc:
                    # The concatenated output is already wrong past this point, so
                    # stop rather than go on writing the next members after it.
                    print(
                        f"archivey: {escape_member_name(member.name)}: "
                        f"{format_error_detail(exc)}",
                        file=err,
                    )
                    return EXIT_FAIL
        if not selection.settled and selection.report(err=err):
            return EXIT_FAIL
    return EXIT_OK


def _copy(stream: BinaryIO, sink: BinaryIO) -> None:
    # Not shutil.copyfileobj: a failed write must be told apart from a failed read.
    while chunk := stream.read(_CHUNK):
        try:
            sink.write(chunk)
        except OSError as exc:
            raise _SinkWriteError(exc) from exc
    try:
        sink.flush()
    except OSError as exc:
        raise _SinkWriteError(exc) from exc
