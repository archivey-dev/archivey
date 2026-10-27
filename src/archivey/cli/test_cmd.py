"""``test`` / ``t`` verb — full-read integrity check."""

from __future__ import annotations

import sys
from typing import TextIO, cast

from archivey import ArchiveReader, ExtractionProgress
from archivey.cli.common import open_for_cli, outer_format_for
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK
from archivey.cli.filters import MemberSelection
from archivey.cli.format import escape_member_name, format_error_detail
from archivey.cli.logging_config import cli_opens_members
from archivey.cli.password import resolve_password
from archivey.cli.progress import ProgressCallback, make_progress_callback
from archivey.config import ArchiveyConfig, PasswordInput
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    LinkTargetNotFoundError,
    PackageNotInstalledError,
    ReadError,
    UnsupportedFeatureError,
)
from archivey.types import ArchiveMember, MemberType

# Codes saying a digest went unchecked: the bytes were read but nothing confirmed them,
# so the run is not a clean verification (X6). Archive-level digests count too, such as
# a gzip trailer past the trailing-data scan bound.
_UNVERIFIED_CODES = (
    DiagnosticCode.DIGEST_UNVERIFIABLE,
    DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED,
)


def run_test(
    *,
    archive: str,
    patterns: list[str],
    exclude: list[str],
    verbose: bool,
    password: str | None,
    track_io: bool,
    config: ArchiveyConfig | None = None,
    hide_progress: bool = False,
    outer: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    del out  # test writes summaries to stderr only
    err = err if err is not None else sys.stderr
    pwd: PasswordInput = resolve_password(password)
    selection = MemberSelection(patterns, exclude)
    pred = selection.predicate

    ok = 0
    failed = 0
    members_total: int | None = None
    # --outer tests the compression layer alone, as gzip -t does: the one member is
    # the whole decompressed stream, checked against the codec's own trailer.
    fmt = (
        outer_format_for(archive, patterns, exclude, config=config, verb="test")
        if outer
        else None
    )
    with open_for_cli(
        archive,
        password=pwd,
        track_io=track_io,
        config=config,
        err=err,
        format=fmt,
    ) as reader:
        indexed = reader.members_report_if_available()
        total_bytes: int | None = None
        if indexed is not None:
            # A complete free index settles the patterns before the run. One that ends
            # in damage settles nothing, but its members still give the totals. When
            # the patterns are not settled, the run's own pass offers each member to
            # them (see the end of the pass).
            selected = selection.settle_from(indexed, err=err)
            if selection.settled and selection.selects_nothing:
                return EXIT_FAIL
            file_members = [m for m in selected if _has_data(m)]
            members_total = len(file_members)
            sizes = [m.size for m in file_members if m.size is not None]
            if len(sizes) == len(file_members):
                total_bytes = sum(sizes)

        on_progress: ProgressCallback | None = make_progress_callback(
            hide_progress=hide_progress, stream=err
        )
        bytes_done = 0
        files_done = 0
        pending_links: list[ArchiveMember] = []
        untested_dirs = 0
        pass_ended_early = False
        # The error the member read that just ran raised, or None once the pass yields
        # another member. A pass that raises right after a failed member read is
        # ending on the fault that member already reported, whether it raises the same
        # object (a truncated compressed TAR) or a new, equal one (a truncated plain
        # TAR): it gets a stop notice and is not counted a second time. Requiring the
        # failure to be the immediately preceding read is safe: a stream that re-raises
        # a parked fault fails the next read as well, so no member reads cleanly
        # between the failure and the end of the pass.
        member_error: BaseException | None = None
        try:
            # Manual iteration so open-time failures (wrong password, corrupt header)
            # count as FAIL and still reach the summary (F4). A member's data error is
            # raised from its own stream read and the pass goes on, solid archives
            # included. Of the damage cases, only damage to the archive's structure (a
            # cut TAR, a failed compressed TAR stream, a pipe ZIP whose local-header
            # walk loses its place) makes the pass raise; so can non-damage errors such
            # as a ListingLimits bound. Further next() then yields StopIteration and
            # the remaining members are reported "not tested" (P8).
            # The ``with`` ends the pass here, deterministically, whatever leaves the
            # loop (Ctrl-C, a broken stderr pipe), rather than leaving a suspended
            # pass for ``reader.close()`` or the garbage collector to end while the
            # error travels up to ``main()``.
            with reader.stream_members(pred) as it:
                while True:
                    try:
                        member, stream = next(it)
                    except StopIteration:
                        break
                    except (ArchiveyError, OSError) as exc:
                        pass_ended_early = True
                        if member_error is None:
                            failed += 1
                            print(f"FAIL: {format_error_detail(exc)}", file=err)
                        else:
                            if not _same_fault(exc, member_error):
                                print(f"archivey: {format_error_detail(exc)}", file=err)
                            print(
                                "test stopped; remaining members were not tested",
                                file=err,
                            )
                        continue
                    member_error = None

                    if stream is None and _link_needs_verification(member):
                        # Verified after the pass: the reader refuses an open() while
                        # stream_members() is running.
                        pending_links.append(member)
                        continue
                    if stream is None:
                        # No data to verify: a link, a special entry, a tombstone, a
                        # directory that declares no data, or a bit-3 ZIP directory
                        # read from a pipe, whose size arrives after its data. Left
                        # out of the counts. A directory that declares data gets a
                        # stream and is read like a file, as `unzip -t` tests it.
                        if verbose:
                            print(f"skip {escape_member_name(member.name)}", file=err)
                        continue
                    member_written = 0
                    try:
                        with stream:
                            while True:
                                chunk = stream.read(1024 * 1024)
                                if not chunk:
                                    break
                                n = len(chunk)
                                member_written += n
                                bytes_done += n
                                if on_progress is not None:
                                    on_progress(
                                        ExtractionProgress(
                                            member=member,
                                            bytes_written=bytes_done,
                                            total_bytes_estimated=total_bytes,
                                            members_done=files_done,
                                            members_total=members_total,
                                            member_bytes_written=member_written,
                                            members_extracted=0,
                                            members_blocked=0,
                                        )
                                    )
                        ok += 1
                        files_done += 1
                        if on_progress is not None:
                            on_progress(
                                ExtractionProgress(
                                    member=member,
                                    bytes_written=bytes_done,
                                    total_bytes_estimated=total_bytes,
                                    members_done=files_done,
                                    members_total=members_total,
                                    member_bytes_written=member_written,
                                    members_extracted=0,
                                    members_blocked=0,
                                )
                            )
                        if verbose:
                            print(f"OK   {escape_member_name(member.name)}", file=err)
                    except BrokenPipeError:
                        # The -v line or the progress bar lost its reader: not a
                        # member failure. main() exits 141 for it, with no message.
                        raise
                    except (UnsupportedFeatureError, PackageNotInstalledError) as exc:
                        if not member.is_dir:
                            failed += 1
                            member_error = exc
                            print(
                                f"FAIL {escape_member_name(member.name)}: "
                                f"{format_error_detail(exc)}",
                                file=err,
                            )
                            continue
                        # A directory's data archivey cannot decode is not tested
                        # rather than failed (DR-4), as `unzip -t` skips it: the
                        # archive extracts in full, since the bytes are never written.
                        # A body that needs a password is an EncryptionError and stays
                        # a failure, as for a file. Recorded so that a pass ending on
                        # this fault gets the stop notice, not a second count.
                        untested_dirs += 1
                        member_error = exc
                        print(
                            f"skip {escape_member_name(member.name)}: "
                            f"{format_error_detail(exc)}",
                            file=err,
                        )
                    except (ArchiveyError, OSError) as exc:
                        failed += 1
                        member_error = exc
                        print(
                            f"FAIL {escape_member_name(member.name)}: "
                            f"{format_error_detail(exc)}",
                            file=err,
                        )
        finally:
            if on_progress is not None:
                on_progress.close()

        # Decided only now: a 7z or RAR4 link's target is member data the pass reads
        # at its end, in either reader mode, so which links need this is known only
        # once the pass is over. A target the pass read was checked by that read, as
        # listing checks a ZIP link's, and the link is skipped like a ZIP link. Only a
        # link the pass could not read a target for is opened again here.
        unverified: list[ArchiveMember] = []
        for link in pending_links:
            if _link_needs_verification(link):
                unverified.append(link)
            elif verbose:
                print(f"skip {escape_member_name(link.name)}", file=err)
        if members_total is not None:
            members_total += len(unverified)
        for link in unverified:
            try:
                # Only 7z and RAR4 leave a link to verify, and neither opens in the
                # streaming mode the CLI uses for a pipe, so ``reader`` is open for
                # random access here. The cast states that for the type checker only.
                # If that stops holding, ``open()`` on the streaming reader raises
                # ``ArchiveyUsageError``, which is caught here so the link counts as
                # a FAIL instead of ending the run with a traceback.
                with cli_opens_members():
                    _verify_link(cast(ArchiveReader, reader), link)
            except (ArchiveyError, ArchiveyUsageError, OSError) as exc:
                failed += 1
                print(
                    f"FAIL {escape_member_name(link.name)}: {format_error_detail(exc)}",
                    file=err,
                )
            else:
                ok += 1
                if verbose:
                    print(f"OK   {escape_member_name(link.name)}", file=err)

        # Without a complete index, the pass that just ran offered every member to the
        # patterns. Only the generator raising ends that pass early and leaves later
        # members unseen; a failure inside one member's read does not. So the
        # patterns are judged after any pass that reached its end.
        if not selection.settled and not pass_ended_early and selection.report(err=err):
            return EXIT_FAIL

        # Read before the reader closes; each such diagnostic was already logged with
        # its reason, so the summary only counts them.
        counts = reader.diagnostics.counts
        not_verified = sum(counts.get(code, 0) for code in _UNVERIFIED_CODES)
        if untested_dirs and members_total is None:
            # No index counted them in advance: count the skipped directories here,
            # so they show as not tested either way.
            members_total = ok + failed + untested_dirs

    print(
        _test_summary(
            ok=ok,
            failed=failed,
            members_total=members_total,
            not_verified=not_verified,
        ),
        file=err,
    )
    # An untested remainder or an unchecked digest is an incomplete verification.
    not_tested = _not_tested(ok=ok, failed=failed, members_total=members_total)
    return EXIT_FAIL if failed or not_tested or not_verified else EXIT_OK


def _has_data(member: ArchiveMember) -> bool:
    """Whether a pass is expected to yield a stream for ``member``: a file, or a
    directory whose header declares data (``MEMBER_DIRECTORY_DATA_IGNORED``).

    A copy of ``archivey.internal.base_reader.pass_has_data``, which every backend
    pass calls; the CLI uses only the public API. Keep the two in step, or
    ``members_total`` mispredicts the pass and the summary shows a false "not tested".
    The indexed total it feeds never meets that function's one exception, a bit-3 ZIP
    directory from a pipe, because a pipe has no index.
    """
    return member.is_file or (member.is_dir and bool(member.size))


def _same_fault(exc: BaseException, reported: BaseException) -> bool:
    """Whether ``exc`` reports the same fault as ``reported``, already printed.

    The member name is left out of the comparison: a pass that re-raises a member's
    fault builds its error without one.
    """
    if exc is reported:
        return True
    if type(exc) is not type(reported):
        return False
    if isinstance(exc, ArchiveyError) and isinstance(reported, ArchiveyError):
        return (exc.message, exc.archive_name, exc.source_format) == (
            reported.message,
            reported.archive_name,
            reported.source_format,
        )
    return str(exc) == str(reported)


def _link_needs_verification(member: ArchiveMember) -> bool:
    """Whether ``member`` is a symlink whose stored target has not been read cleanly.

    A ZIP, 7z or RAR4 symlink keeps its target in the member's data. Listing reads and
    checks that data, so a link listed with a target has passed its check. A link
    listed without one either records no target at all
    (``ArchiveMember.link_target_unrecorded``: not a fault, and ``extract`` reports it
    as ``LINK_TARGET_UNAVAILABLE``) or has a target that the read could not produce:
    damaged, encrypted, or out of reach. ``extract`` fails the second kind, so ``test``
    does too.
    """
    return (
        member.type is MemberType.SYMLINK
        and member.link_target is None
        and not member.link_target_unrecorded
    )


def _verify_link(reader: ArchiveReader, member: ArchiveMember) -> None:
    """Read ``member``'s stored target again, raising what the read raises.

    ``open()`` reads a link's target before it follows the link, and that read raises
    the fault that listing only reported. Once the target is read, the rest is about
    where the link points, not about this member's data: a target outside the archive,
    a link cycle, or a directory is not a fault, and a target inside it is verified as
    a member of its own. Those errors are the only ones ignored; any other error is
    raised, such as a target member that cannot be decoded.
    """
    try:
        reader.open(member).close()
    except (ReadError, ArchiveyUsageError) as exc:
        # ``open()`` sets ``link_target`` once it has read the stored target, so a
        # target still ``None`` means the error came from this member's own data.
        if member.link_target is None or not _is_link_destination_error(exc):
            raise


def _is_link_destination_error(exc: ReadError | ArchiveyUsageError) -> bool:
    """Whether ``exc``, raised by ``open()`` after it read the link's own target, is
    about where the link points rather than about any data.

    A target that names no member, or a chain of links that loops, is a
    ``LinkTargetNotFoundError``. A link that resolves to a directory, an anti-item or
    an OTHER member is a usage error that carries ``refused_member_type``: ``open()``
    refuses to return bytes for it. Any other usage error is raised.
    """
    if isinstance(exc, LinkTargetNotFoundError):
        return True
    return isinstance(exc, ArchiveyUsageError) and exc.refused_member_type is not None


def _not_tested(*, ok: int, failed: int, members_total: int | None) -> int:
    """Untested remainder of an indexed selection; ``0`` when unknown or none (P8).

    The summary line and the exit code both read this, so they cannot disagree.
    """
    if members_total is None:
        return 0
    return max(members_total - ok - failed, 0)


def _test_summary(
    *, ok: int, failed: int, members_total: int | None, not_verified: int = 0
) -> str:
    """Format the quiet test summary, with the untested remainder (P8) and unchecked
    digests (X6) when there are any.
    """
    summary = f"{ok} OK, {failed} failed"
    not_tested = _not_tested(ok=ok, failed=failed, members_total=members_total)
    if not_tested:
        summary += f", {not_tested} not tested"
    if not_verified:
        summary += f", {not_verified} not verified"
    return summary
