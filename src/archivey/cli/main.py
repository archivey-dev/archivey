"""``archivey`` CLI entry point: argparse grammar + verb dispatch.

:func:`main` is the console script. It wraps the output streams so a closed pipe or
an unencodable character cannot crash the run, then :func:`_parse_and_dispatch`
inserts the default ``list`` verb when none is given (:func:`_inject_default_list`),
parses the arguments with the parser :func:`build_parser` defines, and calls the
verb's ``run_*`` function from its own ``*_cmd`` module. Faults that end a run are
printed here, as ``archivey: …`` lines, and turned into exit codes
(:mod:`archivey.cli.exit_codes`).
"""

from __future__ import annotations

import argparse
import errno
import functools
import os
import sys
from collections.abc import Callable, Sequence
from enum import Enum
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    AnyStr,
    BinaryIO,
    Generic,
    NamedTuple,
    NoReturn,
    TextIO,
    TypedDict,
    cast,
)

import archivey
from archivey import (
    AbortOn,
    ArchiveyConfig,
    ExtractionPolicy,
    FormatDetectionError,
    FormatSupport,
    MissingComponent,
    OverwritePolicy,
    format_availability,
    list_known_formats,
)
from archivey.cli.cat_cmd import run_cat
from archivey.cli.choices import cli_choices
from archivey.cli.errors import CliError
from archivey.cli.exit_codes import (
    EXIT_BROKEN_PIPE,
    EXIT_FAIL,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_USAGE,
)
from archivey.cli.extract_cmd import run_extract
from archivey.cli.format import (
    escape_member_name,
    format_error_detail,
    format_format_label,
)
from archivey.cli.info_cmd import run_info
from archivey.cli.list_cmd import run_list
from archivey.cli.logging_config import cli_logging
from archivey.cli.test_cmd import run_test
from archivey.exceptions import ArchiveyError
from archivey.terminal import display_path, quoted

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

_TOP_EPILOG = """\
examples:
  archivey archive.zip                  list members
  archivey x archive.zip                extract safely (into ./archive/ if needed)
  archivey x archive.zip -d out '*.py'  extract *.py into out/
  archivey t archive.zip                verify integrity
  archivey cat archive.zip notes.txt    write a member's contents to stdout
"""

_CAT_EPILOG = """\
examples:
  archivey cat archive.zip notes.txt    write one member's contents to stdout
  archivey cat archive.tar.zst '*.log'  write every top-level .log, in archive order
  archivey cat data.tar.zst --outer     decompress only: write the tar bytes
  curl -s URL | archivey cat - --outer | tar t
"""

_EXTRACT_EPILOG = """\
examples:
  archivey x archive.zip                extract safely (into ./archive/ if needed)
  archivey x archive.zip -d out         extract into out/ (use -d . for cwd)
  archivey x archive.zip '*.py'         extract matching members only
  archivey x archive.zip --exclude 't*' extract all except exclude patterns
  archivey x archive.zip --dry-run      run every check and read, write nothing
  archivey x data.tar.zst --outer       decompress only: write data.tar
"""

# Classic tar-style flag spellings that are not options here (verbs are bare words).
_VERB_FLAG_HINTS = {
    "-x": "x",
    "-l": "l",
    "-t": "t",
    "-i": "i",
}
# Letters a tar flag bundle is made of: the verb letters above, tar's lowercase
# modifiers (-v, -f, the -z/-j/-J/-a compressors, -k, -p, -m, -h) and GNU tar's
# uppercase short options (-Z compress, -C, -O, -P, -S, -W and the rest). Other
# lowercase letters stay out so a mistyped long option (``-exclude``) is no bundle.
_TAR_BUNDLE_LETTERS = frozenset("xltivfzjJakpmh" + "ABCFGKLMNOPRSTUVWXZ")


# The include-pattern positional's metavar; ``_ArchiveyArgumentParser.error`` matches it.
_PATTERNS_METAVAR = "pattern"


def _inject_default_list(argv: list[str]) -> list[str]:
    """If the first positional is not a known verb, insert ``list`` (known-verb-wins)."""
    grammar = _grammar()
    i = 0
    skip_next = False
    while i < len(argv):
        if skip_next:
            skip_next = False
            i += 1
            continue
        tok = argv[i]
        if tok == "--":
            # Everything after ``--`` is a positional, so no verb can follow it: the
            # default verb goes ahead of the separator (``list -- -weird.zip``).
            return argv[:i] + ["list"] + argv[i:]
        # Bare "-" is the stdin positional (read by cat, reserved for the other
        # verbs), not an option (F6).
        if tok.startswith("-") and tok != "-":
            key = tok.split("=", 1)[0]
            # Only the main parser's own options (today just ``--password``): before
            # the verb argparse does not know a verb's options, so it does not consume
            # their value, and skipping it would blame that value as a bad verb.
            if key in grammar.value_options and "=" not in tok:
                skip_next = True
            i += 1
            continue
        if tok not in grammar.verbs:
            return argv[:i] + ["list"] + argv[i:]
        return argv
    return argv


class _Grammar(NamedTuple):
    """What the default-verb injection and the usage errors read from the parser."""

    # Every verb word: aliases and reserved verbs too.
    verbs: frozenset[str]
    # The main parser's own value-taking options (see ``_inject_default_list``).
    value_options: frozenset[str]
    # A verb-only option → the verbs that take it.
    verb_options: dict[str, tuple[str, ...]]


@functools.cache
def _grammar() -> _Grammar:
    parser = build_parser()
    main_actions = [a for a in parser._actions if a.option_strings]
    shared = {opt for a in main_actions for opt in a.option_strings}
    value_options = frozenset(
        opt for a in main_actions if a.nargs != 0 for opt in a.option_strings
    )
    sub = cast(
        "argparse._SubParsersAction[argparse.ArgumentParser]",
        next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)),
    )
    owners: dict[str, list[str]] = {}
    seen: set[int] = set()
    for verb, verb_parser in sub.choices.items():
        if id(verb_parser) in seen:  # an alias: the verb's name came first
            continue
        seen.add(id(verb_parser))
        for action in verb_parser._actions:
            for opt in set(action.option_strings) - shared:
                owners.setdefault(opt, []).append(verb)
    verb_options = {opt: tuple(verbs) for opt, verbs in owners.items()}
    return _Grammar(frozenset(sub.choices), value_options, verb_options)


class _ArchiveyArgumentParser(argparse.ArgumentParser):
    """argparse tweaks for product-facing error messages (P12 / P13)."""

    def error(self, message: str) -> NoReturn:
        # bpo-26240: nargs='*' positionals are wrongly listed as required. argparse
        # names them by metavar, so drop the include-pattern one by that name.
        required = "the following arguments are required: "
        if message.startswith(required):
            names = message[len(required) :].split(", ")
            kept = [name for name in names if name != _PATTERNS_METAVAR]
            message = required + ", ".join(kept or names)
        unrecognized = "unrecognized arguments: "
        if message.startswith(unrecognized):
            message += _unrecognized_hints(message[len(unrecognized) :].split())
        super().error(message)

    def _print_message(
        self, message: str, file: SupportsWrite[str] | None = None
    ) -> None:
        # argparse drops an OSError from writing help or usage, so a reader that
        # closed the pipe would see exit 0 or 2 for output it never got. Let a
        # broken pipe reach main(), which exits 141 for it.
        if message:
            try:
                (file or sys.stderr).write(message)
            except OSError as exc:
                if _is_dead_pipe(exc):
                    raise _as_broken_pipe(exc) from exc
            except AttributeError:
                pass


def _unrecognized_hints(tokens: list[str]) -> str:
    """Hints for unrecognized options: a tar-style verb flag, a verb's own flag."""
    opts = [tok.split("=", 1)[0] for tok in tokens]
    hints = ""
    # Tar users type -x/-l/-t, often bundled (-xvf, -zxf); verbs here are bare words.
    # Only a single-dash bundle of tar letters counts, so ``--my-list`` is not ``-l``
    # and a mistyped long option such as ``-exclude`` or ``-file`` is not ``-x``/``-i``.
    # A bundle is one letter (``-x``) or names the archive with ``f`` (``-xvf``), so a
    # word such as ``-max`` or ``-tail`` gets no hint either.
    bundles = [
        o[1:]
        for o in opts
        if len(o) > 1
        and o[0] == "-"
        and set(o[1:]) <= _TAR_BUNDLE_LETTERS
        and (len(o) == 2 or "f" in o[1:])
    ]
    flags = [f"-{ch}" for bundle in bundles for ch in bundle]
    verb = next((_VERB_FLAG_HINTS[f] for f in flags if f in _VERB_FLAG_HINTS), None)
    if verb is not None:
        hints += f" (verbs are bare words — try 'archivey {verb} ARCHIVE')"
    # Name the owning verb only: the flag may already follow some other verb.
    verb_options = _grammar().verb_options
    for opt in opts:
        if opt in verb_options:
            verbs = verb_options[opt]
            owners = ", ".join(f"'{verb}'" for verb in verbs)
            where = (
                f"after that verb: archivey {verbs[0]} ARCHIVE {opt} ..."
                if len(verbs) == 1
                else "after one of those verbs"
            )
            hints += f" ({opt} is an option of {owners}; it goes {where})"
            break
    return hints


def _common_parent(*, suppress_defaults: bool) -> _ArchiveyArgumentParser:
    """Shared flags available before or after the verb.

    Build *two* instances (see ``build_parser``): the top-level copy carries real
    defaults; the subparser copy uses ``SUPPRESS`` so an absent post-verb flag cannot
    clobber a value the main parser already set (argparse shared-parents pitfall).
    """
    p = _ArchiveyArgumentParser(add_help=False, allow_abbrev=False)
    default_none: object = argparse.SUPPRESS if suppress_defaults else None
    default_false: object = argparse.SUPPRESS if suppress_defaults else False
    p.add_argument(
        "--password",
        default=default_none,
        help="archive password (prefer a TTY prompt; visible in process lists)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=default_false,
        help="more detail (per-member test/extract lines; list diagnostics)",
    )
    p.add_argument(
        "--hide-progress",
        action="store_true",
        default=default_false,
        help="suppress progress bars even when tqdm is installed",
    )
    p.add_argument(
        "--track-io",
        action="store_true",
        default=default_false,
        help=(
            "report decode/seek accounting "
            "(bytes decompressed, compressed consumed, seeks)"
        ),
    )
    p.add_argument(
        "--probe-content",
        action="store_true",
        default=default_false,
        help=(
            "recognise a raw LZMA, zlib or Brotli stream by trial-decoding it, "
            "whatever the file is named (off by default: random files can pass)"
        ),
    )
    # Pre-verb globals include reserved --salvage so it gets the same "not yet"
    # message as post-verb (P13), not argparse's "unrecognized arguments".
    p.add_argument(
        "--salvage",
        action="store_true",
        default=default_false,
        help="reserved: best-effort reads (not implemented yet)",
    )
    return p


def _cli_spelling(enum_cls: type[Enum]) -> Callable[[str], str]:
    """Build the ``type=`` fold that lets this CLI accept the library's spellings.

    argparse applies ``type=`` before checking ``choices=``, so this is what lets
    ``--abort-on blocked_member`` through: the library takes either separator and any
    case, and the CLI should not be the narrower of the two.

    The fold applies **only when it lands on a real choice**. argparse quotes the
    post-``type=`` value in ``invalid choice:``, so a fold applied to every value would
    make a refusal echo a string the caller never wrote: ``--policy Trusted_`` would be
    refused as ``'trusted-'``, a spelling that is not legal anywhere, sending the reader
    after a trailing dash they did not type. Passing an unrecognised value through
    untouched keeps the message about what they actually typed.
    """
    choices = cli_choices(enum_cls)

    def fold(value: str) -> str:
        folded = value.strip().lower().replace("_", "-")
        return folded if folded in choices else value

    return fold


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "patterns",
        nargs="*",
        metavar=_PATTERNS_METAVAR,
        help=(
            "glob include patterns: * stays in a folder, ** matches any depth, a "
            "matching folder brings its contents (omit to select all members)"
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "glob exclude pattern, matched like the includes (repeatable; exclude "
            "wins over include)"
        ),
    )


class _Common(TypedDict):
    """The keyword arguments every verb's ``run_*`` takes."""

    archive: str
    password: str | None
    track_io: bool
    verbose: bool
    config: ArchiveyConfig | None
    out: TextIO
    err: TextIO


# A verb's runner: the parsed args plus the shared kwargs, to an exit code.
_Runner = Callable[[argparse.Namespace, _Common], int]


class _Selection(TypedDict):
    """Member-selection kwargs of the verbs that read members."""

    patterns: list[str]
    exclude: list[str]


def _selection(args: argparse.Namespace) -> _Selection:
    return _Selection(patterns=list(args.patterns), exclude=list(args.exclude))


# The runners look their run_* up by name when called, so tests can patch it.
def _run_list(args: argparse.Namespace, common: _Common) -> int:
    return run_list(
        **common,
        **_selection(args),
        digests=bool(args.digests),
        long=bool(args.long),
        details=bool(args.details),
    )


def _run_test(args: argparse.Namespace, common: _Common) -> int:
    hide_progress = bool(args.hide_progress)
    return run_test(
        **common,
        **_selection(args),
        hide_progress=hide_progress,
        outer=bool(args.outer),
    )


def _run_extract(args: argparse.Namespace, common: _Common) -> int:
    return run_extract(
        **common,
        **_selection(args),
        dest=args.dest,
        policy=args.policy,
        overwrite=args.overwrite,
        hide_progress=bool(args.hide_progress),
        stop_on_error=bool(args.stop_on_error),
        abort_on=list(args.abort_on or ()),
        dry_run=bool(args.dry_run),
        outer=bool(args.outer),
    )


def _run_info(args: argparse.Namespace, common: _Common) -> int:
    return run_info(**common)


def _run_cat(args: argparse.Namespace, common: _Common) -> int:
    out = common["out"]
    buffer = getattr(out, "buffer", None)
    if buffer is None:
        # An in-process caller's text-only stream (a StringIO): no bytes can go there.
        raise CliError("cat needs a binary standard output", code=EXIT_USAGE)
    # Nothing is written to the text layer first, but flush it anyway so its bytes
    # could never land after the binary ones.
    out.flush()
    stdin = getattr(sys.stdin, "buffer", None)
    return run_cat(
        archive=common["archive"],
        password=common["password"],
        track_io=common["track_io"],
        verbose=common["verbose"],
        config=common["config"],
        err=common["err"],
        **_selection(args),
        outer=bool(args.outer),
        # The same closed-pipe translation as the text streams (see _DeadPipeWriter).
        sink=cast(BinaryIO, _DeadPipeWriter(buffer)),
        stdin=stdin,
    )


def _refuse_reserved(args: argparse.Namespace, common: _Common) -> NoReturn:
    raise CliError(args._reserved_message, code=EXIT_USAGE)


def _add_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    name: str,
    *,
    common_sub: _ArchiveyArgumentParser,
    run: _Runner,
    aliases: Sequence[str] = (),
    **kwargs: Any,
) -> argparse.ArgumentParser:
    p = sub.add_parser(
        name,
        aliases=list(aliases),
        parents=[common_sub],
        allow_abbrev=False,
        **kwargs,
    )
    p.set_defaults(_run=run)
    return p


def _add_list_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define ``list`` / ``l``: the default verb."""
    p_list = _add_verb(
        sub,
        "list",
        aliases=["l"],
        common_sub=common_sub,
        run=_run_list,
        help="list archive members (default verb)",
    )
    p_list.add_argument("archive", help="archive path")
    _add_filter_args(p_list)
    p_list.add_argument(
        "--digests",
        action="store_true",
        help="show stored member digests (no body read)",
    )
    layout = p_list.add_mutually_exclusive_group()
    layout.add_argument(
        "--long",
        action="store_true",
        help="add packed size, space saved, compression method and CRC-32 columns",
    )
    layout.add_argument(
        "--details",
        action="store_true",
        help="print every stored field of each member as key: value lines",
    )


def _add_test_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define ``test`` / ``t``."""
    p_test = _add_verb(
        sub,
        "test",
        aliases=["t"],
        common_sub=common_sub,
        run=_run_test,
        help="full-read integrity check (verify stored digests)",
    )
    p_test.add_argument("archive", help="archive path")
    p_test.add_argument(
        "--outer",
        action="store_true",
        help=(
            "test only the compression layer, as gzip -t does: read the whole "
            "decompressed stream (the tar of a .tar.gz) and check its checksum, "
            "where the compressor has one"
        ),
    )
    _add_filter_args(p_test)


def _add_extract_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define ``extract`` / ``x``."""
    p_extract = _add_verb(
        sub,
        "extract",
        aliases=["x"],
        common_sub=common_sub,
        run=_run_extract,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EXTRACT_EPILOG,
        help="safely extract members",
    )
    p_extract.add_argument("archive", help="archive path")
    p_extract.add_argument(
        "-d",
        "--dest",
        default=None,
        help=(
            "destination directory. By default, extract into a new folder named "
            "after the archive, or into the current directory when the archive holds "
            "a single top-level folder. Pass -d . to extract into the current "
            "directory in any case."
        ),
    )
    p_extract.add_argument(
        "--policy",
        choices=cli_choices(ExtractionPolicy),
        type=_cli_spelling(ExtractionPolicy),
        default="strict",
        help="extraction safety policy (default: strict)",
    )
    p_extract.add_argument(
        "--overwrite",
        choices=cli_choices(OverwritePolicy),
        type=_cli_spelling(OverwritePolicy),
        default="rename",
        help="collision policy (CLI default: rename; library default remains error)",
    )
    p_extract.add_argument(
        "--stop-on-error",
        action="store_true",
        help=(
            "stop at the first member failure "
            "(policy blocks are always reported and continued; "
            "default: continue and report)"
        ),
    )
    p_extract.add_argument(
        "--abort-on",
        action="append",
        choices=cli_choices(AbortOn),
        type=_cli_spelling(AbortOn),
        default=None,
        metavar="EVENT",
        dest="abort_on",
        help=(
            "abort the whole extraction the first time EVENT occurs, instead of "
            "recording it and continuing; repeatable. blocked-member is the "
            "fail-closed choice for untrusted archives. name-sanitized is a narrow "
            "escape hatch for byte-fidelity work, not part of ordinary strict "
            "extraction"
        ),
    )
    p_extract.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "run the extraction's checks and read every member, but write nothing; "
            "reports what extracting into an empty destination would do"
        ),
    )
    p_extract.add_argument(
        "--outer",
        action="store_true",
        help=(
            "remove only the compression layer and write the file inside, as "
            "gunzip -k does (data.tar from data.tar.gz or data.tgz)"
        ),
    )
    _add_filter_args(p_extract)


def _add_info_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define ``info`` / ``i`` / ``detect``."""
    p_info = _add_verb(
        sub,
        "info",
        aliases=["i", "detect"],
        common_sub=common_sub,
        run=_run_info,
        help="format detection + archive identity",
    )
    p_info.add_argument("archive", help="archive path")


def _add_cat_verb(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define ``cat``."""
    p_cat = _add_verb(
        sub,
        "cat",
        common_sub=common_sub,
        run=_run_cat,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_CAT_EPILOG,
        help="write member contents to stdout",
    )
    p_cat.add_argument("archive", help="archive path, or - to read it from stdin")
    p_cat.add_argument(
        "--outer",
        action="store_true",
        help=(
            "remove only the compression layer and write the stream inside "
            "unchanged (the tar of a .tar.gz, the file of a .gz)"
        ),
    )
    _add_filter_args(p_cat)


def _add_reserved_verbs(
    sub: argparse._SubParsersAction[_ArchiveyArgumentParser],
    common_sub: _ArchiveyArgumentParser,
) -> None:
    """Define The verbs reserved for later, which refuse to run (``_refuse_reserved``)."""
    for name, hint in (
        ("hash", "hash emission is not implemented yet"),
        ("create", "archive creation is not implemented yet"),
        ("convert", "archive conversion is not implemented yet"),
    ):
        p = _add_verb(
            sub,
            name,
            common_sub=common_sub,
            run=_refuse_reserved,
            help=f"reserved ({hint})",
        )
        p.add_argument("archive", nargs="?", default=None)
        p.set_defaults(_reserved_message=hint)


def build_parser() -> argparse.ArgumentParser:
    """The ``archivey`` parser: the shared options, then one subparser per verb."""
    # Two parent instances: action objects are shared if the same instance is reused,
    # so SUPPRESS on a single parent would also wipe the main parser's defaults.
    common = _common_parent(suppress_defaults=False)
    common_sub = _common_parent(suppress_defaults=True)
    parser = _ArchiveyArgumentParser(
        prog="archivey",
        description=(
            "Inspect, verify, and safely extract archives. "
            "Bare invocation defaults to list. "
            "Forthcoming: hash, create, convert."
        ),
        epilog=_TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
        conflict_handler="resolve",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="print version and exit (-v adds format availability)",
    )

    sub = parser.add_subparsers(
        dest="verb",
        metavar="VERB",
        parser_class=_ArchiveyArgumentParser,
    )

    _add_list_verb(sub, common_sub)
    _add_test_verb(sub, common_sub)
    _add_extract_verb(sub, common_sub)
    _add_info_verb(sub, common_sub)
    _add_cat_verb(sub, common_sub)
    _add_reserved_verbs(sub, common_sub)

    return parser


def _format_missing_components(missing: Sequence[MissingComponent]) -> str:
    """``"a, b (hint1); c (hint2)"``: names grouped by install hint (or the reason
    archivey does not use one), first-seen order."""
    names_by_hint: dict[str, list[str]] = {}
    for component in missing:
        names_by_hint.setdefault(component.advice, []).append(component.name)
    groups = [f"{', '.join(names)} ({hint})" for hint, names in names_by_hint.items()]
    return "; ".join(groups)


def _print_version(*, verbose: bool, out: TextIO) -> None:
    """``--version`` / ``--version -v`` (Q6 / P14)."""
    print(f"archivey {archivey.__version__}", file=out)
    if not verbose:
        return
    print(file=out)
    print("formats:", file=out)
    for fmt in list_known_formats():
        avail = format_availability(fmt)
        label = format_format_label(fmt)
        if avail.missing:
            missing = _format_missing_components(avail.missing)
            print(f"  {label}: {avail.support.value} — missing {missing}", file=out)
        elif avail.support is FormatSupport.NONE:
            # A registered format with nothing missing is recognised and not
            # readable. Every other ``none`` on this list names a component.
            print(
                f"  {label}: {avail.support.value} — recognised, not readable",
                file=out,
            )
        else:
            print(f"  {label}: {avail.support.value}", file=out)


def _dispatch(args: argparse.Namespace, *, out: TextIO, err: TextIO) -> int:
    if args.version:
        _print_version(verbose=bool(args.verbose), out=out)
        return EXIT_OK

    if args.salvage:
        raise CliError("--salvage is not implemented yet", code=EXIT_USAGE)

    run = getattr(args, "_run", None)
    if run is None:
        build_parser().print_help(err)
        return EXIT_USAGE

    common = _Common(
        archive=args.archive,
        password=args.password,
        track_io=bool(args.track_io),
        verbose=bool(args.verbose),
        config=ArchiveyConfig(always_probe_content=True)
        if args.probe_content
        else None,
        out=out,
        err=err,
    )
    return cast(_Runner, run)(args, common)


def _format_os_error(exc: OSError) -> str:
    """Human prose for missing paths / I/O errors (cli-product P6).

    Returned **unescaped**: the caller escapes it once, at the print site. The filename
    is therefore delimited with :func:`~archivey.terminal.quoted`, not ``!r`` — ``repr``
    would escape it here and the print site would escape those backslashes again — and
    rendered ``/``-separated so a Windows path's separators are not doubled either.
    """
    path = exc.filename
    if path is None:
        return f"archivey: {exc.strerror or str(exc)}"
    shown = str(path) if isinstance(path, int) else display_path(os.fsdecode(path))
    if exc.errno == errno.ENOENT:
        return f"archivey: cannot open {quoted(shown)}: no such file or directory"
    # Not ``str(exc)`` as the fallback: it embeds the filename through ``repr``.
    reason = exc.strerror or (os.strerror(exc.errno) if exc.errno else "I/O error")
    return f"archivey: cannot open {quoted(shown)}: {reason}"


def _parse_cli_args(
    parser: argparse.ArgumentParser, argv_list: list[str]
) -> argparse.Namespace:
    """Parse argv, folding leftover positionals into ``patterns``.

    argparse leaves include patterns in the "unknown" remainder when optional
    flags like ``-d`` appear before a ``nargs='*'`` patterns positional
    (``archivey x a.zip -d out '*.py'``). Fold those tokens back so the
    documented flag/pattern order works.

    Tokens after the first ``--`` are always positionals, including ``--`` itself
    and names that start with ``-`` (``x ARCHIVE -d out -- -file.txt``).
    """
    # The separator is handled here, not by argparse: 3.11 and 3.12 drop a ``--``
    # from every positional group they consume, so ``x a.zip -- --`` lost the
    # pattern ``--`` there while ``x a.zip -d out -- --`` kept it. argparse sees
    # one ``--`` and opaque stand-ins for the tail, which it cannot strip or read
    # as options, and the stand-ins are swapped back after parsing. A real argv word
    # can never collide with a stand-in, because a process argv cannot carry ``\0``:
    # execve rejects an embedded NUL, and os.exec*/subprocess raise ValueError.
    cut = argv_list.index("--") if "--" in argv_list else len(argv_list)
    head, tail = argv_list[:cut], argv_list[cut + 1 :]
    stand_ins = {f"\0archivey-tail-{i}\0": tok for i, tok in enumerate(tail)}
    args, rest = parser.parse_known_args(
        [*head, "--", *stand_ins.keys()] if tail else head
    )
    for name, value in vars(args).items():
        if isinstance(value, str) and value in stand_ins:
            setattr(args, name, stand_ins[value])
        elif isinstance(value, list):
            setattr(args, name, [stand_ins.get(v, v) for v in value])
    # A ``--`` left in ``rest`` is the one passed above; tail tokens are positionals.
    rest = [tok for tok in rest if tok != "--"]
    unknown_opts = [
        tok
        for tok in rest
        if tok not in stand_ins and tok.startswith("-") and tok != "-"
    ]
    if unknown_opts:
        parser.error(f"unrecognized arguments: {' '.join(unknown_opts)}")
    rest = [stand_ins.get(tok, tok) for tok in rest]
    if not rest:
        return args
    if not hasattr(args, "patterns"):
        parser.error(f"unrecognized arguments: {' '.join(rest)}")
    args.patterns = list(args.patterns or ()) + list(rest)
    return args


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """CLI entry point. Returns a process exit code.

    ``out`` and ``err`` carry the operation's own output. argparse's help and usage
    errors (unknown flags, a missing archive) still print to the process
    ``sys.stdout`` and ``sys.stderr``.
    """
    # Archive text (member names, comments) is printable but may not be encodable: a
    # cp1252 console, PYTHONIOENCODING=ascii. The interpreter's stderr already escapes
    # what it cannot encode; stdout raises, so it gets the same errors handler here.
    # Both streams also go through _DeadPipeWriter, so a closed pipe is a
    # BrokenPipeError on Windows too.
    escaping = cast(
        TextIO, _BackslashReplacingWriter(out if out is not None else sys.stdout)
    )
    out_stream = cast(TextIO, _DeadPipeWriter(escaping))
    err_stream = cast(TextIO, _DeadPipeWriter(err if err is not None else sys.stderr))
    # The OSError messages _parse_and_dispatch already printed: a write that failed
    # inside the verb leaves its bytes buffered, so the final flush below fails again
    # on them with the same error, which needs no second line.
    reported: list[str] = []
    try:
        exit_code = _parse_and_dispatch(
            argv, out=out_stream, err=err_stream, reported=reported
        )
        # Flush here, not at interpreter exit, so a reader that closed the pipe
        # after the last write is still a broken pipe handled below. Without out=
        # and err=, these are the process streams, so this also flushes argparse's
        # buffered help and usage text. It also carries a lost log record to 141:
        # logging's StreamHandler swallows its own write error, which leaves the
        # record in the buffer, so this flush is where the closed pipe surfaces.
        out_stream.flush()
        err_stream.flush()
        return exit_code
    except BrokenPipeError:
        # The verb's output, help and usage text, and the error messages
        # _parse_and_dispatch prints are all written inside this try. Not 0: the
        # reader left before all the output arrived, so `test` may not have
        # verified the whole archive and `list` may not have printed it all. A
        # usage error whose message is lost also lands here, as 141 rather than 2.
        _silence_dead_streams()
        return EXIT_BROKEN_PIPE
    except OSError as exc:
        # The final flush failed for another reason (a full disk, a quota, a
        # network share that went away). _parse_and_dispatch handles the same
        # error the same way when a write inside the verb raises it.
        message = escape_member_name(_format_os_error(exc))
        if message not in reported:
            _report_quietly(message, err_stream)
        # The output that failed to flush is still buffered; without this, the
        # interpreter's exit flush fails on it again and exits 120.
        _silence_dead_streams()
        return EXIT_FAIL
    except KeyboardInterrupt:
        _report_quietly("interrupted", err_stream)
        return EXIT_INTERRUPTED


def _report_quietly(message: str, err: TextIO) -> None:
    """Print ``message`` to ``err``, dropping a second error from that stream."""
    try:
        print(message, file=err)
        err.flush()
    except OSError:
        # err may be the stream whose flush just failed; the exit code still
        # says what happened.
        pass


def _parse_and_dispatch(
    argv: Sequence[str] | None,
    *,
    out: TextIO,
    err: TextIO,
    reported: list[str] | None = None,
) -> int:
    """Parse ``argv`` and run the verb; ``BrokenPipeError`` is left to ``main``.

    Each OSError message printed here is appended to ``reported``, so ``main`` does
    not print it again when its final flush fails the same way.
    """
    raw = list(sys.argv[1:] if argv is None else argv)

    if not raw:
        build_parser().print_help(err)
        return EXIT_USAGE

    argv_list = _inject_default_list(raw)
    parser = build_parser()
    try:
        args = _parse_cli_args(parser, argv_list)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return EXIT_OK
        if isinstance(code, int):
            return code
        print(code, file=err)
        return EXIT_USAGE

    # The line that reports the fault which ended the run starts with ``archivey: ``:
    # the ``CliError``, ``ArchiveyError`` and ``OSError`` handlers below
    # (``_format_os_error`` adds it for ``OSError``), ``list``'s report error,
    # ``extract``'s stop and ``hoist failed`` lines, and the uncounted fault that ends
    # ``test``'s pass after a member already failed. A counted failure (``test``'s
    # ``FAIL …``), a line about one member (``extract``'s ``WARNING: Skipping …``),
    # the notices and counts that follow the fault line (stop notices,
    # ``N member(s) extracted before the stop``, ``files left in …/``) and
    # ``interrupted`` keep their own shape.
    try:
        with cli_logging(verbose=bool(args.verbose), err=err):
            return _dispatch(args, out=out, err=err)
    except CliError as exc:
        # CliError is a plain Exception, outside the archivey hierarchy, so it does not
        # escape its own message the way ArchiveyError does — and an archive-derived name
        # reaches here inside that message, not as a separate argument.
        print(f"archivey: {escape_member_name(exc.message)}", file=err)
        return exc.code
    except ArchiveyError as exc:
        print(f"archivey: {format_error_detail(exc)}", file=err)
        if isinstance(exc, FormatDetectionError) and "always_probe_content" in str(exc):
            # The library's message names the config field; say what the CLI spells it.
            print("archivey: on the command line, pass --probe-content", file=err)
        return EXIT_FAIL
    except BrokenPipeError:
        # BrokenPipeError ⊂ OSError — must precede the OSError handler (F2), which
        # would print to the closed pipe and return 1. main() turns it into 141.
        raise
    except OSError as exc:
        message = escape_member_name(_format_os_error(exc))
        print(message, file=err)
        if reported is not None:
            reported.append(message)
        return EXIT_FAIL
    except KeyboardInterrupt:
        print("interrupted", file=err)
        return EXIT_INTERRUPTED


class _BackslashReplacingWriter:
    """A text stream's ``write`` with ``errors="backslashreplace"``, as on ``sys.stderr``.

    Wraps rather than reconfigures, so a stream the caller passed as ``out=`` is left as
    it was. ``TextIOWrapper.write`` encodes the whole string before buffering any of it,
    so a write that raises ``UnicodeEncodeError`` has written nothing, and is retried
    with what the stream cannot encode escaped.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except UnicodeEncodeError:
            encoding = getattr(self._stream, "encoding", None)
            if not encoding:
                raise
            escaped = text.encode(encoding, "backslashreplace").decode(encoding)
            return self._stream.write(escaped)

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


# What a write to a pipe whose reader has gone raises on Windows. CPython writes
# through the C runtime, which maps ERROR_BROKEN_PIPE (109) to EPIPE, so that one is
# already a BrokenPipeError, but maps ERROR_NO_DATA (232) to EINVAL: a plain OSError,
# "Invalid argument", with no winerror attached. The winerror codes are matched in
# case a write path sets them (compare internal/extraction.py's _typed_os_error).
_WINDOWS_DEAD_PIPE_WINERRORS = frozenset({109, 232})


def _is_dead_pipe(exc: OSError) -> bool:
    """Whether ``exc``, raised writing or flushing an output stream, is a closed pipe.

    Only for errors from the CLI's own output streams: ``EINVAL`` is far too broad to
    read as a closed pipe anywhere else, and even here it counts only on Windows.
    """
    if isinstance(exc, BrokenPipeError):
        return True
    if sys.platform != "win32":
        return False
    if getattr(exc, "winerror", None) in _WINDOWS_DEAD_PIPE_WINERRORS:
        return True
    return exc.errno == errno.EINVAL


def _as_broken_pipe(exc: OSError) -> BrokenPipeError:
    if isinstance(exc, BrokenPipeError):
        return exc
    return BrokenPipeError(errno.EPIPE, exc.strerror or "Broken pipe")


class _DeadPipeWriter(Generic[AnyStr]):
    """An output stream whose closed-pipe errors are all ``BrokenPipeError``.

    Wraps the text streams and, for ``cat``, stdout's byte buffer, so it passes the
    data through unchanged whatever its type.

    On Windows a write to a pipe whose reader has gone can raise ``OSError(EINVAL)``
    instead (see ``_is_dead_pipe``). Translating it at the stream keeps the match
    to the CLI's own output: the ``except BrokenPipeError`` arms in ``main()`` and
    in the verbs then cover Windows too, and an ``EINVAL`` from archive I/O is
    still reported as the error it is.
    """

    def __init__(self, stream: IO[AnyStr]) -> None:
        self._stream = stream

    def write(self, data: AnyStr) -> int:
        try:
            return self._stream.write(data)
        except OSError as exc:
            if _is_dead_pipe(exc):
                raise _as_broken_pipe(exc) from exc
            raise

    def flush(self) -> None:
        try:
            self._stream.flush()
        except OSError as exc:
            if _is_dead_pipe(exc):
                raise _as_broken_pipe(exc) from exc
            raise

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


def _silence_dead_streams() -> None:
    """Point a standard stream that cannot flush at the null device, with no message.

    The interpreter flushes ``sys.stdout`` and ``sys.stderr`` as it exits. Output
    still buffered for a closed pipe or a full disk would fail again there
    (``BrokenPipeError``, ``EINVAL`` on Windows, ``ENOSPC``), print "Exception
    ignored" and exit 120. A stream that still flushes is left as it is.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        try:
            stream.flush()
            continue
        except (OSError, ValueError):
            # Wider than BrokenPipeError on purpose. ValueError is an in-process
            # caller's closed sys.stdout (a closed StringIO); any other OSError
            # (ENOSPC on a redirected stdout) would fail the exit flush the same
            # way. The exit code is already set, so that second error is dropped.
            pass
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
        except OSError:
            # No descriptor to spare means the other stream cannot get one
            # either, so stop rather than try again for it.
            return
        try:
            os.dup2(devnull, stream.fileno())
        except (OSError, ValueError):
            pass
        finally:
            os.close(devnull)


if __name__ == "__main__":
    raise SystemExit(main())
