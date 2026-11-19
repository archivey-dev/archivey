"""Archive arguments that name a URL: resolution through fsspec, labels and redaction.

The CLI's archive argument is a local path unless it looks like a URL that fsspec
knows (``openspec/specs/cli/spec.md``, "CLI archive arguments accept fsspec URLs").
:func:`resolve_archive` applies the rule:

1. The empty argument and ``-`` keep their own rules, decided by the verbs before
   anything here runs.
2. An existing local path wins, and fsspec is not imported for it.
3. Otherwise a *URL candidate* (``scheme://…``, or a ``::`` chain whose first link is
   ``scheme://…`` or a bare protocol such as ``simplecache``) imports fsspec. A missing
   fsspec is a :class:`~archivey.cli.errors.CliError` with an install hint.
4. A candidate whose first protocol fsspec has registered becomes the unentered
   ``OpenFile`` that ``fsspec.open(arg, mode="rb")`` returns; the library reads it.
5. Everything else stays a local path: Windows drive and UNC paths, and an unknown
   first protocol.

The CLI never enters the ``OpenFile``, never turns the URL into a ``Path`` and never
passes ``compression=``: the URL reaches fsspec exactly as typed.

A URL can carry a secret: ``user:password@`` in its authority, or a signature in an
HTTP query. :func:`display_label` is what the CLI prints for one, and
:func:`redact` replaces the exact URL text in third-party error messages before they
reach the terminal. :func:`display_url` is a copy of the library's internal display
policy, which the CLI may not import; ``tests/test_cli_urls.py`` pins the two together.

Resolution runs once per argument and invocation: :func:`reset` clears the cache at the
start and end of each ``main()`` run, so detection and the open see one ``OpenFile``.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from typing import Any

from archivey.cli.errors import CliError
from archivey.terminal import display_path, quoted

# A scheme: a letter, then at least one more of letters, digits, ``+``, ``.`` or ``-``.
_URL_PREFIX = re.compile(r"([A-Za-z][A-Za-z0-9+.-]+)://", re.ASCII)
_BARE_PROTOCOL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+", re.ASCII)
# A URL inside a message: a scheme, ``://`` and everything up to whitespace or a quote.
_URL_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+://[^\s'\"<>]+", re.ASCII)

# Arguments resolved in this invocation: the argument → its OpenFile.
_resolved: dict[str, Any] = {}
# (exact text, label) pairs for :func:`redact`.
_redactions: dict[str, str] = {}


def reset() -> None:
    """Forget the URLs resolved so far; ``main()`` calls it around each run."""
    _resolved.clear()
    _redactions.clear()


def first_protocol(arg: str) -> str | None:
    """The first protocol of a URL candidate, or ``None`` when ``arg`` is not one.

    A scheme has at least two characters, so ``C:/x`` and ``C://x`` are not
    candidates. The match is anchored at the start of the argument.
    """
    match = _URL_PREFIX.match(arg)
    if match is not None:
        return match.group(1)
    first, sep, _ = arg.partition("::")
    if not sep:
        return None
    match = _URL_PREFIX.match(first)
    if match is not None:
        return match.group(1)
    if _BARE_PROTOCOL.fullmatch(first):
        return first
    return None


def _import_fsspec(label: str) -> Any:
    try:
        import fsspec
    except ImportError as exc:
        raise CliError(
            f"{label}: reading an archive from a URL needs fsspec, which is not "
            f"installed; install it with 'pip install fsspec' (HTTP and HTTPS URLs also "
            f"need 'pip install aiohttp')"
        ) from exc
    return fsspec


def _is_registered(protocol: str) -> bool:
    """Whether fsspec knows ``protocol``: built in, an entry point, or registered."""
    from fsspec.registry import known_implementations, registry

    return protocol in known_implementations or protocol in registry


def resolve_archive(arg: str) -> Any:
    """The source for the library: ``arg`` itself (a local path) or an ``OpenFile``.

    Raises :class:`~archivey.cli.errors.CliError` when ``arg`` is a URL candidate and
    fsspec or the backend its protocol needs is missing. Other errors from setting up
    the ``OpenFile`` (a chain's archive or cache file system reads the remote object)
    propagate, as the same errors do during later reads.
    """
    if arg in _resolved:
        return _resolved[arg]
    protocol = first_protocol(arg)
    if protocol is None or os.path.lexists(arg):
        return arg
    label = url_label(arg)
    fsspec = _import_fsspec(label)
    if not _is_registered(protocol):
        return arg
    _register_redactions(arg)
    try:
        # url_to_fs and OpenFile rather than fsspec.open: fsspec 2024.2 open()
        # globbed a read path holding '*', so 'a*[1].zip' could open another object.
        fs, path = fsspec.core.url_to_fs(arg, **_http_options(arg))
        source = fsspec.core.OpenFile(fs, path, mode="rb")
    except ImportError as exc:
        # A known protocol whose backend package is missing (s3fs, aiohttp, …): not a
        # local path, so no fallback to one.
        raise CliError(
            f"{label}: the {protocol!r} protocol needs a package that is not "
            f"installed: {redact(str(exc))}"
        ) from exc
    _resolved[arg] = source
    return source


_HTTP_PROTOCOLS = frozenset({"http", "https"})


def _http_options(arg: str) -> dict[str, Any]:
    """fsspec options that send ``User-Agent: archivey/<version>`` on HTTP(S) links.

    Keyed by protocol, so they reach each ``http``/``https`` link of a chain too. fsspec
    replaces a configured ``client_kwargs`` with the one passed here rather than merging
    the two, so the user's own ``client_kwargs`` from the fsspec configuration (a
    proxy, an auth header) are copied in first, and a ``User-Agent`` they set wins.
    """
    from fsspec.config import conf

    import archivey

    options: dict[str, Any] = {}
    for link in arg.split("::"):
        match = _URL_PREFIX.match(link)
        protocol = match.group(1).lower() if match is not None else ""
        if protocol not in _HTTP_PROTOCOLS or protocol in options:
            continue
        # As fsspec's ``apply_config`` builds it for HTTPFileSystem, whose protocols
        # are ``("http", "https")``: both sections, in that order, for either link.
        configured: dict[str, Any] = {}
        for section in ("http", "https"):
            configured.update(conf.get(section, {}))
        client = dict(configured.get("client_kwargs") or {})
        headers = dict(client.get("headers") or {})
        if not any(str(key).lower() == "user-agent" for key in headers):
            headers["User-Agent"] = f"archivey/{archivey.__version__}"
        client["headers"] = headers
        options[protocol] = {"client_kwargs": client}
    return options


def is_remote(arg: str) -> bool:
    """Whether ``arg`` resolved to an ``OpenFile`` in this invocation."""
    return arg in _resolved


def remote_label() -> str | None:
    """The label of the URL resolved in this invocation, or ``None`` when none was."""
    # The CLI resolves one archive argument per run, so the last one is the source.
    return url_label(next(reversed(_resolved))) if _resolved else None


def remote_error_text(exc: OSError) -> str | None:
    """The message for an ``OSError`` that the resolved URL raised, or ``None``.

    fsspec back ends raise without a ``filename``, with the URL or the object's path
    as the whole text. Only an error of that shape is named after the URL: any other
    filename-less ``OSError`` (a full disk under stdout) did not come from the source.

    fsspec's HTTP back end turns every failure to reach the object into
    ``FileNotFoundError(url)`` and chains the real error, so the cause is reported
    instead: a refused connection or a failed TLS handshake is not a missing object.
    The cause's own text is never printed for an aiohttp error, which re-encodes the
    URL (:func:`http_error_text`).
    """
    if not _resolved:
        return None
    arg = next(reversed(_resolved))
    text = str(exc)
    path = str(getattr(_resolved[arg], "path", ""))
    if text not in (arg, path) and redact(text) == text:
        return None
    label = url_label(arg)
    cause = exc.__cause__
    while isinstance(exc, FileNotFoundError) and cause is not None:
        if (
            isinstance(cause, FileNotFoundError)
            or getattr(cause, "status", None) == 404
        ):
            break  # a real 404: the object is missing
        http_text = http_error_text(cause)
        if http_text is not None:
            return http_text
        if isinstance(cause, OSError):
            return _typed_detail(label, cause)
        cause = cause.__cause__
    if isinstance(exc, FileNotFoundError):
        return f"cannot open {quoted(label)}: no such file or object"
    return _typed_detail(label, exc)


def shown_archive(arg: str) -> str:
    """The archive as the CLI names it in a message, before escaping.

    A URL gets its sanitized label; a local path is ``/``-separated, as
    :func:`~archivey.terminal.display_path` renders it.
    """
    if is_remote(arg):
        return url_label(arg)
    return display_path(arg)


# --- display policy -------------------------------------------------------------------

# Schemes whose query and fragment are dropped from display text: a signed HTTP URL
# carries its secret in the query. On other schemes a ``?`` can be part of the object's
# name (an S3 key), so it is kept.
_QUERY_DROPPED_SCHEMES = frozenset({"http", "https"})


def display_url(url: str) -> str:
    """``url`` without ``user:password@``, and for HTTP(S) without query and fragment.

    The CLI's copy of the library's internal display policy for remote names. Text
    without ``scheme://`` is returned unchanged. For display only: I/O uses the URL as
    given.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        return url
    end = len(rest)
    for stop in "/?#":
        at = rest.find(stop)
        if at != -1:
            end = min(end, at)
    authority, tail = rest[:end], rest[end:]
    authority = authority.rpartition("@")[2]
    if scheme.lower() in _QUERY_DROPPED_SCHEMES:
        for stop in "?#":
            tail = tail.partition(stop)[0]
    return f"{scheme}://{authority}{tail}"


def url_label(arg: str) -> str:
    """``arg`` as the CLI shows it: each ``::`` link sanitized by :func:`display_url`."""
    return "::".join(display_url(link) for link in arg.split("::"))


def _register_redactions(arg: str) -> None:
    pairs = {arg: url_label(arg)}
    for link in arg.split("::"):
        pairs[link] = display_url(link)
    for text, label in pairs.items():
        if text and text != label:
            _redactions[text] = label


def redact(text: str) -> str:
    """``text`` with every resolved URL in it replaced by its label.

    First every exact occurrence, longest first, so a whole chain is replaced before
    one of its links. Then, in a run that resolved a URL, every other ``scheme://``
    token goes through :func:`display_url` too: aiohttp re-encodes the request URL in
    some messages (``user:pw@`` dropped, ``%2F`` decoded to ``/``), so the exact text
    is not there to find, but the query is still cut at its ``?``. A backend that
    prints a credential on its own, outside a URL, is not covered.
    """
    for original in sorted(_redactions, key=len, reverse=True):
        text = text.replace(original, _redactions[original])
    if _resolved:
        text = _URL_TOKEN.sub(lambda match: display_url(match.group(0)), text)
    return text


# --- transport errors -----------------------------------------------------------------


class _NeverRaised(Exception):
    """Stands in for ``aiohttp.ClientError`` when aiohttp is not loaded."""


def http_error_type() -> type[BaseException]:
    """``aiohttp.ClientError`` when a backend loaded aiohttp, else a type never raised.

    Read from ``sys.modules``: the CLI never imports aiohttp itself.
    """
    aiohttp = sys.modules.get("aiohttp")
    error = getattr(aiohttp, "ClientError", None)
    if isinstance(error, type) and issubclass(error, BaseException):
        return error
    return _NeverRaised


def http_error_text(exc: BaseException) -> str | None:
    """The message for an aiohttp error, or ``None`` for any other exception.

    ``ClientResponseError`` text is never printed: aiohttp re-encodes the request URL
    in it (``%2F`` becomes ``/``), so :func:`redact` could miss a signature. The
    message is built from its ``status`` and ``message`` and the sanitized label.
    """
    if not isinstance(exc, http_error_type()):
        return None
    aiohttp = sys.modules.get("aiohttp")
    response_error = getattr(aiohttp, "ClientResponseError", None)
    where = remote_label() or "remote source"
    if isinstance(response_error, type) and isinstance(exc, response_error):
        status = getattr(exc, "status", None)
        reason = getattr(exc, "message", "") or ""
        return f"{where}: HTTP {status} {reason}".rstrip()
    return _typed_detail(where, exc)


def _typed_detail(label: str, exc: BaseException) -> str:
    """``label: Type: detail``, or ``label: Type`` when the error has no text."""
    detail = redact(getattr(exc, "strerror", None) or str(exc))
    if not detail:
        return f"{label}: {type(exc).__name__}"
    return f"{label}: {type(exc).__name__}: {detail}"


# --- names for extraction -------------------------------------------------------------

_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in "123456789¹²³"}
    | {f"LPT{i}" for i in "123456789¹²³"}
)
_WINDOWS_INVALID = frozenset('<>"|?*')


def url_file_name(arg: str, source: Any) -> str:
    """The last path segment of the URL ``arg``, for the smart extraction folder.

    A single URL loses its credentials and, for HTTP(S), its query and fragment; a
    chain uses the ``OpenFile``'s path, the selected member of an archive file system
    or the target of a cache. Nothing is percent-decoded, and redirects or
    ``Content-Disposition`` play no part.
    """
    if "::" in arg:
        path = display_url(str(getattr(source, "path", "")))
    else:
        rest = display_url(arg).partition("://")[2]
        slash = rest.find("/")
        path = rest[slash:] if slash != -1 else ""
    return path.rpartition("/")[2]


def is_safe_url_stem(stem: str, *, windows: bool | None = None) -> bool:
    """Whether ``stem``, taken from a URL, is one safe local path segment.

    Refuses an empty stem, ``.``, ``..``, separators, ``:`` and control characters,
    and on Windows a reserved device name, ``< > " | ? *`` and a trailing space or dot.
    """
    if windows is None:
        windows = sys.platform == "win32"
    if stem in ("", ".", ".."):
        return False
    if any(ch in "/\\:" or unicodedata.category(ch) == "Cc" for ch in stem):
        return False
    if windows:
        if any(ch in _WINDOWS_INVALID for ch in stem) or stem[-1] in " .":
            return False
        base = stem.split(".", 1)[0].rstrip(" ").upper()
        if base in _WINDOWS_RESERVED:
            return False
    return True
