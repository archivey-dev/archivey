"""``archivey --version -v``: which formats this install reads, and what would add more.

The report has three parts. Archive formats and compression formats are listed
separately, by support level. A container read inside a compression (``tar.zst``) is
not listed: its support is the weaker of its two parts, so one sentence names the
containers that pair up, and only a pair whose support differs from its parts is
printed on its own. Last, everything missing or slower is grouped by the command that
installs it, each command once, in the form that fits how the CLI was installed
(:func:`install_command`).
"""

from __future__ import annotations

import os
import sys
import textwrap
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Literal, TextIO

from archivey import (
    ArchiveFormat,
    ContainerFormat,
    FormatAvailability,
    FormatSupport,
    MissingComponent,
    StreamFormat,
    format_availability,
    list_known_formats,
)
from archivey.cli.format import format_format_label

_WIDTH = 79
_LEVELS = (FormatSupport.FULL, FormatSupport.PARTIAL, FormatSupport.NONE)
_RANK = {FormatSupport.NONE: 0, FormatSupport.PARTIAL: 1, FormatSupport.FULL: 2}

Installer = Literal["uvx", "uv-tool", "pipx", "pip"]

_CLI_DISTRIBUTION = "archivey-cli"
_PIP_INSTALL = "pip install "


def detect_installer() -> Installer:
    """How the running ``archivey`` command was installed, as far as can be told.

    ``"uvx"``, ``"uv-tool"`` and ``"pipx"`` need the ``archivey-cli`` distribution and
    an environment of its own: a uv cache entry (``…/archive-v0/<id>``), a uv tool
    directory (``…/uv/tools/archivey-cli`` or under ``UV_TOOL_DIR``) or a pipx venv
    (``…/venvs/archivey-cli``). Anything else is ``"pip"``, whose hint is the library's
    own ``pip install …``.
    """
    try:
        installer = metadata.distribution(_CLI_DISTRIBUTION).read_text("INSTALLER")
    except metadata.PackageNotFoundError:
        return "pip"
    prefix = Path(sys.prefix)
    by_uv = (installer or "").strip() == "uv"
    if by_uv and prefix.parent.name.startswith("archive-v"):
        return "uvx"
    if by_uv and prefix.name == _CLI_DISTRIBUTION:
        tool_dir = os.environ.get("UV_TOOL_DIR")
        if (tool_dir and prefix.parent == Path(tool_dir)) or (
            prefix.parent.name == "tools" and prefix.parent.parent.name == "uv"
        ):
            return "uv-tool"
    if prefix.name == _CLI_DISTRIBUTION and prefix.parent.name == "venvs":
        return "pipx"
    return "pip"


def install_command(advice: str, installer: Installer) -> str:
    """``advice`` rewritten for ``installer`` when it is a ``pip install`` command.

    ``pip install archivey[bzip3]`` adds a package to the environment pip runs in,
    which is not the one ``uvx`` or ``pipx`` made for the CLI. Other advice (an
    external program, a reason the package is not used) is returned unchanged.
    """
    if installer == "pip" or not advice.startswith(_PIP_INSTALL):
        return advice
    requirement = advice.removeprefix(_PIP_INSTALL).strip()
    if "[" in requirement:
        requirement = f'"{requirement}"'
    if installer == "uvx":
        return f"uvx --with {requirement} {_CLI_DISTRIBUTION}"
    if installer == "uv-tool":
        return f"uv tool install --with {requirement} {_CLI_DISTRIBUTION}"
    return f"pipx inject {_CLI_DISTRIBUTION} {requirement}"


@dataclass
class _Group:
    """What one command (or one reason) would change, in first-seen order."""

    names: list[str] = field(default_factory=list)
    adds: list[str] = field(default_factory=list)
    completes: list[str] = field(default_factory=list)
    faster: list[str] = field(default_factory=list)

    def note(self, bucket: list[str], label: str, component: MissingComponent) -> None:
        if label not in bucket:
            bucket.append(label)
        name = str(component.name)
        if name not in self.names:
            self.names.append(name)


def _label_key(label: str) -> str:
    return label.lower()


def _is_container(fmt: ArchiveFormat) -> bool:
    return (
        fmt.container is not ContainerFormat.RAW_STREAM
        and fmt.stream is StreamFormat.UNCOMPRESSED
    )


def _is_stream(fmt: ArchiveFormat) -> bool:
    return fmt.container is ContainerFormat.RAW_STREAM


def _wrapped(prefix: str, items: Iterable[str], indent: int) -> list[str]:
    return textwrap.wrap(
        ", ".join(items),
        width=_WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * indent,
        break_on_hyphens=False,
        break_long_words=False,
    )


def _section(
    title: str,
    formats: Sequence[ArchiveFormat],
    avail: dict[ArchiveFormat, FormatAvailability],
) -> list[str]:
    lines = [title]
    for level in _LEVELS:
        labels = []
        for fmt in formats:
            if avail[fmt].support is not level:
                continue
            label = format_format_label(fmt)
            if level is FormatSupport.NONE and not avail[fmt].missing:
                label += " (recognised, not readable)"
            labels.append(label)
        if labels:
            lines += _wrapped(f"  {level.value + ':':<10}", labels, 12)
    slower = [format_format_label(f) for f in formats if avail[f].faster_with]
    if slower:
        lines += _wrapped("  slower without optional packages: ", slower, 4)
    return lines


def _pair_outliers(
    pairs: Sequence[ArchiveFormat], avail: dict[ArchiveFormat, FormatAvailability]
) -> list[ArchiveFormat]:
    """Pairs whose support is not the weaker of their container's and stream's."""
    outliers = []
    for fmt in pairs:
        parts = (
            ArchiveFormat(fmt.container, StreamFormat.UNCOMPRESSED),
            ArchiveFormat(ContainerFormat.RAW_STREAM, fmt.stream),
        )
        if not all(part in avail for part in parts):
            outliers.append(fmt)
            continue
        expected = min((avail[part].support for part in parts), key=_RANK.__getitem__)
        if avail[fmt].support is not expected:
            outliers.append(fmt)
    return outliers


def _format_line(fmt: ArchiveFormat, availability: FormatAvailability) -> list[str]:
    """One line for a format printed on its own: its level and what it lacks."""
    text = f"{format_format_label(fmt)}: {availability.support.value}"
    if availability.missing:
        text += (
            " (missing " + ", ".join(str(m.name) for m in availability.missing) + ")"
        )
    elif availability.support is FormatSupport.NONE:
        text += " (recognised, not readable)"
    return [f"  {text}"]


def _groups(
    formats: Sequence[ArchiveFormat], avail: dict[ArchiveFormat, FormatAvailability]
) -> dict[str, _Group]:
    groups: dict[str, _Group] = {}
    for fmt in formats:
        availability = avail[fmt]
        label = format_format_label(fmt)
        for component in availability.missing:
            group = groups.setdefault(component.advice, _Group())
            bucket = (
                group.adds
                if availability.support is FormatSupport.NONE
                else group.completes
            )
            group.note(bucket, label, component)
        for component in availability.faster_with:
            group = groups.setdefault(component.advice, _Group())
            group.note(group.faster, label, component)
    return groups


def _by_label(formats: Iterable[ArchiveFormat]) -> list[ArchiveFormat]:
    return sorted(formats, key=lambda f: _label_key(format_format_label(f)))


def _pairs_sentence(
    pairs: Sequence[ArchiveFormat], streams: Sequence[ArchiveFormat]
) -> list[str]:
    """The sentence that stands for every ``container.stream`` pair."""
    wrapping = sorted(
        {
            format_format_label(ArchiveFormat(f.container, StreamFormat.UNCOMPRESSED))
            for f in pairs
        },
        key=_label_key,
    )
    if not wrapping or not streams:
        return []
    names = wrapping[0]
    if len(wrapping) > 1:
        names = ", ".join(wrapping[:-1]) + f" and {wrapping[-1]}"
    stream_labels = [format_format_label(f) for f in streams]
    example = (
        f"{'tar' if 'tar' in wrapping else wrapping[0]}."
        f"{'gz' if 'gz' in stream_labels else stream_labels[0]}"
    )
    return textwrap.wrap(
        f"{names} also open inside any of these, such as {example}.",
        width=_WIDTH,
        initial_indent="  ",
        subsequent_indent="  ",
    )


def print_version_report(*, version: str, verbose: bool, out: TextIO) -> None:
    """``--version`` (one line) and ``--version -v`` (the whole report)."""
    print(f"archivey {version}", file=out)
    if not verbose:
        return
    known = list_known_formats()
    avail = {fmt: format_availability(fmt) for fmt in known}
    containers = _by_label(f for f in known if _is_container(f))
    streams = _by_label(f for f in known if _is_stream(f))
    pairs = [f for f in known if not _is_container(f) and not _is_stream(f)]

    lines = [""]
    lines += _section("archive formats", containers, avail)
    lines.append("")
    lines += _section("compression and encodings", streams, avail)
    lines += _pairs_sentence(pairs, streams)
    outliers = _pair_outliers(pairs, avail)
    if outliers:
        lines += ["", "combinations that differ from their parts"]
        for fmt in outliers:
            lines += _format_line(fmt, avail[fmt])

    groups = _groups([*containers, *streams, *outliers], avail)
    if groups:
        installer = detect_installer()
        lines += ["", "to read more, or faster"]
        for advice, group in groups.items():
            lines += textwrap.wrap(
                install_command(advice, installer),
                width=_WIDTH,
                initial_indent="  ",
                subsequent_indent="    ",
                break_on_hyphens=False,
                break_long_words=False,
            )
            if group.adds:
                lines += _wrapped("    adds ", group.adds, 6)
            if group.completes:
                lines += _wrapped("    completes ", group.completes, 6)
            if group.faster:
                lines += _wrapped("    faster for ", group.faster, 6)
            lines += _wrapped("    packages: ", group.names, 6)
    for line in lines:
        print(line, file=out)
