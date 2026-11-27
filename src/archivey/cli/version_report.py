"""``archivey --version -v``: which formats this install reads, and what would add more.

The report has three parts. Archive formats and compression formats are listed
separately, by support level. A container read inside a compression (``tar.zst``) is
not listed: its support is the weaker of its two parts, so one sentence names the
containers that pair up, and only a pair whose support differs from its parts is
printed on its own. Last, everything missing or slower is grouped by the command that
installs it, each command once, in the form that fits how the CLI was installed
(:func:`install_command`). A command run from an environment made for the library
alone (``uvx archivey``) is pointed at ``archivey-cli``.

``format_availability`` finds optional packages without importing them, so it counts a
package that is installed but fails to import as present, where a read treats it as
absent. This short-lived report imports each package it finds
(:func:`unimportable_packages`) and reports the ones that fail as absent, with the
error in place of the install advice.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import os
import sys
import textwrap
import warnings
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Literal, TextIO

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ContainerFormat,
    FormatPolicy,
    StreamFormat,
    format_availability,
)
from archivey.cli.format import format_format_label
from archivey.core import list_known_formats
from archivey.types import (
    FormatAvailability,
    FormatSupport,
    MissingComponent,
    OptionalLibrary,
)

_WIDTH = 79
_LEVELS = (FormatSupport.FULL, FormatSupport.PARTIAL, FormatSupport.NONE)
_RANK = {FormatSupport.NONE: 0, FormatSupport.PARTIAL: 1, FormatSupport.FULL: 2}

Installer = Literal["uvx", "uv-tool", "pipx", "pip"]

_CLI_DISTRIBUTION = "archivey-cli"
_LIBRARY_DISTRIBUTION = "archivey"
_PIP_INSTALL = "pip install "

#: The PyPI name of each optional package whose import name differs from it.
_DISTRIBUTIONS: dict[str, str] = {
    OptionalLibrary.BZIP3: "bzip3",
    OptionalLibrary.COMPRESS_UTILS: "compress-utils",
    OptionalLibrary.GOOGLE_CRC32C: "google-crc32c",
}


def distribution_name(name: str) -> str:
    """The name ``pip install`` takes for the package or program ``name``."""
    return _DISTRIBUTIONS.get(name, name)


@dataclass(frozen=True)
class Install:
    """How the running ``archivey`` command was installed: the tool that made its
    environment, and the distribution that environment was made for (``archivey-cli``,
    or ``archivey`` when the user ran ``uvx archivey`` and so on)."""

    installer: Installer
    distribution: str = _CLI_DISTRIBUTION


def _tool_installer(distribution: str) -> Installer | None:
    """The tool that made an environment of its own for ``distribution``, or ``None``.

    That is a uv cache entry (``…/archive-v0/<id>``), a uv tool directory
    (``…/uv/tools/<distribution>``, ``…/uv/data/tools/<distribution>`` on Windows, or
    under ``UV_TOOL_DIR``) or a pipx venv (``…/venvs/<distribution>``).
    """
    try:
        installer = metadata.distribution(distribution).read_text("INSTALLER")
    except metadata.PackageNotFoundError:
        return None
    prefix = Path(sys.prefix)
    by_uv = (installer or "").strip() == "uv"
    if by_uv and prefix.parent.name.startswith("archive-v"):
        return "uvx"
    if by_uv and prefix.name == distribution:
        tool_dir = os.environ.get("UV_TOOL_DIR")
        if (tool_dir and prefix.parent == Path(tool_dir)) or (
            # uv's tool directory: ``…/uv/tools`` on Linux and macOS,
            # ``…/uv/data/tools`` (under %APPDATA%) on Windows.
            prefix.parent.name == "tools" and "uv" in prefix.parent.parts[-3:]
        ):
            return "uv-tool"
    if prefix.name == distribution and prefix.parent.name == "venvs":
        return "pipx"
    return None


def detect_installer() -> Install:
    """How the running ``archivey`` command was installed, as far as can be told.

    An environment made for ``archivey-cli`` is checked first, then one made for the
    ``archivey`` library alone, which has the same command without the recommended
    packages. Anything else is ``"pip"``, whose hint is the library's own
    ``pip install …``.
    """
    for distribution in (_CLI_DISTRIBUTION, _LIBRARY_DISTRIBUTION):
        installer = _tool_installer(distribution)
        if installer is not None:
            return Install(installer, distribution)
    return Install("pip")


def install_command(advice: str, install: Install) -> str:
    """``advice`` rewritten for ``install`` when it is a ``pip install`` command.

    ``pip install archivey[bzip3]`` adds a package to the environment pip runs in,
    which is not the one ``uvx`` or ``pipx`` made for the CLI. Other advice (an
    external program, a reason the package is not used) is returned unchanged. A
    requirement with an extra is quoted in every form, as zsh would expand the brackets.
    """
    if not advice.startswith(_PIP_INSTALL):
        return advice
    requirement = advice.removeprefix(_PIP_INSTALL).strip()
    if "[" in requirement:
        requirement = f'"{requirement}"'
    if install.installer == "pip":
        return _PIP_INSTALL + requirement
    tool = install.distribution
    if install.installer == "uvx":
        return f"uvx --with {requirement} {tool}"
    if install.installer == "uv-tool":
        return f"uv tool install --with {requirement} {tool}"
    return f"pipx inject {tool} {requirement}"


def cli_package_hint(install: Install) -> str | None:
    """A pointer to ``archivey-cli`` when the command runs from an environment made
    for the ``archivey`` library alone, which lacks the recommended packages."""
    if install.installer == "pip" or install.distribution != _LIBRARY_DISTRIBUTION:
        return None
    command = {
        "uvx": "uvx archivey-cli",
        "uv-tool": "uv tool install archivey-cli",
        "pipx": "pipx install archivey-cli",
    }[install.installer]
    return (
        f"This archivey command comes from the archivey package alone. "
        f"{command} installs the same command with archivey's recommended "
        f"optional packages."
    )


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
        name = distribution_name(str(component.name))
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
    # Only a package the user could install: one with a ``reason`` (turned off, or
    # unused on this interpreter) is explained in the grouped section instead.
    slower = [
        format_format_label(f)
        for f in formats
        if any(not m.reason for m in avail[f].faster_with)
    ]
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
            " (missing "
            + ", ".join(distribution_name(str(m.name)) for m in availability.missing)
            + ")"
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
        f"{names} also open inside any of these that can be read, such as {example}.",
        width=_WIDTH,
        initial_indent="  ",
        subsequent_indent="  ",
    )


def unimportable_packages(skip: Collection[str] = ()) -> dict[OptionalLibrary, str]:
    """The optional packages that are installed but fail to import, with the error.

    Each package that is found is imported, so this is for a short-lived process such
    as this report: ``format_availability`` must not import them (``packaging-and-
    extras``). The packages in ``skip`` are not imported. Any exception counts as a
    failure, as it does when a codec imports the package.
    """
    broken: dict[OptionalLibrary, str] = {}
    for library in OptionalLibrary:
        # pycdlib is deprecated and nothing uses it (ISO needs no package), and
        # naming it in exclude_libraries= warns, so it is never reported broken.
        if library is OptionalLibrary.PYCDLIB or library in skip:
            continue
        try:
            if importlib.util.find_spec(library) is None:
                continue
        except (ImportError, ValueError):
            continue
        try:
            # On a free-threaded build CPython warns that importing an extension
            # without free-thread support turns the GIL on. That is expected in this
            # short-lived process, and under -W error it would read as a broken
            # package.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                importlib.import_module(library)
        except Exception as exc:  # noqa: BLE001 - any import failure means absent
            first = (str(exc).splitlines() or [""])[0]
            broken[library] = f"{type(exc).__name__}: {first}".removesuffix(": ")
    return broken


def _broken_advice(
    component: MissingComponent, broken: dict[str, str]
) -> MissingComponent:
    """``component`` with an import failure in place of its policy reason, when the
    report turned it off because it fails to import."""
    error = broken.get(str(component.name))
    if error is None:
        return component
    return dataclasses.replace(
        component,
        install_hint=(
            f"{distribution_name(str(component.name))} is installed but fails to "
            f"import ({error}); reinstalling it may fix this"
        ),
        reason="",
    )


def _availability(
    known: Sequence[ArchiveFormat],
) -> dict[ArchiveFormat, FormatAvailability]:
    """Each format's availability, with the packages that fail to import as absent.

    A package already reported with a ``reason`` (one archivey does not use on this
    interpreter, such as lz4 under PyPy) is not imported: it is absent already, and
    its reason says why.
    """
    avail = {fmt: format_availability(fmt) for fmt in known}
    with_reason = {
        str(m.name)
        for a in avail.values()
        for m in (*a.missing, *a.faster_with)
        if m.reason
    }
    broken = unimportable_packages(with_reason)
    if not broken:
        return avail
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries=set(broken)))
    errors = {str(library): error for library, error in broken.items()}
    for fmt in known:
        found = format_availability(fmt, config=config)
        avail[fmt] = dataclasses.replace(
            found,
            missing=tuple(_broken_advice(m, errors) for m in found.missing),
            faster_with=tuple(_broken_advice(m, errors) for m in found.faster_with),
        )
    return avail


def print_version_report(*, version: str, verbose: bool, out: TextIO) -> None:
    """``--version`` (one line) and ``--version -v`` (the whole report)."""
    print(f"archivey {version}", file=out)
    if not verbose:
        return
    known = list_known_formats()
    avail = _availability(known)
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
        hint = cli_package_hint(installer)
        if hint:
            lines += textwrap.wrap(
                hint, width=_WIDTH, initial_indent="  ", subsequent_indent="  "
            )
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
