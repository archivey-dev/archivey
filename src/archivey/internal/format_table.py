"""Core's table of its own formats, in registration order.

This is the first form of the manifest's entries (``openspec/changes/plugin-platform``,
step 1). A reader written against ``archivey.formats`` does not register itself: its
module defines a handler, and an entry here names that handler by dotted path and adds
what a handler cannot declare yet. Those additions are data, as they will be in a
manifest: a trailer at the end of the source, a refinement of another format's magic,
whether the format's magic may sit behind a self-extracting stub, and whether the
reader searches past damage under ``open_archive(salvage=True)``. Code an entry
needs (a refinement check, a stub-hit validator) is named by dotted path too.

A reader written against ``BaseArchiveReader`` (ZIP, TAR, 7z, RAR, single-file and
directory) still registers when its module is imported; its entry names the module.

Order matters: detection takes the first magic that matches, so deb comes before ar,
whose magic a ``.deb`` starts with.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from archivey.types import ArchiveFormat, MagicSignature, TrailerSignature

if TYPE_CHECKING:
    from archivey.formats import FormatHandler
    from archivey.internal.sfx import HitValidator

_BACKENDS = "archivey.internal.backends"

# A UDIF image ends with a 512-byte ``koly`` block (``udif.parse_koly``). Its first
# run is a real bzip2 or xz stream, so that magic is one block of the image, and the
# trailer outranks it.
_KOLY = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")
# A pre-10.5 encrypted image ends with ``cdsaencr``; the reader refuses it by name.
_ENCRYPTED_V1 = b"cdsaencr"


@dataclass(frozen=True)
class HandlerEntry:
    """A format whose reader is written against ``archivey.formats``.

    ``handler`` is ``"module:Class"``. ``refines`` pairs a base format with the dotted
    path of a check ``(peek, name) -> bool``: when the base's magic matches and the
    check says yes, the file is this format. ``behind_stub`` says the handler's magic
    may sit behind an executable stub, which detection then scans for, calling
    ``stub_validator`` on each hit; ``stub_parser_scans`` says the reader runs its
    own capped scan at open. ``salvage`` says the reader searches past damage when
    opened with ``salvage=True`` (``ReadBackend.SUPPORTS_SALVAGE``); a reader without
    it reads as the default and records ``SALVAGE_UNAVAILABLE``.
    """

    handler: str
    trailers: tuple[TrailerSignature, ...] = ()
    refines: tuple[tuple[ArchiveFormat, str], ...] = ()
    behind_stub: bool = False
    stub_validator: str | None = None
    stub_parser_scans: bool = False
    salvage: bool = False


@dataclass(frozen=True)
class ModuleEntry:
    """A reader written against ``BaseArchiveReader``, which registers on import."""

    module: str


CORE_FORMATS: tuple[HandlerEntry | ModuleEntry, ...] = (
    HandlerEntry(f"{_BACKENDS}.deb_reader:DebHandler", salvage=True),
    HandlerEntry(f"{_BACKENDS}.ar_reader:ArHandler", salvage=True),
    HandlerEntry(
        f"{_BACKENDS}.arj_reader:ArjHandler",
        behind_stub=True,
        stub_validator=f"{_BACKENDS}.arj_reader:validate_stub_hit",
        stub_parser_scans=True,
    ),
    HandlerEntry(f"{_BACKENDS}.cab_reader:CabHandler"),
    HandlerEntry(f"{_BACKENDS}.cpio_reader:CpioHandler", salvage=True),
    ModuleEntry(f"{_BACKENDS}.directory_reader"),
    HandlerEntry(
        f"{_BACKENDS}.dmg_reader:DmgHandler",
        trailers=(
            TrailerSignature(
                512,
                _KOLY,
                ArchiveFormat.DMG,
                preempts=(ArchiveFormat.BZ2, ArchiveFormat.XZ),
            ),
            TrailerSignature(len(_ENCRYPTED_V1), _ENCRYPTED_V1, ArchiveFormat.DMG),
        ),
    ),
    HandlerEntry(f"{_BACKENDS}.iso_reader:IsoHandler"),
    HandlerEntry(
        f"{_BACKENDS}.lha_reader:LhaHandler",
        behind_stub=True,
        stub_validator=f"{_BACKENDS}.lha_reader:validate_stub_hit",
        stub_parser_scans=True,
    ),
    HandlerEntry(f"{_BACKENDS}.makeself_reader:MakeselfHandler"),
    # pkg before xar would change nothing: a refinement is looked up by its base.
    HandlerEntry(f"{_BACKENDS}.xar_reader:XarHandler"),
    HandlerEntry(
        f"{_BACKENDS}.pkg_reader:PkgHandler",
        refines=((ArchiveFormat.XAR, f"{_BACKENDS}.pkg_reader:is_package"),),
    ),
    ModuleEntry(f"{_BACKENDS}.rar_reader"),
    HandlerEntry(f"{_BACKENDS}.rpm_reader:RpmHandler"),
    ModuleEntry(f"{_BACKENDS}.sevenzip_reader"),
    ModuleEntry(f"{_BACKENDS}.single_file_reader"),
    HandlerEntry(f"{_BACKENDS}.squashfs_reader:SquashfsHandler"),
    ModuleEntry(f"{_BACKENDS}.tar_reader"),
    ModuleEntry(f"{_BACKENDS}.zip_reader"),
)


def load(path: str) -> object:
    """The object a ``"module:name"`` path names, importing the module."""
    module, _, name = path.partition(":")
    return getattr(importlib.import_module(module), name)


def _backend_attributes(
    entry: HandlerEntry, handler: type[FormatHandler]
) -> dict[str, object]:
    """The backend attributes the entry sets beyond what the handler declares."""
    attrs: dict[str, object] = {}
    if entry.salvage:
        attrs["SUPPORTS_SALVAGE"] = True
    if entry.trailers:
        attrs["TRAILER"] = entry.trailers
    if entry.refines:
        attrs["MAGIC_REFINEMENTS"] = tuple(
            (
                base,
                cast(
                    "Callable[[Callable[[int], bytes], str | None], bool]", load(check)
                ),
            )
            for base, check in entry.refines
        )
    if entry.behind_stub:
        attrs["SFX_MAGIC"] = tuple(
            MagicSignature(m.offset, m.data, handler.format) for m in handler.magic
        )
        if entry.stub_validator is not None:
            validator = cast("HitValidator", load(entry.stub_validator))
            attrs["SFX_HIT_VALIDATOR"] = staticmethod(validator)
        attrs["SFX_PARSER_SCANS"] = entry.stub_parser_scans
    return attrs


def register_core_formats() -> None:
    """Register every format of :data:`CORE_FORMATS`, in table order."""
    from archivey.formats import FormatHandler
    from archivey.internal.format_adapter import register_builtin_format

    for entry in CORE_FORMATS:
        if isinstance(entry, ModuleEntry):
            importlib.import_module(entry.module)
            continue
        handler = load(entry.handler)
        assert isinstance(handler, type) and issubclass(handler, FormatHandler)
        register_builtin_format(handler, **_backend_attributes(entry, handler))
