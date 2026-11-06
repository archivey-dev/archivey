"""An archive as a read-only ``fsspec`` file system: the ``archivey://`` protocol.

:class:`ArchiveyFileSystem` shows the members of any archive archivey reads as files and
directories, so ``pandas.read_csv("archivey://data/t.csv::s3://bucket/a.7z")`` reads one
member of a remote 7z without downloading the rest. The base package registers the
protocol through fsspec's ``fsspec.specs`` entry point, so fsspec finds it without an
``import archivey``.

This module imports fsspec, and it is the only archivey module that does: without
fsspec installed, importing it raises ``ModuleNotFoundError``. No archivey extra
installs fsspec; every package that reads a remote store (``s3fs``, ``gcsfs``,
``adlfs``) depends on it.
"""

from __future__ import annotations

import os
import weakref
from typing import TYPE_CHECKING, Any, BinaryIO, Self, cast

import fsspec
from fsspec.archive import AbstractArchiveFileSystem
from fsspec.core import OpenFile

from archivey.core import open_archive
from archivey.diagnostics import DiagnosticCode, PathRefusedContext
from archivey.exceptions import FilterRejectionError
from archivey.internal.enum_args import coerce_enum
from archivey.internal.filters import extraction_view_name
from archivey.internal.overrides import override
from archivey.terminal import quoted
from archivey.types import ArchiveMember, ExtractionPolicy, MemberType

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig, PasswordInput
    from archivey.formats import ArchiveFormat
    from archivey.internal.base_reader import BaseArchiveReader
    from archivey.reader import ArchiveReader, ArchiveStream
    from archivey.types import ExtractionPolicyStr

__all__ = ["ArchiveyFileSystem"]

# How many links one path may pass through before it counts as unresolved. A cycle
# never reaches here (the reader leaves a cyclic link without a target member); this
# bounds a long chain.
_MAX_LINK_HOPS = 40


class ArchiveyFileSystem(AbstractArchiveFileSystem):
    """A read-only ``fsspec`` file system over one archive, protocol ``archivey``.

    ``fo`` is the archive: an fsspec URL (``"s3://bucket/a.7z"``), an
    ``fsspec.core.OpenFile``, a local path, or a binary file object. A ``str`` goes
    through ``fsspec.open(fo, protocol=target_protocol, **target_options)``, so
    chained URLs (``archivey://member::s3://bucket/a.7z``) work, and so, unlike a
    ``str`` given to :func:`~archivey.open_archive`, a ``str`` here reaches whatever
    protocol it names. Build the file system from a trusted ``fo`` and pass a member
    name from a caller as the path of ``open()``, never formatted into a URL:
    fsspec splits a URL on ``::``, so a name in one can add a protocol of its own.

    The archive is opened once, with ``seekable_members=True`` and
    ``concurrent_operations=True``, and the reader is :attr:`reader`. ``format``,
    ``password``, ``encoding`` and ``config`` are :func:`~archivey.open_archive`'s.

    **The tree is what extraction writes.** Each path is the relative path
    ``reader.extract_all(dest, policy=policy)`` gives the member, and a duplicate name
    shows its current entry. A member the policy refuses (a ``..`` segment, an absolute
    name under ``STRICT``, a name the policy will not write) is left out, and the
    refusal is a ``MEMBER_PATH_REFUSED`` diagnostic on ``fs.reader.diagnostics``. What
    a destination decides (``overwrite=``, existing files, collisions on a
    case-insensitive disk) and ``filter=`` are not modelled.

    A link whose target is a member is listed as the target's type, with
    ``"islink": True`` and ``"destination"`` in its ``info()``, and opens the target.
    A link that resolves to nothing is listed as ``"other"``, and opening it raises
    ``FileNotFoundError``.

    The instance owns its reader: :meth:`close`, or leaving a ``with`` block, closes it,
    and so does collecting the instance. A member stream from ``open()`` keeps the
    instance alive until the stream closes. ``cachable`` is ``False``: fsspec's
    instance cache would keep every reader open for the life of the process.

    The file system pickles as its constructor arguments and opens the archive again
    when unpickled, as dask needs to send it to a worker. A file-object ``fo`` cannot
    be sent that way, and pickling raises ``TypeError``.
    """

    protocol = "archivey"
    root_marker = ""
    cachable = False

    def __init__(
        self,
        fo: str | os.PathLike[str] | OpenFile | BinaryIO = "",
        *,
        target_protocol: str | None = None,
        target_options: dict[str, Any] | None = None,
        format: ArchiveFormat | str | None = None,  # open_archive's name
        password: PasswordInput = None,
        encoding: str | None = None,
        config: ArchiveyConfig | None = None,
        policy: ExtractionPolicy | ExtractionPolicyStr = ExtractionPolicy.STRICT,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.policy = coerce_enum(
            policy, ExtractionPolicy, call="ArchiveyFileSystem()", param="policy="
        )
        self.fo = fo
        source: OpenFile | os.PathLike[str] | BinaryIO
        if isinstance(fo, str):
            source = cast(
                "OpenFile",
                fsspec.open(
                    fo, mode="rb", protocol=target_protocol, **(target_options or {})
                ),
            )
        else:
            source = fo
        reader = open_archive(
            cast("Any", source),
            format=cast("Any", format),
            password=password,
            encoding=encoding,
            config=config,
            seekable_members=True,
            concurrent_operations=True,
        )
        self.reader: ArchiveReader = reader
        # Closes the reader when the instance is collected. The callback holds the
        # reader, never ``self``, so it does not keep the instance alive.
        self._finalizer = weakref.finalize(self, reader.close)
        self.dir_cache: dict[str, dict[str, Any]] | None = None

    @classmethod
    @override
    def _strip_protocol(cls, path: str) -> str:
        # Paths are relative to the archive's root. fsspec's own annotation allows a
        # list, for a list of paths; a path is one string here.
        return cast("str", super()._strip_protocol(path)).lstrip("/")

    def close(self) -> None:
        """Close the reader. The file system lists and opens nothing after this."""
        self._finalizer()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @override
    def __reduce__(self) -> tuple[Any, ...]:
        if not isinstance(self.fo, (str, os.PathLike, OpenFile)):
            raise TypeError(
                "an ArchiveyFileSystem built from a file object cannot be pickled: "
                "it pickles as its constructor arguments, and a file object cannot be "
                "sent to another process; build it from a URL, a path or an OpenFile"
            )
        return super().__reduce__()

    def _get_dirs(self) -> None:
        if self.dir_cache is not None:
            return
        reader = self.reader
        files: dict[str, dict[str, Any]] = {}
        for member in reader.members():
            if not member.is_current:
                continue
            try:
                name = extraction_view_name(member, self.policy)
            except FilterRejectionError as exc:
                self._report_refused(member, exc)
                continue
            if not name or name == ".":
                continue
            files[name] = self._entry(name, member)
        dir_cache = {
            name: {"name": name, "size": 0, "type": "directory"}
            for name in self._all_dirnames(files)
        }
        dir_cache.update(files)
        self.dir_cache = dir_cache

    def _entry(self, name: str, member: ArchiveMember) -> dict[str, Any]:
        target = member
        islink = member.type in (MemberType.SYMLINK, MemberType.HARDLINK)
        for _ in range(_MAX_LINK_HOPS):
            if target is None or target.type not in (
                MemberType.SYMLINK,
                MemberType.HARDLINK,
            ):
                break
            target = target.link_target_member
        else:
            target = None
        entry: dict[str, Any] = {"name": name}
        if target is None or target.type is MemberType.OTHER:
            entry.update(type="other", size=None)
        elif target.type is MemberType.DIRECTORY:
            entry.update(type="directory", size=0)
        else:
            entry.update(type="file", size=target.size)
        if islink:
            entry.update(islink=True, destination=member.link_target)
        modified = member.modified_utc()
        if modified is not None:
            entry["mtime"] = modified.timestamp()
        entry["member"] = member
        return entry

    def _report_refused(self, member: ArchiveMember, exc: FilterRejectionError) -> None:
        reader = cast("BaseArchiveReader", self.reader)
        reason = exc.raw_message
        reader._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_PATH_REFUSED,
            message=(
                f"{quoted(member.name)} is not in the archivey:// tree: the "
                f"{self.policy.value} extraction policy refuses it ({reason})"
            ),
            context=PathRefusedContext(
                archive_name=reader._archive_name,
                member_name=member.name,
                member_id=member.member_id,
                policy=self.policy.value,
                reason=reason,
            ),
            member=member,
        )

    # fsspec annotates ``_open`` as returning its own buffered file; any binary file
    # object is what callers of ``open`` get, and a member stream is one.
    @override
    def _open(  # pyrefly: ignore[bad-override]
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ArchiveStream:
        if mode != "rb":
            raise NotImplementedError(
                f"the archivey file system is read-only; mode {mode!r} is not 'rb'"
            )
        path = self._strip_protocol(path)
        info: dict[str, Any] = self.info(path)
        if info["type"] == "directory":
            raise IsADirectoryError(path)
        if info["type"] != "file":
            raise FileNotFoundError(path)
        stream = self.reader.open(info["member"])
        # The stream keeps this file system, and through it the reader, alive while
        # the caller holds only the stream (``fsspec.open(url).open()``).
        stream._archivey_fs = self  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
        return stream

    # Every write method of AbstractFileSystem, refused as fsspec's other read-only
    # file systems refuse them.
    def _read_only(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("the archivey file system is read-only")

    mkdir = makedirs = rmdir = _read_only
    pipe_file = put_file = cp_file = mv = _read_only
    rm_file = rm = _rm = touch = _read_only
