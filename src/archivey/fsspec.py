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
import tempfile
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Self, cast

import fsspec
from fsspec.archive import AbstractArchiveFileSystem
from fsspec.core import OpenFile

from archivey.core import open_archive
from archivey.diagnostics import DiagnosticCode, PathRefusedContext
from archivey.exceptions import FilterRejectionError
from archivey.internal.enum_args import coerce_enum
from archivey.internal.filters import (
    check_universal,
    collision_key,
    extraction_view,
    resolve_or_raise_on_loop,
)
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
    ``reader.extract_all(dest, policy=policy)`` gives the member, into an empty
    ``dest``, and the tree leaves out what that extraction would not write: a member
    the policy refuses (a ``..`` segment, an absolute name under ``STRICT``, a name the
    policy will not write, a symlink whose target leaves the destination), a hard link
    to a refused member, a member whose name collides with one before it (the
    policy's collision key: ``README`` and ``readme`` collide under ``STRICT`` and
    ``STANDARD``), and a path under a file. Each is a ``MEMBER_PATH_REFUSED``
    diagnostic on ``fs.reader.diagnostics``. A duplicate name shows its current entry.
    What a non-empty destination decides (``overwrite=``, existing files) and
    ``filter=`` are not modelled.

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
        files: dict[str, dict[str, Any]] = {}
        # What extraction decides from the members written before one, in its order:
        # the first member to claim a collision key keeps it, a path under a file or a
        # file over a directory is refused, and a hard link whose source is refused is
        # refused too. Keys are ``collision_key``s, as extraction's are.
        claimed: dict[str, bool] = {}  # key -> whether it is a file
        refused_ids: set[int] = set()
        # An empty directory as the destination: nothing is written to it, so the
        # symlink checks of ``check_universal`` resolve every path by its name alone.
        with tempfile.TemporaryDirectory(prefix="archivey-fsspec-") as tmp:
            root = resolve_or_raise_on_loop(Path(tmp))
            for member in self.reader.members():
                if not member.is_current:
                    continue
                try:
                    view = self._view(member, root, refused_ids)
                except FilterRejectionError as exc:
                    refused_ids.add(member.member_id)
                    self._report_refused(member, exc.raw_message)
                    continue
                name = view.name.rstrip("/")
                if not name or name == ".":
                    continue
                conflict = self._claim(name, view, claimed)
                if conflict is not None:
                    self._report_refused(member, conflict)
                    continue
                files[name] = self._entry(name, member)
        dir_cache = {
            name: {"name": name, "size": 0, "type": "directory"}
            for name in self._all_dirnames(files)
        }
        dir_cache.update(files)
        self.dir_cache = dir_cache

    def _view(
        self, member: ArchiveMember, root: Path, refused_ids: set[int]
    ) -> ArchiveMember:
        """``member`` as extraction writes it, or ``FilterRejectionError``."""
        view = extraction_view(member, self.policy)
        if view.type is MemberType.SYMLINK:
            # Where its target points: a target that leaves the destination is refused
            # whatever the destination is.
            check_universal(view, root, dest_resolved=True)
        elif member.type is MemberType.HARDLINK:
            source = member.link_target_member
            if (
                source is not None
                and source.type is not MemberType.SYMLINK
                and source.member_id in refused_ids
            ):
                raise FilterRejectionError(
                    "Hardlink target was refused",
                    member_name=member.name,
                    link_target=member.link_target,
                )
        return view

    def _claim(
        self, name: str, view: ArchiveMember, claimed: dict[str, bool]
    ) -> str | None:
        """Claim ``name`` and its parents, or say why extraction would not write it."""
        policy = self.policy
        key = collision_key(name, policy)
        is_dir = view.type is MemberType.DIRECTORY
        parts = key.split("/")
        for depth in range(1, len(parts)):
            if claimed.get("/".join(parts[:depth])):
                return "a parent of it is a file"
        if key in claimed:
            if is_dir and not claimed[key]:
                return None  # a directory listed again
            return "its name collides with a member written before it"
        claimed[key] = not is_dir
        for depth in range(1, len(parts)):
            claimed.setdefault("/".join(parts[:depth]), False)
        return None

    def _entry(self, name: str, member: ArchiveMember) -> dict[str, Any]:
        islink = member.type in (MemberType.SYMLINK, MemberType.HARDLINK)
        # ``link_target_member`` is the end of the link chain; a cycle or a target
        # that is no member leaves it ``None``, and a chain that ends at a symlink
        # with no target ends at that symlink.
        target = member.link_target_member if islink else member
        entry: dict[str, Any] = {"name": name}
        if target is None or target.type in (
            MemberType.OTHER,
            MemberType.SYMLINK,
            MemberType.HARDLINK,
        ):
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

    def _report_refused(self, member: ArchiveMember, reason: str) -> None:
        reader = cast("BaseArchiveReader", self.reader)
        reader._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_PATH_REFUSED,
            message=(
                f"{quoted(member.name)} is not in the archivey:// tree: extraction "
                f"under the {self.policy.value} policy would not write it ({reason})"
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
        stream._archivey_fs = self  # pyrefly: ignore[missing-attribute]  # ty: ignore[unresolved-attribute]
        return stream

    # Every write method of AbstractFileSystem, refused as fsspec's other read-only
    # file systems refuse them.
    def _read_only(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("the archivey file system is read-only")

    mkdir = makedirs = rmdir = _read_only
    pipe_file = put_file = cp_file = mv = _read_only
    rm_file = rm = _rm = touch = _read_only
